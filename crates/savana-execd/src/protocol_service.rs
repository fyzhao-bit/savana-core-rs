use std::sync::Arc;
use std::time::{Duration, Instant};

use chacha20poly1305::aead::{Aead as _, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit as _, Nonce};
use hkdf::Hkdf;
use savana_kernel_protocol::v2::{
    decode_executor_completion_payload_v2, encode_acknowledge_committed_completion_response_v2,
    encode_connector_registry_sync_response_v2, encode_dispatch_response_v2,
    encode_executor_health_response_v2, encode_fetch_completion_response_v2,
    encode_query_by_execution_nonce_response_v2, encode_signed_sealed_execution_envelope_v2,
    AcknowledgeCommittedCompletionResponseV2, Digest32V2, DispatchResponseV2, DispatchSubjectV2,
    ExecutorCompletionDescriptorV2, ExecutorFailureClassV2, ExecutorHealthResponseV2,
    ExecutorStatusV2, FetchCompletionResponseV2, HpkeX25519KeyIdV2, KernelExecutorOperationV2,
    PublicStableCodeV2, QueryByExecutionNonceResponseV2, SignedExecutorEffectStartedReceiptV2,
    UnixMillisV2,
};
use savana_policy_core::v2::{BoundedConnectorHostV2, ConnectorDescriptorV2};
use sha2::{Digest as _, Sha256};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::{
    DispatchEnvelopeKindV2, ExecdConnectorRegistryErrorV2, ExecdConnectorRegistryGuardV2,
    ExecdConnectorRegistryV2, ExecdJournalStateV2, ExecdQueryV2, ExecdStateOwnerErrorV2,
    ExecdStateOwnerV2, VerifiedExecdDeploymentV2,
};

const PRE_EFFECT_TERMINALIZATION_TIMEOUT_V2: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ExecdProtocolServiceErrorV2 {
    #[error("executor protocol request was malformed")]
    Protocol,
    #[error("executor request did not match durable journal identity")]
    Binding,
    #[error("executor completion is not available in the required typed form")]
    ResultUnavailable,
    #[error("executor state owner rejected the operation")]
    Owner(ExecdStateOwnerErrorV2),
}

#[derive(Debug, Clone)]
pub struct ExecdProtocolDeploymentV2 {
    active_state_manifest_digest: Digest32V2,
    deployment_generation: u64,
    effect_fence_epoch: u64,
    executor_identity: savana_kernel_protocol::v2::ExecutorIdentityV2,
    seal_key_id: HpkeX25519KeyIdV2,
    seal_private_key: [u8; 32],
    journal_schema_version: u16,
    journal_key_epoch: u64,
    connector_set_digest: Digest32V2,
}

impl ExecdProtocolDeploymentV2 {
    pub fn from_verified_deployment(
        deployment: &VerifiedExecdDeploymentV2,
        seal_key_id: HpkeX25519KeyIdV2,
        seal_private_key: [u8; 32],
        journal_schema_version: u16,
        journal_key_epoch: u64,
        connector_set_digest: Digest32V2,
    ) -> Result<Self, ExecdProtocolServiceErrorV2> {
        let seal_public_key =
            X25519PublicKey::from(&StaticSecret::from(seal_private_key)).to_bytes();
        if seal_key_id.as_bytes() == &[0; 32]
            || seal_private_key == [0; 32]
            || hpke_x25519_key_id(seal_public_key) != seal_key_id
            || journal_schema_version == 0
            || journal_key_epoch == 0
            || connector_set_digest.as_bytes() == &[0; 32]
        {
            return Err(ExecdProtocolServiceErrorV2::Binding);
        }
        Ok(Self {
            active_state_manifest_digest: deployment.active_state_manifest_digest(),
            deployment_generation: deployment.deployment_generation(),
            effect_fence_epoch: deployment.effect_fence_epoch(),
            executor_identity: deployment.executor_identity(),
            seal_key_id,
            seal_private_key,
            journal_schema_version,
            journal_key_epoch,
            connector_set_digest,
        })
    }
}

/// Typed five-operation V2 service facade over the durable execd owner.
pub struct ExecdProtocolServiceV2 {
    deployment: ExecdProtocolDeploymentV2,
    owner: ExecdStateOwnerV2,
    processor: Box<dyn PreparedDispatchProcessorV2>,
    connector_registry: Option<Arc<ExecdConnectorRegistryV2>>,
}

#[derive(Debug, Clone)]
pub(crate) struct PreparedConnectorDispatchV2 {
    descriptor: ConnectorDescriptorV2,
    active_host_allowlist: Vec<BoundedConnectorHostV2>,
}

impl PreparedConnectorDispatchV2 {
    pub(crate) const fn descriptor(&self) -> &ConnectorDescriptorV2 {
        &self.descriptor
    }

    pub(crate) fn active_host_allowlist(&self) -> &[BoundedConnectorHostV2] {
        &self.active_host_allowlist
    }
}

pub(crate) trait PreparedDispatchProcessorV2: Send + Sync {
    fn is_ready(&self) -> bool;

    fn process(
        &self,
        owner: &ExecdStateOwnerV2,
        query: ExecdQueryV2,
        payload: Zeroizing<Vec<u8>>,
        connector: Option<&PreparedConnectorDispatchV2>,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<(), ExecdProtocolServiceErrorV2>;

    fn recover(
        &self,
        owner: &ExecdStateOwnerV2,
        query: ExecdQueryV2,
        task_payload: Option<savana_kernel_protocol::v2::TaskExecutionPayloadV2>,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<(), ExecdProtocolServiceErrorV2>;
}

impl std::fmt::Debug for ExecdProtocolServiceV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExecdProtocolServiceV2")
            .field(
                "deployment_generation",
                &self.deployment.deployment_generation,
            )
            .finish_non_exhaustive()
    }
}

impl ExecdProtocolServiceV2 {
    pub(crate) fn new(
        deployment: ExecdProtocolDeploymentV2,
        owner: ExecdStateOwnerV2,
        processor: Box<dyn PreparedDispatchProcessorV2>,
    ) -> Result<Self, ExecdProtocolServiceErrorV2> {
        Self::new_inner(deployment, owner, processor, None)
    }

    pub(crate) fn new_with_connector_registry(
        deployment: ExecdProtocolDeploymentV2,
        owner: ExecdStateOwnerV2,
        processor: Box<dyn PreparedDispatchProcessorV2>,
        connector_registry: Arc<ExecdConnectorRegistryV2>,
    ) -> Result<Self, ExecdProtocolServiceErrorV2> {
        Self::new_inner(deployment, owner, processor, Some(connector_registry))
    }

    fn new_inner(
        deployment: ExecdProtocolDeploymentV2,
        owner: ExecdStateOwnerV2,
        processor: Box<dyn PreparedDispatchProcessorV2>,
        connector_registry: Option<Arc<ExecdConnectorRegistryV2>>,
    ) -> Result<Self, ExecdProtocolServiceErrorV2> {
        if !processor.is_ready() {
            return Err(ExecdProtocolServiceErrorV2::ResultUnavailable);
        }
        let service = Self {
            deployment,
            owner,
            processor,
            connector_registry,
        };
        let deadline = Instant::now()
            .checked_add(std::time::Duration::from_secs(5))
            .ok_or(ExecdProtocolServiceErrorV2::ResultUnavailable)?;
        if service
            .owner
            .recovery_projection(deadline)
            .map_err(ExecdProtocolServiceErrorV2::Owner)?
            .into_iter()
            .any(|entry| {
                matches!(
                    entry.state(),
                    ExecdJournalStateV2::ProviderAttemptPrepared
                        | ExecdJournalStateV2::EffectStarted
                        | ExecdJournalStateV2::ProviderResponseRetained
                        | ExecdJournalStateV2::ReleaseEvidencePrepared
                )
            })
        {
            return Err(ExecdProtocolServiceErrorV2::ResultUnavailable);
        }
        Ok(service)
    }

    #[cfg(test)]
    pub(crate) fn recovery_projection_for_test(
        &self,
        deadline: Instant,
    ) -> Result<Vec<ExecdQueryV2>, ExecdProtocolServiceErrorV2> {
        self.owner
            .recovery_projection(deadline)
            .map_err(ExecdProtocolServiceErrorV2::Owner)
    }

    #[cfg(test)]
    pub(crate) fn active_effect_guard_count_for_test(&self) -> usize {
        self.owner.active_guard_count_for_test()
    }

    pub(crate) fn recover_prepared(
        deployment: &ExecdProtocolDeploymentV2,
        owner: &ExecdStateOwnerV2,
        processor: &dyn PreparedDispatchProcessorV2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<(), ExecdProtocolServiceErrorV2> {
        Self::recover_prepared_inner(deployment, owner, processor, None, now, deadline)
    }

    pub(crate) fn recover_prepared_with_connector_registry(
        deployment: &ExecdProtocolDeploymentV2,
        owner: &ExecdStateOwnerV2,
        processor: &dyn PreparedDispatchProcessorV2,
        connector_registry: &Arc<ExecdConnectorRegistryV2>,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<(), ExecdProtocolServiceErrorV2> {
        Self::recover_prepared_inner(
            deployment,
            owner,
            processor,
            Some(connector_registry),
            now,
            deadline,
        )
    }

    fn recover_prepared_inner(
        deployment: &ExecdProtocolDeploymentV2,
        owner: &ExecdStateOwnerV2,
        processor: &dyn PreparedDispatchProcessorV2,
        connector_registry: Option<&Arc<ExecdConnectorRegistryV2>>,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<(), ExecdProtocolServiceErrorV2> {
        if !processor.is_ready() || now.get() == 0 || Instant::now() >= deadline {
            return Err(ExecdProtocolServiceErrorV2::ResultUnavailable);
        }
        for query in owner
            .recovery_projection(deadline)
            .map_err(ExecdProtocolServiceErrorV2::Owner)?
        {
            match query.state() {
                ExecdJournalStateV2::Prepared => {
                    let canonical = owner
                        .sealed_execution_envelope(query.execution_nonce(), deadline)
                        .map_err(ExecdProtocolServiceErrorV2::Owner)?;
                    let envelope =
                        savana_kernel_protocol::v2::decode_signed_sealed_execution_envelope_v2(
                            &canonical,
                        )
                        .map_err(|_| ExecdProtocolServiceErrorV2::Protocol)?;
                    let expected_head = envelope
                        .payload()
                        .core()
                        .executor_connector_registry_digest();
                    let registry_guard = match connector_registry {
                        Some(registry) => match registry.admit_head(expected_head) {
                            Ok(guard) => Some(guard),
                            Err(ExecdConnectorRegistryErrorV2::HeadMismatch) => {
                                let observed_head = registry
                                    .current_head_digest()
                                    .map_err(|_| ExecdProtocolServiceErrorV2::ResultUnavailable)?;
                                owner
                                    .record_failed_no_effect_recovery(
                                        query.execution_nonce(),
                                        ExecutorFailureClassV2::ConnectorUnavailableBeforeEffect,
                                        stale_prepared_registry_head_digest(
                                            query,
                                            expected_head,
                                            observed_head,
                                        ),
                                        now,
                                        deadline,
                                    )
                                    .map_err(ExecdProtocolServiceErrorV2::Owner)?;
                                continue;
                            }
                            Err(_) => {
                                return Err(ExecdProtocolServiceErrorV2::ResultUnavailable);
                            }
                        },
                        None => None,
                    };
                    let plaintext =
                        open_execution_payload(envelope.payload(), deployment.seal_private_key)
                            .map_err(|()| ExecdProtocolServiceErrorV2::Binding)?;
                    let connector = registry_guard
                        .as_ref()
                        .map(|guard| {
                            connector_dispatch_for_subject(
                                guard,
                                envelope.payload().core().subject(),
                                envelope.payload().core().task_binding().is_some(),
                            )
                        })
                        .transpose()?
                        .flatten();
                    Self::process_dispatch_with_owner(
                        owner,
                        processor,
                        query,
                        plaintext,
                        connector.as_ref(),
                        now,
                        deadline,
                    )?;
                }
                ExecdJournalStateV2::ProviderAttemptPrepared
                | ExecdJournalStateV2::EffectStarted
                | ExecdJournalStateV2::ProviderResponseRetained
                | ExecdJournalStateV2::ReleaseEvidencePrepared => {
                    let canonical = owner
                        .sealed_execution_envelope(query.execution_nonce(), deadline)
                        .map_err(ExecdProtocolServiceErrorV2::Owner)?;
                    let envelope =
                        savana_kernel_protocol::v2::decode_signed_sealed_execution_envelope_v2(
                            &canonical,
                        )
                        .map_err(|_| ExecdProtocolServiceErrorV2::Protocol)?;
                    let task_payload = if envelope.payload().core().task_binding().is_some() {
                        let plaintext =
                            open_execution_payload(envelope.payload(), deployment.seal_private_key)
                                .map_err(|_| ExecdProtocolServiceErrorV2::Binding)?;
                        Some(
                            savana_kernel_protocol::v2::decode_task_execution_payload_v2(
                                &plaintext,
                            )
                            .map_err(|_| ExecdProtocolServiceErrorV2::Binding)?,
                        )
                    } else {
                        None
                    };
                    processor.recover(owner, query, task_payload, now, deadline)?;
                }
                ExecdJournalStateV2::CompletionAvailable
                | ExecdJournalStateV2::FailedNoEffect
                | ExecdJournalStateV2::Indeterminate
                | ExecdJournalStateV2::Acknowledged => {}
            }
        }
        Ok(())
    }

    fn ensure_ready(&self) -> Result<(), ExecdProtocolServiceErrorV2> {
        if self.processor.is_ready() {
            Ok(())
        } else {
            Err(ExecdProtocolServiceErrorV2::ResultUnavailable)
        }
    }

    /*
     * Dispatch plaintext is never exposed as a public queue. The verified
     * processor consumes it synchronously or durably terminalizes the nonce.
     */
    fn process_dispatch(
        &self,
        query: ExecdQueryV2,
        plaintext: Zeroizing<Vec<u8>>,
        connector: Option<&PreparedConnectorDispatchV2>,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<Instant, ExecdProtocolServiceErrorV2> {
        Self::process_dispatch_with_owner(
            &self.owner,
            self.processor.as_ref(),
            query,
            plaintext,
            connector,
            now,
            deadline,
        )
    }

    fn process_dispatch_with_owner(
        owner: &ExecdStateOwnerV2,
        processor: &dyn PreparedDispatchProcessorV2,
        query: ExecdQueryV2,
        plaintext: Zeroizing<Vec<u8>>,
        connector: Option<&PreparedConnectorDispatchV2>,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<Instant, ExecdProtocolServiceErrorV2> {
        match processor.process(owner, query, plaintext, connector, now, deadline) {
            Ok(()) => Ok(deadline),
            Err(error) => {
                // Once the request budget is exhausted, the daemon still owns a
                // short, bounded budget to make the durable pre-effect record
                // terminal before releasing the registry read guard.
                let cleanup_deadline = Instant::now()
                    .checked_add(PRE_EFFECT_TERMINALIZATION_TIMEOUT_V2)
                    .ok_or(ExecdProtocolServiceErrorV2::ResultUnavailable)?;
                let current = owner
                    .query(query.execution_nonce(), cleanup_deadline)
                    .map_err(ExecdProtocolServiceErrorV2::Owner)?;
                if matches!(
                    current.state(),
                    ExecdJournalStateV2::Prepared | ExecdJournalStateV2::ProviderAttemptPrepared
                ) {
                    owner
                        .record_failed_no_effect(
                            query.execution_nonce(),
                            ExecutorFailureClassV2::ConnectorUnavailableBeforeEffect,
                            processor_pre_effect_failure_digest(query, connector, error),
                            now,
                            cleanup_deadline,
                        )
                        .map_err(ExecdProtocolServiceErrorV2::Owner)?;
                    Ok(cleanup_deadline)
                } else {
                    Err(error)
                }
            }
        }
    }

    pub fn execute(
        &self,
        operation: KernelExecutorOperationV2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<Vec<u8>, ExecdProtocolServiceErrorV2> {
        if now.get() == 0 || Instant::now() >= deadline {
            return Err(ExecdProtocolServiceErrorV2::Binding);
        }
        match operation {
            KernelExecutorOperationV2::Health(_) => self.health(deadline),
            KernelExecutorOperationV2::Dispatch(request) => {
                self.ensure_ready()?;
                let core = request.envelope().payload().core();
                let registry_guard = if let Some(registry) = self.connector_registry.as_ref() {
                    Some(
                        registry
                            .admit_head(core.executor_connector_registry_digest())
                            .map_err(|_| ExecdProtocolServiceErrorV2::Binding)?,
                    )
                } else {
                    if core.executor_connector_registry_digest()
                        != self.deployment.connector_set_digest
                    {
                        return Err(ExecdProtocolServiceErrorV2::Binding);
                    }
                    None
                };
                let connector = registry_guard
                    .as_ref()
                    .map(|guard| {
                        connector_dispatch_for_subject(
                            guard,
                            core.subject(),
                            core.task_binding().is_some(),
                        )
                    })
                    .transpose()?
                    .flatten();
                let envelope = encode_signed_sealed_execution_envelope_v2(request.envelope())
                    .map_err(|_| ExecdProtocolServiceErrorV2::Protocol)?;
                let query = self
                    .owner
                    .accept_signed_dispatch(envelope, now, deadline)
                    .map_err(ExecdProtocolServiceErrorV2::Owner)?;
                let mut response_deadline = deadline;
                if query.state() == ExecdJournalStateV2::Prepared {
                    match open_execution_payload(
                        request.envelope().payload(),
                        self.deployment.seal_private_key,
                    ) {
                        Ok(plaintext) => {
                            response_deadline = self.process_dispatch(
                                query,
                                plaintext,
                                connector.as_ref(),
                                now,
                                deadline,
                            )?;
                        }
                        Err(()) => {
                            let evidence_digest = domain_digest(
                                b"SAVANA_EXECUTOR_SEALED_PAYLOAD_REJECTED_V2\0",
                                request.envelope().payload().hpke_ciphertext(),
                            );
                            self.owner
                                .record_failed_no_effect(
                                    query.execution_nonce(),
                                    savana_kernel_protocol::v2::ExecutorFailureClassV2::
                                        EnvelopeRejectedBeforeEffect,
                                    evidence_digest,
                                    now,
                                    deadline,
                                )
                                .map_err(ExecdProtocolServiceErrorV2::Owner)?;
                        }
                    }
                }
                let query = self
                    .owner
                    .query(query.execution_nonce(), response_deadline)
                    .map_err(ExecdProtocolServiceErrorV2::Owner)?;
                let status = self.status(query, response_deadline)?;
                encode_dispatch_response_v2(&DispatchResponseV2::new(status))
                    .map_err(|_| ExecdProtocolServiceErrorV2::Protocol)
            }
            KernelExecutorOperationV2::QueryByExecutionNonce(request) => {
                let query = self
                    .owner
                    .query(request.execution_nonce(), deadline)
                    .map_err(ExecdProtocolServiceErrorV2::Owner)?;
                verify_query_binding(
                    query,
                    request.dispatch_core_digest(),
                    request.dispatch_subject_digest(),
                )?;
                let status = self.status(query, deadline)?;
                let no_effect = matches!(status, ExecutorStatusV2::FailedNoEffect { .. });
                let mut response = QueryByExecutionNonceResponseV2::new(status);
                if no_effect {
                    let receipt = self
                        .owner
                        .terminal_receipt(query.execution_nonce(), deadline)
                        .map_err(ExecdProtocolServiceErrorV2::Owner)?;
                    response = response
                        .with_terminal_receipt(receipt.canonical_bytes().to_vec())
                        .map_err(|_| ExecdProtocolServiceErrorV2::Protocol)?;
                }
                encode_query_by_execution_nonce_response_v2(&response)
                    .map_err(|_| ExecdProtocolServiceErrorV2::Protocol)
            }
            KernelExecutorOperationV2::AcknowledgeCommittedCompletion(request) => {
                let query = self
                    .owner
                    .query(request.execution_nonce(), deadline)
                    .map_err(ExecdProtocolServiceErrorV2::Owner)?;
                verify_query_binding(
                    query,
                    request.dispatch_core_digest(),
                    request.dispatch_subject_digest(),
                )?;
                let expected = self.completion_descriptor(query, deadline)?;
                if request.completion() != expected {
                    return Err(ExecdProtocolServiceErrorV2::Binding);
                }
                self.owner
                    .acknowledge_completion(
                        request.execution_nonce(),
                        request.kernel_commit_digest(),
                        deadline,
                    )
                    .map_err(ExecdProtocolServiceErrorV2::Owner)?;
                encode_acknowledge_committed_completion_response_v2(
                    &AcknowledgeCommittedCompletionResponseV2::new(ExecutorStatusV2::Acknowledged),
                )
                .map_err(|_| ExecdProtocolServiceErrorV2::Protocol)
            }
            KernelExecutorOperationV2::FetchCompletion(request) => {
                let query = self
                    .owner
                    .query(request.execution_nonce(), deadline)
                    .map_err(ExecdProtocolServiceErrorV2::Owner)?;
                verify_query_binding(
                    query,
                    request.dispatch_core_digest(),
                    request.dispatch_subject_digest(),
                )?;
                let expected = self.completion_descriptor(query, deadline)?;
                if request.completion() != expected {
                    return Err(ExecdProtocolServiceErrorV2::Binding);
                }
                let effect_receipt = self.effect_started_receipt(query, deadline)?;
                let stored = self
                    .owner
                    .completion(query.execution_nonce(), deadline)
                    .map_err(ExecdProtocolServiceErrorV2::Owner)?;
                let payload = decode_executor_completion_payload_v2(stored.canonical_payload())
                    .map_err(|_| ExecdProtocolServiceErrorV2::Protocol)?;
                let response = FetchCompletionResponseV2::new(
                    query.execution_nonce(),
                    query.dispatch_core_digest(),
                    query.dispatch_subject_digest(),
                    effect_receipt.clone(),
                    signed_receipt_digest(&effect_receipt)?,
                    expected,
                    payload,
                )
                .map_err(|_| ExecdProtocolServiceErrorV2::Protocol)?;
                let canonical = self
                    .owner
                    .sealed_execution_envelope(query.execution_nonce(), deadline)
                    .map_err(ExecdProtocolServiceErrorV2::Owner)?;
                let envelope =
                    savana_kernel_protocol::v2::decode_signed_sealed_execution_envelope_v2(
                        &canonical,
                    )
                    .map_err(|_| ExecdProtocolServiceErrorV2::Protocol)?;
                let response = if let Some(binding) = envelope.payload().core().task_binding() {
                    let terminal = self
                        .owner
                        .terminal_receipt(query.execution_nonce(), deadline)
                        .map_err(ExecdProtocolServiceErrorV2::Owner)?;
                    response.with_task_outcome(
                        savana_kernel_protocol::v2::TaskCompletionEvidenceV2::new(
                            binding.authorization_digest(),
                            query
                                .prepared_request_digest()
                                .ok_or(ExecdProtocolServiceErrorV2::Binding)?,
                            query
                                .retained_provider_response_digest()
                                .ok_or(ExecdProtocolServiceErrorV2::Binding)?,
                            terminal.canonical_bytes().to_vec(),
                        )
                        .map_err(|_| ExecdProtocolServiceErrorV2::Protocol)?,
                    )
                } else {
                    response
                };
                encode_fetch_completion_response_v2(&response)
                    .map_err(|_| ExecdProtocolServiceErrorV2::Protocol)
            }
            KernelExecutorOperationV2::ConnectorRegistrySync(request) => {
                let registry = self
                    .connector_registry
                    .as_ref()
                    .ok_or(ExecdProtocolServiceErrorV2::Binding)?;
                let response = registry
                    .synchronize(&request)
                    .map_err(|_| ExecdProtocolServiceErrorV2::Binding)?;
                encode_connector_registry_sync_response_v2(&response)
                    .map_err(|_| ExecdProtocolServiceErrorV2::Protocol)
            }
        }
    }

    fn health(&self, deadline: Instant) -> Result<Vec<u8>, ExecdProtocolServiceErrorV2> {
        let backlog = self
            .owner
            .recovery_projection(deadline)
            .map_err(ExecdProtocolServiceErrorV2::Owner)?
            .into_iter()
            .filter(|query| {
                !matches!(
                    query.state(),
                    ExecdJournalStateV2::Acknowledged
                        | ExecdJournalStateV2::FailedNoEffect
                        | ExecdJournalStateV2::Indeterminate
                )
            })
            .count();
        let connector_set_digest = self
            .connector_registry
            .as_ref()
            .map(|registry| registry.current_head_digest())
            .transpose()
            .map_err(|_| ExecdProtocolServiceErrorV2::ResultUnavailable)?
            .unwrap_or(self.deployment.connector_set_digest);
        let response = ExecutorHealthResponseV2::new(
            self.processor.is_ready(),
            self.deployment.active_state_manifest_digest,
            self.deployment.deployment_generation,
            self.deployment.effect_fence_epoch,
            self.deployment.executor_identity,
            self.deployment.seal_key_id,
            self.deployment.journal_schema_version,
            self.deployment.journal_key_epoch,
            connector_set_digest,
            u32::try_from(backlog).map_err(|_| ExecdProtocolServiceErrorV2::Binding)?,
            (!self.processor.is_ready()).then_some(PublicStableCodeV2::ServiceUnavailable),
        )
        .map_err(|_| ExecdProtocolServiceErrorV2::Protocol)?;
        encode_executor_health_response_v2(&response)
            .map_err(|_| ExecdProtocolServiceErrorV2::Protocol)
    }

    fn status(
        &self,
        query: ExecdQueryV2,
        deadline: Instant,
    ) -> Result<ExecutorStatusV2, ExecdProtocolServiceErrorV2> {
        match query.state() {
            ExecdJournalStateV2::Prepared | ExecdJournalStateV2::ProviderAttemptPrepared => {
                Ok(ExecutorStatusV2::Prepared)
            }
            ExecdJournalStateV2::EffectStarted
            | ExecdJournalStateV2::ProviderResponseRetained
            | ExecdJournalStateV2::ReleaseEvidencePrepared => {
                let receipt = self.effect_started_receipt(query, deadline)?;
                ExecutorStatusV2::effect_started(receipt.clone(), signed_receipt_digest(&receipt)?)
                    .map_err(|_| ExecdProtocolServiceErrorV2::Protocol)
            }
            ExecdJournalStateV2::CompletionAvailable => {
                let receipt = self.effect_started_receipt(query, deadline)?;
                let completion = self.completion_descriptor(query, deadline)?;
                ExecutorStatusV2::completion_available(
                    receipt.clone(),
                    signed_receipt_digest(&receipt)?,
                    completion,
                )
                .map_err(|_| ExecdProtocolServiceErrorV2::Protocol)
            }
            ExecdJournalStateV2::FailedNoEffect => Ok(ExecutorStatusV2::FailedNoEffect {
                class: query
                    .failure_class()
                    .ok_or(ExecdProtocolServiceErrorV2::ResultUnavailable)?,
            }),
            ExecdJournalStateV2::Indeterminate => {
                let receipt = self.effect_started_receipt(query, deadline).ok();
                let digest = receipt.as_ref().map(signed_receipt_digest).transpose()?;
                ExecutorStatusV2::indeterminate(receipt, digest)
                    .map_err(|_| ExecdProtocolServiceErrorV2::Protocol)
            }
            ExecdJournalStateV2::Acknowledged => Ok(ExecutorStatusV2::Acknowledged),
        }
    }

    fn effect_started_receipt(
        &self,
        query: ExecdQueryV2,
        deadline: Instant,
    ) -> Result<SignedExecutorEffectStartedReceiptV2, ExecdProtocolServiceErrorV2> {
        let receipt = self
            .owner
            .effect_started_receipt(query.execution_nonce(), deadline)
            .map_err(ExecdProtocolServiceErrorV2::Owner)?;
        Ok(receipt)
    }

    fn completion_descriptor(
        &self,
        query: ExecdQueryV2,
        deadline: Instant,
    ) -> Result<ExecutorCompletionDescriptorV2, ExecdProtocolServiceErrorV2> {
        if query.state() != ExecdJournalStateV2::CompletionAvailable {
            return Err(ExecdProtocolServiceErrorV2::ResultUnavailable);
        }
        match query.kind() {
            DispatchEnvelopeKindV2::ToolExecution | DispatchEnvelopeKindV2::FinalRelease => self
                .owner
                .completion(query.execution_nonce(), deadline)
                .map(|stored| stored.descriptor())
                .map_err(ExecdProtocolServiceErrorV2::Owner),
        }
    }
}

fn open_execution_payload(
    payload: &savana_kernel_protocol::v2::SealedExecutionEnvelopePayloadV2,
    recipient_private_key: [u8; 32],
) -> Result<Zeroizing<Vec<u8>>, ()> {
    let recipient_secret = StaticSecret::from(recipient_private_key);
    let recipient_public = X25519PublicKey::from(&recipient_secret).to_bytes();
    let ephemeral_public = *payload.hpke_enc().as_bytes();
    let shared = recipient_secret
        .diffie_hellman(&X25519PublicKey::from(ephemeral_public))
        .to_bytes();
    if shared == [0; 32] {
        return Err(());
    }
    let mut key_nonce = Zeroizing::new([0_u8; 44]);
    let mut info = Vec::with_capacity(96);
    info.extend_from_slice(b"SAVANA_EXECUTION_HPKE_X25519_CHACHA20POLY1305_V2\0");
    info.extend_from_slice(&ephemeral_public);
    info.extend_from_slice(&recipient_public);
    Hkdf::<Sha256>::new(Some(payload.dispatch_core_digest().as_bytes()), &shared)
        .expand(&info, key_nonce.as_mut())
        .map_err(|_| ())?;
    let cipher = ChaCha20Poly1305::new_from_slice(&key_nonce[..32]).map_err(|_| ())?;
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&key_nonce[32..]),
            Payload {
                msg: payload.hpke_ciphertext(),
                aad: payload.dispatch_core_digest().as_bytes(),
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| ())?;
    if let Some(binding) = payload.core().task_binding() {
        let domain: &[u8] = match payload.core().subject() {
            savana_kernel_protocol::v2::DispatchSubjectV2::ToolExecution { .. } => {
                b"SAVANA_PRESEALED_EXECUTOR_PAYLOAD_V2\0"
            }
            savana_kernel_protocol::v2::DispatchSubjectV2::FinalRelease { .. } => {
                b"SAVANA_PRESEALED_FINAL_RELEASE_PAYLOAD_V2\0"
            }
        };
        let mut hash = Sha256::new();
        hash.update(domain);
        hash.update((plaintext.len() as u64).to_be_bytes());
        hash.update(plaintext.as_slice());
        hash.update(32u64.to_be_bytes());
        hash.update(payload.declassification_provenance_digest().as_bytes());
        if Digest32V2::new(hash.finalize().into()) != binding.presealed_payload_digest() {
            return Err(());
        }
        let body = savana_kernel_protocol::v2::decode_task_execution_payload_v2(&plaintext)
            .map_err(|_| ())?;
        body.check_core(&payload.core()).map_err(|_| ())?;
    }
    Ok(plaintext)
}

pub(crate) fn hpke_x25519_key_id(public_key: [u8; 32]) -> HpkeX25519KeyIdV2 {
    HpkeX25519KeyIdV2::new(
        *domain_digest(b"SAVANA_HPKE_X25519_KEY_ID_V2\0", &public_key).as_bytes(),
    )
}

fn domain_digest(domain: &[u8], bytes: &[u8]) -> Digest32V2 {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    Digest32V2::new(hasher.finalize().into())
}

fn processor_pre_effect_failure_digest(
    query: ExecdQueryV2,
    connector: Option<&PreparedConnectorDispatchV2>,
    error: ExecdProtocolServiceErrorV2,
) -> Digest32V2 {
    let error_tag = match error {
        ExecdProtocolServiceErrorV2::Protocol => 1_u16,
        ExecdProtocolServiceErrorV2::Binding => 2,
        ExecdProtocolServiceErrorV2::ResultUnavailable => 3,
        ExecdProtocolServiceErrorV2::Owner(_) => 4,
    };
    let mut hasher = Sha256::new();
    hasher.update(b"SAVANA_EXECD_PROCESSOR_PRE_EFFECT_FAILURE_V2\0");
    hasher.update(query.execution_nonce().as_bytes());
    hasher.update(query.dispatch_core_digest().as_bytes());
    hasher.update(query.dispatch_subject_digest().as_bytes());
    hasher.update(error_tag.to_be_bytes());
    match connector {
        Some(connector) => {
            hasher.update([1]);
            hasher.update(Sha256::digest(connector.descriptor().canonical_bytes()));
        }
        None => hasher.update([0]),
    }
    Digest32V2::new(hasher.finalize().into())
}

fn stale_prepared_registry_head_digest(
    query: ExecdQueryV2,
    recorded_head: Digest32V2,
    observed_head: Digest32V2,
) -> Digest32V2 {
    let mut hasher = Sha256::new();
    hasher.update(b"SAVANA_EXECD_STALE_PREPARED_REGISTRY_HEAD_RECOVERY_V2\0");
    hasher.update(query.execution_nonce().as_bytes());
    hasher.update(query.dispatch_core_digest().as_bytes());
    hasher.update(query.dispatch_subject_digest().as_bytes());
    hasher.update(recorded_head.as_bytes());
    hasher.update(observed_head.as_bytes());
    Digest32V2::new(hasher.finalize().into())
}

fn verify_query_binding(
    query: ExecdQueryV2,
    expected_core: Digest32V2,
    expected_subject: Digest32V2,
) -> Result<(), ExecdProtocolServiceErrorV2> {
    if query.dispatch_core_digest() != expected_core
        || query.dispatch_subject_digest() != expected_subject
    {
        return Err(ExecdProtocolServiceErrorV2::Binding);
    }
    Ok(())
}

fn connector_dispatch_for_subject(
    guard: &ExecdConnectorRegistryGuardV2<'_>,
    subject: DispatchSubjectV2,
    task_bound: bool,
) -> Result<Option<PreparedConnectorDispatchV2>, ExecdProtocolServiceErrorV2> {
    let DispatchSubjectV2::ToolExecution { binding, .. } = subject else {
        return Ok(None);
    };
    if task_bound {
        return Ok(Some(PreparedConnectorDispatchV2 {
            descriptor: guard
                .resolve_task_tool_connector(binding.tool_descriptor_digest())
                .map_err(|_| ExecdProtocolServiceErrorV2::Binding)?,
            active_host_allowlist: guard.active_host_allowlist().to_vec(),
        }));
    }
    let connector_id = binding.destination_digest();
    match guard.resolve_active_tool_connector(connector_id, binding.tool_descriptor_digest()) {
        Ok(descriptor) => Ok(Some(PreparedConnectorDispatchV2 {
            descriptor,
            active_host_allowlist: guard.active_host_allowlist().to_vec(),
        })),
        Err(_) if !guard.contains_registered_connector(connector_id) => Ok(None),
        Err(_) => Err(ExecdProtocolServiceErrorV2::Binding),
    }
}

fn signed_receipt_digest(
    receipt: &SignedExecutorEffectStartedReceiptV2,
) -> Result<Digest32V2, ExecdProtocolServiceErrorV2> {
    Ok(receipt.digest())
}
