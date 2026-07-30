use std::time::Instant;

use chacha20poly1305::aead::{Aead as _, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit as _, Nonce};
use hkdf::Hkdf;
use savana_kernel_protocol::v2::{
    decode_executor_completion_payload_v2, encode_acknowledge_committed_completion_response_v2,
    encode_dispatch_response_v2, encode_executor_health_response_v2,
    encode_fetch_completion_response_v2, encode_query_by_execution_nonce_response_v2,
    encode_signed_sealed_execution_envelope_v2, AcknowledgeCommittedCompletionResponseV2,
    Digest32V2, DispatchResponseV2, ExecutorCompletionDescriptorV2, ExecutorHealthResponseV2,
    ExecutorStatusV2, FetchCompletionResponseV2, HpkeX25519KeyIdV2, KernelExecutorOperationV2,
    PublicStableCodeV2, QueryByExecutionNonceResponseV2, SignedExecutorEffectStartedReceiptV2,
    UnixMillisV2,
};
use sha2::{Digest as _, Sha256};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::{
    DispatchEnvelopeKindV2, ExecdJournalStateV2, ExecdQueryV2, ExecdStateOwnerErrorV2,
    ExecdStateOwnerV2, VerifiedExecdDeploymentV2,
};

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
}

pub(crate) trait PreparedDispatchProcessorV2: Send + Sync {
    fn is_ready(&self) -> bool;

    fn process(
        &self,
        owner: &ExecdStateOwnerV2,
        query: ExecdQueryV2,
        payload: Zeroizing<Vec<u8>>,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<(), ExecdProtocolServiceErrorV2>;

    fn recover(
        &self,
        owner: &ExecdStateOwnerV2,
        query: ExecdQueryV2,
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
        if !processor.is_ready() {
            return Err(ExecdProtocolServiceErrorV2::ResultUnavailable);
        }
        let service = Self {
            deployment,
            owner,
            processor,
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

    pub(crate) fn recover_prepared(
        deployment: &ExecdProtocolDeploymentV2,
        owner: &ExecdStateOwnerV2,
        processor: &dyn PreparedDispatchProcessorV2,
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
                    let plaintext =
                        open_execution_payload(envelope.payload(), deployment.seal_private_key)
                            .map_err(|()| ExecdProtocolServiceErrorV2::Binding)?;
                    processor.process(owner, query, plaintext, now, deadline)?;
                }
                ExecdJournalStateV2::ProviderAttemptPrepared
                | ExecdJournalStateV2::EffectStarted
                | ExecdJournalStateV2::ProviderResponseRetained
                | ExecdJournalStateV2::ReleaseEvidencePrepared => {
                    processor.recover(owner, query, now, deadline)?;
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
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<(), ExecdProtocolServiceErrorV2> {
        self.processor
            .process(&self.owner, query, plaintext, now, deadline)
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
                let envelope = encode_signed_sealed_execution_envelope_v2(request.envelope())
                    .map_err(|_| ExecdProtocolServiceErrorV2::Protocol)?;
                let query = self
                    .owner
                    .accept_signed_dispatch(envelope, now, deadline)
                    .map_err(ExecdProtocolServiceErrorV2::Owner)?;
                if query.state() == ExecdJournalStateV2::Prepared {
                    match open_execution_payload(
                        request.envelope().payload(),
                        self.deployment.seal_private_key,
                    ) {
                        Ok(plaintext) => {
                            self.process_dispatch(query, plaintext, now, deadline)?;
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
                    .query(query.execution_nonce(), deadline)
                    .map_err(ExecdProtocolServiceErrorV2::Owner)?;
                let status = self.status(query, deadline)?;
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
                encode_query_by_execution_nonce_response_v2(&QueryByExecutionNonceResponseV2::new(
                    status,
                ))
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
                encode_fetch_completion_response_v2(&response)
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
        let response = ExecutorHealthResponseV2::new(
            self.processor.is_ready(),
            self.deployment.active_state_manifest_digest,
            self.deployment.deployment_generation,
            self.deployment.effect_fence_epoch,
            self.deployment.executor_identity,
            self.deployment.seal_key_id,
            self.deployment.journal_schema_version,
            self.deployment.journal_key_epoch,
            self.deployment.connector_set_digest,
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
    cipher
        .decrypt(
            Nonce::from_slice(&key_nonce[32..]),
            Payload {
                msg: payload.hpke_ciphertext(),
                aad: payload.dispatch_core_digest().as_bytes(),
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| ())
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

fn signed_receipt_digest(
    receipt: &SignedExecutorEffectStartedReceiptV2,
) -> Result<Digest32V2, ExecdProtocolServiceErrorV2> {
    Ok(receipt.digest())
}
