use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Instant;

use savana_kernel_protocol::v2::{Digest32V2, ExecutorFailureClassV2, UnixMillisV2};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::protocol_service::{PreparedConnectorDispatchV2, PreparedDispatchProcessorV2};
use crate::worker_protocol::ConnectorJobDescriptorIssuerV2;
use crate::worker_supervisor::{
    ConnectorWorkerOutcomeV2, ConnectorWorkerSupervisorErrorV2, ConnectorWorkerSupervisorV2,
    OwnerBackedProviderAttemptV2, ProviderTransportV2,
};
use crate::{
    DispatchEnvelopeKindV2, ExecdJournalStateV2, ExecdProtocolServiceErrorV2, ExecdQueryV2,
    ExecdStateOwnerV2,
};

enum VerifiedProviderTransportRouterV2 {
    LegacyShared(Mutex<Box<dyn ProviderTransportV2>>),
    Split {
        tool: Mutex<Box<dyn ProviderTransportV2>>,
        final_release: Mutex<Box<dyn ProviderTransportV2>>,
    },
}

impl VerifiedProviderTransportRouterV2 {
    fn legacy(transport: Box<dyn ProviderTransportV2>) -> Self {
        Self::LegacyShared(Mutex::new(transport))
    }

    fn split(
        tool: Box<dyn ProviderTransportV2>,
        final_release: Box<dyn ProviderTransportV2>,
    ) -> Self {
        Self::Split {
            tool: Mutex::new(tool),
            final_release: Mutex::new(final_release),
        }
    }

    fn with_transport<T>(
        &self,
        kind: DispatchEnvelopeKindV2,
        has_connector: bool,
        operation: impl FnOnce(&mut dyn ProviderTransportV2) -> Result<T, ExecdProtocolServiceErrorV2>,
    ) -> Result<T, ExecdProtocolServiceErrorV2> {
        if !matches!(
            (kind, has_connector),
            (DispatchEnvelopeKindV2::ToolExecution, true)
                | (DispatchEnvelopeKindV2::FinalRelease, false)
        ) {
            return Err(ExecdProtocolServiceErrorV2::Binding);
        }
        let selected = match self {
            Self::LegacyShared(transport) => transport,
            Self::Split {
                tool,
                final_release,
            } => match kind {
                DispatchEnvelopeKindV2::ToolExecution => tool,
                DispatchEnvelopeKindV2::FinalRelease => final_release,
            },
        };
        let mut transport = selected
            .lock()
            .map_err(|_| ExecdProtocolServiceErrorV2::ResultUnavailable)?;
        operation(transport.as_mut())
    }
}

pub(crate) struct VerifiedConnectorExecutionRuntimeV2 {
    supervisor: ConnectorWorkerSupervisorV2,
    issuer: ConnectorJobDescriptorIssuerV2,
    final_release_issuer: Option<ConnectorJobDescriptorIssuerV2>,
    transports: VerifiedProviderTransportRouterV2,
    ready: AtomicBool,
}

impl std::fmt::Debug for VerifiedConnectorExecutionRuntimeV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifiedConnectorExecutionRuntimeV2")
            .field("ready", &self.ready.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

impl VerifiedConnectorExecutionRuntimeV2 {
    pub(crate) fn from_verified_components(
        supervisor: ConnectorWorkerSupervisorV2,
        issuer: ConnectorJobDescriptorIssuerV2,
        transport: Box<dyn ProviderTransportV2>,
    ) -> Self {
        Self {
            supervisor,
            issuer,
            final_release_issuer: None,
            transports: VerifiedProviderTransportRouterV2::legacy(transport),
            ready: AtomicBool::new(true),
        }
    }

    pub(crate) fn from_verified_split_components(
        supervisor: ConnectorWorkerSupervisorV2,
        tool_issuer: ConnectorJobDescriptorIssuerV2,
        final_release_issuer: ConnectorJobDescriptorIssuerV2,
        tool_transport: Box<dyn ProviderTransportV2>,
        final_release_transport: Box<dyn ProviderTransportV2>,
    ) -> Self {
        Self {
            supervisor,
            issuer: tool_issuer,
            final_release_issuer: Some(final_release_issuer),
            transports: VerifiedProviderTransportRouterV2::split(
                tool_transport,
                final_release_transport,
            ),
            ready: AtomicBool::new(true),
        }
    }

    fn process_inner(
        &self,
        owner: &ExecdStateOwnerV2,
        query: ExecdQueryV2,
        payload: Zeroizing<Vec<u8>>,
        connector: Option<&PreparedConnectorDispatchV2>,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<(), ExecdProtocolServiceErrorV2> {
        if query.state() != ExecdJournalStateV2::Prepared
            || payload.is_empty()
            || now.get() == 0
            || Instant::now() >= deadline
        {
            return Err(ExecdProtocolServiceErrorV2::Binding);
        }
        let result =
            self.transports
                .with_transport(query.kind(), connector.is_some(), |transport| {
                    self.process_with_transport(
                        owner, query, payload, connector, now, deadline, transport,
                    )
                });
        if matches!(result, Err(ExecdProtocolServiceErrorV2::ResultUnavailable)) {
            self.ready.store(false, Ordering::Release);
        }
        result
    }

    fn issuer_for(
        &self,
        kind: DispatchEnvelopeKindV2,
    ) -> Result<&ConnectorJobDescriptorIssuerV2, ExecdProtocolServiceErrorV2> {
        match kind {
            DispatchEnvelopeKindV2::ToolExecution => Ok(&self.issuer),
            DispatchEnvelopeKindV2::FinalRelease => {
                Ok(self.final_release_issuer.as_ref().unwrap_or(&self.issuer))
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn process_with_transport(
        &self,
        owner: &ExecdStateOwnerV2,
        query: ExecdQueryV2,
        payload: Zeroizing<Vec<u8>>,
        connector: Option<&PreparedConnectorDispatchV2>,
        now: UnixMillisV2,
        deadline: Instant,
        transport: &mut dyn ProviderTransportV2,
    ) -> Result<(), ExecdProtocolServiceErrorV2> {
        let target = match connector {
            Some(connector) => transport.verify_connector_target(
                connector.descriptor().tier(),
                connector.descriptor().transport(),
                connector.active_host_allowlist(),
            ),
            None => transport.verified_deployment_target(),
        }
        .map_err(|_| ExecdProtocolServiceErrorV2::Binding)?;
        let descriptor_deadline = UnixMillisV2::new(
            now.get()
                .checked_add(30_000)
                .ok_or(ExecdProtocolServiceErrorV2::Binding)?,
        );
        let (descriptor, ephemeral_seed) = self
            .issuer_for(query.kind())?
            .issue_prepare(
                query.execution_nonce(),
                query.dispatch_core_digest(),
                query.dispatch_subject_digest(),
                &payload,
                descriptor_deadline,
            )
            .map_err(|_| ExecdProtocolServiceErrorV2::Binding)?;
        let mut provider = OwnerBackedProviderAttemptV2::new(owner, transport, &target, now);
        let outcome = self.supervisor.prepare_and_decode(
            &descriptor,
            payload,
            ephemeral_seed,
            now,
            deadline,
            &mut provider,
        );
        match outcome {
            Ok(ConnectorWorkerOutcomeV2::FailedBeforeEffect) => {
                owner
                    .record_failed_no_effect(
                        query.execution_nonce(),
                        ExecutorFailureClassV2::ConnectorRejectedBeforeEffect,
                        domain_digest(b"SAVANA_CONNECTOR_REJECTED_BEFORE_EFFECT_V2\0", &descriptor),
                        now,
                        deadline,
                    )
                    .map_err(ExecdProtocolServiceErrorV2::Owner)?;
                Ok(())
            }
            Ok(ConnectorWorkerOutcomeV2::Completion {
                result,
                result_digest,
            }) => self.complete(owner, query, result, result_digest, now, deadline),
            Ok(ConnectorWorkerOutcomeV2::Indeterminate) => {
                owner
                    .record_indeterminate(
                        query.execution_nonce(),
                        domain_digest(b"SAVANA_CONNECTOR_INDETERMINATE_V2\0", &descriptor),
                        now,
                        deadline,
                    )
                    .map_err(ExecdProtocolServiceErrorV2::Owner)?;
                Ok(())
            }
            Err(error) => self.terminalize_worker_error(owner, query, error, now, deadline),
        }
    }

    fn complete(
        &self,
        owner: &ExecdStateOwnerV2,
        query: ExecdQueryV2,
        result: Zeroizing<Vec<u8>>,
        result_digest: Digest32V2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<(), ExecdProtocolServiceErrorV2> {
        match query.kind() {
            DispatchEnvelopeKindV2::ToolExecution => {
                owner
                    .record_tool_completion(
                        query.execution_nonce(),
                        result.to_vec(),
                        result_digest,
                        now,
                        deadline,
                    )
                    .map_err(ExecdProtocolServiceErrorV2::Owner)?;
            }
            DispatchEnvelopeKindV2::FinalRelease => {
                let effect_receipt = owner
                    .effect_started_receipt(query.execution_nonce(), deadline)
                    .map_err(ExecdProtocolServiceErrorV2::Owner)?;
                let mut audit = minicbor::Encoder::new(Vec::new());
                audit
                    .array(7)
                    .and_then(|encoder| encoder.u16(2))
                    .and_then(|encoder| encoder.bytes(query.execution_nonce().as_bytes()))
                    .and_then(|encoder| encoder.bytes(query.dispatch_core_digest().as_bytes()))
                    .and_then(|encoder| encoder.bytes(query.dispatch_subject_digest().as_bytes()))
                    .and_then(|encoder| encoder.bytes(effect_receipt.digest().as_bytes()))
                    .and_then(|encoder| encoder.bytes(result_digest.as_bytes()))
                    .and_then(|encoder| encoder.u64(now.get()))
                    .map_err(|_| ExecdProtocolServiceErrorV2::ResultUnavailable)?;
                owner
                    .prepare_final_release_evidence(
                        query.execution_nonce(),
                        result.to_vec(),
                        audit.into_writer(),
                        now,
                        deadline,
                    )
                    .map_err(ExecdProtocolServiceErrorV2::Owner)?;
                owner
                    .record_final_release_completion(query.execution_nonce(), now, deadline)
                    .map_err(ExecdProtocolServiceErrorV2::Owner)?;
            }
        }
        Ok(())
    }

    fn terminalize_worker_error(
        &self,
        owner: &ExecdStateOwnerV2,
        query: ExecdQueryV2,
        error: ConnectorWorkerSupervisorErrorV2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<(), ExecdProtocolServiceErrorV2> {
        let current = owner
            .query(query.execution_nonce(), deadline)
            .map_err(ExecdProtocolServiceErrorV2::Owner)?;
        let evidence = worker_error_digest(query, error);
        match current.state() {
            ExecdJournalStateV2::Prepared | ExecdJournalStateV2::ProviderAttemptPrepared => {
                owner
                    .record_failed_no_effect(
                        query.execution_nonce(),
                        ExecutorFailureClassV2::ConnectorUnavailableBeforeEffect,
                        evidence,
                        now,
                        deadline,
                    )
                    .map_err(ExecdProtocolServiceErrorV2::Owner)?;
            }
            ExecdJournalStateV2::EffectStarted
            | ExecdJournalStateV2::ProviderResponseRetained
            | ExecdJournalStateV2::ReleaseEvidencePrepared => {
                owner
                    .record_indeterminate(query.execution_nonce(), evidence, now, deadline)
                    .map_err(ExecdProtocolServiceErrorV2::Owner)?;
            }
            ExecdJournalStateV2::CompletionAvailable
            | ExecdJournalStateV2::FailedNoEffect
            | ExecdJournalStateV2::Indeterminate
            | ExecdJournalStateV2::Acknowledged => {}
        }
        Ok(())
    }

    fn recover_inner(
        &self,
        owner: &ExecdStateOwnerV2,
        query: ExecdQueryV2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<(), ExecdProtocolServiceErrorV2> {
        match query.state() {
            ExecdJournalStateV2::ProviderAttemptPrepared | ExecdJournalStateV2::EffectStarted => {
                owner
                    .record_indeterminate_recovery(
                        query.execution_nonce(),
                        domain_digest(
                            b"SAVANA_CONNECTOR_CRASH_WITHOUT_RETAINED_RESPONSE_V2\0",
                            query.dispatch_core_digest().as_bytes(),
                        ),
                        now,
                        deadline,
                    )
                    .map_err(ExecdProtocolServiceErrorV2::Owner)?;
                Ok(())
            }
            ExecdJournalStateV2::ProviderResponseRetained => {
                let retained = owner
                    .retained_provider_response(query.execution_nonce(), deadline)
                    .map_err(ExecdProtocolServiceErrorV2::Owner)?;
                let effect_receipt = owner
                    .effect_started_receipt(query.execution_nonce(), deadline)
                    .map_err(ExecdProtocolServiceErrorV2::Owner)?;
                let descriptor_deadline = UnixMillisV2::new(
                    now.get()
                        .checked_add(30_000)
                        .ok_or(ExecdProtocolServiceErrorV2::Binding)?,
                );
                let (descriptor, ephemeral_seed) = self
                    .issuer_for(query.kind())?
                    .issue_decode_retained(
                        query.execution_nonce(),
                        query.dispatch_core_digest(),
                        query.dispatch_subject_digest(),
                        query
                            .prepared_request_digest()
                            .ok_or(ExecdProtocolServiceErrorV2::Binding)?,
                        retained.bytes(),
                        effect_receipt.digest(),
                        descriptor_deadline,
                    )
                    .map_err(|_| ExecdProtocolServiceErrorV2::Binding)?;
                match self.supervisor.decode_retained_response(
                    &descriptor,
                    retained.into_bytes(),
                    ephemeral_seed,
                    effect_receipt.digest(),
                    now,
                    deadline,
                ) {
                    Ok(ConnectorWorkerOutcomeV2::Completion {
                        result,
                        result_digest,
                    }) => self.complete(owner, query, result, result_digest, now, deadline),
                    Ok(ConnectorWorkerOutcomeV2::FailedBeforeEffect)
                    | Ok(ConnectorWorkerOutcomeV2::Indeterminate)
                    | Err(_) => {
                        owner
                            .record_indeterminate_recovery(
                                query.execution_nonce(),
                                domain_digest(
                                    b"SAVANA_CONNECTOR_RETAINED_RESPONSE_DECODE_FAILED_V2\0",
                                    &descriptor,
                                ),
                                now,
                                deadline,
                            )
                            .map_err(ExecdProtocolServiceErrorV2::Owner)?;
                        Ok(())
                    }
                }
            }
            ExecdJournalStateV2::ReleaseEvidencePrepared => {
                owner
                    .record_final_release_completion(query.execution_nonce(), now, deadline)
                    .map_err(ExecdProtocolServiceErrorV2::Owner)?;
                Ok(())
            }
            ExecdJournalStateV2::Prepared
            | ExecdJournalStateV2::CompletionAvailable
            | ExecdJournalStateV2::FailedNoEffect
            | ExecdJournalStateV2::Indeterminate
            | ExecdJournalStateV2::Acknowledged => Err(ExecdProtocolServiceErrorV2::Binding),
        }
    }
}

impl PreparedDispatchProcessorV2 for VerifiedConnectorExecutionRuntimeV2 {
    fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }

    fn process(
        &self,
        owner: &ExecdStateOwnerV2,
        query: ExecdQueryV2,
        payload: Zeroizing<Vec<u8>>,
        connector: Option<&PreparedConnectorDispatchV2>,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<(), ExecdProtocolServiceErrorV2> {
        self.process_inner(owner, query, payload, connector, now, deadline)
    }

    fn recover(
        &self,
        owner: &ExecdStateOwnerV2,
        query: ExecdQueryV2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<(), ExecdProtocolServiceErrorV2> {
        self.recover_inner(owner, query, now, deadline)
    }
}

fn worker_error_digest(query: ExecdQueryV2, error: ConnectorWorkerSupervisorErrorV2) -> Digest32V2 {
    let tag = match error {
        ConnectorWorkerSupervisorErrorV2::SandboxUnavailable => 1_u16,
        ConnectorWorkerSupervisorErrorV2::LaunchFailed => 2,
        ConnectorWorkerSupervisorErrorV2::DeadlineExceeded => 3,
        ConnectorWorkerSupervisorErrorV2::ProtocolViolation => 4,
        ConnectorWorkerSupervisorErrorV2::Protocol(_) => 5,
        ConnectorWorkerSupervisorErrorV2::ProviderAttemptFailed => 6,
    };
    let mut hasher = Sha256::new();
    hasher.update(b"SAVANA_CONNECTOR_WORKER_ERROR_V2\0");
    hasher.update(query.execution_nonce().as_bytes());
    hasher.update(query.dispatch_core_digest().as_bytes());
    hasher.update(query.dispatch_subject_digest().as_bytes());
    hasher.update(tag.to_be_bytes());
    Digest32V2::new(hasher.finalize().into())
}

fn domain_digest(domain: &[u8], bytes: &[u8]) -> Digest32V2 {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    Digest32V2::new(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use savana_policy_core::v2::{
        BoundedConnectorHostV2, BoundedConnectorUrlV2, ConnectorTierV2, ConnectorTransportV2,
    };

    use super::*;
    use crate::worker_supervisor::{VerifiedProviderRequestV2, VerifiedProviderTargetV2};
    use crate::EffectPermitV2;

    struct RecordingTransportV2 {
        target: VerifiedProviderTargetV2,
        calls: Arc<AtomicUsize>,
    }

    impl RecordingTransportV2 {
        fn new(url: &str, marker: u8, calls: Arc<AtomicUsize>) -> Self {
            Self {
                target: VerifiedProviderTargetV2::https(
                    BoundedConnectorUrlV2::new(url).unwrap(),
                    Digest32V2::new([marker; 32]),
                )
                .unwrap(),
                calls,
            }
        }
    }

    impl ProviderTransportV2 for RecordingTransportV2 {
        fn verified_deployment_target(
            &self,
        ) -> Result<VerifiedProviderTargetV2, ConnectorWorkerSupervisorErrorV2> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Ok(self.target.clone())
        }

        fn verify_connector_target(
            &self,
            _tier: ConnectorTierV2,
            _transport: &ConnectorTransportV2,
            _active_host_allowlist: &[BoundedConnectorHostV2],
        ) -> Result<VerifiedProviderTargetV2, ConnectorWorkerSupervisorErrorV2> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Ok(self.target.clone())
        }

        fn execute(
            &mut self,
            _request: &VerifiedProviderRequestV2,
            _permit: &EffectPermitV2,
            _maximum_response_bytes: u32,
            _deadline: Instant,
        ) -> Result<Vec<u8>, ConnectorWorkerSupervisorErrorV2> {
            unreachable!("routing tests do not execute provider requests")
        }
    }

    #[test]
    fn split_router_selects_manifest_bound_transport_by_dispatch_kind() {
        let tool_calls = Arc::new(AtomicUsize::new(0));
        let release_calls = Arc::new(AtomicUsize::new(0));
        let router = VerifiedProviderTransportRouterV2::split(
            Box::new(RecordingTransportV2::new(
                "https://tool.example:9444/mcp",
                1,
                Arc::clone(&tool_calls),
            )),
            Box::new(RecordingTransportV2::new(
                "https://release.example:43191/savana/final-release",
                2,
                Arc::clone(&release_calls),
            )),
        );

        let tool_url = router
            .with_transport(DispatchEnvelopeKindV2::ToolExecution, true, |transport| {
                Ok(transport
                    .verified_deployment_target()
                    .map_err(|_| ExecdProtocolServiceErrorV2::Binding)?
                    .canonical_url()
                    .as_str()
                    .to_owned())
            })
            .unwrap();
        let release_url = router
            .with_transport(DispatchEnvelopeKindV2::FinalRelease, false, |transport| {
                Ok(transport
                    .verified_deployment_target()
                    .map_err(|_| ExecdProtocolServiceErrorV2::Binding)?
                    .canonical_url()
                    .as_str()
                    .to_owned())
            })
            .unwrap();

        assert_eq!(tool_url, "https://tool.example:9444/mcp");
        assert_eq!(
            release_url,
            "https://release.example:43191/savana/final-release"
        );
        assert_eq!(tool_calls.load(Ordering::Relaxed), 1);
        assert_eq!(release_calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn split_router_rejects_kind_connector_mismatch_before_transport_access() {
        let tool_calls = Arc::new(AtomicUsize::new(0));
        let release_calls = Arc::new(AtomicUsize::new(0));
        let router = VerifiedProviderTransportRouterV2::split(
            Box::new(RecordingTransportV2::new(
                "https://tool.example:9444/mcp",
                1,
                Arc::clone(&tool_calls),
            )),
            Box::new(RecordingTransportV2::new(
                "https://release.example:43191/savana/final-release",
                2,
                Arc::clone(&release_calls),
            )),
        );

        for (kind, has_connector) in [
            (DispatchEnvelopeKindV2::ToolExecution, false),
            (DispatchEnvelopeKindV2::FinalRelease, true),
        ] {
            assert_eq!(
                router.with_transport(kind, has_connector, |_| Ok(())),
                Err(ExecdProtocolServiceErrorV2::Binding)
            );
        }
        assert_eq!(tool_calls.load(Ordering::Relaxed), 0);
        assert_eq!(release_calls.load(Ordering::Relaxed), 0);
    }
}
