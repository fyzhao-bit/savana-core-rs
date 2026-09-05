use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use savana_kernel_protocol::v2::{
    encode_abort_input_response_v2, encode_append_input_chunk_response_v2,
    encode_append_parser_worker_page_frame_response_v2,
    encode_apply_approved_connector_registration_response_v2,
    encode_authenticate_agent_ui_response_v2, encode_authenticate_ingress_ui_response_v2,
    encode_authorize_connector_registration_response_v2, encode_authorize_release_response_v2,
    encode_authorize_tool_call_response_v2, encode_begin_input_response_v2,
    encode_cancel_kernel_task_response_v2, encode_claim_agent_session_response_v2,
    encode_close_agent_session_response_v2, encode_commit_input_settlement_response_v2,
    encode_commit_parser_worker_result_response_v2, encode_commit_planner_value_response_v2,
    encode_connector_registry_snapshot_response_v2, encode_derive_value_response_v2,
    encode_dispatch_execution_response_v2, encode_dispatch_release_response_v2,
    encode_evaluate_tool_call_response_v2, encode_finalize_input_response_v2,
    encode_get_agent_session_status_response_v2, encode_get_execution_status_response_v2,
    encode_get_input_status_response_v2, encode_get_kernel_task_status_response_v2,
    encode_get_release_status_response_v2, encode_kernel_agent_health_response_v2,
    encode_kernel_agent_operation_v2, encode_kernel_ingress_health_response_v2,
    encode_kernel_ingress_operation_v2, encode_prepare_agent_ui_authentication_response_v2,
    encode_prepare_connector_registration_response_v2,
    encode_prepare_connector_removal_response_v2, encode_prepare_followup_ingress_response_v2,
    encode_prepare_ingress_ui_authentication_response_v2, encode_prepare_new_ingress_response_v2,
    encode_prepare_planner_call_response_v2, encode_prepare_release_response_v2,
    encode_propose_connector_registration_response_v2, encode_propose_tool_call_response_v2,
    encode_read_agent_view_response_v2, encode_register_parser_worker_job_response_v2,
    encode_remove_connector_response_v2, encode_resume_committed_agent_authentication_response_v2,
    encode_revoke_vault_response_v2, AbortInputResponseV2, AppendInputChunkResponseV2,
    AppendParserWorkerPageFrameResponseV2, ApplyApprovedConnectorRegistrationResponseV2,
    AuthenticateAgentUiResponseV2, AuthenticateIngressUiResponseV2,
    AuthorizeConnectorRegistrationResponseV2, BeginInputResponseV2, BootIdV2,
    BoundedConnectorRegistrySnapshotV2, CloseAgentSessionResponseV2,
    CommitInputSettlementResponseV2, CommitParserWorkerResultResponseV2,
    ConnectorRegistrySnapshotResponseV2, DeriveValueResponseV2, Digest32V2, DurableTaskIdV2,
    FinalizeInputResponseV2, GetInputStatusResponseV2, InputNextSequenceV2, InputPublicStateV2,
    InputStatusTargetV2, KernelAgentHealthResponseV2, KernelAgentOperationV2,
    KernelConnectorControlOperationV2, KernelIngressHealthResponseV2, KernelIngressOperationV2,
    KernelServiceOperationV2, MaskedDocumentHandleV2, PeerIdentityBindingV2,
    PrepareConnectorRemovalResponseV2, PrepareIngressUiAuthenticationResponseV2, PrincipalIdV2,
    PublicServiceStateV2, ReadAgentViewResponseV2, RegisterParserWorkerJobResponseV2,
    RemoveConnectorResponseV2, RequestIdV2, ServiceIdentityV2, UnixMillisV2, VaultPublicStateV2,
};
use savana_kernel_protocol::StableCode;
use sha2::{Digest as _, Sha256};

use crate::v2_agent_authority::{
    KernelAgentAuthorityErrorV2, KernelAgentAuthorityV2, PreparedAgentClaimMaterialV2,
};
use crate::v2_connector_authority::{KernelConnectorAuthorityErrorV2, KernelConnectorAuthorityV2};
use crate::v2_dispatch::{
    KernelRuntimeResponseBuilderV2, KernelRuntimeResponsePreparationErrorV2,
    KernelServiceResponseBodyV2, PreparedKernelServiceResponseV2,
};
use crate::v2_ingress_authority::{
    FinalizeRecoveryIdentityV2, KernelIngressAuthorityErrorV2, KernelIngressAuthorityV2,
    KernelPendingIngressStateV2, VerifiedIngressSettlementDecisionV2,
};
use crate::v2_input_owner::{
    FinalizedKernelInputV2, KernelInputErrorV2, KernelInputFinalizeTransactionErrorV2,
    KernelInputOwnerV2, KernelInputPublicStateV2, KernelParserTrustV2,
};
use crate::v2_kernel_owner::{KernelRuntimeRequestV2, KernelRuntimeServicesV2};
use crate::v2_state_owner::{StateOwnerCommitV2, StateOwnerErrorV2};
use crate::v2_value_owner::{KernelValueErrorV2, KernelValueOwnerV2};

const REQUIRED_AGENT_KERNEL_ROUTES_V2: usize = 27;
const REQUIRED_INGRESS_KERNEL_ROUTES_V2: usize = 16;
const IMPLEMENTED_AGENT_KERNEL_ROUTES_V2: usize = 27;
const IMPLEMENTED_INGRESS_KERNEL_ROUTES_V2: usize = 16;

pub(crate) trait KernelIngressCommitSinkV2: Send + 'static {
    #[allow(clippy::too_many_arguments)]
    fn commit(
        &mut self,
        durable_task_id: DurableTaskIdV2,
        principal: PrincipalIdV2,
        finalized: &FinalizedKernelInputV2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        now: UnixMillisV2,
    ) -> Result<PreparedAgentClaimMaterialV2, StableCode>;

    fn read_agent_view(
        &mut self,
        document: MaskedDocumentHandleV2,
        maximum_encoded_bytes: u32,
        now: UnixMillisV2,
    ) -> Result<ReadAgentViewResponseV2, StableCode>;

    fn revoke_vault(
        &mut self,
        document: MaskedDocumentHandleV2,
        now: UnixMillisV2,
    ) -> Result<VaultPublicStateV2, StableCode>;

    fn read_release_payload(
        &mut self,
        document: MaskedDocumentHandleV2,
        durable_run_id: savana_kernel_protocol::v2::DurableRunIdV2,
        now: UnixMillisV2,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, StableCode>;

    fn prepare_release(
        &mut self,
        document: MaskedDocumentHandleV2,
        durable_run_id: savana_kernel_protocol::v2::DurableRunIdV2,
        material: savana_vault::VaultReleaseMaterialV2,
        now: UnixMillisV2,
    ) -> Result<savana_vault::PendingVaultReleaseV2, StableCode>;

    fn authorize_release(
        &mut self,
        pending: savana_vault::PendingVaultReleaseV2,
        approval: savana_vault::VerifiedFinalReleaseApprovalV2,
        now: UnixMillisV2,
    ) -> Result<savana_vault::AuthorizedVaultReleaseV2, StableCode>;

    fn mark_release_dispatch_prepared(
        &mut self,
        authorized: savana_vault::AuthorizedVaultReleaseV2,
        commit: savana_vault::KernelPreparedReleaseDispatchV2,
        now: UnixMillisV2,
    ) -> Result<savana_vault::VaultDispatchPreparedV2, StableCode>;

    fn mark_release_dispatching(
        &mut self,
        prepared: savana_vault::VaultDispatchPreparedV2,
        now: UnixMillisV2,
    ) -> Result<(), StableCode>;

    fn commit_known_release(
        &mut self,
        prepared: savana_vault::VaultDispatchPreparedV2,
        final_release_receipt_digest: Digest32V2,
        release_audit_digest: Digest32V2,
        now: UnixMillisV2,
    ) -> Result<(), StableCode>;

    fn mark_release_failed_no_effect(
        &mut self,
        durable_release_id: savana_kernel_protocol::v2::DurableReleaseIdV2,
        execution_nonce: savana_kernel_protocol::v2::Nonce32V2,
        dispatch_core_digest: Digest32V2,
        dispatch_subject_digest: Digest32V2,
        now: UnixMillisV2,
    ) -> Result<(), StableCode>;

    fn mark_release_indeterminate(
        &mut self,
        prepared: savana_vault::VaultDispatchPreparedV2,
        now: UnixMillisV2,
    ) -> Result<(), StableCode>;

    #[allow(clippy::too_many_arguments)]
    fn commit_tool_result(
        &mut self,
        durable_task_id: DurableTaskIdV2,
        durable_run_id: savana_kernel_protocol::v2::DurableRunIdV2,
        principal: PrincipalIdV2,
        provenance: savana_policy_core::v2::ProvenanceRecordV2,
        executor_commit_digest: Digest32V2,
        result: Vec<u8>,
        expires_at: UnixMillisV2,
        now: UnixMillisV2,
    ) -> Result<MaskedDocumentHandleV2, StableCode>;
}

pub(crate) struct CoreKernelRuntimeServicesV2 {
    input: KernelInputOwnerV2,
    values: KernelValueOwnerV2,
    agent_authority: Option<KernelAgentAuthorityV2>,
    connector_authority: Option<KernelConnectorAuthorityV2>,
    ingress_authority: Option<KernelIngressAuthorityV2>,
    ingress_commit_sink: Option<Box<dyn KernelIngressCommitSinkV2>>,
    parser_trust: Option<KernelParserTrustV2>,
    readiness: Arc<AtomicBool>,
    #[cfg(test)]
    finalize_linearization_hook: Option<FinalizeLinearizationHookV2>,
}

#[cfg(test)]
struct FinalizeLinearizationHookV2 {
    before_commit_reached: std::sync::mpsc::SyncSender<()>,
    release_before_commit: std::sync::mpsc::Receiver<()>,
    after_publish_reached: std::sync::mpsc::SyncSender<()>,
    release_after_publish: std::sync::mpsc::Receiver<()>,
    panic_before_commit: bool,
    panic_after_claim: bool,
    panic_after_publish: bool,
}

#[cfg(test)]
impl FinalizeLinearizationHookV2 {
    fn before_commit(&self) {
        let _ = self.before_commit_reached.send(());
        self.release_before_commit.recv().unwrap();
        assert!(!self.panic_before_commit, "test panic before commit claim");
    }

    fn after_claim(&self) {
        assert!(!self.panic_after_claim, "test panic after commit claim");
    }

    fn after_publish(&self) {
        let _ = self.after_publish_reached.send(());
        self.release_after_publish.recv().unwrap();
        assert!(
            !self.panic_after_publish,
            "test panic after durable publication"
        );
    }
}

#[derive(Clone)]
pub(crate) struct KernelReadinessAuthorityV2 {
    ready: Arc<AtomicBool>,
}

impl std::fmt::Debug for KernelReadinessAuthorityV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("KernelReadinessAuthorityV2(<write-once>)")
    }
}

impl KernelReadinessAuthorityV2 {
    pub(crate) fn publish_ready(&self) -> Result<(), StableCode> {
        self.ready
            .compare_exchange(false, true, Ordering::Release, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| StableCode::KernelUnavailable)
    }
}

impl std::fmt::Debug for CoreKernelRuntimeServicesV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CoreKernelRuntimeServicesV2(<private-state>)")
    }
}

impl CoreKernelRuntimeServicesV2 {
    pub(crate) fn new_production_starting(
        maximum_input_sessions: usize,
        maximum_input_bytes: usize,
        maximum_runs: usize,
        maximum_values: usize,
    ) -> Result<(Self, KernelReadinessAuthorityV2), StableCode> {
        if IMPLEMENTED_AGENT_KERNEL_ROUTES_V2 != REQUIRED_AGENT_KERNEL_ROUTES_V2
            || IMPLEMENTED_INGRESS_KERNEL_ROUTES_V2 != REQUIRED_INGRESS_KERNEL_ROUTES_V2
        {
            return Err(StableCode::KernelUnavailable);
        }
        Self::new_starting(
            maximum_input_sessions,
            maximum_input_bytes,
            maximum_runs,
            maximum_values,
        )
    }

    #[cfg(test)]
    pub(crate) fn new(
        maximum_input_sessions: usize,
        maximum_input_bytes: usize,
        maximum_runs: usize,
        maximum_values: usize,
    ) -> Result<Self, StableCode> {
        Self::new_starting(
            maximum_input_sessions,
            maximum_input_bytes,
            maximum_runs,
            maximum_values,
        )
        .map(|(services, _readiness)| services)
    }

    pub(crate) fn new_starting(
        maximum_input_sessions: usize,
        maximum_input_bytes: usize,
        maximum_runs: usize,
        maximum_values: usize,
    ) -> Result<(Self, KernelReadinessAuthorityV2), StableCode> {
        let readiness = Arc::new(AtomicBool::new(false));
        let authority = KernelReadinessAuthorityV2 {
            ready: Arc::clone(&readiness),
        };
        Ok((
            Self {
                input: KernelInputOwnerV2::new(maximum_input_sessions, maximum_input_bytes)
                    .map_err(map_input_error)?,
                values: KernelValueOwnerV2::new(maximum_runs, maximum_values)
                    .map_err(map_value_error)?,
                agent_authority: None,
                connector_authority: None,
                ingress_authority: None,
                ingress_commit_sink: None,
                parser_trust: None,
                readiness,
                #[cfg(test)]
                finalize_linearization_hook: None,
            },
            authority,
        ))
    }

    pub(crate) fn install_ingress_security(
        &mut self,
        authority: KernelIngressAuthorityV2,
        sink: Box<dyn KernelIngressCommitSinkV2>,
    ) -> Result<(), StableCode> {
        if self.ingress_authority.replace(authority).is_some()
            || self.ingress_commit_sink.replace(sink).is_some()
        {
            return Err(StableCode::PolicyDenied);
        }
        Ok(())
    }

    pub(crate) fn install_parser_trust(
        &mut self,
        trust: KernelParserTrustV2,
    ) -> Result<(), StableCode> {
        if self.parser_trust.replace(trust).is_some() {
            return Err(StableCode::PolicyDenied);
        }
        Ok(())
    }

    pub(crate) fn install_agent_security(
        &mut self,
        authority: KernelAgentAuthorityV2,
    ) -> Result<(), StableCode> {
        if self.agent_authority.replace(authority).is_some() {
            return Err(StableCode::PolicyDenied);
        }
        Ok(())
    }

    pub(crate) fn install_connector_authority(
        &mut self,
        authority: KernelConnectorAuthorityV2,
    ) -> Result<(), StableCode> {
        if self.connector_authority.replace(authority).is_some() {
            return Err(StableCode::PolicyDenied);
        }
        Ok(())
    }

    pub(crate) fn verify_production_complete(&self) -> Result<(), StableCode> {
        if !self
            .agent_authority
            .as_ref()
            .is_some_and(KernelAgentAuthorityV2::production_ready)
            || self.connector_authority.is_none()
            || self.ingress_authority.is_none()
            || self.ingress_commit_sink.is_none()
            || self.parser_trust.is_none()
            || self.readiness.load(Ordering::Acquire)
        {
            return Err(StableCode::KernelUnavailable);
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    #[cfg(test)]
    fn execute_operation(
        &mut self,
        request_id: RequestIdV2,
        operation: KernelServiceOperationV2,
        now: UnixMillisV2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        effect_fence_epoch: u64,
        caller_identity: ServiceIdentityV2,
    ) -> Result<KernelServiceResponseBodyV2, StableCode> {
        match self.execute_operation_prepared(
            request_id,
            UnixMillisV2::new(u64::MAX),
            operation,
            now,
            active_state_manifest_digest,
            deployment_generation,
            effect_fence_epoch,
            BootIdV2::new(*caller_identity.as_bytes()),
            caller_identity,
            PeerIdentityBindingV2::linux(501, 502, 503, 504, Digest32V2::new([0xf3; 32]))
                .expect("fixed test peer binding"),
            KernelRuntimeResponseBuilderV2::Body,
            None,
        ) {
            Ok(PreparedKernelServiceResponseV2::Body(outcome)) => outcome,
            Ok(_) => Err(StableCode::KernelUnavailable),
            Err(KernelRuntimeResponsePreparationErrorV2::DeadlineExceeded) => {
                Err(StableCode::DeadlineExceeded)
            }
            Err(KernelRuntimeResponsePreparationErrorV2::Unavailable) => {
                Err(StableCode::KernelUnavailable)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn execute_operation_prepared(
        &mut self,
        request_id: RequestIdV2,
        logical_deadline: UnixMillisV2,
        operation: KernelServiceOperationV2,
        now: UnixMillisV2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        effect_fence_epoch: u64,
        caller_boot_id: BootIdV2,
        caller_identity: ServiceIdentityV2,
        caller_observed_peer: PeerIdentityBindingV2,
        response_builder: KernelRuntimeResponseBuilderV2,
        commit: Option<&StateOwnerCommitV2>,
    ) -> Result<PreparedKernelServiceResponseV2, KernelRuntimeResponsePreparationErrorV2> {
        if let KernelServiceOperationV2::Ingress(KernelIngressOperationV2::FinalizeInput(request)) =
            operation
        {
            return self.execute_finalize_input_prepared(
                request,
                request_id,
                logical_deadline,
                now,
                active_state_manifest_digest,
                deployment_generation,
                effect_fence_epoch,
                caller_boot_id,
                caller_identity,
                caller_observed_peer,
                response_builder,
                commit,
            );
        }
        response_builder.prepare(self.execute_operation_body(
            request_id,
            operation,
            now,
            active_state_manifest_digest,
            deployment_generation,
            effect_fence_epoch,
            caller_boot_id,
            caller_identity,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn execute_operation_body(
        &mut self,
        request_id: RequestIdV2,
        operation: KernelServiceOperationV2,
        now: UnixMillisV2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        effect_fence_epoch: u64,
        caller_boot_id: BootIdV2,
        caller_identity: ServiceIdentityV2,
    ) -> Result<KernelServiceResponseBodyV2, StableCode> {
        match operation {
            KernelServiceOperationV2::Agent(operation) => self.execute_agent(
                request_id,
                operation,
                now,
                active_state_manifest_digest,
                deployment_generation,
                effect_fence_epoch,
                caller_identity,
            ),
            KernelServiceOperationV2::Ingress(operation) => self.execute_ingress(
                operation,
                now,
                active_state_manifest_digest,
                deployment_generation,
                caller_identity,
            ),
            KernelServiceOperationV2::Connector(operation) => self.execute_connector_control(
                operation,
                caller_boot_id,
                now,
                active_state_manifest_digest,
                deployment_generation,
                caller_identity,
            ),
            KernelServiceOperationV2::Executor(_) => Err(StableCode::IdentityPeerRejected),
        }
    }

    fn execute_connector_control(
        &mut self,
        operation: KernelConnectorControlOperationV2,
        caller_boot_id: BootIdV2,
        now: UnixMillisV2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        caller_identity: ServiceIdentityV2,
    ) -> Result<KernelServiceResponseBodyV2, StableCode> {
        let agent_authority = self
            .agent_authority
            .as_mut()
            .ok_or(StableCode::KernelUnavailable)?;
        let canonical = match operation {
            KernelConnectorControlOperationV2::PrepareRegistration(request) => {
                let response = agent_authority
                    .prepare_connector_registration(
                        &request,
                        caller_boot_id,
                        caller_identity,
                        active_state_manifest_digest,
                        deployment_generation,
                        now,
                    )
                    .map_err(map_agent_authority_error)?;
                encode_prepare_connector_registration_response_v2(response)
            }
            KernelConnectorControlOperationV2::ProposeRegistration(request) => {
                let response = self
                    .connector_authority
                    .as_mut()
                    .ok_or(StableCode::KernelUnavailable)?
                    .propose_add(
                        &request,
                        agent_authority,
                        &self.values,
                        caller_boot_id,
                        caller_identity,
                        active_state_manifest_digest,
                        deployment_generation,
                        now,
                    )
                    .map_err(|error| map_connector_authority_error_for_tag(71, error))?;
                encode_propose_connector_registration_response_v2(&response)
            }
            KernelConnectorControlOperationV2::AuthorizeRegistration(request) => {
                let approved = self
                    .connector_authority
                    .as_mut()
                    .ok_or(StableCode::KernelUnavailable)?
                    .authorize_add(
                        request.pending(),
                        request.settlement(),
                        agent_authority,
                        active_state_manifest_digest,
                        deployment_generation,
                        now,
                    )
                    .map_err(|error| map_connector_authority_error_for_tag(72, error))?;
                encode_authorize_connector_registration_response_v2(
                    AuthorizeConnectorRegistrationResponseV2::new(approved),
                )
            }
            KernelConnectorControlOperationV2::ApplyApprovedRegistration(request) => {
                let result = self
                    .connector_authority
                    .as_mut()
                    .ok_or(StableCode::KernelUnavailable)?
                    .apply_approved_add(
                        request.approved(),
                        agent_authority,
                        active_state_manifest_digest,
                        deployment_generation,
                    )
                    .map_err(|error| map_connector_authority_error_for_tag(73, error))?;
                agent_authority
                    .synchronize_executor_connector_registry(
                        active_state_manifest_digest,
                        deployment_generation,
                        now,
                    )
                    .map_err(map_agent_authority_error)?;
                let response = ApplyApprovedConnectorRegistrationResponseV2::new(
                    result.signed_delta_digest(),
                    result.head_digest(),
                    result.sequence(),
                    result.connector_id(),
                )
                .map_err(|_| StableCode::KernelUnavailable)?;
                encode_apply_approved_connector_registration_response_v2(&response)
            }
            KernelConnectorControlOperationV2::PrepareRemoval(request) => {
                let prepared = self
                    .connector_authority
                    .as_mut()
                    .ok_or(StableCode::KernelUnavailable)?
                    .prepare_remove(
                        request.session(),
                        request.connector_id(),
                        agent_authority,
                        caller_boot_id,
                        caller_identity,
                        active_state_manifest_digest,
                        deployment_generation,
                        now,
                    )
                    .map_err(|error| map_connector_authority_error_for_tag(74, error))?;
                let response = PrepareConnectorRemovalResponseV2::new(
                    prepared.authorization(),
                    prepared.previous_head_digest(),
                    prepared.expires_at(),
                )
                .map_err(|_| StableCode::KernelUnavailable)?;
                encode_prepare_connector_removal_response_v2(response)
            }
            KernelConnectorControlOperationV2::Remove(request) => {
                let result = self
                    .connector_authority
                    .as_mut()
                    .ok_or(StableCode::KernelUnavailable)?
                    .remove(
                        request.session(),
                        request.authorization(),
                        request.connector_id(),
                        agent_authority,
                        caller_boot_id,
                        caller_identity,
                        active_state_manifest_digest,
                        deployment_generation,
                        now,
                    )
                    .map_err(|error| map_connector_authority_error_for_tag(75, error))?;
                agent_authority
                    .synchronize_executor_connector_registry(
                        active_state_manifest_digest,
                        deployment_generation,
                        now,
                    )
                    .map_err(map_agent_authority_error)?;
                let response = RemoveConnectorResponseV2::new(
                    result.signed_delta_digest(),
                    result.head_digest(),
                    result.sequence(),
                    result.connector_id(),
                )
                .map_err(|_| StableCode::KernelUnavailable)?;
                encode_remove_connector_response_v2(&response)
            }
            KernelConnectorControlOperationV2::Snapshot(request) => {
                let snapshot = self
                    .connector_authority
                    .as_ref()
                    .ok_or(StableCode::KernelUnavailable)?
                    .snapshot(
                        request.session(),
                        agent_authority,
                        caller_boot_id,
                        caller_identity,
                        active_state_manifest_digest,
                        deployment_generation,
                        now,
                    )
                    .map_err(|error| map_connector_authority_error_for_tag(76, error))?;
                let response = ConnectorRegistrySnapshotResponseV2::new(
                    BoundedConnectorRegistrySnapshotV2::new(snapshot.canonical_bytes().to_vec())
                        .map_err(|_| StableCode::KernelUnavailable)?,
                );
                encode_connector_registry_snapshot_response_v2(&response)
            }
        }
        .map_err(|_| StableCode::KernelUnavailable)?;
        typed_body(canonical)
    }

    fn execute_finalize_input_prepared(
        &mut self,
        request: savana_kernel_protocol::v2::FinalizeInputRequestV2,
        request_id: RequestIdV2,
        logical_deadline: UnixMillisV2,
        now: UnixMillisV2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        effect_fence_epoch: u64,
        caller_boot_id: BootIdV2,
        caller_identity: ServiceIdentityV2,
        caller_observed_peer: PeerIdentityBindingV2,
        response_builder: KernelRuntimeResponseBuilderV2,
        commit: Option<&StateOwnerCommitV2>,
    ) -> Result<PreparedKernelServiceResponseV2, KernelRuntimeResponsePreparationErrorV2> {
        enum PreparationErrorV2 {
            Authority(KernelIngressAuthorityErrorV2),
            Commit(StateOwnerErrorV2),
            Response,
        }

        let operation_digest = match encode_kernel_ingress_operation_v2(
            &KernelIngressOperationV2::FinalizeInput(request.clone()),
        ) {
            Ok(canonical) => Digest32V2::new(Sha256::digest(canonical).into()),
            Err(_) => {
                return prepare_finalize_terminal_response(
                    response_builder,
                    Err(StableCode::KernelUnavailable),
                    commit,
                )
            }
        };
        let finalized_input_commitment = match self.input.exact_finalized_input_commitment(&request)
        {
            Ok(commitment) => commitment,
            Err(error) => {
                return prepare_finalize_terminal_response(
                    response_builder,
                    Err(map_input_error(error)),
                    commit,
                )
            }
        };
        let authority = match self.ingress_authority.as_mut() {
            Some(authority) => authority,
            None => {
                return prepare_finalize_terminal_response(
                    response_builder,
                    Err(StableCode::KernelUnavailable),
                    commit,
                );
            }
        };
        #[cfg(test)]
        let linearization_hook = self.finalize_linearization_hook.as_ref();
        if let Some(input_commitment) = finalized_input_commitment {
            let identity = FinalizeRecoveryIdentityV2::new(
                savana_kernel_protocol::v2::EndpointRoleV2::IngressKernel,
                caller_boot_id,
                caller_identity,
                caller_observed_peer.clone(),
                request_id,
                logical_deadline,
                operation_digest,
                input_commitment,
                active_state_manifest_digest,
                deployment_generation,
                effect_fence_epoch,
            )
            .map_err(|_| KernelRuntimeResponsePreparationErrorV2::Unavailable)?;
            let recovered = authority
                .recover_pending_approval(identity, now)
                .map_err(|error| match error {
                    KernelIngressAuthorityErrorV2::BindingMismatch
                    | KernelIngressAuthorityErrorV2::AlreadyConsumed
                    | KernelIngressAuthorityErrorV2::InvalidReference
                    | KernelIngressAuthorityErrorV2::RequestConflict => StableCode::PolicyDenied,
                    other => map_ingress_authority_error(other),
                });
            return match recovered {
                Ok((material, recovery_proof)) => {
                    let canonical =
                        encode_finalize_input_response_v2(&FinalizeInputResponseV2::new(
                            material.pending,
                            material.approval,
                            material.envelope,
                            material.display_authentication,
                        ))
                        .map_err(|_| KernelRuntimeResponsePreparationErrorV2::Unavailable)?;
                    let response = response_builder.prepare_canonical_success(canonical)?;
                    #[cfg(test)]
                    if let Some(hook) = linearization_hook {
                        hook.before_commit();
                    }
                    if let Some(commit) = commit {
                        commit.claim().map_err(|error| match error {
                            StateOwnerErrorV2::DeadlineExceeded => {
                                KernelRuntimeResponsePreparationErrorV2::DeadlineExceeded
                            }
                            StateOwnerErrorV2::RuntimeBusy
                            | StateOwnerErrorV2::RuntimeUnavailable => {
                                KernelRuntimeResponsePreparationErrorV2::Unavailable
                            }
                        })?;
                        commit
                            .mark_durable_complete(&recovery_proof)
                            .map_err(|_| KernelRuntimeResponsePreparationErrorV2::Unavailable)?;
                    }
                    #[cfg(test)]
                    if let Some(hook) = linearization_hook {
                        hook.after_claim();
                    }
                    response.commit_staged_suite_one()
                }
                Err(error) => {
                    prepare_finalize_terminal_response(response_builder, Err(error), commit)
                }
            };
        }
        if now.get() == 0 || now.get() >= logical_deadline.get() {
            return prepare_finalize_terminal_response(
                response_builder,
                Err(StableCode::DeadlineExceeded),
                commit,
            );
        }
        let mut response_builder = Some(response_builder);
        let transaction = self.input.finalize_with(request, |finalized| {
            let recovery_identity = FinalizeRecoveryIdentityV2::new(
                savana_kernel_protocol::v2::EndpointRoleV2::IngressKernel,
                caller_boot_id,
                caller_identity,
                caller_observed_peer,
                request_id,
                logical_deadline,
                operation_digest,
                finalized.input_commitment(),
                active_state_manifest_digest,
                deployment_generation,
                effect_fence_epoch,
            )
            .map_err(PreparationErrorV2::Authority)?;
            let candidate = authority
                .prepare_pending_approval(
                    finalized,
                    recovery_identity,
                    active_state_manifest_digest,
                    deployment_generation,
                    now,
                )
                .map_err(PreparationErrorV2::Authority)?;
            let material = candidate.response();
            let canonical = encode_finalize_input_response_v2(&FinalizeInputResponseV2::new(
                material.pending,
                material.approval,
                material.envelope.clone(),
                material.display_authentication.clone(),
            ))
            .map_err(|_| PreparationErrorV2::Response)?;
            let response = response_builder
                .take()
                .ok_or(PreparationErrorV2::Response)?
                .prepare_canonical_success(canonical)
                .map_err(|_| PreparationErrorV2::Response)?;
            #[cfg(test)]
            if let Some(hook) = linearization_hook {
                hook.before_commit();
            }
            if let Some(commit) = commit {
                commit.claim().map_err(PreparationErrorV2::Commit)?;
            }
            #[cfg(test)]
            if let Some(hook) = linearization_hook {
                hook.after_claim();
            }
            let response = response
                .commit_staged_suite_one()
                .map_err(|_| PreparationErrorV2::Response)?;
            Ok((candidate, response))
        });
        match transaction {
            Ok((finalized, (candidate, response))) => {
                let (_, recovery_proof) = authority.publish_pending_approval(candidate, finalized);
                if let Some(commit) = commit {
                    commit
                        .mark_durable_complete(&recovery_proof)
                        .map_err(|_| KernelRuntimeResponsePreparationErrorV2::Unavailable)?;
                }
                #[cfg(test)]
                if let Some(hook) = linearization_hook {
                    hook.after_publish();
                }
                Ok(response)
            }
            Err(KernelInputFinalizeTransactionErrorV2::Input(error)) => {
                prepare_finalize_terminal_response(
                    response_builder
                        .take()
                        .ok_or(KernelRuntimeResponsePreparationErrorV2::Unavailable)?,
                    Err(map_input_error(error)),
                    commit,
                )
            }
            Err(KernelInputFinalizeTransactionErrorV2::Preparation(
                PreparationErrorV2::Authority(error),
            )) => prepare_finalize_terminal_response(
                response_builder
                    .take()
                    .ok_or(KernelRuntimeResponsePreparationErrorV2::Unavailable)?,
                Err(map_ingress_authority_error(error)),
                commit,
            ),
            Err(KernelInputFinalizeTransactionErrorV2::Preparation(
                PreparationErrorV2::Response,
            )) => match response_builder.take() {
                Some(builder) => prepare_finalize_terminal_response(
                    builder,
                    Err(StableCode::KernelUnavailable),
                    commit,
                ),
                None => Err(KernelRuntimeResponsePreparationErrorV2::Unavailable),
            },
            Err(KernelInputFinalizeTransactionErrorV2::Preparation(
                PreparationErrorV2::Commit(error),
            )) => Err(match error {
                StateOwnerErrorV2::DeadlineExceeded => {
                    KernelRuntimeResponsePreparationErrorV2::DeadlineExceeded
                }
                StateOwnerErrorV2::RuntimeBusy | StateOwnerErrorV2::RuntimeUnavailable => {
                    KernelRuntimeResponsePreparationErrorV2::Unavailable
                }
            }),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn execute_agent(
        &mut self,
        request_id: RequestIdV2,
        operation: KernelAgentOperationV2,
        now: UnixMillisV2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        effect_fence_epoch: u64,
        caller_identity: ServiceIdentityV2,
    ) -> Result<KernelServiceResponseBodyV2, StableCode> {
        let authenticated_canonical_operation = encode_kernel_agent_operation_v2(&operation)
            .map_err(|_| StableCode::KernelUnavailable)?;
        let canonical = match operation {
            KernelAgentOperationV2::Health(_) => {
                let (ready, state) = self.health_state();
                encode_kernel_agent_health_response_v2(&KernelAgentHealthResponseV2::new(
                    ready, state,
                ))
            }
            KernelAgentOperationV2::DeriveValue(request) => {
                let derived = self.values.derive(request, now).map_err(map_value_error)?;
                encode_derive_value_response_v2(
                    &DeriveValueResponseV2::new(derived.handle(), derived.value_digest())
                        .map_err(|_| StableCode::KernelUnavailable)?,
                )
            }
            KernelAgentOperationV2::PrepareNewIngress(request) => {
                let authority = self
                    .agent_authority
                    .as_mut()
                    .ok_or(StableCode::KernelUnavailable)?;
                let ingress = self
                    .ingress_authority
                    .as_mut()
                    .ok_or(StableCode::KernelUnavailable)?;
                let response = authority
                    .prepare_new_ingress(
                        request,
                        ingress,
                        caller_identity,
                        active_state_manifest_digest,
                        deployment_generation,
                        now,
                    )
                    .map_err(map_agent_authority_error)?;
                encode_prepare_new_ingress_response_v2(&response)
            }
            KernelAgentOperationV2::PrepareAgentUiAuthentication(request) => {
                let response = self
                    .agent_authority
                    .as_mut()
                    .ok_or(StableCode::KernelUnavailable)?
                    .prepare_ui_authentication(
                        request,
                        caller_identity,
                        active_state_manifest_digest,
                        deployment_generation,
                        now,
                    )
                    .map_err(map_agent_authority_error)?;
                encode_prepare_agent_ui_authentication_response_v2(&response)
            }
            KernelAgentOperationV2::AuthenticateAgentUi(request) => {
                let authorization = self
                    .agent_authority
                    .as_mut()
                    .ok_or(StableCode::KernelUnavailable)?
                    .authenticate_ui(
                        request.authentication_preparation(),
                        request.settlement(),
                        caller_identity,
                        active_state_manifest_digest,
                        deployment_generation,
                        now,
                    )
                    .map_err(map_agent_authority_error)?;
                encode_authenticate_agent_ui_response_v2(&AuthenticateAgentUiResponseV2::new(
                    authorization,
                ))
            }
            KernelAgentOperationV2::ClaimAgentSession(request) => {
                let response = self
                    .agent_authority
                    .as_mut()
                    .ok_or(StableCode::KernelUnavailable)?
                    .claim_session(
                        request,
                        &mut self.values,
                        caller_identity,
                        active_state_manifest_digest,
                        now,
                    )
                    .map_err(map_agent_authority_error)?;
                encode_claim_agent_session_response_v2(&response)
            }
            KernelAgentOperationV2::PrepareFollowupIngress(request) => {
                let response = self
                    .agent_authority
                    .as_ref()
                    .ok_or(StableCode::KernelUnavailable)?
                    .prepare_followup_ingress(request, caller_identity)
                    .map_err(map_agent_authority_error)?;
                encode_prepare_followup_ingress_response_v2(&response)
            }
            KernelAgentOperationV2::GetAgentSessionStatus(request) => {
                let response = self
                    .agent_authority
                    .as_ref()
                    .ok_or(StableCode::KernelUnavailable)?
                    .session_status(request, caller_identity)
                    .map_err(map_agent_authority_error)?;
                encode_get_agent_session_status_response_v2(&response)
            }
            KernelAgentOperationV2::PreparePlannerCall(request) => {
                let response = self
                    .agent_authority
                    .as_mut()
                    .ok_or(StableCode::KernelUnavailable)?
                    .prepare_planner_call(&request, &self.values, caller_identity, now)
                    .map_err(map_agent_authority_error)?;
                encode_prepare_planner_call_response_v2(&response)
            }
            KernelAgentOperationV2::CommitPlannerValue(request) => {
                let response = self
                    .agent_authority
                    .as_mut()
                    .ok_or(StableCode::KernelUnavailable)?
                    .commit_planner_value(&request, &mut self.values, caller_identity, now)
                    .map_err(map_agent_authority_error)?;
                encode_commit_planner_value_response_v2(&response)
            }
            KernelAgentOperationV2::ProposeToolCall(request) => {
                let response = self
                    .agent_authority
                    .as_mut()
                    .ok_or(StableCode::KernelUnavailable)?
                    .propose_tool_call(
                        request_id,
                        &authenticated_canonical_operation,
                        &request,
                        &self.values,
                        caller_identity,
                        active_state_manifest_digest,
                        deployment_generation,
                        now,
                    )
                    .map_err(map_agent_authority_error)?;
                encode_propose_tool_call_response_v2(&response)
            }
            KernelAgentOperationV2::EvaluateToolCall(request) => {
                let response = self
                    .agent_authority
                    .as_mut()
                    .ok_or(StableCode::KernelUnavailable)?
                    .evaluate_tool_call(
                        request,
                        &self.values,
                        caller_identity,
                        active_state_manifest_digest,
                        deployment_generation,
                        now,
                    )
                    .map_err(map_agent_authority_error)?;
                encode_evaluate_tool_call_response_v2(&response)
            }
            KernelAgentOperationV2::AuthorizeToolCall(request) => {
                let response = self
                    .agent_authority
                    .as_mut()
                    .ok_or(StableCode::KernelUnavailable)?
                    .authorize_tool_call(
                        &request,
                        caller_identity,
                        active_state_manifest_digest,
                        deployment_generation,
                        now,
                    )
                    .map_err(map_agent_authority_error)?;
                encode_authorize_tool_call_response_v2(&response)
            }
            KernelAgentOperationV2::DispatchExecution(request) => {
                let response = self
                    .agent_authority
                    .as_mut()
                    .ok_or(StableCode::KernelUnavailable)?
                    .dispatch_execution(
                        request_id,
                        request,
                        caller_identity,
                        active_state_manifest_digest,
                        deployment_generation,
                        effect_fence_epoch,
                        now,
                    )
                    .map_err(map_agent_authority_error)?;
                encode_dispatch_execution_response_v2(&response)
            }
            KernelAgentOperationV2::GetExecutionStatus(request) => {
                let response = self
                    .agent_authority
                    .as_mut()
                    .ok_or(StableCode::KernelUnavailable)?
                    .execution_status(
                        request_id,
                        request,
                        self.ingress_commit_sink
                            .as_mut()
                            .ok_or(StableCode::KernelUnavailable)?
                            .as_mut(),
                        caller_identity,
                        active_state_manifest_digest,
                        deployment_generation,
                        effect_fence_epoch,
                        now,
                    )
                    .map_err(map_agent_authority_error)?;
                encode_get_execution_status_response_v2(&response)
            }
            KernelAgentOperationV2::ReadAgentView(request) => {
                self.agent_authority
                    .as_ref()
                    .ok_or(StableCode::KernelUnavailable)?
                    .authorize_agent_view(&request, caller_identity)
                    .map_err(map_agent_authority_error)?;
                let response = self
                    .ingress_commit_sink
                    .as_mut()
                    .ok_or(StableCode::KernelUnavailable)?
                    .read_agent_view(request.document(), request.maximum_encoded_bytes(), now)?;
                encode_read_agent_view_response_v2(&response)
            }
            KernelAgentOperationV2::PrepareRelease(request) => {
                let response = self
                    .agent_authority
                    .as_mut()
                    .ok_or(StableCode::KernelUnavailable)?
                    .prepare_release(
                        &request,
                        &self.values,
                        self.ingress_commit_sink
                            .as_mut()
                            .ok_or(StableCode::KernelUnavailable)?
                            .as_mut(),
                        caller_identity,
                        active_state_manifest_digest,
                        deployment_generation,
                        now,
                    )
                    .map_err(map_agent_authority_error)?;
                encode_prepare_release_response_v2(&response)
            }
            KernelAgentOperationV2::AuthorizeRelease(request) => {
                let response = self
                    .agent_authority
                    .as_mut()
                    .ok_or(StableCode::KernelUnavailable)?
                    .authorize_release(
                        &request,
                        self.ingress_commit_sink
                            .as_mut()
                            .ok_or(StableCode::KernelUnavailable)?
                            .as_mut(),
                        caller_identity,
                        active_state_manifest_digest,
                        deployment_generation,
                        now,
                    )
                    .map_err(map_agent_authority_error)?;
                encode_authorize_release_response_v2(&response)
            }
            KernelAgentOperationV2::DispatchRelease(request) => {
                let response = self
                    .agent_authority
                    .as_mut()
                    .ok_or(StableCode::KernelUnavailable)?
                    .dispatch_release(
                        request_id,
                        request,
                        self.ingress_commit_sink
                            .as_mut()
                            .ok_or(StableCode::KernelUnavailable)?
                            .as_mut(),
                        caller_identity,
                        active_state_manifest_digest,
                        deployment_generation,
                        effect_fence_epoch,
                        now,
                    )
                    .map_err(map_agent_authority_error)?;
                encode_dispatch_release_response_v2(&response)
            }
            KernelAgentOperationV2::GetReleaseStatus(request) => {
                let response = self
                    .agent_authority
                    .as_mut()
                    .ok_or(StableCode::KernelUnavailable)?
                    .release_status(
                        request_id,
                        request,
                        self.ingress_commit_sink
                            .as_mut()
                            .ok_or(StableCode::KernelUnavailable)?
                            .as_mut(),
                        caller_identity,
                        now,
                    )
                    .map_err(map_agent_authority_error)?;
                encode_get_release_status_response_v2(&response)
            }
            KernelAgentOperationV2::RevokeVault(request) => {
                self.agent_authority
                    .as_ref()
                    .ok_or(StableCode::KernelUnavailable)?
                    .authorize_vault_revocation(&request, caller_identity)
                    .map_err(map_agent_authority_error)?;
                let state = self
                    .ingress_commit_sink
                    .as_mut()
                    .ok_or(StableCode::KernelUnavailable)?
                    .revoke_vault(request.document(), now)?;
                let response = savana_kernel_protocol::v2::RevokeVaultResponseV2::new(state);
                encode_revoke_vault_response_v2(&response)
            }
            KernelAgentOperationV2::GetKernelTaskStatus(request) => {
                let response = self
                    .agent_authority
                    .as_ref()
                    .ok_or(StableCode::KernelUnavailable)?
                    .task_status(&request, caller_identity, active_state_manifest_digest, now)
                    .map_err(map_agent_authority_error)?;
                encode_get_kernel_task_status_response_v2(&response)
            }
            KernelAgentOperationV2::CancelKernelTask(request) => {
                let response = self
                    .agent_authority
                    .as_mut()
                    .ok_or(StableCode::KernelUnavailable)?
                    .cancel_task(&request, caller_identity, active_state_manifest_digest, now)
                    .map_err(map_agent_authority_error)?;
                encode_cancel_kernel_task_response_v2(&response)
            }
            KernelAgentOperationV2::ResumeCommittedAgentAuthentication(request) => {
                let response = self
                    .agent_authority
                    .as_mut()
                    .ok_or(StableCode::KernelUnavailable)?
                    .resume_committed_authentication(
                        &request,
                        caller_identity,
                        active_state_manifest_digest,
                        deployment_generation,
                        now,
                    )
                    .map_err(map_agent_authority_error)?;
                encode_resume_committed_agent_authentication_response_v2(&response)
            }
            KernelAgentOperationV2::CloseAgentSession(request) => {
                let state = self
                    .agent_authority
                    .as_mut()
                    .ok_or(StableCode::KernelUnavailable)?
                    .close_session(request.session(), caller_identity)
                    .map_err(map_agent_authority_error)?;
                encode_close_agent_session_response_v2(&CloseAgentSessionResponseV2::new(state))
            }
        }
        .map_err(|_| StableCode::KernelUnavailable)?;
        typed_body(canonical)
    }

    fn execute_ingress(
        &mut self,
        operation: KernelIngressOperationV2,
        now: UnixMillisV2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        caller_identity: ServiceIdentityV2,
    ) -> Result<KernelServiceResponseBodyV2, StableCode> {
        let canonical = match operation {
            KernelIngressOperationV2::Health(_) => {
                let (ready, state) = self.health_state();
                encode_kernel_ingress_health_response_v2(&KernelIngressHealthResponseV2::new(
                    ready, state,
                ))
            }
            KernelIngressOperationV2::PrepareIngressUiAuthentication(request) => {
                let prepared = self
                    .ingress_authority
                    .as_mut()
                    .ok_or(StableCode::KernelUnavailable)?
                    .prepare_ui_authentication(
                        request.transfer(),
                        caller_identity,
                        active_state_manifest_digest,
                        deployment_generation,
                        now,
                    )
                    .map_err(map_ingress_authority_error)?;
                encode_prepare_ingress_ui_authentication_response_v2(
                    &PrepareIngressUiAuthenticationResponseV2::new(
                        prepared.preparation,
                        prepared.envelope,
                    ),
                )
            }
            KernelIngressOperationV2::AuthenticateIngressUi(request) => {
                let authenticated = self
                    .ingress_authority
                    .as_mut()
                    .ok_or(StableCode::KernelUnavailable)?
                    .authenticate_ui(
                        request.authentication_preparation(),
                        request.settlement(),
                        caller_identity,
                        active_state_manifest_digest,
                        deployment_generation,
                        now,
                    )
                    .map_err(map_ingress_authority_error)?;
                self.input
                    .register_verified_ui_authorization(
                        authenticated.authorization,
                        authenticated.evidence,
                    )
                    .map_err(map_input_error)?;
                encode_authenticate_ingress_ui_response_v2(&AuthenticateIngressUiResponseV2::new(
                    authenticated.authorization,
                ))
            }
            KernelIngressOperationV2::BeginInput(request) => {
                let begun = self
                    .input
                    .begin(
                        request,
                        active_state_manifest_digest,
                        deployment_generation,
                        now,
                    )
                    .map_err(map_input_error)?;
                let next_sequences = begun
                    .channels()
                    .iter()
                    .map(|cursor| {
                        InputNextSequenceV2::new(cursor.channel(), cursor.next_sequence())
                    })
                    .collect();
                encode_begin_input_response_v2(
                    &BeginInputResponseV2::new(
                        begun.session(),
                        begun.writer(),
                        begun.parser_job_session_binding_digest(),
                        next_sequences,
                    )
                    .map_err(|_| StableCode::KernelUnavailable)?,
                )
            }
            KernelIngressOperationV2::AppendInputChunk(request) => {
                let acknowledged = self.input.append(request).map_err(map_input_error)?;
                encode_append_input_chunk_response_v2(
                    &AppendInputChunkResponseV2::new(
                        acknowledged.channel(),
                        acknowledged.acknowledged_sequence(),
                        acknowledged.cumulative_digest(),
                    )
                    .map_err(|_| StableCode::KernelUnavailable)?,
                )
            }
            KernelIngressOperationV2::FinalizeInput(_) => {
                return Err(StableCode::KernelUnavailable)
            }
            KernelIngressOperationV2::CommitInputSettlement(request) => {
                let decision = self
                    .ingress_authority
                    .as_ref()
                    .ok_or(StableCode::KernelUnavailable)?
                    .verify_settlement(
                        request.pending(),
                        request.approval(),
                        request.settlement(),
                        active_state_manifest_digest,
                        deployment_generation,
                        now,
                    )
                    .map_err(map_ingress_authority_error)?;
                let state = match decision {
                    VerifiedIngressSettlementDecisionV2::Denied => {
                        self.ingress_authority
                            .as_mut()
                            .ok_or(StableCode::KernelUnavailable)?
                            .finish_verified_denial(request.pending(), request.approval())
                            .map_err(map_ingress_authority_error)?;
                        InputPublicStateV2::Denied
                    }
                    VerifiedIngressSettlementDecisionV2::Approved {
                        record_index,
                        durable_task_id,
                        principal,
                    } => {
                        let finalized = self
                            .ingress_authority
                            .as_ref()
                            .ok_or(StableCode::KernelUnavailable)?
                            .finalized_for_verified_approval(record_index)
                            .map_err(map_ingress_authority_error)?;
                        let source = finalized.input_commitment();
                        let recovered = self
                            .agent_authority
                            .as_ref()
                            .ok_or(StableCode::KernelUnavailable)?
                            .ingress_material_is_committed(
                                durable_task_id,
                                principal,
                                source,
                                active_state_manifest_digest,
                            )
                            .map_err(map_agent_authority_error)?;
                        // A retry after the durable agent handoff must retain
                        // the original document, provenance and expiry. Calling
                        // the sink again would mint different claim material.
                        if !recovered {
                            let material = self
                                .ingress_commit_sink
                                .as_mut()
                                .ok_or(StableCode::KernelUnavailable)?
                                .commit(
                                    durable_task_id,
                                    principal,
                                    finalized,
                                    active_state_manifest_digest,
                                    deployment_generation,
                                    now,
                                )?;
                            self.agent_authority
                                .as_mut()
                                .ok_or(StableCode::KernelUnavailable)?
                                .mark_ingress_committed(
                                    durable_task_id,
                                    principal,
                                    source,
                                    material,
                                )
                                .map_err(map_agent_authority_error)?;
                        }
                        self.agent_authority
                            .as_mut()
                            .ok_or(StableCode::KernelUnavailable)?
                            .activate_committed_task_authorization(
                                durable_task_id,
                                principal,
                                active_state_manifest_digest,
                                deployment_generation,
                                now,
                            )
                            .map_err(map_task_authority_error)?;
                        self.ingress_authority
                            .as_mut()
                            .ok_or(StableCode::KernelUnavailable)?
                            .finish_verified_settlement(decision)
                            .map_err(map_ingress_authority_error)?;
                        InputPublicStateV2::CommittedUnclaimed
                    }
                };
                encode_commit_input_settlement_response_v2(&CommitInputSettlementResponseV2::new(
                    state,
                ))
            }
            KernelIngressOperationV2::EstablishTaskAuthorization(request) => {
                let proof = self
                    .input
                    .authenticate_task_draft_submission(
                        request.session(),
                        request.draft(),
                        active_state_manifest_digest,
                        deployment_generation,
                        now,
                    )
                    .map_err(map_input_error)?;
                let response = self
                    .agent_authority
                    .as_mut()
                    .ok_or(StableCode::KernelUnavailable)?
                    .establish_task_authorization(&request, &proof, now)
                    .map_err(|e| match e {
                        crate::v2_task_authority::TaskAuthorityErrorV2::Unavailable => {
                            StableCode::KernelUnavailable
                        }
                        _ => StableCode::PolicyDenied,
                    })?;
                savana_kernel_protocol::v2::encode_establish_task_authorization_response_v2(
                    &response,
                )
            }
            KernelIngressOperationV2::GetTaskAuthorizationContext(request) => {
                let subject = self
                    .input
                    .authenticate_task_context(
                        &request,
                        active_state_manifest_digest,
                        deployment_generation,
                        now,
                    )
                    .map_err(map_input_error)?;
                let context = self
                    .agent_authority
                    .as_ref()
                    .ok_or(StableCode::KernelUnavailable)?
                    .task_authorization_context(&subject, now)
                    .map_err(map_task_authority_error)?;
                savana_kernel_protocol::v2::encode_task_authorization_context_v2(&context)
            }
            KernelIngressOperationV2::RecoverTaskAuthorization(request) => {
                use savana_kernel_protocol::v2::{
                    EstablishTaskAuthorizationResponseV2,
                    PrepareTaskAuthorizationApprovalResponseV2,
                    RecoverTaskAuthorizationResponseV2 as R,
                };
                let agent = self
                    .agent_authority
                    .as_ref()
                    .ok_or(StableCode::KernelUnavailable)?;
                let pending = agent
                    .recover_task_issuance_record(request.request_digest())
                    .map_err(map_task_authority_error)?;
                let proof = self
                    .input
                    .authenticate_task_recovery(
                        request.authorization(),
                        &pending,
                        active_state_manifest_digest,
                        deployment_generation,
                        now,
                    )
                    .map_err(map_input_error)?;
                agent
                    .validate_task_issuance_recovery(&pending, now)
                    .map_err(map_task_authority_error)?;
                let response = if let Some(digest) = pending.installed_digest() {
                    // Observation only: never invoke issuance or task activation.
                    R::Installed(
                        EstablishTaskAuthorizationResponseV2::new(pending.request_digest(), digest)
                            .map_err(|_| StableCode::KernelUnavailable)?,
                    )
                } else {
                    let (envelope, display) =
                        match (pending.envelope(), pending.display_authentication()) {
                            (Some(e), Some(d)) => (e.clone(), d.clone()),
                            (None, None) => {
                                let (e, d) = self
                                    .ingress_authority
                                    .as_ref()
                                    .ok_or(StableCode::KernelUnavailable)?
                                    .prepare_task_authorization_display(
                                        pending.draft(),
                                        &proof,
                                        now,
                                    )
                                    .map_err(map_ingress_authority_error)?;
                                self.agent_authority
                                    .as_mut()
                                    .ok_or(StableCode::KernelUnavailable)?
                                    .attach_task_approval(
                                        pending.request_digest(),
                                        e.clone(),
                                        d.clone(),
                                        active_state_manifest_digest,
                                        deployment_generation,
                                        now,
                                    )
                                    .map_err(map_task_authority_error)?;
                                (e, d)
                            }
                            _ => return Err(StableCode::KernelUnavailable),
                        };
                    R::Approval(
                        PrepareTaskAuthorizationApprovalResponseV2::new(
                            pending.request_digest(),
                            envelope,
                            display,
                        )
                        .map_err(|_| StableCode::KernelUnavailable)?,
                    )
                };
                savana_kernel_protocol::v2::encode_recover_task_authorization_response_v2(&response)
            }
            KernelIngressOperationV2::RevokeTaskAuthorization(request) => {
                let proof = self
                    .input
                    .authenticate_task_draft_submission(
                        request.session(),
                        request.draft(),
                        active_state_manifest_digest,
                        deployment_generation,
                        now,
                    )
                    .map_err(map_input_error)?;
                let response = self
                    .agent_authority
                    .as_mut()
                    .ok_or(StableCode::KernelUnavailable)?
                    .revoke_task_authorization(&request, &proof, now)
                    .map_err(map_task_authority_error)?;
                savana_kernel_protocol::v2::encode_revoke_task_authorization_response_v2(&response)
            }
            KernelIngressOperationV2::PrepareTaskAuthorizationApproval(request) => {
                let proof = self
                    .input
                    .authenticate_task_draft_submission(
                        request.session(),
                        request.draft(),
                        active_state_manifest_digest,
                        deployment_generation,
                        now,
                    )
                    .map_err(map_input_error)?;
                let pending = self
                    .agent_authority
                    .as_mut()
                    .ok_or(StableCode::KernelUnavailable)?
                    .prepare_task_approval(&request, &proof, now)
                    .map_err(map_task_authority_error)?;
                let (envelope, display) =
                    match (pending.envelope(), pending.display_authentication()) {
                        (Some(e), Some(d)) => (e.clone(), d.clone()),
                        (None, None) => {
                            let (e, d) = self
                                .ingress_authority
                                .as_ref()
                                .ok_or(StableCode::KernelUnavailable)?
                                .prepare_task_authorization_display(pending.draft(), &proof, now)
                                .map_err(map_ingress_authority_error)?;
                            self.agent_authority
                                .as_mut()
                                .ok_or(StableCode::KernelUnavailable)?
                                .attach_task_approval(
                                    pending.request_digest(),
                                    e.clone(),
                                    d.clone(),
                                    active_state_manifest_digest,
                                    deployment_generation,
                                    now,
                                )
                                .map_err(map_task_authority_error)?;
                            (e, d)
                        }
                        _ => return Err(StableCode::KernelUnavailable),
                    };
                savana_kernel_protocol::v2::encode_prepare_task_authorization_approval_response_v2(
                    &savana_kernel_protocol::v2::PrepareTaskAuthorizationApprovalResponseV2::new(
                        pending.request_digest(),
                        envelope,
                        display,
                    )
                    .map_err(|_| StableCode::KernelUnavailable)?,
                )
            }
            KernelIngressOperationV2::CommitTaskAuthorizationApproval(request) => {
                let response = self
                    .agent_authority
                    .as_mut()
                    .ok_or(StableCode::KernelUnavailable)?
                    .commit_task_approval(
                        &request,
                        active_state_manifest_digest,
                        deployment_generation,
                        now,
                    )
                    .map_err(map_task_authority_error)?;
                savana_kernel_protocol::v2::encode_establish_task_authorization_response_v2(
                    &response,
                )
            }
            KernelIngressOperationV2::AbortInput(request) => {
                let state = self.input.abort(request).map_err(map_input_error)?;
                encode_abort_input_response_v2(&AbortInputResponseV2::new(public_input_state(
                    state,
                )))
            }
            KernelIngressOperationV2::GetInputStatus(request) => {
                let state = match request.target() {
                    InputStatusTargetV2::Session(_) => public_input_state(
                        self.input
                            .status(request.target())
                            .map_err(map_input_error)?,
                    ),
                    InputStatusTargetV2::Pending(pending) => public_pending_state(
                        self.ingress_authority
                            .as_ref()
                            .ok_or(StableCode::KernelUnavailable)?
                            .pending_status(pending)
                            .map_err(map_ingress_authority_error)?,
                    ),
                };
                encode_get_input_status_response_v2(&GetInputStatusResponseV2::new(state))
            }
            KernelIngressOperationV2::RegisterParserWorkerJob(request) => {
                let trust = self.parser_trust.ok_or(StableCode::KernelUnavailable)?;
                let registered = self
                    .input
                    .register_parser_worker_job(
                        request,
                        trust,
                        caller_identity,
                        active_state_manifest_digest,
                        deployment_generation,
                        now,
                    )
                    .map_err(map_input_error)?;
                encode_register_parser_worker_job_response_v2(
                    &RegisterParserWorkerJobResponseV2::new(registered.extraction()),
                )
            }
            KernelIngressOperationV2::AppendParserWorkerPageFrame(request) => {
                let acknowledged = self
                    .input
                    .append_parser_worker_page_frame(request)
                    .map_err(map_input_error)?;
                encode_append_parser_worker_page_frame_response_v2(
                    &AppendParserWorkerPageFrameResponseV2::new(
                        acknowledged.page_index(),
                        acknowledged.page_chunk_index(),
                        acknowledged.transcript_digest(),
                    )
                    .map_err(|_| StableCode::KernelUnavailable)?,
                )
            }
            KernelIngressOperationV2::CommitParserWorkerResult(request) => {
                let committed = self
                    .input
                    .commit_parser_worker_result(request, now)
                    .map_err(map_input_error)?;
                encode_commit_parser_worker_result_response_v2(
                    &CommitParserWorkerResultResponseV2::new(
                        committed.extracted_channel_commitment(),
                        committed.parsed_source_provenance_digest(),
                    )
                    .map_err(|_| StableCode::KernelUnavailable)?,
                )
            }
        }
        .map_err(|_| StableCode::KernelUnavailable)?;
        typed_body(canonical)
    }

    fn health_state(&self) -> (bool, PublicServiceStateV2) {
        if self.readiness.load(Ordering::Acquire) {
            (true, PublicServiceStateV2::Ready)
        } else {
            (false, PublicServiceStateV2::Starting)
        }
    }
}

impl KernelRuntimeServicesV2 for CoreKernelRuntimeServicesV2 {
    fn execute(
        &mut self,
        request: KernelRuntimeRequestV2,
        commit: Option<StateOwnerCommitV2>,
    ) -> Result<PreparedKernelServiceResponseV2, KernelRuntimeResponsePreparationErrorV2> {
        let (context, response_builder) = request.into_parts();
        let (peer, lease, request_id, logical_deadline, now, _, operation) = context.into_parts();
        self.execute_operation_prepared(
            request_id,
            logical_deadline,
            operation,
            now,
            lease.active_state_manifest_digest(),
            lease.deployment_generation(),
            lease.effect_fence_epoch(),
            peer.caller_boot_id(),
            peer.caller_identity(),
            peer.observed_peer().clone(),
            response_builder,
            commit.as_ref(),
        )
    }
}

fn typed_body(canonical: Vec<u8>) -> Result<KernelServiceResponseBodyV2, StableCode> {
    KernelServiceResponseBodyV2::from_typed_handler(canonical)
        .map_err(|_| StableCode::KernelUnavailable)
}

const fn public_input_state(state: KernelInputPublicStateV2) -> InputPublicStateV2 {
    match state {
        KernelInputPublicStateV2::Receiving => InputPublicStateV2::Receiving,
        KernelInputPublicStateV2::Finalized => InputPublicStateV2::AwaitingApproval,
        KernelInputPublicStateV2::Aborted => InputPublicStateV2::Aborted,
        KernelInputPublicStateV2::FailedClosed => InputPublicStateV2::FailedClosed,
    }
}

const fn public_pending_state(state: KernelPendingIngressStateV2) -> InputPublicStateV2 {
    match state {
        KernelPendingIngressStateV2::AwaitingApproval => InputPublicStateV2::AwaitingApproval,
        KernelPendingIngressStateV2::Approved => InputPublicStateV2::CommittedUnclaimed,
        KernelPendingIngressStateV2::Denied => InputPublicStateV2::Denied,
    }
}

fn prepare_finalize_terminal_response(
    response_builder: KernelRuntimeResponseBuilderV2,
    outcome: Result<KernelServiceResponseBodyV2, StableCode>,
    commit: Option<&StateOwnerCommitV2>,
) -> Result<PreparedKernelServiceResponseV2, KernelRuntimeResponsePreparationErrorV2> {
    let response = response_builder.prepare_transactional(outcome)?;
    if let Some(commit) = commit {
        commit.claim().map_err(|error| match error {
            StateOwnerErrorV2::DeadlineExceeded => {
                KernelRuntimeResponsePreparationErrorV2::DeadlineExceeded
            }
            StateOwnerErrorV2::RuntimeBusy | StateOwnerErrorV2::RuntimeUnavailable => {
                KernelRuntimeResponsePreparationErrorV2::Unavailable
            }
        })?;
    }
    response.commit_staged_suite_one()
}

const fn map_task_authority_error(
    error: crate::v2_task_authority::TaskAuthorityErrorV2,
) -> StableCode {
    match error {
        crate::v2_task_authority::TaskAuthorityErrorV2::Unavailable => {
            StableCode::KernelUnavailable
        }
        _ => StableCode::PolicyDenied,
    }
}

const fn map_input_error(error: KernelInputErrorV2) -> StableCode {
    match error {
        KernelInputErrorV2::InvalidReference => StableCode::HandleUnknown,
        KernelInputErrorV2::AlreadyConsumed => StableCode::HandleAlreadyConsumed,
        KernelInputErrorV2::LimitExceeded => StableCode::PolicyLimitExceeded,
        KernelInputErrorV2::Unavailable => StableCode::KernelUnavailable,
        KernelInputErrorV2::StateConflict
        | KernelInputErrorV2::InvalidSequence
        | KernelInputErrorV2::DigestMismatch
        | KernelInputErrorV2::ProvenanceMismatch => StableCode::PolicyDenied,
    }
}

const fn map_value_error(error: KernelValueErrorV2) -> StableCode {
    match error {
        KernelValueErrorV2::InvalidReference => StableCode::HandleUnknown,
        KernelValueErrorV2::WrongRun => StableCode::HandleWrongRun,
        KernelValueErrorV2::Expired => StableCode::PolicyExpired,
        KernelValueErrorV2::LimitExceeded => StableCode::PolicyLimitExceeded,
        KernelValueErrorV2::PolicyDenied => StableCode::PolicyDenied,
        KernelValueErrorV2::StateConflict => StableCode::PolicyDenied,
        KernelValueErrorV2::Unavailable => StableCode::KernelUnavailable,
    }
}

const fn map_ingress_authority_error(error: KernelIngressAuthorityErrorV2) -> StableCode {
    match error {
        KernelIngressAuthorityErrorV2::InvalidReference => StableCode::HandleUnknown,
        KernelIngressAuthorityErrorV2::AlreadyConsumed => StableCode::HandleAlreadyConsumed,
        KernelIngressAuthorityErrorV2::BindingMismatch => StableCode::ApprovalBindingMismatch,
        KernelIngressAuthorityErrorV2::RequestConflict => StableCode::PolicyDenied,
        KernelIngressAuthorityErrorV2::Expired => StableCode::PolicyExpired,
        KernelIngressAuthorityErrorV2::LimitExceeded => StableCode::PolicyLimitExceeded,
        KernelIngressAuthorityErrorV2::Unavailable => StableCode::KernelUnavailable,
    }
}

const fn map_agent_authority_error(error: KernelAgentAuthorityErrorV2) -> StableCode {
    match error {
        KernelAgentAuthorityErrorV2::InvalidReference => StableCode::HandleUnknown,
        KernelAgentAuthorityErrorV2::AlreadyConsumed => StableCode::HandleAlreadyConsumed,
        KernelAgentAuthorityErrorV2::BindingMismatch => StableCode::ApprovalBindingMismatch,
        KernelAgentAuthorityErrorV2::Expired => StableCode::PolicyExpired,
        KernelAgentAuthorityErrorV2::StateConflict => StableCode::PolicyDenied,
        KernelAgentAuthorityErrorV2::LimitExceeded => StableCode::PolicyLimitExceeded,
        KernelAgentAuthorityErrorV2::Unavailable => StableCode::KernelUnavailable,
    }
}

const fn map_connector_authority_error_for_tag(
    operation_tag: u16,
    error: KernelConnectorAuthorityErrorV2,
) -> StableCode {
    match operation_tag {
        71 | 72 => match error {
            KernelConnectorAuthorityErrorV2::InvalidReference => StableCode::HandleUnknown,
            KernelConnectorAuthorityErrorV2::AlreadyConsumed => StableCode::HandleAlreadyConsumed,
            KernelConnectorAuthorityErrorV2::BindingMismatch
            | KernelConnectorAuthorityErrorV2::Denied => StableCode::ApprovalBindingMismatch,
            KernelConnectorAuthorityErrorV2::Expired => StableCode::ApprovalReplayed,
            KernelConnectorAuthorityErrorV2::StateConflict => StableCode::RegistryEquivocation,
            KernelConnectorAuthorityErrorV2::LimitExceeded => StableCode::PolicyLimitExceeded,
            KernelConnectorAuthorityErrorV2::Durable
            | KernelConnectorAuthorityErrorV2::Unavailable => StableCode::KernelUnavailable,
        },
        73..=75 => match error {
            KernelConnectorAuthorityErrorV2::InvalidReference
            | KernelConnectorAuthorityErrorV2::AlreadyConsumed
            | KernelConnectorAuthorityErrorV2::BindingMismatch
            | KernelConnectorAuthorityErrorV2::Denied
            | KernelConnectorAuthorityErrorV2::Expired
            | KernelConnectorAuthorityErrorV2::StateConflict => StableCode::HandleUnknown,
            KernelConnectorAuthorityErrorV2::LimitExceeded => StableCode::PolicyLimitExceeded,
            KernelConnectorAuthorityErrorV2::Durable
            | KernelConnectorAuthorityErrorV2::Unavailable => StableCode::KernelUnavailable,
        },
        76 => match error {
            KernelConnectorAuthorityErrorV2::InvalidReference
            | KernelConnectorAuthorityErrorV2::AlreadyConsumed
            | KernelConnectorAuthorityErrorV2::BindingMismatch
            | KernelConnectorAuthorityErrorV2::Denied
            | KernelConnectorAuthorityErrorV2::Expired => StableCode::HandleUnknown,
            KernelConnectorAuthorityErrorV2::StateConflict
            | KernelConnectorAuthorityErrorV2::LimitExceeded
            | KernelConnectorAuthorityErrorV2::Durable
            | KernelConnectorAuthorityErrorV2::Unavailable => StableCode::KernelUnavailable,
        },
        _ => StableCode::KernelUnavailable,
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixStream;
    use std::sync::atomic::Ordering;
    use std::sync::{mpsc, Arc, Mutex};
    use std::thread;
    use std::time::{Duration, Instant};

    use ed25519_dalek::SigningKey;
    use savana_kernel_protocol::v2::{
        decode_append_input_chunk_response_v2, decode_begin_input_response_v2,
        decode_finalize_input_response_v2, decode_kernel_agent_health_response_v2,
        decode_kernel_ingress_health_response_v2, derive_ed25519_key_id_v2,
        encode_kernel_ingress_operation_v2, encode_kernel_service_application_request_v2,
        encode_kernel_service_request_envelope_v2, input_channel_begin_digest_v2,
        input_channel_step_digest_v2, input_chunk_digest_v2,
        kernel_service_public_error_is_allowed_v2, AbortInputRequestV2, AppendInputChunkRequestV2,
        BeginInputRequestV2, BootIdV2, ContentKindV2, Digest32V2, DirectInputChannelV2,
        EndpointRoleV2, FinalizeInputRequestV2, IngressUiAuthorizationHandleV2,
        InputChannelCommitmentV2, InputChannelV2, InputSessionHandleV2, InputSourceKindV2,
        InputSourceProvenanceV2, InputStatusTargetV2, KernelAgentHealthRequestV2,
        KernelAgentOperationV2, KernelIngressHealthRequestV2, KernelIngressOperationV2,
        KernelServiceApplicationRequestV2, KernelServiceApplicationResponseBodyV2,
        KernelServiceApplicationResponseV2, KernelServiceHandshakeEdgeV2, KernelServiceOperationV2,
        KernelServiceRequestEnvelopeV2, Nonce32V2, PeerIdentityBindingV2, PublicServiceStateV2,
        PublicStableCodeV2, RequestIdV2, ServiceIdentityV2, UnixMillisV2, V2ClientHandshake,
        V2ClientTransportSession, V2ServerHandshake, VersionV2, ZeroizingBytesV2,
    };
    use savana_policy_core::v2::{
        declassification_implementation_digest_v2, ClosedDeclassificationPurposeV2,
        DeclassificationRuleSetV2, DeclassificationRuleV2, EffectSetV2, LeakGateDutyV2,
        OperationalTrustRootPurposeV2, OperationalTrustRootSetItemV2, OperationalTrustRootSetV2,
    };
    use sha2::{Digest as _, Sha256};
    use x25519_dalek::StaticSecret;

    use super::{map_connector_authority_error_for_tag, CoreKernelRuntimeServicesV2};
    use crate::policy_runtime::V2GenerationLease;
    use crate::v2_channel::{ChannelErrorV2, UnixV2FrameChannel, V2FrameChannel};
    use crate::v2_connection::serve_one_suite_one_v2_channel;
    use crate::v2_connector_authority::KernelConnectorAuthorityErrorV2;
    use crate::v2_declassification_policy::ActiveDeclassificationRuleSetV2;
    use crate::v2_dispatch::public_error_code;
    use crate::v2_dispatch::{
        KernelResponseFailurePointV2, KernelRuntimeResponsePreparationErrorV2,
        KernelServiceDeploymentV2, KernelServiceDispatcherV2, KernelServiceResponseBodyV2,
        PreparedKernelServiceResponseV2, SuiteOneResponseSessionSlotV2,
        VerifiedKernelServicePeerV2,
    };
    use crate::v2_ingress_authority::{KernelIngressAuthorityV2, KernelIngressSecurityConfigV2};
    use crate::v2_input_owner::{KernelInputPublicStateV2, KernelVerifiedUiAuthorizationV2};
    use crate::v2_kernel_owner::{
        KernelRuntimeOwnerV2, KernelRuntimeRequestV2, KernelRuntimeServicesV2,
    };
    use crate::v2_state_owner::StateOwnerCommitV2;
    use crate::v2_transport_owner::KernelV2HandshakeOwner;

    struct SharedCoreServicesV2(Arc<Mutex<CoreKernelRuntimeServicesV2>>);

    #[test]
    fn connector_error_mapping_is_closed_under_frozen_per_tag_contracts() {
        let errors = [
            KernelConnectorAuthorityErrorV2::InvalidReference,
            KernelConnectorAuthorityErrorV2::AlreadyConsumed,
            KernelConnectorAuthorityErrorV2::BindingMismatch,
            KernelConnectorAuthorityErrorV2::Denied,
            KernelConnectorAuthorityErrorV2::Expired,
            KernelConnectorAuthorityErrorV2::StateConflict,
            KernelConnectorAuthorityErrorV2::LimitExceeded,
            KernelConnectorAuthorityErrorV2::Durable,
            KernelConnectorAuthorityErrorV2::Unavailable,
        ];
        for tag in 70..=76 {
            for error in errors {
                let public = public_error_code(map_connector_authority_error_for_tag(tag, error));
                assert!(
                    kernel_service_public_error_is_allowed_v2(
                        EndpointRoleV2::AgentKernel,
                        tag,
                        public,
                    ),
                    "tag {tag} rejected mapped {error:?} as {public:?}",
                );
                KernelServiceApplicationResponseV2::error(
                    EndpointRoleV2::AgentKernel,
                    RequestIdV2::new([tag as u8; 16]),
                    tag,
                    public,
                )
                .unwrap();
            }
        }

        assert_eq!(
            public_error_code(map_connector_authority_error_for_tag(
                72,
                KernelConnectorAuthorityErrorV2::Denied,
            )),
            PublicStableCodeV2::ApprovalBindingMismatch,
        );
        for tag in 73..=76 {
            assert_eq!(
                public_error_code(map_connector_authority_error_for_tag(
                    tag,
                    KernelConnectorAuthorityErrorV2::BindingMismatch,
                )),
                PublicStableCodeV2::InvalidReference,
            );
        }
    }

    impl KernelRuntimeServicesV2 for SharedCoreServicesV2 {
        fn execute(
            &mut self,
            request: KernelRuntimeRequestV2,
            commit: Option<StateOwnerCommitV2>,
        ) -> Result<PreparedKernelServiceResponseV2, KernelRuntimeResponsePreparationErrorV2>
        {
            self.0
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .execute(request, commit)
        }
    }

    fn suite_one_response_session(
        request: &KernelServiceApplicationRequestV2,
    ) -> (SuiteOneResponseSessionSlotV2, V2ClientTransportSession) {
        suite_one_response_session_with_seed(request, 0xfb)
    }

    struct FailFinalRecordWriteChannelV2 {
        inner: UnixV2FrameChannel,
        record_writes: usize,
    }

    impl FailFinalRecordWriteChannelV2 {
        fn new(stream: UnixStream) -> Self {
            Self {
                inner: UnixV2FrameChannel::new(stream),
                record_writes: 0,
            }
        }
    }

    impl V2FrameChannel for FailFinalRecordWriteChannelV2 {
        fn read_handshake_frame(&mut self, deadline: Instant) -> Result<Vec<u8>, ChannelErrorV2> {
            self.inner.read_handshake_frame(deadline)
        }

        fn write_handshake_frame(
            &mut self,
            frame: &[u8],
            deadline: Instant,
        ) -> Result<(), ChannelErrorV2> {
            self.inner.write_handshake_frame(frame, deadline)
        }

        fn read_record_frame(&mut self, deadline: Instant) -> Result<Vec<u8>, ChannelErrorV2> {
            self.inner.read_record_frame(deadline)
        }

        fn write_record_frame(
            &mut self,
            frame: &[u8],
            deadline: Instant,
        ) -> Result<(), ChannelErrorV2> {
            self.record_writes += 1;
            if self.record_writes == 2 {
                return Err(ChannelErrorV2::Unavailable);
            }
            self.inner.write_record_frame(frame, deadline)
        }

        fn close(&mut self) {
            self.inner.close();
        }
    }

    fn finalize_handshake_material() -> (
        KernelServiceHandshakeEdgeV2,
        PeerIdentityBindingV2,
        SigningKey,
        SigningKey,
    ) {
        let client_key = SigningKey::from_bytes(&[0xf1; 32]);
        let server_key = SigningKey::from_bytes(&[0xf2; 32]);
        let observed =
            PeerIdentityBindingV2::linux(501, 502, 503, 504, Digest32V2::new([0xf3; 32])).unwrap();
        let edge = KernelServiceHandshakeEdgeV2::from_verified_deployment(
            EndpointRoleV2::IngressKernel,
            Digest32V2::new([0xf4; 32]),
            ServiceIdentityV2::new([0xe2; 32]),
            ServiceIdentityV2::new([0xe7; 32]),
            derive_ed25519_key_id_v2(client_key.verifying_key().to_bytes()),
            derive_ed25519_key_id_v2(server_key.verifying_key().to_bytes()),
            BootIdV2::new([0xe6; 32]),
            5,
            Digest32V2::new([0x35; 32]),
            7,
            8,
            Digest32V2::new([0xf5; 32]),
            Digest32V2::new([0xf6; 32]),
            Digest32V2::new([0xf7; 32]),
            Digest32V2::new([0xf8; 32]),
            Digest32V2::new([0xf9; 32]),
            Digest32V2::new([0xfa; 32]),
        )
        .unwrap();
        (edge, observed, client_key, server_key)
    }

    fn send_finalize_request_over_suite_one(
        stream: UnixStream,
        edge: KernelServiceHandshakeEdgeV2,
        observed: PeerIdentityBindingV2,
        client_key: &SigningKey,
        server_public_key: [u8; 32],
        seed: u8,
        request: &KernelServiceApplicationRequestV2,
    ) -> (UnixV2FrameChannel, V2ClientTransportSession) {
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut channel = UnixV2FrameChannel::new(stream);
        let (pending, hello) = V2ClientHandshake::start(
            edge,
            BootIdV2::new([0xe8; 32]),
            Nonce32V2::new([seed; 32]),
            observed,
            StaticSecret::from([seed.wrapping_add(1); 32]),
            client_key,
        )
        .unwrap();
        channel.write_handshake_frame(&hello, deadline).unwrap();
        let server_hello = channel.read_handshake_frame(deadline).unwrap();
        let (finish, mut session) = pending
            .accept_server_hello(&server_hello, server_public_key, client_key)
            .unwrap();
        channel.write_handshake_frame(&finish, deadline).unwrap();
        let accepted = channel.read_record_frame(deadline).unwrap();
        session.accept_server_confirmation(&accepted).unwrap();
        let canonical = encode_kernel_service_application_request_v2(request).unwrap();
        let record = session
            .seal_application_request(request.request_id(), request.operation().tag(), &canonical)
            .unwrap();
        channel.write_record_frame(&record, deadline).unwrap();
        (channel, session)
    }

    fn suite_one_response_session_with_seed(
        request: &KernelServiceApplicationRequestV2,
        seed: u8,
    ) -> (SuiteOneResponseSessionSlotV2, V2ClientTransportSession) {
        let client_key = SigningKey::from_bytes(&[0xf1; 32]);
        let server_key = SigningKey::from_bytes(&[0xf2; 32]);
        let observed =
            PeerIdentityBindingV2::linux(501, 502, 503, 504, Digest32V2::new([0xf3; 32])).unwrap();
        let edge = KernelServiceHandshakeEdgeV2::from_verified_deployment(
            EndpointRoleV2::IngressKernel,
            Digest32V2::new([0xf4; 32]),
            ServiceIdentityV2::new([0xe2; 32]),
            ServiceIdentityV2::new([0xe7; 32]),
            derive_ed25519_key_id_v2(client_key.verifying_key().to_bytes()),
            derive_ed25519_key_id_v2(server_key.verifying_key().to_bytes()),
            BootIdV2::new([0xe6; 32]),
            5,
            Digest32V2::new([0x35; 32]),
            7,
            8,
            Digest32V2::new([0xf5; 32]),
            Digest32V2::new([0xf6; 32]),
            Digest32V2::new([0xf7; 32]),
            Digest32V2::new([0xf8; 32]),
            Digest32V2::new([0xf9; 32]),
            Digest32V2::new([0xfa; 32]),
        )
        .unwrap();
        let (client, hello) = V2ClientHandshake::start(
            edge,
            BootIdV2::new([0xe8; 32]),
            Nonce32V2::new([seed; 32]),
            observed.clone(),
            StaticSecret::from([seed.wrapping_add(1); 32]),
            &client_key,
        )
        .unwrap();
        let (server, server_hello) = V2ServerHandshake::accept_client_hello(
            edge,
            observed,
            &hello,
            Nonce32V2::new([seed.wrapping_add(2); 32]),
            StaticSecret::from([seed.wrapping_add(3); 32]),
            client_key.verifying_key().to_bytes(),
            &server_key,
        )
        .unwrap();
        let (finish, mut client_session) = client
            .accept_server_hello(
                &server_hello,
                server_key.verifying_key().to_bytes(),
                &client_key,
            )
            .unwrap();
        let (accepted, mut server_session, _) = server.accept_client_finish(&finish).unwrap();
        client_session
            .accept_server_confirmation(&accepted)
            .unwrap();
        let plaintext = encode_kernel_service_application_request_v2(request).unwrap();
        let record = client_session
            .seal_application_request(request.request_id(), request.operation().tag(), &plaintext)
            .unwrap();
        let opened = server_session.open_application_request(&record).unwrap();
        assert_eq!(opened.plaintext(), plaintext);
        (
            SuiteOneResponseSessionSlotV2::new(server_session),
            client_session,
        )
    }

    struct FinalizeRecoveryFixtureV2 {
        shared: Arc<Mutex<CoreKernelRuntimeServicesV2>>,
        dispatcher: KernelServiceDispatcherV2,
        peer: VerifiedKernelServicePeerV2,
        lease_manifest: Digest32V2,
        session: savana_kernel_protocol::v2::InputSessionHandleV2,
        finalize: FinalizeInputRequestV2,
    }

    impl FinalizeRecoveryFixtureV2 {
        fn request(
            &self,
            request_id: RequestIdV2,
            finalize: FinalizeInputRequestV2,
        ) -> KernelServiceApplicationRequestV2 {
            self.request_with_logical_deadline(request_id, finalize, UnixMillisV2::new(1_000))
        }

        fn request_with_logical_deadline(
            &self,
            request_id: RequestIdV2,
            finalize: FinalizeInputRequestV2,
            logical_deadline: UnixMillisV2,
        ) -> KernelServiceApplicationRequestV2 {
            KernelServiceApplicationRequestV2::new(
                EndpointRoleV2::IngressKernel,
                request_id,
                logical_deadline,
                KernelServiceOperationV2::ingress(KernelIngressOperationV2::FinalizeInput(
                    finalize,
                )),
            )
            .unwrap()
        }
    }

    fn finalize_recovery_fixture() -> FinalizeRecoveryFixtureV2 {
        finalize_recovery_fixture_with_hook(None)
    }

    fn add_receiving_finalize_session(
        services: &mut CoreKernelRuntimeServicesV2,
        manifest: Digest32V2,
        caller: ServiceIdentityV2,
        seed: u8,
    ) -> (InputSessionHandleV2, FinalizeInputRequestV2) {
        let authorization =
            IngressUiAuthorizationHandleV2::from_authority_entropy([seed; 32]).unwrap();
        services
            .input
            .register_verified_ui_authorization(
                authorization,
                KernelVerifiedUiAuthorizationV2::for_test_with_expiry(UnixMillisV2::new(10_000)),
            )
            .unwrap();
        let bytes = b"a distinct valid receiving session for request-id collision";
        let begin = services
            .execute_operation(
                RequestIdV2::new([seed.wrapping_add(1); 16]),
                KernelServiceOperationV2::ingress(KernelIngressOperationV2::BeginInput(
                    BeginInputRequestV2::new(
                        authorization,
                        ContentKindV2::ChatText,
                        bytes.len() as u64,
                        Some(Digest32V2::new(Sha256::digest(bytes).into())),
                    )
                    .unwrap(),
                )),
                UnixMillisV2::new(130),
                manifest,
                7,
                9,
                caller,
            )
            .unwrap();
        let begun = decode_begin_input_response_v2(begin.as_bytes()).unwrap();
        let initial = input_channel_begin_digest_v2(begun.session(), InputChannelV2::ChatText);
        let chunk =
            input_chunk_digest_v2(begun.session(), InputChannelV2::ChatText, 0, bytes).unwrap();
        let cumulative = input_channel_step_digest_v2(initial, 0, chunk).unwrap();
        let append = services
            .execute_operation(
                RequestIdV2::new([seed.wrapping_add(2); 16]),
                KernelServiceOperationV2::ingress(KernelIngressOperationV2::AppendInputChunk(
                    AppendInputChunkRequestV2::new(
                        begun.writer(),
                        DirectInputChannelV2::ChatText,
                        0,
                        initial,
                        ZeroizingBytesV2::new(bytes.to_vec()).unwrap(),
                        chunk,
                        cumulative,
                    )
                    .unwrap(),
                )),
                UnixMillisV2::new(131),
                manifest,
                7,
                9,
                caller,
            )
            .unwrap();
        let accepted = decode_append_input_chunk_response_v2(append.as_bytes()).unwrap();
        let finalize = FinalizeInputRequestV2::new(
            begun.session(),
            vec![InputChannelCommitmentV2::new(
                InputChannelV2::ChatText,
                1,
                0,
                bytes.len() as u64,
                accepted.cumulative_digest(),
            )
            .unwrap()],
            InputSourceProvenanceV2::direct(
                InputSourceKindV2::Chat,
                bytes.len() as u64,
                Digest32V2::new(Sha256::digest(bytes).into()),
                VersionV2::new(1, 0, 0),
            )
            .unwrap(),
        )
        .unwrap();
        (begun.session(), finalize)
    }

    fn finalize_panic_hook(
        panic_before_commit: bool,
        panic_after_claim: bool,
        panic_after_publish: bool,
    ) -> super::FinalizeLinearizationHookV2 {
        let (before_commit_reached, before_commit_observed) = mpsc::sync_channel(1);
        let (release_before_commit, release_before_commit_rx) = mpsc::channel();
        let (after_publish_reached, after_publish_observed) = mpsc::sync_channel(1);
        let (release_after_publish, release_after_publish_rx) = mpsc::channel();
        release_before_commit.send(()).unwrap();
        release_after_publish.send(()).unwrap();
        drop(before_commit_observed);
        drop(after_publish_observed);
        super::FinalizeLinearizationHookV2 {
            before_commit_reached,
            release_before_commit: release_before_commit_rx,
            after_publish_reached,
            release_after_publish: release_after_publish_rx,
            panic_before_commit,
            panic_after_claim,
            panic_after_publish,
        }
    }

    fn finalize_recovery_fixture_with_hook(
        linearization_hook: Option<super::FinalizeLinearizationHookV2>,
    ) -> FinalizeRecoveryFixtureV2 {
        let mut services = CoreKernelRuntimeServicesV2::new(4, 4096, 4, 32).unwrap();
        services.finalize_linearization_hook = linearization_hook;
        services.ingress_authority = Some(approval_authority(ApprovalRuleModeV2::Admit));
        let authorization =
            IngressUiAuthorizationHandleV2::from_authority_entropy([0xb1; 32]).unwrap();
        services
            .input
            .register_verified_ui_authorization(
                authorization,
                KernelVerifiedUiAuthorizationV2::for_test_with_expiry(UnixMillisV2::new(10_000)),
            )
            .unwrap();
        let manifest = Digest32V2::new([0x35; 32]);
        let caller = ServiceIdentityV2::new([0xe2; 32]);
        let bytes = b"recover the exact committed finalize result";
        let begin = services
            .execute_operation(
                RequestIdV2::new([0xb2; 16]),
                KernelServiceOperationV2::ingress(KernelIngressOperationV2::BeginInput(
                    BeginInputRequestV2::new(
                        authorization,
                        ContentKindV2::ChatText,
                        bytes.len() as u64,
                        Some(Digest32V2::new(Sha256::digest(bytes).into())),
                    )
                    .unwrap(),
                )),
                UnixMillisV2::new(100),
                manifest,
                7,
                9,
                caller,
            )
            .unwrap();
        let begun = decode_begin_input_response_v2(begin.as_bytes()).unwrap();
        let initial = input_channel_begin_digest_v2(begun.session(), InputChannelV2::ChatText);
        let chunk =
            input_chunk_digest_v2(begun.session(), InputChannelV2::ChatText, 0, bytes).unwrap();
        let cumulative = input_channel_step_digest_v2(initial, 0, chunk).unwrap();
        let append = services
            .execute_operation(
                RequestIdV2::new([0xb3; 16]),
                KernelServiceOperationV2::ingress(KernelIngressOperationV2::AppendInputChunk(
                    AppendInputChunkRequestV2::new(
                        begun.writer(),
                        DirectInputChannelV2::ChatText,
                        0,
                        initial,
                        ZeroizingBytesV2::new(bytes.to_vec()).unwrap(),
                        chunk,
                        cumulative,
                    )
                    .unwrap(),
                )),
                UnixMillisV2::new(110),
                manifest,
                7,
                9,
                caller,
            )
            .unwrap();
        let accepted = decode_append_input_chunk_response_v2(append.as_bytes()).unwrap();
        let finalize = FinalizeInputRequestV2::new(
            begun.session(),
            vec![InputChannelCommitmentV2::new(
                InputChannelV2::ChatText,
                1,
                0,
                bytes.len() as u64,
                accepted.cumulative_digest(),
            )
            .unwrap()],
            InputSourceProvenanceV2::direct(
                InputSourceKindV2::Chat,
                bytes.len() as u64,
                Digest32V2::new(Sha256::digest(bytes).into()),
                VersionV2::new(1, 0, 0),
            )
            .unwrap(),
        )
        .unwrap();
        let shared = Arc::new(Mutex::new(services));
        let owner =
            KernelRuntimeOwnerV2::spawn(4, SharedCoreServicesV2(Arc::clone(&shared))).unwrap();
        let signing_key = SigningKey::from_bytes(&[0xb4; 32]);
        let dispatcher = KernelServiceDispatcherV2::spawn(
            KernelServiceDeploymentV2::from_verified_startup(
                BootIdV2::new([0xe6; 32]),
                ServiceIdentityV2::new([0xe7; 32]),
                manifest,
                7,
            )
            .unwrap(),
            derive_ed25519_key_id_v2(signing_key.verifying_key().to_bytes()),
            signing_key,
            owner,
        )
        .unwrap();
        let peer = VerifiedKernelServicePeerV2::from_test_mutual_authentication(
            EndpointRoleV2::IngressKernel,
            BootIdV2::new([0xe8; 32]),
            caller,
            PeerIdentityBindingV2::linux(501, 502, 503, 504, Digest32V2::new([0xf3; 32])).unwrap(),
        )
        .unwrap();
        FinalizeRecoveryFixtureV2 {
            shared,
            dispatcher,
            peer,
            lease_manifest: manifest,
            session: begun.session(),
            finalize,
        }
    }

    #[derive(Clone, Copy)]
    enum ApprovalRuleModeV2 {
        Admit,
        NoRule,
        WrongImplementation,
    }

    fn approval_authority(mode: ApprovalRuleModeV2) -> KernelIngressAuthorityV2 {
        let installer = SigningKey::from_bytes(&[0xc1; 32]);
        let declassification_authority = SigningKey::from_bytes(&[0xc2; 32]);
        let product = Digest32V2::new([0xc3; 32]);
        let roots = OperationalTrustRootSetV2::new_declassification_signed_for_test(
            product,
            1,
            None,
            vec![OperationalTrustRootSetItemV2::new(
                OperationalTrustRootPurposeV2::DeclassificationAuthority,
                declassification_authority.verifying_key().to_bytes(),
                1,
                1,
                10_000,
            )
            .unwrap()],
            1,
            10_000,
            &installer,
            1,
        )
        .unwrap();
        let (tag, purpose, implementation, duty) = match mode {
            ApprovalRuleModeV2::Admit => (
                3,
                ClosedDeclassificationPurposeV2::ApprovalDisplay,
                declassification_implementation_digest_v2(3).unwrap(),
                LeakGateDutyV2::BlocklistOnly,
            ),
            ApprovalRuleModeV2::NoRule => (
                1,
                ClosedDeclassificationPurposeV2::AgentIngressMasking,
                declassification_implementation_digest_v2(1).unwrap(),
                LeakGateDutyV2::BlocklistAndNoResidualPii,
            ),
            ApprovalRuleModeV2::WrongImplementation => (
                3,
                ClosedDeclassificationPurposeV2::ApprovalDisplay,
                Digest32V2::new([0xc4; 32]),
                LeakGateDutyV2::BlocklistOnly,
            ),
        };
        let rules = DeclassificationRuleSetV2::new_signed_for_test(
            product,
            1,
            None,
            vec![DeclassificationRuleV2::new_for_test(
                tag,
                purpose,
                implementation,
                duty,
                None,
                None,
                1,
                10_000,
            )
            .unwrap()],
            1,
            10_000,
            &roots,
            &declassification_authority,
            1,
            100,
        )
        .unwrap();
        let envelope_key = SigningKey::from_bytes(&[0xc5; 32]);
        let ui_key = SigningKey::from_bytes(&[0xc6; 32]);
        let settlement_key = SigningKey::from_bytes(&[0xc7; 32]);
        KernelIngressAuthorityV2::new(
            KernelIngressSecurityConfigV2::new(
                Digest32V2::new([0x30; 32]),
                ServiceIdentityV2::new([0xc8; 32]),
                ServiceIdentityV2::new([0xc9; 32]),
                envelope_key,
                derive_ed25519_key_id_v2(ui_key.verifying_key().to_bytes()),
                ui_key.verifying_key().to_bytes(),
                derive_ed25519_key_id_v2(settlement_key.verifying_key().to_bytes()),
                settlement_key.verifying_key().to_bytes(),
                ActiveDeclassificationRuleSetV2::new(rules, Arc::new(roots)).unwrap(),
                EffectSetV2::SEND,
            )
            .unwrap(),
            8,
        )
        .unwrap()
    }

    #[test]
    fn production_runtime_requires_all_security_adapters_before_readiness() {
        let (services, _) =
            CoreKernelRuntimeServicesV2::new_production_starting(4, 4096, 4, 32).unwrap();
        assert_eq!(
            services.verify_production_complete().unwrap_err(),
            savana_kernel_protocol::StableCode::KernelUnavailable,
        );
    }

    #[test]
    fn health_becomes_ready_only_after_the_startup_authority_publishes_once() {
        let (mut services, readiness) =
            CoreKernelRuntimeServicesV2::new_starting(4, 4096, 4, 32).unwrap();

        let agent_before = services
            .execute_operation(
                RequestIdV2::new([0x51; 16]),
                KernelServiceOperationV2::agent(KernelAgentOperationV2::Health(
                    KernelAgentHealthRequestV2,
                )),
                UnixMillisV2::new(100),
                Digest32V2::new([0x35; 32]),
                7,
                9,
                ServiceIdentityV2::new([0x43; 32]),
            )
            .unwrap();
        let ingress_before = services
            .execute_operation(
                RequestIdV2::new([0x52; 16]),
                KernelServiceOperationV2::ingress(KernelIngressOperationV2::Health(
                    KernelIngressHealthRequestV2,
                )),
                UnixMillisV2::new(100),
                Digest32V2::new([0x35; 32]),
                7,
                9,
                ServiceIdentityV2::new([0x44; 32]),
            )
            .unwrap();
        assert_eq!(
            decode_kernel_agent_health_response_v2(agent_before.as_bytes()).unwrap(),
            savana_kernel_protocol::v2::KernelAgentHealthResponseV2::new(
                false,
                PublicServiceStateV2::Starting,
            )
        );
        assert_eq!(
            decode_kernel_ingress_health_response_v2(ingress_before.as_bytes()).unwrap(),
            savana_kernel_protocol::v2::KernelIngressHealthResponseV2::new(
                false,
                PublicServiceStateV2::Starting,
            )
        );

        readiness.publish_ready().unwrap();
        assert!(readiness.publish_ready().is_err());

        let agent_after = services
            .execute_operation(
                RequestIdV2::new([0x53; 16]),
                KernelServiceOperationV2::agent(KernelAgentOperationV2::Health(
                    KernelAgentHealthRequestV2,
                )),
                UnixMillisV2::new(101),
                Digest32V2::new([0x35; 32]),
                7,
                9,
                ServiceIdentityV2::new([0x43; 32]),
            )
            .unwrap();
        let ingress_after = services
            .execute_operation(
                RequestIdV2::new([0x54; 16]),
                KernelServiceOperationV2::ingress(KernelIngressOperationV2::Health(
                    KernelIngressHealthRequestV2,
                )),
                UnixMillisV2::new(101),
                Digest32V2::new([0x35; 32]),
                7,
                9,
                ServiceIdentityV2::new([0x44; 32]),
            )
            .unwrap();
        assert_eq!(
            decode_kernel_agent_health_response_v2(agent_after.as_bytes()).unwrap(),
            savana_kernel_protocol::v2::KernelAgentHealthResponseV2::new(
                true,
                PublicServiceStateV2::Ready,
            )
        );
        assert_eq!(
            decode_kernel_ingress_health_response_v2(ingress_after.as_bytes()).unwrap(),
            savana_kernel_protocol::v2::KernelIngressHealthResponseV2::new(
                true,
                PublicServiceStateV2::Ready,
            )
        );
    }

    #[test]
    fn core_services_execute_real_begin_input_and_emit_typed_success() {
        let mut services = CoreKernelRuntimeServicesV2::new(4, 4096, 4, 32).unwrap();
        let authorization =
            IngressUiAuthorizationHandleV2::from_authority_entropy([0x41; 32]).unwrap();
        services
            .input
            .register_verified_ui_authorization(
                authorization,
                KernelVerifiedUiAuthorizationV2::for_test(),
            )
            .unwrap();
        let operation = KernelIngressOperationV2::BeginInput(
            BeginInputRequestV2::new(
                authorization,
                ContentKindV2::ChatText,
                3,
                Some(Digest32V2::new([0x42; 32])),
            )
            .unwrap(),
        );
        let canonical_request = encode_kernel_ingress_operation_v2(&operation).unwrap();
        assert!(!canonical_request.is_empty());
        let response = services
            .execute_operation(
                RequestIdV2::new([0x55; 16]),
                KernelServiceOperationV2::ingress(operation),
                UnixMillisV2::new(100),
                Digest32V2::new([0x35; 32]),
                7,
                9,
                ServiceIdentityV2::new([0x43; 32]),
            )
            .unwrap();
        let decoded = decode_begin_input_response_v2(response.as_bytes()).unwrap();
        assert_eq!(decoded.next_sequences().len(), 1);
        assert_eq!(decoded.next_sequences()[0].next_sequence(), 0);
    }

    #[test]
    fn core_structured_task_handler_binds_finalized_input_and_returns_exact_retry_receipt() {
        use crate::v2_agent_authority::tests::{planner_active_tools, task_issuer_agent_fixture};
        use crate::v2_task_authority::tests::{draft, issuer, owner};
        use savana_kernel_protocol::v2::{
            decode_establish_task_authorization_response_v2, EstablishTaskAuthorizationRequestV2,
            Nonce32V2,
        };
        let (input, session, commitment) =
            crate::v2_input_owner::tests::finalized_task_input_fixture();
        let dir = tempfile::tempdir().unwrap();
        let mut services = CoreKernelRuntimeServicesV2::new(4, 4096, 4, 32).unwrap();
        services.input = input;
        services
            .install_agent_security(task_issuer_agent_fixture(owner(dir.path()), issuer()))
            .unwrap();
        let d = draft(&planner_active_tools(), commitment, 1, "Alice");
        let request =
            EstablishTaskAuthorizationRequestV2::new(session, d, Nonce32V2::new([88; 32])).unwrap();
        let mut execute = |request: EstablishTaskAuthorizationRequestV2, id: u8| {
            services.execute_operation(
                RequestIdV2::new([id; 16]),
                KernelServiceOperationV2::ingress(
                    KernelIngressOperationV2::EstablishTaskAuthorization(request),
                ),
                UnixMillisV2::new(200),
                Digest32V2::new([0x35; 32]),
                7,
                9,
                ServiceIdentityV2::new([67; 32]),
            )
        };
        let wrong = EstablishTaskAuthorizationRequestV2::new(
            session,
            draft(
                &planner_active_tools(),
                Digest32V2::new([89; 32]),
                1,
                "Alice",
            ),
            Nonce32V2::new([88; 32]),
        )
        .unwrap();
        assert!(execute(wrong, 1).is_err());
        let first = execute(request.clone(), 2).unwrap();
        let second = execute(request, 3).unwrap();
        assert_eq!(first.as_bytes(), second.as_bytes());
        assert!(decode_establish_task_authorization_response_v2(first.as_bytes()).is_ok());
    }

    #[test]
    fn core_task_approval_preparation_returns_the_same_persisted_display_pair() {
        use crate::v2_agent_authority::tests::{planner_active_tools, task_issuer_agent_fixture};
        use crate::v2_task_authority::tests::{draft, ingress, issuer, owner};
        use savana_kernel_protocol::v2::{
            decode_prepare_task_authorization_approval_response_v2, Nonce32V2,
            PrepareTaskAuthorizationApprovalRequestV2,
        };
        let (input, session, commitment) =
            crate::v2_input_owner::tests::finalized_task_input_fixture();
        let dir = tempfile::tempdir().unwrap();
        let mut services = CoreKernelRuntimeServicesV2::new(4, 4096, 4, 32).unwrap();
        services.input = input;
        services.ingress_authority = Some(ingress(true));
        services
            .install_agent_security(task_issuer_agent_fixture(owner(dir.path()), issuer()))
            .unwrap();
        let request = PrepareTaskAuthorizationApprovalRequestV2::new(
            session,
            draft(&planner_active_tools(), commitment, 1, "Alice"),
            Nonce32V2::new([88; 32]),
        )
        .unwrap();
        let mut execute = |id: u8| {
            services.execute_operation(
                RequestIdV2::new([id; 16]),
                KernelServiceOperationV2::ingress(
                    KernelIngressOperationV2::PrepareTaskAuthorizationApproval(request.clone()),
                ),
                UnixMillisV2::new(200),
                Digest32V2::new([0x35; 32]),
                7,
                9,
                ServiceIdentityV2::new([67; 32]),
            )
        };
        let first = execute(1).unwrap();
        let retry = execute(2).unwrap();
        assert_eq!(first.as_bytes(), retry.as_bytes());
        let decoded =
            decode_prepare_task_authorization_approval_response_v2(first.as_bytes()).unwrap();
        assert_eq!(
            decoded
                .envelope()
                .unverified_material()
                .unwrap()
                .display_text(),
            &request.draft().render_approval_text().unwrap()
        );
    }

    #[test]
    fn fresh_authenticated_task_recovery_reuses_durable_issuance_without_new_input_or_grant() {
        use crate::v2_agent_authority::tests::{
            planner_active_tools, task_issuer_agent_fixture, TestG4StateAnchorV2,
        };
        use crate::v2_input_owner::tests::{
            finalized_task_input_fixture, fresh_task_recovery_authentication,
        };
        use crate::v2_task_authority::tests::{draft, ingress, issuer};
        use savana_kernel_protocol::v2::*;
        use savana_policy_core::v2::{
            DurableG4StateV2, DurableStateNamespaceV2, RollbackProtectedStateAnchorV2,
        };
        use std::os::unix::fs::PermissionsExt;
        for approved_draft in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            let anchor = TestG4StateAnchorV2::default();
            let open = || {
                DurableG4StateV2::open(
                    &dir.path().join("kernel-g4-state-v2.cbor"),
                    [72; 32],
                    DurableStateNamespaceV2::from_verified_installation(
                        Digest32V2::new([0x30; 32]),
                        Digest32V2::new([73; 32]),
                    )
                    .unwrap(),
                    Box::new(anchor.clone()),
                )
                .unwrap()
            };
            let new_services = |owner| {
                let mut s = CoreKernelRuntimeServicesV2::new(8, 4096, 8, 32).unwrap();
                s.ingress_authority = Some(ingress(true));
                s.install_agent_security(task_issuer_agent_fixture(owner, issuer()))
                    .unwrap();
                s
            };
            let execute = |s: &mut CoreKernelRuntimeServicesV2, operation, time| {
                s.execute_operation(
                    RequestIdV2::new([80; 16]),
                    KernelServiceOperationV2::ingress(operation),
                    UnixMillisV2::new(time),
                    Digest32V2::new([0x35; 32]),
                    7,
                    9,
                    ServiceIdentityV2::new([67; 32]),
                )
            };
            let mut services = new_services(open());
            let (input, session, commitment) = finalized_task_input_fixture();
            services.input = input;
            let request = EstablishTaskAuthorizationRequestV2::new(
                session,
                draft(&planner_active_tools(), commitment, 1, "Alice"),
                Nonce32V2::new([88; 32]),
            )
            .unwrap();
            let first = execute(
                &mut services,
                if approved_draft {
                    KernelIngressOperationV2::PrepareTaskAuthorizationApproval(request)
                } else {
                    KernelIngressOperationV2::EstablishTaskAuthorization(request)
                },
                200,
            )
            .unwrap();
            let expected = if approved_draft {
                RecoverTaskAuthorizationResponseV2::Approval(
                    decode_prepare_task_authorization_approval_response_v2(first.as_bytes())
                        .unwrap(),
                )
            } else {
                RecoverTaskAuthorizationResponseV2::Installed(
                    decode_establish_task_authorization_response_v2(first.as_bytes()).unwrap(),
                )
            };
            let id = match &expected {
                RecoverTaskAuthorizationResponseV2::Approval(p) => p.request_digest(),
                RecoverTaskAuthorizationResponseV2::Installed(p) => p.request_digest(),
            };
            let before = anchor.current_head().unwrap();
            drop(services); // Input/session handles and browser state really disappear.
            let mut recovered = new_services(open());
            assert_eq!(recovered.input.retained_plaintext_bytes(), 0);
            for (i, bad_principal, bad_task, bad_id, time) in [
                (90, true, false, false, 201),
                (91, false, true, false, 201),
                (92, false, false, true, 201),
                (93, false, false, false, 500),
            ] {
                let auth = fresh_task_recovery_authentication(
                    &mut recovered.input,
                    i,
                    bad_principal,
                    bad_task,
                );
                let req = RecoverTaskAuthorizationRequestV2::new(
                    auth,
                    if bad_id {
                        Digest32V2::new([99; 32])
                    } else {
                        id
                    },
                )
                .unwrap();
                assert!(execute(
                    &mut recovered,
                    KernelIngressOperationV2::RecoverTaskAuthorization(req),
                    time
                )
                .is_err());
            }
            let auth = fresh_task_recovery_authentication(&mut recovered.input, 94, false, false);
            let req = RecoverTaskAuthorizationRequestV2::new(auth, id).unwrap();
            for _ in 0..2 {
                let response = execute(
                    &mut recovered,
                    KernelIngressOperationV2::RecoverTaskAuthorization(req),
                    202,
                )
                .unwrap();
                assert_eq!(
                    response.as_bytes(),
                    encode_recover_task_authorization_response_v2(&expected).unwrap()
                );
                assert_eq!(anchor.current_head().unwrap(), before, "recovery must not sign/install another grant, reset counters, or rewrite the existing display");
            }
            if !approved_draft {
                drop(recovered);
                let mut owner = open();
                owner
                    .revoke_task_authorization(DurableTaskIdV2::new([0x2f; 32]))
                    .unwrap();
                drop(owner);
                let revoked_head = anchor.current_head().unwrap();
                let mut recovered = new_services(open());
                let auth =
                    fresh_task_recovery_authentication(&mut recovered.input, 95, false, false);
                let req = RecoverTaskAuthorizationRequestV2::new(auth, id).unwrap();
                assert!(execute(
                    &mut recovered,
                    KernelIngressOperationV2::RecoverTaskAuthorization(req),
                    203
                )
                .is_err());
                assert_eq!(anchor.current_head().unwrap(), revoked_head);
            }
        }
    }

    #[test]
    fn finalize_gate_refusal_preserves_retryable_session_and_exact_bytes() {
        for refused_mode in [
            ApprovalRuleModeV2::NoRule,
            ApprovalRuleModeV2::WrongImplementation,
        ] {
            let mut services = CoreKernelRuntimeServicesV2::new(4, 4096, 4, 32).unwrap();
            services.ingress_authority = Some(approval_authority(refused_mode));
            let authorization =
                IngressUiAuthorizationHandleV2::from_authority_entropy([0xd1; 32]).unwrap();
            services
                .input
                .register_verified_ui_authorization(
                    authorization,
                    KernelVerifiedUiAuthorizationV2::for_test(),
                )
                .unwrap();
            let manifest = Digest32V2::new([0x35; 32]);
            let caller = ServiceIdentityV2::new([0xd2; 32]);
            let bytes = b"atomic ingress bytes";
            let begin = services
                .execute_operation(
                    RequestIdV2::new([0xd3; 16]),
                    KernelServiceOperationV2::ingress(KernelIngressOperationV2::BeginInput(
                        BeginInputRequestV2::new(
                            authorization,
                            ContentKindV2::ChatText,
                            bytes.len() as u64,
                            Some(Digest32V2::new(Sha256::digest(bytes).into())),
                        )
                        .unwrap(),
                    )),
                    UnixMillisV2::new(100),
                    manifest,
                    7,
                    9,
                    caller,
                )
                .unwrap();
            let begun = decode_begin_input_response_v2(begin.as_bytes()).unwrap();
            let initial_cumulative_digest =
                input_channel_begin_digest_v2(begun.session(), InputChannelV2::ChatText);
            let chunk_digest =
                input_chunk_digest_v2(begun.session(), InputChannelV2::ChatText, 0, bytes).unwrap();
            let cumulative_digest =
                input_channel_step_digest_v2(initial_cumulative_digest, 0, chunk_digest).unwrap();
            let append_request = || {
                AppendInputChunkRequestV2::new(
                    begun.writer(),
                    DirectInputChannelV2::ChatText,
                    0,
                    initial_cumulative_digest,
                    ZeroizingBytesV2::new(bytes.to_vec()).unwrap(),
                    chunk_digest,
                    cumulative_digest,
                )
                .unwrap()
            };
            let append = services
                .execute_operation(
                    RequestIdV2::new([0xd4; 16]),
                    KernelServiceOperationV2::ingress(KernelIngressOperationV2::AppendInputChunk(
                        append_request(),
                    )),
                    UnixMillisV2::new(110),
                    manifest,
                    7,
                    9,
                    caller,
                )
                .unwrap();
            let accepted = decode_append_input_chunk_response_v2(append.as_bytes()).unwrap();
            let finalize_request = FinalizeInputRequestV2::new(
                begun.session(),
                vec![InputChannelCommitmentV2::new(
                    InputChannelV2::ChatText,
                    1,
                    0,
                    bytes.len() as u64,
                    accepted.cumulative_digest(),
                )
                .unwrap()],
                InputSourceProvenanceV2::direct(
                    InputSourceKindV2::Chat,
                    bytes.len() as u64,
                    Digest32V2::new(Sha256::digest(bytes).into()),
                    VersionV2::new(1, 0, 0),
                )
                .unwrap(),
            )
            .unwrap();

            assert_eq!(
                services.execute_operation(
                    RequestIdV2::new([0xd5; 16]),
                    KernelServiceOperationV2::ingress(KernelIngressOperationV2::FinalizeInput(
                        finalize_request.clone(),
                    )),
                    UnixMillisV2::new(120),
                    manifest,
                    7,
                    9,
                    caller,
                ),
                Err(savana_kernel_protocol::StableCode::ApprovalBindingMismatch),
            );
            assert_eq!(
                services
                    .input
                    .status(InputStatusTargetV2::Session(begun.session()))
                    .unwrap(),
                KernelInputPublicStateV2::Receiving,
            );
            let replay = services
                .execute_operation(
                    RequestIdV2::new([0xd6; 16]),
                    KernelServiceOperationV2::ingress(KernelIngressOperationV2::AppendInputChunk(
                        append_request(),
                    )),
                    UnixMillisV2::new(121),
                    manifest,
                    7,
                    9,
                    caller,
                )
                .unwrap();
            assert_eq!(replay.as_bytes(), append.as_bytes());

            let refused_authority = services
                .ingress_authority
                .replace(approval_authority(ApprovalRuleModeV2::Admit))
                .unwrap();
            assert_eq!(refused_authority.pending_record_count(), 0);
            let finalized = services
                .execute_operation(
                    RequestIdV2::new([0xd7; 16]),
                    KernelServiceOperationV2::ingress(KernelIngressOperationV2::FinalizeInput(
                        finalize_request.clone(),
                    )),
                    UnixMillisV2::new(130),
                    manifest,
                    7,
                    9,
                    caller,
                )
                .unwrap();
            let finalized = decode_finalize_input_response_v2(finalized.as_bytes()).unwrap();
            assert_ne!(
                finalized.envelope().envelope_digest().unwrap().as_bytes(),
                &[0; 32],
            );
            assert_eq!(
                services
                    .input
                    .status(InputStatusTargetV2::Session(begun.session()))
                    .unwrap(),
                KernelInputPublicStateV2::Finalized,
            );
            assert_eq!(
                services.execute_operation(
                    RequestIdV2::new([0xd8; 16]),
                    KernelServiceOperationV2::ingress(KernelIngressOperationV2::FinalizeInput(
                        finalize_request,
                    )),
                    UnixMillisV2::new(131),
                    manifest,
                    7,
                    9,
                    caller,
                ),
                Err(savana_kernel_protocol::StableCode::PolicyDenied),
            );
        }
    }

    #[test]
    fn task_context_uses_finalized_source_and_fresh_auth_without_issuing_authority() {
        use crate::v2_agent_authority::tests::{planner_active_tools, task_issuer_agent_fixture};
        use crate::v2_input_owner::tests::{
            finalized_task_input_fixture, fresh_task_recovery_authentication,
        };
        use crate::v2_task_authority::tests::{draft, issuer, owner};
        use savana_kernel_protocol::v2::*;
        let (input, session, commitment) = finalized_task_input_fixture();
        let dir = tempfile::tempdir().unwrap();
        let mut services = CoreKernelRuntimeServicesV2::new(8, 4096, 8, 32).unwrap();
        services.input = input;
        services
            .install_agent_security(task_issuer_agent_fixture(owner(dir.path()), issuer()))
            .unwrap();
        let auth = IngressUiAuthorizationHandleV2::from_authority_entropy([0x41; 32]).unwrap();
        let manifest = Digest32V2::new([0x35; 32]);
        let read = |services: &mut CoreKernelRuntimeServicesV2, auth, session, time| {
            services.execute_operation(
                RequestIdV2::new([88; 16]),
                KernelServiceOperationV2::ingress(
                    KernelIngressOperationV2::GetTaskAuthorizationContext(
                        GetTaskAuthorizationContextRequestV2::new(auth, session),
                    ),
                ),
                UnixMillisV2::new(time),
                manifest,
                7,
                9,
                ServiceIdentityV2::new([67; 32]),
            )
        };
        // No finalized source and no durable history: fail rather than inventing one.
        assert!(read(&mut services, auth, None, 200).is_err());
        let context = decode_task_authorization_context_v2(
            read(&mut services, auth, Some(session), 200)
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
        assert_eq!(context.source_input_digest(), commitment);
        assert_eq!(context.authorization_identity(), None);
        assert!(context.pending_requests().is_empty());
        assert_eq!(context.tools().len(), planner_active_tools().len());
        let proposal = draft(&planner_active_tools(), commitment, 1, "Alice");
        let built = context
            .draft(proposal.authorization_id(), proposal.clauses().to_vec())
            .unwrap();
        assert_eq!(built.principal(), proposal.principal());
        assert_eq!(built.source_input_digest(), commitment);
        let proof = services
            .input
            .authenticate_task_draft_submission(
                session,
                &built,
                manifest,
                7,
                UnixMillisV2::new(200),
            )
            .unwrap();
        assert!(!proof.is_recovery());
        assert!(read(&mut services, auth, Some(session), 1000).is_err());
        let new_auth = fresh_task_recovery_authentication(&mut services.input, 90, false, false);
        assert!(read(&mut services, new_auth, Some(session), 201).is_err());
        let request = PrepareTaskAuthorizationApprovalRequestV2::new(
            session,
            built,
            Nonce32V2::new([89; 32]),
        )
        .unwrap();
        let pending = services
            .agent_authority
            .as_mut()
            .unwrap()
            .prepare_task_approval(&request, &proof, UnixMillisV2::new(200))
            .unwrap();
        let observed = decode_task_authorization_context_v2(
            read(&mut services, new_auth, None, 201).unwrap().as_bytes(),
        )
        .unwrap();
        assert_eq!(observed.source_input_digest(), commitment);
        assert_eq!(observed.pending_requests(), &[pending.request_digest()]);
        assert_eq!(
            observed.authorization_identity(),
            Some((proposal.authorization_id(), 1))
        );
        assert!(services
            .agent_authority
            .as_ref()
            .unwrap()
            .recover_task_issuance_record(pending.request_digest())
            .unwrap()
            .installed_digest()
            .is_none());
        for (entropy, principal, task) in [(91, true, false), (92, false, true)] {
            let wrong =
                fresh_task_recovery_authentication(&mut services.input, entropy, principal, task);
            assert!(read(&mut services, wrong, None, 201).is_err());
        }
    }

    #[test]
    fn recovery_of_persisted_draft_without_display_requires_new_task_approval() {
        use crate::v2_agent_authority::tests::{planner_active_tools, task_issuer_agent_fixture};
        use crate::v2_input_owner::tests::{
            finalized_task_input_fixture, fresh_task_recovery_authentication,
        };
        use crate::v2_task_authority::tests::{draft, ingress, issuer, owner};
        use savana_kernel_protocol::v2::*;
        let registry = planner_active_tools();
        let (input, session, commitment) = finalized_task_input_fixture();
        let draft = draft(&registry, commitment, 1, "Alice");
        let proof = input
            .authenticate_task_draft_submission(
                session,
                &draft,
                Digest32V2::new([0x35; 32]),
                7,
                UnixMillisV2::new(200),
            )
            .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut durable = owner(dir.path());
        let issuer = issuer();
        let request_digest = Digest32V2::new([88; 32]);
        issuer
            .prepare(
                &mut durable,
                &registry,
                RoleIdV2::new(1),
                &proof,
                draft.clone(),
                request_digest,
                UnixMillisV2::new(200),
            )
            .unwrap();
        drop(input);
        let mut services = CoreKernelRuntimeServicesV2::new(8, 4096, 8, 32).unwrap();
        services.ingress_authority = Some(ingress(true));
        services
            .install_agent_security(task_issuer_agent_fixture(durable, issuer))
            .unwrap();
        let auth = fresh_task_recovery_authentication(&mut services.input, 90, false, false);
        let request = RecoverTaskAuthorizationRequestV2::new(auth, request_digest).unwrap();
        let response = services
            .execute_operation(
                RequestIdV2::new([80; 16]),
                KernelServiceOperationV2::ingress(
                    KernelIngressOperationV2::RecoverTaskAuthorization(request),
                ),
                UnixMillisV2::new(201),
                Digest32V2::new([0x35; 32]),
                7,
                9,
                ServiceIdentityV2::new([67; 32]),
            )
            .unwrap();
        let RecoverTaskAuthorizationResponseV2::Approval(prepared) =
            decode_recover_task_authorization_response_v2(response.as_bytes()).unwrap()
        else {
            panic!("recovery must not install a grant without task approval");
        };
        let agent = services.agent_authority.as_ref().unwrap();
        let pending = agent.recover_task_issuance_record(request_digest).unwrap();
        assert_eq!(pending.draft(), &draft);
        assert_eq!(pending.envelope(), Some(prepared.envelope()));
        assert_eq!(pending.installed_digest(), None);
        assert_eq!(
            prepared.envelope().unverified_material().unwrap().purpose(),
            ApprovalPurposeV2::TaskAuthorization
        );
    }

    #[test]
    fn finalize_response_construction_failure_is_atomic_across_real_dispatch() {
        for failure in [
            KernelResponseFailurePointV2::TypedWrapper,
            KernelResponseFailurePointV2::ApplicationWrapper,
            KernelResponseFailurePointV2::SignedEnvelope,
            KernelResponseFailurePointV2::SuiteOneSeal,
        ] {
            let mut services = CoreKernelRuntimeServicesV2::new(4, 4096, 4, 32).unwrap();
            services.ingress_authority = Some(approval_authority(ApprovalRuleModeV2::Admit));
            let authorization =
                IngressUiAuthorizationHandleV2::from_authority_entropy([0xe1; 32]).unwrap();
            services
                .input
                .register_verified_ui_authorization(
                    authorization,
                    KernelVerifiedUiAuthorizationV2::for_test(),
                )
                .unwrap();
            let manifest = Digest32V2::new([0x35; 32]);
            let caller = ServiceIdentityV2::new([0xe2; 32]);
            let bytes = b"response construction remains transactional";
            let begin = services
                .execute_operation(
                    RequestIdV2::new([0xe3; 16]),
                    KernelServiceOperationV2::ingress(KernelIngressOperationV2::BeginInput(
                        BeginInputRequestV2::new(
                            authorization,
                            ContentKindV2::ChatText,
                            bytes.len() as u64,
                            Some(Digest32V2::new(Sha256::digest(bytes).into())),
                        )
                        .unwrap(),
                    )),
                    UnixMillisV2::new(100),
                    manifest,
                    7,
                    9,
                    caller,
                )
                .unwrap();
            let begun = decode_begin_input_response_v2(begin.as_bytes()).unwrap();
            let initial = input_channel_begin_digest_v2(begun.session(), InputChannelV2::ChatText);
            let chunk =
                input_chunk_digest_v2(begun.session(), InputChannelV2::ChatText, 0, bytes).unwrap();
            let cumulative = input_channel_step_digest_v2(initial, 0, chunk).unwrap();
            let append_request = || {
                AppendInputChunkRequestV2::new(
                    begun.writer(),
                    DirectInputChannelV2::ChatText,
                    0,
                    initial,
                    ZeroizingBytesV2::new(bytes.to_vec()).unwrap(),
                    chunk,
                    cumulative,
                )
                .unwrap()
            };
            let append = services
                .execute_operation(
                    RequestIdV2::new([0xe4; 16]),
                    KernelServiceOperationV2::ingress(KernelIngressOperationV2::AppendInputChunk(
                        append_request(),
                    )),
                    UnixMillisV2::new(110),
                    manifest,
                    7,
                    9,
                    caller,
                )
                .unwrap();
            let accepted = decode_append_input_chunk_response_v2(append.as_bytes()).unwrap();
            let finalize_request = FinalizeInputRequestV2::new(
                begun.session(),
                vec![InputChannelCommitmentV2::new(
                    InputChannelV2::ChatText,
                    1,
                    0,
                    bytes.len() as u64,
                    accepted.cumulative_digest(),
                )
                .unwrap()],
                InputSourceProvenanceV2::direct(
                    InputSourceKindV2::Chat,
                    bytes.len() as u64,
                    Digest32V2::new(Sha256::digest(bytes).into()),
                    VersionV2::new(1, 0, 0),
                )
                .unwrap(),
            )
            .unwrap();

            let shared = Arc::new(Mutex::new(services));
            let owner =
                KernelRuntimeOwnerV2::spawn(4, SharedCoreServicesV2(Arc::clone(&shared))).unwrap();
            let signing_key = SigningKey::from_bytes(&[0xe5; 32]);
            let dispatcher = KernelServiceDispatcherV2::spawn(
                KernelServiceDeploymentV2::from_verified_startup(
                    BootIdV2::new([0xe6; 32]),
                    ServiceIdentityV2::new([0xe7; 32]),
                    manifest,
                    7,
                )
                .unwrap(),
                derive_ed25519_key_id_v2(signing_key.verifying_key().to_bytes()),
                signing_key,
                owner,
            )
            .unwrap();
            let peer = VerifiedKernelServicePeerV2::from_test_mutual_authentication(
                EndpointRoleV2::IngressKernel,
                BootIdV2::new([0xe8; 32]),
                caller,
                PeerIdentityBindingV2::linux(501, 502, 503, 504, Digest32V2::new([0xf3; 32]))
                    .unwrap(),
            )
            .unwrap();
            let application_request = |request_id| {
                KernelServiceApplicationRequestV2::new(
                    EndpointRoleV2::IngressKernel,
                    request_id,
                    UnixMillisV2::new(1_000),
                    KernelServiceOperationV2::ingress(KernelIngressOperationV2::FinalizeInput(
                        finalize_request.clone(),
                    )),
                )
                .unwrap()
            };

            let failure_result = if failure == KernelResponseFailurePointV2::SignedEnvelope {
                let canonical = encode_kernel_service_request_envelope_v2(
                    &KernelServiceRequestEnvelopeV2::from_authenticated_connection(
                        EndpointRoleV2::IngressKernel,
                        RequestIdV2::new([0xe9; 16]),
                        BootIdV2::new([0xe8; 32]),
                        BootIdV2::new([0xe6; 32]),
                        caller,
                        ServiceIdentityV2::new([0xe7; 32]),
                        manifest,
                        7,
                        UnixMillisV2::new(1_000),
                        KernelServiceOperationV2::ingress(KernelIngressOperationV2::FinalizeInput(
                            finalize_request.clone(),
                        )),
                    )
                    .unwrap(),
                )
                .unwrap();
                dispatcher
                    .dispatch_one_signed_with_failure_for_test(
                        peer.clone(),
                        V2GenerationLease::for_dispatch_test(manifest, 7),
                        &canonical,
                        UnixMillisV2::new(120),
                        Instant::now() + Duration::from_secs(1),
                        failure,
                    )
                    .map(|_| ())
            } else if failure == KernelResponseFailurePointV2::SuiteOneSeal {
                let request = application_request(RequestIdV2::new([0xe9; 16]));
                let (response_session, mut client_session) = suite_one_response_session(&request);
                let result = dispatcher
                    .dispatch_one_suite_one_with_failure_for_test(
                        peer.clone(),
                        V2GenerationLease::for_dispatch_test(manifest, 7),
                        request,
                        response_session.clone(),
                        UnixMillisV2::new(120),
                        Instant::now() + Duration::from_secs(1),
                        failure,
                    )
                    .map(|_| ());
                let closed_error = response_session
                    .seal_public_error(
                        EndpointRoleV2::IngressKernel,
                        RequestIdV2::new([0xe9; 16]),
                        42,
                        savana_kernel_protocol::v2::PublicStableCodeV2::ServiceUnavailable,
                    )
                    .unwrap();
                client_session
                    .open_application_response(&closed_error)
                    .unwrap();
                result
            } else {
                dispatcher
                    .dispatch_one_application_with_failure_for_test(
                        peer.clone(),
                        V2GenerationLease::for_dispatch_test(manifest, 7),
                        application_request(RequestIdV2::new([0xe9; 16])),
                        UnixMillisV2::new(120),
                        Instant::now() + Duration::from_secs(1),
                        failure,
                    )
                    .map(|_| ())
            };
            assert_eq!(
                failure_result,
                Err(crate::v2_dispatch::KernelServiceDispatchErrorV2::Unavailable),
            );
            {
                let mut services = shared.lock().unwrap();
                assert_eq!(
                    services
                        .input
                        .status(InputStatusTargetV2::Session(begun.session()))
                        .unwrap(),
                    KernelInputPublicStateV2::Receiving,
                );
                assert_eq!(
                    services
                        .ingress_authority
                        .as_ref()
                        .unwrap()
                        .pending_record_count(),
                    0,
                );
                let replay = services
                    .execute_operation(
                        RequestIdV2::new([0xea; 16]),
                        KernelServiceOperationV2::ingress(
                            KernelIngressOperationV2::AppendInputChunk(append_request()),
                        ),
                        UnixMillisV2::new(121),
                        manifest,
                        7,
                        9,
                        caller,
                    )
                    .unwrap();
                assert_eq!(replay.as_bytes(), append.as_bytes());
            }

            let success = dispatcher
                .dispatch_one_application(
                    peer.clone(),
                    V2GenerationLease::for_dispatch_test(manifest, 7),
                    application_request(RequestIdV2::new([0xeb; 16])),
                    UnixMillisV2::new(130),
                    Instant::now() + Duration::from_secs(1),
                )
                .unwrap();
            let KernelServiceApplicationResponseBodyV2::Success(body) = success.body() else {
                panic!("retry must return success")
            };
            decode_finalize_input_response_v2(body).unwrap();
            let duplicate = dispatcher
                .dispatch_one_application(
                    peer.clone(),
                    V2GenerationLease::for_dispatch_test(manifest, 7),
                    application_request(RequestIdV2::new([0xec; 16])),
                    UnixMillisV2::new(131),
                    Instant::now() + Duration::from_secs(1),
                )
                .unwrap();
            assert_eq!(
                duplicate.body(),
                &KernelServiceApplicationResponseBodyV2::Error(
                    savana_kernel_protocol::v2::PublicStableCodeV2::PolicyDenied,
                ),
            );
            let services = shared.lock().unwrap();
            assert_eq!(
                services
                    .ingress_authority
                    .as_ref()
                    .unwrap()
                    .pending_record_count(),
                1,
            );
        }
    }

    #[test]
    fn finalize_panic_before_claim_is_fail_stop_without_input_or_pending_mutation() {
        let fixture =
            finalize_recovery_fixture_with_hook(Some(finalize_panic_hook(true, false, false)));
        let request_id = RequestIdV2::new([0xbc; 16]);
        let request = fixture.request(request_id, fixture.finalize.clone());
        let (response_session, _) = suite_one_response_session_with_seed(&request, 0xe1);

        assert_eq!(
            fixture.dispatcher.dispatch_one_suite_one(
                fixture.peer.clone(),
                V2GenerationLease::for_dispatch_test(fixture.lease_manifest, 7),
                request,
                response_session,
                UnixMillisV2::new(120),
                Instant::now() + Duration::from_secs(1),
            ),
            Err(crate::v2_dispatch::KernelServiceDispatchErrorV2::Unavailable),
        );
        assert_eq!(
            fixture.dispatcher.dispatch_one_application(
                fixture.peer.clone(),
                V2GenerationLease::for_dispatch_test(fixture.lease_manifest, 7),
                fixture.request(request_id, fixture.finalize.clone()),
                UnixMillisV2::new(121),
                Instant::now() + Duration::from_secs(1),
            ),
            Err(crate::v2_dispatch::KernelServiceDispatchErrorV2::Unavailable),
        );
        let services = fixture
            .shared
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert_eq!(
            services
                .input
                .status(InputStatusTargetV2::Session(fixture.session))
                .unwrap(),
            KernelInputPublicStateV2::Receiving,
        );
        assert_eq!(
            services
                .ingress_authority
                .as_ref()
                .unwrap()
                .pending_record_count(),
            0,
        );
    }

    #[test]
    fn finalize_panic_after_claim_before_durable_publication_remains_fail_stop() {
        let fixture =
            finalize_recovery_fixture_with_hook(Some(finalize_panic_hook(false, true, false)));
        let request_id = RequestIdV2::new([0xbd; 16]);
        let request = fixture.request(request_id, fixture.finalize.clone());
        let (response_session, _) = suite_one_response_session_with_seed(&request, 0xe2);

        assert_eq!(
            fixture.dispatcher.dispatch_one_suite_one(
                fixture.peer.clone(),
                V2GenerationLease::for_dispatch_test(fixture.lease_manifest, 7),
                request,
                response_session,
                UnixMillisV2::new(120),
                Instant::now() + Duration::from_secs(1),
            ),
            Err(crate::v2_dispatch::KernelServiceDispatchErrorV2::Unavailable),
        );
        assert_eq!(
            fixture.dispatcher.dispatch_one_application(
                fixture.peer.clone(),
                V2GenerationLease::for_dispatch_test(fixture.lease_manifest, 7),
                fixture.request(request_id, fixture.finalize.clone()),
                UnixMillisV2::new(121),
                Instant::now() + Duration::from_secs(1),
            ),
            Err(crate::v2_dispatch::KernelServiceDispatchErrorV2::Unavailable),
        );
        let services = fixture
            .shared
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert_eq!(
            services
                .input
                .status(InputStatusTargetV2::Session(fixture.session))
                .unwrap(),
            KernelInputPublicStateV2::Receiving,
        );
        assert_eq!(
            services
                .ingress_authority
                .as_ref()
                .unwrap()
                .pending_record_count(),
            0,
        );
    }

    #[test]
    fn finalize_panic_after_durable_publication_keeps_exact_retry_recoverable() {
        let fixture =
            finalize_recovery_fixture_with_hook(Some(finalize_panic_hook(false, false, true)));
        let request_id = RequestIdV2::new([0xbe; 16]);
        let request = fixture.request(request_id, fixture.finalize.clone());
        let (response_session, _) = suite_one_response_session_with_seed(&request, 0xe3);

        assert_eq!(
            fixture.dispatcher.dispatch_one_suite_one(
                fixture.peer.clone(),
                V2GenerationLease::for_dispatch_test(fixture.lease_manifest, 7),
                request,
                response_session,
                UnixMillisV2::new(120),
                Instant::now() + Duration::from_secs(1),
            ),
            Err(crate::v2_dispatch::KernelServiceDispatchErrorV2::Unavailable),
        );
        fixture
            .shared
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .finalize_linearization_hook = None;
        let retry = fixture.request(request_id, fixture.finalize.clone());
        let (retry_session, mut retry_client) = suite_one_response_session_with_seed(&retry, 0xe4);
        let recovered_record = fixture
            .dispatcher
            .dispatch_one_suite_one(
                fixture.peer.clone(),
                V2GenerationLease::for_dispatch_test(fixture.lease_manifest, 7),
                retry,
                retry_session,
                UnixMillisV2::new(121),
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
        let recovered = retry_client
            .open_application_response(&recovered_record)
            .unwrap();
        let recovered = savana_kernel_protocol::v2::decode_kernel_service_application_response_v2(
            recovered.plaintext(),
            EndpointRoleV2::IngressKernel,
            42,
        )
        .unwrap();
        assert!(matches!(
            recovered.body(),
            KernelServiceApplicationResponseBodyV2::Success(body)
                if decode_finalize_input_response_v2(body).is_ok()
        ));
        let services = fixture
            .shared
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert_eq!(
            services
                .input
                .status(InputStatusTargetV2::Session(fixture.session))
                .unwrap(),
            KernelInputPublicStateV2::Finalized,
        );
        assert_eq!(
            services
                .ingress_authority
                .as_ref()
                .unwrap()
                .pending_record_count(),
            1,
        );
    }

    #[test]
    fn finalize_deadline_cancellation_wins_at_real_precommit_and_preserves_closed_error() {
        let (before_tx, before_rx) = mpsc::sync_channel(1);
        let (release_before_tx, release_before_rx) = mpsc::channel();
        let (after_tx, _after_rx) = mpsc::sync_channel(1);
        let (_release_after_tx, release_after_rx) = mpsc::channel();
        let fixture =
            finalize_recovery_fixture_with_hook(Some(super::FinalizeLinearizationHookV2 {
                before_commit_reached: before_tx,
                release_before_commit: release_before_rx,
                after_publish_reached: after_tx,
                release_after_publish: release_after_rx,
                panic_before_commit: false,
                panic_after_claim: false,
                panic_after_publish: false,
            }));
        let request_id = RequestIdV2::new([0xba; 16]);
        let request = fixture.request(request_id, fixture.finalize.clone());
        let (response_session, mut client_session) =
            suite_one_response_session_with_seed(&request, 0xc1);
        let dispatcher = Arc::new(fixture.dispatcher);
        let deadline = Instant::now() + Duration::from_secs(2);
        let requesting = {
            let dispatcher = Arc::clone(&dispatcher);
            let response_session = response_session.clone();
            thread::spawn(move || {
                dispatcher.dispatch_one_suite_one(
                    fixture.peer.clone(),
                    V2GenerationLease::for_dispatch_test(fixture.lease_manifest, 7),
                    request,
                    response_session,
                    UnixMillisV2::new(120),
                    deadline,
                )
            })
        };
        before_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(
            requesting.join().unwrap(),
            Err(crate::v2_dispatch::KernelServiceDispatchErrorV2::DeadlineExceeded),
        );
        let closed_error = response_session
            .cancel_staged_and_seal_public_error(
                EndpointRoleV2::IngressKernel,
                request_id,
                42,
                savana_kernel_protocol::v2::PublicStableCodeV2::DeadlineExceeded,
            )
            .unwrap();
        let opened = client_session
            .open_application_response(&closed_error)
            .unwrap();
        let response = savana_kernel_protocol::v2::decode_kernel_service_application_response_v2(
            opened.plaintext(),
            EndpointRoleV2::IngressKernel,
            42,
        )
        .unwrap();
        assert_eq!(
            response.body(),
            &KernelServiceApplicationResponseBodyV2::Error(
                savana_kernel_protocol::v2::PublicStableCodeV2::DeadlineExceeded,
            ),
        );
        release_before_tx.send(()).unwrap();
        let services = fixture.shared.lock().unwrap();
        assert_eq!(
            services
                .input
                .status(InputStatusTargetV2::Session(fixture.session))
                .unwrap(),
            KernelInputPublicStateV2::Receiving,
        );
        assert_eq!(
            services
                .ingress_authority
                .as_ref()
                .unwrap()
                .pending_record_count(),
            0,
        );
    }

    #[test]
    fn finalize_commit_wins_at_real_precommit_and_returns_success_after_deadline() {
        let (before_tx, before_rx) = mpsc::sync_channel(1);
        let (release_before_tx, release_before_rx) = mpsc::channel();
        let (after_tx, after_rx) = mpsc::sync_channel(1);
        let (release_after_tx, release_after_rx) = mpsc::channel();
        let fixture =
            finalize_recovery_fixture_with_hook(Some(super::FinalizeLinearizationHookV2 {
                before_commit_reached: before_tx,
                release_before_commit: release_before_rx,
                after_publish_reached: after_tx,
                release_after_publish: release_after_rx,
                panic_before_commit: false,
                panic_after_claim: false,
                panic_after_publish: false,
            }));
        let request_id = RequestIdV2::new([0xbb; 16]);
        let request = fixture.request(request_id, fixture.finalize.clone());
        let (response_session, mut client_session) =
            suite_one_response_session_with_seed(&request, 0xd1);
        let dispatcher = Arc::new(fixture.dispatcher);
        let deadline = Instant::now() + Duration::from_secs(2);
        let (result_tx, result_rx) = mpsc::channel();
        let requesting = {
            let dispatcher = Arc::clone(&dispatcher);
            thread::spawn(move || {
                let result = dispatcher.dispatch_one_suite_one(
                    fixture.peer.clone(),
                    V2GenerationLease::for_dispatch_test(fixture.lease_manifest, 7),
                    request,
                    response_session,
                    UnixMillisV2::new(120),
                    deadline,
                );
                result_tx.send(result).unwrap();
            })
        };
        before_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        release_before_tx.send(()).unwrap();
        after_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        while Instant::now() < deadline + Duration::from_millis(20) {
            thread::yield_now();
        }
        assert!(result_rx.try_recv().is_err());
        release_after_tx.send(()).unwrap();
        let response_record = result_rx
            .recv_timeout(Duration::from_secs(1))
            .unwrap()
            .unwrap();
        requesting.join().unwrap();
        let opened = client_session
            .open_application_response(&response_record)
            .unwrap();
        let response = savana_kernel_protocol::v2::decode_kernel_service_application_response_v2(
            opened.plaintext(),
            EndpointRoleV2::IngressKernel,
            42,
        )
        .unwrap();
        assert!(matches!(
            response.body(),
            KernelServiceApplicationResponseBodyV2::Success(body)
                if decode_finalize_input_response_v2(body).is_ok()
        ));
        let services = fixture.shared.lock().unwrap();
        assert_eq!(
            services
                .input
                .status(InputStatusTargetV2::Session(fixture.session))
                .unwrap(),
            KernelInputPublicStateV2::Finalized,
        );
        assert_eq!(
            services
                .ingress_authority
                .as_ref()
                .unwrap()
                .pending_record_count(),
            1,
        );
    }

    #[test]
    fn final_channel_write_loss_is_recovered_on_a_fresh_authenticated_connection() {
        let fixture = finalize_recovery_fixture();
        let request_id = RequestIdV2::new([0xbf; 16]);
        let request = fixture.request(request_id, fixture.finalize.clone());
        let shared = Arc::clone(&fixture.shared);
        let lease_manifest = fixture.lease_manifest;
        let input_session = fixture.session;
        let dispatcher = Arc::new(fixture.dispatcher);
        let (edge, observed, client_key, server_key) = finalize_handshake_material();
        let server_public_key = server_key.verifying_key().to_bytes();
        let handshake_owner = Arc::new(
            KernelV2HandshakeOwner::spawn(
                edge,
                client_key.verifying_key().to_bytes(),
                server_key,
                4,
            )
            .unwrap(),
        );

        let (first_client_stream, first_server_stream) = UnixStream::pair().unwrap();
        let first_owner = Arc::clone(&handshake_owner);
        let first_dispatcher = Arc::clone(&dispatcher);
        let first_observed = observed.clone();
        let first_server = thread::spawn(move || {
            let mut channel = FailFinalRecordWriteChannelV2::new(first_server_stream);
            let result = serve_one_suite_one_v2_channel(
                &mut channel,
                first_observed,
                V2GenerationLease::for_dispatch_test(lease_manifest, 7),
                first_owner.as_ref(),
                first_dispatcher.as_ref(),
                UnixMillisV2::new(120),
                Instant::now() + Duration::from_secs(3),
            );
            let record_writes = channel.record_writes;
            channel.close();
            (result, record_writes)
        });
        let (mut first_channel, _first_session) = send_finalize_request_over_suite_one(
            first_client_stream,
            edge,
            observed.clone(),
            &client_key,
            server_public_key,
            0xf0,
            &request,
        );
        let (first_result, record_writes) = first_server.join().unwrap();
        assert_eq!(
            first_result,
            Err(crate::v2_dispatch::KernelServiceDispatchErrorV2::Unavailable),
        );
        assert_eq!(record_writes, 2, "failure must be the final record write");
        assert!(first_channel
            .read_record_frame(Instant::now() + Duration::from_millis(100))
            .is_err());

        {
            let services = shared.lock().unwrap();
            assert_eq!(
                services
                    .input
                    .status(InputStatusTargetV2::Session(input_session))
                    .unwrap(),
                KernelInputPublicStateV2::Finalized,
            );
            assert_eq!(
                services
                    .ingress_authority
                    .as_ref()
                    .unwrap()
                    .pending_record_count(),
                1,
            );
        }

        let (retry_client_stream, retry_server_stream) = UnixStream::pair().unwrap();
        let retry_owner = Arc::clone(&handshake_owner);
        let retry_dispatcher = Arc::clone(&dispatcher);
        let retry_observed = observed.clone();
        let retry_server = thread::spawn(move || {
            let mut channel = UnixV2FrameChannel::new(retry_server_stream);
            let result = serve_one_suite_one_v2_channel(
                &mut channel,
                retry_observed,
                V2GenerationLease::for_dispatch_test(lease_manifest, 7),
                retry_owner.as_ref(),
                retry_dispatcher.as_ref(),
                UnixMillisV2::new(121),
                Instant::now() + Duration::from_secs(3),
            );
            channel.close();
            result
        });
        let (mut retry_channel, mut retry_session) = send_finalize_request_over_suite_one(
            retry_client_stream,
            edge,
            observed,
            &client_key,
            server_public_key,
            0xf4,
            &request,
        );
        let recovered_record = retry_channel
            .read_record_frame(Instant::now() + Duration::from_secs(3))
            .unwrap();
        assert_eq!(retry_server.join().unwrap(), Ok(()));
        let recovered = retry_session
            .open_application_response(&recovered_record)
            .unwrap();
        let recovered = savana_kernel_protocol::v2::decode_kernel_service_application_response_v2(
            recovered.plaintext(),
            EndpointRoleV2::IngressKernel,
            42,
        )
        .unwrap();
        assert!(matches!(
            recovered.body(),
            KernelServiceApplicationResponseBodyV2::Success(body)
                if decode_finalize_input_response_v2(body).is_ok()
        ));
        let services = shared.lock().unwrap();
        assert_eq!(
            services
                .ingress_authority
                .as_ref()
                .unwrap()
                .pending_record_count(),
            1,
            "recovery must not create a duplicate pending ingress",
        );
    }

    #[test]
    fn runtime_queue_busy_leaves_suite_one_session_available_for_closed_overload() {
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let executions = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let executions_for_handler = Arc::clone(&executions);
        let owner = KernelRuntimeOwnerV2::spawn_for_test(1, move |_| {
            if executions_for_handler.fetch_add(1, Ordering::AcqRel) == 0 {
                entered_tx.send(()).unwrap();
                release_rx.recv().unwrap();
            }
            Ok(KernelServiceResponseBodyV2::from_typed_handler(vec![0x80]).unwrap())
        })
        .unwrap();
        let signing_key = SigningKey::from_bytes(&[0xb4; 32]);
        let dispatcher = Arc::new(
            KernelServiceDispatcherV2::spawn(
                KernelServiceDeploymentV2::from_verified_startup(
                    BootIdV2::new([0xe6; 32]),
                    ServiceIdentityV2::new([0xe7; 32]),
                    Digest32V2::new([0x35; 32]),
                    7,
                )
                .unwrap(),
                derive_ed25519_key_id_v2(signing_key.verifying_key().to_bytes()),
                signing_key,
                owner,
            )
            .unwrap(),
        );
        let peer = VerifiedKernelServicePeerV2::from_test_mutual_authentication(
            EndpointRoleV2::IngressKernel,
            BootIdV2::new([0xe8; 32]),
            ServiceIdentityV2::new([0xe2; 32]),
            PeerIdentityBindingV2::linux(501, 502, 503, 504, Digest32V2::new([0xf3; 32])).unwrap(),
        )
        .unwrap();
        let request = |id: u8| {
            KernelServiceApplicationRequestV2::new(
                EndpointRoleV2::IngressKernel,
                RequestIdV2::new([id; 16]),
                UnixMillisV2::new(1_000),
                KernelServiceOperationV2::ingress(KernelIngressOperationV2::AbortInput(
                    AbortInputRequestV2::new(
                        InputSessionHandleV2::from_authority_entropy([id.wrapping_add(1); 32])
                            .unwrap(),
                    ),
                )),
            )
            .unwrap()
        };

        let first_dispatcher = Arc::clone(&dispatcher);
        let first_peer = peer.clone();
        let first = thread::spawn(move || {
            first_dispatcher.dispatch_one_application(
                first_peer,
                V2GenerationLease::for_dispatch_test(Digest32V2::new([0x35; 32]), 7),
                request(0xc1),
                UnixMillisV2::new(100),
                Instant::now() + Duration::from_secs(3),
            )
        });
        entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        let second_dispatcher = Arc::clone(&dispatcher);
        let second_peer = peer.clone();
        let second = thread::spawn(move || {
            second_dispatcher.dispatch_one_application(
                second_peer,
                V2GenerationLease::for_dispatch_test(Digest32V2::new([0x35; 32]), 7),
                request(0xc2),
                UnixMillisV2::new(100),
                Instant::now() + Duration::from_secs(3),
            )
        });
        let queued_deadline = Instant::now() + Duration::from_secs(1);
        while dispatcher.queued_for_test() == 0 && Instant::now() < queued_deadline {
            thread::yield_now();
        }
        assert_eq!(dispatcher.queued_for_test(), 1);

        let busy_request = request(0xc3);
        let operation_tag = busy_request.operation().tag();
        let (response_session, mut client_session) =
            suite_one_response_session_with_seed(&busy_request, 0xe5);
        assert_eq!(
            dispatcher.dispatch_one_suite_one(
                peer.clone(),
                V2GenerationLease::for_dispatch_test(Digest32V2::new([0x35; 32]), 7),
                busy_request,
                response_session.clone(),
                UnixMillisV2::new(100),
                Instant::now() + Duration::from_secs(1),
            ),
            Err(crate::v2_dispatch::KernelServiceDispatchErrorV2::Busy),
        );
        let overload = response_session
            .seal_public_error(
                EndpointRoleV2::IngressKernel,
                RequestIdV2::new([0xc3; 16]),
                operation_tag,
                savana_kernel_protocol::v2::PublicStableCodeV2::Overloaded,
            )
            .unwrap();
        let opened = client_session.open_application_response(&overload).unwrap();
        let response = savana_kernel_protocol::v2::decode_kernel_service_application_response_v2(
            opened.plaintext(),
            EndpointRoleV2::IngressKernel,
            operation_tag,
        )
        .unwrap();
        assert_eq!(
            response.body(),
            &KernelServiceApplicationResponseBodyV2::Error(
                savana_kernel_protocol::v2::PublicStableCodeV2::Overloaded,
            ),
        );
        release_tx.send(()).unwrap();
        assert!(first.join().unwrap().is_ok());
        assert!(second.join().unwrap().is_ok());
        assert_eq!(executions.load(Ordering::Acquire), 2);
    }

    #[test]
    fn recovered_finalize_delivery_obeys_the_fresh_connection_absolute_deadline() {
        let fixture = finalize_recovery_fixture();
        let request_id = RequestIdV2::new([0xc0; 16]);
        let initial_request = fixture.request(request_id, fixture.finalize.clone());
        let (initial_session, _) = suite_one_response_session_with_seed(&initial_request, 0xd5);
        fixture
            .dispatcher
            .dispatch_one_suite_one(
                fixture.peer.clone(),
                V2GenerationLease::for_dispatch_test(fixture.lease_manifest, 7),
                initial_request,
                initial_session,
                UnixMillisV2::new(120),
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();

        let (before_tx, before_rx) = mpsc::sync_channel(1);
        let (release_before_tx, release_before_rx) = mpsc::channel();
        let (after_tx, _after_rx) = mpsc::sync_channel(1);
        let (_release_after_tx, release_after_rx) = mpsc::channel();
        fixture.shared.lock().unwrap().finalize_linearization_hook =
            Some(super::FinalizeLinearizationHookV2 {
                before_commit_reached: before_tx,
                release_before_commit: release_before_rx,
                after_publish_reached: after_tx,
                release_after_publish: release_after_rx,
                panic_before_commit: false,
                panic_after_claim: false,
                panic_after_publish: false,
            });
        let retry = fixture.request(request_id, fixture.finalize.clone());
        let (response_session, mut retry_client) =
            suite_one_response_session_with_seed(&retry, 0xd6);
        let dispatcher = Arc::new(fixture.dispatcher);
        let deadline = Instant::now() + Duration::from_millis(300);
        let requesting = {
            let dispatcher = Arc::clone(&dispatcher);
            let response_session = response_session.clone();
            thread::spawn(move || {
                dispatcher.dispatch_one_suite_one(
                    fixture.peer.clone(),
                    V2GenerationLease::for_dispatch_test(fixture.lease_manifest, 7),
                    retry,
                    response_session,
                    UnixMillisV2::new(121),
                    deadline,
                )
            })
        };
        before_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(
            requesting.join().unwrap(),
            Err(crate::v2_dispatch::KernelServiceDispatchErrorV2::DeadlineExceeded),
        );
        let closed_error = response_session
            .cancel_staged_and_seal_public_error(
                EndpointRoleV2::IngressKernel,
                request_id,
                42,
                savana_kernel_protocol::v2::PublicStableCodeV2::DeadlineExceeded,
            )
            .unwrap();
        let opened = retry_client
            .open_application_response(&closed_error)
            .unwrap();
        let response = savana_kernel_protocol::v2::decode_kernel_service_application_response_v2(
            opened.plaintext(),
            EndpointRoleV2::IngressKernel,
            42,
        )
        .unwrap();
        assert_eq!(
            response.body(),
            &KernelServiceApplicationResponseBodyV2::Error(
                savana_kernel_protocol::v2::PublicStableCodeV2::DeadlineExceeded,
            ),
        );
        release_before_tx.send(()).unwrap();
        let services = fixture.shared.lock().unwrap();
        assert_eq!(
            services
                .input
                .status(InputStatusTargetV2::Session(fixture.session))
                .unwrap(),
            KernelInputPublicStateV2::Finalized,
        );
        assert_eq!(
            services
                .ingress_authority
                .as_ref()
                .unwrap()
                .pending_record_count(),
            1,
        );
    }

    #[test]
    fn exact_committed_finalize_recovers_after_original_logical_deadline() {
        let fixture = finalize_recovery_fixture();
        let request_id = RequestIdV2::new([0xc4; 16]);
        let original_request = fixture.request(request_id, fixture.finalize.clone());
        let (initial_slot, mut initial_client) =
            suite_one_response_session_with_seed(&original_request, 0xd7);
        let initial_record = fixture
            .dispatcher
            .dispatch_one_suite_one(
                fixture.peer.clone(),
                V2GenerationLease::for_dispatch_test(fixture.lease_manifest, 7),
                original_request,
                initial_slot,
                UnixMillisV2::new(120),
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
        let initial_opened = initial_client
            .open_application_response(&initial_record)
            .unwrap();
        let initial_response =
            savana_kernel_protocol::v2::decode_kernel_service_application_response_v2(
                initial_opened.plaintext(),
                EndpointRoleV2::IngressKernel,
                42,
            )
            .unwrap();
        let KernelServiceApplicationResponseBodyV2::Success(initial_body) = initial_response.body()
        else {
            panic!("initial finalize must commit")
        };
        let initial_body = initial_body.to_vec();

        let retry_request = fixture.request(request_id, fixture.finalize.clone());
        let (retry_slot, mut retry_client) =
            suite_one_response_session_with_seed(&retry_request, 0xd8);
        let recovered_record = fixture
            .dispatcher
            .dispatch_one_suite_one(
                fixture.peer.clone(),
                V2GenerationLease::for_dispatch_test(fixture.lease_manifest, 7),
                retry_request,
                retry_slot,
                UnixMillisV2::new(1_001),
                Instant::now() + Duration::from_secs(1),
            )
            .expect("fresh delivery deadline must carry exact committed recovery");
        let recovered_opened = retry_client
            .open_application_response(&recovered_record)
            .unwrap();
        let recovered_response =
            savana_kernel_protocol::v2::decode_kernel_service_application_response_v2(
                recovered_opened.plaintext(),
                EndpointRoleV2::IngressKernel,
                42,
            )
            .unwrap();
        let KernelServiceApplicationResponseBodyV2::Success(recovered_body) =
            recovered_response.body()
        else {
            panic!(
                "exact committed retry must remain recoverable after logical expiry: {:?}",
                recovered_response.body()
            )
        };
        assert_eq!(recovered_body.as_slice(), initial_body.as_slice());
        let services = fixture.shared.lock().unwrap();
        assert_eq!(
            services
                .ingress_authority
                .as_ref()
                .unwrap()
                .pending_record_count(),
            1,
        );
    }

    #[test]
    fn expired_uncommitted_finalize_refuses_before_input_or_pending_mutation() {
        let fixture = finalize_recovery_fixture();
        let request_id = RequestIdV2::new([0xc8; 16]);
        let response = fixture
            .dispatcher
            .dispatch_one_application(
                fixture.peer.clone(),
                V2GenerationLease::for_dispatch_test(fixture.lease_manifest, 7),
                fixture.request(request_id, fixture.finalize.clone()),
                UnixMillisV2::new(1_001),
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
        assert_eq!(
            response.body(),
            &KernelServiceApplicationResponseBodyV2::Error(
                savana_kernel_protocol::v2::PublicStableCodeV2::DeadlineExceeded,
            ),
        );
        let services = fixture.shared.lock().unwrap();
        assert_eq!(
            services
                .input
                .status(InputStatusTargetV2::Session(fixture.session))
                .unwrap(),
            KernelInputPublicStateV2::Receiving,
        );
        assert_eq!(
            services
                .ingress_authority
                .as_ref()
                .unwrap()
                .pending_record_count(),
            0,
        );
    }

    #[test]
    fn same_authenticated_principal_request_id_cannot_finalize_a_different_receiving_session() {
        let fixture = finalize_recovery_fixture();
        let request_id = RequestIdV2::new([0xc5; 16]);
        let conflicting_caller = ServiceIdentityV2::new([0xe2; 32]);
        let (conflicting_session, conflicting_finalize) = {
            let mut services = fixture.shared.lock().unwrap();
            add_receiving_finalize_session(
                &mut services,
                fixture.lease_manifest,
                conflicting_caller,
                0xc6,
            )
        };

        let original = fixture
            .dispatcher
            .dispatch_one_application(
                fixture.peer.clone(),
                V2GenerationLease::for_dispatch_test(fixture.lease_manifest, 7),
                fixture.request(request_id, fixture.finalize.clone()),
                UnixMillisV2::new(140),
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
        let KernelServiceApplicationResponseBodyV2::Success(original_body) = original.body() else {
            panic!("original finalize must commit")
        };
        let original_body = original_body.to_vec();

        let conflict = fixture
            .dispatcher
            .dispatch_one_application(
                fixture.peer.clone(),
                V2GenerationLease::for_dispatch_test(fixture.lease_manifest, 7),
                fixture.request(request_id, conflicting_finalize),
                UnixMillisV2::new(141),
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
        assert_eq!(
            conflict.body(),
            &KernelServiceApplicationResponseBodyV2::Error(
                savana_kernel_protocol::v2::PublicStableCodeV2::PolicyDenied,
            ),
        );

        let exact_recovery = fixture
            .dispatcher
            .dispatch_one_application(
                fixture.peer.clone(),
                V2GenerationLease::for_dispatch_test(fixture.lease_manifest, 7),
                fixture.request(request_id, fixture.finalize.clone()),
                UnixMillisV2::new(142),
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
        let KernelServiceApplicationResponseBodyV2::Success(recovered_body) = exact_recovery.body()
        else {
            panic!("exact same request must recover")
        };
        assert_eq!(recovered_body.as_slice(), original_body.as_slice());

        let services = fixture.shared.lock().unwrap();
        assert_eq!(
            services
                .input
                .status(InputStatusTargetV2::Session(conflicting_session))
                .unwrap(),
            KernelInputPublicStateV2::Receiving,
        );
        assert_eq!(
            services
                .ingress_authority
                .as_ref()
                .unwrap()
                .pending_record_count(),
            1,
        );
    }

    #[test]
    fn finalize_recovery_identity_binds_the_verified_observed_os_peer() {
        let fixture = finalize_recovery_fixture();
        let request_id = RequestIdV2::new([0xc7; 16]);
        let original = fixture
            .dispatcher
            .dispatch_one_application(
                fixture.peer.clone(),
                V2GenerationLease::for_dispatch_test(fixture.lease_manifest, 7),
                fixture.request(request_id, fixture.finalize.clone()),
                UnixMillisV2::new(150),
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
        assert!(matches!(
            original.body(),
            KernelServiceApplicationResponseBodyV2::Success(_)
        ));

        let changed_observed_peer = VerifiedKernelServicePeerV2::from_test_mutual_authentication(
            EndpointRoleV2::IngressKernel,
            BootIdV2::new([0xe8; 32]),
            ServiceIdentityV2::new([0xe2; 32]),
            PeerIdentityBindingV2::linux(501, 502, 999, 504, Digest32V2::new([0xee; 32])).unwrap(),
        )
        .unwrap();
        let rejected = fixture
            .dispatcher
            .dispatch_one_application(
                changed_observed_peer,
                V2GenerationLease::for_dispatch_test(fixture.lease_manifest, 7),
                fixture.request(request_id, fixture.finalize.clone()),
                UnixMillisV2::new(151),
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
        assert_eq!(
            rejected.body(),
            &KernelServiceApplicationResponseBodyV2::Error(
                savana_kernel_protocol::v2::PublicStableCodeV2::PolicyDenied,
            ),
        );
        let services = fixture.shared.lock().unwrap();
        assert_eq!(
            services
                .ingress_authority
                .as_ref()
                .unwrap()
                .pending_record_count(),
            1,
        );
    }

    #[test]
    fn committed_finalize_is_recovered_only_for_identical_fresh_suite_one_retry() {
        let fixture = finalize_recovery_fixture();
        let request_id = RequestIdV2::new([0xb5; 16]);
        let original_request = fixture.request(request_id, fixture.finalize.clone());
        let (first_slot, mut first_client) =
            suite_one_response_session_with_seed(&original_request, 0xa1);
        let first_record = fixture
            .dispatcher
            .dispatch_one_suite_one(
                fixture.peer.clone(),
                V2GenerationLease::for_dispatch_test(fixture.lease_manifest, 7),
                original_request,
                first_slot,
                UnixMillisV2::new(120),
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
        let first_opened = first_client
            .open_application_response(&first_record)
            .unwrap();
        let first_response =
            savana_kernel_protocol::v2::decode_kernel_service_application_response_v2(
                first_opened.plaintext(),
                EndpointRoleV2::IngressKernel,
                42,
            )
            .unwrap();
        let KernelServiceApplicationResponseBodyV2::Success(first_body) = first_response.body()
        else {
            panic!("initial finalize must commit successfully")
        };
        let first_body = first_body.to_vec();
        let first_logical = decode_finalize_input_response_v2(&first_body).unwrap();
        let first_pending = first_logical.pending();
        let first_approval = first_logical.approval();
        let first_envelope_digest = first_logical.envelope().envelope_digest().unwrap();
        let first_display_digest = first_logical
            .display_authentication()
            .envelope_digest()
            .unwrap();

        // The server committed the logical result, but this first sealed record
        // is treated as lost at the final channel-write boundary.
        let retry_request = fixture.request(request_id, fixture.finalize.clone());
        let (retry_slot, mut retry_client) =
            suite_one_response_session_with_seed(&retry_request, 0xb1);
        let retry_record = fixture
            .dispatcher
            .dispatch_one_suite_one(
                fixture.peer.clone(),
                V2GenerationLease::for_dispatch_test(fixture.lease_manifest, 7),
                retry_request,
                retry_slot,
                UnixMillisV2::new(121),
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
        assert_ne!(retry_record, first_record, "fresh Suite-1 keys must reseal");
        let retry_opened = retry_client
            .open_application_response(&retry_record)
            .unwrap();
        let retry_response =
            savana_kernel_protocol::v2::decode_kernel_service_application_response_v2(
                retry_opened.plaintext(),
                EndpointRoleV2::IngressKernel,
                42,
            )
            .unwrap();
        let KernelServiceApplicationResponseBodyV2::Success(retry_body) = retry_response.body()
        else {
            panic!("identical retry must recover committed success")
        };
        assert_eq!(retry_body.as_slice(), first_body.as_slice());
        let retry_logical = decode_finalize_input_response_v2(retry_body).unwrap();
        assert_eq!(retry_logical.pending(), first_pending);
        assert_eq!(retry_logical.approval(), first_approval);
        assert_eq!(
            retry_logical.envelope().envelope_digest().unwrap(),
            first_envelope_digest,
        );
        assert_eq!(
            retry_logical
                .display_authentication()
                .envelope_digest()
                .unwrap(),
            first_display_digest,
        );

        let different_request_id = fixture
            .dispatcher
            .dispatch_one_application(
                fixture.peer.clone(),
                V2GenerationLease::for_dispatch_test(fixture.lease_manifest, 7),
                fixture.request(RequestIdV2::new([0xb6; 16]), fixture.finalize.clone()),
                UnixMillisV2::new(122),
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
        assert_eq!(
            different_request_id.body(),
            &KernelServiceApplicationResponseBodyV2::Error(
                savana_kernel_protocol::v2::PublicStableCodeV2::PolicyDenied,
            ),
        );

        let original_commitment = fixture.finalize.channels()[0];
        let mismatched_finalize = FinalizeInputRequestV2::new(
            fixture.finalize.session(),
            vec![InputChannelCommitmentV2::new(
                original_commitment.channel(),
                original_commitment.chunk_count(),
                original_commitment.final_sequence(),
                original_commitment.total_length(),
                Digest32V2::new([0xb7; 32]),
            )
            .unwrap()],
            fixture.finalize.source_provenance().clone(),
        )
        .unwrap();
        let different_commitment = fixture
            .dispatcher
            .dispatch_one_application(
                fixture.peer.clone(),
                V2GenerationLease::for_dispatch_test(fixture.lease_manifest, 7),
                fixture.request(request_id, mismatched_finalize),
                UnixMillisV2::new(123),
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
        assert_eq!(
            different_commitment.body(),
            &KernelServiceApplicationResponseBodyV2::Error(
                savana_kernel_protocol::v2::PublicStableCodeV2::PolicyDenied,
            ),
        );

        let mismatched_session_finalize = FinalizeInputRequestV2::new(
            InputSessionHandleV2::from_authority_entropy([0xba; 32]).unwrap(),
            fixture.finalize.channels().to_vec(),
            fixture.finalize.source_provenance().clone(),
        )
        .unwrap();
        let different_session = fixture
            .dispatcher
            .dispatch_one_application(
                fixture.peer.clone(),
                V2GenerationLease::for_dispatch_test(fixture.lease_manifest, 7),
                fixture.request(request_id, mismatched_session_finalize),
                UnixMillisV2::new(124),
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
        assert_eq!(
            different_session.body(),
            &KernelServiceApplicationResponseBodyV2::Error(
                savana_kernel_protocol::v2::PublicStableCodeV2::InvalidReference,
            ),
        );

        let different_peer = VerifiedKernelServicePeerV2::from_test_mutual_authentication(
            EndpointRoleV2::IngressKernel,
            BootIdV2::new([0xb8; 32]),
            ServiceIdentityV2::new([0xb9; 32]),
            PeerIdentityBindingV2::linux(501, 502, 503, 504, Digest32V2::new([0xf3; 32])).unwrap(),
        )
        .unwrap();
        let different_identity = fixture
            .dispatcher
            .dispatch_one_application(
                different_peer,
                V2GenerationLease::for_dispatch_test(fixture.lease_manifest, 7),
                fixture.request(request_id, fixture.finalize.clone()),
                UnixMillisV2::new(125),
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
        assert_eq!(
            different_identity.body(),
            &KernelServiceApplicationResponseBodyV2::Error(
                savana_kernel_protocol::v2::PublicStableCodeV2::PolicyDenied,
            ),
        );

        let different_logical_deadline = fixture
            .dispatcher
            .dispatch_one_application(
                fixture.peer.clone(),
                V2GenerationLease::for_dispatch_test(fixture.lease_manifest, 7),
                fixture.request_with_logical_deadline(
                    request_id,
                    fixture.finalize.clone(),
                    UnixMillisV2::new(1_001),
                ),
                UnixMillisV2::new(126),
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
        assert_eq!(
            different_logical_deadline.body(),
            &KernelServiceApplicationResponseBodyV2::Error(
                savana_kernel_protocol::v2::PublicStableCodeV2::PolicyDenied,
            ),
        );

        let different_effect_fence = fixture
            .dispatcher
            .dispatch_one_application(
                fixture.peer.clone(),
                V2GenerationLease::for_dispatch_test_with_fence(fixture.lease_manifest, 7, 2),
                fixture.request(request_id, fixture.finalize.clone()),
                UnixMillisV2::new(127),
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
        assert_eq!(
            different_effect_fence.body(),
            &KernelServiceApplicationResponseBodyV2::Error(
                savana_kernel_protocol::v2::PublicStableCodeV2::PolicyDenied,
            ),
        );

        let services = fixture.shared.lock().unwrap();
        assert_eq!(
            services
                .input
                .status(InputStatusTargetV2::Session(fixture.session))
                .unwrap(),
            KernelInputPublicStateV2::Finalized,
        );
        assert_eq!(
            services
                .ingress_authority
                .as_ref()
                .unwrap()
                .pending_record_count(),
            1,
        );
    }

    #[test]
    fn production_runtime_owner_routes_typed_begin_without_a_callback() {
        let mut services = CoreKernelRuntimeServicesV2::new(4, 4096, 4, 32).unwrap();
        let authorization =
            IngressUiAuthorizationHandleV2::from_authority_entropy([0x51; 32]).unwrap();
        services
            .input
            .register_verified_ui_authorization(
                authorization,
                KernelVerifiedUiAuthorizationV2::for_test(),
            )
            .unwrap();
        let owner = KernelRuntimeOwnerV2::spawn(4, services).unwrap();
        let signing_key = SigningKey::from_bytes(&[0x52; 32]);
        let dispatcher = KernelServiceDispatcherV2::spawn(
            KernelServiceDeploymentV2::from_verified_startup(
                BootIdV2::new([0x53; 32]),
                ServiceIdentityV2::new([0x54; 32]),
                Digest32V2::new([0x35; 32]),
                7,
            )
            .unwrap(),
            derive_ed25519_key_id_v2(signing_key.verifying_key().to_bytes()),
            signing_key,
            owner,
        )
        .unwrap();
        let request = KernelServiceApplicationRequestV2::new(
            EndpointRoleV2::IngressKernel,
            RequestIdV2::new([0x55; 16]),
            UnixMillisV2::new(200),
            KernelServiceOperationV2::ingress(KernelIngressOperationV2::BeginInput(
                BeginInputRequestV2::new(
                    authorization,
                    ContentKindV2::ChatText,
                    3,
                    Some(Digest32V2::new([0x56; 32])),
                )
                .unwrap(),
            )),
        )
        .unwrap();
        let response = dispatcher
            .dispatch_one_application(
                VerifiedKernelServicePeerV2::from_test_mutual_authentication(
                    EndpointRoleV2::IngressKernel,
                    BootIdV2::new([0x57; 32]),
                    ServiceIdentityV2::new([0x58; 32]),
                    PeerIdentityBindingV2::linux(501, 502, 503, 504, Digest32V2::new([0xf3; 32]))
                        .unwrap(),
                )
                .unwrap(),
                V2GenerationLease::for_dispatch_test(Digest32V2::new([0x35; 32]), 7),
                request,
                UnixMillisV2::new(100),
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
        let KernelServiceApplicationResponseBodyV2::Success(body) = response.body() else {
            panic!("typed begin must succeed");
        };
        assert_eq!(
            decode_begin_input_response_v2(body)
                .unwrap()
                .next_sequences()
                .len(),
            1
        );
    }
}
