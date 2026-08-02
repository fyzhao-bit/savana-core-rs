use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use savana_kernel_protocol::v2::{
    encode_abort_input_response_v2, encode_append_input_chunk_response_v2,
    encode_append_parser_worker_page_frame_response_v2, encode_authenticate_agent_ui_response_v2,
    encode_authenticate_ingress_ui_response_v2, encode_authorize_release_response_v2,
    encode_authorize_tool_call_response_v2, encode_begin_input_response_v2,
    encode_cancel_kernel_task_response_v2, encode_claim_agent_session_response_v2,
    encode_close_agent_session_response_v2, encode_commit_input_settlement_response_v2,
    encode_commit_parser_worker_result_response_v2, encode_commit_planner_value_response_v2,
    encode_derive_value_response_v2, encode_dispatch_execution_response_v2,
    encode_dispatch_release_response_v2, encode_evaluate_tool_call_response_v2,
    encode_finalize_input_response_v2, encode_get_agent_session_status_response_v2,
    encode_get_execution_status_response_v2, encode_get_input_status_response_v2,
    encode_get_kernel_task_status_response_v2, encode_get_release_status_response_v2,
    encode_kernel_agent_health_response_v2, encode_kernel_agent_operation_v2,
    encode_kernel_ingress_health_response_v2, encode_prepare_agent_ui_authentication_response_v2,
    encode_prepare_followup_ingress_response_v2,
    encode_prepare_ingress_ui_authentication_response_v2, encode_prepare_new_ingress_response_v2,
    encode_prepare_planner_call_response_v2, encode_prepare_release_response_v2,
    encode_propose_tool_call_response_v2, encode_read_agent_view_response_v2,
    encode_register_parser_worker_job_response_v2,
    encode_resume_committed_agent_authentication_response_v2, encode_revoke_vault_response_v2,
    AbortInputResponseV2, AppendInputChunkResponseV2, AppendParserWorkerPageFrameResponseV2,
    AuthenticateAgentUiResponseV2, AuthenticateIngressUiResponseV2, BeginInputResponseV2,
    CloseAgentSessionResponseV2, CommitInputSettlementResponseV2,
    CommitParserWorkerResultResponseV2, DeriveValueResponseV2, Digest32V2, DurableTaskIdV2,
    FinalizeInputResponseV2, GetInputStatusResponseV2, InputNextSequenceV2, InputPublicStateV2,
    InputStatusTargetV2, KernelAgentHealthResponseV2, KernelAgentOperationV2,
    KernelIngressHealthResponseV2, KernelIngressOperationV2, KernelServiceOperationV2,
    MaskedDocumentHandleV2, PrepareIngressUiAuthenticationResponseV2, PrincipalIdV2,
    PublicServiceStateV2, ReadAgentViewResponseV2, RegisterParserWorkerJobResponseV2, RequestIdV2,
    ServiceIdentityV2, UnixMillisV2, VaultPublicStateV2,
};
use savana_kernel_protocol::StableCode;

use crate::v2_agent_authority::{
    KernelAgentAuthorityErrorV2, KernelAgentAuthorityV2, PreparedAgentClaimMaterialV2,
};
use crate::v2_dispatch::KernelServiceResponseBodyV2;
use crate::v2_ingress_authority::{
    KernelIngressAuthorityErrorV2, KernelIngressAuthorityV2, KernelPendingIngressStateV2,
    VerifiedIngressSettlementDecisionV2,
};
use crate::v2_input_owner::{
    FinalizedKernelInputV2, KernelInputErrorV2, KernelInputFinalizeTransactionErrorV2,
    KernelInputOwnerV2, KernelInputPublicStateV2, KernelParserTrustV2,
};
use crate::v2_kernel_owner::{KernelRuntimeRequestV2, KernelRuntimeServicesV2};
use crate::v2_value_owner::{KernelValueErrorV2, KernelValueOwnerV2};

const REQUIRED_AGENT_KERNEL_ROUTES_V2: usize = 25;
const REQUIRED_INGRESS_KERNEL_ROUTES_V2: usize = 12;
const IMPLEMENTED_AGENT_KERNEL_ROUTES_V2: usize = 25;
const IMPLEMENTED_INGRESS_KERNEL_ROUTES_V2: usize = 12;

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
    ingress_authority: Option<KernelIngressAuthorityV2>,
    ingress_commit_sink: Option<Box<dyn KernelIngressCommitSinkV2>>,
    parser_trust: Option<KernelParserTrustV2>,
    readiness: Arc<AtomicBool>,
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
                ingress_authority: None,
                ingress_commit_sink: None,
                parser_trust: None,
                readiness,
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

    pub(crate) fn verify_production_complete(&self) -> Result<(), StableCode> {
        if !self
            .agent_authority
            .as_ref()
            .is_some_and(KernelAgentAuthorityV2::production_ready)
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
            KernelServiceOperationV2::Executor(_) => Err(StableCode::IdentityPeerRejected),
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
            KernelIngressOperationV2::FinalizeInput(request) => {
                let authority = self
                    .ingress_authority
                    .as_mut()
                    .ok_or(StableCode::KernelUnavailable)?;
                let (finalized, prepared) = self
                    .input
                    .finalize_with(request, |finalized| {
                        authority.prepare_pending_approval(
                            finalized,
                            active_state_manifest_digest,
                            deployment_generation,
                            now,
                        )
                    })
                    .map_err(|error| match error {
                        KernelInputFinalizeTransactionErrorV2::Input(error) => {
                            map_input_error(error)
                        }
                        KernelInputFinalizeTransactionErrorV2::Preparation(error) => {
                            map_ingress_authority_error(error)
                        }
                    })?;
                let prepared = authority.publish_pending_approval(prepared, finalized);
                encode_finalize_input_response_v2(&FinalizeInputResponseV2::new(
                    prepared.pending,
                    prepared.approval,
                    prepared.envelope,
                    prepared.display_authentication,
                ))
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
                            .mark_ingress_committed(durable_task_id, principal, material)
                            .map_err(map_agent_authority_error)?;
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
    ) -> Result<KernelServiceResponseBodyV2, StableCode> {
        let (peer, lease, request_id, now, _, operation) = request.into_parts();
        self.execute_operation(
            request_id,
            operation,
            now,
            lease.active_state_manifest_digest(),
            lease.deployment_generation(),
            lease.effect_fence_epoch(),
            peer.caller_identity(),
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use ed25519_dalek::SigningKey;
    use savana_kernel_protocol::v2::{
        decode_append_input_chunk_response_v2, decode_begin_input_response_v2,
        decode_finalize_input_response_v2, decode_kernel_agent_health_response_v2,
        decode_kernel_ingress_health_response_v2, derive_ed25519_key_id_v2,
        encode_kernel_ingress_operation_v2, input_channel_begin_digest_v2,
        input_channel_step_digest_v2, input_chunk_digest_v2, AppendInputChunkRequestV2,
        BeginInputRequestV2, BootIdV2, ContentKindV2, Digest32V2, DirectInputChannelV2,
        EndpointRoleV2, FinalizeInputRequestV2, IngressUiAuthorizationHandleV2,
        InputChannelCommitmentV2, InputChannelV2, InputSourceKindV2, InputSourceProvenanceV2,
        InputStatusTargetV2, KernelAgentHealthRequestV2, KernelAgentOperationV2,
        KernelIngressHealthRequestV2, KernelIngressOperationV2, KernelServiceApplicationRequestV2,
        KernelServiceApplicationResponseBodyV2, KernelServiceOperationV2, PublicServiceStateV2,
        RequestIdV2, ServiceIdentityV2, UnixMillisV2, VersionV2, ZeroizingBytesV2,
    };
    use savana_policy_core::v2::{
        declassification_implementation_digest_v2, ClosedDeclassificationPurposeV2,
        DeclassificationRuleSetV2, DeclassificationRuleV2, EffectSetV2, LeakGateDutyV2,
        OperationalTrustRootPurposeV2, OperationalTrustRootSetItemV2, OperationalTrustRootSetV2,
    };
    use sha2::{Digest as _, Sha256};

    use super::CoreKernelRuntimeServicesV2;
    use crate::policy_runtime::V2GenerationLease;
    use crate::v2_declassification_policy::ActiveDeclassificationRuleSetV2;
    use crate::v2_dispatch::{
        KernelServiceDeploymentV2, KernelServiceDispatcherV2, VerifiedKernelServicePeerV2,
    };
    use crate::v2_ingress_authority::{KernelIngressAuthorityV2, KernelIngressSecurityConfigV2};
    use crate::v2_input_owner::{KernelInputPublicStateV2, KernelVerifiedUiAuthorizationV2};
    use crate::v2_kernel_owner::KernelRuntimeOwnerV2;

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
                VerifiedKernelServicePeerV2::from_mutual_authentication(
                    EndpointRoleV2::IngressKernel,
                    BootIdV2::new([0x57; 32]),
                    ServiceIdentityV2::new([0x58; 32]),
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
