mod application;
mod approval_service;
mod bindings;
mod browser;
mod browser_agent;
mod browser_approval;
mod browser_assets;
mod browser_enrollment;
mod browser_ingress;
mod business_json;
mod business_request;
mod business_unicode;
mod final_release_business;
pub use business_request::{
    decode_business_controls_v2, decode_business_profile_v2, encode_business_controls_v2,
    encode_business_profile_v2, BusinessCodecErrorV2, BusinessControlsV2, BusinessFieldRoleV2,
    BusinessFieldTypeV2, BusinessFieldV2, BusinessMagnitudeV2, BusinessProfileV2,
    BusinessRequestV2, BusinessResponseDispositionV2, BusinessValueV2, MAX_BUSINESS_JSON_BYTES_V2,
    MAX_BUSINESS_PROFILE_BYTES_V2,
};
pub use final_release_business::{
    decode_final_release_delivery_v2, final_release_business_profile_v2,
    final_release_business_request_v2, FinalReleaseDeliveryV2,
    MAX_FINAL_RELEASE_BUSINESS_PAYLOAD_BYTES_V2,
};
mod cbor;
mod effect_gate_projection;
mod handles;
pub use handles::TaskAuthorizationApprovalRecordHandleV2;
mod http;
mod jarvis;
mod kernel_agent;
mod kernel_agent_success;
mod kernel_connector;
mod kernel_executor;
mod kernel_executor_success;
mod kernel_ingress;
pub use kernel_ingress::{
    decode_establish_task_authorization_response_v2,
    encode_establish_task_authorization_response_v2, EstablishTaskAuthorizationRequestV2,
    EstablishTaskAuthorizationResponseV2,
};
pub use kernel_ingress::{
    decode_prepare_task_authorization_approval_response_v2,
    encode_prepare_task_authorization_approval_response_v2,
    CommitTaskAuthorizationApprovalRequestV2, PrepareTaskAuthorizationApprovalRequestV2,
    PrepareTaskAuthorizationApprovalResponseV2,
};
pub use kernel_ingress::{
    decode_recover_task_authorization_response_v2, decode_revoke_task_authorization_response_v2,
    encode_recover_task_authorization_response_v2, encode_revoke_task_authorization_response_v2,
    RecoverTaskAuthorizationRequestV2, RecoverTaskAuthorizationResponseV2,
    RevokeTaskAuthorizationRequestV2, RevokeTaskAuthorizationResponseV2,
};
mod kernel_service;
mod kernel_success;
mod primitives;
mod service;
mod signed;
pub use signed::TaskAuthorizationChangeV2;
mod task_action_approval;
mod task_action_display;
pub use task_action_display::{render_task_action_display_v2, MAX_TASK_ACTION_DISPLAY_BYTES_V2};
mod task_authorization;
mod task_completion;
mod task_execution_payload;
pub use task_action_approval::{
    decode_signed_task_action_approval_v2, decode_task_action_approval_v2,
    encode_signed_task_action_approval_v2, encode_task_action_approval_v2,
    sign_task_action_approval_v2, verify_task_action_approval_v2, SignedTaskActionApprovalV2,
    TaskActionApprovalBindingV2, TaskActionApprovalContextV2, TaskActionApprovalDecisionV2,
    TaskActionApprovalV2, VerifiedTaskActionApprovalV2, MAX_TASK_ACTION_APPROVAL_BYTES_V2,
};
pub use task_completion::{task_completion_evidence_digest_v2, TaskCompletionEvidenceV2};
pub use task_execution_payload::{
    business_target_identity_v2, decode_task_execution_payload_v2,
    encode_task_execution_payload_v2, TaskExecutionPayloadV2, MAX_TASK_EXECUTION_PAYLOAD_BYTES_V2,
};
#[cfg(test)]
mod task_action_approval_tests;
#[cfg(test)]
mod task_authorization_tests;
mod transport;

pub use task_authorization::{
    action_content_digest_v2, decode_action_content_v2, decode_signed_task_authorization_v2,
    decode_task_authorization_draft_v2, decode_task_authorization_v2, encode_action_content_v2,
    encode_signed_task_authorization_v2, encode_task_authorization_draft_v2,
    encode_task_authorization_v2, sign_task_authorization_v2, task_authorization_digest_v2,
    task_authorization_draft_digest_v2, verify_task_authorization_v2, ActionAlternativeV2,
    ActionCodecProfileV2, ActionContentV2, MagnitudeUnitV2, SignedTaskAuthorizationV2,
    TaskAuthorizationClauseV2, TaskAuthorizationDraftAlternativeV2, TaskAuthorizationDraftClauseV2,
    TaskAuthorizationDraftV2, TaskAuthorizationV2, TaskEffectV2, TaskEvidenceKindV2,
    MAX_ACTION_ALTERNATIVES_V2, MAX_TASK_AUTHORIZATION_BYTES_V2, MAX_TASK_AUTHORIZATION_CLAUSES_V2,
    MAX_TASK_AUTHORIZATION_DRAFT_BYTES_V2, MAX_TASK_PREDECESSORS_V2,
};

pub use application::{
    decode_kernel_service_application_request_v2, decode_kernel_service_application_response_v2,
    encode_kernel_service_application_request_v2, encode_kernel_service_application_response_v2,
    kernel_service_operation_has_error_contract_v2, kernel_service_public_error_is_allowed_v2,
    peek_kernel_service_application_request_v2, KernelServiceApplicationRequestV2,
    KernelServiceApplicationResponseBodyV2, KernelServiceApplicationResponseV2,
    KernelServiceApplicationRoutingV2, PublicStableCodeV2,
};
pub use approval_service::{
    decode_approval_health_response_v2, decode_approval_service_request_v2,
    decode_approval_settlement_view_v2, decode_consumed_ui_authentication_settlement_v2,
    decode_create_enrollment_code_response_v2, decode_registered_approval_v2,
    decode_registered_ui_authentication_v2, decode_revoke_credential_response_v2,
    encode_approval_health_response_v2, encode_approval_service_request_v2,
    encode_approval_settlement_view_v2, encode_consumed_ui_authentication_settlement_v2,
    encode_create_enrollment_code_response_v2, encode_registered_approval_v2,
    encode_registered_ui_authentication_v2, encode_revoke_credential_response_v2,
    AgentApprovalRecordTargetV2, ApprovalHealthResponseV2, ApprovalServiceOperationV2,
    ApprovalServiceRequestV2, ApprovalSettlementViewV2, ClosedCredentialRevocationReasonV2,
    ConsumedUiAuthenticationSettlementV2, CreateEnrollmentCodeResponseV2, CredentialPublicStateV2,
    RegisteredApprovalV2, RegisteredUiAuthenticationV2, RevokeCredentialResponseV2,
};
pub use bindings::FinalReleaseSemanticBindingV2;
pub use browser::{
    decode_owner_authentication_profile_v2, decode_ui_authentication_browser_begin_request_v2,
    decode_ui_authentication_browser_begin_response_v2,
    decode_ui_authentication_browser_finish_request_v2,
    decode_ui_authentication_browser_finish_response_v2,
    decode_ui_authentication_platform_begin_response_v2,
    decode_ui_authentication_platform_status_request_v2,
    decode_ui_authentication_platform_status_response_v2, encode_owner_authentication_profile_v2,
    encode_ui_authentication_browser_begin_request_v2,
    encode_ui_authentication_browser_begin_response_v2,
    encode_ui_authentication_browser_finish_request_v2,
    encode_ui_authentication_browser_finish_response_v2,
    encode_ui_authentication_platform_begin_response_v2,
    encode_ui_authentication_platform_status_request_v2,
    encode_ui_authentication_platform_status_response_v2, BrowserWebAuthnAssertionV2,
    OwnerAuthenticationProfileV2, UiAuthenticationBrowserBeginRequestV2,
    UiAuthenticationBrowserBeginResponseV2, UiAuthenticationBrowserFinishRequestV2,
    UiAuthenticationBrowserFinishResponseV2, UiAuthenticationPlatformBeginResponseV2,
    UiAuthenticationPlatformStatusRequestV2, UiAuthenticationPlatformStatusResponseV2,
};
pub use browser_agent::{
    decode_agent_browser_mutation_response_v2, decode_agent_browser_read_view_response_v2,
    decode_agent_browser_request_v2, decode_agent_ui_authentication_complete_browser_response_v2,
    encode_agent_browser_mutation_response_v2, encode_agent_browser_read_view_response_v2,
    encode_agent_browser_request_v2, encode_agent_ui_authentication_complete_browser_response_v2,
    AgentBrowserActionV2, AgentBrowserExecutionStateV2, AgentBrowserMutationResponseV2,
    AgentBrowserObjectRefV2, AgentBrowserReadViewResponseV2, AgentBrowserReleaseStateV2,
    AgentBrowserRequestV2, AgentUiAuthenticationCompleteBrowserResponseV2,
    FixedBrowserFormPostCarrierV2,
};
pub use browser_approval::{
    decode_approval_decision_browser_begin_request_v2,
    decode_approval_decision_browser_begin_response_v2,
    decode_approval_decision_browser_finish_request_v2,
    decode_approval_decision_browser_finish_response_v2,
    decode_approval_decision_platform_begin_response_v2,
    decode_approval_decision_platform_status_request_v2,
    decode_approval_decision_platform_status_response_v2,
    decode_approval_display_browser_request_v2, decode_approval_display_view_v2,
    encode_approval_decision_browser_begin_request_v2,
    encode_approval_decision_browser_begin_response_v2,
    encode_approval_decision_browser_finish_request_v2,
    encode_approval_decision_browser_finish_response_v2,
    encode_approval_decision_platform_begin_response_v2,
    encode_approval_decision_platform_status_request_v2,
    encode_approval_decision_platform_status_response_v2,
    encode_approval_display_browser_request_v2, encode_approval_display_view_v2,
    ApprovalDecisionBrowserBeginRequestV2, ApprovalDecisionBrowserBeginResponseV2,
    ApprovalDecisionBrowserFinishRequestV2, ApprovalDecisionBrowserFinishResponseV2,
    ApprovalDecisionPlatformBeginResponseV2, ApprovalDecisionPlatformStatusRequestV2,
    ApprovalDecisionPlatformStatusResponseV2, ApprovalDisplayBrowserRequestV2,
    ApprovalDisplayViewV2,
};
pub use browser_assets::SAVANA_BROWSER_SCRIPT_V2;
pub use browser_enrollment::{
    decode_begin_enrollment_browser_request_v2, decode_begin_enrollment_browser_response_v2,
    decode_finish_enrollment_browser_request_v2, decode_finish_enrollment_browser_response_v2,
    encode_begin_enrollment_browser_request_v2, encode_begin_enrollment_browser_response_v2,
    encode_finish_enrollment_browser_request_v2, encode_finish_enrollment_browser_response_v2,
    BeginEnrollmentBrowserRequestV2, BeginEnrollmentBrowserResponseV2,
    FinishEnrollmentBrowserRequestV2, FinishEnrollmentBrowserResponseV2,
};
pub use browser_ingress::{
    decode_ingress_browser_mutation_response_v2, decode_ingress_browser_request_v2,
    decode_ingress_ui_authentication_complete_browser_response_v2,
    encode_ingress_browser_mutation_response_v2, encode_ingress_browser_request_v2,
    encode_ingress_ui_authentication_complete_browser_response_v2,
    IngressBrowserMutationResponseV2, IngressBrowserRequestV2,
    IngressUiAuthenticationCompleteBrowserResponseV2,
};
pub use cbor::{
    decode_agent_control_operation_v2, decode_public_task_status_v2,
    encode_agent_control_operation_v2, encode_public_task_status_v2, V2DecodeContext,
};
pub use effect_gate_projection::{
    verify_effect_ledger_projection_v2, EffectLedgerProjectionBindingV2,
    EffectLedgerProjectionErrorV2, VerifiedEffectLedgerProjectionV2,
    MAX_EFFECT_LEDGER_PROJECTION_BYTES_V2,
};
pub use handles::{
    ActionIntentHandleV2, AgentBrowserViewCursorCapabilityV2, AgentExecutionRefV2,
    AgentExecutionTicketRefV2, AgentMaskedDocumentRefV2, AgentPendingConnectorRegistrationRefV2,
    AgentPendingToolCallRefV2, AgentPlanStepRefV2, AgentReleaseRefV2, AgentReleaseTicketRefV2,
    AgentSessionHandleV2, AgentTabSessionCapabilityV2,
    AgentUiAuthenticationBrowserCeremonyCapabilityV2, AgentUiAuthenticationPreparationHandleV2,
    AgentUiAuthenticationSettlementTransferCapabilityV2, AgentUiAuthenticationTransferCapabilityV2,
    AgentUiAuthorizationHandleV2, AgentUiPreAuthenticationTabCapabilityV2,
    ApprovalDecisionCeremonyCapabilityV2, ApprovalDisplayAuthenticationTransferCapabilityV2,
    ApprovalDisplayUiAuthenticationBrowserCeremonyCapabilityV2,
    ApprovalDisplayUiPreAuthenticationTabCapabilityV2, ApprovalTabSessionCapabilityV2,
    ApprovalUiRecordHandleV2, ApprovedConnectorRegistrationHandleV2, AuthorityHandleKeyV2,
    ConnectorApprovalRecordHandleV2, ConnectorRemovalAuthorizationHandleV2,
    ConnectorUiAuthorizationHandleV2, EnrollmentCeremonyCapabilityV2, EnrollmentHandleV2,
    ExecutionHandleV2, ExecutionTicketHandleV2, IngressApprovalRecordHandleV2,
    IngressKernelApprovalHandleV2, IngressTabSessionCapabilityV2,
    IngressUiAuthenticationBrowserCeremonyCapabilityV2, IngressUiAuthenticationPreparationHandleV2,
    IngressUiAuthenticationSettlementTransferCapabilityV2,
    IngressUiAuthenticationTransferCapabilityV2, IngressUiAuthorizationHandleV2,
    IngressUiPreAuthenticationTabCapabilityV2, IngressWriteCapabilityV2, InputSessionHandleV2,
    JarvisBootstrapSelectorV2, KernelAgentViewCursorV2, KernelIngressBootstrapTransferCapabilityV2,
    MaskedDocumentHandleV2, NewTaskPreparationHandleV2, ParserExtractionHandleV2,
    PendingConnectorRegistrationHandleV2, PendingIngressHandleV2, PendingReleaseHandleV2,
    PendingToolCallHandleV2, PlanStepHandleV2, PlannerTicketHandleV2,
    ReleaseApprovalRecordHandleV2, ReleaseHandleV2, ReleaseKernelApprovalHandleV2,
    ReleaseTicketHandleV2, RunHandleV2, TaskHandleV2, ToolApprovalRecordHandleV2, ToolHandleV2,
    ToolKernelApprovalHandleV2, ValueHandleV2,
};
pub use http::{
    decode_continue_jarvis_bootstrap_request_v2, encode_continue_jarvis_bootstrap_request_v2,
    read_fixed_http_request_v2, render_agent_ui_authentication_form_v2, render_agent_workspace_v2,
    render_approval_display_authentication_form_v2, render_ingress_bootstrap_form_v2,
    render_ingress_ui_authentication_form_v2, render_ingress_workspace_v2,
    write_fixed_http_response_v2, ContinueJarvisBootstrapRequestV2, FixedHttpErrorV2,
    FixedHttpRequestV2, FixedHttpRouteV2, FixedHttpServiceV2, MAX_HTTP_BODY_BYTES_V2,
};
pub use jarvis::{
    AgentControlHealthResponseV2, AgentControlOperationV2, BootstrapKindV2, CancelTaskRequestV2,
    CancelTaskResponseV2, FixedOriginV2, GetTaskStatusRequestV2, GetTaskStatusResponseV2,
    JarvisBootstrapActionV2, JarvisBootstrapUrlV2, PrepareIngressRequestV2,
    PrepareIngressResponseV2, PublicFailureClassV2, PublicServiceStateV2, PublicTaskStatusV2,
};
pub use kernel_agent::{
    decode_kernel_agent_operation_v2, decode_planner_plan_v2,
    decode_signed_durable_task_correlation_v2, encode_kernel_agent_operation_v2,
    encode_planner_plan_v2, encode_signed_durable_task_correlation_v2,
    kernel_agent_operation_tags_v2, AuthenticateAgentUiRequestV2, AuthorizeReleaseRequestV2,
    AuthorizeToolCallRequestV2, CancelKernelTaskRequestV2, ClaimAgentSessionRequestV2,
    CloseAgentSessionRequestV2, CommitPlannerValueRequestV2, DeriveOperationV2,
    DeriveValueRequestV2, DispatchExecutionRequestV2, DispatchReleaseRequestV2,
    EvaluateToolCallRequestV2, ExecutionStatusTargetV2, GetAgentSessionStatusRequestV2,
    GetExecutionStatusRequestV2, GetKernelTaskStatusRequestV2, GetReleaseStatusRequestV2,
    KernelAgentHealthRequestV2, KernelAgentOperationV2, NamedArgumentValueBindingV2, PlannerPlanV2,
    PlannerStepV2, PrepareAgentUiAuthenticationRequestV2, PrepareFollowupIngressRequestV2,
    PrepareNewIngressRequestV2, PreparePlannerCallRequestV2, PrepareReleaseRequestV2,
    ProposeToolCallRequestV2, ReadAgentViewRequestV2, ReleaseStatusTargetV2,
    ResumeCommittedAgentAuthenticationRequestV2, RevokeVaultRequestV2,
    SignedDurableTaskCorrelationV2, UnsignedDurableTaskCorrelationV2,
};
pub use kernel_agent_success::{
    decode_authorize_release_response_v2, decode_authorize_tool_call_response_v2,
    decode_commit_planner_value_response_v2, decode_dispatch_execution_response_v2,
    decode_dispatch_release_response_v2, decode_evaluate_tool_call_response_v2,
    decode_get_execution_status_response_v2, decode_get_release_status_response_v2,
    decode_prepare_planner_call_response_v2, decode_prepare_release_response_v2,
    decode_propose_tool_call_response_v2, decode_read_agent_view_response_v2,
    decode_resume_committed_agent_authentication_response_v2, decode_revoke_vault_response_v2,
    encode_authorize_release_response_v2, encode_authorize_tool_call_response_v2,
    encode_commit_planner_value_response_v2, encode_dispatch_execution_response_v2,
    encode_dispatch_release_response_v2, encode_evaluate_tool_call_response_v2,
    encode_get_execution_status_response_v2, encode_get_release_status_response_v2,
    encode_prepare_planner_call_response_v2, encode_prepare_release_response_v2,
    encode_propose_tool_call_response_v2, encode_read_agent_view_response_v2,
    encode_resume_committed_agent_authentication_response_v2, encode_revoke_vault_response_v2,
    ActionIntentCurrentStateV2, ActionIntentDispatchPhaseV2, ActionIntentTerminalSummaryV2,
    AgentContentStateV2, AgentViewFieldV2, AgentViewV2, AuthorizeReleaseResponseV2,
    AuthorizeToolCallResponseV2, BoundedAgentTextV2, ClosedRedactionClassV2,
    CommitPlannerValueResponseV2, DispatchExecutionResponseV2, DispatchReleaseResponseV2,
    EvaluateToolCallResponseV2, GetExecutionStatusResponseV2, GetReleaseStatusResponseV2,
    PlaceholderViewV2, PlannerAbstractRelationV2, PlannerAbstractSlotV2, PlannerEnvelopeV2,
    PlannerIntentKindV2, PlannerLimitsV2, PlannerPurposeV2, PlannerSlotCardinalityV2,
    PlannerSlotConfidentialityV2, PreparePlannerCallResponseV2, PrepareReleaseResponseV2,
    ProposeToolCallResponseV2, PublicDecisionTraceV2, PublicDispatchAcceptedStateV2,
    PublicDispatchCompletionV2, PublicExecutionStatusV2, ReadAgentViewResponseV2,
    ResumeCommittedAgentAuthenticationResponseV2, RevokeVaultResponseV2, VaultPublicStateV2,
};
pub use kernel_connector::{
    connector_registration_descriptor_digest_v2,
    decode_apply_approved_connector_registration_response_v2,
    decode_authorize_connector_registration_response_v2,
    decode_connector_registry_snapshot_response_v2, decode_kernel_connector_control_operation_v2,
    decode_prepare_connector_registration_response_v2,
    decode_prepare_connector_removal_response_v2,
    decode_propose_connector_registration_response_v2, decode_remove_connector_response_v2,
    encode_apply_approved_connector_registration_response_v2,
    encode_authorize_connector_registration_response_v2,
    encode_connector_registry_snapshot_response_v2, encode_kernel_connector_control_operation_v2,
    encode_prepare_connector_registration_response_v2,
    encode_prepare_connector_removal_response_v2,
    encode_propose_connector_registration_response_v2, encode_remove_connector_response_v2,
    kernel_connector_control_operation_tags_v2, ApplyApprovedConnectorRegistrationRequestV2,
    ApplyApprovedConnectorRegistrationResponseV2, AuthorizeConnectorRegistrationRequestV2,
    AuthorizeConnectorRegistrationResponseV2, BoundedConnectorRegistryDeltaV2,
    BoundedConnectorRegistrySnapshotV2, ConnectorRegistrySnapshotRequestV2,
    ConnectorRegistrySnapshotResponseV2, KernelConnectorControlOperationV2,
    PrepareConnectorRegistrationRequestV2, PrepareConnectorRegistrationResponseV2,
    PrepareConnectorRemovalRequestV2, PrepareConnectorRemovalResponseV2,
    ProposeConnectorRegistrationRequestV2, ProposeConnectorRegistrationResponseV2,
    RemoveConnectorRequestV2, RemoveConnectorResponseV2, MAX_CONNECTOR_REGISTRY_DELTA_BYTES_V2,
    MAX_CONNECTOR_REGISTRY_SNAPSHOT_BYTES_V2,
};
pub use kernel_executor::{
    decode_kernel_executor_operation_v2, decode_signed_sealed_execution_envelope_v2,
    encode_kernel_executor_operation_v2, encode_signed_sealed_execution_envelope_v2,
    kernel_executor_operation_tags_v2, AcknowledgeCommittedCompletionRequestV2,
    BoundedCiphertextV2, ConnectorRegistrySyncModeV2, ConnectorRegistrySyncPageV2,
    ConnectorRegistrySyncRequestV2, ConnectorRegistrySyncScopeV2, DispatchCoreV2,
    DispatchRequestV2, DispatchSubjectV2, DispatchTaskBindingV2, ExecutorCompletionDescriptorV2,
    ExecutorHealthRequestV2, FetchCompletionRequestV2, KernelExecutorOperationV2,
    QueryByExecutionNonceRequestV2, SealedExecutionEnvelopePayloadV2,
    SignedSealedExecutionEnvelopeV2, ToolExecutionSemanticBindingV2,
    MAX_CONNECTOR_REGISTRY_SYNC_PAGE_DELTAS_V2, MAX_CONNECTOR_REGISTRY_SYNC_PAGE_DELTA_BYTES_V2,
};
pub use kernel_executor_success::{
    decode_acknowledge_committed_completion_response_v2,
    decode_connector_registry_sync_response_v2, decode_dispatch_response_v2,
    decode_executor_completion_payload_v2, decode_executor_health_response_v2,
    decode_fetch_completion_response_v2, decode_query_by_execution_nonce_response_v2,
    encode_acknowledge_committed_completion_response_v2,
    encode_connector_registry_sync_response_v2, encode_dispatch_response_v2,
    encode_executor_completion_payload_v2, encode_executor_health_response_v2,
    encode_fetch_completion_response_v2, encode_query_by_execution_nonce_response_v2,
    AcknowledgeCommittedCompletionResponseV2, ConnectorRegistrySyncResponseV2,
    ConnectorRegistrySyncStatusV2, DispatchResponseV2, ExecutorCompletionPayloadV2,
    ExecutorFailureClassV2, ExecutorFinalReleaseAuditEvidenceV2, ExecutorHealthResponseV2,
    ExecutorStatusV2, FetchCompletionResponseV2, QueryByExecutionNonceResponseV2,
    SignedExecutorEffectStartedReceiptV2, SignedExecutorFinalReleaseReceiptV2,
    UnsignedExecutorEffectStartedReceiptV2, UnsignedExecutorFinalReleaseReceiptV2,
};
pub use kernel_ingress::{
    decode_kernel_ingress_operation_v2, decode_parser_worker_page_frame_v2,
    decode_signed_parser_worker_job_descriptor_v2,
    decode_signed_parser_worker_result_attestation_v2, encode_kernel_ingress_operation_v2,
    encode_parser_worker_page_frame_v2, encode_signed_parser_worker_job_descriptor_v2,
    encode_signed_parser_worker_result_attestation_v2, input_channel_begin_digest_v2,
    input_channel_step_digest_v2, input_chunk_digest_v2, input_session_internal_id_v2,
    input_source_provenance_digest_v2, kernel_ingress_operation_tags_v2,
    parser_worker_transcript_begin_v2, parser_worker_transcript_step_v2, AbortInputRequestV2,
    AppendInputChunkRequestV2, AppendParserWorkerPageFrameRequestV2,
    AuthenticateIngressUiRequestV2, BeginInputRequestV2, CommitInputSettlementRequestV2,
    CommitParserWorkerResultRequestV2, ContentKindV2, DirectInputChannelV2, FinalizeInputRequestV2,
    GetInputStatusRequestV2, InputChannelCommitmentV2, InputChannelV2, InputSourceKindV2,
    InputSourceProvenanceV2, InputStatusTargetV2, KernelIngressHealthRequestV2,
    KernelIngressOperationV2, PageProvenanceV2, ParserWorkerPageFrameV2,
    PrepareIngressUiAuthenticationRequestV2, RegisterParserWorkerJobRequestV2,
    SignedParserWorkerJobDescriptorV2, SignedParserWorkerResultAttestationV2,
    UnsignedParserWorkerJobDescriptorV2, UnsignedParserWorkerResultAttestationV2,
    VerifiedParserWorkerJobDescriptorV2, VerifiedParserWorkerResultAttestationV2,
};
pub use kernel_service::{
    decode_kernel_service_request_envelope_v2, encode_kernel_service_request_envelope_v2,
    kernel_service_operation_tags_for_role_v2, sign_kernel_service_response_envelope_v2,
    verify_kernel_service_response_envelope_v2, KernelServiceOperationV2,
    KernelServiceRequestEnvelopeV2, KernelServiceResponseEnvelopeV2, KernelServiceResponseV2,
};
pub use kernel_success::{
    decode_abort_input_response_v2, decode_append_input_chunk_response_v2,
    decode_append_parser_worker_page_frame_response_v2, decode_authenticate_agent_ui_response_v2,
    decode_authenticate_ingress_ui_response_v2, decode_begin_input_response_v2,
    decode_cancel_kernel_task_response_v2, decode_claim_agent_session_response_v2,
    decode_close_agent_session_response_v2, decode_commit_input_settlement_response_v2,
    decode_commit_parser_worker_result_response_v2, decode_derive_value_response_v2,
    decode_finalize_input_response_v2, decode_get_agent_session_status_response_v2,
    decode_get_input_status_response_v2, decode_get_kernel_task_status_response_v2,
    decode_kernel_agent_health_response_v2, decode_kernel_ingress_health_response_v2,
    decode_prepare_agent_ui_authentication_response_v2,
    decode_prepare_followup_ingress_response_v2,
    decode_prepare_ingress_ui_authentication_response_v2, decode_prepare_new_ingress_response_v2,
    decode_register_parser_worker_job_response_v2, encode_abort_input_response_v2,
    encode_append_input_chunk_response_v2, encode_append_parser_worker_page_frame_response_v2,
    encode_authenticate_agent_ui_response_v2, encode_authenticate_ingress_ui_response_v2,
    encode_begin_input_response_v2, encode_cancel_kernel_task_response_v2,
    encode_claim_agent_session_response_v2, encode_close_agent_session_response_v2,
    encode_commit_input_settlement_response_v2, encode_commit_parser_worker_result_response_v2,
    encode_derive_value_response_v2, encode_finalize_input_response_v2,
    encode_get_agent_session_status_response_v2, encode_get_input_status_response_v2,
    encode_get_kernel_task_status_response_v2, encode_kernel_agent_health_response_v2,
    encode_kernel_ingress_health_response_v2, encode_prepare_agent_ui_authentication_response_v2,
    encode_prepare_followup_ingress_response_v2,
    encode_prepare_ingress_ui_authentication_response_v2, encode_prepare_new_ingress_response_v2,
    encode_register_parser_worker_job_response_v2, AbortInputResponseV2, ActiveToolViewV2,
    AgentSessionStatusV2, AppendInputChunkResponseV2, AppendParserWorkerPageFrameResponseV2,
    AuthenticateAgentUiResponseV2, AuthenticateIngressUiResponseV2, BeginInputResponseV2,
    CancelKernelTaskResponseV2, ClaimAgentSessionResponseV2, CloseAgentSessionResponseV2,
    CommitInputSettlementResponseV2, CommitParserWorkerResultResponseV2, DeriveValueResponseV2,
    FinalizeInputResponseV2, GetAgentSessionStatusResponseV2, GetInputStatusResponseV2,
    GetKernelTaskStatusResponseV2, InputNextSequenceV2, InputPublicStateV2,
    KernelAgentHealthResponseV2, KernelIngressHealthResponseV2,
    PrepareAgentUiAuthenticationResponseV2, PrepareFollowupIngressResponseV2,
    PrepareIngressUiAuthenticationResponseV2, PrepareNewIngressResponseV2,
    RegisterParserWorkerJobResponseV2, RunRevisionObservationV2,
};
pub use primitives::{
    ActionIntentIdV2, ActionTemplateIdV2, ArgumentNameV2, AttemptKindV2, BootIdV2,
    BoundedIdentityStringV2, ClosedConfidenceClassV2, ClosedExtensionClassV2, ClosedMediaTypeV2,
    Digest32V2, DisplayProjectionIdV2, DurableReleaseIdV2, DurableRunIdV2, DurableTaskIdV2,
    Ed25519KeyIdV2, Ed25519SignatureV2, EndpointRoleV2, EnrollmentProfileIdV2, EntityIdV2,
    ExecutorIdentityV2, FixedBytes32V2, HpkeX25519KeyIdV2, ImplementationIdV2,
    InternalSlotDigestV2, InternalStepIdV2, MonotonicNanosV2, NamespaceIdV2, Nonce32V2,
    OntologySetIdV2, PlanRevisionDigestV2, PlannerRouteIdV2, PlannerSlotRefV2, PolicyConstantIdV2,
    PrincipalIdV2, ProducerIdentityV2, ProjectionIdV2, RelationIdV2, ReplayAeadKeyIdV2,
    RequestIdV2, RoleIdV2, RunRevisionDigestV2, ServiceIdentityV2, SlotKindV2, StaticTemplateIdV2,
    ToolClassIdV2, UnixMillisV2, ValueInternalIdV2, VaultKeyIdV2, VersionV2, ZeroizingBytesV2,
    ZeroizingTextV2,
};
pub use service::{
    decode_agent_control_request_envelope_v2, decode_agent_control_response_envelope_v2,
    encode_agent_control_request_envelope_v2, encode_agent_control_response_envelope_v2,
    AgentControlRequestEnvelopeV2, AgentControlResponseEnvelopeV2, AgentControlResponseV2,
};
pub use signed::{
    approval_display_digest_v2, decode_signed_agent_authentication_attempt_closure_proof_v2,
    decode_signed_agent_authentication_closure_descriptor_v2, decode_signed_approval_envelope_v2,
    decode_signed_approval_settlement_v2, decode_signed_ui_authentication_envelope_v2,
    decode_signed_ui_authentication_settlement_v2,
    encode_signed_agent_authentication_attempt_closure_proof_v2,
    encode_signed_agent_authentication_closure_descriptor_v2, encode_signed_approval_envelope_v2,
    encode_signed_approval_settlement_v2, encode_signed_ui_authentication_envelope_v2,
    encode_signed_ui_authentication_settlement_v2, AgentAuthenticationClosureEvidenceV2,
    AgentAuthenticationInitialTransferTerminalStateV2,
    AgentAuthenticationSettlementTerminalStateV2,
    AgentAuthenticationSettlementTransferTerminalStateV2,
    AgentAuthenticationTransferTerminalStateV2, ApprovalBindingV2, ApprovalDecisionV2,
    ApprovalPurposeV2, BoundedApprovalDisplayTextV2,
    SignedAgentAuthenticationAttemptClosureProofV2, SignedAgentAuthenticationClosureDescriptorV2,
    SignedApprovalEnvelopeV2, SignedApprovalSettlementV2, SignedUiAuthenticationEnvelopeV2,
    SignedUiAuthenticationSettlementV2, UiAuthenticationBindingV2, UiAuthenticationPurposeV2,
    UnsignedAgentAuthenticationAttemptClosureProofV2,
    UnsignedAgentAuthenticationClosureDescriptorV2, UnsignedApprovalEnvelopeV2,
    UnsignedApprovalSettlementV2, UnsignedUiAuthenticationEnvelopeV2,
    UnsignedUiAuthenticationSettlementV2, VerifiedApprovalSettlementV2,
    VerifiedUiAuthenticationSettlementV2, MAX_APPROVAL_DISPLAY_BYTES_V2,
};
pub use transport::{
    derive_ed25519_key_id_v2, peer_identity_binding_digest_v2, KernelServiceHandshakeEdgeV2,
    OpenedV2Record, PeerIdentityBindingV2, PreparedV2ServerApplicationResponse, V2ClientHandshake,
    V2ClientTransportSession, V2PendingServerHandshake,
    V2ServerApplicationResponsePreparationError, V2ServerHandshake, V2ServerHelloAcceptanceErrorV2,
    V2ServerTransportSession, VerifiedV2HandshakePeer, HANDSHAKE_FRAME_HEADER_BYTES_V2,
    MAX_HANDSHAKE_BODY_BYTES_V2, MAX_RECORD_CIPHERTEXT_BYTES_V2, MAX_RECORD_HEADER_BYTES_V2,
    RECORD_FRAME_HEADER_BYTES_V2,
};

pub const PROTOCOL_MAJOR: u16 = 2;
pub const PROTOCOL_MINOR: u16 = 0;
pub const SUITE_ID: u16 = 1;
