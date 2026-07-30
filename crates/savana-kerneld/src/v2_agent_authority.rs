use chacha20poly1305::aead::{Aead as _, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit as _, Nonce};
use ed25519_dalek::SigningKey;
use getrandom::getrandom;
use hkdf::Hkdf;
use savana_kernel_protocol::v2::{
    derive_ed25519_key_id_v2, ActionIntentCurrentStateV2, ActionIntentHandleV2, ActionIntentIdV2,
    ActiveToolViewV2, AgentAuthenticationClosureEvidenceV2, AgentSessionHandleV2,
    AgentSessionStatusV2, AgentUiAuthenticationPreparationHandleV2, AgentUiAuthorizationHandleV2,
    ApprovalBindingV2, ApprovalDecisionV2, ApprovalPurposeV2, AuthorityHandleKeyV2,
    AuthorizeToolCallResponseV2, BootIdV2, BoundedCiphertextV2, CancelKernelTaskRequestV2,
    CancelKernelTaskResponseV2, ClaimAgentSessionRequestV2, ClaimAgentSessionResponseV2,
    CommitPlannerValueRequestV2, CommitPlannerValueResponseV2, Digest32V2,
    DispatchCoreV2 as ProtocolDispatchCoreV2, DispatchExecutionResponseV2, DispatchRequestV2,
    DispatchSubjectV2 as ProtocolDispatchSubjectV2, DurableRunIdV2, DurableTaskIdV2,
    Ed25519KeyIdV2, EvaluateToolCallRequestV2, EvaluateToolCallResponseV2, ExecutionHandleV2,
    ExecutionStatusTargetV2, ExecutionTicketHandleV2, ExecutorIdentityV2, ExecutorStatusV2,
    FixedBytes32V2, FixedOriginV2, GetAgentSessionStatusRequestV2, GetAgentSessionStatusResponseV2,
    GetExecutionStatusRequestV2, GetExecutionStatusResponseV2, GetKernelTaskStatusRequestV2,
    GetKernelTaskStatusResponseV2, GetReleaseStatusRequestV2, GetReleaseStatusResponseV2,
    HpkeX25519KeyIdV2, KernelIngressBootstrapTransferCapabilityV2, MaskedDocumentHandleV2,
    NewTaskPreparationHandleV2, Nonce32V2, PendingReleaseHandleV2, PendingToolCallHandleV2,
    PlanRevisionDigestV2, PlanStepHandleV2, PlannerAbstractSlotV2, PlannerEnvelopeV2,
    PlannerIntentKindV2, PlannerLimitsV2, PlannerSlotCardinalityV2, PlannerSlotConfidentialityV2,
    PlannerSlotRefV2, PlannerTicketHandleV2, PrepareAgentUiAuthenticationRequestV2,
    PrepareAgentUiAuthenticationResponseV2, PrepareFollowupIngressRequestV2,
    PrepareFollowupIngressResponseV2, PrepareNewIngressRequestV2, PrepareNewIngressResponseV2,
    PreparePlannerCallRequestV2, PreparePlannerCallResponseV2, PrepareReleaseRequestV2,
    PrepareReleaseResponseV2, PrincipalIdV2, ProducerIdentityV2, ProposeToolCallRequestV2,
    ProposeToolCallResponseV2, PublicDecisionTraceV2 as ProtocolDecisionTraceV2,
    PublicDispatchAcceptedStateV2, PublicDispatchCompletionV2, PublicExecutionStatusV2,
    PublicFailureClassV2, PublicStableCodeV2, PublicTaskStatusV2, QueryByExecutionNonceRequestV2,
    ReadAgentViewRequestV2, ReleaseHandleV2, ReleaseKernelApprovalHandleV2, ReleaseStatusTargetV2,
    ReleaseTicketHandleV2, ResumeCommittedAgentAuthenticationRequestV2,
    ResumeCommittedAgentAuthenticationResponseV2, RevokeVaultRequestV2, RoleIdV2,
    RunRevisionDigestV2, RunRevisionObservationV2, SealedExecutionEnvelopePayloadV2,
    ServiceIdentityV2, SignedAgentAuthenticationClosureDescriptorV2, SignedApprovalEnvelopeV2,
    SignedDurableTaskCorrelationV2, SignedSealedExecutionEnvelopeV2,
    SignedUiAuthenticationEnvelopeV2, SignedUiAuthenticationSettlementV2, SlotKindV2,
    StaticTemplateIdV2, ToolHandleV2, ToolKernelApprovalHandleV2, UiAuthenticationBindingV2,
    UiAuthenticationPurposeV2, UnixMillisV2, UnsignedAgentAuthenticationClosureDescriptorV2,
    UnsignedApprovalEnvelopeV2, UnsignedDurableTaskCorrelationV2,
    UnsignedUiAuthenticationEnvelopeV2, V2DecodeContext, ValueHandleV2,
};
use savana_policy_core::v2::{
    decode_provenance_record_v2, encode_provenance_record_v2, provenance_digest_v2,
    value_digest_v2, ActiveToolRegistryV2, ClosedCardinalityV2, DispatchQuotaSubjectV2,
    DurableG4StateV2, EffectSetV2, G5DecisionBranchV2, KernelPreparedDispatchV2, KernelValueV2,
    OntologyExprV2, PlannerSlotConfidentialityV2 as PolicySlotConfidentialityV2,
    ProvenanceRecordV2, ResolvedExecutionTicketV2, StoredBindingResolverV2, StoredValueRecordV2,
    VerifiedActionIntentMaterialV2, VerifiedEffectGateLeaseV2, VerifiedInternalSlotMaterialV2,
    VerifiedInternalValidatorRegistryV2, VerifiedOntologyEvaluationV2, VerifiedPlanArgumentV2,
    VerifiedPolicyDispositionV2, VerifiedProjectionOutputsV2, VerifiedQuotaLimitV2,
    VerifiedResolvedRelationSetV2,
};
use sha2::{Digest as _, Sha256};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use crate::v2_agent_durable::{
    DurableKernelAgentAuthorityStateV2, KernelAgentAuthorityRollbackAnchorV2,
};
use crate::v2_core_services::KernelIngressCommitSinkV2;
use crate::v2_executor_client::{KernelExecutorClientErrorV2, SuiteOneKernelExecutorClientV2};
use crate::v2_ingress_authority::KernelIngressAuthorityV2;
use crate::v2_value_owner::{KernelValueErrorV2, KernelValueOwnerV2};

const TASK_LOGICAL_TTL_MS: u64 = 30 * 60 * 1_000;
const TASK_STATUS_RETENTION_MS: u64 = 24 * 60 * 60 * 1_000;
const AGENT_UI_AUTH_TTL_MS: u64 = 5 * 60 * 1_000;
const CLAIM_DIGEST_DOMAIN: &[u8] = b"SAVANA_AGENT_INGRESS_CLAIM_V2\0";
const RUN_REVISION_DOMAIN: &[u8] = b"SAVANA_RUN_REVISION_V2\0";
const PLANNER_ROUTE_DOMAIN: &[u8] = b"SAVANA_PLANNER_ROUTE_V2\0";
const PLANNER_ENVELOPE_DOMAIN: &[u8] = b"SAVANA_PLANNER_ENVELOPE_V2\0";
const PLANNER_OUTPUT_DOMAIN: &[u8] = b"SAVANA_PLANNER_OUTPUT_V2\0";
const PLAN_REVISION_DOMAIN: &[u8] = b"SAVANA_PLAN_REVISION_V2\0";
const INTERNAL_STEP_DOMAIN: &[u8] = b"SAVANA_INTERNAL_PLAN_STEP_V2\0";
const PROJECTION_DESTINATION_DOMAIN: &[u8] = b"SAVANA_KERNEL_DESTINATION_PROJECTION_V2\0";
const PROJECTION_DISPLAY_DOMAIN: &[u8] = b"SAVANA_KERNEL_DISPLAY_PROJECTION_V2\0";
const TOOL_APPROVAL_TTL_MS: u64 = 5 * 60 * 1_000;
const AGENT_AUTH_RECOVERY_RECORD_DOMAIN: &[u8] = b"SAVANA_AGENT_AUTH_RECOVERY_RECORD_V2\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KernelAgentAuthorityErrorV2 {
    InvalidReference,
    AlreadyConsumed,
    BindingMismatch,
    Expired,
    StateConflict,
    LimitExceeded,
    Unavailable,
}

pub(crate) struct PreparedAgentClaimMaterialV2 {
    durable_run_id: DurableRunIdV2,
    producer_identity: ProducerIdentityV2,
    initial_value: KernelValueV2,
    provenance: ProvenanceRecordV2,
    initial_document: MaskedDocumentHandleV2,
    policy_allowed_effects: EffectSetV2,
    expires_at: UnixMillisV2,
}

impl std::fmt::Debug for PreparedAgentClaimMaterialV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedAgentClaimMaterialV2")
            .field("durable_run_id", &self.durable_run_id)
            .field("initial_document", &self.initial_document)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

impl PreparedAgentClaimMaterialV2 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_verified_ingress(
        durable_run_id: DurableRunIdV2,
        producer_identity: ProducerIdentityV2,
        initial_value: KernelValueV2,
        provenance: ProvenanceRecordV2,
        initial_document: MaskedDocumentHandleV2,
        policy_allowed_effects: EffectSetV2,
        expires_at: UnixMillisV2,
    ) -> Result<Self, KernelAgentAuthorityErrorV2> {
        if is_zero(durable_run_id.as_bytes())
            || is_zero(producer_identity.as_bytes())
            || expires_at.get() == 0
        {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        Ok(Self {
            durable_run_id,
            producer_identity,
            initial_value,
            provenance,
            initial_document,
            policy_allowed_effects,
            expires_at,
        })
    }
}

pub(crate) struct KernelAgentSecurityConfigV2 {
    installation_id: Digest32V2,
    kerneld_identity: ServiceIdentityV2,
    agentd_identity: ServiceIdentityV2,
    approvald_identity: ServiceIdentityV2,
    agentd_kernel_client_boot_id: BootIdV2,
    kerneld_server_boot_id: BootIdV2,
    approvald_boot_id: BootIdV2,
    machine_boot_id: BootIdV2,
    correlation_signing_key: SigningKey,
    envelope_signing_key: SigningKey,
    ui_settlement_key_id: Ed25519KeyIdV2,
    ui_settlement_public_key: [u8; 32],
}

impl std::fmt::Debug for KernelAgentSecurityConfigV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("KernelAgentSecurityConfigV2(<redacted>)")
    }
}

impl KernelAgentSecurityConfigV2 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        installation_id: Digest32V2,
        kerneld_identity: ServiceIdentityV2,
        agentd_identity: ServiceIdentityV2,
        approvald_identity: ServiceIdentityV2,
        agentd_kernel_client_boot_id: BootIdV2,
        kerneld_server_boot_id: BootIdV2,
        approvald_boot_id: BootIdV2,
        machine_boot_id: BootIdV2,
        correlation_signing_key: SigningKey,
        envelope_signing_key: SigningKey,
        ui_settlement_key_id: Ed25519KeyIdV2,
        ui_settlement_public_key: [u8; 32],
    ) -> Result<Self, KernelAgentAuthorityErrorV2> {
        if is_zero(installation_id.as_bytes())
            || is_zero(kerneld_identity.as_bytes())
            || is_zero(agentd_identity.as_bytes())
            || is_zero(approvald_identity.as_bytes())
            || is_zero(agentd_kernel_client_boot_id.as_bytes())
            || is_zero(kerneld_server_boot_id.as_bytes())
            || is_zero(approvald_boot_id.as_bytes())
            || is_zero(machine_boot_id.as_bytes())
            || derive_ed25519_key_id_v2(ui_settlement_public_key) != ui_settlement_key_id
            || correlation_signing_key.verifying_key() == envelope_signing_key.verifying_key()
        {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        Ok(Self {
            installation_id,
            kerneld_identity,
            agentd_identity,
            approvald_identity,
            agentd_kernel_client_boot_id,
            kerneld_server_boot_id,
            approvald_boot_id,
            machine_boot_id,
            correlation_signing_key,
            envelope_signing_key,
            ui_settlement_key_id,
            ui_settlement_public_key,
        })
    }
}

struct TaskRecordV2 {
    preparation: NewTaskPreparationHandleV2,
    agent_task_nonce: Nonce32V2,
    client_request_nonce: Nonce32V2,
    durable_task_id: DurableTaskIdV2,
    active_state_manifest_digest: Digest32V2,
    correlation: SignedDurableTaskCorrelationV2,
    ingress_transfer: KernelIngressBootstrapTransferCapabilityV2,
    status: PublicTaskStatusV2,
    expected_principal: Option<PrincipalIdV2>,
    claim_digest: Option<Digest32V2>,
    durable_run_id: Option<DurableRunIdV2>,
    material: Option<PreparedAgentClaimMaterialV2>,
    current_authentication_preparation: Option<usize>,
}

struct AuthenticationPreparationRecordV2 {
    preparation: AgentUiAuthenticationPreparationHandleV2,
    task_index: usize,
    originating_kerneld_boot_id: BootIdV2,
    envelope: SignedUiAuthenticationEnvelopeV2,
    envelope_digest: Digest32V2,
    binding_digest: Digest32V2,
    challenge: Nonce32V2,
    recovery_record_digest: Digest32V2,
    closure: SignedAgentAuthenticationClosureDescriptorV2,
    replacement_nonce: Nonce32V2,
    expires_at: UnixMillisV2,
    consumed: bool,
    restart_tombstoned: bool,
}

struct AuthorizationRecordV2 {
    authorization: AgentUiAuthorizationHandleV2,
    task_index: usize,
    consumed: bool,
}

struct SessionRecordV2 {
    session: AgentSessionHandleV2,
    run: savana_kernel_protocol::v2::RunHandleV2,
    durable_run_id: DurableRunIdV2,
    durable_task_id: DurableTaskIdV2,
    active_state_manifest_digest: Digest32V2,
    principal: PrincipalIdV2,
    producer_identity: ProducerIdentityV2,
    role: RoleIdV2,
    policy_allowed_effects: EffectSetV2,
    expires_at: UnixMillisV2,
    revision: RunRevisionObservationV2,
    initial_document: MaskedDocumentHandleV2,
    status: AgentSessionStatusV2,
}

#[derive(Clone, Copy)]
struct PlannerSlotBindingRecordV2 {
    slot: PlannerAbstractSlotV2,
    value: ValueHandleV2,
}

struct PlannerTicketRecordV2 {
    ticket: PlannerTicketHandleV2,
    run: savana_kernel_protocol::v2::RunHandleV2,
    planner_route: savana_kernel_protocol::v2::PlannerRouteIdV2,
    prompt_values: Vec<savana_kernel_protocol::v2::ValueHandleV2>,
    slot_bindings: Vec<PlannerSlotBindingRecordV2>,
    envelope_nonce: Nonce32V2,
    envelope_digest: Digest32V2,
    expires_at: UnixMillisV2,
    consumed: bool,
}

struct ToolRecordV2 {
    commitment: Digest32V2,
    run: savana_kernel_protocol::v2::RunHandleV2,
    descriptor_digest: Digest32V2,
}

#[derive(Clone)]
struct PlanArgumentRecordV2 {
    name: savana_policy_core::v2::ArgumentNameV2,
    slot: PlannerAbstractSlotV2,
    value: ValueHandleV2,
}

struct PlanStepRecordV2 {
    commitment: Digest32V2,
    run: savana_kernel_protocol::v2::RunHandleV2,
    durable_run_id: DurableRunIdV2,
    durable_task_id: DurableTaskIdV2,
    principal: PrincipalIdV2,
    role: RoleIdV2,
    plan_revision_digest: PlanRevisionDigestV2,
    internal_step_id: savana_kernel_protocol::v2::InternalStepIdV2,
    descriptor_digest: Digest32V2,
    arguments: Vec<PlanArgumentRecordV2>,
}

#[derive(Clone)]
struct IntentRecordV2 {
    intent: ActionIntentHandleV2,
    pending: PendingToolCallHandleV2,
    intent_commitment: Digest32V2,
    pending_commitment: Digest32V2,
    action_intent_id: ActionIntentIdV2,
    run: savana_kernel_protocol::v2::RunHandleV2,
    durable_run_id: DurableRunIdV2,
    durable_task_id: DurableTaskIdV2,
    principal: PrincipalIdV2,
    role: RoleIdV2,
    descriptor_digest: Digest32V2,
    plan_revision_digest: PlanRevisionDigestV2,
    internal_step_id: savana_kernel_protocol::v2::InternalStepIdV2,
    policy_binding: savana_policy_core::v2::ToolExecutionSemanticBindingV2,
    semantic_binding: savana_kernel_protocol::v2::ToolExecutionSemanticBindingV2,
    dispatch_plaintext: Vec<u8>,
    arguments: Vec<PlanArgumentRecordV2>,
    state: IntentRecordStateV2,
    decision_trace: Option<Digest32V2>,
    ticket_commitment: Option<Digest32V2>,
    approval_commitment: Option<Digest32V2>,
    approval_settlement: Option<savana_policy_core::v2::VerifiedToolApprovalSettlementV2>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum IntentRecordStateV2 {
    Proposed,
    Evaluating,
    Denied,
    AwaitingApproval,
    Authorized,
}

struct ExecutionTicketRecordV2 {
    ticket: ExecutionTicketHandleV2,
    commitment: Digest32V2,
    action_intent_id: ActionIntentIdV2,
    semantic_binding_digest: Digest32V2,
}

struct ExecutionRecordV2 {
    execution: ExecutionHandleV2,
    commitment: Digest32V2,
    ticket_commitment: Digest32V2,
    action_intent_id: ActionIntentIdV2,
    execution_nonce: Nonce32V2,
    dispatch_core_digest: Digest32V2,
    dispatch_subject_digest: Digest32V2,
    status: PublicExecutionStatusV2,
    completion: Option<savana_kernel_protocol::v2::ExecutorCompletionDescriptorV2>,
}

struct ToolApprovalRecordV2 {
    approval: ToolKernelApprovalHandleV2,
    commitment: Digest32V2,
    pending_commitment: Digest32V2,
    action_intent_id: ActionIntentIdV2,
    envelope: SignedApprovalEnvelopeV2,
    display_authentication: SignedUiAuthenticationEnvelopeV2,
    envelope_digest: Digest32V2,
    binding_digest: Digest32V2,
    challenge: Nonce32V2,
    expected_principal: PrincipalIdV2,
    active_state_manifest_digest: Digest32V2,
    expires_at: UnixMillisV2,
    consumed: bool,
}

struct PendingReleaseRecordV2 {
    pending: PendingReleaseHandleV2,
    pending_commitment: Digest32V2,
    approval: ReleaseKernelApprovalHandleV2,
    approval_commitment: Digest32V2,
    document: MaskedDocumentHandleV2,
    run: savana_kernel_protocol::v2::RunHandleV2,
    durable_run_id: DurableRunIdV2,
    durable_task_id: DurableTaskIdV2,
    principal: PrincipalIdV2,
    vault_pending: savana_vault::PendingVaultReleaseV2,
    envelope_digest: Digest32V2,
    binding_digest: Digest32V2,
    challenge: Nonce32V2,
    active_state_manifest_digest: Digest32V2,
    expires_at: UnixMillisV2,
    consumed: bool,
    authorized: Option<savana_vault::AuthorizedVaultReleaseV2>,
    settlement: Option<savana_policy_core::v2::VerifiedFinalReleaseSettlementV2>,
    ticket_commitment: Option<Digest32V2>,
}

struct ReleaseTicketRecordV2 {
    ticket: ReleaseTicketHandleV2,
    commitment: Digest32V2,
    pending_commitment: Digest32V2,
    durable_release_id: savana_kernel_protocol::v2::DurableReleaseIdV2,
    binding_digest: Digest32V2,
}

struct ReleaseRecordV2 {
    release: ReleaseHandleV2,
    commitment: Digest32V2,
    ticket_commitment: Digest32V2,
    pending_commitment: Digest32V2,
    prepared: savana_vault::VaultDispatchPreparedV2,
    execution_nonce: Nonce32V2,
    dispatch_core_digest: Digest32V2,
    dispatch_subject_digest: Digest32V2,
    status: PublicExecutionStatusV2,
    completion: Option<savana_kernel_protocol::v2::ExecutorCompletionDescriptorV2>,
}

pub(crate) struct KernelToolApprovalConfigV2 {
    approvald_identity: ServiceIdentityV2,
    settlement_key_id: Ed25519KeyIdV2,
    settlement_public_key: [u8; 32],
}

impl KernelToolApprovalConfigV2 {
    pub(crate) fn from_verified_manifest(
        approvald_identity: ServiceIdentityV2,
        settlement_key_id: Ed25519KeyIdV2,
        settlement_public_key: [u8; 32],
    ) -> Result<Self, KernelAgentAuthorityErrorV2> {
        if is_zero(approvald_identity.as_bytes())
            || derive_ed25519_key_id_v2(settlement_public_key) != settlement_key_id
        {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        Ok(Self {
            approvald_identity,
            settlement_key_id,
            settlement_public_key,
        })
    }
}

pub(crate) struct KernelG4G5RuntimeV2 {
    active_tools: ActiveToolRegistryV2,
    validators: VerifiedInternalValidatorRegistryV2,
    durable: DurableG4StateV2,
    role: RoleIdV2,
    ontology: OntologyExprV2,
    disposition: VerifiedPolicyDispositionV2,
    approval: KernelToolApprovalConfigV2,
    g7: Option<KernelG7RuntimeV2>,
}

pub(crate) struct KernelG7RuntimeV2 {
    quota_limit: u32,
    quota_policy_digest: Digest32V2,
    executor_identity: ExecutorIdentityV2,
    executor_key_id: HpkeX25519KeyIdV2,
    executor_seal_public_key: [u8; 32],
    executor_connector_registry_digest: Digest32V2,
    effect_ledger_projection: savana_kernel_protocol::v2::VerifiedEffectLedgerProjectionV2,
    envelope_signing_key: SigningKey,
    executor_receipt_key_id: Ed25519KeyIdV2,
    executor_receipt_public_key: [u8; 32],
    executor: SuiteOneKernelExecutorClientV2,
}

impl KernelG7RuntimeV2 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_verified_deployment(
        quota_limit: u32,
        quota_policy_digest: Digest32V2,
        executor_identity: ExecutorIdentityV2,
        executor_key_id: HpkeX25519KeyIdV2,
        executor_seal_public_key: [u8; 32],
        executor_connector_registry_digest: Digest32V2,
        effect_ledger_projection: savana_kernel_protocol::v2::VerifiedEffectLedgerProjectionV2,
        envelope_signing_key: SigningKey,
        executor_receipt_key_id: Ed25519KeyIdV2,
        executor_receipt_public_key: [u8; 32],
        executor: SuiteOneKernelExecutorClientV2,
    ) -> Result<Self, KernelAgentAuthorityErrorV2> {
        if quota_limit == 0
            || [
                quota_policy_digest,
                Digest32V2::new(*executor_identity.as_bytes()),
                Digest32V2::new(*executor_key_id.as_bytes()),
                executor_connector_registry_digest,
                effect_ledger_projection.authenticated_head_digest(),
                effect_ledger_projection.projection_identity(),
            ]
            .iter()
            .any(|digest| is_zero(digest.as_bytes()))
            || hpke_x25519_key_id(executor_seal_public_key) != executor_key_id
            || derive_ed25519_key_id_v2(executor_receipt_public_key) != executor_receipt_key_id
        {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        Ok(Self {
            quota_limit,
            quota_policy_digest,
            executor_identity,
            executor_key_id,
            executor_seal_public_key,
            executor_connector_registry_digest,
            effect_ledger_projection,
            envelope_signing_key,
            executor_receipt_key_id,
            executor_receipt_public_key,
            executor,
        })
    }
}

impl KernelG4G5RuntimeV2 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_verified_policy(
        active_tools: ActiveToolRegistryV2,
        validators: VerifiedInternalValidatorRegistryV2,
        durable: DurableG4StateV2,
        role: RoleIdV2,
        ontology: OntologyExprV2,
        disposition: VerifiedPolicyDispositionV2,
        approval: KernelToolApprovalConfigV2,
    ) -> Result<Self, KernelAgentAuthorityErrorV2> {
        if active_tools.is_empty() || role.get() == 0 {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        Ok(Self {
            active_tools,
            validators,
            durable,
            role,
            ontology,
            disposition,
            approval,
            g7: None,
        })
    }

    pub(crate) fn install_g7(
        &mut self,
        g7: KernelG7RuntimeV2,
    ) -> Result<(), KernelAgentAuthorityErrorV2> {
        if self.g7.is_some() {
            return Err(KernelAgentAuthorityErrorV2::StateConflict);
        }
        self.g7 = Some(g7);
        Ok(())
    }
}

pub(crate) struct KernelAgentAuthorityV2 {
    config: KernelAgentSecurityConfigV2,
    handle_key: AuthorityHandleKeyV2,
    maximum_records: usize,
    tasks: Vec<TaskRecordV2>,
    authentication_preparations: Vec<AuthenticationPreparationRecordV2>,
    authorizations: Vec<AuthorizationRecordV2>,
    sessions: Vec<SessionRecordV2>,
    planner_tickets: Vec<PlannerTicketRecordV2>,
    tools: Vec<ToolRecordV2>,
    plan_steps: Vec<PlanStepRecordV2>,
    intents: Vec<IntentRecordV2>,
    execution_tickets: Vec<ExecutionTicketRecordV2>,
    executions: Vec<ExecutionRecordV2>,
    tool_approvals: Vec<ToolApprovalRecordV2>,
    pending_releases: Vec<PendingReleaseRecordV2>,
    release_tickets: Vec<ReleaseTicketRecordV2>,
    releases: Vec<ReleaseRecordV2>,
    policy: Option<KernelG4G5RuntimeV2>,
    durable_state: Option<DurableKernelAgentAuthorityStateV2>,
    durable_poisoned: bool,
}

impl std::fmt::Debug for KernelAgentAuthorityV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("KernelAgentAuthorityV2")
            .field("task_count", &self.tasks.len())
            .field(
                "authentication_preparation_count",
                &self.authentication_preparations.len(),
            )
            .field("authorization_count", &self.authorizations.len())
            .field("session_count", &self.sessions.len())
            .field("planner_ticket_count", &self.planner_tickets.len())
            .field("tool_count", &self.tools.len())
            .field("plan_step_count", &self.plan_steps.len())
            .field("intent_count", &self.intents.len())
            .field("execution_ticket_count", &self.execution_tickets.len())
            .field("execution_count", &self.executions.len())
            .field("tool_approval_count", &self.tool_approvals.len())
            .field("pending_release_count", &self.pending_releases.len())
            .field("release_ticket_count", &self.release_tickets.len())
            .field("release_count", &self.releases.len())
            .field("policy_installed", &self.policy.is_some())
            .finish_non_exhaustive()
    }
}

impl KernelAgentAuthorityV2 {
    pub(crate) fn new(
        config: KernelAgentSecurityConfigV2,
        maximum_records: usize,
    ) -> Result<Self, KernelAgentAuthorityErrorV2> {
        if maximum_records == 0 || maximum_records > 65_536 {
            return Err(KernelAgentAuthorityErrorV2::LimitExceeded);
        }
        Ok(Self {
            config,
            handle_key: AuthorityHandleKeyV2::from_entropy(random_bytes()?)
                .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?,
            maximum_records,
            tasks: Vec::new(),
            authentication_preparations: Vec::new(),
            authorizations: Vec::new(),
            sessions: Vec::new(),
            planner_tickets: Vec::new(),
            tools: Vec::new(),
            plan_steps: Vec::new(),
            intents: Vec::new(),
            execution_tickets: Vec::new(),
            executions: Vec::new(),
            tool_approvals: Vec::new(),
            pending_releases: Vec::new(),
            release_tickets: Vec::new(),
            releases: Vec::new(),
            policy: None,
            durable_state: None,
            durable_poisoned: false,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn open_durable(
        config: KernelAgentSecurityConfigV2,
        maximum_records: usize,
        path: &std::path::Path,
        encryption_key: [u8; 32],
        store_id: Digest32V2,
        rollback_anchor: Box<dyn KernelAgentAuthorityRollbackAnchorV2>,
        now: UnixMillisV2,
    ) -> Result<Self, KernelAgentAuthorityErrorV2> {
        let installation_id = config.installation_id;
        let (durable_state, snapshot) = DurableKernelAgentAuthorityStateV2::open(
            path,
            encryption_key,
            installation_id,
            store_id,
            rollback_anchor,
        )
        .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        let mut authority = Self::new(config, maximum_records)?;
        let had_snapshot = snapshot.is_some();
        if let Some(snapshot) = snapshot {
            authority.restore_recovery_snapshot(&snapshot, now)?;
        }
        authority.durable_state = Some(durable_state);
        if had_snapshot {
            authority.persist_recovery_snapshot()?;
        }
        Ok(authority)
    }

    fn ensure_durable_available(&self) -> Result<(), KernelAgentAuthorityErrorV2> {
        if self.durable_poisoned {
            Err(KernelAgentAuthorityErrorV2::Unavailable)
        } else {
            Ok(())
        }
    }

    fn persist_recovery_snapshot(&mut self) -> Result<(), KernelAgentAuthorityErrorV2> {
        self.ensure_durable_available()?;
        if self.durable_state.is_none() {
            return Ok(());
        }
        let bytes = self.encode_recovery_snapshot()?;
        let result = self
            .durable_state
            .as_mut()
            .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?
            .commit(&bytes);
        if result.is_err() {
            self.durable_poisoned = true;
            return Err(KernelAgentAuthorityErrorV2::Unavailable);
        }
        Ok(())
    }

    fn encode_recovery_snapshot(&self) -> Result<Vec<u8>, KernelAgentAuthorityErrorV2> {
        let mut encoder = minicbor::Encoder::new(Vec::new());
        encoder
            .array(4)
            .and_then(|encoder| encoder.u16(2))
            .and_then(|encoder| encoder.bytes(self.recovery_security_binding().as_bytes()))
            .and_then(|encoder| encoder.array(self.tasks.len() as u64))
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        for task in &self.tasks {
            encoder
                .array(13)
                .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
            encode_recovery_value(&mut encoder, &task.preparation)?;
            encode_recovery_value(&mut encoder, &task.agent_task_nonce)?;
            encode_recovery_value(&mut encoder, &task.client_request_nonce)?;
            encode_recovery_value(&mut encoder, &task.durable_task_id)?;
            encode_recovery_value(&mut encoder, &task.active_state_manifest_digest)?;
            encode_recovery_value(&mut encoder, &task.correlation)?;
            encode_recovery_value(&mut encoder, &task.ingress_transfer)?;
            encode_recovery_value(&mut encoder, &task.status)?;
            encode_optional_recovery_value(&mut encoder, task.expected_principal.as_ref())?;
            encode_optional_recovery_value(&mut encoder, task.claim_digest.as_ref())?;
            encode_optional_recovery_value(&mut encoder, task.durable_run_id.as_ref())?;
            match task.material.as_ref() {
                Some(material) => encode_prepared_claim_material(&mut encoder, material)?,
                None => {
                    encoder
                        .null()
                        .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
                }
            }
            match task.current_authentication_preparation {
                Some(index) => {
                    encoder
                        .u32(
                            u32::try_from(index)
                                .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?,
                        )
                        .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
                }
                None => {
                    encoder
                        .null()
                        .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
                }
            }
        }
        encoder
            .array(self.authentication_preparations.len() as u64)
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        for record in &self.authentication_preparations {
            encoder
                .array(13)
                .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
            encode_recovery_value(&mut encoder, &record.preparation)?;
            encoder
                .u32(
                    u32::try_from(record.task_index)
                        .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?,
                )
                .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
            encode_recovery_value(&mut encoder, &record.originating_kerneld_boot_id)?;
            encode_recovery_value(&mut encoder, &record.envelope)?;
            encode_recovery_value(&mut encoder, &record.envelope_digest)?;
            encode_recovery_value(&mut encoder, &record.binding_digest)?;
            encode_recovery_value(&mut encoder, &record.challenge)?;
            encode_recovery_value(&mut encoder, &record.recovery_record_digest)?;
            encode_recovery_value(&mut encoder, &record.closure)?;
            encode_recovery_value(&mut encoder, &record.replacement_nonce)?;
            encode_recovery_value(&mut encoder, &record.expires_at)?;
            encoder
                .bool(record.consumed)
                .and_then(|encoder| encoder.bool(record.restart_tombstoned))
                .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        }
        Ok(encoder.into_writer())
    }

    fn restore_recovery_snapshot(
        &mut self,
        bytes: &[u8],
        now: UnixMillisV2,
    ) -> Result<(), KernelAgentAuthorityErrorV2> {
        if !self.tasks.is_empty()
            || !self.authentication_preparations.is_empty()
            || bytes.is_empty()
            || bytes.len() > 128 * 1024 * 1024
        {
            return Err(KernelAgentAuthorityErrorV2::Unavailable);
        }
        let mut decoder = minicbor::Decoder::new(bytes);
        if decoder
            .array()
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?
            != Some(4)
            || decoder
                .u16()
                .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?
                != 2
            || Digest32V2::new(decode_recovery_fixed::<32>(&mut decoder)?)
                != self.recovery_security_binding()
        {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        let task_count = decode_recovery_count(&mut decoder, self.maximum_records)?;
        self.tasks
            .try_reserve_exact(task_count)
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        let correlation_key_id = derive_ed25519_key_id_v2(
            self.config
                .correlation_signing_key
                .verifying_key()
                .to_bytes(),
        );
        for _ in 0..task_count {
            require_recovery_array(&mut decoder, 13)?;
            let mut context = V2DecodeContext;
            let preparation = decode_recovery_value(&mut decoder, &mut context)?;
            let agent_task_nonce = decode_recovery_value(&mut decoder, &mut context)?;
            let client_request_nonce = decode_recovery_value(&mut decoder, &mut context)?;
            let durable_task_id = decode_recovery_value(&mut decoder, &mut context)?;
            let active_state_manifest_digest = decode_recovery_value(&mut decoder, &mut context)?;
            let correlation: SignedDurableTaskCorrelationV2 =
                decode_recovery_value(&mut decoder, &mut context)?;
            let ingress_transfer = decode_recovery_value(&mut decoder, &mut context)?;
            let status: PublicTaskStatusV2 = decode_recovery_value(&mut decoder, &mut context)?;
            let expected_principal = decode_optional_recovery_value(&mut decoder, &mut context)?;
            let claim_digest = decode_optional_recovery_value(&mut decoder, &mut context)?;
            let durable_run_id = decode_optional_recovery_value(&mut decoder, &mut context)?;
            let material = if decoder
                .datatype()
                .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?
                == minicbor::data::Type::Null
            {
                decoder
                    .null()
                    .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
                None
            } else {
                Some(decode_prepared_claim_material(&mut decoder, &mut context)?)
            };
            let current_authentication_preparation = decode_optional_recovery_u32(&mut decoder)?;
            let verified = correlation
                .verify(
                    correlation_key_id,
                    self.config
                        .correlation_signing_key
                        .verifying_key()
                        .to_bytes(),
                    self.config.installation_id,
                    active_state_manifest_digest,
                    self.config.agentd_identity,
                    correlation.unsigned().issued_at(),
                )
                .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
            if verified.durable_task_id() != durable_task_id
                || material.as_ref().is_some_and(|material| {
                    Some(material.durable_run_id) != durable_run_id
                        || material.provenance.producer_identity() != material.producer_identity
                        || material.provenance.run_internal_id() != material.durable_run_id
                        || material.provenance.active_state_manifest_digest()
                            != active_state_manifest_digest
                        || material.provenance.expires_at() != material.expires_at
                        || value_digest_v2(&material.initial_value)
                            .map_or(true, |digest| digest != material.provenance.value_digest())
                })
                || expected_principal.is_some() != claim_digest.is_some()
                || material.is_some() != (expected_principal.is_some() && durable_run_id.is_some())
            {
                return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
            }
            self.tasks.push(TaskRecordV2 {
                preparation,
                agent_task_nonce,
                client_request_nonce,
                durable_task_id,
                active_state_manifest_digest,
                correlation,
                ingress_transfer,
                status,
                expected_principal,
                claim_digest,
                durable_run_id,
                material,
                current_authentication_preparation: current_authentication_preparation
                    .map(|value| value as usize),
            });
        }
        let authentication_count = decode_recovery_count(&mut decoder, self.maximum_records)?;
        self.authentication_preparations
            .try_reserve_exact(authentication_count)
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        for _ in 0..authentication_count {
            require_recovery_array(&mut decoder, 13)?;
            let mut context = V2DecodeContext;
            let preparation = decode_recovery_value(&mut decoder, &mut context)?;
            let task_index = usize::try_from(
                decoder
                    .u32()
                    .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?,
            )
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
            let originating_kerneld_boot_id = decode_recovery_value(&mut decoder, &mut context)?;
            let envelope: SignedUiAuthenticationEnvelopeV2 =
                decode_recovery_value(&mut decoder, &mut context)?;
            let envelope_digest = decode_recovery_value(&mut decoder, &mut context)?;
            let binding_digest = decode_recovery_value(&mut decoder, &mut context)?;
            let challenge = decode_recovery_value(&mut decoder, &mut context)?;
            let recovery_record_digest = decode_recovery_value(&mut decoder, &mut context)?;
            let closure: SignedAgentAuthenticationClosureDescriptorV2 =
                decode_recovery_value(&mut decoder, &mut context)?;
            let replacement_nonce = decode_recovery_value(&mut decoder, &mut context)?;
            let expires_at = decode_recovery_value(&mut decoder, &mut context)?;
            let consumed = decoder
                .bool()
                .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
            let restart_tombstoned = decoder
                .bool()
                .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
            let task = self
                .tasks
                .get(task_index)
                .ok_or(KernelAgentAuthorityErrorV2::BindingMismatch)?;
            let descriptor = closure
                .verify(
                    correlation_key_id,
                    self.config
                        .correlation_signing_key
                        .verifying_key()
                        .to_bytes(),
                    closure.unsigned().issued_at(),
                )
                .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
            if descriptor.durable_task_id() != task.durable_task_id
                || descriptor.signed_correlation_digest()
                    != task
                        .correlation
                        .correlation_digest()
                        .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?
                || descriptor.authentication_envelope_digest() != envelope_digest
                || descriptor.authentication_recovery_record_digest() != recovery_record_digest
                || descriptor.auth_attempt_nonce() != challenge
                || envelope
                    .envelope_digest()
                    .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?
                    != envelope_digest
                || envelope
                    .verify_deployment(
                        derive_ed25519_key_id_v2(
                            self.config.envelope_signing_key.verifying_key().to_bytes(),
                        ),
                        self.config.envelope_signing_key.verifying_key().to_bytes(),
                        self.config.installation_id,
                        descriptor.attempt_manifest_digest(),
                        descriptor.attempt_deployment_generation(),
                    )
                    .is_err()
            {
                return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
            }
            self.authentication_preparations
                .push(AuthenticationPreparationRecordV2 {
                    preparation,
                    task_index,
                    originating_kerneld_boot_id,
                    envelope,
                    envelope_digest,
                    binding_digest,
                    challenge,
                    recovery_record_digest,
                    closure,
                    replacement_nonce,
                    expires_at,
                    consumed,
                    restart_tombstoned,
                });
        }
        if decoder.position() != bytes.len()
            || self.tasks.iter().enumerate().any(|(task_index, task)| {
                task.current_authentication_preparation
                    .is_some_and(|index| {
                        index >= self.authentication_preparations.len()
                            || self.authentication_preparations[index].task_index != task_index
                    })
            })
            || self.encode_recovery_snapshot()? != bytes
        {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        for task in &mut self.tasks {
            let verified = task
                .correlation
                .verify(
                    correlation_key_id,
                    self.config
                        .correlation_signing_key
                        .verifying_key()
                        .to_bytes(),
                    self.config.installation_id,
                    task.active_state_manifest_digest,
                    self.config.agentd_identity,
                    task.correlation.unsigned().issued_at(),
                )
                .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
            if now.get() >= verified.status_retain_until().get() {
                task.status = PublicTaskStatusV2::Expired;
                task.material = None;
                task.current_authentication_preparation = None;
            } else if matches!(
                task.status,
                PublicTaskStatusV2::Running | PublicTaskStatusV2::Dispatching
            ) {
                task.status = PublicTaskStatusV2::Indeterminate;
                task.material = None;
                task.current_authentication_preparation = None;
            }
        }
        for (index, record) in self.authentication_preparations.iter().enumerate() {
            if record.consumed
                && self.tasks[record.task_index].current_authentication_preparation == Some(index)
            {
                self.tasks[record.task_index].status = PublicTaskStatusV2::Indeterminate;
                self.tasks[record.task_index].material = None;
                self.tasks[record.task_index].current_authentication_preparation = None;
            }
        }
        Ok(())
    }

    fn recovery_security_binding(&self) -> Digest32V2 {
        domain_digest(
            b"SAVANA_KERNEL_AGENT_AUTHORITY_SECURITY_BINDING_V2\0",
            &[
                self.config.installation_id.as_bytes(),
                self.config.kerneld_identity.as_bytes(),
                self.config.agentd_identity.as_bytes(),
                self.config.approvald_identity.as_bytes(),
                self.config
                    .correlation_signing_key
                    .verifying_key()
                    .as_bytes(),
                self.config.envelope_signing_key.verifying_key().as_bytes(),
                self.config.ui_settlement_key_id.as_bytes(),
            ],
        )
    }

    pub(crate) fn install_g4_g5_runtime(
        &mut self,
        runtime: KernelG4G5RuntimeV2,
    ) -> Result<(), KernelAgentAuthorityErrorV2> {
        if self.policy.is_some()
            || !self.sessions.is_empty()
            || !self.planner_tickets.is_empty()
            || !self.intents.is_empty()
        {
            return Err(KernelAgentAuthorityErrorV2::StateConflict);
        }
        self.policy = Some(runtime);
        Ok(())
    }

    pub(crate) fn production_ready(&self) -> bool {
        !self.durable_poisoned
            && self.durable_state.is_some()
            && self
                .policy
                .as_ref()
                .is_some_and(|policy| policy.g7.is_some())
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare_new_ingress(
        &mut self,
        request: PrepareNewIngressRequestV2,
        ingress: &mut KernelIngressAuthorityV2,
        caller_identity: ServiceIdentityV2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        now: UnixMillisV2,
    ) -> Result<PrepareNewIngressResponseV2, KernelAgentAuthorityErrorV2> {
        self.verify_agent_caller(caller_identity)?;
        if let Some(existing) = self.tasks.iter().find(|task| {
            task.agent_task_nonce == request.agent_task_nonce()
                && task.client_request_nonce == request.client_request_nonce()
        }) {
            return Ok(PrepareNewIngressResponseV2::Reconciled {
                preparation: existing.preparation,
                correlation: existing.correlation.clone(),
                ingress_transfer: existing.ingress_transfer,
                current: existing.status,
            });
        }
        if self.tasks.len() >= self.maximum_records {
            return Err(KernelAgentAuthorityErrorV2::LimitExceeded);
        }
        let task_expires_at = checked_deadline(now, TASK_LOGICAL_TTL_MS)?;
        let status_retain_until = checked_deadline(now, TASK_STATUS_RETENTION_MS)?;
        let (durable_task_id, ingress_transfer) = ingress
            .mint_new_task_bootstrap(request.agent_task_nonce(), None, now, task_expires_at)
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        let correlation = SignedDurableTaskCorrelationV2::sign(
            UnsignedDurableTaskCorrelationV2::new(
                self.config.installation_id,
                active_state_manifest_digest,
                deployment_generation,
                durable_task_id,
                self.config.agentd_identity,
                self.config.agentd_kernel_client_boot_id,
                self.config.kerneld_server_boot_id,
                self.config.machine_boot_id,
                now,
                task_expires_at,
                status_retain_until,
            )
            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?,
            &self.config.correlation_signing_key,
        )
        .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        let preparation = mint_handle(NewTaskPreparationHandleV2::from_authority_entropy)?;
        self.tasks
            .try_reserve(1)
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        self.tasks.push(TaskRecordV2 {
            preparation,
            agent_task_nonce: request.agent_task_nonce(),
            client_request_nonce: request.client_request_nonce(),
            durable_task_id,
            active_state_manifest_digest,
            correlation: correlation.clone(),
            ingress_transfer,
            status: PublicTaskStatusV2::AwaitingInput,
            expected_principal: None,
            claim_digest: None,
            durable_run_id: None,
            material: None,
            current_authentication_preparation: None,
        });
        self.persist_recovery_snapshot()?;
        Ok(PrepareNewIngressResponseV2::Prepared {
            preparation,
            correlation,
            ingress_transfer,
        })
    }

    pub(crate) fn mark_ingress_committed(
        &mut self,
        durable_task_id: DurableTaskIdV2,
        principal: PrincipalIdV2,
        material: PreparedAgentClaimMaterialV2,
    ) -> Result<(), KernelAgentAuthorityErrorV2> {
        self.ensure_durable_available()?;
        let task = self
            .tasks
            .iter_mut()
            .find(|task| task.durable_task_id == durable_task_id)
            .ok_or(KernelAgentAuthorityErrorV2::InvalidReference)?;
        if let Some(existing) = task.expected_principal {
            if existing != principal {
                return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
            }
            if task.material.is_some() {
                return Ok(());
            }
        }
        if !matches!(
            task.status,
            PublicTaskStatusV2::AwaitingInput
                | PublicTaskStatusV2::Processing
                | PublicTaskStatusV2::AwaitingIngressApproval
        ) {
            return Err(KernelAgentAuthorityErrorV2::StateConflict);
        }
        let claim_digest = claim_digest(
            durable_task_id,
            principal,
            material.durable_run_id,
            material.initial_document,
        )?;
        task.expected_principal = Some(principal);
        task.claim_digest = Some(claim_digest);
        task.durable_run_id = Some(material.durable_run_id);
        task.material = Some(material);
        task.status = PublicTaskStatusV2::Ready { bootstrap: None };
        self.persist_recovery_snapshot()
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare_ui_authentication(
        &mut self,
        request: PrepareAgentUiAuthenticationRequestV2,
        caller_identity: ServiceIdentityV2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        now: UnixMillisV2,
    ) -> Result<PrepareAgentUiAuthenticationResponseV2, KernelAgentAuthorityErrorV2> {
        self.verify_agent_caller(caller_identity)?;
        let task_index = self
            .tasks
            .iter()
            .position(|task| task.preparation == request.preparation())
            .ok_or(KernelAgentAuthorityErrorV2::InvalidReference)?;
        if !matches!(
            self.tasks[task_index].status,
            PublicTaskStatusV2::Ready { .. }
        ) {
            return Err(KernelAgentAuthorityErrorV2::StateConflict);
        }
        if let Some(record_index) = self.tasks[task_index].current_authentication_preparation {
            let record = self
                .authentication_preparations
                .get(record_index)
                .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?;
            if record.originating_kerneld_boot_id == self.config.kerneld_server_boot_id
                && !record.consumed
                && !record.restart_tombstoned
                && now.get() < record.expires_at.get()
            {
                return Ok(PrepareAgentUiAuthenticationResponseV2::new(
                    record.preparation,
                    record.envelope.clone(),
                ));
            }
            return Err(KernelAgentAuthorityErrorV2::StateConflict);
        }
        let replacement_nonce = Nonce32V2::new(random_bytes()?);
        self.create_authentication_attempt(
            task_index,
            replacement_nonce,
            active_state_manifest_digest,
            deployment_generation,
            now,
        )
    }

    fn create_authentication_attempt(
        &mut self,
        task_index: usize,
        replacement_nonce: Nonce32V2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        now: UnixMillisV2,
    ) -> Result<PrepareAgentUiAuthenticationResponseV2, KernelAgentAuthorityErrorV2> {
        if self.authentication_preparations.len() >= self.maximum_records {
            return Err(KernelAgentAuthorityErrorV2::LimitExceeded);
        }
        let task = self
            .tasks
            .get(task_index)
            .ok_or(KernelAgentAuthorityErrorV2::InvalidReference)?;
        let principal = task
            .expected_principal
            .ok_or(KernelAgentAuthorityErrorV2::StateConflict)?;
        let claim_digest = task
            .claim_digest
            .ok_or(KernelAgentAuthorityErrorV2::StateConflict)?;
        let durable_run_id = task
            .durable_run_id
            .ok_or(KernelAgentAuthorityErrorV2::StateConflict)?;
        let correlation_digest = task
            .correlation
            .correlation_digest()
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        let challenge = Nonce32V2::new(random_bytes()?);
        let expires_at = checked_deadline(now, AGENT_UI_AUTH_TTL_MS)?;
        let binding = UiAuthenticationBindingV2::AgentContent {
            durable_task_id: task.durable_task_id,
            ingress_claim_digest: claim_digest,
            agentd_identity: self.config.agentd_identity,
            agentd_boot_id: self.config.agentd_kernel_client_boot_id,
        };
        let unsigned = UnsignedUiAuthenticationEnvelopeV2::new(
            self.config.installation_id,
            active_state_manifest_digest,
            deployment_generation,
            UiAuthenticationPurposeV2::AgentContent,
            binding,
            Some(principal),
            FixedOriginV2::Approval8766,
            FixedOriginV2::Agent8768,
            challenge,
            now,
            expires_at,
        )
        .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let binding_digest = unsigned
            .binding_digest()
            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let envelope =
            SignedUiAuthenticationEnvelopeV2::sign(unsigned, &self.config.envelope_signing_key)
                .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        let envelope_digest = envelope
            .envelope_digest()
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        let preparation =
            mint_handle(AgentUiAuthenticationPreparationHandleV2::from_authority_entropy)?;
        let preparation_hash = preparation.authority_commitment(&self.handle_key);
        let recovery_record_digest = authentication_recovery_record_digest(
            task.durable_task_id,
            durable_run_id,
            correlation_digest,
            claim_digest,
            principal,
            challenge,
            envelope_digest,
            preparation_hash,
            self.config.kerneld_server_boot_id,
        );
        let closure_expires_at = checked_deadline(now, TASK_STATUS_RETENTION_MS)?;
        let closure = SignedAgentAuthenticationClosureDescriptorV2::sign(
            UnsignedAgentAuthenticationClosureDescriptorV2::new(
                self.config.installation_id,
                task.active_state_manifest_digest,
                task.correlation.unsigned().deployment_generation(),
                active_state_manifest_digest,
                deployment_generation,
                None,
                task.durable_task_id,
                durable_run_id,
                correlation_digest,
                claim_digest,
                principal,
                self.config.agentd_identity,
                self.config.agentd_kernel_client_boot_id,
                self.config.kerneld_identity,
                self.config.kerneld_server_boot_id,
                self.config.approvald_identity,
                challenge,
                recovery_record_digest,
                preparation_hash,
                envelope_digest,
                Nonce32V2::new(random_bytes()?),
                now,
                closure_expires_at,
            )
            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?,
            &self.config.correlation_signing_key,
        )
        .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        self.authentication_preparations
            .try_reserve(1)
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        let record_index = self.authentication_preparations.len();
        self.authentication_preparations
            .push(AuthenticationPreparationRecordV2 {
                preparation,
                task_index,
                originating_kerneld_boot_id: self.config.kerneld_server_boot_id,
                envelope: envelope.clone(),
                envelope_digest,
                binding_digest,
                challenge,
                recovery_record_digest,
                closure,
                replacement_nonce,
                expires_at,
                consumed: false,
                restart_tombstoned: false,
            });
        self.tasks[task_index].current_authentication_preparation = Some(record_index);
        self.persist_recovery_snapshot()?;
        Ok(PrepareAgentUiAuthenticationResponseV2::new(
            preparation,
            envelope,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn authenticate_ui(
        &mut self,
        preparation: AgentUiAuthenticationPreparationHandleV2,
        settlement: &SignedUiAuthenticationSettlementV2,
        caller_identity: ServiceIdentityV2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        now: UnixMillisV2,
    ) -> Result<AgentUiAuthorizationHandleV2, KernelAgentAuthorityErrorV2> {
        self.verify_agent_caller(caller_identity)?;
        let record_index = self
            .authentication_preparations
            .iter()
            .position(|record| record.preparation == preparation)
            .ok_or(KernelAgentAuthorityErrorV2::InvalidReference)?;
        let record = &self.authentication_preparations[record_index];
        if record.consumed {
            return Err(KernelAgentAuthorityErrorV2::AlreadyConsumed);
        }
        if now.get() >= record.expires_at.get() {
            return Err(KernelAgentAuthorityErrorV2::Expired);
        }
        let verified = settlement
            .verify_agent_content(
                self.config.ui_settlement_key_id,
                self.config.ui_settlement_public_key,
                self.config.installation_id,
                active_state_manifest_digest,
                deployment_generation,
                now,
            )
            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let task = &self.tasks[record.task_index];
        if verified.envelope_digest() != record.envelope_digest
            || verified.binding_digest() != record.binding_digest
            || verified.challenge() != record.challenge
            || Some(verified.authenticated_principal()) != task.expected_principal
        {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        if self.authorizations.len() >= self.maximum_records {
            return Err(KernelAgentAuthorityErrorV2::LimitExceeded);
        }
        let authorization = mint_handle(AgentUiAuthorizationHandleV2::from_authority_entropy)?;
        self.authorizations
            .try_reserve(1)
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        self.authorizations.push(AuthorizationRecordV2 {
            authorization,
            task_index: record.task_index,
            consumed: false,
        });
        self.authentication_preparations[record_index].consumed = true;
        self.persist_recovery_snapshot()?;
        Ok(authorization)
    }

    pub(crate) fn claim_session(
        &mut self,
        request: ClaimAgentSessionRequestV2,
        values: &mut KernelValueOwnerV2,
        caller_identity: ServiceIdentityV2,
        active_state_manifest_digest: Digest32V2,
        now: UnixMillisV2,
    ) -> Result<ClaimAgentSessionResponseV2, KernelAgentAuthorityErrorV2> {
        self.verify_agent_caller(caller_identity)?;
        if self.sessions.len() >= self.maximum_records {
            return Err(KernelAgentAuthorityErrorV2::LimitExceeded);
        }
        let authorization_index = self
            .authorizations
            .iter()
            .position(|record| record.authorization == request.authorization())
            .ok_or(KernelAgentAuthorityErrorV2::InvalidReference)?;
        if self.authorizations[authorization_index].consumed {
            return Err(KernelAgentAuthorityErrorV2::AlreadyConsumed);
        }
        let task_index = self.authorizations[authorization_index].task_index;
        let task = &mut self.tasks[task_index];
        if task.active_state_manifest_digest != active_state_manifest_digest {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        if !matches!(task.status, PublicTaskStatusV2::Ready { .. }) {
            return Err(KernelAgentAuthorityErrorV2::StateConflict);
        }
        let material = task
            .material
            .as_ref()
            .ok_or(KernelAgentAuthorityErrorV2::StateConflict)?;
        let principal = task
            .expected_principal
            .ok_or(KernelAgentAuthorityErrorV2::StateConflict)?;
        let durable_task_id = task.durable_task_id;
        if now.get() >= material.expires_at.get() {
            task.status = PublicTaskStatusV2::Expired;
            self.persist_recovery_snapshot()?;
            return Err(KernelAgentAuthorityErrorV2::Expired);
        }
        let admission = values
            .prepare_verified_run_admission(
                material.producer_identity,
                material.durable_run_id,
                active_state_manifest_digest,
                now,
                material.expires_at,
                material.policy_allowed_effects,
                &material.initial_value,
                &material.provenance,
            )
            .map_err(map_value_error)?;
        let run = admission.run_handle();
        let initial = admission.initial_value();
        let revision = RunRevisionObservationV2::new(
            material.durable_run_id,
            1,
            run_revision_digest(
                material.durable_run_id,
                active_state_manifest_digest,
                initial.value_digest(),
            ),
        )
        .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        let session = mint_handle(AgentSessionHandleV2::from_authority_entropy)?;
        let role = self
            .policy
            .as_ref()
            .map_or(RoleIdV2::new(1), |policy| policy.role);
        let mut active_tool_entries = Vec::new();
        if let Some(policy) = self.policy.as_ref() {
            active_tool_entries
                .try_reserve_exact(policy.active_tools.len())
                .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
            for active in policy.active_tools.records() {
                let descriptor = active.descriptor();
                if policy
                    .active_tools
                    .resolve(descriptor.descriptor_digest(), role, now)
                    .is_none()
                {
                    continue;
                }
                let tool = mint_handle(ToolHandleV2::from_authority_entropy)?;
                let commitment = tool.authority_commitment(&self.handle_key);
                if self
                    .tools
                    .iter()
                    .any(|record| record.commitment == commitment)
                    || active_tool_entries.iter().any(
                        |entry: &(ActiveToolViewV2, ToolRecordV2, u32, u32, Digest32V2)| {
                            entry.1.commitment == commitment
                        },
                    )
                {
                    return Err(KernelAgentAuthorityErrorV2::Unavailable);
                }
                let unsigned = descriptor.unsigned();
                let view = ActiveToolViewV2::new(
                    tool,
                    unsigned.action_template(),
                    unsigned.tool_class(),
                    StaticTemplateIdV2::new(unsigned.display_projection().get()),
                )
                .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
                active_tool_entries.push((
                    view,
                    ToolRecordV2 {
                        commitment,
                        run,
                        descriptor_digest: descriptor.descriptor_digest(),
                    },
                    unsigned.action_template().get(),
                    unsigned.tool_class().get(),
                    descriptor.descriptor_digest(),
                ));
            }
        }
        active_tool_entries.sort_unstable_by(|left, right| {
            (left.2, left.3, left.4.as_bytes()).cmp(&(right.2, right.3, right.4.as_bytes()))
        });
        let active_tools = active_tool_entries
            .iter()
            .map(|entry| entry.0)
            .collect::<Vec<_>>();
        self.sessions
            .try_reserve(1)
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        self.tools
            .try_reserve(active_tool_entries.len())
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        let response = ClaimAgentSessionResponseV2::new(
            session,
            run,
            revision,
            initial.handle(),
            material.initial_document,
            active_tools,
        )
        .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        let material = task
            .material
            .take()
            .ok_or(KernelAgentAuthorityErrorV2::StateConflict)?;
        values.commit_verified_run_admission(
            admission,
            material.initial_value,
            material.provenance,
        );
        self.sessions.push(SessionRecordV2 {
            session,
            run,
            durable_run_id: material.durable_run_id,
            durable_task_id,
            active_state_manifest_digest,
            principal,
            producer_identity: material.producer_identity,
            role,
            policy_allowed_effects: material.policy_allowed_effects,
            expires_at: material.expires_at,
            revision,
            initial_document: material.initial_document,
            status: AgentSessionStatusV2::Running,
        });
        self.tools.extend(
            active_tool_entries
                .into_iter()
                .map(|(_, record, _, _, _)| record),
        );
        self.authorizations[authorization_index].consumed = true;
        task.status = PublicTaskStatusV2::Running;
        self.persist_recovery_snapshot()?;
        Ok(response)
    }

    pub(crate) fn task_status(
        &self,
        request: &GetKernelTaskStatusRequestV2,
        caller_identity: ServiceIdentityV2,
        active_state_manifest_digest: Digest32V2,
        now: UnixMillisV2,
    ) -> Result<GetKernelTaskStatusResponseV2, KernelAgentAuthorityErrorV2> {
        self.verify_agent_caller(caller_identity)?;
        let unsigned = request
            .correlation()
            .verify(
                derive_ed25519_key_id_v2(
                    self.config
                        .correlation_signing_key
                        .verifying_key()
                        .to_bytes(),
                ),
                self.config
                    .correlation_signing_key
                    .verifying_key()
                    .to_bytes(),
                self.config.installation_id,
                active_state_manifest_digest,
                self.config.agentd_identity,
                now,
            )
            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let task = self
            .tasks
            .iter()
            .find(|task| task.durable_task_id == unsigned.durable_task_id())
            .ok_or(KernelAgentAuthorityErrorV2::InvalidReference)?;
        if &task.correlation != request.correlation() {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        Ok(GetKernelTaskStatusResponseV2::new(task.status))
    }

    pub(crate) fn cancel_task(
        &mut self,
        request: &CancelKernelTaskRequestV2,
        caller_identity: ServiceIdentityV2,
        active_state_manifest_digest: Digest32V2,
        now: UnixMillisV2,
    ) -> Result<CancelKernelTaskResponseV2, KernelAgentAuthorityErrorV2> {
        self.verify_agent_caller(caller_identity)?;
        let unsigned = request
            .correlation()
            .verify(
                derive_ed25519_key_id_v2(
                    self.config
                        .correlation_signing_key
                        .verifying_key()
                        .to_bytes(),
                ),
                self.config
                    .correlation_signing_key
                    .verifying_key()
                    .to_bytes(),
                self.config.installation_id,
                active_state_manifest_digest,
                self.config.agentd_identity,
                now,
            )
            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let task = self
            .tasks
            .iter_mut()
            .find(|task| {
                task.durable_task_id == unsigned.durable_task_id()
                    && task.preparation == request.preparation()
            })
            .ok_or(KernelAgentAuthorityErrorV2::InvalidReference)?;
        if &task.correlation != request.correlation() {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        if task.status == PublicTaskStatusV2::Cancelled {
            return Ok(CancelKernelTaskResponseV2::new(task.status));
        }
        if matches!(
            task.status,
            PublicTaskStatusV2::Running
                | PublicTaskStatusV2::Dispatching
                | PublicTaskStatusV2::Succeeded
                | PublicTaskStatusV2::EffectSucceededOutputQuarantined { .. }
                | PublicTaskStatusV2::FailedNoEffect { .. }
                | PublicTaskStatusV2::Indeterminate
        ) {
            return Err(KernelAgentAuthorityErrorV2::StateConflict);
        }
        task.material = None;
        task.status = PublicTaskStatusV2::Cancelled;
        let status = task.status;
        self.persist_recovery_snapshot()?;
        Ok(CancelKernelTaskResponseV2::new(status))
    }

    pub(crate) fn session_status(
        &self,
        request: GetAgentSessionStatusRequestV2,
        caller_identity: ServiceIdentityV2,
    ) -> Result<GetAgentSessionStatusResponseV2, KernelAgentAuthorityErrorV2> {
        self.verify_agent_caller(caller_identity)?;
        let session = self
            .sessions
            .iter()
            .find(|session| session.session == request.session())
            .ok_or(KernelAgentAuthorityErrorV2::InvalidReference)?;
        let revision = matches!(
            session.status,
            AgentSessionStatusV2::Ready | AgentSessionStatusV2::Running
        )
        .then_some(session.revision);
        GetAgentSessionStatusResponseV2::new(session.status, revision)
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)
    }

    pub(crate) fn prepare_planner_call(
        &mut self,
        request: &PreparePlannerCallRequestV2,
        values: &KernelValueOwnerV2,
        caller_identity: ServiceIdentityV2,
        now: UnixMillisV2,
    ) -> Result<PreparePlannerCallResponseV2, KernelAgentAuthorityErrorV2> {
        self.verify_agent_caller(caller_identity)?;
        if self.planner_tickets.len() >= self.maximum_records {
            return Err(KernelAgentAuthorityErrorV2::LimitExceeded);
        }
        if !self.sessions.iter().any(|session| {
            session.run == request.run()
                && matches!(
                    session.status,
                    AgentSessionStatusV2::Ready | AgentSessionStatusV2::Running
                )
        }) {
            return Err(KernelAgentAuthorityErrorV2::InvalidReference);
        }
        values
            .validate_run_values(request.run(), request.prompt_values(), now)
            .map_err(map_value_error)?;

        let expires_at = checked_deadline(now, 60_000)?;
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(request.prompt_values().len())
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        for _ in request.prompt_values() {
            let mut reference = [0_u8; 16];
            getrandom(&mut reference).map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
            if reference == [0; 16] {
                return Err(KernelAgentAuthorityErrorV2::Unavailable);
            }
            slots.push(
                PlannerAbstractSlotV2::new(
                    PlannerSlotRefV2::new(reference),
                    SlotKindV2::new(1),
                    PlannerSlotCardinalityV2::ExactlyOne,
                    PlannerSlotConfidentialityV2::ConfidentialAbstract,
                )
                .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?,
            );
        }
        let mut sortable_slots = Vec::new();
        sortable_slots
            .try_reserve_exact(slots.len())
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        for (slot, value) in slots.into_iter().zip(request.prompt_values()) {
            let canonical =
                minicbor::to_vec(slot).map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
            sortable_slots.push((canonical, slot, *value));
        }
        sortable_slots.sort_unstable_by(|left, right| left.0.cmp(&right.0));
        let slot_bindings = sortable_slots
            .iter()
            .map(|(_, slot, value)| PlannerSlotBindingRecordV2 {
                slot: *slot,
                value: *value,
            })
            .collect::<Vec<_>>();
        let slots = sortable_slots
            .into_iter()
            .map(|(_, slot, _)| slot)
            .collect();
        let envelope_nonce = Nonce32V2::new(random_bytes()?);
        let envelope = PlannerEnvelopeV2::new(
            request.planner_route(),
            StaticTemplateIdV2::new(1),
            PlannerIntentKindV2::SummarizeDocument,
            Vec::new(),
            slots,
            Vec::new(),
            PlannerLimitsV2::new(256, 256, 256, 8 * 1024 * 1024)
                .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?,
            envelope_nonce,
            expires_at,
        )
        .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        let canonical =
            minicbor::to_vec(&envelope).map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        let envelope_digest = domain_digest(PLANNER_ENVELOPE_DOMAIN, &[canonical.as_slice()]);
        let ticket = mint_handle(PlannerTicketHandleV2::from_authority_entropy)?;
        let response =
            PreparePlannerCallResponseV2::new(ticket, envelope, envelope_digest, expires_at)
                .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        self.planner_tickets
            .try_reserve(1)
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        self.planner_tickets.push(PlannerTicketRecordV2 {
            ticket,
            run: request.run(),
            planner_route: request.planner_route(),
            prompt_values: request.prompt_values().to_vec(),
            slot_bindings,
            envelope_nonce,
            envelope_digest,
            expires_at,
            consumed: false,
        });
        Ok(response)
    }

    pub(crate) fn prepare_followup_ingress(
        &self,
        request: PrepareFollowupIngressRequestV2,
        caller_identity: ServiceIdentityV2,
    ) -> Result<PrepareFollowupIngressResponseV2, KernelAgentAuthorityErrorV2> {
        self.verify_agent_caller(caller_identity)?;
        let session = self
            .sessions
            .iter()
            .find(|session| session.session == request.session())
            .ok_or(KernelAgentAuthorityErrorV2::InvalidReference)?;
        if session.run != request.run() {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        if !matches!(
            session.status,
            AgentSessionStatusV2::Ready | AgentSessionStatusV2::Running
        ) {
            return Err(KernelAgentAuthorityErrorV2::StateConflict);
        }
        // The default verified manifest has no follow-up input transition.
        // A request is therefore a closed policy denial, never a fallback or
        // an untyped ingress transfer.
        Err(KernelAgentAuthorityErrorV2::StateConflict)
    }

    pub(crate) fn commit_planner_value(
        &mut self,
        request: &CommitPlannerValueRequestV2,
        values: &mut KernelValueOwnerV2,
        caller_identity: ServiceIdentityV2,
        now: UnixMillisV2,
    ) -> Result<CommitPlannerValueResponseV2, KernelAgentAuthorityErrorV2> {
        self.verify_agent_caller(caller_identity)?;
        let index = self
            .planner_tickets
            .iter()
            .position(|record| record.ticket == request.ticket())
            .ok_or(KernelAgentAuthorityErrorV2::InvalidReference)?;
        let record = &self.planner_tickets[index];
        if record.consumed {
            return Err(KernelAgentAuthorityErrorV2::AlreadyConsumed);
        }
        if record.run != request.run() || record.envelope_nonce != request.plan().envelope_nonce() {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        if now.get() >= record.expires_at.get() {
            return Err(KernelAgentAuthorityErrorV2::Expired);
        }
        let session = self
            .sessions
            .iter()
            .find(|session| {
                session.run == request.run()
                    && matches!(
                        session.status,
                        AgentSessionStatusV2::Ready | AgentSessionStatusV2::Running
                    )
            })
            .ok_or(KernelAgentAuthorityErrorV2::InvalidReference)?;
        let policy = self
            .policy
            .as_ref()
            .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?;
        let mut resolved_steps = Vec::new();
        resolved_steps
            .try_reserve_exact(request.plan().steps().len())
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        for step in request.plan().steps() {
            let active = policy
                .active_tools
                .resolve_class(step.tool_class(), session.role, now)
                .ok_or(KernelAgentAuthorityErrorV2::InvalidReference)?;
            if active.descriptor().unsigned().action_template() != step.action_template() {
                return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
            }
            let mut arguments = Vec::new();
            arguments
                .try_reserve_exact(step.slot_bindings().len())
                .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
            for (name, reference) in step.slot_bindings() {
                let binding = record
                    .slot_bindings
                    .iter()
                    .find(|binding| binding.slot.reference() == *reference)
                    .ok_or(KernelAgentAuthorityErrorV2::InvalidReference)?;
                arguments.push(PlanArgumentRecordV2 {
                    name: savana_policy_core::v2::ArgumentNameV2::new(name.as_str())
                        .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?,
                    slot: binding.slot,
                    value: binding.value,
                });
            }
            resolved_steps.push((
                step.ordinal(),
                active.descriptor().descriptor_digest(),
                arguments,
            ));
        }
        let canonical_plan = savana_kernel_protocol::v2::encode_kernel_agent_operation_v2(
            &savana_kernel_protocol::v2::KernelAgentOperationV2::CommitPlannerValue(
                request.clone(),
            ),
        )
        .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        let planner_output_digest =
            domain_digest(PLANNER_OUTPUT_DOMAIN, &[canonical_plan.as_slice()]);
        let planner_route_digest = domain_digest(
            PLANNER_ROUTE_DOMAIN,
            &[&record.planner_route.get().to_be_bytes()],
        );
        let committed = values
            .commit_planner_value(
                request.run(),
                &record.prompt_values,
                canonical_plan.clone(),
                planner_route_digest,
                record.envelope_digest,
                planner_output_digest,
                now,
            )
            .map_err(map_value_error)?;
        let plan_revision_digest = PlanRevisionDigestV2::new(
            domain_digest(
                PLAN_REVISION_DOMAIN,
                &[
                    record.envelope_digest.as_bytes(),
                    planner_output_digest.as_bytes(),
                    committed.value_digest().as_bytes(),
                ],
            )
            .as_bytes()
            .to_owned(),
        );
        let response = CommitPlannerValueResponseV2::new(
            committed.handle(),
            committed.value_digest(),
            plan_revision_digest,
            {
                let mut handles = Vec::new();
                handles
                    .try_reserve_exact(resolved_steps.len())
                    .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
                let mut records = Vec::new();
                records
                    .try_reserve_exact(resolved_steps.len())
                    .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
                for (ordinal, descriptor_digest, arguments) in resolved_steps {
                    let mut internal_step_parts = Vec::new();
                    internal_step_parts.extend_from_slice(plan_revision_digest.as_bytes());
                    internal_step_parts.extend_from_slice(&ordinal.to_be_bytes());
                    internal_step_parts.extend_from_slice(descriptor_digest.as_bytes());
                    for argument in &arguments {
                        internal_step_parts.extend_from_slice(argument.name.as_str().as_bytes());
                        internal_step_parts.extend_from_slice(argument.slot.reference().as_bytes());
                    }
                    let internal_step_id = savana_kernel_protocol::v2::InternalStepIdV2::new(
                        *domain_digest(INTERNAL_STEP_DOMAIN, &[&internal_step_parts]).as_bytes(),
                    );
                    let step = mint_handle(PlanStepHandleV2::from_authority_entropy)?;
                    let commitment = step.authority_commitment(&self.handle_key);
                    if self
                        .plan_steps
                        .iter()
                        .any(|record| record.commitment == commitment)
                        || records
                            .iter()
                            .any(|record: &PlanStepRecordV2| record.commitment == commitment)
                    {
                        return Err(KernelAgentAuthorityErrorV2::Unavailable);
                    }
                    handles.push(step);
                    records.push(PlanStepRecordV2 {
                        commitment,
                        run: request.run(),
                        durable_run_id: session.durable_run_id,
                        durable_task_id: session.durable_task_id,
                        principal: session.principal,
                        role: session.role,
                        plan_revision_digest,
                        internal_step_id,
                        descriptor_digest,
                        arguments,
                    });
                }
                self.plan_steps
                    .try_reserve(records.len())
                    .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
                self.plan_steps.extend(records);
                handles
            },
        )
        .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        self.planner_tickets[index].consumed = true;
        Ok(response)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn propose_tool_call(
        &mut self,
        request_id: savana_kernel_protocol::v2::RequestIdV2,
        authenticated_canonical_request: &[u8],
        request: &ProposeToolCallRequestV2,
        values: &KernelValueOwnerV2,
        caller_identity: ServiceIdentityV2,
        active_state_manifest_digest: Digest32V2,
        now: UnixMillisV2,
    ) -> Result<ProposeToolCallResponseV2, KernelAgentAuthorityErrorV2> {
        self.verify_agent_caller(caller_identity)?;
        if authenticated_canonical_request.is_empty() || self.intents.len() >= self.maximum_records
        {
            return Err(KernelAgentAuthorityErrorV2::LimitExceeded);
        }
        let step_commitment = request.step().authority_commitment(&self.handle_key);
        let step = self
            .plan_steps
            .iter()
            .find(|record| record.commitment == step_commitment)
            .ok_or(KernelAgentAuthorityErrorV2::InvalidReference)?;
        let tool_commitment = request.tool().authority_commitment(&self.handle_key);
        let tool = self
            .tools
            .iter()
            .find(|record| record.commitment == tool_commitment)
            .ok_or(KernelAgentAuthorityErrorV2::InvalidReference)?;
        if tool.run != step.run || tool.descriptor_digest != step.descriptor_digest {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        if request.arguments().len() != step.arguments.len() {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        for (actual, expected) in request.arguments().iter().zip(&step.arguments) {
            if actual.name().as_str() != expected.name.as_str() || actual.value() != expected.value
            {
                return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
            }
        }
        let policy = self
            .policy
            .as_ref()
            .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?;
        let active = policy
            .active_tools
            .resolve(step.descriptor_digest, step.role, now)
            .ok_or(KernelAgentAuthorityErrorV2::InvalidReference)?;
        let unsigned = active.descriptor().unsigned();
        let slot_count = u16::try_from(step.arguments.len())
            .map_err(|_| KernelAgentAuthorityErrorV2::LimitExceeded)?;
        if slot_count == 0 {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        if active_state_manifest_digest
            != values
                .resolve_g4_value(step.run, step.arguments[0].value, now)
                .map_err(map_value_error)?
                .active_state_manifest_digest()
        {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        let relations =
            VerifiedResolvedRelationSetV2::from_verified_plan_envelope(slot_count, Vec::new())
                .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let mut resolved_values = Vec::new();
        resolved_values
            .try_reserve_exact(step.arguments.len())
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        for argument in &step.arguments {
            resolved_values.push(
                values
                    .resolve_g4_value(step.run, argument.value, now)
                    .map_err(map_value_error)?,
            );
        }
        let mut slots = Vec::new();
        let mut plan_arguments = Vec::new();
        slots
            .try_reserve_exact(step.arguments.len())
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        plan_arguments
            .try_reserve_exact(step.arguments.len())
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        for (ordinal, (argument, resolved)) in
            step.arguments.iter().zip(&resolved_values).enumerate()
        {
            let slot = VerifiedInternalSlotMaterialV2::from_resolved_envelope(
                self.config.installation_id,
                active_state_manifest_digest,
                step.durable_run_id,
                u16::try_from(ordinal).map_err(|_| KernelAgentAuthorityErrorV2::LimitExceeded)?,
                argument.slot.kind(),
                map_cardinality(argument.slot.cardinality()),
                map_confidentiality(argument.slot.confidentiality()),
                Vec::new(),
                resolved.value_internal_id(),
                resolved.value_digest(),
                provenance_digest_v2(resolved.provenance())
                    .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?,
                &relations,
            )
            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
            plan_arguments.push(
                VerifiedPlanArgumentV2::from_verified_plan(argument.name.clone(), &slot)
                    .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?,
            );
            slots.push(slot);
        }
        let stored_values = slots
            .iter()
            .zip(&resolved_values)
            .map(|(slot, resolved)| {
                StoredValueRecordV2::from_store(slot, resolved.value(), resolved.provenance())
                    .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let stored = StoredBindingResolverV2::resolve(
            step.durable_run_id,
            active_state_manifest_digest,
            unsigned.executor_identity(),
            &plan_arguments,
            &stored_values,
            &[],
            &[],
        )
        .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let destination_projection_digest = compiled_projection_digest(
            PROJECTION_DESTINATION_DOMAIN,
            unsigned.destination_projection().get(),
        );
        let display_projection_digest = compiled_projection_digest(
            PROJECTION_DISPLAY_DOMAIN,
            unsigned.display_projection().get(),
        );
        if unsigned.destination_projection_digest() != destination_projection_digest
            || unsigned.display_projection_digest() != display_projection_digest
        {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        let destination = projected_destination(&stored)?;
        let display = projected_display(&stored)?;
        let dispatch_plaintext =
            minicbor::to_vec(&destination).map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        let projections =
            VerifiedProjectionOutputsV2::from_verified_projection(active, &destination, &display)
                .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let material = VerifiedActionIntentMaterialV2::from_verified_g4(
            step.plan_revision_digest,
            step.internal_step_id,
            active,
            &stored,
            projections,
        )
        .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let policy_binding = material.binding().clone();
        let semantic_binding = protocol_semantic_binding(&policy_binding)?;
        let action = self
            .policy
            .as_mut()
            .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?
            .durable
            .create_or_replay_verified_intent(
                request_id,
                authenticated_canonical_request,
                self.config.installation_id,
                active_state_manifest_digest,
                step.durable_run_id,
                step.durable_task_id,
                material,
            )
            .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?;
        if let Some(existing) = self
            .intents
            .iter()
            .find(|record| record.action_intent_id == action.action_intent_id())
        {
            return Ok(ProposeToolCallResponseV2::new(
                existing.intent,
                intent_current_state(existing, &self.execution_tickets)?,
            ));
        }
        let intent = mint_handle(ActionIntentHandleV2::from_authority_entropy)?;
        let pending = mint_handle(PendingToolCallHandleV2::from_authority_entropy)?;
        let intent_commitment = intent.authority_commitment(&self.handle_key);
        let pending_commitment = pending.authority_commitment(&self.handle_key);
        if self.intents.iter().any(|record| {
            record.intent_commitment == intent_commitment
                || record.pending_commitment == pending_commitment
        }) {
            return Err(KernelAgentAuthorityErrorV2::Unavailable);
        }
        self.intents
            .try_reserve(1)
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        self.intents.push(IntentRecordV2 {
            intent,
            pending,
            intent_commitment,
            pending_commitment,
            action_intent_id: action.action_intent_id(),
            run: step.run,
            durable_run_id: step.durable_run_id,
            durable_task_id: step.durable_task_id,
            principal: step.principal,
            role: step.role,
            descriptor_digest: step.descriptor_digest,
            plan_revision_digest: step.plan_revision_digest,
            internal_step_id: step.internal_step_id,
            policy_binding,
            semantic_binding,
            dispatch_plaintext,
            arguments: step.arguments.clone(),
            state: IntentRecordStateV2::Proposed,
            decision_trace: None,
            ticket_commitment: None,
            approval_commitment: None,
            approval_settlement: None,
        });
        Ok(ProposeToolCallResponseV2::new(
            intent,
            ActionIntentCurrentStateV2::Proposed { pending },
        ))
    }

    pub(crate) fn evaluate_tool_call(
        &mut self,
        request: EvaluateToolCallRequestV2,
        values: &KernelValueOwnerV2,
        caller_identity: ServiceIdentityV2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        now: UnixMillisV2,
    ) -> Result<EvaluateToolCallResponseV2, KernelAgentAuthorityErrorV2> {
        self.verify_agent_caller(caller_identity)?;
        let pending_commitment = request.pending().authority_commitment(&self.handle_key);
        let index = self
            .intents
            .iter()
            .position(|record| record.pending_commitment == pending_commitment)
            .ok_or(KernelAgentAuthorityErrorV2::InvalidReference)?;
        match self.intents[index].state {
            IntentRecordStateV2::Denied => {
                return Ok(EvaluateToolCallResponseV2::Denied {
                    code: PublicStableCodeV2::PolicyDenied,
                    trace: protocol_trace(
                        self.intents[index]
                            .decision_trace
                            .ok_or(KernelAgentAuthorityErrorV2::StateConflict)?,
                    )?,
                });
            }
            IntentRecordStateV2::AwaitingApproval => {
                let approval_commitment = self.intents[index]
                    .approval_commitment
                    .ok_or(KernelAgentAuthorityErrorV2::StateConflict)?;
                let approval = self
                    .tool_approvals
                    .iter()
                    .find(|record| record.commitment == approval_commitment)
                    .ok_or(KernelAgentAuthorityErrorV2::StateConflict)?;
                return Ok(EvaluateToolCallResponseV2::NeedsApproval {
                    approval: approval.approval,
                    envelope: approval.envelope.clone(),
                    display_authentication: approval.display_authentication.clone(),
                    trace: protocol_trace(
                        self.intents[index]
                            .decision_trace
                            .ok_or(KernelAgentAuthorityErrorV2::StateConflict)?,
                    )?,
                });
            }
            IntentRecordStateV2::Authorized => {
                let ticket_commitment = self.intents[index]
                    .ticket_commitment
                    .ok_or(KernelAgentAuthorityErrorV2::StateConflict)?;
                let ticket = self
                    .execution_tickets
                    .iter()
                    .find(|record| record.commitment == ticket_commitment)
                    .ok_or(KernelAgentAuthorityErrorV2::StateConflict)?;
                return Ok(EvaluateToolCallResponseV2::Allowed {
                    ticket: ticket.ticket,
                    trace: protocol_trace(
                        self.intents[index]
                            .decision_trace
                            .ok_or(KernelAgentAuthorityErrorV2::StateConflict)?,
                    )?,
                });
            }
            IntentRecordStateV2::Proposed | IntentRecordStateV2::Evaluating => {}
        }
        let intent = self.intents[index].clone();
        if intent.arguments.is_empty() {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        let policy = self
            .policy
            .as_mut()
            .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?;
        let active = policy
            .active_tools
            .resolve(intent.descriptor_digest, intent.role, now)
            .ok_or(KernelAgentAuthorityErrorV2::InvalidReference)?;
        let slot_count = u16::try_from(intent.arguments.len())
            .map_err(|_| KernelAgentAuthorityErrorV2::LimitExceeded)?;
        let relations =
            VerifiedResolvedRelationSetV2::from_verified_plan_envelope(slot_count, Vec::new())
                .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let mut resolved_values = Vec::new();
        resolved_values
            .try_reserve_exact(intent.arguments.len())
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        for argument in &intent.arguments {
            resolved_values.push(
                values
                    .resolve_g4_value(intent.run, argument.value, now)
                    .map_err(map_value_error)?,
            );
        }
        let mut slots = Vec::new();
        let mut plan_arguments = Vec::new();
        for (ordinal, (argument, resolved)) in
            intent.arguments.iter().zip(&resolved_values).enumerate()
        {
            let slot = VerifiedInternalSlotMaterialV2::from_resolved_envelope(
                self.config.installation_id,
                active_state_manifest_digest,
                intent.durable_run_id,
                u16::try_from(ordinal).map_err(|_| KernelAgentAuthorityErrorV2::LimitExceeded)?,
                argument.slot.kind(),
                map_cardinality(argument.slot.cardinality()),
                map_confidentiality(argument.slot.confidentiality()),
                Vec::new(),
                resolved.value_internal_id(),
                resolved.value_digest(),
                provenance_digest_v2(resolved.provenance())
                    .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?,
                &relations,
            )
            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
            plan_arguments.push(
                VerifiedPlanArgumentV2::from_verified_plan(argument.name.clone(), &slot)
                    .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?,
            );
            slots.push(slot);
        }
        let stored_values = slots
            .iter()
            .zip(&resolved_values)
            .map(|(slot, resolved)| {
                StoredValueRecordV2::from_store(slot, resolved.value(), resolved.provenance())
                    .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let stored = StoredBindingResolverV2::resolve(
            intent.durable_run_id,
            active_state_manifest_digest,
            active.descriptor().unsigned().executor_identity(),
            &plan_arguments,
            &stored_values,
            &[],
            &[],
        )
        .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let ontology_arguments = stored
            .arguments()
            .iter()
            .map(|argument| (argument.argument_name().clone(), argument.value()))
            .collect();
        let ontology = VerifiedOntologyEvaluationV2::evaluate(
            &policy.ontology,
            ontology_arguments,
            Vec::new(),
            Vec::new(),
            intent.role,
            active.descriptor().unsigned().tool_class(),
            active.descriptor().unsigned().attempt_kind(),
            intent.principal,
            intent.durable_task_id,
        )
        .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let resolution = policy
            .durable
            .evaluate_verified_g5(
                &policy.validators,
                intent.action_intent_id,
                &stored,
                ontology,
                policy.disposition,
            )
            .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?;
        let trace_digest = resolution.trace().decision_record_digest();
        let trace = protocol_trace(trace_digest)?;
        self.intents[index].decision_trace = Some(trace_digest);
        match resolution.branch() {
            G5DecisionBranchV2::Deny => {
                self.intents[index].state = IntentRecordStateV2::Denied;
                Ok(EvaluateToolCallResponseV2::Denied {
                    code: PublicStableCodeV2::PolicyDenied,
                    trace,
                })
            }
            G5DecisionBranchV2::Permit => {
                let ticket = mint_handle(ExecutionTicketHandleV2::from_authority_entropy)?;
                let commitment = ticket.authority_commitment(&self.handle_key);
                let semantic_binding_digest =
                    savana_policy_core::v2::tool_execution_semantic_binding_digest_v2(
                        &intent.policy_binding,
                    )
                    .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
                self.execution_tickets
                    .try_reserve(1)
                    .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
                self.execution_tickets.push(ExecutionTicketRecordV2 {
                    ticket,
                    commitment,
                    action_intent_id: intent.action_intent_id,
                    semantic_binding_digest,
                });
                self.intents[index].ticket_commitment = Some(commitment);
                self.intents[index].state = IntentRecordStateV2::Authorized;
                Ok(EvaluateToolCallResponseV2::Allowed { ticket, trace })
            }
            G5DecisionBranchV2::RequireApproval => {
                if self.tool_approvals.len() >= self.maximum_records {
                    return Err(KernelAgentAuthorityErrorV2::LimitExceeded);
                }
                let expires_at = checked_deadline(now, TOOL_APPROVAL_TTL_MS)?;
                let envelope_nonce = Nonce32V2::new(random_bytes()?);
                let challenge = Nonce32V2::new(random_bytes()?);
                let binding = ApprovalBindingV2::ToolExecution {
                    action_intent_id: intent.action_intent_id,
                    binding: intent.semantic_binding,
                };
                let unsigned = UnsignedApprovalEnvelopeV2::new(
                    self.config.installation_id,
                    active_state_manifest_digest,
                    deployment_generation,
                    ApprovalPurposeV2::ToolExecution,
                    envelope_nonce,
                    challenge,
                    binding,
                    intent.principal,
                    intent.semantic_binding.display_projection_digest(),
                    intent.semantic_binding.display_digest(),
                    policy.approval.approvald_identity,
                    now,
                    expires_at,
                )
                .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
                let envelope =
                    SignedApprovalEnvelopeV2::sign(unsigned, &self.config.envelope_signing_key)
                        .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
                let envelope_digest = envelope
                    .envelope_digest()
                    .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
                let display_unsigned = UnsignedUiAuthenticationEnvelopeV2::new(
                    self.config.installation_id,
                    active_state_manifest_digest,
                    deployment_generation,
                    UiAuthenticationPurposeV2::ApprovalDisplay,
                    UiAuthenticationBindingV2::ApprovalDisplay {
                        durable_task_id: intent.durable_task_id,
                        approval_envelope_digest: envelope_digest,
                        approval_purpose: ApprovalPurposeV2::ToolExecution,
                        display_digest: intent.semantic_binding.display_digest(),
                    },
                    Some(intent.principal),
                    FixedOriginV2::Approval8766,
                    FixedOriginV2::Approval8766,
                    Nonce32V2::new(random_bytes()?),
                    now,
                    expires_at,
                )
                .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
                let display_authentication = SignedUiAuthenticationEnvelopeV2::sign(
                    display_unsigned,
                    &self.config.envelope_signing_key,
                )
                .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
                let approval = mint_handle(ToolKernelApprovalHandleV2::from_authority_entropy)?;
                let commitment = approval.authority_commitment(&self.handle_key);
                let binding_digest = savana_policy_core::v2::tool_approval_binding_digest_v2(
                    intent.action_intent_id,
                    savana_policy_core::v2::tool_execution_semantic_binding_digest_v2(
                        &intent.policy_binding,
                    )
                    .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?,
                    active_state_manifest_digest,
                )
                .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
                self.tool_approvals
                    .try_reserve(1)
                    .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
                self.tool_approvals.push(ToolApprovalRecordV2 {
                    approval,
                    commitment,
                    pending_commitment,
                    action_intent_id: intent.action_intent_id,
                    envelope: envelope.clone(),
                    display_authentication: display_authentication.clone(),
                    envelope_digest,
                    binding_digest,
                    challenge,
                    expected_principal: intent.principal,
                    active_state_manifest_digest,
                    expires_at,
                    consumed: false,
                });
                self.intents[index].approval_commitment = Some(commitment);
                self.intents[index].state = IntentRecordStateV2::AwaitingApproval;
                Ok(EvaluateToolCallResponseV2::NeedsApproval {
                    approval,
                    envelope,
                    display_authentication,
                    trace,
                })
            }
        }
    }

    pub(crate) fn authorize_tool_call(
        &mut self,
        request: &savana_kernel_protocol::v2::AuthorizeToolCallRequestV2,
        caller_identity: ServiceIdentityV2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        now: UnixMillisV2,
    ) -> Result<savana_kernel_protocol::v2::AuthorizeToolCallResponseV2, KernelAgentAuthorityErrorV2>
    {
        self.verify_agent_caller(caller_identity)?;
        let pending_commitment = request.pending().authority_commitment(&self.handle_key);
        let approval_commitment = request.approval().authority_commitment(&self.handle_key);
        let intent_index = self
            .intents
            .iter()
            .position(|record| record.pending_commitment == pending_commitment)
            .ok_or(KernelAgentAuthorityErrorV2::InvalidReference)?;
        let approval_index = self
            .tool_approvals
            .iter()
            .position(|record| {
                record.commitment == approval_commitment
                    && record.pending_commitment == pending_commitment
            })
            .ok_or(KernelAgentAuthorityErrorV2::InvalidReference)?;
        if self.tool_approvals[approval_index].consumed {
            if self.intents[intent_index].state == IntentRecordStateV2::Authorized {
                let ticket_commitment = self.intents[intent_index]
                    .ticket_commitment
                    .ok_or(KernelAgentAuthorityErrorV2::StateConflict)?;
                let ticket = self
                    .execution_tickets
                    .iter()
                    .find(|record| record.commitment == ticket_commitment)
                    .ok_or(KernelAgentAuthorityErrorV2::StateConflict)?;
                return Ok(AuthorizeToolCallResponseV2::new(ticket.ticket));
            }
            return Err(KernelAgentAuthorityErrorV2::AlreadyConsumed);
        }
        let approval_action_intent_id = self.tool_approvals[approval_index].action_intent_id;
        let approval_binding_digest = self.tool_approvals[approval_index].binding_digest;
        let approval_envelope_digest = self.tool_approvals[approval_index].envelope_digest;
        let approval_expected_principal = self.tool_approvals[approval_index].expected_principal;
        let approval_challenge = self.tool_approvals[approval_index].challenge;
        let approval_expires_at = self.tool_approvals[approval_index].expires_at;
        if approval_action_intent_id != self.intents[intent_index].action_intent_id
            || self.tool_approvals[approval_index].active_state_manifest_digest
                != active_state_manifest_digest
        {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        if now.get() >= approval_expires_at.get() {
            return Err(KernelAgentAuthorityErrorV2::Expired);
        }
        let policy = self
            .policy
            .as_ref()
            .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?;
        let verified = request
            .receipt()
            .verify_tool_execution(
                policy.approval.settlement_key_id,
                policy.approval.settlement_public_key,
                self.config.installation_id,
                active_state_manifest_digest,
                deployment_generation,
                approval_envelope_digest,
                approval_expected_principal,
                approval_challenge,
                now,
            )
            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        self.tool_approvals[approval_index].consumed = true;
        if verified.decision() != ApprovalDecisionV2::Approve {
            self.intents[intent_index].state = IntentRecordStateV2::Denied;
            return Err(KernelAgentAuthorityErrorV2::StateConflict);
        }
        let settlement =
            savana_policy_core::v2::VerifiedToolApprovalSettlementV2::from_consumed_exact_settlement(
                verified.settlement_digest(),
                approval_action_intent_id,
                approval_binding_digest,
                active_state_manifest_digest,
            )
            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let semantic_binding_digest =
            savana_policy_core::v2::tool_execution_semantic_binding_digest_v2(
                &self.intents[intent_index].policy_binding,
            )
            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let ticket = mint_handle(ExecutionTicketHandleV2::from_authority_entropy)?;
        let commitment = ticket.authority_commitment(&self.handle_key);
        self.execution_tickets
            .try_reserve(1)
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        self.execution_tickets.push(ExecutionTicketRecordV2 {
            ticket,
            commitment,
            action_intent_id: approval_action_intent_id,
            semantic_binding_digest,
        });
        self.intents[intent_index].approval_settlement = Some(settlement);
        self.intents[intent_index].ticket_commitment = Some(commitment);
        self.intents[intent_index].state = IntentRecordStateV2::Authorized;
        Ok(AuthorizeToolCallResponseV2::new(ticket))
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn dispatch_execution(
        &mut self,
        request_id: savana_kernel_protocol::v2::RequestIdV2,
        request: savana_kernel_protocol::v2::DispatchExecutionRequestV2,
        caller_identity: ServiceIdentityV2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        effect_fence_epoch: u64,
        now: UnixMillisV2,
    ) -> Result<savana_kernel_protocol::v2::DispatchExecutionResponseV2, KernelAgentAuthorityErrorV2>
    {
        self.verify_agent_caller(caller_identity)?;
        let ticket_commitment = request.ticket().authority_commitment(&self.handle_key);
        if let Some(existing) = self
            .executions
            .iter()
            .find(|record| record.ticket_commitment == ticket_commitment)
        {
            return Ok(DispatchExecutionResponseV2::new(
                existing.execution,
                accepted_state(existing.status),
            ));
        }
        if self.executions.len() >= self.maximum_records {
            return Err(KernelAgentAuthorityErrorV2::LimitExceeded);
        }
        let ticket = self
            .execution_tickets
            .iter()
            .find(|record| record.commitment == ticket_commitment)
            .ok_or(KernelAgentAuthorityErrorV2::InvalidReference)?;
        let intent_index = self
            .intents
            .iter()
            .position(|record| record.action_intent_id == ticket.action_intent_id)
            .ok_or(KernelAgentAuthorityErrorV2::InvalidReference)?;
        let intent = self.intents[intent_index].clone();
        if intent.state != IntentRecordStateV2::Authorized
            || intent.ticket_commitment != Some(ticket_commitment)
            || savana_policy_core::v2::tool_execution_semantic_binding_digest_v2(
                &intent.policy_binding,
            )
            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?
                != ticket.semantic_binding_digest
        {
            return Err(KernelAgentAuthorityErrorV2::StateConflict);
        }
        let policy = self
            .policy
            .as_mut()
            .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?;
        let g7 = policy
            .g7
            .as_ref()
            .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?;
        let active = policy
            .active_tools
            .resolve(intent.descriptor_digest, intent.role, now)
            .ok_or(KernelAgentAuthorityErrorV2::InvalidReference)?;
        if active.descriptor().unsigned().executor_identity() != g7.executor_identity {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        let expires_at = checked_deadline(now, 30_000)?;
        let quota_subject =
            DispatchQuotaSubjectV2::tool_attempt(intent.policy_binding.attempt_kind());
        let quota = VerifiedQuotaLimitV2::from_verified_policy(
            g7.quota_limit,
            g7.quota_policy_digest,
            quota_subject,
        )
        .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let effect_lease = VerifiedEffectGateLeaseV2::from_verified_ledger_projection(
            g7.effect_ledger_projection,
            self.config.installation_id,
            active_state_manifest_digest,
            deployment_generation,
            effect_fence_epoch,
            savana_kernel_protocol::v2::ExecutorIdentityV2::new(*g7.executor_identity.as_bytes()),
            g7.executor_key_id,
            g7.executor_connector_registry_digest,
            expires_at,
        )
        .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let resolved_ticket = ResolvedExecutionTicketV2::from_resolved_kernel_ticket(
            ticket.commitment,
            intent.action_intent_id,
            ticket.semantic_binding_digest,
        )
        .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let sealed_payload_digest = domain_digest(
            b"SAVANA_PRESEALED_EXECUTOR_PAYLOAD_V2\0",
            &[&intent.dispatch_plaintext],
        );
        let prepared = policy
            .durable
            .prepare_verified_tool_dispatch(
                intent.action_intent_id,
                quota,
                intent.approval_settlement,
                resolved_ticket,
                effect_lease,
                sealed_payload_digest,
            )
            .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?;
        let protocol_core = protocol_dispatch_core(&prepared)?;
        if protocol_core
            .semantic_digest()
            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?
            != prepared.preparation().dispatch_core_digest()
            || protocol_core.dispatch_subject_digest()
                != prepared.preparation().dispatch_subject_digest()
        {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        let (hpke_enc, hpke_ciphertext) = seal_execution_payload(
            &intent.dispatch_plaintext,
            g7.executor_seal_public_key,
            protocol_core
                .semantic_digest()
                .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?,
        )?;
        let envelope = SignedSealedExecutionEnvelopeV2::sign(
            SealedExecutionEnvelopePayloadV2::new(
                protocol_core,
                FixedBytes32V2::new(hpke_enc),
                BoundedCiphertextV2::new(hpke_ciphertext)
                    .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?,
            )
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?,
            &g7.envelope_signing_key,
        )
        .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        let deadline = checked_deadline(now, 5_000)?;
        let response = g7
            .executor
            .dispatch(request_id, deadline, DispatchRequestV2::new(envelope))
            .map_err(map_executor_client_error)?;
        let status = public_executor_status(response.status());
        let execution = mint_handle(ExecutionHandleV2::from_authority_entropy)?;
        let commitment = execution.authority_commitment(&self.handle_key);
        self.executions
            .try_reserve(1)
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        self.executions.push(ExecutionRecordV2 {
            execution,
            commitment,
            ticket_commitment,
            action_intent_id: intent.action_intent_id,
            execution_nonce: prepared.preparation().execution_nonce(),
            dispatch_core_digest: prepared.preparation().dispatch_core_digest(),
            dispatch_subject_digest: prepared.preparation().dispatch_subject_digest(),
            status,
            completion: None,
        });
        Ok(DispatchExecutionResponseV2::new(
            execution,
            accepted_state(status),
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn execution_status(
        &mut self,
        request_id: savana_kernel_protocol::v2::RequestIdV2,
        request: GetExecutionStatusRequestV2,
        vault: &mut dyn KernelIngressCommitSinkV2,
        caller_identity: ServiceIdentityV2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        effect_fence_epoch: u64,
        now: UnixMillisV2,
    ) -> Result<GetExecutionStatusResponseV2, KernelAgentAuthorityErrorV2> {
        self.verify_agent_caller(caller_identity)?;
        let index = match request.target() {
            ExecutionStatusTargetV2::Intent(intent) => {
                let commitment = intent.authority_commitment(&self.handle_key);
                let action_intent_id = self
                    .intents
                    .iter()
                    .find(|record| record.intent_commitment == commitment)
                    .map(|record| record.action_intent_id)
                    .ok_or(KernelAgentAuthorityErrorV2::InvalidReference)?;
                self.executions
                    .iter()
                    .position(|record| record.action_intent_id == action_intent_id)
            }
            ExecutionStatusTargetV2::Ticket(ticket) => {
                let commitment = ticket.authority_commitment(&self.handle_key);
                self.executions
                    .iter()
                    .position(|record| record.ticket_commitment == commitment)
            }
            ExecutionStatusTargetV2::Execution(execution) => {
                let commitment = execution.authority_commitment(&self.handle_key);
                self.executions
                    .iter()
                    .position(|record| record.commitment == commitment)
            }
        }
        .ok_or(KernelAgentAuthorityErrorV2::InvalidReference)?;
        if matches!(
            self.executions[index].status,
            PublicExecutionStatusV2::Succeeded { .. }
                | PublicExecutionStatusV2::EffectSucceededOutputQuarantined { .. }
                | PublicExecutionStatusV2::FailedNoEffect { .. }
                | PublicExecutionStatusV2::Indeterminate
        ) {
            return Ok(GetExecutionStatusResponseV2::new(
                self.executions[index].status,
            ));
        }
        let (nonce, core, subject) = {
            let record = &self.executions[index];
            (
                record.execution_nonce,
                record.dispatch_core_digest,
                record.dispatch_subject_digest,
            )
        };
        let response = self
            .policy
            .as_ref()
            .and_then(|policy| policy.g7.as_ref())
            .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?
            .executor
            .query(
                request_id,
                checked_deadline(now, 5_000)?,
                QueryByExecutionNonceRequestV2::new(nonce, core, subject)
                    .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?,
            )
            .map_err(map_executor_client_error)?;
        let status = match response.status() {
            ExecutorStatusV2::EffectStarted {
                effect_started_receipt,
                ..
            } => {
                let (key_id, public_key) = self.executor_receipt_identity()?;
                self.policy
                    .as_mut()
                    .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?
                    .durable
                    .reconcile_typed_effect_started_tool_dispatch(
                        effect_started_receipt,
                        key_id,
                        public_key,
                        now,
                    )
                    .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?;
                PublicExecutionStatusV2::Dispatching
            }
            ExecutorStatusV2::CompletionAvailable { completion, .. } => self
                .commit_tool_completion(
                    request_id,
                    index,
                    *completion,
                    vault,
                    active_state_manifest_digest,
                    deployment_generation,
                    effect_fence_epoch,
                    now,
                )?,
            ExecutorStatusV2::FailedNoEffect { .. } => {
                let evidence = domain_digest(
                    b"SAVANA_AUTHENTICATED_FAILED_NO_EFFECT_STATUS_V2\0",
                    &[nonce.as_bytes(), core.as_bytes(), subject.as_bytes()],
                );
                self.policy
                    .as_mut()
                    .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?
                    .durable
                    .reconcile_authenticated_failed_no_effect(nonce, core, subject, evidence)
                    .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?;
                PublicExecutionStatusV2::FailedNoEffect {
                    class: PublicFailureClassV2::Connector,
                }
            }
            ExecutorStatusV2::Indeterminate { .. } => {
                let evidence = domain_digest(
                    b"SAVANA_AUTHENTICATED_INDETERMINATE_STATUS_V2\0",
                    &[nonce.as_bytes(), core.as_bytes(), subject.as_bytes()],
                );
                self.policy
                    .as_mut()
                    .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?
                    .durable
                    .reconcile_authenticated_indeterminate(nonce, core, subject, evidence)
                    .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?;
                PublicExecutionStatusV2::Indeterminate
            }
            other => public_executor_status(other),
        };
        self.executions[index].status = status;
        Ok(GetExecutionStatusResponseV2::new(status))
    }

    fn executor_receipt_identity(
        &self,
    ) -> Result<(Ed25519KeyIdV2, [u8; 32]), KernelAgentAuthorityErrorV2> {
        let g7 = self
            .policy
            .as_ref()
            .and_then(|policy| policy.g7.as_ref())
            .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?;
        Ok((g7.executor_receipt_key_id, g7.executor_receipt_public_key))
    }

    #[allow(clippy::too_many_arguments)]
    fn commit_tool_completion(
        &mut self,
        request_id: savana_kernel_protocol::v2::RequestIdV2,
        index: usize,
        completion: savana_kernel_protocol::v2::ExecutorCompletionDescriptorV2,
        vault: &mut dyn KernelIngressCommitSinkV2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        effect_fence_epoch: u64,
        now: UnixMillisV2,
    ) -> Result<PublicExecutionStatusV2, KernelAgentAuthorityErrorV2> {
        let (nonce, core, subject, action_intent_id) = {
            let record = &self.executions[index];
            (
                record.execution_nonce,
                record.dispatch_core_digest,
                record.dispatch_subject_digest,
                record.action_intent_id,
            )
        };
        let response = self
            .policy
            .as_ref()
            .and_then(|policy| policy.g7.as_ref())
            .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?
            .executor
            .fetch_completion(
                request_id,
                checked_deadline(now, 5_000)?,
                savana_kernel_protocol::v2::FetchCompletionRequestV2::new(
                    nonce, core, subject, completion,
                )
                .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?,
            )
            .map_err(map_executor_client_error)?;
        if response.execution_nonce() != nonce
            || response.dispatch_core_digest() != core
            || response.dispatch_subject_digest() != subject
            || response.completion() != completion
        {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        let (receipt_key_id, receipt_public_key) = self.executor_receipt_identity()?;
        response
            .effect_started_receipt()
            .verify(receipt_key_id, receipt_public_key)
            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let result = match response.payload() {
            savana_kernel_protocol::v2::ExecutorCompletionPayloadV2::ToolResult { result } => {
                if completion.tool_result_digest()
                    != Some(domain_digest(
                        b"SAVANA_CONNECTOR_RESULT_DIGEST_V2\0",
                        &[result.as_bytes()],
                    ))
                {
                    return Ok(PublicExecutionStatusV2::EffectSucceededOutputQuarantined {
                        class: PublicFailureClassV2::ResultGate,
                    });
                }
                result.as_bytes().to_vec()
            }
            savana_kernel_protocol::v2::ExecutorCompletionPayloadV2::FinalReleaseReceipt {
                ..
            } => {
                return Ok(PublicExecutionStatusV2::EffectSucceededOutputQuarantined {
                    class: PublicFailureClassV2::ResultGate,
                })
            }
        };
        let intent = self
            .intents
            .iter()
            .find(|intent| intent.action_intent_id == action_intent_id)
            .ok_or(KernelAgentAuthorityErrorV2::StateConflict)?;
        let session = self
            .sessions
            .iter()
            .find(|session| session.run == intent.run)
            .ok_or(KernelAgentAuthorityErrorV2::StateConflict)?;
        if session.active_state_manifest_digest != active_state_manifest_digest
            || deployment_generation == 0
            || effect_fence_epoch == 0
        {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        let value = KernelValueV2::bytes(result.clone())
            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let provenance_context =
            savana_policy_core::v2::ProvenanceContextV2::from_authenticated_runtime(
                session.producer_identity,
                session.durable_run_id,
                active_state_manifest_digest,
                now,
                session.expires_at,
            )
            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let action_intent_record_digest = domain_digest(
            b"SAVANA_ACTION_INTENT_RESULT_BINDING_V2\0",
            &[
                action_intent_id.as_bytes(),
                intent.intent_commitment.as_bytes(),
            ],
        );
        let provenance = ProvenanceRecordV2::from_verified_executor_tool_result(
            &value,
            provenance_context,
            action_intent_id,
            domain_digest(b"SAVANA_EXECUTION_NONCE_DIGEST_V2\0", &[nonce.as_bytes()]),
            action_intent_record_digest,
            intent.descriptor_digest,
            response.effect_started_receipt_digest(),
            session.policy_allowed_effects,
        )
        .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let commit_digest = domain_digest(
            b"SAVANA_TOOL_RESULT_GATE_COMMIT_V2\0",
            &[
                core.as_bytes(),
                response.effect_started_receipt_digest().as_bytes(),
                completion
                    .tool_result_digest()
                    .ok_or(KernelAgentAuthorityErrorV2::BindingMismatch)?
                    .as_bytes(),
            ],
        );
        let document = vault
            .commit_tool_result(
                session.durable_task_id,
                session.durable_run_id,
                session.principal,
                provenance,
                commit_digest,
                result,
                session.expires_at,
                now,
            )
            .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?;
        self.policy
            .as_mut()
            .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?
            .durable
            .reconcile_authenticated_completion(
                response.effect_started_receipt(),
                receipt_key_id,
                receipt_public_key,
                commit_digest,
                now,
            )
            .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?;
        self.policy
            .as_ref()
            .and_then(|policy| policy.g7.as_ref())
            .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?
            .executor
            .acknowledge(
                request_id,
                checked_deadline(now, 5_000)?,
                savana_kernel_protocol::v2::AcknowledgeCommittedCompletionRequestV2::new(
                    nonce,
                    core,
                    subject,
                    completion,
                    commit_digest,
                )
                .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?,
            )
            .map_err(map_executor_client_error)?;
        self.executions[index].completion = Some(completion);
        Ok(PublicExecutionStatusV2::Succeeded {
            completion: PublicDispatchCompletionV2::ToolExecution { document },
        })
    }

    pub(crate) fn authorize_agent_view(
        &self,
        request: &ReadAgentViewRequestV2,
        caller_identity: ServiceIdentityV2,
    ) -> Result<(), KernelAgentAuthorityErrorV2> {
        self.verify_agent_caller(caller_identity)?;
        if request.cursor().is_some() {
            return Err(KernelAgentAuthorityErrorV2::InvalidReference);
        }
        if !self
            .sessions
            .iter()
            .any(|session| session.initial_document == request.document())
        {
            return Err(KernelAgentAuthorityErrorV2::InvalidReference);
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare_release(
        &mut self,
        request: &PrepareReleaseRequestV2,
        values: &KernelValueOwnerV2,
        vault: &mut dyn KernelIngressCommitSinkV2,
        caller_identity: ServiceIdentityV2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        now: UnixMillisV2,
    ) -> Result<PrepareReleaseResponseV2, KernelAgentAuthorityErrorV2> {
        self.verify_agent_caller(caller_identity)?;
        if self.pending_releases.len() >= self.maximum_records {
            return Err(KernelAgentAuthorityErrorV2::LimitExceeded);
        }
        let session = self
            .sessions
            .iter()
            .find(|session| {
                session.initial_document == request.document()
                    && matches!(
                        session.status,
                        AgentSessionStatusV2::Ready | AgentSessionStatusV2::Running
                    )
            })
            .ok_or(KernelAgentAuthorityErrorV2::InvalidReference)?;
        if now.get() >= session.expires_at.get() {
            return Err(KernelAgentAuthorityErrorV2::Expired);
        }
        let policy = self
            .policy
            .as_ref()
            .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?;
        let g7 = policy
            .g7
            .as_ref()
            .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?;
        if request.executor() != g7.executor_identity {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        let mut evidence = request
            .evidence()
            .iter()
            .map(|handle| {
                let resolved = values
                    .resolve_g4_value(session.run, *handle, now)
                    .map_err(map_value_error)?;
                Ok(savana_policy_core::v2::EvidenceDigestEntryV2::new(
                    resolved.value_digest(),
                    provenance_digest_v2(resolved.provenance())
                        .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?,
                ))
            })
            .collect::<Result<Vec<_>, KernelAgentAuthorityErrorV2>>()?;
        evidence.sort_unstable_by_key(|entry| minicbor::to_vec(entry).unwrap_or_default());
        let evidence_digest = savana_policy_core::v2::evidence_digest_v2(&evidence)
            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let token_set_digest = savana_policy_core::v2::token_set_digest_v2(&[])
            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let plaintext = vault
            .read_release_payload(request.document(), session.durable_run_id, now)
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        let release_payload_digest = domain_digest(
            b"SAVANA_FINAL_RELEASE_PAYLOAD_V2\0",
            &[plaintext.as_slice()],
        );
        let destination_id = request.destination_projection().get().to_be_bytes();
        let destination_digest = domain_digest(
            b"SAVANA_FINAL_RELEASE_DESTINATION_V2\0",
            &[&destination_id, request.executor().as_bytes()],
        );
        let display_id = request.display_projection().get().to_be_bytes();
        let display_projection_digest = domain_digest(
            b"SAVANA_FINAL_RELEASE_DISPLAY_PROJECTION_V2\0",
            &[&display_id, &destination_id],
        );
        let display_digest = domain_digest(
            b"SAVANA_FINAL_RELEASE_DISPLAY_V2\0",
            &[
                release_payload_digest.as_bytes(),
                evidence_digest.as_bytes(),
                destination_digest.as_bytes(),
            ],
        );
        let release_quota_subject_digest = domain_digest(
            b"SAVANA_FINAL_RELEASE_QUOTA_SUBJECT_V2\0",
            &[
                session.durable_run_id.as_bytes(),
                destination_digest.as_bytes(),
            ],
        );
        let material = savana_vault::VaultReleaseMaterialV2::from_verified_projection(
            release_payload_digest,
            evidence_digest,
            token_set_digest,
            destination_digest,
            display_projection_digest,
            display_digest,
            Digest32V2::new(*request.executor().as_bytes()),
            release_quota_subject_digest,
        )
        .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let vault_pending = vault
            .prepare_release(request.document(), session.durable_run_id, material, now)
            .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?;
        let binding = vault_pending.binding();
        let binding_digest = vault_pending.binding_digest();
        let candidate_expiry = checked_deadline(now, TOOL_APPROVAL_TTL_MS)?;
        let expires_at = UnixMillisV2::new(candidate_expiry.get().min(session.expires_at.get()));
        let challenge = Nonce32V2::new(random_bytes()?);
        let unsigned = UnsignedApprovalEnvelopeV2::new(
            self.config.installation_id,
            active_state_manifest_digest,
            deployment_generation,
            ApprovalPurposeV2::FinalRelease,
            Nonce32V2::new(random_bytes()?),
            challenge,
            ApprovalBindingV2::FinalRelease { binding },
            session.principal,
            binding.display_projection_digest(),
            binding.display_digest(),
            policy.approval.approvald_identity,
            now,
            expires_at,
        )
        .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let envelope = SignedApprovalEnvelopeV2::sign(unsigned, &self.config.envelope_signing_key)
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        let envelope_digest = envelope
            .envelope_digest()
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        let display_unsigned = UnsignedUiAuthenticationEnvelopeV2::new(
            self.config.installation_id,
            active_state_manifest_digest,
            deployment_generation,
            UiAuthenticationPurposeV2::ApprovalDisplay,
            UiAuthenticationBindingV2::ApprovalDisplay {
                durable_task_id: session.durable_task_id,
                approval_envelope_digest: envelope_digest,
                approval_purpose: ApprovalPurposeV2::FinalRelease,
                display_digest: binding.display_digest(),
            },
            Some(session.principal),
            FixedOriginV2::Approval8766,
            FixedOriginV2::Approval8766,
            Nonce32V2::new(random_bytes()?),
            now,
            expires_at,
        )
        .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let display_authentication = SignedUiAuthenticationEnvelopeV2::sign(
            display_unsigned,
            &self.config.envelope_signing_key,
        )
        .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        let pending = mint_handle(PendingReleaseHandleV2::from_authority_entropy)?;
        let approval = mint_handle(ReleaseKernelApprovalHandleV2::from_authority_entropy)?;
        let pending_commitment = pending.authority_commitment(&self.handle_key);
        let approval_commitment = approval.authority_commitment(&self.handle_key);
        self.pending_releases.push(PendingReleaseRecordV2 {
            pending,
            pending_commitment,
            approval,
            approval_commitment,
            document: request.document(),
            run: session.run,
            durable_run_id: session.durable_run_id,
            durable_task_id: session.durable_task_id,
            principal: session.principal,
            vault_pending,
            envelope_digest,
            binding_digest,
            challenge,
            active_state_manifest_digest,
            expires_at,
            consumed: false,
            authorized: None,
            settlement: None,
            ticket_commitment: None,
        });
        Ok(PrepareReleaseResponseV2::new(
            pending,
            approval,
            envelope,
            display_authentication,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn authorize_release(
        &mut self,
        request: &savana_kernel_protocol::v2::AuthorizeReleaseRequestV2,
        vault: &mut dyn KernelIngressCommitSinkV2,
        caller_identity: ServiceIdentityV2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        now: UnixMillisV2,
    ) -> Result<savana_kernel_protocol::v2::AuthorizeReleaseResponseV2, KernelAgentAuthorityErrorV2>
    {
        self.verify_agent_caller(caller_identity)?;
        let pending_commitment = request.pending().authority_commitment(&self.handle_key);
        let approval_commitment = request.approval().authority_commitment(&self.handle_key);
        let index = self
            .pending_releases
            .iter()
            .position(|record| {
                record.pending_commitment == pending_commitment
                    && record.approval_commitment == approval_commitment
            })
            .ok_or(KernelAgentAuthorityErrorV2::InvalidReference)?;
        if self.pending_releases[index].consumed {
            if let Some(ticket_commitment) = self.pending_releases[index].ticket_commitment {
                let ticket = self
                    .release_tickets
                    .iter()
                    .find(|ticket| ticket.commitment == ticket_commitment)
                    .ok_or(KernelAgentAuthorityErrorV2::StateConflict)?;
                return Ok(savana_kernel_protocol::v2::AuthorizeReleaseResponseV2::new(
                    ticket.ticket,
                ));
            }
            return Err(KernelAgentAuthorityErrorV2::AlreadyConsumed);
        }
        let record = &self.pending_releases[index];
        if record.active_state_manifest_digest != active_state_manifest_digest
            || now.get() >= record.expires_at.get()
        {
            return Err(KernelAgentAuthorityErrorV2::Expired);
        }
        let approval = &self
            .policy
            .as_ref()
            .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?
            .approval;
        let verified = request
            .settlement()
            .verify_final_release(
                approval.settlement_key_id,
                approval.settlement_public_key,
                self.config.installation_id,
                active_state_manifest_digest,
                deployment_generation,
                record.envelope_digest,
                record.principal,
                record.challenge,
                now,
            )
            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        if verified.decision() != ApprovalDecisionV2::Approve {
            self.pending_releases[index].consumed = true;
            return Err(KernelAgentAuthorityErrorV2::StateConflict);
        }
        let vault_approval =
            savana_vault::VerifiedFinalReleaseApprovalV2::from_verified_protocol_settlement(
                verified,
                record.binding_digest,
                now,
            )
            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let authorized = vault
            .authorize_release(record.vault_pending, vault_approval, now)
            .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?;
        let binding = authorized.binding();
        let settlement =
            savana_policy_core::v2::VerifiedFinalReleaseSettlementV2::from_consumed_exact_settlement(
                verified.settlement_digest(),
                binding.durable_release_id(),
                record.binding_digest,
                active_state_manifest_digest,
            )
            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let ticket = mint_handle(ReleaseTicketHandleV2::from_authority_entropy)?;
        let commitment = ticket.authority_commitment(&self.handle_key);
        self.release_tickets.push(ReleaseTicketRecordV2 {
            ticket,
            commitment,
            pending_commitment,
            durable_release_id: binding.durable_release_id(),
            binding_digest: record.binding_digest,
        });
        self.pending_releases[index].consumed = true;
        self.pending_releases[index].authorized = Some(authorized);
        self.pending_releases[index].settlement = Some(settlement);
        self.pending_releases[index].ticket_commitment = Some(commitment);
        Ok(savana_kernel_protocol::v2::AuthorizeReleaseResponseV2::new(
            ticket,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn dispatch_release(
        &mut self,
        request_id: savana_kernel_protocol::v2::RequestIdV2,
        request: savana_kernel_protocol::v2::DispatchReleaseRequestV2,
        vault: &mut dyn KernelIngressCommitSinkV2,
        caller_identity: ServiceIdentityV2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        effect_fence_epoch: u64,
        now: UnixMillisV2,
    ) -> Result<savana_kernel_protocol::v2::DispatchReleaseResponseV2, KernelAgentAuthorityErrorV2>
    {
        self.verify_agent_caller(caller_identity)?;
        let ticket_commitment = request.ticket().authority_commitment(&self.handle_key);
        if let Some(existing) = self
            .releases
            .iter()
            .find(|release| release.ticket_commitment == ticket_commitment)
        {
            return Ok(savana_kernel_protocol::v2::DispatchReleaseResponseV2::new(
                existing.release,
                accepted_state(existing.status),
            ));
        }
        let ticket = self
            .release_tickets
            .iter()
            .find(|ticket| ticket.commitment == ticket_commitment)
            .ok_or(KernelAgentAuthorityErrorV2::InvalidReference)?;
        let pending_index = self
            .pending_releases
            .iter()
            .position(|record| record.pending_commitment == ticket.pending_commitment)
            .ok_or(KernelAgentAuthorityErrorV2::InvalidReference)?;
        let pending = &self.pending_releases[pending_index];
        let authorized = pending
            .authorized
            .ok_or(KernelAgentAuthorityErrorV2::StateConflict)?;
        let settlement = pending
            .settlement
            .ok_or(KernelAgentAuthorityErrorV2::StateConflict)?;
        let binding = authorized.binding();
        if ticket.durable_release_id != binding.durable_release_id()
            || ticket.binding_digest != pending.binding_digest
            || pending.active_state_manifest_digest != active_state_manifest_digest
        {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        let plaintext = vault
            .read_release_payload(pending.document, pending.durable_run_id, now)
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        if domain_digest(
            b"SAVANA_FINAL_RELEASE_PAYLOAD_V2\0",
            &[plaintext.as_slice()],
        ) != binding.release_payload_digest()
        {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        let policy = self
            .policy
            .as_mut()
            .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?;
        let g7 = policy
            .g7
            .as_ref()
            .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?;
        let release =
            savana_policy_core::v2::VerifiedFinalReleaseRecordV2::from_authorized_vault_release(
                self.config.installation_id,
                active_state_manifest_digest,
                pending.durable_task_id,
                pending.durable_run_id,
                binding.durable_release_id(),
                binding,
            )
            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let quota = VerifiedQuotaLimitV2::from_verified_policy(
            g7.quota_limit,
            g7.quota_policy_digest,
            DispatchQuotaSubjectV2::final_release(binding.release_quota_subject_digest()),
        )
        .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let effect_lease = VerifiedEffectGateLeaseV2::from_verified_ledger_projection(
            g7.effect_ledger_projection,
            self.config.installation_id,
            active_state_manifest_digest,
            deployment_generation,
            effect_fence_epoch,
            g7.executor_identity,
            g7.executor_key_id,
            g7.executor_connector_registry_digest,
            checked_deadline(now, 30_000)?,
        )
        .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let resolved_ticket =
            savana_policy_core::v2::ResolvedFinalReleaseTicketV2::from_resolved_kernel_ticket(
                ticket.commitment,
                binding.durable_release_id(),
                pending.binding_digest,
            )
            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let sealed_payload_digest = domain_digest(
            b"SAVANA_PRESEALED_FINAL_RELEASE_PAYLOAD_V2\0",
            &[plaintext.as_slice()],
        );
        let prepared = policy
            .durable
            .prepare_verified_final_release_dispatch(
                &release,
                quota,
                settlement,
                resolved_ticket,
                effect_lease,
                sealed_payload_digest,
            )
            .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?;
        let protocol_core = protocol_dispatch_core(&prepared)?;
        let vault_commit =
            savana_vault::KernelPreparedReleaseDispatchV2::from_verified_kernel_commit(
                binding,
                prepared.consumed_ticket_digest(),
                prepared.preparation().execution_nonce(),
                prepared.preparation().dispatch_core_digest(),
                prepared.preparation().dispatch_subject_digest(),
            )
            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let vault_prepared = vault
            .mark_release_dispatch_prepared(authorized, vault_commit, now)
            .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?;
        let (hpke_enc, hpke_ciphertext) = seal_execution_payload(
            &plaintext,
            g7.executor_seal_public_key,
            protocol_core
                .semantic_digest()
                .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?,
        )?;
        let envelope = SignedSealedExecutionEnvelopeV2::sign(
            SealedExecutionEnvelopePayloadV2::new(
                protocol_core,
                FixedBytes32V2::new(hpke_enc),
                BoundedCiphertextV2::new(hpke_ciphertext)
                    .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?,
            )
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?,
            &g7.envelope_signing_key,
        )
        .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        let response = g7
            .executor
            .dispatch(
                request_id,
                checked_deadline(now, 5_000)?,
                DispatchRequestV2::new(envelope),
            )
            .map_err(map_executor_client_error)?;
        let status = public_executor_status(response.status());
        vault
            .mark_release_dispatching(vault_prepared, now)
            .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?;
        let release_handle = mint_handle(ReleaseHandleV2::from_authority_entropy)?;
        let commitment = release_handle.authority_commitment(&self.handle_key);
        self.releases.push(ReleaseRecordV2 {
            release: release_handle,
            commitment,
            ticket_commitment,
            pending_commitment: pending.pending_commitment,
            prepared: vault_prepared,
            execution_nonce: prepared.preparation().execution_nonce(),
            dispatch_core_digest: prepared.preparation().dispatch_core_digest(),
            dispatch_subject_digest: prepared.preparation().dispatch_subject_digest(),
            status,
            completion: None,
        });
        Ok(savana_kernel_protocol::v2::DispatchReleaseResponseV2::new(
            release_handle,
            accepted_state(status),
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn release_status(
        &mut self,
        request_id: savana_kernel_protocol::v2::RequestIdV2,
        request: GetReleaseStatusRequestV2,
        vault: &mut dyn KernelIngressCommitSinkV2,
        caller_identity: ServiceIdentityV2,
        now: UnixMillisV2,
    ) -> Result<GetReleaseStatusResponseV2, KernelAgentAuthorityErrorV2> {
        self.verify_agent_caller(caller_identity)?;
        let index = match request.target() {
            ReleaseStatusTargetV2::Pending(pending) => {
                let commitment = pending.authority_commitment(&self.handle_key);
                self.releases
                    .iter()
                    .position(|record| record.pending_commitment == commitment)
            }
            ReleaseStatusTargetV2::Ticket(ticket) => {
                let commitment = ticket.authority_commitment(&self.handle_key);
                self.releases
                    .iter()
                    .position(|record| record.ticket_commitment == commitment)
            }
            ReleaseStatusTargetV2::Release(release) => {
                let commitment = release.authority_commitment(&self.handle_key);
                self.releases
                    .iter()
                    .position(|record| record.commitment == commitment)
            }
        }
        .ok_or(KernelAgentAuthorityErrorV2::InvalidReference)?;
        if matches!(
            self.releases[index].status,
            PublicExecutionStatusV2::Succeeded { .. }
                | PublicExecutionStatusV2::FailedNoEffect { .. }
                | PublicExecutionStatusV2::Indeterminate
        ) {
            return Ok(GetReleaseStatusResponseV2::new(self.releases[index].status));
        }
        let (nonce, core, subject) = {
            let record = &self.releases[index];
            (
                record.execution_nonce,
                record.dispatch_core_digest,
                record.dispatch_subject_digest,
            )
        };
        let response = self
            .policy
            .as_ref()
            .and_then(|policy| policy.g7.as_ref())
            .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?
            .executor
            .query(
                request_id,
                checked_deadline(now, 5_000)?,
                QueryByExecutionNonceRequestV2::new(nonce, core, subject)
                    .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?,
            )
            .map_err(map_executor_client_error)?;
        let status = match response.status() {
            ExecutorStatusV2::CompletionAvailable { completion, .. } => {
                self.commit_release_completion(request_id, index, *completion, vault, now)?
            }
            ExecutorStatusV2::FailedNoEffect { .. } => {
                let pending = self
                    .pending_releases
                    .iter()
                    .find(|pending| {
                        pending.pending_commitment == self.releases[index].pending_commitment
                    })
                    .ok_or(KernelAgentAuthorityErrorV2::StateConflict)?;
                vault
                    .mark_release_failed_no_effect(
                        pending.vault_pending.durable_release_id(),
                        nonce,
                        core,
                        subject,
                        now,
                    )
                    .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?;
                PublicExecutionStatusV2::FailedNoEffect {
                    class: PublicFailureClassV2::Connector,
                }
            }
            ExecutorStatusV2::Indeterminate { .. } => {
                vault
                    .mark_release_indeterminate(self.releases[index].prepared, now)
                    .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?;
                PublicExecutionStatusV2::Indeterminate
            }
            other => public_executor_status(other),
        };
        self.releases[index].status = status;
        Ok(GetReleaseStatusResponseV2::new(status))
    }

    fn commit_release_completion(
        &mut self,
        request_id: savana_kernel_protocol::v2::RequestIdV2,
        index: usize,
        completion: savana_kernel_protocol::v2::ExecutorCompletionDescriptorV2,
        vault: &mut dyn KernelIngressCommitSinkV2,
        now: UnixMillisV2,
    ) -> Result<PublicExecutionStatusV2, KernelAgentAuthorityErrorV2> {
        let record = &self.releases[index];
        let fetch_request = savana_kernel_protocol::v2::FetchCompletionRequestV2::new(
            record.execution_nonce,
            record.dispatch_core_digest,
            record.dispatch_subject_digest,
            completion,
        )
        .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let response = self
            .policy
            .as_ref()
            .and_then(|policy| policy.g7.as_ref())
            .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?
            .executor
            .fetch_completion(request_id, checked_deadline(now, 5_000)?, fetch_request)
            .map_err(map_executor_client_error)?;
        if response.execution_nonce() != record.execution_nonce
            || response.dispatch_core_digest() != record.dispatch_core_digest
            || response.dispatch_subject_digest() != record.dispatch_subject_digest
            || response.completion() != completion
        {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        let (receipt_key_id, receipt_public_key, executor_identity) = {
            let g7 = self
                .policy
                .as_ref()
                .and_then(|policy| policy.g7.as_ref())
                .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?;
            (
                g7.executor_receipt_key_id,
                g7.executor_receipt_public_key,
                g7.executor_identity,
            )
        };
        response
            .effect_started_receipt()
            .verify(receipt_key_id, receipt_public_key)
            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let pending = self
            .pending_releases
            .iter()
            .find(|pending| pending.pending_commitment == record.pending_commitment)
            .ok_or(KernelAgentAuthorityErrorV2::StateConflict)?;
        let binding = pending.vault_pending.binding();
        let (final_release_receipt_digest, release_audit_digest) = match response.payload() {
            savana_kernel_protocol::v2::ExecutorCompletionPayloadV2::FinalReleaseReceipt {
                receipt,
                audit_evidence,
                ..
            } => {
                receipt
                    .verify(receipt_key_id, receipt_public_key)
                    .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
                let unsigned = *receipt.unsigned();
                if unsigned.installation_id() != self.config.installation_id
                    || unsigned.active_state_manifest_digest()
                        != pending.active_state_manifest_digest
                    || unsigned.durable_release_id() != binding.durable_release_id()
                    || unsigned.execution_nonce() != record.execution_nonce
                    || unsigned.dispatch_core_digest() != record.dispatch_core_digest
                    || unsigned.dispatch_subject_digest() != record.dispatch_subject_digest
                    || unsigned.vault_segment_digest() != binding.vault_segment_digest()
                    || unsigned.release_payload_digest() != binding.release_payload_digest()
                    || unsigned.destination_digest() != binding.destination_digest()
                    || unsigned.executor_identity() != executor_identity
                    || unsigned.release_audit_digest() != audit_evidence.digest()
                    || receipt.digest()
                        != completion
                            .final_release_identity()
                            .ok_or(KernelAgentAuthorityErrorV2::BindingMismatch)?
                            .1
                {
                    return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
                }
                (receipt.digest(), audit_evidence.digest())
            }
            savana_kernel_protocol::v2::ExecutorCompletionPayloadV2::ToolResult { .. } => {
                return Err(KernelAgentAuthorityErrorV2::BindingMismatch)
            }
        };
        let completion_evidence_digest = domain_digest(
            b"SAVANA_AUTHENTICATED_EXECUTOR_COMPLETION_V2\0",
            &[
                response.effect_started_receipt_digest().as_bytes(),
                final_release_receipt_digest.as_bytes(),
                release_audit_digest.as_bytes(),
            ],
        );
        self.policy
            .as_mut()
            .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?
            .durable
            .reconcile_authenticated_completion(
                response.effect_started_receipt(),
                receipt_key_id,
                receipt_public_key,
                completion_evidence_digest,
                now,
            )
            .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?;
        vault
            .commit_known_release(
                record.prepared,
                final_release_receipt_digest,
                release_audit_digest,
                now,
            )
            .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?;
        let kernel_commit_digest = domain_digest(
            b"SAVANA_KERNEL_RELEASE_COMMIT_V2\0",
            &[
                record.dispatch_core_digest.as_bytes(),
                final_release_receipt_digest.as_bytes(),
                release_audit_digest.as_bytes(),
            ],
        );
        self.policy
            .as_ref()
            .and_then(|policy| policy.g7.as_ref())
            .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?
            .executor
            .acknowledge(
                request_id,
                checked_deadline(now, 5_000)?,
                savana_kernel_protocol::v2::AcknowledgeCommittedCompletionRequestV2::new(
                    record.execution_nonce,
                    record.dispatch_core_digest,
                    record.dispatch_subject_digest,
                    completion,
                    kernel_commit_digest,
                )
                .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?,
            )
            .map_err(map_executor_client_error)?;
        self.releases[index].completion = Some(completion);
        Ok(PublicExecutionStatusV2::Succeeded {
            completion: PublicDispatchCompletionV2::FinalRelease,
        })
    }

    pub(crate) fn authorize_vault_revocation(
        &self,
        request: &RevokeVaultRequestV2,
        caller_identity: ServiceIdentityV2,
    ) -> Result<(), KernelAgentAuthorityErrorV2> {
        self.verify_agent_caller(caller_identity)?;
        let known = self
            .sessions
            .iter()
            .any(|session| session.initial_document == request.document())
            || self.tasks.iter().any(|task| {
                task.material
                    .as_ref()
                    .is_some_and(|material| material.initial_document == request.document())
            });
        if !known {
            return Err(KernelAgentAuthorityErrorV2::InvalidReference);
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn resume_committed_authentication(
        &mut self,
        request: &ResumeCommittedAgentAuthenticationRequestV2,
        caller_identity: ServiceIdentityV2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        now: UnixMillisV2,
    ) -> Result<ResumeCommittedAgentAuthenticationResponseV2, KernelAgentAuthorityErrorV2> {
        self.verify_agent_caller(caller_identity)?;
        let unsigned = request
            .correlation()
            .verify(
                derive_ed25519_key_id_v2(
                    self.config
                        .correlation_signing_key
                        .verifying_key()
                        .to_bytes(),
                ),
                self.config
                    .correlation_signing_key
                    .verifying_key()
                    .to_bytes(),
                self.config.installation_id,
                active_state_manifest_digest,
                self.config.agentd_identity,
                now,
            )
            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let task_index = self
            .tasks
            .iter()
            .position(|task| task.durable_task_id == unsigned.durable_task_id())
            .ok_or(KernelAgentAuthorityErrorV2::InvalidReference)?;
        if &self.tasks[task_index].correlation != request.correlation()
            || !matches!(
                self.tasks[task_index].status,
                PublicTaskStatusV2::Ready { .. }
            )
        {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        let Some(record_index) = self.tasks[task_index].current_authentication_preparation else {
            let response = self.create_authentication_attempt(
                task_index,
                request.client_request_nonce(),
                active_state_manifest_digest,
                deployment_generation,
                now,
            )?;
            return Ok(ResumeCommittedAgentAuthenticationResponseV2::Prepared {
                authentication_preparation: response.authentication_preparation(),
                envelope: response.envelope().clone(),
            });
        };
        let record = self
            .authentication_preparations
            .get(record_index)
            .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?;
        if record.consumed {
            return Err(KernelAgentAuthorityErrorV2::StateConflict);
        }
        if record.originating_kerneld_boot_id == self.config.kerneld_server_boot_id
            && !record.restart_tombstoned
            && now.get() < record.expires_at.get()
        {
            if record.replacement_nonce != request.client_request_nonce()
                || request.prior_attempt_closure_proof().is_some()
            {
                return Err(KernelAgentAuthorityErrorV2::StateConflict);
            }
            return Ok(ResumeCommittedAgentAuthenticationResponseV2::Prepared {
                authentication_preparation: record.preparation,
                envelope: record.envelope.clone(),
            });
        }
        let closure = record.closure.clone();
        let Some(proof) = request.prior_attempt_closure_proof() else {
            return Ok(ResumeCommittedAgentAuthenticationResponseV2::ClosureRequired { closure });
        };
        let proof = proof
            .verify(
                self.config.ui_settlement_key_id,
                self.config.ui_settlement_public_key,
                now,
            )
            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let descriptor = closure.unsigned();
        let closure_digest = closure
            .descriptor_digest()
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        let correlation_digest = request
            .correlation()
            .correlation_digest()
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        let safe_evidence = matches!(
            proof.evidence(),
            AgentAuthenticationClosureEvidenceV2::NeverRegisteredDenylisted { .. }
                | AgentAuthenticationClosureEvidenceV2::RegisteredInvalidatedUnredeemed { .. }
        );
        if !safe_evidence
            || proof.installation_id() != descriptor.installation_id()
            || proof.attempt_manifest_digest() != descriptor.attempt_manifest_digest()
            || proof.attempt_deployment_generation() != descriptor.attempt_deployment_generation()
            || proof.closure_issuing_manifest_digest()
                != descriptor.closure_issuing_manifest_digest()
            || proof.closure_issuing_deployment_generation()
                != descriptor.closure_issuing_deployment_generation()
            || proof.agent_claim_compatibility_edge_identity_digest()
                != descriptor.agent_claim_compatibility_edge_identity_digest()
            || proof.durable_task_id() != descriptor.durable_task_id()
            || proof.durable_run_id() != descriptor.durable_run_id()
            || proof.signed_correlation_digest() != correlation_digest
            || proof.signed_correlation_digest() != descriptor.signed_correlation_digest()
            || proof.claim_commitment_digest() != descriptor.claim_commitment_digest()
            || proof.authenticated_principal() != descriptor.authenticated_principal()
            || proof.agentd_identity() != descriptor.agentd_identity()
            || proof.originating_agentd_boot_id() != descriptor.originating_agentd_boot_id()
            || proof.kerneld_identity() != descriptor.kerneld_identity()
            || proof.originating_kerneld_boot_id() != descriptor.originating_kerneld_boot_id()
            || proof.approvald_identity() != descriptor.approvald_identity()
            || proof.approvald_boot_id() != self.config.approvald_boot_id
            || proof.authentication_recovery_record_digest() != record.recovery_record_digest
            || proof.authentication_recovery_record_digest()
                != descriptor.authentication_recovery_record_digest()
            || proof.authentication_envelope_digest() != record.envelope_digest
            || proof.authentication_envelope_digest() != descriptor.authentication_envelope_digest()
            || proof.auth_attempt_nonce() != record.challenge
            || proof.auth_attempt_nonce() != descriptor.auth_attempt_nonce()
            || proof.closure_descriptor_digest() != closure_digest
        {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        self.authentication_preparations[record_index].restart_tombstoned = true;
        self.tasks[task_index].current_authentication_preparation = None;
        let response = self.create_authentication_attempt(
            task_index,
            request.client_request_nonce(),
            active_state_manifest_digest,
            deployment_generation,
            now,
        )?;
        Ok(ResumeCommittedAgentAuthenticationResponseV2::Prepared {
            authentication_preparation: response.authentication_preparation(),
            envelope: response.envelope().clone(),
        })
    }

    pub(crate) fn close_session(
        &mut self,
        session_handle: AgentSessionHandleV2,
        caller_identity: ServiceIdentityV2,
    ) -> Result<AgentSessionStatusV2, KernelAgentAuthorityErrorV2> {
        self.verify_agent_caller(caller_identity)?;
        let session = self
            .sessions
            .iter_mut()
            .find(|session| session.session == session_handle)
            .ok_or(KernelAgentAuthorityErrorV2::InvalidReference)?;
        if session.status == AgentSessionStatusV2::Closed {
            return Err(KernelAgentAuthorityErrorV2::AlreadyConsumed);
        }
        session.status = AgentSessionStatusV2::Closed;
        Ok(session.status)
    }

    fn verify_agent_caller(
        &self,
        caller_identity: ServiceIdentityV2,
    ) -> Result<(), KernelAgentAuthorityErrorV2> {
        self.ensure_durable_available()?;
        if caller_identity != self.config.agentd_identity {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        Ok(())
    }
}

fn checked_deadline(
    now: UnixMillisV2,
    delta: u64,
) -> Result<UnixMillisV2, KernelAgentAuthorityErrorV2> {
    if now.get() == 0 {
        return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
    }
    now.get()
        .checked_add(delta)
        .map(UnixMillisV2::new)
        .ok_or(KernelAgentAuthorityErrorV2::Unavailable)
}

fn mint_handle<T>(
    constructor: impl Fn([u8; 32]) -> Option<T>,
) -> Result<T, KernelAgentAuthorityErrorV2> {
    for _ in 0..8 {
        if let Some(handle) = constructor(random_bytes()?) {
            return Ok(handle);
        }
    }
    Err(KernelAgentAuthorityErrorV2::Unavailable)
}

fn random_bytes() -> Result<[u8; 32], KernelAgentAuthorityErrorV2> {
    let mut bytes = [0_u8; 32];
    getrandom(&mut bytes).map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
    if is_zero(&bytes) {
        return Err(KernelAgentAuthorityErrorV2::Unavailable);
    }
    Ok(bytes)
}

fn claim_digest(
    durable_task_id: DurableTaskIdV2,
    principal: PrincipalIdV2,
    durable_run_id: DurableRunIdV2,
    document: MaskedDocumentHandleV2,
) -> Result<Digest32V2, KernelAgentAuthorityErrorV2> {
    let document =
        minicbor::to_vec(document).map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
    let mut hasher = Sha256::new();
    hasher.update(CLAIM_DIGEST_DOMAIN);
    hasher.update(durable_task_id.as_bytes());
    hasher.update(principal.as_bytes());
    hasher.update(durable_run_id.as_bytes());
    hasher.update(document);
    Ok(Digest32V2::new(hasher.finalize().into()))
}

#[allow(clippy::too_many_arguments)]
fn authentication_recovery_record_digest(
    durable_task_id: DurableTaskIdV2,
    durable_run_id: DurableRunIdV2,
    correlation_digest: Digest32V2,
    claim_digest: Digest32V2,
    principal: PrincipalIdV2,
    auth_attempt_nonce: Nonce32V2,
    envelope_digest: Digest32V2,
    preparation_hash: Digest32V2,
    originating_kerneld_boot_id: BootIdV2,
) -> Digest32V2 {
    let mut hasher = Sha256::new();
    hasher.update(AGENT_AUTH_RECOVERY_RECORD_DOMAIN);
    hasher.update(2_u16.to_be_bytes());
    hasher.update(durable_task_id.as_bytes());
    hasher.update(durable_run_id.as_bytes());
    hasher.update(correlation_digest.as_bytes());
    hasher.update(claim_digest.as_bytes());
    hasher.update(principal.as_bytes());
    hasher.update(auth_attempt_nonce.as_bytes());
    hasher.update(envelope_digest.as_bytes());
    hasher.update(preparation_hash.as_bytes());
    hasher.update(originating_kerneld_boot_id.as_bytes());
    Digest32V2::new(hasher.finalize().into())
}

fn run_revision_digest(
    durable_run_id: DurableRunIdV2,
    active_state_manifest_digest: Digest32V2,
    initial_value_digest: Digest32V2,
) -> RunRevisionDigestV2 {
    let mut hasher = Sha256::new();
    hasher.update(RUN_REVISION_DOMAIN);
    hasher.update(durable_run_id.as_bytes());
    hasher.update(1_u64.to_be_bytes());
    hasher.update(active_state_manifest_digest.as_bytes());
    hasher.update(initial_value_digest.as_bytes());
    RunRevisionDigestV2::new(hasher.finalize().into())
}

fn domain_digest(domain: &[u8], values: &[&[u8]]) -> Digest32V2 {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for value in values {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value);
    }
    Digest32V2::new(hasher.finalize().into())
}

const fn map_cardinality(value: PlannerSlotCardinalityV2) -> ClosedCardinalityV2 {
    match value {
        PlannerSlotCardinalityV2::ExactlyOne => ClosedCardinalityV2::ExactlyOne,
        PlannerSlotCardinalityV2::ZeroOrOne => ClosedCardinalityV2::ZeroOrOne,
        PlannerSlotCardinalityV2::OneOrMore => ClosedCardinalityV2::OneOrMore,
        PlannerSlotCardinalityV2::ZeroOrMore => ClosedCardinalityV2::ZeroOrMore,
    }
}

const fn map_confidentiality(value: PlannerSlotConfidentialityV2) -> PolicySlotConfidentialityV2 {
    match value {
        PlannerSlotConfidentialityV2::PublicStructural => {
            PolicySlotConfidentialityV2::PublicStructural
        }
        PlannerSlotConfidentialityV2::ConfidentialAbstract => {
            PolicySlotConfidentialityV2::ConfidentialAbstract
        }
    }
}

fn compiled_projection_digest(domain: &[u8], projection_id: u32) -> Digest32V2 {
    domain_digest(domain, &[&projection_id.to_be_bytes()])
}

fn projected_destination(
    stored: &savana_policy_core::v2::VerifiedStoredBindingsV2<'_>,
) -> Result<KernelValueV2, KernelAgentAuthorityErrorV2> {
    let mut bytes = Vec::new();
    for argument in stored.arguments() {
        let name = argument.argument_name().as_str().as_bytes();
        let canonical = minicbor::to_vec(argument.value())
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        bytes.extend_from_slice(
            &u32::try_from(name.len())
                .map_err(|_| KernelAgentAuthorityErrorV2::LimitExceeded)?
                .to_be_bytes(),
        );
        bytes.extend_from_slice(name);
        bytes.extend_from_slice(
            &u32::try_from(canonical.len())
                .map_err(|_| KernelAgentAuthorityErrorV2::LimitExceeded)?
                .to_be_bytes(),
        );
        bytes.extend_from_slice(&canonical);
    }
    KernelValueV2::bytes(bytes).map_err(|_| KernelAgentAuthorityErrorV2::LimitExceeded)
}

fn projected_display(
    stored: &savana_policy_core::v2::VerifiedStoredBindingsV2<'_>,
) -> Result<KernelValueV2, KernelAgentAuthorityErrorV2> {
    let mut bytes = Vec::new();
    for argument in stored.arguments() {
        let name = argument.argument_name().as_str().as_bytes();
        bytes.extend_from_slice(
            &u32::try_from(name.len())
                .map_err(|_| KernelAgentAuthorityErrorV2::LimitExceeded)?
                .to_be_bytes(),
        );
        bytes.extend_from_slice(name);
        bytes.extend_from_slice(argument.value_digest().as_bytes());
        bytes.extend_from_slice(argument.provenance_digest().as_bytes());
    }
    KernelValueV2::bytes(bytes).map_err(|_| KernelAgentAuthorityErrorV2::LimitExceeded)
}

fn protocol_trace(
    digest: Digest32V2,
) -> Result<ProtocolDecisionTraceV2, KernelAgentAuthorityErrorV2> {
    ProtocolDecisionTraceV2::new(digest).map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)
}

fn protocol_semantic_binding(
    binding: &savana_policy_core::v2::ToolExecutionSemanticBindingV2,
) -> Result<savana_kernel_protocol::v2::ToolExecutionSemanticBindingV2, KernelAgentAuthorityErrorV2>
{
    savana_kernel_protocol::v2::ToolExecutionSemanticBindingV2::new(
        binding.plan_revision_digest(),
        binding.internal_step_id(),
        binding.tool_descriptor_digest(),
        binding.argument_digest(),
        binding.provenance_set_digest(),
        binding.token_set_digest(),
        binding.destination_digest(),
        binding.display_projection_digest(),
        binding.display_digest(),
        binding.executor_identity_digest(),
        savana_kernel_protocol::v2::AttemptKindV2::new(u32::from(binding.attempt_kind().tag())),
    )
    .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)
}

pub(crate) fn protocol_dispatch_core(
    prepared: &KernelPreparedDispatchV2,
) -> Result<ProtocolDispatchCoreV2, KernelAgentAuthorityErrorV2> {
    let core = prepared.core();
    let subject = match core.subject() {
        savana_policy_core::v2::DispatchSubjectV2::ToolExecution {
            action_intent_id,
            binding,
            approval_settlement_digest,
        } => ProtocolDispatchSubjectV2::tool_execution(
            *action_intent_id,
            protocol_semantic_binding(binding)?,
            *approval_settlement_digest,
        )
        .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?,
        savana_policy_core::v2::DispatchSubjectV2::FinalRelease {
            binding,
            approval_settlement_digest,
        } => ProtocolDispatchSubjectV2::final_release(*binding, *approval_settlement_digest)
            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?,
    };
    ProtocolDispatchCoreV2::new(
        core.installation_id(),
        core.active_state_manifest_digest(),
        core.deployment_generation(),
        core.effect_fence_epoch(),
        core.durable_task_id(),
        core.durable_run_id(),
        core.execution_nonce(),
        subject,
        savana_kernel_protocol::v2::ExecutorIdentityV2::new(*core.executor_identity().as_bytes()),
        core.executor_key_id(),
        core.executor_connector_registry_digest(),
        core.expires_at(),
    )
    .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)
}

fn seal_execution_payload(
    plaintext: &[u8],
    recipient_public_key: [u8; 32],
    dispatch_core_digest: Digest32V2,
) -> Result<([u8; 32], Vec<u8>), KernelAgentAuthorityErrorV2> {
    if plaintext.is_empty() {
        return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
    }
    let ephemeral_secret = StaticSecret::from(random_bytes()?);
    let ephemeral_public = X25519PublicKey::from(&ephemeral_secret).to_bytes();
    let recipient = X25519PublicKey::from(recipient_public_key);
    let shared = ephemeral_secret.diffie_hellman(&recipient).to_bytes();
    if shared == [0; 32] {
        return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
    }
    let mut key_nonce = [0_u8; 44];
    let mut info = Vec::with_capacity(96);
    info.extend_from_slice(b"SAVANA_EXECUTION_HPKE_X25519_CHACHA20POLY1305_V2\0");
    info.extend_from_slice(&ephemeral_public);
    info.extend_from_slice(&recipient_public_key);
    Hkdf::<Sha256>::new(Some(dispatch_core_digest.as_bytes()), &shared)
        .expand(&info, &mut key_nonce)
        .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
    let cipher = ChaCha20Poly1305::new_from_slice(&key_nonce[..32])
        .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&key_nonce[32..]),
            Payload {
                msg: plaintext,
                aad: dispatch_core_digest.as_bytes(),
            },
        )
        .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
    Ok((ephemeral_public, ciphertext))
}

fn hpke_x25519_key_id(public_key: [u8; 32]) -> HpkeX25519KeyIdV2 {
    let mut hasher = Sha256::new();
    hasher.update(b"SAVANA_HPKE_X25519_KEY_ID_V2\0");
    hasher.update(public_key);
    HpkeX25519KeyIdV2::new(hasher.finalize().into())
}

fn public_executor_status(status: &ExecutorStatusV2) -> PublicExecutionStatusV2 {
    match status {
        ExecutorStatusV2::Prepared => PublicExecutionStatusV2::Prepared,
        ExecutorStatusV2::EffectStarted { .. } => PublicExecutionStatusV2::Dispatching,
        ExecutorStatusV2::CompletionAvailable { .. } => PublicExecutionStatusV2::ResultGatePending,
        ExecutorStatusV2::FailedNoEffect { .. } => PublicExecutionStatusV2::FailedNoEffect {
            class: PublicFailureClassV2::Connector,
        },
        ExecutorStatusV2::Indeterminate { .. } => PublicExecutionStatusV2::Indeterminate,
        ExecutorStatusV2::Acknowledged => PublicExecutionStatusV2::ResultGatePending,
    }
}

const fn accepted_state(status: PublicExecutionStatusV2) -> PublicDispatchAcceptedStateV2 {
    match status {
        PublicExecutionStatusV2::Prepared => PublicDispatchAcceptedStateV2::Prepared,
        PublicExecutionStatusV2::Dispatching
        | PublicExecutionStatusV2::ResultGatePending
        | PublicExecutionStatusV2::Succeeded { .. }
        | PublicExecutionStatusV2::EffectSucceededOutputQuarantined { .. }
        | PublicExecutionStatusV2::FailedNoEffect { .. }
        | PublicExecutionStatusV2::Indeterminate => PublicDispatchAcceptedStateV2::Dispatching,
    }
}

const fn map_executor_client_error(
    error: KernelExecutorClientErrorV2,
) -> KernelAgentAuthorityErrorV2 {
    match error {
        KernelExecutorClientErrorV2::DeadlineExceeded => KernelAgentAuthorityErrorV2::Expired,
        KernelExecutorClientErrorV2::Remote(_) => KernelAgentAuthorityErrorV2::StateConflict,
        KernelExecutorClientErrorV2::Unavailable => KernelAgentAuthorityErrorV2::Unavailable,
    }
}

fn intent_current_state(
    intent: &IntentRecordV2,
    tickets: &[ExecutionTicketRecordV2],
) -> Result<ActionIntentCurrentStateV2, KernelAgentAuthorityErrorV2> {
    Ok(match intent.state {
        IntentRecordStateV2::Proposed => ActionIntentCurrentStateV2::Proposed {
            pending: intent.pending,
        },
        IntentRecordStateV2::Evaluating => ActionIntentCurrentStateV2::Evaluating {
            pending: intent.pending,
        },
        IntentRecordStateV2::Denied => ActionIntentCurrentStateV2::Denied {
            code: PublicStableCodeV2::PolicyDenied,
            trace: protocol_trace(
                intent
                    .decision_trace
                    .ok_or(KernelAgentAuthorityErrorV2::StateConflict)?,
            )?,
        },
        IntentRecordStateV2::AwaitingApproval => ActionIntentCurrentStateV2::AwaitingApproval {
            pending: intent.pending,
        },
        IntentRecordStateV2::Authorized => {
            let commitment = intent
                .ticket_commitment
                .ok_or(KernelAgentAuthorityErrorV2::StateConflict)?;
            let ticket = tickets
                .iter()
                .find(|ticket| ticket.commitment == commitment)
                .ok_or(KernelAgentAuthorityErrorV2::StateConflict)?;
            ActionIntentCurrentStateV2::Authorized {
                ticket: ticket.ticket,
            }
        }
    })
}

const fn map_value_error(error: KernelValueErrorV2) -> KernelAgentAuthorityErrorV2 {
    match error {
        KernelValueErrorV2::InvalidReference => KernelAgentAuthorityErrorV2::InvalidReference,
        KernelValueErrorV2::WrongRun | KernelValueErrorV2::PolicyDenied => {
            KernelAgentAuthorityErrorV2::BindingMismatch
        }
        KernelValueErrorV2::Expired => KernelAgentAuthorityErrorV2::Expired,
        KernelValueErrorV2::LimitExceeded => KernelAgentAuthorityErrorV2::LimitExceeded,
        KernelValueErrorV2::StateConflict => KernelAgentAuthorityErrorV2::StateConflict,
        KernelValueErrorV2::Unavailable => KernelAgentAuthorityErrorV2::Unavailable,
    }
}

fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

fn encode_recovery_value<T>(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    value: &T,
) -> Result<(), KernelAgentAuthorityErrorV2>
where
    T: minicbor::Encode<()>,
{
    minicbor::Encode::encode(value, encoder, &mut ())
        .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)
}

fn encode_optional_recovery_value<T>(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    value: Option<&T>,
) -> Result<(), KernelAgentAuthorityErrorV2>
where
    T: minicbor::Encode<()>,
{
    match value {
        Some(value) => encode_recovery_value(encoder, value),
        None => encoder
            .null()
            .map(|_| ())
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable),
    }
}

fn encode_prepared_claim_material(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    material: &PreparedAgentClaimMaterialV2,
) -> Result<(), KernelAgentAuthorityErrorV2> {
    let provenance = encode_provenance_record_v2(&material.provenance)
        .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
    encoder
        .array(7)
        .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
    encode_recovery_value(encoder, &material.durable_run_id)?;
    encode_recovery_value(encoder, &material.producer_identity)?;
    encode_recovery_value(encoder, &material.initial_value)?;
    encoder
        .bytes(&provenance)
        .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
    encode_recovery_value(encoder, &material.initial_document)?;
    encoder
        .u16(material.policy_allowed_effects.bits())
        .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
    encode_recovery_value(encoder, &material.expires_at)
}

fn decode_recovery_fixed<const N: usize>(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<[u8; N], KernelAgentAuthorityErrorV2> {
    decoder
        .bytes()
        .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?
        .try_into()
        .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)
}

fn decode_recovery_count(
    decoder: &mut minicbor::Decoder<'_>,
    maximum: usize,
) -> Result<usize, KernelAgentAuthorityErrorV2> {
    let count = decoder
        .array()
        .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?
        .ok_or(KernelAgentAuthorityErrorV2::BindingMismatch)?;
    let count = usize::try_from(count).map_err(|_| KernelAgentAuthorityErrorV2::LimitExceeded)?;
    if count > maximum {
        return Err(KernelAgentAuthorityErrorV2::LimitExceeded);
    }
    Ok(count)
}

fn require_recovery_array(
    decoder: &mut minicbor::Decoder<'_>,
    expected: u64,
) -> Result<(), KernelAgentAuthorityErrorV2> {
    if decoder
        .array()
        .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?
        != Some(expected)
    {
        return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
    }
    Ok(())
}

fn decode_recovery_value<'bytes, T>(
    decoder: &mut minicbor::Decoder<'bytes>,
    context: &mut V2DecodeContext,
) -> Result<T, KernelAgentAuthorityErrorV2>
where
    T: minicbor::Decode<'bytes, V2DecodeContext>,
{
    minicbor::Decode::decode(decoder, context)
        .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)
}

fn decode_optional_recovery_value<'bytes, T>(
    decoder: &mut minicbor::Decoder<'bytes>,
    context: &mut V2DecodeContext,
) -> Result<Option<T>, KernelAgentAuthorityErrorV2>
where
    T: minicbor::Decode<'bytes, V2DecodeContext>,
{
    if decoder
        .datatype()
        .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?
        == minicbor::data::Type::Null
    {
        decoder
            .null()
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        Ok(None)
    } else {
        decode_recovery_value(decoder, context).map(Some)
    }
}

fn decode_optional_recovery_u32(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<Option<u32>, KernelAgentAuthorityErrorV2> {
    if decoder
        .datatype()
        .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?
        == minicbor::data::Type::Null
    {
        decoder
            .null()
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        Ok(None)
    } else {
        decoder
            .u32()
            .map(Some)
            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)
    }
}

fn decode_prepared_claim_material(
    decoder: &mut minicbor::Decoder<'_>,
    context: &mut V2DecodeContext,
) -> Result<PreparedAgentClaimMaterialV2, KernelAgentAuthorityErrorV2> {
    require_recovery_array(decoder, 7)?;
    let durable_run_id = decode_recovery_value(decoder, context)?;
    let producer_identity = decode_recovery_value(decoder, context)?;
    let initial_value = decode_recovery_value(decoder, context)?;
    let provenance_bytes = decoder
        .bytes()
        .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
    if provenance_bytes.is_empty() || provenance_bytes.len() > 8 * 1024 * 1024 {
        return Err(KernelAgentAuthorityErrorV2::LimitExceeded);
    }
    let provenance = decode_provenance_record_v2(provenance_bytes)
        .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
    let initial_document = decode_recovery_value(decoder, context)?;
    let policy_allowed_effects = EffectSetV2::from_bits(
        decoder
            .u16()
            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?,
    )
    .ok_or(KernelAgentAuthorityErrorV2::BindingMismatch)?;
    let expires_at = decode_recovery_value(decoder, context)?;
    PreparedAgentClaimMaterialV2::from_verified_ingress(
        durable_run_id,
        producer_identity,
        initial_value,
        provenance,
        initial_document,
        policy_allowed_effects,
        expires_at,
    )
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;
    use std::sync::{Arc, Mutex};

    use ed25519_dalek::SigningKey;
    use savana_kernel_protocol::v2::{
        derive_ed25519_key_id_v2, BootIdV2, CancelKernelTaskRequestV2, Digest32V2, DurableRunIdV2,
        GetKernelTaskStatusRequestV2, Nonce32V2, PrepareNewIngressRequestV2,
        PrepareNewIngressResponseV2, PrincipalIdV2, PublicTaskStatusV2,
        ResumeCommittedAgentAuthenticationRequestV2, ResumeCommittedAgentAuthenticationResponseV2,
        ServiceIdentityV2, UnixMillisV2,
    };
    use sha2::{Digest as _, Sha256};

    use super::{hpke_x25519_key_id, KernelAgentAuthorityV2, KernelAgentSecurityConfigV2};
    use crate::v2_agent_durable::{
        KernelAgentAuthorityRollbackAnchorV2, KernelAgentAuthorityStateHeadV2,
    };
    use crate::v2_ingress_authority::{KernelIngressAuthorityV2, KernelIngressSecurityConfigV2};

    #[derive(Clone, Default)]
    struct TestAgentStateAnchorV2(Arc<Mutex<KernelAgentAuthorityStateHeadV2>>);

    impl KernelAgentAuthorityRollbackAnchorV2 for TestAgentStateAnchorV2 {
        fn current_head(&self) -> Result<KernelAgentAuthorityStateHeadV2, ()> {
            self.0.lock().map(|head| *head).map_err(|_| ())
        }

        fn compare_and_advance(
            &mut self,
            expected: KernelAgentAuthorityStateHeadV2,
            next: KernelAgentAuthorityStateHeadV2,
        ) -> Result<(), ()> {
            let mut head = self.0.lock().map_err(|_| ())?;
            if *head != expected
                || next.sequence() != expected.sequence().checked_add(1).ok_or(())?
            {
                return Err(());
            }
            *head = next;
            Ok(())
        }
    }

    #[test]
    fn g7_uses_the_protocol_hpke_x25519_key_identifier_derivation() {
        let public_key = [0x55; 32];
        let mut hasher = Sha256::new();
        hasher.update(b"SAVANA_HPKE_X25519_KEY_ID_V2\0");
        hasher.update(public_key);
        assert_eq!(
            hpke_x25519_key_id(public_key).as_bytes(),
            &<[u8; 32]>::from(hasher.finalize())
        );
    }

    #[test]
    fn prepare_reconcile_status_and_cancel_are_bound_to_the_signed_correlation() {
        let agentd_identity = ServiceIdentityV2::new([0x11; 32]);
        let approvald_identity = ServiceIdentityV2::new([0x12; 32]);
        let ui_key = SigningKey::from_bytes(&[0x13; 32]);
        let ingress_settlement_key = SigningKey::from_bytes(&[0x14; 32]);
        let envelope_key = SigningKey::from_bytes(&[0x15; 32]);
        let mut ingress = KernelIngressAuthorityV2::new(
            KernelIngressSecurityConfigV2::new(
                Digest32V2::new([0x16; 32]),
                ServiceIdentityV2::new([0x17; 32]),
                approvald_identity,
                SigningKey::from_bytes(&[0x18; 32]),
                derive_ed25519_key_id_v2(ui_key.verifying_key().to_bytes()),
                ui_key.verifying_key().to_bytes(),
                derive_ed25519_key_id_v2(ingress_settlement_key.verifying_key().to_bytes()),
                ingress_settlement_key.verifying_key().to_bytes(),
            )
            .unwrap(),
            8,
        )
        .unwrap();
        let mut authority = KernelAgentAuthorityV2::new(
            KernelAgentSecurityConfigV2::new(
                Digest32V2::new([0x16; 32]),
                ServiceIdentityV2::new([0x17; 32]),
                agentd_identity,
                ServiceIdentityV2::new([0x18; 32]),
                BootIdV2::new([0x19; 32]),
                BootIdV2::new([0x1a; 32]),
                BootIdV2::new([0x1c; 32]),
                BootIdV2::new([0x1b; 32]),
                SigningKey::from_bytes(&[0x1d; 32]),
                envelope_key,
                derive_ed25519_key_id_v2(ui_key.verifying_key().to_bytes()),
                ui_key.verifying_key().to_bytes(),
            )
            .unwrap(),
            8,
        )
        .unwrap();
        let manifest = Digest32V2::new([0x1d; 32]);
        let request =
            PrepareNewIngressRequestV2::new(Nonce32V2::new([0x1e; 32]), Nonce32V2::new([0x1f; 32]))
                .unwrap();
        let prepared = authority
            .prepare_new_ingress(
                request,
                &mut ingress,
                agentd_identity,
                manifest,
                7,
                UnixMillisV2::new(100),
            )
            .unwrap();
        let PrepareNewIngressResponseV2::Prepared {
            preparation,
            correlation,
            ..
        } = prepared
        else {
            panic!("first request must prepare");
        };
        let reconciled = authority
            .prepare_new_ingress(
                request,
                &mut ingress,
                agentd_identity,
                manifest,
                7,
                UnixMillisV2::new(101),
            )
            .unwrap();
        assert!(matches!(
            reconciled,
            PrepareNewIngressResponseV2::Reconciled {
                current: PublicTaskStatusV2::AwaitingInput,
                ..
            }
        ));
        assert_eq!(
            authority
                .task_status(
                    &GetKernelTaskStatusRequestV2::new(correlation.clone()),
                    agentd_identity,
                    manifest,
                    UnixMillisV2::new(102),
                )
                .unwrap()
                .status(),
            PublicTaskStatusV2::AwaitingInput
        );
        assert_eq!(
            authority
                .cancel_task(
                    &CancelKernelTaskRequestV2::new(preparation, correlation.clone()),
                    agentd_identity,
                    manifest,
                    UnixMillisV2::new(103),
                )
                .unwrap()
                .status(),
            PublicTaskStatusV2::Cancelled
        );
        assert_eq!(
            authority
                .task_status(
                    &GetKernelTaskStatusRequestV2::new(correlation),
                    agentd_identity,
                    manifest,
                    UnixMillisV2::new(104),
                )
                .unwrap()
                .status(),
            PublicTaskStatusV2::Cancelled
        );
    }

    #[test]
    fn cancelled_task_status_survives_encrypted_authority_restart() {
        let installation = Digest32V2::new([0x31; 32]);
        let manifest = Digest32V2::new([0x32; 32]);
        let kerneld_identity = ServiceIdentityV2::new([0x33; 32]);
        let agentd_identity = ServiceIdentityV2::new([0x34; 32]);
        let approvald_identity = ServiceIdentityV2::new([0x35; 32]);
        let agentd_boot = BootIdV2::new([0x36; 32]);
        let approvald_boot = BootIdV2::new([0x37; 32]);
        let machine_boot = BootIdV2::new([0x38; 32]);
        let settlement_key = SigningKey::from_bytes(&[0x39; 32]);
        let security = |kerneld_boot| {
            KernelAgentSecurityConfigV2::new(
                installation,
                kerneld_identity,
                agentd_identity,
                approvald_identity,
                agentd_boot,
                kerneld_boot,
                approvald_boot,
                machine_boot,
                SigningKey::from_bytes(&[0x3a; 32]),
                SigningKey::from_bytes(&[0x3b; 32]),
                derive_ed25519_key_id_v2(settlement_key.verifying_key().to_bytes()),
                settlement_key.verifying_key().to_bytes(),
            )
            .unwrap()
        };
        let ingress_settlement_key = SigningKey::from_bytes(&[0x3c; 32]);
        let mut ingress = KernelIngressAuthorityV2::new(
            KernelIngressSecurityConfigV2::new(
                installation,
                ServiceIdentityV2::new([0x3d; 32]),
                approvald_identity,
                SigningKey::from_bytes(&[0x3e; 32]),
                derive_ed25519_key_id_v2(settlement_key.verifying_key().to_bytes()),
                settlement_key.verifying_key().to_bytes(),
                derive_ed25519_key_id_v2(ingress_settlement_key.verifying_key().to_bytes()),
                ingress_settlement_key.verifying_key().to_bytes(),
            )
            .unwrap(),
            8,
        )
        .unwrap();
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory
            .path()
            .join("kernel-agent-authority-state-v2.cbor");
        let anchor = TestAgentStateAnchorV2::default();
        let mut authority = KernelAgentAuthorityV2::open_durable(
            security(BootIdV2::new([0x3f; 32])),
            8,
            &path,
            [0x40; 32],
            Digest32V2::new([0x41; 32]),
            Box::new(anchor.clone()),
            UnixMillisV2::new(100),
        )
        .unwrap();
        let prepared = authority
            .prepare_new_ingress(
                PrepareNewIngressRequestV2::new(
                    Nonce32V2::new([0x42; 32]),
                    Nonce32V2::new([0x43; 32]),
                )
                .unwrap(),
                &mut ingress,
                agentd_identity,
                manifest,
                9,
                UnixMillisV2::new(101),
            )
            .unwrap();
        let PrepareNewIngressResponseV2::Prepared {
            preparation,
            correlation,
            ..
        } = prepared
        else {
            panic!("new ingress must prepare");
        };
        authority
            .cancel_task(
                &CancelKernelTaskRequestV2::new(preparation, correlation.clone()),
                agentd_identity,
                manifest,
                UnixMillisV2::new(102),
            )
            .unwrap();
        drop(authority);

        let reopened = KernelAgentAuthorityV2::open_durable(
            security(BootIdV2::new([0x44; 32])),
            8,
            &path,
            [0x40; 32],
            Digest32V2::new([0x41; 32]),
            Box::new(anchor),
            UnixMillisV2::new(103),
        )
        .unwrap();
        assert_eq!(
            reopened
                .task_status(
                    &GetKernelTaskStatusRequestV2::new(correlation),
                    agentd_identity,
                    manifest,
                    UnixMillisV2::new(104),
                )
                .unwrap()
                .status(),
            PublicTaskStatusV2::Cancelled
        );
    }

    #[test]
    fn resume_authentication_requires_durable_approvald_closure_after_boot_change() {
        let installation = Digest32V2::new([0x51; 32]);
        let manifest = Digest32V2::new([0x52; 32]);
        let kerneld_identity = ServiceIdentityV2::new([0x53; 32]);
        let agentd_identity = ServiceIdentityV2::new([0x54; 32]);
        let approvald_identity = ServiceIdentityV2::new([0x55; 32]);
        let agentd_boot = BootIdV2::new([0x56; 32]);
        let original_kerneld_boot = BootIdV2::new([0x57; 32]);
        let replacement_kerneld_boot = BootIdV2::new([0x58; 32]);
        let approvald_boot = BootIdV2::new([0x59; 32]);
        let machine_boot = BootIdV2::new([0x5a; 32]);
        let correlation_key = SigningKey::from_bytes(&[0x5b; 32]);
        let envelope_key = SigningKey::from_bytes(&[0x5c; 32]);
        let settlement_key = SigningKey::from_bytes(&[0x5d; 32]);
        let ingress_settlement_key = SigningKey::from_bytes(&[0x5e; 32]);
        let mut ingress = KernelIngressAuthorityV2::new(
            KernelIngressSecurityConfigV2::new(
                installation,
                ServiceIdentityV2::new([0x5f; 32]),
                approvald_identity,
                SigningKey::from_bytes(&[0x60; 32]),
                derive_ed25519_key_id_v2(settlement_key.verifying_key().to_bytes()),
                settlement_key.verifying_key().to_bytes(),
                derive_ed25519_key_id_v2(ingress_settlement_key.verifying_key().to_bytes()),
                ingress_settlement_key.verifying_key().to_bytes(),
            )
            .unwrap(),
            8,
        )
        .unwrap();
        let mut authority = KernelAgentAuthorityV2::new(
            KernelAgentSecurityConfigV2::new(
                installation,
                kerneld_identity,
                agentd_identity,
                approvald_identity,
                agentd_boot,
                original_kerneld_boot,
                approvald_boot,
                machine_boot,
                correlation_key.clone(),
                envelope_key.clone(),
                derive_ed25519_key_id_v2(settlement_key.verifying_key().to_bytes()),
                settlement_key.verifying_key().to_bytes(),
            )
            .unwrap(),
            8,
        )
        .unwrap();
        let prepared = authority
            .prepare_new_ingress(
                PrepareNewIngressRequestV2::new(
                    Nonce32V2::new([0x61; 32]),
                    Nonce32V2::new([0x62; 32]),
                )
                .unwrap(),
                &mut ingress,
                agentd_identity,
                manifest,
                7,
                UnixMillisV2::new(1_000),
            )
            .unwrap();
        let PrepareNewIngressResponseV2::Prepared { correlation, .. } = prepared else {
            panic!("new ingress must prepare");
        };
        authority.tasks[0].expected_principal = Some(PrincipalIdV2::new([0x63; 32]));
        authority.tasks[0].claim_digest = Some(Digest32V2::new([0x64; 32]));
        authority.tasks[0].durable_run_id = Some(DurableRunIdV2::new([0x65; 32]));
        authority.tasks[0].status = PublicTaskStatusV2::Ready { bootstrap: None };
        let first_nonce = Nonce32V2::new([0x66; 32]);
        let first = authority
            .resume_committed_authentication(
                &ResumeCommittedAgentAuthenticationRequestV2::new(
                    correlation.clone(),
                    first_nonce,
                    None,
                )
                .unwrap(),
                agentd_identity,
                manifest,
                7,
                UnixMillisV2::new(1_100),
            )
            .unwrap();
        assert!(matches!(
            first,
            ResumeCommittedAgentAuthenticationResponseV2::Prepared { .. }
        ));

        authority.config.kerneld_server_boot_id = replacement_kerneld_boot;
        let replacement_nonce = Nonce32V2::new([0x67; 32]);
        let closure = authority
            .resume_committed_authentication(
                &ResumeCommittedAgentAuthenticationRequestV2::new(
                    correlation.clone(),
                    replacement_nonce,
                    None,
                )
                .unwrap(),
                agentd_identity,
                manifest,
                7,
                UnixMillisV2::new(1_200),
            )
            .unwrap();
        let ResumeCommittedAgentAuthenticationResponseV2::ClosureRequired { closure } = closure
        else {
            panic!("boot change must require approvald closure");
        };
        let mut approvald = savana_approvald::ProtocolApprovalServiceV2::from_verified_deployment(
            installation,
            manifest,
            7,
            approvald_boot,
            3,
            approvald_identity,
            derive_ed25519_key_id_v2(envelope_key.verifying_key().to_bytes()),
            envelope_key.verifying_key().to_bytes(),
            derive_ed25519_key_id_v2(correlation_key.verifying_key().to_bytes()),
            correlation_key.verifying_key().to_bytes(),
            derive_ed25519_key_id_v2(settlement_key.verifying_key().to_bytes()),
            settlement_key.to_bytes(),
            8,
        )
        .unwrap();
        let proof = approvald
            .close_agent_authentication_attempt(&closure, agentd_identity, UnixMillisV2::new(1_300))
            .unwrap();
        let replacement = authority
            .resume_committed_authentication(
                &ResumeCommittedAgentAuthenticationRequestV2::new(
                    correlation,
                    replacement_nonce,
                    Some(proof),
                )
                .unwrap(),
                agentd_identity,
                manifest,
                7,
                UnixMillisV2::new(1_400),
            )
            .unwrap();
        assert!(matches!(
            replacement,
            ResumeCommittedAgentAuthenticationResponseV2::Prepared { .. }
        ));
        assert_eq!(
            authority.authentication_preparations.len(),
            2,
            "replacement must be one new attempt after durable closure"
        );
        assert!(authority.authentication_preparations[0].restart_tombstoned);
    }
}
