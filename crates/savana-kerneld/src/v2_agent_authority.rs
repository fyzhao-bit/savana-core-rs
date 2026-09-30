use base64::Engine as _;
#[path = "v04_fused_action_driver.rs"]
mod fused_action_driver;
#[path = "v04_fused_actions.rs"]
mod fused_actions;
#[path = "v04_fused_approval_delivery.rs"]
mod fused_approval_delivery;
#[path = "v04_fused_approval_recovery.rs"]
mod fused_approval_recovery;
#[path = "v04_fused_compiler.rs"]
mod fused_compiler;
#[path = "v04_fused_input_admission.rs"]
mod fused_input_admission;
#[path = "v04_fused_final_result.rs"]
mod fused_final_result;
#[path = "v04_fused_host.rs"]
mod fused_host;
#[path = "v04_fused_recovery_driver.rs"]
mod fused_recovery_driver;
#[path = "v04_fused_release_driver.rs"]
mod fused_release_driver;
#[path = "v04_fused_release_recovery.rs"]
mod fused_release_recovery;
#[path = "v04_private_session.rs"]
mod private_session;
use chacha20poly1305::aead::{Aead as _, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit as _, Nonce};
use ed25519_dalek::{Signer as _, SigningKey};
use getrandom::getrandom;
use hkdf::Hkdf;
use savana_kernel_protocol::v2::{
    approval_display_digest_v2, connector_registration_descriptor_digest_v2,
    derive_ed25519_key_id_v2, ActionIntentCurrentStateV2, ActionIntentHandleV2, ActionIntentIdV2,
    ActionTemplateIdV2, ActiveToolViewV2, AgentAuthenticationClosureEvidenceV2,
    AgentSessionHandleV2, AgentSessionStatusV2, AgentUiAuthenticationPreparationHandleV2,
    AgentUiAuthorizationHandleV2, ApprovalBindingV2, ApprovalDecisionV2, ApprovalPurposeV2,
    AuthorityHandleKeyV2, AuthorizeToolCallResponseV2, BootIdV2, BoundedApprovalDisplayTextV2,
    BoundedCiphertextV2, BoundedConnectorRegistryDeltaV2, CancelKernelTaskRequestV2,
    CancelKernelTaskResponseV2, ClaimAgentSessionRequestV2, ClaimAgentSessionResponseV2,
    CommitPlannerValueRequestV2, CommitPlannerValueResponseV2, ConnectorRegistrySyncModeV2,
    ConnectorRegistrySyncPageV2, ConnectorRegistrySyncRequestV2, ConnectorRegistrySyncScopeV2,
    ConnectorRegistrySyncStatusV2, ConnectorUiAuthorizationHandleV2, Digest32V2,
    DispatchCoreV2 as ProtocolDispatchCoreV2, DispatchExecutionResponseV2, DispatchRequestV2,
    DispatchSubjectV2 as ProtocolDispatchSubjectV2, DurableRunIdV2, DurableTaskIdV2,
    Ed25519KeyIdV2, EvaluateToolCallRequestV2, EvaluateToolCallResponseV2, ExecutionHandleV2,
    ExecutionStatusTargetV2, ExecutionTicketHandleV2, ExecutorIdentityV2, ExecutorStatusV2,
    FixedBytes32V2, FixedOriginV2, GetAgentSessionStatusRequestV2, GetAgentSessionStatusResponseV2,
    GetExecutionStatusRequestV2, GetExecutionStatusResponseV2, GetKernelTaskStatusRequestV2,
    GetKernelTaskStatusResponseV2, GetReleaseStatusRequestV2, GetReleaseStatusResponseV2,
    HpkeX25519KeyIdV2, KernelIngressBootstrapTransferCapabilityV2, MaskedDocumentHandleV2,
    NewTaskPreparationHandleV2, Nonce32V2, PendingConnectorRegistrationHandleV2,
    PendingReleaseHandleV2, PendingToolCallHandleV2, PlanRevisionDigestV2, PlanStepHandleV2,
    PlannerAbstractSlotV2, PlannerEnvelopeV2, PlannerIntentKindV2, PlannerLimitsV2, PlannerPlanV2,
    PlannerPurposeV2, PlannerRouteIdV2, PlannerSlotCardinalityV2, PlannerSlotConfidentialityV2,
    PlannerSlotRefV2, PlannerTicketHandleV2, PrepareAgentUiAuthenticationRequestV2,
    PrepareAgentUiAuthenticationResponseV2, PrepareConnectorRegistrationRequestV2,
    PrepareConnectorRegistrationResponseV2, PrepareFollowupIngressRequestV2,
    PrepareFollowupIngressResponseV2, PrepareNewIngressRequestV2, PrepareNewIngressResponseV2,
    PreparePlannerCallRequestV2, PreparePlannerCallResponseV2, PrepareReleaseRequestV2,
    PrepareReleaseResponseV2, PrincipalIdV2, ProducerIdentityV2,
    ProposeConnectorRegistrationRequestV2, ProposeConnectorRegistrationResponseV2,
    ProposeToolCallRequestV2, ProposeToolCallResponseV2,
    PublicDecisionTraceV2 as ProtocolDecisionTraceV2, PublicDispatchAcceptedStateV2,
    PublicDispatchCompletionV2, PublicExecutionStatusV2, PublicFailureClassV2, PublicStableCodeV2,
    PublicTaskStatusV2, QueryByExecutionNonceRequestV2, ReadAgentViewRequestV2, ReleaseHandleV2,
    ReleaseKernelApprovalHandleV2, ReleaseStatusTargetV2, ReleaseTicketHandleV2,
    ResumeCommittedAgentAuthenticationRequestV2, ResumeCommittedAgentAuthenticationResponseV2,
    RevokeVaultRequestV2, RoleIdV2, RunRevisionDigestV2, RunRevisionObservationV2,
    SealedExecutionEnvelopePayloadV2, ServiceIdentityV2,
    SignedAgentAuthenticationClosureDescriptorV2, SignedApprovalEnvelopeV2,
    SignedDurableTaskCorrelationV2, SignedSealedExecutionEnvelopeV2,
    SignedUiAuthenticationEnvelopeV2, SignedUiAuthenticationSettlementV2, SlotKindV2,
    StaticTemplateIdV2, ToolClassIdV2, ToolHandleV2, ToolKernelApprovalHandleV2,
    UiAuthenticationBindingV2, UiAuthenticationPurposeV2, UnixMillisV2,
    UnsignedAgentAuthenticationClosureDescriptorV2, UnsignedApprovalEnvelopeV2,
    UnsignedDurableTaskCorrelationV2, UnsignedUiAuthenticationEnvelopeV2, V2DecodeContext,
    ValueHandleV2, MAX_CONNECTOR_REGISTRY_SYNC_PAGE_DELTAS_V2,
    MAX_CONNECTOR_REGISTRY_SYNC_PAGE_DELTA_BYTES_V2,
};
use savana_kernel_protocol::StableCode;
use savana_policy_core::v2::{
    connector_host_allowlist_digest_v2, decode_provenance_record_v2, encode_provenance_record_v2,
    provenance_digest_v2, value_digest_v2, ActiveToolRegistryV2, ClosedCardinalityV2,
    ClosedDeclassificationPurposeV2, ConnectorDescriptorV2, ConnectorRegistryDeltaV2,
    ConnectorRegistryStateV2, ConnectorTierV2, ConnectorTransportV2, DeclassificationTransitionV2,
    DispatchQuotaSubjectV2, DurableG4StateV2, EffectSetV2, G5DecisionBranchV2, HandoffJudgmentV2,
    IdentifierV2, KernelPreparedDispatchV2, KernelValueV2, OntologyExprV2,
    PlannerSlotConfidentialityV2 as PolicySlotConfidentialityV2, PreparedConnectorRegistryDeltaV2,
    ProvenanceContextV2, ProvenanceRecordV2, ResolvedExecutionTicketV2,
    SharedVerifiedConnectorRegistryV2, StoredBindingResolverV2, StoredValueRecordV2,
    TokenSetDigestEntryV2, VerifiedActionIntentMaterialV2, VerifiedEffectGateLeaseV2,
    VerifiedInternalSlotMaterialV2, VerifiedInternalValidatorRegistryV2,
    VerifiedOntologyEvaluationV2, VerifiedPlanArgumentV2, VerifiedPolicyDispositionV2,
    VerifiedProjectionOutputsV2, VerifiedQuotaLimitV2, VerifiedResolvedRelationSetV2,
};
use sha2::{Digest as _, Sha256};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use crate::v2_agent_durable::{
    DurableKernelAgentAuthorityStateV2, KernelAgentAuthorityRollbackAnchorV2,
};
use crate::v2_core_services::KernelIngressCommitSinkV2;
use crate::v2_declassification_policy::ActiveDeclassificationRuleSetV2;
use crate::v2_executor_client::{KernelExecutorClientErrorV2, SuiteOneKernelExecutorClientV2};
use crate::v2_ingress_authority::KernelIngressAuthorityV2;
use crate::v2_value_owner::{KernelValueErrorV2, KernelValueOwnerV2};

const TASK_LOGICAL_TTL_MS: u64 = 30 * 60 * 1_000;
const TASK_STATUS_RETENTION_MS: u64 = 24 * 60 * 60 * 1_000;
const AGENT_UI_AUTH_TTL_MS: u64 = 5 * 60 * 1_000;
const CLAIM_DIGEST_DOMAIN: &[u8] = b"SAVANA_AGENT_INGRESS_CLAIM_V2\0";
const RUN_REVISION_DOMAIN: &[u8] = b"SAVANA_RUN_REVISION_V2\0";
const PLANNER_ROUTE_DOMAIN: &[u8] = b"SAVANA_PLANNER_ROUTE_V2\0";
const PLANNER_OUTPUT_DOMAIN: &[u8] = b"SAVANA_PLANNER_OUTPUT_V2\0";
const PLAN_REVISION_DOMAIN: &[u8] = b"SAVANA_PLAN_REVISION_V2\0";
const INTERNAL_STEP_DOMAIN: &[u8] = b"SAVANA_INTERNAL_PLAN_STEP_V2\0";
const PROJECTION_DESTINATION_DOMAIN: &[u8] = b"SAVANA_KERNEL_DESTINATION_PROJECTION_V2\0";
const PROJECTION_DISPLAY_DOMAIN: &[u8] = b"SAVANA_KERNEL_DISPLAY_PROJECTION_V2\0";
const TOOL_APPROVAL_TTL_MS: u64 = 5 * 60 * 1_000;
const MAX_CONNECTOR_AUTHORIZATIONS_PER_SESSION_V2: usize = 16;
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

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExecutionDeclassificationGateTestObservationV2 {
    ProvenanceDeclassificationRefused,
    HandoffJudgmentRefused,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SignedPlannerPolicyV2 {
    planner_route: PlannerRouteIdV2,
    task_template: StaticTemplateIdV2,
    intent: PlannerIntentKindV2,
    purpose: PlannerPurposeV2,
    limits: PlannerLimitsV2,
    allowed_action_templates: Vec<ActionTemplateIdV2>,
}

impl SignedPlannerPolicyV2 {
    pub(crate) fn from_verified_input(
        envelope: &savana_input_runtime::PlannerEnvelopeV2,
    ) -> Result<Self, KernelAgentAuthorityErrorV2> {
        let intent = match envelope.intent() {
            savana_input_runtime::IntentKindV2::SendMessage => PlannerIntentKindV2::SendMessage,
            savana_input_runtime::IntentKindV2::Search => PlannerIntentKindV2::Search,
            savana_input_runtime::IntentKindV2::SummarizeDocument => {
                PlannerIntentKindV2::SummarizeDocument
            }
            savana_input_runtime::IntentKindV2::StoreRecord => PlannerIntentKindV2::StoreRecord,
        };
        let signed_limits = envelope.effective_limits();
        let limits = PlannerLimitsV2::new(
            signed_limits.maximum_steps(),
            signed_limits.maximum_dependencies_per_step(),
            signed_limits.maximum_arguments_per_step(),
            signed_limits.maximum_encoded_plan_bytes(),
        )
        .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let task_template = StaticTemplateIdV2::new(envelope.task_template());
        if envelope.planner_route().get() == 0 || task_template.get() == 0 {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        let allowed_action_templates = envelope.allowed_action_templates().to_vec();
        if allowed_action_templates.is_empty() {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        Ok(Self {
            planner_route: envelope.planner_route(),
            task_template,
            intent,
            purpose: PlannerPurposeV2::PlannerCall,
            limits,
            allowed_action_templates,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EffectivePlannerPolicyV2 {
    limits: PlannerLimitsV2,
    allowed_action_templates: Vec<ActionTemplateIdV2>,
    allowed_tool_classes: Vec<ToolClassIdV2>,
    task_template: StaticTemplateIdV2,
    intent: PlannerIntentKindV2,
    purpose: PlannerPurposeV2,
}

impl EffectivePlannerPolicyV2 {
    fn validate_committed_plan(
        &self,
        plan: &PlannerPlanV2,
        encoded_len: usize,
    ) -> Result<(), KernelAgentAuthorityErrorV2> {
        let retained_binding = (self.task_template, self.intent, self.purpose);
        if retained_binding.0.get() == 0 || retained_binding.2 != PlannerPurposeV2::PlannerCall {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        if encoded_len
            > usize::try_from(self.limits.maximum_encoded_plan_bytes())
                .map_err(|_| KernelAgentAuthorityErrorV2::LimitExceeded)?
            || plan.steps().len() > usize::from(self.limits.maximum_steps())
        {
            return Err(KernelAgentAuthorityErrorV2::LimitExceeded);
        }
        for step in plan.steps() {
            if step.dependencies().len() > usize::from(self.limits.maximum_dependencies_per_step())
                || step.slot_bindings().len()
                    > usize::from(self.limits.maximum_arguments_per_step())
            {
                return Err(KernelAgentAuthorityErrorV2::LimitExceeded);
            }
            if self
                .allowed_action_templates
                .binary_search(&step.action_template())
                .is_err()
                || self
                    .allowed_tool_classes
                    .binary_search(&step.tool_class())
                    .is_err()
            {
                return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
            }
        }
        Ok(())
    }
}

fn intersect_planner_request(
    policy: &SignedPlannerPolicyV2,
    planner_route: PlannerRouteIdV2,
    task_template: StaticTemplateIdV2,
    intent: PlannerIntentKindV2,
    purpose: PlannerPurposeV2,
    requested: PlannerLimitsV2,
) -> Result<PlannerLimitsV2, KernelAgentAuthorityErrorV2> {
    if planner_route != policy.planner_route
        || task_template != policy.task_template
        || intent != policy.intent
        || purpose != policy.purpose
    {
        return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
    }
    PlannerLimitsV2::new(
        requested.maximum_steps().min(policy.limits.maximum_steps()),
        requested
            .maximum_dependencies_per_step()
            .min(policy.limits.maximum_dependencies_per_step()),
        requested
            .maximum_arguments_per_step()
            .min(policy.limits.maximum_arguments_per_step()),
        requested
            .maximum_encoded_plan_bytes()
            .min(policy.limits.maximum_encoded_plan_bytes()),
    )
    .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)
}

fn presealed_execution_payload_digest(
    exact_plaintext: &[u8],
    declassification_node_digest: Digest32V2,
) -> Digest32V2 {
    savana_kernel_protocol::v2::presealed_tool_payload_digest_v2(
        exact_plaintext,
        declassification_node_digest,
    )
}

fn presealed_final_release_payload_digest(
    exact_plaintext: &[u8],
    declassification_node_digest: Digest32V2,
) -> Digest32V2 {
    savana_kernel_protocol::v2::presealed_release_payload_digest_v2(
        exact_plaintext,
        declassification_node_digest,
    )
}

fn gate_execution_before_durable_prepare<T>(
    exact_plaintext: &[u8],
    declassify_and_authorize_handoff: impl FnOnce() -> Result<
        ProvenanceRecordV2,
        KernelAgentAuthorityErrorV2,
    >,
    synchronize_registry: impl FnOnce() -> Result<(), KernelAgentAuthorityErrorV2>,
    prepare_durable_dispatch: impl FnOnce(Digest32V2) -> Result<T, KernelAgentAuthorityErrorV2>,
) -> Result<(T, ProvenanceRecordV2), KernelAgentAuthorityErrorV2> {
    let declassification = declassify_and_authorize_handoff()?;
    synchronize_registry()?;
    let sealed_payload_digest =
        presealed_execution_payload_digest(exact_plaintext, declassification.provenance_digest());
    let prepared = prepare_durable_dispatch(sealed_payload_digest)?;
    Ok((prepared, declassification))
}

fn gate_final_release_before_durable_prepare<T>(
    exact_plaintext: &[u8],
    declassify_and_authorize_handoff: impl FnOnce() -> Result<
        ProvenanceRecordV2,
        KernelAgentAuthorityErrorV2,
    >,
    synchronize_registry: impl FnOnce() -> Result<(), KernelAgentAuthorityErrorV2>,
    prepare_durable_dispatch: impl FnOnce(Digest32V2) -> Result<T, KernelAgentAuthorityErrorV2>,
) -> Result<(T, ProvenanceRecordV2), KernelAgentAuthorityErrorV2> {
    let declassification = declassify_and_authorize_handoff()?;
    synchronize_registry()?;
    let sealed_payload_digest = presealed_final_release_payload_digest(
        exact_plaintext,
        declassification.provenance_digest(),
    );
    let prepared = prepare_durable_dispatch(sealed_payload_digest)?;
    Ok((prepared, declassification))
}

pub(crate) struct PreparedAgentClaimMaterialV2 {
    durable_run_id: DurableRunIdV2,
    producer_identity: ProducerIdentityV2,
    initial_value: KernelValueV2,
    provenance: ProvenanceRecordV2,
    initial_document: MaskedDocumentHandleV2,
    policy_allowed_effects: EffectSetV2,
    signed_planner_policy: SignedPlannerPolicyV2,
    expires_at: UnixMillisV2,
    /// Consented owner document for kernel-internal fused input derivation.
    /// It is registered only for private sessions, never returned to Agent.
    owner_input: Option<(KernelValueV2, ProvenanceRecordV2)>,
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
    fn matches_exactly(&self, other: &Self) -> Result<bool, KernelAgentAuthorityErrorV2> {
        Ok(self.durable_run_id == other.durable_run_id
            && self.producer_identity == other.producer_identity
            && savana_policy_core::v2::value_digest_v2(&self.initial_value)
                .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?
                == savana_policy_core::v2::value_digest_v2(&other.initial_value)
                    .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?
            && self.provenance == other.provenance
            && self.initial_document == other.initial_document
            && self.policy_allowed_effects == other.policy_allowed_effects
            && self.signed_planner_policy == other.signed_planner_policy
            && self.expires_at == other.expires_at
            && match (&self.owner_input, &other.owner_input) {
                (None, None) => true,
                (Some((a, pa)), Some((b, pb))) => {
                    pa == pb
                        && savana_policy_core::v2::value_digest_v2(a)
                            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?
                            == savana_policy_core::v2::value_digest_v2(b)
                                .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?
                }
                _ => false,
            })
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_verified_ingress(
        durable_run_id: DurableRunIdV2,
        producer_identity: ProducerIdentityV2,
        initial_value: KernelValueV2,
        provenance: ProvenanceRecordV2,
        initial_document: MaskedDocumentHandleV2,
        policy_allowed_effects: EffectSetV2,
        signed_planner_policy: SignedPlannerPolicyV2,
        expires_at: UnixMillisV2,
        owner_input: Option<(KernelValueV2, ProvenanceRecordV2)>,
    ) -> Result<Self, KernelAgentAuthorityErrorV2> {
        if is_zero(durable_run_id.as_bytes())
            || is_zero(producer_identity.as_bytes())
            || expires_at.get() == 0
        {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        if let Some((value, owner)) = &owner_input {
            // Same authenticated ingress, run, manifest and lifetime as the
            // masked agent value; only a GatedIngress source is an owner input.
            if !matches!(
                owner.source_kind(),
                savana_policy_core::v2::SourceKindV2::GatedIngress { .. }
            ) || owner.producer_identity() != producer_identity
                || owner.run_internal_id() != durable_run_id
                || owner.active_state_manifest_digest() != provenance.active_state_manifest_digest()
                || owner.expires_at() != expires_at
                || savana_policy_core::v2::value_digest_v2(value)
                    .map_or(true, |digest| digest != owner.value_digest())
            {
                return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
            }
        }
        Ok(Self {
            durable_run_id,
            producer_identity,
            initial_value,
            provenance,
            initial_document,
            policy_allowed_effects,
            signed_planner_policy,
            expires_at,
            owner_input,
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
    source_input_digest: Option<Digest32V2>,
    task_authorization_digest: Option<Digest32V2>,
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
    signed_planner_policy: SignedPlannerPolicyV2,
    expires_at: UnixMillisV2,
    revision: RunRevisionObservationV2,
    initial_document: MaskedDocumentHandleV2,
    initial_value: ValueHandleV2,
    /// Kernel-internal handle of the consented owner document (private
    /// sessions only). Never returned to Agent, browser or model workers.
    owner_input_value: Option<ValueHandleV2>,
    status: AgentSessionStatusV2,
    task_authorization_digest: Option<Digest32V2>,
}

struct ConnectorAuthorizationRecordV2 {
    authorization_commitment: Digest32V2,
    session_commitment: Digest32V2,
    descriptor_digest: Digest32V2,
    previous_head_digest: Digest32V2,
    principal: PrincipalIdV2,
    durable_task_id: DurableTaskIdV2,
    durable_run_id: DurableRunIdV2,
    origin: FixedOriginV2,
    caller_boot_id: BootIdV2,
    active_state_manifest_digest: Digest32V2,
    deployment_generation: u64,
    issued_at: UnixMillisV2,
    expires_at: UnixMillisV2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConnectorUiSessionContextV2 {
    session: AgentSessionHandleV2,
    principal: PrincipalIdV2,
    durable_task_id: DurableTaskIdV2,
    durable_run_id: DurableRunIdV2,
    caller_boot_id: BootIdV2,
    active_state_manifest_digest: Digest32V2,
    deployment_generation: u64,
    issued_at: UnixMillisV2,
    expires_at: UnixMillisV2,
}

impl ConnectorUiSessionContextV2 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_durable_connector_state(
        session: AgentSessionHandleV2,
        principal: PrincipalIdV2,
        durable_task_id: DurableTaskIdV2,
        durable_run_id: DurableRunIdV2,
        caller_boot_id: BootIdV2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        issued_at: UnixMillisV2,
        expires_at: UnixMillisV2,
    ) -> Result<Self, KernelAgentAuthorityErrorV2> {
        if is_zero(principal.as_bytes())
            || is_zero(durable_task_id.as_bytes())
            || is_zero(durable_run_id.as_bytes())
            || is_zero(caller_boot_id.as_bytes())
            || is_zero(active_state_manifest_digest.as_bytes())
            || deployment_generation == 0
            || issued_at.get() == 0
            || issued_at.get() >= expires_at.get()
        {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        Ok(Self {
            session,
            principal,
            durable_task_id,
            durable_run_id,
            caller_boot_id,
            active_state_manifest_digest,
            deployment_generation,
            issued_at,
            expires_at,
        })
    }

    pub(crate) const fn session(&self) -> AgentSessionHandleV2 {
        self.session
    }

    pub(crate) const fn principal(&self) -> PrincipalIdV2 {
        self.principal
    }

    pub(crate) const fn durable_task_id(&self) -> DurableTaskIdV2 {
        self.durable_task_id
    }

    pub(crate) const fn durable_run_id(&self) -> DurableRunIdV2 {
        self.durable_run_id
    }

    pub(crate) const fn caller_boot_id(&self) -> BootIdV2 {
        self.caller_boot_id
    }

    pub(crate) const fn active_state_manifest_digest(&self) -> Digest32V2 {
        self.active_state_manifest_digest
    }

    pub(crate) const fn deployment_generation(&self) -> u64 {
        self.deployment_generation
    }

    pub(crate) const fn issued_at(&self) -> UnixMillisV2 {
        self.issued_at
    }

    pub(crate) const fn expires_at(&self) -> UnixMillisV2 {
        self.expires_at
    }
}

#[derive(Debug, Clone)]
pub(crate) struct PreparedConnectorRegistrationProposalV2 {
    authorization_commitment: Digest32V2,
    session: ConnectorUiSessionContextV2,
    caller_identity: ServiceIdentityV2,
    canonical_descriptor: Vec<u8>,
    descriptor_digest: Digest32V2,
    previous_head_digest: Digest32V2,
    envelope: SignedApprovalEnvelopeV2,
    display_authentication: SignedUiAuthenticationEnvelopeV2,
    envelope_digest: Digest32V2,
    decision_challenge: Nonce32V2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ConnectorSecurityVerifiersV2 {
    pub(crate) installation_id: Digest32V2,
    pub(crate) settlement_key_id: Ed25519KeyIdV2,
    pub(crate) settlement_public_key: [u8; 32],
    pub(crate) envelope_key_id: Ed25519KeyIdV2,
    pub(crate) envelope_public_key: [u8; 32],
}

impl PreparedConnectorRegistrationProposalV2 {
    pub(crate) const fn authorization_commitment(&self) -> Digest32V2 {
        self.authorization_commitment
    }

    pub(crate) const fn session(&self) -> &ConnectorUiSessionContextV2 {
        &self.session
    }

    pub(crate) const fn caller_identity(&self) -> ServiceIdentityV2 {
        self.caller_identity
    }

    pub(crate) fn canonical_descriptor(&self) -> &[u8] {
        &self.canonical_descriptor
    }

    pub(crate) const fn descriptor_digest(&self) -> Digest32V2 {
        self.descriptor_digest
    }

    pub(crate) const fn previous_head_digest(&self) -> Digest32V2 {
        self.previous_head_digest
    }

    pub(crate) const fn envelope(&self) -> &SignedApprovalEnvelopeV2 {
        &self.envelope
    }

    pub(crate) const fn display_authentication(&self) -> &SignedUiAuthenticationEnvelopeV2 {
        &self.display_authentication
    }

    pub(crate) const fn envelope_digest(&self) -> Digest32V2 {
        self.envelope_digest
    }

    pub(crate) const fn decision_challenge(&self) -> Nonce32V2 {
        self.decision_challenge
    }
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
    effective_policy: EffectivePlannerPolicyV2,
    prompt_values: Vec<savana_kernel_protocol::v2::ValueHandleV2>,
    slot_bindings: Vec<PlannerSlotBindingRecordV2>,
    envelope_nonce: Nonce32V2,
    envelope_digest: Digest32V2,
    declassification_provenance_digest: Digest32V2,
    expires_at: UnixMillisV2,
    consumed: bool,
    task_authorization_digest: Digest32V2,
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

#[derive(Clone)]
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
    task_authorization_digest: Digest32V2,
    proposer_parent: Digest32V2,
    arguments: Vec<PlanArgumentRecordV2>,
    /// Owner-signed result-derived controls for this step, by field name. Empty
    /// for the agent path and for steps with no result edge into a control
    /// field; G4 uses them to build the match alternative under the derived rule.
    derived_controls: Vec<(String, savana_kernel_protocol::v2::ResultDerivedControlV2)>,
}

struct PreparedToolIntentV2 {
    material: VerifiedActionIntentMaterialV2,
    recipe_slots: Vec<VerifiedInternalSlotMaterialV2>,
    policy_binding: savana_policy_core::v2::ToolExecutionSemanticBindingV2,
    semantic_binding: savana_kernel_protocol::v2::ToolExecutionSemanticBindingV2,
    task_match: savana_policy_core::v2::VerifiedTaskMatchV2,
    control_selections: [savana_policy_core::v2::ControlSelectionV2; 7],
    business_request: savana_kernel_protocol::v2::BusinessRequestV2,
    dispatch_plaintext: Vec<u8>,
    display_plaintext: Vec<u8>,
    provenance_parents: Vec<ProvenanceRecordV2>,
    policy_allowed_effects: EffectSetV2,
}

#[derive(Clone)]
struct IntentRecordV2 {
    fused: Option<fused_actions::FusedIntentBindingV04>,
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
    // Retained for the record's own audit shape. Both are already bound into
    // `policy_binding`, and the authority reads them from there.
    #[allow(dead_code)]
    plan_revision_digest: PlanRevisionDigestV2,
    #[allow(dead_code)]
    internal_step_id: savana_kernel_protocol::v2::InternalStepIdV2,
    policy_binding: savana_policy_core::v2::ToolExecutionSemanticBindingV2,
    semantic_binding: savana_kernel_protocol::v2::ToolExecutionSemanticBindingV2,
    task_match: savana_policy_core::v2::VerifiedTaskMatchV2,
    control_selections: [savana_policy_core::v2::ControlSelectionV2; 7],
    business_request: savana_kernel_protocol::v2::BusinessRequestV2,
    dispatch_plaintext: Vec<u8>,
    display_plaintext: Vec<u8>,
    provenance_parents: Vec<ProvenanceRecordV2>,
    policy_allowed_effects: EffectSetV2,
    arguments: Vec<PlanArgumentRecordV2>,
    /// The step's owner-signed result-derived rules; the display must be
    /// re-rendered under them to re-verify the stored approval text.
    derived_controls: Vec<(String, savana_kernel_protocol::v2::ResultDerivedControlV2)>,
    state: IntentRecordStateV2,
    decision_trace: Option<Digest32V2>,
    ticket_commitment: Option<Digest32V2>,
    approval_commitment: Option<Digest32V2>,
    approval_settlement: Option<savana_policy_core::v2::VerifiedToolApprovalSettlementV2>,
    task_action_approval: Option<savana_kernel_protocol::v2::VerifiedTaskActionApprovalV2>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum IntentRecordStateV2 {
    Proposed,
    // Mapped to the public `ActionIntentCurrentStateV2::Evaluating` but never
    // entered: G5 evaluation completes inside one owner-thread operation, so a
    // record moves from `Proposed` straight to `Denied`, `AwaitingApproval`, or
    // `Authorized`. The variant is kept so the public projection stays total.
    #[allow(dead_code)]
    Evaluating,
    Denied,
    AwaitingApproval,
    Authorized,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum IntentAccessV2 {
    LegacyAgent,
    PrivateFused,
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
    ticket_commitment: Option<Digest32V2>,
    // Authenticated historical result scope; present for private executions,
    // including recovery with no volatile session/intent/ticket at all.
    fused_recovery: Option<savana_policy_core::v2::RecoveredFusedExecutionV04>,
    action_intent_id: ActionIntentIdV2,
    active_state_manifest_digest: Digest32V2,
    deployment_generation: u64,
    effect_fence_epoch: u64,
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
    private_candidate: Option<Digest32V2>,
    display_authentication: SignedUiAuthenticationEnvelopeV2,
    // The handles are held so the record owns them for its lifetime; the
    // release path authenticates against the commitments below instead.
    #[allow(dead_code)]
    pending: PendingReleaseHandleV2,
    pending_commitment: Digest32V2,
    #[allow(dead_code)]
    approval: ReleaseKernelApprovalHandleV2,
    approval_commitment: Digest32V2,
    document: Option<MaskedDocumentHandleV2>,
    #[allow(dead_code)]
    run: savana_kernel_protocol::v2::RunHandleV2,
    durable_run_id: DurableRunIdV2,
    durable_task_id: DurableTaskIdV2,
    principal: PrincipalIdV2,
    business_request: savana_kernel_protocol::v2::BusinessRequestV2,
    task_match: savana_policy_core::v2::VerifiedTaskMatchV2,
    control_selections: [savana_policy_core::v2::ControlSelectionV2; 7],
    envelope: SignedApprovalEnvelopeV2,
    task_action_approval: Option<savana_kernel_protocol::v2::VerifiedTaskActionApprovalV2>,
    provenance_parents: Vec<ProvenanceRecordV2>,
    policy_allowed_effects: EffectSetV2,
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
    // Endpoint implementations are trusted deployment adapters, not Agent data.
    // Empty in production until the explicitly deferred cloud adapter exists.
    fused_workers: Vec<Box<dyn savana_policy_core::v2::FusedModelTransportV04 + Send>>,
    fused_last_task: Option<DurableTaskIdV2>,
    fused_workflow_phase: u8,
    fused_action_last_task: Option<[u8; 32]>,
    fused_action_not_before: u64,
    fused_release_last_task: Option<[u8; 32]>,
    fused_release_not_before: u64,
    fused_approval_client: Option<savana_approvald::ApprovalSuiteOneClientV2>,
    fused_recovery_last_nonce: Option<[u8; 32]>,
    fused_recovery_not_before: u64,
    fused_cleanup_confirmed: std::collections::BTreeSet<[u8; 32]>,
    declassification_rules: ActiveDeclassificationRuleSetV2,
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
    connector_registry: SharedVerifiedConnectorRegistryV2,
    connector_registry_genesis_digest: Digest32V2,
    connector_authority_key_id: Ed25519KeyIdV2,
    connector_authority_public_key: [u8; 32],
    connector_authority_signing_key: Option<SigningKey>,
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
        connector_registry_genesis_digest: Digest32V2,
        connector_authority_key_id: Ed25519KeyIdV2,
        connector_authority_public_key: [u8; 32],
        connector_authority_signing_key: Option<SigningKey>,
        connector_registry: SharedVerifiedConnectorRegistryV2,
        effect_ledger_projection: savana_kernel_protocol::v2::VerifiedEffectLedgerProjectionV2,
        envelope_signing_key: SigningKey,
        executor_receipt_key_id: Ed25519KeyIdV2,
        executor_receipt_public_key: [u8; 32],
        executor: SuiteOneKernelExecutorClientV2,
    ) -> Result<Self, KernelAgentAuthorityErrorV2> {
        let registry = connector_registry
            .snapshot()
            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let authority_disabled = is_zero(connector_authority_key_id.as_bytes())
            && is_zero(&connector_authority_public_key)
            && connector_authority_signing_key.is_none();
        let authority_enabled = !is_zero(connector_authority_key_id.as_bytes())
            && !is_zero(&connector_authority_public_key)
            && connector_authority_signing_key
                .as_ref()
                .is_some_and(|signing_key| {
                    let private_key = signing_key.to_bytes();
                    let envelope_private_key = envelope_signing_key.to_bytes();
                    let envelope_public_key = envelope_signing_key.verifying_key().to_bytes();
                    private_key != [0; 32]
                        && private_key != connector_authority_public_key
                        && signing_key.verifying_key().to_bytes() == connector_authority_public_key
                        && derive_ed25519_key_id_v2(connector_authority_public_key)
                            == connector_authority_key_id
                        && private_key != envelope_private_key
                        && private_key != envelope_public_key
                        && connector_authority_public_key != envelope_private_key
                        && connector_authority_public_key != envelope_public_key
                });
        if quota_limit == 0
            || [
                quota_policy_digest,
                Digest32V2::new(*executor_identity.as_bytes()),
                Digest32V2::new(*executor_key_id.as_bytes()),
                connector_registry_genesis_digest,
                effect_ledger_projection.authenticated_head_digest(),
                effect_ledger_projection.projection_identity(),
            ]
            .iter()
            .any(|digest| is_zero(digest.as_bytes()))
            || hpke_x25519_key_id(executor_seal_public_key) != executor_key_id
            || derive_ed25519_key_id_v2(executor_receipt_public_key) != executor_receipt_key_id
            || (!authority_disabled && !authority_enabled)
            || registry.genesis_digest() != connector_registry_genesis_digest
            || registry.connector_authority_public_key() != connector_authority_public_key
            || connector_authority_signing_key
                .as_ref()
                .is_some_and(|signing_key| {
                    let private_key = signing_key.to_bytes();
                    private_key == executor_seal_public_key
                        || private_key == executor_receipt_public_key
                        || connector_authority_public_key == executor_seal_public_key
                        || connector_authority_public_key == executor_receipt_public_key
                })
        {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        Ok(Self {
            quota_limit,
            quota_policy_digest,
            executor_identity,
            executor_key_id,
            executor_seal_public_key,
            connector_registry,
            connector_registry_genesis_digest,
            connector_authority_key_id,
            connector_authority_public_key,
            connector_authority_signing_key,
            effect_ledger_projection,
            envelope_signing_key,
            executor_receipt_key_id,
            executor_receipt_public_key,
            executor,
        })
    }

    fn synchronize_connector_registry(
        &self,
        installation_id: Digest32V2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        now: UnixMillisV2,
    ) -> Result<(), KernelAgentAuthorityErrorV2> {
        let source = self
            .connector_registry
            .snapshot()
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        if source.genesis_digest() != self.connector_registry_genesis_digest
            || source.connector_authority_public_key() != self.connector_authority_public_key
        {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        let scope = ConnectorRegistrySyncScopeV2::new(
            installation_id,
            active_state_manifest_digest,
            deployment_generation,
            source.genesis_digest(),
            self.connector_authority_key_id,
            FixedBytes32V2::new(self.connector_authority_public_key),
            connector_host_allowlist_digest_v2(source.user_host_allowlist())
                .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?,
        )
        .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let deadline = checked_deadline(now, 5_000)?;
        let probe = ConnectorRegistrySyncRequestV2::new(scope, ConnectorRegistrySyncModeV2::Probe)
            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let mut response = self
            .executor
            .synchronize_connector_registry(connector_sync_request_id()?, deadline, probe)
            .map_err(map_executor_client_error)?;
        validate_connector_registry_sync_observation_v2(&source, response)?;

        if !scope.authority_enabled() {
            if source.sequence() != 0
                || source.head_digest() != source.genesis_digest()
                || response.status() != ConnectorRegistrySyncStatusV2::DisabledGenesisOnly
                || response.local_sequence() != 0
                || response.local_head_digest() != source.genesis_digest()
            {
                return Err(KernelAgentAuthorityErrorV2::StateConflict);
            }
            return Ok(());
        }
        if response.status() == ConnectorRegistrySyncStatusV2::DisabledGenesisOnly
            || response.status() == ConnectorRegistrySyncStatusV2::Diverged
        {
            return Err(KernelAgentAuthorityErrorV2::StateConflict);
        }
        if response.local_sequence() == source.sequence() {
            return if response.local_head_digest() == source.head_digest() {
                Ok(())
            } else {
                Err(KernelAgentAuthorityErrorV2::BindingMismatch)
            };
        }
        if response.status() != ConnectorRegistrySyncStatusV2::Behind {
            return Err(KernelAgentAuthorityErrorV2::StateConflict);
        }

        let mut page_count = 0usize;
        while response.local_sequence() < source.sequence() {
            page_count = page_count
                .checked_add(1)
                .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?;
            if page_count > 4_096 {
                return Err(KernelAgentAuthorityErrorV2::LimitExceeded);
            }
            let page = build_connector_registry_sync_page_v2(
                &source,
                response.local_sequence(),
                response.local_head_digest(),
            )?;
            let expected_sequence = page.page_final_sequence();
            let expected_head = page.page_final_head_digest();
            let source_complete = expected_sequence == source.sequence();
            let apply = ConnectorRegistrySyncRequestV2::new(
                scope,
                ConnectorRegistrySyncModeV2::ApplyPage(page),
            )
            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
            response = self
                .executor
                .synchronize_connector_registry(connector_sync_request_id()?, deadline, apply)
                .map_err(map_executor_client_error)?;
            validate_connector_registry_sync_observation_v2(&source, response)?;
            if response.local_sequence() != expected_sequence
                || response.local_head_digest() != expected_head
                || (source_complete
                    && response.status() != ConnectorRegistrySyncStatusV2::Converged)
                || (!source_complete && response.status() != ConnectorRegistrySyncStatusV2::Behind)
            {
                return Err(KernelAgentAuthorityErrorV2::StateConflict);
            }
        }
        Ok(())
    }
}

fn connector_registry_head_at_sequence_v2(
    source: &ConnectorRegistryStateV2,
    sequence: u64,
) -> Result<Digest32V2, KernelAgentAuthorityErrorV2> {
    if sequence > source.sequence() {
        return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
    }
    if sequence == 0 {
        return Ok(source.genesis_digest());
    }
    if sequence == source.sequence() {
        return Ok(source.head_digest());
    }
    let next_delta_index =
        usize::try_from(sequence).map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
    let next_delta = source
        .deltas()
        .get(next_delta_index)
        .ok_or(KernelAgentAuthorityErrorV2::BindingMismatch)?;
    if next_delta.sequence() != sequence.saturating_add(1) {
        return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
    }
    Ok(next_delta.previous_head_digest())
}

fn validate_connector_registry_sync_observation_v2(
    source: &ConnectorRegistryStateV2,
    response: savana_kernel_protocol::v2::ConnectorRegistrySyncResponseV2,
) -> Result<(), KernelAgentAuthorityErrorV2> {
    if response.status() == ConnectorRegistrySyncStatusV2::Diverged
        || response.local_sequence() > source.sequence()
        || connector_registry_head_at_sequence_v2(source, response.local_sequence())?
            != response.local_head_digest()
    {
        return Err(KernelAgentAuthorityErrorV2::StateConflict);
    }
    Ok(())
}

fn build_connector_registry_sync_page_v2(
    source: &ConnectorRegistryStateV2,
    base_sequence: u64,
    base_head_digest: Digest32V2,
) -> Result<ConnectorRegistrySyncPageV2, KernelAgentAuthorityErrorV2> {
    if base_sequence >= source.sequence()
        || connector_registry_head_at_sequence_v2(source, base_sequence)? != base_head_digest
    {
        return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
    }
    let start =
        usize::try_from(base_sequence).map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
    let remaining = source
        .deltas()
        .get(start..)
        .ok_or(KernelAgentAuthorityErrorV2::BindingMismatch)?;
    let mut total_bytes = 0usize;
    let mut deltas = Vec::new();
    deltas
        .try_reserve(
            remaining
                .len()
                .min(MAX_CONNECTOR_REGISTRY_SYNC_PAGE_DELTAS_V2),
        )
        .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
    for delta in remaining {
        if deltas.len() == MAX_CONNECTOR_REGISTRY_SYNC_PAGE_DELTAS_V2 {
            break;
        }
        let next_total = total_bytes
            .checked_add(delta.canonical_bytes().len())
            .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?;
        if next_total > MAX_CONNECTOR_REGISTRY_SYNC_PAGE_DELTA_BYTES_V2 {
            if deltas.is_empty() {
                return Err(KernelAgentAuthorityErrorV2::LimitExceeded);
            }
            break;
        }
        let expected_sequence = base_sequence
            .checked_add(
                u64::try_from(deltas.len())
                    .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?,
            )
            .and_then(|sequence| sequence.checked_add(1))
            .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?;
        if delta.sequence() != expected_sequence
            || delta.previous_head_digest()
                != connector_registry_head_at_sequence_v2(source, expected_sequence - 1)?
        {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        deltas.push(
            BoundedConnectorRegistryDeltaV2::new(delta.canonical_bytes().to_vec())
                .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?,
        );
        total_bytes = next_total;
    }
    let page_final_sequence = base_sequence
        .checked_add(
            u64::try_from(deltas.len()).map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?,
        )
        .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?;
    ConnectorRegistrySyncPageV2::new(
        base_sequence,
        base_head_digest,
        page_final_sequence,
        connector_registry_head_at_sequence_v2(source, page_final_sequence)?,
        source.sequence(),
        source.head_digest(),
        deltas,
    )
    .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)
}

impl KernelG4G5RuntimeV2 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_verified_policy(
        declassification_rules: ActiveDeclassificationRuleSetV2,
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
            fused_workers: Vec::new(),
            fused_last_task: None,
            fused_workflow_phase: 0,
            fused_action_last_task: None,
            fused_action_not_before: 0,
            fused_release_last_task: None,
            fused_release_not_before: 0,
            fused_approval_client: None,
            fused_recovery_last_nonce: None,
            fused_recovery_not_before: 0,
            fused_cleanup_confirmed: std::collections::BTreeSet::new(),
            declassification_rules,
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

    pub(crate) fn install_fused_workers_v04(
        &mut self,
        workers: Vec<savana_agentd::UnixMtlsFusedModelTransportV04>,
    ) -> Result<(), KernelAgentAuthorityErrorV2> {
        use savana_policy_core::v2::FusedModelTransportV04;
        let identities: std::collections::BTreeSet<_> =
            workers.iter().map(|w| w.recipient_identity()).collect();
        if !self.fused_workers.is_empty()
            || workers.len() > 8
            || identities.len() != workers.len()
            || identities.contains(&[0; 32])
        {
            return Err(KernelAgentAuthorityErrorV2::StateConflict);
        }
        self.fused_workers = workers
            .into_iter()
            .map(|w| Box::new(w) as Box<dyn FusedModelTransportV04 + Send>)
            .collect();
        Ok(())
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
    connector_authorizations: Vec<ConnectorAuthorizationRecordV2>,
    planner_tickets: Vec<PlannerTicketRecordV2>,
    tools: Vec<ToolRecordV2>,
    plan_steps: Vec<PlanStepRecordV2>,
    intents: Vec<IntentRecordV2>,
    execution_tickets: Vec<ExecutionTicketRecordV2>,
    executions: Vec<ExecutionRecordV2>,
    tool_approvals: Vec<ToolApprovalRecordV2>,
    fused_approval_recovery: Vec<fused_approval_recovery::FusedApprovalRecoveryV04>,
    fused_release_recovery: Vec<fused_release_recovery::FusedReleaseRecoveryV04>,
    private_session_authentications: Vec<private_session::PrivateSessionAuthenticationV04>,
    pending_releases: Vec<PendingReleaseRecordV2>,
    release_tickets: Vec<ReleaseTicketRecordV2>,
    releases: Vec<ReleaseRecordV2>,
    policy: Option<KernelG4G5RuntimeV2>,
    task_issuer: Option<crate::v2_task_authority::KernelTaskAuthorizationIssuerV2>,
    managed_resource_issuer: Option<crate::v2_managed_resource::KernelManagedResourceIssuerV04>,
    managed_admin: Option<crate::v04_managed_admin::AdminTrustV04>,
    durable_state: Option<DurableKernelAgentAuthorityStateV2>,
    durable_poisoned: bool,
    #[cfg(test)]
    execution_declassification_gate_test_observation:
        Option<ExecutionDeclassificationGateTestObservationV2>,
    #[cfg(test)]
    fused_recovery_fault: Option<fused_actions::FusedRecoveryFaultV04>,
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
            .field(
                "connector_authorization_count",
                &self.connector_authorizations.len(),
            )
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
    pub(crate) fn task_authorization_context(
        &self,
        subject: &crate::v2_input_owner::AuthenticatedTaskContextSubjectV2,
        now: UnixMillisV2,
    ) -> Result<
        savana_kernel_protocol::v2::TaskAuthorizationContextV2,
        crate::v2_task_authority::TaskAuthorityErrorV2,
    > {
        use crate::v2_task_authority::TaskAuthorityErrorV2 as E;
        use savana_kernel_protocol::v2::{
            TaskAuthorizationContextV2, TaskAuthorizationToolContextV2,
        };
        self.ensure_durable_available()
            .map_err(|_| E::Unavailable)?;
        let p = self.policy.as_ref().ok_or(E::Unavailable)?;
        let auth = subject.authorization();
        let task = auth.durable_task_id().ok_or(E::Binding)?;
        let current = p
            .durable
            .find_task_authorization_state(task)
            .map_err(|_| E::State)?;
        let mut identity = None;
        let mut source = subject.source();
        if let Some(state) = &current {
            let m = state.authorization().material();
            if state.revoked()
                || m.principal() != auth.authenticated_principal()
                || m.installation_digest() != auth.installation_id()
                || m.manifest_digest() != auth.active_state_manifest_digest()
            {
                return Err(E::Binding);
            }
            identity = Some((
                m.authorization_id(),
                m.revision().checked_add(1).ok_or(E::State)?,
            ));
            if source.is_none() {
                source = Some(
                    p.durable
                        .installed_task_authorization_draft(state.authorization().digest())
                        .map_err(|_| E::State)?
                        .ok_or(E::State)?
                        .source_input_digest(),
                );
            }
        }
        let mut pending = Vec::new();
        let previous = current.as_ref().map(|s| s.authorization().digest());
        for record in p
            .durable
            .task_authorization_issuance_history(task)
            .map_err(|_| E::State)?
        {
            let draft = record.draft();
            if draft.principal() != auth.authenticated_principal()
                || draft.installation_digest() != auth.installation_id()
            {
                return Err(E::Binding);
            }
            // Preserve identity even for expired first proposals: retry cannot
            // create a fresh root identity and erase durable accounting/history.
            if identity.is_none() {
                identity = Some((draft.authorization_id(), 1));
            }
            if record.installed_digest().is_none()
                && record.previous_authorization() == previous
                && identity == Some((draft.authorization_id(), draft.revision()))
                && draft.manifest_digest() == auth.active_state_manifest_digest()
                && draft.deployment_generation() == auth.deployment_generation()
                && now.get() >= draft.not_before().get()
                && now.get() < draft.expires_at().get()
                && p.active_tools
                    .validate_task_draft_profiles(draft, p.role, now)
                    .is_ok()
            {
                if source.is_none() {
                    source = Some(draft.source_input_digest());
                }
                pending.push(record.request_digest());
            }
        }
        let mut tools = Vec::new();
        for r in p.active_tools.records() {
            let descriptor = r.descriptor();
            if p.active_tools
                .resolve(descriptor.descriptor_digest(), p.role, now)
                .is_none()
            {
                continue;
            }
            let Ok(profile) = descriptor.unsigned().require_business_profile() else {
                continue;
            };
            tools.push(
                TaskAuthorizationToolContextV2::new(
                    descriptor.descriptor_digest(),
                    descriptor.unsigned().provider_tool_id().as_str().into(),
                    profile.clone(),
                )
                .map_err(|_| E::Binding)?,
            );
        }
        tools.sort_by_key(|t| *t.descriptor_digest().as_bytes());
        pending.sort_by_key(|d| *d.as_bytes());
        TaskAuthorizationContextV2::new(
            auth.authenticated_principal(),
            task,
            auth.installation_id(),
            auth.active_state_manifest_digest(),
            auth.deployment_generation(),
            source.ok_or(E::State)?,
            now,
            auth.expires_at(),
            identity,
            tools,
            pending,
        )
        .map_err(|_| E::Binding)
    }
    pub(crate) fn revoke_task_authorization(
        &mut self,
        request: &savana_kernel_protocol::v2::RevokeTaskAuthorizationRequestV2,
        proof: &crate::v2_input_owner::AuthenticatedTaskDraftSubmissionV2,
        now: UnixMillisV2,
    ) -> Result<
        savana_kernel_protocol::v2::RevokeTaskAuthorizationResponseV2,
        crate::v2_task_authority::TaskAuthorityErrorV2,
    > {
        use crate::v2_task_authority::TaskAuthorityErrorV2 as E;
        self.ensure_durable_available()
            .map_err(|_| E::Unavailable)?;
        let digest = self.task_issuer.as_ref().ok_or(E::Unavailable)?.revoke(
            &mut self.policy.as_mut().ok_or(E::Unavailable)?.durable,
            proof,
            request.draft(),
            now,
        )?;
        for s in &mut self.sessions {
            if s.durable_task_id == request.draft().task()
                && s.principal == request.draft().principal()
            {
                s.status = AgentSessionStatusV2::Closed;
            }
        }
        // The durable G4 revocation is authoritative even if this subsequent
        // status write is interrupted. Existing effect history is never erased.
        if let Some(t) = self
            .tasks
            .iter_mut()
            .find(|t| t.durable_task_id == request.draft().task())
        {
            t.task_authorization_digest = Some(digest);
            if matches!(
                t.status,
                PublicTaskStatusV2::AwaitingInput
                    | PublicTaskStatusV2::Processing
                    | PublicTaskStatusV2::AwaitingIngressApproval
                    | PublicTaskStatusV2::Ready { .. }
            ) {
                t.status = PublicTaskStatusV2::Cancelled;
            }
        }
        self.persist_recovery_snapshot()
            .map_err(|_| E::Unavailable)?;
        savana_kernel_protocol::v2::RevokeTaskAuthorizationResponseV2::new(digest)
            .map_err(|_| E::Binding)
    }
    pub(crate) fn recover_task_issuance_record(
        &self,
        request: Digest32V2,
    ) -> Result<
        savana_policy_core::v2::PendingTaskAuthorizationV2,
        crate::v2_task_authority::TaskAuthorityErrorV2,
    > {
        use crate::v2_task_authority::TaskAuthorityErrorV2 as E;
        self.ensure_durable_available()
            .map_err(|_| E::Unavailable)?;
        self.policy
            .as_ref()
            .ok_or(E::Unavailable)?
            .durable
            .pending_task_authorization(request)
            .map_err(|_| E::State)?
            .cloned()
            .ok_or(E::State)
    }

    pub(crate) fn validate_task_issuance_recovery(
        &self,
        pending: &savana_policy_core::v2::PendingTaskAuthorizationV2,
        now: UnixMillisV2,
    ) -> Result<(), crate::v2_task_authority::TaskAuthorityErrorV2> {
        use crate::v2_task_authority::TaskAuthorityErrorV2 as E;
        let p = self.policy.as_ref().ok_or(E::Unavailable)?;
        p.active_tools
            .validate_task_draft_profiles(pending.draft(), p.role, now)
            .map_err(|_| E::Binding)?;
        if let Some(digest) = pending.installed_digest() {
            let state = p
                .durable
                .task_authorization_state(pending.draft().task())
                .map_err(|_| E::State)?;
            if state.revoked() || state.authorization().digest() != digest {
                return Err(E::State);
            }
        } else {
            // A pending amendment cannot be revived after a different revision
            // was installed (or the predecessor was revoked).
            let current = p
                .durable
                .find_task_authorization_state(pending.draft().task())
                .map_err(|_| E::State)?;
            if current.as_ref().is_some_and(|s| s.revoked())
                || current.map(|s| s.authorization().digest()) != pending.previous_authorization()
            {
                return Err(E::State);
            }
            self.task_issuer
                .as_ref()
                .ok_or(E::Unavailable)?
                .verify_recovered_display(pending, now)?;
        }
        Ok(())
    }

    pub(crate) fn prepare_task_approval(
        &mut self,
        request: &savana_kernel_protocol::v2::PrepareTaskAuthorizationApprovalRequestV2,
        proof: &crate::v2_input_owner::AuthenticatedTaskDraftSubmissionV2,
        now: UnixMillisV2,
    ) -> Result<
        savana_policy_core::v2::PendingTaskAuthorizationV2,
        crate::v2_task_authority::TaskAuthorityErrorV2,
    > {
        use crate::v2_task_authority::TaskAuthorityErrorV2;
        let issuer = self
            .task_issuer
            .as_ref()
            .ok_or(TaskAuthorityErrorV2::Unavailable)?;
        let policy = self
            .policy
            .as_mut()
            .ok_or(TaskAuthorityErrorV2::Unavailable)?;
        let d = request.draft();
        let id = domain_digest(
            b"SAVANA_TASK_ISSUANCE_REQUEST_V2_SCHEMA1\0",
            &[
                d.installation_digest().as_bytes(),
                d.task().as_bytes(),
                d.principal().as_bytes(),
                request.request_nonce().as_bytes(),
            ],
        );
        let pending = issuer.prepare(
            &mut policy.durable,
            &policy.active_tools,
            policy.role,
            proof,
            d.clone(),
            id,
            now,
        )?;
        if pending.installed_digest().is_some() {
            return Err(TaskAuthorityErrorV2::State);
        }
        Ok(pending)
    }

    pub(crate) fn attach_task_approval(
        &mut self,
        request: Digest32V2,
        envelope: SignedApprovalEnvelopeV2,
        display: SignedUiAuthenticationEnvelopeV2,
        manifest: Digest32V2,
        generation: u64,
        now: UnixMillisV2,
    ) -> Result<(), crate::v2_task_authority::TaskAuthorityErrorV2> {
        use crate::v2_task_authority::TaskAuthorityErrorV2;
        self.task_issuer
            .as_ref()
            .ok_or(TaskAuthorityErrorV2::Unavailable)?
            .attach_approval(
                &mut self
                    .policy
                    .as_mut()
                    .ok_or(TaskAuthorityErrorV2::Unavailable)?
                    .durable,
                request,
                envelope,
                display,
                manifest,
                generation,
                now,
            )
    }

    pub(crate) fn commit_task_approval(
        &mut self,
        request: &savana_kernel_protocol::v2::CommitTaskAuthorizationApprovalRequestV2,
        manifest: Digest32V2,
        generation: u64,
        now: UnixMillisV2,
    ) -> Result<
        savana_kernel_protocol::v2::EstablishTaskAuthorizationResponseV2,
        crate::v2_task_authority::TaskAuthorityErrorV2,
    > {
        use crate::v2_task_authority::TaskAuthorityErrorV2;
        let issuer = self
            .task_issuer
            .as_ref()
            .ok_or(TaskAuthorityErrorV2::Unavailable)?;
        let p = self
            .policy
            .as_mut()
            .ok_or(TaskAuthorityErrorV2::Unavailable)?;
        let digest = issuer.settle_approved(
            &mut p.durable,
            &p.active_tools,
            p.role,
            request.request_digest(),
            request.settlement(),
            manifest,
            generation,
            now,
        )?;
        let draft = p
            .durable
            .pending_task_authorization(request.request_digest())
            .map_err(|_| TaskAuthorityErrorV2::State)?
            .ok_or(TaskAuthorityErrorV2::State)?
            .draft();
        let task = draft.task();
        let principal = draft.principal();
        // Exact retries may return an historical installation receipt, but may
        // never revive a revoked/replaced grant or move a session backwards.
        self.activate_task_authorization(task, principal, digest, now)?;
        savana_kernel_protocol::v2::EstablishTaskAuthorizationResponseV2::new(
            request.request_digest(),
            digest,
        )
        .map_err(|_| TaskAuthorityErrorV2::Binding)
    }

    pub(crate) fn install_task_issuer(
        &mut self,
        issuer: crate::v2_task_authority::KernelTaskAuthorizationIssuerV2,
    ) -> Result<(), KernelAgentAuthorityErrorV2> {
        if self.task_issuer.is_some() {
            return Err(KernelAgentAuthorityErrorV2::StateConflict);
        }
        self.task_issuer = Some(issuer);
        Ok(())
    }

    pub(crate) fn install_managed_resource_issuer(
        &mut self,
        issuer: crate::v2_managed_resource::KernelManagedResourceIssuerV04,
    ) -> Result<(), KernelAgentAuthorityErrorV2> {
        if self.managed_resource_issuer.is_some() {
            return Err(KernelAgentAuthorityErrorV2::StateConflict);
        }
        self.managed_resource_issuer = Some(issuer);
        Ok(())
    }

    pub(crate) fn install_managed_admin(
        &mut self,
        trust: crate::v04_managed_admin::AdminTrustV04,
    ) -> Result<(), StableCode> {
        if self.managed_admin.is_some() {
            return Err(StableCode::PolicyDenied);
        }
        self.managed_admin = Some(trust);
        Ok(())
    }

    pub(crate) fn apply_managed_admin(
        &mut self,
        submission: crate::v04_managed_admin::AdminSubmissionV04,
        values: &mut KernelValueOwnerV2,
    ) -> Result<savana_policy_core::v2::ManagedAdminReceiptV04, StableCode> {
        let trust = self
            .managed_admin
            .as_ref()
            .ok_or(StableCode::PolicyDenied)?;
        let proof = trust.verify(&submission)?;
        let now = crate::v04_managed_admin::now()?;
        if let Some(receipt) = self.policy.as_ref().ok_or(StableCode::KernelUnavailable)?
            .durable.managed_admin_receipt_v04(&proof).map_err(|_| StableCode::PolicyDenied)? {
            return Ok(receipt);
        }
        // Before compiling, not inside the pure compiler, which never sees owner text.
        self.check_compile_owner_views_v04(&proof).map_err(|_| StableCode::PolicyDenied)?;
        if let Some((task, root)) = proof.planning_execution_request(now).map_err(|_| StableCode::PolicyDenied)? {
            return self.prepare_owner_execution_review_v04(&proof, task, root, values, now)
                .map_err(|_| StableCode::PolicyDenied);
        }
        let policy = self.policy.as_mut().ok_or(StableCode::KernelUnavailable)?;
        policy
            .durable
            .apply_managed_admin_with_tools_v04(
                &proof,
                &policy.active_tools,
                policy.role,
                now,
            )
            .map_err(|_| StableCode::PolicyDenied)
    }

    pub(crate) fn establish_task_authorization(
        &mut self,
        request: &savana_kernel_protocol::v2::EstablishTaskAuthorizationRequestV2,
        proof: &crate::v2_input_owner::AuthenticatedTaskDraftSubmissionV2,
        now: UnixMillisV2,
    ) -> Result<
        savana_kernel_protocol::v2::EstablishTaskAuthorizationResponseV2,
        crate::v2_task_authority::TaskAuthorityErrorV2,
    > {
        use crate::v2_task_authority::TaskAuthorityErrorV2;
        let issuer = self
            .task_issuer
            .as_ref()
            .ok_or(TaskAuthorityErrorV2::Unavailable)?;
        let policy = self
            .policy
            .as_mut()
            .ok_or(TaskAuthorityErrorV2::Unavailable)?;
        let d = request.draft();
        let request_digest = domain_digest(
            b"SAVANA_TASK_ISSUANCE_REQUEST_V2_SCHEMA1\0",
            &[
                d.installation_digest().as_bytes(),
                d.task().as_bytes(),
                d.principal().as_bytes(),
                request.request_nonce().as_bytes(),
            ],
        );
        issuer.prepare(
            &mut policy.durable,
            &policy.active_tools,
            policy.role,
            proof,
            d.clone(),
            request_digest,
            now,
        )?;
        let digest = issuer.issue_structured(
            &mut policy.durable,
            &policy.active_tools,
            policy.role,
            proof,
            request_digest,
            now,
        )?;
        self.activate_task_authorization(d.task(), d.principal(), digest, now)?;
        savana_kernel_protocol::v2::EstablishTaskAuthorizationResponseV2::new(
            request_digest,
            digest,
        )
        .map_err(|_| TaskAuthorityErrorV2::Binding)
    }

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
            connector_authorizations: Vec::new(),
            planner_tickets: Vec::new(),
            tools: Vec::new(),
            plan_steps: Vec::new(),
            intents: Vec::new(),
            execution_tickets: Vec::new(),
            executions: Vec::new(),
            tool_approvals: Vec::new(),
            fused_approval_recovery: Vec::new(),
            fused_release_recovery: Vec::new(),
            private_session_authentications: Vec::new(),
            pending_releases: Vec::new(),
            release_tickets: Vec::new(),
            releases: Vec::new(),
            policy: None,
            task_issuer: None,
            managed_resource_issuer: None,
            managed_admin: None,
            durable_state: None,
            durable_poisoned: false,
            #[cfg(test)]
            execution_declassification_gate_test_observation: None,
            #[cfg(test)]
            fused_recovery_fault: None,
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
        self.encode_recovery_snapshot_schema(5)
    }

    fn encode_recovery_snapshot_schema(
        &self,
        schema: u16,
    ) -> Result<Vec<u8>, KernelAgentAuthorityErrorV2> {
        if !matches!(schema, 2..=5)
            || (schema < 4 && !self.fused_approval_recovery.is_empty())
            || (schema < 5 && !self.fused_release_recovery.is_empty())
        {
            return Err(KernelAgentAuthorityErrorV2::Unavailable);
        }
        let mut encoder = minicbor::Encoder::new(Vec::new());
        encoder
            .array(if schema == 5 {
                6
            } else if schema == 4 {
                5
            } else {
                4
            })
            .and_then(|encoder| encoder.u16(schema))
            .and_then(|encoder| encoder.bytes(self.recovery_security_binding().as_bytes()))
            .and_then(|encoder| encoder.array(self.tasks.len() as u64))
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        for task in &self.tasks {
            encoder
                .array(if schema >= 3 { 15 } else { 13 })
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
            if schema >= 3 {
                encode_optional_recovery_value(&mut encoder, task.source_input_digest.as_ref())?;
                encode_optional_recovery_value(
                    &mut encoder,
                    task.task_authorization_digest.as_ref(),
                )?;
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
        if schema >= 4 {
            self.encode_fused_approval_recovery_v04(&mut encoder)?;
        }
        if schema == 5 {
            self.encode_fused_release_recovery_v04(&mut encoder)?;
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
            || !self.fused_approval_recovery.is_empty()
            || !self.fused_release_recovery.is_empty()
            || bytes.is_empty()
            || bytes.len() > 128 * 1024 * 1024
        {
            return Err(KernelAgentAuthorityErrorV2::Unavailable);
        }
        let mut decoder = minicbor::Decoder::new(bytes);
        let fields = decoder
            .array()
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        let schema = decoder
            .u16()
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        if !matches!(schema, 2..=5)
            || fields
                != Some(if schema == 5 {
                    6
                } else if schema == 4 {
                    5
                } else {
                    4
                })
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
            require_recovery_array(&mut decoder, if schema >= 3 { 15 } else { 13 })?;
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
            let source_input_digest: Option<Digest32V2> = if schema >= 3 {
                decode_optional_recovery_value(&mut decoder, &mut context)?
            } else {
                None
            };
            let task_authorization_digest: Option<Digest32V2> = if schema >= 3 {
                decode_optional_recovery_value(&mut decoder, &mut context)?
            } else {
                None
            };
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
                || source_input_digest.is_some_and(|d| d.as_bytes() == &[0; 32])
                || task_authorization_digest.is_some_and(|d| d.as_bytes() == &[0; 32])
                || (task_authorization_digest.is_some() && source_input_digest.is_none())
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
                || expected_principal.is_some() != durable_run_id.is_some()
                || (material.is_some() && expected_principal.is_none())
                // Admission consumes the plaintext material, but its task/run
                // identity must survive as a fail-closed tombstone. Only a
                // post-admission or terminal task may lack committed material;
                // a Ready task must never be reconstructed from identity alone.
                || (material.is_none()
                    && expected_principal.is_some()
                    && !matches!(
                        status,
                        PublicTaskStatusV2::Running
                            | PublicTaskStatusV2::Dispatching
                            | PublicTaskStatusV2::Succeeded
                            | PublicTaskStatusV2::EffectSucceededOutputQuarantined { .. }
                            | PublicTaskStatusV2::PolicyDenied { .. }
                            | PublicTaskStatusV2::FailedNoEffect { .. }
                            | PublicTaskStatusV2::Indeterminate
                            | PublicTaskStatusV2::Cancelled
                            | PublicTaskStatusV2::Expired
                    ))
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
                source_input_digest,
                task_authorization_digest,
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
        if schema >= 4 {
            self.decode_fused_approval_recovery_v04(&mut decoder, &mut V2DecodeContext)?;
        }
        if schema == 5 {
            self.decode_fused_release_recovery_v04(&mut decoder, &mut V2DecodeContext)?;
        }
        if decoder.position() != bytes.len()
            || self.tasks.iter().enumerate().any(|(task_index, task)| {
                task.current_authentication_preparation
                    .is_some_and(|index| {
                        index >= self.authentication_preparations.len()
                            || self.authentication_preparations[index].task_index != task_index
                    })
            })
            || self.encode_recovery_snapshot_schema(schema)? != bytes
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
            && self.task_issuer.is_some()
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
            self.require_public_task_v04(existing.durable_task_id)?;
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
            source_input_digest: None,
            task_authorization_digest: None,
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
        source_input_digest: Digest32V2,
        material: PreparedAgentClaimMaterialV2,
    ) -> Result<(), KernelAgentAuthorityErrorV2> {
        self.ensure_durable_available()?;
        if source_input_digest.as_bytes() == &[0; 32] {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        let task = self
            .tasks
            .iter_mut()
            .find(|task| task.durable_task_id == durable_task_id)
            .ok_or(KernelAgentAuthorityErrorV2::InvalidReference)?;
        if let Some(existing) = task.expected_principal {
            if existing != principal {
                return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
            }
            if let Some(stored) = &task.material {
                return if task.source_input_digest == Some(source_input_digest)
                    && stored.matches_exactly(&material)?
                {
                    Ok(())
                } else {
                    Err(KernelAgentAuthorityErrorV2::BindingMismatch)
                };
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
        task.source_input_digest = Some(source_input_digest);
        // Input consent is not task authority. The subsequent typed submission
        // or independent task approval makes this input available to planning.
        task.status = PublicTaskStatusV2::Processing;
        self.persist_recovery_snapshot()
    }

    pub(crate) fn ingress_material_is_committed(
        &self,
        task: DurableTaskIdV2,
        principal: PrincipalIdV2,
        source: Digest32V2,
        manifest: Digest32V2,
    ) -> Result<bool, KernelAgentAuthorityErrorV2> {
        self.ensure_durable_available()?;
        let t = self
            .tasks
            .iter()
            .find(|t| t.durable_task_id == task)
            .ok_or(KernelAgentAuthorityErrorV2::InvalidReference)?;
        if t.material.is_some() {
            if t.expected_principal != Some(principal)
                || t.source_input_digest != Some(source)
                || t.active_state_manifest_digest != manifest
            {
                return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
            }
            return Ok(true);
        }
        Ok(false)
    }

    pub(crate) fn activate_committed_task_authorization(
        &mut self,
        task: DurableTaskIdV2,
        principal: PrincipalIdV2,
        manifest: Digest32V2,
        generation: u64,
        now: UnixMillisV2,
    ) -> Result<(), crate::v2_task_authority::TaskAuthorityErrorV2> {
        use crate::v2_task_authority::TaskAuthorityErrorV2 as E;
        self.ensure_durable_available()
            .map_err(|_| E::Unavailable)?;
        let owner = &self.policy.as_ref().ok_or(E::Unavailable)?.durable;
        let Some(state) = owner
            .find_task_authorization_state(task)
            .map_err(|_| E::State)?
        else {
            return Ok(());
        };
        if state.revoked() {
            return Ok(());
        }
        let digest = state.authorization().digest();
        let Some(draft) = owner
            .installed_task_authorization_draft(digest)
            .map_err(|_| E::State)?
        else {
            // Legacy grants have no authenticated input association and cannot
            // activate newly handed-off input through recovery.
            return Ok(());
        };
        if draft.manifest_digest() != manifest || draft.deployment_generation() != generation {
            return Err(E::Binding);
        }
        self.activate_task_authorization(task, principal, digest, now)
    }

    fn activate_task_authorization(
        &mut self,
        task: DurableTaskIdV2,
        principal: PrincipalIdV2,
        digest: Digest32V2,
        now: UnixMillisV2,
    ) -> Result<(), crate::v2_task_authority::TaskAuthorityErrorV2> {
        use crate::v2_task_authority::TaskAuthorityErrorV2 as E;
        self.ensure_durable_available()
            .map_err(|_| E::Unavailable)?;
        let p = self.policy.as_ref().ok_or(E::Unavailable)?;
        let state = p
            .durable
            .task_authorization_state(task)
            .map_err(|_| E::State)?;
        if state.revoked() || state.authorization().digest() != digest {
            return Ok(());
        }
        let draft = p
            .durable
            .installed_task_authorization_draft(digest)
            .map_err(|_| E::State)?
            .ok_or(E::State)?;
        if draft.principal() != principal
            || now.get() < draft.not_before().get()
            || now.get() >= draft.expires_at().get()
        {
            return Err(E::Binding);
        }
        if let Some(t) = self.tasks.iter_mut().find(|t| t.durable_task_id == task) {
            if let Some(material) = &t.material {
                if t.expected_principal != Some(principal)
                    || t.source_input_digest != Some(draft.source_input_digest())
                    || t.active_state_manifest_digest != draft.manifest_digest()
                    || now.get() >= material.expires_at.get()
                {
                    return Err(E::Binding);
                }
                t.task_authorization_digest = Some(digest);
                if t.status == PublicTaskStatusV2::Processing {
                    t.status = PublicTaskStatusV2::Ready { bootstrap: None };
                }
            }
        }
        for s in &mut self.sessions {
            if s.durable_task_id == task
                && s.principal == principal
                && s.active_state_manifest_digest == draft.manifest_digest()
            {
                s.task_authorization_digest = Some(digest);
            }
        }
        self.persist_recovery_snapshot().map_err(|_| E::Unavailable)
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
        self.require_public_task_v04(self.tasks[task_index].durable_task_id)?;
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
        self.require_public_task_v04(self.tasks[record.task_index].durable_task_id)?;
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
        self.require_public_task_v04(self.tasks[task_index].durable_task_id)?;
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
            signed_planner_policy: material.signed_planner_policy,
            expires_at: material.expires_at,
            revision,
            initial_document: material.initial_document,
            initial_value: initial.handle(),
            // Agent-claimed sessions receive only the masked view.
            owner_input_value: None,
            status: AgentSessionStatusV2::Running,
            task_authorization_digest: None,
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
        self.require_public_task_v04(task.durable_task_id)?;
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
        self.require_public_task_v04(unsigned.durable_task_id())?;
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
        self.require_public_task_v04(session.durable_task_id)?;
        let revision = matches!(
            session.status,
            AgentSessionStatusV2::Ready | AgentSessionStatusV2::Running
        )
        .then_some(session.revision);
        GetAgentSessionStatusResponseV2::new(session.status, revision)
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)
    }

    fn require_session_task_authorization(
        &self,
        session: &SessionRecordV2,
        now: UnixMillisV2,
    ) -> Result<Digest32V2, KernelAgentAuthorityErrorV2> {
        // Explicit fused enrollment cannot silently use the legacy planner or
        // existing cached session as a bypass of its not-yet-active publisher.
        if self
            .policy
            .as_ref()
            .ok_or(KernelAgentAuthorityErrorV2::StateConflict)?
            .durable
            .fused_planning_enrolled_v04(session.durable_task_id)
            .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?
        {
            return Err(KernelAgentAuthorityErrorV2::StateConflict);
        }
        self.require_current_session_task_authorization(session, now)
    }

    // Private compilation still checks the complete live root; only the
    // public legacy-entry prohibition is factored out, not any root check.
    fn require_current_session_task_authorization(
        &self,
        session: &SessionRecordV2,
        now: UnixMillisV2,
    ) -> Result<Digest32V2, KernelAgentAuthorityErrorV2> {
        let state = self
            .policy
            .as_ref()
            .ok_or(KernelAgentAuthorityErrorV2::StateConflict)?
            .durable
            .task_authorization_state(session.durable_task_id)
            .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?;
        let authorization = state.authorization();
        let m = authorization.material();
        if state.revoked()
            || m.principal() != session.principal
            || m.task() != session.durable_task_id
            || m.installation_digest() != self.config.installation_id
            || m.manifest_digest() != session.active_state_manifest_digest
            || now.get() < m.not_before().get()
            || now.get() >= m.expires_at().get()
            || now.get() >= session.expires_at.get()
            || session
                .task_authorization_digest
                .is_some_and(|d| d != authorization.digest())
        {
            return Err(KernelAgentAuthorityErrorV2::StateConflict);
        }
        Ok(authorization.digest())
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
        let task_authorization_digest = self.require_session_task_authorization(session, now)?;
        let signed_planner_policy = session.signed_planner_policy.clone();
        let session_role = session.role;
        let effective_limits = intersect_planner_request(
            &signed_planner_policy,
            request.planner_route(),
            request.task_template(),
            request.intent(),
            request.purpose(),
            request.limits(),
        )?;
        let policy = self
            .policy
            .as_ref()
            .ok_or(KernelAgentAuthorityErrorV2::StateConflict)?;
        let mut allowed_tool_classes = Vec::new();
        allowed_tool_classes
            .try_reserve_exact(policy.active_tools.len())
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        for active in policy.active_tools.records() {
            let descriptor = active.descriptor();
            if signed_planner_policy
                .allowed_action_templates
                .binary_search(&descriptor.unsigned().action_template())
                .is_ok()
                && policy
                    .active_tools
                    .resolve(descriptor.descriptor_digest(), session_role, now)
                    .is_some()
            {
                allowed_tool_classes.push(descriptor.unsigned().tool_class());
            }
        }
        allowed_tool_classes.sort_unstable();
        allowed_tool_classes.dedup();
        let effective_policy = EffectivePlannerPolicyV2 {
            limits: effective_limits,
            allowed_action_templates: signed_planner_policy.allowed_action_templates.clone(),
            allowed_tool_classes,
            task_template: signed_planner_policy.task_template,
            intent: signed_planner_policy.intent,
            purpose: signed_planner_policy.purpose,
        };
        values
            .validate_run_values(request.run(), request.prompt_values(), now)
            .map_err(map_value_error)?;
        if request.prompt_values().is_empty() {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }

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
            request.task_template(),
            request.intent(),
            signed_planner_policy.allowed_action_templates.clone(),
            slots,
            Vec::new(),
            effective_limits,
            envelope_nonce,
            expires_at,
        )
        .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        let canonical =
            minicbor::to_vec(&envelope).map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        let envelope_digest = Digest32V2::new(Sha256::digest(&canonical).into());
        let slot_binding_digest = planner_slot_binding_digest(&slot_bindings)?;
        let resolved = request
            .prompt_values()
            .iter()
            .map(|value| {
                values
                    .resolve_g4_value(request.run(), *value, now)
                    .map_err(map_value_error)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let first = resolved
            .first()
            .ok_or(KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let parents = resolved
            .iter()
            .map(|value| value.provenance())
            .collect::<Vec<_>>();
        let policy_allowed_effects = parents.iter().fold(EffectSetV2::ALL, |effects, parent| {
            effects.intersection(parent.label().effects())
        });
        let context = ProvenanceContextV2::from_authenticated_runtime(
            first.provenance().producer_identity(),
            first.durable_run_id(),
            first.active_state_manifest_digest(),
            now,
            first.provenance().expires_at(),
        )
        .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let envelope_value = KernelValueV2::bytes(canonical)
            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let declassification_rules = policy
            .declassification_rules
            .snapshot()
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        let declassification = ProvenanceRecordV2::declassify(
            &envelope_value,
            context,
            DeclassificationTransitionV2::BuildPlannerEnvelope,
            &declassification_rules,
            ClosedDeclassificationPurposeV2::PlannerCall.purpose_digest(),
            slot_binding_digest,
            None,
            &parents,
            policy_allowed_effects,
            now.get(),
        )
        .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        if declassification.judge_handoff(
            DeclassificationTransitionV2::BuildPlannerEnvelope,
            &declassification_rules,
        ) != HandoffJudgmentV2::Admits
        {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        let declassification_provenance_digest = declassification.provenance_digest();
        let ticket = mint_handle(PlannerTicketHandleV2::from_authority_entropy)?;
        let response = PreparePlannerCallResponseV2::new(
            ticket,
            envelope,
            envelope_digest,
            declassification_provenance_digest,
            expires_at,
        )
        .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        self.planner_tickets
            .try_reserve(1)
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        self.planner_tickets.push(PlannerTicketRecordV2 {
            ticket,
            run: request.run(),
            planner_route: request.planner_route(),
            effective_policy,
            prompt_values: request.prompt_values().to_vec(),
            slot_bindings,
            envelope_nonce,
            envelope_digest,
            declassification_provenance_digest,
            expires_at,
            consumed: false,
            task_authorization_digest,
        });
        self.sessions
            .iter_mut()
            .find(|s| s.run == request.run())
            .ok_or(KernelAgentAuthorityErrorV2::InvalidReference)?
            .task_authorization_digest = Some(task_authorization_digest);
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
        let encoded_plan_len = request
            .plan()
            .canonical_encoded_len()
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        record
            .effective_policy
            .validate_committed_plan(request.plan(), encoded_plan_len)?;
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
        if self.require_session_task_authorization(session, now)?
            != record.task_authorization_digest
        {
            return Err(KernelAgentAuthorityErrorV2::StateConflict);
        }
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
        let proposer_parent = values
            .resolve_g4_value(request.run(), committed.handle(), now)
            .map_err(map_value_error)?
            .provenance()
            .provenance_digest();
        let plan_revision_digest = PlanRevisionDigestV2::new(
            domain_digest(
                PLAN_REVISION_DOMAIN,
                &[
                    record.envelope_digest.as_bytes(),
                    record.declassification_provenance_digest.as_bytes(),
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
                        task_authorization_digest: record.task_authorization_digest,
                        proposer_parent,
                        arguments,
                        derived_controls: vec![],
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
        deployment_generation: u64,
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
        let session = self
            .sessions
            .iter()
            .find(|session| {
                session.run == step.run
                    && matches!(
                        session.status,
                        AgentSessionStatusV2::Ready | AgentSessionStatusV2::Running
                    )
            })
            .ok_or(KernelAgentAuthorityErrorV2::InvalidReference)?;
        if self.require_session_task_authorization(session, now)? != step.task_authorization_digest
            || session.active_state_manifest_digest != active_state_manifest_digest
        {
            return Err(KernelAgentAuthorityErrorV2::StateConflict);
        }
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
        let prepared = self.prepare_tool_intent_material(
            step,
            values,
            active_state_manifest_digest,
            deployment_generation,
            now,
        )?;
        let step = step.clone();
        self.commit_prepared_tool_intent(
            request_id,
            authenticated_canonical_request,
            &step,
            prepared,
            None,
            active_state_manifest_digest,
        )
    }

    /// Shared G4 commit. Admission/route authorization is performed by the
    /// legacy proposer or by the lease-guarded private fused owner, never a model.
    fn commit_prepared_tool_intent(
        &mut self,
        request_id: savana_kernel_protocol::v2::RequestIdV2,
        authenticated_canonical_request: &[u8],
        step: &PlanStepRecordV2,
        prepared: PreparedToolIntentV2,
        fused: Option<fused_actions::FusedIntentBindingV04>,
        active_state_manifest_digest: Digest32V2,
    ) -> Result<ProposeToolCallResponseV2, KernelAgentAuthorityErrorV2> {
        if authenticated_canonical_request.is_empty() || self.intents.len() >= self.maximum_records
        {
            return Err(KernelAgentAuthorityErrorV2::LimitExceeded);
        }
        let PreparedToolIntentV2 {
            material,
            recipe_slots: _,
            policy_binding,
            semantic_binding,
            task_match,
            control_selections,
            business_request,
            dispatch_plaintext,
            display_plaintext,
            provenance_parents,
            policy_allowed_effects,
        } = prepared;
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
            if existing.fused.is_some() != fused.is_some() {
                return Err(KernelAgentAuthorityErrorV2::StateConflict);
            }
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
            fused,
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
            task_match,
            control_selections,
            business_request,
            dispatch_plaintext,
            display_plaintext,
            provenance_parents,
            policy_allowed_effects,
            arguments: step.arguments.clone(),
            derived_controls: step.derived_controls.clone(),
            state: IntentRecordStateV2::Proposed,
            decision_trace: None,
            ticket_commitment: None,
            approval_commitment: None,
            approval_settlement: None,
            task_action_approval: None,
        });
        Ok(ProposeToolCallResponseV2::new(
            intent,
            ActionIntentCurrentStateV2::Proposed { pending },
        ))
    }

    /// One G4 implementation for legacy proposals and private local compilation.
    /// This prepares material only: it creates no durable intent or permission.
    fn prepare_tool_intent_material(
        &self,
        step: &PlanStepRecordV2,
        values: &KernelValueOwnerV2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        now: UnixMillisV2,
    ) -> Result<PreparedToolIntentV2, KernelAgentAuthorityErrorV2> {
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
        let mut stored_values = slots
            .iter()
            .zip(&resolved_values)
            .map(|(slot, resolved)| {
                StoredValueRecordV2::from_store(slot, resolved.value(), resolved.provenance())
                    .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)
            })
            .collect::<Result<Vec<_>, _>>()?;
        stored_values.sort_by_key(|v| *v.value_internal_id().as_bytes());
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
        let profile = unsigned
            .business_profile()
            .ok_or(KernelAgentAuthorityErrorV2::BindingMismatch)?;
        // A request alias cannot change the application request identity. This
        // identifier is derived from the immutable committed plan step.
        let business_request = stored
            .business_request(profile, &business_step_request_id(step.internal_step_id))
            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let state = policy
            .durable
            .task_authorization_state(step.durable_task_id)
            .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?;
        let derived: std::collections::BTreeMap<_, _> =
            step.derived_controls.iter().cloned().collect();
        let task_match = match_business_proposal(
            &state,
            &business_request,
            step.descriptor_digest,
            step.plan_revision_digest,
            stored.provenance_set_digest(),
            &derived,
            deployment_generation,
            now,
        )?;
        let control_selections = savana_policy_core::v2::ControlSelectionV2::from_match(
            &task_match,
            step.proposer_parent,
        )
        .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let relations = VerifiedResolvedRelationSetV2::from_task_match(slot_count, &task_match)
            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let recipe_slots = slots.clone();
        let slots = slots
            .into_iter()
            .map(|s| s.with_task_relation(&relations))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let plan_arguments = step
            .arguments
            .iter()
            .zip(&slots)
            .map(|(argument, slot)| {
                VerifiedPlanArgumentV2::from_verified_plan(argument.name.clone(), slot)
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let mut stored_values = slots
            .iter()
            .zip(&resolved_values)
            .map(|(slot, resolved)| {
                StoredValueRecordV2::from_store(slot, resolved.value(), resolved.provenance())
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        stored_values.sort_by_key(|v| *v.value_internal_id().as_bytes());
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
        // Provenance commits names and owned value identities, not the internal
        // slot relation hash; this second binding introduces no digest cycle.
        if stored.provenance_set_digest() != task_match.content().provenance_digest() {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        let dispatch_plaintext = task_execution_plaintext(&task_match, &business_request, &derived)?;
        let destination = KernelValueV2::bytes(business_request.canonical_json())
            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        // The G4 display commitment includes the complete content, before any
        // action approval or final authorization digest is constructed.
        let display_text = task_bound_display(&task_match, &business_request, &state, &derived)?;
        let display_plaintext = display_text.as_bytes().to_vec();
        let display = KernelValueV2::text(display_text.as_str())
            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let provenance_parents = resolved_values
            .iter()
            .map(|resolved| resolved.provenance().clone())
            .collect::<Vec<_>>();
        let policy_allowed_effects = provenance_parents
            .iter()
            .fold(EffectSetV2::ALL, |effects, parent| {
                effects.intersection(parent.label().effects())
            });
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
        Ok(PreparedToolIntentV2 {
            material,
            recipe_slots,
            policy_binding,
            semantic_binding,
            task_match,
            control_selections,
            business_request,
            dispatch_plaintext,
            display_plaintext,
            provenance_parents,
            policy_allowed_effects,
        })
    }

    fn recheck_intent_task(
        &self,
        intent: &IntentRecordV2,
        manifest: Digest32V2,
        generation: u64,
        now: UnixMillisV2,
        access: IntentAccessV2,
    ) -> Result<(), KernelAgentAuthorityErrorV2> {
        if intent
            .task_match
            .authorization()
            .material()
            .manifest_digest()
            != manifest
        {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        let session = self
            .sessions
            .iter()
            .find(|s| {
                s.run == intent.run
                    && matches!(
                        s.status,
                        AgentSessionStatusV2::Ready | AgentSessionStatusV2::Running
                    )
            })
            .ok_or(KernelAgentAuthorityErrorV2::InvalidReference)?;
        let root = match access {
            IntentAccessV2::LegacyAgent => {
                if intent.fused.is_some() {
                    return Err(KernelAgentAuthorityErrorV2::StateConflict);
                }
                self.require_session_task_authorization(session, now)?
            }
            IntentAccessV2::PrivateFused => {
                let binding = intent
                    .fused
                    .as_ref()
                    .ok_or(KernelAgentAuthorityErrorV2::StateConflict)?;
                let owner = &self
                    .policy
                    .as_ref()
                    .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?
                    .durable;
                let active = owner
                    .active_fused_plan_v04(intent.durable_task_id, now)
                    .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?;
                if now.get() >= binding.expires_at.get()
                    || active.revision() != binding.reference.plan_revision
                    || active.next_operation() != Some(binding.reference.operation)
                    || !active.recipe_approved(
                        binding.reference.operation,
                        &binding.recipe,
                        generation,
                        now,
                    )
                    || !owner
                        .fused_inputs_pinned_v04(intent.durable_task_id)
                        .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?
                {
                    return Err(KernelAgentAuthorityErrorV2::StateConflict);
                }
                owner
                    .recover_fused_inputs_v04(intent.durable_task_id, generation, now)
                    .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?;
                self.require_current_session_task_authorization(session, now)?
            }
        };
        if root != intent.task_match.authorization().digest() {
            return Err(KernelAgentAuthorityErrorV2::StateConflict);
        }
        let state = self
            .policy
            .as_ref()
            .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?
            .durable
            .task_authorization_state(intent.durable_task_id)
            .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?;
        if state.revoked() {
            return Err(KernelAgentAuthorityErrorV2::StateConflict);
        }
        intent
            .task_match
            .recheck(&savana_policy_core::v2::TaskMatchContextV2 {
                current_authorization: Some(state.authorization()),
                pre_state_digest: state.digest(),
                pre_state_revision: state.revision(),
                deployment_generation: generation,
                now,
            })
            .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)
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
        self.evaluate_tool_call_inner(
            request,
            values,
            active_state_manifest_digest,
            deployment_generation,
            now,
            IntentAccessV2::LegacyAgent,
            None,
        )
    }

    // Keep caller route and held-policy rules explicit at the shared gate.
    #[allow(clippy::too_many_arguments)]
    fn evaluate_tool_call_inner(
        &mut self,
        request: EvaluateToolCallRequestV2,
        values: &KernelValueOwnerV2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        now: UnixMillisV2,
        access: IntentAccessV2,
        leased_rules: Option<&savana_policy_core::v2::DeclassificationRuleSetV2>,
    ) -> Result<EvaluateToolCallResponseV2, KernelAgentAuthorityErrorV2> {
        self.ensure_durable_available()?;
        if (access == IntentAccessV2::PrivateFused) != leased_rules.is_some() {
            return Err(KernelAgentAuthorityErrorV2::StateConflict);
        }
        let pending_commitment = request.pending().authority_commitment(&self.handle_key);
        let index = self
            .intents
            .iter()
            .position(|record| record.pending_commitment == pending_commitment)
            .ok_or(KernelAgentAuthorityErrorV2::InvalidReference)?;
        self.recheck_intent_task(
            &self.intents[index],
            active_state_manifest_digest,
            deployment_generation,
            now,
            access,
        )?;
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
                if now.get() >= approval.expires_at.get() {
                    return Err(KernelAgentAuthorityErrorV2::Expired);
                }
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
            VerifiedResolvedRelationSetV2::from_task_match(slot_count, &intent.task_match)
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
        let mut stored_values = slots
            .iter()
            .zip(&resolved_values)
            .map(|(slot, resolved)| {
                StoredValueRecordV2::from_store(slot, resolved.value(), resolved.provenance())
                    .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)
            })
            .collect::<Result<Vec<_>, _>>()?;
        stored_values.sort_by_key(|v| *v.value_internal_id().as_bytes());
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
        let projected = stored
            .business_request(
                active
                    .descriptor()
                    .unsigned()
                    .business_profile()
                    .ok_or(KernelAgentAuthorityErrorV2::BindingMismatch)?,
                intent.business_request.request_id(),
            )
            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        if projected != intent.business_request
            || task_execution_plaintext(
                &intent.task_match,
                &projected,
                &intent.derived_controls.iter().cloned().collect(),
            )?
                != intent.dispatch_plaintext
            || stored.provenance_set_digest() != intent.task_match.content().provenance_digest()
        {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        let state = policy
            .durable
            .task_authorization_state(intent.durable_task_id)
            .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?;
        let derived: std::collections::BTreeMap<_, _> =
            intent.derived_controls.iter().cloned().collect();
        if task_bound_display(&intent.task_match, &projected, &state, &derived)?.as_bytes()
            != intent.display_plaintext
        {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
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
                let deadline = checked_deadline(now, TOOL_APPROVAL_TTL_MS)?;
                let expires_at = intent.fused.as_ref().map_or(deadline, |binding| {
                    UnixMillisV2::new(deadline.get().min(binding.expires_at.get()))
                });
                let envelope_nonce = Nonce32V2::new(random_bytes()?);
                let challenge = Nonce32V2::new(random_bytes()?);
                let binding = ApprovalBindingV2::ToolExecution {
                    action_intent_id: intent.action_intent_id,
                    binding: intent.semantic_binding,
                };
                let display_text =
                    BoundedApprovalDisplayTextV2::from_utf8_bytes(intent.display_plaintext.clone())
                        .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
                let display_value = KernelValueV2::text(display_text.as_str())
                    .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
                let first_parent = intent
                    .provenance_parents
                    .first()
                    .ok_or(KernelAgentAuthorityErrorV2::BindingMismatch)?;
                let display_context = ProvenanceContextV2::from_authenticated_runtime(
                    first_parent.producer_identity(),
                    intent.durable_run_id,
                    active_state_manifest_digest,
                    now,
                    first_parent.expires_at(),
                )
                .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
                let display_parents = intent.provenance_parents.iter().collect::<Vec<_>>();
                // The private caller already holds the publication read lock;
                // do not reacquire it (a queued writer could deadlock a nested read).
                let snapshot;
                let declassification_rules = if let Some(rules) = leased_rules {
                    rules
                } else {
                    snapshot = policy
                        .declassification_rules
                        .snapshot()
                        .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
                    &snapshot
                };
                let display_declassification = ProvenanceRecordV2::declassify(
                    &display_value,
                    display_context,
                    DeclassificationTransitionV2::BuildApprovalDisplay,
                    declassification_rules,
                    ClosedDeclassificationPurposeV2::ApprovalDisplay.purpose_digest(),
                    intent.policy_binding.token_set_digest(),
                    None,
                    &display_parents,
                    intent.policy_allowed_effects,
                    now.get(),
                )
                .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
                if display_declassification.judge_handoff(
                    DeclassificationTransitionV2::BuildApprovalDisplay,
                    declassification_rules,
                ) != HandoffJudgmentV2::Admits
                {
                    return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
                }
                let approvald_identity = policy.approval.approvald_identity;
                if let Some(recovered) = self.rebind_fused_approval_v04(
                    index,
                    active_state_manifest_digest,
                    deployment_generation,
                    now,
                    trace,
                )? {
                    return Ok(recovered);
                }
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
                    approval_display_digest_v2(display_text.as_bytes()),
                    display_text.clone(),
                    Some(display_declassification.provenance_digest()),
                    approvald_identity,
                    now,
                    expires_at,
                )
                .and_then(|unsigned| {
                    unsigned.with_task_action_binding(
                        savana_kernel_protocol::v2::TaskActionApprovalBindingV2::new(
                            intent.task_match.content_digest(),
                            intent.task_match.content().authorization_id(),
                            intent.task_match.content().authorization_revision(),
                            intent.durable_task_id,
                        )?,
                    )
                })
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
                        display_digest: approval_display_digest_v2(display_text.as_bytes()),
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
                if intent.fused.is_some() {
                    self.retain_fused_approval_v04(
                        intent.action_intent_id,
                        envelope.clone(),
                        display_authentication.clone(),
                    )?;
                }
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
        self.authorize_tool_call_inner(
            request,
            active_state_manifest_digest,
            deployment_generation,
            now,
            IntentAccessV2::LegacyAgent,
        )
    }

    fn authorize_tool_call_inner(
        &mut self,
        request: &savana_kernel_protocol::v2::AuthorizeToolCallRequestV2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        now: UnixMillisV2,
        access: IntentAccessV2,
    ) -> Result<AuthorizeToolCallResponseV2, KernelAgentAuthorityErrorV2> {
        self.ensure_durable_available()?;
        let pending_commitment = request.pending().authority_commitment(&self.handle_key);
        let approval_commitment = request.approval().authority_commitment(&self.handle_key);
        let intent_index = self
            .intents
            .iter()
            .position(|record| record.pending_commitment == pending_commitment)
            .ok_or(KernelAgentAuthorityErrorV2::InvalidReference)?;
        self.recheck_intent_task(
            &self.intents[intent_index],
            active_state_manifest_digest,
            deployment_generation,
            now,
            access,
        )?;
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
        if verified.decision() != ApprovalDecisionV2::Approve {
            self.retain_fused_settlement_v04(intent_index, request.receipt())?;
            self.tool_approvals[approval_index].consumed = true;
            self.intents[intent_index].state = IntentRecordStateV2::Denied;
            return Err(KernelAgentAuthorityErrorV2::StateConflict);
        }
        let envelope_material = self.tool_approvals[approval_index]
            .envelope
            .unverified_material()
            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let expected = envelope_material
            .task_action_context(&request.receipt().unsigned())
            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let task_action = savana_kernel_protocol::v2::verify_task_action_approval_v2(
            request
                .receipt()
                .task_action_approval()
                .ok_or(KernelAgentAuthorityErrorV2::BindingMismatch)?,
            &ed25519_dalek::VerifyingKey::from_bytes(&policy.approval.settlement_public_key)
                .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?,
            &expected,
            now,
        )
        .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let matched = &self.intents[intent_index].task_match;
        if expected.content_digest != matched.content_digest()
            || expected.authorization_id != matched.content().authorization_id()
            || expected.authorization_revision != matched.content().authorization_revision()
            || expected.task != self.intents[intent_index].durable_task_id
        {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
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
        self.retain_fused_settlement_v04(intent_index, request.receipt())?;
        self.execution_tickets.push(ExecutionTicketRecordV2 {
            ticket,
            commitment,
            action_intent_id: approval_action_intent_id,
            semantic_binding_digest,
        });
        self.intents[intent_index].approval_settlement = Some(settlement);
        self.intents[intent_index].task_action_approval = Some(task_action);
        self.tool_approvals[approval_index].consumed = true;
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
        self.dispatch_execution_inner(
            request_id,
            request,
            active_state_manifest_digest,
            deployment_generation,
            effect_fence_epoch,
            now,
            IntentAccessV2::LegacyAgent,
            None,
        )
    }

    // Private dispatch holds the publication lease through G7 and transport;
    // use its borrowed rules rather than recursively acquiring the same lock.
    #[allow(clippy::too_many_arguments)]
    fn dispatch_execution_inner(
        &mut self,
        request_id: savana_kernel_protocol::v2::RequestIdV2,
        request: savana_kernel_protocol::v2::DispatchExecutionRequestV2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        effect_fence_epoch: u64,
        now: UnixMillisV2,
        access: IntentAccessV2,
        leased_rules: Option<(&savana_policy_core::v2::DeclassificationRuleSetV2, u64)>,
    ) -> Result<DispatchExecutionResponseV2, KernelAgentAuthorityErrorV2> {
        self.ensure_durable_available()?;
        if (access == IntentAccessV2::PrivateFused) != leased_rules.is_some() {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        #[cfg(test)]
        {
            self.execution_declassification_gate_test_observation = None;
        }
        let ticket_commitment = request.ticket().authority_commitment(&self.handle_key);
        // Route isolation precedes *all* cache lookups. An opaque private ticket
        // remains private even after an execution has already been dispatched.
        let ticket = self
            .execution_tickets
            .iter()
            .find(|record| record.commitment == ticket_commitment)
            .ok_or(KernelAgentAuthorityErrorV2::InvalidReference)?;
        let intent = self
            .intents
            .iter()
            .find(|record| record.action_intent_id == ticket.action_intent_id)
            .ok_or(KernelAgentAuthorityErrorV2::InvalidReference)?;
        if intent.fused.is_some() != (access == IntentAccessV2::PrivateFused) {
            return Err(KernelAgentAuthorityErrorV2::InvalidReference);
        }
        if let Some(existing) = self
            .executions
            .iter()
            .find(|record| record.ticket_commitment == Some(ticket_commitment))
        {
            self.check_execution_context(
                existing,
                active_state_manifest_digest,
                deployment_generation,
                effect_fence_epoch,
            )?;
            return Ok(DispatchExecutionResponseV2::new(
                existing.execution,
                accepted_state(existing.status),
            ));
        }
        if self.executions.len() >= self.maximum_records {
            return Err(KernelAgentAuthorityErrorV2::LimitExceeded);
        }
        // Allocate the query identity before any durable charge or possible effect.
        self.executions
            .try_reserve(1)
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        let execution = mint_handle(ExecutionHandleV2::from_authority_entropy)?;
        let commitment = execution.authority_commitment(&self.handle_key);
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
        self.recheck_intent_task(
            &intent,
            active_state_manifest_digest,
            deployment_generation,
            now,
            access,
        )?;
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
        let result_scope = if intent.fused.is_some() {
            let session = self
                .sessions
                .iter()
                .find(|s| s.run == intent.run)
                .ok_or(KernelAgentAuthorityErrorV2::InvalidReference)?;
            Some(
                savana_policy_core::v2::FusedResultScopeV04::from_authenticated_session(
                    session.principal,
                    session.producer_identity,
                    UnixMillisV2::new(
                        session.expires_at.get().min(
                            intent
                                .task_match
                                .authorization()
                                .material()
                                .expires_at()
                                .get(),
                        ),
                    ),
                    session.policy_allowed_effects,
                )
                .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?,
            )
        } else {
            None
        };
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
        if active.descriptor().unsigned().business_profile()
            != Some(intent.business_request.profile())
            || task_execution_plaintext(
                &intent.task_match,
                &intent.business_request,
                &intent.derived_controls.iter().cloned().collect(),
            )? != intent.dispatch_plaintext
            || intent
                .business_request
                .action_alternative_with_derived(
                    intent.descriptor_digest,
                    &intent.derived_controls.iter().cloned().collect(),
                )
                .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?
                != *intent.task_match.content().action()
            || intent.business_request.payload_digest()
                != intent.task_match.content().payload_digest()
            || intent.business_request.magnitude() != intent.task_match.content().magnitude()
        {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        let mut expires_at = checked_deadline(now, 30_000)?;
        if let Some(binding) = &intent.fused {
            let (_, lease_expiry) =
                leased_rules.ok_or(KernelAgentAuthorityErrorV2::BindingMismatch)?;
            expires_at = UnixMillisV2::new(
                expires_at
                    .get()
                    .min(binding.expires_at.get())
                    .min(lease_expiry),
            );
            if now.get() >= expires_at.get() {
                return Err(KernelAgentAuthorityErrorV2::Expired);
            }
        }
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
            &g7.connector_registry,
            expires_at,
        )
        .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let resolved_ticket = ResolvedExecutionTicketV2::from_resolved_kernel_ticket(
            ticket.commitment,
            intent.action_intent_id,
            ticket.semantic_binding_digest,
        )
        .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let execution_value = KernelValueV2::bytes(intent.dispatch_plaintext.clone())
            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let first_parent = intent
            .provenance_parents
            .first()
            .ok_or(KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let execution_context = ProvenanceContextV2::from_authenticated_runtime(
            first_parent.producer_identity(),
            intent.durable_run_id,
            active_state_manifest_digest,
            now,
            first_parent.expires_at(),
        )
        .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let execution_parents = intent.provenance_parents.iter().collect::<Vec<_>>();
        let execution_transition = DeclassificationTransitionV2::BuildExecutionEnvelope {
            executor_identity_digest: Digest32V2::new(*g7.executor_identity.as_bytes()),
        };
        let snapshot;
        let declassification_rules = if let Some((rules, _)) = leased_rules {
            rules
        } else {
            snapshot = policy
                .declassification_rules
                .snapshot()
                .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
            &snapshot
        };
        #[cfg(test)]
        let mut execution_declassification_gate_test_observation = None;
        let execution_gate_result = gate_execution_before_durable_prepare(
            &intent.dispatch_plaintext,
            || {
                let declassification_result = ProvenanceRecordV2::declassify(
                    &execution_value,
                    execution_context,
                    execution_transition,
                    declassification_rules,
                    ClosedDeclassificationPurposeV2::ExecutionHandoff.purpose_digest(),
                    intent.policy_binding.token_set_digest(),
                    None,
                    &execution_parents,
                    intent.policy_allowed_effects,
                    now.get(),
                );
                #[cfg(test)]
                if declassification_result.is_err() {
                    execution_declassification_gate_test_observation = Some(
                        ExecutionDeclassificationGateTestObservationV2::ProvenanceDeclassificationRefused,
                    );
                }
                let declassification = declassification_result
                    .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
                if declassification.judge_handoff(execution_transition, declassification_rules)
                    != HandoffJudgmentV2::Admits
                {
                    #[cfg(test)]
                    {
                        execution_declassification_gate_test_observation = Some(
                            ExecutionDeclassificationGateTestObservationV2::HandoffJudgmentRefused,
                        );
                    }
                    return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
                }
                Ok(declassification)
            },
            || {
                g7.synchronize_connector_registry(
                    self.config.installation_id,
                    active_state_manifest_digest,
                    deployment_generation,
                    now,
                )
            },
            |sealed_payload_digest| {
                g7.connector_registry
                    .snapshot()
                    .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?
                    .resolve_task_tool_connector(intent.descriptor_digest)
                    .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
                let state = policy
                    .durable
                    .task_authorization_state(intent.durable_task_id)
                    .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?;
                if state.revoked() {
                    return Err(KernelAgentAuthorityErrorV2::StateConflict);
                }
                let evidence = match (&intent.approval_settlement, &intent.task_action_approval) {
                    (Some(_), Some(approval)) => {
                        savana_policy_core::v2::ControlEvidenceV2::ActionApproval {
                            approval,
                            expected_context: approval.material().context(),
                        }
                    }
                    (None, None) => savana_policy_core::v2::ControlEvidenceV2::ExplicitAlternative,
                    _ => return Err(KernelAgentAuthorityErrorV2::BindingMismatch),
                };
                let endorsements = savana_policy_core::v2::checked_control_endorsements_v2(
                    &intent.task_match,
                    &intent.control_selections,
                    evidence,
                    &savana_policy_core::v2::TaskMatchContextV2 {
                        current_authorization: Some(state.authorization()),
                        pre_state_digest: state.digest(),
                        pre_state_revision: state.revision(),
                        deployment_generation,
                        now,
                    },
                )
                .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?;
                let task = savana_policy_core::v2::TaskDispatchAuthorizationV2::new(
                    intent.task_match.clone(),
                    endorsements,
                );
                let task = if let Some(binding) = &intent.fused {
                    task.with_fused_recipe(binding.recipe.clone())
                        .with_fused_result_scope(
                            result_scope
                                .clone()
                                .ok_or(KernelAgentAuthorityErrorV2::BindingMismatch)?,
                        )
                } else {
                    task
                };
                // Resolve the selector locally from signed activation and exact
                // frozen G4 material; never trust an Agent/model operation ID.
                // This does not open the fused-session legacy entry guards.
                let task = policy
                    .durable
                    .bind_fused_dispatch_v04(
                        intent.action_intent_id,
                        task,
                        deployment_generation,
                        now,
                    )
                    .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?;
                let task = policy
                    .durable
                    .bind_managed_dispatch_input_v04(
                        intent.action_intent_id,
                        task,
                        &intent.dispatch_plaintext,
                        self.managed_resource_issuer
                            .as_ref()
                            .map(|issuer| issuer.signer()),
                        now,
                    )
                    .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?;
                policy
                    .durable
                    .prepare_task_bound_tool_dispatch(
                        intent.action_intent_id,
                        quota,
                        intent.approval_settlement,
                        resolved_ticket,
                        effect_lease,
                        sealed_payload_digest,
                        &task,
                        now,
                    )
                    .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)
            },
        );
        #[cfg(test)]
        {
            self.execution_declassification_gate_test_observation =
                execution_declassification_gate_test_observation;
        }
        let (prepared, execution_declassification) = execution_gate_result?;
        #[cfg(test)]
        if self.fused_recovery_fault == Some(fused_actions::FusedRecoveryFaultV04::G7Prepared) {
            self.fused_recovery_fault = None;
            return Err(KernelAgentAuthorityErrorV2::Unavailable);
        }
        let fused_recovery = if intent.fused.is_some() {
            Some(
                policy
                    .durable
                    .recover_fused_executions_v04(intent.durable_task_id)
                    .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?
                    .into_iter()
                    .find(|r| {
                        r.core().execution_nonce() == prepared.preparation().execution_nonce()
                    })
                    .ok_or(KernelAgentAuthorityErrorV2::StateConflict)?,
            )
        } else {
            None
        };
        // Managed inputs are not generic attachments: the signed source policy
        // must permit the exact fixed projection, and bytes must match the
        // original G7 snapshot AND already G3-gated presealed commitment.
        policy
            .durable
            .check_managed_execution_handoff_v04(
                &prepared,
                &intent.dispatch_plaintext,
                execution_declassification.provenance_digest(),
                now,
            )
            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
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
                execution_declassification.provenance_digest(),
                FixedBytes32V2::new(hpke_enc),
                BoundedCiphertextV2::new(hpke_ciphertext)
                    .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?,
            )
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?,
            &g7.envelope_signing_key,
        )
        .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        let deadline = checked_deadline(now, 5_000)?;
        // A lost response is not proof of no effect. Retain this exact identity
        // before transport so a ticket retry observes it without dispatching again.
        let execution_index = self.executions.len();
        self.executions.push(ExecutionRecordV2 {
            execution,
            commitment,
            ticket_commitment: Some(ticket_commitment),
            fused_recovery,
            action_intent_id: intent.action_intent_id,
            active_state_manifest_digest,
            deployment_generation,
            effect_fence_epoch,
            execution_nonce: prepared.preparation().execution_nonce(),
            dispatch_core_digest: prepared.preparation().dispatch_core_digest(),
            dispatch_subject_digest: prepared.preparation().dispatch_subject_digest(),
            status: PublicExecutionStatusV2::Dispatching,
            completion: None,
        });
        let response = g7
            .executor
            .dispatch(request_id, deadline, DispatchRequestV2::new(envelope))
            .map_err(map_executor_client_error)?;
        let status = public_unreconciled_executor_status(response.status());
        self.executions[execution_index].status = status;
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
        self.execution_status_inner(
            request_id,
            request,
            vault,
            active_state_manifest_digest,
            deployment_generation,
            effect_fence_epoch,
            now,
            IntentAccessV2::LegacyAgent,
        )
    }

    fn check_execution_context(
        &self,
        record: &ExecutionRecordV2,
        manifest: Digest32V2,
        generation: u64,
        fence: u64,
    ) -> Result<(), KernelAgentAuthorityErrorV2> {
        if record.active_state_manifest_digest != manifest
            || record.deployment_generation != generation
            || record.effect_fence_epoch != fence
        {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn execution_status_inner(
        &mut self,
        request_id: savana_kernel_protocol::v2::RequestIdV2,
        request: GetExecutionStatusRequestV2,
        vault: &mut dyn KernelIngressCommitSinkV2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        effect_fence_epoch: u64,
        now: UnixMillisV2,
        access: IntentAccessV2,
    ) -> Result<GetExecutionStatusResponseV2, KernelAgentAuthorityErrorV2> {
        self.ensure_durable_available()?;
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
                    .position(|record| record.ticket_commitment == Some(commitment))
            }
            ExecutionStatusTargetV2::Execution(execution) => {
                let commitment = execution.authority_commitment(&self.handle_key);
                self.executions
                    .iter()
                    .position(|record| record.commitment == commitment)
            }
        }
        .ok_or(KernelAgentAuthorityErrorV2::InvalidReference)?;
        if self.executions[index].fused_recovery.is_some()
            != (access == IntentAccessV2::PrivateFused)
        {
            return Err(KernelAgentAuthorityErrorV2::InvalidReference);
        }
        self.check_execution_context(
            &self.executions[index],
            active_state_manifest_digest,
            deployment_generation,
            effect_fence_epoch,
        )?;
        if let Some(recovered) = self.executions[index].fused_recovery.as_ref().filter(|_| {
            !matches!(
                self.executions[index].status,
                PublicExecutionStatusV2::Succeeded { .. }
            )
        }) {
            if let Some(commit) = recovered.result_commit() {
                let scope = recovered.scope();
                let document = vault
                    .recover_tool_result(
                        recovered.core().durable_task_id(),
                        recovered.core().durable_run_id(),
                        scope.principal(),
                        commit,
                        scope.expires_at(),
                        now,
                    )
                    .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?;
                let status = PublicExecutionStatusV2::Succeeded {
                    completion: PublicDispatchCompletionV2::ToolExecution { document },
                };
                self.executions[index].status = status;
                return Ok(GetExecutionStatusResponseV2::new(status));
            }
        }
        // Historical receipts settle the original reservation, including after
        // plan replacement, expiry or revocation. Do not recheck the next action
        // or refresh the original match against today's pre-state here.
        if matches!(
            self.executions[index].status,
            PublicExecutionStatusV2::Succeeded { .. }
                | PublicExecutionStatusV2::EffectSucceededOutputQuarantined { .. }
                | PublicExecutionStatusV2::FailedNoEffect { .. }
        ) || (access == IntentAccessV2::LegacyAgent
            && self.executions[index].status == PublicExecutionStatusV2::Indeterminate)
        {
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
        // An authenticated transport may still return the wrong job's receipt.
        // Bind every status witness to the exact query before mutating any job
        // or fetching a completion. A signature alone is not this association.
        let status_receipt = match response.status() {
            ExecutorStatusV2::EffectStarted {
                effect_started_receipt,
                effect_started_receipt_digest,
            }
            | ExecutorStatusV2::CompletionAvailable {
                effect_started_receipt,
                effect_started_receipt_digest,
                ..
            } => Some((effect_started_receipt, *effect_started_receipt_digest)),
            ExecutorStatusV2::Indeterminate {
                effect_started_receipt: Some(receipt),
                effect_started_receipt_digest: Some(digest),
            } => Some((receipt, *digest)),
            _ => None,
        };
        if let Some((receipt, digest)) = status_receipt {
            let unsigned = receipt.unsigned();
            if unsigned.execution_nonce() != nonce
                || unsigned.dispatch_core_digest() != core
                || unsigned.dispatch_subject_digest() != subject
                || unsigned.installation_id() != self.config.installation_id
                || unsigned.active_state_manifest_digest() != active_state_manifest_digest
                || unsigned.deployment_generation() != deployment_generation
                || unsigned.effect_fence_epoch() != effect_fence_epoch
                || unsigned.started_at().get() > now.get()
                || receipt.digest() != digest
            {
                return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
            }
            let (key_id, public_key) = self.executor_receipt_identity()?;
            receipt
                .verify(key_id, public_key)
                .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        }
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
                let (key_id, public_key) = self.executor_receipt_identity()?;
                let outcome = verify_task_no_effect_response(
                    &self
                        .policy
                        .as_ref()
                        .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?
                        .durable,
                    &response,
                    nonce,
                    core,
                    subject,
                    key_id,
                    public_key,
                    now,
                )?;
                self.policy
                    .as_mut()
                    .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?
                    .durable
                    .reconcile_task_outcome(outcome)
                    .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?;
                PublicExecutionStatusV2::FailedNoEffect {
                    class: PublicFailureClassV2::Connector,
                }
            }
            ExecutorStatusV2::Indeterminate {
                effect_started_receipt,
                ..
            } if access == IntentAccessV2::PrivateFused => {
                // A query's uncertain status is not a signed terminal outcome.
                // Keep the existing G7 reservation (or verified effect-start)
                // durable, so a later exact success can still settle it. Never
                // use V2's irreversible terminal-Indeterminate transition here.
                if let Some(receipt) = effect_started_receipt {
                    let (key_id, public_key) = self.executor_receipt_identity()?;
                    self.policy
                        .as_mut()
                        .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?
                        .durable
                        .reconcile_typed_effect_started_tool_dispatch(
                            receipt, key_id, public_key, now,
                        )
                        .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?;
                }
                PublicExecutionStatusV2::Indeterminate
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
        let started = response.effect_started_receipt().unsigned();
        if started.execution_nonce() != nonce
            || started.dispatch_core_digest() != core
            || started.dispatch_subject_digest() != subject
            || started.active_state_manifest_digest() != active_state_manifest_digest
            || started.deployment_generation() != deployment_generation
            || started.effect_fence_epoch() != effect_fence_epoch
            || response.effect_started_receipt().digest()
                != response.effect_started_receipt_digest()
        {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        response
            .effect_started_receipt()
            .verify(receipt_key_id, receipt_public_key)
            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let task_outcome = verify_task_completion_response(
            &self
                .policy
                .as_ref()
                .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?
                .durable,
            &response,
            receipt_key_id,
            receipt_public_key,
            now,
        )?;
        let result = match response.payload() {
            savana_kernel_protocol::v2::ExecutorCompletionPayloadV2::ToolResult { result } => {
                // Use the protocol's canonical descriptor (digest domain and
                // byte length), not a second locally invented result hash.
                if response.payload().descriptor().ok() != Some(completion) {
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
        let (
            task,
            run,
            principal,
            producer,
            expires_at,
            effects,
            action_intent_record_digest,
            descriptor,
        ) = if let Some(recovered) = &self.executions[index].fused_recovery {
            // Use the original G7 scope, never a newly logged-in session or
            // fresh handle as the authority/provenance of yesterday's result.
            let scope = recovered.scope();
            (
                recovered.core().durable_task_id(),
                recovered.core().durable_run_id(),
                scope.principal(),
                scope.producer(),
                scope.expires_at(),
                scope.effects(),
                recovered.result_binding(),
                recovered.descriptor(),
            )
        } else {
            let intent = self
                .intents
                .iter()
                .find(|i| i.action_intent_id == action_intent_id)
                .ok_or(KernelAgentAuthorityErrorV2::StateConflict)?;
            let session = self
                .sessions
                .iter()
                .find(|s| s.run == intent.run)
                .ok_or(KernelAgentAuthorityErrorV2::StateConflict)?;
            if session.active_state_manifest_digest != active_state_manifest_digest
                || deployment_generation == 0
                || effect_fence_epoch == 0
            {
                return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
            }
            (
                session.durable_task_id,
                session.durable_run_id,
                session.principal,
                session.producer_identity,
                session.expires_at,
                session.policy_allowed_effects,
                domain_digest(
                    b"SAVANA_ACTION_INTENT_RESULT_BINDING_V2\0",
                    &[
                        action_intent_id.as_bytes(),
                        intent.intent_commitment.as_bytes(),
                    ],
                ),
                intent.descriptor_digest,
            )
        };
        let value = KernelValueV2::bytes(result.clone())
            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let provenance_context =
            savana_policy_core::v2::ProvenanceContextV2::from_authenticated_runtime(
                producer,
                run,
                active_state_manifest_digest,
                // Stable across a retry after a vault commit response loss.
                response.effect_started_receipt().unsigned().started_at(),
                expires_at,
            )
            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let provenance = ProvenanceRecordV2::from_verified_executor_tool_result(
            &value,
            provenance_context,
            action_intent_id,
            domain_digest(b"SAVANA_EXECUTION_NONCE_DIGEST_V2\0", &[nonce.as_bytes()]),
            action_intent_record_digest,
            descriptor,
            response.effect_started_receipt_digest(),
            effects,
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
                task,
                run,
                principal,
                provenance.clone(),
                commit_digest,
                result,
                expires_at,
                now,
            )
            .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?;
        #[cfg(test)]
        if self.fused_recovery_fault == Some(fused_actions::FusedRecoveryFaultV04::VaultCommitted) {
            self.fused_recovery_fault = None;
            return Err(KernelAgentAuthorityErrorV2::Unavailable);
        }
        self.policy
            .as_mut()
            .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?
            .durable
            .reconcile_task_outcome(task_outcome)
            .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?;
        #[cfg(test)]
        if self.fused_recovery_fault == Some(fused_actions::FusedRecoveryFaultV04::OutcomeCommitted)
        {
            self.fused_recovery_fault = None;
            return Err(KernelAgentAuthorityErrorV2::Unavailable);
        }
        if self.executions[index].fused_recovery.is_some() {
            let durable = &mut self
                .policy
                .as_mut()
                .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?
                .durable;
            if durable
                .fused_execution_needs_result_v04(task, nonce)
                .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?
            {
                durable
                    .record_fused_result_value_v04(
                        task,
                        nonce,
                        commit_digest,
                        savana_policy_core::v2::FusedOwnedResultV04::from_verified_result(
                            &value,
                            &provenance,
                        )
                        .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?,
                    )
                    .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?;
            } else {
                durable
                    .record_fused_result_commit_v04(task, nonce, commit_digest)
                    .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?;
            }
            // Publish the new durable reference to the existing private handle
            // before any later fault/cleanup. A surviving handle must never try
            // to refetch bytes that the recovery driver has already cleaned.
            self.executions[index].fused_recovery = Some(
                self.policy
                    .as_ref()
                    .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?
                    .durable
                    .recover_all_scoped_fused_executions_v04()
                    .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?
                    .into_iter()
                    .find(|r| r.core().execution_nonce() == nonce)
                    .ok_or(KernelAgentAuthorityErrorV2::StateConflict)?,
            );
        }
        #[cfg(test)]
        if self.fused_recovery_fault
            == Some(fused_actions::FusedRecoveryFaultV04::ResultCheckpointed)
        {
            self.fused_recovery_fault = None;
            return Err(KernelAgentAuthorityErrorV2::Unavailable);
        }
        // Both result bytes and the verified terminal outcome are durable now.
        // Retain the local observation before the cleanup acknowledgement: a
        // lost acknowledgement cannot turn this success back into pending or
        // force a second result insertion/provider attempt.
        let committed_status = PublicExecutionStatusV2::Succeeded {
            completion: PublicDispatchCompletionV2::ToolExecution { document },
        };
        self.executions[index].completion = Some(completion);
        self.executions[index].status = committed_status;
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
        Ok(committed_status)
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
        let current_root = self.require_session_task_authorization(session, now)?;
        let owned_source = self
            .tasks
            .iter()
            .find(|task| {
                task.durable_task_id == session.durable_task_id
                    && task.expected_principal == Some(session.principal)
                    && task.durable_run_id == Some(session.durable_run_id)
                    && task.active_state_manifest_digest == active_state_manifest_digest
            })
            .and_then(|task| task.source_input_digest)
            .ok_or(KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let committed_plan = self
            .plan_steps
            .iter()
            .rev()
            .find(|step| step.run == session.run && step.task_authorization_digest == current_root)
            .ok_or(KernelAgentAuthorityErrorV2::StateConflict)?;
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
        if request.evidence().is_empty() {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        // The released document is the session's original input. Its owned
        // provenance is mandatory even if the untrusted caller omits it.
        let mut evidence_handles = request.evidence().to_vec();
        if !evidence_handles.contains(&session.initial_value) {
            evidence_handles.insert(0, session.initial_value);
        }
        let resolved_evidence = evidence_handles
            .iter()
            .map(|handle| {
                values
                    .resolve_g4_value(session.run, *handle, now)
                    .map_err(map_value_error)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut evidence = resolved_evidence
            .iter()
            .map(|resolved| {
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
        let token_entries = resolved_evidence
            .iter()
            .enumerate()
            .map(|(ordinal, resolved)| {
                Ok(TokenSetDigestEntryV2::new(
                    IdentifierV2::new(format!("release_value_{ordinal:04}"))
                        .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?,
                    Digest32V2::new(*resolved.value_internal_id().as_bytes()),
                    provenance_digest_v2(resolved.provenance())
                        .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?,
                    request.executor(),
                ))
            })
            .collect::<Result<Vec<_>, KernelAgentAuthorityErrorV2>>()?;
        let token_set_digest = savana_policy_core::v2::token_set_digest_v2(&token_entries)
            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let provenance_parents = resolved_evidence
            .iter()
            .map(|resolved| resolved.provenance().clone())
            .collect::<Vec<_>>();
        let policy_allowed_effects = provenance_parents
            .iter()
            .fold(EffectSetV2::ALL, |effects, parent| {
                effects.intersection(parent.label().effects())
            });
        let plaintext = vault
            .read_release_payload(request.document(), session.durable_run_id, now)
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        let release_payload_digest = domain_digest(
            b"SAVANA_FINAL_RELEASE_PAYLOAD_V2\0",
            &[plaintext.as_slice()],
        );
        let proposal = project_final_release_business(
            policy,
            session,
            request,
            owned_source,
            committed_plan,
            &plaintext,
            evidence_digest,
            deployment_generation,
            now,
        )?;
        let run = session.run;
        self.finish_prepare_release(
            run,
            Some(request.document()),
            request.executor(),
            None,
            proposal,
            provenance_parents,
            policy_allowed_effects,
            release_payload_digest,
            evidence_digest,
            token_set_digest,
            vault,
            active_state_manifest_digest,
            deployment_generation,
            now,
        )
    }

    /// Both entry paths must establish their own source authority first. Only
    /// the exact G3 display, vault binding and G6 ceremony construction is shared.
    #[allow(clippy::too_many_arguments)]
    fn finish_prepare_release(
        &mut self,
        run: savana_kernel_protocol::v2::RunHandleV2,
        document: Option<MaskedDocumentHandleV2>,
        executor: ExecutorIdentityV2,
        private_candidate: Option<Digest32V2>,
        proposal: FinalReleaseBusinessProposalV2,
        provenance_parents: Vec<ProvenanceRecordV2>,
        policy_allowed_effects: EffectSetV2,
        release_payload_digest: Digest32V2,
        evidence_digest: Digest32V2,
        token_set_digest: Digest32V2,
        vault: &mut dyn KernelIngressCommitSinkV2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        now: UnixMillisV2,
    ) -> Result<PrepareReleaseResponseV2, KernelAgentAuthorityErrorV2> {
        let session = self
            .sessions
            .iter()
            .find(|s| s.run == run)
            .ok_or(KernelAgentAuthorityErrorV2::InvalidReference)?;
        let policy = self
            .policy
            .as_ref()
            .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?;
        let destination_digest = proposal.task_match.content().action().destination_digest();
        let display_projection_digest = proposal.display_projection_digest;
        let state = policy
            .durable
            .task_authorization_state(session.durable_task_id)
            .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?;
        // Final release has no result-derived controls.
        let display_text = task_bound_display(
            &proposal.task_match,
            &proposal.business_request,
            &state,
            &std::collections::BTreeMap::new(),
        )?;
        let display_digest = approval_display_digest_v2(display_text.as_bytes());
        let display_value = KernelValueV2::text(display_text.as_str())
            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let first_parent = provenance_parents
            .first()
            .ok_or(KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let display_context = ProvenanceContextV2::from_authenticated_runtime(
            first_parent.producer_identity(),
            session.durable_run_id,
            active_state_manifest_digest,
            now,
            first_parent.expires_at(),
        )
        .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let display_parents = provenance_parents.iter().collect::<Vec<_>>();
        let declassification_rules = policy
            .declassification_rules
            .snapshot()
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        let display_declassification = ProvenanceRecordV2::declassify(
            &display_value,
            display_context,
            DeclassificationTransitionV2::BuildApprovalDisplay,
            &declassification_rules,
            ClosedDeclassificationPurposeV2::ApprovalDisplay.purpose_digest(),
            token_set_digest,
            None,
            &display_parents,
            policy_allowed_effects,
            now.get(),
        )
        .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        if display_declassification.judge_handoff(
            DeclassificationTransitionV2::BuildApprovalDisplay,
            &declassification_rules,
        ) != HandoffJudgmentV2::Admits
        {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
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
            Digest32V2::new(*executor.as_bytes()),
            release_quota_subject_digest,
        )
        .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let vault_pending = if let Some(digest) = private_candidate {
            if document.is_some() {
                return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
            }
            let c = policy
                .durable
                .fused_final_result_candidate_v04(session.durable_task_id, now)
                .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?;
            if c.digest() != digest {
                return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
            }
            vault.prepare_fused_result_release(&c, session.principal, material, now)
        } else {
            vault.prepare_release(
                document.ok_or(KernelAgentAuthorityErrorV2::BindingMismatch)?,
                session.durable_run_id,
                material,
                now,
            )
        }
        .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?;
        let binding = vault_pending.binding();
        let binding_digest = vault_pending.binding_digest();
        let candidate_expiry = checked_deadline(now, TOOL_APPROVAL_TTL_MS)?;
        let expires_at = UnixMillisV2::new(
            candidate_expiry
                .get()
                .min(session.expires_at.get())
                .min(first_parent.expires_at().get())
                .min(state.authorization().material().expires_at().get()),
        );
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
            display_text,
            Some(display_declassification.provenance_digest()),
            policy.approval.approvald_identity,
            now,
            expires_at,
        )
        .and_then(|unsigned| {
            unsigned.with_task_action_binding(
                savana_kernel_protocol::v2::TaskActionApprovalBindingV2::new(
                    proposal.task_match.content_digest(),
                    proposal.task_match.content().authorization_id(),
                    proposal.task_match.content().authorization_revision(),
                    session.durable_task_id,
                )?,
            )
        })
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
            private_candidate,
            display_authentication: display_authentication.clone(),
            pending,
            pending_commitment,
            approval,
            approval_commitment,
            document,
            run: session.run,
            durable_run_id: session.durable_run_id,
            durable_task_id: session.durable_task_id,
            principal: session.principal,
            business_request: proposal.business_request,
            task_match: proposal.task_match,
            control_selections: proposal.control_selections,
            envelope: envelope.clone(),
            task_action_approval: None,
            provenance_parents,
            policy_allowed_effects,
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
        let index = self.pending_releases.len() - 1;
        if let Err(error) = self.bind_fused_release_archive_v04(index, now) {
            self.pending_releases.pop();
            return Err(error);
        }
        let p = &self.pending_releases[index];
        Ok(PrepareReleaseResponseV2::new(
            p.pending,
            p.approval,
            p.envelope.clone(),
            p.display_authentication.clone(),
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
        self.authorize_release_for(
            request,
            vault,
            false,
            active_state_manifest_digest,
            deployment_generation,
            now,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn authorize_release_for(
        &mut self,
        request: &savana_kernel_protocol::v2::AuthorizeReleaseRequestV2,
        vault: &mut dyn KernelIngressCommitSinkV2,
        private: bool,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        now: UnixMillisV2,
    ) -> Result<savana_kernel_protocol::v2::AuthorizeReleaseResponseV2, KernelAgentAuthorityErrorV2>
    {
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
        if self.pending_releases[index].private_candidate.is_some() != private {
            return Err(KernelAgentAuthorityErrorV2::InvalidReference);
        }
        self.recheck_release_task(
            &self.pending_releases[index],
            active_state_manifest_digest,
            deployment_generation,
            now,
        )?;
        if self.pending_releases[index].consumed {
            if private {
                self.retain_fused_release_settlement_v04(index, request.settlement())?;
            }
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
            self.retain_fused_release_settlement_v04(index, request.settlement())?;
            self.pending_releases[index].consumed = true;
            return Err(KernelAgentAuthorityErrorV2::StateConflict);
        }
        let expected = record
            .envelope
            .unverified_material()
            .and_then(|envelope| envelope.task_action_context(&request.settlement().unsigned()))
            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let task_action = savana_kernel_protocol::v2::verify_task_action_approval_v2(
            request
                .settlement()
                .task_action_approval()
                .ok_or(KernelAgentAuthorityErrorV2::BindingMismatch)?,
            &ed25519_dalek::VerifyingKey::from_bytes(&approval.settlement_public_key)
                .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?,
            &expected,
            now,
        )
        .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        if expected.content_digest != record.task_match.content_digest()
            || expected.authorization_id != record.task_match.content().authorization_id()
            || expected.authorization_revision
                != record.task_match.content().authorization_revision()
            || expected.task != record.durable_task_id
        {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        self.retain_fused_release_settlement_v04(index, request.settlement())?;
        let record = &self.pending_releases[index];
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
                binding.destination_digest(),
                binding.token_set_digest(),
                active_state_manifest_digest,
                verified.issued_at(),
                verified.expires_at(),
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
        self.pending_releases[index].task_action_approval = Some(task_action);
        self.pending_releases[index].ticket_commitment = Some(commitment);
        Ok(savana_kernel_protocol::v2::AuthorizeReleaseResponseV2::new(
            ticket,
        ))
    }

    fn recheck_release_task(
        &self,
        record: &PendingReleaseRecordV2,
        manifest: Digest32V2,
        generation: u64,
        now: UnixMillisV2,
    ) -> Result<(), KernelAgentAuthorityErrorV2> {
        let session = self
            .sessions
            .iter()
            .find(|s| {
                s.run == record.run
                    && matches!(
                        s.status,
                        AgentSessionStatusV2::Ready | AgentSessionStatusV2::Running
                    )
            })
            .ok_or(KernelAgentAuthorityErrorV2::InvalidReference)?;
        if record.active_state_manifest_digest != manifest
            || session.active_state_manifest_digest != manifest
            || (if record.private_candidate.is_some() {
                self.require_current_session_task_authorization(session, now)?
            } else {
                self.require_session_task_authorization(session, now)?
            }) != record.task_match.authorization().digest()
        {
            return Err(KernelAgentAuthorityErrorV2::StateConflict);
        }
        let policy = self
            .policy
            .as_ref()
            .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?;
        if let Some(expected) = record.private_candidate {
            let candidate = policy
                .durable
                .fused_final_result_candidate_v04(record.durable_task_id, now)
                .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?;
            if candidate.digest() != expected
                || candidate.core().durable_run_id() != record.durable_run_id
            {
                return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
            }
        }
        let state = policy
            .durable
            .task_authorization_state(record.durable_task_id)
            .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?;
        if state.revoked() {
            return Err(KernelAgentAuthorityErrorV2::StateConflict);
        }
        record
            .task_match
            .recheck(&savana_policy_core::v2::TaskMatchContextV2 {
                current_authorization: Some(state.authorization()),
                pre_state_digest: state.digest(),
                pre_state_revision: state.revision(),
                deployment_generation: generation,
                now,
            })
            .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?;
        let descriptor = policy
            .active_tools
            .resolve(
                record
                    .task_match
                    .content()
                    .action()
                    .tool_descriptor_digest(),
                session.role,
                now,
            )
            .ok_or(KernelAgentAuthorityErrorV2::BindingMismatch)?;
        if descriptor.descriptor().unsigned().business_profile()
            != Some(record.business_request.profile())
        {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        Ok(())
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
        self.dispatch_release_for(
            request_id,
            request,
            vault,
            false,
            active_state_manifest_digest,
            deployment_generation,
            effect_fence_epoch,
            now,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn dispatch_release_for(
        &mut self,
        request_id: savana_kernel_protocol::v2::RequestIdV2,
        request: savana_kernel_protocol::v2::DispatchReleaseRequestV2,
        vault: &mut dyn KernelIngressCommitSinkV2,
        private: bool,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        effect_fence_epoch: u64,
        now: UnixMillisV2,
    ) -> Result<savana_kernel_protocol::v2::DispatchReleaseResponseV2, KernelAgentAuthorityErrorV2>
    {
        let ticket_commitment = request.ticket().authority_commitment(&self.handle_key);
        let owner = self
            .release_tickets
            .iter()
            .find(|r| r.commitment == ticket_commitment)
            .and_then(|t| {
                self.pending_releases
                    .iter()
                    .find(|p| p.pending_commitment == t.pending_commitment)
            })
            .ok_or(KernelAgentAuthorityErrorV2::InvalidReference)?;
        if owner.private_candidate.is_some() != private {
            return Err(KernelAgentAuthorityErrorV2::InvalidReference);
        }
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
        if self.releases.len() >= self.maximum_records {
            return Err(KernelAgentAuthorityErrorV2::LimitExceeded);
        }
        self.releases
            .try_reserve(1)
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        let release_handle = mint_handle(ReleaseHandleV2::from_authority_entropy)?;
        let commitment = release_handle.authority_commitment(&self.handle_key);
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
        self.recheck_release_task(
            pending,
            active_state_manifest_digest,
            deployment_generation,
            now,
        )?;
        let authorized = pending
            .authorized
            .ok_or(KernelAgentAuthorityErrorV2::StateConflict)?;
        let settlement = pending
            .settlement
            .as_ref()
            .ok_or(KernelAgentAuthorityErrorV2::StateConflict)?;
        let binding = authorized.binding();
        if ticket.durable_release_id != binding.durable_release_id()
            || ticket.binding_digest != pending.binding_digest
            || pending.active_state_manifest_digest != active_state_manifest_digest
        {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        let plaintext = if let Some(expected) = pending.private_candidate {
            let candidate = self
                .policy
                .as_ref()
                .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?
                .durable
                .fused_final_result_candidate_v04(pending.durable_task_id, now)
                .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?;
            if candidate.digest() != expected {
                return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
            }
            zeroize::Zeroizing::new(candidate.private_payload().to_vec())
        } else {
            vault
                .read_release_payload(
                    pending
                        .document
                        .ok_or(KernelAgentAuthorityErrorV2::BindingMismatch)?,
                    pending.durable_run_id,
                    now,
                )
                .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?
        };
        if domain_digest(
            b"SAVANA_FINAL_RELEASE_PAYLOAD_V2\0",
            &[plaintext.as_slice()],
        ) != binding.release_payload_digest()
        {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        let same_payload = if private {
            savana_kernel_protocol::v2::decode_final_result_release_delivery_v04(
                &pending.business_request.canonical_json(),
            )
            .map(|d| d.payload() == plaintext.as_slice())
        } else {
            savana_kernel_protocol::v2::decode_final_release_delivery_v2(
                &pending.business_request.canonical_json(),
            )
            .map(|d| d.payload() == plaintext.as_slice())
        }
        .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        if !same_payload
            || pending.task_match.content().action().destination_digest()
                != binding.destination_digest()
            || pending.task_match.content().provenance_digest() != binding.evidence_digest()
        {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        // Final release has no result-derived controls.
        let dispatch_plaintext = task_execution_plaintext(
            &pending.task_match,
            &pending.business_request,
            &std::collections::BTreeMap::new(),
        )?;
        let policy = self
            .policy
            .as_mut()
            .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?;
        let g7 = policy
            .g7
            .as_ref()
            .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?;
        // Review the actual decoded data, not base64/CBOR that could conceal a
        // forbidden token from the leak gate. The exact closed transport capsule
        // is separately committed by the preseal digest below.
        let release_value = KernelValueV2::bytes(plaintext.as_slice().to_vec())
            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let first_parent = pending
            .provenance_parents
            .first()
            .ok_or(KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let release_context = ProvenanceContextV2::from_authenticated_runtime(
            first_parent.producer_identity(),
            pending.durable_run_id,
            active_state_manifest_digest,
            now,
            first_parent.expires_at(),
        )
        .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let release_parents = pending.provenance_parents.iter().collect::<Vec<_>>();
        let release_transition = DeclassificationTransitionV2::BuildFinalRelease {
            sink_identity_digest: binding.destination_digest(),
        };
        let declassification_rules = policy
            .declassification_rules
            .snapshot()
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        let (prepared, release_declassification) = gate_final_release_before_durable_prepare(
            &dispatch_plaintext,
            || {
                let declassification = ProvenanceRecordV2::declassify(
                    &release_value,
                    release_context,
                    release_transition,
                    &declassification_rules,
                    ClosedDeclassificationPurposeV2::FinalRelease.purpose_digest(),
                    binding.token_set_digest(),
                    Some(settlement),
                    &release_parents,
                    pending.policy_allowed_effects,
                    now.get(),
                )
                .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
                if declassification.judge_handoff(release_transition, &declassification_rules)
                    != HandoffJudgmentV2::Admits
                {
                    return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
                }
                Ok(declassification)
            },
            || {
                g7.synchronize_connector_registry(
                    self.config.installation_id,
                    active_state_manifest_digest,
                    deployment_generation,
                    now,
                )
            },
            |sealed_payload_digest| {
                let release = savana_policy_core::v2::VerifiedFinalReleaseRecordV2::
                    from_authorized_vault_release(
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
                    &g7.connector_registry,
                    UnixMillisV2::new(
                        checked_deadline(now, 30_000)?
                            .get()
                            .min(pending.expires_at.get())
                            .min(first_parent.expires_at().get())
                            .min(
                                pending
                                    .task_action_approval
                                    .as_ref()
                                    .ok_or(KernelAgentAuthorityErrorV2::BindingMismatch)?
                                    .material()
                                    .expires_at()
                                    .get(),
                            ),
                    ),
                )
                .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
                let resolved_ticket = savana_policy_core::v2::ResolvedFinalReleaseTicketV2::
                    from_resolved_kernel_ticket(
                        ticket.commitment,
                        binding.durable_release_id(),
                        pending.binding_digest,
                    )
                    .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
                let state = policy
                    .durable
                    .task_authorization_state(pending.durable_task_id)
                    .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?;
                if state.revoked() {
                    return Err(KernelAgentAuthorityErrorV2::StateConflict);
                }
                let approval = pending
                    .task_action_approval
                    .as_ref()
                    .ok_or(KernelAgentAuthorityErrorV2::BindingMismatch)?;
                let endorsements = savana_policy_core::v2::checked_control_endorsements_v2(
                    &pending.task_match,
                    &pending.control_selections,
                    savana_policy_core::v2::ControlEvidenceV2::ActionApproval {
                        approval,
                        expected_context: approval.material().context(),
                    },
                    &savana_policy_core::v2::TaskMatchContextV2 {
                        current_authorization: Some(state.authorization()),
                        pre_state_digest: state.digest(),
                        pre_state_revision: state.revision(),
                        deployment_generation,
                        now,
                    },
                )
                .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?;
                let mut task = savana_policy_core::v2::TaskDispatchAuthorizationV2::new(
                    pending.task_match.clone(),
                    endorsements,
                );
                if let Some(candidate) = pending.private_candidate {
                    task =
                        task.with_fused_final_result(candidate, pending.business_request.clone());
                }
                policy
                    .durable
                    .prepare_task_bound_final_release_dispatch(
                        &release,
                        quota,
                        settlement,
                        resolved_ticket,
                        effect_lease,
                        sealed_payload_digest,
                        &task,
                        now,
                    )
                    .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)
            },
        )?;
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
        let private_archive = pending.private_candidate;
        let pending_commitment = pending.pending_commitment;
        let (hpke_enc, hpke_ciphertext) = seal_execution_payload(
            &dispatch_plaintext,
            g7.executor_seal_public_key,
            protocol_core
                .semantic_digest()
                .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?,
        )?;
        let envelope = SignedSealedExecutionEnvelopeV2::sign(
            SealedExecutionEnvelopePayloadV2::new(
                protocol_core,
                release_declassification.provenance_digest(),
                FixedBytes32V2::new(hpke_enc),
                BoundedCiphertextV2::new(hpke_ciphertext)
                    .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?,
            )
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?,
            &g7.envelope_signing_key,
        )
        .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        let deadline = checked_deadline(now, 5_000)?;
        vault
            .mark_release_dispatching(vault_prepared, now)
            .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?;
        let release_index = self.releases.len();
        self.releases.push(ReleaseRecordV2 {
            release: release_handle,
            commitment,
            ticket_commitment,
            pending_commitment,
            prepared: vault_prepared,
            execution_nonce: prepared.preparation().execution_nonce(),
            dispatch_core_digest: prepared.preparation().dispatch_core_digest(),
            dispatch_subject_digest: prepared.preparation().dispatch_subject_digest(),
            status: PublicExecutionStatusV2::Dispatching,
            completion: None,
        });
        if let Some(candidate) = private_archive {
            self.retain_fused_release_dispatch_v04(candidate, protocol_core)?;
        }
        let g7 = self
            .policy
            .as_ref()
            .and_then(|p| p.g7.as_ref())
            .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?;
        let response = g7
            .executor
            .dispatch(request_id, deadline, DispatchRequestV2::new(envelope))
            .map_err(map_executor_client_error)?;
        let status = public_unreconciled_executor_status(response.status());
        self.releases[release_index].status = status;
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
        self.release_status_for(request_id, request, vault, false, now)
    }

    fn release_status_for(
        &mut self,
        request_id: savana_kernel_protocol::v2::RequestIdV2,
        request: GetReleaseStatusRequestV2,
        vault: &mut dyn KernelIngressCommitSinkV2,
        private: bool,
        now: UnixMillisV2,
    ) -> Result<GetReleaseStatusResponseV2, KernelAgentAuthorityErrorV2> {
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
        let pending = self
            .pending_releases
            .iter()
            .find(|p| p.pending_commitment == self.releases[index].pending_commitment)
            .ok_or(KernelAgentAuthorityErrorV2::InvalidReference)?;
        if pending.private_candidate.is_some() != private {
            return Err(KernelAgentAuthorityErrorV2::InvalidReference);
        }
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
                let (key_id, public_key) = self.executor_receipt_identity()?;
                let outcome = verify_task_no_effect_response(
                    &self
                        .policy
                        .as_ref()
                        .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?
                        .durable,
                    &response,
                    nonce,
                    core,
                    subject,
                    key_id,
                    public_key,
                    now,
                )?;
                self.policy
                    .as_mut()
                    .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?
                    .durable
                    .reconcile_task_outcome(outcome)
                    .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?;
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
        let private_candidate = pending.private_candidate;
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
        let task_outcome = verify_task_completion_response(
            &self
                .policy
                .as_ref()
                .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?
                .durable,
            &response,
            receipt_key_id,
            receipt_public_key,
            now,
        )?;
        self.policy
            .as_mut()
            .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?
            .durable
            .reconcile_task_outcome(task_outcome)
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
        // The release and task outcome are committed before this cleanup IPC.
        // Keep the exact terminal observation even if its reply is lost.
        let acknowledgement =
            savana_kernel_protocol::v2::AcknowledgeCommittedCompletionRequestV2::new(
                record.execution_nonce,
                record.dispatch_core_digest,
                record.dispatch_subject_digest,
                completion,
                kernel_commit_digest,
            )
            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let committed_status = PublicExecutionStatusV2::Succeeded {
            completion: PublicDispatchCompletionV2::FinalRelease,
        };
        self.releases[index].completion = Some(completion);
        self.releases[index].status = committed_status;
        if let Some(candidate) = private_candidate {
            let r = self
                .fused_release_recovery
                .iter_mut()
                .find(|r| r.candidate == candidate)
                .ok_or(KernelAgentAuthorityErrorV2::StateConflict)?;
            r.completion = Some(completion);
            r.commit = Some(kernel_commit_digest);
            self.persist_fused_release_archive_v04()?;
        }
        self.policy
            .as_ref()
            .and_then(|policy| policy.g7.as_ref())
            .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?
            .executor
            .acknowledge(request_id, checked_deadline(now, 5_000)?, acknowledgement)
            .map_err(map_executor_client_error)?;
        Ok(committed_status)
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
        self.require_public_task_v04(self.tasks[task_index].durable_task_id)?;
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

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare_connector_registration(
        &mut self,
        request: &PrepareConnectorRegistrationRequestV2,
        caller_boot_id: BootIdV2,
        caller_identity: ServiceIdentityV2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        now: UnixMillisV2,
    ) -> Result<PrepareConnectorRegistrationResponseV2, KernelAgentAuthorityErrorV2> {
        self.verify_connector_ui_caller(caller_boot_id, caller_identity)?;
        if now.get() == 0 {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        self.connector_authorizations
            .retain(|record| now.get() < record.expires_at.get());
        let session = self
            .sessions
            .iter()
            .find(|session| session.session == request.session())
            .ok_or(KernelAgentAuthorityErrorV2::InvalidReference)?;
        if !matches!(
            session.status,
            AgentSessionStatusV2::Ready | AgentSessionStatusV2::Running
        ) || session.active_state_manifest_digest != active_state_manifest_digest
            || deployment_generation == 0
            || now.get() >= session.expires_at.get()
        {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        let policy = self
            .policy
            .as_ref()
            .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?;
        let g7 = policy
            .g7
            .as_ref()
            .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?;
        if is_zero(g7.connector_authority_key_id.as_bytes())
            || is_zero(&g7.connector_authority_public_key)
            || g7.connector_authority_signing_key.is_none()
        {
            return Err(KernelAgentAuthorityErrorV2::Unavailable);
        }
        let registry = g7
            .connector_registry
            .snapshot()
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        if registry.genesis_digest() != g7.connector_registry_genesis_digest {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        let descriptor = ConnectorDescriptorV2::from_canonical_bytes(
            request.canonical_descriptor(),
            registry.user_host_allowlist(),
        )
        .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        if descriptor.tier() != ConnectorTierV2::UserRegistered
            || registry.contains_registered_connector(descriptor.connector_id())
        {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        let session_commitment = session.session.authority_commitment(&self.handle_key);
        if self.connector_authorizations.len() >= self.maximum_records
            || self
                .connector_authorizations
                .iter()
                .filter(|record| record.session_commitment == session_commitment)
                .count()
                >= MAX_CONNECTOR_AUTHORIZATIONS_PER_SESSION_V2
        {
            return Err(KernelAgentAuthorityErrorV2::LimitExceeded);
        }
        let descriptor_digest =
            connector_registration_descriptor_digest_v2(request.canonical_descriptor())
                .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let previous_head_digest = registry.head_digest();
        let authorization = mint_handle(ConnectorUiAuthorizationHandleV2::from_authority_entropy)?;
        let authorization_commitment = authorization.authority_commitment(&self.handle_key);
        if self
            .connector_authorizations
            .iter()
            .any(|record| record.authorization_commitment == authorization_commitment)
        {
            return Err(KernelAgentAuthorityErrorV2::Unavailable);
        }
        let expires_at = UnixMillisV2::new(
            checked_deadline(now, TOOL_APPROVAL_TTL_MS)?
                .get()
                .min(session.expires_at.get()),
        );
        let record = ConnectorAuthorizationRecordV2 {
            authorization_commitment,
            session_commitment,
            descriptor_digest,
            previous_head_digest,
            principal: session.principal,
            durable_task_id: session.durable_task_id,
            durable_run_id: session.durable_run_id,
            origin: FixedOriginV2::Agent8768,
            caller_boot_id,
            active_state_manifest_digest,
            deployment_generation,
            issued_at: now,
            expires_at,
        };
        self.connector_authorizations
            .try_reserve(1)
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        self.connector_authorizations.push(record);
        PrepareConnectorRegistrationResponseV2::new(
            authorization,
            descriptor_digest,
            previous_head_digest,
            expires_at,
        )
        .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare_connector_registration_proposal(
        &self,
        request: &ProposeConnectorRegistrationRequestV2,
        values: &KernelValueOwnerV2,
        caller_boot_id: BootIdV2,
        caller_identity: ServiceIdentityV2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        now: UnixMillisV2,
    ) -> Result<PreparedConnectorRegistrationProposalV2, KernelAgentAuthorityErrorV2> {
        self.verify_connector_ui_caller(caller_boot_id, caller_identity)?;
        let authorization_commitment = request
            .authorization()
            .authority_commitment(&self.handle_key);
        let authorization_index = self
            .connector_authorizations
            .iter()
            .position(|record| record.authorization_commitment == authorization_commitment)
            .ok_or(KernelAgentAuthorityErrorV2::InvalidReference)?;
        let authorization = &self.connector_authorizations[authorization_index];
        if authorization.origin != FixedOriginV2::Agent8768
            || authorization.caller_boot_id != caller_boot_id
            || authorization.active_state_manifest_digest != active_state_manifest_digest
            || authorization.deployment_generation != deployment_generation
            || now.get() < authorization.issued_at.get()
            || now.get() >= authorization.expires_at.get()
        {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        let descriptor_digest =
            connector_registration_descriptor_digest_v2(request.canonical_descriptor())
                .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        if descriptor_digest != authorization.descriptor_digest {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        let session = self
            .sessions
            .iter()
            .find(|session| {
                session.session.authority_commitment(&self.handle_key)
                    == authorization.session_commitment
            })
            .ok_or(KernelAgentAuthorityErrorV2::InvalidReference)?;
        if !matches!(
            session.status,
            AgentSessionStatusV2::Ready | AgentSessionStatusV2::Running
        ) || session.principal != authorization.principal
            || session.durable_task_id != authorization.durable_task_id
            || session.durable_run_id != authorization.durable_run_id
            || session.active_state_manifest_digest != active_state_manifest_digest
            || now.get() >= session.expires_at.get()
        {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        let policy = self
            .policy
            .as_ref()
            .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?;
        let g7 = policy
            .g7
            .as_ref()
            .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?;
        if is_zero(g7.connector_authority_key_id.as_bytes())
            || is_zero(&g7.connector_authority_public_key)
            || g7.connector_authority_signing_key.is_none()
        {
            return Err(KernelAgentAuthorityErrorV2::Unavailable);
        }
        let registry = g7
            .connector_registry
            .snapshot()
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        if registry.head_digest() != authorization.previous_head_digest
            || registry.genesis_digest() != g7.connector_registry_genesis_digest
        {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        let descriptor = ConnectorDescriptorV2::from_canonical_bytes(
            request.canonical_descriptor(),
            registry.user_host_allowlist(),
        )
        .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        if descriptor.tier() != ConnectorTierV2::UserRegistered
            || registry.contains_registered_connector(descriptor.connector_id())
        {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }

        let display_text = connector_registration_display(&descriptor)?;
        let display_digest = approval_display_digest_v2(display_text.as_bytes());
        let binding = ApprovalBindingV2::ConnectorRegistration {
            descriptor_digest,
            previous_head_digest: authorization.previous_head_digest,
        };
        let display_projection_digest = domain_digest(
            b"SAVANA_CONNECTOR_REGISTRATION_DISPLAY_PROJECTION_V2\0",
            &[
                descriptor_digest.as_bytes(),
                authorization.previous_head_digest.as_bytes(),
            ],
        );
        let parent = values
            .resolve_g4_value(session.run, session.initial_value, now)
            .map_err(map_value_error)?;
        let display_value = KernelValueV2::text(display_text.as_str())
            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let display_context = ProvenanceContextV2::from_authenticated_runtime(
            parent.provenance().producer_identity(),
            session.durable_run_id,
            active_state_manifest_digest,
            now,
            parent.provenance().expires_at(),
        )
        .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let declassification_rules = policy
            .declassification_rules
            .snapshot()
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        let parents = [parent.provenance()];
        let display_declassification = ProvenanceRecordV2::declassify(
            &display_value,
            display_context,
            DeclassificationTransitionV2::BuildApprovalDisplay,
            &declassification_rules,
            ClosedDeclassificationPurposeV2::ApprovalDisplay.purpose_digest(),
            binding
                .binding_digest()
                .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?,
            None,
            &parents,
            session.policy_allowed_effects,
            now.get(),
        )
        .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        if display_declassification.judge_handoff(
            DeclassificationTransitionV2::BuildApprovalDisplay,
            &declassification_rules,
        ) != HandoffJudgmentV2::Admits
        {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        let decision_challenge = Nonce32V2::new(random_bytes()?);
        let unsigned = UnsignedApprovalEnvelopeV2::new(
            self.config.installation_id,
            active_state_manifest_digest,
            deployment_generation,
            ApprovalPurposeV2::ConnectorRegistration,
            Nonce32V2::new(random_bytes()?),
            decision_challenge,
            binding,
            session.principal,
            display_projection_digest,
            display_digest,
            display_text,
            Some(display_declassification.provenance_digest()),
            policy.approval.approvald_identity,
            now,
            authorization.expires_at,
        )
        .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let envelope = SignedApprovalEnvelopeV2::sign(unsigned, &self.config.envelope_signing_key)
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        let envelope_digest = envelope
            .envelope_digest()
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        let display_authentication = SignedUiAuthenticationEnvelopeV2::sign(
            UnsignedUiAuthenticationEnvelopeV2::new(
                self.config.installation_id,
                active_state_manifest_digest,
                deployment_generation,
                UiAuthenticationPurposeV2::ApprovalDisplay,
                UiAuthenticationBindingV2::ApprovalDisplay {
                    durable_task_id: session.durable_task_id,
                    approval_envelope_digest: envelope_digest,
                    approval_purpose: ApprovalPurposeV2::ConnectorRegistration,
                    display_digest,
                },
                Some(session.principal),
                FixedOriginV2::Approval8766,
                FixedOriginV2::Approval8766,
                Nonce32V2::new(random_bytes()?),
                now,
                authorization.expires_at,
            )
            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?,
            &self.config.envelope_signing_key,
        )
        .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        Ok(PreparedConnectorRegistrationProposalV2 {
            authorization_commitment,
            session: ConnectorUiSessionContextV2 {
                session: session.session,
                principal: session.principal,
                durable_task_id: session.durable_task_id,
                durable_run_id: session.durable_run_id,
                caller_boot_id,
                active_state_manifest_digest,
                deployment_generation,
                issued_at: now,
                expires_at: authorization.expires_at,
            },
            caller_identity,
            canonical_descriptor: request.canonical_descriptor().to_vec(),
            descriptor_digest,
            previous_head_digest: authorization.previous_head_digest,
            envelope,
            display_authentication,
            envelope_digest,
            decision_challenge,
        })
    }

    pub(crate) fn consume_connector_registration_proposal(
        &mut self,
        prepared: &PreparedConnectorRegistrationProposalV2,
    ) -> Result<(), KernelAgentAuthorityErrorV2> {
        let index = self
            .connector_authorizations
            .iter()
            .position(|record| record.authorization_commitment == prepared.authorization_commitment)
            .ok_or(KernelAgentAuthorityErrorV2::InvalidReference)?;
        let record = &self.connector_authorizations[index];
        if record.descriptor_digest != prepared.descriptor_digest
            || record.previous_head_digest != prepared.previous_head_digest
            || record.principal != prepared.session.principal
            || record.durable_task_id != prepared.session.durable_task_id
            || record.durable_run_id != prepared.session.durable_run_id
            || record.caller_boot_id != prepared.session.caller_boot_id
            || record.active_state_manifest_digest != prepared.session.active_state_manifest_digest
            || record.deployment_generation != prepared.session.deployment_generation
            || record.expires_at != prepared.session.expires_at
        {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        self.connector_authorizations.remove(index);
        Ok(())
    }

    pub(crate) fn connector_authorization_commitment(
        &self,
        authorization: ConnectorUiAuthorizationHandleV2,
    ) -> Result<Digest32V2, KernelAgentAuthorityErrorV2> {
        self.ensure_durable_available()?;
        Ok(authorization.authority_commitment(&self.handle_key))
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn propose_connector_registration(
        &mut self,
        request: &ProposeConnectorRegistrationRequestV2,
        values: &KernelValueOwnerV2,
        caller_boot_id: BootIdV2,
        caller_identity: ServiceIdentityV2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        now: UnixMillisV2,
    ) -> Result<ProposeConnectorRegistrationResponseV2, KernelAgentAuthorityErrorV2> {
        let prepared = self.prepare_connector_registration_proposal(
            request,
            values,
            caller_boot_id,
            caller_identity,
            active_state_manifest_digest,
            deployment_generation,
            now,
        )?;
        self.consume_connector_registration_proposal(&prepared)?;
        let pending = mint_handle(PendingConnectorRegistrationHandleV2::from_authority_entropy)?;
        Ok(ProposeConnectorRegistrationResponseV2::new(
            pending,
            prepared.envelope,
            prepared.display_authentication,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn connector_ui_session_context(
        &self,
        session_handle: AgentSessionHandleV2,
        caller_boot_id: BootIdV2,
        caller_identity: ServiceIdentityV2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        now: UnixMillisV2,
    ) -> Result<ConnectorUiSessionContextV2, KernelAgentAuthorityErrorV2> {
        self.verify_connector_ui_caller(caller_boot_id, caller_identity)?;
        if deployment_generation == 0 || now.get() == 0 {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        let session = self
            .sessions
            .iter()
            .find(|session| session.session == session_handle)
            .ok_or(KernelAgentAuthorityErrorV2::InvalidReference)?;
        if !matches!(
            session.status,
            AgentSessionStatusV2::Ready | AgentSessionStatusV2::Running
        ) || session.active_state_manifest_digest != active_state_manifest_digest
            || now.get() >= session.expires_at.get()
        {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        let g7 = self
            .policy
            .as_ref()
            .and_then(|policy| policy.g7.as_ref())
            .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?;
        if is_zero(g7.connector_authority_key_id.as_bytes())
            || is_zero(&g7.connector_authority_public_key)
            || g7.connector_authority_signing_key.is_none()
        {
            return Err(KernelAgentAuthorityErrorV2::Unavailable);
        }
        Ok(ConnectorUiSessionContextV2 {
            session: session.session,
            principal: session.principal,
            durable_task_id: session.durable_task_id,
            durable_run_id: session.durable_run_id,
            caller_boot_id,
            active_state_manifest_digest,
            deployment_generation,
            issued_at: now,
            expires_at: session.expires_at,
        })
    }

    pub(crate) fn connector_security_verifiers(
        &self,
    ) -> Result<ConnectorSecurityVerifiersV2, KernelAgentAuthorityErrorV2> {
        self.ensure_durable_available()?;
        let envelope_public_key = self.config.envelope_signing_key.verifying_key().to_bytes();
        Ok(ConnectorSecurityVerifiersV2 {
            installation_id: self.config.installation_id,
            settlement_key_id: self.config.ui_settlement_key_id,
            settlement_public_key: self.config.ui_settlement_public_key,
            envelope_key_id: derive_ed25519_key_id_v2(envelope_public_key),
            envelope_public_key,
        })
    }

    pub(crate) fn synchronize_executor_connector_registry(
        &self,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        now: UnixMillisV2,
    ) -> Result<(), KernelAgentAuthorityErrorV2> {
        self.ensure_durable_available()?;
        self.policy
            .as_ref()
            .and_then(|policy| policy.g7.as_ref())
            .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?
            .synchronize_connector_registry(
                self.config.installation_id,
                active_state_manifest_digest,
                deployment_generation,
                now,
            )
    }

    #[cfg(test)]
    pub(crate) fn connector_authorization_retained_descriptor_bytes_for_test(&self) -> usize {
        0
    }

    #[cfg(test)]
    pub(crate) fn connector_authorization_count_for_test(&self) -> usize {
        self.connector_authorizations.len()
    }

    /// The only connector-authority signing surface. Its argument can be
    /// created only by policy-core after validating a complete next delta.
    pub(crate) fn sign_prepared_connector_delta(
        &mut self,
        prepared: PreparedConnectorRegistryDeltaV2,
    ) -> Result<ConnectorRegistryDeltaV2, KernelAgentAuthorityErrorV2> {
        self.ensure_durable_available()?;
        let g7 = self
            .policy
            .as_mut()
            .and_then(|policy| policy.g7.as_mut())
            .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?;
        if g7.connector_registry_genesis_digest
            != g7
                .connector_registry
                .snapshot()
                .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?
                .genesis_digest()
            || g7
                .connector_registry
                .current_head_digest()
                .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?
                != prepared.previous_head_digest()
        {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        let signing_key = g7
            .connector_authority_signing_key
            .as_ref()
            .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?;
        if signing_key.verifying_key().to_bytes() != g7.connector_authority_public_key
            || derive_ed25519_key_id_v2(g7.connector_authority_public_key)
                != g7.connector_authority_key_id
        {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        let signature = signing_key
            .sign(prepared.signature_digest().as_bytes())
            .to_bytes();
        prepared
            .finalize(signature)
            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)
    }

    fn verify_connector_ui_caller(
        &self,
        caller_boot_id: BootIdV2,
        caller_identity: ServiceIdentityV2,
    ) -> Result<(), KernelAgentAuthorityErrorV2> {
        self.verify_agent_caller(caller_identity)?;
        if caller_boot_id != self.config.agentd_kernel_client_boot_id {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        Ok(())
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

fn connector_registration_display(
    descriptor: &ConnectorDescriptorV2,
) -> Result<BoundedApprovalDisplayTextV2, KernelAgentAuthorityErrorV2> {
    use std::fmt::Write as _;

    // Approval display text deliberately has no control characters. The wire
    // type rejects them, so fields use an explicit printable separator.
    let mut display = String::from("Connector registration proposal v2; ");
    display
        .try_reserve(16 * 1024)
        .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
    write!(
        &mut display,
        "tier: UserRegistered ({}); ",
        descriptor.tier().tag()
    )
    .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
    write!(
        &mut display,
        "name: {}; ",
        descriptor.display_name().as_str()
    )
    .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
    match descriptor.transport() {
        ConnectorTransportV2::Stdio { package_digest } => {
            write!(&mut display, "transport: stdio; package_digest: ")
                .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
            push_lower_hex(&mut display, package_digest.as_bytes())?;
            display.push_str("; ");
        }
        ConnectorTransportV2::Https {
            canonical_url,
            tls_identity_pin,
        } => {
            write!(
                &mut display,
                "transport: https; url: {}; tls_identity_pin: ",
                canonical_url.as_str()
            )
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
            push_lower_hex(&mut display, tls_identity_pin.as_bytes())?;
            display.push_str("; ");
        }
    }
    write!(
        &mut display,
        "requested_effects: {} (0x{:04x}); ",
        effect_names(descriptor.requested_effects()),
        descriptor.requested_effects().bits()
    )
    .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
    write!(
        &mut display,
        "structural_role: {} ({}); ",
        match descriptor.structural_role() {
            savana_policy_core::v2::ConnectorStructuralRoleV2::Source => "Source",
            savana_policy_core::v2::ConnectorStructuralRoleV2::Transform => "Transform",
            savana_policy_core::v2::ConnectorStructuralRoleV2::Sink => "Sink",
        },
        descriptor.structural_role().tag(),
    )
    .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
    write!(
        &mut display,
        "descriptor_version: {}; ",
        descriptor.descriptor_version()
    )
    .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
    write!(
        &mut display,
        "tool_count: {}; ",
        descriptor.tool_descriptors().len()
    )
    .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
    for (index, tool) in descriptor.tool_descriptors().iter().enumerate() {
        write!(
            &mut display,
            "tool[{index}].name: {}; ",
            tool.provider_tool_id().as_str()
        )
        .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        write!(
            &mut display,
            "tool[{index}].effects: {} (0x{:04x}); ",
            effect_names(tool.effects()),
            tool.effects().bits()
        )
        .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        let canonical =
            minicbor::to_vec(tool).map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let semantics = base64::engine::general_purpose::STANDARD.encode(canonical);
        write!(
            &mut display,
            "tool[{index}].semantics_canonical_cbor_base64: {semantics}; "
        )
        .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
    }
    let complete = base64::engine::general_purpose::STANDARD.encode(descriptor.canonical_bytes());
    write!(
        &mut display,
        "connector_descriptor_canonical_cbor_base64: {complete}"
    )
    .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
    BoundedApprovalDisplayTextV2::new(display)
        .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)
}

fn push_lower_hex(output: &mut String, bytes: &[u8]) -> Result<(), KernelAgentAuthorityErrorV2> {
    use std::fmt::Write as _;
    output
        .try_reserve(bytes.len().saturating_mul(2))
        .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
    for byte in bytes {
        write!(output, "{byte:02x}").map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
    }
    Ok(())
}

fn effect_names(effects: EffectSetV2) -> String {
    let mut names = Vec::new();
    for (effect, name) in [
        (EffectSetV2::READ, "READ"),
        (EffectSetV2::CREATE, "CREATE"),
        (EffectSetV2::UPDATE, "UPDATE"),
        (EffectSetV2::DELETE, "DELETE"),
        (EffectSetV2::SEND, "SEND"),
        (EffectSetV2::EXECUTE, "EXECUTE"),
        (EffectSetV2::FINAL_RELEASE, "FINAL_RELEASE"),
    ] {
        if effects.contains(effect) {
            names.push(name);
        }
    }
    if names.is_empty() {
        "NONE".to_owned()
    } else {
        names.join("|")
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

fn connector_sync_request_id(
) -> Result<savana_kernel_protocol::v2::RequestIdV2, KernelAgentAuthorityErrorV2> {
    for _ in 0..4 {
        let entropy = random_bytes()?;
        let mut request_id = [0_u8; 16];
        request_id.copy_from_slice(&entropy[..16]);
        if request_id != [0; 16] {
            return Ok(savana_kernel_protocol::v2::RequestIdV2::new(request_id));
        }
    }
    Err(KernelAgentAuthorityErrorV2::Unavailable)
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

fn planner_slot_binding_digest(
    bindings: &[PlannerSlotBindingRecordV2],
) -> Result<Digest32V2, KernelAgentAuthorityErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(bindings.len() as u64)
        .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
    for binding in bindings {
        encoder
            .array(2)
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        minicbor::Encode::encode(&binding.slot, &mut encoder, &mut ())
            .and_then(|_| minicbor::Encode::encode(&binding.value, &mut encoder, &mut ()))
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
    }
    Ok(domain_digest(
        b"SAVANA_PLANNER_SLOT_BINDING_SET_V2\0",
        &[&encoder.into_writer()],
    ))
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

fn business_step_request_id(step: savana_kernel_protocol::v2::InternalStepIdV2) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut id = String::with_capacity(69);
    id.push_str("step-");
    for b in step.as_bytes() {
        id.push(HEX[usize::from(b >> 4)] as char);
        id.push(HEX[usize::from(b & 15)] as char);
    }
    id
}

struct FinalReleaseBusinessProposalV2 {
    business_request: savana_kernel_protocol::v2::BusinessRequestV2,
    task_match: savana_policy_core::v2::VerifiedTaskMatchV2,
    control_selections: [savana_policy_core::v2::ControlSelectionV2; 7],
    display_projection_digest: Digest32V2,
}

/// Current release API has no independently approved clause selector. Therefore
/// exactly one whole original-input/application-turn alternative must apply;
/// overlapping destinations or budget buckets are refused, never guessed.
#[allow(clippy::too_many_arguments)]
fn project_final_release_business(
    policy: &KernelG4G5RuntimeV2,
    session: &SessionRecordV2,
    request: &PrepareReleaseRequestV2,
    owned_source: Digest32V2,
    committed_plan: &PlanStepRecordV2,
    plaintext: &[u8],
    provenance: Digest32V2,
    generation: u64,
    now: UnixMillisV2,
) -> Result<FinalReleaseBusinessProposalV2, KernelAgentAuthorityErrorV2> {
    use savana_kernel_protocol::v2::{BusinessRequestV2, BusinessValueV2, TaskEffectV2};
    if plaintext.len() > savana_kernel_protocol::v2::MAX_FINAL_RELEASE_BUSINESS_PAYLOAD_BYTES_V2 {
        return Err(KernelAgentAuthorityErrorV2::LimitExceeded);
    }
    let state = policy
        .durable
        .task_authorization_state(session.durable_task_id)
        .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?;
    let root = state.authorization();
    let draft = policy
        .durable
        .installed_task_authorization_draft(root.digest())
        .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?
        .ok_or(KernelAgentAuthorityErrorV2::StateConflict)?;
    if state.revoked()
        || draft.source_input_digest() != owned_source
        || draft.principal() != session.principal
        || draft.task() != session.durable_task_id
        || draft.manifest_digest() != session.active_state_manifest_digest
        || draft.deployment_generation() != generation
        || committed_plan.run != session.run
        || committed_plan.durable_run_id != session.durable_run_id
        || committed_plan.durable_task_id != session.durable_task_id
        || committed_plan.principal != session.principal
        || committed_plan.task_authorization_digest != root.digest()
    {
        return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
    }
    let mut selected = None;
    for alternative in draft.clauses().iter().flat_map(|c| c.alternatives()) {
        let controls = alternative.controls();
        let profile = controls.profile();
        if profile.effect() != TaskEffectV2::FinalRelease {
            continue;
        }
        let Some(active) =
            policy
                .active_tools
                .resolve(alternative.descriptor_digest(), session.role, now)
        else {
            continue;
        };
        let descriptor = active.descriptor().unsigned();
        if descriptor.executor_identity() != request.executor()
            || descriptor.destination_projection() != request.destination_projection()
            || descriptor.display_projection() != request.display_projection()
        {
            continue;
        }
        if descriptor.business_profile() != Some(profile)
            || descriptor.destination_projection_digest()
                != compiled_projection_digest(
                    PROJECTION_DESTINATION_DOMAIN,
                    request.destination_projection().get(),
                )
            || descriptor.display_projection_digest()
                != compiled_projection_digest(
                    PROJECTION_DISPLAY_DOMAIN,
                    request.display_projection().get(),
                )
            || *profile
                != savana_kernel_protocol::v2::final_release_business_profile_v2(
                    profile.target_identity(),
                    profile.credential_identity(),
                )
                .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?
        {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        let business_request = BusinessRequestV2::from_fields(
            profile,
            &business_step_request_id(committed_plan.internal_step_id),
            vec![
                (
                    "resource".into(),
                    BusinessValueV2::Text(controls.resource().into()),
                ),
                (
                    "destination".into(),
                    BusinessValueV2::Text(controls.destination().into()),
                ),
                (
                    "payload".into(),
                    BusinessValueV2::Text(
                        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(plaintext),
                    ),
                ),
            ],
        )
        .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let delivery = savana_kernel_protocol::v2::decode_final_release_delivery_v2(
            &business_request.canonical_json(),
        )
        .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        if delivery.source_input_digest() != owned_source {
            continue;
        }
        if selected.is_some() {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        let task_match = match_business_proposal(
            &state,
            &business_request,
            alternative.descriptor_digest(),
            committed_plan.plan_revision_digest,
            provenance,
            // Final release has no result-derived controls; every field is exact.
            &std::collections::BTreeMap::new(),
            generation,
            now,
        )?;
        let control_selections = savana_policy_core::v2::ControlSelectionV2::from_match(
            &task_match,
            committed_plan.proposer_parent,
        )
        .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        selected = Some(FinalReleaseBusinessProposalV2 {
            business_request,
            task_match,
            control_selections,
            display_projection_digest: descriptor.display_projection_digest(),
        });
    }
    selected.ok_or(KernelAgentAuthorityErrorV2::BindingMismatch)
}

#[allow(clippy::too_many_arguments)]
fn match_business_proposal(
    state: &savana_policy_core::v2::TaskAuthorizationStateV2,
    request: &savana_kernel_protocol::v2::BusinessRequestV2,
    descriptor: Digest32V2,
    plan_revision: PlanRevisionDigestV2,
    provenance: Digest32V2,
    derived: &std::collections::BTreeMap<String, savana_kernel_protocol::v2::ResultDerivedControlV2>,
    generation: u64,
    now: UnixMillisV2,
) -> Result<savana_policy_core::v2::VerifiedTaskMatchV2, KernelAgentAuthorityErrorV2> {
    if state.revoked() {
        return Err(KernelAgentAuthorityErrorV2::StateConflict);
    }
    let authorization = state.authorization();
    // Result-derived fields match the owner-signed rule, not this request's
    // concrete extracted value; every other field matches its exact value.
    let action = request
        .action_alternative_with_derived(descriptor, derived)
        .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
    let mut choices = authorization
        .material()
        .clauses()
        .iter()
        .flat_map(|clause| {
            clause
                .alternatives()
                .iter()
                .enumerate()
                .filter(|(_, alternative)| **alternative == action)
                .map(move |(index, _)| (clause.clause_id(), index as u64))
        });
    let (clause, alternative) = choices
        .next()
        .ok_or(KernelAgentAuthorityErrorV2::BindingMismatch)?;
    // Overlapping clauses are ambiguous without an authenticated clause choice.
    // Do not select a different budget bucket on the agent's behalf.
    if choices.next().is_some() {
        return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
    }
    let domain = authorization
        .candidate_domain(clause, now)
        .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?;
    let content = savana_kernel_protocol::v2::ActionContentV2::new(
        authorization.material().authorization_id(),
        authorization.material().revision(),
        clause,
        alternative,
        action,
        request.magnitude(),
        request.payload_digest(),
        provenance,
        Digest32V2::new(*plan_revision.as_bytes()),
        domain.digest(),
        state.digest(),
        state.revision(),
    )
    .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
    authorization
        .match_action(
            &content,
            &savana_policy_core::v2::TaskMatchContextV2 {
                current_authorization: Some(authorization),
                pre_state_digest: state.digest(),
                pre_state_revision: state.revision(),
                deployment_generation: generation,
                now,
            },
        )
        .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)
}

fn task_execution_plaintext(
    matched: &savana_policy_core::v2::VerifiedTaskMatchV2,
    request: &savana_kernel_protocol::v2::BusinessRequestV2,
    derived: &std::collections::BTreeMap<String, savana_kernel_protocol::v2::ResultDerivedControlV2>,
) -> Result<Vec<u8>, KernelAgentAuthorityErrorV2> {
    // The step's signed derived rules travel with the sealed payload so every
    // verifier rebuilds the exact alternative G4 matched.
    let payload = savana_kernel_protocol::v2::TaskExecutionPayloadV2::new_with_derived(
        matched.content().clone(),
        request.clone(),
        derived.clone(),
    )
    .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
    savana_kernel_protocol::v2::encode_task_execution_payload_v2(&payload)
        .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)
}

fn task_bound_display(
    matched: &savana_policy_core::v2::VerifiedTaskMatchV2,
    request: &savana_kernel_protocol::v2::BusinessRequestV2,
    state: &savana_policy_core::v2::TaskAuthorizationStateV2,
    derived: &std::collections::BTreeMap<String, savana_kernel_protocol::v2::ResultDerivedControlV2>,
) -> Result<BoundedApprovalDisplayTextV2, KernelAgentAuthorityErrorV2> {
    if state.revoked()
        || state.authorization().digest() != matched.authorization().digest()
        || state.digest() != matched.content().pre_state_digest()
        || state.revision() != matched.content().pre_state_revision()
    {
        return Err(KernelAgentAuthorityErrorV2::StateConflict);
    }
    let (attempts, magnitude) = state
        .clause_consumption(matched.content().clause_id())
        .ok_or(KernelAgentAuthorityErrorV2::StateConflict)?;
    savana_kernel_protocol::v2::render_task_action_display_v2(
        matched.content(),
        matched.authorization().material(),
        request,
        derived,
        attempts,
        magnitude,
    )
    .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)
}

#[allow(clippy::too_many_arguments)]
fn verify_task_no_effect_response(
    durable: &savana_policy_core::v2::DurableG4StateV2,
    response: &savana_kernel_protocol::v2::QueryByExecutionNonceResponseV2,
    nonce: Nonce32V2,
    core: Digest32V2,
    subject: Digest32V2,
    key_id: Ed25519KeyIdV2,
    public_key: [u8; 32],
    now: UnixMillisV2,
) -> Result<savana_policy_core::v2::VerifiedTaskOutcomeV2, KernelAgentAuthorityErrorV2> {
    if !matches!(response.status(), ExecutorStatusV2::FailedNoEffect { .. }) {
        return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
    }
    let receipt = savana_policy_core::v2::SignedExecutorDispositionReceiptV2::from_canonical_bytes(
        response
            .terminal_receipt()
            .ok_or(KernelAgentAuthorityErrorV2::BindingMismatch)?,
    )
    .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
    let outcome = durable
        .verify_task_outcome(&receipt, key_id, public_key, now)
        .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
    if outcome.is_known_success()
        || outcome.execution_nonce() != nonce
        || outcome.dispatch_core_digest() != core
        || outcome.dispatch_subject_digest() != subject
    {
        return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
    }
    Ok(outcome)
}

fn public_unreconciled_executor_status(status: &ExecutorStatusV2) -> PublicExecutionStatusV2 {
    // Dispatch acknowledgement is not durable task reconciliation. Query the
    // signed terminal record before caching a terminal status or refunding.
    match status {
        ExecutorStatusV2::FailedNoEffect { .. } | ExecutorStatusV2::Indeterminate { .. } => {
            PublicExecutionStatusV2::Dispatching
        }
        other => public_executor_status(other),
    }
}

fn verify_task_completion_response(
    durable: &savana_policy_core::v2::DurableG4StateV2,
    response: &savana_kernel_protocol::v2::FetchCompletionResponseV2,
    key_id: Ed25519KeyIdV2,
    public_key: [u8; 32],
    now: UnixMillisV2,
) -> Result<savana_policy_core::v2::VerifiedTaskOutcomeV2, KernelAgentAuthorityErrorV2> {
    let evidence = response
        .task_outcome()
        .ok_or(KernelAgentAuthorityErrorV2::BindingMismatch)?;
    let receipt = savana_policy_core::v2::SignedExecutorDispositionReceiptV2::from_canonical_bytes(
        evidence.terminal_receipt(),
    )
    .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
    let verified = durable
        .verify_task_outcome(&receipt, key_id, public_key, now)
        .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
    let binding = durable
        .task_dispatch_binding(response.execution_nonce())
        .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
    if !verified.is_known_success()
        || verified.execution_nonce() != response.execution_nonce()
        || verified.dispatch_core_digest() != response.dispatch_core_digest()
        || verified.dispatch_subject_digest() != response.dispatch_subject_digest()
        || verified.authorization_digest() != binding.authorization_digest()
        || verified.authorization_digest() != evidence.authorization_digest()
        || verified.evidence_digest()
            != evidence
                .evidence_digest(response.completion())
                .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?
    {
        return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
    }
    Ok(verified)
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
    let task_binding = core
        .task_binding()
        .ok_or(KernelAgentAuthorityErrorV2::BindingMismatch)?;
    if task_binding.content_digest()
        != savana_kernel_protocol::v2::action_content_digest_v2(prepared.task_binding().content())
            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?
        || task_binding.authorization_digest() != prepared.task_binding().authorization_digest()
        || task_binding.presealed_payload_digest() != prepared.sealed_envelope_digest()
    {
        return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
    }
    protocol_historical_dispatch_core(core)
}

fn protocol_historical_dispatch_core(
    core: &savana_policy_core::v2::DispatchCoreV2,
) -> Result<ProtocolDispatchCoreV2, KernelAgentAuthorityErrorV2> {
    let task_binding = core
        .task_binding()
        .ok_or(KernelAgentAuthorityErrorV2::BindingMismatch)?;
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
    .map(|core| core.with_task_binding(task_binding))
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
        .array(if material.owner_input.is_some() { 10 } else { 8 })
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
    encoder
        .array(6)
        .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
    encode_recovery_value(encoder, &material.signed_planner_policy.planner_route)?;
    encode_recovery_value(encoder, &material.signed_planner_policy.task_template)?;
    encode_recovery_value(encoder, &material.signed_planner_policy.intent)?;
    encode_recovery_value(encoder, &material.signed_planner_policy.purpose)?;
    encode_recovery_value(encoder, &material.signed_planner_policy.limits)?;
    encoder
        .array(
            material
                .signed_planner_policy
                .allowed_action_templates
                .len() as u64,
        )
        .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
    for action_template in &material.signed_planner_policy.allowed_action_templates {
        encode_recovery_value(encoder, action_template)?;
    }
    encode_recovery_value(encoder, &material.expires_at)?;
    if let Some((value, owner)) = &material.owner_input {
        let owner = encode_provenance_record_v2(owner)
            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        encode_recovery_value(encoder, value)?;
        encoder
            .bytes(&owner)
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
    }
    Ok(())
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
    // 8 fields before owner-input retention; 10 with the owner document.
    let fields = decoder
        .array()
        .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
    if !matches!(fields, Some(8 | 10)) {
        return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
    }
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
    require_recovery_array(decoder, 6)?;
    let planner_route = decode_recovery_value(decoder, context)?;
    let task_template = decode_recovery_value(decoder, context)?;
    let intent = decode_recovery_value(decoder, context)?;
    let purpose = decode_recovery_value(decoder, context)?;
    let limits = decode_recovery_value(decoder, context)?;
    let action_template_count = decode_recovery_count(decoder, 256)?;
    let mut allowed_action_templates = Vec::new();
    allowed_action_templates
        .try_reserve_exact(action_template_count)
        .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
    for _ in 0..action_template_count {
        allowed_action_templates.push(decode_recovery_value(decoder, context)?);
    }
    if allowed_action_templates.is_empty()
        || allowed_action_templates
            .iter()
            .any(|template: &ActionTemplateIdV2| template.get() == 0)
        || allowed_action_templates
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
    {
        return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
    }
    let signed_planner_policy = SignedPlannerPolicyV2 {
        planner_route,
        task_template,
        intent,
        purpose,
        limits,
        allowed_action_templates,
    };
    let expires_at = decode_recovery_value(decoder, context)?;
    let owner_input = if fields == Some(10) {
        let value = decode_recovery_value(decoder, context)?;
        let owner_bytes = decoder
            .bytes()
            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        if owner_bytes.is_empty() || owner_bytes.len() > 8 * 1024 * 1024 {
            return Err(KernelAgentAuthorityErrorV2::LimitExceeded);
        }
        let owner = decode_provenance_record_v2(owner_bytes)
            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        Some((value, owner))
    } else {
        None
    };
    PreparedAgentClaimMaterialV2::from_verified_ingress(
        durable_run_id,
        producer_identity,
        initial_value,
        provenance,
        initial_document,
        policy_allowed_effects,
        signed_planner_policy,
        expires_at,
        owner_input,
    )
}

#[cfg(test)]
pub(crate) mod tests {
    include!("v04_fused_host_tests.rs");
    include!("v04_fused_compiler_tests.rs");
    use std::cell::Cell;
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;
    use std::sync::{Arc, Mutex};

    use base64::Engine as _;
    use ed25519_dalek::{Signer as _, SigningKey};
    use minicbor::Encode as _;
    use savana_input_runtime::{
        InputChannelV2, InputRuntimeV2, SignedInputRuntimeAssetsV2, VerifiedInputRuntimeAssetsV2,
    };
    use savana_kernel_protocol::v2::{
        derive_ed25519_key_id_v2, encode_planner_plan_v2, verify_effect_ledger_projection_v2,
        ActionIntentCurrentStateV2, ActionTemplateIdV2, AgentSessionHandleV2, AgentSessionStatusV2,
        ApprovalBindingV2, ApprovalPurposeV2, ArgumentNameV2, BootIdV2, CancelKernelTaskRequestV2,
        CommitPlannerValueRequestV2, ConnectorUiAuthorizationHandleV2, Digest32V2,
        DispatchExecutionRequestV2, DisplayProjectionIdV2, DurableReleaseIdV2, DurableRunIdV2,
        DurableTaskIdV2, Ed25519KeyIdV2, EffectLedgerProjectionBindingV2, EndpointRoleV2,
        EvaluateToolCallRequestV2, EvaluateToolCallResponseV2, ExecutorIdentityV2,
        FinalReleaseSemanticBindingV2, FixedOriginV2, GetKernelTaskStatusRequestV2,
        HpkeX25519KeyIdV2, ImplementationIdV2, KernelServiceHandshakeEdgeV2,
        MaskedDocumentHandleV2, NamedArgumentValueBindingV2, Nonce32V2, PeerIdentityBindingV2,
        PlannerIntentKindV2, PlannerLimitsV2, PlannerPlanV2, PlannerPurposeV2, PlannerRouteIdV2,
        PlannerSlotRefV2, PlannerStepV2, PrepareConnectorRegistrationRequestV2,
        PrepareNewIngressRequestV2, PrepareNewIngressResponseV2, PreparePlannerCallRequestV2,
        PrincipalIdV2, ProducerIdentityV2, ProjectionIdV2, ProposeConnectorRegistrationRequestV2,
        ProposeToolCallRequestV2, PublicTaskStatusV2, RequestIdV2,
        ResumeCommittedAgentAuthenticationRequestV2, ResumeCommittedAgentAuthenticationResponseV2,
        RoleIdV2, RunRevisionDigestV2, RunRevisionObservationV2, ServiceIdentityV2,
        StaticTemplateIdV2, ToolClassIdV2, ToolHandleV2, UiAuthenticationBindingV2,
        UiAuthenticationPurposeV2, UnixMillisV2, VersionV2,
    };
    use savana_policy_core::v2::{
        activate_internal_validator_registry, declassification_implementation_digest_v2,
        descriptor_digest_v2, ActiveToolRegistryV2, AttemptKindV2, BoundedConnectorHostV2,
        BoundedConnectorRetryPolicyV2, ClosedDeclassificationPurposeV2, ConnectorDescriptorV2,
        ConnectorRegistryStateV2, ConnectorTierV2, ContextFieldV2, DeclassificationRuleSetV2,
        DeclassificationRuleV2, DispatchQuotaSubjectV2, DurableG4StateV2, DurableStateNamespaceV2,
        EffectSetV2, ExecutorIdempotencyContractV2, G4Error, IdentifierV2,
        InternalValidatorDeclarationV2, KernelValueV2, LeakGateDutyV2, OntologyExprV2,
        OntologyOperandV2, OntologyScalarV2, OperationalTrustRootPurposeV2,
        OperationalTrustRootSetItemV2, OperationalTrustRootSetV2, ProvenanceContextV2,
        ProvenanceRecordV2, ResolvedFinalReleaseTicketV2, RollbackProtectedStateAnchorV2,
        RollbackProtectedStateHeadV2, SharedVerifiedConnectorRegistryV2, SignedToolDescriptorV2,
        UnsignedToolDescriptorV2, VerifiedEffectGateLeaseV2, VerifiedFinalReleaseRecordV2,
        VerifiedFinalReleaseSettlementV2, VerifiedManifestToolConstraintSetV2,
        VerifiedManifestToolConstraintV2, VerifiedPolicyDispositionV2,
        VerifiedPolicyToolActivationV2, VerifiedPolicyToolSetV2, VerifiedQuotaLimitV2,
        VerifiedRegistryPublisherV2, VerifiedToolRegistryV2,
    };
    use sha2::{Digest as _, Sha256};

    use super::{
        build_connector_registry_sync_page_v2, gate_final_release_before_durable_prepare,
        hpke_x25519_key_id, intersect_planner_request, presealed_execution_payload_digest,
        presealed_final_release_payload_digest, ExecutionDeclassificationGateTestObservationV2,
        IntentRecordStateV2, KernelAgentAuthorityErrorV2, KernelAgentAuthorityV2,
        KernelAgentSecurityConfigV2, KernelG4G5RuntimeV2, KernelG7RuntimeV2,
        KernelToolApprovalConfigV2, SessionRecordV2, SignedPlannerPolicyV2, ToolRecordV2,
    };
    use crate::v2_agent_durable::{
        KernelAgentAuthorityRollbackAnchorV2, KernelAgentAuthorityStateHeadV2,
    };
    use crate::v2_executor_client::SuiteOneKernelExecutorClientV2;
    use crate::v2_ingress_authority::{KernelIngressAuthorityV2, KernelIngressSecurityConfigV2};
    use crate::v2_value_owner::KernelValueOwnerV2;

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

    #[derive(Clone)]
    pub(crate) struct TestG4StateAnchorV2(Arc<Mutex<RollbackProtectedStateHeadV2>>);

    impl Default for TestG4StateAnchorV2 {
        fn default() -> Self {
            Self(Arc::new(Mutex::new(
                RollbackProtectedStateHeadV2::new(0, Digest32V2::new([0; 32])).unwrap(),
            )))
        }
    }

    impl RollbackProtectedStateAnchorV2 for TestG4StateAnchorV2 {
        fn current_head(
            &self,
        ) -> Result<RollbackProtectedStateHeadV2, savana_policy_core::v2::G4Error> {
            self.0
                .lock()
                .map(|head| *head)
                .map_err(|_| savana_policy_core::v2::G4Error::DurableStateIo)
        }

        fn compare_and_advance(
            &mut self,
            expected: RollbackProtectedStateHeadV2,
            next: RollbackProtectedStateHeadV2,
        ) -> Result<(), savana_policy_core::v2::G4Error> {
            let mut head = self
                .0
                .lock()
                .map_err(|_| savana_policy_core::v2::G4Error::DurableStateIo)?;
            if *head != expected {
                return Err(savana_policy_core::v2::G4Error::DurableStateRollback);
            }
            *head = next;
            Ok(())
        }
    }

    pub(crate) struct PlannerAuthorityFixtureV2 {
        _directory: tempfile::TempDir,
        authority: KernelAgentAuthorityV2,
        values: KernelValueOwnerV2,
        caller_identity: ServiceIdentityV2,
        run: savana_kernel_protocol::v2::RunHandleV2,
        prompt: savana_kernel_protocol::v2::ValueHandleV2,
    }

    impl PlannerAuthorityFixtureV2 {
        pub(crate) fn connector_agent_and_values(
            &mut self,
        ) -> (&mut KernelAgentAuthorityV2, &KernelValueOwnerV2) {
            (&mut self.authority, &self.values)
        }

        pub(crate) fn connector_agent(&mut self) -> &mut KernelAgentAuthorityV2 {
            &mut self.authority
        }

        pub(crate) fn connector_session(&self) -> AgentSessionHandleV2 {
            self.authority.sessions[0].session
        }

        pub(crate) const fn connector_caller_identity(&self) -> ServiceIdentityV2 {
            self.caller_identity
        }

        pub(crate) fn connector_principal(&self) -> PrincipalIdV2 {
            self.authority.sessions[0].principal
        }

        pub(crate) fn replace_connector_principal(
            &mut self,
            replacement: PrincipalIdV2,
        ) -> PrincipalIdV2 {
            std::mem::replace(&mut self.authority.sessions[0].principal, replacement)
        }

        pub(crate) fn connector_registry(&self) -> SharedVerifiedConnectorRegistryV2 {
            self.authority
                .policy
                .as_ref()
                .and_then(|policy| policy.g7.as_ref())
                .expect("connector runtime must be installed")
                .connector_registry
                .clone()
        }

        pub(crate) fn replace_connector_registry(
            &mut self,
            registry: SharedVerifiedConnectorRegistryV2,
        ) {
            self.authority
                .policy
                .as_mut()
                .and_then(|policy| policy.g7.as_mut())
                .expect("connector runtime must be installed")
                .connector_registry = registry;
        }

        pub(crate) fn extend_connector_session(&mut self, expires_at: UnixMillisV2) {
            self.authority.sessions[0].expires_at = expires_at;
        }

        fn prepare(
            &mut self,
            limits: PlannerLimitsV2,
        ) -> (
            savana_kernel_protocol::v2::PlannerTicketHandleV2,
            Nonce32V2,
            PlannerSlotRefV2,
        ) {
            let prepared = self
                .authority
                .prepare_planner_call(
                    &PreparePlannerCallRequestV2::new(
                        self.run,
                        PlannerRouteIdV2::new(7),
                        StaticTemplateIdV2::new(11),
                        PlannerIntentKindV2::SendMessage,
                        PlannerPurposeV2::PlannerCall,
                        limits,
                        vec![self.prompt],
                    )
                    .unwrap(),
                    &self.values,
                    self.caller_identity,
                    UnixMillisV2::new(200),
                )
                .unwrap();
            let slot = self.authority.planner_tickets.last().unwrap().slot_bindings[0]
                .slot
                .reference();
            (
                prepared.ticket(),
                prepared.envelope().envelope_nonce(),
                slot,
            )
        }

        fn commit(
            &mut self,
            ticket: savana_kernel_protocol::v2::PlannerTicketHandleV2,
            plan: PlannerPlanV2,
        ) -> Result<
            savana_kernel_protocol::v2::CommitPlannerValueResponseV2,
            KernelAgentAuthorityErrorV2,
        > {
            self.authority.commit_planner_value(
                &CommitPlannerValueRequestV2::new(self.run, ticket, plan),
                &mut self.values,
                self.caller_identity,
                UnixMillisV2::new(201),
            )
        }
    }

    pub(crate) fn planner_authority_fixture() -> PlannerAuthorityFixtureV2 {
        planner_authority_fixture_with_approval_display(true)
    }
    pub(crate) fn task_issuer_agent_fixture(
        durable: DurableG4StateV2,
        issuer: crate::v2_task_authority::KernelTaskAuthorizationIssuerV2,
    ) -> KernelAgentAuthorityV2 {
        let mut f = planner_authority_fixture_with_task(true, false);
        f.authority.config.installation_id = Digest32V2::new([0x30; 32]);
        f.authority.policy.as_mut().unwrap().durable = durable;
        f.authority.install_task_issuer(issuer).unwrap();
        f.authority
    }

    #[test]
    fn ingress_handoff_replay_preserves_exact_material_and_waits_for_task_authority() {
        use super::*;
        let mut f = planner_authority_fixture_with_task(true, false);
        let s = &f.authority.sessions[0];
        let task = s.durable_task_id;
        let principal = s.principal;
        let manifest = s.active_state_manifest_digest;
        let correlation = SignedDurableTaskCorrelationV2::sign(
            UnsignedDurableTaskCorrelationV2::new(
                f.authority.config.installation_id,
                manifest,
                7,
                task,
                f.authority.config.agentd_identity,
                f.authority.config.agentd_kernel_client_boot_id,
                f.authority.config.kerneld_server_boot_id,
                f.authority.config.machine_boot_id,
                UnixMillisV2::new(1),
                UnixMillisV2::new(9000),
                UnixMillisV2::new(10000),
            )
            .unwrap(),
            &f.authority.config.correlation_signing_key,
        )
        .unwrap();
        let material = || {
            let initial_value = KernelValueV2::text("private planner prompt").unwrap();
            let provenance = f
                .values
                .resolve_g4_value(f.run, f.prompt, UnixMillisV2::new(200))
                .unwrap()
                .provenance()
                .clone();
            PreparedAgentClaimMaterialV2::from_verified_ingress(
                provenance.run_internal_id(),
                provenance.producer_identity(),
                initial_value,
                provenance,
                MaskedDocumentHandleV2::from_authority_entropy([0x96; 32]).unwrap(),
                EffectSetV2::SEND,
                SignedPlannerPolicyV2::from_verified_input(
                    planner_input_runtime()
                        .process(
                            InputChannelV2::ChatText,
                            "send to alice@example.com",
                            UnixMillisV2::new(100),
                        )
                        .unwrap()
                        .planner_envelope(),
                )
                .unwrap(),
                UnixMillisV2::new(10000),
                None,
            )
            .unwrap()
        };
        f.authority.tasks.push(TaskRecordV2 {
            preparation: NewTaskPreparationHandleV2::from_authority_entropy([71; 32]).unwrap(),
            agent_task_nonce: Nonce32V2::new([72; 32]),
            client_request_nonce: Nonce32V2::new([73; 32]),
            durable_task_id: task,
            active_state_manifest_digest: manifest,
            correlation,
            ingress_transfer: KernelIngressBootstrapTransferCapabilityV2::from_authority_entropy(
                [74; 32],
            )
            .unwrap(),
            status: PublicTaskStatusV2::AwaitingInput,
            expected_principal: None,
            claim_digest: None,
            durable_run_id: None,
            material: None,
            current_authentication_preparation: None,
            source_input_digest: None,
            task_authorization_digest: None,
        });
        let source = Digest32V2::new([75; 32]);
        assert!(f
            .authority
            .mark_ingress_committed(task, principal, Digest32V2::new([0; 32]), material())
            .is_err());
        f.authority
            .mark_ingress_committed(task, principal, source, material())
            .unwrap();
        assert_eq!(f.authority.tasks[0].status, PublicTaskStatusV2::Processing);
        assert_eq!(f.authority.tasks[0].task_authorization_digest, None);
        f.authority
            .mark_ingress_committed(task, principal, source, material())
            .unwrap();
        assert!(f
            .authority
            .ingress_material_is_committed(task, principal, source, manifest)
            .unwrap());
        assert!(f
            .authority
            .ingress_material_is_committed(task, principal, Digest32V2::new([76; 32]), manifest)
            .is_err());
        let mut changed = material();
        changed.initial_document =
            MaskedDocumentHandleV2::from_authority_entropy([77; 32]).unwrap();
        assert!(f
            .authority
            .mark_ingress_committed(task, principal, source, changed)
            .is_err());
        for schema in [2, 3, 4] {
            let encoded = f.authority.encode_recovery_snapshot_schema(schema).unwrap();
            let mut restored = planner_authority_fixture().authority;
            restored
                .restore_recovery_snapshot(&encoded, UnixMillisV2::new(201))
                .unwrap();
            assert_eq!(restored.tasks[0].task_authorization_digest, None);
            assert_eq!(
                restored.tasks[0].source_input_digest,
                if schema >= 3 { Some(source) } else { None }
            );
            assert_eq!(restored.tasks[0].status, PublicTaskStatusV2::Processing);
            assert_eq!(
                restored.encode_recovery_snapshot_schema(schema).unwrap(),
                encoded
            );
        }
        // The policy owner may finish before the input handoff or before the
        // agent owner's follow-up write. Recover the current exact root without
        // reminting the claim, and never revive a revoked grant.
        let template =
            crate::v2_task_authority::tests::draft(&planner_active_tools(), source, 1, "Alice");
        let draft = savana_kernel_protocol::v2::TaskAuthorizationDraftV2::new(
            template.authorization_id(),
            principal,
            task,
            1,
            f.authority.config.installation_id,
            manifest,
            7,
            UnixMillisV2::new(1),
            UnixMillisV2::new(10000),
            source,
            template.clauses().to_vec(),
        )
        .unwrap();
        let key = SigningKey::from_bytes(&[0x39; 32]);
        let signed = savana_kernel_protocol::v2::sign_task_authorization_v2(
            draft
                .to_unsigned_authorization(
                    savana_kernel_protocol::v2::TaskEvidenceKindV2::AuthenticatedStructuredInput,
                    Digest32V2::new([0x37; 32]),
                )
                .unwrap(),
            &key,
        )
        .unwrap();
        let verified = savana_policy_core::v2::VerifiedTaskAuthorizationV2::verify(
            &signed,
            &key.verifying_key(),
            principal,
            task,
            f.authority.config.installation_id,
            manifest,
            UnixMillisV2::new(200),
        )
        .unwrap();
        let digest = verified.digest();
        let owner = &mut f.authority.policy.as_mut().unwrap().durable;
        owner
            .record_pending_task_authorization(draft, Digest32V2::new([78; 32]))
            .unwrap();
        owner
            .install_pending_task_authorization(Digest32V2::new([78; 32]), verified)
            .unwrap();
        assert!(f
            .authority
            .activate_committed_task_authorization(
                task,
                principal,
                manifest,
                8,
                UnixMillisV2::new(201)
            )
            .is_err());
        f.authority
            .activate_committed_task_authorization(
                task,
                principal,
                manifest,
                7,
                UnixMillisV2::new(201),
            )
            .unwrap();
        assert_eq!(
            f.authority.tasks[0].status,
            PublicTaskStatusV2::Ready { bootstrap: None }
        );
        assert_eq!(f.authority.tasks[0].task_authorization_digest, Some(digest));
        assert!(f
            .authority
            .ingress_material_is_committed(task, principal, source, manifest)
            .unwrap());
        let encoded = f.authority.encode_recovery_snapshot().unwrap();
        let mut restarted = planner_authority_fixture_with_task(true, false);
        restarted.authority.policy = f.authority.policy.take();
        restarted
            .authority
            .restore_recovery_snapshot(&encoded, UnixMillisV2::new(202))
            .unwrap();
        f.authority = restarted.authority;
        f.authority
            .activate_committed_task_authorization(
                task,
                principal,
                manifest,
                7,
                UnixMillisV2::new(202),
            )
            .unwrap();
        assert_eq!(f.authority.tasks[0].task_authorization_digest, Some(digest));
        f.authority
            .policy
            .as_mut()
            .unwrap()
            .durable
            .revoke_task_authorization(task)
            .unwrap();
        f.authority.tasks[0].status = PublicTaskStatusV2::Processing;
        f.authority
            .activate_committed_task_authorization(
                task,
                principal,
                manifest,
                7,
                UnixMillisV2::new(203),
            )
            .unwrap();
        assert_eq!(f.authority.tasks[0].status, PublicTaskStatusV2::Processing);
    }

    fn planner_authority_fixture_with_approval_display(
        include_approval_display: bool,
    ) -> PlannerAuthorityFixtureV2 {
        planner_authority_fixture_with_task(include_approval_display, true)
    }

    fn planner_authority_fixture_with_task(
        include_approval_display: bool,
        install_task: bool,
    ) -> PlannerAuthorityFixtureV2 {
        let caller_identity = ServiceIdentityV2::new([0x81; 32]);
        let producer = ProducerIdentityV2::new([0x82; 32]);
        let durable_run_id = DurableRunIdV2::new([0x83; 32]);
        let durable_task_id = DurableTaskIdV2::new([0x84; 32]);
        let manifest = Digest32V2::new([0x85; 32]);
        let mut values = KernelValueOwnerV2::new(4, 32).unwrap();
        let run = values
            .open_verified_run(
                producer,
                durable_run_id,
                manifest,
                UnixMillisV2::new(100),
                UnixMillisV2::new(10_000),
                EffectSetV2::SEND,
            )
            .unwrap();
        let prompt_value = KernelValueV2::text("private planner prompt").unwrap();
        let prompt_provenance = ProvenanceRecordV2::planner_output(
            &prompt_value,
            ProvenanceContextV2::from_authenticated_runtime(
                producer,
                durable_run_id,
                manifest,
                UnixMillisV2::new(100),
                UnixMillisV2::new(10_000),
            )
            .unwrap(),
            Digest32V2::new([0x86; 32]),
            Digest32V2::new([0x87; 32]),
            Digest32V2::new([0x88; 32]),
            &[],
            EffectSetV2::SEND,
        )
        .unwrap();
        let prompt = values
            .register_verified_value(run, prompt_value, prompt_provenance)
            .unwrap()
            .handle();

        let input_runtime = planner_input_runtime();
        let gated = input_runtime
            .process(
                InputChannelV2::ChatText,
                "send to alice@example.com",
                UnixMillisV2::new(100),
            )
            .unwrap();
        let signed_planner_policy =
            SignedPlannerPolicyV2::from_verified_input(gated.planner_envelope()).unwrap();

        let security = KernelAgentSecurityConfigV2::new(
            Digest32V2::new([0x89; 32]),
            ServiceIdentityV2::new([0x8a; 32]),
            caller_identity,
            ServiceIdentityV2::new([0x9d; 32]),
            BootIdV2::new([0x8c; 32]),
            BootIdV2::new([0x8d; 32]),
            BootIdV2::new([0x8e; 32]),
            BootIdV2::new([0x8f; 32]),
            SigningKey::from_bytes(&[0x90; 32]),
            SigningKey::from_bytes(&[0x91; 32]),
            derive_ed25519_key_id_v2(
                SigningKey::from_bytes(&[0x92; 32])
                    .verifying_key()
                    .to_bytes(),
            ),
            SigningKey::from_bytes(&[0x92; 32])
                .verifying_key()
                .to_bytes(),
        )
        .unwrap();
        let mut authority = KernelAgentAuthorityV2::new(security, 32).unwrap();
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        authority.policy = Some(planner_policy_runtime(
            directory.path(),
            include_approval_display,
        ));
        authority.sessions.push(SessionRecordV2 {
            session: AgentSessionHandleV2::from_authority_entropy([0x93; 32]).unwrap(),
            run,
            durable_run_id,
            durable_task_id,
            active_state_manifest_digest: manifest,
            principal: PrincipalIdV2::new([0x94; 32]),
            producer_identity: producer,
            role: RoleIdV2::new(1),
            policy_allowed_effects: EffectSetV2::SEND,
            signed_planner_policy,
            expires_at: UnixMillisV2::new(10_000),
            revision: RunRevisionObservationV2::new(
                durable_run_id,
                1,
                RunRevisionDigestV2::new([0x95; 32]),
            )
            .unwrap(),
            initial_document: MaskedDocumentHandleV2::from_authority_entropy([0x96; 32]).unwrap(),
            initial_value: prompt,
            owner_input_value: None,
            status: AgentSessionStatusV2::Ready,
            task_authorization_digest: None,
        });
        if install_task {
            install_planner_task(&mut authority, 1, UnixMillisV2::new(10_000));
        }
        PlannerAuthorityFixtureV2 {
            _directory: directory,
            authority,
            values,
            caller_identity,
            run,
            prompt,
        }
    }

    fn install_planner_task(
        authority: &mut KernelAgentAuthorityV2,
        revision: u64,
        expires: UnixMillisV2,
    ) {
        use savana_kernel_protocol::v2::{
            sign_task_authorization_v2, ActionAlternativeV2, ActionCodecProfileV2, MagnitudeUnitV2,
            TaskAuthorizationClauseV2, TaskAuthorizationV2, TaskEffectV2, TaskEvidenceKindV2,
        };
        let s = &authority.sessions[0];
        let key = SigningKey::from_bytes(&[0x39; 32]);
        let m = TaskAuthorizationV2::new(
            Digest32V2::new([0x38; 32]),
            s.principal,
            s.durable_task_id,
            revision,
            authority.config.installation_id,
            s.active_state_manifest_digest,
            UnixMillisV2::new(1),
            expires,
            TaskEvidenceKindV2::ApprovedDraft,
            Digest32V2::new([0x37; 32]),
            Digest32V2::new([0x36; 32]),
            vec![TaskAuthorizationClauseV2::new(
                1,
                vec![ActionAlternativeV2::new(
                    Digest32V2::new([0x35; 32]),
                    ActionCodecProfileV2::FixedJsonPostV1,
                    TaskEffectV2::Send,
                    Digest32V2::new([0x34; 32]),
                    Digest32V2::new([0x33; 32]),
                    Digest32V2::new([0x32; 32]),
                    MagnitudeUnitV2::Count,
                )
                .unwrap()],
                1,
                10,
                10,
                vec![],
                false,
            )
            .unwrap()],
        )
        .unwrap();
        let verified = savana_policy_core::v2::VerifiedTaskAuthorizationV2::verify(
            &sign_task_authorization_v2(m, &key).unwrap(),
            &key.verifying_key(),
            s.principal,
            s.durable_task_id,
            authority.config.installation_id,
            s.active_state_manifest_digest,
            UnixMillisV2::new(100),
        )
        .unwrap();
        authority
            .policy
            .as_mut()
            .unwrap()
            .durable
            .install_verified_task_authorization(verified)
            .unwrap();
    }

    #[test]
    fn planner_entry_requires_live_exact_task_authority_and_commit_rechecks_revocation() {
        let limits = PlannerLimitsV2::new(2, 1, 2, 4096).unwrap();
        let mut f = planner_authority_fixture_with_task(true, false);
        let request = PreparePlannerCallRequestV2::new(
            f.run,
            PlannerRouteIdV2::new(7),
            StaticTemplateIdV2::new(11),
            PlannerIntentKindV2::SendMessage,
            PlannerPurposeV2::PlannerCall,
            limits,
            vec![f.prompt],
        )
        .unwrap();
        assert!(f
            .authority
            .prepare_planner_call(
                &request,
                &f.values,
                f.caller_identity,
                UnixMillisV2::new(200)
            )
            .is_err());
        assert!(f.authority.planner_tickets.is_empty());
        install_planner_task(&mut f.authority, 1, UnixMillisV2::new(10_000));
        let principal = f.authority.sessions[0].principal;
        f.authority.sessions[0].principal = PrincipalIdV2::new([0x30; 32]);
        assert!(f
            .authority
            .prepare_planner_call(
                &request,
                &f.values,
                f.caller_identity,
                UnixMillisV2::new(200)
            )
            .is_err());
        f.authority.sessions[0].principal = principal;
        assert!(f
            .authority
            .prepare_planner_call(
                &request,
                &f.values,
                f.caller_identity,
                UnixMillisV2::new(10_000)
            )
            .is_err());
        let (ticket, nonce, slot) = f.prepare(limits);
        let task = f.authority.sessions[0].durable_task_id;
        f.authority
            .policy
            .as_mut()
            .unwrap()
            .durable
            .revoke_task_authorization(task)
            .unwrap();
        let plan = valid_planner_plan_for_task_gate(nonce, slot);
        assert!(f.commit(ticket, plan).is_err());
        assert!(!f.authority.planner_tickets[0].consumed);
        assert!(f
            .authority
            .prepare_planner_call(
                &request,
                &f.values,
                f.caller_identity,
                UnixMillisV2::new(202)
            )
            .is_err());
    }

    #[test]
    fn task_revision_replacement_invalidates_prepared_planner_ticket() {
        let mut f = planner_authority_fixture();
        let (ticket, nonce, slot) = f.prepare(PlannerLimitsV2::new(2, 1, 2, 4096).unwrap());
        install_planner_task(&mut f.authority, 2, UnixMillisV2::new(10_000));
        assert!(f
            .commit(ticket, valid_planner_plan_for_task_gate(nonce, slot))
            .is_err());
        assert!(!f.authority.planner_tickets[0].consumed);
    }

    #[test]
    fn fused_enrollment_blocks_legacy_planner_and_previously_prepared_ticket() {
        use ed25519_dalek::Signer;
        use savana_policy_core::v2::{FusedPlanningProfileV04, VerifiedFusedPlanningProfileV04};
        let mut f = planner_authority_fixture();
        let limits = PlannerLimitsV2::new(2, 1, 2, 4096).unwrap();
        let (ticket, nonce, slot) = f.prepare(limits);
        let task = f.authority.sessions[0].durable_task_id;
        let durable = &mut f.authority.policy.as_mut().unwrap().durable;
        let parent = durable.task_authorization_state(task).unwrap();
        let m = parent.authorization().material();
        let p: FusedPlanningProfileV04 = serde_json::from_value(serde_json::json!({
            "schema":1,"installation":m.installation_digest().as_bytes(),"task":task.as_bytes(),
            "not_before":m.not_before().get(),"expires_at":m.expires_at().get(),
            "policy":{"schema":1,"root":parent.authorization().digest().as_bytes(),"observer_scope":vec![1u8;32],
                "operations":[{"id":1,"tool_class":31,"action_template":21,"bindings":[],"after":[]}],
                "templates":[{"id":1,"order":[1]}],"max_replacements":0,
                "rounds":[{"id":1,"opens_at":200,"advice_cut":200,"closes_at":500,
                    "advisor":null,"planner":vec![2u8;32],"model_profile":1,"mode":"registered_template_v04",
                    "public_view":[],"template_ids":[1],"question_codes":[],"max_deliveries":1}]}
        })).unwrap();
        let key = SigningKey::from_bytes(&[0x21; 32]);
        let proof = VerifiedFusedPlanningProfileV04::verify(
            &serde_json::to_vec(&p).unwrap(),
            &key.sign(&p.signing_digest().unwrap()).to_bytes(),
            &key.verifying_key(),
            parent.authorization(),
            UnixMillisV2::new(200),
        )
        .unwrap();
        durable
            .install_fused_planning_v04(proof, UnixMillisV2::new(200))
            .unwrap();
        assert!(f
            .commit(ticket, valid_planner_plan_for_task_gate(nonce, slot))
            .is_err());
        assert!(!f.authority.planner_tickets[0].consumed);
        let request = PreparePlannerCallRequestV2::new(
            f.run,
            PlannerRouteIdV2::new(7),
            StaticTemplateIdV2::new(11),
            PlannerIntentKindV2::SendMessage,
            PlannerPurposeV2::PlannerCall,
            limits,
            vec![f.prompt],
        )
        .unwrap();
        assert!(f
            .authority
            .prepare_planner_call(
                &request,
                &f.values,
                f.caller_identity,
                UnixMillisV2::new(201)
            )
            .is_err());
        assert_eq!(f.authority.planner_tickets.len(), 1);
    }

    fn valid_planner_plan_for_task_gate(nonce: Nonce32V2, slot: PlannerSlotRefV2) -> PlannerPlanV2 {
        PlannerPlanV2::new(nonce, vec![planner_step(1, 21, 31, slot, vec![])]).unwrap()
    }

    fn connector_tool_descriptor(
        seed: u8,
        name: &str,
        effects: EffectSetV2,
    ) -> UnsignedToolDescriptorV2 {
        let idempotency = ExecutorIdempotencyContractV2::ConnectorIdempotentByExecutionNonce;
        UnsignedToolDescriptorV2::from_verified_manifest(
            2,
            VersionV2::new(1, 0, 0),
            Digest32V2::new([seed; 32]),
            IdentifierV2::new(name).unwrap(),
            ActionTemplateIdV2::new(u32::from(seed) + 1),
            ToolClassIdV2::new(u32::from(seed) + 2),
            Digest32V2::new([seed.wrapping_add(1); 32]),
            Digest32V2::new([seed.wrapping_add(2); 32]),
            vec![RoleIdV2::new(1)],
            effects,
            AttemptKindV2::ToolWrite,
            BoundedConnectorRetryPolicyV2::new(idempotency, 2, 1_000_000).unwrap(),
            vec![InternalValidatorDeclarationV2::new(
                ImplementationIdV2::new(u32::from(seed) + 3),
                VersionV2::new(1, 0, 0),
                Digest32V2::new([seed.wrapping_add(3); 32]),
            )],
            ExecutorIdentityV2::new([seed.wrapping_add(4); 32]),
            ProjectionIdV2::new(u32::from(seed) + 4),
            Digest32V2::new([seed.wrapping_add(5); 32]),
            DisplayProjectionIdV2::new(u32::from(seed) + 5),
            Digest32V2::new([seed.wrapping_add(6); 32]),
            idempotency,
            UnixMillisV2::new(1),
            UnixMillisV2::new(10_000),
        )
        .unwrap()
    }

    fn valid_user_connector_descriptor() -> (Vec<u8>, Vec<UnsignedToolDescriptorV2>) {
        const CONNECTOR_USER_DOMAIN: &[u8] = b"savana.connector.user.v2\0";
        const NAME: &str = "mail-connector";
        const URL: &str = "https://api.example.com/mcp/v2?scope=full";
        let tls_pin = Digest32V2::new([0x34; 32]);
        let effects = EffectSetV2::READ.union(EffectSetV2::SEND);
        let tools = vec![
            connector_tool_descriptor(0xd1, "mail.read", EffectSetV2::READ),
            connector_tool_descriptor(0xe1, "mail.send", EffectSetV2::SEND),
        ];

        let mut identity = minicbor::Encoder::new(Vec::new());
        identity
            .array(2)
            .unwrap()
            .str(NAME)
            .unwrap()
            .array(3)
            .unwrap()
            .u16(2)
            .unwrap()
            .str(URL)
            .unwrap()
            .bytes(tls_pin.as_bytes())
            .unwrap();
        let connector_id = Digest32V2::new(
            Sha256::new()
                .chain_update(CONNECTOR_USER_DOMAIN)
                .chain_update(identity.into_writer())
                .finalize()
                .into(),
        );

        let mut descriptor = minicbor::Encoder::new(Vec::new());
        descriptor
            .array(8)
            .unwrap()
            .bytes(connector_id.as_bytes())
            .unwrap()
            .str(NAME)
            .unwrap()
            .u16(ConnectorTierV2::UserRegistered.tag())
            .unwrap()
            .array(3)
            .unwrap()
            .u16(2)
            .unwrap()
            .str(URL)
            .unwrap()
            .bytes(tls_pin.as_bytes())
            .unwrap()
            .array(tools.len() as u64)
            .unwrap();
        for tool in &tools {
            descriptor
                .writer_mut()
                .extend_from_slice(&minicbor::to_vec(tool).unwrap());
        }
        descriptor
            .u16(effects.bits())
            .unwrap()
            .u16(savana_policy_core::v2::ConnectorStructuralRoleV2::Sink.tag())
            .unwrap()
            .u64(1)
            .unwrap();
        let bytes = descriptor.into_writer();
        ConnectorDescriptorV2::from_canonical_bytes(
            &bytes,
            &[BoundedConnectorHostV2::new("example.com").unwrap()],
        )
        .unwrap();
        (bytes, tools)
    }

    fn valid_user_stdio_connector_descriptor(tool_count: usize) -> Vec<u8> {
        const CONNECTOR_USER_DOMAIN: &[u8] = b"savana.connector.user.v2\0";
        const NAME: &str = "local-mail-connector";
        let package_digest = Digest32V2::new([0x35; 32]);
        let tools = (0..tool_count)
            .map(|index| {
                connector_tool_descriptor(
                    u8::try_from(index % 190).unwrap().saturating_add(1),
                    &format!("bulk.tool.{index:04}"),
                    EffectSetV2::READ,
                )
            })
            .collect::<Vec<_>>();

        let mut identity = minicbor::Encoder::new(Vec::new());
        identity
            .array(2)
            .unwrap()
            .str(NAME)
            .unwrap()
            .array(2)
            .unwrap()
            .u16(1)
            .unwrap()
            .bytes(package_digest.as_bytes())
            .unwrap();
        let connector_id = Digest32V2::new(
            Sha256::new()
                .chain_update(CONNECTOR_USER_DOMAIN)
                .chain_update(identity.into_writer())
                .finalize()
                .into(),
        );

        let mut descriptor = minicbor::Encoder::new(Vec::new());
        descriptor
            .array(8)
            .unwrap()
            .bytes(connector_id.as_bytes())
            .unwrap()
            .str(NAME)
            .unwrap()
            .u16(ConnectorTierV2::UserRegistered.tag())
            .unwrap()
            .array(2)
            .unwrap()
            .u16(1)
            .unwrap()
            .bytes(package_digest.as_bytes())
            .unwrap()
            .array(tools.len() as u64)
            .unwrap();
        for tool in &tools {
            descriptor
                .writer_mut()
                .extend_from_slice(&minicbor::to_vec(tool).unwrap());
        }
        descriptor
            .u16(EffectSetV2::READ.bits())
            .unwrap()
            .u16(savana_policy_core::v2::ConnectorStructuralRoleV2::Source.tag())
            .unwrap()
            .u64(1)
            .unwrap();
        let bytes = descriptor.into_writer();
        ConnectorDescriptorV2::from_canonical_bytes(&bytes, &[]).unwrap();
        bytes
    }

    fn signed_connector_add_delta(
        previous_head_digest: Digest32V2,
        canonical_descriptor: &[u8],
        authority: &SigningKey,
    ) -> Vec<u8> {
        let mut payload = minicbor::Encoder::new(Vec::new());
        payload
            .array(6)
            .unwrap()
            .u16(1)
            .unwrap()
            .u64(1)
            .unwrap()
            .bytes(previous_head_digest.as_bytes())
            .unwrap()
            .array(2)
            .unwrap()
            .u16(1)
            .unwrap();
        payload.writer_mut().extend_from_slice(canonical_descriptor);
        payload
            .bytes(Digest32V2::new([0xfa; 32]).as_bytes())
            .unwrap()
            .u64(201)
            .unwrap();
        let payload = payload.into_writer();
        let payload_digest = Digest32V2::new(
            Sha256::new()
                .chain_update(b"savana.connector-registry.delta.v2.payload\0")
                .chain_update(&payload)
                .finalize()
                .into(),
        );
        let signature_digest = Digest32V2::new(
            Sha256::new()
                .chain_update(b"savana.connector-registry.delta.v2.signature\0")
                .chain_update(payload_digest.as_bytes())
                .finalize()
                .into(),
        );
        let signature = authority.sign(signature_digest.as_bytes()).to_bytes();
        let mut delta = minicbor::Encoder::new(Vec::new());
        delta.array(3).unwrap();
        delta.writer_mut().extend_from_slice(&payload);
        delta
            .bytes(payload_digest.as_bytes())
            .unwrap()
            .bytes(&signature)
            .unwrap();
        delta.into_writer()
    }

    #[test]
    fn registry_sync_page_comes_only_from_the_verified_canonical_chain() {
        let authority = SigningKey::from_bytes(&[0xd7; 32]);
        let genesis = Digest32V2::new([0xd8; 32]);
        let mut registry = ConnectorRegistryStateV2::from_verified_genesis(
            genesis,
            authority.verifying_key().to_bytes(),
            vec![BoundedConnectorHostV2::new("example.com").unwrap()],
            vec![],
        )
        .unwrap();
        let (descriptor, _) = valid_user_connector_descriptor();
        let canonical_delta = signed_connector_add_delta(genesis, &descriptor, &authority);
        registry.apply_canonical_delta(&canonical_delta).unwrap();

        let page = build_connector_registry_sync_page_v2(&registry, 0, genesis).unwrap();
        assert_eq!(page.base_sequence(), 0);
        assert_eq!(page.base_head_digest(), genesis);
        assert_eq!(page.page_final_sequence(), 1);
        assert_eq!(page.page_final_head_digest(), registry.head_digest());
        assert_eq!(page.source_final_sequence(), 1);
        assert_eq!(page.source_final_head_digest(), registry.head_digest());
        assert_eq!(page.deltas().len(), 1);
        assert_eq!(page.deltas()[0].as_bytes(), canonical_delta);

        assert_eq!(
            build_connector_registry_sync_page_v2(&registry, 0, Digest32V2::new([0xd9; 32])),
            Err(KernelAgentAuthorityErrorV2::BindingMismatch)
        );
    }

    pub(crate) fn install_connector_runtime(
        fixture: &mut PlannerAuthorityFixtureV2,
        enabled: bool,
    ) {
        let runtime = if enabled {
            test_g7_runtime_with_connector_authority(
                Digest32V2::new([0x89; 32]),
                Digest32V2::new([0x85; 32]),
                1,
                1,
            )
        } else {
            test_g7_runtime(
                Digest32V2::new([0x89; 32]),
                Digest32V2::new([0x85; 32]),
                1,
                1,
            )
        };
        fixture
            .authority
            .policy
            .as_mut()
            .unwrap()
            .install_g7(runtime)
            .unwrap();
    }

    #[test]
    fn connector_control_refuses_unknown_session_and_caller_fabricated_authorization() {
        let mut fixture = planner_authority_fixture();
        let caller_boot_id = BootIdV2::new([0x8c; 32]);
        let active_manifest = Digest32V2::new([0x85; 32]);
        let descriptor = vec![0x80];

        assert_eq!(
            fixture.authority.prepare_connector_registration(
                &PrepareConnectorRegistrationRequestV2::new(
                    AgentSessionHandleV2::from_authority_entropy([0xf1; 32]).unwrap(),
                    descriptor.clone(),
                )
                .unwrap(),
                caller_boot_id,
                fixture.caller_identity,
                active_manifest,
                1,
                UnixMillisV2::new(200),
            ),
            Err(KernelAgentAuthorityErrorV2::InvalidReference)
        );

        assert_eq!(
            fixture.authority.propose_connector_registration(
                &ProposeConnectorRegistrationRequestV2::new(
                    ConnectorUiAuthorizationHandleV2::from_authority_entropy([0xf2; 32]).unwrap(),
                    descriptor,
                )
                .unwrap(),
                &fixture.values,
                caller_boot_id,
                fixture.caller_identity,
                active_manifest,
                1,
                UnixMillisV2::new(200),
            ),
            Err(KernelAgentAuthorityErrorV2::InvalidReference)
        );
    }

    #[test]
    fn connector_control_refuses_wrong_origin_context_and_dead_session_lifecycle() {
        let mut fixture = planner_authority_fixture();
        install_connector_runtime(&mut fixture, true);
        let (descriptor, _) = valid_user_connector_descriptor();
        fixture.authority.sessions[0].expires_at = UnixMillisV2::new(1_000_000);
        let session = fixture.authority.sessions[0].session;
        let caller_boot_id = BootIdV2::new([0x8c; 32]);
        let caller_identity = fixture.caller_identity;
        let active_manifest = Digest32V2::new([0x85; 32]);
        let request =
            PrepareConnectorRegistrationRequestV2::new(session, descriptor.clone()).unwrap();

        assert_eq!(
            fixture.authority.prepare_connector_registration(
                &request,
                BootIdV2::new([0xf3; 32]),
                caller_identity,
                active_manifest,
                1,
                UnixMillisV2::new(200),
            ),
            Err(KernelAgentAuthorityErrorV2::BindingMismatch)
        );
        assert_eq!(
            fixture.authority.prepare_connector_registration(
                &request,
                caller_boot_id,
                ServiceIdentityV2::new([0xf4; 32]),
                active_manifest,
                1,
                UnixMillisV2::new(200),
            ),
            Err(KernelAgentAuthorityErrorV2::BindingMismatch)
        );

        let prepared = fixture
            .authority
            .prepare_connector_registration(
                &request,
                caller_boot_id,
                caller_identity,
                active_manifest,
                1,
                UnixMillisV2::new(200),
            )
            .unwrap();

        for (boot, identity, manifest, generation) in [
            (
                BootIdV2::new([0xf3; 32]),
                caller_identity,
                active_manifest,
                1,
            ),
            (
                caller_boot_id,
                ServiceIdentityV2::new([0xf4; 32]),
                active_manifest,
                1,
            ),
            (
                caller_boot_id,
                caller_identity,
                Digest32V2::new([0xf5; 32]),
                1,
            ),
            (caller_boot_id, caller_identity, active_manifest, 2),
        ] {
            assert_eq!(
                fixture.authority.propose_connector_registration(
                    &ProposeConnectorRegistrationRequestV2::new(
                        prepared.authorization(),
                        descriptor.clone(),
                    )
                    .unwrap(),
                    &fixture.values,
                    boot,
                    identity,
                    manifest,
                    generation,
                    UnixMillisV2::new(201),
                ),
                Err(KernelAgentAuthorityErrorV2::BindingMismatch)
            );
        }

        assert_eq!(
            fixture.authority.connector_authorizations[0].origin,
            FixedOriginV2::Agent8768
        );
        fixture.authority.connector_authorizations[0].origin = FixedOriginV2::Approval8766;
        assert_eq!(
            fixture.authority.propose_connector_registration(
                &ProposeConnectorRegistrationRequestV2::new(
                    prepared.authorization(),
                    descriptor.clone(),
                )
                .unwrap(),
                &fixture.values,
                caller_boot_id,
                caller_identity,
                active_manifest,
                1,
                UnixMillisV2::new(201),
            ),
            Err(KernelAgentAuthorityErrorV2::BindingMismatch)
        );
        fixture.authority.connector_authorizations[0].origin = FixedOriginV2::Agent8768;

        fixture.authority.sessions[0].status = AgentSessionStatusV2::Closed;
        assert_eq!(
            fixture.authority.propose_connector_registration(
                &ProposeConnectorRegistrationRequestV2::new(
                    prepared.authorization(),
                    descriptor.clone(),
                )
                .unwrap(),
                &fixture.values,
                caller_boot_id,
                caller_identity,
                active_manifest,
                1,
                UnixMillisV2::new(201),
            ),
            Err(KernelAgentAuthorityErrorV2::BindingMismatch)
        );
        fixture.authority.sessions[0].status = AgentSessionStatusV2::Ready;

        let principal = fixture.authority.sessions[0].principal;
        fixture.authority.sessions[0].principal = PrincipalIdV2::new([0xf6; 32]);
        assert_eq!(
            fixture.authority.propose_connector_registration(
                &ProposeConnectorRegistrationRequestV2::new(
                    prepared.authorization(),
                    descriptor.clone(),
                )
                .unwrap(),
                &fixture.values,
                caller_boot_id,
                caller_identity,
                active_manifest,
                1,
                UnixMillisV2::new(201),
            ),
            Err(KernelAgentAuthorityErrorV2::BindingMismatch)
        );
        fixture.authority.sessions[0].principal = principal;

        let durable_task_id = fixture.authority.sessions[0].durable_task_id;
        fixture.authority.sessions[0].durable_task_id = DurableTaskIdV2::new([0xf7; 32]);
        assert_eq!(
            fixture.authority.propose_connector_registration(
                &ProposeConnectorRegistrationRequestV2::new(
                    prepared.authorization(),
                    descriptor.clone(),
                )
                .unwrap(),
                &fixture.values,
                caller_boot_id,
                caller_identity,
                active_manifest,
                1,
                UnixMillisV2::new(201),
            ),
            Err(KernelAgentAuthorityErrorV2::BindingMismatch)
        );
        fixture.authority.sessions[0].durable_task_id = durable_task_id;

        let durable_run_id = fixture.authority.sessions[0].durable_run_id;
        fixture.authority.sessions[0].durable_run_id = DurableRunIdV2::new([0xf8; 32]);
        assert_eq!(
            fixture.authority.propose_connector_registration(
                &ProposeConnectorRegistrationRequestV2::new(
                    prepared.authorization(),
                    descriptor.clone(),
                )
                .unwrap(),
                &fixture.values,
                caller_boot_id,
                caller_identity,
                active_manifest,
                1,
                UnixMillisV2::new(201),
            ),
            Err(KernelAgentAuthorityErrorV2::BindingMismatch)
        );
        fixture.authority.sessions[0].durable_run_id = durable_run_id;

        fixture.authority.sessions[0].expires_at = UnixMillisV2::new(201);
        assert_eq!(
            fixture.authority.propose_connector_registration(
                &ProposeConnectorRegistrationRequestV2::new(
                    prepared.authorization(),
                    descriptor.clone(),
                )
                .unwrap(),
                &fixture.values,
                caller_boot_id,
                caller_identity,
                active_manifest,
                1,
                UnixMillisV2::new(201),
            ),
            Err(KernelAgentAuthorityErrorV2::BindingMismatch)
        );
        fixture.authority.sessions[0].expires_at = UnixMillisV2::new(1_000_000);

        assert_eq!(
            fixture.authority.propose_connector_registration(
                &ProposeConnectorRegistrationRequestV2::new(
                    prepared.authorization(),
                    descriptor.clone(),
                )
                .unwrap(),
                &fixture.values,
                caller_boot_id,
                caller_identity,
                active_manifest,
                1,
                prepared.expires_at(),
            ),
            Err(KernelAgentAuthorityErrorV2::BindingMismatch)
        );

        let registry = fixture
            .authority
            .policy
            .as_ref()
            .unwrap()
            .g7
            .as_ref()
            .unwrap()
            .connector_registry
            .clone();
        registry
            .verify_and_apply_canonical_delta(&signed_connector_add_delta(
                prepared.previous_head_digest(),
                &descriptor,
                &SigningKey::from_bytes(&[0xc3; 32]),
            ))
            .unwrap();
        assert_ne!(
            registry.current_head_digest().unwrap(),
            prepared.previous_head_digest()
        );
        assert_eq!(
            fixture.authority.propose_connector_registration(
                &ProposeConnectorRegistrationRequestV2::new(prepared.authorization(), descriptor,)
                    .unwrap(),
                &fixture.values,
                caller_boot_id,
                caller_identity,
                active_manifest,
                1,
                UnixMillisV2::new(201),
            ),
            Err(KernelAgentAuthorityErrorV2::BindingMismatch)
        );
        assert_eq!(fixture.authority.connector_authorizations.len(), 1);
    }

    #[test]
    fn connector_control_binds_one_use_ui_authorization_and_complete_human_display() {
        let mut fixture = planner_authority_fixture();
        install_connector_runtime(&mut fixture, true);
        let (descriptor, tools) = valid_user_connector_descriptor();
        let session = fixture.authority.sessions[0].session;
        let prepared = fixture
            .authority
            .prepare_connector_registration(
                &PrepareConnectorRegistrationRequestV2::new(session, descriptor.clone()).unwrap(),
                BootIdV2::new([0x8c; 32]),
                fixture.caller_identity,
                Digest32V2::new([0x85; 32]),
                1,
                UnixMillisV2::new(200),
            )
            .unwrap();
        assert_eq!(
            prepared.descriptor_digest(),
            savana_kernel_protocol::v2::connector_registration_descriptor_digest_v2(&descriptor)
                .unwrap()
        );
        assert_eq!(
            prepared.previous_head_digest(),
            fixture
                .authority
                .policy
                .as_ref()
                .unwrap()
                .g7
                .as_ref()
                .unwrap()
                .connector_registry
                .snapshot()
                .unwrap()
                .head_digest()
        );

        let mut tampered_descriptor = descriptor.clone();
        *tampered_descriptor.last_mut().unwrap() = 2;
        assert_eq!(
            fixture.authority.propose_connector_registration(
                &ProposeConnectorRegistrationRequestV2::new(
                    prepared.authorization(),
                    tampered_descriptor,
                )
                .unwrap(),
                &fixture.values,
                BootIdV2::new([0x8c; 32]),
                fixture.caller_identity,
                Digest32V2::new([0x85; 32]),
                1,
                UnixMillisV2::new(201),
            ),
            Err(KernelAgentAuthorityErrorV2::BindingMismatch)
        );
        assert_eq!(fixture.authority.connector_authorizations.len(), 1);

        let proposed = fixture
            .authority
            .propose_connector_registration(
                &ProposeConnectorRegistrationRequestV2::new(
                    prepared.authorization(),
                    descriptor.clone(),
                )
                .unwrap(),
                &fixture.values,
                BootIdV2::new([0x8c; 32]),
                fixture.caller_identity,
                Digest32V2::new([0x85; 32]),
                1,
                UnixMillisV2::new(201),
            )
            .unwrap();
        let envelope_key = SigningKey::from_bytes(&[0x91; 32]);
        let envelope_key_id = derive_ed25519_key_id_v2(envelope_key.verifying_key().to_bytes());
        let verified = proposed
            .envelope()
            .verify(
                envelope_key_id,
                envelope_key.verifying_key().to_bytes(),
                Digest32V2::new([0x89; 32]),
                Digest32V2::new([0x85; 32]),
                1,
                ApprovalPurposeV2::ConnectorRegistration,
                PrincipalIdV2::new([0x94; 32]),
                UnixMillisV2::new(201),
            )
            .unwrap();
        assert_eq!(
            verified.binding(),
            ApprovalBindingV2::ConnectorRegistration {
                descriptor_digest: prepared.descriptor_digest(),
                previous_head_digest: prepared.previous_head_digest(),
            }
        );
        assert!(verified
            .display_declassification_provenance_digest()
            .is_some());
        let display = verified.display_text().as_str();
        assert!(!display.chars().any(char::is_control));
        for required in [
            "tier: UserRegistered (2)",
            "name: mail-connector",
            "url: https://api.example.com/mcp/v2?scope=full",
            "tls_identity_pin: 3434343434343434343434343434343434343434343434343434343434343434",
            "requested_effects: READ|SEND (0x0011)",
            "tool[0].name: mail.read",
            "tool[0].effects: READ (0x0001)",
            "tool[1].name: mail.send",
            "tool[1].effects: SEND (0x0010)",
        ] {
            assert!(
                display.contains(required),
                "missing display field {required}"
            );
        }
        for (index, tool) in tools.iter().enumerate() {
            let encoded =
                base64::engine::general_purpose::STANDARD.encode(minicbor::to_vec(tool).unwrap());
            assert!(display.contains(&format!(
                "tool[{index}].semantics_canonical_cbor_base64: {encoded}"
            )));
        }
        let complete = base64::engine::general_purpose::STANDARD.encode(&descriptor);
        assert!(display.contains(&format!(
            "connector_descriptor_canonical_cbor_base64: {complete}"
        )));

        let verified_ui = proposed
            .display_authentication()
            .verify(
                envelope_key_id,
                envelope_key.verifying_key().to_bytes(),
                Digest32V2::new([0x89; 32]),
                Digest32V2::new([0x85; 32]),
                1,
                UnixMillisV2::new(201),
            )
            .unwrap();
        assert_eq!(
            verified_ui.purpose(),
            UiAuthenticationPurposeV2::ApprovalDisplay
        );
        assert_eq!(
            verified_ui.expected_principal(),
            Some(PrincipalIdV2::new([0x94; 32]))
        );
        assert_eq!(
            verified_ui.authentication_origin(),
            FixedOriginV2::Approval8766
        );
        assert_eq!(verified_ui.return_origin(), FixedOriginV2::Approval8766);
        assert!(matches!(
            verified_ui.binding(),
            UiAuthenticationBindingV2::ApprovalDisplay {
                durable_task_id,
                approval_purpose: ApprovalPurposeV2::ConnectorRegistration,
                display_digest,
                ..
            } if durable_task_id == DurableTaskIdV2::new([0x84; 32])
                && display_digest == verified.display_digest()
        ));
        assert!(fixture.authority.connector_authorizations.is_empty());
        assert_eq!(
            fixture.authority.propose_connector_registration(
                &ProposeConnectorRegistrationRequestV2::new(prepared.authorization(), descriptor,)
                    .unwrap(),
                &fixture.values,
                BootIdV2::new([0x8c; 32]),
                fixture.caller_identity,
                Digest32V2::new([0x85; 32]),
                1,
                UnixMillisV2::new(202),
            ),
            Err(KernelAgentAuthorityErrorV2::InvalidReference)
        );
    }

    #[test]
    fn connector_prepare_retains_constant_size_binding_and_consume_prunes_record() {
        let mut fixture = planner_authority_fixture();
        install_connector_runtime(&mut fixture, true);
        let (descriptor, _) = valid_user_connector_descriptor();
        let prepared = fixture
            .authority
            .prepare_connector_registration(
                &PrepareConnectorRegistrationRequestV2::new(
                    fixture.authority.sessions[0].session,
                    descriptor.clone(),
                )
                .unwrap(),
                BootIdV2::new([0x8c; 32]),
                fixture.caller_identity,
                Digest32V2::new([0x85; 32]),
                1,
                UnixMillisV2::new(200),
            )
            .unwrap();
        assert_eq!(
            fixture
                .authority
                .connector_authorization_retained_descriptor_bytes_for_test(),
            0
        );
        assert_eq!(
            fixture.authority.connector_authorization_count_for_test(),
            1
        );

        let proposed = fixture
            .authority
            .prepare_connector_registration_proposal(
                &ProposeConnectorRegistrationRequestV2::new(prepared.authorization(), descriptor)
                    .unwrap(),
                &fixture.values,
                BootIdV2::new([0x8c; 32]),
                fixture.caller_identity,
                Digest32V2::new([0x85; 32]),
                1,
                UnixMillisV2::new(201),
            )
            .unwrap();
        fixture
            .authority
            .consume_connector_registration_proposal(&proposed)
            .unwrap();
        assert_eq!(
            fixture.authority.connector_authorization_count_for_test(),
            0
        );
    }

    #[test]
    fn connector_prepare_has_small_per_session_constant_record_cap() {
        let mut fixture = planner_authority_fixture();
        install_connector_runtime(&mut fixture, true);
        let (descriptor, _) = valid_user_connector_descriptor();
        for offset in 0..16 {
            fixture
                .authority
                .prepare_connector_registration(
                    &PrepareConnectorRegistrationRequestV2::new(
                        fixture.authority.sessions[0].session,
                        descriptor.clone(),
                    )
                    .unwrap(),
                    BootIdV2::new([0x8c; 32]),
                    fixture.caller_identity,
                    Digest32V2::new([0x85; 32]),
                    1,
                    UnixMillisV2::new(200 + offset),
                )
                .unwrap();
        }
        assert_eq!(fixture.authority.connector_authorizations.len(), 16);
        assert_eq!(
            fixture.authority.prepare_connector_registration(
                &PrepareConnectorRegistrationRequestV2::new(
                    fixture.authority.sessions[0].session,
                    descriptor,
                )
                .unwrap(),
                BootIdV2::new([0x8c; 32]),
                fixture.caller_identity,
                Digest32V2::new([0x85; 32]),
                1,
                UnixMillisV2::new(300),
            ),
            Err(KernelAgentAuthorityErrorV2::LimitExceeded)
        );
    }

    #[test]
    fn connector_control_refuses_missing_tag3_invalid_display_text_and_zero_authority() {
        let (descriptor, _) = valid_user_connector_descriptor();

        let mut no_tag3 = planner_authority_fixture_with_approval_display(false);
        install_connector_runtime(&mut no_tag3, true);
        let prepared = no_tag3
            .authority
            .prepare_connector_registration(
                &PrepareConnectorRegistrationRequestV2::new(
                    no_tag3.authority.sessions[0].session,
                    descriptor.clone(),
                )
                .unwrap(),
                BootIdV2::new([0x8c; 32]),
                no_tag3.caller_identity,
                Digest32V2::new([0x85; 32]),
                1,
                UnixMillisV2::new(200),
            )
            .unwrap();
        assert_eq!(
            no_tag3.authority.propose_connector_registration(
                &ProposeConnectorRegistrationRequestV2::new(
                    prepared.authorization(),
                    descriptor.clone(),
                )
                .unwrap(),
                &no_tag3.values,
                BootIdV2::new([0x8c; 32]),
                no_tag3.caller_identity,
                Digest32V2::new([0x85; 32]),
                1,
                UnixMillisV2::new(201),
            ),
            Err(KernelAgentAuthorityErrorV2::BindingMismatch)
        );
        assert_eq!(no_tag3.authority.connector_authorizations.len(), 1);

        let mut invalid_text = planner_authority_fixture();
        install_connector_runtime(&mut invalid_text, true);
        let name_offset = descriptor
            .windows(b"mail-connector".len())
            .position(|window| window == b"mail-connector")
            .unwrap();
        for replacement in [0xff, 0x01] {
            let mut invalid = descriptor.clone();
            invalid[name_offset] = replacement;
            assert_eq!(
                invalid_text.authority.prepare_connector_registration(
                    &PrepareConnectorRegistrationRequestV2::new(
                        invalid_text.authority.sessions[0].session,
                        invalid,
                    )
                    .unwrap(),
                    BootIdV2::new([0x8c; 32]),
                    invalid_text.caller_identity,
                    Digest32V2::new([0x85; 32]),
                    1,
                    UnixMillisV2::new(200),
                ),
                Err(KernelAgentAuthorityErrorV2::BindingMismatch)
            );
        }

        let mut zero_authority = planner_authority_fixture();
        install_connector_runtime(&mut zero_authority, false);
        assert_eq!(
            zero_authority.authority.prepare_connector_registration(
                &PrepareConnectorRegistrationRequestV2::new(
                    zero_authority.authority.sessions[0].session,
                    descriptor,
                )
                .unwrap(),
                BootIdV2::new([0x8c; 32]),
                zero_authority.caller_identity,
                Digest32V2::new([0x85; 32]),
                1,
                UnixMillisV2::new(200),
            ),
            Err(KernelAgentAuthorityErrorV2::Unavailable)
        );
    }

    #[test]
    fn connector_display_covers_stdio_package_digest_and_refuses_oversize_output() {
        let canonical = valid_user_stdio_connector_descriptor(1);
        let descriptor = ConnectorDescriptorV2::from_canonical_bytes(&canonical, &[]).unwrap();
        let display = super::connector_registration_display(&descriptor).unwrap();
        assert!(display.as_str().contains(&format!(
            "transport: stdio; package_digest: {}",
            "35".repeat(32)
        )));
        assert!(display.as_str().contains("structural_role: Source (1)"));
        assert!(!display.as_str().contains("url:"));

        let oversized = valid_user_stdio_connector_descriptor(4_096);
        let descriptor = ConnectorDescriptorV2::from_canonical_bytes(&oversized, &[]).unwrap();
        assert_eq!(
            super::connector_registration_display(&descriptor),
            Err(KernelAgentAuthorityErrorV2::BindingMismatch)
        );
    }

    fn planner_input_runtime() -> InputRuntimeV2 {
        planner_input_runtime_with_arguments(1)
    }

    fn planner_input_runtime_with_arguments(maximum_arguments: u16) -> InputRuntimeV2 {
        planner_input_runtime_with_template(maximum_arguments, 21)
    }

    fn planner_input_runtime_with_template(
        maximum_arguments: u16,
        action_template: u32,
    ) -> InputRuntimeV2 {
        const ASSET_DIGEST_DOMAIN: &[u8] = b"SAVANA_INPUT_RUNTIME_ASSET_V2\0";
        const ASSET_SIGNATURE_DOMAIN: &[u8] = b"SAVANA_INPUT_RUNTIME_ASSET_SIGNATURE_V2\0";

        let mut payload = minicbor::Encoder::new(Vec::new());
        payload
            .array(7)
            .unwrap()
            .u16(2)
            .unwrap()
            .u64(1)
            .unwrap()
            .u64(10_000)
            .unwrap();
        PlannerRouteIdV2::new(7)
            .encode(&mut payload, &mut ())
            .unwrap();
        payload
            .array(6)
            .unwrap()
            .u32(4096)
            .unwrap()
            .u16(32)
            .unwrap()
            .u16(4)
            .unwrap()
            .u16(1)
            .unwrap()
            .u16(maximum_arguments)
            .unwrap()
            .u32(65_536)
            .unwrap()
            .array(0)
            .unwrap()
            .array(1)
            .unwrap()
            .array(6)
            .unwrap()
            .u32(1)
            .unwrap()
            .str("send")
            .unwrap()
            .u16(1)
            .unwrap()
            .u32(11)
            .unwrap()
            .array(1)
            .unwrap();
        ActionTemplateIdV2::new(action_template)
            .encode(&mut payload, &mut ())
            .unwrap();
        payload.null().unwrap();
        let payload = payload.into_writer();
        let signing_key = SigningKey::from_bytes(&[0x97; 32]);
        let key_id = Ed25519KeyIdV2::new([0x98; 32]);
        let asset_digest: [u8; 32] = Sha256::new()
            .chain_update(ASSET_DIGEST_DOMAIN)
            .chain_update(&payload)
            .finalize()
            .into();
        let mut signature_input = Vec::from(ASSET_SIGNATURE_DOMAIN);
        signature_input.extend_from_slice(&asset_digest);
        let mut signed = minicbor::Encoder::new(Vec::new());
        signed.array(3).unwrap().bytes(&payload).unwrap();
        key_id.encode(&mut signed, &mut ()).unwrap();
        signed
            .bytes(&signing_key.sign(&signature_input).to_bytes())
            .unwrap();
        let signed =
            SignedInputRuntimeAssetsV2::from_canonical_bytes(&signed.into_writer()).unwrap();
        InputRuntimeV2::new(
            VerifiedInputRuntimeAssetsV2::verify(
                &signed,
                key_id,
                signing_key.verifying_key().to_bytes(),
                UnixMillisV2::new(100),
            )
            .unwrap(),
        )
    }

    #[test]
    fn managed_admin_real_owner_is_disabled_until_trusted_then_deduplicates() {
        use crate::v04_managed_admin::{AdminSubmissionV04, AdminTrustV04};
        use crate::v2_core_services::CoreKernelRuntimeServicesV2;
        use crate::v2_kernel_owner::KernelRuntimeOwnerV2;
        use savana_policy_core::v2::{
            ManagedAdminCommandV04, ManagedAdminOperationV04 as Op, ManagedAdminResultV04,
            ManagedSourcePolicyV04,
        };
        use std::time::{Duration, Instant};
        let mut f = planner_authority_fixture();
        let key = SigningKey::from_bytes(&[92; 32]);
        let public = key.verifying_key().to_bytes();
        let now = crate::v04_managed_admin::now().unwrap().get();
        let policy = ManagedSourcePolicyV04 {
            schema: 1,
            installation: [0x89; 32],
            source: [71; 32],
            namespace: [72; 32],
            target: [73; 32],
            resource_issuer: SigningKey::from_bytes(&[93; 32]).verifying_key().to_bytes(),
            not_before: now - 1,
            expires_at: now + 60_000,
            max_objects: 8,
            max_object_bytes: 1024,
            max_mutations: 32,
            execution_projection: None,
        };
        let mut command = ManagedAdminCommandV04 {
            schema: 1,
            installation: [0x89; 32],
            store: [0x9b; 32],
            request: [74; 32],
            not_before: now - 1,
            expires_at: now + 60_000,
            operation: Op::RegisterSource {
                signature: key
                    .sign(&policy.signing_digest().unwrap())
                    .to_bytes()
                    .to_vec(),
                policy,
            },
        };
        assert!(f
            .authority
            .apply_managed_admin(AdminSubmissionV04::for_test(&command, &key), &mut f.values)
            .is_err());
        let trust = || {
            AdminTrustV04::from_deployment(
                Some((derive_ed25519_key_id_v2(public), public)),
                Digest32V2::new([0x89; 32]),
                Digest32V2::new([0x9b; 32]),
                &[],
            )
            .unwrap()
            .unwrap()
        };
        f.authority.install_managed_admin(trust()).unwrap();
        assert!(f.authority.install_managed_admin(trust()).is_err());
        let mut services = CoreKernelRuntimeServicesV2::new(8, 4096, 8, 64).unwrap();
        services.install_agent_security(f.authority).unwrap();
        let owner = KernelRuntimeOwnerV2::spawn(4, services).unwrap();
        let submit = |command: &ManagedAdminCommandV04, key: &SigningKey| {
            owner.submit_managed_admin(
                AdminSubmissionV04::for_test(command, key),
                Instant::now() + Duration::from_secs(5),
            )
        };
        assert!(submit(&command, &SigningKey::from_bytes(&[94; 32])).is_err());
        assert!(matches!(
            submit(&command, &key).unwrap().result(),
            ManagedAdminResultV04::SourceRegistered { .. }
        ));
        command.request = [75; 32];
        command.operation = Op::CreateResource {
            source: [71; 32],
            namespace: [72; 32],
            label: "private".into(),
            content: b"private bytes".to_vec(),
        };
        // An expired queue deadline cannot write; it also must not poison admission.
        assert!(owner
            .submit_managed_admin(
                AdminSubmissionV04::for_test(&command, &key),
                Instant::now() - Duration::from_millis(1)
            )
            .is_err());
        let receipt = submit(&command, &key).unwrap();
        assert_eq!(receipt, submit(&command, &key).unwrap());
        let resource = match receipt.result() {
            ManagedAdminResultV04::ResourceCreated { resource } => *resource,
            _ => panic!("wrong private receipt"),
        };
        command.request = [76; 32];
        command.operation = Op::UpdateResource {
            resource,
            expected_revision: 1,
            value: None,
        };
        assert!(matches!(
            submit(&command, &key).unwrap().result(),
            ManagedAdminResultV04::ResourceUpdated { revision: 2, .. }
        ));
        assert!(submit(&command, &SigningKey::from_bytes(&[94; 32])).is_err());
        command.request = [77; 32]; // new stale revision fails, exact retry succeeds
        assert!(submit(&command, &key).is_err());
        command.request = [76; 32];
        assert!(submit(&command, &key).is_ok());
    }

    fn planner_policy_runtime(
        directory: &std::path::Path,
        include_approval_display: bool,
    ) -> KernelG4G5RuntimeV2 {
        let active_tools = planner_active_tools();
        let declassification_rules = planner_declassification_rules(include_approval_display);
        let durable = DurableG4StateV2::open(
            &directory.join("kernel-g4-state-v2.cbor"),
            [0x99; 32],
            DurableStateNamespaceV2::from_verified_installation(
                Digest32V2::new([0x89; 32]),
                Digest32V2::new([0x9b; 32]),
            )
            .unwrap(),
            Box::new(TestG4StateAnchorV2::default()),
        )
        .unwrap();
        let settlement_key = SigningKey::from_bytes(&[0x9c; 32]);
        KernelG4G5RuntimeV2::from_verified_policy(
            declassification_rules,
            active_tools,
            activate_internal_validator_registry(Vec::new()).unwrap(),
            durable,
            RoleIdV2::new(1),
            OntologyExprV2::eq(
                OntologyOperandV2::context(ContextFieldV2::Role),
                OntologyOperandV2::literal(OntologyScalarV2::integer(1)),
            ),
            VerifiedPolicyDispositionV2::permit_from_verified_policy(),
            KernelToolApprovalConfigV2::from_verified_manifest(
                ServiceIdentityV2::new([0x9d; 32]),
                derive_ed25519_key_id_v2(settlement_key.verifying_key().to_bytes()),
                settlement_key.verifying_key().to_bytes(),
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn verified_effect_ledger_projection(
        installation_id: Digest32V2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        effect_fence_epoch: u64,
    ) -> savana_kernel_protocol::v2::VerifiedEffectLedgerProjectionV2 {
        const SIGNATURE_DOMAIN: &[u8] = b"SAVANA_EFFECT_LEDGER_PROJECTION_SIGNATURE_V2\0";
        let signing_key = SigningKey::from_bytes(&[0xaa; 32]);
        let signing_key_id = derive_ed25519_key_id_v2(signing_key.verifying_key().to_bytes());
        let binding = EffectLedgerProjectionBindingV2::from_verified_deployment(
            installation_id,
            active_state_manifest_digest,
            deployment_generation,
            effect_fence_epoch,
            Digest32V2::new([0xab; 32]),
            Digest32V2::new([0xac; 32]),
            signing_key_id,
            signing_key.verifying_key().to_bytes(),
        )
        .unwrap();
        let mut payload = minicbor::Encoder::new(Vec::new());
        payload
            .array(11)
            .unwrap()
            .u16(2)
            .unwrap()
            .bytes(installation_id.as_bytes())
            .unwrap()
            .bytes(active_state_manifest_digest.as_bytes())
            .unwrap()
            .u64(deployment_generation)
            .unwrap()
            .u64(effect_fence_epoch)
            .unwrap()
            .bytes(binding.projection_identity().as_bytes())
            .unwrap()
            .bytes(binding.authenticated_head_digest().as_bytes())
            .unwrap()
            .bool(false)
            .unwrap()
            .bool(true)
            .unwrap()
            .bytes(&[0xad; 32])
            .unwrap()
            .bytes(&[0xae; 32])
            .unwrap();
        let payload = payload.into_writer();
        let payload_digest: [u8; 32] = Sha256::digest(&payload).into();
        let mut signature_input = Vec::from(SIGNATURE_DOMAIN);
        signature_input.extend_from_slice(&payload_digest);
        let signature = signing_key.sign(&signature_input).to_bytes();
        let mut signed = minicbor::Encoder::new(Vec::new());
        signed
            .array(3)
            .unwrap()
            .bytes(&payload)
            .unwrap()
            .bytes(signing_key_id.as_bytes())
            .unwrap()
            .bytes(&signature)
            .unwrap();
        verify_effect_ledger_projection_v2(&signed.into_writer(), binding).unwrap()
    }

    fn test_g7_runtime(
        installation_id: Digest32V2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        effect_fence_epoch: u64,
    ) -> KernelG7RuntimeV2 {
        test_g7_runtime_with_connector_configuration(
            installation_id,
            active_state_manifest_digest,
            deployment_generation,
            effect_fence_epoch,
            None,
        )
    }

    fn test_g7_runtime_with_connector_authority(
        installation_id: Digest32V2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        effect_fence_epoch: u64,
    ) -> KernelG7RuntimeV2 {
        test_g7_runtime_with_connector_configuration(
            installation_id,
            active_state_manifest_digest,
            deployment_generation,
            effect_fence_epoch,
            Some(SigningKey::from_bytes(&[0xc3; 32])),
        )
    }

    fn test_g7_runtime_with_connector_configuration(
        installation_id: Digest32V2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        effect_fence_epoch: u64,
        connector_authority_signing_key: Option<SigningKey>,
    ) -> KernelG7RuntimeV2 {
        let client_key = SigningKey::from_bytes(&[0xaf; 32]);
        let server_key = SigningKey::from_bytes(&[0xb0; 32]);
        let edge = KernelServiceHandshakeEdgeV2::from_verified_deployment(
            EndpointRoleV2::KernelExecutor,
            installation_id,
            ServiceIdentityV2::new([0xb1; 32]),
            ServiceIdentityV2::new([0xb2; 32]),
            derive_ed25519_key_id_v2(client_key.verifying_key().to_bytes()),
            derive_ed25519_key_id_v2(server_key.verifying_key().to_bytes()),
            BootIdV2::new([0xb3; 32]),
            1,
            active_state_manifest_digest,
            deployment_generation,
            effect_fence_epoch,
            Digest32V2::new([0xb4; 32]),
            Digest32V2::new([0xb5; 32]),
            Digest32V2::new([0xb6; 32]),
            Digest32V2::new([0xb7; 32]),
            Digest32V2::new([0xb8; 32]),
            Digest32V2::new([0xb9; 32]),
        )
        .unwrap();
        let executor = SuiteOneKernelExecutorClientV2::from_verified_deployment(
            edge,
            BootIdV2::new([0xba; 32]),
            PeerIdentityBindingV2::linux(501, 502, 503, 504, Digest32V2::new([0xbb; 32])).unwrap(),
            client_key,
            server_key.verifying_key().to_bytes(),
        )
        .unwrap();
        let executor_secret = x25519_dalek::StaticSecret::from([0xbc; 32]);
        let executor_seal_public_key = x25519_dalek::PublicKey::from(&executor_secret).to_bytes();
        let receipt_key = SigningKey::from_bytes(&[0xbd; 32]);
        let connector_registry_genesis_digest = Digest32V2::new([0xbf; 32]);
        let connector_authority_public_key = connector_authority_signing_key
            .as_ref()
            .map_or([0; 32], |key| key.verifying_key().to_bytes());
        let connector_authority_key_id = if connector_authority_public_key == [0; 32] {
            Ed25519KeyIdV2::new([0; 32])
        } else {
            derive_ed25519_key_id_v2(connector_authority_public_key)
        };
        let user_host_allowlist = if connector_authority_public_key == [0; 32] {
            Vec::new()
        } else {
            vec![BoundedConnectorHostV2::new("example.com").unwrap()]
        };
        let connector_registry = SharedVerifiedConnectorRegistryV2::from_verified_state(
            ConnectorRegistryStateV2::from_verified_genesis(
                connector_registry_genesis_digest,
                connector_authority_public_key,
                user_host_allowlist,
                vec![],
            )
            .unwrap(),
        )
        .unwrap();
        KernelG7RuntimeV2::from_verified_deployment(
            2,
            Digest32V2::new([0xbe; 32]),
            ExecutorIdentityV2::new([0xa7; 32]),
            hpke_x25519_key_id(executor_seal_public_key),
            executor_seal_public_key,
            connector_registry_genesis_digest,
            connector_authority_key_id,
            connector_authority_public_key,
            connector_authority_signing_key,
            connector_registry,
            verified_effect_ledger_projection(
                installation_id,
                active_state_manifest_digest,
                deployment_generation,
                effect_fence_epoch,
            ),
            SigningKey::from_bytes(&[0xc0; 32]),
            derive_ed25519_key_id_v2(receipt_key.verifying_key().to_bytes()),
            receipt_key.verifying_key().to_bytes(),
            executor,
        )
        .unwrap()
    }

    pub(crate) fn planner_declassification_rules(
        include_approval_display: bool,
    ) -> crate::v2_declassification_policy::ActiveDeclassificationRuleSetV2 {
        planner_declassification_rules_with_handoffs(include_approval_display, None, None)
    }

    fn planner_declassification_rules_with_handoffs(
        include_approval_display: bool,
        execution_reader: Option<Digest32V2>,
        final_release_reader: Option<Digest32V2>,
    ) -> crate::v2_declassification_policy::ActiveDeclassificationRuleSetV2 {
        planner_declassification_rules_with_model(
            include_approval_display,
            execution_reader,
            final_release_reader,
            None,
        )
    }
    fn planner_declassification_rules_with_model(
        include_approval_display: bool,
        execution_reader: Option<Digest32V2>,
        final_release_reader: Option<Digest32V2>,
        fused_reader: Option<Digest32V2>,
    ) -> crate::v2_declassification_policy::ActiveDeclassificationRuleSetV2 {
        let installer = SigningKey::from_bytes(&[0x9e; 32]);
        let authority = SigningKey::from_bytes(&[0x9f; 32]);
        let family = Digest32V2::new([0xa0; 32]);
        let roots = OperationalTrustRootSetV2::new_declassification_signed_for_test(
            family,
            1,
            None,
            vec![OperationalTrustRootSetItemV2::new(
                OperationalTrustRootPurposeV2::DeclassificationAuthority,
                authority.verifying_key().to_bytes(),
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
        let planner_rule = DeclassificationRuleV2::new_for_test(
            2,
            ClosedDeclassificationPurposeV2::PlannerCall,
            declassification_implementation_digest_v2(2).unwrap(),
            LeakGateDutyV2::BlocklistAndNoResidualPii,
            None,
            None,
            1,
            10_000,
        )
        .unwrap();
        let mut rules = vec![planner_rule];
        if include_approval_display {
            rules.push(
                DeclassificationRuleV2::new_for_test(
                    3,
                    ClosedDeclassificationPurposeV2::ApprovalDisplay,
                    declassification_implementation_digest_v2(3).unwrap(),
                    LeakGateDutyV2::BlocklistOnly,
                    None,
                    None,
                    1,
                    10_000,
                )
                .unwrap(),
            );
        }
        if let Some(reader) = execution_reader {
            rules.push(
                DeclassificationRuleV2::new_for_test(
                    4,
                    ClosedDeclassificationPurposeV2::ExecutionHandoff,
                    declassification_implementation_digest_v2(4).unwrap(),
                    LeakGateDutyV2::BlocklistOnly,
                    Some(vec![reader]),
                    None,
                    1,
                    10_000,
                )
                .unwrap(),
            );
        }
        if let Some(reader) = final_release_reader {
            rules.push(
                DeclassificationRuleV2::new_for_test(
                    5,
                    ClosedDeclassificationPurposeV2::FinalRelease,
                    declassification_implementation_digest_v2(5).unwrap(),
                    LeakGateDutyV2::BlocklistOnly,
                    Some(vec![reader]),
                    Some(300_000),
                    1,
                    10_000,
                )
                .unwrap(),
            );
        }
        if let Some(reader) = fused_reader {
            rules.push(
                DeclassificationRuleV2::new_for_test(
                    6,
                    ClosedDeclassificationPurposeV2::FusedModelCall,
                    declassification_implementation_digest_v2(6).unwrap(),
                    LeakGateDutyV2::BlocklistAndNoResidualPii,
                    Some(vec![reader]),
                    None,
                    1,
                    10_000,
                )
                .unwrap(),
            );
        }
        let rules = DeclassificationRuleSetV2::new_signed_for_test(
            family, 1, None, rules, 1, 10_000, &roots, &authority, 1, 100,
        )
        .unwrap();
        crate::v2_declassification_policy::ActiveDeclassificationRuleSetV2::new(
            rules,
            Arc::new(roots),
        )
        .unwrap()
    }

    pub(crate) fn planner_active_tools() -> ActiveToolRegistryV2 {
        planner_active_tools_with_release(false)
    }

    fn planner_active_tools_with_release(include_release: bool) -> ActiveToolRegistryV2 {
        planner_active_tools_with_release_mode(include_release, false)
    }
    fn planner_active_tools_with_release_mode(
        include_release: bool,
        result: bool,
    ) -> ActiveToolRegistryV2 {
        let registry_version = VersionV2::new(1, 0, 0);
        let publisher_key = SigningKey::from_bytes(&[0xa1; 32]);
        let publisher_key_id = Ed25519KeyIdV2::new([0xa2; 32]);
        let publisher = VerifiedRegistryPublisherV2::from_verified_manifest(
            publisher_key_id,
            publisher_key.verifying_key().to_bytes(),
            UnixMillisV2::new(1),
            UnixMillisV2::new(10_000),
        )
        .unwrap();
        let mut descriptors = vec![
            verified_planner_descriptor(
                registry_version,
                &publisher,
                &publisher_key,
                publisher_key_id,
                "mail.allowed",
                ActionTemplateIdV2::new(21),
                ToolClassIdV2::new(31),
            ),
            verified_planner_descriptor(
                registry_version,
                &publisher,
                &publisher_key,
                publisher_key_id,
                "mail.unlisted",
                ActionTemplateIdV2::new(22),
                ToolClassIdV2::new(32),
            ),
            verified_planner_descriptor(
                registry_version,
                &publisher,
                &publisher_key,
                publisher_key_id,
                "mail.allowed-alternate",
                ActionTemplateIdV2::new(21),
                ToolClassIdV2::new(33),
            ),
        ];
        if include_release {
            descriptors.push(verified_planner_descriptor(
                registry_version,
                &publisher,
                &publisher_key,
                publisher_key_id,
                if result {
                    "result-release.allowed"
                } else {
                    "release.allowed"
                },
                ActionTemplateIdV2::new(23),
                ToolClassIdV2::new(34),
            ));
        }
        let registry = VerifiedToolRegistryV2::from_verified_descriptors(
            registry_version,
            descriptors.clone(),
        )
        .unwrap();
        let mut activations = descriptors
            .iter()
            .enumerate()
            .map(|(ordinal, descriptor)| {
                (
                    descriptor.descriptor_digest(),
                    VerifiedPolicyToolActivationV2::from_verified_policy(
                        descriptor.descriptor_digest(),
                        ordinal as u32,
                        Digest32V2::new([0xa3_u8.wrapping_add(ordinal as u8); 32]),
                    ),
                )
            })
            .collect::<Vec<_>>();
        activations.sort_unstable_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
        let policy = VerifiedPolicyToolSetV2::from_verified_policy(
            activations
                .into_iter()
                .map(|(_, activation)| activation)
                .collect(),
        )
        .unwrap();
        descriptors.sort_unstable_by(|left, right| {
            left.descriptor_digest()
                .as_bytes()
                .cmp(right.descriptor_digest().as_bytes())
        });
        let constraints = VerifiedManifestToolConstraintSetV2::from_manifest(
            descriptors
                .iter()
                .map(|descriptor| {
                    VerifiedManifestToolConstraintV2::from_manifest(
                        descriptor.descriptor_digest(),
                        2,
                        500_000_000,
                        Vec::new(),
                    )
                    .unwrap()
                })
                .collect(),
        )
        .unwrap();
        ActiveToolRegistryV2::intersect(&registry, &policy, &constraints).unwrap()
    }

    #[allow(clippy::too_many_arguments)]
    fn verified_planner_descriptor(
        registry_version: VersionV2,
        publisher: &VerifiedRegistryPublisherV2,
        publisher_key: &SigningKey,
        publisher_key_id: Ed25519KeyIdV2,
        provider_tool_id: &str,
        action_template: ActionTemplateIdV2,
        tool_class: ToolClassIdV2,
    ) -> savana_policy_core::v2::VerifiedToolDescriptorV2 {
        let unsigned = UnsignedToolDescriptorV2::from_verified_manifest(
            2,
            registry_version,
            test_tool_connector_identity(),
            IdentifierV2::new(provider_tool_id).unwrap(),
            action_template,
            tool_class,
            Digest32V2::new([0xa5; 32]),
            Digest32V2::new([0xa6; 32]),
            vec![RoleIdV2::new(1)],
            if matches!(
                provider_tool_id,
                "release.allowed" | "result-release.allowed"
            ) {
                EffectSetV2::FINAL_RELEASE
            } else {
                EffectSetV2::SEND
            },
            AttemptKindV2::ToolWrite,
            BoundedConnectorRetryPolicyV2::new(
                ExecutorIdempotencyContractV2::ConnectorIdempotentByExecutionNonce,
                3,
                1_000_000_000,
            )
            .unwrap(),
            Vec::<InternalValidatorDeclarationV2>::new(),
            ExecutorIdentityV2::new([0xa7; 32]),
            ProjectionIdV2::new(3),
            // Independently pinned SHA-256 vector for destination projection 3.
            Digest32V2::new([
                0x59, 0xe6, 0xe3, 0xf1, 0x21, 0x72, 0x54, 0x67, 0xb5, 0x4a, 0xb5, 0x70, 0x0e, 0x1c,
                0xbf, 0x9f, 0xde, 0x2a, 0xec, 0xb6, 0x81, 0xf3, 0x99, 0x31, 0x46, 0x9d, 0x60, 0x14,
                0xfc, 0xa0, 0x8d, 0xfe,
            ]),
            savana_kernel_protocol::v2::DisplayProjectionIdV2::new(4),
            // Independently pinned SHA-256 vector for display projection 4.
            Digest32V2::new([
                0xc8, 0x73, 0x8f, 0x91, 0x81, 0x6b, 0x49, 0xcb, 0x41, 0x2e, 0x99, 0xfc, 0xb3, 0xc5,
                0xf8, 0x00, 0x3e, 0x0b, 0x1c, 0x3d, 0x6a, 0x5f, 0xc3, 0x1d, 0x8c, 0x63, 0x10, 0xdb,
                0x12, 0xc4, 0xca, 0x78,
            ]),
            ExecutorIdempotencyContractV2::ConnectorIdempotentByExecutionNonce,
            UnixMillisV2::new(1),
            UnixMillisV2::new(10_000),
        )
        .unwrap();
        let unsigned = unsigned
            .with_business_profile(
                if matches!(
                    provider_tool_id,
                    "release.allowed" | "result-release.allowed"
                ) {
                    (if provider_tool_id == "result-release.allowed" {
                        savana_kernel_protocol::v2::final_result_release_business_profile_v04
                    } else {
                        savana_kernel_protocol::v2::final_release_business_profile_v2
                    })(
                        savana_kernel_protocol::v2::business_target_identity_v2(
                            "https://provider.example/savana/final-release",
                            Digest32V2::new([0x28; 32]),
                        )
                        .unwrap(),
                        Digest32V2::new([0x29; 32]),
                    )
                    .unwrap()
                } else {
                    task_business_profile(provider_tool_id)
                },
            )
            .unwrap();
        let descriptor_digest = descriptor_digest_v2(&unsigned).unwrap();
        let mut signature_input = b"SAVANA_TOOL_DESCRIPTOR_SIGNATURE_V2\0".to_vec();
        signature_input.extend_from_slice(descriptor_digest.as_bytes());
        let unsigned_payload = minicbor::to_vec(&unsigned).unwrap();
        let mut signed = minicbor::Encoder::new(Vec::new());
        signed.array(3).unwrap().bytes(&unsigned_payload).unwrap();
        publisher_key_id.encode(&mut signed, &mut ()).unwrap();
        signed
            .bytes(&publisher_key.sign(&signature_input).to_bytes())
            .unwrap();
        SignedToolDescriptorV2::from_canonical_bytes(&signed.into_writer())
            .unwrap()
            .verify(publisher, registry_version, UnixMillisV2::new(100))
            .unwrap()
    }

    fn task_business_profile(operation: &str) -> savana_kernel_protocol::v2::BusinessProfileV2 {
        use savana_kernel_protocol::v2::*;
        BusinessProfileV2::new(
            ActionCodecProfileV2::McpToolsCallJsonV1,
            operation,
            business_target_identity_v2(
                "https://provider.example/savana/final-release",
                Digest32V2::new([0x28; 32]),
            )
            .unwrap(),
            Digest32V2::new([0x29; 32]),
            TaskEffectV2::Send,
            BusinessMagnitudeV2::FixedCount(1),
            vec![
                BusinessFieldV2::new(
                    "body",
                    BusinessFieldRoleV2::Payload,
                    BusinessFieldTypeV2::Text,
                )
                .unwrap(),
                BusinessFieldV2::new(
                    "file",
                    BusinessFieldRoleV2::Resource,
                    BusinessFieldTypeV2::Text,
                )
                .unwrap(),
                BusinessFieldV2::new(
                    "to",
                    BusinessFieldRoleV2::Destination,
                    BusinessFieldTypeV2::Text,
                )
                .unwrap(),
            ],
        )
        .unwrap()
    }

    fn test_tool_connector_identity() -> Digest32V2 {
        let mut identity = minicbor::Encoder::new(Vec::new());
        identity
            .array(2)
            .unwrap()
            .str("intent-bound-test")
            .unwrap()
            .array(3)
            .unwrap()
            .u16(2)
            .unwrap()
            .str("https://provider.example/savana/final-release")
            .unwrap()
            .bytes(&[0x28; 32])
            .unwrap();
        Digest32V2::new(
            Sha256::new()
                .chain_update(b"savana.connector.deployment.v2\0")
                .chain_update(identity.into_writer())
                .finalize()
                .into(),
        )
    }

    fn planner_step(
        ordinal: u16,
        action_template: u32,
        tool_class: u32,
        slot: PlannerSlotRefV2,
        dependencies: Vec<u16>,
    ) -> PlannerStepV2 {
        PlannerStepV2::new(
            ordinal,
            ActionTemplateIdV2::new(action_template),
            ToolClassIdV2::new(tool_class),
            vec![(ArgumentNameV2::new("input".to_owned()).unwrap(), slot)],
            dependencies,
        )
        .unwrap()
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
    fn planner_request_is_closed_to_signed_policy_and_limits_are_intersected() {
        let policy = SignedPlannerPolicyV2 {
            planner_route: PlannerRouteIdV2::new(7),
            task_template: StaticTemplateIdV2::new(11),
            intent: PlannerIntentKindV2::SummarizeDocument,
            purpose: PlannerPurposeV2::PlannerCall,
            limits: PlannerLimitsV2::new(8, 8, 8, 65_536).unwrap(),
            allowed_action_templates: vec![ActionTemplateIdV2::new(21)],
        };
        let effective = intersect_planner_request(
            &policy,
            PlannerRouteIdV2::new(7),
            StaticTemplateIdV2::new(11),
            PlannerIntentKindV2::SummarizeDocument,
            PlannerPurposeV2::PlannerCall,
            PlannerLimitsV2::new(4, 16, 2, 32_768).unwrap(),
        )
        .unwrap();
        assert_eq!(effective.maximum_steps(), 4);
        assert_eq!(effective.maximum_dependencies_per_step(), 8);
        assert_eq!(effective.maximum_arguments_per_step(), 2);
        assert_eq!(effective.maximum_encoded_plan_bytes(), 32_768);

        for mismatch in [
            intersect_planner_request(
                &policy,
                PlannerRouteIdV2::new(9),
                StaticTemplateIdV2::new(11),
                PlannerIntentKindV2::SummarizeDocument,
                PlannerPurposeV2::PlannerCall,
                policy.limits,
            ),
            intersect_planner_request(
                &policy,
                PlannerRouteIdV2::new(7),
                StaticTemplateIdV2::new(12),
                PlannerIntentKindV2::SummarizeDocument,
                PlannerPurposeV2::PlannerCall,
                policy.limits,
            ),
            intersect_planner_request(
                &policy,
                PlannerRouteIdV2::new(7),
                StaticTemplateIdV2::new(11),
                PlannerIntentKindV2::Search,
                PlannerPurposeV2::PlannerCall,
                policy.limits,
            ),
        ] {
            assert_eq!(mismatch, Err(KernelAgentAuthorityErrorV2::BindingMismatch));
        }
    }

    #[test]
    fn planner_commit_enforces_retained_signed_policy_step_limit_atomically() {
        let mut fixture = planner_authority_fixture();
        let (ticket, nonce, slot) = fixture.prepare(PlannerLimitsV2::new(1, 1, 1, 65_536).unwrap());
        let plan = PlannerPlanV2::new(
            nonce,
            vec![
                planner_step(1, 21, 31, slot, vec![]),
                planner_step(2, 21, 31, slot, vec![1]),
            ],
        )
        .unwrap();
        let values_before = format!("{:?}", fixture.values);
        let steps_before = fixture.authority.plan_steps.len();

        assert_eq!(
            fixture.commit(ticket, plan),
            Err(KernelAgentAuthorityErrorV2::LimitExceeded)
        );
        assert_eq!(format!("{:?}", fixture.values), values_before);
        assert_eq!(fixture.authority.plan_steps.len(), steps_before);
        assert!(
            !fixture
                .authority
                .planner_tickets
                .iter()
                .find(|record| record.ticket == ticket)
                .unwrap()
                .consumed
        );
    }

    #[test]
    fn planner_commit_enforces_retained_signed_policy_dependency_limit_atomically() {
        let mut fixture = planner_authority_fixture();
        let (ticket, nonce, slot) = fixture.prepare(PlannerLimitsV2::new(3, 1, 1, 65_536).unwrap());
        let plan = PlannerPlanV2::new(
            nonce,
            vec![
                planner_step(1, 21, 31, slot, vec![]),
                planner_step(2, 21, 31, slot, vec![1]),
                planner_step(3, 21, 31, slot, vec![1, 2]),
            ],
        )
        .unwrap();
        let values_before = format!("{:?}", fixture.values);
        let steps_before = fixture.authority.plan_steps.len();

        assert_eq!(
            fixture.commit(ticket, plan),
            Err(KernelAgentAuthorityErrorV2::LimitExceeded)
        );
        assert_eq!(format!("{:?}", fixture.values), values_before);
        assert_eq!(fixture.authority.plan_steps.len(), steps_before);
        assert!(
            !fixture
                .authority
                .planner_tickets
                .iter()
                .find(|record| record.ticket == ticket)
                .unwrap()
                .consumed
        );
    }

    #[test]
    fn planner_commit_enforces_retained_signed_policy_argument_limit_atomically() {
        let mut fixture = planner_authority_fixture();
        let (ticket, nonce, slot) = fixture.prepare(PlannerLimitsV2::new(2, 1, 1, 65_536).unwrap());
        let plan = PlannerPlanV2::new(
            nonce,
            vec![PlannerStepV2::new(
                1,
                ActionTemplateIdV2::new(21),
                ToolClassIdV2::new(31),
                vec![
                    (ArgumentNameV2::new("first".to_owned()).unwrap(), slot),
                    (ArgumentNameV2::new("second".to_owned()).unwrap(), slot),
                ],
                vec![],
            )
            .unwrap()],
        )
        .unwrap();
        let values_before = format!("{:?}", fixture.values);
        let steps_before = fixture.authority.plan_steps.len();

        assert_eq!(
            fixture.commit(ticket, plan),
            Err(KernelAgentAuthorityErrorV2::LimitExceeded)
        );
        assert_eq!(format!("{:?}", fixture.values), values_before);
        assert_eq!(fixture.authority.plan_steps.len(), steps_before);
        assert!(
            !fixture
                .authority
                .planner_tickets
                .iter()
                .find(|record| record.ticket == ticket)
                .unwrap()
                .consumed
        );
    }

    #[test]
    fn planner_commit_enforces_retained_signed_policy_encoded_size_limit_atomically() {
        let dummy_plan = PlannerPlanV2::new(
            Nonce32V2::new([1; 32]),
            vec![planner_step(
                1,
                21,
                31,
                PlannerSlotRefV2::new([1; 16]),
                vec![],
            )],
        )
        .unwrap();
        let encoded_len =
            u32::try_from(encode_planner_plan_v2(&dummy_plan).unwrap().len()).unwrap();
        let mut fixture = planner_authority_fixture();
        let (ticket, nonce, slot) =
            fixture.prepare(PlannerLimitsV2::new(2, 1, 1, encoded_len - 1).unwrap());
        let plan = PlannerPlanV2::new(nonce, vec![planner_step(1, 21, 31, slot, vec![])]).unwrap();
        assert_eq!(
            u32::try_from(encode_planner_plan_v2(&plan).unwrap().len()).unwrap(),
            encoded_len
        );
        let values_before = format!("{:?}", fixture.values);
        let steps_before = fixture.authority.plan_steps.len();

        assert_eq!(
            fixture.commit(ticket, plan),
            Err(KernelAgentAuthorityErrorV2::LimitExceeded)
        );
        assert_eq!(format!("{:?}", fixture.values), values_before);
        assert_eq!(fixture.authority.plan_steps.len(), steps_before);
        assert!(
            !fixture
                .authority
                .planner_tickets
                .iter()
                .find(|record| record.ticket == ticket)
                .unwrap()
                .consumed
        );
    }

    #[test]
    fn planner_commit_enforces_retained_signed_policy_action_allowlist_atomically() {
        let mut fixture = planner_authority_fixture();
        let (ticket, nonce, slot) = fixture.prepare(PlannerLimitsV2::new(2, 1, 1, 65_536).unwrap());
        let ticket_policy = &mut fixture
            .authority
            .planner_tickets
            .iter_mut()
            .find(|record| record.ticket == ticket)
            .unwrap()
            .effective_policy;
        ticket_policy
            .allowed_tool_classes
            .push(ToolClassIdV2::new(32));
        ticket_policy.allowed_tool_classes.sort_unstable();
        let plan = PlannerPlanV2::new(nonce, vec![planner_step(1, 22, 32, slot, vec![])]).unwrap();
        let values_before = format!("{:?}", fixture.values);
        let steps_before = fixture.authority.plan_steps.len();

        assert_eq!(
            fixture.commit(ticket, plan),
            Err(KernelAgentAuthorityErrorV2::BindingMismatch)
        );
        assert_eq!(format!("{:?}", fixture.values), values_before);
        assert_eq!(fixture.authority.plan_steps.len(), steps_before);
        assert!(
            !fixture
                .authority
                .planner_tickets
                .iter()
                .find(|record| record.ticket == ticket)
                .unwrap()
                .consumed
        );
    }

    #[test]
    fn planner_commit_enforces_retained_signed_policy_tool_class_allowlist_atomically() {
        let mut fixture = planner_authority_fixture();
        let (ticket, nonce, slot) = fixture.prepare(PlannerLimitsV2::new(2, 1, 1, 65_536).unwrap());
        fixture
            .authority
            .planner_tickets
            .iter_mut()
            .find(|record| record.ticket == ticket)
            .unwrap()
            .effective_policy
            .allowed_tool_classes
            .retain(|class| *class != ToolClassIdV2::new(33));
        let plan = PlannerPlanV2::new(nonce, vec![planner_step(1, 21, 33, slot, vec![])]).unwrap();
        let values_before = format!("{:?}", fixture.values);
        let steps_before = fixture.authority.plan_steps.len();

        assert_eq!(
            fixture.commit(ticket, plan),
            Err(KernelAgentAuthorityErrorV2::BindingMismatch)
        );
        assert_eq!(format!("{:?}", fixture.values), values_before);
        assert_eq!(fixture.authority.plan_steps.len(), steps_before);
        assert!(
            !fixture
                .authority
                .planner_tickets
                .iter()
                .find(|record| record.ticket == ticket)
                .unwrap()
                .consumed
        );
    }

    #[test]
    fn planner_commit_enforces_retained_signed_policy_accepts_boundary_equal_plan() {
        let dummy_slot = PlannerSlotRefV2::new([1; 16]);
        let dummy_plan = PlannerPlanV2::new(
            Nonce32V2::new([1; 32]),
            vec![
                planner_step(1, 21, 31, dummy_slot, vec![]),
                planner_step(2, 21, 31, dummy_slot, vec![1]),
            ],
        )
        .unwrap();
        let exact_encoded_len =
            u32::try_from(encode_planner_plan_v2(&dummy_plan).unwrap().len()).unwrap();
        let mut fixture = planner_authority_fixture();
        let (ticket, nonce, slot) =
            fixture.prepare(PlannerLimitsV2::new(2, 1, 1, exact_encoded_len).unwrap());
        let plan = PlannerPlanV2::new(
            nonce,
            vec![
                planner_step(1, 21, 31, slot, vec![]),
                planner_step(2, 21, 31, slot, vec![1]),
            ],
        )
        .unwrap();
        assert_eq!(
            u32::try_from(encode_planner_plan_v2(&plan).unwrap().len()).unwrap(),
            exact_encoded_len
        );

        let committed = fixture.commit(ticket, plan).unwrap();

        assert_eq!(committed.steps().len(), 2);
        assert!(
            fixture
                .authority
                .planner_tickets
                .iter()
                .find(|record| record.ticket == ticket)
                .unwrap()
                .consumed
        );
    }

    #[test]
    fn durable_preseal_binding_covers_exact_plaintext_and_declassification_node() {
        let node = Digest32V2::new([0x71; 32]);
        let digest = presealed_execution_payload_digest(b"exact plaintext", node);
        assert_ne!(
            digest,
            presealed_execution_payload_digest(b"other plaintext", node)
        );
        assert_ne!(
            digest,
            presealed_execution_payload_digest(b"exact plaintext", Digest32V2::new([0x72; 32]))
        );

        let release_digest = presealed_final_release_payload_digest(b"exact plaintext", node);
        assert_ne!(
            release_digest,
            presealed_final_release_payload_digest(b"other plaintext", node)
        );
        assert_ne!(
            release_digest,
            presealed_final_release_payload_digest(b"exact plaintext", Digest32V2::new([0x72; 32]))
        );
    }

    #[test]
    fn final_release_projection_requires_owned_source_unique_contract_and_exact_destination() {
        final_release_native_executor_fixture(0);
    }

    #[test]
    #[cfg(feature = "test-support")]
    fn native_final_release_checks_real_executor_provider_and_lost_acknowledgement() {
        for mode in 1..=7 {
            final_release_native_executor_fixture(mode);
        }
    }

    // 0: IPC refusal; 1: success; 2: malicious worker; 3/4: provider failure/unknown;
    // 5: real provider success with its dispatch acknowledgement deliberately lost.
    // 6: same lost acknowledgement, then reopen the real encrypted executor journal.
    fn final_release_native_executor_fixture(mode: u8) {
        use super::*;
        use savana_kernel_protocol::v2::*;
        let mut f = planner_authority_fixture_with_task(true, false);
        f.authority.policy.as_mut().unwrap().active_tools = planner_active_tools_with_release(true);
        let s = &f.authority.sessions[0];
        let (input_owner, input_session, actual_source) =
            crate::v2_input_owner::tests::finalized_input_for_authority_fixture(
                s.durable_task_id,
                f.authority.config.installation_id,
                s.principal,
                s.active_state_manifest_digest,
                b"actual vault bytes",
            );
        let source = if mode == 0 {
            Digest32V2::new([3; 32])
        } else {
            actual_source
        };
        let p = f.authority.policy.as_mut().unwrap();
        let active = p
            .active_tools
            .resolve_class(ToolClassIdV2::new(34), s.role, UnixMillisV2::new(100))
            .unwrap();
        let descriptor = active.descriptor().descriptor_digest();
        let profile = active
            .descriptor()
            .unsigned()
            .business_profile()
            .unwrap()
            .clone();
        let controls = BusinessControlsV2::from_fields(
            &profile,
            vec![
                (
                    "resource".into(),
                    BusinessValueV2::Text(format!(
                        "input:{}",
                        source
                            .as_bytes()
                            .iter()
                            .map(|b| format!("{b:02x}"))
                            .collect::<String>()
                    )),
                ),
                (
                    "destination".into(),
                    BusinessValueV2::Text(format!("application-turn:{}", "04".repeat(32))),
                ),
            ],
        )
        .unwrap();
        let draft = TaskAuthorizationDraftV2::new(
            Digest32V2::new([0x38; 32]),
            s.principal,
            s.durable_task_id,
            1,
            f.authority.config.installation_id,
            s.active_state_manifest_digest,
            7,
            UnixMillisV2::new(1),
            UnixMillisV2::new(10000),
            source,
            vec![TaskAuthorizationDraftClauseV2::new(
                1,
                vec![TaskAuthorizationDraftAlternativeV2::new(descriptor, controls).unwrap()],
                1,
                1,
                1,
                vec![],
                false,
            )
            .unwrap()],
        )
        .unwrap();
        let key = SigningKey::from_bytes(&[0x39; 32]);
        let signed = sign_task_authorization_v2(
            draft
                .to_unsigned_authorization(
                    TaskEvidenceKindV2::AuthenticatedStructuredInput,
                    Digest32V2::new([0x37; 32]),
                )
                .unwrap(),
            &key,
        )
        .unwrap();
        let verified = savana_policy_core::v2::VerifiedTaskAuthorizationV2::verify(
            &signed,
            &key.verifying_key(),
            s.principal,
            s.durable_task_id,
            f.authority.config.installation_id,
            s.active_state_manifest_digest,
            UnixMillisV2::new(100),
        )
        .unwrap();
        let root_digest = verified.digest();
        let root_digest = if mode == 0 {
            p.durable
                .record_pending_task_authorization(draft, Digest32V2::new([0x36; 32]))
                .unwrap();
            p.durable
                .install_pending_task_authorization(Digest32V2::new([0x36; 32]), verified)
                .unwrap();
            root_digest
        } else {
            let issuer = crate::v2_task_authority::KernelTaskAuthorizationIssuerV2::new(
                f.authority.config.installation_id,
                key.clone(),
                derive_ed25519_key_id_v2(key.verifying_key().to_bytes()),
                key.verifying_key().to_bytes(),
                SigningKey::from_bytes(&[0x9b; 32])
                    .verifying_key()
                    .to_bytes(),
                SigningKey::from_bytes(&[0x9c; 32])
                    .verifying_key()
                    .to_bytes(),
                &[],
            )
            .unwrap();
            let proof = input_owner
                .authenticate_task_draft_submission(
                    input_session,
                    &draft,
                    s.active_state_manifest_digest,
                    7,
                    UnixMillisV2::new(100),
                )
                .unwrap();
            issuer
                .prepare(
                    &mut p.durable,
                    &p.active_tools,
                    s.role,
                    &proof,
                    draft,
                    Digest32V2::new([0x36; 32]),
                    UnixMillisV2::new(100),
                )
                .unwrap();
            issuer
                .issue_structured(
                    &mut p.durable,
                    &p.active_tools,
                    s.role,
                    &proof,
                    Digest32V2::new([0x36; 32]),
                    UnixMillisV2::new(100),
                )
                .unwrap()
        };
        // This fixture exercises the real native projection/matching helper, not
        // a full ingress/agent/provider run (covered separately by Task 8).
        let step = PlanStepRecordV2 {
            commitment: Digest32V2::new([0x41; 32]),
            run: s.run,
            durable_run_id: s.durable_run_id,
            durable_task_id: s.durable_task_id,
            principal: s.principal,
            role: s.role,
            plan_revision_digest: PlanRevisionDigestV2::new([0x42; 32]),
            internal_step_id: InternalStepIdV2::new([0x43; 32]),
            descriptor_digest: descriptor,
            task_authorization_digest: root_digest,
            proposer_parent: Digest32V2::new([0x44; 32]),
            arguments: vec![],
            derived_controls: vec![],
        };
        let request = PrepareReleaseRequestV2::new(
            s.initial_document,
            vec![s.initial_value],
            ExecutorIdentityV2::new([0xa7; 32]),
            ProjectionIdV2::new(3),
            DisplayProjectionIdV2::new(4),
        )
        .unwrap();
        let project = |source, request: &PrepareReleaseRequestV2, now| {
            project_final_release_business(
                p,
                s,
                request,
                source,
                &step,
                b"actual vault bytes",
                Digest32V2::new([0x45; 32]),
                7,
                UnixMillisV2::new(now),
            )
        };
        let projected = project(source, &request, 100).unwrap();
        let delivered =
            decode_final_release_delivery_v2(&projected.business_request.canonical_json()).unwrap();
        assert_eq!(delivered.payload(), b"actual vault bytes");
        assert_eq!(delivered.turn_binding(), Digest32V2::new([4; 32]));
        assert_eq!(
            projected.task_match.content().action().effect(),
            TaskEffectV2::FinalRelease
        );
        assert!(project(Digest32V2::new([5; 32]), &request, 100).is_err());
        assert!(project(source, &request, 10000).is_err());
        let wrong_projection = PrepareReleaseRequestV2::new(
            s.initial_document,
            vec![s.initial_value],
            request.executor(),
            ProjectionIdV2::new(9),
            request.display_projection(),
        )
        .unwrap();
        assert!(project(source, &wrong_projection, 100).is_err());
        assert_eq!(
            p.durable
                .task_authorization_state(s.durable_task_id)
                .unwrap()
                .clause_consumption(1),
            Some((0, 0))
        );

        // Exercise the production prepare/authorize handlers with a real durable
        // vault and signed fixture settlements. No browser ceremony or provider
        // transport is claimed by this component fixture.
        let (task, run, principal, manifest, producer) = (
            s.durable_task_id,
            s.durable_run_id,
            s.principal,
            s.active_state_manifest_digest,
            s.producer_identity,
        );
        let installation = f.authority.config.installation_id;
        let boot = f.authority.config.agentd_kernel_client_boot_id;
        let agent = f.caller_identity;
        let peer = Digest32V2::new([0x52; 32]);
        #[derive(Default)]
        struct Anchor(savana_vault::VaultStateHeadV2);
        impl savana_vault::VaultRollbackAnchorV2 for Anchor {
            fn current_head(
                &self,
            ) -> Result<savana_vault::VaultStateHeadV2, savana_vault::VaultErrorV2> {
                Ok(self.0)
            }
            fn compare_and_advance(
                &mut self,
                expected: savana_vault::VaultStateHeadV2,
                next: savana_vault::VaultStateHeadV2,
            ) -> Result<(), savana_vault::VaultErrorV2> {
                if self.0 != expected {
                    return Err(savana_vault::VaultErrorV2::RollbackDetected);
                }
                self.0 = next;
                Ok(())
            }
        }
        let vault_dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(
            vault_dir.path(),
            <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700),
        )
        .unwrap();
        let mut vault = savana_vault::DurableVaultServiceV2::open(
            &vault_dir.path().join("vault-state-v2.cbor"),
            [0x53; 32],
            savana_vault::DurableVaultNamespaceV2::from_verified_installation(
                installation,
                Digest32V2::new([0x54; 32]),
            )
            .unwrap(),
            Box::<Anchor>::default(),
            savana_vault::VaultServiceV2::from_verified_deployment(
                installation,
                manifest,
                boot,
                10,
            )
            .unwrap(),
        )
        .unwrap();
        let pending = vault
            .create_pending_ingress(
                savana_vault::VaultIngressMaterialV2::from_verified_gated_input(
                    task,
                    run,
                    principal,
                    Digest32V2::new([0x55; 32]),
                    Digest32V2::new([0x56; 32]),
                    UnixMillisV2::new(10000),
                    b"actual vault bytes".to_vec(),
                )
                .unwrap(),
                UnixMillisV2::new(100),
            )
            .unwrap();
        let live = vault
            .commit_ingress(pending, UnixMillisV2::new(101))
            .unwrap();
        let document = vault
            .issue_masked_document(
                &live,
                savana_vault::VaultAccessContextV2::from_authenticated_agent(
                    boot,
                    agent,
                    peer,
                    run,
                    UnixMillisV2::new(10000),
                )
                .unwrap(),
                UnixMillisV2::new(102),
            )
            .unwrap();
        let mut data = crate::v2_data_plane::ProductionKernelDataPlaneV2::new(
            planner_input_runtime(),
            vault,
            planner_declassification_rules(true),
            installation,
            producer,
            boot,
            agent,
            peer,
            EffectSetV2::ALL,
            10000,
        )
        .unwrap();
        f.authority.sessions[0].initial_document = document;
        f.authority.sessions[0].task_authorization_digest = Some(root_digest);
        if mode == 0 {
            f.authority.plan_steps.push(step);
        } else {
            f.authority.sessions[0].signed_planner_policy =
                SignedPlannerPolicyV2::from_verified_input(
                    planner_input_runtime_with_template(1, 23)
                        .process(
                            savana_input_runtime::InputChannelV2::ChatText,
                            "send approved release",
                            UnixMillisV2::new(100),
                        )
                        .unwrap()
                        .planner_envelope(),
                )
                .unwrap();
            let (ticket, nonce, _) = f.prepare(PlannerLimitsV2::new(1, 1, 1, 65536).unwrap());
            let plan = PlannerPlanV2::new(
                nonce,
                vec![PlannerStepV2::new(
                    1,
                    ActionTemplateIdV2::new(23),
                    ToolClassIdV2::new(34),
                    vec![],
                    vec![],
                )
                .unwrap()],
            )
            .unwrap();
            f.commit(ticket, plan).unwrap();
        }
        let mut g7 = test_g7_runtime(installation, manifest, 7, 11);
        g7.executor = g7
            .executor
            .with_socket_path_for_test(vault_dir.path().join("no-executor.sock"));
        f.authority.policy.as_mut().unwrap().install_g7(g7).unwrap();
        let correlation = SignedDurableTaskCorrelationV2::sign(
            UnsignedDurableTaskCorrelationV2::new(
                installation,
                manifest,
                7,
                task,
                agent,
                boot,
                f.authority.config.kerneld_server_boot_id,
                f.authority.config.machine_boot_id,
                UnixMillisV2::new(1),
                UnixMillisV2::new(9000),
                UnixMillisV2::new(10000),
            )
            .unwrap(),
            &f.authority.config.correlation_signing_key,
        )
        .unwrap();
        f.authority.tasks.push(TaskRecordV2 {
            preparation: NewTaskPreparationHandleV2::from_authority_entropy([0x57; 32]).unwrap(),
            agent_task_nonce: Nonce32V2::new([0x58; 32]),
            client_request_nonce: Nonce32V2::new([0x59; 32]),
            durable_task_id: task,
            active_state_manifest_digest: manifest,
            correlation,
            ingress_transfer: KernelIngressBootstrapTransferCapabilityV2::from_authority_entropy(
                [0x60; 32],
            )
            .unwrap(),
            status: PublicTaskStatusV2::Processing,
            expected_principal: Some(principal),
            claim_digest: None,
            durable_run_id: Some(run),
            material: None,
            current_authentication_preparation: None,
            source_input_digest: Some(source),
            task_authorization_digest: Some(root_digest),
        });
        let request = PrepareReleaseRequestV2::new(
            document,
            vec![f.prompt],
            request.executor(),
            request.destination_projection(),
            request.display_projection(),
        )
        .unwrap();
        let prepared = f
            .authority
            .prepare_release(
                &request,
                &f.values,
                &mut data,
                agent,
                manifest,
                7,
                UnixMillisV2::new(200),
            )
            .unwrap();
        let envelope = prepared.envelope().unverified_material().unwrap();
        assert_eq!(
            envelope.task_action_binding().unwrap().content_digest(),
            f.authority.pending_releases[0].task_match.content_digest()
        );
        assert!(envelope
            .display_text()
            .as_str()
            .contains("application-turn:"));
        let key = SigningKey::from_bytes(&[0x9c; 32]);
        let generic = UnsignedApprovalSettlementV2::new(
            installation,
            manifest,
            7,
            ApprovalPurposeV2::FinalRelease,
            prepared.envelope().envelope_digest().unwrap(),
            ApprovalDecisionV2::Approve,
            principal,
            Digest32V2::new([0xd1; 32]),
            Digest32V2::new([0xd2; 32]),
            true,
            true,
            false,
            false,
            2,
            envelope.decision_challenge(),
            Nonce32V2::new([0xd3; 32]),
            UnixMillisV2::new(201),
            UnixMillisV2::new(500),
        )
        .unwrap();
        let old = SignedApprovalSettlementV2::sign(generic, &key).unwrap();
        let consent = |receipt| {
            AuthorizeReleaseRequestV2::new(prepared.pending(), prepared.approval(), receipt)
                .unwrap()
        };
        assert!(f
            .authority
            .authorize_release(
                &consent(old.clone()),
                &mut data,
                agent,
                manifest,
                7,
                UnixMillisV2::new(202)
            )
            .is_err());
        assert!(!f.authority.pending_releases[0].consumed);
        let context = envelope.task_action_context(&generic).unwrap();
        let mut wrong = context.clone();
        wrong.content_digest = Digest32V2::new([0xee; 32]);
        let proof = |context| {
            sign_task_action_approval_v2(
                TaskActionApprovalV2::new(
                    context,
                    TaskActionApprovalDecisionV2::Approve,
                    generic.issued_at(),
                    generic.expires_at(),
                )
                .unwrap(),
                &key,
            )
            .unwrap()
        };
        assert!(f
            .authority
            .authorize_release(
                &consent(old.clone().with_task_action_approval(proof(wrong)).unwrap()),
                &mut data,
                agent,
                manifest,
                7,
                UnixMillisV2::new(202)
            )
            .is_err());
        assert!(!f.authority.pending_releases[0].consumed);
        let authorized = f
            .authority
            .authorize_release(
                &consent(old.with_task_action_approval(proof(context)).unwrap()),
                &mut data,
                agent,
                manifest,
                7,
                UnixMillisV2::new(203),
            )
            .unwrap();
        assert!(f.authority.pending_releases[0].consumed);
        assert!(f.authority.pending_releases[0]
            .task_action_approval
            .is_some());
        let expected_messages = match mode {
            0 => 2,
            1 | 5 | 6 | 7 => 5,
            _ => 3,
        };
        #[cfg(feature = "test-support")]
        let (executor_service, observations) = if mode == 0 {
            (None, None)
        } else {
            use savana_execd::intent_bound_test_support::{service, ProviderReply};
            let executor_root = vault_dir.path().join("executor");
            fs::create_dir(&executor_root).unwrap();
            fs::set_permissions(&executor_root, fs::Permissions::from_mode(0o700)).unwrap();
            let reply = match mode {
                3 => ProviderReply::Failure,
                4 => ProviderReply::Unknown,
                _ => ProviderReply::Success,
            };
            let (service, observations) = service(
                &executor_root,
                installation,
                manifest,
                7,
                11,
                mode == 2,
                reply,
            );
            (Some(service), Some(observations))
        };
        let server = f
            .authority
            .policy
            .as_ref()
            .unwrap()
            .g7
            .as_ref()
            .unwrap()
            .executor
            .fixture_server(
                SigningKey::from_bytes(&[0xb0; 32]),
                expected_messages,
                move |request| {
                    let role = EndpointRoleV2::KernelExecutor;
                    let tag = request.operation().tag();
                    #[cfg(feature = "test-support")]
                    if let Some(service) = &executor_service {
                        let KernelServiceOperationV2::Executor(operation) = request.operation()
                        else {
                            panic!("executor operation required")
                        };
                        let result = service.execute(
                            operation.clone(),
                            UnixMillisV2::new(205),
                            std::time::Instant::now() + std::time::Duration::from_secs(5),
                        );
                        let bytes = result.unwrap_or_else(|e| {
                            panic!("real executor operation {tag}, mode {mode}: {e:?}")
                        });
                        if mode == 6 && tag == 60 {
                            service.restart();
                        }
                        return if ((mode == 5 || mode == 6) && tag == 60)
                            || (mode == 7 && tag == 62)
                        {
                            KernelServiceApplicationResponseV2::error(
                                role,
                                request.request_id(),
                                tag,
                                PublicStableCodeV2::ServiceUnavailable,
                            )
                            .unwrap()
                        } else {
                            KernelServiceApplicationResponseV2::success(
                                role,
                                request.request_id(),
                                tag,
                                bytes,
                            )
                            .unwrap()
                        };
                    }
                    if tag == 64 {
                        KernelServiceApplicationResponseV2::success(
                            role,
                            request.request_id(),
                            tag,
                            encode_connector_registry_sync_response_v2(
                                &ConnectorRegistrySyncResponseV2::new(
                                    ConnectorRegistrySyncStatusV2::DisabledGenesisOnly,
                                    0,
                                    Digest32V2::new([0xbf; 32]),
                                )
                                .unwrap(),
                            )
                            .unwrap(),
                        )
                        .unwrap()
                    } else {
                        assert_eq!(tag, 60);
                        KernelServiceApplicationResponseV2::error(
                            role,
                            request.request_id(),
                            tag,
                            PublicStableCodeV2::ServiceUnavailable,
                        )
                        .unwrap()
                    }
                },
            );
        let dispatch = DispatchReleaseRequestV2::new(authorized.ticket());
        assert!(f
            .authority
            .dispatch_release(
                RequestIdV2::new([0x61; 16]),
                dispatch.clone(),
                &mut data,
                agent,
                manifest,
                7,
                11,
                UnixMillisV2::new(204)
            )
            .is_err());
        assert_eq!(
            f.authority
                .policy
                .as_ref()
                .unwrap()
                .durable
                .task_authorization_state(task)
                .unwrap()
                .clause_consumption(1),
            Some((0, 0)),
            "missing final-release declassification rule must refuse before atomic prepare"
        );
        let destination = f.authority.pending_releases[0]
            .task_match
            .content()
            .action()
            .destination_digest();
        f.authority.policy.as_mut().unwrap().declassification_rules =
            planner_declassification_rules_with_handoffs(true, None, Some(destination));
        let dispatched = f.authority.dispatch_release(
            RequestIdV2::new([0x62; 16]),
            dispatch.clone(),
            &mut data,
            agent,
            manifest,
            7,
            11,
            UnixMillisV2::new(205),
        );
        assert_eq!(
            dispatched.is_err(),
            mode == 0 || mode == 5 || mode == 6,
            "mode {mode}: {dispatched:?}"
        );
        assert_eq!(f.authority.policy.as_ref().unwrap().durable.task_authorization_state(task).unwrap().clause_consumption(1), Some((1, 1)), "the real G7 path must atomically charge once before the unavailable test executor; this is not provider success: {dispatched:?}");
        assert_eq!(
            f.authority.releases.len(),
            1,
            "uncertain transport must retain a queryable release identity"
        );
        let retry = f
            .authority
            .dispatch_release(
                RequestIdV2::new([0x63; 16]),
                dispatch,
                &mut data,
                agent,
                manifest,
                7,
                11,
                UnixMillisV2::new(206),
            )
            .unwrap();
        assert_eq!(retry.release(), f.authority.releases[0].release);
        assert_eq!(
            f.authority
                .policy
                .as_ref()
                .unwrap()
                .durable
                .task_authorization_state(task)
                .unwrap()
                .clause_consumption(1),
            Some((1, 1))
        );
        if mode != 0 {
            let status = f.authority.release_status(
                RequestIdV2::new([0x64; 16]),
                GetReleaseStatusRequestV2::new(ReleaseStatusTargetV2::Release(retry.release())),
                &mut data,
                agent,
                UnixMillisV2::new(207),
            );
            let status = if mode == 7 {
                assert!(status.is_err());
                f.authority
                    .release_status(
                        RequestIdV2::new([0x65; 16]),
                        GetReleaseStatusRequestV2::new(ReleaseStatusTargetV2::Release(
                            retry.release(),
                        )),
                        &mut data,
                        agent,
                        UnixMillisV2::new(208),
                    )
                    .unwrap()
            } else {
                status.unwrap()
            };
            match mode {
                1 | 5 | 6 | 7 => assert!(matches!(
                    status.status(),
                    PublicExecutionStatusV2::Succeeded { .. }
                )),
                2 => assert!(matches!(
                    status.status(),
                    PublicExecutionStatusV2::FailedNoEffect { .. }
                )),
                _ => assert_eq!(status.status(), PublicExecutionStatusV2::Indeterminate),
            }
            #[cfg(feature = "test-support")]
            assert_eq!(
                observations.as_ref().unwrap().requests().len(),
                if mode == 2 { 0 } else { 1 },
                "actual provider emissions, mode {mode}"
            );
        }
        let transmitted = server.join().unwrap();
        assert_eq!(transmitted.len(), expected_messages);
        let KernelServiceOperationV2::Executor(KernelExecutorOperationV2::Dispatch(sent)) =
            transmitted[1].operation()
        else {
            panic!("expected actual sealed dispatch");
        };
        let key = SigningKey::from_bytes(&[0xc0; 32]);
        let sealed = sent
            .envelope()
            .verify(
                derive_ed25519_key_id_v2(key.verifying_key().to_bytes()),
                key.verifying_key().to_bytes(),
                installation,
                manifest,
                7,
                11,
                request.executor(),
                Some(UnixMillisV2::new(205)),
            )
            .unwrap();
        let recipient = StaticSecret::from([0xbc; 32]);
        let public = X25519PublicKey::from(&recipient).to_bytes();
        let shared = recipient
            .diffie_hellman(&X25519PublicKey::from(*sealed.hpke_enc().as_bytes()))
            .to_bytes();
        let mut info = b"SAVANA_EXECUTION_HPKE_X25519_CHACHA20POLY1305_V2\0".to_vec();
        info.extend_from_slice(sealed.hpke_enc().as_bytes());
        info.extend_from_slice(&public);
        let mut key_nonce = [0; 44];
        Hkdf::<Sha256>::new(Some(sealed.dispatch_core_digest().as_bytes()), &shared)
            .expand(&info, &mut key_nonce)
            .unwrap();
        let plaintext = ChaCha20Poly1305::new_from_slice(&key_nonce[..32])
            .unwrap()
            .decrypt(
                Nonce::from_slice(&key_nonce[32..]),
                Payload {
                    msg: sealed.hpke_ciphertext(),
                    aad: sealed.dispatch_core_digest().as_bytes(),
                },
            )
            .unwrap();
        let capsule = decode_task_execution_payload_v2(&plaintext).unwrap();
        capsule.check_core(&sealed.core()).unwrap();
        let delivered =
            decode_final_release_delivery_v2(&capsule.request().canonical_json()).unwrap();
        assert_eq!(delivered.payload(), b"actual vault bytes");
        assert_eq!(delivered.turn_binding(), Digest32V2::new([4; 32]));
    }

    fn business_proposal_fixture(
        resource: &str,
        destination: &str,
    ) -> (PlannerAuthorityFixtureV2, ProposeToolCallRequestV2) {
        business_proposal_fixture_with_dependencies(resource, destination, false)
    }

    fn business_proposal_fixture_with_dependencies(
        resource: &str,
        destination: &str,
        dependent: bool,
    ) -> (PlannerAuthorityFixtureV2, ProposeToolCallRequestV2) {
        business_proposal_fixture_with_chain(resource, destination, dependent, false)
    }

    fn business_proposal_fixture_with_chain(
        resource: &str,
        destination: &str,
        dependent: bool,
        three_steps: bool,
    ) -> (PlannerAuthorityFixtureV2, ProposeToolCallRequestV2) {
        business_proposal_fixture_with_result_release(
            resource,
            destination,
            dependent,
            three_steps,
            false,
        )
    }
    fn business_proposal_fixture_with_result_release(
        resource: &str,
        destination: &str,
        dependent: bool,
        three_steps: bool,
        release: bool,
    ) -> (PlannerAuthorityFixtureV2, ProposeToolCallRequestV2) {
        use savana_kernel_protocol::v2::{BusinessControlsV2, BusinessValueV2};
        let mut f = planner_authority_fixture_with_task(true, false);
        if release {
            f.authority.policy.as_mut().unwrap().active_tools =
                planner_active_tools_with_release_mode(true, true);
        }
        let s = &f.authority.sessions[0];
        let active = f
            .authority
            .policy
            .as_ref()
            .unwrap()
            .active_tools
            .resolve_class(ToolClassIdV2::new(31), s.role, UnixMillisV2::new(100))
            .unwrap();
        let descriptor = active.descriptor().descriptor_digest();
        let profile = active
            .descriptor()
            .unsigned()
            .require_business_profile()
            .unwrap();
        let destinations = if three_steps {
            vec![("A", "Alice"), ("B", "Bob"), ("C", "Carol")]
        } else {
            vec![("A", "Alice"), ("B", "Bob")]
        };
        let alternatives: Vec<_> = destinations
            .iter()
            .map(|(file, to)| {
                savana_kernel_protocol::v2::TaskAuthorizationDraftAlternativeV2::new(
                    descriptor,
                    BusinessControlsV2::from_fields(
                        profile,
                        vec![
                            ("file".into(), BusinessValueV2::Text((*file).into())),
                            ("to".into(), BusinessValueV2::Text((*to).into())),
                        ],
                    )
                    .unwrap(),
                )
                .unwrap()
            })
            .collect();
        let (input, input_session, source) =
            crate::v2_input_owner::tests::finalized_input_for_authority_fixture(
                s.durable_task_id,
                f.authority.config.installation_id,
                s.principal,
                s.active_state_manifest_digest,
                b"send the reports",
            );
        let mut clauses = if dependent {
            alternatives
                .into_iter()
                .enumerate()
                .map(|(index, alternative)| {
                    savana_kernel_protocol::v2::TaskAuthorizationDraftClauseV2::new(
                        index as u64 + 1,
                        vec![alternative],
                        1,
                        1,
                        1,
                        if index > 0 {
                            vec![index as u64]
                        } else {
                            vec![]
                        },
                        false,
                    )
                    .unwrap()
                })
                .collect::<Vec<_>>()
        } else {
            vec![
                savana_kernel_protocol::v2::TaskAuthorizationDraftClauseV2::new(
                    1,
                    alternatives,
                    1,
                    2,
                    2,
                    vec![],
                    false,
                )
                .unwrap(),
            ]
        };
        if release {
            use savana_kernel_protocol::v2::*;
            let r = f
                .authority
                .policy
                .as_ref()
                .unwrap()
                .active_tools
                .resolve_class(ToolClassIdV2::new(34), s.role, UnixMillisV2::new(100))
                .unwrap()
                .descriptor();
            let resource =
                fused_final_result_resource_v04(s.durable_task_id, 2, descriptor).unwrap();
            let controls = BusinessControlsV2::from_fields(
                r.unsigned().business_profile().unwrap(),
                vec![
                    (
                        "resource".into(),
                        BusinessValueV2::Text(format!(
                            "result:{}",
                            resource
                                .as_bytes()
                                .iter()
                                .map(|b| format!("{b:02x}"))
                                .collect::<String>()
                        )),
                    ),
                    (
                        "destination".into(),
                        BusinessValueV2::Text(format!("application-turn:{}", "04".repeat(32))),
                    ),
                ],
            )
            .unwrap();
            clauses.push(
                TaskAuthorizationDraftClauseV2::new(
                    3,
                    vec![
                        TaskAuthorizationDraftAlternativeV2::new(r.descriptor_digest(), controls)
                            .unwrap(),
                    ],
                    1,
                    1,
                    1,
                    vec![1, 2],
                    false,
                )
                .unwrap(),
            );
        }
        let draft = savana_kernel_protocol::v2::TaskAuthorizationDraftV2::new(
            Digest32V2::new([0x38; 32]),
            s.principal,
            s.durable_task_id,
            1,
            f.authority.config.installation_id,
            s.active_state_manifest_digest,
            7,
            UnixMillisV2::new(1),
            UnixMillisV2::new(10000),
            source,
            clauses,
        )
        .unwrap();
        let key = SigningKey::from_bytes(&[0x39; 32]);
        let issuer = crate::v2_task_authority::KernelTaskAuthorizationIssuerV2::new(
            f.authority.config.installation_id,
            key.clone(),
            derive_ed25519_key_id_v2(key.verifying_key().to_bytes()),
            key.verifying_key().to_bytes(),
            SigningKey::from_bytes(&[0x9b; 32])
                .verifying_key()
                .to_bytes(),
            SigningKey::from_bytes(&[0x9c; 32])
                .verifying_key()
                .to_bytes(),
            &[],
        )
        .unwrap();
        let proof = input
            .authenticate_task_draft_submission(
                input_session,
                &draft,
                s.active_state_manifest_digest,
                7,
                UnixMillisV2::new(100),
            )
            .unwrap();
        let p = f.authority.policy.as_mut().unwrap();
        issuer
            .prepare(
                &mut p.durable,
                &p.active_tools,
                s.role,
                &proof,
                draft,
                Digest32V2::new([0x36; 32]),
                UnixMillisV2::new(100),
            )
            .unwrap();
        let root = issuer
            .issue_structured(
                &mut p.durable,
                &p.active_tools,
                s.role,
                &proof,
                Digest32V2::new([0x36; 32]),
                UnixMillisV2::new(100),
            )
            .unwrap();
        f.authority.sessions[0].task_authorization_digest = Some(root);
        f.authority.sessions[0].signed_planner_policy = SignedPlannerPolicyV2::from_verified_input(
            planner_input_runtime_with_arguments(3)
                .process(
                    InputChannelV2::ChatText,
                    "send the reports",
                    UnixMillisV2::new(100),
                )
                .unwrap()
                .planner_envelope(),
        )
        .unwrap();
        let proposal = replan_business_proposal(&mut f, resource, destination, 200);
        (f, proposal)
    }

    fn replan_business_proposal(
        f: &mut PlannerAuthorityFixtureV2,
        resource: &str,
        destination: &str,
        now: u64,
    ) -> ProposeToolCallRequestV2 {
        let s = &f.authority.sessions[0];
        let descriptor = f
            .authority
            .policy
            .as_ref()
            .unwrap()
            .active_tools
            .resolve_class(ToolClassIdV2::new(31), s.role, UnixMillisV2::new(now))
            .unwrap()
            .descriptor()
            .descriptor_digest();
        let context = ProvenanceContextV2::from_authenticated_runtime(
            s.producer_identity,
            s.durable_run_id,
            s.active_state_manifest_digest,
            UnixMillisV2::new(now),
            s.expires_at,
        )
        .unwrap();
        let mut inputs = Vec::new();
        for (name, text) in [
            ("body", "private payload"),
            ("file", resource),
            ("to", destination),
        ] {
            let value = KernelValueV2::text(text).unwrap();
            let provenance = ProvenanceRecordV2::planner_output(
                &value,
                context,
                Digest32V2::new([0x86; 32]),
                Digest32V2::new([0x87; 32]),
                Digest32V2::new([0x88; 32]),
                &[],
                EffectSetV2::SEND,
            )
            .unwrap();
            let handle = f
                .values
                .register_verified_value(f.run, value, provenance)
                .unwrap()
                .handle();
            inputs.push((name, handle));
        }
        let prepared = f
            .authority
            .prepare_planner_call(
                &PreparePlannerCallRequestV2::new(
                    f.run,
                    PlannerRouteIdV2::new(7),
                    StaticTemplateIdV2::new(11),
                    PlannerIntentKindV2::SendMessage,
                    PlannerPurposeV2::PlannerCall,
                    PlannerLimitsV2::new(1, 1, 3, 65536).unwrap(),
                    inputs.iter().map(|(_, h)| *h).collect(),
                )
                .unwrap(),
                &f.values,
                f.caller_identity,
                UnixMillisV2::new(now),
            )
            .unwrap();
        let record = f.authority.planner_tickets.last().unwrap();
        let bindings = inputs
            .iter()
            .map(|(name, value)| {
                (
                    ArgumentNameV2::new((*name).into()).unwrap(),
                    record
                        .slot_bindings
                        .iter()
                        .find(|b| b.value == *value)
                        .unwrap()
                        .slot
                        .reference(),
                )
            })
            .collect();
        let plan = PlannerPlanV2::new(
            record.envelope_nonce,
            vec![PlannerStepV2::new(
                1,
                ActionTemplateIdV2::new(21),
                ToolClassIdV2::new(31),
                bindings,
                vec![],
            )
            .unwrap()],
        )
        .unwrap();
        let committed = f
            .authority
            .commit_planner_value(
                &CommitPlannerValueRequestV2::new(f.run, prepared.ticket(), plan),
                &mut f.values,
                f.caller_identity,
                UnixMillisV2::new(now + 1),
            )
            .unwrap();
        let tool = ToolHandleV2::from_authority_entropy([0xc1; 32]).unwrap();
        f.authority.tools.push(ToolRecordV2 {
            commitment: tool.authority_commitment(&f.authority.handle_key),
            run: f.run,
            descriptor_digest: descriptor,
        });
        let proposal = ProposeToolCallRequestV2::new(
            committed.steps()[0],
            tool,
            inputs
                .into_iter()
                .map(|(name, h)| {
                    NamedArgumentValueBindingV2::new(ArgumentNameV2::new(name.into()).unwrap(), h)
                })
                .collect(),
        )
        .unwrap();
        proposal
    }

    #[test]
    fn real_tool_proposal_rejects_cross_pair_before_creating_durable_intent() {
        let (mut allowed, request) = business_proposal_fixture("A", "Alice");
        assert!(
            allowed
                .authority
                .propose_tool_call(
                    RequestIdV2::new([0xc2; 16]),
                    b"authenticated allowed proposal",
                    &request,
                    &allowed.values,
                    allowed.caller_identity,
                    Digest32V2::new([0x85; 32]),
                    7,
                    UnixMillisV2::new(202),
                )
                .is_ok(),
            "exact authorized tuple must reach a durable proposed intent"
        );
        let (mut f, proposal) = business_proposal_fixture("A", "Bob");
        let before = f
            .authority
            .policy
            .as_ref()
            .unwrap()
            .durable
            .authenticated_state_head()
            .unwrap();
        assert!(f
            .authority
            .propose_tool_call(
                RequestIdV2::new([0xc2; 16]),
                b"authenticated cross-pair proposal",
                &proposal,
                &f.values,
                f.caller_identity,
                Digest32V2::new([0x85; 32]),
                7,
                UnixMillisV2::new(202)
            )
            .is_err());
        assert_eq!(
            f.authority
                .policy
                .as_ref()
                .unwrap()
                .durable
                .authenticated_state_head()
                .unwrap(),
            before
        );
        assert!(f.authority.intents.is_empty());
    }

    #[test]
    fn real_tool_proposal_replays_exact_content_and_preserves_untrusted_control_origin() {
        let (mut f, request) = business_proposal_fixture("A", "Alice");
        let first = f
            .authority
            .propose_tool_call(
                RequestIdV2::new([0xc2; 16]),
                b"first authenticated proposal",
                &request,
                &f.values,
                f.caller_identity,
                Digest32V2::new([0x85; 32]),
                7,
                UnixMillisV2::new(202),
            )
            .unwrap();
        let head = f
            .authority
            .policy
            .as_ref()
            .unwrap()
            .durable
            .authenticated_state_head()
            .unwrap();
        let repeated = f
            .authority
            .propose_tool_call(
                RequestIdV2::new([0xc3; 16]),
                b"first authenticated proposal",
                &request,
                &f.values,
                f.caller_identity,
                Digest32V2::new([0x85; 32]),
                7,
                UnixMillisV2::new(202),
            )
            .unwrap();
        assert_eq!(first, repeated);
        assert_eq!(f.authority.intents.len(), 1);
        // The G4 request-id alias itself may be journaled; task counters must not change.
        assert!(
            f.authority
                .policy
                .as_ref()
                .unwrap()
                .durable
                .authenticated_state_head()
                .unwrap()
                .sequence()
                >= head.sequence()
        );
        let intent = &f.authority.intents[0];
        assert_eq!(
            savana_kernel_protocol::v2::decode_task_execution_payload_v2(
                &intent.dispatch_plaintext
            )
            .unwrap()
            .request()
            .canonical_json(),
            intent.business_request.canonical_json()
        );
        assert_eq!(intent.business_request.resource(), "A");
        assert_eq!(intent.business_request.destination(), "Alice");
        assert_eq!(intent.task_match.candidates().candidate_count(), 2);
        let provenance = f.authority.plan_steps[0].proposer_parent;
        for (selection, facet) in intent
            .control_selections
            .iter()
            .zip(savana_policy_core::v2::ControlFacetV2::ALL)
        {
            assert_eq!(selection.facet(), facet);
            assert_eq!(selection.proposer_parent(), provenance);
            assert_eq!(
                selection.content_digest(),
                intent.task_match.content_digest()
            );
            assert_eq!(
                selection.integrity(),
                savana_policy_core::v2::IntegrityV2::ExternalUntrusted
            );
            assert_eq!(selection.allowed_effects(), EffectSetV2::READ);
        }
        let state = f
            .authority
            .policy
            .as_ref()
            .unwrap()
            .durable
            .task_authorization_state(intent.durable_task_id)
            .unwrap();
        assert_eq!(state.clause_consumption(1), Some((0, 0)));
    }

    #[test]
    fn real_tool_proposal_rejects_revoked_task_and_post_commit_slot_swap() {
        for revoke in [false, true] {
            let (mut f, request) = business_proposal_fixture("A", "Alice");
            let request = if revoke {
                let task = f.authority.plan_steps[0].durable_task_id;
                f.authority
                    .policy
                    .as_mut()
                    .unwrap()
                    .durable
                    .revoke_task_authorization(task)
                    .unwrap();
                request
            } else {
                let arguments = request.arguments();
                ProposeToolCallRequestV2::new(
                    request.step(),
                    request.tool(),
                    vec![
                        NamedArgumentValueBindingV2::new(
                            arguments[0].name().clone(),
                            arguments[0].value(),
                        ),
                        NamedArgumentValueBindingV2::new(
                            arguments[1].name().clone(),
                            arguments[2].value(),
                        ),
                        NamedArgumentValueBindingV2::new(
                            arguments[2].name().clone(),
                            arguments[1].value(),
                        ),
                    ],
                )
                .unwrap()
            };
            let before = f
                .authority
                .policy
                .as_ref()
                .unwrap()
                .durable
                .authenticated_state_head()
                .unwrap();
            assert!(f
                .authority
                .propose_tool_call(
                    RequestIdV2::new([0xc2; 16]),
                    b"invalid proposal",
                    &request,
                    &f.values,
                    f.caller_identity,
                    Digest32V2::new([0x85; 32]),
                    7,
                    UnixMillisV2::new(202),
                )
                .is_err());
            assert_eq!(
                f.authority
                    .policy
                    .as_ref()
                    .unwrap()
                    .durable
                    .authenticated_state_head()
                    .unwrap(),
                before
            );
            assert!(f.authority.intents.is_empty());
        }
    }

    #[test]
    fn real_tool_proposal_cached_evaluation_cannot_survive_generation_change_or_revocation() {
        let (mut f, request) = business_proposal_fixture("A", "Alice");
        let proposed = f
            .authority
            .propose_tool_call(
                RequestIdV2::new([0xc2; 16]),
                b"authenticated proposal",
                &request,
                &f.values,
                f.caller_identity,
                Digest32V2::new([0x85; 32]),
                7,
                UnixMillisV2::new(202),
            )
            .unwrap();
        let ActionIntentCurrentStateV2::Proposed { pending } = proposed.current() else {
            panic!("proposed")
        };
        let allowed = f
            .authority
            .evaluate_tool_call(
                EvaluateToolCallRequestV2::new(pending),
                &f.values,
                f.caller_identity,
                Digest32V2::new([0x85; 32]),
                7,
                UnixMillisV2::new(203),
            )
            .unwrap();
        assert!(matches!(
            allowed,
            EvaluateToolCallResponseV2::Allowed { .. }
        ));
        let before = f
            .authority
            .policy
            .as_ref()
            .unwrap()
            .durable
            .authenticated_state_head()
            .unwrap();
        assert!(f
            .authority
            .evaluate_tool_call(
                EvaluateToolCallRequestV2::new(pending),
                &f.values,
                f.caller_identity,
                Digest32V2::new([0x85; 32]),
                8,
                UnixMillisV2::new(204)
            )
            .is_err());
        assert_eq!(
            f.authority
                .policy
                .as_ref()
                .unwrap()
                .durable
                .authenticated_state_head()
                .unwrap(),
            before
        );
        let task = f.authority.intents[0].durable_task_id;
        f.authority
            .policy
            .as_mut()
            .unwrap()
            .durable
            .revoke_task_authorization(task)
            .unwrap();
        assert!(f
            .authority
            .evaluate_tool_call(
                EvaluateToolCallRequestV2::new(pending),
                &f.values,
                f.caller_identity,
                Digest32V2::new([0x85; 32]),
                7,
                UnixMillisV2::new(205)
            )
            .is_err());
        assert!(f
            .authority
            .policy
            .as_ref()
            .unwrap()
            .durable
            .recovery_projection()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn real_tool_approval_requires_exact_content_proof_before_consumption_and_endorsement() {
        use savana_kernel_protocol::v2::{
            sign_task_action_approval_v2, ApprovalDecisionV2, AuthorizeToolCallRequestV2,
            SignedApprovalSettlementV2, TaskActionApprovalDecisionV2, TaskActionApprovalV2,
            UnsignedApprovalSettlementV2,
        };
        let (mut f, request) = business_proposal_fixture("A", "Alice");
        f.authority.policy.as_mut().unwrap().disposition =
            VerifiedPolicyDispositionV2::require_approval_from_verified_policy();
        let manifest = Digest32V2::new([0x85; 32]);
        let proposed = f
            .authority
            .propose_tool_call(
                RequestIdV2::new([0xc2; 16]),
                b"exact approved proposal",
                &request,
                &f.values,
                f.caller_identity,
                manifest,
                7,
                UnixMillisV2::new(202),
            )
            .unwrap();
        let ActionIntentCurrentStateV2::Proposed { pending } = proposed.current() else {
            panic!("proposed")
        };
        let evaluated = f
            .authority
            .evaluate_tool_call(
                EvaluateToolCallRequestV2::new(pending),
                &f.values,
                f.caller_identity,
                manifest,
                7,
                UnixMillisV2::new(203),
            )
            .unwrap();
        let EvaluateToolCallResponseV2::NeedsApproval {
            approval, envelope, ..
        } = evaluated
        else {
            panic!("approval required")
        };
        let material = envelope.unverified_material().unwrap();
        assert!(
            material
                .display_text()
                .as_str()
                .contains("\"resource\":\"A\""),
            "approval must name the actual owned resource, not encode opaque binary"
        );
        assert!(material
            .display_text()
            .as_str()
            .contains("\"destination\":\"Alice\""));
        assert!(material
            .display_text()
            .as_str()
            .contains("\"approval_kind\":\"One action; does not amend task authorization\""));
        assert_eq!(
            material.task_action_binding().unwrap().content_digest(),
            f.authority.intents[0].task_match.content_digest()
        );
        let key = SigningKey::from_bytes(&[0x9c; 32]);
        let generic = UnsignedApprovalSettlementV2::new(
            f.authority.config.installation_id,
            manifest,
            7,
            ApprovalPurposeV2::ToolExecution,
            envelope.envelope_digest().unwrap(),
            ApprovalDecisionV2::Approve,
            material.expected_principal(),
            Digest32V2::new([0xd1; 32]),
            Digest32V2::new([0xd2; 32]),
            true,
            true,
            false,
            false,
            2,
            material.decision_challenge(),
            Nonce32V2::new([0xd3; 32]),
            UnixMillisV2::new(204),
            UnixMillisV2::new(500),
        )
        .unwrap();
        let old = SignedApprovalSettlementV2::sign(generic, &key).unwrap();
        let old_request = AuthorizeToolCallRequestV2::new(pending, approval, old.clone()).unwrap();
        assert!(f
            .authority
            .authorize_tool_call(
                &old_request,
                f.caller_identity,
                manifest,
                7,
                UnixMillisV2::new(205)
            )
            .is_err());
        assert!(!f.authority.tool_approvals[0].consumed);
        let context = material.task_action_context(&generic).unwrap();
        let mut wrong = context.clone();
        wrong.content_digest = Digest32V2::new([0xee; 32]);
        let forged_other_action = sign_task_action_approval_v2(
            TaskActionApprovalV2::new(
                wrong,
                TaskActionApprovalDecisionV2::Approve,
                generic.issued_at(),
                generic.expires_at(),
            )
            .unwrap(),
            &key,
        )
        .unwrap();
        let wrong_request = AuthorizeToolCallRequestV2::new(
            pending,
            approval,
            old.clone()
                .with_task_action_approval(forged_other_action)
                .unwrap(),
        )
        .unwrap();
        assert!(f
            .authority
            .authorize_tool_call(
                &wrong_request,
                f.caller_identity,
                manifest,
                7,
                UnixMillisV2::new(205)
            )
            .is_err());
        assert!(!f.authority.tool_approvals[0].consumed);
        let proof = sign_task_action_approval_v2(
            TaskActionApprovalV2::new(
                context.clone(),
                TaskActionApprovalDecisionV2::Approve,
                generic.issued_at(),
                generic.expires_at(),
            )
            .unwrap(),
            &key,
        )
        .unwrap();
        let correct = AuthorizeToolCallRequestV2::new(
            pending,
            approval,
            old.with_task_action_approval(proof).unwrap(),
        )
        .unwrap();
        let ticket = f
            .authority
            .authorize_tool_call(
                &correct,
                f.caller_identity,
                manifest,
                7,
                UnixMillisV2::new(205),
            )
            .unwrap();
        assert_eq!(
            ticket,
            f.authority
                .authorize_tool_call(
                    &correct,
                    f.caller_identity,
                    manifest,
                    7,
                    UnixMillisV2::new(206)
                )
                .unwrap()
        );
        assert!(f.authority.tool_approvals[0].consumed);
        let intent = &f.authority.intents[0];
        let verified = intent.task_action_approval.as_ref().unwrap();
        let state = f
            .authority
            .policy
            .as_ref()
            .unwrap()
            .durable
            .task_authorization_state(intent.durable_task_id)
            .unwrap();
        let current = savana_policy_core::v2::TaskMatchContextV2 {
            current_authorization: Some(state.authorization()),
            pre_state_digest: state.digest(),
            pre_state_revision: state.revision(),
            deployment_generation: 7,
            now: UnixMillisV2::new(206),
        };
        let endorsements = savana_policy_core::v2::checked_control_endorsements_v2(
            &intent.task_match,
            &intent.control_selections,
            savana_policy_core::v2::ControlEvidenceV2::ActionApproval {
                approval: verified,
                expected_context: &context,
            },
            &current,
        )
        .unwrap();
        assert!(endorsements
            .iter()
            .all(|e| e.settlement_digest() == Some(verified.digest())
                && e.settlement_nonce() == Some(context.settlement_nonce)));
        let stale = savana_policy_core::v2::TaskMatchContextV2 {
            now: UnixMillisV2::new(500),
            ..current
        };
        assert!(savana_policy_core::v2::checked_control_endorsements_v2(
            &intent.task_match,
            &intent.control_selections,
            savana_policy_core::v2::ControlEvidenceV2::ActionApproval {
                approval: verified,
                expected_context: &context
            },
            &stale
        )
        .is_err());
    }

    #[test]
    fn rejected_execution_gate_leaves_real_durable_dispatch_and_quota_unmodified() {
        let installation_id = Digest32V2::new([0x89; 32]);
        let active_state_manifest_digest = Digest32V2::new([0x85; 32]);
        let deployment_generation = 7;
        let effect_fence_epoch = 8;
        let durable_run_id = DurableRunIdV2::new([0x83; 32]);
        let quota_subject = DispatchQuotaSubjectV2::tool_attempt(AttemptKindV2::ToolWrite);
        let (mut fixture, proposal) = business_proposal_fixture("A", "Alice");
        fixture
            .authority
            .policy
            .as_mut()
            .unwrap()
            .install_g7(test_g7_runtime(
                installation_id,
                active_state_manifest_digest,
                deployment_generation,
                effect_fence_epoch,
            ))
            .unwrap();

        let proposed = fixture
            .authority
            .propose_tool_call(
                RequestIdV2::new([0xc2; 16]),
                b"authenticated canonical tool proposal",
                &proposal,
                &fixture.values,
                fixture.caller_identity,
                active_state_manifest_digest,
                deployment_generation,
                UnixMillisV2::new(202),
            )
            .unwrap();
        let ActionIntentCurrentStateV2::Proposed { pending } = proposed.current() else {
            panic!("real authority must create a proposed durable intent");
        };
        let evaluated = fixture
            .authority
            .evaluate_tool_call(
                EvaluateToolCallRequestV2::new(pending),
                &fixture.values,
                fixture.caller_identity,
                active_state_manifest_digest,
                deployment_generation,
                UnixMillisV2::new(203),
            )
            .unwrap();
        let EvaluateToolCallResponseV2::Allowed { ticket, .. } = evaluated else {
            panic!("verified permit policy must authorize the real intent");
        };

        let durable_path = fixture._directory.path().join("kernel-g4-state-v2.cbor");
        let (head_before, journal_before, quota_before) = {
            let durable = &fixture.authority.policy.as_ref().unwrap().durable;
            (
                durable.authenticated_state_head().unwrap(),
                durable.recovery_projection().unwrap(),
                durable.quota_counter(durable_run_id, quota_subject),
            )
        };
        let durable_bytes_before = fs::read(&durable_path).unwrap();
        let executions_before = fixture.authority.executions.len();
        assert!(matches!(
            fixture.authority.intents[0].state,
            IntentRecordStateV2::Authorized
        ));
        assert!(journal_before.is_empty());
        assert_eq!(quota_before, Err(G4Error::QuotaCounterNotFound));

        assert_eq!(
            fixture.authority.dispatch_execution(
                RequestIdV2::new([0xc3; 16]),
                DispatchExecutionRequestV2::new(ticket),
                fixture.caller_identity,
                Digest32V2::new([0x86; 32]),
                deployment_generation,
                effect_fence_epoch,
                UnixMillisV2::new(204),
            ),
            Err(KernelAgentAuthorityErrorV2::BindingMismatch)
        );
        assert_eq!(
            fixture
                .authority
                .execution_declassification_gate_test_observation,
            None,
            "an earlier binding refusal must not impersonate the declassification gate"
        );

        assert_eq!(
            fixture.authority.dispatch_execution(
                RequestIdV2::new([0xc4; 16]),
                DispatchExecutionRequestV2::new(ticket),
                fixture.caller_identity,
                active_state_manifest_digest,
                deployment_generation,
                effect_fence_epoch,
                UnixMillisV2::new(205),
            ),
            Err(KernelAgentAuthorityErrorV2::BindingMismatch)
        );
        assert_eq!(
            fixture
                .authority
                .execution_declassification_gate_test_observation,
            Some(
                ExecutionDeclassificationGateTestObservationV2::ProvenanceDeclassificationRefused
            ),
            "the generic public refusal must come from the real execution-handoff declassification gate"
        );

        fixture
            .authority
            .policy
            .as_mut()
            .unwrap()
            .declassification_rules = planner_declassification_rules_with_handoffs(
            false,
            Some(Digest32V2::new([0xa7; 32])),
            None,
        );
        assert_eq!(
            fixture.authority.dispatch_execution(
                RequestIdV2::new([0xc5; 16]),
                DispatchExecutionRequestV2::new(ticket),
                fixture.caller_identity,
                active_state_manifest_digest,
                deployment_generation,
                effect_fence_epoch,
                UnixMillisV2::new(206),
            ),
            Err(KernelAgentAuthorityErrorV2::Expired),
            "after declassification succeeds, sync must fail before durable prepare"
        );
        assert_eq!(
            fixture
                .authority
                .execution_declassification_gate_test_observation,
            None,
            "a registry-sync refusal must not impersonate the earlier declassification gate"
        );

        let (head_after, journal_after, quota_after) = {
            let durable = &fixture.authority.policy.as_ref().unwrap().durable;
            (
                durable.authenticated_state_head().unwrap(),
                durable.recovery_projection().unwrap(),
                durable.quota_counter(durable_run_id, quota_subject),
            )
        };
        assert_eq!(head_after, head_before);
        assert_eq!(journal_after, journal_before);
        assert_eq!(quota_after, quota_before);
        assert_eq!(fs::read(&durable_path).unwrap(), durable_bytes_before);
        assert_eq!(fixture.authority.executions.len(), executions_before);
        assert!(matches!(
            fixture.authority.intents[0].state,
            IntentRecordStateV2::Authorized
        ));
    }

    #[test]
    #[cfg(feature = "test-support")]
    fn native_tool_dispatch_requires_registered_exact_profile_and_query_identity() {
        for case in 0..=8 {
            native_tool_dispatch_fixture(case);
        }
    }

    #[cfg(feature = "test-support")]
    fn native_tool_dispatch_fixture(case: u8) {
        use savana_execd::intent_bound_test_support::{
            deployment_connector, deployment_connector_named, service_with_connectors,
            ProviderReply,
        };
        use savana_kernel_protocol::v2::{
            ExecutionStatusTargetV2, GetExecutionStatusRequestV2,
            KernelServiceApplicationResponseV2, KernelServiceOperationV2, PublicExecutionStatusV2,
            PublicStableCodeV2,
        };
        let (mut f, proposal) =
            business_proposal_fixture_with_dependencies("A", "Alice", case == 7);
        let installation = f.authority.config.installation_id;
        let manifest = f.authority.sessions[0].active_state_manifest_digest;
        let task = f.authority.sessions[0].durable_task_id;
        let active = f
            .authority
            .policy
            .as_ref()
            .unwrap()
            .active_tools
            .resolve_class(
                ToolClassIdV2::new(31),
                RoleIdV2::new(1),
                UnixMillisV2::new(200),
            )
            .unwrap();
        let connector = deployment_connector(vec![active.descriptor().unsigned().clone()]);
        assert_eq!(connector.connector_id(), test_tool_connector_identity());
        let renamed =
            deployment_connector_named(vec![active.descriptor().unsigned().clone()], "renamed");
        let denied_route = matches!(case, 1 | 5 | 6);
        let connectors = match case {
            1 => vec![],
            5 => vec![renamed],
            6 => vec![connector, renamed],
            _ => vec![connector],
        };
        let expected_messages = if case == 7 {
            11
        } else if denied_route {
            1
        } else if matches!(case, 2 | 3) {
            3
        } else {
            5
        };
        let mut g7 = test_g7_runtime(installation, manifest, 7, 8);
        g7.connector_registry = SharedVerifiedConnectorRegistryV2::from_verified_state(
            ConnectorRegistryStateV2::from_verified_genesis(
                Digest32V2::new([0xbf; 32]),
                [0; 32],
                vec![],
                connectors.clone(),
            )
            .unwrap(),
        )
        .unwrap();
        g7.executor = g7
            .executor
            .with_socket_path_for_test(f._directory.path().join("executor.sock"));
        f.authority.policy.as_mut().unwrap().install_g7(g7).unwrap();
        f.authority.policy.as_mut().unwrap().declassification_rules =
            planner_declassification_rules_with_handoffs(
                false,
                Some(Digest32V2::new([0xa7; 32])),
                None,
            );
        let executor_root = f._directory.path().join("executor");
        fs::create_dir(&executor_root).unwrap();
        fs::set_permissions(&executor_root, fs::Permissions::from_mode(0o700)).unwrap();
        let (service, observed) = service_with_connectors(
            &executor_root,
            installation,
            manifest,
            7,
            8,
            case == 2,
            if case == 3 {
                ProviderReply::Failure
            } else {
                ProviderReply::Success
            },
            connectors,
        );
        let server = f
            .authority
            .policy
            .as_ref()
            .unwrap()
            .g7
            .as_ref()
            .unwrap()
            .executor
            .fixture_server(
                SigningKey::from_bytes(&[0xb0; 32]),
                expected_messages,
                move |request| {
                    let KernelServiceOperationV2::Executor(operation) = request.operation() else {
                        panic!("executor operation")
                    };
                    let bytes = service
                        .execute(
                            operation.clone(),
                            UnixMillisV2::new(205),
                            std::time::Instant::now() + std::time::Duration::from_secs(5),
                        )
                        .unwrap();
                    if (case == 4 && request.operation().tag() == 60)
                        || (case == 8 && request.operation().tag() == 62)
                    {
                        service.restart();
                        return KernelServiceApplicationResponseV2::error(
                            EndpointRoleV2::KernelExecutor,
                            request.request_id(),
                            request.operation().tag(),
                            PublicStableCodeV2::ServiceUnavailable,
                        )
                        .unwrap();
                    }
                    KernelServiceApplicationResponseV2::success(
                        EndpointRoleV2::KernelExecutor,
                        request.request_id(),
                        request.operation().tag(),
                        bytes,
                    )
                    .unwrap()
                },
            );
        let proposal = if case == 7 {
            let premature = replan_business_proposal(&mut f, "B", "Bob", 200);
            assert!(dispatch_fixture_proposal(&mut f, &premature, 0xd0).is_err());
            assert!(
                observed.requests().is_empty(),
                "uncompleted predecessor cannot send"
            );
            assert_eq!(
                f.authority
                    .policy
                    .as_ref()
                    .unwrap()
                    .durable
                    .task_authorization_state(task)
                    .unwrap()
                    .clause_consumption(2),
                Some((0, 0))
            );
            replan_business_proposal(&mut f, "A", "Alice", 200)
        } else {
            proposal
        };
        let proposed = f
            .authority
            .propose_tool_call(
                RequestIdV2::new([0xc2; 16]),
                b"actual tool proposal",
                &proposal,
                &f.values,
                f.caller_identity,
                manifest,
                7,
                UnixMillisV2::new(202),
            )
            .unwrap();
        let ActionIntentCurrentStateV2::Proposed { pending } = proposed.current() else {
            panic!("pending")
        };
        let evaluated = f
            .authority
            .evaluate_tool_call(
                EvaluateToolCallRequestV2::new(pending),
                &f.values,
                f.caller_identity,
                manifest,
                7,
                UnixMillisV2::new(203),
            )
            .unwrap();
        let EvaluateToolCallResponseV2::Allowed { ticket, .. } = evaluated else {
            panic!("allowed")
        };
        let dispatched = f.authority.dispatch_execution(
            RequestIdV2::new([0xc3; 16]),
            DispatchExecutionRequestV2::new(ticket),
            f.caller_identity,
            manifest,
            7,
            8,
            UnixMillisV2::new(205),
        );
        if denied_route {
            assert!(dispatched.is_err());
            assert_eq!(
                f.authority
                    .policy
                    .as_ref()
                    .unwrap()
                    .durable
                    .task_authorization_state(task)
                    .unwrap()
                    .clause_consumption(1),
                Some((0, 0))
            );
            assert!(f.authority.executions.is_empty());
            assert_eq!(server.join().unwrap().len(), 1);
            assert!(observed.requests().is_empty());
            return;
        }
        assert_eq!(
            dispatched.is_err(),
            case == 4,
            "case {case}: {dispatched:?}"
        );
        let retried = f
            .authority
            .dispatch_execution(
                RequestIdV2::new([0xc4; 16]),
                DispatchExecutionRequestV2::new(ticket),
                f.caller_identity,
                manifest,
                7,
                8,
                UnixMillisV2::new(206),
            )
            .unwrap();
        if let Ok(dispatched) = dispatched {
            assert_eq!(dispatched, retried);
        }
        assert_eq!(
            f.authority
                .policy
                .as_ref()
                .unwrap()
                .durable
                .task_authorization_state(task)
                .unwrap()
                .clause_consumption(1),
            Some((1, 1))
        );
        let mut data = tool_result_data_fixture(&f);
        let status = f.authority.execution_status(
            RequestIdV2::new([0xc5; 16]),
            GetExecutionStatusRequestV2::new(ExecutionStatusTargetV2::Execution(
                retried.execution(),
            )),
            &mut data,
            f.caller_identity,
            manifest,
            7,
            8,
            UnixMillisV2::new(207),
        );
        let status = if case == 8 {
            assert!(status.is_err(), "the acknowledgement is deliberately lost");
            f.authority
                .execution_status(
                    RequestIdV2::new([0xc6; 16]),
                    GetExecutionStatusRequestV2::new(ExecutionStatusTargetV2::Execution(
                        retried.execution(),
                    )),
                    &mut data,
                    f.caller_identity,
                    manifest,
                    7,
                    8,
                    UnixMillisV2::new(208),
                )
                .unwrap()
        } else {
            status.unwrap()
        };
        match case {
            2 => assert!(matches!(
                status.status(),
                PublicExecutionStatusV2::FailedNoEffect { .. }
            )),
            3 => assert_eq!(status.status(), PublicExecutionStatusV2::Indeterminate),
            _ => assert!(
                matches!(status.status(), PublicExecutionStatusV2::Succeeded { .. }),
                "case {case}: {:?}",
                status.status()
            ),
        }
        if case == 7 {
            // The next plan is created only after the first verified result.
            // Authority and counters remain on the same durable task.
            let second = replan_business_proposal(&mut f, "B", "Bob", 208);
            let executed = dispatch_fixture_proposal(&mut f, &second, 0xd4).unwrap();
            let result = f
                .authority
                .execution_status(
                    RequestIdV2::new([0xd7; 16]),
                    GetExecutionStatusRequestV2::new(ExecutionStatusTargetV2::Execution(
                        executed.execution(),
                    )),
                    &mut data,
                    f.caller_identity,
                    manifest,
                    7,
                    8,
                    UnixMillisV2::new(215),
                )
                .unwrap();
            assert!(matches!(
                result.status(),
                PublicExecutionStatusV2::Succeeded { .. }
            ));
            let exhausted = replan_business_proposal(&mut f, "B", "Bob", 216);
            assert!(dispatch_fixture_proposal(&mut f, &exhausted, 0xd8).is_err());
            let state = f
                .authority
                .policy
                .as_ref()
                .unwrap()
                .durable
                .task_authorization_state(task)
                .unwrap();
            assert_eq!(state.clause_consumption(1), Some((1, 1)));
            assert_eq!(state.clause_consumption(2), Some((1, 1)));
        }
        let transmitted = server.join().unwrap();
        assert_eq!(transmitted.len(), expected_messages);
        assert_eq!(
            observed.requests().len(),
            if case == 2 {
                0
            } else if case == 7 {
                2
            } else {
                1
            },
            "registered exact task-bound tool must reach provider once"
        );
    }

    #[cfg(feature = "test-support")]
    fn dispatch_fixture_proposal(
        f: &mut PlannerAuthorityFixtureV2,
        proposal: &ProposeToolCallRequestV2,
        request_seed: u8,
    ) -> Result<savana_kernel_protocol::v2::DispatchExecutionResponseV2, KernelAgentAuthorityErrorV2>
    {
        let manifest = f.authority.sessions[0].active_state_manifest_digest;
        let proposed = f.authority.propose_tool_call(
            RequestIdV2::new([request_seed; 16]),
            &[request_seed],
            proposal,
            &f.values,
            f.caller_identity,
            manifest,
            7,
            UnixMillisV2::new(220),
        )?;
        let ActionIntentCurrentStateV2::Proposed { pending } = proposed.current() else {
            panic!("pending");
        };
        let evaluated = f.authority.evaluate_tool_call(
            EvaluateToolCallRequestV2::new(pending),
            &f.values,
            f.caller_identity,
            manifest,
            7,
            UnixMillisV2::new(221),
        )?;
        let EvaluateToolCallResponseV2::Allowed { ticket, .. } = evaluated else {
            panic!("allowed");
        };
        f.authority.dispatch_execution(
            RequestIdV2::new([request_seed + 1; 16]),
            DispatchExecutionRequestV2::new(ticket),
            f.caller_identity,
            manifest,
            7,
            8,
            UnixMillisV2::new(222),
        )
    }

    #[cfg(feature = "test-support")]
    fn tool_result_data_fixture(
        f: &PlannerAuthorityFixtureV2,
    ) -> crate::v2_data_plane::ProductionKernelDataPlaneV2 {
        #[derive(Default)]
        struct Anchor(savana_vault::VaultStateHeadV2);
        impl savana_vault::VaultRollbackAnchorV2 for Anchor {
            fn current_head(
                &self,
            ) -> Result<savana_vault::VaultStateHeadV2, savana_vault::VaultErrorV2> {
                Ok(self.0)
            }
            fn compare_and_advance(
                &mut self,
                expected: savana_vault::VaultStateHeadV2,
                next: savana_vault::VaultStateHeadV2,
            ) -> Result<(), savana_vault::VaultErrorV2> {
                if self.0 != expected {
                    return Err(savana_vault::VaultErrorV2::RollbackDetected);
                }
                self.0 = next;
                Ok(())
            }
        }
        let root = f._directory.path().join("result-vault");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let s = &f.authority.sessions[0];
        let c = &f.authority.config;
        let vault = savana_vault::DurableVaultServiceV2::open(
            &root.join("vault-state-v2.cbor"),
            [0x53; 32],
            savana_vault::DurableVaultNamespaceV2::from_verified_installation(
                c.installation_id,
                Digest32V2::new([0x54; 32]),
            )
            .unwrap(),
            Box::<Anchor>::default(),
            savana_vault::VaultServiceV2::from_verified_deployment(
                c.installation_id,
                s.active_state_manifest_digest,
                c.agentd_kernel_client_boot_id,
                10,
            )
            .unwrap(),
        )
        .unwrap();
        crate::v2_data_plane::ProductionKernelDataPlaneV2::new(
            planner_input_runtime(),
            vault,
            planner_declassification_rules(true),
            c.installation_id,
            s.producer_identity,
            c.agentd_kernel_client_boot_id,
            f.caller_identity,
            Digest32V2::new([0x52; 32]),
            EffectSetV2::ALL,
            10000,
        )
        .unwrap()
    }

    #[test]
    fn final_release_sync_refusal_precedes_real_durable_prepare_and_quota_reservation() {
        let installation = Digest32V2::new([0xd1; 32]);
        let manifest = Digest32V2::new([0xd2; 32]);
        let run = DurableRunIdV2::new([0xd3; 32]);
        let release_id = DurableReleaseIdV2::new([0xd4; 32]);
        let executor = ExecutorIdentityV2::new([0xd5; 32]);
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.path().join("kernel-g4-state-v2.cbor");
        let mut durable = DurableG4StateV2::open(
            &path,
            [0xd6; 32],
            DurableStateNamespaceV2::from_verified_installation(
                installation,
                Digest32V2::new([0xd7; 32]),
            )
            .unwrap(),
            Box::new(TestG4StateAnchorV2::default()),
        )
        .unwrap();
        let binding = FinalReleaseSemanticBindingV2::from_nonzero_components(
            release_id,
            Digest32V2::new([0xd8; 32]),
            Digest32V2::new([0xd9; 32]),
            Digest32V2::new([0xda; 32]),
            Digest32V2::new([0xdb; 32]),
            Digest32V2::new([0xdc; 32]),
            Digest32V2::new([0xdd; 32]),
            Digest32V2::new([0xde; 32]),
            Digest32V2::new([0xdf; 32]),
            Digest32V2::new(*executor.as_bytes()),
            Digest32V2::new([0xe0; 32]),
        )
        .unwrap();
        let release = VerifiedFinalReleaseRecordV2::from_authorized_vault_release(
            installation,
            manifest,
            DurableTaskIdV2::new([0xe1; 32]),
            run,
            release_id,
            binding,
        )
        .unwrap();
        let settlement = VerifiedFinalReleaseSettlementV2::from_consumed_exact_settlement(
            Digest32V2::new([0xe2; 32]),
            release_id,
            binding.semantic_digest().unwrap(),
            binding.destination_digest(),
            binding.token_set_digest(),
            manifest,
            UnixMillisV2::new(10),
            UnixMillisV2::new(100),
        )
        .unwrap();
        let quota_subject =
            DispatchQuotaSubjectV2::final_release(binding.release_quota_subject_digest());
        let quota = VerifiedQuotaLimitV2::from_verified_policy(
            1,
            Digest32V2::new([0xe3; 32]),
            quota_subject,
        )
        .unwrap();
        let registry = SharedVerifiedConnectorRegistryV2::from_verified_state(
            ConnectorRegistryStateV2::from_verified_genesis(
                Digest32V2::new([0xe4; 32]),
                [0; 32],
                vec![],
                vec![],
            )
            .unwrap(),
        )
        .unwrap();
        let effect_lease = VerifiedEffectGateLeaseV2::from_authenticated_ledger(
            installation,
            manifest,
            7,
            9,
            false,
            executor,
            HpkeX25519KeyIdV2::new([0xe5; 32]),
            &registry,
            UnixMillisV2::new(10_000),
        )
        .unwrap();
        let resolved_ticket = ResolvedFinalReleaseTicketV2::from_resolved_kernel_ticket(
            Digest32V2::new([0xe6; 32]),
            release_id,
            binding.semantic_digest().unwrap(),
        )
        .unwrap();
        let value = KernelValueV2::bytes(b"authorized release".to_vec()).unwrap();
        let provenance = ProvenanceRecordV2::from_verified_kernel_input(
            &value,
            ProvenanceContextV2::from_authenticated_runtime(
                ProducerIdentityV2::new([0xe7; 32]),
                run,
                manifest,
                UnixMillisV2::new(20),
                UnixMillisV2::new(1_000),
            )
            .unwrap(),
            Digest32V2::new([0xe8; 32]),
            Digest32V2::new([0xe9; 32]),
            Digest32V2::new([0xea; 32]),
            Digest32V2::new([0xeb; 32]),
            EffectSetV2::FINAL_RELEASE,
        )
        .unwrap();
        let head_before = durable.authenticated_state_head().unwrap();
        let journal_before = durable.recovery_projection().unwrap();
        let quota_before = durable.quota_counter(run, quota_subject);
        let bytes_before = fs::read(&path).ok();
        let declassification_finished = Cell::new(false);
        let synchronization_attempted = Cell::new(false);
        let durable_prepare_called = Cell::new(false);

        let result = gate_final_release_before_durable_prepare(
            b"authorized release",
            || {
                declassification_finished.set(true);
                Ok(provenance)
            },
            || {
                assert!(declassification_finished.get());
                synchronization_attempted.set(true);
                Err(KernelAgentAuthorityErrorV2::StateConflict)
            },
            |sealed_payload_digest| {
                durable_prepare_called.set(true);
                durable
                    .prepare_verified_final_release_dispatch(
                        &release,
                        quota,
                        &settlement,
                        resolved_ticket,
                        effect_lease,
                        sealed_payload_digest,
                    )
                    .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)
            },
        );
        assert!(matches!(
            result,
            Err(KernelAgentAuthorityErrorV2::StateConflict)
        ));
        assert!(declassification_finished.get());
        assert!(synchronization_attempted.get());
        assert!(!durable_prepare_called.get());
        assert_eq!(durable.authenticated_state_head().unwrap(), head_before);
        assert_eq!(durable.recovery_projection().unwrap(), journal_before);
        assert_eq!(durable.quota_counter(run, quota_subject), quota_before);
        assert_eq!(fs::read(path).ok(), bytes_before);
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
                planner_declassification_rules(true),
                EffectSetV2::SEND,
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
                planner_declassification_rules(true),
                EffectSetV2::SEND,
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
                planner_declassification_rules(true),
                EffectSetV2::SEND,
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
