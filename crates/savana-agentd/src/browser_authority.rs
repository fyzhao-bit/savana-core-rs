use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use savana_approvald::{ApprovalSuiteOneClientErrorV2, ApprovalSuiteOneClientV2};
use savana_kernel_protocol::v2::{
    ActionIntentCurrentStateV2, ActiveToolViewV2, AgentApprovalRecordTargetV2,
    AgentBrowserActionV2, AgentBrowserExecutionStateV2, AgentBrowserMutationResponseV2,
    AgentBrowserObjectRefV2, AgentBrowserReadViewResponseV2, AgentBrowserReleaseStateV2,
    AgentBrowserRequestV2, AgentBrowserViewCursorCapabilityV2, AgentExecutionRefV2,
    AgentExecutionTicketRefV2, AgentMaskedDocumentRefV2, AgentPendingConnectorRegistrationRefV2,
    AgentPendingToolCallRefV2, AgentPlanStepRefV2, AgentReleaseRefV2, AgentReleaseTicketRefV2,
    AgentSessionHandleV2, AgentTabSessionCapabilityV2, AgentUiAuthenticationPreparationHandleV2,
    AgentUiAuthenticationSettlementTransferCapabilityV2, AgentUiAuthenticationTransferCapabilityV2,
    AgentUiAuthorizationHandleV2, ApplyApprovedConnectorRegistrationRequestV2,
    ApplyApprovedConnectorRegistrationResponseV2, ApprovalSettlementViewV2,
    ApprovalUiRecordHandleV2, AuthorizeConnectorRegistrationRequestV2,
    AuthorizeConnectorRegistrationResponseV2, AuthorizeReleaseRequestV2,
    AuthorizeToolCallRequestV2, BootIdV2, CloseAgentSessionRequestV2, CommitPlannerValueRequestV2,
    CommitPlannerValueResponseV2, ConnectorApprovalRecordHandleV2,
    ConnectorRegistrySnapshotRequestV2, Digest32V2, DispatchExecutionRequestV2,
    DispatchReleaseRequestV2, DisplayProjectionIdV2, EvaluateToolCallRequestV2,
    EvaluateToolCallResponseV2, ExecutionHandleV2, ExecutionStatusTargetV2,
    ExecutionTicketHandleV2, ExecutorIdentityV2, FixedBrowserFormPostCarrierV2, FixedOriginV2,
    GetExecutionStatusRequestV2, GetReleaseStatusRequestV2, KernelAgentOperationV2,
    KernelAgentViewCursorV2, MaskedDocumentHandleV2, NamedArgumentValueBindingV2, Nonce32V2,
    PendingConnectorRegistrationHandleV2, PendingReleaseHandleV2, PendingToolCallHandleV2,
    PlanStepHandleV2, PlannerIntentKindV2, PlannerLimitsV2, PlannerPlanV2, PlannerPurposeV2,
    PlannerRouteIdV2, PlannerTicketHandleV2, PrepareConnectorRegistrationRequestV2,
    PrepareConnectorRemovalRequestV2, PrepareConnectorRemovalResponseV2,
    PrepareFollowupIngressRequestV2, PreparePlannerCallRequestV2, PreparePlannerCallResponseV2,
    PrepareReleaseRequestV2, ProjectionIdV2, ProposeConnectorRegistrationRequestV2,
    ProposeToolCallRequestV2, PublicDispatchCompletionV2, PublicExecutionStatusV2,
    PublicStableCodeV2, RegisteredApprovalV2, RegisteredUiAuthenticationV2,
    ReleaseApprovalRecordHandleV2, ReleaseHandleV2, ReleaseKernelApprovalHandleV2,
    ReleaseStatusTargetV2, ReleaseTicketHandleV2, RemoveConnectorRequestV2,
    RemoveConnectorResponseV2, RequestIdV2, ResumeCommittedAgentAuthenticationResponseV2,
    RunHandleV2, SignedDurableTaskCorrelationV2, SignedUiAuthenticationSettlementV2,
    StaticTemplateIdV2, ToolApprovalRecordHandleV2, ToolHandleV2, ToolKernelApprovalHandleV2,
    UnixMillisV2, ValueHandleV2,
};
use zeroize::Zeroizing;

use crate::{
    effect_gate::{EffectGateCoordinatorV2, EffectGateErrorV2, EffectGateOperationKindV2},
    planner_privacy::{
        decode_ordered_plan_v2, IntentTrustBoundaryV2, MappedWorkflowV2, MapperCatalogToolV2,
        MapperIntentRequestV2, OrderedStructuralPlanV2, StructuralNodeIdIssuerV2,
        StructuralPlannerRequestV2,
    },
    AgentControlKernelClientErrorV2, AgentMapperClientErrorV2, AgentPlannerClientErrorV2,
    DurablePlannerCatalogV2, PinnedMtlsAgentMapperClientV2, PinnedMtlsAgentPlannerClientV2,
    PlannerCatalogEntryV2, SuiteOneAgentKernelClientV2,
};

const MAX_AUTHENTICATIONS_V2: usize = 4096;
const MAX_TABS_V2: usize = 4096;
const MAX_COMPLETIONS_V2: usize = 4096;
const MAX_REPLAYS_PER_TAB_V2: usize = 256;
const MAX_CURSORS_PER_TAB_V2: usize = 256;
const MAX_OBJECTS_PER_TAB_V2: usize = 4096;
const MAX_PENDING_CONNECTOR_DESCRIPTOR_BYTES_PER_TAB_V2: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AgentBrowserAuthorityErrorV2 {
    #[error("agent browser reference is invalid")]
    InvalidReference,
    #[error("agent browser request conflicts with prior state")]
    StateConflict,
    #[error("agent browser authority is overloaded")]
    Overloaded,
    #[error("agent browser authority is unavailable")]
    Unavailable,
}

#[derive(Debug, Clone)]
struct ActiveAuthenticationV2 {
    correlation_digest: Digest32V2,
    request_nonce: Nonce32V2,
    record: ApprovalUiRecordHandleV2,
    preparation: AgentUiAuthenticationPreparationHandleV2,
    initial_transfer: AgentUiAuthenticationTransferCapabilityV2,
    settlement: Option<SignedUiAuthenticationSettlementV2>,
}

#[derive(Debug, Clone, Copy)]
struct CompletedAuthenticationV2 {
    transfer: AgentUiAuthenticationSettlementTransferCapabilityV2,
    tab: AgentTabSessionCapabilityV2,
    initial_document: AgentMaskedDocumentRefV2,
}

#[derive(Debug, Clone, Copy)]
struct BrowserCursorV2 {
    reference: AgentBrowserViewCursorCapabilityV2,
    kernel: KernelAgentViewCursorV2,
}

#[derive(Debug, Clone)]
struct ViewReplayV2 {
    request_digest: Digest32V2,
    nonce: Nonce32V2,
    response: AgentBrowserReadViewResponseV2,
}

#[derive(Debug)]
enum BrowserObjectBindingV2 {
    Document {
        reference: AgentMaskedDocumentRefV2,
        kernel: MaskedDocumentHandleV2,
    },
    PlanStep {
        reference: AgentPlanStepRefV2,
        kernel: PlanStepHandleV2,
        tool: ToolHandleV2,
        arguments: Vec<NamedArgumentValueBindingV2>,
    },
    PendingToolCall {
        reference: AgentPendingToolCallRefV2,
        kernel: PendingToolCallHandleV2,
        approval: Option<ToolApprovalStateV2>,
    },
    ExecutionTicket {
        reference: AgentExecutionTicketRefV2,
        kernel: ExecutionTicketHandleV2,
    },
    ReleaseTicket {
        reference: AgentReleaseTicketRefV2,
        kernel: ReleaseTicketHandleV2,
    },
    Execution {
        reference: AgentExecutionRefV2,
        kernel: ExecutionHandleV2,
    },
    Release {
        reference: AgentReleaseRefV2,
        kernel: ReleaseHandleV2,
    },
}

#[derive(Debug, Clone)]
struct ToolApprovalStateV2 {
    kernel: ToolKernelApprovalHandleV2,
    approvald: ToolApprovalRecordHandleV2,
    trace: savana_kernel_protocol::v2::PublicDecisionTraceV2,
    transfer: savana_kernel_protocol::v2::ApprovalDisplayAuthenticationTransferCapabilityV2,
}

#[derive(Debug, Clone)]
struct PendingReleaseApprovalV2 {
    pending: PendingReleaseHandleV2,
    kernel: ReleaseKernelApprovalHandleV2,
    approvald: ReleaseApprovalRecordHandleV2,
}

#[derive(Clone)]
struct PendingConnectorRegistrationV2 {
    reference: AgentPendingConnectorRegistrationRefV2,
    kernel: PendingConnectorRegistrationHandleV2,
    approvald: ConnectorApprovalRecordHandleV2,
    transfer: savana_kernel_protocol::v2::ApprovalDisplayAuthenticationTransferCapabilityV2,
    canonical_descriptor: Arc<Zeroizing<Vec<u8>>>,
}

impl core::fmt::Debug for PendingConnectorRegistrationV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PendingConnectorRegistrationV2")
            .field("reference", &self.reference)
            .field("kernel", &self.kernel)
            .field("approvald", &self.approvald)
            .field("transfer", &self.transfer)
            .field("canonical_descriptor", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone)]
struct ActionReplayV2 {
    request_digest: Digest32V2,
    nonce: Nonce32V2,
    response: Option<AgentBrowserMutationResponseV2>,
}

#[derive(Debug)]
struct AgentTabV2 {
    tab: AgentTabSessionCapabilityV2,
    authorization: Option<AgentUiAuthorizationHandleV2>,
    initial_document: AgentMaskedDocumentRefV2,
    kernel_document: Option<MaskedDocumentHandleV2>,
    session: Option<AgentSessionHandleV2>,
    run: Option<RunHandleV2>,
    initial_value: Option<ValueHandleV2>,
    active_tools: Vec<ActiveToolViewV2>,
    reference_key: Zeroizing<[u8; 32]>,
    tab_internal_id: Digest32V2,
    agentd_boot_id: BootIdV2,
    origin: FixedOriginV2,
    next_reference_revision: u64,
    objects: Vec<BrowserObjectBindingV2>,
    pending_releases: Vec<PendingReleaseApprovalV2>,
    pending_connectors: Vec<PendingConnectorRegistrationV2>,
    cursors: Vec<BrowserCursorV2>,
    replays: Vec<ViewReplayV2>,
    action_replays: Vec<ActionReplayV2>,
}

#[derive(Default)]
struct AuthorityStateV2 {
    authentications: Vec<ActiveAuthenticationV2>,
    completions: Vec<CompletedAuthenticationV2>,
    tabs: Vec<AgentTabV2>,
}

pub struct PrivatePlanningResultV2 {
    committed: CommitPlannerValueResponseV2,
    plan: PlannerPlanV2,
}

impl PrivatePlanningResultV2 {
    pub const fn committed(&self) -> &CommitPlannerValueResponseV2 {
        &self.committed
    }

    pub const fn plan(&self) -> &PlannerPlanV2 {
        &self.plan
    }
}

#[allow(clippy::too_many_arguments)]
pub fn execute_private_planning_pipeline_v2<Guard, Prepare, ProjectCatalog, Map, Plan, Commit>(
    _effect_guard: Guard,
    run: RunHandleV2,
    active_tools: &[ActiveToolViewV2],
    issuer: &Mutex<StructuralNodeIdIssuerV2>,
    boundary: IntentTrustBoundaryV2,
    prepare: Prepare,
    project_catalog: ProjectCatalog,
    map: Map,
    plan: Plan,
    commit: Commit,
) -> Result<PrivatePlanningResultV2, AgentBrowserAuthorityErrorV2>
where
    Prepare: FnOnce() -> Result<PreparePlannerCallResponseV2, AgentBrowserAuthorityErrorV2>,
    ProjectCatalog: FnOnce(
        &[ActiveToolViewV2],
    ) -> Result<Vec<PlannerCatalogEntryV2>, AgentBrowserAuthorityErrorV2>,
    Map: FnOnce(
        &MapperIntentRequestV2,
        IntentTrustBoundaryV2,
    ) -> Result<MappedWorkflowV2, AgentBrowserAuthorityErrorV2>,
    Plan: FnOnce(
        &StructuralPlannerRequestV2,
    ) -> Result<OrderedStructuralPlanV2, AgentBrowserAuthorityErrorV2>,
    Commit: FnOnce(
        CommitPlannerValueRequestV2,
    ) -> Result<CommitPlannerValueResponseV2, AgentBrowserAuthorityErrorV2>,
{
    let prepared = prepare()?;
    let projected = project_catalog(active_tools)?;
    let mapper_tools = projected
        .iter()
        .map(MapperCatalogToolV2::from_catalog_entry)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| AgentBrowserAuthorityErrorV2::InvalidReference)?;
    let mapper_request =
        MapperIntentRequestV2::new(prepared.envelope(), active_tools, mapper_tools)
            .map_err(|_| AgentBrowserAuthorityErrorV2::InvalidReference)?;
    let mapped = map(&mapper_request, boundary)?;
    let (structural_request, decode_table) = {
        let mut issuer = issuer
            .lock()
            .map_err(|_| AgentBrowserAuthorityErrorV2::Unavailable)?;
        mapped
            .relabel(&mut issuer)
            .map_err(|_| AgentBrowserAuthorityErrorV2::Unavailable)?
    };
    let ordered = plan(&structural_request)?;
    let decoded = decode_ordered_plan_v2(prepared.envelope(), &decode_table, &ordered)
        .map_err(|_| AgentBrowserAuthorityErrorV2::InvalidReference)?;
    let committed = commit(planner_commit_value_request_v2(
        run,
        prepared.ticket(),
        decoded.clone(),
    ))?;
    Ok(PrivatePlanningResultV2 {
        committed,
        plan: decoded,
    })
}

pub struct AgentBrowserAuthorityV2 {
    effect_gate: EffectGateCoordinatorV2,
    kernel: SuiteOneAgentKernelClientV2,
    approval: ApprovalSuiteOneClientV2,
    mapper: PinnedMtlsAgentMapperClientV2,
    planner: PinnedMtlsAgentPlannerClientV2,
    planner_route: PlannerRouteIdV2,
    planner_template: StaticTemplateIdV2,
    planner_intent: PlannerIntentKindV2,
    planner_limits: PlannerLimitsV2,
    release_executor: ExecutorIdentityV2,
    release_destination_projection: ProjectionIdV2,
    release_display_projection: DisplayProjectionIdV2,
    agentd_boot_id: BootIdV2,
    planner_catalog: Mutex<DurablePlannerCatalogV2>,
    structural_node_id_issuer: Mutex<StructuralNodeIdIssuerV2>,
    state: Mutex<AuthorityStateV2>,
}

impl core::fmt::Debug for AgentBrowserAuthorityV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("AgentBrowserAuthorityV2(<capabilities-redacted>)")
    }
}

impl AgentBrowserAuthorityV2 {
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        effect_gate: EffectGateCoordinatorV2,
        kernel: SuiteOneAgentKernelClientV2,
        approval: ApprovalSuiteOneClientV2,
        mapper: PinnedMtlsAgentMapperClientV2,
        planner: PinnedMtlsAgentPlannerClientV2,
        planner_route: PlannerRouteIdV2,
        planner_template: StaticTemplateIdV2,
        planner_intent: PlannerIntentKindV2,
        planner_limits: PlannerLimitsV2,
        release_executor: ExecutorIdentityV2,
        release_destination_projection: ProjectionIdV2,
        release_display_projection: DisplayProjectionIdV2,
        agentd_boot_id: BootIdV2,
        planner_catalog: DurablePlannerCatalogV2,
        structural_node_id_issuer: StructuralNodeIdIssuerV2,
    ) -> Self {
        Self {
            effect_gate,
            kernel,
            approval,
            mapper,
            planner,
            planner_route,
            planner_template,
            planner_intent,
            planner_limits,
            release_executor,
            release_destination_projection,
            release_display_projection,
            agentd_boot_id,
            planner_catalog: Mutex::new(planner_catalog),
            structural_node_id_issuer: Mutex::new(structural_node_id_issuer),
            state: Mutex::new(AuthorityStateV2::default()),
        }
    }

    pub fn prepare_authentication(
        &self,
        correlation: SignedDurableTaskCorrelationV2,
        client_request_nonce: Nonce32V2,
        deadline: UnixMillisV2,
    ) -> Result<AgentUiAuthenticationTransferCapabilityV2, AgentBrowserAuthorityErrorV2> {
        let correlation_digest = correlation
            .correlation_digest()
            .map_err(|_| AgentBrowserAuthorityErrorV2::InvalidReference)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| AgentBrowserAuthorityErrorV2::Unavailable)?;
        if let Some(existing) = state.authentications.iter().find(|entry| {
            entry.correlation_digest == correlation_digest
                && entry.request_nonce == client_request_nonce
        }) {
            return Ok(existing.initial_transfer);
        }
        if state.authentications.len() >= MAX_AUTHENTICATIONS_V2 {
            return Err(AgentBrowserAuthorityErrorV2::Overloaded);
        }
        state
            .authentications
            .try_reserve(1)
            .map_err(|_| AgentBrowserAuthorityErrorV2::Overloaded)?;

        let first = self
            .kernel
            .resume_committed_agent_authentication(
                correlation.clone(),
                client_request_nonce,
                None,
                deadline,
            )
            .map_err(map_kernel)?;
        let (preparation, envelope) = match first {
            ResumeCommittedAgentAuthenticationResponseV2::Prepared {
                authentication_preparation,
                envelope,
            } => (authentication_preparation, envelope),
            ResumeCommittedAgentAuthenticationResponseV2::ClosureRequired { closure } => {
                let proof = self
                    .approval
                    .close_agent_authentication_attempt(closure, deadline)
                    .map_err(map_approval)?;
                let replacement_nonce = draw_nonce()?;
                match self
                    .kernel
                    .resume_committed_agent_authentication(
                        correlation,
                        replacement_nonce,
                        Some(proof),
                        deadline,
                    )
                    .map_err(map_kernel)?
                {
                    ResumeCommittedAgentAuthenticationResponseV2::Prepared {
                        authentication_preparation,
                        envelope,
                    } => (authentication_preparation, envelope),
                    ResumeCommittedAgentAuthenticationResponseV2::ClosureRequired { .. } => {
                        return Err(AgentBrowserAuthorityErrorV2::StateConflict);
                    }
                }
            }
        };
        let registered = self
            .approval
            .register_ui_authentication(envelope, deadline)
            .map_err(map_approval)?;
        let RegisteredUiAuthenticationV2::Agent { record, transfer } = registered else {
            return Err(AgentBrowserAuthorityErrorV2::Unavailable);
        };
        state.authentications.push(ActiveAuthenticationV2 {
            correlation_digest,
            request_nonce: client_request_nonce,
            record,
            preparation,
            initial_transfer: transfer,
            settlement: None,
        });
        Ok(transfer)
    }

    pub fn complete_authentication(
        &self,
        transfer: AgentUiAuthenticationSettlementTransferCapabilityV2,
        deadline: UnixMillisV2,
    ) -> Result<
        savana_kernel_protocol::v2::AgentUiAuthenticationCompleteBrowserResponseV2,
        AgentBrowserAuthorityErrorV2,
    > {
        let mut state = self
            .state
            .lock()
            .map_err(|_| AgentBrowserAuthorityErrorV2::Unavailable)?;
        if let Some(existing) = state
            .completions
            .iter()
            .find(|entry| entry.transfer == transfer)
        {
            return Ok(
                savana_kernel_protocol::v2::AgentUiAuthenticationCompleteBrowserResponseV2::new(
                    existing.tab,
                    existing.initial_document,
                ),
            );
        }
        if state.tabs.len() >= MAX_TABS_V2 || state.completions.len() >= MAX_COMPLETIONS_V2 {
            return Err(AgentBrowserAuthorityErrorV2::Overloaded);
        }
        state
            .tabs
            .try_reserve(1)
            .and_then(|()| state.completions.try_reserve(1))
            .map_err(|_| AgentBrowserAuthorityErrorV2::Overloaded)?;

        let mut matched = None;
        for index in 0..state.authentications.len() {
            let settlement = match state.authentications[index].settlement.clone() {
                Some(settlement) => settlement,
                None => match self.approval.consume_agent_ui_authentication(
                    state.authentications[index].record,
                    transfer,
                    deadline,
                ) {
                    Ok(consumed) => consumed.settlement().clone(),
                    Err(ApprovalSuiteOneClientErrorV2::Rejected(_)) => continue,
                    Err(error) => return Err(map_approval(error)),
                },
            };
            state.authentications[index].settlement = Some(settlement.clone());
            matched = Some((index, settlement));
            break;
        }
        let (index, settlement) = matched.ok_or(AgentBrowserAuthorityErrorV2::InvalidReference)?;
        let preparation = state.authentications[index].preparation;
        let authorization = self
            .kernel
            .authenticate_agent_ui(preparation, settlement, deadline)
            .map_err(map_kernel)?
            .authorization();
        let tab = AgentTabSessionCapabilityV2::from_authority_entropy(draw_nonzero()?)
            .ok_or(AgentBrowserAuthorityErrorV2::Unavailable)?;
        let initial_document = AgentMaskedDocumentRefV2::from_authority_entropy(draw_nonzero_16()?)
            .ok_or(AgentBrowserAuthorityErrorV2::Unavailable)?;
        state.authentications.swap_remove(index);
        let reference_key = Zeroizing::new(draw_nonzero()?);
        let tab_internal_id = Digest32V2::new(draw_nonzero()?);
        state.tabs.push(AgentTabV2 {
            tab,
            authorization: Some(authorization),
            initial_document,
            kernel_document: None,
            session: None,
            run: None,
            initial_value: None,
            active_tools: Vec::new(),
            reference_key,
            tab_internal_id,
            agentd_boot_id: self.agentd_boot_id,
            origin: FixedOriginV2::Agent8768,
            next_reference_revision: 1,
            objects: Vec::new(),
            pending_releases: Vec::new(),
            pending_connectors: Vec::new(),
            cursors: Vec::new(),
            replays: Vec::new(),
            action_replays: Vec::new(),
        });
        state.completions.push(CompletedAuthenticationV2 {
            transfer,
            tab,
            initial_document,
        });
        Ok(
            savana_kernel_protocol::v2::AgentUiAuthenticationCompleteBrowserResponseV2::new(
                tab,
                initial_document,
            ),
        )
    }

    pub fn read_view(
        &self,
        request: AgentBrowserRequestV2,
        deadline: UnixMillisV2,
    ) -> Result<AgentBrowserReadViewResponseV2, AgentBrowserAuthorityErrorV2> {
        let AgentBrowserRequestV2::ReadView {
            tab,
            client_request_nonce,
            document,
            cursor,
            maximum_encoded_bytes,
        } = request
        else {
            return Err(AgentBrowserAuthorityErrorV2::InvalidReference);
        };
        let request_digest =
            browser_read_request_digest(tab, document, cursor, maximum_encoded_bytes)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| AgentBrowserAuthorityErrorV2::Unavailable)?;
        let tab = find_action_tab(&mut state, tab)?;
        if let Some(existing) = tab
            .replays
            .iter()
            .find(|entry| entry.nonce == client_request_nonce)
        {
            return if existing.request_digest == request_digest {
                Ok(existing.response.clone())
            } else {
                Err(AgentBrowserAuthorityErrorV2::StateConflict)
            };
        }
        if tab.replays.len() >= MAX_REPLAYS_PER_TAB_V2 {
            return Err(AgentBrowserAuthorityErrorV2::Overloaded);
        }
        tab.replays
            .try_reserve(1)
            .map_err(|_| AgentBrowserAuthorityErrorV2::Overloaded)?;
        self.claim_tab(tab, deadline)?;
        self.reconcile_release_approvals(tab, deadline)?;
        if document != tab.initial_document {
            return Err(AgentBrowserAuthorityErrorV2::InvalidReference);
        }
        let kernel_cursor = match cursor {
            Some(cursor) => Some(
                tab.cursors
                    .iter()
                    .find(|candidate| candidate.reference == cursor)
                    .map(|candidate| candidate.kernel)
                    .ok_or(AgentBrowserAuthorityErrorV2::InvalidReference)?,
            ),
            None => None,
        };
        let response = self
            .kernel
            .read_agent_view(
                tab.kernel_document
                    .ok_or(AgentBrowserAuthorityErrorV2::StateConflict)?,
                kernel_cursor,
                maximum_encoded_bytes,
                client_request_nonce,
                deadline,
            )
            .map_err(map_kernel)?;
        let next = match response.next() {
            Some(kernel) => {
                if tab.cursors.len() >= MAX_CURSORS_PER_TAB_V2 {
                    return Err(AgentBrowserAuthorityErrorV2::Overloaded);
                }
                tab.cursors
                    .try_reserve(1)
                    .map_err(|_| AgentBrowserAuthorityErrorV2::Overloaded)?;
                let reference =
                    AgentBrowserViewCursorCapabilityV2::from_authority_entropy(draw_nonzero_16()?)
                        .ok_or(AgentBrowserAuthorityErrorV2::Unavailable)?;
                tab.cursors.push(BrowserCursorV2 { reference, kernel });
                Some(reference)
            }
            None => None,
        };
        let objects = tab
            .objects
            .iter()
            .map(browser_object_projection)
            .collect::<Vec<_>>();
        let public = AgentBrowserReadViewResponseV2::new(response.view().clone(), objects, next)
            .map_err(|_| AgentBrowserAuthorityErrorV2::Unavailable)?;
        tab.replays.push(ViewReplayV2 {
            request_digest,
            nonce: client_request_nonce,
            response: public.clone(),
        });
        Ok(public)
    }

    pub fn act(
        &self,
        request: AgentBrowserRequestV2,
        deadline: UnixMillisV2,
    ) -> Result<AgentBrowserMutationResponseV2, AgentBrowserAuthorityErrorV2> {
        let AgentBrowserRequestV2::Act {
            tab,
            client_request_nonce,
            action,
        } = request
        else {
            return Err(AgentBrowserAuthorityErrorV2::InvalidReference);
        };
        let planner_boundary = match &action {
            AgentBrowserActionV2::RunPlanner
            | AgentBrowserActionV2::RunPlannerWithThirdPartyMapper => {
                Some(planner_intent_boundary_for_action_v2(&action)?)
            }
            _ => None,
        };
        if let Some(boundary) = planner_boundary {
            self.mapper
                .authorize_boundary(boundary)
                .map_err(map_mapper)?;
        }
        let request_digest = browser_action_request_digest(tab, action.clone())?;
        let request_id = browser_kernel_request_id(tab, client_request_nonce, action.clone())?;
        let effect_operation_id =
            browser_effect_operation_id(tab, client_request_nonce, action.clone())?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| AgentBrowserAuthorityErrorV2::Unavailable)?;
        let tab = if connector_action_requires_authenticated_tab(&action) {
            authenticated_connector_tab(&mut state, tab, self.agentd_boot_id)?
        } else {
            find_action_tab(&mut state, tab)?
        };
        execute_action_nonce_bound_v2(tab, client_request_nonce, request_digest, |tab| {
            self.claim_tab(tab, deadline)?;
            let response = match action {
                AgentBrowserActionV2::PrepareFollowupIngress => {
                    let response = self
                        .kernel
                        .prepare_followup_ingress(
                            PrepareFollowupIngressRequestV2::new(
                                required(tab.session)?,
                                required(tab.run)?,
                                client_request_nonce,
                            )
                            .map_err(|_| AgentBrowserAuthorityErrorV2::InvalidReference)?,
                            request_id,
                            deadline,
                        )
                        .map_err(map_kernel)?;
                    AgentBrowserMutationResponseV2::FollowupOpenIngress {
                        post: FixedBrowserFormPostCarrierV2::AgentFollowupIngress(
                            response.input_transfer(),
                        ),
                    }
                }
                AgentBrowserActionV2::RunPlanner
                | AgentBrowserActionV2::RunPlannerWithThirdPartyMapper => {
                    let effect_guard = self
                        .effect_gate
                        .acquire(
                            EffectGateOperationKindV2::PlannerExchange,
                            effect_operation_id,
                            effect_gate_deadline(deadline)?,
                        )
                        .map_err(map_effect_gate)?;
                    let run = required(tab.run)?;
                    let initial_value = required(tab.initial_value)?;
                    let boundary =
                        planner_boundary.ok_or(AgentBrowserAuthorityErrorV2::InvalidReference)?;
                    let pipeline = execute_private_planning_pipeline_v2(
                        effect_guard,
                        run,
                        &tab.active_tools,
                        &self.structural_node_id_issuer,
                        boundary,
                        || {
                            self.kernel
                                .prepare_planner_call(
                                    planner_prepare_call_request_v2(
                                        run,
                                        self.planner_route,
                                        self.planner_template,
                                        self.planner_intent,
                                        self.planner_limits,
                                        initial_value,
                                    )?,
                                    request_id,
                                    deadline,
                                )
                                .map_err(map_kernel)
                        },
                        |active_tools| {
                            self.planner_catalog
                                .lock()
                                .map_err(|_| AgentBrowserAuthorityErrorV2::Unavailable)?
                                .project_active(active_tools)
                                .map_err(|error| match error {
                                    crate::PlannerCatalogErrorV2::Invalid => {
                                        AgentBrowserAuthorityErrorV2::InvalidReference
                                    }
                                    _ => AgentBrowserAuthorityErrorV2::Unavailable,
                                })
                        },
                        |request, selected_boundary| {
                            self.mapper
                                .map(request, selected_boundary, deadline)
                                .map_err(map_mapper)
                        },
                        |request| self.planner.plan(request, deadline).map_err(map_planner),
                        |request| {
                            self.kernel
                                .commit_planner_value(request, request_id, deadline)
                                .map_err(map_kernel)
                        },
                    )?;
                    let committed = pipeline.committed();
                    let plan = pipeline.plan();
                    if committed.steps().len() != plan.steps().len()
                        || tab.objects.len().saturating_add(committed.steps().len())
                            > MAX_OBJECTS_PER_TAB_V2
                    {
                        return Err(AgentBrowserAuthorityErrorV2::StateConflict);
                    }
                    tab.objects
                        .try_reserve(committed.steps().len())
                        .map_err(|_| AgentBrowserAuthorityErrorV2::Overloaded)?;
                    let mut references = Vec::new();
                    references
                        .try_reserve(committed.steps().len())
                        .map_err(|_| AgentBrowserAuthorityErrorV2::Overloaded)?;
                    for (kernel_step, plan_step) in
                        committed.steps().iter().copied().zip(plan.steps())
                    {
                        let tool = tab
                            .active_tools
                            .iter()
                            .copied()
                            .find(|tool| {
                                tool.action_template() == plan_step.action_template()
                                    && tool.tool_class() == plan_step.tool_class()
                            })
                            .ok_or(AgentBrowserAuthorityErrorV2::StateConflict)?
                            .tool();
                        let arguments = plan_step
                            .slot_bindings()
                            .iter()
                            .map(|(name, _)| {
                                NamedArgumentValueBindingV2::new(name.clone(), initial_value)
                            })
                            .collect::<Vec<_>>();
                        let reference = mint_step_reference(tab)?;
                        tab.objects.push(BrowserObjectBindingV2::PlanStep {
                            reference,
                            kernel: kernel_step,
                            tool,
                            arguments,
                        });
                        references.push(reference);
                    }
                    AgentBrowserMutationResponseV2::PlannerCommitted { steps: references }
                }
                AgentBrowserActionV2::ProposePlanStep(reference) => {
                    let (step, tool, arguments) = tab
                        .objects
                        .iter()
                        .find_map(|object| match object {
                            BrowserObjectBindingV2::PlanStep {
                                reference: candidate,
                                kernel,
                                tool,
                                arguments,
                            } if *candidate == reference => {
                                Some((*kernel, *tool, arguments.clone()))
                            }
                            _ => None,
                        })
                        .ok_or(AgentBrowserAuthorityErrorV2::InvalidReference)?;
                    let proposed = self
                        .kernel
                        .propose_tool_call(
                            ProposeToolCallRequestV2::new(step, tool, arguments)
                                .map_err(|_| AgentBrowserAuthorityErrorV2::InvalidReference)?,
                            request_id,
                            deadline,
                        )
                        .map_err(map_kernel)?;
                    let pending = match proposed.current() {
                        ActionIntentCurrentStateV2::Proposed { pending }
                        | ActionIntentCurrentStateV2::Evaluating { pending }
                        | ActionIntentCurrentStateV2::AwaitingApproval { pending } => pending,
                        _ => return Err(AgentBrowserAuthorityErrorV2::StateConflict),
                    };
                    let pending_reference = mint_pending_reference(tab)?;
                    tab.objects.push(BrowserObjectBindingV2::PendingToolCall {
                        reference: pending_reference,
                        kernel: pending,
                        approval: None,
                    });
                    AgentBrowserMutationResponseV2::ToolProposed {
                        pending: pending_reference,
                    }
                }
                AgentBrowserActionV2::EvaluatePending(reference) => {
                    self.evaluate_pending(tab, reference, request_id, deadline)?
                }
                AgentBrowserActionV2::DispatchTicket(reference) => {
                    let _effect_guard = self
                        .effect_gate
                        .acquire(
                            EffectGateOperationKindV2::ExecutionDispatch,
                            effect_operation_id,
                            effect_gate_deadline(deadline)?,
                        )
                        .map_err(map_effect_gate)?;
                    let ticket = find_execution_ticket(tab, reference)?;
                    let dispatched = self
                        .kernel
                        .dispatch_execution(
                            DispatchExecutionRequestV2::new(ticket),
                            request_id,
                            deadline,
                        )
                        .map_err(map_kernel)?;
                    let execution_reference = mint_execution_reference(tab)?;
                    tab.objects.push(BrowserObjectBindingV2::Execution {
                        reference: execution_reference,
                        kernel: dispatched.execution(),
                    });
                    AgentBrowserMutationResponseV2::ExecutionDispatched {
                        execution: execution_reference,
                        state: dispatched.status(),
                    }
                }
                AgentBrowserActionV2::PrepareRelease(document) => {
                    let kernel_document = find_document(tab, document)?;
                    let prepared = self
                        .kernel
                        .prepare_release(
                            PrepareReleaseRequestV2::new(
                                kernel_document,
                                vec![required(tab.initial_value)?],
                                self.release_executor,
                                self.release_destination_projection,
                                self.release_display_projection,
                            )
                            .map_err(|_| AgentBrowserAuthorityErrorV2::InvalidReference)?,
                            request_id,
                            deadline,
                        )
                        .map_err(map_kernel)?;
                    let registered = self
                        .approval
                        .register_approval(
                            prepared.envelope().clone(),
                            prepared.display_authentication().clone(),
                            deadline,
                        )
                        .map_err(map_approval)?;
                    let RegisteredApprovalV2::Release {
                        approval,
                        display_authentication,
                    } = registered
                    else {
                        return Err(AgentBrowserAuthorityErrorV2::StateConflict);
                    };
                    tab.pending_releases.push(PendingReleaseApprovalV2 {
                        pending: prepared.pending(),
                        kernel: prepared.approval(),
                        approvald: approval,
                    });
                    AgentBrowserMutationResponseV2::ReleaseOpenApproval {
                        post: FixedBrowserFormPostCarrierV2::AgentApprovalDisplay(
                            display_authentication,
                        ),
                    }
                }
                AgentBrowserActionV2::DispatchRelease(reference) => {
                    let _effect_guard = self
                        .effect_gate
                        .acquire(
                            EffectGateOperationKindV2::ReleaseDispatch,
                            effect_operation_id,
                            effect_gate_deadline(deadline)?,
                        )
                        .map_err(map_effect_gate)?;
                    let ticket = find_release_ticket(tab, reference)?;
                    let dispatched = self
                        .kernel
                        .dispatch_release(
                            DispatchReleaseRequestV2::new(ticket),
                            request_id,
                            deadline,
                        )
                        .map_err(map_kernel)?;
                    let release_reference = mint_release_reference(tab)?;
                    tab.objects.push(BrowserObjectBindingV2::Release {
                        reference: release_reference,
                        kernel: dispatched.release(),
                    });
                    AgentBrowserMutationResponseV2::ReleaseDispatched {
                        release: release_reference,
                        state: dispatched.status(),
                    }
                }
                AgentBrowserActionV2::RevokeVault(document) => {
                    let response = self
                        .kernel
                        .revoke_vault(
                            savana_kernel_protocol::v2::RevokeVaultRequestV2::new(find_document(
                                tab, document,
                            )?),
                            request_id,
                            deadline,
                        )
                        .map_err(map_kernel)?;
                    AgentBrowserMutationResponseV2::VaultRevoked {
                        state: response.state(),
                    }
                }
                AgentBrowserActionV2::CloseSession => {
                    let response = self
                        .kernel
                        .close_agent_session(
                            CloseAgentSessionRequestV2::new(required(tab.session)?),
                            request_id,
                            deadline,
                        )
                        .map_err(map_kernel)?;
                    AgentBrowserMutationResponseV2::SessionClosed {
                        state: response.state(),
                    }
                }
                AgentBrowserActionV2::RefreshExecution(reference) => {
                    self.refresh_execution(tab, reference, request_id, deadline)?
                }
                AgentBrowserActionV2::RefreshRelease(reference) => {
                    self.refresh_release(tab, reference, request_id, deadline)?
                }
                AgentBrowserActionV2::RegisterConnector(canonical_descriptor) => {
                    reserve_pending_connector_registration(tab, canonical_descriptor.len())?;
                    let pending_descriptor = Arc::new(Zeroizing::new(canonical_descriptor.clone()));
                    let prepare_descriptor = canonical_descriptor.clone();
                    let proposed = prepare_and_propose_connector_registration(
                        || {
                            self.kernel
                                .prepare_connector_registration(
                                    PrepareConnectorRegistrationRequestV2::new(
                                        required(tab.session)?,
                                        prepare_descriptor,
                                    )
                                    .map_err(|_| AgentBrowserAuthorityErrorV2::InvalidReference)?,
                                    deadline,
                                )
                                .map_err(map_kernel)
                        },
                        |prepared| {
                            self.kernel
                                .propose_connector_registration(
                                    ProposeConnectorRegistrationRequestV2::new(
                                        prepared.authorization(),
                                        canonical_descriptor,
                                    )
                                    .map_err(|_| AgentBrowserAuthorityErrorV2::InvalidReference)?,
                                    deadline,
                                )
                                .map_err(map_kernel)
                        },
                    )?;
                    let registered = self
                        .approval
                        .register_approval(
                            proposed.envelope().clone(),
                            proposed.display_authentication().clone(),
                            deadline,
                        )
                        .map_err(map_approval)?;
                    let RegisteredApprovalV2::Connector {
                        approval,
                        display_authentication,
                    } = registered
                    else {
                        return Err(AgentBrowserAuthorityErrorV2::StateConflict);
                    };
                    let pending = mint_pending_connector_reference(tab)?;
                    tab.pending_connectors.push(PendingConnectorRegistrationV2 {
                        reference: pending,
                        kernel: proposed.pending(),
                        approvald: approval,
                        transfer: display_authentication,
                        canonical_descriptor: pending_descriptor,
                    });
                    AgentBrowserMutationResponseV2::ConnectorOpenApproval {
                        pending,
                        post: FixedBrowserFormPostCarrierV2::AgentApprovalDisplay(
                            display_authentication,
                        ),
                    }
                }
                AgentBrowserActionV2::FinalizeConnectorRegistration(reference) => {
                    self.finalize_connector_registration(tab, reference, deadline)?
                }
                AgentBrowserActionV2::RemoveConnector(connector_id) => {
                    let session = required(tab.session)?;
                    remove_connector_flow(
                        session,
                        connector_id,
                        |request| {
                            self.kernel
                                .prepare_connector_removal(request, deadline)
                                .map_err(map_kernel)
                        },
                        |request| {
                            self.kernel
                                .remove_connector(request, deadline)
                                .map_err(map_kernel)
                        },
                    )?
                }
                AgentBrowserActionV2::SnapshotConnectors => {
                    let snapshot = self
                        .kernel
                        .connector_registry_snapshot(
                            ConnectorRegistrySnapshotRequestV2::new(required(tab.session)?),
                            deadline,
                        )
                        .map_err(map_kernel)?;
                    AgentBrowserMutationResponseV2::ConnectorRegistrySnapshot {
                        canonical_snapshot: snapshot.canonical_snapshot().clone(),
                    }
                }
            };
            Ok(response)
        })
    }

    fn claim_tab(
        &self,
        tab: &mut AgentTabV2,
        deadline: UnixMillisV2,
    ) -> Result<(), AgentBrowserAuthorityErrorV2> {
        if tab.kernel_document.is_some() {
            return Ok(());
        }
        let authorization = tab
            .authorization
            .take()
            .ok_or(AgentBrowserAuthorityErrorV2::StateConflict)?;
        let claimed = match self.kernel.claim_agent_session(authorization, deadline) {
            Ok(claimed) => claimed,
            Err(error) => {
                tab.authorization = Some(authorization);
                return Err(map_kernel(error));
            }
        };
        tab.kernel_document = Some(claimed.initial_document());
        tab.session = Some(claimed.session());
        tab.run = Some(claimed.run());
        tab.initial_value = Some(claimed.initial_value());
        tab.active_tools = claimed.active_tools().to_vec();
        tab.objects.push(BrowserObjectBindingV2::Document {
            reference: tab.initial_document,
            kernel: claimed.initial_document(),
        });
        Ok(())
    }

    fn evaluate_pending(
        &self,
        tab: &mut AgentTabV2,
        reference: AgentPendingToolCallRefV2,
        request_id: RequestIdV2,
        deadline: UnixMillisV2,
    ) -> Result<AgentBrowserMutationResponseV2, AgentBrowserAuthorityErrorV2> {
        let index = tab
            .objects
            .iter()
            .position(|object| {
                matches!(
                    object,
                    BrowserObjectBindingV2::PendingToolCall {
                        reference: candidate,
                        ..
                    } if *candidate == reference
                )
            })
            .ok_or(AgentBrowserAuthorityErrorV2::InvalidReference)?;
        let (pending, approval) = match &tab.objects[index] {
            BrowserObjectBindingV2::PendingToolCall {
                kernel, approval, ..
            } => (*kernel, approval.clone()),
            _ => return Err(AgentBrowserAuthorityErrorV2::InvalidReference),
        };
        if let Some(approval) = approval {
            return match self
                .approval
                .get_agent_approval_settlement(
                    AgentApprovalRecordTargetV2::Tool(approval.approvald),
                    deadline,
                )
                .map_err(map_approval)?
            {
                ApprovalSettlementViewV2::Pending => {
                    Ok(AgentBrowserMutationResponseV2::ToolOpenApproval {
                        post: FixedBrowserFormPostCarrierV2::AgentApprovalDisplay(
                            approval.transfer,
                        ),
                        trace: approval.trace,
                    })
                }
                ApprovalSettlementViewV2::Approved { settlement } => {
                    let authorized = self
                        .kernel
                        .authorize_tool_call(
                            AuthorizeToolCallRequestV2::new(pending, approval.kernel, settlement)
                                .map_err(|_| AgentBrowserAuthorityErrorV2::StateConflict)?,
                            request_id,
                            deadline,
                        )
                        .map_err(map_kernel)?;
                    let ticket = mint_execution_ticket_reference(tab)?;
                    tab.objects.push(BrowserObjectBindingV2::ExecutionTicket {
                        reference: ticket,
                        kernel: authorized.ticket(),
                    });
                    Ok(AgentBrowserMutationResponseV2::ToolAuthorized {
                        ticket,
                        trace: approval.trace,
                    })
                }
                ApprovalSettlementViewV2::Denied { .. } => {
                    Ok(AgentBrowserMutationResponseV2::ToolDenied {
                        code: PublicStableCodeV2::ApprovalDenied,
                        trace: approval.trace,
                    })
                }
                ApprovalSettlementViewV2::Expired => {
                    Ok(AgentBrowserMutationResponseV2::ToolDenied {
                        code: PublicStableCodeV2::ApprovalExpired,
                        trace: approval.trace,
                    })
                }
            };
        }
        match self
            .kernel
            .evaluate_tool_call(
                EvaluateToolCallRequestV2::new(pending),
                request_id,
                deadline,
            )
            .map_err(map_kernel)?
        {
            EvaluateToolCallResponseV2::Denied { code, trace } => {
                Ok(AgentBrowserMutationResponseV2::ToolDenied { code, trace })
            }
            EvaluateToolCallResponseV2::Allowed { ticket, trace } => {
                let reference = mint_execution_ticket_reference(tab)?;
                tab.objects.push(BrowserObjectBindingV2::ExecutionTicket {
                    reference,
                    kernel: ticket,
                });
                Ok(AgentBrowserMutationResponseV2::ToolAuthorized {
                    ticket: reference,
                    trace,
                })
            }
            EvaluateToolCallResponseV2::NeedsApproval {
                approval: kernel,
                envelope,
                display_authentication,
                trace,
            } => {
                let registered = self
                    .approval
                    .register_approval(envelope, display_authentication, deadline)
                    .map_err(map_approval)?;
                let RegisteredApprovalV2::Tool {
                    approval: approvald,
                    display_authentication: transfer,
                } = registered
                else {
                    return Err(AgentBrowserAuthorityErrorV2::StateConflict);
                };
                let approval = ToolApprovalStateV2 {
                    kernel,
                    approvald,
                    trace,
                    transfer,
                };
                let BrowserObjectBindingV2::PendingToolCall {
                    approval: target, ..
                } = &mut tab.objects[index]
                else {
                    return Err(AgentBrowserAuthorityErrorV2::StateConflict);
                };
                *target = Some(approval);
                Ok(AgentBrowserMutationResponseV2::ToolOpenApproval {
                    post: FixedBrowserFormPostCarrierV2::AgentApprovalDisplay(transfer),
                    trace,
                })
            }
        }
    }

    fn finalize_connector_registration(
        &self,
        tab: &mut AgentTabV2,
        reference: AgentPendingConnectorRegistrationRefV2,
        deadline: UnixMillisV2,
    ) -> Result<AgentBrowserMutationResponseV2, AgentBrowserAuthorityErrorV2> {
        let index = tab
            .pending_connectors
            .iter()
            .position(|candidate| candidate.reference == reference)
            .ok_or(AgentBrowserAuthorityErrorV2::InvalidReference)?;
        let approvald = tab.pending_connectors[index].approvald;
        let settlement = self
            .approval
            .get_agent_approval_settlement(
                AgentApprovalRecordTargetV2::Connector(approvald),
                deadline,
            )
            .map_err(map_approval)?;
        finalize_connector_registration_settlement(
            tab,
            index,
            settlement,
            |request| {
                self.kernel
                    .authorize_connector_registration(request, deadline)
                    .map_err(map_kernel)
            },
            |canonical_descriptor| {
                self.planner_catalog
                    .lock()
                    .map_err(|_| AgentBrowserAuthorityErrorV2::Unavailable)?
                    .insert_connector_descriptor(canonical_descriptor)
                    .map_err(|error| match error {
                        crate::PlannerCatalogErrorV2::Invalid => {
                            AgentBrowserAuthorityErrorV2::InvalidReference
                        }
                        _ => AgentBrowserAuthorityErrorV2::Unavailable,
                    })
            },
            |request| {
                self.kernel
                    .apply_approved_connector_registration(request, deadline)
                    .map_err(map_kernel)
            },
        )
    }

    fn refresh_execution(
        &self,
        tab: &mut AgentTabV2,
        reference: AgentExecutionRefV2,
        request_id: RequestIdV2,
        deadline: UnixMillisV2,
    ) -> Result<AgentBrowserMutationResponseV2, AgentBrowserAuthorityErrorV2> {
        let execution = tab
            .objects
            .iter()
            .find_map(|object| match object {
                BrowserObjectBindingV2::Execution {
                    reference: candidate,
                    kernel,
                } if *candidate == reference => Some(*kernel),
                _ => None,
            })
            .ok_or(AgentBrowserAuthorityErrorV2::InvalidReference)?;
        let status = self
            .kernel
            .get_execution_status(
                GetExecutionStatusRequestV2::new(ExecutionStatusTargetV2::Execution(execution)),
                request_id,
                deadline,
            )
            .map_err(map_kernel)?
            .status();
        let state = map_execution_state(tab, status)?;
        Ok(AgentBrowserMutationResponseV2::ExecutionRefreshed {
            execution: reference,
            state,
        })
    }

    fn refresh_release(
        &self,
        tab: &mut AgentTabV2,
        reference: AgentReleaseRefV2,
        request_id: RequestIdV2,
        deadline: UnixMillisV2,
    ) -> Result<AgentBrowserMutationResponseV2, AgentBrowserAuthorityErrorV2> {
        let release = tab
            .objects
            .iter()
            .find_map(|object| match object {
                BrowserObjectBindingV2::Release {
                    reference: candidate,
                    kernel,
                } if *candidate == reference => Some(*kernel),
                _ => None,
            })
            .ok_or(AgentBrowserAuthorityErrorV2::InvalidReference)?;
        let status = self
            .kernel
            .get_release_status(
                GetReleaseStatusRequestV2::new(ReleaseStatusTargetV2::Release(release)),
                request_id,
                deadline,
            )
            .map_err(map_kernel)?
            .status();
        Ok(AgentBrowserMutationResponseV2::ReleaseRefreshed {
            release: reference,
            state: map_release_state(status),
        })
    }

    fn reconcile_release_approvals(
        &self,
        tab: &mut AgentTabV2,
        deadline: UnixMillisV2,
    ) -> Result<(), AgentBrowserAuthorityErrorV2> {
        let mut index = 0;
        while index < tab.pending_releases.len() {
            let pending = tab.pending_releases[index].clone();
            match self
                .approval
                .get_agent_approval_settlement(
                    AgentApprovalRecordTargetV2::Release(pending.approvald),
                    deadline,
                )
                .map_err(map_approval)?
            {
                ApprovalSettlementViewV2::Pending => {
                    index += 1;
                }
                ApprovalSettlementViewV2::Approved { settlement } => {
                    let request =
                        AuthorizeReleaseRequestV2::new(pending.pending, pending.kernel, settlement)
                            .map_err(|_| AgentBrowserAuthorityErrorV2::StateConflict)?;
                    let request_id = stable_operation_request_id(
                        &KernelAgentOperationV2::AuthorizeRelease(request.clone()),
                    )?;
                    let authorized = self
                        .kernel
                        .authorize_release(request, request_id, deadline)
                        .map_err(map_kernel)?;
                    let reference = mint_release_ticket_reference(tab)?;
                    tab.objects.push(BrowserObjectBindingV2::ReleaseTicket {
                        reference,
                        kernel: authorized.ticket(),
                    });
                    tab.pending_releases.swap_remove(index);
                }
                ApprovalSettlementViewV2::Denied { .. } | ApprovalSettlementViewV2::Expired => {
                    tab.pending_releases.swap_remove(index);
                }
            }
        }
        Ok(())
    }
}

fn prepare_and_propose_connector_registration<Prepare, Propose, Prepared, Proposed>(
    prepare: Prepare,
    propose: Propose,
) -> Result<Proposed, AgentBrowserAuthorityErrorV2>
where
    Prepare: FnOnce() -> Result<Prepared, AgentBrowserAuthorityErrorV2>,
    Propose: FnOnce(Prepared) -> Result<Proposed, AgentBrowserAuthorityErrorV2>,
{
    propose(prepare()?)
}

fn reserve_pending_connector_registration(
    tab: &mut AgentTabV2,
    descriptor_bytes: usize,
) -> Result<(), AgentBrowserAuthorityErrorV2> {
    if tab
        .objects
        .len()
        .saturating_add(tab.pending_connectors.len())
        >= MAX_OBJECTS_PER_TAB_V2
    {
        return Err(AgentBrowserAuthorityErrorV2::Overloaded);
    }
    let retained_bytes = tab
        .pending_connectors
        .iter()
        .try_fold(0_usize, |total, pending| {
            total.checked_add(pending.canonical_descriptor.len())
        })
        .ok_or(AgentBrowserAuthorityErrorV2::Overloaded)?;
    if descriptor_bytes == 0
        || retained_bytes
            .checked_add(descriptor_bytes)
            .filter(|total| *total <= MAX_PENDING_CONNECTOR_DESCRIPTOR_BYTES_PER_TAB_V2)
            .is_none()
    {
        return Err(AgentBrowserAuthorityErrorV2::Overloaded);
    }
    tab.pending_connectors
        .try_reserve(1)
        .map_err(|_| AgentBrowserAuthorityErrorV2::Overloaded)
}

fn finalize_connector_registration_settlement<Authorize, Persist, Apply>(
    tab: &mut AgentTabV2,
    pending_index: usize,
    settlement: ApprovalSettlementViewV2,
    authorize: Authorize,
    persist: Persist,
    apply: Apply,
) -> Result<AgentBrowserMutationResponseV2, AgentBrowserAuthorityErrorV2>
where
    Authorize:
        FnOnce(
            AuthorizeConnectorRegistrationRequestV2,
        )
            -> Result<AuthorizeConnectorRegistrationResponseV2, AgentBrowserAuthorityErrorV2>,
    Persist: FnOnce(&[u8]) -> Result<(), AgentBrowserAuthorityErrorV2>,
    Apply: FnOnce(
        ApplyApprovedConnectorRegistrationRequestV2,
    ) -> Result<
        ApplyApprovedConnectorRegistrationResponseV2,
        AgentBrowserAuthorityErrorV2,
    >,
{
    let pending = tab
        .pending_connectors
        .get(pending_index)
        .cloned()
        .ok_or(AgentBrowserAuthorityErrorV2::InvalidReference)?;
    match settlement {
        ApprovalSettlementViewV2::Pending => {
            Ok(AgentBrowserMutationResponseV2::ConnectorOpenApproval {
                pending: pending.reference,
                post: FixedBrowserFormPostCarrierV2::AgentApprovalDisplay(pending.transfer),
            })
        }
        ApprovalSettlementViewV2::Approved { settlement } => {
            let authorized = authorize(
                AuthorizeConnectorRegistrationRequestV2::new(pending.kernel, settlement)
                    .map_err(|_| AgentBrowserAuthorityErrorV2::StateConflict)?,
            )?;
            persist(pending.canonical_descriptor.as_slice())?;
            let committed = apply(ApplyApprovedConnectorRegistrationRequestV2::new(
                authorized.approved(),
            ))?;
            tab.pending_connectors.swap_remove(pending_index);
            Ok(
                AgentBrowserMutationResponseV2::ConnectorRegistrationCommitted {
                    pending: pending.reference,
                    signed_delta_digest: committed.signed_delta_digest(),
                    head_digest: committed.head_digest(),
                    sequence: committed.sequence(),
                    connector_id: committed.connector_id(),
                },
            )
        }
        ApprovalSettlementViewV2::Denied { .. } | ApprovalSettlementViewV2::Expired => {
            tab.pending_connectors.swap_remove(pending_index);
            Err(AgentBrowserAuthorityErrorV2::StateConflict)
        }
    }
}

fn remove_connector_flow<Prepare, Remove>(
    session: AgentSessionHandleV2,
    connector_id: Digest32V2,
    prepare: Prepare,
    remove: Remove,
) -> Result<AgentBrowserMutationResponseV2, AgentBrowserAuthorityErrorV2>
where
    Prepare: FnOnce(
        PrepareConnectorRemovalRequestV2,
    ) -> Result<PrepareConnectorRemovalResponseV2, AgentBrowserAuthorityErrorV2>,
    Remove: FnOnce(
        RemoveConnectorRequestV2,
    ) -> Result<RemoveConnectorResponseV2, AgentBrowserAuthorityErrorV2>,
{
    let prepared = prepare(
        PrepareConnectorRemovalRequestV2::new(session, connector_id)
            .map_err(|_| AgentBrowserAuthorityErrorV2::InvalidReference)?,
    )?;
    let removed = remove(
        RemoveConnectorRequestV2::new(session, prepared.authorization(), connector_id)
            .map_err(|_| AgentBrowserAuthorityErrorV2::InvalidReference)?,
    )?;
    if removed.connector_id() != connector_id {
        return Err(AgentBrowserAuthorityErrorV2::StateConflict);
    }
    Ok(AgentBrowserMutationResponseV2::ConnectorRemovalCommitted {
        signed_delta_digest: removed.signed_delta_digest(),
        head_digest: removed.head_digest(),
        sequence: removed.sequence(),
        connector_id,
    })
}

fn required<T: Copy>(value: Option<T>) -> Result<T, AgentBrowserAuthorityErrorV2> {
    value.ok_or(AgentBrowserAuthorityErrorV2::StateConflict)
}

fn browser_object_projection(object: &BrowserObjectBindingV2) -> AgentBrowserObjectRefV2 {
    match object {
        BrowserObjectBindingV2::Document { reference, .. } => {
            AgentBrowserObjectRefV2::Document(*reference)
        }
        BrowserObjectBindingV2::PlanStep { reference, .. } => {
            AgentBrowserObjectRefV2::PlanStep(*reference)
        }
        BrowserObjectBindingV2::PendingToolCall { reference, .. } => {
            AgentBrowserObjectRefV2::PendingToolCall(*reference)
        }
        BrowserObjectBindingV2::ExecutionTicket { reference, .. } => {
            AgentBrowserObjectRefV2::ExecutionTicket(*reference)
        }
        BrowserObjectBindingV2::ReleaseTicket { reference, .. } => {
            AgentBrowserObjectRefV2::ReleaseTicket(*reference)
        }
        BrowserObjectBindingV2::Execution { reference, .. } => {
            AgentBrowserObjectRefV2::Execution(*reference)
        }
        BrowserObjectBindingV2::Release { reference, .. } => {
            AgentBrowserObjectRefV2::Release(*reference)
        }
    }
}

fn browser_action_request_digest(
    tab: AgentTabSessionCapabilityV2,
    action: AgentBrowserActionV2,
) -> Result<Digest32V2, AgentBrowserAuthorityErrorV2> {
    let request = AgentBrowserRequestV2::Act {
        tab,
        client_request_nonce: Nonce32V2::new([1; 32]),
        action,
    };
    let bytes = savana_kernel_protocol::v2::encode_agent_browser_request_v2(request)
        .map_err(|_| AgentBrowserAuthorityErrorV2::InvalidReference)?;
    let mut hasher = sha2::Sha256::new();
    use sha2::Digest as _;
    hasher.update(b"SAVANA_AGENT_BROWSER_ACTION_REQUEST_V2\0");
    hasher.update(bytes);
    Ok(Digest32V2::new(hasher.finalize().into()))
}

fn resolve_action_replay_v2(
    replays: &[ActionReplayV2],
    nonce: Nonce32V2,
    request_digest: Digest32V2,
) -> Option<Result<AgentBrowserMutationResponseV2, AgentBrowserAuthorityErrorV2>> {
    replays
        .iter()
        .find(|entry| entry.nonce == nonce)
        .map(|existing| {
            if existing.request_digest != request_digest {
                return Err(AgentBrowserAuthorityErrorV2::StateConflict);
            }
            existing
                .response
                .clone()
                .ok_or(AgentBrowserAuthorityErrorV2::StateConflict)
        })
}

fn execute_action_nonce_bound_v2<Execute>(
    tab: &mut AgentTabV2,
    nonce: Nonce32V2,
    request_digest: Digest32V2,
    execute: Execute,
) -> Result<AgentBrowserMutationResponseV2, AgentBrowserAuthorityErrorV2>
where
    Execute: FnOnce(
        &mut AgentTabV2,
    ) -> Result<AgentBrowserMutationResponseV2, AgentBrowserAuthorityErrorV2>,
{
    if let Some(replayed) = resolve_action_replay_v2(&tab.action_replays, nonce, request_digest) {
        return replayed;
    }
    if tab.action_replays.len() >= MAX_REPLAYS_PER_TAB_V2 {
        return Err(AgentBrowserAuthorityErrorV2::Overloaded);
    }
    tab.action_replays
        .try_reserve(1)
        .map_err(|_| AgentBrowserAuthorityErrorV2::Overloaded)?;
    let claim_index = tab.action_replays.len();
    tab.action_replays.push(ActionReplayV2 {
        request_digest,
        nonce,
        response: None,
    });

    let response = execute(tab)?;
    let claim = tab
        .action_replays
        .get_mut(claim_index)
        .filter(|claim| claim.nonce == nonce && claim.request_digest == request_digest)
        .ok_or(AgentBrowserAuthorityErrorV2::StateConflict)?;
    if claim.response.is_some() {
        return Err(AgentBrowserAuthorityErrorV2::StateConflict);
    }
    claim.response = Some(response.clone());
    Ok(response)
}

fn browser_kernel_request_id(
    tab: AgentTabSessionCapabilityV2,
    nonce: Nonce32V2,
    action: AgentBrowserActionV2,
) -> Result<RequestIdV2, AgentBrowserAuthorityErrorV2> {
    let bytes =
        savana_kernel_protocol::v2::encode_agent_browser_request_v2(AgentBrowserRequestV2::Act {
            tab,
            client_request_nonce: nonce,
            action,
        })
        .map_err(|_| AgentBrowserAuthorityErrorV2::InvalidReference)?;
    use sha2::Digest as _;
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"SAVANA_AGENT_BROWSER_KERNEL_REQUEST_ID_V2\0");
    hasher.update(bytes);
    let digest: [u8; 32] = hasher.finalize().into();
    let mut request_id = [0_u8; 16];
    request_id.copy_from_slice(&digest[..16]);
    if request_id == [0; 16] {
        request_id[15] = 1;
    }
    Ok(RequestIdV2::new(request_id))
}

fn browser_effect_operation_id(
    tab: AgentTabSessionCapabilityV2,
    nonce: Nonce32V2,
    action: AgentBrowserActionV2,
) -> Result<Digest32V2, AgentBrowserAuthorityErrorV2> {
    let bytes =
        savana_kernel_protocol::v2::encode_agent_browser_request_v2(AgentBrowserRequestV2::Act {
            tab,
            client_request_nonce: nonce,
            action,
        })
        .map_err(|_| AgentBrowserAuthorityErrorV2::InvalidReference)?;
    use sha2::Digest as _;
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"SAVANA_AGENTD_EFFECT_OPERATION_ID_V2\0");
    hasher.update(bytes);
    Ok(Digest32V2::new(hasher.finalize().into()))
}

fn effect_gate_deadline(deadline: UnixMillisV2) -> Result<Instant, AgentBrowserAuthorityErrorV2> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AgentBrowserAuthorityErrorV2::Unavailable)?;
    let now = u64::try_from(elapsed.as_millis())
        .map_err(|_| AgentBrowserAuthorityErrorV2::Unavailable)?;
    let remaining = deadline
        .get()
        .checked_sub(now)
        .filter(|remaining| *remaining != 0)
        .ok_or(AgentBrowserAuthorityErrorV2::Unavailable)?;
    Instant::now()
        .checked_add(Duration::from_millis(remaining))
        .ok_or(AgentBrowserAuthorityErrorV2::Unavailable)
}

const fn map_effect_gate(_error: EffectGateErrorV2) -> AgentBrowserAuthorityErrorV2 {
    AgentBrowserAuthorityErrorV2::Unavailable
}

fn stable_operation_request_id(
    operation: &KernelAgentOperationV2,
) -> Result<RequestIdV2, AgentBrowserAuthorityErrorV2> {
    let bytes = savana_kernel_protocol::v2::encode_kernel_agent_operation_v2(operation)
        .map_err(|_| AgentBrowserAuthorityErrorV2::StateConflict)?;
    use sha2::Digest as _;
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"SAVANA_AGENT_BROWSER_RECONCILE_REQUEST_ID_V2\0");
    hasher.update(bytes);
    let digest: [u8; 32] = hasher.finalize().into();
    let mut request_id = [0_u8; 16];
    request_id.copy_from_slice(&digest[..16]);
    if request_id == [0; 16] {
        request_id[15] = 1;
    }
    Ok(RequestIdV2::new(request_id))
}

fn mint_reference(
    tab: &mut AgentTabV2,
    type_tag: u16,
) -> Result<[u8; 16], AgentBrowserAuthorityErrorV2> {
    if tab.objects.len() >= MAX_OBJECTS_PER_TAB_V2 {
        return Err(AgentBrowserAuthorityErrorV2::Overloaded);
    }
    let object_id = draw_nonzero()?;
    let revision = tab.next_reference_revision;
    tab.next_reference_revision = revision
        .checked_add(1)
        .ok_or(AgentBrowserAuthorityErrorV2::Overloaded)?;
    use hmac::{Hmac, Mac as _};
    use sha2::Sha256;
    let mut mac = Hmac::<Sha256>::new_from_slice(tab.reference_key.as_ref())
        .map_err(|_| AgentBrowserAuthorityErrorV2::Unavailable)?;
    mac.update(b"SAVANA_AGENT_BROWSER_OBJECT_REF_V2\0");
    mac.update(tab.agentd_boot_id.as_bytes());
    mac.update(tab.tab_internal_id.as_bytes());
    mac.update(&type_tag.to_be_bytes());
    mac.update(&object_id);
    mac.update(&revision.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let mut reference = [0_u8; 16];
    reference.copy_from_slice(&digest[..16]);
    if reference == [0; 16] {
        return Err(AgentBrowserAuthorityErrorV2::Unavailable);
    }
    Ok(reference)
}

fn mint_step_reference(
    tab: &mut AgentTabV2,
) -> Result<AgentPlanStepRefV2, AgentBrowserAuthorityErrorV2> {
    AgentPlanStepRefV2::from_authority_entropy(mint_reference(tab, 2)?)
        .ok_or(AgentBrowserAuthorityErrorV2::Unavailable)
}

fn mint_pending_reference(
    tab: &mut AgentTabV2,
) -> Result<AgentPendingToolCallRefV2, AgentBrowserAuthorityErrorV2> {
    AgentPendingToolCallRefV2::from_authority_entropy(mint_reference(tab, 3)?)
        .ok_or(AgentBrowserAuthorityErrorV2::Unavailable)
}

fn mint_execution_ticket_reference(
    tab: &mut AgentTabV2,
) -> Result<AgentExecutionTicketRefV2, AgentBrowserAuthorityErrorV2> {
    AgentExecutionTicketRefV2::from_authority_entropy(mint_reference(tab, 4)?)
        .ok_or(AgentBrowserAuthorityErrorV2::Unavailable)
}

fn mint_release_ticket_reference(
    tab: &mut AgentTabV2,
) -> Result<AgentReleaseTicketRefV2, AgentBrowserAuthorityErrorV2> {
    AgentReleaseTicketRefV2::from_authority_entropy(mint_reference(tab, 5)?)
        .ok_or(AgentBrowserAuthorityErrorV2::Unavailable)
}

fn mint_execution_reference(
    tab: &mut AgentTabV2,
) -> Result<AgentExecutionRefV2, AgentBrowserAuthorityErrorV2> {
    AgentExecutionRefV2::from_authority_entropy(mint_reference(tab, 6)?)
        .ok_or(AgentBrowserAuthorityErrorV2::Unavailable)
}

fn mint_release_reference(
    tab: &mut AgentTabV2,
) -> Result<AgentReleaseRefV2, AgentBrowserAuthorityErrorV2> {
    AgentReleaseRefV2::from_authority_entropy(mint_reference(tab, 7)?)
        .ok_or(AgentBrowserAuthorityErrorV2::Unavailable)
}

fn mint_pending_connector_reference(
    tab: &mut AgentTabV2,
) -> Result<AgentPendingConnectorRegistrationRefV2, AgentBrowserAuthorityErrorV2> {
    AgentPendingConnectorRegistrationRefV2::from_authority_entropy(mint_reference(tab, 8)?)
        .ok_or(AgentBrowserAuthorityErrorV2::Unavailable)
}

fn mint_document_reference(
    tab: &mut AgentTabV2,
) -> Result<AgentMaskedDocumentRefV2, AgentBrowserAuthorityErrorV2> {
    AgentMaskedDocumentRefV2::from_authority_entropy(mint_reference(tab, 1)?)
        .ok_or(AgentBrowserAuthorityErrorV2::Unavailable)
}

fn find_document(
    tab: &AgentTabV2,
    reference: AgentMaskedDocumentRefV2,
) -> Result<MaskedDocumentHandleV2, AgentBrowserAuthorityErrorV2> {
    tab.objects
        .iter()
        .find_map(|object| match object {
            BrowserObjectBindingV2::Document {
                reference: candidate,
                kernel,
            } if *candidate == reference => Some(*kernel),
            _ => None,
        })
        .ok_or(AgentBrowserAuthorityErrorV2::InvalidReference)
}

fn find_execution_ticket(
    tab: &AgentTabV2,
    reference: AgentExecutionTicketRefV2,
) -> Result<ExecutionTicketHandleV2, AgentBrowserAuthorityErrorV2> {
    tab.objects
        .iter()
        .find_map(|object| match object {
            BrowserObjectBindingV2::ExecutionTicket {
                reference: candidate,
                kernel,
            } if *candidate == reference => Some(*kernel),
            _ => None,
        })
        .ok_or(AgentBrowserAuthorityErrorV2::InvalidReference)
}

fn find_release_ticket(
    tab: &AgentTabV2,
    reference: AgentReleaseTicketRefV2,
) -> Result<ReleaseTicketHandleV2, AgentBrowserAuthorityErrorV2> {
    tab.objects
        .iter()
        .find_map(|object| match object {
            BrowserObjectBindingV2::ReleaseTicket {
                reference: candidate,
                kernel,
            } if *candidate == reference => Some(*kernel),
            _ => None,
        })
        .ok_or(AgentBrowserAuthorityErrorV2::InvalidReference)
}

fn map_execution_state(
    tab: &mut AgentTabV2,
    status: PublicExecutionStatusV2,
) -> Result<AgentBrowserExecutionStateV2, AgentBrowserAuthorityErrorV2> {
    Ok(match status {
        PublicExecutionStatusV2::Prepared => AgentBrowserExecutionStateV2::Prepared,
        PublicExecutionStatusV2::Dispatching => AgentBrowserExecutionStateV2::Dispatching,
        PublicExecutionStatusV2::ResultGatePending => {
            AgentBrowserExecutionStateV2::ResultGatePending
        }
        PublicExecutionStatusV2::Succeeded {
            completion: PublicDispatchCompletionV2::ToolExecution { document },
        } => {
            let reference = if let Some(reference) =
                tab.objects.iter().find_map(|object| match object {
                    BrowserObjectBindingV2::Document { reference, kernel }
                        if *kernel == document =>
                    {
                        Some(*reference)
                    }
                    _ => None,
                }) {
                reference
            } else {
                let reference = mint_document_reference(tab)?;
                tab.objects.push(BrowserObjectBindingV2::Document {
                    reference,
                    kernel: document,
                });
                reference
            };
            AgentBrowserExecutionStateV2::Succeeded {
                document: reference,
            }
        }
        PublicExecutionStatusV2::Succeeded { .. } => AgentBrowserExecutionStateV2::Indeterminate,
        PublicExecutionStatusV2::EffectSucceededOutputQuarantined { class } => {
            AgentBrowserExecutionStateV2::EffectSucceededOutputQuarantined { class }
        }
        PublicExecutionStatusV2::FailedNoEffect { class } => {
            AgentBrowserExecutionStateV2::FailedNoEffect { class }
        }
        PublicExecutionStatusV2::Indeterminate => AgentBrowserExecutionStateV2::Indeterminate,
    })
}

fn map_release_state(status: PublicExecutionStatusV2) -> AgentBrowserReleaseStateV2 {
    match status {
        PublicExecutionStatusV2::Prepared => AgentBrowserReleaseStateV2::Prepared,
        PublicExecutionStatusV2::Dispatching | PublicExecutionStatusV2::ResultGatePending => {
            AgentBrowserReleaseStateV2::Dispatching
        }
        PublicExecutionStatusV2::Succeeded {
            completion: PublicDispatchCompletionV2::FinalRelease,
        } => AgentBrowserReleaseStateV2::Succeeded,
        PublicExecutionStatusV2::Succeeded { .. } => AgentBrowserReleaseStateV2::Indeterminate,
        PublicExecutionStatusV2::EffectSucceededOutputQuarantined { class } => {
            AgentBrowserReleaseStateV2::EffectSucceededOutputQuarantined { class }
        }
        PublicExecutionStatusV2::FailedNoEffect { class } => {
            AgentBrowserReleaseStateV2::FailedNoEffect { class }
        }
        PublicExecutionStatusV2::Indeterminate => AgentBrowserReleaseStateV2::Indeterminate,
    }
}

fn browser_read_request_digest(
    tab: AgentTabSessionCapabilityV2,
    document: AgentMaskedDocumentRefV2,
    cursor: Option<AgentBrowserViewCursorCapabilityV2>,
    maximum_encoded_bytes: u32,
) -> Result<Digest32V2, AgentBrowserAuthorityErrorV2> {
    let request = AgentBrowserRequestV2::ReadView {
        tab,
        client_request_nonce: Nonce32V2::new([1; 32]),
        document,
        cursor,
        maximum_encoded_bytes,
    };
    let bytes = savana_kernel_protocol::v2::encode_agent_browser_request_v2(request)
        .map_err(|_| AgentBrowserAuthorityErrorV2::InvalidReference)?;
    use sha2::{Digest as _, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"SAVANA_AGENT_BROWSER_READ_REQUEST_V2\0");
    hasher.update(bytes);
    Ok(Digest32V2::new(hasher.finalize().into()))
}

fn find_action_tab(
    state: &mut AuthorityStateV2,
    requested: AgentTabSessionCapabilityV2,
) -> Result<&mut AgentTabV2, AgentBrowserAuthorityErrorV2> {
    state
        .tabs
        .iter_mut()
        .find(|candidate| candidate.tab == requested)
        .ok_or(AgentBrowserAuthorityErrorV2::InvalidReference)
}

const fn connector_action_requires_authenticated_tab(action: &AgentBrowserActionV2) -> bool {
    matches!(
        action,
        AgentBrowserActionV2::RegisterConnector(_)
            | AgentBrowserActionV2::FinalizeConnectorRegistration(_)
            | AgentBrowserActionV2::RemoveConnector(_)
            | AgentBrowserActionV2::SnapshotConnectors
    )
}

fn authenticated_connector_tab(
    state: &mut AuthorityStateV2,
    requested: AgentTabSessionCapabilityV2,
    current_agentd_boot_id: BootIdV2,
) -> Result<&mut AgentTabV2, AgentBrowserAuthorityErrorV2> {
    let tab = find_action_tab(state, requested)?;
    let freshly_authenticated = tab.authorization.is_some()
        && tab.kernel_document.is_none()
        && tab.session.is_none()
        && tab.run.is_none()
        && tab.initial_value.is_none();
    let claimed_authenticated = tab.authorization.is_none()
        && tab.kernel_document.is_some()
        && tab.session.is_some()
        && tab.run.is_some()
        && tab.initial_value.is_some();
    if tab.agentd_boot_id != current_agentd_boot_id
        || tab.origin != FixedOriginV2::Agent8768
        || !(freshly_authenticated || claimed_authenticated)
    {
        return Err(AgentBrowserAuthorityErrorV2::InvalidReference);
    }
    Ok(tab)
}

fn draw_nonce() -> Result<Nonce32V2, AgentBrowserAuthorityErrorV2> {
    Ok(Nonce32V2::new(draw_nonzero()?))
}

fn draw_nonzero_16() -> Result<[u8; 16], AgentBrowserAuthorityErrorV2> {
    for _ in 0..4 {
        let mut bytes = [0_u8; 16];
        getrandom::getrandom(&mut bytes).map_err(|_| AgentBrowserAuthorityErrorV2::Unavailable)?;
        if bytes != [0; 16] {
            return Ok(bytes);
        }
    }
    Err(AgentBrowserAuthorityErrorV2::Unavailable)
}

fn draw_nonzero() -> Result<[u8; 32], AgentBrowserAuthorityErrorV2> {
    for _ in 0..4 {
        let mut bytes = [0_u8; 32];
        getrandom::getrandom(&mut bytes).map_err(|_| AgentBrowserAuthorityErrorV2::Unavailable)?;
        if bytes != [0; 32] {
            return Ok(bytes);
        }
    }
    Err(AgentBrowserAuthorityErrorV2::Unavailable)
}

fn map_kernel(_: AgentControlKernelClientErrorV2) -> AgentBrowserAuthorityErrorV2 {
    AgentBrowserAuthorityErrorV2::Unavailable
}

fn map_planner(_: AgentPlannerClientErrorV2) -> AgentBrowserAuthorityErrorV2 {
    AgentBrowserAuthorityErrorV2::Unavailable
}

fn map_mapper(_: AgentMapperClientErrorV2) -> AgentBrowserAuthorityErrorV2 {
    AgentBrowserAuthorityErrorV2::Unavailable
}

fn planner_intent_boundary_for_action_v2(
    action: &AgentBrowserActionV2,
) -> Result<IntentTrustBoundaryV2, AgentBrowserAuthorityErrorV2> {
    match action {
        AgentBrowserActionV2::RunPlanner => Ok(IntentTrustBoundaryV2::Private),
        AgentBrowserActionV2::RunPlannerWithThirdPartyMapper => {
            Ok(IntentTrustBoundaryV2::ThirdParty)
        }
        _ => Err(AgentBrowserAuthorityErrorV2::InvalidReference),
    }
}

fn planner_prepare_call_request_v2(
    run: RunHandleV2,
    planner_route: PlannerRouteIdV2,
    planner_template: StaticTemplateIdV2,
    planner_intent: PlannerIntentKindV2,
    planner_limits: PlannerLimitsV2,
    initial_value: ValueHandleV2,
) -> Result<PreparePlannerCallRequestV2, AgentBrowserAuthorityErrorV2> {
    PreparePlannerCallRequestV2::new(
        run,
        planner_route,
        planner_template,
        planner_intent,
        PlannerPurposeV2::PlannerCall,
        planner_limits,
        vec![initial_value],
    )
    .map_err(|_| AgentBrowserAuthorityErrorV2::InvalidReference)
}

fn planner_commit_value_request_v2(
    run: RunHandleV2,
    ticket: PlannerTicketHandleV2,
    plan: PlannerPlanV2,
) -> CommitPlannerValueRequestV2 {
    CommitPlannerValueRequestV2::new(run, ticket, plan)
}

fn map_approval(error: ApprovalSuiteOneClientErrorV2) -> AgentBrowserAuthorityErrorV2 {
    match error {
        ApprovalSuiteOneClientErrorV2::Rejected(_) => {
            AgentBrowserAuthorityErrorV2::InvalidReference
        }
        ApprovalSuiteOneClientErrorV2::DeadlineExceeded
        | ApprovalSuiteOneClientErrorV2::Unavailable => AgentBrowserAuthorityErrorV2::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;
    use std::rc::Rc;
    use std::sync::Arc;

    use ed25519_dalek::SigningKey;
    use savana_kernel_protocol::v2::{
        encode_kernel_agent_operation_v2, ActionTemplateIdV2, ApprovalDecisionV2,
        ApprovalPurposeV2, ApprovedConnectorRegistrationHandleV2,
        ConnectorRemovalAuthorizationHandleV2, KernelAgentOperationV2, PlannerPlanV2,
        PlannerStepV2, PlannerTicketHandleV2, PrincipalIdV2, SignedApprovalSettlementV2,
        ToolClassIdV2, UnsignedApprovalSettlementV2,
    };

    use crate::planner_privacy::IntentTrustDeploymentCeilingV2;
    use crate::{
        BoundedPlannerSemanticTextV2, DurablePlannerCatalogNamespaceV2, PlannerCatalogErrorV2,
        PlannerCatalogRollbackAnchorV2, PlannerCatalogStateHeadV2,
    };
    use savana_policy_core::v2::{ConnectorStructuralRoleV2, EffectSetV2};

    use super::*;

    #[derive(Clone, Default)]
    struct ConnectorTestCatalogAnchor(Arc<Mutex<PlannerCatalogStateHeadV2>>);

    impl PlannerCatalogRollbackAnchorV2 for ConnectorTestCatalogAnchor {
        fn current_head(&self) -> Result<PlannerCatalogStateHeadV2, PlannerCatalogErrorV2> {
            Ok(*self.0.lock().unwrap())
        }

        fn compare_and_advance(
            &mut self,
            expected: PlannerCatalogStateHeadV2,
            next: PlannerCatalogStateHeadV2,
        ) -> Result<(), PlannerCatalogErrorV2> {
            let mut head = self.0.lock().unwrap();
            if *head != expected || next.sequence() != expected.sequence() + 1 {
                return Err(PlannerCatalogErrorV2::RollbackDetected);
            }
            *head = next;
            Ok(())
        }
    }

    fn empty_connector_test_catalog() -> (tempfile::TempDir, DurablePlannerCatalogV2) {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let catalog = DurablePlannerCatalogV2::open(
            &directory.path().join("planner-catalog-state-v2.cbor"),
            [0x91; 32],
            DurablePlannerCatalogNamespaceV2::from_verified_installation(
                Digest32V2::new([0x92; 32]),
                Digest32V2::new([0x93; 32]),
            )
            .unwrap(),
            Box::new(ConnectorTestCatalogAnchor::default()),
            vec![],
        )
        .unwrap();
        (directory, catalog)
    }

    fn connector_test_catalog_entry() -> PlannerCatalogEntryV2 {
        PlannerCatalogEntryV2::new(
            ToolClassIdV2::new(777),
            ActionTemplateIdV2::new(778),
            ConnectorStructuralRoleV2::Sink,
            EffectSetV2::SEND,
            BoundedPlannerSemanticTextV2::new("approved.connector").unwrap(),
            BoundedPlannerSemanticTextV2::new("approved connector description").unwrap(),
        )
        .unwrap()
    }

    fn connector_test_catalog_conflict_entry() -> PlannerCatalogEntryV2 {
        PlannerCatalogEntryV2::new(
            ToolClassIdV2::new(777),
            ActionTemplateIdV2::new(778),
            ConnectorStructuralRoleV2::Sink,
            EffectSetV2::SEND,
            BoundedPlannerSemanticTextV2::new("unapproved.connector").unwrap(),
            BoundedPlannerSemanticTextV2::new("unapproved conflicting description").unwrap(),
        )
        .unwrap()
    }

    mod planner_privacy {
        use super::*;
        use std::fs::{File, OpenOptions};
        use std::io::{Read as _, Write as _};
        use std::net::TcpListener;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use std::thread;

        use crate::planner_privacy::{
            decode_mapper_intent_request_v2, decode_structural_planner_request_v2,
            encode_mapped_workflow_v2, encode_ordered_structural_plan_v2, MappedNodeV2,
            MappedWorkflowV2, OrderedStructuralPlanV2, StructuralNodeIdIssuerV2, StructuralRoleV2,
        };
        use crate::{
            BoundedPlannerSemanticTextV2, DurablePlannerCatalogNamespaceV2,
            MapperEndpointDeploymentV2, PlannerCatalogEntryV2, PlannerCatalogErrorV2,
            PlannerCatalogRollbackAnchorV2, PlannerCatalogStateHeadV2,
        };
        use ed25519_dalek::SigningKey;
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        use rustls::server::WebPkiClientVerifier;
        use rustls::{RootCertStore, ServerConfig, ServerConnection, StreamOwned};
        use savana_kernel_protocol::v2::{
            derive_ed25519_key_id_v2, encode_commit_planner_value_response_v2,
            encode_prepare_planner_call_response_v2, CommitPlannerValueResponseV2, EndpointRoleV2,
            KernelAgentOperationV2, KernelServiceHandshakeEdgeV2, KernelServiceOperationV2,
            MaskedDocumentHandleV2, PeerIdentityBindingV2, PlanRevisionDigestV2, PlanStepHandleV2,
            PreparePlannerCallResponseV2, ServiceIdentityV2,
        };
        use savana_policy_core::v2::{ConnectorStructuralRoleV2, EffectSetV2};
        use sha2::{Digest as _, Sha256};

        struct ObservableGuard {
            held: Rc<Cell<bool>>,
            events: Rc<RefCell<Vec<&'static str>>>,
        }

        impl Drop for ObservableGuard {
            fn drop(&mut self) {
                self.held.set(false);
                self.events.borrow_mut().push("guard_drop");
            }
        }

        #[derive(Default)]
        struct TestCatalogAnchor(Mutex<PlannerCatalogStateHeadV2>);

        impl PlannerCatalogRollbackAnchorV2 for TestCatalogAnchor {
            fn current_head(&self) -> Result<PlannerCatalogStateHeadV2, PlannerCatalogErrorV2> {
                Ok(*self.0.lock().unwrap())
            }

            fn compare_and_advance(
                &mut self,
                expected: PlannerCatalogStateHeadV2,
                next: PlannerCatalogStateHeadV2,
            ) -> Result<(), PlannerCatalogErrorV2> {
                let mut head = self.0.lock().unwrap();
                if *head != expected || next.sequence() != expected.sequence() + 1 {
                    return Err(PlannerCatalogErrorV2::RollbackDetected);
                }
                *head = next;
                Ok(())
            }
        }

        fn tls_fixture(name: &str) -> Vec<u8> {
            let prefix = format!("{name}=");
            let encoded = include_str!("../../savana-execd/tests/fixtures/provider-tls-v2.hex")
                .lines()
                .find_map(|line| line.strip_prefix(&prefix))
                .unwrap();
            encoded
                .as_bytes()
                .chunks_exact(2)
                .map(|pair| {
                    let digit = |byte: u8| match byte {
                        b'0'..=b'9' => byte - b'0',
                        b'a'..=b'f' => byte - b'a' + 10,
                        _ => panic!("non-hex TLS fixture"),
                    };
                    (digit(pair[0]) << 4) | digit(pair[1])
                })
                .collect()
        }

        fn server_pin() -> Digest32V2 {
            let certificate = tls_fixture("server_cert");
            Digest32V2::new(
                Sha256::digest(
                    crate::private_model_transport::certificate_spki_der(&certificate).unwrap(),
                )
                .into(),
            )
        }

        fn deadline_after(duration: Duration) -> UnixMillisV2 {
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
            UnixMillisV2::new(u64::try_from((now + duration).as_millis()).unwrap())
        }

        fn model_server_config() -> ServerConfig {
            let mut client_roots = RootCertStore::empty();
            client_roots
                .add(CertificateDer::from(tls_fixture("ca_cert")))
                .unwrap();
            let verifier = WebPkiClientVerifier::builder(Arc::new(client_roots))
                .build()
                .unwrap();
            let mut config = ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_client_cert_verifier(verifier)
            .with_single_cert(
                vec![CertificateDer::from(tls_fixture("server_cert"))],
                PrivateKeyDer::try_from(tls_fixture("server_key")).unwrap(),
            )
            .unwrap();
            config.alpn_protocols = vec![b"http/1.1".to_vec()];
            config
        }

        fn spawn_model_server<F>(
            listener: TcpListener,
            expected_path: &'static str,
            calls: Arc<AtomicUsize>,
            respond: F,
        ) -> thread::JoinHandle<()>
        where
            F: FnOnce(Vec<u8>) -> Vec<u8> + Send + 'static,
        {
            thread::spawn(move || {
                listener.set_nonblocking(true).unwrap();
                let accept_deadline = Instant::now() + Duration::from_secs(3);
                let (socket, _) = loop {
                    match listener.accept() {
                        Ok(accepted) => break accepted,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            if Instant::now() >= accept_deadline {
                                return;
                            }
                            thread::yield_now();
                        }
                        Err(error) => panic!("model listener failed: {error}"),
                    }
                };
                socket.set_nonblocking(false).unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                socket
                    .set_write_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut tls = StreamOwned::new(
                    ServerConnection::new(Arc::new(model_server_config())).unwrap(),
                    socket,
                );
                let mut header = Vec::new();
                while !header.ends_with(b"\r\n\r\n") {
                    let mut byte = [0_u8; 1];
                    tls.read_exact(&mut byte).unwrap();
                    header.push(byte[0]);
                }
                let header_text = std::str::from_utf8(&header).unwrap();
                assert!(header_text.starts_with(&format!("POST {expected_path} HTTP/1.1\r\n")));
                let length = header_text
                    .split("\r\n")
                    .find_map(|line| line.strip_prefix("Content-Length: "))
                    .unwrap()
                    .parse::<usize>()
                    .unwrap();
                let mut body = vec![0_u8; length];
                tls.read_exact(&mut body).unwrap();
                assert!(tls
                    .conn
                    .peer_certificates()
                    .is_some_and(|certificates| !certificates.is_empty()));
                calls.fetch_add(1, Ordering::SeqCst);
                let response = respond(body);
                write!(
                    tls,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/cbor\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    response.len()
                )
                .unwrap();
                tls.write_all(&response).unwrap();
                tls.flush().unwrap();
                tls.conn.send_close_notify();
                let _ = tls.conn.complete_io(&mut tls.sock);
            })
        }

        fn deployment_edge(
            role: EndpointRoleV2,
            client_key: &SigningKey,
            server_key: &SigningKey,
        ) -> KernelServiceHandshakeEdgeV2 {
            KernelServiceHandshakeEdgeV2::from_verified_deployment(
                role,
                Digest32V2::new([0x81; 32]),
                ServiceIdentityV2::new([0x82; 32]),
                ServiceIdentityV2::new([0x83; 32]),
                derive_ed25519_key_id_v2(client_key.verifying_key().to_bytes()),
                derive_ed25519_key_id_v2(server_key.verifying_key().to_bytes()),
                BootIdV2::new([0x84; 32]),
                1,
                Digest32V2::new([0x85; 32]),
                1,
                1,
                Digest32V2::new([0x86; 32]),
                Digest32V2::new([0x87; 32]),
                Digest32V2::new([0x88; 32]),
                Digest32V2::new([0x89; 32]),
                Digest32V2::new([0x8a; 32]),
                Digest32V2::new([0x8b; 32]),
            )
            .unwrap()
        }

        #[derive(Default)]
        struct PipelineCalls {
            prepare: AtomicUsize,
            commit: AtomicUsize,
            mapper: AtomicUsize,
            planner: AtomicUsize,
        }

        struct ActFixture {
            authority: AgentBrowserAuthorityV2,
            tab: AgentTabSessionCapabilityV2,
            calls: Arc<PipelineCalls>,
            mapper_server: thread::JoinHandle<()>,
            planner_server: thread::JoinHandle<()>,
            _directory: tempfile::TempDir,
        }

        fn act_fixture(commit_fails: bool) -> ActFixture {
            let directory = tempfile::tempdir().unwrap();
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                .unwrap();
            let calls = Arc::new(PipelineCalls::default());
            let active = ActiveToolViewV2::new(
                ToolHandleV2::from_authority_entropy([0x91; 32]).unwrap(),
                ActionTemplateIdV2::new(10),
                ToolClassIdV2::new(100),
                StaticTemplateIdV2::new(7),
            )
            .unwrap();

            let mapper_listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let mapper_address = mapper_listener.local_addr().unwrap();
            let mapper_calls = Arc::clone(&calls);
            let mapper_server = spawn_model_server(
                mapper_listener,
                "/savana.mapper.v2/map",
                Arc::new(AtomicUsize::new(0)),
                move |body| {
                    mapper_calls.mapper.fetch_add(1, Ordering::SeqCst);
                    let request = decode_mapper_intent_request_v2(&body).unwrap();
                    assert_eq!(request.available_tools().len(), 1);
                    assert_eq!(
                        request.available_tools()[0].semantic_name(),
                        "customer_lookup"
                    );
                    let node = MappedNodeV2::new(
                        1,
                        ToolClassIdV2::new(100),
                        ActionTemplateIdV2::new(10),
                        vec![],
                        StructuralRoleV2::Source,
                        EffectSetV2::READ,
                    )
                    .unwrap();
                    encode_mapped_workflow_v2(
                        &MappedWorkflowV2::new(&request, vec![node], vec![]).unwrap(),
                    )
                    .unwrap()
                },
            );

            let planner_listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let planner_address = planner_listener.local_addr().unwrap();
            let planner_calls = Arc::clone(&calls);
            let planner_server = spawn_model_server(
                planner_listener,
                "/savana.planner.v2/plan",
                Arc::new(AtomicUsize::new(0)),
                move |body| {
                    planner_calls.planner.fetch_add(1, Ordering::SeqCst);
                    let request = decode_structural_planner_request_v2(&body).unwrap();
                    assert_eq!(request.graph().nodes().len(), 1);
                    encode_ordered_structural_plan_v2(
                        &OrderedStructuralPlanV2::new(vec![request.graph().nodes()[0].id()])
                            .unwrap(),
                    )
                    .unwrap()
                },
            );

            let mapper = PinnedMtlsAgentMapperClientV2::from_verified_deployment(
                IntentTrustDeploymentCeilingV2::UserMayUseThirdParty,
                MapperEndpointDeploymentV2::new(
                    "provider.example".to_owned(),
                    mapper_address.port(),
                    vec![mapper_address],
                    server_pin(),
                )
                .unwrap(),
                Some(
                    MapperEndpointDeploymentV2::new(
                        "provider.example".to_owned(),
                        mapper_address.port(),
                        vec![mapper_address],
                        server_pin(),
                    )
                    .unwrap(),
                ),
                tls_fixture("ca_cert"),
                tls_fixture("client_cert"),
                Zeroizing::new(tls_fixture("client_key")),
            )
            .unwrap();
            let planner = PinnedMtlsAgentPlannerClientV2::from_verified_deployment(
                "provider.example".to_owned(),
                planner_address.port(),
                vec![planner_address],
                server_pin(),
                tls_fixture("ca_cert"),
                tls_fixture("client_cert"),
                Zeroizing::new(tls_fixture("client_key")),
            )
            .unwrap();

            let kernel_client_key = SigningKey::from_bytes(&[0x92; 32]);
            let kernel_server_key = SigningKey::from_bytes(&[0x93; 32]);
            let task_authority_key = SigningKey::from_bytes(&[0x94; 32]);
            let kernel_calls = Arc::clone(&calls);
            let kernel = SuiteOneAgentKernelClientV2::from_verified_deployment(
                deployment_edge(
                    EndpointRoleV2::AgentKernel,
                    &kernel_client_key,
                    &kernel_server_key,
                ),
                BootIdV2::new([0x95; 32]),
                PeerIdentityBindingV2::linux(501, 20, 42, 99, Digest32V2::new([0x96; 32])).unwrap(),
                kernel_client_key,
                kernel_server_key.verifying_key().to_bytes(),
                derive_ed25519_key_id_v2(task_authority_key.verifying_key().to_bytes()),
                task_authority_key.verifying_key().to_bytes(),
            )
            .unwrap()
            .with_operation_exchange_for_test(move |_, deadline, operation| match operation {
                KernelServiceOperationV2::Agent(KernelAgentOperationV2::PreparePlannerCall(
                    request,
                )) => {
                    kernel_calls.prepare.fetch_add(1, Ordering::SeqCst);
                    let envelope = savana_kernel_protocol::v2::PlannerEnvelopeV2::new(
                        request.planner_route(),
                        request.task_template(),
                        request.intent(),
                        vec![ActionTemplateIdV2::new(10)],
                        vec![],
                        vec![],
                        request.limits(),
                        Nonce32V2::new([0x97; 32]),
                        deadline,
                    )
                    .unwrap();
                    let digest = Digest32V2::new(
                        Sha256::digest(minicbor::to_vec(&envelope).unwrap()).into(),
                    );
                    encode_prepare_planner_call_response_v2(
                        &PreparePlannerCallResponseV2::new(
                            PlannerTicketHandleV2::from_authority_entropy([0x98; 32]).unwrap(),
                            envelope,
                            digest,
                            Digest32V2::new([0x99; 32]),
                            deadline,
                        )
                        .unwrap(),
                    )
                    .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)
                }
                KernelServiceOperationV2::Agent(KernelAgentOperationV2::CommitPlannerValue(
                    request,
                )) => {
                    kernel_calls.commit.fetch_add(1, Ordering::SeqCst);
                    assert_eq!(request.plan().steps().len(), 1);
                    if commit_fails {
                        return Err(AgentControlKernelClientErrorV2::Unavailable);
                    }
                    encode_commit_planner_value_response_v2(
                        &CommitPlannerValueResponseV2::new(
                            ValueHandleV2::from_authority_entropy([0x9a; 32]).unwrap(),
                            Digest32V2::new([0x9b; 32]),
                            PlanRevisionDigestV2::new([0x9c; 32]),
                            vec![PlanStepHandleV2::from_authority_entropy([0x9d; 32]).unwrap()],
                        )
                        .unwrap(),
                    )
                    .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)
                }
                _ => panic!("unexpected fake-kernel operation"),
            });

            let approval_client_key = SigningKey::from_bytes(&[0xa1; 32]);
            let approval_server_key = SigningKey::from_bytes(&[0xa2; 32]);
            let approval = ApprovalSuiteOneClientV2::from_verified_deployment(
                deployment_edge(
                    EndpointRoleV2::AgentApproval,
                    &approval_client_key,
                    &approval_server_key,
                ),
                BootIdV2::new([0xa3; 32]),
                PeerIdentityBindingV2::linux(501, 20, 43, 100, Digest32V2::new([0xa4; 32]))
                    .unwrap(),
                approval_client_key,
                approval_server_key.verifying_key().to_bytes(),
            )
            .unwrap();

            let gate_path = directory.path().join("effect-gate-v2");
            File::create(&gate_path).unwrap();
            let gate_file = OpenOptions::new().read(true).open(&gate_path).unwrap();
            let effect_gate =
                EffectGateCoordinatorV2::from_shared_only_descriptor(gate_file).unwrap();
            let catalog_entry = PlannerCatalogEntryV2::new(
                ToolClassIdV2::new(100),
                ActionTemplateIdV2::new(10),
                ConnectorStructuralRoleV2::Source,
                EffectSetV2::READ,
                BoundedPlannerSemanticTextV2::new("customer_lookup").unwrap(),
                BoundedPlannerSemanticTextV2::new("query private customer records").unwrap(),
            )
            .unwrap();
            let planner_catalog = DurablePlannerCatalogV2::open(
                &directory.path().join("planner-catalog-state-v2.cbor"),
                [0xa5; 32],
                DurablePlannerCatalogNamespaceV2::from_verified_installation(
                    Digest32V2::new([0xa6; 32]),
                    Digest32V2::new([0xa7; 32]),
                )
                .unwrap(),
                Box::<TestCatalogAnchor>::default(),
                vec![catalog_entry],
            )
            .unwrap();
            let boot = BootIdV2::new([0xa8; 32]);
            let mut authority = AgentBrowserAuthorityV2::new(
                effect_gate,
                kernel,
                approval,
                mapper,
                planner,
                PlannerRouteIdV2::new(9),
                StaticTemplateIdV2::new(7),
                PlannerIntentKindV2::Search,
                PlannerLimitsV2::new(2, 1, 1, 4096).unwrap(),
                ExecutorIdentityV2::new([0xa9; 32]),
                ProjectionIdV2::new(10),
                DisplayProjectionIdV2::new(11),
                boot,
                planner_catalog,
                StructuralNodeIdIssuerV2::new().unwrap(),
            );
            let tab = AgentTabSessionCapabilityV2::from_authority_entropy([0xaa; 32]).unwrap();
            let mut tab_state = tab_record(tab, boot, FixedOriginV2::Agent8768, None);
            tab_state.kernel_document =
                Some(MaskedDocumentHandleV2::from_authority_entropy([0xab; 32]).unwrap());
            tab_state.session =
                Some(AgentSessionHandleV2::from_authority_entropy([0xac; 32]).unwrap());
            tab_state.run = Some(RunHandleV2::from_authority_entropy([0xad; 32]).unwrap());
            tab_state.initial_value =
                Some(ValueHandleV2::from_authority_entropy([0xae; 32]).unwrap());
            tab_state.active_tools = vec![active];
            authority.state.get_mut().unwrap().tabs.push(tab_state);

            ActFixture {
                authority,
                tab,
                calls,
                mapper_server,
                planner_server,
                _directory: directory,
            }
        }

        #[test]
        fn planner_privacy_pipeline_orders_and_holds_guard_through_commit() {
            let events = Rc::new(RefCell::new(vec!["guard_acquire"]));
            let held = Rc::new(Cell::new(true));
            let guard = ObservableGuard {
                held: Rc::clone(&held),
                events: Rc::clone(&events),
            };
            let run = RunHandleV2::from_authority_entropy([0x31; 32]).unwrap();
            let ticket = PlannerTicketHandleV2::from_authority_entropy([0x32; 32]).unwrap();
            let active = ActiveToolViewV2::new(
                ToolHandleV2::from_authority_entropy([0x33; 32]).unwrap(),
                ActionTemplateIdV2::new(10),
                ToolClassIdV2::new(100),
                StaticTemplateIdV2::new(7),
            )
            .unwrap();
            let envelope = savana_kernel_protocol::v2::PlannerEnvelopeV2::new(
                PlannerRouteIdV2::new(9),
                StaticTemplateIdV2::new(7),
                PlannerIntentKindV2::Search,
                vec![ActionTemplateIdV2::new(10)],
                vec![],
                vec![],
                PlannerLimitsV2::new(2, 1, 1, 4096).unwrap(),
                Nonce32V2::new([0x34; 32]),
                UnixMillisV2::new(99_999),
            )
            .unwrap();
            let envelope_digest =
                Digest32V2::new(Sha256::digest(minicbor::to_vec(&envelope).unwrap()).into());
            let prepared = PreparePlannerCallResponseV2::new(
                ticket,
                envelope,
                envelope_digest,
                Digest32V2::new([0x35; 32]),
                UnixMillisV2::new(99_999),
            )
            .unwrap();
            let catalog_entry = PlannerCatalogEntryV2::new(
                ToolClassIdV2::new(100),
                ActionTemplateIdV2::new(10),
                ConnectorStructuralRoleV2::Source,
                EffectSetV2::READ,
                BoundedPlannerSemanticTextV2::new("customer_lookup").unwrap(),
                BoundedPlannerSemanticTextV2::new("query private customer records").unwrap(),
            )
            .unwrap();
            let issuer = Mutex::new(StructuralNodeIdIssuerV2::new().unwrap());

            let result = execute_private_planning_pipeline_v2(
                guard,
                run,
                &[active],
                &issuer,
                IntentTrustBoundaryV2::Private,
                {
                    let events = Rc::clone(&events);
                    move || {
                        events.borrow_mut().push("prepare");
                        Ok(prepared)
                    }
                },
                {
                    let events = Rc::clone(&events);
                    move |_| {
                        events.borrow_mut().push("catalog");
                        Ok(vec![catalog_entry])
                    }
                },
                {
                    let events = Rc::clone(&events);
                    move |request, boundary| {
                        events.borrow_mut().push("mapper");
                        assert_eq!(boundary, IntentTrustBoundaryV2::Private);
                        assert_eq!(
                            request.available_tools()[0].semantic_name(),
                            "customer_lookup"
                        );
                        let node = MappedNodeV2::new(
                            1,
                            ToolClassIdV2::new(100),
                            ActionTemplateIdV2::new(10),
                            vec![],
                            StructuralRoleV2::Source,
                            EffectSetV2::READ,
                        )
                        .unwrap();
                        Ok(MappedWorkflowV2::new(request, vec![node], vec![]).unwrap())
                    }
                },
                {
                    let events = Rc::clone(&events);
                    move |request| {
                        events.borrow_mut().push("planner");
                        Ok(
                            OrderedStructuralPlanV2::new(vec![request.graph().nodes()[0].id()])
                                .unwrap(),
                        )
                    }
                },
                {
                    let events = Rc::clone(&events);
                    let held = Rc::clone(&held);
                    move |request| {
                        events.borrow_mut().push("commit");
                        assert!(held.get());
                        assert_eq!(request.plan().envelope_nonce(), Nonce32V2::new([0x34; 32]));
                        CommitPlannerValueResponseV2::new(
                            ValueHandleV2::from_authority_entropy([0x36; 32]).unwrap(),
                            Digest32V2::new([0x37; 32]),
                            PlanRevisionDigestV2::new([0x38; 32]),
                            vec![PlanStepHandleV2::from_authority_entropy([0x39; 32]).unwrap()],
                        )
                        .map_err(|_| AgentBrowserAuthorityErrorV2::Unavailable)
                    }
                },
            )
            .unwrap();

            assert_eq!(result.plan().steps().len(), 1);
            assert_eq!(result.committed().steps().len(), 1);
            assert_eq!(
                events.borrow().as_slice(),
                [
                    "guard_acquire",
                    "prepare",
                    "catalog",
                    "mapper",
                    "planner",
                    "commit",
                    "guard_drop"
                ]
            );
        }

        #[test]
        fn real_act_run_planner_caches_success_without_repeating_any_effect() {
            let fixture = act_fixture(false);
            let nonce = Nonce32V2::new([0xb1; 32]);
            let request = || AgentBrowserRequestV2::Act {
                tab: fixture.tab,
                client_request_nonce: nonce,
                action: AgentBrowserActionV2::RunPlanner,
            };
            let deadline = deadline_after(Duration::from_secs(5));

            let first_result = fixture.authority.act(request(), deadline);
            fixture.mapper_server.join().unwrap();
            fixture.planner_server.join().unwrap();
            let first = first_result.unwrap_or_else(|error| {
                panic!(
                    "first act failed at counts prepare={} mapper={} planner={} commit={}: {error:?}",
                    fixture.calls.prepare.load(Ordering::SeqCst),
                    fixture.calls.mapper.load(Ordering::SeqCst),
                    fixture.calls.planner.load(Ordering::SeqCst),
                    fixture.calls.commit.load(Ordering::SeqCst),
                )
            });
            let replay = fixture.authority.act(request(), deadline).unwrap();

            assert_eq!(replay, first);
            assert_eq!(fixture.calls.prepare.load(Ordering::SeqCst), 1);
            assert_eq!(fixture.calls.mapper.load(Ordering::SeqCst), 1);
            assert_eq!(fixture.calls.planner.load(Ordering::SeqCst), 1);
            assert_eq!(fixture.calls.commit.load(Ordering::SeqCst), 1);
        }

        #[test]
        fn real_act_failed_effect_claim_fences_same_nonce_and_boundary_rebinding() {
            let fixture = act_fixture(true);
            let nonce = Nonce32V2::new([0xb2; 32]);
            let request = |action| AgentBrowserRequestV2::Act {
                tab: fixture.tab,
                client_request_nonce: nonce,
                action,
            };
            let deadline = deadline_after(Duration::from_secs(5));

            let first = fixture
                .authority
                .act(request(AgentBrowserActionV2::RunPlanner), deadline);
            fixture.mapper_server.join().unwrap();
            fixture.planner_server.join().unwrap();
            assert_eq!(first, Err(AgentBrowserAuthorityErrorV2::Unavailable));
            let counts_after_effect = (
                fixture.calls.prepare.load(Ordering::SeqCst),
                fixture.calls.mapper.load(Ordering::SeqCst),
                fixture.calls.planner.load(Ordering::SeqCst),
                fixture.calls.commit.load(Ordering::SeqCst),
            );
            assert_eq!(counts_after_effect, (1, 1, 1, 1));

            assert_eq!(
                fixture
                    .authority
                    .act(request(AgentBrowserActionV2::RunPlanner), deadline),
                Err(AgentBrowserAuthorityErrorV2::StateConflict)
            );
            assert_eq!(
                fixture.authority.act(
                    request(AgentBrowserActionV2::RunPlannerWithThirdPartyMapper),
                    deadline,
                ),
                Err(AgentBrowserAuthorityErrorV2::StateConflict)
            );
            assert_eq!(
                (
                    fixture.calls.prepare.load(Ordering::SeqCst),
                    fixture.calls.mapper.load(Ordering::SeqCst),
                    fixture.calls.planner.load(Ordering::SeqCst),
                    fixture.calls.commit.load(Ordering::SeqCst),
                ),
                counts_after_effect
            );
        }
    }

    fn tab_record(
        tab: AgentTabSessionCapabilityV2,
        agentd_boot_id: BootIdV2,
        origin: FixedOriginV2,
        authorization: Option<AgentUiAuthorizationHandleV2>,
    ) -> AgentTabV2 {
        AgentTabV2 {
            tab,
            authorization,
            initial_document: AgentMaskedDocumentRefV2::from_authority_entropy([0x11; 16]).unwrap(),
            kernel_document: None,
            session: None,
            run: None,
            initial_value: None,
            active_tools: Vec::new(),
            reference_key: Zeroizing::new([0x12; 32]),
            tab_internal_id: Digest32V2::new([0x13; 32]),
            agentd_boot_id,
            origin,
            next_reference_revision: 1,
            objects: Vec::new(),
            pending_releases: Vec::new(),
            pending_connectors: Vec::new(),
            cursors: Vec::new(),
            replays: Vec::new(),
            action_replays: Vec::new(),
        }
    }

    fn pending_connector_record() -> PendingConnectorRegistrationV2 {
        PendingConnectorRegistrationV2 {
            reference: AgentPendingConnectorRegistrationRefV2::from_authority_entropy([0x41; 16])
                .unwrap(),
            kernel: PendingConnectorRegistrationHandleV2::from_authority_entropy([0x42; 32])
                .unwrap(),
            approvald: ConnectorApprovalRecordHandleV2::from_authority_entropy([0x43; 32])
                .unwrap(),
            transfer: savana_kernel_protocol::v2::ApprovalDisplayAuthenticationTransferCapabilityV2::from_authority_entropy(
                [0x44; 32],
            )
            .unwrap(),
            canonical_descriptor: Arc::new(Zeroizing::new(
                b"private canonical connector descriptor".to_vec(),
            )),
        }
    }

    #[test]
    fn planner_actions_bind_private_default_and_explicit_third_party_per_request() {
        assert_eq!(
            planner_intent_boundary_for_action_v2(&AgentBrowserActionV2::RunPlanner).unwrap(),
            IntentTrustBoundaryV2::Private
        );
        assert_eq!(
            planner_intent_boundary_for_action_v2(
                &AgentBrowserActionV2::RunPlannerWithThirdPartyMapper
            )
            .unwrap(),
            IntentTrustBoundaryV2::ThirdParty
        );
        assert!(IntentTrustDeploymentCeilingV2::PrivateOnly.permits(IntentTrustBoundaryV2::Private));
        assert!(
            !IntentTrustDeploymentCeilingV2::PrivateOnly.permits(IntentTrustBoundaryV2::ThirdParty)
        );
        assert!(IntentTrustDeploymentCeilingV2::UserMayUseThirdParty
            .permits(IntentTrustBoundaryV2::ThirdParty));

        let tab = AgentTabSessionCapabilityV2::from_authority_entropy([0x5a; 32]).unwrap();
        assert_ne!(
            browser_action_request_digest(tab, AgentBrowserActionV2::RunPlanner).unwrap(),
            browser_action_request_digest(
                tab,
                AgentBrowserActionV2::RunPlannerWithThirdPartyMapper
            )
            .unwrap()
        );
    }

    #[test]
    fn planner_action_nonce_replay_cannot_rebind_private_to_third_party() {
        let tab = AgentTabSessionCapabilityV2::from_authority_entropy([0x5b; 32]).unwrap();
        let nonce = Nonce32V2::new([0x5c; 32]);
        let private_digest =
            browser_action_request_digest(tab, AgentBrowserActionV2::RunPlanner).unwrap();
        let third_party_digest = browser_action_request_digest(
            tab,
            AgentBrowserActionV2::RunPlannerWithThirdPartyMapper,
        )
        .unwrap();
        let response = AgentBrowserMutationResponseV2::PlannerCommitted { steps: vec![] };
        let replays = vec![ActionReplayV2 {
            request_digest: private_digest,
            nonce,
            response: Some(response.clone()),
        }];

        assert_eq!(
            resolve_action_replay_v2(&replays, nonce, private_digest),
            Some(Ok(response))
        );
        assert_eq!(
            resolve_action_replay_v2(&replays, nonce, third_party_digest),
            Some(Err(AgentBrowserAuthorityErrorV2::StateConflict))
        );
    }

    #[test]
    fn failed_planner_action_claim_blocks_rebinding_and_retry_before_more_side_effects() {
        let tab_capability =
            AgentTabSessionCapabilityV2::from_authority_entropy([0x5d; 32]).unwrap();
        let mut tab = tab_record(
            tab_capability,
            BootIdV2::new([0x5e; 32]),
            FixedOriginV2::Agent8768,
            None,
        );
        let nonce = Nonce32V2::new([0x5f; 32]);
        let private_action = AgentBrowserActionV2::RunPlanner;
        let third_party_action = AgentBrowserActionV2::RunPlannerWithThirdPartyMapper;
        assert!(IntentTrustDeploymentCeilingV2::UserMayUseThirdParty
            .permits(planner_intent_boundary_for_action_v2(&private_action).unwrap()));
        assert!(IntentTrustDeploymentCeilingV2::UserMayUseThirdParty
            .permits(planner_intent_boundary_for_action_v2(&third_party_action).unwrap()));
        let private_digest =
            browser_action_request_digest(tab_capability, private_action.clone()).unwrap();
        let third_party_digest =
            browser_action_request_digest(tab_capability, third_party_action).unwrap();
        let side_effect_calls = Cell::new(0_u8);

        assert_eq!(
            execute_action_nonce_bound_v2(&mut tab, nonce, private_digest, |_| {
                side_effect_calls.set(side_effect_calls.get() + 1);
                Err(AgentBrowserAuthorityErrorV2::Unavailable)
            }),
            Err(AgentBrowserAuthorityErrorV2::Unavailable)
        );
        assert_eq!(side_effect_calls.get(), 1);

        assert_eq!(
            execute_action_nonce_bound_v2(&mut tab, nonce, third_party_digest, |_| {
                side_effect_calls.set(side_effect_calls.get() + 1);
                Ok(AgentBrowserMutationResponseV2::PlannerCommitted { steps: vec![] })
            }),
            Err(AgentBrowserAuthorityErrorV2::StateConflict)
        );
        assert_eq!(side_effect_calls.get(), 1);

        assert_eq!(
            execute_action_nonce_bound_v2(&mut tab, nonce, private_digest, |_| {
                side_effect_calls.set(side_effect_calls.get() + 1);
                Ok(AgentBrowserMutationResponseV2::PlannerCommitted { steps: vec![] })
            }),
            Err(AgentBrowserAuthorityErrorV2::StateConflict)
        );
        assert_eq!(side_effect_calls.get(), 1);
    }

    #[test]
    fn mapper_boundary_choice_cannot_change_kernel_planner_payloads() {
        let run = RunHandleV2::from_authority_entropy([0x61; 32]).unwrap();
        let initial = ValueHandleV2::from_authority_entropy([0x62; 32]).unwrap();
        let ticket = PlannerTicketHandleV2::from_authority_entropy([0x63; 32]).unwrap();
        let limits = PlannerLimitsV2::new(4, 3, 2, 4096).unwrap();
        let plan = PlannerPlanV2::new(
            Nonce32V2::new([0x64; 32]),
            vec![PlannerStepV2::new(
                1,
                ActionTemplateIdV2::new(10),
                ToolClassIdV2::new(100),
                vec![],
                vec![],
            )
            .unwrap()],
        )
        .unwrap();
        let payloads = |boundary| {
            assert!(IntentTrustDeploymentCeilingV2::UserMayUseThirdParty.permits(boundary));
            let prepare = planner_prepare_call_request_v2(
                run,
                PlannerRouteIdV2::new(7),
                StaticTemplateIdV2::new(8),
                PlannerIntentKindV2::Search,
                limits,
                initial,
            )
            .unwrap();
            let commit = planner_commit_value_request_v2(run, ticket, plan.clone());
            (
                prepare.clone(),
                commit.clone(),
                encode_kernel_agent_operation_v2(&KernelAgentOperationV2::PreparePlannerCall(
                    prepare,
                ))
                .unwrap(),
                encode_kernel_agent_operation_v2(&KernelAgentOperationV2::CommitPlannerValue(
                    commit,
                ))
                .unwrap(),
            )
        };
        let private = payloads(
            planner_intent_boundary_for_action_v2(&AgentBrowserActionV2::RunPlanner).unwrap(),
        );
        let third_party = payloads(
            planner_intent_boundary_for_action_v2(
                &AgentBrowserActionV2::RunPlannerWithThirdPartyMapper,
            )
            .unwrap(),
        );
        assert_eq!(private, third_party);
    }

    fn connector_settlement(decision: ApprovalDecisionV2) -> SignedApprovalSettlementV2 {
        SignedApprovalSettlementV2::sign(
            UnsignedApprovalSettlementV2::new(
                Digest32V2::new([0x45; 32]),
                Digest32V2::new([0x46; 32]),
                7,
                ApprovalPurposeV2::ConnectorRegistration,
                Digest32V2::new([0x47; 32]),
                decision,
                PrincipalIdV2::new([0x48; 32]),
                Digest32V2::new([0x49; 32]),
                Digest32V2::new([0x4a; 32]),
                true,
                true,
                false,
                false,
                1,
                Nonce32V2::new([0x4b; 32]),
                Nonce32V2::new([0x4c; 32]),
                UnixMillisV2::new(100),
                UnixMillisV2::new(200),
            )
            .unwrap(),
            &SigningKey::from_bytes(&[0x4d; 32]),
        )
        .unwrap()
    }

    #[test]
    fn rejected_connector_prepare_or_propose_never_changes_the_real_catalog() {
        let (_directory, catalog) = empty_connector_test_catalog();
        for _ in 0..4_097 {
            assert_eq!(
                prepare_and_propose_connector_registration(
                    || Err::<(), _>(AgentBrowserAuthorityErrorV2::InvalidReference),
                    |_: ()| -> Result<(), AgentBrowserAuthorityErrorV2> { unreachable!() },
                ),
                Err(AgentBrowserAuthorityErrorV2::InvalidReference),
            );
        }
        assert!(catalog.entries().is_empty());

        assert_eq!(
            prepare_and_propose_connector_registration(
                || Ok(7_u8),
                |_| Err::<(), _>(AgentBrowserAuthorityErrorV2::StateConflict),
            ),
            Err(AgentBrowserAuthorityErrorV2::StateConflict),
        );
        assert!(catalog.entries().is_empty());
    }

    #[test]
    fn connector_finalize_reopens_pending_and_rejects_terminal_nonapproval_without_kernel_calls() {
        let pending = pending_connector_record();
        let calls = Cell::new(0_u8);
        let mut tab = tab_record(
            AgentTabSessionCapabilityV2::from_authority_entropy([0x71; 32]).unwrap(),
            BootIdV2::new([0x72; 32]),
            FixedOriginV2::Agent8768,
            None,
        );
        tab.pending_connectors.push(pending.clone());
        let reopened = finalize_connector_registration_settlement(
            &mut tab,
            0,
            ApprovalSettlementViewV2::Pending,
            |_| {
                calls.set(calls.get() + 1);
                unreachable!()
            },
            |_| {
                calls.set(calls.get() + 1);
                unreachable!()
            },
            |_| {
                calls.set(calls.get() + 1);
                unreachable!()
            },
        )
        .unwrap();
        assert_eq!(calls.get(), 0);
        assert_eq!(
            reopened,
            AgentBrowserMutationResponseV2::ConnectorOpenApproval {
                pending: pending.reference,
                post: FixedBrowserFormPostCarrierV2::AgentApprovalDisplay(pending.transfer),
            }
        );
        assert_eq!(tab.pending_connectors.len(), 1);

        for settlement in [
            ApprovalSettlementViewV2::Denied {
                settlement: connector_settlement(ApprovalDecisionV2::Deny),
            },
            ApprovalSettlementViewV2::Expired,
        ] {
            let mut tab = tab_record(
                AgentTabSessionCapabilityV2::from_authority_entropy([0x73; 32]).unwrap(),
                BootIdV2::new([0x74; 32]),
                FixedOriginV2::Agent8768,
                None,
            );
            tab.pending_connectors.push(pending.clone());
            assert_eq!(
                finalize_connector_registration_settlement(
                    &mut tab,
                    0,
                    settlement,
                    |_| {
                        calls.set(calls.get() + 1);
                        unreachable!()
                    },
                    |_| {
                        calls.set(calls.get() + 1);
                        unreachable!()
                    },
                    |_| {
                        calls.set(calls.get() + 1);
                        unreachable!()
                    },
                ),
                Err(AgentBrowserAuthorityErrorV2::StateConflict)
            );
            assert!(tab.pending_connectors.is_empty());
        }
        assert_eq!(calls.get(), 0);
    }

    #[test]
    fn approved_connector_finalize_authorizes_then_applies_exact_commit_evidence() {
        let pending = pending_connector_record();
        let settlement = connector_settlement(ApprovalDecisionV2::Approve);
        let expected_settlement = settlement.clone();
        let approved =
            ApprovedConnectorRegistrationHandleV2::from_authority_entropy([0x51; 32]).unwrap();
        let signed_delta_digest = Digest32V2::new([0x54; 32]);
        let head_digest = Digest32V2::new([0x52; 32]);
        let connector_id = Digest32V2::new([0x53; 32]);
        let stage = Cell::new(0_u8);
        let mut tab = tab_record(
            AgentTabSessionCapabilityV2::from_authority_entropy([0x75; 32]).unwrap(),
            BootIdV2::new([0x76; 32]),
            FixedOriginV2::Agent8768,
            None,
        );
        tab.pending_connectors.push(pending.clone());
        let response = finalize_connector_registration_settlement(
            &mut tab,
            0,
            ApprovalSettlementViewV2::Approved { settlement },
            |request| {
                assert_eq!(stage.get(), 0);
                stage.set(1);
                assert_eq!(request.pending(), pending.kernel);
                assert_eq!(request.settlement(), &expected_settlement);
                Ok(AuthorizeConnectorRegistrationResponseV2::new(approved))
            },
            |descriptor| {
                assert_eq!(stage.get(), 1);
                stage.set(2);
                assert_eq!(descriptor, pending.canonical_descriptor.as_slice());
                Ok(())
            },
            |request| {
                assert_eq!(stage.get(), 2);
                stage.set(3);
                assert_eq!(request.approved(), approved);
                ApplyApprovedConnectorRegistrationResponseV2::new(
                    signed_delta_digest,
                    head_digest,
                    9,
                    connector_id,
                )
                .map_err(|_| AgentBrowserAuthorityErrorV2::StateConflict)
            },
        )
        .unwrap();
        assert_eq!(stage.get(), 3);
        assert!(tab.pending_connectors.is_empty());
        assert_eq!(
            response,
            AgentBrowserMutationResponseV2::ConnectorRegistrationCommitted {
                pending: pending.reference,
                signed_delta_digest,
                head_digest,
                sequence: 9,
                connector_id,
            }
        );
    }

    #[test]
    fn approved_catalog_failure_skips_apply_and_retains_pending_for_new_nonce_retry() {
        let pending = pending_connector_record();
        let settlement = connector_settlement(ApprovalDecisionV2::Approve);
        let approved =
            ApprovedConnectorRegistrationHandleV2::from_authority_entropy([0x77; 32]).unwrap();
        let apply_calls = Cell::new(0_u8);
        let mut tab = tab_record(
            AgentTabSessionCapabilityV2::from_authority_entropy([0x78; 32]).unwrap(),
            BootIdV2::new([0x79; 32]),
            FixedOriginV2::Agent8768,
            None,
        );
        tab.pending_connectors.push(pending);

        assert_eq!(
            finalize_connector_registration_settlement(
                &mut tab,
                0,
                ApprovalSettlementViewV2::Approved { settlement },
                |_| Ok(AuthorizeConnectorRegistrationResponseV2::new(approved)),
                |_| Err(AgentBrowserAuthorityErrorV2::Unavailable),
                |_| {
                    apply_calls.set(apply_calls.get() + 1);
                    unreachable!()
                },
            ),
            Err(AgentBrowserAuthorityErrorV2::Unavailable),
        );
        assert_eq!(apply_calls.get(), 0);
        assert_eq!(tab.pending_connectors.len(), 1);
    }

    #[test]
    fn more_than_catalog_capacity_unapproved_requests_leave_room_for_same_key_approval() {
        let (_directory, mut catalog) = empty_connector_test_catalog();
        let pending = pending_connector_record();
        for index in 0..4_097_u32 {
            let mut tab = tab_record(
                AgentTabSessionCapabilityV2::from_authority_entropy(
                    (index + 1).to_be_bytes().repeat(8).try_into().unwrap(),
                )
                .unwrap(),
                BootIdV2::new([0x7a; 32]),
                FixedOriginV2::Agent8768,
                None,
            );
            tab.pending_connectors.push(pending.clone());
            assert_eq!(
                finalize_connector_registration_settlement(
                    &mut tab,
                    0,
                    ApprovalSettlementViewV2::Expired,
                    |_| unreachable!(),
                    |_| {
                        catalog
                            .insert_entries(vec![connector_test_catalog_conflict_entry()])
                            .map_err(|_| AgentBrowserAuthorityErrorV2::Unavailable)?;
                        Ok(())
                    },
                    |_| unreachable!(),
                ),
                Err(AgentBrowserAuthorityErrorV2::StateConflict),
            );
            assert!(tab.pending_connectors.is_empty());
        }
        assert!(catalog.entries().is_empty());

        let settlement = connector_settlement(ApprovalDecisionV2::Approve);
        let approved =
            ApprovedConnectorRegistrationHandleV2::from_authority_entropy([0x7b; 32]).unwrap();
        let mut tab = tab_record(
            AgentTabSessionCapabilityV2::from_authority_entropy([0x7c; 32]).unwrap(),
            BootIdV2::new([0x7d; 32]),
            FixedOriginV2::Agent8768,
            None,
        );
        tab.pending_connectors.push(pending);
        finalize_connector_registration_settlement(
            &mut tab,
            0,
            ApprovalSettlementViewV2::Approved { settlement },
            |_| Ok(AuthorizeConnectorRegistrationResponseV2::new(approved)),
            |_| {
                catalog
                    .insert_entries(vec![connector_test_catalog_entry()])
                    .map_err(|_| AgentBrowserAuthorityErrorV2::Unavailable)
            },
            |_| {
                ApplyApprovedConnectorRegistrationResponseV2::new(
                    Digest32V2::new([0x7e; 32]),
                    Digest32V2::new([0x7f; 32]),
                    1,
                    Digest32V2::new([0x80; 32]),
                )
                .map_err(|_| AgentBrowserAuthorityErrorV2::StateConflict)
            },
        )
        .unwrap();
        assert_eq!(catalog.entries(), &[connector_test_catalog_entry()]);
    }

    #[test]
    fn pending_connector_debug_redacts_the_canonical_descriptor() {
        let pending = pending_connector_record();
        let debug = format!("{pending:?}");
        assert!(!debug.contains("private canonical connector descriptor"));
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn pending_connector_descriptor_budget_bounds_retained_private_bytes() {
        let mut tab = tab_record(
            AgentTabSessionCapabilityV2::from_authority_entropy([0x81; 32]).unwrap(),
            BootIdV2::new([0x82; 32]),
            FixedOriginV2::Agent8768,
            None,
        );
        tab.pending_connectors.push(pending_connector_record());
        assert_eq!(
            reserve_pending_connector_registration(
                &mut tab,
                MAX_PENDING_CONNECTOR_DESCRIPTOR_BYTES_PER_TAB_V2,
            ),
            Err(AgentBrowserAuthorityErrorV2::Overloaded),
        );
        assert_eq!(tab.pending_connectors.len(), 1);

        tab.pending_connectors.clear();
        assert_eq!(
            reserve_pending_connector_registration(
                &mut tab,
                MAX_PENDING_CONNECTOR_DESCRIPTOR_BYTES_PER_TAB_V2,
            ),
            Ok(()),
        );
        assert_eq!(
            reserve_pending_connector_registration(&mut tab, 0),
            Err(AgentBrowserAuthorityErrorV2::Overloaded),
        );
    }

    #[test]
    fn connector_removal_prepares_then_commits_without_an_approval_step() {
        let session = AgentSessionHandleV2::from_authority_entropy([0x61; 32]).unwrap();
        let connector_id = Digest32V2::new([0x62; 32]);
        let authorization =
            ConnectorRemovalAuthorizationHandleV2::from_authority_entropy([0x63; 32]).unwrap();
        let signed_delta_digest = Digest32V2::new([0x66; 32]);
        let head_digest = Digest32V2::new([0x64; 32]);
        let stage = Cell::new(0_u8);
        let response = remove_connector_flow(
            session,
            connector_id,
            |request| {
                assert_eq!(stage.get(), 0);
                stage.set(1);
                assert_eq!(request.session(), session);
                assert_eq!(request.connector_id(), connector_id);
                PrepareConnectorRemovalResponseV2::new(
                    authorization,
                    Digest32V2::new([0x65; 32]),
                    UnixMillisV2::new(900),
                )
                .map_err(|_| AgentBrowserAuthorityErrorV2::StateConflict)
            },
            |request| {
                assert_eq!(stage.get(), 1);
                stage.set(2);
                assert_eq!(request.session(), session);
                assert_eq!(request.authorization(), authorization);
                assert_eq!(request.connector_id(), connector_id);
                RemoveConnectorResponseV2::new(signed_delta_digest, head_digest, 10, connector_id)
                    .map_err(|_| AgentBrowserAuthorityErrorV2::StateConflict)
            },
        )
        .unwrap();
        assert_eq!(stage.get(), 2);
        assert_eq!(
            response,
            AgentBrowserMutationResponseV2::ConnectorRemovalCommitted {
                signed_delta_digest,
                head_digest,
                sequence: 10,
                connector_id,
            }
        );
    }

    #[test]
    fn connector_dispatch_requires_an_exact_authenticated_agent_origin_tab() {
        let current_boot = BootIdV2::new([0x21; 32]);
        let valid_tab = AgentTabSessionCapabilityV2::from_authority_entropy([0x22; 32]).unwrap();
        let claimed_tab = AgentTabSessionCapabilityV2::from_authority_entropy([0x2c; 32]).unwrap();
        let forged_tab = AgentTabSessionCapabilityV2::from_authority_entropy([0x23; 32]).unwrap();
        let absent_tab = AgentTabSessionCapabilityV2::from_authority_entropy([0x2b; 32]).unwrap();
        let unauthenticated_tab =
            AgentTabSessionCapabilityV2::from_authority_entropy([0x24; 32]).unwrap();
        let stale_tab = AgentTabSessionCapabilityV2::from_authority_entropy([0x25; 32]).unwrap();
        let wrong_origin_tab =
            AgentTabSessionCapabilityV2::from_authority_entropy([0x26; 32]).unwrap();
        let authorization =
            AgentUiAuthorizationHandleV2::from_authority_entropy([0x27; 32]).unwrap();
        let mut state = AuthorityStateV2::default();
        state.tabs.push(tab_record(
            valid_tab,
            current_boot,
            FixedOriginV2::Agent8768,
            Some(authorization),
        ));
        let mut claimed = tab_record(claimed_tab, current_boot, FixedOriginV2::Agent8768, None);
        claimed.kernel_document =
            Some(MaskedDocumentHandleV2::from_authority_entropy([0x2d; 32]).unwrap());
        claimed.session = Some(AgentSessionHandleV2::from_authority_entropy([0x2e; 32]).unwrap());
        claimed.run = Some(RunHandleV2::from_authority_entropy([0x2f; 32]).unwrap());
        claimed.initial_value = Some(ValueHandleV2::from_authority_entropy([0x30; 32]).unwrap());
        state.tabs.push(claimed);
        state.tabs.push(tab_record(
            unauthenticated_tab,
            current_boot,
            FixedOriginV2::Agent8768,
            None,
        ));
        state.tabs.push(tab_record(
            stale_tab,
            BootIdV2::new([0x28; 32]),
            FixedOriginV2::Agent8768,
            Some(authorization),
        ));
        state.tabs.push(tab_record(
            wrong_origin_tab,
            current_boot,
            FixedOriginV2::Approval8766,
            Some(authorization),
        ));

        let mut kernel_client_dispatches = 0_u8;
        for rejected in [
            absent_tab,
            forged_tab,
            unauthenticated_tab,
            stale_tab,
            wrong_origin_tab,
        ] {
            assert_eq!(
                authenticated_connector_tab(&mut state, rejected, current_boot).map(|_| {
                    kernel_client_dispatches += 1;
                }),
                Err(AgentBrowserAuthorityErrorV2::InvalidReference)
            );
        }
        assert_eq!(kernel_client_dispatches, 0);

        authenticated_connector_tab(&mut state, valid_tab, current_boot)
            .map(|_| {
                kernel_client_dispatches += 1;
            })
            .unwrap();
        authenticated_connector_tab(&mut state, claimed_tab, current_boot)
            .map(|_| {
                kernel_client_dispatches += 1;
            })
            .unwrap();
        assert_eq!(kernel_client_dispatches, 2);
    }

    #[test]
    fn all_connector_actions_share_the_closed_authenticated_tab_gate() {
        let pending =
            AgentPendingConnectorRegistrationRefV2::from_authority_entropy([0x31; 16]).unwrap();
        for action in [
            AgentBrowserActionV2::RegisterConnector(vec![0x81, 0x01]),
            AgentBrowserActionV2::FinalizeConnectorRegistration(pending),
            AgentBrowserActionV2::RemoveConnector(Digest32V2::new([0x32; 32])),
            AgentBrowserActionV2::SnapshotConnectors,
        ] {
            assert!(connector_action_requires_authenticated_tab(&action));
        }
        assert!(!connector_action_requires_authenticated_tab(
            &AgentBrowserActionV2::PrepareFollowupIngress
        ));
    }

    #[test]
    fn pending_connector_references_are_browser_local_and_distinct() {
        let tab = AgentTabSessionCapabilityV2::from_authority_entropy([0x33; 32]).unwrap();
        let mut tab = tab_record(
            tab,
            BootIdV2::new([0x34; 32]),
            FixedOriginV2::Agent8768,
            AgentUiAuthorizationHandleV2::from_authority_entropy([0x35; 32]),
        );
        let first = mint_pending_connector_reference(&mut tab).unwrap();
        let second = mint_pending_connector_reference(&mut tab).unwrap();
        assert_ne!(first, second);
    }
}
