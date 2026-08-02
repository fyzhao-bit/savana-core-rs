use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use savana_approvald::{ApprovalSuiteOneClientErrorV2, ApprovalSuiteOneClientV2};
use savana_kernel_protocol::v2::{
    ActionIntentCurrentStateV2, ActiveToolViewV2, AgentApprovalRecordTargetV2,
    AgentBrowserActionV2, AgentBrowserExecutionStateV2, AgentBrowserMutationResponseV2,
    AgentBrowserObjectRefV2, AgentBrowserReadViewResponseV2, AgentBrowserReleaseStateV2,
    AgentBrowserRequestV2, AgentBrowserViewCursorCapabilityV2, AgentExecutionRefV2,
    AgentExecutionTicketRefV2, AgentMaskedDocumentRefV2, AgentPendingToolCallRefV2,
    AgentPlanStepRefV2, AgentReleaseRefV2, AgentReleaseTicketRefV2, AgentSessionHandleV2,
    AgentTabSessionCapabilityV2, AgentUiAuthenticationPreparationHandleV2,
    AgentUiAuthenticationSettlementTransferCapabilityV2, AgentUiAuthenticationTransferCapabilityV2,
    AgentUiAuthorizationHandleV2, ApprovalSettlementViewV2, ApprovalUiRecordHandleV2,
    AuthorizeReleaseRequestV2, AuthorizeToolCallRequestV2, BootIdV2, CloseAgentSessionRequestV2,
    CommitPlannerValueRequestV2, Digest32V2, DispatchExecutionRequestV2, DispatchReleaseRequestV2,
    DisplayProjectionIdV2, EvaluateToolCallRequestV2, EvaluateToolCallResponseV2,
    ExecutionHandleV2, ExecutionStatusTargetV2, ExecutionTicketHandleV2, ExecutorIdentityV2,
    FixedBrowserFormPostCarrierV2, FixedOriginV2, GetExecutionStatusRequestV2,
    GetReleaseStatusRequestV2, KernelAgentOperationV2, KernelAgentViewCursorV2,
    MaskedDocumentHandleV2, NamedArgumentValueBindingV2, Nonce32V2, PendingReleaseHandleV2,
    PendingToolCallHandleV2, PlanStepHandleV2, PlannerIntentKindV2, PlannerLimitsV2,
    PlannerPurposeV2, PlannerRouteIdV2, PrepareConnectorRegistrationRequestV2,
    PrepareFollowupIngressRequestV2, PreparePlannerCallRequestV2, PrepareReleaseRequestV2,
    ProjectionIdV2, ProposeConnectorRegistrationRequestV2, ProposeToolCallRequestV2,
    PublicDispatchCompletionV2, PublicExecutionStatusV2, PublicStableCodeV2, RegisteredApprovalV2,
    RegisteredUiAuthenticationV2, ReleaseApprovalRecordHandleV2, ReleaseHandleV2,
    ReleaseKernelApprovalHandleV2, ReleaseStatusTargetV2, ReleaseTicketHandleV2, RequestIdV2,
    ResumeCommittedAgentAuthenticationResponseV2, RunHandleV2, SignedDurableTaskCorrelationV2,
    SignedUiAuthenticationSettlementV2, StaticTemplateIdV2, ToolApprovalRecordHandleV2,
    ToolHandleV2, ToolKernelApprovalHandleV2, UnixMillisV2, ValueHandleV2,
};
use zeroize::Zeroizing;

use crate::{
    effect_gate::{EffectGateCoordinatorV2, EffectGateErrorV2, EffectGateOperationKindV2},
    AgentControlKernelClientErrorV2, AgentPlannerClientErrorV2, PinnedMtlsAgentPlannerClientV2,
    SuiteOneAgentKernelClientV2,
};

const MAX_AUTHENTICATIONS_V2: usize = 4096;
const MAX_TABS_V2: usize = 4096;
const MAX_COMPLETIONS_V2: usize = 4096;
const MAX_REPLAYS_PER_TAB_V2: usize = 256;
const MAX_CURSORS_PER_TAB_V2: usize = 256;
const MAX_OBJECTS_PER_TAB_V2: usize = 4096;

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

#[derive(Debug, Clone)]
struct ActionReplayV2 {
    request_digest: Digest32V2,
    nonce: Nonce32V2,
    response: AgentBrowserMutationResponseV2,
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

pub struct AgentBrowserAuthorityV2 {
    effect_gate: EffectGateCoordinatorV2,
    kernel: SuiteOneAgentKernelClientV2,
    approval: ApprovalSuiteOneClientV2,
    planner: PinnedMtlsAgentPlannerClientV2,
    planner_route: PlannerRouteIdV2,
    planner_template: StaticTemplateIdV2,
    planner_intent: PlannerIntentKindV2,
    planner_limits: PlannerLimitsV2,
    release_executor: ExecutorIdentityV2,
    release_destination_projection: ProjectionIdV2,
    release_display_projection: DisplayProjectionIdV2,
    agentd_boot_id: BootIdV2,
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
        planner: PinnedMtlsAgentPlannerClientV2,
        planner_route: PlannerRouteIdV2,
        planner_template: StaticTemplateIdV2,
        planner_intent: PlannerIntentKindV2,
        planner_limits: PlannerLimitsV2,
        release_executor: ExecutorIdentityV2,
        release_destination_projection: ProjectionIdV2,
        release_display_projection: DisplayProjectionIdV2,
        agentd_boot_id: BootIdV2,
    ) -> Self {
        Self {
            effect_gate,
            kernel,
            approval,
            planner,
            planner_route,
            planner_template,
            planner_intent,
            planner_limits,
            release_executor,
            release_destination_projection,
            release_display_projection,
            agentd_boot_id,
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
        let request_digest = browser_action_request_digest(tab, action.clone())?;
        let request_id = browser_kernel_request_id(tab, client_request_nonce, action.clone())?;
        let effect_operation_id =
            browser_effect_operation_id(tab, client_request_nonce, action.clone())?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| AgentBrowserAuthorityErrorV2::Unavailable)?;
        let tab = if matches!(&action, AgentBrowserActionV2::RegisterConnector(_)) {
            authenticated_connector_tab(&mut state, tab, self.agentd_boot_id)?
        } else {
            find_action_tab(&mut state, tab)?
        };
        if let Some(existing) = tab
            .action_replays
            .iter()
            .find(|entry| entry.nonce == client_request_nonce)
        {
            return if existing.request_digest == request_digest {
                Ok(existing.response.clone())
            } else {
                Err(AgentBrowserAuthorityErrorV2::StateConflict)
            };
        }
        if tab.action_replays.len() >= MAX_REPLAYS_PER_TAB_V2 {
            return Err(AgentBrowserAuthorityErrorV2::Overloaded);
        }
        tab.action_replays
            .try_reserve(1)
            .map_err(|_| AgentBrowserAuthorityErrorV2::Overloaded)?;
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
            AgentBrowserActionV2::RunPlanner => {
                let _effect_guard = self
                    .effect_gate
                    .acquire(
                        EffectGateOperationKindV2::PlannerExchange,
                        effect_operation_id,
                        effect_gate_deadline(deadline)?,
                    )
                    .map_err(map_effect_gate)?;
                let run = required(tab.run)?;
                let initial_value = required(tab.initial_value)?;
                let prepared = self
                    .kernel
                    .prepare_planner_call(
                        PreparePlannerCallRequestV2::new(
                            run,
                            self.planner_route,
                            self.planner_template,
                            self.planner_intent,
                            PlannerPurposeV2::PlannerCall,
                            self.planner_limits,
                            vec![initial_value],
                        )
                        .map_err(|_| AgentBrowserAuthorityErrorV2::InvalidReference)?,
                        request_id,
                        deadline,
                    )
                    .map_err(map_kernel)?;
                let plan = self
                    .planner
                    .plan(prepared.envelope(), deadline)
                    .map_err(map_planner)?;
                let committed = self
                    .kernel
                    .commit_planner_value(
                        CommitPlannerValueRequestV2::new(run, prepared.ticket(), plan.clone()),
                        request_id,
                        deadline,
                    )
                    .map_err(map_kernel)?;
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
                for (kernel_step, plan_step) in committed.steps().iter().copied().zip(plan.steps())
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
                        } if *candidate == reference => Some((*kernel, *tool, arguments.clone())),
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
                    .dispatch_release(DispatchReleaseRequestV2::new(ticket), request_id, deadline)
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
                let prepared = self
                    .kernel
                    .prepare_connector_registration(
                        PrepareConnectorRegistrationRequestV2::new(
                            required(tab.session)?,
                            canonical_descriptor.clone(),
                        )
                        .map_err(|_| AgentBrowserAuthorityErrorV2::InvalidReference)?,
                        deadline,
                    )
                    .map_err(map_kernel)?;
                let proposed = self
                    .kernel
                    .propose_connector_registration(
                        ProposeConnectorRegistrationRequestV2::new(
                            prepared.authorization(),
                            canonical_descriptor,
                        )
                        .map_err(|_| AgentBrowserAuthorityErrorV2::InvalidReference)?,
                        deadline,
                    )
                    .map_err(map_kernel)?;
                let registered = self
                    .approval
                    .register_approval(
                        proposed.envelope().clone(),
                        proposed.display_authentication().clone(),
                        deadline,
                    )
                    .map_err(map_approval)?;
                let RegisteredApprovalV2::Connector {
                    display_authentication,
                    ..
                } = registered
                else {
                    return Err(AgentBrowserAuthorityErrorV2::StateConflict);
                };
                AgentBrowserMutationResponseV2::ConnectorOpenApproval {
                    post: FixedBrowserFormPostCarrierV2::AgentApprovalDisplay(
                        display_authentication,
                    ),
                }
            }
        };
        tab.action_replays.push(ActionReplayV2 {
            request_digest,
            nonce: client_request_nonce,
            response: response.clone(),
        });
        Ok(response)
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
    use super::*;

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
            cursors: Vec::new(),
            replays: Vec::new(),
            action_replays: Vec::new(),
        }
    }

    #[test]
    fn connector_dispatch_requires_an_exact_authenticated_agent_origin_tab() {
        let current_boot = BootIdV2::new([0x21; 32]);
        let valid_tab = AgentTabSessionCapabilityV2::from_authority_entropy([0x22; 32]).unwrap();
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
        assert_eq!(kernel_client_dispatches, 1);
    }
}
