mod support;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use savana_client::{
    AgentEvent, ApprovalCallback, ApprovalRequest, EventCallback, ExecutionStatus, IntentPrivacy,
    RunLimits, SavanaError,
};
use savana_kernel_protocol::v2::{
    decode_agent_browser_request_v2, encode_agent_browser_mutation_response_v2,
    AgentBrowserActionV2, AgentBrowserExecutionStateV2, AgentBrowserMutationResponseV2,
    AgentBrowserRequestV2, AgentExecutionRefV2, AgentExecutionTicketRefV2,
    AgentMaskedDocumentRefV2, AgentPendingToolCallRefV2, AgentPlanStepRefV2,
    ApprovalDecisionBrowserFinishResponseV2, ApprovalDisplayAuthenticationTransferCapabilityV2,
    ApprovalPurposeV2, Digest32V2, FixedBrowserFormPostCarrierV2, PublicDecisionTraceV2,
    PublicDispatchAcceptedStateV2, PublicFailureClassV2, PublicStableCodeV2,
};
use support::task5::{approval_responses, authenticated_session, cbor_response, RecordingDecision};

fn mutation(
    response: AgentBrowserMutationResponseV2,
) -> Result<savana_client::BrowserResponse, SavanaError> {
    cbor_response(encode_agent_browser_mutation_response_v2(&response).unwrap())
}

fn trace(byte: u8) -> PublicDecisionTraceV2 {
    PublicDecisionTraceV2::new(Digest32V2::new([byte; 32])).unwrap()
}

fn step(byte: u8) -> AgentPlanStepRefV2 {
    AgentPlanStepRefV2::from_authority_entropy([byte; 16]).unwrap()
}

fn plan(steps: Vec<AgentPlanStepRefV2>) -> Result<savana_client::BrowserResponse, SavanaError> {
    mutation(AgentBrowserMutationResponseV2::PlannerCommitted { steps })
}

fn execution(
    seed: u8,
    terminal: AgentBrowserExecutionStateV2,
) -> Vec<Result<savana_client::BrowserResponse, SavanaError>> {
    let pending = AgentPendingToolCallRefV2::from_authority_entropy([seed; 16]).unwrap();
    let ticket = AgentExecutionTicketRefV2::from_authority_entropy([seed + 1; 16]).unwrap();
    let execution = AgentExecutionRefV2::from_authority_entropy([seed + 2; 16]).unwrap();
    vec![
        mutation(AgentBrowserMutationResponseV2::ToolProposed { pending }),
        mutation(AgentBrowserMutationResponseV2::ToolAuthorized {
            ticket,
            trace: trace(seed + 3),
        }),
        mutation(AgentBrowserMutationResponseV2::ExecutionDispatched {
            execution,
            state: PublicDispatchAcceptedStateV2::Prepared,
        }),
        mutation(AgentBrowserMutationResponseV2::ExecutionRefreshed {
            execution,
            state: terminal,
        }),
    ]
}

fn actions(requests: &[savana_client::BrowserRequest]) -> Vec<AgentBrowserActionV2> {
    requests[4..]
        .iter()
        .filter_map(|request| {
            let decoded = decode_agent_browser_request_v2(&request.body).ok()?;
            match decoded {
                AgentBrowserRequestV2::Act { action, .. } => Some(action),
                _ => None,
            }
        })
        .collect()
}

#[derive(Default)]
struct RecordingEvents {
    events: Mutex<Vec<AgentEvent>>,
}

impl RecordingEvents {
    fn take(&self) -> Vec<AgentEvent> {
        std::mem::take(&mut *self.events.lock().unwrap())
    }
}

impl EventCallback for RecordingEvents {
    fn on_event(&self, event: &AgentEvent) -> Result<(), SavanaError> {
        self.events.lock().unwrap().push(*event);
        Ok(())
    }
}

struct CancelOnEvent {
    limits: RunLimits,
    kind: fn(&AgentEvent) -> bool,
}

impl EventCallback for CancelOnEvent {
    fn on_event(&self, event: &AgentEvent) -> Result<(), SavanaError> {
        if (self.kind)(event) {
            self.limits.cancel();
        }
        Ok(())
    }
}

struct SleepOnPlanning;

impl EventCallback for SleepOnPlanning {
    fn on_event(&self, event: &AgentEvent) -> Result<(), SavanaError> {
        if matches!(event, AgentEvent::Planning) {
            std::thread::sleep(Duration::from_millis(10));
        }
        Ok(())
    }
}

struct FailOnStepStart;

impl EventCallback for FailOnStepStart {
    fn on_event(&self, event: &AgentEvent) -> Result<(), SavanaError> {
        if matches!(event, AgentEvent::StepStarted { .. }) {
            Err(SavanaError::InvalidRequest)
        } else {
            Ok(())
        }
    }
}

struct CancellingApproval {
    limits: RunLimits,
    called: AtomicBool,
}

struct FailingApproval;

impl ApprovalCallback for FailingApproval {
    fn decide(&self, _request: &ApprovalRequest) -> Result<bool, SavanaError> {
        Err(SavanaError::InvalidRequest)
    }
}

impl ApprovalCallback for CancellingApproval {
    fn decide(&self, _request: &ApprovalRequest) -> Result<bool, SavanaError> {
        self.called.store(true, Ordering::SeqCst);
        self.limits.cancel();
        Ok(true)
    }
}

#[test]
fn run_limits_reject_zero_and_unrepresentable_deadlines() {
    assert!(matches!(
        RunLimits::new(0, 1, Duration::from_secs(1)),
        Err(SavanaError::InvalidRequest)
    ));
    assert!(matches!(
        RunLimits::new(1, 0, Duration::from_secs(1)),
        Err(SavanaError::InvalidRequest)
    ));
    assert!(matches!(
        RunLimits::new(1, 1, Duration::ZERO),
        Err(SavanaError::InvalidRequest)
    ));
    assert!(matches!(
        RunLimits::new(1, 1, Duration::MAX),
        Err(SavanaError::InvalidRequest)
    ));
}

#[test]
fn zero_step_planner_completion_returns_real_empty_success() {
    let (mut session, transport, _) = authenticated_session(vec![plan(vec![])]);
    let events = RecordingEvents::default();

    let result = session
        .run_agent(
            IntentPrivacy::Private,
            RunLimits::new(4, 2, Duration::from_secs(1)).unwrap(),
            &RecordingDecision::new(true),
            &events,
        )
        .unwrap();

    assert_eq!(result.status(), ExecutionStatus::Succeeded);
    assert!(result.outputs().is_empty());
    assert_eq!(result.failure_class(), None);
    assert_eq!(
        actions(&transport.take_requests()),
        [AgentBrowserActionV2::RunPlanner]
    );
    assert_eq!(events.take(), [AgentEvent::Planning, AgentEvent::Completed]);
}

#[test]
fn a_multi_step_plan_completes_once_and_reports_only_counts_and_statuses() {
    let first = step(0x31);
    let second = step(0x32);
    let first_output = AgentMaskedDocumentRefV2::from_authority_entropy([0x33; 16]).unwrap();
    let second_output = AgentMaskedDocumentRefV2::from_authority_entropy([0x34; 16]).unwrap();
    let mut responses = vec![plan(vec![first, second])];
    responses.extend(execution(
        0x40,
        AgentBrowserExecutionStateV2::Succeeded {
            document: first_output,
        },
    ));
    responses.extend(execution(
        0x50,
        AgentBrowserExecutionStateV2::Succeeded {
            document: second_output,
        },
    ));
    let (mut session, transport, _) = authenticated_session(responses);
    let events = RecordingEvents::default();

    let result = session
        .run_agent(
            IntentPrivacy::ThirdParty,
            RunLimits::new(2, 1, Duration::from_secs(1)).unwrap(),
            &RecordingDecision::new(true),
            &events,
        )
        .unwrap();

    assert_eq!(result.status(), ExecutionStatus::Succeeded);
    assert_eq!(result.outputs().len(), 2);
    let observed = events.take();
    assert_eq!(
        observed,
        [
            AgentEvent::Planning,
            AgentEvent::StepStarted { index: 1 },
            AgentEvent::StepCompleted {
                index: 1,
                status: ExecutionStatus::Succeeded,
            },
            AgentEvent::StepStarted { index: 2 },
            AgentEvent::StepCompleted {
                index: 2,
                status: ExecutionStatus::Succeeded,
            },
            AgentEvent::Completed,
        ]
    );
    let debug = format!("{observed:?}");
    for forbidden in [
        "31313131",
        "32323232",
        "33333333",
        "34343434",
        "ThirdParty",
        "masked",
    ] {
        assert!(!debug.contains(forbidden), "event leaked {forbidden}");
    }
    assert_eq!(
        actions(&transport.take_requests())
            .iter()
            .filter(|action| matches!(action, AgentBrowserActionV2::RunPlannerWithThirdPartyMapper))
            .count(),
        1
    );
}

#[test]
fn step_limit_stops_before_starting_an_excess_step() {
    let first = step(0x61);
    let second = step(0x62);
    let output = AgentMaskedDocumentRefV2::from_authority_entropy([0x63; 16]).unwrap();
    let mut responses = vec![plan(vec![first, second])];
    responses.extend(execution(
        0x64,
        AgentBrowserExecutionStateV2::Succeeded { document: output },
    ));
    let (mut session, transport, _) = authenticated_session(responses);

    assert!(matches!(
        session.run_agent(
            IntentPrivacy::Private,
            RunLimits::new(1, 1, Duration::from_secs(1)).unwrap(),
            &RecordingDecision::new(true),
            &RecordingEvents::default(),
        ),
        Err(SavanaError::StepLimitExceeded)
    ));
    let observed = actions(&transport.take_requests());
    assert_eq!(
        observed
            .iter()
            .filter(|action| matches!(action, AgentBrowserActionV2::ProposePlanStep(_)))
            .count(),
        1
    );
}

#[test]
fn only_failed_no_effect_replans_and_the_replan_limit_is_checked() {
    let first = step(0x71);
    let second = step(0x72);
    let mut responses = vec![plan(vec![first])];
    responses.extend(execution(
        0x73,
        AgentBrowserExecutionStateV2::FailedNoEffect {
            class: PublicFailureClassV2::Infrastructure,
        },
    ));
    responses.push(plan(vec![second]));
    responses.extend(execution(
        0x78,
        AgentBrowserExecutionStateV2::FailedNoEffect {
            class: PublicFailureClassV2::Input,
        },
    ));
    let (mut session, transport, _) = authenticated_session(responses);
    let events = RecordingEvents::default();

    assert!(matches!(
        session.run_agent(
            IntentPrivacy::Private,
            RunLimits::new(3, 1, Duration::from_secs(1)).unwrap(),
            &RecordingDecision::new(true),
            &events,
        ),
        Err(SavanaError::ReplanLimitExceeded)
    ));

    let observed_actions = actions(&transport.take_requests());
    assert_eq!(
        observed_actions
            .iter()
            .filter(|action| matches!(action, AgentBrowserActionV2::RunPlanner))
            .count(),
        2
    );
    assert_eq!(
        events
            .take()
            .iter()
            .filter(|event| matches!(event, AgentEvent::Replanning { .. }))
            .count(),
        1
    );
}

#[test]
fn failed_no_effect_can_replan_to_truthful_zero_step_completion() {
    let first = step(0x7a);
    let mut responses = vec![plan(vec![first])];
    responses.extend(execution(
        0x7b,
        AgentBrowserExecutionStateV2::FailedNoEffect {
            class: PublicFailureClassV2::Infrastructure,
        },
    ));
    responses.push(plan(vec![]));
    let (mut session, transport, _) = authenticated_session(responses);
    let events = RecordingEvents::default();

    let result = session
        .run_agent(
            IntentPrivacy::Private,
            RunLimits::new(2, 1, Duration::from_secs(1)).unwrap(),
            &RecordingDecision::new(true),
            &events,
        )
        .unwrap();

    assert_eq!(result.status(), ExecutionStatus::Succeeded);
    assert!(result.outputs().is_empty());
    assert_eq!(
        actions(&transport.take_requests())
            .iter()
            .filter(|action| matches!(action, AgentBrowserActionV2::RunPlanner))
            .count(),
        2
    );
    assert!(events.take().contains(&AgentEvent::Replanning { count: 1 }));
}

#[test]
fn cancellation_and_deadline_stop_before_the_next_service_request() {
    let limits = RunLimits::new(1, 1, Duration::from_secs(1)).unwrap();
    let (mut cancelled_session, cancelled_transport, _) = authenticated_session(vec![plan(vec![])]);
    let cancellation_events = CancelOnEvent {
        limits: limits.clone(),
        kind: |event| matches!(event, AgentEvent::Planning),
    };
    assert!(matches!(
        cancelled_session.run_agent(
            IntentPrivacy::Private,
            limits,
            &RecordingDecision::new(true),
            &cancellation_events,
        ),
        Err(SavanaError::Cancelled)
    ));
    assert!(cancelled_session
        .run_planner(IntentPrivacy::Private)
        .is_ok());
    let cancelled_requests = cancelled_transport.take_requests();
    assert_eq!(cancelled_requests.len(), 5);
    assert_eq!(
        actions(&cancelled_requests),
        [AgentBrowserActionV2::RunPlanner]
    );

    let (mut expired_session, expired_transport, _) = authenticated_session(vec![plan(vec![])]);
    assert!(matches!(
        expired_session.run_agent(
            IntentPrivacy::Private,
            RunLimits::new(1, 1, Duration::from_millis(1)).unwrap(),
            &RecordingDecision::new(true),
            &SleepOnPlanning,
        ),
        Err(SavanaError::DeadlineExceeded)
    ));
    assert!(expired_session.run_planner(IntentPrivacy::Private).is_ok());
    let expired_requests = expired_transport.take_requests();
    assert_eq!(expired_requests.len(), 5);
    assert_eq!(
        actions(&expired_requests),
        [AgentBrowserActionV2::RunPlanner]
    );
}

#[test]
fn cancellation_inside_approval_blocks_its_next_nested_request() {
    let planned = step(0x81);
    let pending = AgentPendingToolCallRefV2::from_authority_entropy([0x82; 16]).unwrap();
    let transfer =
        ApprovalDisplayAuthenticationTransferCapabilityV2::from_authority_entropy([0x83; 32])
            .unwrap();
    let mut responses = vec![
        plan(vec![planned]),
        mutation(AgentBrowserMutationResponseV2::ToolProposed { pending }),
        mutation(AgentBrowserMutationResponseV2::ToolOpenApproval {
            post: FixedBrowserFormPostCarrierV2::AgentApprovalDisplay(transfer),
            trace: trace(0x84),
        }),
    ];
    let mut nested_approval_responses = approval_responses(
        ApprovalPurposeV2::ToolExecution,
        ApprovalDecisionBrowserFinishResponseV2::Approved,
    );
    nested_approval_responses.truncate(4);
    responses.extend(nested_approval_responses);
    responses.push(plan(vec![]));
    let (mut session, transport, _) = authenticated_session(responses);
    let limits = RunLimits::new(1, 1, Duration::from_secs(1)).unwrap();
    let approval = CancellingApproval {
        limits: limits.clone(),
        called: AtomicBool::new(false),
    };
    let events = RecordingEvents::default();

    assert!(matches!(
        session.run_agent(IntentPrivacy::Private, limits, &approval, &events,),
        Err(SavanaError::Cancelled)
    ));
    assert!(approval.called.load(Ordering::SeqCst));
    assert!(session.run_planner(IntentPrivacy::Private).is_ok());
    let requests = transport.take_requests();
    assert!(!requests
        .iter()
        .any(|request| request.route == savana_client::BrowserRoute::ApprovalDecisionBegin));
    assert_eq!(
        actions(&requests)
            .iter()
            .filter(|action| matches!(action, AgentBrowserActionV2::RunPlanner))
            .count(),
        2
    );
    let event_debug = format!("{:?}", events.take());
    assert!(event_debug.contains("ApprovalRequired"));
    assert!(!event_debug.contains("Approve exact operation"));
}

#[test]
fn approval_denial_and_callback_failure_are_terminal_without_dispatch_or_replan() {
    let denied_step = step(0x85);
    let denied_pending = AgentPendingToolCallRefV2::from_authority_entropy([0x86; 16]).unwrap();
    let denied_transfer =
        ApprovalDisplayAuthenticationTransferCapabilityV2::from_authority_entropy([0x87; 32])
            .unwrap();
    let mut denied_responses = vec![
        plan(vec![denied_step]),
        mutation(AgentBrowserMutationResponseV2::ToolProposed {
            pending: denied_pending,
        }),
        mutation(AgentBrowserMutationResponseV2::ToolOpenApproval {
            post: FixedBrowserFormPostCarrierV2::AgentApprovalDisplay(denied_transfer),
            trace: trace(0x88),
        }),
    ];
    denied_responses.extend(approval_responses(
        ApprovalPurposeV2::ToolExecution,
        ApprovalDecisionBrowserFinishResponseV2::Denied,
    ));
    denied_responses.push(mutation(AgentBrowserMutationResponseV2::ToolDenied {
        code: PublicStableCodeV2::ApprovalDenied,
        trace: trace(0x89),
    }));
    let (mut denied_session, denied_transport, _) = authenticated_session(denied_responses);
    assert!(matches!(
        denied_session.run_agent(
            IntentPrivacy::Private,
            RunLimits::new(2, 1, Duration::from_secs(1)).unwrap(),
            &RecordingDecision::new(false),
            &RecordingEvents::default(),
        ),
        Err(SavanaError::ApprovalDenied(_))
    ));
    let denied_actions = actions(&denied_transport.take_requests());
    assert_eq!(
        denied_actions
            .iter()
            .filter(|action| matches!(action, AgentBrowserActionV2::RunPlanner))
            .count(),
        1
    );
    assert!(!denied_actions
        .iter()
        .any(|action| matches!(action, AgentBrowserActionV2::DispatchTicket(_))));

    let callback_step = step(0x8a);
    let callback_pending = AgentPendingToolCallRefV2::from_authority_entropy([0x8b; 16]).unwrap();
    let callback_transfer =
        ApprovalDisplayAuthenticationTransferCapabilityV2::from_authority_entropy([0x8c; 32])
            .unwrap();
    let mut callback_responses = vec![
        plan(vec![callback_step]),
        mutation(AgentBrowserMutationResponseV2::ToolProposed {
            pending: callback_pending,
        }),
        mutation(AgentBrowserMutationResponseV2::ToolOpenApproval {
            post: FixedBrowserFormPostCarrierV2::AgentApprovalDisplay(callback_transfer),
            trace: trace(0x8d),
        }),
    ];
    let mut callback_approval_responses = approval_responses(
        ApprovalPurposeV2::ToolExecution,
        ApprovalDecisionBrowserFinishResponseV2::Approved,
    );
    callback_approval_responses.truncate(4);
    callback_responses.extend(callback_approval_responses);
    let (mut callback_session, callback_transport, _) = authenticated_session(callback_responses);
    assert!(matches!(
        callback_session.run_agent(
            IntentPrivacy::Private,
            RunLimits::new(2, 1, Duration::from_secs(1)).unwrap(),
            &FailingApproval,
            &RecordingEvents::default(),
        ),
        Err(SavanaError::CallbackFailed)
    ));
    let callback_requests = callback_transport.take_requests();
    assert!(!callback_requests
        .iter()
        .any(|request| request.route == savana_client::BrowserRoute::ApprovalDecisionBegin));
    assert!(matches!(
        callback_session.run_planner(IntentPrivacy::Private),
        Err(SavanaError::InvalidState)
    ));
    assert!(callback_transport.take_requests().is_empty());
}

#[test]
fn policy_approval_indeterminate_quarantine_and_success_are_never_replanned() {
    let policy_step = step(0x91);
    let policy_pending = AgentPendingToolCallRefV2::from_authority_entropy([0x92; 16]).unwrap();
    let (mut policy_session, policy_transport, _) = authenticated_session(vec![
        plan(vec![policy_step]),
        mutation(AgentBrowserMutationResponseV2::ToolProposed {
            pending: policy_pending,
        }),
        mutation(AgentBrowserMutationResponseV2::ToolDenied {
            code: PublicStableCodeV2::PolicyDenied,
            trace: trace(0x93),
        }),
    ]);
    assert!(matches!(
        policy_session.run_agent(
            IntentPrivacy::Private,
            RunLimits::new(2, 1, Duration::from_secs(1)).unwrap(),
            &RecordingDecision::new(true),
            &RecordingEvents::default(),
        ),
        Err(SavanaError::PolicyRefused(_))
    ));
    assert_eq!(
        actions(&policy_transport.take_requests())
            .iter()
            .filter(|action| matches!(action, AgentBrowserActionV2::RunPlanner))
            .count(),
        1
    );

    for (seed, terminal, expected) in [
        (
            0xa0,
            AgentBrowserExecutionStateV2::EffectSucceededOutputQuarantined {
                class: PublicFailureClassV2::ResultGate,
            },
            Some(ExecutionStatus::EffectSucceededOutputQuarantined),
        ),
        (0xb0, AgentBrowserExecutionStateV2::Indeterminate, None),
        (
            0xc0,
            AgentBrowserExecutionStateV2::Succeeded {
                document: AgentMaskedDocumentRefV2::from_authority_entropy([0xc4; 16]).unwrap(),
            },
            Some(ExecutionStatus::Succeeded),
        ),
    ] {
        let planned = step(seed);
        let mut responses = vec![plan(vec![planned])];
        responses.extend(execution(seed + 1, terminal));
        let (mut session, transport, _) = authenticated_session(responses);
        let result = session.run_agent(
            IntentPrivacy::Private,
            RunLimits::new(2, 1, Duration::from_secs(1)).unwrap(),
            &RecordingDecision::new(true),
            &RecordingEvents::default(),
        );
        match expected {
            Some(status) => assert_eq!(result.unwrap().status(), status),
            None => assert!(matches!(result, Err(SavanaError::IndeterminateEffect))),
        }
        assert_eq!(
            actions(&transport.take_requests())
                .iter()
                .filter(|action| matches!(action, AgentBrowserActionV2::RunPlanner))
                .count(),
            1
        );
    }
}

#[test]
fn observer_failure_stops_before_execution_without_closing_or_retrying() {
    let first = step(0xd1);
    let (mut session, transport, _) = authenticated_session(vec![plan(vec![first]), plan(vec![])]);

    assert!(matches!(
        session.run_agent(
            IntentPrivacy::Private,
            RunLimits::new(1, 1, Duration::from_secs(1)).unwrap(),
            &RecordingDecision::new(true),
            &FailOnStepStart,
        ),
        Err(SavanaError::CallbackFailed)
    ));
    assert!(session.run_planner(IntentPrivacy::Private).is_ok());
    let observed = actions(&transport.take_requests());
    assert_eq!(
        observed
            .iter()
            .filter(|action| matches!(action, AgentBrowserActionV2::RunPlanner))
            .count(),
        2
    );
    assert!(!observed
        .iter()
        .any(|action| matches!(action, AgentBrowserActionV2::ProposePlanStep(_))));
}

#[test]
fn ambiguous_transport_failure_is_terminal_and_never_replanned() {
    let planned = step(0xe1);
    let (mut session, transport, _) =
        authenticated_session(vec![plan(vec![planned]), Err(SavanaError::Transport)]);

    assert!(matches!(
        session.run_agent(
            IntentPrivacy::Private,
            RunLimits::new(2, 1, Duration::from_secs(1)).unwrap(),
            &RecordingDecision::new(true),
            &RecordingEvents::default(),
        ),
        Err(SavanaError::Transport)
    ));
    let observed = actions(&transport.take_requests());
    assert_eq!(
        observed
            .iter()
            .filter(|action| matches!(action, AgentBrowserActionV2::RunPlanner))
            .count(),
        1
    );
    assert_eq!(
        observed
            .iter()
            .filter(|action| matches!(action, AgentBrowserActionV2::ProposePlanStep(_)))
            .count(),
        1
    );
}

#[test]
fn transport_lookalike_guard_errors_close_after_a_planner_request() {
    let cases: [fn() -> SavanaError; 3] = [
        || SavanaError::Cancelled,
        || SavanaError::DeadlineExceeded,
        || SavanaError::CallbackFailed,
    ];
    for make_error in cases {
        let expected_code = make_error().code();
        let (mut session, transport, _) =
            authenticated_session(vec![Err(make_error()), plan(vec![])]);

        let error = session
            .run_agent(
                IntentPrivacy::Private,
                RunLimits::new(1, 1, Duration::from_secs(1)).unwrap(),
                &RecordingDecision::new(true),
                &RecordingEvents::default(),
            )
            .unwrap_err();
        assert_eq!(error.code(), expected_code);
        let requests = transport.take_requests();
        assert_eq!(actions(&requests), [AgentBrowserActionV2::RunPlanner]);
        assert!(matches!(
            session.run_planner(IntentPrivacy::Private),
            Err(SavanaError::InvalidState)
        ));
        assert!(transport.take_requests().is_empty());
    }
}

#[test]
fn transport_lookalike_guard_errors_close_after_an_execution_request() {
    let cases: [fn() -> SavanaError; 3] = [
        || SavanaError::Cancelled,
        || SavanaError::DeadlineExceeded,
        || SavanaError::CallbackFailed,
    ];
    for (index, make_error) in cases.into_iter().enumerate() {
        let expected_code = make_error().code();
        let planned = step(0xe2 + index as u8);
        let (mut session, transport, _) =
            authenticated_session(vec![plan(vec![planned]), Err(make_error()), plan(vec![])]);

        let error = session
            .run_agent(
                IntentPrivacy::Private,
                RunLimits::new(1, 1, Duration::from_secs(1)).unwrap(),
                &RecordingDecision::new(true),
                &RecordingEvents::default(),
            )
            .unwrap_err();
        assert_eq!(error.code(), expected_code);
        let requests = transport.take_requests();
        let observed = actions(&requests);
        assert_eq!(
            observed
                .iter()
                .filter(|action| matches!(action, AgentBrowserActionV2::RunPlanner))
                .count(),
            1
        );
        assert_eq!(
            observed
                .iter()
                .filter(|action| matches!(action, AgentBrowserActionV2::ProposePlanStep(_)))
                .count(),
            1
        );
        assert!(matches!(
            session.run_planner(IntentPrivacy::Private),
            Err(SavanaError::InvalidState)
        ));
        assert!(transport.take_requests().is_empty());
    }
}

#[test]
fn transport_callback_failure_during_remote_approval_closes_the_session() {
    let planned = step(0xe6);
    let pending = AgentPendingToolCallRefV2::from_authority_entropy([0xe7; 16]).unwrap();
    let transfer =
        ApprovalDisplayAuthenticationTransferCapabilityV2::from_authority_entropy([0xe8; 32])
            .unwrap();
    let (mut session, transport, _) = authenticated_session(vec![
        plan(vec![planned]),
        mutation(AgentBrowserMutationResponseV2::ToolProposed { pending }),
        mutation(AgentBrowserMutationResponseV2::ToolOpenApproval {
            post: FixedBrowserFormPostCarrierV2::AgentApprovalDisplay(transfer),
            trace: trace(0xe9),
        }),
        Err(SavanaError::CallbackFailed),
        plan(vec![]),
    ]);

    assert!(matches!(
        session.run_agent(
            IntentPrivacy::Private,
            RunLimits::new(1, 1, Duration::from_secs(1)).unwrap(),
            &RecordingDecision::new(true),
            &RecordingEvents::default(),
        ),
        Err(SavanaError::CallbackFailed)
    ));
    let requests = transport.take_requests();
    assert!(requests.iter().any(|request| {
        request.route == savana_client::BrowserRoute::ApprovalUiAuthenticationAccept
    }));
    assert!(matches!(
        session.run_planner(IntentPrivacy::Private),
        Err(SavanaError::InvalidState)
    ));
    assert!(transport.take_requests().is_empty());
}
