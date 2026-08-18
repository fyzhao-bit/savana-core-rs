mod support;

use savana_client::{
    ApprovalPurpose, BrowserRoute, ExecutionStatus, HandleKind, IntentPrivacy, SavanaError,
};
use savana_kernel_protocol::v2::{
    decode_agent_browser_request_v2, decode_approval_decision_browser_begin_request_v2,
    encode_agent_browser_mutation_response_v2, encode_agent_browser_read_view_response_v2,
    AgentBrowserActionV2, AgentBrowserExecutionStateV2, AgentBrowserMutationResponseV2,
    AgentBrowserObjectRefV2, AgentBrowserReadViewResponseV2, AgentBrowserReleaseStateV2,
    AgentBrowserRequestV2, AgentContentStateV2, AgentExecutionRefV2, AgentExecutionTicketRefV2,
    AgentMaskedDocumentRefV2, AgentPendingToolCallRefV2, AgentPlanStepRefV2, AgentReleaseRefV2,
    AgentReleaseTicketRefV2, AgentSessionStatusV2, AgentViewV2,
    ApprovalDecisionBrowserFinishResponseV2, ApprovalDecisionV2,
    ApprovalDisplayAuthenticationTransferCapabilityV2, ApprovalPurposeV2, Digest32V2,
    FixedBrowserFormPostCarrierV2, PublicDecisionTraceV2, PublicDispatchAcceptedStateV2,
    PublicFailureClassV2, PublicStableCodeV2,
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

fn planned_step(byte: u8) -> AgentPlanStepRefV2 {
    AgentPlanStepRefV2::from_authority_entropy([byte; 16]).unwrap()
}

fn plan_response(step: AgentPlanStepRefV2) -> Result<savana_client::BrowserResponse, SavanaError> {
    mutation(AgentBrowserMutationResponseV2::PlannerCommitted { steps: vec![step] })
}

fn actions_after_authentication(
    requests: &[savana_client::BrowserRequest],
) -> Vec<AgentBrowserActionV2> {
    requests[4..]
        .iter()
        .filter(|request| request.route == BrowserRoute::AgentAction)
        .map(
            |request| match decode_agent_browser_request_v2(&request.body).unwrap() {
                AgentBrowserRequestV2::Act { action, .. } => action,
                _ => panic!("agent action route must contain Act"),
            },
        )
        .collect()
}

#[test]
fn direct_authorization_dispatches_once_and_returns_only_the_terminal_document() {
    let step = planned_step(0x41);
    let pending = AgentPendingToolCallRefV2::from_authority_entropy([0x42; 16]).unwrap();
    let ticket = AgentExecutionTicketRefV2::from_authority_entropy([0x43; 16]).unwrap();
    let execution = AgentExecutionRefV2::from_authority_entropy([0x44; 16]).unwrap();
    let output = AgentMaskedDocumentRefV2::from_authority_entropy([0x45; 16]).unwrap();
    let responses = vec![
        plan_response(step),
        mutation(AgentBrowserMutationResponseV2::ToolProposed { pending }),
        mutation(AgentBrowserMutationResponseV2::ToolAuthorized {
            ticket,
            trace: trace(0x46),
        }),
        mutation(AgentBrowserMutationResponseV2::ExecutionDispatched {
            execution,
            state: PublicDispatchAcceptedStateV2::Prepared,
        }),
        mutation(AgentBrowserMutationResponseV2::ExecutionRefreshed {
            execution,
            state: AgentBrowserExecutionStateV2::Succeeded { document: output },
        }),
    ];
    let (mut session, transport, _) = authenticated_session(responses);
    let plan = session.run_planner(IntentPrivacy::Private).unwrap();

    let result = session
        .execute(&plan, &RecordingDecision::new(true))
        .unwrap();

    assert_eq!(result.status(), ExecutionStatus::Succeeded);
    assert_eq!(result.failure_class(), None);
    assert_eq!(result.outputs().len(), 1);
    assert_eq!(result.outputs()[0].kind(), HandleKind::Document);
    let requests = transport.take_requests();
    assert_eq!(
        actions_after_authentication(&requests),
        vec![
            AgentBrowserActionV2::RunPlanner,
            AgentBrowserActionV2::ProposePlanStep(step),
            AgentBrowserActionV2::EvaluatePending(pending),
            AgentBrowserActionV2::DispatchTicket(ticket),
            AgentBrowserActionV2::RefreshExecution(execution),
        ]
    );
    assert!(matches!(
        session.read_view(&result.outputs()[0]),
        Err(SavanaError::InvalidState)
    ));
    assert!(
        transport.take_requests().is_empty(),
        "ordinary output documents must be rejected before transport"
    );
}

#[test]
fn tool_denial_is_typed_and_never_dispatches() {
    let step = planned_step(0x51);
    let pending = AgentPendingToolCallRefV2::from_authority_entropy([0x52; 16]).unwrap();
    let responses = vec![
        plan_response(step),
        mutation(AgentBrowserMutationResponseV2::ToolProposed { pending }),
        mutation(AgentBrowserMutationResponseV2::ToolDenied {
            code: PublicStableCodeV2::PolicyDenied,
            trace: trace(0x53),
        }),
    ];
    let (mut session, transport, _) = authenticated_session(responses);
    let plan = session.run_planner(IntentPrivacy::Private).unwrap();

    assert!(matches!(
        session.execute(&plan, &RecordingDecision::new(true)),
        Err(SavanaError::PolicyRefused(_))
    ));

    let actions = actions_after_authentication(&transport.take_requests());
    assert_eq!(
        actions,
        vec![
            AgentBrowserActionV2::RunPlanner,
            AgentBrowserActionV2::ProposePlanStep(step),
            AgentBrowserActionV2::EvaluatePending(pending),
        ]
    );
    assert!(!actions
        .iter()
        .any(|action| matches!(action, AgentBrowserActionV2::DispatchTicket(_))));
}

#[test]
fn open_approval_uses_the_callback_decision_and_approvald_remains_the_settler() {
    let step = planned_step(0x61);
    let pending = AgentPendingToolCallRefV2::from_authority_entropy([0x62; 16]).unwrap();
    let ticket = AgentExecutionTicketRefV2::from_authority_entropy([0x63; 16]).unwrap();
    let execution = AgentExecutionRefV2::from_authority_entropy([0x64; 16]).unwrap();
    let output = AgentMaskedDocumentRefV2::from_authority_entropy([0x65; 16]).unwrap();
    let transfer =
        ApprovalDisplayAuthenticationTransferCapabilityV2::from_authority_entropy([0x66; 32])
            .unwrap();
    let mut responses = vec![
        plan_response(step),
        mutation(AgentBrowserMutationResponseV2::ToolProposed { pending }),
        mutation(AgentBrowserMutationResponseV2::ToolOpenApproval {
            post: FixedBrowserFormPostCarrierV2::AgentApprovalDisplay(transfer),
            trace: trace(0x67),
        }),
    ];
    responses.extend(approval_responses(
        ApprovalPurposeV2::ToolExecution,
        ApprovalDecisionBrowserFinishResponseV2::Approved,
    ));
    responses.extend([
        mutation(AgentBrowserMutationResponseV2::ToolAuthorized {
            ticket,
            trace: trace(0x68),
        }),
        mutation(AgentBrowserMutationResponseV2::ExecutionDispatched {
            execution,
            state: PublicDispatchAcceptedStateV2::Dispatching,
        }),
        mutation(AgentBrowserMutationResponseV2::ExecutionRefreshed {
            execution,
            state: AgentBrowserExecutionStateV2::Succeeded { document: output },
        }),
    ]);
    let (mut session, transport, _) = authenticated_session(responses);
    let plan = session.run_planner(IntentPrivacy::Private).unwrap();
    let approval = RecordingDecision::new(true);

    session.execute(&plan, &approval).unwrap();

    assert_eq!(
        approval.requests.lock().unwrap().as_slice(),
        [(
            "Approve exact operation".to_owned(),
            ApprovalPurpose::ToolExecution
        )]
    );
    let requests = transport.take_requests();
    let workflow = &requests[4..];
    assert_eq!(
        workflow
            .iter()
            .map(|request| request.route)
            .collect::<Vec<_>>(),
        vec![
            BrowserRoute::AgentAction,
            BrowserRoute::AgentAction,
            BrowserRoute::AgentAction,
            BrowserRoute::ApprovalUiAuthenticationAccept,
            BrowserRoute::ApprovalUiAuthenticationBegin,
            BrowserRoute::ApprovalUiAuthenticationFinish,
            BrowserRoute::ApprovalDisplay,
            BrowserRoute::ApprovalDecisionBegin,
            BrowserRoute::ApprovalDecisionFinish,
            BrowserRoute::AgentAction,
            BrowserRoute::AgentAction,
            BrowserRoute::AgentAction,
        ]
    );
    let decision = decode_approval_decision_browser_begin_request_v2(&workflow[7].body).unwrap();
    assert_eq!(decision.decision(), ApprovalDecisionV2::Approve);
    assert_eq!(
        actions_after_authentication(&requests),
        vec![
            AgentBrowserActionV2::RunPlanner,
            AgentBrowserActionV2::ProposePlanStep(step),
            AgentBrowserActionV2::EvaluatePending(pending),
            AgentBrowserActionV2::EvaluatePending(pending),
            AgentBrowserActionV2::DispatchTicket(ticket),
            AgentBrowserActionV2::RefreshExecution(execution),
        ]
    );
}

#[test]
fn rejected_approval_is_settled_then_denied_without_dispatch() {
    let step = planned_step(0x71);
    let pending = AgentPendingToolCallRefV2::from_authority_entropy([0x72; 16]).unwrap();
    let transfer =
        ApprovalDisplayAuthenticationTransferCapabilityV2::from_authority_entropy([0x73; 32])
            .unwrap();
    let mut responses = vec![
        plan_response(step),
        mutation(AgentBrowserMutationResponseV2::ToolProposed { pending }),
        mutation(AgentBrowserMutationResponseV2::ToolOpenApproval {
            post: FixedBrowserFormPostCarrierV2::AgentApprovalDisplay(transfer),
            trace: trace(0x74),
        }),
    ];
    responses.extend(approval_responses(
        ApprovalPurposeV2::ToolExecution,
        ApprovalDecisionBrowserFinishResponseV2::Denied,
    ));
    responses.push(mutation(AgentBrowserMutationResponseV2::ToolDenied {
        code: PublicStableCodeV2::ApprovalDenied,
        trace: trace(0x75),
    }));
    let (mut session, transport, _) = authenticated_session(responses);
    let plan = session.run_planner(IntentPrivacy::Private).unwrap();

    assert!(matches!(
        session.execute(&plan, &RecordingDecision::new(false)),
        Err(SavanaError::ApprovalDenied(_))
    ));

    let requests = transport.take_requests();
    let workflow = &requests[4..];
    let decision = decode_approval_decision_browser_begin_request_v2(&workflow[7].body).unwrap();
    assert_eq!(decision.decision(), ApprovalDecisionV2::Deny);
    let actions = actions_after_authentication(&requests);
    assert!(!actions
        .iter()
        .any(|action| matches!(action, AgentBrowserActionV2::DispatchTicket(_))));
}

#[test]
fn every_terminal_execution_state_is_preserved_without_inventing_output() {
    let cases = [
        (
            AgentBrowserExecutionStateV2::EffectSucceededOutputQuarantined {
                class: PublicFailureClassV2::ResultGate,
            },
            Some((
                ExecutionStatus::EffectSucceededOutputQuarantined,
                "result_gate",
            )),
        ),
        (
            AgentBrowserExecutionStateV2::FailedNoEffect {
                class: PublicFailureClassV2::Infrastructure,
            },
            Some((ExecutionStatus::FailedNoEffect, "infrastructure")),
        ),
        (AgentBrowserExecutionStateV2::Indeterminate, None),
    ];
    for (index, (terminal, expected)) in cases.into_iter().enumerate() {
        let seed = 0x80 + index as u8 * 4;
        let step = planned_step(seed);
        let pending = AgentPendingToolCallRefV2::from_authority_entropy([seed + 1; 16]).unwrap();
        let ticket = AgentExecutionTicketRefV2::from_authority_entropy([seed + 2; 16]).unwrap();
        let execution = AgentExecutionRefV2::from_authority_entropy([seed + 3; 16]).unwrap();
        let responses = vec![
            plan_response(step),
            mutation(AgentBrowserMutationResponseV2::ToolProposed { pending }),
            mutation(AgentBrowserMutationResponseV2::ToolAuthorized {
                ticket,
                trace: trace(seed),
            }),
            mutation(AgentBrowserMutationResponseV2::ExecutionDispatched {
                execution,
                state: PublicDispatchAcceptedStateV2::Prepared,
            }),
            mutation(AgentBrowserMutationResponseV2::ExecutionRefreshed {
                execution,
                state: terminal,
            }),
        ];
        let (mut session, transport, _) = authenticated_session(responses);
        let plan = session.run_planner(IntentPrivacy::Private).unwrap();
        let result = session.execute(&plan, &RecordingDecision::new(true));
        match expected {
            Some((expected, failure_class)) => {
                let result = result.unwrap();
                assert_eq!(result.status(), expected);
                assert_eq!(result.failure_class(), Some(failure_class));
                assert!(result.outputs().is_empty());
            }
            None => assert!(matches!(result, Err(SavanaError::IndeterminateEffect))),
        }
        let actions = actions_after_authentication(&transport.take_requests());
        assert_eq!(
            actions
                .iter()
                .filter(|action| matches!(action, AgentBrowserActionV2::RefreshExecution(_)))
                .count(),
            1,
            "terminal state must never be auto-retried"
        );
    }
}

#[test]
fn execution_polls_every_valid_nonterminal_state_without_redispatching() {
    let step = planned_step(0xa0);
    let pending = AgentPendingToolCallRefV2::from_authority_entropy([0xa1; 16]).unwrap();
    let ticket = AgentExecutionTicketRefV2::from_authority_entropy([0xa2; 16]).unwrap();
    let execution = AgentExecutionRefV2::from_authority_entropy([0xa3; 16]).unwrap();
    let output = AgentMaskedDocumentRefV2::from_authority_entropy([0xa4; 16]).unwrap();
    let responses = vec![
        plan_response(step),
        mutation(AgentBrowserMutationResponseV2::ToolProposed { pending }),
        mutation(AgentBrowserMutationResponseV2::ToolAuthorized {
            ticket,
            trace: trace(0xa5),
        }),
        mutation(AgentBrowserMutationResponseV2::ExecutionDispatched {
            execution,
            state: PublicDispatchAcceptedStateV2::Prepared,
        }),
        mutation(AgentBrowserMutationResponseV2::ExecutionRefreshed {
            execution,
            state: AgentBrowserExecutionStateV2::Prepared,
        }),
        mutation(AgentBrowserMutationResponseV2::ExecutionRefreshed {
            execution,
            state: AgentBrowserExecutionStateV2::Dispatching,
        }),
        mutation(AgentBrowserMutationResponseV2::ExecutionRefreshed {
            execution,
            state: AgentBrowserExecutionStateV2::ResultGatePending,
        }),
        mutation(AgentBrowserMutationResponseV2::ExecutionRefreshed {
            execution,
            state: AgentBrowserExecutionStateV2::Succeeded { document: output },
        }),
    ];
    let (mut session, transport, _) = authenticated_session(responses);
    let plan = session.run_planner(IntentPrivacy::Private).unwrap();

    let result = session
        .execute(&plan, &RecordingDecision::new(true))
        .unwrap();

    assert_eq!(result.status(), ExecutionStatus::Succeeded);
    let actions = actions_after_authentication(&transport.take_requests());
    assert_eq!(
        actions
            .iter()
            .filter(|action| matches!(action, AgentBrowserActionV2::DispatchTicket(_)))
            .count(),
        1
    );
    assert_eq!(
        actions
            .iter()
            .filter(|action| matches!(action, AgentBrowserActionV2::RefreshExecution(_)))
            .count(),
        4
    );
}

#[test]
fn mismatched_execution_refresh_reference_fails_closed_without_retry() {
    let step = planned_step(0xb0);
    let pending = AgentPendingToolCallRefV2::from_authority_entropy([0xb1; 16]).unwrap();
    let ticket = AgentExecutionTicketRefV2::from_authority_entropy([0xb2; 16]).unwrap();
    let execution = AgentExecutionRefV2::from_authority_entropy([0xb3; 16]).unwrap();
    let other = AgentExecutionRefV2::from_authority_entropy([0xb4; 16]).unwrap();
    let responses = vec![
        plan_response(step),
        mutation(AgentBrowserMutationResponseV2::ToolProposed { pending }),
        mutation(AgentBrowserMutationResponseV2::ToolAuthorized {
            ticket,
            trace: trace(0xb5),
        }),
        mutation(AgentBrowserMutationResponseV2::ExecutionDispatched {
            execution,
            state: PublicDispatchAcceptedStateV2::Prepared,
        }),
        mutation(AgentBrowserMutationResponseV2::ExecutionRefreshed {
            execution: other,
            state: AgentBrowserExecutionStateV2::Prepared,
        }),
    ];
    let (mut session, transport, _) = authenticated_session(responses);
    let plan = session.run_planner(IntentPrivacy::Private).unwrap();

    assert!(matches!(
        session.execute(&plan, &RecordingDecision::new(true)),
        Err(SavanaError::InvalidState)
    ));
    assert_eq!(
        actions_after_authentication(&transport.take_requests())
            .iter()
            .filter(|action| matches!(action, AgentBrowserActionV2::RefreshExecution(_)))
            .count(),
        1
    );
}

#[test]
fn release_polls_valid_nonterminal_states_without_redispatching() {
    let transfer =
        ApprovalDisplayAuthenticationTransferCapabilityV2::from_authority_entropy([0xc1; 32])
            .unwrap();
    let ticket = AgentReleaseTicketRefV2::from_authority_entropy([0xc2; 16]).unwrap();
    let release = AgentReleaseRefV2::from_authority_entropy([0xc3; 16]).unwrap();
    let mut responses = vec![mutation(
        AgentBrowserMutationResponseV2::ReleaseOpenApproval {
            post: FixedBrowserFormPostCarrierV2::AgentApprovalDisplay(transfer),
        },
    )];
    responses.extend(approval_responses(
        ApprovalPurposeV2::FinalRelease,
        ApprovalDecisionBrowserFinishResponseV2::Approved,
    ));
    responses.extend([
        cbor_response(
            encode_agent_browser_read_view_response_v2(
                &AgentBrowserReadViewResponseV2::new(
                    AgentViewV2::ContentState(AgentContentStateV2::Ready),
                    vec![AgentBrowserObjectRefV2::ReleaseTicket(ticket)],
                    None,
                )
                .unwrap(),
            )
            .unwrap(),
        ),
        mutation(AgentBrowserMutationResponseV2::ReleaseDispatched {
            release,
            state: PublicDispatchAcceptedStateV2::Prepared,
        }),
        mutation(AgentBrowserMutationResponseV2::ReleaseRefreshed {
            release,
            state: AgentBrowserReleaseStateV2::Prepared,
        }),
        mutation(AgentBrowserMutationResponseV2::ReleaseRefreshed {
            release,
            state: AgentBrowserReleaseStateV2::Dispatching,
        }),
        mutation(AgentBrowserMutationResponseV2::ReleaseRefreshed {
            release,
            state: AgentBrowserReleaseStateV2::Succeeded,
        }),
    ]);
    let (mut session, transport, _) = authenticated_session(responses);
    let document = session.initial_document().clone();
    let approval = RecordingDecision::new(true);

    let result = session.release(&document, &approval).unwrap();

    assert_eq!(result.status(), ExecutionStatus::Succeeded);
    assert!(result.outputs().is_empty());
    assert_eq!(
        approval.requests.lock().unwrap().as_slice(),
        [(
            "Approve exact operation".to_owned(),
            ApprovalPurpose::FinalRelease
        )]
    );
    let requests = transport.take_requests();
    assert_eq!(
        requests[4..]
            .iter()
            .map(|request| request.route)
            .collect::<Vec<_>>(),
        vec![
            BrowserRoute::AgentAction,
            BrowserRoute::ApprovalUiAuthenticationAccept,
            BrowserRoute::ApprovalUiAuthenticationBegin,
            BrowserRoute::ApprovalUiAuthenticationFinish,
            BrowserRoute::ApprovalDisplay,
            BrowserRoute::ApprovalDecisionBegin,
            BrowserRoute::ApprovalDecisionFinish,
            BrowserRoute::AgentView,
            BrowserRoute::AgentAction,
            BrowserRoute::AgentAction,
            BrowserRoute::AgentAction,
            BrowserRoute::AgentAction,
        ]
    );
    let actions = actions_after_authentication(&requests);
    assert!(matches!(
        actions[0],
        AgentBrowserActionV2::PrepareRelease(_)
    ));
    assert_eq!(actions[1], AgentBrowserActionV2::DispatchRelease(ticket));
    assert_eq!(actions[2], AgentBrowserActionV2::RefreshRelease(release));
    assert_eq!(actions[3], AgentBrowserActionV2::RefreshRelease(release));
    assert_eq!(actions[4], AgentBrowserActionV2::RefreshRelease(release));
}

#[test]
fn every_terminal_release_state_is_preserved_without_inventing_output_or_retrying() {
    let cases = [
        (
            AgentBrowserReleaseStateV2::EffectSucceededOutputQuarantined {
                class: PublicFailureClassV2::ReleaseEvidence,
            },
            Some((
                ExecutionStatus::EffectSucceededOutputQuarantined,
                "release_evidence",
            )),
        ),
        (
            AgentBrowserReleaseStateV2::FailedNoEffect {
                class: PublicFailureClassV2::Infrastructure,
            },
            Some((ExecutionStatus::FailedNoEffect, "infrastructure")),
        ),
        (AgentBrowserReleaseStateV2::Indeterminate, None),
    ];
    for (index, (terminal, expected)) in cases.into_iter().enumerate() {
        let seed = 0xd0 + index as u8 * 4;
        let transfer =
            ApprovalDisplayAuthenticationTransferCapabilityV2::from_authority_entropy([seed; 32])
                .unwrap();
        let ticket = AgentReleaseTicketRefV2::from_authority_entropy([seed + 1; 16]).unwrap();
        let release = AgentReleaseRefV2::from_authority_entropy([seed + 2; 16]).unwrap();
        let mut responses = vec![mutation(
            AgentBrowserMutationResponseV2::ReleaseOpenApproval {
                post: FixedBrowserFormPostCarrierV2::AgentApprovalDisplay(transfer),
            },
        )];
        responses.extend(approval_responses(
            ApprovalPurposeV2::FinalRelease,
            ApprovalDecisionBrowserFinishResponseV2::Approved,
        ));
        responses.extend([
            cbor_response(
                encode_agent_browser_read_view_response_v2(
                    &AgentBrowserReadViewResponseV2::new(
                        AgentViewV2::ContentState(AgentContentStateV2::Ready),
                        vec![AgentBrowserObjectRefV2::ReleaseTicket(ticket)],
                        None,
                    )
                    .unwrap(),
                )
                .unwrap(),
            ),
            mutation(AgentBrowserMutationResponseV2::ReleaseDispatched {
                release,
                state: PublicDispatchAcceptedStateV2::Dispatching,
            }),
            mutation(AgentBrowserMutationResponseV2::ReleaseRefreshed {
                release,
                state: terminal,
            }),
        ]);
        let (mut session, transport, _) = authenticated_session(responses);
        let document = session.initial_document().clone();
        let result = session.release(&document, &RecordingDecision::new(true));
        match expected {
            Some((expected, failure_class)) => {
                let result = result.unwrap();
                assert_eq!(result.status(), expected);
                assert_eq!(result.failure_class(), Some(failure_class));
                assert!(result.outputs().is_empty());
            }
            None => assert!(matches!(result, Err(SavanaError::IndeterminateEffect))),
        }
        assert_eq!(
            actions_after_authentication(&transport.take_requests())
                .iter()
                .filter(|action| matches!(action, AgentBrowserActionV2::RefreshRelease(_)))
                .count(),
            1
        );
    }
}

#[test]
fn ambiguous_release_ticket_projection_fails_before_dispatch() {
    let transfer =
        ApprovalDisplayAuthenticationTransferCapabilityV2::from_authority_entropy([0xe1; 32])
            .unwrap();
    let first = AgentReleaseTicketRefV2::from_authority_entropy([0xe2; 16]).unwrap();
    let second = AgentReleaseTicketRefV2::from_authority_entropy([0xe3; 16]).unwrap();
    let mut responses = vec![mutation(
        AgentBrowserMutationResponseV2::ReleaseOpenApproval {
            post: FixedBrowserFormPostCarrierV2::AgentApprovalDisplay(transfer),
        },
    )];
    responses.extend(approval_responses(
        ApprovalPurposeV2::FinalRelease,
        ApprovalDecisionBrowserFinishResponseV2::Approved,
    ));
    responses.push(cbor_response(
        encode_agent_browser_read_view_response_v2(
            &AgentBrowserReadViewResponseV2::new(
                AgentViewV2::ContentState(AgentContentStateV2::Ready),
                vec![
                    AgentBrowserObjectRefV2::ReleaseTicket(first),
                    AgentBrowserObjectRefV2::ReleaseTicket(second),
                ],
                None,
            )
            .unwrap(),
        )
        .unwrap(),
    ));
    let (mut session, transport, _) = authenticated_session(responses);
    let document = session.initial_document().clone();

    assert!(matches!(
        session.release(&document, &RecordingDecision::new(true)),
        Err(SavanaError::InvalidState)
    ));
    assert_eq!(
        actions_after_authentication(&transport.take_requests()),
        vec![AgentBrowserActionV2::PrepareRelease(
            AgentMaskedDocumentRefV2::from_authority_entropy([0x35; 16]).unwrap()
        )]
    );
}

#[test]
fn release_rejects_wrong_kind_cross_session_and_closed_state_before_transport() {
    let step = planned_step(0xd1);
    let (owner, _, _) = authenticated_session(Vec::new());
    let foreign_document = owner.initial_document().clone();
    let (mut session, transport, _) = authenticated_session(vec![
        plan_response(step),
        mutation(AgentBrowserMutationResponseV2::SessionClosed {
            state: AgentSessionStatusV2::Closed,
        }),
    ]);
    let plan = session.run_planner(IntentPrivacy::Private).unwrap();
    let step_handle = plan.steps()[0].handle().clone();
    transport.take_requests();

    assert!(matches!(
        session.release(&step_handle, &RecordingDecision::new(true)),
        Err(SavanaError::WrongHandleKind { .. })
    ));
    assert!(matches!(
        session.release(&foreign_document, &RecordingDecision::new(true)),
        Err(SavanaError::WrongSession)
    ));
    assert!(transport.take_requests().is_empty());
    session.close().unwrap();
    assert_eq!(transport.take_requests().len(), 1);
    let own_document = session.initial_document().clone();
    assert!(matches!(
        session.release(&own_document, &RecordingDecision::new(true)),
        Err(SavanaError::InvalidState)
    ));
    assert!(transport.take_requests().is_empty());
}
