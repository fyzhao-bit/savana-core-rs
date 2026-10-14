// Included in the compiler fixture module; no provider/network effect is sent.
fn action_driver_fixture() -> PlannerAuthorityFixtureV2 {
    let mut f = private_action_fixture(2);
    let manifest = f.authority.sessions[0].active_state_manifest_digest;
    f.authority
        .policy
        .as_mut()
        .unwrap()
        .install_g7(test_g7_runtime(
            f.authority.config.installation_id,
            manifest,
            7,
            8,
        ))
        .unwrap();
    f.authority
        .policy
        .as_ref()
        .unwrap()
        .declassification_rules
        .set_recovery_fence_for_test(8);
    f
}

#[test]
fn fused_action_driver_stops_at_deny_or_exact_user_approval_without_ticket() {
    for approval in [false, true] {
        let mut f = action_driver_fixture();
        f.authority.policy.as_mut().unwrap().disposition = if approval {
            VerifiedPolicyDispositionV2::require_approval_from_verified_policy()
        } else {
            VerifiedPolicyDispositionV2::deny_from_verified_policy()
        };
        f.authority
            .tick_fused_actions_v04(&mut f.values, &mut || UnixMillisV2::new(203))
            .unwrap();
        assert_eq!(f.authority.intents.len(), 1);
        assert_eq!(f.authority.tool_approvals.len(), usize::from(approval));
        assert!(f.authority.execution_tickets.is_empty());
        assert!(f.authority.executions.is_empty());
        let head = disk(&f);
        let intent = f.authority.intents[0].intent;
        f.authority.policy.as_mut().unwrap().fused_action_not_before = 0;
        f.authority
            .tick_fused_actions_v04(&mut f.values, &mut || UnixMillisV2::new(204))
            .unwrap();
        assert_eq!(disk(&f), head);
        assert_eq!(f.authority.intents[0].intent, intent);
        assert_eq!(f.authority.intents.len(), 1);
        assert_eq!(f.authority.tool_approvals.len(), usize::from(approval));
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
}

#[test]
fn fused_action_driver_never_renews_expired_or_revoked_authority() {
    for revoked in [false, true] {
        let mut f = action_driver_fixture();
        if revoked {
            f.authority
                .policy
                .as_mut()
                .unwrap()
                .durable
                .revoke_task_authorization(f.authority.sessions[0].durable_task_id)
                .unwrap();
        }
        let head = disk(&f);
        f.authority
            .tick_fused_actions_v04(&mut f.values, &mut || {
                UnixMillisV2::new(if revoked { 203 } else { 10_001 })
            })
            .unwrap();
        assert_eq!(disk(&f), head);
        assert!(f.authority.intents.is_empty());
        assert!(f.authority.executions.is_empty());
    }
}

#[test]
fn fused_action_driver_rechecks_time_between_prepare_evaluate_and_dispatch() {
    for times in [[203, 350, 351], [203, 204, 350]] {
        let mut f = action_driver_fixture();
        let mut clock = times.into_iter();
        f.authority
            .tick_fused_actions_v04(&mut f.values, &mut || {
                UnixMillisV2::new(clock.next().unwrap())
            })
            .unwrap();
        assert!(f.authority.executions.is_empty());
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
    let mut f = action_driver_fixture();
    let mut clock = [203, 202].into_iter();
    assert_eq!(
        f.authority
            .tick_fused_actions_v04(&mut f.values, &mut || UnixMillisV2::new(
                clock.next().unwrap()
            )),
        Err(savana_kernel_protocol::StableCode::KernelUnavailable)
    );
}

fn private_action_fixture(count: u16) -> PlannerAuthorityFixtureV2 {
    let (mut f, request) = business_proposal_fixture("A", "Alice");
    install(&mut f, &request, count);
    choose(&mut f, 1, 1, true, 202);
    let b = bindings(&request);
    pin_inputs(&mut f, &b, 202).unwrap();
    let candidate = compile(&f, &b, 202).unwrap();
    approve_recipes(&mut f, &candidate);
    f
}
fn prepare_private(
    f: &mut PlannerAuthorityFixtureV2,
    time: u64,
) -> Result<super::super::fused_actions::FusedPrivateActionV04, KernelAgentAuthorityErrorV2> {
    f.authority.prepare_next_fused_action_v04(
        f.run,
        &mut f.values,
        f.authority.sessions[0].active_state_manifest_digest,
        7,
        UnixMillisV2::new(time),
    )
}

#[test]
fn fused_private_action_real_g4_g5_retry_keeps_one_intent_and_legacy_entry_closed() {
    let mut f = private_action_fixture(2);
    let manifest = f.authority.sessions[0].active_state_manifest_digest;
    let root = f
        .authority
        .policy
        .as_ref()
        .unwrap()
        .durable
        .task_authorization_state(f.authority.sessions[0].durable_task_id)
        .unwrap()
        .digest();
    let action = prepare_private(&mut f, 202).unwrap();
    let first = disk(&f);
    let replay = prepare_private(&mut f, 203).unwrap();
    assert_eq!(action.intent, replay.intent);
    assert_eq!(disk(&f), first);
    assert_eq!(f.authority.intents.len(), 1);
    let intent = &f.authority.intents[0];
    assert_eq!(intent.fused.as_ref().unwrap().reference.operation, 1);
    let pending = intent.pending;
    assert!(f
        .authority
        .evaluate_tool_call(
            EvaluateToolCallRequestV2::new(pending),
            &f.values,
            f.caller_identity,
            manifest,
            7,
            UnixMillisV2::new(203)
        )
        .is_err());
    let evaluated = f
        .authority
        .evaluate_fused_action_v04(&action, &f.values, manifest, 7, UnixMillisV2::new(203))
        .unwrap();
    let EvaluateToolCallResponseV2::Allowed { ticket, .. } = evaluated.0 else {
        panic!("fixture G5 permit expected")
    };
    let evaluated = f
        .authority
        .evaluate_fused_action_v04(&action, &f.values, manifest, 7, UnixMillisV2::new(204))
        .unwrap();
    let EvaluateToolCallResponseV2::Allowed { ticket: again, .. } = evaluated.0 else {
        panic!("same permit")
    };
    assert_eq!(ticket, again);
    assert_eq!(f.authority.execution_tickets.len(), 1);
    assert!(f
        .authority
        .dispatch_execution(
            RequestIdV2::new([19; 16]),
            savana_kernel_protocol::v2::DispatchExecutionRequestV2::new(ticket),
            f.caller_identity,
            manifest,
            7,
            11,
            UnixMillisV2::new(204)
        )
        .is_err());
    assert!(f.authority.executions.is_empty());
    assert_eq!(
        f.authority
            .policy
            .as_ref()
            .unwrap()
            .durable
            .task_authorization_state(f.authority.sessions[0].durable_task_id)
            .unwrap()
            .digest(),
        root
    );
}

#[test]
fn fused_private_action_cannot_start_without_pin_recipe_or_live_generation() {
    for mode in 0..3 {
        let (mut f, request) = business_proposal_fixture("A", "Alice");
        install(&mut f, &request, 1);
        choose(&mut f, 1, 1, true, 202);
        let b = bindings(&request);
        if mode > 0 {
            pin_inputs(&mut f, &b, 202).unwrap();
        }
        if mode == 2 {
            let candidate = compile(&f, &b, 202).unwrap();
            approve_recipes(&mut f, &candidate);
        }
        let disk_before = disk(&f);
        let result = f.authority.prepare_next_fused_action_v04(
            f.run,
            &mut f.values,
            f.authority.sessions[0].active_state_manifest_digest,
            if mode == 2 { 8 } else { 7 },
            UnixMillisV2::new(202),
        );
        assert!(result.is_err());
        assert_eq!(disk(&f), disk_before);
        assert!(f.authority.intents.is_empty());
    }
}

#[test]
fn fused_private_action_replacement_invalidates_old_pending_without_reusing_approval() {
    let mut f = private_action_fixture(2);
    let manifest = f.authority.sessions[0].active_state_manifest_digest;
    let old = prepare_private(&mut f, 202).unwrap();
    choose(&mut f, 2, 2, true, 302);
    let before = disk(&f);
    assert!(f
        .authority
        .evaluate_fused_action_v04(&old, &f.values, manifest, 7, UnixMillisV2::new(302))
        .is_err());
    assert_eq!(disk(&f), before);
    let next = prepare_private(&mut f, 302).unwrap();
    assert_ne!(old.intent, next.intent);
    let latest = f.authority.intents.last().unwrap();
    assert_eq!(latest.fused.as_ref().unwrap().reference.operation, 2);
    assert_eq!(latest.fused.as_ref().unwrap().reference.plan_revision, 2);
    assert!(f
        .authority
        .evaluate_fused_action_v04(&next, &f.values, manifest, 7, UnixMillisV2::new(350))
        .is_err());
    f.authority
        .policy
        .as_mut()
        .unwrap()
        .durable
        .revoke_task_authorization(f.authority.sessions[0].durable_task_id)
        .unwrap();
    assert!(prepare_private(&mut f, 303).is_err());
}

#[test]
fn fused_private_action_still_runs_g5_deny_policy() {
    let mut f = private_action_fixture(1);
    let manifest = f.authority.sessions[0].active_state_manifest_digest;
    f.authority.policy.as_mut().unwrap().disposition =
        VerifiedPolicyDispositionV2::deny_from_verified_policy();
    let action = prepare_private(&mut f, 202).unwrap();
    assert!(matches!(
        f.authority
            .evaluate_fused_action_v04(&action, &f.values, manifest, 7, UnixMillisV2::new(203))
            .unwrap()
            .0,
        EvaluateToolCallResponseV2::Denied { .. }
    ));
    assert!(f.authority.execution_tickets.is_empty());
    assert!(f.authority.executions.is_empty());
}

#[test]
fn fused_private_action_g6_requires_exact_signed_current_content_and_blocks_legacy_authorize() {
    use savana_kernel_protocol::v2::{
        sign_task_action_approval_v2, ApprovalDecisionV2, AuthorizeToolCallRequestV2,
        SignedApprovalSettlementV2, TaskActionApprovalDecisionV2, TaskActionApprovalV2,
        UnsignedApprovalSettlementV2,
    };
    for replace_before_approval in [false, true] {
        let mut f = private_action_fixture(1);
        let manifest = f.authority.sessions[0].active_state_manifest_digest;
        f.authority.policy.as_mut().unwrap().disposition =
            VerifiedPolicyDispositionV2::require_approval_from_verified_policy();
        let action = prepare_private(&mut f, 202).unwrap();
        let evaluated = f
            .authority
            .evaluate_fused_action_v04(&action, &f.values, manifest, 7, UnixMillisV2::new(203))
            .unwrap();
        let EvaluateToolCallResponseV2::NeedsApproval {
            approval, envelope, ..
        } = evaluated.0
        else {
            panic!("exact G6 required")
        };
        assert!(f.authority.execution_tickets.is_empty());
        let material = envelope.unverified_material().unwrap();
        assert_eq!(material.expires_at(), UnixMillisV2::new(350));
        assert!(material
            .display_text()
            .as_str()
            .contains("\"resource\":\"A\""));
        assert!(material
            .display_text()
            .as_str()
            .contains("\"destination\":\"Alice\""));
        assert_eq!(
            material.task_action_binding().unwrap().content_digest(),
            f.authority.intents[0].task_match.content_digest()
        );
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
            UnixMillisV2::new(340),
        )
        .unwrap();
        let key = SigningKey::from_bytes(&[0x9c; 32]);
        let old = SignedApprovalSettlementV2::sign(generic, &key).unwrap();
        assert!(f
            .authority
            .authorize_fused_action_v04(&action, old.clone(), manifest, 7, UnixMillisV2::new(205))
            .is_err());
        assert!(!f.authority.tool_approvals[0].consumed);
        let context = material.task_action_context(&generic).unwrap();
        let mut wrong = context.clone();
        wrong.content_digest = Digest32V2::new([99; 32]);
        let sign = |context| {
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
        let wrong = old.clone().with_task_action_approval(sign(wrong)).unwrap();
        assert!(f
            .authority
            .authorize_fused_action_v04(&action, wrong, manifest, 7, UnixMillisV2::new(205))
            .is_err());
        assert!(!f.authority.tool_approvals[0].consumed);
        let correct = old.with_task_action_approval(sign(context)).unwrap();
        let legacy = AuthorizeToolCallRequestV2::new(
            f.authority.intents[0].pending,
            approval,
            correct.clone(),
        )
        .unwrap();
        assert!(f
            .authority
            .authorize_tool_call(
                &legacy,
                f.caller_identity,
                manifest,
                7,
                UnixMillisV2::new(205)
            )
            .is_err());
        assert!(!f.authority.tool_approvals[0].consumed);
        if replace_before_approval {
            choose(&mut f, 2, 2, true, 302);
            assert!(f
                .authority
                .authorize_fused_action_v04(&action, correct, manifest, 7, UnixMillisV2::new(303))
                .is_err());
            assert!(!f.authority.tool_approvals[0].consumed);
            assert!(f.authority.execution_tickets.is_empty());
            continue;
        }
        let ticket = f
            .authority
            .authorize_fused_action_v04(
                &action,
                correct.clone(),
                manifest,
                7,
                UnixMillisV2::new(205),
            )
            .unwrap();
        assert!(f.authority.tool_approvals[0].consumed);
        assert_eq!(
            f.authority
                .authorize_fused_action_v04(&action, correct, manifest, 7, UnixMillisV2::new(206))
                .unwrap()
                .0,
            ticket.0
        );
        assert_eq!(f.authority.execution_tickets.len(), 1);
        assert!(f.authority.executions.is_empty());
    }
}

#[test]
fn fused_private_action_lost_volatile_handles_reuses_original_durable_g4_and_g5() {
    let mut f = private_action_fixture(1);
    let manifest = f.authority.sessions[0].active_state_manifest_digest;
    let action = prepare_private(&mut f, 202).unwrap();
    f.authority
        .evaluate_fused_action_v04(&action, &f.values, manifest, 7, UnixMillisV2::new(203))
        .unwrap();
    let original = f.authority.intents[0].action_intent_id;
    let before = disk(&f);
    // Simulate loss of these volatile mappings only, not full session recovery.
    f.authority.intents.clear();
    f.authority.execution_tickets.clear();
    let restored = prepare_private(&mut f, 204).unwrap();
    assert_ne!(restored.intent, action.intent);
    assert_eq!(f.authority.intents[0].action_intent_id, original);
    assert_eq!(disk(&f), before);
    assert!(matches!(
        f.authority
            .evaluate_fused_action_v04(&restored, &f.values, manifest, 7, UnixMillisV2::new(204))
            .unwrap()
            .0,
        EvaluateToolCallResponseV2::Allowed { .. }
    ));
    assert_eq!(disk(&f), before);
    assert!(f.authority.executions.is_empty());
}
