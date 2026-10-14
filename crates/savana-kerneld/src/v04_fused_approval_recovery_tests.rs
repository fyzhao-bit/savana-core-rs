// Included in the private compiler fixture. These tests do not restore login
// sessions or send provider effects; session authority is supplied by the fixture.
fn approval_recovery_fixture() -> PlannerAuthorityFixtureV2 {
    let mut f = private_action_fixture(1);
    f.authority.policy.as_mut().unwrap().disposition =
        VerifiedPolicyDispositionV2::require_approval_from_verified_policy();
    f
}

fn pending_private_approval(
    f: &mut PlannerAuthorityFixtureV2,
) -> (
    super::super::fused_actions::FusedPrivateActionV04,
    savana_kernel_protocol::v2::ToolKernelApprovalHandleV2,
    savana_kernel_protocol::v2::SignedApprovalEnvelopeV2,
) {
    let action = prepare_private(f, 202).unwrap();
    let manifest = f.authority.sessions[0].active_state_manifest_digest;
    let result = f
        .authority
        .evaluate_fused_action_v04(&action, &f.values, manifest, 7, UnixMillisV2::new(203))
        .unwrap();
    let EvaluateToolCallResponseV2::NeedsApproval {
        approval, envelope, ..
    } = result.0
    else {
        panic!("pending exact approval");
    };
    (action, approval, envelope)
}

fn signed_private_settlement(
    f: &PlannerAuthorityFixtureV2,
    envelope: &savana_kernel_protocol::v2::SignedApprovalEnvelopeV2,
    approve: bool,
    expires: u64,
) -> savana_kernel_protocol::v2::SignedApprovalSettlementV2 {
    use savana_kernel_protocol::v2::{
        sign_task_action_approval_v2, ApprovalDecisionV2, SignedApprovalSettlementV2,
        TaskActionApprovalDecisionV2, TaskActionApprovalV2, UnsignedApprovalSettlementV2,
    };
    let material = envelope.unverified_material().unwrap();
    let unsigned = UnsignedApprovalSettlementV2::new(
        f.authority.config.installation_id,
        material.active_state_manifest_digest(),
        7,
        ApprovalPurposeV2::ToolExecution,
        envelope.envelope_digest().unwrap(),
        if approve {
            ApprovalDecisionV2::Approve
        } else {
            ApprovalDecisionV2::Deny
        },
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
        UnixMillisV2::new(expires),
    )
    .unwrap();
    let key = SigningKey::from_bytes(&[0x9c; 32]);
    let receipt = SignedApprovalSettlementV2::sign(unsigned, &key).unwrap();
    if !approve {
        return receipt;
    }
    let exact = sign_task_action_approval_v2(
        TaskActionApprovalV2::new(
            material.task_action_context(&unsigned).unwrap(),
            TaskActionApprovalDecisionV2::Approve,
            unsigned.issued_at(),
            unsigned.expires_at(),
        )
        .unwrap(),
        &key,
    )
    .unwrap();
    receipt.with_task_action_approval(exact).unwrap()
}

fn restore_private_approval_snapshot(f: &mut PlannerAuthorityFixtureV2, bytes: &[u8]) {
    // Only encrypted owner data is restored here. Supply the existing fixture's
    // live session afterwards; this is not an authenticated session-recovery test.
    let sessions = std::mem::take(&mut f.authority.sessions);
    f.authority.tasks.clear();
    f.authority.authentication_preparations.clear();
    f.authority.intents.clear();
    f.authority.tool_approvals.clear();
    f.authority.execution_tickets.clear();
    f.authority.fused_approval_recovery.clear();
    f.authority
        .restore_recovery_snapshot(bytes, UnixMillisV2::new(206))
        .unwrap();
    assert!(f.authority.sessions.is_empty());
    assert!(f.authority.intents.is_empty());
    assert!(f.authority.tool_approvals.is_empty());
    assert!(f.authority.execution_tickets.is_empty());
    assert!(f.authority.executions.is_empty());
    f.authority.sessions = sessions;
}

#[test]
fn fused_approval_recovery_encrypted_reopen_keeps_original_challenge_and_new_handles() {
    use crate::v2_agent_durable::DurableKernelAgentAuthorityStateV2;
    let mut f = approval_recovery_fixture();
    let path = f
        ._directory
        .path()
        .join("kernel-agent-authority-state-v2.cbor");
    let anchor = TestAgentStateAnchorV2::default();
    let open = || {
        DurableKernelAgentAuthorityStateV2::open(
            &path,
            [0xe1; 32],
            f.authority.config.installation_id,
            Digest32V2::new([0xe2; 32]),
            Box::new(anchor.clone()),
        )
    };
    f.authority.durable_state = Some(open().unwrap().0);
    let (action, approval, envelope) = pending_private_approval(&mut f);
    let original_id = f.authority.intents[0].action_intent_id;
    let policy_head = disk(&f);
    let ciphertext = std::fs::read(&path).unwrap();
    assert!(!ciphertext.windows(5).any(|w| w == b"Alice"));
    drop(f.authority.durable_state.take());
    let (store, snapshot) = DurableKernelAgentAuthorityStateV2::open(
        &path,
        [0xe1; 32],
        f.authority.config.installation_id,
        Digest32V2::new([0xe2; 32]),
        Box::new(anchor.clone()),
    )
    .unwrap();
    restore_private_approval_snapshot(&mut f, &snapshot.unwrap());
    f.authority.durable_state = Some(store);
    let restored = prepare_private(&mut f, 207).unwrap();
    assert_ne!(action.intent, restored.intent);
    assert_eq!(f.authority.intents[0].action_intent_id, original_id);
    let manifest = f.authority.sessions[0].active_state_manifest_digest;
    let result = f
        .authority
        .evaluate_fused_action_v04(&restored, &f.values, manifest, 7, UnixMillisV2::new(208))
        .unwrap();
    let EvaluateToolCallResponseV2::NeedsApproval {
        approval: new_approval,
        envelope: recovered,
        display_authentication,
        ..
    } = result.0
    else {
        panic!("same pending approval")
    };
    assert_ne!(approval, new_approval);
    assert_eq!(envelope, recovered);
    assert_eq!(
        display_authentication,
        f.authority.tool_approvals[0].display_authentication
    );
    assert_eq!(f.authority.tool_approvals.len(), 1);
    assert_eq!(f.authority.fused_approval_recovery.len(), 1);
    assert_eq!(disk(&f), policy_head);
    assert_eq!(
        std::fs::read(&path).unwrap(),
        ciphertext,
        "rebind does not rewrite/renew approval"
    );
    let receipt = signed_private_settlement(&f, &recovered, true, 340);
    f.authority
        .authorize_fused_action_v04(&restored, receipt, manifest, 7, UnixMillisV2::new(209))
        .unwrap();
    let settled_ciphertext = std::fs::read(&path).unwrap();
    assert_ne!(settled_ciphertext, ciphertext);
    drop(f.authority.durable_state.take());
    let (store, snapshot) = DurableKernelAgentAuthorityStateV2::open(
        &path,
        [0xe1; 32],
        f.authority.config.installation_id,
        Digest32V2::new([0xe2; 32]),
        Box::new(anchor.clone()),
    )
    .unwrap();
    restore_private_approval_snapshot(&mut f, &snapshot.unwrap());
    f.authority.durable_state = Some(store);
    let restored = prepare_private(&mut f, 210).unwrap();
    assert!(matches!(
        f.authority
            .evaluate_fused_action_v04(&restored, &f.values, manifest, 7, UnixMillisV2::new(211),)
            .unwrap()
            .0,
        EvaluateToolCallResponseV2::Allowed { .. }
    ));
    assert!(f.authority.executions.is_empty());
    drop(f.authority.durable_state.take());
    // Replaying the authentic pre-settlement file cannot erase consumption.
    std::fs::write(&path, ciphertext).unwrap();
    assert!(DurableKernelAgentAuthorityStateV2::open(
        &path,
        [0xe1; 32],
        f.authority.config.installation_id,
        Digest32V2::new([0xe2; 32]),
        Box::new(anchor),
    )
    .is_err());
}

#[test]
fn fused_approval_recovery_reverifies_approved_and_retains_denied_settlement() {
    for approve in [false, true] {
        let mut f = approval_recovery_fixture();
        let (action, _, envelope) = pending_private_approval(&mut f);
        let manifest = f.authority.sessions[0].active_state_manifest_digest;
        let receipt = signed_private_settlement(&f, &envelope, approve, 340);
        let authorized = f.authority.authorize_fused_action_v04(
            &action,
            receipt,
            manifest,
            7,
            UnixMillisV2::new(205),
        );
        assert_eq!(authorized.is_ok(), approve);
        let old_ticket = authorized.ok().map(|t| t.0);
        let bytes = f.authority.encode_recovery_snapshot().unwrap();
        restore_private_approval_snapshot(&mut f, &bytes);
        let restored = prepare_private(&mut f, 207).unwrap();
        let result = f.authority.evaluate_fused_action_v04(
            &restored,
            &f.values,
            manifest,
            7,
            UnixMillisV2::new(208),
        );
        if approve {
            let EvaluateToolCallResponseV2::Allowed { ticket, .. } = result.unwrap().0 else {
                panic!("exact G6")
            };
            assert_ne!(Some(ticket), old_ticket);
            assert_eq!(f.authority.execution_tickets.len(), 1);
        } else {
            assert!(result.is_err());
            assert!(f.authority.intents[0].state == IntentRecordStateV2::Denied);
            let again = f
                .authority
                .evaluate_fused_action_v04(
                    &restored,
                    &f.values,
                    manifest,
                    7,
                    UnixMillisV2::new(209),
                )
                .unwrap();
            assert!(matches!(again.0, EvaluateToolCallResponseV2::Denied { .. }));
            assert!(f.authority.execution_tickets.is_empty());
        }
        assert_eq!(f.authority.encode_recovery_snapshot().unwrap(), bytes);
        assert!(f.authority.executions.is_empty());
    }
}

#[test]
fn fused_approval_recovery_expired_receipt_never_becomes_new_pending_approval() {
    let mut f = approval_recovery_fixture();
    let (action, _, envelope) = pending_private_approval(&mut f);
    let manifest = f.authority.sessions[0].active_state_manifest_digest;
    let receipt = signed_private_settlement(&f, &envelope, true, 206);
    f.authority
        .authorize_fused_action_v04(&action, receipt, manifest, 7, UnixMillisV2::new(205))
        .unwrap();
    let bytes = f.authority.encode_recovery_snapshot().unwrap();
    restore_private_approval_snapshot(&mut f, &bytes);
    let restored = prepare_private(&mut f, 207).unwrap();
    for time in [208, 209] {
        assert!(f
            .authority
            .evaluate_fused_action_v04(&restored, &f.values, manifest, 7, UnixMillisV2::new(time),)
            .is_err());
        assert!(f.authority.tool_approvals.is_empty());
        assert!(f.authority.execution_tickets.is_empty());
    }
    assert_eq!(f.authority.encode_recovery_snapshot().unwrap(), bytes);
}

#[test]
fn fused_approval_recovery_rejects_changed_plan_expiry_and_revocation() {
    for case in 0..3 {
        let mut f = approval_recovery_fixture();
        let (old, _, _) = pending_private_approval(&mut f);
        let manifest = f.authority.sessions[0].active_state_manifest_digest;
        let bytes = f.authority.encode_recovery_snapshot().unwrap();
        restore_private_approval_snapshot(&mut f, &bytes);
        let restored = prepare_private(&mut f, 207).unwrap();
        let time = match case {
            0 => {
                choose(&mut f, 2, 2, true, 302);
                303
            }
            1 => 350,
            _ => {
                f.authority
                    .policy
                    .as_mut()
                    .unwrap()
                    .durable
                    .revoke_task_authorization(f.authority.sessions[0].durable_task_id)
                    .unwrap();
                208
            }
        };
        for action in [&old, &restored] {
            assert!(f
                .authority
                .evaluate_fused_action_v04(action, &f.values, manifest, 7, UnixMillisV2::new(time),)
                .is_err());
        }
        assert!(f.authority.tool_approvals.is_empty());
        assert!(f.authority.execution_tickets.is_empty());
    }
}

#[test]
fn fused_approval_recovery_rejects_tampered_signature_duplicate_and_wrong_binding() {
    let mut f = approval_recovery_fixture();
    pending_private_approval(&mut f);
    let bytes = f.authority.encode_recovery_snapshot().unwrap();
    assert!(f.authority.encode_recovery_snapshot_schema(3).is_err());
    // The recovery image has its own signature check even inside an AEAD owner.
    let mut tampered = bytes.clone();
    let last = tampered.len() - 2; // end of signed display envelope, before null receipt
    tampered[last] ^= 1;
    f.authority.fused_approval_recovery.clear();
    assert!(f
        .authority
        .restore_recovery_snapshot(&tampered, UnixMillisV2::new(206))
        .is_err());
    f.authority.fused_approval_recovery.clear();
    f.authority
        .restore_recovery_snapshot(&bytes, UnixMillisV2::new(206))
        .unwrap();
    let duplicate = f.authority.fused_approval_recovery[0].clone();
    f.authority.fused_approval_recovery.push(duplicate);
    let duplicated = f.authority.encode_recovery_snapshot().unwrap();
    f.authority.fused_approval_recovery.clear();
    assert!(f
        .authority
        .restore_recovery_snapshot(&duplicated, UnixMillisV2::new(206))
        .is_err());
    f.authority.fused_approval_recovery.clear();
    f.authority.config.installation_id = Digest32V2::new([0xe7; 32]);
    assert!(f
        .authority
        .restore_recovery_snapshot(&bytes, UnixMillisV2::new(206))
        .is_err());
}

#[test]
fn fused_approval_recovery_storage_failure_exposes_no_pending_or_ticket() {
    use crate::v2_agent_durable::DurableKernelAgentAuthorityStateV2;
    for settle in [false, true] {
        let mut f = approval_recovery_fixture();
        let pending = if settle {
            Some(pending_private_approval(&mut f))
        } else {
            None
        };
        let path = f
            ._directory
            .path()
            .join("kernel-agent-authority-state-v2.cbor");
        let anchor = TestAgentStateAnchorV2::default();
        let (store, _) = DurableKernelAgentAuthorityStateV2::open(
            &path,
            [0xe1; 32],
            f.authority.config.installation_id,
            Digest32V2::new([0xe2; 32]),
            Box::new(anchor.clone()),
        )
        .unwrap();
        f.authority.durable_state = Some(store);
        // Make the rollback anchor reject the next commit without modifying any
        // installed service or deployment state.
        *anchor.0.lock().unwrap() =
            KernelAgentAuthorityStateHeadV2::new(9, Digest32V2::new([9; 32])).unwrap();
        let manifest = f.authority.sessions[0].active_state_manifest_digest;
        if let Some((action, _, envelope)) = pending {
            let receipt = signed_private_settlement(&f, &envelope, true, 340);
            assert!(f
                .authority
                .authorize_fused_action_v04(&action, receipt, manifest, 7, UnixMillisV2::new(205),)
                .is_err());
            assert!(!f.authority.tool_approvals[0].consumed);
        } else {
            let action = prepare_private(&mut f, 202).unwrap();
            assert!(f
                .authority
                .evaluate_fused_action_v04(&action, &f.values, manifest, 7, UnixMillisV2::new(203),)
                .is_err());
            assert!(f.authority.tool_approvals.is_empty());
        }
        assert!(f.authority.durable_poisoned);
        assert!(f.authority.execution_tickets.is_empty());
        assert!(f.authority.executions.is_empty());
        assert!(prepare_private(&mut f, 209).is_err());
    }
}

#[test]
fn fused_approval_recovery_checks_current_settlement_key_and_stale_handle() {
    let mut f = approval_recovery_fixture();
    let (action, approval, envelope) = pending_private_approval(&mut f);
    let old_pending = f.authority.intents[0].pending;
    let manifest = f.authority.sessions[0].active_state_manifest_digest;
    let receipt = signed_private_settlement(&f, &envelope, true, 340);
    f.authority
        .authorize_fused_action_v04(
            &action,
            receipt.clone(),
            manifest,
            7,
            UnixMillisV2::new(205),
        )
        .unwrap();
    let bytes = f.authority.encode_recovery_snapshot().unwrap();
    restore_private_approval_snapshot(&mut f, &bytes);
    let restored = prepare_private(&mut f, 207).unwrap();
    let key = SigningKey::from_bytes(&[0xe8; 32])
        .verifying_key()
        .to_bytes();
    let policy = f.authority.policy.as_mut().unwrap();
    policy.approval.settlement_public_key = key;
    policy.approval.settlement_key_id = derive_ed25519_key_id_v2(key);
    for time in [208, 209] {
        assert!(f
            .authority
            .evaluate_fused_action_v04(&restored, &f.values, manifest, 7, UnixMillisV2::new(time),)
            .is_err());
    }
    let stale =
        savana_kernel_protocol::v2::AuthorizeToolCallRequestV2::new(old_pending, approval, receipt)
            .unwrap();
    assert!(f
        .authority
        .authorize_tool_call_inner(
            &stale,
            manifest,
            7,
            UnixMillisV2::new(210),
            super::super::IntentAccessV2::PrivateFused,
        )
        .is_err());
    assert!(f.authority.tool_approvals.is_empty());
    assert!(f.authority.execution_tickets.is_empty());
    assert_eq!(f.authority.encode_recovery_snapshot().unwrap(), bytes);
}
