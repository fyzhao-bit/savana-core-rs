use super::*;
use crate::v2::durable_tests::{signed_task, task_clause, task_store};
use crate::v2::{
    FusedPlanningProfileV04, FusedPlanningUpdateV04 as U, VerifiedFusedPlanningProfileV04,
};
use ed25519_dalek::{Signer, SigningKey};
use savana_continuation_core::planning::Mode;
use savana_continuation_core::planning::*;
use savana_kernel_protocol::v2::{
    ActionAlternativeV2, ActionCodecProfileV2, MagnitudeUnitV2, TaskEffectV2,
};
#[path = "durable_fused_inputs_tests.rs"]
mod input_tests;
#[path = "durable_fused_model_tests.rs"]
mod model_exchange_tests;
#[path = "durable_fused_recipe_tests.rs"]
mod recipe_tests;

fn task() -> DurableTaskIdV2 {
    DurableTaskIdV2::new([4; 32])
}
fn now(t: u64) -> UnixMillisV2 {
    UnixMillisV2::new(t)
}
fn auth(revision: u64) -> VerifiedTaskAuthorizationV2 {
    signed_task(
        task(),
        revision,
        vec![task_clause(
            1,
            ActionAlternativeV2::new(
                Digest32V2::new([7; 32]),
                ActionCodecProfileV2::FixedJsonPostV1,
                TaskEffectV2::Update,
                Digest32V2::new([8; 32]),
                Digest32V2::new([9; 32]),
                Digest32V2::new([10; 32]),
                MagnitudeUnitV2::Count,
            )
            .unwrap(),
            2,
            2,
            vec![],
            false,
        )],
    )
}
pub(super) fn profile() -> FusedPlanningProfileV04 {
    FusedPlanningProfileV04 {
        final_release: None,
        final_result_source: None,
        delivery_schedule: vec![],
        execution_bindings: vec![],
        release_model_views: false,
        schema: 1,
        installation: [2; 32],
        task: [4; 32],
        not_before: 1,
        expires_at: 1000,
        policy: Policy {
            schema: 1,
            root: *auth(1).digest().as_bytes(),
            observer_scope: [30; 32],
            operations: vec![Operation {
                id: 1,
                tool_class: 1,
                action_template: 1,
                bindings: vec![],
                after: vec![],
            }],
            templates: vec![Template {
                id: 1,
                order: vec![1],
            }],
            rounds: vec![Round {
                observations: vec![],
                id: 1,
                opens_at: 10,
                advice_cut: 20,
                closes_at: 50,
                advisor: Some([20; 32]),
                planner: [21; 32],
                model_profile: 1,
                mode: Mode::RegisteredTemplateV04,
                public_view: b"fused-owner-private-config-marker".to_vec(),
                template_ids: vec![1],
                question_codes: vec![],
                max_deliveries: 2,
            }],
            max_replacements: 0,
        },
    }
}
fn verified(p: FusedPlanningProfileV04) -> VerifiedFusedPlanningProfileV04 {
    let key = SigningKey::from_bytes(&[0x21; 32]);
    VerifiedFusedPlanningProfileV04::verify(
        &serde_json::to_vec(&p).unwrap(),
        &key.sign(&p.signing_digest().unwrap()).to_bytes(),
        &key.verifying_key(),
        &auth(1),
        now(10),
    )
    .unwrap()
}

#[test]
fn fused_final_source_profile_rejects_unsigned_changes_and_schema_downgrade() {
    let key = SigningKey::from_bytes(&[0x21; 32]);
    let mut p = profile();
    let old_bytes = serde_json::to_vec(&p).unwrap();
    assert!(!std::str::from_utf8(&old_bytes)
        .unwrap()
        .contains("final_result_source"));
    let old_signature = key.sign(&p.signing_digest().unwrap()).to_bytes();
    p.final_result_source = Some(1);
    assert!(p.signing_digest().is_err());
    p.schema = 3;
    assert!(p.signing_digest().is_ok());
    assert!(VerifiedFusedPlanningProfileV04::verify(
        &serde_json::to_vec(&p).unwrap(),
        &old_signature,
        &key.verifying_key(),
        &auth(1),
        now(1),
    )
    .is_err());
    let signature = key.sign(&p.signing_digest().unwrap()).to_bytes();
    assert!(VerifiedFusedPlanningProfileV04::verify(
        &serde_json::to_vec(&p).unwrap(),
        &signature,
        &key.verifying_key(),
        &auth(1),
        now(1),
    )
    .is_ok());
    p.final_result_source = None;
    assert!(VerifiedFusedPlanningProfileV04::verify(
        &serde_json::to_vec(&p).unwrap(),
        &signature,
        &key.verifying_key(),
        &auth(1),
        now(1),
    )
    .is_err());
    p.final_result_source = Some(9);
    assert!(p.signing_digest().is_err());
}
fn install(store: &mut DurableG4StateV2) {
    store.install_verified_task_authorization(auth(1)).unwrap();
    store
        .install_fused_planning_v04(verified(profile()), now(10))
        .unwrap();
}
fn send() -> U {
    U::ReserveDelivery {
        round: 1,
        role: Role::Advisor,
        recipient: [20; 32],
    }
}

#[test]
fn fused_profile_signature_namespace_current_root_and_no_replacement() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(STATE_FILE_NAME);
    let mut s = task_store(
        &path,
        [0x81; 32],
        TestRollbackProtectedStateAnchorV2::default(),
    );
    assert!(s
        .install_fused_planning_v04(verified(profile()), now(10))
        .is_err());
    install(&mut s);
    let head = s.current_head;
    s.install_fused_planning_v04(verified(profile()), now(10))
        .unwrap();
    assert_eq!(s.current_head, head);
    let mut changed = profile();
    changed.policy.rounds[0].max_deliveries = 3;
    assert!(s
        .install_fused_planning_v04(verified(changed), now(10))
        .is_err());
    let p = profile();
    let key = SigningKey::from_bytes(&[0x21; 32]);
    let sig = key.sign(&p.signing_digest().unwrap()).to_bytes();
    assert!(VerifiedFusedPlanningProfileV04::verify(
        &serde_json::to_vec(&p).unwrap(),
        &sig,
        &SigningKey::from_bytes(&[0x22; 32]).verifying_key(),
        &auth(1),
        now(10)
    )
    .is_err());
    assert!(VerifiedFusedPlanningProfileV04::verify(
        &serde_json::to_vec(&p).unwrap(),
        &sig,
        &key.verifying_key(),
        &auth(2),
        now(10)
    )
    .is_err());
}

#[test]
fn fused_outbox_reopen_returns_same_view_without_renewing_send_capacity() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(STATE_FILE_NAME);
    let anchor = TestRollbackProtectedStateAnchorV2::default();
    let mut s = task_store(&path, [0x81; 32], anchor.clone());
    install(&mut s);
    assert_eq!(s.snapshot.payload_schema, 11);
    let a = s
        .update_fused_planning_v04(task(), 1, send(), now(10))
        .unwrap();
    assert_eq!(a.revision(), 2);
    let raw = fs::read(&path).unwrap();
    assert!(!raw
        .windows(b"fused-owner-private-config-marker".len())
        .any(|w| w == b"fused-owner-private-config-marker"));
    drop(s);
    let mut s = task_store(&path, [0x81; 32], anchor);
    let status_head = s.current_head;
    assert_eq!(
        s.fused_planning_status_v04(task(), now(11))
            .unwrap()
            .revision,
        2
    );
    assert_eq!(s.current_head, status_head);
    let b = s
        .update_fused_planning_v04(task(), 2, send(), now(11))
        .unwrap();
    assert_eq!(a.view_for_release_check(), b.view_for_release_check());
    assert!(s
        .update_fused_planning_v04(task(), 3, send(), now(12))
        .is_err());
}

#[test]
fn fused_real_owner_advice_envelope_compile_roundtrip_and_duplicate_rejection() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(STATE_FILE_NAME);
    let anchor = TestRollbackProtectedStateAnchorV2::default();
    let mut s = task_store(&path, [0x81; 32], anchor.clone());
    install(&mut s);
    let r = s
        .update_fused_planning_v04(task(), 1, send(), now(10))
        .unwrap();
    let v = r.view_for_release_check().unwrap();
    let advice = ReviewAdvice {
        schema: 1,
        job: v.job,
        view: v.commitment(),
        templates: vec![1],
        questions: vec![],
    };
    s.update_fused_planning_v04(
        task(),
        2,
        U::AcceptAdvice {
            round: 1,
            sender: [20; 32],
            bytes: serde_json::to_vec(&advice).unwrap(),
        },
        now(11),
    )
    .unwrap();
    drop(s);
    let mut s = task_store(&path, [0x81; 32], anchor);
    s.update_fused_planning_v04(task(), 3, U::FreezeEnvelope { round: 1 }, now(20))
        .unwrap();
    let r = s
        .update_fused_planning_v04(
            task(),
            4,
            U::ReserveDelivery {
                round: 1,
                role: Role::Planner,
                recipient: [21; 32],
            },
            now(20),
        )
        .unwrap();
    let v = r.view_for_release_check().unwrap();
    assert_eq!(v.suggested_templates, vec![1]);
    let proposal = PlanProposal {
        schema: 1,
        job: v.job,
        view: v.commitment(),
        choice: PlanChoice::RegisteredTemplate { template: 1 },
    };
    let bytes = serde_json::to_vec(&proposal).unwrap();
    s.update_fused_planning_v04(
        task(),
        5,
        U::AcceptPlan {
            round: 1,
            sender: [21; 32],
            bytes: bytes.clone(),
        },
        now(21),
    )
    .unwrap();
    let head = s.current_head;
    s.update_fused_planning_v04(
        task(),
        6,
        U::AcceptPlan {
            round: 1,
            sender: [21; 32],
            bytes,
        },
        now(21),
    )
    .unwrap();
    assert_eq!(s.current_head, head);
    let plan = s.compiled_fused_plan_v04(task(), 1, now(21)).unwrap();
    assert_eq!(plan.operations().len(), 1);
    s.update_fused_planning_v04(
        task(),
        6,
        U::Activate {
            round: 1,
            expected_plan_revision: 0,
        },
        now(21),
    )
    .unwrap();
    assert!(s.snapshot.dispatch.entries.is_empty()); // no execution ticket created
}

#[test]
fn fused_clock_stale_owner_revision_revocation_and_amendment_fail_closed() {
    for case in 0..4 {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(STATE_FILE_NAME);
        let mut s = task_store(
            &path,
            [0x81; 32],
            TestRollbackProtectedStateAnchorV2::default(),
        );
        install(&mut s);
        s.update_fused_planning_v04(task(), 1, send(), now(12))
            .unwrap();
        let (revision, time) = match case {
            0 => (1, 13),
            1 => (2, 11),
            2 => {
                s.revoke_task_authorization(task()).unwrap();
                (2, 13)
            }
            _ => {
                s.install_verified_task_authorization(auth(2)).unwrap();
                (2, 13)
            }
        };
        let head = s.current_head;
        assert!(s
            .update_fused_planning_v04(task(), revision, send(), now(time))
            .is_err());
        assert_eq!(s.current_head, head);
    }
}

#[test]
fn fused_uncertain_commit_never_returns_view_and_reopen_keeps_charged_attempt() {
    for after in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(STATE_FILE_NAME);
        let anchor = TestRollbackProtectedStateAnchorV2::default();
        let mut s = task_store(&path, [0x81; 32], anchor.clone());
        install(&mut s);
        s.rollback_anchor = Box::new(super::continuation_tests::FailAnchor {
            inner: anchor.clone(),
            after,
        });
        assert!(matches!(
            s.update_fused_planning_v04(task(), 1, send(), now(10)),
            Err(G4Error::DurableCommitUncertain)
        ));
        assert!(s
            .update_fused_planning_v04(task(), 1, send(), now(10))
            .is_err());
        drop(s);
        let mut s = task_store(&path, [0x81; 32], anchor);
        s.update_fused_planning_v04(task(), 2, send(), now(10))
            .unwrap();
        assert!(s
            .update_fused_planning_v04(task(), 3, send(), now(10))
            .is_err());
    }
}

#[test]
fn fused_schema_and_rollback_cannot_erase_outbox_history() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(STATE_FILE_NAME);
    let anchor = TestRollbackProtectedStateAnchorV2::default();
    let mut s = task_store(&path, [0x81; 32], anchor.clone());
    install(&mut s);
    let old = fs::read(&path).unwrap();
    s.update_fused_planning_v04(task(), 1, send(), now(10))
        .unwrap();
    let mut corrupt = s.snapshot.clone();
    corrupt.payload_schema = 10;
    assert!(validate_snapshot(&corrupt).is_err());
    drop(s);
    fs::write(&path, old).unwrap();
    assert!(matches!(
        DurableG4StateV2::open_for_test_in_namespace(
            &path,
            [0x81; 32],
            anchor,
            DurableStateNamespaceV2::new_for_test(2, 0x54)
        ),
        Err(G4Error::DurableStateRollback)
    ));
}

#[test]
fn fused_signed_admin_enrollment_is_atomic_idempotent_and_restart_safe() {
    use crate::v2::{
        ManagedAdminCommandV04, ManagedAdminOperationV04, ManagedAdminResultV04,
        VerifiedManagedAdminCommandV04,
    };
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(STATE_FILE_NAME);
    let anchor = TestRollbackProtectedStateAnchorV2::default();
    let mut s = task_store(&path, [0x81; 32], anchor.clone());
    s.install_verified_task_authorization(auth(1)).unwrap();
    let key = SigningKey::from_bytes(&[0x21; 32]);
    let p = profile();
    let command = ManagedAdminCommandV04 {
        schema: 1,
        installation: [2; 32],
        store: [0x54; 32],
        request: [60; 32],
        not_before: 1,
        expires_at: 100,
        operation: ManagedAdminOperationV04::EnrollPlanning {
            profile: Box::new(p.clone()),
            profile_signature: key.sign(&p.signing_digest().unwrap()).to_bytes().to_vec(),
        },
    };
    let proof = VerifiedManagedAdminCommandV04::verify(
        &command.canonical_bytes().unwrap(),
        &key.sign(&command.signing_digest().unwrap()).to_bytes(),
        &key.verifying_key(),
        Digest32V2::new([2; 32]),
        Digest32V2::new([0x54; 32]),
    )
    .unwrap();
    let receipt = s.apply_managed_admin_v04(&proof, now(10)).unwrap();
    assert!(matches!(
        receipt.result(),
        ManagedAdminResultV04::PlanningEnrolled { .. }
    ));
    let head = s.current_head;
    drop(s);
    let mut s = task_store(&path, [0x81; 32], anchor);
    let replay = s.apply_managed_admin_v04(&proof, now(200)).unwrap();
    assert!(receipt.result() == replay.result());
    assert_eq!(s.current_head, head);
    // Admin replay does not create fresh jobs or give extra transmissions.
    s.update_fused_planning_v04(task(), 1, send(), now(10))
        .unwrap();
    s.update_fused_planning_v04(task(), 2, send(), now(10))
        .unwrap();
    assert!(s
        .update_fused_planning_v04(task(), 3, send(), now(10))
        .is_err());
}

#[test]
fn fused_precommit_failure_does_not_release_or_charge_view() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(STATE_FILE_NAME);
    let anchor = TestRollbackProtectedStateAnchorV2::default();
    let mut s = task_store(&path, [0x81; 32], anchor.clone());
    install(&mut s);
    let head = s.current_head;
    s.set_before_next_commit_hook_for_test(|| Err(G4Error::DurableStateIo));
    assert!(matches!(
        s.update_fused_planning_v04(task(), 1, send(), now(10)),
        Err(G4Error::DurableStateIo)
    ));
    assert_eq!(s.current_head, head);
    drop(s);
    let mut s = task_store(&path, [0x81; 32], anchor);
    s.update_fused_planning_v04(task(), 1, send(), now(10))
        .unwrap();
    s.update_fused_planning_v04(task(), 2, send(), now(10))
        .unwrap();
}
