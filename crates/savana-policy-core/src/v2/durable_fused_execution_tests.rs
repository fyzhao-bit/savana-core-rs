//! Real G7 transaction/restart tests. No network or simulated successful provider.
use super::*;
use savana_continuation_core::planning::{Operation, PlanChoice, PlanProposal, Role, Template};
#[path = "durable_fused_recipe_dispatch_tests.rs"]
mod recipe_dispatch_tests;

fn reference(input: &mut Input, operation: u16, revision: u64) {
    input.request.fused_operation = Some(FusedOperationRefV04 {
        operation,
        plan_revision: revision,
    });
}
fn commitment(f: &Fixture, input: &Input) -> [u8; 32] {
    let record = &f
        .store
        .snapshot
        .intents
        .intents
        .iter()
        .find(|i| i.record.action_intent_id == input.id)
        .unwrap()
        .record;
    fused_execution_commitment_v04(record.material(), input.request.matched.content()).unwrap()
}
fn enroll(f: &mut Fixture, inputs: &[&Input], dependencies: bool) {
    let parent = f.store.task_authorization_state(task()).unwrap();
    let mut p = super::super::fused_planning_tests::profile();
    p.task = *task().as_bytes();
    p.policy.root = *parent.authorization().digest().as_bytes();
    p.policy.operations = (1..=inputs.len() as u16)
        .map(|id| Operation {
            id,
            tool_class: 1,
            action_template: 1,
            bindings: vec![],
            after: if dependencies && id > 1 {
                vec![1]
            } else {
                vec![]
            },
        })
        .collect();
    let order: Vec<_> = p.policy.operations.iter().map(|o| o.id).collect();
    let mut reordered = order.clone();
    reordered[1..].reverse();
    p.policy.templates = vec![
        Template { id: 1, order },
        Template {
            id: 2,
            order: reordered,
        },
    ];
    let mut round = p.policy.rounds[0].clone();
    round.advisor = None;
    round.opens_at = 10;
    round.advice_cut = 10;
    round.closes_at = 20;
    round.template_ids = vec![1, 2];
    p.policy.rounds = vec![round.clone()];
    round.id = 2;
    round.opens_at = 20;
    round.advice_cut = 20;
    round.closes_at = 30;
    p.policy.rounds.push(round);
    p.policy.max_replacements = 1;
    p.execution_bindings = inputs
        .iter()
        .enumerate()
        .map(|(i, input)| FusedExecutionBindingV04 {
            operation: (i + 1) as u16,
            commitment: commitment(f, input),
        })
        .collect();
    let proof = VerifiedFusedPlanningProfileV04::verify(
        &serde_json::to_vec(&p).unwrap(),
        &admin_key().sign(&p.signing_digest().unwrap()).to_bytes(),
        &admin_key().verifying_key(),
        parent.authorization(),
        now(),
    )
    .unwrap();
    f.store.install_fused_planning_v04(proof, now()).unwrap();
}
fn update(
    f: &mut Fixture,
    u: FusedPlanningUpdateV04,
    time: u64,
) -> Result<FusedPlanningResultV04, G4Error> {
    let t = UnixMillisV2::new(time);
    let revision = f.store.fused_planning_status_v04(task(), t)?.revision;
    f.store.update_fused_planning_v04(task(), revision, u, t)
}
fn choose(f: &mut Fixture, round: u16, template: u16, time: u64) {
    update(f, FusedPlanningUpdateV04::FreezeEnvelope { round }, time).unwrap();
    let result = update(
        f,
        FusedPlanningUpdateV04::ReserveDelivery {
            round,
            role: Role::Planner,
            recipient: [21; 32],
        },
        time,
    )
    .unwrap();
    let view = result.view_for_release_check().unwrap();
    let proposal = PlanProposal {
        schema: 1,
        job: view.job,
        view: view.commitment(),
        choice: PlanChoice::RegisteredTemplate { template },
    };
    update(
        f,
        FusedPlanningUpdateV04::AcceptPlan {
            round,
            sender: [21; 32],
            bytes: serde_json::to_vec(&proposal).unwrap(),
        },
        time,
    )
    .unwrap();
}
fn activate(
    f: &mut Fixture,
    round: u16,
    revision: u64,
    time: u64,
) -> Result<FusedPlanningResultV04, G4Error> {
    update(
        f,
        FusedPlanningUpdateV04::Activate {
            round,
            expected_plan_revision: revision,
        },
        time,
    )
}
fn empty_fixture() -> Fixture {
    Fixture::build_with_storage(false, false, false, false)
}

#[test]
fn fused_recipe_admin_approval_is_not_an_exact_g7_execution_grant() {
    use crate::v2::{
        FusedRecipeApprovalV04, FusedRecipeBindingV04, ManagedAdminCommandV04,
        ManagedAdminOperationV04, VerifiedManagedAdminCommandV04,
    };
    let mut f = empty_fixture();
    let input = f.input(40, 1, 1);
    let parent = f.store.task_authorization_state(task()).unwrap();
    let mut p = super::super::fused_planning_tests::profile();
    p.task = *task().as_bytes();
    p.policy.root = *parent.authorization().digest().as_bytes();
    p.policy.rounds[0].advisor = None;
    p.policy.rounds[0].advice_cut = 10;
    let verified = VerifiedFusedPlanningProfileV04::verify(
        &serde_json::to_vec(&p).unwrap(),
        &admin_key().sign(&p.signing_digest().unwrap()).to_bytes(),
        &admin_key().verifying_key(),
        parent.authorization(),
        now(),
    )
    .unwrap();
    f.store.install_fused_planning_v04(verified, now()).unwrap();
    choose(&mut f, 1, 1, 10);
    activate(&mut f, 1, 0, 10).unwrap();
    // Even intentionally signing an old exact commitment in the NEW field
    // must not make it an exact execution approval or bypass G7.
    let a = FusedRecipeApprovalV04 {
        inputs_digest: None,
        schema: 1,
        recipe_schema: 1,
        installation: p.installation,
        manifest: [3; 32],
        task: p.task,
        root: p.policy.root,
        profile: p.signing_digest().unwrap(),
        deployment_generation: 7,
        not_before: 1,
        expires_at: 100,
        bindings: vec![FusedRecipeBindingV04 {
            operation: 1,
            recipe: commitment(&f, &input),
        }],
    };
    let command = ManagedAdminCommandV04 {
        schema: 1,
        installation: [2; 32],
        store: [0x54; 32],
        request: [99; 32],
        not_before: 1,
        expires_at: 100,
        operation: ManagedAdminOperationV04::ApprovePlanningRecipes {
            approval_signature: admin_key()
                .sign(&a.signing_digest().unwrap())
                .to_bytes()
                .to_vec(),
            approval: Box::new(a),
        },
    };
    let proof = VerifiedManagedAdminCommandV04::verify(
        &command.canonical_bytes().unwrap(),
        &admin_key()
            .sign(&command.signing_digest().unwrap())
            .to_bytes(),
        &admin_key().verifying_key(),
        d(2),
        d(0x54),
    )
    .unwrap();
    f.store.apply_managed_admin_v04(&proof, now()).unwrap();
    let head = f.store.current_head;
    assert!(bind(&f, &input, 10).is_err());
    assert_eq!(f.store.current_head, head);
    assert!(f.store.snapshot.dispatch.entries.is_empty());
    let f = f.reopen();
    assert!(bind(&f, &input, 10).is_err());
}

fn bind(f: &Fixture, input: &Input, time: u64) -> Result<TaskDispatchAuthorizationV2, G4Error> {
    f.store
        .bind_fused_dispatch_v04(input.id, input.request.clone(), 7, UnixMillisV2::new(time))
}

#[test]
fn fused_active_compilation_snapshot_reads_only_activation_across_reopen() {
    let mut f = empty_fixture();
    let a = f.input(40, 1, 1);
    enroll(&mut f, &[&a], false);
    choose(&mut f, 1, 1, 10);
    assert!(f.store.active_fused_plan_v04(task(), now()).is_err());
    activate(&mut f, 1, 0, 10).unwrap();
    let head = f.store.current_head;
    let snapshot = f.store.active_fused_plan_v04(task(), now()).unwrap();
    assert_eq!(snapshot.revision(), 1);
    assert_eq!(snapshot.compiled().operations()[0].id, 1);
    assert_eq!(snapshot.approved_commitment(1), Some(commitment(&f, &a)));
    assert_eq!(snapshot.approved_commitment(2), None);
    assert_eq!(f.store.current_head, head);
    choose(&mut f, 2, 1, 20);
    let mut f = f.reopen();
    let pending = f
        .store
        .active_fused_plan_v04(task(), UnixMillisV2::new(20))
        .unwrap();
    assert_eq!(pending.revision(), 1);
    assert_eq!(pending.profile_digest(), snapshot.profile_digest());
    activate(&mut f, 2, 1, 20).unwrap();
    assert_eq!(
        f.store
            .active_fused_plan_v04(task(), UnixMillisV2::new(20))
            .unwrap()
            .revision(),
        2
    );
    assert!(f.store.active_fused_plan_v04(task(), now()).is_err());
    f.store.revoke_task_authorization(task()).unwrap();
    assert!(f
        .store
        .active_fused_plan_v04(task(), UnixMillisV2::new(20))
        .is_err());
}

#[test]
fn fused_dispatch_bridge_selects_frozen_work_without_charging_then_real_g7_charges_once() {
    let mut f = empty_fixture();
    let mut a = f.input(40, 1, 1);
    let b = f.input(41, 1, 2);
    enroll(&mut f, &[&a, &b], false);
    choose(&mut f, 1, 1, 10);
    assert!(bind(&f, &a, 10).is_err()); // a candidate is not an active plan
    activate(&mut f, 1, 0, 10).unwrap();
    let head = f.store.current_head;
    let status = f
        .store
        .fused_planning_status_v04(task(), now())
        .unwrap()
        .revision;
    assert!(bind(&f, &b, 10).is_err()); // no scanning ahead for a matching material
    for _ in 0..3 {
        let selected = bind(&f, &a, 10).unwrap();
        assert_eq!(
            selected.fused_operation,
            Some(FusedOperationRefV04 {
                plan_revision: 1,
                operation: 1,
            })
        );
    }
    assert_eq!(f.store.current_head, head);
    assert_eq!(
        f.store
            .fused_planning_status_v04(task(), now())
            .unwrap()
            .revision,
        status
    );
    assert!(f.store.snapshot.dispatch.entries.is_empty());
    a.request = bind(&f, &a, 10).unwrap();
    let original = f.prepare(&a).unwrap();
    let mut f = f.reopen();
    a.request.fused_operation = None;
    a.request = bind(&f, &a, 10).unwrap();
    let head = f.store.current_head;
    let replay = f.prepare(&a).unwrap();
    assert_eq!(replay.core(), original.core());
    assert_eq!(f.store.current_head, head);
    assert_eq!(f.store.snapshot.dispatch.entries.len(), 1);
    let fresh = f.input(42, 1, 1);
    let mut changed_replay = a.request.clone();
    changed_replay.matched = fresh.request.matched;
    let head = f.store.current_head;
    // Replay must retain its entire original content, not refresh even the
    // otherwise normalized task pre-state counters under an old intent ID.
    assert!(f
        .store
        .bind_fused_dispatch_v04(a.id, changed_replay, 7, now())
        .is_err());
    assert_eq!(f.store.current_head, head);
}

#[test]
fn fused_dispatch_bridge_keeps_original_selector_after_replacement_and_reopen() {
    let mut f = empty_fixture();
    let mut a = f.input(40, 1, 1);
    let b = f.input(41, 1, 2);
    let c = f.input(42, 1, 3);
    enroll(&mut f, &[&a, &b, &c], false);
    choose(&mut f, 1, 1, 10);
    activate(&mut f, 1, 0, 10).unwrap();
    a.request = bind(&f, &a, 10).unwrap();
    let original = f.prepare(&a).unwrap();
    choose(&mut f, 2, 2, 20);
    activate(&mut f, 2, 1, 20).unwrap();
    let mut f = f.reopen();
    a.request.fused_operation = None;
    a.request = bind(&f, &a, 20).unwrap();
    assert_eq!(a.request.fused_operation.unwrap().plan_revision, 1);
    assert_eq!(
        f.prepare_at(&a, UnixMillisV2::new(20), 100).unwrap().core(),
        original.core()
    );
    // New material uses the updated task pre-state, while the approved stable
    // operation commitment still binds the identical original business action.
    let wrong = f.input(43, 1, 2);
    assert!(bind(&f, &wrong, 20).is_err());
    let mut next = f.input(44, 1, 3);
    next.request = bind(&f, &next, 20).unwrap();
    assert_eq!(
        next.request.fused_operation,
        Some(FusedOperationRefV04 {
            plan_revision: 2,
            operation: 3,
        })
    );
    f.prepare_at(&next, UnixMillisV2::new(20), 100).unwrap();
    assert_eq!(f.store.snapshot.dispatch.entries.len(), 2);
}

#[test]
fn fused_dispatch_bridge_preflight_cannot_survive_plan_change_as_new_authority() {
    let mut f = empty_fixture();
    let mut a = f.input(40, 1, 1);
    let b = f.input(41, 1, 2);
    enroll(&mut f, &[&a, &b], false);
    choose(&mut f, 1, 1, 10);
    activate(&mut f, 1, 0, 10).unwrap();
    a.request = bind(&f, &a, 10).unwrap();
    choose(&mut f, 2, 1, 20);
    activate(&mut f, 2, 1, 20).unwrap();
    let head = f.store.current_head;
    // Even an identical ordering has a new activation revision.
    assert!(f.prepare_at(&a, UnixMillisV2::new(20), 100).is_err());
    assert!(bind(&f, &a, 20).is_err()); // don't silently repair an explicit stale hint
    assert_eq!(f.store.current_head, head);
    a.request.fused_operation = None;
    a.request = bind(&f, &a, 20).unwrap();
    assert_eq!(a.request.fused_operation.unwrap().plan_revision, 2);
    f.prepare_at(&a, UnixMillisV2::new(20), 100).unwrap();
}

#[test]
fn fused_dispatch_bridge_rejects_changed_material_expiry_generation_clock_and_revocation() {
    let mut f = empty_fixture();
    let a = f.input(40, 1, 1);
    let changed = f.input(41, 1, 2);
    enroll(&mut f, &[&a], false);
    choose(&mut f, 1, 1, 10);
    activate(&mut f, 1, 0, 10).unwrap();
    let head = f.store.current_head;
    assert!(bind(&f, &changed, 10).is_err());
    assert!(bind(&f, &a, 9).is_err());
    assert!(bind(&f, &a, 10_000).is_err());
    assert!(f
        .store
        .bind_fused_dispatch_v04(a.id, a.request.clone(), 8, now())
        .is_err());
    assert!(f
        .store
        .bind_fused_dispatch_v04(ActionIntentIdV2::new([99; 32]), a.request.clone(), 7, now())
        .is_err());
    assert_eq!(f.store.current_head, head);
    f.store.revoke_task_authorization(task()).unwrap();
    assert!(bind(&f, &a, 10).is_err());
    assert!(f.store.snapshot.dispatch.entries.is_empty());
}

#[test]
fn fused_dispatch_bridge_requires_real_dependency_success_not_reserved_or_failed_work() {
    for disposition in [
        AuthenticatedEffectDispositionV2::known_success_for_test(),
        AuthenticatedEffectDispositionV2::failed_no_effect_for_test(),
        AuthenticatedEffectDispositionV2::indeterminate_for_test(),
    ] {
        let mut f = empty_fixture();
        let mut a = f.input(40, 1, 1);
        let b = f.input(41, 1, 2);
        enroll(&mut f, &[&a, &b], true);
        choose(&mut f, 1, 1, 10);
        activate(&mut f, 1, 0, 10).unwrap();
        a.request = bind(&f, &a, 10).unwrap();
        let p = f.prepare(&a).unwrap();
        let next = f.input(42, 1, 2);
        assert!(bind(&f, &next, 10).is_err());
        let p = p.preparation();
        let outcome = f
            .store
            .reconcile_tool_dispatch_with_outcome(
                VerifiedExecutorDispositionV2 {
                    execution_nonce: p.execution_nonce(),
                    dispatch_core_digest: p.dispatch_core_digest(),
                    dispatch_subject_digest: p.dispatch_subject_digest(),
                    evidence_digest: d(66),
                    disposition,
                },
                true,
            )
            .unwrap();
        let mut f = f.reopen();
        let next = f.input(43, 1, 2);
        assert_eq!(
            bind(&f, &next, 10).is_ok(),
            outcome == KernelDispatchStateV2::CompletionCommitted
        );
    }
}

#[test]
fn fused_dispatch_bridge_is_noop_for_legacy_and_refuses_injected_selector() {
    let mut f = empty_fixture();
    let mut a = f.input(40, 1, 1);
    let head = f.store.current_head;
    assert!(bind(&f, &a, 10).unwrap().fused_operation.is_none());
    reference(&mut a, 1, 1);
    assert!(bind(&f, &a, 10).is_err());
    assert_eq!(f.store.current_head, head);
}

#[test]
fn fused_g7_atomic_link_and_original_nonce_survive_encrypted_restart() {
    let mut f = Fixture::new();
    f.activate().unwrap();
    let mut input = f.input(40, 1, 1);
    f.attach(&mut input, 50);
    enroll(&mut f, &[&input], false);
    choose(&mut f, 1, 1, 10);
    activate(&mut f, 1, 0, 10).unwrap();
    reference(&mut input, 1, 1);
    let head = f.store.current_head;
    let before = f
        .store
        .fused_planning_status_v04(task(), now())
        .unwrap()
        .revision;
    let prepared = f.prepare(&input).unwrap();
    assert_eq!(f.store.current_head.sequence, head.sequence + 1);
    assert_eq!(f.store.snapshot.payload_schema, 12);
    assert_eq!(f.usage(), (1, 4));
    assert_eq!(
        f.store
            .fused_planning_status_v04(task(), now())
            .unwrap()
            .revision,
        before + 1
    );
    let mut f = f.reopen();
    let head = f.store.current_head;
    let replay = f.prepare(&input).unwrap();
    assert_eq!(replay.core(), prepared.core());
    assert_eq!(
        replay.preparation().kind(),
        DispatchPreparationKindV2::Replay
    );
    assert_eq!(f.store.current_head, head);
    assert_eq!(f.usage(), (1, 4));
    let mut alias = f.input(41, 1, 1);
    f.attach(&mut alias, 51);
    reference(&mut alias, 1, 1);
    let head = f.store.current_head;
    assert!(f.prepare(&alias).is_err());
    assert_eq!(f.store.current_head, head);
    assert_eq!(f.usage(), (1, 4));
}

#[test]
fn fused_g7_missing_inactive_wrong_operation_revision_and_material_fail_closed() {
    let mut f = empty_fixture();
    let mut input = f.input(40, 1, 1);
    enroll(&mut f, &[&input], false);
    choose(&mut f, 1, 1, 10);
    reference(&mut input, 1, 1);
    assert!(f.prepare(&input).is_err()); // compiled != active
    activate(&mut f, 1, 0, 10).unwrap();
    for selector in [
        None,
        Some(FusedOperationRefV04 {
            operation: 1,
            plan_revision: 0,
        }),
        Some(FusedOperationRefV04 {
            operation: 2,
            plan_revision: 1,
        }),
    ] {
        input.request.fused_operation = selector;
        let head = f.store.current_head;
        assert!(f.prepare(&input).is_err());
        assert_eq!(f.store.current_head, head);
    }
    let mut changed = f.input(41, 1, 2); // still root-authorized, but not this operation
    reference(&mut changed, 1, 1);
    let head = f.store.current_head;
    assert!(f.prepare(&changed).is_err());
    assert_eq!(f.store.current_head, head);
    assert!(f.store.snapshot.dispatch.entries.is_empty());
    reference(&mut input, 1, 1);
    f.prepare(&input).unwrap();
}

#[test]
fn fused_g7_replacement_retains_pending_original_execution_and_rejects_stale_work() {
    let mut f = empty_fixture();
    let mut first = f.input(40, 1, 1);
    let second = f.input(41, 1, 2);
    let third = f.input(42, 1, 3);
    enroll(&mut f, &[&first, &second, &third], false);
    choose(&mut f, 1, 1, 10);
    activate(&mut f, 1, 0, 10).unwrap();
    reference(&mut first, 1, 1);
    let old = f.prepare(&first).unwrap(); // retained pending work, not a fake success
    choose(&mut f, 2, 2, 20);
    activate(&mut f, 2, 1, 20).unwrap(); // [1,2,3] -> [1,3,2]
    let mut f = f.reopen();
    let replay = f.prepare_at(&first, UnixMillisV2::new(20), 100).unwrap();
    assert_eq!(old.core(), replay.core());
    let mut next = f.input(43, 1, 3);
    reference(&mut next, 3, 1);
    assert!(f.prepare_at(&next, UnixMillisV2::new(20), 100).is_err());
    reference(&mut next, 3, 2);
    f.prepare_at(&next, UnixMillisV2::new(20), 100).unwrap();
    let mut last = f.input(44, 1, 2);
    reference(&mut last, 2, 2);
    f.prepare_at(&last, UnixMillisV2::new(20), 100).unwrap();
    assert_eq!(f.store.snapshot.dispatch.entries.len(), 3);
    assert_eq!(
        f.store
            .task_authorization_state(task())
            .unwrap()
            .clause_consumption(1),
        Some((3, 6))
    );
}

#[test]
fn fused_g7_two_valid_plans_cannot_switch_across_an_already_started_prefix() {
    let mut f = empty_fixture();
    let mut a = f.input(40, 1, 1);
    let b = f.input(41, 1, 2);
    let c = f.input(42, 1, 3);
    enroll(&mut f, &[&a, &b, &c], false);
    choose(&mut f, 1, 1, 10);
    activate(&mut f, 1, 0, 10).unwrap();
    reference(&mut a, 1, 1);
    f.prepare(&a).unwrap();
    let mut b = f.input(43, 1, 2);
    reference(&mut b, 2, 1);
    f.prepare(&b).unwrap();
    choose(&mut f, 2, 2, 20);
    let head = f.store.current_head;
    assert!(activate(&mut f, 2, 1, 20).is_err());
    assert_eq!(f.store.current_head, head);
    assert_eq!(
        f.store
            .fused_planning_status_v04(task(), UnixMillisV2::new(20))
            .unwrap()
            .active_plan_revision,
        1
    );
}

#[test]
fn fused_g7_dependency_requires_authenticated_success_not_just_reservation() {
    let mut f = empty_fixture();
    let mut a = f.input(40, 1, 1);
    let b = f.input(41, 1, 2);
    enroll(&mut f, &[&a, &b], true);
    choose(&mut f, 1, 1, 10);
    activate(&mut f, 1, 0, 10).unwrap();
    reference(&mut a, 1, 1);
    f.prepare(&a).unwrap();
    let mut b = f.input(42, 1, 2);
    reference(&mut b, 2, 1);
    let head = f.store.current_head;
    assert!(f.prepare(&b).is_err());
    assert_eq!(f.store.current_head, head);
}

#[test]
fn fused_g7_uncertain_commit_retains_link_and_never_mints_another_execution() {
    for after in [false, true] {
        let mut f = empty_fixture();
        let mut a = f.input(40, 1, 1);
        enroll(&mut f, &[&a], false);
        choose(&mut f, 1, 1, 10);
        activate(&mut f, 1, 0, 10).unwrap();
        reference(&mut a, 1, 1);
        f.store.rollback_anchor = Box::new(super::super::continuation_tests::FailAnchor {
            inner: f.anchor.clone(),
            after,
        });
        assert!(matches!(
            f.prepare(&a),
            Err(G4Error::DurableCommitUncertain)
        ));
        assert!(f.prepare(&a).is_err());
        assert!(bind(&f, &a, 10).is_err()); // a poisoned owner issues no preflight
        let mut f = f.reopen();
        assert_eq!(
            f.prepare(&a).unwrap().preparation().kind(),
            DispatchPreparationKindV2::Replay
        );
        assert_eq!(f.store.snapshot.dispatch.entries.len(), 1);
    }
}

#[test]
fn fused_g7_restore_rejects_missing_links_and_schema_downgrade() {
    let mut f = empty_fixture();
    let mut a = f.input(40, 1, 1);
    enroll(&mut f, &[&a], false);
    choose(&mut f, 1, 1, 10);
    activate(&mut f, 1, 0, 10).unwrap();
    reference(&mut a, 1, 1);
    f.prepare(&a).unwrap();
    let mut broken = f.store.snapshot.clone();
    broken.payload_schema = 11;
    assert!(validate_snapshot(&broken).is_err());
    let mut broken = f.store.snapshot.clone();
    broken.dispatch.entries.clear();
    assert!(validate_snapshot(&broken).is_err());
    let mut broken = f.store.snapshot.clone();
    broken.continuations.planning = Default::default();
    assert!(validate_snapshot(&broken).is_err());
    let bytes = encode_snapshot_payload(&f.store.snapshot).unwrap();
    validate_snapshot(&decode_snapshot_payload(&bytes).unwrap()).unwrap();
}

#[test]
fn fused_g7_late_old_outcomes_preserve_replacement_and_only_success_unblocks_dependencies() {
    // Verified receipt fields are supplied at the private test seam, not by a
    // model and not through a production proof constructor.
    for disposition in [
        AuthenticatedEffectDispositionV2::known_success_for_test(),
        AuthenticatedEffectDispositionV2::failed_no_effect_for_test(),
        AuthenticatedEffectDispositionV2::indeterminate_for_test(),
    ] {
        let mut f = empty_fixture();
        let mut a = f.input(40, 1, 1);
        let b = f.input(41, 1, 2);
        let c = f.input(42, 1, 3);
        enroll(&mut f, &[&a, &b, &c], true);
        choose(&mut f, 1, 1, 10);
        activate(&mut f, 1, 0, 10).unwrap();
        reference(&mut a, 1, 1);
        let original = f.prepare(&a).unwrap();
        choose(&mut f, 2, 2, 20);
        activate(&mut f, 2, 1, 20).unwrap();
        let mut f = f.reopen();
        let p = original.preparation();
        let proof = VerifiedExecutorDispositionV2 {
            execution_nonce: p.execution_nonce(),
            dispatch_core_digest: p.dispatch_core_digest(),
            dispatch_subject_digest: p.dispatch_subject_digest(),
            evidence_digest: d(66),
            disposition,
        };
        let result = f
            .store
            .reconcile_tool_dispatch_with_outcome(proof, true)
            .unwrap();
        assert_eq!(
            f.store
                .fused_planning_status_v04(task(), UnixMillisV2::new(20))
                .unwrap()
                .active_plan_revision,
            2
        );
        let mut next = f.input(43, 1, 3);
        reference(&mut next, 3, 2);
        assert_eq!(
            f.prepare_at(&next, UnixMillisV2::new(20), 100).is_ok(),
            result == KernelDispatchStateV2::CompletionCommitted
        );
        let mut duplicate = f.input(44, 1, 1);
        reference(&mut duplicate, 1, 2);
        assert!(f
            .prepare_at(&duplicate, UnixMillisV2::new(20), 100)
            .is_err());
    }
}

#[test]
fn fused_execution_commitment_keeps_security_fields_but_abstracts_plan_identity() {
    let mut f = empty_fixture();
    let input = f.input(40, 1, 1);
    let material = f
        .store
        .snapshot
        .intents
        .intents
        .iter()
        .find(|i| i.record.action_intent_id == input.id)
        .unwrap()
        .record
        .material()
        .clone();
    let original = commitment(&f, &input);
    let mut reordered = material.clone();
    reordered.binding.plan_revision_digest = PlanRevisionDigestV2::new([99; 32]);
    reordered.binding.internal_step_id = InternalStepIdV2::new([98; 32]);
    assert_eq!(
        fused_execution_commitment_v04(&reordered, input.request.matched.content()).unwrap(),
        original
    );
    for field in 0..5 {
        let mut changed = material.clone();
        match field {
            0 => changed.binding.argument_digest = d(99),
            1 => changed.binding.provenance_set_digest = d(99),
            2 => changed.binding.destination_digest = d(99),
            3 => changed.binding.token_set_digest = d(99),
            _ => changed.binding.executor_identity_digest = d(99),
        }
        assert_ne!(
            fused_execution_commitment_v04(&changed, input.request.matched.content()).unwrap(),
            original
        );
    }
    let larger = f.input(41, 1, 2);
    assert_ne!(commitment(&f, &larger), original);
}

#[test]
fn fused_g7_precommit_failure_changes_neither_started_prefix_nor_any_ledger() {
    let mut f = Fixture::new();
    f.activate().unwrap();
    let mut a = f.input(40, 1, 1);
    f.attach(&mut a, 50);
    enroll(&mut f, &[&a], false);
    choose(&mut f, 1, 1, 10);
    activate(&mut f, 1, 0, 10).unwrap();
    reference(&mut a, 1, 1);
    let head = f.store.current_head;
    let revision = f
        .store
        .fused_planning_status_v04(task(), now())
        .unwrap()
        .revision;
    f.store
        .set_before_next_commit_hook_for_test(|| Err(G4Error::DurableStateIo));
    assert!(matches!(f.prepare(&a), Err(G4Error::DurableStateIo)));
    assert_eq!(f.store.current_head, head);
    assert_eq!(
        f.store
            .fused_planning_status_v04(task(), now())
            .unwrap()
            .revision,
        revision
    );
    assert_eq!(f.usage(), (0, 0));
    assert!(f.store.snapshot.dispatch.entries.is_empty());
    let mut f = f.reopen();
    assert_eq!(
        f.prepare(&a).unwrap().preparation().kind(),
        DispatchPreparationKindV2::Created
    );
}
