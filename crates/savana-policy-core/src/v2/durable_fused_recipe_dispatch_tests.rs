//! Nonempty stored bindings -> G5 -> real G7 transaction/reopen tests. Descriptors
//! and effect dispositions use private test fixtures; no provider effect is sent.
use super::*;
use savana_continuation_core::planning::SlotBinding;
use savana_kernel_protocol::v2::{ProducerIdentityV2, SlotKindV2};

fn setup(dependencies: bool) -> (Fixture, FusedPlanningProfileV04) {
    setup_with_final_source(dependencies, None)
}

fn setup_with_final_source(
    dependencies: bool,
    final_result_source: Option<u16>,
) -> (Fixture, FusedPlanningProfileV04) {
    let mut f = empty_fixture();
    let root = f.store.task_authorization_state(task()).unwrap();
    let mut p = super::super::super::fused_planning_tests::profile();
    p.task = *task().as_bytes();
    p.policy.root = *root.authorization().digest().as_bytes();
    p.policy.operations = (1..=3)
        .map(|id| Operation {
            id,
            tool_class: 1,
            action_template: 1,
            bindings: vec![SlotBinding {
                result_of: None,
                result_path: None,
                result_max_bytes: None,
                result_source_clause: None,
                argument: "body".into(),
                slot: [7; 16],
            }],
            after: if dependencies && id > 1 {
                vec![1]
            } else {
                vec![]
            },
        })
        .collect();
    p.policy.templates = vec![
        Template {
            id: 1,
            order: vec![1, 2, 3],
        },
        Template {
            id: 2,
            order: vec![1, 3, 2],
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
    if final_result_source.is_some() {
        p.schema = 3;
        p.final_result_source = final_result_source;
        p.policy.templates[1].order = vec![2, 1, 3];
    }
    let proof = VerifiedFusedPlanningProfileV04::verify(
        &serde_json::to_vec(&p).unwrap(),
        &admin_key().sign(&p.signing_digest().unwrap()).to_bytes(),
        &admin_key().verifying_key(),
        root.authorization(),
        now(),
    )
    .unwrap();
    f.store.install_fused_planning_v04(proof, now()).unwrap();
    choose(&mut f, 1, 1, 10);
    activate(&mut f, 1, 0, 10).unwrap();
    (f, p)
}

fn input(
    f: &mut Fixture,
    p: &FusedPlanningProfileV04,
    op: u16,
    rev: u64,
    id: u8,
    source: u8,
) -> Input {
    input_with_policy(
        f,
        p,
        op,
        rev,
        id,
        source,
        G5PolicyDispositionV2::permit_for_test(),
    )
}

fn input_with_policy(
    f: &mut Fixture,
    p: &FusedPlanningProfileV04,
    op: u16,
    rev: u64,
    id: u8,
    source: u8,
    disposition: G5PolicyDispositionV2,
) -> Input {
    let implementation = crate::v2::validator_tests::implementation(
        InternalValidatorImplementationKindV2::ProjectionBindingIntegrity,
        0x82,
    );
    let registry =
        VerifiedInternalValidatorRegistryV2::from_build_manifest(vec![implementation.clone()])
            .unwrap();
    let policy = p.policy.commitment().unwrap();
    let plan = crate::v2::task_authorization::hash_parts(
        b"SAVANA_FUSED_LOCAL_PLAN_V04\0",
        &[&policy, &rev.to_be_bytes()],
    );
    let step = crate::v2::task_authorization::hash_parts(
        b"SAVANA_FUSED_LOCAL_OPERATION_V04\0",
        &[&policy, &op.to_be_bytes()],
    );
    let value = KernelValueV2::text("private body").unwrap();
    let prov = ProvenanceRecordV2::gated_ingress(
        &value,
        ProvenanceContextV2::from_authenticated_runtime(
            ProducerIdentityV2::new([90; 32]),
            DurableRunIdV2::new([4; 32]),
            d(3),
            UnixMillisV2::new(1),
            UnixMillisV2::new(1000),
        )
        .unwrap(),
        d(91),
        d(92),
        d(source),
        EffectSetV2::ALL,
    )
    .unwrap();
    let neutral = VerifiedInternalSlotMaterialV2::from_resolved_envelope(
        d(2),
        d(3),
        DurableRunIdV2::new([4; 32]),
        0,
        SlotKindV2::new(1),
        ClosedCardinalityV2::ExactlyOne,
        PlannerSlotConfidentialityV2::ConfidentialAbstract,
        vec![],
        ValueInternalIdV2::new([94; 32]),
        prov.value_digest(),
        prov.provenance_digest(),
        &VerifiedResolvedRelationSetV2::from_verified_plan_envelope(1, vec![]).unwrap(),
    )
    .unwrap();
    let arg = ArgumentNameV2::new("body").unwrap();
    let args = [VerifiedPlanArgumentV2::from_verified_plan(arg.clone(), &neutral).unwrap()];
    let values = [StoredValueRecordV2::from_store(&neutral, &value, &prov).unwrap()];
    let stored = StoredBindingResolverV2::resolve(
        DurableRunIdV2::new([4; 32]),
        d(3),
        ExecutorIdentityV2::new([13; 32]),
        &args,
        &values,
        &[],
        &[],
    )
    .unwrap();
    let request = task_request(
        &f.store,
        task(),
        1,
        1,
        stored.argument_digest(),
        stored.provenance_set_digest(),
        plan,
    );
    let slot = neutral
        .clone()
        .with_task_relation(
            &VerifiedResolvedRelationSetV2::from_task_match(1, &request.matched).unwrap(),
        )
        .unwrap();
    let args = [VerifiedPlanArgumentV2::from_verified_plan(arg.clone(), &slot).unwrap()];
    let values = [StoredValueRecordV2::from_store(&slot, &value, &prov).unwrap()];
    let stored = StoredBindingResolverV2::resolve(
        DurableRunIdV2::new([4; 32]),
        d(3),
        ExecutorIdentityV2::new([13; 32]),
        &args,
        &values,
        &[],
        &[],
    )
    .unwrap();
    let binding = ToolExecutionSemanticBindingV2::from_verified_authorization(
        PlanRevisionDigestV2::new(*plan.as_bytes()),
        InternalStepIdV2::new(*step.as_bytes()),
        d(7),
        stored.argument_digest(),
        stored.provenance_set_digest(),
        stored.token_set_digest(),
        d(10),
        d(11),
        d(12),
        ExecutorIdentityV2::new([13; 32]),
        AttemptKindV2::ToolWrite,
    )
    .unwrap();
    let material = VerifiedActionIntentMaterialV2::new_for_test_with_validators(
        binding,
        vec![StableActionArgumentBindingV2::new_for_test(
            arg,
            slot.internal_slot_digest().unwrap(),
            ValueInternalIdV2::new([94; 32]),
            prov.value_digest(),
            prov.provenance_digest(),
        )],
        6,
        vec![implementation.declaration()],
    );
    let recipe =
        FusedExecutionRecipeV04::from_verified_g4(&material, &request.matched, &[neutral]).unwrap();
    let semantic = tool_execution_semantic_binding_digest_v2(material.binding()).unwrap();
    let proposal = VerifiedToolProposalV2::from_authenticated_decoded_request(
        RequestIdV2::new([id; 16]),
        &[id],
        d(2),
        d(3),
        DurableRunIdV2::new([4; 32]),
        task(),
        &material,
    )
    .unwrap();
    let intent = f.store.create_or_replay_intent(proposal, material).unwrap();
    f.store
        .evaluate_g5(
            &registry,
            intent.action_intent_id(),
            &stored,
            OntologyEvaluationV2::Match,
            disposition,
        )
        .unwrap();
    Input {
        id: intent.action_intent_id(),
        semantic,
        request: request.with_fused_recipe(recipe),
        plaintext: None,
    }
}

fn approve(f: &mut Fixture, p: &FusedPlanningProfileV04, inputs: &[&Input]) {
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
        bindings: inputs
            .iter()
            .enumerate()
            .map(|(i, v)| FusedRecipeBindingV04 {
                operation: i as u16 + 1,
                recipe: v.request.fused_recipe.as_ref().unwrap().commitment(),
            })
            .collect(),
    };
    let command = ManagedAdminCommandV04 {
        schema: 1,
        installation: [2; 32],
        store: [0x54; 32],
        request: [98; 32],
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
}

fn prepare(
    f: &mut Fixture,
    input: &Input,
    time: u64,
    expiry: u64,
) -> Result<KernelPreparedDispatchV2, G4Error> {
    f.store.prepare_task_bound_tool_dispatch(
        input.id,
        VerifiedQuotaLimitV2::new_for_test(100, 0x85, subject()),
        None,
        ResolvedExecutionTicketV2::from_resolved_kernel_ticket(
            Digest32V2::new(*input.id.as_bytes()),
            input.id,
            input.semantic,
        )
        .unwrap(),
        VerifiedEffectGateLeaseV2::from_authenticated_ledger(
            d(2),
            d(3),
            7,
            8,
            false,
            ExecutorIdentityV2::new([13; 32]),
            HpkeX25519KeyIdV2::new([0x83; 32]),
            &shared_connector_registry(0x84),
            UnixMillisV2::new(expiry),
        )
        .unwrap(),
        d(0x87),
        &input.request,
        UnixMillisV2::new(time),
    )
}
fn initial() -> (Fixture, FusedPlanningProfileV04, Input, Input, Input) {
    let (mut f, p) = setup(false);
    let a = input(&mut f, &p, 1, 1, 40, 93);
    let b = input(&mut f, &p, 2, 1, 41, 93);
    let c = input(&mut f, &p, 3, 1, 42, 93);
    approve(&mut f, &p, &[&a, &b, &c]);
    (f, p, a, b, c)
}

fn recovery_scope_fixture() -> (Fixture, Input) {
    let (f, _, mut inputs) = scoped_inputs_fixture(None);
    (f, inputs.remove(0))
}

fn scoped_inputs_fixture(
    final_source: Option<u16>,
) -> (Fixture, FusedPlanningProfileV04, Vec<Input>) {
    let (mut f, p) = setup_with_final_source(false, final_source);
    // Recipe approval is a compilation step, not pre-creation of future live
    // intents against the initial task counters. Keep these drafts in a
    // separate synthetic owner; runtime intents are created step by step.
    let mut compilation = empty_fixture();
    let mut a = input(&mut compilation, &p, 1, 1, 40, 93);
    let b = input(&mut compilation, &p, 2, 1, 41, 93);
    let c = input(&mut compilation, &p, 3, 1, 42, 93);
    let value = KernelValueV2::text("private body").unwrap();
    let provenance = ProvenanceRecordV2::gated_ingress(
        &value,
        ProvenanceContextV2::from_authenticated_runtime(
            ProducerIdentityV2::new([90; 32]),
            DurableRunIdV2::new([4; 32]),
            d(3),
            UnixMillisV2::new(1),
            UnixMillisV2::new(1000),
        )
        .unwrap(),
        d(91),
        d(92),
        d(93),
        EffectSetV2::ALL,
    )
    .unwrap();
    let owned = crate::v2::FusedOwnedInputV04::from_owned_value(
        [7; 16],
        ValueInternalIdV2::new([94; 32]),
        &value,
        &provenance,
    )
    .unwrap();
    f.store
        .pin_fused_inputs_v04(task(), DurableRunIdV2::new([4; 32]), 7, vec![owned], now())
        .unwrap();
    approve(&mut f, &p, &[&a, &b, &c]);
    if final_source.is_none() {
        a = input(&mut f, &p, 1, 1, 40, 93);
        a.request = bind(&f, &a, 10).unwrap().with_fused_result_scope(
            crate::v2::FusedResultScopeV04::from_authenticated_session(
                f.store
                    .task_authorization_state(task())
                    .unwrap()
                    .authorization()
                    .material()
                    .principal(),
                ProducerIdentityV2::new([90; 32]),
                UnixMillisV2::new(100),
                EffectSetV2::SEND,
            )
            .unwrap(),
        );
    }
    (f, p, vec![a, b, c])
}

#[path = "durable_fused_final_result_tests.rs"]
mod final_result_tests;

#[test]
fn fused_execution_recovery_scope_atomic_reopen_replay_and_revocation() {
    let (mut f, mut a) = recovery_scope_fixture();
    let dispatch = prepare(&mut f, &a, 10, 100).unwrap();
    assert_eq!(f.store.snapshot.payload_schema, 17);
    let original = f
        .store
        .recover_fused_executions_v04(task())
        .unwrap()
        .remove(0);
    let binding = original.result_binding();
    let mut f = f.reopen();
    let head = f.store.current_head;
    assert_eq!(
        prepare(&mut f, &a, 10, 100).unwrap().preparation().kind(),
        DispatchPreparationKindV2::Replay
    );
    assert_eq!(f.store.current_head, head);
    let scope = a.request.fused_result_scope.as_ref().unwrap();
    a.request.fused_result_scope = Some(
        crate::v2::FusedResultScopeV04::from_authenticated_session(
            scope.principal(),
            ProducerIdentityV2::new([89; 32]),
            scope.expires_at(),
            scope.effects(),
        )
        .unwrap(),
    );
    assert!(prepare(&mut f, &a, 10, 100).is_err());
    assert_eq!(f.store.current_head, head);
    f.store.revoke_task_authorization(task()).unwrap();
    let f = f.reopen();
    let head = f.store.current_head;
    let recovered = f
        .store
        .recover_fused_executions_v04(task())
        .unwrap()
        .remove(0);
    assert_eq!(recovered.result_binding(), binding);
    assert_eq!(
        recovered.core().execution_nonce(),
        dispatch.preparation().execution_nonce()
    );
    assert_eq!(
        recovered.scope().producer(),
        ProducerIdentityV2::new([90; 32])
    );
    assert_eq!(recovered.scope().expires_at(), UnixMillisV2::new(100));
    assert_eq!(recovered.scope().effects(), EffectSetV2::SEND);
    assert_eq!(f.store.current_head, head);
    assert_eq!(
        f.store
            .task_authorization_state(task())
            .unwrap()
            .clause_consumption(1),
        Some((1, 1))
    );
}

#[test]
fn fused_recovery_inventory_is_read_only_and_survives_revocation_and_reopen() {
    let (mut f, a) = recovery_scope_fixture();
    assert!(f
        .store
        .recover_all_scoped_fused_executions_v04()
        .unwrap()
        .is_empty());
    let prepared = prepare(&mut f, &a, 10, 100).unwrap();
    f.store.revoke_task_authorization(task()).unwrap();
    let f = f.reopen();
    let head = f.store.current_head;
    let jobs = f.store.recover_all_scoped_fused_executions_v04().unwrap();
    assert_eq!(jobs.len(), 1);
    assert_eq!(
        jobs[0].core().execution_nonce(),
        prepared.preparation().execution_nonce()
    );
    assert_eq!(jobs[0].core().durable_task_id(), task());
    assert_eq!(jobs[0].scope().expires_at(), UnixMillisV2::new(100));
    assert_eq!(f.store.current_head, head);
}

#[test]
fn fused_recovery_inventory_never_backfills_legacy_result_scope() {
    let (mut f, mut a) = recovery_scope_fixture();
    a.request.fused_result_scope = None;
    prepare(&mut f, &a, 10, 100).unwrap();
    let f = f.reopen();
    let head = f.store.current_head;
    assert!(f
        .store
        .recover_all_scoped_fused_executions_v04()
        .unwrap()
        .is_empty());
    assert!(f.store.recover_fused_executions_v04(task()).is_err());
    assert_eq!(f.store.current_head, head);
}

#[test]
fn fused_execution_recovery_scope_refuses_wrong_principal_or_extended_lifetime_before_commit() {
    for wrong_principal in [true, false] {
        let (mut f, mut a) = recovery_scope_fixture();
        let root = f.store.task_authorization_state(task()).unwrap();
        a.request.fused_result_scope = Some(
            crate::v2::FusedResultScopeV04::from_authenticated_session(
                if wrong_principal {
                    savana_kernel_protocol::v2::PrincipalIdV2::new([81; 32])
                } else {
                    root.authorization().material().principal()
                },
                ProducerIdentityV2::new([90; 32]),
                UnixMillisV2::new(if wrong_principal {
                    100
                } else {
                    root.authorization().material().expires_at().get() + 1
                }),
                EffectSetV2::SEND,
            )
            .unwrap(),
        );
        let head = f.store.current_head;
        assert!(prepare(&mut f, &a, 10, 100).is_err());
        assert_eq!(f.store.current_head, head);
        assert!(f
            .store
            .recover_fused_executions_v04(task())
            .unwrap()
            .is_empty());
        assert!(f.store.recovery_projection().unwrap().is_empty());
    }
}

#[test]
fn fused_execution_recovery_scope_corruption_and_schema_downgrade_fail_closed() {
    let (mut f, a) = recovery_scope_fixture();
    prepare(&mut f, &a, 10, 100).unwrap();
    let raw: serde_json::Value =
        serde_json::from_slice(&f.store.snapshot.continuations.encode().unwrap()).unwrap();
    for field in [
        "principal",
        "producer",
        "effects",
        "expires_at",
        "schema",
        "missing",
    ] {
        let mut json = raw.clone();
        let scope = &mut json["planning"]["records"][0]["executions"][0]["result_scope"];
        match field {
            "principal" | "producer" => scope[field] = serde_json::json!(vec![0u8; 32]),
            "effects" => scope[field] = serde_json::json!(65535),
            "expires_at" => scope[field] = serde_json::json!(1),
            "schema" => scope[field] = serde_json::json!(2),
            _ => *scope = serde_json::Value::Null,
        }
        let mut snapshot = f.store.snapshot.clone();
        match crate::v2::continuation_state::ContinuationTableV04::decode(
            &serde_json::to_vec(&json).unwrap(),
        ) {
            Ok(table) => {
                snapshot.continuations = table;
                assert!(validate_snapshot(&snapshot).is_err(), "{field}");
            }
            Err(_) => {}
        }
    }
    let mut snapshot = f.store.snapshot.clone();
    snapshot.payload_schema = 16;
    assert!(validate_snapshot(&snapshot).is_err());
}

#[test]
fn fused_execution_result_checkpoint_requires_success_and_is_immutable_after_reopen() {
    let (mut f, a) = recovery_scope_fixture();
    let dispatch = prepare(&mut f, &a, 10, 100).unwrap();
    let p = dispatch.preparation();
    let head = f.store.current_head;
    assert!(f
        .store
        .record_fused_result_commit_v04(task(), p.execution_nonce(), d(77))
        .is_err());
    assert_eq!(f.store.current_head, head);
    f.store
        .reconcile_tool_dispatch_with_outcome(
            VerifiedExecutorDispositionV2 {
                execution_nonce: p.execution_nonce(),
                dispatch_core_digest: p.dispatch_core_digest(),
                dispatch_subject_digest: p.dispatch_subject_digest(),
                evidence_digest: d(66),
                disposition: AuthenticatedEffectDispositionV2::known_success_for_test(),
            },
            true,
        )
        .unwrap();
    f.store
        .record_fused_result_commit_v04(task(), p.execution_nonce(), d(77))
        .unwrap();
    let mut f = f.reopen();
    let head = f.store.current_head;
    f.store
        .record_fused_result_commit_v04(task(), p.execution_nonce(), d(77))
        .unwrap();
    assert!(f
        .store
        .record_fused_result_commit_v04(task(), p.execution_nonce(), d(78))
        .is_err());
    assert_eq!(f.store.current_head, head);
    assert_eq!(
        f.store.recover_fused_executions_v04(task()).unwrap()[0].result_commit(),
        Some(d(77))
    );
}

#[test]
fn fused_inputs_g7_checks_original_snapshot_even_with_signed_different_recipe() {
    for source in [93, 95] {
        let (mut f, p) = setup(false);
        let mut a = input(&mut f, &p, 1, 1, 40, source);
        let b = input(&mut f, &p, 2, 1, 41, source);
        let c = input(&mut f, &p, 3, 1, 42, source);
        let value = KernelValueV2::text("private body").unwrap();
        let provenance = ProvenanceRecordV2::gated_ingress(
            &value,
            ProvenanceContextV2::from_authenticated_runtime(
                ProducerIdentityV2::new([90; 32]),
                DurableRunIdV2::new([4; 32]),
                d(3),
                UnixMillisV2::new(1),
                UnixMillisV2::new(1000),
            )
            .unwrap(),
            d(91),
            d(92),
            d(93),
            EffectSetV2::ALL,
        )
        .unwrap();
        let owned = crate::v2::FusedOwnedInputV04::from_owned_value(
            [7; 16],
            ValueInternalIdV2::new([94; 32]),
            &value,
            &provenance,
        )
        .unwrap();
        f.store
            .pin_fused_inputs_v04(task(), DurableRunIdV2::new([4; 32]), 7, vec![owned], now())
            .unwrap();
        approve(&mut f, &p, &[&a, &b, &c]);
        let mut f = f.reopen();
        let head = f.store.current_head;
        assert_eq!(bind(&f, &a, 10).is_ok(), source == 93);
        reference(&mut a, 1, 1);
        assert_eq!(prepare(&mut f, &a, 10, 100).is_ok(), source == 93);
        if source == 93 {
            assert_eq!(f.store.snapshot.payload_schema, 16);
            let mut f = f.reopen();
            a.request.fused_recipe = None;
            let head = f.store.current_head;
            assert_eq!(
                prepare(&mut f, &a, 10, 100).unwrap().preparation().kind(),
                DispatchPreparationKindV2::Replay
            );
            assert_eq!(f.store.current_head, head);
        } else {
            assert_eq!(f.store.current_head, head);
        }
    }
}

#[test]
fn fused_recipe_g7_commits_once_reorders_and_restores_original_execution() {
    let (mut f, p, mut a, _, c) = initial();
    a.request = bind(&f, &a, 10).unwrap();
    let before = f.store.current_head;
    let original = prepare(&mut f, &a, 10, 100).unwrap();
    assert_eq!(f.store.snapshot.payload_schema, 15);
    assert_eq!(f.store.current_head.sequence, before.sequence + 1);
    assert_eq!(
        f.store
            .task_authorization_state(task())
            .unwrap()
            .clause_consumption(1),
        Some((1, 1))
    );
    choose(&mut f, 2, 2, 20);
    activate(&mut f, 2, 1, 20).unwrap();
    let mut f = f.reopen();
    // Recovery does not manufacture fresh recipe evidence or new consumption.
    a.request.fused_recipe = None;
    a.request = bind(&f, &a, 20).unwrap();
    assert_eq!(a.request.fused_operation.unwrap().plan_revision, 1);
    let head = f.store.current_head;
    let replay = prepare(&mut f, &a, 20, 100).unwrap();
    assert_eq!(
        replay.preparation().execution_nonce(),
        original.preparation().execution_nonce()
    );
    assert_eq!(f.store.current_head, head);
    assert!(bind(&f, &a, 100).is_err());
    assert!(prepare(&mut f, &a, 100, 1000).is_err()); // a new lease cannot extend an old execution
    assert_eq!(f.store.current_head, head);
    let mut next = input(&mut f, &p, 3, 2, 43, 93);
    let current_proof = next.request.fused_recipe.clone();
    assert_eq!(
        current_proof.as_ref().unwrap().commitment(),
        c.request.fused_recipe.as_ref().unwrap().commitment()
    );
    next.request.fused_recipe = c.request.fused_recipe;
    assert!(bind(&f, &next, 20).is_err()); // same recipe, but another exact draft
    next.request.fused_recipe = current_proof;
    next.request = bind(&f, &next, 20).unwrap();
    prepare(&mut f, &next, 20, 100).unwrap();
    let mut third = input(&mut f, &p, 2, 2, 44, 93);
    third.request = bind(&f, &third, 20).unwrap();
    prepare(&mut f, &third, 20, 100).unwrap();
    assert_eq!(
        f.store
            .task_authorization_state(task())
            .unwrap()
            .clause_consumption(1),
        Some((3, 3))
    );
    assert_eq!(
        f.store
            .quota_counter(DurableRunIdV2::new([4; 32]), subject())
            .unwrap()
            .reserved(),
        3
    );
    let f = f.reopen();
    assert_eq!(f.store.snapshot.dispatch.entries.len(), 3);
}

#[test]
fn fused_recipe_g7_refuses_absent_swapped_stale_source_expired_and_wrong_lease() {
    let (mut f, p, mut a, b, _) = initial();
    let original = a.request.clone();
    let head = f.store.current_head;
    a.request.fused_recipe = None;
    assert!(bind(&f, &a, 10).is_err());
    reference(&mut a, 1, 1);
    assert!(prepare(&mut f, &a, 10, 100).is_err());
    a.request = original.clone();
    a.request.fused_recipe = b.request.fused_recipe.clone();
    assert!(bind(&f, &a, 10).is_err());
    reference(&mut a, 1, 1);
    assert!(prepare(&mut f, &a, 10, 100).is_err());
    a.request = original;
    a.request = bind(&f, &a, 10).unwrap();
    assert!(prepare(&mut f, &a, 10, 101).is_err()); // cannot outlive recipe approval
    assert!(prepare(&mut f, &a, 100, 100).is_err());
    assert_eq!(f.store.current_head, head);
    choose(&mut f, 2, 2, 20);
    activate(&mut f, 2, 1, 20).unwrap();
    let bad = input(&mut f, &p, 1, 2, 43, 95);
    let head = f.store.current_head;
    assert!(bind(&f, &bad, 20).is_err());
    assert_eq!(f.store.current_head, head);
    assert!(bind(&f, &a, 20).is_err()); // old activated plan cannot start fresh work
    reference(&mut a, 1, 2);
    let head = f.store.current_head;
    assert!(prepare(&mut f, &a, 20, 100).is_err());
    assert_eq!(f.store.current_head, head);
}

#[test]
fn fused_recipe_g7_restore_rejects_receipt_loss_substitution_and_schema_downgrade() {
    let (mut f, _, mut a, _, _) = initial();
    a.request = bind(&f, &a, 10).unwrap();
    prepare(&mut f, &a, 10, 100).unwrap();
    let original: serde_json::Value =
        serde_json::from_slice(&f.store.snapshot.continuations.encode().unwrap()).unwrap();
    for field in ["approval", "recipe", "material", "content"] {
        let mut json = original.clone();
        json["planning"]["records"][0]["executions"][0]["recipe"][field] =
            serde_json::json!(vec![99; 32]);
        let mut changed = f.store.snapshot.clone();
        if let Ok(table) = ContinuationTableV04::decode(&serde_json::to_vec(&json).unwrap()) {
            changed.continuations = table;
            assert!(validate_snapshot(&changed).is_err(), "{field}");
        }
    }
    let mut json = original.clone();
    json["planning"]["records"][0]["executions"][0]
        .as_object_mut()
        .unwrap()
        .remove("recipe");
    let mut changed = f.store.snapshot.clone();
    if let Ok(table) = ContinuationTableV04::decode(&serde_json::to_vec(&json).unwrap()) {
        changed.continuations = table;
        assert!(validate_snapshot(&changed).is_err());
    }
    for schema in [11, 12, 13, 14] {
        let mut changed = f.store.snapshot.clone();
        changed.payload_schema = schema;
        assert!(validate_snapshot(&changed).is_err());
    }
}

#[test]
fn fused_recipe_g7_does_not_replace_current_g6_approval() {
    let (mut f, p) = setup(false);
    let mut a = input_with_policy(
        &mut f,
        &p,
        1,
        1,
        40,
        93,
        G5PolicyDispositionV2::require_approval_for_test(),
    );
    let b = input(&mut f, &p, 2, 1, 41, 93);
    let c = input(&mut f, &p, 3, 1, 42, 93);
    approve(&mut f, &p, &[&a, &b, &c]);
    a.request = bind(&f, &a, 10).unwrap();
    let head = f.store.current_head;
    assert!(prepare(&mut f, &a, 10, 100).is_err());
    assert_eq!(f.store.current_head, head);
    assert!(f.store.snapshot.dispatch.entries.is_empty());
    assert_eq!(
        f.store
            .task_authorization_state(task())
            .unwrap()
            .clause_consumption(1),
        Some((0, 0))
    );
    let mut f = f.reopen();
    assert!(prepare(&mut f, &a, 10, 100).is_err());
    assert_eq!(f.store.current_head, head);
}

#[test]
fn fused_recipe_g7_uncertain_commit_restores_receipt_and_consumption_once() {
    for after in [false, true] {
        let (mut f, _, mut a, _, _) = initial();
        a.request = bind(&f, &a, 10).unwrap();
        f.store.rollback_anchor = Box::new(super::super::super::continuation_tests::FailAnchor {
            inner: f.anchor.clone(),
            after,
        });
        assert!(matches!(
            prepare(&mut f, &a, 10, 100),
            Err(G4Error::DurableCommitUncertain)
        ));
        assert!(prepare(&mut f, &a, 10, 100).is_err());
        assert!(bind(&f, &a, 10).is_err());
        let mut f = f.reopen();
        a.request.fused_recipe = None;
        a.request = bind(&f, &a, 10).unwrap();
        let head = f.store.current_head;
        assert_eq!(
            prepare(&mut f, &a, 10, 100).unwrap().preparation().kind(),
            DispatchPreparationKindV2::Replay
        );
        assert_eq!(f.store.current_head, head);
        assert_eq!(f.store.snapshot.payload_schema, 15);
        assert_eq!(f.store.snapshot.dispatch.entries.len(), 1);
        assert_eq!(
            f.store
                .task_authorization_state(task())
                .unwrap()
                .clause_consumption(1),
            Some((1, 1))
        );
        assert_eq!(
            f.store
                .quota_counter(DurableRunIdV2::new([4; 32]), subject())
                .unwrap()
                .reserved(),
            1
        );
    }
}

#[test]
fn fused_recipe_g7_only_late_success_unblocks_reordered_dependencies() {
    for disposition in [
        AuthenticatedEffectDispositionV2::known_success_for_test(),
        AuthenticatedEffectDispositionV2::failed_no_effect_for_test(),
        AuthenticatedEffectDispositionV2::indeterminate_for_test(),
    ] {
        let (mut f, p) = setup(true);
        let mut a = input(&mut f, &p, 1, 1, 40, 93);
        let b = input(&mut f, &p, 2, 1, 41, 93);
        let c = input(&mut f, &p, 3, 1, 42, 93);
        approve(&mut f, &p, &[&a, &b, &c]);
        a.request = bind(&f, &a, 10).unwrap();
        let original = prepare(&mut f, &a, 10, 100).unwrap();
        choose(&mut f, 2, 2, 20);
        activate(&mut f, 2, 1, 20).unwrap();
        let mut f = f.reopen();
        let preparation = original.preparation();
        let result = f
            .store
            .reconcile_tool_dispatch_with_outcome(
                VerifiedExecutorDispositionV2 {
                    execution_nonce: preparation.execution_nonce(),
                    dispatch_core_digest: preparation.dispatch_core_digest(),
                    dispatch_subject_digest: preparation.dispatch_subject_digest(),
                    evidence_digest: d(66),
                    disposition,
                },
                true,
            )
            .unwrap();
        let mut next = input(&mut f, &p, 3, 2, 43, 93);
        let successful = result == KernelDispatchStateV2::CompletionCommitted;
        assert_eq!(bind(&f, &next, 20).is_ok(), successful);
        reference(&mut next, 3, 2);
        assert_eq!(prepare(&mut f, &next, 20, 100).is_ok(), successful);
        assert_eq!(
            f.store
                .task_authorization_state(task())
                .unwrap()
                .clause_consumption(1),
            Some(if successful {
                (2, 2)
            } else if result == KernelDispatchStateV2::FailedNoEffect {
                (1, 0)
            } else {
                (1, 1)
            })
        );
        // Authenticated no-effect releases magnitude under existing V2 policy;
        // its attempt remains consumed. Unknown retains both, never refunds.
        let f = f.reopen();
        assert_eq!(
            f.store
                .fused_planning_status_v04(task(), UnixMillisV2::new(20))
                .unwrap()
                .active_plan_revision,
            2
        );
    }
}
