//! Recipe admission through the real signed admin/encrypted owner transaction.
use super::*;
use crate::v2::{
    FusedRecipeApprovalV04, FusedRecipeBindingV04, ManagedAdminCommandV04,
    ManagedAdminOperationV04, ManagedAdminResultV04, VerifiedManagedAdminCommandV04,
};

fn approval() -> FusedRecipeApprovalV04 {
    FusedRecipeApprovalV04 {
        inputs_digest: None,
        schema: 1,
        recipe_schema: 1,
        installation: [2; 32],
        manifest: [3; 32],
        task: *task().as_bytes(),
        root: profile().policy.root,
        profile: profile().signing_digest().unwrap(),
        deployment_generation: 7,
        not_before: 1,
        expires_at: 100,
        bindings: vec![FusedRecipeBindingV04 {
            operation: 1,
            recipe: [80; 32],
        }],
    }
}
fn command(a: FusedRecipeApprovalV04, id: u8) -> ManagedAdminCommandV04 {
    let key = SigningKey::from_bytes(&[0x21; 32]);
    ManagedAdminCommandV04 {
        schema: 1,
        installation: [2; 32],
        store: [0x54; 32],
        request: [id; 32],
        not_before: 1,
        expires_at: 100,
        operation: ManagedAdminOperationV04::ApprovePlanningRecipes {
            approval_signature: key.sign(&a.signing_digest().unwrap()).to_bytes().to_vec(),
            approval: Box::new(a),
        },
    }
}
fn proof(c: &ManagedAdminCommandV04) -> VerifiedManagedAdminCommandV04 {
    let key = SigningKey::from_bytes(&[0x21; 32]);
    VerifiedManagedAdminCommandV04::verify(
        &c.canonical_bytes().unwrap(),
        &key.sign(&c.signing_digest().unwrap()).to_bytes(),
        &key.verifying_key(),
        Digest32V2::new([2; 32]),
        Digest32V2::new([0x54; 32]),
    )
    .unwrap()
}

#[test]
fn fused_recipe_admin_atomic_restart_exact_retry_and_immutable_approval() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(STATE_FILE_NAME);
    let anchor = TestRollbackProtectedStateAnchorV2::default();
    let mut s = task_store(&path, [0x81; 32], anchor.clone());
    install(&mut s);
    let root = s.task_authorization_state(task()).unwrap();
    let command = command(approval(), 60);
    let verified = proof(&command);
    let receipt = s.apply_managed_admin_v04(&verified, now(12)).unwrap();
    assert!(matches!(
        receipt.result(),
        ManagedAdminResultV04::PlanningRecipesApproved { .. }
    ));
    assert_eq!(s.snapshot.payload_schema, 14);
    assert_eq!(
        s.fused_planning_status_v04(task(), now(12))
            .unwrap()
            .revision,
        2
    );
    assert_eq!(
        s.task_authorization_state(task()).unwrap().digest(),
        root.digest()
    );
    assert!(s.snapshot.dispatch.entries.is_empty());
    let head = s.current_head;
    drop(s);
    let mut s = task_store(&path, [0x81; 32], anchor);
    assert!(s.apply_managed_admin_v04(&verified, now(200)).unwrap() == receipt);
    assert_eq!(s.current_head, head); // expired historical retry, not live permission
    let mut overwrite = command.clone();
    overwrite.request = [61; 32];
    assert!(s
        .apply_managed_admin_v04(&proof(&overwrite), now(12))
        .is_err());
    assert_eq!(s.current_head, head);
    let mut conflict = command.clone();
    conflict.expires_at = 90;
    assert!(s
        .apply_managed_admin_v04(&proof(&conflict), now(12))
        .is_err());
    s.revoke_task_authorization(task()).unwrap();
    let revoked = s.current_head;
    assert!(s.apply_managed_admin_v04(&verified, now(200)).unwrap() == receipt);
    assert_eq!(s.current_head, revoked);
    assert!(s.active_fused_plan_v04(task(), now(20)).is_err());
}

#[test]
fn fused_recipe_admin_rejects_wrong_scope_lifetime_signature_and_clock_without_writes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(STATE_FILE_NAME);
    let mut s = task_store(
        &path,
        [0x81; 32],
        TestRollbackProtectedStateAnchorV2::default(),
    );
    let valid = proof(&command(approval(), 60));
    assert!(s.apply_managed_admin_v04(&valid, now(12)).is_err()); // no enrollment/root
    install(&mut s);
    let head = s.current_head;
    for n in 0..10 {
        let mut a = approval();
        match n {
            0 => a.installation = [99; 32],
            1 => a.manifest = [99; 32],
            2 => a.task = [99; 32],
            3 => a.root = [99; 32],
            4 => a.profile = [99; 32],
            5 => a.not_before = 13,
            6 => a.expires_at = 12,
            7 => a.expires_at = 1001,
            8 => a.bindings[0].operation = 2,
            _ => a.bindings.push(FusedRecipeBindingV04 {
                operation: 2,
                recipe: [81; 32],
            }),
        }
        assert!(
            s.apply_managed_admin_v04(&proof(&command(a, 61)), now(12))
                .is_err(),
            "scope {n}"
        );
        assert_eq!(s.current_head, head);
    }
    let mut bad_signature = command(approval(), 61);
    if let ManagedAdminOperationV04::ApprovePlanningRecipes {
        approval_signature, ..
    } = &mut bad_signature.operation
    {
        approval_signature[0] ^= 1;
    }
    assert!(s
        .apply_managed_admin_v04(&proof(&bad_signature), now(12))
        .is_err());
    assert_eq!(s.current_head, head);
    s.update_fused_planning_v04(task(), 1, send(), now(15))
        .unwrap();
    let head = s.current_head;
    assert!(s.apply_managed_admin_v04(&valid, now(14)).is_err());
    assert_eq!(s.current_head, head);
    s.revoke_task_authorization(task()).unwrap();
    assert!(s.apply_managed_admin_v04(&valid, now(20)).is_err());
}

#[test]
fn fused_recipe_schema_and_receipt_links_cannot_lose_or_substitute_approval() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(STATE_FILE_NAME);
    let mut s = task_store(
        &path,
        [0x81; 32],
        TestRollbackProtectedStateAnchorV2::default(),
    );
    install(&mut s);
    let mut premature = s.snapshot.clone();
    premature.payload_schema = 14;
    assert!(validate_snapshot(&premature).is_err());
    s.apply_managed_admin_v04(&proof(&command(approval(), 60)), now(12))
        .unwrap();
    for schema in [4, 10, 11, 12, 13] {
        let mut downgraded = s.snapshot.clone();
        downgraded.payload_schema = schema;
        assert!(validate_snapshot(&downgraded).is_err());
    }
    let original: serde_json::Value =
        serde_json::from_slice(&s.snapshot.continuations.encode().unwrap()).unwrap();
    for n in 0..5 {
        let mut json = original.clone();
        let record = &mut json["planning"]["records"][0];
        match n {
            0 => {
                record.as_object_mut().unwrap().remove("recipe_approval");
            }
            1 => record["recipe_approval"]["manifest"] = serde_json::json!(vec![99; 32]),
            2 => {
                record["recipe_approval"]["bindings"][0]["recipe"] = serde_json::json!(vec![99; 32])
            }
            3 => record["recipe_approval"]["not_before"] = serde_json::json!(13),
            _ => record["recipe_approval"]["recipe_schema"] = serde_json::json!(2),
        }
        // Restore rejects malformed records OR the altered receipt-to-state link.
        let decoded = super::super::super::continuation_state::ContinuationTableV04::decode(
            &serde_json::to_vec(&json).unwrap(),
        );
        if let Ok(table) = decoded {
            let mut changed = s.snapshot.clone();
            changed.continuations = table;
            assert!(validate_snapshot(&changed).is_err(), "corruption {n}");
        }
    }
}

#[test]
fn fused_recipe_uncertain_commit_recovers_same_receipt_without_second_approval() {
    for after in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(STATE_FILE_NAME);
        let anchor = TestRollbackProtectedStateAnchorV2::default();
        let mut s = task_store(&path, [0x81; 32], anchor.clone());
        install(&mut s);
        s.rollback_anchor = Box::new(super::super::continuation_tests::FailAnchor {
            inner: anchor.clone(),
            after,
        });
        let p = proof(&command(approval(), 60));
        assert!(matches!(
            s.apply_managed_admin_v04(&p, now(12)),
            Err(G4Error::DurableCommitUncertain)
        ));
        assert!(s.apply_managed_admin_v04(&p, now(12)).is_err());
        drop(s);
        let mut s = task_store(&path, [0x81; 32], anchor);
        let head = s.current_head;
        assert!(matches!(
            s.apply_managed_admin_v04(&p, now(200)).unwrap().result(),
            ManagedAdminResultV04::PlanningRecipesApproved { .. }
        ));
        assert_eq!(s.current_head, head);
        assert_eq!(
            s.fused_planning_status_v04(task(), now(12))
                .unwrap()
                .revision,
            2
        );
    }
}

#[test]
fn fused_recipe_rollback_cannot_restore_unapproved_state() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(STATE_FILE_NAME);
    let anchor = TestRollbackProtectedStateAnchorV2::default();
    let mut s = task_store(&path, [0x81; 32], anchor.clone());
    install(&mut s);
    let old = fs::read(&path).unwrap();
    s.apply_managed_admin_v04(&proof(&command(approval(), 60)), now(12))
        .unwrap();
    drop(s);
    // Deliberate test-only rollback of this tempfile; never a deployed store.
    fs::write(&path, old).unwrap();
    assert!(matches!(
        DurableG4StateV2::open_for_test_in_namespace(
            &path,
            [0x81; 32],
            anchor,
            DurableStateNamespaceV2::new_for_test(2, 0x54),
        ),
        Err(G4Error::DurableStateRollback)
    ));
}

#[test]
fn fused_recipe_approval_refuses_legacy_exact_mode_and_coexists_with_schedule() {
    for exact_mode in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(STATE_FILE_NAME);
        let anchor = TestRollbackProtectedStateAnchorV2::default();
        let mut s = task_store(&path, [0x81; 32], anchor.clone());
        s.install_verified_task_authorization(auth(1)).unwrap();
        let mut p = profile();
        if exact_mode {
            p.execution_bindings = vec![crate::v2::FusedExecutionBindingV04 {
                operation: 1,
                commitment: [80; 32],
            }];
        } else {
            p.release_model_views = true;
            p.delivery_schedule = vec![crate::v2::FusedDeliverySlotV04 {
                id: 1,
                round: 1,
                role: Role::Advisor,
                opens_at: 10,
                closes_at: 20,
            }];
        }
        s.install_fused_planning_v04(verified(p.clone()), now(10))
            .unwrap();
        let head = s.current_head;
        let mut a = approval();
        a.profile = p.signing_digest().unwrap();
        let result = s.apply_managed_admin_v04(&proof(&command(a, 60)), now(12));
        if exact_mode {
            assert!(result.is_err());
            assert_eq!(s.current_head, head);
        } else {
            assert!(result.is_ok());
            assert_eq!(s.snapshot.payload_schema, 14);
            drop(s);
            let s = task_store(&path, [0x81; 32], anchor);
            assert!(s.snapshot.continuations.planning.has_recipe_approvals());
            assert!(s.snapshot.continuations.planning.has_delivery_schedule());
        }
    }
}
