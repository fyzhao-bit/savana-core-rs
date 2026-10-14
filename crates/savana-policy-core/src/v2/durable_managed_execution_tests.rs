use super::*;

fn read(f: &Fixture, p: &KernelPreparedDispatchV2) -> ManagedExecutionSnapshotV04 {
    f.store
        .managed_execution_snapshot_v04(
            task(),
            p.preparation().execution_nonce(),
            p.preparation().dispatch_core_digest(),
        )
        .unwrap()
}
fn prepared() -> (Fixture, Input, KernelPreparedDispatchV2) {
    let mut f = Fixture::build(true);
    f.activate().unwrap();
    let mut input = f.input(40, 1, 1);
    let key = f.managed_keys[0];
    attach(&f, &mut input, key);
    let p = f.prepare(&input).unwrap();
    (f, input, p)
}
fn table_json(f: &Fixture) -> serde_json::Value {
    serde_json::from_slice(&f.store.snapshot.continuations.encode().unwrap()).unwrap()
}
fn with_json(f: &Fixture, json: serde_json::Value) -> DurableG4SnapshotV2 {
    let mut s = f.store.snapshot.clone();
    s.continuations = serde_json::from_value(json).unwrap();
    s
}

#[test]
fn managed_execution_pins_actual_source_with_original_g7_commit() {
    let (f, _, p) = prepared();
    let v = read(&f, &p);
    assert_eq!(v.execution_nonce(), p.preparation().execution_nonce());
    assert_eq!(v.resource(), f.managed_keys[0]);
    assert_eq!(v.revision(), 1);
    assert_eq!(v.content(), b"private initial bytes");
    assert_eq!(v.label(), "same display name");
    assert_eq!(f.store.snapshot.payload_schema, 8);
    assert_eq!(f.usage(), (1, 4));
    assert_eq!(
        table_json(&f)["records"][0]["dispatch"]["snapshot_start"],
        0
    );
    let bytes = std::fs::read(f.dir.path().join(STATE_FILE_NAME)).unwrap();
    assert!(!bytes.windows(v.content().len()).any(|w| w == v.content()));
    let debug = format!("{v:?}");
    assert!(!debug.contains("private initial"));
    assert!(!debug.contains("same display"));
}

#[test]
fn managed_execution_never_refreshes_after_edit_delete_restart_or_replay() {
    let (mut f, input, p) = prepared();
    let key = f.managed_keys[0];
    let commitment = read(&f, &p).commitment();
    f.store
        .update_managed_resource_v04(
            key,
            1,
            Some(("new label", b"replacement private content")),
            now(),
        )
        .unwrap();
    assert_eq!(read(&f, &p).content(), b"private initial bytes");
    f.store
        .update_managed_resource_v04(key, 2, None, now())
        .unwrap();
    let mut f = f.reopen();
    let head = f.store.current_head;
    let replay = f.prepare(&input).unwrap();
    assert_eq!(
        replay.preparation().kind(),
        DispatchPreparationKindV2::Replay
    );
    assert_eq!(f.store.current_head, head);
    assert_eq!(f.usage(), (1, 4));
    let v = read(&f, &replay);
    assert_eq!(v.commitment(), commitment);
    assert_eq!(v.revision(), 1);
    assert_eq!(v.content(), b"private initial bytes");
    assert_eq!(v.label(), "same display name");
    assert!(f.store.managed_resource_v04(key).unwrap().deleted);
}

#[test]
fn managed_execution_is_bound_to_task_nonce_and_exact_dispatch_core() {
    let (f, _, p) = prepared();
    let nonce = p.preparation().execution_nonce();
    let core = p.preparation().dispatch_core_digest();
    assert!(f
        .store
        .managed_execution_snapshot_v04(DurableTaskIdV2::new([99; 32]), nonce, core)
        .is_err());
    assert!(f
        .store
        .managed_execution_snapshot_v04(task(), Nonce32V2::new([99; 32]), core)
        .is_err());
    assert!(f
        .store
        .managed_execution_snapshot_v04(task(), nonce, d(99))
        .is_err());
    assert_eq!(read(&f, &p).execution_nonce(), nonce);
}

#[test]
fn managed_execution_fails_atomically_on_original_quota_and_commit_failure() {
    let mut f = Fixture::build(true);
    f.activate().unwrap();
    let key = f.managed_keys[0];
    let mut a = f.input(40, 1, 1);
    attach(&f, &mut a, key);
    let before = f.store.snapshot.continuations.encode().unwrap();
    let head = f.store.current_head;
    f.store
        .set_before_next_commit_hook_for_test(|| Err(G4Error::DurableStateIo));
    assert!(matches!(f.prepare(&a), Err(G4Error::DurableStateIo)));
    assert_eq!(f.store.snapshot.continuations.encode().unwrap(), before);
    assert_eq!(f.store.current_head, head);
    assert_eq!(f.store.snapshot.payload_schema, 7);
    assert!(!f.store.snapshot.continuations.has_execution_snapshots());
    f.prepare_at(&a, now(), 1).unwrap();
    let mut b = f.input(41, 2, 1);
    let key = f.managed_keys[1];
    attach(&f, &mut b, key);
    let before = f.store.snapshot.continuations.encode().unwrap();
    let head = f.store.current_head;
    assert!(f.prepare_at(&b, now(), 1).is_err());
    assert_eq!(f.store.snapshot.continuations.encode().unwrap(), before);
    assert_eq!(f.store.current_head, head);
    assert_eq!(f.usage(), (1, 4));
}

#[test]
fn managed_execution_uncertain_commit_returns_no_snapshot_and_recovers_once() {
    for after in [false, true] {
        let mut f = Fixture::build(true);
        f.activate().unwrap();
        let key = f.managed_keys[0];
        let mut input = f.input(40, 1, 1);
        attach(&f, &mut input, key);
        f.store.rollback_anchor = Box::new(super::super::super::continuation_tests::FailAnchor {
            inner: f.anchor.clone(),
            after,
        });
        assert!(matches!(
            f.prepare(&input),
            Err(G4Error::DurableCommitUncertain)
        ));
        assert!(f
            .store
            .managed_execution_snapshot_v04(task(), Nonce32V2::new([1; 32]), d(1))
            .is_err());
        assert!(f.store.authenticated_state_head().is_err());
        let mut f = f.reopen();
        let p = f.prepare(&input).unwrap();
        assert_eq!(p.preparation().kind(), DispatchPreparationKindV2::Replay);
        assert_eq!(read(&f, &p).content(), b"private initial bytes");
        assert_eq!(f.usage(), (1, 4));
        let head = f.store.current_head;
        let old = read(&f, &p).commitment();
        let p = f.prepare(&input).unwrap();
        assert_eq!(read(&f, &p).commitment(), old);
        assert_eq!(f.store.current_head, head);
    }
}

#[test]
fn managed_execution_cannot_capture_from_stale_source_or_failed_domain_charge() {
    let mut f = Fixture::build(true);
    f.activate().unwrap();
    let key = f.managed_keys[0];
    let mut a = f.input(40, 1, 1);
    attach(&f, &mut a, key);
    f.store
        .update_managed_resource_v04(key, 1, Some(("new", b"new")), now())
        .unwrap();
    let before = f.store.snapshot.continuations.encode().unwrap();
    assert!(f.prepare(&a).is_err());
    assert_eq!(f.store.snapshot.continuations.encode().unwrap(), before);
    let mut b = f.input(41, 1, 3);
    attach(&f, &mut b, key); // domain 2 exceeds remaining limit
    assert!(f.prepare(&b).is_err());
    assert!(!f.store.snapshot.continuations.has_execution_snapshots());
    let mut c = f.input(42, 1, 1);
    attach(&f, &mut c, key);
    let p = f.prepare(&c).unwrap();
    assert_eq!(read(&f, &p).revision(), 2);
    assert_eq!(read(&f, &p).content(), b"new");
}

#[test]
fn managed_execution_snapshot_tampering_and_missing_required_pin_fail_restore() {
    let (f, _, _) = prepared();
    for change in 0..12 {
        let mut json = table_json(&f);
        let d = &mut json["records"][0]["dispatch"];
        match change {
            0 => {
                d["records"][0].as_object_mut().unwrap().remove("snapshot");
            }
            1 => d["snapshot_start"] = 1.into(),
            2 => {
                d.as_object_mut().unwrap().remove("snapshot_start");
            }
            3 => d["records"][0]["snapshot"]["body"]["execution"][0] = 99.into(),
            4 => d["records"][0]["snapshot"]["body"]["request_binding"][0] = 99.into(),
            5 => d["records"][0]["snapshot"]["body"]["source_policy"][0] = 99.into(),
            6 => d["records"][0]["snapshot"]["body"]["dispatch_policy"][0] = 99.into(),
            7 => d["records"][0]["snapshot"]["body"]["action_content"][0] = 99.into(),
            8 => d["records"][0]["snapshot"]["body"]["revision"] = 2.into(),
            9 => d["records"][0]["snapshot"]["body"]["resource"]["object"][0] = 99.into(),
            10 => d["records"][0]["snapshot"]["body"]["content"][0] = 99.into(),
            _ => d["records"][0]["snapshot"]["body"]["label"] = "forged label".into(),
        }
        assert!(
            validate_snapshot(&with_json(&f, json)).is_err(),
            "case {change}"
        );
    }
    let mut snapshot = f.store.snapshot.clone();
    snapshot.payload_schema = 7;
    assert!(validate_snapshot(&snapshot).is_err());
}

#[test]
fn managed_execution_matching_current_revision_rechecks_bytes_even_with_rehashed_pin() {
    let (f, _, _) = prepared();
    let mut json = table_json(&f);
    let mut pin: crate::v2::managed_execution::StoredManagedExecutionSnapshotV04 =
        serde_json::from_value(json["records"][0]["dispatch"]["records"][0]["snapshot"].clone())
            .unwrap();
    pin.body.content = b"not source content".to_vec();
    let pin =
        crate::v2::managed_execution::StoredManagedExecutionSnapshotV04::new(pin.body).unwrap();
    json["records"][0]["dispatch"]["records"][0]["snapshot"] = serde_json::to_value(pin).unwrap();
    assert!(validate_snapshot(&with_json(&f, json)).is_err());
}

#[test]
fn managed_execution_pins_cannot_be_swapped_between_real_executions() {
    let (mut f, _, p) = prepared();
    let mut b = f.input(41, 2, 1);
    let key = f.managed_keys[1];
    attach(&f, &mut b, key);
    let q = f.prepare(&b).unwrap();
    assert_ne!(read(&f, &p).commitment(), read(&f, &q).commitment());
    let mut json = table_json(&f);
    let records = json["records"][0]["dispatch"]["records"]
        .as_array_mut()
        .unwrap();
    let left = records[0]["snapshot"].clone();
    records[0]["snapshot"] = records[1]["snapshot"].clone();
    records[1]["snapshot"] = left;
    assert!(validate_snapshot(&with_json(&f, json)).is_err());
}

// Build an authentic old-layout fixture using the private writer, not a public
// downgrade API. Old code stored admitted facts/charges but no input snapshots.
fn emulate_schema7_writer(f: &mut Fixture) {
    let mut json = table_json(f);
    let d = &mut json["records"][0]["dispatch"];
    d.as_object_mut().unwrap().remove("snapshot_start");
    for a in d["records"].as_array_mut().unwrap() {
        a.as_object_mut().unwrap().remove("snapshot");
    }
    let mut old = with_json(f, json);
    old.payload_schema = 7;
    validate_snapshot(&old).unwrap();
    f.store.snapshot.payload_schema = 7;
    f.store.commit(old).unwrap();
}

#[test]
fn managed_execution_legacy_history_is_never_backfilled_and_new_suffix_is_pinned() {
    let (mut f, a, p) = prepared();
    emulate_schema7_writer(&mut f);
    let key = f.managed_keys[0];
    f.store
        .update_managed_resource_v04(key, 1, Some(("changed", b"not original")), now())
        .unwrap();
    let mut f = f.reopen();
    let head = f.store.current_head;
    assert!(f
        .store
        .managed_execution_snapshot_v04(
            task(),
            p.preparation().execution_nonce(),
            p.preparation().dispatch_core_digest()
        )
        .is_err());
    assert_eq!(
        f.prepare(&a).unwrap().preparation().kind(),
        DispatchPreparationKindV2::Replay
    );
    assert_eq!(f.store.current_head, head);
    assert_eq!(f.store.snapshot.payload_schema, 7);
    let mut b = f.input(41, 2, 1);
    let key = f.managed_keys[1];
    attach(&f, &mut b, key);
    let q = f.prepare(&b).unwrap();
    assert_eq!(
        table_json(&f)["records"][0]["dispatch"]["snapshot_start"],
        1
    );
    assert_eq!(f.store.snapshot.payload_schema, 8);
    assert_eq!(f.usage(), (2, 8));
    let f = f.reopen();
    assert_eq!(read(&f, &q).content(), b"private initial bytes");
    assert!(f
        .store
        .managed_execution_snapshot_v04(
            task(),
            p.preparation().execution_nonce(),
            p.preparation().dispatch_core_digest()
        )
        .is_err());
}

#[test]
fn managed_execution_external_sources_keep_old_format_and_have_no_snapshot() {
    let mut f = Fixture::new();
    f.activate().unwrap();
    let mut input = f.input(40, 1, 1);
    f.attach(&mut input, 50);
    let p = f.prepare(&input).unwrap();
    assert_eq!(f.store.snapshot.payload_schema, 6);
    assert!(!f.store.snapshot.continuations.has_execution_snapshots());
    let json = table_json(&f);
    assert!(json["records"][0]["dispatch"]
        .get("snapshot_start")
        .is_none());
    assert!(json["records"][0]["dispatch"]["records"][0]
        .get("snapshot")
        .is_none());
    assert!(f
        .store
        .managed_execution_snapshot_v04(
            task(),
            p.preparation().execution_nonce(),
            p.preparation().dispatch_core_digest()
        )
        .is_err());
    let f = f.reopen();
    assert_eq!(f.usage(), (1, 4));
}

#[test]
fn managed_execution_private_audit_read_does_not_restore_revoked_authority() {
    let (mut f, input, p) = prepared();
    let commitment = read(&f, &p).commitment();
    f.store.revoke_task_authorization(task()).unwrap();
    assert!(f.prepare(&input).is_err());
    assert_eq!(read(&f, &p).commitment(), commitment);
    let f = f.reopen();
    assert_eq!(read(&f, &p).commitment(), commitment);
    assert_eq!(f.usage(), (1, 4));
}

#[test]
fn managed_execution_all_outcomes_retain_original_private_input_and_usage() {
    // Inject only the private receipt-verification result, as in the existing
    // G7 recovery tests. No real executor/provider claim is made here.
    for disposition in [
        AuthenticatedEffectDispositionV2::known_success_for_test(),
        AuthenticatedEffectDispositionV2::failed_no_effect_for_test(),
        AuthenticatedEffectDispositionV2::indeterminate_for_test(),
    ] {
        let (mut f, _, p) = prepared();
        let original = read(&f, &p).commitment();
        let a = p.preparation();
        f.store
            .reconcile_tool_dispatch_with_outcome(
                VerifiedExecutorDispositionV2 {
                    execution_nonce: a.execution_nonce(),
                    dispatch_core_digest: a.dispatch_core_digest(),
                    dispatch_subject_digest: a.dispatch_subject_digest(),
                    evidence_digest: d(66),
                    disposition,
                },
                true,
            )
            .unwrap();
        let key = f.managed_keys[0];
        f.store
            .update_managed_resource_v04(key, 1, None, now())
            .unwrap();
        let f = f.reopen();
        assert_eq!(read(&f, &p).commitment(), original);
        assert_eq!(read(&f, &p).content(), b"private initial bytes");
        assert_eq!(f.usage(), (1, 4));
    }
}

#[test]
fn managed_execution_snapshot_constructor_is_bounded_and_closed() {
    let (f, _, _) = prepared();
    let json = table_json(&f);
    let body = &json["records"][0]["dispatch"]["records"][0]["snapshot"]["body"];
    for change in 0..5 {
        let mut b: crate::v2::managed_execution::SnapshotBody =
            serde_json::from_value(body.clone()).unwrap();
        match change {
            0 => b.content = vec![1; 32769],
            1 => b.label = "a".repeat(257),
            2 => b.label = "bad\nlabel".into(),
            3 => b.revision = 0,
            _ => b.execution = [0; 32],
        }
        assert!(crate::v2::managed_execution::StoredManagedExecutionSnapshotV04::new(b).is_err());
    }
    let mut unknown = body.clone();
    unknown["outbound_allowed"] = true.into();
    assert!(serde_json::from_value::<crate::v2::managed_execution::SnapshotBody>(unknown).is_err());
}

#[test]
fn managed_execution_rollback_cannot_remove_pin_and_restore_unspent_budget() {
    let mut f = Fixture::build(true);
    f.activate().unwrap();
    let path = f.dir.path().join(STATE_FILE_NAME);
    let before = std::fs::read(&path).unwrap();
    let key = f.managed_keys[0];
    let mut input = f.input(40, 1, 1);
    attach(&f, &mut input, key);
    let p = f.prepare(&input).unwrap();
    assert_eq!(read(&f, &p).content(), b"private initial bytes");
    let anchor = f.anchor.clone();
    drop(f.store);
    // Deliberately restore a genuine old encrypted file, not a forged plaintext.
    std::fs::write(&path, before).unwrap();
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
