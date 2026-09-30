use super::*;
use crate::v2::{
    EffectSetV2, FusedOwnedInputV04, KernelValueV2, ProvenanceContextV2, ProvenanceRecordV2,
};
use savana_kernel_protocol::v2::{ProducerIdentityV2, ValueInternalIdV2};

fn install_inputs(s: &mut DurableG4StateV2) {
    s.install_verified_task_authorization(auth(1)).unwrap();
    let mut p = profile();
    p.policy.operations[0].bindings = vec![SlotBinding {
        result_of: None,
        result_path: None,
        result_max_bytes: None,
        result_source_clause: None,
        argument: "body".into(),
        slot: [1; 16],
    }];
    s.install_fused_planning_v04(verified(p), now(10)).unwrap();
}
fn input(id: u8, run: u8, expiry: u64) -> FusedOwnedInputV04 {
    let value = KernelValueV2::text("fused-private-fixed-input").unwrap();
    let p = ProvenanceRecordV2::gated_ingress(
        &value,
        ProvenanceContextV2::from_authenticated_runtime(
            ProducerIdentityV2::new([40; 32]),
            DurableRunIdV2::new([run; 32]),
            Digest32V2::new([3; 32]),
            now(1),
            now(expiry),
        )
        .unwrap(),
        Digest32V2::new([41; 32]),
        Digest32V2::new([42; 32]),
        Digest32V2::new([43; 32]),
        EffectSetV2::ALL,
    )
    .unwrap();
    FusedOwnedInputV04::from_owned_value([1; 16], ValueInternalIdV2::new([id; 32]), &value, &p)
        .unwrap()
}
fn pin(s: &mut DurableG4StateV2, time: u64) -> Result<(), G4Error> {
    s.pin_fused_inputs_v04(
        task(),
        DurableRunIdV2::new([44; 32]),
        7,
        vec![input(45, 44, 100)],
        now(time),
    )
}

#[test]
fn fused_inputs_encrypted_reopen_keeps_identity_source_expiry_and_exact_retry() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(STATE_FILE_NAME);
    let anchor = TestRollbackProtectedStateAnchorV2::default();
    let mut s = task_store(&path, [0x81; 32], anchor.clone());
    install_inputs(&mut s);
    let root = s.task_authorization_state(task()).unwrap().digest();
    pin(&mut s, 12).unwrap();
    assert_eq!(s.snapshot.payload_schema, 16);
    let head = s.current_head;
    pin(&mut s, 13).unwrap();
    assert_eq!(s.current_head, head);
    assert_eq!(s.task_authorization_state(task()).unwrap().digest(), root);
    assert!(s.snapshot.dispatch.entries.is_empty());
    let disk = std::fs::read(&path).unwrap();
    assert!(!disk
        .windows(b"fused-private-fixed-input".len())
        .any(|w| w == b"fused-private-fixed-input"));
    drop(s);
    let mut s = task_store(&path, [0x81; 32], anchor);
    let recovered = s.recover_fused_inputs_v04(task(), 7, now(13)).unwrap();
    assert_eq!(recovered.run(), DurableRunIdV2::new([44; 32]));
    assert_eq!(
        recovered.inputs()[0].identity(),
        ValueInternalIdV2::new([45; 32])
    );
    assert_eq!(recovered.inputs()[0].provenance().expires_at(), now(100));
    assert!(s.recover_fused_inputs_v04(task(), 8, now(13)).is_err());
    assert!(s.recover_fused_inputs_v04(task(), 7, now(11)).is_err());
    assert!(s.recover_fused_inputs_v04(task(), 7, now(100)).is_err());
    assert!(pin(&mut s, 100).is_err());
    s.revoke_task_authorization(task()).unwrap();
    assert!(s.recover_fused_inputs_v04(task(), 7, now(13)).is_err());
}

#[test]
fn fused_inputs_reject_rebinding_wrong_run_missing_extra_and_expiry_without_writes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(STATE_FILE_NAME);
    let mut s = task_store(
        &path,
        [0x81; 32],
        TestRollbackProtectedStateAnchorV2::default(),
    );
    install_inputs(&mut s);
    let head = s.current_head;
    for entries in [
        vec![],
        vec![input(45, 44, 12)],
        vec![input(45, 46, 100)],
        vec![input(45, 44, 100), input(46, 44, 100)],
    ] {
        assert!(s
            .pin_fused_inputs_v04(task(), DurableRunIdV2::new([44; 32]), 7, entries, now(12))
            .is_err());
        assert_eq!(s.current_head, head);
    }
    pin(&mut s, 12).unwrap();
    let head = s.current_head;
    for (id, run, gen, expiry) in [
        (46, 44, 7, 100),
        (45, 46, 7, 100),
        (45, 44, 8, 100),
        (45, 44, 7, 200),
    ] {
        assert!(s
            .pin_fused_inputs_v04(
                task(),
                DurableRunIdV2::new([run; 32]),
                gen,
                vec![input(id, run, expiry)],
                now(13)
            )
            .is_err());
        assert_eq!(s.current_head, head);
    }
}

#[test]
fn fused_inputs_uncertain_commit_cannot_rebind_snapshot() {
    for after in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(STATE_FILE_NAME);
        let anchor = TestRollbackProtectedStateAnchorV2::default();
        let mut s = task_store(&path, [0x81; 32], anchor.clone());
        install_inputs(&mut s);
        s.rollback_anchor = Box::new(super::super::continuation_tests::FailAnchor {
            inner: anchor.clone(),
            after,
        });
        assert!(matches!(
            pin(&mut s, 12),
            Err(G4Error::DurableCommitUncertain)
        ));
        assert!(pin(&mut s, 12).is_err());
        drop(s);
        let mut s = task_store(&path, [0x81; 32], anchor);
        let head = s.current_head;
        pin(&mut s, 12).unwrap();
        assert_eq!(s.current_head, head);
        assert_eq!(
            s.recover_fused_inputs_v04(task(), 7, now(12))
                .unwrap()
                .inputs()
                .len(),
            1
        );
    }
}

#[test]
fn fused_inputs_restore_rejects_corrupt_scope_value_provenance_and_schema() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(STATE_FILE_NAME);
    let mut s = task_store(
        &path,
        [0x81; 32],
        TestRollbackProtectedStateAnchorV2::default(),
    );
    install_inputs(&mut s);
    pin(&mut s, 12).unwrap();
    let original: serde_json::Value =
        serde_json::from_slice(&s.snapshot.continuations.encode().unwrap()).unwrap();
    for field in ["profile", "manifest", "run", "inputs", "captured_at"] {
        let mut j = original.clone();
        let inputs = &mut j["planning"]["records"][0]["inputs"];
        inputs[field] = match field {
            "inputs" => serde_json::json!([]),
            "captured_at" => serde_json::json!(1001),
            _ => serde_json::json!(vec![99; 32]),
        };
        if let Ok(table) = ContinuationTableV04::decode(&serde_json::to_vec(&j).unwrap()) {
            let mut broken = s.snapshot.clone();
            broken.continuations = table;
            assert!(validate_snapshot(&broken).is_err(), "{field}");
        }
    }
    for field in ["value", "provenance"] {
        let mut j = original.clone();
        j["planning"]["records"][0]["inputs"]["inputs"][0][field] = serde_json::json!([0]);
        if let Ok(table) = ContinuationTableV04::decode(&serde_json::to_vec(&j).unwrap()) {
            let mut broken = s.snapshot.clone();
            broken.continuations = table;
            assert!(validate_snapshot(&broken).is_err());
        }
    }
    for schema in [11, 12, 13, 14, 15] {
        let mut broken = s.snapshot.clone();
        broken.payload_schema = schema;
        assert!(validate_snapshot(&broken).is_err());
    }
}
