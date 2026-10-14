//! Signed private management through the actual encrypted owner transaction.
use super::*;

fn command(id: u8, operation: ManagedAdminOperationV04) -> ManagedAdminCommandV04 {
    ManagedAdminCommandV04 {
        schema: 1,
        installation: [2; 32],
        store: [0x54; 32],
        request: [id; 32],
        not_before: 1,
        expires_at: 100,
        operation,
    }
}
fn verified(c: &ManagedAdminCommandV04) -> VerifiedManagedAdminCommandV04 {
    verified_by(c, &admin_key())
}
fn verified_by(c: &ManagedAdminCommandV04, key: &SigningKey) -> VerifiedManagedAdminCommandV04 {
    VerifiedManagedAdminCommandV04::verify(
        &c.canonical_bytes().unwrap(),
        &key.sign(&c.signing_digest().unwrap()).to_bytes(),
        &key.verifying_key(),
        d(2),
        d(0x54),
    )
    .unwrap()
}
fn create(id: u8) -> ManagedAdminCommandV04 {
    command(
        id,
        ManagedAdminOperationV04::CreateResource {
            source: [33; 32],
            namespace: [34; 32],
            label: "private imported label".into(),
            content: b"private imported bytes".to_vec(),
        },
    )
}
fn key(receipt: &ManagedAdminReceiptV04) -> ResourceKey {
    match receipt.result() {
        ManagedAdminResultV04::ResourceCreated { resource } => *resource,
        _ => panic!("expected a private creation receipt"),
    }
}
fn enroll(f: &Fixture, id: u8) -> ManagedAdminCommandV04 {
    command(
        id,
        ManagedAdminOperationV04::EnrollTask {
            profile: Box::new(f.profile.clone()),
            profile_signature: admin_key()
                .sign(&f.profile.signing_digest().unwrap())
                .to_bytes()
                .to_vec(),
            dispatch: f.policy.clone(),
            dispatch_signature: admin_key()
                .sign(&f.policy.signing_digest().unwrap())
                .to_bytes()
                .to_vec(),
        },
    )
}
fn json(f: &Fixture) -> serde_json::Value {
    serde_json::from_slice(&f.store.snapshot.continuations.encode().unwrap()).unwrap()
}

#[test]
fn managed_admin_registers_only_independently_signed_source_policy() {
    let mut f = Fixture::new();
    let p = managed_tests::source_policy();
    let mut reused = p.clone();
    reused.resource_issuer = admin_key().verifying_key().to_bytes();
    let reused = command(
        59,
        ManagedAdminOperationV04::RegisterSource {
            signature: admin_key()
                .sign(&reused.signing_digest().unwrap())
                .to_bytes()
                .to_vec(),
            policy: reused,
        },
    );
    assert!(f
        .store
        .apply_managed_admin_v04(&verified(&reused), now())
        .is_err());
    assert!(f.store.snapshot.continuations.admin.is_empty());
    let mut c = command(
        60,
        ManagedAdminOperationV04::RegisterSource {
            policy: p.clone(),
            signature: vec![0; 64],
        },
    );
    let head = f.store.current_head;
    assert!(f
        .store
        .apply_managed_admin_v04(&verified(&c), now())
        .is_err());
    assert_eq!(f.store.current_head, head);
    if let ManagedAdminOperationV04::RegisterSource { signature, .. } = &mut c.operation {
        *signature = admin_key()
            .sign(&p.signing_digest().unwrap())
            .to_bytes()
            .to_vec();
    }
    let proof = verified(&c);
    let receipt = f.store.apply_managed_admin_v04(&proof, now()).unwrap();
    assert_eq!(f.store.snapshot.payload_schema, 10);
    let mut f = f.reopen();
    let head = f.store.current_head;
    assert_eq!(
        f.store
            .apply_managed_admin_v04(&proof, UnixMillisV2::new(2000))
            .unwrap(),
        receipt
    );
    assert_eq!(f.store.current_head, head);
}

#[test]
fn managed_admin_create_retry_after_restart_returns_original_object_without_mutation() {
    let mut f = Fixture::build(true);
    let proof = verified(&create(60));
    let receipt = f.store.apply_managed_admin_v04(&proof, now()).unwrap();
    let object = key(&receipt);
    assert_eq!(
        f.store.managed_resource_v04(object).unwrap().content,
        b"private imported bytes"
    );
    let bytes = std::fs::read(f.dir.path().join(STATE_FILE_NAME)).unwrap();
    assert!(!bytes.windows(22).any(|w| w == b"private imported bytes"));
    assert!(!format!("{receipt:?}").contains("imported"));
    let mut f = f.reopen();
    let head = f.store.current_head;
    assert_eq!(
        f.store
            .apply_managed_admin_v04(&proof, UnixMillisV2::new(1000))
            .unwrap(),
        receipt
    );
    assert_eq!(f.store.current_head, head);
    assert_eq!(
        json(&f)["managed"]["sources"][0]["objects"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
}

#[test]
fn managed_admin_same_request_cannot_rebind_content_or_admin_identity() {
    let mut f = Fixture::build(true);
    let c = create(60);
    f.store
        .apply_managed_admin_v04(&verified(&c), now())
        .unwrap();
    let head = f.store.current_head;
    let mut changed = c.clone();
    if let ManagedAdminOperationV04::CreateResource { content, .. } = &mut changed.operation {
        content.push(1);
    }
    assert!(f
        .store
        .apply_managed_admin_v04(&verified(&changed), now())
        .is_err());
    assert!(f
        .store
        .apply_managed_admin_v04(&verified_by(&c, &SigningKey::from_bytes(&[99; 32])), now())
        .is_err());
    assert_eq!(f.store.current_head, head);
}

#[test]
fn managed_admin_update_delete_and_old_receipt_replay_never_resurrect() {
    let mut f = Fixture::build(true);
    let resource = f.managed_keys[0];
    let update = verified(&command(
        60,
        ManagedAdminOperationV04::UpdateResource {
            resource,
            expected_revision: 1,
            value: Some(ManagedAdminValueV04 {
                label: "renamed".into(),
                content: b"next".to_vec(),
            }),
        },
    ));
    let receipt = f.store.apply_managed_admin_v04(&update, now()).unwrap();
    let delete = verified(&command(
        61,
        ManagedAdminOperationV04::UpdateResource {
            resource,
            expected_revision: 2,
            value: None,
        },
    ));
    f.store.apply_managed_admin_v04(&delete, now()).unwrap();
    let mut f = f.reopen();
    let head = f.store.current_head;
    assert_eq!(
        f.store.apply_managed_admin_v04(&update, now()).unwrap(),
        receipt
    );
    assert!(f.store.managed_resource_v04(resource).unwrap().deleted);
    assert_eq!(f.store.managed_resource_v04(resource).unwrap().revision, 3);
    assert_eq!(f.store.current_head, head);
}

#[test]
fn managed_admin_stale_edit_and_new_expired_commands_do_not_commit_receipts() {
    let mut f = Fixture::build(true);
    let head = f.store.current_head;
    let wrong_revision = verified(&command(
        60,
        ManagedAdminOperationV04::UpdateResource {
            resource: f.managed_keys[0],
            expected_revision: 2,
            value: None,
        },
    ));
    assert!(f
        .store
        .apply_managed_admin_v04(&wrong_revision, now())
        .is_err());
    let proof = verified(&create(61));
    for time in [0, 100, 1000] {
        assert!(f
            .store
            .apply_managed_admin_v04(&proof, UnixMillisV2::new(time))
            .is_err());
    }
    assert_eq!(f.store.current_head, head);
    assert!(f.store.snapshot.continuations.admin.is_empty());
}

#[test]
fn managed_admin_verification_rejects_bad_signature_scope_encoding_and_limits() {
    let c = create(60);
    let bytes = c.canonical_bytes().unwrap();
    let sig = admin_key().sign(&c.signing_digest().unwrap()).to_bytes();
    for (body, signature, issuer, installation, store) in [
        (
            bytes.clone(),
            [0; 64],
            admin_key().verifying_key(),
            d(2),
            d(0x54),
        ),
        (
            bytes.clone(),
            sig,
            resource_key().verifying_key(),
            d(2),
            d(0x54),
        ),
        (
            bytes.clone(),
            sig,
            admin_key().verifying_key(),
            d(3),
            d(0x54),
        ),
        (
            bytes.clone(),
            sig,
            admin_key().verifying_key(),
            d(2),
            d(0x55),
        ),
        (
            [bytes.clone(), b" ".to_vec()].concat(),
            sig,
            admin_key().verifying_key(),
            d(2),
            d(0x54),
        ),
        (
            vec![0; 256 * 1024 + 1],
            sig,
            admin_key().verifying_key(),
            d(2),
            d(0x54),
        ),
    ] {
        assert!(VerifiedManagedAdminCommandV04::verify(
            &body,
            &signature,
            &issuer,
            installation,
            store
        )
        .is_err());
    }
    let mut json = serde_json::to_value(&c).unwrap();
    json["operation"]["caller_selected_key"] = "untrusted".into();
    assert!(serde_json::from_value::<ManagedAdminCommandV04>(json).is_err());
}

#[test]
fn managed_admin_enrollment_installs_storage_and_dispatch_in_one_commit() {
    let mut f = Fixture::build_with_storage(true, false, false, false);
    assert!(f.store.continuation_storage_v04(task()).is_err());
    let proof = verified(&enroll(&f, 60));
    let head = f.store.current_head;
    let receipt = f.store.apply_managed_admin_v04(&proof, now()).unwrap();
    assert_eq!(f.store.current_head.sequence, head.sequence + 1);
    assert!(f.store.snapshot.continuations.dispatch_enabled(task()));
    assert_eq!(f.usage(), (0, 0));
    let mut f = f.reopen();
    let head = f.store.current_head;
    assert_eq!(
        f.store.apply_managed_admin_v04(&proof, now()).unwrap(),
        receipt
    );
    assert_eq!(f.store.current_head, head);
}

#[test]
fn managed_admin_bad_enrollment_never_leaves_half_installed_storage() {
    let mut f = Fixture::build_with_storage(true, false, false, false);
    let mut c = enroll(&f, 60);
    if let ManagedAdminOperationV04::EnrollTask {
        dispatch_signature, ..
    } = &mut c.operation
    {
        *dispatch_signature = vec![0; 64];
    }
    let head = f.store.current_head;
    assert!(f
        .store
        .apply_managed_admin_v04(&verified(&c), now())
        .is_err());
    assert!(f.store.continuation_storage_v04(task()).is_err());
    assert_eq!(f.store.current_head, head);
    let proof = verified(&enroll(&f, 60));
    f.store
        .set_before_next_commit_hook_for_test(|| Err(G4Error::DurableStateIo));
    assert!(matches!(
        f.store.apply_managed_admin_v04(&proof, now()),
        Err(G4Error::DurableStateIo)
    ));
    assert!(f.store.continuation_storage_v04(task()).is_err());
    assert_eq!(f.store.current_head, head);
    f.store.apply_managed_admin_v04(&proof, now()).unwrap();
}

#[test]
fn managed_admin_reenrollment_preserves_actual_g7_usage_and_revoked_root() {
    let mut f = Fixture::build(true);
    let c = enroll(&f, 60);
    let proof = verified(&c);
    let receipt = f.store.apply_managed_admin_v04(&proof, now()).unwrap();
    let mut input = f.input(40, 1, 1);
    input.request = input.request.clone().with_continuation_resource(
        f.store
            .issue_managed_resource_evidence_v04(
                task(),
                input.request.matched.content(),
                f.managed_keys[0],
                &resource_key(),
                now(),
            )
            .unwrap(),
    );
    f.prepare(&input).unwrap();
    let mut fresh = c.clone();
    fresh.request = [61; 32];
    f.store
        .apply_managed_admin_v04(&verified(&fresh), now())
        .unwrap();
    assert_eq!(f.usage(), (1, 4));
    f.store.revoke_task_authorization(task()).unwrap();
    let mut f = f.reopen();
    assert_eq!(
        f.store
            .apply_managed_admin_v04(&proof, UnixMillisV2::new(1000))
            .unwrap(),
        receipt
    );
    fresh.request = [62; 32];
    assert!(f
        .store
        .apply_managed_admin_v04(&verified(&fresh), now())
        .is_err());
    assert!(f.store.task_authorization_state(task()).unwrap().revoked());
    assert_eq!(f.usage(), (1, 4));
}

#[test]
fn managed_admin_enrollment_needs_existing_source_and_existing_root() {
    let mut f = Fixture::build_with_storage(false, false, false, false);
    let head = f.store.current_head;
    assert!(f
        .store
        .apply_managed_admin_v04(&verified(&enroll(&f, 60)), now())
        .is_err());
    assert_eq!(f.store.current_head, head);
    assert!(f.store.continuation_storage_v04(task()).is_err());
    let mut f = Fixture::build_with_storage(true, false, false, false);
    f.profile.task = [99; 32];
    f.policy.task = [99; 32];
    f.policy.storage_profile = f.profile.signing_digest().unwrap();
    let head = f.store.current_head;
    assert!(f
        .store
        .apply_managed_admin_v04(&verified(&enroll(&f, 61)), now())
        .is_err());
    assert_eq!(f.store.current_head, head);
}

#[test]
fn managed_admin_owner_independently_rejects_other_store_proof() {
    let mut f = Fixture::build(true);
    let mut c = create(60);
    c.store = [99; 32];
    let proof = VerifiedManagedAdminCommandV04::verify(
        &c.canonical_bytes().unwrap(),
        &admin_key().sign(&c.signing_digest().unwrap()).to_bytes(),
        &admin_key().verifying_key(),
        d(2),
        d(99),
    )
    .unwrap();
    let head = f.store.current_head;
    assert!(f.store.apply_managed_admin_v04(&proof, now()).is_err());
    assert_eq!(f.store.current_head, head);
}

#[test]
fn managed_admin_full_receipt_journal_refuses_new_mutation_but_keeps_replay() {
    let mut f = Fixture::new();
    let p = managed_tests::source_policy();
    let c = command(
        60,
        ManagedAdminOperationV04::RegisterSource {
            signature: admin_key()
                .sign(&p.signing_digest().unwrap())
                .to_bytes()
                .to_vec(),
            policy: p,
        },
    );
    let proof = verified(&c);
    let receipt = f.store.apply_managed_admin_v04(&proof, now()).unwrap();
    // Construct a valid saturated history without 1023 fsyncs. All results are
    // repeated registration observations, not forged object births or grants.
    let mut j = json(&f);
    let entries = j["admin"]["entries"].as_array_mut().unwrap();
    for n in 1..1024u64 {
        let mut e = entries[0].clone();
        let mut id = [0; 32];
        id[..8].copy_from_slice(&n.to_be_bytes());
        e["request"] = serde_json::to_value(id).unwrap();
        e["digest"] = serde_json::to_value(id).unwrap();
        entries.push(e);
    }
    let mut s = f.store.snapshot.clone();
    s.continuations = serde_json::from_value(j).unwrap();
    f.store.commit(s).unwrap();
    let mut f = f.reopen();
    let head = f.store.current_head;
    assert!(f
        .store
        .apply_managed_admin_v04(&verified(&create(61)), now())
        .is_err());
    assert_eq!(f.store.current_head, head);
    assert_eq!(
        json(&f)["managed"]["sources"][0]["objects"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    assert_eq!(
        f.store
            .apply_managed_admin_v04(&proof, UnixMillisV2::new(1000))
            .unwrap(),
        receipt
    );
}

#[test]
fn managed_admin_uncertain_create_recovers_one_receipt_and_one_object() {
    for after in [false, true] {
        let mut f = Fixture::build(true);
        let proof = verified(&create(60));
        f.store.rollback_anchor = Box::new(super::super::continuation_tests::FailAnchor {
            inner: f.anchor.clone(),
            after,
        });
        assert!(matches!(
            f.store.apply_managed_admin_v04(&proof, now()),
            Err(G4Error::DurableCommitUncertain)
        ));
        assert!(f.store.apply_managed_admin_v04(&proof, now()).is_err());
        let mut f = f.reopen();
        let receipt = f.store.apply_managed_admin_v04(&proof, now()).unwrap();
        let head = f.store.current_head;
        assert_eq!(
            f.store.apply_managed_admin_v04(&proof, now()).unwrap(),
            receipt
        );
        assert_eq!(f.store.current_head, head);
        assert_eq!(
            json(&f)["managed"]["sources"][0]["objects"]
                .as_array()
                .unwrap()
                .len(),
            3
        );
        assert_eq!(
            f.store
                .managed_resource_v04(key(&receipt))
                .unwrap()
                .revision,
            1
        );
    }
}

#[test]
fn managed_admin_precommit_failure_never_inserts_resource_or_receipt() {
    let mut f = Fixture::build(true);
    let proof = verified(&create(60));
    let old = f.store.snapshot.continuations.encode().unwrap();
    f.store
        .set_before_next_commit_hook_for_test(|| Err(G4Error::DurableStateIo));
    assert!(f.store.apply_managed_admin_v04(&proof, now()).is_err());
    assert_eq!(f.store.snapshot.continuations.encode().unwrap(), old);
    f.store.apply_managed_admin_v04(&proof, now()).unwrap();
    assert_eq!(
        json(&f)["managed"]["sources"][0]["objects"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
}

#[test]
fn managed_admin_schema_and_corrupt_receipt_links_fail_closed() {
    let mut f = Fixture::build(true);
    f.store
        .apply_managed_admin_v04(&verified(&create(60)), now())
        .unwrap();
    let mut s = f.store.snapshot.clone();
    s.payload_schema = 9;
    assert!(validate_snapshot(&s).is_err());
    for case in 0..3 {
        let mut j = json(&f);
        if case == 0 {
            let duplicate = j["admin"]["entries"][0].clone();
            j["admin"]["entries"]
                .as_array_mut()
                .unwrap()
                .push(duplicate);
        } else if case == 1 {
            j["admin"]["entries"][0]["result"]["resource"]["object"] =
                serde_json::json!([99; 32].to_vec());
        } else {
            j["admin"]["entries"][0]["digest"] = serde_json::json!([0; 32].to_vec());
        }
        let mut s = f.store.snapshot.clone();
        s.continuations = serde_json::from_value(j).unwrap();
        assert!(validate_snapshot(&s).is_err());
    }
}
