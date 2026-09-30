//! First-party source tests through the real encrypted owner and G7 path.
use super::*;

#[path = "durable_managed_execution_tests.rs"]
mod execution_tests;

pub(super) fn source_policy() -> ManagedSourcePolicyV04 {
    ManagedSourcePolicyV04 {
        schema: 1,
        installation: [2; 32],
        source: [33; 32],
        namespace: [34; 32],
        target: [23; 32],
        resource_issuer: resource_key().verifying_key().to_bytes(),
        not_before: 1,
        expires_at: 1000,
        max_objects: 4,
        max_object_bytes: 1024,
        max_mutations: 16,
        execution_projection: None,
    }
}
pub(super) fn verified_source(p: ManagedSourcePolicyV04) -> VerifiedManagedSourceV04 {
    VerifiedManagedSourceV04::verify(
        &serde_json::to_vec(&p).unwrap(),
        &admin_key().sign(&p.signing_digest().unwrap()).to_bytes(),
        &admin_key().verifying_key(),
        d(2),
        now(),
    )
    .unwrap()
}
fn attach(f: &Fixture, input: &mut Input, key: ResourceKey) {
    let evidence = f
        .store
        .issue_managed_resource_evidence_v04(
            task(),
            input.request.matched.content(),
            key,
            &resource_key(),
            now(),
        )
        .unwrap();
    input.request = input.request.clone().with_continuation_resource(evidence);
}

#[test]
fn managed_rename_content_and_delete_keep_identity_and_lifetime_capacity() {
    let mut f = Fixture::build(true);
    let key = f.managed_keys[0];
    assert_ne!(key, f.managed_keys[1]); // same display label, different births
    let selector = managed_resource_locator_v04(key).unwrap();
    f.store
        .update_managed_resource_v04(key, 1, Some(("renamed", b"new private bytes")), now())
        .unwrap();
    let v = f.store.managed_resource_v04(key).unwrap();
    assert_eq!(v.revision, 2);
    assert_eq!(v.content, b"new private bytes");
    assert_eq!(managed_resource_locator_v04(v.key).unwrap(), selector);
    let head = f.store.current_head;
    assert!(f
        .store
        .update_managed_resource_v04(key, 1, None, now())
        .is_err());
    f.store
        .update_managed_resource_v04(key, 2, Some(("renamed", b"new private bytes")), now())
        .unwrap();
    assert_eq!(f.store.current_head, head); // idempotent source edit
    f.store
        .update_managed_resource_v04(key, 2, None, now())
        .unwrap();
    let head = f.store.current_head;
    f.store
        .update_managed_resource_v04(key, 3, None, now())
        .unwrap();
    assert_eq!(f.store.current_head, head);
    assert!(f
        .store
        .update_managed_resource_v04(key, 3, Some(("resurrect", b"x")), now())
        .is_err());
    let mut f = f.reopen();
    let v = f.store.managed_resource_v04(key).unwrap();
    assert!(v.deleted);
    assert!(v.content.is_empty());
    assert!(v.label.is_empty());
    assert_eq!(v.revision, 3);
    for _ in 0..2 {
        let fresh = f
            .store
            .create_managed_resource_v04([33; 32], [34; 32], "renamed", b"x", now())
            .unwrap();
        assert_ne!(fresh, key);
    }
    assert!(f
        .store
        .create_managed_resource_v04([33; 32], [34; 32], "renamed", b"x", now())
        .is_err());
}

#[test]
fn managed_source_signature_scope_bounds_and_canonical_encoding() {
    let p = source_policy();
    let bytes = serde_json::to_vec(&p).unwrap();
    let sig = admin_key().sign(&p.signing_digest().unwrap()).to_bytes();
    assert!(VerifiedManagedSourceV04::verify(
        &bytes,
        &sig,
        &resource_key().verifying_key(),
        d(2),
        now()
    )
    .is_err());
    assert!(VerifiedManagedSourceV04::verify(
        &bytes,
        &sig,
        &admin_key().verifying_key(),
        d(3),
        now()
    )
    .is_err());
    assert!(VerifiedManagedSourceV04::verify(
        &bytes,
        &sig,
        &admin_key().verifying_key(),
        d(2),
        UnixMillisV2::new(1000)
    )
    .is_err());
    let mut alternate = bytes.clone();
    alternate.push(b' ');
    assert!(VerifiedManagedSourceV04::verify(
        &alternate,
        &sig,
        &admin_key().verifying_key(),
        d(2),
        now()
    )
    .is_err());
    let mut unknown: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    unknown["allow_reuse"] = true.into();
    assert!(VerifiedManagedSourceV04::verify(
        &serde_json::to_vec(&unknown).unwrap(),
        &sig,
        &admin_key().verifying_key(),
        d(2),
        now()
    )
    .is_err());
    for change in 0..4 {
        let mut p = p.clone();
        match change {
            0 => p.max_objects = 1025,
            1 => p.max_object_bytes = 32769,
            2 => p.max_mutations = 65537,
            _ => p.source = [0; 32],
        }
        assert!(p.signing_digest().is_err());
    }
}

#[test]
fn managed_source_cannot_reinterpret_existing_dispatch_policy_or_change_pins() {
    let mut f = Fixture::new();
    f.activate().unwrap();
    let head = f.store.current_head;
    assert!(f
        .store
        .install_managed_source_v04(verified_source(source_policy()), now())
        .is_err());
    assert_eq!(head, f.store.current_head);
    assert_eq!(f.store.snapshot.payload_schema, 6);
    let mut f = Fixture::build(true);
    f.activate().unwrap();
    let head = f.store.current_head;
    f.store
        .install_managed_source_v04(verified_source(source_policy()), now())
        .unwrap();
    assert_eq!(head, f.store.current_head);
    let mut p = source_policy();
    p.target = [99; 32];
    assert!(f
        .store
        .install_managed_source_v04(verified_source(p), now())
        .is_err());
    let mut f = Fixture::build(true);
    f.policy.resource_issuer = admin_key().verifying_key().to_bytes();
    assert!(f.activate().is_err());
}

#[test]
fn managed_source_rechecks_owner_installation() {
    let mut f = Fixture::new();
    let mut p = source_policy();
    p.installation = [99; 32];
    let verified = VerifiedManagedSourceV04::verify(
        &serde_json::to_vec(&p).unwrap(),
        &admin_key().sign(&p.signing_digest().unwrap()).to_bytes(),
        &admin_key().verifying_key(),
        d(99),
        now(),
    )
    .unwrap();
    assert!(f.store.install_managed_source_v04(verified, now()).is_err());
}

#[test]
fn managed_g7_stale_facts_fail_without_consumption_then_current_fact_succeeds() {
    let mut f = Fixture::build(true);
    f.activate().unwrap();
    let key = f.managed_keys[0];
    let mut input = f.input(40, 1, 1);
    attach(&f, &mut input, key);
    f.store
        .update_managed_resource_v04(key, 1, Some(("renamed", b"v2")), now())
        .unwrap();
    let head = f.store.current_head;
    assert!(f.prepare(&input).is_err());
    assert_eq!(f.store.current_head, head);
    assert_eq!(f.usage(), (0, 0));
    attach(&f, &mut input, key);
    f.prepare(&input).unwrap();
    assert_eq!(f.usage(), (1, 4));
}

#[test]
fn managed_g7_replay_after_edits_and_deletion_preserves_old_id_and_charge() {
    let mut f = Fixture::build(true);
    f.activate().unwrap();
    let key = f.managed_keys[0];
    let mut input = f.input(40, 1, 1);
    attach(&f, &mut input, key);
    f.prepare(&input).unwrap();
    let execution = f
        .store
        .continuation_storage_v04(task())
        .unwrap()
        .ledger
        .snapshot()
        .unwrap();
    f.store
        .update_managed_resource_v04(key, 1, Some(("changed", b"v2")), now())
        .unwrap();
    let mut next = f.input(41, 1, 1);
    attach(&f, &mut next, key);
    assert!(f.prepare(&next).is_err()); // fresh fact, same stable per-resource budget
    f.store
        .update_managed_resource_v04(key, 2, None, now())
        .unwrap();
    let mut f = f.reopen();
    let head = f.store.current_head;
    assert_eq!(
        f.prepare(&input).unwrap().preparation().kind(),
        DispatchPreparationKindV2::Replay
    );
    assert_eq!(f.store.current_head, head);
    assert_eq!(f.usage(), (1, 4));
    assert_eq!(
        f.store
            .continuation_storage_v04(task())
            .unwrap()
            .ledger
            .snapshot()
            .unwrap(),
        execution
    );
    assert!(f
        .store
        .issue_managed_resource_evidence_v04(
            task(),
            input.request.matched.content(),
            key,
            &resource_key(),
            now()
        )
        .is_err());
}

#[test]
fn managed_g7_deleted_pending_fact_and_wrong_selector_or_issuer_are_rejected() {
    let mut f = Fixture::build(true);
    f.activate().unwrap();
    let key = f.managed_keys[0];
    let mut input = f.input(40, 1, 1);
    assert!(f
        .store
        .issue_managed_resource_evidence_v04(
            task(),
            input.request.matched.content(),
            f.managed_keys[1],
            &resource_key(),
            now()
        )
        .is_err());
    assert!(f
        .store
        .issue_managed_resource_evidence_v04(
            task(),
            input.request.matched.content(),
            key,
            &admin_key(),
            now()
        )
        .is_err());
    attach(&f, &mut input, key);
    f.store
        .update_managed_resource_v04(key, 1, None, now())
        .unwrap();
    assert!(f.prepare(&input).is_err());
    assert_eq!(f.usage(), (0, 0));
}

#[test]
fn managed_g7_valid_signature_does_not_bypass_catalog_revision_or_selector() {
    let mut f = Fixture::build(true);
    f.activate().unwrap();
    let key = f.managed_keys[0];
    let mut input = f.input(40, 1, 1);
    for change in 0..5 {
        let mut fact = f.fact(&input, 50);
        fact.resource = key;
        fact.managed_revision = Some(1);
        match change {
            0 => fact.managed_revision = None,
            1 => fact.managed_revision = Some(2),
            2 => fact.resource = f.managed_keys[1],
            3 => fact.resource.incarnation = 1,
            _ => fact.resource.object = [99; 32],
        }
        input.request = input
            .request
            .clone()
            .with_continuation_resource(sign_fact(fact, resource_key()));
        assert!(f.prepare(&input).is_err());
        assert_eq!(f.usage(), (0, 0));
    }
    attach(&f, &mut input, key);
    f.prepare(&input).unwrap();
}

#[test]
fn managed_revision_is_not_accepted_for_unregistered_external_source() {
    let mut f = Fixture::new();
    f.activate().unwrap();
    let mut input = f.input(40, 1, 1);
    let mut fact = f.fact(&input, 50);
    fact.managed_revision = Some(1);
    input.request = input
        .request
        .clone()
        .with_continuation_resource(sign_fact(fact, resource_key()));
    assert!(f.prepare(&input).is_err());
    assert_eq!(f.usage(), (0, 0));
}

#[test]
fn managed_encrypted_restart_schema_and_snapshot_invariants() {
    let mut f = Fixture::build(true);
    f.activate().unwrap();
    assert_eq!(f.store.snapshot.payload_schema, 7);
    let bytes = std::fs::read(f.dir.path().join(STATE_FILE_NAME)).unwrap();
    assert!(!bytes
        .windows(b"private initial bytes".len())
        .any(|w| w == b"private initial bytes"));
    let encoded = encode_snapshot_payload(&f.store.snapshot).unwrap();
    let decoded = decode_snapshot_payload(&encoded).unwrap();
    validate_snapshot(&decoded).unwrap();
    assert_eq!(*encode_snapshot_payload(&decoded).unwrap(), *encoded);
    let mut corrupt = f.store.snapshot.clone();
    corrupt.payload_schema = 6;
    assert!(validate_snapshot(&corrupt).is_err());
    let mut json: serde_json::Value =
        serde_json::from_slice(&f.store.snapshot.continuations.encode().unwrap()).unwrap();
    json["managed"]["sources"][0]["objects"][0]["revision"] = 12.into();
    corrupt = f.store.snapshot.clone();
    corrupt.continuations = serde_json::from_value(json).unwrap();
    assert!(validate_snapshot(&corrupt).is_err());
    let f = f.reopen();
    assert_eq!(
        f.store
            .managed_resource_v04(f.managed_keys[0])
            .unwrap()
            .content,
        b"private initial bytes"
    );
}

#[test]
fn managed_precommit_failure_does_not_expose_new_object_or_apply_edit() {
    let mut f = Fixture::build(true);
    let key = f.managed_keys[0];
    let before = f.store.snapshot.continuations.encode().unwrap();
    let head = f.store.current_head;
    f.store
        .set_before_next_commit_hook_for_test(|| Err(G4Error::DurableStateIo));
    assert!(f
        .store
        .create_managed_resource_v04([33; 32], [34; 32], "new", b"secret", now())
        .is_err());
    assert_eq!(f.store.current_head, head);
    assert_eq!(f.store.snapshot.continuations.encode().unwrap(), before);
    f.store
        .set_before_next_commit_hook_for_test(|| Err(G4Error::DurableStateIo));
    assert!(f
        .store
        .update_managed_resource_v04(key, 1, None, now())
        .is_err());
    assert_eq!(f.store.current_head, head);
    assert!(!f.store.managed_resource_v04(key).unwrap().deleted);
}

#[test]
fn managed_uncertain_commit_fails_closed_and_recovers_original_identity() {
    for after in [false, true] {
        let mut f = Fixture::build(true);
        let key = f.managed_keys[0];
        f.store.rollback_anchor = Box::new(super::super::continuation_tests::FailAnchor {
            inner: f.anchor.clone(),
            after,
        });
        assert!(matches!(
            f.store
                .update_managed_resource_v04(key, 1, Some(("renamed", b"next")), now()),
            Err(G4Error::DurableCommitUncertain)
        ));
        assert!(f.store.managed_resource_v04(key).is_err());
        let f = f.reopen();
        let v = f.store.managed_resource_v04(key).unwrap();
        assert_eq!(v.revision, 2);
        assert_eq!(v.content, b"next");
        assert_eq!(v.key, key);
    }
}

#[test]
fn managed_mutation_budget_and_size_window_limits_do_not_reset_on_delete() {
    let mut f = Fixture::new();
    let mut p = source_policy();
    p.max_mutations = 2;
    f.store
        .install_managed_source_v04(verified_source(p), now())
        .unwrap();
    let head = f.store.current_head;
    assert!(f
        .store
        .create_managed_resource_v04([33; 32], [34; 32], "bad\nlabel", b"x", now())
        .is_err());
    assert!(f
        .store
        .create_managed_resource_v04([33; 32], [34; 32], "ok", &[0; 1025], now())
        .is_err());
    assert!(f
        .store
        .create_managed_resource_v04([33; 32], [34; 32], "ok", b"x", UnixMillisV2::new(1000))
        .is_err());
    assert_eq!(f.store.current_head, head);
    let key = f
        .store
        .create_managed_resource_v04([33; 32], [34; 32], "ok", b"x", now())
        .unwrap();
    f.store
        .update_managed_resource_v04(key, 1, None, now())
        .unwrap();
    let mut f = f.reopen();
    assert!(f
        .store
        .create_managed_resource_v04([33; 32], [34; 32], "ok", b"x", now())
        .is_err());
}

#[test]
fn managed_old_fact_encoding_omits_absent_revision() {
    let mut f = Fixture::new();
    let input = f.input(40, 1, 1);
    let fact = f.fact(&input, 50);
    let bytes = serde_json::to_vec(&fact).unwrap();
    assert!(!String::from_utf8(bytes.clone())
        .unwrap()
        .contains("managed_revision"));
    let copy: ContinuationResourceFactV04 = serde_json::from_slice(&bytes).unwrap();
    assert!(copy.managed_revision.is_none());
    assert_eq!(
        copy.signing_digest().unwrap(),
        fact.signing_digest().unwrap()
    );
    assert!(
        !String::from_utf8(f.store.snapshot.continuations.encode().unwrap())
            .unwrap()
            .contains("managed")
    );
}

#[test]
fn managed_selector_matches_actual_business_codec_not_display_name() {
    use savana_kernel_protocol::v2::{
        BusinessFieldRoleV2 as Role, BusinessFieldTypeV2 as Type, BusinessFieldV2 as Field,
        BusinessMagnitudeV2, BusinessProfileV2, BusinessRequestV2, BusinessValueV2 as Value,
    };
    let f = Fixture::build(true);
    let key = f.managed_keys[0];
    for codec in [
        ActionCodecProfileV2::FixedJsonPostV1,
        ActionCodecProfileV2::McpToolsCallJsonV1,
    ] {
        let operation = if codec == ActionCodecProfileV2::FixedJsonPostV1 {
            "/update"
        } else {
            "update"
        };
        let profile = BusinessProfileV2::new(
            codec,
            operation,
            d(23),
            d(24),
            TaskEffectV2::Update,
            BusinessMagnitudeV2::FixedCount(1),
            vec![
                Field::new("destination", Role::Destination, Type::Text).unwrap(),
                Field::new("payload", Role::Payload, Type::Text).unwrap(),
                Field::new("resource", Role::Resource, Type::Text).unwrap(),
            ],
        )
        .unwrap();
        let request = BusinessRequestV2::from_fields(
            &profile,
            "request-1",
            vec![
                ("destination".into(), Value::Text("local".into())),
                ("payload".into(), Value::Text("private content".into())),
                (
                    "resource".into(),
                    Value::Text(managed_resource_locator_v04(key).unwrap()),
                ),
            ],
        )
        .unwrap();
        assert_eq!(
            request.resource_digest(),
            managed_resource_selector_digest_v04(d(23), key).unwrap()
        );
        assert_ne!(
            request.resource_digest(),
            managed_resource_selector_digest_v04(d(25), key).unwrap()
        );
    }
}
