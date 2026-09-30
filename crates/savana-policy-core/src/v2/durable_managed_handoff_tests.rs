//! Real durable G7 admission and exact pre-seal guard; no provider/network.
use super::*;
#[path = "durable_managed_admission_tests.rs"]
mod admission_tests;
use savana_kernel_protocol::v2::{
    BusinessFieldRoleV2 as Role, BusinessFieldTypeV2, BusinessFieldV2, BusinessMagnitudeV2,
    BusinessProfileV2, BusinessRequestV2, BusinessValueV2,
};

pub(super) fn business(key: ResourceKey, bytes: &[u8]) -> BusinessRequestV2 {
    let profile = BusinessProfileV2::new(
        ActionCodecProfileV2::FixedJsonPostV1,
        "/copy",
        d(23),
        d(24),
        TaskEffectV2::Update,
        BusinessMagnitudeV2::FixedCount(1),
        vec![
            ("destination", Role::Destination),
            ("payload", Role::Payload),
            ("resource", Role::Resource),
        ]
        .into_iter()
        .map(|(name, role)| BusinessFieldV2::new(name, role, BusinessFieldTypeV2::Text).unwrap())
        .collect(),
    )
    .unwrap();
    BusinessRequestV2::from_fields(
        &profile,
        "copy-1",
        vec![
            (
                "destination".into(),
                BusinessValueV2::Text("user-inbox".into()),
            ),
            (
                "payload".into(),
                BusinessValueV2::Text(std::str::from_utf8(bytes).unwrap().into()),
            ),
            (
                "resource".into(),
                BusinessValueV2::Text(managed_resource_locator_v04(key).unwrap()),
            ),
        ],
    )
    .unwrap()
}

fn prepared(projection: bool) -> (Fixture, Input, KernelPreparedDispatchV2) {
    let mut f = Fixture::build_mode(true, true, projection);
    f.activate().unwrap();
    let mut i = f.input(40, 1, 1);
    let evidence = f
        .store
        .issue_managed_resource_evidence_v04(
            task(),
            i.request.matched.content(),
            f.managed_keys[0],
            &resource_key(),
            now(),
        )
        .unwrap();
    i.request = i.request.with_continuation_resource(evidence);
    let p = f.prepare(&i).unwrap();
    (f, i, p)
}
fn check(f: &Fixture, i: &Input, p: &KernelPreparedDispatchV2) -> Result<(), G4Error> {
    f.store
        .check_managed_execution_handoff_v04(p, i.plaintext.as_ref().unwrap(), d(0x88), now())
}

#[test]
fn managed_handoff_exact_admitted_payload_survives_edit_delete_restart_replay() {
    let (mut f, i, p) = prepared(true);
    assert_eq!(f.store.snapshot.payload_schema, 9);
    check(&f, &i, &p).unwrap();
    let key = f.managed_keys[0];
    f.store
        .update_managed_resource_v04(key, 1, Some(("changed label", b"replacement")), now())
        .unwrap();
    f.store
        .update_managed_resource_v04(key, 2, None, now())
        .unwrap();
    let mut f = f.reopen();
    let head = f.store.current_head;
    check(&f, &i, &p).unwrap();
    let replay = f.prepare(&i).unwrap();
    check(&f, &i, &replay).unwrap();
    assert_eq!(f.store.current_head, head);
    assert_eq!(f.usage(), (1, 4));
    let payload =
        savana_kernel_protocol::v2::decode_task_execution_payload_v2(i.plaintext.as_ref().unwrap())
            .unwrap();
    assert_eq!(payload.request().payload(), "private initial bytes");
    assert!(!i
        .plaintext
        .as_ref()
        .unwrap()
        .windows(17)
        .any(|w| w == b"same display name"));
}

#[test]
fn managed_handoff_requires_explicit_signed_projection() {
    let (f, i, p) = prepared(false);
    assert!(check(&f, &i, &p).is_err());
    assert_eq!(f.store.snapshot.payload_schema, 8);
    // Still privately auditable; audit reads do not grant permission to send.
    assert!(f
        .store
        .managed_execution_snapshot_v04(
            task(),
            p.preparation().execution_nonce(),
            p.preparation().dispatch_core_digest()
        )
        .is_ok());
}

#[test]
fn managed_handoff_binds_exact_plaintext_and_live_g3_node() {
    let (f, i, p) = prepared(true);
    let head = f.store.current_head;
    let bytes = i.plaintext.as_ref().unwrap();
    for node in [d(0), d(0x89)] {
        assert!(f
            .store
            .check_managed_execution_handoff_v04(&p, bytes, node, now())
            .is_err());
    }
    let mut changed = bytes.clone();
    changed.push(0);
    assert!(f
        .store
        .check_managed_execution_handoff_v04(&p, &changed, d(0x88), now())
        .is_err());
    assert!(f
        .store
        .check_managed_execution_handoff_v04(&p, &[], d(0x88), now())
        .is_err());
    assert_eq!(f.store.current_head, head);
    assert_eq!(f.usage(), (1, 4));
}

#[test]
fn managed_handoff_rejects_revoked_and_expired_authority() {
    let (mut f, i, p) = prepared(true);
    assert!(f
        .store
        .check_managed_execution_handoff_v04(
            &p,
            i.plaintext.as_ref().unwrap(),
            d(0x88),
            UnixMillisV2::new(1000)
        )
        .is_err());
    f.store.revoke_task_authorization(task()).unwrap();
    assert!(check(&f, &i, &p).is_err());
    let f = f.reopen();
    assert!(check(&f, &i, &p).is_err());
}

#[test]
fn managed_handoff_projection_is_signed_and_old_encoding_stays_unchanged() {
    let mut source = managed_tests::source_policy();
    let old = serde_json::to_vec(&source).unwrap();
    assert!(!String::from_utf8(old.clone())
        .unwrap()
        .contains("execution_projection"));
    let sig = admin_key()
        .sign(&source.signing_digest().unwrap())
        .to_bytes();
    source.execution_projection = Some(ManagedInputProjectionV04::Utf8PayloadV1);
    assert!(VerifiedManagedSourceV04::verify(
        &serde_json::to_vec(&source).unwrap(),
        &sig,
        &admin_key().verifying_key(),
        d(2),
        now()
    )
    .is_err());
    let mut json = serde_json::to_value(&source).unwrap();
    json["execution_projection"] = "raw_everything".into();
    assert!(serde_json::from_value::<ManagedSourcePolicyV04>(json).is_err());
}

#[test]
fn managed_handoff_new_policy_cannot_be_disguised_as_old_snapshot() {
    let (f, _, _) = prepared(true);
    for schema in [7, 8] {
        let mut s = f.store.snapshot.clone();
        s.payload_schema = schema;
        assert!(validate_snapshot(&s).is_err());
    }
}

#[test]
fn managed_handoff_rejects_payload_not_equal_to_admitted_source() {
    for bytes in [
        b"replacement".as_slice(),
        b"private initial bytessame display name",
    ] {
        let mut f = Fixture::build_mode(true, true, true);
        f.activate().unwrap();
        let mut i = f.input(40, 1, 1);
        let request = business(f.managed_keys[0], bytes);
        // Even a canonical, fully committed request must match source bytes.
        i.request = task_request(
            &f.store,
            task(),
            1,
            1,
            request.payload_digest(),
            i.request.matched.content().provenance_digest(),
            d(6),
        );
        i.plaintext = Some(
            savana_kernel_protocol::v2::encode_task_execution_payload_v2(
                &savana_kernel_protocol::v2::TaskExecutionPayloadV2::new(
                    i.request.matched.content().clone(),
                    request,
                )
                .unwrap(),
            )
            .unwrap(),
        );
        let evidence = f
            .store
            .issue_managed_resource_evidence_v04(
                task(),
                i.request.matched.content(),
                f.managed_keys[0],
                &resource_key(),
                now(),
            )
            .unwrap();
        i.request = i.request.with_continuation_resource(evidence);
        let p = f.prepare(&i).unwrap();
        assert!(check(&f, &i, &p).is_err());
        // This is a post-admission guard: rejection never refunds stable usage.
        assert_eq!(f.usage(), (1, 4));
    }
}

#[test]
fn managed_handoff_rejects_terminal_journal_and_foreign_preparation() {
    let (mut f, i, p) = prepared(true);
    let (_, _, foreign) = prepared(true);
    assert!(check(&f, &i, &foreign).is_err());
    // Test seam for an already verified terminal receipt, not a live executor.
    f.store
        .reconcile_tool_dispatch_with_outcome(
            VerifiedExecutorDispositionV2 {
                execution_nonce: p.preparation().execution_nonce(),
                dispatch_core_digest: p.preparation().dispatch_core_digest(),
                dispatch_subject_digest: p.preparation().dispatch_subject_digest(),
                evidence_digest: d(0x90),
                disposition: AuthenticatedEffectDispositionV2::failed_no_effect_for_test(),
            },
            true,
        )
        .unwrap();
    assert!(check(&f, &i, &p).is_err());
    let f = f.reopen();
    assert!(check(&f, &i, &p).is_err());
    assert_eq!(f.usage(), (1, 4));
}

#[test]
fn managed_handoff_legacy_unpinned_history_never_captures_current_data() {
    let (mut f, i, p) = prepared(true);
    let mut json: serde_json::Value =
        serde_json::from_slice(&f.store.snapshot.continuations.encode().unwrap()).unwrap();
    json["records"][0]["dispatch"]
        .as_object_mut()
        .unwrap()
        .remove("snapshot_start");
    json["records"][0]["dispatch"]["records"][0]
        .as_object_mut()
        .unwrap()
        .remove("snapshot");
    let mut s = f.store.snapshot.clone();
    s.continuations = serde_json::from_value(json).unwrap();
    validate_snapshot(&s).unwrap();
    f.store.commit(s).unwrap();
    let f = f.reopen();
    assert!(check(&f, &i, &p).is_err());
    assert_eq!(f.usage(), (1, 4));
}
