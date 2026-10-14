//! Real encrypted G4 owner/reopen tests; no cloud or external business effect.
use super::*;
use crate::v2::durable_tests::{signed_task, task_clause, task_store};
use crate::v2::{ContinuationStorageProfileV04, VerifiedContinuationStorageV04};
use ed25519_dalek::{Signer, SigningKey};
use savana_continuation_core::ledger::{Charge, DomainLimit, Reservation, ResourceKey};
use savana_continuation_core::observation::{PinnedInput, Projection, Slot};
use savana_kernel_protocol::v2::{
    ActionAlternativeV2, ActionCodecProfileV2, MagnitudeUnitV2, TaskEffectV2,
};

fn task() -> DurableTaskIdV2 {
    DurableTaskIdV2::new([4; 32])
}
fn now() -> UnixMillisV2 {
    UnixMillisV2::new(10)
}
fn auth(revision: u64) -> VerifiedTaskAuthorizationV2 {
    let action = ActionAlternativeV2::new(
        Digest32V2::new([7; 32]),
        ActionCodecProfileV2::FixedJsonPostV1,
        TaskEffectV2::Update,
        Digest32V2::new([8; 32]),
        Digest32V2::new([9; 32]),
        Digest32V2::new([10; 32]),
        MagnitudeUnitV2::Count,
    )
    .unwrap();
    signed_task(
        task(),
        revision,
        vec![task_clause(1, action, 2, 2, vec![], false)],
    )
}
fn profile() -> ContinuationStorageProfileV04 {
    ContinuationStorageProfileV04 {
        schema: 1,
        installation: [2; 32],
        task: [4; 32],
        parent_authorization: *auth(1).digest().as_bytes(),
        not_before: 1,
        expires_at: 1000,
        observer_scope: [5; 32],
        renderer: [6; 32],
        domains: vec![DomainLimit {
            domain: 1,
            total: 2,
            per_resource: 1,
        }],
        max_executions: 2,
        slots: vec![
            Slot {
                id: 1,
                logical_round: 1,
                projection: Projection::PublicConstant(
                    b"continuation-private-storage-fixture".to_vec(),
                ),
            },
            Slot {
                id: 2,
                logical_round: 3,
                projection: Projection::DeclaredBoolean,
            },
        ],
    }
}
fn verified(p: ContinuationStorageProfileV04) -> VerifiedContinuationStorageV04 {
    let key = SigningKey::from_bytes(&[0x21; 32]);
    let signature = key.sign(&p.signing_digest().unwrap()).to_bytes();
    VerifiedContinuationStorageV04::verify(
        &serde_json::to_vec(&p).unwrap(),
        &signature,
        &key.verifying_key(),
        &auth(1),
        now(),
    )
    .unwrap()
}
fn reserve(id: u8, object: u8) -> ContinuationStorageUpdateV04 {
    ContinuationStorageUpdateV04::RecordReservation(Reservation {
        execution: [id; 32],
        request_binding: [12; 32],
        resource: ResourceKey {
            source: [13; 32],
            namespace: [14; 32],
            object: [object; 32],
            incarnation: 0,
        },
        charges: vec![Charge {
            domain: 1,
            amount: 1,
        }],
    })
}
fn install(store: &mut DurableG4StateV2) {
    store.install_verified_task_authorization(auth(1)).unwrap();
    store
        .install_continuation_storage_v04(verified(profile()), now())
        .unwrap();
}

#[test]
fn signed_profile_requires_exact_issuer_parent_and_window() {
    let p = profile();
    let key = SigningKey::from_bytes(&[0x21; 32]);
    let bytes = serde_json::to_vec(&p).unwrap();
    let sig = key.sign(&p.signing_digest().unwrap()).to_bytes();
    let wrong = SigningKey::from_bytes(&[0x22; 32]);
    assert!(VerifiedContinuationStorageV04::verify(
        &bytes,
        &sig,
        &wrong.verifying_key(),
        &auth(1),
        now()
    )
    .is_err());
    assert!(VerifiedContinuationStorageV04::verify(
        &bytes,
        &sig,
        &key.verifying_key(),
        &auth(2),
        now()
    )
    .is_err());
    assert!(VerifiedContinuationStorageV04::verify(
        &bytes,
        &sig,
        &key.verifying_key(),
        &auth(1),
        UnixMillisV2::new(1000)
    )
    .is_err());
    let mut trailing = bytes.clone();
    trailing.push(b' ');
    assert!(VerifiedContinuationStorageV04::verify(
        &trailing,
        &sig,
        &key.verifying_key(),
        &auth(1),
        now()
    )
    .is_err());
    let mut changed = p;
    changed.domains[0].total = 3;
    assert!(VerifiedContinuationStorageV04::verify(
        &serde_json::to_vec(&changed).unwrap(),
        &sig,
        &key.verifying_key(),
        &auth(1),
        now()
    )
    .is_err());
}

#[test]
fn install_needs_current_installed_authority_and_never_replaces_profile() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(STATE_FILE_NAME);
    let mut store = task_store(
        &path,
        [0x81; 32],
        TestRollbackProtectedStateAnchorV2::default(),
    );
    assert!(store
        .install_continuation_storage_v04(verified(profile()), now())
        .is_err());
    install(&mut store);
    let head = store.current_head;
    store
        .install_continuation_storage_v04(verified(profile()), now())
        .unwrap();
    assert_eq!(store.current_head, head);
    let mut changed = profile();
    changed.domains[0].total = 3;
    assert!(store
        .install_continuation_storage_v04(verified(changed), now())
        .is_err());
    assert_eq!(store.current_head, head);
}

#[test]
fn encrypted_owner_reopen_keeps_charges_original_ids_and_pinned_inputs() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(STATE_FILE_NAME);
    let anchor = TestRollbackProtectedStateAnchorV2::default();
    let mut store = task_store(&path, [0x81; 32], anchor.clone());
    install(&mut store);
    store
        .update_continuation_storage_v04(
            task(),
            1,
            vec![
                reserve(20, 30),
                ContinuationStorageUpdateV04::Pin {
                    slot: 2,
                    logical_round: 3,
                    input: PinnedInput::Boolean {
                        cut: [16; 32],
                        value: true,
                    },
                },
            ],
            now(),
        )
        .unwrap();
    let bytes = fs::read(&path).unwrap();
    assert!(!bytes
        .windows(b"continuation-private-storage-fixture".len())
        .any(|w| w == b"continuation-private-storage-fixture"));
    drop(store);
    let mut reopened = task_store(&path, [0x81; 32], anchor);
    let state = reopened.continuation_storage_v04(task()).unwrap();
    assert_eq!(state.revision, 2);
    assert_eq!(state.ledger.usage(1), Some(1));
    assert!(state.ledger.reservation(&[20; 32]).is_some());
    assert_eq!(state.observations.charged_slots(), 1);
    assert!(state
        .observations
        .frozen_bytes_for_release_check(2)
        .is_none());
    reopened
        .update_continuation_storage_v04(
            task(),
            2,
            vec![ContinuationStorageUpdateV04::Freeze { slot: 2 }],
            now(),
        )
        .unwrap();
    let state = reopened.continuation_storage_v04(task()).unwrap();
    assert_eq!(
        state.observations.frozen_bytes_for_release_check(2),
        Some(b"true".as_slice())
    );
    assert!(reopened
        .update_continuation_storage_v04(task(), 3, vec![reserve(21, 30)], now())
        .is_err());
    assert_eq!(
        reopened
            .continuation_storage_v04(task())
            .unwrap()
            .ledger
            .usage(1),
        Some(1)
    );
}

#[test]
fn invalid_batch_and_before_commit_failure_do_not_partially_apply() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(STATE_FILE_NAME);
    let anchor = TestRollbackProtectedStateAnchorV2::default();
    let mut store = task_store(&path, [0x81; 32], anchor.clone());
    install(&mut store);
    let head = store.current_head;
    assert!(store
        .update_continuation_storage_v04(
            task(),
            1,
            vec![
                reserve(20, 30),
                ContinuationStorageUpdateV04::Freeze { slot: 2 }
            ],
            now()
        )
        .is_err());
    assert_eq!(store.current_head, head);
    store.set_before_next_commit_hook_for_test(|| Err(G4Error::DurableStateIo));
    assert_eq!(
        store.update_continuation_storage_v04(task(), 1, vec![reserve(20, 30)], now()),
        Err(G4Error::DurableStateIo)
    );
    assert_eq!(anchor.current_head().unwrap(), head);
    drop(store);
    let reopened = task_store(&path, [0x81; 32], anchor);
    assert_eq!(
        reopened
            .continuation_storage_v04(task())
            .unwrap()
            .ledger
            .usage(1),
        Some(0)
    );
}

#[test]
fn replay_is_uncharged_but_stale_revision_and_repin_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(STATE_FILE_NAME);
    let mut store = task_store(
        &path,
        [0x81; 32],
        TestRollbackProtectedStateAnchorV2::default(),
    );
    install(&mut store);
    store
        .update_continuation_storage_v04(task(), 1, vec![reserve(20, 30)], now())
        .unwrap();
    let head = store.current_head;
    assert!(store
        .update_continuation_storage_v04(task(), 1, vec![reserve(21, 31)], now())
        .is_err());
    store
        .update_continuation_storage_v04(task(), 2, vec![reserve(20, 30)], now())
        .unwrap();
    assert_eq!(store.current_head, head);
    store
        .update_continuation_storage_v04(
            task(),
            2,
            vec![ContinuationStorageUpdateV04::Pin {
                slot: 2,
                logical_round: 3,
                input: PinnedInput::Boolean {
                    cut: [16; 32],
                    value: false,
                },
            }],
            now(),
        )
        .unwrap();
    assert!(store
        .update_continuation_storage_v04(
            task(),
            3,
            vec![ContinuationStorageUpdateV04::Pin {
                slot: 2,
                logical_round: 3,
                input: PinnedInput::Boolean {
                    cut: [17; 32],
                    value: true
                }
            }],
            now()
        )
        .is_err());
}

#[test]
fn expiry_revocation_and_amendment_stop_updates_without_erasing_history() {
    for case in 0..3 {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(STATE_FILE_NAME);
        let anchor = TestRollbackProtectedStateAnchorV2::default();
        let mut store = task_store(&path, [0x81; 32], anchor.clone());
        install(&mut store);
        store
            .update_continuation_storage_v04(task(), 1, vec![reserve(20, 30)], now())
            .unwrap();
        let time = match case {
            0 => UnixMillisV2::new(1000),
            1 => {
                store.revoke_task_authorization(task()).unwrap();
                now()
            }
            _ => {
                store.install_verified_task_authorization(auth(2)).unwrap();
                now()
            }
        };
        assert!(store
            .update_continuation_storage_v04(task(), 2, vec![reserve(21, 31)], time)
            .is_err());
        drop(store);
        let reopened = task_store(&path, [0x81; 32], anchor);
        assert_eq!(
            reopened
                .continuation_storage_v04(task())
                .unwrap()
                .ledger
                .usage(1),
            Some(1)
        );
    }
}

#[test]
fn old_snapshot_with_current_anchor_is_rejected_not_reinitialized() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(STATE_FILE_NAME);
    let anchor = TestRollbackProtectedStateAnchorV2::default();
    let mut store = task_store(&path, [0x81; 32], anchor.clone());
    install(&mut store);
    let old = fs::read(&path).unwrap();
    store
        .update_continuation_storage_v04(task(), 1, vec![reserve(20, 30)], now())
        .unwrap();
    drop(store);
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

pub(super) struct FailAnchor {
    pub(super) inner: TestRollbackProtectedStateAnchorV2,
    pub(super) after: bool,
}
impl RollbackProtectedStateAnchorV2 for FailAnchor {
    fn current_head(&self) -> Result<RollbackProtectedStateHeadV2, G4Error> {
        self.inner.current_head()
    }
    fn compare_and_advance(
        &mut self,
        expected: RollbackProtectedStateHeadV2,
        next: RollbackProtectedStateHeadV2,
    ) -> Result<(), G4Error> {
        if self.after {
            self.inner.compare_and_advance(expected, next)?;
        }
        Err(G4Error::DurableStateIo)
    }
}
#[test]
fn uncertain_anchor_commit_poison_then_reopen_recovers_exact_original_state() {
    for after in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(STATE_FILE_NAME);
        let anchor = TestRollbackProtectedStateAnchorV2::default();
        let mut store = task_store(&path, [0x81; 32], anchor.clone());
        install(&mut store);
        store.rollback_anchor = Box::new(FailAnchor {
            inner: anchor.clone(),
            after,
        });
        assert_eq!(
            store.update_continuation_storage_v04(task(), 1, vec![reserve(20, 30)], now()),
            Err(G4Error::DurableCommitUncertain)
        );
        assert!(store.continuation_storage_v04(task()).is_err());
        drop(store);
        let reopened = task_store(&path, [0x81; 32], anchor);
        let state = reopened.continuation_storage_v04(task()).unwrap();
        assert_eq!((state.revision, state.ledger.usage(1)), (2, Some(1)));
        assert!(state.ledger.reservation(&[20; 32]).is_some());
    }
}

#[test]
fn schema_four_remains_four_until_explicit_install_and_decodes_back_canonically() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(STATE_FILE_NAME);
    let mut store = task_store(
        &path,
        [0x81; 32],
        TestRollbackProtectedStateAnchorV2::default(),
    );
    store.install_verified_task_authorization(auth(1)).unwrap();
    assert_eq!(store.snapshot.payload_schema, 4);
    let old = encode_snapshot_payload(&store.snapshot).unwrap();
    assert_eq!(
        *encode_snapshot_payload(&decode_snapshot_payload(&old).unwrap()).unwrap(),
        *old
    );
    store
        .install_continuation_storage_v04(verified(profile()), now())
        .unwrap();
    assert_eq!(store.snapshot.payload_schema, 5);
    let mut wrong = store.snapshot.clone();
    wrong.payload_schema = 4;
    assert!(validate_snapshot(&wrong).is_err());
    let mut missing = store.snapshot.clone();
    missing.tasks = Default::default();
    assert!(validate_snapshot(&missing).is_err());
}

#[test]
fn storage_profile_bounds_are_checked_before_installation() {
    let p = profile();
    let mut cases = Vec::new();
    let mut changed = p.clone();
    changed.max_executions = 257;
    cases.push(changed);
    let mut changed = p.clone();
    changed.max_executions = 0;
    cases.push(changed);
    let mut changed = p.clone();
    changed.domains = (0..9)
        .map(|domain| DomainLimit {
            domain,
            total: 2,
            per_resource: 1,
        })
        .collect();
    cases.push(changed);
    let mut changed = p.clone();
    changed.slots = (0..33)
        .map(|id| Slot {
            id,
            logical_round: 1,
            projection: Projection::PublicConstant(vec![]),
        })
        .collect();
    cases.push(changed);
    let mut changed = p.clone();
    changed.slots[0].projection = Projection::PublicConstant(vec![0; 4097]);
    cases.push(changed);
    let mut changed = p.clone();
    changed.observer_scope = [0; 32];
    cases.push(changed);
    let mut changed = p;
    changed.not_before = changed.expires_at;
    cases.push(changed);
    for invalid in cases {
        assert!(invalid.signing_digest().is_err());
    }
}

#[test]
fn malformed_persisted_continuation_bytes_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(STATE_FILE_NAME);
    let mut store = task_store(
        &path,
        [0x81; 32],
        TestRollbackProtectedStateAnchorV2::default(),
    );
    install(&mut store);
    let bytes = store.snapshot.continuations.encode().unwrap();
    let mut trailing = bytes.clone();
    trailing.push(b' ');
    assert!(ContinuationTableV04::decode(&trailing).is_err());
    assert!(ContinuationTableV04::decode(b"{\"records\":[],\"ignored\":true}").is_err());
    assert!(ContinuationTableV04::decode(&vec![0; 8 * 1024 * 1024 + 1]).is_err());
    // Canonically encode using the trusted type, then independently validate the
    // nested ledger. A decoded JSON document is never sufficient for reopening.
    let encoded_ledger = String::from_utf8(
        store
            .continuation_storage_v04(task())
            .unwrap()
            .ledger
            .snapshot()
            .unwrap(),
    )
    .unwrap();
    let old = serde_json::to_string(encoded_ledger.as_bytes()).unwrap();
    let corrupt = encoded_ledger.replace("\"max_executions\":2", "\"max_executions\":3");
    assert_ne!(encoded_ledger, corrupt);
    let new = serde_json::to_string(corrupt.as_bytes()).unwrap();
    let text = String::from_utf8(bytes).unwrap();
    let tampered = text.replace(&old, &new);
    assert_ne!(text, tampered);
    let table = ContinuationTableV04::decode(tampered.as_bytes()).unwrap();
    assert!(table.validate(&store.snapshot.tasks).is_err());
}
