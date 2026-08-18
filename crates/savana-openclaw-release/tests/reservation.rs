use savana_openclaw_release::{ReleaseReservationStore, ReservationError, VerifiedReleaseRequest};
use std::fs;
use tempfile::tempdir;

const GOLDEN_HEX: &str = include_str!("fixtures/provider-request-v2.hex");

fn golden() -> VerifiedReleaseRequest {
    let text = GOLDEN_HEX.trim().as_bytes();
    let bytes = text
        .chunks_exact(2)
        .map(|pair| {
            let digit = |byte| match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                _ => panic!("valid golden hex digit"),
            };
            (digit(pair[0]) << 4) | digit(pair[1])
        })
        .collect::<Vec<_>>();
    VerifiedReleaseRequest::decode(&bytes).unwrap()
}

#[test]
fn reserve_claim_read_complete_and_reject_duplicate_delivery() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("release.cbor");
    let store = ReleaseReservationStore::open(&path).unwrap();
    let reservation = store.reserve([0x41; 32], 10, 100).unwrap();

    assert_eq!(
        store.reserve([0x42; 32], 10, 100).unwrap_err(),
        ReservationError::Busy
    );
    store.claim_next(11, golden()).unwrap();
    assert_eq!(
        store.read_delivery(&reservation).unwrap().payload(),
        b"released assistant response"
    );
    assert_eq!(
        store.claim_next(12, golden()).unwrap_err(),
        ReservationError::DuplicateDelivery
    );
    store.complete_delivery(&reservation).unwrap();

    let next = store.reserve([0x42; 32], 13, 100).unwrap();
    assert_ne!(reservation, next);
    assert_eq!(
        store.claim_next(14, golden()).unwrap_err(),
        ReservationError::DuplicateDelivery
    );
    assert!(store.is_sealed().unwrap());
}

#[test]
fn timeout_and_indeterminate_seal_durably() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("release.cbor");
    let store = ReleaseReservationStore::open(&path).unwrap();
    store.reserve([0x51; 32], 10, 20).unwrap();
    assert_eq!(
        store.claim_next(21, golden()).unwrap_err(),
        ReservationError::Expired
    );
    drop(store);
    assert!(ReleaseReservationStore::open(&path)
        .unwrap()
        .is_sealed()
        .unwrap());

    ReleaseReservationStore::open(&path)
        .unwrap()
        .reconcile_after_operator_review()
        .unwrap();
    let store = ReleaseReservationStore::open(&path).unwrap();
    let reservation = store.reserve([0x52; 32], 30, 40).unwrap();
    store.seal_indeterminate(&reservation).unwrap();
    drop(store);
    assert!(ReleaseReservationStore::open(&path)
        .unwrap()
        .is_sealed()
        .unwrap());
}

#[test]
fn failed_no_effect_clears_only_an_unclaimed_matching_turn() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("release.cbor");
    let store = ReleaseReservationStore::open(&path).unwrap();
    let first = store.reserve([0x61; 32], 10, 100).unwrap();
    store.clear_failed_no_effect(&first).unwrap();

    let second = store.reserve([0x62; 32], 11, 100).unwrap();
    assert_eq!(
        store.clear_failed_no_effect(&first).unwrap_err(),
        ReservationError::CrossTurn
    );
    store.claim_next(12, golden()).unwrap();
    assert_eq!(
        store.clear_failed_no_effect(&second).unwrap_err(),
        ReservationError::AlreadyClaimed
    );
    assert!(store.is_sealed().unwrap());
}

#[test]
fn reservation_and_claim_survive_process_restart_and_stay_turn_bound() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("release.cbor");
    let (old, reservation) = {
        let store = ReleaseReservationStore::open(&path).unwrap();
        let old = store.reserve([0x70; 32], 8, 100).unwrap();
        store.clear_failed_no_effect(&old).unwrap();
        (old, store.reserve([0x71; 32], 10, 100).unwrap())
    };

    {
        let store = ReleaseReservationStore::open(&path).unwrap();
        store.claim_next(11, golden()).unwrap();
    }

    let store = ReleaseReservationStore::open(&path).unwrap();
    assert_eq!(
        store.read_delivery(&old).unwrap_err(),
        ReservationError::CrossTurn
    );
    let delivery = store.read_delivery(&reservation).unwrap();
    assert_eq!(delivery.turn_binding(), &[0x71; 32]);
    assert_eq!(delivery.payload(), b"released assistant response");
}

#[test]
fn journal_tampering_is_rejected_on_restart() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("release.cbor");
    let store = ReleaseReservationStore::open(&path).unwrap();
    store.reserve([0x81; 32], 10, 100).unwrap();
    store.claim_next(11, golden()).unwrap();
    drop(store);

    let mut bytes = fs::read(&path).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    fs::write(&path, bytes).unwrap();
    assert_eq!(
        ReleaseReservationStore::open(&path).unwrap_err(),
        ReservationError::DurableState
    );
}
