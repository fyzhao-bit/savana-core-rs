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

fn turn_request(turn: u8) -> VerifiedReleaseRequest {
    use savana_kernel_protocol::v2::*;
    use sha2::{Digest as _, Sha256};
    let profile =
        final_release_business_profile_v2(Digest32V2::new([1; 32]), Digest32V2::new([2; 32]))
            .unwrap();
    let payload = final_release_business_request_v2(
        &profile,
        "release-1",
        Digest32V2::new([3; 32]),
        Digest32V2::new([turn; 32]),
        b"released assistant response",
    )
    .unwrap()
    .canonical_json();
    let hash = |domain: &[u8], length: bool| {
        let mut h = Sha256::new();
        h.update(domain);
        if length {
            h.update((payload.len() as u64).to_be_bytes());
        }
        h.update(&payload);
        <[u8; 32]>::from(h.finalize())
    };
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(11)
        .unwrap()
        .u16(2)
        .unwrap()
        .u16(1)
        .unwrap()
        .str("https://127.0.0.1:43191/savana/final-release")
        .unwrap()
        .bytes(&[0x70; 32])
        .unwrap()
        .bytes(&[5; 32])
        .unwrap()
        .bytes(&[6; 32])
        .unwrap()
        .bytes(&[7; 32])
        .unwrap()
        .u32(payload.len() as u32)
        .unwrap()
        .bytes(&hash(b"SAVANA_PREPARED_PROVIDER_REQUEST_V2\0", false))
        .unwrap()
        .bytes(&hash(b"SAVANA_PROVIDER_REQUEST_PAYLOAD_V2\0", true))
        .unwrap()
        .bytes(&payload)
        .unwrap();
    VerifiedReleaseRequest::decode(&e.into_writer()).unwrap()
}

#[test]
fn new_delivery_cannot_borrow_the_next_reserved_turn_or_use_legacy_raw_payload() {
    for request in [turn_request(0x42), golden()] {
        let dir = tempdir().unwrap();
        let store = ReleaseReservationStore::open(dir.path().join("release.cbor")).unwrap();
        let reservation = store.reserve([0x41; 32], 10, 100).unwrap();
        assert!(store.claim_next(11, request).is_err());
        assert!(store.read_delivery(&reservation).is_err());
        assert!(store.is_sealed().unwrap());
    }
}

#[test]
fn new_turn_bound_journal_restores_actual_payload_not_the_business_envelope() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("release.cbor");
    let store = ReleaseReservationStore::open(&path).unwrap();
    let reservation = store.reserve([0x41; 32], 10, 100).unwrap();
    store.claim_next(11, turn_request(0x41)).unwrap();
    drop(store);
    let reopened = ReleaseReservationStore::open(&path).unwrap();
    let delivery = reopened.read_delivery(&reservation).unwrap();
    assert_eq!(delivery.payload(), b"released assistant response");
    assert_eq!(delivery.turn_binding(), &[0x41; 32]);
}

#[test]
fn legacy_claimed_journal_is_readable_without_creating_new_legacy_authority() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("release.cbor");
    let store = ReleaseReservationStore::open(&path).unwrap();
    let reservation = store.reserve([0x41; 32], 10, 100).unwrap();
    let saved = fs::read(&path).unwrap();
    let mut d = minicbor::Decoder::new(&saved);
    d.array().unwrap();
    d.u16().unwrap();
    d.u64().unwrap();
    d.array().unwrap();
    d.u8().unwrap();
    let id = d.bytes().unwrap().to_vec();
    drop(store);
    // Encode the historical arity/tag directly; never use the new claim path.
    let old = golden();
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(4)
        .unwrap()
        .u16(1)
        .unwrap()
        .u64(2)
        .unwrap()
        .array(13)
        .unwrap()
        .u8(2)
        .unwrap()
        .bytes(&id)
        .unwrap()
        .bytes(&[0x41; 32])
        .unwrap()
        .u64(100)
        .unwrap()
        .str(old.canonical_url())
        .unwrap()
        .bytes(old.tls_identity_pin())
        .unwrap()
        .bytes(old.execution_nonce())
        .unwrap()
        .bytes(old.dispatch_core_digest())
        .unwrap()
        .bytes(old.dispatch_subject_digest())
        .unwrap()
        .bytes(old.credential_free_request_digest())
        .unwrap()
        .bytes(old.payload_digest())
        .unwrap()
        .bytes(old.wire_digest())
        .unwrap()
        .bytes(old.payload())
        .unwrap()
        .array(0)
        .unwrap();
    let legacy = e.into_writer();
    fs::write(&path, &legacy).unwrap();
    let reopened = ReleaseReservationStore::open(&path).unwrap();
    assert_eq!(
        reopened.read_delivery(&reservation).unwrap().payload(),
        old.payload()
    );
    assert_eq!(fs::read(&path).unwrap(), legacy); // opening never rewrites history
    reopened.complete_delivery(&reservation).unwrap();
    reopened.reserve([0x42; 32], 12, 100).unwrap();
    assert!(reopened.claim_next(13, golden()).is_err());
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
    store.claim_next(11, turn_request(0x41)).unwrap();
    assert_eq!(
        store.read_delivery(&reservation).unwrap().payload(),
        b"released assistant response"
    );
    assert_eq!(
        store.claim_next(12, turn_request(0x41)).unwrap_err(),
        ReservationError::DuplicateDelivery
    );
    store.complete_delivery(&reservation).unwrap();

    let next = store.reserve([0x42; 32], 13, 100).unwrap();
    assert_ne!(reservation, next);
    assert_eq!(
        store.claim_next(14, turn_request(0x41)).unwrap_err(),
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
    store.claim_next(12, turn_request(0x62)).unwrap();
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
        store.claim_next(11, turn_request(0x71)).unwrap();
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
    store.claim_next(11, turn_request(0x81)).unwrap();
    drop(store);

    let mut bytes = fs::read(&path).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    fs::write(&path, bytes).unwrap();
    assert_eq!(
        ReleaseReservationStore::open(&path).unwrap_err(),
        ReservationError::DurableState
    );
}
