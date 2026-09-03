use minicbor::Encoder;
use savana_openclaw_release::{
    ReleaseRequestError, VerifiedReleaseRequest, MAX_RELEASE_PAYLOAD_BYTES,
};
use sha2::{Digest as _, Sha256};

const GOLDEN_HEX: &str = include_str!("fixtures/provider-request-v2.hex");

fn golden() -> Vec<u8> {
    let text = GOLDEN_HEX.trim().as_bytes();
    assert_eq!(text.len() % 2, 0, "valid golden hex length");
    text.chunks_exact(2)
        .map(|pair| {
            let digit = |byte| match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                b'A'..=b'F' => byte - b'A' + 10,
                _ => panic!("valid golden hex digit"),
            };
            (digit(pair[0]) << 4) | digit(pair[1])
        })
        .collect()
}

fn encode_request(payload: &[u8]) -> Vec<u8> {
    let domain_hash = |domain: &[u8], include_length: bool| {
        let mut hasher = Sha256::new();
        hasher.update(domain);
        if include_length {
            hasher.update((payload.len() as u64).to_be_bytes());
        }
        hasher.update(payload);
        <[u8; 32]>::from(hasher.finalize())
    };
    let request_digest = domain_hash(b"SAVANA_PREPARED_PROVIDER_REQUEST_V2\0", false);
    let payload_digest = domain_hash(b"SAVANA_PROVIDER_REQUEST_PAYLOAD_V2\0", true);
    let mut encoder = Encoder::new(Vec::new());
    encoder
        .array(11)
        .and_then(|encoder| encoder.u16(2))
        .and_then(|encoder| encoder.u16(1))
        .and_then(|encoder| encoder.str("https://127.0.0.1:43191/savana/final-release"))
        .and_then(|encoder| encoder.bytes(&[0x70; 32]))
        .and_then(|encoder| encoder.bytes(&[0x05; 32]))
        .and_then(|encoder| encoder.bytes(&[0x06; 32]))
        .and_then(|encoder| encoder.bytes(&[0x07; 32]))
        .and_then(|encoder| encoder.u32(payload.len() as u32))
        .and_then(|encoder| encoder.bytes(&request_digest))
        .and_then(|encoder| encoder.bytes(&payload_digest))
        .and_then(|encoder| encoder.bytes(payload))
        .unwrap();
    encoder.into_writer()
}

#[test]
fn decodes_the_execd_verified_provider_request_golden_vector() {
    let request = VerifiedReleaseRequest::decode(&golden()).unwrap();

    assert_eq!(
        request.canonical_url(),
        "https://127.0.0.1:43191/savana/final-release"
    );
    assert_eq!(request.tls_identity_pin(), &[0x70; 32]);
    assert_eq!(request.execution_nonce(), &[0x05; 32]);
    assert_eq!(request.dispatch_core_digest(), &[0x06; 32]);
    assert_eq!(request.dispatch_subject_digest(), &[0x07; 32]);
    assert_eq!(request.payload(), b"released assistant response");
}

#[test]
fn rejects_noncanonical_or_invalid_outer_frames() {
    let valid = golden();
    let mut cases = Vec::new();

    let mut trailing = valid.clone();
    trailing.push(0);
    cases.push(trailing);

    let mut wrong_version = valid.clone();
    wrong_version[1] = 3;
    cases.push(wrong_version);

    let mut indefinite = valid.clone();
    indefinite[0] = 0x9f;
    cases.push(indefinite);

    let mut mismatched_payload = valid.clone();
    *mismatched_payload.last_mut().unwrap() ^= 1;
    cases.push(mismatched_payload);

    for bytes in cases {
        assert_eq!(
            VerifiedReleaseRequest::decode(&bytes).unwrap_err(),
            ReleaseRequestError::NonCanonical
        );
    }
}

#[test]
fn rejects_empty_zero_digest_and_oversized_payloads() {
    assert_eq!(
        VerifiedReleaseRequest::decode(&[]).unwrap_err(),
        ReleaseRequestError::NonCanonical
    );

    let mut zero_nonce = golden();
    let marker = [0x58, 0x20, 0x05, 0x05, 0x05, 0x05];
    let start = zero_nonce
        .windows(marker.len())
        .position(|window| window == marker)
        .unwrap()
        + 2;
    zero_nonce[start..start + 32].fill(0);
    assert_eq!(
        VerifiedReleaseRequest::decode(&zero_nonce).unwrap_err(),
        ReleaseRequestError::NonCanonical
    );

    let oversized_payload = encode_request(&vec![b'x'; MAX_RELEASE_PAYLOAD_BYTES + 1]);
    assert_eq!(
        VerifiedReleaseRequest::decode(&oversized_payload).unwrap_err(),
        ReleaseRequestError::TooLarge
    );
}

#[test]
fn debug_output_never_contains_released_payload() {
    let request = VerifiedReleaseRequest::decode(&golden()).unwrap();
    let debug = format!("{request:?}");
    assert!(!debug.contains("released assistant response"));
}
