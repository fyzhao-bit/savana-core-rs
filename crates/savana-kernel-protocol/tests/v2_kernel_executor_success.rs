use ed25519_dalek::SigningKey;
use savana_kernel_protocol::v2::{
    decode_fetch_completion_response_v2, derive_ed25519_key_id_v2,
    encode_fetch_completion_response_v2, Digest32V2, DurableReleaseIdV2,
    ExecutorCompletionDescriptorV2, ExecutorCompletionPayloadV2,
    ExecutorFinalReleaseAuditEvidenceV2, ExecutorIdentityV2, FetchCompletionResponseV2, Nonce32V2,
    SignedExecutorEffectStartedReceiptV2, SignedExecutorFinalReleaseReceiptV2, UnixMillisV2,
    UnsignedExecutorEffectStartedReceiptV2, UnsignedExecutorFinalReleaseReceiptV2,
};
use sha2::{Digest as _, Sha256};

fn effect_receipt() -> SignedExecutorEffectStartedReceiptV2 {
    let signing_key = SigningKey::from_bytes(&[0x40; 32]);
    let key_id = derive_ed25519_key_id_v2(signing_key.verifying_key().to_bytes());
    let unsigned = UnsignedExecutorEffectStartedReceiptV2::new(
        Digest32V2::new([1; 32]),
        Digest32V2::new([2; 32]),
        3,
        4,
        Nonce32V2::new([5; 32]),
        Digest32V2::new([6; 32]),
        Digest32V2::new([7; 32]),
        ExecutorIdentityV2::new([8; 32]),
        Digest32V2::new([9; 32]),
        1,
        Digest32V2::new([10; 32]),
        Digest32V2::new([11; 32]),
        Digest32V2::new([12; 32]),
        UnixMillisV2::new(13),
    )
    .unwrap();
    SignedExecutorEffectStartedReceiptV2::sign(unsigned, key_id, &signing_key).unwrap()
}

fn provider_evidence_digest(bytes: &[u8]) -> Digest32V2 {
    let mut hasher = Sha256::new();
    hasher.update(b"SAVANA_CONNECTOR_PROVIDER_EVIDENCE_V2\0");
    hasher.update(bytes);
    Digest32V2::new(hasher.finalize().into())
}

#[test]
fn effect_receipt_is_typed_signed_and_exactly_bound() {
    let receipt = effect_receipt();
    let signing_key = SigningKey::from_bytes(&[0x40; 32]);
    let key_id = derive_ed25519_key_id_v2(signing_key.verifying_key().to_bytes());

    receipt
        .verify(key_id, signing_key.verifying_key().to_bytes())
        .unwrap();
    assert_eq!(
        receipt.unsigned().execution_nonce(),
        Nonce32V2::new([5; 32])
    );
    assert_eq!(
        receipt.unsigned().dispatch_core_digest(),
        Digest32V2::new([6; 32])
    );
    assert_eq!(
        receipt.unsigned().dispatch_subject_digest(),
        Digest32V2::new([7; 32])
    );
    assert_ne!(receipt.digest().as_bytes(), &[0; 32]);

    let mut wrong_key = signing_key.verifying_key().to_bytes();
    wrong_key[0] ^= 1;
    assert!(receipt.verify(key_id, wrong_key).is_err());

    let mut noncanonical = receipt.canonical_bytes().unwrap();
    noncanonical.push(0);
    assert!(SignedExecutorEffectStartedReceiptV2::from_canonical_bytes(&noncanonical).is_err());
}

#[test]
fn final_release_payload_must_match_all_descriptor_digests() {
    let effect = effect_receipt();
    let signing_key = SigningKey::from_bytes(&[0x40; 32]);
    let key_id = derive_ed25519_key_id_v2(signing_key.verifying_key().to_bytes());
    let durable_release_id = DurableReleaseIdV2::new([20; 32]);
    let provider_evidence = vec![21; 41];
    let audit = ExecutorFinalReleaseAuditEvidenceV2::new(vec![22; 53]).unwrap();
    let unsigned = UnsignedExecutorFinalReleaseReceiptV2::new(
        Digest32V2::new([1; 32]),
        Digest32V2::new([2; 32]),
        3,
        4,
        durable_release_id,
        Nonce32V2::new([5; 32]),
        Digest32V2::new([6; 32]),
        Digest32V2::new([7; 32]),
        Digest32V2::new([23; 32]),
        Digest32V2::new([24; 32]),
        Digest32V2::new([25; 32]),
        ExecutorIdentityV2::new([8; 32]),
        provider_evidence_digest(&provider_evidence),
        audit.digest(),
        Digest32V2::new([27; 32]),
        UnixMillisV2::new(28),
    )
    .unwrap();
    let final_receipt =
        SignedExecutorFinalReleaseReceiptV2::sign(unsigned, key_id, &signing_key).unwrap();
    let payload =
        ExecutorCompletionPayloadV2::final_release(final_receipt, provider_evidence, audit)
            .unwrap();
    let descriptor = payload.descriptor().unwrap();
    let response = FetchCompletionResponseV2::new(
        Nonce32V2::new([5; 32]),
        Digest32V2::new([6; 32]),
        Digest32V2::new([7; 32]),
        effect.clone(),
        effect.digest(),
        descriptor,
        payload,
    )
    .unwrap();
    let encoded = encode_fetch_completion_response_v2(&response).unwrap();
    assert!(decode_fetch_completion_response_v2(&encoded).is_ok());

    use savana_kernel_protocol::v2::TaskCompletionEvidenceV2;
    let evidence = TaskCompletionEvidenceV2::new(
        Digest32V2::new([31; 32]),
        Digest32V2::new([32; 32]),
        Digest32V2::new([33; 32]),
        vec![34; 300],
    )
    .unwrap();
    let evidence_digest = evidence.evidence_digest(descriptor).unwrap();
    for field in 0..3 {
        let mut hashes = [
            Digest32V2::new([31; 32]),
            Digest32V2::new([32; 32]),
            Digest32V2::new([33; 32]),
        ];
        hashes[field] = Digest32V2::new([99; 32]);
        let changed =
            TaskCompletionEvidenceV2::new(hashes[0], hashes[1], hashes[2], vec![34; 300]).unwrap();
        assert_ne!(
            changed.evidence_digest(descriptor).unwrap(),
            evidence_digest
        );
    }
    let response = response.with_task_outcome(evidence.clone());
    let encoded = encode_fetch_completion_response_v2(&response).unwrap();
    assert_eq!(
        decode_fetch_completion_response_v2(&encoded)
            .unwrap()
            .task_outcome(),
        Some(&evidence)
    );
    for end in 0..encoded.len() {
        assert!(decode_fetch_completion_response_v2(&encoded[..end]).is_err());
    }
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(decode_fetch_completion_response_v2(&trailing).is_err());
    let mut unknown = encoded;
    unknown[0] = 0x89;
    assert!(decode_fetch_completion_response_v2(&unknown).is_err());

    let bad_descriptor = ExecutorCompletionDescriptorV2::final_release_receipt(
        durable_release_id,
        Digest32V2::new([99; 32]),
        Digest32V2::new([22; 32]),
        94,
    )
    .unwrap();
    let audit = ExecutorFinalReleaseAuditEvidenceV2::new(vec![22; 53]).unwrap();
    let unsigned = UnsignedExecutorFinalReleaseReceiptV2::new(
        Digest32V2::new([1; 32]),
        Digest32V2::new([2; 32]),
        3,
        4,
        durable_release_id,
        Nonce32V2::new([5; 32]),
        Digest32V2::new([6; 32]),
        Digest32V2::new([7; 32]),
        Digest32V2::new([23; 32]),
        Digest32V2::new([24; 32]),
        Digest32V2::new([25; 32]),
        ExecutorIdentityV2::new([8; 32]),
        provider_evidence_digest(&[21; 41]),
        audit.digest(),
        Digest32V2::new([27; 32]),
        UnixMillisV2::new(28),
    )
    .unwrap();
    let final_receipt =
        SignedExecutorFinalReleaseReceiptV2::sign(unsigned, key_id, &signing_key).unwrap();
    let payload =
        ExecutorCompletionPayloadV2::final_release(final_receipt, vec![21; 41], audit).unwrap();
    assert!(FetchCompletionResponseV2::new(
        Nonce32V2::new([5; 32]),
        Digest32V2::new([6; 32]),
        Digest32V2::new([7; 32]),
        effect.clone(),
        effect.digest(),
        bad_descriptor,
        payload,
    )
    .is_err());

    assert!(FetchCompletionResponseV2::new(
        Nonce32V2::new([5; 32]),
        Digest32V2::new([6; 32]),
        Digest32V2::new([7; 32]),
        effect,
        Digest32V2::new([98; 32]),
        ExecutorCompletionDescriptorV2::tool_result(Digest32V2::new([97; 32]), 1).unwrap(),
        ExecutorCompletionPayloadV2::tool_result(vec![1]).unwrap(),
    )
    .is_err());
}

#[test]
fn query_terminal_receipt_is_bounded_versioned_and_does_not_make_status_authority() {
    use savana_kernel_protocol::v2::*;
    let status = ExecutorStatusV2::FailedNoEffect {
        class: ExecutorFailureClassV2::EnvelopeRejectedBeforeEffect,
    };
    let legacy = QueryByExecutionNonceResponseV2::new(status.clone());
    let bytes = encode_query_by_execution_nonce_response_v2(&legacy).unwrap();
    assert!(decode_query_by_execution_nonce_response_v2(&bytes)
        .unwrap()
        .terminal_receipt()
        .is_none());
    let response = legacy.with_terminal_receipt(vec![17; 300]).unwrap();
    let encoded = encode_query_by_execution_nonce_response_v2(&response).unwrap();
    assert_eq!(
        decode_query_by_execution_nonce_response_v2(&encoded).unwrap(),
        response
    );
    for end in 0..encoded.len() {
        assert!(decode_query_by_execution_nonce_response_v2(&encoded[..end]).is_err());
    }
    let mut trailing = encoded;
    trailing.push(0);
    assert!(decode_query_by_execution_nonce_response_v2(&trailing).is_err());
    for bytes in [vec![], vec![1; 1025]] {
        assert!(QueryByExecutionNonceResponseV2::new(status.clone())
            .with_terminal_receipt(bytes)
            .is_err());
    }
    assert!(
        QueryByExecutionNonceResponseV2::new(ExecutorStatusV2::Prepared)
            .with_terminal_receipt(vec![1; 300])
            .is_err()
    );
}
