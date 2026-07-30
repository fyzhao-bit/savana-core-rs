use super::{
    argument_digest_v2, evidence_digest_v2, provenance_set_digest_v2, token_set_digest_v2,
    ArgumentDigestEntryV2, EvidenceDigestEntryV2, ProvenanceSetDigestEntryV2,
    TokenSetDigestEntryV2,
};
use crate::v2::{
    value_digest_v2, ArgumentNameV2, FieldNameV2, G3Error, IdentifierV2, KernelValueV2,
};
use savana_kernel_protocol::v2::{Digest32V2, ExecutorIdentityV2, ValueInternalIdV2};
use sha2::{Digest as _, Sha256};

fn digest(byte: u8) -> Digest32V2 {
    Digest32V2::new([byte; 32])
}

fn domain_hash(domain: &[u8], canonical: &[u8]) -> Digest32V2 {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(canonical);
    Digest32V2::new(hasher.finalize().into())
}

#[test]
fn value_digest_uses_the_exact_domain_and_closed_value_tags() {
    assert_eq!(
        value_digest_v2(&KernelValueV2::null()).unwrap(),
        domain_hash(b"SAVANA_VALUE_V2\0", &[0x81, 0x00])
    );
    assert_eq!(
        value_digest_v2(&KernelValueV2::boolean(true)).unwrap(),
        domain_hash(b"SAVANA_VALUE_V2\0", &[0x82, 0x01, 0xf5])
    );

    let text = KernelValueV2::text("hello").unwrap();
    assert_eq!(
        value_digest_v2(&text).unwrap(),
        domain_hash(
            b"SAVANA_VALUE_V2\0",
            &[0x82, 0x03, 0x65, b'h', b'e', b'l', b'l', b'o']
        )
    );
}

#[test]
fn kernel_objects_require_strict_canonical_field_order() {
    let a = FieldNameV2::new("a").unwrap();
    let b = FieldNameV2::new("b").unwrap();
    assert!(KernelValueV2::object(vec![
        (a.clone(), KernelValueV2::null()),
        (b.clone(), KernelValueV2::null()),
    ])
    .is_ok());
    assert_eq!(
        KernelValueV2::object(vec![(b, KernelValueV2::null()), (a, KernelValueV2::null()),])
            .err()
            .unwrap(),
        G3Error::NonCanonicalOrder
    );
}

#[test]
fn identifiers_are_closed_ascii_nfc_names() {
    for valid in ["a", "A_1", "tool.argument-name"] {
        assert!(ArgumentNameV2::new(valid).is_ok());
    }
    for invalid in ["", "1name", "a/b", "é", "white space"] {
        assert_eq!(
            ArgumentNameV2::new(invalid).unwrap_err(),
            G3Error::InvalidIdentifier
        );
    }
}

#[test]
fn argument_and_evidence_digests_reject_noncanonical_order() {
    let first = ArgumentDigestEntryV2::new(
        ArgumentNameV2::new("a").unwrap(),
        ValueInternalIdV2::new([1; 32]),
        digest(2),
        digest(3),
    );
    let second = ArgumentDigestEntryV2::new(
        ArgumentNameV2::new("b").unwrap(),
        ValueInternalIdV2::new([4; 32]),
        digest(5),
        digest(6),
    );
    let mut argument_canonical = vec![0x81, 0x84, 0x61, b'a'];
    for byte in [1_u8, 2, 3] {
        argument_canonical.extend_from_slice(&[0x58, 0x20]);
        argument_canonical.extend_from_slice(&[byte; 32]);
    }
    assert_eq!(
        argument_digest_v2(std::slice::from_ref(&first)).unwrap(),
        domain_hash(b"SAVANA_ARGUMENTS_V2\0", &argument_canonical)
    );
    assert!(argument_digest_v2(&[first.clone(), second.clone()]).is_ok());
    assert_eq!(
        argument_digest_v2(&[second, first]).unwrap_err(),
        G3Error::NonCanonicalOrder
    );

    let evidence_a = EvidenceDigestEntryV2::new(digest(1), digest(2));
    let evidence_b = EvidenceDigestEntryV2::new(digest(2), digest(1));
    let mut evidence_canonical = vec![0x81, 0x82];
    for byte in [1_u8, 2] {
        evidence_canonical.extend_from_slice(&[0x58, 0x20]);
        evidence_canonical.extend_from_slice(&[byte; 32]);
    }
    assert_eq!(
        evidence_digest_v2(&[evidence_a]).unwrap(),
        domain_hash(b"SAVANA_EVIDENCE_V2\0", &evidence_canonical)
    );
    assert!(evidence_digest_v2(&[evidence_a, evidence_b]).is_ok());
    assert_eq!(
        evidence_digest_v2(&[evidence_b, evidence_a]).unwrap_err(),
        G3Error::NonCanonicalOrder
    );
}

#[test]
fn provenance_set_is_exactly_bound_to_arguments() {
    let argument = ArgumentDigestEntryV2::new(
        ArgumentNameV2::new("subject").unwrap(),
        ValueInternalIdV2::new([1; 32]),
        digest(2),
        digest(3),
    );
    let entry =
        ProvenanceSetDigestEntryV2::new(ValueInternalIdV2::new([1; 32]), digest(2), digest(3));
    let mut canonical = vec![0x81, 0x83];
    for byte in [1_u8, 2, 3] {
        canonical.extend_from_slice(&[0x58, 0x20]);
        canonical.extend_from_slice(&[byte; 32]);
    }
    assert_eq!(
        provenance_set_digest_v2(
            std::slice::from_ref(&argument),
            std::slice::from_ref(&entry)
        )
        .unwrap(),
        domain_hash(b"SAVANA_PROVENANCE_SET_V2\0", &canonical)
    );

    let mismatch =
        ProvenanceSetDigestEntryV2::new(ValueInternalIdV2::new([1; 32]), digest(9), digest(3));
    assert_eq!(
        provenance_set_digest_v2(&[argument], &[mismatch]).unwrap_err(),
        G3Error::BindingMismatch
    );

    let aliased = [
        ArgumentDigestEntryV2::new(
            ArgumentNameV2::new("a").unwrap(),
            ValueInternalIdV2::new([1; 32]),
            digest(2),
            digest(3),
        ),
        ArgumentDigestEntryV2::new(
            ArgumentNameV2::new("b").unwrap(),
            ValueInternalIdV2::new([1; 32]),
            digest(2),
            digest(3),
        ),
    ];
    assert_eq!(
        provenance_set_digest_v2(&aliased, &[entry]).unwrap_err(),
        G3Error::DuplicateInternalId
    );
}

#[test]
fn token_set_hashes_stable_internal_identities_and_exact_count() {
    let token = TokenSetDigestEntryV2::new(
        IdentifierV2::new("slot").unwrap(),
        digest(1),
        digest(2),
        ExecutorIdentityV2::new([3; 32]),
    );
    let actual = token_set_digest_v2(&[token]).unwrap();

    let mut canonical = vec![0x82, 0x01, 0x81, 0x84, 0x64, b's', b'l', b'o', b't'];
    for byte in [1_u8, 2, 3] {
        canonical.extend_from_slice(&[0x58, 0x20]);
        canonical.extend_from_slice(&[byte; 32]);
    }
    assert_eq!(actual, domain_hash(b"SAVANA_TOKEN_SET_V2\0", &canonical));
}

#[test]
fn kernel_values_enforce_depth_and_node_limits_before_hashing() {
    let mut deepest_valid = KernelValueV2::null();
    for _ in 0..15 {
        deepest_valid = KernelValueV2::list(vec![deepest_valid]).unwrap();
    }
    assert_eq!(
        KernelValueV2::list(vec![deepest_valid]).err().unwrap(),
        G3Error::ValueDepthExceeded
    );

    assert_eq!(
        KernelValueV2::list((0..65_536).map(|_| KernelValueV2::null()).collect())
            .err()
            .unwrap(),
        G3Error::ValueNodeLimitExceeded
    );

    assert_eq!(
        KernelValueV2::bytes(vec![0; 8 * 1024 * 1024])
            .err()
            .unwrap(),
        G3Error::ValueEncodedBytesExceeded
    );
}
