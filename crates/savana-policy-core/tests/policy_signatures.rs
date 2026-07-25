mod support;

use savana_kernel_protocol::{Digest32, KeyId, StableCode};
use savana_policy_core::{AuthorityRoleV1, PolicyTrustRootV1, PolicyVerifier};

#[test]
fn valid_policy_signature_is_accepted() {
    let policy = support::valid_policy(7, 3);
    let (bundle, signature) = support::signed(&policy);
    let verified = support::verifier()
        .verify(&bundle, &signature, support::unix_now())
        .unwrap();
    assert_eq!(verified.identity().policy_version, 7);
    assert_eq!(verified.identity().key_epoch, 3);
    assert_eq!(
        verified.effective_limits().frame_bytes(),
        savana_kernel_protocol::HardLimits::COMPILED.frame_bytes()
    );
    let validator_id = KeyId::try_from("role-04").unwrap();
    let validator = verified
        .authority(&validator_id, AuthorityRoleV1::Validator)
        .unwrap();
    assert_eq!(validator.key_id(), &validator_id);
    assert_eq!(validator.role(), AuthorityRoleV1::Validator);
    assert_eq!(validator.public_key(), &[5; 32]);
    assert_eq!(validator.epoch(), 1);
    assert!(verified
        .authority(&validator_id, AuthorityRoleV1::Ontology)
        .is_none());
}

#[test]
fn authority_view_excludes_revoked_and_partial_window_keys() {
    let mut policy = support::valid_policy(7, 3);
    policy.authorities.push(support::Authority {
        key_id: "role-04-window".to_owned(),
        role: 4,
        public_key: [0x52; 32],
        epoch: 2,
        not_before: 1_001,
        not_after: 4_100,
        revoked: false,
    });
    policy.authorities.push(support::Authority {
        key_id: "role-04-revoked".to_owned(),
        role: 4,
        public_key: [0x51; 32],
        epoch: 2,
        not_before: 900,
        not_after: 4_100,
        revoked: true,
    });
    let (bundle, signature) = support::signed(&policy);
    let verified = support::verifier()
        .verify(&bundle, &signature, support::unix_now())
        .unwrap();

    for key_id in ["role-04-revoked", "role-04-window"] {
        assert!(verified
            .authority(
                &KeyId::try_from(key_id).unwrap(),
                AuthorityRoleV1::Validator
            )
            .is_none());
    }
}

#[test]
fn modified_bundle_and_wrong_domain_are_rejected() {
    let policy = support::valid_policy(7, 3);
    let (bundle, signature) = support::signed(&policy);
    let verifier = support::verifier();

    let mut modified = bundle.clone();
    let digest_offset = modified
        .windows(32)
        .position(|window| window == [0x21; 32])
        .expect("fixture descriptor digest is encoded");
    modified[digest_offset] ^= 1;
    assert_eq!(
        verifier
            .verify(&modified, &signature, support::unix_now())
            .unwrap_err()
            .code(),
        StableCode::PolicyInvalidSignature
    );

    let (_, wrong_domain_signature) =
        support::signed_with_domain(&policy, support::RELEASE_DOMAIN, &support::signing_key());
    assert_eq!(
        verifier
            .verify(&bundle, &wrong_domain_signature, support::unix_now())
            .unwrap_err()
            .code(),
        StableCode::PolicyInvalidSignature
    );
}

#[test]
fn unknown_revoked_epoch_mismatched_and_wrong_keys_are_rejected() {
    let key = support::signing_key();
    let policy = support::valid_policy(7, 3);
    let (bundle, signature) = support::signed(&policy);

    let unknown =
        support::verifier_with_roots(vec![support::trust_root("other-root", &key, 3, false)]);
    assert_eq!(
        unknown
            .verify(&bundle, &signature, support::unix_now())
            .unwrap_err()
            .code(),
        StableCode::PolicyInvalidSignature
    );

    let revoked =
        support::verifier_with_roots(vec![support::trust_root("policy-root", &key, 3, true)]);
    assert_eq!(
        revoked
            .verify(&bundle, &signature, support::unix_now())
            .unwrap_err()
            .code(),
        StableCode::PolicyInvalidSignature
    );

    let wrong_epoch =
        support::verifier_with_roots(vec![support::trust_root("policy-root", &key, 4, false)]);
    assert_eq!(
        wrong_epoch
            .verify(&bundle, &signature, support::unix_now())
            .unwrap_err()
            .code(),
        StableCode::PolicyInvalidSignature
    );

    let (_, wrong_key_signature) =
        support::signed_with_key(&policy, &support::alternate_signing_key());
    assert_eq!(
        support::verifier()
            .verify(&bundle, &wrong_key_signature, support::unix_now())
            .unwrap_err()
            .code(),
        StableCode::PolicyInvalidSignature
    );
}

#[test]
fn embedded_authority_never_creates_policy_trust() {
    let mut policy = support::valid_policy(7, 3);
    policy.signing_key_id = "role-00".to_owned();
    let (bundle, signature) = support::signed(&policy);
    assert_eq!(
        support::verifier()
            .verify(&bundle, &signature, support::unix_now())
            .unwrap_err()
            .code(),
        StableCode::PolicyInvalidSignature
    );
}

#[test]
fn verifier_constructor_rejects_invalid_root_sets() {
    let key = support::signing_key();
    assert_eq!(
        PolicyVerifier::new(Vec::new(), support::active_target())
            .unwrap_err()
            .code(),
        StableCode::ProtocolMalformedCbor
    );

    let too_many = (0..17)
        .map(|index| support::trust_root(&format!("root-{index:02}"), &key, 3, false))
        .collect();
    assert_eq!(
        PolicyVerifier::new(too_many, support::active_target())
            .unwrap_err()
            .code(),
        StableCode::PolicyLimitExceeded
    );

    let duplicate = support::trust_root("policy-root", &key, 3, false);
    assert_eq!(
        PolicyVerifier::new(vec![duplicate.clone(), duplicate], support::active_target())
            .unwrap_err()
            .code(),
        StableCode::ProtocolMalformedCbor
    );

    let unsorted = vec![
        support::trust_root("root-bb", &key, 3, false),
        support::trust_root("root-aa", &key, 3, false),
    ];
    assert_eq!(
        PolicyVerifier::new(unsorted, support::active_target())
            .unwrap_err()
            .code(),
        StableCode::ProtocolMalformedCbor
    );

    for invalid in [
        PolicyTrustRootV1 {
            key_id: KeyId::try_from("zero-epoch").unwrap(),
            public_key: key.verifying_key().to_bytes(),
            epoch: 0,
            revoked: false,
        },
        PolicyTrustRootV1 {
            key_id: KeyId::try_from("zero-key").unwrap(),
            public_key: [0; 32],
            epoch: 3,
            revoked: false,
        },
    ] {
        assert_eq!(
            PolicyVerifier::new(vec![invalid], Digest32::new([0xa0; 32]))
                .unwrap_err()
                .code(),
            StableCode::PolicyInvalidSignature
        );
    }
}

#[test]
fn noncanonical_indefinite_and_trailing_policy_bytes_are_rejected() {
    let policy = support::valid_policy(7, 3);
    let canonical = support::encode_policy(&policy);
    let verifier = support::verifier();

    let mut non_shortest = canonical.clone();
    let mut decoder = minicbor::Decoder::new(&canonical);
    assert_eq!(decoder.array().unwrap(), Some(17));
    assert_eq!(decoder.u16().unwrap(), 1);
    assert_eq!(decoder.array().unwrap(), Some(3));
    assert_eq!(decoder.u16().unwrap(), 1);
    assert_eq!(decoder.u16().unwrap(), 0);
    assert_eq!(decoder.u16().unwrap(), 0);
    let policy_version_position = decoder.position();
    assert_eq!(decoder.u64().unwrap(), 7);
    non_shortest.splice(
        policy_version_position..policy_version_position + 1,
        [0x18, 0x07],
    );

    let mut indefinite = canonical.clone();
    assert_eq!(indefinite[0], 0x91);
    indefinite[0] = 0x9f;
    indefinite.push(0xff);

    let mut trailing = canonical;
    trailing.push(0);

    for bytes in [non_shortest, indefinite, trailing] {
        let signature =
            support::detached_signature(support::POLICY_DOMAIN, &bytes, &support::signing_key());
        assert_eq!(
            verifier
                .verify(&bytes, &signature, support::unix_now())
                .unwrap_err()
                .code(),
            StableCode::ProtocolMalformedCbor
        );
    }
}
