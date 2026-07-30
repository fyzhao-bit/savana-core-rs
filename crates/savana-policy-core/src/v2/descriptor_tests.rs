use crate::v2::{
    AttemptKindV2, BoundedConnectorRetryPolicyV2, ExecutorIdempotencyContractV2, G4Error,
    IdentifierV2, InternalValidatorDeclarationV2,
};
use ed25519_dalek::{Signer as _, SigningKey};
use savana_kernel_protocol::v2::{
    Digest32V2, Ed25519KeyIdV2, ImplementationIdV2, ProjectionIdV2, RoleIdV2, UnixMillisV2,
    VersionV2,
};

use super::{
    descriptor_digest_v2, ActiveToolRegistryV2, SignedToolDescriptorV2, UnsignedToolDescriptorV2,
    VerifiedManifestToolConstraintSetV2, VerifiedManifestToolConstraintV2,
    VerifiedPolicyToolActivationV2, VerifiedPolicyToolSetV2, VerifiedRegistryPublisherV2,
    VerifiedToolRegistryV2,
};

#[test]
fn attempt_and_idempotency_contract_tags_are_exact() {
    assert_eq!(
        minicbor::to_vec(AttemptKindV2::ToolIrreversible).unwrap(),
        [0x81, 0x03]
    );
    assert_eq!(
        minicbor::to_vec(ExecutorIdempotencyContractV2::ConnectorNonIdempotentSingleAttempt)
            .unwrap(),
        [0x81, 0x02]
    );
}

#[test]
fn retry_policy_is_closed_by_idempotency_contract() {
    let single = BoundedConnectorRetryPolicyV2::new(
        ExecutorIdempotencyContractV2::ConnectorNonIdempotentSingleAttempt,
        1,
        0,
    )
    .unwrap();
    assert_eq!(minicbor::to_vec(single).unwrap(), [0x82, 0x01, 0x00]);

    for invalid in [(0, 0), (2, 0), (1, 1)] {
        assert_eq!(
            BoundedConnectorRetryPolicyV2::new(
                ExecutorIdempotencyContractV2::ConnectorNonIdempotentSingleAttempt,
                invalid.0,
                invalid.1,
            )
            .unwrap_err(),
            G4Error::InvalidRetryPolicy
        );
    }

    assert!(BoundedConnectorRetryPolicyV2::new(
        ExecutorIdempotencyContractV2::ConnectorIdempotentByExecutionNonce,
        8,
        30_000_000_000,
    )
    .is_ok());
    for invalid in [(0, 1), (9, 1), (1, 0), (1, 30_000_000_001)] {
        assert_eq!(
            BoundedConnectorRetryPolicyV2::new(
                ExecutorIdempotencyContractV2::ConnectorIdempotentByExecutionNonce,
                invalid.0,
                invalid.1,
            )
            .unwrap_err(),
            G4Error::InvalidRetryPolicy
        );
    }
}

#[test]
fn internal_validator_declaration_has_the_exact_three_field_shape() {
    let declaration = InternalValidatorDeclarationV2::new(
        ImplementationIdV2::new(7),
        VersionV2::new(1, 2, 3),
        Digest32V2::new([8; 32]),
    );
    let encoded = minicbor::to_vec(declaration).unwrap();
    assert_eq!(&encoded[..6], &[0x83, 0x07, 0x83, 0x01, 0x02, 0x03]);
    assert_eq!(encoded.len(), 40);
}

#[test]
fn signed_descriptor_requires_exact_canonical_payload_key_domain_and_time() {
    let signing_key = SigningKey::from_bytes(&[0x41; 32]);
    let publisher_key_id = Ed25519KeyIdV2::new([0x42; 32]);
    let unsigned = descriptor(
        VersionV2::new(4, 5, 6),
        vec![RoleIdV2::new(1), RoleIdV2::new(7)],
        vec![validator(1), validator(2)],
    );
    let descriptor_digest = descriptor_digest_v2(&unsigned).unwrap();
    let mut signing_bytes = b"SAVANA_TOOL_DESCRIPTOR_SIGNATURE_V2\0".to_vec();
    signing_bytes.extend_from_slice(descriptor_digest.as_bytes());
    let signed = SignedToolDescriptorV2::new_for_test(
        minicbor::to_vec(&unsigned).unwrap(),
        publisher_key_id,
        signing_key.sign(&signing_bytes).to_bytes(),
    );
    let canonical = minicbor::to_vec(&signed).unwrap();
    let parsed = SignedToolDescriptorV2::from_canonical_bytes(&canonical).unwrap();
    let publisher = VerifiedRegistryPublisherV2::new_for_test(
        publisher_key_id,
        signing_key.verifying_key().to_bytes(),
        UnixMillisV2::new(100),
        UnixMillisV2::new(1_000),
    )
    .unwrap();
    let verified = parsed
        .verify(&publisher, VersionV2::new(4, 5, 6), UnixMillisV2::new(500))
        .unwrap();

    assert_eq!(verified.descriptor_digest(), descriptor_digest);
    assert_eq!(verified.unsigned().provider_tool_id().as_str(), "mail.send");
    assert_eq!(minicbor::to_vec(&parsed).unwrap(), canonical);

    let mut mutated = canonical.clone();
    *mutated.last_mut().unwrap() ^= 1;
    assert_eq!(
        SignedToolDescriptorV2::from_canonical_bytes(&mutated)
            .unwrap()
            .verify(&publisher, VersionV2::new(4, 5, 6), UnixMillisV2::new(500))
            .unwrap_err(),
        G4Error::InvalidDescriptorSignature
    );

    let mut noncanonical = canonical;
    noncanonical.splice(0..1, [0x98, 0x03]);
    assert_eq!(
        SignedToolDescriptorV2::from_canonical_bytes(&noncanonical).unwrap_err(),
        G4Error::NonCanonicalDescriptor
    );
    assert_eq!(
        signed
            .verify(
                &publisher,
                VersionV2::new(4, 5, 6),
                UnixMillisV2::new(1_000)
            )
            .unwrap_err(),
        G4Error::DescriptorNotActive
    );
    assert_eq!(
        signed
            .verify(&publisher, VersionV2::new(4, 5, 7), UnixMillisV2::new(500))
            .unwrap_err(),
        G4Error::RegistryVersionMismatch
    );
}

#[test]
fn descriptor_validation_rejects_role_validator_and_projection_ambiguity() {
    assert_eq!(
        UnsignedToolDescriptorV2::new_for_test(
            VersionV2::new(1, 0, 0),
            vec![RoleIdV2::new(2), RoleIdV2::new(2)],
            vec![validator(1)],
            ProjectionIdV2::new(1),
            Digest32V2::new([7; 32]),
        )
        .unwrap_err(),
        G4Error::NonCanonicalOrder
    );
    assert_eq!(
        UnsignedToolDescriptorV2::new_for_test(
            VersionV2::new(1, 0, 0),
            vec![RoleIdV2::new(2)],
            vec![validator(1), validator(1)],
            ProjectionIdV2::new(1),
            Digest32V2::new([7; 32]),
        )
        .unwrap_err(),
        G4Error::DuplicateValidatorImplementation
    );
    assert_eq!(
        UnsignedToolDescriptorV2::new_for_test(
            VersionV2::new(1, 0, 0),
            vec![RoleIdV2::new(2)],
            vec![validator(1)],
            ProjectionIdV2::new(0),
            Digest32V2::new([0; 32]),
        )
        .unwrap_err(),
        G4Error::InvalidProjectionBinding
    );
}

#[test]
fn active_registry_is_the_exact_policy_registry_intersection() {
    let registry_version = VersionV2::new(2, 0, 0);
    let first = verified_descriptor(registry_version, 0x51, "mail.read");
    let second = verified_descriptor(registry_version, 0x61, "mail.send");
    let first_digest = first.descriptor_digest();
    let second_digest = second.descriptor_digest();
    let registry =
        VerifiedToolRegistryV2::new_for_test(registry_version, vec![first.clone(), second.clone()])
            .unwrap();
    let policy = VerifiedPolicyToolSetV2::new_for_test(vec![
        VerifiedPolicyToolActivationV2::new_for_test(first_digest, 0, Digest32V2::new([0xa1; 32])),
        VerifiedPolicyToolActivationV2::new_for_test(
            Digest32V2::new([0xff; 32]),
            1,
            Digest32V2::new([0xa2; 32]),
        ),
    ])
    .unwrap();
    let mut manifest_entries = vec![
        VerifiedManifestToolConstraintV2::new_for_test(
            first_digest,
            2,
            500_000_000,
            first.unsigned().internal_validators().to_vec(),
        ),
        VerifiedManifestToolConstraintV2::new_for_test(
            second_digest,
            2,
            500_000_000,
            second.unsigned().internal_validators().to_vec(),
        ),
    ];
    manifest_entries.sort_unstable_by(|left, right| {
        left.descriptor_digest
            .as_bytes()
            .cmp(right.descriptor_digest.as_bytes())
    });
    let constraints = VerifiedManifestToolConstraintSetV2::new_for_test(manifest_entries).unwrap();
    let active = ActiveToolRegistryV2::intersect(&registry, &policy, &constraints).unwrap();

    assert_eq!(active.len(), 1);
    let active_first = active
        .resolve(first_digest, RoleIdV2::new(1), UnixMillisV2::new(500))
        .unwrap();
    assert_eq!(active_first.descriptor().descriptor_digest(), first_digest);
    assert_eq!(active_first.effective_retry_policy().maximum_attempts(), 2);
    assert!(active
        .resolve(second_digest, RoleIdV2::new(1), UnixMillisV2::new(500))
        .is_none());
    assert!(active
        .resolve(first_digest, RoleIdV2::new(9), UnixMillisV2::new(500))
        .is_none());
    assert!(active
        .resolve(first_digest, RoleIdV2::new(1), UnixMillisV2::new(900))
        .is_none());
}

fn validator(id: u32) -> InternalValidatorDeclarationV2 {
    InternalValidatorDeclarationV2::new(
        ImplementationIdV2::new(id),
        VersionV2::new(1, 0, 0),
        Digest32V2::new([id as u8; 32]),
    )
}

fn descriptor(
    registry_version: VersionV2,
    roles: Vec<RoleIdV2>,
    validators: Vec<InternalValidatorDeclarationV2>,
) -> UnsignedToolDescriptorV2 {
    UnsignedToolDescriptorV2::new_for_test(
        registry_version,
        roles,
        validators,
        ProjectionIdV2::new(3),
        Digest32V2::new([7; 32]),
    )
    .unwrap()
}

fn verified_descriptor(
    registry_version: VersionV2,
    seed: u8,
    tool_id: &str,
) -> super::VerifiedToolDescriptorV2 {
    let signing_key = SigningKey::from_bytes(&[seed; 32]);
    let publisher_key_id = Ed25519KeyIdV2::new([seed.wrapping_add(1); 32]);
    let mut unsigned = descriptor(
        registry_version,
        vec![RoleIdV2::new(1)],
        vec![validator(u32::from(seed))],
    );
    unsigned.provider_tool_id = IdentifierV2::new(tool_id).unwrap();
    let digest = descriptor_digest_v2(&unsigned).unwrap();
    let mut signing_bytes = b"SAVANA_TOOL_DESCRIPTOR_SIGNATURE_V2\0".to_vec();
    signing_bytes.extend_from_slice(digest.as_bytes());
    let signed = SignedToolDescriptorV2::new_for_test(
        minicbor::to_vec(unsigned).unwrap(),
        publisher_key_id,
        signing_key.sign(&signing_bytes).to_bytes(),
    );
    let publisher = VerifiedRegistryPublisherV2::new_for_test(
        publisher_key_id,
        signing_key.verifying_key().to_bytes(),
        UnixMillisV2::new(1),
        UnixMillisV2::new(2_000),
    )
    .unwrap();
    signed
        .verify(&publisher, registry_version, UnixMillisV2::new(500))
        .unwrap()
}
