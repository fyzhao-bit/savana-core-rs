use ed25519_dalek::SigningKey;
use savana_kernel_protocol::v2::{derive_ed25519_key_id_v2, Digest32V2};
use savana_policy_core::v2::{
    AuthenticatedNativeDeploymentTrustV2, ClosedSecurityDomainV2, ComponentSignerAuthorizationV2,
    InstallerOrMdmVerifierV2, ManifestComponentKindV2, ManifestComponentRefV2,
    NativeDeploymentBootstrapTrustMaterialV2, OperationalTrustRootPurposeV2,
    OperationalTrustRootSetBindingV2, OperationalTrustRootSetItemV2, OperationalTrustRootSetV2,
    ReleaseRootKeyV2, ReleaseSigningRoleV2, ReleaseTrustRootSetV2, VersionedIdentityV2,
};

fn digest(byte: u8) -> Digest32V2 {
    Digest32V2::new([byte; 32])
}

fn root(purpose: OperationalTrustRootPurposeV2, byte: u8) -> OperationalTrustRootSetItemV2 {
    OperationalTrustRootSetItemV2::new(
        purpose,
        SigningKey::from_bytes(&[byte; 32])
            .verifying_key()
            .to_bytes(),
        1,
        10,
        90,
    )
    .unwrap()
}

fn sort_roots(items: &mut [OperationalTrustRootSetItemV2]) {
    items.sort_by_key(|item| {
        (
            item.purpose().tag(),
            *item.key_id().as_bytes(),
            item.key_epoch(),
        )
    });
}

#[test]
fn deployment_and_activation_root_sets_are_complete_signed_closed_objects() {
    let installer = SigningKey::from_bytes(&[1; 32]);
    let verifier = InstallerOrMdmVerifierV2::new(
        derive_ed25519_key_id_v2(installer.verifying_key().to_bytes()),
        7,
        installer.verifying_key().to_bytes(),
    )
    .unwrap();
    let mut deployment_members = vec![
        root(OperationalTrustRootPurposeV2::RollbackAuthorization, 3),
        root(OperationalTrustRootPurposeV2::DeploymentAuthorization, 2),
    ];
    sort_roots(&mut deployment_members);
    let deployment = OperationalTrustRootSetV2::new_deployment_signed_for_test(
        digest(4),
        1,
        None,
        deployment_members.clone(),
        5,
        100,
        &installer,
        7,
    )
    .unwrap();
    assert_eq!(
        OperationalTrustRootSetV2::from_canonical_bytes(deployment.canonical_bytes(), &verifier)
            .unwrap(),
        deployment
    );
    assert!(matches!(
        deployment.binding(),
        OperationalTrustRootSetBindingV2::Deployment { .. }
    ));
    assert_ne!(
        deployment.binding().member_set_digest(),
        deployment.signed_digest()
    );
    let deployment_authorizer = deployment_members
        .iter()
        .find(|item| item.purpose() == OperationalTrustRootPurposeV2::DeploymentAuthorization)
        .unwrap();
    assert!(deployment
        .authorization_verifier(
            OperationalTrustRootPurposeV2::DeploymentAuthorization,
            deployment_authorizer.key_id(),
            deployment_authorizer.key_epoch(),
            50,
        )
        .is_ok());
    assert!(deployment
        .authorization_verifier(
            OperationalTrustRootPurposeV2::DeploymentAuthorization,
            deployment_authorizer.key_id(),
            deployment_authorizer.key_epoch(),
            101,
        )
        .is_err());

    let activation_member = root(OperationalTrustRootPurposeV2::InstallationActivation, 5);
    let activation = OperationalTrustRootSetV2::new_activation_signed_for_test(
        digest(4),
        1,
        None,
        vec![activation_member.clone()],
        5,
        100,
        &installer,
        7,
    )
    .unwrap();
    assert!(activation
        .activation_verifier(
            digest(6),
            activation_member.key_id(),
            activation_member.key_epoch(),
            50,
        )
        .is_ok());
    let identity = VersionedIdentityV2::new(
        ClosedSecurityDomainV2::ActivationTrustRootSet,
        activation.root_set_sequence(),
        activation.signed_digest(),
        verifier.key_id(),
        verifier.key_epoch(),
        activation.not_before_unix_ms(),
        activation.not_after_unix_ms(),
    )
    .unwrap();
    activation.matches_versioned_identity(&identity).unwrap();
}

#[test]
fn declassification_root_set_has_closed_binding_purpose_and_domain() {
    let installer = SigningKey::from_bytes(&[0x31; 32]);
    let verifier = InstallerOrMdmVerifierV2::new(
        derive_ed25519_key_id_v2(installer.verifying_key().to_bytes()),
        11,
        installer.verifying_key().to_bytes(),
    )
    .unwrap();
    let member = root(
        OperationalTrustRootPurposeV2::DeclassificationAuthority,
        0x32,
    );
    let set = OperationalTrustRootSetV2::new_declassification_signed_for_test(
        digest(0x33),
        1,
        None,
        vec![member],
        5,
        100,
        &installer,
        11,
    )
    .unwrap();

    assert!(matches!(
        set.binding(),
        OperationalTrustRootSetBindingV2::Declassification { .. }
    ));
    assert_eq!(set.binding().tag(), 3);
    assert_eq!(
        OperationalTrustRootPurposeV2::DeclassificationAuthority.tag(),
        5
    );
    let decoded =
        OperationalTrustRootSetV2::from_canonical_bytes(set.canonical_bytes(), &verifier).unwrap();
    let identity = VersionedIdentityV2::new(
        ClosedSecurityDomainV2::DeclassificationTrustRootSet,
        decoded.root_set_sequence(),
        decoded.signed_digest(),
        verifier.key_id(),
        verifier.key_epoch(),
        decoded.not_before_unix_ms(),
        decoded.not_after_unix_ms(),
    )
    .unwrap();
    decoded.matches_versioned_identity(&identity).unwrap();
    let wrong_version = VersionedIdentityV2::new(
        ClosedSecurityDomainV2::DeclassificationTrustRootSet,
        decoded.root_set_sequence() + 1,
        decoded.signed_digest(),
        verifier.key_id(),
        verifier.key_epoch(),
        decoded.not_before_unix_ms(),
        decoded.not_after_unix_ms(),
    )
    .unwrap();
    assert!(decoded.matches_versioned_identity(&wrong_version).is_err());
}

#[test]
fn operational_root_sets_reject_wrong_purpose_key_reuse_and_chain_forks() {
    let installer = SigningKey::from_bytes(&[10; 32]);
    let deployment_only = vec![root(
        OperationalTrustRootPurposeV2::DeploymentAuthorization,
        11,
    )];
    assert!(OperationalTrustRootSetV2::new_deployment_signed_for_test(
        digest(12),
        1,
        None,
        deployment_only,
        5,
        100,
        &installer,
        1,
    )
    .is_err());

    let shared_key = SigningKey::from_bytes(&[13; 32]).verifying_key().to_bytes();
    let mut reused = vec![
        OperationalTrustRootSetItemV2::new(
            OperationalTrustRootPurposeV2::DeploymentAuthorization,
            shared_key,
            1,
            10,
            90,
        )
        .unwrap(),
        OperationalTrustRootSetItemV2::new(
            OperationalTrustRootPurposeV2::RollbackAuthorization,
            shared_key,
            2,
            10,
            90,
        )
        .unwrap(),
    ];
    sort_roots(&mut reused);
    assert!(OperationalTrustRootSetV2::new_deployment_signed_for_test(
        digest(12),
        1,
        None,
        reused,
        5,
        100,
        &installer,
        1,
    )
    .is_err());

    let mut first_members = vec![
        root(OperationalTrustRootPurposeV2::DeploymentAuthorization, 14),
        root(OperationalTrustRootPurposeV2::RollbackAuthorization, 15),
    ];
    sort_roots(&mut first_members);
    let first = OperationalTrustRootSetV2::new_deployment_signed_for_test(
        digest(16),
        1,
        None,
        first_members.clone(),
        5,
        100,
        &installer,
        1,
    )
    .unwrap();
    let second = OperationalTrustRootSetV2::new_deployment_signed_for_test(
        digest(16),
        2,
        Some(first.signed_digest()),
        first_members,
        5,
        100,
        &installer,
        1,
    )
    .unwrap();
    second.validate_predecessor(Some(&first)).unwrap();
    assert!(second.validate_predecessor(None).is_err());

    let mut mutated = second.canonical_bytes().to_vec();
    *mutated.last_mut().unwrap() ^= 1;
    let verifier = InstallerOrMdmVerifierV2::new(
        derive_ed25519_key_id_v2(installer.verifying_key().to_bytes()),
        1,
        installer.verifying_key().to_bytes(),
    )
    .unwrap();
    assert!(OperationalTrustRootSetV2::from_canonical_bytes(&mutated, &verifier).is_err());
}

#[test]
fn native_bootstrap_trust_requires_four_complete_same_product_chains() {
    let installer = SigningKey::from_bytes(&[0x21; 32]);
    let family = digest(0x22);
    let mut deployment_members = vec![
        root(OperationalTrustRootPurposeV2::DeploymentAuthorization, 0x23),
        root(OperationalTrustRootPurposeV2::RollbackAuthorization, 0x24),
    ];
    sort_roots(&mut deployment_members);
    let deployment = OperationalTrustRootSetV2::new_deployment_signed_for_test(
        family,
        1,
        None,
        deployment_members,
        5,
        100,
        &installer,
        9,
    )
    .unwrap();
    let activation = OperationalTrustRootSetV2::new_activation_signed_for_test(
        family,
        1,
        None,
        vec![root(
            OperationalTrustRootPurposeV2::InstallationActivation,
            0x25,
        )],
        5,
        100,
        &installer,
        9,
    )
    .unwrap();
    let declassification = OperationalTrustRootSetV2::new_declassification_signed_for_test(
        family,
        1,
        None,
        vec![root(
            OperationalTrustRootPurposeV2::DeclassificationAuthority,
            0x2a,
        )],
        5,
        100,
        &installer,
        9,
    )
    .unwrap();
    let component = SigningKey::from_bytes(&[0x26; 32]);
    let release = SigningKey::from_bytes(&[0x27; 32]);
    let component_ref =
        ManifestComponentRefV2::new(ManifestComponentKindV2::BinaryArtifact, digest(0x28)).unwrap();
    let release_roots = vec![
        ReleaseRootKeyV2::new(
            ReleaseSigningRoleV2::ManifestComponent,
            component.verifying_key().to_bytes(),
            1,
            5,
            100,
        )
        .unwrap(),
        ReleaseRootKeyV2::new(
            ReleaseSigningRoleV2::ManifestRelease,
            release.verifying_key().to_bytes(),
            1,
            5,
            100,
        )
        .unwrap(),
    ];
    let release_set = ReleaseTrustRootSetV2::new_signed_for_test(
        family,
        1,
        None,
        release_roots,
        vec![ComponentSignerAuthorizationV2::new(
            digest(0x29),
            component_ref,
            derive_ed25519_key_id_v2(component.verifying_key().to_bytes()),
            1,
        )
        .unwrap()],
        5,
        100,
        &installer,
        9,
    )
    .unwrap();
    let material = NativeDeploymentBootstrapTrustMaterialV2::new_for_test(
        *derive_ed25519_key_id_v2(installer.verifying_key().to_bytes()).as_bytes(),
        9,
        installer.verifying_key().to_bytes(),
        vec![deployment.canonical_bytes().to_vec()],
        vec![activation.canonical_bytes().to_vec()],
        vec![declassification.canonical_bytes().to_vec()],
        vec![release_set.canonical_bytes().to_vec()],
    )
    .unwrap();

    let authenticated = AuthenticatedNativeDeploymentTrustV2::verify(&material).unwrap();
    assert_eq!(
        authenticated.deployment_trust_root_set().signed_digest(),
        deployment.signed_digest()
    );
    assert_eq!(
        authenticated.activation_trust_root_set().signed_digest(),
        activation.signed_digest()
    );
    assert_eq!(
        authenticated.release_trust_root_set().signed_digest(),
        release_set.signed_digest()
    );
    assert_eq!(
        authenticated
            .declassification_trust_root_set()
            .signed_digest(),
        declassification.signed_digest()
    );

    let wrong_family_release = ReleaseTrustRootSetV2::new_signed_for_test(
        digest(0x30),
        1,
        None,
        release_set.roots().to_vec(),
        release_set.component_authorizations().to_vec(),
        5,
        100,
        &installer,
        9,
    )
    .unwrap();
    let mismatched = NativeDeploymentBootstrapTrustMaterialV2::new_for_test(
        *derive_ed25519_key_id_v2(installer.verifying_key().to_bytes()).as_bytes(),
        9,
        installer.verifying_key().to_bytes(),
        vec![deployment.canonical_bytes().to_vec()],
        vec![activation.canonical_bytes().to_vec()],
        vec![declassification.canonical_bytes().to_vec()],
        vec![wrong_family_release.canonical_bytes().to_vec()],
    )
    .unwrap();
    assert!(AuthenticatedNativeDeploymentTrustV2::verify(&mismatched).is_err());

    let wrong_domain = NativeDeploymentBootstrapTrustMaterialV2::new_for_test(
        *derive_ed25519_key_id_v2(installer.verifying_key().to_bytes()).as_bytes(),
        9,
        installer.verifying_key().to_bytes(),
        vec![deployment.canonical_bytes().to_vec()],
        vec![activation.canonical_bytes().to_vec()],
        vec![activation.canonical_bytes().to_vec()],
        vec![release_set.canonical_bytes().to_vec()],
    )
    .unwrap();
    assert!(AuthenticatedNativeDeploymentTrustV2::verify(&wrong_domain).is_err());

    let wrong_family_declassification =
        OperationalTrustRootSetV2::new_declassification_signed_for_test(
            digest(0x30),
            1,
            None,
            declassification.members().to_vec(),
            5,
            100,
            &installer,
            9,
        )
        .unwrap();
    let mismatched_declassification = NativeDeploymentBootstrapTrustMaterialV2::new_for_test(
        *derive_ed25519_key_id_v2(installer.verifying_key().to_bytes()).as_bytes(),
        9,
        installer.verifying_key().to_bytes(),
        vec![deployment.canonical_bytes().to_vec()],
        vec![activation.canonical_bytes().to_vec()],
        vec![wrong_family_declassification.canonical_bytes().to_vec()],
        vec![release_set.canonical_bytes().to_vec()],
    )
    .unwrap();
    assert!(AuthenticatedNativeDeploymentTrustV2::verify(&mismatched_declassification).is_err());
}
