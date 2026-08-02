use std::os::unix::fs::PermissionsExt as _;

use savana_kernel_protocol::v2::{derive_ed25519_key_id_v2, Digest32V2, Nonce32V2};
use savana_policy_core::v2::{
    AgentClaimCompatibilityDirectionV2, AgentClaimCompatibilityMaterialV2,
    AgentClaimCompatibilitySetV2, AgentClaimCompatibilityV2, AgentViewProjectionSetItemV2,
    ArtifactIdentityV2, ArtifactInstallPlanV2, ArtifactSetIdentityV2, BinaryClosureV2,
    BootstrapTcbLockV2, ClosedArtifactTypeV2, ClosedDigestRuleV2, ClosedDurableDeploymentStepV2,
    ClosedLogicalPathIdV2, ClosedSecurityDomainV2, ClosedTargetArchitectureV2, ClosedTargetOsV2,
    ComponentSignerAuthorizationV2, DeploymentActivationUpdateV2, DeploymentActivationVerifierV2,
    DeploymentAuthorizationVerifierV2, DeploymentBranchV2, DeploymentLedgerRecordV2,
    DeploymentLedgerStoreV2, DeploymentOwnerClaimV2, DeploymentOwnerRoleV2, DeploymentPhaseV2,
    DeploymentRecoveryActionV2, DeploymentRecoveryTargetV2, DeploymentTransactionIntentMaterialV2,
    DeploymentTransactionIntentV2, DeploymentTransactionV2,
    DurableDeploymentAuxiliaryEvidenceStoreV2, DurableDeploymentCoreKeyDiscoveryStoreV2,
    DurableDeploymentEvidenceRefV2, DurableDeploymentRecoveryTargetV2,
    DurableDeploymentTransactionCoreMaterialV2, DurableDeploymentTransactionCoreStoreV2,
    DurableDeploymentTransactionCoreV2, DurableDeploymentTransactionRecordV2,
    DurableDeploymentTransactionStoreV2, DurableDeploymentTransitionStoreV2,
    DurableInstallationEvidenceStoreV2, EvidenceContractV2, ExpectedPreStateV2, FileTreeEntryV2,
    FileTreeV2, FrozenEffectWorkSetV2, InclusiveEpochRangeV2, InstallationClassV2,
    InstallerOrMdmVerifierV2, IsolatedE2EPlanV2, LedgerSlotIdV2, ManifestComponentKindV2,
    ManifestComponentRefV2, MigrationPlanV2, NativeControlMeasurementSetItemV2,
    NativeControlMeasurementSetV2, PersistentStoreCompatibilitySetV2,
    PersistentStoreCompatibilityV2, PlatformClosureV2, PlatformLockV2, ProtectedAcceptancePlanV2,
    RecoveryPhaseHighWaterV2, ReleaseRootKeyV2, ReleaseSigningRoleV2, ReleaseTrustRootSetV2,
    RollbackGrantStateV2, RollbackGrantV2, SecurityStateClosureV2, SecurityStateManifestMaterialV2,
    SecurityStateManifestV2, ServiceTransitionPlanV2, SignedLedgerSlotV2, SourceLockV2,
    TestNativeDeploymentSigningAuthorityV2, TestNativeRollbackAuthorityV2, VaultKeyReadSetItemV2,
    VersionedIdentityV2,
};

fn digest(byte: u8) -> Digest32V2 {
    Digest32V2::new([byte; 32])
}

fn worker(byte: u8) -> ArtifactIdentityV2 {
    artifact(ClosedArtifactTypeV2::Worker, byte)
}

fn artifact(artifact_type: ClosedArtifactTypeV2, byte: u8) -> ArtifactIdentityV2 {
    ArtifactIdentityV2::new(
        artifact_type,
        ClosedTargetOsV2::Linux,
        ClosedTargetArchitectureV2::X86_64,
        1,
        digest(byte),
        digest(byte.wrapping_add(1)),
        digest(byte.wrapping_add(2)),
    )
    .expect("worker identity")
}

fn identity(domain: ClosedSecurityDomainV2, byte: u8) -> VersionedIdentityV2 {
    VersionedIdentityV2::new(
        domain,
        1,
        digest(byte),
        savana_kernel_protocol::v2::Ed25519KeyIdV2::new([byte.wrapping_add(1); 32]),
        1,
        10,
        20,
    )
    .expect("versioned identity")
}

#[test]
fn manifest_primitives_round_trip_and_reject_ambiguous_sets() {
    let source = SourceLockV2::new(digest(1), digest(2), digest(3), digest(4), digest(5))
        .expect("source lock");
    assert_eq!(
        SourceLockV2::from_canonical_bytes(source.canonical_bytes()).expect("decode"),
        source
    );

    let identity = VersionedIdentityV2::new(
        ClosedSecurityDomainV2::Policy,
        7,
        digest(6),
        savana_kernel_protocol::v2::Ed25519KeyIdV2::new([7; 32]),
        8,
        10,
        20,
    )
    .expect("versioned identity");
    assert_eq!(
        VersionedIdentityV2::from_canonical_bytes(identity.canonical_bytes()).expect("decode"),
        identity
    );

    let first = worker(10);
    let second = worker(20);
    let set = ArtifactSetIdentityV2::new(vec![first.clone()]).expect("worker set");
    assert_eq!(
        ArtifactSetIdentityV2::from_canonical_bytes(set.canonical_bytes()).expect("decode"),
        set
    );
    assert!(ArtifactSetIdentityV2::new(vec![second, first]).is_err());
    assert!(ArtifactSetIdentityV2::new(vec![worker(30), worker(30)]).is_err());

    let range = InclusiveEpochRangeV2::new(3, 9).expect("epoch range");
    assert!(range.contains(3));
    assert!(range.contains(9));
    assert!(!range.contains(10));
    assert_eq!(
        InclusiveEpochRangeV2::from_canonical_bytes(range.canonical_bytes()).expect("decode"),
        range
    );

    assert_eq!(ClosedDigestRuleV2::ExactCanonicalState.tag(), 1);
    assert!(ClosedDigestRuleV2::from_tag(0).is_none());
    assert!(ClosedDigestRuleV2::from_tag(2).is_none());
}

#[test]
fn primitive_decoders_reject_trailing_and_noncanonical_bytes() {
    let source = SourceLockV2::new(digest(1), digest(2), digest(3), digest(4), digest(5))
        .expect("source lock");
    let mut trailing = source.canonical_bytes().to_vec();
    trailing.push(0);
    assert!(SourceLockV2::from_canonical_bytes(&trailing).is_err());

    // [1, 0] uses an invalid zero lower bound.
    assert!(InclusiveEpochRangeV2::from_canonical_bytes(&[0x82, 0x01, 0x00]).is_err());
}

#[test]
fn fixed_manifest_closures_round_trip_and_lock_roles() {
    let binary = BinaryClosureV2::new(
        artifact(ClosedArtifactTypeV2::ControlShell, 1),
        artifact(ClosedArtifactTypeV2::Daemon, 4),
        artifact(ClosedArtifactTypeV2::Daemon, 7),
        artifact(ClosedArtifactTypeV2::Daemon, 10),
        artifact(ClosedArtifactTypeV2::Daemon, 13),
        artifact(ClosedArtifactTypeV2::Daemon, 16),
        artifact(ClosedArtifactTypeV2::CommandLineTool, 19),
        artifact(ClosedArtifactTypeV2::Worker, 21),
        ArtifactSetIdentityV2::new(vec![worker(22)]).expect("parser set"),
        ArtifactSetIdentityV2::new(vec![worker(25)]).expect("connector set"),
    )
    .expect("binary closure");
    assert_eq!(
        BinaryClosureV2::from_canonical_bytes(binary.canonical_bytes()).expect("decode"),
        binary
    );

    let security_domains: [ClosedSecurityDomainV2; 18] = ClosedSecurityDomainV2::ALL[1..19]
        .try_into()
        .expect("domains");
    let security = SecurityStateClosureV2::new(std::array::from_fn(|index| {
        identity(security_domains[index], 40 + index as u8)
    }))
    .expect("security closure");
    assert_eq!(
        SecurityStateClosureV2::from_canonical_bytes(security.canonical_bytes()).expect("decode"),
        security
    );

    let platform_domains: [ClosedSecurityDomainV2; 6] = ClosedSecurityDomainV2::ALL[19..25]
        .try_into()
        .expect("domains");
    let platform = PlatformClosureV2::new(std::array::from_fn(|index| {
        identity(platform_domains[index], 70 + index as u8)
    }))
    .expect("platform closure");
    assert_eq!(
        PlatformClosureV2::from_canonical_bytes(platform.canonical_bytes()).expect("decode"),
        platform
    );

    let bootstrap = BootstrapTcbLockV2::new(
        artifact(ClosedArtifactTypeV2::RootHelper, 90),
        artifact(ClosedArtifactTypeV2::Watchdog, 93),
        artifact(ClosedArtifactTypeV2::RecoveryTool, 96),
        artifact(ClosedArtifactTypeV2::LedgerVerifier, 99),
        digest(102),
        digest(103),
        digest(104),
        digest(105),
        identity(ClosedSecurityDomainV2::DeploymentTrustRootSet, 106),
        identity(ClosedSecurityDomainV2::ActivationTrustRootSet, 109),
        identity(ClosedSecurityDomainV2::ReleaseTrustRootSet, 112),
        identity(ClosedSecurityDomainV2::DeclassificationTrustRootSet, 115),
        1,
    )
    .expect("bootstrap closure");
    assert_eq!(
        BootstrapTcbLockV2::from_canonical_bytes(bootstrap.canonical_bytes()).expect("decode"),
        bootstrap
    );

    assert!(BinaryClosureV2::new(
        artifact(ClosedArtifactTypeV2::Daemon, 1),
        artifact(ClosedArtifactTypeV2::Daemon, 4),
        artifact(ClosedArtifactTypeV2::Daemon, 7),
        artifact(ClosedArtifactTypeV2::Daemon, 10),
        artifact(ClosedArtifactTypeV2::Daemon, 13),
        artifact(ClosedArtifactTypeV2::Daemon, 16),
        artifact(ClosedArtifactTypeV2::CommandLineTool, 19),
        artifact(ClosedArtifactTypeV2::Worker, 21),
        ArtifactSetIdentityV2::new(vec![worker(22)]).expect("parser set"),
        ArtifactSetIdentityV2::new(vec![worker(25)]).expect("connector set"),
    )
    .is_err());
}

#[test]
fn persistent_store_compatibility_is_exact_and_complete() {
    let entries = std::array::from_fn(|index| {
        let store_id = savana_policy_core::v2::ClosedStoreIdV2::ALL[index];
        PersistentStoreCompatibilityV2::new(
            store_id,
            1,
            InclusiveEpochRangeV2::new(1, 2).expect("reader"),
            InclusiveEpochRangeV2::new(1, 1).expect("writer"),
            InclusiveEpochRangeV2::new(1, 2).expect("reader"),
            InclusiveEpochRangeV2::new(1, 1).expect("writer"),
            digest(120 + index as u8),
            ClosedDigestRuleV2::ExactCanonicalState,
            digest(140 + index as u8),
        )
        .expect("compatibility")
    });
    let set = PersistentStoreCompatibilitySetV2::new(entries).expect("complete set");
    assert_eq!(
        PersistentStoreCompatibilitySetV2::from_canonical_bytes(set.canonical_bytes())
            .expect("decode"),
        set
    );

    let mut wrong = set.entries().clone();
    wrong.swap(0, 1);
    assert!(PersistentStoreCompatibilitySetV2::new(wrong).is_err());
    assert!(PersistentStoreCompatibilityV2::new(
        savana_policy_core::v2::ClosedStoreIdV2::KerneldVault,
        1,
        InclusiveEpochRangeV2::new(1, 1).expect("reader"),
        InclusiveEpochRangeV2::new(1, 2).expect("writer"),
        InclusiveEpochRangeV2::new(1, 1).expect("reader"),
        InclusiveEpochRangeV2::new(1, 1).expect("writer"),
        digest(1),
        ClosedDigestRuleV2::ExactCanonicalState,
        digest(2),
    )
    .is_err());
}

#[test]
fn agent_claim_edge_uses_acyclic_lineage_and_exact_nested_sets() {
    let material = AgentClaimCompatibilityMaterialV2 {
        direction: AgentClaimCompatibilityDirectionV2::FromOldManifestIntoDestinationReadOnly,
        from_manifest_lineage_digest: digest(1),
        to_manifest_lineage_digest: digest(2),
        logical_agentd_identity_digest: digest(3),
        from_agentd_code_identity_digest: digest(4),
        to_agentd_code_identity_digest: digest(5),
        from_kerneld_code_identity_digest: digest(6),
        to_kerneld_code_identity_digest: digest(7),
        from_protocol_lock_digest: digest(8),
        to_protocol_lock_digest: digest(9),
        protocol_abi_digest: digest(9),
        claim_schema_digest: digest(10),
        store_id: savana_policy_core::v2::ClosedStoreIdV2::AgentdRecovery,
        from_store_schema_epoch: 1,
        to_store_schema_epoch: 2,
        persistent_store_compatibility_digest: digest(11),
        vault_key_read_set: vec![VaultKeyReadSetItemV2::new(
            1,
            savana_kernel_protocol::v2::VaultKeyIdV2::new([12; 32]),
            1,
        )
        .expect("vault key")],
        agent_view_projection_set: vec![
            AgentViewProjectionSetItemV2::new(1, digest(13)).expect("view projection")
        ],
        not_before_unix_ms: 10,
        expires_at_unix_ms: 20,
    };
    let edge = AgentClaimCompatibilityV2::new(material.clone()).expect("edge");
    assert_eq!(
        AgentClaimCompatibilityV2::from_canonical_bytes(edge.canonical_bytes()).expect("decode"),
        edge
    );
    let set = AgentClaimCompatibilitySetV2::new(vec![edge]).expect("set");
    assert_eq!(
        AgentClaimCompatibilitySetV2::from_canonical_bytes(set.canonical_bytes()).expect("decode"),
        set
    );

    let mut cyclic = material;
    cyclic.to_manifest_lineage_digest = cyclic.from_manifest_lineage_digest;
    assert!(AgentClaimCompatibilityV2::new(cyclic).is_err());
}

#[test]
fn installer_signed_release_root_set_round_trips_and_binds_component_authority() {
    let installer = ed25519_dalek::SigningKey::from_bytes(&[1; 32]);
    let component = ed25519_dalek::SigningKey::from_bytes(&[2; 32]);
    let release = ed25519_dalek::SigningKey::from_bytes(&[3; 32]);
    let component_ref =
        ManifestComponentRefV2::new(ManifestComponentKindV2::BinaryArtifact, digest(4))
            .expect("component");
    let roots = vec![
        ReleaseRootKeyV2::new(
            ReleaseSigningRoleV2::ManifestComponent,
            component.verifying_key().to_bytes(),
            1,
            10,
            30,
        )
        .expect("component root"),
        ReleaseRootKeyV2::new(
            ReleaseSigningRoleV2::ManifestRelease,
            release.verifying_key().to_bytes(),
            1,
            10,
            30,
        )
        .expect("release root"),
    ];
    let authorizations = vec![ComponentSignerAuthorizationV2::new(
        digest(5),
        component_ref,
        savana_kernel_protocol::v2::derive_ed25519_key_id_v2(component.verifying_key().to_bytes()),
        1,
    )
    .expect("authorization")];
    let root_set = ReleaseTrustRootSetV2::new_signed_for_test(
        digest(6),
        1,
        None,
        roots,
        authorizations,
        10,
        30,
        &installer,
        1,
    )
    .expect("root set");
    let verifier = InstallerOrMdmVerifierV2::new(
        savana_kernel_protocol::v2::derive_ed25519_key_id_v2(installer.verifying_key().to_bytes()),
        1,
        installer.verifying_key().to_bytes(),
    )
    .expect("installer verifier");
    assert_eq!(
        ReleaseTrustRootSetV2::from_canonical_bytes(root_set.canonical_bytes(), &verifier)
            .expect("decode"),
        root_set
    );
    root_set
        .validate_predecessor(None)
        .expect("genesis predecessor");

    let shared_key_id = derive_ed25519_key_id_v2(component.verifying_key().to_bytes());
    let separating_key = (4_u8..=u8::MAX)
        .map(|byte| ed25519_dalek::SigningKey::from_bytes(&[byte; 32]))
        .find(|candidate| {
            derive_ed25519_key_id_v2(candidate.verifying_key().to_bytes()).as_bytes()
                > shared_key_id.as_bytes()
        })
        .expect("a deterministic separating key");
    let mut reused_roots = vec![
        ReleaseRootKeyV2::new(
            ReleaseSigningRoleV2::ManifestComponent,
            component.verifying_key().to_bytes(),
            1,
            10,
            30,
        )
        .expect("shared component root"),
        ReleaseRootKeyV2::new(
            ReleaseSigningRoleV2::ManifestComponent,
            separating_key.verifying_key().to_bytes(),
            1,
            10,
            30,
        )
        .expect("separating component root"),
        ReleaseRootKeyV2::new(
            ReleaseSigningRoleV2::ManifestRelease,
            component.verifying_key().to_bytes(),
            1,
            10,
            30,
        )
        .expect("reused release root"),
    ];
    reused_roots.sort_by_key(|root| {
        (
            root.role().tag(),
            *root.key_id().as_bytes(),
            root.key_epoch(),
        )
    });
    assert!(ReleaseTrustRootSetV2::new_signed_for_test(
        digest(7),
        1,
        None,
        reused_roots,
        Vec::new(),
        10,
        30,
        &installer,
        1,
    )
    .is_err());
}

#[test]
fn complete_security_state_manifest_round_trips_and_rejects_signature_mutation() {
    let installer = ed25519_dalek::SigningKey::from_bytes(&[31; 32]);
    let component = ed25519_dalek::SigningKey::from_bytes(&[32; 32]);
    let release_signer = ed25519_dalek::SigningKey::from_bytes(&[33; 32]);

    let binary = BinaryClosureV2::new(
        artifact(ClosedArtifactTypeV2::ControlShell, 1),
        artifact(ClosedArtifactTypeV2::Daemon, 4),
        artifact(ClosedArtifactTypeV2::Daemon, 7),
        artifact(ClosedArtifactTypeV2::Daemon, 10),
        artifact(ClosedArtifactTypeV2::Daemon, 13),
        artifact(ClosedArtifactTypeV2::Daemon, 16),
        artifact(ClosedArtifactTypeV2::CommandLineTool, 19),
        artifact(ClosedArtifactTypeV2::Worker, 21),
        ArtifactSetIdentityV2::new(vec![worker(22)]).expect("parser set"),
        ArtifactSetIdentityV2::new(vec![worker(25)]).expect("connector set"),
    )
    .expect("binary closure");
    let security_domains: [ClosedSecurityDomainV2; 18] = ClosedSecurityDomainV2::ALL[1..19]
        .try_into()
        .expect("domains");
    let security = SecurityStateClosureV2::new(std::array::from_fn(|index| {
        identity(security_domains[index], 40 + index as u8)
    }))
    .expect("security closure");
    let platform_domains: [ClosedSecurityDomainV2; 6] = ClosedSecurityDomainV2::ALL[19..25]
        .try_into()
        .expect("domains");
    let platform = PlatformClosureV2::new(std::array::from_fn(|index| {
        identity(platform_domains[index], 70 + index as u8)
    }))
    .expect("platform closure");
    let helper = artifact(ClosedArtifactTypeV2::RootHelper, 90);
    let watchdog = artifact(ClosedArtifactTypeV2::Watchdog, 93);

    let mut components = Vec::new();
    for fixed in binary.fixed_artifacts() {
        components.push(
            ManifestComponentRefV2::new(
                ManifestComponentKindV2::BinaryArtifact,
                fixed.identity_digest(),
            )
            .expect("component"),
        );
    }
    for worker_identity in binary
        .parser_worker_set()
        .artifacts()
        .iter()
        .chain(binary.connector_worker_set().artifacts())
    {
        components.push(
            ManifestComponentRefV2::new(
                ManifestComponentKindV2::BinaryArtifact,
                worker_identity.identity_digest(),
            )
            .expect("component"),
        );
    }
    for security_identity in security.identities() {
        components.push(
            ManifestComponentRefV2::new(
                ManifestComponentKindV2::SecurityDomainObject,
                security_identity.content_digest(),
            )
            .expect("component"),
        );
    }
    for platform_identity in platform.identities() {
        components.push(
            ManifestComponentRefV2::new(
                ManifestComponentKindV2::PlatformDomainObject,
                platform_identity.content_digest(),
            )
            .expect("component"),
        );
    }
    for bootstrap in [&helper, &watchdog] {
        components.push(
            ManifestComponentRefV2::new(
                ManifestComponentKindV2::BootstrapArtifact,
                bootstrap.identity_digest(),
            )
            .expect("component"),
        );
    }
    components.sort_by_key(|value| {
        (
            value.kind().tag(),
            *value.component_identity_digest().as_bytes(),
        )
    });

    let component_key_id =
        savana_kernel_protocol::v2::derive_ed25519_key_id_v2(component.verifying_key().to_bytes());
    let authorizations = components
        .iter()
        .enumerate()
        .map(|(index, component_ref)| {
            ComponentSignerAuthorizationV2::new(
                digest(150 + index as u8),
                *component_ref,
                component_key_id,
                1,
            )
            .expect("authorization")
        })
        .collect();
    let roots = vec![
        ReleaseRootKeyV2::new(
            ReleaseSigningRoleV2::ManifestComponent,
            component.verifying_key().to_bytes(),
            1,
            10,
            30,
        )
        .expect("component root"),
        ReleaseRootKeyV2::new(
            ReleaseSigningRoleV2::ManifestRelease,
            release_signer.verifying_key().to_bytes(),
            1,
            10,
            30,
        )
        .expect("release root"),
    ];
    let root_set = ReleaseTrustRootSetV2::new_signed_for_test(
        digest(200),
        1,
        None,
        roots,
        authorizations,
        10,
        30,
        &installer,
        1,
    )
    .expect("root set");
    let release_root_identity = VersionedIdentityV2::new(
        ClosedSecurityDomainV2::ReleaseTrustRootSet,
        1,
        root_set.signed_digest(),
        savana_kernel_protocol::v2::derive_ed25519_key_id_v2(installer.verifying_key().to_bytes()),
        1,
        10,
        30,
    )
    .expect("release root identity");
    let bootstrap = BootstrapTcbLockV2::new(
        helper,
        watchdog,
        artifact(ClosedArtifactTypeV2::RecoveryTool, 96),
        artifact(ClosedArtifactTypeV2::LedgerVerifier, 99),
        digest(202),
        digest(203),
        digest(204),
        digest(205),
        identity(ClosedSecurityDomainV2::DeploymentTrustRootSet, 206),
        identity(ClosedSecurityDomainV2::ActivationTrustRootSet, 209),
        release_root_identity,
        identity(ClosedSecurityDomainV2::DeclassificationTrustRootSet, 212),
        1,
    )
    .expect("bootstrap");
    let stores = PersistentStoreCompatibilitySetV2::new(std::array::from_fn(|index| {
        PersistentStoreCompatibilityV2::new(
            savana_policy_core::v2::ClosedStoreIdV2::ALL[index],
            1,
            InclusiveEpochRangeV2::new(1, 1).expect("range"),
            InclusiveEpochRangeV2::new(1, 1).expect("range"),
            InclusiveEpochRangeV2::new(1, 1).expect("range"),
            InclusiveEpochRangeV2::new(1, 1).expect("range"),
            digest(10 + index as u8),
            ClosedDigestRuleV2::ExactCanonicalState,
            digest(30 + index as u8),
        )
        .expect("store")
    }))
    .expect("stores");
    let file_tree = build_manifest_file_tree(&binary);
    let material = SecurityStateManifestMaterialV2 {
        installation_class: InstallationClassV2::NormalApplication,
        target_platform: PlatformLockV2::new(
            ClosedTargetOsV2::Linux,
            ClosedTargetArchitectureV2::X86_64,
            digest(210),
            digest(211),
            digest(212),
            digest(213),
            digest(214),
        )
        .expect("platform lock"),
        release: identity(ClosedSecurityDomainV2::BinaryRelease, 215),
        source_lock: SourceLockV2::new(
            digest(216),
            digest(217),
            digest(218),
            digest(219),
            digest(220),
        )
        .expect("source lock"),
        binary_closure: binary,
        security_state: security,
        platform_closure: platform,
        bootstrap_tcb_lock: bootstrap,
        persistent_store_compatibility: stores,
        agent_claim_compatibility_edges: AgentClaimCompatibilitySetV2::new(vec![])
            .expect("empty edges"),
        declassification_rule_set_digest: digest(221),
        file_tree,
    };
    let manifest = SecurityStateManifestV2::new_signed_for_test(
        material,
        &root_set,
        &component,
        1,
        &release_signer,
        1,
        20,
    )
    .expect("manifest");
    let decoded =
        SecurityStateManifestV2::from_canonical_bytes(manifest.canonical_bytes(), &root_set, 20)
            .expect("decode manifest");
    assert_eq!(decoded, manifest);
    assert_eq!(
        decoded.material().declassification_rule_set_digest,
        digest(221)
    );
    assert_eq!(
        decoded
            .material()
            .bootstrap_tcb_lock
            .declassification_trust_root_set()
            .domain(),
        ClosedSecurityDomainV2::DeclassificationTrustRootSet
    );
    decoded
        .validate_for_normal_transaction()
        .expect("normal manifest");

    let mut mutated = manifest.canonical_bytes().to_vec();
    let last = mutated.len() - 1;
    mutated[last] ^= 1;
    assert!(SecurityStateManifestV2::from_canonical_bytes(&mutated, &root_set, 20).is_err());

    let desired_manifest = decoded.clone();
    let rollback_manifest = decoded;
    let migration_plan = MigrationPlanV2::new(vec![]).expect("migration");
    let artifact_install_plan =
        ArtifactInstallPlanV2::new(ArtifactInstallPlanV2::complete_operations())
            .expect("install plan");
    let service_transition_plan =
        ServiceTransitionPlanV2::from_canonical_bytes(&service_plan_bytes()).expect("service plan");
    let isolated_e2e_plan =
        IsolatedE2EPlanV2::from_canonical_bytes(&e2e_plan_bytes()).expect("isolated e2e plan");
    let evidence_contract = EvidenceContractV2::from_canonical_bytes(&evidence_contract_bytes())
        .expect("evidence contract");
    let protected_acceptance_plan =
        ProtectedAcceptancePlanV2::from_canonical_bytes(&acceptance_plan_bytes())
            .expect("acceptance plan");
    let desired_material = desired_manifest.material();
    let installation_id = digest(55);
    let installation_epoch = 1;
    let transaction_id = Nonce32V2::new([56; 32]);
    let activation_signing_key = ed25519_dalek::SigningKey::from_bytes(&[104; 32]);
    let selected_ledger = DeploymentLedgerRecordV2::new_signed_for_test(
        installation_id,
        installation_epoch,
        1,
        Digest32V2::new([0; 32]),
        DeploymentPhaseV2::Idle,
        None,
        false,
        1,
        RollbackGrantStateV2::None,
        None,
        9,
        57,
        &activation_signing_key,
    )
    .and_then(|ledger| {
        ledger.with_bootstrap_tcb_lock_for_test(
            desired_material.bootstrap_tcb_lock.digest(),
            &activation_signing_key,
        )
    })
    .expect("selected pre-state ledger");
    let expected_pre_state = ExpectedPreStateV2::new(
        selected_ledger.projection().generation(),
        selected_ledger.projection().record_payload_digest(),
        selected_ledger.projection().phase(),
        selected_ledger.active_activation().clone(),
        selected_ledger.projection().effects_fenced(),
        selected_ledger.active_manifest_digest(),
        selected_ledger.highest_ever().digest().expect("high water"),
        selected_ledger.install_identity_profile_signed_digest(),
        desired_material
            .bootstrap_tcb_lock
            .deploy_helper_identity()
            .clone(),
        desired_material
            .bootstrap_tcb_lock
            .deploy_watchdog_identity()
            .clone(),
        desired_material
            .bootstrap_tcb_lock
            .deployment_trust_root_set()
            .content_digest(),
        desired_material
            .bootstrap_tcb_lock
            .activation_trust_root_set()
            .content_digest(),
        root_set.release_trust_root_set_digest(),
        desired_material
            .bootstrap_tcb_lock
            .declassification_trust_root_set()
            .content_digest(),
        digest(61),
        installation_epoch,
        selected_ledger.projection().effect_fence_epoch(),
    )
    .expect("expected pre-state");
    let intent = DeploymentTransactionIntentV2::new(DeploymentTransactionIntentMaterialV2 {
        transaction_id,
        installation_id,
        target_platform: desired_material.target_platform.clone(),
        evidence_trust_policy_digest: digest(62),
        evidence_layer_limits_digest: digest(63),
        source_evidence_digest: digest(64),
        artifact_evidence_digest: digest(65),
        created_at_unix_ms: 10,
        not_before_unix_ms: 11,
        expires_at_unix_ms: 29,
        maximum_prepare_duration_ns: 1_000,
        maximum_cutover_duration_ns: 1_000,
        maximum_boot_recovery_duration_ns: 1_000,
        maximum_clock_skew_ns: 1_000,
        expected_pre_state,
        staging_tree_digest: digest(66),
        desired_manifest_digest: desired_manifest.signed_digest(),
        recovery_target: DeploymentRecoveryTargetV2::normal(rollback_manifest.signed_digest())
            .expect("recovery projection"),
        migration_plan_digest: migration_plan.digest(),
        artifact_install_plan_digest: artifact_install_plan.digest(),
        service_transition_plan_digest: service_transition_plan.digest(),
        isolated_e2e_plan_digest: isolated_e2e_plan.digest(),
        evidence_contract_digest: evidence_contract.digest(),
        protected_acceptance_plan_digest: protected_acceptance_plan.digest(),
    })
    .expect("transaction intent");
    let grant_signer = ed25519_dalek::SigningKey::from_bytes(&[67; 32]);
    let grant_verifier = DeploymentAuthorizationVerifierV2::new(
        derive_ed25519_key_id_v2(grant_signer.verifying_key().to_bytes()),
        1,
        grant_signer.verifying_key().to_bytes(),
    )
    .expect("grant verifier");
    let grant = RollbackGrantV2::new_signed_for_test(
        &intent,
        RecoveryPhaseHighWaterV2::normal(std::array::from_fn(|index| digest(70 + index as u8)))
            .expect("high water"),
        40,
        &grant_signer,
        1,
    )
    .expect("grant");
    let transaction_signer = ed25519_dalek::SigningKey::from_bytes(&[68; 32]);
    let transaction = DeploymentTransactionV2::new_signed_for_test(
        intent,
        grant,
        &transaction_signer,
        1,
        &grant_verifier,
    )
    .expect("signed transaction");
    let transaction_verifier = DeploymentAuthorizationVerifierV2::new(
        derive_ed25519_key_id_v2(transaction_signer.verifying_key().to_bytes()),
        1,
        transaction_signer.verifying_key().to_bytes(),
    )
    .expect("transaction verifier");
    let initial_owner = DeploymentOwnerClaimV2::new(
        transaction_id,
        DeploymentOwnerRoleV2::Helper,
        digest(100),
        7,
        8,
        desired_material
            .bootstrap_tcb_lock
            .deploy_helper_identity()
            .identity_digest(),
        Nonce32V2::new([101; 32]),
        1,
        1_000,
    )
    .expect("initial owner");
    let recovery_target =
        DurableDeploymentRecoveryTargetV2::normal(rollback_manifest).expect("recovery target");
    let watchdog_process_identity_digest = desired_material
        .bootstrap_tcb_lock
        .deploy_watchdog_identity()
        .identity_digest();
    let core_material = DurableDeploymentTransactionCoreMaterialV2 {
        installation_id,
        installation_epoch,
        signed_transaction: transaction,
        desired_manifest,
        recovery_target,
        migration_plan,
        artifact_install_plan,
        service_transition_plan,
        isolated_e2e_plan,
        evidence_contract,
        protected_acceptance_plan,
        initial_owner,
        watchdog_boot_id: digest(102),
        watchdog_process_identity_digest,
        watchdog_deadline_monotonic_ns: 2_000,
        created_at_unix_ms: 20,
    };
    let mut activation_authority = TestNativeDeploymentSigningAuthorityV2::new_for_test(
        [103; 32],
        *installation_id.as_bytes(),
        installation_epoch,
        [104; 32],
    )
    .expect("activation authority");
    let activation_verifier = DeploymentActivationVerifierV2::new(
        installation_id,
        savana_kernel_protocol::v2::Ed25519KeyIdV2::new(
            savana_platform_identity::NativeDeploymentSigningAuthorityV2::key_id(
                &activation_authority,
            ),
        ),
        installation_epoch,
        savana_platform_identity::NativeDeploymentSigningAuthorityV2::public_key(
            &activation_authority,
        ),
    )
    .expect("activation verifier");
    let core = DurableDeploymentTransactionCoreV2::new_signed_with_authority(
        core_material,
        &mut activation_authority,
        &activation_verifier,
        &root_set,
    )
    .expect("core");
    let discovered_keys = DurableDeploymentTransactionCoreV2::authenticated_authorization_key_refs(
        core.canonical_bytes(),
        &activation_verifier,
    )
    .expect("activation-authenticated key discovery");
    assert_eq!(discovered_keys.rollback_key_id(), grant_verifier.key_id());
    assert_eq!(
        discovered_keys.transaction_key_id(),
        transaction_verifier.key_id()
    );
    let mut forged_core = core.canonical_bytes().to_vec();
    let last = forged_core.len() - 1;
    forged_core[last] ^= 1;
    assert!(
        DurableDeploymentTransactionCoreV2::authenticated_authorization_key_refs(
            &forged_core,
            &activation_verifier,
        )
        .is_err()
    );
    let signed_transaction = &core.material().signed_transaction;
    let expected = signed_transaction.intent().expected_pre_state();
    signed_transaction
        .validate_authenticated_pre_state(
            &selected_ledger,
            expected.deployment_trust_root_set_digest(),
            expected.activation_trust_root_set_digest(),
            expected.release_trust_root_set_digest(),
            expected.declassification_trust_root_set_digest(),
        )
        .expect("authenticated transaction pre-state");
    assert!(signed_transaction
        .validate_authenticated_pre_state(
            &selected_ledger,
            digest(99),
            expected.activation_trust_root_set_digest(),
            expected.release_trust_root_set_digest(),
            expected.declassification_trust_root_set_digest(),
        )
        .is_err());
    core.validate_selected_ledger_pre_state(&selected_ledger)
        .expect("selected pre-state binding");
    let mismatched_ledger = selected_ledger
        .with_active_manifest_for_test(digest(99), &activation_signing_key)
        .expect("mismatched ledger");
    assert!(core
        .validate_selected_ledger_pre_state(&mismatched_ledger)
        .is_err());
    assert_eq!(
        DurableDeploymentTransactionCoreV2::from_canonical_bytes(
            core.canonical_bytes(),
            &activation_verifier,
            &grant_verifier,
            &transaction_verifier,
            &root_set,
        )
        .expect("decode core"),
        core
    );

    let directory = tempfile::tempdir().expect("core directory");
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
        .expect("private core directory");
    let store = DurableDeploymentTransactionCoreStoreV2::open_for_test(
        directory.path(),
        activation_verifier.clone(),
        grant_verifier.clone(),
        transaction_verifier.clone(),
        root_set.clone(),
    )
    .expect("core store");
    assert_eq!(
        store.append_core(&core).expect("append"),
        core.signed_digest()
    );
    let discovery_store = DurableDeploymentCoreKeyDiscoveryStoreV2::open_for_test(
        directory.path(),
        activation_verifier.clone(),
    )
    .expect("key discovery store");
    assert_eq!(
        discovery_store
            .load_authorization_key_refs(core.signed_digest())
            .expect("discover keys from stored activation-authenticated core")
            .transaction_key_id(),
        transaction_verifier.key_id()
    );
    assert_eq!(
        store
            .load_core(core.signed_digest())
            .expect("reopen content-addressed core"),
        core
    );

    let ledger_directory = tempfile::tempdir().expect("ledger directory");
    let head_directory = tempfile::tempdir().expect("head directory");
    let evidence_directory = tempfile::tempdir().expect("evidence directory");
    let auxiliary_evidence_directory = tempfile::tempdir().expect("auxiliary evidence directory");
    let missing_core_directory = tempfile::tempdir().expect("missing core directory");
    for private in [
        ledger_directory.path(),
        head_directory.path(),
        evidence_directory.path(),
        auxiliary_evidence_directory.path(),
        missing_core_directory.path(),
    ] {
        std::fs::set_permissions(private, std::fs::Permissions::from_mode(0o700))
            .expect("private deployment directory");
    }
    for (leaf, slot_id) in [
        ("ledger-a.cbor", LedgerSlotIdV2::A),
        ("ledger-b.cbor", LedgerSlotIdV2::B),
    ] {
        let slot = SignedLedgerSlotV2::new_signed_for_test(
            slot_id,
            &selected_ledger,
            &activation_signing_key,
        )
        .expect("signed slot");
        let path = ledger_directory.path().join(leaf);
        std::fs::write(&path, slot.canonical_bytes()).expect("write slot");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .expect("private slot");
    }
    let rollback_authority_identity = digest(115);
    let ledger_store = DeploymentLedgerStoreV2::open_for_test(
        ledger_directory.path(),
        activation_verifier.clone(),
        rollback_authority_identity,
    )
    .expect("ledger store");
    let head_store = DurableDeploymentTransactionStoreV2::open_for_test(
        head_directory.path(),
        activation_verifier.clone(),
    )
    .expect("head store");
    let evidence_store = DurableInstallationEvidenceStoreV2::open_for_test(
        evidence_directory.path(),
        activation_verifier.clone(),
    )
    .expect("evidence store");
    let auxiliary_evidence_store = DurableDeploymentAuxiliaryEvidenceStoreV2::open_for_test(
        auxiliary_evidence_directory.path(),
    )
    .expect("auxiliary evidence store");
    let missing_core_store = DurableDeploymentTransactionCoreStoreV2::open_for_test(
        missing_core_directory.path(),
        activation_verifier.clone(),
        grant_verifier,
        transaction_verifier,
        root_set,
    )
    .expect("missing core store");
    let prepared_head = DurableDeploymentTransactionRecordV2::new_signed_with_authority(
        installation_id,
        installation_epoch,
        transaction_id,
        core.signed_digest(),
        1,
        None,
        selected_ledger.signed_record_digest(),
        selected_ledger.projection().generation(),
        DeploymentPhaseV2::Prepared,
        vec![
            ClosedDurableDeploymentStepV2::TransactionAuthenticated,
            ClosedDurableDeploymentStepV2::StagingTreeVerified,
            ClosedDurableDeploymentStepV2::DesiredManifestVerified,
            ClosedDurableDeploymentStepV2::RecoveryTargetVerified,
            ClosedDurableDeploymentStepV2::PlansVerified,
            ClosedDurableDeploymentStepV2::StoreCompatibilityVerified,
            ClosedDurableDeploymentStepV2::GrantPrearmed,
        ],
        vec![DurableDeploymentEvidenceRefV2::StoreCompatibility(digest(
            116,
        ))],
        core.material().initial_owner,
        2_000,
        21,
        &mut activation_authority,
        &activation_verifier,
    )
    .expect("prepared head");
    let prepared_ledger = DeploymentLedgerRecordV2::new_successor_signed_with_authority(
        &selected_ledger,
        DeploymentBranchV2::Normal,
        &prepared_head,
        DeploymentActivationUpdateV2::Retain,
        selected_ledger.highest_ever().clone(),
        22,
        &mut activation_authority,
        &activation_verifier,
    )
    .expect("prepared ledger");
    let transition_store =
        DurableDeploymentTransitionStoreV2::new_with_core_and_installation_evidence(
            ledger_store,
            head_store,
            missing_core_store,
            evidence_store,
            auxiliary_evidence_store,
        );
    let mut rollback_authority = TestNativeRollbackAuthorityV2::new_for_test(
        *rollback_authority_identity.as_bytes(),
        *installation_id.as_bytes(),
        installation_epoch,
        1,
    )
    .expect("rollback authority");
    assert_eq!(
        transition_store
            .commit_transition(
                None,
                DeploymentBranchV2::Normal,
                &prepared_head,
                &prepared_ledger,
                &mut activation_authority,
                &mut rollback_authority,
            )
            .expect_err("missing immutable core must reject"),
        savana_policy_core::v2::DeploymentControlErrorV2::DeploymentTransactionIo
    );
    assert_eq!(
        std::fs::read_dir(head_directory.path())
            .expect("head directory")
            .filter_map(Result::ok)
            .filter(|entry| entry
                .path()
                .extension()
                .is_some_and(|value| value == "cbor"))
            .count(),
        0
    );
    assert_eq!(
        transition_store
            .load_authenticated(&mut rollback_authority)
            .expect("unchanged ledger")
            .selected_record()
            .signed_record_digest(),
        selected_ledger.signed_record_digest()
    );

    let complete_ledger_directory = tempfile::tempdir().expect("complete ledger directory");
    let complete_head_directory = tempfile::tempdir().expect("complete head directory");
    let complete_evidence_directory = tempfile::tempdir().expect("complete evidence directory");
    let complete_auxiliary_evidence_directory =
        tempfile::tempdir().expect("complete auxiliary evidence directory");
    for private in [
        complete_ledger_directory.path(),
        complete_head_directory.path(),
        complete_evidence_directory.path(),
        complete_auxiliary_evidence_directory.path(),
    ] {
        std::fs::set_permissions(private, std::fs::Permissions::from_mode(0o700))
            .expect("private complete deployment directory");
    }
    for (leaf, slot_id) in [
        ("ledger-a.cbor", LedgerSlotIdV2::A),
        ("ledger-b.cbor", LedgerSlotIdV2::B),
    ] {
        let slot = SignedLedgerSlotV2::new_signed_for_test(
            slot_id,
            &selected_ledger,
            &activation_signing_key,
        )
        .expect("signed complete slot");
        let path = complete_ledger_directory.path().join(leaf);
        std::fs::write(&path, slot.canonical_bytes()).expect("write complete slot");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .expect("private complete slot");
    }
    let complete_rollback_identity = digest(117);
    let complete_ledger_store = DeploymentLedgerStoreV2::open_for_test(
        complete_ledger_directory.path(),
        activation_verifier.clone(),
        complete_rollback_identity,
    )
    .expect("complete ledger store");
    let complete_head_store = DurableDeploymentTransactionStoreV2::open_for_test(
        complete_head_directory.path(),
        activation_verifier.clone(),
    )
    .expect("complete head store");
    let complete_evidence_store = DurableInstallationEvidenceStoreV2::open_for_test(
        complete_evidence_directory.path(),
        activation_verifier.clone(),
    )
    .expect("complete evidence store");
    let complete_auxiliary_evidence_store =
        DurableDeploymentAuxiliaryEvidenceStoreV2::open_for_test(
            complete_auxiliary_evidence_directory.path(),
        )
        .expect("complete auxiliary evidence store");
    let complete_transition_store =
        DurableDeploymentTransitionStoreV2::new_with_core_and_installation_evidence(
            complete_ledger_store,
            complete_head_store,
            store,
            complete_evidence_store,
            complete_auxiliary_evidence_store,
        );
    let mut complete_rollback_authority = TestNativeRollbackAuthorityV2::new_for_test(
        *complete_rollback_identity.as_bytes(),
        *installation_id.as_bytes(),
        installation_epoch,
        1,
    )
    .expect("complete rollback authority");
    let committed = complete_transition_store
        .commit_transition(
            None,
            DeploymentBranchV2::Normal,
            &prepared_head,
            &prepared_ledger,
            &mut activation_authority,
            &mut complete_rollback_authority,
        )
        .expect("core-bound transition");
    assert_eq!(
        committed.selected_record().signed_record_digest(),
        prepared_ledger.signed_record_digest()
    );
    let recovery_plan = complete_transition_store
        .load_recovery_plan(&mut complete_rollback_authority)
        .expect("authenticated recovery plan");
    assert_eq!(recovery_plan.phase(), DeploymentPhaseV2::Prepared);
    assert_eq!(recovery_plan.branch(), Some(DeploymentBranchV2::Normal));
    assert_eq!(
        recovery_plan.action(),
        DeploymentRecoveryActionV2::ResumeArm
    );
    assert_eq!(recovery_plan.transaction_id(), Some(transaction_id));
    assert_eq!(
        recovery_plan.core_signed_digest(),
        Some(core.signed_digest())
    );
    assert_eq!(
        recovery_plan.transaction_head_signed_digest(),
        Some(prepared_head.signed_digest())
    );
    let reopened_evidence = DurableInstallationEvidenceStoreV2::open_for_test(
        complete_evidence_directory.path(),
        activation_verifier.clone(),
    )
    .expect("reopen evidence store");
    let transition_audit = reopened_evidence
        .load_latest()
        .expect("load audit")
        .expect("audit envelope")
        .transition_audit()
        .expect("typed transition audit");
    assert_eq!(
        transition_audit.candidate_head_signed_digest(),
        prepared_head.signed_digest()
    );
    assert_eq!(
        transition_audit.candidate_ledger_signed_digest(),
        prepared_ledger.signed_record_digest()
    );

    let native_measurements =
        NativeControlMeasurementSetV2::new(vec![NativeControlMeasurementSetItemV2::new(
            digest(118),
            digest(119),
            digest(120),
            true,
        )
        .expect("native measurement")])
        .expect("native measurement set");
    let frozen_work = FrozenEffectWorkSetV2::new(
        installation_id,
        transaction_id,
        prepared_ledger.signed_record_digest(),
        prepared_ledger.projection().generation(),
        prepared_ledger.projection().effect_fence_epoch(),
        Vec::new(),
    )
    .expect("frozen work set");
    let armed_head = DurableDeploymentTransactionRecordV2::new_signed_with_authority(
        installation_id,
        installation_epoch,
        transaction_id,
        core.signed_digest(),
        2,
        Some(prepared_head.signed_digest()),
        prepared_ledger.signed_record_digest(),
        prepared_ledger.projection().generation(),
        DeploymentPhaseV2::Armed,
        vec![
            ClosedDurableDeploymentStepV2::TransactionAuthenticated,
            ClosedDurableDeploymentStepV2::StagingTreeVerified,
            ClosedDurableDeploymentStepV2::DesiredManifestVerified,
            ClosedDurableDeploymentStepV2::RecoveryTargetVerified,
            ClosedDurableDeploymentStepV2::PlansVerified,
            ClosedDurableDeploymentStepV2::StoreCompatibilityVerified,
            ClosedDurableDeploymentStepV2::GrantPrearmed,
            ClosedDurableDeploymentStepV2::ExclusiveEffectGateAcquired,
            ClosedDurableDeploymentStepV2::OsEffectDenyInstalled,
            ClosedDurableDeploymentStepV2::EffectWorkSetFrozen,
            ClosedDurableDeploymentStepV2::ArmedTransitionReady,
        ],
        vec![
            DurableDeploymentEvidenceRefV2::StoreCompatibility(digest(116)),
            DurableDeploymentEvidenceRefV2::NativeControlMeasurementSet(
                native_measurements.digest(),
            ),
            DurableDeploymentEvidenceRefV2::FrozenEffectWorkSet(frozen_work.digest()),
        ],
        prepared_head.owner(),
        3_000,
        23,
        &mut activation_authority,
        &activation_verifier,
    )
    .expect("armed head");
    let armed_ledger = DeploymentLedgerRecordV2::new_successor_signed_with_authority(
        &prepared_ledger,
        DeploymentBranchV2::Normal,
        &armed_head,
        DeploymentActivationUpdateV2::Retain,
        prepared_ledger.highest_ever().clone(),
        24,
        &mut activation_authority,
        &activation_verifier,
    )
    .expect("armed ledger");
    assert_eq!(
        complete_transition_store
            .commit_transition(
                Some(DeploymentBranchV2::Normal),
                DeploymentBranchV2::Normal,
                &armed_head,
                &armed_ledger,
                &mut activation_authority,
                &mut complete_rollback_authority,
            )
            .expect_err("unresolved auxiliary digests must reject"),
        savana_policy_core::v2::DeploymentControlErrorV2::DeploymentAuxiliaryEvidenceIo
    );
    let auxiliary_writer = DurableDeploymentAuxiliaryEvidenceStoreV2::open_for_test(
        complete_auxiliary_evidence_directory.path(),
    )
    .expect("reopen auxiliary evidence writer");
    auxiliary_writer
        .append_native_control_measurement_set(&native_measurements)
        .expect("persist native measurement");
    auxiliary_writer
        .append_frozen_effect_work_set(&frozen_work)
        .expect("persist frozen work");
    let armed = complete_transition_store
        .commit_transition(
            Some(DeploymentBranchV2::Normal),
            DeploymentBranchV2::Normal,
            &armed_head,
            &armed_ledger,
            &mut activation_authority,
            &mut complete_rollback_authority,
        )
        .expect("typed auxiliary-evidence-bound armed transition");
    assert_eq!(
        armed.selected_record().signed_record_digest(),
        armed_ledger.signed_record_digest()
    );
}

fn build_manifest_file_tree(binary: &BinaryClosureV2) -> FileTreeV2 {
    let entries = ClosedLogicalPathIdV2::ALL
        .iter()
        .copied()
        .take(40)
        .map(|path| {
            if path.is_directory() {
                return FileTreeEntryV2::new_directory(path, digest(240), digest(241))
                    .expect("directory");
            }
            let identity = match path {
                ClosedLogicalPathIdV2::JarvisExecutable => binary.jarvis().clone(),
                ClosedLogicalPathIdV2::AgentdExecutable => binary.agentd().clone(),
                ClosedLogicalPathIdV2::IngressdExecutable => binary.ingressd().clone(),
                ClosedLogicalPathIdV2::KerneldExecutable => binary.kerneld().clone(),
                ClosedLogicalPathIdV2::ApprovaldExecutable => binary.approvald().clone(),
                ClosedLogicalPathIdV2::ExecdExecutable => binary.execd().clone(),
                ClosedLogicalPathIdV2::ApprovalctlExecutable => binary.approvalctl().clone(),
                ClosedLogicalPathIdV2::WorkerSandboxExecutable => binary.worker_sandbox().clone(),
                ClosedLogicalPathIdV2::ParserWorkerExecutable => {
                    binary.parser_worker_set().artifacts()[0].clone()
                }
                ClosedLogicalPathIdV2::ConnectorWorkerExecutable => {
                    binary.connector_worker_set().artifacts()[0].clone()
                }
                _ => artifact(
                    path.expected_artifact_type().expect("file artifact type"),
                    100 + path.tag() as u8,
                ),
            };
            FileTreeEntryV2::new_regular_file(path, digest(242), digest(243), identity)
                .expect("regular file")
        })
        .collect();
    FileTreeV2::new(entries).expect("file tree")
}

fn encode_tags(encoder: &mut minicbor::Encoder<Vec<u8>>, tags: std::ops::RangeInclusive<u16>) {
    let tags: Vec<u16> = tags.collect();
    encoder.array(tags.len() as u64).expect("tag array");
    for tag in tags {
        encoder.u16(tag).expect("tag");
    }
}

fn service_plan_bytes() -> Vec<u8> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder.array(4).expect("service plan");
    for _ in 0..4 {
        encoder.array(0).expect("empty service order");
    }
    encoder.into_writer()
}

fn e2e_plan_bytes() -> Vec<u8> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder.array(4).expect("e2e");
    encode_tags(&mut encoder, 1..=16);
    encoder.bytes(digest(110).as_bytes()).expect("planner");
    encoder.bytes(digest(111).as_bytes()).expect("connector");
    encoder.bytes(digest(112).as_bytes()).expect("isolation");
    encoder.into_writer()
}

fn evidence_contract_bytes() -> Vec<u8> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder.array(5).expect("contract");
    encode_tags(&mut encoder, 1..=9);
    encode_tags(&mut encoder, 1..=7);
    encoder.u16(1).expect("reviews");
    encoder.array(1).expect("platforms");
    encoder.array(2).expect("platform");
    encoder.u16(1).expect("linux");
    encoder.u16(1).expect("x86");
    encoder.u16(1).expect("retention");
    encoder.into_writer()
}

fn acceptance_plan_bytes() -> Vec<u8> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder.array(3).expect("acceptance");
    encode_tags(&mut encoder, 1..=11);
    encoder.bytes(digest(113).as_bytes()).expect("isolation");
    encoder.bytes(digest(114).as_bytes()).expect("sink");
    encoder.into_writer()
}
