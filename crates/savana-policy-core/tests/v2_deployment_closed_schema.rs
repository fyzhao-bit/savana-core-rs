use savana_kernel_protocol::v2::Digest32V2;
use savana_policy_core::v2::{
    ArtifactIdentityV2, ClosedArtifactTypeV2, ClosedLogicalPathIdV2, ClosedStagingPathIdV2,
    ClosedStoreIdV2, ClosedTargetArchitectureV2, ClosedTargetOsV2, DeploymentControlErrorV2,
    FileTreeEntryV2, FileTreeV2, PlatformLockV2, StagingEntryV2, StagingTreeV2,
};

fn digest(byte: u8) -> Digest32V2 {
    Digest32V2::new([byte; 32])
}

fn complete_file_tree_entries() -> Vec<FileTreeEntryV2> {
    ClosedLogicalPathIdV2::ALL
        .iter()
        .copied()
        .take(40)
        .map(|path| {
            let seed = u8::try_from(path.tag()).unwrap();
            if path.is_directory() {
                FileTreeEntryV2::new_directory(
                    path,
                    digest(seed.wrapping_add(0x40)),
                    digest(seed.wrapping_add(0x70)),
                )
                .unwrap()
            } else {
                let identity = ArtifactIdentityV2::new(
                    path.expected_artifact_type().unwrap(),
                    ClosedTargetOsV2::Linux,
                    ClosedTargetArchitectureV2::X86_64,
                    8192,
                    digest(seed),
                    digest(seed.wrapping_add(0x40)),
                    digest(seed.wrapping_add(0x70)),
                )
                .unwrap();
                FileTreeEntryV2::new_regular_file(
                    path,
                    digest(seed.wrapping_add(0x80)),
                    digest(seed.wrapping_add(0xa0)),
                    identity,
                )
                .unwrap()
            }
        })
        .collect()
}

fn regular(path: ClosedStagingPathIdV2, byte: u8) -> StagingEntryV2 {
    StagingEntryV2::new_regular(
        path,
        4096,
        digest(byte),
        0o600,
        digest(byte.wrapping_add(1)),
        digest(byte.wrapping_add(2)),
    )
    .unwrap()
}

fn complete_staging_entries() -> Vec<StagingEntryV2> {
    vec![
        regular(ClosedStagingPathIdV2::MigrationPlan, 0x11),
        regular(ClosedStagingPathIdV2::ArtifactInstallPlan, 0x14),
        regular(ClosedStagingPathIdV2::ServiceTransitionPlan, 0x17),
        regular(ClosedStagingPathIdV2::IsolatedE2EPlan, 0x1a),
        regular(ClosedStagingPathIdV2::EvidenceContract, 0x1d),
        regular(ClosedStagingPathIdV2::ProtectedAcceptancePlan, 0x20),
        StagingEntryV2::new_directory(
            ClosedStagingPathIdV2::ArtifactPayloadRoot,
            0o700,
            digest(0x23),
            digest(0x24),
        )
        .unwrap(),
        regular(ClosedStagingPathIdV2::KerneldExecutable, 0x25),
    ]
}

#[test]
fn deployment_registries_are_closed_exact_and_have_no_numeric_fallback() {
    assert_eq!(ClosedStoreIdV2::ALL.len(), 18);
    assert_eq!(ClosedStoreIdV2::KerneldVault.tag(), 1);
    assert_eq!(ClosedStoreIdV2::DeploymentEvidence.tag(), 18);
    assert!(ClosedStoreIdV2::from_tag(0).is_none());
    assert!(ClosedStoreIdV2::from_tag(19).is_none());

    assert!(ClosedLogicalPathIdV2::DeployHelperExecutable.is_bootstrap_owned());
    assert!(ClosedLogicalPathIdV2::DeployWatchdogExecutable.is_bootstrap_owned());
    assert!(!ClosedLogicalPathIdV2::KerneldExecutable.is_bootstrap_owned());
    assert_eq!(
        ClosedStagingPathIdV2::KerneldExecutable.target_logical_path(),
        Some(ClosedLogicalPathIdV2::KerneldExecutable)
    );
    assert_eq!(
        ClosedStagingPathIdV2::MigrationPlan.target_logical_path(),
        None
    );
    assert!(ClosedStagingPathIdV2::from_tag(8).is_none());
    assert!(ClosedStagingPathIdV2::from_tag(u16::MAX).is_none());
}

#[test]
fn artifact_identity_is_canonical_bounded_and_platform_exact() {
    let platform = PlatformLockV2::new(
        ClosedTargetOsV2::Linux,
        ClosedTargetArchitectureV2::X86_64,
        digest(0x2a),
        digest(0x2b),
        digest(0x2c),
        digest(0x2d),
        digest(0x2e),
    )
    .unwrap();
    assert_eq!(
        PlatformLockV2::from_canonical_bytes(platform.canonical_bytes()).unwrap(),
        platform
    );
    assert_ne!(platform.digest(), platform.kernel_abi_digest());

    let artifact = ArtifactIdentityV2::new(
        ClosedArtifactTypeV2::Daemon,
        ClosedTargetOsV2::Linux,
        ClosedTargetArchitectureV2::X86_64,
        8_388_608,
        digest(0x31),
        digest(0x32),
        digest(0x33),
    )
    .unwrap();
    let reopened = ArtifactIdentityV2::from_canonical_bytes(artifact.canonical_bytes()).unwrap();
    assert_eq!(reopened, artifact);
    assert_ne!(artifact.identity_digest(), artifact.sha256());
    assert_eq!(artifact.byte_length(), 8_388_608);

    let mut trailing = artifact.canonical_bytes().to_vec();
    trailing.push(0);
    assert_eq!(
        ArtifactIdentityV2::from_canonical_bytes(&trailing).unwrap_err(),
        DeploymentControlErrorV2::InvalidArtifactIdentity
    );
    assert_eq!(
        ArtifactIdentityV2::new(
            ClosedArtifactTypeV2::Daemon,
            ClosedTargetOsV2::Linux,
            ClosedTargetArchitectureV2::X86_64,
            0,
            digest(0x31),
            digest(0x32),
            digest(0x33),
        )
        .unwrap_err(),
        DeploymentControlErrorV2::InvalidArtifactIdentity
    );
}

#[test]
fn staging_tree_requires_every_plan_and_exact_sorted_closed_entries() {
    let entries = complete_staging_entries();
    let tree = StagingTreeV2::new(entries.clone()).unwrap();
    let reopened = StagingTreeV2::from_canonical_bytes(tree.canonical_bytes()).unwrap();
    assert_eq!(reopened, tree);
    assert_eq!(tree.entries().len(), 8);
    assert_ne!(tree.merkle_root(), digest(0));

    let mut missing = entries.clone();
    missing.remove(4);
    assert_eq!(
        StagingTreeV2::new(missing).unwrap_err(),
        DeploymentControlErrorV2::InvalidDeploymentTree
    );

    let mut unsorted = entries.clone();
    unsorted.swap(0, 1);
    assert_eq!(
        StagingTreeV2::new(unsorted).unwrap_err(),
        DeploymentControlErrorV2::InvalidDeploymentTree
    );

    let mut duplicate = entries;
    duplicate.insert(1, duplicate[0].clone());
    assert_eq!(
        StagingTreeV2::new(duplicate).unwrap_err(),
        DeploymentControlErrorV2::InvalidDeploymentTree
    );
}

#[test]
fn file_tree_has_one_root_exact_parent_closure_and_no_bootstrap_path() {
    let entries = complete_file_tree_entries();
    assert_eq!(entries[0].parent_logical_path_id(), None);
    assert!(entries
        .iter()
        .skip(1)
        .all(|entry| entry.parent_logical_path_id().is_some()));
    let tree = FileTreeV2::new(entries.clone()).unwrap();
    let reopened = FileTreeV2::from_canonical_bytes(tree.canonical_bytes()).unwrap();
    assert_eq!(reopened, tree);
    assert_eq!(tree.entries().len(), 40);
    assert_ne!(tree.merkle_root(), digest(0));

    let mut missing = entries.clone();
    missing.pop();
    assert_eq!(
        FileTreeV2::new(missing).unwrap_err(),
        DeploymentControlErrorV2::InvalidDeploymentTree
    );
    let mut reordered = entries;
    reordered.swap(8, 9);
    assert_eq!(
        FileTreeV2::new(reordered).unwrap_err(),
        DeploymentControlErrorV2::InvalidDeploymentTree
    );

    let bootstrap_identity = ArtifactIdentityV2::new(
        ClosedArtifactTypeV2::RootHelper,
        ClosedTargetOsV2::Linux,
        ClosedTargetArchitectureV2::X86_64,
        4096,
        digest(0xd1),
        digest(0xd2),
        digest(0xd3),
    )
    .unwrap();
    assert_eq!(
        FileTreeEntryV2::new_regular_file(
            ClosedLogicalPathIdV2::DeployHelperExecutable,
            digest(0xd4),
            digest(0xd5),
            bootstrap_identity,
        )
        .unwrap_err(),
        DeploymentControlErrorV2::InvalidDeploymentTree
    );
}
