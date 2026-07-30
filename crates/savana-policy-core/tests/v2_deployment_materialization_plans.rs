use savana_kernel_protocol::v2::Digest32V2;
use savana_policy_core::v2::{
    ArtifactInstallOperationV2, ArtifactInstallPlanV2, ClosedLogicalPathIdV2, ClosedStoreIdV2,
    DeploymentControlErrorV2, MigrationPlanV2, MigrationStepV2,
};

fn digest(byte: u8) -> Digest32V2 {
    Digest32V2::new([byte; 32])
}

#[test]
fn migration_plan_accepts_only_closed_stores_and_expand_only_epochs() {
    let plan = MigrationPlanV2::new(vec![
        MigrationStepV2::AssertStoreEpoch {
            store_id: ClosedStoreIdV2::KerneldVault,
            expected_epoch: 7,
        },
        MigrationStepV2::ExpandSchema {
            store_id: ClosedStoreIdV2::KerneldVault,
            from_epoch: 7,
            to_epoch: 8,
            migration_artifact_digest: digest(0x31),
        },
        MigrationStepV2::ProvisionKeySlot {
            store_id: ClosedStoreIdV2::ExecdConnectorJournal,
            closed_slot_id: digest(0x32),
        },
    ])
    .unwrap();
    assert_eq!(
        MigrationPlanV2::from_canonical_bytes(plan.canonical_bytes()).unwrap(),
        plan
    );
    assert_eq!(
        MigrationPlanV2::new(vec![MigrationStepV2::ExpandSchema {
            store_id: ClosedStoreIdV2::KerneldVault,
            from_epoch: 8,
            to_epoch: 7,
            migration_artifact_digest: digest(0x33),
        }])
        .unwrap_err(),
        DeploymentControlErrorV2::InvalidDeploymentPlan
    );
    assert_eq!(
        MigrationPlanV2::new(vec![
            MigrationStepV2::ProvisionKeySlot {
                store_id: ClosedStoreIdV2::KerneldVault,
                closed_slot_id: digest(0x34),
            },
            MigrationStepV2::AssertStoreEpoch {
                store_id: ClosedStoreIdV2::KerneldVault,
                expected_epoch: 7,
            },
        ])
        .unwrap_err(),
        DeploymentControlErrorV2::InvalidDeploymentPlan
    );
}

#[test]
fn artifact_install_plan_is_the_exact_complete_nonbootstrap_tree() {
    let operations = ArtifactInstallPlanV2::complete_operations();
    assert_eq!(operations.len(), 75);
    assert_eq!(
        operations[0],
        ArtifactInstallOperationV2::MaterializeDirectory(
            ClosedLogicalPathIdV2::InstallationRootDirectory
        )
    );
    assert!(operations
        .iter()
        .all(|operation| { !operation.logical_path_id().is_bootstrap_owned() }));
    let plan = ArtifactInstallPlanV2::new(operations.clone()).unwrap();
    assert_eq!(
        ArtifactInstallPlanV2::from_canonical_bytes(plan.canonical_bytes()).unwrap(),
        plan
    );

    let mut missing = operations.clone();
    missing.pop();
    assert_eq!(
        ArtifactInstallPlanV2::new(missing).unwrap_err(),
        DeploymentControlErrorV2::InvalidDeploymentPlan
    );
    let mut reordered = operations;
    reordered.swap(5, 6);
    assert_eq!(
        ArtifactInstallPlanV2::new(reordered).unwrap_err(),
        DeploymentControlErrorV2::InvalidDeploymentPlan
    );
}
