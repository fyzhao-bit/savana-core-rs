use savana_kernel_protocol::v2::{Digest32V2, Nonce32V2};
use savana_policy_core::v2::{
    BootstrapBridgeRestoreIntegrityV2, ClosedServiceIdV2,
    DurableDeploymentAuxiliaryEvidenceStoreV2, FrozenEffectWorkItemV2, FrozenEffectWorkKindV2,
    FrozenEffectWorkSetV2, NativeControlMeasurementSetItemV2, NativeControlMeasurementSetV2,
    RoleJournalReconciliationItemV2, RoleJournalReconciliationV2, RollbackOriginPhaseV2,
};
use sha2::Digest as _;
use std::os::unix::fs::PermissionsExt as _;

fn digest(byte: u8) -> Digest32V2 {
    Digest32V2::new([byte; 32])
}

#[test]
fn native_control_measurements_are_exact_sorted_passing_items() {
    let first =
        NativeControlMeasurementSetItemV2::new(digest(1), digest(2), digest(3), true).unwrap();
    let second =
        NativeControlMeasurementSetItemV2::new(digest(4), digest(5), digest(6), true).unwrap();
    let set = NativeControlMeasurementSetV2::new(vec![first, second]).unwrap();
    assert_eq!(
        NativeControlMeasurementSetV2::from_canonical_bytes(set.canonical_bytes()).unwrap(),
        set
    );

    let mut expected = sha2::Sha256::new();
    expected.update(b"savana.set.native-control-measurement.v2\0");
    expected.update(2_u64.to_be_bytes());
    expected.update(set.canonical_bytes());
    assert_eq!(set.digest().as_bytes(), &expected.finalize()[..]);

    assert!(NativeControlMeasurementSetV2::new(vec![second, first]).is_err());
    assert!(
        NativeControlMeasurementSetItemV2::new(digest(7), digest(8), digest(9), false).is_err()
    );
}

#[test]
fn frozen_effect_work_is_role_typed_content_addressed_and_canonical() {
    let agent = FrozenEffectWorkItemV2::new(
        FrozenEffectWorkKindV2::AgentdPlannerMarker,
        ClosedServiceIdV2::Agentd,
        digest(10),
        digest(11),
        digest(12),
        1,
    )
    .unwrap();
    let kernel = FrozenEffectWorkItemV2::new(
        FrozenEffectWorkKindV2::KerneldDispatchWalHead,
        ClosedServiceIdV2::Kerneld,
        digest(13),
        digest(14),
        digest(15),
        2,
    )
    .unwrap();
    let set = FrozenEffectWorkSetV2::new(
        digest(16),
        Nonce32V2::new([17; 32]),
        digest(18),
        9,
        10,
        vec![agent, kernel],
    )
    .unwrap();
    assert_eq!(
        FrozenEffectWorkSetV2::from_canonical_bytes(set.canonical_bytes()).unwrap(),
        set
    );
    assert_ne!(set.frozen_effect_work_set_digest(), set.digest());

    assert!(FrozenEffectWorkItemV2::new(
        FrozenEffectWorkKindV2::ExecdJournalHead,
        ClosedServiceIdV2::Agentd,
        digest(19),
        digest(20),
        digest(21),
        3,
    )
    .is_err());
    assert!(FrozenEffectWorkSetV2::new(
        digest(16),
        Nonce32V2::new([17; 32]),
        digest(18),
        9,
        10,
        vec![kernel, agent],
    )
    .is_err());

    let empty = FrozenEffectWorkSetV2::new(
        digest(22),
        Nonce32V2::new([23; 32]),
        digest(24),
        1,
        1,
        Vec::new(),
    )
    .unwrap();
    assert_eq!(
        FrozenEffectWorkSetV2::from_canonical_bytes(empty.canonical_bytes()).unwrap(),
        empty
    );
}

#[test]
fn role_journal_reconciliation_is_exactly_bound_to_every_frozen_item() {
    let agent = FrozenEffectWorkItemV2::new(
        FrozenEffectWorkKindV2::AgentdPlannerMarker,
        ClosedServiceIdV2::Agentd,
        digest(30),
        digest(31),
        digest(32),
        1,
    )
    .unwrap();
    let kernel = FrozenEffectWorkItemV2::new(
        FrozenEffectWorkKindV2::KerneldDispatchWalHead,
        ClosedServiceIdV2::Kerneld,
        digest(33),
        digest(34),
        digest(35),
        2,
    )
    .unwrap();
    let frozen = FrozenEffectWorkSetV2::new(
        digest(36),
        Nonce32V2::new([37; 32]),
        digest(38),
        12,
        13,
        vec![agent, kernel],
    )
    .unwrap();
    let agent_terminal = RoleJournalReconciliationItemV2::new(
        FrozenEffectWorkKindV2::AgentdPlannerMarker,
        ClosedServiceIdV2::Agentd,
        digest(30),
        digest(32),
        digest(39),
        10,
    )
    .unwrap();
    let kernel_terminal = RoleJournalReconciliationItemV2::new(
        FrozenEffectWorkKindV2::KerneldDispatchWalHead,
        ClosedServiceIdV2::Kerneld,
        digest(33),
        digest(35),
        digest(40),
        11,
    )
    .unwrap();
    let reconciliation = RoleJournalReconciliationV2::new(
        &frozen,
        digest(41),
        14,
        vec![agent_terminal, kernel_terminal],
        15,
    )
    .unwrap();
    assert_eq!(
        RoleJournalReconciliationV2::from_canonical_bytes(reconciliation.canonical_bytes())
            .unwrap(),
        reconciliation
    );
    reconciliation.validate_frozen_set(&frozen).unwrap();

    assert!(
        RoleJournalReconciliationV2::new(&frozen, digest(41), 14, vec![agent_terminal], 15,)
            .is_err()
    );
    let wrong_frozen_head = RoleJournalReconciliationItemV2::new(
        FrozenEffectWorkKindV2::KerneldDispatchWalHead,
        ClosedServiceIdV2::Kerneld,
        digest(33),
        digest(42),
        digest(43),
        11,
    )
    .unwrap();
    assert!(RoleJournalReconciliationV2::new(
        &frozen,
        digest(41),
        14,
        vec![agent_terminal, wrong_frozen_head],
        15,
    )
    .is_err());
}

#[test]
fn bootstrap_bridge_restore_integrity_is_closed_canonical_and_fail_closed() {
    let integrity = BootstrapBridgeRestoreIntegrityV2::new(
        digest(50),
        2,
        Nonce32V2::new([51; 32]),
        digest(52),
        digest(53),
        RollbackOriginPhaseV2::Armed,
        3,
        4,
        digest(54),
        digest(55),
        digest(56),
        digest(57),
        digest(58),
        digest(59),
        digest(60),
        digest(61),
        digest(62),
        5,
    )
    .unwrap();
    assert_eq!(
        BootstrapBridgeRestoreIntegrityV2::from_canonical_bytes(integrity.canonical_bytes())
            .unwrap(),
        integrity
    );

    let mut trailing = integrity.canonical_bytes().to_vec();
    trailing.push(0);
    assert!(BootstrapBridgeRestoreIntegrityV2::from_canonical_bytes(&trailing).is_err());
    assert!(BootstrapBridgeRestoreIntegrityV2::new(
        digest(50),
        2,
        Nonce32V2::new([51; 32]),
        digest(52),
        digest(53),
        RollbackOriginPhaseV2::Armed,
        3,
        4,
        digest(54),
        digest(55),
        digest(56),
        digest(57),
        digest(58),
        digest(59),
        digest(60),
        digest(61),
        digest(0),
        5,
    )
    .is_err());
}

#[test]
fn auxiliary_evidence_store_is_content_addressed_durable_and_tamper_evident() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let store = DurableDeploymentAuxiliaryEvidenceStoreV2::open_for_test(directory.path()).unwrap();

    let native = NativeControlMeasurementSetV2::new(vec![NativeControlMeasurementSetItemV2::new(
        digest(70),
        digest(71),
        digest(72),
        true,
    )
    .unwrap()])
    .unwrap();
    assert_eq!(
        store
            .append_native_control_measurement_set(&native)
            .unwrap(),
        native.digest()
    );
    assert_eq!(
        store
            .load_native_control_measurement_set(native.digest())
            .unwrap(),
        native
    );

    let frozen_item = FrozenEffectWorkItemV2::new(
        FrozenEffectWorkKindV2::ExecdJournalHead,
        ClosedServiceIdV2::Execd,
        digest(73),
        digest(74),
        digest(75),
        1,
    )
    .unwrap();
    let frozen = FrozenEffectWorkSetV2::new(
        digest(76),
        Nonce32V2::new([77; 32]),
        digest(78),
        2,
        3,
        vec![frozen_item],
    )
    .unwrap();
    store.append_frozen_effect_work_set(&frozen).unwrap();
    assert_eq!(
        store.load_frozen_effect_work_set(frozen.digest()).unwrap(),
        frozen
    );

    let terminal = RoleJournalReconciliationItemV2::new(
        FrozenEffectWorkKindV2::ExecdJournalHead,
        ClosedServiceIdV2::Execd,
        digest(73),
        digest(75),
        digest(79),
        2,
    )
    .unwrap();
    let reconciliation =
        RoleJournalReconciliationV2::new(&frozen, digest(80), 4, vec![terminal], 5).unwrap();
    store
        .append_role_journal_reconciliation(&reconciliation)
        .unwrap();
    assert_eq!(
        store
            .load_role_journal_reconciliation(reconciliation.digest())
            .unwrap(),
        reconciliation
    );

    let bridge = BootstrapBridgeRestoreIntegrityV2::new(
        digest(81),
        6,
        Nonce32V2::new([82; 32]),
        digest(83),
        digest(84),
        RollbackOriginPhaseV2::Installed,
        7,
        8,
        digest(85),
        digest(86),
        digest(87),
        digest(88),
        digest(89),
        digest(90),
        reconciliation.digest(),
        native.digest(),
        digest(91),
        9,
    )
    .unwrap();
    store
        .append_bootstrap_bridge_restore_integrity(&bridge)
        .unwrap();
    assert_eq!(
        store
            .load_bootstrap_bridge_restore_integrity(bridge.digest())
            .unwrap(),
        bridge
    );

    let native_leaf = std::fs::read_dir(directory.path())
        .unwrap()
        .map(Result::unwrap)
        .find(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with("evidence-02-")
        })
        .unwrap()
        .path();
    std::fs::write(&native_leaf, [0_u8; 3]).unwrap();
    std::fs::set_permissions(&native_leaf, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(store
        .load_native_control_measurement_set(native.digest())
        .is_err());
}
