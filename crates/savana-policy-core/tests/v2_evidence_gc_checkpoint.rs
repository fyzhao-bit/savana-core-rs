use std::fs;
use std::os::unix::fs::PermissionsExt as _;

use ed25519_dalek::SigningKey;
use savana_kernel_protocol::v2::{derive_ed25519_key_id_v2, Digest32V2, Nonce32V2};
use savana_policy_core::v2::{
    ClosedDurableDeploymentStepV2, CompactedTransactionProvenanceV2, DeploymentActivationUpdateV2,
    DeploymentActivationVerifierV2, DeploymentBranchV2, DeploymentLedgerRecordV2,
    DeploymentLedgerStoreV2, DeploymentOwnerClaimV2, DeploymentOwnerRoleV2, DeploymentPhaseV2,
    DurableDeploymentEvidenceRefV2, DurableDeploymentTransactionRecordV2,
    DurableDeploymentTransactionStoreV2, DurableDeploymentTransitionStoreV2,
    DurableEvidenceGcCheckpointStoreV2, EvidenceGcCheckpointV2, EvidenceGcWindowV2,
    InstallationEvidenceEnvelopeV2, LedgerSlotIdV2, NativeDeploymentSigningAuthorityV2,
    RollbackGrantStateV2, SignedLedgerSlotV2, TestAbortedCompactionCrashPointV2,
    TestNativeDeploymentSigningAuthorityV2, TestNativeRollbackAuthorityV2,
};

fn digest(seed: u8) -> Digest32V2 {
    Digest32V2::new([seed; 32])
}

fn nonce(seed: u8) -> Nonce32V2 {
    Nonce32V2::new([seed; 32])
}

fn prepared_steps() -> Vec<ClosedDurableDeploymentStepV2> {
    vec![
        ClosedDurableDeploymentStepV2::TransactionAuthenticated,
        ClosedDurableDeploymentStepV2::StagingTreeVerified,
        ClosedDurableDeploymentStepV2::DesiredManifestVerified,
        ClosedDurableDeploymentStepV2::RecoveryTargetVerified,
        ClosedDurableDeploymentStepV2::PlansVerified,
        ClosedDurableDeploymentStepV2::StoreCompatibilityVerified,
        ClosedDurableDeploymentStepV2::GrantPrearmed,
    ]
}

struct CompactionFixture {
    _ledger_directory: tempfile::TempDir,
    head_directory: tempfile::TempDir,
    _checkpoint_directory: tempfile::TempDir,
    store: DurableDeploymentTransitionStoreV2,
    checkpoint: EvidenceGcCheckpointV2,
    checkpoint_envelope: InstallationEvidenceEnvelopeV2,
    aborted: DeploymentLedgerRecordV2,
    signing_authority: TestNativeDeploymentSigningAuthorityV2,
    rollback_authority: TestNativeRollbackAuthorityV2,
}

fn compaction_fixture() -> CompactionFixture {
    let ledger_directory = tempfile::tempdir().unwrap();
    let head_directory = tempfile::tempdir().unwrap();
    let checkpoint_directory = tempfile::tempdir().unwrap();
    for directory in [
        ledger_directory.path(),
        head_directory.path(),
        checkpoint_directory.path(),
    ] {
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
    }

    let installation_id = digest(0x31);
    let installation_epoch = 41;
    let signing_seed = [0x32; 32];
    let signing_key = SigningKey::from_bytes(&signing_seed);
    let mut signing_authority = TestNativeDeploymentSigningAuthorityV2::new_for_test(
        [0x33; 32],
        *installation_id.as_bytes(),
        installation_epoch,
        signing_seed,
    )
    .unwrap();
    let verifier = DeploymentActivationVerifierV2::new(
        installation_id,
        derive_ed25519_key_id_v2(signing_key.verifying_key().to_bytes()),
        installation_epoch,
        signing_key.verifying_key().to_bytes(),
    )
    .unwrap();
    let genesis = DeploymentLedgerRecordV2::new_signed_for_test(
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
        1_783_100_000_000,
        0x34,
        &signing_key,
    )
    .unwrap();
    let transaction_id = nonce(0x35);
    let owner = DeploymentOwnerClaimV2::new(
        transaction_id,
        DeploymentOwnerRoleV2::Helper,
        digest(0x36),
        100,
        101,
        digest(0x37),
        nonce(0x38),
        1,
        200_000,
    )
    .unwrap();
    let core_signed_digest = digest(0x39);
    let prepared_head = DurableDeploymentTransactionRecordV2::new_signed_for_test(
        installation_id,
        installation_epoch,
        transaction_id,
        core_signed_digest,
        1,
        None,
        genesis.signed_record_digest(),
        1,
        DeploymentPhaseV2::Prepared,
        prepared_steps(),
        vec![DurableDeploymentEvidenceRefV2::StoreCompatibility(digest(
            0x3a,
        ))],
        owner,
        200_000,
        1_783_100_000_001,
        &signing_key,
    )
    .unwrap();
    let prepared = DeploymentLedgerRecordV2::new_successor_signed_with_authority(
        &genesis,
        DeploymentBranchV2::Normal,
        &prepared_head,
        DeploymentActivationUpdateV2::Retain,
        genesis.highest_ever().clone(),
        1_783_100_000_002,
        &mut signing_authority,
        &verifier,
    )
    .unwrap();
    let aborted_head = DurableDeploymentTransactionRecordV2::new_signed_for_test(
        installation_id,
        installation_epoch,
        transaction_id,
        core_signed_digest,
        2,
        Some(prepared_head.signed_digest()),
        prepared.signed_record_digest(),
        2,
        DeploymentPhaseV2::Aborted,
        prepared_steps(),
        vec![DurableDeploymentEvidenceRefV2::StoreCompatibility(digest(
            0x3a,
        ))],
        owner,
        200_000,
        1_783_100_000_003,
        &signing_key,
    )
    .unwrap();
    let aborted = DeploymentLedgerRecordV2::new_successor_signed_with_authority(
        &prepared,
        DeploymentBranchV2::Normal,
        &aborted_head,
        DeploymentActivationUpdateV2::Retain,
        prepared.highest_ever().clone(),
        1_783_100_000_004,
        &mut signing_authority,
        &verifier,
    )
    .unwrap();

    for (leaf, slot_id, record) in [
        ("ledger-a.cbor", LedgerSlotIdV2::A, &aborted),
        ("ledger-b.cbor", LedgerSlotIdV2::B, &prepared),
    ] {
        let slot = SignedLedgerSlotV2::new_signed_for_test(slot_id, record, &signing_key).unwrap();
        let path = ledger_directory.path().join(leaf);
        fs::write(&path, slot.canonical_bytes()).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let ledger_store = DeploymentLedgerStoreV2::open_for_test(
        ledger_directory.path(),
        verifier.clone(),
        digest(0x3b),
    )
    .unwrap();
    let head_store =
        DurableDeploymentTransactionStoreV2::open_for_test(head_directory.path(), verifier.clone())
            .unwrap();
    head_store.append_head(&prepared_head).unwrap();
    head_store.append_head(&aborted_head).unwrap();
    let checkpoint_store = DurableEvidenceGcCheckpointStoreV2::open_for_test(
        checkpoint_directory.path(),
        verifier.clone(),
    )
    .unwrap();
    let store = DurableDeploymentTransitionStoreV2::new_with_aborted_compaction_checkpoints(
        ledger_store,
        head_store,
        checkpoint_store,
    );
    let chain = vec![prepared_head, aborted_head];
    let provenance =
        CompactedTransactionProvenanceV2::from_aborted_chain(&aborted, &chain).unwrap();
    let window = EvidenceGcWindowV2::new(
        digest(0x3c),
        digest(0x3d),
        digest(0x3e),
        2,
        digest(0x3f),
        1_783_100_000_005,
    )
    .unwrap();
    let checkpoint = EvidenceGcCheckpointV2::new_signed_with_authority(
        installation_id,
        installation_epoch,
        window,
        provenance,
        &mut signing_authority,
        &verifier,
    )
    .unwrap();
    let checkpoint_envelope =
        InstallationEvidenceEnvelopeV2::new_gc_checkpoint_signed_with_authority(
            1,
            None,
            &checkpoint,
            &mut signing_authority,
            &verifier,
        )
        .unwrap();
    let rollback_authority = TestNativeRollbackAuthorityV2::new_for_test(
        [0x3b; 32],
        *installation_id.as_bytes(),
        installation_epoch,
        3,
    )
    .unwrap();
    CompactionFixture {
        _ledger_directory: ledger_directory,
        head_directory,
        _checkpoint_directory: checkpoint_directory,
        store,
        checkpoint,
        checkpoint_envelope,
        aborted,
        signing_authority,
        rollback_authority,
    }
}

#[test]
fn aborted_to_idle_requires_a_flushed_signed_checkpoint_with_exact_head_ancestry() {
    let mut fixture = compaction_fixture();
    let compacted = fixture
        .store
        .compact_aborted_to_idle(
            &fixture.checkpoint_envelope,
            1_783_100_000_006,
            &mut fixture.signing_authority,
            &mut fixture.rollback_authority,
        )
        .unwrap();

    assert_eq!(
        compacted.selected_record().projection().phase(),
        DeploymentPhaseV2::Idle
    );
    assert_eq!(
        compacted
            .selected_record()
            .projection()
            .previous_record_digest(),
        fixture.aborted.record_payload_digest()
    );
    assert_eq!(
        compacted.selected_record().projection().transaction_id(),
        None
    );
    assert_eq!(
        compacted
            .selected_record()
            .projection()
            .transaction_head_digest(),
        None
    );
    let reopened = fixture
        .store
        .load_aborted_compaction_checkpoint(fixture.aborted.signed_record_digest())
        .unwrap();
    assert_eq!(
        reopened.canonical_bytes(),
        fixture.checkpoint_envelope.canonical_bytes()
    );
}

#[test]
fn every_checkpoint_and_idle_ledger_boundary_recovers_old_or_exact_new_state() {
    use TestAbortedCompactionCrashPointV2 as Crash;

    for point in Crash::ALL {
        let mut fixture = compaction_fixture();
        fixture
            .store
            .compact_aborted_to_idle_with_crash_for_test(
                &fixture.checkpoint_envelope,
                1_783_100_000_006,
                &mut fixture.signing_authority,
                &mut fixture.rollback_authority,
                point,
            )
            .unwrap_err();
        let recovered = fixture
            .store
            .load_authenticated(&mut fixture.rollback_authority)
            .unwrap();
        let expected_phase = if point >= Crash::LedgerRenamedBeforeDirectoryFlush {
            DeploymentPhaseV2::Idle
        } else {
            DeploymentPhaseV2::Aborted
        };
        assert_eq!(
            recovered.selected_record().projection().phase(),
            expected_phase,
            "unexpected recovered phase at {point:?}"
        );
        if expected_phase == DeploymentPhaseV2::Idle {
            assert_eq!(
                recovered
                    .selected_record()
                    .projection()
                    .previous_record_digest(),
                fixture.aborted.record_payload_digest(),
                "wrong compacted predecessor at {point:?}"
            );
        }
    }
}

#[test]
fn signed_checkpoint_with_wrong_predecessor_chain_cannot_clear_the_ledger_head() {
    let mut fixture = compaction_fixture();
    let CompactedTransactionProvenanceV2::Aborted {
        aborted_ledger_record_digest,
        transaction_core_signed_digest,
        final_transaction_head_signed_digest,
        ..
    } = fixture.checkpoint.compacted_transaction_provenance()
    else {
        panic!("fixture checkpoint must carry aborted provenance");
    };
    let verifier = DeploymentActivationVerifierV2::new(
        fixture.checkpoint.installation_id(),
        fixture.checkpoint.activation_key_id(),
        fixture.checkpoint.installation_epoch(),
        fixture.signing_authority.public_key(),
    )
    .unwrap();
    let wrong = EvidenceGcCheckpointV2::new_signed_with_authority(
        fixture.checkpoint.installation_id(),
        fixture.checkpoint.installation_epoch(),
        fixture.checkpoint.window(),
        CompactedTransactionProvenanceV2::Aborted {
            aborted_ledger_record_digest,
            transaction_core_signed_digest,
            final_transaction_head_signed_digest,
            predecessor_chain_digest: digest(0xee),
        },
        &mut fixture.signing_authority,
        &verifier,
    )
    .unwrap();
    let wrong_envelope = InstallationEvidenceEnvelopeV2::new_gc_checkpoint_signed_with_authority(
        1,
        None,
        &wrong,
        &mut fixture.signing_authority,
        &verifier,
    )
    .unwrap();

    assert_eq!(
        fixture
            .store
            .compact_aborted_to_idle(
                &wrong_envelope,
                1_783_100_000_006,
                &mut fixture.signing_authority,
                &mut fixture.rollback_authority,
            )
            .unwrap_err(),
        savana_policy_core::v2::DeploymentControlErrorV2::InvalidCompactedTransactionProvenance
    );
    assert_eq!(
        fixture
            .store
            .load_authenticated(&mut fixture.rollback_authority)
            .unwrap()
            .selected_record()
            .projection()
            .phase(),
        DeploymentPhaseV2::Aborted
    );
}

#[test]
fn compacted_checkpoint_remains_a_gc_root_after_the_aborted_slot_is_overwritten() {
    let mut fixture = compaction_fixture();
    let compacted = fixture
        .store
        .compact_aborted_to_idle(
            &fixture.checkpoint_envelope,
            1_783_100_000_006,
            &mut fixture.signing_authority,
            &mut fixture.rollback_authority,
        )
        .unwrap();
    let idle = compacted.selected_record();
    let signing_key = SigningKey::from_bytes(&[0x32; 32]);
    let transaction_id = nonce(0x81);
    let owner = DeploymentOwnerClaimV2::new(
        transaction_id,
        DeploymentOwnerRoleV2::Helper,
        digest(0x82),
        201,
        202,
        digest(0x83),
        nonce(0x84),
        1,
        300_000,
    )
    .unwrap();
    let next_head = DurableDeploymentTransactionRecordV2::new_signed_for_test(
        idle.projection().installation_id(),
        idle.projection().installation_epoch(),
        transaction_id,
        digest(0x85),
        1,
        None,
        idle.signed_record_digest(),
        idle.projection().generation(),
        DeploymentPhaseV2::Prepared,
        prepared_steps(),
        vec![DurableDeploymentEvidenceRefV2::StoreCompatibility(digest(
            0x86,
        ))],
        owner,
        300_000,
        1_783_100_000_007,
        &signing_key,
    )
    .unwrap();
    let verifier = DeploymentActivationVerifierV2::new(
        idle.projection().installation_id(),
        fixture.checkpoint.activation_key_id(),
        idle.projection().installation_epoch(),
        signing_key.verifying_key().to_bytes(),
    )
    .unwrap();
    let next_record = DeploymentLedgerRecordV2::new_successor_signed_with_authority(
        idle,
        DeploymentBranchV2::Normal,
        &next_head,
        DeploymentActivationUpdateV2::Retain,
        idle.highest_ever().clone(),
        1_783_100_000_008,
        &mut fixture.signing_authority,
        &verifier,
    )
    .unwrap();
    fixture
        .store
        .commit_transition(
            None,
            DeploymentBranchV2::Normal,
            &next_head,
            &next_record,
            &mut fixture.signing_authority,
            &mut fixture.rollback_authority,
        )
        .unwrap();

    assert_eq!(
        fixture
            .store
            .gc_current_generation_orphan_heads(
                DeploymentBranchV2::Normal,
                &mut fixture.rollback_authority,
            )
            .unwrap(),
        0
    );
    let published_heads = fs::read_dir(fixture.head_directory.path())
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .as_encoded_bytes()
                .strip_suffix(b".cbor")
                .is_some_and(|stem| {
                    stem.len() == 64
                        && stem
                            .iter()
                            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
                })
        })
        .count();
    assert_eq!(published_heads, 3);
}
