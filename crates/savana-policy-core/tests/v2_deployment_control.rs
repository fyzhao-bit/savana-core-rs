use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

use ed25519_dalek::SigningKey;
use savana_kernel_protocol::v2::{derive_ed25519_key_id_v2, Digest32V2, Nonce32V2};
use savana_policy_core::v2::{
    select_authenticated_ledger_slot_v2, ClosedDeploymentFailureClassV2,
    ClosedDurableDeploymentStepV2, ClosedSecurityDomainV2, DeploymentActivationVerifierV2,
    DeploymentBranchV2, DeploymentControlErrorV2, DeploymentFailureEvidenceV2,
    DeploymentLedgerProjectionV2, DeploymentLedgerRecordV2, DeploymentLedgerStoreV2,
    DeploymentOwnerClaimV2, DeploymentOwnerIdentityV2, DeploymentOwnerRoleV2, DeploymentPhaseV2,
    DeploymentTransitionV2, DurableDeploymentEvidenceRefV2, DurableDeploymentTransactionRecordV2,
    DurableDeploymentTransactionStoreV2, DurableDeploymentTransitionStoreV2,
    DurableInstallationEvidenceStoreV2, HighWaterEntryV2, HighestEverV2,
    InstallationEvidenceEnvelopeV2, LedgerSlotIdV2, RollbackGrantStateV2, RollbackOriginPhaseV2,
    SignedLedgerSlotV2, TestDeploymentCrashPointV2, TestDeploymentGcCrashPointV2,
    TestNativeDeploymentSigningAuthorityV2, TestNativeRollbackAuthorityV2, VerifiedLedgerSlotV2,
};
use sha2::Digest as _;

fn digest(seed: u8) -> Digest32V2 {
    Digest32V2::new([seed; 32])
}

fn transaction(seed: u8) -> Nonce32V2 {
    Nonce32V2::new([seed; 32])
}

fn projection(
    generation: u64,
    previous: Digest32V2,
    payload: Digest32V2,
) -> DeploymentLedgerProjectionV2 {
    DeploymentLedgerProjectionV2::new_for_test(
        digest(1),
        2,
        generation,
        previous,
        payload,
        DeploymentPhaseV2::Prepared,
        Some(transaction(3)),
        false,
        5,
        RollbackGrantStateV2::Prearmed,
        Some(digest(6)),
    )
    .unwrap()
}

#[test]
fn highest_ever_uses_the_exact_closed_28_domain_order() {
    assert_eq!(ClosedSecurityDomainV2::ALL.len(), 28);
    for (index, domain) in ClosedSecurityDomainV2::ALL.iter().copied().enumerate() {
        assert_eq!(domain.tag(), u16::try_from(index).unwrap() + 1);
        assert_eq!(domain.index(), index);
    }
    let vector = HighestEverV2::new(std::array::from_fn(|index| {
        HighWaterEntryV2::new(
            u64::try_from(index).unwrap() + 1,
            digest(u8::try_from(index).unwrap() + 1),
            1,
        )
        .unwrap()
    }))
    .unwrap();
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder.array(28).unwrap();
    for index in 0_u8..28 {
        encoder.array(3).unwrap();
        encoder.u64(u64::from(index) + 1).unwrap();
        encoder.bytes(&[index + 1; 32]).unwrap();
        encoder.u64(1).unwrap();
    }
    let canonical = encoder.into_writer();
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"savana.highest-ever.v2\0");
    hasher.update(&canonical);
    assert_eq!(vector.canonical_bytes().unwrap(), canonical);
    assert_eq!(vector.digest().unwrap().as_bytes(), &hasher.finalize()[..]);
    assert_eq!(
        vector
            .entry(ClosedSecurityDomainV2::BinaryRelease)
            .sequence(),
        1
    );
    let advanced = vector
        .with_advanced(
            ClosedSecurityDomainV2::BinaryRelease,
            HighWaterEntryV2::new(29, digest(0xee), 2).unwrap(),
        )
        .unwrap();
    assert_eq!(
        advanced
            .entry(ClosedSecurityDomainV2::BinaryRelease)
            .sequence(),
        29
    );
    assert_eq!(
        vector
            .with_advanced(
                ClosedSecurityDomainV2::BinaryRelease,
                HighWaterEntryV2::new(1, digest(0xef), 2).unwrap(),
            )
            .unwrap_err(),
        DeploymentControlErrorV2::HighestEverMismatch
    );
}

#[test]
fn normal_and_bridge_phase_graphs_are_closed_and_non_interchangeable() {
    assert!(DeploymentTransitionV2::new(
        DeploymentBranchV2::Normal,
        DeploymentPhaseV2::Prepared,
        DeploymentPhaseV2::Armed,
    )
    .is_ok());
    assert!(DeploymentTransitionV2::new(
        DeploymentBranchV2::Normal,
        DeploymentPhaseV2::Verified,
        DeploymentPhaseV2::Committed,
    )
    .is_ok());
    assert!(DeploymentTransitionV2::new(
        DeploymentBranchV2::Normal,
        DeploymentPhaseV2::Installed,
        DeploymentPhaseV2::RollbackPrepared,
    )
    .is_ok());
    assert!(DeploymentTransitionV2::new(
        DeploymentBranchV2::BootstrapBridgeRestore,
        DeploymentPhaseV2::Installed,
        DeploymentPhaseV2::BridgeRestorePrepared,
    )
    .is_ok());
    assert!(DeploymentTransitionV2::new(
        DeploymentBranchV2::BootstrapBridgeRestore,
        DeploymentPhaseV2::Verified,
        DeploymentPhaseV2::Committed,
    )
    .is_ok());

    assert_eq!(
        DeploymentTransitionV2::new(
            DeploymentBranchV2::Normal,
            DeploymentPhaseV2::Installed,
            DeploymentPhaseV2::BridgeRestorePrepared,
        )
        .unwrap_err(),
        DeploymentControlErrorV2::IllegalPhaseTransition
    );
    assert_eq!(
        DeploymentTransitionV2::new(
            DeploymentBranchV2::BootstrapBridgeRestore,
            DeploymentPhaseV2::Installed,
            DeploymentPhaseV2::RollbackPrepared,
        )
        .unwrap_err(),
        DeploymentControlErrorV2::IllegalPhaseTransition
    );
}

#[test]
fn dual_slot_selection_implements_the_exact_conflict_table() {
    let old = projection(7, digest(10), digest(11));
    let new = projection(8, digest(11), digest(12));
    let slot_a = VerifiedLedgerSlotV2::new_for_test(LedgerSlotIdV2::A, old.clone()).unwrap();
    let slot_b = VerifiedLedgerSlotV2::new_for_test(LedgerSlotIdV2::B, new.clone()).unwrap();
    assert_eq!(
        select_authenticated_ledger_slot_v2(Some(slot_a), Some(slot_b))
            .unwrap()
            .record_payload_digest(),
        digest(12)
    );

    let gap = VerifiedLedgerSlotV2::new_for_test(
        LedgerSlotIdV2::B,
        projection(9, digest(11), digest(13)),
    )
    .unwrap();
    assert_eq!(
        select_authenticated_ledger_slot_v2(
            Some(VerifiedLedgerSlotV2::new_for_test(LedgerSlotIdV2::A, old.clone()).unwrap()),
            Some(gap),
        )
        .unwrap_err(),
        DeploymentControlErrorV2::LedgerConflict
    );

    let equivocation = VerifiedLedgerSlotV2::new_for_test(
        LedgerSlotIdV2::B,
        projection(7, digest(10), digest(99)),
    )
    .unwrap();
    assert_eq!(
        select_authenticated_ledger_slot_v2(
            Some(VerifiedLedgerSlotV2::new_for_test(LedgerSlotIdV2::A, old).unwrap()),
            Some(equivocation),
        )
        .unwrap_err(),
        DeploymentControlErrorV2::LedgerEquivocation
    );
}

#[test]
fn grant_fence_and_head_rules_are_checked_with_the_phase_transition() {
    let current = projection(7, digest(10), digest(11));
    let armed = DeploymentLedgerProjectionV2::new_for_test(
        digest(1),
        2,
        8,
        digest(11),
        digest(12),
        DeploymentPhaseV2::Armed,
        Some(transaction(3)),
        true,
        6,
        RollbackGrantStateV2::Prearmed,
        Some(digest(7)),
    )
    .unwrap();
    current
        .validate_successor(&armed, DeploymentBranchV2::Normal)
        .unwrap();

    assert_eq!(
        DeploymentLedgerProjectionV2::new_for_test(
            digest(1),
            2,
            8,
            digest(11),
            digest(12),
            DeploymentPhaseV2::Armed,
            Some(transaction(3)),
            false,
            5,
            RollbackGrantStateV2::Prearmed,
            Some(digest(7)),
        )
        .unwrap_err(),
        DeploymentControlErrorV2::InvalidLedgerRecord
    );
}

#[test]
fn active_manifest_cannot_change_before_a_committed_transition() {
    let signing_key = SigningKey::from_bytes(&[0x51; 32]);
    let installation_id = digest(0x52);
    let current = DeploymentLedgerRecordV2::new_signed_for_test(
        installation_id,
        12,
        5,
        digest(0x53),
        DeploymentPhaseV2::Idle,
        None,
        false,
        9,
        RollbackGrantStateV2::None,
        None,
        1_783_000_000_200,
        0x54,
        &signing_key,
    )
    .unwrap();
    let prepared = DeploymentLedgerRecordV2::new_signed_for_test(
        installation_id,
        12,
        6,
        current.record_payload_digest(),
        DeploymentPhaseV2::Prepared,
        Some(transaction(0x55)),
        false,
        9,
        RollbackGrantStateV2::Prearmed,
        Some(digest(0x56)),
        1_783_000_000_201,
        0x54,
        &signing_key,
    )
    .unwrap();
    current
        .validate_successor(&prepared, DeploymentBranchV2::Normal)
        .unwrap();

    let substituted = prepared
        .with_active_manifest_for_test(digest(0x57), &signing_key)
        .unwrap();
    assert_eq!(
        current
            .validate_successor(&substituted, DeploymentBranchV2::Normal)
            .unwrap_err(),
        DeploymentControlErrorV2::ActiveStateMismatch
    );
}

#[test]
fn committed_transition_must_activate_a_new_normal_manifest() {
    let signing_key = SigningKey::from_bytes(&[0x61; 32]);
    let installation_id = digest(0x62);
    let verified = DeploymentLedgerRecordV2::new_signed_for_test(
        installation_id,
        13,
        20,
        digest(0x63),
        DeploymentPhaseV2::Verified,
        Some(transaction(0x64)),
        true,
        14,
        RollbackGrantStateV2::Prearmed,
        Some(digest(0x65)),
        1_783_000_000_300,
        0x66,
        &signing_key,
    )
    .unwrap();
    let unchanged = DeploymentLedgerRecordV2::new_signed_for_test(
        installation_id,
        13,
        21,
        verified.record_payload_digest(),
        DeploymentPhaseV2::Committed,
        Some(transaction(0x64)),
        false,
        15,
        RollbackGrantStateV2::Burned,
        Some(digest(0x67)),
        1_783_000_000_301,
        0x66,
        &signing_key,
    )
    .unwrap();
    assert_eq!(
        verified
            .validate_successor(&unchanged, DeploymentBranchV2::Normal)
            .unwrap_err(),
        DeploymentControlErrorV2::ActiveStateMismatch
    );

    let activated = unchanged
        .with_active_manifest_for_test(digest(0x68), &signing_key)
        .unwrap();
    verified
        .validate_successor(&activated, DeploymentBranchV2::Normal)
        .unwrap();
}

#[test]
fn rollback_origin_is_bound_to_the_exact_source_phase() {
    let signing_key = SigningKey::from_bytes(&[0x69; 32]);
    let installation_id = digest(0x6a);
    let installed = DeploymentLedgerRecordV2::new_signed_for_test(
        installation_id,
        14,
        30,
        digest(0x6b),
        DeploymentPhaseV2::Installed,
        Some(transaction(0x6c)),
        true,
        18,
        RollbackGrantStateV2::Prearmed,
        Some(digest(0x6d)),
        1_783_000_000_400,
        0x6e,
        &signing_key,
    )
    .unwrap();
    let wrong_origin = DeploymentLedgerRecordV2::new_signed_with_origin_for_test(
        installation_id,
        14,
        31,
        installed.record_payload_digest(),
        DeploymentPhaseV2::RollbackPrepared,
        Some(transaction(0x6c)),
        true,
        19,
        RollbackGrantStateV2::Consuming,
        Some(RollbackOriginPhaseV2::Quiesced),
        Some(digest(0x6f)),
        1_783_000_000_401,
        0x6e,
        &signing_key,
    )
    .unwrap();
    assert_eq!(
        installed
            .validate_successor(&wrong_origin, DeploymentBranchV2::Normal)
            .unwrap_err(),
        DeploymentControlErrorV2::RollbackOriginMismatch
    );

    let exact_origin = DeploymentLedgerRecordV2::new_signed_with_origin_for_test(
        installation_id,
        14,
        31,
        installed.record_payload_digest(),
        DeploymentPhaseV2::RollbackPrepared,
        Some(transaction(0x6c)),
        true,
        19,
        RollbackGrantStateV2::Consuming,
        Some(RollbackOriginPhaseV2::Installed),
        Some(digest(0x70)),
        1_783_000_000_401,
        0x6e,
        &signing_key,
    )
    .unwrap();
    installed
        .validate_successor(&exact_origin, DeploymentBranchV2::Normal)
        .unwrap();
}

#[test]
fn watchdog_takeover_requires_expiry_and_the_exact_process_identity() {
    let helper = DeploymentOwnerClaimV2::new(
        transaction(20),
        DeploymentOwnerRoleV2::Helper,
        digest(21),
        22,
        23,
        digest(24),
        transaction(25),
        6,
        1_000,
    )
    .unwrap();
    let observed_helper = DeploymentOwnerIdentityV2::new(digest(21), 22, 23, digest(24)).unwrap();
    let watchdog = DeploymentOwnerIdentityV2::new(digest(31), 32, 33, digest(34)).unwrap();
    assert_eq!(
        helper
            .watchdog_takeover(&observed_helper, watchdog, 999, transaction(26), 2_000,)
            .unwrap_err(),
        DeploymentControlErrorV2::HeartbeatLive
    );
    let takeover = helper
        .watchdog_takeover(&observed_helper, watchdog, 1_000, transaction(26), 2_000)
        .unwrap();
    assert_eq!(takeover.owner_role(), DeploymentOwnerRoleV2::Watchdog);
    assert_eq!(takeover.heartbeat_generation(), 7);

    let wrong = DeploymentOwnerIdentityV2::new(digest(21), 22, 24, digest(24)).unwrap();
    assert_eq!(
        helper
            .watchdog_takeover(&wrong, watchdog, 1_000, transaction(27), 2_000)
            .unwrap_err(),
        DeploymentControlErrorV2::OwnerIdentityMismatch
    );
}

#[test]
fn owner_heartbeat_renewal_requires_the_live_exact_process_identity() {
    let owner = DeploymentOwnerClaimV2::new(
        transaction(30),
        DeploymentOwnerRoleV2::Helper,
        digest(31),
        32,
        33,
        digest(34),
        transaction(35),
        4,
        10_000,
    )
    .unwrap();
    let observed = DeploymentOwnerIdentityV2::new(digest(31), 32, 33, digest(34)).unwrap();
    let renewed = owner.renew_heartbeat(&observed, 9_000, 20_000).unwrap();
    assert_eq!(renewed.owner_role(), DeploymentOwnerRoleV2::Helper);
    assert_eq!(renewed.identity(), observed);
    assert_eq!(renewed.operation_nonce(), transaction(35));
    assert_eq!(renewed.heartbeat_generation(), 5);
    assert_eq!(renewed.heartbeat_deadline_monotonic_ns(), 20_000);

    let wrong = DeploymentOwnerIdentityV2::new(digest(31), 32, 36, digest(34)).unwrap();
    assert_eq!(
        owner.renew_heartbeat(&wrong, 9_000, 20_000).unwrap_err(),
        DeploymentControlErrorV2::OwnerIdentityMismatch
    );
    assert_eq!(
        owner
            .renew_heartbeat(&observed, 10_000, 20_000)
            .unwrap_err(),
        DeploymentControlErrorV2::HeartbeatExpired
    );
    assert_eq!(
        owner.renew_heartbeat(&observed, 9_000, 10_000).unwrap_err(),
        DeploymentControlErrorV2::OwnerIdentityMismatch
    );
}

#[test]
fn complete_ledger_record_rejects_noncanonical_bytes_and_signature_substitution() {
    let signing_key = SigningKey::from_bytes(&[0x71; 32]);
    let key_id = derive_ed25519_key_id_v2(signing_key.verifying_key().to_bytes());
    let verifier = DeploymentActivationVerifierV2::new(
        digest(1),
        key_id,
        7,
        signing_key.verifying_key().to_bytes(),
    )
    .unwrap();
    let record = DeploymentLedgerRecordV2::new_signed_for_test(
        digest(1),
        7,
        11,
        digest(2),
        DeploymentPhaseV2::Prepared,
        Some(transaction(3)),
        false,
        1,
        RollbackGrantStateV2::Prearmed,
        Some(digest(4)),
        1_783_000_000_000,
        0x20,
        &signing_key,
    )
    .unwrap();

    let reopened =
        DeploymentLedgerRecordV2::from_canonical_bytes(record.canonical_bytes(), &verifier)
            .unwrap();
    assert_eq!(
        reopened.record_payload_digest(),
        record.record_payload_digest()
    );
    assert_eq!(
        reopened.signed_record_digest(),
        record.signed_record_digest()
    );
    assert_eq!(reopened.highest_ever().entries().len(), 28);

    let mut noncanonical = record.canonical_bytes().to_vec();
    // schema_version=2 is the first member after the one-byte 21-element
    // array header. 0x18 0x02 is a valid but non-minimal CBOR integer.
    assert_eq!(noncanonical[1], 0x02);
    noncanonical.splice(1..2, [0x18, 0x02]);
    assert_eq!(
        DeploymentLedgerRecordV2::from_canonical_bytes(&noncanonical, &verifier).unwrap_err(),
        DeploymentControlErrorV2::NonCanonicalLedgerEncoding
    );

    let other_key = SigningKey::from_bytes(&[0x72; 32]);
    let other_verifier = DeploymentActivationVerifierV2::new(
        digest(1),
        derive_ed25519_key_id_v2(other_key.verifying_key().to_bytes()),
        7,
        other_key.verifying_key().to_bytes(),
    )
    .unwrap();
    assert_eq!(
        DeploymentLedgerRecordV2::from_canonical_bytes(record.canonical_bytes(), &other_verifier)
            .unwrap_err(),
        DeploymentControlErrorV2::ActivationKeyMismatch
    );
    let wrong_installation_verifier = DeploymentActivationVerifierV2::new(
        digest(99),
        key_id,
        7,
        signing_key.verifying_key().to_bytes(),
    )
    .unwrap();
    assert_eq!(
        DeploymentLedgerRecordV2::from_canonical_bytes(
            record.canonical_bytes(),
            &wrong_installation_verifier,
        )
        .unwrap_err(),
        DeploymentControlErrorV2::InstallationTupleMismatch
    );
}

#[test]
fn complete_slot_authentication_checks_headers_checksum_and_distinct_domain_signature() {
    let signing_key = SigningKey::from_bytes(&[0x73; 32]);
    let verifier = DeploymentActivationVerifierV2::new(
        digest(11),
        derive_ed25519_key_id_v2(signing_key.verifying_key().to_bytes()),
        9,
        signing_key.verifying_key().to_bytes(),
    )
    .unwrap();
    let record = DeploymentLedgerRecordV2::new_signed_for_test(
        digest(11),
        9,
        17,
        digest(12),
        DeploymentPhaseV2::Prepared,
        Some(transaction(13)),
        false,
        2,
        RollbackGrantStateV2::Prearmed,
        Some(digest(14)),
        1_783_000_000_001,
        0x40,
        &signing_key,
    )
    .unwrap();
    let slot =
        SignedLedgerSlotV2::new_signed_for_test(LedgerSlotIdV2::B, &record, &signing_key).unwrap();

    let verified =
        SignedLedgerSlotV2::verify_canonical_bytes(slot.canonical_bytes(), &verifier).unwrap();
    assert_eq!(verified.slot_id(), LedgerSlotIdV2::B);
    assert_eq!(verified.record().generation(), 17);

    let mut corrupted = slot.canonical_bytes().to_vec();
    let last = corrupted.len() - 1;
    corrupted[last] ^= 1;
    assert_eq!(
        SignedLedgerSlotV2::verify_canonical_bytes(&corrupted, &verifier).unwrap_err(),
        DeploymentControlErrorV2::InvalidActivationSignature
    );
}

#[test]
fn durable_writer_overwrites_only_the_older_slot_and_reconciles_counter_crash_window() {
    let temporary = tempfile::tempdir().unwrap();
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let signing_key = SigningKey::from_bytes(&[0x74; 32]);
    let verifier = DeploymentActivationVerifierV2::new(
        digest(41),
        derive_ed25519_key_id_v2(signing_key.verifying_key().to_bytes()),
        12,
        signing_key.verifying_key().to_bytes(),
    )
    .unwrap();
    let genesis = DeploymentLedgerRecordV2::new_signed_for_test(
        digest(41),
        12,
        1,
        Digest32V2::new([0; 32]),
        DeploymentPhaseV2::Idle,
        None,
        false,
        1,
        RollbackGrantStateV2::None,
        None,
        1_783_000_000_010,
        0x60,
        &signing_key,
    )
    .unwrap();
    let slot_a =
        SignedLedgerSlotV2::new_signed_for_test(LedgerSlotIdV2::A, &genesis, &signing_key).unwrap();
    let slot_b =
        SignedLedgerSlotV2::new_signed_for_test(LedgerSlotIdV2::B, &genesis, &signing_key).unwrap();
    fs::write(
        temporary.path().join("ledger-a.cbor"),
        slot_a.canonical_bytes(),
    )
    .unwrap();
    fs::write(
        temporary.path().join("ledger-b.cbor"),
        slot_b.canonical_bytes(),
    )
    .unwrap();
    fs::set_permissions(
        temporary.path().join("ledger-a.cbor"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    fs::set_permissions(
        temporary.path().join("ledger-b.cbor"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();

    let store =
        DeploymentLedgerStoreV2::open_for_test(temporary.path(), verifier, digest(44)).unwrap();
    let successor = DeploymentLedgerRecordV2::new_signed_for_test(
        digest(41),
        12,
        2,
        genesis.record_payload_digest(),
        DeploymentPhaseV2::Prepared,
        Some(transaction(42)),
        false,
        1,
        RollbackGrantStateV2::Prearmed,
        Some(digest(43)),
        1_783_000_000_011,
        0x60,
        &signing_key,
    )
    .unwrap();
    let mut signing_authority =
        TestNativeDeploymentSigningAuthorityV2::new_for_test([46; 32], [41; 32], 12, [0x74; 32])
            .unwrap();
    let mut authority =
        TestNativeRollbackAuthorityV2::new_for_test([44; 32], [41; 32], 12, 1).unwrap();
    let mut wrong_authority =
        TestNativeRollbackAuthorityV2::new_for_test([45; 32], [41; 32], 12, 1).unwrap();
    assert_eq!(
        store.load_selected(&mut wrong_authority).unwrap_err(),
        DeploymentControlErrorV2::NativeRollbackAuthorityUnavailable
    );
    authority.fail_next_advance_for_test();
    assert_eq!(
        store
            .write_successor_record(
                &successor,
                DeploymentBranchV2::Normal,
                &mut signing_authority,
                &mut authority,
            )
            .unwrap_err(),
        DeploymentControlErrorV2::NativeRollbackAuthorityUnavailable
    );

    // The signed successor is already durable, while the simulated native
    // counter remains at its predecessor. Reopening is allowed to perform
    // exactly this adjacent, hash-linked compare-and-advance and no other.
    let selected = store.load_selected(&mut authority).unwrap();
    assert_eq!(selected.generation(), 2);
    assert_eq!(authority.generation_for_test(), 2);
    let authenticated = store.load_selected_authenticated(&mut authority).unwrap();
    assert_eq!(
        authenticated.selected_record().signed_record_digest(),
        successor.signed_record_digest()
    );
    assert_eq!(
        authenticated
            .predecessor_record()
            .unwrap()
            .signed_record_digest(),
        genesis.signed_record_digest()
    );
    let retained_b = fs::read(temporary.path().join("ledger-b.cbor")).unwrap();
    assert_eq!(retained_b, slot_b.canonical_bytes());
}

#[test]
fn durable_transition_store_publishes_head_before_ledger_and_recovers_counter_window() {
    let ledger_directory = tempfile::tempdir().unwrap();
    let head_directory = tempfile::tempdir().unwrap();
    fs::set_permissions(ledger_directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(head_directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let installation_id = digest(0xb0);
    let seed = [0xb1; 32];
    let signing_key = SigningKey::from_bytes(&seed);
    let verifier = DeploymentActivationVerifierV2::new(
        installation_id,
        derive_ed25519_key_id_v2(signing_key.verifying_key().to_bytes()),
        21,
        signing_key.verifying_key().to_bytes(),
    )
    .unwrap();
    let genesis = DeploymentLedgerRecordV2::new_signed_for_test(
        installation_id,
        21,
        1,
        Digest32V2::new([0; 32]),
        DeploymentPhaseV2::Idle,
        None,
        false,
        1,
        RollbackGrantStateV2::None,
        None,
        1_783_000_001_000,
        0xb2,
        &signing_key,
    )
    .unwrap();
    for (leaf, slot_id) in [
        ("ledger-a.cbor", LedgerSlotIdV2::A),
        ("ledger-b.cbor", LedgerSlotIdV2::B),
    ] {
        let slot =
            SignedLedgerSlotV2::new_signed_for_test(slot_id, &genesis, &signing_key).unwrap();
        let path = ledger_directory.path().join(leaf);
        fs::write(&path, slot.canonical_bytes()).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let ledger_store = DeploymentLedgerStoreV2::open_for_test(
        ledger_directory.path(),
        verifier.clone(),
        digest(0xb3),
    )
    .unwrap();
    let head_store =
        DurableDeploymentTransactionStoreV2::open_for_test(head_directory.path(), verifier.clone())
            .unwrap();
    let transition_store = DurableDeploymentTransitionStoreV2::new(ledger_store, head_store);
    let transaction_id = transaction(0xb4);
    let owner = DeploymentOwnerClaimV2::new(
        transaction_id,
        DeploymentOwnerRoleV2::Helper,
        digest(0xb5),
        182,
        183,
        digest(0xb8),
        transaction(0xb9),
        1,
        120_000,
    )
    .unwrap();
    let prepared_head = DurableDeploymentTransactionRecordV2::new_signed_for_test(
        installation_id,
        21,
        transaction_id,
        digest(0xba),
        1,
        None,
        genesis.signed_record_digest(),
        1,
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
            0xbb,
        ))],
        owner,
        120_000,
        1_783_000_001_001,
        &signing_key,
    )
    .unwrap();
    let mut signing_authority = TestNativeDeploymentSigningAuthorityV2::new_for_test(
        [0xbc; 32],
        *installation_id.as_bytes(),
        21,
        seed,
    )
    .unwrap();
    let prepared_record = DeploymentLedgerRecordV2::new_successor_signed_with_authority(
        &genesis,
        DeploymentBranchV2::Normal,
        &prepared_head,
        savana_policy_core::v2::DeploymentActivationUpdateV2::Retain,
        genesis.highest_ever().clone(),
        1_783_000_001_002,
        &mut signing_authority,
        &verifier,
    )
    .unwrap();
    let mut rollback_authority =
        TestNativeRollbackAuthorityV2::new_for_test([0xb3; 32], *installation_id.as_bytes(), 21, 1)
            .unwrap();
    rollback_authority.fail_next_advance_for_test();

    assert_eq!(
        transition_store
            .commit_transition(
                None,
                DeploymentBranchV2::Normal,
                &prepared_head,
                &prepared_record,
                &mut signing_authority,
                &mut rollback_authority,
            )
            .unwrap_err(),
        DeploymentControlErrorV2::NativeRollbackAuthorityUnavailable
    );

    let recovered = transition_store
        .load_authenticated(&mut rollback_authority)
        .unwrap();
    assert_eq!(
        recovered.selected_record().signed_record_digest(),
        prepared_record.signed_record_digest()
    );
    let chain = transition_store
        .authenticate_selected_chain(&recovered, DeploymentBranchV2::Normal)
        .unwrap();
    assert_eq!(chain.len(), 1);
    assert_eq!(chain[0].signed_digest(), prepared_head.signed_digest());
}

struct TransitionCrashFixture {
    _ledger_directory: tempfile::TempDir,
    head_directory: tempfile::TempDir,
    evidence_directory: tempfile::TempDir,
    store: DurableDeploymentTransitionStoreV2,
    verifier: DeploymentActivationVerifierV2,
    genesis: DeploymentLedgerRecordV2,
    prepared_head: DurableDeploymentTransactionRecordV2,
    prepared_record: DeploymentLedgerRecordV2,
    signing_authority: TestNativeDeploymentSigningAuthorityV2,
    rollback_authority: TestNativeRollbackAuthorityV2,
}

fn transition_crash_fixture() -> TransitionCrashFixture {
    let ledger_directory = tempfile::tempdir().unwrap();
    let head_directory = tempfile::tempdir().unwrap();
    let evidence_directory = tempfile::tempdir().unwrap();
    for directory in [
        ledger_directory.path(),
        head_directory.path(),
        evidence_directory.path(),
    ] {
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let installation_id = digest(0xc0);
    let seed = [0xc1; 32];
    let signing_key = SigningKey::from_bytes(&seed);
    let verifier = DeploymentActivationVerifierV2::new(
        installation_id,
        derive_ed25519_key_id_v2(signing_key.verifying_key().to_bytes()),
        22,
        signing_key.verifying_key().to_bytes(),
    )
    .unwrap();
    let genesis = DeploymentLedgerRecordV2::new_signed_for_test(
        installation_id,
        22,
        1,
        Digest32V2::new([0; 32]),
        DeploymentPhaseV2::Idle,
        None,
        false,
        1,
        RollbackGrantStateV2::None,
        None,
        1_783_000_001_100,
        0xc2,
        &signing_key,
    )
    .unwrap();
    for (leaf, slot_id) in [
        ("ledger-a.cbor", LedgerSlotIdV2::A),
        ("ledger-b.cbor", LedgerSlotIdV2::B),
    ] {
        let slot =
            SignedLedgerSlotV2::new_signed_for_test(slot_id, &genesis, &signing_key).unwrap();
        let path = ledger_directory.path().join(leaf);
        fs::write(&path, slot.canonical_bytes()).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let ledger_store = DeploymentLedgerStoreV2::open_for_test(
        ledger_directory.path(),
        verifier.clone(),
        digest(0xc3),
    )
    .unwrap();
    let head_store =
        DurableDeploymentTransactionStoreV2::open_for_test(head_directory.path(), verifier.clone())
            .unwrap();
    let evidence_store = DurableInstallationEvidenceStoreV2::open_for_test(
        evidence_directory.path(),
        verifier.clone(),
    )
    .unwrap();
    let transaction_id = transaction(0xc4);
    let owner = DeploymentOwnerClaimV2::new(
        transaction_id,
        DeploymentOwnerRoleV2::Helper,
        digest(0xc5),
        192,
        193,
        digest(0xc6),
        transaction(0xc7),
        1,
        130_000,
    )
    .unwrap();
    let prepared_head = DurableDeploymentTransactionRecordV2::new_signed_for_test(
        installation_id,
        22,
        transaction_id,
        digest(0xc8),
        1,
        None,
        genesis.signed_record_digest(),
        1,
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
            0xc9,
        ))],
        owner,
        130_000,
        1_783_000_001_101,
        &signing_key,
    )
    .unwrap();
    let mut signing_authority = TestNativeDeploymentSigningAuthorityV2::new_for_test(
        [0xca; 32],
        *installation_id.as_bytes(),
        22,
        seed,
    )
    .unwrap();
    let prepared_record = DeploymentLedgerRecordV2::new_successor_signed_with_authority(
        &genesis,
        DeploymentBranchV2::Normal,
        &prepared_head,
        savana_policy_core::v2::DeploymentActivationUpdateV2::Retain,
        genesis.highest_ever().clone(),
        1_783_000_001_102,
        &mut signing_authority,
        &verifier,
    )
    .unwrap();
    let rollback_authority =
        TestNativeRollbackAuthorityV2::new_for_test([0xc3; 32], *installation_id.as_bytes(), 22, 1)
            .unwrap();
    TransitionCrashFixture {
        _ledger_directory: ledger_directory,
        head_directory,
        evidence_directory,
        store: DurableDeploymentTransitionStoreV2::new_with_installation_evidence(
            ledger_store,
            head_store,
            evidence_store,
        ),
        verifier,
        genesis,
        prepared_head,
        prepared_record,
        signing_authority,
        rollback_authority,
    }
}

#[test]
fn every_durable_transition_boundary_recovers_old_or_exact_new_state() {
    use TestDeploymentCrashPointV2 as Crash;

    for point in Crash::ALL {
        let mut fixture = transition_crash_fixture();
        let expected_error = match point {
            Crash::LedgerFileFlushed
            | Crash::LedgerRenamedBeforeDirectoryFlush
            | Crash::LedgerDirectoryFlushed => DeploymentControlErrorV2::DeploymentLedgerIo,
            _ => DeploymentControlErrorV2::DeploymentTransactionIo,
        };
        assert_eq!(
            fixture
                .store
                .commit_transition_with_crash_for_test(
                    None,
                    DeploymentBranchV2::Normal,
                    &fixture.prepared_head,
                    &fixture.prepared_record,
                    &mut fixture.signing_authority,
                    &mut fixture.rollback_authority,
                    point,
                )
                .unwrap_err(),
            expected_error,
            "unexpected injected result at {point:?}"
        );

        let head_was_renamed = point >= Crash::HeadRenamedBeforeDirectoryFlush;
        let published_heads = fs::read_dir(fixture.head_directory.path())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "cbor")
            })
            .count();
        assert_eq!(
            published_heads,
            usize::from(head_was_renamed),
            "unexpected visible head set at {point:?}"
        );

        let ledger_was_renamed = point >= Crash::LedgerRenamedBeforeDirectoryFlush;
        let counter_was_advanced = point >= Crash::CounterAdvanced;
        assert_eq!(
            fixture.rollback_authority.generation_for_test(),
            if counter_was_advanced { 2 } else { 1 },
            "unexpected counter state before recovery at {point:?}"
        );

        let recovered = fixture
            .store
            .load_authenticated(&mut fixture.rollback_authority)
            .unwrap();
        let expected = if ledger_was_renamed {
            fixture.prepared_record.signed_record_digest()
        } else {
            fixture.genesis.signed_record_digest()
        };
        assert_eq!(
            recovered.selected_record().signed_record_digest(),
            expected,
            "unexpected selected ledger at {point:?}"
        );
        assert_eq!(
            fixture.rollback_authority.generation_for_test(),
            if ledger_was_renamed { 2 } else { 1 },
            "counter did not converge at {point:?}"
        );
        let chain = fixture
            .store
            .authenticate_selected_chain(&recovered, DeploymentBranchV2::Normal)
            .unwrap();
        if ledger_was_renamed {
            assert_eq!(chain.len(), 1, "missing selected head at {point:?}");
            assert_eq!(
                chain[0].signed_digest(),
                fixture.prepared_head.signed_digest()
            );
        } else {
            assert!(chain.is_empty(), "orphan head selected at {point:?}");
        }
    }
}

#[test]
fn failed_safe_transition_resolves_and_binds_the_durable_failure_envelope() {
    let mut fixture = transition_crash_fixture();
    fixture
        .store
        .commit_transition(
            None,
            DeploymentBranchV2::Normal,
            &fixture.prepared_head,
            &fixture.prepared_record,
            &mut fixture.signing_authority,
            &mut fixture.rollback_authority,
        )
        .unwrap();

    let signing_key = SigningKey::from_bytes(&[0xc1; 32]);
    let arbitrary_failure_head = DurableDeploymentTransactionRecordV2::new_signed_for_test(
        fixture.prepared_head.installation_id(),
        fixture.prepared_head.installation_epoch(),
        fixture.prepared_head.transaction_id(),
        fixture.prepared_head.core_signed_digest(),
        2,
        Some(fixture.prepared_head.signed_digest()),
        fixture.prepared_record.signed_record_digest(),
        2,
        DeploymentPhaseV2::FailedSafe,
        fixture.prepared_head.completed_steps().to_vec(),
        vec![
            DurableDeploymentEvidenceRefV2::StoreCompatibility(digest(0xc9)),
            DurableDeploymentEvidenceRefV2::DeploymentFailure(digest(0xee)),
        ],
        fixture.prepared_head.owner(),
        130_000,
        1_783_000_001_103,
        &signing_key,
    )
    .unwrap();
    let arbitrary_failure_record = DeploymentLedgerRecordV2::new_successor_signed_with_authority(
        &fixture.prepared_record,
        DeploymentBranchV2::Normal,
        &arbitrary_failure_head,
        savana_policy_core::v2::DeploymentActivationUpdateV2::Retain,
        fixture.prepared_record.highest_ever().clone(),
        1_783_000_001_104,
        &mut fixture.signing_authority,
        &fixture.verifier,
    )
    .unwrap();
    assert_eq!(
        fixture
            .store
            .commit_transition(
                Some(DeploymentBranchV2::Normal),
                DeploymentBranchV2::Normal,
                &arbitrary_failure_head,
                &arbitrary_failure_record,
                &mut fixture.signing_authority,
                &mut fixture.rollback_authority,
            )
            .unwrap_err(),
        DeploymentControlErrorV2::InstallationEvidenceIo
    );

    let failure = DeploymentFailureEvidenceV2::new(
        fixture.prepared_head.installation_id(),
        fixture.prepared_head.installation_epoch(),
        fixture.prepared_head.transaction_id(),
        fixture.prepared_head.core_signed_digest(),
        fixture.prepared_head.signed_digest(),
        DeploymentPhaseV2::Prepared,
        DeploymentPhaseV2::Armed,
        ClosedDeploymentFailureClassV2::NativeEffectFenceFailure,
        digest(0xd1),
        digest(0xd2),
        1_783_000_001_102,
    )
    .unwrap();
    let envelope = InstallationEvidenceEnvelopeV2::new_deployment_failure_signed_with_authority(
        1,
        None,
        &failure,
        &mut fixture.signing_authority,
        &fixture.verifier,
    )
    .unwrap();
    let evidence_writer = DurableInstallationEvidenceStoreV2::open_for_test(
        fixture.evidence_directory.path(),
        fixture.verifier.clone(),
    )
    .unwrap();
    evidence_writer.append(&envelope).unwrap();

    let failed_safe_head = DurableDeploymentTransactionRecordV2::new_signed_for_test(
        fixture.prepared_head.installation_id(),
        fixture.prepared_head.installation_epoch(),
        fixture.prepared_head.transaction_id(),
        fixture.prepared_head.core_signed_digest(),
        2,
        Some(fixture.prepared_head.signed_digest()),
        fixture.prepared_record.signed_record_digest(),
        2,
        DeploymentPhaseV2::FailedSafe,
        fixture.prepared_head.completed_steps().to_vec(),
        vec![
            DurableDeploymentEvidenceRefV2::StoreCompatibility(digest(0xc9)),
            DurableDeploymentEvidenceRefV2::DeploymentFailure(envelope.signed_digest()),
        ],
        fixture.prepared_head.owner(),
        130_000,
        1_783_000_001_103,
        &signing_key,
    )
    .unwrap();
    let failed_safe_record = DeploymentLedgerRecordV2::new_successor_signed_with_authority(
        &fixture.prepared_record,
        DeploymentBranchV2::Normal,
        &failed_safe_head,
        savana_policy_core::v2::DeploymentActivationUpdateV2::Retain,
        fixture.prepared_record.highest_ever().clone(),
        1_783_000_001_104,
        &mut fixture.signing_authority,
        &fixture.verifier,
    )
    .unwrap();
    let committed = fixture
        .store
        .commit_transition(
            Some(DeploymentBranchV2::Normal),
            DeploymentBranchV2::Normal,
            &failed_safe_head,
            &failed_safe_record,
            &mut fixture.signing_authority,
            &mut fixture.rollback_authority,
        )
        .unwrap();
    assert_eq!(
        committed.selected_record().projection().phase(),
        DeploymentPhaseV2::FailedSafe
    );
}

#[test]
fn fixed_deployment_mutex_rejects_a_concurrent_successor_before_head_publication() {
    let TransitionCrashFixture {
        _ledger_directory: ledger_directory,
        head_directory,
        evidence_directory: _,
        store,
        verifier: _,
        genesis: _,
        prepared_head,
        prepared_record,
        mut signing_authority,
        mut rollback_authority,
    } = transition_crash_fixture();
    let first_store = std::sync::Arc::new(store);
    let signing_key = SigningKey::from_bytes(&[0xc1; 32]);
    let verifier = DeploymentActivationVerifierV2::new(
        digest(0xc0),
        derive_ed25519_key_id_v2(signing_key.verifying_key().to_bytes()),
        22,
        signing_key.verifying_key().to_bytes(),
    )
    .unwrap();
    let second_store = DurableDeploymentTransitionStoreV2::new(
        DeploymentLedgerStoreV2::open_for_test(
            ledger_directory.path(),
            verifier.clone(),
            digest(0xc3),
        )
        .unwrap(),
        DurableDeploymentTransactionStoreV2::open_for_test(head_directory.path(), verifier)
            .unwrap(),
    );
    let acquired = std::sync::Arc::new(std::sync::Barrier::new(2));
    let release = std::sync::Arc::new(std::sync::Barrier::new(2));
    let holder = {
        let store = std::sync::Arc::clone(&first_store);
        let acquired = std::sync::Arc::clone(&acquired);
        let release = std::sync::Arc::clone(&release);
        std::thread::spawn(move || {
            store
                .hold_deployment_mutex_for_test(&acquired, &release)
                .unwrap();
        })
    };
    acquired.wait();

    assert_eq!(
        second_store
            .commit_transition(
                None,
                DeploymentBranchV2::Normal,
                &prepared_head,
                &prepared_record,
                &mut signing_authority,
                &mut rollback_authority,
            )
            .unwrap_err(),
        DeploymentControlErrorV2::DeploymentMutexUnavailable
    );
    assert_eq!(
        fs::read_dir(head_directory.path()).unwrap().count(),
        0,
        "a rejected concurrent commit published a transaction head"
    );

    release.wait();
    holder.join().unwrap();
    let committed = second_store
        .commit_transition(
            None,
            DeploymentBranchV2::Normal,
            &prepared_head,
            &prepared_record,
            &mut signing_authority,
            &mut rollback_authority,
        )
        .unwrap();
    assert_eq!(
        committed.selected_record().signed_record_digest(),
        prepared_record.signed_record_digest()
    );
}

#[test]
fn replacing_the_fixed_deployment_mutex_inode_poisons_the_open_store() {
    let TransitionCrashFixture {
        _ledger_directory: ledger_directory,
        head_directory: _,
        evidence_directory: _,
        store,
        verifier: _,
        genesis: _,
        prepared_head: _,
        prepared_record: _,
        signing_authority: _,
        rollback_authority: _,
    } = transition_crash_fixture();
    let store = std::sync::Arc::new(store);
    let acquired = std::sync::Arc::new(std::sync::Barrier::new(2));
    let release = std::sync::Arc::new(std::sync::Barrier::new(2));
    let holder = {
        let store = std::sync::Arc::clone(&store);
        let acquired = std::sync::Arc::clone(&acquired);
        let release = std::sync::Arc::clone(&release);
        std::thread::spawn(move || store.hold_deployment_mutex_for_test(&acquired, &release))
    };
    acquired.wait();

    let lock = ledger_directory.path().join(".deployment-v2.lock");
    let replaced = ledger_directory.path().join(".deployment-v2.lock.replaced");
    fs::rename(&lock, &replaced).unwrap();
    fs::write(&lock, []).unwrap();
    fs::set_permissions(&lock, fs::Permissions::from_mode(0o600)).unwrap();

    release.wait();
    assert_eq!(
        holder.join().unwrap().unwrap_err(),
        DeploymentControlErrorV2::DeploymentMutexUnavailable
    );
    assert_eq!(
        store
            .hold_deployment_mutex_for_test(
                &std::sync::Barrier::new(1),
                &std::sync::Barrier::new(1),
            )
            .unwrap_err(),
        DeploymentControlErrorV2::DeploymentMutexUnavailable
    );
}

fn published_head_count(directory: &Path) -> usize {
    fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "cbor")
        })
        .count()
}

#[test]
fn bounded_gc_deletes_only_current_generation_orphans_and_retains_selected_ancestry() {
    let mut orphan = transition_crash_fixture();
    assert_eq!(
        orphan
            .store
            .commit_transition_with_crash_for_test(
                None,
                DeploymentBranchV2::Normal,
                &orphan.prepared_head,
                &orphan.prepared_record,
                &mut orphan.signing_authority,
                &mut orphan.rollback_authority,
                TestDeploymentCrashPointV2::HeadReopened,
            )
            .unwrap_err(),
        DeploymentControlErrorV2::DeploymentTransactionIo
    );
    assert_eq!(published_head_count(orphan.head_directory.path()), 1);
    assert_eq!(
        orphan
            .store
            .gc_current_generation_orphan_heads(
                DeploymentBranchV2::Normal,
                &mut orphan.rollback_authority,
            )
            .unwrap(),
        1
    );
    assert_eq!(published_head_count(orphan.head_directory.path()), 0);

    let mut selected = transition_crash_fixture();
    selected
        .store
        .commit_transition(
            None,
            DeploymentBranchV2::Normal,
            &selected.prepared_head,
            &selected.prepared_record,
            &mut selected.signing_authority,
            &mut selected.rollback_authority,
        )
        .unwrap();
    assert_eq!(
        selected
            .store
            .gc_current_generation_orphan_heads(
                DeploymentBranchV2::Normal,
                &mut selected.rollback_authority,
            )
            .unwrap(),
        0
    );
    assert_eq!(published_head_count(selected.head_directory.path()), 1);
}

#[test]
fn gc_retains_an_older_orphan_until_checkpoint_provenance_can_prove_deletion() {
    let mut fixture = transition_crash_fixture();
    fixture
        .store
        .commit_transition_with_crash_for_test(
            None,
            DeploymentBranchV2::Normal,
            &fixture.prepared_head,
            &fixture.prepared_record,
            &mut fixture.signing_authority,
            &mut fixture.rollback_authority,
            TestDeploymentCrashPointV2::HeadReopened,
        )
        .unwrap_err();

    let signing_key = SigningKey::from_bytes(&[0xc1; 32]);
    let transaction_id = transaction(0xd4);
    let owner = DeploymentOwnerClaimV2::new(
        transaction_id,
        DeploymentOwnerRoleV2::Helper,
        digest(0xd5),
        194,
        195,
        digest(0xd6),
        transaction(0xd7),
        1,
        140_000,
    )
    .unwrap();
    let alternative = DurableDeploymentTransactionRecordV2::new_signed_for_test(
        digest(0xc0),
        22,
        transaction_id,
        digest(0xd8),
        1,
        None,
        fixture.genesis.signed_record_digest(),
        1,
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
            0xd9,
        ))],
        owner,
        140_000,
        1_783_000_001_103,
        &signing_key,
    )
    .unwrap();
    let verifier = DeploymentActivationVerifierV2::new(
        digest(0xc0),
        derive_ed25519_key_id_v2(signing_key.verifying_key().to_bytes()),
        22,
        signing_key.verifying_key().to_bytes(),
    )
    .unwrap();
    let alternative_record = DeploymentLedgerRecordV2::new_successor_signed_with_authority(
        &fixture.genesis,
        DeploymentBranchV2::Normal,
        &alternative,
        savana_policy_core::v2::DeploymentActivationUpdateV2::Retain,
        fixture.genesis.highest_ever().clone(),
        1_783_000_001_104,
        &mut fixture.signing_authority,
        &verifier,
    )
    .unwrap();
    fixture
        .store
        .commit_transition(
            None,
            DeploymentBranchV2::Normal,
            &alternative,
            &alternative_record,
            &mut fixture.signing_authority,
            &mut fixture.rollback_authority,
        )
        .unwrap();
    assert_eq!(published_head_count(fixture.head_directory.path()), 2);
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
    assert_eq!(published_head_count(fixture.head_directory.path()), 2);
}

#[test]
fn gc_removes_only_exactly_named_private_temporary_head_files() {
    let mut fixture = transition_crash_fixture();
    let digest_name = hex(fixture.prepared_head.signed_digest().as_bytes());
    let temporary = fixture
        .head_directory
        .path()
        .join(format!(".{digest_name}.cbor.tmp-{}", "ab".repeat(16)));
    fs::write(&temporary, b"partial durable head").unwrap();
    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600)).unwrap();

    assert_eq!(
        fixture
            .store
            .gc_current_generation_orphan_heads(
                DeploymentBranchV2::Normal,
                &mut fixture.rollback_authority,
            )
            .unwrap(),
        1
    );
    assert!(!temporary.exists());
}

#[test]
fn every_unreferenced_head_gc_boundary_preserves_a_valid_selected_state() {
    use TestDeploymentGcCrashPointV2 as Crash;

    for point in Crash::ALL {
        let mut fixture = transition_crash_fixture();
        assert_eq!(
            fixture
                .store
                .commit_transition_with_crash_for_test(
                    None,
                    DeploymentBranchV2::Normal,
                    &fixture.prepared_head,
                    &fixture.prepared_record,
                    &mut fixture.signing_authority,
                    &mut fixture.rollback_authority,
                    TestDeploymentCrashPointV2::HeadReopened,
                )
                .unwrap_err(),
            DeploymentControlErrorV2::DeploymentTransactionIo
        );
        assert_eq!(
            fixture
                .store
                .gc_current_generation_orphan_heads_with_crash_for_test(
                    DeploymentBranchV2::Normal,
                    &mut fixture.rollback_authority,
                    point,
                )
                .unwrap_err(),
            DeploymentControlErrorV2::DeploymentTransactionIo,
            "unexpected GC result at {point:?}"
        );
        assert_eq!(
            published_head_count(fixture.head_directory.path()),
            usize::from(point == Crash::BeforeUnreferencedHeadUnlink),
            "unexpected visible orphan at {point:?}"
        );
        let selected = fixture
            .store
            .load_authenticated(&mut fixture.rollback_authority)
            .unwrap();
        assert_eq!(
            selected.selected_record().signed_record_digest(),
            fixture.genesis.signed_record_digest()
        );
        assert!(fixture
            .store
            .authenticate_selected_chain(&selected, DeploymentBranchV2::Normal)
            .unwrap()
            .is_empty());
    }
}

#[test]
fn gc_rejects_unknown_directory_entries_without_deleting_an_orphan() {
    let mut fixture = transition_crash_fixture();
    fixture
        .store
        .commit_transition_with_crash_for_test(
            None,
            DeploymentBranchV2::Normal,
            &fixture.prepared_head,
            &fixture.prepared_record,
            &mut fixture.signing_authority,
            &mut fixture.rollback_authority,
            TestDeploymentCrashPointV2::HeadReopened,
        )
        .unwrap_err();
    let unknown = fixture.head_directory.path().join("unregistered-entry");
    fs::write(&unknown, b"not a deployment head").unwrap();
    fs::set_permissions(&unknown, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        fixture
            .store
            .gc_current_generation_orphan_heads(
                DeploymentBranchV2::Normal,
                &mut fixture.rollback_authority,
            )
            .unwrap_err(),
        DeploymentControlErrorV2::DeploymentTransactionIo
    );
    assert_eq!(published_head_count(fixture.head_directory.path()), 1);
}

#[test]
fn complete_record_successor_rejects_high_water_regression_and_equivocation() {
    let signing_key = SigningKey::from_bytes(&[0x75; 32]);
    let current = DeploymentLedgerRecordV2::new_signed_for_test(
        digest(51),
        13,
        6,
        digest(52),
        DeploymentPhaseV2::Prepared,
        Some(transaction(53)),
        false,
        8,
        RollbackGrantStateV2::Prearmed,
        Some(digest(54)),
        1_783_000_000_020,
        0x70,
        &signing_key,
    )
    .unwrap();
    let successor = DeploymentLedgerRecordV2::new_signed_for_test(
        digest(51),
        13,
        7,
        current.record_payload_digest(),
        DeploymentPhaseV2::Armed,
        Some(transaction(53)),
        true,
        9,
        RollbackGrantStateV2::Prearmed,
        Some(digest(55)),
        1_783_000_000_021,
        0x70,
        &signing_key,
    )
    .unwrap();
    current
        .validate_successor(&successor, DeploymentBranchV2::Normal)
        .unwrap();

    let regressed = successor
        .with_high_water_entry_for_test(0, 0, digest(0x70), 1, &signing_key)
        .unwrap();
    assert_eq!(
        current
            .validate_successor(&regressed, DeploymentBranchV2::Normal)
            .unwrap_err(),
        DeploymentControlErrorV2::HighestEverMismatch
    );

    let equivocated = successor
        .with_high_water_entry_for_test(0, 1, digest(0x7f), 1, &signing_key)
        .unwrap();
    assert_eq!(
        current
            .validate_successor(&equivocated, DeploymentBranchV2::Normal)
            .unwrap_err(),
        DeploymentControlErrorV2::HighestEverMismatch
    );
}

#[test]
fn standalone_signed_records_reject_impossible_phase_grant_and_fence_shapes() {
    let signing_key = SigningKey::from_bytes(&[0x76; 32]);
    assert_eq!(
        DeploymentLedgerRecordV2::new_signed_for_test(
            digest(61),
            14,
            3,
            digest(62),
            DeploymentPhaseV2::Committed,
            Some(transaction(63)),
            true,
            4,
            RollbackGrantStateV2::Burned,
            Some(digest(64)),
            1_783_000_000_030,
            0x80,
            &signing_key,
        )
        .unwrap_err(),
        DeploymentControlErrorV2::InvalidLedgerRecord
    );
    assert_eq!(
        DeploymentLedgerRecordV2::new_signed_for_test(
            digest(61),
            14,
            3,
            digest(62),
            DeploymentPhaseV2::RollbackPrepared,
            Some(transaction(63)),
            true,
            4,
            RollbackGrantStateV2::Consuming,
            Some(digest(64)),
            1_783_000_000_030,
            0x80,
            &signing_key,
        )
        .unwrap_err(),
        DeploymentControlErrorV2::InvalidLedgerRecord
    );
    assert_eq!(
        DeploymentLedgerRecordV2::new_signed_for_test(
            digest(61),
            14,
            3,
            digest(62),
            DeploymentPhaseV2::RollbackInstalled,
            Some(transaction(63)),
            true,
            4,
            RollbackGrantStateV2::Prearmed,
            Some(digest(64)),
            1_783_000_000_030,
            0x80,
            &signing_key,
        )
        .unwrap_err(),
        DeploymentControlErrorV2::InvalidLedgerRecord
    );
    assert_eq!(
        DeploymentLedgerRecordV2::new_signed_for_test(
            digest(61),
            14,
            3,
            digest(62),
            DeploymentPhaseV2::BootstrapBridge,
            None,
            true,
            4,
            RollbackGrantStateV2::Burned,
            None,
            1_783_000_000_030,
            0x80,
            &signing_key,
        )
        .unwrap_err(),
        DeploymentControlErrorV2::InvalidLedgerRecord
    );
}

#[test]
fn durable_head_is_canonical_signed_prefix_only_and_owner_takeover_bound() {
    let signing_key = SigningKey::from_bytes(&[0x77; 32]);
    let installation_id = digest(71);
    let verifier = DeploymentActivationVerifierV2::new(
        installation_id,
        derive_ed25519_key_id_v2(signing_key.verifying_key().to_bytes()),
        15,
        signing_key.verifying_key().to_bytes(),
    )
    .unwrap();
    let owner = DeploymentOwnerClaimV2::new(
        transaction(72),
        DeploymentOwnerRoleV2::Helper,
        digest(73),
        74,
        75,
        digest(76),
        transaction(77),
        1,
        10_000,
    )
    .unwrap();
    let first = DurableDeploymentTransactionRecordV2::new_signed_for_test(
        installation_id,
        15,
        transaction(72),
        digest(78),
        1,
        None,
        digest(79),
        5,
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
            80,
        ))],
        owner,
        20_000,
        1_783_000_000_040,
        &signing_key,
    )
    .unwrap();
    let reopened = DurableDeploymentTransactionRecordV2::from_canonical_bytes(
        first.canonical_bytes(),
        &verifier,
    )
    .unwrap();
    assert_eq!(reopened.signed_digest(), first.signed_digest());

    let common_through_armed = vec![
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
    ];
    let armed = DurableDeploymentTransactionRecordV2::new_signed_for_test(
        installation_id,
        15,
        transaction(72),
        digest(78),
        2,
        Some(first.signed_digest()),
        digest(81),
        6,
        DeploymentPhaseV2::Armed,
        common_through_armed.clone(),
        vec![
            DurableDeploymentEvidenceRefV2::StoreCompatibility(digest(80)),
            DurableDeploymentEvidenceRefV2::NativeControlMeasurementSet(digest(81)),
            DurableDeploymentEvidenceRefV2::FrozenEffectWorkSet(digest(82)),
        ],
        owner,
        20_000,
        1_783_000_000_041,
        &signing_key,
    )
    .unwrap();
    first
        .validate_successor(&armed, DeploymentBranchV2::Normal)
        .unwrap();

    assert_eq!(
        DurableDeploymentTransactionRecordV2::new_signed_for_test(
            installation_id,
            15,
            transaction(72),
            digest(78),
            2,
            Some(first.signed_digest()),
            digest(81),
            6,
            DeploymentPhaseV2::Armed,
            vec![
                ClosedDurableDeploymentStepV2::TransactionAuthenticated,
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
                DurableDeploymentEvidenceRefV2::StoreCompatibility(digest(80)),
                DurableDeploymentEvidenceRefV2::NativeControlMeasurementSet(digest(81)),
                DurableDeploymentEvidenceRefV2::FrozenEffectWorkSet(digest(82)),
            ],
            owner,
            20_000,
            1_783_000_000_041,
            &signing_key,
        )
        .unwrap_err(),
        DeploymentControlErrorV2::InvalidDurableDeploymentHead
    );

    let observed_helper = DeploymentOwnerIdentityV2::new(digest(73), 74, 75, digest(76)).unwrap();
    let watchdog_identity = DeploymentOwnerIdentityV2::new(digest(83), 84, 85, digest(86)).unwrap();
    let takeover = owner
        .watchdog_takeover(
            &observed_helper,
            watchdog_identity,
            10_000,
            transaction(87),
            30_000,
        )
        .unwrap();
    let mut through_quiesced = common_through_armed;
    through_quiesced.push(ClosedDurableDeploymentStepV2::RoleJournalsReconciled);
    through_quiesced.push(ClosedDurableDeploymentStepV2::ServicesQuiesced);
    let quiesced = DurableDeploymentTransactionRecordV2::new_signed_for_test(
        installation_id,
        15,
        transaction(72),
        digest(78),
        3,
        Some(armed.signed_digest()),
        digest(88),
        7,
        DeploymentPhaseV2::Quiesced,
        through_quiesced,
        vec![
            DurableDeploymentEvidenceRefV2::StoreCompatibility(digest(80)),
            DurableDeploymentEvidenceRefV2::NativeControlMeasurementSet(digest(81)),
            DurableDeploymentEvidenceRefV2::FrozenEffectWorkSet(digest(82)),
            DurableDeploymentEvidenceRefV2::RoleJournalReconciliation(digest(89)),
        ],
        takeover,
        30_000,
        1_783_000_000_042,
        &signing_key,
    )
    .unwrap();
    armed
        .validate_successor(&quiesced, DeploymentBranchV2::Normal)
        .unwrap();

    let mut corrupt = quiesced.canonical_bytes().to_vec();
    let last = corrupt.len() - 1;
    corrupt[last] ^= 1;
    assert_eq!(
        DurableDeploymentTransactionRecordV2::from_canonical_bytes(&corrupt, &verifier)
            .unwrap_err(),
        DeploymentControlErrorV2::InvalidActivationSignature
    );
}

#[test]
fn durable_steps_require_their_exact_flushed_evidence_refs() {
    let signing_key = SigningKey::from_bytes(&[0x88; 32]);
    let installation_id = digest(0x89);
    let owner = DeploymentOwnerClaimV2::new(
        transaction(0x8a),
        DeploymentOwnerRoleV2::Helper,
        digest(0x8b),
        140,
        141,
        digest(0x8c),
        transaction(0x8d),
        1,
        50_000,
    )
    .unwrap();
    let through_armed = vec![
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
    ];

    assert_eq!(
        DurableDeploymentTransactionRecordV2::new_signed_for_test(
            installation_id,
            15,
            transaction(0x8a),
            digest(0x8e),
            2,
            Some(digest(0x93)),
            digest(0x8f),
            4,
            DeploymentPhaseV2::Armed,
            through_armed.clone(),
            vec![DurableDeploymentEvidenceRefV2::StoreCompatibility(digest(
                0x90
            ),)],
            owner,
            50_000,
            1_783_000_000_500,
            &signing_key,
        )
        .unwrap_err(),
        DeploymentControlErrorV2::InvalidDurableDeploymentHead
    );

    DurableDeploymentTransactionRecordV2::new_signed_for_test(
        installation_id,
        15,
        transaction(0x8a),
        digest(0x8e),
        2,
        Some(digest(0x93)),
        digest(0x8f),
        4,
        DeploymentPhaseV2::Armed,
        through_armed,
        vec![
            DurableDeploymentEvidenceRefV2::StoreCompatibility(digest(0x90)),
            DurableDeploymentEvidenceRefV2::NativeControlMeasurementSet(digest(0x91)),
            DurableDeploymentEvidenceRefV2::FrozenEffectWorkSet(digest(0x92)),
        ],
        owner,
        50_000,
        1_783_000_000_500,
        &signing_key,
    )
    .unwrap();
}

#[test]
fn durable_head_steps_are_an_exact_phase_prefix_and_first_head_is_prepared() {
    let signing_key = SigningKey::from_bytes(&[0x93; 32]);
    let installation_id = digest(0x94);
    let owner = DeploymentOwnerClaimV2::new(
        transaction(0x95),
        DeploymentOwnerRoleV2::Helper,
        digest(0x96),
        151,
        152,
        digest(0x97),
        transaction(0x98),
        1,
        60_000,
    )
    .unwrap();
    let through_armed = vec![
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
    ];
    let armed_evidence = vec![
        DurableDeploymentEvidenceRefV2::StoreCompatibility(digest(0x99)),
        DurableDeploymentEvidenceRefV2::NativeControlMeasurementSet(digest(0x9a)),
        DurableDeploymentEvidenceRefV2::FrozenEffectWorkSet(digest(0x9b)),
    ];
    assert_eq!(
        DurableDeploymentTransactionRecordV2::new_signed_for_test(
            installation_id,
            16,
            transaction(0x95),
            digest(0x9c),
            1,
            None,
            digest(0x9d),
            7,
            DeploymentPhaseV2::Armed,
            through_armed,
            armed_evidence,
            owner,
            60_000,
            1_783_000_000_600,
            &signing_key,
        )
        .unwrap_err(),
        DeploymentControlErrorV2::InvalidDurableDeploymentHead
    );

    let skipped_effect_freeze = vec![
        ClosedDurableDeploymentStepV2::TransactionAuthenticated,
        ClosedDurableDeploymentStepV2::StagingTreeVerified,
        ClosedDurableDeploymentStepV2::DesiredManifestVerified,
        ClosedDurableDeploymentStepV2::RecoveryTargetVerified,
        ClosedDurableDeploymentStepV2::PlansVerified,
        ClosedDurableDeploymentStepV2::StoreCompatibilityVerified,
        ClosedDurableDeploymentStepV2::GrantPrearmed,
        ClosedDurableDeploymentStepV2::ExclusiveEffectGateAcquired,
        ClosedDurableDeploymentStepV2::OsEffectDenyInstalled,
        ClosedDurableDeploymentStepV2::ArmedTransitionReady,
    ];
    assert_eq!(
        DurableDeploymentTransactionRecordV2::new_signed_for_test(
            installation_id,
            16,
            transaction(0x95),
            digest(0x9c),
            2,
            Some(digest(0x9e)),
            digest(0x9d),
            8,
            DeploymentPhaseV2::Armed,
            skipped_effect_freeze,
            vec![
                DurableDeploymentEvidenceRefV2::StoreCompatibility(digest(0x99)),
                DurableDeploymentEvidenceRefV2::NativeControlMeasurementSet(digest(0x9a)),
            ],
            owner,
            60_000,
            1_783_000_000_601,
            &signing_key,
        )
        .unwrap_err(),
        DeploymentControlErrorV2::InvalidDurableDeploymentHead
    );

    DurableDeploymentTransactionRecordV2::new_signed_for_test(
        installation_id,
        16,
        transaction(0x95),
        digest(0x9c),
        1,
        None,
        digest(0x9d),
        7,
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
            0x99,
        ))],
        owner,
        60_000,
        1_783_000_000_600,
        &signing_key,
    )
    .unwrap();
}

#[test]
fn failed_safe_head_requires_exactly_one_durable_failure_evidence_ref() {
    let signing_key = SigningKey::from_bytes(&[0xa1; 32]);
    let installation_id = digest(0xa2);
    let owner = DeploymentOwnerClaimV2::new(
        transaction(0xa3),
        DeploymentOwnerRoleV2::Helper,
        digest(0xa4),
        161,
        162,
        digest(0xa5),
        transaction(0xa6),
        1,
        70_000,
    )
    .unwrap();

    assert_eq!(
        DurableDeploymentTransactionRecordV2::new_signed_for_test(
            installation_id,
            17,
            transaction(0xa3),
            digest(0xa7),
            2,
            Some(digest(0xa8)),
            digest(0xa9),
            9,
            DeploymentPhaseV2::FailedSafe,
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
                0xaa,
            ))],
            owner,
            70_000,
            1_783_000_000_700,
            &signing_key,
        )
        .unwrap_err(),
        DeploymentControlErrorV2::InvalidDurableDeploymentHead
    );

    let failed_safe = DurableDeploymentTransactionRecordV2::new_signed_for_test(
        installation_id,
        17,
        transaction(0xa3),
        digest(0xa7),
        2,
        Some(digest(0xa8)),
        digest(0xa9),
        9,
        DeploymentPhaseV2::FailedSafe,
        vec![
            ClosedDurableDeploymentStepV2::TransactionAuthenticated,
            ClosedDurableDeploymentStepV2::StagingTreeVerified,
            ClosedDurableDeploymentStepV2::DesiredManifestVerified,
            ClosedDurableDeploymentStepV2::RecoveryTargetVerified,
            ClosedDurableDeploymentStepV2::PlansVerified,
            ClosedDurableDeploymentStepV2::StoreCompatibilityVerified,
            ClosedDurableDeploymentStepV2::GrantPrearmed,
        ],
        vec![
            DurableDeploymentEvidenceRefV2::StoreCompatibility(digest(0xaa)),
            DurableDeploymentEvidenceRefV2::DeploymentFailure(digest(0xab)),
        ],
        owner,
        70_000,
        1_783_000_000_700,
        &signing_key,
    )
    .unwrap();
    assert_eq!(failed_safe.target_phase(), DeploymentPhaseV2::FailedSafe);
}

#[test]
fn durable_head_store_is_content_addressed_immutable_and_reauthenticated() {
    let signing_key = SigningKey::from_bytes(&[0x91; 32]);
    let installation_id = digest(92);
    let verifier = DeploymentActivationVerifierV2::new(
        installation_id,
        derive_ed25519_key_id_v2(signing_key.verifying_key().to_bytes()),
        16,
        signing_key.verifying_key().to_bytes(),
    )
    .unwrap();
    let owner = DeploymentOwnerClaimV2::new(
        transaction(93),
        DeploymentOwnerRoleV2::Helper,
        digest(94),
        95,
        96,
        digest(97),
        transaction(98),
        1,
        30_000,
    )
    .unwrap();
    let predecessor_ledger = DeploymentLedgerRecordV2::new_signed_for_test(
        installation_id,
        16,
        8,
        digest(100),
        DeploymentPhaseV2::Idle,
        None,
        false,
        7,
        RollbackGrantStateV2::None,
        None,
        1_783_000_000_049,
        0xa0,
        &signing_key,
    )
    .unwrap();
    let head = DurableDeploymentTransactionRecordV2::new_signed_for_test(
        installation_id,
        16,
        transaction(93),
        digest(99),
        1,
        None,
        predecessor_ledger.signed_record_digest(),
        8,
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
            102,
        ))],
        owner,
        40_000,
        1_783_000_000_050,
        &signing_key,
    )
    .unwrap();
    head.validate_expected_previous_ledger(&predecessor_ledger)
        .unwrap();
    let wrong_predecessor = DeploymentLedgerRecordV2::new_signed_for_test(
        installation_id,
        16,
        8,
        digest(100),
        DeploymentPhaseV2::Idle,
        None,
        false,
        7,
        RollbackGrantStateV2::None,
        None,
        1_783_000_000_049,
        0xa1,
        &signing_key,
    )
    .unwrap();
    assert_eq!(
        head.validate_expected_previous_ledger(&wrong_predecessor)
            .unwrap_err(),
        DeploymentControlErrorV2::TransactionBindingMismatch
    );

    let ledger_directory = tempfile::tempdir().unwrap();
    fs::set_permissions(ledger_directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let current_ledger = DeploymentLedgerRecordV2::new_signed_for_test(
        installation_id,
        16,
        9,
        predecessor_ledger.record_payload_digest(),
        DeploymentPhaseV2::Prepared,
        Some(transaction(93)),
        false,
        7,
        RollbackGrantStateV2::Prearmed,
        Some(head.signed_digest()),
        1_783_000_000_051,
        0xa0,
        &signing_key,
    )
    .unwrap();
    predecessor_ledger
        .validate_successor(&current_ledger, DeploymentBranchV2::Normal)
        .unwrap();
    let current_slot =
        SignedLedgerSlotV2::new_signed_for_test(LedgerSlotIdV2::A, &current_ledger, &signing_key)
            .unwrap();
    let predecessor_slot = SignedLedgerSlotV2::new_signed_for_test(
        LedgerSlotIdV2::B,
        &predecessor_ledger,
        &signing_key,
    )
    .unwrap();
    for (leaf, bytes) in [
        ("ledger-a.cbor", current_slot.canonical_bytes()),
        ("ledger-b.cbor", predecessor_slot.canonical_bytes()),
    ] {
        let path = ledger_directory.path().join(leaf);
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let ledger_store = DeploymentLedgerStoreV2::open_for_test(
        ledger_directory.path(),
        verifier.clone(),
        digest(102),
    )
    .unwrap();
    let mut authority =
        TestNativeRollbackAuthorityV2::new_for_test([102; 32], [92; 32], 16, 9).unwrap();
    let ledger_snapshot = ledger_store
        .load_selected_authenticated(&mut authority)
        .unwrap();

    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let store =
        DurableDeploymentTransactionStoreV2::open_for_test(directory.path(), verifier).unwrap();
    assert_eq!(store.append_head(&head).unwrap(), head.signed_digest());
    assert_eq!(
        store
            .load_selected_chain(&ledger_snapshot, 8, DeploymentBranchV2::Normal)
            .unwrap()
            .last()
            .unwrap()
            .signed_digest(),
        head.signed_digest()
    );
    assert_eq!(
        store
            .load_head(head.signed_digest())
            .unwrap()
            .signed_digest(),
        head.signed_digest()
    );
    assert_eq!(store.append_head(&head).unwrap(), head.signed_digest());
    let armed = DurableDeploymentTransactionRecordV2::new_signed_for_test(
        installation_id,
        16,
        transaction(93),
        digest(99),
        2,
        Some(head.signed_digest()),
        digest(101),
        9,
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
            DurableDeploymentEvidenceRefV2::StoreCompatibility(digest(102)),
            DurableDeploymentEvidenceRefV2::NativeControlMeasurementSet(digest(103)),
            DurableDeploymentEvidenceRefV2::FrozenEffectWorkSet(digest(104)),
        ],
        owner,
        40_000,
        1_783_000_000_051,
        &signing_key,
    )
    .unwrap();
    store.append_head(&armed).unwrap();
    let chain = store
        .load_chain(armed.signed_digest(), 8, DeploymentBranchV2::Normal)
        .unwrap();
    assert_eq!(
        chain
            .iter()
            .map(DurableDeploymentTransactionRecordV2::signed_digest)
            .collect::<Vec<_>>(),
        vec![head.signed_digest(), armed.signed_digest()]
    );

    let leaf = format!("{}.cbor", hex(head.signed_digest().as_bytes()));
    let path = directory.path().join(leaf);
    fs::write(&path, b"tampered").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        store.load_head(head.signed_digest()).unwrap_err(),
        DeploymentControlErrorV2::DeploymentTransactionIo
    );
    assert_eq!(
        store.append_head(&head).unwrap_err(),
        DeploymentControlErrorV2::DeploymentTransactionIo
    );
    assert_eq!(
        store
            .load_chain(armed.signed_digest(), 8, DeploymentBranchV2::Normal)
            .unwrap_err(),
        DeploymentControlErrorV2::DeploymentTransactionIo
    );
    assert_eq!(fs::read(path).unwrap(), b"tampered");
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        value.push(char::from(DIGITS[usize::from(byte >> 4)]));
        value.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    value
}
