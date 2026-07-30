use ed25519_dalek::{Signature, SigningKey, Verifier as _, VerifyingKey};
use savana_kernel_protocol::v2::{derive_ed25519_key_id_v2, Digest32V2, Ed25519KeyIdV2, Nonce32V2};
use savana_policy_core::v2::{
    AuthenticatedNativeDeploymentLedgerV2, ClosedDurableDeploymentStepV2,
    DeploymentActivationUpdateV2, DeploymentActivationVerifierV2, DeploymentBranchV2,
    DeploymentControlErrorV2, DeploymentLedgerRecordV2, DeploymentOwnerClaimV2,
    DeploymentOwnerRoleV2, DeploymentPhaseV2, DurableDeploymentEvidenceRefV2,
    DurableDeploymentTransactionRecordV2, LedgerSlotIdV2, NativeDeploymentAuthorityHandlesV2,
    NativeDeploymentSignatureDomainV2, NativeDeploymentSignatureRequestV2,
    NativeDeploymentSigningAuthorityV2, RollbackGrantStateV2, SignedLedgerSlotV2,
    TestNativeDeploymentSigningAuthorityV2, TestNativeRollbackAuthorityV2,
};
use sha2::{Digest as _, Sha256};
use std::os::unix::fs::PermissionsExt as _;

fn digest(byte: u8) -> Digest32V2 {
    Digest32V2::new([byte; 32])
}

fn nonce(byte: u8) -> Nonce32V2 {
    Nonce32V2::new([byte; 32])
}

fn signature_input(tag: u16, domain: &[u8], payload_digest: [u8; 32]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"savana.domain-signature.v2\0");
    hash.update(tag.to_be_bytes());
    hash.update(domain);
    hash.update(payload_digest);
    hash.finalize().into()
}

#[test]
fn native_signing_authority_is_domain_installation_and_epoch_bound() {
    let mut authority =
        TestNativeDeploymentSigningAuthorityV2::new_for_test([0x11; 32], [0x12; 32], 7, [0x13; 32])
            .unwrap();
    let request = NativeDeploymentSignatureRequestV2::new(
        NativeDeploymentSignatureDomainV2::DurableDeploymentTransactionRecord,
        [0x12; 32],
        7,
        [0x14; 32],
    )
    .unwrap();
    let signature = authority.sign(request).unwrap();
    let key = VerifyingKey::from_bytes(&authority.public_key()).unwrap();
    key.verify(
        &signature_input(
            26,
            b"savana.durable-deployment-record.v2.signature\0",
            [0x14; 32],
        ),
        &Signature::from_bytes(&signature),
    )
    .unwrap();
    assert!(key
        .verify(
            &signature_input(5, b"savana.deployment-ledger.v2.activation\0", [0x14; 32],),
            &Signature::from_bytes(&signature),
        )
        .is_err());

    let wrong_installation = NativeDeploymentSignatureRequestV2::new(
        NativeDeploymentSignatureDomainV2::DurableDeploymentTransactionRecord,
        [0x15; 32],
        7,
        [0x14; 32],
    )
    .unwrap();
    assert!(authority.sign(wrong_installation).is_err());
    let wrong_epoch = NativeDeploymentSignatureRequestV2::new(
        NativeDeploymentSignatureDomainV2::DurableDeploymentTransactionRecord,
        [0x12; 32],
        8,
        [0x14; 32],
    )
    .unwrap();
    assert!(authority.sign(wrong_epoch).is_err());
}

#[test]
fn durable_head_is_constructed_without_exporting_activation_private_key() {
    let installation_id = digest(0x21);
    let mut authority = TestNativeDeploymentSigningAuthorityV2::new_for_test(
        [0x22; 32],
        *installation_id.as_bytes(),
        9,
        [0x23; 32],
    )
    .unwrap();
    let verifier = DeploymentActivationVerifierV2::new(
        installation_id,
        Ed25519KeyIdV2::new(authority.key_id()),
        authority.key_epoch(),
        authority.public_key(),
    )
    .unwrap();
    let owner = DeploymentOwnerClaimV2::new(
        nonce(0x24),
        DeploymentOwnerRoleV2::Helper,
        digest(0x25),
        26,
        27,
        digest(0x28),
        nonce(0x29),
        1,
        30_000,
    )
    .unwrap();
    let head = DurableDeploymentTransactionRecordV2::new_signed_with_authority(
        installation_id,
        9,
        nonce(0x24),
        digest(0x2a),
        1,
        None,
        digest(0x2b),
        4,
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
            0x2c,
        ))],
        owner,
        30_000,
        1_783_000_000_000,
        &mut authority,
        &verifier,
    )
    .unwrap();
    assert_eq!(head.installation_id(), installation_id);
    assert_eq!(head.head_sequence(), 1);
    DurableDeploymentTransactionRecordV2::from_canonical_bytes(head.canonical_bytes(), &verifier)
        .unwrap();

    let wrong_key = SigningKey::from_bytes(&[0x31; 32]);
    let wrong_public_key = wrong_key.verifying_key().to_bytes();
    let wrong_verifier = DeploymentActivationVerifierV2::new(
        installation_id,
        derive_ed25519_key_id_v2(wrong_public_key),
        9,
        wrong_public_key,
    )
    .unwrap();
    assert_eq!(
        DurableDeploymentTransactionRecordV2::new_signed_with_authority(
            installation_id,
            9,
            nonce(0x24),
            digest(0x2a),
            1,
            None,
            digest(0x2b),
            4,
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
                0x2c
            )),],
            owner,
            30_000,
            1_783_000_000_000,
            &mut authority,
            &wrong_verifier,
        )
        .unwrap_err(),
        DeploymentControlErrorV2::ActivationKeyMismatch
    );
}

#[test]
fn ledger_slot_is_constructed_through_the_same_closed_native_authority() {
    let installation_id = digest(0x41);
    let seed = [0x42; 32];
    let signing_key = SigningKey::from_bytes(&seed);
    let mut authority = TestNativeDeploymentSigningAuthorityV2::new_for_test(
        [0x43; 32],
        *installation_id.as_bytes(),
        11,
        seed,
    )
    .unwrap();
    let verifier = DeploymentActivationVerifierV2::new(
        installation_id,
        Ed25519KeyIdV2::new(authority.key_id()),
        11,
        authority.public_key(),
    )
    .unwrap();
    let record = DeploymentLedgerRecordV2::new_signed_for_test(
        installation_id,
        11,
        3,
        digest(0x44),
        DeploymentPhaseV2::Idle,
        None,
        false,
        2,
        RollbackGrantStateV2::None,
        None,
        1_783_000_000_100,
        0x45,
        &signing_key,
    )
    .unwrap();
    let slot = SignedLedgerSlotV2::new_signed_with_authority(
        LedgerSlotIdV2::B,
        &record,
        &mut authority,
        &verifier,
    )
    .unwrap();
    let verified =
        SignedLedgerSlotV2::verify_canonical_bytes(slot.canonical_bytes(), &verifier).unwrap();
    assert_eq!(verified.slot_id(), LedgerSlotIdV2::B);
    assert_eq!(verified.record(), record.projection());
}

#[test]
fn ledger_successor_is_derived_from_the_authenticated_head_and_signed_natively() {
    let installation_id = digest(0x51);
    let seed = [0x52; 32];
    let signing_key = SigningKey::from_bytes(&seed);
    let mut authority = TestNativeDeploymentSigningAuthorityV2::new_for_test(
        [0x53; 32],
        *installation_id.as_bytes(),
        13,
        seed,
    )
    .unwrap();
    let verifier = DeploymentActivationVerifierV2::new(
        installation_id,
        Ed25519KeyIdV2::new(authority.key_id()),
        13,
        authority.public_key(),
    )
    .unwrap();
    let transaction_id = nonce(0x54);
    let owner = DeploymentOwnerClaimV2::new(
        transaction_id,
        DeploymentOwnerRoleV2::Helper,
        digest(0x55),
        56,
        57,
        digest(0x58),
        nonce(0x59),
        1,
        90_000,
    )
    .unwrap();
    let prepared_head = DurableDeploymentTransactionRecordV2::new_signed_for_test(
        installation_id,
        13,
        transaction_id,
        digest(0x5a),
        1,
        None,
        digest(0x5b),
        6,
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
            0x5c,
        ))],
        owner,
        90_000,
        1_783_000_000_200,
        &signing_key,
    )
    .unwrap();
    let current = DeploymentLedgerRecordV2::new_signed_for_test(
        installation_id,
        13,
        7,
        digest(0x5b),
        DeploymentPhaseV2::Prepared,
        Some(transaction_id),
        false,
        3,
        RollbackGrantStateV2::Prearmed,
        Some(prepared_head.signed_digest()),
        1_783_000_000_201,
        0x60,
        &signing_key,
    )
    .unwrap();
    let armed_head = DurableDeploymentTransactionRecordV2::new_signed_for_test(
        installation_id,
        13,
        transaction_id,
        digest(0x5a),
        2,
        Some(prepared_head.signed_digest()),
        current.signed_record_digest(),
        7,
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
            DurableDeploymentEvidenceRefV2::StoreCompatibility(digest(0x5c)),
            DurableDeploymentEvidenceRefV2::NativeControlMeasurementSet(digest(0x5d)),
            DurableDeploymentEvidenceRefV2::FrozenEffectWorkSet(digest(0x5e)),
        ],
        owner,
        90_000,
        1_783_000_000_202,
        &signing_key,
    )
    .unwrap();

    let successor = DeploymentLedgerRecordV2::new_successor_signed_with_authority(
        &current,
        DeploymentBranchV2::Normal,
        &armed_head,
        DeploymentActivationUpdateV2::Retain,
        current.highest_ever().clone(),
        1_783_000_000_203,
        &mut authority,
        &verifier,
    )
    .unwrap();

    assert_eq!(successor.projection().phase(), DeploymentPhaseV2::Armed);
    assert!(successor.projection().effects_fenced());
    assert_eq!(successor.projection().effect_fence_epoch(), 4);
    assert_eq!(
        successor.projection().transaction_head_digest(),
        Some(armed_head.signed_digest())
    );
    current
        .validate_successor(&successor, DeploymentBranchV2::Normal)
        .unwrap();
}

#[test]
fn native_authority_bundle_bootstraps_and_authenticates_the_fixed_ledger_shape() {
    let installation_id = digest(0x71);
    let installation_epoch = 17;
    let generation = 5;
    let seed = [0x72; 32];
    let signing_key = SigningKey::from_bytes(&seed);
    let record = DeploymentLedgerRecordV2::new_signed_for_test(
        installation_id,
        installation_epoch,
        generation,
        digest(0x73),
        DeploymentPhaseV2::Idle,
        None,
        false,
        4,
        RollbackGrantStateV2::None,
        None,
        1_783_000_000_300,
        0x74,
        &signing_key,
    )
    .unwrap();
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    for (leaf, slot_id) in [
        ("ledger-a.cbor", LedgerSlotIdV2::A),
        ("ledger-b.cbor", LedgerSlotIdV2::B),
    ] {
        let slot = SignedLedgerSlotV2::new_signed_for_test(slot_id, &record, &signing_key).unwrap();
        let path = directory.path().join(leaf);
        std::fs::write(&path, slot.canonical_bytes()).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let rollback_identity = [0x75; 32];
    let mut handles = NativeDeploymentAuthorityHandlesV2::new_for_test(
        TestNativeDeploymentSigningAuthorityV2::new_for_test(
            [0x76; 32],
            *installation_id.as_bytes(),
            installation_epoch,
            seed,
        )
        .unwrap(),
        TestNativeRollbackAuthorityV2::new_for_test(
            rollback_identity,
            *installation_id.as_bytes(),
            installation_epoch,
            generation,
        )
        .unwrap(),
    )
    .unwrap();

    let bootstrap =
        AuthenticatedNativeDeploymentLedgerV2::open_for_test(directory.path(), &mut handles)
            .unwrap();
    assert_eq!(
        bootstrap
            .snapshot()
            .selected_record()
            .signed_record_digest(),
        record.signed_record_digest()
    );
    assert_eq!(
        bootstrap.activation_verifier().installation_id(),
        installation_id
    );
    assert_eq!(
        bootstrap.rollback_authority_identity(),
        Digest32V2::new(rollback_identity)
    );

    let mut stale_handles = NativeDeploymentAuthorityHandlesV2::new_for_test(
        TestNativeDeploymentSigningAuthorityV2::new_for_test(
            [0x76; 32],
            *installation_id.as_bytes(),
            installation_epoch,
            seed,
        )
        .unwrap(),
        TestNativeRollbackAuthorityV2::new_for_test(
            rollback_identity,
            *installation_id.as_bytes(),
            installation_epoch,
            generation - 1,
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        AuthenticatedNativeDeploymentLedgerV2::open_for_test(directory.path(), &mut stale_handles,)
            .unwrap_err(),
        DeploymentControlErrorV2::NativeRollbackGenerationMismatch
    );
}
