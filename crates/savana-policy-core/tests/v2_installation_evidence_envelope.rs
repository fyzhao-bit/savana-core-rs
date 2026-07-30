use savana_kernel_protocol::v2::{Digest32V2, Nonce32V2};
use savana_policy_core::v2::{
    ArtifactIdentityV2, ClosedArtifactTypeV2, ClosedCommitDigestFieldV2,
    ClosedDeploymentFailureClassV2, ClosedInstallationEvidenceKindV2,
    ClosedRecoveryRollbackDigestFieldV2, ClosedRollbackAttestationDigestFieldV2,
    ClosedRollbackVerificationDigestFieldV2, ClosedTargetArchitectureV2, ClosedTargetOsV2,
    ClosedVerificationDigestFieldV2, CommitAttestationV2, CompactedTransactionProvenanceV2,
    DeploymentActivationVerifierV2, DeploymentBranchV2, DeploymentControlErrorV2,
    DeploymentFailureEvidenceV2, DeploymentPhaseV2, EvidenceGcCheckpointV2, EvidenceGcWindowV2,
    InstallationEvidenceEnvelopeV2, NativeDeploymentSigningAuthorityV2, PlatformLockV2,
    RecoveryRollbackOriginMeasurementsV2, RecoveryRollbackReadinessEvidenceV2,
    RecoveryValidationResultV2, RollbackOriginPhaseV2, RollbackTerminalReadinessRefV2,
    RollbackVerificationAttestationV2, RollbackVerificationEvidenceV2,
    StoreCompatibilityAttestationV2, TestNativeDeploymentSigningAuthorityV2, TransitionAuditV2,
    VerificationEvidenceV2,
};

fn digest(byte: u8) -> Digest32V2 {
    Digest32V2::new([byte; 32])
}

fn nonce(byte: u8) -> Nonce32V2 {
    Nonce32V2::new([byte; 32])
}

fn fixture() -> (
    TestNativeDeploymentSigningAuthorityV2,
    DeploymentActivationVerifierV2,
    EvidenceGcCheckpointV2,
) {
    let installation_id = [0x31; 32];
    let installation_epoch = 17;
    let mut authority = TestNativeDeploymentSigningAuthorityV2::new_for_test(
        [0x41; 32],
        installation_id,
        installation_epoch,
        [0x42; 32],
    )
    .unwrap();
    let verifier = DeploymentActivationVerifierV2::new(
        digest(0x31),
        savana_kernel_protocol::v2::Ed25519KeyIdV2::new(authority.key_id()),
        installation_epoch,
        authority.public_key(),
    )
    .unwrap();
    let checkpoint = EvidenceGcCheckpointV2::new_signed_with_authority(
        digest(0x31),
        installation_epoch,
        EvidenceGcWindowV2::new(
            digest(0x51),
            digest(0x52),
            digest(0x53),
            3,
            digest(0x54),
            1_784_000_000_000,
        )
        .unwrap(),
        CompactedTransactionProvenanceV2::None,
        &mut authority,
        &verifier,
    )
    .unwrap();
    (authority, verifier, checkpoint)
}

#[test]
fn checkpoint_envelope_is_an_exact_activation_signed_hash_chain_item() {
    let (mut authority, verifier, checkpoint) = fixture();
    let first = InstallationEvidenceEnvelopeV2::new_gc_checkpoint_signed_with_authority(
        1,
        None,
        &checkpoint,
        &mut authority,
        &verifier,
    )
    .unwrap();
    assert_eq!(first.evidence_sequence(), 1);
    assert_eq!(first.previous_evidence_signed_digest(), None);
    assert_eq!(
        first.evidence_kind(),
        ClosedInstallationEvidenceKindV2::EvidenceGcCheckpoint
    );
    assert_eq!(first.evidence_bytes(), checkpoint.canonical_bytes());
    assert_ne!(first.evidence_digest(), first.payload_digest());
    assert_ne!(first.payload_digest(), first.signed_digest());

    let reopened =
        InstallationEvidenceEnvelopeV2::from_canonical_bytes(first.canonical_bytes(), &verifier)
            .unwrap();
    assert_eq!(reopened, first);

    let second = InstallationEvidenceEnvelopeV2::new_gc_checkpoint_signed_with_authority(
        2,
        Some(first.signed_digest()),
        &checkpoint,
        &mut authority,
        &verifier,
    )
    .unwrap();
    assert_eq!(
        second.previous_evidence_signed_digest(),
        Some(first.signed_digest())
    );
}

#[test]
fn transition_audit_envelope_binds_one_exact_candidate_transition() {
    let (mut authority, verifier, _) = fixture();
    let audit = TransitionAuditV2::new(
        digest(0x31),
        17,
        nonce(0x61),
        digest(0x62),
        DeploymentBranchV2::Normal,
        DeploymentPhaseV2::Idle,
        DeploymentPhaseV2::Prepared,
        digest(0x63),
        1,
        None,
        digest(0x64),
        1,
        digest(0x65),
        2,
        false,
        1,
        1_784_000_000_050,
    )
    .unwrap();
    let envelope = InstallationEvidenceEnvelopeV2::new_transition_audit_signed_with_authority(
        1,
        None,
        &audit,
        &mut authority,
        &verifier,
    )
    .unwrap();
    assert_eq!(
        envelope.evidence_kind(),
        ClosedInstallationEvidenceKindV2::TransitionAudit
    );
    assert_eq!(envelope.transition_audit().unwrap(), audit);
    assert_eq!(
        InstallationEvidenceEnvelopeV2::from_canonical_bytes(envelope.canonical_bytes(), &verifier)
            .unwrap(),
        envelope
    );
    assert_eq!(
        TransitionAuditV2::new(
            digest(0x31),
            17,
            nonce(0x61),
            digest(0x62),
            DeploymentBranchV2::Normal,
            DeploymentPhaseV2::Idle,
            DeploymentPhaseV2::Prepared,
            digest(0x63),
            1,
            None,
            digest(0x64),
            1,
            digest(0x65),
            3,
            false,
            1,
            1_784_000_000_050,
        )
        .unwrap_err(),
        DeploymentControlErrorV2::InvalidTransitionAudit
    );
}

#[test]
fn envelope_rejects_sequence_chain_mutation_noncanonical_cbor_and_signature_substitution() {
    let (mut authority, verifier, checkpoint) = fixture();
    assert_eq!(
        InstallationEvidenceEnvelopeV2::new_gc_checkpoint_signed_with_authority(
            1,
            Some(digest(0x99)),
            &checkpoint,
            &mut authority,
            &verifier,
        )
        .unwrap_err(),
        DeploymentControlErrorV2::InvalidInstallationEvidenceEnvelope
    );
    assert_eq!(
        InstallationEvidenceEnvelopeV2::new_gc_checkpoint_signed_with_authority(
            2,
            None,
            &checkpoint,
            &mut authority,
            &verifier,
        )
        .unwrap_err(),
        DeploymentControlErrorV2::InvalidInstallationEvidenceEnvelope
    );

    let envelope = InstallationEvidenceEnvelopeV2::new_gc_checkpoint_signed_with_authority(
        1,
        None,
        &checkpoint,
        &mut authority,
        &verifier,
    )
    .unwrap();
    let mut mutated = envelope.canonical_bytes().to_vec();
    let evidence_byte = mutated
        .windows(checkpoint.canonical_bytes().len())
        .position(|window| window == checkpoint.canonical_bytes())
        .unwrap();
    mutated[evidence_byte + checkpoint.canonical_bytes().len() / 2] ^= 1;
    assert!(InstallationEvidenceEnvelopeV2::from_canonical_bytes(&mutated, &verifier).is_err());

    let mut trailing = envelope.canonical_bytes().to_vec();
    trailing.push(0);
    assert_eq!(
        InstallationEvidenceEnvelopeV2::from_canonical_bytes(&trailing, &verifier).unwrap_err(),
        DeploymentControlErrorV2::InvalidInstallationEvidenceEnvelope
    );
}

#[test]
fn failed_safe_evidence_is_closed_fenced_and_enveloped_before_reference() {
    let (mut authority, verifier, _) = fixture();
    let failure = DeploymentFailureEvidenceV2::new(
        digest(0x31),
        17,
        nonce(0x71),
        digest(0x72),
        digest(0x73),
        DeploymentPhaseV2::Prepared,
        DeploymentPhaseV2::Armed,
        ClosedDeploymentFailureClassV2::NativeEffectFenceFailure,
        digest(0x74),
        digest(0x75),
        1_784_000_000_100,
    )
    .unwrap();
    let envelope = InstallationEvidenceEnvelopeV2::new_deployment_failure_signed_with_authority(
        1,
        None,
        &failure,
        &mut authority,
        &verifier,
    )
    .unwrap();
    assert_eq!(
        envelope.evidence_kind(),
        ClosedInstallationEvidenceKindV2::DeploymentFailure
    );
    assert_eq!(envelope.deployment_failure_evidence().unwrap(), failure);
    assert_eq!(
        InstallationEvidenceEnvelopeV2::from_canonical_bytes(envelope.canonical_bytes(), &verifier)
            .unwrap(),
        envelope
    );

    assert_eq!(
        DeploymentFailureEvidenceV2::new(
            digest(0x31),
            17,
            nonce(0x71),
            digest(0x72),
            digest(0x73),
            DeploymentPhaseV2::Prepared,
            DeploymentPhaseV2::FailedSafe,
            ClosedDeploymentFailureClassV2::NativeEffectFenceFailure,
            digest(0x74),
            digest(0x75),
            1_784_000_000_100,
        )
        .unwrap_err(),
        DeploymentControlErrorV2::InvalidDeploymentFailureEvidence
    );
}

#[test]
fn store_compatibility_attestation_is_typed_signed_and_enveloped() {
    let (mut authority, verifier, _) = fixture();
    let attestation = StoreCompatibilityAttestationV2::new_signed_with_authority(
        digest(0x81),
        digest(0x31),
        9,
        digest(0x82),
        digest(0x83),
        digest(0x84),
        digest(0x85),
        digest(0x86),
        RecoveryValidationResultV2::NormalRollbackManifest {
            rollback_copy_validation_result_digest: digest(0x87),
        },
        digest(0x88),
        digest(0x89),
        1_784_000_000_200,
        &mut authority,
        &verifier,
    )
    .unwrap();
    assert_eq!(attestation.installation_epoch(), 17);
    assert_eq!(
        StoreCompatibilityAttestationV2::from_canonical_bytes(
            attestation.canonical_bytes(),
            &verifier
        )
        .unwrap(),
        attestation
    );
    let envelope = InstallationEvidenceEnvelopeV2::new_store_compatibility_signed_with_authority(
        1,
        None,
        &attestation,
        &mut authority,
        &verifier,
    )
    .unwrap();
    assert_eq!(
        envelope.evidence_kind(),
        ClosedInstallationEvidenceKindV2::StoreCompatibility
    );
    assert_eq!(
        envelope.store_compatibility_attestation(&verifier).unwrap(),
        attestation
    );

    assert_eq!(
        StoreCompatibilityAttestationV2::new_signed_with_authority(
            digest(0x81),
            digest(0x31),
            9,
            digest(0x82),
            digest(0x83),
            digest(0x84),
            digest(0x85),
            digest(0x86),
            RecoveryValidationResultV2::BootstrapBridgeRestore {
                unchanged_store_and_journal_integrity_result_digest: digest(0x87),
                native_effect_fence_measurement_digest: Digest32V2::new([0; 32]),
            },
            digest(0x88),
            digest(0x89),
            1_784_000_000_200,
            &mut authority,
            &verifier,
        )
        .unwrap_err(),
        DeploymentControlErrorV2::InvalidStoreCompatibilityAttestation
    );
}

#[test]
fn verification_evidence_is_closed_activation_signed_and_enveloped() {
    let (mut authority, verifier, _) = fixture();
    let mut digests = std::array::from_fn(|index| digest(u8::try_from(index + 0x61).unwrap()));
    digests[ClosedVerificationDigestFieldV2::InstallationId as usize - 1] = digest(0x31);
    let helper = ArtifactIdentityV2::new(
        ClosedArtifactTypeV2::RootHelper,
        ClosedTargetOsV2::Linux,
        ClosedTargetArchitectureV2::X86_64,
        4096,
        digest(0xa1),
        digest(0xa2),
        digest(0xa3),
    )
    .unwrap();
    let watchdog = ArtifactIdentityV2::new(
        ClosedArtifactTypeV2::Watchdog,
        ClosedTargetOsV2::Linux,
        ClosedTargetArchitectureV2::X86_64,
        4096,
        digest(0xa4),
        digest(0xa5),
        digest(0xa6),
    )
    .unwrap();
    let evidence = VerificationEvidenceV2::new_signed_with_authority(
        digests,
        17,
        nonce(0xb1),
        19,
        23,
        1_784_000_000_300,
        helper,
        watchdog,
        &mut authority,
        &verifier,
    )
    .unwrap();
    assert_eq!(
        VerificationEvidenceV2::from_canonical_bytes(evidence.canonical_bytes(), &verifier)
            .unwrap(),
        evidence
    );
    assert_eq!(
        evidence.digest_field(ClosedVerificationDigestFieldV2::TransactionIntent),
        digests[ClosedVerificationDigestFieldV2::TransactionIntent as usize - 1]
    );

    let envelope = InstallationEvidenceEnvelopeV2::new_verification_signed_with_authority(
        1,
        None,
        &evidence,
        &mut authority,
        &verifier,
    )
    .unwrap();
    assert_eq!(
        envelope.evidence_kind(),
        ClosedInstallationEvidenceKindV2::Verification
    );
    assert_eq!(envelope.verification_evidence(&verifier).unwrap(), evidence);

    let wrong_helper = ArtifactIdentityV2::new(
        ClosedArtifactTypeV2::Daemon,
        ClosedTargetOsV2::Linux,
        ClosedTargetArchitectureV2::X86_64,
        4096,
        digest(0xc1),
        digest(0xc2),
        digest(0xc3),
    )
    .unwrap();
    assert_eq!(
        VerificationEvidenceV2::new_signed_with_authority(
            digests,
            17,
            nonce(0xb1),
            19,
            23,
            1_784_000_000_300,
            wrong_helper,
            evidence.watchdog_identity().clone(),
            &mut authority,
            &verifier,
        )
        .unwrap_err(),
        DeploymentControlErrorV2::InvalidVerificationEvidence
    );
}

#[test]
fn commit_attestation_has_only_the_reconstructible_normal_terminal_shape() {
    let (mut authority, verifier, _) = fixture();
    let mut digests = std::array::from_fn(|index| digest(u8::try_from(index + 0x41).unwrap()));
    digests[ClosedCommitDigestFieldV2::InstallationId as usize - 1] = digest(0x31);
    let platform = PlatformLockV2::new(
        ClosedTargetOsV2::Linux,
        ClosedTargetArchitectureV2::X86_64,
        digest(0xd1),
        digest(0xd2),
        digest(0xd3),
        digest(0xd4),
        digest(0xd5),
    )
    .unwrap();
    let attestation = CommitAttestationV2::new_signed_with_authority(
        digests,
        17,
        platform,
        nonce(0xd6),
        29,
        31,
        1_784_000_000_400,
        &mut authority,
        &verifier,
    )
    .unwrap();
    assert_eq!(
        CommitAttestationV2::from_canonical_bytes(attestation.canonical_bytes(), &verifier)
            .unwrap(),
        attestation
    );
    let envelope = InstallationEvidenceEnvelopeV2::new_commit_signed_with_authority(
        1,
        None,
        &attestation,
        &mut authority,
        &verifier,
    )
    .unwrap();
    assert_eq!(
        envelope.evidence_kind(),
        ClosedInstallationEvidenceKindV2::Commit
    );
    assert_eq!(envelope.commit_attestation(&verifier).unwrap(), attestation);

    let mut mutated = attestation.canonical_bytes().to_vec();
    let false_position = mutated
        .iter()
        .position(|byte| *byte == 0xf4)
        .expect("canonical false terminal-fence field");
    mutated[false_position] = 0xf5;
    assert_eq!(
        CommitAttestationV2::from_canonical_bytes(&mutated, &verifier).unwrap_err(),
        DeploymentControlErrorV2::InvalidCommitAttestation
    );
}

#[test]
fn verified_origin_rollback_evidence_is_a_distinct_closed_branch() {
    let (mut authority, verifier, _) = fixture();
    let mut digests = std::array::from_fn(|index| digest(u8::try_from(index + 0x61).unwrap()));
    digests[ClosedRollbackVerificationDigestFieldV2::InstallationId as usize - 1] = digest(0x31);
    let platform = PlatformLockV2::new(
        ClosedTargetOsV2::Linux,
        ClosedTargetArchitectureV2::X86_64,
        digest(0xe1),
        digest(0xe2),
        digest(0xe3),
        digest(0xe4),
        digest(0xe5),
    )
    .unwrap();
    let helper = ArtifactIdentityV2::new(
        ClosedArtifactTypeV2::RootHelper,
        ClosedTargetOsV2::Linux,
        ClosedTargetArchitectureV2::X86_64,
        4096,
        digest(0xe6),
        digest(0xe7),
        digest(0xe8),
    )
    .unwrap();
    let watchdog = ArtifactIdentityV2::new(
        ClosedArtifactTypeV2::Watchdog,
        ClosedTargetOsV2::Linux,
        ClosedTargetArchitectureV2::X86_64,
        4096,
        digest(0xe9),
        digest(0xea),
        digest(0xeb),
    )
    .unwrap();
    let evidence = RollbackVerificationEvidenceV2::new_signed_with_authority(
        digests,
        17,
        platform,
        nonce(0xec),
        37,
        41,
        1_784_000_000_500,
        helper,
        watchdog,
        &mut authority,
        &verifier,
    )
    .unwrap();
    assert_eq!(
        RollbackVerificationEvidenceV2::from_canonical_bytes(evidence.canonical_bytes(), &verifier)
            .unwrap(),
        evidence
    );
    let envelope =
        InstallationEvidenceEnvelopeV2::new_rollback_verification_evidence_signed_with_authority(
            1,
            None,
            &evidence,
            &mut authority,
            &verifier,
        )
        .unwrap();
    assert_eq!(
        envelope.evidence_kind(),
        ClosedInstallationEvidenceKindV2::RollbackVerificationEvidence
    );
    assert_eq!(
        envelope.rollback_verification_evidence(&verifier).unwrap(),
        evidence
    );

    let mac_watchdog = ArtifactIdentityV2::new(
        ClosedArtifactTypeV2::Watchdog,
        ClosedTargetOsV2::MacOs,
        ClosedTargetArchitectureV2::X86_64,
        4096,
        digest(0xf1),
        digest(0xf2),
        digest(0xf3),
    )
    .unwrap();
    assert_eq!(
        RollbackVerificationEvidenceV2::new_signed_with_authority(
            digests,
            17,
            evidence.platform().clone(),
            nonce(0xec),
            37,
            41,
            1_784_000_000_500,
            evidence.helper_identity().clone(),
            mac_watchdog,
            &mut authority,
            &verifier,
        )
        .unwrap_err(),
        DeploymentControlErrorV2::InvalidRollbackVerificationEvidence
    );
}

#[test]
fn early_recovery_rollback_has_a_phase_tagged_measurement_union() {
    let (mut authority, verifier, _) = fixture();
    let mut digests = std::array::from_fn(|index| digest(u8::try_from(index + 0x71).unwrap()));
    digests[ClosedRecoveryRollbackDigestFieldV2::InstallationId as usize - 1] = digest(0x31);
    digests[ClosedRecoveryRollbackDigestFieldV2::RoleJournalReconciliation as usize - 1] =
        digest(0xc1);
    let platform = PlatformLockV2::new(
        ClosedTargetOsV2::Linux,
        ClosedTargetArchitectureV2::X86_64,
        digest(0xc2),
        digest(0xc3),
        digest(0xc4),
        digest(0xc5),
        digest(0xc6),
    )
    .unwrap();
    let helper = ArtifactIdentityV2::new(
        ClosedArtifactTypeV2::RootHelper,
        ClosedTargetOsV2::Linux,
        ClosedTargetArchitectureV2::X86_64,
        4096,
        digest(0xc7),
        digest(0xc8),
        digest(0xc9),
    )
    .unwrap();
    let watchdog = ArtifactIdentityV2::new(
        ClosedArtifactTypeV2::Watchdog,
        ClosedTargetOsV2::Linux,
        ClosedTargetArchitectureV2::X86_64,
        4096,
        digest(0xca),
        digest(0xcb),
        digest(0xcc),
    )
    .unwrap();
    let origin = RecoveryRollbackOriginMeasurementsV2::Quiesced {
        quiesced_ledger_record_digest: digest(0xcd),
        frozen_effect_work_set_digest: digest(0xce),
        role_journal_reconciliation_digest: digest(0xc1),
    };
    let evidence = RecoveryRollbackReadinessEvidenceV2::new_signed_with_authority(
        digests,
        17,
        platform,
        nonce(0xcf),
        origin,
        43,
        47,
        1_784_000_000_600,
        helper,
        watchdog,
        &mut authority,
        &verifier,
    )
    .unwrap();
    assert_eq!(evidence.origin_measurements(), origin);
    assert_eq!(
        RecoveryRollbackReadinessEvidenceV2::from_canonical_bytes(
            evidence.canonical_bytes(),
            &verifier
        )
        .unwrap(),
        evidence
    );
    let envelope =
        InstallationEvidenceEnvelopeV2::new_recovery_rollback_readiness_signed_with_authority(
            1,
            None,
            &evidence,
            &mut authority,
            &verifier,
        )
        .unwrap();
    assert_eq!(
        envelope.evidence_kind(),
        ClosedInstallationEvidenceKindV2::RecoveryRollbackReadinessEvidence
    );
    assert_eq!(
        envelope
            .recovery_rollback_readiness_evidence(&verifier)
            .unwrap(),
        evidence
    );

    let mismatched_origin = RecoveryRollbackOriginMeasurementsV2::Installed {
        installed_ledger_record_digest: digest(0xd1),
        attempted_file_tree_root: digest(0xd2),
        attempted_store_migration_result_digest: digest(0xd3),
        role_journal_reconciliation_digest: digest(0xd4),
    };
    assert_eq!(
        RecoveryRollbackReadinessEvidenceV2::new_signed_with_authority(
            digests,
            17,
            evidence.platform().clone(),
            nonce(0xcf),
            mismatched_origin,
            43,
            47,
            1_784_000_000_600,
            evidence.helper_identity().clone(),
            evidence.watchdog_identity().clone(),
            &mut authority,
            &verifier,
        )
        .unwrap_err(),
        DeploymentControlErrorV2::InvalidRecoveryRollbackReadinessEvidence
    );
}

#[test]
fn rolled_back_attestation_binds_consumed_grant_activation_and_readiness_branch() {
    let (mut authority, verifier, _) = fixture();
    let mut digests = std::array::from_fn(|index| digest(u8::try_from(index + 0x81).unwrap()));
    digests[ClosedRollbackAttestationDigestFieldV2::InstallationId as usize - 1] = digest(0x31);
    let platform = PlatformLockV2::new(
        ClosedTargetOsV2::Linux,
        ClosedTargetArchitectureV2::X86_64,
        digest(0xd5),
        digest(0xd6),
        digest(0xd7),
        digest(0xd8),
        digest(0xd9),
    )
    .unwrap();
    let readiness = RollbackTerminalReadinessRefV2::VerifiedOrigin {
        candidate_verification_evidence_digest: digest(0xda),
        rollback_verification_evidence_digest: digest(0xdb),
    };
    let attestation = RollbackVerificationAttestationV2::new_signed_with_authority(
        digests,
        17,
        platform,
        nonce(0xdc),
        readiness,
        53,
        59,
        RollbackOriginPhaseV2::Verified,
        1_784_000_000_700,
        &mut authority,
        &verifier,
    )
    .unwrap();
    assert_eq!(attestation.terminal_readiness(), readiness);
    assert_eq!(
        RollbackVerificationAttestationV2::from_canonical_bytes(
            attestation.canonical_bytes(),
            &verifier
        )
        .unwrap(),
        attestation
    );
    let envelope =
        InstallationEvidenceEnvelopeV2::new_rollback_verification_attestation_signed_with_authority(
            1,
            None,
            &attestation,
            &mut authority,
            &verifier,
        )
        .unwrap();
    assert_eq!(
        envelope.evidence_kind(),
        ClosedInstallationEvidenceKindV2::RollbackVerificationAttestation
    );
    assert_eq!(
        envelope
            .rollback_verification_attestation(&verifier)
            .unwrap(),
        attestation
    );

    assert_eq!(
        RollbackVerificationAttestationV2::new_signed_with_authority(
            digests,
            17,
            attestation.platform().clone(),
            nonce(0xdc),
            readiness,
            53,
            59,
            RollbackOriginPhaseV2::Installed,
            1_784_000_000_700,
            &mut authority,
            &verifier,
        )
        .unwrap_err(),
        DeploymentControlErrorV2::InvalidRollbackVerificationAttestation
    );
}
