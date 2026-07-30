use ed25519_dalek::SigningKey;
use savana_kernel_protocol::v2::{derive_ed25519_key_id_v2, Digest32V2, Nonce32V2};
use savana_policy_core::v2::{
    ActiveActivationV2, ArtifactIdentityV2, ClosedArtifactTypeV2, ClosedTargetArchitectureV2,
    ClosedTargetOsV2, DeploymentAuthorizationKeyRefsV2, DeploymentAuthorizationVerifierV2,
    DeploymentControlErrorV2, DeploymentPhaseV2, DeploymentRecoveryTargetV2,
    DeploymentTransactionIntentMaterialV2, DeploymentTransactionIntentV2, DeploymentTransactionV2,
    ExpectedPreStateV2, PlatformLockV2, RecoveryPhaseHighWaterV2, RollbackGrantV2,
};

fn digest(byte: u8) -> Digest32V2 {
    Digest32V2::new([byte; 32])
}

fn fixture_material() -> DeploymentTransactionIntentMaterialV2 {
    let platform = PlatformLockV2::new(
        ClosedTargetOsV2::Linux,
        ClosedTargetArchitectureV2::X86_64,
        digest(0x11),
        digest(0x12),
        digest(0x13),
        digest(0x14),
        digest(0x15),
    )
    .unwrap();
    let helper = ArtifactIdentityV2::new(
        ClosedArtifactTypeV2::RootHelper,
        ClosedTargetOsV2::Linux,
        ClosedTargetArchitectureV2::X86_64,
        4096,
        digest(0x21),
        digest(0x22),
        digest(0x23),
    )
    .unwrap();
    let watchdog = ArtifactIdentityV2::new(
        ClosedArtifactTypeV2::Watchdog,
        ClosedTargetOsV2::Linux,
        ClosedTargetArchitectureV2::X86_64,
        4096,
        digest(0x24),
        digest(0x25),
        digest(0x26),
    )
    .unwrap();
    let expected_pre_state = ExpectedPreStateV2::new(
        7,
        digest(0x31),
        DeploymentPhaseV2::Committed,
        ActiveActivationV2::Normal,
        false,
        digest(0x32),
        digest(0x33),
        digest(0x34),
        helper,
        watchdog,
        digest(0x35),
        digest(0x36),
        digest(0x37),
        digest(0x38),
        17,
        19,
    )
    .unwrap();
    DeploymentTransactionIntentMaterialV2 {
        transaction_id: Nonce32V2::new([0x41; 32]),
        installation_id: digest(0x42),
        target_platform: platform,
        evidence_trust_policy_digest: digest(0x43),
        evidence_layer_limits_digest: digest(0x44),
        source_evidence_digest: digest(0x45),
        artifact_evidence_digest: digest(0x46),
        created_at_unix_ms: 1_784_100_000_000,
        not_before_unix_ms: 1_784_100_000_001,
        expires_at_unix_ms: 1_784_200_000_000,
        maximum_prepare_duration_ns: 80_000_000_000_000,
        maximum_cutover_duration_ns: 3_000_000_000_000,
        maximum_boot_recovery_duration_ns: 3_000_000_000_000,
        maximum_clock_skew_ns: 200_000_000_000,
        expected_pre_state,
        staging_tree_digest: digest(0x47),
        desired_manifest_digest: digest(0x48),
        recovery_target: DeploymentRecoveryTargetV2::normal(digest(0x49)).unwrap(),
        migration_plan_digest: digest(0x4a),
        artifact_install_plan_digest: digest(0x4b),
        service_transition_plan_digest: digest(0x4c),
        isolated_e2e_plan_digest: digest(0x4d),
        evidence_contract_digest: digest(0x4e),
        protected_acceptance_plan_digest: digest(0x4f),
    }
}

#[test]
fn transaction_intent_is_complete_canonical_and_acyclic() {
    let intent = DeploymentTransactionIntentV2::new(fixture_material()).unwrap();
    let reopened =
        DeploymentTransactionIntentV2::from_canonical_bytes(intent.canonical_bytes()).unwrap();
    assert_eq!(reopened, intent);
    assert_ne!(intent.intent_digest(), digest(0));
    assert_eq!(
        intent.recovery_target().digest(),
        fixture_material().recovery_target.digest()
    );
}

#[test]
fn transaction_intent_rejects_wrong_recovery_branch_time_and_bootstrap_artifact_kind() {
    let mut wrong_branch = fixture_material();
    wrong_branch.recovery_target = DeploymentRecoveryTargetV2::bootstrap_bridge_restore(
        digest(0x51),
        digest(0x52),
        digest(0x53),
        digest(0x54),
        digest(0x55),
    )
    .unwrap();
    assert_eq!(
        DeploymentTransactionIntentV2::new(wrong_branch).unwrap_err(),
        DeploymentControlErrorV2::InvalidDeploymentTransaction
    );

    let mut expired = fixture_material();
    expired.expires_at_unix_ms = expired.not_before_unix_ms;
    assert_eq!(
        DeploymentTransactionIntentV2::new(expired).unwrap_err(),
        DeploymentControlErrorV2::InvalidDeploymentTransaction
    );

    let material = fixture_material();
    let wrong_helper = ArtifactIdentityV2::new(
        ClosedArtifactTypeV2::Daemon,
        ClosedTargetOsV2::Linux,
        ClosedTargetArchitectureV2::X86_64,
        4096,
        digest(0x61),
        digest(0x62),
        digest(0x63),
    )
    .unwrap();
    assert_eq!(
        ExpectedPreStateV2::new(
            material.expected_pre_state.ledger_generation(),
            material.expected_pre_state.ledger_record_payload_digest(),
            DeploymentPhaseV2::Committed,
            ActiveActivationV2::Normal,
            false,
            material.expected_pre_state.active_manifest_digest(),
            material.expected_pre_state.highest_ever_digest(),
            material
                .expected_pre_state
                .install_identity_profile_signed_digest(),
            wrong_helper,
            material
                .expected_pre_state
                .deploy_watchdog_identity()
                .clone(),
            material
                .expected_pre_state
                .deployment_trust_root_set_digest(),
            material
                .expected_pre_state
                .activation_trust_root_set_digest(),
            material.expected_pre_state.release_trust_root_set_digest(),
            material.expected_pre_state.bootstrap_slot_closure_digest(),
            material.expected_pre_state.installation_epoch(),
            material.expected_pre_state.effect_fence_epoch(),
        )
        .unwrap_err(),
        DeploymentControlErrorV2::InvalidDeploymentTransaction
    );
}

#[test]
fn rollback_grant_and_transaction_authorization_are_distinct_exact_signatures() {
    let intent = DeploymentTransactionIntentV2::new(fixture_material()).unwrap();
    let grant_key = SigningKey::from_bytes(&[0x91; 32]);
    let grant_verifier = DeploymentAuthorizationVerifierV2::new(
        derive_ed25519_key_id_v2(grant_key.verifying_key().to_bytes()),
        7,
        grant_key.verifying_key().to_bytes(),
    )
    .unwrap();
    let high_water = RecoveryPhaseHighWaterV2::normal(std::array::from_fn(|index| {
        digest(u8::try_from(index).unwrap().wrapping_add(0x70))
    }))
    .unwrap();
    let grant = RollbackGrantV2::new_signed_for_test(
        &intent,
        high_water,
        intent.material().expires_at_unix_ms + 10_000_000,
        &grant_key,
        7,
    )
    .unwrap();
    grant.validate_against_intent(&intent).unwrap();

    let authorization_key = SigningKey::from_bytes(&[0x92; 32]);
    let transaction = DeploymentTransactionV2::new_signed_for_test(
        intent,
        grant,
        &authorization_key,
        8,
        &grant_verifier,
    )
    .unwrap();
    let authorization_verifier = DeploymentAuthorizationVerifierV2::new(
        derive_ed25519_key_id_v2(authorization_key.verifying_key().to_bytes()),
        8,
        authorization_key.verifying_key().to_bytes(),
    )
    .unwrap();
    assert_eq!(
        DeploymentTransactionV2::from_canonical_bytes(
            transaction.canonical_bytes(),
            &grant_verifier,
            &authorization_verifier,
        )
        .unwrap(),
        transaction
    );
    assert_ne!(
        transaction.transaction_payload_digest(),
        transaction.intent().intent_digest()
    );
    let key_refs = DeploymentAuthorizationKeyRefsV2::peek(transaction.canonical_bytes()).unwrap();
    assert_eq!(key_refs.rollback_key_id(), grant_verifier.key_id());
    assert_eq!(key_refs.rollback_key_epoch(), grant_verifier.key_epoch());
    assert_eq!(
        key_refs.transaction_key_id(),
        authorization_verifier.key_id()
    );
    assert_eq!(
        key_refs.transaction_key_epoch(),
        authorization_verifier.key_epoch()
    );
    assert_eq!(
        key_refs.authorization_time_unix_ms(),
        transaction.intent().material().created_at_unix_ms
    );

    let wrong_grant_key = SigningKey::from_bytes(&[0x93; 32]);
    let wrong_grant_verifier = DeploymentAuthorizationVerifierV2::new(
        derive_ed25519_key_id_v2(wrong_grant_key.verifying_key().to_bytes()),
        7,
        wrong_grant_key.verifying_key().to_bytes(),
    )
    .unwrap();
    assert_eq!(
        DeploymentTransactionV2::from_canonical_bytes(
            transaction.canonical_bytes(),
            &wrong_grant_verifier,
            &authorization_verifier,
        )
        .unwrap_err(),
        DeploymentControlErrorV2::InvalidDeploymentTransaction
    );
}

#[test]
fn grant_branch_must_equal_the_signed_recovery_target() {
    let intent = DeploymentTransactionIntentV2::new(fixture_material()).unwrap();
    let grant_key = SigningKey::from_bytes(&[0x94; 32]);
    let grant = RollbackGrantV2::new_signed_for_test(
        &intent,
        RecoveryPhaseHighWaterV2::bootstrap_bridge_restore(std::array::from_fn(|index| {
            digest(u8::try_from(index).unwrap().wrapping_add(0x80))
        }))
        .unwrap(),
        intent.material().expires_at_unix_ms + 10_000_000,
        &grant_key,
        9,
    )
    .unwrap();
    assert_eq!(
        grant.validate_against_intent(&intent).unwrap_err(),
        DeploymentControlErrorV2::InvalidDeploymentTransaction
    );
}
