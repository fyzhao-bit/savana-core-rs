use ed25519_dalek::SigningKey;
use savana_kernel_protocol::v2::{derive_ed25519_key_id_v2, Digest32V2, Nonce32V2};
use savana_policy_core::v2::{
    ActiveActivationV2, ArtifactIdentityV2, AuthenticatedNativeDeploymentTrustV2,
    ClosedArtifactTypeV2, ClosedTargetArchitectureV2, ClosedTargetOsV2,
    ComponentSignerAuthorizationV2, DeploymentAuthorizationKeyRefsV2,
    DeploymentAuthorizationVerifierV2, DeploymentControlErrorV2, DeploymentLedgerRecordV2,
    DeploymentPhaseV2, DeploymentRecoveryTargetV2, DeploymentTransactionIntentMaterialV2,
    DeploymentTransactionIntentV2, DeploymentTransactionV2, ExpectedPreStateV2,
    ManifestComponentKindV2, ManifestComponentRefV2, NativeDeploymentBootstrapTrustMaterialV2,
    OperationalTrustRootPurposeV2, OperationalTrustRootSetItemV2, OperationalTrustRootSetV2,
    PlatformLockV2, RecoveryPhaseHighWaterV2, ReleaseRootKeyV2, ReleaseSigningRoleV2,
    ReleaseTrustRootSetV2, RollbackGrantStateV2, RollbackGrantV2,
};

fn digest(byte: u8) -> Digest32V2 {
    Digest32V2::new([byte; 32])
}

fn trust_root(
    purpose: OperationalTrustRootPurposeV2,
    key: &SigningKey,
) -> OperationalTrustRootSetItemV2 {
    OperationalTrustRootSetItemV2::new(purpose, key.verifying_key().to_bytes(), 1, 10, 90)
        .expect("trust root")
}

fn sort_trust_roots(values: &mut [OperationalTrustRootSetItemV2]) {
    values.sort_by_key(|value| {
        (
            value.purpose().tag(),
            *value.key_id().as_bytes(),
            value.key_epoch(),
        )
    });
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
        digest(0x39),
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
            material
                .expected_pre_state
                .declassification_trust_root_set_digest(),
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
fn authenticated_pre_state_requires_the_exact_declassification_root_digest() {
    let mut material = fixture_material();
    let activation_signing_key = SigningKey::from_bytes(&[0x95; 32]);
    let selected_ledger = DeploymentLedgerRecordV2::new_signed_for_test(
        material.installation_id,
        material.expected_pre_state.installation_epoch(),
        material.expected_pre_state.ledger_generation(),
        Digest32V2::new([0; 32]),
        DeploymentPhaseV2::Idle,
        None,
        false,
        material.expected_pre_state.effect_fence_epoch(),
        RollbackGrantStateV2::None,
        None,
        9,
        57,
        &activation_signing_key,
    )
    .expect("selected ledger");
    let expected = ExpectedPreStateV2::new(
        selected_ledger.projection().generation(),
        selected_ledger.projection().record_payload_digest(),
        selected_ledger.projection().phase(),
        selected_ledger.active_activation().clone(),
        selected_ledger.projection().effects_fenced(),
        selected_ledger.active_manifest_digest(),
        selected_ledger.highest_ever().digest().expect("high water"),
        selected_ledger.install_identity_profile_signed_digest(),
        material.expected_pre_state.deploy_helper_identity().clone(),
        material
            .expected_pre_state
            .deploy_watchdog_identity()
            .clone(),
        digest(0x51),
        digest(0x52),
        digest(0x53),
        digest(0x54),
        material.expected_pre_state.bootstrap_slot_closure_digest(),
        material.expected_pre_state.installation_epoch(),
        selected_ledger.projection().effect_fence_epoch(),
    )
    .expect("expected pre-state");
    material.expected_pre_state = expected.clone();
    let intent = DeploymentTransactionIntentV2::new(material).expect("transaction intent");
    let grant_key = SigningKey::from_bytes(&[0x96; 32]);
    let grant_verifier = DeploymentAuthorizationVerifierV2::new(
        derive_ed25519_key_id_v2(grant_key.verifying_key().to_bytes()),
        7,
        grant_key.verifying_key().to_bytes(),
    )
    .expect("grant verifier");
    let grant = RollbackGrantV2::new_signed_for_test(
        &intent,
        RecoveryPhaseHighWaterV2::normal(std::array::from_fn(|index| {
            digest(u8::try_from(index).expect("index").wrapping_add(0x70))
        }))
        .expect("high water"),
        intent.material().expires_at_unix_ms + 10_000_000,
        &grant_key,
        7,
    )
    .expect("rollback grant");
    let transaction_key = SigningKey::from_bytes(&[0x97; 32]);
    let transaction = DeploymentTransactionV2::new_signed_for_test(
        intent,
        grant,
        &transaction_key,
        8,
        &grant_verifier,
    )
    .expect("signed transaction");

    assert_eq!(
        transaction.validate_authenticated_pre_state(
            &selected_ledger,
            expected.deployment_trust_root_set_digest(),
            expected.activation_trust_root_set_digest(),
            expected.release_trust_root_set_digest(),
            expected.declassification_trust_root_set_digest(),
        ),
        Ok(())
    );
    for invalid_declassification_root in [
        Digest32V2::new([0; 32]),
        expected.release_trust_root_set_digest(),
        digest(0x55),
    ] {
        assert_eq!(
            transaction.validate_authenticated_pre_state(
                &selected_ledger,
                expected.deployment_trust_root_set_digest(),
                expected.activation_trust_root_set_digest(),
                expected.release_trust_root_set_digest(),
                invalid_declassification_root,
            ),
            Err(DeploymentControlErrorV2::TransactionBindingMismatch)
        );
    }
}

#[test]
fn authenticated_native_trust_support_path_requires_its_declassification_member_set_digest() {
    let installer = SigningKey::from_bytes(&[0xa1; 32]);
    let grant_key = SigningKey::from_bytes(&[0xa2; 32]);
    let transaction_key = SigningKey::from_bytes(&[0xa3; 32]);
    let activation_key = SigningKey::from_bytes(&[0xa4; 32]);
    let declassification_key = SigningKey::from_bytes(&[0xa5; 32]);
    let previous_declassification_key = SigningKey::from_bytes(&[0xaf; 32]);
    let component_key = SigningKey::from_bytes(&[0xa6; 32]);
    let release_key = SigningKey::from_bytes(&[0xa7; 32]);
    let product_family = digest(0xa8);

    let mut deployment_members = vec![
        trust_root(
            OperationalTrustRootPurposeV2::RollbackAuthorization,
            &grant_key,
        ),
        trust_root(
            OperationalTrustRootPurposeV2::DeploymentAuthorization,
            &transaction_key,
        ),
    ];
    sort_trust_roots(&mut deployment_members);
    let deployment = OperationalTrustRootSetV2::new_deployment_signed_for_test(
        product_family,
        1,
        None,
        deployment_members,
        10,
        90,
        &installer,
        1,
    )
    .expect("deployment root");
    let activation = OperationalTrustRootSetV2::new_activation_signed_for_test(
        product_family,
        1,
        None,
        vec![trust_root(
            OperationalTrustRootPurposeV2::InstallationActivation,
            &activation_key,
        )],
        10,
        90,
        &installer,
        1,
    )
    .expect("activation root");
    let previous_declassification =
        OperationalTrustRootSetV2::new_declassification_signed_for_test(
            product_family,
            1,
            None,
            vec![trust_root(
                OperationalTrustRootPurposeV2::DeclassificationAuthority,
                &previous_declassification_key,
            )],
            10,
            90,
            &installer,
            1,
        )
        .expect("previous declassification root");
    let declassification = OperationalTrustRootSetV2::new_declassification_signed_for_test(
        product_family,
        2,
        Some(previous_declassification.signed_digest()),
        vec![trust_root(
            OperationalTrustRootPurposeV2::DeclassificationAuthority,
            &declassification_key,
        )],
        10,
        90,
        &installer,
        1,
    )
    .expect("declassification root");
    let component_ref =
        ManifestComponentRefV2::new(ManifestComponentKindV2::BinaryArtifact, digest(0xa9))
            .expect("component ref");
    let release = ReleaseTrustRootSetV2::new_signed_for_test(
        product_family,
        1,
        None,
        vec![
            ReleaseRootKeyV2::new(
                ReleaseSigningRoleV2::ManifestComponent,
                component_key.verifying_key().to_bytes(),
                1,
                10,
                90,
            )
            .expect("component release root"),
            ReleaseRootKeyV2::new(
                ReleaseSigningRoleV2::ManifestRelease,
                release_key.verifying_key().to_bytes(),
                1,
                10,
                90,
            )
            .expect("release root"),
        ],
        vec![ComponentSignerAuthorizationV2::new(
            digest(0xaa),
            component_ref,
            derive_ed25519_key_id_v2(component_key.verifying_key().to_bytes()),
            1,
        )
        .expect("component authorization")],
        10,
        90,
        &installer,
        1,
    )
    .expect("release trust root");
    let trust_material = NativeDeploymentBootstrapTrustMaterialV2::new_for_test(
        *derive_ed25519_key_id_v2(installer.verifying_key().to_bytes()).as_bytes(),
        1,
        installer.verifying_key().to_bytes(),
        vec![deployment.canonical_bytes().to_vec()],
        vec![activation.canonical_bytes().to_vec()],
        vec![
            previous_declassification.canonical_bytes().to_vec(),
            declassification.canonical_bytes().to_vec(),
        ],
        vec![release.canonical_bytes().to_vec()],
    )
    .expect("native bootstrap trust material");
    let trust = AuthenticatedNativeDeploymentTrustV2::verify(&trust_material)
        .expect("authenticated native deployment trust");

    let mut material = fixture_material();
    material.created_at_unix_ms = 20;
    material.not_before_unix_ms = 21;
    material.expires_at_unix_ms = 80;
    let ledger_signing_key = SigningKey::from_bytes(&[0xab; 32]);
    let selected_ledger = DeploymentLedgerRecordV2::new_signed_for_test(
        material.installation_id,
        material.expected_pre_state.installation_epoch(),
        material.expected_pre_state.ledger_generation(),
        Digest32V2::new([0; 32]),
        DeploymentPhaseV2::Idle,
        None,
        false,
        material.expected_pre_state.effect_fence_epoch(),
        RollbackGrantStateV2::None,
        None,
        9,
        57,
        &ledger_signing_key,
    )
    .expect("selected ledger");
    let expected = ExpectedPreStateV2::new(
        selected_ledger.projection().generation(),
        selected_ledger.projection().record_payload_digest(),
        selected_ledger.projection().phase(),
        selected_ledger.active_activation().clone(),
        selected_ledger.projection().effects_fenced(),
        selected_ledger.active_manifest_digest(),
        selected_ledger.highest_ever().digest().expect("high water"),
        selected_ledger.install_identity_profile_signed_digest(),
        material.expected_pre_state.deploy_helper_identity().clone(),
        material
            .expected_pre_state
            .deploy_watchdog_identity()
            .clone(),
        trust
            .deployment_trust_root_set()
            .binding()
            .member_set_digest(),
        trust
            .activation_trust_root_set()
            .binding()
            .member_set_digest(),
        trust
            .release_trust_root_set()
            .release_trust_root_set_digest(),
        trust
            .declassification_trust_root_set()
            .binding()
            .member_set_digest(),
        material.expected_pre_state.bootstrap_slot_closure_digest(),
        material.expected_pre_state.installation_epoch(),
        selected_ledger.projection().effect_fence_epoch(),
    )
    .expect("expected pre-state");
    material.expected_pre_state = expected.clone();
    let intent = DeploymentTransactionIntentV2::new(material).expect("transaction intent");
    let grant_verifier = DeploymentAuthorizationVerifierV2::new(
        derive_ed25519_key_id_v2(grant_key.verifying_key().to_bytes()),
        1,
        grant_key.verifying_key().to_bytes(),
    )
    .expect("grant verifier");
    let grant = RollbackGrantV2::new_signed_for_test(
        &intent,
        RecoveryPhaseHighWaterV2::normal(std::array::from_fn(|index| {
            digest(u8::try_from(index).expect("index").wrapping_add(0x70))
        }))
        .expect("high water"),
        intent.material().expires_at_unix_ms + 10_000_000,
        &grant_key,
        1,
    )
    .expect("rollback grant");
    let transaction = DeploymentTransactionV2::new_signed_for_test(
        intent,
        grant,
        &transaction_key,
        1,
        &grant_verifier,
    )
    .expect("signed transaction");
    let (authenticated_grant_verifier, authenticated_transaction_verifier) = trust
        .transaction_authorization_verifiers(transaction.canonical_bytes())
        .expect("authenticated transaction verifiers");
    let transaction = DeploymentTransactionV2::from_canonical_bytes(
        transaction.canonical_bytes(),
        &authenticated_grant_verifier,
        &authenticated_transaction_verifier,
    )
    .expect("authenticated staged transaction");

    trust
        .validate_authenticated_transaction_pre_state(&transaction, &selected_ledger)
        .expect("production support pre-state binding");

    let mut wrong_material = transaction.intent().material().clone();
    wrong_material.expected_pre_state = ExpectedPreStateV2::new(
        expected.ledger_generation(),
        expected.ledger_record_payload_digest(),
        expected.phase(),
        expected.active_activation().clone(),
        expected.effects_fenced(),
        expected.active_manifest_digest(),
        expected.highest_ever_digest(),
        expected.install_identity_profile_signed_digest(),
        expected.deploy_helper_identity().clone(),
        expected.deploy_watchdog_identity().clone(),
        expected.deployment_trust_root_set_digest(),
        expected.activation_trust_root_set_digest(),
        expected.release_trust_root_set_digest(),
        previous_declassification.binding().member_set_digest(),
        expected.bootstrap_slot_closure_digest(),
        expected.installation_epoch(),
        expected.effect_fence_epoch(),
    )
    .expect("wrong-version declassification pre-state");
    let wrong_intent = DeploymentTransactionIntentV2::new(wrong_material).expect("wrong intent");
    let wrong_grant = RollbackGrantV2::new_signed_for_test(
        &wrong_intent,
        RecoveryPhaseHighWaterV2::normal(std::array::from_fn(|index| {
            digest(u8::try_from(index).expect("index").wrapping_add(0x70))
        }))
        .expect("high water"),
        wrong_intent.material().expires_at_unix_ms + 10_000_000,
        &grant_key,
        1,
    )
    .expect("wrong rollback grant");
    let wrong_transaction = DeploymentTransactionV2::new_signed_for_test(
        wrong_intent,
        wrong_grant,
        &transaction_key,
        1,
        &grant_verifier,
    )
    .expect("wrong signed transaction");
    let wrong_transaction = DeploymentTransactionV2::from_canonical_bytes(
        wrong_transaction.canonical_bytes(),
        &authenticated_grant_verifier,
        &authenticated_transaction_verifier,
    )
    .expect("wrong authenticated staged transaction");
    assert_eq!(
        trust.validate_authenticated_transaction_pre_state(&wrong_transaction, &selected_ledger),
        Err(DeploymentControlErrorV2::TransactionBindingMismatch)
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
