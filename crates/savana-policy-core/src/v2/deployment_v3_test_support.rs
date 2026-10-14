//! Synthetic signing fixture, compiled only in tests. Never native authority.
use super::*;
use ed25519_dalek::{Signer, SigningKey};
use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature};
use savana_kernel_protocol::v2::{derive_ed25519_key_id_v2, Digest32V2, Nonce32V2};
use savana_platform_identity::{
    DeploymentRecordScopeV3, TpmClientIdentityV3, TpmEnrollmentProposalV3, TpmEnrollmentV3,
    TpmNvBindingV3, TpmPcrPolicyV3, TpmSigningBindingV3, TpmSigningPublicV3, TpmStateHeadV3,
    TpmStoreV3, VerifiedDeploymentRecordEnvelopeV3,
};
use sha2::{Digest, Sha256};

pub(super) fn transaction_material(
    state: &DeploymentLedgerStateV3,
) -> DeploymentTransactionIntentMaterialV2 {
    let d = |n| Digest32V2::new([n; 32]);
    transaction_material_on(
        state,
        PlatformLockV2::new(
            ClosedTargetOsV2::Linux,
            ClosedTargetArchitectureV2::X86_64,
            d(11),
            d(12),
            d(13),
            d(14),
            d(15),
        )
        .unwrap(),
    )
}
pub(super) fn transaction_material_on(
    state: &DeploymentLedgerStateV3,
    platform: PlatformLockV2,
) -> DeploymentTransactionIntentMaterialV2 {
    let d = |n| Digest32V2::new([n; 32]);
    let m = state.material();
    let artifact = |kind| {
        ArtifactIdentityV2::new(
            kind,
            platform.target_os(),
            platform.target_architecture(),
            4096,
            d(60),
            d(61),
            d(62),
        )
        .unwrap()
    };
    let expected = ExpectedPreStateV2::new(
        m.generation,
        state.payload_digest(),
        m.phase,
        m.active_activation.clone(),
        m.effects_fenced,
        m.active_manifest,
        m.highest_ever.digest().unwrap(),
        m.identity_profile,
        artifact(ClosedArtifactTypeV2::RootHelper),
        artifact(ClosedArtifactTypeV2::Watchdog),
        d(50),
        d(51),
        d(52),
        d(53),
        d(54),
        m.epoch,
        m.fence_epoch,
    )
    .unwrap();
    DeploymentTransactionIntentMaterialV2 {
        transaction_id: Nonce32V2::new([80; 32]),
        installation_id: m.installation,
        target_platform: platform,
        evidence_trust_policy_digest: d(40),
        evidence_layer_limits_digest: d(41),
        source_evidence_digest: d(42),
        artifact_evidence_digest: d(43),
        created_at_unix_ms: 150000,
        not_before_unix_ms: 150001,
        expires_at_unix_ms: 160000,
        maximum_prepare_duration_ns: 1_000_000,
        maximum_cutover_duration_ns: 1_000_000,
        maximum_boot_recovery_duration_ns: 1_000_000,
        maximum_clock_skew_ns: 1_000_000,
        expected_pre_state: expected,
        staging_tree_digest: d(44),
        desired_manifest_digest: d(45),
        recovery_target: DeploymentRecoveryTargetV2::normal(d(46)).unwrap(),
        migration_plan_digest: d(47),
        artifact_install_plan_digest: d(48),
        service_transition_plan_digest: d(49),
        isolated_e2e_plan_digest: d(55),
        evidence_contract_digest: d(56),
        protected_acceptance_plan_digest: d(57),
    }
}
pub(super) fn sign_transaction(
    material: DeploymentTransactionIntentMaterialV2,
) -> DeploymentTransactionV2 {
    let grant_key = SigningKey::from_bytes(&[70; 32]);
    let intent = DeploymentTransactionIntentV2::new(material).unwrap();
    let grant = RollbackGrantV2::new_signed_for_test(
        &intent,
        RecoveryPhaseHighWaterV2::normal([Digest32V2::new([71; 32]); 21]).unwrap(),
        intent.material().expires_at_unix_ms + 1000,
        &grant_key,
        1,
    )
    .unwrap();
    let verifier = DeploymentAuthorizationVerifierV2::new(
        derive_ed25519_key_id_v2(grant_key.verifying_key().to_bytes()),
        1,
        grant_key.verifying_key().to_bytes(),
    )
    .unwrap();
    DeploymentTransactionV2::new_signed_for_test(
        intent,
        grant,
        &SigningKey::from_bytes(&[72; 32]),
        1,
        &verifier,
    )
    .unwrap()
}

pub(super) fn enrollment() -> TpmEnrollmentV3 {
    enrollment_for([23; 32])
}
pub(super) fn enrollment_for(broker: [u8; 32]) -> TpmEnrollmentV3 {
    let key = p256::ecdsa::SigningKey::from_bytes((&[7; 32]).into()).unwrap();
    let p = key.verifying_key().to_encoded_point(false);
    let policy = TpmPcrPolicyV3::new(0x81, [8; 32]).unwrap();
    let mut area = vec![0, 0x23, 0, 0x0b, 0, 4, 0, 0xb2, 0, 32];
    area.extend_from_slice(&policy.auth_policy());
    area.extend_from_slice(&[0, 0x10, 0, 0x18, 0, 0x0b, 0, 3, 0, 0x10]);
    for c in [p.x().unwrap(), p.y().unwrap()] {
        area.extend_from_slice(&[0, 32]);
        area.extend_from_slice(c);
    }
    let mut bytes = (area.len() as u16).to_be_bytes().to_vec();
    bytes.extend_from_slice(&area);
    let public = TpmSigningPublicV3::from_tpm2b_public(&bytes).unwrap();
    let mut q = [9; 34];
    q[..2].copy_from_slice(&[0, 0x0b]);
    let binding =
        TpmSigningBindingV3::new_with_pcr(public, q, 0x81010003, [1; 32], 1, policy).unwrap();
    let stores = std::array::from_fn(|i| {
        let index = TpmStoreV3::ALL[i].index();
        TpmNvBindingV3::new(
            index,
            TpmNvBindingV3::expected_name(index),
            [1; 32],
            [i as u8 + 10; 32],
            1,
            [i as u8 + 20; 32],
            TpmStateHeadV3::GENESIS,
        )
        .unwrap()
    });
    let proposal = TpmEnrollmentProposalV3::new(
        binding,
        stores,
        TpmClientIdentityV3::new(0, 0, [21; 32]).unwrap(),
        TpmClientIdentityV3::new(1001, 1001, [22; 32]).unwrap(),
        TpmClientIdentityV3::new(0, 0, broker).unwrap(),
        100,
        200,
        [0; 32],
    )
    .unwrap();
    let root = SigningKey::from_bytes(&[9; 32]);
    TpmEnrollmentV3::verify(
        &proposal.attach_signature(root.sign(&proposal.signature_input()).to_bytes()),
        root.verifying_key().to_bytes(),
        150,
    )
    .unwrap()
}
pub(super) fn record(
    payload: &[u8],
    scope: DeploymentRecordScopeV3,
    previous: TpmStateHeadV3,
) -> VerifiedDeploymentRecordEnvelopeV3 {
    record_for(payload, scope, previous, enrollment())
}
pub(super) fn record_for(
    payload: &[u8],
    scope: DeploymentRecordScopeV3,
    previous: TpmStateHeadV3,
    e: TpmEnrollmentV3,
) -> VerifiedDeploymentRecordEnvelopeV3 {
    let b = e.signing_binding();
    let mut bytes = b"SDR3".to_vec();
    bytes.extend_from_slice(&3_u16.to_be_bytes());
    bytes.extend_from_slice(&(scope.domain() as u16).to_be_bytes());
    bytes.extend_from_slice(&e.digest());
    bytes.extend_from_slice(&b.installation_id());
    bytes.extend_from_slice(&b.epoch().to_be_bytes());
    bytes.extend_from_slice(&e.store_binding(TpmStoreV3::Deployment).store_id());
    bytes.extend_from_slice(&(previous.sequence() + 1).to_be_bytes());
    bytes.extend_from_slice(&previous.digest());
    bytes.extend_from_slice(&scope.generation().to_be_bytes());
    bytes.extend_from_slice(&scope.transaction());
    bytes.extend_from_slice(&150_u64.to_be_bytes());
    bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    bytes.extend_from_slice(payload);
    let mut h = Sha256::new();
    h.update(b"savana.deployment-record.v3.unsigned\0");
    h.update(&bytes);
    let digest: [u8; 32] = h.finalize().into();
    let mut h = Sha256::new();
    h.update(b"savana.deployment-signature.v3\0");
    h.update(3_u16.to_be_bytes());
    h.update(2_u16.to_be_bytes());
    h.update((scope.domain() as u16).to_be_bytes());
    h.update(b.installation_id());
    h.update(b.epoch().to_be_bytes());
    h.update(b.public().key_id());
    h.update(digest);
    let key = p256::ecdsa::SigningKey::from_bytes((&[7; 32]).into()).unwrap();
    let sig: Signature = key.sign_prehash(&h.finalize()).unwrap();
    let sig = sig.normalize_s().unwrap_or(sig);
    bytes.extend_from_slice(b"SVS3");
    bytes.extend_from_slice(&2_u16.to_be_bytes());
    bytes.extend_from_slice(&(scope.domain() as u16).to_be_bytes());
    bytes.extend_from_slice(&b.installation_id());
    bytes.extend_from_slice(&b.epoch().to_be_bytes());
    bytes.extend_from_slice(&b.public().key_id());
    bytes.extend_from_slice(&digest);
    bytes.extend_from_slice(&sig.to_bytes());
    VerifiedDeploymentRecordEnvelopeV3::verify_for(&bytes, &e, scope, previous, 150).unwrap()
}
