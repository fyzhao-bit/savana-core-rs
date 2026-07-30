use std::fs;
use std::os::unix::fs::PermissionsExt as _;

use savana_kernel_protocol::v2::{Digest32V2, Nonce32V2};
use savana_policy_core::v2::{
    ClosedDeploymentFailureClassV2, DeploymentActivationVerifierV2, DeploymentControlErrorV2,
    DeploymentFailureEvidenceV2, DeploymentPhaseV2, DurableInstallationEvidenceStoreV2,
    InstallationEvidenceEnvelopeV2, NativeDeploymentSigningAuthorityV2,
    TestInstallationEvidenceCrashPointV2, TestNativeDeploymentSigningAuthorityV2,
};

fn digest(byte: u8) -> Digest32V2 {
    Digest32V2::new([byte; 32])
}

fn nonce(byte: u8) -> Nonce32V2 {
    Nonce32V2::new([byte; 32])
}

fn authority_and_verifier() -> (
    TestNativeDeploymentSigningAuthorityV2,
    DeploymentActivationVerifierV2,
) {
    let authority = TestNativeDeploymentSigningAuthorityV2::new_for_test(
        [0x41; 32], [0x31; 32], 17, [0x42; 32],
    )
    .unwrap();
    let verifier = DeploymentActivationVerifierV2::new(
        digest(0x31),
        savana_kernel_protocol::v2::Ed25519KeyIdV2::new(authority.key_id()),
        17,
        authority.public_key(),
    )
    .unwrap();
    (authority, verifier)
}

fn failure(detail: u8) -> DeploymentFailureEvidenceV2 {
    DeploymentFailureEvidenceV2::new(
        digest(0x31),
        17,
        nonce(0x71),
        digest(0x72),
        digest(0x73),
        DeploymentPhaseV2::Prepared,
        DeploymentPhaseV2::Armed,
        ClosedDeploymentFailureClassV2::NativeEffectFenceFailure,
        digest(detail),
        digest(0x75),
        1_784_000_000_100 + u64::from(detail),
    )
    .unwrap()
}

fn private_directory() -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    directory
}

#[test]
fn store_persists_reopens_and_authenticates_one_contiguous_chain() {
    let directory = private_directory();
    let (mut authority, verifier) = authority_and_verifier();
    let first = InstallationEvidenceEnvelopeV2::new_deployment_failure_signed_with_authority(
        1,
        None,
        &failure(0x81),
        &mut authority,
        &verifier,
    )
    .unwrap();
    let second = InstallationEvidenceEnvelopeV2::new_deployment_failure_signed_with_authority(
        2,
        Some(first.signed_digest()),
        &failure(0x82),
        &mut authority,
        &verifier,
    )
    .unwrap();

    let store =
        DurableInstallationEvidenceStoreV2::open_for_test(directory.path(), verifier.clone())
            .unwrap();
    assert_eq!(store.append(&first).unwrap(), first.signed_digest());
    assert_eq!(store.append(&first).unwrap(), first.signed_digest());
    assert_eq!(store.append(&second).unwrap(), second.signed_digest());
    drop(store);

    let reopened =
        DurableInstallationEvidenceStoreV2::open_for_test(directory.path(), verifier).unwrap();
    assert_eq!(
        reopened.load_signed_digest(first.signed_digest()).unwrap(),
        first
    );
    assert_eq!(reopened.load_latest().unwrap(), Some(second));
}

#[test]
fn store_rejects_sequence_gaps_wrong_predecessors_and_same_sequence_forks() {
    let directory = private_directory();
    let (mut authority, verifier) = authority_and_verifier();
    let first = InstallationEvidenceEnvelopeV2::new_deployment_failure_signed_with_authority(
        1,
        None,
        &failure(0x81),
        &mut authority,
        &verifier,
    )
    .unwrap();
    let gap = InstallationEvidenceEnvelopeV2::new_deployment_failure_signed_with_authority(
        3,
        Some(first.signed_digest()),
        &failure(0x82),
        &mut authority,
        &verifier,
    )
    .unwrap();
    let wrong_predecessor =
        InstallationEvidenceEnvelopeV2::new_deployment_failure_signed_with_authority(
            2,
            Some(digest(0xee)),
            &failure(0x83),
            &mut authority,
            &verifier,
        )
        .unwrap();
    let second = InstallationEvidenceEnvelopeV2::new_deployment_failure_signed_with_authority(
        2,
        Some(first.signed_digest()),
        &failure(0x84),
        &mut authority,
        &verifier,
    )
    .unwrap();
    let fork = InstallationEvidenceEnvelopeV2::new_deployment_failure_signed_with_authority(
        2,
        Some(first.signed_digest()),
        &failure(0x85),
        &mut authority,
        &verifier,
    )
    .unwrap();
    let store =
        DurableInstallationEvidenceStoreV2::open_for_test(directory.path(), verifier).unwrap();
    store.append(&first).unwrap();
    assert_eq!(
        store.append(&gap).unwrap_err(),
        DeploymentControlErrorV2::InvalidInstallationEvidenceEnvelope
    );
    assert_eq!(
        store.append(&wrong_predecessor).unwrap_err(),
        DeploymentControlErrorV2::InvalidInstallationEvidenceEnvelope
    );
    store.append(&second).unwrap();
    assert_eq!(
        store.append(&fork).unwrap_err(),
        DeploymentControlErrorV2::InvalidInstallationEvidenceEnvelope
    );
}

#[test]
fn store_fails_closed_on_unknown_or_tampered_directory_entries() {
    let directory = private_directory();
    let (mut authority, verifier) = authority_and_verifier();
    let first = InstallationEvidenceEnvelopeV2::new_deployment_failure_signed_with_authority(
        1,
        None,
        &failure(0x81),
        &mut authority,
        &verifier,
    )
    .unwrap();
    let store =
        DurableInstallationEvidenceStoreV2::open_for_test(directory.path(), verifier).unwrap();
    store.append(&first).unwrap();
    fs::write(directory.path().join("unregistered"), []).unwrap();
    fs::set_permissions(
        directory.path().join("unregistered"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    assert_eq!(
        store.load_latest().unwrap_err(),
        DeploymentControlErrorV2::InstallationEvidenceIo
    );
}

#[test]
fn every_evidence_publication_boundary_recovers_none_or_the_exact_envelope() {
    use TestInstallationEvidenceCrashPointV2 as Crash;

    for point in Crash::ALL {
        let directory = private_directory();
        let (mut authority, verifier) = authority_and_verifier();
        let envelope =
            InstallationEvidenceEnvelopeV2::new_deployment_failure_signed_with_authority(
                1,
                None,
                &failure(0x91),
                &mut authority,
                &verifier,
            )
            .unwrap();
        let store =
            DurableInstallationEvidenceStoreV2::open_for_test(directory.path(), verifier.clone())
                .unwrap();
        assert_eq!(
            store
                .append_with_crash_for_test(&envelope, point)
                .unwrap_err(),
            DeploymentControlErrorV2::InstallationEvidenceIo,
            "unexpected injected result at {point:?}"
        );
        drop(store);

        let reopened =
            DurableInstallationEvidenceStoreV2::open_for_test(directory.path(), verifier).unwrap();
        let expected_visible = point >= Crash::RenamedBeforeDirectoryFlush;
        assert_eq!(
            reopened.load_latest().unwrap(),
            expected_visible.then_some(envelope.clone()),
            "unexpected recovered evidence at {point:?}"
        );
        assert_eq!(
            reopened.append(&envelope).unwrap(),
            envelope.signed_digest(),
            "retry did not converge at {point:?}"
        );
        assert_eq!(reopened.load_latest().unwrap(), Some(envelope));
    }
}
