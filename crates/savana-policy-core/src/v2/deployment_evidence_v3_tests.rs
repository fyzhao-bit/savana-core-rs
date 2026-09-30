use super::super::deployment_v3_test_support::{enrollment_for, record, record_for};
use super::super::{ClosedTargetArchitectureV2 as Arch, ClosedTargetOsV2 as Os};
use super::*;
use savana_platform_identity::TpmStateHeadV3;

#[test]
fn approved_but_different_enrollments_cannot_be_spliced() {
    let v = verified();
    let c = commit(&v);
    let foreign = record_for(
        &c.canonical_bytes(),
        c.scope(),
        v.record.head(),
        enrollment_for([99; 32]),
    );
    assert!(VerifiedCommitAttestationV3::verify(foreign, c, &v).is_err());
}
fn d(n: u8) -> Digest32V2 {
    Digest32V2::new([n; 32])
}
fn artifact(kind: ClosedArtifactTypeV2) -> ArtifactIdentityV2 {
    ArtifactIdentityV2::new(kind, Os::Linux, Arch::Aarch64, 100, d(40), d(41), d(42)).unwrap()
}
fn verification() -> VerificationClaimsV3 {
    let mut digests = std::array::from_fn(|i| d(i as u8 + 2));
    digests[V::InstallationId as usize - 1] = d(1);
    VerificationClaimsV3::new(
        digests,
        1,
        Nonce32V2::new([3; 32]),
        4,
        5,
        150000,
        artifact(ClosedArtifactTypeV2::RootHelper),
        artifact(ClosedArtifactTypeV2::Watchdog),
    )
    .unwrap()
}
fn verified() -> VerifiedVerificationEvidenceV3 {
    let v = verification();
    let r = record(&v.canonical_bytes(), v.scope(), TpmStateHeadV3::GENESIS);
    VerifiedVerificationEvidenceV3::verify(r, v).unwrap()
}
fn commit(v: &VerifiedVerificationEvidenceV3) -> CommitClaimsV3 {
    let mut digests = [d(70); 16];
    for (c, k) in [
        (C::EvidenceTrustPolicy, V::EvidenceTrustPolicy),
        (C::EvidenceLayerLimits, V::EvidenceLayerLimits),
        (C::SourceEvidence, V::SourceEvidence),
        (C::ArtifactEvidence, V::ArtifactEvidence),
        (C::InstallationId, V::InstallationId),
        (C::TransactionIntent, V::TransactionIntent),
        (C::TransactionPayload, V::TransactionPayload),
        (C::CommittedManifest, V::InstalledManifest),
        (C::CommittedHighestEver, V::HighestEver),
        (C::RollbackGrant, V::RollbackGrant),
        (C::SourceLock, V::SourceLock),
        (C::ProtocolLock, V::ProtocolLock),
        (C::PlatformClosure, V::PlatformClosure),
    ] {
        digests[c as usize - 1] = v.claims.digest(k);
    }
    digests[C::VerificationEvidence as usize - 1] = v.record_digest();
    let p =
        PlatformLockV2::new(Os::Linux, Arch::Aarch64, d(71), d(72), d(73), d(74), d(75)).unwrap();
    CommitClaimsV3::new(digests, 1, p, v.claims.transaction, 6, 6, 150001).unwrap()
}
#[test]
fn v3_verification_and_commit_match_complete_expected_claims() {
    let v = verified();
    let c = commit(&v);
    let r = record(&c.canonical_bytes(), c.scope(), v.record.head());
    let done = VerifiedCommitAttestationV3::verify(r, c, &v).unwrap();
    assert_eq!(done.record().scope().domain(), Domain::CommitAttestation);
}
#[test]
fn every_verification_digest_is_checked_against_expected_material() {
    let v = verification();
    let r = record(&v.canonical_bytes(), v.scope(), TpmStateHeadV3::GENESIS);
    for i in 0..28 {
        let mut bad = v.clone();
        bad.digests[i] = d(99);
        assert!(VerifiedVerificationEvidenceV3::verify(r.clone(), bad).is_err());
    }
    let mut bad = v.clone();
    bad.fence += 1;
    assert!(VerifiedVerificationEvidenceV3::verify(r.clone(), bad).is_err());
    let bad_scope = DeploymentRecordScopeV3::new(Domain::CommitAttestation, 4, [3; 32]).unwrap();
    let wrong = record(&v.canonical_bytes(), bad_scope, TpmStateHeadV3::GENESIS);
    assert!(VerifiedVerificationEvidenceV3::verify(wrong, v).is_err());
}
#[test]
fn even_signed_commit_cannot_switch_verification_transaction_manifest_or_fence() {
    let v = verified();
    let c = commit(&v);
    for i in 0..16 {
        let r = record(&c.canonical_bytes(), c.scope(), v.record.head());
        let mut bad = c.clone();
        bad.digests[i] = d(99);
        assert!(VerifiedCommitAttestationV3::verify(r, bad, &v).is_err());
    }
    for mutation in 0..6 {
        let mut bad = c.clone();
        match mutation {
            0 => bad.digests[C::VerificationEvidence as usize - 1] = d(99),
            1 => bad.transaction = Nonce32V2::new([99; 32]),
            2 => bad.fence = 5,
            3 => bad.generation = 4,
            4 => bad.digests[C::CommittedManifest as usize - 1] = d(99),
            _ => bad.committed_at_ms = 149999,
        }
        let r = record(&bad.canonical_bytes(), bad.scope(), v.record.head());
        assert!(VerifiedCommitAttestationV3::verify(r, bad, &v).is_err());
    }
}
#[test]
fn roles_zero_fields_and_future_claim_time_fail_closed() {
    let v = verification();
    assert!(VerificationClaimsV3::new(
        v.digests,
        1,
        v.transaction,
        4,
        5,
        150000,
        v.watchdog.clone(),
        v.helper.clone()
    )
    .is_err());
    assert!(VerificationClaimsV3::new(
        [d(0); 28],
        1,
        v.transaction,
        4,
        5,
        150000,
        v.helper.clone(),
        v.watchdog.clone()
    )
    .is_err());
    let mut future = v.clone();
    future.verified_at_ms = 151000;
    let r = record(
        &future.canonical_bytes(),
        future.scope(),
        TpmStateHeadV3::GENESIS,
    );
    assert!(VerifiedVerificationEvidenceV3::verify(r, future).is_err());
}
