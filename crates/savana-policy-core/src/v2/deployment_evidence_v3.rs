//! Typed V3 evidence consumers. No V2 Ed25519 fields are reused as TPM fields.
//! Expected claims must come from the deployment driver and measured evidence,
//! never from a model or from the signed object itself. These are not boot permits.
use super::{
    ArtifactIdentityV2, ClosedArtifactTypeV2, ClosedCommitDigestFieldV2 as C,
    ClosedVerificationDigestFieldV2 as V, DeploymentControlErrorV2 as Error, PlatformLockV2,
};
use savana_kernel_protocol::v2::{Digest32V2, Nonce32V2};
use savana_platform_identity::{
    DeploymentRecordScopeV3, NativeDeploymentSignatureDomainV2 as Domain,
    VerifiedDeploymentRecordEnvelopeV3,
};

#[derive(Clone, PartialEq, Eq)]
pub struct VerificationClaimsV3 {
    digests: [Digest32V2; 28],
    epoch: u64,
    transaction: Nonce32V2,
    generation: u64,
    fence: u64,
    verified_at_ms: u64,
    helper: ArtifactIdentityV2,
    watchdog: ArtifactIdentityV2,
}
impl VerificationClaimsV3 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        digests: [Digest32V2; 28],
        epoch: u64,
        transaction: Nonce32V2,
        generation: u64,
        fence: u64,
        verified_at_ms: u64,
        helper: ArtifactIdentityV2,
        watchdog: ArtifactIdentityV2,
    ) -> Result<Self, Error> {
        if digests.iter().any(zero)
            || epoch == 0
            || transaction.as_bytes() == &[0; 32]
            || generation == 0
            || fence == 0
            || verified_at_ms == 0
            || helper.artifact_type() != ClosedArtifactTypeV2::RootHelper
            || watchdog.artifact_type() != ClosedArtifactTypeV2::Watchdog
            || helper.target_os() != watchdog.target_os()
            || helper.target_architecture() != watchdog.target_architecture()
        {
            return Err(Error::InvalidVerificationEvidence);
        }
        Ok(Self {
            digests,
            epoch,
            transaction,
            generation,
            fence,
            verified_at_ms,
            helper,
            watchdog,
        })
    }
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut b = b"SVEV3\0".to_vec();
        for d in &self.digests {
            b.extend_from_slice(d.as_bytes());
        }
        b.extend_from_slice(&self.epoch.to_be_bytes());
        b.extend_from_slice(self.transaction.as_bytes());
        for n in [self.generation, self.fence, self.verified_at_ms] {
            b.extend_from_slice(&n.to_be_bytes());
        }
        for identity in [&self.helper, &self.watchdog] {
            let bytes = identity.canonical_bytes();
            b.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
            b.extend_from_slice(bytes);
        }
        b
    }
    pub fn scope(&self) -> DeploymentRecordScopeV3 {
        DeploymentRecordScopeV3::new(
            Domain::VerificationEvidence,
            self.generation,
            *self.transaction.as_bytes(),
        )
        .expect("validated nonzero generation")
    }
    pub fn digest(&self, field: V) -> Digest32V2 {
        self.digests[field as usize - 1]
    }
}

/// Signature, complete expected claims, role identities and context were checked.
/// The caller still has to prove the claims came from the actual measurements.
pub struct VerifiedVerificationEvidenceV3 {
    record: VerifiedDeploymentRecordEnvelopeV3,
    claims: VerificationClaimsV3,
}
impl VerifiedVerificationEvidenceV3 {
    pub fn verify(
        record: VerifiedDeploymentRecordEnvelopeV3,
        expected: VerificationClaimsV3,
    ) -> Result<Self, Error> {
        if record.scope() != expected.scope()
            || record.installation_id() != *expected.digest(V::InstallationId).as_bytes()
            || record.installation_epoch() != expected.epoch
            || !timestamp_ok(expected.verified_at_ms, record.written_at())
            || record.authenticated_payload() != expected.canonical_bytes()
        {
            return Err(Error::InvalidVerificationEvidence);
        }
        Ok(Self {
            record,
            claims: expected,
        })
    }
    pub fn record_digest(&self) -> Digest32V2 {
        Digest32V2::new(self.record.head().digest())
    }
    pub fn claims(&self) -> &VerificationClaimsV3 {
        &self.claims
    }
    pub fn record(&self) -> &VerifiedDeploymentRecordEnvelopeV3 {
        &self.record
    }
    /// Bind actual installed-state bookkeeping, not just expected digest bytes.
    /// The installed candidate manifest is authenticated by the transaction core;
    /// it must not be confused with the still-active old manifest in this phase.
    pub fn validate_installed_ledger(
        &self,
        ledger: &super::VerifiedDeploymentLedgerRecordV3,
        intervening: &[VerifiedDeploymentRecordEnvelopeV3],
    ) -> Result<(), Error> {
        let m = ledger.state().material();
        let c = &self.claims;
        if m.phase != super::DeploymentPhaseV2::Installed
            || !m.effects_fenced
            || m.grant != super::RollbackGrantStateV2::Prearmed
            || m.installation != c.digest(V::InstallationId)
            || m.epoch != c.epoch
            || m.generation != c.generation
            || m.fence_epoch != c.fence
            || m.transaction != Some(c.transaction)
            || m.written_at_ms > c.verified_at_ms
            || m.identity_profile != c.digest(V::InstallIdentityProfile)
            || m.highest_ever.digest()? != c.digest(V::HighestEver)
        {
            return Err(Error::InvalidVerificationEvidence);
        }
        validate_evidence_ancestry(ledger.record(), &self.record, intervening)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct CommitClaimsV3 {
    digests: [Digest32V2; 16],
    epoch: u64,
    platform: PlatformLockV2,
    transaction: Nonce32V2,
    generation: u64,
    fence: u64,
    committed_at_ms: u64,
}
impl CommitClaimsV3 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        digests: [Digest32V2; 16],
        epoch: u64,
        platform: PlatformLockV2,
        transaction: Nonce32V2,
        generation: u64,
        fence: u64,
        committed_at_ms: u64,
    ) -> Result<Self, Error> {
        if digests.iter().any(zero)
            || epoch == 0
            || transaction.as_bytes() == &[0; 32]
            || generation == 0
            || fence == 0
            || committed_at_ms == 0
        {
            return Err(Error::InvalidCommitAttestation);
        }
        Ok(Self {
            digests,
            epoch,
            platform,
            transaction,
            generation,
            fence,
            committed_at_ms,
        })
    }
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut b = b"SCAV3\0".to_vec();
        for d in &self.digests {
            b.extend_from_slice(d.as_bytes());
        }
        b.extend_from_slice(&self.epoch.to_be_bytes());
        let p = self.platform.canonical_bytes();
        b.extend_from_slice(&(p.len() as u32).to_be_bytes());
        b.extend_from_slice(p);
        b.extend_from_slice(self.transaction.as_bytes());
        for n in [self.generation, self.fence, self.committed_at_ms] {
            b.extend_from_slice(&n.to_be_bytes());
        }
        // Closed terminal semantics: no effect fence, burned grant, normal activation.
        b.extend_from_slice(&[0, 4, 1]);
        b
    }
    pub fn scope(&self) -> DeploymentRecordScopeV3 {
        DeploymentRecordScopeV3::new(
            Domain::CommitAttestation,
            self.generation,
            *self.transaction.as_bytes(),
        )
        .expect("validated nonzero generation")
    }
    pub fn digest(&self, field: C) -> Digest32V2 {
        self.digests[field as usize - 1]
    }
    pub fn platform(&self) -> &PlatformLockV2 {
        &self.platform
    }
}
pub struct VerifiedCommitAttestationV3 {
    record: VerifiedDeploymentRecordEnvelopeV3,
    claims: CommitClaimsV3,
}
impl VerifiedCommitAttestationV3 {
    pub fn verify(
        record: VerifiedDeploymentRecordEnvelopeV3,
        expected: CommitClaimsV3,
        verified: &VerifiedVerificationEvidenceV3,
    ) -> Result<Self, Error> {
        let v = &verified.claims;
        if record.scope() != expected.scope()
            || record.installation_id() != *expected.digest(C::InstallationId).as_bytes()
            || record.installation_epoch() != expected.epoch
            || !timestamp_ok(expected.committed_at_ms, record.written_at())
            || record.authenticated_payload() != expected.canonical_bytes()
            || expected.digest(C::VerificationEvidence) != verified.record_digest()
            || expected.epoch != v.epoch
            || expected.transaction != v.transaction
            || expected.generation <= v.generation
            || v.fence.checked_add(1) != Some(expected.fence)
            || expected.committed_at_ms < v.verified_at_ms
            || record.head().sequence() <= verified.record.head().sequence()
            || record.enrollment_digest() != verified.record.enrollment_digest()
            || expected.platform.target_os() != v.helper.target_os()
            || expected.platform.target_architecture() != v.helper.target_architecture()
        {
            return Err(Error::InvalidCommitAttestation);
        }
        for (commit, verification) in [
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
            if expected.digest(commit) != v.digest(verification) {
                return Err(Error::InvalidCommitAttestation);
            }
        }
        Ok(Self {
            record,
            claims: expected,
        })
    }
    pub fn record(&self) -> &VerifiedDeploymentRecordEnvelopeV3 {
        &self.record
    }
    pub fn claims(&self) -> &CommitClaimsV3 {
        &self.claims
    }
    /// Match the actual committed ledger payload before using this attestation
    /// as one input to a higher-layer readiness decision. This does not boot.
    pub fn validate_committed_ledger(
        &self,
        ledger: &super::VerifiedDeploymentLedgerRecordV3,
        intervening: &[VerifiedDeploymentRecordEnvelopeV3],
    ) -> Result<(), Error> {
        let m = ledger.state().material();
        let c = &self.claims;
        if m.phase != super::DeploymentPhaseV2::Committed
            || m.effects_fenced
            || m.grant != super::RollbackGrantStateV2::Burned
            || m.active_activation != super::ActiveActivationV2::Normal
            || m.installation != c.digest(C::InstallationId)
            || m.epoch != c.epoch
            || m.generation != c.generation
            || m.fence_epoch != c.fence
            || m.transaction != Some(c.transaction)
            || m.written_at_ms != c.committed_at_ms
            || ledger.state().payload_digest() != c.digest(C::CommittedRecordPayload)
            || m.active_manifest != c.digest(C::CommittedManifest)
            || m.highest_ever.digest()? != c.digest(C::CommittedHighestEver)
        {
            return Err(Error::InvalidCommitAttestation);
        }
        validate_evidence_ancestry(ledger.record(), &self.record, intervening)
    }
}
fn validate_evidence_ancestry(
    ledger: &VerifiedDeploymentRecordEnvelopeV3,
    evidence: &VerifiedDeploymentRecordEnvelopeV3,
    intervening: &[VerifiedDeploymentRecordEnvelopeV3],
) -> Result<(), Error> {
    if intervening.len() > 64 {
        return Err(Error::LedgerConflict);
    }
    let mut head = ledger.head();
    let mut time = ledger.written_at();
    for r in intervening.iter().chain(std::iter::once(evidence)) {
        if r.scope().domain() == Domain::LedgerActivation
            || r.previous_head() != head
            || r.enrollment_digest() != ledger.enrollment_digest()
            || r.written_at() < time
            || r.scope().generation() != ledger.scope().generation()
            || r.scope().transaction() != ledger.scope().transaction()
        {
            return Err(Error::LedgerConflict);
        }
        head = r.head();
        time = r.written_at();
    }
    Ok(())
}
fn zero(d: &Digest32V2) -> bool {
    d.as_bytes() == &[0; 32]
}
fn timestamp_ok(ms: u64, seconds: u64) -> bool {
    seconds
        .checked_mul(1000)
        .and_then(|v| v.checked_add(999))
        .is_some_and(|end| ms <= end)
}

#[cfg(test)]
#[path = "deployment_evidence_v3_tests.rs"]
mod tests;
