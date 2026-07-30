use savana_kernel_protocol::v2::{Digest32V2, Ed25519KeyIdV2, Ed25519SignatureV2, Nonce32V2};
use savana_platform_identity::{
    NativeDeploymentSignatureDomainV2, NativeDeploymentSignatureRequestV2,
    NativeDeploymentSigningAuthorityV2,
};
use sha2::{Digest as _, Sha256};

#[cfg(any(test, feature = "test-support"))]
use ed25519_dalek::{Signer as _, SigningKey};
#[cfg(any(test, feature = "test-support"))]
use savana_kernel_protocol::v2::derive_ed25519_key_id_v2;

use super::{
    DeploymentActivationVerifierV2, DeploymentBranchV2, DeploymentControlErrorV2,
    DeploymentLedgerRecordV2, DeploymentOwnerClaimV2, DeploymentOwnerRoleV2, DeploymentPhaseV2,
    DeploymentTransitionV2,
};

const DURABLE_HEAD_SCHEMA_VERSION_V2: u16 = 2;
const DURABLE_HEAD_COMPLETE_FIELDS_V2: u64 = 3;
const DURABLE_HEAD_PAYLOAD_FIELDS_V2: u64 = 15;
const DURABLE_OWNER_FIELDS_V2: u64 = 9;
const DURABLE_EVIDENCE_FIELDS_V2: u64 = 2;
const DOMAIN_SIGNATURE_FIELDS_V2: u64 = 4;
const DURABLE_HEAD_SIGNATURE_TAG_V2: u16 = 26;
const MAX_DURABLE_HEAD_BYTES_V2: usize = 1024 * 1024;
const MAX_DURABLE_STEPS_V2: usize = 25;
const MAX_DURABLE_EVIDENCE_REFS_V2: usize = 4096;
const DURABLE_HEAD_PAYLOAD_DOMAIN_V2: &[u8] = b"savana.durable-deployment-record.v2.payload\0";
const DURABLE_HEAD_SIGNED_DOMAIN_V2: &[u8] = b"savana.durable-deployment-record.v2.signed\0";
const DURABLE_HEAD_SIGNATURE_DOMAIN_V2: &[u8] = b"savana.durable-deployment-record.v2.signature\0";
#[cfg(any(test, feature = "test-support"))]
const DOMAIN_SIGNATURE_INPUT_V2: &[u8] = b"savana.domain-signature.v2\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u16)]
pub enum ClosedDurableDeploymentStepV2 {
    TransactionAuthenticated = 1,
    StagingTreeVerified = 2,
    DesiredManifestVerified = 3,
    RecoveryTargetVerified = 4,
    PlansVerified = 5,
    StoreCompatibilityVerified = 6,
    GrantPrearmed = 7,
    ExclusiveEffectGateAcquired = 8,
    OsEffectDenyInstalled = 9,
    EffectWorkSetFrozen = 10,
    ArmedTransitionReady = 11,
    RoleJournalsReconciled = 12,
    ServicesQuiesced = 13,
    DesiredArtifactsInstalled = 14,
    CandidateVerified = 15,
    GrantBurnReady = 16,
    CommitTransitionReady = 17,
    RollbackGrantConsumeReady = 18,
    RollbackArtifactsInstalled = 19,
    RollbackReadinessVerified = 20,
    RollbackTransitionReady = 21,
    BridgeRestoreGrantConsumeReady = 22,
    BridgeClosureRestored = 23,
    BridgeRestoreIntegrityVerified = 24,
    BridgeRestoreTransitionReady = 25,
}

impl ClosedDurableDeploymentStepV2 {
    const fn from_tag(tag: u16) -> Option<Self> {
        match tag {
            1 => Some(Self::TransactionAuthenticated),
            2 => Some(Self::StagingTreeVerified),
            3 => Some(Self::DesiredManifestVerified),
            4 => Some(Self::RecoveryTargetVerified),
            5 => Some(Self::PlansVerified),
            6 => Some(Self::StoreCompatibilityVerified),
            7 => Some(Self::GrantPrearmed),
            8 => Some(Self::ExclusiveEffectGateAcquired),
            9 => Some(Self::OsEffectDenyInstalled),
            10 => Some(Self::EffectWorkSetFrozen),
            11 => Some(Self::ArmedTransitionReady),
            12 => Some(Self::RoleJournalsReconciled),
            13 => Some(Self::ServicesQuiesced),
            14 => Some(Self::DesiredArtifactsInstalled),
            15 => Some(Self::CandidateVerified),
            16 => Some(Self::GrantBurnReady),
            17 => Some(Self::CommitTransitionReady),
            18 => Some(Self::RollbackGrantConsumeReady),
            19 => Some(Self::RollbackArtifactsInstalled),
            20 => Some(Self::RollbackReadinessVerified),
            21 => Some(Self::RollbackTransitionReady),
            22 => Some(Self::BridgeRestoreGrantConsumeReady),
            23 => Some(Self::BridgeClosureRestored),
            24 => Some(Self::BridgeRestoreIntegrityVerified),
            25 => Some(Self::BridgeRestoreTransitionReady),
            _ => None,
        }
    }

    const fn tag(self) -> u16 {
        self as u16
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DurableDeploymentEvidenceRefV2 {
    StoreCompatibility(Digest32V2),
    NativeControlMeasurementSet(Digest32V2),
    FrozenEffectWorkSet(Digest32V2),
    RoleJournalReconciliation(Digest32V2),
    VerificationEvidence(Digest32V2),
    RollbackVerificationEvidence(Digest32V2),
    RecoveryRollbackReadinessEvidence(Digest32V2),
    BootstrapBridgeRestoreIntegrity(Digest32V2),
    DeploymentFailure(Digest32V2),
}

impl DurableDeploymentEvidenceRefV2 {
    const fn from_tag(tag: u16, digest: Digest32V2) -> Option<Self> {
        match tag {
            1 => Some(Self::StoreCompatibility(digest)),
            2 => Some(Self::NativeControlMeasurementSet(digest)),
            3 => Some(Self::FrozenEffectWorkSet(digest)),
            4 => Some(Self::RoleJournalReconciliation(digest)),
            5 => Some(Self::VerificationEvidence(digest)),
            6 => Some(Self::RollbackVerificationEvidence(digest)),
            7 => Some(Self::RecoveryRollbackReadinessEvidence(digest)),
            8 => Some(Self::BootstrapBridgeRestoreIntegrity(digest)),
            9 => Some(Self::DeploymentFailure(digest)),
            _ => None,
        }
    }

    pub const fn tag(self) -> u16 {
        match self {
            Self::StoreCompatibility(_) => 1,
            Self::NativeControlMeasurementSet(_) => 2,
            Self::FrozenEffectWorkSet(_) => 3,
            Self::RoleJournalReconciliation(_) => 4,
            Self::VerificationEvidence(_) => 5,
            Self::RollbackVerificationEvidence(_) => 6,
            Self::RecoveryRollbackReadinessEvidence(_) => 7,
            Self::BootstrapBridgeRestoreIntegrity(_) => 8,
            Self::DeploymentFailure(_) => 9,
        }
    }

    pub const fn digest(self) -> Digest32V2 {
        match self {
            Self::StoreCompatibility(value)
            | Self::NativeControlMeasurementSet(value)
            | Self::FrozenEffectWorkSet(value)
            | Self::RoleJournalReconciliation(value)
            | Self::VerificationEvidence(value)
            | Self::RollbackVerificationEvidence(value)
            | Self::RecoveryRollbackReadinessEvidence(value)
            | Self::BootstrapBridgeRestoreIntegrity(value)
            | Self::DeploymentFailure(value) => value,
        }
    }

    fn sort_key(self) -> (u16, [u8; 32]) {
        (self.tag(), *self.digest().as_bytes())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DurableHeadSignatureV2 {
    domain_tag: u16,
    signer_key_id: Ed25519KeyIdV2,
    signer_key_epoch: u64,
    signature: Ed25519SignatureV2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DecodedDurableDeploymentTransactionRecordV2 {
    schema_version: u16,
    installation_id: Digest32V2,
    installation_epoch: u64,
    transaction_id: Nonce32V2,
    core_signed_digest: Digest32V2,
    head_sequence: u64,
    previous_head_digest: Option<Digest32V2>,
    expected_previous_ledger_record_digest: Digest32V2,
    expected_previous_ledger_generation: u64,
    target_phase: DeploymentPhaseV2,
    completed_steps: Vec<ClosedDurableDeploymentStepV2>,
    evidence_refs: Vec<DurableDeploymentEvidenceRefV2>,
    owner: DeploymentOwnerClaimV2,
    watchdog_deadline_monotonic_ns: u64,
    written_at_unix_ms: u64,
    payload_digest: Digest32V2,
    activation_signature: DurableHeadSignatureV2,
}

impl DecodedDurableDeploymentTransactionRecordV2 {
    fn validate_shape(&self) -> Result<(), DeploymentControlErrorV2> {
        if self.schema_version != DURABLE_HEAD_SCHEMA_VERSION_V2
            || self.installation_epoch == 0
            || self.head_sequence == 0
            || self.expected_previous_ledger_generation == 0
            || self.watchdog_deadline_monotonic_ns == 0
            || self.written_at_unix_ms == 0
            || is_zero(self.installation_id.as_bytes())
            || is_zero(self.transaction_id.as_bytes())
            || is_zero(self.core_signed_digest.as_bytes())
            || is_zero(self.expected_previous_ledger_record_digest.as_bytes())
            || is_zero(self.payload_digest.as_bytes())
            || is_zero(self.activation_signature.signature.as_bytes())
            || self.owner.transaction_id() != self.transaction_id
            || self.owner.heartbeat_deadline_monotonic_ns() > self.watchdog_deadline_monotonic_ns
            || (self.head_sequence == 1) != self.previous_head_digest.is_none()
            || self.previous_head_digest.is_some_and(|value| {
                is_zero(value.as_bytes()) || self.head_sequence.checked_sub(1).is_none()
            })
        {
            return Err(DeploymentControlErrorV2::InvalidDurableDeploymentHead);
        }
        validate_steps(&self.completed_steps, self.target_phase)?;
        if self.head_sequence == 1 && self.target_phase != DeploymentPhaseV2::Prepared {
            return Err(DeploymentControlErrorV2::InvalidDurableDeploymentHead);
        }
        validate_evidence(
            &self.evidence_refs,
            &self.completed_steps,
            self.target_phase,
        )?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableDeploymentTransactionRecordV2 {
    canonical_bytes: Vec<u8>,
    signed_digest: Digest32V2,
    installation_id: Digest32V2,
    installation_epoch: u64,
    transaction_id: Nonce32V2,
    core_signed_digest: Digest32V2,
    head_sequence: u64,
    previous_head_digest: Option<Digest32V2>,
    expected_previous_ledger_record_digest: Digest32V2,
    expected_previous_ledger_generation: u64,
    target_phase: DeploymentPhaseV2,
    completed_steps: Vec<ClosedDurableDeploymentStepV2>,
    evidence_refs: Vec<DurableDeploymentEvidenceRefV2>,
    owner: DeploymentOwnerClaimV2,
    watchdog_deadline_monotonic_ns: u64,
    written_at_unix_ms: u64,
}

impl DurableDeploymentTransactionRecordV2 {
    pub fn from_canonical_bytes(
        bytes: &[u8],
        verifier: &DeploymentActivationVerifierV2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        if bytes.is_empty() || bytes.len() > MAX_DURABLE_HEAD_BYTES_V2 {
            return Err(DeploymentControlErrorV2::InvalidDurableDeploymentHead);
        }
        let decoded = decode_complete_record(bytes)?;
        decoded.validate_shape()?;
        if encode_complete_record(&decoded)? != bytes {
            return Err(DeploymentControlErrorV2::NonCanonicalLedgerEncoding);
        }
        if decoded.installation_id != verifier.installation_id()
            || decoded.installation_epoch != verifier.key_epoch()
        {
            return Err(DeploymentControlErrorV2::InstallationTupleMismatch);
        }
        if decoded.activation_signature.signer_key_id != verifier.key_id() {
            return Err(DeploymentControlErrorV2::ActivationKeyMismatch);
        }
        let expected_payload_digest =
            hash_domain(DURABLE_HEAD_PAYLOAD_DOMAIN_V2, &encode_payload(&decoded)?);
        if decoded.payload_digest != expected_payload_digest {
            return Err(DeploymentControlErrorV2::LedgerPayloadDigestMismatch);
        }
        verifier.verify_domain_signature_parts(
            decoded.activation_signature.domain_tag,
            decoded.activation_signature.signer_key_id,
            decoded.activation_signature.signer_key_epoch,
            decoded.activation_signature.signature,
            DURABLE_HEAD_SIGNATURE_TAG_V2,
            DURABLE_HEAD_SIGNATURE_DOMAIN_V2,
            expected_payload_digest,
        )?;
        Ok(Self {
            canonical_bytes: bytes.to_vec(),
            signed_digest: hash_domain(DURABLE_HEAD_SIGNED_DOMAIN_V2, bytes),
            installation_id: decoded.installation_id,
            installation_epoch: decoded.installation_epoch,
            transaction_id: decoded.transaction_id,
            core_signed_digest: decoded.core_signed_digest,
            head_sequence: decoded.head_sequence,
            previous_head_digest: decoded.previous_head_digest,
            expected_previous_ledger_record_digest: decoded.expected_previous_ledger_record_digest,
            expected_previous_ledger_generation: decoded.expected_previous_ledger_generation,
            target_phase: decoded.target_phase,
            completed_steps: decoded.completed_steps,
            evidence_refs: decoded.evidence_refs,
            owner: decoded.owner,
            watchdog_deadline_monotonic_ns: decoded.watchdog_deadline_monotonic_ns,
            written_at_unix_ms: decoded.written_at_unix_ms,
        })
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub const fn signed_digest(&self) -> Digest32V2 {
        self.signed_digest
    }

    pub const fn installation_id(&self) -> Digest32V2 {
        self.installation_id
    }

    pub const fn installation_epoch(&self) -> u64 {
        self.installation_epoch
    }

    pub const fn core_signed_digest(&self) -> Digest32V2 {
        self.core_signed_digest
    }

    pub const fn head_sequence(&self) -> u64 {
        self.head_sequence
    }

    pub const fn transaction_id(&self) -> Nonce32V2 {
        self.transaction_id
    }

    pub const fn previous_head_digest(&self) -> Option<Digest32V2> {
        self.previous_head_digest
    }

    pub const fn target_phase(&self) -> DeploymentPhaseV2 {
        self.target_phase
    }

    pub const fn expected_previous_ledger_record_digest(&self) -> Digest32V2 {
        self.expected_previous_ledger_record_digest
    }

    pub const fn expected_previous_ledger_generation(&self) -> u64 {
        self.expected_previous_ledger_generation
    }

    pub const fn owner(&self) -> DeploymentOwnerClaimV2 {
        self.owner
    }

    pub fn completed_steps(&self) -> &[ClosedDurableDeploymentStepV2] {
        &self.completed_steps
    }

    pub fn evidence_refs(&self) -> &[DurableDeploymentEvidenceRefV2] {
        &self.evidence_refs
    }

    pub const fn written_at_unix_ms(&self) -> u64 {
        self.written_at_unix_ms
    }

    pub fn validate_expected_previous_ledger(
        &self,
        ledger: &DeploymentLedgerRecordV2,
    ) -> Result<(), DeploymentControlErrorV2> {
        let projection = ledger.projection();
        if projection.installation_id() != self.installation_id
            || projection.installation_epoch() != self.installation_epoch
            || projection.generation() != self.expected_previous_ledger_generation
            || ledger.signed_record_digest() != self.expected_previous_ledger_record_digest
        {
            return Err(DeploymentControlErrorV2::TransactionBindingMismatch);
        }
        Ok(())
    }

    pub fn validate_successor(
        &self,
        successor: &Self,
        branch: DeploymentBranchV2,
    ) -> Result<(), DeploymentControlErrorV2> {
        if successor.installation_id != self.installation_id
            || successor.installation_epoch != self.installation_epoch
            || successor.transaction_id != self.transaction_id
            || successor.core_signed_digest != self.core_signed_digest
            || successor.head_sequence
                != self
                    .head_sequence
                    .checked_add(1)
                    .ok_or(DeploymentControlErrorV2::InvalidDurableDeploymentHead)?
            || successor.previous_head_digest != Some(self.signed_digest)
            || successor.expected_previous_ledger_generation
                != self
                    .expected_previous_ledger_generation
                    .checked_add(1)
                    .ok_or(DeploymentControlErrorV2::InvalidDurableDeploymentHead)?
            || successor.written_at_unix_ms < self.written_at_unix_ms
            || successor.watchdog_deadline_monotonic_ns < self.watchdog_deadline_monotonic_ns
        {
            return Err(DeploymentControlErrorV2::TransactionBindingMismatch);
        }
        DeploymentTransitionV2::new(branch, self.target_phase, successor.target_phase)?;
        validate_branch(successor, branch)?;
        if !successor.completed_steps.starts_with(&self.completed_steps) {
            return Err(DeploymentControlErrorV2::DurableHeadPrefixMismatch);
        }
        if self.evidence_refs.iter().any(|current| {
            successor
                .evidence_refs
                .binary_search_by_key(&current.sort_key(), |evidence| evidence.sort_key())
                .is_err()
        }) {
            return Err(DeploymentControlErrorV2::DurableHeadEvidenceMismatch);
        }
        validate_owner_successor(self.owner, successor.owner)?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_signed_with_authority(
        installation_id: Digest32V2,
        installation_epoch: u64,
        transaction_id: Nonce32V2,
        core_signed_digest: Digest32V2,
        head_sequence: u64,
        previous_head_digest: Option<Digest32V2>,
        expected_previous_ledger_record_digest: Digest32V2,
        expected_previous_ledger_generation: u64,
        target_phase: DeploymentPhaseV2,
        completed_steps: Vec<ClosedDurableDeploymentStepV2>,
        evidence_refs: Vec<DurableDeploymentEvidenceRefV2>,
        owner: DeploymentOwnerClaimV2,
        watchdog_deadline_monotonic_ns: u64,
        written_at_unix_ms: u64,
        authority: &mut dyn NativeDeploymentSigningAuthorityV2,
        verifier: &DeploymentActivationVerifierV2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        let signer_key_id = Ed25519KeyIdV2::new(authority.key_id());
        if authority.installation_id() != *installation_id.as_bytes()
            || authority.key_epoch() != installation_epoch
            || verifier.installation_id() != installation_id
            || verifier.key_epoch() != installation_epoch
            || verifier.key_id() != signer_key_id
        {
            return Err(DeploymentControlErrorV2::ActivationKeyMismatch);
        }
        let mut decoded = DecodedDurableDeploymentTransactionRecordV2 {
            schema_version: DURABLE_HEAD_SCHEMA_VERSION_V2,
            installation_id,
            installation_epoch,
            transaction_id,
            core_signed_digest,
            head_sequence,
            previous_head_digest,
            expected_previous_ledger_record_digest,
            expected_previous_ledger_generation,
            target_phase,
            completed_steps,
            evidence_refs,
            owner,
            watchdog_deadline_monotonic_ns,
            written_at_unix_ms,
            payload_digest: Digest32V2::new([1; 32]),
            activation_signature: DurableHeadSignatureV2 {
                domain_tag: DURABLE_HEAD_SIGNATURE_TAG_V2,
                signer_key_id,
                signer_key_epoch: installation_epoch,
                signature: Ed25519SignatureV2::new([1; 64]),
            },
        };
        decoded.validate_shape()?;
        decoded.payload_digest =
            hash_domain(DURABLE_HEAD_PAYLOAD_DOMAIN_V2, &encode_payload(&decoded)?);
        let request = NativeDeploymentSignatureRequestV2::new(
            NativeDeploymentSignatureDomainV2::DurableDeploymentTransactionRecord,
            *installation_id.as_bytes(),
            installation_epoch,
            *decoded.payload_digest.as_bytes(),
        )
        .map_err(|_| DeploymentControlErrorV2::NativeSigningAuthorityUnavailable)?;
        decoded.activation_signature.signature = Ed25519SignatureV2::new(
            authority
                .sign(request)
                .map_err(|_| DeploymentControlErrorV2::NativeSigningAuthorityUnavailable)?,
        );
        Self::from_canonical_bytes(&encode_complete_record(&decoded)?, verifier)
    }

    #[cfg(any(test, feature = "test-support"))]
    #[allow(clippy::too_many_arguments)]
    pub fn new_signed_for_test(
        installation_id: Digest32V2,
        installation_epoch: u64,
        transaction_id: Nonce32V2,
        core_signed_digest: Digest32V2,
        head_sequence: u64,
        previous_head_digest: Option<Digest32V2>,
        expected_previous_ledger_record_digest: Digest32V2,
        expected_previous_ledger_generation: u64,
        target_phase: DeploymentPhaseV2,
        completed_steps: Vec<ClosedDurableDeploymentStepV2>,
        evidence_refs: Vec<DurableDeploymentEvidenceRefV2>,
        owner: DeploymentOwnerClaimV2,
        watchdog_deadline_monotonic_ns: u64,
        written_at_unix_ms: u64,
        signing_key: &SigningKey,
    ) -> Result<Self, DeploymentControlErrorV2> {
        let mut decoded = DecodedDurableDeploymentTransactionRecordV2 {
            schema_version: DURABLE_HEAD_SCHEMA_VERSION_V2,
            installation_id,
            installation_epoch,
            transaction_id,
            core_signed_digest,
            head_sequence,
            previous_head_digest,
            expected_previous_ledger_record_digest,
            expected_previous_ledger_generation,
            target_phase,
            completed_steps,
            evidence_refs,
            owner,
            watchdog_deadline_monotonic_ns,
            written_at_unix_ms,
            payload_digest: Digest32V2::new([1; 32]),
            activation_signature: DurableHeadSignatureV2 {
                domain_tag: DURABLE_HEAD_SIGNATURE_TAG_V2,
                signer_key_id: derive_ed25519_key_id_v2(signing_key.verifying_key().to_bytes()),
                signer_key_epoch: installation_epoch,
                signature: Ed25519SignatureV2::new([1; 64]),
            },
        };
        decoded.validate_shape()?;
        decoded.payload_digest =
            hash_domain(DURABLE_HEAD_PAYLOAD_DOMAIN_V2, &encode_payload(&decoded)?);
        decoded.activation_signature.signature = Ed25519SignatureV2::new(
            signing_key
                .sign(&domain_signature_input(
                    DURABLE_HEAD_SIGNATURE_TAG_V2,
                    DURABLE_HEAD_SIGNATURE_DOMAIN_V2,
                    decoded.payload_digest,
                ))
                .to_bytes(),
        );
        let verifier = DeploymentActivationVerifierV2::new(
            installation_id,
            decoded.activation_signature.signer_key_id,
            installation_epoch,
            signing_key.verifying_key().to_bytes(),
        )?;
        Self::from_canonical_bytes(&encode_complete_record(&decoded)?, &verifier)
    }
}

fn validate_steps(
    steps: &[ClosedDurableDeploymentStepV2],
    target_phase: DeploymentPhaseV2,
) -> Result<(), DeploymentControlErrorV2> {
    if steps.is_empty()
        || steps.len() > MAX_DURABLE_STEPS_V2
        || steps.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(DeploymentControlErrorV2::InvalidDurableDeploymentHead);
    }
    let common_length = steps.iter().take_while(|step| step.tag() <= 17).count();
    if common_length == 0
        || steps[..common_length]
            .iter()
            .enumerate()
            .any(|(index, step)| step.tag() != u16::try_from(index).unwrap_or(u16::MAX) + 1)
    {
        return Err(DeploymentControlErrorV2::InvalidDurableDeploymentHead);
    }
    let suffix = &steps[common_length..];
    let common_is_recovery_source = matches!(common_length, 11 | 13 | 14 | 15);
    let valid = match target_phase {
        DeploymentPhaseV2::Idle => false,
        DeploymentPhaseV2::Prepared | DeploymentPhaseV2::Aborted => {
            common_length == 7 && suffix.is_empty()
        }
        DeploymentPhaseV2::Armed => common_length == 11 && suffix.is_empty(),
        DeploymentPhaseV2::Quiesced => common_length == 13 && suffix.is_empty(),
        DeploymentPhaseV2::Installed => common_length == 14 && suffix.is_empty(),
        DeploymentPhaseV2::Verified => common_length == 15 && suffix.is_empty(),
        DeploymentPhaseV2::Committed => common_length == 17 && suffix.is_empty(),
        DeploymentPhaseV2::RollbackPrepared => {
            common_is_recovery_source && exact_step_suffix(suffix, 18, 18)
        }
        DeploymentPhaseV2::RollbackInstalled => {
            common_is_recovery_source && exact_step_suffix(suffix, 18, 19)
        }
        DeploymentPhaseV2::RollbackVerified => {
            common_is_recovery_source && exact_step_suffix(suffix, 18, 20)
        }
        DeploymentPhaseV2::RolledBack => {
            common_is_recovery_source && exact_step_suffix(suffix, 18, 21)
        }
        DeploymentPhaseV2::BridgeRestorePrepared => {
            common_is_recovery_source && exact_step_suffix(suffix, 22, 22)
        }
        DeploymentPhaseV2::BridgeRestoreInstalled => {
            common_is_recovery_source && exact_step_suffix(suffix, 22, 23)
        }
        DeploymentPhaseV2::BridgeRestoreVerified => {
            common_is_recovery_source && exact_step_suffix(suffix, 22, 24)
        }
        DeploymentPhaseV2::BootstrapBridge => {
            (common_length == 7 && suffix.is_empty())
                || (common_is_recovery_source && exact_step_suffix(suffix, 22, 25))
        }
        DeploymentPhaseV2::FailedSafe => {
            matches!(common_length, 7 | 11 | 13 | 14 | 15)
                && (suffix.is_empty()
                    || exact_step_suffix(suffix, 18, 18)
                    || exact_step_suffix(suffix, 18, 19)
                    || exact_step_suffix(suffix, 18, 20)
                    || exact_step_suffix(suffix, 22, 22)
                    || exact_step_suffix(suffix, 22, 23)
                    || exact_step_suffix(suffix, 22, 24))
        }
    };
    if !valid {
        return Err(DeploymentControlErrorV2::InvalidDurableDeploymentHead);
    }
    Ok(())
}

fn exact_step_suffix(suffix: &[ClosedDurableDeploymentStepV2], first: u16, last: u16) -> bool {
    suffix.len() == usize::from(last - first + 1)
        && suffix
            .iter()
            .enumerate()
            .all(|(index, step)| step.tag() == first + u16::try_from(index).unwrap_or(u16::MAX))
}

fn validate_evidence(
    evidence_refs: &[DurableDeploymentEvidenceRefV2],
    steps: &[ClosedDurableDeploymentStepV2],
    target_phase: DeploymentPhaseV2,
) -> Result<(), DeploymentControlErrorV2> {
    if evidence_refs.len() > MAX_DURABLE_EVIDENCE_REFS_V2
        || evidence_refs
            .iter()
            .any(|evidence| is_zero(evidence.digest().as_bytes()))
        || evidence_refs
            .windows(2)
            .any(|pair| pair[0].sort_key() >= pair[1].sort_key())
    {
        return Err(DeploymentControlErrorV2::InvalidDurableDeploymentHead);
    }
    let has_step = |step| steps.contains(&step);
    let has_tag = |tag| evidence_refs.iter().any(|evidence| evidence.tag() == tag);
    for (step, tag) in [
        (ClosedDurableDeploymentStepV2::StoreCompatibilityVerified, 1),
        (ClosedDurableDeploymentStepV2::OsEffectDenyInstalled, 2),
        (ClosedDurableDeploymentStepV2::EffectWorkSetFrozen, 3),
        (ClosedDurableDeploymentStepV2::RoleJournalsReconciled, 4),
        (ClosedDurableDeploymentStepV2::CandidateVerified, 5),
        (
            ClosedDurableDeploymentStepV2::BridgeRestoreIntegrityVerified,
            8,
        ),
    ] {
        if has_step(step) != has_tag(tag) {
            return Err(DeploymentControlErrorV2::InvalidDurableDeploymentHead);
        }
    }
    let rollback_evidence_count = evidence_refs
        .iter()
        .filter(|evidence| matches!(evidence.tag(), 6 | 7))
        .count();
    if (has_step(ClosedDurableDeploymentStepV2::RollbackReadinessVerified)
        && rollback_evidence_count != 1)
        || (!has_step(ClosedDurableDeploymentStepV2::RollbackReadinessVerified)
            && rollback_evidence_count != 0)
    {
        return Err(DeploymentControlErrorV2::InvalidDurableDeploymentHead);
    }
    let failure_evidence_count = evidence_refs
        .iter()
        .filter(|evidence| evidence.tag() == 9)
        .count();
    if (target_phase == DeploymentPhaseV2::FailedSafe) != (failure_evidence_count == 1) {
        return Err(DeploymentControlErrorV2::InvalidDurableDeploymentHead);
    }
    Ok(())
}

fn validate_branch(
    successor: &DurableDeploymentTransactionRecordV2,
    branch: DeploymentBranchV2,
) -> Result<(), DeploymentControlErrorV2> {
    let has_step_in = |range: core::ops::RangeInclusive<u16>| {
        successor
            .completed_steps
            .iter()
            .any(|step| range.contains(&step.tag()))
    };
    match branch {
        DeploymentBranchV2::Normal => {
            if has_step_in(22..=25)
                || successor
                    .evidence_refs
                    .iter()
                    .any(|evidence| evidence.tag() == 8)
            {
                return Err(DeploymentControlErrorV2::InvalidDurableDeploymentHead);
            }
        }
        DeploymentBranchV2::BootstrapBridgeRestore => {
            if has_step_in(18..=21)
                || successor
                    .evidence_refs
                    .iter()
                    .any(|evidence| matches!(evidence.tag(), 6 | 7))
            {
                return Err(DeploymentControlErrorV2::InvalidDurableDeploymentHead);
            }
        }
    }
    Ok(())
}

fn validate_owner_successor(
    current: DeploymentOwnerClaimV2,
    successor: DeploymentOwnerClaimV2,
) -> Result<(), DeploymentControlErrorV2> {
    if current == successor {
        return Ok(());
    }
    if successor.transaction_id() != current.transaction_id()
        || successor.heartbeat_generation()
            != current
                .heartbeat_generation()
                .checked_add(1)
                .ok_or(DeploymentControlErrorV2::OwnerGenerationOverflow)?
        || successor.heartbeat_deadline_monotonic_ns() <= current.heartbeat_deadline_monotonic_ns()
    {
        return Err(DeploymentControlErrorV2::DurableHeadOwnerMismatch);
    }
    match (current.owner_role(), successor.owner_role()) {
        (DeploymentOwnerRoleV2::Helper, DeploymentOwnerRoleV2::Watchdog) => Ok(()),
        (current_role, successor_role) if current_role == successor_role => {
            if successor.identity() != current.identity()
                || successor.operation_nonce() != current.operation_nonce()
            {
                return Err(DeploymentControlErrorV2::DurableHeadOwnerMismatch);
            }
            Ok(())
        }
        _ => Err(DeploymentControlErrorV2::DurableHeadOwnerMismatch),
    }
}

fn encode_complete_record(
    value: &DecodedDurableDeploymentTransactionRecordV2,
) -> Result<Vec<u8>, DeploymentControlErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(DURABLE_HEAD_COMPLETE_FIELDS_V2)
        .map_err(|_| DeploymentControlErrorV2::InvalidDurableDeploymentHead)?;
    encode_payload_into(&mut encoder, value)?;
    encoder
        .bytes(value.payload_digest.as_bytes())
        .map_err(|_| DeploymentControlErrorV2::InvalidDurableDeploymentHead)?;
    encode_signature(&mut encoder, value.activation_signature)?;
    Ok(encoder.into_writer())
}

fn encode_payload(
    value: &DecodedDurableDeploymentTransactionRecordV2,
) -> Result<Vec<u8>, DeploymentControlErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encode_payload_into(&mut encoder, value)?;
    Ok(encoder.into_writer())
}

fn encode_payload_into(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    value: &DecodedDurableDeploymentTransactionRecordV2,
) -> Result<(), DeploymentControlErrorV2> {
    encoder
        .array(DURABLE_HEAD_PAYLOAD_FIELDS_V2)
        .and_then(|encoder| encoder.u16(value.schema_version))
        .and_then(|encoder| encoder.bytes(value.installation_id.as_bytes()))
        .and_then(|encoder| encoder.u64(value.installation_epoch))
        .and_then(|encoder| encoder.bytes(value.transaction_id.as_bytes()))
        .and_then(|encoder| encoder.bytes(value.core_signed_digest.as_bytes()))
        .and_then(|encoder| encoder.u64(value.head_sequence))
        .map_err(|_| DeploymentControlErrorV2::InvalidDurableDeploymentHead)?;
    encode_optional_digest(encoder, value.previous_head_digest)?;
    encoder
        .bytes(value.expected_previous_ledger_record_digest.as_bytes())
        .and_then(|encoder| encoder.u64(value.expected_previous_ledger_generation))
        .and_then(|encoder| encoder.u16(value.target_phase as u16))
        .and_then(|encoder| encoder.array(value.completed_steps.len() as u64))
        .map_err(|_| DeploymentControlErrorV2::InvalidDurableDeploymentHead)?;
    for step in &value.completed_steps {
        encoder
            .u16(step.tag())
            .map_err(|_| DeploymentControlErrorV2::InvalidDurableDeploymentHead)?;
    }
    encoder
        .array(value.evidence_refs.len() as u64)
        .map_err(|_| DeploymentControlErrorV2::InvalidDurableDeploymentHead)?;
    for evidence in &value.evidence_refs {
        encoder
            .array(DURABLE_EVIDENCE_FIELDS_V2)
            .and_then(|encoder| encoder.u16(evidence.tag()))
            .and_then(|encoder| encoder.bytes(evidence.digest().as_bytes()))
            .map_err(|_| DeploymentControlErrorV2::InvalidDurableDeploymentHead)?;
    }
    encode_owner(encoder, value.owner)?;
    encoder
        .u64(value.watchdog_deadline_monotonic_ns)
        .and_then(|encoder| encoder.u64(value.written_at_unix_ms))
        .map(|_| ())
        .map_err(|_| DeploymentControlErrorV2::InvalidDurableDeploymentHead)
}

fn decode_complete_record(
    bytes: &[u8],
) -> Result<DecodedDurableDeploymentTransactionRecordV2, DeploymentControlErrorV2> {
    let mut decoder = minicbor::Decoder::new(bytes);
    expect_array(&mut decoder, DURABLE_HEAD_COMPLETE_FIELDS_V2)?;
    expect_array(&mut decoder, DURABLE_HEAD_PAYLOAD_FIELDS_V2)?;
    let schema_version = decode_u16(&mut decoder)?;
    let installation_id = decode_digest(&mut decoder)?;
    let installation_epoch = decode_u64(&mut decoder)?;
    let transaction_id = decode_nonce(&mut decoder)?;
    let core_signed_digest = decode_digest(&mut decoder)?;
    let head_sequence = decode_u64(&mut decoder)?;
    let previous_head_digest = decode_optional_digest(&mut decoder)?;
    let expected_previous_ledger_record_digest = decode_digest(&mut decoder)?;
    let expected_previous_ledger_generation = decode_u64(&mut decoder)?;
    let target_phase = decode_phase(&mut decoder)?;
    let completed_steps = decode_steps(&mut decoder)?;
    let evidence_refs = decode_evidence(&mut decoder)?;
    let owner = decode_owner(&mut decoder)?;
    let watchdog_deadline_monotonic_ns = decode_u64(&mut decoder)?;
    let written_at_unix_ms = decode_u64(&mut decoder)?;
    let payload_digest = decode_digest(&mut decoder)?;
    let activation_signature = decode_signature(&mut decoder)?;
    if decoder.position() != bytes.len() {
        return Err(DeploymentControlErrorV2::InvalidDurableDeploymentHead);
    }
    Ok(DecodedDurableDeploymentTransactionRecordV2 {
        schema_version,
        installation_id,
        installation_epoch,
        transaction_id,
        core_signed_digest,
        head_sequence,
        previous_head_digest,
        expected_previous_ledger_record_digest,
        expected_previous_ledger_generation,
        target_phase,
        completed_steps,
        evidence_refs,
        owner,
        watchdog_deadline_monotonic_ns,
        written_at_unix_ms,
        payload_digest,
        activation_signature,
    })
}

fn encode_optional_digest(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    value: Option<Digest32V2>,
) -> Result<(), DeploymentControlErrorV2> {
    match value {
        None => encoder
            .array(1)
            .and_then(|encoder| encoder.u16(0))
            .map(|_| ())
            .map_err(|_| DeploymentControlErrorV2::InvalidDurableDeploymentHead),
        Some(value) => encoder
            .array(2)
            .and_then(|encoder| encoder.u16(1))
            .and_then(|encoder| encoder.bytes(value.as_bytes()))
            .map(|_| ())
            .map_err(|_| DeploymentControlErrorV2::InvalidDurableDeploymentHead),
    }
}

fn decode_optional_digest(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<Option<Digest32V2>, DeploymentControlErrorV2> {
    let length = decoder
        .array()
        .map_err(|_| DeploymentControlErrorV2::InvalidDurableDeploymentHead)?;
    match (decode_u16(decoder)?, length) {
        (0, Some(1)) => Ok(None),
        (1, Some(2)) => decode_digest(decoder).map(Some),
        _ => Err(DeploymentControlErrorV2::InvalidDurableDeploymentHead),
    }
}

fn encode_owner(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    owner: DeploymentOwnerClaimV2,
) -> Result<(), DeploymentControlErrorV2> {
    let identity = owner.identity();
    encoder
        .array(DURABLE_OWNER_FIELDS_V2)
        .and_then(|encoder| encoder.bytes(owner.transaction_id().as_bytes()))
        .and_then(|encoder| encoder.u16(owner.owner_role() as u16))
        .and_then(|encoder| encoder.bytes(identity.boot_id().as_bytes()))
        .and_then(|encoder| encoder.u64(identity.pid()))
        .and_then(|encoder| encoder.u64(identity.process_start_identity()))
        .and_then(|encoder| encoder.bytes(identity.executable_identity_digest().as_bytes()))
        .and_then(|encoder| encoder.bytes(owner.operation_nonce().as_bytes()))
        .and_then(|encoder| encoder.u64(owner.heartbeat_generation()))
        .and_then(|encoder| encoder.u64(owner.heartbeat_deadline_monotonic_ns()))
        .map(|_| ())
        .map_err(|_| DeploymentControlErrorV2::InvalidDurableDeploymentHead)
}

fn decode_owner(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<DeploymentOwnerClaimV2, DeploymentControlErrorV2> {
    expect_array(decoder, DURABLE_OWNER_FIELDS_V2)?;
    let transaction_id = decode_nonce(decoder)?;
    let owner_role = match decode_u16(decoder)? {
        1 => DeploymentOwnerRoleV2::Helper,
        2 => DeploymentOwnerRoleV2::Watchdog,
        _ => return Err(DeploymentControlErrorV2::InvalidDurableDeploymentHead),
    };
    let boot_id = decode_digest(decoder)?;
    let pid = decode_u64(decoder)?;
    let process_start_identity = decode_u64(decoder)?;
    let executable_identity_digest = decode_digest(decoder)?;
    let operation_nonce = decode_nonce(decoder)?;
    let heartbeat_generation = decode_u64(decoder)?;
    let heartbeat_deadline_monotonic_ns = decode_u64(decoder)?;
    DeploymentOwnerClaimV2::new(
        transaction_id,
        owner_role,
        boot_id,
        pid,
        process_start_identity,
        executable_identity_digest,
        operation_nonce,
        heartbeat_generation,
        heartbeat_deadline_monotonic_ns,
    )
    .map_err(|_| DeploymentControlErrorV2::InvalidDurableDeploymentHead)
}

fn decode_steps(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<Vec<ClosedDurableDeploymentStepV2>, DeploymentControlErrorV2> {
    let count = decode_bounded_array_len(decoder, MAX_DURABLE_STEPS_V2)?;
    let mut steps = Vec::with_capacity(count);
    for _ in 0..count {
        steps.push(
            ClosedDurableDeploymentStepV2::from_tag(decode_u16(decoder)?)
                .ok_or(DeploymentControlErrorV2::InvalidDurableDeploymentHead)?,
        );
    }
    Ok(steps)
}

fn decode_evidence(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<Vec<DurableDeploymentEvidenceRefV2>, DeploymentControlErrorV2> {
    let count = decode_bounded_array_len(decoder, MAX_DURABLE_EVIDENCE_REFS_V2)?;
    let mut evidence_refs = Vec::with_capacity(count);
    for _ in 0..count {
        expect_array(decoder, DURABLE_EVIDENCE_FIELDS_V2)?;
        let tag = decode_u16(decoder)?;
        let digest = decode_digest(decoder)?;
        evidence_refs.push(
            DurableDeploymentEvidenceRefV2::from_tag(tag, digest)
                .ok_or(DeploymentControlErrorV2::InvalidDurableDeploymentHead)?,
        );
    }
    Ok(evidence_refs)
}

fn encode_signature(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    signature: DurableHeadSignatureV2,
) -> Result<(), DeploymentControlErrorV2> {
    encoder
        .array(DOMAIN_SIGNATURE_FIELDS_V2)
        .and_then(|encoder| encoder.u16(signature.domain_tag))
        .and_then(|encoder| encoder.bytes(signature.signer_key_id.as_bytes()))
        .and_then(|encoder| encoder.u64(signature.signer_key_epoch))
        .and_then(|encoder| encoder.bytes(signature.signature.as_bytes()))
        .map(|_| ())
        .map_err(|_| DeploymentControlErrorV2::InvalidDurableDeploymentHead)
}

fn decode_signature(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<DurableHeadSignatureV2, DeploymentControlErrorV2> {
    expect_array(decoder, DOMAIN_SIGNATURE_FIELDS_V2)?;
    Ok(DurableHeadSignatureV2 {
        domain_tag: decode_u16(decoder)?,
        signer_key_id: Ed25519KeyIdV2::new(decode_fixed_bytes::<32>(decoder)?),
        signer_key_epoch: decode_u64(decoder)?,
        signature: Ed25519SignatureV2::new(decode_fixed_bytes::<64>(decoder)?),
    })
}

fn decode_phase(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<DeploymentPhaseV2, DeploymentControlErrorV2> {
    match decode_u16(decoder)? {
        1 => Ok(DeploymentPhaseV2::Idle),
        2 => Ok(DeploymentPhaseV2::Prepared),
        3 => Ok(DeploymentPhaseV2::Armed),
        4 => Ok(DeploymentPhaseV2::Quiesced),
        5 => Ok(DeploymentPhaseV2::Installed),
        6 => Ok(DeploymentPhaseV2::Verified),
        7 => Ok(DeploymentPhaseV2::Committed),
        8 => Ok(DeploymentPhaseV2::Aborted),
        9 => Ok(DeploymentPhaseV2::RollbackPrepared),
        10 => Ok(DeploymentPhaseV2::RollbackInstalled),
        11 => Ok(DeploymentPhaseV2::RollbackVerified),
        12 => Ok(DeploymentPhaseV2::RolledBack),
        13 => Ok(DeploymentPhaseV2::FailedSafe),
        14 => Ok(DeploymentPhaseV2::BootstrapBridge),
        15 => Ok(DeploymentPhaseV2::BridgeRestorePrepared),
        16 => Ok(DeploymentPhaseV2::BridgeRestoreInstalled),
        17 => Ok(DeploymentPhaseV2::BridgeRestoreVerified),
        _ => Err(DeploymentControlErrorV2::InvalidDurableDeploymentHead),
    }
}

fn expect_array(
    decoder: &mut minicbor::Decoder<'_>,
    expected: u64,
) -> Result<(), DeploymentControlErrorV2> {
    if decoder
        .array()
        .map_err(|_| DeploymentControlErrorV2::InvalidDurableDeploymentHead)?
        != Some(expected)
    {
        return Err(DeploymentControlErrorV2::InvalidDurableDeploymentHead);
    }
    Ok(())
}

fn decode_bounded_array_len(
    decoder: &mut minicbor::Decoder<'_>,
    maximum: usize,
) -> Result<usize, DeploymentControlErrorV2> {
    let count = decoder
        .array()
        .map_err(|_| DeploymentControlErrorV2::InvalidDurableDeploymentHead)?
        .ok_or(DeploymentControlErrorV2::InvalidDurableDeploymentHead)?;
    let count = usize::try_from(count)
        .map_err(|_| DeploymentControlErrorV2::InvalidDurableDeploymentHead)?;
    if count > maximum {
        return Err(DeploymentControlErrorV2::InvalidDurableDeploymentHead);
    }
    Ok(count)
}

fn decode_u16(decoder: &mut minicbor::Decoder<'_>) -> Result<u16, DeploymentControlErrorV2> {
    decoder
        .u16()
        .map_err(|_| DeploymentControlErrorV2::InvalidDurableDeploymentHead)
}

fn decode_u64(decoder: &mut minicbor::Decoder<'_>) -> Result<u64, DeploymentControlErrorV2> {
    decoder
        .u64()
        .map_err(|_| DeploymentControlErrorV2::InvalidDurableDeploymentHead)
}

fn decode_fixed_bytes<const N: usize>(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<[u8; N], DeploymentControlErrorV2> {
    decoder
        .bytes()
        .map_err(|_| DeploymentControlErrorV2::InvalidDurableDeploymentHead)?
        .try_into()
        .map_err(|_| DeploymentControlErrorV2::InvalidDurableDeploymentHead)
}

fn decode_digest(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<Digest32V2, DeploymentControlErrorV2> {
    Ok(Digest32V2::new(decode_fixed_bytes::<32>(decoder)?))
}

fn decode_nonce(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<Nonce32V2, DeploymentControlErrorV2> {
    Ok(Nonce32V2::new(decode_fixed_bytes::<32>(decoder)?))
}

#[cfg(any(test, feature = "test-support"))]
fn domain_signature_input(domain_tag: u16, domain: &[u8], digest: Digest32V2) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_SIGNATURE_INPUT_V2);
    hasher.update(domain_tag.to_be_bytes());
    hasher.update(domain);
    hasher.update(digest.as_bytes());
    hasher.finalize().into()
}

fn hash_domain(domain: &[u8], bytes: &[u8]) -> Digest32V2 {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    Digest32V2::new(hasher.finalize().into())
}

fn is_zero<const N: usize>(bytes: &[u8; N]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}
