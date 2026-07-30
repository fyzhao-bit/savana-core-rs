use savana_kernel_protocol::v2::{Digest32V2, Nonce32V2};
use sha2::{Digest as _, Sha256};

use super::{DeploymentControlErrorV2, DeploymentPhaseV2, RollbackGrantStateV2};

const FAILURE_EVIDENCE_FIELDS_V2: u64 = 14;
const FAILURE_EVIDENCE_SCHEMA_VERSION_V2: u16 = 2;
const FAILURE_EVIDENCE_MAX_BYTES_V2: usize = 2048;
const FAILURE_EVIDENCE_DOMAIN_V2: &[u8] = b"savana.deployment-failure-evidence.v2\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u16)]
pub enum ClosedDeploymentFailureClassV2 {
    AuthenticatedStateCorruption = 1,
    NativeEffectFenceFailure = 2,
    RollbackAuthorityFailure = 3,
    ServiceQuiescenceIndeterminate = 4,
    ArtifactInstallIndeterminate = 5,
    CandidateVerificationFailure = 6,
    RollbackVerificationFailure = 7,
    BridgeRestoreFailure = 8,
    DurabilityOutcomeUncertain = 9,
}

impl ClosedDeploymentFailureClassV2 {
    const fn from_tag(tag: u16) -> Option<Self> {
        match tag {
            1 => Some(Self::AuthenticatedStateCorruption),
            2 => Some(Self::NativeEffectFenceFailure),
            3 => Some(Self::RollbackAuthorityFailure),
            4 => Some(Self::ServiceQuiescenceIndeterminate),
            5 => Some(Self::ArtifactInstallIndeterminate),
            6 => Some(Self::CandidateVerificationFailure),
            7 => Some(Self::RollbackVerificationFailure),
            8 => Some(Self::BridgeRestoreFailure),
            9 => Some(Self::DurabilityOutcomeUncertain),
            _ => None,
        }
    }

    const fn tag(self) -> u16 {
        self as u16
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeploymentFailureEvidenceV2 {
    canonical_bytes: Vec<u8>,
    installation_id: Digest32V2,
    installation_epoch: u64,
    transaction_id: Nonce32V2,
    core_signed_digest: Digest32V2,
    source_head_signed_digest: Digest32V2,
    source_phase: DeploymentPhaseV2,
    failed_transition_target: DeploymentPhaseV2,
    failure_class: ClosedDeploymentFailureClassV2,
    failure_detail_digest: Digest32V2,
    effects_fenced: bool,
    rollback_grant_state: RollbackGrantStateV2,
    native_fence_measurement_digest: Digest32V2,
    observed_at_unix_ms: u64,
    digest: Digest32V2,
}

impl DeploymentFailureEvidenceV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        installation_id: Digest32V2,
        installation_epoch: u64,
        transaction_id: Nonce32V2,
        core_signed_digest: Digest32V2,
        source_head_signed_digest: Digest32V2,
        source_phase: DeploymentPhaseV2,
        failed_transition_target: DeploymentPhaseV2,
        failure_class: ClosedDeploymentFailureClassV2,
        failure_detail_digest: Digest32V2,
        native_fence_measurement_digest: Digest32V2,
        observed_at_unix_ms: u64,
    ) -> Result<Self, DeploymentControlErrorV2> {
        let canonical_bytes = encode_failure_evidence(
            installation_id,
            installation_epoch,
            transaction_id,
            core_signed_digest,
            source_head_signed_digest,
            source_phase,
            failed_transition_target,
            failure_class,
            failure_detail_digest,
            native_fence_measurement_digest,
            observed_at_unix_ms,
        )?;
        Self::from_canonical_bytes(&canonical_bytes)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, DeploymentControlErrorV2> {
        if bytes.is_empty() || bytes.len() > FAILURE_EVIDENCE_MAX_BYTES_V2 {
            return Err(DeploymentControlErrorV2::InvalidDeploymentFailureEvidence);
        }
        let mut decoder = minicbor::Decoder::new(bytes);
        expect_array(&mut decoder, FAILURE_EVIDENCE_FIELDS_V2)?;
        let schema_version = decode_u16(&mut decoder)?;
        let installation_id = decode_digest(&mut decoder)?;
        let installation_epoch = decode_u64(&mut decoder)?;
        let transaction_id = decode_nonce(&mut decoder)?;
        let core_signed_digest = decode_digest(&mut decoder)?;
        let source_head_signed_digest = decode_digest(&mut decoder)?;
        let source_phase = decode_phase(&mut decoder)?;
        let failed_transition_target = decode_phase(&mut decoder)?;
        let failure_class = ClosedDeploymentFailureClassV2::from_tag(decode_u16(&mut decoder)?)
            .ok_or(DeploymentControlErrorV2::InvalidDeploymentFailureEvidence)?;
        let failure_detail_digest = decode_digest(&mut decoder)?;
        let effects_fenced = decoder
            .bool()
            .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentFailureEvidence)?;
        let rollback_grant_state = decode_grant_state(&mut decoder)?;
        let native_fence_measurement_digest = decode_digest(&mut decoder)?;
        let observed_at_unix_ms = decode_u64(&mut decoder)?;
        if decoder.position() != bytes.len()
            || schema_version != FAILURE_EVIDENCE_SCHEMA_VERSION_V2
            || installation_epoch == 0
            || observed_at_unix_ms == 0
            || !effects_fenced
            || rollback_grant_state != RollbackGrantStateV2::Burned
            || !is_failure_source_phase(source_phase)
            || matches!(
                failed_transition_target,
                DeploymentPhaseV2::Idle | DeploymentPhaseV2::FailedSafe
            )
            || [
                installation_id.as_bytes(),
                transaction_id.as_bytes(),
                core_signed_digest.as_bytes(),
                source_head_signed_digest.as_bytes(),
                failure_detail_digest.as_bytes(),
                native_fence_measurement_digest.as_bytes(),
            ]
            .iter()
            .any(|value| is_zero(*value))
        {
            return Err(DeploymentControlErrorV2::InvalidDeploymentFailureEvidence);
        }
        let canonical_bytes = encode_failure_evidence(
            installation_id,
            installation_epoch,
            transaction_id,
            core_signed_digest,
            source_head_signed_digest,
            source_phase,
            failed_transition_target,
            failure_class,
            failure_detail_digest,
            native_fence_measurement_digest,
            observed_at_unix_ms,
        )?;
        if canonical_bytes != bytes {
            return Err(DeploymentControlErrorV2::InvalidDeploymentFailureEvidence);
        }
        let digest = hash_domain(FAILURE_EVIDENCE_DOMAIN_V2, bytes);
        Ok(Self {
            canonical_bytes,
            installation_id,
            installation_epoch,
            transaction_id,
            core_signed_digest,
            source_head_signed_digest,
            source_phase,
            failed_transition_target,
            failure_class,
            failure_detail_digest,
            effects_fenced,
            rollback_grant_state,
            native_fence_measurement_digest,
            observed_at_unix_ms,
            digest,
        })
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub const fn installation_id(&self) -> Digest32V2 {
        self.installation_id
    }

    pub const fn installation_epoch(&self) -> u64 {
        self.installation_epoch
    }

    pub const fn transaction_id(&self) -> Nonce32V2 {
        self.transaction_id
    }

    pub const fn core_signed_digest(&self) -> Digest32V2 {
        self.core_signed_digest
    }

    pub const fn source_head_signed_digest(&self) -> Digest32V2 {
        self.source_head_signed_digest
    }

    pub const fn source_phase(&self) -> DeploymentPhaseV2 {
        self.source_phase
    }

    pub const fn failed_transition_target(&self) -> DeploymentPhaseV2 {
        self.failed_transition_target
    }

    pub const fn failure_class(&self) -> ClosedDeploymentFailureClassV2 {
        self.failure_class
    }

    pub const fn failure_detail_digest(&self) -> Digest32V2 {
        self.failure_detail_digest
    }

    pub const fn effects_fenced(&self) -> bool {
        self.effects_fenced
    }

    pub const fn rollback_grant_state(&self) -> RollbackGrantStateV2 {
        self.rollback_grant_state
    }

    pub const fn native_fence_measurement_digest(&self) -> Digest32V2 {
        self.native_fence_measurement_digest
    }

    pub const fn observed_at_unix_ms(&self) -> u64 {
        self.observed_at_unix_ms
    }

    pub const fn digest(&self) -> Digest32V2 {
        self.digest
    }
}

#[allow(clippy::too_many_arguments)]
fn encode_failure_evidence(
    installation_id: Digest32V2,
    installation_epoch: u64,
    transaction_id: Nonce32V2,
    core_signed_digest: Digest32V2,
    source_head_signed_digest: Digest32V2,
    source_phase: DeploymentPhaseV2,
    failed_transition_target: DeploymentPhaseV2,
    failure_class: ClosedDeploymentFailureClassV2,
    failure_detail_digest: Digest32V2,
    native_fence_measurement_digest: Digest32V2,
    observed_at_unix_ms: u64,
) -> Result<Vec<u8>, DeploymentControlErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(FAILURE_EVIDENCE_FIELDS_V2)
        .and_then(|encoder| encoder.u16(FAILURE_EVIDENCE_SCHEMA_VERSION_V2))
        .and_then(|encoder| encoder.bytes(installation_id.as_bytes()))
        .and_then(|encoder| encoder.u64(installation_epoch))
        .and_then(|encoder| encoder.bytes(transaction_id.as_bytes()))
        .and_then(|encoder| encoder.bytes(core_signed_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(source_head_signed_digest.as_bytes()))
        .and_then(|encoder| encoder.u16(source_phase as u16))
        .and_then(|encoder| encoder.u16(failed_transition_target as u16))
        .and_then(|encoder| encoder.u16(failure_class.tag()))
        .and_then(|encoder| encoder.bytes(failure_detail_digest.as_bytes()))
        .and_then(|encoder| encoder.bool(true))
        .and_then(|encoder| encoder.u16(RollbackGrantStateV2::Burned as u16))
        .and_then(|encoder| encoder.bytes(native_fence_measurement_digest.as_bytes()))
        .and_then(|encoder| encoder.u64(observed_at_unix_ms))
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentFailureEvidence)?;
    Ok(encoder.into_writer())
}

fn is_failure_source_phase(phase: DeploymentPhaseV2) -> bool {
    matches!(
        phase,
        DeploymentPhaseV2::Prepared
            | DeploymentPhaseV2::Armed
            | DeploymentPhaseV2::Quiesced
            | DeploymentPhaseV2::Installed
            | DeploymentPhaseV2::Verified
            | DeploymentPhaseV2::RollbackPrepared
            | DeploymentPhaseV2::RollbackInstalled
            | DeploymentPhaseV2::RollbackVerified
            | DeploymentPhaseV2::BridgeRestorePrepared
            | DeploymentPhaseV2::BridgeRestoreInstalled
            | DeploymentPhaseV2::BridgeRestoreVerified
    )
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
        _ => Err(DeploymentControlErrorV2::InvalidDeploymentFailureEvidence),
    }
}

fn decode_grant_state(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<RollbackGrantStateV2, DeploymentControlErrorV2> {
    match decode_u16(decoder)? {
        0 => Ok(RollbackGrantStateV2::None),
        1 => Ok(RollbackGrantStateV2::Prearmed),
        2 => Ok(RollbackGrantStateV2::Consuming),
        3 => Ok(RollbackGrantStateV2::Consumed),
        4 => Ok(RollbackGrantStateV2::Burned),
        _ => Err(DeploymentControlErrorV2::InvalidDeploymentFailureEvidence),
    }
}

fn expect_array(
    decoder: &mut minicbor::Decoder<'_>,
    expected: u64,
) -> Result<(), DeploymentControlErrorV2> {
    if decoder
        .array()
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentFailureEvidence)?
        != Some(expected)
    {
        return Err(DeploymentControlErrorV2::InvalidDeploymentFailureEvidence);
    }
    Ok(())
}

fn decode_u16(decoder: &mut minicbor::Decoder<'_>) -> Result<u16, DeploymentControlErrorV2> {
    decoder
        .u16()
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentFailureEvidence)
}

fn decode_u64(decoder: &mut minicbor::Decoder<'_>) -> Result<u64, DeploymentControlErrorV2> {
    decoder
        .u64()
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentFailureEvidence)
}

fn decode_digest(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<Digest32V2, DeploymentControlErrorV2> {
    let bytes = decoder
        .bytes()
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentFailureEvidence)?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentFailureEvidence)?;
    Ok(Digest32V2::new(bytes))
}

fn decode_nonce(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<Nonce32V2, DeploymentControlErrorV2> {
    Ok(Nonce32V2::new(*decode_digest(decoder)?.as_bytes()))
}

fn hash_domain(domain: &[u8], bytes: &[u8]) -> Digest32V2 {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(bytes);
    Digest32V2::new(hash.finalize().into())
}

fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}
