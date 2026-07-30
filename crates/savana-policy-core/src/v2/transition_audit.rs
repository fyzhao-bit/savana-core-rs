use savana_kernel_protocol::v2::{Digest32V2, Nonce32V2};
use sha2::{Digest as _, Sha256};

use super::{
    DeploymentBranchV2, DeploymentControlErrorV2, DeploymentPhaseV2, DeploymentTransitionV2,
};

const TRANSITION_AUDIT_SCHEMA_VERSION_V2: u16 = 2;
const TRANSITION_AUDIT_FIELDS_V2: u64 = 18;
const MAX_TRANSITION_AUDIT_BYTES_V2: usize = 4096;
const TRANSITION_AUDIT_DOMAIN_V2: &[u8] = b"savana.deployment-transition-audit.v2\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionAuditV2 {
    canonical_bytes: Vec<u8>,
    digest: Digest32V2,
    installation_id: Digest32V2,
    installation_epoch: u64,
    transaction_id: Nonce32V2,
    core_signed_digest: Digest32V2,
    branch: DeploymentBranchV2,
    from_phase: DeploymentPhaseV2,
    to_phase: DeploymentPhaseV2,
    source_ledger_signed_digest: Digest32V2,
    source_ledger_generation: u64,
    source_head_signed_digest: Option<Digest32V2>,
    candidate_head_signed_digest: Digest32V2,
    candidate_head_sequence: u64,
    candidate_ledger_signed_digest: Digest32V2,
    candidate_ledger_generation: u64,
    effects_fenced_after: bool,
    effect_fence_epoch_after: u64,
    written_at_unix_ms: u64,
}

impl TransitionAuditV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        installation_id: Digest32V2,
        installation_epoch: u64,
        transaction_id: Nonce32V2,
        core_signed_digest: Digest32V2,
        branch: DeploymentBranchV2,
        from_phase: DeploymentPhaseV2,
        to_phase: DeploymentPhaseV2,
        source_ledger_signed_digest: Digest32V2,
        source_ledger_generation: u64,
        source_head_signed_digest: Option<Digest32V2>,
        candidate_head_signed_digest: Digest32V2,
        candidate_head_sequence: u64,
        candidate_ledger_signed_digest: Digest32V2,
        candidate_ledger_generation: u64,
        effects_fenced_after: bool,
        effect_fence_epoch_after: u64,
        written_at_unix_ms: u64,
    ) -> Result<Self, DeploymentControlErrorV2> {
        let fields = TransitionAuditFieldsV2 {
            installation_id,
            installation_epoch,
            transaction_id,
            core_signed_digest,
            branch,
            from_phase,
            to_phase,
            source_ledger_signed_digest,
            source_ledger_generation,
            source_head_signed_digest,
            candidate_head_signed_digest,
            candidate_head_sequence,
            candidate_ledger_signed_digest,
            candidate_ledger_generation,
            effects_fenced_after,
            effect_fence_epoch_after,
            written_at_unix_ms,
        };
        Self::from_fields(fields)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, DeploymentControlErrorV2> {
        if bytes.is_empty() || bytes.len() > MAX_TRANSITION_AUDIT_BYTES_V2 {
            return Err(DeploymentControlErrorV2::InvalidTransitionAudit);
        }
        let mut decoder = minicbor::Decoder::new(bytes);
        expect_array(&mut decoder, TRANSITION_AUDIT_FIELDS_V2)?;
        if decode_u16(&mut decoder)? != TRANSITION_AUDIT_SCHEMA_VERSION_V2 {
            return Err(DeploymentControlErrorV2::InvalidTransitionAudit);
        }
        let fields = TransitionAuditFieldsV2 {
            installation_id: decode_digest(&mut decoder)?,
            installation_epoch: decode_u64(&mut decoder)?,
            transaction_id: Nonce32V2::new(*decode_digest(&mut decoder)?.as_bytes()),
            core_signed_digest: decode_digest(&mut decoder)?,
            branch: decode_branch(&mut decoder)?,
            from_phase: decode_phase(&mut decoder)?,
            to_phase: decode_phase(&mut decoder)?,
            source_ledger_signed_digest: decode_digest(&mut decoder)?,
            source_ledger_generation: decode_u64(&mut decoder)?,
            source_head_signed_digest: decode_optional_digest(&mut decoder)?,
            candidate_head_signed_digest: decode_digest(&mut decoder)?,
            candidate_head_sequence: decode_u64(&mut decoder)?,
            candidate_ledger_signed_digest: decode_digest(&mut decoder)?,
            candidate_ledger_generation: decode_u64(&mut decoder)?,
            effects_fenced_after: decoder
                .bool()
                .map_err(|_| DeploymentControlErrorV2::InvalidTransitionAudit)?,
            effect_fence_epoch_after: decode_u64(&mut decoder)?,
            written_at_unix_ms: decode_u64(&mut decoder)?,
        };
        if decoder.position() != bytes.len() {
            return Err(DeploymentControlErrorV2::InvalidTransitionAudit);
        }
        let value = Self::from_fields(fields)?;
        if value.canonical_bytes != bytes {
            return Err(DeploymentControlErrorV2::InvalidTransitionAudit);
        }
        Ok(value)
    }

    fn from_fields(fields: TransitionAuditFieldsV2) -> Result<Self, DeploymentControlErrorV2> {
        validate_fields(&fields)?;
        let canonical_bytes = encode_fields(&fields)?;
        let digest = hash_domain(TRANSITION_AUDIT_DOMAIN_V2, &canonical_bytes);
        Ok(Self {
            canonical_bytes,
            digest,
            installation_id: fields.installation_id,
            installation_epoch: fields.installation_epoch,
            transaction_id: fields.transaction_id,
            core_signed_digest: fields.core_signed_digest,
            branch: fields.branch,
            from_phase: fields.from_phase,
            to_phase: fields.to_phase,
            source_ledger_signed_digest: fields.source_ledger_signed_digest,
            source_ledger_generation: fields.source_ledger_generation,
            source_head_signed_digest: fields.source_head_signed_digest,
            candidate_head_signed_digest: fields.candidate_head_signed_digest,
            candidate_head_sequence: fields.candidate_head_sequence,
            candidate_ledger_signed_digest: fields.candidate_ledger_signed_digest,
            candidate_ledger_generation: fields.candidate_ledger_generation,
            effects_fenced_after: fields.effects_fenced_after,
            effect_fence_epoch_after: fields.effect_fence_epoch_after,
            written_at_unix_ms: fields.written_at_unix_ms,
        })
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub const fn digest(&self) -> Digest32V2 {
        self.digest
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

    pub const fn branch(&self) -> DeploymentBranchV2 {
        self.branch
    }

    pub const fn from_phase(&self) -> DeploymentPhaseV2 {
        self.from_phase
    }

    pub const fn to_phase(&self) -> DeploymentPhaseV2 {
        self.to_phase
    }

    pub const fn source_ledger_signed_digest(&self) -> Digest32V2 {
        self.source_ledger_signed_digest
    }

    pub const fn source_ledger_generation(&self) -> u64 {
        self.source_ledger_generation
    }

    pub const fn source_head_signed_digest(&self) -> Option<Digest32V2> {
        self.source_head_signed_digest
    }

    pub const fn candidate_head_signed_digest(&self) -> Digest32V2 {
        self.candidate_head_signed_digest
    }

    pub const fn candidate_head_sequence(&self) -> u64 {
        self.candidate_head_sequence
    }

    pub const fn candidate_ledger_signed_digest(&self) -> Digest32V2 {
        self.candidate_ledger_signed_digest
    }

    pub const fn candidate_ledger_generation(&self) -> u64 {
        self.candidate_ledger_generation
    }

    pub const fn effects_fenced_after(&self) -> bool {
        self.effects_fenced_after
    }

    pub const fn effect_fence_epoch_after(&self) -> u64 {
        self.effect_fence_epoch_after
    }

    pub const fn written_at_unix_ms(&self) -> u64 {
        self.written_at_unix_ms
    }
}

#[derive(Debug, Clone, Copy)]
struct TransitionAuditFieldsV2 {
    installation_id: Digest32V2,
    installation_epoch: u64,
    transaction_id: Nonce32V2,
    core_signed_digest: Digest32V2,
    branch: DeploymentBranchV2,
    from_phase: DeploymentPhaseV2,
    to_phase: DeploymentPhaseV2,
    source_ledger_signed_digest: Digest32V2,
    source_ledger_generation: u64,
    source_head_signed_digest: Option<Digest32V2>,
    candidate_head_signed_digest: Digest32V2,
    candidate_head_sequence: u64,
    candidate_ledger_signed_digest: Digest32V2,
    candidate_ledger_generation: u64,
    effects_fenced_after: bool,
    effect_fence_epoch_after: u64,
    written_at_unix_ms: u64,
}

fn validate_fields(fields: &TransitionAuditFieldsV2) -> Result<(), DeploymentControlErrorV2> {
    DeploymentTransitionV2::new(fields.branch, fields.from_phase, fields.to_phase)
        .map_err(|_| DeploymentControlErrorV2::InvalidTransitionAudit)?;
    if fields.installation_epoch == 0
        || fields.source_ledger_generation == 0
        || fields.candidate_head_sequence == 0
        || fields.effect_fence_epoch_after == 0
        || fields.written_at_unix_ms == 0
        || fields.source_ledger_generation.checked_add(1)
            != Some(fields.candidate_ledger_generation)
        || fields
            .source_head_signed_digest
            .is_some_and(|value| is_zero(value.as_bytes()))
        || [
            fields.installation_id.as_bytes(),
            fields.transaction_id.as_bytes(),
            fields.core_signed_digest.as_bytes(),
            fields.source_ledger_signed_digest.as_bytes(),
            fields.candidate_head_signed_digest.as_bytes(),
            fields.candidate_ledger_signed_digest.as_bytes(),
        ]
        .iter()
        .any(|value| is_zero(*value))
    {
        return Err(DeploymentControlErrorV2::InvalidTransitionAudit);
    }
    Ok(())
}

fn encode_fields(fields: &TransitionAuditFieldsV2) -> Result<Vec<u8>, DeploymentControlErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(TRANSITION_AUDIT_FIELDS_V2)
        .and_then(|encoder| encoder.u16(TRANSITION_AUDIT_SCHEMA_VERSION_V2))
        .and_then(|encoder| encoder.bytes(fields.installation_id.as_bytes()))
        .and_then(|encoder| encoder.u64(fields.installation_epoch))
        .and_then(|encoder| encoder.bytes(fields.transaction_id.as_bytes()))
        .and_then(|encoder| encoder.bytes(fields.core_signed_digest.as_bytes()))
        .and_then(|encoder| encoder.u16(fields.branch as u16))
        .and_then(|encoder| encoder.u16(fields.from_phase as u16))
        .and_then(|encoder| encoder.u16(fields.to_phase as u16))
        .and_then(|encoder| encoder.bytes(fields.source_ledger_signed_digest.as_bytes()))
        .and_then(|encoder| encoder.u64(fields.source_ledger_generation))
        .map_err(|_| DeploymentControlErrorV2::InvalidTransitionAudit)?;
    encode_optional_digest(&mut encoder, fields.source_head_signed_digest)?;
    encoder
        .bytes(fields.candidate_head_signed_digest.as_bytes())
        .and_then(|encoder| encoder.u64(fields.candidate_head_sequence))
        .and_then(|encoder| encoder.bytes(fields.candidate_ledger_signed_digest.as_bytes()))
        .and_then(|encoder| encoder.u64(fields.candidate_ledger_generation))
        .and_then(|encoder| encoder.bool(fields.effects_fenced_after))
        .and_then(|encoder| encoder.u64(fields.effect_fence_epoch_after))
        .and_then(|encoder| encoder.u64(fields.written_at_unix_ms))
        .map_err(|_| DeploymentControlErrorV2::InvalidTransitionAudit)?;
    Ok(encoder.into_writer())
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
            .map_err(|_| DeploymentControlErrorV2::InvalidTransitionAudit),
        Some(value) => encoder
            .array(2)
            .and_then(|encoder| encoder.u16(1))
            .and_then(|encoder| encoder.bytes(value.as_bytes()))
            .map(|_| ())
            .map_err(|_| DeploymentControlErrorV2::InvalidTransitionAudit),
    }
}

fn decode_optional_digest(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<Option<Digest32V2>, DeploymentControlErrorV2> {
    let count = decoder
        .array()
        .map_err(|_| DeploymentControlErrorV2::InvalidTransitionAudit)?
        .ok_or(DeploymentControlErrorV2::InvalidTransitionAudit)?;
    let tag = decode_u16(decoder)?;
    match (count, tag) {
        (1, 0) => Ok(None),
        (2, 1) => Ok(Some(decode_digest(decoder)?)),
        _ => Err(DeploymentControlErrorV2::InvalidTransitionAudit),
    }
}

fn decode_branch(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<DeploymentBranchV2, DeploymentControlErrorV2> {
    match decode_u16(decoder)? {
        1 => Ok(DeploymentBranchV2::Normal),
        2 => Ok(DeploymentBranchV2::BootstrapBridgeRestore),
        _ => Err(DeploymentControlErrorV2::InvalidTransitionAudit),
    }
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
        _ => Err(DeploymentControlErrorV2::InvalidTransitionAudit),
    }
}

fn expect_array(
    decoder: &mut minicbor::Decoder<'_>,
    expected: u64,
) -> Result<(), DeploymentControlErrorV2> {
    if decoder
        .array()
        .map_err(|_| DeploymentControlErrorV2::InvalidTransitionAudit)?
        != Some(expected)
    {
        return Err(DeploymentControlErrorV2::InvalidTransitionAudit);
    }
    Ok(())
}

fn decode_u16(decoder: &mut minicbor::Decoder<'_>) -> Result<u16, DeploymentControlErrorV2> {
    decoder
        .u16()
        .map_err(|_| DeploymentControlErrorV2::InvalidTransitionAudit)
}

fn decode_u64(decoder: &mut minicbor::Decoder<'_>) -> Result<u64, DeploymentControlErrorV2> {
    decoder
        .u64()
        .map_err(|_| DeploymentControlErrorV2::InvalidTransitionAudit)
}

fn decode_digest(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<Digest32V2, DeploymentControlErrorV2> {
    let bytes = decoder
        .bytes()
        .map_err(|_| DeploymentControlErrorV2::InvalidTransitionAudit)?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| DeploymentControlErrorV2::InvalidTransitionAudit)?;
    Ok(Digest32V2::new(bytes))
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
