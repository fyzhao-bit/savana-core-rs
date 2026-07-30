use savana_kernel_protocol::v2::{Digest32V2, Ed25519KeyIdV2, Ed25519SignatureV2};
use savana_platform_identity::{
    NativeDeploymentSignatureDomainV2, NativeDeploymentSignatureRequestV2,
    NativeDeploymentSigningAuthorityV2,
};
use sha2::{Digest as _, Sha256};

use super::{
    DeploymentActivationVerifierV2, DeploymentBranchV2, DeploymentControlErrorV2,
    DeploymentLedgerRecordV2, DeploymentPhaseV2, DurableDeploymentTransactionRecordV2,
};

const CHECKPOINT_COMPLETE_FIELDS_V2: u64 = 11;
const CHECKPOINT_PAYLOAD_FIELDS_V2: u64 = 10;
const DOMAIN_SIGNATURE_FIELDS_V2: u64 = 4;
const ABORTED_PROVENANCE_FIELDS_V2: u64 = 5;
const EVIDENCE_GC_CHECKPOINT_SIGNATURE_TAG_V2: u16 = 13;
const MAX_EVIDENCE_GC_CHECKPOINT_BYTES_V2: usize = 64 * 1024;
const MAX_TRANSACTION_HEAD_RECORDS_V2: usize = 4096;
const EVIDENCE_GC_CHECKPOINT_PAYLOAD_DOMAIN_V2: &[u8] =
    b"savana.evidence-gc-checkpoint.v2.payload\0";
const EVIDENCE_GC_CHECKPOINT_SIGNATURE_DOMAIN_V2: &[u8] =
    b"savana.evidence-gc-checkpoint.v2.signature\0";
const TRANSACTION_PREDECESSOR_CHAIN_DOMAIN_V2: &[u8] =
    b"savana.durable-deployment-predecessor-chain.v2\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvidenceGcWindowV2 {
    pruned_prefix_last_digest: Digest32V2,
    retained_first_digest: Digest32V2,
    retained_last_digest: Digest32V2,
    retained_count: u64,
    gc_policy_digest: Digest32V2,
    completed_at_unix_ms: u64,
}

impl EvidenceGcWindowV2 {
    pub fn new(
        pruned_prefix_last_digest: Digest32V2,
        retained_first_digest: Digest32V2,
        retained_last_digest: Digest32V2,
        retained_count: u64,
        gc_policy_digest: Digest32V2,
        completed_at_unix_ms: u64,
    ) -> Result<Self, DeploymentControlErrorV2> {
        let value = Self {
            pruned_prefix_last_digest,
            retained_first_digest,
            retained_last_digest,
            retained_count,
            gc_policy_digest,
            completed_at_unix_ms,
        };
        value.validate()?;
        Ok(value)
    }

    pub const fn pruned_prefix_last_digest(self) -> Digest32V2 {
        self.pruned_prefix_last_digest
    }

    pub const fn retained_first_digest(self) -> Digest32V2 {
        self.retained_first_digest
    }

    pub const fn retained_last_digest(self) -> Digest32V2 {
        self.retained_last_digest
    }

    pub const fn retained_count(self) -> u64 {
        self.retained_count
    }

    pub const fn gc_policy_digest(self) -> Digest32V2 {
        self.gc_policy_digest
    }

    pub const fn completed_at_unix_ms(self) -> u64 {
        self.completed_at_unix_ms
    }

    fn validate(self) -> Result<(), DeploymentControlErrorV2> {
        if self.retained_count == 0
            || self.completed_at_unix_ms == 0
            || [
                self.pruned_prefix_last_digest,
                self.retained_first_digest,
                self.retained_last_digest,
                self.gc_policy_digest,
            ]
            .iter()
            .any(|digest| is_zero(digest.as_bytes()))
        {
            return Err(DeploymentControlErrorV2::InvalidEvidenceGcCheckpoint);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompactedTransactionProvenanceV2 {
    None,
    Aborted {
        aborted_ledger_record_digest: Digest32V2,
        transaction_core_signed_digest: Digest32V2,
        final_transaction_head_signed_digest: Digest32V2,
        predecessor_chain_digest: Digest32V2,
    },
}

impl CompactedTransactionProvenanceV2 {
    pub fn from_aborted_chain(
        aborted_ledger: &DeploymentLedgerRecordV2,
        chain: &[DurableDeploymentTransactionRecordV2],
    ) -> Result<Self, DeploymentControlErrorV2> {
        validate_aborted_chain(aborted_ledger, chain)?;
        let final_head = chain
            .last()
            .ok_or(DeploymentControlErrorV2::InvalidCompactedTransactionProvenance)?;
        Ok(Self::Aborted {
            aborted_ledger_record_digest: aborted_ledger.signed_record_digest(),
            transaction_core_signed_digest: final_head.core_signed_digest(),
            final_transaction_head_signed_digest: final_head.signed_digest(),
            predecessor_chain_digest: predecessor_chain_digest(chain)?,
        })
    }

    pub const fn aborted_ledger_record_digest(self) -> Option<Digest32V2> {
        match self {
            Self::None => None,
            Self::Aborted {
                aborted_ledger_record_digest,
                ..
            } => Some(aborted_ledger_record_digest),
        }
    }

    pub const fn transaction_core_signed_digest(self) -> Option<Digest32V2> {
        match self {
            Self::None => None,
            Self::Aborted {
                transaction_core_signed_digest,
                ..
            } => Some(transaction_core_signed_digest),
        }
    }

    pub const fn final_transaction_head_signed_digest(self) -> Option<Digest32V2> {
        match self {
            Self::None => None,
            Self::Aborted {
                final_transaction_head_signed_digest,
                ..
            } => Some(final_transaction_head_signed_digest),
        }
    }

    pub const fn predecessor_chain_digest(self) -> Option<Digest32V2> {
        match self {
            Self::None => None,
            Self::Aborted {
                predecessor_chain_digest,
                ..
            } => Some(predecessor_chain_digest),
        }
    }

    pub fn validate_aborted_binding(
        self,
        aborted_ledger: &DeploymentLedgerRecordV2,
        chain: &[DurableDeploymentTransactionRecordV2],
    ) -> Result<(), DeploymentControlErrorV2> {
        let expected = Self::from_aborted_chain(aborted_ledger, chain)?;
        if self != expected {
            return Err(DeploymentControlErrorV2::InvalidCompactedTransactionProvenance);
        }
        Ok(())
    }

    fn validate(self) -> Result<(), DeploymentControlErrorV2> {
        if let Self::Aborted {
            aborted_ledger_record_digest,
            transaction_core_signed_digest,
            final_transaction_head_signed_digest,
            predecessor_chain_digest,
        } = self
        {
            if [
                aborted_ledger_record_digest,
                transaction_core_signed_digest,
                final_transaction_head_signed_digest,
                predecessor_chain_digest,
            ]
            .iter()
            .any(|digest| is_zero(digest.as_bytes()))
            {
                return Err(DeploymentControlErrorV2::InvalidCompactedTransactionProvenance);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CheckpointSignatureV2 {
    domain_tag: u16,
    signer_key_id: Ed25519KeyIdV2,
    signer_key_epoch: u64,
    signature: Ed25519SignatureV2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceGcCheckpointV2 {
    canonical_bytes: Vec<u8>,
    payload_digest: Digest32V2,
    installation_id: Digest32V2,
    installation_epoch: u64,
    window: EvidenceGcWindowV2,
    compacted_transaction_provenance: CompactedTransactionProvenanceV2,
    activation_key_id: Ed25519KeyIdV2,
}

impl EvidenceGcCheckpointV2 {
    pub fn from_canonical_bytes(
        bytes: &[u8],
        verifier: &DeploymentActivationVerifierV2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        if bytes.is_empty() || bytes.len() > MAX_EVIDENCE_GC_CHECKPOINT_BYTES_V2 {
            return Err(DeploymentControlErrorV2::InvalidEvidenceGcCheckpoint);
        }
        let decoded = decode_checkpoint(bytes)?;
        decoded.validate()?;
        if encode_complete_checkpoint(&decoded)? != bytes {
            return Err(DeploymentControlErrorV2::NonCanonicalLedgerEncoding);
        }
        if decoded.installation_id != verifier.installation_id()
            || decoded.installation_epoch != verifier.key_epoch()
        {
            return Err(DeploymentControlErrorV2::InstallationTupleMismatch);
        }
        if decoded.activation_key_id != verifier.key_id() {
            return Err(DeploymentControlErrorV2::ActivationKeyMismatch);
        }
        let payload_digest = hash_domain(
            EVIDENCE_GC_CHECKPOINT_PAYLOAD_DOMAIN_V2,
            &encode_checkpoint_payload(&decoded)?,
        );
        verifier.verify_domain_signature_parts(
            decoded.signature.domain_tag,
            decoded.signature.signer_key_id,
            decoded.signature.signer_key_epoch,
            decoded.signature.signature,
            EVIDENCE_GC_CHECKPOINT_SIGNATURE_TAG_V2,
            EVIDENCE_GC_CHECKPOINT_SIGNATURE_DOMAIN_V2,
            payload_digest,
        )?;
        Ok(Self {
            canonical_bytes: bytes.to_vec(),
            payload_digest,
            installation_id: decoded.installation_id,
            installation_epoch: decoded.installation_epoch,
            window: decoded.window,
            compacted_transaction_provenance: decoded.compacted_transaction_provenance,
            activation_key_id: decoded.activation_key_id,
        })
    }

    pub fn new_signed_with_authority(
        installation_id: Digest32V2,
        installation_epoch: u64,
        window: EvidenceGcWindowV2,
        compacted_transaction_provenance: CompactedTransactionProvenanceV2,
        authority: &mut dyn NativeDeploymentSigningAuthorityV2,
        verifier: &DeploymentActivationVerifierV2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        window.validate()?;
        compacted_transaction_provenance.validate()?;
        let activation_key_id = Ed25519KeyIdV2::new(authority.key_id());
        if authority.installation_id() != *installation_id.as_bytes()
            || authority.key_epoch() != installation_epoch
            || verifier.installation_id() != installation_id
            || verifier.key_epoch() != installation_epoch
            || verifier.key_id() != activation_key_id
        {
            return Err(DeploymentControlErrorV2::ActivationKeyMismatch);
        }
        let mut decoded = DecodedEvidenceGcCheckpointV2 {
            installation_id,
            installation_epoch,
            window,
            compacted_transaction_provenance,
            activation_key_id,
            signature: CheckpointSignatureV2 {
                domain_tag: EVIDENCE_GC_CHECKPOINT_SIGNATURE_TAG_V2,
                signer_key_id: activation_key_id,
                signer_key_epoch: installation_epoch,
                signature: Ed25519SignatureV2::new([1; 64]),
            },
        };
        decoded.validate_without_signature()?;
        let payload_digest = hash_domain(
            EVIDENCE_GC_CHECKPOINT_PAYLOAD_DOMAIN_V2,
            &encode_checkpoint_payload(&decoded)?,
        );
        let request = NativeDeploymentSignatureRequestV2::new(
            NativeDeploymentSignatureDomainV2::EvidenceGcCheckpoint,
            *installation_id.as_bytes(),
            installation_epoch,
            *payload_digest.as_bytes(),
        )
        .map_err(|_| DeploymentControlErrorV2::NativeSigningAuthorityUnavailable)?;
        decoded.signature.signature = Ed25519SignatureV2::new(
            authority
                .sign(request)
                .map_err(|_| DeploymentControlErrorV2::NativeSigningAuthorityUnavailable)?,
        );
        Self::from_canonical_bytes(&encode_complete_checkpoint(&decoded)?, verifier)
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub const fn payload_digest(&self) -> Digest32V2 {
        self.payload_digest
    }

    pub const fn installation_id(&self) -> Digest32V2 {
        self.installation_id
    }

    pub const fn installation_epoch(&self) -> u64 {
        self.installation_epoch
    }

    pub const fn window(&self) -> EvidenceGcWindowV2 {
        self.window
    }

    pub const fn compacted_transaction_provenance(&self) -> CompactedTransactionProvenanceV2 {
        self.compacted_transaction_provenance
    }

    pub const fn activation_key_id(&self) -> Ed25519KeyIdV2 {
        self.activation_key_id
    }

    pub fn validate_aborted_binding(
        &self,
        aborted_ledger: &DeploymentLedgerRecordV2,
        chain: &[DurableDeploymentTransactionRecordV2],
    ) -> Result<(), DeploymentControlErrorV2> {
        if self.installation_id != aborted_ledger.projection().installation_id()
            || self.installation_epoch != aborted_ledger.projection().installation_epoch()
        {
            return Err(DeploymentControlErrorV2::InstallationTupleMismatch);
        }
        self.compacted_transaction_provenance
            .validate_aborted_binding(aborted_ledger, chain)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DecodedEvidenceGcCheckpointV2 {
    installation_id: Digest32V2,
    installation_epoch: u64,
    window: EvidenceGcWindowV2,
    compacted_transaction_provenance: CompactedTransactionProvenanceV2,
    activation_key_id: Ed25519KeyIdV2,
    signature: CheckpointSignatureV2,
}

impl DecodedEvidenceGcCheckpointV2 {
    fn validate_without_signature(self) -> Result<(), DeploymentControlErrorV2> {
        if self.installation_epoch == 0
            || is_zero(self.installation_id.as_bytes())
            || is_zero(self.activation_key_id.as_bytes())
            || self.signature.domain_tag != EVIDENCE_GC_CHECKPOINT_SIGNATURE_TAG_V2
            || self.signature.signer_key_id != self.activation_key_id
            || self.signature.signer_key_epoch != self.installation_epoch
        {
            return Err(DeploymentControlErrorV2::InvalidEvidenceGcCheckpoint);
        }
        self.window.validate()?;
        self.compacted_transaction_provenance.validate()
    }

    fn validate(self) -> Result<(), DeploymentControlErrorV2> {
        self.validate_without_signature()?;
        if is_zero(self.signature.signature.as_bytes()) {
            return Err(DeploymentControlErrorV2::InvalidEvidenceGcCheckpoint);
        }
        Ok(())
    }
}

fn validate_aborted_chain(
    aborted_ledger: &DeploymentLedgerRecordV2,
    chain: &[DurableDeploymentTransactionRecordV2],
) -> Result<(), DeploymentControlErrorV2> {
    if chain.is_empty()
        || chain.len() > MAX_TRANSACTION_HEAD_RECORDS_V2
        || aborted_ledger.projection().phase() != DeploymentPhaseV2::Aborted
    {
        return Err(DeploymentControlErrorV2::InvalidCompactedTransactionProvenance);
    }
    let transaction_id = aborted_ledger
        .projection()
        .transaction_id()
        .ok_or(DeploymentControlErrorV2::InvalidCompactedTransactionProvenance)?;
    let selected_head_digest = aborted_ledger
        .projection()
        .transaction_head_digest()
        .ok_or(DeploymentControlErrorV2::InvalidCompactedTransactionProvenance)?;
    let first = &chain[0];
    let final_head = chain
        .last()
        .ok_or(DeploymentControlErrorV2::InvalidCompactedTransactionProvenance)?;
    if first.head_sequence() != 1
        || first.previous_head_digest().is_some()
        || final_head.signed_digest() != selected_head_digest
        || final_head.target_phase() != DeploymentPhaseV2::Aborted
        || chain.iter().any(|head| {
            head.installation_id() != aborted_ledger.projection().installation_id()
                || head.installation_epoch() != aborted_ledger.projection().installation_epoch()
                || head.transaction_id() != transaction_id
                || head.core_signed_digest() != final_head.core_signed_digest()
        })
    {
        return Err(DeploymentControlErrorV2::InvalidCompactedTransactionProvenance);
    }
    for pair in chain.windows(2) {
        pair[0]
            .validate_successor(&pair[1], DeploymentBranchV2::Normal)
            .map_err(|_| DeploymentControlErrorV2::InvalidCompactedTransactionProvenance)?;
    }
    Ok(())
}

fn predecessor_chain_digest(
    chain: &[DurableDeploymentTransactionRecordV2],
) -> Result<Digest32V2, DeploymentControlErrorV2> {
    let predecessor_count = chain
        .len()
        .checked_sub(1)
        .ok_or(DeploymentControlErrorV2::InvalidCompactedTransactionProvenance)?;
    let mut hasher = Sha256::new();
    hasher.update(TRANSACTION_PREDECESSOR_CHAIN_DOMAIN_V2);
    hasher.update(
        u64::try_from(predecessor_count)
            .map_err(|_| DeploymentControlErrorV2::InvalidCompactedTransactionProvenance)?
            .to_be_bytes(),
    );
    for head in &chain[..predecessor_count] {
        hasher.update(head.signed_digest().as_bytes());
    }
    Ok(Digest32V2::new(hasher.finalize().into()))
}

fn encode_complete_checkpoint(
    value: &DecodedEvidenceGcCheckpointV2,
) -> Result<Vec<u8>, DeploymentControlErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(CHECKPOINT_COMPLETE_FIELDS_V2)
        .map_err(|_| DeploymentControlErrorV2::InvalidEvidenceGcCheckpoint)?;
    encode_checkpoint_fields(&mut encoder, value)?;
    encode_signature(&mut encoder, value.signature)?;
    Ok(encoder.into_writer())
}

fn encode_checkpoint_payload(
    value: &DecodedEvidenceGcCheckpointV2,
) -> Result<Vec<u8>, DeploymentControlErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(CHECKPOINT_PAYLOAD_FIELDS_V2)
        .map_err(|_| DeploymentControlErrorV2::InvalidEvidenceGcCheckpoint)?;
    encode_checkpoint_fields(&mut encoder, value)?;
    Ok(encoder.into_writer())
}

fn encode_checkpoint_fields(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    value: &DecodedEvidenceGcCheckpointV2,
) -> Result<(), DeploymentControlErrorV2> {
    encoder
        .bytes(value.installation_id.as_bytes())
        .and_then(|encoder| encoder.u64(value.installation_epoch))
        .and_then(|encoder| encoder.bytes(value.window.pruned_prefix_last_digest().as_bytes()))
        .and_then(|encoder| encoder.bytes(value.window.retained_first_digest().as_bytes()))
        .and_then(|encoder| encoder.bytes(value.window.retained_last_digest().as_bytes()))
        .and_then(|encoder| encoder.u64(value.window.retained_count()))
        .and_then(|encoder| encoder.bytes(value.window.gc_policy_digest().as_bytes()))
        .map_err(|_| DeploymentControlErrorV2::InvalidEvidenceGcCheckpoint)?;
    encode_provenance(encoder, value.compacted_transaction_provenance)?;
    encoder
        .u64(value.window.completed_at_unix_ms())
        .and_then(|encoder| encoder.bytes(value.activation_key_id.as_bytes()))
        .map(|_| ())
        .map_err(|_| DeploymentControlErrorV2::InvalidEvidenceGcCheckpoint)
}

fn encode_provenance(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    value: CompactedTransactionProvenanceV2,
) -> Result<(), DeploymentControlErrorV2> {
    match value {
        CompactedTransactionProvenanceV2::None => encoder
            .array(1)
            .and_then(|encoder| encoder.u16(0))
            .map(|_| ())
            .map_err(|_| DeploymentControlErrorV2::InvalidEvidenceGcCheckpoint),
        CompactedTransactionProvenanceV2::Aborted {
            aborted_ledger_record_digest,
            transaction_core_signed_digest,
            final_transaction_head_signed_digest,
            predecessor_chain_digest,
        } => encoder
            .array(ABORTED_PROVENANCE_FIELDS_V2)
            .and_then(|encoder| encoder.u16(1))
            .and_then(|encoder| encoder.bytes(aborted_ledger_record_digest.as_bytes()))
            .and_then(|encoder| encoder.bytes(transaction_core_signed_digest.as_bytes()))
            .and_then(|encoder| encoder.bytes(final_transaction_head_signed_digest.as_bytes()))
            .and_then(|encoder| encoder.bytes(predecessor_chain_digest.as_bytes()))
            .map(|_| ())
            .map_err(|_| DeploymentControlErrorV2::InvalidEvidenceGcCheckpoint),
    }
}

fn encode_signature(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    value: CheckpointSignatureV2,
) -> Result<(), DeploymentControlErrorV2> {
    encoder
        .array(DOMAIN_SIGNATURE_FIELDS_V2)
        .and_then(|encoder| encoder.u16(value.domain_tag))
        .and_then(|encoder| encoder.bytes(value.signer_key_id.as_bytes()))
        .and_then(|encoder| encoder.u64(value.signer_key_epoch))
        .and_then(|encoder| encoder.bytes(value.signature.as_bytes()))
        .map(|_| ())
        .map_err(|_| DeploymentControlErrorV2::InvalidEvidenceGcCheckpoint)
}

fn decode_checkpoint(
    bytes: &[u8],
) -> Result<DecodedEvidenceGcCheckpointV2, DeploymentControlErrorV2> {
    let mut decoder = minicbor::Decoder::new(bytes);
    expect_array(&mut decoder, CHECKPOINT_COMPLETE_FIELDS_V2)?;
    let installation_id = decode_digest(&mut decoder)?;
    let installation_epoch = decode_u64(&mut decoder)?;
    let pruned_prefix_last_digest = decode_digest(&mut decoder)?;
    let retained_first_digest = decode_digest(&mut decoder)?;
    let retained_last_digest = decode_digest(&mut decoder)?;
    let retained_count = decode_u64(&mut decoder)?;
    let gc_policy_digest = decode_digest(&mut decoder)?;
    let compacted_transaction_provenance = decode_provenance(&mut decoder)?;
    let completed_at_unix_ms = decode_u64(&mut decoder)?;
    let activation_key_id = decode_key_id(&mut decoder)?;
    let signature = decode_signature(&mut decoder)?;
    if decoder.position() != bytes.len() {
        return Err(DeploymentControlErrorV2::InvalidEvidenceGcCheckpoint);
    }
    Ok(DecodedEvidenceGcCheckpointV2 {
        installation_id,
        installation_epoch,
        window: EvidenceGcWindowV2 {
            pruned_prefix_last_digest,
            retained_first_digest,
            retained_last_digest,
            retained_count,
            gc_policy_digest,
            completed_at_unix_ms,
        },
        compacted_transaction_provenance,
        activation_key_id,
        signature,
    })
}

fn decode_provenance(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<CompactedTransactionProvenanceV2, DeploymentControlErrorV2> {
    let length = decoder
        .array()
        .map_err(|_| DeploymentControlErrorV2::InvalidEvidenceGcCheckpoint)?;
    match (decode_u16(decoder)?, length) {
        (0, Some(1)) => Ok(CompactedTransactionProvenanceV2::None),
        (1, Some(ABORTED_PROVENANCE_FIELDS_V2)) => Ok(CompactedTransactionProvenanceV2::Aborted {
            aborted_ledger_record_digest: decode_digest(decoder)?,
            transaction_core_signed_digest: decode_digest(decoder)?,
            final_transaction_head_signed_digest: decode_digest(decoder)?,
            predecessor_chain_digest: decode_digest(decoder)?,
        }),
        _ => Err(DeploymentControlErrorV2::InvalidEvidenceGcCheckpoint),
    }
}

fn decode_signature(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<CheckpointSignatureV2, DeploymentControlErrorV2> {
    expect_array(decoder, DOMAIN_SIGNATURE_FIELDS_V2)?;
    Ok(CheckpointSignatureV2 {
        domain_tag: decode_u16(decoder)?,
        signer_key_id: decode_key_id(decoder)?,
        signer_key_epoch: decode_u64(decoder)?,
        signature: Ed25519SignatureV2::new(decode_fixed_bytes::<64>(decoder)?),
    })
}

fn expect_array(
    decoder: &mut minicbor::Decoder<'_>,
    expected: u64,
) -> Result<(), DeploymentControlErrorV2> {
    if decoder
        .array()
        .map_err(|_| DeploymentControlErrorV2::InvalidEvidenceGcCheckpoint)?
        != Some(expected)
    {
        return Err(DeploymentControlErrorV2::InvalidEvidenceGcCheckpoint);
    }
    Ok(())
}

fn decode_u16(decoder: &mut minicbor::Decoder<'_>) -> Result<u16, DeploymentControlErrorV2> {
    decoder
        .u16()
        .map_err(|_| DeploymentControlErrorV2::InvalidEvidenceGcCheckpoint)
}

fn decode_u64(decoder: &mut minicbor::Decoder<'_>) -> Result<u64, DeploymentControlErrorV2> {
    decoder
        .u64()
        .map_err(|_| DeploymentControlErrorV2::InvalidEvidenceGcCheckpoint)
}

fn decode_digest(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<Digest32V2, DeploymentControlErrorV2> {
    Ok(Digest32V2::new(decode_fixed_bytes::<32>(decoder)?))
}

fn decode_key_id(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<Ed25519KeyIdV2, DeploymentControlErrorV2> {
    Ok(Ed25519KeyIdV2::new(decode_fixed_bytes::<32>(decoder)?))
}

fn decode_fixed_bytes<const N: usize>(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<[u8; N], DeploymentControlErrorV2> {
    let bytes = decoder
        .bytes()
        .map_err(|_| DeploymentControlErrorV2::InvalidEvidenceGcCheckpoint)?;
    bytes
        .try_into()
        .map_err(|_| DeploymentControlErrorV2::InvalidEvidenceGcCheckpoint)
}

fn hash_domain(domain: &[u8], bytes: &[u8]) -> Digest32V2 {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    Digest32V2::new(hasher.finalize().into())
}

fn is_zero(value: &[u8]) -> bool {
    value.iter().all(|byte| *byte == 0)
}
