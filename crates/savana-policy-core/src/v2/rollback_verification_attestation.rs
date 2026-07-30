use savana_kernel_protocol::v2::{Digest32V2, Ed25519KeyIdV2, Ed25519SignatureV2, Nonce32V2};
use savana_platform_identity::{
    NativeDeploymentSignatureDomainV2, NativeDeploymentSignatureRequestV2,
    NativeDeploymentSigningAuthorityV2,
};
use sha2::{Digest as _, Sha256};

use super::{
    ActiveActivationV2, DeploymentActivationVerifierV2, DeploymentControlErrorV2, PlatformLockV2,
    RollbackGrantStateV2, RollbackOriginPhaseV2,
};

const SCHEMA_VERSION: u16 = 2;
const COMPLETE_FIELDS: u64 = 33;
const PAYLOAD_FIELDS: u64 = 32;
const SIGNATURE_FIELDS: u64 = 4;
const SIGNATURE_TAG: u16 = 18;
const PAYLOAD_DOMAIN: &[u8] = b"savana.rollback-verification-attestation.v2.payload\0";
const SIGNATURE_DOMAIN: &[u8] = b"savana.rollback-verification-attestation.v2.signature\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u16)]
pub enum ClosedRollbackAttestationDigestFieldV2 {
    EvidenceTrustPolicy = 1,
    EvidenceLayerLimits = 2,
    SourceEvidence = 3,
    ArtifactEvidence = 4,
    InstallationId = 5,
    TransactionIntent = 6,
    TransactionPayload = 7,
    RolledBackRecordPayload = 8,
    AttemptedManifest = 9,
    ActiveRollbackManifest = 10,
    RolledBackHighestEver = 11,
    RollbackGrant = 12,
    AttemptedSourceLock = 13,
    AttemptedProtocolLock = 14,
    AttemptedPlatformClosure = 15,
    ActiveRollbackSourceLock = 16,
    ActiveRollbackProtocolLock = 17,
    ActiveRollbackPlatformClosure = 18,
    InstallationEpochAttestation = 19,
}

impl ClosedRollbackAttestationDigestFieldV2 {
    pub const ALL: [Self; 19] = [
        Self::EvidenceTrustPolicy,
        Self::EvidenceLayerLimits,
        Self::SourceEvidence,
        Self::ArtifactEvidence,
        Self::InstallationId,
        Self::TransactionIntent,
        Self::TransactionPayload,
        Self::RolledBackRecordPayload,
        Self::AttemptedManifest,
        Self::ActiveRollbackManifest,
        Self::RolledBackHighestEver,
        Self::RollbackGrant,
        Self::AttemptedSourceLock,
        Self::AttemptedProtocolLock,
        Self::AttemptedPlatformClosure,
        Self::ActiveRollbackSourceLock,
        Self::ActiveRollbackProtocolLock,
        Self::ActiveRollbackPlatformClosure,
        Self::InstallationEpochAttestation,
    ];

    const fn index(self) -> usize {
        self as usize - 1
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RollbackTerminalReadinessRefV2 {
    VerifiedOrigin {
        candidate_verification_evidence_digest: Digest32V2,
        rollback_verification_evidence_digest: Digest32V2,
    },
    RecoveryOrigin {
        recovery_rollback_readiness_evidence_digest: Digest32V2,
    },
}

impl RollbackTerminalReadinessRefV2 {
    fn validate(self, origin: RollbackOriginPhaseV2) -> Result<(), DeploymentControlErrorV2> {
        let valid = match self {
            Self::VerifiedOrigin {
                candidate_verification_evidence_digest,
                rollback_verification_evidence_digest,
            } => {
                origin == RollbackOriginPhaseV2::Verified
                    && !is_zero(candidate_verification_evidence_digest.as_bytes())
                    && !is_zero(rollback_verification_evidence_digest.as_bytes())
            }
            Self::RecoveryOrigin {
                recovery_rollback_readiness_evidence_digest,
            } => {
                matches!(
                    origin,
                    RollbackOriginPhaseV2::Armed
                        | RollbackOriginPhaseV2::Quiesced
                        | RollbackOriginPhaseV2::Installed
                ) && !is_zero(recovery_rollback_readiness_evidence_digest.as_bytes())
            }
        };
        if !valid {
            return Err(DeploymentControlErrorV2::InvalidRollbackVerificationAttestation);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EvidenceSignature {
    domain_tag: u16,
    key_id: Ed25519KeyIdV2,
    key_epoch: u64,
    signature: Ed25519SignatureV2,
}

#[derive(Clone, PartialEq, Eq)]
pub struct RollbackVerificationAttestationV2 {
    canonical_bytes: Vec<u8>,
    digests: [Digest32V2; 19],
    installation_epoch: u64,
    platform: PlatformLockV2,
    transaction_id: Nonce32V2,
    terminal_readiness: RollbackTerminalReadinessRefV2,
    rolled_back_ledger_generation: u64,
    rolled_back_effect_fence_epoch: u64,
    rollback_origin_phase: RollbackOriginPhaseV2,
    rolled_back_at_unix_ms: u64,
    activation_key_id: Ed25519KeyIdV2,
    payload_digest: Digest32V2,
}

impl std::fmt::Debug for RollbackVerificationAttestationV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RollbackVerificationAttestationV2")
            .field(
                "rolled_back_ledger_generation",
                &self.rolled_back_ledger_generation,
            )
            .field("rollback_origin_phase", &self.rollback_origin_phase)
            .field("rolled_back_at_unix_ms", &self.rolled_back_at_unix_ms)
            .field("payload_digest", &self.payload_digest)
            .finish_non_exhaustive()
    }
}

impl RollbackVerificationAttestationV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn new_signed_with_authority(
        digests: [Digest32V2; 19],
        installation_epoch: u64,
        platform: PlatformLockV2,
        transaction_id: Nonce32V2,
        terminal_readiness: RollbackTerminalReadinessRefV2,
        rolled_back_ledger_generation: u64,
        rolled_back_effect_fence_epoch: u64,
        rollback_origin_phase: RollbackOriginPhaseV2,
        rolled_back_at_unix_ms: u64,
        authority: &mut dyn NativeDeploymentSigningAuthorityV2,
        verifier: &DeploymentActivationVerifierV2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        let installation_id =
            digests[ClosedRollbackAttestationDigestFieldV2::InstallationId.index()];
        let activation_key_id = Ed25519KeyIdV2::new(authority.key_id());
        if authority.installation_id() != *installation_id.as_bytes()
            || authority.key_epoch() != installation_epoch
            || verifier.installation_id() != installation_id
            || verifier.key_epoch() != installation_epoch
            || verifier.key_id() != activation_key_id
        {
            return Err(DeploymentControlErrorV2::ActivationKeyMismatch);
        }
        let mut decoded = Decoded {
            schema_version: SCHEMA_VERSION,
            digests,
            installation_epoch,
            platform,
            transaction_id,
            terminal_readiness,
            rolled_back_ledger_generation,
            rolled_back_effect_fence_epoch,
            rollback_origin_phase,
            rolled_back_at_unix_ms,
            activation_key_id,
            signature: EvidenceSignature {
                domain_tag: SIGNATURE_TAG,
                key_id: activation_key_id,
                key_epoch: installation_epoch,
                signature: Ed25519SignatureV2::new([1; 64]),
            },
        };
        decoded.validate(verifier)?;
        let payload_digest = hash_domain(PAYLOAD_DOMAIN, &encode_payload(&decoded)?);
        let request = NativeDeploymentSignatureRequestV2::new(
            NativeDeploymentSignatureDomainV2::RollbackVerificationAttestation,
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
        Self::from_canonical_bytes(&encode_complete(&decoded)?, verifier)
    }

    pub fn from_canonical_bytes(
        bytes: &[u8],
        verifier: &DeploymentActivationVerifierV2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        if bytes.is_empty() || bytes.len() > 16 * 1024 {
            return Err(DeploymentControlErrorV2::InvalidRollbackVerificationAttestation);
        }
        let decoded = decode_complete(bytes)?;
        decoded.validate(verifier)?;
        if encode_complete(&decoded)? != bytes {
            return Err(DeploymentControlErrorV2::NonCanonicalLedgerEncoding);
        }
        let payload_digest = hash_domain(PAYLOAD_DOMAIN, &encode_payload(&decoded)?);
        verifier.verify_domain_signature_parts(
            decoded.signature.domain_tag,
            decoded.signature.key_id,
            decoded.signature.key_epoch,
            decoded.signature.signature,
            SIGNATURE_TAG,
            SIGNATURE_DOMAIN,
            payload_digest,
        )?;
        Ok(Self {
            canonical_bytes: bytes.to_vec(),
            digests: decoded.digests,
            installation_epoch: decoded.installation_epoch,
            platform: decoded.platform,
            transaction_id: decoded.transaction_id,
            terminal_readiness: decoded.terminal_readiness,
            rolled_back_ledger_generation: decoded.rolled_back_ledger_generation,
            rolled_back_effect_fence_epoch: decoded.rolled_back_effect_fence_epoch,
            rollback_origin_phase: decoded.rollback_origin_phase,
            rolled_back_at_unix_ms: decoded.rolled_back_at_unix_ms,
            activation_key_id: decoded.activation_key_id,
            payload_digest,
        })
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub const fn digest_field(&self, field: ClosedRollbackAttestationDigestFieldV2) -> Digest32V2 {
        self.digests[field.index()]
    }

    pub const fn installation_id(&self) -> Digest32V2 {
        self.digest_field(ClosedRollbackAttestationDigestFieldV2::InstallationId)
    }

    pub const fn installation_epoch(&self) -> u64 {
        self.installation_epoch
    }

    pub const fn platform(&self) -> &PlatformLockV2 {
        &self.platform
    }

    pub const fn transaction_id(&self) -> Nonce32V2 {
        self.transaction_id
    }

    pub const fn terminal_readiness(&self) -> RollbackTerminalReadinessRefV2 {
        self.terminal_readiness
    }

    pub const fn rolled_back_ledger_generation(&self) -> u64 {
        self.rolled_back_ledger_generation
    }

    pub const fn rolled_back_effect_fence_epoch(&self) -> u64 {
        self.rolled_back_effect_fence_epoch
    }

    pub const fn rollback_origin_phase(&self) -> RollbackOriginPhaseV2 {
        self.rollback_origin_phase
    }

    pub const fn rolled_back_at_unix_ms(&self) -> u64 {
        self.rolled_back_at_unix_ms
    }

    pub const fn activation_key_id(&self) -> Ed25519KeyIdV2 {
        self.activation_key_id
    }

    pub const fn payload_digest(&self) -> Digest32V2 {
        self.payload_digest
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Decoded {
    schema_version: u16,
    digests: [Digest32V2; 19],
    installation_epoch: u64,
    platform: PlatformLockV2,
    transaction_id: Nonce32V2,
    terminal_readiness: RollbackTerminalReadinessRefV2,
    rolled_back_ledger_generation: u64,
    rolled_back_effect_fence_epoch: u64,
    rollback_origin_phase: RollbackOriginPhaseV2,
    rolled_back_at_unix_ms: u64,
    activation_key_id: Ed25519KeyIdV2,
    signature: EvidenceSignature,
}

impl Decoded {
    fn validate(
        &self,
        verifier: &DeploymentActivationVerifierV2,
    ) -> Result<(), DeploymentControlErrorV2> {
        self.terminal_readiness
            .validate(self.rollback_origin_phase)?;
        if self.schema_version != SCHEMA_VERSION
            || self.installation_epoch == 0
            || self.rolled_back_ledger_generation == 0
            || self.rolled_back_effect_fence_epoch == 0
            || self.rolled_back_at_unix_ms == 0
            || self.digests.iter().any(|value| is_zero(value.as_bytes()))
            || is_zero(self.transaction_id.as_bytes())
            || self.digests[ClosedRollbackAttestationDigestFieldV2::InstallationId.index()]
                != verifier.installation_id()
            || self.installation_epoch != verifier.key_epoch()
            || self.activation_key_id != verifier.key_id()
            || self.signature.domain_tag != SIGNATURE_TAG
            || self.signature.key_id != self.activation_key_id
            || self.signature.key_epoch != self.installation_epoch
            || is_zero(self.signature.signature.as_bytes())
        {
            return Err(DeploymentControlErrorV2::InvalidRollbackVerificationAttestation);
        }
        Ok(())
    }

    fn active_activation(&self) -> ActiveActivationV2 {
        ActiveActivationV2::ConsumedRollback {
            failed_transaction_id: self.transaction_id,
            rollback_grant_id: self.digests
                [ClosedRollbackAttestationDigestFieldV2::RollbackGrant.index()],
        }
    }
}

fn encode_payload(value: &Decoded) -> Result<Vec<u8>, DeploymentControlErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encode_fields(&mut encoder, value, PAYLOAD_FIELDS)?;
    Ok(encoder.into_writer())
}

fn encode_complete(value: &Decoded) -> Result<Vec<u8>, DeploymentControlErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encode_fields(&mut encoder, value, COMPLETE_FIELDS)?;
    encode_signature(&mut encoder, value.signature)?;
    Ok(encoder.into_writer())
}

fn encode_fields(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    value: &Decoded,
    count: u64,
) -> Result<(), DeploymentControlErrorV2> {
    encoder
        .array(count)
        .and_then(|encoder| encoder.u16(value.schema_version))
        .map_err(|_| DeploymentControlErrorV2::InvalidRollbackVerificationAttestation)?;
    for field in &ClosedRollbackAttestationDigestFieldV2::ALL[..5] {
        put_digest(encoder, value.digests[field.index()])?;
    }
    encoder
        .u64(value.installation_epoch)
        .map_err(|_| DeploymentControlErrorV2::InvalidRollbackVerificationAttestation)?;
    encoder
        .writer_mut()
        .extend_from_slice(value.platform.canonical_bytes());
    encoder
        .bytes(value.transaction_id.as_bytes())
        .map_err(|_| DeploymentControlErrorV2::InvalidRollbackVerificationAttestation)?;
    for field in &ClosedRollbackAttestationDigestFieldV2::ALL[5..7] {
        put_digest(encoder, value.digests[field.index()])?;
    }
    encode_terminal_readiness(encoder, value.terminal_readiness)?;
    encoder
        .u64(value.rolled_back_ledger_generation)
        .map_err(|_| DeploymentControlErrorV2::InvalidRollbackVerificationAttestation)?;
    for field in &ClosedRollbackAttestationDigestFieldV2::ALL[7..11] {
        put_digest(encoder, value.digests[field.index()])?;
    }
    encoder
        .u64(value.rolled_back_effect_fence_epoch)
        .and_then(|encoder| encoder.bool(false))
        .map_err(|_| DeploymentControlErrorV2::InvalidRollbackVerificationAttestation)?;
    put_digest(
        encoder,
        value.digests[ClosedRollbackAttestationDigestFieldV2::RollbackGrant.index()],
    )?;
    encoder
        .u16(RollbackGrantStateV2::Consumed as u16)
        .map_err(|_| DeploymentControlErrorV2::InvalidRollbackVerificationAttestation)?;
    encoder
        .writer_mut()
        .extend_from_slice(&value.active_activation().canonical_bytes()?);
    encoder
        .u16(value.rollback_origin_phase as u16)
        .map_err(|_| DeploymentControlErrorV2::InvalidRollbackVerificationAttestation)?;
    for field in &ClosedRollbackAttestationDigestFieldV2::ALL[12..] {
        put_digest(encoder, value.digests[field.index()])?;
    }
    encoder
        .u64(value.rolled_back_at_unix_ms)
        .and_then(|encoder| encoder.bytes(value.activation_key_id.as_bytes()))
        .map_err(|_| DeploymentControlErrorV2::InvalidRollbackVerificationAttestation)?;
    Ok(())
}

fn decode_complete(bytes: &[u8]) -> Result<Decoded, DeploymentControlErrorV2> {
    let mut decoder = minicbor::Decoder::new(bytes);
    expect_array(&mut decoder, COMPLETE_FIELDS)?;
    let schema_version = get_u16(&mut decoder)?;
    let mut digests = [Digest32V2::new([0; 32]); 19];
    for field in &ClosedRollbackAttestationDigestFieldV2::ALL[..5] {
        digests[field.index()] = get_digest(&mut decoder)?;
    }
    let installation_epoch = get_u64(&mut decoder)?;
    let platform = nested(&mut decoder, PlatformLockV2::from_canonical_bytes)?;
    let transaction_id = Nonce32V2::new(get_fixed::<32>(&mut decoder)?);
    for field in &ClosedRollbackAttestationDigestFieldV2::ALL[5..7] {
        digests[field.index()] = get_digest(&mut decoder)?;
    }
    let terminal_readiness = decode_terminal_readiness(&mut decoder)?;
    let rolled_back_ledger_generation = get_u64(&mut decoder)?;
    for field in &ClosedRollbackAttestationDigestFieldV2::ALL[7..11] {
        digests[field.index()] = get_digest(&mut decoder)?;
    }
    let rolled_back_effect_fence_epoch = get_u64(&mut decoder)?;
    if decoder
        .bool()
        .map_err(|_| DeploymentControlErrorV2::InvalidRollbackVerificationAttestation)?
    {
        return Err(DeploymentControlErrorV2::InvalidRollbackVerificationAttestation);
    }
    digests[ClosedRollbackAttestationDigestFieldV2::RollbackGrant.index()] =
        get_digest(&mut decoder)?;
    if get_u16(&mut decoder)? != RollbackGrantStateV2::Consumed as u16 {
        return Err(DeploymentControlErrorV2::InvalidRollbackVerificationAttestation);
    }
    let active_activation = nested(&mut decoder, ActiveActivationV2::from_canonical_bytes)?;
    let rollback_origin_phase = decode_origin(&mut decoder)?;
    for field in &ClosedRollbackAttestationDigestFieldV2::ALL[12..] {
        digests[field.index()] = get_digest(&mut decoder)?;
    }
    let rolled_back_at_unix_ms = get_u64(&mut decoder)?;
    let activation_key_id = Ed25519KeyIdV2::new(get_fixed::<32>(&mut decoder)?);
    let signature = decode_signature(&mut decoder)?;
    if decoder.position() != bytes.len() {
        return Err(DeploymentControlErrorV2::InvalidRollbackVerificationAttestation);
    }
    let decoded = Decoded {
        schema_version,
        digests,
        installation_epoch,
        platform,
        transaction_id,
        terminal_readiness,
        rolled_back_ledger_generation,
        rolled_back_effect_fence_epoch,
        rollback_origin_phase,
        rolled_back_at_unix_ms,
        activation_key_id,
        signature,
    };
    if active_activation != decoded.active_activation() {
        return Err(DeploymentControlErrorV2::InvalidRollbackVerificationAttestation);
    }
    Ok(decoded)
}

fn encode_terminal_readiness(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    value: RollbackTerminalReadinessRefV2,
) -> Result<(), DeploymentControlErrorV2> {
    match value {
        RollbackTerminalReadinessRefV2::VerifiedOrigin {
            candidate_verification_evidence_digest,
            rollback_verification_evidence_digest,
        } => {
            encoder
                .array(3)
                .and_then(|encoder| encoder.u16(1))
                .map_err(|_| DeploymentControlErrorV2::InvalidRollbackVerificationAttestation)?;
            put_digest(encoder, candidate_verification_evidence_digest)?;
            put_digest(encoder, rollback_verification_evidence_digest)?;
        }
        RollbackTerminalReadinessRefV2::RecoveryOrigin {
            recovery_rollback_readiness_evidence_digest,
        } => {
            encoder
                .array(2)
                .and_then(|encoder| encoder.u16(2))
                .map_err(|_| DeploymentControlErrorV2::InvalidRollbackVerificationAttestation)?;
            put_digest(encoder, recovery_rollback_readiness_evidence_digest)?;
        }
    }
    Ok(())
}

fn decode_terminal_readiness(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<RollbackTerminalReadinessRefV2, DeploymentControlErrorV2> {
    let length = decoder
        .array()
        .map_err(|_| DeploymentControlErrorV2::InvalidRollbackVerificationAttestation)?
        .ok_or(DeploymentControlErrorV2::InvalidRollbackVerificationAttestation)?;
    match (get_u16(decoder)?, length) {
        (1, 3) => Ok(RollbackTerminalReadinessRefV2::VerifiedOrigin {
            candidate_verification_evidence_digest: get_digest(decoder)?,
            rollback_verification_evidence_digest: get_digest(decoder)?,
        }),
        (2, 2) => Ok(RollbackTerminalReadinessRefV2::RecoveryOrigin {
            recovery_rollback_readiness_evidence_digest: get_digest(decoder)?,
        }),
        _ => Err(DeploymentControlErrorV2::InvalidRollbackVerificationAttestation),
    }
}

fn decode_origin(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<RollbackOriginPhaseV2, DeploymentControlErrorV2> {
    match get_u16(decoder)? {
        1 => Ok(RollbackOriginPhaseV2::Armed),
        2 => Ok(RollbackOriginPhaseV2::Quiesced),
        3 => Ok(RollbackOriginPhaseV2::Installed),
        4 => Ok(RollbackOriginPhaseV2::Verified),
        _ => Err(DeploymentControlErrorV2::InvalidRollbackVerificationAttestation),
    }
}

fn put_digest(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    value: Digest32V2,
) -> Result<(), DeploymentControlErrorV2> {
    encoder
        .bytes(value.as_bytes())
        .map_err(|_| DeploymentControlErrorV2::InvalidRollbackVerificationAttestation)?;
    Ok(())
}

fn encode_signature(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    value: EvidenceSignature,
) -> Result<(), DeploymentControlErrorV2> {
    encoder
        .array(SIGNATURE_FIELDS)
        .and_then(|encoder| encoder.u16(value.domain_tag))
        .and_then(|encoder| encoder.bytes(value.key_id.as_bytes()))
        .and_then(|encoder| encoder.u64(value.key_epoch))
        .and_then(|encoder| encoder.bytes(value.signature.as_bytes()))
        .map_err(|_| DeploymentControlErrorV2::InvalidRollbackVerificationAttestation)?;
    Ok(())
}

fn decode_signature(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<EvidenceSignature, DeploymentControlErrorV2> {
    expect_array(decoder, SIGNATURE_FIELDS)?;
    Ok(EvidenceSignature {
        domain_tag: get_u16(decoder)?,
        key_id: Ed25519KeyIdV2::new(get_fixed::<32>(decoder)?),
        key_epoch: get_u64(decoder)?,
        signature: Ed25519SignatureV2::new(get_fixed::<64>(decoder)?),
    })
}

fn nested<T>(
    decoder: &mut minicbor::Decoder<'_>,
    decode: impl FnOnce(&[u8]) -> Result<T, DeploymentControlErrorV2>,
) -> Result<T, DeploymentControlErrorV2> {
    let start = decoder.position();
    decoder
        .skip()
        .map_err(|_| DeploymentControlErrorV2::InvalidRollbackVerificationAttestation)?;
    decode(
        decoder
            .input()
            .get(start..decoder.position())
            .ok_or(DeploymentControlErrorV2::InvalidRollbackVerificationAttestation)?,
    )
}

fn expect_array(
    decoder: &mut minicbor::Decoder<'_>,
    expected: u64,
) -> Result<(), DeploymentControlErrorV2> {
    if decoder
        .array()
        .map_err(|_| DeploymentControlErrorV2::InvalidRollbackVerificationAttestation)?
        != Some(expected)
    {
        return Err(DeploymentControlErrorV2::InvalidRollbackVerificationAttestation);
    }
    Ok(())
}

fn get_u16(decoder: &mut minicbor::Decoder<'_>) -> Result<u16, DeploymentControlErrorV2> {
    decoder
        .u16()
        .map_err(|_| DeploymentControlErrorV2::InvalidRollbackVerificationAttestation)
}

fn get_u64(decoder: &mut minicbor::Decoder<'_>) -> Result<u64, DeploymentControlErrorV2> {
    decoder
        .u64()
        .map_err(|_| DeploymentControlErrorV2::InvalidRollbackVerificationAttestation)
}

fn get_digest(decoder: &mut minicbor::Decoder<'_>) -> Result<Digest32V2, DeploymentControlErrorV2> {
    Ok(Digest32V2::new(get_fixed::<32>(decoder)?))
}

fn get_fixed<const N: usize>(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<[u8; N], DeploymentControlErrorV2> {
    decoder
        .bytes()
        .map_err(|_| DeploymentControlErrorV2::InvalidRollbackVerificationAttestation)?
        .try_into()
        .map_err(|_| DeploymentControlErrorV2::InvalidRollbackVerificationAttestation)
}

fn hash_domain(domain: &[u8], bytes: &[u8]) -> Digest32V2 {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(bytes);
    Digest32V2::new(hash.finalize().into())
}

fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|value| *value == 0)
}
