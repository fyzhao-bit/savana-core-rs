use savana_kernel_protocol::v2::{Digest32V2, Ed25519KeyIdV2, Ed25519SignatureV2, Nonce32V2};
use savana_platform_identity::{
    NativeDeploymentSignatureDomainV2, NativeDeploymentSignatureRequestV2,
    NativeDeploymentSigningAuthorityV2,
};
use sha2::{Digest as _, Sha256};

use super::{
    ActiveActivationV2, DeploymentActivationVerifierV2, DeploymentControlErrorV2, PlatformLockV2,
    RollbackGrantStateV2,
};

const SCHEMA_VERSION: u16 = 2;
const COMPLETE_FIELDS: u64 = 28;
const PAYLOAD_FIELDS: u64 = 27;
const SIGNATURE_FIELDS: u64 = 4;
const SIGNATURE_TAG: u16 = 10;
const PAYLOAD_DOMAIN: &[u8] = b"savana.commit-attestation.v2.payload\0";
const SIGNATURE_DOMAIN: &[u8] = b"savana.commit-attestation.v2.signature\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u16)]
pub enum ClosedCommitDigestFieldV2 {
    EvidenceTrustPolicy = 1,
    EvidenceLayerLimits = 2,
    SourceEvidence = 3,
    ArtifactEvidence = 4,
    InstallationId = 5,
    TransactionIntent = 6,
    TransactionPayload = 7,
    VerificationEvidence = 8,
    CommittedRecordPayload = 9,
    CommittedManifest = 10,
    CommittedHighestEver = 11,
    RollbackGrant = 12,
    SourceLock = 13,
    ProtocolLock = 14,
    PlatformClosure = 15,
    InstallationEpochAttestation = 16,
}

impl ClosedCommitDigestFieldV2 {
    pub const ALL: [Self; 16] = [
        Self::EvidenceTrustPolicy,
        Self::EvidenceLayerLimits,
        Self::SourceEvidence,
        Self::ArtifactEvidence,
        Self::InstallationId,
        Self::TransactionIntent,
        Self::TransactionPayload,
        Self::VerificationEvidence,
        Self::CommittedRecordPayload,
        Self::CommittedManifest,
        Self::CommittedHighestEver,
        Self::RollbackGrant,
        Self::SourceLock,
        Self::ProtocolLock,
        Self::PlatformClosure,
        Self::InstallationEpochAttestation,
    ];

    const fn index(self) -> usize {
        self as usize - 1
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
pub struct CommitAttestationV2 {
    canonical_bytes: Vec<u8>,
    digests: [Digest32V2; 16],
    installation_epoch: u64,
    platform: PlatformLockV2,
    transaction_id: Nonce32V2,
    committed_ledger_generation: u64,
    committed_effect_fence_epoch: u64,
    committed_at_unix_ms: u64,
    activation_key_id: Ed25519KeyIdV2,
    payload_digest: Digest32V2,
}

impl std::fmt::Debug for CommitAttestationV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CommitAttestationV2")
            .field(
                "committed_ledger_generation",
                &self.committed_ledger_generation,
            )
            .field("committed_at_unix_ms", &self.committed_at_unix_ms)
            .field("payload_digest", &self.payload_digest)
            .finish_non_exhaustive()
    }
}

impl CommitAttestationV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn new_signed_with_authority(
        digests: [Digest32V2; 16],
        installation_epoch: u64,
        platform: PlatformLockV2,
        transaction_id: Nonce32V2,
        committed_ledger_generation: u64,
        committed_effect_fence_epoch: u64,
        committed_at_unix_ms: u64,
        authority: &mut dyn NativeDeploymentSigningAuthorityV2,
        verifier: &DeploymentActivationVerifierV2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        let installation_id = digests[ClosedCommitDigestFieldV2::InstallationId.index()];
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
            committed_ledger_generation,
            committed_effect_fence_epoch,
            committed_at_unix_ms,
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
            NativeDeploymentSignatureDomainV2::CommitAttestation,
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
            return Err(DeploymentControlErrorV2::InvalidCommitAttestation);
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
            committed_ledger_generation: decoded.committed_ledger_generation,
            committed_effect_fence_epoch: decoded.committed_effect_fence_epoch,
            committed_at_unix_ms: decoded.committed_at_unix_ms,
            activation_key_id: decoded.activation_key_id,
            payload_digest,
        })
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub const fn digest_field(&self, field: ClosedCommitDigestFieldV2) -> Digest32V2 {
        self.digests[field.index()]
    }

    pub const fn installation_id(&self) -> Digest32V2 {
        self.digest_field(ClosedCommitDigestFieldV2::InstallationId)
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

    pub const fn committed_ledger_generation(&self) -> u64 {
        self.committed_ledger_generation
    }

    pub const fn committed_effect_fence_epoch(&self) -> u64 {
        self.committed_effect_fence_epoch
    }

    pub const fn committed_at_unix_ms(&self) -> u64 {
        self.committed_at_unix_ms
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
    digests: [Digest32V2; 16],
    installation_epoch: u64,
    platform: PlatformLockV2,
    transaction_id: Nonce32V2,
    committed_ledger_generation: u64,
    committed_effect_fence_epoch: u64,
    committed_at_unix_ms: u64,
    activation_key_id: Ed25519KeyIdV2,
    signature: EvidenceSignature,
}

impl Decoded {
    fn validate(
        &self,
        verifier: &DeploymentActivationVerifierV2,
    ) -> Result<(), DeploymentControlErrorV2> {
        if self.schema_version != SCHEMA_VERSION
            || self.installation_epoch == 0
            || self.committed_ledger_generation == 0
            || self.committed_effect_fence_epoch == 0
            || self.committed_at_unix_ms == 0
            || self.digests.iter().any(|value| is_zero(value.as_bytes()))
            || is_zero(self.transaction_id.as_bytes())
            || self.digests[ClosedCommitDigestFieldV2::InstallationId.index()]
                != verifier.installation_id()
            || self.installation_epoch != verifier.key_epoch()
            || self.activation_key_id != verifier.key_id()
            || self.signature.domain_tag != SIGNATURE_TAG
            || self.signature.key_id != self.activation_key_id
            || self.signature.key_epoch != self.installation_epoch
            || is_zero(self.signature.signature.as_bytes())
        {
            return Err(DeploymentControlErrorV2::InvalidCommitAttestation);
        }
        Ok(())
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
        .map_err(|_| DeploymentControlErrorV2::InvalidCommitAttestation)?;
    for field in &ClosedCommitDigestFieldV2::ALL[..5] {
        put_digest(encoder, value.digests[field.index()])?;
    }
    encoder
        .u64(value.installation_epoch)
        .map_err(|_| DeploymentControlErrorV2::InvalidCommitAttestation)?;
    encoder
        .writer_mut()
        .extend_from_slice(value.platform.canonical_bytes());
    encoder
        .bytes(value.transaction_id.as_bytes())
        .map_err(|_| DeploymentControlErrorV2::InvalidCommitAttestation)?;
    for field in &ClosedCommitDigestFieldV2::ALL[5..8] {
        put_digest(encoder, value.digests[field.index()])?;
    }
    encoder
        .u64(value.committed_ledger_generation)
        .map_err(|_| DeploymentControlErrorV2::InvalidCommitAttestation)?;
    for field in &ClosedCommitDigestFieldV2::ALL[8..11] {
        put_digest(encoder, value.digests[field.index()])?;
    }
    encoder
        .u64(value.committed_effect_fence_epoch)
        .and_then(|encoder| encoder.bool(false))
        .map_err(|_| DeploymentControlErrorV2::InvalidCommitAttestation)?;
    put_digest(
        encoder,
        value.digests[ClosedCommitDigestFieldV2::RollbackGrant.index()],
    )?;
    encoder
        .u16(RollbackGrantStateV2::Burned as u16)
        .map_err(|_| DeploymentControlErrorV2::InvalidCommitAttestation)?;
    encoder
        .writer_mut()
        .extend_from_slice(&ActiveActivationV2::Normal.canonical_bytes()?);
    for field in &ClosedCommitDigestFieldV2::ALL[12..] {
        put_digest(encoder, value.digests[field.index()])?;
    }
    encoder
        .u64(value.committed_at_unix_ms)
        .and_then(|encoder| encoder.bytes(value.activation_key_id.as_bytes()))
        .map_err(|_| DeploymentControlErrorV2::InvalidCommitAttestation)?;
    Ok(())
}

fn decode_complete(bytes: &[u8]) -> Result<Decoded, DeploymentControlErrorV2> {
    let mut decoder = minicbor::Decoder::new(bytes);
    expect_array(&mut decoder, COMPLETE_FIELDS)?;
    let schema_version = get_u16(&mut decoder)?;
    let mut digests = [Digest32V2::new([0; 32]); 16];
    for field in &ClosedCommitDigestFieldV2::ALL[..5] {
        digests[field.index()] = get_digest(&mut decoder)?;
    }
    let installation_epoch = get_u64(&mut decoder)?;
    let platform = nested(&mut decoder, PlatformLockV2::from_canonical_bytes)?;
    let transaction_id = Nonce32V2::new(get_fixed::<32>(&mut decoder)?);
    for field in &ClosedCommitDigestFieldV2::ALL[5..8] {
        digests[field.index()] = get_digest(&mut decoder)?;
    }
    let committed_ledger_generation = get_u64(&mut decoder)?;
    for field in &ClosedCommitDigestFieldV2::ALL[8..11] {
        digests[field.index()] = get_digest(&mut decoder)?;
    }
    let committed_effect_fence_epoch = get_u64(&mut decoder)?;
    if decoder
        .bool()
        .map_err(|_| DeploymentControlErrorV2::InvalidCommitAttestation)?
    {
        return Err(DeploymentControlErrorV2::InvalidCommitAttestation);
    }
    digests[ClosedCommitDigestFieldV2::RollbackGrant.index()] = get_digest(&mut decoder)?;
    if get_u16(&mut decoder)? != RollbackGrantStateV2::Burned as u16 {
        return Err(DeploymentControlErrorV2::InvalidCommitAttestation);
    }
    if nested(&mut decoder, ActiveActivationV2::from_canonical_bytes)? != ActiveActivationV2::Normal
    {
        return Err(DeploymentControlErrorV2::InvalidCommitAttestation);
    }
    for field in &ClosedCommitDigestFieldV2::ALL[12..] {
        digests[field.index()] = get_digest(&mut decoder)?;
    }
    let committed_at_unix_ms = get_u64(&mut decoder)?;
    let activation_key_id = Ed25519KeyIdV2::new(get_fixed::<32>(&mut decoder)?);
    let signature = decode_signature(&mut decoder)?;
    if decoder.position() != bytes.len() {
        return Err(DeploymentControlErrorV2::InvalidCommitAttestation);
    }
    Ok(Decoded {
        schema_version,
        digests,
        installation_epoch,
        platform,
        transaction_id,
        committed_ledger_generation,
        committed_effect_fence_epoch,
        committed_at_unix_ms,
        activation_key_id,
        signature,
    })
}

fn put_digest(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    value: Digest32V2,
) -> Result<(), DeploymentControlErrorV2> {
    encoder
        .bytes(value.as_bytes())
        .map_err(|_| DeploymentControlErrorV2::InvalidCommitAttestation)?;
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
        .map_err(|_| DeploymentControlErrorV2::InvalidCommitAttestation)?;
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
        .map_err(|_| DeploymentControlErrorV2::InvalidCommitAttestation)?;
    decode(
        decoder
            .input()
            .get(start..decoder.position())
            .ok_or(DeploymentControlErrorV2::InvalidCommitAttestation)?,
    )
}

fn expect_array(
    decoder: &mut minicbor::Decoder<'_>,
    expected: u64,
) -> Result<(), DeploymentControlErrorV2> {
    if decoder
        .array()
        .map_err(|_| DeploymentControlErrorV2::InvalidCommitAttestation)?
        != Some(expected)
    {
        return Err(DeploymentControlErrorV2::InvalidCommitAttestation);
    }
    Ok(())
}

fn get_u16(decoder: &mut minicbor::Decoder<'_>) -> Result<u16, DeploymentControlErrorV2> {
    decoder
        .u16()
        .map_err(|_| DeploymentControlErrorV2::InvalidCommitAttestation)
}

fn get_u64(decoder: &mut minicbor::Decoder<'_>) -> Result<u64, DeploymentControlErrorV2> {
    decoder
        .u64()
        .map_err(|_| DeploymentControlErrorV2::InvalidCommitAttestation)
}

fn get_digest(decoder: &mut minicbor::Decoder<'_>) -> Result<Digest32V2, DeploymentControlErrorV2> {
    Ok(Digest32V2::new(get_fixed::<32>(decoder)?))
}

fn get_fixed<const N: usize>(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<[u8; N], DeploymentControlErrorV2> {
    decoder
        .bytes()
        .map_err(|_| DeploymentControlErrorV2::InvalidCommitAttestation)?
        .try_into()
        .map_err(|_| DeploymentControlErrorV2::InvalidCommitAttestation)
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
