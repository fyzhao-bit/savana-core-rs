use savana_kernel_protocol::v2::{Digest32V2, Ed25519KeyIdV2, Ed25519SignatureV2, Nonce32V2};
use savana_platform_identity::{
    NativeDeploymentSignatureDomainV2, NativeDeploymentSignatureRequestV2,
    NativeDeploymentSigningAuthorityV2,
};
use sha2::{Digest as _, Sha256};

use super::{
    ArtifactIdentityV2, ClosedArtifactTypeV2, DeploymentActivationVerifierV2,
    DeploymentControlErrorV2, PlatformLockV2, RollbackOriginPhaseV2,
};

const SCHEMA_VERSION: u16 = 2;
const COMPLETE_FIELDS: u64 = 39;
const PAYLOAD_FIELDS: u64 = 38;
const SIGNATURE_FIELDS: u64 = 4;
const SIGNATURE_TAG: u16 = 17;
const PAYLOAD_DOMAIN: &[u8] = b"savana.rollback-verification-evidence.v2.payload\0";
const SIGNATURE_DOMAIN: &[u8] = b"savana.rollback-verification-evidence.v2.signature\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u16)]
pub enum ClosedRollbackVerificationDigestFieldV2 {
    EvidenceTrustPolicy = 1,
    EvidenceLayerLimits = 2,
    SourceEvidence = 3,
    ArtifactEvidence = 4,
    InstallationId = 5,
    TransactionIntent = 6,
    TransactionPayload = 7,
    CandidateVerificationEvidence = 8,
    AttemptedManifest = 9,
    RollbackManifest = 10,
    HighestEver = 11,
    RollbackGrant = 12,
    AttemptedSourceLock = 13,
    AttemptedProtocolLock = 14,
    AttemptedPlatformClosure = 15,
    RollbackSourceLock = 16,
    RollbackProtocolLock = 17,
    RollbackPlatformClosure = 18,
    RollbackStoreCompatibilityAttestation = 19,
    RollbackNativeControlMeasurementSet = 20,
    RollbackEffectFenceResult = 21,
    RollbackIsolatedE2eResult = 22,
    RollbackProtectedAcceptanceResult = 23,
    RollbackServiceReadinessResult = 24,
    RollbackRecoveryResult = 25,
    RollbackLegacyAbsenceResult = 26,
}

impl ClosedRollbackVerificationDigestFieldV2 {
    pub const ALL: [Self; 26] = [
        Self::EvidenceTrustPolicy,
        Self::EvidenceLayerLimits,
        Self::SourceEvidence,
        Self::ArtifactEvidence,
        Self::InstallationId,
        Self::TransactionIntent,
        Self::TransactionPayload,
        Self::CandidateVerificationEvidence,
        Self::AttemptedManifest,
        Self::RollbackManifest,
        Self::HighestEver,
        Self::RollbackGrant,
        Self::AttemptedSourceLock,
        Self::AttemptedProtocolLock,
        Self::AttemptedPlatformClosure,
        Self::RollbackSourceLock,
        Self::RollbackProtocolLock,
        Self::RollbackPlatformClosure,
        Self::RollbackStoreCompatibilityAttestation,
        Self::RollbackNativeControlMeasurementSet,
        Self::RollbackEffectFenceResult,
        Self::RollbackIsolatedE2eResult,
        Self::RollbackProtectedAcceptanceResult,
        Self::RollbackServiceReadinessResult,
        Self::RollbackRecoveryResult,
        Self::RollbackLegacyAbsenceResult,
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
pub struct RollbackVerificationEvidenceV2 {
    canonical_bytes: Vec<u8>,
    digests: [Digest32V2; 26],
    installation_epoch: u64,
    platform: PlatformLockV2,
    transaction_id: Nonce32V2,
    rollback_installed_ledger_generation: u64,
    rollback_installed_effect_fence_epoch: u64,
    verified_at_unix_ms: u64,
    helper_identity: ArtifactIdentityV2,
    watchdog_identity: ArtifactIdentityV2,
    activation_key_id: Ed25519KeyIdV2,
    payload_digest: Digest32V2,
}

impl std::fmt::Debug for RollbackVerificationEvidenceV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RollbackVerificationEvidenceV2")
            .field(
                "rollback_installed_ledger_generation",
                &self.rollback_installed_ledger_generation,
            )
            .field("verified_at_unix_ms", &self.verified_at_unix_ms)
            .field("payload_digest", &self.payload_digest)
            .finish_non_exhaustive()
    }
}

impl RollbackVerificationEvidenceV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn new_signed_with_authority(
        digests: [Digest32V2; 26],
        installation_epoch: u64,
        platform: PlatformLockV2,
        transaction_id: Nonce32V2,
        rollback_installed_ledger_generation: u64,
        rollback_installed_effect_fence_epoch: u64,
        verified_at_unix_ms: u64,
        helper_identity: ArtifactIdentityV2,
        watchdog_identity: ArtifactIdentityV2,
        authority: &mut dyn NativeDeploymentSigningAuthorityV2,
        verifier: &DeploymentActivationVerifierV2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        let installation_id =
            digests[ClosedRollbackVerificationDigestFieldV2::InstallationId.index()];
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
            rollback_installed_ledger_generation,
            rollback_installed_effect_fence_epoch,
            verified_at_unix_ms,
            helper_identity,
            watchdog_identity,
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
            NativeDeploymentSignatureDomainV2::RollbackVerificationEvidence,
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
            return Err(DeploymentControlErrorV2::InvalidRollbackVerificationEvidence);
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
            rollback_installed_ledger_generation: decoded.rollback_installed_ledger_generation,
            rollback_installed_effect_fence_epoch: decoded.rollback_installed_effect_fence_epoch,
            verified_at_unix_ms: decoded.verified_at_unix_ms,
            helper_identity: decoded.helper_identity,
            watchdog_identity: decoded.watchdog_identity,
            activation_key_id: decoded.activation_key_id,
            payload_digest,
        })
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub const fn digest_field(&self, field: ClosedRollbackVerificationDigestFieldV2) -> Digest32V2 {
        self.digests[field.index()]
    }

    pub const fn installation_id(&self) -> Digest32V2 {
        self.digest_field(ClosedRollbackVerificationDigestFieldV2::InstallationId)
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

    pub const fn rollback_origin_phase(&self) -> RollbackOriginPhaseV2 {
        RollbackOriginPhaseV2::Verified
    }

    pub const fn rollback_installed_ledger_generation(&self) -> u64 {
        self.rollback_installed_ledger_generation
    }

    pub const fn rollback_installed_effect_fence_epoch(&self) -> u64 {
        self.rollback_installed_effect_fence_epoch
    }

    pub const fn verified_at_unix_ms(&self) -> u64 {
        self.verified_at_unix_ms
    }

    pub const fn helper_identity(&self) -> &ArtifactIdentityV2 {
        &self.helper_identity
    }

    pub const fn watchdog_identity(&self) -> &ArtifactIdentityV2 {
        &self.watchdog_identity
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
    digests: [Digest32V2; 26],
    installation_epoch: u64,
    platform: PlatformLockV2,
    transaction_id: Nonce32V2,
    rollback_installed_ledger_generation: u64,
    rollback_installed_effect_fence_epoch: u64,
    verified_at_unix_ms: u64,
    helper_identity: ArtifactIdentityV2,
    watchdog_identity: ArtifactIdentityV2,
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
            || self.rollback_installed_ledger_generation == 0
            || self.rollback_installed_effect_fence_epoch == 0
            || self.verified_at_unix_ms == 0
            || self.digests.iter().any(|value| is_zero(value.as_bytes()))
            || is_zero(self.transaction_id.as_bytes())
            || self.digests[ClosedRollbackVerificationDigestFieldV2::InstallationId.index()]
                != verifier.installation_id()
            || self.installation_epoch != verifier.key_epoch()
            || self.activation_key_id != verifier.key_id()
            || self.signature.domain_tag != SIGNATURE_TAG
            || self.signature.key_id != self.activation_key_id
            || self.signature.key_epoch != self.installation_epoch
            || is_zero(self.signature.signature.as_bytes())
            || self.helper_identity.artifact_type() != ClosedArtifactTypeV2::RootHelper
            || self.watchdog_identity.artifact_type() != ClosedArtifactTypeV2::Watchdog
            || self.helper_identity.target_os() != self.platform.target_os()
            || self.watchdog_identity.target_os() != self.platform.target_os()
            || self.helper_identity.target_architecture() != self.platform.target_architecture()
            || self.watchdog_identity.target_architecture() != self.platform.target_architecture()
        {
            return Err(DeploymentControlErrorV2::InvalidRollbackVerificationEvidence);
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
        .map_err(|_| DeploymentControlErrorV2::InvalidRollbackVerificationEvidence)?;
    for field in &ClosedRollbackVerificationDigestFieldV2::ALL[..5] {
        put_digest(encoder, value.digests[field.index()])?;
    }
    encoder
        .u64(value.installation_epoch)
        .map_err(|_| DeploymentControlErrorV2::InvalidRollbackVerificationEvidence)?;
    encoder
        .writer_mut()
        .extend_from_slice(value.platform.canonical_bytes());
    encoder
        .bytes(value.transaction_id.as_bytes())
        .map_err(|_| DeploymentControlErrorV2::InvalidRollbackVerificationEvidence)?;
    for field in &ClosedRollbackVerificationDigestFieldV2::ALL[5..8] {
        put_digest(encoder, value.digests[field.index()])?;
    }
    encoder
        .u16(RollbackOriginPhaseV2::Verified as u16)
        .and_then(|encoder| encoder.u64(value.rollback_installed_ledger_generation))
        .and_then(|encoder| encoder.u64(value.rollback_installed_effect_fence_epoch))
        .and_then(|encoder| encoder.bool(true))
        .map_err(|_| DeploymentControlErrorV2::InvalidRollbackVerificationEvidence)?;
    for field in &ClosedRollbackVerificationDigestFieldV2::ALL[8..] {
        put_digest(encoder, value.digests[field.index()])?;
    }
    encoder
        .u64(value.verified_at_unix_ms)
        .map_err(|_| DeploymentControlErrorV2::InvalidRollbackVerificationEvidence)?;
    encoder
        .writer_mut()
        .extend_from_slice(value.helper_identity.canonical_bytes());
    encoder
        .writer_mut()
        .extend_from_slice(value.watchdog_identity.canonical_bytes());
    encoder
        .bytes(value.activation_key_id.as_bytes())
        .map_err(|_| DeploymentControlErrorV2::InvalidRollbackVerificationEvidence)?;
    Ok(())
}

fn decode_complete(bytes: &[u8]) -> Result<Decoded, DeploymentControlErrorV2> {
    let mut decoder = minicbor::Decoder::new(bytes);
    expect_array(&mut decoder, COMPLETE_FIELDS)?;
    let schema_version = get_u16(&mut decoder)?;
    let mut digests = [Digest32V2::new([0; 32]); 26];
    for field in &ClosedRollbackVerificationDigestFieldV2::ALL[..5] {
        digests[field.index()] = get_digest(&mut decoder)?;
    }
    let installation_epoch = get_u64(&mut decoder)?;
    let platform = nested(&mut decoder, PlatformLockV2::from_canonical_bytes)?;
    let transaction_id = Nonce32V2::new(get_fixed::<32>(&mut decoder)?);
    for field in &ClosedRollbackVerificationDigestFieldV2::ALL[5..8] {
        digests[field.index()] = get_digest(&mut decoder)?;
    }
    if get_u16(&mut decoder)? != RollbackOriginPhaseV2::Verified as u16 {
        return Err(DeploymentControlErrorV2::InvalidRollbackVerificationEvidence);
    }
    let rollback_installed_ledger_generation = get_u64(&mut decoder)?;
    let rollback_installed_effect_fence_epoch = get_u64(&mut decoder)?;
    if !decoder
        .bool()
        .map_err(|_| DeploymentControlErrorV2::InvalidRollbackVerificationEvidence)?
    {
        return Err(DeploymentControlErrorV2::InvalidRollbackVerificationEvidence);
    }
    for field in &ClosedRollbackVerificationDigestFieldV2::ALL[8..] {
        digests[field.index()] = get_digest(&mut decoder)?;
    }
    let verified_at_unix_ms = get_u64(&mut decoder)?;
    let helper_identity = nested(&mut decoder, ArtifactIdentityV2::from_canonical_bytes)?;
    let watchdog_identity = nested(&mut decoder, ArtifactIdentityV2::from_canonical_bytes)?;
    let activation_key_id = Ed25519KeyIdV2::new(get_fixed::<32>(&mut decoder)?);
    let signature = decode_signature(&mut decoder)?;
    if decoder.position() != bytes.len() {
        return Err(DeploymentControlErrorV2::InvalidRollbackVerificationEvidence);
    }
    Ok(Decoded {
        schema_version,
        digests,
        installation_epoch,
        platform,
        transaction_id,
        rollback_installed_ledger_generation,
        rollback_installed_effect_fence_epoch,
        verified_at_unix_ms,
        helper_identity,
        watchdog_identity,
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
        .map_err(|_| DeploymentControlErrorV2::InvalidRollbackVerificationEvidence)?;
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
        .map_err(|_| DeploymentControlErrorV2::InvalidRollbackVerificationEvidence)?;
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
        .map_err(|_| DeploymentControlErrorV2::InvalidRollbackVerificationEvidence)?;
    decode(
        decoder
            .input()
            .get(start..decoder.position())
            .ok_or(DeploymentControlErrorV2::InvalidRollbackVerificationEvidence)?,
    )
}

fn expect_array(
    decoder: &mut minicbor::Decoder<'_>,
    expected: u64,
) -> Result<(), DeploymentControlErrorV2> {
    if decoder
        .array()
        .map_err(|_| DeploymentControlErrorV2::InvalidRollbackVerificationEvidence)?
        != Some(expected)
    {
        return Err(DeploymentControlErrorV2::InvalidRollbackVerificationEvidence);
    }
    Ok(())
}

fn get_u16(decoder: &mut minicbor::Decoder<'_>) -> Result<u16, DeploymentControlErrorV2> {
    decoder
        .u16()
        .map_err(|_| DeploymentControlErrorV2::InvalidRollbackVerificationEvidence)
}

fn get_u64(decoder: &mut minicbor::Decoder<'_>) -> Result<u64, DeploymentControlErrorV2> {
    decoder
        .u64()
        .map_err(|_| DeploymentControlErrorV2::InvalidRollbackVerificationEvidence)
}

fn get_digest(decoder: &mut minicbor::Decoder<'_>) -> Result<Digest32V2, DeploymentControlErrorV2> {
    Ok(Digest32V2::new(get_fixed::<32>(decoder)?))
}

fn get_fixed<const N: usize>(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<[u8; N], DeploymentControlErrorV2> {
    decoder
        .bytes()
        .map_err(|_| DeploymentControlErrorV2::InvalidRollbackVerificationEvidence)?
        .try_into()
        .map_err(|_| DeploymentControlErrorV2::InvalidRollbackVerificationEvidence)
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
