use savana_kernel_protocol::v2::{Digest32V2, Ed25519KeyIdV2, Ed25519SignatureV2, Nonce32V2};
use savana_platform_identity::{
    NativeDeploymentSignatureDomainV2, NativeDeploymentSignatureRequestV2,
    NativeDeploymentSigningAuthorityV2,
};
use sha2::{Digest as _, Sha256};

use super::{
    ArtifactIdentityV2, ClosedArtifactTypeV2, DeploymentActivationVerifierV2,
    DeploymentControlErrorV2,
};

const SCHEMA_VERSION: u16 = 2;
const COMPLETE_FIELDS: u64 = 38;
const PAYLOAD_FIELDS: u64 = 37;
const SIGNATURE_FIELDS: u64 = 4;
const SIGNATURE_TAG: u16 = 9;
const PAYLOAD_DOMAIN: &[u8] = b"savana.verification-evidence.v2.payload\0";
const SIGNATURE_DOMAIN: &[u8] = b"savana.verification-evidence.v2.signature\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u16)]
pub enum ClosedVerificationDigestFieldV2 {
    EvidenceTrustPolicy = 1,
    EvidenceLayerLimits = 2,
    SourceEvidence = 3,
    ArtifactEvidence = 4,
    InstallationId = 5,
    TransactionIntent = 6,
    TransactionPayload = 7,
    InstalledManifest = 8,
    HighestEver = 9,
    RecoveryTarget = 10,
    RollbackGrant = 11,
    SourceLock = 12,
    ProtocolLock = 13,
    BinaryClosure = 14,
    SecurityState = 15,
    PlatformClosure = 16,
    InstallIdentityProfile = 17,
    StoreCompatibilityAttestation = 18,
    NativeControlMeasurementSet = 19,
    EffectFenceResult = 20,
    IsolatedE2eResult = 21,
    ProtectedAcceptanceResult = 22,
    ServiceReadinessResult = 23,
    RollbackExerciseResult = 24,
    LegacyAbsenceResult = 25,
    CanonicalVectorResult = 26,
    NegativeTestResult = 27,
    EvidenceContract = 28,
}

impl ClosedVerificationDigestFieldV2 {
    pub const ALL: [Self; 28] = [
        Self::EvidenceTrustPolicy,
        Self::EvidenceLayerLimits,
        Self::SourceEvidence,
        Self::ArtifactEvidence,
        Self::InstallationId,
        Self::TransactionIntent,
        Self::TransactionPayload,
        Self::InstalledManifest,
        Self::HighestEver,
        Self::RecoveryTarget,
        Self::RollbackGrant,
        Self::SourceLock,
        Self::ProtocolLock,
        Self::BinaryClosure,
        Self::SecurityState,
        Self::PlatformClosure,
        Self::InstallIdentityProfile,
        Self::StoreCompatibilityAttestation,
        Self::NativeControlMeasurementSet,
        Self::EffectFenceResult,
        Self::IsolatedE2eResult,
        Self::ProtectedAcceptanceResult,
        Self::ServiceReadinessResult,
        Self::RollbackExerciseResult,
        Self::LegacyAbsenceResult,
        Self::CanonicalVectorResult,
        Self::NegativeTestResult,
        Self::EvidenceContract,
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
pub struct VerificationEvidenceV2 {
    canonical_bytes: Vec<u8>,
    digests: [Digest32V2; 28],
    installation_epoch: u64,
    transaction_id: Nonce32V2,
    installed_ledger_generation: u64,
    installed_effect_fence_epoch: u64,
    verified_at_unix_ms: u64,
    helper_identity: ArtifactIdentityV2,
    watchdog_identity: ArtifactIdentityV2,
    activation_key_id: Ed25519KeyIdV2,
    payload_digest: Digest32V2,
}

impl std::fmt::Debug for VerificationEvidenceV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerificationEvidenceV2")
            .field(
                "installed_ledger_generation",
                &self.installed_ledger_generation,
            )
            .field("verified_at_unix_ms", &self.verified_at_unix_ms)
            .field("payload_digest", &self.payload_digest)
            .finish_non_exhaustive()
    }
}

impl VerificationEvidenceV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn new_signed_with_authority(
        digests: [Digest32V2; 28],
        installation_epoch: u64,
        transaction_id: Nonce32V2,
        installed_ledger_generation: u64,
        installed_effect_fence_epoch: u64,
        verified_at_unix_ms: u64,
        helper_identity: ArtifactIdentityV2,
        watchdog_identity: ArtifactIdentityV2,
        authority: &mut dyn NativeDeploymentSigningAuthorityV2,
        verifier: &DeploymentActivationVerifierV2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        let activation_key_id = Ed25519KeyIdV2::new(authority.key_id());
        let installation_id = digests[ClosedVerificationDigestFieldV2::InstallationId.index()];
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
            transaction_id,
            installed_ledger_generation,
            installed_effect_fence_epoch,
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
            NativeDeploymentSignatureDomainV2::VerificationEvidence,
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
            return Err(DeploymentControlErrorV2::InvalidVerificationEvidence);
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
            transaction_id: decoded.transaction_id,
            installed_ledger_generation: decoded.installed_ledger_generation,
            installed_effect_fence_epoch: decoded.installed_effect_fence_epoch,
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

    pub const fn digest_field(&self, field: ClosedVerificationDigestFieldV2) -> Digest32V2 {
        self.digests[field.index()]
    }

    pub const fn installation_id(&self) -> Digest32V2 {
        self.digest_field(ClosedVerificationDigestFieldV2::InstallationId)
    }

    pub const fn installation_epoch(&self) -> u64 {
        self.installation_epoch
    }

    pub const fn transaction_id(&self) -> Nonce32V2 {
        self.transaction_id
    }

    pub const fn installed_ledger_generation(&self) -> u64 {
        self.installed_ledger_generation
    }

    pub const fn installed_effect_fence_epoch(&self) -> u64 {
        self.installed_effect_fence_epoch
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
    digests: [Digest32V2; 28],
    installation_epoch: u64,
    transaction_id: Nonce32V2,
    installed_ledger_generation: u64,
    installed_effect_fence_epoch: u64,
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
            || self.installed_ledger_generation == 0
            || self.installed_effect_fence_epoch == 0
            || self.verified_at_unix_ms == 0
            || self.digests.iter().any(|value| is_zero(value.as_bytes()))
            || is_zero(self.transaction_id.as_bytes())
            || self.digests[ClosedVerificationDigestFieldV2::InstallationId.index()]
                != verifier.installation_id()
            || self.installation_epoch != verifier.key_epoch()
            || self.activation_key_id != verifier.key_id()
            || self.signature.domain_tag != SIGNATURE_TAG
            || self.signature.key_id != self.activation_key_id
            || self.signature.key_epoch != self.installation_epoch
            || is_zero(self.signature.signature.as_bytes())
            || self.helper_identity.artifact_type() != ClosedArtifactTypeV2::RootHelper
            || self.watchdog_identity.artifact_type() != ClosedArtifactTypeV2::Watchdog
            || self.helper_identity.target_os() != self.watchdog_identity.target_os()
            || self.helper_identity.target_architecture()
                != self.watchdog_identity.target_architecture()
        {
            return Err(DeploymentControlErrorV2::InvalidVerificationEvidence);
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
        .map_err(|_| DeploymentControlErrorV2::InvalidVerificationEvidence)?;
    for field in &ClosedVerificationDigestFieldV2::ALL[..5] {
        put_digest(encoder, value.digests[field.index()])?;
    }
    encoder
        .u64(value.installation_epoch)
        .and_then(|encoder| encoder.bytes(value.transaction_id.as_bytes()))
        .map_err(|_| DeploymentControlErrorV2::InvalidVerificationEvidence)?;
    for field in &ClosedVerificationDigestFieldV2::ALL[5..7] {
        put_digest(encoder, value.digests[field.index()])?;
    }
    encoder
        .u64(value.installed_ledger_generation)
        .and_then(|encoder| encoder.u64(value.installed_effect_fence_epoch))
        .map_err(|_| DeploymentControlErrorV2::InvalidVerificationEvidence)?;
    for field in &ClosedVerificationDigestFieldV2::ALL[7..] {
        put_digest(encoder, value.digests[field.index()])?;
    }
    encoder
        .u64(value.verified_at_unix_ms)
        .map_err(|_| DeploymentControlErrorV2::InvalidVerificationEvidence)?;
    encoder
        .writer_mut()
        .extend_from_slice(value.helper_identity.canonical_bytes());
    encoder
        .writer_mut()
        .extend_from_slice(value.watchdog_identity.canonical_bytes());
    encoder
        .bytes(value.activation_key_id.as_bytes())
        .map_err(|_| DeploymentControlErrorV2::InvalidVerificationEvidence)?;
    Ok(())
}

fn decode_complete(bytes: &[u8]) -> Result<Decoded, DeploymentControlErrorV2> {
    let mut decoder = minicbor::Decoder::new(bytes);
    expect_array(&mut decoder, COMPLETE_FIELDS)?;
    let schema_version = get_u16(&mut decoder)?;
    let mut digests = [Digest32V2::new([0; 32]); 28];
    for field in &ClosedVerificationDigestFieldV2::ALL[..5] {
        digests[field.index()] = get_digest(&mut decoder)?;
    }
    let installation_epoch = get_u64(&mut decoder)?;
    let transaction_id = Nonce32V2::new(get_fixed::<32>(&mut decoder)?);
    for field in &ClosedVerificationDigestFieldV2::ALL[5..7] {
        digests[field.index()] = get_digest(&mut decoder)?;
    }
    let installed_ledger_generation = get_u64(&mut decoder)?;
    let installed_effect_fence_epoch = get_u64(&mut decoder)?;
    for field in &ClosedVerificationDigestFieldV2::ALL[7..] {
        digests[field.index()] = get_digest(&mut decoder)?;
    }
    let verified_at_unix_ms = get_u64(&mut decoder)?;
    let helper_identity = nested(&mut decoder, ArtifactIdentityV2::from_canonical_bytes)?;
    let watchdog_identity = nested(&mut decoder, ArtifactIdentityV2::from_canonical_bytes)?;
    let activation_key_id = Ed25519KeyIdV2::new(get_fixed::<32>(&mut decoder)?);
    let signature = decode_signature(&mut decoder)?;
    if decoder.position() != bytes.len() {
        return Err(DeploymentControlErrorV2::InvalidVerificationEvidence);
    }
    Ok(Decoded {
        schema_version,
        digests,
        installation_epoch,
        transaction_id,
        installed_ledger_generation,
        installed_effect_fence_epoch,
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
        .map_err(|_| DeploymentControlErrorV2::InvalidVerificationEvidence)?;
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
        .map_err(|_| DeploymentControlErrorV2::InvalidVerificationEvidence)?;
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
        .map_err(|_| DeploymentControlErrorV2::InvalidVerificationEvidence)?;
    decode(
        decoder
            .input()
            .get(start..decoder.position())
            .ok_or(DeploymentControlErrorV2::InvalidVerificationEvidence)?,
    )
}

fn expect_array(
    decoder: &mut minicbor::Decoder<'_>,
    expected: u64,
) -> Result<(), DeploymentControlErrorV2> {
    if decoder
        .array()
        .map_err(|_| DeploymentControlErrorV2::InvalidVerificationEvidence)?
        != Some(expected)
    {
        return Err(DeploymentControlErrorV2::InvalidVerificationEvidence);
    }
    Ok(())
}

fn get_u16(decoder: &mut minicbor::Decoder<'_>) -> Result<u16, DeploymentControlErrorV2> {
    decoder
        .u16()
        .map_err(|_| DeploymentControlErrorV2::InvalidVerificationEvidence)
}

fn get_u64(decoder: &mut minicbor::Decoder<'_>) -> Result<u64, DeploymentControlErrorV2> {
    decoder
        .u64()
        .map_err(|_| DeploymentControlErrorV2::InvalidVerificationEvidence)
}

fn get_digest(decoder: &mut minicbor::Decoder<'_>) -> Result<Digest32V2, DeploymentControlErrorV2> {
    Ok(Digest32V2::new(get_fixed::<32>(decoder)?))
}

fn get_fixed<const N: usize>(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<[u8; N], DeploymentControlErrorV2> {
    decoder
        .bytes()
        .map_err(|_| DeploymentControlErrorV2::InvalidVerificationEvidence)?
        .try_into()
        .map_err(|_| DeploymentControlErrorV2::InvalidVerificationEvidence)
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
