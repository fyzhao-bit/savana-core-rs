use savana_kernel_protocol::v2::{Digest32V2, Ed25519KeyIdV2};
use sha2::{Digest as _, Sha256};

use super::{
    ArtifactIdentityV2, ClosedArtifactTypeV2, ClosedSecurityDomainV2, DeploymentControlErrorV2,
    DeploymentHardLimitsV2,
};

const SOURCE_LOCK_FIELDS_V2: u64 = 5;
const SOURCE_LOCK_DOMAIN_V2: &[u8] = b"savana.source-lock.v2\0";
const VERSIONED_IDENTITY_FIELDS_V2: u64 = 7;
const EPOCH_RANGE_FIELDS_V2: u64 = 2;
const ARTIFACT_SET_DOMAIN_V2: &[u8] = b"savana.artifact-set-identity.v2\0";
const MANIFEST_LINEAGE_DOMAIN_V2: &[u8] = b"savana.manifest-lineage.v2\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceLockV2 {
    canonical_bytes: Vec<u8>,
    exact_ten_crate_source_digest: Digest32V2,
    cargo_lock_digest: Digest32V2,
    build_toolchain_digest: Digest32V2,
    reproducible_build_recipe_digest: Digest32V2,
    sbom_digest: Digest32V2,
    digest: Digest32V2,
}

impl SourceLockV2 {
    pub fn new(
        exact_ten_crate_source_digest: Digest32V2,
        cargo_lock_digest: Digest32V2,
        build_toolchain_digest: Digest32V2,
        reproducible_build_recipe_digest: Digest32V2,
        sbom_digest: Digest32V2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        let values = [
            exact_ten_crate_source_digest,
            cargo_lock_digest,
            build_toolchain_digest,
            reproducible_build_recipe_digest,
            sbom_digest,
        ];
        validate_nonzero_digests(&values)?;
        let canonical_bytes = encode_digest_array(&values)?;
        Ok(Self {
            digest: hash_domain(SOURCE_LOCK_DOMAIN_V2, &canonical_bytes),
            canonical_bytes,
            exact_ten_crate_source_digest,
            cargo_lock_digest,
            build_toolchain_digest,
            reproducible_build_recipe_digest,
            sbom_digest,
        })
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, DeploymentControlErrorV2> {
        check_manifest_object_size(bytes)?;
        let mut decoder = minicbor::Decoder::new(bytes);
        expect_array(&mut decoder, SOURCE_LOCK_FIELDS_V2)?;
        let values = [
            decode_digest(&mut decoder)?,
            decode_digest(&mut decoder)?,
            decode_digest(&mut decoder)?,
            decode_digest(&mut decoder)?,
            decode_digest(&mut decoder)?,
        ];
        require_eof(&decoder, bytes)?;
        let value = Self::new(values[0], values[1], values[2], values[3], values[4])?;
        require_canonical(value.canonical_bytes(), bytes)?;
        Ok(value)
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub const fn digest(&self) -> Digest32V2 {
        self.digest
    }

    pub const fn exact_ten_crate_source_digest(&self) -> Digest32V2 {
        self.exact_ten_crate_source_digest
    }

    pub const fn cargo_lock_digest(&self) -> Digest32V2 {
        self.cargo_lock_digest
    }

    pub const fn build_toolchain_digest(&self) -> Digest32V2 {
        self.build_toolchain_digest
    }

    pub const fn reproducible_build_recipe_digest(&self) -> Digest32V2 {
        self.reproducible_build_recipe_digest
    }

    pub const fn sbom_digest(&self) -> Digest32V2 {
        self.sbom_digest
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionedIdentityV2 {
    canonical_bytes: Vec<u8>,
    domain: ClosedSecurityDomainV2,
    sequence: u64,
    content_digest: Digest32V2,
    signer_key_id: Ed25519KeyIdV2,
    signer_key_epoch: u64,
    not_before_unix_ms: u64,
    not_after_unix_ms: u64,
}

impl VersionedIdentityV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        domain: ClosedSecurityDomainV2,
        sequence: u64,
        content_digest: Digest32V2,
        signer_key_id: Ed25519KeyIdV2,
        signer_key_epoch: u64,
        not_before_unix_ms: u64,
        not_after_unix_ms: u64,
    ) -> Result<Self, DeploymentControlErrorV2> {
        if sequence == 0
            || signer_key_epoch == 0
            || not_before_unix_ms >= not_after_unix_ms
            || is_zero(content_digest.as_bytes())
            || is_zero(signer_key_id.as_bytes())
        {
            return Err(DeploymentControlErrorV2::InvalidSecurityStateManifest);
        }
        let mut encoder = minicbor::Encoder::new(Vec::new());
        encoder
            .array(VERSIONED_IDENTITY_FIELDS_V2)
            .and_then(|encoder| encoder.u16(domain.tag()))
            .and_then(|encoder| encoder.u64(sequence))
            .and_then(|encoder| encoder.bytes(content_digest.as_bytes()))
            .and_then(|encoder| encoder.bytes(signer_key_id.as_bytes()))
            .and_then(|encoder| encoder.u64(signer_key_epoch))
            .and_then(|encoder| encoder.u64(not_before_unix_ms))
            .and_then(|encoder| encoder.u64(not_after_unix_ms))
            .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
        Ok(Self {
            canonical_bytes: encoder.into_writer(),
            domain,
            sequence,
            content_digest,
            signer_key_id,
            signer_key_epoch,
            not_before_unix_ms,
            not_after_unix_ms,
        })
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, DeploymentControlErrorV2> {
        check_manifest_object_size(bytes)?;
        let mut decoder = minicbor::Decoder::new(bytes);
        expect_array(&mut decoder, VERSIONED_IDENTITY_FIELDS_V2)?;
        let domain = ClosedSecurityDomainV2::from_tag(decode_u16(&mut decoder)?)
            .ok_or(DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
        let sequence = decode_u64(&mut decoder)?;
        let content_digest = decode_digest(&mut decoder)?;
        let signer_key_id = decode_key_id(&mut decoder)?;
        let signer_key_epoch = decode_u64(&mut decoder)?;
        let not_before_unix_ms = decode_u64(&mut decoder)?;
        let not_after_unix_ms = decode_u64(&mut decoder)?;
        require_eof(&decoder, bytes)?;
        let value = Self::new(
            domain,
            sequence,
            content_digest,
            signer_key_id,
            signer_key_epoch,
            not_before_unix_ms,
            not_after_unix_ms,
        )?;
        require_canonical(value.canonical_bytes(), bytes)?;
        Ok(value)
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub const fn domain(&self) -> ClosedSecurityDomainV2 {
        self.domain
    }

    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub const fn content_digest(&self) -> Digest32V2 {
        self.content_digest
    }

    pub const fn signer_key_id(&self) -> Ed25519KeyIdV2 {
        self.signer_key_id
    }

    pub const fn signer_key_epoch(&self) -> u64 {
        self.signer_key_epoch
    }

    pub const fn not_before_unix_ms(&self) -> u64 {
        self.not_before_unix_ms
    }

    pub const fn not_after_unix_ms(&self) -> u64 {
        self.not_after_unix_ms
    }

    pub fn manifest_lineage_digest(&self) -> Result<Digest32V2, DeploymentControlErrorV2> {
        if self.domain != ClosedSecurityDomainV2::BinaryRelease {
            return Err(DeploymentControlErrorV2::InvalidSecurityStateManifest);
        }
        Ok(hash_domain(
            MANIFEST_LINEAGE_DOMAIN_V2,
            &self.canonical_bytes,
        ))
    }
}

/// Exact closed range used by persistent-store compatibility declarations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InclusiveEpochRangeV2 {
    minimum: u64,
    maximum: u64,
    canonical_bytes: [u8; 19],
    canonical_length: usize,
}

impl InclusiveEpochRangeV2 {
    pub fn new(minimum: u64, maximum: u64) -> Result<Self, DeploymentControlErrorV2> {
        if minimum == 0 || minimum > maximum {
            return Err(DeploymentControlErrorV2::InvalidSecurityStateManifest);
        }
        let mut encoder = minicbor::Encoder::new(Vec::new());
        encoder
            .array(EPOCH_RANGE_FIELDS_V2)
            .and_then(|encoder| encoder.u64(minimum))
            .and_then(|encoder| encoder.u64(maximum))
            .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
        let bytes = encoder.into_writer();
        let mut canonical_bytes = [0_u8; 19];
        canonical_bytes[..bytes.len()].copy_from_slice(&bytes);
        Ok(Self {
            minimum,
            maximum,
            canonical_bytes,
            canonical_length: bytes.len(),
        })
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, DeploymentControlErrorV2> {
        let mut decoder = minicbor::Decoder::new(bytes);
        expect_array(&mut decoder, EPOCH_RANGE_FIELDS_V2)?;
        let value = Self::new(decode_u64(&mut decoder)?, decode_u64(&mut decoder)?)?;
        require_eof(&decoder, bytes)?;
        require_canonical(value.canonical_bytes(), bytes)?;
        Ok(value)
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes[..self.canonical_length]
    }

    pub const fn minimum(self) -> u64 {
        self.minimum
    }

    pub const fn maximum(self) -> u64 {
        self.maximum
    }

    pub const fn contains(self, epoch: u64) -> bool {
        epoch >= self.minimum && epoch <= self.maximum
    }
}

/// V2 deliberately has one post-migration state rule; no algorithm selection is accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ClosedDigestRuleV2 {
    ExactCanonicalState = 1,
}

impl ClosedDigestRuleV2 {
    pub const fn from_tag(tag: u16) -> Option<Self> {
        match tag {
            1 => Some(Self::ExactCanonicalState),
            _ => None,
        }
    }

    pub const fn tag(self) -> u16 {
        self as u16
    }
}

/// A nonempty, identity-sorted set of exact worker artifacts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactSetIdentityV2 {
    canonical_bytes: Vec<u8>,
    artifacts: Vec<ArtifactIdentityV2>,
    digest: Digest32V2,
}

impl ArtifactSetIdentityV2 {
    pub fn new(artifacts: Vec<ArtifactIdentityV2>) -> Result<Self, DeploymentControlErrorV2> {
        let limit = usize::try_from(DeploymentHardLimitsV2::compiled().max_component_signatures())
            .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
        if artifacts.len() != 1 || artifacts.len() > limit {
            return Err(DeploymentControlErrorV2::InvalidSecurityStateManifest);
        }
        let mut previous: Option<Digest32V2> = None;
        let first = &artifacts[0];
        for artifact in &artifacts {
            if artifact.artifact_type() != ClosedArtifactTypeV2::Worker
                || artifact.target_os() != first.target_os()
                || artifact.target_architecture() != first.target_architecture()
                || previous
                    .as_ref()
                    .is_some_and(|value| value.as_bytes() >= artifact.identity_digest().as_bytes())
            {
                return Err(DeploymentControlErrorV2::InvalidSecurityStateManifest);
            }
            previous = Some(artifact.identity_digest());
        }
        let mut encoder = minicbor::Encoder::new(Vec::new());
        encoder
            .array(artifacts.len() as u64)
            .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
        for artifact in &artifacts {
            encoder
                .writer_mut()
                .extend_from_slice(artifact.canonical_bytes());
        }
        let canonical_bytes = encoder.into_writer();
        Ok(Self {
            digest: hash_domain(ARTIFACT_SET_DOMAIN_V2, &canonical_bytes),
            canonical_bytes,
            artifacts,
        })
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, DeploymentControlErrorV2> {
        check_manifest_object_size(bytes)?;
        let mut decoder = minicbor::Decoder::new(bytes);
        let count = decode_bounded_array_length(
            &mut decoder,
            DeploymentHardLimitsV2::compiled().max_component_signatures(),
        )?;
        let mut artifacts = Vec::new();
        artifacts
            .try_reserve_exact(count)
            .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
        for _ in 0..count {
            artifacts.push(decode_nested(
                &mut decoder,
                ArtifactIdentityV2::from_canonical_bytes,
            )?);
        }
        require_eof(&decoder, bytes)?;
        let value = Self::new(artifacts)?;
        require_canonical(value.canonical_bytes(), bytes)?;
        Ok(value)
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub fn artifacts(&self) -> &[ArtifactIdentityV2] {
        &self.artifacts
    }

    pub const fn digest(&self) -> Digest32V2 {
        self.digest
    }
}

pub(super) fn decode_nested<T>(
    decoder: &mut minicbor::Decoder<'_>,
    decode: impl FnOnce(&[u8]) -> Result<T, DeploymentControlErrorV2>,
) -> Result<T, DeploymentControlErrorV2> {
    let start = decoder.position();
    decoder
        .skip()
        .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
    decode(
        decoder
            .input()
            .get(start..decoder.position())
            .ok_or(DeploymentControlErrorV2::InvalidSecurityStateManifest)?,
    )
}

pub(super) fn expect_array(
    decoder: &mut minicbor::Decoder<'_>,
    expected: u64,
) -> Result<(), DeploymentControlErrorV2> {
    if decoder
        .array()
        .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)?
        != Some(expected)
    {
        return Err(DeploymentControlErrorV2::InvalidSecurityStateManifest);
    }
    Ok(())
}

pub(super) fn decode_bounded_array_length(
    decoder: &mut minicbor::Decoder<'_>,
    maximum: u64,
) -> Result<usize, DeploymentControlErrorV2> {
    let count = decoder
        .array()
        .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)?
        .ok_or(DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
    if count > maximum {
        return Err(DeploymentControlErrorV2::InvalidSecurityStateManifest);
    }
    usize::try_from(count).map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)
}

pub(super) fn decode_u16(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<u16, DeploymentControlErrorV2> {
    decoder
        .u16()
        .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)
}

pub(super) fn decode_u64(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<u64, DeploymentControlErrorV2> {
    decoder
        .u64()
        .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)
}

pub(super) fn decode_digest(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<Digest32V2, DeploymentControlErrorV2> {
    let bytes = decoder
        .bytes()
        .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
    Ok(Digest32V2::new(bytes))
}

pub(super) fn decode_key_id(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<Ed25519KeyIdV2, DeploymentControlErrorV2> {
    let bytes = decoder
        .bytes()
        .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
    Ok(Ed25519KeyIdV2::new(bytes))
}

pub(super) fn require_eof(
    decoder: &minicbor::Decoder<'_>,
    bytes: &[u8],
) -> Result<(), DeploymentControlErrorV2> {
    if decoder.position() != bytes.len() {
        return Err(DeploymentControlErrorV2::InvalidSecurityStateManifest);
    }
    Ok(())
}

pub(super) fn require_canonical(
    canonical: &[u8],
    original: &[u8],
) -> Result<(), DeploymentControlErrorV2> {
    if canonical != original {
        return Err(DeploymentControlErrorV2::NonCanonicalLedgerEncoding);
    }
    Ok(())
}

pub(super) fn check_manifest_object_size(bytes: &[u8]) -> Result<(), DeploymentControlErrorV2> {
    let maximum = usize::try_from(DeploymentHardLimitsV2::compiled().max_manifest_bytes())
        .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(DeploymentControlErrorV2::InvalidSecurityStateManifest);
    }
    Ok(())
}

pub(super) fn hash_domain(domain: &[u8], bytes: &[u8]) -> Digest32V2 {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(bytes);
    Digest32V2::new(hash.finalize().into())
}

pub(super) fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

fn validate_nonzero_digests(digests: &[Digest32V2]) -> Result<(), DeploymentControlErrorV2> {
    if digests.iter().any(|digest| is_zero(digest.as_bytes())) {
        return Err(DeploymentControlErrorV2::InvalidSecurityStateManifest);
    }
    Ok(())
}

fn encode_digest_array(values: &[Digest32V2]) -> Result<Vec<u8>, DeploymentControlErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(values.len() as u64)
        .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
    for value in values {
        encoder
            .bytes(value.as_bytes())
            .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
    }
    Ok(encoder.into_writer())
}
