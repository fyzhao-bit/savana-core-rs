use ed25519_dalek::{Signature, VerifyingKey};
#[cfg(any(
    test,
    feature = "test-support",
    feature = "macos-development-authority"
))]
use ed25519_dalek::{Signer as _, SigningKey};
use savana_kernel_protocol::v2::{
    derive_ed25519_key_id_v2, Digest32V2, Ed25519KeyIdV2, Ed25519SignatureV2,
};
use sha2::{Digest as _, Sha256};

use super::deployment_manifest_primitives::{
    check_manifest_object_size, decode_bounded_array_length, decode_digest, decode_key_id,
    decode_nested, decode_u16, decode_u64, expect_array, hash_domain, is_zero, require_canonical,
    require_eof,
};
use super::{DeploymentControlErrorV2, DeploymentHardLimitsV2, VersionedIdentityV2};

const RELEASE_ROOT_KEY_FIELDS_V2: u64 = 6;
const COMPONENT_REF_FIELDS_V2: u64 = 2;
const COMPONENT_AUTHORIZATION_FIELDS_V2: u64 = 4;
const RELEASE_ROOT_PAYLOAD_FIELDS_V2: u64 = 9;
const RELEASE_ROOT_COMPLETE_FIELDS_V2: u64 = 3;
const DOMAIN_SIGNATURE_FIELDS_V2: u64 = 4;
const RELEASE_ROOT_SIGNATURE_TAG_V2: u16 = 30;
const MANIFEST_COMPONENT_SIGNATURE_TAG_V2: u16 = 1;
const MANIFEST_RELEASE_SIGNATURE_TAG_V2: u16 = 2;
const RELEASE_ROOT_PAYLOAD_DOMAIN_V2: &[u8] = b"savana.release-trust-root-set.v2.payload\0";
const RELEASE_ROOT_SIGNED_DOMAIN_V2: &[u8] = b"savana.release-trust-root-set.v2.signed\0";
const RELEASE_ROOT_SET_DOMAIN_V2: &[u8] = b"savana.set.release-trust-root.v2\0";
const RELEASE_ROOT_SIGNATURE_DOMAIN_V2: &[u8] = b"savana.release-trust-root-set.v2.signature\0";
const MANIFEST_COMPONENT_SIGNATURE_DOMAIN_V2: &[u8] = b"savana.manifest-component.v2.signature\0";
const MANIFEST_RELEASE_SIGNATURE_DOMAIN_V2: &[u8] = b"savana.manifest-release.v2.signature\0";
const DOMAIN_SIGNATURE_INPUT_V2: &[u8] = b"savana.domain-signature.v2\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u16)]
pub enum ReleaseSigningRoleV2 {
    ManifestComponent = 1,
    ManifestRelease = 2,
    ProductRelease = 3,
    CompletionEvidenceTrustPolicy = 4,
}

impl ReleaseSigningRoleV2 {
    pub const fn from_tag(tag: u16) -> Option<Self> {
        match tag {
            1 => Some(Self::ManifestComponent),
            2 => Some(Self::ManifestRelease),
            3 => Some(Self::ProductRelease),
            4 => Some(Self::CompletionEvidenceTrustPolicy),
            _ => None,
        }
    }

    pub const fn tag(self) -> u16 {
        self as u16
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u16)]
pub enum ManifestComponentKindV2 {
    BinaryArtifact = 1,
    SecurityDomainObject = 2,
    PlatformDomainObject = 3,
    BootstrapArtifact = 4,
}

impl ManifestComponentKindV2 {
    pub const fn from_tag(tag: u16) -> Option<Self> {
        match tag {
            1 => Some(Self::BinaryArtifact),
            2 => Some(Self::SecurityDomainObject),
            3 => Some(Self::PlatformDomainObject),
            4 => Some(Self::BootstrapArtifact),
            _ => None,
        }
    }

    pub const fn tag(self) -> u16 {
        self as u16
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManifestComponentRefV2 {
    kind: ManifestComponentKindV2,
    component_identity_digest: Digest32V2,
}

impl ManifestComponentRefV2 {
    pub fn new(
        kind: ManifestComponentKindV2,
        component_identity_digest: Digest32V2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        if is_zero(component_identity_digest.as_bytes()) {
            return Err(DeploymentControlErrorV2::InvalidSecurityStateManifest);
        }
        Ok(Self {
            kind,
            component_identity_digest,
        })
    }

    pub const fn kind(self) -> ManifestComponentKindV2 {
        self.kind
    }

    pub const fn component_identity_digest(self) -> Digest32V2 {
        self.component_identity_digest
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseRootKeyV2 {
    role: ReleaseSigningRoleV2,
    public_key: [u8; 32],
    key_id: Ed25519KeyIdV2,
    key_epoch: u64,
    not_before_unix_ms: u64,
    not_after_unix_ms: u64,
}

impl ReleaseRootKeyV2 {
    pub fn new(
        role: ReleaseSigningRoleV2,
        public_key: [u8; 32],
        key_epoch: u64,
        not_before_unix_ms: u64,
        not_after_unix_ms: u64,
    ) -> Result<Self, DeploymentControlErrorV2> {
        if key_epoch == 0
            || not_before_unix_ms >= not_after_unix_ms
            || is_zero(&public_key)
            || VerifyingKey::from_bytes(&public_key).is_err()
        {
            return Err(DeploymentControlErrorV2::InvalidSecurityStateManifest);
        }
        Ok(Self {
            role,
            public_key,
            key_id: derive_ed25519_key_id_v2(public_key),
            key_epoch,
            not_before_unix_ms,
            not_after_unix_ms,
        })
    }

    pub const fn role(&self) -> ReleaseSigningRoleV2 {
        self.role
    }

    pub const fn public_key(&self) -> [u8; 32] {
        self.public_key
    }

    pub const fn key_id(&self) -> Ed25519KeyIdV2 {
        self.key_id
    }

    pub const fn key_epoch(&self) -> u64 {
        self.key_epoch
    }

    pub const fn not_before_unix_ms(&self) -> u64 {
        self.not_before_unix_ms
    }

    pub const fn not_after_unix_ms(&self) -> u64 {
        self.not_after_unix_ms
    }

    fn sort_key(&self) -> (u16, [u8; 32], u64) {
        (self.role.tag(), *self.key_id.as_bytes(), self.key_epoch)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ComponentSignerAuthorizationV2 {
    authorization_id: Digest32V2,
    component: ManifestComponentRefV2,
    signer_key_id: Ed25519KeyIdV2,
    signer_key_epoch: u64,
}

impl ComponentSignerAuthorizationV2 {
    pub fn new(
        authorization_id: Digest32V2,
        component: ManifestComponentRefV2,
        signer_key_id: Ed25519KeyIdV2,
        signer_key_epoch: u64,
    ) -> Result<Self, DeploymentControlErrorV2> {
        if is_zero(authorization_id.as_bytes())
            || is_zero(signer_key_id.as_bytes())
            || signer_key_epoch == 0
        {
            return Err(DeploymentControlErrorV2::InvalidSecurityStateManifest);
        }
        Ok(Self {
            authorization_id,
            component,
            signer_key_id,
            signer_key_epoch,
        })
    }

    pub const fn authorization_id(self) -> Digest32V2 {
        self.authorization_id
    }

    pub const fn component(self) -> ManifestComponentRefV2 {
        self.component
    }

    pub const fn signer_key_id(self) -> Ed25519KeyIdV2 {
        self.signer_key_id
    }

    pub const fn signer_key_epoch(self) -> u64 {
        self.signer_key_epoch
    }

    fn sort_key(self) -> (u16, [u8; 32], [u8; 32], u64, [u8; 32]) {
        (
            self.component.kind.tag(),
            *self.component.component_identity_digest.as_bytes(),
            *self.signer_key_id.as_bytes(),
            self.signer_key_epoch,
            *self.authorization_id.as_bytes(),
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManifestDomainSignatureV2 {
    domain_tag: u16,
    signer_key_id: Ed25519KeyIdV2,
    signer_key_epoch: u64,
    signature: Ed25519SignatureV2,
}

impl ManifestDomainSignatureV2 {
    pub(crate) const fn empty_for_decode() -> Self {
        Self {
            domain_tag: 0,
            signer_key_id: Ed25519KeyIdV2::new([0; 32]),
            signer_key_epoch: 0,
            signature: Ed25519SignatureV2::new([0; 64]),
        }
    }

    pub const fn domain_tag(self) -> u16 {
        self.domain_tag
    }

    pub const fn signer_key_id(self) -> Ed25519KeyIdV2 {
        self.signer_key_id
    }

    pub const fn signer_key_epoch(self) -> u64 {
        self.signer_key_epoch
    }

    pub const fn signature(self) -> Ed25519SignatureV2 {
        self.signature
    }

    #[cfg(any(
        test,
        feature = "test-support",
        feature = "macos-development-authority"
    ))]
    pub fn sign_for_test(
        domain_tag: u16,
        domain: &[u8],
        payload_digest: Digest32V2,
        signing_key: &SigningKey,
        key_epoch: u64,
    ) -> Self {
        let key_id = derive_ed25519_key_id_v2(signing_key.verifying_key().to_bytes());
        let input = domain_signature_input(domain_tag, domain, payload_digest);
        Self {
            domain_tag,
            signer_key_id: key_id,
            signer_key_epoch: key_epoch,
            signature: Ed25519SignatureV2::new(signing_key.sign(&input).to_bytes()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct InstallerOrMdmVerifierV2 {
    key_id: Ed25519KeyIdV2,
    key_epoch: u64,
    verifying_key: VerifyingKey,
}

impl InstallerOrMdmVerifierV2 {
    pub fn new(
        key_id: Ed25519KeyIdV2,
        key_epoch: u64,
        public_key: [u8; 32],
    ) -> Result<Self, DeploymentControlErrorV2> {
        if key_epoch == 0
            || derive_ed25519_key_id_v2(public_key) != key_id
            || is_zero(key_id.as_bytes())
        {
            return Err(DeploymentControlErrorV2::InvalidSecurityStateManifest);
        }
        Ok(Self {
            key_id,
            key_epoch,
            verifying_key: VerifyingKey::from_bytes(&public_key)
                .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)?,
        })
    }

    pub const fn key_id(&self) -> Ed25519KeyIdV2 {
        self.key_id
    }

    pub const fn key_epoch(&self) -> u64 {
        self.key_epoch
    }

    pub(crate) fn verify_operational_root_signature(
        &self,
        signature: ManifestDomainSignatureV2,
        domain_tag: u16,
        domain: &[u8],
        payload_digest: Digest32V2,
    ) -> Result<(), DeploymentControlErrorV2> {
        verify_domain_signature(
            &self.verifying_key,
            self.key_id,
            self.key_epoch,
            signature,
            domain_tag,
            domain,
            payload_digest,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseTrustRootSetV2 {
    canonical_bytes: Vec<u8>,
    product_family_digest: Digest32V2,
    root_set_sequence: u64,
    previous_signed_digest: Option<Digest32V2>,
    roots: Vec<ReleaseRootKeyV2>,
    component_authorizations: Vec<ComponentSignerAuthorizationV2>,
    release_trust_root_set_digest: Digest32V2,
    not_before_unix_ms: u64,
    not_after_unix_ms: u64,
    payload_digest: Digest32V2,
    signed_digest: Digest32V2,
    installer_signature: ManifestDomainSignatureV2,
}

impl ReleaseTrustRootSetV2 {
    pub fn from_canonical_bytes(
        bytes: &[u8],
        verifier: &InstallerOrMdmVerifierV2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        check_manifest_object_size(bytes)?;
        let decoded = decode_release_root_set(bytes)?;
        validate_release_root_payload(&decoded)?;
        let canonical_payload = encode_release_root_payload(&decoded)?;
        if hash_domain(RELEASE_ROOT_PAYLOAD_DOMAIN_V2, &canonical_payload) != decoded.payload_digest
        {
            return Err(DeploymentControlErrorV2::InvalidSecurityStateManifest);
        }
        verify_domain_signature(
            &verifier.verifying_key,
            verifier.key_id,
            verifier.key_epoch,
            decoded.installer_signature,
            RELEASE_ROOT_SIGNATURE_TAG_V2,
            RELEASE_ROOT_SIGNATURE_DOMAIN_V2,
            decoded.payload_digest,
        )?;
        let canonical_bytes = encode_release_root_complete(&decoded)?;
        require_canonical(&canonical_bytes, bytes)?;
        let signed_digest = hash_domain(RELEASE_ROOT_SIGNED_DOMAIN_V2, &canonical_bytes);
        Ok(Self {
            canonical_bytes,
            product_family_digest: decoded.product_family_digest,
            root_set_sequence: decoded.root_set_sequence,
            previous_signed_digest: decoded.previous_signed_digest,
            roots: decoded.roots,
            component_authorizations: decoded.component_authorizations,
            release_trust_root_set_digest: decoded.release_trust_root_set_digest,
            not_before_unix_ms: decoded.not_before_unix_ms,
            not_after_unix_ms: decoded.not_after_unix_ms,
            payload_digest: decoded.payload_digest,
            signed_digest,
            installer_signature: decoded.installer_signature,
        })
    }

    #[cfg(any(
        test,
        feature = "test-support",
        feature = "macos-development-authority"
    ))]
    #[allow(clippy::too_many_arguments)]
    pub fn new_signed_for_test(
        product_family_digest: Digest32V2,
        root_set_sequence: u64,
        previous_signed_digest: Option<Digest32V2>,
        roots: Vec<ReleaseRootKeyV2>,
        component_authorizations: Vec<ComponentSignerAuthorizationV2>,
        not_before_unix_ms: u64,
        not_after_unix_ms: u64,
        installer_signing_key: &SigningKey,
        installer_key_epoch: u64,
    ) -> Result<Self, DeploymentControlErrorV2> {
        let release_trust_root_set_digest =
            compute_release_root_set_digest(&roots, &component_authorizations)?;
        let mut decoded = DecodedReleaseTrustRootSetV2 {
            product_family_digest,
            root_set_sequence,
            previous_signed_digest,
            roots,
            component_authorizations,
            release_trust_root_set_digest,
            not_before_unix_ms,
            not_after_unix_ms,
            payload_digest: Digest32V2::new([0; 32]),
            installer_signature: ManifestDomainSignatureV2 {
                domain_tag: RELEASE_ROOT_SIGNATURE_TAG_V2,
                signer_key_id: derive_ed25519_key_id_v2(
                    installer_signing_key.verifying_key().to_bytes(),
                ),
                signer_key_epoch: installer_key_epoch,
                signature: Ed25519SignatureV2::new([0; 64]),
            },
        };
        validate_release_root_payload(&decoded)?;
        decoded.payload_digest = hash_domain(
            RELEASE_ROOT_PAYLOAD_DOMAIN_V2,
            &encode_release_root_payload(&decoded)?,
        );
        decoded.installer_signature = ManifestDomainSignatureV2::sign_for_test(
            RELEASE_ROOT_SIGNATURE_TAG_V2,
            RELEASE_ROOT_SIGNATURE_DOMAIN_V2,
            decoded.payload_digest,
            installer_signing_key,
            installer_key_epoch,
        );
        let bytes = encode_release_root_complete(&decoded)?;
        let verifier = InstallerOrMdmVerifierV2::new(
            decoded.installer_signature.signer_key_id,
            installer_key_epoch,
            installer_signing_key.verifying_key().to_bytes(),
        )?;
        Self::from_canonical_bytes(&bytes, &verifier)
    }

    pub fn validate_predecessor(
        &self,
        predecessor: Option<&Self>,
    ) -> Result<(), DeploymentControlErrorV2> {
        match (
            self.root_set_sequence,
            self.previous_signed_digest,
            predecessor,
        ) {
            (1, None, None) => Ok(()),
            (sequence, Some(expected), Some(previous))
                if sequence == previous.root_set_sequence.checked_add(1).unwrap_or(0)
                    && expected == previous.signed_digest
                    && self.product_family_digest == previous.product_family_digest =>
            {
                Ok(())
            }
            _ => Err(DeploymentControlErrorV2::InvalidSecurityStateManifest),
        }
    }

    pub fn matches_versioned_identity(
        &self,
        identity: &VersionedIdentityV2,
    ) -> Result<(), DeploymentControlErrorV2> {
        if identity.domain() != super::ClosedSecurityDomainV2::ReleaseTrustRootSet
            || identity.sequence() != self.root_set_sequence
            || identity.content_digest() != self.signed_digest
            || identity.signer_key_id() != self.installer_signature.signer_key_id
            || identity.signer_key_epoch() != self.installer_signature.signer_key_epoch
            || identity.not_before_unix_ms() != self.not_before_unix_ms
            || identity.not_after_unix_ms() != self.not_after_unix_ms
        {
            return Err(DeploymentControlErrorV2::InvalidSecurityStateManifest);
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub fn roots(&self) -> &[ReleaseRootKeyV2] {
        &self.roots
    }

    pub fn component_authorizations(&self) -> &[ComponentSignerAuthorizationV2] {
        &self.component_authorizations
    }

    pub const fn signed_digest(&self) -> Digest32V2 {
        self.signed_digest
    }

    pub const fn payload_digest(&self) -> Digest32V2 {
        self.payload_digest
    }

    pub const fn release_trust_root_set_digest(&self) -> Digest32V2 {
        self.release_trust_root_set_digest
    }
}

impl ReleaseTrustRootSetV2 {
    pub const fn product_family_digest(&self) -> Digest32V2 {
        self.product_family_digest
    }

    pub(crate) fn verify_component_signature(
        &self,
        component: ManifestComponentRefV2,
        authorization_id: Digest32V2,
        signature: ManifestDomainSignatureV2,
        binding_digest: Digest32V2,
        at_unix_ms: u64,
    ) -> Result<(), DeploymentControlErrorV2> {
        let authorization = self
            .component_authorizations
            .iter()
            .find(|authorization| {
                authorization.component == component
                    && authorization.authorization_id == authorization_id
            })
            .ok_or(DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
        let root = self
            .roots
            .iter()
            .find(|root| {
                root.role == ReleaseSigningRoleV2::ManifestComponent
                    && root.key_id == authorization.signer_key_id
                    && root.key_epoch == authorization.signer_key_epoch
            })
            .ok_or(DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
        verify_root_signature(
            root,
            signature,
            MANIFEST_COMPONENT_SIGNATURE_TAG_V2,
            MANIFEST_COMPONENT_SIGNATURE_DOMAIN_V2,
            binding_digest,
            at_unix_ms,
        )
    }

    pub(crate) fn verify_release_signature(
        &self,
        signature: ManifestDomainSignatureV2,
        manifest_payload_digest: Digest32V2,
        at_unix_ms: u64,
    ) -> Result<(), DeploymentControlErrorV2> {
        let root = self
            .roots
            .iter()
            .find(|root| {
                root.role == ReleaseSigningRoleV2::ManifestRelease
                    && root.key_id == signature.signer_key_id
                    && root.key_epoch == signature.signer_key_epoch
            })
            .ok_or(DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
        verify_root_signature(
            root,
            signature,
            MANIFEST_RELEASE_SIGNATURE_TAG_V2,
            MANIFEST_RELEASE_SIGNATURE_DOMAIN_V2,
            manifest_payload_digest,
            at_unix_ms,
        )
    }
}

#[derive(Debug, Clone)]
struct DecodedReleaseTrustRootSetV2 {
    product_family_digest: Digest32V2,
    root_set_sequence: u64,
    previous_signed_digest: Option<Digest32V2>,
    roots: Vec<ReleaseRootKeyV2>,
    component_authorizations: Vec<ComponentSignerAuthorizationV2>,
    release_trust_root_set_digest: Digest32V2,
    not_before_unix_ms: u64,
    not_after_unix_ms: u64,
    payload_digest: Digest32V2,
    installer_signature: ManifestDomainSignatureV2,
}

fn validate_release_root_payload(
    value: &DecodedReleaseTrustRootSetV2,
) -> Result<(), DeploymentControlErrorV2> {
    if is_zero(value.product_family_digest.as_bytes())
        || value.root_set_sequence == 0
        || value.not_before_unix_ms >= value.not_after_unix_ms
        || value.roots.is_empty()
        || value.roots.len() as u64 > DeploymentHardLimitsV2::compiled().max_release_trust_roots()
        || value.component_authorizations.len() as u64
            > DeploymentHardLimitsV2::compiled().max_component_signatures()
        || value
            .roots
            .windows(2)
            .any(|pair| pair[0].sort_key() >= pair[1].sort_key())
        || value.roots.iter().enumerate().any(|(index, root)| {
            value.roots[index + 1..]
                .iter()
                .any(|candidate| root.key_id == candidate.key_id)
        })
        || value
            .component_authorizations
            .windows(2)
            .any(|pair| pair[0].sort_key() >= pair[1].sort_key())
        || value
            .component_authorizations
            .windows(2)
            .any(|pair| pair[0].component == pair[1].component)
        || value.roots.iter().any(|root| {
            root.not_before_unix_ms < value.not_before_unix_ms
                || root.not_after_unix_ms > value.not_after_unix_ms
        })
        || value.component_authorizations.iter().any(|authorization| {
            !value.roots.iter().any(|root| {
                root.role == ReleaseSigningRoleV2::ManifestComponent
                    && root.key_id == authorization.signer_key_id
                    && root.key_epoch == authorization.signer_key_epoch
            })
        })
        || compute_release_root_set_digest(&value.roots, &value.component_authorizations)?
            != value.release_trust_root_set_digest
    {
        return Err(DeploymentControlErrorV2::InvalidSecurityStateManifest);
    }
    match (value.root_set_sequence, value.previous_signed_digest) {
        (1, None) | (2.., Some(_)) => Ok(()),
        _ => Err(DeploymentControlErrorV2::InvalidSecurityStateManifest),
    }
}

fn compute_release_root_set_digest(
    roots: &[ReleaseRootKeyV2],
    authorizations: &[ComponentSignerAuthorizationV2],
) -> Result<Digest32V2, DeploymentControlErrorV2> {
    let count = roots
        .len()
        .checked_add(authorizations.len())
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(count)
        .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
    for root in roots {
        encoder
            .array(2)
            .and_then(|encoder| encoder.u16(1))
            .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
        encode_release_root_key(&mut encoder, root)?;
    }
    for authorization in authorizations {
        encoder
            .array(2)
            .and_then(|encoder| encoder.u16(2))
            .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
        encode_component_authorization(&mut encoder, *authorization)?;
    }
    let items = encoder.into_writer();
    let mut material = Vec::with_capacity(8 + items.len());
    material.extend_from_slice(&count.to_be_bytes());
    material.extend_from_slice(&items);
    Ok(hash_domain(RELEASE_ROOT_SET_DOMAIN_V2, &material))
}

fn decode_release_root_set(
    bytes: &[u8],
) -> Result<DecodedReleaseTrustRootSetV2, DeploymentControlErrorV2> {
    let mut decoder = minicbor::Decoder::new(bytes);
    expect_array(&mut decoder, RELEASE_ROOT_COMPLETE_FIELDS_V2)?;
    let payload = decode_nested(&mut decoder, decode_release_root_payload)?;
    let payload_digest = decode_digest(&mut decoder)?;
    let installer_signature = decode_domain_signature(&mut decoder)?;
    require_eof(&decoder, bytes)?;
    Ok(DecodedReleaseTrustRootSetV2 {
        payload_digest,
        installer_signature,
        ..payload
    })
}

fn decode_release_root_payload(
    bytes: &[u8],
) -> Result<DecodedReleaseTrustRootSetV2, DeploymentControlErrorV2> {
    let mut decoder = minicbor::Decoder::new(bytes);
    expect_array(&mut decoder, RELEASE_ROOT_PAYLOAD_FIELDS_V2)?;
    if decode_u16(&mut decoder)? != 2 {
        return Err(DeploymentControlErrorV2::InvalidSecurityStateManifest);
    }
    let product_family_digest = decode_digest(&mut decoder)?;
    let root_set_sequence = decode_u64(&mut decoder)?;
    let previous_signed_digest = decode_optional_digest(&mut decoder)?;
    let root_count = decode_bounded_array_length(
        &mut decoder,
        DeploymentHardLimitsV2::compiled().max_release_trust_roots(),
    )?;
    let mut roots = Vec::with_capacity(root_count);
    for _ in 0..root_count {
        roots.push(decode_release_root_key(&mut decoder)?);
    }
    let authorization_count = decode_bounded_array_length(
        &mut decoder,
        DeploymentHardLimitsV2::compiled().max_component_signatures(),
    )?;
    let mut component_authorizations = Vec::with_capacity(authorization_count);
    for _ in 0..authorization_count {
        component_authorizations.push(decode_component_authorization(&mut decoder)?);
    }
    let release_trust_root_set_digest = decode_digest(&mut decoder)?;
    let not_before_unix_ms = decode_u64(&mut decoder)?;
    let not_after_unix_ms = decode_u64(&mut decoder)?;
    require_eof(&decoder, bytes)?;
    Ok(DecodedReleaseTrustRootSetV2 {
        product_family_digest,
        root_set_sequence,
        previous_signed_digest,
        roots,
        component_authorizations,
        release_trust_root_set_digest,
        not_before_unix_ms,
        not_after_unix_ms,
        payload_digest: Digest32V2::new([0; 32]),
        installer_signature: ManifestDomainSignatureV2 {
            domain_tag: 0,
            signer_key_id: Ed25519KeyIdV2::new([0; 32]),
            signer_key_epoch: 0,
            signature: Ed25519SignatureV2::new([0; 64]),
        },
    })
}

fn encode_release_root_complete(
    value: &DecodedReleaseTrustRootSetV2,
) -> Result<Vec<u8>, DeploymentControlErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(RELEASE_ROOT_COMPLETE_FIELDS_V2)
        .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
    encoder
        .writer_mut()
        .extend_from_slice(&encode_release_root_payload(value)?);
    encoder
        .bytes(value.payload_digest.as_bytes())
        .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
    encode_domain_signature(&mut encoder, value.installer_signature)?;
    Ok(encoder.into_writer())
}

fn encode_release_root_payload(
    value: &DecodedReleaseTrustRootSetV2,
) -> Result<Vec<u8>, DeploymentControlErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(RELEASE_ROOT_PAYLOAD_FIELDS_V2)
        .and_then(|encoder| encoder.u16(2))
        .and_then(|encoder| encoder.bytes(value.product_family_digest.as_bytes()))
        .and_then(|encoder| encoder.u64(value.root_set_sequence))
        .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
    encode_optional_digest(&mut encoder, value.previous_signed_digest)?;
    encoder
        .array(value.roots.len() as u64)
        .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
    for root in &value.roots {
        encode_release_root_key(&mut encoder, root)?;
    }
    encoder
        .array(value.component_authorizations.len() as u64)
        .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
    for authorization in &value.component_authorizations {
        encode_component_authorization(&mut encoder, *authorization)?;
    }
    encoder
        .bytes(value.release_trust_root_set_digest.as_bytes())
        .and_then(|encoder| encoder.u64(value.not_before_unix_ms))
        .and_then(|encoder| encoder.u64(value.not_after_unix_ms))
        .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
    Ok(encoder.into_writer())
}

fn decode_release_root_key(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<ReleaseRootKeyV2, DeploymentControlErrorV2> {
    expect_array(decoder, RELEASE_ROOT_KEY_FIELDS_V2)?;
    let role = ReleaseSigningRoleV2::from_tag(decode_u16(decoder)?)
        .ok_or(DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
    let public_key = decoder
        .bytes()
        .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
    let public_key: [u8; 32] = public_key
        .try_into()
        .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
    let encoded_key_id = decode_key_id(decoder)?;
    let value = ReleaseRootKeyV2::new(
        role,
        public_key,
        decode_u64(decoder)?,
        decode_u64(decoder)?,
        decode_u64(decoder)?,
    )?;
    if value.key_id != encoded_key_id {
        return Err(DeploymentControlErrorV2::InvalidSecurityStateManifest);
    }
    Ok(value)
}

fn encode_release_root_key(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    root: &ReleaseRootKeyV2,
) -> Result<(), DeploymentControlErrorV2> {
    encoder
        .array(RELEASE_ROOT_KEY_FIELDS_V2)
        .and_then(|encoder| encoder.u16(root.role.tag()))
        .and_then(|encoder| encoder.bytes(&root.public_key))
        .and_then(|encoder| encoder.bytes(root.key_id.as_bytes()))
        .and_then(|encoder| encoder.u64(root.key_epoch))
        .and_then(|encoder| encoder.u64(root.not_before_unix_ms))
        .and_then(|encoder| encoder.u64(root.not_after_unix_ms))
        .map(|_| ())
        .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)
}

pub(crate) fn decode_component_ref(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<ManifestComponentRefV2, DeploymentControlErrorV2> {
    expect_array(decoder, COMPONENT_REF_FIELDS_V2)?;
    ManifestComponentRefV2::new(
        ManifestComponentKindV2::from_tag(decode_u16(decoder)?)
            .ok_or(DeploymentControlErrorV2::InvalidSecurityStateManifest)?,
        decode_digest(decoder)?,
    )
}

pub(crate) fn encode_component_ref(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    component: ManifestComponentRefV2,
) -> Result<(), DeploymentControlErrorV2> {
    encoder
        .array(COMPONENT_REF_FIELDS_V2)
        .and_then(|encoder| encoder.u16(component.kind.tag()))
        .and_then(|encoder| encoder.bytes(component.component_identity_digest.as_bytes()))
        .map(|_| ())
        .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)
}

fn decode_component_authorization(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<ComponentSignerAuthorizationV2, DeploymentControlErrorV2> {
    expect_array(decoder, COMPONENT_AUTHORIZATION_FIELDS_V2)?;
    ComponentSignerAuthorizationV2::new(
        decode_digest(decoder)?,
        decode_component_ref(decoder)?,
        decode_key_id(decoder)?,
        decode_u64(decoder)?,
    )
}

fn encode_component_authorization(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    authorization: ComponentSignerAuthorizationV2,
) -> Result<(), DeploymentControlErrorV2> {
    encoder
        .array(COMPONENT_AUTHORIZATION_FIELDS_V2)
        .and_then(|encoder| encoder.bytes(authorization.authorization_id.as_bytes()))
        .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
    encode_component_ref(encoder, authorization.component)?;
    encoder
        .bytes(authorization.signer_key_id.as_bytes())
        .and_then(|encoder| encoder.u64(authorization.signer_key_epoch))
        .map(|_| ())
        .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)
}

pub(crate) fn decode_domain_signature(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<ManifestDomainSignatureV2, DeploymentControlErrorV2> {
    expect_array(decoder, DOMAIN_SIGNATURE_FIELDS_V2)?;
    let domain_tag = decode_u16(decoder)?;
    let signer_key_id = decode_key_id(decoder)?;
    let signer_key_epoch = decode_u64(decoder)?;
    let signature = decoder
        .bytes()
        .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
    let signature: [u8; 64] = signature
        .try_into()
        .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
    Ok(ManifestDomainSignatureV2 {
        domain_tag,
        signer_key_id,
        signer_key_epoch,
        signature: Ed25519SignatureV2::new(signature),
    })
}

pub(crate) fn encode_domain_signature(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    signature: ManifestDomainSignatureV2,
) -> Result<(), DeploymentControlErrorV2> {
    encoder
        .array(DOMAIN_SIGNATURE_FIELDS_V2)
        .and_then(|encoder| encoder.u16(signature.domain_tag))
        .and_then(|encoder| encoder.bytes(signature.signer_key_id.as_bytes()))
        .and_then(|encoder| encoder.u64(signature.signer_key_epoch))
        .and_then(|encoder| encoder.bytes(signature.signature.as_bytes()))
        .map(|_| ())
        .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)
}

fn decode_optional_digest(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<Option<Digest32V2>, DeploymentControlErrorV2> {
    let count = decoder
        .array()
        .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)?
        .ok_or(DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
    match (count, decode_u16(decoder)?) {
        (1, 0) => Ok(None),
        (2, 1) => Ok(Some(decode_digest(decoder)?)),
        _ => Err(DeploymentControlErrorV2::InvalidSecurityStateManifest),
    }
}

fn encode_optional_digest(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    digest: Option<Digest32V2>,
) -> Result<(), DeploymentControlErrorV2> {
    match digest {
        None => encoder
            .array(1)
            .and_then(|encoder| encoder.u16(0))
            .map(|_| ())
            .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest),
        Some(digest) => encoder
            .array(2)
            .and_then(|encoder| encoder.u16(1))
            .and_then(|encoder| encoder.bytes(digest.as_bytes()))
            .map(|_| ())
            .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest),
    }
}

fn verify_root_signature(
    root: &ReleaseRootKeyV2,
    signature: ManifestDomainSignatureV2,
    expected_domain_tag: u16,
    expected_domain: &[u8],
    digest: Digest32V2,
    at_unix_ms: u64,
) -> Result<(), DeploymentControlErrorV2> {
    if at_unix_ms < root.not_before_unix_ms || at_unix_ms > root.not_after_unix_ms {
        return Err(DeploymentControlErrorV2::InvalidSecurityStateManifest);
    }
    verify_domain_signature(
        &VerifyingKey::from_bytes(&root.public_key)
            .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)?,
        root.key_id,
        root.key_epoch,
        signature,
        expected_domain_tag,
        expected_domain,
        digest,
    )
}

#[allow(clippy::too_many_arguments)]
fn verify_domain_signature(
    verifying_key: &VerifyingKey,
    expected_key_id: Ed25519KeyIdV2,
    expected_key_epoch: u64,
    signature: ManifestDomainSignatureV2,
    expected_domain_tag: u16,
    expected_domain: &[u8],
    digest: Digest32V2,
) -> Result<(), DeploymentControlErrorV2> {
    if signature.domain_tag != expected_domain_tag
        || signature.signer_key_id != expected_key_id
        || signature.signer_key_epoch != expected_key_epoch
        || is_zero(signature.signature.as_bytes())
    {
        return Err(DeploymentControlErrorV2::InvalidSecurityStateManifest);
    }
    let input = domain_signature_input(expected_domain_tag, expected_domain, digest);
    verifying_key
        .verify_strict(
            &input,
            &Signature::from_bytes(signature.signature.as_bytes()),
        )
        .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)
}

fn domain_signature_input(tag: u16, domain: &[u8], digest: Digest32V2) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(DOMAIN_SIGNATURE_INPUT_V2);
    hash.update(tag.to_be_bytes());
    hash.update(domain);
    hash.update(digest.as_bytes());
    hash.finalize().into()
}

pub(crate) fn manifest_component_binding_digest(
    component: ManifestComponentRefV2,
    authorization_id: Digest32V2,
    manifest_payload_digest: Digest32V2,
) -> Result<Digest32V2, DeploymentControlErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(3)
        .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
    encode_component_ref(&mut encoder, component)?;
    encoder
        .bytes(authorization_id.as_bytes())
        .and_then(|encoder| encoder.bytes(manifest_payload_digest.as_bytes()))
        .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
    Ok(hash_domain(
        b"savana.manifest-component.v2.binding\0",
        &encoder.into_writer(),
    ))
}
