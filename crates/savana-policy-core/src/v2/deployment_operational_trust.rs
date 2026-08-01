#[cfg(any(
    test,
    feature = "test-support",
    feature = "macos-development-authority"
))]
use ed25519_dalek::SigningKey;
use ed25519_dalek::VerifyingKey;
use savana_kernel_protocol::v2::{derive_ed25519_key_id_v2, Digest32V2, Ed25519KeyIdV2};
use sha2::{Digest as _, Sha256};

use super::deployment_manifest_primitives::{
    check_manifest_object_size, decode_bounded_array_length, decode_digest, decode_key_id,
    decode_nested, decode_u16, decode_u64, expect_array, hash_domain, is_zero, require_canonical,
    require_eof,
};
use super::deployment_release_trust::{decode_domain_signature, encode_domain_signature};
use super::{
    ClosedSecurityDomainV2, DeploymentActivationVerifierV2, DeploymentAuthorizationVerifierV2,
    DeploymentControlErrorV2, DeploymentHardLimitsV2, InstallerOrMdmVerifierV2,
    ManifestDomainSignatureV2, VersionedIdentityV2,
};

const OPERATIONAL_ROOT_ITEM_FIELDS_V2: u64 = 6;
const OPERATIONAL_ROOT_BINDING_FIELDS_V2: u64 = 2;
const OPERATIONAL_ROOT_PAYLOAD_FIELDS_V2: u64 = 8;
const OPERATIONAL_ROOT_COMPLETE_FIELDS_V2: u64 = 3;
const OPERATIONAL_ROOT_SCHEMA_VERSION_V2: u16 = 2;
const OPERATIONAL_ROOT_SIGNATURE_TAG_V2: u16 = 28;
const OPERATIONAL_ROOT_PAYLOAD_DOMAIN_V2: &[u8] = b"savana.operational-trust-root-set.v2.payload\0";
const OPERATIONAL_ROOT_SIGNED_DOMAIN_V2: &[u8] = b"savana.operational-trust-root-set.v2.signed\0";
const OPERATIONAL_ROOT_SIGNATURE_DOMAIN_V2: &[u8] =
    b"savana.operational-trust-root-set.v2.signature\0";
const DEPLOYMENT_ROOT_SET_DOMAIN_V2: &[u8] = b"savana.set.deployment-trust-root.v2\0";
const ACTIVATION_ROOT_SET_DOMAIN_V2: &[u8] = b"savana.set.activation-trust-root.v2\0";
const DECLASSIFICATION_ROOT_SET_DOMAIN_V2: &[u8] = b"savana.set.declassification-trust-root.v2\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u16)]
pub enum OperationalTrustRootPurposeV2 {
    DeploymentAuthorization = 1,
    RollbackAuthorization = 2,
    InstallationActivation = 3,
    InstallerOrMdm = 4,
    DeclassificationAuthority = 5,
}

impl OperationalTrustRootPurposeV2 {
    const fn from_tag(tag: u16) -> Option<Self> {
        match tag {
            1 => Some(Self::DeploymentAuthorization),
            2 => Some(Self::RollbackAuthorization),
            3 => Some(Self::InstallationActivation),
            4 => Some(Self::InstallerOrMdm),
            5 => Some(Self::DeclassificationAuthority),
            _ => None,
        }
    }

    pub const fn tag(self) -> u16 {
        self as u16
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationalTrustRootSetItemV2 {
    purpose: OperationalTrustRootPurposeV2,
    key_id: Ed25519KeyIdV2,
    key_epoch: u64,
    public_key: [u8; 32],
    not_before_unix_ms: u64,
    not_after_unix_ms: u64,
}

impl OperationalTrustRootSetItemV2 {
    pub fn new(
        purpose: OperationalTrustRootPurposeV2,
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
            return Err(DeploymentControlErrorV2::InvalidOperationalTrustRootSet);
        }
        Ok(Self {
            purpose,
            key_id: derive_ed25519_key_id_v2(public_key),
            key_epoch,
            public_key,
            not_before_unix_ms,
            not_after_unix_ms,
        })
    }

    pub const fn purpose(&self) -> OperationalTrustRootPurposeV2 {
        self.purpose
    }

    pub const fn key_id(&self) -> Ed25519KeyIdV2 {
        self.key_id
    }

    pub const fn key_epoch(&self) -> u64 {
        self.key_epoch
    }

    pub const fn public_key(&self) -> [u8; 32] {
        self.public_key
    }

    pub const fn not_before_unix_ms(&self) -> u64 {
        self.not_before_unix_ms
    }

    pub const fn not_after_unix_ms(&self) -> u64 {
        self.not_after_unix_ms
    }

    fn sort_key(&self) -> (u16, [u8; 32], u64) {
        (self.purpose.tag(), *self.key_id.as_bytes(), self.key_epoch)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationalTrustRootSetBindingV2 {
    Deployment {
        deployment_trust_root_set_digest: Digest32V2,
    },
    Activation {
        activation_trust_root_set_digest: Digest32V2,
    },
    Declassification {
        declassification_trust_root_set_digest: Digest32V2,
    },
}

impl OperationalTrustRootSetBindingV2 {
    pub const fn tag(self) -> u16 {
        match self {
            Self::Deployment { .. } => 1,
            Self::Activation { .. } => 2,
            Self::Declassification { .. } => 3,
        }
    }

    pub const fn member_set_digest(self) -> Digest32V2 {
        match self {
            Self::Deployment {
                deployment_trust_root_set_digest,
            } => deployment_trust_root_set_digest,
            Self::Activation {
                activation_trust_root_set_digest,
            } => activation_trust_root_set_digest,
            Self::Declassification {
                declassification_trust_root_set_digest,
            } => declassification_trust_root_set_digest,
        }
    }

    const fn with_digest(tag: u16, digest: Digest32V2) -> Option<Self> {
        match tag {
            1 => Some(Self::Deployment {
                deployment_trust_root_set_digest: digest,
            }),
            2 => Some(Self::Activation {
                activation_trust_root_set_digest: digest,
            }),
            3 => Some(Self::Declassification {
                declassification_trust_root_set_digest: digest,
            }),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationalTrustRootSetV2 {
    canonical_bytes: Vec<u8>,
    product_family_digest: Digest32V2,
    root_set_sequence: u64,
    previous_signed_digest: Option<Digest32V2>,
    binding: OperationalTrustRootSetBindingV2,
    members: Vec<OperationalTrustRootSetItemV2>,
    not_before_unix_ms: u64,
    not_after_unix_ms: u64,
    payload_digest: Digest32V2,
    signed_digest: Digest32V2,
    installer_signature: ManifestDomainSignatureV2,
}

impl OperationalTrustRootSetV2 {
    pub fn from_canonical_bytes(
        bytes: &[u8],
        verifier: &InstallerOrMdmVerifierV2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        map_invalid(check_manifest_object_size(bytes))?;
        let decoded = decode_complete(bytes)?;
        validate_payload(&decoded)?;
        let payload = encode_payload(&decoded)?;
        if hash_domain(OPERATIONAL_ROOT_PAYLOAD_DOMAIN_V2, &payload) != decoded.payload_digest {
            return Err(DeploymentControlErrorV2::InvalidOperationalTrustRootSet);
        }
        verifier
            .verify_operational_root_signature(
                decoded.installer_signature,
                OPERATIONAL_ROOT_SIGNATURE_TAG_V2,
                OPERATIONAL_ROOT_SIGNATURE_DOMAIN_V2,
                decoded.payload_digest,
            )
            .map_err(|_| DeploymentControlErrorV2::InvalidOperationalTrustRootSet)?;
        let canonical_bytes = encode_complete(&decoded)?;
        map_invalid(require_canonical(&canonical_bytes, bytes))?;
        let signed_digest = hash_domain(OPERATIONAL_ROOT_SIGNED_DOMAIN_V2, &canonical_bytes);
        Ok(Self {
            canonical_bytes,
            product_family_digest: decoded.product_family_digest,
            root_set_sequence: decoded.root_set_sequence,
            previous_signed_digest: decoded.previous_signed_digest,
            binding: decoded.binding,
            members: decoded.members,
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
    pub fn new_deployment_signed_for_test(
        product_family_digest: Digest32V2,
        root_set_sequence: u64,
        previous_signed_digest: Option<Digest32V2>,
        members: Vec<OperationalTrustRootSetItemV2>,
        not_before_unix_ms: u64,
        not_after_unix_ms: u64,
        installer_signing_key: &SigningKey,
        installer_key_epoch: u64,
    ) -> Result<Self, DeploymentControlErrorV2> {
        Self::new_signed_for_test(
            1,
            product_family_digest,
            root_set_sequence,
            previous_signed_digest,
            members,
            not_before_unix_ms,
            not_after_unix_ms,
            installer_signing_key,
            installer_key_epoch,
        )
    }

    #[cfg(any(
        test,
        feature = "test-support",
        feature = "macos-development-authority"
    ))]
    #[allow(clippy::too_many_arguments)]
    pub fn new_activation_signed_for_test(
        product_family_digest: Digest32V2,
        root_set_sequence: u64,
        previous_signed_digest: Option<Digest32V2>,
        members: Vec<OperationalTrustRootSetItemV2>,
        not_before_unix_ms: u64,
        not_after_unix_ms: u64,
        installer_signing_key: &SigningKey,
        installer_key_epoch: u64,
    ) -> Result<Self, DeploymentControlErrorV2> {
        Self::new_signed_for_test(
            2,
            product_family_digest,
            root_set_sequence,
            previous_signed_digest,
            members,
            not_before_unix_ms,
            not_after_unix_ms,
            installer_signing_key,
            installer_key_epoch,
        )
    }

    #[cfg(any(
        test,
        feature = "test-support",
        feature = "macos-development-authority"
    ))]
    #[allow(clippy::too_many_arguments)]
    pub fn new_declassification_signed_for_test(
        product_family_digest: Digest32V2,
        root_set_sequence: u64,
        previous_signed_digest: Option<Digest32V2>,
        members: Vec<OperationalTrustRootSetItemV2>,
        not_before_unix_ms: u64,
        not_after_unix_ms: u64,
        installer_signing_key: &SigningKey,
        installer_key_epoch: u64,
    ) -> Result<Self, DeploymentControlErrorV2> {
        Self::new_signed_for_test(
            3,
            product_family_digest,
            root_set_sequence,
            previous_signed_digest,
            members,
            not_before_unix_ms,
            not_after_unix_ms,
            installer_signing_key,
            installer_key_epoch,
        )
    }

    #[cfg(any(
        test,
        feature = "test-support",
        feature = "macos-development-authority"
    ))]
    #[allow(clippy::too_many_arguments)]
    fn new_signed_for_test(
        binding_tag: u16,
        product_family_digest: Digest32V2,
        root_set_sequence: u64,
        previous_signed_digest: Option<Digest32V2>,
        members: Vec<OperationalTrustRootSetItemV2>,
        not_before_unix_ms: u64,
        not_after_unix_ms: u64,
        installer_signing_key: &SigningKey,
        installer_key_epoch: u64,
    ) -> Result<Self, DeploymentControlErrorV2> {
        let member_set_digest = compute_member_set_digest(binding_tag, &members)?;
        let binding = OperationalTrustRootSetBindingV2::with_digest(binding_tag, member_set_digest)
            .ok_or(DeploymentControlErrorV2::InvalidOperationalTrustRootSet)?;
        let mut decoded = DecodedOperationalTrustRootSetV2 {
            product_family_digest,
            root_set_sequence,
            previous_signed_digest,
            binding,
            members,
            not_before_unix_ms,
            not_after_unix_ms,
            payload_digest: Digest32V2::new([0; 32]),
            installer_signature: ManifestDomainSignatureV2::sign_for_test(
                OPERATIONAL_ROOT_SIGNATURE_TAG_V2,
                OPERATIONAL_ROOT_SIGNATURE_DOMAIN_V2,
                Digest32V2::new([1; 32]),
                installer_signing_key,
                installer_key_epoch,
            ),
        };
        validate_payload(&decoded)?;
        decoded.payload_digest = hash_domain(
            OPERATIONAL_ROOT_PAYLOAD_DOMAIN_V2,
            &encode_payload(&decoded)?,
        );
        decoded.installer_signature = ManifestDomainSignatureV2::sign_for_test(
            OPERATIONAL_ROOT_SIGNATURE_TAG_V2,
            OPERATIONAL_ROOT_SIGNATURE_DOMAIN_V2,
            decoded.payload_digest,
            installer_signing_key,
            installer_key_epoch,
        );
        let bytes = encode_complete(&decoded)?;
        let verifier = InstallerOrMdmVerifierV2::new(
            derive_ed25519_key_id_v2(installer_signing_key.verifying_key().to_bytes()),
            installer_key_epoch,
            installer_signing_key.verifying_key().to_bytes(),
        )
        .map_err(|_| DeploymentControlErrorV2::InvalidOperationalTrustRootSet)?;
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
                    && self.product_family_digest == previous.product_family_digest
                    && self.binding.tag() == previous.binding.tag() =>
            {
                Ok(())
            }
            _ => Err(DeploymentControlErrorV2::InvalidOperationalTrustRootSet),
        }
    }

    pub fn matches_versioned_identity(
        &self,
        identity: &VersionedIdentityV2,
    ) -> Result<(), DeploymentControlErrorV2> {
        let expected_domain = match self.binding {
            OperationalTrustRootSetBindingV2::Deployment { .. } => {
                ClosedSecurityDomainV2::DeploymentTrustRootSet
            }
            OperationalTrustRootSetBindingV2::Activation { .. } => {
                ClosedSecurityDomainV2::ActivationTrustRootSet
            }
            OperationalTrustRootSetBindingV2::Declassification { .. } => {
                ClosedSecurityDomainV2::DeclassificationTrustRootSet
            }
        };
        if identity.domain() != expected_domain
            || identity.sequence() != self.root_set_sequence
            || identity.content_digest() != self.signed_digest
            || identity.signer_key_id() != self.installer_signature.signer_key_id()
            || identity.signer_key_epoch() != self.installer_signature.signer_key_epoch()
            || identity.not_before_unix_ms() != self.not_before_unix_ms
            || identity.not_after_unix_ms() != self.not_after_unix_ms
        {
            return Err(DeploymentControlErrorV2::InvalidOperationalTrustRootSet);
        }
        Ok(())
    }

    pub fn authorizes(
        &self,
        purpose: OperationalTrustRootPurposeV2,
        key_id: Ed25519KeyIdV2,
        key_epoch: u64,
        at_unix_ms: u64,
    ) -> bool {
        at_unix_ms >= self.not_before_unix_ms
            && at_unix_ms <= self.not_after_unix_ms
            && self.members.iter().any(|member| {
                member.purpose == purpose
                    && member.key_id == key_id
                    && member.key_epoch == key_epoch
                    && at_unix_ms >= member.not_before_unix_ms
                    && at_unix_ms <= member.not_after_unix_ms
            })
    }

    pub fn authorization_verifier(
        &self,
        purpose: OperationalTrustRootPurposeV2,
        key_id: Ed25519KeyIdV2,
        key_epoch: u64,
        at_unix_ms: u64,
    ) -> Result<DeploymentAuthorizationVerifierV2, DeploymentControlErrorV2> {
        if !matches!(
            purpose,
            OperationalTrustRootPurposeV2::DeploymentAuthorization
                | OperationalTrustRootPurposeV2::RollbackAuthorization
        ) {
            return Err(DeploymentControlErrorV2::InvalidOperationalTrustRootSet);
        }
        let member = self.member(purpose, key_id, key_epoch, at_unix_ms)?;
        DeploymentAuthorizationVerifierV2::new(key_id, key_epoch, member.public_key)
            .map_err(|_| DeploymentControlErrorV2::InvalidOperationalTrustRootSet)
    }

    pub fn activation_verifier(
        &self,
        installation_id: Digest32V2,
        key_id: Ed25519KeyIdV2,
        key_epoch: u64,
        at_unix_ms: u64,
    ) -> Result<DeploymentActivationVerifierV2, DeploymentControlErrorV2> {
        let member = self.member(
            OperationalTrustRootPurposeV2::InstallationActivation,
            key_id,
            key_epoch,
            at_unix_ms,
        )?;
        DeploymentActivationVerifierV2::new(installation_id, key_id, key_epoch, member.public_key)
            .map_err(|_| DeploymentControlErrorV2::InvalidOperationalTrustRootSet)
    }

    fn member(
        &self,
        purpose: OperationalTrustRootPurposeV2,
        key_id: Ed25519KeyIdV2,
        key_epoch: u64,
        at_unix_ms: u64,
    ) -> Result<&OperationalTrustRootSetItemV2, DeploymentControlErrorV2> {
        if !self.authorizes(purpose, key_id, key_epoch, at_unix_ms) {
            return Err(DeploymentControlErrorV2::InvalidOperationalTrustRootSet);
        }
        self.members
            .iter()
            .find(|member| {
                member.purpose == purpose
                    && member.key_id == key_id
                    && member.key_epoch == key_epoch
            })
            .ok_or(DeploymentControlErrorV2::InvalidOperationalTrustRootSet)
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub const fn product_family_digest(&self) -> Digest32V2 {
        self.product_family_digest
    }

    pub const fn root_set_sequence(&self) -> u64 {
        self.root_set_sequence
    }

    pub const fn previous_signed_digest(&self) -> Option<Digest32V2> {
        self.previous_signed_digest
    }

    pub const fn binding(&self) -> OperationalTrustRootSetBindingV2 {
        self.binding
    }

    pub fn members(&self) -> &[OperationalTrustRootSetItemV2] {
        &self.members
    }

    pub const fn not_before_unix_ms(&self) -> u64 {
        self.not_before_unix_ms
    }

    pub const fn not_after_unix_ms(&self) -> u64 {
        self.not_after_unix_ms
    }

    pub const fn payload_digest(&self) -> Digest32V2 {
        self.payload_digest
    }

    pub const fn signed_digest(&self) -> Digest32V2 {
        self.signed_digest
    }
}

#[derive(Debug, Clone)]
struct DecodedOperationalTrustRootSetV2 {
    product_family_digest: Digest32V2,
    root_set_sequence: u64,
    previous_signed_digest: Option<Digest32V2>,
    binding: OperationalTrustRootSetBindingV2,
    members: Vec<OperationalTrustRootSetItemV2>,
    not_before_unix_ms: u64,
    not_after_unix_ms: u64,
    payload_digest: Digest32V2,
    installer_signature: ManifestDomainSignatureV2,
}

fn validate_payload(
    value: &DecodedOperationalTrustRootSetV2,
) -> Result<(), DeploymentControlErrorV2> {
    let maximum = DeploymentHardLimitsV2::compiled().max_operational_trust_roots();
    if is_zero(value.product_family_digest.as_bytes())
        || value.root_set_sequence == 0
        || (value.root_set_sequence == 1) != value.previous_signed_digest.is_none()
        || value
            .previous_signed_digest
            .is_some_and(|digest| is_zero(digest.as_bytes()))
        || value.not_before_unix_ms >= value.not_after_unix_ms
        || value.members.is_empty()
        || value.members.len() as u64 > maximum
        || value
            .members
            .windows(2)
            .any(|pair| pair[0].sort_key() >= pair[1].sort_key())
        || value.members.iter().any(|member| {
            member.not_before_unix_ms < value.not_before_unix_ms
                || member.not_after_unix_ms > value.not_after_unix_ms
        })
    {
        return Err(DeploymentControlErrorV2::InvalidOperationalTrustRootSet);
    }
    for (index, member) in value.members.iter().enumerate() {
        if value.members[index + 1..]
            .iter()
            .any(|other| member.key_id == other.key_id)
        {
            return Err(DeploymentControlErrorV2::InvalidOperationalTrustRootSet);
        }
    }
    let permitted = match value.binding {
        OperationalTrustRootSetBindingV2::Deployment { .. } => {
            value.members.iter().all(|member| {
                matches!(
                    member.purpose,
                    OperationalTrustRootPurposeV2::DeploymentAuthorization
                        | OperationalTrustRootPurposeV2::RollbackAuthorization
                )
            }) && value.members.iter().any(|member| {
                member.purpose == OperationalTrustRootPurposeV2::DeploymentAuthorization
            }) && value.members.iter().any(|member| {
                member.purpose == OperationalTrustRootPurposeV2::RollbackAuthorization
            })
        }
        OperationalTrustRootSetBindingV2::Activation { .. } => value
            .members
            .iter()
            .all(|member| member.purpose == OperationalTrustRootPurposeV2::InstallationActivation),
        OperationalTrustRootSetBindingV2::Declassification { .. } => {
            value.members.iter().all(|member| {
                member.purpose == OperationalTrustRootPurposeV2::DeclassificationAuthority
            })
        }
    };
    if !permitted
        || compute_member_set_digest(value.binding.tag(), &value.members)?
            != value.binding.member_set_digest()
    {
        return Err(DeploymentControlErrorV2::InvalidOperationalTrustRootSet);
    }
    Ok(())
}

fn compute_member_set_digest(
    binding_tag: u16,
    members: &[OperationalTrustRootSetItemV2],
) -> Result<Digest32V2, DeploymentControlErrorV2> {
    let domain = match binding_tag {
        1 => DEPLOYMENT_ROOT_SET_DOMAIN_V2,
        2 => ACTIVATION_ROOT_SET_DOMAIN_V2,
        3 => DECLASSIFICATION_ROOT_SET_DOMAIN_V2,
        _ => return Err(DeploymentControlErrorV2::InvalidOperationalTrustRootSet),
    };
    let count = u64::try_from(members.len())
        .map_err(|_| DeploymentControlErrorV2::InvalidOperationalTrustRootSet)?;
    let canonical_items = encode_members(members)?;
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(count.to_be_bytes());
    hash.update(canonical_items);
    Ok(Digest32V2::new(hash.finalize().into()))
}

fn decode_complete(
    bytes: &[u8],
) -> Result<DecodedOperationalTrustRootSetV2, DeploymentControlErrorV2> {
    let mut decoder = minicbor::Decoder::new(bytes);
    map_invalid(expect_array(
        &mut decoder,
        OPERATIONAL_ROOT_COMPLETE_FIELDS_V2,
    ))?;
    let mut payload = map_invalid(decode_nested(&mut decoder, decode_payload))?;
    payload.payload_digest = map_invalid(decode_digest(&mut decoder))?;
    payload.installer_signature = map_invalid(decode_domain_signature(&mut decoder))?;
    map_invalid(require_eof(&decoder, bytes))?;
    Ok(payload)
}

fn decode_payload(
    bytes: &[u8],
) -> Result<DecodedOperationalTrustRootSetV2, DeploymentControlErrorV2> {
    let mut decoder = minicbor::Decoder::new(bytes);
    map_invalid(expect_array(
        &mut decoder,
        OPERATIONAL_ROOT_PAYLOAD_FIELDS_V2,
    ))?;
    if map_invalid(decode_u16(&mut decoder))? != OPERATIONAL_ROOT_SCHEMA_VERSION_V2 {
        return Err(DeploymentControlErrorV2::InvalidOperationalTrustRootSet);
    }
    let product_family_digest = map_invalid(decode_digest(&mut decoder))?;
    let root_set_sequence = map_invalid(decode_u64(&mut decoder))?;
    let previous_signed_digest = decode_optional_digest(&mut decoder)?;
    let binding = decode_binding(&mut decoder)?;
    let count = map_invalid(decode_bounded_array_length(
        &mut decoder,
        DeploymentHardLimitsV2::compiled().max_operational_trust_roots(),
    ))?;
    let mut members = Vec::with_capacity(count);
    for _ in 0..count {
        members.push(decode_member(&mut decoder)?);
    }
    let not_before_unix_ms = map_invalid(decode_u64(&mut decoder))?;
    let not_after_unix_ms = map_invalid(decode_u64(&mut decoder))?;
    map_invalid(require_eof(&decoder, bytes))?;
    Ok(DecodedOperationalTrustRootSetV2 {
        product_family_digest,
        root_set_sequence,
        previous_signed_digest,
        binding,
        members,
        not_before_unix_ms,
        not_after_unix_ms,
        payload_digest: Digest32V2::new([0; 32]),
        installer_signature: ManifestDomainSignatureV2::empty_for_decode(),
    })
}

fn encode_complete(
    value: &DecodedOperationalTrustRootSetV2,
) -> Result<Vec<u8>, DeploymentControlErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(OPERATIONAL_ROOT_COMPLETE_FIELDS_V2)
        .map_err(|_| DeploymentControlErrorV2::InvalidOperationalTrustRootSet)?;
    encoder
        .writer_mut()
        .extend_from_slice(&encode_payload(value)?);
    encoder
        .bytes(value.payload_digest.as_bytes())
        .map_err(|_| DeploymentControlErrorV2::InvalidOperationalTrustRootSet)?;
    map_invalid(encode_domain_signature(
        &mut encoder,
        value.installer_signature,
    ))?;
    Ok(encoder.into_writer())
}

fn encode_payload(
    value: &DecodedOperationalTrustRootSetV2,
) -> Result<Vec<u8>, DeploymentControlErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(OPERATIONAL_ROOT_PAYLOAD_FIELDS_V2)
        .and_then(|encoder| encoder.u16(OPERATIONAL_ROOT_SCHEMA_VERSION_V2))
        .and_then(|encoder| encoder.bytes(value.product_family_digest.as_bytes()))
        .and_then(|encoder| encoder.u64(value.root_set_sequence))
        .map_err(|_| DeploymentControlErrorV2::InvalidOperationalTrustRootSet)?;
    encode_optional_digest(&mut encoder, value.previous_signed_digest)?;
    encode_binding(&mut encoder, value.binding)?;
    encoder
        .array(value.members.len() as u64)
        .map_err(|_| DeploymentControlErrorV2::InvalidOperationalTrustRootSet)?;
    for member in &value.members {
        encode_member(&mut encoder, member)?;
    }
    encoder
        .u64(value.not_before_unix_ms)
        .and_then(|encoder| encoder.u64(value.not_after_unix_ms))
        .map_err(|_| DeploymentControlErrorV2::InvalidOperationalTrustRootSet)?;
    Ok(encoder.into_writer())
}

fn encode_members(
    members: &[OperationalTrustRootSetItemV2],
) -> Result<Vec<u8>, DeploymentControlErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(members.len() as u64)
        .map_err(|_| DeploymentControlErrorV2::InvalidOperationalTrustRootSet)?;
    for member in members {
        encode_member(&mut encoder, member)?;
    }
    Ok(encoder.into_writer())
}

fn decode_member(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<OperationalTrustRootSetItemV2, DeploymentControlErrorV2> {
    map_invalid(expect_array(decoder, OPERATIONAL_ROOT_ITEM_FIELDS_V2))?;
    let purpose = OperationalTrustRootPurposeV2::from_tag(map_invalid(decode_u16(decoder))?)
        .ok_or(DeploymentControlErrorV2::InvalidOperationalTrustRootSet)?;
    let encoded_key_id = map_invalid(decode_key_id(decoder))?;
    let key_epoch = map_invalid(decode_u64(decoder))?;
    let public_key: [u8; 32] = decoder
        .bytes()
        .map_err(|_| DeploymentControlErrorV2::InvalidOperationalTrustRootSet)?
        .try_into()
        .map_err(|_| DeploymentControlErrorV2::InvalidOperationalTrustRootSet)?;
    let value = OperationalTrustRootSetItemV2::new(
        purpose,
        public_key,
        key_epoch,
        map_invalid(decode_u64(decoder))?,
        map_invalid(decode_u64(decoder))?,
    )?;
    if value.key_id != encoded_key_id {
        return Err(DeploymentControlErrorV2::InvalidOperationalTrustRootSet);
    }
    Ok(value)
}

fn encode_member(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    value: &OperationalTrustRootSetItemV2,
) -> Result<(), DeploymentControlErrorV2> {
    encoder
        .array(OPERATIONAL_ROOT_ITEM_FIELDS_V2)
        .and_then(|encoder| encoder.u16(value.purpose.tag()))
        .and_then(|encoder| encoder.bytes(value.key_id.as_bytes()))
        .and_then(|encoder| encoder.u64(value.key_epoch))
        .and_then(|encoder| encoder.bytes(&value.public_key))
        .and_then(|encoder| encoder.u64(value.not_before_unix_ms))
        .and_then(|encoder| encoder.u64(value.not_after_unix_ms))
        .map(|_| ())
        .map_err(|_| DeploymentControlErrorV2::InvalidOperationalTrustRootSet)
}

fn decode_binding(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<OperationalTrustRootSetBindingV2, DeploymentControlErrorV2> {
    map_invalid(expect_array(decoder, OPERATIONAL_ROOT_BINDING_FIELDS_V2))?;
    OperationalTrustRootSetBindingV2::with_digest(
        map_invalid(decode_u16(decoder))?,
        map_invalid(decode_digest(decoder))?,
    )
    .ok_or(DeploymentControlErrorV2::InvalidOperationalTrustRootSet)
}

fn encode_binding(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    value: OperationalTrustRootSetBindingV2,
) -> Result<(), DeploymentControlErrorV2> {
    encoder
        .array(OPERATIONAL_ROOT_BINDING_FIELDS_V2)
        .and_then(|encoder| encoder.u16(value.tag()))
        .and_then(|encoder| encoder.bytes(value.member_set_digest().as_bytes()))
        .map(|_| ())
        .map_err(|_| DeploymentControlErrorV2::InvalidOperationalTrustRootSet)
}

fn decode_optional_digest(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<Option<Digest32V2>, DeploymentControlErrorV2> {
    let count = decoder
        .array()
        .map_err(|_| DeploymentControlErrorV2::InvalidOperationalTrustRootSet)?
        .ok_or(DeploymentControlErrorV2::InvalidOperationalTrustRootSet)?;
    match (count, map_invalid(decode_u16(decoder))?) {
        (1, 0) => Ok(None),
        (2, 1) => Ok(Some(map_invalid(decode_digest(decoder))?)),
        _ => Err(DeploymentControlErrorV2::InvalidOperationalTrustRootSet),
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
            .map_err(|_| DeploymentControlErrorV2::InvalidOperationalTrustRootSet),
        Some(digest) => encoder
            .array(2)
            .and_then(|encoder| encoder.u16(1))
            .and_then(|encoder| encoder.bytes(digest.as_bytes()))
            .map(|_| ())
            .map_err(|_| DeploymentControlErrorV2::InvalidOperationalTrustRootSet),
    }
}

fn map_invalid<T>(
    result: Result<T, DeploymentControlErrorV2>,
) -> Result<T, DeploymentControlErrorV2> {
    result.map_err(|_| DeploymentControlErrorV2::InvalidOperationalTrustRootSet)
}
