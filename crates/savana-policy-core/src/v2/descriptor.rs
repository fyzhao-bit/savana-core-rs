use std::cmp::Ordering;

use ed25519_dalek::{Signature, VerifyingKey};
use savana_kernel_protocol::v2::{
    decode_business_profile_v2, encode_business_profile_v2, ActionCodecProfileV2,
    ActionTemplateIdV2, BusinessProfileV2, Digest32V2, DisplayProjectionIdV2, Ed25519KeyIdV2,
    ExecutorIdentityV2, ImplementationIdV2, ProjectionIdV2, RoleIdV2, ToolClassIdV2, UnixMillisV2,
    VersionV2,
};
use sha2::{Digest as _, Sha256};

use super::{AttemptKindV2, EffectSetV2, G4Error, IdentifierV2};

const TOOL_DESCRIPTOR_SCHEMA_VERSION: u16 = 2;
const PROFILE_DESCRIPTOR_SCHEMA_VERSION: u16 = 3;
const MAX_DESCRIPTOR_BYTES: usize = 8 * 1024 * 1024;
const MAX_ALLOWED_ROLES: usize = 64;
const MAX_INTERNAL_VALIDATORS: usize = 32;
pub(super) const MAX_ACTIVE_TOOL_DESCRIPTORS: usize = 4_096;
const DESCRIPTOR_DIGEST_DOMAIN: &[u8] = b"SAVANA_TOOL_DESCRIPTOR_V2\0";
const DESCRIPTOR_SIGNATURE_DOMAIN: &[u8] = b"SAVANA_TOOL_DESCRIPTOR_SIGNATURE_V2\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExecutorIdempotencyContractV2 {
    ConnectorIdempotentByExecutionNonce,
    ConnectorNonIdempotentSingleAttempt,
}

impl ExecutorIdempotencyContractV2 {
    pub const fn tag(self) -> u16 {
        match self {
            Self::ConnectorIdempotentByExecutionNonce => 1,
            Self::ConnectorNonIdempotentSingleAttempt => 2,
        }
    }
}

impl<C> minicbor::Encode<C> for ExecutorIdempotencyContractV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        _context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.array(1)?.u16(self.tag())?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BoundedConnectorRetryPolicyV2 {
    maximum_attempts: u16,
    maximum_elapsed_ns: u64,
}

impl BoundedConnectorRetryPolicyV2 {
    pub const fn new(
        contract: ExecutorIdempotencyContractV2,
        maximum_attempts: u16,
        maximum_elapsed_ns: u64,
    ) -> Result<Self, G4Error> {
        let valid = match contract {
            ExecutorIdempotencyContractV2::ConnectorNonIdempotentSingleAttempt => {
                maximum_attempts == 1 && maximum_elapsed_ns == 0
            }
            ExecutorIdempotencyContractV2::ConnectorIdempotentByExecutionNonce => {
                maximum_attempts >= 1
                    && maximum_attempts <= 8
                    && maximum_elapsed_ns >= 1
                    && maximum_elapsed_ns <= 30_000_000_000
            }
        };
        if !valid {
            return Err(G4Error::InvalidRetryPolicy);
        }
        Ok(Self {
            maximum_attempts,
            maximum_elapsed_ns,
        })
    }

    pub const fn maximum_attempts(self) -> u16 {
        self.maximum_attempts
    }

    pub const fn maximum_elapsed_ns(self) -> u64 {
        self.maximum_elapsed_ns
    }
}

impl<C> minicbor::Encode<C> for BoundedConnectorRetryPolicyV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        _context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder
            .array(2)?
            .u16(self.maximum_attempts)?
            .u64(self.maximum_elapsed_ns)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InternalValidatorDeclarationV2 {
    implementation_id: ImplementationIdV2,
    semantic_version: VersionV2,
    build_manifest_digest: Digest32V2,
}

impl InternalValidatorDeclarationV2 {
    pub const fn new(
        implementation_id: ImplementationIdV2,
        semantic_version: VersionV2,
        build_manifest_digest: Digest32V2,
    ) -> Self {
        Self {
            implementation_id,
            semantic_version,
            build_manifest_digest,
        }
    }

    pub const fn implementation_id(self) -> ImplementationIdV2 {
        self.implementation_id
    }

    pub const fn semantic_version(self) -> VersionV2 {
        self.semantic_version
    }

    pub const fn build_manifest_digest(self) -> Digest32V2 {
        self.build_manifest_digest
    }
}

impl<C> minicbor::Encode<C> for InternalValidatorDeclarationV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.array(3)?;
        self.implementation_id.encode(encoder, context)?;
        self.semantic_version.encode(encoder, context)?;
        self.build_manifest_digest.encode(encoder, context)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsignedToolDescriptorV2 {
    schema_version: u16,
    registry_version: VersionV2,
    provider_identity_digest: Digest32V2,
    pub(crate) provider_tool_id: IdentifierV2,
    action_template: ActionTemplateIdV2,
    tool_class: ToolClassIdV2,
    argument_schema_digest: Digest32V2,
    result_schema_digest: Digest32V2,
    allowed_roles: Vec<RoleIdV2>,
    effects: EffectSetV2,
    attempt_kind: AttemptKindV2,
    connector_retry_policy: BoundedConnectorRetryPolicyV2,
    internal_validators: Vec<InternalValidatorDeclarationV2>,
    executor_identity: ExecutorIdentityV2,
    destination_projection: ProjectionIdV2,
    destination_projection_digest: Digest32V2,
    display_projection: DisplayProjectionIdV2,
    display_projection_digest: Digest32V2,
    idempotency_contract: ExecutorIdempotencyContractV2,
    not_before: UnixMillisV2,
    expires_at: UnixMillisV2,
    business_profile: Option<BusinessProfileV2>,
}

impl UnsignedToolDescriptorV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn from_verified_manifest(
        schema_version: u16,
        registry_version: VersionV2,
        provider_identity_digest: Digest32V2,
        provider_tool_id: IdentifierV2,
        action_template: ActionTemplateIdV2,
        tool_class: ToolClassIdV2,
        argument_schema_digest: Digest32V2,
        result_schema_digest: Digest32V2,
        allowed_roles: Vec<RoleIdV2>,
        effects: EffectSetV2,
        attempt_kind: AttemptKindV2,
        connector_retry_policy: BoundedConnectorRetryPolicyV2,
        internal_validators: Vec<InternalValidatorDeclarationV2>,
        executor_identity: ExecutorIdentityV2,
        destination_projection: ProjectionIdV2,
        destination_projection_digest: Digest32V2,
        display_projection: DisplayProjectionIdV2,
        display_projection_digest: Digest32V2,
        idempotency_contract: ExecutorIdempotencyContractV2,
        not_before: UnixMillisV2,
        expires_at: UnixMillisV2,
    ) -> Result<Self, G4Error> {
        let descriptor = Self {
            schema_version,
            registry_version,
            provider_identity_digest,
            provider_tool_id,
            action_template,
            tool_class,
            argument_schema_digest,
            result_schema_digest,
            allowed_roles,
            effects,
            attempt_kind,
            connector_retry_policy,
            internal_validators,
            executor_identity,
            destination_projection,
            destination_projection_digest,
            display_projection,
            display_projection_digest,
            idempotency_contract,
            not_before,
            expires_at,
            business_profile: None,
        };
        descriptor.validate()?;
        Ok(descriptor)
    }

    #[cfg(test)]
    pub(super) fn new_for_test(
        registry_version: VersionV2,
        allowed_roles: Vec<RoleIdV2>,
        internal_validators: Vec<InternalValidatorDeclarationV2>,
        destination_projection: ProjectionIdV2,
        destination_projection_digest: Digest32V2,
    ) -> Result<Self, G4Error> {
        Self::from_verified_manifest(
            TOOL_DESCRIPTOR_SCHEMA_VERSION,
            registry_version,
            Digest32V2::new([1; 32]),
            IdentifierV2::new("mail.send").map_err(|_| G4Error::InvalidDescriptor)?,
            ActionTemplateIdV2::new(1),
            ToolClassIdV2::new(2),
            Digest32V2::new([2; 32]),
            Digest32V2::new([3; 32]),
            allowed_roles,
            EffectSetV2::SEND,
            AttemptKindV2::ToolWrite,
            BoundedConnectorRetryPolicyV2::new(
                ExecutorIdempotencyContractV2::ConnectorIdempotentByExecutionNonce,
                3,
                1_000_000_000,
            )?,
            internal_validators,
            ExecutorIdentityV2::new([4; 32]),
            destination_projection,
            destination_projection_digest,
            DisplayProjectionIdV2::new(4),
            Digest32V2::new([8; 32]),
            ExecutorIdempotencyContractV2::ConnectorIdempotentByExecutionNonce,
            UnixMillisV2::new(100),
            UnixMillisV2::new(900),
        )
    }

    fn validate(&self) -> Result<(), G4Error> {
        if !matches!(
            (self.schema_version, self.business_profile.is_some()),
            (TOOL_DESCRIPTOR_SCHEMA_VERSION, false) | (PROFILE_DESCRIPTOR_SCHEMA_VERSION, true)
        ) || is_zero(self.provider_identity_digest.as_bytes())
            || is_zero(self.argument_schema_digest.as_bytes())
            || is_zero(self.result_schema_digest.as_bytes())
            || is_zero(self.executor_identity.as_bytes())
            || self.not_before.get() >= self.expires_at.get()
        {
            return Err(G4Error::InvalidDescriptor);
        }
        if self.allowed_roles.len() > MAX_ALLOWED_ROLES
            || self.internal_validators.len() > MAX_INTERNAL_VALIDATORS
        {
            return Err(G4Error::DescriptorLimitExceeded);
        }
        if self.allowed_roles.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(G4Error::NonCanonicalOrder);
        }
        if self
            .internal_validators
            .windows(2)
            .any(|pair| pair[0].implementation_id == pair[1].implementation_id)
        {
            return Err(G4Error::DuplicateValidatorImplementation);
        }
        if self
            .internal_validators
            .windows(2)
            .any(|pair| validator_cmp(&pair[0], &pair[1]) != Ordering::Less)
        {
            return Err(G4Error::NonCanonicalOrder);
        }
        if self.destination_projection.get() == 0
            || self.display_projection.get() == 0
            || is_zero(self.destination_projection_digest.as_bytes())
            || is_zero(self.display_projection_digest.as_bytes())
        {
            return Err(G4Error::InvalidProjectionBinding);
        }
        BoundedConnectorRetryPolicyV2::new(
            self.idempotency_contract,
            self.connector_retry_policy.maximum_attempts,
            self.connector_retry_policy.maximum_elapsed_ns,
        )?;
        if let Some(profile) = &self.business_profile {
            if !self
                .effects
                .contains(super::task_effect_set_v2(profile.effect()))
                || (profile.codec() == ActionCodecProfileV2::McpToolsCallJsonV1
                    && profile.operation() != self.provider_tool_id.as_str())
            {
                return Err(G4Error::InvalidDescriptor);
            }
        }
        Ok(())
    }

    /// Explicit schema-3 manifest material. This does not sign/activate a tool;
    /// the existing expected-publisher verification must authenticate this entire
    /// descriptor, including the reviewed mapping, before strict use.
    pub fn with_business_profile(mut self, profile: BusinessProfileV2) -> Result<Self, G4Error> {
        self.schema_version = PROFILE_DESCRIPTOR_SCHEMA_VERSION;
        self.business_profile = Some(profile);
        self.validate()?;
        Ok(self)
    }

    pub fn business_profile(&self) -> Option<&BusinessProfileV2> {
        self.business_profile.as_ref()
    }

    pub fn require_business_profile(&self) -> Result<&BusinessProfileV2, G4Error> {
        self.business_profile
            .as_ref()
            .ok_or(G4Error::InvalidDescriptor)
    }

    pub const fn registry_version(&self) -> VersionV2 {
        self.registry_version
    }

    pub const fn provider_tool_id(&self) -> &IdentifierV2 {
        &self.provider_tool_id
    }

    pub const fn action_template(&self) -> ActionTemplateIdV2 {
        self.action_template
    }

    pub const fn tool_class(&self) -> ToolClassIdV2 {
        self.tool_class
    }

    pub const fn effects(&self) -> EffectSetV2 {
        self.effects
    }

    pub const fn attempt_kind(&self) -> AttemptKindV2 {
        self.attempt_kind
    }

    pub const fn executor_identity(&self) -> ExecutorIdentityV2 {
        self.executor_identity
    }

    pub fn internal_validators(&self) -> &[InternalValidatorDeclarationV2] {
        &self.internal_validators
    }

    pub const fn destination_projection(&self) -> ProjectionIdV2 {
        self.destination_projection
    }

    pub const fn destination_projection_digest(&self) -> Digest32V2 {
        self.destination_projection_digest
    }

    pub const fn display_projection(&self) -> DisplayProjectionIdV2 {
        self.display_projection
    }

    pub const fn display_projection_digest(&self) -> Digest32V2 {
        self.display_projection_digest
    }

    pub const fn connector_retry_policy(&self) -> BoundedConnectorRetryPolicyV2 {
        self.connector_retry_policy
    }

    pub const fn idempotency_contract(&self) -> ExecutorIdempotencyContractV2 {
        self.idempotency_contract
    }

    pub const fn not_before(&self) -> UnixMillisV2 {
        self.not_before
    }

    pub const fn expires_at(&self) -> UnixMillisV2 {
        self.expires_at
    }

    fn allows_role(&self, role: RoleIdV2) -> bool {
        self.allowed_roles.binary_search(&role).is_ok()
    }
}

impl<C> minicbor::Encode<C> for UnsignedToolDescriptorV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder
            .array(if self.business_profile.is_some() {
                22
            } else {
                21
            })?
            .u16(self.schema_version)?;
        self.registry_version.encode(encoder, context)?;
        self.provider_identity_digest.encode(encoder, context)?;
        self.provider_tool_id.encode(encoder, context)?;
        self.action_template.encode(encoder, context)?;
        self.tool_class.encode(encoder, context)?;
        self.argument_schema_digest.encode(encoder, context)?;
        self.result_schema_digest.encode(encoder, context)?;
        encoder.array(self.allowed_roles.len() as u64)?;
        for role in &self.allowed_roles {
            role.encode(encoder, context)?;
        }
        self.effects.encode(encoder, context)?;
        self.attempt_kind.encode(encoder, context)?;
        self.connector_retry_policy.encode(encoder, context)?;
        encoder.array(self.internal_validators.len() as u64)?;
        for validator in &self.internal_validators {
            validator.encode(encoder, context)?;
        }
        self.executor_identity.encode(encoder, context)?;
        self.destination_projection.encode(encoder, context)?;
        self.destination_projection_digest
            .encode(encoder, context)?;
        self.display_projection.encode(encoder, context)?;
        self.display_projection_digest.encode(encoder, context)?;
        self.idempotency_contract.encode(encoder, context)?;
        self.not_before.encode(encoder, context)?;
        self.expires_at.encode(encoder, context)?;
        if let Some(profile) = &self.business_profile {
            let bytes = encode_business_profile_v2(profile)
                .map_err(|_| minicbor::encode::Error::message("invalid business profile"))?;
            encoder.bytes(&bytes)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedToolDescriptorV2 {
    unsigned_descriptor_payload: Vec<u8>,
    publisher_key_id: Ed25519KeyIdV2,
    signature: [u8; 64],
}

impl SignedToolDescriptorV2 {
    #[cfg(test)]
    pub(super) const fn new_for_test(
        unsigned_descriptor_payload: Vec<u8>,
        publisher_key_id: Ed25519KeyIdV2,
        signature: [u8; 64],
    ) -> Self {
        Self {
            unsigned_descriptor_payload,
            publisher_key_id,
            signature,
        }
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, G4Error> {
        if bytes.len() > MAX_DESCRIPTOR_BYTES {
            return Err(G4Error::DescriptorLimitExceeded);
        }
        let mut decoder = minicbor::Decoder::new(bytes);
        require_array(&mut decoder, 3)?;
        let payload = decoder
            .bytes()
            .map_err(|_| G4Error::NonCanonicalDescriptor)?;
        if payload.len() > MAX_DESCRIPTOR_BYTES {
            return Err(G4Error::DescriptorLimitExceeded);
        }
        let mut unsigned_descriptor_payload = Vec::new();
        unsigned_descriptor_payload
            .try_reserve_exact(payload.len())
            .map_err(|_| G4Error::AllocationFailure)?;
        unsigned_descriptor_payload.extend_from_slice(payload);
        let publisher_key_id = Ed25519KeyIdV2::new(decode_fixed::<32>(&mut decoder)?);
        let signature = decode_fixed::<64>(&mut decoder)?;
        if decoder.position() != bytes.len() {
            return Err(G4Error::NonCanonicalDescriptor);
        }
        decode_unsigned_descriptor(&unsigned_descriptor_payload)?;
        let signed = Self {
            unsigned_descriptor_payload,
            publisher_key_id,
            signature,
        };
        let canonical = minicbor::to_vec(&signed).map_err(|_| G4Error::NonCanonicalDescriptor)?;
        if canonical != bytes {
            return Err(G4Error::NonCanonicalDescriptor);
        }
        Ok(signed)
    }

    pub fn verify(
        &self,
        publisher: &VerifiedRegistryPublisherV2,
        expected_registry_version: VersionV2,
        now: UnixMillisV2,
    ) -> Result<VerifiedToolDescriptorV2, G4Error> {
        if self.publisher_key_id != publisher.key_id {
            return Err(G4Error::InvalidDescriptorSignature);
        }
        let unsigned = decode_unsigned_descriptor(&self.unsigned_descriptor_payload)?;
        if unsigned.registry_version != expected_registry_version {
            return Err(G4Error::RegistryVersionMismatch);
        }
        if now.get() < publisher.not_before.get()
            || now.get() >= publisher.expires_at.get()
            || unsigned.not_before.get() < publisher.not_before.get()
            || unsigned.expires_at.get() > publisher.expires_at.get()
            || now.get() < unsigned.not_before.get()
            || now.get() >= unsigned.expires_at.get()
        {
            return Err(G4Error::DescriptorNotActive);
        }
        let digest = descriptor_digest_from_payload(&self.unsigned_descriptor_payload);
        let mut signed_bytes = Vec::new();
        signed_bytes
            .try_reserve_exact(DESCRIPTOR_SIGNATURE_DOMAIN.len() + 32)
            .map_err(|_| G4Error::AllocationFailure)?;
        signed_bytes.extend_from_slice(DESCRIPTOR_SIGNATURE_DOMAIN);
        signed_bytes.extend_from_slice(digest.as_bytes());
        let signature = Signature::from_bytes(&self.signature);
        publisher
            .verifying_key
            .verify_strict(&signed_bytes, &signature)
            .map_err(|_| G4Error::InvalidDescriptorSignature)?;
        Ok(VerifiedToolDescriptorV2 {
            unsigned,
            descriptor_digest: digest,
            publisher_key_id: self.publisher_key_id,
        })
    }
}

impl<C> minicbor::Encode<C> for SignedToolDescriptorV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.array(3)?.bytes(&self.unsigned_descriptor_payload)?;
        self.publisher_key_id.encode(encoder, context)?;
        encoder.bytes(&self.signature)?;
        Ok(())
    }
}

pub struct VerifiedRegistryPublisherV2 {
    key_id: Ed25519KeyIdV2,
    verifying_key: VerifyingKey,
    not_before: UnixMillisV2,
    expires_at: UnixMillisV2,
}

impl VerifiedRegistryPublisherV2 {
    /// Builds the registry publisher authority from fields already authenticated
    /// by the active state manifest verifier.
    pub fn from_verified_manifest(
        key_id: Ed25519KeyIdV2,
        public_key: [u8; 32],
        not_before: UnixMillisV2,
        expires_at: UnixMillisV2,
    ) -> Result<Self, G4Error> {
        let verifying_key =
            VerifyingKey::from_bytes(&public_key).map_err(|_| G4Error::InvalidRegistryPublisher)?;
        if verifying_key.is_weak()
            || is_zero(key_id.as_bytes())
            || not_before.get() >= expires_at.get()
        {
            return Err(G4Error::InvalidRegistryPublisher);
        }
        Ok(Self {
            key_id,
            verifying_key,
            not_before,
            expires_at,
        })
    }

    #[cfg(test)]
    pub(super) fn new_for_test(
        key_id: Ed25519KeyIdV2,
        public_key: [u8; 32],
        not_before: UnixMillisV2,
        expires_at: UnixMillisV2,
    ) -> Result<Self, G4Error> {
        Self::from_verified_manifest(key_id, public_key, not_before, expires_at)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedToolDescriptorV2 {
    unsigned: UnsignedToolDescriptorV2,
    descriptor_digest: Digest32V2,
    publisher_key_id: Ed25519KeyIdV2,
}

impl VerifiedToolDescriptorV2 {
    pub const fn unsigned(&self) -> &UnsignedToolDescriptorV2 {
        &self.unsigned
    }

    pub const fn descriptor_digest(&self) -> Digest32V2 {
        self.descriptor_digest
    }

    pub const fn publisher_key_id(&self) -> Ed25519KeyIdV2 {
        self.publisher_key_id
    }
}

pub fn descriptor_digest_v2(unsigned: &UnsignedToolDescriptorV2) -> Result<Digest32V2, G4Error> {
    let payload = minicbor::to_vec(unsigned).map_err(|_| G4Error::NonCanonicalDescriptor)?;
    if payload.len() > MAX_DESCRIPTOR_BYTES {
        return Err(G4Error::DescriptorLimitExceeded);
    }
    Ok(descriptor_digest_from_payload(&payload))
}

#[derive(Debug, Clone)]
pub struct VerifiedToolRegistryV2 {
    registry_version: VersionV2,
    descriptors: Vec<VerifiedToolDescriptorV2>,
}

impl VerifiedToolRegistryV2 {
    pub fn from_verified_descriptors(
        registry_version: VersionV2,
        descriptors: Vec<VerifiedToolDescriptorV2>,
    ) -> Result<Self, G4Error> {
        if descriptors.len() > MAX_ACTIVE_TOOL_DESCRIPTORS {
            return Err(G4Error::DescriptorLimitExceeded);
        }
        if descriptors
            .iter()
            .any(|descriptor| descriptor.unsigned.registry_version != registry_version)
        {
            return Err(G4Error::RegistryVersionMismatch);
        }
        for (index, descriptor) in descriptors.iter().enumerate() {
            if descriptors[..index]
                .iter()
                .any(|candidate| candidate.descriptor_digest == descriptor.descriptor_digest)
            {
                return Err(G4Error::NonCanonicalOrder);
            }
        }
        Ok(Self {
            registry_version,
            descriptors,
        })
    }

    #[cfg(test)]
    pub(super) fn new_for_test(
        registry_version: VersionV2,
        descriptors: Vec<VerifiedToolDescriptorV2>,
    ) -> Result<Self, G4Error> {
        Self::from_verified_descriptors(registry_version, descriptors)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedPolicyToolActivationV2 {
    descriptor_digest: Digest32V2,
    registry_ordinal: u32,
    policy_activation_digest: Digest32V2,
}

impl VerifiedPolicyToolActivationV2 {
    pub const fn from_verified_policy(
        descriptor_digest: Digest32V2,
        registry_ordinal: u32,
        policy_activation_digest: Digest32V2,
    ) -> Self {
        Self {
            descriptor_digest,
            registry_ordinal,
            policy_activation_digest,
        }
    }

    #[cfg(test)]
    pub(super) const fn new_for_test(
        descriptor_digest: Digest32V2,
        registry_ordinal: u32,
        policy_activation_digest: Digest32V2,
    ) -> Self {
        Self::from_verified_policy(
            descriptor_digest,
            registry_ordinal,
            policy_activation_digest,
        )
    }
}

#[derive(Debug, Clone)]
pub struct VerifiedPolicyToolSetV2(Vec<VerifiedPolicyToolActivationV2>);

impl VerifiedPolicyToolSetV2 {
    pub fn from_verified_policy(
        activations: Vec<VerifiedPolicyToolActivationV2>,
    ) -> Result<Self, G4Error> {
        if activations.len() > MAX_ACTIVE_TOOL_DESCRIPTORS {
            return Err(G4Error::DescriptorLimitExceeded);
        }
        if activations
            .windows(2)
            .any(|pair| policy_activation_cmp(&pair[0], &pair[1]) != Ordering::Less)
        {
            return Err(G4Error::NonCanonicalOrder);
        }
        if activations.iter().any(|entry| {
            is_zero(entry.descriptor_digest.as_bytes())
                || is_zero(entry.policy_activation_digest.as_bytes())
        }) {
            return Err(G4Error::InvalidDescriptor);
        }
        Ok(Self(activations))
    }

    #[cfg(test)]
    pub(super) fn new_for_test(
        activations: Vec<VerifiedPolicyToolActivationV2>,
    ) -> Result<Self, G4Error> {
        Self::from_verified_policy(activations)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedManifestToolConstraintV2 {
    descriptor_digest: Digest32V2,
    maximum_attempts: u16,
    maximum_elapsed_ns: u64,
    internal_validators: Vec<InternalValidatorDeclarationV2>,
}

impl VerifiedManifestToolConstraintV2 {
    pub fn from_manifest(
        descriptor_digest: Digest32V2,
        maximum_attempts: u16,
        maximum_elapsed_ns: u64,
        internal_validators: Vec<InternalValidatorDeclarationV2>,
    ) -> Result<Self, G4Error> {
        if is_zero(descriptor_digest.as_bytes())
            || maximum_attempts == 0
            || maximum_attempts > 8
            || maximum_elapsed_ns > 30_000_000_000
            || internal_validators.len() > MAX_INTERNAL_VALIDATORS
        {
            return Err(G4Error::InvalidDescriptor);
        }
        if internal_validators
            .windows(2)
            .any(|pair| pair[0].implementation_id == pair[1].implementation_id)
        {
            return Err(G4Error::DuplicateValidatorImplementation);
        }
        if internal_validators
            .windows(2)
            .any(|pair| validator_cmp(&pair[0], &pair[1]) != Ordering::Less)
        {
            return Err(G4Error::NonCanonicalOrder);
        }
        Ok(Self {
            descriptor_digest,
            maximum_attempts,
            maximum_elapsed_ns,
            internal_validators,
        })
    }

    #[cfg(test)]
    pub(super) fn new_for_test(
        descriptor_digest: Digest32V2,
        maximum_attempts: u16,
        maximum_elapsed_ns: u64,
        internal_validators: Vec<InternalValidatorDeclarationV2>,
    ) -> Self {
        Self::from_manifest(
            descriptor_digest,
            maximum_attempts,
            maximum_elapsed_ns,
            internal_validators,
        )
        .unwrap()
    }
}

#[derive(Debug, Clone)]
pub struct VerifiedManifestToolConstraintSetV2(Vec<VerifiedManifestToolConstraintV2>);

impl VerifiedManifestToolConstraintSetV2 {
    pub fn from_manifest(
        constraints: Vec<VerifiedManifestToolConstraintV2>,
    ) -> Result<Self, G4Error> {
        if constraints.len() > MAX_ACTIVE_TOOL_DESCRIPTORS {
            return Err(G4Error::DescriptorLimitExceeded);
        }
        if constraints.windows(2).any(|pair| {
            pair[0].descriptor_digest.as_bytes() >= pair[1].descriptor_digest.as_bytes()
        }) {
            return Err(G4Error::NonCanonicalOrder);
        }
        Ok(Self(constraints))
    }

    #[cfg(test)]
    pub(super) fn new_for_test(
        constraints: Vec<VerifiedManifestToolConstraintV2>,
    ) -> Result<Self, G4Error> {
        Self::from_manifest(constraints)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveToolRecordV2 {
    descriptor: VerifiedToolDescriptorV2,
    registry_ordinal: u32,
    policy_activation_digest: Digest32V2,
    effective_retry_policy: BoundedConnectorRetryPolicyV2,
}

impl ActiveToolRecordV2 {
    pub const fn descriptor(&self) -> &VerifiedToolDescriptorV2 {
        &self.descriptor
    }

    pub const fn registry_ordinal(&self) -> u32 {
        self.registry_ordinal
    }

    pub const fn policy_activation_digest(&self) -> Digest32V2 {
        self.policy_activation_digest
    }

    pub const fn effective_retry_policy(&self) -> BoundedConnectorRetryPolicyV2 {
        self.effective_retry_policy
    }
}

#[derive(Debug, Clone)]
pub struct ActiveToolRegistryV2(Vec<ActiveToolRecordV2>);

impl ActiveToolRegistryV2 {
    pub fn intersect(
        registry: &VerifiedToolRegistryV2,
        policy: &VerifiedPolicyToolSetV2,
        manifest_constraints: &VerifiedManifestToolConstraintSetV2,
    ) -> Result<Self, G4Error> {
        let mut active = Vec::new();
        active
            .try_reserve_exact(policy.0.len().min(registry.descriptors.len()))
            .map_err(|_| G4Error::AllocationFailure)?;
        for activation in &policy.0 {
            let Some(descriptor) = registry
                .descriptors
                .get(activation.registry_ordinal as usize)
            else {
                continue;
            };
            if descriptor.descriptor_digest != activation.descriptor_digest
                || descriptor.unsigned.registry_version != registry.registry_version
            {
                continue;
            }
            let Some(constraints) = manifest_constraints
                .0
                .binary_search_by(|candidate| {
                    candidate
                        .descriptor_digest
                        .as_bytes()
                        .cmp(descriptor.descriptor_digest.as_bytes())
                })
                .ok()
                .map(|index| &manifest_constraints.0[index])
            else {
                continue;
            };
            if constraints.internal_validators != descriptor.unsigned.internal_validators
                || constraints.maximum_attempts
                    > descriptor.unsigned.connector_retry_policy.maximum_attempts
                || constraints.maximum_elapsed_ns
                    > descriptor
                        .unsigned
                        .connector_retry_policy
                        .maximum_elapsed_ns
            {
                continue;
            }
            let effective_retry_policy = BoundedConnectorRetryPolicyV2::new(
                descriptor.unsigned.idempotency_contract,
                constraints.maximum_attempts,
                constraints.maximum_elapsed_ns,
            )?;
            active.push(ActiveToolRecordV2 {
                descriptor: descriptor.clone(),
                registry_ordinal: activation.registry_ordinal,
                policy_activation_digest: activation.policy_activation_digest,
                effective_retry_policy,
            });
        }
        Ok(Self(active))
    }

    pub fn resolve(
        &self,
        descriptor_digest: Digest32V2,
        role: RoleIdV2,
        now: UnixMillisV2,
    ) -> Option<&ActiveToolRecordV2> {
        self.0.iter().find(|record| {
            record.descriptor.descriptor_digest == descriptor_digest
                && record.descriptor.unsigned.allows_role(role)
                && now.get() >= record.descriptor.unsigned.not_before.get()
                && now.get() < record.descriptor.unsigned.expires_at.get()
        })
    }

    pub fn resolve_class(
        &self,
        tool_class: ToolClassIdV2,
        role: RoleIdV2,
        now: UnixMillisV2,
    ) -> Option<&ActiveToolRecordV2> {
        self.0.iter().find(|record| {
            record.descriptor.unsigned.tool_class() == tool_class
                && record.descriptor.unsigned.allows_role(role)
                && now.get() >= record.descriptor.unsigned.not_before.get()
                && now.get() < record.descriptor.unsigned.expires_at.get()
        })
    }

    pub fn records(&self) -> &[ActiveToolRecordV2] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

pub(crate) fn decode_unsigned_descriptor(
    bytes: &[u8],
) -> Result<UnsignedToolDescriptorV2, G4Error> {
    if bytes.len() > MAX_DESCRIPTOR_BYTES {
        return Err(G4Error::DescriptorLimitExceeded);
    }
    let mut decoder = minicbor::Decoder::new(bytes);
    let field_count = decoder
        .array()
        .map_err(|_| G4Error::NonCanonicalDescriptor)?;
    let schema_version = decoder.u16().map_err(|_| G4Error::NonCanonicalDescriptor)?;
    if !matches!(
        (field_count, schema_version),
        (Some(21), TOOL_DESCRIPTOR_SCHEMA_VERSION) | (Some(22), PROFILE_DESCRIPTOR_SCHEMA_VERSION)
    ) {
        return Err(G4Error::NonCanonicalDescriptor);
    }
    let registry_version = decode_version(&mut decoder)?;
    let provider_identity_digest = Digest32V2::new(decode_fixed::<32>(&mut decoder)?);
    let provider_tool_id =
        IdentifierV2::new(decoder.str().map_err(|_| G4Error::NonCanonicalDescriptor)?)
            .map_err(|_| G4Error::InvalidDescriptor)?;
    let action_template =
        ActionTemplateIdV2::new(decoder.u32().map_err(|_| G4Error::NonCanonicalDescriptor)?);
    let tool_class =
        ToolClassIdV2::new(decoder.u32().map_err(|_| G4Error::NonCanonicalDescriptor)?);
    let argument_schema_digest = Digest32V2::new(decode_fixed::<32>(&mut decoder)?);
    let result_schema_digest = Digest32V2::new(decode_fixed::<32>(&mut decoder)?);
    let role_count = bounded_array_len(&mut decoder, MAX_ALLOWED_ROLES)?;
    let mut allowed_roles = Vec::new();
    allowed_roles
        .try_reserve_exact(role_count)
        .map_err(|_| G4Error::AllocationFailure)?;
    for _ in 0..role_count {
        allowed_roles.push(RoleIdV2::new(
            decoder.u32().map_err(|_| G4Error::NonCanonicalDescriptor)?,
        ));
    }
    let effects =
        EffectSetV2::from_bits(decoder.u16().map_err(|_| G4Error::NonCanonicalDescriptor)?)
            .ok_or(G4Error::InvalidDescriptor)?;
    let attempt_kind = decode_attempt_kind(&mut decoder)?;
    let retry = decode_retry_policy(&mut decoder)?;
    let validator_count = bounded_array_len(&mut decoder, MAX_INTERNAL_VALIDATORS)?;
    let mut internal_validators = Vec::new();
    internal_validators
        .try_reserve_exact(validator_count)
        .map_err(|_| G4Error::AllocationFailure)?;
    for _ in 0..validator_count {
        require_array(&mut decoder, 3)?;
        internal_validators.push(InternalValidatorDeclarationV2::new(
            ImplementationIdV2::new(decoder.u32().map_err(|_| G4Error::NonCanonicalDescriptor)?),
            decode_version(&mut decoder)?,
            Digest32V2::new(decode_fixed::<32>(&mut decoder)?),
        ));
    }
    let executor_identity = ExecutorIdentityV2::new(decode_fixed::<32>(&mut decoder)?);
    let destination_projection =
        ProjectionIdV2::new(decoder.u32().map_err(|_| G4Error::NonCanonicalDescriptor)?);
    let destination_projection_digest = Digest32V2::new(decode_fixed::<32>(&mut decoder)?);
    let display_projection =
        DisplayProjectionIdV2::new(decoder.u32().map_err(|_| G4Error::NonCanonicalDescriptor)?);
    let display_projection_digest = Digest32V2::new(decode_fixed::<32>(&mut decoder)?);
    let idempotency_contract = decode_idempotency_contract(&mut decoder)?;
    let not_before = UnixMillisV2::new(decoder.u64().map_err(|_| G4Error::NonCanonicalDescriptor)?);
    let expires_at = UnixMillisV2::new(decoder.u64().map_err(|_| G4Error::NonCanonicalDescriptor)?);
    let business_profile = if schema_version == PROFILE_DESCRIPTOR_SCHEMA_VERSION {
        Some(
            decode_business_profile_v2(
                decoder
                    .bytes()
                    .map_err(|_| G4Error::NonCanonicalDescriptor)?,
            )
            .map_err(|_| G4Error::InvalidDescriptor)?,
        )
    } else {
        None
    };
    if decoder.position() != bytes.len() {
        return Err(G4Error::NonCanonicalDescriptor);
    }
    let mut descriptor = UnsignedToolDescriptorV2::from_verified_manifest(
        TOOL_DESCRIPTOR_SCHEMA_VERSION,
        registry_version,
        provider_identity_digest,
        provider_tool_id,
        action_template,
        tool_class,
        argument_schema_digest,
        result_schema_digest,
        allowed_roles,
        effects,
        attempt_kind,
        BoundedConnectorRetryPolicyV2::new(idempotency_contract, retry.0, retry.1)?,
        internal_validators,
        executor_identity,
        destination_projection,
        destination_projection_digest,
        display_projection,
        display_projection_digest,
        idempotency_contract,
        not_before,
        expires_at,
    )?;
    if let Some(profile) = business_profile {
        descriptor = descriptor.with_business_profile(profile)?;
    }
    let canonical = minicbor::to_vec(&descriptor).map_err(|_| G4Error::NonCanonicalDescriptor)?;
    if canonical != bytes {
        return Err(G4Error::NonCanonicalDescriptor);
    }
    Ok(descriptor)
}

fn decode_version(decoder: &mut minicbor::Decoder<'_>) -> Result<VersionV2, G4Error> {
    require_array(decoder, 3)?;
    Ok(VersionV2::new(
        decoder.u16().map_err(|_| G4Error::NonCanonicalDescriptor)?,
        decoder.u16().map_err(|_| G4Error::NonCanonicalDescriptor)?,
        decoder.u16().map_err(|_| G4Error::NonCanonicalDescriptor)?,
    ))
}

fn decode_attempt_kind(decoder: &mut minicbor::Decoder<'_>) -> Result<AttemptKindV2, G4Error> {
    require_array(decoder, 1)?;
    match decoder.u16().map_err(|_| G4Error::NonCanonicalDescriptor)? {
        1 => Ok(AttemptKindV2::ToolRead),
        2 => Ok(AttemptKindV2::ToolWrite),
        3 => Ok(AttemptKindV2::ToolIrreversible),
        _ => Err(G4Error::InvalidDescriptor),
    }
}

fn decode_retry_policy(decoder: &mut minicbor::Decoder<'_>) -> Result<(u16, u64), G4Error> {
    require_array(decoder, 2)?;
    Ok((
        decoder.u16().map_err(|_| G4Error::NonCanonicalDescriptor)?,
        decoder.u64().map_err(|_| G4Error::NonCanonicalDescriptor)?,
    ))
}

fn decode_idempotency_contract(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<ExecutorIdempotencyContractV2, G4Error> {
    require_array(decoder, 1)?;
    match decoder.u16().map_err(|_| G4Error::NonCanonicalDescriptor)? {
        1 => Ok(ExecutorIdempotencyContractV2::ConnectorIdempotentByExecutionNonce),
        2 => Ok(ExecutorIdempotencyContractV2::ConnectorNonIdempotentSingleAttempt),
        _ => Err(G4Error::InvalidDescriptor),
    }
}

fn require_array(decoder: &mut minicbor::Decoder<'_>, expected: u64) -> Result<(), G4Error> {
    match decoder
        .array()
        .map_err(|_| G4Error::NonCanonicalDescriptor)?
    {
        Some(length) if length == expected => Ok(()),
        _ => Err(G4Error::NonCanonicalDescriptor),
    }
}

fn bounded_array_len(
    decoder: &mut minicbor::Decoder<'_>,
    maximum: usize,
) -> Result<usize, G4Error> {
    let length = decoder
        .array()
        .map_err(|_| G4Error::NonCanonicalDescriptor)?
        .ok_or(G4Error::NonCanonicalDescriptor)?;
    let length = usize::try_from(length).map_err(|_| G4Error::DescriptorLimitExceeded)?;
    if length > maximum {
        return Err(G4Error::DescriptorLimitExceeded);
    }
    Ok(length)
}

fn decode_fixed<const N: usize>(decoder: &mut minicbor::Decoder<'_>) -> Result<[u8; N], G4Error> {
    <[u8; N]>::try_from(
        decoder
            .bytes()
            .map_err(|_| G4Error::NonCanonicalDescriptor)?,
    )
    .map_err(|_| G4Error::NonCanonicalDescriptor)
}

fn descriptor_digest_from_payload(payload: &[u8]) -> Digest32V2 {
    let mut hasher = Sha256::new();
    hasher.update(DESCRIPTOR_DIGEST_DOMAIN);
    hasher.update(payload);
    Digest32V2::new(hasher.finalize().into())
}

fn validator_cmp(
    left: &InternalValidatorDeclarationV2,
    right: &InternalValidatorDeclarationV2,
) -> Ordering {
    left.implementation_id
        .cmp(&right.implementation_id)
        .then_with(|| left.semantic_version.cmp(&right.semantic_version))
        .then_with(|| {
            left.build_manifest_digest
                .as_bytes()
                .cmp(right.build_manifest_digest.as_bytes())
        })
}

fn policy_activation_cmp(
    left: &VerifiedPolicyToolActivationV2,
    right: &VerifiedPolicyToolActivationV2,
) -> Ordering {
    left.descriptor_digest
        .as_bytes()
        .cmp(right.descriptor_digest.as_bytes())
        .then_with(|| left.registry_ordinal.cmp(&right.registry_ordinal))
}

fn is_zero<const N: usize>(bytes: &[u8; N]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

#[cfg(test)]
#[path = "descriptor_tests.rs"]
mod tests;
