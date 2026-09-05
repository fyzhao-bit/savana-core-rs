use core::fmt;

use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use sha2::{Digest as _, Sha256};

use crate::{ProtocolError, StableCode};

use super::{
    cbor::{scan_single, V2DecodeContext},
    derive_ed25519_key_id_v2, ActionIntentIdV2, AttemptKindV2, BoundedConnectorRegistryDeltaV2,
    Digest32V2, DurableReleaseIdV2, DurableRunIdV2, DurableTaskIdV2, Ed25519KeyIdV2,
    Ed25519SignatureV2, ExecutorIdentityV2, FinalReleaseSemanticBindingV2, FixedBytes32V2,
    HpkeX25519KeyIdV2, InternalStepIdV2, Nonce32V2, PlanRevisionDigestV2, UnixMillisV2,
};

const MAX_HPKE_CIPHERTEXT_BYTES_V2: usize = 7 * 1024 * 1024 + 16;
const MAX_SIGNED_EXECUTION_ENVELOPE_PAYLOAD_BYTES_V2: usize = 8 * 1024 * 1024;
const DISPATCH_SUBJECT_DOMAIN: &[u8] = b"SAVANA_DISPATCH_SUBJECT_V2\0";
const DISPATCH_CORE_DOMAIN: &[u8] = b"SAVANA_DISPATCH_CORE_V2\0";
const SEALED_EXECUTION_ENVELOPE_DOMAIN: &[u8] = b"SAVANA_SEALED_EXECUTION_ENVELOPE_V2\0";
const CONNECTOR_REGISTRY_SYNC_PAGE_DOMAIN_V2: &[u8] = b"SAVANA_CONNECTOR_REGISTRY_SYNC_PAGE_V2\0";
pub const MAX_CONNECTOR_REGISTRY_SYNC_PAGE_DELTAS_V2: usize = 256;
pub const MAX_CONNECTOR_REGISTRY_SYNC_PAGE_DELTA_BYTES_V2: usize = 8 * 1024 * 1024 - 4096;

#[derive(Clone, PartialEq, Eq)]
pub struct BoundedCiphertextV2(Vec<u8>);

impl BoundedCiphertextV2 {
    pub fn new(value: Vec<u8>) -> Result<Self, ProtocolError> {
        if value.is_empty() || value.len() > MAX_HPKE_CIPHERTEXT_BYTES_V2 {
            return Err(malformed());
        }
        Ok(Self(value))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for BoundedCiphertextV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundedCiphertextV2")
            .field("encoded_length", &self.0.len())
            .finish()
    }
}

impl<C> minicbor::Encode<C> for BoundedCiphertextV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        _context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.bytes(&self.0)?;
        Ok(())
    }
}

impl<'bytes> minicbor::Decode<'bytes, V2DecodeContext> for BoundedCiphertextV2 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        _context: &mut V2DecodeContext,
    ) -> Result<Self, minicbor::decode::Error> {
        let position = decoder.position();
        Self::new(decoder.bytes()?.to_vec()).map_err(|_| decode_error(position))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ToolExecutionSemanticBindingV2 {
    plan_revision_digest: PlanRevisionDigestV2,
    internal_step_id: InternalStepIdV2,
    tool_descriptor_digest: Digest32V2,
    argument_digest: Digest32V2,
    provenance_set_digest: Digest32V2,
    token_set_digest: Digest32V2,
    destination_digest: Digest32V2,
    display_projection_digest: Digest32V2,
    display_digest: Digest32V2,
    executor_identity_digest: Digest32V2,
    attempt_kind: AttemptKindV2,
}

impl ToolExecutionSemanticBindingV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        plan_revision_digest: PlanRevisionDigestV2,
        internal_step_id: InternalStepIdV2,
        tool_descriptor_digest: Digest32V2,
        argument_digest: Digest32V2,
        provenance_set_digest: Digest32V2,
        token_set_digest: Digest32V2,
        destination_digest: Digest32V2,
        display_projection_digest: Digest32V2,
        display_digest: Digest32V2,
        executor_identity_digest: Digest32V2,
        attempt_kind: AttemptKindV2,
    ) -> Result<Self, ProtocolError> {
        if is_zero(plan_revision_digest.as_bytes())
            || is_zero(internal_step_id.as_bytes())
            || [
                tool_descriptor_digest,
                argument_digest,
                provenance_set_digest,
                token_set_digest,
                destination_digest,
                display_projection_digest,
                display_digest,
                executor_identity_digest,
            ]
            .iter()
            .any(|digest| is_zero(digest.as_bytes()))
            || attempt_kind.get() == 0
        {
            return Err(malformed());
        }
        Ok(Self {
            plan_revision_digest,
            internal_step_id,
            tool_descriptor_digest,
            argument_digest,
            provenance_set_digest,
            token_set_digest,
            destination_digest,
            display_projection_digest,
            display_digest,
            executor_identity_digest,
            attempt_kind,
        })
    }

    pub const fn plan_revision_digest(self) -> PlanRevisionDigestV2 {
        self.plan_revision_digest
    }

    pub const fn internal_step_id(self) -> InternalStepIdV2 {
        self.internal_step_id
    }

    pub const fn tool_descriptor_digest(self) -> Digest32V2 {
        self.tool_descriptor_digest
    }

    pub const fn argument_digest(self) -> Digest32V2 {
        self.argument_digest
    }

    pub const fn provenance_set_digest(self) -> Digest32V2 {
        self.provenance_set_digest
    }

    pub const fn token_set_digest(self) -> Digest32V2 {
        self.token_set_digest
    }

    pub const fn destination_digest(self) -> Digest32V2 {
        self.destination_digest
    }

    pub const fn display_projection_digest(self) -> Digest32V2 {
        self.display_projection_digest
    }

    pub const fn display_digest(self) -> Digest32V2 {
        self.display_digest
    }

    pub const fn executor_identity_digest(self) -> Digest32V2 {
        self.executor_identity_digest
    }

    pub const fn attempt_kind(self) -> AttemptKindV2 {
        self.attempt_kind
    }
}

impl<C> minicbor::Encode<C> for ToolExecutionSemanticBindingV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.array(11)?;
        self.plan_revision_digest.encode(encoder, context)?;
        self.internal_step_id.encode(encoder, context)?;
        self.tool_descriptor_digest.encode(encoder, context)?;
        self.argument_digest.encode(encoder, context)?;
        self.provenance_set_digest.encode(encoder, context)?;
        self.token_set_digest.encode(encoder, context)?;
        self.destination_digest.encode(encoder, context)?;
        self.display_projection_digest.encode(encoder, context)?;
        self.display_digest.encode(encoder, context)?;
        self.executor_identity_digest.encode(encoder, context)?;
        self.attempt_kind.encode(encoder, context)?;
        Ok(())
    }
}

impl<'bytes> minicbor::Decode<'bytes, V2DecodeContext> for ToolExecutionSemanticBindingV2 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut V2DecodeContext,
    ) -> Result<Self, minicbor::decode::Error> {
        let position = decoder.position();
        if decoder.array()? != Some(11) {
            return Err(decode_error(position));
        }
        Self::new(
            minicbor::Decode::decode(decoder, context)?,
            minicbor::Decode::decode(decoder, context)?,
            minicbor::Decode::decode(decoder, context)?,
            minicbor::Decode::decode(decoder, context)?,
            minicbor::Decode::decode(decoder, context)?,
            minicbor::Decode::decode(decoder, context)?,
            minicbor::Decode::decode(decoder, context)?,
            minicbor::Decode::decode(decoder, context)?,
            minicbor::Decode::decode(decoder, context)?,
            minicbor::Decode::decode(decoder, context)?,
            minicbor::Decode::decode(decoder, context)?,
        )
        .map_err(|_| decode_error(position))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchSubjectV2 {
    ToolExecution {
        action_intent_id: ActionIntentIdV2,
        binding: ToolExecutionSemanticBindingV2,
        approval_settlement_digest: Option<Digest32V2>,
    },
    FinalRelease {
        binding: FinalReleaseSemanticBindingV2,
        approval_settlement_digest: Digest32V2,
    },
}

impl DispatchSubjectV2 {
    pub fn tool_execution(
        action_intent_id: ActionIntentIdV2,
        binding: ToolExecutionSemanticBindingV2,
        approval_settlement_digest: Option<Digest32V2>,
    ) -> Result<Self, ProtocolError> {
        if is_zero(action_intent_id.as_bytes()) || option_is_zero(approval_settlement_digest) {
            return Err(malformed());
        }
        Ok(Self::ToolExecution {
            action_intent_id,
            binding,
            approval_settlement_digest,
        })
    }

    pub fn final_release(
        binding: FinalReleaseSemanticBindingV2,
        approval_settlement_digest: Digest32V2,
    ) -> Result<Self, ProtocolError> {
        if is_zero(approval_settlement_digest.as_bytes()) {
            return Err(malformed());
        }
        Ok(Self::FinalRelease {
            binding,
            approval_settlement_digest,
        })
    }

    pub fn semantic_digest(self) -> Result<Digest32V2, ProtocolError> {
        let mut encoder = minicbor::Encoder::new(Vec::new());
        encode_dispatch_subject(&mut encoder, self)?;
        Ok(domain_hash(DISPATCH_SUBJECT_DOMAIN, &encoder.into_writer()))
    }
}

/// Kernel-signed linkage, not independently verified authority. The preseal
/// commitment binds exact application plaintext AND its declassification node
/// in the existing tool/release-specific hash domain. It is not the raw-body
/// SHA-256, a provider response, or a TLS transcript.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DispatchTaskBindingV2 {
    content_digest: Digest32V2,
    authorization_digest: Digest32V2,
    presealed_payload_digest: Digest32V2,
}
impl DispatchTaskBindingV2 {
    pub fn new(
        content_digest: Digest32V2,
        authorization_digest: Digest32V2,
        presealed_payload_digest: Digest32V2,
    ) -> Result<Self, ProtocolError> {
        if [
            content_digest,
            authorization_digest,
            presealed_payload_digest,
        ]
        .iter()
        .any(|d| is_zero(d.as_bytes()))
        {
            return Err(malformed());
        }
        Ok(Self {
            content_digest,
            authorization_digest,
            presealed_payload_digest,
        })
    }
    pub const fn content_digest(self) -> Digest32V2 {
        self.content_digest
    }
    pub const fn authorization_digest(self) -> Digest32V2 {
        self.authorization_digest
    }
    pub const fn presealed_payload_digest(self) -> Digest32V2 {
        self.presealed_payload_digest
    }
}
impl<C> minicbor::Encode<C> for DispatchTaskBindingV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        c: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.array(3)?;
        self.content_digest.encode(e, c)?;
        self.authorization_digest.encode(e, c)?;
        self.presealed_payload_digest.encode(e, c)?;
        Ok(())
    }
}
impl<'b> minicbor::Decode<'b, V2DecodeContext> for DispatchTaskBindingV2 {
    fn decode(
        d: &mut minicbor::Decoder<'b>,
        c: &mut V2DecodeContext,
    ) -> Result<Self, minicbor::decode::Error> {
        if d.array()? != Some(3) {
            return Err(minicbor::decode::Error::message("invalid task binding"));
        }
        Self::new(d.decode_with(c)?, d.decode_with(c)?, d.decode_with(c)?)
            .map_err(|_| minicbor::decode::Error::message("invalid task binding"))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DispatchCoreV2 {
    installation_id: Digest32V2,
    active_state_manifest_digest: Digest32V2,
    deployment_generation: u64,
    effect_fence_epoch: u64,
    durable_task_id: DurableTaskIdV2,
    durable_run_id: DurableRunIdV2,
    execution_nonce: Nonce32V2,
    subject: DispatchSubjectV2,
    dispatch_subject_digest: Digest32V2,
    executor_identity: ExecutorIdentityV2,
    executor_key_id: HpkeX25519KeyIdV2,
    executor_connector_registry_digest: Digest32V2,
    expires_at: UnixMillisV2,
    task_binding: Option<DispatchTaskBindingV2>,
}

impl DispatchCoreV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        installation_id: Digest32V2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        effect_fence_epoch: u64,
        durable_task_id: DurableTaskIdV2,
        durable_run_id: DurableRunIdV2,
        execution_nonce: Nonce32V2,
        subject: DispatchSubjectV2,
        executor_identity: ExecutorIdentityV2,
        executor_key_id: HpkeX25519KeyIdV2,
        executor_connector_registry_digest: Digest32V2,
        expires_at: UnixMillisV2,
    ) -> Result<Self, ProtocolError> {
        if is_zero(installation_id.as_bytes())
            || is_zero(active_state_manifest_digest.as_bytes())
            || deployment_generation == 0
            || effect_fence_epoch == 0
            || is_zero(durable_task_id.as_bytes())
            || is_zero(durable_run_id.as_bytes())
            || is_zero(execution_nonce.as_bytes())
            || is_zero(executor_identity.as_bytes())
            || is_zero(executor_key_id.as_bytes())
            || is_zero(executor_connector_registry_digest.as_bytes())
            || expires_at.get() == 0
        {
            return Err(malformed());
        }
        let dispatch_subject_digest = subject.semantic_digest()?;
        Ok(Self {
            installation_id,
            active_state_manifest_digest,
            deployment_generation,
            effect_fence_epoch,
            durable_task_id,
            durable_run_id,
            execution_nonce,
            subject,
            dispatch_subject_digest,
            executor_identity,
            executor_key_id,
            executor_connector_registry_digest,
            expires_at,
            task_binding: None,
        })
    }

    pub fn with_task_binding(mut self, binding: DispatchTaskBindingV2) -> Self {
        self.task_binding = Some(binding);
        self
    }
    pub const fn task_binding(self) -> Option<DispatchTaskBindingV2> {
        self.task_binding
    }

    pub const fn execution_nonce(self) -> Nonce32V2 {
        self.execution_nonce
    }

    pub const fn installation_id(self) -> Digest32V2 {
        self.installation_id
    }

    pub const fn active_state_manifest_digest(self) -> Digest32V2 {
        self.active_state_manifest_digest
    }

    pub const fn deployment_generation(self) -> u64 {
        self.deployment_generation
    }

    pub const fn effect_fence_epoch(self) -> u64 {
        self.effect_fence_epoch
    }

    pub const fn durable_task_id(self) -> DurableTaskIdV2 {
        self.durable_task_id
    }

    pub const fn durable_run_id(self) -> DurableRunIdV2 {
        self.durable_run_id
    }

    pub const fn subject(self) -> DispatchSubjectV2 {
        self.subject
    }

    pub const fn dispatch_subject_digest(self) -> Digest32V2 {
        self.dispatch_subject_digest
    }

    pub const fn executor_identity(self) -> ExecutorIdentityV2 {
        self.executor_identity
    }

    pub const fn executor_key_id(self) -> HpkeX25519KeyIdV2 {
        self.executor_key_id
    }

    pub const fn executor_connector_registry_digest(self) -> Digest32V2 {
        self.executor_connector_registry_digest
    }

    pub const fn expires_at(self) -> UnixMillisV2 {
        self.expires_at
    }

    pub fn semantic_digest(self) -> Result<Digest32V2, ProtocolError> {
        let mut encoder = minicbor::Encoder::new(Vec::new());
        encode_dispatch_core(&mut encoder, self)?;
        Ok(domain_hash(DISPATCH_CORE_DOMAIN, &encoder.into_writer()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedExecutionEnvelopePayloadV2 {
    core: DispatchCoreV2,
    dispatch_core_digest: Digest32V2,
    declassification_provenance_digest: Digest32V2,
    hpke_enc: FixedBytes32V2,
    hpke_ciphertext: BoundedCiphertextV2,
}

impl SealedExecutionEnvelopePayloadV2 {
    pub fn new(
        core: DispatchCoreV2,
        declassification_provenance_digest: Digest32V2,
        hpke_enc: FixedBytes32V2,
        hpke_ciphertext: BoundedCiphertextV2,
    ) -> Result<Self, ProtocolError> {
        if is_zero(declassification_provenance_digest.as_bytes()) || is_zero(hpke_enc.as_bytes()) {
            return Err(malformed());
        }
        let dispatch_core_digest = core.semantic_digest()?;
        Ok(Self {
            core,
            dispatch_core_digest,
            declassification_provenance_digest,
            hpke_enc,
            hpke_ciphertext,
        })
    }

    pub const fn core(&self) -> DispatchCoreV2 {
        self.core
    }

    pub const fn dispatch_core_digest(&self) -> Digest32V2 {
        self.dispatch_core_digest
    }

    pub const fn declassification_provenance_digest(&self) -> Digest32V2 {
        self.declassification_provenance_digest
    }

    pub const fn hpke_enc(&self) -> FixedBytes32V2 {
        self.hpke_enc
    }

    pub fn hpke_ciphertext(&self) -> &[u8] {
        &self.hpke_ciphertext.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedSealedExecutionEnvelopeV2 {
    payload: SealedExecutionEnvelopePayloadV2,
    key_id: Ed25519KeyIdV2,
    signature: Ed25519SignatureV2,
}

impl SignedSealedExecutionEnvelopeV2 {
    pub fn sign(
        payload: SealedExecutionEnvelopePayloadV2,
        signing_key: &SigningKey,
    ) -> Result<Self, ProtocolError> {
        let canonical_payload = encode_sealed_execution_envelope_payload(&payload)?;
        let signature_input = sealed_execution_signature_input(&canonical_payload);
        Self::from_parts(
            payload,
            super::derive_ed25519_key_id_v2(signing_key.verifying_key().to_bytes()),
            Ed25519SignatureV2::new(signing_key.sign(&signature_input).to_bytes()),
        )
    }

    pub fn from_parts(
        payload: SealedExecutionEnvelopePayloadV2,
        key_id: Ed25519KeyIdV2,
        signature: Ed25519SignatureV2,
    ) -> Result<Self, ProtocolError> {
        if is_zero(key_id.as_bytes()) || is_zero(signature.as_bytes()) {
            return Err(malformed());
        }
        Ok(Self {
            payload,
            key_id,
            signature,
        })
    }

    pub const fn payload(&self) -> &SealedExecutionEnvelopePayloadV2 {
        &self.payload
    }

    pub const fn key_id(&self) -> Ed25519KeyIdV2 {
        self.key_id
    }

    pub const fn signature(&self) -> Ed25519SignatureV2 {
        self.signature
    }

    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        expected_key_id: Ed25519KeyIdV2,
        expected_public_key: [u8; 32],
        expected_installation_id: Digest32V2,
        expected_active_state_manifest_digest: Digest32V2,
        expected_deployment_generation: u64,
        expected_effect_fence_epoch: u64,
        expected_executor_identity: ExecutorIdentityV2,
        now: Option<UnixMillisV2>,
    ) -> Result<SealedExecutionEnvelopePayloadV2, ProtocolError> {
        let core = self.payload.core();
        if self.key_id != expected_key_id
            || super::derive_ed25519_key_id_v2(expected_public_key) != expected_key_id
            || core.installation_id() != expected_installation_id
            || core.active_state_manifest_digest() != expected_active_state_manifest_digest
            || core.deployment_generation() != expected_deployment_generation
            || core.effect_fence_epoch() != expected_effect_fence_epoch
            || core.executor_identity() != expected_executor_identity
            || now.is_some_and(|now| now.get() == 0 || now.get() >= core.expires_at().get())
        {
            return Err(malformed());
        }
        let canonical_payload = encode_sealed_execution_envelope_payload(&self.payload)?;
        VerifyingKey::from_bytes(&expected_public_key)
            .map_err(ProtocolError::malformed)?
            .verify_strict(
                &sealed_execution_signature_input(&canonical_payload),
                &Signature::from_bytes(self.signature.as_bytes()),
            )
            .map_err(ProtocolError::malformed)?;
        Ok(self.payload.clone())
    }
}

pub fn encode_signed_sealed_execution_envelope_v2(
    value: &SignedSealedExecutionEnvelopeV2,
) -> Result<Vec<u8>, ProtocolError> {
    minicbor::to_vec(value).map_err(ProtocolError::malformed)
}

pub fn decode_signed_sealed_execution_envelope_v2(
    bytes: &[u8],
) -> Result<SignedSealedExecutionEnvelopeV2, ProtocolError> {
    scan_single(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    let mut context = V2DecodeContext;
    let value = minicbor::Decode::decode(&mut decoder, &mut context)
        .map_err(ProtocolError::from_typed_decode)?;
    if decoder.position() != bytes.len()
        || encode_signed_sealed_execution_envelope_v2(&value)? != bytes
    {
        return Err(malformed());
    }
    Ok(value)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutorCompletionDescriptorV2 {
    ToolResult {
        result_digest: Digest32V2,
        encoded_length: u32,
    },
    FinalReleaseReceipt {
        durable_release_id: DurableReleaseIdV2,
        final_release_receipt_digest: Digest32V2,
        release_audit_digest: Digest32V2,
        encoded_length: u32,
    },
}

impl ExecutorCompletionDescriptorV2 {
    pub fn tool_result(
        result_digest: Digest32V2,
        encoded_length: u32,
    ) -> Result<Self, ProtocolError> {
        if is_zero(result_digest.as_bytes()) || encoded_length == 0 {
            return Err(malformed());
        }
        Ok(Self::ToolResult {
            result_digest,
            encoded_length,
        })
    }

    pub fn final_release_receipt(
        durable_release_id: DurableReleaseIdV2,
        final_release_receipt_digest: Digest32V2,
        release_audit_digest: Digest32V2,
        encoded_length: u32,
    ) -> Result<Self, ProtocolError> {
        if is_zero(durable_release_id.as_bytes())
            || is_zero(final_release_receipt_digest.as_bytes())
            || is_zero(release_audit_digest.as_bytes())
            || encoded_length == 0
        {
            return Err(malformed());
        }
        Ok(Self::FinalReleaseReceipt {
            durable_release_id,
            final_release_receipt_digest,
            release_audit_digest,
            encoded_length,
        })
    }

    pub const fn encoded_length(self) -> u32 {
        match self {
            Self::ToolResult { encoded_length, .. }
            | Self::FinalReleaseReceipt { encoded_length, .. } => encoded_length,
        }
    }

    pub const fn tool_result_digest(self) -> Option<Digest32V2> {
        match self {
            Self::ToolResult { result_digest, .. } => Some(result_digest),
            Self::FinalReleaseReceipt { .. } => None,
        }
    }

    pub const fn final_release_identity(
        self,
    ) -> Option<(DurableReleaseIdV2, Digest32V2, Digest32V2)> {
        match self {
            Self::FinalReleaseReceipt {
                durable_release_id,
                final_release_receipt_digest,
                release_audit_digest,
                ..
            } => Some((
                durable_release_id,
                final_release_receipt_digest,
                release_audit_digest,
            )),
            Self::ToolResult { .. } => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutorHealthRequestV2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchRequestV2 {
    envelope: SignedSealedExecutionEnvelopeV2,
}

impl DispatchRequestV2 {
    pub const fn new(envelope: SignedSealedExecutionEnvelopeV2) -> Self {
        Self { envelope }
    }

    pub const fn envelope(&self) -> &SignedSealedExecutionEnvelopeV2 {
        &self.envelope
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueryByExecutionNonceRequestV2 {
    execution_nonce: Nonce32V2,
    dispatch_core_digest: Digest32V2,
    dispatch_subject_digest: Digest32V2,
}

impl QueryByExecutionNonceRequestV2 {
    pub fn new(
        execution_nonce: Nonce32V2,
        dispatch_core_digest: Digest32V2,
        dispatch_subject_digest: Digest32V2,
    ) -> Result<Self, ProtocolError> {
        validate_nonce_core_subject(
            execution_nonce,
            dispatch_core_digest,
            dispatch_subject_digest,
        )?;
        Ok(Self {
            execution_nonce,
            dispatch_core_digest,
            dispatch_subject_digest,
        })
    }

    pub const fn execution_nonce(self) -> Nonce32V2 {
        self.execution_nonce
    }

    pub const fn dispatch_core_digest(self) -> Digest32V2 {
        self.dispatch_core_digest
    }

    pub const fn dispatch_subject_digest(self) -> Digest32V2 {
        self.dispatch_subject_digest
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcknowledgeCommittedCompletionRequestV2 {
    execution_nonce: Nonce32V2,
    dispatch_core_digest: Digest32V2,
    dispatch_subject_digest: Digest32V2,
    completion: ExecutorCompletionDescriptorV2,
    kernel_commit_digest: Digest32V2,
}

impl AcknowledgeCommittedCompletionRequestV2 {
    pub fn new(
        execution_nonce: Nonce32V2,
        dispatch_core_digest: Digest32V2,
        dispatch_subject_digest: Digest32V2,
        completion: ExecutorCompletionDescriptorV2,
        kernel_commit_digest: Digest32V2,
    ) -> Result<Self, ProtocolError> {
        validate_nonce_core_subject(
            execution_nonce,
            dispatch_core_digest,
            dispatch_subject_digest,
        )?;
        if is_zero(kernel_commit_digest.as_bytes()) {
            return Err(malformed());
        }
        Ok(Self {
            execution_nonce,
            dispatch_core_digest,
            dispatch_subject_digest,
            completion,
            kernel_commit_digest,
        })
    }

    pub const fn execution_nonce(self) -> Nonce32V2 {
        self.execution_nonce
    }

    pub const fn dispatch_core_digest(self) -> Digest32V2 {
        self.dispatch_core_digest
    }

    pub const fn dispatch_subject_digest(self) -> Digest32V2 {
        self.dispatch_subject_digest
    }

    pub const fn completion(self) -> ExecutorCompletionDescriptorV2 {
        self.completion
    }

    pub const fn kernel_commit_digest(self) -> Digest32V2 {
        self.kernel_commit_digest
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FetchCompletionRequestV2 {
    execution_nonce: Nonce32V2,
    dispatch_core_digest: Digest32V2,
    dispatch_subject_digest: Digest32V2,
    completion: ExecutorCompletionDescriptorV2,
}

impl FetchCompletionRequestV2 {
    pub fn new(
        execution_nonce: Nonce32V2,
        dispatch_core_digest: Digest32V2,
        dispatch_subject_digest: Digest32V2,
        completion: ExecutorCompletionDescriptorV2,
    ) -> Result<Self, ProtocolError> {
        validate_nonce_core_subject(
            execution_nonce,
            dispatch_core_digest,
            dispatch_subject_digest,
        )?;
        Ok(Self {
            execution_nonce,
            dispatch_core_digest,
            dispatch_subject_digest,
            completion,
        })
    }

    pub const fn execution_nonce(self) -> Nonce32V2 {
        self.execution_nonce
    }

    pub const fn dispatch_core_digest(self) -> Digest32V2 {
        self.dispatch_core_digest
    }

    pub const fn dispatch_subject_digest(self) -> Digest32V2 {
        self.dispatch_subject_digest
    }

    pub const fn completion(self) -> ExecutorCompletionDescriptorV2 {
        self.completion
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectorRegistrySyncScopeV2 {
    installation_id: Digest32V2,
    active_state_manifest_digest: Digest32V2,
    deployment_generation: u64,
    genesis_head_digest: Digest32V2,
    authority_key_id: Ed25519KeyIdV2,
    authority_public_key: FixedBytes32V2,
    canonical_host_allowlist_digest: Digest32V2,
}

impl ConnectorRegistrySyncScopeV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        installation_id: Digest32V2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        genesis_head_digest: Digest32V2,
        authority_key_id: Ed25519KeyIdV2,
        authority_public_key: FixedBytes32V2,
        canonical_host_allowlist_digest: Digest32V2,
    ) -> Result<Self, ProtocolError> {
        let key_id_is_zero = is_zero(authority_key_id.as_bytes());
        let public_key_is_zero = is_zero(authority_public_key.as_bytes());
        if deployment_generation == 0
            || is_zero(installation_id.as_bytes())
            || is_zero(active_state_manifest_digest.as_bytes())
            || is_zero(genesis_head_digest.as_bytes())
            || is_zero(canonical_host_allowlist_digest.as_bytes())
            || key_id_is_zero != public_key_is_zero
            || (!public_key_is_zero
                && derive_ed25519_key_id_v2(*authority_public_key.as_bytes()) != authority_key_id)
        {
            return Err(malformed());
        }
        Ok(Self {
            installation_id,
            active_state_manifest_digest,
            deployment_generation,
            genesis_head_digest,
            authority_key_id,
            authority_public_key,
            canonical_host_allowlist_digest,
        })
    }

    pub const fn installation_id(self) -> Digest32V2 {
        self.installation_id
    }

    pub const fn active_state_manifest_digest(self) -> Digest32V2 {
        self.active_state_manifest_digest
    }

    pub const fn deployment_generation(self) -> u64 {
        self.deployment_generation
    }

    pub const fn genesis_head_digest(self) -> Digest32V2 {
        self.genesis_head_digest
    }

    pub const fn authority_key_id(self) -> Ed25519KeyIdV2 {
        self.authority_key_id
    }

    pub const fn authority_public_key(self) -> FixedBytes32V2 {
        self.authority_public_key
    }

    pub const fn canonical_host_allowlist_digest(self) -> Digest32V2 {
        self.canonical_host_allowlist_digest
    }

    pub fn authority_enabled(self) -> bool {
        !is_zero(self.authority_key_id.as_bytes())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorRegistrySyncPageV2 {
    base_sequence: u64,
    base_head_digest: Digest32V2,
    page_final_sequence: u64,
    page_final_head_digest: Digest32V2,
    source_final_sequence: u64,
    source_final_head_digest: Digest32V2,
    deltas: Vec<BoundedConnectorRegistryDeltaV2>,
    commitment: Digest32V2,
}

impl ConnectorRegistrySyncPageV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        base_sequence: u64,
        base_head_digest: Digest32V2,
        page_final_sequence: u64,
        page_final_head_digest: Digest32V2,
        source_final_sequence: u64,
        source_final_head_digest: Digest32V2,
        deltas: Vec<BoundedConnectorRegistryDeltaV2>,
    ) -> Result<Self, ProtocolError> {
        if deltas.is_empty()
            || deltas.len() > MAX_CONNECTOR_REGISTRY_SYNC_PAGE_DELTAS_V2
            || is_zero(base_head_digest.as_bytes())
            || is_zero(page_final_head_digest.as_bytes())
            || is_zero(source_final_head_digest.as_bytes())
        {
            return Err(malformed());
        }
        let delta_count = u64::try_from(deltas.len()).map_err(|_| malformed())?;
        if base_sequence.checked_add(delta_count) != Some(page_final_sequence)
            || source_final_sequence < page_final_sequence
            || ((source_final_sequence == page_final_sequence)
                != (source_final_head_digest == page_final_head_digest))
        {
            return Err(malformed());
        }
        let total_delta_bytes = deltas.iter().try_fold(0usize, |total, delta| {
            total
                .checked_add(delta.as_bytes().len())
                .ok_or_else(malformed)
        })?;
        if total_delta_bytes > MAX_CONNECTOR_REGISTRY_SYNC_PAGE_DELTA_BYTES_V2 {
            return Err(malformed());
        }
        let commitment = connector_registry_sync_page_commitment(
            base_sequence,
            base_head_digest,
            page_final_sequence,
            page_final_head_digest,
            source_final_sequence,
            source_final_head_digest,
            &deltas,
        )?;
        Ok(Self {
            base_sequence,
            base_head_digest,
            page_final_sequence,
            page_final_head_digest,
            source_final_sequence,
            source_final_head_digest,
            deltas,
            commitment,
        })
    }

    pub const fn base_sequence(&self) -> u64 {
        self.base_sequence
    }

    pub const fn base_head_digest(&self) -> Digest32V2 {
        self.base_head_digest
    }

    pub const fn page_final_sequence(&self) -> u64 {
        self.page_final_sequence
    }

    pub const fn page_final_head_digest(&self) -> Digest32V2 {
        self.page_final_head_digest
    }

    pub const fn source_final_sequence(&self) -> u64 {
        self.source_final_sequence
    }

    pub const fn source_final_head_digest(&self) -> Digest32V2 {
        self.source_final_head_digest
    }

    pub fn deltas(&self) -> &[BoundedConnectorRegistryDeltaV2] {
        &self.deltas
    }

    pub const fn commitment(&self) -> Digest32V2 {
        self.commitment
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectorRegistrySyncModeV2 {
    Probe,
    ApplyPage(ConnectorRegistrySyncPageV2),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorRegistrySyncRequestV2 {
    scope: ConnectorRegistrySyncScopeV2,
    mode: ConnectorRegistrySyncModeV2,
}

impl ConnectorRegistrySyncRequestV2 {
    pub fn new(
        scope: ConnectorRegistrySyncScopeV2,
        mode: ConnectorRegistrySyncModeV2,
    ) -> Result<Self, ProtocolError> {
        if !scope.authority_enabled() && matches!(mode, ConnectorRegistrySyncModeV2::ApplyPage(_)) {
            return Err(malformed());
        }
        Ok(Self { scope, mode })
    }

    pub const fn scope(&self) -> &ConnectorRegistrySyncScopeV2 {
        &self.scope
    }

    pub const fn mode(&self) -> &ConnectorRegistrySyncModeV2 {
        &self.mode
    }

    pub fn into_parts(self) -> (ConnectorRegistrySyncScopeV2, ConnectorRegistrySyncModeV2) {
        (self.scope, self.mode)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum KernelExecutorOperationV2 {
    Health(ExecutorHealthRequestV2),
    Dispatch(DispatchRequestV2),
    QueryByExecutionNonce(QueryByExecutionNonceRequestV2),
    AcknowledgeCommittedCompletion(AcknowledgeCommittedCompletionRequestV2),
    FetchCompletion(FetchCompletionRequestV2),
    ConnectorRegistrySync(ConnectorRegistrySyncRequestV2),
}

impl KernelExecutorOperationV2 {
    pub const fn tag(&self) -> u16 {
        match self {
            Self::Health(_) => 0,
            Self::Dispatch(_) => 60,
            Self::QueryByExecutionNonce(_) => 61,
            Self::AcknowledgeCommittedCompletion(_) => 62,
            Self::FetchCompletion(_) => 63,
            Self::ConnectorRegistrySync(_) => 64,
        }
    }
}

pub const fn kernel_executor_operation_tags_v2() -> &'static [u16; 6] {
    &[0, 60, 61, 62, 63, 64]
}

pub fn encode_kernel_executor_operation_v2(
    value: &KernelExecutorOperationV2,
) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    match value {
        KernelExecutorOperationV2::Health(_) => encode_header(&mut encoder, 0, 0)?,
        KernelExecutorOperationV2::Dispatch(request) => {
            encode_header(&mut encoder, 60, 1)?;
            encode_fixed(&mut encoder, &request.envelope)?;
        }
        KernelExecutorOperationV2::QueryByExecutionNonce(request) => {
            encode_header(&mut encoder, 61, 3)?;
            encode_nonce_core_subject(
                &mut encoder,
                request.execution_nonce,
                request.dispatch_core_digest,
                request.dispatch_subject_digest,
            )?;
        }
        KernelExecutorOperationV2::AcknowledgeCommittedCompletion(request) => {
            encode_header(&mut encoder, 62, 5)?;
            encode_nonce_core_subject(
                &mut encoder,
                request.execution_nonce,
                request.dispatch_core_digest,
                request.dispatch_subject_digest,
            )?;
            encode_completion_descriptor(&mut encoder, request.completion)?;
            encode_fixed(&mut encoder, &request.kernel_commit_digest)?;
        }
        KernelExecutorOperationV2::FetchCompletion(request) => {
            encode_header(&mut encoder, 63, 4)?;
            encode_nonce_core_subject(
                &mut encoder,
                request.execution_nonce,
                request.dispatch_core_digest,
                request.dispatch_subject_digest,
            )?;
            encode_completion_descriptor(&mut encoder, request.completion)?;
        }
        KernelExecutorOperationV2::ConnectorRegistrySync(request) => {
            encode_header(&mut encoder, 64, 2)?;
            encode_connector_registry_sync_scope(&mut encoder, request.scope)?;
            encode_connector_registry_sync_mode(&mut encoder, &request.mode)?;
        }
    }
    Ok(encoder.into_writer())
}

pub fn decode_kernel_executor_operation_v2(
    bytes: &[u8],
) -> Result<KernelExecutorOperationV2, ProtocolError> {
    scan_single(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    expect_array(&mut decoder, 2)?;
    let tag = decoder.u16().map_err(ProtocolError::malformed)?;
    let mut context = V2DecodeContext;
    let value = match tag {
        0 => {
            expect_array(&mut decoder, 0)?;
            KernelExecutorOperationV2::Health(ExecutorHealthRequestV2)
        }
        60 => {
            expect_array(&mut decoder, 1)?;
            KernelExecutorOperationV2::Dispatch(DispatchRequestV2::new(decode_fixed(
                &mut decoder,
                &mut context,
            )?))
        }
        61 => {
            expect_array(&mut decoder, 3)?;
            let (nonce, core, subject) = decode_nonce_core_subject(&mut decoder, &mut context)?;
            KernelExecutorOperationV2::QueryByExecutionNonce(QueryByExecutionNonceRequestV2::new(
                nonce, core, subject,
            )?)
        }
        62 => {
            expect_array(&mut decoder, 5)?;
            let (nonce, core, subject) = decode_nonce_core_subject(&mut decoder, &mut context)?;
            let completion = decode_completion_descriptor(&mut decoder, &mut context)?;
            let kernel_commit_digest = decode_fixed(&mut decoder, &mut context)?;
            KernelExecutorOperationV2::AcknowledgeCommittedCompletion(
                AcknowledgeCommittedCompletionRequestV2::new(
                    nonce,
                    core,
                    subject,
                    completion,
                    kernel_commit_digest,
                )?,
            )
        }
        63 => {
            expect_array(&mut decoder, 4)?;
            let (nonce, core, subject) = decode_nonce_core_subject(&mut decoder, &mut context)?;
            let completion = decode_completion_descriptor(&mut decoder, &mut context)?;
            KernelExecutorOperationV2::FetchCompletion(FetchCompletionRequestV2::new(
                nonce, core, subject, completion,
            )?)
        }
        64 => {
            expect_array(&mut decoder, 2)?;
            let scope = decode_connector_registry_sync_scope(&mut decoder, &mut context)?;
            let mode = decode_connector_registry_sync_mode(&mut decoder, &mut context)?;
            KernelExecutorOperationV2::ConnectorRegistrySync(ConnectorRegistrySyncRequestV2::new(
                scope, mode,
            )?)
        }
        _ => return Err(ProtocolError::stable(StableCode::ProtocolUnknownOperation)),
    };
    if decoder.position() != bytes.len() || encode_kernel_executor_operation_v2(&value)? != bytes {
        return Err(malformed());
    }
    Ok(value)
}

fn encode_connector_registry_sync_scope(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    scope: ConnectorRegistrySyncScopeV2,
) -> Result<(), ProtocolError> {
    encoder.array(7).map_err(ProtocolError::malformed)?;
    encode_fixed(encoder, &scope.installation_id)?;
    encode_fixed(encoder, &scope.active_state_manifest_digest)?;
    encoder
        .u64(scope.deployment_generation)
        .map_err(ProtocolError::malformed)?;
    encode_fixed(encoder, &scope.genesis_head_digest)?;
    encode_fixed(encoder, &scope.authority_key_id)?;
    encode_fixed(encoder, &scope.authority_public_key)?;
    encode_fixed(encoder, &scope.canonical_host_allowlist_digest)
}

fn decode_connector_registry_sync_scope(
    decoder: &mut minicbor::Decoder<'_>,
    context: &mut V2DecodeContext,
) -> Result<ConnectorRegistrySyncScopeV2, ProtocolError> {
    expect_array(decoder, 7)?;
    ConnectorRegistrySyncScopeV2::new(
        decode_fixed(decoder, context)?,
        decode_fixed(decoder, context)?,
        decoder.u64().map_err(ProtocolError::malformed)?,
        decode_fixed(decoder, context)?,
        decode_fixed(decoder, context)?,
        decode_fixed(decoder, context)?,
        decode_fixed(decoder, context)?,
    )
}

fn encode_connector_registry_sync_mode(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    mode: &ConnectorRegistrySyncModeV2,
) -> Result<(), ProtocolError> {
    match mode {
        ConnectorRegistrySyncModeV2::Probe => {
            encoder
                .array(1)
                .and_then(|encoder| encoder.u16(0))
                .map_err(ProtocolError::malformed)?;
        }
        ConnectorRegistrySyncModeV2::ApplyPage(page) => {
            encoder
                .array(2)
                .and_then(|encoder| encoder.u16(1))
                .map_err(ProtocolError::malformed)?;
            encode_connector_registry_sync_page(encoder, page)?;
        }
    }
    Ok(())
}

fn decode_connector_registry_sync_mode(
    decoder: &mut minicbor::Decoder<'_>,
    context: &mut V2DecodeContext,
) -> Result<ConnectorRegistrySyncModeV2, ProtocolError> {
    let length = decoder
        .array()
        .map_err(ProtocolError::malformed)?
        .ok_or_else(malformed)?;
    let tag = decoder.u16().map_err(ProtocolError::malformed)?;
    match (tag, length) {
        (0, 1) => Ok(ConnectorRegistrySyncModeV2::Probe),
        (1, 2) => decode_connector_registry_sync_page(decoder, context)
            .map(ConnectorRegistrySyncModeV2::ApplyPage),
        _ => Err(malformed()),
    }
}

fn encode_connector_registry_sync_page(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    page: &ConnectorRegistrySyncPageV2,
) -> Result<(), ProtocolError> {
    encoder
        .array(8)
        .and_then(|encoder| encoder.u64(page.base_sequence))
        .map_err(ProtocolError::malformed)?;
    encode_fixed(encoder, &page.base_head_digest)?;
    encoder
        .u64(page.page_final_sequence)
        .map_err(ProtocolError::malformed)?;
    encode_fixed(encoder, &page.page_final_head_digest)?;
    encoder
        .u64(page.source_final_sequence)
        .map_err(ProtocolError::malformed)?;
    encode_fixed(encoder, &page.source_final_head_digest)?;
    encoder
        .array(u64::try_from(page.deltas.len()).map_err(|_| malformed())?)
        .map_err(ProtocolError::malformed)?;
    for delta in &page.deltas {
        encoder
            .bytes(delta.as_bytes())
            .map_err(ProtocolError::malformed)?;
    }
    encode_fixed(encoder, &page.commitment)
}

fn decode_connector_registry_sync_page(
    decoder: &mut minicbor::Decoder<'_>,
    context: &mut V2DecodeContext,
) -> Result<ConnectorRegistrySyncPageV2, ProtocolError> {
    expect_array(decoder, 8)?;
    let base_sequence = decoder.u64().map_err(ProtocolError::malformed)?;
    let base_head_digest = decode_fixed(decoder, context)?;
    let page_final_sequence = decoder.u64().map_err(ProtocolError::malformed)?;
    let page_final_head_digest = decode_fixed(decoder, context)?;
    let source_final_sequence = decoder.u64().map_err(ProtocolError::malformed)?;
    let source_final_head_digest = decode_fixed(decoder, context)?;
    let delta_count = decoder
        .array()
        .map_err(ProtocolError::malformed)?
        .ok_or_else(malformed)?;
    let delta_count = usize::try_from(delta_count).map_err(|_| malformed())?;
    if delta_count == 0 || delta_count > MAX_CONNECTOR_REGISTRY_SYNC_PAGE_DELTAS_V2 {
        return Err(malformed());
    }
    let mut total_delta_bytes = 0usize;
    let mut deltas = Vec::with_capacity(delta_count);
    for _ in 0..delta_count {
        let bytes = decoder.bytes().map_err(ProtocolError::malformed)?.to_vec();
        total_delta_bytes = total_delta_bytes
            .checked_add(bytes.len())
            .ok_or_else(malformed)?;
        if total_delta_bytes > MAX_CONNECTOR_REGISTRY_SYNC_PAGE_DELTA_BYTES_V2 {
            return Err(malformed());
        }
        deltas.push(BoundedConnectorRegistryDeltaV2::new(bytes)?);
    }
    let claimed_commitment: Digest32V2 = decode_fixed(decoder, context)?;
    let page = ConnectorRegistrySyncPageV2::new(
        base_sequence,
        base_head_digest,
        page_final_sequence,
        page_final_head_digest,
        source_final_sequence,
        source_final_head_digest,
        deltas,
    )?;
    if claimed_commitment != page.commitment {
        return Err(malformed());
    }
    Ok(page)
}

#[allow(clippy::too_many_arguments)]
fn connector_registry_sync_page_commitment(
    base_sequence: u64,
    base_head_digest: Digest32V2,
    page_final_sequence: u64,
    page_final_head_digest: Digest32V2,
    source_final_sequence: u64,
    source_final_head_digest: Digest32V2,
    deltas: &[BoundedConnectorRegistryDeltaV2],
) -> Result<Digest32V2, ProtocolError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(7)
        .and_then(|encoder| encoder.u64(base_sequence))
        .map_err(ProtocolError::malformed)?;
    encode_fixed(&mut encoder, &base_head_digest)?;
    encoder
        .u64(page_final_sequence)
        .map_err(ProtocolError::malformed)?;
    encode_fixed(&mut encoder, &page_final_head_digest)?;
    encoder
        .u64(source_final_sequence)
        .map_err(ProtocolError::malformed)?;
    encode_fixed(&mut encoder, &source_final_head_digest)?;
    encoder
        .array(u64::try_from(deltas.len()).map_err(|_| malformed())?)
        .map_err(ProtocolError::malformed)?;
    for delta in deltas {
        encoder
            .bytes(delta.as_bytes())
            .map_err(ProtocolError::malformed)?;
    }
    Ok(domain_hash(
        CONNECTOR_REGISTRY_SYNC_PAGE_DOMAIN_V2,
        &encoder.into_writer(),
    ))
}

impl<C> minicbor::Encode<C> for SignedSealedExecutionEnvelopeV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        _context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        let payload = encode_sealed_execution_envelope_payload(&self.payload)
            .map_err(|_| minicbor::encode::Error::message("invalid sealed execution envelope"))?;
        encoder.array(3)?.bytes(&payload)?;
        minicbor::Encode::encode(&self.key_id, encoder, &mut ())?;
        minicbor::Encode::encode(&self.signature, encoder, &mut ())?;
        Ok(())
    }
}

impl<'bytes> minicbor::Decode<'bytes, V2DecodeContext> for SignedSealedExecutionEnvelopeV2 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut V2DecodeContext,
    ) -> Result<Self, minicbor::decode::Error> {
        let position = decoder.position();
        if decoder.array()? != Some(3) {
            return Err(decode_error(position));
        }
        let payload = decoder.bytes()?;
        if payload.len() > MAX_SIGNED_EXECUTION_ENVELOPE_PAYLOAD_BYTES_V2 {
            return Err(decode_error(position));
        }
        let payload = decode_sealed_execution_envelope_payload(payload)
            .map_err(|_| decode_error(position))?;
        let key_id = minicbor::Decode::decode(decoder, context)?;
        let signature = minicbor::Decode::decode(decoder, context)?;
        Self::from_parts(payload, key_id, signature).map_err(|_| decode_error(position))
    }
}

fn encode_tool_execution_binding(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    value: ToolExecutionSemanticBindingV2,
) -> Result<(), ProtocolError> {
    encoder.array(11).map_err(ProtocolError::malformed)?;
    encode_fixed(encoder, &value.plan_revision_digest)?;
    encode_fixed(encoder, &value.internal_step_id)?;
    encode_fixed(encoder, &value.tool_descriptor_digest)?;
    encode_fixed(encoder, &value.argument_digest)?;
    encode_fixed(encoder, &value.provenance_set_digest)?;
    encode_fixed(encoder, &value.token_set_digest)?;
    encode_fixed(encoder, &value.destination_digest)?;
    encode_fixed(encoder, &value.display_projection_digest)?;
    encode_fixed(encoder, &value.display_digest)?;
    encode_fixed(encoder, &value.executor_identity_digest)?;
    encode_fixed(encoder, &value.attempt_kind)
}

fn decode_tool_execution_binding(
    decoder: &mut minicbor::Decoder<'_>,
    context: &mut V2DecodeContext,
) -> Result<ToolExecutionSemanticBindingV2, ProtocolError> {
    expect_array(decoder, 11)?;
    ToolExecutionSemanticBindingV2::new(
        decode_fixed(decoder, context)?,
        decode_fixed(decoder, context)?,
        decode_fixed(decoder, context)?,
        decode_fixed(decoder, context)?,
        decode_fixed(decoder, context)?,
        decode_fixed(decoder, context)?,
        decode_fixed(decoder, context)?,
        decode_fixed(decoder, context)?,
        decode_fixed(decoder, context)?,
        decode_fixed(decoder, context)?,
        decode_fixed(decoder, context)?,
    )
}

fn encode_dispatch_subject(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    value: DispatchSubjectV2,
) -> Result<(), ProtocolError> {
    match value {
        DispatchSubjectV2::ToolExecution {
            action_intent_id,
            binding,
            approval_settlement_digest,
        } => {
            encoder
                .array(4)
                .and_then(|encoder| encoder.u16(1))
                .map_err(ProtocolError::malformed)?;
            encode_fixed(encoder, &action_intent_id)?;
            encode_tool_execution_binding(encoder, binding)?;
            encode_optional_fixed(encoder, approval_settlement_digest)?;
        }
        DispatchSubjectV2::FinalRelease {
            binding,
            approval_settlement_digest,
        } => {
            encoder
                .array(3)
                .and_then(|encoder| encoder.u16(2))
                .map_err(ProtocolError::malformed)?;
            encode_fixed(encoder, &binding)?;
            encode_fixed(encoder, &approval_settlement_digest)?;
        }
    }
    Ok(())
}

fn decode_dispatch_subject(
    decoder: &mut minicbor::Decoder<'_>,
    context: &mut V2DecodeContext,
) -> Result<DispatchSubjectV2, ProtocolError> {
    let length = decoder
        .array()
        .map_err(ProtocolError::malformed)?
        .ok_or_else(malformed)?;
    let tag = decoder.u16().map_err(ProtocolError::malformed)?;
    match (tag, length) {
        (1, 4) => DispatchSubjectV2::tool_execution(
            decode_fixed(decoder, context)?,
            decode_tool_execution_binding(decoder, context)?,
            decode_optional_fixed(decoder, context)?,
        ),
        (2, 3) => DispatchSubjectV2::final_release(
            decode_fixed(decoder, context)?,
            decode_fixed(decoder, context)?,
        ),
        _ => Err(malformed()),
    }
}

fn encode_dispatch_core(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    value: DispatchCoreV2,
) -> Result<(), ProtocolError> {
    encoder
        .array(if value.task_binding.is_some() { 15 } else { 14 })
        .and_then(|encoder| encoder.u16(if value.task_binding.is_some() { 3 } else { 2 }))
        .map_err(ProtocolError::malformed)?;
    encode_fixed(encoder, &value.installation_id)?;
    encode_fixed(encoder, &value.active_state_manifest_digest)?;
    encoder
        .u64(value.deployment_generation)
        .and_then(|encoder| encoder.u64(value.effect_fence_epoch))
        .map_err(ProtocolError::malformed)?;
    encode_fixed(encoder, &value.durable_task_id)?;
    encode_fixed(encoder, &value.durable_run_id)?;
    encode_fixed(encoder, &value.execution_nonce)?;
    encode_dispatch_subject(encoder, value.subject)?;
    encode_fixed(encoder, &value.dispatch_subject_digest)?;
    encode_fixed(encoder, &value.executor_identity)?;
    encode_fixed(encoder, &value.executor_key_id)?;
    encode_fixed(encoder, &value.executor_connector_registry_digest)?;
    encode_fixed(encoder, &value.expires_at)?;
    if let Some(binding) = value.task_binding {
        encode_fixed(encoder, &binding)?;
    }
    Ok(())
}

fn decode_dispatch_core(
    decoder: &mut minicbor::Decoder<'_>,
    context: &mut V2DecodeContext,
) -> Result<DispatchCoreV2, ProtocolError> {
    let length = decoder.array().map_err(ProtocolError::malformed)?;
    let schema = decoder.u16().map_err(ProtocolError::malformed)?;
    if !matches!((length, schema), (Some(14), 2) | (Some(15), 3)) {
        return Err(malformed());
    }
    let installation_id = decode_fixed(decoder, context)?;
    let active_state_manifest_digest = decode_fixed(decoder, context)?;
    let deployment_generation = decoder.u64().map_err(ProtocolError::malformed)?;
    let effect_fence_epoch = decoder.u64().map_err(ProtocolError::malformed)?;
    let durable_task_id = decode_fixed(decoder, context)?;
    let durable_run_id = decode_fixed(decoder, context)?;
    let execution_nonce = decode_fixed(decoder, context)?;
    let subject = decode_dispatch_subject(decoder, context)?;
    let claimed_subject_digest: Digest32V2 = decode_fixed(decoder, context)?;
    let executor_identity = decode_fixed(decoder, context)?;
    let executor_key_id = decode_fixed(decoder, context)?;
    let executor_connector_registry_digest = decode_fixed(decoder, context)?;
    let expires_at = decode_fixed(decoder, context)?;
    let mut value = DispatchCoreV2::new(
        installation_id,
        active_state_manifest_digest,
        deployment_generation,
        effect_fence_epoch,
        durable_task_id,
        durable_run_id,
        execution_nonce,
        subject,
        executor_identity,
        executor_key_id,
        executor_connector_registry_digest,
        expires_at,
    )?;
    if claimed_subject_digest != value.dispatch_subject_digest {
        return Err(malformed());
    }
    if schema == 3 {
        value = value.with_task_binding(decode_fixed(decoder, context)?);
    }
    Ok(value)
}

fn encode_sealed_execution_envelope_payload(
    value: &SealedExecutionEnvelopePayloadV2,
) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(6)
        .and_then(|encoder| encoder.u16(2))
        .map_err(ProtocolError::malformed)?;
    encode_dispatch_core(&mut encoder, value.core)?;
    encode_fixed(&mut encoder, &value.dispatch_core_digest)?;
    encode_fixed(&mut encoder, &value.declassification_provenance_digest)?;
    encode_fixed(&mut encoder, &value.hpke_enc)?;
    encode_fixed(&mut encoder, &value.hpke_ciphertext)?;
    Ok(encoder.into_writer())
}

fn decode_sealed_execution_envelope_payload(
    bytes: &[u8],
) -> Result<SealedExecutionEnvelopePayloadV2, ProtocolError> {
    scan_single(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    expect_array(&mut decoder, 6)?;
    if decoder.u16().map_err(ProtocolError::malformed)? != 2 {
        return Err(malformed());
    }
    let mut context = V2DecodeContext;
    let core = decode_dispatch_core(&mut decoder, &mut context)?;
    let claimed_core_digest: Digest32V2 = decode_fixed(&mut decoder, &mut context)?;
    let declassification_provenance_digest = decode_fixed(&mut decoder, &mut context)?;
    let hpke_enc = decode_fixed(&mut decoder, &mut context)?;
    let hpke_ciphertext = decode_fixed(&mut decoder, &mut context)?;
    let value = SealedExecutionEnvelopePayloadV2::new(
        core,
        declassification_provenance_digest,
        hpke_enc,
        hpke_ciphertext,
    )?;
    if claimed_core_digest != value.dispatch_core_digest
        || decoder.position() != bytes.len()
        || encode_sealed_execution_envelope_payload(&value)? != bytes
    {
        return Err(malformed());
    }
    Ok(value)
}

pub(super) fn encode_completion_descriptor(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    value: ExecutorCompletionDescriptorV2,
) -> Result<(), ProtocolError> {
    match value {
        ExecutorCompletionDescriptorV2::ToolResult {
            result_digest,
            encoded_length,
        } => {
            encoder
                .array(3)
                .and_then(|encoder| encoder.u16(1))
                .map_err(ProtocolError::malformed)?;
            encode_fixed(encoder, &result_digest)?;
            encoder
                .u32(encoded_length)
                .map_err(ProtocolError::malformed)?;
        }
        ExecutorCompletionDescriptorV2::FinalReleaseReceipt {
            durable_release_id,
            final_release_receipt_digest,
            release_audit_digest,
            encoded_length,
        } => {
            encoder
                .array(5)
                .and_then(|encoder| encoder.u16(2))
                .map_err(ProtocolError::malformed)?;
            encode_fixed(encoder, &durable_release_id)?;
            encode_fixed(encoder, &final_release_receipt_digest)?;
            encode_fixed(encoder, &release_audit_digest)?;
            encoder
                .u32(encoded_length)
                .map_err(ProtocolError::malformed)?;
        }
    }
    Ok(())
}

pub(super) fn decode_completion_descriptor(
    decoder: &mut minicbor::Decoder<'_>,
    context: &mut V2DecodeContext,
) -> Result<ExecutorCompletionDescriptorV2, ProtocolError> {
    let length = decoder
        .array()
        .map_err(ProtocolError::malformed)?
        .ok_or_else(malformed)?;
    let tag = decoder.u16().map_err(ProtocolError::malformed)?;
    match (tag, length) {
        (1, 3) => ExecutorCompletionDescriptorV2::tool_result(
            decode_fixed(decoder, context)?,
            decoder.u32().map_err(ProtocolError::malformed)?,
        ),
        (2, 5) => ExecutorCompletionDescriptorV2::final_release_receipt(
            decode_fixed(decoder, context)?,
            decode_fixed(decoder, context)?,
            decode_fixed(decoder, context)?,
            decoder.u32().map_err(ProtocolError::malformed)?,
        ),
        _ => Err(malformed()),
    }
}

fn encode_nonce_core_subject(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    nonce: Nonce32V2,
    core: Digest32V2,
    subject: Digest32V2,
) -> Result<(), ProtocolError> {
    encode_fixed(encoder, &nonce)?;
    encode_fixed(encoder, &core)?;
    encode_fixed(encoder, &subject)
}

fn decode_nonce_core_subject(
    decoder: &mut minicbor::Decoder<'_>,
    context: &mut V2DecodeContext,
) -> Result<(Nonce32V2, Digest32V2, Digest32V2), ProtocolError> {
    Ok((
        decode_fixed(decoder, context)?,
        decode_fixed(decoder, context)?,
        decode_fixed(decoder, context)?,
    ))
}

fn validate_nonce_core_subject(
    nonce: Nonce32V2,
    core: Digest32V2,
    subject: Digest32V2,
) -> Result<(), ProtocolError> {
    if is_zero(nonce.as_bytes()) || is_zero(core.as_bytes()) || is_zero(subject.as_bytes()) {
        return Err(malformed());
    }
    Ok(())
}

fn encode_header(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    tag: u16,
    fields: u64,
) -> Result<(), ProtocolError> {
    encoder
        .array(2)
        .and_then(|encoder| encoder.u16(tag))
        .and_then(|encoder| encoder.array(fields))
        .map_err(ProtocolError::malformed)?;
    Ok(())
}

fn encode_fixed<T: minicbor::Encode<()>>(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    value: &T,
) -> Result<(), ProtocolError> {
    minicbor::Encode::encode(value, encoder, &mut ()).map_err(ProtocolError::malformed)
}

fn decode_fixed<'bytes, T>(
    decoder: &mut minicbor::Decoder<'bytes>,
    context: &mut V2DecodeContext,
) -> Result<T, ProtocolError>
where
    T: minicbor::Decode<'bytes, V2DecodeContext>,
{
    minicbor::Decode::decode(decoder, context).map_err(ProtocolError::from_typed_decode)
}

fn encode_optional_fixed<T: minicbor::Encode<()>>(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    value: Option<T>,
) -> Result<(), ProtocolError> {
    match value {
        Some(value) => encode_fixed(encoder, &value),
        None => {
            encoder.null().map_err(ProtocolError::malformed)?;
            Ok(())
        }
    }
}

fn decode_optional_fixed<'bytes, T>(
    decoder: &mut minicbor::Decoder<'bytes>,
    context: &mut V2DecodeContext,
) -> Result<Option<T>, ProtocolError>
where
    T: minicbor::Decode<'bytes, V2DecodeContext>,
{
    if decoder.datatype().map_err(ProtocolError::malformed)? == minicbor::data::Type::Null {
        decoder.null().map_err(ProtocolError::malformed)?;
        Ok(None)
    } else {
        decode_fixed(decoder, context).map(Some)
    }
}

fn expect_array(decoder: &mut minicbor::Decoder<'_>, length: u64) -> Result<(), ProtocolError> {
    if decoder.array().map_err(ProtocolError::malformed)? != Some(length) {
        return Err(malformed());
    }
    Ok(())
}

fn domain_hash(domain: &[u8], canonical: &[u8]) -> Digest32V2 {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(canonical);
    Digest32V2::new(hasher.finalize().into())
}

fn sealed_execution_signature_input(canonical_payload: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(SEALED_EXECUTION_ENVELOPE_DOMAIN.len() + 32);
    input.extend_from_slice(SEALED_EXECUTION_ENVELOPE_DOMAIN);
    input.extend_from_slice(&Sha256::digest(canonical_payload));
    input
}

fn option_is_zero(value: Option<Digest32V2>) -> bool {
    value.is_some_and(|digest| is_zero(digest.as_bytes()))
}

fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

fn decode_error(position: usize) -> minicbor::decode::Error {
    minicbor::decode::Error::message(StableCode::ProtocolMalformedCbor.as_str()).at(position)
}

fn malformed() -> ProtocolError {
    ProtocolError::stable(StableCode::ProtocolMalformedCbor)
}
