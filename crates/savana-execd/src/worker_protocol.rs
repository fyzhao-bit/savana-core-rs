use ed25519_dalek::{
    Signature as Ed25519Signature, SigningKey, VerifyingKey as Ed25519VerifyingKey,
};
use savana_kernel_protocol::v2::{
    derive_ed25519_key_id_v2, Digest32V2, Ed25519KeyIdV2, Nonce32V2, UnixMillisV2,
};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

pub(crate) const MAX_CONNECTOR_DESCRIPTOR_BYTES: usize = 32 * 1024;
pub(crate) const MAX_CONNECTOR_FRAME_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const MAX_CONNECTOR_MATERIAL_BYTES: usize = 2 * 1024 * 1024;
pub(crate) const MAX_CONNECTOR_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

const DESCRIPTOR_DOMAIN: &[u8] = b"SAVANA_CONNECTOR_CODEC_JOB_DESCRIPTOR_V2\0";
const DESCRIPTOR_SIGNATURE_DOMAIN: &[u8] = b"SAVANA_CONNECTOR_CODEC_JOB_DESCRIPTOR_SIGNATURE_V2\0";
const PREPARED_SIGNATURE_DOMAIN: &[u8] = b"SAVANA_CONNECTOR_CODEC_PREPARED_REQUEST_SIGNATURE_V2\0";
const OUTCOME_SIGNATURE_DOMAIN: &[u8] = b"SAVANA_CONNECTOR_CODEC_OUTCOME_SIGNATURE_V2\0";
const REQUEST_DOMAIN: &[u8] = b"SAVANA_PREPARED_PROVIDER_REQUEST_V2\0";
const RESPONSE_DOMAIN: &[u8] = b"SAVANA_CONNECTOR_PROVIDER_RESPONSE_V2\0";
const RESULT_DOMAIN: &[u8] = b"SAVANA_CONNECTOR_CODEC_RESULT_V2\0";
const TRANSCRIPT_BEGIN_DOMAIN: &[u8] = b"SAVANA_CONNECTOR_CODEC_TRANSCRIPT_BEGIN_V2\0";
const TRANSCRIPT_STEP_DOMAIN: &[u8] = b"SAVANA_CONNECTOR_CODEC_TRANSCRIPT_STEP_V2\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ConnectorWorkerProtocolErrorV2 {
    #[error("connector worker frame is malformed or noncanonical")]
    NonCanonical,
    #[error("connector parent descriptor signature is invalid")]
    InvalidParentSignature,
    #[error("connector worker attestation signature is invalid")]
    InvalidWorkerSignature,
    #[error("connector worker binding does not match this job")]
    BindingMismatch,
    #[error("connector worker input or output exceeded a compiled bound")]
    Bounds,
    #[error("connector worker job expired")]
    Expired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConnectorCodecJobModeV2 {
    PrepareAndDecode,
    DecodeRetainedResponse,
}

impl ConnectorCodecJobModeV2 {
    const fn tag(self) -> u16 {
        match self {
            Self::PrepareAndDecode => 1,
            Self::DecodeRetainedResponse => 2,
        }
    }

    fn from_tag(tag: u16) -> Result<Self, ConnectorWorkerProtocolErrorV2> {
        match tag {
            1 => Ok(Self::PrepareAndDecode),
            2 => Ok(Self::DecodeRetainedResponse),
            _ => Err(ConnectorWorkerProtocolErrorV2::NonCanonical),
        }
    }
}

#[derive(Clone)]
pub(crate) struct VerifiedConnectorWorkerTrustV2 {
    installation_id: Digest32V2,
    active_state_manifest_digest: Digest32V2,
    deployment_generation: u64,
    effect_fence_epoch: u64,
    worker_artifact_digest: Digest32V2,
    no_network_sandbox_profile_digest: Digest32V2,
    credential_absence_profile_digest: Digest32V2,
    parent_key_id: Ed25519KeyIdV2,
    parent_verifying_key: Ed25519VerifyingKey,
}

impl std::fmt::Debug for VerifiedConnectorWorkerTrustV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifiedConnectorWorkerTrustV2")
            .field("deployment_generation", &self.deployment_generation)
            .field("effect_fence_epoch", &self.effect_fence_epoch)
            .finish_non_exhaustive()
    }
}

impl VerifiedConnectorWorkerTrustV2 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_verified_deployment(
        installation_id: Digest32V2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        effect_fence_epoch: u64,
        worker_artifact_digest: Digest32V2,
        no_network_sandbox_profile_digest: Digest32V2,
        credential_absence_profile_digest: Digest32V2,
        parent_key_id: Ed25519KeyIdV2,
        parent_public_key: [u8; 32],
    ) -> Result<Self, ConnectorWorkerProtocolErrorV2> {
        if [
            installation_id.as_bytes(),
            active_state_manifest_digest.as_bytes(),
            worker_artifact_digest.as_bytes(),
            no_network_sandbox_profile_digest.as_bytes(),
            credential_absence_profile_digest.as_bytes(),
            parent_key_id.as_bytes(),
        ]
        .iter()
        .any(|value| is_zero(*value))
            || deployment_generation == 0
            || effect_fence_epoch == 0
        {
            return Err(ConnectorWorkerProtocolErrorV2::BindingMismatch);
        }
        let parent_verifying_key = Ed25519VerifyingKey::from_bytes(&parent_public_key)
            .map_err(|_| ConnectorWorkerProtocolErrorV2::BindingMismatch)?;
        if derive_ed25519_key_id_v2(parent_public_key) != parent_key_id {
            return Err(ConnectorWorkerProtocolErrorV2::BindingMismatch);
        }
        Ok(Self {
            installation_id,
            active_state_manifest_digest,
            deployment_generation,
            effect_fence_epoch,
            worker_artifact_digest,
            no_network_sandbox_profile_digest,
            credential_absence_profile_digest,
            parent_key_id,
            parent_verifying_key,
        })
    }
}

pub(crate) struct ConnectorJobDescriptorIssuerV2 {
    trust: VerifiedConnectorWorkerTrustV2,
    parent_signing_key: SigningKey,
    credential_handle_identity_digest: Digest32V2,
}

impl std::fmt::Debug for ConnectorJobDescriptorIssuerV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConnectorJobDescriptorIssuerV2")
            .field("trust", &self.trust)
            .finish_non_exhaustive()
    }
}

impl ConnectorJobDescriptorIssuerV2 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_verified_deployment(
        installation_id: Digest32V2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        effect_fence_epoch: u64,
        worker_artifact_digest: Digest32V2,
        no_network_sandbox_profile_digest: Digest32V2,
        credential_absence_profile_digest: Digest32V2,
        credential_handle_identity_digest: Digest32V2,
        parent_signing_seed: Zeroizing<[u8; 32]>,
    ) -> Result<Self, ConnectorWorkerProtocolErrorV2> {
        if is_zero(credential_handle_identity_digest.as_bytes())
            || parent_signing_seed.as_ref() == [0; 32]
        {
            return Err(ConnectorWorkerProtocolErrorV2::BindingMismatch);
        }
        let parent_signing_key = SigningKey::from_bytes(&parent_signing_seed);
        let parent_public_key = parent_signing_key.verifying_key().to_bytes();
        let parent_key_id = derive_ed25519_key_id_v2(parent_public_key);
        let trust = VerifiedConnectorWorkerTrustV2::from_verified_deployment(
            installation_id,
            active_state_manifest_digest,
            deployment_generation,
            effect_fence_epoch,
            worker_artifact_digest,
            no_network_sandbox_profile_digest,
            credential_absence_profile_digest,
            parent_key_id,
            parent_public_key,
        )?;
        Ok(Self {
            trust,
            parent_signing_key,
            credential_handle_identity_digest,
        })
    }

    pub(crate) fn trust(&self) -> VerifiedConnectorWorkerTrustV2 {
        self.trust.clone()
    }

    pub(crate) fn issue_prepare(
        &self,
        execution_nonce: Nonce32V2,
        dispatch_core_digest: Digest32V2,
        dispatch_subject_digest: Digest32V2,
        bounded_material: &[u8],
        deadline: UnixMillisV2,
    ) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>), ConnectorWorkerProtocolErrorV2> {
        if [
            execution_nonce.as_bytes(),
            dispatch_core_digest.as_bytes(),
            dispatch_subject_digest.as_bytes(),
        ]
        .iter()
        .any(|value| is_zero(*value))
            || bounded_material.is_empty()
            || bounded_material.len() > MAX_CONNECTOR_MATERIAL_BYTES
            || deadline.get() == 0
        {
            return Err(ConnectorWorkerProtocolErrorV2::Bounds);
        }
        let worker_job_nonce = Nonce32V2::new(random_nonzero()?);
        let anonymous_channel_binding_digest = Digest32V2::new(random_nonzero()?);
        let ephemeral_seed = Zeroizing::new(random_nonzero()?);
        let ephemeral = SigningKey::from_bytes(&ephemeral_seed);
        let ephemeral_public_key = ephemeral.verifying_key().to_bytes();
        let payload = ConnectorJobPayloadV2 {
            installation_id: self.trust.installation_id,
            active_state_manifest_digest: self.trust.active_state_manifest_digest,
            deployment_generation: self.trust.deployment_generation,
            effect_fence_epoch: self.trust.effect_fence_epoch,
            execution_nonce,
            dispatch_core_digest,
            dispatch_subject_digest,
            worker_artifact_digest: self.trust.worker_artifact_digest,
            credential_handle_identity_digest: self.credential_handle_identity_digest,
            bounded_material_digest: connector_material_digest(bounded_material),
            no_network_sandbox_profile_digest: self.trust.no_network_sandbox_profile_digest,
            credential_absence_profile_digest: self.trust.credential_absence_profile_digest,
            mode: ConnectorCodecJobModeV2::PrepareAndDecode,
            external_attempt_ordinal: 1,
            codec_job_ordinal: 1,
            worker_job_nonce,
            anonymous_channel_binding_digest,
            ephemeral_attestation_public_key: ephemeral_public_key,
            ephemeral_attestation_key_id: derive_ed25519_key_id_v2(ephemeral_public_key),
            prepared_request_digest: None,
            retained_provider_response_digest: None,
            retained_provider_response_length: None,
            effect_started_receipt_digest: None,
            deadline,
        };
        let payload_bytes = encode_job_payload(payload)?;
        use ed25519_dalek::Signer as _;
        let signature = self
            .parent_signing_key
            .sign(&signature_input(
                DESCRIPTOR_SIGNATURE_DOMAIN,
                sha256(&payload_bytes),
            ))
            .to_bytes();
        let descriptor = encode_signed(
            &payload_bytes,
            derive_ed25519_key_id_v2(self.parent_signing_key.verifying_key().to_bytes()),
            &signature,
        )?;
        verify_connector_worker_job(
            &descriptor,
            &self.trust,
            UnixMillisV2::new(deadline.get() - 1),
        )?;
        Ok((descriptor, ephemeral_seed))
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn issue_decode_retained(
        &self,
        execution_nonce: Nonce32V2,
        dispatch_core_digest: Digest32V2,
        dispatch_subject_digest: Digest32V2,
        prepared_request_digest: Digest32V2,
        retained_provider_response: &[u8],
        effect_started_receipt_digest: Digest32V2,
        deadline: UnixMillisV2,
    ) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>), ConnectorWorkerProtocolErrorV2> {
        if [
            execution_nonce.as_bytes(),
            dispatch_core_digest.as_bytes(),
            dispatch_subject_digest.as_bytes(),
            prepared_request_digest.as_bytes(),
            effect_started_receipt_digest.as_bytes(),
        ]
        .iter()
        .any(|value| is_zero(*value))
            || retained_provider_response.is_empty()
            || retained_provider_response.len() > MAX_CONNECTOR_RESPONSE_BYTES
            || deadline.get() == 0
        {
            return Err(ConnectorWorkerProtocolErrorV2::Bounds);
        }
        let worker_job_nonce = Nonce32V2::new(random_nonzero()?);
        let anonymous_channel_binding_digest = Digest32V2::new(random_nonzero()?);
        let ephemeral_seed = Zeroizing::new(random_nonzero()?);
        let ephemeral = SigningKey::from_bytes(&ephemeral_seed);
        let ephemeral_public_key = ephemeral.verifying_key().to_bytes();
        let payload = ConnectorJobPayloadV2 {
            installation_id: self.trust.installation_id,
            active_state_manifest_digest: self.trust.active_state_manifest_digest,
            deployment_generation: self.trust.deployment_generation,
            effect_fence_epoch: self.trust.effect_fence_epoch,
            execution_nonce,
            dispatch_core_digest,
            dispatch_subject_digest,
            worker_artifact_digest: self.trust.worker_artifact_digest,
            credential_handle_identity_digest: self.credential_handle_identity_digest,
            bounded_material_digest: connector_material_digest(retained_provider_response),
            no_network_sandbox_profile_digest: self.trust.no_network_sandbox_profile_digest,
            credential_absence_profile_digest: self.trust.credential_absence_profile_digest,
            mode: ConnectorCodecJobModeV2::DecodeRetainedResponse,
            external_attempt_ordinal: 1,
            codec_job_ordinal: 2,
            worker_job_nonce,
            anonymous_channel_binding_digest,
            ephemeral_attestation_public_key: ephemeral_public_key,
            ephemeral_attestation_key_id: derive_ed25519_key_id_v2(ephemeral_public_key),
            prepared_request_digest: Some(prepared_request_digest),
            retained_provider_response_digest: Some(connector_response_digest(
                retained_provider_response,
            )),
            retained_provider_response_length: Some(
                u32::try_from(retained_provider_response.len())
                    .map_err(|_| ConnectorWorkerProtocolErrorV2::Bounds)?,
            ),
            effect_started_receipt_digest: Some(effect_started_receipt_digest),
            deadline,
        };
        let payload_bytes = encode_job_payload(payload)?;
        use ed25519_dalek::Signer as _;
        let signature = self
            .parent_signing_key
            .sign(&signature_input(
                DESCRIPTOR_SIGNATURE_DOMAIN,
                sha256(&payload_bytes),
            ))
            .to_bytes();
        let descriptor = encode_signed(
            &payload_bytes,
            derive_ed25519_key_id_v2(self.parent_signing_key.verifying_key().to_bytes()),
            &signature,
        )?;
        verify_connector_worker_job(
            &descriptor,
            &self.trust,
            UnixMillisV2::new(deadline.get() - 1),
        )?;
        Ok((descriptor, ephemeral_seed))
    }
}

#[derive(Debug, Clone, Copy)]
struct ConnectorJobPayloadV2 {
    installation_id: Digest32V2,
    active_state_manifest_digest: Digest32V2,
    deployment_generation: u64,
    effect_fence_epoch: u64,
    execution_nonce: Nonce32V2,
    dispatch_core_digest: Digest32V2,
    dispatch_subject_digest: Digest32V2,
    worker_artifact_digest: Digest32V2,
    credential_handle_identity_digest: Digest32V2,
    bounded_material_digest: Digest32V2,
    no_network_sandbox_profile_digest: Digest32V2,
    credential_absence_profile_digest: Digest32V2,
    mode: ConnectorCodecJobModeV2,
    external_attempt_ordinal: u16,
    codec_job_ordinal: u16,
    worker_job_nonce: Nonce32V2,
    anonymous_channel_binding_digest: Digest32V2,
    ephemeral_attestation_public_key: [u8; 32],
    ephemeral_attestation_key_id: Ed25519KeyIdV2,
    prepared_request_digest: Option<Digest32V2>,
    retained_provider_response_digest: Option<Digest32V2>,
    retained_provider_response_length: Option<u32>,
    effect_started_receipt_digest: Option<Digest32V2>,
    deadline: UnixMillisV2,
}

pub(crate) struct VerifiedConnectorWorkerJobV2 {
    canonical_descriptor: Vec<u8>,
    descriptor_digest: Digest32V2,
    execution_nonce: Nonce32V2,
    dispatch_core_digest: Digest32V2,
    dispatch_subject_digest: Digest32V2,
    worker_artifact_digest: Digest32V2,
    bounded_material_digest: Digest32V2,
    mode: ConnectorCodecJobModeV2,
    external_attempt_ordinal: u16,
    codec_job_ordinal: u16,
    worker_job_nonce: Nonce32V2,
    ephemeral_attestation_key_id: Ed25519KeyIdV2,
    ephemeral_attestation_verifying_key: Ed25519VerifyingKey,
    parent_key_id: Ed25519KeyIdV2,
    parent_public_key: [u8; 32],
    retained_provider_response_digest: Option<Digest32V2>,
    retained_provider_response_length: Option<u32>,
    effect_started_receipt_digest: Option<Digest32V2>,
    deadline: UnixMillisV2,
}

impl std::fmt::Debug for VerifiedConnectorWorkerJobV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifiedConnectorWorkerJobV2")
            .field("descriptor_digest", &self.descriptor_digest)
            .field("execution_nonce", &self.execution_nonce)
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}

impl VerifiedConnectorWorkerJobV2 {
    pub(crate) fn canonical_descriptor(&self) -> &[u8] {
        &self.canonical_descriptor
    }

    pub(crate) const fn descriptor_digest(&self) -> Digest32V2 {
        self.descriptor_digest
    }

    pub(crate) const fn execution_nonce(&self) -> Nonce32V2 {
        self.execution_nonce
    }

    pub(crate) const fn dispatch_core_digest(&self) -> Digest32V2 {
        self.dispatch_core_digest
    }

    pub(crate) const fn dispatch_subject_digest(&self) -> Digest32V2 {
        self.dispatch_subject_digest
    }

    pub(crate) const fn mode(&self) -> ConnectorCodecJobModeV2 {
        self.mode
    }

    pub(crate) const fn bounded_material_digest(&self) -> Digest32V2 {
        self.bounded_material_digest
    }

    pub(crate) const fn worker_job_nonce(&self) -> Nonce32V2 {
        self.worker_job_nonce
    }

    pub(crate) const fn retained_provider_response_digest(&self) -> Option<Digest32V2> {
        self.retained_provider_response_digest
    }

    pub(crate) const fn retained_provider_response_length(&self) -> Option<u32> {
        self.retained_provider_response_length
    }

    pub(crate) const fn effect_started_receipt_digest(&self) -> Option<Digest32V2> {
        self.effect_started_receipt_digest
    }

    pub(crate) const fn deadline(&self) -> UnixMillisV2 {
        self.deadline
    }

    pub(crate) const fn worker_artifact_digest(&self) -> Digest32V2 {
        self.worker_artifact_digest
    }

    pub(crate) fn ephemeral_seed_matches(&self, seed: &[u8; 32]) -> bool {
        SigningKey::from_bytes(seed).verifying_key() == self.ephemeral_attestation_verifying_key
    }

    pub(crate) const fn parent_key_id(&self) -> Ed25519KeyIdV2 {
        self.parent_key_id
    }

    pub(crate) const fn parent_public_key(&self) -> [u8; 32] {
        self.parent_public_key
    }

    pub(crate) const fn ephemeral_attestation_key_id(&self) -> Ed25519KeyIdV2 {
        self.ephemeral_attestation_key_id
    }

    pub(crate) const fn external_attempt_ordinal(&self) -> u16 {
        self.external_attempt_ordinal
    }

    pub(crate) const fn codec_job_ordinal(&self) -> u16 {
        self.codec_job_ordinal
    }
}

#[derive(Debug)]
pub(crate) struct PreparedProviderRequestFrameV2 {
    credential_free_request: Zeroizing<Vec<u8>>,
    credential_free_request_digest: Digest32V2,
    maximum_response_bytes: u32,
    transcript_digest: Digest32V2,
    canonical_payload: Vec<u8>,
    transcript_material: Vec<u8>,
}

impl PreparedProviderRequestFrameV2 {
    pub(crate) fn request(&self) -> &[u8] {
        &self.credential_free_request
    }

    pub(crate) const fn request_digest(&self) -> Digest32V2 {
        self.credential_free_request_digest
    }

    pub(crate) const fn maximum_response_bytes(&self) -> u32 {
        self.maximum_response_bytes
    }

    pub(crate) const fn transcript_digest(&self) -> Digest32V2 {
        self.transcript_digest
    }

    pub(crate) fn canonical_payload(&self) -> &[u8] {
        &self.canonical_payload
    }

    pub(crate) fn transcript_material(&self) -> &[u8] {
        &self.transcript_material
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConnectorOutcomeKindV2 {
    FailedBeforeEffect,
    Completion,
    Indeterminate,
}

#[derive(Debug)]
pub(crate) struct ConnectorOutcomeFrameV2 {
    kind: ConnectorOutcomeKindV2,
    provider_response_digest: Option<Digest32V2>,
    result: Option<Zeroizing<Vec<u8>>>,
    result_digest: Option<Digest32V2>,
    transcript_digest: Digest32V2,
    canonical_payload: Vec<u8>,
    transcript_material: Vec<u8>,
}

impl ConnectorOutcomeFrameV2 {
    pub(crate) const fn kind(&self) -> ConnectorOutcomeKindV2 {
        self.kind
    }

    pub(crate) const fn provider_response_digest(&self) -> Option<Digest32V2> {
        self.provider_response_digest
    }

    pub(crate) fn result(&self) -> Option<&[u8]> {
        self.result.as_ref().map(|value| value.as_slice())
    }

    pub(crate) const fn result_digest(&self) -> Option<Digest32V2> {
        self.result_digest
    }

    pub(crate) const fn transcript_digest(&self) -> Digest32V2 {
        self.transcript_digest
    }

    pub(crate) fn canonical_payload(&self) -> &[u8] {
        &self.canonical_payload
    }

    pub(crate) fn transcript_material(&self) -> &[u8] {
        &self.transcript_material
    }
}

#[derive(Debug)]
pub(crate) enum ConnectorWorkerFrameV2 {
    Prepared(PreparedProviderRequestFrameV2),
    Outcome(ConnectorOutcomeFrameV2),
}

pub(crate) fn verify_connector_worker_job(
    canonical_descriptor: &[u8],
    trust: &VerifiedConnectorWorkerTrustV2,
    now: UnixMillisV2,
) -> Result<VerifiedConnectorWorkerJobV2, ConnectorWorkerProtocolErrorV2> {
    if canonical_descriptor.is_empty()
        || canonical_descriptor.len() > MAX_CONNECTOR_DESCRIPTOR_BYTES
    {
        return Err(ConnectorWorkerProtocolErrorV2::Bounds);
    }
    let mut decoder = minicbor::Decoder::new(canonical_descriptor);
    require_array(&mut decoder, 3)?;
    let payload_bytes = decoder
        .bytes()
        .map_err(|_| ConnectorWorkerProtocolErrorV2::NonCanonical)?
        .to_vec();
    let key_id = Ed25519KeyIdV2::new(decode_fixed::<32>(&mut decoder)?);
    let signature = decode_fixed::<64>(&mut decoder)?;
    if decoder.position() != canonical_descriptor.len()
        || encode_signed(&payload_bytes, key_id, &signature)? != canonical_descriptor
        || key_id != trust.parent_key_id
    {
        return Err(ConnectorWorkerProtocolErrorV2::NonCanonical);
    }
    let payload = decode_job_payload(&payload_bytes)?;
    if encode_job_payload(payload)? != payload_bytes {
        return Err(ConnectorWorkerProtocolErrorV2::NonCanonical);
    }
    trust
        .parent_verifying_key
        .verify_strict(
            &signature_input(DESCRIPTOR_SIGNATURE_DOMAIN, sha256(&payload_bytes)),
            &Ed25519Signature::from_bytes(&signature),
        )
        .map_err(|_| ConnectorWorkerProtocolErrorV2::InvalidParentSignature)?;
    if payload.installation_id != trust.installation_id
        || payload.active_state_manifest_digest != trust.active_state_manifest_digest
        || payload.deployment_generation != trust.deployment_generation
        || payload.effect_fence_epoch != trust.effect_fence_epoch
        || payload.worker_artifact_digest != trust.worker_artifact_digest
        || payload.no_network_sandbox_profile_digest != trust.no_network_sandbox_profile_digest
        || payload.credential_absence_profile_digest != trust.credential_absence_profile_digest
        || [
            payload.execution_nonce.as_bytes(),
            payload.dispatch_core_digest.as_bytes(),
            payload.dispatch_subject_digest.as_bytes(),
            payload.credential_handle_identity_digest.as_bytes(),
            payload.bounded_material_digest.as_bytes(),
            payload.worker_job_nonce.as_bytes(),
            payload.anonymous_channel_binding_digest.as_bytes(),
            payload.ephemeral_attestation_key_id.as_bytes(),
        ]
        .iter()
        .any(|value| is_zero(*value))
        || payload.external_attempt_ordinal == 0
        || payload.codec_job_ordinal == 0
        || derive_ed25519_key_id_v2(payload.ephemeral_attestation_public_key)
            != payload.ephemeral_attestation_key_id
    {
        return Err(ConnectorWorkerProtocolErrorV2::BindingMismatch);
    }
    if now.get() == 0 || now.get() >= payload.deadline.get() {
        return Err(ConnectorWorkerProtocolErrorV2::Expired);
    }
    let mode_options_valid = match payload.mode {
        ConnectorCodecJobModeV2::PrepareAndDecode => {
            payload.prepared_request_digest.is_none()
                && payload.retained_provider_response_digest.is_none()
                && payload.retained_provider_response_length.is_none()
                && payload.effect_started_receipt_digest.is_none()
        }
        ConnectorCodecJobModeV2::DecodeRetainedResponse => {
            payload.prepared_request_digest.is_some()
                && payload.retained_provider_response_digest.is_some()
                && payload
                    .retained_provider_response_length
                    .is_some_and(|length| {
                        length > 0 && length as usize <= MAX_CONNECTOR_RESPONSE_BYTES
                    })
                && payload.effect_started_receipt_digest.is_some()
        }
    };
    if !mode_options_valid {
        return Err(ConnectorWorkerProtocolErrorV2::BindingMismatch);
    }
    let ephemeral_attestation_verifying_key =
        Ed25519VerifyingKey::from_bytes(&payload.ephemeral_attestation_public_key)
            .map_err(|_| ConnectorWorkerProtocolErrorV2::BindingMismatch)?;
    Ok(VerifiedConnectorWorkerJobV2 {
        canonical_descriptor: canonical_descriptor.to_vec(),
        descriptor_digest: domain_hash(DESCRIPTOR_DOMAIN, &payload_bytes),
        execution_nonce: payload.execution_nonce,
        dispatch_core_digest: payload.dispatch_core_digest,
        dispatch_subject_digest: payload.dispatch_subject_digest,
        worker_artifact_digest: payload.worker_artifact_digest,
        bounded_material_digest: payload.bounded_material_digest,
        mode: payload.mode,
        external_attempt_ordinal: payload.external_attempt_ordinal,
        codec_job_ordinal: payload.codec_job_ordinal,
        worker_job_nonce: payload.worker_job_nonce,
        ephemeral_attestation_key_id: payload.ephemeral_attestation_key_id,
        ephemeral_attestation_verifying_key,
        parent_key_id: trust.parent_key_id,
        parent_public_key: trust.parent_verifying_key.to_bytes(),
        retained_provider_response_digest: payload.retained_provider_response_digest,
        retained_provider_response_length: payload.retained_provider_response_length,
        effect_started_receipt_digest: payload.effect_started_receipt_digest,
        deadline: payload.deadline,
    })
}

fn random_nonzero<const N: usize>() -> Result<[u8; N], ConnectorWorkerProtocolErrorV2> {
    for _ in 0..4 {
        let mut value = [0_u8; N];
        getrandom::getrandom(&mut value).map_err(|_| ConnectorWorkerProtocolErrorV2::Bounds)?;
        if !is_zero(&value) {
            return Ok(value);
        }
    }
    Err(ConnectorWorkerProtocolErrorV2::Bounds)
}

pub(crate) fn verify_connector_worker_child_job(
    canonical_descriptor: &[u8],
    parent_public_key: [u8; 32],
    ephemeral_signing_seed: &[u8; 32],
    now: UnixMillisV2,
) -> Result<VerifiedConnectorWorkerJobV2, ConnectorWorkerProtocolErrorV2> {
    let mut decoder = minicbor::Decoder::new(canonical_descriptor);
    require_array(&mut decoder, 3)?;
    let payload_bytes = decoder
        .bytes()
        .map_err(|_| ConnectorWorkerProtocolErrorV2::NonCanonical)?;
    let parent_key_id = Ed25519KeyIdV2::new(decode_fixed::<32>(&mut decoder)?);
    let _signature = decode_fixed::<64>(&mut decoder)?;
    if decoder.position() != canonical_descriptor.len() {
        return Err(ConnectorWorkerProtocolErrorV2::NonCanonical);
    }
    let payload = decode_job_payload(payload_bytes)?;
    let trust = VerifiedConnectorWorkerTrustV2::from_verified_deployment(
        payload.installation_id,
        payload.active_state_manifest_digest,
        payload.deployment_generation,
        payload.effect_fence_epoch,
        payload.worker_artifact_digest,
        payload.no_network_sandbox_profile_digest,
        payload.credential_absence_profile_digest,
        parent_key_id,
        parent_public_key,
    )?;
    let job = verify_connector_worker_job(canonical_descriptor, &trust, now)?;
    if !job.ephemeral_seed_matches(ephemeral_signing_seed) {
        return Err(ConnectorWorkerProtocolErrorV2::BindingMismatch);
    }
    Ok(job)
}

pub(crate) fn decode_connector_worker_frame(
    bytes: &[u8],
    job: &VerifiedConnectorWorkerJobV2,
) -> Result<ConnectorWorkerFrameV2, ConnectorWorkerProtocolErrorV2> {
    if bytes.is_empty() || bytes.len() > MAX_CONNECTOR_FRAME_BYTES {
        return Err(ConnectorWorkerProtocolErrorV2::Bounds);
    }
    let mut decoder = minicbor::Decoder::new(bytes);
    require_array(&mut decoder, 4)?;
    let tag = decoder
        .u16()
        .map_err(|_| ConnectorWorkerProtocolErrorV2::NonCanonical)?;
    let payload_bytes = decoder
        .bytes()
        .map_err(|_| ConnectorWorkerProtocolErrorV2::NonCanonical)?
        .to_vec();
    let key_id = Ed25519KeyIdV2::new(decode_fixed::<32>(&mut decoder)?);
    let signature = decode_fixed::<64>(&mut decoder)?;
    if decoder.position() != bytes.len()
        || key_id != job.ephemeral_attestation_key_id
        || encode_worker_frame(tag, &payload_bytes, key_id, &signature)? != bytes
    {
        return Err(ConnectorWorkerProtocolErrorV2::NonCanonical);
    }
    let domain = match tag {
        1 => PREPARED_SIGNATURE_DOMAIN,
        3 => OUTCOME_SIGNATURE_DOMAIN,
        _ => return Err(ConnectorWorkerProtocolErrorV2::NonCanonical),
    };
    job.ephemeral_attestation_verifying_key
        .verify_strict(
            &signature_input(domain, sha256(&payload_bytes)),
            &Ed25519Signature::from_bytes(&signature),
        )
        .map_err(|_| ConnectorWorkerProtocolErrorV2::InvalidWorkerSignature)?;
    match tag {
        1 => decode_prepared_payload(&payload_bytes, job).map(ConnectorWorkerFrameV2::Prepared),
        3 => decode_outcome_payload(&payload_bytes, job).map(ConnectorWorkerFrameV2::Outcome),
        _ => Err(ConnectorWorkerProtocolErrorV2::NonCanonical),
    }
}

pub(crate) fn connector_material_digest(bytes: &[u8]) -> Digest32V2 {
    domain_hash(b"SAVANA_CONNECTOR_CODEC_MATERIAL_V2\0", bytes)
}

pub(crate) fn prepared_provider_request_digest(bytes: &[u8]) -> Digest32V2 {
    domain_hash(REQUEST_DOMAIN, bytes)
}

pub(crate) fn connector_response_digest(bytes: &[u8]) -> Digest32V2 {
    domain_hash(RESPONSE_DOMAIN, bytes)
}

pub(crate) fn connector_result_digest(bytes: &[u8]) -> Digest32V2 {
    domain_hash(RESULT_DOMAIN, bytes)
}

pub(crate) fn encode_provider_response_frame(
    job: &VerifiedConnectorWorkerJobV2,
    response: &[u8],
    effect_started_receipt_digest: Digest32V2,
) -> Result<Vec<u8>, ConnectorWorkerProtocolErrorV2> {
    if response.is_empty()
        || response.len() > MAX_CONNECTOR_RESPONSE_BYTES
        || is_zero(effect_started_receipt_digest.as_bytes())
    {
        return Err(ConnectorWorkerProtocolErrorV2::Bounds);
    }
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(5)
        .and_then(|encoder| encoder.u16(2))
        .and_then(|encoder| encoder.bytes(job.worker_job_nonce.as_bytes()))
        .and_then(|encoder| encoder.bytes(response))
        .and_then(|encoder| encoder.bytes(connector_response_digest(response).as_bytes()))
        .and_then(|encoder| encoder.bytes(effect_started_receipt_digest.as_bytes()))
        .map_err(|_| ConnectorWorkerProtocolErrorV2::Bounds)?;
    Ok(encoder.into_writer())
}

pub(crate) fn decode_provider_response_frame(
    bytes: &[u8],
    job: &VerifiedConnectorWorkerJobV2,
) -> Result<(Zeroizing<Vec<u8>>, Digest32V2), ConnectorWorkerProtocolErrorV2> {
    if bytes.is_empty() || bytes.len() > MAX_CONNECTOR_FRAME_BYTES {
        return Err(ConnectorWorkerProtocolErrorV2::Bounds);
    }
    let mut decoder = minicbor::Decoder::new(bytes);
    require_array(&mut decoder, 5)?;
    if decoder
        .u16()
        .map_err(|_| ConnectorWorkerProtocolErrorV2::NonCanonical)?
        != 2
    {
        return Err(ConnectorWorkerProtocolErrorV2::NonCanonical);
    }
    let worker_job_nonce = Nonce32V2::new(decode_fixed::<32>(&mut decoder)?);
    let response = decoder
        .bytes()
        .map_err(|_| ConnectorWorkerProtocolErrorV2::NonCanonical)?;
    let response_digest = Digest32V2::new(decode_fixed::<32>(&mut decoder)?);
    let effect_started_receipt_digest = Digest32V2::new(decode_fixed::<32>(&mut decoder)?);
    if decoder.position() != bytes.len()
        || encode_provider_response_frame(job, response, effect_started_receipt_digest)? != bytes
        || worker_job_nonce != job.worker_job_nonce
        || response_digest != connector_response_digest(response)
    {
        return Err(ConnectorWorkerProtocolErrorV2::BindingMismatch);
    }
    Ok((
        Zeroizing::new(response.to_vec()),
        effect_started_receipt_digest,
    ))
}

pub(crate) fn connector_transcript_begin(job: &VerifiedConnectorWorkerJobV2) -> Digest32V2 {
    let mut hasher = Sha256::new();
    hasher.update(TRANSCRIPT_BEGIN_DOMAIN);
    hasher.update(job.descriptor_digest().as_bytes());
    Digest32V2::new(hasher.finalize().into())
}

pub(crate) fn connector_transcript_step(
    previous: Digest32V2,
    direction_tag: u16,
    frame_tag: u16,
    ordinal: u32,
    canonical_frame_without_attestation: &[u8],
) -> Digest32V2 {
    let mut hasher = Sha256::new();
    hasher.update(TRANSCRIPT_STEP_DOMAIN);
    hasher.update(previous.as_bytes());
    hasher.update(direction_tag.to_be_bytes());
    hasher.update(frame_tag.to_be_bytes());
    hasher.update(ordinal.to_be_bytes());
    hasher.update(Sha256::digest(canonical_frame_without_attestation));
    Digest32V2::new(hasher.finalize().into())
}

pub(crate) fn prepared_transcript_material(
    job: &VerifiedConnectorWorkerJobV2,
    request: &[u8],
    maximum_response_bytes: u32,
) -> Result<Vec<u8>, ConnectorWorkerProtocolErrorV2> {
    encode_prepared_transcript_material(
        job,
        request,
        prepared_provider_request_digest(request),
        maximum_response_bytes,
    )
}

pub(crate) fn outcome_transcript_material(
    job: &VerifiedConnectorWorkerJobV2,
    kind: ConnectorOutcomeKindV2,
    response_digest: Option<Digest32V2>,
    result: Option<&[u8]>,
) -> Result<Vec<u8>, ConnectorWorkerProtocolErrorV2> {
    encode_outcome_transcript_material(
        job,
        kind,
        response_digest,
        result,
        result.map(connector_result_digest),
    )
}

pub(crate) fn encode_connector_prepared_frame(
    job: &VerifiedConnectorWorkerJobV2,
    signing_key: &SigningKey,
    request: &[u8],
    maximum_response_bytes: u32,
    transcript_digest: Digest32V2,
) -> Result<Vec<u8>, ConnectorWorkerProtocolErrorV2> {
    use ed25519_dalek::Signer as _;

    if job.mode != ConnectorCodecJobModeV2::PrepareAndDecode
        || !job.ephemeral_seed_matches(&signing_key.to_bytes())
        || request.is_empty()
        || request.len() > MAX_CONNECTOR_MATERIAL_BYTES
        || maximum_response_bytes == 0
        || maximum_response_bytes as usize > MAX_CONNECTOR_RESPONSE_BYTES
    {
        return Err(ConnectorWorkerProtocolErrorV2::BindingMismatch);
    }
    let payload = encode_prepared_payload(
        job,
        request,
        prepared_provider_request_digest(request),
        maximum_response_bytes,
        transcript_digest,
    )?;
    let signature = signing_key
        .sign(&signature_input(
            PREPARED_SIGNATURE_DOMAIN,
            sha256(&payload),
        ))
        .to_bytes();
    encode_worker_frame(1, &payload, job.ephemeral_attestation_key_id, &signature)
}

pub(crate) fn encode_connector_outcome_frame(
    job: &VerifiedConnectorWorkerJobV2,
    signing_key: &SigningKey,
    kind: ConnectorOutcomeKindV2,
    response_digest: Option<Digest32V2>,
    result: Option<&[u8]>,
    transcript_digest: Digest32V2,
) -> Result<Vec<u8>, ConnectorWorkerProtocolErrorV2> {
    use ed25519_dalek::Signer as _;

    if !job.ephemeral_seed_matches(&signing_key.to_bytes()) {
        return Err(ConnectorWorkerProtocolErrorV2::BindingMismatch);
    }
    let result_digest = result.map(connector_result_digest);
    match kind {
        ConnectorOutcomeKindV2::FailedBeforeEffect
            if job.mode == ConnectorCodecJobModeV2::PrepareAndDecode
                && response_digest.is_none()
                && result.is_none() => {}
        ConnectorOutcomeKindV2::Completion
            if response_digest.is_some()
                && result.is_some_and(|bytes| {
                    !bytes.is_empty() && bytes.len() <= MAX_CONNECTOR_RESPONSE_BYTES
                }) => {}
        ConnectorOutcomeKindV2::Indeterminate if response_digest.is_some() && result.is_none() => {}
        _ => return Err(ConnectorWorkerProtocolErrorV2::BindingMismatch),
    }
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(8)
        .and_then(|encoder| encoder.u16(2))
        .and_then(|encoder| encoder.bytes(job.worker_job_nonce.as_bytes()))
        .and_then(|encoder| encoder.bytes(job.execution_nonce.as_bytes()))
        .and_then(|encoder| {
            encoder.u16(match kind {
                ConnectorOutcomeKindV2::FailedBeforeEffect => 1,
                ConnectorOutcomeKindV2::Completion => 2,
                ConnectorOutcomeKindV2::Indeterminate => 3,
            })
        })
        .map_err(|_| ConnectorWorkerProtocolErrorV2::Bounds)?;
    encode_optional_digest(&mut encoder, response_digest)?;
    match result {
        Some(value) => {
            encoder
                .bytes(value)
                .map_err(|_| ConnectorWorkerProtocolErrorV2::Bounds)?;
        }
        None => {
            encoder
                .null()
                .map_err(|_| ConnectorWorkerProtocolErrorV2::Bounds)?;
        }
    }
    encode_optional_digest(&mut encoder, result_digest)?;
    encoder
        .bytes(transcript_digest.as_bytes())
        .map_err(|_| ConnectorWorkerProtocolErrorV2::Bounds)?;
    let payload = encoder.into_writer();
    let signature = signing_key
        .sign(&signature_input(OUTCOME_SIGNATURE_DOMAIN, sha256(&payload)))
        .to_bytes();
    encode_worker_frame(3, &payload, job.ephemeral_attestation_key_id, &signature)
}

fn decode_prepared_payload(
    bytes: &[u8],
    job: &VerifiedConnectorWorkerJobV2,
) -> Result<PreparedProviderRequestFrameV2, ConnectorWorkerProtocolErrorV2> {
    let mut decoder = minicbor::Decoder::new(bytes);
    require_array(&mut decoder, 9)?;
    if decoder
        .u16()
        .map_err(|_| ConnectorWorkerProtocolErrorV2::NonCanonical)?
        != 2
    {
        return Err(ConnectorWorkerProtocolErrorV2::NonCanonical);
    }
    let worker_job_nonce = Nonce32V2::new(decode_fixed::<32>(&mut decoder)?);
    let execution_nonce = Nonce32V2::new(decode_fixed::<32>(&mut decoder)?);
    let external_attempt_ordinal = decoder
        .u16()
        .map_err(|_| ConnectorWorkerProtocolErrorV2::NonCanonical)?;
    let codec_job_ordinal = decoder
        .u16()
        .map_err(|_| ConnectorWorkerProtocolErrorV2::NonCanonical)?;
    let request = decoder
        .bytes()
        .map_err(|_| ConnectorWorkerProtocolErrorV2::NonCanonical)?;
    let request_digest = Digest32V2::new(decode_fixed::<32>(&mut decoder)?);
    let maximum_response_bytes = decoder
        .u32()
        .map_err(|_| ConnectorWorkerProtocolErrorV2::NonCanonical)?;
    let transcript_digest = Digest32V2::new(decode_fixed::<32>(&mut decoder)?);
    if decoder.position() != bytes.len()
        || encode_prepared_payload(
            job,
            request,
            request_digest,
            maximum_response_bytes,
            transcript_digest,
        )? != bytes
        || job.mode != ConnectorCodecJobModeV2::PrepareAndDecode
        || worker_job_nonce != job.worker_job_nonce
        || execution_nonce != job.execution_nonce
        || external_attempt_ordinal != job.external_attempt_ordinal
        || codec_job_ordinal != job.codec_job_ordinal
        || request.is_empty()
        || request.len() > MAX_CONNECTOR_MATERIAL_BYTES
        || request_digest != prepared_provider_request_digest(request)
        || maximum_response_bytes == 0
        || maximum_response_bytes as usize > MAX_CONNECTOR_RESPONSE_BYTES
    {
        return Err(ConnectorWorkerProtocolErrorV2::BindingMismatch);
    }
    Ok(PreparedProviderRequestFrameV2 {
        credential_free_request: Zeroizing::new(request.to_vec()),
        credential_free_request_digest: request_digest,
        maximum_response_bytes,
        transcript_digest,
        canonical_payload: bytes.to_vec(),
        transcript_material: encode_prepared_transcript_material(
            job,
            request,
            request_digest,
            maximum_response_bytes,
        )?,
    })
}

fn decode_outcome_payload(
    bytes: &[u8],
    job: &VerifiedConnectorWorkerJobV2,
) -> Result<ConnectorOutcomeFrameV2, ConnectorWorkerProtocolErrorV2> {
    let mut decoder = minicbor::Decoder::new(bytes);
    require_array(&mut decoder, 8)?;
    if decoder
        .u16()
        .map_err(|_| ConnectorWorkerProtocolErrorV2::NonCanonical)?
        != 2
    {
        return Err(ConnectorWorkerProtocolErrorV2::NonCanonical);
    }
    let worker_job_nonce = Nonce32V2::new(decode_fixed::<32>(&mut decoder)?);
    let execution_nonce = Nonce32V2::new(decode_fixed::<32>(&mut decoder)?);
    let kind = match decoder
        .u16()
        .map_err(|_| ConnectorWorkerProtocolErrorV2::NonCanonical)?
    {
        1 => ConnectorOutcomeKindV2::FailedBeforeEffect,
        2 => ConnectorOutcomeKindV2::Completion,
        3 => ConnectorOutcomeKindV2::Indeterminate,
        _ => return Err(ConnectorWorkerProtocolErrorV2::NonCanonical),
    };
    let response_digest = decode_optional_digest(&mut decoder)?;
    let result = decode_optional_bytes(&mut decoder)?;
    let result_digest = decode_optional_digest(&mut decoder)?;
    let transcript_digest = Digest32V2::new(decode_fixed::<32>(&mut decoder)?);
    if decoder.position() != bytes.len()
        || worker_job_nonce != job.worker_job_nonce
        || execution_nonce != job.execution_nonce
    {
        return Err(ConnectorWorkerProtocolErrorV2::BindingMismatch);
    }
    match kind {
        ConnectorOutcomeKindV2::FailedBeforeEffect => {
            if job.mode != ConnectorCodecJobModeV2::PrepareAndDecode
                || response_digest.is_some()
                || result.is_some()
                || result_digest.is_some()
            {
                return Err(ConnectorWorkerProtocolErrorV2::BindingMismatch);
            }
        }
        ConnectorOutcomeKindV2::Completion => {
            let result_bytes = result
                .as_deref()
                .ok_or(ConnectorWorkerProtocolErrorV2::BindingMismatch)?;
            if response_digest.is_none()
                || result_bytes.is_empty()
                || result_bytes.len() > MAX_CONNECTOR_RESPONSE_BYTES
                || result_digest != Some(connector_result_digest(result_bytes))
            {
                return Err(ConnectorWorkerProtocolErrorV2::BindingMismatch);
            }
        }
        ConnectorOutcomeKindV2::Indeterminate => {
            if response_digest.is_none() || result.is_some() || result_digest.is_some() {
                return Err(ConnectorWorkerProtocolErrorV2::BindingMismatch);
            }
        }
    }
    let transcript_material = encode_outcome_transcript_material(
        job,
        kind,
        response_digest,
        result.as_deref(),
        result_digest,
    )?;
    Ok(ConnectorOutcomeFrameV2 {
        kind,
        provider_response_digest: response_digest,
        result: result.map(Zeroizing::new),
        result_digest,
        transcript_digest,
        canonical_payload: bytes.to_vec(),
        transcript_material,
    })
}

fn decode_job_payload(
    bytes: &[u8],
) -> Result<ConnectorJobPayloadV2, ConnectorWorkerProtocolErrorV2> {
    let mut decoder = minicbor::Decoder::new(bytes);
    require_array(&mut decoder, 25)?;
    if decoder
        .u16()
        .map_err(|_| ConnectorWorkerProtocolErrorV2::NonCanonical)?
        != 2
    {
        return Err(ConnectorWorkerProtocolErrorV2::NonCanonical);
    }
    let payload = ConnectorJobPayloadV2 {
        installation_id: Digest32V2::new(decode_fixed::<32>(&mut decoder)?),
        active_state_manifest_digest: Digest32V2::new(decode_fixed::<32>(&mut decoder)?),
        deployment_generation: decoder
            .u64()
            .map_err(|_| ConnectorWorkerProtocolErrorV2::NonCanonical)?,
        effect_fence_epoch: decoder
            .u64()
            .map_err(|_| ConnectorWorkerProtocolErrorV2::NonCanonical)?,
        execution_nonce: Nonce32V2::new(decode_fixed::<32>(&mut decoder)?),
        dispatch_core_digest: Digest32V2::new(decode_fixed::<32>(&mut decoder)?),
        dispatch_subject_digest: Digest32V2::new(decode_fixed::<32>(&mut decoder)?),
        worker_artifact_digest: Digest32V2::new(decode_fixed::<32>(&mut decoder)?),
        credential_handle_identity_digest: Digest32V2::new(decode_fixed::<32>(&mut decoder)?),
        bounded_material_digest: Digest32V2::new(decode_fixed::<32>(&mut decoder)?),
        no_network_sandbox_profile_digest: Digest32V2::new(decode_fixed::<32>(&mut decoder)?),
        credential_absence_profile_digest: Digest32V2::new(decode_fixed::<32>(&mut decoder)?),
        mode: ConnectorCodecJobModeV2::from_tag(
            decoder
                .u16()
                .map_err(|_| ConnectorWorkerProtocolErrorV2::NonCanonical)?,
        )?,
        external_attempt_ordinal: decoder
            .u16()
            .map_err(|_| ConnectorWorkerProtocolErrorV2::NonCanonical)?,
        codec_job_ordinal: decoder
            .u16()
            .map_err(|_| ConnectorWorkerProtocolErrorV2::NonCanonical)?,
        worker_job_nonce: Nonce32V2::new(decode_fixed::<32>(&mut decoder)?),
        anonymous_channel_binding_digest: Digest32V2::new(decode_fixed::<32>(&mut decoder)?),
        ephemeral_attestation_public_key: decode_fixed::<32>(&mut decoder)?,
        ephemeral_attestation_key_id: Ed25519KeyIdV2::new(decode_fixed::<32>(&mut decoder)?),
        prepared_request_digest: decode_optional_digest(&mut decoder)?,
        retained_provider_response_digest: decode_optional_digest(&mut decoder)?,
        retained_provider_response_length: decode_optional_u32(&mut decoder)?,
        effect_started_receipt_digest: decode_optional_digest(&mut decoder)?,
        deadline: UnixMillisV2::new(
            decoder
                .u64()
                .map_err(|_| ConnectorWorkerProtocolErrorV2::NonCanonical)?,
        ),
    };
    if decoder.position() != bytes.len() {
        return Err(ConnectorWorkerProtocolErrorV2::NonCanonical);
    }
    Ok(payload)
}

fn encode_job_payload(
    payload: ConnectorJobPayloadV2,
) -> Result<Vec<u8>, ConnectorWorkerProtocolErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(25)
        .and_then(|encoder| encoder.u16(2))
        .and_then(|encoder| encoder.bytes(payload.installation_id.as_bytes()))
        .and_then(|encoder| encoder.bytes(payload.active_state_manifest_digest.as_bytes()))
        .and_then(|encoder| encoder.u64(payload.deployment_generation))
        .and_then(|encoder| encoder.u64(payload.effect_fence_epoch))
        .and_then(|encoder| encoder.bytes(payload.execution_nonce.as_bytes()))
        .and_then(|encoder| encoder.bytes(payload.dispatch_core_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(payload.dispatch_subject_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(payload.worker_artifact_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(payload.credential_handle_identity_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(payload.bounded_material_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(payload.no_network_sandbox_profile_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(payload.credential_absence_profile_digest.as_bytes()))
        .and_then(|encoder| encoder.u16(payload.mode.tag()))
        .and_then(|encoder| encoder.u16(payload.external_attempt_ordinal))
        .and_then(|encoder| encoder.u16(payload.codec_job_ordinal))
        .and_then(|encoder| encoder.bytes(payload.worker_job_nonce.as_bytes()))
        .and_then(|encoder| encoder.bytes(payload.anonymous_channel_binding_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(&payload.ephemeral_attestation_public_key))
        .and_then(|encoder| encoder.bytes(payload.ephemeral_attestation_key_id.as_bytes()))
        .map_err(|_| ConnectorWorkerProtocolErrorV2::Bounds)?;
    encode_optional_digest(&mut encoder, payload.prepared_request_digest)?;
    encode_optional_digest(&mut encoder, payload.retained_provider_response_digest)?;
    encode_optional_u32(&mut encoder, payload.retained_provider_response_length)?;
    encode_optional_digest(&mut encoder, payload.effect_started_receipt_digest)?;
    encoder
        .u64(payload.deadline.get())
        .map_err(|_| ConnectorWorkerProtocolErrorV2::Bounds)?;
    Ok(encoder.into_writer())
}

fn encode_prepared_payload(
    job: &VerifiedConnectorWorkerJobV2,
    request: &[u8],
    request_digest: Digest32V2,
    maximum_response_bytes: u32,
    transcript_digest: Digest32V2,
) -> Result<Vec<u8>, ConnectorWorkerProtocolErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(9)
        .and_then(|encoder| encoder.u16(2))
        .and_then(|encoder| encoder.bytes(job.worker_job_nonce.as_bytes()))
        .and_then(|encoder| encoder.bytes(job.execution_nonce.as_bytes()))
        .and_then(|encoder| encoder.u16(job.external_attempt_ordinal))
        .and_then(|encoder| encoder.u16(job.codec_job_ordinal))
        .and_then(|encoder| encoder.bytes(request))
        .and_then(|encoder| encoder.bytes(request_digest.as_bytes()))
        .and_then(|encoder| encoder.u32(maximum_response_bytes))
        .and_then(|encoder| encoder.bytes(transcript_digest.as_bytes()))
        .map_err(|_| ConnectorWorkerProtocolErrorV2::Bounds)?;
    Ok(encoder.into_writer())
}

fn encode_prepared_transcript_material(
    job: &VerifiedConnectorWorkerJobV2,
    request: &[u8],
    request_digest: Digest32V2,
    maximum_response_bytes: u32,
) -> Result<Vec<u8>, ConnectorWorkerProtocolErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(8)
        .and_then(|encoder| encoder.u16(2))
        .and_then(|encoder| encoder.bytes(job.worker_job_nonce.as_bytes()))
        .and_then(|encoder| encoder.bytes(job.execution_nonce.as_bytes()))
        .and_then(|encoder| encoder.u16(job.external_attempt_ordinal))
        .and_then(|encoder| encoder.u16(job.codec_job_ordinal))
        .and_then(|encoder| encoder.bytes(request))
        .and_then(|encoder| encoder.bytes(request_digest.as_bytes()))
        .and_then(|encoder| encoder.u32(maximum_response_bytes))
        .map_err(|_| ConnectorWorkerProtocolErrorV2::Bounds)?;
    Ok(encoder.into_writer())
}

fn encode_outcome_transcript_material(
    job: &VerifiedConnectorWorkerJobV2,
    kind: ConnectorOutcomeKindV2,
    response_digest: Option<Digest32V2>,
    result: Option<&[u8]>,
    result_digest: Option<Digest32V2>,
) -> Result<Vec<u8>, ConnectorWorkerProtocolErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(7)
        .and_then(|encoder| encoder.u16(2))
        .and_then(|encoder| encoder.bytes(job.worker_job_nonce.as_bytes()))
        .and_then(|encoder| encoder.bytes(job.execution_nonce.as_bytes()))
        .and_then(|encoder| {
            encoder.u16(match kind {
                ConnectorOutcomeKindV2::FailedBeforeEffect => 1,
                ConnectorOutcomeKindV2::Completion => 2,
                ConnectorOutcomeKindV2::Indeterminate => 3,
            })
        })
        .map_err(|_| ConnectorWorkerProtocolErrorV2::Bounds)?;
    encode_optional_digest(&mut encoder, response_digest)?;
    match result {
        Some(value) => {
            encoder
                .bytes(value)
                .map_err(|_| ConnectorWorkerProtocolErrorV2::Bounds)?;
        }
        None => {
            encoder
                .null()
                .map_err(|_| ConnectorWorkerProtocolErrorV2::Bounds)?;
        }
    }
    encode_optional_digest(&mut encoder, result_digest)?;
    Ok(encoder.into_writer())
}

fn encode_signed(
    payload: &[u8],
    key_id: Ed25519KeyIdV2,
    signature: &[u8; 64],
) -> Result<Vec<u8>, ConnectorWorkerProtocolErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(3)
        .and_then(|encoder| encoder.bytes(payload))
        .and_then(|encoder| encoder.bytes(key_id.as_bytes()))
        .and_then(|encoder| encoder.bytes(signature))
        .map_err(|_| ConnectorWorkerProtocolErrorV2::Bounds)?;
    Ok(encoder.into_writer())
}

fn encode_worker_frame(
    tag: u16,
    payload: &[u8],
    key_id: Ed25519KeyIdV2,
    signature: &[u8; 64],
) -> Result<Vec<u8>, ConnectorWorkerProtocolErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(4)
        .and_then(|encoder| encoder.u16(tag))
        .and_then(|encoder| encoder.bytes(payload))
        .and_then(|encoder| encoder.bytes(key_id.as_bytes()))
        .and_then(|encoder| encoder.bytes(signature))
        .map_err(|_| ConnectorWorkerProtocolErrorV2::Bounds)?;
    Ok(encoder.into_writer())
}

fn require_array(
    decoder: &mut minicbor::Decoder<'_>,
    expected: u64,
) -> Result<(), ConnectorWorkerProtocolErrorV2> {
    if decoder
        .array()
        .map_err(|_| ConnectorWorkerProtocolErrorV2::NonCanonical)?
        != Some(expected)
    {
        return Err(ConnectorWorkerProtocolErrorV2::NonCanonical);
    }
    Ok(())
}

fn decode_fixed<const N: usize>(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<[u8; N], ConnectorWorkerProtocolErrorV2> {
    decoder
        .bytes()
        .map_err(|_| ConnectorWorkerProtocolErrorV2::NonCanonical)?
        .try_into()
        .map_err(|_| ConnectorWorkerProtocolErrorV2::NonCanonical)
}

fn decode_optional_digest(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<Option<Digest32V2>, ConnectorWorkerProtocolErrorV2> {
    let position = decoder.position();
    match decoder
        .datatype()
        .map_err(|_| ConnectorWorkerProtocolErrorV2::NonCanonical)?
    {
        minicbor::data::Type::Null => {
            decoder
                .null()
                .map_err(|_| ConnectorWorkerProtocolErrorV2::NonCanonical)?;
            Ok(None)
        }
        minicbor::data::Type::Bytes => {
            let value = Digest32V2::new(decode_fixed::<32>(decoder)?);
            if is_zero(value.as_bytes()) {
                return Err(ConnectorWorkerProtocolErrorV2::BindingMismatch);
            }
            Ok(Some(value))
        }
        _ => {
            let _ = position;
            Err(ConnectorWorkerProtocolErrorV2::NonCanonical)
        }
    }
}

fn decode_optional_u32(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<Option<u32>, ConnectorWorkerProtocolErrorV2> {
    match decoder
        .datatype()
        .map_err(|_| ConnectorWorkerProtocolErrorV2::NonCanonical)?
    {
        minicbor::data::Type::Null => {
            decoder
                .null()
                .map_err(|_| ConnectorWorkerProtocolErrorV2::NonCanonical)?;
            Ok(None)
        }
        minicbor::data::Type::U8 | minicbor::data::Type::U16 | minicbor::data::Type::U32 => decoder
            .u32()
            .map(Some)
            .map_err(|_| ConnectorWorkerProtocolErrorV2::NonCanonical),
        _ => Err(ConnectorWorkerProtocolErrorV2::NonCanonical),
    }
}

fn decode_optional_bytes(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<Option<Vec<u8>>, ConnectorWorkerProtocolErrorV2> {
    match decoder
        .datatype()
        .map_err(|_| ConnectorWorkerProtocolErrorV2::NonCanonical)?
    {
        minicbor::data::Type::Null => {
            decoder
                .null()
                .map_err(|_| ConnectorWorkerProtocolErrorV2::NonCanonical)?;
            Ok(None)
        }
        minicbor::data::Type::Bytes => decoder
            .bytes()
            .map(|bytes| Some(bytes.to_vec()))
            .map_err(|_| ConnectorWorkerProtocolErrorV2::NonCanonical),
        _ => Err(ConnectorWorkerProtocolErrorV2::NonCanonical),
    }
}

fn encode_optional_digest(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    value: Option<Digest32V2>,
) -> Result<(), ConnectorWorkerProtocolErrorV2> {
    match value {
        Some(value) => {
            encoder
                .bytes(value.as_bytes())
                .map_err(|_| ConnectorWorkerProtocolErrorV2::Bounds)?;
        }
        None => {
            encoder
                .null()
                .map_err(|_| ConnectorWorkerProtocolErrorV2::Bounds)?;
        }
    }
    Ok(())
}

fn encode_optional_u32(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    value: Option<u32>,
) -> Result<(), ConnectorWorkerProtocolErrorV2> {
    match value {
        Some(value) => {
            encoder
                .u32(value)
                .map_err(|_| ConnectorWorkerProtocolErrorV2::Bounds)?;
        }
        None => {
            encoder
                .null()
                .map_err(|_| ConnectorWorkerProtocolErrorV2::Bounds)?;
        }
    }
    Ok(())
}

fn signature_input(domain: &[u8], digest: [u8; 32]) -> Vec<u8> {
    let mut input = Vec::with_capacity(domain.len() + digest.len());
    input.extend_from_slice(domain);
    input.extend_from_slice(&digest);
    input
}

fn domain_hash(domain: &[u8], bytes: &[u8]) -> Digest32V2 {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    Digest32V2::new(hasher.finalize().into())
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

#[cfg(test)]
pub(crate) mod test_support {
    use ed25519_dalek::{Signer as _, SigningKey};

    use super::{
        connector_material_digest, connector_response_digest, connector_result_digest,
        encode_job_payload, encode_outcome_transcript_material,
        encode_prepared_transcript_material, encode_signed, encode_worker_frame, sha256,
        signature_input, ConnectorCodecJobModeV2, ConnectorJobPayloadV2, ConnectorOutcomeKindV2,
        ConnectorWorkerProtocolErrorV2, VerifiedConnectorWorkerJobV2, DESCRIPTOR_SIGNATURE_DOMAIN,
        OUTCOME_SIGNATURE_DOMAIN, PREPARED_SIGNATURE_DOMAIN, REQUEST_DOMAIN,
    };
    use savana_kernel_protocol::v2::{
        derive_ed25519_key_id_v2, Digest32V2, Ed25519KeyIdV2, Nonce32V2, UnixMillisV2,
    };

    pub(crate) struct ConnectorFixtureV2 {
        pub(crate) descriptor: Vec<u8>,
        pub(crate) parent_public_key: [u8; 32],
        pub(crate) ephemeral: SigningKey,
        pub(crate) ephemeral_key_id: Ed25519KeyIdV2,
        pub(crate) material: Vec<u8>,
    }

    pub(crate) fn fixture(mode: ConnectorCodecJobModeV2) -> ConnectorFixtureV2 {
        let parent = SigningKey::from_bytes(&[0x41; 32]);
        let ephemeral = SigningKey::from_bytes(&[0x42; 32]);
        let ephemeral_key_id = derive_ed25519_key_id_v2(ephemeral.verifying_key().to_bytes());
        let material = b"credential-free material".to_vec();
        let retained = connector_response_digest(b"provider response");
        let payload = ConnectorJobPayloadV2 {
            installation_id: Digest32V2::new([1; 32]),
            active_state_manifest_digest: Digest32V2::new([2; 32]),
            deployment_generation: 3,
            effect_fence_epoch: 4,
            execution_nonce: Nonce32V2::new([5; 32]),
            dispatch_core_digest: Digest32V2::new([6; 32]),
            dispatch_subject_digest: Digest32V2::new([7; 32]),
            worker_artifact_digest: Digest32V2::new([8; 32]),
            credential_handle_identity_digest: Digest32V2::new([9; 32]),
            bounded_material_digest: connector_material_digest(&material),
            no_network_sandbox_profile_digest: Digest32V2::new([10; 32]),
            credential_absence_profile_digest: Digest32V2::new([11; 32]),
            mode,
            external_attempt_ordinal: 1,
            codec_job_ordinal: 1,
            worker_job_nonce: Nonce32V2::new([12; 32]),
            anonymous_channel_binding_digest: Digest32V2::new([13; 32]),
            ephemeral_attestation_public_key: ephemeral.verifying_key().to_bytes(),
            ephemeral_attestation_key_id: ephemeral_key_id,
            prepared_request_digest: match mode {
                ConnectorCodecJobModeV2::PrepareAndDecode => None,
                ConnectorCodecJobModeV2::DecodeRetainedResponse => Some(Digest32V2::new([14; 32])),
            },
            retained_provider_response_digest: match mode {
                ConnectorCodecJobModeV2::PrepareAndDecode => None,
                ConnectorCodecJobModeV2::DecodeRetainedResponse => Some(retained),
            },
            retained_provider_response_length: match mode {
                ConnectorCodecJobModeV2::PrepareAndDecode => None,
                ConnectorCodecJobModeV2::DecodeRetainedResponse => {
                    Some(b"provider response".len() as u32)
                }
            },
            effect_started_receipt_digest: match mode {
                ConnectorCodecJobModeV2::PrepareAndDecode => None,
                ConnectorCodecJobModeV2::DecodeRetainedResponse => Some(Digest32V2::new([15; 32])),
            },
            deadline: UnixMillisV2::new(1_000),
        };
        let payload_bytes = encode_job_payload(payload).unwrap();
        let signature = parent
            .sign(&signature_input(
                DESCRIPTOR_SIGNATURE_DOMAIN,
                sha256(&payload_bytes),
            ))
            .to_bytes();
        ConnectorFixtureV2 {
            descriptor: encode_signed(
                &payload_bytes,
                derive_ed25519_key_id_v2(parent.verifying_key().to_bytes()),
                &signature,
            )
            .unwrap(),
            parent_public_key: parent.verifying_key().to_bytes(),
            ephemeral,
            ephemeral_key_id,
            material,
        }
    }

    pub(crate) fn prepared_frame(
        fixture: &ConnectorFixtureV2,
        job: &VerifiedConnectorWorkerJobV2,
        transcript: Digest32V2,
    ) -> Vec<u8> {
        let request = b"prepared request";
        let request_digest = super::domain_hash(REQUEST_DOMAIN, request);
        let mut encoder = minicbor::Encoder::new(Vec::new());
        encoder
            .array(9)
            .and_then(|encoder| encoder.u16(2))
            .and_then(|encoder| encoder.bytes(job.worker_job_nonce.as_bytes()))
            .and_then(|encoder| encoder.bytes(job.execution_nonce.as_bytes()))
            .and_then(|encoder| encoder.u16(job.external_attempt_ordinal))
            .and_then(|encoder| encoder.u16(job.codec_job_ordinal))
            .and_then(|encoder| encoder.bytes(request))
            .and_then(|encoder| encoder.bytes(request_digest.as_bytes()))
            .and_then(|encoder| encoder.u32(1024))
            .and_then(|encoder| encoder.bytes(transcript.as_bytes()))
            .unwrap();
        let payload = encoder.into_writer();
        let signature = fixture
            .ephemeral
            .sign(&signature_input(
                PREPARED_SIGNATURE_DOMAIN,
                sha256(&payload),
            ))
            .to_bytes();
        encode_worker_frame(1, &payload, fixture.ephemeral_key_id, &signature).unwrap()
    }

    pub(crate) fn prepared_transcript_material(job: &VerifiedConnectorWorkerJobV2) -> Vec<u8> {
        let request = b"prepared request";
        let request_digest = super::domain_hash(REQUEST_DOMAIN, request);
        encode_prepared_transcript_material(job, request, request_digest, 1024).unwrap()
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn outcome_frame(
        fixture: &ConnectorFixtureV2,
        job: &VerifiedConnectorWorkerJobV2,
        kind: ConnectorOutcomeKindV2,
        response: Option<&[u8]>,
        result: Option<&[u8]>,
        transcript: Digest32V2,
    ) -> Result<Vec<u8>, ConnectorWorkerProtocolErrorV2> {
        let response_digest = response.map(connector_response_digest);
        let result_digest = result.map(connector_result_digest);
        let mut encoder = minicbor::Encoder::new(Vec::new());
        encoder
            .array(8)
            .and_then(|encoder| encoder.u16(2))
            .and_then(|encoder| encoder.bytes(job.worker_job_nonce.as_bytes()))
            .and_then(|encoder| encoder.bytes(job.execution_nonce.as_bytes()))
            .and_then(|encoder| {
                encoder.u16(match kind {
                    ConnectorOutcomeKindV2::FailedBeforeEffect => 1,
                    ConnectorOutcomeKindV2::Completion => 2,
                    ConnectorOutcomeKindV2::Indeterminate => 3,
                })
            })
            .map_err(|_| ConnectorWorkerProtocolErrorV2::Bounds)?;
        match response_digest {
            Some(value) => {
                encoder
                    .bytes(value.as_bytes())
                    .map_err(|_| ConnectorWorkerProtocolErrorV2::Bounds)?;
            }
            None => {
                encoder
                    .null()
                    .map_err(|_| ConnectorWorkerProtocolErrorV2::Bounds)?;
            }
        }
        match result {
            Some(value) => {
                encoder
                    .bytes(value)
                    .map_err(|_| ConnectorWorkerProtocolErrorV2::Bounds)?;
            }
            None => {
                encoder
                    .null()
                    .map_err(|_| ConnectorWorkerProtocolErrorV2::Bounds)?;
            }
        }
        match result_digest {
            Some(value) => {
                encoder
                    .bytes(value.as_bytes())
                    .map_err(|_| ConnectorWorkerProtocolErrorV2::Bounds)?;
            }
            None => {
                encoder
                    .null()
                    .map_err(|_| ConnectorWorkerProtocolErrorV2::Bounds)?;
            }
        }
        encoder
            .bytes(transcript.as_bytes())
            .map_err(|_| ConnectorWorkerProtocolErrorV2::Bounds)?;
        let payload = encoder.into_writer();
        let signature = fixture
            .ephemeral
            .sign(&signature_input(OUTCOME_SIGNATURE_DOMAIN, sha256(&payload)))
            .to_bytes();
        encode_worker_frame(3, &payload, fixture.ephemeral_key_id, &signature)
    }

    pub(crate) fn outcome_transcript_material(
        job: &VerifiedConnectorWorkerJobV2,
        kind: ConnectorOutcomeKindV2,
        response: Option<&[u8]>,
        result: Option<&[u8]>,
    ) -> Vec<u8> {
        encode_outcome_transcript_material(
            job,
            kind,
            response.map(connector_response_digest),
            result,
            result.map(connector_result_digest),
        )
        .unwrap()
    }
}
