use ed25519_dalek::{
    Signature as Ed25519Signature, SigningKey, VerifyingKey as Ed25519VerifyingKey,
};
use savana_kernel_protocol::v2::{
    Digest32V2, Ed25519KeyIdV2, Nonce32V2, ServiceIdentityV2, UnixMillisV2,
};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

pub(crate) const MAX_PARSER_JOB_DESCRIPTOR_BYTES: usize = 16 * 1024;
pub(crate) const MAX_PARSER_WORKER_FRAME_BYTES: usize = 512 * 1024;
pub(crate) const MAX_PARSER_ORIGINAL_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const MAX_PARSER_PAGES: u32 = 2_048;
pub(crate) const MAX_PARSER_CHUNK_BYTES: usize = 256 * 1024;

const JOB_DESCRIPTOR_DOMAIN: &[u8] = b"SAVANA_PARSER_WORKER_JOB_DESCRIPTOR_V2\0";
const JOB_DESCRIPTOR_SIGNATURE_DOMAIN: &[u8] =
    b"SAVANA_PARSER_WORKER_JOB_DESCRIPTOR_SIGNATURE_V2\0";
const RESULT_SIGNATURE_DOMAIN: &[u8] = b"SAVANA_PARSER_WORKER_RESULT_SIGNATURE_V2\0";
const OUTPUT_DOMAIN: &[u8] = b"SAVANA_PARSER_WORKER_OUTPUT_V2\0";
const TRANSCRIPT_BEGIN_DOMAIN: &[u8] = b"SAVANA_PARSER_WORKER_TRANSCRIPT_BEGIN_V2\0";
const TRANSCRIPT_STEP_DOMAIN: &[u8] = b"SAVANA_PARSER_WORKER_TRANSCRIPT_STEP_V2\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ParserWorkerProtocolErrorV2 {
    #[error("parser worker frame is malformed or noncanonical")]
    NonCanonical,
    #[error("parser worker descriptor signature is invalid")]
    InvalidParentSignature,
    #[error("parser worker result signature is invalid")]
    InvalidWorkerSignature,
    #[error("parser worker descriptor is bound to another deployment or job")]
    BindingMismatch,
    #[error("parser worker input or output exceeded a compiled bound")]
    Bounds,
    #[error("parser worker job expired")]
    Expired,
}

#[derive(Clone)]
pub(crate) struct VerifiedParserWorkerTrustV2 {
    installation_id: Digest32V2,
    active_state_manifest_digest: Digest32V2,
    deployment_generation: u64,
    ingressd_identity: ServiceIdentityV2,
    worker_artifact_digest: Digest32V2,
    anonymous_channel_binding_digest: Digest32V2,
    parent_key_id: Ed25519KeyIdV2,
    parent_verifying_key: Ed25519VerifyingKey,
}

impl std::fmt::Debug for VerifiedParserWorkerTrustV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifiedParserWorkerTrustV2")
            .field("deployment_generation", &self.deployment_generation)
            .finish_non_exhaustive()
    }
}

impl VerifiedParserWorkerTrustV2 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_verified_deployment(
        installation_id: Digest32V2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        ingressd_identity: ServiceIdentityV2,
        worker_artifact_digest: Digest32V2,
        anonymous_channel_binding_digest: Digest32V2,
        parent_key_id: Ed25519KeyIdV2,
        parent_public_key: [u8; 32],
    ) -> Result<Self, ParserWorkerProtocolErrorV2> {
        if [
            installation_id.as_bytes(),
            active_state_manifest_digest.as_bytes(),
            ingressd_identity.as_bytes(),
            worker_artifact_digest.as_bytes(),
            anonymous_channel_binding_digest.as_bytes(),
            parent_key_id.as_bytes(),
        ]
        .iter()
        .any(|value| is_zero(*value))
            || deployment_generation == 0
        {
            return Err(ParserWorkerProtocolErrorV2::BindingMismatch);
        }
        let parent_verifying_key = Ed25519VerifyingKey::from_bytes(&parent_public_key)
            .map_err(|_| ParserWorkerProtocolErrorV2::BindingMismatch)?;
        Ok(Self {
            installation_id,
            active_state_manifest_digest,
            deployment_generation,
            ingressd_identity,
            worker_artifact_digest,
            anonymous_channel_binding_digest,
            parent_key_id,
            parent_verifying_key,
        })
    }
}

#[derive(Debug, Clone, Copy)]
struct ParserWorkerJobPayloadV2 {
    installation_id: Digest32V2,
    active_state_manifest_digest: Digest32V2,
    deployment_generation: u64,
    ingressd_identity: ServiceIdentityV2,
    job_nonce: Nonce32V2,
    parser_job_session_binding_digest: Digest32V2,
    original_byte_length: u64,
    original_sha256: Digest32V2,
    worker_artifact_digest: Digest32V2,
    output_limit_bytes: u32,
    maximum_pages: u32,
    anonymous_channel_binding_digest: Digest32V2,
    ephemeral_result_public_key: [u8; 32],
    ephemeral_result_key_id: Ed25519KeyIdV2,
    expires_at: UnixMillisV2,
}

pub(crate) struct VerifiedParserWorkerJobV2 {
    canonical_descriptor: Vec<u8>,
    descriptor_digest: Digest32V2,
    job_nonce: Nonce32V2,
    parser_job_session_binding_digest: Digest32V2,
    worker_artifact_digest: Digest32V2,
    original_sha256: Digest32V2,
    output_limit_bytes: u32,
    maximum_pages: u32,
    ephemeral_result_key_id: Ed25519KeyIdV2,
    ephemeral_result_verifying_key: Ed25519VerifyingKey,
    parent_key_id: Ed25519KeyIdV2,
    parent_public_key: [u8; 32],
    expires_at: UnixMillisV2,
}

impl std::fmt::Debug for VerifiedParserWorkerJobV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifiedParserWorkerJobV2")
            .field("descriptor_digest", &self.descriptor_digest)
            .field("job_nonce", &self.job_nonce)
            .finish_non_exhaustive()
    }
}

impl VerifiedParserWorkerJobV2 {
    pub(crate) fn canonical_descriptor(&self) -> &[u8] {
        &self.canonical_descriptor
    }

    pub(crate) const fn descriptor_digest(&self) -> Digest32V2 {
        self.descriptor_digest
    }

    pub(crate) const fn job_nonce(&self) -> Nonce32V2 {
        self.job_nonce
    }

    pub(crate) const fn output_limit_bytes(&self) -> u32 {
        self.output_limit_bytes
    }

    pub(crate) const fn maximum_pages(&self) -> u32 {
        self.maximum_pages
    }

    pub(crate) const fn expires_at(&self) -> UnixMillisV2 {
        self.expires_at
    }

    pub(crate) const fn worker_artifact_digest(&self) -> Digest32V2 {
        self.worker_artifact_digest
    }

    pub(crate) fn ephemeral_seed_matches(&self, seed: &[u8; 32]) -> bool {
        SigningKey::from_bytes(seed).verifying_key() == self.ephemeral_result_verifying_key
    }

    pub(crate) const fn parent_key_id(&self) -> Ed25519KeyIdV2 {
        self.parent_key_id
    }

    pub(crate) const fn parent_public_key(&self) -> [u8; 32] {
        self.parent_public_key
    }

    pub(crate) const fn parser_job_session_binding_digest(&self) -> Digest32V2 {
        self.parser_job_session_binding_digest
    }

    pub(crate) const fn ephemeral_result_key_id(&self) -> Ed25519KeyIdV2 {
        self.ephemeral_result_key_id
    }
}

#[derive(Debug)]
pub(crate) struct ParserWorkerPageFrameV2 {
    job_nonce: Nonce32V2,
    page_index: u32,
    page_chunk_index: u32,
    final_chunk_for_page: bool,
    extracted_chunk: Zeroizing<Vec<u8>>,
    extracted_chunk_digest: Digest32V2,
    canonical_without_attestation: Vec<u8>,
}

impl ParserWorkerPageFrameV2 {
    pub(crate) const fn job_nonce(&self) -> Nonce32V2 {
        self.job_nonce
    }

    pub(crate) const fn page_index(&self) -> u32 {
        self.page_index
    }

    pub(crate) const fn page_chunk_index(&self) -> u32 {
        self.page_chunk_index
    }

    pub(crate) const fn final_chunk_for_page(&self) -> bool {
        self.final_chunk_for_page
    }

    pub(crate) fn extracted_chunk(&self) -> &[u8] {
        &self.extracted_chunk
    }

    pub(crate) const fn extracted_chunk_digest(&self) -> Digest32V2 {
        self.extracted_chunk_digest
    }

    pub(crate) fn canonical_without_attestation(&self) -> &[u8] {
        &self.canonical_without_attestation
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ParserWorkerCompleteFrameV2 {
    job_nonce: Nonce32V2,
    job_descriptor_digest: Digest32V2,
    parser_job_session_binding_digest: Digest32V2,
    worker_artifact_digest: Digest32V2,
    ephemeral_result_key_id: Ed25519KeyIdV2,
    page_count: u32,
    ordered_page_frame_transcript_digest: Digest32V2,
    extracted_byte_length: u64,
    extracted_output_digest: Digest32V2,
    completed_at: UnixMillisV2,
}

impl ParserWorkerCompleteFrameV2 {
    pub(crate) const fn page_count(self) -> u32 {
        self.page_count
    }

    pub(crate) const fn transcript_digest(self) -> Digest32V2 {
        self.ordered_page_frame_transcript_digest
    }

    pub(crate) const fn extracted_byte_length(self) -> u64 {
        self.extracted_byte_length
    }

    pub(crate) const fn extracted_output_digest(self) -> Digest32V2 {
        self.extracted_output_digest
    }

    pub(crate) const fn completed_at(self) -> UnixMillisV2 {
        self.completed_at
    }
}

#[derive(Debug)]
pub(crate) enum ParserWorkerFrameV2 {
    Page(ParserWorkerPageFrameV2),
    Complete(ParserWorkerCompleteFrameV2),
    Failed(u16),
}

pub(crate) fn verify_parser_worker_job(
    canonical_descriptor: &[u8],
    original: &[u8],
    trust: &VerifiedParserWorkerTrustV2,
    now: UnixMillisV2,
) -> Result<VerifiedParserWorkerJobV2, ParserWorkerProtocolErrorV2> {
    if canonical_descriptor.is_empty()
        || canonical_descriptor.len() > MAX_PARSER_JOB_DESCRIPTOR_BYTES
        || original.is_empty()
        || original.len() > MAX_PARSER_ORIGINAL_BYTES
    {
        return Err(ParserWorkerProtocolErrorV2::Bounds);
    }
    let mut decoder = minicbor::Decoder::new(canonical_descriptor);
    require_array(&mut decoder, 3)?;
    let payload_bytes = decoder
        .bytes()
        .map_err(|_| ParserWorkerProtocolErrorV2::NonCanonical)?
        .to_vec();
    let key_id = Ed25519KeyIdV2::new(decode_fixed::<32>(&mut decoder)?);
    let signature = decode_fixed::<64>(&mut decoder)?;
    if decoder.position() != canonical_descriptor.len()
        || encode_signed(&payload_bytes, key_id, &signature)? != canonical_descriptor
        || key_id != trust.parent_key_id
    {
        return Err(ParserWorkerProtocolErrorV2::NonCanonical);
    }
    let payload = decode_job_payload(&payload_bytes)?;
    if encode_job_payload(payload)? != payload_bytes {
        return Err(ParserWorkerProtocolErrorV2::NonCanonical);
    }
    let payload_digest = sha256(&payload_bytes);
    let signature_input = signature_input(JOB_DESCRIPTOR_SIGNATURE_DOMAIN, payload_digest);
    trust
        .parent_verifying_key
        .verify_strict(&signature_input, &Ed25519Signature::from_bytes(&signature))
        .map_err(|_| ParserWorkerProtocolErrorV2::InvalidParentSignature)?;
    if payload.installation_id != trust.installation_id
        || payload.active_state_manifest_digest != trust.active_state_manifest_digest
        || payload.deployment_generation != trust.deployment_generation
        || payload.ingressd_identity != trust.ingressd_identity
        || payload.worker_artifact_digest != trust.worker_artifact_digest
        || payload.anonymous_channel_binding_digest != trust.anonymous_channel_binding_digest
        || is_zero(payload.job_nonce.as_bytes())
        || is_zero(payload.parser_job_session_binding_digest.as_bytes())
        || is_zero(payload.original_sha256.as_bytes())
        || is_zero(payload.ephemeral_result_key_id.as_bytes())
    {
        return Err(ParserWorkerProtocolErrorV2::BindingMismatch);
    }
    if now.get() == 0 || now.get() >= payload.expires_at.get() {
        return Err(ParserWorkerProtocolErrorV2::Expired);
    }
    if payload.original_byte_length != original.len() as u64
        || payload.original_sha256 != Digest32V2::new(sha256(original))
    {
        return Err(ParserWorkerProtocolErrorV2::BindingMismatch);
    }
    if payload.output_limit_bytes == 0
        || payload.output_limit_bytes as usize > MAX_PARSER_ORIGINAL_BYTES
        || payload.maximum_pages == 0
        || payload.maximum_pages > MAX_PARSER_PAGES
    {
        return Err(ParserWorkerProtocolErrorV2::Bounds);
    }
    let ephemeral_result_verifying_key =
        Ed25519VerifyingKey::from_bytes(&payload.ephemeral_result_public_key)
            .map_err(|_| ParserWorkerProtocolErrorV2::BindingMismatch)?;
    let descriptor_digest = domain_hash(JOB_DESCRIPTOR_DOMAIN, &payload_bytes);
    Ok(VerifiedParserWorkerJobV2 {
        canonical_descriptor: canonical_descriptor.to_vec(),
        descriptor_digest,
        job_nonce: payload.job_nonce,
        parser_job_session_binding_digest: payload.parser_job_session_binding_digest,
        worker_artifact_digest: payload.worker_artifact_digest,
        original_sha256: payload.original_sha256,
        output_limit_bytes: payload.output_limit_bytes,
        maximum_pages: payload.maximum_pages,
        ephemeral_result_key_id: payload.ephemeral_result_key_id,
        ephemeral_result_verifying_key,
        parent_key_id: trust.parent_key_id,
        parent_public_key: trust.parent_verifying_key.to_bytes(),
        expires_at: payload.expires_at,
    })
}

/// Revalidates the complete descriptor inside the sandboxed child. The parent
/// public key is delivered over the inherited anonymous channel only after the
/// parent has verified it against deployment state.
pub(crate) fn verify_parser_worker_child_job(
    canonical_descriptor: &[u8],
    original: &[u8],
    parent_public_key: [u8; 32],
    ephemeral_signing_seed: &[u8; 32],
    now: UnixMillisV2,
) -> Result<VerifiedParserWorkerJobV2, ParserWorkerProtocolErrorV2> {
    let mut decoder = minicbor::Decoder::new(canonical_descriptor);
    require_array(&mut decoder, 3)?;
    let payload_bytes = decoder
        .bytes()
        .map_err(|_| ParserWorkerProtocolErrorV2::NonCanonical)?;
    let parent_key_id = Ed25519KeyIdV2::new(decode_fixed::<32>(&mut decoder)?);
    let _signature = decode_fixed::<64>(&mut decoder)?;
    if decoder.position() != canonical_descriptor.len() {
        return Err(ParserWorkerProtocolErrorV2::NonCanonical);
    }
    let payload = decode_job_payload(payload_bytes)?;
    let trust = VerifiedParserWorkerTrustV2::from_verified_deployment(
        payload.installation_id,
        payload.active_state_manifest_digest,
        payload.deployment_generation,
        payload.ingressd_identity,
        payload.worker_artifact_digest,
        payload.anonymous_channel_binding_digest,
        parent_key_id,
        parent_public_key,
    )?;
    let job = verify_parser_worker_job(canonical_descriptor, original, &trust, now)?;
    if !job.ephemeral_seed_matches(ephemeral_signing_seed) {
        return Err(ParserWorkerProtocolErrorV2::BindingMismatch);
    }
    Ok(job)
}

pub(crate) fn decode_parser_worker_frame(
    bytes: &[u8],
    job: &VerifiedParserWorkerJobV2,
) -> Result<ParserWorkerFrameV2, ParserWorkerProtocolErrorV2> {
    if bytes.is_empty() || bytes.len() > MAX_PARSER_WORKER_FRAME_BYTES {
        return Err(ParserWorkerProtocolErrorV2::Bounds);
    }
    let mut decoder = minicbor::Decoder::new(bytes);
    let length = decoder
        .array()
        .map_err(|_| ParserWorkerProtocolErrorV2::NonCanonical)?
        .ok_or(ParserWorkerProtocolErrorV2::NonCanonical)?;
    let tag = decoder
        .u16()
        .map_err(|_| ParserWorkerProtocolErrorV2::NonCanonical)?;
    let frame = match tag {
        1 if length == 8 => {
            let job_nonce = Nonce32V2::new(decode_fixed::<32>(&mut decoder)?);
            let page_index = decoder
                .u32()
                .map_err(|_| ParserWorkerProtocolErrorV2::NonCanonical)?;
            let page_chunk_index = decoder
                .u32()
                .map_err(|_| ParserWorkerProtocolErrorV2::NonCanonical)?;
            let final_chunk_for_page = decoder
                .bool()
                .map_err(|_| ParserWorkerProtocolErrorV2::NonCanonical)?;
            let extracted_chunk = decoder
                .bytes()
                .map_err(|_| ParserWorkerProtocolErrorV2::NonCanonical)?;
            if extracted_chunk.is_empty() || extracted_chunk.len() > MAX_PARSER_CHUNK_BYTES {
                return Err(ParserWorkerProtocolErrorV2::Bounds);
            }
            let extracted_chunk_digest = Digest32V2::new(decode_fixed::<32>(&mut decoder)?);
            let frame_binding = Digest32V2::new(decode_fixed::<32>(&mut decoder)?);
            let canonical_without_attestation = encode_page_frame_without_binding(
                job_nonce,
                page_index,
                page_chunk_index,
                final_chunk_for_page,
                extracted_chunk,
                extracted_chunk_digest,
            )?;
            if frame_binding != domain_hash(OUTPUT_DOMAIN, &canonical_without_attestation) {
                return Err(ParserWorkerProtocolErrorV2::BindingMismatch);
            }
            ParserWorkerFrameV2::Page(ParserWorkerPageFrameV2 {
                job_nonce,
                page_index,
                page_chunk_index,
                final_chunk_for_page,
                extracted_chunk: Zeroizing::new(extracted_chunk.to_vec()),
                extracted_chunk_digest,
                canonical_without_attestation,
            })
        }
        2 if length == 4 => {
            let payload_bytes = decoder
                .bytes()
                .map_err(|_| ParserWorkerProtocolErrorV2::NonCanonical)?
                .to_vec();
            let key_id = Ed25519KeyIdV2::new(decode_fixed::<32>(&mut decoder)?);
            let signature = decode_fixed::<64>(&mut decoder)?;
            let complete = decode_complete_payload(&payload_bytes)?;
            if encode_complete_payload(complete)? != payload_bytes
                || key_id != job.ephemeral_result_key_id
            {
                return Err(ParserWorkerProtocolErrorV2::NonCanonical);
            }
            let signature_input = signature_input(RESULT_SIGNATURE_DOMAIN, sha256(&payload_bytes));
            job.ephemeral_result_verifying_key
                .verify_strict(&signature_input, &Ed25519Signature::from_bytes(&signature))
                .map_err(|_| ParserWorkerProtocolErrorV2::InvalidWorkerSignature)?;
            if complete.job_nonce != job.job_nonce
                || complete.job_descriptor_digest != job.descriptor_digest
                || complete.parser_job_session_binding_digest
                    != job.parser_job_session_binding_digest
                || complete.worker_artifact_digest != job.worker_artifact_digest
                || complete.ephemeral_result_key_id != job.ephemeral_result_key_id
            {
                return Err(ParserWorkerProtocolErrorV2::BindingMismatch);
            }
            ParserWorkerFrameV2::Complete(complete)
        }
        3 if length == 2 => {
            let failure_class = decoder
                .u16()
                .map_err(|_| ParserWorkerProtocolErrorV2::NonCanonical)?;
            if !(1..=8).contains(&failure_class) {
                return Err(ParserWorkerProtocolErrorV2::NonCanonical);
            }
            ParserWorkerFrameV2::Failed(failure_class)
        }
        _ => return Err(ParserWorkerProtocolErrorV2::NonCanonical),
    };
    if decoder.position() != bytes.len() {
        return Err(ParserWorkerProtocolErrorV2::NonCanonical);
    }
    Ok(frame)
}

pub(crate) fn parser_output_digest(bytes: &[u8]) -> Digest32V2 {
    domain_hash(OUTPUT_DOMAIN, bytes)
}

pub(crate) fn parser_transcript_begin(job: &VerifiedParserWorkerJobV2) -> Digest32V2 {
    let mut hasher = Sha256::new();
    hasher.update(TRANSCRIPT_BEGIN_DOMAIN);
    hasher.update(job.job_nonce().as_bytes());
    hasher.update(job.descriptor_digest().as_bytes());
    Digest32V2::new(hasher.finalize().into())
}

pub(crate) fn parser_transcript_step(previous: Digest32V2, canonical_frame: &[u8]) -> Digest32V2 {
    let mut hasher = Sha256::new();
    hasher.update(TRANSCRIPT_STEP_DOMAIN);
    hasher.update(previous.as_bytes());
    hasher.update(Sha256::digest(canonical_frame));
    Digest32V2::new(hasher.finalize().into())
}

pub(crate) fn encode_parser_page_frame(
    job_nonce: Nonce32V2,
    page_index: u32,
    page_chunk_index: u32,
    final_chunk_for_page: bool,
    extracted_chunk: &[u8],
) -> Result<Vec<u8>, ParserWorkerProtocolErrorV2> {
    if extracted_chunk.is_empty() || extracted_chunk.len() > MAX_PARSER_CHUNK_BYTES {
        return Err(ParserWorkerProtocolErrorV2::Bounds);
    }
    let digest = Digest32V2::new(sha256(extracted_chunk));
    let canonical = encode_page_frame_without_binding(
        job_nonce,
        page_index,
        page_chunk_index,
        final_chunk_for_page,
        extracted_chunk,
        digest,
    )?;
    let binding = domain_hash(OUTPUT_DOMAIN, &canonical);
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(8)
        .and_then(|encoder| encoder.u16(1))
        .and_then(|encoder| encoder.bytes(job_nonce.as_bytes()))
        .and_then(|encoder| encoder.u32(page_index))
        .and_then(|encoder| encoder.u32(page_chunk_index))
        .and_then(|encoder| encoder.bool(final_chunk_for_page))
        .and_then(|encoder| encoder.bytes(extracted_chunk))
        .and_then(|encoder| encoder.bytes(digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(binding.as_bytes()))
        .map_err(|_| ParserWorkerProtocolErrorV2::Bounds)?;
    Ok(encoder.into_writer())
}

pub(crate) fn encode_parser_complete_frame(
    job: &VerifiedParserWorkerJobV2,
    ephemeral_signing_key: &SigningKey,
    page_count: u32,
    transcript_digest: Digest32V2,
    output: &[u8],
    completed_at: UnixMillisV2,
) -> Result<Vec<u8>, ParserWorkerProtocolErrorV2> {
    use ed25519_dalek::Signer as _;

    if !job.ephemeral_seed_matches(&ephemeral_signing_key.to_bytes())
        || output.is_empty()
        || output.len() > job.output_limit_bytes as usize
        || page_count == 0
        || page_count > job.maximum_pages
    {
        return Err(ParserWorkerProtocolErrorV2::BindingMismatch);
    }
    let complete = ParserWorkerCompleteFrameV2 {
        job_nonce: job.job_nonce,
        job_descriptor_digest: job.descriptor_digest,
        parser_job_session_binding_digest: job.parser_job_session_binding_digest,
        worker_artifact_digest: job.worker_artifact_digest,
        ephemeral_result_key_id: job.ephemeral_result_key_id,
        page_count,
        ordered_page_frame_transcript_digest: transcript_digest,
        extracted_byte_length: output.len() as u64,
        extracted_output_digest: parser_output_digest(output),
        completed_at,
    };
    let payload = encode_complete_payload(complete)?;
    let signature = ephemeral_signing_key
        .sign(&signature_input(RESULT_SIGNATURE_DOMAIN, sha256(&payload)))
        .to_bytes();
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(4)
        .and_then(|encoder| encoder.u16(2))
        .and_then(|encoder| encoder.bytes(&payload))
        .and_then(|encoder| encoder.bytes(job.ephemeral_result_key_id.as_bytes()))
        .and_then(|encoder| encoder.bytes(&signature))
        .map_err(|_| ParserWorkerProtocolErrorV2::Bounds)?;
    Ok(encoder.into_writer())
}

pub(crate) fn encode_parser_failed_frame(
    failure_class: u16,
) -> Result<Vec<u8>, ParserWorkerProtocolErrorV2> {
    if !(1..=8).contains(&failure_class) {
        return Err(ParserWorkerProtocolErrorV2::NonCanonical);
    }
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(2)
        .and_then(|encoder| encoder.u16(3))
        .and_then(|encoder| encoder.u16(failure_class))
        .map_err(|_| ParserWorkerProtocolErrorV2::Bounds)?;
    Ok(encoder.into_writer())
}

fn decode_job_payload(
    bytes: &[u8],
) -> Result<ParserWorkerJobPayloadV2, ParserWorkerProtocolErrorV2> {
    let mut decoder = minicbor::Decoder::new(bytes);
    require_array(&mut decoder, 16)?;
    if decoder
        .u16()
        .map_err(|_| ParserWorkerProtocolErrorV2::NonCanonical)?
        != 2
    {
        return Err(ParserWorkerProtocolErrorV2::NonCanonical);
    }
    let payload = ParserWorkerJobPayloadV2 {
        installation_id: Digest32V2::new(decode_fixed::<32>(&mut decoder)?),
        active_state_manifest_digest: Digest32V2::new(decode_fixed::<32>(&mut decoder)?),
        deployment_generation: decoder
            .u64()
            .map_err(|_| ParserWorkerProtocolErrorV2::NonCanonical)?,
        ingressd_identity: ServiceIdentityV2::new(decode_fixed::<32>(&mut decoder)?),
        job_nonce: Nonce32V2::new(decode_fixed::<32>(&mut decoder)?),
        parser_job_session_binding_digest: Digest32V2::new(decode_fixed::<32>(&mut decoder)?),
        original_byte_length: decoder
            .u64()
            .map_err(|_| ParserWorkerProtocolErrorV2::NonCanonical)?,
        original_sha256: Digest32V2::new(decode_fixed::<32>(&mut decoder)?),
        worker_artifact_digest: Digest32V2::new(decode_fixed::<32>(&mut decoder)?),
        output_limit_bytes: decoder
            .u32()
            .map_err(|_| ParserWorkerProtocolErrorV2::NonCanonical)?,
        maximum_pages: decoder
            .u32()
            .map_err(|_| ParserWorkerProtocolErrorV2::NonCanonical)?,
        anonymous_channel_binding_digest: Digest32V2::new(decode_fixed::<32>(&mut decoder)?),
        ephemeral_result_public_key: decode_fixed::<32>(&mut decoder)?,
        ephemeral_result_key_id: Ed25519KeyIdV2::new(decode_fixed::<32>(&mut decoder)?),
        expires_at: UnixMillisV2::new(
            decoder
                .u64()
                .map_err(|_| ParserWorkerProtocolErrorV2::NonCanonical)?,
        ),
    };
    if decoder.position() != bytes.len() {
        return Err(ParserWorkerProtocolErrorV2::NonCanonical);
    }
    Ok(payload)
}

fn encode_job_payload(
    payload: ParserWorkerJobPayloadV2,
) -> Result<Vec<u8>, ParserWorkerProtocolErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(16)
        .and_then(|encoder| encoder.u16(2))
        .and_then(|encoder| encoder.bytes(payload.installation_id.as_bytes()))
        .and_then(|encoder| encoder.bytes(payload.active_state_manifest_digest.as_bytes()))
        .and_then(|encoder| encoder.u64(payload.deployment_generation))
        .and_then(|encoder| encoder.bytes(payload.ingressd_identity.as_bytes()))
        .and_then(|encoder| encoder.bytes(payload.job_nonce.as_bytes()))
        .and_then(|encoder| encoder.bytes(payload.parser_job_session_binding_digest.as_bytes()))
        .and_then(|encoder| encoder.u64(payload.original_byte_length))
        .and_then(|encoder| encoder.bytes(payload.original_sha256.as_bytes()))
        .and_then(|encoder| encoder.bytes(payload.worker_artifact_digest.as_bytes()))
        .and_then(|encoder| encoder.u32(payload.output_limit_bytes))
        .and_then(|encoder| encoder.u32(payload.maximum_pages))
        .and_then(|encoder| encoder.bytes(payload.anonymous_channel_binding_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(&payload.ephemeral_result_public_key))
        .and_then(|encoder| encoder.bytes(payload.ephemeral_result_key_id.as_bytes()))
        .and_then(|encoder| encoder.u64(payload.expires_at.get()))
        .map_err(|_| ParserWorkerProtocolErrorV2::Bounds)?;
    Ok(encoder.into_writer())
}

fn decode_complete_payload(
    bytes: &[u8],
) -> Result<ParserWorkerCompleteFrameV2, ParserWorkerProtocolErrorV2> {
    let mut decoder = minicbor::Decoder::new(bytes);
    require_array(&mut decoder, 11)?;
    if decoder
        .u16()
        .map_err(|_| ParserWorkerProtocolErrorV2::NonCanonical)?
        != 2
    {
        return Err(ParserWorkerProtocolErrorV2::NonCanonical);
    }
    let complete = ParserWorkerCompleteFrameV2 {
        job_nonce: Nonce32V2::new(decode_fixed::<32>(&mut decoder)?),
        job_descriptor_digest: Digest32V2::new(decode_fixed::<32>(&mut decoder)?),
        parser_job_session_binding_digest: Digest32V2::new(decode_fixed::<32>(&mut decoder)?),
        worker_artifact_digest: Digest32V2::new(decode_fixed::<32>(&mut decoder)?),
        ephemeral_result_key_id: Ed25519KeyIdV2::new(decode_fixed::<32>(&mut decoder)?),
        page_count: decoder
            .u32()
            .map_err(|_| ParserWorkerProtocolErrorV2::NonCanonical)?,
        ordered_page_frame_transcript_digest: Digest32V2::new(decode_fixed::<32>(&mut decoder)?),
        extracted_byte_length: decoder
            .u64()
            .map_err(|_| ParserWorkerProtocolErrorV2::NonCanonical)?,
        extracted_output_digest: Digest32V2::new(decode_fixed::<32>(&mut decoder)?),
        completed_at: UnixMillisV2::new(
            decoder
                .u64()
                .map_err(|_| ParserWorkerProtocolErrorV2::NonCanonical)?,
        ),
    };
    if decoder.position() != bytes.len() {
        return Err(ParserWorkerProtocolErrorV2::NonCanonical);
    }
    Ok(complete)
}

fn encode_complete_payload(
    complete: ParserWorkerCompleteFrameV2,
) -> Result<Vec<u8>, ParserWorkerProtocolErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(11)
        .and_then(|encoder| encoder.u16(2))
        .and_then(|encoder| encoder.bytes(complete.job_nonce.as_bytes()))
        .and_then(|encoder| encoder.bytes(complete.job_descriptor_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(complete.parser_job_session_binding_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(complete.worker_artifact_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(complete.ephemeral_result_key_id.as_bytes()))
        .and_then(|encoder| encoder.u32(complete.page_count))
        .and_then(|encoder| encoder.bytes(complete.ordered_page_frame_transcript_digest.as_bytes()))
        .and_then(|encoder| encoder.u64(complete.extracted_byte_length))
        .and_then(|encoder| encoder.bytes(complete.extracted_output_digest.as_bytes()))
        .and_then(|encoder| encoder.u64(complete.completed_at.get()))
        .map_err(|_| ParserWorkerProtocolErrorV2::Bounds)?;
    Ok(encoder.into_writer())
}

fn encode_signed(
    payload: &[u8],
    key_id: Ed25519KeyIdV2,
    signature: &[u8; 64],
) -> Result<Vec<u8>, ParserWorkerProtocolErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(3)
        .and_then(|encoder| encoder.bytes(payload))
        .and_then(|encoder| encoder.bytes(key_id.as_bytes()))
        .and_then(|encoder| encoder.bytes(signature))
        .map_err(|_| ParserWorkerProtocolErrorV2::Bounds)?;
    Ok(encoder.into_writer())
}

fn encode_page_frame_without_binding(
    job_nonce: Nonce32V2,
    page_index: u32,
    page_chunk_index: u32,
    final_chunk_for_page: bool,
    extracted_chunk: &[u8],
    extracted_chunk_digest: Digest32V2,
) -> Result<Vec<u8>, ParserWorkerProtocolErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(7)
        .and_then(|encoder| encoder.u16(1))
        .and_then(|encoder| encoder.bytes(job_nonce.as_bytes()))
        .and_then(|encoder| encoder.u32(page_index))
        .and_then(|encoder| encoder.u32(page_chunk_index))
        .and_then(|encoder| encoder.bool(final_chunk_for_page))
        .and_then(|encoder| encoder.bytes(extracted_chunk))
        .and_then(|encoder| encoder.bytes(extracted_chunk_digest.as_bytes()))
        .map_err(|_| ParserWorkerProtocolErrorV2::Bounds)?;
    Ok(encoder.into_writer())
}

fn require_array(
    decoder: &mut minicbor::Decoder<'_>,
    expected: u64,
) -> Result<(), ParserWorkerProtocolErrorV2> {
    if decoder
        .array()
        .map_err(|_| ParserWorkerProtocolErrorV2::NonCanonical)?
        != Some(expected)
    {
        return Err(ParserWorkerProtocolErrorV2::NonCanonical);
    }
    Ok(())
}

fn decode_fixed<const N: usize>(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<[u8; N], ParserWorkerProtocolErrorV2> {
    decoder
        .bytes()
        .map_err(|_| ParserWorkerProtocolErrorV2::NonCanonical)?
        .try_into()
        .map_err(|_| ParserWorkerProtocolErrorV2::NonCanonical)
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
        domain_hash, encode_complete_payload, encode_job_payload,
        encode_page_frame_without_binding, encode_signed, sha256, signature_input,
        ParserWorkerCompleteFrameV2, ParserWorkerJobPayloadV2, ParserWorkerProtocolErrorV2,
        JOB_DESCRIPTOR_SIGNATURE_DOMAIN, OUTPUT_DOMAIN, RESULT_SIGNATURE_DOMAIN,
    };
    use savana_kernel_protocol::v2::{
        Digest32V2, Ed25519KeyIdV2, Nonce32V2, ServiceIdentityV2, UnixMillisV2,
    };

    pub(crate) struct ParserFixtureV2 {
        pub(crate) descriptor: Vec<u8>,
        pub(crate) original: Vec<u8>,
        pub(crate) parent_public_key: [u8; 32],
        pub(crate) ephemeral_signing_key: SigningKey,
        pub(crate) ephemeral_key_id: Ed25519KeyIdV2,
    }

    pub(crate) fn fixture() -> ParserFixtureV2 {
        let original = b"verified original".to_vec();
        let parent = SigningKey::from_bytes(&[0x11; 32]);
        let ephemeral_signing_key = SigningKey::from_bytes(&[0x12; 32]);
        let ephemeral_key_id = Ed25519KeyIdV2::new([0x13; 32]);
        let payload = ParserWorkerJobPayloadV2 {
            installation_id: Digest32V2::new([1; 32]),
            active_state_manifest_digest: Digest32V2::new([2; 32]),
            deployment_generation: 3,
            ingressd_identity: ServiceIdentityV2::new([4; 32]),
            job_nonce: Nonce32V2::new([5; 32]),
            parser_job_session_binding_digest: Digest32V2::new([6; 32]),
            original_byte_length: original.len() as u64,
            original_sha256: Digest32V2::new(sha256(&original)),
            worker_artifact_digest: Digest32V2::new([7; 32]),
            output_limit_bytes: 1024,
            maximum_pages: 4,
            anonymous_channel_binding_digest: Digest32V2::new([8; 32]),
            ephemeral_result_public_key: ephemeral_signing_key.verifying_key().to_bytes(),
            ephemeral_result_key_id: ephemeral_key_id,
            expires_at: UnixMillisV2::new(1_000),
        };
        let payload_bytes = encode_job_payload(payload).unwrap();
        let signature = parent
            .sign(&signature_input(
                JOB_DESCRIPTOR_SIGNATURE_DOMAIN,
                sha256(&payload_bytes),
            ))
            .to_bytes();
        ParserFixtureV2 {
            descriptor: encode_signed(&payload_bytes, Ed25519KeyIdV2::new([9; 32]), &signature)
                .unwrap(),
            original,
            parent_public_key: parent.verifying_key().to_bytes(),
            ephemeral_signing_key,
            ephemeral_key_id,
        }
    }

    pub(crate) fn page_frame(
        nonce: Nonce32V2,
        page: u32,
        chunk_index: u32,
        final_chunk: bool,
        chunk: &[u8],
    ) -> Vec<u8> {
        let digest = Digest32V2::new(sha256(chunk));
        let canonical =
            encode_page_frame_without_binding(nonce, page, chunk_index, final_chunk, chunk, digest)
                .unwrap();
        let binding = domain_hash(OUTPUT_DOMAIN, &canonical);
        let mut encoder = minicbor::Encoder::new(Vec::new());
        encoder
            .array(8)
            .and_then(|encoder| encoder.u16(1))
            .and_then(|encoder| encoder.bytes(nonce.as_bytes()))
            .and_then(|encoder| encoder.u32(page))
            .and_then(|encoder| encoder.u32(chunk_index))
            .and_then(|encoder| encoder.bool(final_chunk))
            .and_then(|encoder| encoder.bytes(chunk))
            .and_then(|encoder| encoder.bytes(digest.as_bytes()))
            .and_then(|encoder| encoder.bytes(binding.as_bytes()))
            .unwrap();
        encoder.into_writer()
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn complete_frame(
        ephemeral: &SigningKey,
        ephemeral_key_id: Ed25519KeyIdV2,
        nonce: Nonce32V2,
        descriptor_digest: Digest32V2,
        transcript_digest: Digest32V2,
        page_count: u32,
        output: &[u8],
        completed_at: UnixMillisV2,
    ) -> Result<Vec<u8>, ParserWorkerProtocolErrorV2> {
        let complete = ParserWorkerCompleteFrameV2 {
            job_nonce: nonce,
            job_descriptor_digest: descriptor_digest,
            parser_job_session_binding_digest: Digest32V2::new([6; 32]),
            worker_artifact_digest: Digest32V2::new([7; 32]),
            ephemeral_result_key_id: ephemeral_key_id,
            page_count,
            ordered_page_frame_transcript_digest: transcript_digest,
            extracted_byte_length: output.len() as u64,
            extracted_output_digest: domain_hash(OUTPUT_DOMAIN, output),
            completed_at,
        };
        let payload = encode_complete_payload(complete)?;
        let signature = ephemeral
            .sign(&signature_input(RESULT_SIGNATURE_DOMAIN, sha256(&payload)))
            .to_bytes();
        let mut encoder = minicbor::Encoder::new(Vec::new());
        encoder
            .array(4)
            .and_then(|encoder| encoder.u16(2))
            .and_then(|encoder| encoder.bytes(&payload))
            .and_then(|encoder| encoder.bytes(ephemeral_key_id.as_bytes()))
            .and_then(|encoder| encoder.bytes(&signature))
            .map_err(|_| ParserWorkerProtocolErrorV2::Bounds)?;
        Ok(encoder.into_writer())
    }
}
