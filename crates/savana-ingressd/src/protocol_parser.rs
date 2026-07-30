use std::fs;
use std::io::{self, Read as _, Write as _};
use std::os::fd::{AsFd as _, AsRawFd};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use nix::fcntl::{fcntl, FcntlArg, OFlag};
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use savana_kernel_protocol::v2::{
    decode_parser_worker_page_frame_v2, decode_signed_parser_worker_job_descriptor_v2,
    decode_signed_parser_worker_result_attestation_v2, derive_ed25519_key_id_v2,
    encode_parser_worker_page_frame_v2, encode_signed_parser_worker_job_descriptor_v2,
    encode_signed_parser_worker_result_attestation_v2, parser_worker_transcript_begin_v2,
    parser_worker_transcript_step_v2, ClosedConfidenceClassV2, ClosedExtensionClassV2,
    ClosedMediaTypeV2, Digest32V2, Ed25519KeyIdV2, FixedBytes32V2, ImplementationIdV2, Nonce32V2,
    PageProvenanceV2, ParserWorkerPageFrameV2, ServiceIdentityV2,
    SignedParserWorkerJobDescriptorV2, SignedParserWorkerResultAttestationV2, UnixMillisV2,
    UnsignedParserWorkerJobDescriptorV2, UnsignedParserWorkerResultAttestationV2,
    VerifiedParserWorkerJobDescriptorV2, VersionV2, ZeroizingBytesV2,
};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

const MAX_ORIGINAL_BYTES_V2: usize = 8 * 1024 * 1024;
const MAX_PAGE_FRAME_BYTES_V2: usize = 512 * 1024;
const MAX_CHILD_FRAME_BYTES_V2: usize = 16 * 1024 * 1024;
const MAX_PAGE_FRAMES_V2: usize = 8_192;
const EXTRACTED_CHUNK_BYTES_V2: usize = 256 * 1024;
const OUTPUT_LIMITS_DOMAIN_V2: &[u8] = b"SAVANA_PARSER_OUTPUT_LIMITS_V2\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ProtocolParserErrorV2 {
    #[error("the verified parser deployment is invalid")]
    Deployment,
    #[error("the parser sandbox could not be launched")]
    Launch,
    #[error("the parser job exceeded its deadline")]
    Deadline,
    #[error("the parser child violated its closed protocol")]
    Protocol,
    #[error("the parser rejected the document")]
    Rejected,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ParserProfileV2 {
    pub(crate) declared_media_type: ClosedMediaTypeV2,
    pub(crate) detected_media_type: ClosedMediaTypeV2,
    pub(crate) extension_class: ClosedExtensionClassV2,
    pub(crate) implementation_id: ImplementationIdV2,
    pub(crate) semantic_version: VersionV2,
    pub(crate) parser_code_digest: Digest32V2,
    pub(crate) renderer_code_digest: Option<Digest32V2>,
    pub(crate) ocr_model_set_digest: Option<Digest32V2>,
    pub(crate) normalization_version: VersionV2,
    pub(crate) worker_artifact_digest: Digest32V2,
    pub(crate) output_limit_bytes: u32,
    pub(crate) maximum_pages: u32,
}

pub(crate) struct ProtocolParserRuntimeV2 {
    installation_id: Digest32V2,
    active_state_manifest_digest: Digest32V2,
    deployment_generation: u64,
    ingressd_identity: ServiceIdentityV2,
    descriptor_signing_key: SigningKey,
    profile: ParserProfileV2,
    output_limits_digest: Digest32V2,
    sandbox_program: PathBuf,
    worker_program: PathBuf,
    sandbox_profile: PathBuf,
}

impl core::fmt::Debug for ProtocolParserRuntimeV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ProtocolParserRuntimeV2")
            .field("deployment_generation", &self.deployment_generation)
            .field("profile", &self.profile)
            .finish_non_exhaustive()
    }
}

pub(crate) struct PreparedProtocolParserJobV2 {
    child: ProtocolParserChildV2,
    ephemeral_public_key: [u8; 32],
    ephemeral_key_id: Ed25519KeyIdV2,
}

pub(crate) struct ProtocolParserOutputV2 {
    pub(crate) descriptor: SignedParserWorkerJobDescriptorV2,
    pub(crate) verified_job: VerifiedParserWorkerJobDescriptorV2,
    pub(crate) frames: Vec<ParserWorkerPageFrameV2>,
    pub(crate) attestation: SignedParserWorkerResultAttestationV2,
}

impl ProtocolParserRuntimeV2 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_verified_deployment(
        installation_id: Digest32V2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        ingressd_identity: ServiceIdentityV2,
        descriptor_signing_key: SigningKey,
        expected_descriptor_key_id: Ed25519KeyIdV2,
        profile: ParserProfileV2,
        expected_output_limits_digest: Digest32V2,
        sandbox_program: PathBuf,
        sandbox_program_digest: Digest32V2,
        worker_program: PathBuf,
        sandbox_profile: PathBuf,
        sandbox_profile_digest: Digest32V2,
        owner_uid: u32,
        owner_gid: u32,
    ) -> Result<Self, ProtocolParserErrorV2> {
        let computed_limits =
            parser_output_limits_digest_v2(profile.output_limit_bytes, profile.maximum_pages)
                .ok_or(ProtocolParserErrorV2::Deployment)?;
        if installation_id.as_bytes() == &[0; 32]
            || active_state_manifest_digest.as_bytes() == &[0; 32]
            || deployment_generation == 0
            || ingressd_identity.as_bytes() == &[0; 32]
            || derive_ed25519_key_id_v2(descriptor_signing_key.verifying_key().to_bytes())
                != expected_descriptor_key_id
            || profile.declared_media_type.get() == 0
            || profile.detected_media_type.get() == 0
            || profile.extension_class.get() == 0
            || profile.implementation_id.get() == 0
            || profile.worker_artifact_digest.as_bytes() == &[0; 32]
            || profile.parser_code_digest.as_bytes() == &[0; 32]
            || (profile.semantic_version.major() == 0
                && profile.semantic_version.minor() == 0
                && profile.semantic_version.patch() == 0)
            || (profile.normalization_version.major() == 0
                && profile.normalization_version.minor() == 0
                && profile.normalization_version.patch() == 0)
            || profile
                .renderer_code_digest
                .is_some_and(|digest| digest.as_bytes() == &[0; 32])
            || profile
                .ocr_model_set_digest
                .is_some_and(|digest| digest.as_bytes() == &[0; 32])
            || computed_limits != expected_output_limits_digest
        {
            return Err(ProtocolParserErrorV2::Deployment);
        }
        verify_measured_file(
            &sandbox_program,
            sandbox_program_digest,
            owner_uid,
            owner_gid,
            true,
        )?;
        verify_measured_file(
            &worker_program,
            profile.worker_artifact_digest,
            owner_uid,
            owner_gid,
            true,
        )?;
        verify_measured_file(
            &sandbox_profile,
            sandbox_profile_digest,
            owner_uid,
            owner_gid,
            false,
        )?;
        Ok(Self {
            installation_id,
            active_state_manifest_digest,
            deployment_generation,
            ingressd_identity,
            descriptor_signing_key,
            profile,
            output_limits_digest: computed_limits,
            sandbox_program,
            worker_program,
            sandbox_profile,
        })
    }

    pub(crate) fn prepare(
        &self,
        deadline: Instant,
    ) -> Result<PreparedProtocolParserJobV2, ProtocolParserErrorV2> {
        if Instant::now() >= deadline {
            return Err(ProtocolParserErrorV2::Deadline);
        }
        let mut child = Command::new(&self.sandbox_program)
            .arg("--profile")
            .arg(&self.sandbox_profile)
            .arg("--")
            .arg(&self.worker_program)
            .env_clear()
            .current_dir("/")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| ProtocolParserErrorV2::Launch)?;
        let stdin = child.stdin.take().ok_or(ProtocolParserErrorV2::Launch)?;
        let stdout = child.stdout.take().ok_or(ProtocolParserErrorV2::Launch)?;
        set_nonblocking(&stdin)?;
        set_nonblocking(&stdout)?;
        let mut child = ProtocolParserChildV2 {
            child,
            stdin: Some(stdin),
            stdout: Some(stdout),
            reaped: false,
        };
        let init = child
            .read_frame(MAX_PAGE_FRAME_BYTES_V2, deadline)?
            .ok_or(ProtocolParserErrorV2::Protocol)?;
        let (ephemeral_public_key, ephemeral_key_id) = decode_init(&init)?;
        if derive_ed25519_key_id_v2(ephemeral_public_key) != ephemeral_key_id {
            return Err(ProtocolParserErrorV2::Protocol);
        }
        Ok(PreparedProtocolParserJobV2 {
            child,
            ephemeral_public_key,
            ephemeral_key_id,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn execute(
        &self,
        mut prepared: PreparedProtocolParserJobV2,
        parser_job_session_binding_digest: Digest32V2,
        original: Zeroizing<Vec<u8>>,
        original_digest: Digest32V2,
        now: UnixMillisV2,
        expires_at: UnixMillisV2,
        deadline: Instant,
    ) -> Result<ProtocolParserOutputV2, ProtocolParserErrorV2> {
        if original.is_empty()
            || original.len() > MAX_ORIGINAL_BYTES_V2
            || Digest32V2::new(Sha256::digest(original.as_slice()).into()) != original_digest
            || now.get() == 0
            || now.get() >= expires_at.get()
        {
            return Err(ProtocolParserErrorV2::Rejected);
        }
        let job_nonce = Nonce32V2::new(draw_nonzero()?);
        let unsigned = UnsignedParserWorkerJobDescriptorV2::new(
            self.installation_id,
            self.active_state_manifest_digest,
            self.deployment_generation,
            self.ingressd_identity,
            job_nonce,
            parser_job_session_binding_digest,
            original.len() as u64,
            original_digest,
            self.profile.declared_media_type,
            self.profile.detected_media_type,
            self.profile.worker_artifact_digest,
            self.profile.implementation_id,
            self.profile.parser_code_digest,
            self.profile.renderer_code_digest,
            self.profile.ocr_model_set_digest,
            self.profile.normalization_version,
            self.output_limits_digest,
            FixedBytes32V2::new(prepared.ephemeral_public_key),
            prepared.ephemeral_key_id,
            expires_at,
        )
        .map_err(|_| ProtocolParserErrorV2::Deployment)?;
        let descriptor =
            SignedParserWorkerJobDescriptorV2::sign(unsigned, &self.descriptor_signing_key)
                .map_err(|_| ProtocolParserErrorV2::Deployment)?;
        let verified_job = descriptor
            .verify(
                derive_ed25519_key_id_v2(self.descriptor_signing_key.verifying_key().to_bytes()),
                self.descriptor_signing_key.verifying_key().to_bytes(),
                self.installation_id,
                self.active_state_manifest_digest,
                self.deployment_generation,
                self.ingressd_identity,
                parser_job_session_binding_digest,
                original.len() as u64,
                original_digest,
                now,
            )
            .map_err(|_| ProtocolParserErrorV2::Deployment)?;
        let descriptor_bytes = encode_signed_parser_worker_job_descriptor_v2(&descriptor)
            .map_err(|_| ProtocolParserErrorV2::Protocol)?;
        let job = encode_job(
            &descriptor_bytes,
            original.as_slice(),
            self.profile.output_limit_bytes,
            self.profile.maximum_pages,
            self.output_limits_digest,
            self.descriptor_signing_key.verifying_key().to_bytes(),
        )?;
        prepared.child.write_frame(&job, deadline)?;

        let mut frames = Vec::new();
        let mut output_hasher = Sha256::new();
        let mut output_length = 0_u64;
        let mut transcript =
            parser_worker_transcript_begin_v2(job_nonce, verified_job.descriptor_digest())
                .map_err(|_| ProtocolParserErrorV2::Protocol)?;
        let mut expected_page = 0_u32;
        let mut expected_chunk = 0_u32;
        let attestation = loop {
            if frames.len() >= MAX_PAGE_FRAMES_V2 {
                return Err(ProtocolParserErrorV2::Protocol);
            }
            let frame = prepared
                .child
                .read_frame(MAX_PAGE_FRAME_BYTES_V2, deadline)?
                .ok_or(ProtocolParserErrorV2::Protocol)?;
            match decode_result(&frame)? {
                ChildResultV2::Page(page) => {
                    if page.job_nonce() != job_nonce
                        || page.page_index() != expected_page
                        || page.page_chunk_index() != expected_chunk
                        || page.extracted_chunk().is_empty()
                    {
                        return Err(ProtocolParserErrorV2::Protocol);
                    }
                    let next = parser_worker_transcript_step_v2(transcript, &page)
                        .map_err(|_| ProtocolParserErrorV2::Protocol)?;
                    if next != page.transcript_step_digest() {
                        return Err(ProtocolParserErrorV2::Protocol);
                    }
                    transcript = next;
                    output_hasher.update(page.extracted_chunk());
                    output_length = output_length
                        .checked_add(page.extracted_chunk().len() as u64)
                        .ok_or(ProtocolParserErrorV2::Protocol)?;
                    if output_length > self.profile.output_limit_bytes as u64 {
                        return Err(ProtocolParserErrorV2::Protocol);
                    }
                    if page.final_chunk_for_page() {
                        expected_page = expected_page
                            .checked_add(1)
                            .ok_or(ProtocolParserErrorV2::Protocol)?;
                        expected_chunk = 0;
                    } else {
                        expected_chunk = expected_chunk
                            .checked_add(1)
                            .ok_or(ProtocolParserErrorV2::Protocol)?;
                    }
                    frames.push(page);
                }
                ChildResultV2::Complete(attestation) => break *attestation,
                ChildResultV2::Failed => return Err(ProtocolParserErrorV2::Rejected),
            }
        };
        let verified_attestation = attestation
            .verify_for_job(
                verified_job,
                unix_now().map_err(|_| ProtocolParserErrorV2::Protocol)?,
            )
            .map_err(|_| ProtocolParserErrorV2::Protocol)?;
        if expected_page == 0
            || expected_page > self.profile.maximum_pages
            || verified_attestation.page_count() != expected_page
            || verified_attestation.ordered_page_frame_transcript_digest() != transcript
            || verified_attestation.extracted_byte_length() != output_length
            || verified_attestation.extracted_output_digest()
                != Digest32V2::new(output_hasher.finalize().into())
        {
            return Err(ProtocolParserErrorV2::Protocol);
        }
        prepared.child.finish(deadline)?;
        Ok(ProtocolParserOutputV2 {
            descriptor,
            verified_job,
            frames,
            attestation,
        })
    }

    pub(crate) const fn profile(&self) -> ParserProfileV2 {
        self.profile
    }
}

pub(crate) fn parser_output_limits_digest_v2(
    output_limit_bytes: u32,
    maximum_pages: u32,
) -> Option<Digest32V2> {
    if output_limit_bytes == 0
        || output_limit_bytes as usize > MAX_ORIGINAL_BYTES_V2
        || maximum_pages == 0
        || maximum_pages > 2_048
    {
        return None;
    }
    let mut hasher = Sha256::new();
    hasher.update(OUTPUT_LIMITS_DOMAIN_V2);
    hasher.update(output_limit_bytes.to_be_bytes());
    hasher.update(maximum_pages.to_be_bytes());
    Some(Digest32V2::new(hasher.finalize().into()))
}

enum ChildResultV2 {
    Page(ParserWorkerPageFrameV2),
    Complete(Box<SignedParserWorkerResultAttestationV2>),
    Failed,
}

fn decode_init(bytes: &[u8]) -> Result<([u8; 32], Ed25519KeyIdV2), ProtocolParserErrorV2> {
    let mut decoder = minicbor::Decoder::new(bytes);
    if decoder.array().ok() != Some(Some(3)) || decoder.u16().ok() != Some(0) {
        return Err(ProtocolParserErrorV2::Protocol);
    }
    let public: [u8; 32] = decoder
        .bytes()
        .map_err(|_| ProtocolParserErrorV2::Protocol)?
        .try_into()
        .map_err(|_| ProtocolParserErrorV2::Protocol)?;
    let key_id = Ed25519KeyIdV2::new(
        decoder
            .bytes()
            .map_err(|_| ProtocolParserErrorV2::Protocol)?
            .try_into()
            .map_err(|_| ProtocolParserErrorV2::Protocol)?,
    );
    let canonical = encode_init(public, key_id)?;
    if decoder.position() != bytes.len() || canonical != bytes {
        return Err(ProtocolParserErrorV2::Protocol);
    }
    Ok((public, key_id))
}

fn encode_init(public: [u8; 32], key_id: Ed25519KeyIdV2) -> Result<Vec<u8>, ProtocolParserErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(3)
        .and_then(|encoder| encoder.u16(0))
        .and_then(|encoder| encoder.bytes(&public))
        .and_then(|encoder| encoder.bytes(key_id.as_bytes()))
        .map_err(|_| ProtocolParserErrorV2::Protocol)?;
    Ok(encoder.into_writer())
}

fn encode_job(
    descriptor: &[u8],
    original: &[u8],
    output_limit_bytes: u32,
    maximum_pages: u32,
    output_limits_digest: Digest32V2,
    descriptor_public_key: [u8; 32],
) -> Result<Vec<u8>, ProtocolParserErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(7)
        .and_then(|encoder| encoder.u16(1))
        .and_then(|encoder| encoder.bytes(descriptor))
        .and_then(|encoder| encoder.bytes(original))
        .and_then(|encoder| encoder.u32(output_limit_bytes))
        .and_then(|encoder| encoder.u32(maximum_pages))
        .and_then(|encoder| encoder.bytes(output_limits_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(&descriptor_public_key))
        .map_err(|_| ProtocolParserErrorV2::Protocol)?;
    let value = encoder.into_writer();
    if value.len() > MAX_CHILD_FRAME_BYTES_V2 {
        return Err(ProtocolParserErrorV2::Rejected);
    }
    Ok(value)
}

fn decode_result(bytes: &[u8]) -> Result<ChildResultV2, ProtocolParserErrorV2> {
    let mut decoder = minicbor::Decoder::new(bytes);
    if decoder.array().ok() != Some(Some(2)) {
        return Err(ProtocolParserErrorV2::Protocol);
    }
    let tag = decoder.u16().map_err(|_| ProtocolParserErrorV2::Protocol)?;
    let payload = decoder
        .bytes()
        .map_err(|_| ProtocolParserErrorV2::Protocol)?;
    if decoder.position() != bytes.len() {
        return Err(ProtocolParserErrorV2::Protocol);
    }
    match tag {
        1 => decode_parser_worker_page_frame_v2(payload)
            .map(ChildResultV2::Page)
            .map_err(|_| ProtocolParserErrorV2::Protocol),
        2 => decode_signed_parser_worker_result_attestation_v2(payload)
            .map(Box::new)
            .map(ChildResultV2::Complete)
            .map_err(|_| ProtocolParserErrorV2::Protocol),
        3 if payload == [1] => Ok(ChildResultV2::Failed),
        _ => Err(ProtocolParserErrorV2::Protocol),
    }
}

fn encode_result(tag: u16, payload: &[u8]) -> Result<Vec<u8>, ProtocolParserErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(2)
        .and_then(|encoder| encoder.u16(tag))
        .and_then(|encoder| encoder.bytes(payload))
        .map_err(|_| ProtocolParserErrorV2::Protocol)?;
    Ok(encoder.into_writer())
}

struct ProtocolParserChildV2 {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: Option<ChildStdout>,
    reaped: bool,
}

impl ProtocolParserChildV2 {
    fn write_frame(
        &mut self,
        payload: &[u8],
        deadline: Instant,
    ) -> Result<(), ProtocolParserErrorV2> {
        let length = u32::try_from(payload.len()).map_err(|_| ProtocolParserErrorV2::Protocol)?;
        let stdin = self.stdin.as_mut().ok_or(ProtocolParserErrorV2::Protocol)?;
        write_all_deadline(stdin, &length.to_be_bytes(), deadline)?;
        write_all_deadline(stdin, payload, deadline)
    }

    fn read_frame(
        &mut self,
        maximum: usize,
        deadline: Instant,
    ) -> Result<Option<Vec<u8>>, ProtocolParserErrorV2> {
        let stdout = self
            .stdout
            .as_mut()
            .ok_or(ProtocolParserErrorV2::Protocol)?;
        let mut header = [0_u8; 4];
        if !read_exact_or_eof(stdout, &mut header, deadline)? {
            return Ok(None);
        }
        let length = u32::from_be_bytes(header) as usize;
        if length == 0 || length > maximum {
            return Err(ProtocolParserErrorV2::Protocol);
        }
        let mut body = vec![0; length];
        if !read_exact_or_eof(stdout, &mut body, deadline)? {
            return Err(ProtocolParserErrorV2::Protocol);
        }
        Ok(Some(body))
    }

    fn finish(&mut self, deadline: Instant) -> Result<(), ProtocolParserErrorV2> {
        if self
            .read_frame(MAX_PAGE_FRAME_BYTES_V2, deadline)?
            .is_some()
        {
            return Err(ProtocolParserErrorV2::Protocol);
        }
        self.stdin.take();
        self.stdout.take();
        wait_success(&mut self.child, deadline)?;
        self.reaped = true;
        Ok(())
    }

    fn kill_and_reap(&mut self) {
        self.stdin.take();
        self.stdout.take();
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.reaped = true;
    }
}

impl Drop for ProtocolParserChildV2 {
    fn drop(&mut self) {
        if !self.reaped {
            self.kill_and_reap();
        }
    }
}

pub(crate) fn run_protocol_parser_worker_stdio_v2() -> Result<(), &'static str> {
    let mut seed = [0_u8; 32];
    getrandom::getrandom(&mut seed).map_err(|_| "parser entropy")?;
    if seed == [0; 32] {
        return Err("parser entropy");
    }
    let seed = Zeroizing::new(seed);
    let signing_key = SigningKey::from_bytes(&seed);
    let public_key = signing_key.verifying_key().to_bytes();
    let key_id = derive_ed25519_key_id_v2(public_key);
    let mut stdout = std::io::stdout().lock();
    write_blocking_frame(
        &mut stdout,
        &encode_init(public_key, key_id).map_err(|_| "init")?,
    )?;
    stdout.flush().map_err(|_| "init flush")?;

    let job_bytes = read_blocking_frame(std::io::stdin().lock(), MAX_CHILD_FRAME_BYTES_V2)?;
    let result = execute_child_job(&job_bytes, &signing_key, key_id);
    match result {
        Ok((frames, attestation)) => {
            for frame in frames {
                let payload =
                    encode_parser_worker_page_frame_v2(&frame).map_err(|_| "page encode")?;
                write_blocking_frame(
                    &mut stdout,
                    &encode_result(1, &payload).map_err(|_| "page wrapper")?,
                )?;
            }
            let payload = encode_signed_parser_worker_result_attestation_v2(&attestation)
                .map_err(|_| "attestation encode")?;
            write_blocking_frame(
                &mut stdout,
                &encode_result(2, &payload).map_err(|_| "attestation wrapper")?,
            )?;
        }
        Err(_) => write_blocking_frame(
            &mut stdout,
            &encode_result(3, &[1]).map_err(|_| "failure wrapper")?,
        )?,
    }
    stdout.flush().map_err(|_| "parser flush")
}

fn execute_child_job(
    bytes: &[u8],
    signing_key: &SigningKey,
    key_id: Ed25519KeyIdV2,
) -> Result<
    (
        Vec<ParserWorkerPageFrameV2>,
        SignedParserWorkerResultAttestationV2,
    ),
    ProtocolParserErrorV2,
> {
    let mut decoder = minicbor::Decoder::new(bytes);
    if decoder.array().ok() != Some(Some(7)) || decoder.u16().ok() != Some(1) {
        return Err(ProtocolParserErrorV2::Protocol);
    }
    let descriptor_bytes = decoder
        .bytes()
        .map_err(|_| ProtocolParserErrorV2::Protocol)?;
    let original = Zeroizing::new(
        decoder
            .bytes()
            .map_err(|_| ProtocolParserErrorV2::Protocol)?
            .to_vec(),
    );
    let output_limit_bytes = decoder.u32().map_err(|_| ProtocolParserErrorV2::Protocol)?;
    let maximum_pages = decoder.u32().map_err(|_| ProtocolParserErrorV2::Protocol)?;
    let output_limits_digest = Digest32V2::new(
        decoder
            .bytes()
            .map_err(|_| ProtocolParserErrorV2::Protocol)?
            .try_into()
            .map_err(|_| ProtocolParserErrorV2::Protocol)?,
    );
    let descriptor_public_key: [u8; 32] = decoder
        .bytes()
        .map_err(|_| ProtocolParserErrorV2::Protocol)?
        .try_into()
        .map_err(|_| ProtocolParserErrorV2::Protocol)?;
    if decoder.position() != bytes.len()
        || parser_output_limits_digest_v2(output_limit_bytes, maximum_pages)
            != Some(output_limits_digest)
        || original.is_empty()
        || original.len() > output_limit_bytes as usize
    {
        return Err(ProtocolParserErrorV2::Rejected);
    }
    let descriptor = decode_signed_parser_worker_job_descriptor_v2(descriptor_bytes)
        .map_err(|_| ProtocolParserErrorV2::Protocol)?;
    let now = unix_now()?;
    let verified = descriptor
        .verify_embedded_for_sandbox(descriptor.key_id(), descriptor_public_key, now)
        .map_err(|_| ProtocolParserErrorV2::Protocol)?;
    if verified.ephemeral_result_public_key().as_bytes() != &signing_key.verifying_key().to_bytes()
        || verified.ephemeral_result_key_id() != key_id
        || verified.output_limits_digest() != output_limits_digest
        || verified.original_byte_length() != original.len() as u64
        || verified.original_sha256() != Digest32V2::new(Sha256::digest(original.as_slice()).into())
        || maximum_pages == 0
    {
        return Err(ProtocolParserErrorV2::Protocol);
    }
    let text =
        std::str::from_utf8(original.as_slice()).map_err(|_| ProtocolParserErrorV2::Rejected)?;
    if text.chars().count() > u32::MAX as usize {
        return Err(ProtocolParserErrorV2::Rejected);
    }
    let chunks = original.chunks(EXTRACTED_CHUNK_BYTES_V2);
    let chunk_count = chunks.len();
    let chunk_count_u32 =
        u32::try_from(chunk_count).map_err(|_| ProtocolParserErrorV2::Rejected)?;
    let original_digest = verified.original_sha256();
    let mut transcript =
        parser_worker_transcript_begin_v2(verified.job_nonce(), verified.descriptor_digest())
            .map_err(|_| ProtocolParserErrorV2::Protocol)?;
    let mut frames = Vec::new();
    frames
        .try_reserve_exact(chunk_count)
        .map_err(|_| ProtocolParserErrorV2::Rejected)?;
    for (index, chunk) in original.chunks(EXTRACTED_CHUNK_BYTES_V2).enumerate() {
        let extracted_digest = Digest32V2::new(Sha256::digest(chunk).into());
        let placeholder = ParserWorkerPageFrameV2::new(
            verified.job_nonce(),
            0,
            u32::try_from(index).map_err(|_| ProtocolParserErrorV2::Rejected)?,
            index + 1 == chunk_count,
            original_digest,
            ZeroizingBytesV2::new(chunk.to_vec()).map_err(|_| ProtocolParserErrorV2::Rejected)?,
            extracted_digest,
            Digest32V2::new([1; 32]),
        )
        .map_err(|_| ProtocolParserErrorV2::Protocol)?;
        let next = parser_worker_transcript_step_v2(transcript, &placeholder)
            .map_err(|_| ProtocolParserErrorV2::Protocol)?;
        let frame = ParserWorkerPageFrameV2::new(
            verified.job_nonce(),
            0,
            u32::try_from(index).map_err(|_| ProtocolParserErrorV2::Rejected)?,
            index + 1 == chunk_count,
            original_digest,
            ZeroizingBytesV2::new(chunk.to_vec()).map_err(|_| ProtocolParserErrorV2::Rejected)?,
            extracted_digest,
            next,
        )
        .map_err(|_| ProtocolParserErrorV2::Protocol)?;
        transcript = next;
        frames.push(frame);
    }
    let page = PageProvenanceV2::new(
        0,
        0,
        chunk_count_u32,
        original.len() as u64,
        original_digest,
        original.len() as u64,
        original_digest,
        u32::try_from(text.chars().count()).map_err(|_| ProtocolParserErrorV2::Rejected)?,
        ClosedConfidenceClassV2::new(1),
    )
    .map_err(|_| ProtocolParserErrorV2::Protocol)?;
    let unsigned = UnsignedParserWorkerResultAttestationV2::new(
        verified.job_nonce(),
        verified.descriptor_digest(),
        verified.parser_job_session_binding_digest(),
        verified.worker_artifact_digest(),
        verified.ephemeral_result_key_id(),
        verified.original_byte_length(),
        verified.original_sha256(),
        1,
        vec![page],
        transcript,
        original.len() as u64,
        original_digest,
        now,
    )
    .map_err(|_| ProtocolParserErrorV2::Protocol)?;
    let attestation = SignedParserWorkerResultAttestationV2::sign(unsigned, signing_key)
        .map_err(|_| ProtocolParserErrorV2::Protocol)?;
    Ok((frames, attestation))
}

fn verify_measured_file(
    path: &Path,
    expected_digest: Digest32V2,
    owner_uid: u32,
    owner_gid: u32,
    executable: bool,
) -> Result<(), ProtocolParserErrorV2> {
    if !path.is_absolute() || expected_digest.as_bytes() == &[0; 32] {
        return Err(ProtocolParserErrorV2::Deployment);
    }
    for component in path
        .parent()
        .ok_or(ProtocolParserErrorV2::Deployment)?
        .ancestors()
    {
        let metadata =
            fs::symlink_metadata(component).map_err(|_| ProtocolParserErrorV2::Deployment)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || (metadata.mode() & 0o002 != 0 && metadata.mode() & 0o1000 == 0)
        {
            return Err(ProtocolParserErrorV2::Deployment);
        }
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| ProtocolParserErrorV2::Deployment)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != owner_uid
        || metadata.gid() != owner_gid
        || metadata.nlink() != 1
        || metadata.mode() & 0o022 != 0
        || (executable && metadata.mode() & 0o111 == 0)
    {
        return Err(ProtocolParserErrorV2::Deployment);
    }
    let bytes = fs::read(path).map_err(|_| ProtocolParserErrorV2::Deployment)?;
    if Digest32V2::new(Sha256::digest(&bytes).into()) != expected_digest {
        return Err(ProtocolParserErrorV2::Deployment);
    }
    Ok(())
}

fn set_nonblocking(file: &impl AsRawFd) -> Result<(), ProtocolParserErrorV2> {
    let raw = file.as_raw_fd();
    let flags = fcntl(raw, FcntlArg::F_GETFL)
        .map(OFlag::from_bits_truncate)
        .map_err(|_| ProtocolParserErrorV2::Launch)?;
    fcntl(raw, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK))
        .map(|_| ())
        .map_err(|_| ProtocolParserErrorV2::Launch)
}

fn write_all_deadline(
    output: &mut ChildStdin,
    mut bytes: &[u8],
    deadline: Instant,
) -> Result<(), ProtocolParserErrorV2> {
    while !bytes.is_empty() {
        poll_ready(output.as_fd(), PollFlags::POLLOUT, deadline)?;
        match output.write(bytes) {
            Ok(0) => return Err(ProtocolParserErrorV2::Protocol),
            Ok(written) => bytes = &bytes[written..],
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(_) => return Err(ProtocolParserErrorV2::Protocol),
        }
    }
    Ok(())
}

fn read_exact_or_eof(
    input: &mut ChildStdout,
    bytes: &mut [u8],
    deadline: Instant,
) -> Result<bool, ProtocolParserErrorV2> {
    let mut offset = 0;
    while offset < bytes.len() {
        poll_ready(input.as_fd(), PollFlags::POLLIN, deadline)?;
        match input.read(&mut bytes[offset..]) {
            Ok(0) if offset == 0 => return Ok(false),
            Ok(0) => return Err(ProtocolParserErrorV2::Protocol),
            Ok(read) => offset += read,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(_) => return Err(ProtocolParserErrorV2::Protocol),
        }
    }
    Ok(true)
}

fn poll_ready(
    descriptor: std::os::fd::BorrowedFd<'_>,
    interest: PollFlags,
    deadline: Instant,
) -> Result<(), ProtocolParserErrorV2> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(ProtocolParserErrorV2::Deadline);
    }
    let timeout = PollTimeout::try_from(remaining).unwrap_or(PollTimeout::MAX);
    let mut descriptors = [PollFd::new(descriptor, interest)];
    let ready = poll(&mut descriptors, timeout).map_err(|_| ProtocolParserErrorV2::Protocol)?;
    if ready == 0 {
        return Err(ProtocolParserErrorV2::Deadline);
    }
    let flags = descriptors[0]
        .revents()
        .ok_or(ProtocolParserErrorV2::Protocol)?;
    if flags.intersects(PollFlags::POLLERR | PollFlags::POLLNVAL) {
        return Err(ProtocolParserErrorV2::Protocol);
    }
    Ok(())
}

fn wait_success(child: &mut Child, deadline: Instant) -> Result<(), ProtocolParserErrorV2> {
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|_| ProtocolParserErrorV2::Protocol)?
        {
            return if status.success() {
                Ok(())
            } else {
                Err(ProtocolParserErrorV2::Protocol)
            };
        }
        if Instant::now() >= deadline {
            return Err(ProtocolParserErrorV2::Deadline);
        }
        std::thread::park_timeout(Duration::from_millis(1));
    }
}

fn write_blocking_frame(
    output: &mut impl std::io::Write,
    payload: &[u8],
) -> Result<(), &'static str> {
    let length = u32::try_from(payload.len()).map_err(|_| "parser frame length")?;
    output
        .write_all(&length.to_be_bytes())
        .and_then(|()| output.write_all(payload))
        .map_err(|_| "parser frame write")
}

fn read_blocking_frame(
    mut input: impl std::io::Read,
    maximum: usize,
) -> Result<Vec<u8>, &'static str> {
    let mut header = [0_u8; 4];
    input
        .read_exact(&mut header)
        .map_err(|_| "parser frame header")?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > maximum {
        return Err("parser frame bounds");
    }
    let mut body = vec![0; length];
    input
        .read_exact(&mut body)
        .map_err(|_| "parser frame body")?;
    Ok(body)
}

fn draw_nonzero() -> Result<[u8; 32], ProtocolParserErrorV2> {
    let mut bytes = [0_u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|_| ProtocolParserErrorV2::Protocol)?;
    if bytes == [0; 32] {
        Err(ProtocolParserErrorV2::Protocol)
    } else {
        Ok(bytes)
    }
}

fn unix_now() -> Result<UnixMillisV2, ProtocolParserErrorV2> {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| ProtocolParserErrorV2::Protocol)?
        .as_millis();
    let millis = u64::try_from(millis).map_err(|_| ProtocolParserErrorV2::Protocol)?;
    if millis == 0 {
        Err(ProtocolParserErrorV2::Protocol)
    } else {
        Ok(UnixMillisV2::new(millis))
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use savana_kernel_protocol::v2::{
        derive_ed25519_key_id_v2, encode_signed_parser_worker_job_descriptor_v2, ClosedMediaTypeV2,
        Digest32V2, FixedBytes32V2, ImplementationIdV2, Nonce32V2, ServiceIdentityV2,
        SignedParserWorkerJobDescriptorV2, UnixMillisV2, UnsignedParserWorkerJobDescriptorV2,
        VersionV2,
    };
    use sha2::{Digest as _, Sha256};

    use super::{encode_job, execute_child_job, parser_output_limits_digest_v2};

    #[test]
    fn output_limit_commitment_is_closed_and_nonzero() {
        let digest = parser_output_limits_digest_v2(1024, 4).unwrap();
        assert_ne!(digest.as_bytes(), &[0; 32]);
        assert_ne!(digest, parser_output_limits_digest_v2(1025, 4).unwrap());
        assert!(parser_output_limits_digest_v2(0, 4).is_none());
    }

    #[test]
    fn child_emits_protocol_native_frames_and_attestation() {
        let descriptor_key = SigningKey::from_bytes(&[0x41; 32]);
        let ephemeral_key = SigningKey::from_bytes(&[0x42; 32]);
        let original = b"verified utf8 document";
        let original_digest = Digest32V2::new(Sha256::digest(original).into());
        let limits = parser_output_limits_digest_v2(1024, 4).unwrap();
        let unsigned = UnsignedParserWorkerJobDescriptorV2::new(
            Digest32V2::new([1; 32]),
            Digest32V2::new([2; 32]),
            3,
            ServiceIdentityV2::new([4; 32]),
            Nonce32V2::new([5; 32]),
            Digest32V2::new([6; 32]),
            original.len() as u64,
            original_digest,
            ClosedMediaTypeV2::new(1),
            ClosedMediaTypeV2::new(1),
            Digest32V2::new([7; 32]),
            ImplementationIdV2::new(1),
            Digest32V2::new([8; 32]),
            None,
            None,
            VersionV2::new(1, 0, 0),
            limits,
            FixedBytes32V2::new(ephemeral_key.verifying_key().to_bytes()),
            derive_ed25519_key_id_v2(ephemeral_key.verifying_key().to_bytes()),
            UnixMillisV2::new(u64::MAX),
        )
        .unwrap();
        let descriptor =
            SignedParserWorkerJobDescriptorV2::sign(unsigned, &descriptor_key).unwrap();
        let descriptor_bytes = encode_signed_parser_worker_job_descriptor_v2(&descriptor).unwrap();
        let job = encode_job(
            &descriptor_bytes,
            original,
            1024,
            4,
            limits,
            descriptor_key.verifying_key().to_bytes(),
        )
        .unwrap();

        let (frames, attestation) = execute_child_job(
            &job,
            &ephemeral_key,
            derive_ed25519_key_id_v2(ephemeral_key.verifying_key().to_bytes()),
        )
        .unwrap();
        let verified = descriptor
            .verify(
                derive_ed25519_key_id_v2(descriptor_key.verifying_key().to_bytes()),
                descriptor_key.verifying_key().to_bytes(),
                Digest32V2::new([1; 32]),
                Digest32V2::new([2; 32]),
                3,
                ServiceIdentityV2::new([4; 32]),
                Digest32V2::new([6; 32]),
                original.len() as u64,
                original_digest,
                UnixMillisV2::new(1),
            )
            .unwrap();

        assert_eq!(frames.len(), 1);
        assert!(attestation
            .verify_for_job(verified, UnixMillisV2::new(u64::MAX - 1))
            .is_ok());
    }
}
