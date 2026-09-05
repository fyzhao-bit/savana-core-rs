use crate::{ProtocolError, StableCode};
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use sha2::{Digest as _, Sha256};

use super::{
    cbor::{scan_single, V2DecodeContext},
    derive_ed25519_key_id_v2, ApprovalPurposeV2, ClosedConfidenceClassV2, ClosedExtensionClassV2,
    ClosedMediaTypeV2, Digest32V2, Ed25519KeyIdV2, Ed25519SignatureV2, FixedBytes32V2,
    ImplementationIdV2, IngressKernelApprovalHandleV2, IngressUiAuthenticationPreparationHandleV2,
    IngressUiAuthorizationHandleV2, IngressWriteCapabilityV2, InputSessionHandleV2,
    KernelIngressBootstrapTransferCapabilityV2, ParserExtractionHandleV2, PendingIngressHandleV2,
    ServiceIdentityV2, SignedApprovalSettlementV2, SignedUiAuthenticationSettlementV2,
    UiAuthenticationPurposeV2, UnixMillisV2, VersionV2, ZeroizingBytesV2,
};

const MAX_INPUT_CHANNELS_V2: usize = 3;
const MAX_PAGE_PROVENANCE_V2: usize = 2048;
const INPUT_SESSION_INTERNAL_ID_DOMAIN: &[u8] = b"SAVANA_INPUT_SESSION_INTERNAL_ID_V2\0";
const INPUT_CHANNEL_BEGIN_DOMAIN: &[u8] = b"SAVANA_INPUT_CHANNEL_BEGIN_V2\0";
const INPUT_CHUNK_DOMAIN: &[u8] = b"SAVANA_INPUT_CHUNK_V2\0";
const INPUT_CHANNEL_STEP_DOMAIN: &[u8] = b"SAVANA_INPUT_CHANNEL_STEP_V2\0";
const INPUT_SOURCE_PROVENANCE_DOMAIN: &[u8] = b"SAVANA_INPUT_SOURCE_PROVENANCE_V2\0";
const PARSER_JOB_DESCRIPTOR_DOMAIN: &[u8] = b"SAVANA_PARSER_WORKER_JOB_DESCRIPTOR_V2\0";
const PARSER_JOB_DESCRIPTOR_SIGNATURE_DOMAIN: &[u8] =
    b"SAVANA_PARSER_WORKER_JOB_DESCRIPTOR_SIGNATURE_V2\0";
const PARSER_RESULT_SIGNATURE_DOMAIN: &[u8] = b"SAVANA_PARSER_WORKER_RESULT_SIGNATURE_V2\0";
const PARSER_TRANSCRIPT_BEGIN_DOMAIN: &[u8] = b"SAVANA_PARSER_WORKER_TRANSCRIPT_BEGIN_V2\0";
const PARSER_TRANSCRIPT_STEP_DOMAIN: &[u8] = b"SAVANA_PARSER_WORKER_TRANSCRIPT_STEP_V2\0";

macro_rules! closed_unit_enum_v2 {
    (
        $name:ident {
            $($variant:ident = $tag:literal),+ $(,)?
        }
    ) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum $name {
            $($variant),+
        }

        impl $name {
            pub const fn tag(self) -> u16 {
                match self {
                    $(Self::$variant => $tag),+
                }
            }

            fn from_tag(tag: u16) -> Result<Self, ProtocolError> {
                match tag {
                    $($tag => Ok(Self::$variant)),+,
                    _ => Err(malformed()),
                }
            }
        }

        impl<C> minicbor::Encode<C> for $name {
            fn encode<W: minicbor::encode::Write>(
                &self,
                encoder: &mut minicbor::Encoder<W>,
                _context: &mut C,
            ) -> Result<(), minicbor::encode::Error<W::Error>> {
                encoder.array(1)?.u16(self.tag())?;
                Ok(())
            }
        }

        impl<'bytes> minicbor::Decode<'bytes, V2DecodeContext> for $name {
            fn decode(
                decoder: &mut minicbor::Decoder<'bytes>,
                _context: &mut V2DecodeContext,
            ) -> Result<Self, minicbor::decode::Error> {
                let position = decoder.position();
                if decoder.array()? != Some(1) {
                    return Err(decode_error(position));
                }
                Self::from_tag(decoder.u16()?)
                    .map_err(|_| decode_error(position))
            }
        }
    };
}

closed_unit_enum_v2! {
    ContentKindV2 {
        ChatText = 1,
        PlainText = 2,
        ParsedDocument = 3,
    }
}

closed_unit_enum_v2! {
    InputChannelV2 {
        OriginalSource = 1,
        ExtractedPage = 2,
        ChatText = 3,
    }
}

closed_unit_enum_v2! {
    DirectInputChannelV2 {
        OriginalSource = 1,
        ChatText = 2,
    }
}

closed_unit_enum_v2! {
    InputSourceKindV2 {
        Chat = 1,
        Paste = 2,
        FileUpload = 3,
    }
}

pub fn input_session_internal_id_v2(session: InputSessionHandleV2) -> Digest32V2 {
    domain_hash_many(INPUT_SESSION_INTERNAL_ID_DOMAIN, &[session.as_bytes()])
}

pub fn input_channel_begin_digest_v2(
    session: InputSessionHandleV2,
    channel: InputChannelV2,
) -> Digest32V2 {
    let session_internal_id = input_session_internal_id_v2(session);
    domain_hash_many(
        INPUT_CHANNEL_BEGIN_DOMAIN,
        &[session_internal_id.as_bytes(), &channel.tag().to_be_bytes()],
    )
}

pub fn input_chunk_digest_v2(
    session: InputSessionHandleV2,
    channel: InputChannelV2,
    sequence: u32,
    chunk: &[u8],
) -> Result<Digest32V2, ProtocolError> {
    let length = u32::try_from(chunk.len()).map_err(|_| malformed())?;
    if chunk.is_empty() {
        return Err(malformed());
    }
    let session_internal_id = input_session_internal_id_v2(session);
    Ok(domain_hash_many(
        INPUT_CHUNK_DOMAIN,
        &[
            session_internal_id.as_bytes(),
            &channel.tag().to_be_bytes(),
            &sequence.to_be_bytes(),
            &length.to_be_bytes(),
            chunk,
        ],
    ))
}

pub fn input_channel_step_digest_v2(
    prior_cumulative_digest: Digest32V2,
    sequence: u32,
    chunk_digest: Digest32V2,
) -> Result<Digest32V2, ProtocolError> {
    if is_zero(prior_cumulative_digest.as_bytes()) || is_zero(chunk_digest.as_bytes()) {
        return Err(malformed());
    }
    Ok(domain_hash_many(
        INPUT_CHANNEL_STEP_DOMAIN,
        &[
            prior_cumulative_digest.as_bytes(),
            &sequence.to_be_bytes(),
            chunk_digest.as_bytes(),
        ],
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernelIngressHealthRequestV2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrepareIngressUiAuthenticationRequestV2 {
    transfer: KernelIngressBootstrapTransferCapabilityV2,
}

impl PrepareIngressUiAuthenticationRequestV2 {
    pub const fn new(transfer: KernelIngressBootstrapTransferCapabilityV2) -> Self {
        Self { transfer }
    }

    pub const fn transfer(self) -> KernelIngressBootstrapTransferCapabilityV2 {
        self.transfer
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticateIngressUiRequestV2 {
    authentication_preparation: IngressUiAuthenticationPreparationHandleV2,
    settlement: SignedUiAuthenticationSettlementV2,
}

impl AuthenticateIngressUiRequestV2 {
    pub fn new(
        authentication_preparation: IngressUiAuthenticationPreparationHandleV2,
        settlement: SignedUiAuthenticationSettlementV2,
    ) -> Result<Self, ProtocolError> {
        if settlement.purpose() != UiAuthenticationPurposeV2::IngressInput {
            return Err(malformed());
        }
        Ok(Self {
            authentication_preparation,
            settlement,
        })
    }

    pub const fn authentication_preparation(&self) -> IngressUiAuthenticationPreparationHandleV2 {
        self.authentication_preparation
    }

    pub const fn settlement(&self) -> &SignedUiAuthenticationSettlementV2 {
        &self.settlement
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BeginInputRequestV2 {
    ui_authorization: IngressUiAuthorizationHandleV2,
    content_kind: ContentKindV2,
    declared_total_bytes: u64,
    declared_content_digest: Option<Digest32V2>,
}

impl BeginInputRequestV2 {
    pub fn new(
        ui_authorization: IngressUiAuthorizationHandleV2,
        content_kind: ContentKindV2,
        declared_total_bytes: u64,
        declared_content_digest: Option<Digest32V2>,
    ) -> Result<Self, ProtocolError> {
        if declared_total_bytes == 0 || option_is_zero(declared_content_digest) {
            return Err(malformed());
        }
        Ok(Self {
            ui_authorization,
            content_kind,
            declared_total_bytes,
            declared_content_digest,
        })
    }

    pub const fn ui_authorization(self) -> IngressUiAuthorizationHandleV2 {
        self.ui_authorization
    }

    pub const fn content_kind(self) -> ContentKindV2 {
        self.content_kind
    }

    pub const fn declared_total_bytes(self) -> u64 {
        self.declared_total_bytes
    }

    pub const fn declared_content_digest(self) -> Option<Digest32V2> {
        self.declared_content_digest
    }
}

#[derive(Debug)]
pub struct AppendInputChunkRequestV2 {
    writer: IngressWriteCapabilityV2,
    channel: DirectInputChannelV2,
    sequence: u32,
    prior_cumulative_digest: Digest32V2,
    chunk: ZeroizingBytesV2,
    chunk_digest: Digest32V2,
    resulting_cumulative_digest: Digest32V2,
}

impl AppendInputChunkRequestV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        writer: IngressWriteCapabilityV2,
        channel: DirectInputChannelV2,
        sequence: u32,
        prior_cumulative_digest: Digest32V2,
        chunk: ZeroizingBytesV2,
        chunk_digest: Digest32V2,
        resulting_cumulative_digest: Digest32V2,
    ) -> Result<Self, ProtocolError> {
        if chunk.as_bytes().is_empty()
            || is_zero(prior_cumulative_digest.as_bytes())
            || is_zero(chunk_digest.as_bytes())
            || is_zero(resulting_cumulative_digest.as_bytes())
        {
            return Err(malformed());
        }
        Ok(Self {
            writer,
            channel,
            sequence,
            prior_cumulative_digest,
            chunk,
            chunk_digest,
            resulting_cumulative_digest,
        })
    }

    pub fn chunk(&self) -> &[u8] {
        self.chunk.as_bytes()
    }

    pub const fn writer(&self) -> IngressWriteCapabilityV2 {
        self.writer
    }

    pub const fn channel(&self) -> DirectInputChannelV2 {
        self.channel
    }

    pub const fn sequence(&self) -> u32 {
        self.sequence
    }

    pub const fn prior_cumulative_digest(&self) -> Digest32V2 {
        self.prior_cumulative_digest
    }

    pub const fn chunk_digest(&self) -> Digest32V2 {
        self.chunk_digest
    }

    pub const fn resulting_cumulative_digest(&self) -> Digest32V2 {
        self.resulting_cumulative_digest
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InputChannelCommitmentV2 {
    channel: InputChannelV2,
    chunk_count: u32,
    final_sequence: u32,
    total_length: u64,
    final_cumulative_digest: Digest32V2,
}

impl InputChannelCommitmentV2 {
    pub fn new(
        channel: InputChannelV2,
        chunk_count: u32,
        final_sequence: u32,
        total_length: u64,
        final_cumulative_digest: Digest32V2,
    ) -> Result<Self, ProtocolError> {
        if chunk_count == 0
            || final_sequence.checked_add(1) != Some(chunk_count)
            || total_length == 0
            || is_zero(final_cumulative_digest.as_bytes())
        {
            return Err(malformed());
        }
        Ok(Self {
            channel,
            chunk_count,
            final_sequence,
            total_length,
            final_cumulative_digest,
        })
    }

    pub const fn channel(self) -> InputChannelV2 {
        self.channel
    }

    pub const fn chunk_count(self) -> u32 {
        self.chunk_count
    }

    pub const fn final_sequence(self) -> u32 {
        self.final_sequence
    }

    pub const fn total_length(self) -> u64 {
        self.total_length
    }

    pub const fn final_cumulative_digest(self) -> Digest32V2 {
        self.final_cumulative_digest
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageProvenanceV2 {
    page_index: u32,
    extracted_channel_first_sequence: u32,
    extracted_channel_chunk_count: u32,
    rendered_byte_length: u64,
    rendered_input_digest: Digest32V2,
    extracted_byte_length: u64,
    extracted_text_digest: Digest32V2,
    character_count: u32,
    confidence_class: ClosedConfidenceClassV2,
}

impl PageProvenanceV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        page_index: u32,
        extracted_channel_first_sequence: u32,
        extracted_channel_chunk_count: u32,
        rendered_byte_length: u64,
        rendered_input_digest: Digest32V2,
        extracted_byte_length: u64,
        extracted_text_digest: Digest32V2,
        character_count: u32,
        confidence_class: ClosedConfidenceClassV2,
    ) -> Result<Self, ProtocolError> {
        if extracted_channel_chunk_count == 0
            || rendered_byte_length == 0
            || is_zero(rendered_input_digest.as_bytes())
            || extracted_byte_length == 0
            || is_zero(extracted_text_digest.as_bytes())
            || character_count == 0
            || confidence_class.get() == 0
        {
            return Err(malformed());
        }
        Ok(Self {
            page_index,
            extracted_channel_first_sequence,
            extracted_channel_chunk_count,
            rendered_byte_length,
            rendered_input_digest,
            extracted_byte_length,
            extracted_text_digest,
            character_count,
            confidence_class,
        })
    }

    pub const fn page_index(self) -> u32 {
        self.page_index
    }

    pub const fn extracted_channel_first_sequence(self) -> u32 {
        self.extracted_channel_first_sequence
    }

    pub const fn extracted_channel_chunk_count(self) -> u32 {
        self.extracted_channel_chunk_count
    }

    pub const fn rendered_byte_length(self) -> u64 {
        self.rendered_byte_length
    }

    pub const fn rendered_input_digest(self) -> Digest32V2 {
        self.rendered_input_digest
    }

    pub const fn extracted_byte_length(self) -> u64 {
        self.extracted_byte_length
    }

    pub const fn extracted_text_digest(self) -> Digest32V2 {
        self.extracted_text_digest
    }

    pub const fn character_count(self) -> u32 {
        self.character_count
    }

    pub const fn confidence_class(self) -> ClosedConfidenceClassV2 {
        self.confidence_class
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnsignedParserWorkerJobDescriptorV2 {
    installation_id: Digest32V2,
    active_state_manifest_digest: Digest32V2,
    deployment_generation: u64,
    ingressd_identity: ServiceIdentityV2,
    job_nonce: super::Nonce32V2,
    parser_job_session_binding_digest: Digest32V2,
    original_byte_length: u64,
    original_sha256: Digest32V2,
    declared_media_type: ClosedMediaTypeV2,
    detected_media_type: ClosedMediaTypeV2,
    worker_artifact_digest: Digest32V2,
    parser_implementation_id: ImplementationIdV2,
    parser_code_digest: Digest32V2,
    renderer_code_digest: Option<Digest32V2>,
    ocr_model_set_digest: Option<Digest32V2>,
    normalization_version: VersionV2,
    output_limits_digest: Digest32V2,
    ephemeral_result_public_key: FixedBytes32V2,
    ephemeral_result_key_id: Ed25519KeyIdV2,
    expires_at: UnixMillisV2,
}

impl UnsignedParserWorkerJobDescriptorV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        installation_id: Digest32V2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        ingressd_identity: ServiceIdentityV2,
        job_nonce: super::Nonce32V2,
        parser_job_session_binding_digest: Digest32V2,
        original_byte_length: u64,
        original_sha256: Digest32V2,
        declared_media_type: ClosedMediaTypeV2,
        detected_media_type: ClosedMediaTypeV2,
        worker_artifact_digest: Digest32V2,
        parser_implementation_id: ImplementationIdV2,
        parser_code_digest: Digest32V2,
        renderer_code_digest: Option<Digest32V2>,
        ocr_model_set_digest: Option<Digest32V2>,
        normalization_version: VersionV2,
        output_limits_digest: Digest32V2,
        ephemeral_result_public_key: FixedBytes32V2,
        ephemeral_result_key_id: Ed25519KeyIdV2,
        expires_at: UnixMillisV2,
    ) -> Result<Self, ProtocolError> {
        if is_zero(installation_id.as_bytes())
            || is_zero(active_state_manifest_digest.as_bytes())
            || deployment_generation == 0
            || is_zero(ingressd_identity.as_bytes())
            || is_zero(job_nonce.as_bytes())
            || is_zero(parser_job_session_binding_digest.as_bytes())
            || original_byte_length == 0
            || is_zero(original_sha256.as_bytes())
            || declared_media_type.get() == 0
            || detected_media_type.get() == 0
            || is_zero(worker_artifact_digest.as_bytes())
            || parser_implementation_id.get() == 0
            || is_zero(parser_code_digest.as_bytes())
            || option_is_zero(renderer_code_digest)
            || option_is_zero(ocr_model_set_digest)
            || version_is_zero(normalization_version)
            || is_zero(output_limits_digest.as_bytes())
            || is_zero(ephemeral_result_public_key.as_bytes())
            || is_zero(ephemeral_result_key_id.as_bytes())
            || expires_at.get() == 0
        {
            return Err(malformed());
        }
        Ok(Self {
            installation_id,
            active_state_manifest_digest,
            deployment_generation,
            ingressd_identity,
            job_nonce,
            parser_job_session_binding_digest,
            original_byte_length,
            original_sha256,
            declared_media_type,
            detected_media_type,
            worker_artifact_digest,
            parser_implementation_id,
            parser_code_digest,
            renderer_code_digest,
            ocr_model_set_digest,
            normalization_version,
            output_limits_digest,
            ephemeral_result_public_key,
            ephemeral_result_key_id,
            expires_at,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedParserWorkerJobDescriptorV2 {
    unsigned: UnsignedParserWorkerJobDescriptorV2,
    key_id: Ed25519KeyIdV2,
    signature: Ed25519SignatureV2,
}

impl SignedParserWorkerJobDescriptorV2 {
    pub fn sign(
        unsigned: UnsignedParserWorkerJobDescriptorV2,
        signing_key: &SigningKey,
    ) -> Result<Self, ProtocolError> {
        let payload = encode_unsigned_parser_worker_job_descriptor(&unsigned)?;
        let signature = signing_key
            .sign(&signature_input(
                PARSER_JOB_DESCRIPTOR_SIGNATURE_DOMAIN,
                &payload,
            ))
            .to_bytes();
        Self::from_parts(
            unsigned,
            derive_ed25519_key_id_v2(signing_key.verifying_key().to_bytes()),
            Ed25519SignatureV2::new(signature),
        )
    }

    pub fn from_parts(
        unsigned: UnsignedParserWorkerJobDescriptorV2,
        key_id: Ed25519KeyIdV2,
        signature: Ed25519SignatureV2,
    ) -> Result<Self, ProtocolError> {
        validate_signature_parts(key_id, signature)?;
        Ok(Self {
            unsigned,
            key_id,
            signature,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        expected_key_id: Ed25519KeyIdV2,
        verifying_key: [u8; 32],
        expected_installation_id: Digest32V2,
        expected_active_state_manifest_digest: Digest32V2,
        expected_deployment_generation: u64,
        expected_ingressd_identity: ServiceIdentityV2,
        expected_parser_job_session_binding_digest: Digest32V2,
        expected_original_byte_length: u64,
        expected_original_sha256: Digest32V2,
        now: UnixMillisV2,
    ) -> Result<VerifiedParserWorkerJobDescriptorV2, ProtocolError> {
        if self.key_id != expected_key_id
            || derive_ed25519_key_id_v2(verifying_key) != expected_key_id
        {
            return Err(ProtocolError::stable(
                StableCode::AttestationInvalidSignature,
            ));
        }
        let unsigned = self.unsigned;
        if unsigned.installation_id != expected_installation_id
            || unsigned.active_state_manifest_digest != expected_active_state_manifest_digest
            || unsigned.deployment_generation != expected_deployment_generation
            || unsigned.ingressd_identity != expected_ingressd_identity
            || unsigned.parser_job_session_binding_digest
                != expected_parser_job_session_binding_digest
            || unsigned.original_byte_length != expected_original_byte_length
            || unsigned.original_sha256 != expected_original_sha256
        {
            return Err(ProtocolError::stable(
                StableCode::AttestationBindingMismatch,
            ));
        }
        if now.get() == 0 || now.get() >= unsigned.expires_at.get() {
            return Err(ProtocolError::stable(StableCode::AttestationExpired));
        }
        if derive_ed25519_key_id_v2(*unsigned.ephemeral_result_public_key.as_bytes())
            != unsigned.ephemeral_result_key_id
        {
            return Err(ProtocolError::stable(
                StableCode::AttestationBindingMismatch,
            ));
        }
        let payload = encode_unsigned_parser_worker_job_descriptor(&unsigned)?;
        verify_signature(
            PARSER_JOB_DESCRIPTOR_SIGNATURE_DOMAIN,
            &payload,
            verifying_key,
            self.signature,
        )?;
        Ok(VerifiedParserWorkerJobDescriptorV2 {
            unsigned,
            descriptor_digest: domain_hash_many(PARSER_JOB_DESCRIPTOR_DOMAIN, &[&payload]),
        })
    }

    /// Verifies the signed descriptor against the bindings carried inside it.
    ///
    /// This is intentionally for the already sandboxed parser child. The
    /// ingress parent and kerneld must use [`Self::verify`] with independent
    /// deployment/session expectations before launching the child.
    pub fn verify_embedded_for_sandbox(
        &self,
        expected_key_id: Ed25519KeyIdV2,
        verifying_key: [u8; 32],
        now: UnixMillisV2,
    ) -> Result<VerifiedParserWorkerJobDescriptorV2, ProtocolError> {
        let unsigned = self.unsigned;
        self.verify(
            expected_key_id,
            verifying_key,
            unsigned.installation_id,
            unsigned.active_state_manifest_digest,
            unsigned.deployment_generation,
            unsigned.ingressd_identity,
            unsigned.parser_job_session_binding_digest,
            unsigned.original_byte_length,
            unsigned.original_sha256,
            now,
        )
    }

    pub const fn key_id(&self) -> Ed25519KeyIdV2 {
        self.key_id
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedParserWorkerJobDescriptorV2 {
    unsigned: UnsignedParserWorkerJobDescriptorV2,
    descriptor_digest: Digest32V2,
}

impl VerifiedParserWorkerJobDescriptorV2 {
    pub const fn descriptor_digest(self) -> Digest32V2 {
        self.descriptor_digest
    }

    pub const fn job_nonce(self) -> super::Nonce32V2 {
        self.unsigned.job_nonce
    }

    pub const fn parser_job_session_binding_digest(self) -> Digest32V2 {
        self.unsigned.parser_job_session_binding_digest
    }

    pub const fn worker_artifact_digest(self) -> Digest32V2 {
        self.unsigned.worker_artifact_digest
    }

    pub const fn parser_implementation_id(self) -> ImplementationIdV2 {
        self.unsigned.parser_implementation_id
    }

    pub const fn parser_code_digest(self) -> Digest32V2 {
        self.unsigned.parser_code_digest
    }

    pub const fn renderer_code_digest(self) -> Option<Digest32V2> {
        self.unsigned.renderer_code_digest
    }

    pub const fn ocr_model_set_digest(self) -> Option<Digest32V2> {
        self.unsigned.ocr_model_set_digest
    }

    pub const fn output_limits_digest(self) -> Digest32V2 {
        self.unsigned.output_limits_digest
    }

    pub const fn original_byte_length(self) -> u64 {
        self.unsigned.original_byte_length
    }

    pub const fn original_sha256(self) -> Digest32V2 {
        self.unsigned.original_sha256
    }

    pub const fn declared_media_type(self) -> ClosedMediaTypeV2 {
        self.unsigned.declared_media_type
    }

    pub const fn detected_media_type(self) -> ClosedMediaTypeV2 {
        self.unsigned.detected_media_type
    }

    pub const fn normalization_version(self) -> VersionV2 {
        self.unsigned.normalization_version
    }

    pub const fn ephemeral_result_public_key(self) -> FixedBytes32V2 {
        self.unsigned.ephemeral_result_public_key
    }

    pub const fn ephemeral_result_key_id(self) -> Ed25519KeyIdV2 {
        self.unsigned.ephemeral_result_key_id
    }

    pub const fn expires_at(self) -> UnixMillisV2 {
        self.unsigned.expires_at
    }
}

#[derive(Debug)]
pub struct ParserWorkerPageFrameV2 {
    job_nonce: super::Nonce32V2,
    page_index: u32,
    page_chunk_index: u32,
    final_chunk_for_page: bool,
    rendered_input_digest: Digest32V2,
    extracted_chunk: ZeroizingBytesV2,
    extracted_chunk_digest: Digest32V2,
    transcript_step_digest: Digest32V2,
}

impl ParserWorkerPageFrameV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        job_nonce: super::Nonce32V2,
        page_index: u32,
        page_chunk_index: u32,
        final_chunk_for_page: bool,
        rendered_input_digest: Digest32V2,
        extracted_chunk: ZeroizingBytesV2,
        extracted_chunk_digest: Digest32V2,
        transcript_step_digest: Digest32V2,
    ) -> Result<Self, ProtocolError> {
        if is_zero(job_nonce.as_bytes())
            || is_zero(rendered_input_digest.as_bytes())
            || extracted_chunk.as_bytes().is_empty()
            || is_zero(extracted_chunk_digest.as_bytes())
            || is_zero(transcript_step_digest.as_bytes())
        {
            return Err(malformed());
        }
        Ok(Self {
            job_nonce,
            page_index,
            page_chunk_index,
            final_chunk_for_page,
            rendered_input_digest,
            extracted_chunk,
            extracted_chunk_digest,
            transcript_step_digest,
        })
    }

    pub const fn job_nonce(&self) -> super::Nonce32V2 {
        self.job_nonce
    }

    pub const fn page_index(&self) -> u32 {
        self.page_index
    }

    pub const fn page_chunk_index(&self) -> u32 {
        self.page_chunk_index
    }

    pub const fn final_chunk_for_page(&self) -> bool {
        self.final_chunk_for_page
    }

    pub const fn rendered_input_digest(&self) -> Digest32V2 {
        self.rendered_input_digest
    }

    pub fn extracted_chunk(&self) -> &[u8] {
        self.extracted_chunk.as_bytes()
    }

    pub const fn extracted_chunk_digest(&self) -> Digest32V2 {
        self.extracted_chunk_digest
    }

    pub const fn transcript_step_digest(&self) -> Digest32V2 {
        self.transcript_step_digest
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsignedParserWorkerResultAttestationV2 {
    job_nonce: super::Nonce32V2,
    job_descriptor_digest: Digest32V2,
    parser_job_session_binding_digest: Digest32V2,
    worker_artifact_digest: Digest32V2,
    ephemeral_result_key_id: Ed25519KeyIdV2,
    original_byte_length: u64,
    original_sha256: Digest32V2,
    page_count: u32,
    page_records: Vec<PageProvenanceV2>,
    ordered_page_frame_transcript_digest: Digest32V2,
    extracted_byte_length: u64,
    extracted_output_digest: Digest32V2,
    completed_at: UnixMillisV2,
}

impl UnsignedParserWorkerResultAttestationV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        job_nonce: super::Nonce32V2,
        job_descriptor_digest: Digest32V2,
        parser_job_session_binding_digest: Digest32V2,
        worker_artifact_digest: Digest32V2,
        ephemeral_result_key_id: Ed25519KeyIdV2,
        original_byte_length: u64,
        original_sha256: Digest32V2,
        page_count: u32,
        page_records: Vec<PageProvenanceV2>,
        ordered_page_frame_transcript_digest: Digest32V2,
        extracted_byte_length: u64,
        extracted_output_digest: Digest32V2,
        completed_at: UnixMillisV2,
    ) -> Result<Self, ProtocolError> {
        if is_zero(job_nonce.as_bytes())
            || is_zero(job_descriptor_digest.as_bytes())
            || is_zero(parser_job_session_binding_digest.as_bytes())
            || is_zero(worker_artifact_digest.as_bytes())
            || is_zero(ephemeral_result_key_id.as_bytes())
            || original_byte_length == 0
            || is_zero(original_sha256.as_bytes())
            || page_count == 0
            || usize::try_from(page_count) != Ok(page_records.len())
            || page_records.len() > MAX_PAGE_PROVENANCE_V2
            || page_records
                .iter()
                .enumerate()
                .any(|(index, page)| usize::try_from(page.page_index) != Ok(index))
            || is_zero(ordered_page_frame_transcript_digest.as_bytes())
            || extracted_byte_length == 0
            || is_zero(extracted_output_digest.as_bytes())
            || completed_at.get() == 0
        {
            return Err(malformed());
        }
        Ok(Self {
            job_nonce,
            job_descriptor_digest,
            parser_job_session_binding_digest,
            worker_artifact_digest,
            ephemeral_result_key_id,
            original_byte_length,
            original_sha256,
            page_count,
            page_records,
            ordered_page_frame_transcript_digest,
            extracted_byte_length,
            extracted_output_digest,
            completed_at,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedParserWorkerResultAttestationV2 {
    unsigned: UnsignedParserWorkerResultAttestationV2,
    key_id: Ed25519KeyIdV2,
    signature: Ed25519SignatureV2,
}

impl SignedParserWorkerResultAttestationV2 {
    pub fn sign(
        unsigned: UnsignedParserWorkerResultAttestationV2,
        signing_key: &SigningKey,
    ) -> Result<Self, ProtocolError> {
        let payload = encode_unsigned_parser_worker_result_attestation(&unsigned)?;
        let signature = signing_key
            .sign(&signature_input(PARSER_RESULT_SIGNATURE_DOMAIN, &payload))
            .to_bytes();
        Self::from_parts(
            unsigned,
            derive_ed25519_key_id_v2(signing_key.verifying_key().to_bytes()),
            Ed25519SignatureV2::new(signature),
        )
    }

    pub fn from_parts(
        unsigned: UnsignedParserWorkerResultAttestationV2,
        key_id: Ed25519KeyIdV2,
        signature: Ed25519SignatureV2,
    ) -> Result<Self, ProtocolError> {
        validate_signature_parts(key_id, signature)?;
        if key_id != unsigned.ephemeral_result_key_id {
            return Err(malformed());
        }
        Ok(Self {
            unsigned,
            key_id,
            signature,
        })
    }

    pub fn verify_for_job(
        &self,
        job: VerifiedParserWorkerJobDescriptorV2,
        now: UnixMillisV2,
    ) -> Result<VerifiedParserWorkerResultAttestationV2, ProtocolError> {
        let unsigned = &self.unsigned;
        if self.key_id != job.ephemeral_result_key_id()
            || unsigned.job_nonce != job.job_nonce()
            || unsigned.job_descriptor_digest != job.descriptor_digest()
            || unsigned.parser_job_session_binding_digest != job.parser_job_session_binding_digest()
            || unsigned.worker_artifact_digest != job.worker_artifact_digest()
            || unsigned.ephemeral_result_key_id != job.ephemeral_result_key_id()
            || unsigned.original_byte_length != job.original_byte_length()
            || unsigned.original_sha256 != job.original_sha256()
        {
            return Err(ProtocolError::stable(
                StableCode::AttestationBindingMismatch,
            ));
        }
        if now.get() == 0
            || now.get() >= job.expires_at().get()
            || unsigned.completed_at.get() > now.get()
        {
            return Err(ProtocolError::stable(StableCode::AttestationExpired));
        }
        let payload = encode_unsigned_parser_worker_result_attestation(unsigned)?;
        verify_signature(
            PARSER_RESULT_SIGNATURE_DOMAIN,
            &payload,
            *job.ephemeral_result_public_key().as_bytes(),
            self.signature,
        )?;
        Ok(VerifiedParserWorkerResultAttestationV2 {
            unsigned: self.unsigned.clone(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedParserWorkerResultAttestationV2 {
    unsigned: UnsignedParserWorkerResultAttestationV2,
}

impl VerifiedParserWorkerResultAttestationV2 {
    pub fn page_records(&self) -> &[PageProvenanceV2] {
        &self.unsigned.page_records
    }

    pub const fn page_count(&self) -> u32 {
        self.unsigned.page_count
    }

    pub const fn ordered_page_frame_transcript_digest(&self) -> Digest32V2 {
        self.unsigned.ordered_page_frame_transcript_digest
    }

    pub const fn extracted_byte_length(&self) -> u64 {
        self.unsigned.extracted_byte_length
    }

    pub const fn extracted_output_digest(&self) -> Digest32V2 {
        self.unsigned.extracted_output_digest
    }

    pub const fn completed_at(&self) -> UnixMillisV2 {
        self.unsigned.completed_at
    }
}

pub fn parser_worker_transcript_begin_v2(
    job_nonce: super::Nonce32V2,
    descriptor_digest: Digest32V2,
) -> Result<Digest32V2, ProtocolError> {
    if is_zero(job_nonce.as_bytes()) || is_zero(descriptor_digest.as_bytes()) {
        return Err(malformed());
    }
    Ok(domain_hash_many(
        PARSER_TRANSCRIPT_BEGIN_DOMAIN,
        &[job_nonce.as_bytes(), descriptor_digest.as_bytes()],
    ))
}

pub fn parser_worker_transcript_step_v2(
    prior: Digest32V2,
    frame: &ParserWorkerPageFrameV2,
) -> Result<Digest32V2, ProtocolError> {
    if is_zero(prior.as_bytes())
        || Digest32V2::new(Sha256::digest(frame.extracted_chunk()).into())
            != frame.extracted_chunk_digest
    {
        return Err(malformed());
    }
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder.array(7).map_err(ProtocolError::malformed)?;
    encode_fixed(&mut encoder, &frame.job_nonce)?;
    encoder
        .u32(frame.page_index)
        .and_then(|encoder| encoder.u32(frame.page_chunk_index))
        .and_then(|encoder| encoder.bool(frame.final_chunk_for_page))
        .map_err(ProtocolError::malformed)?;
    encode_fixed(&mut encoder, &frame.rendered_input_digest)?;
    encode_fixed(&mut encoder, &frame.extracted_chunk)?;
    encode_fixed(&mut encoder, &frame.extracted_chunk_digest)?;
    Ok(domain_hash_many(
        PARSER_TRANSCRIPT_STEP_DOMAIN,
        &[prior.as_bytes(), &encoder.into_writer()],
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputSourceProvenanceV2 {
    Direct {
        source_kind: InputSourceKindV2,
        original_byte_length: u64,
        original_sha256: Digest32V2,
        normalization_version: VersionV2,
    },
    ParsedDocument {
        source_kind: InputSourceKindV2,
        original_byte_length: u64,
        original_sha256: Digest32V2,
        declared_media_type: ClosedMediaTypeV2,
        detected_media_type: ClosedMediaTypeV2,
        extension_class: ClosedExtensionClassV2,
        parser_implementation_id: ImplementationIdV2,
        parser_semantic_version: VersionV2,
        parser_code_digest: Digest32V2,
        renderer_code_digest: Option<Digest32V2>,
        ocr_model_set_digest: Option<Digest32V2>,
        normalization_version: VersionV2,
        page_records: Vec<PageProvenanceV2>,
        extracted_output_digest: Digest32V2,
    },
}

impl InputSourceProvenanceV2 {
    pub fn direct(
        source_kind: InputSourceKindV2,
        original_byte_length: u64,
        original_sha256: Digest32V2,
        normalization_version: VersionV2,
    ) -> Result<Self, ProtocolError> {
        if original_byte_length == 0
            || is_zero(original_sha256.as_bytes())
            || version_is_zero(normalization_version)
        {
            return Err(malformed());
        }
        Ok(Self::Direct {
            source_kind,
            original_byte_length,
            original_sha256,
            normalization_version,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn parsed_document(
        source_kind: InputSourceKindV2,
        original_byte_length: u64,
        original_sha256: Digest32V2,
        declared_media_type: ClosedMediaTypeV2,
        detected_media_type: ClosedMediaTypeV2,
        extension_class: ClosedExtensionClassV2,
        parser_implementation_id: ImplementationIdV2,
        parser_semantic_version: VersionV2,
        parser_code_digest: Digest32V2,
        renderer_code_digest: Option<Digest32V2>,
        ocr_model_set_digest: Option<Digest32V2>,
        normalization_version: VersionV2,
        page_records: Vec<PageProvenanceV2>,
        extracted_output_digest: Digest32V2,
    ) -> Result<Self, ProtocolError> {
        if source_kind != InputSourceKindV2::FileUpload
            || original_byte_length == 0
            || is_zero(original_sha256.as_bytes())
            || declared_media_type.get() == 0
            || detected_media_type.get() == 0
            || extension_class.get() == 0
            || parser_implementation_id.get() == 0
            || version_is_zero(parser_semantic_version)
            || is_zero(parser_code_digest.as_bytes())
            || option_is_zero(renderer_code_digest)
            || option_is_zero(ocr_model_set_digest)
            || version_is_zero(normalization_version)
            || page_records.is_empty()
            || page_records.len() > MAX_PAGE_PROVENANCE_V2
            || page_records
                .iter()
                .enumerate()
                .any(|(index, page)| usize::try_from(page.page_index) != Ok(index))
            || is_zero(extracted_output_digest.as_bytes())
        {
            return Err(malformed());
        }
        Ok(Self::ParsedDocument {
            source_kind,
            original_byte_length,
            original_sha256,
            declared_media_type,
            detected_media_type,
            extension_class,
            parser_implementation_id,
            parser_semantic_version,
            parser_code_digest,
            renderer_code_digest,
            ocr_model_set_digest,
            normalization_version,
            page_records,
            extracted_output_digest,
        })
    }
}

pub fn input_source_provenance_digest_v2(
    provenance: &InputSourceProvenanceV2,
) -> Result<Digest32V2, ProtocolError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encode_source_provenance(&mut encoder, provenance)?;
    Ok(domain_hash_many(
        INPUT_SOURCE_PROVENANCE_DOMAIN,
        &[&encoder.into_writer()],
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalizeInputRequestV2 {
    session: InputSessionHandleV2,
    channels: Vec<InputChannelCommitmentV2>,
    source_provenance: InputSourceProvenanceV2,
}

impl FinalizeInputRequestV2 {
    pub fn new(
        session: InputSessionHandleV2,
        channels: Vec<InputChannelCommitmentV2>,
        source_provenance: InputSourceProvenanceV2,
    ) -> Result<Self, ProtocolError> {
        if channels.is_empty()
            || channels.len() > MAX_INPUT_CHANNELS_V2
            || channels
                .windows(2)
                .any(|pair| pair[0].channel >= pair[1].channel)
        {
            return Err(malformed());
        }
        Ok(Self {
            session,
            channels,
            source_provenance,
        })
    }

    pub const fn session(&self) -> InputSessionHandleV2 {
        self.session
    }

    pub fn channels(&self) -> &[InputChannelCommitmentV2] {
        &self.channels
    }

    pub const fn source_provenance(&self) -> &InputSourceProvenanceV2 {
        &self.source_provenance
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitInputSettlementRequestV2 {
    pending: PendingIngressHandleV2,
    approval: IngressKernelApprovalHandleV2,
    settlement: SignedApprovalSettlementV2,
}

impl CommitInputSettlementRequestV2 {
    pub fn new(
        pending: PendingIngressHandleV2,
        approval: IngressKernelApprovalHandleV2,
        settlement: SignedApprovalSettlementV2,
    ) -> Result<Self, ProtocolError> {
        if settlement.purpose() != ApprovalPurposeV2::Ingress {
            return Err(malformed());
        }
        Ok(Self {
            pending,
            approval,
            settlement,
        })
    }

    pub const fn pending(&self) -> PendingIngressHandleV2 {
        self.pending
    }

    pub const fn approval(&self) -> IngressKernelApprovalHandleV2 {
        self.approval
    }

    pub const fn settlement(&self) -> &SignedApprovalSettlementV2 {
        &self.settlement
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AbortInputRequestV2 {
    session: InputSessionHandleV2,
}

impl AbortInputRequestV2 {
    pub const fn new(session: InputSessionHandleV2) -> Self {
        Self { session }
    }

    pub const fn session(self) -> InputSessionHandleV2 {
        self.session
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputStatusTargetV2 {
    Session(InputSessionHandleV2),
    Pending(PendingIngressHandleV2),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GetInputStatusRequestV2 {
    target: InputStatusTargetV2,
}

impl GetInputStatusRequestV2 {
    pub const fn new(target: InputStatusTargetV2) -> Self {
        Self { target }
    }

    pub const fn target(self) -> InputStatusTargetV2 {
        self.target
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterParserWorkerJobRequestV2 {
    session: InputSessionHandleV2,
    descriptor: SignedParserWorkerJobDescriptorV2,
}

impl RegisterParserWorkerJobRequestV2 {
    pub const fn new(
        session: InputSessionHandleV2,
        descriptor: SignedParserWorkerJobDescriptorV2,
    ) -> Self {
        Self {
            session,
            descriptor,
        }
    }

    pub const fn session(&self) -> InputSessionHandleV2 {
        self.session
    }

    pub const fn descriptor(&self) -> &SignedParserWorkerJobDescriptorV2 {
        &self.descriptor
    }
}

#[derive(Debug)]
pub struct AppendParserWorkerPageFrameRequestV2 {
    extraction: ParserExtractionHandleV2,
    frame: ParserWorkerPageFrameV2,
}

impl AppendParserWorkerPageFrameRequestV2 {
    pub const fn new(extraction: ParserExtractionHandleV2, frame: ParserWorkerPageFrameV2) -> Self {
        Self { extraction, frame }
    }

    pub const fn extraction(&self) -> ParserExtractionHandleV2 {
        self.extraction
    }

    pub const fn frame(&self) -> &ParserWorkerPageFrameV2 {
        &self.frame
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitParserWorkerResultRequestV2 {
    extraction: ParserExtractionHandleV2,
    attestation: SignedParserWorkerResultAttestationV2,
}

impl CommitParserWorkerResultRequestV2 {
    pub const fn new(
        extraction: ParserExtractionHandleV2,
        attestation: SignedParserWorkerResultAttestationV2,
    ) -> Self {
        Self {
            extraction,
            attestation,
        }
    }

    pub const fn extraction(&self) -> ParserExtractionHandleV2 {
        self.extraction
    }

    pub const fn attestation(&self) -> &SignedParserWorkerResultAttestationV2 {
        &self.attestation
    }
}

/// Deliberate typed submission on the authenticated ingress edge. The input
/// session is resolved by the kernel; the draft's principal is not an assertion.
#[derive(Debug, Clone)]
pub struct EstablishTaskAuthorizationRequestV2 {
    session: InputSessionHandleV2,
    draft: super::TaskAuthorizationDraftV2,
    request_nonce: super::Nonce32V2,
}
pub type PrepareTaskAuthorizationApprovalRequestV2 = EstablishTaskAuthorizationRequestV2;
pub type RevokeTaskAuthorizationRequestV2 = EstablishTaskAuthorizationRequestV2;

#[derive(Debug, Clone, Copy)]
pub struct GetTaskAuthorizationContextRequestV2 {
    authorization: IngressUiAuthorizationHandleV2,
    session: Option<InputSessionHandleV2>,
}
impl GetTaskAuthorizationContextRequestV2 {
    pub fn new(
        authorization: IngressUiAuthorizationHandleV2,
        session: Option<InputSessionHandleV2>,
    ) -> Self {
        Self {
            authorization,
            session,
        }
    }
    pub fn authorization(&self) -> IngressUiAuthorizationHandleV2 {
        self.authorization
    }
    pub fn session(&self) -> Option<InputSessionHandleV2> {
        self.session
    }
}

/// Recovery uses a freshly verified UI authorization, not an old input handle.
/// The request identifies existing durable issuance only; it carries no draft.
#[derive(Debug, Clone, Copy)]
pub struct RecoverTaskAuthorizationRequestV2 {
    authorization: IngressUiAuthorizationHandleV2,
    request_digest: Digest32V2,
}
impl RecoverTaskAuthorizationRequestV2 {
    pub fn new(
        authorization: IngressUiAuthorizationHandleV2,
        request_digest: Digest32V2,
    ) -> Result<Self, ProtocolError> {
        if is_zero(request_digest.as_bytes()) {
            return Err(malformed());
        }
        Ok(Self {
            authorization,
            request_digest,
        })
    }
    pub fn authorization(&self) -> IngressUiAuthorizationHandleV2 {
        self.authorization
    }
    pub fn request_digest(&self) -> Digest32V2 {
        self.request_digest
    }
}

#[derive(Debug, Clone)]
pub enum RecoverTaskAuthorizationResponseV2 {
    Installed(EstablishTaskAuthorizationResponseV2),
    Approval(PrepareTaskAuthorizationApprovalResponseV2),
}
pub fn encode_recover_task_authorization_response_v2(
    value: &RecoverTaskAuthorizationResponseV2,
) -> Result<Vec<u8>, ProtocolError> {
    let (tag, bytes) = match value {
        RecoverTaskAuthorizationResponseV2::Installed(v) => {
            (1, encode_establish_task_authorization_response_v2(v)?)
        }
        RecoverTaskAuthorizationResponseV2::Approval(v) => (
            2,
            encode_prepare_task_authorization_approval_response_v2(v)?,
        ),
    };
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(2)
        .and_then(|e| e.u8(tag))
        .and_then(|e| e.bytes(&bytes))
        .map_err(ProtocolError::malformed)?;
    Ok(e.into_writer())
}
pub fn decode_recover_task_authorization_response_v2(
    bytes: &[u8],
) -> Result<RecoverTaskAuthorizationResponseV2, ProtocolError> {
    scan_single(bytes)?;
    let mut d = minicbor::Decoder::new(bytes);
    expect_array(&mut d, 2)?;
    let tag = d.u8().map_err(ProtocolError::malformed)?;
    let inner = d.bytes().map_err(ProtocolError::malformed)?;
    let value = match tag {
        1 => RecoverTaskAuthorizationResponseV2::Installed(
            decode_establish_task_authorization_response_v2(inner)?,
        ),
        2 => RecoverTaskAuthorizationResponseV2::Approval(
            decode_prepare_task_authorization_approval_response_v2(inner)?,
        ),
        _ => return Err(malformed()),
    };
    if d.position() != bytes.len()
        || encode_recover_task_authorization_response_v2(&value)? != bytes
    {
        return Err(malformed());
    }
    Ok(value)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevokeTaskAuthorizationResponseV2 {
    authorization_digest: Digest32V2,
}
impl RevokeTaskAuthorizationResponseV2 {
    pub fn new(authorization_digest: Digest32V2) -> Result<Self, ProtocolError> {
        if is_zero(authorization_digest.as_bytes()) {
            return Err(malformed());
        }
        Ok(Self {
            authorization_digest,
        })
    }
    pub fn authorization_digest(&self) -> Digest32V2 {
        self.authorization_digest
    }
}
pub fn encode_revoke_task_authorization_response_v2(
    value: &RevokeTaskAuthorizationResponseV2,
) -> Result<Vec<u8>, ProtocolError> {
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(1).map_err(ProtocolError::malformed)?;
    encode_fixed(&mut e, &value.authorization_digest)?;
    Ok(e.into_writer())
}
pub fn decode_revoke_task_authorization_response_v2(
    bytes: &[u8],
) -> Result<RevokeTaskAuthorizationResponseV2, ProtocolError> {
    scan_single(bytes)?;
    let mut d = minicbor::Decoder::new(bytes);
    expect_array(&mut d, 1)?;
    let value =
        RevokeTaskAuthorizationResponseV2::new(decode_fixed(&mut d, &mut V2DecodeContext)?)?;
    if d.position() != bytes.len() || encode_revoke_task_authorization_response_v2(&value)? != bytes
    {
        return Err(malformed());
    }
    Ok(value)
}

#[derive(Debug, Clone)]
pub struct PrepareTaskAuthorizationApprovalResponseV2 {
    request_digest: Digest32V2,
    envelope: super::SignedApprovalEnvelopeV2,
    display_authentication: super::SignedUiAuthenticationEnvelopeV2,
}
impl PrepareTaskAuthorizationApprovalResponseV2 {
    pub fn new(
        request_digest: Digest32V2,
        envelope: super::SignedApprovalEnvelopeV2,
        display_authentication: super::SignedUiAuthenticationEnvelopeV2,
    ) -> Result<Self, ProtocolError> {
        if is_zero(request_digest.as_bytes())
            || envelope.unverified_material()?.purpose() != ApprovalPurposeV2::TaskAuthorization
        {
            return Err(malformed());
        }
        Ok(Self {
            request_digest,
            envelope,
            display_authentication,
        })
    }
    pub fn request_digest(&self) -> Digest32V2 {
        self.request_digest
    }
    pub fn envelope(&self) -> &super::SignedApprovalEnvelopeV2 {
        &self.envelope
    }
    pub fn display_authentication(&self) -> &super::SignedUiAuthenticationEnvelopeV2 {
        &self.display_authentication
    }
}
pub fn encode_prepare_task_authorization_approval_response_v2(
    value: &PrepareTaskAuthorizationApprovalResponseV2,
) -> Result<Vec<u8>, ProtocolError> {
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(3).map_err(ProtocolError::malformed)?;
    encode_fixed(&mut e, &value.request_digest)?;
    encode_fixed(&mut e, &value.envelope)?;
    encode_fixed(&mut e, &value.display_authentication)?;
    Ok(e.into_writer())
}
pub fn decode_prepare_task_authorization_approval_response_v2(
    bytes: &[u8],
) -> Result<PrepareTaskAuthorizationApprovalResponseV2, ProtocolError> {
    scan_single(bytes)?;
    let mut d = minicbor::Decoder::new(bytes);
    let mut c = V2DecodeContext;
    expect_array(&mut d, 3)?;
    let v = PrepareTaskAuthorizationApprovalResponseV2::new(
        decode_fixed(&mut d, &mut c)?,
        decode_fixed(&mut d, &mut c)?,
        decode_fixed(&mut d, &mut c)?,
    )?;
    if d.position() != bytes.len()
        || encode_prepare_task_authorization_approval_response_v2(&v)? != bytes
    {
        return Err(malformed());
    }
    Ok(v)
}
#[derive(Debug, Clone)]
pub struct CommitTaskAuthorizationApprovalRequestV2 {
    request_digest: Digest32V2,
    settlement: SignedApprovalSettlementV2,
}
impl CommitTaskAuthorizationApprovalRequestV2 {
    pub fn new(
        request_digest: Digest32V2,
        settlement: SignedApprovalSettlementV2,
    ) -> Result<Self, ProtocolError> {
        if is_zero(request_digest.as_bytes())
            || settlement.unsigned().purpose() != ApprovalPurposeV2::TaskAuthorization
        {
            return Err(malformed());
        }
        Ok(Self {
            request_digest,
            settlement,
        })
    }
    pub fn request_digest(&self) -> Digest32V2 {
        self.request_digest
    }
    pub fn settlement(&self) -> &SignedApprovalSettlementV2 {
        &self.settlement
    }
}
impl EstablishTaskAuthorizationRequestV2 {
    pub fn new(
        session: InputSessionHandleV2,
        draft: super::TaskAuthorizationDraftV2,
        request_nonce: super::Nonce32V2,
    ) -> Result<Self, ProtocolError> {
        if is_zero(request_nonce.as_bytes()) {
            return Err(malformed());
        }
        Ok(Self {
            session,
            draft,
            request_nonce,
        })
    }
    pub fn session(&self) -> InputSessionHandleV2 {
        self.session
    }
    pub fn draft(&self) -> &super::TaskAuthorizationDraftV2 {
        &self.draft
    }
    pub fn request_nonce(&self) -> super::Nonce32V2 {
        self.request_nonce
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EstablishTaskAuthorizationResponseV2 {
    request_digest: Digest32V2,
    authorization_digest: Digest32V2,
}
impl EstablishTaskAuthorizationResponseV2 {
    pub fn new(
        request_digest: Digest32V2,
        authorization_digest: Digest32V2,
    ) -> Result<Self, ProtocolError> {
        if is_zero(request_digest.as_bytes()) || is_zero(authorization_digest.as_bytes()) {
            return Err(malformed());
        }
        Ok(Self {
            request_digest,
            authorization_digest,
        })
    }
    pub fn request_digest(&self) -> Digest32V2 {
        self.request_digest
    }
    pub fn authorization_digest(&self) -> Digest32V2 {
        self.authorization_digest
    }
}
pub fn encode_establish_task_authorization_response_v2(
    value: &EstablishTaskAuthorizationResponseV2,
) -> Result<Vec<u8>, ProtocolError> {
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(2).map_err(ProtocolError::malformed)?;
    encode_fixed(&mut e, &value.request_digest)?;
    encode_fixed(&mut e, &value.authorization_digest)?;
    Ok(e.into_writer())
}
pub fn decode_establish_task_authorization_response_v2(
    bytes: &[u8],
) -> Result<EstablishTaskAuthorizationResponseV2, ProtocolError> {
    scan_single(bytes)?;
    let mut d = minicbor::Decoder::new(bytes);
    expect_array(&mut d, 2)?;
    let mut c = V2DecodeContext;
    let value = EstablishTaskAuthorizationResponseV2::new(
        decode_fixed(&mut d, &mut c)?,
        decode_fixed(&mut d, &mut c)?,
    )?;
    if d.position() != bytes.len()
        || encode_establish_task_authorization_response_v2(&value)? != bytes
    {
        return Err(malformed());
    }
    Ok(value)
}

#[derive(Debug)]
pub enum KernelIngressOperationV2 {
    Health(KernelIngressHealthRequestV2),
    BeginInput(BeginInputRequestV2),
    AppendInputChunk(AppendInputChunkRequestV2),
    FinalizeInput(FinalizeInputRequestV2),
    CommitInputSettlement(CommitInputSettlementRequestV2),
    AbortInput(AbortInputRequestV2),
    GetInputStatus(GetInputStatusRequestV2),
    PrepareIngressUiAuthentication(PrepareIngressUiAuthenticationRequestV2),
    AuthenticateIngressUi(AuthenticateIngressUiRequestV2),
    RegisterParserWorkerJob(RegisterParserWorkerJobRequestV2),
    AppendParserWorkerPageFrame(AppendParserWorkerPageFrameRequestV2),
    CommitParserWorkerResult(CommitParserWorkerResultRequestV2),
    EstablishTaskAuthorization(EstablishTaskAuthorizationRequestV2),
    PrepareTaskAuthorizationApproval(PrepareTaskAuthorizationApprovalRequestV2),
    CommitTaskAuthorizationApproval(CommitTaskAuthorizationApprovalRequestV2),
    RevokeTaskAuthorization(RevokeTaskAuthorizationRequestV2),
    RecoverTaskAuthorization(RecoverTaskAuthorizationRequestV2),
    GetTaskAuthorizationContext(GetTaskAuthorizationContextRequestV2),
}

impl KernelIngressOperationV2 {
    pub const fn tag(&self) -> u16 {
        match self {
            Self::Health(_) => 0,
            Self::BeginInput(_) => 40,
            Self::AppendInputChunk(_) => 41,
            Self::FinalizeInput(_) => 42,
            Self::CommitInputSettlement(_) => 43,
            Self::AbortInput(_) => 44,
            Self::GetInputStatus(_) => 45,
            Self::PrepareIngressUiAuthentication(_) => 46,
            Self::AuthenticateIngressUi(_) => 47,
            Self::RegisterParserWorkerJob(_) => 48,
            Self::AppendParserWorkerPageFrame(_) => 49,
            Self::CommitParserWorkerResult(_) => 50,
            Self::EstablishTaskAuthorization(_) => 51,
            Self::PrepareTaskAuthorizationApproval(_) => 52,
            Self::CommitTaskAuthorizationApproval(_) => 53,
            Self::RevokeTaskAuthorization(_) => 54,
            Self::RecoverTaskAuthorization(_) => 55,
            Self::GetTaskAuthorizationContext(_) => 56,
        }
    }
}

pub const fn kernel_ingress_operation_tags_v2() -> &'static [u16; 18] {
    &[
        0, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56,
    ]
}

pub fn encode_kernel_ingress_operation_v2(
    value: &KernelIngressOperationV2,
) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    match value {
        KernelIngressOperationV2::Health(_) => encode_header(&mut encoder, 0, 0)?,
        KernelIngressOperationV2::BeginInput(request) => {
            encode_header(&mut encoder, 40, 4)?;
            encode_fixed(&mut encoder, &request.ui_authorization)?;
            encode_closed(&mut encoder, request.content_kind)?;
            encoder
                .u64(request.declared_total_bytes)
                .map_err(ProtocolError::malformed)?;
            encode_optional_fixed(&mut encoder, request.declared_content_digest)?;
        }
        KernelIngressOperationV2::AppendInputChunk(request) => {
            encode_header(&mut encoder, 41, 7)?;
            encode_fixed(&mut encoder, &request.writer)?;
            encode_closed(&mut encoder, request.channel)?;
            encoder
                .u32(request.sequence)
                .map_err(ProtocolError::malformed)?;
            encode_fixed(&mut encoder, &request.prior_cumulative_digest)?;
            encode_fixed(&mut encoder, &request.chunk)?;
            encode_fixed(&mut encoder, &request.chunk_digest)?;
            encode_fixed(&mut encoder, &request.resulting_cumulative_digest)?;
        }
        KernelIngressOperationV2::FinalizeInput(request) => {
            encode_header(&mut encoder, 42, 3)?;
            encode_fixed(&mut encoder, &request.session)?;
            encode_channel_commitments(&mut encoder, &request.channels)?;
            encode_source_provenance(&mut encoder, &request.source_provenance)?;
        }
        KernelIngressOperationV2::CommitInputSettlement(request) => {
            encode_header(&mut encoder, 43, 3)?;
            encode_fixed(&mut encoder, &request.pending)?;
            encode_fixed(&mut encoder, &request.approval)?;
            encode_fixed(&mut encoder, &request.settlement)?;
        }
        KernelIngressOperationV2::AbortInput(request) => {
            encode_header(&mut encoder, 44, 1)?;
            encode_fixed(&mut encoder, &request.session)?;
        }
        KernelIngressOperationV2::GetInputStatus(request) => {
            encode_header(&mut encoder, 45, 1)?;
            encode_input_status_target(&mut encoder, request.target)?;
        }
        KernelIngressOperationV2::PrepareIngressUiAuthentication(request) => {
            encode_header(&mut encoder, 46, 1)?;
            encode_fixed(&mut encoder, &request.transfer)?;
        }
        KernelIngressOperationV2::AuthenticateIngressUi(request) => {
            encode_header(&mut encoder, 47, 2)?;
            encode_fixed(&mut encoder, &request.authentication_preparation)?;
            encode_fixed(&mut encoder, &request.settlement)?;
        }
        KernelIngressOperationV2::RegisterParserWorkerJob(request) => {
            encode_header(&mut encoder, 48, 2)?;
            encode_fixed(&mut encoder, &request.session)?;
            encode_fixed(&mut encoder, &request.descriptor)?;
        }
        KernelIngressOperationV2::AppendParserWorkerPageFrame(request) => {
            encode_header(&mut encoder, 49, 2)?;
            encode_fixed(&mut encoder, &request.extraction)?;
            encode_parser_worker_page_frame(&mut encoder, &request.frame)?;
        }
        KernelIngressOperationV2::CommitParserWorkerResult(request) => {
            encode_header(&mut encoder, 50, 2)?;
            encode_fixed(&mut encoder, &request.extraction)?;
            encode_fixed(&mut encoder, &request.attestation)?;
        }
        KernelIngressOperationV2::EstablishTaskAuthorization(request)
        | KernelIngressOperationV2::RevokeTaskAuthorization(request)
        | KernelIngressOperationV2::PrepareTaskAuthorizationApproval(request) => {
            encode_header(&mut encoder, value.tag(), 3)?;
            encode_fixed(&mut encoder, &request.session)?;
            encoder
                .bytes(&super::encode_task_authorization_draft_v2(&request.draft)?)
                .map_err(ProtocolError::malformed)?;
            encode_fixed(&mut encoder, &request.request_nonce)?;
        }
        KernelIngressOperationV2::CommitTaskAuthorizationApproval(request) => {
            encode_header(&mut encoder, 53, 2)?;
            encode_fixed(&mut encoder, &request.request_digest)?;
            encode_fixed(&mut encoder, &request.settlement)?;
        }
        KernelIngressOperationV2::RecoverTaskAuthorization(request) => {
            encode_header(&mut encoder, 55, 2)?;
            encode_fixed(&mut encoder, &request.authorization)?;
            encode_fixed(&mut encoder, &request.request_digest)?;
        }
        KernelIngressOperationV2::GetTaskAuthorizationContext(request) => {
            encode_header(&mut encoder, 56, 2)?;
            encode_fixed(&mut encoder, &request.authorization)?;
            if let Some(session) = request.session {
                encode_fixed(&mut encoder, &session)?;
            } else {
                encoder.null().map_err(ProtocolError::malformed)?;
            }
        }
    }
    Ok(encoder.into_writer())
}

pub fn decode_kernel_ingress_operation_v2(
    bytes: &[u8],
) -> Result<KernelIngressOperationV2, ProtocolError> {
    scan_single(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    expect_array(&mut decoder, 2)?;
    let tag = decoder.u16().map_err(ProtocolError::malformed)?;
    let mut context = V2DecodeContext;
    let value = match tag {
        0 => {
            expect_array(&mut decoder, 0)?;
            KernelIngressOperationV2::Health(KernelIngressHealthRequestV2)
        }
        40 => {
            expect_array(&mut decoder, 4)?;
            KernelIngressOperationV2::BeginInput(BeginInputRequestV2::new(
                decode_fixed(&mut decoder, &mut context)?,
                decode_closed(&mut decoder, ContentKindV2::from_tag)?,
                decoder.u64().map_err(ProtocolError::malformed)?,
                decode_optional_fixed(&mut decoder, &mut context)?,
            )?)
        }
        41 => {
            expect_array(&mut decoder, 7)?;
            KernelIngressOperationV2::AppendInputChunk(AppendInputChunkRequestV2::new(
                decode_fixed(&mut decoder, &mut context)?,
                decode_closed(&mut decoder, DirectInputChannelV2::from_tag)?,
                decoder.u32().map_err(ProtocolError::malformed)?,
                decode_fixed(&mut decoder, &mut context)?,
                decode_fixed(&mut decoder, &mut context)?,
                decode_fixed(&mut decoder, &mut context)?,
                decode_fixed(&mut decoder, &mut context)?,
            )?)
        }
        42 => {
            expect_array(&mut decoder, 3)?;
            KernelIngressOperationV2::FinalizeInput(FinalizeInputRequestV2::new(
                decode_fixed(&mut decoder, &mut context)?,
                decode_channel_commitments(&mut decoder, &mut context)?,
                decode_source_provenance(&mut decoder, &mut context)?,
            )?)
        }
        43 => {
            expect_array(&mut decoder, 3)?;
            KernelIngressOperationV2::CommitInputSettlement(CommitInputSettlementRequestV2::new(
                decode_fixed(&mut decoder, &mut context)?,
                decode_fixed(&mut decoder, &mut context)?,
                decode_fixed(&mut decoder, &mut context)?,
            )?)
        }
        44 => {
            expect_array(&mut decoder, 1)?;
            KernelIngressOperationV2::AbortInput(AbortInputRequestV2::new(decode_fixed(
                &mut decoder,
                &mut context,
            )?))
        }
        45 => {
            expect_array(&mut decoder, 1)?;
            KernelIngressOperationV2::GetInputStatus(GetInputStatusRequestV2::new(
                decode_input_status_target(&mut decoder, &mut context)?,
            ))
        }
        46 => {
            expect_array(&mut decoder, 1)?;
            KernelIngressOperationV2::PrepareIngressUiAuthentication(
                PrepareIngressUiAuthenticationRequestV2::new(decode_fixed(
                    &mut decoder,
                    &mut context,
                )?),
            )
        }
        47 => {
            expect_array(&mut decoder, 2)?;
            KernelIngressOperationV2::AuthenticateIngressUi(AuthenticateIngressUiRequestV2::new(
                decode_fixed(&mut decoder, &mut context)?,
                decode_fixed(&mut decoder, &mut context)?,
            )?)
        }
        48 => {
            expect_array(&mut decoder, 2)?;
            KernelIngressOperationV2::RegisterParserWorkerJob(
                RegisterParserWorkerJobRequestV2::new(
                    decode_fixed(&mut decoder, &mut context)?,
                    decode_fixed(&mut decoder, &mut context)?,
                ),
            )
        }
        49 => {
            expect_array(&mut decoder, 2)?;
            KernelIngressOperationV2::AppendParserWorkerPageFrame(
                AppendParserWorkerPageFrameRequestV2::new(
                    decode_fixed(&mut decoder, &mut context)?,
                    decode_parser_worker_page_frame(&mut decoder, &mut context)?,
                ),
            )
        }
        50 => {
            expect_array(&mut decoder, 2)?;
            KernelIngressOperationV2::CommitParserWorkerResult(
                CommitParserWorkerResultRequestV2::new(
                    decode_fixed(&mut decoder, &mut context)?,
                    decode_fixed(&mut decoder, &mut context)?,
                ),
            )
        }
        51 | 52 | 54 => {
            expect_array(&mut decoder, 3)?;
            let request = EstablishTaskAuthorizationRequestV2::new(
                decode_fixed(&mut decoder, &mut context)?,
                super::decode_task_authorization_draft_v2(
                    decoder.bytes().map_err(ProtocolError::malformed)?,
                )?,
                decode_fixed(&mut decoder, &mut context)?,
            )?;
            if tag == 54 {
                KernelIngressOperationV2::RevokeTaskAuthorization(request)
            } else if tag == 51 {
                KernelIngressOperationV2::EstablishTaskAuthorization(request)
            } else {
                KernelIngressOperationV2::PrepareTaskAuthorizationApproval(request)
            }
        }
        53 => {
            expect_array(&mut decoder, 2)?;
            KernelIngressOperationV2::CommitTaskAuthorizationApproval(
                CommitTaskAuthorizationApprovalRequestV2::new(
                    decode_fixed(&mut decoder, &mut context)?,
                    decode_fixed(&mut decoder, &mut context)?,
                )?,
            )
        }
        55 => {
            expect_array(&mut decoder, 2)?;
            KernelIngressOperationV2::RecoverTaskAuthorization(
                RecoverTaskAuthorizationRequestV2::new(
                    decode_fixed(&mut decoder, &mut context)?,
                    decode_fixed(&mut decoder, &mut context)?,
                )?,
            )
        }
        56 => {
            expect_array(&mut decoder, 2)?;
            let authorization = decode_fixed(&mut decoder, &mut context)?;
            let session = if decoder.datatype().map_err(ProtocolError::malformed)?
                == minicbor::data::Type::Null
            {
                decoder.null().map_err(ProtocolError::malformed)?;
                None
            } else {
                Some(decode_fixed(&mut decoder, &mut context)?)
            };
            KernelIngressOperationV2::GetTaskAuthorizationContext(
                GetTaskAuthorizationContextRequestV2::new(authorization, session),
            )
        }
        _ => return Err(ProtocolError::stable(StableCode::ProtocolUnknownOperation)),
    };
    if decoder.position() != bytes.len() || encode_kernel_ingress_operation_v2(&value)? != bytes {
        return Err(malformed());
    }
    Ok(value)
}

impl<C> minicbor::Encode<C> for SignedParserWorkerJobDescriptorV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        _context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        let payload = encode_unsigned_parser_worker_job_descriptor(&self.unsigned)
            .map_err(|_| minicbor::encode::Error::message("invalid parser job descriptor"))?;
        encoder.array(3)?.bytes(&payload)?;
        minicbor::Encode::encode(&self.key_id, encoder, &mut ())?;
        minicbor::Encode::encode(&self.signature, encoder, &mut ())?;
        Ok(())
    }
}

impl<'bytes> minicbor::Decode<'bytes, V2DecodeContext> for SignedParserWorkerJobDescriptorV2 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut V2DecodeContext,
    ) -> Result<Self, minicbor::decode::Error> {
        let position = decoder.position();
        if decoder.array()? != Some(3) {
            return Err(decode_error(position));
        }
        let payload = decoder.bytes()?;
        if payload.len() > 8 * 1024 {
            return Err(decode_error(position));
        }
        let unsigned = decode_unsigned_parser_worker_job_descriptor(payload)
            .map_err(|_| decode_error(position))?;
        let key_id = minicbor::Decode::decode(decoder, context)?;
        let signature = minicbor::Decode::decode(decoder, context)?;
        Self::from_parts(unsigned, key_id, signature).map_err(|_| decode_error(position))
    }
}

impl<C> minicbor::Encode<C> for SignedParserWorkerResultAttestationV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        _context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        let payload = encode_unsigned_parser_worker_result_attestation(&self.unsigned)
            .map_err(|_| minicbor::encode::Error::message("invalid parser result attestation"))?;
        encoder.array(3)?.bytes(&payload)?;
        minicbor::Encode::encode(&self.key_id, encoder, &mut ())?;
        minicbor::Encode::encode(&self.signature, encoder, &mut ())?;
        Ok(())
    }
}

impl<'bytes> minicbor::Decode<'bytes, V2DecodeContext> for SignedParserWorkerResultAttestationV2 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut V2DecodeContext,
    ) -> Result<Self, minicbor::decode::Error> {
        let position = decoder.position();
        if decoder.array()? != Some(3) {
            return Err(decode_error(position));
        }
        let payload = decoder.bytes()?;
        if payload.len() > 256 * 1024 {
            return Err(decode_error(position));
        }
        let unsigned = decode_unsigned_parser_worker_result_attestation(payload)
            .map_err(|_| decode_error(position))?;
        let key_id = minicbor::Decode::decode(decoder, context)?;
        let signature = minicbor::Decode::decode(decoder, context)?;
        Self::from_parts(unsigned, key_id, signature).map_err(|_| decode_error(position))
    }
}

fn encode_unsigned_parser_worker_job_descriptor(
    value: &UnsignedParserWorkerJobDescriptorV2,
) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(21)
        .and_then(|encoder| encoder.u16(2))
        .map_err(ProtocolError::malformed)?;
    encode_fixed(&mut encoder, &value.installation_id)?;
    encode_fixed(&mut encoder, &value.active_state_manifest_digest)?;
    encoder
        .u64(value.deployment_generation)
        .map_err(ProtocolError::malformed)?;
    encode_fixed(&mut encoder, &value.ingressd_identity)?;
    encode_fixed(&mut encoder, &value.job_nonce)?;
    encode_fixed(&mut encoder, &value.parser_job_session_binding_digest)?;
    encoder
        .u64(value.original_byte_length)
        .map_err(ProtocolError::malformed)?;
    encode_fixed(&mut encoder, &value.original_sha256)?;
    encode_fixed(&mut encoder, &value.declared_media_type)?;
    encode_fixed(&mut encoder, &value.detected_media_type)?;
    encode_fixed(&mut encoder, &value.worker_artifact_digest)?;
    encode_fixed(&mut encoder, &value.parser_implementation_id)?;
    encode_fixed(&mut encoder, &value.parser_code_digest)?;
    encode_optional_fixed(&mut encoder, value.renderer_code_digest)?;
    encode_optional_fixed(&mut encoder, value.ocr_model_set_digest)?;
    encode_fixed(&mut encoder, &value.normalization_version)?;
    encode_fixed(&mut encoder, &value.output_limits_digest)?;
    encode_fixed(&mut encoder, &value.ephemeral_result_public_key)?;
    encode_fixed(&mut encoder, &value.ephemeral_result_key_id)?;
    encode_fixed(&mut encoder, &value.expires_at)?;
    Ok(encoder.into_writer())
}

fn decode_unsigned_parser_worker_job_descriptor(
    bytes: &[u8],
) -> Result<UnsignedParserWorkerJobDescriptorV2, ProtocolError> {
    scan_single(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    expect_array(&mut decoder, 21)?;
    if decoder.u16().map_err(ProtocolError::malformed)? != 2 {
        return Err(malformed());
    }
    let mut context = V2DecodeContext;
    let value = UnsignedParserWorkerJobDescriptorV2::new(
        decode_fixed(&mut decoder, &mut context)?,
        decode_fixed(&mut decoder, &mut context)?,
        decoder.u64().map_err(ProtocolError::malformed)?,
        decode_fixed(&mut decoder, &mut context)?,
        decode_fixed(&mut decoder, &mut context)?,
        decode_fixed(&mut decoder, &mut context)?,
        decoder.u64().map_err(ProtocolError::malformed)?,
        decode_fixed(&mut decoder, &mut context)?,
        decode_fixed(&mut decoder, &mut context)?,
        decode_fixed(&mut decoder, &mut context)?,
        decode_fixed(&mut decoder, &mut context)?,
        decode_fixed(&mut decoder, &mut context)?,
        decode_fixed(&mut decoder, &mut context)?,
        decode_optional_fixed(&mut decoder, &mut context)?,
        decode_optional_fixed(&mut decoder, &mut context)?,
        decode_fixed(&mut decoder, &mut context)?,
        decode_fixed(&mut decoder, &mut context)?,
        decode_fixed(&mut decoder, &mut context)?,
        decode_fixed(&mut decoder, &mut context)?,
        decode_fixed(&mut decoder, &mut context)?,
    )?;
    if decoder.position() != bytes.len()
        || encode_unsigned_parser_worker_job_descriptor(&value)? != bytes
    {
        return Err(malformed());
    }
    Ok(value)
}

fn encode_parser_worker_page_frame(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    value: &ParserWorkerPageFrameV2,
) -> Result<(), ProtocolError> {
    encoder.array(8).map_err(ProtocolError::malformed)?;
    encode_fixed(encoder, &value.job_nonce)?;
    encoder
        .u32(value.page_index)
        .and_then(|encoder| encoder.u32(value.page_chunk_index))
        .and_then(|encoder| encoder.bool(value.final_chunk_for_page))
        .map_err(ProtocolError::malformed)?;
    encode_fixed(encoder, &value.rendered_input_digest)?;
    encode_fixed(encoder, &value.extracted_chunk)?;
    encode_fixed(encoder, &value.extracted_chunk_digest)?;
    encode_fixed(encoder, &value.transcript_step_digest)
}

fn decode_parser_worker_page_frame(
    decoder: &mut minicbor::Decoder<'_>,
    context: &mut V2DecodeContext,
) -> Result<ParserWorkerPageFrameV2, ProtocolError> {
    expect_array(decoder, 8)?;
    ParserWorkerPageFrameV2::new(
        decode_fixed(decoder, context)?,
        decoder.u32().map_err(ProtocolError::malformed)?,
        decoder.u32().map_err(ProtocolError::malformed)?,
        decoder.bool().map_err(ProtocolError::malformed)?,
        decode_fixed(decoder, context)?,
        decode_fixed(decoder, context)?,
        decode_fixed(decoder, context)?,
        decode_fixed(decoder, context)?,
    )
}

pub fn encode_parser_worker_page_frame_v2(
    value: &ParserWorkerPageFrameV2,
) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encode_parser_worker_page_frame(&mut encoder, value)?;
    Ok(encoder.into_writer())
}

pub fn decode_parser_worker_page_frame_v2(
    bytes: &[u8],
) -> Result<ParserWorkerPageFrameV2, ProtocolError> {
    scan_single(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    let mut context = V2DecodeContext;
    let value = decode_parser_worker_page_frame(&mut decoder, &mut context)?;
    if decoder.position() != bytes.len() || encode_parser_worker_page_frame_v2(&value)? != bytes {
        return Err(malformed());
    }
    Ok(value)
}

pub fn encode_signed_parser_worker_job_descriptor_v2(
    value: &SignedParserWorkerJobDescriptorV2,
) -> Result<Vec<u8>, ProtocolError> {
    minicbor::to_vec(value).map_err(ProtocolError::malformed)
}

pub fn decode_signed_parser_worker_job_descriptor_v2(
    bytes: &[u8],
) -> Result<SignedParserWorkerJobDescriptorV2, ProtocolError> {
    scan_single(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    let mut context = V2DecodeContext;
    let value = minicbor::Decode::decode(&mut decoder, &mut context)
        .map_err(ProtocolError::from_typed_decode)?;
    if decoder.position() != bytes.len()
        || encode_signed_parser_worker_job_descriptor_v2(&value)? != bytes
    {
        return Err(malformed());
    }
    Ok(value)
}

pub fn encode_signed_parser_worker_result_attestation_v2(
    value: &SignedParserWorkerResultAttestationV2,
) -> Result<Vec<u8>, ProtocolError> {
    minicbor::to_vec(value).map_err(ProtocolError::malformed)
}

pub fn decode_signed_parser_worker_result_attestation_v2(
    bytes: &[u8],
) -> Result<SignedParserWorkerResultAttestationV2, ProtocolError> {
    scan_single(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    let mut context = V2DecodeContext;
    let value = minicbor::Decode::decode(&mut decoder, &mut context)
        .map_err(ProtocolError::from_typed_decode)?;
    if decoder.position() != bytes.len()
        || encode_signed_parser_worker_result_attestation_v2(&value)? != bytes
    {
        return Err(malformed());
    }
    Ok(value)
}

fn encode_unsigned_parser_worker_result_attestation(
    value: &UnsignedParserWorkerResultAttestationV2,
) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(14)
        .and_then(|encoder| encoder.u16(2))
        .map_err(ProtocolError::malformed)?;
    encode_fixed(&mut encoder, &value.job_nonce)?;
    encode_fixed(&mut encoder, &value.job_descriptor_digest)?;
    encode_fixed(&mut encoder, &value.parser_job_session_binding_digest)?;
    encode_fixed(&mut encoder, &value.worker_artifact_digest)?;
    encode_fixed(&mut encoder, &value.ephemeral_result_key_id)?;
    encoder
        .u64(value.original_byte_length)
        .map_err(ProtocolError::malformed)?;
    encode_fixed(&mut encoder, &value.original_sha256)?;
    encoder
        .u32(value.page_count)
        .map_err(ProtocolError::malformed)?;
    encode_page_records(&mut encoder, &value.page_records)?;
    encode_fixed(&mut encoder, &value.ordered_page_frame_transcript_digest)?;
    encoder
        .u64(value.extracted_byte_length)
        .map_err(ProtocolError::malformed)?;
    encode_fixed(&mut encoder, &value.extracted_output_digest)?;
    encode_fixed(&mut encoder, &value.completed_at)?;
    Ok(encoder.into_writer())
}

fn decode_unsigned_parser_worker_result_attestation(
    bytes: &[u8],
) -> Result<UnsignedParserWorkerResultAttestationV2, ProtocolError> {
    scan_single(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    expect_array(&mut decoder, 14)?;
    if decoder.u16().map_err(ProtocolError::malformed)? != 2 {
        return Err(malformed());
    }
    let mut context = V2DecodeContext;
    let job_nonce = decode_fixed(&mut decoder, &mut context)?;
    let job_descriptor_digest = decode_fixed(&mut decoder, &mut context)?;
    let parser_job_session_binding_digest = decode_fixed(&mut decoder, &mut context)?;
    let worker_artifact_digest = decode_fixed(&mut decoder, &mut context)?;
    let ephemeral_result_key_id = decode_fixed(&mut decoder, &mut context)?;
    let original_byte_length = decoder.u64().map_err(ProtocolError::malformed)?;
    let original_sha256 = decode_fixed(&mut decoder, &mut context)?;
    let page_count = decoder.u32().map_err(ProtocolError::malformed)?;
    let page_records = decode_page_records(&mut decoder, &mut context)?;
    let ordered_page_frame_transcript_digest = decode_fixed(&mut decoder, &mut context)?;
    let extracted_byte_length = decoder.u64().map_err(ProtocolError::malformed)?;
    let extracted_output_digest = decode_fixed(&mut decoder, &mut context)?;
    let completed_at = decode_fixed(&mut decoder, &mut context)?;
    let value = UnsignedParserWorkerResultAttestationV2::new(
        job_nonce,
        job_descriptor_digest,
        parser_job_session_binding_digest,
        worker_artifact_digest,
        ephemeral_result_key_id,
        original_byte_length,
        original_sha256,
        page_count,
        page_records,
        ordered_page_frame_transcript_digest,
        extracted_byte_length,
        extracted_output_digest,
        completed_at,
    )?;
    if decoder.position() != bytes.len()
        || encode_unsigned_parser_worker_result_attestation(&value)? != bytes
    {
        return Err(malformed());
    }
    Ok(value)
}

fn encode_source_provenance(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    value: &InputSourceProvenanceV2,
) -> Result<(), ProtocolError> {
    match value {
        InputSourceProvenanceV2::Direct {
            source_kind,
            original_byte_length,
            original_sha256,
            normalization_version,
        } => {
            encoder
                .array(5)
                .and_then(|encoder| encoder.u16(1))
                .map_err(ProtocolError::malformed)?;
            encode_closed(encoder, *source_kind)?;
            encoder
                .u64(*original_byte_length)
                .map_err(ProtocolError::malformed)?;
            encode_fixed(encoder, original_sha256)?;
            encode_fixed(encoder, normalization_version)?;
        }
        InputSourceProvenanceV2::ParsedDocument {
            source_kind,
            original_byte_length,
            original_sha256,
            declared_media_type,
            detected_media_type,
            extension_class,
            parser_implementation_id,
            parser_semantic_version,
            parser_code_digest,
            renderer_code_digest,
            ocr_model_set_digest,
            normalization_version,
            page_records,
            extracted_output_digest,
        } => {
            encoder
                .array(15)
                .and_then(|encoder| encoder.u16(2))
                .map_err(ProtocolError::malformed)?;
            encode_closed(encoder, *source_kind)?;
            encoder
                .u64(*original_byte_length)
                .map_err(ProtocolError::malformed)?;
            encode_fixed(encoder, original_sha256)?;
            encode_fixed(encoder, declared_media_type)?;
            encode_fixed(encoder, detected_media_type)?;
            encode_fixed(encoder, extension_class)?;
            encode_fixed(encoder, parser_implementation_id)?;
            encode_fixed(encoder, parser_semantic_version)?;
            encode_fixed(encoder, parser_code_digest)?;
            encode_optional_fixed(encoder, *renderer_code_digest)?;
            encode_optional_fixed(encoder, *ocr_model_set_digest)?;
            encode_fixed(encoder, normalization_version)?;
            encode_page_records(encoder, page_records)?;
            encode_fixed(encoder, extracted_output_digest)?;
        }
    }
    Ok(())
}

fn decode_source_provenance(
    decoder: &mut minicbor::Decoder<'_>,
    context: &mut V2DecodeContext,
) -> Result<InputSourceProvenanceV2, ProtocolError> {
    let length = definite_array_length(decoder)?;
    let tag = decoder.u16().map_err(ProtocolError::malformed)?;
    match (tag, length) {
        (1, 5) => InputSourceProvenanceV2::direct(
            decode_closed(decoder, InputSourceKindV2::from_tag)?,
            decoder.u64().map_err(ProtocolError::malformed)?,
            decode_fixed(decoder, context)?,
            decode_fixed(decoder, context)?,
        ),
        (2, 15) => InputSourceProvenanceV2::parsed_document(
            decode_closed(decoder, InputSourceKindV2::from_tag)?,
            decoder.u64().map_err(ProtocolError::malformed)?,
            decode_fixed(decoder, context)?,
            decode_fixed(decoder, context)?,
            decode_fixed(decoder, context)?,
            decode_fixed(decoder, context)?,
            decode_fixed(decoder, context)?,
            decode_fixed(decoder, context)?,
            decode_fixed(decoder, context)?,
            decode_optional_fixed(decoder, context)?,
            decode_optional_fixed(decoder, context)?,
            decode_fixed(decoder, context)?,
            decode_page_records(decoder, context)?,
            decode_fixed(decoder, context)?,
        ),
        _ => Err(malformed()),
    }
}

fn encode_page_records(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    values: &[PageProvenanceV2],
) -> Result<(), ProtocolError> {
    encoder
        .array(u64::try_from(values.len()).map_err(|_| malformed())?)
        .map_err(ProtocolError::malformed)?;
    for value in values {
        encoder
            .array(9)
            .and_then(|encoder| encoder.u32(value.page_index))
            .and_then(|encoder| encoder.u32(value.extracted_channel_first_sequence))
            .and_then(|encoder| encoder.u32(value.extracted_channel_chunk_count))
            .and_then(|encoder| encoder.u64(value.rendered_byte_length))
            .map_err(ProtocolError::malformed)?;
        encode_fixed(encoder, &value.rendered_input_digest)?;
        encoder
            .u64(value.extracted_byte_length)
            .map_err(ProtocolError::malformed)?;
        encode_fixed(encoder, &value.extracted_text_digest)?;
        encoder
            .u32(value.character_count)
            .map_err(ProtocolError::malformed)?;
        encode_fixed(encoder, &value.confidence_class)?;
    }
    Ok(())
}

fn decode_page_records(
    decoder: &mut minicbor::Decoder<'_>,
    context: &mut V2DecodeContext,
) -> Result<Vec<PageProvenanceV2>, ProtocolError> {
    let length = bounded_array_length(decoder, MAX_PAGE_PROVENANCE_V2)?;
    let mut values = Vec::new();
    values.try_reserve_exact(length).map_err(|_| malformed())?;
    for _ in 0..length {
        expect_array(decoder, 9)?;
        values.push(PageProvenanceV2::new(
            decoder.u32().map_err(ProtocolError::malformed)?,
            decoder.u32().map_err(ProtocolError::malformed)?,
            decoder.u32().map_err(ProtocolError::malformed)?,
            decoder.u64().map_err(ProtocolError::malformed)?,
            decode_fixed(decoder, context)?,
            decoder.u64().map_err(ProtocolError::malformed)?,
            decode_fixed(decoder, context)?,
            decoder.u32().map_err(ProtocolError::malformed)?,
            decode_fixed(decoder, context)?,
        )?);
    }
    Ok(values)
}

fn encode_channel_commitments(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    values: &[InputChannelCommitmentV2],
) -> Result<(), ProtocolError> {
    encoder
        .array(u64::try_from(values.len()).map_err(|_| malformed())?)
        .map_err(ProtocolError::malformed)?;
    for value in values {
        encoder.array(5).map_err(ProtocolError::malformed)?;
        encode_closed(encoder, value.channel)?;
        encoder
            .u32(value.chunk_count)
            .and_then(|encoder| encoder.u32(value.final_sequence))
            .and_then(|encoder| encoder.u64(value.total_length))
            .map_err(ProtocolError::malformed)?;
        encode_fixed(encoder, &value.final_cumulative_digest)?;
    }
    Ok(())
}

fn decode_channel_commitments(
    decoder: &mut minicbor::Decoder<'_>,
    context: &mut V2DecodeContext,
) -> Result<Vec<InputChannelCommitmentV2>, ProtocolError> {
    let length = bounded_array_length(decoder, MAX_INPUT_CHANNELS_V2)?;
    let mut values = Vec::new();
    values.try_reserve_exact(length).map_err(|_| malformed())?;
    for _ in 0..length {
        expect_array(decoder, 5)?;
        values.push(InputChannelCommitmentV2::new(
            decode_closed(decoder, InputChannelV2::from_tag)?,
            decoder.u32().map_err(ProtocolError::malformed)?,
            decoder.u32().map_err(ProtocolError::malformed)?,
            decoder.u64().map_err(ProtocolError::malformed)?,
            decode_fixed(decoder, context)?,
        )?);
    }
    Ok(values)
}

fn encode_input_status_target(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    value: InputStatusTargetV2,
) -> Result<(), ProtocolError> {
    encoder.array(2).map_err(ProtocolError::malformed)?;
    match value {
        InputStatusTargetV2::Session(handle) => {
            encoder.u16(1).map_err(ProtocolError::malformed)?;
            encode_fixed(encoder, &handle)
        }
        InputStatusTargetV2::Pending(handle) => {
            encoder.u16(2).map_err(ProtocolError::malformed)?;
            encode_fixed(encoder, &handle)
        }
    }
}

fn decode_input_status_target(
    decoder: &mut minicbor::Decoder<'_>,
    context: &mut V2DecodeContext,
) -> Result<InputStatusTargetV2, ProtocolError> {
    expect_array(decoder, 2)?;
    match decoder.u16().map_err(ProtocolError::malformed)? {
        1 => decode_fixed(decoder, context).map(InputStatusTargetV2::Session),
        2 => decode_fixed(decoder, context).map(InputStatusTargetV2::Pending),
        _ => Err(malformed()),
    }
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

fn encode_closed<T: ClosedTag>(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    value: T,
) -> Result<(), ProtocolError> {
    encoder
        .array(1)
        .and_then(|encoder| encoder.u16(value.closed_tag()))
        .map_err(ProtocolError::malformed)?;
    Ok(())
}

trait ClosedTag {
    fn closed_tag(self) -> u16;
}

impl ClosedTag for ContentKindV2 {
    fn closed_tag(self) -> u16 {
        self.tag()
    }
}

impl ClosedTag for InputChannelV2 {
    fn closed_tag(self) -> u16 {
        self.tag()
    }
}

impl ClosedTag for DirectInputChannelV2 {
    fn closed_tag(self) -> u16 {
        self.tag()
    }
}

impl ClosedTag for InputSourceKindV2 {
    fn closed_tag(self) -> u16 {
        self.tag()
    }
}

fn decode_closed<T>(
    decoder: &mut minicbor::Decoder<'_>,
    from_tag: fn(u16) -> Result<T, ProtocolError>,
) -> Result<T, ProtocolError> {
    expect_array(decoder, 1)?;
    from_tag(decoder.u16().map_err(ProtocolError::malformed)?)
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

fn definite_array_length(decoder: &mut minicbor::Decoder<'_>) -> Result<u64, ProtocolError> {
    decoder
        .array()
        .map_err(ProtocolError::malformed)?
        .ok_or_else(malformed)
}

fn bounded_array_length(
    decoder: &mut minicbor::Decoder<'_>,
    maximum: usize,
) -> Result<usize, ProtocolError> {
    let length = usize::try_from(definite_array_length(decoder)?).map_err(|_| malformed())?;
    if length > maximum {
        return Err(malformed());
    }
    Ok(length)
}

fn version_is_zero(value: VersionV2) -> bool {
    value.major() == 0 && value.minor() == 0 && value.patch() == 0
}

fn option_is_zero(value: Option<Digest32V2>) -> bool {
    value.is_some_and(|digest| is_zero(digest.as_bytes()))
}

fn validate_signature_parts(
    key_id: Ed25519KeyIdV2,
    signature: Ed25519SignatureV2,
) -> Result<(), ProtocolError> {
    if is_zero(key_id.as_bytes()) || is_zero(signature.as_bytes()) {
        return Err(malformed());
    }
    Ok(())
}

fn verify_signature(
    domain: &[u8],
    payload: &[u8],
    public_key: [u8; 32],
    signature: Ed25519SignatureV2,
) -> Result<(), ProtocolError> {
    let key = VerifyingKey::from_bytes(&public_key)
        .map_err(|_| ProtocolError::stable(StableCode::AttestationInvalidSignature))?;
    key.verify_strict(
        &signature_input(domain, payload),
        &Signature::from_bytes(signature.as_bytes()),
    )
    .map_err(|_| ProtocolError::stable(StableCode::AttestationInvalidSignature))
}

fn signature_input(domain: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut signing_input = Vec::with_capacity(domain.len() + 32);
    signing_input.extend_from_slice(domain);
    signing_input.extend_from_slice(&Sha256::digest(payload));
    signing_input
}

fn decode_error(position: usize) -> minicbor::decode::Error {
    minicbor::decode::Error::message(StableCode::ProtocolMalformedCbor.as_str()).at(position)
}

fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

fn domain_hash_many(domain: &[u8], values: &[&[u8]]) -> Digest32V2 {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for value in values {
        hasher.update(value);
    }
    Digest32V2::new(hasher.finalize().into())
}

fn malformed() -> ProtocolError {
    ProtocolError::stable(StableCode::ProtocolMalformedCbor)
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer as _, SigningKey};

    use super::{
        encode_unsigned_parser_worker_job_descriptor,
        encode_unsigned_parser_worker_result_attestation, parser_worker_transcript_begin_v2,
        parser_worker_transcript_step_v2, PageProvenanceV2, ParserWorkerPageFrameV2,
        SignedParserWorkerJobDescriptorV2, SignedParserWorkerResultAttestationV2,
        UnsignedParserWorkerJobDescriptorV2, UnsignedParserWorkerResultAttestationV2,
        PARSER_JOB_DESCRIPTOR_SIGNATURE_DOMAIN, PARSER_RESULT_SIGNATURE_DOMAIN,
    };
    use crate::v2::{
        derive_ed25519_key_id_v2, ClosedConfidenceClassV2, ClosedMediaTypeV2, Digest32V2,
        Ed25519SignatureV2, FixedBytes32V2, ImplementationIdV2, Nonce32V2, ServiceIdentityV2,
        UnixMillisV2, VersionV2, ZeroizingBytesV2,
    };
    use sha2::{Digest as _, Sha256};

    fn signature_input(domain: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut input = Vec::from(domain);
        input.extend_from_slice(&Sha256::digest(payload));
        input
    }

    #[test]
    fn parser_job_and_result_signatures_bind_exact_transcript_and_job() {
        let descriptor_signing_key = SigningKey::from_bytes(&[0x11; 32]);
        let result_signing_key = SigningKey::from_bytes(&[0x12; 32]);
        let installation = Digest32V2::new([0x13; 32]);
        let manifest = Digest32V2::new([0x14; 32]);
        let ingressd = ServiceIdentityV2::new([0x15; 32]);
        let session_binding = Digest32V2::new([0x16; 32]);
        let original_digest = Digest32V2::new([0x17; 32]);
        let job_nonce = Nonce32V2::new([0x18; 32]);
        let result_public_key = result_signing_key.verifying_key().to_bytes();
        let result_key_id = derive_ed25519_key_id_v2(result_public_key);
        let unsigned_job = UnsignedParserWorkerJobDescriptorV2::new(
            installation,
            manifest,
            7,
            ingressd,
            job_nonce,
            session_binding,
            4,
            original_digest,
            ClosedMediaTypeV2::new(1),
            ClosedMediaTypeV2::new(1),
            Digest32V2::new([0x19; 32]),
            ImplementationIdV2::new(1),
            Digest32V2::new([0x1a; 32]),
            None,
            None,
            VersionV2::new(1, 0, 0),
            Digest32V2::new([0x1b; 32]),
            FixedBytes32V2::new(result_public_key),
            result_key_id,
            UnixMillisV2::new(200),
        )
        .unwrap();
        let job_payload = encode_unsigned_parser_worker_job_descriptor(&unsigned_job).unwrap();
        let signed_job = SignedParserWorkerJobDescriptorV2::from_parts(
            unsigned_job,
            derive_ed25519_key_id_v2(descriptor_signing_key.verifying_key().to_bytes()),
            Ed25519SignatureV2::new(
                descriptor_signing_key
                    .sign(&signature_input(
                        PARSER_JOB_DESCRIPTOR_SIGNATURE_DOMAIN,
                        &job_payload,
                    ))
                    .to_bytes(),
            ),
        )
        .unwrap();
        let verified_job = signed_job
            .verify(
                derive_ed25519_key_id_v2(descriptor_signing_key.verifying_key().to_bytes()),
                descriptor_signing_key.verifying_key().to_bytes(),
                installation,
                manifest,
                7,
                ingressd,
                session_binding,
                4,
                original_digest,
                UnixMillisV2::new(100),
            )
            .unwrap();

        let extracted = b"abc";
        let extracted_digest = Digest32V2::new(Sha256::digest(extracted).into());
        let begin =
            parser_worker_transcript_begin_v2(job_nonce, verified_job.descriptor_digest()).unwrap();
        let provisional = ParserWorkerPageFrameV2::new(
            job_nonce,
            0,
            0,
            true,
            Digest32V2::new([0x1c; 32]),
            ZeroizingBytesV2::new(extracted.to_vec()).unwrap(),
            extracted_digest,
            Digest32V2::new([0x1d; 32]),
        )
        .unwrap();
        let transcript = parser_worker_transcript_step_v2(begin, &provisional).unwrap();
        let frame = ParserWorkerPageFrameV2::new(
            job_nonce,
            0,
            0,
            true,
            provisional.rendered_input_digest(),
            ZeroizingBytesV2::new(extracted.to_vec()).unwrap(),
            extracted_digest,
            transcript,
        )
        .unwrap();
        assert_eq!(
            parser_worker_transcript_step_v2(begin, &frame).unwrap(),
            transcript
        );

        let unsigned_result = UnsignedParserWorkerResultAttestationV2::new(
            job_nonce,
            verified_job.descriptor_digest(),
            session_binding,
            verified_job.worker_artifact_digest(),
            result_key_id,
            4,
            original_digest,
            1,
            vec![PageProvenanceV2::new(
                0,
                0,
                1,
                3,
                frame.rendered_input_digest(),
                3,
                extracted_digest,
                3,
                ClosedConfidenceClassV2::new(1),
            )
            .unwrap()],
            transcript,
            3,
            extracted_digest,
            UnixMillisV2::new(150),
        )
        .unwrap();
        let result_payload =
            encode_unsigned_parser_worker_result_attestation(&unsigned_result).unwrap();
        let result = SignedParserWorkerResultAttestationV2::from_parts(
            unsigned_result,
            result_key_id,
            Ed25519SignatureV2::new(
                result_signing_key
                    .sign(&signature_input(
                        PARSER_RESULT_SIGNATURE_DOMAIN,
                        &result_payload,
                    ))
                    .to_bytes(),
            ),
        )
        .unwrap()
        .verify_for_job(verified_job, UnixMillisV2::new(160))
        .unwrap();
        assert_eq!(result.page_count(), 1);
        assert_eq!(result.extracted_output_digest(), extracted_digest);
        assert_eq!(result.ordered_page_frame_transcript_digest(), transcript);
    }
}
