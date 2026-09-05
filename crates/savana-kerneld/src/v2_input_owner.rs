use getrandom::getrandom;
use hmac::{Hmac, Mac as _};
use savana_kernel_protocol::v2::{
    encode_kernel_ingress_operation_v2, input_channel_begin_digest_v2,
    input_channel_step_digest_v2, input_session_internal_id_v2, input_source_provenance_digest_v2,
    parser_worker_transcript_begin_v2, parser_worker_transcript_step_v2, AbortInputRequestV2,
    AppendInputChunkRequestV2, AppendParserWorkerPageFrameRequestV2, AuthorityHandleKeyV2,
    BeginInputRequestV2, ClosedExtensionClassV2, CommitParserWorkerResultRequestV2, ContentKindV2,
    Digest32V2, DirectInputChannelV2, DurableTaskIdV2, Ed25519KeyIdV2, FinalizeInputRequestV2,
    ImplementationIdV2, IngressUiAuthorizationHandleV2, IngressWriteCapabilityV2,
    InputChannelCommitmentV2, InputChannelV2, InputSessionHandleV2, InputSourceKindV2,
    InputSourceProvenanceV2, InputStatusTargetV2, KernelIngressOperationV2,
    ParserExtractionHandleV2, PrincipalIdV2, RegisterParserWorkerJobRequestV2, ServiceIdentityV2,
    UnixMillisV2, VerifiedParserWorkerJobDescriptorV2, VerifiedParserWorkerResultAttestationV2,
    VerifiedUiAuthenticationSettlementV2, VersionV2,
};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

const MAX_INPUT_CHUNK_BYTES: usize = 1024 * 1024;
const TASK_SUBMISSION_DOMAIN: &[u8] =
    b"SAVANA_AUTHENTICATED_STRUCTURED_TASK_SUBMISSION_V2_SCHEMA1\0";
const MAX_INPUT_SESSION_BYTES: usize = 64 * 1024 * 1024;
const INPUT_COMMITMENT_DOMAIN: &[u8] = b"SAVANA_FINALIZED_INPUT_COMMITMENT_V2\0";
const CHANNEL_COMMITMENTS_DOMAIN: &[u8] = b"SAVANA_INPUT_CHANNEL_COMMITMENTS_V2\0";
const PARSER_JOB_BINDING_DOMAIN: &[u8] = b"SAVANA_PARSER_JOB_SESSION_BINDING_V2\0";
const PARSER_EXTRACTION_HANDLE_DOMAIN: &[u8] = b"SAVANA_PARSER_EXTRACTION_HANDLE_MINT_V2\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KernelInputErrorV2 {
    InvalidReference,
    AlreadyConsumed,
    StateConflict,
    InvalidSequence,
    DigestMismatch,
    LimitExceeded,
    ProvenanceMismatch,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KernelInputFinalizeTransactionErrorV2<E> {
    Input(KernelInputErrorV2),
    Preparation(E),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KernelInputPublicStateV2 {
    Receiving,
    Finalized,
    Aborted,
    FailedClosed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct KernelParserTrustV2 {
    descriptor_key_id: Ed25519KeyIdV2,
    descriptor_verifying_key: [u8; 32],
    worker_artifact_digest: Digest32V2,
    parser_implementation_id: ImplementationIdV2,
    parser_semantic_version: VersionV2,
    parser_code_digest: Digest32V2,
    renderer_code_digest: Option<Digest32V2>,
    ocr_model_set_digest: Option<Digest32V2>,
    normalization_version: VersionV2,
    output_limits_digest: Digest32V2,
    extension_class: ClosedExtensionClassV2,
    maximum_pages: u32,
    maximum_output_bytes: usize,
}

impl KernelParserTrustV2 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        descriptor_key_id: Ed25519KeyIdV2,
        descriptor_verifying_key: [u8; 32],
        worker_artifact_digest: Digest32V2,
        parser_implementation_id: ImplementationIdV2,
        parser_semantic_version: VersionV2,
        parser_code_digest: Digest32V2,
        renderer_code_digest: Option<Digest32V2>,
        ocr_model_set_digest: Option<Digest32V2>,
        normalization_version: VersionV2,
        output_limits_digest: Digest32V2,
        extension_class: ClosedExtensionClassV2,
        maximum_pages: u32,
        maximum_output_bytes: usize,
    ) -> Result<Self, KernelInputErrorV2> {
        if savana_kernel_protocol::v2::derive_ed25519_key_id_v2(descriptor_verifying_key)
            != descriptor_key_id
            || is_zero(descriptor_key_id.as_bytes())
            || is_zero(&descriptor_verifying_key)
            || is_zero(worker_artifact_digest.as_bytes())
            || parser_implementation_id.get() == 0
            || version_is_zero(parser_semantic_version)
            || is_zero(parser_code_digest.as_bytes())
            || renderer_code_digest.is_some_and(|digest| is_zero(digest.as_bytes()))
            || ocr_model_set_digest.is_some_and(|digest| is_zero(digest.as_bytes()))
            || version_is_zero(normalization_version)
            || is_zero(output_limits_digest.as_bytes())
            || extension_class.get() == 0
            || maximum_pages == 0
            || maximum_pages > 2048
            || maximum_output_bytes == 0
            || maximum_output_bytes > 8 * 1024 * 1024
        {
            return Err(KernelInputErrorV2::ProvenanceMismatch);
        }
        Ok(Self {
            descriptor_key_id,
            descriptor_verifying_key,
            worker_artifact_digest,
            parser_implementation_id,
            parser_semantic_version,
            parser_code_digest,
            renderer_code_digest,
            ocr_model_set_digest,
            normalization_version,
            output_limits_digest,
            extension_class,
            maximum_pages,
            maximum_output_bytes,
        })
    }

    #[cfg(test)]
    pub(crate) const fn descriptor_key_id(self) -> Ed25519KeyIdV2 {
        self.descriptor_key_id
    }

    #[cfg(test)]
    pub(crate) const fn descriptor_verifying_key(self) -> [u8; 32] {
        self.descriptor_verifying_key
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct KernelParserRegistrationV2 {
    extraction: ParserExtractionHandleV2,
}

impl KernelParserRegistrationV2 {
    pub(crate) const fn extraction(self) -> ParserExtractionHandleV2 {
        self.extraction
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct KernelParserAppendAckV2 {
    page_index: u32,
    page_chunk_index: u32,
    transcript_digest: Digest32V2,
}

impl KernelParserAppendAckV2 {
    pub(crate) const fn page_index(self) -> u32 {
        self.page_index
    }

    pub(crate) const fn page_chunk_index(self) -> u32 {
        self.page_chunk_index
    }

    pub(crate) const fn transcript_digest(self) -> Digest32V2 {
        self.transcript_digest
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KernelParserCommitV2 {
    extracted_channel_commitment: InputChannelCommitmentV2,
    parsed_source_provenance_digest: Digest32V2,
    parsed_source_provenance: InputSourceProvenanceV2,
}

impl KernelParserCommitV2 {
    pub(crate) const fn extracted_channel_commitment(&self) -> InputChannelCommitmentV2 {
        self.extracted_channel_commitment
    }

    pub(crate) const fn parsed_source_provenance_digest(&self) -> Digest32V2 {
        self.parsed_source_provenance_digest
    }

    #[cfg(test)]
    pub(crate) const fn parsed_source_provenance(&self) -> &InputSourceProvenanceV2 {
        &self.parsed_source_provenance
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct KernelVerifiedUiAuthorizationV2 {
    durable_task_id: Option<DurableTaskIdV2>,
    installation_id: Digest32V2,
    authenticated_principal: PrincipalIdV2,
    settlement_digest: Digest32V2,
    authentication_context_digest: Digest32V2,
    binding_digest: Digest32V2,
    active_state_manifest_digest: Digest32V2,
    deployment_generation: u64,
    expires_at: UnixMillisV2,
}

impl KernelVerifiedUiAuthorizationV2 {
    pub(crate) fn from_verified_settlement(
        settlement: VerifiedUiAuthenticationSettlementV2,
    ) -> Self {
        Self {
            durable_task_id: None,
            installation_id: settlement.installation_id(),
            authenticated_principal: settlement.authenticated_principal(),
            settlement_digest: settlement.settlement_digest(),
            authentication_context_digest: settlement.authentication_context_digest(),
            binding_digest: settlement.binding_digest(),
            active_state_manifest_digest: settlement.active_state_manifest_digest(),
            deployment_generation: settlement.deployment_generation(),
            expires_at: settlement.expires_at(),
        }
    }

    pub(crate) fn from_bound_verified_settlement(
        durable_task_id: DurableTaskIdV2,
        settlement: VerifiedUiAuthenticationSettlementV2,
    ) -> Result<Self, KernelInputErrorV2> {
        if durable_task_id.as_bytes().iter().all(|byte| *byte == 0) {
            return Err(KernelInputErrorV2::ProvenanceMismatch);
        }
        let mut authorization = Self::from_verified_settlement(settlement);
        authorization.durable_task_id = Some(durable_task_id);
        Ok(authorization)
    }

    pub(crate) const fn durable_task_id(self) -> Option<DurableTaskIdV2> {
        self.durable_task_id
    }

    pub(crate) const fn installation_id(self) -> Digest32V2 {
        self.installation_id
    }

    pub(crate) const fn authenticated_principal(self) -> PrincipalIdV2 {
        self.authenticated_principal
    }

    pub(crate) const fn settlement_digest(self) -> Digest32V2 {
        self.settlement_digest
    }

    pub(crate) const fn authentication_context_digest(self) -> Digest32V2 {
        self.authentication_context_digest
    }

    pub(crate) const fn binding_digest(self) -> Digest32V2 {
        self.binding_digest
    }

    pub(crate) const fn active_state_manifest_digest(self) -> Digest32V2 {
        self.active_state_manifest_digest
    }

    pub(crate) const fn deployment_generation(self) -> u64 {
        self.deployment_generation
    }

    pub(crate) const fn expires_at(self) -> UnixMillisV2 {
        self.expires_at
    }

    #[cfg(test)]
    pub(crate) fn for_test() -> Self {
        Self {
            durable_task_id: Some(DurableTaskIdV2::new([0x2f; 32])),
            installation_id: Digest32V2::new([0x30; 32]),
            authenticated_principal: PrincipalIdV2::new([0x31; 32]),
            settlement_digest: Digest32V2::new([0x32; 32]),
            authentication_context_digest: Digest32V2::new([0x33; 32]),
            binding_digest: Digest32V2::new([0x34; 32]),
            active_state_manifest_digest: Digest32V2::new([0x35; 32]),
            deployment_generation: 7,
            expires_at: UnixMillisV2::new(500),
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test_with_expiry(expires_at: UnixMillisV2) -> Self {
        let mut authorization = Self::for_test();
        authorization.expires_at = expires_at;
        authorization
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct KernelInputChannelCursorV2 {
    channel: InputChannelV2,
    next_sequence: u32,
    cumulative_digest: Digest32V2,
}

impl KernelInputChannelCursorV2 {
    pub(crate) const fn channel(self) -> InputChannelV2 {
        self.channel
    }

    pub(crate) const fn next_sequence(self) -> u32 {
        self.next_sequence
    }

    #[cfg(test)]
    pub(crate) const fn cumulative_digest(self) -> Digest32V2 {
        self.cumulative_digest
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KernelInputBeginV2 {
    session: InputSessionHandleV2,
    writer: IngressWriteCapabilityV2,
    parser_job_session_binding_digest: Digest32V2,
    channels: Vec<KernelInputChannelCursorV2>,
}

impl KernelInputBeginV2 {
    pub(crate) const fn session(&self) -> InputSessionHandleV2 {
        self.session
    }

    pub(crate) const fn writer(&self) -> IngressWriteCapabilityV2 {
        self.writer
    }

    pub(crate) const fn parser_job_session_binding_digest(&self) -> Digest32V2 {
        self.parser_job_session_binding_digest
    }

    pub(crate) fn channels(&self) -> &[KernelInputChannelCursorV2] {
        &self.channels
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct KernelInputAppendAckV2 {
    channel: DirectInputChannelV2,
    acknowledged_sequence: u32,
    cumulative_digest: Digest32V2,
}

impl KernelInputAppendAckV2 {
    pub(crate) const fn channel(self) -> DirectInputChannelV2 {
        self.channel
    }

    pub(crate) const fn acknowledged_sequence(self) -> u32 {
        self.acknowledged_sequence
    }

    pub(crate) const fn cumulative_digest(self) -> Digest32V2 {
        self.cumulative_digest
    }
}

pub(crate) struct FinalizedKernelInputChannelV2 {
    channel: InputChannelV2,
    bytes: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for FinalizedKernelInputChannelV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FinalizedKernelInputChannelV2")
            .field("channel", &self.channel)
            .field("encoded_length", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

impl FinalizedKernelInputChannelV2 {
    pub(crate) const fn channel(&self) -> InputChannelV2 {
        self.channel
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

pub(crate) struct FinalizedKernelInputV2 {
    input_commitment: Digest32V2,
    source_provenance_digest: Digest32V2,
    authorization: KernelVerifiedUiAuthorizationV2,
    channels: Vec<FinalizedKernelInputChannelV2>,
}

impl std::fmt::Debug for FinalizedKernelInputV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FinalizedKernelInputV2")
            .field("input_commitment", &self.input_commitment)
            .field("channel_count", &self.channels.len())
            .finish_non_exhaustive()
    }
}

impl FinalizedKernelInputV2 {
    pub(crate) const fn input_commitment(&self) -> Digest32V2 {
        self.input_commitment
    }

    pub(crate) const fn source_provenance_digest(&self) -> Digest32V2 {
        self.source_provenance_digest
    }

    pub(crate) const fn authorization(&self) -> KernelVerifiedUiAuthorizationV2 {
        self.authorization
    }

    pub(crate) fn channels(&self) -> &[FinalizedKernelInputChannelV2] {
        &self.channels
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PreparedKernelInputFinalizationV2 {
    input_commitment: Digest32V2,
    source_provenance_digest: Digest32V2,
    authorization: KernelVerifiedUiAuthorizationV2,
    channel_commitments_digest: Digest32V2,
}

impl PreparedKernelInputFinalizationV2 {
    pub(crate) const fn input_commitment(self) -> Digest32V2 {
        self.input_commitment
    }

    pub(crate) const fn source_provenance_digest(self) -> Digest32V2 {
        self.source_provenance_digest
    }

    pub(crate) const fn authorization(self) -> KernelVerifiedUiAuthorizationV2 {
        self.authorization
    }

    pub(crate) const fn channel_commitments_digest(self) -> Digest32V2 {
        self.channel_commitments_digest
    }
}

struct AuthorizationRecordV2 {
    commitment: Digest32V2,
    authorization: KernelVerifiedUiAuthorizationV2,
    consumed: bool,
}

struct AcceptedChunkV2 {
    sequence: u32,
    start: usize,
    length: usize,
    chunk_digest: Digest32V2,
    prior_cumulative_digest: Digest32V2,
    resulting_cumulative_digest: Digest32V2,
}

struct InputChannelRecordV2 {
    channel: InputChannelV2,
    next_sequence: u32,
    cumulative_digest: Digest32V2,
    bytes: Zeroizing<Vec<u8>>,
    chunks: Vec<AcceptedChunkV2>,
}

struct InputSessionRecordV2 {
    session_commitment: Digest32V2,
    session_internal_id: Digest32V2,
    writer_commitment: Digest32V2,
    content_kind: ContentKindV2,
    declared_total_bytes: u64,
    declared_content_digest: Option<Digest32V2>,
    parser_job_session_binding_digest: Digest32V2,
    authorization: KernelVerifiedUiAuthorizationV2,
    state: KernelInputPublicStateV2,
    finalize_request_digest: Option<Digest32V2>,
    finalized_input_commitment: Option<Digest32V2>,
    channels: Vec<InputChannelRecordV2>,
    parsed_source_provenance: Option<(InputSourceProvenanceV2, Digest32V2)>,
}

struct AcceptedParserFrameV2 {
    page_index: u32,
    page_chunk_index: u32,
    final_chunk_for_page: bool,
    rendered_input_digest: Digest32V2,
    extracted_chunk_digest: Digest32V2,
    transcript_digest: Digest32V2,
    start: usize,
    length: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParserExtractionStateV2 {
    Staging,
    FailedClosed,
    Committed,
}

struct ParserExtractionRecordV2 {
    handle_commitment: Digest32V2,
    session_commitment: Digest32V2,
    verified_job: VerifiedParserWorkerJobDescriptorV2,
    trust: KernelParserTrustV2,
    transcript_digest: Digest32V2,
    frames: Vec<AcceptedParserFrameV2>,
    bytes: Zeroizing<Vec<u8>>,
    state: ParserExtractionStateV2,
    commit_request_digest: Option<Digest32V2>,
    committed_result: Option<KernelParserCommitV2>,
}

pub(crate) struct KernelInputOwnerV2 {
    handle_key: AuthorityHandleKeyV2,
    parser_handle_mint_key: Zeroizing<[u8; 32]>,
    maximum_sessions: usize,
    maximum_input_bytes: usize,
    authorizations: Vec<AuthorizationRecordV2>,
    sessions: Vec<InputSessionRecordV2>,
    extractions: Vec<ParserExtractionRecordV2>,
}

/// Created only by the input owner after resolving verified UI authentication
/// and either finalized input or an exact, previously persisted task draft.
/// Recovery proof is for the existing issuance only, never input finalization.
pub(crate) struct AuthenticatedTaskContextSubjectV2 {
    authorization: KernelVerifiedUiAuthorizationV2,
    source: Option<Digest32V2>,
}
impl AuthenticatedTaskContextSubjectV2 {
    pub(crate) fn authorization(&self) -> KernelVerifiedUiAuthorizationV2 {
        self.authorization
    }
    pub(crate) fn source(&self) -> Option<Digest32V2> {
        self.source
    }
}

pub(crate) struct AuthenticatedTaskDraftSubmissionV2 {
    draft_digest: Digest32V2,
    evidence_digest: Digest32V2,
    authorization: KernelVerifiedUiAuthorizationV2,
    recovery_request: Option<Digest32V2>,
}
impl AuthenticatedTaskDraftSubmissionV2 {
    pub(crate) fn is_recovery(&self) -> bool {
        self.recovery_request.is_some()
    }
    pub(crate) fn draft_digest(&self) -> Digest32V2 {
        self.draft_digest
    }
    pub(crate) fn evidence_digest(&self) -> Digest32V2 {
        self.evidence_digest
    }
    pub(crate) fn authorization(&self) -> KernelVerifiedUiAuthorizationV2 {
        self.authorization
    }
}

impl std::fmt::Debug for KernelInputOwnerV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("KernelInputOwnerV2")
            .field("maximum_sessions", &self.maximum_sessions)
            .field("maximum_input_bytes", &self.maximum_input_bytes)
            .field("session_count", &self.sessions.len())
            .finish_non_exhaustive()
    }
}

impl KernelInputOwnerV2 {
    pub(crate) fn authenticate_task_context(
        &self,
        request: &savana_kernel_protocol::v2::GetTaskAuthorizationContextRequestV2,
        manifest: Digest32V2,
        generation: u64,
        now: UnixMillisV2,
    ) -> Result<AuthenticatedTaskContextSubjectV2, KernelInputErrorV2> {
        let commitment = request
            .authorization()
            .authority_commitment(&self.handle_key);
        let auth = self
            .authorizations
            .iter()
            .find(|r| r.commitment == commitment)
            .ok_or(KernelInputErrorV2::InvalidReference)?
            .authorization;
        if auth.durable_task_id().is_none()
            || auth.active_state_manifest_digest() != manifest
            || auth.deployment_generation() != generation
            || now.get() == 0
            || now.get() >= auth.expires_at().get()
        {
            return Err(KernelInputErrorV2::ProvenanceMismatch);
        }
        let source = if let Some(session) = request.session() {
            let commitment = session.authority_commitment(&self.handle_key);
            let record = self
                .sessions
                .iter()
                .find(|r| r.session_commitment == commitment)
                .ok_or(KernelInputErrorV2::InvalidReference)?;
            if record.authorization != auth || record.state != KernelInputPublicStateV2::Finalized {
                return Err(KernelInputErrorV2::ProvenanceMismatch);
            }
            Some(
                record
                    .finalized_input_commitment
                    .ok_or(KernelInputErrorV2::ProvenanceMismatch)?,
            )
        } else {
            None
        };
        Ok(AuthenticatedTaskContextSubjectV2 {
            authorization: auth,
            source,
        })
    }
    pub(crate) fn authenticate_task_recovery(
        &self,
        authorization: IngressUiAuthorizationHandleV2,
        pending: &savana_policy_core::v2::PendingTaskAuthorizationV2,
        manifest: Digest32V2,
        generation: u64,
        now: UnixMillisV2,
    ) -> Result<AuthenticatedTaskDraftSubmissionV2, KernelInputErrorV2> {
        let commitment = authorization.authority_commitment(&self.handle_key);
        let auth = self
            .authorizations
            .iter()
            .find(|r| r.commitment == commitment)
            .ok_or(KernelInputErrorV2::InvalidReference)?
            .authorization;
        let draft = pending.draft();
        if auth.durable_task_id() != Some(draft.task())
            || auth.authenticated_principal() != draft.principal()
            || auth.installation_id() != draft.installation_digest()
            || auth.active_state_manifest_digest() != manifest
            || draft.manifest_digest() != manifest
            || auth.deployment_generation() != generation
            || draft.deployment_generation() != generation
            || now.get() == 0
            || now.get() >= auth.expires_at().get()
            || now.get() < draft.not_before().get()
            || now.get() >= draft.expires_at().get()
        {
            return Err(KernelInputErrorV2::ProvenanceMismatch);
        }
        let draft_digest = pending
            .draft_digest()
            .map_err(|_| KernelInputErrorV2::ProvenanceMismatch)?;
        Ok(AuthenticatedTaskDraftSubmissionV2 {
            draft_digest,
            recovery_request: Some(pending.request_digest()),
            evidence_digest: domain_hash_many(
                b"SAVANA_TASK_RECOVERY_AUTHENTICATION_V2\0",
                &[
                    pending.request_digest().as_bytes(),
                    draft_digest.as_bytes(),
                    auth.settlement_digest().as_bytes(),
                    auth.authentication_context_digest().as_bytes(),
                    auth.binding_digest().as_bytes(),
                ],
            ),
            authorization: auth,
        })
    }

    /// This method is for the dedicated typed ingress operation only, never for
    /// interpreting chat text or planner output as user authorization.
    pub(crate) fn authenticate_task_draft_submission(
        &self,
        session: InputSessionHandleV2,
        draft: &savana_kernel_protocol::v2::TaskAuthorizationDraftV2,
        manifest: Digest32V2,
        generation: u64,
        now: UnixMillisV2,
    ) -> Result<AuthenticatedTaskDraftSubmissionV2, KernelInputErrorV2> {
        let commitment = session.authority_commitment(&self.handle_key);
        let record = self
            .sessions
            .iter()
            .find(|s| s.session_commitment == commitment)
            .ok_or(KernelInputErrorV2::InvalidReference)?;
        let auth = record.authorization;
        if record.state != KernelInputPublicStateV2::Finalized
            || record.finalized_input_commitment != Some(draft.source_input_digest())
            || auth.durable_task_id() != Some(draft.task())
            || auth.authenticated_principal() != draft.principal()
            || auth.installation_id() != draft.installation_digest()
            || auth.active_state_manifest_digest() != manifest
            || draft.manifest_digest() != manifest
            || auth.deployment_generation() != generation
            || draft.deployment_generation() != generation
            || now.get() == 0
            || now.get() >= auth.expires_at().get()
            || now.get() < draft.not_before().get()
            || now.get() >= draft.expires_at().get()
        {
            return Err(KernelInputErrorV2::ProvenanceMismatch);
        }
        let draft_digest = savana_kernel_protocol::v2::task_authorization_draft_digest_v2(draft)
            .map_err(|_| KernelInputErrorV2::ProvenanceMismatch)?;
        let evidence_digest = domain_hash_many(
            TASK_SUBMISSION_DOMAIN,
            &[
                draft_digest.as_bytes(),
                auth.settlement_digest().as_bytes(),
                auth.authentication_context_digest().as_bytes(),
                auth.binding_digest().as_bytes(),
                draft.source_input_digest().as_bytes(),
            ],
        );
        Ok(AuthenticatedTaskDraftSubmissionV2 {
            draft_digest,
            evidence_digest,
            authorization: auth,
            recovery_request: None,
        })
    }

    pub(crate) fn new(
        maximum_sessions: usize,
        maximum_input_bytes: usize,
    ) -> Result<Self, KernelInputErrorV2> {
        if maximum_sessions == 0
            || maximum_sessions > 65_536
            || maximum_input_bytes == 0
            || maximum_input_bytes > MAX_INPUT_SESSION_BYTES
        {
            return Err(KernelInputErrorV2::LimitExceeded);
        }
        let handle_key = AuthorityHandleKeyV2::from_entropy(random_bytes()?)
            .ok_or(KernelInputErrorV2::Unavailable)?;
        let parser_handle_mint_key = Zeroizing::new(random_bytes()?);
        Ok(Self {
            handle_key,
            parser_handle_mint_key,
            maximum_sessions,
            maximum_input_bytes,
            authorizations: Vec::new(),
            sessions: Vec::new(),
            extractions: Vec::new(),
        })
    }

    pub(crate) fn register_verified_ui_authorization(
        &mut self,
        authorization: IngressUiAuthorizationHandleV2,
        evidence: KernelVerifiedUiAuthorizationV2,
    ) -> Result<(), KernelInputErrorV2> {
        let commitment = authorization.authority_commitment(&self.handle_key);
        if self
            .authorizations
            .iter()
            .any(|record| record.commitment == commitment)
        {
            return Err(KernelInputErrorV2::AlreadyConsumed);
        }
        self.authorizations
            .try_reserve(1)
            .map_err(|_| KernelInputErrorV2::Unavailable)?;
        self.authorizations.push(AuthorizationRecordV2 {
            commitment,
            authorization: evidence,
            consumed: false,
        });
        Ok(())
    }

    pub(crate) fn begin(
        &mut self,
        request: BeginInputRequestV2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        now: UnixMillisV2,
    ) -> Result<KernelInputBeginV2, KernelInputErrorV2> {
        if self.sessions.len() >= self.maximum_sessions
            || request.declared_total_bytes() > self.maximum_input_bytes as u64
        {
            return Err(KernelInputErrorV2::LimitExceeded);
        }
        let authorization = request
            .ui_authorization()
            .authority_commitment(&self.handle_key);
        let authorization_index = self
            .authorizations
            .iter()
            .position(|record| record.commitment == authorization)
            .ok_or(KernelInputErrorV2::InvalidReference)?;
        if self.authorizations[authorization_index].consumed {
            return Err(KernelInputErrorV2::AlreadyConsumed);
        }
        let authorization_evidence = self.authorizations[authorization_index].authorization;
        if authorization_evidence.active_state_manifest_digest() != active_state_manifest_digest
            || authorization_evidence.deployment_generation() != deployment_generation
            || now.get() == 0
            || now.get() >= authorization_evidence.expires_at().get()
        {
            return Err(KernelInputErrorV2::ProvenanceMismatch);
        }

        let session = self.mint_session()?;
        let writer = self.mint_writer()?;
        let session_commitment = session.authority_commitment(&self.handle_key);
        let writer_commitment = writer.authority_commitment(&self.handle_key);
        let allowed_channels = allowed_channels(request.content_kind());
        let mut channels = Vec::new();
        let mut public_channels = Vec::new();
        channels
            .try_reserve_exact(allowed_channels.len())
            .map_err(|_| KernelInputErrorV2::Unavailable)?;
        public_channels
            .try_reserve_exact(allowed_channels.len())
            .map_err(|_| KernelInputErrorV2::Unavailable)?;
        for channel in allowed_channels {
            let channel = *channel;
            let cumulative_digest = input_channel_begin_digest_v2(session, channel);
            channels.push(InputChannelRecordV2 {
                channel,
                next_sequence: 0,
                cumulative_digest,
                bytes: Zeroizing::new(Vec::new()),
                chunks: Vec::new(),
            });
            public_channels.push(KernelInputChannelCursorV2 {
                channel,
                next_sequence: 0,
                cumulative_digest,
            });
        }
        let parser_job_session_binding_digest = domain_hash_many(
            PARSER_JOB_BINDING_DOMAIN,
            &[
                input_session_internal_id_v2(session).as_bytes(),
                &request.content_kind().tag().to_be_bytes(),
            ],
        );
        self.sessions
            .try_reserve(1)
            .map_err(|_| KernelInputErrorV2::Unavailable)?;
        self.sessions.push(InputSessionRecordV2 {
            session_commitment,
            session_internal_id: input_session_internal_id_v2(session),
            writer_commitment,
            content_kind: request.content_kind(),
            declared_total_bytes: request.declared_total_bytes(),
            declared_content_digest: request.declared_content_digest(),
            parser_job_session_binding_digest,
            authorization: authorization_evidence,
            state: KernelInputPublicStateV2::Receiving,
            finalize_request_digest: None,
            finalized_input_commitment: None,
            channels,
            parsed_source_provenance: None,
        });
        self.authorizations[authorization_index].consumed = true;
        Ok(KernelInputBeginV2 {
            session,
            writer,
            parser_job_session_binding_digest,
            channels: public_channels,
        })
    }

    pub(crate) fn append(
        &mut self,
        request: AppendInputChunkRequestV2,
    ) -> Result<KernelInputAppendAckV2, KernelInputErrorV2> {
        if request.chunk().len() > MAX_INPUT_CHUNK_BYTES {
            return Err(KernelInputErrorV2::LimitExceeded);
        }
        let writer_commitment = request.writer().authority_commitment(&self.handle_key);
        let session_index = self
            .sessions
            .iter()
            .position(|session| session.writer_commitment == writer_commitment)
            .ok_or(KernelInputErrorV2::InvalidReference)?;
        if self.sessions[session_index].state != KernelInputPublicStateV2::Receiving {
            return Err(KernelInputErrorV2::StateConflict);
        }
        let channel_kind = direct_channel(request.channel());
        let channel_index = self.sessions[session_index]
            .channels
            .iter()
            .position(|channel| channel.channel == channel_kind)
            .ok_or(KernelInputErrorV2::StateConflict)?;
        let session = &mut self.sessions[session_index];
        let channel = &mut session.channels[channel_index];

        if request.sequence() < channel.next_sequence {
            let accepted = channel
                .chunks
                .iter()
                .find(|accepted| accepted.sequence == request.sequence())
                .ok_or(KernelInputErrorV2::StateConflict)?;
            let exact_bytes = channel
                .bytes
                .get(accepted.start..accepted.start + accepted.length)
                .is_some_and(|bytes| bytes == request.chunk());
            if !exact_bytes
                || accepted.chunk_digest != request.chunk_digest()
                || accepted.prior_cumulative_digest != request.prior_cumulative_digest()
                || accepted.resulting_cumulative_digest != request.resulting_cumulative_digest()
            {
                fail_closed(session);
                return Err(KernelInputErrorV2::DigestMismatch);
            }
            return Ok(KernelInputAppendAckV2 {
                channel: request.channel(),
                acknowledged_sequence: accepted.sequence,
                cumulative_digest: accepted.resulting_cumulative_digest,
            });
        }
        if request.sequence() != channel.next_sequence {
            return Err(KernelInputErrorV2::InvalidSequence);
        }
        let new_length = channel
            .bytes
            .len()
            .checked_add(request.chunk().len())
            .ok_or(KernelInputErrorV2::LimitExceeded)?;
        if new_length > self.maximum_input_bytes
            || (channel_kind != InputChannelV2::ExtractedPage
                && new_length as u64 > session.declared_total_bytes)
        {
            fail_closed(session);
            return Err(KernelInputErrorV2::LimitExceeded);
        }
        let computed_chunk = input_chunk_digest_from_internal_id(
            session.session_internal_id,
            channel_kind,
            request.sequence(),
            request.chunk(),
        )?;
        let computed_result = input_channel_step_digest_v2(
            channel.cumulative_digest,
            request.sequence(),
            computed_chunk,
        )
        .map_err(|_| KernelInputErrorV2::DigestMismatch)?;
        if request.prior_cumulative_digest() != channel.cumulative_digest
            || request.chunk_digest() != computed_chunk
            || request.resulting_cumulative_digest() != computed_result
        {
            fail_closed(session);
            return Err(KernelInputErrorV2::DigestMismatch);
        }
        channel
            .bytes
            .try_reserve(request.chunk().len())
            .map_err(|_| KernelInputErrorV2::Unavailable)?;
        channel
            .chunks
            .try_reserve(1)
            .map_err(|_| KernelInputErrorV2::Unavailable)?;
        let start = channel.bytes.len();
        channel.bytes.extend_from_slice(request.chunk());
        channel.chunks.push(AcceptedChunkV2 {
            sequence: request.sequence(),
            start,
            length: request.chunk().len(),
            chunk_digest: computed_chunk,
            prior_cumulative_digest: channel.cumulative_digest,
            resulting_cumulative_digest: computed_result,
        });
        channel.next_sequence = channel
            .next_sequence
            .checked_add(1)
            .ok_or(KernelInputErrorV2::StateConflict)?;
        channel.cumulative_digest = computed_result;
        Ok(KernelInputAppendAckV2 {
            channel: request.channel(),
            acknowledged_sequence: request.sequence(),
            cumulative_digest: computed_result,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn register_parser_worker_job(
        &mut self,
        request: RegisterParserWorkerJobRequestV2,
        trust: KernelParserTrustV2,
        ingressd_identity: ServiceIdentityV2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        now: UnixMillisV2,
    ) -> Result<KernelParserRegistrationV2, KernelInputErrorV2> {
        let session_commitment = request.session().authority_commitment(&self.handle_key);
        let session = self
            .sessions
            .iter()
            .find(|session| session.session_commitment == session_commitment)
            .ok_or(KernelInputErrorV2::InvalidReference)?;
        if session.state != KernelInputPublicStateV2::Receiving
            || session.content_kind != ContentKindV2::ParsedDocument
            || session.parsed_source_provenance.is_some()
        {
            return Err(KernelInputErrorV2::StateConflict);
        }
        let original = session
            .channels
            .iter()
            .find(|channel| channel.channel == InputChannelV2::OriginalSource)
            .ok_or(KernelInputErrorV2::StateConflict)?;
        let original_digest = Digest32V2::new(Sha256::digest(&original.bytes).into());
        if original.bytes.len() as u64 != session.declared_total_bytes
            || session
                .declared_content_digest
                .is_some_and(|declared| declared != original_digest)
        {
            return Err(KernelInputErrorV2::ProvenanceMismatch);
        }
        let verified_job = request
            .descriptor()
            .verify(
                trust.descriptor_key_id,
                trust.descriptor_verifying_key,
                session.authorization.installation_id(),
                active_state_manifest_digest,
                deployment_generation,
                ingressd_identity,
                session.parser_job_session_binding_digest,
                original.bytes.len() as u64,
                original_digest,
                now,
            )
            .map_err(|_| KernelInputErrorV2::ProvenanceMismatch)?;
        if !parser_job_matches_trust(verified_job, trust) {
            return Err(KernelInputErrorV2::ProvenanceMismatch);
        }

        if let Some(existing) = self.extractions.iter().find(|extraction| {
            extraction.session_commitment == session_commitment
                && extraction.verified_job.descriptor_digest() == verified_job.descriptor_digest()
        }) {
            if existing.state == ParserExtractionStateV2::FailedClosed {
                return Err(KernelInputErrorV2::StateConflict);
            }
            let extraction = self.parser_extraction_handle(
                session.session_internal_id,
                verified_job.descriptor_digest(),
            )?;
            if extraction.authority_commitment(&self.handle_key) != existing.handle_commitment {
                return Err(KernelInputErrorV2::Unavailable);
            }
            return Ok(KernelParserRegistrationV2 { extraction });
        }
        if self.extractions.iter().any(|extraction| {
            extraction.verified_job.job_nonce() == verified_job.job_nonce()
                || extraction.verified_job.ephemeral_result_key_id()
                    == verified_job.ephemeral_result_key_id()
                || (extraction.session_commitment == session_commitment
                    && extraction.state != ParserExtractionStateV2::FailedClosed)
        }) {
            return Err(KernelInputErrorV2::ProvenanceMismatch);
        }
        let extraction = self.parser_extraction_handle(
            session.session_internal_id,
            verified_job.descriptor_digest(),
        )?;
        let handle_commitment = extraction.authority_commitment(&self.handle_key);
        if self
            .extractions
            .iter()
            .any(|record| record.handle_commitment == handle_commitment)
        {
            return Err(KernelInputErrorV2::Unavailable);
        }
        let transcript_digest = parser_worker_transcript_begin_v2(
            verified_job.job_nonce(),
            verified_job.descriptor_digest(),
        )
        .map_err(|_| KernelInputErrorV2::ProvenanceMismatch)?;
        self.extractions
            .try_reserve(1)
            .map_err(|_| KernelInputErrorV2::Unavailable)?;
        self.extractions.push(ParserExtractionRecordV2 {
            handle_commitment,
            session_commitment,
            verified_job,
            trust,
            transcript_digest,
            frames: Vec::new(),
            bytes: Zeroizing::new(Vec::new()),
            state: ParserExtractionStateV2::Staging,
            commit_request_digest: None,
            committed_result: None,
        });
        Ok(KernelParserRegistrationV2 { extraction })
    }

    pub(crate) fn append_parser_worker_page_frame(
        &mut self,
        request: AppendParserWorkerPageFrameRequestV2,
    ) -> Result<KernelParserAppendAckV2, KernelInputErrorV2> {
        let commitment = request.extraction().authority_commitment(&self.handle_key);
        let extraction_index = self
            .extractions
            .iter()
            .position(|extraction| extraction.handle_commitment == commitment)
            .ok_or(KernelInputErrorV2::InvalidReference)?;
        let frame = request.frame();
        let extraction = &mut self.extractions[extraction_index];
        if extraction.state != ParserExtractionStateV2::Staging {
            return Err(KernelInputErrorV2::StateConflict);
        }

        if let Some(accepted) = extraction.frames.iter().find(|accepted| {
            accepted.page_index == frame.page_index()
                && accepted.page_chunk_index == frame.page_chunk_index()
        }) {
            let exact_bytes = extraction
                .bytes
                .get(accepted.start..accepted.start + accepted.length)
                .is_some_and(|bytes| bytes == frame.extracted_chunk());
            if exact_bytes
                && accepted.final_chunk_for_page == frame.final_chunk_for_page()
                && accepted.rendered_input_digest == frame.rendered_input_digest()
                && accepted.extracted_chunk_digest == frame.extracted_chunk_digest()
                && accepted.transcript_digest == frame.transcript_step_digest()
            {
                return Ok(KernelParserAppendAckV2 {
                    page_index: accepted.page_index,
                    page_chunk_index: accepted.page_chunk_index,
                    transcript_digest: accepted.transcript_digest,
                });
            }
            fail_parser_extraction(extraction);
            return Err(KernelInputErrorV2::DigestMismatch);
        }

        let expected = extraction.frames.last().map_or(Some((0, 0)), |last| {
            if last.final_chunk_for_page {
                last.page_index
                    .checked_add(1)
                    .map(|page_index| (page_index, 0))
            } else {
                last.page_chunk_index
                    .checked_add(1)
                    .map(|chunk_index| (last.page_index, chunk_index))
            }
        });
        let computed_transcript =
            parser_worker_transcript_step_v2(extraction.transcript_digest, frame);
        let new_length = extraction
            .bytes
            .len()
            .checked_add(frame.extracted_chunk().len());
        let same_rendered_digest = extraction.frames.last().is_none_or(|last| {
            last.page_index != frame.page_index()
                || last.rendered_input_digest == frame.rendered_input_digest()
        });
        if expected != Some((frame.page_index(), frame.page_chunk_index()))
            || frame.job_nonce() != extraction.verified_job.job_nonce()
            || frame.page_index() >= extraction.trust.maximum_pages
            || frame.extracted_chunk().len() > MAX_INPUT_CHUNK_BYTES
            || new_length.is_none_or(|length| {
                length > extraction.trust.maximum_output_bytes || length > self.maximum_input_bytes
            })
            || !same_rendered_digest
            || computed_transcript.as_ref().ok() != Some(&frame.transcript_step_digest())
        {
            fail_parser_extraction(extraction);
            return Err(KernelInputErrorV2::ProvenanceMismatch);
        }
        let new_length = new_length.ok_or(KernelInputErrorV2::LimitExceeded)?;
        extraction
            .bytes
            .try_reserve(frame.extracted_chunk().len())
            .map_err(|_| KernelInputErrorV2::Unavailable)?;
        extraction
            .frames
            .try_reserve(1)
            .map_err(|_| KernelInputErrorV2::Unavailable)?;
        let start = extraction.bytes.len();
        extraction.bytes.extend_from_slice(frame.extracted_chunk());
        extraction.frames.push(AcceptedParserFrameV2 {
            page_index: frame.page_index(),
            page_chunk_index: frame.page_chunk_index(),
            final_chunk_for_page: frame.final_chunk_for_page(),
            rendered_input_digest: frame.rendered_input_digest(),
            extracted_chunk_digest: frame.extracted_chunk_digest(),
            transcript_digest: frame.transcript_step_digest(),
            start,
            length: new_length - start,
        });
        extraction.transcript_digest = frame.transcript_step_digest();
        Ok(KernelParserAppendAckV2 {
            page_index: frame.page_index(),
            page_chunk_index: frame.page_chunk_index(),
            transcript_digest: frame.transcript_step_digest(),
        })
    }

    pub(crate) fn commit_parser_worker_result(
        &mut self,
        request: CommitParserWorkerResultRequestV2,
        now: UnixMillisV2,
    ) -> Result<KernelParserCommitV2, KernelInputErrorV2> {
        let canonical_request = encode_kernel_ingress_operation_v2(
            &KernelIngressOperationV2::CommitParserWorkerResult(request.clone()),
        )
        .map_err(|_| KernelInputErrorV2::Unavailable)?;
        let request_digest = Digest32V2::new(Sha256::digest(&canonical_request).into());
        let commitment = request.extraction().authority_commitment(&self.handle_key);
        let extraction_index = self
            .extractions
            .iter()
            .position(|extraction| extraction.handle_commitment == commitment)
            .ok_or(KernelInputErrorV2::InvalidReference)?;
        if self.extractions[extraction_index].state == ParserExtractionStateV2::Committed {
            return if self.extractions[extraction_index].commit_request_digest
                == Some(request_digest)
            {
                self.extractions[extraction_index]
                    .committed_result
                    .clone()
                    .ok_or(KernelInputErrorV2::Unavailable)
            } else {
                Err(KernelInputErrorV2::AlreadyConsumed)
            };
        }
        if self.extractions[extraction_index].state != ParserExtractionStateV2::Staging {
            return Err(KernelInputErrorV2::AlreadyConsumed);
        }
        let verified_result = request
            .attestation()
            .verify_for_job(self.extractions[extraction_index].verified_job, now);
        let Ok(verified_result) = verified_result else {
            fail_parser_extraction(&mut self.extractions[extraction_index]);
            return Err(KernelInputErrorV2::ProvenanceMismatch);
        };
        if !parser_result_matches(&self.extractions[extraction_index], &verified_result) {
            fail_parser_extraction(&mut self.extractions[extraction_index]);
            return Err(KernelInputErrorV2::ProvenanceMismatch);
        }

        let session_commitment = self.extractions[extraction_index].session_commitment;
        let session_index = self
            .sessions
            .iter()
            .position(|session| session.session_commitment == session_commitment)
            .ok_or(KernelInputErrorV2::InvalidReference)?;
        let channel_index = self.sessions[session_index]
            .channels
            .iter()
            .position(|channel| channel.channel == InputChannelV2::ExtractedPage)
            .ok_or(KernelInputErrorV2::StateConflict)?;
        let session = &self.sessions[session_index];
        let channel = &session.channels[channel_index];
        if session.state != KernelInputPublicStateV2::Receiving
            || session.parsed_source_provenance.is_some()
            || channel.next_sequence != 0
            || !channel.bytes.is_empty()
        {
            return Err(KernelInputErrorV2::StateConflict);
        }

        let extraction = &self.extractions[extraction_index];
        let mut cumulative_digest = channel.cumulative_digest;
        let mut chunks = Vec::new();
        chunks
            .try_reserve_exact(extraction.frames.len())
            .map_err(|_| KernelInputErrorV2::Unavailable)?;
        for (sequence, frame) in extraction.frames.iter().enumerate() {
            let sequence =
                u32::try_from(sequence).map_err(|_| KernelInputErrorV2::LimitExceeded)?;
            let chunk = extraction
                .bytes
                .get(frame.start..frame.start + frame.length)
                .ok_or(KernelInputErrorV2::StateConflict)?;
            let chunk_digest = input_chunk_digest_from_internal_id(
                session.session_internal_id,
                InputChannelV2::ExtractedPage,
                sequence,
                chunk,
            )?;
            let resulting_cumulative_digest =
                input_channel_step_digest_v2(cumulative_digest, sequence, chunk_digest)
                    .map_err(|_| KernelInputErrorV2::DigestMismatch)?;
            chunks.push(AcceptedChunkV2 {
                sequence,
                start: frame.start,
                length: frame.length,
                chunk_digest,
                prior_cumulative_digest: cumulative_digest,
                resulting_cumulative_digest,
            });
            cumulative_digest = resulting_cumulative_digest;
        }
        let chunk_count =
            u32::try_from(chunks.len()).map_err(|_| KernelInputErrorV2::LimitExceeded)?;
        let final_sequence = chunk_count
            .checked_sub(1)
            .ok_or(KernelInputErrorV2::StateConflict)?;
        let total_length = extraction.bytes.len() as u64;
        let extracted_channel_commitment = InputChannelCommitmentV2::new(
            InputChannelV2::ExtractedPage,
            chunk_count,
            final_sequence,
            total_length,
            cumulative_digest,
        )
        .map_err(|_| KernelInputErrorV2::ProvenanceMismatch)?;
        let parsed_source_provenance =
            parsed_source_provenance(&self.extractions[extraction_index], &verified_result)?;
        let parsed_source_provenance_digest =
            input_source_provenance_digest_v2(&parsed_source_provenance)
                .map_err(|_| KernelInputErrorV2::ProvenanceMismatch)?;

        let (sessions, extractions) = (&mut self.sessions, &mut self.extractions);
        let extraction = &mut extractions[extraction_index];
        let session = &mut sessions[session_index];
        let channel = &mut session.channels[channel_index];
        channel.bytes = std::mem::replace(&mut extraction.bytes, Zeroizing::new(Vec::new()));
        channel.chunks = chunks;
        channel.next_sequence = chunk_count;
        channel.cumulative_digest = cumulative_digest;
        session.parsed_source_provenance = Some((
            parsed_source_provenance.clone(),
            parsed_source_provenance_digest,
        ));
        extraction.frames.clear();
        let result = KernelParserCommitV2 {
            extracted_channel_commitment,
            parsed_source_provenance_digest,
            parsed_source_provenance,
        };
        extraction.state = ParserExtractionStateV2::Committed;
        extraction.commit_request_digest = Some(request_digest);
        extraction.committed_result = Some(result.clone());
        Ok(result)
    }

    pub(crate) fn finalize_with<T, E>(
        &mut self,
        request: FinalizeInputRequestV2,
        prepare: impl FnOnce(&PreparedKernelInputFinalizationV2) -> Result<T, E>,
    ) -> Result<(FinalizedKernelInputV2, T), KernelInputFinalizeTransactionErrorV2<E>> {
        let canonical_request = encode_kernel_ingress_operation_v2(
            &KernelIngressOperationV2::FinalizeInput(request.clone()),
        )
        .map_err(|_| {
            KernelInputFinalizeTransactionErrorV2::Input(KernelInputErrorV2::Unavailable)
        })?;
        let source_provenance_digest = Digest32V2::new(Sha256::digest(&canonical_request).into());
        let session_commitment = request.session().authority_commitment(&self.handle_key);
        let session_index = self
            .sessions
            .iter()
            .position(|session| session.session_commitment == session_commitment)
            .ok_or(KernelInputFinalizeTransactionErrorV2::Input(
                KernelInputErrorV2::InvalidReference,
            ))?;
        let session = &self.sessions[session_index];
        if session.state != KernelInputPublicStateV2::Receiving {
            return Err(KernelInputFinalizeTransactionErrorV2::Input(
                KernelInputErrorV2::StateConflict,
            ));
        }
        if !commitments_match(session, request.channels())
            || !provenance_matches(session, request.source_provenance())
        {
            fail_closed(&mut self.sessions[session_index]);
            return Err(KernelInputFinalizeTransactionErrorV2::Input(
                KernelInputErrorV2::ProvenanceMismatch,
            ));
        }

        let mut hasher = Sha256::new();
        hasher.update(INPUT_COMMITMENT_DOMAIN);
        hasher.update([session.content_kind.tag() as u8]);
        for channel in &session.channels {
            hasher.update(channel.channel.tag().to_be_bytes());
            hasher.update(channel.cumulative_digest.as_bytes());
            hasher.update((channel.bytes.len() as u64).to_be_bytes());
        }
        let input_commitment = Digest32V2::new(hasher.finalize().into());
        let mut channel_hasher = Sha256::new();
        channel_hasher.update(CHANNEL_COMMITMENTS_DOMAIN);
        for channel in &session.channels {
            channel_hasher.update(channel.channel.tag().to_be_bytes());
            channel_hasher.update((channel.bytes.len() as u64).to_be_bytes());
            channel_hasher.update(Sha256::digest(&channel.bytes));
        }
        let prepared = PreparedKernelInputFinalizationV2 {
            input_commitment,
            source_provenance_digest,
            authorization: session.authorization,
            channel_commitments_digest: Digest32V2::new(channel_hasher.finalize().into()),
        };
        let mut finalized_channels = Vec::new();
        finalized_channels
            .try_reserve_exact(session.channels.len())
            .map_err(|_| {
                KernelInputFinalizeTransactionErrorV2::Input(KernelInputErrorV2::Unavailable)
            })?;
        let prepared_result =
            prepare(&prepared).map_err(KernelInputFinalizeTransactionErrorV2::Preparation)?;
        let session = &mut self.sessions[session_index];
        for channel in &mut session.channels {
            finalized_channels.push(FinalizedKernelInputChannelV2 {
                channel: channel.channel,
                bytes: std::mem::replace(&mut channel.bytes, Zeroizing::new(Vec::new())),
            });
            channel.chunks.clear();
        }
        session.state = KernelInputPublicStateV2::Finalized;
        session.finalize_request_digest = Some(source_provenance_digest);
        session.finalized_input_commitment = Some(input_commitment);
        Ok((
            FinalizedKernelInputV2 {
                input_commitment,
                source_provenance_digest,
                authorization: session.authorization,
                channels: finalized_channels,
            },
            prepared_result,
        ))
    }

    pub(crate) fn exact_finalized_input_commitment(
        &self,
        request: &FinalizeInputRequestV2,
    ) -> Result<Option<Digest32V2>, KernelInputErrorV2> {
        let session_commitment = request.session().authority_commitment(&self.handle_key);
        let session = self
            .sessions
            .iter()
            .find(|session| session.session_commitment == session_commitment)
            .ok_or(KernelInputErrorV2::InvalidReference)?;
        if session.state == KernelInputPublicStateV2::Receiving {
            return Ok(None);
        }
        if session.state != KernelInputPublicStateV2::Finalized {
            return Err(KernelInputErrorV2::StateConflict);
        }
        let canonical_request = encode_kernel_ingress_operation_v2(
            &KernelIngressOperationV2::FinalizeInput(request.clone()),
        )
        .map_err(|_| KernelInputErrorV2::Unavailable)?;
        let request_digest = Digest32V2::new(Sha256::digest(canonical_request).into());
        if session.finalize_request_digest != Some(request_digest) {
            return Err(KernelInputErrorV2::StateConflict);
        }
        session
            .finalized_input_commitment
            .map(Some)
            .ok_or(KernelInputErrorV2::StateConflict)
    }

    pub(crate) fn abort(
        &mut self,
        request: AbortInputRequestV2,
    ) -> Result<KernelInputPublicStateV2, KernelInputErrorV2> {
        let commitment = request.session().authority_commitment(&self.handle_key);
        let session_index = self
            .sessions
            .iter()
            .position(|session| session.session_commitment == commitment)
            .ok_or(KernelInputErrorV2::InvalidReference)?;
        let session = &mut self.sessions[session_index];
        match session.state {
            KernelInputPublicStateV2::Receiving | KernelInputPublicStateV2::FailedClosed => {
                clear_plaintext(session);
                session.state = KernelInputPublicStateV2::Aborted;
                for extraction in &mut self.extractions {
                    if extraction.session_commitment == commitment
                        && extraction.state == ParserExtractionStateV2::Staging
                    {
                        fail_parser_extraction(extraction);
                    }
                }
                Ok(session.state)
            }
            KernelInputPublicStateV2::Aborted => Ok(session.state),
            KernelInputPublicStateV2::Finalized => Err(KernelInputErrorV2::StateConflict),
        }
    }

    pub(crate) fn status(
        &self,
        target: InputStatusTargetV2,
    ) -> Result<KernelInputPublicStateV2, KernelInputErrorV2> {
        let commitment = match target {
            InputStatusTargetV2::Session(session) => session.authority_commitment(&self.handle_key),
            InputStatusTargetV2::Pending(_) => {
                return Err(KernelInputErrorV2::InvalidReference);
            }
        };
        self.sessions
            .iter()
            .find(|session| session.session_commitment == commitment)
            .map(|session| session.state)
            .ok_or(KernelInputErrorV2::InvalidReference)
    }

    fn mint_session(&self) -> Result<InputSessionHandleV2, KernelInputErrorV2> {
        for _ in 0..8 {
            let handle = InputSessionHandleV2::from_authority_entropy(random_bytes()?)
                .ok_or(KernelInputErrorV2::Unavailable)?;
            let commitment = handle.authority_commitment(&self.handle_key);
            if self
                .sessions
                .iter()
                .all(|session| session.session_commitment != commitment)
            {
                return Ok(handle);
            }
        }
        Err(KernelInputErrorV2::Unavailable)
    }

    fn mint_writer(&self) -> Result<IngressWriteCapabilityV2, KernelInputErrorV2> {
        for _ in 0..8 {
            let handle = IngressWriteCapabilityV2::from_authority_entropy(random_bytes()?)
                .ok_or(KernelInputErrorV2::Unavailable)?;
            let commitment = handle.authority_commitment(&self.handle_key);
            if self
                .sessions
                .iter()
                .all(|session| session.writer_commitment != commitment)
            {
                return Ok(handle);
            }
        }
        Err(KernelInputErrorV2::Unavailable)
    }

    fn parser_extraction_handle(
        &self,
        session_internal_id: Digest32V2,
        descriptor_digest: Digest32V2,
    ) -> Result<ParserExtractionHandleV2, KernelInputErrorV2> {
        let mut mac = Hmac::<Sha256>::new_from_slice(self.parser_handle_mint_key.as_ref())
            .map_err(|_| KernelInputErrorV2::Unavailable)?;
        mac.update(PARSER_EXTRACTION_HANDLE_DOMAIN);
        mac.update(session_internal_id.as_bytes());
        mac.update(descriptor_digest.as_bytes());
        ParserExtractionHandleV2::from_authority_entropy(mac.finalize().into_bytes().into())
            .ok_or(KernelInputErrorV2::Unavailable)
    }

    #[cfg(test)]
    pub(crate) fn retained_plaintext_bytes(&self) -> usize {
        let session_bytes: usize = self
            .sessions
            .iter()
            .flat_map(|session| &session.channels)
            .map(|channel| channel.bytes.len())
            .sum();
        session_bytes
            + self
                .extractions
                .iter()
                .map(|extraction| extraction.bytes.len())
                .sum::<usize>()
    }

    #[cfg(test)]
    fn committed_extracted_bytes(&self, begun: &KernelInputBeginV2) -> usize {
        let commitment = begun.session().authority_commitment(&self.handle_key);
        self.sessions
            .iter()
            .find(|session| session.session_commitment == commitment)
            .and_then(|session| {
                session
                    .channels
                    .iter()
                    .find(|channel| channel.channel == InputChannelV2::ExtractedPage)
            })
            .map_or(0, |channel| channel.bytes.len())
    }
}

fn parser_job_matches_trust(
    job: VerifiedParserWorkerJobDescriptorV2,
    trust: KernelParserTrustV2,
) -> bool {
    job.worker_artifact_digest() == trust.worker_artifact_digest
        && job.parser_implementation_id() == trust.parser_implementation_id
        && job.parser_code_digest() == trust.parser_code_digest
        && job.renderer_code_digest() == trust.renderer_code_digest
        && job.ocr_model_set_digest() == trust.ocr_model_set_digest
        && job.normalization_version() == trust.normalization_version
        && job.output_limits_digest() == trust.output_limits_digest
}

fn parser_result_matches(
    extraction: &ParserExtractionRecordV2,
    result: &VerifiedParserWorkerResultAttestationV2,
) -> bool {
    if extraction.frames.is_empty()
        || extraction
            .frames
            .last()
            .is_none_or(|frame| !frame.final_chunk_for_page)
        || result.page_count() == 0
        || result.page_count() > extraction.trust.maximum_pages
        || usize::try_from(result.page_count()) != Ok(result.page_records().len())
        || result.ordered_page_frame_transcript_digest() != extraction.transcript_digest
        || result.extracted_byte_length() != extraction.bytes.len() as u64
        || result.extracted_output_digest()
            != Digest32V2::new(Sha256::digest(&extraction.bytes).into())
    {
        return false;
    }
    let mut frame_cursor = 0_usize;
    for page in result.page_records() {
        let first = match usize::try_from(page.extracted_channel_first_sequence()) {
            Ok(first) => first,
            Err(_) => return false,
        };
        let count = match usize::try_from(page.extracted_channel_chunk_count()) {
            Ok(count) => count,
            Err(_) => return false,
        };
        let Some(end) = first.checked_add(count) else {
            return false;
        };
        let Some(frames) = extraction.frames.get(first..end) else {
            return false;
        };
        if first != frame_cursor
            || frames.is_empty()
            || frames
                .last()
                .is_none_or(|frame| !frame.final_chunk_for_page)
            || frames[..frames.len() - 1]
                .iter()
                .any(|frame| frame.final_chunk_for_page)
            || frames.iter().enumerate().any(|(index, frame)| {
                frame.page_index != page.page_index()
                    || usize::try_from(frame.page_chunk_index) != Ok(index)
                    || frame.rendered_input_digest != page.rendered_input_digest()
            })
        {
            return false;
        }
        let start = frames[0].start;
        let Some(last) = frames.last() else {
            return false;
        };
        let Some(page_end) = last.start.checked_add(last.length) else {
            return false;
        };
        let Some(page_bytes) = extraction.bytes.get(start..page_end) else {
            return false;
        };
        let Ok(text) = std::str::from_utf8(page_bytes) else {
            return false;
        };
        let Ok(character_count) = u32::try_from(text.chars().count()) else {
            return false;
        };
        if page.extracted_byte_length() != page_bytes.len() as u64
            || page.extracted_text_digest() != Digest32V2::new(Sha256::digest(page_bytes).into())
            || page.character_count() != character_count
            || frames.iter().any(|frame| {
                extraction
                    .bytes
                    .get(frame.start..frame.start + frame.length)
                    .is_none_or(|bytes| {
                        frame.extracted_chunk_digest
                            != Digest32V2::new(Sha256::digest(bytes).into())
                    })
            })
        {
            return false;
        }
        frame_cursor = end;
    }
    frame_cursor == extraction.frames.len()
}

fn parsed_source_provenance(
    extraction: &ParserExtractionRecordV2,
    result: &VerifiedParserWorkerResultAttestationV2,
) -> Result<InputSourceProvenanceV2, KernelInputErrorV2> {
    let job = extraction.verified_job;
    InputSourceProvenanceV2::parsed_document(
        InputSourceKindV2::FileUpload,
        job.original_byte_length(),
        job.original_sha256(),
        job.declared_media_type(),
        job.detected_media_type(),
        extraction.trust.extension_class,
        job.parser_implementation_id(),
        extraction.trust.parser_semantic_version,
        job.parser_code_digest(),
        job.renderer_code_digest(),
        job.ocr_model_set_digest(),
        job.normalization_version(),
        result.page_records().to_vec(),
        result.extracted_output_digest(),
    )
    .map_err(|_| KernelInputErrorV2::ProvenanceMismatch)
}

fn fail_parser_extraction(extraction: &mut ParserExtractionRecordV2) {
    extraction.bytes.clear();
    extraction.frames.clear();
    extraction.state = ParserExtractionStateV2::FailedClosed;
}

fn allowed_channels(content_kind: ContentKindV2) -> &'static [InputChannelV2] {
    match content_kind {
        ContentKindV2::ChatText => &[InputChannelV2::ChatText],
        ContentKindV2::PlainText => &[InputChannelV2::OriginalSource],
        ContentKindV2::ParsedDocument => &[
            InputChannelV2::OriginalSource,
            InputChannelV2::ExtractedPage,
        ],
    }
}

const fn direct_channel(channel: DirectInputChannelV2) -> InputChannelV2 {
    match channel {
        DirectInputChannelV2::OriginalSource => InputChannelV2::OriginalSource,
        DirectInputChannelV2::ChatText => InputChannelV2::ChatText,
    }
}

fn commitments_match(
    session: &InputSessionRecordV2,
    commitments: &[InputChannelCommitmentV2],
) -> bool {
    session.channels.len() == commitments.len()
        && session
            .channels
            .iter()
            .zip(commitments)
            .all(|(channel, commitment)| {
                channel.channel == commitment.channel()
                    && channel.next_sequence == commitment.chunk_count()
                    && channel
                        .next_sequence
                        .checked_sub(1)
                        .is_some_and(|last| last == commitment.final_sequence())
                    && channel.bytes.len() as u64 == commitment.total_length()
                    && channel.cumulative_digest == commitment.final_cumulative_digest()
            })
}

fn provenance_matches(
    session: &InputSessionRecordV2,
    provenance: &InputSourceProvenanceV2,
) -> bool {
    let direct_channel = match session.content_kind {
        ContentKindV2::ChatText => InputChannelV2::ChatText,
        ContentKindV2::PlainText | ContentKindV2::ParsedDocument => InputChannelV2::OriginalSource,
    };
    let Some(original) = session
        .channels
        .iter()
        .find(|channel| channel.channel == direct_channel)
    else {
        return false;
    };
    let original_digest = Digest32V2::new(Sha256::digest(&original.bytes).into());
    if original.bytes.len() as u64 != session.declared_total_bytes
        || session
            .declared_content_digest
            .is_some_and(|declared| declared != original_digest)
    {
        return false;
    }
    match (session.content_kind, provenance) {
        (
            ContentKindV2::ChatText,
            InputSourceProvenanceV2::Direct {
                source_kind,
                original_byte_length,
                original_sha256,
                ..
            },
        ) => {
            *source_kind == InputSourceKindV2::Chat
                && *original_byte_length == original.bytes.len() as u64
                && *original_sha256 == original_digest
        }
        (
            ContentKindV2::PlainText,
            InputSourceProvenanceV2::Direct {
                source_kind,
                original_byte_length,
                original_sha256,
                ..
            },
        ) => {
            matches!(
                source_kind,
                InputSourceKindV2::Paste | InputSourceKindV2::FileUpload
            ) && *original_byte_length == original.bytes.len() as u64
                && *original_sha256 == original_digest
        }
        (
            ContentKindV2::ParsedDocument,
            InputSourceProvenanceV2::ParsedDocument {
                source_kind,
                original_byte_length,
                original_sha256,
                extracted_output_digest,
                ..
            },
        ) => {
            let Some(extracted) = session
                .channels
                .iter()
                .find(|channel| channel.channel == InputChannelV2::ExtractedPage)
            else {
                return false;
            };
            let Some((committed_provenance, committed_digest)) = &session.parsed_source_provenance
            else {
                return false;
            };
            *source_kind == InputSourceKindV2::FileUpload
                && *original_byte_length == original.bytes.len() as u64
                && *original_sha256 == original_digest
                && *extracted_output_digest
                    == Digest32V2::new(Sha256::digest(&extracted.bytes).into())
                && committed_provenance == provenance
                && input_source_provenance_digest_v2(provenance)
                    .is_ok_and(|digest| digest == *committed_digest)
        }
        _ => false,
    }
}

fn fail_closed(session: &mut InputSessionRecordV2) {
    clear_plaintext(session);
    session.state = KernelInputPublicStateV2::FailedClosed;
}

fn clear_plaintext(session: &mut InputSessionRecordV2) {
    for channel in &mut session.channels {
        channel.bytes.clear();
        channel.chunks.clear();
    }
    session.parsed_source_provenance = None;
}

fn random_bytes() -> Result<[u8; 32], KernelInputErrorV2> {
    let mut bytes = [0_u8; 32];
    getrandom(&mut bytes).map_err(|_| KernelInputErrorV2::Unavailable)?;
    if bytes == [0; 32] {
        return Err(KernelInputErrorV2::Unavailable);
    }
    Ok(bytes)
}

fn domain_hash_many(domain: &[u8], values: &[&[u8]]) -> Digest32V2 {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for value in values {
        hasher.update(value);
    }
    Digest32V2::new(hasher.finalize().into())
}

fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

fn version_is_zero(version: VersionV2) -> bool {
    version.major() == 0 && version.minor() == 0 && version.patch() == 0
}

fn input_chunk_digest_from_internal_id(
    session_internal_id: Digest32V2,
    channel: InputChannelV2,
    sequence: u32,
    chunk: &[u8],
) -> Result<Digest32V2, KernelInputErrorV2> {
    let length = u32::try_from(chunk.len()).map_err(|_| KernelInputErrorV2::LimitExceeded)?;
    if chunk.is_empty() {
        return Err(KernelInputErrorV2::DigestMismatch);
    }
    Ok(domain_hash_many(
        b"SAVANA_INPUT_CHUNK_V2\0",
        &[
            session_internal_id.as_bytes(),
            &channel.tag().to_be_bytes(),
            &sequence.to_be_bytes(),
            &length.to_be_bytes(),
            chunk,
        ],
    ))
}

#[cfg(test)]
pub(crate) mod tests {
    use ed25519_dalek::SigningKey;
    use savana_kernel_protocol::v2::{
        derive_ed25519_key_id_v2, input_channel_step_digest_v2, input_chunk_digest_v2,
        parser_worker_transcript_begin_v2, parser_worker_transcript_step_v2, BeginInputRequestV2,
        ClosedConfidenceClassV2, ClosedExtensionClassV2, ClosedMediaTypeV2, ContentKindV2,
        Digest32V2, DirectInputChannelV2, FixedBytes32V2, ImplementationIdV2,
        IngressUiAuthorizationHandleV2, InputChannelCommitmentV2, InputChannelV2,
        InputSourceKindV2, InputSourceProvenanceV2, Nonce32V2, PageProvenanceV2,
        ParserWorkerPageFrameV2, RegisterParserWorkerJobRequestV2, ServiceIdentityV2,
        SignedParserWorkerJobDescriptorV2, SignedParserWorkerResultAttestationV2, UnixMillisV2,
        UnsignedParserWorkerJobDescriptorV2, UnsignedParserWorkerResultAttestationV2, VersionV2,
        ZeroizingBytesV2,
    };
    use sha2::{Digest as _, Sha256};

    use super::{
        KernelInputErrorV2, KernelInputFinalizeTransactionErrorV2, KernelInputOwnerV2,
        KernelInputPublicStateV2, KernelParserTrustV2,
    };

    fn begin_chat(owner: &mut KernelInputOwnerV2, bytes: &[u8]) -> super::KernelInputBeginV2 {
        let authorization =
            IngressUiAuthorizationHandleV2::from_authority_entropy([0x41; 32]).unwrap();
        owner
            .register_verified_ui_authorization(
                authorization,
                super::KernelVerifiedUiAuthorizationV2::for_test(),
            )
            .unwrap();
        owner
            .begin(
                BeginInputRequestV2::new(
                    authorization,
                    ContentKindV2::ChatText,
                    bytes.len() as u64,
                    Some(Digest32V2::new(Sha256::digest(bytes).into())),
                )
                .unwrap(),
                Digest32V2::new([0x35; 32]),
                7,
                UnixMillisV2::new(100),
            )
            .unwrap()
    }

    fn append_request(
        begun: &super::KernelInputBeginV2,
        sequence: u32,
        bytes: Vec<u8>,
    ) -> savana_kernel_protocol::v2::AppendInputChunkRequestV2 {
        let cursor = begun.channels()[0];
        let prior = cursor.cumulative_digest();
        let chunk =
            input_chunk_digest_v2(begun.session(), InputChannelV2::ChatText, sequence, &bytes)
                .unwrap();
        let resulting = input_channel_step_digest_v2(prior, sequence, chunk).unwrap();
        savana_kernel_protocol::v2::AppendInputChunkRequestV2::new(
            begun.writer(),
            DirectInputChannelV2::ChatText,
            sequence,
            prior,
            ZeroizingBytesV2::new(bytes).unwrap(),
            chunk,
            resulting,
        )
        .unwrap()
    }

    fn begin_parsed(owner: &mut KernelInputOwnerV2, original: &[u8]) -> super::KernelInputBeginV2 {
        let authorization =
            IngressUiAuthorizationHandleV2::from_authority_entropy([0x61; 32]).unwrap();
        owner
            .register_verified_ui_authorization(
                authorization,
                super::KernelVerifiedUiAuthorizationV2::for_test(),
            )
            .unwrap();
        owner
            .begin(
                BeginInputRequestV2::new(
                    authorization,
                    ContentKindV2::ParsedDocument,
                    original.len() as u64,
                    Some(Digest32V2::new(Sha256::digest(original).into())),
                )
                .unwrap(),
                Digest32V2::new([0x35; 32]),
                7,
                UnixMillisV2::new(100),
            )
            .unwrap()
    }

    fn append_original_request(
        begun: &super::KernelInputBeginV2,
        bytes: Vec<u8>,
    ) -> savana_kernel_protocol::v2::AppendInputChunkRequestV2 {
        let cursor = begun
            .channels()
            .iter()
            .find(|cursor| cursor.channel() == InputChannelV2::OriginalSource)
            .copied()
            .unwrap();
        let chunk =
            input_chunk_digest_v2(begun.session(), InputChannelV2::OriginalSource, 0, &bytes)
                .unwrap();
        let resulting = input_channel_step_digest_v2(cursor.cumulative_digest(), 0, chunk).unwrap();
        savana_kernel_protocol::v2::AppendInputChunkRequestV2::new(
            begun.writer(),
            DirectInputChannelV2::OriginalSource,
            0,
            cursor.cumulative_digest(),
            ZeroizingBytesV2::new(bytes).unwrap(),
            chunk,
            resulting,
        )
        .unwrap()
    }

    #[test]
    fn production_session_limit_accepts_sixty_four_mib_but_nothing_larger() {
        assert!(KernelInputOwnerV2::new(4, 64 * 1024 * 1024).is_ok());
        assert_eq!(
            KernelInputOwnerV2::new(4, 64 * 1024 * 1024 + 1).unwrap_err(),
            KernelInputErrorV2::LimitExceeded,
        );
    }

    #[test]
    fn wrong_replayed_plaintext_fails_closed_and_zeroizes_retained_data() {
        let mut owner = KernelInputOwnerV2::new(4, 4096).unwrap();
        let begun = begin_chat(&mut owner, b"abc");
        let accepted = append_request(&begun, 0, b"abc".to_vec());
        owner.append(accepted).unwrap();
        assert_eq!(owner.retained_plaintext_bytes(), 3);

        let changed = append_request(&begun, 0, b"abd".to_vec());
        assert_eq!(
            owner.append(changed),
            Err(KernelInputErrorV2::DigestMismatch)
        );
        assert_eq!(owner.retained_plaintext_bytes(), 0);
        assert_eq!(
            owner
                .status(savana_kernel_protocol::v2::InputStatusTargetV2::Session(
                    begun.session(),
                ))
                .unwrap(),
            KernelInputPublicStateV2::FailedClosed
        );
    }

    pub(crate) fn finalized_task_input_fixture(
    ) -> (KernelInputOwnerV2, super::InputSessionHandleV2, Digest32V2) {
        let mut owner = KernelInputOwnerV2::new(4, 4096).unwrap();
        let begun = begin_chat(&mut owner, b"abc");
        let ack = owner
            .append(append_request(&begun, 0, b"abc".to_vec()))
            .unwrap();
        let commitment = InputChannelCommitmentV2::new(
            InputChannelV2::ChatText,
            1,
            0,
            3,
            ack.cumulative_digest(),
        )
        .unwrap();
        let (finalized, ()) = owner
            .finalize_with(
                savana_kernel_protocol::v2::FinalizeInputRequestV2::new(
                    begun.session(),
                    vec![commitment],
                    InputSourceProvenanceV2::direct(
                        InputSourceKindV2::Chat,
                        3,
                        Digest32V2::new(Sha256::digest(b"abc").into()),
                        VersionV2::new(1, 0, 0),
                    )
                    .unwrap(),
                )
                .unwrap(),
                |_| Ok::<(), std::convert::Infallible>(()),
            )
            .unwrap();

        assert_ne!(finalized.input_commitment().as_bytes(), &[0; 32]);
        assert_eq!(finalized.channels()[0].bytes(), b"abc");
        assert_eq!(owner.retained_plaintext_bytes(), 0);
        (owner, begun.session(), finalized.input_commitment())
    }

    /// Uses the real input transaction with a fixture-authenticated subject.
    /// Authentication/hardware ceremony itself is tested separately.
    pub(crate) fn finalized_input_for_authority_fixture(
        task: savana_kernel_protocol::v2::DurableTaskIdV2,
        installation: Digest32V2,
        principal: savana_kernel_protocol::v2::PrincipalIdV2,
        manifest: Digest32V2,
        bytes: &[u8],
    ) -> (KernelInputOwnerV2, super::InputSessionHandleV2, Digest32V2) {
        let mut owner = KernelInputOwnerV2::new(4, 4096).unwrap();
        let handle = IngressUiAuthorizationHandleV2::from_authority_entropy([0x41; 32]).unwrap();
        let mut auth = super::KernelVerifiedUiAuthorizationV2::for_test();
        auth.durable_task_id = Some(task);
        auth.installation_id = installation;
        auth.authenticated_principal = principal;
        auth.active_state_manifest_digest = manifest;
        owner
            .register_verified_ui_authorization(handle, auth)
            .unwrap();
        let begun = owner
            .begin(
                BeginInputRequestV2::new(
                    handle,
                    ContentKindV2::ChatText,
                    bytes.len() as u64,
                    Some(Digest32V2::new(Sha256::digest(bytes).into())),
                )
                .unwrap(),
                manifest,
                7,
                UnixMillisV2::new(100),
            )
            .unwrap();
        let ack = owner
            .append(append_request(&begun, 0, bytes.to_vec()))
            .unwrap();
        let channel = InputChannelCommitmentV2::new(
            InputChannelV2::ChatText,
            1,
            0,
            bytes.len() as u64,
            ack.cumulative_digest(),
        )
        .unwrap();
        let (finalized, ()) = owner
            .finalize_with(
                savana_kernel_protocol::v2::FinalizeInputRequestV2::new(
                    begun.session(),
                    vec![channel],
                    InputSourceProvenanceV2::direct(
                        InputSourceKindV2::Chat,
                        bytes.len() as u64,
                        Digest32V2::new(Sha256::digest(bytes).into()),
                        VersionV2::new(1, 0, 0),
                    )
                    .unwrap(),
                )
                .unwrap(),
                |_| Ok::<(), std::convert::Infallible>(()),
            )
            .unwrap();
        (owner, begun.session(), finalized.input_commitment())
    }

    pub(crate) fn fresh_task_recovery_authentication(
        owner: &mut KernelInputOwnerV2,
        entropy: u8,
        wrong_principal: bool,
        wrong_task: bool,
    ) -> IngressUiAuthorizationHandleV2 {
        let handle = IngressUiAuthorizationHandleV2::from_authority_entropy([entropy; 32]).unwrap();
        let mut auth = super::KernelVerifiedUiAuthorizationV2::for_test();
        auth.settlement_digest = Digest32V2::new([entropy; 32]);
        auth.authentication_context_digest = Digest32V2::new([entropy.wrapping_add(1); 32]);
        if wrong_principal {
            auth.authenticated_principal =
                savana_kernel_protocol::v2::PrincipalIdV2::new([0x77; 32]);
        }
        if wrong_task {
            auth.durable_task_id =
                Some(savana_kernel_protocol::v2::DurableTaskIdV2::new([0x78; 32]));
        }
        owner
            .register_verified_ui_authorization(handle, auth)
            .unwrap();
        handle
    }

    #[test]
    fn finalized_chat_material_leaves_no_plaintext_in_the_handle_resolver() {
        finalized_task_input_fixture();
    }

    #[test]
    fn refused_finalize_preparation_preserves_session_bytes_for_exact_retry() {
        let mut owner = KernelInputOwnerV2::new(4, 4096).unwrap();
        let begun = begin_chat(&mut owner, b"abc");
        let append = append_request(&begun, 0, b"abc".to_vec());
        let ack = owner.append(append).unwrap();
        let finalize = savana_kernel_protocol::v2::FinalizeInputRequestV2::new(
            begun.session(),
            vec![InputChannelCommitmentV2::new(
                InputChannelV2::ChatText,
                1,
                0,
                3,
                ack.cumulative_digest(),
            )
            .unwrap()],
            InputSourceProvenanceV2::direct(
                InputSourceKindV2::Chat,
                3,
                Digest32V2::new(Sha256::digest(b"abc").into()),
                VersionV2::new(1, 0, 0),
            )
            .unwrap(),
        )
        .unwrap();

        assert!(matches!(
            owner.finalize_with(finalize.clone(), |_| Err::<(), _>(0x71_u8)),
            Err(KernelInputFinalizeTransactionErrorV2::Preparation(0x71)),
        ));
        assert_eq!(owner.retained_plaintext_bytes(), 3);
        assert_eq!(
            owner
                .status(savana_kernel_protocol::v2::InputStatusTargetV2::Session(
                    begun.session(),
                ))
                .unwrap(),
            KernelInputPublicStateV2::Receiving,
        );
        assert_eq!(
            owner
                .append(append_request(&begun, 0, b"abc".to_vec()))
                .unwrap(),
            ack,
        );

        let (finalized, prepared) = owner
            .finalize_with(finalize, |view| {
                assert_ne!(view.input_commitment().as_bytes(), &[0; 32]);
                assert_ne!(view.channel_commitments_digest().as_bytes(), &[0; 32]);
                Ok::<_, u8>(view.input_commitment())
            })
            .unwrap();
        assert_eq!(prepared, finalized.input_commitment());
        assert_eq!(finalized.channels()[0].bytes(), b"abc");
        assert_eq!(owner.retained_plaintext_bytes(), 0);
    }

    #[test]
    fn parser_staging_commits_extracted_page_only_after_complete_attestation() {
        let original = b"PDF!";
        let extracted = b"hello";
        let mut owner = KernelInputOwnerV2::new(4, 4096).unwrap();
        let begun = begin_parsed(&mut owner, original);
        let original_ack = owner
            .append(append_original_request(&begun, original.to_vec()))
            .unwrap();

        let descriptor_key = SigningKey::from_bytes(&[0x62; 32]);
        let result_key = SigningKey::from_bytes(&[0x63; 32]);
        let ingressd_identity = ServiceIdentityV2::new([0x64; 32]);
        let worker_artifact_digest = Digest32V2::new([0x65; 32]);
        let parser_code_digest = Digest32V2::new([0x66; 32]);
        let output_limits_digest = Digest32V2::new([0x67; 32]);
        let trust = KernelParserTrustV2::new(
            derive_ed25519_key_id_v2(descriptor_key.verifying_key().to_bytes()),
            descriptor_key.verifying_key().to_bytes(),
            worker_artifact_digest,
            ImplementationIdV2::new(1),
            VersionV2::new(2, 1, 0),
            parser_code_digest,
            None,
            None,
            VersionV2::new(1, 0, 0),
            output_limits_digest,
            ClosedExtensionClassV2::new(1),
            8,
            4096,
        )
        .unwrap();
        let result_public_key = result_key.verifying_key().to_bytes();
        let result_key_id = derive_ed25519_key_id_v2(result_public_key);
        let job_nonce = Nonce32V2::new([0x68; 32]);
        let original_digest = Digest32V2::new(Sha256::digest(original).into());
        let unsigned_job = UnsignedParserWorkerJobDescriptorV2::new(
            Digest32V2::new([0x30; 32]),
            Digest32V2::new([0x35; 32]),
            7,
            ingressd_identity,
            job_nonce,
            begun.parser_job_session_binding_digest(),
            original.len() as u64,
            original_digest,
            ClosedMediaTypeV2::new(1),
            ClosedMediaTypeV2::new(1),
            worker_artifact_digest,
            ImplementationIdV2::new(1),
            parser_code_digest,
            None,
            None,
            VersionV2::new(1, 0, 0),
            output_limits_digest,
            FixedBytes32V2::new(result_public_key),
            result_key_id,
            UnixMillisV2::new(300),
        )
        .unwrap();
        let signed_job =
            SignedParserWorkerJobDescriptorV2::sign(unsigned_job, &descriptor_key).unwrap();
        let verified_job = signed_job
            .verify(
                trust.descriptor_key_id(),
                trust.descriptor_verifying_key(),
                Digest32V2::new([0x30; 32]),
                Digest32V2::new([0x35; 32]),
                7,
                ingressd_identity,
                begun.parser_job_session_binding_digest(),
                original.len() as u64,
                original_digest,
                UnixMillisV2::new(120),
            )
            .unwrap();
        let registered = owner
            .register_parser_worker_job(
                RegisterParserWorkerJobRequestV2::new(begun.session(), signed_job.clone()),
                trust,
                ingressd_identity,
                Digest32V2::new([0x35; 32]),
                7,
                UnixMillisV2::new(120),
            )
            .unwrap();
        let replayed_registration = owner
            .register_parser_worker_job(
                RegisterParserWorkerJobRequestV2::new(begun.session(), signed_job),
                trust,
                ingressd_identity,
                Digest32V2::new([0x35; 32]),
                7,
                UnixMillisV2::new(121),
            )
            .unwrap();
        assert_eq!(replayed_registration.extraction(), registered.extraction());
        assert_eq!(owner.committed_extracted_bytes(&begun), 0);

        let extracted_digest = Digest32V2::new(Sha256::digest(extracted).into());
        let transcript_begin =
            parser_worker_transcript_begin_v2(job_nonce, verified_job.descriptor_digest()).unwrap();
        let provisional = ParserWorkerPageFrameV2::new(
            job_nonce,
            0,
            0,
            true,
            Digest32V2::new([0x69; 32]),
            ZeroizingBytesV2::new(extracted.to_vec()).unwrap(),
            extracted_digest,
            Digest32V2::new([0x6a; 32]),
        )
        .unwrap();
        let transcript = parser_worker_transcript_step_v2(transcript_begin, &provisional).unwrap();
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
        let frame_ack = owner
            .append_parser_worker_page_frame(
                savana_kernel_protocol::v2::AppendParserWorkerPageFrameRequestV2::new(
                    registered.extraction(),
                    frame,
                ),
            )
            .unwrap();
        assert_eq!(frame_ack.transcript_digest(), transcript);
        let replayed_frame = ParserWorkerPageFrameV2::new(
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
            owner
                .append_parser_worker_page_frame(
                    savana_kernel_protocol::v2::AppendParserWorkerPageFrameRequestV2::new(
                        registered.extraction(),
                        replayed_frame,
                    ),
                )
                .unwrap(),
            frame_ack
        );
        assert_eq!(owner.committed_extracted_bytes(&begun), 0);

        let page = PageProvenanceV2::new(
            0,
            0,
            1,
            100,
            provisional.rendered_input_digest(),
            extracted.len() as u64,
            extracted_digest,
            extracted.len() as u32,
            ClosedConfidenceClassV2::new(1),
        )
        .unwrap();
        let signed_result = SignedParserWorkerResultAttestationV2::sign(
            UnsignedParserWorkerResultAttestationV2::new(
                job_nonce,
                verified_job.descriptor_digest(),
                begun.parser_job_session_binding_digest(),
                worker_artifact_digest,
                result_key_id,
                original.len() as u64,
                original_digest,
                1,
                vec![page],
                transcript,
                extracted.len() as u64,
                extracted_digest,
                UnixMillisV2::new(140),
            )
            .unwrap(),
            &result_key,
        )
        .unwrap();
        let commit_request = savana_kernel_protocol::v2::CommitParserWorkerResultRequestV2::new(
            registered.extraction(),
            signed_result,
        );
        let committed = owner
            .commit_parser_worker_result(commit_request.clone(), UnixMillisV2::new(150))
            .unwrap();
        assert_eq!(
            owner
                .commit_parser_worker_result(commit_request, UnixMillisV2::new(151))
                .unwrap(),
            committed
        );
        assert_eq!(owner.committed_extracted_bytes(&begun), extracted.len());
        assert_ne!(
            committed.parsed_source_provenance_digest().as_bytes(),
            &[0; 32]
        );

        let original_commitment = InputChannelCommitmentV2::new(
            InputChannelV2::OriginalSource,
            1,
            0,
            original.len() as u64,
            original_ack.cumulative_digest(),
        )
        .unwrap();
        let (finalized, ()) = owner
            .finalize_with(
                savana_kernel_protocol::v2::FinalizeInputRequestV2::new(
                    begun.session(),
                    vec![
                        original_commitment,
                        committed.extracted_channel_commitment(),
                    ],
                    committed.parsed_source_provenance().clone(),
                )
                .unwrap(),
                |_| Ok::<(), std::convert::Infallible>(()),
            )
            .unwrap();
        assert_eq!(finalized.channels().len(), 2);
    }
}
