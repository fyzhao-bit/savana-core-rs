use crate::{ProtocolError, StableCode};
use minicbor::Encode as _;

use super::{
    cbor::{scan_single, V2DecodeContext},
    ActionTemplateIdV2, AgentSessionHandleV2, AgentUiAuthenticationPreparationHandleV2,
    AgentUiAuthorizationHandleV2, Digest32V2, DirectInputChannelV2, DurableRunIdV2,
    IngressKernelApprovalHandleV2, IngressUiAuthenticationPreparationHandleV2,
    IngressUiAuthorizationHandleV2, IngressWriteCapabilityV2, InputChannelCommitmentV2,
    InputChannelV2, InputSessionHandleV2, KernelIngressBootstrapTransferCapabilityV2,
    MaskedDocumentHandleV2, NewTaskPreparationHandleV2, ParserExtractionHandleV2,
    PendingIngressHandleV2, PublicServiceStateV2, PublicTaskStatusV2, RunHandleV2,
    RunRevisionDigestV2, SignedApprovalEnvelopeV2, SignedDurableTaskCorrelationV2,
    SignedUiAuthenticationEnvelopeV2, StaticTemplateIdV2, ToolClassIdV2, ToolHandleV2,
    ValueHandleV2,
};

const MAX_INPUT_CHANNELS_V2: usize = 3;
const MAX_ACTIVE_TOOLS_V2: usize = 4096;

macro_rules! closed_input_state_v2 {
    (
        $name:ident {
            $($variant:ident = $tag:literal),+ $(,)?
        }
    ) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernelAgentHealthResponseV2 {
    ready: bool,
    state: PublicServiceStateV2,
}

impl KernelAgentHealthResponseV2 {
    pub const fn new(ready: bool, state: PublicServiceStateV2) -> Self {
        Self { ready, state }
    }

    pub const fn ready(self) -> bool {
        self.ready
    }

    pub const fn state(self) -> PublicServiceStateV2 {
        self.state
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernelIngressHealthResponseV2 {
    ready: bool,
    state: PublicServiceStateV2,
}

impl KernelIngressHealthResponseV2 {
    pub const fn new(ready: bool, state: PublicServiceStateV2) -> Self {
        Self { ready, state }
    }

    pub const fn ready(self) -> bool {
        self.ready
    }

    pub const fn state(self) -> PublicServiceStateV2 {
        self.state
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrepareIngressUiAuthenticationResponseV2 {
    authentication_preparation: IngressUiAuthenticationPreparationHandleV2,
    envelope: SignedUiAuthenticationEnvelopeV2,
}

impl PrepareIngressUiAuthenticationResponseV2 {
    pub const fn new(
        authentication_preparation: IngressUiAuthenticationPreparationHandleV2,
        envelope: SignedUiAuthenticationEnvelopeV2,
    ) -> Self {
        Self {
            authentication_preparation,
            envelope,
        }
    }

    pub const fn authentication_preparation(&self) -> IngressUiAuthenticationPreparationHandleV2 {
        self.authentication_preparation
    }

    pub const fn envelope(&self) -> &SignedUiAuthenticationEnvelopeV2 {
        &self.envelope
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthenticateIngressUiResponseV2 {
    authorization: IngressUiAuthorizationHandleV2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalizeInputResponseV2 {
    pending: PendingIngressHandleV2,
    approval: IngressKernelApprovalHandleV2,
    envelope: SignedApprovalEnvelopeV2,
    display_authentication: SignedUiAuthenticationEnvelopeV2,
}

impl FinalizeInputResponseV2 {
    pub const fn new(
        pending: PendingIngressHandleV2,
        approval: IngressKernelApprovalHandleV2,
        envelope: SignedApprovalEnvelopeV2,
        display_authentication: SignedUiAuthenticationEnvelopeV2,
    ) -> Self {
        Self {
            pending,
            approval,
            envelope,
            display_authentication,
        }
    }

    pub const fn pending(&self) -> PendingIngressHandleV2 {
        self.pending
    }

    pub const fn approval(&self) -> IngressKernelApprovalHandleV2 {
        self.approval
    }

    pub const fn envelope(&self) -> &SignedApprovalEnvelopeV2 {
        &self.envelope
    }

    pub const fn display_authentication(&self) -> &SignedUiAuthenticationEnvelopeV2 {
        &self.display_authentication
    }
}

impl AuthenticateIngressUiResponseV2 {
    pub const fn new(authorization: IngressUiAuthorizationHandleV2) -> Self {
        Self { authorization }
    }

    pub const fn authorization(self) -> IngressUiAuthorizationHandleV2 {
        self.authorization
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InputNextSequenceV2 {
    channel: InputChannelV2,
    next_sequence: u32,
}

impl InputNextSequenceV2 {
    pub const fn new(channel: InputChannelV2, next_sequence: u32) -> Self {
        Self {
            channel,
            next_sequence,
        }
    }

    pub const fn channel(self) -> InputChannelV2 {
        self.channel
    }

    pub const fn next_sequence(self) -> u32 {
        self.next_sequence
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BeginInputResponseV2 {
    session: InputSessionHandleV2,
    writer: IngressWriteCapabilityV2,
    parser_job_session_binding_digest: Digest32V2,
    next_sequences: Vec<InputNextSequenceV2>,
}

impl BeginInputResponseV2 {
    pub fn new(
        session: InputSessionHandleV2,
        writer: IngressWriteCapabilityV2,
        parser_job_session_binding_digest: Digest32V2,
        next_sequences: Vec<InputNextSequenceV2>,
    ) -> Result<Self, ProtocolError> {
        if parser_job_session_binding_digest
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
            || next_sequences.is_empty()
            || next_sequences.len() > MAX_INPUT_CHANNELS_V2
            || next_sequences
                .windows(2)
                .any(|pair| pair[0].channel >= pair[1].channel)
        {
            return Err(malformed());
        }
        Ok(Self {
            session,
            writer,
            parser_job_session_binding_digest,
            next_sequences,
        })
    }

    pub const fn session(&self) -> InputSessionHandleV2 {
        self.session
    }

    pub const fn writer(&self) -> IngressWriteCapabilityV2 {
        self.writer
    }

    pub const fn parser_job_session_binding_digest(&self) -> Digest32V2 {
        self.parser_job_session_binding_digest
    }

    pub fn next_sequences(&self) -> &[InputNextSequenceV2] {
        &self.next_sequences
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppendInputChunkResponseV2 {
    channel: DirectInputChannelV2,
    acknowledged_sequence: u32,
    cumulative_digest: Digest32V2,
}

impl AppendInputChunkResponseV2 {
    pub fn new(
        channel: DirectInputChannelV2,
        acknowledged_sequence: u32,
        cumulative_digest: Digest32V2,
    ) -> Result<Self, ProtocolError> {
        if cumulative_digest.as_bytes().iter().all(|byte| *byte == 0) {
            return Err(malformed());
        }
        Ok(Self {
            channel,
            acknowledged_sequence,
            cumulative_digest,
        })
    }

    pub const fn channel(self) -> DirectInputChannelV2 {
        self.channel
    }

    pub const fn acknowledged_sequence(self) -> u32 {
        self.acknowledged_sequence
    }

    pub const fn cumulative_digest(self) -> Digest32V2 {
        self.cumulative_digest
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegisterParserWorkerJobResponseV2 {
    extraction: ParserExtractionHandleV2,
}

impl RegisterParserWorkerJobResponseV2 {
    pub const fn new(extraction: ParserExtractionHandleV2) -> Self {
        Self { extraction }
    }

    pub const fn extraction(self) -> ParserExtractionHandleV2 {
        self.extraction
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppendParserWorkerPageFrameResponseV2 {
    page_index: u32,
    page_chunk_index: u32,
    ordered_page_frame_transcript_digest: Digest32V2,
}

impl AppendParserWorkerPageFrameResponseV2 {
    pub fn new(
        page_index: u32,
        page_chunk_index: u32,
        ordered_page_frame_transcript_digest: Digest32V2,
    ) -> Result<Self, ProtocolError> {
        if ordered_page_frame_transcript_digest
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
        {
            return Err(malformed());
        }
        Ok(Self {
            page_index,
            page_chunk_index,
            ordered_page_frame_transcript_digest,
        })
    }

    pub const fn page_index(self) -> u32 {
        self.page_index
    }

    pub const fn page_chunk_index(self) -> u32 {
        self.page_chunk_index
    }

    pub const fn ordered_page_frame_transcript_digest(self) -> Digest32V2 {
        self.ordered_page_frame_transcript_digest
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitParserWorkerResultResponseV2 {
    extracted_channel_commitment: InputChannelCommitmentV2,
    parsed_source_provenance_digest: Digest32V2,
}

impl CommitParserWorkerResultResponseV2 {
    pub fn new(
        extracted_channel_commitment: InputChannelCommitmentV2,
        parsed_source_provenance_digest: Digest32V2,
    ) -> Result<Self, ProtocolError> {
        if extracted_channel_commitment.channel() != InputChannelV2::ExtractedPage
            || parsed_source_provenance_digest
                .as_bytes()
                .iter()
                .all(|byte| *byte == 0)
        {
            return Err(malformed());
        }
        Ok(Self {
            extracted_channel_commitment,
            parsed_source_provenance_digest,
        })
    }

    pub const fn extracted_channel_commitment(self) -> InputChannelCommitmentV2 {
        self.extracted_channel_commitment
    }

    pub const fn parsed_source_provenance_digest(self) -> Digest32V2 {
        self.parsed_source_provenance_digest
    }
}

closed_input_state_v2! {
    InputPublicStateV2 {
        Granted = 1,
        Receiving = 2,
        Finalizing = 3,
        AwaitingApproval = 4,
        Committing = 5,
        CommittedUnclaimed = 6,
        AgentClaimed = 7,
        Denied = 8,
        Aborted = 9,
        Expired = 10,
        FailedClosed = 11,
        RestartInvalidated = 12,
        AgentAuthPending = 13,
    }
}

macro_rules! input_state_response_v2 {
    ($name:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct $name {
            state: InputPublicStateV2,
        }

        impl $name {
            pub const fn new(state: InputPublicStateV2) -> Self {
                Self { state }
            }

            pub const fn state(self) -> InputPublicStateV2 {
                self.state
            }
        }
    };
}

input_state_response_v2!(CommitInputSettlementResponseV2);
input_state_response_v2!(AbortInputResponseV2);
input_state_response_v2!(GetInputStatusResponseV2);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeriveValueResponseV2 {
    value: ValueHandleV2,
    value_digest: Digest32V2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunRevisionObservationV2 {
    durable_run_id: DurableRunIdV2,
    revision_number: u64,
    revision_digest: RunRevisionDigestV2,
}

impl RunRevisionObservationV2 {
    pub fn new(
        durable_run_id: DurableRunIdV2,
        revision_number: u64,
        revision_digest: RunRevisionDigestV2,
    ) -> Result<Self, ProtocolError> {
        if durable_run_id.as_bytes().iter().all(|byte| *byte == 0)
            || revision_number == 0
            || revision_digest.as_bytes().iter().all(|byte| *byte == 0)
        {
            return Err(malformed());
        }
        Ok(Self {
            durable_run_id,
            revision_number,
            revision_digest,
        })
    }

    pub const fn durable_run_id(self) -> DurableRunIdV2 {
        self.durable_run_id
    }

    pub const fn revision_number(self) -> u64 {
        self.revision_number
    }

    pub const fn revision_digest(self) -> RunRevisionDigestV2 {
        self.revision_digest
    }
}

impl<C> minicbor::Encode<C> for RunRevisionObservationV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.array(3)?;
        self.durable_run_id.encode(encoder, context)?;
        encoder.u64(self.revision_number)?;
        self.revision_digest.encode(encoder, context)?;
        Ok(())
    }
}

impl<'bytes> minicbor::Decode<'bytes, V2DecodeContext> for RunRevisionObservationV2 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut V2DecodeContext,
    ) -> Result<Self, minicbor::decode::Error> {
        let position = decoder.position();
        if decoder.array()? != Some(3) {
            return Err(decode_error(position));
        }
        Self::new(
            minicbor::Decode::decode(decoder, context)?,
            decoder.u64()?,
            minicbor::Decode::decode(decoder, context)?,
        )
        .map_err(|_| decode_error(position))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActiveToolViewV2 {
    tool: ToolHandleV2,
    action_template: ActionTemplateIdV2,
    tool_class: ToolClassIdV2,
    display_template: StaticTemplateIdV2,
}

impl ActiveToolViewV2 {
    pub fn new(
        tool: ToolHandleV2,
        action_template: ActionTemplateIdV2,
        tool_class: ToolClassIdV2,
        display_template: StaticTemplateIdV2,
    ) -> Result<Self, ProtocolError> {
        if action_template.get() == 0 || tool_class.get() == 0 || display_template.get() == 0 {
            return Err(malformed());
        }
        Ok(Self {
            tool,
            action_template,
            tool_class,
            display_template,
        })
    }

    pub const fn tool(self) -> ToolHandleV2 {
        self.tool
    }

    pub const fn action_template(self) -> ActionTemplateIdV2 {
        self.action_template
    }

    pub const fn tool_class(self) -> ToolClassIdV2 {
        self.tool_class
    }
}

impl<C> minicbor::Encode<C> for ActiveToolViewV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.array(4)?;
        self.tool.encode(encoder, context)?;
        self.action_template.encode(encoder, context)?;
        self.tool_class.encode(encoder, context)?;
        self.display_template.encode(encoder, context)?;
        Ok(())
    }
}

impl<'bytes> minicbor::Decode<'bytes, V2DecodeContext> for ActiveToolViewV2 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut V2DecodeContext,
    ) -> Result<Self, minicbor::decode::Error> {
        let position = decoder.position();
        if decoder.array()? != Some(4) {
            return Err(decode_error(position));
        }
        Self::new(
            minicbor::Decode::decode(decoder, context)?,
            minicbor::Decode::decode(decoder, context)?,
            minicbor::Decode::decode(decoder, context)?,
            minicbor::Decode::decode(decoder, context)?,
        )
        .map_err(|_| decode_error(position))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimAgentSessionResponseV2 {
    session: AgentSessionHandleV2,
    run: RunHandleV2,
    run_revision: RunRevisionObservationV2,
    initial_value: ValueHandleV2,
    initial_document: MaskedDocumentHandleV2,
    active_tools: Vec<ActiveToolViewV2>,
}

impl ClaimAgentSessionResponseV2 {
    pub fn new(
        session: AgentSessionHandleV2,
        run: RunHandleV2,
        run_revision: RunRevisionObservationV2,
        initial_value: ValueHandleV2,
        initial_document: MaskedDocumentHandleV2,
        active_tools: Vec<ActiveToolViewV2>,
    ) -> Result<Self, ProtocolError> {
        if active_tools.len() > MAX_ACTIVE_TOOLS_V2
            || active_tools
                .windows(2)
                .any(|pair| active_tool_key(&pair[0]) >= active_tool_key(&pair[1]))
        {
            return Err(malformed());
        }
        Ok(Self {
            session,
            run,
            run_revision,
            initial_value,
            initial_document,
            active_tools,
        })
    }

    pub const fn session(&self) -> AgentSessionHandleV2 {
        self.session
    }

    pub const fn run(&self) -> RunHandleV2 {
        self.run
    }

    pub const fn initial_value(&self) -> ValueHandleV2 {
        self.initial_value
    }

    pub const fn initial_document(&self) -> MaskedDocumentHandleV2 {
        self.initial_document
    }

    pub fn active_tools(&self) -> &[ActiveToolViewV2] {
        &self.active_tools
    }
}

fn active_tool_key(value: &ActiveToolViewV2) -> (u32, u32, Vec<u8>) {
    (
        value.action_template.get(),
        value.tool_class.get(),
        minicbor::to_vec(value.tool).unwrap_or_default(),
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrepareNewIngressResponseV2 {
    Prepared {
        preparation: NewTaskPreparationHandleV2,
        correlation: SignedDurableTaskCorrelationV2,
        ingress_transfer: KernelIngressBootstrapTransferCapabilityV2,
    },
    Reconciled {
        preparation: NewTaskPreparationHandleV2,
        correlation: SignedDurableTaskCorrelationV2,
        ingress_transfer: KernelIngressBootstrapTransferCapabilityV2,
        current: PublicTaskStatusV2,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrepareFollowupIngressResponseV2 {
    correlation: SignedDurableTaskCorrelationV2,
    input_transfer: KernelIngressBootstrapTransferCapabilityV2,
}

impl PrepareFollowupIngressResponseV2 {
    pub const fn new(
        correlation: SignedDurableTaskCorrelationV2,
        input_transfer: KernelIngressBootstrapTransferCapabilityV2,
    ) -> Self {
        Self {
            correlation,
            input_transfer,
        }
    }

    pub const fn correlation(&self) -> &SignedDurableTaskCorrelationV2 {
        &self.correlation
    }

    pub const fn input_transfer(&self) -> KernelIngressBootstrapTransferCapabilityV2 {
        self.input_transfer
    }
}

closed_input_state_v2! {
    AgentSessionStatusV2 {
        AwaitingAuthentication = 1,
        Ready = 2,
        Running = 3,
        Closed = 4,
        Expired = 5,
        RestartInvalidated = 6,
        Indeterminate = 7,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GetAgentSessionStatusResponseV2 {
    status: AgentSessionStatusV2,
    run_revision: Option<RunRevisionObservationV2>,
}

impl GetAgentSessionStatusResponseV2 {
    pub fn new(
        status: AgentSessionStatusV2,
        run_revision: Option<RunRevisionObservationV2>,
    ) -> Result<Self, ProtocolError> {
        if matches!(
            status,
            AgentSessionStatusV2::Ready | AgentSessionStatusV2::Running
        ) != run_revision.is_some()
        {
            return Err(malformed());
        }
        Ok(Self {
            status,
            run_revision,
        })
    }

    pub const fn status(self) -> AgentSessionStatusV2 {
        self.status
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrepareAgentUiAuthenticationResponseV2 {
    authentication_preparation: AgentUiAuthenticationPreparationHandleV2,
    envelope: SignedUiAuthenticationEnvelopeV2,
}

impl PrepareAgentUiAuthenticationResponseV2 {
    pub const fn new(
        authentication_preparation: AgentUiAuthenticationPreparationHandleV2,
        envelope: SignedUiAuthenticationEnvelopeV2,
    ) -> Self {
        Self {
            authentication_preparation,
            envelope,
        }
    }

    pub const fn authentication_preparation(&self) -> AgentUiAuthenticationPreparationHandleV2 {
        self.authentication_preparation
    }

    pub const fn envelope(&self) -> &SignedUiAuthenticationEnvelopeV2 {
        &self.envelope
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthenticateAgentUiResponseV2 {
    authorization: AgentUiAuthorizationHandleV2,
}

impl AuthenticateAgentUiResponseV2 {
    pub const fn new(authorization: AgentUiAuthorizationHandleV2) -> Self {
        Self { authorization }
    }

    pub const fn authorization(self) -> AgentUiAuthorizationHandleV2 {
        self.authorization
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GetKernelTaskStatusResponseV2 {
    status: PublicTaskStatusV2,
}

impl GetKernelTaskStatusResponseV2 {
    pub const fn new(status: PublicTaskStatusV2) -> Self {
        Self { status }
    }

    pub const fn status(self) -> PublicTaskStatusV2 {
        self.status
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CancelKernelTaskResponseV2 {
    status: PublicTaskStatusV2,
}

impl CancelKernelTaskResponseV2 {
    pub const fn new(status: PublicTaskStatusV2) -> Self {
        Self { status }
    }

    pub const fn status(self) -> PublicTaskStatusV2 {
        self.status
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CloseAgentSessionResponseV2 {
    state: AgentSessionStatusV2,
}

impl CloseAgentSessionResponseV2 {
    pub const fn new(state: AgentSessionStatusV2) -> Self {
        Self { state }
    }

    pub const fn state(self) -> AgentSessionStatusV2 {
        self.state
    }
}

impl<C> minicbor::Encode<C> for ClaimAgentSessionResponseV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.array(6)?;
        self.session.encode(encoder, context)?;
        self.run.encode(encoder, context)?;
        self.run_revision.encode(encoder, context)?;
        self.initial_value.encode(encoder, context)?;
        self.initial_document.encode(encoder, context)?;
        encoder.array(self.active_tools.len() as u64)?;
        for tool in &self.active_tools {
            tool.encode(encoder, context)?;
        }
        Ok(())
    }
}

impl<'bytes> minicbor::Decode<'bytes, V2DecodeContext> for ClaimAgentSessionResponseV2 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut V2DecodeContext,
    ) -> Result<Self, minicbor::decode::Error> {
        let position = decoder.position();
        if decoder.array()? != Some(6) {
            return Err(decode_error(position));
        }
        let session = minicbor::Decode::decode(decoder, context)?;
        let run = minicbor::Decode::decode(decoder, context)?;
        let run_revision = minicbor::Decode::decode(decoder, context)?;
        let initial_value = minicbor::Decode::decode(decoder, context)?;
        let initial_document = minicbor::Decode::decode(decoder, context)?;
        let count = decoder
            .array()?
            .and_then(|value| usize::try_from(value).ok())
            .ok_or_else(|| decode_error(position))?;
        if count > MAX_ACTIVE_TOOLS_V2 {
            return Err(decode_error(position));
        }
        let mut tools = Vec::new();
        tools
            .try_reserve_exact(count)
            .map_err(|_| decode_error(position))?;
        for _ in 0..count {
            tools.push(minicbor::Decode::decode(decoder, context)?);
        }
        Self::new(
            session,
            run,
            run_revision,
            initial_value,
            initial_document,
            tools,
        )
        .map_err(|_| decode_error(position))
    }
}

impl<C> minicbor::Encode<C> for PrepareNewIngressResponseV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        match self {
            Self::Prepared {
                preparation,
                correlation,
                ingress_transfer,
            } => {
                encoder.array(4)?.u16(1)?;
                preparation.encode(encoder, context)?;
                correlation.encode(encoder, context)?;
                ingress_transfer.encode(encoder, context)?;
            }
            Self::Reconciled {
                preparation,
                correlation,
                ingress_transfer,
                current,
            } => {
                encoder.array(5)?.u16(2)?;
                preparation.encode(encoder, context)?;
                correlation.encode(encoder, context)?;
                ingress_transfer.encode(encoder, context)?;
                current.encode(encoder, context)?;
            }
        }
        Ok(())
    }
}

impl<'bytes> minicbor::Decode<'bytes, V2DecodeContext> for PrepareNewIngressResponseV2 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut V2DecodeContext,
    ) -> Result<Self, minicbor::decode::Error> {
        let position = decoder.position();
        let count = decoder.array()?.ok_or_else(|| decode_error(position))?;
        match (count, decoder.u16()?) {
            (4, 1) => Ok(Self::Prepared {
                preparation: minicbor::Decode::decode(decoder, context)?,
                correlation: minicbor::Decode::decode(decoder, context)?,
                ingress_transfer: minicbor::Decode::decode(decoder, context)?,
            }),
            (5, 2) => Ok(Self::Reconciled {
                preparation: minicbor::Decode::decode(decoder, context)?,
                correlation: minicbor::Decode::decode(decoder, context)?,
                ingress_transfer: minicbor::Decode::decode(decoder, context)?,
                current: minicbor::Decode::decode(decoder, context)?,
            }),
            _ => Err(decode_error(position)),
        }
    }
}

impl<C> minicbor::Encode<C> for PrepareFollowupIngressResponseV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.array(2)?;
        self.correlation.encode(encoder, context)?;
        self.input_transfer.encode(encoder, context)?;
        Ok(())
    }
}

impl<'bytes> minicbor::Decode<'bytes, V2DecodeContext> for PrepareFollowupIngressResponseV2 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut V2DecodeContext,
    ) -> Result<Self, minicbor::decode::Error> {
        let position = decoder.position();
        if decoder.array()? != Some(2) {
            return Err(decode_error(position));
        }
        Ok(Self::new(
            minicbor::Decode::decode(decoder, context)?,
            minicbor::Decode::decode(decoder, context)?,
        ))
    }
}

impl<C> minicbor::Encode<C> for GetAgentSessionStatusResponseV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.array(2)?;
        self.status.encode(encoder, context)?;
        match self.run_revision {
            Some(revision) => revision.encode(encoder, context)?,
            None => {
                encoder.null()?;
            }
        }
        Ok(())
    }
}

impl<'bytes> minicbor::Decode<'bytes, V2DecodeContext> for GetAgentSessionStatusResponseV2 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut V2DecodeContext,
    ) -> Result<Self, minicbor::decode::Error> {
        let position = decoder.position();
        if decoder.array()? != Some(2) {
            return Err(decode_error(position));
        }
        let status = minicbor::Decode::decode(decoder, context)?;
        let revision = if decoder.datatype()? == minicbor::data::Type::Null {
            decoder.skip()?;
            None
        } else {
            Some(minicbor::Decode::decode(decoder, context)?)
        };
        Self::new(status, revision).map_err(|_| decode_error(position))
    }
}

macro_rules! two_field_response_codec_impl_v2 {
    ($type:ident, $first:ident, $second:ident) => {
        impl<C> minicbor::Encode<C> for $type {
            fn encode<W: minicbor::encode::Write>(
                &self,
                encoder: &mut minicbor::Encoder<W>,
                context: &mut C,
            ) -> Result<(), minicbor::encode::Error<W::Error>> {
                encoder.array(2)?;
                self.$first.encode(encoder, context)?;
                self.$second.encode(encoder, context)?;
                Ok(())
            }
        }

        impl<'bytes> minicbor::Decode<'bytes, V2DecodeContext> for $type {
            fn decode(
                decoder: &mut minicbor::Decoder<'bytes>,
                context: &mut V2DecodeContext,
            ) -> Result<Self, minicbor::decode::Error> {
                let position = decoder.position();
                if decoder.array()? != Some(2) {
                    return Err(decode_error(position));
                }
                Ok(Self {
                    $first: minicbor::Decode::decode(decoder, context)?,
                    $second: minicbor::Decode::decode(decoder, context)?,
                })
            }
        }
    };
}

two_field_response_codec_impl_v2!(
    PrepareAgentUiAuthenticationResponseV2,
    authentication_preparation,
    envelope
);

macro_rules! one_field_response_codec_impl_v2 {
    ($type:ident, $field:ident) => {
        impl<C> minicbor::Encode<C> for $type {
            fn encode<W: minicbor::encode::Write>(
                &self,
                encoder: &mut minicbor::Encoder<W>,
                context: &mut C,
            ) -> Result<(), minicbor::encode::Error<W::Error>> {
                encoder.array(1)?;
                self.$field.encode(encoder, context)?;
                Ok(())
            }
        }

        impl<'bytes> minicbor::Decode<'bytes, V2DecodeContext> for $type {
            fn decode(
                decoder: &mut minicbor::Decoder<'bytes>,
                context: &mut V2DecodeContext,
            ) -> Result<Self, minicbor::decode::Error> {
                let position = decoder.position();
                if decoder.array()? != Some(1) {
                    return Err(decode_error(position));
                }
                Ok(Self {
                    $field: minicbor::Decode::decode(decoder, context)?,
                })
            }
        }
    };
}

one_field_response_codec_impl_v2!(AuthenticateAgentUiResponseV2, authorization);
one_field_response_codec_impl_v2!(GetKernelTaskStatusResponseV2, status);
one_field_response_codec_impl_v2!(CancelKernelTaskResponseV2, status);
one_field_response_codec_impl_v2!(CloseAgentSessionResponseV2, state);

impl DeriveValueResponseV2 {
    pub fn new(value: ValueHandleV2, value_digest: Digest32V2) -> Result<Self, ProtocolError> {
        if value_digest.as_bytes().iter().all(|byte| *byte == 0) {
            return Err(malformed());
        }
        Ok(Self {
            value,
            value_digest,
        })
    }

    pub const fn value(self) -> ValueHandleV2 {
        self.value
    }

    pub const fn value_digest(self) -> Digest32V2 {
        self.value_digest
    }
}

macro_rules! health_codec_v2 {
    ($encode:ident, $decode:ident, $type:ident) => {
        pub fn $encode(value: &$type) -> Result<Vec<u8>, ProtocolError> {
            let mut encoder = minicbor::Encoder::new(Vec::new());
            encoder
                .array(2)
                .and_then(|encoder| encoder.bool(value.ready))
                .map_err(ProtocolError::malformed)?;
            value
                .state
                .encode(&mut encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
            Ok(encoder.into_writer())
        }

        pub fn $decode(bytes: &[u8]) -> Result<$type, ProtocolError> {
            scan_single(bytes)?;
            let mut decoder = minicbor::Decoder::new(bytes);
            expect_array(&mut decoder, 2)?;
            let ready = decoder.bool().map_err(ProtocolError::malformed)?;
            let mut context = V2DecodeContext;
            let state = minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?;
            let value = $type::new(ready, state);
            require_canonical_end(&decoder, bytes, $encode(&value)?)?;
            Ok(value)
        }
    };
}

health_codec_v2!(
    encode_kernel_agent_health_response_v2,
    decode_kernel_agent_health_response_v2,
    KernelAgentHealthResponseV2
);
health_codec_v2!(
    encode_kernel_ingress_health_response_v2,
    decode_kernel_ingress_health_response_v2,
    KernelIngressHealthResponseV2
);

pub fn encode_prepare_ingress_ui_authentication_response_v2(
    value: &PrepareIngressUiAuthenticationResponseV2,
) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder.array(2).map_err(ProtocolError::malformed)?;
    value
        .authentication_preparation
        .encode(&mut encoder, &mut ())
        .and_then(|_| value.envelope.encode(&mut encoder, &mut ()))
        .map_err(ProtocolError::malformed)?;
    Ok(encoder.into_writer())
}

pub fn decode_prepare_ingress_ui_authentication_response_v2(
    bytes: &[u8],
) -> Result<PrepareIngressUiAuthenticationResponseV2, ProtocolError> {
    scan_single(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    expect_array(&mut decoder, 2)?;
    let mut context = V2DecodeContext;
    let value = PrepareIngressUiAuthenticationResponseV2::new(
        minicbor::Decode::decode(&mut decoder, &mut context)
            .map_err(ProtocolError::from_typed_decode)?,
        minicbor::Decode::decode(&mut decoder, &mut context)
            .map_err(ProtocolError::from_typed_decode)?,
    );
    require_canonical_end(
        &decoder,
        bytes,
        encode_prepare_ingress_ui_authentication_response_v2(&value)?,
    )?;
    Ok(value)
}

pub fn encode_authenticate_ingress_ui_response_v2(
    value: &AuthenticateIngressUiResponseV2,
) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder.array(1).map_err(ProtocolError::malformed)?;
    value
        .authorization
        .encode(&mut encoder, &mut ())
        .map_err(ProtocolError::malformed)?;
    Ok(encoder.into_writer())
}

pub fn decode_authenticate_ingress_ui_response_v2(
    bytes: &[u8],
) -> Result<AuthenticateIngressUiResponseV2, ProtocolError> {
    scan_single(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    expect_array(&mut decoder, 1)?;
    let mut context = V2DecodeContext;
    let value = AuthenticateIngressUiResponseV2::new(
        minicbor::Decode::decode(&mut decoder, &mut context)
            .map_err(ProtocolError::from_typed_decode)?,
    );
    require_canonical_end(
        &decoder,
        bytes,
        encode_authenticate_ingress_ui_response_v2(&value)?,
    )?;
    Ok(value)
}

pub fn encode_finalize_input_response_v2(
    value: &FinalizeInputResponseV2,
) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder.array(4).map_err(ProtocolError::malformed)?;
    value
        .pending
        .encode(&mut encoder, &mut ())
        .and_then(|_| value.approval.encode(&mut encoder, &mut ()))
        .and_then(|_| value.envelope.encode(&mut encoder, &mut ()))
        .and_then(|_| value.display_authentication.encode(&mut encoder, &mut ()))
        .map_err(ProtocolError::malformed)?;
    Ok(encoder.into_writer())
}

pub fn decode_finalize_input_response_v2(
    bytes: &[u8],
) -> Result<FinalizeInputResponseV2, ProtocolError> {
    scan_single(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    expect_array(&mut decoder, 4)?;
    let mut context = V2DecodeContext;
    let value = FinalizeInputResponseV2::new(
        minicbor::Decode::decode(&mut decoder, &mut context)
            .map_err(ProtocolError::from_typed_decode)?,
        minicbor::Decode::decode(&mut decoder, &mut context)
            .map_err(ProtocolError::from_typed_decode)?,
        minicbor::Decode::decode(&mut decoder, &mut context)
            .map_err(ProtocolError::from_typed_decode)?,
        minicbor::Decode::decode(&mut decoder, &mut context)
            .map_err(ProtocolError::from_typed_decode)?,
    );
    require_canonical_end(&decoder, bytes, encode_finalize_input_response_v2(&value)?)?;
    Ok(value)
}

pub fn encode_begin_input_response_v2(
    value: &BeginInputResponseV2,
) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder.array(4).map_err(ProtocolError::malformed)?;
    value
        .session
        .encode(&mut encoder, &mut ())
        .and_then(|_| value.writer.encode(&mut encoder, &mut ()))
        .and_then(|_| {
            value
                .parser_job_session_binding_digest
                .encode(&mut encoder, &mut ())
        })
        .map_err(ProtocolError::malformed)?;
    encoder
        .array(value.next_sequences.len() as u64)
        .map_err(ProtocolError::malformed)?;
    for next in &value.next_sequences {
        encoder.array(2).map_err(ProtocolError::malformed)?;
        next.channel
            .encode(&mut encoder, &mut ())
            .map_err(ProtocolError::malformed)?;
        encoder
            .u32(next.next_sequence)
            .map_err(ProtocolError::malformed)?;
    }
    Ok(encoder.into_writer())
}

pub fn decode_begin_input_response_v2(bytes: &[u8]) -> Result<BeginInputResponseV2, ProtocolError> {
    scan_single(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    expect_array(&mut decoder, 4)?;
    let mut context = V2DecodeContext;
    let session = minicbor::Decode::decode(&mut decoder, &mut context)
        .map_err(ProtocolError::from_typed_decode)?;
    let writer = minicbor::Decode::decode(&mut decoder, &mut context)
        .map_err(ProtocolError::from_typed_decode)?;
    let parser_job_session_binding_digest = minicbor::Decode::decode(&mut decoder, &mut context)
        .map_err(ProtocolError::from_typed_decode)?;
    let count = decoder
        .array()
        .map_err(ProtocolError::malformed)?
        .ok_or_else(malformed)?;
    let count = usize::try_from(count).map_err(ProtocolError::malformed)?;
    if count == 0 || count > MAX_INPUT_CHANNELS_V2 {
        return Err(malformed());
    }
    let mut next_sequences = Vec::new();
    next_sequences
        .try_reserve_exact(count)
        .map_err(|_| ProtocolError::stable(StableCode::ProtocolAllocationRefused))?;
    for _ in 0..count {
        expect_array(&mut decoder, 2)?;
        next_sequences.push(InputNextSequenceV2::new(
            minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?,
            decoder.u32().map_err(ProtocolError::malformed)?,
        ));
    }
    let value = BeginInputResponseV2::new(
        session,
        writer,
        parser_job_session_binding_digest,
        next_sequences,
    )?;
    require_canonical_end(&decoder, bytes, encode_begin_input_response_v2(&value)?)?;
    Ok(value)
}

pub fn encode_append_input_chunk_response_v2(
    value: &AppendInputChunkResponseV2,
) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder.array(3).map_err(ProtocolError::malformed)?;
    value
        .channel
        .encode(&mut encoder, &mut ())
        .map_err(ProtocolError::malformed)?;
    encoder
        .u32(value.acknowledged_sequence)
        .map_err(ProtocolError::malformed)?;
    value
        .cumulative_digest
        .encode(&mut encoder, &mut ())
        .map_err(ProtocolError::malformed)?;
    Ok(encoder.into_writer())
}

pub fn decode_append_input_chunk_response_v2(
    bytes: &[u8],
) -> Result<AppendInputChunkResponseV2, ProtocolError> {
    scan_single(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    expect_array(&mut decoder, 3)?;
    let mut context = V2DecodeContext;
    let value = AppendInputChunkResponseV2::new(
        minicbor::Decode::decode(&mut decoder, &mut context)
            .map_err(ProtocolError::from_typed_decode)?,
        decoder.u32().map_err(ProtocolError::malformed)?,
        minicbor::Decode::decode(&mut decoder, &mut context)
            .map_err(ProtocolError::from_typed_decode)?,
    )?;
    require_canonical_end(
        &decoder,
        bytes,
        encode_append_input_chunk_response_v2(&value)?,
    )?;
    Ok(value)
}

pub fn encode_register_parser_worker_job_response_v2(
    value: &RegisterParserWorkerJobResponseV2,
) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder.array(1).map_err(ProtocolError::malformed)?;
    value
        .extraction
        .encode(&mut encoder, &mut ())
        .map_err(ProtocolError::malformed)?;
    Ok(encoder.into_writer())
}

pub fn decode_register_parser_worker_job_response_v2(
    bytes: &[u8],
) -> Result<RegisterParserWorkerJobResponseV2, ProtocolError> {
    scan_single(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    expect_array(&mut decoder, 1)?;
    let mut context = V2DecodeContext;
    let value = RegisterParserWorkerJobResponseV2::new(
        minicbor::Decode::decode(&mut decoder, &mut context)
            .map_err(ProtocolError::from_typed_decode)?,
    );
    require_canonical_end(
        &decoder,
        bytes,
        encode_register_parser_worker_job_response_v2(&value)?,
    )?;
    Ok(value)
}

pub fn encode_append_parser_worker_page_frame_response_v2(
    value: &AppendParserWorkerPageFrameResponseV2,
) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(3)
        .and_then(|encoder| encoder.u32(value.page_index))
        .and_then(|encoder| encoder.u32(value.page_chunk_index))
        .map_err(ProtocolError::malformed)?;
    value
        .ordered_page_frame_transcript_digest
        .encode(&mut encoder, &mut ())
        .map_err(ProtocolError::malformed)?;
    Ok(encoder.into_writer())
}

pub fn decode_append_parser_worker_page_frame_response_v2(
    bytes: &[u8],
) -> Result<AppendParserWorkerPageFrameResponseV2, ProtocolError> {
    scan_single(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    expect_array(&mut decoder, 3)?;
    let page_index = decoder.u32().map_err(ProtocolError::malformed)?;
    let page_chunk_index = decoder.u32().map_err(ProtocolError::malformed)?;
    let mut context = V2DecodeContext;
    let value = AppendParserWorkerPageFrameResponseV2::new(
        page_index,
        page_chunk_index,
        minicbor::Decode::decode(&mut decoder, &mut context)
            .map_err(ProtocolError::from_typed_decode)?,
    )?;
    require_canonical_end(
        &decoder,
        bytes,
        encode_append_parser_worker_page_frame_response_v2(&value)?,
    )?;
    Ok(value)
}

pub fn encode_commit_parser_worker_result_response_v2(
    value: &CommitParserWorkerResultResponseV2,
) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder.array(2).map_err(ProtocolError::malformed)?;
    let commitment = value.extracted_channel_commitment;
    encoder.array(5).map_err(ProtocolError::malformed)?;
    commitment
        .channel()
        .encode(&mut encoder, &mut ())
        .map_err(ProtocolError::malformed)?;
    encoder
        .u32(commitment.chunk_count())
        .and_then(|encoder| encoder.u32(commitment.final_sequence()))
        .and_then(|encoder| encoder.u64(commitment.total_length()))
        .map_err(ProtocolError::malformed)?;
    commitment
        .final_cumulative_digest()
        .encode(&mut encoder, &mut ())
        .and_then(|_| {
            value
                .parsed_source_provenance_digest
                .encode(&mut encoder, &mut ())
        })
        .map_err(ProtocolError::malformed)?;
    Ok(encoder.into_writer())
}

pub fn decode_commit_parser_worker_result_response_v2(
    bytes: &[u8],
) -> Result<CommitParserWorkerResultResponseV2, ProtocolError> {
    scan_single(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    expect_array(&mut decoder, 2)?;
    expect_array(&mut decoder, 5)?;
    let mut context = V2DecodeContext;
    let commitment = InputChannelCommitmentV2::new(
        minicbor::Decode::decode(&mut decoder, &mut context)
            .map_err(ProtocolError::from_typed_decode)?,
        decoder.u32().map_err(ProtocolError::malformed)?,
        decoder.u32().map_err(ProtocolError::malformed)?,
        decoder.u64().map_err(ProtocolError::malformed)?,
        minicbor::Decode::decode(&mut decoder, &mut context)
            .map_err(ProtocolError::from_typed_decode)?,
    )?;
    let value = CommitParserWorkerResultResponseV2::new(
        commitment,
        minicbor::Decode::decode(&mut decoder, &mut context)
            .map_err(ProtocolError::from_typed_decode)?,
    )?;
    require_canonical_end(
        &decoder,
        bytes,
        encode_commit_parser_worker_result_response_v2(&value)?,
    )?;
    Ok(value)
}

macro_rules! input_state_codec_v2 {
    ($encode:ident, $decode:ident, $type:ident) => {
        pub fn $encode(value: &$type) -> Result<Vec<u8>, ProtocolError> {
            let mut encoder = minicbor::Encoder::new(Vec::new());
            encoder.array(1).map_err(ProtocolError::malformed)?;
            value
                .state
                .encode(&mut encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
            Ok(encoder.into_writer())
        }

        pub fn $decode(bytes: &[u8]) -> Result<$type, ProtocolError> {
            scan_single(bytes)?;
            let mut decoder = minicbor::Decoder::new(bytes);
            expect_array(&mut decoder, 1)?;
            let mut context = V2DecodeContext;
            let value = $type::new(
                minicbor::Decode::decode(&mut decoder, &mut context)
                    .map_err(ProtocolError::from_typed_decode)?,
            );
            require_canonical_end(&decoder, bytes, $encode(&value)?)?;
            Ok(value)
        }
    };
}

input_state_codec_v2!(
    encode_commit_input_settlement_response_v2,
    decode_commit_input_settlement_response_v2,
    CommitInputSettlementResponseV2
);
input_state_codec_v2!(
    encode_abort_input_response_v2,
    decode_abort_input_response_v2,
    AbortInputResponseV2
);
input_state_codec_v2!(
    encode_get_input_status_response_v2,
    decode_get_input_status_response_v2,
    GetInputStatusResponseV2
);

pub fn encode_derive_value_response_v2(
    value: &DeriveValueResponseV2,
) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder.array(2).map_err(ProtocolError::malformed)?;
    value
        .value
        .encode(&mut encoder, &mut ())
        .and_then(|_| value.value_digest.encode(&mut encoder, &mut ()))
        .map_err(ProtocolError::malformed)?;
    Ok(encoder.into_writer())
}

pub fn decode_derive_value_response_v2(
    bytes: &[u8],
) -> Result<DeriveValueResponseV2, ProtocolError> {
    scan_single(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    expect_array(&mut decoder, 2)?;
    let mut context = V2DecodeContext;
    let value = DeriveValueResponseV2::new(
        minicbor::Decode::decode(&mut decoder, &mut context)
            .map_err(ProtocolError::from_typed_decode)?,
        minicbor::Decode::decode(&mut decoder, &mut context)
            .map_err(ProtocolError::from_typed_decode)?,
    )?;
    require_canonical_end(&decoder, bytes, encode_derive_value_response_v2(&value)?)?;
    Ok(value)
}

macro_rules! exact_response_codec_v2 {
    ($encode:ident, $decode:ident, $type:ty) => {
        pub fn $encode(value: &$type) -> Result<Vec<u8>, ProtocolError> {
            minicbor::to_vec(value).map_err(ProtocolError::malformed)
        }

        pub fn $decode(bytes: &[u8]) -> Result<$type, ProtocolError> {
            scan_single(bytes)?;
            let mut decoder = minicbor::Decoder::new(bytes);
            let mut context = V2DecodeContext;
            let value = minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?;
            require_canonical_end(&decoder, bytes, $encode(&value)?)?;
            Ok(value)
        }
    };
}

exact_response_codec_v2!(
    encode_claim_agent_session_response_v2,
    decode_claim_agent_session_response_v2,
    ClaimAgentSessionResponseV2
);
exact_response_codec_v2!(
    encode_prepare_new_ingress_response_v2,
    decode_prepare_new_ingress_response_v2,
    PrepareNewIngressResponseV2
);
exact_response_codec_v2!(
    encode_prepare_followup_ingress_response_v2,
    decode_prepare_followup_ingress_response_v2,
    PrepareFollowupIngressResponseV2
);
exact_response_codec_v2!(
    encode_get_agent_session_status_response_v2,
    decode_get_agent_session_status_response_v2,
    GetAgentSessionStatusResponseV2
);
exact_response_codec_v2!(
    encode_prepare_agent_ui_authentication_response_v2,
    decode_prepare_agent_ui_authentication_response_v2,
    PrepareAgentUiAuthenticationResponseV2
);
exact_response_codec_v2!(
    encode_authenticate_agent_ui_response_v2,
    decode_authenticate_agent_ui_response_v2,
    AuthenticateAgentUiResponseV2
);
exact_response_codec_v2!(
    encode_get_kernel_task_status_response_v2,
    decode_get_kernel_task_status_response_v2,
    GetKernelTaskStatusResponseV2
);
exact_response_codec_v2!(
    encode_cancel_kernel_task_response_v2,
    decode_cancel_kernel_task_response_v2,
    CancelKernelTaskResponseV2
);
exact_response_codec_v2!(
    encode_close_agent_session_response_v2,
    decode_close_agent_session_response_v2,
    CloseAgentSessionResponseV2
);

fn expect_array(decoder: &mut minicbor::Decoder<'_>, expected: u64) -> Result<(), ProtocolError> {
    if decoder.array().map_err(ProtocolError::malformed)? != Some(expected) {
        return Err(malformed());
    }
    Ok(())
}

fn require_canonical_end(
    decoder: &minicbor::Decoder<'_>,
    original: &[u8],
    canonical: Vec<u8>,
) -> Result<(), ProtocolError> {
    if decoder.position() != original.len() || canonical != original {
        return Err(malformed());
    }
    Ok(())
}

fn malformed() -> ProtocolError {
    ProtocolError::stable(StableCode::ProtocolMalformedCbor)
}

fn decode_error(position: usize) -> minicbor::decode::Error {
    minicbor::decode::Error::message(StableCode::ProtocolMalformedCbor.as_str()).at(position)
}

#[cfg(test)]
mod tests {
    use super::{
        decode_append_input_chunk_response_v2, decode_append_parser_worker_page_frame_response_v2,
        decode_begin_input_response_v2, decode_claim_agent_session_response_v2,
        decode_commit_parser_worker_result_response_v2, decode_derive_value_response_v2,
        decode_prepare_new_ingress_response_v2, decode_register_parser_worker_job_response_v2,
        encode_append_input_chunk_response_v2, encode_append_parser_worker_page_frame_response_v2,
        encode_begin_input_response_v2, encode_claim_agent_session_response_v2,
        encode_commit_parser_worker_result_response_v2, encode_derive_value_response_v2,
        encode_prepare_new_ingress_response_v2, encode_register_parser_worker_job_response_v2,
        AppendInputChunkResponseV2, AppendParserWorkerPageFrameResponseV2, BeginInputResponseV2,
        ClaimAgentSessionResponseV2, CommitParserWorkerResultResponseV2, DeriveValueResponseV2,
        InputNextSequenceV2, PrepareNewIngressResponseV2, RegisterParserWorkerJobResponseV2,
        RunRevisionObservationV2,
    };
    use crate::v2::{
        AgentSessionHandleV2, BootIdV2, Digest32V2, DirectInputChannelV2, DurableRunIdV2,
        DurableTaskIdV2, Ed25519KeyIdV2, Ed25519SignatureV2, IngressWriteCapabilityV2,
        InputChannelCommitmentV2, InputChannelV2, InputSessionHandleV2,
        KernelIngressBootstrapTransferCapabilityV2, MaskedDocumentHandleV2,
        NewTaskPreparationHandleV2, ParserExtractionHandleV2, RunHandleV2, RunRevisionDigestV2,
        ServiceIdentityV2, SignedDurableTaskCorrelationV2, UnixMillisV2,
        UnsignedDurableTaskCorrelationV2, ValueHandleV2,
    };

    #[test]
    fn implemented_kernel_success_bodies_round_trip_canonically() {
        let begin = BeginInputResponseV2::new(
            InputSessionHandleV2::from_authority_entropy([0x11; 32]).unwrap(),
            IngressWriteCapabilityV2::from_authority_entropy([0x12; 32]).unwrap(),
            Digest32V2::new([0x13; 32]),
            vec![InputNextSequenceV2::new(InputChannelV2::ChatText, 0)],
        )
        .unwrap();
        let bytes = encode_begin_input_response_v2(&begin).unwrap();
        assert_eq!(decode_begin_input_response_v2(&bytes).unwrap(), begin);

        let append = AppendInputChunkResponseV2::new(
            DirectInputChannelV2::ChatText,
            0,
            Digest32V2::new([0x14; 32]),
        )
        .unwrap();
        let bytes = encode_append_input_chunk_response_v2(&append).unwrap();
        assert_eq!(
            decode_append_input_chunk_response_v2(&bytes).unwrap(),
            append
        );

        let derived = DeriveValueResponseV2::new(
            ValueHandleV2::from_authority_entropy([0x15; 32]).unwrap(),
            Digest32V2::new([0x16; 32]),
        )
        .unwrap();
        let bytes = encode_derive_value_response_v2(&derived).unwrap();
        assert_eq!(decode_derive_value_response_v2(&bytes).unwrap(), derived);

        let registered = RegisterParserWorkerJobResponseV2::new(
            ParserExtractionHandleV2::from_authority_entropy([0x17; 32]).unwrap(),
        );
        let bytes = encode_register_parser_worker_job_response_v2(&registered).unwrap();
        assert_eq!(
            decode_register_parser_worker_job_response_v2(&bytes).unwrap(),
            registered
        );

        let appended =
            AppendParserWorkerPageFrameResponseV2::new(0, 1, Digest32V2::new([0x18; 32])).unwrap();
        let bytes = encode_append_parser_worker_page_frame_response_v2(&appended).unwrap();
        assert_eq!(
            decode_append_parser_worker_page_frame_response_v2(&bytes).unwrap(),
            appended
        );

        let committed = CommitParserWorkerResultResponseV2::new(
            InputChannelCommitmentV2::new(
                InputChannelV2::ExtractedPage,
                2,
                1,
                6,
                Digest32V2::new([0x19; 32]),
            )
            .unwrap(),
            Digest32V2::new([0x1a; 32]),
        )
        .unwrap();
        let bytes = encode_commit_parser_worker_result_response_v2(&committed).unwrap();
        assert_eq!(
            decode_commit_parser_worker_result_response_v2(&bytes).unwrap(),
            committed
        );
    }

    #[test]
    fn agent_task_success_bodies_round_trip_and_reject_trailing_bytes() {
        let claim = ClaimAgentSessionResponseV2::new(
            AgentSessionHandleV2::from_authority_entropy([0x61; 32]).unwrap(),
            RunHandleV2::from_authority_entropy([0x62; 32]).unwrap(),
            RunRevisionObservationV2::new(
                DurableRunIdV2::new([0x63; 32]),
                1,
                RunRevisionDigestV2::new([0x64; 32]),
            )
            .unwrap(),
            ValueHandleV2::from_authority_entropy([0x65; 32]).unwrap(),
            MaskedDocumentHandleV2::from_authority_entropy([0x66; 32]).unwrap(),
            Vec::new(),
        )
        .unwrap();
        let bytes = encode_claim_agent_session_response_v2(&claim).unwrap();
        assert_eq!(
            decode_claim_agent_session_response_v2(&bytes).unwrap(),
            claim
        );

        let unsigned = UnsignedDurableTaskCorrelationV2::new(
            Digest32V2::new([0x67; 32]),
            Digest32V2::new([0x68; 32]),
            7,
            DurableTaskIdV2::new([0x69; 32]),
            ServiceIdentityV2::new([0x6a; 32]),
            BootIdV2::new([0x6b; 32]),
            BootIdV2::new([0x6c; 32]),
            BootIdV2::new([0x6d; 32]),
            UnixMillisV2::new(10),
            UnixMillisV2::new(20),
            UnixMillisV2::new(30),
        )
        .unwrap();
        let correlation = SignedDurableTaskCorrelationV2::from_parts(
            unsigned,
            Ed25519KeyIdV2::new([0x6e; 32]),
            Ed25519SignatureV2::new([0x6f; 64]),
        )
        .unwrap();
        let prepared = PrepareNewIngressResponseV2::Prepared {
            preparation: NewTaskPreparationHandleV2::from_authority_entropy([0x70; 32]).unwrap(),
            correlation,
            ingress_transfer: KernelIngressBootstrapTransferCapabilityV2::from_authority_entropy(
                [0x71; 32],
            )
            .unwrap(),
        };
        let mut bytes = encode_prepare_new_ingress_response_v2(&prepared).unwrap();
        assert_eq!(
            decode_prepare_new_ingress_response_v2(&bytes).unwrap(),
            prepared
        );
        bytes.push(0);
        assert!(decode_prepare_new_ingress_response_v2(&bytes).is_err());
    }
}
