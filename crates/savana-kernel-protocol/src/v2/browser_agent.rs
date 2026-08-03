use minicbor::Encode as _;

use super::{
    cbor::V2DecodeContext, AgentBrowserViewCursorCapabilityV2, AgentExecutionRefV2,
    AgentExecutionTicketRefV2, AgentMaskedDocumentRefV2, AgentPendingConnectorRegistrationRefV2,
    AgentPendingToolCallRefV2, AgentPlanStepRefV2, AgentReleaseRefV2, AgentReleaseTicketRefV2,
    AgentSessionStatusV2, AgentTabSessionCapabilityV2, AgentViewV2,
    ApprovalDisplayAuthenticationTransferCapabilityV2, BoundedConnectorRegistrySnapshotV2,
    Digest32V2, KernelIngressBootstrapTransferCapabilityV2, Nonce32V2, PublicDecisionTraceV2,
    PublicDispatchAcceptedStateV2, PublicFailureClassV2, PublicStableCodeV2, VaultPublicStateV2,
};
use crate::{ProtocolError, StableCode};

const MAX_AGENT_BROWSER_BODY_BYTES_V2: usize = 8 * 1024 * 1024;
const MAX_AGENT_BROWSER_VIEW_BYTES_V2: u32 = 8 * 1024 * 1024 - 512;
const MAX_AGENT_BROWSER_OBJECTS_V2: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentUiAuthenticationCompleteBrowserResponseV2 {
    tab: AgentTabSessionCapabilityV2,
    initial_document: AgentMaskedDocumentRefV2,
}

impl AgentUiAuthenticationCompleteBrowserResponseV2 {
    pub fn new(
        tab: AgentTabSessionCapabilityV2,
        initial_document: AgentMaskedDocumentRefV2,
    ) -> Self {
        Self {
            tab,
            initial_document,
        }
    }

    pub const fn tab(self) -> AgentTabSessionCapabilityV2 {
        self.tab
    }

    pub const fn initial_document(self) -> AgentMaskedDocumentRefV2 {
        self.initial_document
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentBrowserActionV2 {
    PrepareFollowupIngress,
    RunPlanner,
    RunPlannerWithThirdPartyMapper,
    ProposePlanStep(AgentPlanStepRefV2),
    EvaluatePending(AgentPendingToolCallRefV2),
    DispatchTicket(AgentExecutionTicketRefV2),
    PrepareRelease(AgentMaskedDocumentRefV2),
    DispatchRelease(AgentReleaseTicketRefV2),
    RevokeVault(AgentMaskedDocumentRefV2),
    CloseSession,
    RefreshExecution(AgentExecutionRefV2),
    RefreshRelease(AgentReleaseRefV2),
    RegisterConnector(Vec<u8>),
    FinalizeConnectorRegistration(AgentPendingConnectorRegistrationRefV2),
    RemoveConnector(Digest32V2),
    SnapshotConnectors,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixedBrowserFormPostCarrierV2 {
    AgentFollowupIngress(KernelIngressBootstrapTransferCapabilityV2),
    AgentApprovalDisplay(ApprovalDisplayAuthenticationTransferCapabilityV2),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentBrowserExecutionStateV2 {
    Prepared,
    Dispatching,
    ResultGatePending,
    Succeeded { document: AgentMaskedDocumentRefV2 },
    EffectSucceededOutputQuarantined { class: PublicFailureClassV2 },
    FailedNoEffect { class: PublicFailureClassV2 },
    Indeterminate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentBrowserReleaseStateV2 {
    Prepared,
    Dispatching,
    Succeeded,
    EffectSucceededOutputQuarantined { class: PublicFailureClassV2 },
    FailedNoEffect { class: PublicFailureClassV2 },
    Indeterminate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentBrowserObjectRefV2 {
    Document(AgentMaskedDocumentRefV2),
    PlanStep(AgentPlanStepRefV2),
    PendingToolCall(AgentPendingToolCallRefV2),
    ExecutionTicket(AgentExecutionTicketRefV2),
    ReleaseTicket(AgentReleaseTicketRefV2),
    Execution(AgentExecutionRefV2),
    Release(AgentReleaseRefV2),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentBrowserMutationResponseV2 {
    FollowupOpenIngress {
        post: FixedBrowserFormPostCarrierV2,
    },
    PlannerCommitted {
        steps: Vec<AgentPlanStepRefV2>,
    },
    ToolProposed {
        pending: AgentPendingToolCallRefV2,
    },
    ToolDenied {
        code: PublicStableCodeV2,
        trace: PublicDecisionTraceV2,
    },
    ToolOpenApproval {
        post: FixedBrowserFormPostCarrierV2,
        trace: PublicDecisionTraceV2,
    },
    ToolAuthorized {
        ticket: AgentExecutionTicketRefV2,
        trace: PublicDecisionTraceV2,
    },
    ExecutionDispatched {
        execution: AgentExecutionRefV2,
        state: PublicDispatchAcceptedStateV2,
    },
    ReleaseOpenApproval {
        post: FixedBrowserFormPostCarrierV2,
    },
    ReleaseDispatched {
        release: AgentReleaseRefV2,
        state: PublicDispatchAcceptedStateV2,
    },
    VaultRevoked {
        state: VaultPublicStateV2,
    },
    SessionClosed {
        state: AgentSessionStatusV2,
    },
    ExecutionRefreshed {
        execution: AgentExecutionRefV2,
        state: AgentBrowserExecutionStateV2,
    },
    ReleaseRefreshed {
        release: AgentReleaseRefV2,
        state: AgentBrowserReleaseStateV2,
    },
    ConnectorOpenApproval {
        pending: AgentPendingConnectorRegistrationRefV2,
        post: FixedBrowserFormPostCarrierV2,
    },
    ConnectorRegistrationCommitted {
        pending: AgentPendingConnectorRegistrationRefV2,
        signed_delta_digest: Digest32V2,
        head_digest: Digest32V2,
        sequence: u64,
        connector_id: Digest32V2,
    },
    ConnectorRemovalCommitted {
        signed_delta_digest: Digest32V2,
        head_digest: Digest32V2,
        sequence: u64,
        connector_id: Digest32V2,
    },
    ConnectorRegistrySnapshot {
        canonical_snapshot: BoundedConnectorRegistrySnapshotV2,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentBrowserRequestV2 {
    ReadView {
        tab: AgentTabSessionCapabilityV2,
        client_request_nonce: Nonce32V2,
        document: AgentMaskedDocumentRefV2,
        cursor: Option<AgentBrowserViewCursorCapabilityV2>,
        maximum_encoded_bytes: u32,
    },
    Act {
        tab: AgentTabSessionCapabilityV2,
        client_request_nonce: Nonce32V2,
        action: AgentBrowserActionV2,
    },
}

impl AgentBrowserRequestV2 {
    pub const fn tab(&self) -> AgentTabSessionCapabilityV2 {
        match self {
            Self::ReadView { tab, .. } | Self::Act { tab, .. } => *tab,
        }
    }

    pub const fn client_request_nonce(&self) -> Nonce32V2 {
        match self {
            Self::ReadView {
                client_request_nonce,
                ..
            }
            | Self::Act {
                client_request_nonce,
                ..
            } => *client_request_nonce,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentBrowserReadViewResponseV2 {
    view: AgentViewV2,
    objects: Vec<AgentBrowserObjectRefV2>,
    next: Option<AgentBrowserViewCursorCapabilityV2>,
}

impl AgentBrowserReadViewResponseV2 {
    pub fn new(
        view: AgentViewV2,
        objects: Vec<AgentBrowserObjectRefV2>,
        next: Option<AgentBrowserViewCursorCapabilityV2>,
    ) -> Result<Self, ProtocolError> {
        if objects.len() > MAX_AGENT_BROWSER_OBJECTS_V2 {
            return Err(malformed());
        }
        Ok(Self {
            view,
            objects,
            next,
        })
    }

    pub const fn view(&self) -> &AgentViewV2 {
        &self.view
    }

    pub fn objects(&self) -> &[AgentBrowserObjectRefV2] {
        &self.objects
    }

    pub const fn next(&self) -> Option<AgentBrowserViewCursorCapabilityV2> {
        self.next
    }
}

pub fn encode_agent_ui_authentication_complete_browser_response_v2(
    value: AgentUiAuthenticationCompleteBrowserResponseV2,
) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder.array(2).map_err(ProtocolError::malformed)?;
    value
        .tab
        .encode(&mut encoder, &mut ())
        .and_then(|()| value.initial_document.encode(&mut encoder, &mut ()))
        .map_err(ProtocolError::malformed)?;
    Ok(encoder.into_writer())
}

pub fn decode_agent_ui_authentication_complete_browser_response_v2(
    bytes: &[u8],
) -> Result<AgentUiAuthenticationCompleteBrowserResponseV2, ProtocolError> {
    validate_body(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    if decoder.array().map_err(ProtocolError::malformed)? != Some(2) {
        return Err(malformed());
    }
    let mut context = V2DecodeContext;
    let value = AgentUiAuthenticationCompleteBrowserResponseV2::new(
        minicbor::Decode::decode(&mut decoder, &mut context)
            .map_err(ProtocolError::from_typed_decode)?,
        minicbor::Decode::decode(&mut decoder, &mut context)
            .map_err(ProtocolError::from_typed_decode)?,
    );
    if decoder.position() != bytes.len()
        || encode_agent_ui_authentication_complete_browser_response_v2(value)? != bytes
    {
        return Err(noncanonical());
    }
    Ok(value)
}

pub fn encode_agent_browser_request_v2(
    value: AgentBrowserRequestV2,
) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    match value {
        AgentBrowserRequestV2::ReadView {
            tab,
            client_request_nonce,
            document,
            cursor,
            maximum_encoded_bytes,
        } => {
            if maximum_encoded_bytes == 0 || maximum_encoded_bytes > MAX_AGENT_BROWSER_VIEW_BYTES_V2
            {
                return Err(malformed());
            }
            encoder
                .array(6)
                .and_then(|encoder| encoder.u16(1))
                .map_err(ProtocolError::malformed)?;
            tab.encode(&mut encoder, &mut ())
                .and_then(|()| client_request_nonce.encode(&mut encoder, &mut ()))
                .and_then(|()| document.encode(&mut encoder, &mut ()))
                .map_err(ProtocolError::malformed)?;
            encode_optional(&mut encoder, cursor)?;
            encoder
                .u32(maximum_encoded_bytes)
                .map_err(ProtocolError::malformed)?;
        }
        AgentBrowserRequestV2::Act {
            tab,
            client_request_nonce,
            action,
        } => {
            encoder
                .array(4)
                .and_then(|encoder| encoder.u16(2))
                .map_err(ProtocolError::malformed)?;
            tab.encode(&mut encoder, &mut ())
                .and_then(|()| client_request_nonce.encode(&mut encoder, &mut ()))
                .map_err(ProtocolError::malformed)?;
            encode_action(&mut encoder, action)?;
        }
    }
    Ok(encoder.into_writer())
}

pub fn decode_agent_browser_request_v2(
    bytes: &[u8],
) -> Result<AgentBrowserRequestV2, ProtocolError> {
    if bytes.is_empty() || bytes.len() > MAX_AGENT_BROWSER_BODY_BYTES_V2 {
        return Err(malformed());
    }
    let mut decoder = minicbor::Decoder::new(bytes);
    let count = decoder.array().map_err(ProtocolError::malformed)?;
    let tag = decoder.u16().map_err(ProtocolError::malformed)?;
    let mut context = V2DecodeContext;
    let value = match (tag, count) {
        (1, Some(6)) => {
            let tab = minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?;
            let client_request_nonce = minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?;
            let document = minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?;
            let cursor = decode_optional(&mut decoder, &mut context)?;
            let maximum_encoded_bytes = decoder.u32().map_err(ProtocolError::malformed)?;
            if maximum_encoded_bytes == 0 || maximum_encoded_bytes > MAX_AGENT_BROWSER_VIEW_BYTES_V2
            {
                return Err(malformed());
            }
            AgentBrowserRequestV2::ReadView {
                tab,
                client_request_nonce,
                document,
                cursor,
                maximum_encoded_bytes,
            }
        }
        (2, Some(4)) => AgentBrowserRequestV2::Act {
            tab: minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?,
            client_request_nonce: minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?,
            action: decode_action(&mut decoder, &mut context)?,
        },
        _ => return Err(malformed()),
    };
    if decoder.position() != bytes.len() || encode_agent_browser_request_v2(value.clone())? != bytes
    {
        return Err(noncanonical());
    }
    Ok(value)
}

pub fn encode_agent_browser_read_view_response_v2(
    value: &AgentBrowserReadViewResponseV2,
) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder.array(3).map_err(ProtocolError::malformed)?;
    value
        .view
        .encode(&mut encoder, &mut ())
        .map_err(ProtocolError::malformed)?;
    encoder
        .array(u64::try_from(value.objects.len()).map_err(|_| malformed())?)
        .map_err(ProtocolError::malformed)?;
    for object in &value.objects {
        encode_object(&mut encoder, *object)?;
    }
    encode_optional(&mut encoder, value.next)?;
    let bytes = encoder.into_writer();
    if bytes.len() > MAX_AGENT_BROWSER_BODY_BYTES_V2 {
        return Err(malformed());
    }
    Ok(bytes)
}

pub fn decode_agent_browser_read_view_response_v2(
    bytes: &[u8],
) -> Result<AgentBrowserReadViewResponseV2, ProtocolError> {
    validate_body(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    if decoder.array().map_err(ProtocolError::malformed)? != Some(3) {
        return Err(malformed());
    }
    let mut context = V2DecodeContext;
    let view = minicbor::Decode::decode(&mut decoder, &mut context)
        .map_err(ProtocolError::from_typed_decode)?;
    let object_count = decoder
        .array()
        .map_err(ProtocolError::malformed)?
        .ok_or_else(malformed)?;
    if object_count > MAX_AGENT_BROWSER_OBJECTS_V2 as u64 {
        return Err(malformed());
    }
    let mut objects = Vec::with_capacity(usize::try_from(object_count).map_err(|_| malformed())?);
    for _ in 0..object_count {
        objects.push(decode_object(&mut decoder, &mut context)?);
    }
    let next = decode_optional(&mut decoder, &mut context)?;
    let value = AgentBrowserReadViewResponseV2::new(view, objects, next)?;
    if decoder.position() != bytes.len()
        || encode_agent_browser_read_view_response_v2(&value)? != bytes
    {
        return Err(noncanonical());
    }
    Ok(value)
}

pub fn encode_agent_browser_mutation_response_v2(
    value: &AgentBrowserMutationResponseV2,
) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    match value {
        AgentBrowserMutationResponseV2::FollowupOpenIngress { post } => {
            encoder
                .array(2)
                .and_then(|encoder| encoder.u16(1))
                .map_err(ProtocolError::malformed)?;
            encode_post(&mut encoder, *post)?;
        }
        AgentBrowserMutationResponseV2::PlannerCommitted { steps } => {
            if steps.len() > 256 {
                return Err(malformed());
            }
            encoder
                .array(2)
                .and_then(|encoder| encoder.u16(2))
                .and_then(|encoder| encoder.array(steps.len() as u64))
                .map_err(ProtocolError::malformed)?;
            for step in steps {
                step.encode(&mut encoder, &mut ())
                    .map_err(ProtocolError::malformed)?;
            }
        }
        AgentBrowserMutationResponseV2::ToolProposed { pending } => {
            encoder
                .array(2)
                .and_then(|encoder| encoder.u16(3))
                .map_err(ProtocolError::malformed)?;
            pending
                .encode(&mut encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
        }
        AgentBrowserMutationResponseV2::ToolDenied { code, trace } => {
            encoder
                .array(3)
                .and_then(|encoder| encoder.u16(4))
                .and_then(|encoder| encoder.u16(code.tag()))
                .map_err(ProtocolError::malformed)?;
            trace
                .encode(&mut encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
        }
        AgentBrowserMutationResponseV2::ToolOpenApproval { post, trace } => {
            encoder
                .array(3)
                .and_then(|encoder| encoder.u16(5))
                .map_err(ProtocolError::malformed)?;
            encode_post(&mut encoder, *post)?;
            trace
                .encode(&mut encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
        }
        AgentBrowserMutationResponseV2::ToolAuthorized { ticket, trace } => {
            encoder
                .array(3)
                .and_then(|encoder| encoder.u16(6))
                .map_err(ProtocolError::malformed)?;
            ticket
                .encode(&mut encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
            trace
                .encode(&mut encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
        }
        AgentBrowserMutationResponseV2::ExecutionDispatched { execution, state } => {
            encoder
                .array(3)
                .and_then(|encoder| encoder.u16(7))
                .map_err(ProtocolError::malformed)?;
            execution
                .encode(&mut encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
            state
                .encode(&mut encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
        }
        AgentBrowserMutationResponseV2::ReleaseOpenApproval { post } => {
            encoder
                .array(2)
                .and_then(|encoder| encoder.u16(8))
                .map_err(ProtocolError::malformed)?;
            encode_post(&mut encoder, *post)?;
        }
        AgentBrowserMutationResponseV2::ReleaseDispatched { release, state } => {
            encoder
                .array(3)
                .and_then(|encoder| encoder.u16(9))
                .map_err(ProtocolError::malformed)?;
            release
                .encode(&mut encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
            state
                .encode(&mut encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
        }
        AgentBrowserMutationResponseV2::VaultRevoked { state } => {
            encoder
                .array(2)
                .and_then(|encoder| encoder.u16(10))
                .map_err(ProtocolError::malformed)?;
            state
                .encode(&mut encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
        }
        AgentBrowserMutationResponseV2::SessionClosed { state } => {
            encoder
                .array(2)
                .and_then(|encoder| encoder.u16(11))
                .map_err(ProtocolError::malformed)?;
            state
                .encode(&mut encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
        }
        AgentBrowserMutationResponseV2::ExecutionRefreshed { execution, state } => {
            encoder
                .array(3)
                .and_then(|encoder| encoder.u16(12))
                .map_err(ProtocolError::malformed)?;
            execution
                .encode(&mut encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
            encode_execution_state(&mut encoder, *state)?;
        }
        AgentBrowserMutationResponseV2::ReleaseRefreshed { release, state } => {
            encoder
                .array(3)
                .and_then(|encoder| encoder.u16(13))
                .map_err(ProtocolError::malformed)?;
            release
                .encode(&mut encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
            encode_release_state(&mut encoder, *state)?;
        }
        AgentBrowserMutationResponseV2::ConnectorOpenApproval { pending, post } => {
            encoder
                .array(3)
                .and_then(|encoder| encoder.u16(14))
                .map_err(ProtocolError::malformed)?;
            pending
                .encode(&mut encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
            encode_post(&mut encoder, *post)?;
        }
        AgentBrowserMutationResponseV2::ConnectorRegistrationCommitted {
            pending,
            signed_delta_digest,
            head_digest,
            sequence,
            connector_id,
        } => {
            validate_committed_connector_response(
                *signed_delta_digest,
                *head_digest,
                *sequence,
                *connector_id,
            )?;
            encoder
                .array(6)
                .and_then(|encoder| encoder.u16(15))
                .map_err(ProtocolError::malformed)?;
            pending
                .encode(&mut encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
            signed_delta_digest
                .encode(&mut encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
            head_digest
                .encode(&mut encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
            encoder.u64(*sequence).map_err(ProtocolError::malformed)?;
            connector_id
                .encode(&mut encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
        }
        AgentBrowserMutationResponseV2::ConnectorRemovalCommitted {
            signed_delta_digest,
            head_digest,
            sequence,
            connector_id,
        } => {
            validate_committed_connector_response(
                *signed_delta_digest,
                *head_digest,
                *sequence,
                *connector_id,
            )?;
            encoder
                .array(5)
                .and_then(|encoder| encoder.u16(16))
                .map_err(ProtocolError::malformed)?;
            signed_delta_digest
                .encode(&mut encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
            head_digest
                .encode(&mut encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
            encoder.u64(*sequence).map_err(ProtocolError::malformed)?;
            connector_id
                .encode(&mut encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
        }
        AgentBrowserMutationResponseV2::ConnectorRegistrySnapshot { canonical_snapshot } => {
            encoder
                .array(2)
                .and_then(|encoder| encoder.u16(17))
                .and_then(|encoder| encoder.bytes(canonical_snapshot.as_bytes()))
                .map_err(ProtocolError::malformed)?;
        }
    }
    let bytes = encoder.into_writer();
    if bytes.len() > MAX_AGENT_BROWSER_BODY_BYTES_V2 {
        return Err(malformed());
    }
    Ok(bytes)
}

pub fn decode_agent_browser_mutation_response_v2(
    bytes: &[u8],
) -> Result<AgentBrowserMutationResponseV2, ProtocolError> {
    if bytes.is_empty() || bytes.len() > MAX_AGENT_BROWSER_BODY_BYTES_V2 {
        return Err(malformed());
    }
    let mut decoder = minicbor::Decoder::new(bytes);
    let count = decoder.array().map_err(ProtocolError::malformed)?;
    let tag = decoder.u16().map_err(ProtocolError::malformed)?;
    let mut context = V2DecodeContext;
    let value = match (tag, count) {
        (1, Some(2)) => AgentBrowserMutationResponseV2::FollowupOpenIngress {
            post: decode_post(&mut decoder, &mut context)?,
        },
        (2, Some(2)) => {
            let length = decoder
                .array()
                .map_err(ProtocolError::malformed)?
                .ok_or_else(malformed)?;
            if length > 256 {
                return Err(malformed());
            }
            let mut steps = Vec::with_capacity(usize::try_from(length).map_err(|_| malformed())?);
            for _ in 0..length {
                steps.push(
                    minicbor::Decode::decode(&mut decoder, &mut context)
                        .map_err(ProtocolError::from_typed_decode)?,
                );
            }
            AgentBrowserMutationResponseV2::PlannerCommitted { steps }
        }
        (3, Some(2)) => AgentBrowserMutationResponseV2::ToolProposed {
            pending: minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?,
        },
        (4, Some(3)) => AgentBrowserMutationResponseV2::ToolDenied {
            code: PublicStableCodeV2::from_tag(decoder.u16().map_err(ProtocolError::malformed)?)?,
            trace: minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?,
        },
        (5, Some(3)) => AgentBrowserMutationResponseV2::ToolOpenApproval {
            post: decode_post(&mut decoder, &mut context)?,
            trace: minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?,
        },
        (6, Some(3)) => AgentBrowserMutationResponseV2::ToolAuthorized {
            ticket: minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?,
            trace: minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?,
        },
        (7, Some(3)) => AgentBrowserMutationResponseV2::ExecutionDispatched {
            execution: minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?,
            state: minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?,
        },
        (8, Some(2)) => AgentBrowserMutationResponseV2::ReleaseOpenApproval {
            post: decode_post(&mut decoder, &mut context)?,
        },
        (9, Some(3)) => AgentBrowserMutationResponseV2::ReleaseDispatched {
            release: minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?,
            state: minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?,
        },
        (10, Some(2)) => AgentBrowserMutationResponseV2::VaultRevoked {
            state: minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?,
        },
        (11, Some(2)) => AgentBrowserMutationResponseV2::SessionClosed {
            state: minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?,
        },
        (12, Some(3)) => AgentBrowserMutationResponseV2::ExecutionRefreshed {
            execution: minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?,
            state: decode_execution_state(&mut decoder, &mut context)?,
        },
        (13, Some(3)) => AgentBrowserMutationResponseV2::ReleaseRefreshed {
            release: minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?,
            state: decode_release_state(&mut decoder, &mut context)?,
        },
        (14, Some(3)) => AgentBrowserMutationResponseV2::ConnectorOpenApproval {
            pending: minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?,
            post: decode_post(&mut decoder, &mut context)?,
        },
        (15, Some(6)) => {
            let pending = minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?;
            let signed_delta_digest = minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?;
            let head_digest = minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?;
            let sequence = decoder.u64().map_err(ProtocolError::malformed)?;
            let connector_id = minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?;
            validate_committed_connector_response(
                signed_delta_digest,
                head_digest,
                sequence,
                connector_id,
            )?;
            AgentBrowserMutationResponseV2::ConnectorRegistrationCommitted {
                pending,
                signed_delta_digest,
                head_digest,
                sequence,
                connector_id,
            }
        }
        (16, Some(5)) => {
            let signed_delta_digest = minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?;
            let head_digest = minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?;
            let sequence = decoder.u64().map_err(ProtocolError::malformed)?;
            let connector_id = minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?;
            validate_committed_connector_response(
                signed_delta_digest,
                head_digest,
                sequence,
                connector_id,
            )?;
            AgentBrowserMutationResponseV2::ConnectorRemovalCommitted {
                signed_delta_digest,
                head_digest,
                sequence,
                connector_id,
            }
        }
        (17, Some(2)) => AgentBrowserMutationResponseV2::ConnectorRegistrySnapshot {
            canonical_snapshot: BoundedConnectorRegistrySnapshotV2::new(
                decoder.bytes().map_err(ProtocolError::malformed)?.to_vec(),
            )?,
        },
        _ => return Err(malformed()),
    };
    if decoder.position() != bytes.len()
        || encode_agent_browser_mutation_response_v2(&value)? != bytes
    {
        return Err(noncanonical());
    }
    Ok(value)
}

fn encode_post(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    post: FixedBrowserFormPostCarrierV2,
) -> Result<(), ProtocolError> {
    encoder.array(2).map_err(ProtocolError::malformed)?;
    match post {
        FixedBrowserFormPostCarrierV2::AgentFollowupIngress(transfer) => {
            encoder.u16(7).map_err(ProtocolError::malformed)?;
            transfer
                .encode(encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
        }
        FixedBrowserFormPostCarrierV2::AgentApprovalDisplay(transfer) => {
            encoder.u16(8).map_err(ProtocolError::malformed)?;
            transfer
                .encode(encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
        }
    }
    Ok(())
}

fn decode_post(
    decoder: &mut minicbor::Decoder<'_>,
    context: &mut V2DecodeContext,
) -> Result<FixedBrowserFormPostCarrierV2, ProtocolError> {
    if decoder.array().map_err(ProtocolError::malformed)? != Some(2) {
        return Err(malformed());
    }
    match decoder.u16().map_err(ProtocolError::malformed)? {
        7 => Ok(FixedBrowserFormPostCarrierV2::AgentFollowupIngress(
            minicbor::Decode::decode(decoder, context).map_err(ProtocolError::from_typed_decode)?,
        )),
        8 => Ok(FixedBrowserFormPostCarrierV2::AgentApprovalDisplay(
            minicbor::Decode::decode(decoder, context).map_err(ProtocolError::from_typed_decode)?,
        )),
        _ => Err(malformed()),
    }
}

fn encode_object(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    object: AgentBrowserObjectRefV2,
) -> Result<(), ProtocolError> {
    encoder.array(2).map_err(ProtocolError::malformed)?;
    let (tag, encoded) = match object {
        AgentBrowserObjectRefV2::Document(value) => (1, minicbor::to_vec(value)),
        AgentBrowserObjectRefV2::PlanStep(value) => (2, minicbor::to_vec(value)),
        AgentBrowserObjectRefV2::PendingToolCall(value) => (3, minicbor::to_vec(value)),
        AgentBrowserObjectRefV2::ExecutionTicket(value) => (4, minicbor::to_vec(value)),
        AgentBrowserObjectRefV2::ReleaseTicket(value) => (5, minicbor::to_vec(value)),
        AgentBrowserObjectRefV2::Execution(value) => (6, minicbor::to_vec(value)),
        AgentBrowserObjectRefV2::Release(value) => (7, minicbor::to_vec(value)),
    };
    encoder.u16(tag).map_err(ProtocolError::malformed)?;
    let encoded = encoded.map_err(ProtocolError::malformed)?;
    encoder.writer_mut().extend_from_slice(&encoded);
    Ok(())
}

fn decode_object(
    decoder: &mut minicbor::Decoder<'_>,
    context: &mut V2DecodeContext,
) -> Result<AgentBrowserObjectRefV2, ProtocolError> {
    if decoder.array().map_err(ProtocolError::malformed)? != Some(2) {
        return Err(malformed());
    }
    let tag = decoder.u16().map_err(ProtocolError::malformed)?;
    macro_rules! decode_variant {
        ($variant:ident) => {
            AgentBrowserObjectRefV2::$variant(
                minicbor::Decode::decode(decoder, context)
                    .map_err(ProtocolError::from_typed_decode)?,
            )
        };
    }
    match tag {
        1 => Ok(decode_variant!(Document)),
        2 => Ok(decode_variant!(PlanStep)),
        3 => Ok(decode_variant!(PendingToolCall)),
        4 => Ok(decode_variant!(ExecutionTicket)),
        5 => Ok(decode_variant!(ReleaseTicket)),
        6 => Ok(decode_variant!(Execution)),
        7 => Ok(decode_variant!(Release)),
        _ => Err(malformed()),
    }
}

fn encode_execution_state(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    state: AgentBrowserExecutionStateV2,
) -> Result<(), ProtocolError> {
    match state {
        AgentBrowserExecutionStateV2::Prepared => encode_unit_state(encoder, 1),
        AgentBrowserExecutionStateV2::Dispatching => encode_unit_state(encoder, 2),
        AgentBrowserExecutionStateV2::ResultGatePending => encode_unit_state(encoder, 3),
        AgentBrowserExecutionStateV2::Succeeded { document } => {
            encoder
                .array(2)
                .and_then(|encoder| encoder.u16(4))
                .map_err(ProtocolError::malformed)?;
            document
                .encode(encoder, &mut ())
                .map_err(ProtocolError::malformed)
        }
        AgentBrowserExecutionStateV2::EffectSucceededOutputQuarantined { class } => {
            encoder
                .array(2)
                .and_then(|encoder| encoder.u16(5))
                .map_err(ProtocolError::malformed)?;
            class
                .encode(encoder, &mut ())
                .map_err(ProtocolError::malformed)
        }
        AgentBrowserExecutionStateV2::FailedNoEffect { class } => {
            encoder
                .array(2)
                .and_then(|encoder| encoder.u16(6))
                .map_err(ProtocolError::malformed)?;
            class
                .encode(encoder, &mut ())
                .map_err(ProtocolError::malformed)
        }
        AgentBrowserExecutionStateV2::Indeterminate => encode_unit_state(encoder, 7),
    }
}

fn decode_execution_state(
    decoder: &mut minicbor::Decoder<'_>,
    context: &mut V2DecodeContext,
) -> Result<AgentBrowserExecutionStateV2, ProtocolError> {
    let count = decoder.array().map_err(ProtocolError::malformed)?;
    let tag = decoder.u16().map_err(ProtocolError::malformed)?;
    match (tag, count) {
        (1, Some(1)) => Ok(AgentBrowserExecutionStateV2::Prepared),
        (2, Some(1)) => Ok(AgentBrowserExecutionStateV2::Dispatching),
        (3, Some(1)) => Ok(AgentBrowserExecutionStateV2::ResultGatePending),
        (4, Some(2)) => Ok(AgentBrowserExecutionStateV2::Succeeded {
            document: minicbor::Decode::decode(decoder, context)
                .map_err(ProtocolError::from_typed_decode)?,
        }),
        (5, Some(2)) => Ok(
            AgentBrowserExecutionStateV2::EffectSucceededOutputQuarantined {
                class: minicbor::Decode::decode(decoder, context)
                    .map_err(ProtocolError::from_typed_decode)?,
            },
        ),
        (6, Some(2)) => Ok(AgentBrowserExecutionStateV2::FailedNoEffect {
            class: minicbor::Decode::decode(decoder, context)
                .map_err(ProtocolError::from_typed_decode)?,
        }),
        (7, Some(1)) => Ok(AgentBrowserExecutionStateV2::Indeterminate),
        _ => Err(malformed()),
    }
}

fn encode_release_state(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    state: AgentBrowserReleaseStateV2,
) -> Result<(), ProtocolError> {
    match state {
        AgentBrowserReleaseStateV2::Prepared => encode_unit_state(encoder, 1),
        AgentBrowserReleaseStateV2::Dispatching => encode_unit_state(encoder, 2),
        AgentBrowserReleaseStateV2::Succeeded => encode_unit_state(encoder, 3),
        AgentBrowserReleaseStateV2::EffectSucceededOutputQuarantined { class } => {
            encoder
                .array(2)
                .and_then(|encoder| encoder.u16(4))
                .map_err(ProtocolError::malformed)?;
            class
                .encode(encoder, &mut ())
                .map_err(ProtocolError::malformed)
        }
        AgentBrowserReleaseStateV2::FailedNoEffect { class } => {
            encoder
                .array(2)
                .and_then(|encoder| encoder.u16(5))
                .map_err(ProtocolError::malformed)?;
            class
                .encode(encoder, &mut ())
                .map_err(ProtocolError::malformed)
        }
        AgentBrowserReleaseStateV2::Indeterminate => encode_unit_state(encoder, 6),
    }
}

fn decode_release_state(
    decoder: &mut minicbor::Decoder<'_>,
    context: &mut V2DecodeContext,
) -> Result<AgentBrowserReleaseStateV2, ProtocolError> {
    let count = decoder.array().map_err(ProtocolError::malformed)?;
    let tag = decoder.u16().map_err(ProtocolError::malformed)?;
    match (tag, count) {
        (1, Some(1)) => Ok(AgentBrowserReleaseStateV2::Prepared),
        (2, Some(1)) => Ok(AgentBrowserReleaseStateV2::Dispatching),
        (3, Some(1)) => Ok(AgentBrowserReleaseStateV2::Succeeded),
        (4, Some(2)) => Ok(
            AgentBrowserReleaseStateV2::EffectSucceededOutputQuarantined {
                class: minicbor::Decode::decode(decoder, context)
                    .map_err(ProtocolError::from_typed_decode)?,
            },
        ),
        (5, Some(2)) => Ok(AgentBrowserReleaseStateV2::FailedNoEffect {
            class: minicbor::Decode::decode(decoder, context)
                .map_err(ProtocolError::from_typed_decode)?,
        }),
        (6, Some(1)) => Ok(AgentBrowserReleaseStateV2::Indeterminate),
        _ => Err(malformed()),
    }
}

fn encode_unit_state(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    tag: u16,
) -> Result<(), ProtocolError> {
    encoder
        .array(1)
        .and_then(|encoder| encoder.u16(tag))
        .map(|_| ())
        .map_err(ProtocolError::malformed)
}

fn encode_action(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    value: AgentBrowserActionV2,
) -> Result<(), ProtocolError> {
    if let AgentBrowserActionV2::RegisterConnector(descriptor) = &value {
        if descriptor.is_empty() || descriptor.len() > MAX_AGENT_BROWSER_BODY_BYTES_V2 - 128 {
            return Err(malformed());
        }
        encoder
            .array(2)
            .and_then(|encoder| encoder.u16(12))
            .and_then(|encoder| encoder.bytes(descriptor))
            .map_err(ProtocolError::malformed)?;
        return Ok(());
    }
    if let AgentBrowserActionV2::RemoveConnector(connector_id) = &value {
        if is_zero(connector_id.as_bytes()) {
            return Err(malformed());
        }
    }
    let (tag, handle) = match value {
        AgentBrowserActionV2::PrepareFollowupIngress => (1, None),
        AgentBrowserActionV2::RunPlanner => (2, None),
        AgentBrowserActionV2::RunPlannerWithThirdPartyMapper => (16, None),
        AgentBrowserActionV2::ProposePlanStep(value) => (
            3,
            Some(minicbor::to_vec(value).map_err(ProtocolError::malformed)?),
        ),
        AgentBrowserActionV2::EvaluatePending(value) => (
            4,
            Some(minicbor::to_vec(value).map_err(ProtocolError::malformed)?),
        ),
        AgentBrowserActionV2::DispatchTicket(value) => (
            5,
            Some(minicbor::to_vec(value).map_err(ProtocolError::malformed)?),
        ),
        AgentBrowserActionV2::PrepareRelease(value) => (
            6,
            Some(minicbor::to_vec(value).map_err(ProtocolError::malformed)?),
        ),
        AgentBrowserActionV2::DispatchRelease(value) => (
            7,
            Some(minicbor::to_vec(value).map_err(ProtocolError::malformed)?),
        ),
        AgentBrowserActionV2::RevokeVault(value) => (
            8,
            Some(minicbor::to_vec(value).map_err(ProtocolError::malformed)?),
        ),
        AgentBrowserActionV2::CloseSession => (9, None),
        AgentBrowserActionV2::RefreshExecution(value) => (
            10,
            Some(minicbor::to_vec(value).map_err(ProtocolError::malformed)?),
        ),
        AgentBrowserActionV2::RefreshRelease(value) => (
            11,
            Some(minicbor::to_vec(value).map_err(ProtocolError::malformed)?),
        ),
        AgentBrowserActionV2::RegisterConnector(_) => unreachable!("handled above"),
        AgentBrowserActionV2::FinalizeConnectorRegistration(value) => (
            13,
            Some(minicbor::to_vec(value).map_err(ProtocolError::malformed)?),
        ),
        AgentBrowserActionV2::RemoveConnector(value) => (
            14,
            Some(minicbor::to_vec(value).map_err(ProtocolError::malformed)?),
        ),
        AgentBrowserActionV2::SnapshotConnectors => (15, None),
    };
    encoder
        .array(if handle.is_some() { 2 } else { 1 })
        .and_then(|encoder| encoder.u16(tag))
        .map_err(ProtocolError::malformed)?;
    if let Some(handle) = handle {
        let mut decoder = minicbor::Decoder::new(&handle);
        decoder.skip().map_err(ProtocolError::malformed)?;
        encoder.writer_mut().extend_from_slice(&handle);
    }
    Ok(())
}

fn decode_action(
    decoder: &mut minicbor::Decoder<'_>,
    context: &mut V2DecodeContext,
) -> Result<AgentBrowserActionV2, ProtocolError> {
    let count = decoder.array().map_err(ProtocolError::malformed)?;
    let tag = decoder.u16().map_err(ProtocolError::malformed)?;
    match (tag, count) {
        (1, Some(1)) => Ok(AgentBrowserActionV2::PrepareFollowupIngress),
        (2, Some(1)) => Ok(AgentBrowserActionV2::RunPlanner),
        (16, Some(1)) => Ok(AgentBrowserActionV2::RunPlannerWithThirdPartyMapper),
        (3, Some(2)) => Ok(AgentBrowserActionV2::ProposePlanStep(
            minicbor::Decode::decode(decoder, context).map_err(ProtocolError::from_typed_decode)?,
        )),
        (4, Some(2)) => Ok(AgentBrowserActionV2::EvaluatePending(
            minicbor::Decode::decode(decoder, context).map_err(ProtocolError::from_typed_decode)?,
        )),
        (5, Some(2)) => Ok(AgentBrowserActionV2::DispatchTicket(
            minicbor::Decode::decode(decoder, context).map_err(ProtocolError::from_typed_decode)?,
        )),
        (6, Some(2)) => Ok(AgentBrowserActionV2::PrepareRelease(
            minicbor::Decode::decode(decoder, context).map_err(ProtocolError::from_typed_decode)?,
        )),
        (7, Some(2)) => Ok(AgentBrowserActionV2::DispatchRelease(
            minicbor::Decode::decode(decoder, context).map_err(ProtocolError::from_typed_decode)?,
        )),
        (8, Some(2)) => Ok(AgentBrowserActionV2::RevokeVault(
            minicbor::Decode::decode(decoder, context).map_err(ProtocolError::from_typed_decode)?,
        )),
        (9, Some(1)) => Ok(AgentBrowserActionV2::CloseSession),
        (10, Some(2)) => Ok(AgentBrowserActionV2::RefreshExecution(
            minicbor::Decode::decode(decoder, context).map_err(ProtocolError::from_typed_decode)?,
        )),
        (11, Some(2)) => Ok(AgentBrowserActionV2::RefreshRelease(
            minicbor::Decode::decode(decoder, context).map_err(ProtocolError::from_typed_decode)?,
        )),
        (12, Some(2)) => {
            let descriptor = decoder.bytes().map_err(ProtocolError::malformed)?.to_vec();
            if descriptor.is_empty() || descriptor.len() > MAX_AGENT_BROWSER_BODY_BYTES_V2 - 128 {
                return Err(malformed());
            }
            Ok(AgentBrowserActionV2::RegisterConnector(descriptor))
        }
        (13, Some(2)) => Ok(AgentBrowserActionV2::FinalizeConnectorRegistration(
            minicbor::Decode::decode(decoder, context).map_err(ProtocolError::from_typed_decode)?,
        )),
        (14, Some(2)) => {
            let connector_id: Digest32V2 = minicbor::Decode::decode(decoder, context)
                .map_err(ProtocolError::from_typed_decode)?;
            if is_zero(connector_id.as_bytes()) {
                return Err(malformed());
            }
            Ok(AgentBrowserActionV2::RemoveConnector(connector_id))
        }
        (15, Some(1)) => Ok(AgentBrowserActionV2::SnapshotConnectors),
        _ => Err(malformed()),
    }
}

fn encode_optional<T: minicbor::Encode<()>>(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    value: Option<T>,
) -> Result<(), ProtocolError> {
    match value {
        Some(value) => {
            encoder.array(1).map_err(ProtocolError::malformed)?;
            value
                .encode(encoder, &mut ())
                .map_err(ProtocolError::malformed)
        }
        None => encoder
            .array(0)
            .map(|_| ())
            .map_err(ProtocolError::malformed),
    }
}

fn decode_optional<'bytes, T>(
    decoder: &mut minicbor::Decoder<'bytes>,
    context: &mut V2DecodeContext,
) -> Result<Option<T>, ProtocolError>
where
    T: minicbor::Decode<'bytes, V2DecodeContext>,
{
    match decoder.array().map_err(ProtocolError::malformed)? {
        Some(0) => Ok(None),
        Some(1) => minicbor::Decode::decode(decoder, context)
            .map(Some)
            .map_err(ProtocolError::from_typed_decode),
        _ => Err(malformed()),
    }
}

fn validate_committed_connector_response(
    signed_delta_digest: Digest32V2,
    head_digest: Digest32V2,
    sequence: u64,
    connector_id: Digest32V2,
) -> Result<(), ProtocolError> {
    if is_zero(signed_delta_digest.as_bytes())
        || is_zero(head_digest.as_bytes())
        || sequence == 0
        || is_zero(connector_id.as_bytes())
    {
        return Err(malformed());
    }
    Ok(())
}

fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

fn validate_body(bytes: &[u8]) -> Result<(), ProtocolError> {
    if bytes.is_empty() || bytes.len() > MAX_AGENT_BROWSER_BODY_BYTES_V2 {
        Err(malformed())
    } else {
        Ok(())
    }
}

fn malformed() -> ProtocolError {
    ProtocolError::stable(StableCode::ProtocolMalformedCbor)
}

fn noncanonical() -> ProtocolError {
    ProtocolError::stable(StableCode::ProtocolNonCanonicalCbor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_view_request_is_canonical_and_closed() {
        let request = AgentBrowserRequestV2::ReadView {
            tab: AgentTabSessionCapabilityV2::from_authority_entropy([1; 32]).unwrap(),
            client_request_nonce: Nonce32V2::new([2; 32]),
            document: AgentMaskedDocumentRefV2::from_authority_entropy([3; 16]).unwrap(),
            cursor: None,
            maximum_encoded_bytes: 4096,
        };
        let encoded = encode_agent_browser_request_v2(request.clone()).unwrap();
        assert_eq!(decode_agent_browser_request_v2(&encoded).unwrap(), request);
        let mut trailing = encoded;
        trailing.push(0);
        assert!(decode_agent_browser_request_v2(&trailing).is_err());
    }

    #[test]
    fn connector_registration_is_a_descriptor_only_authenticated_tab_action() {
        let descriptor = vec![0x87, 0x01, 0x02, 0x03];
        let request = AgentBrowserRequestV2::Act {
            tab: AgentTabSessionCapabilityV2::from_authority_entropy([4; 32]).unwrap(),
            client_request_nonce: Nonce32V2::new([5; 32]),
            action: AgentBrowserActionV2::RegisterConnector(descriptor.clone()),
        };
        let encoded = encode_agent_browser_request_v2(request.clone()).unwrap();
        assert_eq!(decode_agent_browser_request_v2(&encoded).unwrap(), request);

        let mut decoder = minicbor::Decoder::new(&encoded);
        assert_eq!(decoder.array().unwrap(), Some(4));
        assert_eq!(decoder.u16().unwrap(), 2);
        decoder.skip().unwrap();
        decoder.skip().unwrap();
        assert_eq!(decoder.array().unwrap(), Some(2));
        assert_eq!(decoder.u16().unwrap(), 12);
        assert_eq!(decoder.bytes().unwrap(), descriptor);
        assert_eq!(decoder.position(), encoded.len());

        assert!(encode_agent_browser_request_v2(AgentBrowserRequestV2::Act {
            tab: AgentTabSessionCapabilityV2::from_authority_entropy([4; 32]).unwrap(),
            client_request_nonce: Nonce32V2::new([5; 32]),
            action: AgentBrowserActionV2::RegisterConnector(Vec::new()),
        })
        .is_err());
    }

    #[test]
    fn agent_browser_responses_round_trip_canonically_and_reject_trailing_data() {
        let authentication = AgentUiAuthenticationCompleteBrowserResponseV2::new(
            AgentTabSessionCapabilityV2::from_authority_entropy([6; 32]).unwrap(),
            AgentMaskedDocumentRefV2::from_authority_entropy([7; 16]).unwrap(),
        );
        let bytes =
            encode_agent_ui_authentication_complete_browser_response_v2(authentication).unwrap();
        let decoded = decode_agent_ui_authentication_complete_browser_response_v2(&bytes).unwrap();
        assert_eq!(
            encode_agent_ui_authentication_complete_browser_response_v2(decoded).unwrap(),
            bytes
        );
        let mut noncanonical = vec![0x98, 0x02];
        noncanonical.extend_from_slice(&bytes[1..]);
        assert!(
            decode_agent_ui_authentication_complete_browser_response_v2(&noncanonical).is_err()
        );
        let mut trailing = bytes;
        trailing.push(0);
        assert!(decode_agent_ui_authentication_complete_browser_response_v2(&trailing).is_err());

        let view = AgentBrowserReadViewResponseV2::new(
            AgentViewV2::ContentState(super::super::AgentContentStateV2::Ready),
            vec![AgentBrowserObjectRefV2::Document(
                AgentMaskedDocumentRefV2::from_authority_entropy([8; 16]).unwrap(),
            )],
            Some(AgentBrowserViewCursorCapabilityV2::from_authority_entropy([9; 16]).unwrap()),
        )
        .unwrap();
        let bytes = encode_agent_browser_read_view_response_v2(&view).unwrap();
        let decoded = decode_agent_browser_read_view_response_v2(&bytes).unwrap();
        assert_eq!(
            encode_agent_browser_read_view_response_v2(&decoded).unwrap(),
            bytes
        );
        let mut trailing = bytes;
        trailing.push(0);
        assert!(decode_agent_browser_read_view_response_v2(&trailing).is_err());
    }
}
