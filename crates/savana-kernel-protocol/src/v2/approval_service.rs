use minicbor::{Decode as _, Encode as _};

use crate::{ProtocolError, StableCode};

use super::{
    cbor::V2DecodeContext, decode_signed_agent_authentication_closure_descriptor_v2,
    decode_signed_approval_envelope_v2, decode_signed_approval_settlement_v2,
    decode_signed_ui_authentication_envelope_v2, decode_signed_ui_authentication_settlement_v2,
    encode_signed_agent_authentication_closure_descriptor_v2, encode_signed_approval_envelope_v2,
    encode_signed_approval_settlement_v2, encode_signed_ui_authentication_envelope_v2,
    encode_signed_ui_authentication_settlement_v2,
    AgentUiAuthenticationSettlementTransferCapabilityV2, AgentUiAuthenticationTransferCapabilityV2,
    ApprovalDisplayAuthenticationTransferCapabilityV2, ApprovalUiRecordHandleV2,
    ConnectorApprovalRecordHandleV2, Digest32V2, EndpointRoleV2, EnrollmentHandleV2,
    EnrollmentProfileIdV2, IngressApprovalRecordHandleV2,
    IngressUiAuthenticationSettlementTransferCapabilityV2,
    IngressUiAuthenticationTransferCapabilityV2, Nonce32V2, PublicServiceStateV2,
    ReleaseApprovalRecordHandleV2, RequestIdV2, SignedAgentAuthenticationClosureDescriptorV2,
    SignedApprovalEnvelopeV2, SignedApprovalSettlementV2, SignedUiAuthenticationEnvelopeV2,
    SignedUiAuthenticationSettlementV2, TaskAuthorizationApprovalRecordHandleV2,
    ToolApprovalRecordHandleV2, UnixMillisV2, ZeroizingTextV2, PROTOCOL_MAJOR, PROTOCOL_MINOR,
};

const MAX_APPROVAL_SERVICE_BYTES_V2: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
// The large closure descriptor is intentionally inline: all variants are
// already hard-bounded wire values and boxing would add a second, fallible
// allocation to the authenticated decode path.
#[allow(clippy::large_enum_variant)]
pub enum ApprovalServiceOperationV2 {
    AgentHealth,
    IngressHealth,
    AdminHealth,
    KernelHealth,
    RegisterPrivateSessionV04 {
        envelope: SignedUiAuthenticationEnvelopeV2,
    },
    GetPrivateSessionAuthenticationV04 {
        record: ApprovalUiRecordHandleV2,
    },
    AttachPrivateApprovalV04 {
        session: ApprovalUiRecordHandleV2,
        approval: ToolApprovalRecordHandleV2,
        root: Digest32V2,
    },
    AttachPrivateReleaseApprovalV04 {
        session: ApprovalUiRecordHandleV2,
        approval: ReleaseApprovalRecordHandleV2,
        root: Digest32V2,
    },
    GetKernelReleaseApprovalSettlement {
        approval: ReleaseApprovalRecordHandleV2,
    },
    AttachPrivatePublicationV04 {
        session: ApprovalUiRecordHandleV2,
        publication: super::PrivatePublicationV04,
    },
    RegisterKernelApproval {
        envelope: SignedApprovalEnvelopeV2,
        display_authentication: SignedUiAuthenticationEnvelopeV2,
    },
    GetKernelApprovalSettlement {
        approval: ToolApprovalRecordHandleV2,
    },
    RegisterAgentApproval {
        envelope: SignedApprovalEnvelopeV2,
        display_authentication: SignedUiAuthenticationEnvelopeV2,
    },
    GetAgentApprovalSettlement {
        approval: AgentApprovalRecordTargetV2,
    },
    RegisterIngressApproval {
        envelope: SignedApprovalEnvelopeV2,
        display_authentication: SignedUiAuthenticationEnvelopeV2,
    },
    GetIngressApprovalSettlement {
        approval: IngressApprovalRecordHandleV2,
    },
    GetTaskAuthorizationApprovalSettlement {
        approval: TaskAuthorizationApprovalRecordHandleV2,
    },
    RegisterAgentUiAuthentication {
        envelope: SignedUiAuthenticationEnvelopeV2,
    },
    ConsumeAgentUiAuthenticationSettlement {
        record: ApprovalUiRecordHandleV2,
        transfer: AgentUiAuthenticationSettlementTransferCapabilityV2,
    },
    CloseAgentAuthenticationAttempt {
        descriptor: SignedAgentAuthenticationClosureDescriptorV2,
    },
    RegisterIngressUiAuthentication {
        envelope: SignedUiAuthenticationEnvelopeV2,
    },
    ConsumeIngressUiAuthenticationSettlement {
        record: ApprovalUiRecordHandleV2,
        transfer: IngressUiAuthenticationSettlementTransferCapabilityV2,
    },
    CreateEnrollmentCode {
        enrollment_profile: EnrollmentProfileIdV2,
        client_request_nonce: Nonce32V2,
    },
    RevokeCredential {
        credential_digest: Digest32V2,
        reason: ClosedCredentialRevocationReasonV2,
    },
}

impl ApprovalServiceOperationV2 {
    pub const fn role(&self) -> EndpointRoleV2 {
        match self {
            Self::KernelHealth
            | Self::RegisterPrivateSessionV04 { .. }
            | Self::GetPrivateSessionAuthenticationV04 { .. }
            | Self::AttachPrivateApprovalV04 { .. }
            | Self::AttachPrivateReleaseApprovalV04 { .. }
            | Self::AttachPrivatePublicationV04 { .. }
            | Self::GetKernelReleaseApprovalSettlement { .. }
            | Self::RegisterKernelApproval { .. }
            | Self::GetKernelApprovalSettlement { .. } => EndpointRoleV2::KernelApproval,
            Self::AgentHealth
            | Self::RegisterAgentApproval { .. }
            | Self::GetAgentApprovalSettlement { .. }
            | Self::RegisterAgentUiAuthentication { .. }
            | Self::ConsumeAgentUiAuthenticationSettlement { .. }
            | Self::CloseAgentAuthenticationAttempt { .. } => EndpointRoleV2::AgentApproval,
            Self::IngressHealth
            | Self::RegisterIngressApproval { .. }
            | Self::GetIngressApprovalSettlement { .. }
            | Self::GetTaskAuthorizationApprovalSettlement { .. }
            | Self::RegisterIngressUiAuthentication { .. }
            | Self::ConsumeIngressUiAuthenticationSettlement { .. } => {
                EndpointRoleV2::IngressApproval
            }
            Self::AdminHealth
            | Self::CreateEnrollmentCode { .. }
            | Self::RevokeCredential { .. } => EndpointRoleV2::ApprovalAdmin,
        }
    }

    pub const fn tag(&self) -> u16 {
        match self {
            Self::AgentHealth | Self::IngressHealth | Self::AdminHealth | Self::KernelHealth => 0,
            Self::RegisterPrivateSessionV04 { .. } => 22,
            Self::GetPrivateSessionAuthenticationV04 { .. } => 23,
            Self::AttachPrivateApprovalV04 { .. } => 24,
            Self::AttachPrivateReleaseApprovalV04 { .. } => 25,
            Self::GetKernelReleaseApprovalSettlement { .. } => 26,
            Self::AttachPrivatePublicationV04 { .. } => 27,
            Self::RegisterAgentApproval { .. }
            | Self::RegisterIngressApproval { .. }
            | Self::RegisterKernelApproval { .. } => 20,
            Self::GetAgentApprovalSettlement { .. }
            | Self::GetIngressApprovalSettlement { .. }
            | Self::GetKernelApprovalSettlement { .. } => 21,
            Self::RegisterAgentUiAuthentication { .. }
            | Self::RegisterIngressUiAuthentication { .. } => 22,
            Self::ConsumeAgentUiAuthenticationSettlement { .. }
            | Self::ConsumeIngressUiAuthenticationSettlement { .. } => 23,
            Self::CloseAgentAuthenticationAttempt { .. } => 24,
            Self::GetTaskAuthorizationApprovalSettlement { .. } => 25,
            Self::CreateEnrollmentCode { .. } => 100,
            Self::RevokeCredential { .. } => 101,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClosedCredentialRevocationReasonV2 {
    Compromised,
    Replaced,
    Administrator,
}

impl ClosedCredentialRevocationReasonV2 {
    pub const fn tag(self) -> u16 {
        match self {
            Self::Compromised => 1,
            Self::Replaced => 2,
            Self::Administrator => 3,
        }
    }
}

impl<C> minicbor::Encode<C> for ClosedCredentialRevocationReasonV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        _context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.array(1)?.u16(self.tag())?;
        Ok(())
    }
}

impl<'bytes> minicbor::Decode<'bytes, V2DecodeContext> for ClosedCredentialRevocationReasonV2 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        _context: &mut V2DecodeContext,
    ) -> Result<Self, minicbor::decode::Error> {
        let position = decoder.position();
        if decoder.array()? != Some(1) {
            return Err(typed_malformed(position));
        }
        match decoder.u16()? {
            1 => Ok(Self::Compromised),
            2 => Ok(Self::Replaced),
            3 => Ok(Self::Administrator),
            _ => Err(typed_malformed(position)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialPublicStateV2 {
    Active,
    Revoked,
}

impl CredentialPublicStateV2 {
    pub const fn tag(self) -> u16 {
        match self {
            Self::Active => 1,
            Self::Revoked => 2,
        }
    }
}

impl<C> minicbor::Encode<C> for CredentialPublicStateV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        _context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.array(1)?.u16(self.tag())?;
        Ok(())
    }
}

impl<'bytes> minicbor::Decode<'bytes, V2DecodeContext> for CredentialPublicStateV2 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        _context: &mut V2DecodeContext,
    ) -> Result<Self, minicbor::decode::Error> {
        let position = decoder.position();
        if decoder.array()? != Some(1) {
            return Err(typed_malformed(position));
        }
        match decoder.u16()? {
            1 => Ok(Self::Active),
            2 => Ok(Self::Revoked),
            _ => Err(typed_malformed(position)),
        }
    }
}

pub struct CreateEnrollmentCodeResponseV2 {
    enrollment: EnrollmentHandleV2,
    code: ZeroizingTextV2,
    expires_at: UnixMillisV2,
}

impl core::fmt::Debug for CreateEnrollmentCodeResponseV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("CreateEnrollmentCodeResponseV2")
            .field("enrollment", &self.enrollment)
            .field("code", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl CreateEnrollmentCodeResponseV2 {
    pub fn new(
        enrollment: EnrollmentHandleV2,
        code: ZeroizingTextV2,
        expires_at: UnixMillisV2,
    ) -> Result<Self, ProtocolError> {
        if expires_at.get() == 0 {
            return Err(malformed());
        }
        Ok(Self {
            enrollment,
            code,
            expires_at,
        })
    }

    pub fn into_parts(self) -> (EnrollmentHandleV2, ZeroizingTextV2, UnixMillisV2) {
        (self.enrollment, self.code, self.expires_at)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevokeCredentialResponseV2 {
    state: CredentialPublicStateV2,
}

impl RevokeCredentialResponseV2 {
    pub const fn new(state: CredentialPublicStateV2) -> Self {
        Self { state }
    }

    pub const fn state(self) -> CredentialPublicStateV2 {
        self.state
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentApprovalRecordTargetV2 {
    Tool(ToolApprovalRecordHandleV2),
    Release(ReleaseApprovalRecordHandleV2),
    Connector(ConnectorApprovalRecordHandleV2),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisteredApprovalV2 {
    TaskAuthorization {
        approval: TaskAuthorizationApprovalRecordHandleV2,
        display_authentication: ApprovalDisplayAuthenticationTransferCapabilityV2,
    },
    Ingress {
        approval: IngressApprovalRecordHandleV2,
        display_authentication: ApprovalDisplayAuthenticationTransferCapabilityV2,
    },
    Tool {
        approval: ToolApprovalRecordHandleV2,
        display_authentication: ApprovalDisplayAuthenticationTransferCapabilityV2,
    },
    Release {
        approval: ReleaseApprovalRecordHandleV2,
        display_authentication: ApprovalDisplayAuthenticationTransferCapabilityV2,
    },
    Connector {
        approval: ConnectorApprovalRecordHandleV2,
        display_authentication: ApprovalDisplayAuthenticationTransferCapabilityV2,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalSettlementViewV2 {
    Pending,
    Denied {
        settlement: SignedApprovalSettlementV2,
    },
    Expired,
    Approved {
        settlement: SignedApprovalSettlementV2,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalServiceRequestV2 {
    role: EndpointRoleV2,
    request_id: RequestIdV2,
    deadline: UnixMillisV2,
    operation: ApprovalServiceOperationV2,
}

impl ApprovalServiceRequestV2 {
    pub fn new(
        request_id: RequestIdV2,
        deadline: UnixMillisV2,
        operation: ApprovalServiceOperationV2,
    ) -> Result<Self, ProtocolError> {
        if request_id.as_bytes() == &[0; 16] || deadline.get() == 0 {
            return Err(malformed());
        }
        Ok(Self {
            role: operation.role(),
            request_id,
            deadline,
            operation,
        })
    }

    pub const fn role(&self) -> EndpointRoleV2 {
        self.role
    }

    pub const fn request_id(&self) -> RequestIdV2 {
        self.request_id
    }

    pub const fn deadline(&self) -> UnixMillisV2 {
        self.deadline
    }

    pub const fn operation(&self) -> &ApprovalServiceOperationV2 {
        &self.operation
    }

    pub fn into_operation(self) -> ApprovalServiceOperationV2 {
        self.operation
    }
}

pub fn encode_approval_service_request_v2(
    value: &ApprovalServiceRequestV2,
) -> Result<Vec<u8>, ProtocolError> {
    if value.role != value.operation.role() {
        return Err(malformed());
    }
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(6)
        .and_then(|encoder| encoder.array(2))
        .and_then(|encoder| encoder.u16(PROTOCOL_MAJOR))
        .and_then(|encoder| encoder.u16(PROTOCOL_MINOR))
        .map_err(ProtocolError::malformed)?;
    value
        .role
        .encode(&mut encoder, &mut ())
        .map_err(ProtocolError::malformed)?;
    encoder
        .bytes(value.request_id.as_bytes())
        .and_then(|encoder| encoder.u64(value.deadline.get()))
        .and_then(|encoder| encoder.u16(value.operation.tag()))
        .map_err(ProtocolError::malformed)?;
    let body = encode_operation_body(&value.operation)?;
    let mut bytes = encoder.into_writer();
    bytes.extend_from_slice(&body);
    validate_size(&bytes)?;
    Ok(bytes)
}

pub fn decode_approval_service_request_v2(
    bytes: &[u8],
    expected_role: EndpointRoleV2,
    expected_tag: u16,
) -> Result<ApprovalServiceRequestV2, ProtocolError> {
    validate_size(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    if decoder.array().map_err(ProtocolError::malformed)? != Some(6)
        || decoder.array().map_err(ProtocolError::malformed)? != Some(2)
        || decoder.u16().map_err(ProtocolError::malformed)? != PROTOCOL_MAJOR
        || decoder.u16().map_err(ProtocolError::malformed)? != PROTOCOL_MINOR
    {
        return Err(malformed());
    }
    let mut context = V2DecodeContext;
    let role = EndpointRoleV2::decode(&mut decoder, &mut context)
        .map_err(ProtocolError::from_typed_decode)?;
    let request_id = RequestIdV2::new(decode_fixed::<16>(&mut decoder)?);
    let deadline = UnixMillisV2::new(decoder.u64().map_err(ProtocolError::malformed)?);
    let tag = decoder.u16().map_err(ProtocolError::malformed)?;
    if role != expected_role || tag != expected_tag {
        return Err(malformed());
    }
    let body_start = decoder.position();
    decoder.skip().map_err(ProtocolError::malformed)?;
    if decoder.position() != bytes.len() {
        return Err(malformed());
    }
    let operation = decode_operation_body(role, tag, &bytes[body_start..])?;
    let value = ApprovalServiceRequestV2::new(request_id, deadline, operation)?;
    if encode_approval_service_request_v2(&value)? != bytes {
        return Err(noncanonical());
    }
    Ok(value)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApprovalHealthResponseV2 {
    state: PublicServiceStateV2,
}

impl ApprovalHealthResponseV2 {
    pub const fn new(state: PublicServiceStateV2) -> Self {
        Self { state }
    }

    pub const fn state(self) -> PublicServiceStateV2 {
        self.state
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisteredUiAuthenticationV2 {
    Ingress {
        record: ApprovalUiRecordHandleV2,
        transfer: IngressUiAuthenticationTransferCapabilityV2,
    },
    Agent {
        record: ApprovalUiRecordHandleV2,
        transfer: AgentUiAuthenticationTransferCapabilityV2,
    },
}

impl RegisteredUiAuthenticationV2 {
    pub const fn record(self) -> ApprovalUiRecordHandleV2 {
        match self {
            Self::Ingress { record, .. } | Self::Agent { record, .. } => record,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsumedUiAuthenticationSettlementV2 {
    settlement: SignedUiAuthenticationSettlementV2,
}

impl ConsumedUiAuthenticationSettlementV2 {
    pub const fn new(settlement: SignedUiAuthenticationSettlementV2) -> Self {
        Self { settlement }
    }

    pub const fn settlement(&self) -> &SignedUiAuthenticationSettlementV2 {
        &self.settlement
    }
}

pub fn encode_approval_health_response_v2(
    value: ApprovalHealthResponseV2,
) -> Result<Vec<u8>, ProtocolError> {
    minicbor::to_vec(value.state).map_err(ProtocolError::malformed)
}

pub fn decode_approval_health_response_v2(
    bytes: &[u8],
) -> Result<ApprovalHealthResponseV2, ProtocolError> {
    validate_size(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    let mut context = V2DecodeContext;
    let state = PublicServiceStateV2::decode(&mut decoder, &mut context)
        .map_err(ProtocolError::from_typed_decode)?;
    let value = ApprovalHealthResponseV2::new(state);
    if decoder.position() != bytes.len() || encode_approval_health_response_v2(value)? != bytes {
        return Err(noncanonical());
    }
    Ok(value)
}

pub fn encode_registered_approval_v2(
    value: RegisteredApprovalV2,
) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder.array(3).map_err(ProtocolError::malformed)?;
    match value {
        RegisteredApprovalV2::TaskAuthorization {
            approval,
            display_authentication,
        } => {
            encoder.u16(5).map_err(ProtocolError::malformed)?;
            approval
                .encode(&mut encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
            display_authentication
                .encode(&mut encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
        }
        RegisteredApprovalV2::Ingress {
            approval,
            display_authentication,
        } => {
            encoder.u16(1).map_err(ProtocolError::malformed)?;
            approval
                .encode(&mut encoder, &mut ())
                .and_then(|()| display_authentication.encode(&mut encoder, &mut ()))
                .map_err(ProtocolError::malformed)?;
        }
        RegisteredApprovalV2::Tool {
            approval,
            display_authentication,
        } => {
            encoder.u16(2).map_err(ProtocolError::malformed)?;
            approval
                .encode(&mut encoder, &mut ())
                .and_then(|()| display_authentication.encode(&mut encoder, &mut ()))
                .map_err(ProtocolError::malformed)?;
        }
        RegisteredApprovalV2::Release {
            approval,
            display_authentication,
        } => {
            encoder.u16(3).map_err(ProtocolError::malformed)?;
            approval
                .encode(&mut encoder, &mut ())
                .and_then(|()| display_authentication.encode(&mut encoder, &mut ()))
                .map_err(ProtocolError::malformed)?;
        }
        RegisteredApprovalV2::Connector {
            approval,
            display_authentication,
        } => {
            encoder.u16(4).map_err(ProtocolError::malformed)?;
            approval
                .encode(&mut encoder, &mut ())
                .and_then(|()| display_authentication.encode(&mut encoder, &mut ()))
                .map_err(ProtocolError::malformed)?;
        }
    }
    Ok(encoder.into_writer())
}

pub fn decode_registered_approval_v2(
    bytes: &[u8],
    role: EndpointRoleV2,
) -> Result<RegisteredApprovalV2, ProtocolError> {
    validate_size(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    require_array(&mut decoder, 3)?;
    let tag = decoder.u16().map_err(ProtocolError::malformed)?;
    let mut context = V2DecodeContext;
    let value = match (role, tag) {
        (EndpointRoleV2::IngressApproval, 5) => RegisteredApprovalV2::TaskAuthorization {
            approval: minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?,
            display_authentication: minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?,
        },
        (EndpointRoleV2::IngressApproval, 1) => RegisteredApprovalV2::Ingress {
            approval: minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?,
            display_authentication: minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?,
        },
        (EndpointRoleV2::AgentApproval | EndpointRoleV2::KernelApproval, 2) => {
            RegisteredApprovalV2::Tool {
                approval: minicbor::Decode::decode(&mut decoder, &mut context)
                    .map_err(ProtocolError::from_typed_decode)?,
                display_authentication: minicbor::Decode::decode(&mut decoder, &mut context)
                    .map_err(ProtocolError::from_typed_decode)?,
            }
        }
        (EndpointRoleV2::AgentApproval | EndpointRoleV2::KernelApproval, 3) => {
            RegisteredApprovalV2::Release {
                approval: minicbor::Decode::decode(&mut decoder, &mut context)
                    .map_err(ProtocolError::from_typed_decode)?,
                display_authentication: minicbor::Decode::decode(&mut decoder, &mut context)
                    .map_err(ProtocolError::from_typed_decode)?,
            }
        }
        (EndpointRoleV2::AgentApproval, 4) => RegisteredApprovalV2::Connector {
            approval: minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?,
            display_authentication: minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?,
        },
        _ => return Err(malformed()),
    };
    if decoder.position() != bytes.len() || encode_registered_approval_v2(value)? != bytes {
        return Err(noncanonical());
    }
    Ok(value)
}

pub fn encode_approval_settlement_view_v2(
    value: &ApprovalSettlementViewV2,
) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    match value {
        ApprovalSettlementViewV2::Pending => {
            encoder
                .array(1)
                .and_then(|encoder| encoder.u16(1))
                .map_err(ProtocolError::malformed)?;
        }
        ApprovalSettlementViewV2::Denied { settlement } => {
            let bytes = encode_signed_approval_settlement_v2(settlement)?;
            encoder
                .array(2)
                .and_then(|encoder| encoder.u16(2))
                .and_then(|encoder| encoder.bytes(&bytes))
                .map_err(ProtocolError::malformed)?;
        }
        ApprovalSettlementViewV2::Expired => {
            encoder
                .array(1)
                .and_then(|encoder| encoder.u16(3))
                .map_err(ProtocolError::malformed)?;
        }
        ApprovalSettlementViewV2::Approved { settlement } => {
            let bytes = encode_signed_approval_settlement_v2(settlement)?;
            encoder
                .array(2)
                .and_then(|encoder| encoder.u16(4))
                .and_then(|encoder| encoder.bytes(&bytes))
                .map_err(ProtocolError::malformed)?;
        }
    }
    Ok(encoder.into_writer())
}

pub fn decode_approval_settlement_view_v2(
    bytes: &[u8],
) -> Result<ApprovalSettlementViewV2, ProtocolError> {
    validate_size(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    let count = decoder.array().map_err(ProtocolError::malformed)?;
    let tag = decoder.u16().map_err(ProtocolError::malformed)?;
    let value = match (tag, count) {
        (1, Some(1)) => ApprovalSettlementViewV2::Pending,
        (2, Some(2)) => ApprovalSettlementViewV2::Denied {
            settlement: decode_signed_approval_settlement_v2(
                decoder.bytes().map_err(ProtocolError::malformed)?,
            )?,
        },
        (3, Some(1)) => ApprovalSettlementViewV2::Expired,
        (4, Some(2)) => ApprovalSettlementViewV2::Approved {
            settlement: decode_signed_approval_settlement_v2(
                decoder.bytes().map_err(ProtocolError::malformed)?,
            )?,
        },
        _ => return Err(malformed()),
    };
    if decoder.position() != bytes.len() || encode_approval_settlement_view_v2(&value)? != bytes {
        return Err(noncanonical());
    }
    Ok(value)
}

pub fn encode_registered_ui_authentication_v2(
    value: RegisteredUiAuthenticationV2,
) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    match value {
        RegisteredUiAuthenticationV2::Ingress { .. } => {
            encoder.array(3).and_then(|encoder| encoder.u16(1))
        }
        RegisteredUiAuthenticationV2::Agent { .. } => {
            encoder.array(3).and_then(|encoder| encoder.u16(2))
        }
    }
    .map_err(ProtocolError::malformed)?;
    let (record, transfer_bytes) = match value {
        RegisteredUiAuthenticationV2::Ingress { record, transfer } => {
            let bytes = minicbor::to_vec(transfer).map_err(ProtocolError::malformed)?;
            (record, bytes)
        }
        RegisteredUiAuthenticationV2::Agent { record, transfer } => {
            let bytes = minicbor::to_vec(transfer).map_err(ProtocolError::malformed)?;
            (record, bytes)
        }
    };
    record
        .encode(&mut encoder, &mut ())
        .map_err(ProtocolError::malformed)?;
    let mut bytes = encoder.into_writer();
    bytes.extend_from_slice(&transfer_bytes);
    Ok(bytes)
}

pub fn decode_registered_ui_authentication_v2(
    bytes: &[u8],
    role: EndpointRoleV2,
) -> Result<RegisteredUiAuthenticationV2, ProtocolError> {
    validate_size(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    if decoder.array().map_err(ProtocolError::malformed)? != Some(3) {
        return Err(malformed());
    }
    let tag = decoder.u16().map_err(ProtocolError::malformed)?;
    let mut context = V2DecodeContext;
    let record = ApprovalUiRecordHandleV2::decode(&mut decoder, &mut context)
        .map_err(ProtocolError::from_typed_decode)?;
    let value = match (role, tag) {
        (EndpointRoleV2::IngressApproval, 1) => RegisteredUiAuthenticationV2::Ingress {
            record,
            transfer: IngressUiAuthenticationTransferCapabilityV2::decode(
                &mut decoder,
                &mut context,
            )
            .map_err(ProtocolError::from_typed_decode)?,
        },
        (EndpointRoleV2::AgentApproval, 2) => RegisteredUiAuthenticationV2::Agent {
            record,
            transfer: AgentUiAuthenticationTransferCapabilityV2::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?,
        },
        _ => return Err(malformed()),
    };
    if decoder.position() != bytes.len() || encode_registered_ui_authentication_v2(value)? != bytes
    {
        return Err(noncanonical());
    }
    Ok(value)
}

pub fn encode_consumed_ui_authentication_settlement_v2(
    value: &ConsumedUiAuthenticationSettlementV2,
) -> Result<Vec<u8>, ProtocolError> {
    let signed = encode_signed_ui_authentication_settlement_v2(&value.settlement)?;
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(1)
        .and_then(|encoder| encoder.bytes(&signed))
        .map_err(ProtocolError::malformed)?;
    Ok(encoder.into_writer())
}

pub fn decode_consumed_ui_authentication_settlement_v2(
    bytes: &[u8],
) -> Result<ConsumedUiAuthenticationSettlementV2, ProtocolError> {
    validate_size(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    if decoder.array().map_err(ProtocolError::malformed)? != Some(1) {
        return Err(malformed());
    }
    let settlement = decode_signed_ui_authentication_settlement_v2(
        decoder.bytes().map_err(ProtocolError::malformed)?,
    )?;
    let value = ConsumedUiAuthenticationSettlementV2::new(settlement);
    if decoder.position() != bytes.len()
        || encode_consumed_ui_authentication_settlement_v2(&value)? != bytes
    {
        return Err(noncanonical());
    }
    Ok(value)
}

pub fn encode_create_enrollment_code_response_v2(
    value: &CreateEnrollmentCodeResponseV2,
) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder.array(3).map_err(ProtocolError::malformed)?;
    value
        .enrollment
        .encode(&mut encoder, &mut ())
        .and_then(|()| value.code.encode(&mut encoder, &mut ()))
        .and_then(|()| value.expires_at.encode(&mut encoder, &mut ()))
        .map_err(ProtocolError::malformed)?;
    Ok(encoder.into_writer())
}

pub fn decode_create_enrollment_code_response_v2(
    bytes: &[u8],
) -> Result<CreateEnrollmentCodeResponseV2, ProtocolError> {
    validate_size(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    require_array(&mut decoder, 3)?;
    let mut context = V2DecodeContext;
    let value = CreateEnrollmentCodeResponseV2::new(
        minicbor::Decode::decode(&mut decoder, &mut context)
            .map_err(ProtocolError::from_typed_decode)?,
        minicbor::Decode::decode(&mut decoder, &mut context)
            .map_err(ProtocolError::from_typed_decode)?,
        minicbor::Decode::decode(&mut decoder, &mut context)
            .map_err(ProtocolError::from_typed_decode)?,
    )?;
    if decoder.position() != bytes.len()
        || encode_create_enrollment_code_response_v2(&value)? != bytes
    {
        return Err(noncanonical());
    }
    Ok(value)
}

pub fn encode_revoke_credential_response_v2(
    value: RevokeCredentialResponseV2,
) -> Result<Vec<u8>, ProtocolError> {
    minicbor::to_vec(value.state).map_err(ProtocolError::malformed)
}

pub fn decode_revoke_credential_response_v2(
    bytes: &[u8],
) -> Result<RevokeCredentialResponseV2, ProtocolError> {
    validate_size(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    let mut context = V2DecodeContext;
    let state = CredentialPublicStateV2::decode(&mut decoder, &mut context)
        .map_err(ProtocolError::from_typed_decode)?;
    let value = RevokeCredentialResponseV2::new(state);
    if decoder.position() != bytes.len() || encode_revoke_credential_response_v2(value)? != bytes {
        return Err(noncanonical());
    }
    Ok(value)
}

fn encode_operation_body(value: &ApprovalServiceOperationV2) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    match value {
        ApprovalServiceOperationV2::AttachPrivatePublicationV04 {
            session,
            publication,
        } => {
            encoder.array(2).map_err(ProtocolError::malformed)?;
            session
                .encode(&mut encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
            encoder
                .bytes(&super::encode_private_publication_v04(*publication)?)
                .map_err(ProtocolError::malformed)?;
        }
        ApprovalServiceOperationV2::AttachPrivateReleaseApprovalV04 {
            session,
            approval,
            root,
        } => {
            encoder.array(3).map_err(ProtocolError::malformed)?;
            session
                .encode(&mut encoder, &mut ())
                .and_then(|()| approval.encode(&mut encoder, &mut ()))
                .and_then(|()| root.encode(&mut encoder, &mut ()))
                .map_err(ProtocolError::malformed)?;
        }
        ApprovalServiceOperationV2::GetKernelReleaseApprovalSettlement { approval } => {
            encoder.array(1).map_err(ProtocolError::malformed)?;
            approval
                .encode(&mut encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
        }
        ApprovalServiceOperationV2::AttachPrivateApprovalV04 {
            session,
            approval,
            root,
        } => {
            encoder.array(3).map_err(ProtocolError::malformed)?;
            session
                .encode(&mut encoder, &mut ())
                .and_then(|()| approval.encode(&mut encoder, &mut ()))
                .and_then(|()| root.encode(&mut encoder, &mut ()))
                .map_err(ProtocolError::malformed)?;
        }
        ApprovalServiceOperationV2::GetPrivateSessionAuthenticationV04 { record } => {
            encoder.array(1).map_err(ProtocolError::malformed)?;
            record
                .encode(&mut encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
        }
        ApprovalServiceOperationV2::RegisterPrivateSessionV04 { envelope } => {
            let bytes = encode_signed_ui_authentication_envelope_v2(envelope)?;
            encoder
                .array(1)
                .and_then(|e| e.bytes(&bytes))
                .map_err(ProtocolError::malformed)?;
        }
        ApprovalServiceOperationV2::AgentHealth
        | ApprovalServiceOperationV2::KernelHealth
        | ApprovalServiceOperationV2::IngressHealth
        | ApprovalServiceOperationV2::AdminHealth => {
            encoder.array(0).map_err(ProtocolError::malformed)?;
        }
        ApprovalServiceOperationV2::RegisterAgentApproval {
            envelope,
            display_authentication,
        }
        | ApprovalServiceOperationV2::RegisterIngressApproval {
            envelope,
            display_authentication,
        }
        | ApprovalServiceOperationV2::RegisterKernelApproval {
            envelope,
            display_authentication,
        } => {
            let envelope = encode_signed_approval_envelope_v2(envelope)?;
            let display = encode_signed_ui_authentication_envelope_v2(display_authentication)?;
            encoder
                .array(2)
                .and_then(|encoder| encoder.bytes(&envelope))
                .and_then(|encoder| encoder.bytes(&display))
                .map_err(ProtocolError::malformed)?;
        }
        ApprovalServiceOperationV2::GetKernelApprovalSettlement { approval } => {
            encoder.array(1).map_err(ProtocolError::malformed)?;
            approval
                .encode(&mut encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
        }
        ApprovalServiceOperationV2::GetIngressApprovalSettlement { approval } => {
            encoder.array(1).map_err(ProtocolError::malformed)?;
            approval
                .encode(&mut encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
        }
        ApprovalServiceOperationV2::GetTaskAuthorizationApprovalSettlement { approval } => {
            encoder.array(1).map_err(ProtocolError::malformed)?;
            approval
                .encode(&mut encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
        }
        ApprovalServiceOperationV2::GetAgentApprovalSettlement { approval } => {
            encoder.array(1).map_err(ProtocolError::malformed)?;
            encode_agent_approval_target(&mut encoder, *approval)?;
        }
        ApprovalServiceOperationV2::RegisterAgentUiAuthentication { envelope }
        | ApprovalServiceOperationV2::RegisterIngressUiAuthentication { envelope } => {
            let signed = encode_signed_ui_authentication_envelope_v2(envelope)?;
            encoder
                .array(1)
                .and_then(|encoder| encoder.bytes(&signed))
                .map_err(ProtocolError::malformed)?;
        }
        ApprovalServiceOperationV2::ConsumeAgentUiAuthenticationSettlement { record, transfer } => {
            encoder.array(2).map_err(ProtocolError::malformed)?;
            record
                .encode(&mut encoder, &mut ())
                .and_then(|()| transfer.encode(&mut encoder, &mut ()))
                .map_err(ProtocolError::malformed)?;
        }
        ApprovalServiceOperationV2::ConsumeIngressUiAuthenticationSettlement {
            record,
            transfer,
        } => {
            encoder.array(2).map_err(ProtocolError::malformed)?;
            record
                .encode(&mut encoder, &mut ())
                .and_then(|()| transfer.encode(&mut encoder, &mut ()))
                .map_err(ProtocolError::malformed)?;
        }
        ApprovalServiceOperationV2::CloseAgentAuthenticationAttempt { descriptor } => {
            let signed = encode_signed_agent_authentication_closure_descriptor_v2(descriptor)?;
            encoder
                .array(1)
                .and_then(|encoder| encoder.bytes(&signed))
                .map_err(ProtocolError::malformed)?;
        }
        ApprovalServiceOperationV2::CreateEnrollmentCode {
            enrollment_profile,
            client_request_nonce,
        } => {
            encoder.array(2).map_err(ProtocolError::malformed)?;
            enrollment_profile
                .encode(&mut encoder, &mut ())
                .and_then(|()| client_request_nonce.encode(&mut encoder, &mut ()))
                .map_err(ProtocolError::malformed)?;
        }
        ApprovalServiceOperationV2::RevokeCredential {
            credential_digest,
            reason,
        } => {
            encoder.array(2).map_err(ProtocolError::malformed)?;
            credential_digest
                .encode(&mut encoder, &mut ())
                .and_then(|()| reason.encode(&mut encoder, &mut ()))
                .map_err(ProtocolError::malformed)?;
        }
    }
    Ok(encoder.into_writer())
}

fn decode_operation_body(
    role: EndpointRoleV2,
    tag: u16,
    bytes: &[u8],
) -> Result<ApprovalServiceOperationV2, ProtocolError> {
    let mut decoder = minicbor::Decoder::new(bytes);
    let value = match (role, tag) {
        (EndpointRoleV2::KernelApproval, 27) => {
            require_array(&mut decoder, 2)?;
            ApprovalServiceOperationV2::AttachPrivatePublicationV04 {
                session: ApprovalUiRecordHandleV2::decode(&mut decoder, &mut V2DecodeContext)
                    .map_err(ProtocolError::from_typed_decode)?,
                publication: super::decode_private_publication_v04(
                    decoder.bytes().map_err(ProtocolError::malformed)?,
                )?,
            }
        }
        (EndpointRoleV2::KernelApproval, 25) => {
            require_array(&mut decoder, 3)?;
            ApprovalServiceOperationV2::AttachPrivateReleaseApprovalV04 {
                session: ApprovalUiRecordHandleV2::decode(&mut decoder, &mut V2DecodeContext)
                    .map_err(ProtocolError::from_typed_decode)?,
                approval: ReleaseApprovalRecordHandleV2::decode(&mut decoder, &mut V2DecodeContext)
                    .map_err(ProtocolError::from_typed_decode)?,
                root: Digest32V2::decode(&mut decoder, &mut V2DecodeContext)
                    .map_err(ProtocolError::from_typed_decode)?,
            }
        }
        (EndpointRoleV2::KernelApproval, 26) => {
            require_array(&mut decoder, 1)?;
            ApprovalServiceOperationV2::GetKernelReleaseApprovalSettlement {
                approval: ReleaseApprovalRecordHandleV2::decode(&mut decoder, &mut V2DecodeContext)
                    .map_err(ProtocolError::from_typed_decode)?,
            }
        }
        (EndpointRoleV2::KernelApproval, 24) => {
            require_array(&mut decoder, 3)?;
            ApprovalServiceOperationV2::AttachPrivateApprovalV04 {
                session: ApprovalUiRecordHandleV2::decode(&mut decoder, &mut V2DecodeContext)
                    .map_err(ProtocolError::from_typed_decode)?,
                approval: ToolApprovalRecordHandleV2::decode(&mut decoder, &mut V2DecodeContext)
                    .map_err(ProtocolError::from_typed_decode)?,
                root: Digest32V2::decode(&mut decoder, &mut V2DecodeContext)
                    .map_err(ProtocolError::from_typed_decode)?,
            }
        }
        (EndpointRoleV2::KernelApproval, 22) => {
            require_array(&mut decoder, 1)?;
            ApprovalServiceOperationV2::RegisterPrivateSessionV04 {
                envelope: decode_signed_ui_authentication_envelope_v2(
                    decoder.bytes().map_err(ProtocolError::malformed)?,
                )?,
            }
        }
        (EndpointRoleV2::KernelApproval, 23) => {
            require_array(&mut decoder, 1)?;
            ApprovalServiceOperationV2::GetPrivateSessionAuthenticationV04 {
                record: minicbor::Decode::decode(&mut decoder, &mut V2DecodeContext)
                    .map_err(ProtocolError::from_typed_decode)?,
            }
        }
        (EndpointRoleV2::KernelApproval, 0) => {
            require_array(&mut decoder, 0)?;
            ApprovalServiceOperationV2::KernelHealth
        }
        (EndpointRoleV2::KernelApproval, 20) => {
            require_array(&mut decoder, 2)?;
            ApprovalServiceOperationV2::RegisterKernelApproval {
                envelope: decode_signed_approval_envelope_v2(
                    decoder.bytes().map_err(ProtocolError::malformed)?,
                )?,
                display_authentication: decode_signed_ui_authentication_envelope_v2(
                    decoder.bytes().map_err(ProtocolError::malformed)?,
                )?,
            }
        }
        (EndpointRoleV2::KernelApproval, 21) => {
            require_array(&mut decoder, 1)?;
            ApprovalServiceOperationV2::GetKernelApprovalSettlement {
                approval: minicbor::Decode::decode(&mut decoder, &mut V2DecodeContext)
                    .map_err(ProtocolError::from_typed_decode)?,
            }
        }
        (EndpointRoleV2::AgentApproval, 0) => {
            require_array(&mut decoder, 0)?;
            ApprovalServiceOperationV2::AgentHealth
        }
        (EndpointRoleV2::IngressApproval, 0) => {
            require_array(&mut decoder, 0)?;
            ApprovalServiceOperationV2::IngressHealth
        }
        (EndpointRoleV2::ApprovalAdmin, 0) => {
            require_array(&mut decoder, 0)?;
            ApprovalServiceOperationV2::AdminHealth
        }
        (EndpointRoleV2::AgentApproval, 20) => {
            require_array(&mut decoder, 2)?;
            ApprovalServiceOperationV2::RegisterAgentApproval {
                envelope: decode_signed_approval_envelope_v2(
                    decoder.bytes().map_err(ProtocolError::malformed)?,
                )?,
                display_authentication: decode_signed_ui_authentication_envelope_v2(
                    decoder.bytes().map_err(ProtocolError::malformed)?,
                )?,
            }
        }
        (EndpointRoleV2::IngressApproval, 20) => {
            require_array(&mut decoder, 2)?;
            ApprovalServiceOperationV2::RegisterIngressApproval {
                envelope: decode_signed_approval_envelope_v2(
                    decoder.bytes().map_err(ProtocolError::malformed)?,
                )?,
                display_authentication: decode_signed_ui_authentication_envelope_v2(
                    decoder.bytes().map_err(ProtocolError::malformed)?,
                )?,
            }
        }
        (EndpointRoleV2::AgentApproval, 21) => {
            require_array(&mut decoder, 1)?;
            ApprovalServiceOperationV2::GetAgentApprovalSettlement {
                approval: decode_agent_approval_target(&mut decoder)?,
            }
        }
        (EndpointRoleV2::IngressApproval, 21) => {
            require_array(&mut decoder, 1)?;
            let mut context = V2DecodeContext;
            ApprovalServiceOperationV2::GetIngressApprovalSettlement {
                approval: minicbor::Decode::decode(&mut decoder, &mut context)
                    .map_err(ProtocolError::from_typed_decode)?,
            }
        }
        (EndpointRoleV2::IngressApproval, 25) => {
            require_array(&mut decoder, 1)?;
            let mut context = V2DecodeContext;
            ApprovalServiceOperationV2::GetTaskAuthorizationApprovalSettlement {
                approval: minicbor::Decode::decode(&mut decoder, &mut context)
                    .map_err(ProtocolError::from_typed_decode)?,
            }
        }
        (EndpointRoleV2::AgentApproval, 22) => {
            require_array(&mut decoder, 1)?;
            ApprovalServiceOperationV2::RegisterAgentUiAuthentication {
                envelope: decode_signed_ui_authentication_envelope_v2(
                    decoder.bytes().map_err(ProtocolError::malformed)?,
                )?,
            }
        }
        (EndpointRoleV2::IngressApproval, 22) => {
            require_array(&mut decoder, 1)?;
            ApprovalServiceOperationV2::RegisterIngressUiAuthentication {
                envelope: decode_signed_ui_authentication_envelope_v2(
                    decoder.bytes().map_err(ProtocolError::malformed)?,
                )?,
            }
        }
        (EndpointRoleV2::AgentApproval, 23) => {
            require_array(&mut decoder, 2)?;
            let mut context = V2DecodeContext;
            ApprovalServiceOperationV2::ConsumeAgentUiAuthenticationSettlement {
                record: ApprovalUiRecordHandleV2::decode(&mut decoder, &mut context)
                    .map_err(ProtocolError::from_typed_decode)?,
                transfer: AgentUiAuthenticationSettlementTransferCapabilityV2::decode(
                    &mut decoder,
                    &mut context,
                )
                .map_err(ProtocolError::from_typed_decode)?,
            }
        }
        (EndpointRoleV2::IngressApproval, 23) => {
            require_array(&mut decoder, 2)?;
            let mut context = V2DecodeContext;
            ApprovalServiceOperationV2::ConsumeIngressUiAuthenticationSettlement {
                record: ApprovalUiRecordHandleV2::decode(&mut decoder, &mut context)
                    .map_err(ProtocolError::from_typed_decode)?,
                transfer: IngressUiAuthenticationSettlementTransferCapabilityV2::decode(
                    &mut decoder,
                    &mut context,
                )
                .map_err(ProtocolError::from_typed_decode)?,
            }
        }
        (EndpointRoleV2::AgentApproval, 24) => {
            require_array(&mut decoder, 1)?;
            ApprovalServiceOperationV2::CloseAgentAuthenticationAttempt {
                descriptor: decode_signed_agent_authentication_closure_descriptor_v2(
                    decoder.bytes().map_err(ProtocolError::malformed)?,
                )?,
            }
        }
        (EndpointRoleV2::ApprovalAdmin, 100) => {
            require_array(&mut decoder, 2)?;
            let mut context = V2DecodeContext;
            ApprovalServiceOperationV2::CreateEnrollmentCode {
                enrollment_profile: minicbor::Decode::decode(&mut decoder, &mut context)
                    .map_err(ProtocolError::from_typed_decode)?,
                client_request_nonce: minicbor::Decode::decode(&mut decoder, &mut context)
                    .map_err(ProtocolError::from_typed_decode)?,
            }
        }
        (EndpointRoleV2::ApprovalAdmin, 101) => {
            require_array(&mut decoder, 2)?;
            let mut context = V2DecodeContext;
            ApprovalServiceOperationV2::RevokeCredential {
                credential_digest: minicbor::Decode::decode(&mut decoder, &mut context)
                    .map_err(ProtocolError::from_typed_decode)?,
                reason: minicbor::Decode::decode(&mut decoder, &mut context)
                    .map_err(ProtocolError::from_typed_decode)?,
            }
        }
        _ => return Err(malformed()),
    };
    if decoder.position() != bytes.len() || encode_operation_body(&value)? != bytes {
        return Err(noncanonical());
    }
    Ok(value)
}

fn encode_agent_approval_target<W: minicbor::encode::Write>(
    encoder: &mut minicbor::Encoder<W>,
    value: AgentApprovalRecordTargetV2,
) -> Result<(), ProtocolError> {
    encoder.array(2).map_err(ProtocolError::malformed)?;
    match value {
        AgentApprovalRecordTargetV2::Tool(handle) => {
            encoder.u16(1).map_err(ProtocolError::malformed)?;
            handle
                .encode(encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
        }
        AgentApprovalRecordTargetV2::Release(handle) => {
            encoder.u16(2).map_err(ProtocolError::malformed)?;
            handle
                .encode(encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
        }
        AgentApprovalRecordTargetV2::Connector(handle) => {
            encoder.u16(3).map_err(ProtocolError::malformed)?;
            handle
                .encode(encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
        }
    }
    Ok(())
}

fn decode_agent_approval_target(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<AgentApprovalRecordTargetV2, ProtocolError> {
    require_array(decoder, 2)?;
    let tag = decoder.u16().map_err(ProtocolError::malformed)?;
    let mut context = V2DecodeContext;
    match tag {
        1 => Ok(AgentApprovalRecordTargetV2::Tool(
            minicbor::Decode::decode(decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?,
        )),
        2 => Ok(AgentApprovalRecordTargetV2::Release(
            minicbor::Decode::decode(decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?,
        )),
        3 => Ok(AgentApprovalRecordTargetV2::Connector(
            minicbor::Decode::decode(decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?,
        )),
        _ => Err(malformed()),
    }
}

fn require_array(decoder: &mut minicbor::Decoder<'_>, expected: u64) -> Result<(), ProtocolError> {
    if decoder.array().map_err(ProtocolError::malformed)? == Some(expected) {
        Ok(())
    } else {
        Err(malformed())
    }
}

fn decode_fixed<const N: usize>(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<[u8; N], ProtocolError> {
    decoder
        .bytes()
        .map_err(ProtocolError::malformed)?
        .try_into()
        .map_err(|_| malformed())
}

fn validate_size(bytes: &[u8]) -> Result<(), ProtocolError> {
    if bytes.is_empty() || bytes.len() > MAX_APPROVAL_SERVICE_BYTES_V2 {
        Err(malformed())
    } else {
        Ok(())
    }
}

fn malformed() -> ProtocolError {
    ProtocolError::stable(StableCode::ProtocolMalformedCbor)
}

fn typed_malformed(position: usize) -> minicbor::decode::Error {
    minicbor::decode::Error::message(StableCode::ProtocolMalformedCbor.as_str()).at(position)
}

fn noncanonical() -> ProtocolError {
    ProtocolError::stable(StableCode::ProtocolNonCanonicalCbor)
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::*;
    #[test]
    fn kernel_approval_wire_role_is_closed_and_canonical() {
        let approval = ToolApprovalRecordHandleV2::from_authority_entropy([0x71; 32]).unwrap();
        for operation in [
            ApprovalServiceOperationV2::KernelHealth,
            ApprovalServiceOperationV2::GetKernelApprovalSettlement { approval },
            ApprovalServiceOperationV2::AttachPrivateReleaseApprovalV04 {
                session: ApprovalUiRecordHandleV2::from_authority_entropy([4; 32]).unwrap(),
                approval: ReleaseApprovalRecordHandleV2::from_authority_entropy([3; 32]).unwrap(),
                root: Digest32V2::new([5; 32]),
            },
            ApprovalServiceOperationV2::GetKernelReleaseApprovalSettlement {
                approval: ReleaseApprovalRecordHandleV2::from_authority_entropy([3; 32]).unwrap(),
            },
        ] {
            let tag = operation.tag();
            let request = ApprovalServiceRequestV2::new(
                RequestIdV2::new([1; 16]),
                UnixMillisV2::new(200),
                operation,
            )
            .unwrap();
            let bytes = encode_approval_service_request_v2(&request).unwrap();
            assert_eq!(
                decode_approval_service_request_v2(&bytes, EndpointRoleV2::KernelApproval, tag)
                    .unwrap(),
                request
            );
            for role in [
                EndpointRoleV2::AgentApproval,
                EndpointRoleV2::IngressApproval,
                EndpointRoleV2::ApprovalAdmin,
            ] {
                assert!(decode_approval_service_request_v2(&bytes, role, tag).is_err());
            }
        }
        for tag in [22, 23, 24, 25, 100, 101] {
            assert!(decode_operation_body(EndpointRoleV2::KernelApproval, tag, &[0x80]).is_err());
        }
        let registered = RegisteredApprovalV2::Tool {
            approval,
            display_authentication:
                ApprovalDisplayAuthenticationTransferCapabilityV2::from_authority_entropy([2; 32])
                    .unwrap(),
        };
        let bytes = encode_registered_approval_v2(registered).unwrap();
        assert_eq!(
            decode_registered_approval_v2(&bytes, EndpointRoleV2::KernelApproval).unwrap(),
            registered
        );
        let release = RegisteredApprovalV2::Release {
            approval: ReleaseApprovalRecordHandleV2::from_authority_entropy([3; 32]).unwrap(),
            display_authentication:
                ApprovalDisplayAuthenticationTransferCapabilityV2::from_authority_entropy([2; 32])
                    .unwrap(),
        };
        assert_eq!(
            decode_registered_approval_v2(
                &encode_registered_approval_v2(release).unwrap(),
                EndpointRoleV2::KernelApproval
            )
            .unwrap(),
            release
        );
        assert!(decode_registered_approval_v2(
            &encode_registered_approval_v2(release).unwrap(),
            EndpointRoleV2::IngressApproval
        )
        .is_err());
    }
    use crate::v2::{
        Digest32V2, DurableRunIdV2, DurableTaskIdV2, FixedOriginV2, Nonce32V2, PrincipalIdV2,
        ServiceIdentityV2, SignedAgentAuthenticationClosureDescriptorV2, UiAuthenticationBindingV2,
        UiAuthenticationPurposeV2, UnsignedAgentAuthenticationClosureDescriptorV2,
        UnsignedUiAuthenticationEnvelopeV2,
    };

    #[test]
    fn ingress_ui_registration_is_canonical_and_cross_role_closed() {
        let signing = SigningKey::from_bytes(&[0x41; 32]);
        let unsigned = UnsignedUiAuthenticationEnvelopeV2::new(
            Digest32V2::new([1; 32]),
            Digest32V2::new([2; 32]),
            3,
            UiAuthenticationPurposeV2::IngressInput,
            UiAuthenticationBindingV2::IngressNewTask {
                durable_task_id: DurableTaskIdV2::new([4; 32]),
                pending_task_digest: Digest32V2::new([5; 32]),
                ingressd_identity: ServiceIdentityV2::new([12; 32]),
            },
            Some(PrincipalIdV2::new([6; 32])),
            FixedOriginV2::Approval8766,
            FixedOriginV2::Ingress8767,
            Nonce32V2::new([7; 32]),
            UnixMillisV2::new(8),
            UnixMillisV2::new(9),
        )
        .unwrap();
        let request = ApprovalServiceRequestV2::new(
            RequestIdV2::new([10; 16]),
            UnixMillisV2::new(11),
            ApprovalServiceOperationV2::RegisterIngressUiAuthentication {
                envelope: SignedUiAuthenticationEnvelopeV2::sign(unsigned, &signing).unwrap(),
            },
        )
        .unwrap();
        let bytes = encode_approval_service_request_v2(&request).unwrap();
        assert_eq!(
            decode_approval_service_request_v2(&bytes, EndpointRoleV2::IngressApproval, 22)
                .unwrap(),
            request
        );
        assert!(
            decode_approval_service_request_v2(&bytes, EndpointRoleV2::AgentApproval, 22).is_err()
        );
    }

    #[test]
    fn agent_authentication_closure_is_canonical_and_agent_role_only() {
        let signing = SigningKey::from_bytes(&[0x51; 32]);
        let descriptor = SignedAgentAuthenticationClosureDescriptorV2::sign(
            UnsignedAgentAuthenticationClosureDescriptorV2::new(
                Digest32V2::new([1; 32]),
                Digest32V2::new([2; 32]),
                3,
                Digest32V2::new([2; 32]),
                3,
                None,
                DurableTaskIdV2::new([7; 32]),
                DurableRunIdV2::new([8; 32]),
                Digest32V2::new([9; 32]),
                Digest32V2::new([10; 32]),
                PrincipalIdV2::new([11; 32]),
                ServiceIdentityV2::new([12; 32]),
                crate::v2::BootIdV2::new([13; 32]),
                ServiceIdentityV2::new([14; 32]),
                crate::v2::BootIdV2::new([15; 32]),
                ServiceIdentityV2::new([16; 32]),
                Nonce32V2::new([17; 32]),
                Digest32V2::new([18; 32]),
                Digest32V2::new([19; 32]),
                Digest32V2::new([20; 32]),
                Nonce32V2::new([21; 32]),
                UnixMillisV2::new(22),
                UnixMillisV2::new(23),
            )
            .unwrap(),
            &signing,
        )
        .unwrap();
        let request = ApprovalServiceRequestV2::new(
            RequestIdV2::new([24; 16]),
            UnixMillisV2::new(25),
            ApprovalServiceOperationV2::CloseAgentAuthenticationAttempt { descriptor },
        )
        .unwrap();
        let bytes = encode_approval_service_request_v2(&request).unwrap();
        assert_eq!(
            decode_approval_service_request_v2(&bytes, EndpointRoleV2::AgentApproval, 24).unwrap(),
            request
        );
        assert!(
            decode_approval_service_request_v2(&bytes, EndpointRoleV2::IngressApproval, 24)
                .is_err()
        );
    }

    #[test]
    fn approval_admin_operations_are_closed_and_canonical() {
        for operation in [
            ApprovalServiceOperationV2::CreateEnrollmentCode {
                enrollment_profile: EnrollmentProfileIdV2::new(7),
                client_request_nonce: Nonce32V2::new([0x61; 32]),
            },
            ApprovalServiceOperationV2::RevokeCredential {
                credential_digest: Digest32V2::new([0x62; 32]),
                reason: ClosedCredentialRevocationReasonV2::Compromised,
            },
        ] {
            let tag = operation.tag();
            let request = ApprovalServiceRequestV2::new(
                RequestIdV2::new([0x63; 16]),
                UnixMillisV2::new(100),
                operation,
            )
            .unwrap();
            let bytes = encode_approval_service_request_v2(&request).unwrap();
            assert_eq!(
                decode_approval_service_request_v2(&bytes, EndpointRoleV2::ApprovalAdmin, tag,)
                    .unwrap(),
                request
            );
            assert!(
                decode_approval_service_request_v2(&bytes, EndpointRoleV2::AgentApproval, tag,)
                    .is_err()
            );
        }
    }
}
