use crate::{ProtocolError, StableCode};

use super::{
    cbor::{scan_single, V2DecodeContext},
    AgentControlHealthResponseV2, AgentControlOperationV2, BootIdV2, CancelTaskResponseV2,
    Digest32V2, EndpointRoleV2, GetTaskStatusResponseV2, PrepareIngressResponseV2,
    PublicServiceStateV2, RequestIdV2, ServiceIdentityV2, UnixMillisV2, PROTOCOL_MAJOR,
    PROTOCOL_MINOR,
};

const AGENT_CONTROL_REQUEST_FIELDS: u64 = 12;
const AGENT_CONTROL_RESPONSE_FIELDS: u64 = 9;
const RESPONSE_ERROR_TAG: u16 = u16::MAX;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentControlRequestEnvelopeV2 {
    request_id: RequestIdV2,
    caller_boot_id: BootIdV2,
    service_boot_id: BootIdV2,
    caller_identity: ServiceIdentityV2,
    service_identity: ServiceIdentityV2,
    active_state_manifest_digest: Digest32V2,
    deployment_generation: u64,
    deadline: UnixMillisV2,
    operation: AgentControlOperationV2,
}

impl AgentControlRequestEnvelopeV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn from_authenticated_connection(
        request_id: RequestIdV2,
        caller_boot_id: BootIdV2,
        service_boot_id: BootIdV2,
        caller_identity: ServiceIdentityV2,
        service_identity: ServiceIdentityV2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        deadline: UnixMillisV2,
        operation: AgentControlOperationV2,
    ) -> Result<Self, ProtocolError> {
        let value = Self {
            request_id,
            caller_boot_id,
            service_boot_id,
            caller_identity,
            service_identity,
            active_state_manifest_digest,
            deployment_generation,
            deadline,
            operation,
        };
        value.validate()?;
        Ok(value)
    }

    pub const fn request_id(self) -> RequestIdV2 {
        self.request_id
    }

    pub const fn caller_boot_id(self) -> BootIdV2 {
        self.caller_boot_id
    }

    pub const fn service_boot_id(self) -> BootIdV2 {
        self.service_boot_id
    }

    pub const fn caller_identity(self) -> ServiceIdentityV2 {
        self.caller_identity
    }

    pub const fn service_identity(self) -> ServiceIdentityV2 {
        self.service_identity
    }

    pub const fn active_state_manifest_digest(self) -> Digest32V2 {
        self.active_state_manifest_digest
    }

    pub const fn deployment_generation(self) -> u64 {
        self.deployment_generation
    }

    pub const fn deadline(self) -> UnixMillisV2 {
        self.deadline
    }

    pub const fn operation(self) -> AgentControlOperationV2 {
        self.operation
    }

    fn validate(self) -> Result<(), ProtocolError> {
        if is_zero(self.request_id.as_bytes())
            || is_zero(self.caller_boot_id.as_bytes())
            || is_zero(self.service_boot_id.as_bytes())
            || is_zero(self.caller_identity.as_bytes())
            || is_zero(self.service_identity.as_bytes())
            || is_zero(self.active_state_manifest_digest.as_bytes())
            || self.deployment_generation == 0
            || self.deadline.get() == 0
        {
            return Err(ProtocolError::stable(StableCode::ProtocolMalformedCbor));
        }
        self.operation.validate()
    }
}

impl<C> minicbor::Encode<C> for AgentControlRequestEnvelopeV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        self.validate().map_err(|_| encode_error())?;
        encoder
            .array(AGENT_CONTROL_REQUEST_FIELDS)?
            .u16(PROTOCOL_MAJOR)?
            .u16(PROTOCOL_MINOR)?;
        EndpointRoleV2::JarvisAgentControl.encode(encoder, context)?;
        self.request_id.encode(encoder, context)?;
        self.caller_boot_id.encode(encoder, context)?;
        self.service_boot_id.encode(encoder, context)?;
        self.caller_identity.encode(encoder, context)?;
        self.service_identity.encode(encoder, context)?;
        self.active_state_manifest_digest.encode(encoder, context)?;
        encoder
            .u64(self.deployment_generation)?
            .u64(self.deadline.get())?;
        self.operation.encode(encoder, context)?;
        Ok(())
    }
}

impl<'bytes> minicbor::Decode<'bytes, V2DecodeContext> for AgentControlRequestEnvelopeV2 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut V2DecodeContext,
    ) -> Result<Self, minicbor::decode::Error> {
        let position = decoder.position();
        expect_array(decoder, position, AGENT_CONTROL_REQUEST_FIELDS)?;
        if decoder.u16()? != PROTOCOL_MAJOR || decoder.u16()? != PROTOCOL_MINOR {
            return Err(malformed(position));
        }
        if EndpointRoleV2::decode(decoder, context)? != EndpointRoleV2::JarvisAgentControl {
            return Err(malformed(position));
        }
        let value = Self {
            request_id: RequestIdV2::decode(decoder, context)?,
            caller_boot_id: BootIdV2::decode(decoder, context)?,
            service_boot_id: BootIdV2::decode(decoder, context)?,
            caller_identity: ServiceIdentityV2::decode(decoder, context)?,
            service_identity: ServiceIdentityV2::decode(decoder, context)?,
            active_state_manifest_digest: Digest32V2::decode(decoder, context)?,
            deployment_generation: decoder.u64()?,
            deadline: UnixMillisV2::new(decoder.u64()?),
            operation: AgentControlOperationV2::decode(decoder, context)?,
        };
        value.validate().map_err(|_| malformed(position))?;
        Ok(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentControlResponseV2 {
    Health(AgentControlHealthResponseV2),
    PrepareIngress(PrepareIngressResponseV2),
    GetTaskStatus(GetTaskStatusResponseV2),
    CancelTask(CancelTaskResponseV2),
    Error(StableCode),
}

impl AgentControlResponseV2 {
    pub const fn health(state: PublicServiceStateV2) -> Self {
        Self::Health(AgentControlHealthResponseV2::new(state))
    }

    pub const fn prepare_ingress(response: PrepareIngressResponseV2) -> Self {
        Self::PrepareIngress(response)
    }

    pub const fn get_task_status(response: GetTaskStatusResponseV2) -> Self {
        Self::GetTaskStatus(response)
    }

    pub const fn cancel_task(response: CancelTaskResponseV2) -> Self {
        Self::CancelTask(response)
    }

    pub fn error(code: StableCode) -> Self {
        if public_agent_control_error(code) {
            Self::Error(code)
        } else {
            Self::Error(StableCode::KernelUnavailable)
        }
    }

    pub const fn stable_error(self) -> Option<StableCode> {
        match self {
            Self::Error(code) => Some(code),
            _ => None,
        }
    }

    const fn tag(self) -> u16 {
        match self {
            Self::Health(_) => 0,
            Self::PrepareIngress(_) => 10,
            Self::GetTaskStatus(_) => 11,
            Self::CancelTask(_) => 12,
            Self::Error(_) => RESPONSE_ERROR_TAG,
        }
    }

    fn validate(self) -> Result<(), ProtocolError> {
        match self {
            Self::Error(code) if !public_agent_control_error(code) => {
                Err(ProtocolError::stable(StableCode::ProtocolMalformedCbor))
            }
            _ => Ok(()),
        }
    }
}

impl<C> minicbor::Encode<C> for AgentControlResponseV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        self.validate().map_err(|_| encode_error())?;
        encoder.array(2)?.u16(self.tag())?;
        match self {
            Self::Health(value) => value.encode(encoder, context)?,
            Self::PrepareIngress(value) => value.encode(encoder, context)?,
            Self::GetTaskStatus(value) => value.encode(encoder, context)?,
            Self::CancelTask(value) => value.encode(encoder, context)?,
            Self::Error(value) => value.encode(encoder, context)?,
        }
        Ok(())
    }
}

impl<'bytes> minicbor::Decode<'bytes, V2DecodeContext> for AgentControlResponseV2 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut V2DecodeContext,
    ) -> Result<Self, minicbor::decode::Error> {
        let position = decoder.position();
        expect_array(decoder, position, 2)?;
        let value = match decoder.u16()? {
            0 => Self::Health(AgentControlHealthResponseV2::decode(decoder, context)?),
            10 => Self::PrepareIngress(PrepareIngressResponseV2::decode(decoder, context)?),
            11 => Self::GetTaskStatus(GetTaskStatusResponseV2::decode(decoder, context)?),
            12 => Self::CancelTask(CancelTaskResponseV2::decode(decoder, context)?),
            RESPONSE_ERROR_TAG => Self::Error(StableCode::decode(decoder, context)?),
            _ => return Err(malformed(position)),
        };
        value.validate().map_err(|_| malformed(position))?;
        Ok(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentControlResponseEnvelopeV2 {
    request_id: RequestIdV2,
    service_boot_id: BootIdV2,
    service_identity: ServiceIdentityV2,
    active_state_manifest_digest: Digest32V2,
    deployment_generation: u64,
    response: AgentControlResponseV2,
}

impl AgentControlResponseEnvelopeV2 {
    pub fn from_authenticated_connection(
        request_id: RequestIdV2,
        service_boot_id: BootIdV2,
        service_identity: ServiceIdentityV2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        response: AgentControlResponseV2,
    ) -> Result<Self, ProtocolError> {
        let value = Self {
            request_id,
            service_boot_id,
            service_identity,
            active_state_manifest_digest,
            deployment_generation,
            response,
        };
        value.validate()?;
        Ok(value)
    }

    pub const fn request_id(self) -> RequestIdV2 {
        self.request_id
    }

    pub const fn response(self) -> AgentControlResponseV2 {
        self.response
    }

    fn validate(self) -> Result<(), ProtocolError> {
        if is_zero(self.request_id.as_bytes())
            || is_zero(self.service_boot_id.as_bytes())
            || is_zero(self.service_identity.as_bytes())
            || is_zero(self.active_state_manifest_digest.as_bytes())
            || self.deployment_generation == 0
        {
            return Err(ProtocolError::stable(StableCode::ProtocolMalformedCbor));
        }
        self.response.validate()
    }
}

impl<C> minicbor::Encode<C> for AgentControlResponseEnvelopeV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        self.validate().map_err(|_| encode_error())?;
        encoder
            .array(AGENT_CONTROL_RESPONSE_FIELDS)?
            .u16(PROTOCOL_MAJOR)?
            .u16(PROTOCOL_MINOR)?;
        EndpointRoleV2::JarvisAgentControl.encode(encoder, context)?;
        self.request_id.encode(encoder, context)?;
        self.service_boot_id.encode(encoder, context)?;
        self.service_identity.encode(encoder, context)?;
        self.active_state_manifest_digest.encode(encoder, context)?;
        encoder.u64(self.deployment_generation)?;
        self.response.encode(encoder, context)?;
        Ok(())
    }
}

impl<'bytes> minicbor::Decode<'bytes, V2DecodeContext> for AgentControlResponseEnvelopeV2 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut V2DecodeContext,
    ) -> Result<Self, minicbor::decode::Error> {
        let position = decoder.position();
        expect_array(decoder, position, AGENT_CONTROL_RESPONSE_FIELDS)?;
        if decoder.u16()? != PROTOCOL_MAJOR || decoder.u16()? != PROTOCOL_MINOR {
            return Err(malformed(position));
        }
        if EndpointRoleV2::decode(decoder, context)? != EndpointRoleV2::JarvisAgentControl {
            return Err(malformed(position));
        }
        let value = Self {
            request_id: RequestIdV2::decode(decoder, context)?,
            service_boot_id: BootIdV2::decode(decoder, context)?,
            service_identity: ServiceIdentityV2::decode(decoder, context)?,
            active_state_manifest_digest: Digest32V2::decode(decoder, context)?,
            deployment_generation: decoder.u64()?,
            response: AgentControlResponseV2::decode(decoder, context)?,
        };
        value.validate().map_err(|_| malformed(position))?;
        Ok(value)
    }
}

pub fn encode_agent_control_request_envelope_v2(
    value: &AgentControlRequestEnvelopeV2,
) -> Result<Vec<u8>, ProtocolError> {
    value.validate()?;
    minicbor::to_vec(value).map_err(ProtocolError::malformed)
}

pub fn decode_agent_control_request_envelope_v2(
    bytes: &[u8],
) -> Result<AgentControlRequestEnvelopeV2, ProtocolError> {
    decode_canonical(bytes, encode_agent_control_request_envelope_v2)
}

pub fn encode_agent_control_response_envelope_v2(
    value: &AgentControlResponseEnvelopeV2,
) -> Result<Vec<u8>, ProtocolError> {
    value.validate()?;
    minicbor::to_vec(value).map_err(ProtocolError::malformed)
}

pub fn decode_agent_control_response_envelope_v2(
    bytes: &[u8],
) -> Result<AgentControlResponseEnvelopeV2, ProtocolError> {
    decode_canonical(bytes, encode_agent_control_response_envelope_v2)
}

fn decode_canonical<T>(
    bytes: &[u8],
    encode: fn(&T) -> Result<Vec<u8>, ProtocolError>,
) -> Result<T, ProtocolError>
where
    for<'bytes> T: minicbor::Decode<'bytes, V2DecodeContext>,
{
    scan_single(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    let mut context = V2DecodeContext;
    let value = T::decode(&mut decoder, &mut context).map_err(ProtocolError::from_typed_decode)?;
    if decoder.position() != bytes.len() {
        return Err(ProtocolError::stable(StableCode::ProtocolMalformedCbor));
    }
    let canonical = encode(&value)?;
    if bytes != canonical {
        return Err(ProtocolError::stable(StableCode::ProtocolNonCanonicalCbor));
    }
    Ok(value)
}

const fn public_agent_control_error(code: StableCode) -> bool {
    matches!(
        code,
        StableCode::ProtocolMalformedFrame
            | StableCode::ProtocolFrameTooLarge
            | StableCode::ProtocolMalformedCbor
            | StableCode::ProtocolNonCanonicalCbor
            | StableCode::ProtocolUnknownOperation
            | StableCode::ProtocolUnsupportedVersion
            | StableCode::IdentityPeerRejected
            | StableCode::IdentityReplay
            | StableCode::DeadlineExceeded
            | StableCode::KernelOverloaded
            | StableCode::KernelUnavailable
            | StableCode::HandleUnknown
            | StableCode::HandleInvalidatedBoot
            | StableCode::CancellationTooLate
    )
}

fn expect_array(
    decoder: &mut minicbor::Decoder<'_>,
    position: usize,
    expected: u64,
) -> Result<(), minicbor::decode::Error> {
    if decoder.array()? == Some(expected) {
        Ok(())
    } else {
        Err(malformed(position))
    }
}

fn malformed(position: usize) -> minicbor::decode::Error {
    minicbor::decode::Error::message(StableCode::ProtocolMalformedCbor.as_str()).at(position)
}

fn encode_error<E>() -> minicbor::encode::Error<E> {
    minicbor::encode::Error::message(StableCode::ProtocolMalformedCbor.as_str())
}

fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}
