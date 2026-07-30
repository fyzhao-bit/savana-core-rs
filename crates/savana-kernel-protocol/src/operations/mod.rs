mod policy;

pub use policy::{
    AuthorizeToolCallRequest, BeginRunRequest, BeginRunResponse, CommitPlannerValueRequest,
    CommitToolResultRequest, DeriveValueRequest, EvaluateToolCallRequest,
    EvaluateToolCallResponseV1, ExecutionEnvelope, IngestUserInputRequest,
    MaterializeExecutionRequest, NamedArgumentHandle, PreparePlannerCallRequest,
    ProposeToolCallRequest,
};

use crate::{ProtocolError, StableCode};

#[derive(Debug, Clone, PartialEq, Eq)]
// V1 operation variants are the frozen direct wire schema.
#[allow(clippy::large_enum_variant)]
pub enum OperationV1 {
    Health,
    BeginRun(BeginRunRequest),
    IngestUserInput(IngestUserInputRequest),
    PreparePlannerCall(PreparePlannerCallRequest),
    CommitPlannerValue(CommitPlannerValueRequest),
    DeriveValue(DeriveValueRequest),
    ProposeToolCall(ProposeToolCallRequest),
    EvaluateToolCall(EvaluateToolCallRequest),
    AuthorizeToolCall(AuthorizeToolCallRequest),
    MaterializeExecution(MaterializeExecutionRequest),
    CommitToolResult(CommitToolResultRequest),
}

impl OperationV1 {
    pub(crate) fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Self::BeginRun(request) => request.registry.unsigned.validate(),
            Self::PreparePlannerCall(request) => {
                if request.prompt_values.len() > policy::MAX_PROMPT_VALUES {
                    Err(ProtocolError::stable(StableCode::ProtocolMalformedCbor))
                } else {
                    Ok(())
                }
            }
            Self::DeriveValue(request) => request.validate(),
            Self::ProposeToolCall(request) => request.validate(),
            Self::EvaluateToolCall(request) => request.validate(),
            Self::Health
            | Self::IngestUserInput(_)
            | Self::CommitPlannerValue(_)
            | Self::AuthorizeToolCall(_)
            | Self::MaterializeExecution(_)
            | Self::CommitToolResult(_) => Ok(()),
        }
    }
}

impl<C> minicbor::Encode<C> for OperationV1 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        self.validate().map_err(|_| {
            minicbor::encode::Error::message(StableCode::ProtocolMalformedCbor.as_str())
        })?;
        encoder.array(2)?;
        match self {
            Self::Health => {
                encoder.u8(0)?.array(0)?;
            }
            Self::BeginRun(value) => {
                encoder.u8(10)?;
                value.encode(encoder, context)?;
            }
            Self::IngestUserInput(value) => {
                encoder.u8(11)?;
                value.encode(encoder, context)?;
            }
            Self::PreparePlannerCall(value) => {
                encoder.u8(12)?;
                value.encode(encoder, context)?;
            }
            Self::CommitPlannerValue(value) => {
                encoder.u8(13)?;
                value.encode(encoder, context)?;
            }
            Self::DeriveValue(value) => {
                encoder.u8(14)?;
                value.encode(encoder, context)?;
            }
            Self::ProposeToolCall(value) => {
                encoder.u8(15)?;
                value.encode(encoder, context)?;
            }
            Self::EvaluateToolCall(value) => {
                encoder.u8(16)?;
                value.encode(encoder, context)?;
            }
            Self::AuthorizeToolCall(value) => {
                encoder.u8(17)?;
                value.encode(encoder, context)?;
            }
            Self::MaterializeExecution(value) => {
                encoder.u8(18)?;
                value.encode(encoder, context)?;
            }
            Self::CommitToolResult(value) => {
                encoder.u8(19)?;
                value.encode(encoder, context)?;
            }
        }
        Ok(())
    }
}

impl<'bytes, C> minicbor::Decode<'bytes, C> for OperationV1 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        let position = decoder.position();
        if decoder.array()? != Some(2) {
            return Err(malformed(position));
        }
        let value = match decoder.u8()? {
            0 => {
                if decoder.array()? != Some(0) {
                    return Err(malformed(position));
                }
                Self::Health
            }
            10 => Self::BeginRun(BeginRunRequest::decode(decoder, context)?),
            11 => Self::IngestUserInput(IngestUserInputRequest::decode(decoder, context)?),
            12 => Self::PreparePlannerCall(PreparePlannerCallRequest::decode(decoder, context)?),
            13 => Self::CommitPlannerValue(CommitPlannerValueRequest::decode(decoder, context)?),
            14 => Self::DeriveValue(DeriveValueRequest::decode(decoder, context)?),
            15 => Self::ProposeToolCall(ProposeToolCallRequest::decode(decoder, context)?),
            16 => Self::EvaluateToolCall(EvaluateToolCallRequest::decode(decoder, context)?),
            17 => Self::AuthorizeToolCall(AuthorizeToolCallRequest::decode(decoder, context)?),
            18 => {
                Self::MaterializeExecution(MaterializeExecutionRequest::decode(decoder, context)?)
            }
            19 => Self::CommitToolResult(CommitToolResultRequest::decode(decoder, context)?),
            _ => {
                return Err(minicbor::decode::Error::message(
                    StableCode::ProtocolUnknownOperation.as_str(),
                )
                .at(position))
            }
        };
        value.validate().map_err(|_| malformed(position))?;
        Ok(value)
    }
}

fn malformed(position: usize) -> minicbor::decode::Error {
    minicbor::decode::Error::message(StableCode::ProtocolMalformedCbor.as_str()).at(position)
}
