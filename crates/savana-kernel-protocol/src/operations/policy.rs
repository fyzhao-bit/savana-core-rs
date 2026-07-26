use crate::{
    primitives::canonical_text_cmp, registry::validate_active_tools, ActiveToolView,
    ApprovalReceiptV1, ArgumentName, DecisionTrace, DeriveOperation, Digest32,
    ExecutionTicketHandle, KernelValue, PendingToolCallHandle, PlannerCommitProofV1, PlannerId,
    ProtocolError, RunHandle, SignedApprovalEnvelopeV1, SignedIngressEnvelopeV1,
    SignedRegistrySnapshotV1, SignedValidatorAttestationV1, StableCode, ToolExecutionIdentity,
    ToolHandle, ValueHandle,
};

pub(crate) const MAX_PROMPT_VALUES: usize = 256;
pub(crate) const MAX_DERIVE_INPUTS: usize = 256;
pub(crate) const MAX_NAMED_ARGUMENTS: usize = 256;
pub(crate) const MAX_ATTESTATIONS: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, minicbor::Encode)]
#[cbor(array)]
pub struct BeginRunRequest {
    #[n(0)]
    pub ingress: SignedIngressEnvelopeV1,
    #[n(1)]
    pub input: KernelValue,
    #[n(2)]
    pub registry: SignedRegistrySnapshotV1,
}

impl<'bytes, C> minicbor::Decode<'bytes, C> for BeginRunRequest {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        expect_array(decoder, 3)?;
        Ok(Self {
            ingress: SignedIngressEnvelopeV1::decode(decoder, context)?,
            input: KernelValue::decode(decoder, context)?,
            registry: SignedRegistrySnapshotV1::decode(decoder, context)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BeginRunResponse {
    pub run: RunHandle,
    pub initial_value: ValueHandle,
    pub active_tools: Vec<ActiveToolView>,
}

impl BeginRunResponse {
    pub(crate) fn validate(&self) -> Result<(), ProtocolError> {
        validate_active_tools(&self.active_tools)
    }
}

impl<C> minicbor::Encode<C> for BeginRunResponse {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        self.validate().map_err(|_| encode_error())?;
        encoder.array(3)?;
        self.run.encode(encoder, context)?;
        self.initial_value.encode(encoder, context)?;
        encode_slice(encoder, context, &self.active_tools)?;
        Ok(())
    }
}

impl<'bytes, C> minicbor::Decode<'bytes, C> for BeginRunResponse {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        expect_array(decoder, 3)?;
        let run = RunHandle::decode(decoder, context)?;
        let initial_value = ValueHandle::decode(decoder, context)?;
        let active_tools = decode_vec(decoder, context, crate::registry::MAX_ACTIVE_TOOLS)?;
        let value = Self {
            run,
            initial_value,
            active_tools,
        };
        value
            .validate()
            .map_err(|_| decode_error(decoder.position()))?;
        Ok(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, minicbor::Encode)]
#[cbor(array)]
pub struct NamedArgumentHandle {
    #[n(0)]
    pub name: ArgumentName,
    #[n(1)]
    pub value: ValueHandle,
}

impl<'bytes, C> minicbor::Decode<'bytes, C> for NamedArgumentHandle {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        expect_array(decoder, 2)?;
        Ok(Self {
            name: ArgumentName::decode(decoder, context)?,
            value: ValueHandle::decode(decoder, context)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, minicbor::Encode)]
#[cbor(array)]
pub struct IngestUserInputRequest {
    #[n(0)]
    pub run: RunHandle,
    #[n(1)]
    pub envelope: SignedIngressEnvelopeV1,
    #[n(2)]
    pub input: KernelValue,
}

impl<'bytes, C> minicbor::Decode<'bytes, C> for IngestUserInputRequest {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        expect_array(decoder, 3)?;
        Ok(Self {
            run: RunHandle::decode(decoder, context)?,
            envelope: SignedIngressEnvelopeV1::decode(decoder, context)?,
            input: KernelValue::decode(decoder, context)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparePlannerCallRequest {
    pub run: RunHandle,
    pub planner: PlannerId,
    pub prompt_values: Vec<ValueHandle>,
}

impl<C> minicbor::Encode<C> for PreparePlannerCallRequest {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        require_max(self.prompt_values.len(), MAX_PROMPT_VALUES).map_err(|_| encode_error())?;
        encoder.array(3)?;
        self.run.encode(encoder, context)?;
        self.planner.encode(encoder, context)?;
        encode_slice(encoder, context, &self.prompt_values)?;
        Ok(())
    }
}

impl<'bytes, C> minicbor::Decode<'bytes, C> for PreparePlannerCallRequest {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        expect_array(decoder, 3)?;
        Ok(Self {
            run: RunHandle::decode(decoder, context)?,
            planner: PlannerId::decode(decoder, context)?,
            prompt_values: decode_vec(decoder, context, MAX_PROMPT_VALUES)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, minicbor::Encode)]
#[cbor(array)]
pub struct CommitPlannerValueRequest {
    #[n(0)]
    pub run: RunHandle,
    #[n(1)]
    pub proof: PlannerCommitProofV1,
    #[n(2)]
    pub value: KernelValue,
}

impl<'bytes, C> minicbor::Decode<'bytes, C> for CommitPlannerValueRequest {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        expect_array(decoder, 3)?;
        Ok(Self {
            run: RunHandle::decode(decoder, context)?,
            proof: PlannerCommitProofV1::decode(decoder, context)?,
            value: KernelValue::decode(decoder, context)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeriveValueRequest {
    pub run: RunHandle,
    pub operation: DeriveOperation,
    pub inputs: Vec<ValueHandle>,
}

impl DeriveValueRequest {
    pub(crate) fn validate(&self) -> Result<(), ProtocolError> {
        require_max(self.inputs.len(), MAX_DERIVE_INPUTS)?;
        if let DeriveOperation::AssembleObject(names) = &self.operation {
            if names.as_slice().len() != self.inputs.len() {
                return Err(malformed());
            }
        }
        Ok(())
    }
}

impl<C> minicbor::Encode<C> for DeriveValueRequest {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        self.validate().map_err(|_| encode_error())?;
        encoder.array(3)?;
        self.run.encode(encoder, context)?;
        self.operation.encode(encoder, context)?;
        encode_slice(encoder, context, &self.inputs)?;
        Ok(())
    }
}

impl<'bytes, C> minicbor::Decode<'bytes, C> for DeriveValueRequest {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        expect_array(decoder, 3)?;
        let value = Self {
            run: RunHandle::decode(decoder, context)?,
            operation: DeriveOperation::decode(decoder, context)?,
            inputs: decode_vec(decoder, context, MAX_DERIVE_INPUTS)?,
        };
        value
            .validate()
            .map_err(|_| decode_error(decoder.position()))?;
        Ok(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposeToolCallRequest {
    pub run: RunHandle,
    pub tool: ToolHandle,
    pub arguments: Vec<NamedArgumentHandle>,
}

impl ProposeToolCallRequest {
    pub(crate) fn validate(&self) -> Result<(), ProtocolError> {
        if self.arguments.len() > MAX_NAMED_ARGUMENTS
            || !self.arguments.windows(2).all(|pair| {
                canonical_text_cmp(pair[0].name.as_str(), pair[1].name.as_str()).is_lt()
            })
        {
            return Err(malformed());
        }
        Ok(())
    }
}

impl<C> minicbor::Encode<C> for ProposeToolCallRequest {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        self.validate().map_err(|_| encode_error())?;
        encoder.array(3)?;
        self.run.encode(encoder, context)?;
        self.tool.encode(encoder, context)?;
        encode_slice(encoder, context, &self.arguments)?;
        Ok(())
    }
}

impl<'bytes, C> minicbor::Decode<'bytes, C> for ProposeToolCallRequest {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        expect_array(decoder, 3)?;
        let value = Self {
            run: RunHandle::decode(decoder, context)?,
            tool: ToolHandle::decode(decoder, context)?,
            arguments: decode_vec(decoder, context, MAX_NAMED_ARGUMENTS)?,
        };
        value
            .validate()
            .map_err(|_| decode_error(decoder.position()))?;
        Ok(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluateToolCallRequest {
    pub pending: PendingToolCallHandle,
    pub attestations: Vec<SignedValidatorAttestationV1>,
}

impl EvaluateToolCallRequest {
    pub(crate) fn validate(&self) -> Result<(), ProtocolError> {
        if self.attestations.len() > MAX_ATTESTATIONS
            || !self.attestations.windows(2).all(|pair| {
                canonical_text_cmp(pair[0].validator_id.as_str(), pair[1].validator_id.as_str())
                    .is_lt()
            })
        {
            return Err(malformed());
        }
        Ok(())
    }
}

impl<C> minicbor::Encode<C> for EvaluateToolCallRequest {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        self.validate().map_err(|_| encode_error())?;
        encoder.array(2)?;
        self.pending.encode(encoder, context)?;
        encode_slice(encoder, context, &self.attestations)?;
        Ok(())
    }
}

impl<'bytes, C> minicbor::Decode<'bytes, C> for EvaluateToolCallRequest {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        expect_array(decoder, 2)?;
        let value = Self {
            pending: PendingToolCallHandle::decode(decoder, context)?,
            attestations: decode_vec(decoder, context, MAX_ATTESTATIONS)?,
        };
        value
            .validate()
            .map_err(|_| decode_error(decoder.position()))?;
        Ok(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, minicbor::Encode)]
#[cbor(array)]
pub struct AuthorizeToolCallRequest {
    #[n(0)]
    pub pending: PendingToolCallHandle,
    #[n(1)]
    pub receipt: ApprovalReceiptV1,
}

impl<'bytes, C> minicbor::Decode<'bytes, C> for AuthorizeToolCallRequest {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        expect_array(decoder, 2)?;
        Ok(Self {
            pending: PendingToolCallHandle::decode(decoder, context)?,
            receipt: ApprovalReceiptV1::decode(decoder, context)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, minicbor::Encode)]
#[cbor(array)]
pub struct MaterializeExecutionRequest {
    #[n(0)]
    pub ticket: ExecutionTicketHandle,
}

impl<'bytes, C> minicbor::Decode<'bytes, C> for MaterializeExecutionRequest {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        expect_array(decoder, 1)?;
        Ok(Self {
            ticket: ExecutionTicketHandle::decode(decoder, context)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, minicbor::Encode)]
#[cbor(array)]
pub struct CommitToolResultRequest {
    #[n(0)]
    pub ticket: ExecutionTicketHandle,
    #[n(1)]
    pub result: KernelValue,
}

impl<'bytes, C> minicbor::Decode<'bytes, C> for CommitToolResultRequest {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        expect_array(decoder, 2)?;
        Ok(Self {
            ticket: ExecutionTicketHandle::decode(decoder, context)?,
            result: KernelValue::decode(decoder, context)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
// V1 freezes the signed approval envelope directly in this response.
#[allow(clippy::large_enum_variant)]
pub enum EvaluateToolCallResponseV1 {
    Denied {
        code: StableCode,
        trace: DecisionTrace,
    },
    NeedsApproval {
        envelope: SignedApprovalEnvelopeV1,
        trace: DecisionTrace,
    },
    Allowed {
        ticket: ExecutionTicketHandle,
        trace: DecisionTrace,
    },
}

impl EvaluateToolCallResponseV1 {
    pub(crate) fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Self::Denied { trace, .. }
            | Self::NeedsApproval { trace, .. }
            | Self::Allowed { trace, .. } => trace.validate(),
        }
    }
}

impl<C> minicbor::Encode<C> for EvaluateToolCallResponseV1 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        self.validate().map_err(|_| encode_error())?;
        encoder.array(2)?;
        match self {
            Self::Denied { code, trace } => {
                encoder.u8(0)?.array(2)?;
                code.encode(encoder, context)?;
                trace.encode(encoder, context)?;
            }
            Self::NeedsApproval { envelope, trace } => {
                encoder.u8(1)?.array(2)?;
                envelope.encode(encoder, context)?;
                trace.encode(encoder, context)?;
            }
            Self::Allowed { ticket, trace } => {
                encoder.u8(2)?.array(2)?;
                ticket.encode(encoder, context)?;
                trace.encode(encoder, context)?;
            }
        }
        Ok(())
    }
}

impl<'bytes, C> minicbor::Decode<'bytes, C> for EvaluateToolCallResponseV1 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        let position = decoder.position();
        expect_array(decoder, 2)?;
        let value = match decoder.u8()? {
            0 => {
                expect_array(decoder, 2)?;
                Self::Denied {
                    code: StableCode::decode(decoder, context)?,
                    trace: DecisionTrace::decode(decoder, context)?,
                }
            }
            1 => {
                expect_array(decoder, 2)?;
                Self::NeedsApproval {
                    envelope: SignedApprovalEnvelopeV1::decode(decoder, context)?,
                    trace: DecisionTrace::decode(decoder, context)?,
                }
            }
            2 => {
                expect_array(decoder, 2)?;
                Self::Allowed {
                    ticket: ExecutionTicketHandle::decode(decoder, context)?,
                    trace: DecisionTrace::decode(decoder, context)?,
                }
            }
            _ => return Err(decode_error(position)),
        };
        value
            .validate()
            .map_err(|_| decode_error(decoder.position()))?;
        Ok(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, minicbor::Encode)]
#[cbor(array)]
pub struct ExecutionEnvelope {
    #[n(0)]
    pub tool: ToolExecutionIdentity,
    #[n(1)]
    pub arguments: KernelValue,
    #[n(2)]
    pub argument_digest: Digest32,
    #[n(3)]
    pub execution_nonce: crate::Nonce32,
}

impl<'bytes, C> minicbor::Decode<'bytes, C> for ExecutionEnvelope {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        expect_array(decoder, 4)?;
        Ok(Self {
            tool: ToolExecutionIdentity::decode(decoder, context)?,
            arguments: KernelValue::decode(decoder, context)?,
            argument_digest: Digest32::decode(decoder, context)?,
            execution_nonce: crate::Nonce32::decode(decoder, context)?,
        })
    }
}

fn malformed() -> ProtocolError {
    ProtocolError::stable(StableCode::ProtocolMalformedCbor)
}

fn require_max(length: usize, maximum: usize) -> Result<(), ProtocolError> {
    if length > maximum {
        Err(malformed())
    } else {
        Ok(())
    }
}

fn expect_array(
    decoder: &mut minicbor::Decoder<'_>,
    expected: u64,
) -> Result<(), minicbor::decode::Error> {
    let position = decoder.position();
    if decoder.array()? == Some(expected) {
        Ok(())
    } else {
        Err(decode_error(position))
    }
}

fn decode_error(position: usize) -> minicbor::decode::Error {
    minicbor::decode::Error::message(StableCode::ProtocolMalformedCbor.as_str()).at(position)
}

fn encode_error<E>() -> minicbor::encode::Error<E> {
    minicbor::encode::Error::message(StableCode::ProtocolMalformedCbor.as_str())
}

fn encode_slice<C, W, T>(
    encoder: &mut minicbor::Encoder<W>,
    context: &mut C,
    values: &[T],
) -> Result<(), minicbor::encode::Error<W::Error>>
where
    W: minicbor::encode::Write,
    T: minicbor::Encode<C>,
{
    encoder.array(
        u64::try_from(values.len())
            .map_err(|error| minicbor::encode::Error::message(error.to_string()))?,
    )?;
    for value in values {
        value.encode(encoder, context)?;
    }
    Ok(())
}

fn decode_vec<'bytes, C, T>(
    decoder: &mut minicbor::Decoder<'bytes>,
    context: &mut C,
    maximum: usize,
) -> Result<Vec<T>, minicbor::decode::Error>
where
    T: minicbor::Decode<'bytes, C>,
{
    let position = decoder.position();
    let length = decoder.array()?.ok_or_else(|| decode_error(position))?;
    let length = usize::try_from(length).map_err(|_| decode_error(position))?;
    if length > maximum {
        return Err(decode_error(position));
    }
    let mut values = Vec::with_capacity(length);
    for _ in 0..length {
        values.push(T::decode(decoder, context)?);
    }
    Ok(values)
}
