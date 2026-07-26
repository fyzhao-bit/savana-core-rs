use crate::{
    BoundedText, ConversationId, Digest32, KeyId, Nonce32, PlannerId, PlannerTicketHandle,
    PrincipalId, ProtocolError, RunId, Signature64, StableCode, ToolHandle, ToolName, UnixMillis,
};

#[derive(Debug, Clone, PartialEq, Eq, minicbor::Encode)]
#[cbor(array)]
pub struct IngressEnvelopeV1 {
    #[n(0)]
    pub principal: PrincipalId,
    #[n(1)]
    pub conversation_id: ConversationId,
    #[n(2)]
    pub request_digest: Digest32,
    #[n(3)]
    pub issued_at: UnixMillis,
    #[n(4)]
    pub expires_at: UnixMillis,
    #[n(5)]
    pub nonce: Nonce32,
    #[n(6)]
    pub authority_session_id: Nonce32,
    #[n(7)]
    pub authentication_context_digest: Digest32,
}

impl<'bytes, C> minicbor::Decode<'bytes, C> for IngressEnvelopeV1 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        expect_array(decoder, 8)?;
        Ok(Self {
            principal: PrincipalId::decode(decoder, context)?,
            conversation_id: ConversationId::decode(decoder, context)?,
            request_digest: Digest32::decode(decoder, context)?,
            issued_at: UnixMillis::decode(decoder, context)?,
            expires_at: UnixMillis::decode(decoder, context)?,
            nonce: Nonce32::decode(decoder, context)?,
            authority_session_id: Nonce32::decode(decoder, context)?,
            authentication_context_digest: Digest32::decode(decoder, context)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, minicbor::Encode)]
#[cbor(array)]
pub struct SignedIngressEnvelopeV1 {
    #[n(0)]
    pub unsigned: IngressEnvelopeV1,
    #[n(1)]
    pub key_id: KeyId,
    #[n(2)]
    pub signature: Signature64,
}

impl<'bytes, C> minicbor::Decode<'bytes, C> for SignedIngressEnvelopeV1 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        expect_array(decoder, 3)?;
        Ok(Self {
            unsigned: IngressEnvelopeV1::decode(decoder, context)?,
            key_id: KeyId::decode(decoder, context)?,
            signature: Signature64::decode(decoder, context)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, minicbor::Encode)]
#[cbor(array)]
pub struct SignedPlannerAttestationV1 {
    #[n(0)]
    pub run_id: RunId,
    #[n(1)]
    pub planner_id: PlannerId,
    #[n(2)]
    pub planner_version: BoundedText,
    #[n(3)]
    pub prompt_digest: Digest32,
    #[n(4)]
    pub output_digest: Digest32,
    #[n(5)]
    pub issued_at: UnixMillis,
    #[n(6)]
    pub expires_at: UnixMillis,
    #[n(7)]
    pub nonce: Nonce32,
    #[n(8)]
    pub key_id: KeyId,
    #[n(9)]
    pub signature: Signature64,
}

impl<'bytes, C> minicbor::Decode<'bytes, C> for SignedPlannerAttestationV1 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        expect_array(decoder, 10)?;
        Ok(Self {
            run_id: RunId::decode(decoder, context)?,
            planner_id: PlannerId::decode(decoder, context)?,
            planner_version: BoundedText::decode(decoder, context)?,
            prompt_digest: Digest32::decode(decoder, context)?,
            output_digest: Digest32::decode(decoder, context)?,
            issued_at: UnixMillis::decode(decoder, context)?,
            expires_at: UnixMillis::decode(decoder, context)?,
            nonce: Nonce32::decode(decoder, context)?,
            key_id: KeyId::decode(decoder, context)?,
            signature: Signature64::decode(decoder, context)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
// V1 freezes the signed attestation directly in this proof.
#[allow(clippy::large_enum_variant)]
pub enum PlannerCommitProofV1 {
    DaemonTicket(PlannerTicketHandle),
    SignedAttestation(SignedPlannerAttestationV1),
}

impl<C> minicbor::Encode<C> for PlannerCommitProofV1 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.array(2)?;
        match self {
            Self::DaemonTicket(value) => {
                encoder.u8(0)?;
                value.encode(encoder, context)?;
            }
            Self::SignedAttestation(value) => {
                encoder.u8(1)?;
                value.encode(encoder, context)?;
            }
        }
        Ok(())
    }
}

impl<'bytes, C> minicbor::Decode<'bytes, C> for PlannerCommitProofV1 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        let position = decoder.position();
        if decoder.array()? != Some(2) {
            return Err(decode_error(position));
        }
        match decoder.u8()? {
            0 => Ok(Self::DaemonTicket(PlannerTicketHandle::decode(
                decoder, context,
            )?)),
            1 => Ok(Self::SignedAttestation(SignedPlannerAttestationV1::decode(
                decoder, context,
            )?)),
            _ => Err(decode_error(position)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, minicbor::Encode)]
#[cbor(array)]
pub struct ToolExecutionIdentity {
    #[n(0)]
    pub name: ToolName,
    #[n(1)]
    pub descriptor_digest: Digest32,
    #[n(2)]
    pub registry_version: u64,
}

impl<'bytes, C> minicbor::Decode<'bytes, C> for ToolExecutionIdentity {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        expect_array(decoder, 3)?;
        Ok(Self {
            name: ToolName::decode(decoder, context)?,
            descriptor_digest: Digest32::decode(decoder, context)?,
            registry_version: decoder.u64()?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, minicbor::Encode)]
#[cbor(array)]
pub struct ActiveToolView {
    #[n(0)]
    pub handle: ToolHandle,
    #[n(1)]
    pub identity: ToolExecutionIdentity,
}

impl<'bytes, C> minicbor::Decode<'bytes, C> for ActiveToolView {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        expect_array(decoder, 2)?;
        Ok(Self {
            handle: ToolHandle::decode(decoder, context)?,
            identity: ToolExecutionIdentity::decode(decoder, context)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionTrace {
    pub rule_ids: Vec<u16>,
    pub public_reason: StableCode,
}

impl DecisionTrace {
    pub(crate) const MAX_RULE_IDS: usize = 256;

    pub(crate) fn validate(&self) -> Result<(), ProtocolError> {
        if self.rule_ids.len() > Self::MAX_RULE_IDS
            || !self.rule_ids.windows(2).all(|pair| pair[0] < pair[1])
        {
            return Err(ProtocolError::stable(StableCode::ProtocolMalformedCbor));
        }
        Ok(())
    }
}

impl<C> minicbor::Encode<C> for DecisionTrace {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        self.validate().map_err(|_| {
            minicbor::encode::Error::message(StableCode::ProtocolMalformedCbor.as_str())
        })?;
        encoder.array(2)?.array(
            u64::try_from(self.rule_ids.len())
                .map_err(|error| minicbor::encode::Error::message(error.to_string()))?,
        )?;
        for rule in &self.rule_ids {
            encoder.u16(*rule)?;
        }
        self.public_reason.encode(encoder, context)?;
        Ok(())
    }
}

impl<'bytes, C> minicbor::Decode<'bytes, C> for DecisionTrace {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        let position = decoder.position();
        if decoder.array()? != Some(2) {
            return Err(decode_error(position));
        }
        let rule_position = decoder.position();
        let length = decoder
            .array()?
            .ok_or_else(|| decode_error(rule_position))?;
        let length = usize::try_from(length).map_err(|_| decode_error(rule_position))?;
        if length > Self::MAX_RULE_IDS {
            return Err(decode_error(rule_position));
        }
        let mut rule_ids = Vec::with_capacity(length);
        for _ in 0..length {
            let rule = decoder.u16()?;
            if rule_ids.last().is_some_and(|previous| *previous >= rule) {
                return Err(decode_error(rule_position));
            }
            rule_ids.push(rule);
        }
        let public_reason = StableCode::decode(decoder, context)?;
        Ok(Self {
            rule_ids,
            public_reason,
        })
    }
}

fn decode_error(position: usize) -> minicbor::decode::Error {
    minicbor::decode::Error::message(StableCode::ProtocolMalformedCbor.as_str()).at(position)
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
