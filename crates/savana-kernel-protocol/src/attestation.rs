use crate::{
    BoundedText, Digest32, KeyId, Nonce32, PendingToolCallHandle, RunId, Signature64, StableCode,
    UnixMillis, ValidatorId,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidatorVerdictV1 {
    Pass,
    Fail,
}

impl<C> minicbor::Encode<C> for ValidatorVerdictV1 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        _context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.array(2)?.u8(match self {
            Self::Pass => 0,
            Self::Fail => 1,
        })?;
        encoder.array(0)?;
        Ok(())
    }
}

impl<'bytes, C> minicbor::Decode<'bytes, C> for ValidatorVerdictV1 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        _context: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        let position = decoder.position();
        if decoder.array()? != Some(2) {
            return Err(decode_error(position));
        }
        let value = match decoder.u8()? {
            0 => Self::Pass,
            1 => Self::Fail,
            _ => return Err(decode_error(position)),
        };
        if decoder.array()? != Some(0) {
            return Err(decode_error(position));
        }
        Ok(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, minicbor::Encode)]
#[cbor(array)]
pub struct SignedValidatorAttestationV1 {
    #[n(0)]
    pub validator_id: ValidatorId,
    #[n(1)]
    pub validator_version: BoundedText,
    #[n(2)]
    pub run_id: RunId,
    #[n(3)]
    pub pending: PendingToolCallHandle,
    #[n(4)]
    pub argument_digest: Digest32,
    #[n(5)]
    pub verdict: ValidatorVerdictV1,
    #[n(6)]
    pub public_reason: StableCode,
    #[n(7)]
    pub issued_at: UnixMillis,
    #[n(8)]
    pub expires_at: UnixMillis,
    #[n(9)]
    pub nonce: Nonce32,
    #[n(10)]
    pub key_id: KeyId,
    #[n(11)]
    pub signature: Signature64,
}

impl<'bytes, C> minicbor::Decode<'bytes, C> for SignedValidatorAttestationV1 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        let position = decoder.position();
        if decoder.array()? != Some(12) {
            return Err(decode_error(position));
        }
        Ok(Self {
            validator_id: ValidatorId::decode(decoder, context)?,
            validator_version: BoundedText::decode(decoder, context)?,
            run_id: RunId::decode(decoder, context)?,
            pending: PendingToolCallHandle::decode(decoder, context)?,
            argument_digest: Digest32::decode(decoder, context)?,
            verdict: ValidatorVerdictV1::decode(decoder, context)?,
            public_reason: StableCode::decode(decoder, context)?,
            issued_at: UnixMillis::decode(decoder, context)?,
            expires_at: UnixMillis::decode(decoder, context)?,
            nonce: Nonce32::decode(decoder, context)?,
            key_id: KeyId::decode(decoder, context)?,
            signature: Signature64::decode(decoder, context)?,
        })
    }
}

fn decode_error(position: usize) -> minicbor::decode::Error {
    minicbor::decode::Error::message(StableCode::ProtocolMalformedCbor.as_str()).at(position)
}
