use crate::{
    primitives::canonical_text_cmp, ConstraintId, Digest32, KeyId, ProtocolError, Signature64,
    StableCode, ToolName, UnixMillis, ValidatorId,
};

const MAX_ONTOLOGY_ENTRIES: usize = 100_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OntologyEffectV1 {
    Allow,
    Deny,
    RequireValidator,
}

impl<C> minicbor::Encode<C> for OntologyEffectV1 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        _context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.array(2)?.u8(match self {
            Self::Allow => 0,
            Self::Deny => 1,
            Self::RequireValidator => 2,
        })?;
        encoder.array(0)?;
        Ok(())
    }
}

impl<'bytes, C> minicbor::Decode<'bytes, C> for OntologyEffectV1 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        _context: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        let position = decoder.position();
        expect_array(decoder, 2)?;
        let value = match decoder.u8()? {
            0 => Self::Allow,
            1 => Self::Deny,
            2 => Self::RequireValidator,
            _ => return Err(decode_error(position)),
        };
        expect_array(decoder, 0)?;
        Ok(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OntologyEntryV1 {
    pub constraint_id: ConstraintId,
    pub tool: ToolName,
    pub effect: OntologyEffectV1,
    pub validator_id: Option<ValidatorId>,
}

impl OntologyEntryV1 {
    pub(crate) fn validate(&self) -> Result<(), ProtocolError> {
        let valid_binding = matches!(
            (self.effect, self.validator_id.is_some()),
            (OntologyEffectV1::RequireValidator, true)
                | (OntologyEffectV1::Allow | OntologyEffectV1::Deny, false)
        );
        if !valid_binding {
            return Err(malformed());
        }
        Ok(())
    }
}

impl<C> minicbor::Encode<C> for OntologyEntryV1 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        self.validate().map_err(|_| encode_error())?;
        encoder.array(4)?;
        self.constraint_id.encode(encoder, context)?;
        self.tool.encode(encoder, context)?;
        self.effect.encode(encoder, context)?;
        encode_option(encoder, context, self.validator_id.as_ref())?;
        Ok(())
    }
}

impl<'bytes, C> minicbor::Decode<'bytes, C> for OntologyEntryV1 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        expect_array(decoder, 4)?;
        let value = Self {
            constraint_id: ConstraintId::decode(decoder, context)?,
            tool: ToolName::decode(decoder, context)?,
            effect: OntologyEffectV1::decode(decoder, context)?,
            validator_id: decode_option(decoder, context)?,
        };
        value
            .validate()
            .map_err(|_| decode_error(decoder.position()))?;
        Ok(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OntologySnapshotV1 {
    pub version: u64,
    pub previous_digest: Option<Digest32>,
    pub entries: Vec<OntologyEntryV1>,
    pub issued_at: UnixMillis,
    pub expires_at: UnixMillis,
}

impl OntologySnapshotV1 {
    pub(crate) fn validate(&self) -> Result<(), ProtocolError> {
        if self.version == 0
            || self.entries.len() > MAX_ONTOLOGY_ENTRIES
            || !self.entries.windows(2).all(|pair| {
                canonical_text_cmp(
                    pair[0].constraint_id.as_str(),
                    pair[1].constraint_id.as_str(),
                )
                .is_lt()
            })
        {
            return Err(malformed());
        }
        for entry in &self.entries {
            entry.validate()?;
        }
        Ok(())
    }
}

impl<C> minicbor::Encode<C> for OntologySnapshotV1 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        self.validate().map_err(|_| encode_error())?;
        encoder.array(5)?.u64(self.version)?;
        encode_option(encoder, context, self.previous_digest.as_ref())?;
        encode_slice(encoder, context, &self.entries)?;
        self.issued_at.encode(encoder, context)?;
        self.expires_at.encode(encoder, context)?;
        Ok(())
    }
}

impl<'bytes, C> minicbor::Decode<'bytes, C> for OntologySnapshotV1 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        expect_array(decoder, 5)?;
        let value = Self {
            version: decoder.u64()?,
            previous_digest: decode_option(decoder, context)?,
            entries: decode_vec(decoder, context, MAX_ONTOLOGY_ENTRIES)?,
            issued_at: UnixMillis::decode(decoder, context)?,
            expires_at: UnixMillis::decode(decoder, context)?,
        };
        value
            .validate()
            .map_err(|_| decode_error(decoder.position()))?;
        Ok(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OntologyEventV1 {
    pub version: u64,
    pub previous_digest: Digest32,
    pub sequence: u64,
    pub replacement: OntologyEntryV1,
    pub issued_at: UnixMillis,
    pub expires_at: UnixMillis,
}

impl OntologyEventV1 {
    fn validate(&self) -> Result<(), ProtocolError> {
        if self.version == 0 {
            return Err(malformed());
        }
        self.replacement.validate()
    }
}

impl<C> minicbor::Encode<C> for OntologyEventV1 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        self.validate().map_err(|_| encode_error())?;
        encoder.array(6)?.u64(self.version)?;
        self.previous_digest.encode(encoder, context)?;
        encoder.u64(self.sequence)?;
        self.replacement.encode(encoder, context)?;
        self.issued_at.encode(encoder, context)?;
        self.expires_at.encode(encoder, context)?;
        Ok(())
    }
}

impl<'bytes, C> minicbor::Decode<'bytes, C> for OntologyEventV1 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        expect_array(decoder, 6)?;
        let value = Self {
            version: decoder.u64()?,
            previous_digest: Digest32::decode(decoder, context)?,
            sequence: decoder.u64()?,
            replacement: OntologyEntryV1::decode(decoder, context)?,
            issued_at: UnixMillis::decode(decoder, context)?,
            expires_at: UnixMillis::decode(decoder, context)?,
        };
        value
            .validate()
            .map_err(|_| decode_error(decoder.position()))?;
        Ok(value)
    }
}

macro_rules! signed_ontology {
    ($name:ident, $unsigned:ty) => {
        #[derive(Debug, Clone, PartialEq, Eq, minicbor::Encode)]
        #[cbor(array)]
        pub struct $name {
            #[n(0)]
            pub unsigned: $unsigned,
            #[n(1)]
            pub key_id: KeyId,
            #[n(2)]
            pub signature: Signature64,
        }

        impl<'bytes, C> minicbor::Decode<'bytes, C> for $name {
            fn decode(
                decoder: &mut minicbor::Decoder<'bytes>,
                context: &mut C,
            ) -> Result<Self, minicbor::decode::Error> {
                expect_array(decoder, 3)?;
                Ok(Self {
                    unsigned: <$unsigned>::decode(decoder, context)?,
                    key_id: KeyId::decode(decoder, context)?,
                    signature: Signature64::decode(decoder, context)?,
                })
            }
        }
    };
}

signed_ontology!(SignedOntologySnapshotV1, OntologySnapshotV1);
signed_ontology!(SignedOntologyEventV1, OntologyEventV1);

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

fn encode_option<C, W, T>(
    encoder: &mut minicbor::Encoder<W>,
    context: &mut C,
    value: Option<&T>,
) -> Result<(), minicbor::encode::Error<W::Error>>
where
    W: minicbor::encode::Write,
    T: minicbor::Encode<C>,
{
    match value {
        Some(value) => value.encode(encoder, context),
        None => {
            encoder.null()?;
            Ok(())
        }
    }
}

fn decode_option<'bytes, C, T>(
    decoder: &mut minicbor::Decoder<'bytes>,
    context: &mut C,
) -> Result<Option<T>, minicbor::decode::Error>
where
    T: minicbor::Decode<'bytes, C>,
{
    if decoder.datatype()? == minicbor::data::Type::Null {
        decoder.null()?;
        Ok(None)
    } else {
        Ok(Some(T::decode(decoder, context)?))
    }
}

fn malformed() -> ProtocolError {
    ProtocolError::stable(StableCode::ProtocolMalformedCbor)
}

fn decode_error(position: usize) -> minicbor::decode::Error {
    minicbor::decode::Error::message(StableCode::ProtocolMalformedCbor.as_str()).at(position)
}

fn encode_error<E>() -> minicbor::encode::Error<E> {
    minicbor::encode::Error::message(StableCode::ProtocolMalformedCbor.as_str())
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
