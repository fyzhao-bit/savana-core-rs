use crate::{
    primitives::canonical_text_cmp, ActiveToolView, AttemptKindV1, BoundedText, ConstraintId,
    Digest32, KeyId, ProtocolError, RoleId, Signature64, StableCode, ToolExecutionIdentity,
    UnixMillis, ValidatorId,
};

pub(crate) const MAX_ACTIVE_TOOLS: usize = 256;
pub(crate) const MAX_REGISTRY_TOOLS: usize = 256;
const MAX_TOOL_ROLES: usize = 64;
const MAX_TOOL_CONSTRAINTS: usize = 64;
const MAX_TOOL_VALIDATORS: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolDescriptorV1 {
    pub identity: ToolExecutionIdentity,
    pub provider_id: BoundedText,
    pub roles: Vec<RoleId>,
    pub input_schema_digest: Digest32,
    pub output_schema_digest: Digest32,
    pub attempt: AttemptKindV1,
    pub constraint_ids: Vec<ConstraintId>,
    pub validator_ids: Vec<ValidatorId>,
    pub projection_digest: Digest32,
}

impl ToolDescriptorV1 {
    pub(crate) fn validate(&self) -> Result<(), ProtocolError> {
        if self.roles.len() > MAX_TOOL_ROLES
            || self.constraint_ids.len() > MAX_TOOL_CONSTRAINTS
            || self.validator_ids.len() > MAX_TOOL_VALIDATORS
            || !strictly_sorted_by(&self.roles, RoleId::as_str)
            || !strictly_sorted_by(&self.constraint_ids, ConstraintId::as_str)
            || !strictly_sorted_by(&self.validator_ids, ValidatorId::as_str)
        {
            return Err(malformed());
        }
        Ok(())
    }
}

impl<C> minicbor::Encode<C> for ToolDescriptorV1 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        self.validate().map_err(|_| encode_error())?;
        encoder.array(9)?;
        self.identity.encode(encoder, context)?;
        self.provider_id.encode(encoder, context)?;
        encode_slice(encoder, context, &self.roles)?;
        self.input_schema_digest.encode(encoder, context)?;
        self.output_schema_digest.encode(encoder, context)?;
        self.attempt.encode(encoder, context)?;
        encode_slice(encoder, context, &self.constraint_ids)?;
        encode_slice(encoder, context, &self.validator_ids)?;
        self.projection_digest.encode(encoder, context)?;
        Ok(())
    }
}

impl<'bytes, C> minicbor::Decode<'bytes, C> for ToolDescriptorV1 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        expect_array(decoder, 9)?;
        let identity = ToolExecutionIdentity::decode(decoder, context)?;
        let provider_id = BoundedText::decode(decoder, context)?;
        let roles = decode_vec(decoder, context, MAX_TOOL_ROLES)?;
        let input_schema_digest = Digest32::decode(decoder, context)?;
        let output_schema_digest = Digest32::decode(decoder, context)?;
        let attempt = AttemptKindV1::decode(decoder, context)?;
        let constraint_ids = decode_vec(decoder, context, MAX_TOOL_CONSTRAINTS)?;
        let validator_ids = decode_vec(decoder, context, MAX_TOOL_VALIDATORS)?;
        let projection_digest = Digest32::decode(decoder, context)?;
        let value = Self {
            identity,
            provider_id,
            roles,
            input_schema_digest,
            output_schema_digest,
            attempt,
            constraint_ids,
            validator_ids,
            projection_digest,
        };
        value
            .validate()
            .map_err(|_| decode_error(decoder.position()))?;
        Ok(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrySnapshotV1 {
    pub version: u64,
    pub previous_digest: Option<Digest32>,
    pub tools: Vec<ToolDescriptorV1>,
    pub issued_at: UnixMillis,
    pub expires_at: UnixMillis,
}

impl RegistrySnapshotV1 {
    pub(crate) fn validate(&self) -> Result<(), ProtocolError> {
        if self.version == 0
            || self.tools.len() > MAX_REGISTRY_TOOLS
            || !self.tools.windows(2).all(|pair| {
                canonical_text_cmp(
                    pair[0].identity.name.as_str(),
                    pair[1].identity.name.as_str(),
                )
                .is_lt()
            })
        {
            return Err(malformed());
        }
        for tool in &self.tools {
            tool.validate()?;
            if tool.identity.registry_version != self.version {
                return Err(malformed());
            }
        }
        Ok(())
    }
}

impl<C> minicbor::Encode<C> for RegistrySnapshotV1 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        self.validate().map_err(|_| encode_error())?;
        encoder.array(5)?.u64(self.version)?;
        encode_option(encoder, context, self.previous_digest.as_ref())?;
        encode_slice(encoder, context, &self.tools)?;
        self.issued_at.encode(encoder, context)?;
        self.expires_at.encode(encoder, context)?;
        Ok(())
    }
}

impl<'bytes, C> minicbor::Decode<'bytes, C> for RegistrySnapshotV1 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        expect_array(decoder, 5)?;
        let version = decoder.u64()?;
        let previous_digest = decode_option(decoder, context)?;
        let tools = decode_vec(decoder, context, MAX_REGISTRY_TOOLS)?;
        let issued_at = UnixMillis::decode(decoder, context)?;
        let expires_at = UnixMillis::decode(decoder, context)?;
        let value = Self {
            version,
            previous_digest,
            tools,
            issued_at,
            expires_at,
        };
        value
            .validate()
            .map_err(|_| decode_error(decoder.position()))?;
        Ok(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, minicbor::Encode)]
#[cbor(array)]
pub struct SignedRegistrySnapshotV1 {
    #[n(0)]
    pub unsigned: RegistrySnapshotV1,
    #[n(1)]
    pub key_id: KeyId,
    #[n(2)]
    pub signature: Signature64,
}

impl<'bytes, C> minicbor::Decode<'bytes, C> for SignedRegistrySnapshotV1 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        expect_array(decoder, 3)?;
        Ok(Self {
            unsigned: RegistrySnapshotV1::decode(decoder, context)?,
            key_id: KeyId::decode(decoder, context)?,
            signature: Signature64::decode(decoder, context)?,
        })
    }
}

pub(crate) fn validate_active_tools(tools: &[ActiveToolView]) -> Result<(), ProtocolError> {
    if tools.len() > MAX_ACTIVE_TOOLS
        || !tools.windows(2).all(|pair| {
            canonical_text_cmp(
                pair[0].identity.name.as_str(),
                pair[1].identity.name.as_str(),
            )
            .is_lt()
        })
    {
        return Err(malformed());
    }
    Ok(())
}

fn strictly_sorted_by<T>(values: &[T], key: impl Fn(&T) -> &str) -> bool {
    values
        .windows(2)
        .all(|pair| canonical_text_cmp(key(&pair[0]), key(&pair[1])).is_lt())
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
