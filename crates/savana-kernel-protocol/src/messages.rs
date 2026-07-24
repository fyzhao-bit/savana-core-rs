use crate::{
    BootId, ClientId, Digest32, KeyId, Nonce32, ProtocolVersion, RequestId, RequestedMode,
    Signature64, StableCode, UnixMillis,
};

#[derive(Debug, Clone, PartialEq, Eq, minicbor::Encode, minicbor::Decode)]
#[cbor(array)]
pub struct ClientHelloV1 {
    #[n(0)]
    pub client_nonce: Nonce32,
    #[n(1)]
    pub supported_versions: Vec<ProtocolVersion>,
    #[n(2)]
    pub client_id: ClientId,
    #[n(3)]
    pub client_key_id: KeyId,
    #[n(4)]
    pub requested_mode: RequestedMode,
}

#[derive(Debug, Clone, PartialEq, Eq, minicbor::Encode, minicbor::Decode)]
#[cbor(array)]
pub struct ClientFinishV1 {
    #[n(0)]
    pub transcript_digest: Digest32,
    #[n(1)]
    pub signature: Signature64,
}

#[derive(Debug, Clone, PartialEq, Eq, minicbor::Encode, minicbor::Decode)]
#[cbor(array)]
pub struct RequestEnvelopeV1 {
    #[n(0)]
    pub version: ProtocolVersion,
    #[n(1)]
    pub request_id: RequestId,
    #[n(2)]
    pub deadline_unix_ms: UnixMillis,
    #[n(3)]
    pub operation: OperationV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationV1 {
    Health,
}

#[derive(Debug, Clone, PartialEq, Eq, minicbor::Encode, minicbor::Decode)]
#[cbor(array)]
pub struct ServerIdentityV1 {
    #[n(0)]
    pub daemon_key_id: KeyId,
    #[n(1)]
    pub boot_id: BootId,
    #[n(2)]
    pub protocol: ProtocolVersion,
    #[n(3)]
    pub release_digest: Digest32,
    #[n(4)]
    pub policy_digest: Digest32,
    #[n(5)]
    pub policy_version: u64,
    #[n(6)]
    pub model_manifest_digest: Digest32,
    #[n(7)]
    pub approval_key_set_digest: Digest32,
    #[n(8)]
    pub resource_profile_digest: Digest32,
}

#[derive(Debug, Clone, PartialEq, Eq, minicbor::Encode, minicbor::Decode)]
#[cbor(array)]
pub struct HandshakeTranscriptV1 {
    #[n(0)]
    pub client: ClientHelloV1,
    #[n(1)]
    pub server_nonce: Nonce32,
    #[n(2)]
    pub server: ServerIdentityV1,
}

#[derive(Debug, Clone, PartialEq, Eq, minicbor::Encode, minicbor::Decode)]
#[cbor(array)]
pub struct SignedServerHelloV1 {
    #[n(0)]
    pub transcript: HandshakeTranscriptV1,
    #[n(1)]
    pub signature: Signature64,
}

#[derive(Debug, Clone, PartialEq, Eq, minicbor::Encode, minicbor::Decode)]
#[cbor(array)]
pub struct HandshakeAcceptedV1 {
    #[n(0)]
    pub boot_id: BootId,
    #[n(1)]
    pub protocol: ProtocolVersion,
}

#[derive(Debug, Clone, PartialEq, Eq, minicbor::Encode, minicbor::Decode)]
#[cbor(array)]
pub struct ResponseEnvelopeV1 {
    #[n(0)]
    pub version: ProtocolVersion,
    #[n(1)]
    pub request_id: RequestId,
    #[n(2)]
    pub body: ResponseBodyV1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
// The frozen V1 public schema embeds its typed success payload directly.
#[allow(clippy::large_enum_variant)]
pub enum ResponseBodyV1 {
    Ok(ResponsePayloadV1),
    Err(StableCode),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponsePayloadV1 {
    Health(HealthSnapshotV1),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthSnapshotV1 {
    pub ready: bool,
    pub identity: ServerIdentityV1,
    pub last_error: Option<StableCode>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientMessageV1 {
    Hello(ClientHelloV1),
    Finish(ClientFinishV1),
    Request(RequestEnvelopeV1),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerMessageV1 {
    Hello(SignedServerHelloV1),
    Accepted(HandshakeAcceptedV1),
    Response(ResponseEnvelopeV1),
}

fn encode_tagged<C, W, T>(
    encoder: &mut minicbor::Encoder<W>,
    context: &mut C,
    tag: u8,
    value: &T,
) -> Result<(), minicbor::encode::Error<W::Error>>
where
    W: minicbor::encode::Write,
    T: minicbor::Encode<C>,
{
    encoder.array(2)?.u8(tag)?;
    value.encode(encoder, context)
}

fn decode_tag(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<(usize, u64), minicbor::decode::Error> {
    let position = decoder.position();
    match decoder.array()? {
        Some(2) => Ok((position, decoder.u64()?)),
        _ => Err(
            minicbor::decode::Error::message(StableCode::ProtocolMalformedCbor.as_str())
                .at(position),
        ),
    }
}

fn unknown_operation(position: usize) -> minicbor::decode::Error {
    minicbor::decode::Error::message(StableCode::ProtocolUnknownOperation.as_str()).at(position)
}

impl<C> minicbor::Encode<C> for OperationV1 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        _context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        match self {
            Self::Health => {
                encoder.array(2)?.u8(0)?.array(0)?;
            }
        }
        Ok(())
    }
}

impl<'bytes, C> minicbor::Decode<'bytes, C> for OperationV1 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        _context: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        let (position, tag) = decode_tag(decoder)?;
        match tag {
            0 => match decoder.array()? {
                Some(0) => Ok(Self::Health),
                _ => Err(minicbor::decode::Error::message(
                    StableCode::ProtocolMalformedCbor.as_str(),
                )
                .at(position)),
            },
            _ => Err(unknown_operation(position)),
        }
    }
}

impl<C> minicbor::Encode<C> for ResponseBodyV1 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        match self {
            Self::Ok(value) => encode_tagged(encoder, context, 0, value),
            Self::Err(value) => encode_tagged(encoder, context, 1, value),
        }
    }
}

impl<'bytes, C> minicbor::Decode<'bytes, C> for ResponseBodyV1 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        let (position, tag) = decode_tag(decoder)?;
        match tag {
            0 => Ok(Self::Ok(ResponsePayloadV1::decode(decoder, context)?)),
            1 => Ok(Self::Err(StableCode::decode(decoder, context)?)),
            _ => Err(unknown_operation(position)),
        }
    }
}

impl<C> minicbor::Encode<C> for ResponsePayloadV1 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        match self {
            Self::Health(value) => encode_tagged(encoder, context, 0, value),
        }
    }
}

impl<'bytes, C> minicbor::Decode<'bytes, C> for ResponsePayloadV1 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        let (position, tag) = decode_tag(decoder)?;
        match tag {
            0 => Ok(Self::Health(HealthSnapshotV1::decode(decoder, context)?)),
            _ => Err(unknown_operation(position)),
        }
    }
}

impl<C> minicbor::Encode<C> for HealthSnapshotV1 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.array(3)?.bool(self.ready)?;
        self.identity.encode(encoder, context)?;
        match self.last_error {
            Some(error) => error.encode(encoder, context)?,
            None => {
                encoder.null()?;
            }
        }
        Ok(())
    }
}

impl<'bytes, C> minicbor::Decode<'bytes, C> for HealthSnapshotV1 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        let position = decoder.position();
        if decoder.array()? != Some(3) {
            return Err(minicbor::decode::Error::message(
                StableCode::ProtocolMalformedCbor.as_str(),
            )
            .at(position));
        }
        let ready = decoder.bool()?;
        let identity = ServerIdentityV1::decode(decoder, context)?;
        let last_error = if decoder.datatype()? == minicbor::data::Type::Null {
            decoder.null()?;
            None
        } else {
            Some(StableCode::decode(decoder, context)?)
        };
        Ok(Self {
            ready,
            identity,
            last_error,
        })
    }
}

impl<C> minicbor::Encode<C> for ClientMessageV1 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        match self {
            Self::Hello(value) => encode_tagged(encoder, context, 0, value),
            Self::Finish(value) => encode_tagged(encoder, context, 1, value),
            Self::Request(value) => encode_tagged(encoder, context, 2, value),
        }
    }
}

impl<'bytes, C> minicbor::Decode<'bytes, C> for ClientMessageV1 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        let (position, tag) = decode_tag(decoder)?;
        match tag {
            0 => Ok(Self::Hello(ClientHelloV1::decode(decoder, context)?)),
            1 => Ok(Self::Finish(ClientFinishV1::decode(decoder, context)?)),
            2 => Ok(Self::Request(RequestEnvelopeV1::decode(decoder, context)?)),
            _ => Err(unknown_operation(position)),
        }
    }
}

impl<C> minicbor::Encode<C> for ServerMessageV1 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        match self {
            Self::Hello(value) => encode_tagged(encoder, context, 0, value),
            Self::Accepted(value) => encode_tagged(encoder, context, 1, value),
            Self::Response(value) => encode_tagged(encoder, context, 2, value),
        }
    }
}

impl<'bytes, C> minicbor::Decode<'bytes, C> for ServerMessageV1 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        let (position, tag) = decode_tag(decoder)?;
        match tag {
            0 => Ok(Self::Hello(SignedServerHelloV1::decode(decoder, context)?)),
            1 => Ok(Self::Accepted(HandshakeAcceptedV1::decode(
                decoder, context,
            )?)),
            2 => Ok(Self::Response(ResponseEnvelopeV1::decode(
                decoder, context,
            )?)),
            _ => Err(unknown_operation(position)),
        }
    }
}

pub(crate) fn validate_client_message(value: &ClientMessageV1) -> Result<(), crate::ProtocolError> {
    match value {
        ClientMessageV1::Hello(hello) => validate_client_hello(hello),
        ClientMessageV1::Finish(_) | ClientMessageV1::Request(_) => Ok(()),
    }
}

pub(crate) fn validate_server_message(value: &ServerMessageV1) -> Result<(), crate::ProtocolError> {
    match value {
        ServerMessageV1::Hello(hello) => validate_client_hello(&hello.transcript.client),
        ServerMessageV1::Accepted(_) | ServerMessageV1::Response(_) => Ok(()),
    }
}

fn validate_client_hello(value: &ClientHelloV1) -> Result<(), crate::ProtocolError> {
    if !(1..=16).contains(&value.supported_versions.len()) {
        return Err(crate::ProtocolError::stable(
            StableCode::ProtocolMalformedCbor,
        ));
    }
    for (index, version) in value.supported_versions.iter().enumerate() {
        if value.supported_versions[..index].contains(version) {
            return Err(crate::ProtocolError::stable(
                StableCode::ProtocolMalformedCbor,
            ));
        }
    }
    Ok(())
}
