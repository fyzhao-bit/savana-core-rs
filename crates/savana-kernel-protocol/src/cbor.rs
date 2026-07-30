use crate::{
    messages::{validate_client_message, validate_server_message},
    ClientMessageV1, EffectiveLimits, ProtocolError, ServerMessageV1, StableCode,
};

pub fn encode_client_message(value: &ClientMessageV1) -> Result<Vec<u8>, ProtocolError> {
    validate_client_message(value)?;
    minicbor::to_vec(value).map_err(ProtocolError::malformed)
}

pub fn decode_client_message(
    bytes: &[u8],
    limits: &EffectiveLimits,
) -> Result<ClientMessageV1, ProtocolError> {
    scan_single(bytes, limits)?;
    validate_client_shape(bytes)?;
    let value = decode_typed::<ClientMessageV1>(bytes)?;
    validate_client_message(&value)?;
    require_canonical(bytes, &encode_client_message(&value)?)?;
    Ok(value)
}

pub fn encode_server_message(value: &ServerMessageV1) -> Result<Vec<u8>, ProtocolError> {
    validate_server_message(value)?;
    minicbor::to_vec(value).map_err(ProtocolError::malformed)
}

pub fn decode_server_message(
    bytes: &[u8],
    limits: &EffectiveLimits,
) -> Result<ServerMessageV1, ProtocolError> {
    scan_single(bytes, limits)?;
    validate_server_shape(bytes)?;
    let value = decode_typed::<ServerMessageV1>(bytes)?;
    validate_server_message(&value)?;
    require_canonical(bytes, &encode_server_message(&value)?)?;
    Ok(value)
}

fn scan_single(bytes: &[u8], limits: &EffectiveLimits) -> Result<(), ProtocolError> {
    limits.check_frame_bytes(bytes.len())?;
    let mut decoder = minicbor::Decoder::new(bytes);
    scan_value(&mut decoder, 0, limits)?;
    if decoder.position() != bytes.len() {
        return Err(ProtocolError::stable(StableCode::ProtocolMalformedCbor));
    }
    Ok(())
}

fn scan_value(
    decoder: &mut minicbor::Decoder<'_>,
    depth: usize,
    limits: &EffectiveLimits,
) -> Result<(), ProtocolError> {
    if u64::try_from(depth).map_or(true, |depth| depth > limits.cbor_depth()) {
        return Err(ProtocolError::stable(StableCode::ProtocolNestingTooDeep));
    }
    match decoder.datatype().map_err(ProtocolError::malformed)? {
        minicbor::data::Type::Array => {
            let len = decoder
                .array()
                .map_err(ProtocolError::malformed)?
                .ok_or_else(ProtocolError::indefinite)?;
            limits.check_wire_items(len)?;
            for _ in 0..len {
                scan_value(decoder, depth + 1, limits)?;
            }
        }
        minicbor::data::Type::Bytes => {
            let bytes = decoder.bytes().map_err(ProtocolError::malformed)?;
            limits.check_wire_bytes(bytes.len())?;
        }
        minicbor::data::Type::String => {
            let text = decoder.str().map_err(ProtocolError::malformed)?;
            limits.check_wire_bytes(text.len())?;
        }
        minicbor::data::Type::Bool => {
            decoder.bool().map_err(ProtocolError::malformed)?;
        }
        minicbor::data::Type::Null => {
            decoder.null().map_err(ProtocolError::malformed)?;
        }
        minicbor::data::Type::U8
        | minicbor::data::Type::U16
        | minicbor::data::Type::U32
        | minicbor::data::Type::U64 => {
            decoder.u64().map_err(ProtocolError::malformed)?;
        }
        minicbor::data::Type::I8
        | minicbor::data::Type::I16
        | minicbor::data::Type::I32
        | minicbor::data::Type::I64
        | minicbor::data::Type::Int => {
            decoder.i64().map_err(ProtocolError::malformed)?;
        }
        _ => return Err(ProtocolError::unsupported_cbor()),
    }
    Ok(())
}

fn decode_typed<'bytes, T>(bytes: &'bytes [u8]) -> Result<T, ProtocolError>
where
    T: minicbor::Decode<'bytes, ()>,
{
    let mut decoder = minicbor::Decoder::new(bytes);
    let value = decoder
        .decode::<T>()
        .map_err(ProtocolError::from_typed_decode)?;
    if decoder.position() != bytes.len() {
        return Err(ProtocolError::stable(StableCode::ProtocolMalformedCbor));
    }
    Ok(value)
}

fn require_canonical(bytes: &[u8], canonical: &[u8]) -> Result<(), ProtocolError> {
    if bytes != canonical {
        return Err(ProtocolError::stable(StableCode::ProtocolNonCanonicalCbor));
    }
    Ok(())
}

fn expect_array(decoder: &mut minicbor::Decoder<'_>, expected: u64) -> Result<(), ProtocolError> {
    match decoder.array().map_err(ProtocolError::malformed)? {
        Some(actual) if actual == expected => Ok(()),
        _ => Err(ProtocolError::stable(StableCode::ProtocolMalformedCbor)),
    }
}

fn skip(decoder: &mut minicbor::Decoder<'_>) -> Result<(), ProtocolError> {
    decoder.skip().map_err(ProtocolError::malformed)
}

fn protocol_version_shape(decoder: &mut minicbor::Decoder<'_>) -> Result<(), ProtocolError> {
    expect_array(decoder, 2)?;
    skip(decoder)?;
    skip(decoder)
}

fn client_hello_shape(decoder: &mut minicbor::Decoder<'_>) -> Result<(), ProtocolError> {
    expect_array(decoder, 5)?;
    skip(decoder)?;
    let versions = decoder
        .array()
        .map_err(ProtocolError::malformed)?
        .ok_or_else(ProtocolError::indefinite)?;
    if !(1..=16).contains(&versions) {
        return Err(ProtocolError::stable(StableCode::ProtocolMalformedCbor));
    }
    for _ in 0..versions {
        protocol_version_shape(decoder)?;
    }
    skip(decoder)?;
    skip(decoder)?;
    skip(decoder)
}

fn operation_shape(decoder: &mut minicbor::Decoder<'_>) -> Result<(), ProtocolError> {
    expect_array(decoder, 2)?;
    let tag = decoder.u64().map_err(ProtocolError::malformed)?;
    let fields = match tag {
        0 => 0,
        10 => 3,
        11 => 3,
        12..=15 => 3,
        16..=17 => 2,
        18 => 1,
        19 => 2,
        _ => return Err(ProtocolError::stable(StableCode::ProtocolUnknownOperation)),
    };
    expect_array(decoder, fields)?;
    for _ in 0..fields {
        skip(decoder)?;
    }
    Ok(())
}

fn request_shape(decoder: &mut minicbor::Decoder<'_>) -> Result<(), ProtocolError> {
    expect_array(decoder, 4)?;
    protocol_version_shape(decoder)?;
    skip(decoder)?;
    skip(decoder)?;
    operation_shape(decoder)
}

fn validate_client_shape(bytes: &[u8]) -> Result<(), ProtocolError> {
    let mut decoder = minicbor::Decoder::new(bytes);
    expect_array(&mut decoder, 2)?;
    match decoder.u64().map_err(ProtocolError::malformed)? {
        0 => client_hello_shape(&mut decoder)?,
        1 => {
            expect_array(&mut decoder, 2)?;
            skip(&mut decoder)?;
            skip(&mut decoder)?;
        }
        2 => request_shape(&mut decoder)?,
        _ => return Err(ProtocolError::stable(StableCode::ProtocolUnknownOperation)),
    }
    Ok(())
}

fn server_identity_shape(decoder: &mut minicbor::Decoder<'_>) -> Result<(), ProtocolError> {
    expect_array(decoder, 9)?;
    skip(decoder)?;
    skip(decoder)?;
    protocol_version_shape(decoder)?;
    for _ in 0..6 {
        skip(decoder)?;
    }
    Ok(())
}

fn signed_server_hello_shape(decoder: &mut minicbor::Decoder<'_>) -> Result<(), ProtocolError> {
    expect_array(decoder, 2)?;
    expect_array(decoder, 3)?;
    client_hello_shape(decoder)?;
    skip(decoder)?;
    server_identity_shape(decoder)?;
    skip(decoder)
}

fn response_payload_shape(decoder: &mut minicbor::Decoder<'_>) -> Result<(), ProtocolError> {
    expect_array(decoder, 2)?;
    match decoder.u64().map_err(ProtocolError::malformed)? {
        0 => {
            expect_array(decoder, 3)?;
            skip(decoder)?;
            server_identity_shape(decoder)?;
            skip(decoder)
        }
        10 => {
            expect_array(decoder, 3)?;
            skip(decoder)?;
            skip(decoder)?;
            skip(decoder)
        }
        11..=15 | 17 | 19 => skip(decoder),
        16 => skip(decoder),
        18 => {
            expect_array(decoder, 4)?;
            skip(decoder)?;
            skip(decoder)?;
            skip(decoder)?;
            skip(decoder)
        }
        _ => Err(ProtocolError::stable(StableCode::ProtocolUnknownOperation)),
    }
}

fn response_body_shape(decoder: &mut minicbor::Decoder<'_>) -> Result<(), ProtocolError> {
    expect_array(decoder, 2)?;
    match decoder.u64().map_err(ProtocolError::malformed)? {
        0 => response_payload_shape(decoder),
        1 => skip(decoder),
        _ => Err(ProtocolError::stable(StableCode::ProtocolUnknownOperation)),
    }
}

fn response_shape(decoder: &mut minicbor::Decoder<'_>) -> Result<(), ProtocolError> {
    expect_array(decoder, 3)?;
    protocol_version_shape(decoder)?;
    skip(decoder)?;
    response_body_shape(decoder)
}

fn validate_server_shape(bytes: &[u8]) -> Result<(), ProtocolError> {
    let mut decoder = minicbor::Decoder::new(bytes);
    expect_array(&mut decoder, 2)?;
    match decoder.u64().map_err(ProtocolError::malformed)? {
        0 => signed_server_hello_shape(&mut decoder)?,
        1 => {
            expect_array(&mut decoder, 2)?;
            skip(&mut decoder)?;
            protocol_version_shape(&mut decoder)?;
        }
        2 => response_shape(&mut decoder)?,
        _ => return Err(ProtocolError::stable(StableCode::ProtocolUnknownOperation)),
    }
    Ok(())
}
