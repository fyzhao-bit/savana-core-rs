use crate::{ProtocolError, StableCode};

use super::{AgentControlOperationV2, PublicTaskStatusV2};

const MAX_V2_CONTROL_BYTES: usize = 8 * 1024 * 1024;
const MAX_V2_CONTROL_DEPTH: usize = 32;
const MAX_V2_CONTROL_ITEMS: u64 = 65_536;

#[derive(Debug, Default)]
pub struct V2DecodeContext;

pub fn encode_agent_control_operation_v2(
    value: &AgentControlOperationV2,
) -> Result<Vec<u8>, ProtocolError> {
    value.validate()?;
    minicbor::to_vec(value).map_err(ProtocolError::malformed)
}

pub fn decode_agent_control_operation_v2(
    bytes: &[u8],
) -> Result<AgentControlOperationV2, ProtocolError> {
    scan_single(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    let mut context = V2DecodeContext;
    let value = <AgentControlOperationV2 as minicbor::Decode<V2DecodeContext>>::decode(
        &mut decoder,
        &mut context,
    )
    .map_err(ProtocolError::from_typed_decode)?;
    if decoder.position() != bytes.len() {
        return Err(ProtocolError::stable(StableCode::ProtocolMalformedCbor));
    }
    value.validate()?;
    let canonical = encode_agent_control_operation_v2(&value)?;
    if bytes != canonical {
        return Err(ProtocolError::stable(StableCode::ProtocolNonCanonicalCbor));
    }
    Ok(value)
}

pub fn encode_public_task_status_v2(value: &PublicTaskStatusV2) -> Result<Vec<u8>, ProtocolError> {
    value.validate()?;
    minicbor::to_vec(value).map_err(ProtocolError::malformed)
}

pub fn decode_public_task_status_v2(bytes: &[u8]) -> Result<PublicTaskStatusV2, ProtocolError> {
    scan_single(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    let mut context = V2DecodeContext;
    let value = <PublicTaskStatusV2 as minicbor::Decode<V2DecodeContext>>::decode(
        &mut decoder,
        &mut context,
    )
    .map_err(ProtocolError::from_typed_decode)?;
    if decoder.position() != bytes.len() {
        return Err(ProtocolError::stable(StableCode::ProtocolMalformedCbor));
    }
    value.validate()?;
    let canonical = encode_public_task_status_v2(&value)?;
    if bytes != canonical {
        return Err(ProtocolError::stable(StableCode::ProtocolNonCanonicalCbor));
    }
    Ok(value)
}

pub(super) fn scan_single(bytes: &[u8]) -> Result<(), ProtocolError> {
    if bytes.len() > MAX_V2_CONTROL_BYTES {
        return Err(ProtocolError::stable(StableCode::ProtocolAllocationRefused));
    }
    let mut decoder = minicbor::Decoder::new(bytes);
    let mut remaining_items = MAX_V2_CONTROL_ITEMS;
    scan_value(&mut decoder, 0, &mut remaining_items)?;
    if decoder.position() != bytes.len() {
        return Err(ProtocolError::stable(StableCode::ProtocolMalformedCbor));
    }
    Ok(())
}

fn scan_value(
    decoder: &mut minicbor::Decoder<'_>,
    depth: usize,
    remaining_items: &mut u64,
) -> Result<(), ProtocolError> {
    if depth > MAX_V2_CONTROL_DEPTH {
        return Err(ProtocolError::stable(StableCode::ProtocolNestingTooDeep));
    }
    *remaining_items = remaining_items
        .checked_sub(1)
        .ok_or_else(|| ProtocolError::stable(StableCode::ProtocolAllocationRefused))?;

    match decoder.datatype().map_err(ProtocolError::malformed)? {
        minicbor::data::Type::Array => {
            let len = decoder
                .array()
                .map_err(ProtocolError::malformed)?
                .ok_or_else(ProtocolError::indefinite)?;
            if len > MAX_V2_CONTROL_ITEMS {
                return Err(ProtocolError::stable(StableCode::ProtocolAllocationRefused));
            }
            for _ in 0..len {
                scan_value(decoder, depth + 1, remaining_items)?;
            }
        }
        minicbor::data::Type::Bytes => {
            let value = decoder.bytes().map_err(ProtocolError::malformed)?;
            if value.len() > MAX_V2_CONTROL_BYTES {
                return Err(ProtocolError::stable(StableCode::ProtocolAllocationRefused));
            }
        }
        minicbor::data::Type::String => {
            let value = decoder.str().map_err(ProtocolError::malformed)?;
            if value.len() > MAX_V2_CONTROL_BYTES {
                return Err(ProtocolError::stable(StableCode::ProtocolAllocationRefused));
            }
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
