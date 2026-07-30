use std::io::{Read, Write};

use crate::{EffectiveLimits, ProtocolError, StableCode};

pub fn read_frame<R: Read>(
    reader: &mut R,
    limits: &EffectiveLimits,
) -> Result<Vec<u8>, ProtocolError> {
    let mut header = [0_u8; 4];
    reader
        .read_exact(&mut header)
        .map_err(ProtocolError::from_read)?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 {
        return Err(ProtocolError::stable(StableCode::ProtocolMalformedFrame));
    }
    limits.check_frame_bytes(length)?;
    let mut body = Vec::new();
    body.try_reserve_exact(length)
        .map_err(|_| ProtocolError::stable(StableCode::ProtocolAllocationRefused))?;
    body.resize(length, 0);
    reader
        .read_exact(&mut body)
        .map_err(ProtocolError::from_read)?;
    Ok(body)
}

pub fn write_frame<W: Write>(
    writer: &mut W,
    payload: &[u8],
    limits: &EffectiveLimits,
) -> Result<(), ProtocolError> {
    if payload.is_empty() {
        return Err(ProtocolError::stable(StableCode::ProtocolMalformedFrame));
    }
    limits.check_frame_bytes(payload.len())?;
    let length = u32::try_from(payload.len())
        .map_err(|_| ProtocolError::stable(StableCode::ProtocolFrameTooLarge))?;
    writer
        .write_all(&length.to_be_bytes())
        .and_then(|_| writer.write_all(payload))
        .map_err(ProtocolError::io)
}
