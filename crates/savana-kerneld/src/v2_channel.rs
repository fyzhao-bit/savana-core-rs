use std::io::{Read as _, Write as _};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::time::Instant;

use savana_kernel_protocol::v2::{
    HANDSHAKE_FRAME_HEADER_BYTES_V2, MAX_HANDSHAKE_BODY_BYTES_V2, MAX_RECORD_CIPHERTEXT_BYTES_V2,
    MAX_RECORD_HEADER_BYTES_V2, RECORD_FRAME_HEADER_BYTES_V2,
};

const HANDSHAKE_MAGIC_V2: &[u8; 8] = b"SAVANA2\0";
const RECORD_MAGIC_V2: &[u8; 4] = b"SV2R";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChannelErrorV2 {
    Malformed,
    DeadlineExceeded,
    Unavailable,
}

pub(crate) trait V2FrameChannel {
    fn read_handshake_frame(&mut self, deadline: Instant) -> Result<Vec<u8>, ChannelErrorV2>;

    fn write_handshake_frame(
        &mut self,
        frame: &[u8],
        deadline: Instant,
    ) -> Result<(), ChannelErrorV2>;

    fn read_record_frame(&mut self, deadline: Instant) -> Result<Vec<u8>, ChannelErrorV2>;

    fn write_record_frame(&mut self, frame: &[u8], deadline: Instant)
        -> Result<(), ChannelErrorV2>;

    fn close(&mut self);
}

pub(crate) struct UnixV2FrameChannel {
    stream: Option<UnixStream>,
}

impl std::fmt::Debug for UnixV2FrameChannel {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("UnixV2FrameChannel(<opaque-encrypted-frames>)")
    }
}

impl UnixV2FrameChannel {
    pub(crate) fn new(stream: UnixStream) -> Self {
        Self {
            stream: Some(stream),
        }
    }

    #[cfg(test)]
    pub(crate) fn into_inner(mut self) -> UnixStream {
        self.stream.take().expect("test channel owns a stream")
    }

    fn stream(&mut self) -> Result<&mut UnixStream, ChannelErrorV2> {
        self.stream.as_mut().ok_or(ChannelErrorV2::Unavailable)
    }

    fn set_deadline(&mut self, deadline: Instant) -> Result<(), ChannelErrorV2> {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(ChannelErrorV2::DeadlineExceeded);
        }
        let stream = self.stream()?;
        stream
            .set_read_timeout(Some(remaining))
            .and_then(|_| stream.set_write_timeout(Some(remaining)))
            .map_err(|_| ChannelErrorV2::Unavailable)
    }
}

impl V2FrameChannel for UnixV2FrameChannel {
    fn read_handshake_frame(&mut self, deadline: Instant) -> Result<Vec<u8>, ChannelErrorV2> {
        self.set_deadline(deadline)?;
        let mut header = [0_u8; HANDSHAKE_FRAME_HEADER_BYTES_V2];
        self.stream()?
            .read_exact(&mut header)
            .map_err(|_| ChannelErrorV2::Malformed)?;
        if &header[..8] != HANDSHAKE_MAGIC_V2 {
            return Err(ChannelErrorV2::Malformed);
        }
        let body_length = u32::from_be_bytes(
            header[HANDSHAKE_FRAME_HEADER_BYTES_V2 - 4..]
                .try_into()
                .map_err(|_| ChannelErrorV2::Malformed)?,
        ) as usize;
        if body_length == 0 || body_length > MAX_HANDSHAKE_BODY_BYTES_V2 {
            return Err(ChannelErrorV2::Malformed);
        }
        let total = HANDSHAKE_FRAME_HEADER_BYTES_V2
            .checked_add(body_length)
            .ok_or(ChannelErrorV2::Malformed)?;
        let mut frame = Vec::new();
        frame
            .try_reserve_exact(total)
            .map_err(|_| ChannelErrorV2::Unavailable)?;
        frame.extend_from_slice(&header);
        frame.resize(total, 0);
        self.stream()?
            .read_exact(&mut frame[HANDSHAKE_FRAME_HEADER_BYTES_V2..])
            .map_err(|_| ChannelErrorV2::Malformed)?;
        Ok(frame)
    }

    fn write_handshake_frame(
        &mut self,
        frame: &[u8],
        deadline: Instant,
    ) -> Result<(), ChannelErrorV2> {
        validate_handshake_frame(frame)?;
        self.set_deadline(deadline)?;
        let stream = self.stream()?;
        stream
            .write_all(frame)
            .and_then(|_| stream.flush())
            .map_err(|_| ChannelErrorV2::Unavailable)
    }

    fn read_record_frame(&mut self, deadline: Instant) -> Result<Vec<u8>, ChannelErrorV2> {
        self.set_deadline(deadline)?;
        let mut header = [0_u8; RECORD_FRAME_HEADER_BYTES_V2];
        self.stream()?
            .read_exact(&mut header)
            .map_err(|_| ChannelErrorV2::Malformed)?;
        let (header_length, ciphertext_length) = record_lengths(&header)?;
        let total = RECORD_FRAME_HEADER_BYTES_V2
            .checked_add(header_length)
            .and_then(|value| value.checked_add(ciphertext_length))
            .ok_or(ChannelErrorV2::Malformed)?;
        let mut frame = Vec::new();
        frame
            .try_reserve_exact(total)
            .map_err(|_| ChannelErrorV2::Unavailable)?;
        frame.extend_from_slice(&header);
        frame.resize(total, 0);
        self.stream()?
            .read_exact(&mut frame[RECORD_FRAME_HEADER_BYTES_V2..])
            .map_err(|_| ChannelErrorV2::Malformed)?;
        Ok(frame)
    }

    fn write_record_frame(
        &mut self,
        frame: &[u8],
        deadline: Instant,
    ) -> Result<(), ChannelErrorV2> {
        validate_record_frame(frame)?;
        self.set_deadline(deadline)?;
        let stream = self.stream()?;
        stream
            .write_all(frame)
            .and_then(|_| stream.flush())
            .map_err(|_| ChannelErrorV2::Unavailable)
    }

    fn close(&mut self) {
        if let Some(stream) = self.stream.take() {
            let _ = stream.shutdown(Shutdown::Both);
        }
    }
}

impl Drop for UnixV2FrameChannel {
    fn drop(&mut self) {
        self.close();
    }
}

fn validate_handshake_frame(frame: &[u8]) -> Result<(), ChannelErrorV2> {
    if frame.len() < HANDSHAKE_FRAME_HEADER_BYTES_V2 || &frame[..8] != HANDSHAKE_MAGIC_V2 {
        return Err(ChannelErrorV2::Malformed);
    }
    let body_length = u32::from_be_bytes(
        frame[HANDSHAKE_FRAME_HEADER_BYTES_V2 - 4..HANDSHAKE_FRAME_HEADER_BYTES_V2]
            .try_into()
            .map_err(|_| ChannelErrorV2::Malformed)?,
    ) as usize;
    if body_length == 0
        || body_length > MAX_HANDSHAKE_BODY_BYTES_V2
        || frame.len() != HANDSHAKE_FRAME_HEADER_BYTES_V2 + body_length
    {
        return Err(ChannelErrorV2::Malformed);
    }
    Ok(())
}

fn validate_record_frame(frame: &[u8]) -> Result<(), ChannelErrorV2> {
    if frame.len() < RECORD_FRAME_HEADER_BYTES_V2 {
        return Err(ChannelErrorV2::Malformed);
    }
    let (header_length, ciphertext_length) =
        record_lengths(&frame[..RECORD_FRAME_HEADER_BYTES_V2])?;
    if frame.len() != RECORD_FRAME_HEADER_BYTES_V2 + header_length + ciphertext_length {
        return Err(ChannelErrorV2::Malformed);
    }
    Ok(())
}

fn record_lengths(header: &[u8]) -> Result<(usize, usize), ChannelErrorV2> {
    if header.len() != RECORD_FRAME_HEADER_BYTES_V2 || &header[..4] != RECORD_MAGIC_V2 {
        return Err(ChannelErrorV2::Malformed);
    }
    let header_length = usize::from(u16::from_be_bytes(
        header[4..6]
            .try_into()
            .map_err(|_| ChannelErrorV2::Malformed)?,
    ));
    let ciphertext_length = u32::from_be_bytes(
        header[6..10]
            .try_into()
            .map_err(|_| ChannelErrorV2::Malformed)?,
    ) as usize;
    if header_length == 0
        || header_length > MAX_RECORD_HEADER_BYTES_V2
        || !(16..=MAX_RECORD_CIPHERTEXT_BYTES_V2).contains(&ciphertext_length)
    {
        return Err(ChannelErrorV2::Malformed);
    }
    Ok((header_length, ciphertext_length))
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;
    use std::os::unix::net::UnixStream;
    use std::time::{Duration, Instant};

    use super::{ChannelErrorV2, UnixV2FrameChannel, V2FrameChannel};

    #[test]
    fn v1_and_oversized_prefixes_are_rejected_before_body_allocation() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        sender.write_all(b"SAVANA1\0").unwrap();
        sender.write_all(&[0_u8; 12]).unwrap();
        let mut channel = UnixV2FrameChannel::new(receiver);
        assert_eq!(
            channel.read_handshake_frame(Instant::now() + Duration::from_secs(1)),
            Err(ChannelErrorV2::Malformed)
        );

        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut header = [0_u8; 20];
        header[..8].copy_from_slice(b"SAVANA2\0");
        header[16..20].copy_from_slice(&u32::MAX.to_be_bytes());
        sender.write_all(&header).unwrap();
        let mut channel = UnixV2FrameChannel::new(receiver);
        assert_eq!(
            channel.read_handshake_frame(Instant::now() + Duration::from_secs(1)),
            Err(ChannelErrorV2::Malformed)
        );
    }
}
