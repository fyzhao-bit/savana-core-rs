use std::io::{self, Cursor, Read, Write};

use savana_kernel_protocol::{read_frame, write_frame, HardLimits, StableCode};

mod support;

struct HeaderOnly {
    bytes: Cursor<Vec<u8>>,
    body_reads: usize,
}

impl Read for HeaderOnly {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.bytes.position() >= 4 {
            self.body_reads += 1;
        }
        self.bytes.read(out)
    }
}

#[test]
fn oversized_frame_is_rejected_before_body_read() {
    let length = (HardLimits::COMPILED.frame_bytes() + 1) as u32;
    let mut reader = HeaderOnly {
        bytes: Cursor::new(length.to_be_bytes().to_vec()),
        body_reads: 0,
    };
    let error = read_frame(&mut reader, &support::compiled_effective_limits()).unwrap_err();
    assert_eq!(error.code(), StableCode::ProtocolFrameTooLarge);
    assert_eq!(reader.body_reads, 0);
}

fn assert_partial_header_is_truncated(header_bytes: usize) {
    let mut reader = Cursor::new(vec![0_u8; header_bytes]);
    let error = read_frame(&mut reader, &support::compiled_effective_limits()).unwrap_err();
    assert_eq!(error.code(), StableCode::ProtocolTruncatedFrame);
}

#[test]
fn one_byte_header_is_truncated() {
    assert_partial_header_is_truncated(1);
}

#[test]
fn two_byte_header_is_truncated() {
    assert_partial_header_is_truncated(2);
}

#[test]
fn three_byte_header_is_truncated() {
    assert_partial_header_is_truncated(3);
}

#[test]
fn truncated_body_is_rejected() {
    let mut bytes = 3_u32.to_be_bytes().to_vec();
    bytes.extend_from_slice(&[1, 2]);
    let error = read_frame(
        &mut Cursor::new(bytes),
        &support::compiled_effective_limits(),
    )
    .unwrap_err();
    assert_eq!(error.code(), StableCode::ProtocolTruncatedFrame);
}

#[test]
fn empty_read_frame_is_rejected() {
    let error = read_frame(
        &mut Cursor::new(0_u32.to_be_bytes()),
        &support::compiled_effective_limits(),
    )
    .unwrap_err();
    assert_eq!(error.code(), StableCode::ProtocolMalformedFrame);
}

#[test]
fn empty_write_frame_is_rejected_without_output() {
    let mut output = Vec::new();
    let error = write_frame(&mut output, &[], &support::compiled_effective_limits()).unwrap_err();
    assert_eq!(error.code(), StableCode::ProtocolMalformedFrame);
    assert!(output.is_empty());
}

#[test]
fn over_limit_write_is_rejected_without_output() {
    let payload = vec![0_u8; HardLimits::COMPILED.frame_bytes() as usize + 1];
    let mut output = Vec::new();
    let error =
        write_frame(&mut output, &payload, &support::compiled_effective_limits()).unwrap_err();
    assert_eq!(error.code(), StableCode::ProtocolFrameTooLarge);
    assert!(output.is_empty());
}

struct FailingIo {
    kind: io::ErrorKind,
}

impl Read for FailingIo {
    fn read(&mut self, _out: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::from(self.kind))
    }
}

impl Write for FailingIo {
    fn write(&mut self, _input: &[u8]) -> io::Result<usize> {
        Err(io::Error::from(self.kind))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn read_timeout_maps_to_deadline_exceeded() {
    let error = read_frame(
        &mut FailingIo {
            kind: io::ErrorKind::TimedOut,
        },
        &support::compiled_effective_limits(),
    )
    .unwrap_err();
    assert_eq!(error.code(), StableCode::DeadlineExceeded);
}

#[test]
fn write_would_block_maps_to_deadline_exceeded() {
    let error = write_frame(
        &mut FailingIo {
            kind: io::ErrorKind::WouldBlock,
        },
        &[1],
        &support::compiled_effective_limits(),
    )
    .unwrap_err();
    assert_eq!(error.code(), StableCode::DeadlineExceeded);
}

#[test]
fn read_would_block_maps_to_deadline_exceeded() {
    let error = read_frame(
        &mut FailingIo {
            kind: io::ErrorKind::WouldBlock,
        },
        &support::compiled_effective_limits(),
    )
    .unwrap_err();
    assert_eq!(error.code(), StableCode::DeadlineExceeded);
}

#[test]
fn write_timeout_maps_to_deadline_exceeded() {
    let error = write_frame(
        &mut FailingIo {
            kind: io::ErrorKind::TimedOut,
        },
        &[1],
        &support::compiled_effective_limits(),
    )
    .unwrap_err();
    assert_eq!(error.code(), StableCode::DeadlineExceeded);
}

#[test]
fn other_read_errors_map_to_protocol_io() {
    let error = read_frame(
        &mut FailingIo {
            kind: io::ErrorKind::ConnectionReset,
        },
        &support::compiled_effective_limits(),
    )
    .unwrap_err();
    assert_eq!(error.code(), StableCode::ProtocolIo);
}

#[test]
fn bounded_frame_round_trip_preserves_payload() {
    let payload = b"canonical payload";
    let mut framed = Vec::new();
    write_frame(&mut framed, payload, &support::compiled_effective_limits()).unwrap();
    let decoded = read_frame(
        &mut Cursor::new(framed),
        &support::compiled_effective_limits(),
    )
    .unwrap();
    assert_eq!(decoded, payload);
}
