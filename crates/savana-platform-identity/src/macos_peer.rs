use std::os::fd::AsRawFd as _;
use std::os::unix::net::UnixStream;

use crate::{macos::ffi, measure_macos_peer_v2, NativeIdentityErrorV2, NativePeerMeasurementV2};

pub fn macos_unix_peer_audit_token_v2(
    stream: &UnixStream,
) -> Result<[u8; 32], NativeIdentityErrorV2> {
    ffi::unix_peer_audit_token_v2(stream.as_raw_fd())
}

pub fn measure_macos_unix_peer_v2(
    stream: &UnixStream,
) -> Result<NativePeerMeasurementV2, NativeIdentityErrorV2> {
    measure_macos_peer_v2(macos_unix_peer_audit_token_v2(stream)?)
}
