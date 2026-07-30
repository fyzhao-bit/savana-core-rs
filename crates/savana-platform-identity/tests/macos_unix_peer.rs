#![cfg(target_os = "macos")]

use std::os::unix::net::{UnixListener, UnixStream};

use nix::sys::socket::{socket, AddressFamily, SockFlag, SockType};
use savana_platform_identity::{
    macos_unix_peer_audit_token_v2, parse_macos_audit_token_v2, NativeIdentityErrorV2,
};

#[test]
fn accepted_unix_stream_yields_the_connecting_process_audit_token() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("peer.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let client = UnixStream::connect(&path).unwrap();
    let (server, _) = listener.accept().unwrap();

    let token = macos_unix_peer_audit_token_v2(&server).unwrap();
    let identity = parse_macos_audit_token_v2(token).unwrap();
    assert_eq!(identity.pid(), std::process::id());

    drop(client);
}

#[test]
fn unconnected_unix_stream_is_rejected() {
    let descriptor = socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::empty(),
        None,
    )
    .unwrap();
    let stream = UnixStream::from(descriptor);
    assert_eq!(
        macos_unix_peer_audit_token_v2(&stream).unwrap_err(),
        NativeIdentityErrorV2::InvalidMeasurement
    );
}
