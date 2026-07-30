#![cfg(target_os = "macos")]

use std::os::fd::{AsRawFd as _, OwnedFd};
use std::os::unix::net::UnixListener;
use std::sync::atomic::{AtomicUsize, Ordering};

use nix::fcntl::{fcntl, FcntlArg, FdFlag};
use nix::sys::socket::{getsockname, AddressFamily, SockaddrLike as _, SockaddrStorage};
use savana_platform_identity::{
    take_launchd_tcp_listeners_with_v2, take_launchd_unix_listeners_v2,
    take_launchd_unix_listeners_with_v2, NativeIdentityErrorV2,
};

#[test]
fn duplicate_names_are_rejected_before_native_activation() {
    static CALLS: AtomicUsize = AtomicUsize::new(0);
    let error = take_launchd_unix_listeners_with_v2(
        &["savana-agent-kernel", "savana-agent-kernel"],
        |_| {
            CALLS.fetch_add(1, Ordering::Relaxed);
            Ok(Vec::new())
        },
    )
    .unwrap_err();
    assert_eq!(error, NativeIdentityErrorV2::InvalidMeasurement);
    assert_eq!(CALLS.load(Ordering::Relaxed), 0);
}

#[test]
fn empty_invalid_and_overlong_names_are_rejected() {
    for names in [
        Vec::<&str>::new(),
        vec![""],
        vec!["contains.dot"],
        vec!["x".repeat(129).leak()],
    ] {
        assert_eq!(
            take_launchd_unix_listeners_with_v2(&names, |_| unreachable!()).unwrap_err(),
            NativeIdentityErrorV2::InvalidMeasurement
        );
    }
}

#[test]
fn activation_requires_exactly_one_descriptor_per_name() {
    assert_eq!(
        take_launchd_unix_listeners_with_v2(&["savana-agent-kernel"], |_| Ok(Vec::new()))
            .unwrap_err(),
        NativeIdentityErrorV2::InvalidMeasurement
    );

    let directory = tempfile::tempdir().unwrap();
    let first = UnixListener::bind(directory.path().join("first.sock")).unwrap();
    let second = UnixListener::bind(directory.path().join("second.sock")).unwrap();
    let mut descriptors = Some(vec![OwnedFd::from(first), OwnedFd::from(second)]);
    assert_eq!(
        take_launchd_unix_listeners_with_v2(&["savana-agent-kernel"], move |_| Ok(descriptors
            .take()
            .unwrap()))
        .unwrap_err(),
        NativeIdentityErrorV2::InvalidMeasurement
    );
}

#[test]
fn unix_activation_rejects_non_listener_and_wrong_family() {
    let (stream, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
    let mut descriptor = Some(OwnedFd::from(stream));
    assert_eq!(
        take_launchd_unix_listeners_with_v2(&["savana-agent-kernel"], move |_| Ok(vec![
            descriptor.take().unwrap()
        ]))
        .unwrap_err(),
        NativeIdentityErrorV2::InvalidMeasurement
    );

    let tcp = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let mut descriptor = Some(OwnedFd::from(tcp));
    assert_eq!(
        take_launchd_unix_listeners_with_v2(&["savana-agent-kernel"], move |_| Ok(vec![
            descriptor.take().unwrap()
        ]))
        .unwrap_err(),
        NativeIdentityErrorV2::InvalidMeasurement
    );
}

#[test]
fn accepted_listeners_preserve_order_and_set_cloexec() {
    let directory = tempfile::tempdir().unwrap();
    let first_path = directory.path().join("first.sock");
    let second_path = directory.path().join("second.sock");
    let first = UnixListener::bind(&first_path).unwrap();
    let second = UnixListener::bind(&second_path).unwrap();
    let address: SockaddrStorage = getsockname(first.as_raw_fd()).unwrap();
    assert_eq!(address.family(), Some(AddressFamily::Unix));
    let mut descriptors = vec![OwnedFd::from(first), OwnedFd::from(second)].into_iter();

    let listeners = take_launchd_unix_listeners_with_v2(
        &["savana-agent-kernel", "savana-ingress-kernel"],
        |_| Ok(vec![descriptors.next().unwrap()]),
    )
    .unwrap();

    let (first_name, first) = listeners.into_iter().next().unwrap().into_parts();
    assert_eq!(first_name, "savana-agent-kernel");
    assert_eq!(
        first.local_addr().unwrap().as_pathname(),
        Some(first_path.as_path())
    );
    let flags = FdFlag::from_bits_truncate(fcntl(first.as_raw_fd(), FcntlArg::F_GETFD).unwrap());
    assert!(flags.contains(FdFlag::FD_CLOEXEC));
}

#[test]
fn tcp_activation_accepts_only_listening_ip_sockets() {
    let tcp = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let expected = tcp.local_addr().unwrap();
    let address: SockaddrStorage = getsockname(tcp.as_raw_fd()).unwrap();
    assert_eq!(address.family(), Some(AddressFamily::Inet));
    let mut descriptor = Some(OwnedFd::from(tcp));
    let listeners = take_launchd_tcp_listeners_with_v2(&["savana-jarvis-http"], move |_| {
        Ok(vec![descriptor.take().unwrap()])
    })
    .unwrap();
    let (name, listener) = listeners.into_iter().next().unwrap().into_parts();
    assert_eq!(name, "savana-jarvis-http");
    assert_eq!(listener.local_addr().unwrap(), expected);
}

#[test]
#[ignore = "requires launchd to provide the named socket in this test domain"]
fn native_launchd_activation_accepts_the_named_unix_listener() {
    let name = std::env::var("SAVANA_LAUNCHD_TEST_SOCKET_NAME").unwrap();
    let listeners = take_launchd_unix_listeners_v2(&[name.as_str()]).unwrap();
    assert_eq!(listeners.len(), 1);
    assert_eq!(listeners.into_iter().next().unwrap().into_parts().0, name);
}
