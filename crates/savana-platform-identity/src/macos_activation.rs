use std::ffi::CString;
use std::net::TcpListener;
use std::os::fd::{AsRawFd as _, OwnedFd};
use std::os::unix::net::UnixListener;

use nix::fcntl::{fcntl, FcntlArg, FdFlag};
use nix::sys::socket::{getsockname, AddressFamily, SockaddrLike as _, SockaddrStorage};

use crate::{macos::ffi, valid_listener_name, NativeIdentityErrorV2};

pub struct InheritedUnixListenerV2 {
    name: String,
    listener: UnixListener,
}

impl std::fmt::Debug for InheritedUnixListenerV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InheritedUnixListenerV2")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl InheritedUnixListenerV2 {
    pub fn into_parts(self) -> (String, UnixListener) {
        (self.name, self.listener)
    }
}

pub struct InheritedTcpListenerV2 {
    name: String,
    listener: TcpListener,
}

impl std::fmt::Debug for InheritedTcpListenerV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InheritedTcpListenerV2")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl InheritedTcpListenerV2 {
    pub fn into_parts(self) -> (String, TcpListener) {
        (self.name, self.listener)
    }
}

#[derive(Clone, Copy)]
enum ExpectedSocketFamilyV2 {
    Unix,
    Tcp,
}

pub fn take_launchd_unix_listeners_v2(
    expected_names: &[&str],
) -> Result<Vec<InheritedUnixListenerV2>, NativeIdentityErrorV2> {
    take_launchd_unix_listeners_with(expected_names, |name| {
        let name = CString::new(name).map_err(|_| NativeIdentityErrorV2::InvalidMeasurement)?;
        ffi::launch_activate_socket_v2(&name)
    })
}

pub fn take_launchd_tcp_listeners_v2(
    expected_names: &[&str],
) -> Result<Vec<InheritedTcpListenerV2>, NativeIdentityErrorV2> {
    take_launchd_tcp_listeners_with(expected_names, |name| {
        let name = CString::new(name).map_err(|_| NativeIdentityErrorV2::InvalidMeasurement)?;
        ffi::launch_activate_socket_v2(&name)
    })
}

#[cfg(feature = "test-support")]
pub fn take_launchd_unix_listeners_with_v2<F>(
    expected_names: &[&str],
    activate: F,
) -> Result<Vec<InheritedUnixListenerV2>, NativeIdentityErrorV2>
where
    F: FnMut(&str) -> Result<Vec<OwnedFd>, NativeIdentityErrorV2>,
{
    take_launchd_unix_listeners_with(expected_names, activate)
}

#[cfg(feature = "test-support")]
pub fn take_launchd_tcp_listeners_with_v2<F>(
    expected_names: &[&str],
    activate: F,
) -> Result<Vec<InheritedTcpListenerV2>, NativeIdentityErrorV2>
where
    F: FnMut(&str) -> Result<Vec<OwnedFd>, NativeIdentityErrorV2>,
{
    take_launchd_tcp_listeners_with(expected_names, activate)
}

fn take_launchd_unix_listeners_with<F>(
    expected_names: &[&str],
    mut activate: F,
) -> Result<Vec<InheritedUnixListenerV2>, NativeIdentityErrorV2>
where
    F: FnMut(&str) -> Result<Vec<OwnedFd>, NativeIdentityErrorV2>,
{
    validate_names(expected_names)?;
    let mut listeners = Vec::new();
    listeners
        .try_reserve_exact(expected_names.len())
        .map_err(|_| NativeIdentityErrorV2::Io)?;
    for name in expected_names {
        let descriptor = take_one_descriptor(name, &mut activate, ExpectedSocketFamilyV2::Unix)?;
        listeners.push(InheritedUnixListenerV2 {
            name: (*name).to_owned(),
            listener: UnixListener::from(descriptor),
        });
    }
    Ok(listeners)
}

fn take_launchd_tcp_listeners_with<F>(
    expected_names: &[&str],
    mut activate: F,
) -> Result<Vec<InheritedTcpListenerV2>, NativeIdentityErrorV2>
where
    F: FnMut(&str) -> Result<Vec<OwnedFd>, NativeIdentityErrorV2>,
{
    validate_names(expected_names)?;
    let mut listeners = Vec::new();
    listeners
        .try_reserve_exact(expected_names.len())
        .map_err(|_| NativeIdentityErrorV2::Io)?;
    for name in expected_names {
        let descriptor = take_one_descriptor(name, &mut activate, ExpectedSocketFamilyV2::Tcp)?;
        listeners.push(InheritedTcpListenerV2 {
            name: (*name).to_owned(),
            listener: TcpListener::from(descriptor),
        });
    }
    Ok(listeners)
}

fn validate_names(expected_names: &[&str]) -> Result<(), NativeIdentityErrorV2> {
    if expected_names.is_empty()
        || expected_names.len() > 16
        || expected_names.iter().any(|name| !valid_listener_name(name))
        || expected_names
            .iter()
            .enumerate()
            .any(|(index, name)| expected_names[..index].contains(name))
    {
        return Err(NativeIdentityErrorV2::InvalidMeasurement);
    }
    Ok(())
}

fn take_one_descriptor<F>(
    name: &str,
    activate: &mut F,
    expected_family: ExpectedSocketFamilyV2,
) -> Result<OwnedFd, NativeIdentityErrorV2>
where
    F: FnMut(&str) -> Result<Vec<OwnedFd>, NativeIdentityErrorV2>,
{
    let mut descriptors = activate(name)?;
    if descriptors.len() != 1 {
        return Err(NativeIdentityErrorV2::InvalidMeasurement);
    }
    let descriptor = descriptors
        .pop()
        .ok_or(NativeIdentityErrorV2::InvalidMeasurement)?;
    if !ffi::socket_is_listening_v2(descriptor.as_raw_fd())? {
        return Err(NativeIdentityErrorV2::InvalidMeasurement);
    }
    let address: SockaddrStorage = getsockname(descriptor.as_raw_fd())
        .map_err(|_| NativeIdentityErrorV2::InvalidMeasurement)?;
    let family_matches = matches!(
        (expected_family, address.family()),
        (ExpectedSocketFamilyV2::Unix, Some(AddressFamily::Unix))
            | (
                ExpectedSocketFamilyV2::Tcp,
                Some(AddressFamily::Inet | AddressFamily::Inet6)
            )
    );
    if !family_matches {
        return Err(NativeIdentityErrorV2::InvalidMeasurement);
    }
    let current =
        fcntl(descriptor.as_raw_fd(), FcntlArg::F_GETFD).map_err(|_| NativeIdentityErrorV2::Io)?;
    let flags = FdFlag::from_bits_truncate(current) | FdFlag::FD_CLOEXEC;
    fcntl(descriptor.as_raw_fd(), FcntlArg::F_SETFD(flags))
        .map_err(|_| NativeIdentityErrorV2::Io)?;
    Ok(descriptor)
}
