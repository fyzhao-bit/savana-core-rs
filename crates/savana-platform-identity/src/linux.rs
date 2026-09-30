use std::fs::File;
use std::io::{Read as _, Seek as _, SeekFrom};
use std::net::TcpListener;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::os::unix::fs::MetadataExt as _;
use std::os::unix::net::{UnixListener, UnixStream};

use nix::fcntl::{fcntl, FcntlArg, FdFlag};
use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use rustix::event::{poll, PollFd, PollFlags, Timespec};
use rustix::fs::{open, openat, Mode, OFlags};
use rustix::process::{pidfd_open, Pid, PidfdFlags};
use sha2::{Digest as _, Sha256};

use crate::{parse_systemd_listener_activation_v2, NativeIdentityErrorV2, NativePeerMeasurementV2};

const MAX_PROC_STAT_BYTES: u64 = 64 * 1024;

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

pub struct InheritedSystemdListenerV2 {
    name: String,
    descriptor: OwnedFd,
}

impl std::fmt::Debug for InheritedSystemdListenerV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InheritedSystemdListenerV2")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl InheritedSystemdListenerV2 {
    pub fn into_unix_listener(self) -> (String, UnixListener) {
        (self.name, UnixListener::from(self.descriptor))
    }

    pub fn into_tcp_listener(self) -> (String, TcpListener) {
        (self.name, TcpListener::from(self.descriptor))
    }
}

pub fn take_systemd_listeners_v2(
    expected_names: &[&str],
) -> Result<Vec<InheritedSystemdListenerV2>, NativeIdentityErrorV2> {
    let listen_pid =
        std::env::var("LISTEN_PID").map_err(|_| NativeIdentityErrorV2::InvalidMeasurement)?;
    let listen_fds =
        std::env::var("LISTEN_FDS").map_err(|_| NativeIdentityErrorV2::InvalidMeasurement)?;
    let listen_fd_names =
        std::env::var("LISTEN_FDNAMES").map_err(|_| NativeIdentityErrorV2::InvalidMeasurement)?;
    let descriptors = parse_systemd_listener_activation_v2(
        Some(&listen_pid),
        Some(&listen_fds),
        Some(&listen_fd_names),
        std::process::id(),
        expected_names,
    )?;
    // Match sd_listen_fds(..., unset_environment=true): after the exact set
    // has been accepted, a second intake or a spawned child cannot reinterpret
    // the same raw descriptors as fresh listener authority.
    std::env::remove_var("LISTEN_PID");
    std::env::remove_var("LISTEN_FDS");
    std::env::remove_var("LISTEN_FDNAMES");
    let mut inherited = Vec::new();
    inherited
        .try_reserve_exact(descriptors.len())
        .map_err(|_| NativeIdentityErrorV2::Io)?;
    for (name, raw_descriptor) in expected_names.iter().zip(descriptors) {
        fcntl(raw_descriptor, FcntlArg::F_GETFD).map_err(|_| NativeIdentityErrorV2::Io)?;
        fcntl(raw_descriptor, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))
            .map_err(|_| NativeIdentityErrorV2::Io)?;
        // SAFETY: systemd owns descriptors 3..3+LISTEN_FDS until this
        // one-time startup intake. The exact PID, count, and ordered names
        // were validated above; F_GETFD proved this descriptor is live; no
        // Rust owner was constructed before this transfer.
        #[allow(unsafe_code)]
        let descriptor = unsafe { OwnedFd::from_raw_fd(raw_descriptor) };
        inherited.push(InheritedSystemdListenerV2 {
            name: (*name).to_owned(),
            descriptor,
        });
    }
    Ok(inherited)
}

pub fn take_systemd_unix_listeners_v2(
    expected_names: &[&str],
) -> Result<Vec<InheritedUnixListenerV2>, NativeIdentityErrorV2> {
    let listeners = take_systemd_listeners_v2(expected_names)?;
    let mut inherited = Vec::new();
    inherited
        .try_reserve_exact(listeners.len())
        .map_err(|_| NativeIdentityErrorV2::Io)?;
    for listener in listeners {
        let (name, listener) = listener.into_unix_listener();
        inherited.push(InheritedUnixListenerV2 { name, listener });
    }
    Ok(inherited)
}

pub struct PinnedLinuxPeerMeasurementV2 {
    pub(crate) measurement: NativePeerMeasurementV2,
    pub(crate) _pidfd: rustix::fd::OwnedFd,
    pub(crate) _proc_dir: Option<rustix::fd::OwnedFd>,
    pub(crate) _executable: File,
}

impl PinnedLinuxPeerMeasurementV2 {
    pub const fn measurement(&self) -> &NativePeerMeasurementV2 {
        &self.measurement
    }
}

pub fn measure_linux_peer_v2(
    stream: &UnixStream,
) -> Result<PinnedLinuxPeerMeasurementV2, NativeIdentityErrorV2> {
    let credentials = getsockopt(stream, PeerCredentials).map_err(|_| NativeIdentityErrorV2::Io)?;
    let raw_pid = credentials.pid();
    let pid_u32 = u32::try_from(raw_pid).map_err(|_| NativeIdentityErrorV2::InvalidMeasurement)?;
    if pid_u32 == 0 {
        return Err(NativeIdentityErrorV2::InvalidMeasurement);
    }
    let pidfd = socket_peer_pidfd(stream)?;
    if credentials.uid() != nix::unistd::geteuid().as_raw() && !nix::unistd::geteuid().is_root() {
        return crate::linux_broker::measure_through_broker(stream, credentials, pidfd);
    }
    measure_linux_process_pinned(pid_u32, credentials.uid(), credentials.gid(), pidfd)
}

/// Get the socket's actual peer process, not a new process that recycled its PID.
/// SO_PEERPIDFD requires Linux 6.5+ (or a backport); absence fails closed.
pub(crate) fn socket_peer_pidfd(stream: &UnixStream) -> Result<OwnedFd, NativeIdentityErrorV2> {
    let mut raw = -1_i32;
    let mut length = std::mem::size_of::<i32>() as nix::libc::socklen_t;
    // SAFETY: the live socket is borrowed; `raw` and `length` are initialized
    // writable stack objects of the exact ABI types and sizes. A successful
    // SO_PEERPIDFD installs a fresh FD owned by this call, not a borrowed FD.
    #[allow(unsafe_code)]
    let result = unsafe {
        nix::libc::getsockopt(
            stream.as_raw_fd(),
            nix::libc::SOL_SOCKET,
            nix::libc::SO_PEERPIDFD,
            (&mut raw as *mut i32).cast(),
            &mut length,
        )
    };
    if result != 0 || raw < 0 {
        return Err(NativeIdentityErrorV2::CodeIdentityUnavailable);
    }
    // SAFETY: the successful kernel call just transferred unique ownership.
    #[allow(unsafe_code)]
    let descriptor = unsafe { OwnedFd::from_raw_fd(raw) };
    if length as usize != std::mem::size_of::<i32>()
        || fcntl(raw, FcntlArg::F_GETFD).map_err(|_| NativeIdentityErrorV2::Io)?
            & FdFlag::FD_CLOEXEC.bits()
            == 0
    {
        return Err(NativeIdentityErrorV2::InvalidMeasurement);
    }
    require_live(&descriptor)?;
    Ok(descriptor)
}

pub fn measure_current_linux_process_v2(
) -> Result<PinnedLinuxPeerMeasurementV2, NativeIdentityErrorV2> {
    measure_linux_process_v2(
        std::process::id(),
        nix::unistd::geteuid().as_raw(),
        nix::unistd::getegid().as_raw(),
    )
}

pub fn pin_current_linux_service_v2(
    expected_uid: u32,
    expected_gid: u32,
    expected_executable_measurement: [u8; 32],
) -> Result<PinnedLinuxPeerMeasurementV2, NativeIdentityErrorV2> {
    if expected_uid == 0
        || expected_gid == 0
        || expected_executable_measurement
            .iter()
            .all(|byte| *byte == 0)
    {
        return Err(NativeIdentityErrorV2::InvalidMeasurement);
    }
    let pinned = measure_current_linux_process_v2()?;
    match pinned.measurement() {
        NativePeerMeasurementV2::Linux {
            uid,
            gid,
            executable_measurement,
            ..
        } if *uid == expected_uid
            && *gid == expected_gid
            && *executable_measurement == expected_executable_measurement =>
        {
            Ok(pinned)
        }
        _ => Err(NativeIdentityErrorV2::IdentityMismatch),
    }
}

fn measure_linux_process_v2(
    pid_u32: u32,
    uid: u32,
    gid: u32,
) -> Result<PinnedLinuxPeerMeasurementV2, NativeIdentityErrorV2> {
    let raw_pid = i32::try_from(pid_u32).map_err(|_| NativeIdentityErrorV2::InvalidMeasurement)?;
    let pid = Pid::from_raw(raw_pid).ok_or(NativeIdentityErrorV2::InvalidMeasurement)?;
    let pidfd = pidfd_open(pid, PidfdFlags::empty()).map_err(|_| NativeIdentityErrorV2::Io)?;
    measure_linux_process_pinned(pid_u32, uid, gid, pidfd)
}

pub(crate) fn measure_linux_process_pinned(
    pid_u32: u32,
    uid: u32,
    gid: u32,
    pidfd: OwnedFd,
) -> Result<PinnedLinuxPeerMeasurementV2, NativeIdentityErrorV2> {
    require_live(&pidfd)?;

    let proc_path = format!("/proc/{pid_u32}");
    let proc_dir = open(
        proc_path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| NativeIdentityErrorV2::Io)?;
    let stat_fd = openat(
        &proc_dir,
        "stat",
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| NativeIdentityErrorV2::Io)?;
    let stat_file = File::from(stat_fd);
    let mut stat = String::new();
    stat_file
        .take(MAX_PROC_STAT_BYTES)
        .read_to_string(&mut stat)
        .map_err(|_| NativeIdentityErrorV2::Io)?;
    let process_start_time = parse_process_start_time_v2(&stat)?;

    let executable_fd = openat(
        &proc_dir,
        "exe",
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| NativeIdentityErrorV2::Io)?;
    let mut executable = File::from(executable_fd);
    let metadata = executable
        .metadata()
        .map_err(|_| NativeIdentityErrorV2::Io)?;
    if !is_trusted_executable_identity_v2(
        metadata.file_type().is_file(),
        metadata.nlink(),
        metadata.uid(),
        metadata.gid(),
        metadata.mode(),
        uid,
        gid,
    ) {
        return Err(NativeIdentityErrorV2::InvalidMeasurement);
    }
    let executable_measurement = hash_executable(&mut executable)?;

    require_live(&pidfd)?;
    let measurement = NativePeerMeasurementV2::linux(
        uid,
        gid,
        pid_u32,
        process_start_time,
        executable_measurement,
    )?;
    Ok(PinnedLinuxPeerMeasurementV2 {
        measurement,
        _pidfd: pidfd,
        _proc_dir: Some(proc_dir),
        _executable: executable,
    })
}

pub(crate) fn hash_executable(executable: &mut File) -> Result<[u8; 32], NativeIdentityErrorV2> {
    let size = executable
        .metadata()
        .map_err(|_| NativeIdentityErrorV2::Io)?
        .len();
    if size == 0 || size > 256 * 1024 * 1024 {
        return Err(NativeIdentityErrorV2::InvalidMeasurement);
    }
    executable
        .seek(SeekFrom::Start(0))
        .map_err(|_| NativeIdentityErrorV2::Io)?;
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = executable
            .read(&mut buffer)
            .map_err(|_| NativeIdentityErrorV2::Io)?;
        if read == 0 {
            break;
        }
        total += read as u64;
        if total > size {
            return Err(NativeIdentityErrorV2::InvalidMeasurement);
        }
        hasher.update(&buffer[..read]);
    }
    executable
        .seek(SeekFrom::Start(0))
        .map_err(|_| NativeIdentityErrorV2::Io)?;
    if total != size {
        return Err(NativeIdentityErrorV2::InvalidMeasurement);
    }
    Ok(hasher.finalize().into())
}

fn is_trusted_executable_identity_v2(
    is_file: bool,
    link_count: u64,
    owner_uid: u32,
    owner_gid: u32,
    mode: u32,
    process_uid: u32,
    process_gid: u32,
) -> bool {
    let trusted_owner = (owner_uid == 0 && owner_gid == 0)
        || (cfg!(debug_assertions) && owner_uid == process_uid && owner_gid == process_gid);
    is_file
        && link_count == 1
        && trusted_owner
        && mode & 0o022 == 0
        && mode & 0o6000 == 0
        && mode & 0o111 != 0
}

pub(crate) fn require_live(pidfd: &rustix::fd::OwnedFd) -> Result<(), NativeIdentityErrorV2> {
    let mut descriptors = [PollFd::new(pidfd, PollFlags::IN)];
    let zero = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let ready = poll(&mut descriptors, Some(&zero)).map_err(|_| NativeIdentityErrorV2::Io)?;
    if ready == 0 && descriptors[0].revents().is_empty() {
        Ok(())
    } else {
        Err(NativeIdentityErrorV2::ProcessExited)
    }
}

fn parse_process_start_time_v2(stat: &str) -> Result<u64, NativeIdentityErrorV2> {
    let closing_parenthesis = stat
        .rfind(')')
        .ok_or(NativeIdentityErrorV2::InvalidMeasurement)?;
    let after_command = stat
        .get(closing_parenthesis + 1..)
        .ok_or(NativeIdentityErrorV2::InvalidMeasurement)?;
    let start_time = after_command
        .split_ascii_whitespace()
        .nth(19)
        .ok_or(NativeIdentityErrorV2::InvalidMeasurement)?
        .parse::<u64>()
        .map_err(|_| NativeIdentityErrorV2::InvalidMeasurement)?;
    if start_time == 0 {
        return Err(NativeIdentityErrorV2::InvalidMeasurement);
    }
    Ok(start_time)
}

#[cfg(test)]
mod tests {
    use super::{is_trusted_executable_identity_v2, parse_process_start_time_v2};

    #[test]
    fn stat_parser_anchors_after_the_final_command_parenthesis() {
        let stat = "42 (worker ) with spaces) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 99";
        assert_eq!(parse_process_start_time_v2(stat).unwrap(), 99);
    }

    #[test]
    fn service_process_must_execute_a_root_owned_immutable_binary() {
        assert!(is_trusted_executable_identity_v2(
            true, 1, 0, 0, 0o100555, 1_001, 1_001
        ));
        assert!(!is_trusted_executable_identity_v2(
            true, 1, 1_002, 1_002, 0o100555, 1_001, 1_001
        ));
        assert!(!is_trusted_executable_identity_v2(
            true, 1, 0, 0, 0o100775, 1_001, 1_001
        ));
        assert!(!is_trusted_executable_identity_v2(
            true, 2, 0, 0, 0o100555, 1_001, 1_001
        ));
    }
}
