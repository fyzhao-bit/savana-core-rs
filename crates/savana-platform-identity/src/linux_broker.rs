//! Narrow privileged measurement boundary, not a signing/authorization service.
//! No caller-provided PID/path/digest is used to select a measurement target.
//! Both endpoints are bound to SO_PEERCRED of actual connected Unix sockets.
use std::fs::File;
use std::io::{IoSlice, IoSliceMut, Read, Write};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use nix::sys::socket::{getsockopt, sockopt::PeerCredentials, sockopt::SockType, UnixCredentials};
use rustix::fs::{open, openat, Mode, OFlags};
use rustix::net::{
    recvmsg, sendmsg, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags,
    SendAncillaryBuffer, SendAncillaryMessage, SendFlags,
};
use serde::Deserialize;

use crate::linux::{
    hash_executable, measure_linux_process_pinned, require_live, socket_peer_pidfd,
    PinnedLinuxPeerMeasurementV2,
};
use crate::{NativeIdentityErrorV2 as Error, NativePeerMeasurementV2};

const SOCKET: &str = "/run/savana-identity/measurement-v2.sock";
const MAGIC: &[u8; 4] = b"SM02";
const RESPONSE: usize = 56;

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct Identity {
    uid: u32,
    gid: u32,
    executable_sha256: [u8; 32],
}

impl Identity {
    fn valid(&self) -> bool {
        (self.uid == 0) == (self.gid == 0) && self.executable_sha256 != [0; 32]
    }

    fn matches(&self, observed: &NativePeerMeasurementV2) -> bool {
        matches!(observed, NativePeerMeasurementV2::Linux { uid, gid, executable_measurement, .. }
            if *uid == self.uid && *gid == self.gid && *executable_measurement == self.executable_sha256)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct Edge {
    caller: Identity,
    peer: Identity,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    version: u32,
    edges: Vec<Edge>,
}

impl Policy {
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > 64 * 1024 {
            return Err(Error::InvalidMeasurement);
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|_| Error::InvalidMeasurement)?;
        if value.version != 2
            || value.edges.is_empty()
            || value.edges.len() > 64
            || value.edges.iter().enumerate().any(|(i, edge)| {
                edge.caller.uid == 0
                    || !edge.caller.valid()
                    || !edge.peer.valid()
                    || value.edges[..i].contains(edge)
            })
        {
            return Err(Error::InvalidMeasurement);
        }
        Ok(value)
    }

    fn permits(&self, caller: &NativePeerMeasurementV2, peer: &NativePeerMeasurementV2) -> bool {
        self.edges
            .iter()
            .any(|e| e.caller.matches(caller) && e.peer.matches(peer))
    }
}

// Root-owned, no symlink, no writable ancestor. Descriptor-relative walks avoid
// path replacement by a service between checking metadata and opening the file.
fn root_directory(path: &str) -> Result<OwnedFd, Error> {
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW;
    let mut directory = open("/", flags, Mode::empty()).map_err(|_| Error::Io)?;
    for part in path.split('/').filter(|p| !p.is_empty()) {
        if part == "." || part == ".." {
            return Err(Error::InvalidMeasurement);
        }
        directory = openat(&directory, part, flags, Mode::empty()).map_err(|_| Error::Io)?;
        let stat = rustix::fs::fstat(&directory).map_err(|_| Error::Io)?;
        if stat.st_uid != 0 || stat.st_mode & 0o022 != 0 {
            return Err(Error::InvalidMeasurement);
        }
    }
    Ok(directory)
}

fn load_policy() -> Result<Policy, Error> {
    let directory = root_directory("/etc/savana")?;
    let fd = openat(
        &directory,
        "identity-broker-v2.json",
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| Error::Io)?;
    let file = File::from(fd);
    let meta = file.metadata().map_err(|_| Error::Io)?;
    if !meta.is_file()
        || meta.uid() != 0
        || meta.gid() != 0
        || meta.mode() & 0o022 != 0
        || meta.nlink() != 1
        || meta.len() > 64 * 1024
    {
        return Err(Error::InvalidMeasurement);
    }
    let mut bytes = Vec::new();
    file.take(64 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Io)?;
    Policy::parse(&bytes)
}

fn deadlines(stream: &UnixStream) -> Result<(), Error> {
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(|_| Error::Io)?;
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .map_err(|_| Error::Io)
}

fn send_fd(mut stream: &UnixStream, bytes: &[u8], fd: impl AsFd) -> Result<(), Error> {
    let deadline = Instant::now() + Duration::from_secs(3);
    stream
        .set_write_timeout(Some(remaining(deadline)?))
        .map_err(|_| Error::Io)?;
    let fds = [fd.as_fd()];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut control = SendAncillaryBuffer::new(&mut space);
    if !control.push(SendAncillaryMessage::ScmRights(&fds)) {
        return Err(Error::Io);
    }
    let sent = sendmsg(
        stream,
        &[IoSlice::new(bytes)],
        &mut control,
        SendFlags::NOSIGNAL,
    )
    .map_err(|_| Error::Io)?;
    if sent == 0 {
        return Err(Error::Io);
    }
    let mut offset = sent;
    while offset < bytes.len() {
        stream
            .set_write_timeout(Some(remaining(deadline)?))
            .map_err(|_| Error::Io)?;
        let count = stream.write(&bytes[offset..]).map_err(|_| Error::Io)?;
        if count == 0 {
            return Err(Error::Io);
        }
        offset += count;
    }
    Ok(())
}

fn remaining(deadline: Instant) -> Result<Duration, Error> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or(Error::Io)
}

fn receive_fd<const N: usize>(stream: &UnixStream) -> Result<([u8; N], OwnedFd), Error> {
    receive_fd_until(stream, Instant::now() + Duration::from_secs(3))
}

fn receive_fd_until<const N: usize>(
    mut stream: &UnixStream,
    deadline: Instant,
) -> Result<([u8; N], OwnedFd), Error> {
    stream
        .set_read_timeout(Some(remaining(deadline)?))
        .map_err(|_| Error::Io)?;
    let mut bytes = [0; N];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
    let mut control = RecvAncillaryBuffer::new(&mut space);
    let message = recvmsg(
        stream,
        &mut [IoSliceMut::new(&mut bytes)],
        &mut control,
        RecvFlags::CMSG_CLOEXEC,
    )
    .map_err(|_| Error::Io)?;
    // rustix owns received descriptors and closes them even on truncation/error.
    if message.bytes == 0
        || message
            .flags
            .intersects(ReturnFlags::CTRUNC | ReturnFlags::TRUNC)
    {
        return Err(Error::InvalidMeasurement);
    }
    let mut descriptors = Vec::new();
    for ancillary in control.drain() {
        match ancillary {
            RecvAncillaryMessage::ScmRights(fds) => descriptors.extend(fds),
            _ => return Err(Error::InvalidMeasurement),
        }
    }
    if descriptors.len() != 1 {
        return Err(Error::InvalidMeasurement);
    }
    let mut offset = message.bytes;
    while offset < N {
        stream
            .set_read_timeout(Some(remaining(deadline)?))
            .map_err(|_| Error::Io)?;
        let count = stream.read(&mut bytes[offset..]).map_err(|_| Error::Io)?;
        if count == 0 {
            return Err(Error::Io);
        }
        offset += count;
    }
    Ok((bytes, descriptors.pop().ok_or(Error::InvalidMeasurement)?))
}

fn measure_credentials(
    stream: &UnixStream,
    creds: UnixCredentials,
) -> Result<PinnedLinuxPeerMeasurementV2, Error> {
    let pid = u32::try_from(creds.pid()).map_err(|_| Error::InvalidMeasurement)?;
    measure_linux_process_pinned(pid, creds.uid(), creds.gid(), socket_peer_pidfd(stream)?)
}

fn handle(stream: &UnixStream, policy: &Policy) -> Result<(), Error> {
    deadlines(stream)?;
    let credentials = getsockopt(stream, PeerCredentials).map_err(|_| Error::Io)?;
    if !policy
        .edges
        .iter()
        .any(|e| e.caller.uid == credentials.uid() && e.caller.gid == credentials.gid())
    {
        return Err(Error::IdentityMismatch);
    }
    let caller = measure_credentials(stream, credentials)?;
    if !policy
        .edges
        .iter()
        .any(|e| e.caller.matches(caller.measurement()))
    {
        return Err(Error::IdentityMismatch);
    }
    let (request, fd) = receive_fd::<4>(stream)?;
    if &request != MAGIC {
        return Err(Error::InvalidMeasurement);
    }
    // Reject pipes/files/datagrams; never read from or write to the subject FD.
    if getsockopt(&fd, SockType).map_err(|_| Error::InvalidMeasurement)?
        != nix::sys::socket::SockType::Stream
    {
        return Err(Error::InvalidMeasurement);
    }
    let subject = UnixStream::from(fd);
    let target_credentials = getsockopt(&subject, PeerCredentials).map_err(|_| Error::Io)?;
    if !policy.edges.iter().any(|e| {
        e.caller.matches(caller.measurement())
            && e.peer.uid == target_credentials.uid()
            && e.peer.gid == target_credentials.gid()
    }) {
        return Err(Error::IdentityMismatch);
    }
    let target = measure_credentials(&subject, target_credentials)?;
    if !policy.permits(caller.measurement(), target.measurement()) {
        return Err(Error::IdentityMismatch);
    }
    require_live(&caller._pidfd)?;
    require_live(&target._pidfd)?;
    let bytes = encode(target.measurement())?;
    send_fd(stream, &bytes, &target._executable)
}

fn encode(measurement: &NativePeerMeasurementV2) -> Result<[u8; RESPONSE], Error> {
    let NativePeerMeasurementV2::Linux {
        uid,
        gid,
        pid,
        process_start_time,
        executable_measurement,
    } = measurement
    else {
        return Err(Error::InvalidMeasurement);
    };
    let mut bytes = [0; RESPONSE];
    bytes[..4].copy_from_slice(MAGIC);
    bytes[4..8].copy_from_slice(&uid.to_be_bytes());
    bytes[8..12].copy_from_slice(&gid.to_be_bytes());
    bytes[12..16].copy_from_slice(&pid.to_be_bytes());
    bytes[16..24].copy_from_slice(&process_start_time.to_be_bytes());
    bytes[24..].copy_from_slice(executable_measurement);
    Ok(bytes)
}

pub(crate) fn measure_through_broker(
    subject: &UnixStream,
    credentials: UnixCredentials,
    pidfd: OwnedFd,
) -> Result<PinnedLinuxPeerMeasurementV2, Error> {
    require_live(&pidfd)?;
    let _directory = root_directory("/run/savana-identity")?;
    let meta = std::fs::symlink_metadata(SOCKET).map_err(|_| Error::Io)?;
    if !meta.file_type().is_socket() || meta.uid() != 0 || meta.mode() & 0o007 != 0 {
        return Err(Error::InvalidMeasurement);
    }
    // A full Unix accept queue must not block a service forever in connect().
    // Unix nonblocking connect succeeds immediately or fails closed; do not
    // retry a backlog error as an unauthenticated fallback route.
    let fd = rustix::net::socket_with(
        rustix::net::AddressFamily::UNIX,
        rustix::net::SocketType::STREAM,
        rustix::net::SocketFlags::CLOEXEC | rustix::net::SocketFlags::NONBLOCK,
        None,
    )
    .map_err(|_| Error::Io)?;
    rustix::net::connect(
        &fd,
        &rustix::net::SocketAddrUnix::new(SOCKET).map_err(|_| Error::Io)?,
    )
    .map_err(|_| Error::Io)?;
    let broker = UnixStream::from(fd);
    broker.set_nonblocking(false).map_err(|_| Error::Io)?;
    deadlines(&broker)?;
    let broker_credentials = getsockopt(&broker, PeerCredentials).map_err(|_| Error::Io)?;
    if broker_credentials.uid() != 0 || broker_credentials.gid() != 0 {
        return Err(Error::IdentityMismatch);
    }
    send_fd(&broker, MAGIC, subject)?;
    let (bytes, fd) = receive_fd::<RESPONSE>(&broker)?;
    let mut executable = File::from(fd);
    let measurement = decode(&bytes, credentials, &mut executable)?;
    require_live(&pidfd)?;
    Ok(PinnedLinuxPeerMeasurementV2 {
        measurement,
        _pidfd: pidfd,
        _proc_dir: None,
        _executable: executable,
    })
}

fn decode(
    bytes: &[u8; RESPONSE],
    credentials: UnixCredentials,
    executable: &mut File,
) -> Result<NativePeerMeasurementV2, Error> {
    let u32_at = |start| {
        u32::from_be_bytes(
            bytes[start..start + 4]
                .try_into()
                .expect("fixed wire offsets"),
        )
    };
    if &bytes[..4] != MAGIC
        || u32_at(4) != credentials.uid()
        || u32_at(8) != credentials.gid()
        || i32::try_from(u32_at(12)).ok() != Some(credentials.pid())
    {
        return Err(Error::IdentityMismatch);
    }
    let meta = executable.metadata().map_err(|_| Error::Io)?;
    if !meta.is_file()
        || meta.uid() != 0
        || meta.gid() != 0
        || meta.nlink() != 1
        || meta.mode() & 0o6022 != 0
        || meta.mode() & 0o111 == 0
    {
        return Err(Error::InvalidMeasurement);
    }
    let digest = hash_executable(executable)?;
    if digest != bytes[24..] {
        return Err(Error::IdentityMismatch);
    }
    let start = u64::from_be_bytes(bytes[16..24].try_into().expect("fixed wire offsets"));
    NativePeerMeasurementV2::linux(
        credentials.uid(),
        credentials.gid(),
        u32_at(12),
        start,
        digest,
    )
}

/// Fixed-path, root-only, socket-activated broker. Failure never becomes a
/// caller-supplied measurement or a relaxed same-UID deployment.
pub fn run_linux_identity_broker_v2() -> Result<(), Error> {
    if !nix::unistd::geteuid().is_root() || nix::unistd::getegid().as_raw() != 0 {
        return Err(Error::IdentityMismatch);
    }
    let mut status = String::new();
    File::open("/proc/self/status")
        .map_err(|_| Error::Io)?
        .take(64 * 1024 + 1)
        .read_to_string(&mut status)
        .map_err(|_| Error::Io)?;
    verify_broker_capabilities(&status)?;
    let policy = load_policy()?;
    let mut listeners = crate::take_systemd_unix_listeners_v2(&["identity-measurement-v2"])?;
    let (_, listener) = listeners
        .pop()
        .ok_or(Error::InvalidMeasurement)?
        .into_parts();
    if !getsockopt(&listener, nix::sys::socket::sockopt::AcceptConn).map_err(|_| Error::Io)?
        || listener.local_addr().map_err(|_| Error::Io)?.as_pathname()
            != Some(std::path::Path::new(SOCKET))
    {
        return Err(Error::IdentityMismatch);
    }
    loop {
        let (stream, _) = listener.accept().map_err(|_| Error::Io)?;
        // One bounded request per connection, close silently on denial. No
        // process information or partial measurement is returned on failure.
        let _ = handle(&stream, &policy);
    }
}

fn verify_broker_capabilities(status: &str) -> Result<(), Error> {
    if status.len() > 64 * 1024 {
        return Err(Error::InvalidMeasurement);
    }
    let fields = [
        ("CapEff:", 1_u64 << 19),
        ("CapPrm:", 1_u64 << 19),
        ("CapBnd:", 1_u64 << 19),
        ("CapInh:", 0),
        ("CapAmb:", 0),
        ("NoNewPrivs:", 1),
    ];
    for (name, expected) in fields {
        let mut found = status.lines().filter_map(|line| line.strip_prefix(name));
        let raw = found.next().ok_or(Error::InvalidMeasurement)?.trim();
        let value = u64::from_str_radix(raw, if name == "NoNewPrivs:" { 10 } else { 16 })
            .map_err(|_| Error::InvalidMeasurement)?;
        if found.next().is_some() || value != expected {
            return Err(Error::InvalidMeasurement);
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "linux_broker_tests.rs"]
mod tests;
