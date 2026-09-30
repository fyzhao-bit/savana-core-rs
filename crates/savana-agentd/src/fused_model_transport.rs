//! v0.4 egress over a single Unix TLS tunnel. No TCP/DNS, retry or fallback.
//! Construction is a trusted deployment operation, NOT an agent/model API.
use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use nix::poll::{poll, PollFd, PollFlags};
use nix::sys::socket::{
    connect, getsockopt, socket, sockopt, AddressFamily, SockFlag, SockType, UnixAddr,
};
use rustls::{ClientConnection, StreamOwned};
use savana_kernel_protocol::v2::{Digest32V2, UnixMillisV2};
use savana_policy_core::v2::{
    FusedModelTransportErrorV04 as Error, FusedModelTransportV04, MAX_FUSED_MODEL_EXCHANGE_MS_V04,
    MAX_FUSED_MODEL_REPLY_BYTES_V04,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::private_model_transport::{
    certificate_spki_der, valid_dns_name, validate_response_header, VerifiedMtlsClientCredentialsV2,
};

const PATH: &str = "/savana.fused.v04/exchange";
const MAX_REQUEST: usize = 32 * 1024;
const MAX_HEADER: usize = 4096;
fn unavailable<T>(_: T) -> Error {
    Error::Unavailable
}

/// Identity names the pinned endpoint, not model-generated metadata or an IP.
/// Signed profiles and G3 reader sets must explicitly name this digest.
pub fn fused_model_recipient_v04(host: &str, spki: Digest32V2) -> Result<[u8; 32], Error> {
    if !valid_dns_name(host) || host != host.to_ascii_lowercase() || spki.as_bytes() == &[0; 32] {
        return Err(Error::Unavailable);
    }
    let mut hash = Sha256::new();
    hash.update(b"SAVANA_FUSED_MTLS_RECIPIENT_V04\0");
    hash.update((host.len() as u32).to_be_bytes());
    hash.update(host.as_bytes());
    hash.update(spki.as_bytes());
    hash.update(PATH.as_bytes());
    Ok(hash.finalize().into())
}

pub struct UnixMtlsFusedModelTransportV04 {
    host: String,
    socket: PathBuf,
    spki: Digest32V2,
    recipient: [u8; 32],
    credentials: VerifiedMtlsClientCredentialsV2,
}

impl std::fmt::Debug for UnixMtlsFusedModelTransportV04 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("UnixMtlsFusedModelTransportV04(<deployment-redacted>)")
    }
}

impl UnixMtlsFusedModelTransportV04 {
    pub fn from_verified_deployment(
        host: String,
        socket: PathBuf,
        spki: Digest32V2,
        root: Vec<u8>,
        certificate: Vec<u8>,
        private_key: Zeroizing<Vec<u8>>,
    ) -> Result<Self, Error> {
        let recipient = fused_model_recipient_v04(&host, spki)?;
        if !socket.is_absolute()
            || socket.as_os_str().len() > 100
            || socket
                .components()
                .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
            || root.len() > 16384
            || certificate.len() > 16384
            || private_key.len() > 16384
        {
            return Err(Error::Unavailable);
        }
        let credentials = VerifiedMtlsClientCredentialsV2::from_verified_deployment(
            root,
            certificate,
            private_key,
        )
        .map_err(unavailable)?;
        Ok(Self {
            host,
            socket,
            spki,
            recipient,
            credentials,
        })
    }

    fn exchange_inner(
        &self,
        request: &[u8],
        deadline: UnixMillisV2,
        limit: usize,
    ) -> Result<Vec<u8>, Error> {
        if request.is_empty()
            || request.len() > MAX_REQUEST
            || limit == 0
            || limit > MAX_FUSED_MODEL_REPLY_BYTES_V04
        {
            return Err(Error::Unavailable);
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(unavailable)?
            .as_millis();
        let remaining = u128::from(deadline.get())
            .checked_sub(now)
            .filter(|v| *v > 0)
            .ok_or(Error::Unavailable)?;
        let duration = Duration::from_millis(
            remaining.min(u128::from(MAX_FUSED_MODEL_EXCHANGE_MS_V04)) as u64,
        );
        let end = Instant::now()
            .checked_add(duration)
            .ok_or(Error::Unavailable)?;
        let raw = connect_unix(&self.socket, end)?;
        let connection = ClientConnection::new(
            self.credentials.tls_config(),
            rustls::pki_types::ServerName::try_from(self.host.clone()).map_err(unavailable)?,
        )
        .map_err(unavailable)?;
        let mut tls = StreamOwned::new(
            connection,
            DeadlineStream {
                stream: raw,
                deadline: end,
            },
        );
        let result = (|| {
            while tls.conn.is_handshaking() {
                tls.conn.complete_io(&mut tls.sock).map_err(unavailable)?;
            }
            let certificate = tls
                .conn
                .peer_certificates()
                .and_then(|v| v.first())
                .ok_or(Error::Unavailable)?;
            let spki = certificate_spki_der(certificate.as_ref()).ok_or(Error::Unavailable)?;
            if Digest32V2::new(Sha256::digest(spki).into()) != self.spki
                || tls.conn.alpn_protocol() != Some(b"http/1.1")
            {
                return Err(Error::Unavailable);
            }
            // Do not send even HTTP headers until PKI, hostname, pin and ALPN pass.
            let body = encode_bytes(request)?;
            let header=format!("POST {PATH} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/cbor\r\nAccept: application/cbor\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",self.host,body.len());
            tls.write_all(header.as_bytes())
                .and_then(|()| tls.write_all(&body))
                .and_then(|()| tls.flush())
                .map_err(unavailable)?;
            let mut header = Vec::new();
            while !header.ends_with(b"\r\n\r\n") {
                if header.len() >= MAX_HEADER {
                    return Err(Error::Unavailable);
                }
                let mut byte = [0];
                tls.read_exact(&mut byte).map_err(unavailable)?;
                header.push(byte[0]);
            }
            let size = validate_response_header(&header, limit + 5).map_err(unavailable)?;
            let mut reply = vec![0; size];
            tls.read_exact(&mut reply).map_err(unavailable)?;
            // close_notify is required; truncation and trailing bytes are errors.
            let mut extra = [0];
            let eof = tls.read(&mut extra);
            if eof.map_err(unavailable)? != 0 {
                return Err(Error::Unavailable);
            }
            if Instant::now() >= end {
                return Err(Error::Unavailable);
            }
            let mut decoder = minicbor::Decoder::new(&reply);
            let value = decoder.bytes().map_err(unavailable)?;
            if value.is_empty()
                || value.len() > limit
                || decoder.position() != reply.len()
                || encode_bytes(value)? != reply
            {
                return Err(Error::Unavailable);
            }
            Ok(value.to_vec())
        })();
        let _ = tls.sock.stream.shutdown(Shutdown::Both);
        result
    }
}

impl FusedModelTransportV04 for UnixMtlsFusedModelTransportV04 {
    fn recipient_identity(&self) -> [u8; 32] {
        self.recipient
    }
    fn exchange(
        &mut self,
        request: &[u8],
        deadline: UnixMillisV2,
        limit: usize,
    ) -> Result<Vec<u8>, Error> {
        self.exchange_inner(request, deadline, limit)
    }
}

fn encode_bytes(value: &[u8]) -> Result<Vec<u8>, Error> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder.bytes(value).map_err(unavailable)?;
    Ok(encoder.into_writer())
}

// Absolute monotonic deadline is refreshed at every OS read/write, including
// TLS handshake IO. Slow byte trickles cannot restart the timeout.
struct DeadlineStream {
    stream: UnixStream,
    deadline: Instant,
}
impl DeadlineStream {
    fn remaining(&self) -> std::io::Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|v| !v.is_zero())
            .ok_or_else(|| std::io::ErrorKind::TimedOut.into())
    }
}
impl Read for DeadlineStream {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        self.stream.set_read_timeout(Some(self.remaining()?))?;
        self.stream.read(b)
    }
}
impl Write for DeadlineStream {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.write(b)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.remaining()?;
        self.stream.flush()
    }
}

fn connect_unix(path: &Path, deadline: Instant) -> Result<UnixStream, Error> {
    use std::os::fd::AsRawFd;
    #[cfg(target_os = "linux")]
    let flags = SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK;
    #[cfg(not(target_os = "linux"))]
    let flags = SockFlag::empty();
    let fd = socket(AddressFamily::Unix, SockType::Stream, flags, None).map_err(unavailable)?;
    #[cfg(not(target_os = "linux"))]
    nix::fcntl::fcntl(
        fd.as_raw_fd(),
        nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::FD_CLOEXEC),
    )
    .map_err(unavailable)?;
    let fd = UnixStream::from(fd);
    fd.set_nonblocking(true).map_err(unavailable)?;
    let address = UnixAddr::new(path).map_err(unavailable)?;
    match connect(fd.as_raw_fd(), &address) {
        Ok(()) => (),
        Err(nix::errno::Errno::EINPROGRESS) => {
            let left = deadline
                .checked_duration_since(Instant::now())
                .ok_or(Error::Unavailable)?;
            let ms = u16::try_from(left.as_millis()).map_err(unavailable)?;
            let mut fds = [PollFd::new(fd.as_fd(), PollFlags::POLLOUT)];
            if ms == 0
                || poll(&mut fds, ms).map_err(unavailable)? != 1
                || getsockopt(&fd, sockopt::SocketError).map_err(unavailable)? != 0
            {
                return Err(Error::Unavailable);
            }
        }
        Err(_) => return Err(Error::Unavailable),
    }
    if Instant::now() >= deadline {
        return Err(Error::Unavailable);
    }
    fd.set_nonblocking(false).map_err(unavailable)?;
    Ok(fd)
}

#[cfg(test)]
#[path = "fused_model_transport_tests.rs"]
mod tests;
