use std::fmt;
use std::io::{ErrorKind, Read as _, Write as _};
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig, ServerConnection, StreamOwned};
use savana_policy_core::v2::BoundedConnectorHostV2;
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::{
    ReleaseRequestError, ReleaseReservationStore, ReservationError, VerifiedReleaseRequest,
    MAX_RELEASE_REQUEST_BYTES,
};

pub const RELEASE_ALPN_PROTOCOL: &[u8] = b"savana-provider-v2";
pub const FINAL_RELEASE_PATH: &str = "/savana/final-release";

const MAX_TLS_CERTIFICATE_BYTES: usize = 128 * 1024;
const MAX_TLS_CHAIN_CERTIFICATES: usize = 8;
const MAX_TLS_PRIVATE_KEY_BYTES: usize = 64 * 1024;
const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(5);
const IO_CHUNK_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ReleaseReceiverError {
    #[error("the final-release receiver configuration is invalid")]
    InvalidConfig,
    #[error("the final-release receiver deadline elapsed")]
    DeadlineExceeded,
    #[error("the final-release receiver transport failed")]
    Transport,
    #[error("the final-release TLS handshake failed")]
    Tls,
    #[error("the final-release client identity is unauthorized")]
    UnauthorizedClient,
    #[error("the final-release ALPN binding is invalid")]
    AlpnMismatch,
    #[error("the final-release request is invalid")]
    InvalidRequest,
    #[error("the final-release reservation rejected the request")]
    Reservation(ReservationError),
}

pub struct ReleaseReceiverConfig {
    canonical_host: String,
    config: Arc<ServerConfig>,
    expected_client_spki_pin: [u8; 32],
    server_spki_pin: [u8; 32],
}

impl fmt::Debug for ReleaseReceiverConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReleaseReceiverConfig")
            .field("canonical_host", &self.canonical_host)
            .field("expected_client_spki_pin", &"[redacted digest]")
            .field("server_spki_pin", &"[redacted digest]")
            .finish_non_exhaustive()
    }
}

impl ReleaseReceiverConfig {
    pub fn new(
        canonical_host: impl AsRef<str>,
        client_root_certificate_der: Vec<u8>,
        server_certificate_chain_der: Vec<Vec<u8>>,
        server_private_key_der: Zeroizing<Vec<u8>>,
        expected_client_spki_pin: [u8; 32],
    ) -> Result<Self, ReleaseReceiverError> {
        let canonical_host = BoundedConnectorHostV2::new(canonical_host.as_ref())
            .map_err(|_| ReleaseReceiverError::InvalidConfig)?;
        if client_root_certificate_der.is_empty()
            || client_root_certificate_der.len() > MAX_TLS_CERTIFICATE_BYTES
            || server_certificate_chain_der.is_empty()
            || server_certificate_chain_der.len() > MAX_TLS_CHAIN_CERTIFICATES
            || server_certificate_chain_der.iter().any(|certificate| {
                certificate.is_empty() || certificate.len() > MAX_TLS_CERTIFICATE_BYTES
            })
            || server_private_key_der.is_empty()
            || server_private_key_der.len() > MAX_TLS_PRIVATE_KEY_BYTES
            || is_zero(&expected_client_spki_pin)
        {
            return Err(ReleaseReceiverError::InvalidConfig);
        }

        let server_spki_pin = Sha256::digest(
            certificate_spki_der(&server_certificate_chain_der[0])
                .ok_or(ReleaseReceiverError::InvalidConfig)?,
        )
        .into();
        let mut client_roots = RootCertStore::empty();
        client_roots
            .add(CertificateDer::from(client_root_certificate_der))
            .map_err(|_| ReleaseReceiverError::InvalidConfig)?;
        let client_verifier = WebPkiClientVerifier::builder(Arc::new(client_roots))
            .build()
            .map_err(|_| ReleaseReceiverError::InvalidConfig)?;
        let certificate_chain = server_certificate_chain_der
            .into_iter()
            .map(CertificateDer::from)
            .collect();
        let private_key = PrivateKeyDer::try_from(server_private_key_der.to_vec())
            .map_err(|_| ReleaseReceiverError::InvalidConfig)?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| ReleaseReceiverError::InvalidConfig)?
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(certificate_chain, private_key)
            .map_err(|_| ReleaseReceiverError::InvalidConfig)?;
        config.alpn_protocols = vec![RELEASE_ALPN_PROTOCOL.to_vec()];
        config.max_early_data_size = 0;
        Ok(Self {
            canonical_host: canonical_host.as_str().to_owned(),
            config: Arc::new(config),
            expected_client_spki_pin,
            server_spki_pin,
        })
    }
}

pub struct ReleaseReceiver {
    listener: TcpListener,
    local_addr: SocketAddr,
    canonical_url: String,
    config: ReleaseReceiverConfig,
    reservations: Arc<ReleaseReservationStore>,
}

impl fmt::Debug for ReleaseReceiver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReleaseReceiver")
            .field("local_addr", &self.local_addr)
            .field("canonical_url", &self.canonical_url)
            .finish_non_exhaustive()
    }
}

impl ReleaseReceiver {
    pub fn bind(
        address: SocketAddr,
        config: ReleaseReceiverConfig,
        reservations: Arc<ReleaseReservationStore>,
    ) -> Result<Self, ReleaseReceiverError> {
        if !address.ip().is_loopback() {
            return Err(ReleaseReceiverError::InvalidConfig);
        }
        let listener = TcpListener::bind(address).map_err(|_| ReleaseReceiverError::Transport)?;
        listener
            .set_nonblocking(true)
            .map_err(|_| ReleaseReceiverError::Transport)?;
        let local_addr = listener
            .local_addr()
            .map_err(|_| ReleaseReceiverError::Transport)?;
        if !local_addr.ip().is_loopback() || local_addr.port() == 0 {
            return Err(ReleaseReceiverError::InvalidConfig);
        }
        let canonical_url = format!(
            "https://{}:{}{}",
            config.canonical_host,
            local_addr.port(),
            FINAL_RELEASE_PATH
        );
        Ok(Self {
            listener,
            local_addr,
            canonical_url,
            config,
            reservations,
        })
    }

    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn canonical_url(&self) -> &str {
        &self.canonical_url
    }

    pub fn accept_one(
        &self,
        now_unix_ms: u64,
        deadline: Instant,
    ) -> Result<(), ReleaseReceiverError> {
        let (stream, peer) = loop {
            if Instant::now() >= deadline {
                return Err(ReleaseReceiverError::DeadlineExceeded);
            }
            match self.listener.accept() {
                Ok(connection) => break connection,
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(ACCEPT_POLL_INTERVAL);
                }
                Err(_) => return Err(ReleaseReceiverError::Transport),
            }
        };
        if !peer.ip().is_loopback() {
            return Err(ReleaseReceiverError::Transport);
        }
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or(ReleaseReceiverError::DeadlineExceeded)?;
        stream
            .set_nonblocking(false)
            .and_then(|()| stream.set_read_timeout(Some(remaining)))
            .and_then(|()| stream.set_write_timeout(Some(remaining)))
            .map_err(|_| ReleaseReceiverError::Transport)?;
        let connection = ServerConnection::new(Arc::clone(&self.config.config))
            .map_err(|_| ReleaseReceiverError::Tls)?;
        let mut tls = StreamOwned::new(connection, stream);
        while tls.conn.is_handshaking() {
            if Instant::now() >= deadline {
                return Err(ReleaseReceiverError::DeadlineExceeded);
            }
            tls.conn
                .complete_io(&mut tls.sock)
                .map_err(|_| ReleaseReceiverError::Tls)?;
        }
        if tls.conn.alpn_protocol() != Some(RELEASE_ALPN_PROTOCOL) {
            return Err(ReleaseReceiverError::AlpnMismatch);
        }
        let client_leaf = tls
            .conn
            .peer_certificates()
            .and_then(|certificates| certificates.first())
            .ok_or(ReleaseReceiverError::UnauthorizedClient)?;
        let client_spki = certificate_spki_der(client_leaf.as_ref())
            .ok_or(ReleaseReceiverError::UnauthorizedClient)?;
        if <[u8; 32]>::from(Sha256::digest(client_spki)) != self.config.expected_client_spki_pin {
            return Err(ReleaseReceiverError::UnauthorizedClient);
        }

        let request = read_request(&mut tls, deadline)?;
        if request.canonical_url() != self.canonical_url
            || request.tls_identity_pin() != &self.config.server_spki_pin
        {
            return Err(ReleaseReceiverError::InvalidRequest);
        }
        let wire_digest = *request.wire_digest();
        self.reservations
            .claim_next(now_unix_ms, request)
            .map_err(ReleaseReceiverError::Reservation)?;
        let acknowledgement = encode_acknowledgement(&wire_digest)?;
        tls.write_all(&acknowledgement)
            .and_then(|()| tls.flush())
            .map_err(|_| ReleaseReceiverError::Transport)?;
        tls.conn.send_close_notify();
        tls.conn
            .complete_io(&mut tls.sock)
            .map_err(|_| ReleaseReceiverError::Transport)?;
        Ok(())
    }
}

fn read_request(
    tls: &mut StreamOwned<ServerConnection, std::net::TcpStream>,
    deadline: Instant,
) -> Result<VerifiedReleaseRequest, ReleaseReceiverError> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(IO_CHUNK_BYTES)
        .map_err(|_| ReleaseReceiverError::Transport)?;
    let mut chunk = [0_u8; IO_CHUNK_BYTES];
    loop {
        if Instant::now() >= deadline {
            return Err(ReleaseReceiverError::DeadlineExceeded);
        }
        let read = tls
            .read(&mut chunk)
            .map_err(|_| ReleaseReceiverError::Transport)?;
        if read == 0 {
            return Err(ReleaseReceiverError::InvalidRequest);
        }
        let next_len = bytes
            .len()
            .checked_add(read)
            .filter(|length| *length <= MAX_RELEASE_REQUEST_BYTES)
            .ok_or(ReleaseReceiverError::InvalidRequest)?;
        bytes
            .try_reserve(next_len.saturating_sub(bytes.len()))
            .map_err(|_| ReleaseReceiverError::Transport)?;
        bytes.extend_from_slice(&chunk[..read]);
        match VerifiedReleaseRequest::decode(&bytes) {
            Ok(request) => return Ok(request),
            Err(ReleaseRequestError::TooLarge) => return Err(ReleaseReceiverError::InvalidRequest),
            Err(ReleaseRequestError::NonCanonical) => {}
        }
    }
}

fn encode_acknowledgement(wire_digest: &[u8; 32]) -> Result<Vec<u8>, ReleaseReceiverError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(3)
        .and_then(|encoder| encoder.u16(2))
        .and_then(|encoder| encoder.u16(1))
        .and_then(|encoder| encoder.bytes(wire_digest))
        .map_err(|_| ReleaseReceiverError::Transport)?;
    Ok(encoder.into_writer())
}

fn certificate_spki_der(certificate: &[u8]) -> Option<&[u8]> {
    let (_, certificate_content, certificate_end) = der_element(certificate, 0, 0x30)?;
    if certificate_end != certificate.len() {
        return None;
    }
    let certificate = certificate.get(certificate_content..certificate_end)?;
    let (_, tbs_content, tbs_end) = der_element(certificate, 0, 0x30)?;
    let tbs = certificate.get(tbs_content..tbs_end)?;
    let mut offset = 0;
    if tbs.get(offset).copied() == Some(0xa0) {
        offset = der_element(tbs, offset, 0xa0)?.2;
    }
    for _ in 0..5 {
        offset = der_any(tbs, offset)?.2;
    }
    let (_, _, spki_end) = der_element(tbs, offset, 0x30)?;
    tbs.get(offset..spki_end)
}

fn der_any(bytes: &[u8], offset: usize) -> Option<(usize, usize, usize)> {
    let tag = *bytes.get(offset)?;
    der_element(bytes, offset, tag)
}

fn der_element(bytes: &[u8], offset: usize, expected_tag: u8) -> Option<(usize, usize, usize)> {
    if *bytes.get(offset)? != expected_tag {
        return None;
    }
    let first = *bytes.get(offset.checked_add(1)?)?;
    let (length, header) = if first & 0x80 == 0 {
        (usize::from(first), 2)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 {
            return None;
        }
        let mut length = 0_usize;
        for byte in bytes.get(offset.checked_add(2)?..offset.checked_add(2 + count)?)? {
            length = length.checked_mul(256)?.checked_add(usize::from(*byte))?;
        }
        (length, 2 + count)
    };
    let content = offset.checked_add(header)?;
    let end = content.checked_add(length)?;
    if end > bytes.len() {
        return None;
    }
    Some((offset, content, end))
}

fn is_zero(bytes: &[u8; 32]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}
