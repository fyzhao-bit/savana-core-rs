use std::io::{Read as _, Write as _};
use std::net::SocketAddr;
use std::net::{Shutdown, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use savana_kernel_protocol::v2::{Digest32V2, UnixMillisV2};
use savana_policy_core::v2::validate_measured_model_connect_addresses_v2;
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

const MAX_HEADER_BYTES_V2: usize = 32 * 1024;
const HTTP_1_1_ALPN_V2: &[u8] = b"http/1.1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PrivateModelTransportErrorV2 {
    DeadlineExceeded,
    InvalidDeployment,
    Unavailable,
    InvalidResponse,
}

#[derive(Clone)]
pub(crate) struct VerifiedMtlsClientCredentialsV2 {
    tls: Arc<ClientConfig>,
}

impl VerifiedMtlsClientCredentialsV2 {
    pub(crate) fn from_verified_deployment(
        root_certificate_der: Vec<u8>,
        client_certificate_der: Vec<u8>,
        client_private_key_pkcs8_der: Zeroizing<Vec<u8>>,
    ) -> Result<Self, PrivateModelTransportErrorV2> {
        if root_certificate_der.is_empty()
            || client_certificate_der.is_empty()
            || client_private_key_pkcs8_der.is_empty()
        {
            return Err(PrivateModelTransportErrorV2::InvalidDeployment);
        }
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(root_certificate_der))
            .map_err(|_| PrivateModelTransportErrorV2::InvalidDeployment)?;
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            client_private_key_pkcs8_der.to_vec(),
        ));
        let mut tls = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(vec![CertificateDer::from(client_certificate_der)], key)
            .map_err(|_| PrivateModelTransportErrorV2::InvalidDeployment)?;
        tls.enable_early_data = false;
        tls.resumption = rustls::client::Resumption::disabled();
        tls.alpn_protocols = vec![HTTP_1_1_ALPN_V2.to_vec()];
        Ok(Self { tls: Arc::new(tls) })
    }
}

pub(crate) type ConnectorFunctionV2 =
    dyn Fn(SocketAddr, Duration) -> std::io::Result<TcpStream> + Send + Sync + 'static;

pub(crate) struct PinnedMtlsCborEndpointV2 {
    host: String,
    port: u16,
    connect_addresses: Vec<SocketAddr>,
    server_spki_sha256: Digest32V2,
    credentials: VerifiedMtlsClientCredentialsV2,
    connector: Arc<ConnectorFunctionV2>,
}

impl core::fmt::Debug for PinnedMtlsCborEndpointV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PinnedMtlsCborEndpointV2")
            .field("host", &self.host)
            .field("port", &self.port)
            .finish_non_exhaustive()
    }
}

impl PinnedMtlsCborEndpointV2 {
    pub(crate) fn from_verified_deployment(
        host: String,
        port: u16,
        connect_addresses: Vec<SocketAddr>,
        server_spki_sha256: Digest32V2,
        credentials: VerifiedMtlsClientCredentialsV2,
    ) -> Result<Self, PrivateModelTransportErrorV2> {
        if !valid_dns_name(&host) || port == 0 || server_spki_sha256.as_bytes() == &[0; 32] {
            return Err(PrivateModelTransportErrorV2::InvalidDeployment);
        }
        ServerName::try_from(host.clone())
            .map_err(|_| PrivateModelTransportErrorV2::InvalidDeployment)?;
        let connect_addresses =
            validate_measured_model_connect_addresses_v2(connect_addresses, port)
                .map_err(|_| PrivateModelTransportErrorV2::InvalidDeployment)?;
        Ok(Self {
            host,
            port,
            connect_addresses,
            server_spki_sha256,
            credentials,
            connector: Arc::new(|address, timeout| TcpStream::connect_timeout(&address, timeout)),
        })
    }

    #[cfg(any(test, all(feature = "test-support", debug_assertions)))]
    pub(crate) fn set_test_connector(&mut self, connect: Arc<ConnectorFunctionV2>) {
        self.connector = connect;
    }

    pub(crate) fn post_canonical_cbor(
        &self,
        path: &str,
        body: &[u8],
        maximum_response_body_bytes: usize,
        deadline: UnixMillisV2,
    ) -> Result<Vec<u8>, PrivateModelTransportErrorV2> {
        if !valid_path(path)
            || body.is_empty()
            || body.len() > maximum_response_body_bytes
            || maximum_response_body_bytes == 0
        {
            return Err(PrivateModelTransportErrorV2::InvalidResponse);
        }
        let timeout = remaining(deadline)?;
        let absolute_deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(PrivateModelTransportErrorV2::DeadlineExceeded)?;
        let socket = self.connect(absolute_deadline)?;
        refresh_io_timeout(&socket, absolute_deadline)?;
        let server_name = ServerName::try_from(self.host.clone())
            .map_err(|_| PrivateModelTransportErrorV2::InvalidDeployment)?;
        let connection = ClientConnection::new(Arc::clone(&self.credentials.tls), server_name)
            .map_err(|_| PrivateModelTransportErrorV2::Unavailable)?;
        let mut stream = StreamOwned::new(connection, socket);
        let result = self.exchange(
            &mut stream,
            path,
            body,
            maximum_response_body_bytes,
            absolute_deadline,
        );
        let _ = stream.sock.shutdown(Shutdown::Both);
        result
    }

    fn connect(&self, deadline: Instant) -> Result<TcpStream, PrivateModelTransportErrorV2> {
        let candidate_count = self.connect_addresses.len();
        for (index, address) in self.connect_addresses.iter().copied().enumerate() {
            let remaining = remaining_until(deadline)?;
            let remaining_candidates = candidate_count
                .checked_sub(index)
                .ok_or(PrivateModelTransportErrorV2::Unavailable)?;
            let divisor = u32::try_from(remaining_candidates)
                .map_err(|_| PrivateModelTransportErrorV2::Unavailable)?;
            let fair_share = remaining / divisor;
            let timeout = fair_share.max(Duration::from_nanos(1)).min(remaining);
            if let Ok(socket) = (self.connector)(address, timeout) {
                return Ok(socket);
            }
        }
        Err(io_failure(deadline))
    }

    fn exchange(
        &self,
        stream: &mut StreamOwned<ClientConnection, TcpStream>,
        path: &str,
        body: &[u8],
        maximum_response_body_bytes: usize,
        deadline: Instant,
    ) -> Result<Vec<u8>, PrivateModelTransportErrorV2> {
        while stream.conn.is_handshaking() {
            refresh_io_timeout(&stream.sock, deadline)?;
            stream
                .conn
                .complete_io(&mut stream.sock)
                .map_err(|_| io_failure(deadline))?;
        }
        let certificate = stream
            .conn
            .peer_certificates()
            .and_then(|certificates| certificates.first())
            .ok_or(PrivateModelTransportErrorV2::Unavailable)?;
        let spki = certificate_spki_der(certificate.as_ref())
            .ok_or(PrivateModelTransportErrorV2::Unavailable)?;
        if Digest32V2::new(Sha256::digest(spki).into()) != self.server_spki_sha256 {
            return Err(PrivateModelTransportErrorV2::InvalidDeployment);
        }
        if stream.conn.alpn_protocol() != Some(HTTP_1_1_ALPN_V2) {
            return Err(PrivateModelTransportErrorV2::InvalidDeployment);
        }
        let host = if self.port == 443 {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        };
        let header = format!(
            "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/cbor\r\nAccept: application/cbor\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        refresh_io_timeout(&stream.sock, deadline)?;
        stream
            .write_all(header.as_bytes())
            .and_then(|()| stream.write_all(body))
            .and_then(|()| stream.flush())
            .map_err(|_| io_failure(deadline))?;
        let header = read_header(stream, deadline)?;
        let content_length = validate_response_header(&header, maximum_response_body_bytes)?;
        let mut response = vec![0_u8; content_length];
        read_exact_deadline(stream, &mut response, deadline)?;
        require_clean_eof(stream, deadline)?;
        Ok(response)
    }
}

fn require_clean_eof(
    stream: &mut StreamOwned<ClientConnection, TcpStream>,
    deadline: Instant,
) -> Result<(), PrivateModelTransportErrorV2> {
    refresh_io_timeout(&stream.sock, deadline)?;
    let mut trailing = [0_u8; 1];
    match stream.read(&mut trailing) {
        Ok(0) => Ok(()),
        Ok(_) => Err(PrivateModelTransportErrorV2::InvalidResponse),
        Err(_) if Instant::now() >= deadline => Err(PrivateModelTransportErrorV2::DeadlineExceeded),
        Err(_) => Err(PrivateModelTransportErrorV2::InvalidResponse),
    }
}

fn read_exact_deadline(
    stream: &mut StreamOwned<ClientConnection, TcpStream>,
    output: &mut [u8],
    deadline: Instant,
) -> Result<(), PrivateModelTransportErrorV2> {
    let mut offset = 0;
    while offset < output.len() {
        refresh_io_timeout(&stream.sock, deadline)?;
        let read = stream
            .read(&mut output[offset..])
            .map_err(|_| io_failure(deadline))?;
        if read == 0 {
            return Err(PrivateModelTransportErrorV2::Unavailable);
        }
        offset = offset
            .checked_add(read)
            .ok_or(PrivateModelTransportErrorV2::InvalidResponse)?;
    }
    Ok(())
}

fn remaining(deadline: UnixMillisV2) -> Result<Duration, PrivateModelTransportErrorV2> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| PrivateModelTransportErrorV2::Unavailable)?
        .as_millis();
    let now = u64::try_from(now).map_err(|_| PrivateModelTransportErrorV2::Unavailable)?;
    let millis = deadline
        .get()
        .checked_sub(now)
        .filter(|millis| *millis > 0)
        .ok_or(PrivateModelTransportErrorV2::DeadlineExceeded)?;
    Ok(Duration::from_millis(millis.min(30_000)))
}

fn read_header(
    stream: &mut StreamOwned<ClientConnection, TcpStream>,
    deadline: Instant,
) -> Result<Vec<u8>, PrivateModelTransportErrorV2> {
    let mut header = Vec::new();
    header
        .try_reserve(1024)
        .map_err(|_| PrivateModelTransportErrorV2::Unavailable)?;
    while header.len() < MAX_HEADER_BYTES_V2 {
        refresh_io_timeout(&stream.sock, deadline)?;
        let mut byte = [0_u8; 1];
        stream
            .read_exact(&mut byte)
            .map_err(|_| io_failure(deadline))?;
        header.push(byte[0]);
        if header.ends_with(b"\r\n\r\n") {
            return Ok(header);
        }
    }
    Err(PrivateModelTransportErrorV2::InvalidResponse)
}

fn refresh_io_timeout(
    socket: &TcpStream,
    deadline: Instant,
) -> Result<(), PrivateModelTransportErrorV2> {
    let remaining = remaining_until(deadline)?;
    socket
        .set_read_timeout(Some(remaining))
        .and_then(|()| socket.set_write_timeout(Some(remaining)))
        .map_err(|_| PrivateModelTransportErrorV2::Unavailable)
}

fn remaining_until(deadline: Instant) -> Result<Duration, PrivateModelTransportErrorV2> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or(PrivateModelTransportErrorV2::DeadlineExceeded)
}

fn io_failure(deadline: Instant) -> PrivateModelTransportErrorV2 {
    if Instant::now() >= deadline {
        PrivateModelTransportErrorV2::DeadlineExceeded
    } else {
        PrivateModelTransportErrorV2::Unavailable
    }
}

pub(crate) fn validate_response_header(
    header: &[u8],
    maximum_response_body_bytes: usize,
) -> Result<usize, PrivateModelTransportErrorV2> {
    let text =
        core::str::from_utf8(header).map_err(|_| PrivateModelTransportErrorV2::InvalidResponse)?;
    let mut lines = text
        .strip_suffix("\r\n\r\n")
        .ok_or(PrivateModelTransportErrorV2::InvalidResponse)?
        .split("\r\n");
    if lines.next() != Some("HTTP/1.1 200 OK") {
        return Err(PrivateModelTransportErrorV2::InvalidResponse);
    }
    let mut content_type = None;
    let mut content_length = None;
    let mut connection = None;
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .ok_or(PrivateModelTransportErrorV2::InvalidResponse)?;
        let name = name.to_ascii_lowercase();
        let value = value.trim();
        match name.as_str() {
            "content-type" if content_type.replace(value).is_none() => {}
            "content-length" if content_length.replace(value).is_none() => {}
            "connection" if connection.replace(value).is_none() => {}
            "content-encoding" | "transfer-encoding" | "set-cookie" | "location" | "trailer" => {
                return Err(PrivateModelTransportErrorV2::InvalidResponse);
            }
            "content-type" | "content-length" | "connection" => {
                return Err(PrivateModelTransportErrorV2::InvalidResponse);
            }
            _ => {}
        }
    }
    if content_type != Some("application/cbor")
        || !connection.is_some_and(|value| value.eq_ignore_ascii_case("close"))
    {
        return Err(PrivateModelTransportErrorV2::InvalidResponse);
    }
    let length = content_length
        .ok_or(PrivateModelTransportErrorV2::InvalidResponse)?
        .parse::<usize>()
        .map_err(|_| PrivateModelTransportErrorV2::InvalidResponse)?;
    if length == 0 || length > maximum_response_body_bytes {
        return Err(PrivateModelTransportErrorV2::InvalidResponse);
    }
    Ok(length)
}

fn valid_path(value: &str) -> bool {
    value.starts_with('/')
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'#' && byte != b'?')
}

fn valid_dns_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

pub(crate) fn certificate_spki_der(certificate: &[u8]) -> Option<&[u8]> {
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

#[cfg(test)]
mod tests {
    use super::validate_response_header;

    #[test]
    fn response_surface_rejects_ambient_http_features() {
        assert_eq!(
            validate_response_header(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/cbor\r\nContent-Length: 42\r\nConnection: close\r\n\r\n",
                1024,
            )
            .unwrap(),
            42
        );
        for forbidden in [
            "Content-Encoding: gzip",
            "Transfer-Encoding: chunked",
            "Set-Cookie: x=y",
            "Location: https://other.example/",
            "Trailer: Digest",
        ] {
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/cbor\r\nContent-Length: 42\r\n{forbidden}\r\nConnection: close\r\n\r\n"
            );
            assert!(validate_response_header(header.as_bytes(), 1024).is_err());
        }
    }
}
