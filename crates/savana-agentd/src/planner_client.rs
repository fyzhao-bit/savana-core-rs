use std::io::{Read as _, Write as _};
use std::net::{Shutdown, TcpStream};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use savana_kernel_protocol::v2::{
    decode_planner_plan_v2, Digest32V2, PlannerEnvelopeV2, PlannerPlanV2, UnixMillisV2,
};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

const PLANNER_PATH_V2: &str = "/savana.planner.v2/plan";
const MAX_HEADER_BYTES_V2: usize = 32 * 1024;
const MAX_PLANNER_BODY_BYTES_V2: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AgentPlannerClientErrorV2 {
    #[error("planner deadline was exceeded")]
    DeadlineExceeded,
    #[error("planner deployment binding is invalid")]
    InvalidDeployment,
    #[error("planner transport or response is unavailable")]
    Unavailable,
    #[error("planner returned a non-canonical or invalid plan")]
    InvalidPlan,
}

pub struct PinnedMtlsAgentPlannerClientV2 {
    host: String,
    port: u16,
    server_spki_sha256: Digest32V2,
    tls: Arc<ClientConfig>,
}

impl core::fmt::Debug for PinnedMtlsAgentPlannerClientV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PinnedMtlsAgentPlannerClientV2")
            .field("host", &self.host)
            .field("port", &self.port)
            .finish_non_exhaustive()
    }
}

impl PinnedMtlsAgentPlannerClientV2 {
    pub fn from_verified_deployment(
        host: String,
        port: u16,
        server_spki_sha256: Digest32V2,
        root_certificate_der: Vec<u8>,
        client_certificate_der: Vec<u8>,
        client_private_key_pkcs8_der: Zeroizing<Vec<u8>>,
    ) -> Result<Self, AgentPlannerClientErrorV2> {
        if !valid_dns_name(&host)
            || port == 0
            || server_spki_sha256.as_bytes() == &[0; 32]
            || root_certificate_der.is_empty()
            || client_certificate_der.is_empty()
            || client_private_key_pkcs8_der.is_empty()
        {
            return Err(AgentPlannerClientErrorV2::InvalidDeployment);
        }
        ServerName::try_from(host.clone())
            .map_err(|_| AgentPlannerClientErrorV2::InvalidDeployment)?;
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(root_certificate_der))
            .map_err(|_| AgentPlannerClientErrorV2::InvalidDeployment)?;
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            client_private_key_pkcs8_der.to_vec(),
        ));
        let tls = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(vec![CertificateDer::from(client_certificate_der)], key)
            .map_err(|_| AgentPlannerClientErrorV2::InvalidDeployment)?;
        Ok(Self {
            host,
            port,
            server_spki_sha256,
            tls: Arc::new(tls),
        })
    }

    pub fn plan(
        &self,
        envelope: &PlannerEnvelopeV2,
        deadline: UnixMillisV2,
    ) -> Result<PlannerPlanV2, AgentPlannerClientErrorV2> {
        let timeout = remaining(deadline)?;
        let body =
            minicbor::to_vec(envelope).map_err(|_| AgentPlannerClientErrorV2::InvalidPlan)?;
        if body.is_empty() || body.len() > MAX_PLANNER_BODY_BYTES_V2 {
            return Err(AgentPlannerClientErrorV2::InvalidPlan);
        }
        let socket = TcpStream::connect((self.host.as_str(), self.port))
            .map_err(|_| AgentPlannerClientErrorV2::Unavailable)?;
        socket
            .set_read_timeout(Some(timeout))
            .and_then(|()| socket.set_write_timeout(Some(timeout)))
            .map_err(|_| AgentPlannerClientErrorV2::Unavailable)?;
        let server_name = ServerName::try_from(self.host.clone())
            .map_err(|_| AgentPlannerClientErrorV2::InvalidDeployment)?;
        let connection = ClientConnection::new(Arc::clone(&self.tls), server_name)
            .map_err(|_| AgentPlannerClientErrorV2::Unavailable)?;
        let mut stream = StreamOwned::new(connection, socket);
        let result = self.exchange(&mut stream, &body);
        let _ = stream.sock.shutdown(Shutdown::Both);
        result
    }

    fn exchange(
        &self,
        stream: &mut StreamOwned<ClientConnection, TcpStream>,
        body: &[u8],
    ) -> Result<PlannerPlanV2, AgentPlannerClientErrorV2> {
        while stream.conn.is_handshaking() {
            stream
                .conn
                .complete_io(&mut stream.sock)
                .map_err(|_| AgentPlannerClientErrorV2::Unavailable)?;
        }
        let certificate = stream
            .conn
            .peer_certificates()
            .and_then(|certificates| certificates.first())
            .ok_or(AgentPlannerClientErrorV2::Unavailable)?;
        let spki = certificate_spki_der(certificate.as_ref())
            .ok_or(AgentPlannerClientErrorV2::Unavailable)?;
        if Digest32V2::new(Sha256::digest(spki).into()) != self.server_spki_sha256 {
            return Err(AgentPlannerClientErrorV2::InvalidDeployment);
        }
        let host = if self.port == 443 {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        };
        let header = format!(
            "POST {PLANNER_PATH_V2} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/cbor\r\nAccept: application/cbor\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream
            .write_all(header.as_bytes())
            .and_then(|()| stream.write_all(body))
            .and_then(|()| stream.flush())
            .map_err(|_| AgentPlannerClientErrorV2::Unavailable)?;
        let header = read_header(stream)?;
        let content_length = validate_response_header(&header)?;
        let mut response = vec![0_u8; content_length];
        stream
            .read_exact(&mut response)
            .map_err(|_| AgentPlannerClientErrorV2::Unavailable)?;
        decode_planner_plan_v2(&response).map_err(|_| AgentPlannerClientErrorV2::InvalidPlan)
    }
}

fn remaining(deadline: UnixMillisV2) -> Result<Duration, AgentPlannerClientErrorV2> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AgentPlannerClientErrorV2::Unavailable)?
        .as_millis();
    let now = u64::try_from(now).map_err(|_| AgentPlannerClientErrorV2::Unavailable)?;
    let millis = deadline
        .get()
        .checked_sub(now)
        .filter(|millis| *millis > 0)
        .ok_or(AgentPlannerClientErrorV2::DeadlineExceeded)?;
    Ok(Duration::from_millis(millis.min(30_000)))
}

fn read_header(
    stream: &mut StreamOwned<ClientConnection, TcpStream>,
) -> Result<Vec<u8>, AgentPlannerClientErrorV2> {
    let mut header = Vec::new();
    header
        .try_reserve(1024)
        .map_err(|_| AgentPlannerClientErrorV2::Unavailable)?;
    while header.len() < MAX_HEADER_BYTES_V2 {
        let mut byte = [0_u8; 1];
        stream
            .read_exact(&mut byte)
            .map_err(|_| AgentPlannerClientErrorV2::Unavailable)?;
        header.push(byte[0]);
        if header.ends_with(b"\r\n\r\n") {
            return Ok(header);
        }
    }
    Err(AgentPlannerClientErrorV2::Unavailable)
}

fn validate_response_header(header: &[u8]) -> Result<usize, AgentPlannerClientErrorV2> {
    let text = core::str::from_utf8(header).map_err(|_| AgentPlannerClientErrorV2::Unavailable)?;
    let mut lines = text
        .strip_suffix("\r\n\r\n")
        .ok_or(AgentPlannerClientErrorV2::Unavailable)?
        .split("\r\n");
    if lines.next() != Some("HTTP/1.1 200 OK") {
        return Err(AgentPlannerClientErrorV2::Unavailable);
    }
    let mut content_type = None;
    let mut content_length = None;
    let mut connection = None;
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .ok_or(AgentPlannerClientErrorV2::Unavailable)?;
        let name = name.to_ascii_lowercase();
        let value = value.trim();
        match name.as_str() {
            "content-type" if content_type.replace(value).is_none() => {}
            "content-length" if content_length.replace(value).is_none() => {}
            "connection" if connection.replace(value).is_none() => {}
            "content-encoding" | "transfer-encoding" | "set-cookie" | "location" | "trailer" => {
                return Err(AgentPlannerClientErrorV2::Unavailable);
            }
            _ => {}
        }
    }
    if content_type != Some("application/cbor")
        || !connection.is_some_and(|value| value.eq_ignore_ascii_case("close"))
    {
        return Err(AgentPlannerClientErrorV2::Unavailable);
    }
    let length = content_length
        .ok_or(AgentPlannerClientErrorV2::Unavailable)?
        .parse::<usize>()
        .map_err(|_| AgentPlannerClientErrorV2::Unavailable)?;
    if length == 0 || length > MAX_PLANNER_BODY_BYTES_V2 {
        return Err(AgentPlannerClientErrorV2::Unavailable);
    }
    Ok(length)
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

fn certificate_spki_der(certificate: &[u8]) -> Option<&[u8]> {
    let (_, certificate_content, certificate_end) = der_element(certificate, 0, 0x30)?;
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
    use super::{valid_dns_name, validate_response_header};

    #[test]
    fn planner_http_surface_is_exact_and_rejects_ambient_features() {
        assert!(valid_dns_name("planner.example.test"));
        assert!(!valid_dns_name("https://planner.example.test"));
        assert_eq!(
            validate_response_header(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/cbor\r\nContent-Length: 42\r\nConnection: close\r\n\r\n"
            )
            .unwrap(),
            42
        );
        assert!(validate_response_header(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/cbor\r\nContent-Length: 42\r\nContent-Encoding: gzip\r\nConnection: close\r\n\r\n"
        )
        .is_err());
    }
}
