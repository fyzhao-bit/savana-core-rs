use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Instant;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{
    CertificateError, ClientConfig, ClientConnection, DigitallySignedStruct, DistinguishedName,
    Error as RustlsError, RootCertStore, SignatureScheme, StreamOwned,
};
use savana_kernel_protocol::v2::Digest32V2;
use savana_policy_core::v2::{
    user_tier_host_allowed_v2, BoundedConnectorHostV2, BoundedConnectorUrlV2, ConnectorTierV2,
    ConnectorTransportV2,
};
use sha2::{Digest as _, Sha256};
use url::Url;
use zeroize::Zeroizing;

use crate::worker_supervisor::{
    ConnectorWorkerSupervisorErrorV2, ProviderTransportV2, VerifiedProviderRequestV2,
    VerifiedProviderTargetV2,
};
use crate::EffectPermitV2;

const MAX_TLS_CERTIFICATE_BYTES_V2: usize = 128 * 1024;
const MAX_TLS_CHAIN_CERTIFICATES_V2: usize = 8;
const MAX_TLS_PRIVATE_KEY_BYTES_V2: usize = 64 * 1024;
const MAX_ALPN_BYTES_V2: usize = 255;

pub(crate) struct VerifiedRustlsProviderTransportV2 {
    address: SocketAddr,
    server_name: ServerName<'static>,
    server_name_canonical: String,
    provisioned_canonical_url: BoundedConnectorUrlV2,
    deployment_tls_identity_pin: Digest32V2,
    expected_alpn_protocol: Vec<u8>,
    config: Arc<ClientConfig>,
    endpoint_binding_digest: Digest32V2,
    credential_handle_identity_digest: Digest32V2,
}

impl std::fmt::Debug for VerifiedRustlsProviderTransportV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifiedRustlsProviderTransportV2")
            .field("address", &self.address)
            .field("endpoint_binding_digest", &self.endpoint_binding_digest)
            .field(
                "credential_handle_identity_digest",
                &self.credential_handle_identity_digest,
            )
            .finish_non_exhaustive()
    }
}

impl VerifiedRustlsProviderTransportV2 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_verified_manifest(
        address: SocketAddr,
        server_name: String,
        provisioned_canonical_url: BoundedConnectorUrlV2,
        deployment_tls_identity_pin: Digest32V2,
        root_certificate_der: Vec<u8>,
        client_certificate_chain_der: Vec<Vec<u8>>,
        client_private_key_der: Zeroizing<Vec<u8>>,
        alpn_protocol: Vec<u8>,
        expected_endpoint_binding_digest: Digest32V2,
        expected_credential_handle_identity_digest: Digest32V2,
    ) -> Result<Self, ConnectorWorkerSupervisorErrorV2> {
        if address.ip().is_unspecified()
            || address.port() == 0
            || server_name.is_empty()
            || server_name.len() > 255
            || root_certificate_der.is_empty()
            || root_certificate_der.len() > MAX_TLS_CERTIFICATE_BYTES_V2
            || client_certificate_chain_der.is_empty()
            || client_certificate_chain_der.len() > MAX_TLS_CHAIN_CERTIFICATES_V2
            || client_certificate_chain_der.iter().any(|certificate| {
                certificate.is_empty() || certificate.len() > MAX_TLS_CERTIFICATE_BYTES_V2
            })
            || client_private_key_der.is_empty()
            || client_private_key_der.len() > MAX_TLS_PRIVATE_KEY_BYTES_V2
            || alpn_protocol.is_empty()
            || alpn_protocol.len() > MAX_ALPN_BYTES_V2
            || is_zero(expected_endpoint_binding_digest.as_bytes())
            || is_zero(expected_credential_handle_identity_digest.as_bytes())
            || is_zero(deployment_tls_identity_pin.as_bytes())
        {
            return Err(ConnectorWorkerSupervisorErrorV2::ProviderAttemptFailed);
        }
        let server_name_canonical = BoundedConnectorHostV2::new(&server_name)
            .map_err(|_| ConnectorWorkerSupervisorErrorV2::ProviderAttemptFailed)?;
        let server_name_canonical = server_name_canonical.as_str().to_owned();
        verify_https_connector_target_v2(
            ConnectorTierV2::DeploymentShipped,
            &ConnectorTransportV2::https(
                provisioned_canonical_url.clone(),
                deployment_tls_identity_pin,
            )
            .map_err(|_| ConnectorWorkerSupervisorErrorV2::ProviderAttemptFailed)?,
            &[],
            &provisioned_canonical_url,
            deployment_tls_identity_pin,
            &server_name_canonical,
            address,
        )?;
        let endpoint_binding_digest = endpoint_binding_digest(
            address,
            &server_name,
            &root_certificate_der,
            &client_certificate_chain_der[0],
            &alpn_protocol,
        );
        let credential_handle_identity_digest =
            credential_identity_digest(&client_certificate_chain_der[0]);
        if endpoint_binding_digest != expected_endpoint_binding_digest
            || credential_handle_identity_digest != expected_credential_handle_identity_digest
        {
            return Err(ConnectorWorkerSupervisorErrorV2::ProviderAttemptFailed);
        }
        let server_name = ServerName::try_from(server_name)
            .map_err(|_| ConnectorWorkerSupervisorErrorV2::ProviderAttemptFailed)?;
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(root_certificate_der))
            .map_err(|_| ConnectorWorkerSupervisorErrorV2::ProviderAttemptFailed)?;
        let certificate_chain = client_certificate_chain_der
            .into_iter()
            .map(CertificateDer::from)
            .collect();
        let private_key = PrivateKeyDer::try_from(client_private_key_der.to_vec())
            .map_err(|_| ConnectorWorkerSupervisorErrorV2::ProviderAttemptFailed)?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let webpki_verifier =
            WebPkiServerVerifier::builder_with_provider(Arc::new(roots), Arc::clone(&provider))
                .build()
                .map_err(|_| ConnectorWorkerSupervisorErrorV2::ProviderAttemptFailed)?;
        let pinned_verifier = Arc::new(PinnedWebPkiServerVerifierV2 {
            inner: webpki_verifier,
            expected_tls_identity_pin: deployment_tls_identity_pin,
        });
        let mut config = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| ConnectorWorkerSupervisorErrorV2::ProviderAttemptFailed)?
            .dangerous()
            .with_custom_certificate_verifier(pinned_verifier)
            .with_client_auth_cert(certificate_chain, private_key)
            .map_err(|_| ConnectorWorkerSupervisorErrorV2::ProviderAttemptFailed)?;
        config.alpn_protocols = vec![alpn_protocol.clone()];
        config.enable_early_data = false;
        config.resumption = rustls::client::Resumption::disabled();
        Ok(Self {
            address,
            server_name,
            server_name_canonical,
            provisioned_canonical_url,
            deployment_tls_identity_pin,
            expected_alpn_protocol: alpn_protocol,
            config: Arc::new(config),
            endpoint_binding_digest,
            credential_handle_identity_digest,
        })
    }
}

impl ProviderTransportV2 for VerifiedRustlsProviderTransportV2 {
    fn verified_deployment_target(
        &self,
    ) -> Result<VerifiedProviderTargetV2, ConnectorWorkerSupervisorErrorV2> {
        VerifiedProviderTargetV2::https(
            self.provisioned_canonical_url.clone(),
            self.deployment_tls_identity_pin,
        )
    }

    fn verify_connector_target(
        &self,
        tier: ConnectorTierV2,
        transport: &ConnectorTransportV2,
        active_host_allowlist: &[BoundedConnectorHostV2],
    ) -> Result<VerifiedProviderTargetV2, ConnectorWorkerSupervisorErrorV2> {
        verify_https_connector_target_v2(
            tier,
            transport,
            active_host_allowlist,
            &self.provisioned_canonical_url,
            self.deployment_tls_identity_pin,
            &self.server_name_canonical,
            self.address,
        )
    }

    fn execute(
        &mut self,
        request: &VerifiedProviderRequestV2,
        permit: &EffectPermitV2,
        maximum_response_bytes: u32,
        deadline: Instant,
    ) -> Result<Vec<u8>, ConnectorWorkerSupervisorErrorV2> {
        if request.canonical_bytes().is_empty()
            || maximum_response_bytes == 0
            || Instant::now() >= deadline
            || is_zero(permit.execution_nonce().as_bytes())
            || is_zero(permit.dispatch_core_digest().as_bytes())
            || is_zero(permit.dispatch_subject_digest().as_bytes())
            || !request.matches_permit(permit)
        {
            return Err(ConnectorWorkerSupervisorErrorV2::ProviderAttemptFailed);
        }
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or(ConnectorWorkerSupervisorErrorV2::DeadlineExceeded)?;
        let stream = TcpStream::connect_timeout(&self.address, remaining)
            .map_err(|_| ConnectorWorkerSupervisorErrorV2::ProviderAttemptFailed)?;
        stream
            .set_read_timeout(Some(remaining))
            .and_then(|()| stream.set_write_timeout(Some(remaining)))
            .map_err(|_| ConnectorWorkerSupervisorErrorV2::ProviderAttemptFailed)?;
        let connection = ClientConnection::new(Arc::clone(&self.config), self.server_name.clone())
            .map_err(|_| ConnectorWorkerSupervisorErrorV2::ProviderAttemptFailed)?;
        let mut tls = StreamOwned::new(connection, stream);
        while tls.conn.is_handshaking() {
            tls.conn
                .complete_io(&mut tls.sock)
                .map_err(|_| ConnectorWorkerSupervisorErrorV2::ProviderAttemptFailed)?;
        }
        if tls.conn.alpn_protocol() != Some(self.expected_alpn_protocol.as_slice()) {
            return Err(ConnectorWorkerSupervisorErrorV2::ProviderAttemptFailed);
        }
        let certificate = tls
            .conn
            .peer_certificates()
            .and_then(|certificates| certificates.first())
            .ok_or(ConnectorWorkerSupervisorErrorV2::ProviderAttemptFailed)?;
        verify_tls_leaf_spki_pin_v2(certificate.as_ref(), request.target().tls_identity_pin())?;
        tls.write_all(request.canonical_bytes())
            .and_then(|()| tls.flush())
            .map_err(|_| ConnectorWorkerSupervisorErrorV2::ProviderAttemptFailed)?;
        let maximum = usize::try_from(maximum_response_bytes)
            .map_err(|_| ConnectorWorkerSupervisorErrorV2::ProviderAttemptFailed)?;
        let mut response = Vec::new();
        response
            .try_reserve_exact(maximum.min(64 * 1024))
            .map_err(|_| ConnectorWorkerSupervisorErrorV2::ProviderAttemptFailed)?;
        let mut chunk = [0_u8; 16 * 1024];
        loop {
            if Instant::now() >= deadline {
                return Err(ConnectorWorkerSupervisorErrorV2::DeadlineExceeded);
            }
            let read = tls
                .read(&mut chunk)
                .map_err(|_| ConnectorWorkerSupervisorErrorV2::ProviderAttemptFailed)?;
            if read == 0 {
                break;
            }
            if response
                .len()
                .checked_add(read)
                .is_none_or(|length| length > maximum)
            {
                return Err(ConnectorWorkerSupervisorErrorV2::ProviderAttemptFailed);
            }
            response
                .try_reserve(read)
                .map_err(|_| ConnectorWorkerSupervisorErrorV2::ProviderAttemptFailed)?;
            response.extend_from_slice(&chunk[..read]);
        }
        if response.is_empty() {
            return Err(ConnectorWorkerSupervisorErrorV2::ProviderAttemptFailed);
        }
        reject_http_redirect_response_v2(&response)?;
        Ok(response)
    }
}

#[derive(Debug)]
struct PinnedWebPkiServerVerifierV2 {
    inner: Arc<dyn ServerCertVerifier>,
    expected_tls_identity_pin: Digest32V2,
}

impl ServerCertVerifier for PinnedWebPkiServerVerifierV2 {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        let verified = self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;
        let spki = certificate_spki_der(end_entity.as_ref())
            .ok_or_else(|| RustlsError::InvalidCertificate(CertificateError::BadEncoding))?;
        if Digest32V2::new(Sha256::digest(spki).into()) != self.expected_tls_identity_pin {
            return Err(RustlsError::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ));
        }
        Ok(verified)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }

    fn requires_raw_public_keys(&self) -> bool {
        self.inner.requires_raw_public_keys()
    }

    fn root_hint_subjects(&self) -> Option<&[DistinguishedName]> {
        self.inner.root_hint_subjects()
    }
}

pub(crate) fn verify_https_connector_target_v2(
    tier: ConnectorTierV2,
    transport: &ConnectorTransportV2,
    active_host_allowlist: &[BoundedConnectorHostV2],
    provisioned_canonical_url: &BoundedConnectorUrlV2,
    deployment_tls_identity_pin: Digest32V2,
    server_name: &str,
    address: SocketAddr,
) -> Result<VerifiedProviderTargetV2, ConnectorWorkerSupervisorErrorV2> {
    let (canonical_url, tls_identity_pin) = match transport {
        ConnectorTransportV2::Https {
            canonical_url,
            tls_identity_pin,
        } => (canonical_url, *tls_identity_pin),
        ConnectorTransportV2::Stdio { .. } => {
            return Err(ConnectorWorkerSupervisorErrorV2::ProviderAttemptFailed);
        }
    };
    let canonical_server_name = BoundedConnectorHostV2::new(server_name)
        .map_err(|_| ConnectorWorkerSupervisorErrorV2::ProviderAttemptFailed)?;
    let parsed = Url::parse(canonical_url.as_str())
        .map_err(|_| ConnectorWorkerSupervisorErrorV2::ProviderAttemptFailed)?;
    let host = parsed
        .host_str()
        .ok_or(ConnectorWorkerSupervisorErrorV2::ProviderAttemptFailed)?;
    let effective_port = parsed
        .port_or_known_default()
        .ok_or(ConnectorWorkerSupervisorErrorV2::ProviderAttemptFailed)?;
    if canonical_url != provisioned_canonical_url
        || tls_identity_pin != deployment_tls_identity_pin
        || canonical_url.host().as_str() != canonical_server_name.as_str()
        || host != canonical_server_name.as_str()
        || effective_port != address.port()
        || address.ip().is_unspecified()
        || (tier == ConnectorTierV2::UserRegistered
            && !user_tier_host_allowed_v2(host, active_host_allowlist)
                .map_err(|_| ConnectorWorkerSupervisorErrorV2::ProviderAttemptFailed)?)
    {
        return Err(ConnectorWorkerSupervisorErrorV2::ProviderAttemptFailed);
    }
    VerifiedProviderTargetV2::https(canonical_url.clone(), tls_identity_pin)
}

pub(crate) fn verify_tls_leaf_spki_pin_v2(
    certificate: &[u8],
    expected_pin: Digest32V2,
) -> Result<(), ConnectorWorkerSupervisorErrorV2> {
    let spki = certificate_spki_der(certificate)
        .ok_or(ConnectorWorkerSupervisorErrorV2::ProviderAttemptFailed)?;
    if expected_pin.as_bytes() == &[0; 32]
        || Digest32V2::new(Sha256::digest(spki).into()) != expected_pin
    {
        return Err(ConnectorWorkerSupervisorErrorV2::ProviderAttemptFailed);
    }
    Ok(())
}

pub(crate) fn reject_http_redirect_response_v2(
    response: &[u8],
) -> Result<(), ConnectorWorkerSupervisorErrorV2> {
    if !response.starts_with(b"HTTP/") {
        return Ok(());
    }
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
        .ok_or(ConnectorWorkerSupervisorErrorV2::ProviderAttemptFailed)?;
    let header = std::str::from_utf8(&response[..header_end])
        .map_err(|_| ConnectorWorkerSupervisorErrorV2::ProviderAttemptFailed)?;
    let mut lines = header.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split_ascii_whitespace().nth(1))
        .and_then(|status| status.parse::<u16>().ok())
        .ok_or(ConnectorWorkerSupervisorErrorV2::ProviderAttemptFailed)?;
    let has_location = lines
        .filter_map(|line| line.split_once(':'))
        .any(|(name, _)| name.eq_ignore_ascii_case("location"));
    if (300..400).contains(&status) || has_location {
        return Err(ConnectorWorkerSupervisorErrorV2::ProviderAttemptFailed);
    }
    Ok(())
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

pub(crate) fn endpoint_binding_digest(
    address: SocketAddr,
    server_name: &str,
    root_certificate_der: &[u8],
    client_leaf_certificate_der: &[u8],
    alpn_protocol: &[u8],
) -> Digest32V2 {
    let mut hasher = Sha256::new();
    hasher.update(b"SAVANA_PROVIDER_TLS_ENDPOINT_BINDING_V2\0");
    match address.ip() {
        std::net::IpAddr::V4(ip) => {
            hasher.update([4]);
            hasher.update(ip.octets());
        }
        std::net::IpAddr::V6(ip) => {
            hasher.update([6]);
            hasher.update(ip.octets());
        }
    }
    hasher.update(address.port().to_be_bytes());
    hasher.update((server_name.len() as u16).to_be_bytes());
    hasher.update(server_name.as_bytes());
    hasher.update(Sha256::digest(root_certificate_der));
    hasher.update(Sha256::digest(client_leaf_certificate_der));
    hasher.update((alpn_protocol.len() as u16).to_be_bytes());
    hasher.update(alpn_protocol);
    Digest32V2::new(hasher.finalize().into())
}

pub(crate) fn credential_identity_digest(client_leaf_certificate_der: &[u8]) -> Digest32V2 {
    let mut hasher = Sha256::new();
    hasher.update(b"SAVANA_PROVIDER_CREDENTIAL_HANDLE_IDENTITY_V2\0");
    hasher.update(Sha256::digest(client_leaf_certificate_der));
    Digest32V2::new(hasher.finalize().into())
}

fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

#[cfg(test)]
mod tests {
    use std::io::{Read as _, Write as _};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, Instant};

    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use rustls::server::WebPkiClientVerifier;
    use rustls::{RootCertStore, ServerConfig, ServerConnection, StreamOwned};
    use savana_kernel_protocol::v2::{Digest32V2, Nonce32V2};
    use savana_policy_core::v2::{
        BoundedConnectorHostV2, BoundedConnectorUrlV2, ConnectorTierV2, ConnectorTransportV2,
    };
    use sha2::{Digest as _, Sha256};
    use zeroize::Zeroizing;

    use super::{
        certificate_spki_der, credential_identity_digest, endpoint_binding_digest,
        reject_http_redirect_response_v2, verify_https_connector_target_v2,
        verify_tls_leaf_spki_pin_v2, VerifiedRustlsProviderTransportV2,
    };
    use crate::worker_supervisor::{ProviderTransportV2, VerifiedProviderRequestV2};
    use crate::EffectPermitV2;

    fn digest(byte: u8) -> Digest32V2 {
        Digest32V2::new([byte; 32])
    }

    fn address(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)), port)
    }

    fn tls_fixture(name: &str) -> Vec<u8> {
        let prefix = format!("{name}=");
        let encoded = include_str!("../tests/fixtures/provider-tls-v2.hex")
            .lines()
            .find_map(|line| line.strip_prefix(&prefix))
            .unwrap();
        encoded
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let digit = |byte: u8| match byte {
                    b'0'..=b'9' => byte - b'0',
                    b'a'..=b'f' => byte - b'a' + 10,
                    _ => panic!("non-hex TLS fixture"),
                };
                (digit(pair[0]) << 4) | digit(pair[1])
            })
            .collect()
    }

    struct ExpectedLiveProviderRequestV2 {
        canonical_bytes: Vec<u8>,
        canonical_url: String,
        tls_identity_pin: Digest32V2,
        payload_digest: Digest32V2,
        payload: Vec<u8>,
    }

    fn assert_exact_live_provider_request(
        request: &[u8],
        expected: &ExpectedLiveProviderRequestV2,
    ) {
        assert_eq!(request, expected.canonical_bytes);
        let mut decoder = minicbor::Decoder::new(request);
        assert_eq!(decoder.array().unwrap(), Some(11));
        assert_eq!(decoder.u16().unwrap(), 2);
        assert_eq!(decoder.u16().unwrap(), 1);
        assert_eq!(decoder.str().unwrap(), expected.canonical_url);
        assert_eq!(
            decoder.bytes().unwrap(),
            expected.tls_identity_pin.as_bytes()
        );
        assert_eq!(decoder.bytes().unwrap(), &[0x51; 32]);
        assert_eq!(decoder.bytes().unwrap(), &[0x52; 32]);
        assert_eq!(decoder.bytes().unwrap(), &[0x53; 32]);
        assert_eq!(
            decoder.u32().unwrap(),
            u32::try_from(expected.payload.len()).unwrap()
        );
        assert_eq!(
            decoder.bytes().unwrap(),
            crate::worker_protocol::prepared_provider_request_digest(&expected.payload).as_bytes()
        );
        assert_eq!(decoder.bytes().unwrap(), expected.payload_digest.as_bytes());
        assert_eq!(decoder.bytes().unwrap(), expected.payload);
        assert_eq!(decoder.position(), request.len());
    }

    fn spawn_mutual_tls_server(
        listener: TcpListener,
        negotiated_alpn: Option<Vec<u8>>,
        expected_request: Option<ExpectedLiveProviderRequestV2>,
    ) -> thread::JoinHandle<(bool, bool)> {
        thread::spawn(move || {
            let ca = tls_fixture("ca_cert");
            let server_cert = tls_fixture("server_cert");
            let server_key = tls_fixture("server_key");
            let mut client_roots = RootCertStore::empty();
            client_roots.add(CertificateDer::from(ca)).unwrap();
            let client_verifier = WebPkiClientVerifier::builder(Arc::new(client_roots))
                .build()
                .unwrap();
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let mut config = ServerConfig::builder_with_provider(provider)
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_client_cert_verifier(client_verifier)
                .with_single_cert(
                    vec![CertificateDer::from(server_cert)],
                    PrivateKeyDer::try_from(server_key).unwrap(),
                )
                .unwrap();
            config.alpn_protocols = negotiated_alpn.into_iter().collect();
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let connection = ServerConnection::new(Arc::new(config)).unwrap();
            let mut tls = StreamOwned::new(connection, stream);
            let mut handshake_succeeded = true;
            while tls.conn.is_handshaking() {
                if tls.conn.complete_io(&mut tls.sock).is_err() {
                    handshake_succeeded = false;
                    break;
                }
            }
            let saw_client_certificate = tls
                .conn
                .peer_certificates()
                .is_some_and(|certificates| !certificates.is_empty());
            let read = if !handshake_succeeded {
                0
            } else if let Some(expected) = expected_request {
                let mut request = vec![0_u8; expected.canonical_bytes.len()];
                match tls.read_exact(&mut request) {
                    Ok(()) => {
                        assert_exact_live_provider_request(&request, &expected);
                        request.len()
                    }
                    Err(_) => 0,
                }
            } else {
                let mut request = vec![0_u8; 4096];
                tls.read(&mut request).unwrap_or(0)
            };
            if read > 0 {
                let _ = tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx");
                let _ = tls.flush();
                tls.conn.send_close_notify();
                let _ = tls.conn.complete_io(&mut tls.sock);
            }
            (saw_client_certificate, read > 0)
        })
    }

    fn loopback_transport(
        address: SocketAddr,
        expected_server_pin: Digest32V2,
    ) -> VerifiedRustlsProviderTransportV2 {
        let ca = tls_fixture("ca_cert");
        let client_cert = tls_fixture("client_cert");
        let client_key = tls_fixture("client_key");
        let alpn = b"savana-provider-v2".to_vec();
        let canonical_url =
            BoundedConnectorUrlV2::new(format!("https://provider.example:{}/mcp", address.port()))
                .unwrap();
        VerifiedRustlsProviderTransportV2::from_verified_manifest(
            address,
            "provider.example".to_owned(),
            canonical_url,
            expected_server_pin,
            ca.clone(),
            vec![client_cert.clone()],
            Zeroizing::new(client_key),
            alpn.clone(),
            endpoint_binding_digest(address, "provider.example", &ca, &client_cert, &alpn),
            credential_identity_digest(&client_cert),
        )
        .unwrap()
    }

    fn execute_loopback(
        transport: &mut VerifiedRustlsProviderTransportV2,
    ) -> Result<Vec<u8>, crate::worker_supervisor::ConnectorWorkerSupervisorErrorV2> {
        let (request, permit) = loopback_request(transport);
        transport.execute(
            &request,
            &permit,
            4096,
            Instant::now() + Duration::from_secs(2),
        )
    }

    fn loopback_request(
        transport: &VerifiedRustlsProviderTransportV2,
    ) -> (VerifiedProviderRequestV2, EffectPermitV2) {
        let target = transport.verified_deployment_target().unwrap();
        let payload = b"opaque credential-free request";
        let request = VerifiedProviderRequestV2::bind(
            target,
            Nonce32V2::new([0x51; 32]),
            digest(0x52),
            digest(0x53),
            crate::worker_protocol::prepared_provider_request_digest(payload),
            payload,
        )
        .unwrap();
        let permit = EffectPermitV2 {
            execution_nonce: Nonce32V2::new([0x51; 32]),
            dispatch_core_digest: digest(0x52),
            dispatch_subject_digest: digest(0x53),
        };
        (request, permit)
    }

    #[test]
    fn connect_time_target_rechecks_active_host_and_exact_provisioning_before_effect() {
        // This catches deleting the current-policy allowlist check, accepting a
        // descriptor for another host/port, or silently provisioning stdio.
        let allowlist = vec![BoundedConnectorHostV2::new("example.com").unwrap()];
        let provisioned = BoundedConnectorUrlV2::new("https://api.example.com:9443/mcp").unwrap();
        let exact = ConnectorTransportV2::https(provisioned.clone(), digest(0x41)).unwrap();
        let target = verify_https_connector_target_v2(
            ConnectorTierV2::UserRegistered,
            &exact,
            &allowlist,
            &provisioned,
            digest(0x41),
            "api.example.com",
            address(9443),
        )
        .unwrap();
        assert_eq!(target.tls_identity_pin(), digest(0x41));

        assert!(verify_https_connector_target_v2(
            ConnectorTierV2::UserRegistered,
            &exact,
            &[],
            &provisioned,
            digest(0x41),
            "api.example.com",
            address(9443),
        )
        .is_err());
        assert!(verify_https_connector_target_v2(
            ConnectorTierV2::UserRegistered,
            &exact,
            &allowlist,
            &provisioned,
            digest(0x41),
            "other.example.com",
            address(9443),
        )
        .is_err());
        assert!(verify_https_connector_target_v2(
            ConnectorTierV2::UserRegistered,
            &exact,
            &allowlist,
            &provisioned,
            digest(0x41),
            "api.example.com",
            address(443),
        )
        .is_err());

        let wrong_pin = ConnectorTransportV2::https(provisioned.clone(), digest(0x42)).unwrap();
        assert!(verify_https_connector_target_v2(
            ConnectorTierV2::UserRegistered,
            &wrong_pin,
            &allowlist,
            &provisioned,
            digest(0x41),
            "api.example.com",
            address(9443),
        )
        .is_err());

        let other_host = ConnectorTransportV2::https(
            BoundedConnectorUrlV2::new("https://evil.example:9443/mcp").unwrap(),
            digest(0x41),
        )
        .unwrap();
        assert!(verify_https_connector_target_v2(
            ConnectorTierV2::UserRegistered,
            &other_host,
            &allowlist,
            &provisioned,
            digest(0x41),
            "api.example.com",
            address(9443),
        )
        .is_err());

        let stdio = ConnectorTransportV2::stdio(digest(0x42)).unwrap();
        assert!(verify_https_connector_target_v2(
            ConnectorTierV2::UserRegistered,
            &stdio,
            &allowlist,
            &provisioned,
            digest(0x41),
            "api.example.com",
            address(9443),
        )
        .is_err());
    }

    #[test]
    fn tls_leaf_spki_pin_is_checked_before_any_application_write() {
        // Minimal DER shaped like Certificate/TBSCertificate is sufficient to
        // independently fix the exact SPKI element hashed by the verifier.
        let spki = [0x30, 0x08, 0x30, 0x03, 0x06, 0x01, 0x2a, 0x03, 0x01, 0x00];
        let mut tbs = vec![
            0x02, 0x01, 0x01, // serial
            0x30, 0x00, // signature
            0x30, 0x00, // issuer
            0x30, 0x00, // validity
            0x30, 0x00, // subject
        ];
        tbs.extend_from_slice(&spki);
        let mut certificate = vec![0x30, u8::try_from(tbs.len() + 2).unwrap(), 0x30];
        certificate.push(u8::try_from(tbs.len()).unwrap());
        certificate.extend_from_slice(&tbs);
        let expected = Digest32V2::new(Sha256::digest(spki).into());

        verify_tls_leaf_spki_pin_v2(&certificate, expected).unwrap();
        assert!(verify_tls_leaf_spki_pin_v2(&certificate, digest(0x43)).is_err());
        assert!(
            verify_tls_leaf_spki_pin_v2(&certificate[..certificate.len() - 1], expected).is_err()
        );
    }

    #[test]
    fn wrong_spki_is_rejected_before_mutual_tls_discloses_the_client_certificate() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = spawn_mutual_tls_server(listener, Some(b"savana-provider-v2".to_vec()), None);
        let mut transport = loopback_transport(address, digest(0x61));

        assert!(execute_loopback(&mut transport).is_err());
        let (saw_client_certificate, saw_application_bytes) = server.join().unwrap();
        assert!(!saw_client_certificate);
        assert!(!saw_application_bytes);
    }

    #[test]
    fn absent_alpn_is_rejected_before_the_first_application_byte() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = spawn_mutual_tls_server(listener, None, None);
        let server_certificate = tls_fixture("server_cert");
        let server_pin = Digest32V2::new(
            Sha256::digest(certificate_spki_der(&server_certificate).unwrap()).into(),
        );
        let mut transport = loopback_transport(address, server_pin);

        assert!(execute_loopback(&mut transport).is_err());
        let (_, saw_application_bytes) = server.join().unwrap();
        assert!(!saw_application_bytes);
    }

    #[test]
    fn live_mutual_tls_server_decodes_the_exact_bound_outer_request_frame() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server_certificate = tls_fixture("server_cert");
        let server_pin = Digest32V2::new(
            Sha256::digest(certificate_spki_der(&server_certificate).unwrap()).into(),
        );
        let mut transport = loopback_transport(address, server_pin);
        let (request, permit) = loopback_request(&transport);
        let expected = ExpectedLiveProviderRequestV2 {
            canonical_bytes: request.canonical_bytes().to_vec(),
            canonical_url: request.target().canonical_url().as_str().to_owned(),
            tls_identity_pin: request.target().tls_identity_pin(),
            payload_digest: request.payload_digest(),
            payload: b"opaque credential-free request".to_vec(),
        };
        let server = spawn_mutual_tls_server(
            listener,
            Some(b"savana-provider-v2".to_vec()),
            Some(expected),
        );

        let response = transport.execute(
            &request,
            &permit,
            4096,
            Instant::now() + Duration::from_secs(2),
        );
        let (saw_client_certificate, saw_application_bytes) = server.join().unwrap();
        assert!(saw_client_certificate);
        assert!(saw_application_bytes);
        let response = response.unwrap();
        assert_eq!(response, b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx");
    }

    #[test]
    fn every_http_redirect_is_refused_without_a_follow_attempt() {
        // Rejecting every redirect is the closed policy: these cases catch a
        // later same-host exception accidentally admitting scheme, port,
        // cross-host, userinfo, or IDNA rebinding.
        for location in [
            "https://evil.example/mcp",
            "http://api.example.com/mcp",
            "https://api.example.com:444/mcp",
            "https://api.example.com@evil.example/mcp",
            "https://xn--pple-43d.example/mcp",
            "https://api.example.com/other",
        ] {
            let response = format!(
                "HTTP/1.1 307 Temporary Redirect\r\nLocation: {location}\r\nContent-Length: 0\r\n\r\n"
            );
            assert!(reject_http_redirect_response_v2(response.as_bytes()).is_err());
        }
        assert!(
            reject_http_redirect_response_v2(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx")
                .is_ok()
        );
        assert!(reject_http_redirect_response_v2(&[0xa1, 0x01, 0x02]).is_ok());
    }
}
