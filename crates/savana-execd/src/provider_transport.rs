use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Instant;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use savana_kernel_protocol::v2::Digest32V2;
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::worker_supervisor::{ConnectorWorkerSupervisorErrorV2, ProviderTransportV2};
use crate::EffectPermitV2;

const MAX_TLS_CERTIFICATE_BYTES_V2: usize = 128 * 1024;
const MAX_TLS_CHAIN_CERTIFICATES_V2: usize = 8;
const MAX_TLS_PRIVATE_KEY_BYTES_V2: usize = 64 * 1024;
const MAX_ALPN_BYTES_V2: usize = 255;

pub(crate) struct VerifiedRustlsProviderTransportV2 {
    address: SocketAddr,
    server_name: ServerName<'static>,
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
        {
            return Err(ConnectorWorkerSupervisorErrorV2::ProviderAttemptFailed);
        }
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
        let mut config = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| ConnectorWorkerSupervisorErrorV2::ProviderAttemptFailed)?
            .with_root_certificates(roots)
            .with_client_auth_cert(certificate_chain, private_key)
            .map_err(|_| ConnectorWorkerSupervisorErrorV2::ProviderAttemptFailed)?;
        config.alpn_protocols = vec![alpn_protocol];
        config.enable_early_data = false;
        config.resumption = rustls::client::Resumption::disabled();
        Ok(Self {
            address,
            server_name,
            config: Arc::new(config),
            endpoint_binding_digest,
            credential_handle_identity_digest,
        })
    }
}

impl ProviderTransportV2 for VerifiedRustlsProviderTransportV2 {
    fn execute(
        &mut self,
        permit: &EffectPermitV2,
        credential_free_request: &[u8],
        maximum_response_bytes: u32,
        deadline: Instant,
    ) -> Result<Vec<u8>, ConnectorWorkerSupervisorErrorV2> {
        if credential_free_request.is_empty()
            || maximum_response_bytes == 0
            || Instant::now() >= deadline
            || is_zero(permit.execution_nonce().as_bytes())
            || is_zero(permit.dispatch_core_digest().as_bytes())
            || is_zero(permit.dispatch_subject_digest().as_bytes())
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
        tls.write_all(credential_free_request)
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
        Ok(response)
    }
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
