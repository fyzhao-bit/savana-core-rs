use savana_kernel_protocol::v2::{Digest32V2, UnixMillisV2};
use zeroize::Zeroizing;

use crate::planner_privacy::{
    decode_mapped_workflow_v2, encode_mapper_intent_request_v2, IntentTrustBoundaryV2,
    IntentTrustDeploymentCeilingV2, MappedWorkflowV2, MapperIntentRequestV2,
};
#[cfg(test)]
use crate::private_model_transport::{ConnectorFunctionV2, ResolverFunctionV2};
use crate::private_model_transport::{
    PinnedMtlsCborEndpointV2, PrivateModelTransportErrorV2, VerifiedMtlsClientCredentialsV2,
};

const MAPPER_PATH_V2: &str = "/savana.mapper.v2/map";
const MAX_MAPPER_BODY_BYTES_V2: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AgentMapperClientErrorV2 {
    #[error("mapper deadline was exceeded")]
    DeadlineExceeded,
    #[error("mapper deployment binding is invalid")]
    InvalidDeployment,
    #[error("requested mapper intent trust boundary is forbidden")]
    BoundaryDenied,
    #[error("mapper transport or response is unavailable")]
    Unavailable,
    #[error("mapper returned a non-canonical or invalid workflow")]
    InvalidWorkflow,
}

#[derive(Clone)]
pub struct MapperEndpointDeploymentV2 {
    host: String,
    port: u16,
    server_spki_sha256: Digest32V2,
    #[cfg(test)]
    test_address: Option<std::net::SocketAddr>,
    #[cfg(test)]
    test_resolver: Option<std::sync::Arc<ResolverFunctionV2>>,
    #[cfg(test)]
    test_connector: Option<std::sync::Arc<ConnectorFunctionV2>>,
}

impl core::fmt::Debug for MapperEndpointDeploymentV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("MapperEndpointDeploymentV2")
            .field("host", &self.host)
            .field("port", &self.port)
            .finish_non_exhaustive()
    }
}

impl MapperEndpointDeploymentV2 {
    pub fn new(
        host: String,
        port: u16,
        server_spki_sha256: Digest32V2,
    ) -> Result<Self, AgentMapperClientErrorV2> {
        if host.is_empty()
            || host.len() > 253
            || port == 0
            || server_spki_sha256.as_bytes() == &[0; 32]
            || rustls::pki_types::ServerName::try_from(host.clone()).is_err()
        {
            return Err(AgentMapperClientErrorV2::InvalidDeployment);
        }
        Ok(Self {
            host,
            port,
            server_spki_sha256,
            #[cfg(test)]
            test_address: None,
            #[cfg(test)]
            test_resolver: None,
            #[cfg(test)]
            test_connector: None,
        })
    }

    #[cfg(test)]
    fn for_test(
        host: String,
        address: std::net::SocketAddr,
        server_spki_sha256: Digest32V2,
    ) -> Result<Self, AgentMapperClientErrorV2> {
        let mut deployment = Self::new(host, address.port(), server_spki_sha256)?;
        deployment.test_address = Some(address);
        Ok(deployment)
    }

    #[cfg(test)]
    fn for_test_resolver<F>(
        host: String,
        port: u16,
        server_spki_sha256: Digest32V2,
        resolve: F,
    ) -> Result<Self, AgentMapperClientErrorV2>
    where
        F: Fn(&str, u16) -> std::io::Result<Vec<std::net::SocketAddr>> + Send + Sync + 'static,
    {
        let mut deployment = Self::new(host, port, server_spki_sha256)?;
        deployment.test_resolver = Some(std::sync::Arc::new(move |host, port| {
            resolve(&host, port).map_err(|_| PrivateModelTransportErrorV2::Unavailable)
        }));
        Ok(deployment)
    }

    #[cfg(test)]
    fn with_test_connector<F>(mut self, connect: F) -> Self
    where
        F: Fn(std::net::SocketAddr, std::time::Duration) -> std::io::Result<std::net::TcpStream>
            + Send
            + Sync
            + 'static,
    {
        self.test_connector = Some(std::sync::Arc::new(connect));
        self
    }
}

pub struct PinnedMtlsAgentMapperClientV2 {
    ceiling: IntentTrustDeploymentCeilingV2,
    private: PinnedMtlsCborEndpointV2,
    third_party: Option<PinnedMtlsCborEndpointV2>,
}

impl core::fmt::Debug for PinnedMtlsAgentMapperClientV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PinnedMtlsAgentMapperClientV2")
            .field("ceiling", &self.ceiling)
            .field("third_party_configured", &self.third_party.is_some())
            .finish_non_exhaustive()
    }
}

impl PinnedMtlsAgentMapperClientV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn from_verified_deployment(
        ceiling: IntentTrustDeploymentCeilingV2,
        private: MapperEndpointDeploymentV2,
        third_party: Option<MapperEndpointDeploymentV2>,
        root_certificate_der: Vec<u8>,
        client_certificate_der: Vec<u8>,
        client_private_key_pkcs8_der: Zeroizing<Vec<u8>>,
    ) -> Result<Self, AgentMapperClientErrorV2> {
        if matches!(ceiling, IntentTrustDeploymentCeilingV2::PrivateOnly) && third_party.is_some() {
            return Err(AgentMapperClientErrorV2::InvalidDeployment);
        }
        let credentials = VerifiedMtlsClientCredentialsV2::from_verified_deployment(
            root_certificate_der,
            client_certificate_der,
            client_private_key_pkcs8_der,
        )
        .map_err(map_transport)?;
        let private = build_endpoint(private, credentials.clone())?;
        let third_party = third_party
            .map(|endpoint| build_endpoint(endpoint, credentials))
            .transpose()?;
        Ok(Self {
            ceiling,
            private,
            third_party,
        })
    }

    pub const fn authorize_boundary(
        &self,
        boundary: IntentTrustBoundaryV2,
    ) -> Result<(), AgentMapperClientErrorV2> {
        if !self.ceiling.permits(boundary) {
            return Err(AgentMapperClientErrorV2::BoundaryDenied);
        }
        if matches!(boundary, IntentTrustBoundaryV2::ThirdParty) && self.third_party.is_none() {
            return Err(AgentMapperClientErrorV2::InvalidDeployment);
        }
        Ok(())
    }

    pub fn map(
        &self,
        request: &MapperIntentRequestV2,
        boundary: IntentTrustBoundaryV2,
        deadline: UnixMillisV2,
    ) -> Result<MappedWorkflowV2, AgentMapperClientErrorV2> {
        self.authorize_boundary(boundary)?;
        let endpoint = match boundary {
            IntentTrustBoundaryV2::Private => &self.private,
            IntentTrustBoundaryV2::ThirdParty => self
                .third_party
                .as_ref()
                .ok_or(AgentMapperClientErrorV2::InvalidDeployment)?,
        };
        let body = encode_mapper_intent_request_v2(request)
            .map_err(|_| AgentMapperClientErrorV2::InvalidWorkflow)?;
        let response = endpoint
            .post_canonical_cbor(MAPPER_PATH_V2, &body, MAX_MAPPER_BODY_BYTES_V2, deadline)
            .map_err(map_transport)?;
        decode_mapped_workflow_v2(&response, request)
            .map_err(|_| AgentMapperClientErrorV2::InvalidWorkflow)
    }
}

fn build_endpoint(
    deployment: MapperEndpointDeploymentV2,
    credentials: VerifiedMtlsClientCredentialsV2,
) -> Result<PinnedMtlsCborEndpointV2, AgentMapperClientErrorV2> {
    let endpoint = PinnedMtlsCborEndpointV2::from_verified_deployment(
        deployment.host,
        deployment.port,
        deployment.server_spki_sha256,
        credentials,
    )
    .map_err(map_transport)?;
    #[cfg(test)]
    let endpoint = {
        let mut endpoint = endpoint;
        if let Some(resolve) = deployment.test_resolver {
            endpoint.set_test_resolver(resolve).map_err(map_transport)?;
        } else if let Some(address) = deployment.test_address {
            endpoint.set_test_address(address);
        }
        if let Some(connect) = deployment.test_connector {
            endpoint.set_test_connector(connect);
        }
        endpoint
    };
    Ok(endpoint)
}

fn map_transport(error: PrivateModelTransportErrorV2) -> AgentMapperClientErrorV2 {
    match error {
        PrivateModelTransportErrorV2::DeadlineExceeded => {
            AgentMapperClientErrorV2::DeadlineExceeded
        }
        PrivateModelTransportErrorV2::InvalidDeployment => {
            AgentMapperClientErrorV2::InvalidDeployment
        }
        PrivateModelTransportErrorV2::Unavailable => AgentMapperClientErrorV2::Unavailable,
        PrivateModelTransportErrorV2::InvalidResponse => AgentMapperClientErrorV2::InvalidWorkflow,
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read as _, Write as _};
    use std::net::{SocketAddr, TcpListener};
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use rustls::server::WebPkiClientVerifier;
    use rustls::{RootCertStore, ServerConfig, ServerConnection, StreamOwned};
    use savana_kernel_protocol::v2::{
        ActionTemplateIdV2, ActiveToolViewV2, ArgumentNameV2, Nonce32V2, PlannerAbstractSlotV2,
        PlannerEnvelopeV2, PlannerIntentKindV2, PlannerLimitsV2, PlannerRouteIdV2,
        PlannerSlotCardinalityV2, PlannerSlotConfidentialityV2, PlannerSlotRefV2, SlotKindV2,
        StaticTemplateIdV2, ToolClassIdV2, ToolHandleV2, UnixMillisV2,
    };
    use savana_policy_core::v2::EffectSetV2;
    use sha2::{Digest as _, Sha256};
    use zeroize::Zeroizing;

    use super::{MapperEndpointDeploymentV2, PinnedMtlsAgentMapperClientV2};
    use crate::planner_privacy::{
        encode_mapped_workflow_v2, encode_mapper_intent_request_v2, IntentTrustBoundaryV2,
        IntentTrustDeploymentCeilingV2, MappedNodeV2, MappedWorkflowV2, MapperCatalogToolV2,
        MapperIntentRequestV2, StructuralRoleV2,
    };

    fn tls_fixture(name: &str) -> Vec<u8> {
        let prefix = format!("{name}=");
        let encoded = include_str!("../../savana-execd/tests/fixtures/provider-tls-v2.hex")
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

    fn certificate_spki_der(certificate: &[u8]) -> &[u8] {
        crate::private_model_transport::certificate_spki_der(certificate).unwrap()
    }

    fn mapper_request() -> MapperIntentRequestV2 {
        let slot = PlannerAbstractSlotV2::new(
            PlannerSlotRefV2::new([0xa1; 16]),
            SlotKindV2::new(1),
            PlannerSlotCardinalityV2::ExactlyOne,
            PlannerSlotConfidentialityV2::ConfidentialAbstract,
        )
        .unwrap();
        let envelope = PlannerEnvelopeV2::new(
            PlannerRouteIdV2::new(0xdead_beef),
            StaticTemplateIdV2::new(7),
            PlannerIntentKindV2::Search,
            vec![ActionTemplateIdV2::new(10)],
            vec![slot],
            vec![],
            PlannerLimitsV2::new(4, 3, 2, 4096).unwrap(),
            Nonce32V2::new([0xcc; 32]),
            UnixMillisV2::new(0x0102_0304_0506_0708),
        )
        .unwrap();
        let active = ActiveToolViewV2::new(
            ToolHandleV2::from_authority_entropy([0xd1; 32]).unwrap(),
            ActionTemplateIdV2::new(10),
            ToolClassIdV2::new(100),
            StaticTemplateIdV2::new(107),
        )
        .unwrap();
        MapperIntentRequestV2::new(
            &envelope,
            &[active],
            vec![MapperCatalogToolV2::new(
                ToolClassIdV2::new(100),
                ActionTemplateIdV2::new(10),
                StructuralRoleV2::Source,
                EffectSetV2::READ,
            )
            .unwrap()],
        )
        .unwrap()
    }

    fn mapped_response(request: &MapperIntentRequestV2) -> Vec<u8> {
        let node = MappedNodeV2::new(
            1,
            ToolClassIdV2::new(100),
            ActionTemplateIdV2::new(10),
            vec![(
                ArgumentNameV2::new("input".to_owned()).unwrap(),
                PlannerSlotRefV2::new([0xa1; 16]),
            )],
            StructuralRoleV2::Source,
            EffectSetV2::READ,
        )
        .unwrap();
        encode_mapped_workflow_v2(&MappedWorkflowV2::new(request, vec![node], vec![]).unwrap())
            .unwrap()
    }

    fn read_request(
        tls: &mut StreamOwned<ServerConnection, std::net::TcpStream>,
    ) -> (Vec<u8>, Vec<u8>) {
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            let mut byte = [0_u8; 1];
            tls.read_exact(&mut byte).unwrap();
            header.push(byte[0]);
        }
        let text = std::str::from_utf8(&header).unwrap();
        let length = text
            .split("\r\n")
            .find_map(|line| line.strip_prefix("Content-Length: "))
            .unwrap()
            .parse::<usize>()
            .unwrap();
        let mut body = vec![0_u8; length];
        tls.read_exact(&mut body).unwrap();
        (header, body)
    }

    fn spawn_mapper_server(
        listener: TcpListener,
        expected_body: Vec<u8>,
        response: Vec<u8>,
    ) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            let mut client_roots = RootCertStore::empty();
            client_roots
                .add(CertificateDer::from(tls_fixture("ca_cert")))
                .unwrap();
            let client_verifier = WebPkiClientVerifier::builder(Arc::new(client_roots))
                .build()
                .unwrap();
            let mut config = ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(
                vec![CertificateDer::from(tls_fixture("server_cert"))],
                PrivateKeyDer::try_from(tls_fixture("server_key")).unwrap(),
            )
            .unwrap();
            config.alpn_protocols = vec![b"http/1.1".to_vec()];
            let (socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut tls =
                StreamOwned::new(ServerConnection::new(Arc::new(config)).unwrap(), socket);
            let (header, body) = read_request(&mut tls);
            assert!(tls
                .conn
                .peer_certificates()
                .is_some_and(|chain| !chain.is_empty()));
            assert_eq!(
                header,
                format!(
                    "POST /savana.mapper.v2/map HTTP/1.1\r\nHost: provider.example:{}\r\nContent-Type: application/cbor\r\nAccept: application/cbor\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    tls.sock.local_addr().unwrap().port(),
                    expected_body.len()
                )
                .as_bytes()
            );
            assert_eq!(body, expected_body);
            assert!(!body.windows(32).any(|window| window == [0xcc; 32]));
            assert!(!body
                .windows(4)
                .any(|window| window == 0xdead_beefu32.to_be_bytes()));
            assert!(!body
                .windows(8)
                .any(|window| window == 0x0102_0304_0506_0708u64.to_be_bytes()));
            assert!(!body.windows(32).any(|window| window == [0xd1; 32]));
            assert!(!body.windows(16).any(|window| window == [0xe2; 16]));
            write!(
                tls,
                "HTTP/1.1 200 OK\r\nContent-Type: application/cbor\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                response.len()
            )
            .unwrap();
            tls.write_all(&response).unwrap();
            tls.flush().unwrap();
            tls.conn.send_close_notify();
            let _ = tls.conn.complete_io(&mut tls.sock);
        })
    }

    fn spawn_pin_observer(listener: TcpListener) -> thread::JoinHandle<bool> {
        spawn_alpn_observer(listener, None)
    }

    fn spawn_alpn_observer(
        listener: TcpListener,
        negotiated_alpn: Option<Vec<u8>>,
    ) -> thread::JoinHandle<bool> {
        thread::spawn(move || {
            let mut client_roots = RootCertStore::empty();
            client_roots
                .add(CertificateDer::from(tls_fixture("ca_cert")))
                .unwrap();
            let client_verifier = WebPkiClientVerifier::builder(Arc::new(client_roots))
                .build()
                .unwrap();
            let mut config = ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(
                vec![CertificateDer::from(tls_fixture("server_cert"))],
                PrivateKeyDer::try_from(tls_fixture("server_key")).unwrap(),
            )
            .unwrap();
            config.alpn_protocols = negotiated_alpn.into_iter().collect();
            let (socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut tls =
                StreamOwned::new(ServerConnection::new(Arc::new(config)).unwrap(), socket);
            let mut byte = [0_u8; 1];
            tls.read(&mut byte).is_ok_and(|read| read > 0)
        })
    }

    fn spawn_slow_header_server(
        listener: TcpListener,
        expected_body: Vec<u8>,
    ) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            let mut client_roots = RootCertStore::empty();
            client_roots
                .add(CertificateDer::from(tls_fixture("ca_cert")))
                .unwrap();
            let client_verifier = WebPkiClientVerifier::builder(Arc::new(client_roots))
                .build()
                .unwrap();
            let mut config = ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(
                vec![CertificateDer::from(tls_fixture("server_cert"))],
                PrivateKeyDer::try_from(tls_fixture("server_key")).unwrap(),
            )
            .unwrap();
            config.alpn_protocols = vec![b"http/1.1".to_vec()];
            let (socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut tls =
                StreamOwned::new(ServerConnection::new(Arc::new(config)).unwrap(), socket);
            let (_, body) = read_request(&mut tls);
            assert_eq!(body, expected_body);
            for chunk in b"HTTP/1.1 200 OK\r\nContent-Type: application/cbor\r\n"
                .chunks(4)
                .take(6)
            {
                if tls.write_all(chunk).is_err() || tls.flush().is_err() {
                    break;
                }
                thread::sleep(Duration::from_millis(40));
            }
        })
    }

    fn spawn_raw_mapper_server(
        listener: TcpListener,
        expected_body: Vec<u8>,
        raw_response: Vec<u8>,
        clean_close: bool,
    ) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            let mut client_roots = RootCertStore::empty();
            client_roots
                .add(CertificateDer::from(tls_fixture("ca_cert")))
                .unwrap();
            let client_verifier = WebPkiClientVerifier::builder(Arc::new(client_roots))
                .build()
                .unwrap();
            let mut config = ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(
                vec![CertificateDer::from(tls_fixture("server_cert"))],
                PrivateKeyDer::try_from(tls_fixture("server_key")).unwrap(),
            )
            .unwrap();
            config.alpn_protocols = vec![b"http/1.1".to_vec()];
            let (socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut tls =
                StreamOwned::new(ServerConnection::new(Arc::new(config)).unwrap(), socket);
            let (_, body) = read_request(&mut tls);
            assert_eq!(body, expected_body);
            tls.write_all(&raw_response).unwrap();
            tls.flush().unwrap();
            if clean_close {
                tls.conn.send_close_notify();
                let _ = tls.conn.complete_io(&mut tls.sock);
            }
        })
    }

    fn mapper_client(
        ceiling: IntentTrustDeploymentCeilingV2,
        private: MapperEndpointDeploymentV2,
        third_party: Option<MapperEndpointDeploymentV2>,
    ) -> Result<PinnedMtlsAgentMapperClientV2, super::AgentMapperClientErrorV2> {
        PinnedMtlsAgentMapperClientV2::from_verified_deployment(
            ceiling,
            private,
            third_party,
            tls_fixture("ca_cert"),
            tls_fixture("client_cert"),
            Zeroizing::new(tls_fixture("client_key")),
        )
    }

    fn server_pin() -> savana_kernel_protocol::v2::Digest32V2 {
        let certificate = tls_fixture("server_cert");
        savana_kernel_protocol::v2::Digest32V2::new(
            Sha256::digest(certificate_spki_der(&certificate)).into(),
        )
    }

    fn deadline_after(duration: Duration) -> UnixMillisV2 {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        UnixMillisV2::new(u64::try_from((now + duration).as_millis()).unwrap())
    }

    #[test]
    fn live_mutual_tls_mapper_receives_only_nonce_free_canonical_intent_projection() {
        let request = mapper_request();
        let request_bytes = encode_mapper_intent_request_v2(&request).unwrap();
        let response = mapped_response(&request);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address: SocketAddr = listener.local_addr().unwrap();
        let server = spawn_mapper_server(listener, request_bytes, response);
        let endpoint = MapperEndpointDeploymentV2::for_test(
            "provider.example".to_owned(),
            address,
            server_pin(),
        )
        .unwrap();
        let client =
            mapper_client(IntentTrustDeploymentCeilingV2::PrivateOnly, endpoint, None).unwrap();

        let mapped = client
            .map(
                &request,
                IntentTrustBoundaryV2::Private,
                deadline_after(Duration::from_secs(2)),
            )
            .unwrap();
        assert_eq!(
            encode_mapped_workflow_v2(&mapped).unwrap(),
            mapped_response(&request)
        );
        server.join().unwrap();
    }

    #[test]
    fn private_only_rejects_third_party_before_any_network_io() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = MapperEndpointDeploymentV2::for_test(
            "provider.example".to_owned(),
            listener.local_addr().unwrap(),
            server_pin(),
        )
        .unwrap();
        let client =
            mapper_client(IntentTrustDeploymentCeilingV2::PrivateOnly, endpoint, None).unwrap();
        assert_eq!(
            client.map(
                &mapper_request(),
                IntentTrustBoundaryV2::ThirdParty,
                deadline_after(Duration::from_secs(2)),
            ),
            Err(super::AgentMapperClientErrorV2::BoundaryDenied)
        );
        listener.set_nonblocking(true).unwrap();
        assert!(listener.accept().is_err());
    }

    #[test]
    fn permissive_ceiling_selects_the_distinct_third_party_endpoint() {
        let third_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let third_address = third_listener.local_addr().unwrap();
        let unused_private = TcpListener::bind("127.0.0.1:0").unwrap();
        let private_address = unused_private.local_addr().unwrap();
        drop(unused_private);
        let request = mapper_request();
        let server = spawn_mapper_server(
            third_listener,
            encode_mapper_intent_request_v2(&request).unwrap(),
            mapped_response(&request),
        );
        let private = MapperEndpointDeploymentV2::for_test(
            "provider.example".to_owned(),
            private_address,
            server_pin(),
        )
        .unwrap();
        let third_party = MapperEndpointDeploymentV2::for_test(
            "provider.example".to_owned(),
            third_address,
            server_pin(),
        )
        .unwrap();
        let client = mapper_client(
            IntentTrustDeploymentCeilingV2::UserMayUseThirdParty,
            private,
            Some(third_party),
        )
        .unwrap();
        client
            .map(
                &request,
                IntentTrustBoundaryV2::ThirdParty,
                deadline_after(Duration::from_secs(2)),
            )
            .unwrap();
        server.join().unwrap();
    }

    #[test]
    fn resolver_tries_all_addresses_with_the_same_absolute_deadline() {
        let request = mapper_request();
        let server_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let good = server_listener.local_addr().unwrap();
        let unused = TcpListener::bind("127.0.0.1:0").unwrap();
        let bad = unused.local_addr().unwrap();
        drop(unused);
        let server = spawn_mapper_server(
            server_listener,
            encode_mapper_intent_request_v2(&request).unwrap(),
            mapped_response(&request),
        );
        let endpoint = MapperEndpointDeploymentV2::for_test_resolver(
            "provider.example".to_owned(),
            good.port(),
            server_pin(),
            move |_, _| Ok(vec![bad, good]),
        )
        .unwrap()
        .with_test_connector(move |address, timeout| {
            if address == bad {
                thread::sleep(timeout);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "simulated black-hole address",
                ));
            }
            std::net::TcpStream::connect(address)
        });
        let client =
            mapper_client(IntentTrustDeploymentCeilingV2::PrivateOnly, endpoint, None).unwrap();
        client
            .map(
                &request,
                IntentTrustBoundaryV2::Private,
                deadline_after(Duration::from_millis(800)),
            )
            .unwrap();
        server.join().unwrap();
    }

    #[test]
    fn blocked_resolver_is_bounded_by_the_absolute_deadline() {
        let endpoint = MapperEndpointDeploymentV2::for_test_resolver(
            "provider.example".to_owned(),
            443,
            server_pin(),
            |_, _| {
                thread::sleep(Duration::from_millis(250));
                Ok(vec![])
            },
        )
        .unwrap();
        let client =
            mapper_client(IntentTrustDeploymentCeilingV2::PrivateOnly, endpoint, None).unwrap();
        let started = Instant::now();
        assert_eq!(
            client.map(
                &mapper_request(),
                IntentTrustBoundaryV2::Private,
                deadline_after(Duration::from_millis(75)),
            ),
            Err(super::AgentMapperClientErrorV2::DeadlineExceeded)
        );
        assert!(started.elapsed() < Duration::from_millis(200));
    }

    #[test]
    fn private_ceiling_rejects_a_configured_third_party_at_construction() {
        let private = MapperEndpointDeploymentV2::new(
            "private.example".to_owned(),
            443,
            savana_kernel_protocol::v2::Digest32V2::new([0x41; 32]),
        )
        .unwrap();
        let third_party = MapperEndpointDeploymentV2::new(
            "third.example".to_owned(),
            443,
            savana_kernel_protocol::v2::Digest32V2::new([0x42; 32]),
        )
        .unwrap();
        assert!(matches!(
            mapper_client(
                IntentTrustDeploymentCeilingV2::PrivateOnly,
                private,
                Some(third_party)
            ),
            Err(super::AgentMapperClientErrorV2::InvalidDeployment)
        ));
    }

    #[test]
    fn wrong_leaf_spki_pin_is_rejected_before_first_application_byte() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let observer = spawn_pin_observer(listener);
        let endpoint = MapperEndpointDeploymentV2::for_test(
            "provider.example".to_owned(),
            address,
            savana_kernel_protocol::v2::Digest32V2::new([0x61; 32]),
        )
        .unwrap();
        let client =
            mapper_client(IntentTrustDeploymentCeilingV2::PrivateOnly, endpoint, None).unwrap();
        assert_eq!(
            client.map(
                &mapper_request(),
                IntentTrustBoundaryV2::Private,
                deadline_after(Duration::from_secs(2)),
            ),
            Err(super::AgentMapperClientErrorV2::InvalidDeployment)
        );
        assert!(!observer.join().unwrap());
    }

    #[test]
    fn absent_or_wrong_alpn_is_rejected_before_first_application_byte() {
        for negotiated_alpn in [None, Some(b"h2".to_vec())] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let observer = spawn_alpn_observer(listener, negotiated_alpn);
            let endpoint = MapperEndpointDeploymentV2::for_test(
                "provider.example".to_owned(),
                address,
                server_pin(),
            )
            .unwrap();
            let client =
                mapper_client(IntentTrustDeploymentCeilingV2::PrivateOnly, endpoint, None).unwrap();
            assert!(client
                .map(
                    &mapper_request(),
                    IntentTrustBoundaryV2::Private,
                    deadline_after(Duration::from_secs(2)),
                )
                .is_err());
            assert!(!observer.join().unwrap());
        }
    }

    #[test]
    fn expired_deadline_is_rejected_before_connect_and_errors_do_not_echo_intent() {
        let endpoint = MapperEndpointDeploymentV2::new(
            "private.example".to_owned(),
            443,
            savana_kernel_protocol::v2::Digest32V2::new([0x71; 32]),
        )
        .unwrap();
        let client =
            mapper_client(IntentTrustDeploymentCeilingV2::PrivateOnly, endpoint, None).unwrap();
        let error = client
            .map(
                &mapper_request(),
                IntentTrustBoundaryV2::Private,
                UnixMillisV2::new(1),
            )
            .unwrap_err();
        assert_eq!(error, super::AgentMapperClientErrorV2::DeadlineExceeded);
        assert!(!format!("{error:?}").contains("Search"));
    }

    #[test]
    fn slow_header_cannot_extend_the_absolute_deadline_byte_by_byte() {
        let request = mapper_request();
        let request_bytes = encode_mapper_intent_request_v2(&request).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = spawn_slow_header_server(listener, request_bytes);
        let endpoint = MapperEndpointDeploymentV2::for_test(
            "provider.example".to_owned(),
            address,
            server_pin(),
        )
        .unwrap();
        let client =
            mapper_client(IntentTrustDeploymentCeilingV2::PrivateOnly, endpoint, None).unwrap();
        let started = Instant::now();
        assert_eq!(
            client.map(
                &request,
                IntentTrustBoundaryV2::Private,
                deadline_after(Duration::from_millis(100)),
            ),
            Err(super::AgentMapperClientErrorV2::DeadlineExceeded)
        );
        assert!(started.elapsed() < Duration::from_secs(1));
        server.join().unwrap();
    }

    #[test]
    fn noncanonical_mapper_response_is_rejected() {
        let request = mapper_request();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = spawn_mapper_server(
            listener,
            encode_mapper_intent_request_v2(&request).unwrap(),
            vec![0x9f, 0x02, 0x80, 0x80, 0xff],
        );
        let endpoint = MapperEndpointDeploymentV2::for_test(
            "provider.example".to_owned(),
            address,
            server_pin(),
        )
        .unwrap();
        let client =
            mapper_client(IntentTrustDeploymentCeilingV2::PrivateOnly, endpoint, None).unwrap();
        assert_eq!(
            client.map(
                &request,
                IntentTrustBoundaryV2::Private,
                deadline_after(Duration::from_secs(2)),
            ),
            Err(super::AgentMapperClientErrorV2::InvalidWorkflow)
        );
        server.join().unwrap();
    }

    #[test]
    fn live_transport_rejects_redirect_cookie_compression_chunking_and_body_overflow() {
        let request = mapper_request();
        let expected_body = encode_mapper_intent_request_v2(&request).unwrap();
        let forbidden_responses = [
            b"HTTP/1.1 307 Temporary Redirect\r\nLocation: https://other.example/map\r\nContent-Type: application/cbor\r\nContent-Length: 1\r\nConnection: close\r\n\r\nx".to_vec(),
            b"HTTP/1.1 200 OK\r\nContent-Type: application/cbor\r\nContent-Encoding: gzip\r\nContent-Length: 1\r\nConnection: close\r\n\r\nx".to_vec(),
            b"HTTP/1.1 200 OK\r\nContent-Type: application/cbor\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n1\r\nx\r\n0\r\n\r\n".to_vec(),
            b"HTTP/1.1 200 OK\r\nContent-Type: application/cbor\r\nSet-Cookie: session=ambient\r\nContent-Length: 1\r\nConnection: close\r\n\r\nx".to_vec(),
            b"HTTP/1.1 200 OK\r\nContent-Type: application/cbor\r\nContent-Length: 8388609\r\nConnection: close\r\n\r\n".to_vec(),
            b"HTTP/1.1 200 OK\r\nContent-Type: application/cbor\r\nContent-Length: 1\r\nConnection: keep-alive\r\n\r\nx".to_vec(),
        ];
        for response in forbidden_responses {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let server = spawn_raw_mapper_server(listener, expected_body.clone(), response, true);
            let endpoint = MapperEndpointDeploymentV2::for_test(
                "provider.example".to_owned(),
                address,
                server_pin(),
            )
            .unwrap();
            let client =
                mapper_client(IntentTrustDeploymentCeilingV2::PrivateOnly, endpoint, None).unwrap();
            assert_eq!(
                client.map(
                    &request,
                    IntentTrustBoundaryV2::Private,
                    deadline_after(Duration::from_secs(2)),
                ),
                Err(super::AgentMapperClientErrorV2::InvalidWorkflow)
            );
            server.join().unwrap();
        }
    }

    #[test]
    fn trailing_application_byte_and_unclean_tls_eof_are_rejected() {
        let request = mapper_request();
        let expected_body = encode_mapper_intent_request_v2(&request).unwrap();
        let mapped = mapped_response(&request);

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let mut raw = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/cbor\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            mapped.len()
        )
        .into_bytes();
        raw.extend_from_slice(&mapped);
        raw.push(0xff);
        let server = spawn_raw_mapper_server(listener, expected_body.clone(), raw, true);
        let endpoint = MapperEndpointDeploymentV2::for_test(
            "provider.example".to_owned(),
            address,
            server_pin(),
        )
        .unwrap();
        let client =
            mapper_client(IntentTrustDeploymentCeilingV2::PrivateOnly, endpoint, None).unwrap();
        assert!(client
            .map(
                &request,
                IntentTrustBoundaryV2::Private,
                deadline_after(Duration::from_secs(2)),
            )
            .is_err());
        server.join().unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let mut raw = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/cbor\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            mapped.len()
        )
        .into_bytes();
        raw.extend_from_slice(&mapped);
        let server = spawn_raw_mapper_server(listener, expected_body, raw, false);
        let endpoint = MapperEndpointDeploymentV2::for_test(
            "provider.example".to_owned(),
            address,
            server_pin(),
        )
        .unwrap();
        let client =
            mapper_client(IntentTrustDeploymentCeilingV2::PrivateOnly, endpoint, None).unwrap();
        assert!(client
            .map(
                &request,
                IntentTrustBoundaryV2::Private,
                deadline_after(Duration::from_secs(2)),
            )
            .is_err());
        server.join().unwrap();
    }
}
