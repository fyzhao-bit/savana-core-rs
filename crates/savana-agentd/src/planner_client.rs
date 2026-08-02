use savana_kernel_protocol::v2::{Digest32V2, UnixMillisV2};
use zeroize::Zeroizing;

use crate::planner_privacy::{
    decode_ordered_structural_plan_for_request_v2, encode_structural_planner_request_v2,
    OrderedStructuralPlanV2, StructuralPlannerRequestV2,
};
use crate::private_model_transport::{
    PinnedMtlsCborEndpointV2, PrivateModelTransportErrorV2, VerifiedMtlsClientCredentialsV2,
};

const PLANNER_PATH_V2: &str = "/savana.planner.v2/plan";
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
    endpoint: PinnedMtlsCborEndpointV2,
}

impl core::fmt::Debug for PinnedMtlsAgentPlannerClientV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("PinnedMtlsAgentPlannerClientV2(<deployment-redacted>)")
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
        let credentials = VerifiedMtlsClientCredentialsV2::from_verified_deployment(
            root_certificate_der,
            client_certificate_der,
            client_private_key_pkcs8_der,
        )
        .map_err(map_transport)?;
        let endpoint = PinnedMtlsCborEndpointV2::from_verified_deployment(
            host,
            port,
            server_spki_sha256,
            credentials,
        )
        .map_err(map_transport)?;
        Ok(Self { endpoint })
    }

    #[cfg(any(test, all(feature = "test-support", debug_assertions)))]
    #[doc(hidden)]
    #[allow(clippy::too_many_arguments)]
    pub fn from_verified_deployment_for_test(
        host: String,
        address: std::net::SocketAddr,
        server_spki_sha256: Digest32V2,
        root_certificate_der: Vec<u8>,
        client_certificate_der: Vec<u8>,
        client_private_key_pkcs8_der: Zeroizing<Vec<u8>>,
    ) -> Result<Self, AgentPlannerClientErrorV2> {
        let mut client = Self::from_verified_deployment(
            host,
            address.port(),
            server_spki_sha256,
            root_certificate_der,
            client_certificate_der,
            client_private_key_pkcs8_der,
        )?;
        client.endpoint.set_test_address(address);
        Ok(client)
    }

    pub fn plan(
        &self,
        request: &StructuralPlannerRequestV2,
        deadline: UnixMillisV2,
    ) -> Result<OrderedStructuralPlanV2, AgentPlannerClientErrorV2> {
        let body = encode_structural_planner_request_v2(request)
            .map_err(|_| AgentPlannerClientErrorV2::InvalidPlan)?;
        if body.is_empty() || body.len() > MAX_PLANNER_BODY_BYTES_V2 {
            return Err(AgentPlannerClientErrorV2::InvalidPlan);
        }
        let response = self
            .endpoint
            .post_canonical_cbor(PLANNER_PATH_V2, &body, MAX_PLANNER_BODY_BYTES_V2, deadline)
            .map_err(map_transport)?;
        decode_ordered_structural_plan_for_request_v2(&response, request)
            .map_err(|_| AgentPlannerClientErrorV2::InvalidPlan)
    }
}

fn map_transport(error: PrivateModelTransportErrorV2) -> AgentPlannerClientErrorV2 {
    match error {
        PrivateModelTransportErrorV2::DeadlineExceeded => {
            AgentPlannerClientErrorV2::DeadlineExceeded
        }
        PrivateModelTransportErrorV2::InvalidDeployment => {
            AgentPlannerClientErrorV2::InvalidDeployment
        }
        PrivateModelTransportErrorV2::Unavailable => AgentPlannerClientErrorV2::Unavailable,
        PrivateModelTransportErrorV2::InvalidResponse => AgentPlannerClientErrorV2::InvalidPlan,
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use rustls::server::WebPkiClientVerifier;
    use rustls::{RootCertStore, ServerConfig, ServerConnection, StreamOwned};
    use savana_kernel_protocol::v2::{Digest32V2, UnixMillisV2};
    use savana_policy_core::v2::EffectSetV2;
    use sha2::{Digest as _, Sha256};
    use zeroize::Zeroizing;

    use super::{AgentPlannerClientErrorV2, PinnedMtlsAgentPlannerClientV2};
    use crate::planner_privacy::{
        decode_structural_planner_request_v2, encode_ordered_structural_plan_v2,
        encode_structural_planner_request_v2, OrderedStructuralPlanV2, StructuralEdgeV2,
        StructuralGoalV2, StructuralGraphV2, StructuralNodeIdV2, StructuralNodeV2,
        StructuralPlannerRequestV2, StructuralRoleV2,
    };
    use crate::private_model_transport::validate_response_header;

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

    fn id(byte: u8) -> StructuralNodeIdV2 {
        StructuralNodeIdV2::new([byte; 16]).unwrap()
    }

    fn structural_request() -> StructuralPlannerRequestV2 {
        StructuralPlannerRequestV2::new(
            StructuralGraphV2::new(
                vec![
                    StructuralNodeV2::new(
                        id(0x31),
                        StructuralRoleV2::Source,
                        EffectSetV2::READ,
                        0,
                        1,
                    )
                    .unwrap(),
                    StructuralNodeV2::new(
                        id(0x42),
                        StructuralRoleV2::Sink,
                        EffectSetV2::SEND,
                        1,
                        0,
                    )
                    .unwrap(),
                ],
                vec![StructuralEdgeV2::new(id(0x31), id(0x42)).unwrap()],
            )
            .unwrap(),
            StructuralGoalV2::OrderValidDataflow,
        )
    }

    fn ordered_response() -> OrderedStructuralPlanV2 {
        OrderedStructuralPlanV2::new(vec![id(0x31), id(0x42)]).unwrap()
    }

    fn deadline_after(duration: Duration) -> UnixMillisV2 {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        UnixMillisV2::new(u64::try_from((now + duration).as_millis()).unwrap())
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

    fn server_config(alpn_protocols: Vec<Vec<u8>>) -> ServerConfig {
        let mut client_roots = RootCertStore::empty();
        client_roots
            .add(CertificateDer::from(tls_fixture("ca_cert")))
            .unwrap();
        let client_verifier = WebPkiClientVerifier::builder(Arc::new(client_roots))
            .build()
            .unwrap();
        let mut config =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_client_cert_verifier(client_verifier)
                .with_single_cert(
                    vec![CertificateDer::from(tls_fixture("server_cert"))],
                    PrivateKeyDer::try_from(tls_fixture("server_key")).unwrap(),
                )
                .unwrap();
        config.alpn_protocols = alpn_protocols;
        config
    }

    fn server_pin() -> Digest32V2 {
        let certificate = tls_fixture("server_cert");
        Digest32V2::new(
            Sha256::digest(
                crate::private_model_transport::certificate_spki_der(&certificate).unwrap(),
            )
            .into(),
        )
    }

    fn planner_client(
        address: std::net::SocketAddr,
        pin: Digest32V2,
    ) -> PinnedMtlsAgentPlannerClientV2 {
        let mut client = PinnedMtlsAgentPlannerClientV2::from_verified_deployment(
            "provider.example".to_owned(),
            address.port(),
            pin,
            tls_fixture("ca_cert"),
            tls_fixture("client_cert"),
            Zeroizing::new(tls_fixture("client_key")),
        )
        .unwrap();
        client.endpoint.set_test_address(address);
        client
    }

    fn spawn_raw_planner_server(
        listener: TcpListener,
        expected_body: Vec<u8>,
        raw_response: Vec<u8>,
        clean_close: bool,
    ) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut tls = StreamOwned::new(
                ServerConnection::new(Arc::new(server_config(vec![b"http/1.1".to_vec()]))).unwrap(),
                socket,
            );
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

    fn raw_success(body: &[u8]) -> Vec<u8> {
        let mut response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/cbor\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        response.extend_from_slice(body);
        response
    }

    fn spawn_application_byte_observer(
        listener: TcpListener,
        alpn_protocols: Vec<Vec<u8>>,
    ) -> thread::JoinHandle<bool> {
        thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut tls = StreamOwned::new(
                ServerConnection::new(Arc::new(server_config(alpn_protocols))).unwrap(),
                socket,
            );
            let mut byte = [0_u8; 1];
            tls.read(&mut byte).is_ok_and(|read| read > 0)
        })
    }

    fn run_raw_response_case(raw_response: Vec<u8>) -> AgentPlannerClientErrorV2 {
        let request = structural_request();
        let expected_body = encode_structural_planner_request_v2(&request).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = spawn_raw_planner_server(listener, expected_body, raw_response, true);
        let error = planner_client(address, server_pin())
            .plan(&request, deadline_after(Duration::from_secs(2)))
            .unwrap_err();
        server.join().unwrap();
        error
    }

    #[test]
    fn planner_http_surface_is_exact_and_rejects_ambient_features() {
        assert_eq!(
            validate_response_header(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/cbor\r\nContent-Length: 42\r\nConnection: close\r\n\r\n",
                1024,
            )
            .unwrap(),
            42
        );
        assert!(validate_response_header(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/cbor\r\nContent-Length: 42\r\nContent-Encoding: gzip\r\nConnection: close\r\n\r\n",
            1024,
        )
        .is_err());
    }

    #[test]
    fn live_planner_receives_only_the_exact_structural_graph() {
        const INTENT_SENTINEL: &[u8] = b"retain-churning-high-value-customers";
        const TOOL_CLASS_SENTINEL: [u8; 4] = 0xf1e2_d3c4_u32.to_be_bytes();
        const ACTION_SENTINEL: [u8; 4] = 0xa5b6_c7d8_u32.to_be_bytes();
        const SEMANTIC_NAME_SENTINEL: &[u8] = b"send_to_private_crm";
        const SEMANTIC_DESCRIPTION_SENTINEL: &[u8] =
            b"send retained customer record to private Salesforce tenant";
        const NONCE_SENTINEL: [u8; 32] = [0xcc; 32];
        const SLOT_REF_SENTINEL: [u8; 16] = [0xee; 16];

        let request = structural_request();
        let expected_body = encode_structural_planner_request_v2(&request).unwrap();
        let expected_plan = ordered_response();
        let response = encode_ordered_structural_plan_v2(&expected_plan).unwrap();
        let server_request = request.clone();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
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
            assert_eq!(
                header,
                format!(
                    "POST /savana.planner.v2/plan HTTP/1.1\r\nHost: provider.example:{}\r\nContent-Type: application/cbor\r\nAccept: application/cbor\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    address.port(),
                    expected_body.len()
                )
                .as_bytes()
            );
            assert_eq!(body, expected_body);
            assert_eq!(
                decode_structural_planner_request_v2(&body).unwrap(),
                server_request
            );
            for sentinel in [
                INTENT_SENTINEL,
                TOOL_CLASS_SENTINEL.as_slice(),
                ACTION_SENTINEL.as_slice(),
                SEMANTIC_NAME_SENTINEL,
                SEMANTIC_DESCRIPTION_SENTINEL,
                NONCE_SENTINEL.as_slice(),
                SLOT_REF_SENTINEL.as_slice(),
            ] {
                assert!(!body
                    .windows(sentinel.len())
                    .any(|window| window == sentinel));
            }
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
        });

        let server_certificate = tls_fixture("server_cert");
        let pin = Digest32V2::new(
            Sha256::digest(
                crate::private_model_transport::certificate_spki_der(&server_certificate).unwrap(),
            )
            .into(),
        );
        let mut client = PinnedMtlsAgentPlannerClientV2::from_verified_deployment(
            "provider.example".to_owned(),
            address.port(),
            pin,
            tls_fixture("ca_cert"),
            tls_fixture("client_cert"),
            Zeroizing::new(tls_fixture("client_key")),
        )
        .unwrap();
        client.endpoint.set_test_address(address);
        assert_eq!(
            client
                .plan(&request, deadline_after(Duration::from_secs(2)))
                .unwrap(),
            expected_plan
        );
        server.join().unwrap();
    }

    #[test]
    fn plan_api_is_structural_at_compile_time() {
        let _: fn(
            &PinnedMtlsAgentPlannerClientV2,
            &StructuralPlannerRequestV2,
            UnixMillisV2,
        ) -> Result<OrderedStructuralPlanV2, AgentPlannerClientErrorV2> =
            PinnedMtlsAgentPlannerClientV2::plan;
    }

    #[test]
    fn planner_rejects_non_permutations_and_non_topological_orders() {
        for invalid in [
            OrderedStructuralPlanV2::new(vec![id(0x31)]).unwrap(),
            OrderedStructuralPlanV2::new(vec![id(0x31), id(0x31)]).unwrap(),
            OrderedStructuralPlanV2::new(vec![id(0x31), id(0x99)]).unwrap(),
            OrderedStructuralPlanV2::new(vec![id(0x42), id(0x31)]).unwrap(),
        ] {
            let body = encode_ordered_structural_plan_v2(&invalid).unwrap();
            assert_eq!(
                run_raw_response_case(raw_success(&body)),
                AgentPlannerClientErrorV2::InvalidPlan
            );
        }
    }

    #[test]
    fn planner_rejects_malformed_noncanonical_and_oversized_responses() {
        let canonical = encode_ordered_structural_plan_v2(&ordered_response()).unwrap();
        assert_eq!(canonical[1], 0x02);
        let mut noncanonical = vec![canonical[0], 0x19, 0x00, 0x02];
        noncanonical.extend_from_slice(&canonical[2..]);
        for response in [
            raw_success(&[0xff]),
            raw_success(&noncanonical),
            b"HTTP/1.1 200 OK\r\nContent-Type: application/cbor\r\nContent-Length: 8388609\r\nConnection: close\r\n\r\n".to_vec(),
        ] {
            assert_eq!(
                run_raw_response_case(response),
                AgentPlannerClientErrorV2::InvalidPlan
            );
        }
    }

    #[test]
    fn planner_rejects_redirect_compression_chunking_and_wrong_content_type() {
        for response in [
            b"HTTP/1.1 307 Temporary Redirect\r\nLocation: https://other.example/plan\r\nContent-Type: application/cbor\r\nContent-Length: 1\r\nConnection: close\r\n\r\nx".to_vec(),
            b"HTTP/1.1 200 OK\r\nContent-Type: application/cbor\r\nContent-Encoding: gzip\r\nContent-Length: 1\r\nConnection: close\r\n\r\nx".to_vec(),
            b"HTTP/1.1 200 OK\r\nContent-Type: application/cbor\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n1\r\nx\r\n0\r\n\r\n".to_vec(),
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 1\r\nConnection: close\r\n\r\nx".to_vec(),
        ] {
            assert_eq!(
                run_raw_response_case(response),
                AgentPlannerClientErrorV2::InvalidPlan
            );
        }
    }

    #[test]
    fn planner_requires_clean_tls_eof_and_rejects_trailing_application_bytes() {
        let body = encode_ordered_structural_plan_v2(&ordered_response()).unwrap();
        let request = structural_request();
        let expected_body = encode_structural_planner_request_v2(&request).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server =
            spawn_raw_planner_server(listener, expected_body.clone(), raw_success(&body), false);
        assert!(planner_client(address, server_pin())
            .plan(&request, deadline_after(Duration::from_secs(2)))
            .is_err());
        server.join().unwrap();

        let mut response = raw_success(&body);
        response.push(0xff);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = spawn_raw_planner_server(listener, expected_body, response, true);
        assert_eq!(
            planner_client(address, server_pin())
                .plan(&request, deadline_after(Duration::from_secs(2))),
            Err(AgentPlannerClientErrorV2::InvalidPlan)
        );
        server.join().unwrap();
    }

    #[test]
    fn planner_rejects_wrong_spki_before_sending_application_bytes() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let observer = spawn_application_byte_observer(listener, vec![b"http/1.1".to_vec()]);
        assert_eq!(
            planner_client(address, Digest32V2::new([0x61; 32])).plan(
                &structural_request(),
                deadline_after(Duration::from_secs(2))
            ),
            Err(AgentPlannerClientErrorV2::InvalidDeployment)
        );
        assert!(!observer.join().unwrap());
    }

    #[test]
    fn planner_rejects_absent_or_wrong_alpn_before_sending_application_bytes() {
        for protocols in [Vec::new(), vec![b"h2".to_vec()]] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let observer = spawn_application_byte_observer(listener, protocols);
            assert!(planner_client(address, server_pin())
                .plan(
                    &structural_request(),
                    deadline_after(Duration::from_secs(2))
                )
                .is_err());
            assert!(!observer.join().unwrap());
        }
    }

    #[test]
    fn planner_rejects_expired_deadline_before_network_io() {
        let client = PinnedMtlsAgentPlannerClientV2::from_verified_deployment(
            "provider.example".to_owned(),
            443,
            server_pin(),
            tls_fixture("ca_cert"),
            tls_fixture("client_cert"),
            Zeroizing::new(tls_fixture("client_key")),
        )
        .unwrap();
        assert_eq!(
            client.plan(&structural_request(), UnixMillisV2::new(1)),
            Err(AgentPlannerClientErrorV2::DeadlineExceeded)
        );
    }
}
