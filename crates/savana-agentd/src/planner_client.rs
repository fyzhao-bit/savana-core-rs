use savana_kernel_protocol::v2::{
    decode_planner_plan_v2, Digest32V2, PlannerEnvelopeV2, PlannerPlanV2, UnixMillisV2,
};
use zeroize::Zeroizing;

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

    pub fn plan(
        &self,
        envelope: &PlannerEnvelopeV2,
        deadline: UnixMillisV2,
    ) -> Result<PlannerPlanV2, AgentPlannerClientErrorV2> {
        let body =
            minicbor::to_vec(envelope).map_err(|_| AgentPlannerClientErrorV2::InvalidPlan)?;
        if body.is_empty() || body.len() > MAX_PLANNER_BODY_BYTES_V2 {
            return Err(AgentPlannerClientErrorV2::InvalidPlan);
        }
        let response = self
            .endpoint
            .post_canonical_cbor(PLANNER_PATH_V2, &body, MAX_PLANNER_BODY_BYTES_V2, deadline)
            .map_err(map_transport)?;
        decode_planner_plan_v2(&response).map_err(|_| AgentPlannerClientErrorV2::InvalidPlan)
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
    use savana_kernel_protocol::v2::{
        encode_planner_plan_v2, ActionTemplateIdV2, Digest32V2, Nonce32V2, PlannerEnvelopeV2,
        PlannerIntentKindV2, PlannerLimitsV2, PlannerPlanV2, PlannerRouteIdV2, StaticTemplateIdV2,
        UnixMillisV2,
    };
    use sha2::{Digest as _, Sha256};
    use zeroize::Zeroizing;

    use super::PinnedMtlsAgentPlannerClientV2;
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

    fn planner_envelope() -> PlannerEnvelopeV2 {
        PlannerEnvelopeV2::new(
            PlannerRouteIdV2::new(99),
            StaticTemplateIdV2::new(7),
            PlannerIntentKindV2::Search,
            vec![ActionTemplateIdV2::new(10)],
            vec![],
            vec![],
            PlannerLimitsV2::new(4, 3, 2, 4096).unwrap(),
            Nonce32V2::new([0xcc; 32]),
            deadline_after(Duration::from_secs(10)),
        )
        .unwrap()
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
    fn live_planner_uses_http_1_1_alpn_and_requires_clean_tls_eof() {
        let envelope = planner_envelope();
        let expected_body = minicbor::to_vec(&envelope).unwrap();
        let expected_plan = PlannerPlanV2::new(envelope.envelope_nonce(), vec![]).unwrap();
        let response = encode_planner_plan_v2(&expected_plan).unwrap();
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
                .plan(&envelope, deadline_after(Duration::from_secs(2)))
                .unwrap(),
            expected_plan
        );
        server.join().unwrap();
    }
}
