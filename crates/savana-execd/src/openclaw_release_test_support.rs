//! Test-only compatibility oracle for the Savana final-release receiver.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use savana_kernel_protocol::v2::{Digest32V2, Nonce32V2};
use savana_policy_core::v2::BoundedConnectorUrlV2;
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::provider_transport::{
    certificate_spki_der, credential_identity_digest, endpoint_binding_digest,
    VerifiedRustlsProviderTransportV2,
};
use crate::worker_protocol::prepared_provider_request_digest;
use crate::worker_supervisor::{
    ProviderTransportV2, VerifiedProviderRequestV2, VerifiedProviderTargetV2,
};
use crate::EffectPermitV2;

pub struct OpenClawReleaseTlsFixtureV2 {
    pub ca_certificate_der: Vec<u8>,
    pub server_certificate_der: Vec<u8>,
    pub server_private_key_der: Zeroizing<Vec<u8>>,
    pub expected_client_spki_pin: [u8; 32],
    pub server_spki_pin: [u8; 32],
}

pub fn tls_fixture_v2() -> OpenClawReleaseTlsFixtureV2 {
    let ca_certificate_der = fixture_bytes("ca_cert");
    let server_certificate_der = fixture_bytes("server_cert");
    let server_private_key_der = Zeroizing::new(fixture_bytes("server_key"));
    let client_certificate_der = fixture_bytes("client_cert");
    let expected_client_spki_pin = Sha256::digest(
        certificate_spki_der(&client_certificate_der).expect("valid fixture client SPKI"),
    )
    .into();
    let server_spki_pin = Sha256::digest(
        certificate_spki_der(&server_certificate_der).expect("valid fixture server SPKI"),
    )
    .into();
    OpenClawReleaseTlsFixtureV2 {
        ca_certificate_der,
        server_certificate_der,
        server_private_key_der,
        expected_client_spki_pin,
        server_spki_pin,
    }
}

pub fn execute_release_fixture_v2(
    address: SocketAddr,
    canonical_url: &str,
    payload: &[u8],
    alpn_protocol: &[u8],
) -> Result<Vec<u8>, &'static str> {
    let ca = fixture_bytes("ca_cert");
    let client_certificate = fixture_bytes("client_cert");
    let client_private_key = fixture_bytes("client_key");
    let canonical_url =
        BoundedConnectorUrlV2::new(canonical_url).map_err(|_| "invalid canonical URL")?;
    let fixture = tls_fixture_v2();
    let mut transport = VerifiedRustlsProviderTransportV2::from_verified_manifest(
        address,
        "provider.example".to_owned(),
        canonical_url,
        Digest32V2::new(fixture.server_spki_pin),
        ca.clone(),
        vec![client_certificate.clone()],
        Zeroizing::new(client_private_key),
        alpn_protocol.to_vec(),
        endpoint_binding_digest(
            address,
            "provider.example",
            &ca,
            &client_certificate,
            alpn_protocol,
        ),
        credential_identity_digest(&client_certificate),
    )
    .map_err(|_| "transport construction failed")?;
    let target: VerifiedProviderTargetV2 = transport
        .verified_deployment_target()
        .map_err(|_| "target verification failed")?;
    let request = VerifiedProviderRequestV2::bind(
        target,
        Nonce32V2::new([0x51; 32]),
        Digest32V2::new([0x52; 32]),
        Digest32V2::new([0x53; 32]),
        prepared_provider_request_digest(payload),
        payload,
    )
    .map_err(|_| "request binding failed")?;
    let permit = EffectPermitV2 {
        execution_nonce: Nonce32V2::new([0x51; 32]),
        dispatch_core_digest: Digest32V2::new([0x52; 32]),
        dispatch_subject_digest: Digest32V2::new([0x53; 32]),
    };
    transport
        .execute(
            &request,
            &permit,
            4_096,
            Instant::now() + Duration::from_secs(3),
        )
        .map_err(|_| "provider request failed")
}

fn fixture_bytes(name: &str) -> Vec<u8> {
    let prefix = format!("{name}=");
    let encoded = include_str!("../tests/fixtures/provider-tls-v2.hex")
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .expect("fixture entry");
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
