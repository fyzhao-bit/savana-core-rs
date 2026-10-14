use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use savana_execd::openclaw_release_test_support::{execute_release_fixture_v2, tls_fixture_v2};
use savana_openclaw_release::{
    ReleaseReceiver, ReleaseReceiverConfig, ReleaseReceiverError, ReleaseReservationStore,
    FINAL_RELEASE_PATH, RELEASE_ALPN_PROTOCOL,
};
use tempfile::tempdir;

fn config(expected_client_spki_pin: [u8; 32]) -> ReleaseReceiverConfig {
    let fixture = tls_fixture_v2();
    ReleaseReceiverConfig::new(
        "provider.example",
        fixture.ca_certificate_der,
        vec![fixture.server_certificate_der],
        fixture.server_private_key_der,
        expected_client_spki_pin,
    )
    .unwrap()
}

#[test]
fn execd_verified_transport_delivers_only_after_mtls_and_durable_claim() {
    let fixture = tls_fixture_v2();
    let directory = tempdir().unwrap();
    let store =
        Arc::new(ReleaseReservationStore::open(directory.path().join("release.cbor")).unwrap());
    let reservation = store.reserve([0x91; 32], 10, 10_000).unwrap();
    let receiver = ReleaseReceiver::bind(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        config(fixture.expected_client_spki_pin),
        Arc::clone(&store),
    )
    .unwrap();
    assert!(receiver.local_addr().ip().is_loopback());
    assert_eq!(
        receiver.canonical_url(),
        format!(
            "https://provider.example:{}{FINAL_RELEASE_PATH}",
            receiver.local_addr().port()
        )
    );
    let address = receiver.local_addr();
    let canonical_url = receiver.canonical_url().to_owned();
    use savana_kernel_protocol::v2::*;
    let profile =
        final_release_business_profile_v2(Digest32V2::new([1; 32]), Digest32V2::new([2; 32]))
            .unwrap();
    let business = final_release_business_request_v2(
        &profile,
        "release-transport-1",
        Digest32V2::new([3; 32]),
        Digest32V2::new([0x91; 32]),
        b"released through real execd transport",
    )
    .unwrap();
    let server =
        thread::spawn(move || receiver.accept_one(11, Instant::now() + Duration::from_secs(3)));

    let client_result = execute_release_fixture_v2(
        address,
        &canonical_url,
        &business.canonical_json(),
        RELEASE_ALPN_PROTOCOL,
    );
    let server_result = server.join().unwrap();
    assert!(
        client_result.is_ok() && server_result.is_ok(),
        "client={client_result:?}, server={server_result:?}"
    );
    let acknowledgement = client_result.unwrap();
    assert_eq!(
        business.classify_response(&acknowledgement).unwrap(),
        BusinessResponseDispositionV2::Succeeded
    );

    let delivery = store.read_delivery(&reservation).unwrap();
    assert_eq!(delivery.turn_binding(), &[0x91; 32]);
    assert_eq!(delivery.payload(), b"released through real execd transport");
}

#[test]
fn receiver_rejects_non_loopback_binding_and_wrong_client_pin() {
    let fixture = tls_fixture_v2();
    let directory = tempdir().unwrap();
    let store =
        Arc::new(ReleaseReservationStore::open(directory.path().join("release.cbor")).unwrap());
    assert_eq!(
        ReleaseReceiver::bind(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            config(fixture.expected_client_spki_pin),
            Arc::clone(&store),
        )
        .unwrap_err(),
        ReleaseReceiverError::InvalidConfig
    );

    let reservation = store.reserve([0x92; 32], 10, 10_000).unwrap();
    let receiver = ReleaseReceiver::bind(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        config([0xa5; 32]),
        Arc::clone(&store),
    )
    .unwrap();
    let address = receiver.local_addr();
    let canonical_url = receiver.canonical_url().to_owned();
    let server =
        thread::spawn(move || receiver.accept_one(11, Instant::now() + Duration::from_secs(3)));
    let client_result = execute_release_fixture_v2(
        address,
        &canonical_url,
        b"must not be claimed",
        RELEASE_ALPN_PROTOCOL,
    );
    let server_result = server.join().unwrap();
    assert!(client_result.is_err());
    assert_eq!(
        server_result.unwrap_err(),
        ReleaseReceiverError::UnauthorizedClient
    );
    assert!(store.read_delivery(&reservation).is_err());
}

#[test]
fn authenticated_transport_cannot_deliver_another_turn_or_legacy_body() {
    use savana_kernel_protocol::v2::*;
    let profile =
        final_release_business_profile_v2(Digest32V2::new([1; 32]), Digest32V2::new([2; 32]))
            .unwrap();
    let cross = final_release_business_request_v2(
        &profile,
        "release-cross",
        Digest32V2::new([3; 32]),
        Digest32V2::new([0x95; 32]),
        b"not this turn",
    )
    .unwrap();
    for body in [cross.canonical_json(), b"legacy raw response".to_vec()] {
        let fixture = tls_fixture_v2();
        let dir = tempdir().unwrap();
        let store =
            Arc::new(ReleaseReservationStore::open(dir.path().join("release.cbor")).unwrap());
        let reservation = store.reserve([0x94; 32], 10, 10000).unwrap();
        let receiver = ReleaseReceiver::bind(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            config(fixture.expected_client_spki_pin),
            Arc::clone(&store),
        )
        .unwrap();
        let address = receiver.local_addr();
        let url = receiver.canonical_url().to_owned();
        let server =
            thread::spawn(move || receiver.accept_one(11, Instant::now() + Duration::from_secs(3)));
        assert!(execute_release_fixture_v2(address, &url, &body, RELEASE_ALPN_PROTOCOL).is_err());
        assert!(server.join().unwrap().is_err());
        assert!(store.read_delivery(&reservation).is_err());
    }
}

#[test]
fn receiver_rejects_alpn_or_canonical_route_mismatch_before_claim() {
    let fixture = tls_fixture_v2();
    for wrong_url in [false, true] {
        let directory = tempdir().unwrap();
        let store =
            Arc::new(ReleaseReservationStore::open(directory.path().join("release.cbor")).unwrap());
        let reservation = store.reserve([0x93; 32], 10, 10_000).unwrap();
        let receiver = ReleaseReceiver::bind(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            config(fixture.expected_client_spki_pin),
            Arc::clone(&store),
        )
        .unwrap();
        let address = receiver.local_addr();
        let canonical_url = if wrong_url {
            format!("https://provider.example:{}/wrong", address.port())
        } else {
            receiver.canonical_url().to_owned()
        };
        let alpn = if wrong_url {
            RELEASE_ALPN_PROTOCOL
        } else {
            b"wrong-provider-v2"
        };
        let server =
            thread::spawn(move || receiver.accept_one(11, Instant::now() + Duration::from_secs(3)));
        assert!(
            execute_release_fixture_v2(address, &canonical_url, b"must not be claimed", alpn,)
                .is_err()
        );
        assert!(server.join().unwrap().is_err());
        assert!(store.read_delivery(&reservation).is_err());
    }
}
