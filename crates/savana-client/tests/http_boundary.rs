mod support;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use savana_client::{
    parse_fixed_http_response, BrowserContentType, BrowserOrigin, BrowserRequest, BrowserRoute,
    BrowserService, ClientEndpoints,
};

const LOOPBACK_PEER: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8768);

fn raw_response(content_type: &str, body: &[u8]) -> Vec<u8> {
    let mut response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    response.extend_from_slice(body);
    response
}

fn valid_agent_action() -> BrowserRequest {
    BrowserRequest {
        service: BrowserService::Agent,
        route: BrowserRoute::AgentAction,
        origin: BrowserOrigin::Agent,
        content_type: BrowserContentType::CanonicalCbor,
        body: vec![0x81, 0x01],
    }
}

#[test]
fn endpoint_set_accepts_only_the_three_fixed_loopback_http_services() {
    assert!(ClientEndpoints::new(
        "http://localhost:8768",
        "http://localhost:8767",
        "http://localhost:8766",
    )
    .is_ok());
    assert!(ClientEndpoints::new(
        "http://127.0.0.1:8768",
        "http://127.0.0.1:8767",
        "http://127.0.0.1:8766",
    )
    .is_ok());

    for invalid_agent in [
        "http://example.com:8768",
        "https://localhost:8768",
        "http://localhost:8767",
        "http://localhost:8768/extra",
        "http://127.1:8768",
        "http://0x7f000001:8768",
        "http://0177.0.0.1:8768",
        "http://2130706433:8768",
        "http://localhost:8768/",
        "http://localhost:8768?query",
        "http://user@localhost:8768",
    ] {
        assert!(
            ClientEndpoints::new(
                invalid_agent,
                "http://localhost:8767",
                "http://localhost:8766",
            )
            .is_err(),
            "accepted non-allowlisted endpoint: {invalid_agent}"
        );
    }
}

#[test]
fn request_tuple_must_match_the_closed_route_surface() {
    let valid = valid_agent_action();
    assert!(valid.validate().is_ok());

    for invalid in [
        BrowserRequest {
            service: BrowserService::Ingress,
            ..valid_agent_action()
        },
        BrowserRequest {
            origin: BrowserOrigin::Approval,
            ..valid_agent_action()
        },
        BrowserRequest {
            content_type: BrowserContentType::FormUrlEncoded,
            ..valid_agent_action()
        },
    ] {
        assert!(invalid.validate().is_err());
    }
}

#[test]
fn strict_response_parser_accepts_only_exact_fixed_http() {
    let body = [0x81, 0x01];
    let parsed = parse_fixed_http_response(
        LOOPBACK_PEER,
        BrowserContentType::CanonicalCbor,
        &raw_response("application/cbor", &body),
    )
    .unwrap();
    assert_eq!(parsed.content_type(), BrowserContentType::CanonicalCbor);
    assert_eq!(parsed.body(), body);

    let rejected = [
        b"HTTP/1.1 307 Temporary Redirect\r\nLocation: http://localhost:8768/v2/agent/action\r\nContent-Type: application/cbor\r\nContent-Length: 1\r\nConnection: close\r\n\r\nx".as_slice(),
        b"HTTP/1.1 200 OK\r\nContent-Type: application/cbor\r\nContent-Length: 1\r\nContent-Length: 1\r\nConnection: close\r\n\r\nx".as_slice(),
        b"HTTP/1.1 200 OK\r\nContent-Type: application/cbor\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n1\r\nx\r\n0\r\n\r\n".as_slice(),
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 1\r\nConnection: close\r\n\r\nx".as_slice(),
        b"HTTP/1.1 200 OK\r\nContent-Type: application/cbor\r\nContent-Length: 8388609\r\nConnection: close\r\n\r\n".as_slice(),
        b"HTTP/1.1 200 OK\r\nContent-Type: application/cbor\r\nContent-Length: 1\r\nConnection: close\r\n\r\nxy".as_slice(),
        b"HTTP/1.1 200 OK\r\nContent-Type: application/cbor\r\nContent-Length: 1\r\nProxy-Authenticate: Basic\r\nConnection: close\r\n\r\nx".as_slice(),
    ];
    for response in rejected {
        assert!(parse_fixed_http_response(
            LOOPBACK_PEER,
            BrowserContentType::CanonicalCbor,
            response,
        )
        .is_err());
    }
}

#[test]
fn response_parser_rejects_a_non_loopback_connected_peer() {
    let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 8768);
    assert!(parse_fixed_http_response(
        peer,
        BrowserContentType::CanonicalCbor,
        &raw_response("application/cbor", &[0x80]),
    )
    .is_err());
}
