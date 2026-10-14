// Included in daemon::native::kernel_approval_startup_tests. Loopback-only test
// sockets and signed fixtures; no hardware authentication is simulated as real.
fn private_http_exchange(authority: Arc<ApprovalUiAuthorityV2>, bytes: Vec<u8>) -> Vec<u8> {
    use std::io::{Read as _, Write as _};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let worker = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        serve_http_stream_with_clock(stream, authority, || Ok(UnixMillisV2::new(201))).unwrap();
    });
    let mut client = TcpStream::connect(address).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    client.write_all(&bytes).unwrap();
    let mut response = Vec::new();
    match client.read_to_end(&mut response) {
        Ok(_) => (),
        Err(error) => assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset),
    }
    worker.join().unwrap();
    response
}

fn private_http_request(origin: &str, path: &str, token: &str) -> Vec<u8> {
    let body = format!("transfer={token}");
    format!("POST {path} HTTP/1.1\r\nHost: localhost:8766\r\nOrigin: {origin}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{body}", body.len()).into_bytes()
}

#[test]
fn private_http_handoff_reaches_only_pre_authentication_and_is_never_reflected() {
    use crate::ui_authority::approval_delivery_tests::{directory, open, Anchor};
    use savana_kernel_protocol::v2::RegisteredApprovalV2;
    let root = directory();
    let authority = Arc::new(open(root.path(), Anchor::default()));
    let (approval, display) = crate::protocol_service::tests::kernel_delivery_pair(true);
    let RegisteredApprovalV2::Tool {
        display_authentication: transfer,
        ..
    } = authority
        .register_approval(
            EndpointRoleV2::KernelApproval,
            approval,
            display,
            UnixMillisV2::new(200),
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap()
    else {
        panic!("tool approval")
    };
    let encoded = minicbor::to_vec(transfer).unwrap();
    let token = URL_SAFE_NO_PAD.encode(minicbor::Decoder::new(&encoded).bytes().unwrap());
    let response = private_http_exchange(
        authority.clone(),
        private_http_request(
            "http://localhost:8766",
            "/v04/private-approval/accept",
            &token,
        ),
    );
    let response = String::from_utf8(response).unwrap();
    assert!(response.starts_with("HTTP/1.1 200 OK"));
    assert!(response.contains("Cache-Control: no-store"));
    assert!(response.contains("Referrer-Policy: no-referrer"));
    assert!(response.contains("frame-ancestors 'none'"));
    assert!(response.contains("data-purpose=\"approval-display\""));
    assert!(response.contains("User verification required"));
    assert!(!response.contains(&token));
    assert!(!response.contains("Send exact private item"));
    assert!(authority
        .accept_approval_display_transfer(transfer)
        .is_err());

    // Origin is necessary but not sufficient: even a valid private transfer
    // cannot enter through a public Agent/Ingress bootstrap.
    for origin in [
        "http://localhost:8765",
        "http://localhost:8767",
        "http://localhost:8768",
    ] {
        assert!(private_http_exchange(
            authority.clone(),
            private_http_request(origin, "/v04/private-approval/accept", &token,)
        )
        .is_empty());
    }
}

#[test]
fn private_http_invalid_handoffs_have_one_bounded_response() {
    use crate::ui_authority::approval_delivery_tests::{directory, open, Anchor};
    let root = directory();
    let authority = Arc::new(open(root.path(), Anchor::default()));
    let mut expected = None;
    for token in [
        "not-a-token".to_owned(),
        URL_SAFE_NO_PAD.encode([0; 32]),
        URL_SAFE_NO_PAD.encode([0xee; 32]),
    ] {
        let response = private_http_exchange(
            authority.clone(),
            private_http_request(
                "http://localhost:8766",
                "/v04/private-approval/accept",
                &token,
            ),
        );
        assert!(response.starts_with(b"HTTP/1.1 400 Bad Request"));
        if let Some(previous) = expected.as_ref() {
            assert_eq!(&response, previous);
        }
        expected = Some(response);
    }
    let landing = private_http_exchange(
        authority,
        b"GET /v04/private-approval HTTP/1.1\r\nHost: localhost:8766\r\n\r\n".to_vec(),
    );
    assert!(landing.starts_with(b"HTTP/1.1 200 OK"));
    assert!(!String::from_utf8(landing).unwrap().contains("pending task"));
}
