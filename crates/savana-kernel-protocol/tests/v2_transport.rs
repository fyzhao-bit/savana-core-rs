use ed25519_dalek::SigningKey;
use savana_kernel_protocol::v2::{
    decode_kernel_service_application_request_v2, decode_kernel_service_application_response_v2,
    derive_ed25519_key_id_v2, encode_kernel_service_application_request_v2,
    encode_kernel_service_application_response_v2, peek_kernel_service_application_request_v2,
    BootIdV2, Digest32V2, EndpointRoleV2, KernelServiceApplicationRequestV2,
    KernelServiceApplicationResponseV2, KernelServiceHandshakeEdgeV2, KernelServiceOperationV2,
    Nonce32V2, PeerIdentityBindingV2, PublicStableCodeV2, RequestIdV2, ServiceIdentityV2,
    UnixMillisV2, V2ClientHandshake, V2ServerHandshake,
};
use x25519_dalek::StaticSecret;

fn edge(client_key: &SigningKey, server_key: &SigningKey) -> KernelServiceHandshakeEdgeV2 {
    KernelServiceHandshakeEdgeV2::from_verified_deployment(
        EndpointRoleV2::AgentKernel,
        Digest32V2::new([1; 32]),
        ServiceIdentityV2::new([2; 32]),
        ServiceIdentityV2::new([3; 32]),
        derive_ed25519_key_id_v2(client_key.verifying_key().to_bytes()),
        derive_ed25519_key_id_v2(server_key.verifying_key().to_bytes()),
        BootIdV2::new([4; 32]),
        5,
        Digest32V2::new([6; 32]),
        7,
        8,
        Digest32V2::new([9; 32]),
        Digest32V2::new([10; 32]),
        Digest32V2::new([11; 32]),
        Digest32V2::new([12; 32]),
        Digest32V2::new([13; 32]),
        Digest32V2::new([14; 32]),
    )
    .unwrap()
}

#[test]
fn exact_suite_one_handshake_confirms_both_sides_and_encrypts_one_request_response() {
    let client_key = SigningKey::from_bytes(&[0x21; 32]);
    let server_key = SigningKey::from_bytes(&[0x22; 32]);
    let edge = edge(&client_key, &server_key);
    let (client_pending, client_hello) = V2ClientHandshake::start(
        edge,
        BootIdV2::new([0x23; 32]),
        Nonce32V2::new([0x24; 32]),
        PeerIdentityBindingV2::macos(
            [0x26; 32],
            501,
            502,
            "com.example.agentd".to_owned(),
            "TEAM123".to_owned(),
            Digest32V2::new([0x27; 32]),
        )
        .unwrap(),
        StaticSecret::from([0x25; 32]),
        &client_key,
    )
    .unwrap();
    assert_eq!(&client_hello[..8], b"SAVANA2\0");

    let observed = PeerIdentityBindingV2::macos(
        [0x26; 32],
        501,
        502,
        "com.example.agentd".to_owned(),
        "TEAM123".to_owned(),
        Digest32V2::new([0x27; 32]),
    )
    .unwrap();
    let (server_pending, server_hello) = V2ServerHandshake::accept_client_hello(
        edge,
        observed.clone(),
        &client_hello,
        Nonce32V2::new([0x28; 32]),
        StaticSecret::from([0x29; 32]),
        client_key.verifying_key().to_bytes(),
        &server_key,
    )
    .unwrap();
    let (client_finish, mut client_session) = client_pending
        .accept_server_hello(
            &server_hello,
            server_key.verifying_key().to_bytes(),
            &client_key,
        )
        .unwrap();
    let (accepted, mut server_session, peer) =
        server_pending.accept_client_finish(&client_finish).unwrap();
    assert_eq!(peer.role(), EndpointRoleV2::AgentKernel);
    assert_eq!(peer.client_boot_id(), BootIdV2::new([0x23; 32]));
    assert_eq!(peer.observed_client_peer(), &observed);
    let mut changed_accepted = accepted.clone();
    *changed_accepted.last_mut().unwrap() ^= 1;
    assert!(client_session
        .accept_server_confirmation(&changed_accepted)
        .is_err());
    client_session
        .accept_server_confirmation(&accepted)
        .unwrap();

    let request_id = RequestIdV2::new([0x2a; 16]);
    let mut request_plaintext = vec![0x58, 0x20];
    request_plaintext.extend_from_slice(&[0xab; 32]);
    let request = client_session
        .seal_application_request(request_id, 29, &request_plaintext)
        .unwrap();
    assert!(!request
        .windows(request_plaintext.len())
        .any(|window| window == request_plaintext));
    let mut changed_request = request.clone();
    *changed_request.last_mut().unwrap() ^= 1;
    assert!(server_session
        .open_application_request(&changed_request)
        .is_err());
    let opened = server_session.open_application_request(&request).unwrap();
    assert_eq!(opened.request_id(), request_id);
    assert_eq!(opened.operation_tag(), 29);
    assert_eq!(opened.plaintext(), request_plaintext);
    assert!(server_session.open_application_request(&request).is_err());

    let failed = server_session
        .prepare_application_response(RequestIdV2::new([0x2b; 16]), 29, &[0x81, 0x01])
        .unwrap_err();
    let (server_session, _) = failed.into_parts();
    let staged = server_session
        .prepare_application_response(request_id, 29, &[0x81, 0x01])
        .unwrap();
    let server_session = staged.rollback();
    let response = server_session
        .prepare_application_response(request_id, 29, &[0x81, 0x01])
        .unwrap()
        .commit();
    let mut changed_response = response.clone();
    *changed_response.last_mut().unwrap() ^= 1;
    assert!(client_session
        .open_application_response(&changed_response)
        .is_err());
    let opened = client_session.open_application_response(&response).unwrap();
    assert_eq!(opened.request_id(), request_id);
    assert_eq!(opened.operation_tag(), 29);
    assert_eq!(opened.plaintext(), &[0x81, 0x01]);
    assert!(client_session.open_application_response(&response).is_err());
}

#[test]
fn prefix_role_transcript_signature_confirm_and_record_tampering_fail_closed() {
    let client_key = SigningKey::from_bytes(&[0x31; 32]);
    let server_key = SigningKey::from_bytes(&[0x32; 32]);
    let edge = edge(&client_key, &server_key);
    let (client_pending, hello) = V2ClientHandshake::start(
        edge,
        BootIdV2::new([0x33; 32]),
        Nonce32V2::new([0x34; 32]),
        PeerIdentityBindingV2::linux(501, 502, 503, 504, Digest32V2::new([0x36; 32])).unwrap(),
        StaticSecret::from([0x35; 32]),
        &client_key,
    )
    .unwrap();
    let observed =
        PeerIdentityBindingV2::linux(501, 502, 503, 504, Digest32V2::new([0x36; 32])).unwrap();
    let mut wrong_role = hello.clone();
    wrong_role[14] = EndpointRoleV2::IngressKernel.tag() as u8;
    assert!(V2ServerHandshake::accept_client_hello(
        edge,
        observed.clone(),
        &wrong_role,
        Nonce32V2::new([0x37; 32]),
        StaticSecret::from([0x38; 32]),
        client_key.verifying_key().to_bytes(),
        &server_key,
    )
    .is_err());

    let (_server_pending, server_hello) = V2ServerHandshake::accept_client_hello(
        edge,
        observed,
        &hello,
        Nonce32V2::new([0x37; 32]),
        StaticSecret::from([0x38; 32]),
        client_key.verifying_key().to_bytes(),
        &server_key,
    )
    .unwrap();
    let mut changed_hello = server_hello.clone();
    *changed_hello.last_mut().unwrap() ^= 1;
    assert!(client_pending
        .accept_server_hello(
            &changed_hello,
            server_key.verifying_key().to_bytes(),
            &client_key,
        )
        .is_err());

    let (client_pending, hello) = V2ClientHandshake::start(
        edge,
        BootIdV2::new([0x33; 32]),
        Nonce32V2::new([0x39; 32]),
        PeerIdentityBindingV2::linux(501, 502, 503, 504, Digest32V2::new([0x36; 32])).unwrap(),
        StaticSecret::from([0x3a; 32]),
        &client_key,
    )
    .unwrap();
    let (server_pending, server_hello) = V2ServerHandshake::accept_client_hello(
        edge,
        PeerIdentityBindingV2::linux(501, 502, 503, 504, Digest32V2::new([0x36; 32])).unwrap(),
        &hello,
        Nonce32V2::new([0x3b; 32]),
        StaticSecret::from([0x3c; 32]),
        client_key.verifying_key().to_bytes(),
        &server_key,
    )
    .unwrap();
    let (mut finish, _) = client_pending
        .accept_server_hello(
            &server_hello,
            server_key.verifying_key().to_bytes(),
            &client_key,
        )
        .unwrap();
    *finish.last_mut().unwrap() ^= 1;
    assert!(server_pending.accept_client_finish(&finish).is_err());
}

#[test]
fn key_ids_are_family_separated_full_sha256_digests() {
    let public = SigningKey::from_bytes(&[0x41; 32])
        .verifying_key()
        .to_bytes();
    let id = derive_ed25519_key_id_v2(public);
    let mut input = b"savana.ed25519-key-id.v2\0".to_vec();
    input.extend_from_slice(&public);
    use sha2::Digest as _;
    assert_eq!(
        id.as_bytes(),
        &<[u8; 32]>::from(sha2::Sha256::digest(input))
    );
}

#[test]
fn exact_application_codec_binds_operation_and_enforces_public_error_sets() {
    let request_id = RequestIdV2::new([0x51; 16]);
    let operation = KernelServiceOperationV2::agent(
        savana_kernel_protocol::v2::KernelAgentOperationV2::DispatchExecution(
            savana_kernel_protocol::v2::DispatchExecutionRequestV2::new(
                savana_kernel_protocol::v2::ExecutionTicketHandleV2::from_authority_entropy(
                    [0x52; 32],
                )
                .unwrap(),
            ),
        ),
    );
    let request = KernelServiceApplicationRequestV2::new(
        EndpointRoleV2::AgentKernel,
        request_id,
        UnixMillisV2::new(1_800_000_000_000),
        operation,
    )
    .unwrap();
    let encoded = encode_kernel_service_application_request_v2(&request).unwrap();
    let routing = peek_kernel_service_application_request_v2(&encoded).unwrap();
    assert_eq!(routing.role(), EndpointRoleV2::AgentKernel);
    assert_eq!(routing.request_id(), request_id);
    assert_eq!(routing.operation_tag(), 29);
    assert_eq!(
        encode_kernel_service_application_request_v2(
            &decode_kernel_service_application_request_v2(&encoded).unwrap()
        )
        .unwrap(),
        encoded
    );
    let mut malformed_body = encoded.clone();
    let body_array_position = malformed_body.len() - 35;
    malformed_body[body_array_position] = 0x80;
    assert_eq!(
        peek_kernel_service_application_request_v2(&malformed_body)
            .unwrap()
            .operation_tag(),
        29
    );
    assert!(decode_kernel_service_application_request_v2(&malformed_body).is_err());
    let mut trailing = encoded;
    trailing.push(0);
    assert!(decode_kernel_service_application_request_v2(&trailing).is_err());

    let response = KernelServiceApplicationResponseV2::error(
        EndpointRoleV2::AgentKernel,
        request_id,
        29,
        PublicStableCodeV2::ExecutionIndeterminate,
    )
    .unwrap();
    let encoded = encode_kernel_service_application_response_v2(&response).unwrap();
    assert_eq!(
        decode_kernel_service_application_response_v2(&encoded, EndpointRoleV2::AgentKernel, 29,)
            .unwrap(),
        response
    );
    assert!(KernelServiceApplicationResponseV2::error(
        EndpointRoleV2::AgentKernel,
        request_id,
        22,
        PublicStableCodeV2::ExecutionIndeterminate,
    )
    .is_err());
}
