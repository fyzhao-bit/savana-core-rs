use super::*;
use crate::ui_authority::approval_delivery_tests::{directory, open, Anchor};
use savana_kernel_protocol::v2::{derive_ed25519_key_id_v2, ServiceIdentityV2};
use std::{os::unix::net::UnixListener, sync::Arc};

// Actual framed/encrypted UDS transport. The native listener's measured peer is
// supplied by a test fixture; this does not attest Linux/systemd deployment.
#[test]
fn kernel_delivery_round_trips_over_suite_one_and_rejects_agent_handshake() {
    let root = directory();
    let authority = Arc::new(open(root.path(), Anchor::default()));
    let key = SigningKey::from_bytes(&[0xc1; 32]);
    let server_key = SigningKey::from_bytes(&[0xc2; 32]);
    let public = server_key.verifying_key().to_bytes();
    let edge_for = |role| {
        KernelServiceHandshakeEdgeV2::from_verified_deployment(
            role,
            Digest32V2::new([0x74; 32]),
            ServiceIdentityV2::new([0xc3; 32]),
            ServiceIdentityV2::new([0x77; 32]),
            derive_ed25519_key_id_v2(key.verifying_key().to_bytes()),
            derive_ed25519_key_id_v2(public),
            BootIdV2::new([0xc4; 32]),
            1,
            Digest32V2::new([0x75; 32]),
            9,
            1,
            Digest32V2::new([1; 32]),
            Digest32V2::new([2; 32]),
            Digest32V2::new([3; 32]),
            Digest32V2::new([4; 32]),
            Digest32V2::new([5; 32]),
            Digest32V2::new([6; 32]),
        )
        .unwrap()
    };
    let edge = edge_for(EndpointRoleV2::KernelApproval);
    let peer = PeerIdentityBindingV2::linux(501, 502, 503, 504, Digest32V2::new([7; 32])).unwrap();
    let server = crate::ApprovalSuiteOneServerV2::new(
        edge,
        key.verifying_key().to_bytes(),
        server_key,
        32,
        authority,
    )
    .unwrap();
    let socket = root.path().join("kernel.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let observed = peer.clone();
    let worker = std::thread::spawn(move || {
        (0..12)
            .map(|_| {
                let (stream, _) = listener.accept().unwrap();
                server
                    .serve_stream(
                        stream,
                        observed.clone(),
                        UnixMillisV2::new(200),
                        Instant::now() + Duration::from_secs(5),
                    )
                    .is_ok()
            })
            .collect::<Vec<_>>()
    });
    let mut client = ApprovalSuiteOneClientV2::from_verified_deployment(
        edge,
        BootIdV2::new([8; 32]),
        peer.clone(),
        key.clone(),
        public,
    )
    .unwrap();
    assert_eq!(
        client.socket_path,
        PathBuf::from(KERNEL_APPROVAL_SOCKET_PATH_V2)
    );
    client.socket_path = socket.clone(); // Only a cfg(test) child can override it.
    let deadline = || {
        UnixMillisV2::new(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64
                + 4_000,
        )
    };
    client.health(deadline()).unwrap();
    let (envelope, display) = crate::protocol_service::tests::kernel_delivery_pair(true);
    let registered = client
        .register_approval(envelope, display, deadline())
        .unwrap();
    let RegisteredApprovalV2::Tool { approval, .. } = registered else {
        panic!("tool")
    };
    assert_eq!(
        client
            .get_kernel_approval_settlement(approval, deadline())
            .unwrap(),
        ApprovalSettlementViewV2::Pending
    );
    // A well-formed unknown capability returns a typed, encrypted rejection.
    let unknown =
        savana_kernel_protocol::v2::ToolApprovalRecordHandleV2::from_authority_entropy([9; 32])
            .unwrap();
    assert!(matches!(
        client.get_kernel_approval_settlement(unknown, deadline()),
        Err(ApprovalSuiteOneClientErrorV2::Rejected(_))
    ));
    use savana_kernel_protocol::v2::{
        DurableRunIdV2, DurableTaskIdV2, FixedOriginV2, PrincipalIdV2, UiAuthenticationBindingV2,
        UiAuthenticationPurposeV2, UnsignedUiAuthenticationEnvelopeV2,
    };
    let session_envelope = SignedUiAuthenticationEnvelopeV2::sign(
        UnsignedUiAuthenticationEnvelopeV2::new(
            Digest32V2::new([0x74; 32]),
            Digest32V2::new([0x75; 32]),
            9,
            UiAuthenticationPurposeV2::PrivateSessionV04,
            UiAuthenticationBindingV2::PrivateSessionV04 {
                durable_task_id: DurableTaskIdV2::new([0xa4; 32]),
                durable_run_id: DurableRunIdV2::new([0xc5; 32]),
                task_authorization_digest: Digest32V2::new([0xc6; 32]),
                kerneld_boot_id: BootIdV2::new([8; 32]),
            },
            Some(PrincipalIdV2::new([0xa6; 32])),
            FixedOriginV2::Approval8766,
            FixedOriginV2::Approval8766,
            Nonce32V2::new([0xc7; 32]),
            UnixMillisV2::new(100),
            UnixMillisV2::new(1000),
        )
        .unwrap(),
        &SigningKey::from_bytes(&[0x71; 32]),
    )
    .unwrap();
    let session = client
        .register_private_session_v04(session_envelope, deadline())
        .unwrap();
    assert!(client
        .private_session_authentication_v04(session.record, deadline())
        .unwrap()
        .is_none());
    // No authentication ceremony has completed, so attaching a tool cannot log
    // in the consumer or turn an operator connection into an approval.
    assert!(matches!(
        client.attach_private_approval_v04(
            session.record,
            approval,
            Digest32V2::new([0xc6; 32]),
            deadline()
        ),
        Err(ApprovalSuiteOneClientErrorV2::Rejected(_))
    ));
    let (envelope, display) = crate::protocol_service::tests::kernel_release_delivery_pair(true);
    let RegisteredApprovalV2::Release { approval, .. } = client
        .register_approval(envelope, display, deadline())
        .unwrap()
    else {
        panic!("release")
    };
    assert_eq!(
        client
            .get_kernel_release_approval_settlement(approval, deadline())
            .unwrap(),
        ApprovalSettlementViewV2::Pending
    );
    let unknown_release =
        savana_kernel_protocol::v2::ReleaseApprovalRecordHandleV2::from_authority_entropy(
            [0xff; 32],
        )
        .unwrap();
    assert!(matches!(
        client.get_kernel_release_approval_settlement(unknown_release, deadline()),
        Err(ApprovalSuiteOneClientErrorV2::Rejected(_))
    ));
    assert!(matches!(
        client.attach_private_release_approval_v04(
            session.record,
            approval,
            Digest32V2::new([0xc6; 32]),
            deadline()
        ),
        Err(ApprovalSuiteOneClientErrorV2::Rejected(_))
    ));
    let mut wrong = ApprovalSuiteOneClientV2::from_verified_deployment(
        edge_for(EndpointRoleV2::AgentApproval),
        BootIdV2::new([8; 32]),
        peer,
        key,
        public,
    )
    .unwrap();
    wrong.socket_path = socket;
    assert!(wrong.health(deadline()).is_err());
    assert_eq!(
        worker.join().unwrap(),
        vec![true, true, true, true, true, true, true, true, true, true, true, false]
    );
}
