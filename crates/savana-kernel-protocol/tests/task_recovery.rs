use savana_kernel_protocol::v2::*;

#[test]
fn recovery_wire_is_closed_and_names_existing_issuance_without_draft_or_session() {
    let auth = IngressUiAuthorizationHandleV2::from_authority_entropy([1; 32]).unwrap();
    let digest = Digest32V2::new([2; 32]);
    assert!(RecoverTaskAuthorizationRequestV2::new(auth, Digest32V2::new([0; 32])).is_err());
    let operation = KernelIngressOperationV2::RecoverTaskAuthorization(
        RecoverTaskAuthorizationRequestV2::new(auth, digest).unwrap(),
    );
    let bytes = encode_kernel_ingress_operation_v2(&operation).unwrap();
    assert_eq!(operation.tag(), 55);
    assert_eq!(&bytes[..6], &[0x82, 0x18, 55, 0x82, 0x58, 32]);
    let decoded = decode_kernel_ingress_operation_v2(&bytes).unwrap();
    assert_eq!(encode_kernel_ingress_operation_v2(&decoded).unwrap(), bytes);
    for length in 0..bytes.len() {
        assert!(decode_kernel_ingress_operation_v2(&bytes[..length]).is_err());
    }
    let mut trailing = bytes;
    trailing.push(0);
    assert!(decode_kernel_ingress_operation_v2(&trailing).is_err());

    let response = RecoverTaskAuthorizationResponseV2::Installed(
        EstablishTaskAuthorizationResponseV2::new(digest, Digest32V2::new([3; 32])).unwrap(),
    );
    let bytes = encode_recover_task_authorization_response_v2(&response).unwrap();
    assert_eq!(
        encode_recover_task_authorization_response_v2(
            &decode_recover_task_authorization_response_v2(&bytes).unwrap()
        )
        .unwrap(),
        bytes
    );
    for length in 0..bytes.len() {
        assert!(decode_recover_task_authorization_response_v2(&bytes[..length]).is_err());
    }
    for tag in [0, 3, 23] {
        let mut bad = bytes.clone();
        bad[1] = tag;
        assert!(decode_recover_task_authorization_response_v2(&bad).is_err());
    }
    let mut bad = bytes;
    bad.push(0);
    assert!(decode_recover_task_authorization_response_v2(&bad).is_err());

    let browser = IngressBrowserRequestV2::RecoverTaskAuthorization {
        tab: IngressTabSessionCapabilityV2::from_authority_entropy([4; 32]).unwrap(),
        client_request_nonce: Nonce32V2::new([5; 32]),
        request_digest: digest,
    };
    let bytes = encode_ingress_browser_request_v2(&browser).unwrap();
    assert_eq!(bytes[..2], [0x84, 9]);
    assert_eq!(
        encode_ingress_browser_request_v2(&decode_ingress_browser_request_v2(&bytes).unwrap())
            .unwrap(),
        bytes
    );
    for length in 0..bytes.len() {
        assert!(decode_ingress_browser_request_v2(&bytes[..length]).is_err());
    }
    let mut bad = bytes.clone();
    let length = bad.len();
    bad[length - 32..].fill(0);
    assert!(decode_ingress_browser_request_v2(&bad).is_err());
    let mut bad = bytes;
    bad.push(0);
    assert!(decode_ingress_browser_request_v2(&bad).is_err());
}
