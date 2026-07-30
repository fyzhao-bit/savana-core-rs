use ed25519_dalek::SigningKey;
use savana_kernel_protocol::v2::{
    decode_kernel_service_request_envelope_v2, encode_kernel_service_request_envelope_v2,
    sign_kernel_service_response_envelope_v2, verify_kernel_service_response_envelope_v2,
    AbortInputRequestV2, BootIdV2, Digest32V2, DispatchExecutionRequestV2, Ed25519KeyIdV2,
    EndpointRoleV2, ExecutionTicketHandleV2, InputSessionHandleV2, KernelAgentOperationV2,
    KernelExecutorOperationV2, KernelIngressOperationV2, KernelServiceOperationV2,
    KernelServiceRequestEnvelopeV2, KernelServiceResponseEnvelopeV2, KernelServiceResponseV2,
    Nonce32V2, QueryByExecutionNonceRequestV2, RequestIdV2, ServiceIdentityV2, UnixMillisV2,
};
use savana_kernel_protocol::StableCode;

fn request(role: EndpointRoleV2, tag: u16) -> KernelServiceRequestEnvelopeV2 {
    KernelServiceRequestEnvelopeV2::from_authenticated_connection(
        role,
        RequestIdV2::new([1; 16]),
        BootIdV2::new([2; 32]),
        BootIdV2::new([3; 32]),
        ServiceIdentityV2::new([4; 32]),
        ServiceIdentityV2::new([5; 32]),
        Digest32V2::new([6; 32]),
        7,
        UnixMillisV2::new(1_000),
        operation(role, tag),
    )
    .unwrap()
}

fn operation(role: EndpointRoleV2, tag: u16) -> KernelServiceOperationV2 {
    match (role, tag) {
        (EndpointRoleV2::AgentKernel, 29) => KernelServiceOperationV2::agent(
            KernelAgentOperationV2::DispatchExecution(DispatchExecutionRequestV2::new(
                ExecutionTicketHandleV2::from_authority_entropy([29; 32]).unwrap(),
            )),
        ),
        (EndpointRoleV2::IngressKernel, 44) => KernelServiceOperationV2::ingress(
            KernelIngressOperationV2::AbortInput(AbortInputRequestV2::new(
                InputSessionHandleV2::from_authority_entropy([44; 32]).unwrap(),
            )),
        ),
        (EndpointRoleV2::KernelExecutor, 61) => {
            KernelServiceOperationV2::executor(KernelExecutorOperationV2::QueryByExecutionNonce(
                QueryByExecutionNonceRequestV2::new(
                    Nonce32V2::new([61; 32]),
                    Digest32V2::new([62; 32]),
                    Digest32V2::new([63; 32]),
                )
                .unwrap(),
            ))
        }
        _ => panic!("unsupported test operation"),
    }
}

#[test]
fn each_kernel_service_role_has_a_closed_operation_tag_set() {
    for (role, allowed) in [
        (EndpointRoleV2::AgentKernel, 29),
        (EndpointRoleV2::IngressKernel, 44),
        (EndpointRoleV2::KernelExecutor, 61),
    ] {
        let encoded = encode_kernel_service_request_envelope_v2(&request(role, allowed)).unwrap();
        assert_eq!(
            encode_kernel_service_request_envelope_v2(
                &decode_kernel_service_request_envelope_v2(&encoded).unwrap()
            )
            .unwrap(),
            encoded
        );
    }

    let wrong_role = KernelServiceRequestEnvelopeV2::from_authenticated_connection(
        EndpointRoleV2::IngressKernel,
        RequestIdV2::new([1; 16]),
        BootIdV2::new([2; 32]),
        BootIdV2::new([3; 32]),
        ServiceIdentityV2::new([4; 32]),
        ServiceIdentityV2::new([5; 32]),
        Digest32V2::new([6; 32]),
        7,
        UnixMillisV2::new(1_000),
        operation(EndpointRoleV2::AgentKernel, 29),
    );
    assert!(wrong_role.is_err());
}

#[test]
fn role_substitution_noncanonical_body_and_trailing_bytes_fail_closed() {
    let canonical =
        encode_kernel_service_request_envelope_v2(&request(EndpointRoleV2::AgentKernel, 29))
            .unwrap();
    let mut substituted = canonical.clone();
    substituted[4] = 0x03;
    assert_eq!(
        decode_kernel_service_request_envelope_v2(&substituted)
            .unwrap_err()
            .code(),
        StableCode::ProtocolUnknownOperation
    );

    let mut trailing = canonical;
    trailing.push(0);
    assert_eq!(
        decode_kernel_service_request_envelope_v2(&trailing)
            .unwrap_err()
            .code(),
        StableCode::ProtocolMalformedCbor
    );
}

#[test]
fn kernel_response_is_signed_role_request_and_operation_bound() {
    let key = SigningKey::from_bytes(&[0x31; 32]);
    let key_id = Ed25519KeyIdV2::new([0x32; 32]);
    let envelope = KernelServiceResponseEnvelopeV2::from_authenticated_connection(
        EndpointRoleV2::AgentKernel,
        RequestIdV2::new([1; 16]),
        BootIdV2::new([3; 32]),
        ServiceIdentityV2::new([5; 32]),
        Digest32V2::new([6; 32]),
        7,
        29,
        KernelServiceResponseV2::success(vec![0x80]).unwrap(),
    )
    .unwrap();
    let signed = sign_kernel_service_response_envelope_v2(&envelope, key_id, &key).unwrap();

    assert_eq!(
        verify_kernel_service_response_envelope_v2(&signed, key_id, key.verifying_key().to_bytes())
            .unwrap(),
        envelope
    );

    let wrong_key_id = Ed25519KeyIdV2::new([0x33; 32]);
    assert_eq!(
        verify_kernel_service_response_envelope_v2(
            &signed,
            wrong_key_id,
            key.verifying_key().to_bytes()
        )
        .unwrap_err()
        .code(),
        StableCode::IdentityInvalidSignature
    );
    let mut corrupted = signed;
    let last = corrupted.len() - 1;
    corrupted[last] ^= 1;
    assert_eq!(
        verify_kernel_service_response_envelope_v2(
            &corrupted,
            key_id,
            key.verifying_key().to_bytes()
        )
        .unwrap_err()
        .code(),
        StableCode::IdentityInvalidSignature
    );
}

#[test]
fn kernel_error_response_is_closed_and_canonical() {
    let key = SigningKey::from_bytes(&[0x41; 32]);
    let key_id = Ed25519KeyIdV2::new([0x42; 32]);
    let envelope = KernelServiceResponseEnvelopeV2::from_authenticated_connection(
        EndpointRoleV2::KernelExecutor,
        RequestIdV2::new([1; 16]),
        BootIdV2::new([3; 32]),
        ServiceIdentityV2::new([5; 32]),
        Digest32V2::new([6; 32]),
        7,
        61,
        KernelServiceResponseV2::error(StableCode::KernelUnavailable),
    )
    .unwrap();
    let signed = sign_kernel_service_response_envelope_v2(&envelope, key_id, &key).unwrap();
    let decoded =
        verify_kernel_service_response_envelope_v2(&signed, key_id, key.verifying_key().to_bytes())
            .unwrap();
    assert_eq!(
        decoded.response().error_code(),
        Some(StableCode::KernelUnavailable)
    );

    let mut trailing = signed;
    trailing.push(0);
    assert_eq!(
        verify_kernel_service_response_envelope_v2(
            &trailing,
            key_id,
            key.verifying_key().to_bytes()
        )
        .unwrap_err()
        .code(),
        StableCode::ProtocolMalformedCbor
    );
}
