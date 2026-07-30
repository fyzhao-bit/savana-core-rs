use savana_kernel_protocol::{
    v2::{
        decode_agent_control_request_envelope_v2, decode_agent_control_response_envelope_v2,
        encode_agent_control_request_envelope_v2, encode_agent_control_response_envelope_v2,
        AgentControlOperationV2, AgentControlRequestEnvelopeV2, AgentControlResponseEnvelopeV2,
        AgentControlResponseV2, BootIdV2, Digest32V2, PublicServiceStateV2, RequestIdV2,
        ServiceIdentityV2, UnixMillisV2,
    },
    StableCode,
};

fn request() -> AgentControlRequestEnvelopeV2 {
    AgentControlRequestEnvelopeV2::from_authenticated_connection(
        RequestIdV2::new([0x11; 16]),
        BootIdV2::new([0x21; 32]),
        BootIdV2::new([0x22; 32]),
        ServiceIdentityV2::new([0x31; 32]),
        ServiceIdentityV2::new([0x32; 32]),
        Digest32V2::new([0x41; 32]),
        7,
        UnixMillisV2::new(1_000),
        AgentControlOperationV2::Health,
    )
    .unwrap()
}

#[test]
fn authenticated_agent_control_request_has_one_exact_canonical_shape() {
    let mut expected = vec![0x8c, 0x02, 0x00, 0x81, 0x01, 0x50];
    expected.extend_from_slice(&[0x11; 16]);
    for (prefix, seed) in [
        ([0x58, 0x20], 0x21),
        ([0x58, 0x20], 0x22),
        ([0x58, 0x20], 0x31),
        ([0x58, 0x20], 0x32),
        ([0x58, 0x20], 0x41),
    ] {
        expected.extend_from_slice(&prefix);
        expected.extend_from_slice(&[seed; 32]);
    }
    expected.extend_from_slice(&[0x07, 0x19, 0x03, 0xe8, 0x82, 0x00, 0x80]);

    assert_eq!(
        encode_agent_control_request_envelope_v2(&request()).unwrap(),
        expected
    );
    assert_eq!(
        decode_agent_control_request_envelope_v2(&expected).unwrap(),
        request()
    );
}

#[test]
fn request_envelope_rejects_cross_role_noncanonical_trailing_and_zero_identity() {
    let canonical = encode_agent_control_request_envelope_v2(&request()).unwrap();

    let mut cross_role = canonical.clone();
    cross_role[4] = 0x03;
    assert_eq!(
        decode_agent_control_request_envelope_v2(&cross_role)
            .unwrap_err()
            .code(),
        StableCode::ProtocolMalformedCbor
    );

    let mut noncanonical = canonical.clone();
    let generation = noncanonical.len() - 7;
    noncanonical.splice(generation..generation + 1, [0x18, 0x07]);
    assert_eq!(
        decode_agent_control_request_envelope_v2(&noncanonical)
            .unwrap_err()
            .code(),
        StableCode::ProtocolNonCanonicalCbor
    );

    let mut trailing = canonical;
    trailing.push(0);
    assert_eq!(
        decode_agent_control_request_envelope_v2(&trailing)
            .unwrap_err()
            .code(),
        StableCode::ProtocolMalformedCbor
    );

    assert!(
        AgentControlRequestEnvelopeV2::from_authenticated_connection(
            RequestIdV2::new([0x11; 16]),
            BootIdV2::new([0; 32]),
            BootIdV2::new([0x22; 32]),
            ServiceIdentityV2::new([0x31; 32]),
            ServiceIdentityV2::new([0x32; 32]),
            Digest32V2::new([0x41; 32]),
            7,
            UnixMillisV2::new(1_000),
            AgentControlOperationV2::Health,
        )
        .is_err()
    );
}

#[test]
fn response_envelope_echoes_identity_and_has_a_closed_error_branch() {
    let response = AgentControlResponseEnvelopeV2::from_authenticated_connection(
        request().request_id(),
        request().service_boot_id(),
        request().service_identity(),
        request().active_state_manifest_digest(),
        request().deployment_generation(),
        AgentControlResponseV2::health(PublicServiceStateV2::Ready),
    )
    .unwrap();
    let encoded = encode_agent_control_response_envelope_v2(&response).unwrap();
    assert_eq!(
        decode_agent_control_response_envelope_v2(&encoded).unwrap(),
        response
    );

    let error = AgentControlResponseEnvelopeV2::from_authenticated_connection(
        request().request_id(),
        request().service_boot_id(),
        request().service_identity(),
        request().active_state_manifest_digest(),
        request().deployment_generation(),
        AgentControlResponseV2::error(StableCode::DeadlineExceeded),
    )
    .unwrap();
    let encoded_error = encode_agent_control_response_envelope_v2(&error).unwrap();
    assert_eq!(
        decode_agent_control_response_envelope_v2(&encoded_error)
            .unwrap()
            .response()
            .stable_error(),
        Some(StableCode::DeadlineExceeded)
    );
    assert_eq!(
        AgentControlResponseV2::error(StableCode::CancellationTooLate).stable_error(),
        Some(StableCode::CancellationTooLate)
    );
}
