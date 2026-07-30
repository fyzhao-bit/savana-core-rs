use savana_kernel_protocol::{
    v2::{
        decode_agent_control_operation_v2, decode_public_task_status_v2,
        encode_agent_control_operation_v2, encode_public_task_status_v2, AgentControlOperationV2,
        JarvisBootstrapActionV2, PublicTaskStatusV2,
    },
    StableCode,
};

#[test]
fn get_task_status_is_exact_tag_11_with_one_opaque_handle() {
    let mut wire = vec![0x82, 0x0b, 0x81, 0x58, 0x20];
    wire.extend_from_slice(&[0x44; 32]);

    let decoded = decode_agent_control_operation_v2(&wire).unwrap();

    assert_eq!(decoded.tag(), 11);
    assert!(matches!(decoded, AgentControlOperationV2::GetTaskStatus(_)));
    assert_eq!(encode_agent_control_operation_v2(&decoded).unwrap(), wire);
}

#[test]
fn unknown_cross_endpoint_and_trailing_operations_fail_closed() {
    for wire in [
        &[0x82, 0x14, 0x80][..],
        &[0x82, 0x18, 0x29, 0x80][..],
        &[0x82, 0x0b, 0x80][..],
        &[0x82, 0x00, 0x80, 0x00][..],
    ] {
        assert!(decode_agent_control_operation_v2(wire).is_err());
    }
}

#[test]
fn operation_decoder_distinguishes_noncanonical_from_malformed() {
    let non_shortest_health_tag = [0x82, 0x18, 0x00, 0x80];
    let error = decode_agent_control_operation_v2(&non_shortest_health_tag).unwrap_err();
    assert_eq!(error.code(), StableCode::ProtocolNonCanonicalCbor);

    let malformed_health_body = [0x82, 0x00, 0x81, 0x00];
    let error = decode_agent_control_operation_v2(&malformed_health_body).unwrap_err();
    assert_eq!(error.code(), StableCode::ProtocolMalformedCbor);
}

#[test]
fn public_status_rejects_payload_on_success_and_wrong_failure_classes() {
    assert!(decode_public_task_status_v2(&[0x82, 0x08, 0x41, 0x78]).is_err());
    assert!(decode_public_task_status_v2(&[0x82, 0x0a, 0x81, 0x07]).is_err());
    assert!(decode_public_task_status_v2(&[0x82, 0x09, 0x81, 0x01]).is_err());
    assert!(decode_public_task_status_v2(&[0x82, 0x0b, 0x81, 0x07]).is_err());
    assert!(decode_public_task_status_v2(&[0x82, 0x01, 0x81, 0x00]).is_err());
}

#[test]
fn jarvis_bootstrap_url_has_only_the_fixed_local_origin_and_selector() {
    let mut wire = vec![
        0x82, 0x01, // AwaitingUiAuthentication
        0x82, 0x01, // OpenIngress
        0x83, 0x81, 0x01, // Jarvis8765
        0x81, 0x01, // Ingress
        0x58, 0x20,
    ];
    wire.extend_from_slice(&[0; 32]);
    let status = decode_public_task_status_v2(&wire).unwrap();
    let url = match status {
        PublicTaskStatusV2::AwaitingUiAuthentication {
            bootstrap: Some(JarvisBootstrapActionV2::OpenIngress { url }),
        } => url,
        _ => unreachable!(),
    };

    assert_eq!(
        url.to_string(),
        "http://localhost:8765/v2/bootstrap/ingress/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    );
    assert!(format!("{url:?}").contains("JarvisBootstrapSelectorV2(<opaque>)"));

    let mut wrong_origin = vec![
        0x82, 0x01, 0x82, 0x01, 0x83, 0x81, 0x02, 0x81, 0x01, 0x58, 0x20,
    ];
    wrong_origin.extend_from_slice(&[0; 32]);
    assert!(decode_public_task_status_v2(&wrong_origin).is_err());
}

#[test]
fn public_status_decoder_enforces_canonical_bytes_and_action_kind_pairing() {
    let non_shortest_succeeded = [0x81, 0x18, 0x08];
    let error = decode_public_task_status_v2(&non_shortest_succeeded).unwrap_err();
    assert_eq!(error.code(), StableCode::ProtocolNonCanonicalCbor);

    let trailing = [0x81, 0x08, 0x00];
    assert_eq!(
        decode_public_task_status_v2(&trailing).unwrap_err().code(),
        StableCode::ProtocolMalformedCbor
    );

    let mut cross_pair = vec![
        0x82, 0x01, // AwaitingUiAuthentication
        0x82, 0x02, // OpenApproval
        0x83, 0x81, 0x01, // Jarvis8765
        0x81, 0x01, // wrong: Ingress
        0x58, 0x20,
    ];
    cross_pair.extend_from_slice(&[0; 32]);
    assert!(decode_public_task_status_v2(&cross_pair).is_err());
}

#[test]
fn scanner_enforces_one_cumulative_item_budget() {
    let mut wire = vec![0x82, 0x99, 0xff, 0xff];
    wire.extend(std::iter::repeat(0).take(65_535));
    wire.push(0x80);

    let error = decode_agent_control_operation_v2(&wire).unwrap_err();
    assert_eq!(error.code(), StableCode::ProtocolAllocationRefused);
}

#[test]
fn all_unit_public_statuses_have_exact_frozen_tags() {
    let cases = [
        (PublicTaskStatusV2::AwaitingInput, 2_u8),
        (PublicTaskStatusV2::Processing, 3),
        (PublicTaskStatusV2::AwaitingIngressApproval, 4),
        (PublicTaskStatusV2::Running, 6),
        (PublicTaskStatusV2::Dispatching, 7),
        (PublicTaskStatusV2::Succeeded, 8),
        (PublicTaskStatusV2::Indeterminate, 12),
        (PublicTaskStatusV2::Cancelled, 13),
        (PublicTaskStatusV2::Expired, 14),
    ];

    for (status, tag) in cases {
        let expected = vec![0x81, tag];
        assert_eq!(encode_public_task_status_v2(&status).unwrap(), expected);
        assert_eq!(decode_public_task_status_v2(&expected).unwrap(), status);
    }
}
