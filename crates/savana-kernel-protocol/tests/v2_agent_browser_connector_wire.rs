use savana_kernel_protocol::v2::{
    decode_agent_browser_mutation_response_v2, decode_agent_browser_request_v2,
    decode_kernel_agent_operation_v2, encode_agent_browser_mutation_response_v2,
    encode_agent_browser_request_v2, kernel_agent_operation_tags_v2, AgentBrowserActionV2,
    AgentBrowserMutationResponseV2, AgentBrowserRequestV2, AgentPendingConnectorRegistrationRefV2,
    AgentTabSessionCapabilityV2, ApprovalDisplayAuthenticationTransferCapabilityV2,
    BoundedConnectorRegistrySnapshotV2, Digest32V2, FixedBrowserFormPostCarrierV2, Nonce32V2,
    MAX_CONNECTOR_REGISTRY_SNAPSHOT_BYTES_V2, MAX_HTTP_BODY_BYTES_V2,
};

fn browser_request(action: AgentBrowserActionV2, nonce_seed: u8) -> AgentBrowserRequestV2 {
    AgentBrowserRequestV2::Act {
        tab: AgentTabSessionCapabilityV2::from_authority_entropy([0x41; 32]).unwrap(),
        client_request_nonce: Nonce32V2::new([nonce_seed; 32]),
        action,
    }
}

fn assert_browser_only_round_trip(action: AgentBrowserActionV2, nonce_seed: u8) {
    let request = browser_request(action, nonce_seed);
    let encoded = encode_agent_browser_request_v2(request.clone()).unwrap();
    assert_eq!(decode_agent_browser_request_v2(&encoded).unwrap(), request);
    assert!(decode_kernel_agent_operation_v2(&encoded).is_err());
}

fn canonical_byte_string_with_total_length(total_length: usize) -> Vec<u8> {
    let payload_length = total_length.checked_sub(3).unwrap();
    let payload_length = u16::try_from(payload_length).unwrap();
    let mut bytes = Vec::with_capacity(total_length);
    bytes.push(0x59);
    bytes.extend_from_slice(&payload_length.to_be_bytes());
    bytes.resize(total_length, 0);
    bytes
}

#[test]
fn connector_completion_removal_and_snapshot_are_closed_browser_actions_only() {
    assert_eq!(
        kernel_agent_operation_tags_v2(),
        &[
            0, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
            41, 42, 43,
        ]
    );
    assert!(AgentPendingConnectorRegistrationRefV2::from_authority_entropy([0; 16]).is_none());
    let pending =
        AgentPendingConnectorRegistrationRefV2::from_authority_entropy([0x51; 16]).unwrap();
    let connector_id = Digest32V2::new([0x52; 32]);

    assert_browser_only_round_trip(
        AgentBrowserActionV2::FinalizeConnectorRegistration(pending),
        0x53,
    );
    assert_browser_only_round_trip(AgentBrowserActionV2::RemoveConnector(connector_id), 0x54);
    assert_browser_only_round_trip(AgentBrowserActionV2::SnapshotConnectors, 0x55);

    assert!(encode_agent_browser_request_v2(browser_request(
        AgentBrowserActionV2::RemoveConnector(Digest32V2::new([0; 32])),
        0x56,
    ))
    .is_err());
}

#[test]
fn planner_intent_boundary_actions_have_fixed_browser_only_tags() {
    let private =
        encode_agent_browser_request_v2(browser_request(AgentBrowserActionV2::RunPlanner, 0x57))
            .unwrap();
    let third_party = encode_agent_browser_request_v2(browser_request(
        AgentBrowserActionV2::RunPlannerWithThirdPartyMapper,
        0x58,
    ))
    .unwrap();

    assert_eq!(private.last(), Some(&0x02));
    assert_eq!(third_party.last(), Some(&0x10));
    assert_eq!(
        decode_agent_browser_request_v2(&private).unwrap(),
        browser_request(AgentBrowserActionV2::RunPlanner, 0x57)
    );
    assert_eq!(
        decode_agent_browser_request_v2(&third_party).unwrap(),
        browser_request(AgentBrowserActionV2::RunPlannerWithThirdPartyMapper, 0x58)
    );
    assert!(decode_kernel_agent_operation_v2(&private).is_err());
    assert!(decode_kernel_agent_operation_v2(&third_party).is_err());
    assert_eq!(
        kernel_agent_operation_tags_v2(),
        &[
            0, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
            41, 42, 43,
        ]
    );
}

#[test]
fn connector_browser_responses_round_trip_pending_commit_and_bounded_snapshot() {
    let pending =
        AgentPendingConnectorRegistrationRefV2::from_authority_entropy([0x61; 16]).unwrap();
    let post = FixedBrowserFormPostCarrierV2::AgentApprovalDisplay(
        ApprovalDisplayAuthenticationTransferCapabilityV2::from_authority_entropy([0x62; 32])
            .unwrap(),
    );
    let canonical_snapshot =
        BoundedConnectorRegistrySnapshotV2::new(vec![0x82, 0x04, 0x05]).unwrap();
    let signed_delta_digest = Digest32V2::new([0x65; 32]);
    let head_digest = Digest32V2::new([0x63; 32]);
    let connector_id = Digest32V2::new([0x64; 32]);

    let responses = [
        AgentBrowserMutationResponseV2::ConnectorOpenApproval { pending, post },
        AgentBrowserMutationResponseV2::ConnectorRegistrationCommitted {
            pending,
            signed_delta_digest,
            head_digest,
            sequence: 7,
            connector_id,
        },
        AgentBrowserMutationResponseV2::ConnectorRemovalCommitted {
            signed_delta_digest,
            head_digest,
            sequence: 8,
            connector_id,
        },
        AgentBrowserMutationResponseV2::ConnectorRegistrySnapshot { canonical_snapshot },
    ];

    for response in responses {
        let encoded = encode_agent_browser_mutation_response_v2(&response).unwrap();
        assert_eq!(
            decode_agent_browser_mutation_response_v2(&encoded).unwrap(),
            response
        );
    }

    assert!(BoundedConnectorRegistrySnapshotV2::new(Vec::new()).is_err());
}

#[test]
fn maximum_connector_snapshot_and_fixed_receipts_fit_the_agent_http_body() {
    let pending =
        AgentPendingConnectorRegistrationRefV2::from_authority_entropy([0x71; 16]).unwrap();
    let signed_delta_digest = Digest32V2::new([0x72; 32]);
    let head_digest = Digest32V2::new([0x73; 32]);
    let connector_id = Digest32V2::new([0x74; 32]);
    let receipts = [
        AgentBrowserMutationResponseV2::ConnectorRegistrationCommitted {
            pending,
            signed_delta_digest,
            head_digest,
            sequence: u64::MAX,
            connector_id,
        },
        AgentBrowserMutationResponseV2::ConnectorRemovalCommitted {
            signed_delta_digest,
            head_digest,
            sequence: u64::MAX,
            connector_id,
        },
    ];
    for receipt in receipts {
        let encoded = encode_agent_browser_mutation_response_v2(&receipt).unwrap();
        assert!(encoded.len() < MAX_HTTP_BODY_BYTES_V2);
        assert_eq!(
            decode_agent_browser_mutation_response_v2(&encoded).unwrap(),
            receipt
        );
    }
    assert!(encode_agent_browser_mutation_response_v2(
        &AgentBrowserMutationResponseV2::ConnectorRegistrationCommitted {
            pending,
            signed_delta_digest: Digest32V2::new([0; 32]),
            head_digest,
            sequence: 1,
            connector_id,
        }
    )
    .is_err());
    assert!(encode_agent_browser_mutation_response_v2(
        &AgentBrowserMutationResponseV2::ConnectorRemovalCommitted {
            signed_delta_digest,
            head_digest,
            sequence: 0,
            connector_id,
        }
    )
    .is_err());

    let maximum = BoundedConnectorRegistrySnapshotV2::new(canonical_byte_string_with_total_length(
        MAX_CONNECTOR_REGISTRY_SNAPSHOT_BYTES_V2,
    ))
    .unwrap();
    let response = AgentBrowserMutationResponseV2::ConnectorRegistrySnapshot {
        canonical_snapshot: maximum,
    };
    let encoded = encode_agent_browser_mutation_response_v2(&response).unwrap();
    assert!(encoded.len() < MAX_HTTP_BODY_BYTES_V2);
    assert_eq!(
        decode_agent_browser_mutation_response_v2(&encoded).unwrap(),
        response
    );

    assert!(
        BoundedConnectorRegistrySnapshotV2::new(canonical_byte_string_with_total_length(
            MAX_CONNECTOR_REGISTRY_SNAPSHOT_BYTES_V2 + 1,
        ))
        .is_err()
    );
}
