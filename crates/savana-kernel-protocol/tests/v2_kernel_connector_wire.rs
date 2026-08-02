use ed25519_dalek::SigningKey;
use savana_kernel_protocol::v2::{
    decode_apply_approved_connector_registration_response_v2,
    decode_authorize_connector_registration_response_v2,
    decode_connector_registry_snapshot_response_v2, decode_kernel_agent_operation_v2,
    decode_kernel_connector_control_operation_v2, decode_prepare_connector_removal_response_v2,
    decode_propose_connector_registration_response_v2, decode_remove_connector_response_v2,
    derive_ed25519_key_id_v2, encode_apply_approved_connector_registration_response_v2,
    encode_authorize_connector_registration_response_v2,
    encode_connector_registry_snapshot_response_v2, encode_kernel_connector_control_operation_v2,
    encode_prepare_connector_removal_response_v2,
    encode_propose_connector_registration_response_v2, encode_remove_connector_response_v2,
    kernel_agent_operation_tags_v2, kernel_connector_control_operation_tags_v2,
    AgentSessionHandleV2, ApplyApprovedConnectorRegistrationRequestV2,
    ApplyApprovedConnectorRegistrationResponseV2, ApprovalBindingV2, ApprovalDecisionV2,
    ApprovalPurposeV2, ApprovedConnectorRegistrationHandleV2,
    AuthorizeConnectorRegistrationRequestV2, AuthorizeConnectorRegistrationResponseV2,
    BoundedConnectorRegistrySnapshotV2, ConnectorRegistrySnapshotRequestV2,
    ConnectorRegistrySnapshotResponseV2, ConnectorRemovalAuthorizationHandleV2,
    ConnectorUiAuthorizationHandleV2, Digest32V2, Ed25519KeyIdV2, Ed25519SignatureV2,
    KernelConnectorControlOperationV2, Nonce32V2, PendingConnectorRegistrationHandleV2,
    PrepareConnectorRegistrationRequestV2, PrepareConnectorRemovalRequestV2,
    PrepareConnectorRemovalResponseV2, PrincipalIdV2, ProposeConnectorRegistrationRequestV2,
    ProposeConnectorRegistrationResponseV2, RemoveConnectorRequestV2, RemoveConnectorResponseV2,
    SignedApprovalEnvelopeV2, SignedApprovalSettlementV2, SignedUiAuthenticationEnvelopeV2,
    UnixMillisV2, UnsignedApprovalSettlementV2, MAX_CONNECTOR_REGISTRY_SNAPSHOT_BYTES_V2,
};
use savana_kernel_protocol::StableCode;

fn connector_descriptor() -> Vec<u8> {
    vec![0x87, 0x58, 0x20, 0x11, 0x22, 0x33]
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

fn connector_settlement() -> SignedApprovalSettlementV2 {
    SignedApprovalSettlementV2::sign(
        UnsignedApprovalSettlementV2::new(
            Digest32V2::new([0x82; 32]),
            Digest32V2::new([0x83; 32]),
            9,
            ApprovalPurposeV2::ConnectorRegistration,
            Digest32V2::new([0x84; 32]),
            ApprovalDecisionV2::Approve,
            PrincipalIdV2::new([0x85; 32]),
            Digest32V2::new([0x87; 32]),
            Digest32V2::new([0x88; 32]),
            true,
            true,
            false,
            false,
            1,
            Nonce32V2::new([0x86; 32]),
            Nonce32V2::new([0x89; 32]),
            UnixMillisV2::new(100),
            UnixMillisV2::new(200),
        )
        .unwrap(),
        &SigningKey::from_bytes(&[0x81; 32]),
    )
    .unwrap()
}

#[test]
fn connector_control_is_a_separate_closed_vocabulary() {
    assert_eq!(
        kernel_agent_operation_tags_v2(),
        &[
            0, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
            41, 42, 43,
        ]
    );
    assert_eq!(
        kernel_connector_control_operation_tags_v2(),
        &[70, 71, 72, 73, 74, 75, 76]
    );

    let prepare = KernelConnectorControlOperationV2::PrepareRegistration(
        PrepareConnectorRegistrationRequestV2::new(
            AgentSessionHandleV2::from_authority_entropy([0x51; 32]).unwrap(),
            connector_descriptor(),
        )
        .unwrap(),
    );
    let encoded = encode_kernel_connector_control_operation_v2(&prepare).unwrap();
    assert_eq!(
        decode_kernel_connector_control_operation_v2(&encoded).unwrap(),
        prepare
    );
    assert_eq!(
        decode_kernel_agent_operation_v2(&encoded)
            .unwrap_err()
            .code(),
        StableCode::ProtocolUnknownOperation
    );

    let mut unknown = encoded.clone();
    unknown[2] = 77;
    assert_eq!(
        decode_kernel_connector_control_operation_v2(&unknown)
            .unwrap_err()
            .code(),
        StableCode::ProtocolUnknownOperation
    );
    let mut trailing = encoded;
    trailing.push(0);
    assert_eq!(
        decode_kernel_connector_control_operation_v2(&trailing)
            .unwrap_err()
            .code(),
        StableCode::ProtocolMalformedCbor
    );
}

#[test]
fn connector_mutation_handles_are_opaque_and_reject_zero_entropy() {
    assert!(PendingConnectorRegistrationHandleV2::from_authority_entropy([0; 32]).is_none());
    assert!(ApprovedConnectorRegistrationHandleV2::from_authority_entropy([0; 32]).is_none());
    assert!(ConnectorRemovalAuthorizationHandleV2::from_authority_entropy([0; 32]).is_none());

    PendingConnectorRegistrationHandleV2::from_authority_entropy([0x91; 32]).unwrap();
    ApprovedConnectorRegistrationHandleV2::from_authority_entropy([0x92; 32]).unwrap();
    ConnectorRemovalAuthorizationHandleV2::from_authority_entropy([0x93; 32]).unwrap();
}

#[test]
fn connector_authorize_apply_remove_and_snapshot_requests_round_trip() {
    let pending = PendingConnectorRegistrationHandleV2::from_authority_entropy([0xa1; 32]).unwrap();
    let approved =
        ApprovedConnectorRegistrationHandleV2::from_authority_entropy([0xa2; 32]).unwrap();
    let removal_authorization =
        ConnectorRemovalAuthorizationHandleV2::from_authority_entropy([0xa3; 32]).unwrap();
    let session = AgentSessionHandleV2::from_authority_entropy([0xa4; 32]).unwrap();
    let connector_id = Digest32V2::new([0xa5; 32]);

    let operations = [
        KernelConnectorControlOperationV2::AuthorizeRegistration(
            AuthorizeConnectorRegistrationRequestV2::new(pending, connector_settlement()).unwrap(),
        ),
        KernelConnectorControlOperationV2::ApplyApprovedRegistration(
            ApplyApprovedConnectorRegistrationRequestV2::new(approved),
        ),
        KernelConnectorControlOperationV2::PrepareRemoval(
            PrepareConnectorRemovalRequestV2::new(session, connector_id).unwrap(),
        ),
        KernelConnectorControlOperationV2::Remove(
            RemoveConnectorRequestV2::new(session, removal_authorization, connector_id).unwrap(),
        ),
        KernelConnectorControlOperationV2::Snapshot(ConnectorRegistrySnapshotRequestV2::new(
            session,
        )),
    ];

    for (operation, expected_tag) in operations.into_iter().zip(72_u16..=76) {
        assert_eq!(operation.tag(), expected_tag);
        let encoded = encode_kernel_connector_control_operation_v2(&operation).unwrap();
        assert_eq!(
            decode_kernel_connector_control_operation_v2(&encoded).unwrap(),
            operation
        );
        assert_eq!(
            decode_kernel_agent_operation_v2(&encoded)
                .unwrap_err()
                .code(),
            StableCode::ProtocolUnknownOperation
        );
    }

    assert!(PrepareConnectorRemovalRequestV2::new(session, Digest32V2::new([0; 32])).is_err());
    assert!(RemoveConnectorRequestV2::new(
        session,
        removal_authorization,
        Digest32V2::new([0; 32]),
    )
    .is_err());
}

#[test]
fn connector_authority_responses_preserve_exact_commit_evidence() {
    let approved =
        ApprovedConnectorRegistrationHandleV2::from_authority_entropy([0xa6; 32]).unwrap();
    let authorization =
        ConnectorRemovalAuthorizationHandleV2::from_authority_entropy([0xa7; 32]).unwrap();
    let snapshot = BoundedConnectorRegistrySnapshotV2::new(vec![0x81, 0x02]).unwrap();
    let signed_delta_digest = Digest32V2::new([0xa7; 32]);
    let head_digest = Digest32V2::new([0xa8; 32]);
    let connector_id = Digest32V2::new([0xa9; 32]);

    let authorized = AuthorizeConnectorRegistrationResponseV2::new(approved);
    let encoded = encode_authorize_connector_registration_response_v2(authorized).unwrap();
    assert_eq!(
        decode_authorize_connector_registration_response_v2(&encoded).unwrap(),
        authorized
    );

    let applied = ApplyApprovedConnectorRegistrationResponseV2::new(
        signed_delta_digest,
        head_digest,
        7,
        connector_id,
    )
    .unwrap();
    let encoded = encode_apply_approved_connector_registration_response_v2(&applied).unwrap();
    assert_eq!(
        decode_apply_approved_connector_registration_response_v2(&encoded).unwrap(),
        applied
    );

    let prepared =
        PrepareConnectorRemovalResponseV2::new(authorization, head_digest, UnixMillisV2::new(900))
            .unwrap();
    let encoded = encode_prepare_connector_removal_response_v2(prepared).unwrap();
    assert_eq!(
        decode_prepare_connector_removal_response_v2(&encoded).unwrap(),
        prepared
    );

    let removed =
        RemoveConnectorResponseV2::new(signed_delta_digest, head_digest, 8, connector_id).unwrap();
    let encoded = encode_remove_connector_response_v2(&removed).unwrap();
    assert_eq!(
        decode_remove_connector_response_v2(&encoded).unwrap(),
        removed
    );

    let snapshot = ConnectorRegistrySnapshotResponseV2::new(snapshot);
    let encoded = encode_connector_registry_snapshot_response_v2(&snapshot).unwrap();
    assert_eq!(
        decode_connector_registry_snapshot_response_v2(&encoded).unwrap(),
        snapshot
    );

    assert!(ApplyApprovedConnectorRegistrationResponseV2::new(
        signed_delta_digest,
        head_digest,
        0,
        connector_id,
    )
    .is_err());
    assert!(ApplyApprovedConnectorRegistrationResponseV2::new(
        Digest32V2::new([0; 32]),
        head_digest,
        1,
        connector_id,
    )
    .is_err());
    assert!(ApplyApprovedConnectorRegistrationResponseV2::new(
        signed_delta_digest,
        Digest32V2::new([0; 32]),
        1,
        connector_id,
    )
    .is_err());
    assert!(ApplyApprovedConnectorRegistrationResponseV2::new(
        signed_delta_digest,
        head_digest,
        1,
        Digest32V2::new([0; 32]),
    )
    .is_err());
    assert_eq!(applied.signed_delta_digest(), signed_delta_digest);
    assert_eq!(removed.signed_delta_digest(), signed_delta_digest);
}

#[test]
fn connector_snapshot_has_an_exact_64_kib_canonical_bound() {
    assert_eq!(MAX_CONNECTOR_REGISTRY_SNAPSHOT_BYTES_V2, 64 * 1024);
    let maximum = canonical_byte_string_with_total_length(MAX_CONNECTOR_REGISTRY_SNAPSHOT_BYTES_V2);
    let response = ConnectorRegistrySnapshotResponseV2::new(
        BoundedConnectorRegistrySnapshotV2::new(maximum.clone()).unwrap(),
    );
    let encoded = encode_connector_registry_snapshot_response_v2(&response).unwrap();
    assert!(encoded.len() < savana_kernel_protocol::v2::MAX_HTTP_BODY_BYTES_V2);
    assert_eq!(
        decode_connector_registry_snapshot_response_v2(&encoded).unwrap(),
        response
    );

    let oversized =
        canonical_byte_string_with_total_length(MAX_CONNECTOR_REGISTRY_SNAPSHOT_BYTES_V2 + 1);
    assert!(BoundedConnectorRegistrySnapshotV2::new(oversized).is_err());
}

#[test]
fn proposed_registration_response_preserves_the_pending_add_handle() {
    let pending = PendingConnectorRegistrationHandleV2::from_authority_entropy([0xb1; 32]).unwrap();
    let envelope = SignedApprovalEnvelopeV2::from_canonical_parts(
        vec![0x81, 0x01],
        Ed25519KeyIdV2::new([0xb2; 32]),
        Ed25519SignatureV2::new([0xb3; 64]),
    )
    .unwrap();
    let display_authentication = SignedUiAuthenticationEnvelopeV2::from_canonical_parts(
        vec![0x81, 0x02],
        Ed25519KeyIdV2::new([0xb4; 32]),
        Ed25519SignatureV2::new([0xb5; 64]),
    )
    .unwrap();
    let response =
        ProposeConnectorRegistrationResponseV2::new(pending, envelope, display_authentication);

    assert_eq!(response.pending(), pending);
    let encoded = encode_propose_connector_registration_response_v2(&response).unwrap();
    assert_eq!(
        decode_propose_connector_registration_response_v2(&encoded).unwrap(),
        response
    );
}

#[test]
fn proposal_wire_requires_a_nonzero_connector_ui_authorization() {
    assert!(ConnectorUiAuthorizationHandleV2::from_authority_entropy([0; 32]).is_none());
    let descriptor = connector_descriptor();
    let authorization =
        ConnectorUiAuthorizationHandleV2::from_authority_entropy([0x61; 32]).unwrap();
    let proposal = KernelConnectorControlOperationV2::ProposeRegistration(
        ProposeConnectorRegistrationRequestV2::new(authorization, descriptor.clone()).unwrap(),
    );
    let encoded = encode_kernel_connector_control_operation_v2(&proposal).unwrap();
    assert_eq!(
        decode_kernel_connector_control_operation_v2(&encoded).unwrap(),
        proposal
    );

    let mut tampered = encoded;
    *tampered.last_mut().unwrap() ^= 1;
    let decoded = decode_kernel_connector_control_operation_v2(&tampered).unwrap();
    assert_ne!(decoded, proposal);

    assert!(ProposeConnectorRegistrationRequestV2::new(authorization, Vec::new()).is_err());
}

#[test]
fn connector_binding_is_purpose_four_and_covers_descriptor_and_head() {
    assert_eq!(ApprovalPurposeV2::ConnectorRegistration.tag(), 4);
    let descriptor_digest = Digest32V2::new([0x71; 32]);
    let previous_head_digest = Digest32V2::new([0x72; 32]);
    let binding = ApprovalBindingV2::ConnectorRegistration {
        descriptor_digest,
        previous_head_digest,
    };
    assert_eq!(binding.purpose(), ApprovalPurposeV2::ConnectorRegistration);

    let digest = binding.binding_digest().unwrap();
    assert_ne!(
        digest,
        ApprovalBindingV2::ConnectorRegistration {
            descriptor_digest: Digest32V2::new([0x73; 32]),
            previous_head_digest,
        }
        .binding_digest()
        .unwrap()
    );
    assert_ne!(
        digest,
        ApprovalBindingV2::ConnectorRegistration {
            descriptor_digest,
            previous_head_digest: Digest32V2::new([0x74; 32]),
        }
        .binding_digest()
        .unwrap()
    );
}

#[test]
fn connector_settlement_domain_cannot_cross_purpose() {
    let key = SigningKey::from_bytes(&[0x81; 32]);
    let key_id = derive_ed25519_key_id_v2(key.verifying_key().to_bytes());
    let installation = Digest32V2::new([0x82; 32]);
    let manifest = Digest32V2::new([0x83; 32]);
    let envelope = Digest32V2::new([0x84; 32]);
    let principal = PrincipalIdV2::new([0x85; 32]);
    let challenge = Nonce32V2::new([0x86; 32]);
    let unsigned = UnsignedApprovalSettlementV2::new(
        installation,
        manifest,
        9,
        ApprovalPurposeV2::ConnectorRegistration,
        envelope,
        ApprovalDecisionV2::Approve,
        principal,
        Digest32V2::new([0x87; 32]),
        Digest32V2::new([0x88; 32]),
        true,
        true,
        false,
        false,
        1,
        challenge,
        Nonce32V2::new([0x89; 32]),
        UnixMillisV2::new(100),
        UnixMillisV2::new(200),
    )
    .unwrap();
    let settlement =
        savana_kernel_protocol::v2::SignedApprovalSettlementV2::sign(unsigned, &key).unwrap();

    settlement
        .verify_connector_registration(
            key_id,
            key.verifying_key().to_bytes(),
            installation,
            manifest,
            9,
            envelope,
            principal,
            challenge,
            UnixMillisV2::new(150),
        )
        .unwrap();
    assert_eq!(
        settlement
            .verify_final_release(
                key_id,
                key.verifying_key().to_bytes(),
                installation,
                manifest,
                9,
                envelope,
                principal,
                challenge,
                UnixMillisV2::new(150),
            )
            .unwrap_err()
            .code(),
        StableCode::ApprovalBindingMismatch
    );
}
