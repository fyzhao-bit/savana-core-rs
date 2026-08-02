use ed25519_dalek::SigningKey;
use savana_kernel_protocol::v2::{
    decode_kernel_agent_operation_v2, decode_kernel_connector_control_operation_v2,
    derive_ed25519_key_id_v2, encode_kernel_connector_control_operation_v2,
    kernel_agent_operation_tags_v2, kernel_connector_control_operation_tags_v2,
    AgentSessionHandleV2, ApprovalBindingV2, ApprovalDecisionV2, ApprovalPurposeV2,
    ConnectorUiAuthorizationHandleV2, Digest32V2, KernelConnectorControlOperationV2, Nonce32V2,
    PrepareConnectorRegistrationRequestV2, PrincipalIdV2, ProposeConnectorRegistrationRequestV2,
    UnixMillisV2, UnsignedApprovalSettlementV2,
};
use savana_kernel_protocol::StableCode;

fn connector_descriptor() -> Vec<u8> {
    vec![0x87, 0x58, 0x20, 0x11, 0x22, 0x33]
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
    assert_eq!(kernel_connector_control_operation_tags_v2(), &[70, 71]);

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
    unknown[2] = 72;
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
