use savana_kernel_protocol::v2::{
    decode_authorize_release_response_v2, decode_authorize_tool_call_response_v2,
    decode_dispatch_execution_response_v2, decode_dispatch_release_response_v2,
    decode_get_execution_status_response_v2, decode_get_release_status_response_v2,
    decode_propose_tool_call_response_v2, decode_read_agent_view_response_v2,
    decode_revoke_vault_response_v2, encode_authorize_release_response_v2,
    encode_authorize_tool_call_response_v2, encode_dispatch_execution_response_v2,
    encode_dispatch_release_response_v2, encode_get_execution_status_response_v2,
    encode_get_release_status_response_v2, encode_propose_tool_call_response_v2,
    encode_read_agent_view_response_v2, encode_revoke_vault_response_v2,
    ActionIntentCurrentStateV2, ActionIntentHandleV2, AgentContentStateV2, AgentViewV2,
    AuthorizeReleaseResponseV2, AuthorizeToolCallResponseV2, DispatchExecutionResponseV2,
    DispatchReleaseResponseV2, ExecutionHandleV2, ExecutionTicketHandleV2,
    GetExecutionStatusResponseV2, GetReleaseStatusResponseV2, ProposeToolCallResponseV2,
    PublicDispatchAcceptedStateV2, PublicExecutionStatusV2, ReadAgentViewResponseV2,
    ReleaseHandleV2, ReleaseTicketHandleV2, RevokeVaultResponseV2, VaultPublicStateV2,
};

fn round_trip<T: PartialEq + std::fmt::Debug>(
    value: &T,
    encode: impl Fn(&T) -> Result<Vec<u8>, savana_kernel_protocol::ProtocolError>,
    decode: impl Fn(&[u8]) -> Result<T, savana_kernel_protocol::ProtocolError>,
) {
    let canonical = encode(value).unwrap();
    assert_eq!(decode(&canonical).unwrap(), *value);
    let mut trailing = canonical;
    trailing.push(0);
    assert!(decode(&trailing).is_err());
}

#[test]
fn remaining_agent_success_bodies_are_exact_and_canonical() {
    let proposed = ProposeToolCallResponseV2::new(
        ActionIntentHandleV2::from_authority_entropy([0x11; 32]).unwrap(),
        ActionIntentCurrentStateV2::Proposed {
            pending: savana_kernel_protocol::v2::PendingToolCallHandleV2::from_authority_entropy(
                [0x12; 32],
            )
            .unwrap(),
        },
    );
    round_trip(
        &proposed,
        encode_propose_tool_call_response_v2,
        decode_propose_tool_call_response_v2,
    );

    let tool_authorized = AuthorizeToolCallResponseV2::new(
        ExecutionTicketHandleV2::from_authority_entropy([0x13; 32]).unwrap(),
    );
    round_trip(
        &tool_authorized,
        encode_authorize_tool_call_response_v2,
        decode_authorize_tool_call_response_v2,
    );

    let dispatch = DispatchExecutionResponseV2::new(
        ExecutionHandleV2::from_authority_entropy([0x14; 32]).unwrap(),
        PublicDispatchAcceptedStateV2::Prepared,
    );
    round_trip(
        &dispatch,
        encode_dispatch_execution_response_v2,
        decode_dispatch_execution_response_v2,
    );

    let execution = GetExecutionStatusResponseV2::new(PublicExecutionStatusV2::Prepared);
    round_trip(
        &execution,
        encode_get_execution_status_response_v2,
        decode_get_execution_status_response_v2,
    );

    let view =
        ReadAgentViewResponseV2::new(AgentViewV2::ContentState(AgentContentStateV2::Ready), None);
    round_trip(
        &view,
        encode_read_agent_view_response_v2,
        decode_read_agent_view_response_v2,
    );

    let release_authorized = AuthorizeReleaseResponseV2::new(
        ReleaseTicketHandleV2::from_authority_entropy([0x15; 32]).unwrap(),
    );
    round_trip(
        &release_authorized,
        encode_authorize_release_response_v2,
        decode_authorize_release_response_v2,
    );

    let release_dispatch = DispatchReleaseResponseV2::new(
        ReleaseHandleV2::from_authority_entropy([0x16; 32]).unwrap(),
        PublicDispatchAcceptedStateV2::Dispatching,
    );
    round_trip(
        &release_dispatch,
        encode_dispatch_release_response_v2,
        decode_dispatch_release_response_v2,
    );

    let release = GetReleaseStatusResponseV2::new(PublicExecutionStatusV2::Dispatching);
    round_trip(
        &release,
        encode_get_release_status_response_v2,
        decode_get_release_status_response_v2,
    );

    let revoked = RevokeVaultResponseV2::new(VaultPublicStateV2::Revoked);
    round_trip(
        &revoked,
        encode_revoke_vault_response_v2,
        decode_revoke_vault_response_v2,
    );
}

#[test]
fn read_agent_view_rejects_an_empty_placeholder_token_on_decode() {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(2)
        .unwrap()
        .array(3)
        .unwrap()
        .u16(1)
        .unwrap()
        .str("masked")
        .unwrap()
        .array(1)
        .unwrap()
        .array(3)
        .unwrap()
        .u32(0)
        .unwrap()
        .str("")
        .unwrap()
        .u16(3)
        .unwrap()
        .null()
        .unwrap();
    assert!(decode_read_agent_view_response_v2(&encoder.into_writer()).is_err());
}
