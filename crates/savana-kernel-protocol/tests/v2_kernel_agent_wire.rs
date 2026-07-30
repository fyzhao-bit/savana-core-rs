use ed25519_dalek::SigningKey;
use savana_kernel_protocol::v2::{
    decode_kernel_agent_operation_v2, derive_ed25519_key_id_v2, encode_kernel_agent_operation_v2,
    kernel_agent_operation_tags_v2, ActionTemplateIdV2, AgentAuthenticationClosureEvidenceV2,
    AgentSessionHandleV2, AgentUiAuthenticationPreparationHandleV2, AgentUiAuthorizationHandleV2,
    ApprovalDecisionV2, ApprovalPurposeV2, ArgumentNameV2, AuthenticateAgentUiRequestV2,
    AuthorizeReleaseRequestV2, AuthorizeToolCallRequestV2, BootIdV2, CancelKernelTaskRequestV2,
    ClaimAgentSessionRequestV2, CloseAgentSessionRequestV2, CommitPlannerValueRequestV2,
    DeriveOperationV2, DeriveValueRequestV2, Digest32V2, DispatchExecutionRequestV2,
    DispatchReleaseRequestV2, DisplayProjectionIdV2, DurableRunIdV2, DurableTaskIdV2,
    Ed25519KeyIdV2, Ed25519SignatureV2, EvaluateToolCallRequestV2, ExecutionHandleV2,
    ExecutionStatusTargetV2, ExecutionTicketHandleV2, ExecutorIdentityV2, FixedOriginV2,
    GetAgentSessionStatusRequestV2, GetExecutionStatusRequestV2, GetKernelTaskStatusRequestV2,
    GetReleaseStatusRequestV2, KernelAgentHealthRequestV2, KernelAgentOperationV2,
    MaskedDocumentHandleV2, NamedArgumentValueBindingV2, NewTaskPreparationHandleV2, Nonce32V2,
    PendingReleaseHandleV2, PlannerPlanV2, PlannerRouteIdV2, PlannerSlotRefV2, PlannerStepV2,
    PrepareAgentUiAuthenticationRequestV2, PrepareFollowupIngressRequestV2,
    PrepareNewIngressRequestV2, PreparePlannerCallRequestV2, PrepareReleaseRequestV2,
    PrincipalIdV2, ProjectionIdV2, ProposeToolCallRequestV2, ReadAgentViewRequestV2,
    ReleaseHandleV2, ReleaseKernelApprovalHandleV2, ReleaseStatusTargetV2, ReleaseTicketHandleV2,
    ResumeCommittedAgentAuthenticationRequestV2, RevokeVaultRequestV2, RunHandleV2,
    ServiceIdentityV2, SignedAgentAuthenticationAttemptClosureProofV2, SignedApprovalSettlementV2,
    SignedDurableTaskCorrelationV2, SignedUiAuthenticationSettlementV2, ToolClassIdV2,
    ToolHandleV2, ToolKernelApprovalHandleV2, UiAuthenticationPurposeV2, UnixMillisV2,
    UnsignedAgentAuthenticationAttemptClosureProofV2, UnsignedApprovalSettlementV2,
    UnsignedDurableTaskCorrelationV2, UnsignedUiAuthenticationSettlementV2, ValueHandleV2,
};

#[test]
fn durable_task_correlation_is_signed_and_verified_with_exact_bindings() {
    let unsigned = UnsignedDurableTaskCorrelationV2::new(
        Digest32V2::new([0x11; 32]),
        Digest32V2::new([0x12; 32]),
        7,
        DurableTaskIdV2::new([0x13; 32]),
        ServiceIdentityV2::new([0x14; 32]),
        BootIdV2::new([0x15; 32]),
        BootIdV2::new([0x16; 32]),
        BootIdV2::new([0x17; 32]),
        UnixMillisV2::new(100),
        UnixMillisV2::new(200),
        UnixMillisV2::new(300),
    )
    .unwrap();
    let key = SigningKey::from_bytes(&[0x18; 32]);
    let signed = SignedDurableTaskCorrelationV2::sign(unsigned, &key).unwrap();
    let key_id = derive_ed25519_key_id_v2(key.verifying_key().to_bytes());
    assert_eq!(
        signed
            .verify(
                key_id,
                key.verifying_key().to_bytes(),
                Digest32V2::new([0x11; 32]),
                Digest32V2::new([0x12; 32]),
                ServiceIdentityV2::new([0x14; 32]),
                UnixMillisV2::new(150),
            )
            .unwrap(),
        unsigned
    );
    assert!(signed
        .verify(
            key_id,
            key.verifying_key().to_bytes(),
            Digest32V2::new([0x19; 32]),
            Digest32V2::new([0x12; 32]),
            ServiceIdentityV2::new([0x14; 32]),
            UnixMillisV2::new(150),
        )
        .is_err());
}

#[test]
fn agent_kernel_health_has_the_exact_typed_wire_shape() {
    assert_eq!(
        kernel_agent_operation_tags_v2(),
        &[
            0, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
            41, 42, 43,
        ]
    );
    let operation = KernelAgentOperationV2::Health(KernelAgentHealthRequestV2);
    let encoded = encode_kernel_agent_operation_v2(&operation).unwrap();

    assert_eq!(encoded, [0x82, 0x00, 0x80]);
    assert_eq!(
        decode_kernel_agent_operation_v2(&encoded).unwrap(),
        operation
    );
}

#[test]
fn agent_kernel_decoder_rejects_unknown_wrong_shape_and_trailing_values() {
    assert!(decode_kernel_agent_operation_v2(&[0x82, 0x01, 0x80]).is_err());
    assert!(decode_kernel_agent_operation_v2(&[0x81, 0x00]).is_err());
    assert!(decode_kernel_agent_operation_v2(&[0x82, 0x00, 0x81, 0x00]).is_err());
    assert!(decode_kernel_agent_operation_v2(&[0x82, 0x00, 0x80, 0x00]).is_err());
}

#[test]
fn agent_session_entry_operations_have_exact_handle_bound_shapes() {
    let authorization = AgentUiAuthorizationHandleV2::from_authority_entropy([0x20; 32]).unwrap();
    let claim =
        KernelAgentOperationV2::ClaimAgentSession(ClaimAgentSessionRequestV2::new(authorization));
    let mut claim_expected = vec![0x82, 0x14, 0x81, 0x58, 0x20];
    claim_expected.extend_from_slice(&[0x20; 32]);
    assert_eq!(
        encode_kernel_agent_operation_v2(&claim).unwrap(),
        claim_expected
    );
    assert_eq!(
        decode_kernel_agent_operation_v2(&claim_expected).unwrap(),
        claim
    );

    let session = AgentSessionHandleV2::from_authority_entropy([0x21; 32]).unwrap();
    let run = RunHandleV2::from_authority_entropy([0x22; 32]).unwrap();
    let followup = KernelAgentOperationV2::PrepareFollowupIngress(
        PrepareFollowupIngressRequestV2::new(session, run, Nonce32V2::new([0x23; 32])).unwrap(),
    );
    let mut followup_expected = vec![0x82, 0x15, 0x83, 0x58, 0x20];
    followup_expected.extend_from_slice(&[0x21; 32]);
    followup_expected.extend_from_slice(&[0x58, 0x20]);
    followup_expected.extend_from_slice(&[0x22; 32]);
    followup_expected.extend_from_slice(&[0x58, 0x20]);
    followup_expected.extend_from_slice(&[0x23; 32]);
    assert_eq!(
        encode_kernel_agent_operation_v2(&followup).unwrap(),
        followup_expected
    );
    assert_eq!(
        decode_kernel_agent_operation_v2(&followup_expected).unwrap(),
        followup
    );

    let status =
        KernelAgentOperationV2::GetAgentSessionStatus(GetAgentSessionStatusRequestV2::new(session));
    let mut status_expected = vec![0x82, 0x16, 0x81, 0x58, 0x20];
    status_expected.extend_from_slice(&[0x21; 32]);
    assert_eq!(
        encode_kernel_agent_operation_v2(&status).unwrap(),
        status_expected
    );
    assert_eq!(
        decode_kernel_agent_operation_v2(&status_expected).unwrap(),
        status
    );
}

#[test]
fn agent_control_mutations_36_through_39_have_closed_bodies() {
    let document = MaskedDocumentHandleV2::from_authority_entropy([0x36; 32]).unwrap();
    let revoke = KernelAgentOperationV2::RevokeVault(RevokeVaultRequestV2::new(document));
    let mut revoke_expected = vec![0x82, 0x18, 0x24, 0x81, 0x58, 0x20];
    revoke_expected.extend_from_slice(&[0x36; 32]);
    assert_eq!(
        encode_kernel_agent_operation_v2(&revoke).unwrap(),
        revoke_expected
    );
    assert_eq!(
        decode_kernel_agent_operation_v2(&revoke_expected).unwrap(),
        revoke
    );

    let session = AgentSessionHandleV2::from_authority_entropy([0x37; 32]).unwrap();
    let close = KernelAgentOperationV2::CloseAgentSession(CloseAgentSessionRequestV2::new(session));
    let mut close_expected = vec![0x82, 0x18, 0x25, 0x81, 0x58, 0x20];
    close_expected.extend_from_slice(&[0x37; 32]);
    assert_eq!(
        encode_kernel_agent_operation_v2(&close).unwrap(),
        close_expected
    );

    let prepare = KernelAgentOperationV2::PrepareNewIngress(
        PrepareNewIngressRequestV2::new(Nonce32V2::new([0x38; 32]), Nonce32V2::new([0x39; 32]))
            .unwrap(),
    );
    let mut prepare_expected = vec![0x82, 0x18, 0x26, 0x82, 0x58, 0x20];
    prepare_expected.extend_from_slice(&[0x38; 32]);
    prepare_expected.extend_from_slice(&[0x58, 0x20]);
    prepare_expected.extend_from_slice(&[0x39; 32]);
    assert_eq!(
        encode_kernel_agent_operation_v2(&prepare).unwrap(),
        prepare_expected
    );
    assert_eq!(
        decode_kernel_agent_operation_v2(&prepare_expected).unwrap(),
        prepare
    );
    assert!(
        PrepareNewIngressRequestV2::new(Nonce32V2::new([0; 32]), Nonce32V2::new([1; 32])).is_err()
    );

    let preparation = NewTaskPreparationHandleV2::from_authority_entropy([0x40; 32]).unwrap();
    let authentication = KernelAgentOperationV2::PrepareAgentUiAuthentication(
        PrepareAgentUiAuthenticationRequestV2::new(preparation),
    );
    let mut authentication_expected = vec![0x82, 0x18, 0x27, 0x81, 0x58, 0x20];
    authentication_expected.extend_from_slice(&[0x40; 32]);
    assert_eq!(
        encode_kernel_agent_operation_v2(&authentication).unwrap(),
        authentication_expected
    );
    assert_eq!(
        decode_kernel_agent_operation_v2(&authentication_expected).unwrap(),
        authentication
    );
}

#[test]
fn execution_and_release_dispatch_targets_are_typed_and_closed() {
    let execution_ticket = ExecutionTicketHandleV2::from_authority_entropy([0x29; 32]).unwrap();
    let dispatch = KernelAgentOperationV2::DispatchExecution(DispatchExecutionRequestV2::new(
        execution_ticket,
    ));
    let mut dispatch_expected = vec![0x82, 0x18, 0x1d, 0x81, 0x58, 0x20];
    dispatch_expected.extend_from_slice(&[0x29; 32]);
    assert_eq!(
        encode_kernel_agent_operation_v2(&dispatch).unwrap(),
        dispatch_expected
    );

    let execution = ExecutionHandleV2::from_authority_entropy([0x30; 32]).unwrap();
    let query = KernelAgentOperationV2::GetExecutionStatus(GetExecutionStatusRequestV2::new(
        ExecutionStatusTargetV2::Execution(execution),
    ));
    let mut query_expected = vec![0x82, 0x18, 0x1e, 0x81, 0x82, 0x03, 0x58, 0x20];
    query_expected.extend_from_slice(&[0x30; 32]);
    assert_eq!(
        encode_kernel_agent_operation_v2(&query).unwrap(),
        query_expected
    );
    assert_eq!(
        decode_kernel_agent_operation_v2(&query_expected).unwrap(),
        query
    );

    let release_ticket = ReleaseTicketHandleV2::from_authority_entropy([0x34; 32]).unwrap();
    let release =
        KernelAgentOperationV2::DispatchRelease(DispatchReleaseRequestV2::new(release_ticket));
    let mut release_expected = vec![0x82, 0x18, 0x22, 0x81, 0x58, 0x20];
    release_expected.extend_from_slice(&[0x34; 32]);
    assert_eq!(
        encode_kernel_agent_operation_v2(&release).unwrap(),
        release_expected
    );

    let pending = PendingReleaseHandleV2::from_authority_entropy([0x35; 32]).unwrap();
    let release_query = KernelAgentOperationV2::GetReleaseStatus(GetReleaseStatusRequestV2::new(
        ReleaseStatusTargetV2::Pending(pending),
    ));
    let mut release_query_expected = vec![0x82, 0x18, 0x23, 0x81, 0x82, 0x01, 0x58, 0x20];
    release_query_expected.extend_from_slice(&[0x35; 32]);
    assert_eq!(
        encode_kernel_agent_operation_v2(&release_query).unwrap(),
        release_query_expected
    );
    assert_eq!(
        decode_kernel_agent_operation_v2(&release_query_expected).unwrap(),
        release_query
    );

    let release_handle = ReleaseHandleV2::from_authority_entropy([0x36; 32]).unwrap();
    assert_ne!(
        ReleaseStatusTargetV2::Release(release_handle),
        ReleaseStatusTargetV2::Pending(pending)
    );
}

#[test]
fn read_agent_view_binds_document_cursor_limit_and_nonce() {
    let document = MaskedDocumentHandleV2::from_authority_entropy([0x31; 32]).unwrap();
    let request = KernelAgentOperationV2::ReadAgentView(
        ReadAgentViewRequestV2::new(document, None, 4096, Nonce32V2::new([0x32; 32])).unwrap(),
    );
    let mut expected = vec![0x82, 0x18, 0x1f, 0x84, 0x58, 0x20];
    expected.extend_from_slice(&[0x31; 32]);
    expected.extend_from_slice(&[0xf6, 0x19, 0x10, 0x00, 0x58, 0x20]);
    expected.extend_from_slice(&[0x32; 32]);

    assert_eq!(
        encode_kernel_agent_operation_v2(&request).unwrap(),
        expected
    );
    assert_eq!(
        decode_kernel_agent_operation_v2(&expected).unwrap(),
        request
    );
    assert!(ReadAgentViewRequestV2::new(document, None, 0, Nonce32V2::new([1; 32])).is_err());
    assert!(ReadAgentViewRequestV2::new(document, None, 1, Nonce32V2::new([0; 32])).is_err());
}

#[test]
fn planner_preparation_has_a_bounded_typed_value_list() {
    let run = RunHandleV2::from_authority_entropy([0x23; 32]).unwrap();
    let first = ValueHandleV2::from_authority_entropy([0x24; 32]).unwrap();
    let second = ValueHandleV2::from_authority_entropy([0x25; 32]).unwrap();
    let request = KernelAgentOperationV2::PreparePlannerCall(
        PreparePlannerCallRequestV2::new(run, PlannerRouteIdV2::new(7), vec![first, second])
            .unwrap(),
    );
    let mut expected = vec![0x82, 0x17, 0x83, 0x58, 0x20];
    expected.extend_from_slice(&[0x23; 32]);
    expected.extend_from_slice(&[0x07, 0x82, 0x58, 0x20]);
    expected.extend_from_slice(&[0x24; 32]);
    expected.extend_from_slice(&[0x58, 0x20]);
    expected.extend_from_slice(&[0x25; 32]);

    assert_eq!(
        encode_kernel_agent_operation_v2(&request).unwrap(),
        expected
    );
    assert_eq!(
        decode_kernel_agent_operation_v2(&expected).unwrap(),
        request
    );
    assert!(
        PreparePlannerCallRequestV2::new(run, PlannerRouteIdV2::new(7), vec![first; 257],).is_err()
    );
}

#[test]
fn durable_task_correlation_is_typed_signed_and_query_only_bound() {
    let unsigned = UnsignedDurableTaskCorrelationV2::new(
        Digest32V2::new([1; 32]),
        Digest32V2::new([2; 32]),
        3,
        DurableTaskIdV2::new([4; 32]),
        ServiceIdentityV2::new([5; 32]),
        BootIdV2::new([6; 32]),
        BootIdV2::new([7; 32]),
        BootIdV2::new([8; 32]),
        UnixMillisV2::new(9),
        UnixMillisV2::new(10),
        UnixMillisV2::new(11),
    )
    .unwrap();
    let correlation = SignedDurableTaskCorrelationV2::from_parts(
        unsigned,
        Ed25519KeyIdV2::new([12; 32]),
        Ed25519SignatureV2::new([13; 64]),
    )
    .unwrap();

    let query = KernelAgentOperationV2::GetKernelTaskStatus(GetKernelTaskStatusRequestV2::new(
        correlation.clone(),
    ));
    let encoded = encode_kernel_agent_operation_v2(&query).unwrap();
    assert_eq!(&encoded[..3], &[0x82, 0x18, 0x29]);
    assert_eq!(decode_kernel_agent_operation_v2(&encoded).unwrap(), query);

    let preparation = NewTaskPreparationHandleV2::from_authority_entropy([0x42; 32]).unwrap();
    let cancel = KernelAgentOperationV2::CancelKernelTask(CancelKernelTaskRequestV2::new(
        preparation,
        correlation,
    ));
    let encoded = encode_kernel_agent_operation_v2(&cancel).unwrap();
    assert_eq!(&encoded[..3], &[0x82, 0x18, 0x2a]);
    assert_eq!(decode_kernel_agent_operation_v2(&encoded).unwrap(), cancel);

    assert!(UnsignedDurableTaskCorrelationV2::new(
        Digest32V2::new([0; 32]),
        Digest32V2::new([2; 32]),
        3,
        DurableTaskIdV2::new([4; 32]),
        ServiceIdentityV2::new([5; 32]),
        BootIdV2::new([6; 32]),
        BootIdV2::new([7; 32]),
        BootIdV2::new([8; 32]),
        UnixMillisV2::new(9),
        UnixMillisV2::new(10),
        UnixMillisV2::new(11),
    )
    .is_err());
}

#[test]
fn planner_value_tool_and_release_requests_are_typed_and_bounded() {
    let run = RunHandleV2::from_authority_entropy([0x24; 32]).unwrap();
    let ticket =
        savana_kernel_protocol::v2::PlannerTicketHandleV2::from_authority_entropy([0x25; 32])
            .unwrap();
    let step = PlannerStepV2::new(
        1,
        ActionTemplateIdV2::new(2),
        ToolClassIdV2::new(3),
        vec![(
            ArgumentNameV2::new("input".to_owned()).unwrap(),
            PlannerSlotRefV2::new([4; 16]),
        )],
        vec![],
    )
    .unwrap();
    let plan = PlannerPlanV2::new(Nonce32V2::new([5; 32]), vec![step]).unwrap();
    let commit = KernelAgentOperationV2::CommitPlannerValue(CommitPlannerValueRequestV2::new(
        run, ticket, plan,
    ));
    let encoded = encode_kernel_agent_operation_v2(&commit).unwrap();
    assert_eq!(&encoded[..3], &[0x82, 0x18, 0x18]);
    assert_eq!(decode_kernel_agent_operation_v2(&encoded).unwrap(), commit);

    let derive = KernelAgentOperationV2::DeriveValue(
        DeriveValueRequestV2::new(
            run,
            DeriveOperationV2::assemble_list(),
            vec![ValueHandleV2::from_authority_entropy([6; 32]).unwrap()],
        )
        .unwrap(),
    );
    let encoded = encode_kernel_agent_operation_v2(&derive).unwrap();
    assert_eq!(&encoded[..3], &[0x82, 0x18, 0x19]);
    assert_eq!(decode_kernel_agent_operation_v2(&encoded).unwrap(), derive);

    let named = NamedArgumentValueBindingV2::new(
        ArgumentNameV2::new("input".to_owned()).unwrap(),
        ValueHandleV2::from_authority_entropy([7; 32]).unwrap(),
    );
    let propose = KernelAgentOperationV2::ProposeToolCall(
        ProposeToolCallRequestV2::new(
            savana_kernel_protocol::v2::PlanStepHandleV2::from_authority_entropy([8; 32]).unwrap(),
            ToolHandleV2::from_authority_entropy([9; 32]).unwrap(),
            vec![named],
        )
        .unwrap(),
    );
    let encoded = encode_kernel_agent_operation_v2(&propose).unwrap();
    assert_eq!(&encoded[..3], &[0x82, 0x18, 0x1a]);
    assert_eq!(decode_kernel_agent_operation_v2(&encoded).unwrap(), propose);

    let pending =
        savana_kernel_protocol::v2::PendingToolCallHandleV2::from_authority_entropy([10; 32])
            .unwrap();
    let evaluate =
        KernelAgentOperationV2::EvaluateToolCall(EvaluateToolCallRequestV2::new(pending));
    let encoded = encode_kernel_agent_operation_v2(&evaluate).unwrap();
    assert_eq!(&encoded[..3], &[0x82, 0x18, 0x1b]);
    assert_eq!(
        decode_kernel_agent_operation_v2(&encoded).unwrap(),
        evaluate
    );

    let release = KernelAgentOperationV2::PrepareRelease(
        PrepareReleaseRequestV2::new(
            MaskedDocumentHandleV2::from_authority_entropy([11; 32]).unwrap(),
            vec![ValueHandleV2::from_authority_entropy([12; 32]).unwrap()],
            ExecutorIdentityV2::new([13; 32]),
            ProjectionIdV2::new(14),
            DisplayProjectionIdV2::new(15),
        )
        .unwrap(),
    );
    let encoded = encode_kernel_agent_operation_v2(&release).unwrap();
    assert_eq!(&encoded[..3], &[0x82, 0x18, 0x20]);
    assert_eq!(decode_kernel_agent_operation_v2(&encoded).unwrap(), release);

    assert!(PrepareReleaseRequestV2::new(
        MaskedDocumentHandleV2::from_authority_entropy([11; 32]).unwrap(),
        vec![ValueHandleV2::from_authority_entropy([12; 32]).unwrap(); 257],
        ExecutorIdentityV2::new([13; 32]),
        ProjectionIdV2::new(14),
        DisplayProjectionIdV2::new(15),
    )
    .is_err());
}

#[test]
fn approval_and_agent_authentication_settlements_are_typed_and_purpose_bound() {
    let tool_settlement = signed_approval_settlement(ApprovalPurposeV2::ToolExecution, 20);
    let authorize_tool = KernelAgentOperationV2::AuthorizeToolCall(
        AuthorizeToolCallRequestV2::new(
            savana_kernel_protocol::v2::PendingToolCallHandleV2::from_authority_entropy([21; 32])
                .unwrap(),
            ToolKernelApprovalHandleV2::from_authority_entropy([22; 32]).unwrap(),
            tool_settlement,
        )
        .unwrap(),
    );
    let encoded = encode_kernel_agent_operation_v2(&authorize_tool).unwrap();
    assert_eq!(&encoded[..3], &[0x82, 0x18, 0x1c]);
    assert_eq!(
        decode_kernel_agent_operation_v2(&encoded).unwrap(),
        authorize_tool
    );

    let release_settlement = signed_approval_settlement(ApprovalPurposeV2::FinalRelease, 30);
    let authorize_release = KernelAgentOperationV2::AuthorizeRelease(
        AuthorizeReleaseRequestV2::new(
            PendingReleaseHandleV2::from_authority_entropy([31; 32]).unwrap(),
            ReleaseKernelApprovalHandleV2::from_authority_entropy([32; 32]).unwrap(),
            release_settlement,
        )
        .unwrap(),
    );
    let encoded = encode_kernel_agent_operation_v2(&authorize_release).unwrap();
    assert_eq!(&encoded[..3], &[0x82, 0x18, 0x21]);
    assert_eq!(
        decode_kernel_agent_operation_v2(&encoded).unwrap(),
        authorize_release
    );

    let ui_unsigned = UnsignedUiAuthenticationSettlementV2::new(
        Digest32V2::new([41; 32]),
        Digest32V2::new([42; 32]),
        43,
        UiAuthenticationPurposeV2::AgentContent,
        Digest32V2::new([44; 32]),
        Digest32V2::new([45; 32]),
        FixedOriginV2::Approval8766,
        FixedOriginV2::Agent8768,
        PrincipalIdV2::new([46; 32]),
        Digest32V2::new([47; 32]),
        Digest32V2::new([48; 32]),
        true,
        true,
        false,
        false,
        49,
        Nonce32V2::new([50; 32]),
        Nonce32V2::new([51; 32]),
        UnixMillisV2::new(52),
        UnixMillisV2::new(53),
    )
    .unwrap();
    let ui_settlement = SignedUiAuthenticationSettlementV2::from_parts(
        ui_unsigned,
        Ed25519KeyIdV2::new([54; 32]),
        Ed25519SignatureV2::new([55; 64]),
    )
    .unwrap();
    let authenticate = KernelAgentOperationV2::AuthenticateAgentUi(
        AuthenticateAgentUiRequestV2::new(
            AgentUiAuthenticationPreparationHandleV2::from_authority_entropy([56; 32]).unwrap(),
            ui_settlement,
        )
        .unwrap(),
    );
    let encoded = encode_kernel_agent_operation_v2(&authenticate).unwrap();
    assert_eq!(&encoded[..3], &[0x82, 0x18, 0x28]);
    assert_eq!(
        decode_kernel_agent_operation_v2(&encoded).unwrap(),
        authenticate
    );

    assert!(AuthorizeToolCallRequestV2::new(
        savana_kernel_protocol::v2::PendingToolCallHandleV2::from_authority_entropy([21; 32])
            .unwrap(),
        ToolKernelApprovalHandleV2::from_authority_entropy([22; 32]).unwrap(),
        signed_approval_settlement(ApprovalPurposeV2::FinalRelease, 60),
    )
    .is_err());
}

fn signed_approval_settlement(purpose: ApprovalPurposeV2, seed: u8) -> SignedApprovalSettlementV2 {
    let unsigned = UnsignedApprovalSettlementV2::new(
        Digest32V2::new([seed; 32]),
        Digest32V2::new([seed.wrapping_add(1); 32]),
        u64::from(seed) + 2,
        purpose,
        Digest32V2::new([seed.wrapping_add(3); 32]),
        ApprovalDecisionV2::Approve,
        PrincipalIdV2::new([seed.wrapping_add(4); 32]),
        Digest32V2::new([seed.wrapping_add(5); 32]),
        Digest32V2::new([seed.wrapping_add(6); 32]),
        true,
        true,
        false,
        false,
        u32::from(seed) + 7,
        Nonce32V2::new([seed.wrapping_add(8); 32]),
        Nonce32V2::new([seed.wrapping_add(9); 32]),
        UnixMillisV2::new(u64::from(seed) + 10),
        UnixMillisV2::new(u64::from(seed) + 11),
    )
    .unwrap();
    SignedApprovalSettlementV2::from_parts(
        unsigned,
        Ed25519KeyIdV2::new([seed.wrapping_add(12); 32]),
        Ed25519SignatureV2::new([seed.wrapping_add(13); 64]),
    )
    .unwrap()
}

#[test]
fn committed_agent_authentication_resume_carries_a_typed_closure_proof() {
    let evidence = AgentAuthenticationClosureEvidenceV2::Indeterminate {
        observation_digest: Digest32V2::new([70; 32]),
        complete_index_generation: 71,
        current_journal_head_digest: Digest32V2::new([72; 32]),
        approvald_key_epoch: 73,
    };
    let unsigned_proof = UnsignedAgentAuthenticationAttemptClosureProofV2::new(
        Digest32V2::new([74; 32]),
        Digest32V2::new([75; 32]),
        76,
        Digest32V2::new([77; 32]),
        78,
        None,
        DurableTaskIdV2::new([79; 32]),
        DurableRunIdV2::new([80; 32]),
        Digest32V2::new([81; 32]),
        Digest32V2::new([82; 32]),
        PrincipalIdV2::new([83; 32]),
        ServiceIdentityV2::new([84; 32]),
        BootIdV2::new([85; 32]),
        ServiceIdentityV2::new([86; 32]),
        BootIdV2::new([87; 32]),
        ServiceIdentityV2::new([88; 32]),
        BootIdV2::new([89; 32]),
        Digest32V2::new([90; 32]),
        Digest32V2::new([91; 32]),
        Nonce32V2::new([92; 32]),
        Digest32V2::new([93; 32]),
        evidence,
        UnixMillisV2::new(94),
        UnixMillisV2::new(95),
    )
    .unwrap();
    let proof = SignedAgentAuthenticationAttemptClosureProofV2::from_parts(
        unsigned_proof,
        Ed25519KeyIdV2::new([96; 32]),
        Ed25519SignatureV2::new([97; 64]),
    )
    .unwrap();
    let request = KernelAgentOperationV2::ResumeCommittedAgentAuthentication(
        ResumeCommittedAgentAuthenticationRequestV2::new(
            signed_task_correlation(100),
            Nonce32V2::new([101; 32]),
            Some(proof),
        )
        .unwrap(),
    );
    let encoded = encode_kernel_agent_operation_v2(&request).unwrap();
    assert_eq!(&encoded[..3], &[0x82, 0x18, 0x2b]);
    assert_eq!(decode_kernel_agent_operation_v2(&encoded).unwrap(), request);

    assert!(ResumeCommittedAgentAuthenticationRequestV2::new(
        signed_task_correlation(110),
        Nonce32V2::new([0; 32]),
        None,
    )
    .is_err());
}

fn signed_task_correlation(seed: u8) -> SignedDurableTaskCorrelationV2 {
    let unsigned = UnsignedDurableTaskCorrelationV2::new(
        Digest32V2::new([seed; 32]),
        Digest32V2::new([seed.wrapping_add(1); 32]),
        u64::from(seed) + 2,
        DurableTaskIdV2::new([seed.wrapping_add(3); 32]),
        ServiceIdentityV2::new([seed.wrapping_add(4); 32]),
        BootIdV2::new([seed.wrapping_add(5); 32]),
        BootIdV2::new([seed.wrapping_add(6); 32]),
        BootIdV2::new([seed.wrapping_add(7); 32]),
        UnixMillisV2::new(u64::from(seed) + 8),
        UnixMillisV2::new(u64::from(seed) + 9),
        UnixMillisV2::new(u64::from(seed) + 10),
    )
    .unwrap();
    SignedDurableTaskCorrelationV2::from_parts(
        unsigned,
        Ed25519KeyIdV2::new([seed.wrapping_add(11); 32]),
        Ed25519SignatureV2::new([seed.wrapping_add(12); 64]),
    )
    .unwrap()
}
