use savana_kernel_protocol::{
    approval_display_digest, connection_binding_digest, encode_client_message,
    encode_server_message, ingress_request_digest, ApprovalAuthMethod, ApprovalChallengeV1,
    ApprovalDecision, ApprovalPurposeV1, ApprovalReceiptV1, ApprovalSubjectV1, BeginRunRequest,
    BootId, BoundedText, ClientMessageV1, CommitPlannerValueRequest, CommitToolResultRequest,
    ConversationId, DecisionTrace, DeriveOperation, DeriveValueRequest, Digest32,
    EvaluateToolCallRequest, EvaluateToolCallResponseV1, HandshakeTranscriptV1,
    IngestUserInputRequest, IngressEnvelopeV1, IngressRequestCommitmentV1, KernelValue, KeyId,
    MaskedDisplayBundleV1, MaterializeExecutionRequest, Nonce32, OperationV1, PlannerCommitProofV1,
    PlannerId, PreparePlannerCallRequest, PrincipalId, ProposeToolCallRequest, ProtocolVersion,
    RegistrySnapshotV1, RequestEnvelopeV1, RequestId, ResponseBodyV1, ResponseEnvelopeV1,
    ResponsePayloadV1, RoleId, RunId, ServerIdentityV1, ServerMessageV1, Signature64,
    SignedApprovalEnvelopeV1, SignedIngressEnvelopeV1, SignedRegistrySnapshotV1, StableCode,
    TaskId, ToolExecutionIdentity, ToolName, UnixMillis, UnsignedApprovalEnvelopeV1,
    UnsignedApprovalReceiptV1, ValueHandle,
};

#[derive(Clone, Copy)]
pub(crate) struct FixtureHandles {
    pub(crate) run: savana_kernel_protocol::RunHandle,
    pub(crate) value: ValueHandle,
    pub(crate) planner: savana_kernel_protocol::PlannerTicketHandle,
    pub(crate) tool: savana_kernel_protocol::ToolHandle,
    pub(crate) pending: savana_kernel_protocol::PendingToolCallHandle,
    pub(crate) execution: savana_kernel_protocol::ExecutionTicketHandle,
}

pub(crate) fn fixture_handles() -> FixtureHandles {
    let (run, value, tool) = decode_begin_run_handle_fixture();
    FixtureHandles {
        run,
        value,
        tool,
        planner: decode_scalar_handle_fixture(12, 0x72, |payload| match payload {
            ResponsePayloadV1::PreparePlannerCall(handle) => handle,
            other => panic!("expected planner handle response, got {other:?}"),
        }),
        pending: decode_scalar_handle_fixture(15, 0x74, |payload| match payload {
            ResponsePayloadV1::ProposeToolCall(handle) => handle,
            other => panic!("expected pending handle response, got {other:?}"),
        }),
        execution: decode_scalar_handle_fixture(17, 0x75, |payload| match payload {
            ResponsePayloadV1::AuthorizeToolCall(handle) => handle,
            other => panic!("expected execution handle response, got {other:?}"),
        }),
    }
}

pub(crate) fn encoded_messages(transcript: &HandshakeTranscriptV1) -> Vec<Vec<u8>> {
    let handles = fixture_handles();
    let begin_input = KernelValue::Null;
    let ingest_input = KernelValue::Null;
    let operations = vec![
        OperationV1::BeginRun(begin_run(transcript, begin_input)),
        OperationV1::IngestUserInput(IngestUserInputRequest {
            run: handles.run,
            envelope: ingress(
                transcript,
                &IngressRequestCommitmentV1::IngestUserInput {
                    run: handles.run,
                    input: ingest_input.clone(),
                },
                0x2a,
            ),
            input: ingest_input,
        }),
        OperationV1::PreparePlannerCall(PreparePlannerCallRequest {
            run: handles.run,
            planner: PlannerId::try_from("fixture-planner").expect("fixed planner ID"),
            prompt_values: vec![handles.value],
        }),
        OperationV1::CommitPlannerValue(CommitPlannerValueRequest {
            run: handles.run,
            proof: PlannerCommitProofV1::DaemonTicket(handles.planner),
            value: KernelValue::Null,
        }),
        OperationV1::DeriveValue(DeriveValueRequest {
            run: handles.run,
            operation: DeriveOperation::AssembleList,
            inputs: vec![handles.value],
        }),
        OperationV1::ProposeToolCall(ProposeToolCallRequest {
            run: handles.run,
            tool: handles.tool,
            arguments: Vec::new(),
        }),
        OperationV1::EvaluateToolCall(EvaluateToolCallRequest {
            pending: handles.pending,
            attestations: Vec::new(),
        }),
        OperationV1::AuthorizeToolCall(savana_kernel_protocol::AuthorizeToolCallRequest {
            pending: handles.pending,
            receipt: receipt(),
        }),
        OperationV1::MaterializeExecution(MaterializeExecutionRequest {
            ticket: handles.execution,
        }),
        OperationV1::CommitToolResult(CommitToolResultRequest {
            ticket: handles.execution,
            result: KernelValue::Bool(true),
        }),
    ];
    let mut messages = operations
        .into_iter()
        .map(|operation| {
            encode_client_message(&ClientMessageV1::Request(RequestEnvelopeV1 {
                version: ProtocolVersion::new(1, 0),
                request_id: RequestId::new([0x11; 16]),
                deadline_unix_ms: UnixMillis::new(1_500),
                operation,
            }))
            .expect("fixed policy request encodes")
        })
        .collect::<Vec<_>>();
    messages.push(
        encode_server_message(&ServerMessageV1::Response(ResponseEnvelopeV1 {
            version: ProtocolVersion::new(1, 0),
            request_id: RequestId::new([0x11; 16]),
            body: ResponseBodyV1::Ok(ResponsePayloadV1::EvaluateToolCall(
                EvaluateToolCallResponseV1::NeedsApproval {
                    envelope: approval_envelope(),
                    trace: DecisionTrace {
                        rule_ids: vec![1, 4],
                        public_reason: StableCode::ApprovalRequired,
                    },
                },
            )),
        }))
        .expect("fixed approval response encodes"),
    );
    messages.push(
        encode_server_message(&ServerMessageV1::Response(ResponseEnvelopeV1 {
            version: ProtocolVersion::new(1, 0),
            request_id: RequestId::new([0x11; 16]),
            body: ResponseBodyV1::Err(StableCode::HandleAlreadyConsumed),
        }))
        .expect("fixed stable error response encodes"),
    );
    messages
}

fn ingress(
    transcript: &HandshakeTranscriptV1,
    commitment: &IngressRequestCommitmentV1,
    nonce_byte: u8,
) -> SignedIngressEnvelopeV1 {
    SignedIngressEnvelopeV1 {
        unsigned: IngressEnvelopeV1 {
            principal: PrincipalId::try_from("fixture-principal").expect("fixed principal"),
            conversation_id: ConversationId::try_from("fixture-conversation")
                .expect("fixed conversation"),
            request_digest: ingress_request_digest(commitment).expect("fixed request commitment"),
            issued_at: UnixMillis::new(1_000),
            expires_at: UnixMillis::new(2_000),
            nonce: Nonce32::new([nonce_byte; 32]),
            authority_session_id: Nonce32::new([0x23; 32]),
            authentication_context_digest: Digest32::new([0x24; 32]),
            role: RoleId::try_from("operator").expect("fixed role"),
            policy_digest: transcript.server.policy_digest,
            boot_id: transcript.server.boot_id,
            connection_binding_digest: connection_binding_digest(transcript)
                .expect("fixed connection binding"),
        },
        key_id: KeyId::try_from("fixture-ingress-key").expect("fixed ingress key"),
        signature: Signature64::new([0x25; 64]),
    }
}

fn begin_run(transcript: &HandshakeTranscriptV1, input: KernelValue) -> BeginRunRequest {
    BeginRunRequest {
        ingress: ingress(
            transcript,
            &IngressRequestCommitmentV1::BeginRun {
                input: input.clone(),
            },
            0x22,
        ),
        input,
        registry: SignedRegistrySnapshotV1 {
            unsigned: RegistrySnapshotV1 {
                version: 7,
                previous_digest: None,
                tools: Vec::new(),
                issued_at: UnixMillis::new(1_000),
                expires_at: UnixMillis::new(2_000),
            },
            key_id: KeyId::try_from("fixture-registry-key").expect("fixed registry key"),
            signature: Signature64::new([0x26; 64]),
        },
    }
}

fn tool_identity() -> ToolExecutionIdentity {
    ToolExecutionIdentity {
        name: ToolName::try_from("fixture-tool").expect("fixed tool name"),
        descriptor_digest: Digest32::new([0x31; 32]),
        registry_version: 7,
    }
}

fn server_identity() -> ServerIdentityV1 {
    ServerIdentityV1 {
        daemon_key_id: KeyId::try_from("fixture-daemon-key").expect("fixed daemon key"),
        boot_id: BootId::new([0x32; 32]),
        protocol: ProtocolVersion::new(1, 0),
        release_digest: Digest32::new([0x33; 32]),
        policy_digest: Digest32::new([0x34; 32]),
        policy_version: 9,
        model_manifest_digest: Digest32::new([0x35; 32]),
        approval_key_set_digest: Digest32::new([0x36; 32]),
        resource_profile_digest: Digest32::new([0x37; 32]),
    }
}

fn challenge() -> ApprovalChallengeV1 {
    let handles = fixture_handles();
    ApprovalChallengeV1 {
        challenge_id: Nonce32::new([0x41; 32]),
        purpose: ApprovalPurposeV1::ToolMaterialization,
        subject: ApprovalSubjectV1::ToolCall {
            pending: handles.pending,
            argument_digest: Digest32::new([0x43; 32]),
            provenance_digest: Digest32::new([0x44; 32]),
        },
        boot_id: BootId::new([0x45; 32]),
        run_id: RunId::new([0x46; 32]),
        principal: PrincipalId::try_from("fixture-principal").expect("fixed principal"),
        conversation_id: ConversationId::try_from("fixture-conversation")
            .expect("fixed conversation"),
        task_id: TaskId::try_from("fixture-task").expect("fixed task"),
        tool: tool_identity(),
        destination_digest: Digest32::new([0x47; 32]),
        policy_version: 9,
        issued_at: UnixMillis::new(1_000),
        expires_at: UnixMillis::new(2_000),
        nonce: Nonce32::new([0x48; 32]),
    }
}

fn decode_begin_run_handle_fixture() -> (
    savana_kernel_protocol::RunHandle,
    ValueHandle,
    savana_kernel_protocol::ToolHandle,
) {
    let mut encoder = response_prefix(10);
    encoder
        .array(3)
        .expect("fixed array")
        .bytes(&[0x70; 32])
        .expect("fixed run")
        .bytes(&[0x71; 32])
        .expect("fixed value")
        .array(1)
        .expect("fixed active tools")
        .array(2)
        .expect("fixed active tool")
        .bytes(&[0x73; 32])
        .expect("fixed tool")
        .array(3)
        .expect("fixed tool identity")
        .str("fixture-tool")
        .expect("fixed tool name")
        .bytes(&[0x31; 32])
        .expect("fixed digest")
        .u64(7)
        .expect("fixed version");
    match minicbor::decode::<ServerMessageV1>(&encoder.into_writer())
        .expect("encoded daemon response decodes")
    {
        ServerMessageV1::Response(ResponseEnvelopeV1 {
            body:
                ResponseBodyV1::Ok(ResponsePayloadV1::BeginRun(
                    savana_kernel_protocol::BeginRunResponse {
                        run,
                        initial_value,
                        mut active_tools,
                    },
                )),
            ..
        }) => (run, initial_value, active_tools.remove(0).handle),
        other => panic!("expected begin-run handle response, got {other:?}"),
    }
}

fn decode_scalar_handle_fixture<T>(
    tag: u8,
    byte: u8,
    extract: impl FnOnce(ResponsePayloadV1) -> T,
) -> T {
    let mut encoder = response_prefix(tag);
    encoder.bytes(&[byte; 32]).expect("fixed handle response");
    match minicbor::decode::<ServerMessageV1>(&encoder.into_writer())
        .expect("encoded daemon response decodes")
    {
        ServerMessageV1::Response(ResponseEnvelopeV1 {
            body: ResponseBodyV1::Ok(payload),
            ..
        }) => extract(payload),
        other => panic!("expected handle response, got {other:?}"),
    }
}

fn response_prefix(tag: u8) -> minicbor::Encoder<Vec<u8>> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(2)
        .expect("fixed server message")
        .u8(2)
        .expect("fixed server response tag")
        .array(3)
        .expect("fixed response envelope")
        .array(2)
        .expect("fixed protocol version")
        .u16(1)
        .expect("fixed major")
        .u16(0)
        .expect("fixed minor")
        .bytes(&[0x11; 16])
        .expect("fixed request ID")
        .array(2)
        .expect("fixed response body")
        .u8(0)
        .expect("fixed success tag")
        .array(2)
        .expect("fixed response payload")
        .u8(tag)
        .expect("fixed operation response tag");
    encoder
}

fn receipt() -> ApprovalReceiptV1 {
    ApprovalReceiptV1 {
        unsigned: UnsignedApprovalReceiptV1 {
            envelope_digest: Digest32::new([0x51; 32]),
            challenge: challenge(),
            decision: ApprovalDecision::Approve,
            approval_principal: PrincipalId::try_from("fixture-approver").expect("fixed approver"),
            auth_method: ApprovalAuthMethod::WebAuthnUv,
            approval_key_id: KeyId::try_from("fixture-approval-key").expect("fixed approval key"),
            issued_at: UnixMillis::new(1_100),
            expires_at: UnixMillis::new(1_900),
            receipt_nonce: Nonce32::new([0x52; 32]),
        },
        signature: Signature64::new([0x53; 64]),
    }
}

fn approval_envelope() -> SignedApprovalEnvelopeV1 {
    let display = MaskedDisplayBundleV1 {
        purpose_label: BoundedText::try_from("execute tool").expect("fixed label"),
        tool_label: BoundedText::try_from("fixture tool").expect("fixed label"),
        masked_destination: KernelValue::Text(
            BoundedText::try_from("https://masked.example").expect("fixed display"),
        ),
        masked_output: KernelValue::Null,
    };
    SignedApprovalEnvelopeV1 {
        unsigned: UnsignedApprovalEnvelopeV1 {
            daemon_identity: server_identity(),
            challenge: challenge(),
            display_digest: approval_display_digest(&display).expect("fixed display digest"),
            display,
        },
        daemon_key_id: KeyId::try_from("fixture-daemon-key").expect("fixed daemon key"),
        signature: Signature64::new([0x55; 64]),
    }
}
