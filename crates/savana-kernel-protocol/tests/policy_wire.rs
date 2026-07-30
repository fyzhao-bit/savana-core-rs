use savana_kernel_protocol::{
    approval_display_digest, connection_binding_digest, decode_client_message,
    decode_server_message, encode_client_message, encode_server_message, ingress_request_digest,
    ActiveToolView, ApprovalAuthMethod, ApprovalChallengeV1, ApprovalDecision, ApprovalPurposeV1,
    ApprovalReceiptV1, ApprovalSubjectV1, ArgumentName, ArtifactId, AttemptKindV1,
    AuthorizeToolCallRequest, BeginRunRequest, BeginRunResponse, BootId, BoundedArgumentNames,
    BoundedBytes, BoundedList, BoundedObject, BoundedText, ClientId, ClientMessageV1,
    CommitPlannerValueRequest, CommitToolResultRequest, ConstraintId, ConversationId,
    DecisionTrace, DeriveOperation, DeriveValueRequest, Digest32, EvaluateToolCallRequest,
    EvaluateToolCallResponseV1, ExecutionEnvelope, ExecutionTicketHandle, IngestUserInputRequest,
    IngressEnvelopeV1, IngressRequestCommitmentV1, KernelValue, KeyId, MaskedDisplayBundleV1,
    MaterializeExecutionRequest, NamedArgumentHandle, Nonce32, OntologyEffectV1, OntologyEntryV1,
    OntologyEventV1, OntologySnapshotV1, OperationV1, PendingToolCallHandle, PlannerCommitProofV1,
    PlannerId, PlannerTicketHandle, PreparePlannerCallRequest, PrincipalId, ProposeToolCallRequest,
    ProtocolVersion, RegistrySnapshotV1, RequestEnvelopeV1, RequestId, ResponseBodyV1,
    ResponseEnvelopeV1, ResponsePayloadV1, RoleId, RunHandle, RunId, ServerIdentityV1,
    ServerMessageV1, Signature64, SignedApprovalEnvelopeV1, SignedIngressEnvelopeV1,
    SignedOntologyEventV1, SignedOntologySnapshotV1, SignedPlannerAttestationV1,
    SignedRegistrySnapshotV1, SignedValidatorAttestationV1, StableCode, TaskId, ToolDescriptorV1,
    ToolExecutionIdentity, ToolHandle, ToolName, UnixMillis, UnsignedApprovalEnvelopeV1,
    UnsignedApprovalReceiptV1, ValidatorId, ValidatorVerdictV1, ValueHandle,
};
use sha2::{Digest, Sha256};

#[path = "../examples/support/policy_flow_fixture.rs"]
mod policy_flow_fixture;
mod support;

fn signed_ingress() -> SignedIngressEnvelopeV1 {
    support::signed_ingress()
}

fn begin_run_request() -> BeginRunRequest {
    BeginRunRequest {
        ingress: signed_ingress(),
        input: KernelValue::Null,
        registry: SignedRegistrySnapshotV1 {
            unsigned: RegistrySnapshotV1 {
                version: 7,
                previous_digest: None,
                tools: Vec::new(),
                issued_at: UnixMillis::new(1_000),
                expires_at: UnixMillis::new(2_000),
            },
            key_id: KeyId::try_from("fixture-registry-key").unwrap(),
            signature: Signature64::new([0x26; 64]),
        },
    }
}

#[test]
fn ingress_begin_and_ingest_have_only_the_new_exact_shapes() {
    let ingress = support::signed_ingress();
    let ingress_bytes = minicbor::to_vec(&ingress.unsigned).unwrap();
    assert_eq!(ingress_bytes[0], 0x8c);

    let begin = BeginRunRequest {
        ingress: ingress.clone(),
        input: KernelValue::Null,
        registry: support::signed_registry(),
    };
    let begin_bytes = minicbor::to_vec(&begin).unwrap();
    assert_eq!(begin_bytes[0], 0x83);
    assert_eq!(
        minicbor::decode::<BeginRunRequest>(&begin_bytes).unwrap(),
        begin
    );

    let ingest = IngestUserInputRequest {
        run: support::run_handle_with_byte(0x70),
        envelope: ingress,
        input: KernelValue::Bool(true),
    };
    let ingest_bytes = minicbor::to_vec(&ingest).unwrap();
    assert_eq!(ingest_bytes[0], 0x83);
    assert_eq!(
        minicbor::decode::<IngestUserInputRequest>(&ingest_bytes).unwrap(),
        ingest
    );
}

#[test]
fn legacy_ingress_lengths_and_bare_begin_role_are_rejected() {
    let old_eight_item_ingress = support::legacy_eight_item_ingress_bytes();
    assert!(minicbor::decode::<IngressEnvelopeV1>(&old_eight_item_ingress).is_err());

    let extra_ingress_slot = support::thirteen_item_ingress_bytes();
    assert!(minicbor::decode::<IngressEnvelopeV1>(&extra_ingress_slot).is_err());

    let legacy_begin = support::legacy_begin_with_role_text_bytes();
    assert!(minicbor::decode::<BeginRunRequest>(&legacy_begin).is_err());

    let old_ingest = support::legacy_two_item_ingest_bytes();
    assert!(minicbor::decode::<IngestUserInputRequest>(&old_ingest).is_err());
}

fn signed_ingress_with_raw_unsigned(
    unsigned: &[u8],
    wrapper_len: u64,
    include_signature: bool,
    include_extra: bool,
) -> Vec<u8> {
    let fixture = support::signed_ingress();
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder.array(wrapper_len).unwrap();
    let mut encoded = encoder.into_writer();
    encoded.extend_from_slice(unsigned);
    let mut encoder = minicbor::Encoder::new(encoded);
    encoder.encode(fixture.key_id).unwrap();
    if include_signature {
        encoder.encode(fixture.signature).unwrap();
    }
    if include_extra {
        encoder.null().unwrap();
    }
    encoder.into_writer()
}

fn begin_payload_with_raw_ingress(
    ingress: &[u8],
    payload_len: u64,
    legacy_role: bool,
    include_registry: bool,
    include_extra: bool,
) -> Vec<u8> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder.array(payload_len).unwrap();
    let mut encoded = encoder.into_writer();
    encoded.extend_from_slice(ingress);
    let mut encoder = minicbor::Encoder::new(encoded);
    if legacy_role {
        encoder
            .encode(RoleId::try_from("operator").unwrap())
            .unwrap();
    } else {
        encoder.encode(KernelValue::Null).unwrap();
    }
    if include_registry {
        encoder.encode(support::signed_registry()).unwrap();
    }
    if include_extra {
        encoder.null().unwrap();
    }
    encoder.into_writer()
}

fn ingest_payload(payload_len: u64, include_input: bool, include_extra: bool) -> Vec<u8> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(payload_len)
        .unwrap()
        .encode(support::run_handle_with_byte(0x70))
        .unwrap()
        .encode(support::signed_ingress())
        .unwrap();
    if include_input {
        encoder.encode(KernelValue::Null).unwrap();
    }
    if include_extra {
        encoder.null().unwrap();
    }
    encoder.into_writer()
}

fn request_with_raw_operation_payload(tag: u8, payload: &[u8]) -> Vec<u8> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(2)
        .unwrap()
        .u8(2)
        .unwrap()
        .array(4)
        .unwrap()
        .encode(ProtocolVersion::new(1, 0))
        .unwrap()
        .encode(RequestId::new([0x11; 16]))
        .unwrap()
        .encode(UnixMillis::new(1_500))
        .unwrap()
        .array(2)
        .unwrap()
        .u8(tag)
        .unwrap();
    let mut encoded = encoder.into_writer();
    encoded.extend_from_slice(payload);
    encoded
}

#[test]
fn malformed_policy_operation_shapes_map_to_the_stable_wire_error() {
    let valid_unsigned = minicbor::to_vec(&support::signed_ingress().unsigned).unwrap();
    let valid_signed = minicbor::to_vec(support::signed_ingress()).unwrap();

    let ingress_len_8 = signed_ingress_with_raw_unsigned(
        &support::legacy_eight_item_ingress_bytes(),
        3,
        true,
        false,
    );
    let ingress_len_13 =
        signed_ingress_with_raw_unsigned(&support::thirteen_item_ingress_bytes(), 3, true, false);
    let signed_len_2 = signed_ingress_with_raw_unsigned(&valid_unsigned, 2, false, false);
    let signed_len_4 = signed_ingress_with_raw_unsigned(&valid_unsigned, 4, true, true);

    let cases = vec![
        (
            10,
            begin_payload_with_raw_ingress(&ingress_len_8, 3, false, true, false),
        ),
        (
            10,
            begin_payload_with_raw_ingress(&ingress_len_13, 3, false, true, false),
        ),
        (
            10,
            begin_payload_with_raw_ingress(&signed_len_2, 3, false, true, false),
        ),
        (
            10,
            begin_payload_with_raw_ingress(&signed_len_4, 3, false, true, false),
        ),
        (
            10,
            begin_payload_with_raw_ingress(&valid_signed, 2, false, false, false),
        ),
        (
            10,
            begin_payload_with_raw_ingress(&valid_signed, 4, false, true, true),
        ),
        (10, support::legacy_begin_with_role_text_bytes()),
        (11, ingest_payload(2, false, false)),
        (11, ingest_payload(4, true, true)),
    ];

    for (tag, payload) in cases {
        let message = request_with_raw_operation_payload(tag, &payload);
        assert_eq!(
            decode_client_message(&message, &support::compiled_effective_limits())
                .unwrap_err()
                .code(),
            StableCode::ProtocolMalformedCbor
        );
    }
}

#[test]
fn connection_binding_is_the_domain_hash_of_the_exact_transcript() {
    let transcript = support::handshake_transcript();
    let canonical = minicbor::to_vec(&transcript).unwrap();
    let mut reference = Sha256::new();
    reference.update(b"SAVANA_CONNECTION_BINDING_V1\0");
    reference.update(&canonical);
    assert_eq!(
        connection_binding_digest(&transcript).unwrap(),
        Digest32::new(reference.finalize().into())
    );
    assert_eq!(
        connection_binding_digest(&transcript).unwrap(),
        support::digest32_from_hex(
            "3d543784844ecf92135e64a4d50ba64f1e7988dbb32ea0c1b9e8b785ff95dc8f"
        )
    );

    let mut changed = transcript.clone();
    changed.server.boot_id = BootId::new([0x91; 32]);
    assert_ne!(
        connection_binding_digest(&transcript).unwrap(),
        connection_binding_digest(&changed).unwrap()
    );
}

#[test]
fn request_commitment_binds_variant_input_and_run() {
    let mutations = vec![
        (KernelValue::Null, KernelValue::Bool(false)),
        (KernelValue::Bool(false), KernelValue::Bool(true)),
        (KernelValue::Integer(7), KernelValue::Integer(8)),
        (
            KernelValue::Text(BoundedText::new("a").unwrap()),
            KernelValue::Text(BoundedText::new("b").unwrap()),
        ),
        (
            KernelValue::Bytes(BoundedBytes::new(vec![1]).unwrap()),
            KernelValue::Bytes(BoundedBytes::new(vec![2]).unwrap()),
        ),
        (
            KernelValue::List(BoundedList::new(vec![KernelValue::Bool(false)]).unwrap()),
            KernelValue::List(BoundedList::new(vec![KernelValue::Bool(true)]).unwrap()),
        ),
        (
            KernelValue::Object(
                BoundedObject::new(vec![(
                    ArgumentName::try_from("nested").unwrap(),
                    KernelValue::Null,
                )])
                .unwrap(),
            ),
            KernelValue::Object(
                BoundedObject::new(vec![(
                    ArgumentName::try_from("nested").unwrap(),
                    KernelValue::Bool(false),
                )])
                .unwrap(),
            ),
        ),
        (
            KernelValue::Object(
                BoundedObject::new(vec![(
                    ArgumentName::try_from("left").unwrap(),
                    KernelValue::Null,
                )])
                .unwrap(),
            ),
            KernelValue::Object(
                BoundedObject::new(vec![(
                    ArgumentName::try_from("right").unwrap(),
                    KernelValue::Null,
                )])
                .unwrap(),
            ),
        ),
    ];
    let fixed_run = support::run_handle_with_byte(0x41);
    for (before, after) in mutations {
        assert_ne!(
            minicbor::to_vec(&before).unwrap(),
            minicbor::to_vec(&after).unwrap()
        );
        assert_ne!(
            ingress_request_digest(&IngressRequestCommitmentV1::BeginRun {
                input: before.clone(),
            })
            .unwrap(),
            ingress_request_digest(&IngressRequestCommitmentV1::BeginRun {
                input: after.clone(),
            })
            .unwrap()
        );
        assert_ne!(
            ingress_request_digest(&IngressRequestCommitmentV1::IngestUserInput {
                run: fixed_run,
                input: before,
            })
            .unwrap(),
            ingress_request_digest(&IngressRequestCommitmentV1::IngestUserInput {
                run: fixed_run,
                input: after,
            })
            .unwrap()
        );
    }

    let begin_null = IngressRequestCommitmentV1::BeginRun {
        input: KernelValue::Null,
    };
    let ingest_a = IngressRequestCommitmentV1::IngestUserInput {
        run: fixed_run,
        input: KernelValue::Bool(true),
    };
    let ingest_b = IngressRequestCommitmentV1::IngestUserInput {
        run: support::run_handle_with_byte(0x42),
        input: KernelValue::Bool(true),
    };
    assert_ne!(
        ingress_request_digest(&IngressRequestCommitmentV1::BeginRun {
            input: KernelValue::Bool(true),
        })
        .unwrap(),
        ingress_request_digest(&ingest_a).unwrap()
    );
    assert_ne!(
        ingress_request_digest(&ingest_a).unwrap(),
        ingress_request_digest(&ingest_b).unwrap()
    );
    assert_eq!(
        ingress_request_digest(&begin_null).unwrap(),
        support::digest32_from_hex(
            "99dbaa60637f157d913d024ca99693f92ca8dba64490e8f6cbd0eeec20f99665"
        )
    );

    let ingest_fixed = IngressRequestCommitmentV1::IngestUserInput {
        run: support::run_handle_with_byte(0x70),
        input: KernelValue::Null,
    };
    assert_eq!(
        ingress_request_digest(&ingest_fixed).unwrap(),
        support::digest32_from_hex(
            "5368417421be910eec040a38eebdb30744f67005890da2ce3cf17ecca7048da5"
        )
    );

    let baseline = ingress_request_digest(&IngressRequestCommitmentV1::IngestUserInput {
        run: fixed_run,
        input: KernelValue::Null,
    })
    .unwrap();
    for index in 0..32 {
        let mut encoded = Vec::with_capacity(34);
        encoded.extend_from_slice(&[0x58, 0x20]);
        encoded.extend_from_slice(&[0x41; 32]);
        encoded[index + 2] = 0x42;
        let mutated_run = minicbor::decode(&encoded).unwrap();
        assert_ne!(
            baseline,
            ingress_request_digest(&IngressRequestCommitmentV1::IngestUserInput {
                run: mutated_run,
                input: KernelValue::Null,
            })
            .unwrap(),
            "run-handle byte {index} must be committed"
        );
    }
}

#[test]
fn commitment_encoding_is_a_closed_two_item_tagged_union() {
    let begin = IngressRequestCommitmentV1::BeginRun {
        input: KernelValue::Null,
    };
    let begin_bytes = minicbor::to_vec(&begin).unwrap();
    assert_eq!(begin_bytes, vec![0x82, 0x00, 0x81, 0x82, 0x00, 0xf6]);
    assert_eq!(
        minicbor::decode::<IngressRequestCommitmentV1>(&begin_bytes).unwrap(),
        begin
    );
    let ingest = IngressRequestCommitmentV1::IngestUserInput {
        run: support::run_handle_with_byte(0x70),
        input: KernelValue::Null,
    };
    let ingest_bytes = minicbor::to_vec(&ingest).unwrap();
    assert_eq!(
        ingest_bytes,
        support::decode_hex(concat!(
            "8201825820",
            "7070707070707070",
            "7070707070707070",
            "7070707070707070",
            "7070707070707070",
            "8200f6"
        ))
    );
    assert_eq!(
        minicbor::decode::<IngressRequestCommitmentV1>(&ingest_bytes).unwrap(),
        ingest
    );

    let mut unknown = minicbor::to_vec(&begin).unwrap();
    unknown[1] = 2;
    let error = minicbor::decode::<IngressRequestCommitmentV1>(&unknown).unwrap_err();
    assert!(error
        .to_string()
        .contains(StableCode::ProtocolMalformedCbor.as_str()));
}

#[test]
fn commitment_decode_rejects_noncanonical_children_and_shapes() {
    let mut non_shortest_run_handle = vec![0x82, 0x01, 0x82, 0x59, 0x00, 0x20];
    non_shortest_run_handle.extend_from_slice(&[0x70; 32]);
    non_shortest_run_handle.extend_from_slice(&[0x82, 0x00, 0xf6]);

    let cases = [
        (
            "outer array length",
            vec![0x98, 0x02, 0x00, 0x81, 0x82, 0x00, 0xf6],
        ),
        (
            "commitment tag",
            vec![0x82, 0x18, 0x00, 0x81, 0x82, 0x00, 0xf6],
        ),
        (
            "payload array length",
            vec![0x82, 0x00, 0x98, 0x01, 0x82, 0x00, 0xf6],
        ),
        (
            "KernelValue array length",
            vec![0x82, 0x00, 0x81, 0x98, 0x02, 0x00, 0xf6],
        ),
        (
            "KernelValue tag",
            vec![0x82, 0x00, 0x81, 0x82, 0x18, 0x00, 0xf6],
        ),
        (
            "KernelValue integer payload",
            vec![0x82, 0x00, 0x81, 0x82, 0x02, 0x18, 0x00],
        ),
        (
            "KernelValue text length",
            vec![0x82, 0x00, 0x81, 0x82, 0x03, 0x78, 0x01, b'a'],
        ),
        (
            "KernelValue byte-string length",
            vec![0x82, 0x00, 0x81, 0x82, 0x04, 0x58, 0x01, 0xaa],
        ),
        (
            "KernelValue list length",
            vec![0x82, 0x00, 0x81, 0x82, 0x05, 0x98, 0x01, 0x82, 0x00, 0xf6],
        ),
        (
            "KernelValue object key length",
            vec![
                0x82, 0x00, 0x81, 0x82, 0x06, 0x81, 0x82, 0x78, 0x01, b'a', 0x82, 0x00, 0xf6,
            ],
        ),
        ("RunHandle byte-string length", non_shortest_run_handle),
    ];

    let mut accepted = Vec::new();
    for (name, bytes) in cases {
        match minicbor::decode::<IngressRequestCommitmentV1>(&bytes) {
            Ok(_) => accepted.push(name),
            Err(error) => assert!(
                error
                    .to_string()
                    .contains(StableCode::ProtocolMalformedCbor.as_str()),
                "{name} returned {error}"
            ),
        }
    }
    assert!(accepted.is_empty(), "accepted encodings: {accepted:?}");

    let commitment = IngressRequestCommitmentV1::BeginRun {
        input: KernelValue::Null,
    };
    let mut wrapped = vec![0xf6];
    wrapped.extend_from_slice(&minicbor::to_vec(&commitment).unwrap());
    wrapped.push(0xf5);
    let mut decoder = minicbor::Decoder::new(&wrapped);
    decoder.null().unwrap();
    assert_eq!(
        decoder.decode::<IngressRequestCommitmentV1>().unwrap(),
        commitment
    );
    assert!(decoder.bool().unwrap());

    let mut wrapped_noncanonical = vec![0xf6];
    wrapped_noncanonical.extend_from_slice(&[0x98, 0x02, 0x00, 0x81, 0x82, 0x00, 0xf6]);
    let mut decoder = minicbor::Decoder::new(&wrapped_noncanonical);
    decoder.null().unwrap();
    let error = decoder.decode::<IngressRequestCommitmentV1>().unwrap_err();
    assert!(error
        .to_string()
        .contains(StableCode::ProtocolMalformedCbor.as_str()));
}

fn request(operation: OperationV1) -> ClientMessageV1 {
    ClientMessageV1::Request(RequestEnvelopeV1 {
        version: ProtocolVersion::new(1, 0),
        request_id: RequestId::new([0x11; 16]),
        deadline_unix_ms: UnixMillis::new(1_500),
        operation,
    })
}

trait FixtureHandle: Sized {
    fn from_fixture(handles: policy_flow_fixture::FixtureHandles) -> Self;
}

macro_rules! fixture_handle {
    ($type:ty, $field:ident) => {
        impl FixtureHandle for $type {
            fn from_fixture(handles: policy_flow_fixture::FixtureHandles) -> Self {
                handles.$field
            }
        }
    };
}

fixture_handle!(RunHandle, run);
fixture_handle!(ValueHandle, value);
fixture_handle!(PlannerTicketHandle, planner);
fixture_handle!(ToolHandle, tool);
fixture_handle!(PendingToolCallHandle, pending);
fixture_handle!(ExecutionTicketHandle, execution);

fn opaque<T: FixtureHandle>(_byte: u8) -> T {
    T::from_fixture(policy_flow_fixture::fixture_handles())
}

fn tool_identity(name: &str) -> ToolExecutionIdentity {
    ToolExecutionIdentity {
        name: ToolName::try_from(name).unwrap(),
        descriptor_digest: Digest32::new([0x31; 32]),
        registry_version: 7,
    }
}

fn tool_descriptor(name: &str) -> ToolDescriptorV1 {
    ToolDescriptorV1 {
        identity: tool_identity(name),
        provider_id: BoundedText::try_from("").unwrap(),
        roles: vec![],
        input_schema_digest: Digest32::new([0x38; 32]),
        output_schema_digest: Digest32::new([0x39; 32]),
        attempt: AttemptKindV1::Read,
        constraint_ids: vec![],
        validator_ids: vec![],
        projection_digest: Digest32::new([0x3a; 32]),
    }
}

fn swap_unique_cbor_texts(encoded: &[u8], left: &str, right: &str) -> Vec<u8> {
    fn encoded_text(value: &str) -> Vec<u8> {
        let mut encoder = minicbor::Encoder::new(Vec::new());
        encoder.str(value).unwrap();
        encoder.into_writer()
    }

    let left = encoded_text(left);
    let right = encoded_text(right);
    let left_positions = encoded
        .windows(left.len())
        .enumerate()
        .filter_map(|(index, window)| (window == left).then_some(index))
        .collect::<Vec<_>>();
    let right_positions = encoded
        .windows(right.len())
        .enumerate()
        .filter_map(|(index, window)| (window == right).then_some(index))
        .collect::<Vec<_>>();
    assert_eq!(left_positions.len(), 1);
    assert_eq!(right_positions.len(), 1);
    let left_position = left_positions[0];
    let right_position = right_positions[0];
    assert!(left_position < right_position);

    let mut swapped = Vec::with_capacity(encoded.len());
    swapped.extend_from_slice(&encoded[..left_position]);
    swapped.extend_from_slice(&right);
    swapped.extend_from_slice(&encoded[left_position + left.len()..right_position]);
    swapped.extend_from_slice(&left);
    swapped.extend_from_slice(&encoded[right_position + right.len()..]);
    swapped
}

fn assert_canonical_text_collection<T>(canonical: &T, reverse: &T)
where
    T: minicbor::Encode<()>
        + for<'bytes> minicbor::Decode<'bytes, ()>
        + PartialEq
        + std::fmt::Debug,
{
    let encoded = minicbor::to_vec(canonical).unwrap();
    assert_eq!(&minicbor::decode::<T>(&encoded).unwrap(), canonical);
    assert!(minicbor::to_vec(reverse).is_err());
    assert!(minicbor::decode::<T>(&swap_unique_cbor_texts(&encoded, "b", "aa")).is_err());
}

fn server_identity() -> ServerIdentityV1 {
    ServerIdentityV1 {
        daemon_key_id: KeyId::try_from("fixture-daemon-key").unwrap(),
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

fn approval_challenge() -> ApprovalChallengeV1 {
    ApprovalChallengeV1 {
        challenge_id: Nonce32::new([0x41; 32]),
        purpose: ApprovalPurposeV1::ToolMaterialization,
        subject: ApprovalSubjectV1::ToolCall {
            pending: opaque(0x42),
            argument_digest: Digest32::new([0x43; 32]),
            provenance_digest: Digest32::new([0x44; 32]),
        },
        boot_id: BootId::new([0x45; 32]),
        run_id: RunId::new([0x46; 32]),
        principal: PrincipalId::try_from("fixture-principal").unwrap(),
        conversation_id: ConversationId::try_from("fixture-conversation").unwrap(),
        task_id: TaskId::try_from("fixture-task").unwrap(),
        tool: tool_identity("fixture-tool"),
        destination_digest: Digest32::new([0x47; 32]),
        policy_version: 9,
        issued_at: UnixMillis::new(1_000),
        expires_at: UnixMillis::new(2_000),
        nonce: Nonce32::new([0x48; 32]),
    }
}

fn approval_receipt() -> ApprovalReceiptV1 {
    ApprovalReceiptV1 {
        unsigned: UnsignedApprovalReceiptV1 {
            envelope_digest: Digest32::new([0x51; 32]),
            challenge: approval_challenge(),
            decision: ApprovalDecision::Approve,
            approval_principal: PrincipalId::try_from("fixture-approver").unwrap(),
            auth_method: ApprovalAuthMethod::WebAuthnUv,
            approval_key_id: KeyId::try_from("fixture-approval-key").unwrap(),
            issued_at: UnixMillis::new(1_100),
            expires_at: UnixMillis::new(1_900),
            receipt_nonce: Nonce32::new([0x52; 32]),
        },
        signature: Signature64::new([0x53; 64]),
    }
}

fn approval_envelope() -> SignedApprovalEnvelopeV1 {
    SignedApprovalEnvelopeV1 {
        unsigned: UnsignedApprovalEnvelopeV1 {
            daemon_identity: server_identity(),
            challenge: approval_challenge(),
            display: MaskedDisplayBundleV1 {
                purpose_label: BoundedText::try_from("execute tool").unwrap(),
                tool_label: BoundedText::try_from("fixture tool").unwrap(),
                masked_destination: KernelValue::Text(BoundedText::try_from("https://…").unwrap()),
                masked_output: KernelValue::Null,
            },
            display_digest: Digest32::new([0x54; 32]),
        },
        daemon_key_id: KeyId::try_from("fixture-daemon-key").unwrap(),
        signature: Signature64::new([0x55; 64]),
    }
}

#[test]
fn approval_display_digest_has_one_domain_separated_definition() {
    let display = approval_envelope().unsigned.display;
    let canonical = minicbor::to_vec(&display).unwrap();
    let mut hasher = Sha256::new();
    hasher.update(b"SAVANA_APPROVAL_DISPLAY_V1\0");
    hasher.update(canonical);
    assert_eq!(
        approval_display_digest(&display).unwrap(),
        Digest32::new(hasher.finalize().into())
    );
}

fn nested_object_value(semantic_depth: usize) -> KernelValue {
    assert!(semantic_depth >= 1);
    let mut value = KernelValue::Null;
    for _ in 1..semantic_depth {
        value = KernelValue::Object(
            BoundedObject::try_from(vec![(ArgumentName::try_from("a").unwrap(), value)]).unwrap(),
        );
    }
    value
}

fn needs_approval_response(masked_destination: KernelValue) -> ServerMessageV1 {
    let mut envelope = approval_envelope();
    envelope.unsigned.display.masked_destination = masked_destination;
    ServerMessageV1::Response(ResponseEnvelopeV1 {
        version: ProtocolVersion::new(1, 0),
        request_id: RequestId::new([0x11; 16]),
        body: ResponseBodyV1::Ok(ResponsePayloadV1::EvaluateToolCall(
            EvaluateToolCallResponseV1::NeedsApproval {
                envelope,
                trace: DecisionTrace {
                    rule_ids: vec![],
                    public_reason: StableCode::ApprovalRequired,
                },
            },
        )),
    })
}

fn attestation(name: String) -> SignedValidatorAttestationV1 {
    SignedValidatorAttestationV1 {
        validator_id: ValidatorId::try_from(name).unwrap(),
        validator_version: BoundedText::try_from("1").unwrap(),
        run_id: RunId::new([0x61; 32]),
        pending: opaque(0x62),
        argument_digest: Digest32::new([0x63; 32]),
        verdict: ValidatorVerdictV1::Pass,
        public_reason: StableCode::PolicyDenied,
        issued_at: UnixMillis::new(1_000),
        expires_at: UnixMillis::new(2_000),
        nonce: Nonce32::new([0x64; 32]),
        key_id: KeyId::try_from("fixture-validator-key").unwrap(),
        signature: Signature64::new([0x65; 64]),
    }
}

fn ontology_entry(constraint: &str, tool: &str) -> OntologyEntryV1 {
    OntologyEntryV1 {
        constraint_id: ConstraintId::try_from(constraint).unwrap(),
        tool: ToolName::try_from(tool).unwrap(),
        effect: OntologyEffectV1::RequireValidator,
        validator_id: Some(ValidatorId::try_from("role-04").unwrap()),
    }
}

#[test]
fn ontology_artifacts_are_exact_bounded_canonical_arrays() {
    let snapshot = SignedOntologySnapshotV1 {
        unsigned: OntologySnapshotV1 {
            version: 7,
            previous_digest: None,
            entries: vec![
                ontology_entry("b", "tool-b"),
                ontology_entry("aa", "tool-aa"),
            ],
            issued_at: UnixMillis::new(1_000),
            expires_at: UnixMillis::new(2_000),
        },
        key_id: KeyId::try_from("role-03").unwrap(),
        signature: Signature64::new([0x66; 64]),
    };
    let encoded = minicbor::to_vec(&snapshot).unwrap();
    assert_eq!(
        minicbor::decode::<SignedOntologySnapshotV1>(&encoded).unwrap(),
        snapshot
    );

    let mut reversed = snapshot.clone();
    reversed.unsigned.entries.reverse();
    assert!(minicbor::to_vec(&reversed).is_err());

    let event = SignedOntologyEventV1 {
        unsigned: OntologyEventV1 {
            version: 8,
            previous_digest: Digest32::new([0x67; 32]),
            sequence: 1,
            replacement: ontology_entry("b", "tool-b"),
            issued_at: UnixMillis::new(1_100),
            expires_at: UnixMillis::new(1_900),
        },
        key_id: KeyId::try_from("role-03").unwrap(),
        signature: Signature64::new([0x68; 64]),
    };
    let encoded = minicbor::to_vec(&event).unwrap();
    assert_eq!(
        minicbor::decode::<SignedOntologyEventV1>(&encoded).unwrap(),
        event
    );
}

#[test]
fn signed_snapshot_versions_and_descriptor_bindings_are_intrinsic() {
    let mut registry = begin_run_request().registry;
    registry.unsigned.version = 0;
    assert!(minicbor::to_vec(&registry).is_err());

    registry.unsigned.version = 8;
    registry.unsigned.tools = vec![tool_descriptor("fixture-tool")];
    registry.unsigned.tools[0].identity.registry_version = 7;
    assert!(minicbor::to_vec(&registry).is_err());

    let ontology = SignedOntologySnapshotV1 {
        unsigned: OntologySnapshotV1 {
            version: 0,
            previous_digest: None,
            entries: Vec::new(),
            issued_at: UnixMillis::new(1_000),
            expires_at: UnixMillis::new(2_000),
        },
        key_id: KeyId::try_from("role-03").unwrap(),
        signature: Signature64::new([0x69; 64]),
    };
    assert!(minicbor::to_vec(ontology).is_err());

    let event = SignedOntologyEventV1 {
        unsigned: OntologyEventV1 {
            version: 0,
            previous_digest: Digest32::new([0x6a; 32]),
            sequence: 1,
            replacement: ontology_entry("constraint-00", "fixture-tool"),
            issued_at: UnixMillis::new(1_000),
            expires_at: UnixMillis::new(2_000),
        },
        key_id: KeyId::try_from("role-03").unwrap(),
        signature: Signature64::new([0x6b; 64]),
    };
    assert!(minicbor::to_vec(event).is_err());
}

fn policy_operations() -> Vec<OperationV1> {
    vec![
        OperationV1::BeginRun(begin_run_request()),
        OperationV1::IngestUserInput(IngestUserInputRequest {
            run: opaque(0x70),
            envelope: signed_ingress(),
            input: KernelValue::Null,
        }),
        OperationV1::PreparePlannerCall(PreparePlannerCallRequest {
            run: opaque(0x70),
            planner: PlannerId::try_from("fixture-planner").unwrap(),
            prompt_values: vec![opaque(0x71)],
        }),
        OperationV1::CommitPlannerValue(CommitPlannerValueRequest {
            run: opaque(0x70),
            proof: PlannerCommitProofV1::DaemonTicket(opaque(0x72)),
            value: KernelValue::Null,
        }),
        OperationV1::DeriveValue(DeriveValueRequest {
            run: opaque(0x70),
            operation: DeriveOperation::AssembleList,
            inputs: vec![opaque(0x71)],
        }),
        OperationV1::ProposeToolCall(ProposeToolCallRequest {
            run: opaque(0x70),
            tool: opaque(0x73),
            arguments: vec![NamedArgumentHandle {
                name: ArgumentName::try_from("destination").unwrap(),
                value: opaque(0x71),
            }],
        }),
        OperationV1::EvaluateToolCall(EvaluateToolCallRequest {
            pending: opaque(0x74),
            attestations: vec![attestation("validator-000".to_owned())],
        }),
        OperationV1::AuthorizeToolCall(AuthorizeToolCallRequest {
            pending: opaque(0x74),
            receipt: approval_receipt(),
        }),
        OperationV1::MaterializeExecution(MaterializeExecutionRequest {
            ticket: opaque(0x75),
        }),
        OperationV1::CommitToolResult(CommitToolResultRequest {
            ticket: opaque(0x75),
            result: KernelValue::Bool(true),
        }),
    ]
}

#[test]
fn begin_run_round_trip_is_canonical() {
    let message = request(OperationV1::BeginRun(begin_run_request()));
    let encoded = encode_client_message(&message).unwrap();
    let decoded = decode_client_message(&encoded, &support::compiled_effective_limits()).unwrap();
    assert_eq!(encode_client_message(&decoded).unwrap(), encoded);
    assert_eq!(decoded, message);
}

#[test]
fn v1_request_boundary_accepts_only_health_and_tags_10_through_19() {
    let accepted =
        std::iter::once((0_u8, OperationV1::Health)).chain((10_u8..=19).zip(policy_operations()));
    for (tag, operation) in accepted {
        let message = request(operation.clone());
        let encoded = encode_client_message(&message).unwrap();
        assert_eq!(
            decode_client_message(&encoded, &support::compiled_effective_limits()).unwrap(),
            message
        );

        // Mutate the actual operation tag inside a complete canonical V1
        // Request envelope.  This covers the decoder boundary, rather than
        // only OperationV1's standalone minicbor implementation.
        let operation_wire = minicbor::to_vec(&operation).unwrap();
        assert_eq!(&operation_wire[..2], &[0x82, tag]);
        let offset = encoded
            .windows(operation_wire.len())
            .position(|window| window == operation_wire)
            .expect("request contains its operation wire value");
        let mut unknown = encoded;
        unknown[offset + 1] = 20;
        let error = decode_client_message(&unknown, &support::compiled_effective_limits())
            .expect_err("tag 20 must remain outside the frozen V1 operation set");
        assert_eq!(error.code(), StableCode::ProtocolUnknownOperation);
    }
}

#[test]
fn no_policy_operation_contains_host_trust_facts() {
    let schema = format!("{:?}", policy_operations()).to_ascii_lowercase();
    for forbidden in [
        "is_trusted",
        "is_public",
        "no_side_effect_tools",
        "consent_overridable_tools",
        "high_risk_tools",
        "active_tools",
        "ontology_rows",
        "g5_verdict",
    ] {
        assert!(!schema.contains(forbidden), "{forbidden}");
    }
}

#[test]
fn handles_are_fixed_bytes_and_redacted() {
    let handles = policy_flow_fixture::fixture_handles();
    macro_rules! assert_handle {
        ($type:ty, $value:expr, $debug:literal) => {{
            let handle: $type = $value;
            assert_eq!(format!("{handle:?}"), $debug);
            assert_eq!(minicbor::to_vec(handle).unwrap().len(), 34);

            let mut short = vec![0x58, 0x1f];
            short.extend_from_slice(&[0; 31]);
            assert!(minicbor::decode::<$type>(&short).is_err());
            let mut long = vec![0x58, 0x21];
            long.extend_from_slice(&[0; 33]);
            assert!(minicbor::decode::<$type>(&long).is_err());
        }};
    }
    assert_handle!(RunHandle, handles.run, "RunHandle(<opaque>)");
    assert_handle!(ValueHandle, handles.value, "ValueHandle(<opaque>)");
    assert_handle!(
        PlannerTicketHandle,
        handles.planner,
        "PlannerTicketHandle(<opaque>)"
    );
    assert_handle!(ToolHandle, handles.tool, "ToolHandle(<opaque>)");
    assert_handle!(
        PendingToolCallHandle,
        handles.pending,
        "PendingToolCallHandle(<opaque>)"
    );
    assert_handle!(
        ExecutionTicketHandle,
        handles.execution,
        "ExecutionTicketHandle(<opaque>)"
    );
}

#[test]
fn argument_names_are_ascii_identifiers() {
    assert_eq!(
        ArgumentName::try_from("destination_1").unwrap().as_str(),
        "destination_1"
    );
    for invalid in ["", "1destination", "not-an-identifier", "naïve", "nul\0"] {
        assert_eq!(
            ArgumentName::try_from(invalid).unwrap_err().code(),
            StableCode::ProtocolMalformedCbor
        );
    }
    let oversized_tool = "x".repeat(1024 * 1024);
    assert!(ToolName::try_from(oversized_tool.as_str()).is_err());
}

#[test]
fn public_text_constructors_accept_borrowed_and_owned_strings() {
    macro_rules! assert_constructor_inputs {
        ($type:ty, $value:literal) => {{
            let borrowed = <$type>::new($value).unwrap();
            let owned = <$type>::new(String::from($value)).unwrap();
            assert_eq!(borrowed.as_str(), $value);
            assert_eq!(owned.as_str(), $value);
            assert_eq!(borrowed, owned);
        }};
    }

    assert_constructor_inputs!(KeyId, "key");
    assert_constructor_inputs!(ClientId, "client");
    assert_constructor_inputs!(ToolName, "tool");
    assert_constructor_inputs!(ValidatorId, "validator");
    assert_constructor_inputs!(ConstraintId, "constraint");
    assert_constructor_inputs!(RoleId, "role");
    assert_constructor_inputs!(PrincipalId, "principal");
    assert_constructor_inputs!(ConversationId, "conversation");
    assert_constructor_inputs!(TaskId, "task");
    assert_constructor_inputs!(ArtifactId, "artifact");
    assert_constructor_inputs!(PlannerId, "planner");
    assert_constructor_inputs!(ArgumentName, "argument");
    assert_constructor_inputs!(BoundedText, "display text");

    assert!(ClientId::new(String::from("control\n")).is_err());
    assert!(ArgumentName::new(String::from("not-valid")).is_err());
    assert!(BoundedText::new(String::from("control\n")).is_err());
}

#[test]
fn every_front_loaded_tagged_variant_has_a_frozen_tag_and_unknowns_fail() {
    fn assert_tag<T>(value: T, expected: u8)
    where
        T: minicbor::Encode<()>
            + for<'bytes> minicbor::Decode<'bytes, ()>
            + PartialEq
            + std::fmt::Debug,
    {
        let encoded = minicbor::to_vec(&value).unwrap();
        assert_eq!(&encoded[..2], &[0x82, expected]);
        assert_eq!(minicbor::decode::<T>(&encoded).unwrap(), value);
    }

    assert_tag(ApprovalPurposeV1::ToolMaterialization, 0);
    assert_tag(ApprovalPurposeV1::FinalRelease, 1);
    assert_tag(ApprovalDecision::Approve, 0);
    assert_tag(ApprovalDecision::Deny, 1);
    assert_tag(ApprovalAuthMethod::WebAuthnUv, 0);
    assert_tag(ValidatorVerdictV1::Pass, 0);
    assert_tag(ValidatorVerdictV1::Fail, 1);

    let handles = policy_flow_fixture::fixture_handles();
    assert_tag(PlannerCommitProofV1::DaemonTicket(handles.planner), 0);
    assert_tag(
        PlannerCommitProofV1::SignedAttestation(SignedPlannerAttestationV1 {
            run_id: RunId::new([0x81; 32]),
            planner_id: PlannerId::try_from("fixture-planner").unwrap(),
            planner_version: BoundedText::try_from("1").unwrap(),
            prompt_digest: Digest32::new([0x82; 32]),
            output_digest: Digest32::new([0x83; 32]),
            issued_at: UnixMillis::new(1_000),
            expires_at: UnixMillis::new(2_000),
            nonce: Nonce32::new([0x84; 32]),
            key_id: KeyId::try_from("fixture-planner-key").unwrap(),
            signature: Signature64::new([0x85; 64]),
        }),
        1,
    );
    assert_tag(
        ApprovalSubjectV1::ToolCall {
            pending: handles.pending,
            argument_digest: Digest32::new([0x86; 32]),
            provenance_digest: Digest32::new([0x87; 32]),
        },
        0,
    );
    assert_tag(
        ApprovalSubjectV1::VaultRelease {
            vault_session_id: Nonce32::new([0x88; 32]),
            evidence_digest: Digest32::new([0x89; 32]),
            masked_output_digest: Digest32::new([0x8a; 32]),
            token_set_digest: Digest32::new([0x8b; 32]),
            artifact_id: ArtifactId::try_from("fixture-artifact").unwrap(),
            artifact_generation: 3,
        },
        1,
    );

    let unknown = [0x82, 0x7f, 0x80];
    assert!(minicbor::decode::<ApprovalPurposeV1>(&unknown).is_err());
    assert!(minicbor::decode::<ApprovalDecision>(&unknown).is_err());
    assert!(minicbor::decode::<ApprovalAuthMethod>(&unknown).is_err());
    assert!(minicbor::decode::<ValidatorVerdictV1>(&unknown).is_err());
    assert!(minicbor::decode::<PlannerCommitProofV1>(&unknown).is_err());
    assert!(minicbor::decode::<ApprovalSubjectV1>(&unknown).is_err());
}

#[test]
fn operation_tags_10_through_19_are_canonical_and_closed() {
    for (tag, operation) in (10_u8..=19).zip(policy_operations()) {
        let encoded = minicbor::to_vec(&operation).unwrap();
        assert_eq!(encoded[0], 0x82);
        assert_eq!(encoded[1], tag);
        assert_eq!(
            minicbor::decode::<OperationV1>(&encoded).unwrap(),
            operation
        );

        let mut short = encoded.clone();
        short[2] -= 1;
        assert!(minicbor::decode::<OperationV1>(&short).is_err());
        let mut extra = encoded;
        extra[2] += 1;
        extra.push(0xf6);
        assert!(minicbor::decode::<OperationV1>(&extra).is_err());
    }

    let extra_health = [0x82, 0x00, 0x81, 0xf6];
    assert!(minicbor::decode::<OperationV1>(&extra_health).is_err());
    let unknown = [0x82, 0x14, 0x80];
    assert!(minicbor::decode::<OperationV1>(&unknown)
        .unwrap_err()
        .to_string()
        .contains(StableCode::ProtocolUnknownOperation.as_str()));
}

#[test]
fn success_response_tags_mirror_policy_operation_tags() {
    let trace = DecisionTrace {
        rule_ids: vec![1, 4],
        public_reason: StableCode::ApprovalRequired,
    };
    let payloads = vec![
        ResponsePayloadV1::BeginRun(BeginRunResponse {
            run: opaque(0x70),
            initial_value: opaque(0x71),
            active_tools: vec![],
        }),
        ResponsePayloadV1::IngestUserInput(opaque(0x71)),
        ResponsePayloadV1::PreparePlannerCall(opaque(0x72)),
        ResponsePayloadV1::CommitPlannerValue(opaque(0x71)),
        ResponsePayloadV1::DeriveValue(opaque(0x71)),
        ResponsePayloadV1::ProposeToolCall(opaque(0x74)),
        ResponsePayloadV1::EvaluateToolCall(EvaluateToolCallResponseV1::NeedsApproval {
            envelope: approval_envelope(),
            trace,
        }),
        ResponsePayloadV1::AuthorizeToolCall(opaque(0x75)),
        ResponsePayloadV1::MaterializeExecution(ExecutionEnvelope {
            tool: tool_identity("fixture-tool"),
            arguments: KernelValue::Null,
            argument_digest: Digest32::new([0x76; 32]),
            execution_nonce: Nonce32::new([0x77; 32]),
        }),
        ResponsePayloadV1::CommitToolResult(opaque(0x71)),
    ];

    for (tag, payload) in (10_u8..=19).zip(payloads) {
        let message = ServerMessageV1::Response(ResponseEnvelopeV1 {
            version: ProtocolVersion::new(1, 0),
            request_id: RequestId::new([0x11; 16]),
            body: ResponseBodyV1::Ok(payload),
        });
        let encoded = encode_server_message(&message).unwrap();
        let decoded =
            decode_server_message(&encoded, &support::compiled_effective_limits()).unwrap();
        assert_eq!(decoded, message);

        let payload = match decoded {
            ServerMessageV1::Response(ResponseEnvelopeV1 {
                body: ResponseBodyV1::Ok(payload),
                ..
            }) => payload,
            _ => unreachable!(),
        };
        let payload_bytes = minicbor::to_vec(payload).unwrap();
        assert_eq!(&payload_bytes[..2], &[0x82, tag]);
    }
}

#[test]
fn fixed_array_response_payloads_reject_short_and_extra_slots() {
    let payloads = [
        ResponsePayloadV1::BeginRun(BeginRunResponse {
            run: opaque(0x70),
            initial_value: opaque(0x71),
            active_tools: vec![],
        }),
        ResponsePayloadV1::EvaluateToolCall(EvaluateToolCallResponseV1::NeedsApproval {
            envelope: approval_envelope(),
            trace: DecisionTrace {
                rule_ids: vec![1],
                public_reason: StableCode::ApprovalRequired,
            },
        }),
        ResponsePayloadV1::MaterializeExecution(ExecutionEnvelope {
            tool: tool_identity("fixture-tool"),
            arguments: KernelValue::Null,
            argument_digest: Digest32::new([0x91; 32]),
            execution_nonce: Nonce32::new([0x92; 32]),
        }),
    ];
    for payload in payloads {
        let encoded = minicbor::to_vec(payload).unwrap();
        let mut short = encoded.clone();
        short[2] -= 1;
        assert!(minicbor::decode::<ResponsePayloadV1>(&short).is_err());
        let mut extra = encoded;
        extra[2] += 1;
        extra.push(0xf6);
        assert!(minicbor::decode::<ResponsePayloadV1>(&extra).is_err());
    }
}

#[test]
fn nested_producer_arrays_reject_unknown_slots() {
    let mut encoded = minicbor::to_vec(attestation("validator-000".to_owned())).unwrap();
    assert_eq!(encoded[0], 0x8c);
    encoded[0] = 0x8d;
    encoded.push(0xf6);
    assert!(minicbor::decode::<SignedValidatorAttestationV1>(&encoded).is_err());

    let invalid_trace = DecisionTrace {
        rule_ids: vec![2, 1],
        public_reason: StableCode::PolicyDenied,
    };
    assert!(minicbor::to_vec(invalid_trace).is_err());
}

#[test]
fn bounded_value_and_name_types_reject_over_limit_or_noncanonical_inputs() {
    assert_eq!(BoundedText::try_from("").unwrap().as_str(), "");
    assert!(BoundedText::try_from("control\n").is_err());
    assert!(BoundedText::try_from("x".repeat(64 * 1024 + 1)).is_err());
    assert!(RoleId::try_from("é".repeat(32)).is_ok());
    assert!(RoleId::try_from("é".repeat(33)).is_err());
    assert!(BoundedText::try_from("é".repeat(32 * 1024)).is_ok());
    assert!(BoundedText::try_from("é".repeat(32 * 1024 + 1)).is_err());
    assert!(BoundedList::try_from(vec![KernelValue::Null; 1_025]).is_err());

    let duplicate = vec![
        (ArgumentName::try_from("same").unwrap(), KernelValue::Null),
        (ArgumentName::try_from("same").unwrap(), KernelValue::Null),
    ];
    assert!(BoundedObject::try_from(duplicate).is_err());

    let mut oversized_list = minicbor::Encoder::new(Vec::new());
    oversized_list
        .array(2)
        .unwrap()
        .u8(5)
        .unwrap()
        .array(1_025)
        .unwrap();
    assert!(minicbor::decode::<KernelValue>(&oversized_list.into_writer()).is_err());
}

#[test]
fn masked_display_values_share_one_total_decode_and_encode_budget() {
    let display = MaskedDisplayBundleV1 {
        purpose_label: BoundedText::try_from("").unwrap(),
        tool_label: BoundedText::try_from("").unwrap(),
        masked_destination: KernelValue::Bytes(
            BoundedBytes::try_from(vec![0x41; 600 * 1024]).unwrap(),
        ),
        masked_output: KernelValue::Bytes(BoundedBytes::try_from(vec![0x42; 600 * 1024]).unwrap()),
    };
    assert!(minicbor::to_vec(display).is_err());

    let mut raw = minicbor::Encoder::new(Vec::new());
    raw.array(4)
        .unwrap()
        .str("")
        .unwrap()
        .str("")
        .unwrap()
        .array(2)
        .unwrap()
        .u8(4)
        .unwrap()
        .bytes(&vec![0x41; 600 * 1024])
        .unwrap()
        .array(2)
        .unwrap()
        .u8(4)
        .unwrap()
        .bytes(&vec![0x42; 600 * 1024])
        .unwrap();
    assert!(minicbor::decode::<MaskedDisplayBundleV1>(&raw.into_writer()).is_err());
}

#[test]
fn kernel_value_depth_is_safe_in_the_deepest_wire_context() {
    // In the deepest Task 1 path, an Object child adds three CBOR levels:
    // Object's tagged array, its entries array, and its [name, value] pair.
    // Seven nested Objects plus the leaf therefore put the leaf payload at
    // global depth 31; an eighth Object would put its leaf tag past depth 32.
    let maximum = needs_approval_response(nested_object_value(8));
    let encoded = encode_server_message(&maximum).unwrap();
    assert_eq!(
        decode_server_message(&encoded, &support::compiled_effective_limits()).unwrap(),
        maximum
    );

    let one_over = needs_approval_response(nested_object_value(9));
    assert_eq!(
        encode_server_message(&one_over).unwrap_err().code(),
        StableCode::ProtocolMalformedCbor
    );
}

#[test]
fn standalone_objects_charge_names_and_values_to_one_text_budget() {
    let entries = (0..256)
        .map(|index| {
            (
                ArgumentName::try_from(format!("a{index:03}_{}", "x".repeat(59))).unwrap(),
                KernelValue::Text(BoundedText::try_from("y".repeat(256)).unwrap()),
            )
        })
        .collect::<Vec<_>>();
    let object = BoundedObject::try_from(entries).unwrap();
    assert!(minicbor::to_vec(object).is_err());

    let mut raw = minicbor::Encoder::new(Vec::new());
    raw.array(256).unwrap();
    for index in 0..256 {
        raw.array(2)
            .unwrap()
            .str(&format!("a{index:03}_{}", "x".repeat(59)))
            .unwrap()
            .array(2)
            .unwrap()
            .u8(3)
            .unwrap()
            .str(&"y".repeat(256))
            .unwrap();
    }
    assert!(minicbor::decode::<BoundedObject>(&raw.into_writer()).is_err());
}

#[test]
fn ordered_text_collections_use_canonical_cbor_text_order() {
    let object = BoundedObject::try_from(vec![
        (ArgumentName::try_from("b").unwrap(), KernelValue::Null),
        (ArgumentName::try_from("aa").unwrap(), KernelValue::Null),
    ])
    .unwrap();
    let object_bytes = minicbor::to_vec(&object).unwrap();
    assert_eq!(
        minicbor::decode::<BoundedObject>(&object_bytes).unwrap(),
        object
    );
    assert!(BoundedObject::try_from(vec![
        (ArgumentName::try_from("aa").unwrap(), KernelValue::Null),
        (ArgumentName::try_from("b").unwrap(), KernelValue::Null),
    ])
    .is_err());
    assert!(
        minicbor::decode::<BoundedObject>(&swap_unique_cbor_texts(&object_bytes, "b", "aa"))
            .is_err()
    );

    let mut roles = tool_descriptor("tool");
    roles.roles = vec![
        RoleId::try_from("b").unwrap(),
        RoleId::try_from("aa").unwrap(),
    ];
    let mut reverse_roles = roles.clone();
    reverse_roles.roles.reverse();
    assert_canonical_text_collection(&roles, &reverse_roles);

    let mut constraints = tool_descriptor("tool");
    constraints.constraint_ids = vec![
        ConstraintId::try_from("b").unwrap(),
        ConstraintId::try_from("aa").unwrap(),
    ];
    let mut reverse_constraints = constraints.clone();
    reverse_constraints.constraint_ids.reverse();
    assert_canonical_text_collection(&constraints, &reverse_constraints);

    let mut validators = tool_descriptor("tool");
    validators.validator_ids = vec![
        ValidatorId::try_from("b").unwrap(),
        ValidatorId::try_from("aa").unwrap(),
    ];
    let mut reverse_validators = validators.clone();
    reverse_validators.validator_ids.reverse();
    assert_canonical_text_collection(&validators, &reverse_validators);

    let registry = RegistrySnapshotV1 {
        version: 7,
        previous_digest: None,
        tools: vec![tool_descriptor("b"), tool_descriptor("aa")],
        issued_at: UnixMillis::new(1),
        expires_at: UnixMillis::new(2),
    };
    let mut reverse_registry = registry.clone();
    reverse_registry.tools.reverse();
    assert_canonical_text_collection(&registry, &reverse_registry);

    let active_tools = BeginRunResponse {
        run: opaque(0x70),
        initial_value: opaque(0x71),
        active_tools: vec![
            ActiveToolView {
                handle: opaque(0x73),
                identity: tool_identity("b"),
            },
            ActiveToolView {
                handle: opaque(0x73),
                identity: tool_identity("aa"),
            },
        ],
    };
    let mut reverse_active_tools = active_tools.clone();
    reverse_active_tools.active_tools.reverse();
    assert_canonical_text_collection(&active_tools, &reverse_active_tools);

    let arguments = ProposeToolCallRequest {
        run: opaque(0x70),
        tool: opaque(0x73),
        arguments: vec![
            NamedArgumentHandle {
                name: ArgumentName::try_from("b").unwrap(),
                value: opaque(0x71),
            },
            NamedArgumentHandle {
                name: ArgumentName::try_from("aa").unwrap(),
                value: opaque(0x71),
            },
        ],
    };
    let mut reverse_arguments = arguments.clone();
    reverse_arguments.arguments.reverse();
    assert_canonical_text_collection(&arguments, &reverse_arguments);

    let attestations = EvaluateToolCallRequest {
        pending: opaque(0x74),
        attestations: vec![attestation("b".to_owned()), attestation("aa".to_owned())],
    };
    let mut reverse_attestations = attestations.clone();
    reverse_attestations.attestations.reverse();
    assert_canonical_text_collection(&attestations, &reverse_attestations);

    let mapping_order = BoundedArgumentNames::try_from(vec![
        ArgumentName::try_from("aa").unwrap(),
        ArgumentName::try_from("b").unwrap(),
    ])
    .unwrap();
    assert_eq!(mapping_order.as_slice()[0].as_str(), "aa");
    assert_eq!(mapping_order.as_slice()[1].as_str(), "b");
    assert_eq!(
        minicbor::decode::<BoundedArgumentNames>(&minicbor::to_vec(&mapping_order).unwrap())
            .unwrap(),
        mapping_order
    );
}

#[test]
fn collection_limits_fail_closed_on_encode() {
    let value: ValueHandle = opaque(0x71);
    let arguments = (0..257)
        .map(|index| NamedArgumentHandle {
            name: ArgumentName::try_from(format!("argument_{index:03}")).unwrap(),
            value,
        })
        .collect();
    let error = encode_client_message(&request(OperationV1::ProposeToolCall(
        ProposeToolCallRequest {
            run: opaque(0x70),
            tool: opaque(0x73),
            arguments,
        },
    )))
    .unwrap_err();
    assert_eq!(error.code(), StableCode::ProtocolMalformedCbor);

    let attestations = (0..33)
        .map(|index| attestation(format!("validator-{index:03}")))
        .collect();
    let error = encode_client_message(&request(OperationV1::EvaluateToolCall(
        EvaluateToolCallRequest {
            pending: opaque(0x74),
            attestations,
        },
    )))
    .unwrap_err();
    assert_eq!(error.code(), StableCode::ProtocolMalformedCbor);

    let active_tools = (0..257)
        .map(|index| ActiveToolView {
            handle: opaque(0x73),
            identity: tool_identity(&format!("tool-{index:03}")),
        })
        .collect();
    let message = ServerMessageV1::Response(ResponseEnvelopeV1 {
        version: ProtocolVersion::new(1, 0),
        request_id: RequestId::new([0x11; 16]),
        body: ResponseBodyV1::Ok(ResponsePayloadV1::BeginRun(BeginRunResponse {
            run: opaque(0x70),
            initial_value: value,
            active_tools,
        })),
    });
    assert_eq!(
        encode_server_message(&message).unwrap_err().code(),
        StableCode::ProtocolMalformedCbor
    );
}

#[test]
fn collection_limits_are_checked_from_declared_lengths_before_decode_allocation() {
    let mut prepare = minicbor::Encoder::new(Vec::new());
    prepare
        .array(3)
        .unwrap()
        .bytes(&[0x70; 32])
        .unwrap()
        .str("planner")
        .unwrap()
        .array(257)
        .unwrap();
    assert!(minicbor::decode::<PreparePlannerCallRequest>(&prepare.into_writer()).is_err());

    let mut arguments = minicbor::Encoder::new(Vec::new());
    arguments
        .array(3)
        .unwrap()
        .bytes(&[0x70; 32])
        .unwrap()
        .bytes(&[0x73; 32])
        .unwrap()
        .array(257)
        .unwrap();
    assert!(minicbor::decode::<ProposeToolCallRequest>(&arguments.into_writer()).is_err());

    let mut attestations = minicbor::Encoder::new(Vec::new());
    attestations
        .array(2)
        .unwrap()
        .bytes(&[0x74; 32])
        .unwrap()
        .array(33)
        .unwrap();
    assert!(minicbor::decode::<EvaluateToolCallRequest>(&attestations.into_writer()).is_err());

    let mut active_tools = minicbor::Encoder::new(Vec::new());
    active_tools
        .array(3)
        .unwrap()
        .bytes(&[0x70; 32])
        .unwrap()
        .bytes(&[0x71; 32])
        .unwrap()
        .array(257)
        .unwrap();
    assert!(minicbor::decode::<BeginRunResponse>(&active_tools.into_writer()).is_err());
}

#[test]
fn conservative_input_and_trace_limits_are_enforced() {
    let value: ValueHandle = opaque(0x71);
    let prompt = OperationV1::PreparePlannerCall(PreparePlannerCallRequest {
        run: opaque(0x70),
        planner: PlannerId::try_from("fixture-planner").unwrap(),
        prompt_values: vec![value; 257],
    });
    assert!(encode_client_message(&request(prompt)).is_err());

    let derive = OperationV1::DeriveValue(DeriveValueRequest {
        run: opaque(0x70),
        operation: DeriveOperation::AssembleList,
        inputs: vec![value; 257],
    });
    assert!(encode_client_message(&request(derive)).is_err());

    let mismatched_object = OperationV1::DeriveValue(DeriveValueRequest {
        run: opaque(0x70),
        operation: DeriveOperation::AssembleObject(
            BoundedArgumentNames::try_from(vec![ArgumentName::try_from("only").unwrap()]).unwrap(),
        ),
        inputs: vec![],
    });
    assert!(encode_client_message(&request(mismatched_object)).is_err());

    let response = ServerMessageV1::Response(ResponseEnvelopeV1 {
        version: ProtocolVersion::new(1, 0),
        request_id: RequestId::new([0x11; 16]),
        body: ResponseBodyV1::Ok(ResponsePayloadV1::EvaluateToolCall(
            EvaluateToolCallResponseV1::Allowed {
                ticket: opaque(0x75),
                trace: DecisionTrace {
                    rule_ids: (0..257).collect(),
                    public_reason: StableCode::PolicyDenied,
                },
            },
        )),
    });
    assert!(encode_server_message(&response).is_err());
}

#[test]
fn stable_policy_errors_round_trip_as_response_errors() {
    let message = ServerMessageV1::Response(ResponseEnvelopeV1 {
        version: ProtocolVersion::new(1, 0),
        request_id: RequestId::new([0x11; 16]),
        body: ResponseBodyV1::Err(StableCode::HandleAlreadyConsumed),
    });
    let bytes = encode_server_message(&message).unwrap();
    assert_eq!(
        decode_server_message(&bytes, &support::compiled_effective_limits()).unwrap(),
        message
    );
}

#[test]
fn all_task_one_stable_codes_keep_their_exact_wire_strings() {
    let cases = [
        (
            StableCode::AttestationInvalidSignature,
            "ATTESTATION_INVALID_SIGNATURE",
        ),
        (StableCode::AttestationExpired, "ATTESTATION_EXPIRED"),
        (
            StableCode::AttestationBindingMismatch,
            "ATTESTATION_BINDING_MISMATCH",
        ),
        (StableCode::OntologySequenceGap, "ONTOLOGY_SEQUENCE_GAP"),
        (StableCode::HandleUnknown, "HANDLE_UNKNOWN"),
        (StableCode::HandleWrongClient, "HANDLE_WRONG_CLIENT"),
        (StableCode::HandleWrongConnection, "HANDLE_WRONG_CONNECTION"),
        (StableCode::HandleWrongRun, "HANDLE_WRONG_RUN"),
        (StableCode::HandleWrongType, "HANDLE_WRONG_TYPE"),
        (StableCode::HandleStalePolicy, "HANDLE_STALE_POLICY"),
        (StableCode::HandleStaleRegistry, "HANDLE_STALE_REGISTRY"),
        (StableCode::HandleAlreadyConsumed, "HANDLE_ALREADY_CONSUMED"),
        (StableCode::HandleInvalidatedBoot, "HANDLE_INVALIDATED_BOOT"),
        (
            StableCode::RegistryInvalidSignature,
            "REGISTRY_INVALID_SIGNATURE",
        ),
        (StableCode::RegistryEquivocation, "REGISTRY_EQUIVOCATION"),
        (
            StableCode::OntologyInvalidSignature,
            "ONTOLOGY_INVALID_SIGNATURE",
        ),
        (StableCode::OntologyEquivocation, "ONTOLOGY_EQUIVOCATION"),
        (StableCode::PolicyDenied, "POLICY_DENIED"),
        (StableCode::ApprovalRequired, "APPROVAL_REQUIRED"),
        (
            StableCode::ApprovalInvalidSignature,
            "APPROVAL_INVALID_SIGNATURE",
        ),
        (
            StableCode::ApprovalBindingMismatch,
            "APPROVAL_BINDING_MISMATCH",
        ),
        (StableCode::ApprovalReplayed, "APPROVAL_REPLAYED"),
        (StableCode::ApprovalLedgerFull, "APPROVAL_LEDGER_FULL"),
    ];
    assert_eq!(cases.len(), 23);
    for (code, expected) in cases {
        assert_eq!(code.as_str(), expected);
        let encoded = minicbor::to_vec(code).unwrap();
        assert_eq!(minicbor::decode::<StableCode>(&encoded).unwrap(), code);
    }
}

#[test]
fn committed_policy_flow_vector_matches_generator_and_covers_required_cases() {
    let transcript = support::handshake_transcript();
    let messages = policy_flow_fixture::encoded_messages(&transcript);
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder.array(messages.len() as u64).unwrap();
    for message in &messages {
        encoder.bytes(message).unwrap();
    }
    let generated = encoder.into_writer();
    let committed = include_bytes!("../../../vectors/kerneld/policy-flow-v1.cbor");
    assert_eq!(generated.as_slice(), committed);

    assert_eq!(messages.len(), 12);
    for (tag, message) in (10_u8..=19).zip(&messages[..10]) {
        let decoded =
            decode_client_message(message, &support::compiled_effective_limits()).unwrap();
        let operation = match decoded {
            ClientMessageV1::Request(request) => request.operation,
            _ => unreachable!(),
        };
        assert_eq!(minicbor::to_vec(operation).unwrap()[1], tag);
    }
    assert!(matches!(
        decode_server_message(&messages[10], &support::compiled_effective_limits()).unwrap(),
        ServerMessageV1::Response(ResponseEnvelopeV1 {
            body: ResponseBodyV1::Ok(ResponsePayloadV1::EvaluateToolCall(
                EvaluateToolCallResponseV1::NeedsApproval { .. }
            )),
            ..
        })
    ));
    assert!(matches!(
        decode_server_message(&messages[11], &support::compiled_effective_limits()).unwrap(),
        ServerMessageV1::Response(ResponseEnvelopeV1 {
            body: ResponseBodyV1::Err(StableCode::HandleAlreadyConsumed),
            ..
        })
    ));
}
