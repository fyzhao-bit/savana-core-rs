use savana_kernel_protocol::v2::{
    decode_kernel_executor_operation_v2, encode_kernel_executor_operation_v2,
    AcknowledgeCommittedCompletionRequestV2, ActionIntentIdV2, AttemptKindV2, BoundedCiphertextV2,
    Digest32V2, DispatchCoreV2, DispatchRequestV2, DispatchSubjectV2, DurableRunIdV2,
    DurableTaskIdV2, Ed25519KeyIdV2, Ed25519SignatureV2, ExecutorCompletionDescriptorV2,
    ExecutorHealthRequestV2, ExecutorIdentityV2, FetchCompletionRequestV2, FixedBytes32V2,
    HpkeX25519KeyIdV2, InternalStepIdV2, KernelExecutorOperationV2, Nonce32V2,
    PlanRevisionDigestV2, QueryByExecutionNonceRequestV2, SealedExecutionEnvelopePayloadV2,
    SignedSealedExecutionEnvelopeV2, ToolExecutionSemanticBindingV2, UnixMillisV2,
};

#[test]
fn executor_health_and_nonce_queries_have_exact_closed_tags() {
    let health = KernelExecutorOperationV2::Health(ExecutorHealthRequestV2);
    assert_eq!(
        encode_kernel_executor_operation_v2(&health).unwrap(),
        [0x82, 0x00, 0x80]
    );

    let query = KernelExecutorOperationV2::QueryByExecutionNonce(
        QueryByExecutionNonceRequestV2::new(
            Nonce32V2::new([1; 32]),
            Digest32V2::new([2; 32]),
            Digest32V2::new([3; 32]),
        )
        .unwrap(),
    );
    let encoded = encode_kernel_executor_operation_v2(&query).unwrap();
    assert_eq!(&encoded[..3], &[0x82, 0x18, 0x3d]);
    assert!(decode_kernel_executor_operation_v2(&encoded).is_ok());
}

#[test]
fn completion_acknowledgement_and_fetch_are_descriptor_bound() {
    let completion =
        ExecutorCompletionDescriptorV2::tool_result(Digest32V2::new([4; 32]), 1024).unwrap();
    let acknowledge = KernelExecutorOperationV2::AcknowledgeCommittedCompletion(
        AcknowledgeCommittedCompletionRequestV2::new(
            Nonce32V2::new([5; 32]),
            Digest32V2::new([6; 32]),
            Digest32V2::new([7; 32]),
            completion,
            Digest32V2::new([8; 32]),
        )
        .unwrap(),
    );
    let encoded = encode_kernel_executor_operation_v2(&acknowledge).unwrap();
    assert_eq!(&encoded[..3], &[0x82, 0x18, 0x3e]);
    assert!(decode_kernel_executor_operation_v2(&encoded).is_ok());

    let fetch = KernelExecutorOperationV2::FetchCompletion(
        FetchCompletionRequestV2::new(
            Nonce32V2::new([5; 32]),
            Digest32V2::new([6; 32]),
            Digest32V2::new([7; 32]),
            completion,
        )
        .unwrap(),
    );
    let encoded = encode_kernel_executor_operation_v2(&fetch).unwrap();
    assert_eq!(&encoded[..3], &[0x82, 0x18, 0x3f]);
    assert!(decode_kernel_executor_operation_v2(&encoded).is_ok());
}

#[test]
fn dispatch_is_a_typed_signed_core_and_hpke_envelope() {
    let binding = ToolExecutionSemanticBindingV2::new(
        PlanRevisionDigestV2::new([10; 32]),
        InternalStepIdV2::new([11; 32]),
        Digest32V2::new([12; 32]),
        Digest32V2::new([13; 32]),
        Digest32V2::new([14; 32]),
        Digest32V2::new([15; 32]),
        Digest32V2::new([16; 32]),
        Digest32V2::new([17; 32]),
        Digest32V2::new([18; 32]),
        Digest32V2::new([19; 32]),
        AttemptKindV2::new(20),
    )
    .unwrap();
    let subject =
        DispatchSubjectV2::tool_execution(ActionIntentIdV2::new([21; 32]), binding, None).unwrap();
    let core = DispatchCoreV2::new(
        Digest32V2::new([22; 32]),
        Digest32V2::new([23; 32]),
        24,
        25,
        DurableTaskIdV2::new([26; 32]),
        DurableRunIdV2::new([27; 32]),
        Nonce32V2::new([28; 32]),
        subject,
        ExecutorIdentityV2::new([29; 32]),
        HpkeX25519KeyIdV2::new([30; 32]),
        Digest32V2::new([31; 32]),
        UnixMillisV2::new(32),
    )
    .unwrap();
    let payload = SealedExecutionEnvelopePayloadV2::new(
        core,
        Digest32V2::new([32; 32]),
        FixedBytes32V2::new([33; 32]),
        BoundedCiphertextV2::new(vec![34; 64]).unwrap(),
    )
    .unwrap();
    let envelope = SignedSealedExecutionEnvelopeV2::from_parts(
        payload,
        Ed25519KeyIdV2::new([35; 32]),
        Ed25519SignatureV2::new([36; 64]),
    )
    .unwrap();
    let dispatch = KernelExecutorOperationV2::Dispatch(DispatchRequestV2::new(envelope));
    let encoded = encode_kernel_executor_operation_v2(&dispatch).unwrap();
    assert_eq!(&encoded[..3], &[0x82, 0x18, 0x3c]);
    assert!(decode_kernel_executor_operation_v2(&encoded).is_ok());

    assert!(DispatchCoreV2::new(
        Digest32V2::new([22; 32]),
        Digest32V2::new([23; 32]),
        0,
        25,
        DurableTaskIdV2::new([26; 32]),
        DurableRunIdV2::new([27; 32]),
        Nonce32V2::new([28; 32]),
        DispatchSubjectV2::tool_execution(ActionIntentIdV2::new([21; 32]), binding, None).unwrap(),
        ExecutorIdentityV2::new([29; 32]),
        HpkeX25519KeyIdV2::new([30; 32]),
        Digest32V2::new([31; 32]),
        UnixMillisV2::new(32),
    )
    .is_err());
}
