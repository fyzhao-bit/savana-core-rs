use savana_kernel_protocol::v2::{
    decode_connector_registry_sync_response_v2, decode_kernel_executor_operation_v2,
    derive_ed25519_key_id_v2, encode_connector_registry_sync_response_v2,
    encode_kernel_executor_operation_v2, kernel_executor_operation_tags_v2,
    kernel_service_operation_has_error_contract_v2, kernel_service_public_error_is_allowed_v2,
    AcknowledgeCommittedCompletionRequestV2, ActionIntentIdV2, AttemptKindV2, BoundedCiphertextV2,
    BoundedConnectorRegistryDeltaV2, ConnectorRegistrySyncModeV2, ConnectorRegistrySyncPageV2,
    ConnectorRegistrySyncRequestV2, ConnectorRegistrySyncResponseV2, ConnectorRegistrySyncScopeV2,
    ConnectorRegistrySyncStatusV2, Digest32V2, DispatchCoreV2, DispatchRequestV2,
    DispatchSubjectV2, DispatchTaskBindingV2, DurableRunIdV2, DurableTaskIdV2, Ed25519KeyIdV2,
    Ed25519SignatureV2, EndpointRoleV2, ExecutorCompletionDescriptorV2, ExecutorHealthRequestV2,
    ExecutorIdentityV2, FetchCompletionRequestV2, FixedBytes32V2, HpkeX25519KeyIdV2,
    InternalStepIdV2, KernelExecutorOperationV2, Nonce32V2, PlanRevisionDigestV2,
    PublicStableCodeV2, QueryByExecutionNonceRequestV2, SealedExecutionEnvelopePayloadV2,
    SignedSealedExecutionEnvelopeV2, ToolExecutionSemanticBindingV2, UnixMillisV2,
    MAX_CONNECTOR_REGISTRY_SYNC_PAGE_DELTAS_V2, MAX_CONNECTOR_REGISTRY_SYNC_PAGE_DELTA_BYTES_V2,
};

fn sync_scope(authority_enabled: bool) -> ConnectorRegistrySyncScopeV2 {
    let authority_public_key = if authority_enabled { [6; 32] } else { [0; 32] };
    let authority_key_id = if authority_enabled {
        *derive_ed25519_key_id_v2(authority_public_key).as_bytes()
    } else {
        [0; 32]
    };
    ConnectorRegistrySyncScopeV2::new(
        Digest32V2::new([1; 32]),
        Digest32V2::new([2; 32]),
        3,
        Digest32V2::new([4; 32]),
        Ed25519KeyIdV2::new(authority_key_id),
        FixedBytes32V2::new(authority_public_key),
        Digest32V2::new([7; 32]),
    )
    .unwrap()
}

fn sync_page() -> ConnectorRegistrySyncPageV2 {
    ConnectorRegistrySyncPageV2::new(
        0,
        Digest32V2::new([1; 32]),
        1,
        Digest32V2::new([2; 32]),
        2,
        Digest32V2::new([3; 32]),
        vec![BoundedConnectorRegistryDeltaV2::new(vec![0x01]).unwrap()],
    )
    .unwrap()
}

fn canonical_byte_string_with_total_length(total_length: usize) -> Vec<u8> {
    let payload_length = u32::try_from(total_length.checked_sub(5).unwrap()).unwrap();
    let mut bytes = Vec::with_capacity(total_length);
    bytes.push(0x5a);
    bytes.extend_from_slice(&payload_length.to_be_bytes());
    bytes.resize(total_length, 0);
    bytes
}

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

    let task_binding = DispatchTaskBindingV2::new(
        Digest32V2::new([41; 32]),
        Digest32V2::new([42; 32]),
        Digest32V2::new([43; 32]),
    )
    .unwrap();
    let bound = core.with_task_binding(task_binding);
    // Independent subject encoding oracle: legacy uses bare 20; schema 3 uses
    // the policy owner's one-element closed attempt-kind tuple [20].
    let mut legacy_binding = minicbor::to_vec(binding).unwrap();
    assert_eq!(legacy_binding.pop(), Some(20));
    for (candidate, tail) in [(core, vec![20]), (bound, vec![0x81, 20])] {
        use sha2::{Digest as _, Sha256};
        let mut expected = minicbor::Encoder::new(Vec::new());
        expected
            .array(4)
            .unwrap()
            .u16(1)
            .unwrap()
            .bytes(&[21; 32])
            .unwrap();
        expected.writer_mut().extend_from_slice(&legacy_binding);
        expected.writer_mut().extend_from_slice(&tail);
        expected.null().unwrap();
        let digest: [u8; 32] = Sha256::new()
            .chain_update(b"SAVANA_DISPATCH_SUBJECT_V2\0")
            .chain_update(expected.into_writer())
            .finalize()
            .into();
        assert_eq!(*candidate.dispatch_subject_digest().as_bytes(), digest);
        assert_eq!(
            candidate.computed_subject_digest().unwrap(),
            candidate.dispatch_subject_digest()
        );
    }
    assert_eq!(
        core.dispatch_subject_digest(),
        subject.semantic_digest().unwrap()
    );
    assert_ne!(
        bound.dispatch_subject_digest(),
        core.dispatch_subject_digest()
    );
    assert_ne!(
        core.semantic_digest().unwrap(),
        bound.semantic_digest().unwrap()
    );
    assert_eq!(core.task_binding(), None);
    for changed in [[44, 42, 43], [41, 44, 43], [41, 42, 44]] {
        let b = DispatchTaskBindingV2::new(
            Digest32V2::new([changed[0]; 32]),
            Digest32V2::new([changed[1]; 32]),
            Digest32V2::new([changed[2]; 32]),
        )
        .unwrap();
        assert_ne!(
            bound.semantic_digest().unwrap(),
            core.with_task_binding(b).semantic_digest().unwrap()
        );
    }
    assert!(DispatchTaskBindingV2::new(
        Digest32V2::new([0; 32]),
        Digest32V2::new([42; 32]),
        Digest32V2::new([43; 32])
    )
    .is_err());
    let envelope = SignedSealedExecutionEnvelopeV2::from_parts(
        SealedExecutionEnvelopePayloadV2::new(
            bound,
            Digest32V2::new([32; 32]),
            FixedBytes32V2::new([33; 32]),
            BoundedCiphertextV2::new(vec![34; 64]).unwrap(),
        )
        .unwrap(),
        Ed25519KeyIdV2::new([35; 32]),
        Ed25519SignatureV2::new([36; 64]),
    )
    .unwrap();
    let encoded = encode_kernel_executor_operation_v2(&KernelExecutorOperationV2::Dispatch(
        DispatchRequestV2::new(envelope),
    ))
    .unwrap();
    let decoded = decode_kernel_executor_operation_v2(&encoded).unwrap();
    assert_eq!(
        encode_kernel_executor_operation_v2(&decoded).unwrap(),
        encoded
    );
    let KernelExecutorOperationV2::Dispatch(decoded) = decoded else {
        panic!("wrong operation")
    };
    assert_eq!(
        decoded.envelope().payload().core().task_binding(),
        Some(task_binding)
    );

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

#[test]
fn registry_sync_probe_has_a_separate_closed_executor_tag() {
    // Catches removing tag 64 from the closed executor routing contract or
    // substituting a browser snapshot for the authenticated sync operation.
    let request =
        ConnectorRegistrySyncRequestV2::new(sync_scope(true), ConnectorRegistrySyncModeV2::Probe)
            .unwrap();
    let operation = KernelExecutorOperationV2::ConnectorRegistrySync(request.clone());
    let encoded = encode_kernel_executor_operation_v2(&operation).unwrap();

    assert_eq!(
        kernel_executor_operation_tags_v2(),
        &[0, 60, 61, 62, 63, 64]
    );
    assert_eq!(operation.tag(), 64);
    assert_eq!(&encoded[..3], &[0x82, 0x18, 0x40]);
    assert_eq!(
        decode_kernel_executor_operation_v2(&encoded).unwrap(),
        operation
    );
    assert_eq!(request.scope().deployment_generation(), 3);
    assert!(request.scope().authority_enabled());
    assert!(matches!(request.mode(), ConnectorRegistrySyncModeV2::Probe));
    assert!(kernel_service_operation_has_error_contract_v2(
        EndpointRoleV2::KernelExecutor,
        64,
    ));
    assert!(kernel_service_public_error_is_allowed_v2(
        EndpointRoleV2::KernelExecutor,
        64,
        PublicStableCodeV2::RegistryMismatch,
    ));
}

#[test]
fn registry_sync_page_derives_and_round_trips_its_commitment() {
    // Catches accepting a caller-claimed page commitment or dropping page,
    // source, or base bindings from the commitment.
    let page = sync_page();
    assert_eq!(
        page.commitment(),
        Digest32V2::new([
            0x95, 0xd4, 0xb7, 0xaf, 0xf0, 0x88, 0x7e, 0x18, 0x7c, 0x77, 0x96, 0x9e, 0x91, 0x62,
            0x5f, 0xae, 0x81, 0x5d, 0x7e, 0x7c, 0xd0, 0x74, 0x4e, 0xb2, 0xa1, 0xff, 0x21, 0x34,
            0xe6, 0x27, 0x3b, 0x2f,
        ])
    );
    assert_eq!(page.base_sequence(), 0);
    assert_eq!(page.page_final_sequence(), 1);
    assert_eq!(page.source_final_sequence(), 2);
    assert_eq!(page.deltas()[0].as_bytes(), &[0x01]);

    let request = ConnectorRegistrySyncRequestV2::new(
        sync_scope(true),
        ConnectorRegistrySyncModeV2::ApplyPage(page),
    )
    .unwrap();
    let operation = KernelExecutorOperationV2::ConnectorRegistrySync(request);
    let encoded = encode_kernel_executor_operation_v2(&operation).unwrap();
    assert_eq!(
        decode_kernel_executor_operation_v2(&encoded).unwrap(),
        operation
    );

    let mut wrong_commitment = encoded.clone();
    *wrong_commitment.last_mut().unwrap() ^= 1;
    assert!(decode_kernel_executor_operation_v2(&wrong_commitment).is_err());

    let commitment_header = encoded.len() - 34;
    assert_eq!(
        &encoded[commitment_header..commitment_header + 2],
        &[0x58, 0x20]
    );
    let mut noncanonical_commitment = encoded[..commitment_header].to_vec();
    noncanonical_commitment.extend_from_slice(&[0x59, 0x00, 0x20]);
    noncanonical_commitment.extend_from_slice(&encoded[commitment_header + 2..]);
    assert!(decode_kernel_executor_operation_v2(&noncanonical_commitment).is_err());

    let mut noncanonical_tag = vec![0x82, 0x19, 0x00, 0x40];
    noncanonical_tag.extend_from_slice(&encoded[3..]);
    assert!(decode_kernel_executor_operation_v2(&noncanonical_tag).is_err());
}

#[test]
fn registry_sync_scope_and_pages_reject_ambiguous_or_unbounded_authority() {
    // Catches half-disabled authority identity, zero-authority delta sync,
    // sequence ambiguity, empty pages, excessive count, and request overflow.
    assert!(ConnectorRegistrySyncScopeV2::new(
        Digest32V2::new([1; 32]),
        Digest32V2::new([2; 32]),
        3,
        Digest32V2::new([4; 32]),
        Ed25519KeyIdV2::new([0; 32]),
        FixedBytes32V2::new([6; 32]),
        Digest32V2::new([7; 32]),
    )
    .is_err());
    assert!(ConnectorRegistrySyncScopeV2::new(
        Digest32V2::new([1; 32]),
        Digest32V2::new([2; 32]),
        3,
        Digest32V2::new([4; 32]),
        Ed25519KeyIdV2::new([5; 32]),
        FixedBytes32V2::new([6; 32]),
        Digest32V2::new([7; 32]),
    )
    .is_err());
    assert!(ConnectorRegistrySyncScopeV2::new(
        Digest32V2::new([1; 32]),
        Digest32V2::new([2; 32]),
        3,
        Digest32V2::new([4; 32]),
        Ed25519KeyIdV2::new([5; 32]),
        FixedBytes32V2::new([0; 32]),
        Digest32V2::new([7; 32]),
    )
    .is_err());
    assert!(ConnectorRegistrySyncRequestV2::new(
        sync_scope(false),
        ConnectorRegistrySyncModeV2::ApplyPage(sync_page()),
    )
    .is_err());
    assert!(ConnectorRegistrySyncPageV2::new(
        0,
        Digest32V2::new([1; 32]),
        0,
        Digest32V2::new([2; 32]),
        0,
        Digest32V2::new([2; 32]),
        Vec::new(),
    )
    .is_err());
    assert!(ConnectorRegistrySyncPageV2::new(
        0,
        Digest32V2::new([1; 32]),
        1,
        Digest32V2::new([2; 32]),
        2,
        Digest32V2::new([2; 32]),
        vec![BoundedConnectorRegistryDeltaV2::new(vec![0x01]).unwrap()],
    )
    .is_err());
    assert!(ConnectorRegistrySyncPageV2::new(
        0,
        Digest32V2::new([1; 32]),
        2,
        Digest32V2::new([2; 32]),
        2,
        Digest32V2::new([2; 32]),
        vec![BoundedConnectorRegistryDeltaV2::new(vec![0x01]).unwrap()],
    )
    .is_err());
    assert!(ConnectorRegistrySyncPageV2::new(
        0,
        Digest32V2::new([1; 32]),
        1,
        Digest32V2::new([2; 32]),
        1,
        Digest32V2::new([3; 32]),
        vec![BoundedConnectorRegistryDeltaV2::new(vec![0x01]).unwrap()],
    )
    .is_err());

    let too_many = (0..=MAX_CONNECTOR_REGISTRY_SYNC_PAGE_DELTAS_V2)
        .map(|_| BoundedConnectorRegistryDeltaV2::new(vec![0x01]).unwrap())
        .collect();
    assert!(ConnectorRegistrySyncPageV2::new(
        0,
        Digest32V2::new([1; 32]),
        u64::try_from(MAX_CONNECTOR_REGISTRY_SYNC_PAGE_DELTAS_V2 + 1).unwrap(),
        Digest32V2::new([2; 32]),
        u64::try_from(MAX_CONNECTOR_REGISTRY_SYNC_PAGE_DELTAS_V2 + 1).unwrap(),
        Digest32V2::new([2; 32]),
        too_many,
    )
    .is_err());

    let oversized = BoundedConnectorRegistryDeltaV2::new(canonical_byte_string_with_total_length(
        MAX_CONNECTOR_REGISTRY_SYNC_PAGE_DELTA_BYTES_V2 + 1,
    ))
    .unwrap();
    assert!(ConnectorRegistrySyncPageV2::new(
        0,
        Digest32V2::new([1; 32]),
        1,
        Digest32V2::new([2; 32]),
        1,
        Digest32V2::new([2; 32]),
        vec![oversized],
    )
    .is_err());

    let maximum = BoundedConnectorRegistryDeltaV2::new(canonical_byte_string_with_total_length(
        MAX_CONNECTOR_REGISTRY_SYNC_PAGE_DELTA_BYTES_V2,
    ))
    .unwrap();
    let maximum_page = ConnectorRegistrySyncPageV2::new(
        0,
        Digest32V2::new([1; 32]),
        1,
        Digest32V2::new([2; 32]),
        1,
        Digest32V2::new([2; 32]),
        vec![maximum],
    )
    .unwrap();
    let maximum_request = KernelExecutorOperationV2::ConnectorRegistrySync(
        ConnectorRegistrySyncRequestV2::new(
            sync_scope(true),
            ConnectorRegistrySyncModeV2::ApplyPage(maximum_page),
        )
        .unwrap(),
    );
    assert!(
        encode_kernel_executor_operation_v2(&maximum_request)
            .unwrap()
            .len()
            < 8 * 1024 * 1024
    );
}

#[test]
fn registry_sync_response_is_typed_and_canonical() {
    // Catches replacing convergence state with a caller-controlled raw head
    // setter or accepting noncanonical/invalid executor observations.
    for (status, sequence) in [
        (ConnectorRegistrySyncStatusV2::Converged, 4),
        (ConnectorRegistrySyncStatusV2::Behind, 3),
        (ConnectorRegistrySyncStatusV2::Diverged, 2),
        (ConnectorRegistrySyncStatusV2::DisabledGenesisOnly, 0),
    ] {
        let response =
            ConnectorRegistrySyncResponseV2::new(status, sequence, Digest32V2::new([9; 32]))
                .unwrap();
        let encoded = encode_connector_registry_sync_response_v2(&response).unwrap();
        assert_eq!(
            decode_connector_registry_sync_response_v2(&encoded).unwrap(),
            response
        );
    }

    assert!(ConnectorRegistrySyncResponseV2::new(
        ConnectorRegistrySyncStatusV2::Converged,
        1,
        Digest32V2::new([0; 32]),
    )
    .is_err());
    assert!(ConnectorRegistrySyncResponseV2::new(
        ConnectorRegistrySyncStatusV2::DisabledGenesisOnly,
        1,
        Digest32V2::new([9; 32]),
    )
    .is_err());

    let response = ConnectorRegistrySyncResponseV2::new(
        ConnectorRegistrySyncStatusV2::Behind,
        1,
        Digest32V2::new([9; 32]),
    )
    .unwrap();
    let canonical = encode_connector_registry_sync_response_v2(&response).unwrap();
    let mut noncanonical_status = vec![0x83, 0x18, 0x01];
    noncanonical_status.extend_from_slice(&canonical[2..]);
    assert!(decode_connector_registry_sync_response_v2(&noncanonical_status).is_err());
}
