use savana_kernel_protocol::v2::{
    decode_kernel_ingress_operation_v2, encode_kernel_ingress_operation_v2,
    kernel_ingress_operation_tags_v2, AbortInputRequestV2, AppendInputChunkRequestV2,
    AppendParserWorkerPageFrameRequestV2, ApprovalDecisionV2, ApprovalPurposeV2,
    AuthenticateIngressUiRequestV2, BeginInputRequestV2, CommitInputSettlementRequestV2,
    CommitParserWorkerResultRequestV2, ContentKindV2, Digest32V2, DirectInputChannelV2,
    Ed25519KeyIdV2, Ed25519SignatureV2, FinalizeInputRequestV2, FixedBytes32V2, FixedOriginV2,
    GetInputStatusRequestV2, ImplementationIdV2, IngressKernelApprovalHandleV2,
    IngressUiAuthenticationPreparationHandleV2, IngressUiAuthorizationHandleV2,
    IngressWriteCapabilityV2, InputChannelCommitmentV2, InputChannelV2, InputSessionHandleV2,
    InputSourceKindV2, InputSourceProvenanceV2, InputStatusTargetV2,
    KernelIngressBootstrapTransferCapabilityV2, KernelIngressHealthRequestV2,
    KernelIngressOperationV2, Nonce32V2, ParserExtractionHandleV2, ParserWorkerPageFrameV2,
    PendingIngressHandleV2, PrepareIngressUiAuthenticationRequestV2, PrincipalIdV2,
    RegisterParserWorkerJobRequestV2, SignedApprovalSettlementV2,
    SignedParserWorkerJobDescriptorV2, SignedParserWorkerResultAttestationV2,
    SignedUiAuthenticationSettlementV2, UiAuthenticationPurposeV2, UnixMillisV2,
    UnsignedApprovalSettlementV2, UnsignedParserWorkerJobDescriptorV2,
    UnsignedParserWorkerResultAttestationV2, UnsignedUiAuthenticationSettlementV2, VersionV2,
    ZeroizingBytesV2,
};

#[test]
fn ingress_health_and_pre_input_authentication_are_closed() {
    assert_eq!(
        kernel_ingress_operation_tags_v2(),
        &[0, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50]
    );
    let health = KernelIngressOperationV2::Health(KernelIngressHealthRequestV2);
    assert_eq!(
        encode_kernel_ingress_operation_v2(&health).unwrap(),
        [0x82, 0x00, 0x80]
    );

    let transfer =
        KernelIngressBootstrapTransferCapabilityV2::from_authority_entropy([1; 32]).unwrap();
    let prepare = KernelIngressOperationV2::PrepareIngressUiAuthentication(
        PrepareIngressUiAuthenticationRequestV2::new(transfer),
    );
    let encoded = encode_kernel_ingress_operation_v2(&prepare).unwrap();
    assert_eq!(&encoded[..3], &[0x82, 0x18, 0x2e]);
    assert_eq!(
        encode_kernel_ingress_operation_v2(&decode_kernel_ingress_operation_v2(&encoded).unwrap())
            .unwrap(),
        encoded
    );

    let authenticate = KernelIngressOperationV2::AuthenticateIngressUi(
        AuthenticateIngressUiRequestV2::new(
            IngressUiAuthenticationPreparationHandleV2::from_authority_entropy([2; 32]).unwrap(),
            signed_ingress_ui_settlement(),
        )
        .unwrap(),
    );
    let encoded = encode_kernel_ingress_operation_v2(&authenticate).unwrap();
    assert_eq!(&encoded[..3], &[0x82, 0x18, 0x2f]);
    assert!(decode_kernel_ingress_operation_v2(&encoded).is_ok());
}

#[test]
fn direct_input_flow_is_typed_bounded_and_cannot_select_extracted_page() {
    let authorization = IngressUiAuthorizationHandleV2::from_authority_entropy([3; 32]).unwrap();
    let begin = KernelIngressOperationV2::BeginInput(
        BeginInputRequestV2::new(
            authorization,
            ContentKindV2::ChatText,
            4,
            Some(Digest32V2::new([4; 32])),
        )
        .unwrap(),
    );
    let encoded = encode_kernel_ingress_operation_v2(&begin).unwrap();
    assert_eq!(&encoded[..3], &[0x82, 0x18, 0x28]);
    assert!(decode_kernel_ingress_operation_v2(&encoded).is_ok());

    let append = KernelIngressOperationV2::AppendInputChunk(
        AppendInputChunkRequestV2::new(
            IngressWriteCapabilityV2::from_authority_entropy([5; 32]).unwrap(),
            DirectInputChannelV2::ChatText,
            0,
            Digest32V2::new([6; 32]),
            ZeroizingBytesV2::new(b"test".to_vec()).unwrap(),
            Digest32V2::new([7; 32]),
            Digest32V2::new([8; 32]),
        )
        .unwrap(),
    );
    let encoded = encode_kernel_ingress_operation_v2(&append).unwrap();
    assert_eq!(&encoded[..3], &[0x82, 0x18, 0x29]);
    assert!(decode_kernel_ingress_operation_v2(&encoded).is_ok());
    assert!(decode_kernel_ingress_operation_v2(&[0x82, 0x18, 0x29, 0x87, 0x58, 0x20,]).is_err());
}

#[test]
fn finalize_settle_abort_and_status_have_exact_typed_targets() {
    let session = InputSessionHandleV2::from_authority_entropy([9; 32]).unwrap();
    let commitment =
        InputChannelCommitmentV2::new(InputChannelV2::ChatText, 1, 0, 4, Digest32V2::new([10; 32]))
            .unwrap();
    let provenance = InputSourceProvenanceV2::direct(
        InputSourceKindV2::Chat,
        4,
        Digest32V2::new([11; 32]),
        VersionV2::new(1, 0, 0),
    )
    .unwrap();
    let finalize = KernelIngressOperationV2::FinalizeInput(
        FinalizeInputRequestV2::new(session, vec![commitment], provenance).unwrap(),
    );
    let encoded = encode_kernel_ingress_operation_v2(&finalize).unwrap();
    assert_eq!(&encoded[..3], &[0x82, 0x18, 0x2a]);
    assert!(decode_kernel_ingress_operation_v2(&encoded).is_ok());

    let pending = PendingIngressHandleV2::from_authority_entropy([12; 32]).unwrap();
    let approval = IngressKernelApprovalHandleV2::from_authority_entropy([13; 32]).unwrap();
    let settle = KernelIngressOperationV2::CommitInputSettlement(
        CommitInputSettlementRequestV2::new(pending, approval, signed_ingress_approval()).unwrap(),
    );
    let encoded = encode_kernel_ingress_operation_v2(&settle).unwrap();
    assert_eq!(&encoded[..3], &[0x82, 0x18, 0x2b]);
    assert!(decode_kernel_ingress_operation_v2(&encoded).is_ok());

    let abort = KernelIngressOperationV2::AbortInput(AbortInputRequestV2::new(session));
    let encoded = encode_kernel_ingress_operation_v2(&abort).unwrap();
    assert_eq!(&encoded[..3], &[0x82, 0x18, 0x2c]);
    assert!(decode_kernel_ingress_operation_v2(&encoded).is_ok());

    let status = KernelIngressOperationV2::GetInputStatus(GetInputStatusRequestV2::new(
        InputStatusTargetV2::Pending(pending),
    ));
    let encoded = encode_kernel_ingress_operation_v2(&status).unwrap();
    assert_eq!(&encoded[..3], &[0x82, 0x18, 0x2d]);
    assert!(decode_kernel_ingress_operation_v2(&encoded).is_ok());
}

#[test]
fn parser_staging_operations_bind_signed_job_frames_and_result() {
    let job_nonce = Nonce32V2::new([60; 32]);
    let session_binding = Digest32V2::new([61; 32]);
    let ephemeral_key_id = Ed25519KeyIdV2::new([62; 32]);
    let unsigned_job = UnsignedParserWorkerJobDescriptorV2::new(
        Digest32V2::new([63; 32]),
        Digest32V2::new([64; 32]),
        65,
        savana_kernel_protocol::v2::ServiceIdentityV2::new([66; 32]),
        job_nonce,
        session_binding,
        4,
        Digest32V2::new([67; 32]),
        savana_kernel_protocol::v2::ClosedMediaTypeV2::new(68),
        savana_kernel_protocol::v2::ClosedMediaTypeV2::new(69),
        Digest32V2::new([70; 32]),
        ImplementationIdV2::new(71),
        Digest32V2::new([72; 32]),
        None,
        None,
        VersionV2::new(1, 0, 0),
        Digest32V2::new([73; 32]),
        FixedBytes32V2::new([74; 32]),
        ephemeral_key_id,
        UnixMillisV2::new(75),
    )
    .unwrap();
    let descriptor = SignedParserWorkerJobDescriptorV2::from_parts(
        unsigned_job,
        Ed25519KeyIdV2::new([76; 32]),
        Ed25519SignatureV2::new([77; 64]),
    )
    .unwrap();
    let register =
        KernelIngressOperationV2::RegisterParserWorkerJob(RegisterParserWorkerJobRequestV2::new(
            InputSessionHandleV2::from_authority_entropy([78; 32]).unwrap(),
            descriptor,
        ));
    let encoded = encode_kernel_ingress_operation_v2(&register).unwrap();
    assert_eq!(&encoded[..3], &[0x82, 0x18, 0x30]);
    assert!(decode_kernel_ingress_operation_v2(&encoded).is_ok());

    let extraction = ParserExtractionHandleV2::from_authority_entropy([79; 32]).unwrap();
    let frame = ParserWorkerPageFrameV2::new(
        job_nonce,
        0,
        0,
        true,
        Digest32V2::new([80; 32]),
        ZeroizingBytesV2::new(b"page".to_vec()).unwrap(),
        Digest32V2::new([81; 32]),
        Digest32V2::new([82; 32]),
    )
    .unwrap();
    let append = KernelIngressOperationV2::AppendParserWorkerPageFrame(
        AppendParserWorkerPageFrameRequestV2::new(extraction, frame),
    );
    let encoded = encode_kernel_ingress_operation_v2(&append).unwrap();
    assert_eq!(&encoded[..3], &[0x82, 0x18, 0x31]);
    assert!(decode_kernel_ingress_operation_v2(&encoded).is_ok());

    let page = savana_kernel_protocol::v2::PageProvenanceV2::new(
        0,
        0,
        1,
        4,
        Digest32V2::new([80; 32]),
        4,
        Digest32V2::new([83; 32]),
        4,
        savana_kernel_protocol::v2::ClosedConfidenceClassV2::new(1),
    )
    .unwrap();
    let unsigned_result = UnsignedParserWorkerResultAttestationV2::new(
        job_nonce,
        Digest32V2::new([84; 32]),
        session_binding,
        Digest32V2::new([70; 32]),
        ephemeral_key_id,
        4,
        Digest32V2::new([67; 32]),
        1,
        vec![page],
        Digest32V2::new([85; 32]),
        4,
        Digest32V2::new([86; 32]),
        UnixMillisV2::new(87),
    )
    .unwrap();
    let attestation = SignedParserWorkerResultAttestationV2::from_parts(
        unsigned_result,
        ephemeral_key_id,
        Ed25519SignatureV2::new([88; 64]),
    )
    .unwrap();
    let commit = KernelIngressOperationV2::CommitParserWorkerResult(
        CommitParserWorkerResultRequestV2::new(extraction, attestation),
    );
    let encoded = encode_kernel_ingress_operation_v2(&commit).unwrap();
    assert_eq!(&encoded[..3], &[0x82, 0x18, 0x32]);
    assert!(decode_kernel_ingress_operation_v2(&encoded).is_ok());
}

fn signed_ingress_approval() -> SignedApprovalSettlementV2 {
    let unsigned = UnsignedApprovalSettlementV2::new(
        Digest32V2::new([20; 32]),
        Digest32V2::new([21; 32]),
        22,
        ApprovalPurposeV2::Ingress,
        Digest32V2::new([23; 32]),
        ApprovalDecisionV2::Approve,
        PrincipalIdV2::new([24; 32]),
        Digest32V2::new([25; 32]),
        Digest32V2::new([26; 32]),
        true,
        true,
        false,
        false,
        27,
        Nonce32V2::new([28; 32]),
        Nonce32V2::new([29; 32]),
        UnixMillisV2::new(30),
        UnixMillisV2::new(31),
    )
    .unwrap();
    SignedApprovalSettlementV2::from_parts(
        unsigned,
        Ed25519KeyIdV2::new([32; 32]),
        Ed25519SignatureV2::new([33; 64]),
    )
    .unwrap()
}

fn signed_ingress_ui_settlement() -> SignedUiAuthenticationSettlementV2 {
    let unsigned = UnsignedUiAuthenticationSettlementV2::new(
        Digest32V2::new([40; 32]),
        Digest32V2::new([41; 32]),
        42,
        UiAuthenticationPurposeV2::IngressInput,
        Digest32V2::new([43; 32]),
        Digest32V2::new([44; 32]),
        FixedOriginV2::Approval8766,
        FixedOriginV2::Ingress8767,
        PrincipalIdV2::new([45; 32]),
        Digest32V2::new([46; 32]),
        Digest32V2::new([47; 32]),
        true,
        true,
        false,
        false,
        48,
        Nonce32V2::new([49; 32]),
        Nonce32V2::new([50; 32]),
        UnixMillisV2::new(51),
        UnixMillisV2::new(52),
    )
    .unwrap();
    SignedUiAuthenticationSettlementV2::from_parts(
        unsigned,
        Ed25519KeyIdV2::new([53; 32]),
        Ed25519SignatureV2::new([54; 64]),
    )
    .unwrap()
}
