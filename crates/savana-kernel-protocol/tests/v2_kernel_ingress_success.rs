use ed25519_dalek::SigningKey;
use savana_kernel_protocol::v2::{
    approval_display_digest_v2, decode_finalize_input_response_v2,
    decode_prepare_ingress_ui_authentication_response_v2, decode_signed_approval_envelope_v2,
    derive_ed25519_key_id_v2, encode_finalize_input_response_v2,
    encode_prepare_ingress_ui_authentication_response_v2, encode_signed_approval_envelope_v2,
    ApprovalBindingV2, ApprovalPurposeV2, Digest32V2, DurableTaskIdV2, Ed25519KeyIdV2,
    Ed25519SignatureV2, FinalizeInputResponseV2, FixedOriginV2, IngressKernelApprovalHandleV2,
    IngressUiAuthenticationPreparationHandleV2, Nonce32V2, PendingIngressHandleV2,
    PrepareIngressUiAuthenticationResponseV2, PrincipalIdV2, ServiceIdentityV2,
    SignedApprovalEnvelopeV2, SignedUiAuthenticationEnvelopeV2, UiAuthenticationBindingV2,
    UiAuthenticationPurposeV2, UnixMillisV2, UnsignedApprovalEnvelopeV2,
    UnsignedUiAuthenticationEnvelopeV2,
};

#[test]
fn ingress_authentication_and_finalize_successes_are_typed_and_canonical() {
    let ui_envelope = SignedUiAuthenticationEnvelopeV2::from_canonical_parts(
        vec![0x81, 0x01],
        Ed25519KeyIdV2::new([0x11; 32]),
        Ed25519SignatureV2::new([0x12; 64]),
    )
    .unwrap();
    let prepared = PrepareIngressUiAuthenticationResponseV2::new(
        IngressUiAuthenticationPreparationHandleV2::from_authority_entropy([0x13; 32]).unwrap(),
        ui_envelope.clone(),
    );
    let prepared_bytes = encode_prepare_ingress_ui_authentication_response_v2(&prepared).unwrap();
    assert_eq!(
        decode_prepare_ingress_ui_authentication_response_v2(&prepared_bytes).unwrap(),
        prepared,
    );

    let approval_envelope = SignedApprovalEnvelopeV2::from_canonical_parts(
        vec![0x81, 0x02],
        Ed25519KeyIdV2::new([0x14; 32]),
        Ed25519SignatureV2::new([0x15; 64]),
    )
    .unwrap();
    let finalized = FinalizeInputResponseV2::new(
        PendingIngressHandleV2::from_authority_entropy([0x16; 32]).unwrap(),
        IngressKernelApprovalHandleV2::from_authority_entropy([0x17; 32]).unwrap(),
        approval_envelope,
        ui_envelope,
    );
    let finalized_bytes = encode_finalize_input_response_v2(&finalized).unwrap();
    assert_eq!(
        decode_finalize_input_response_v2(&finalized_bytes).unwrap(),
        finalized,
    );
}

#[test]
fn kernel_envelopes_are_typed_purpose_bound_and_signature_verified() {
    let key = SigningKey::from_bytes(&[0x91; 32]);
    let installation = Digest32V2::new([0x11; 32]);
    let manifest = Digest32V2::new([0x12; 32]);
    let principal = PrincipalIdV2::new([0x13; 32]);
    let ui_unsigned = UnsignedUiAuthenticationEnvelopeV2::new(
        installation,
        manifest,
        7,
        UiAuthenticationPurposeV2::IngressInput,
        UiAuthenticationBindingV2::IngressNewTask {
            durable_task_id: DurableTaskIdV2::new([0x14; 32]),
            pending_task_digest: Digest32V2::new([0x16; 32]),
            ingressd_identity: ServiceIdentityV2::new([0x15; 32]),
        },
        None,
        FixedOriginV2::Approval8766,
        FixedOriginV2::Ingress8767,
        Nonce32V2::new([0x17; 32]),
        UnixMillisV2::new(100),
        UnixMillisV2::new(200),
    )
    .unwrap();
    let ui_signed = SignedUiAuthenticationEnvelopeV2::sign(ui_unsigned, &key).unwrap();
    let ui_verified = ui_signed
        .verify(
            derive_ed25519_key_id_v2(key.verifying_key().to_bytes()),
            key.verifying_key().to_bytes(),
            installation,
            manifest,
            7,
            UnixMillisV2::new(150),
        )
        .unwrap();
    assert_eq!(ui_verified.binding(), ui_unsigned.binding());

    let display_bytes = vec![0x82, 0x01, 0x02];
    let approval_unsigned = UnsignedApprovalEnvelopeV2::new(
        installation,
        manifest,
        7,
        ApprovalPurposeV2::Ingress,
        Nonce32V2::new([0x18; 32]),
        Nonce32V2::new([0x19; 32]),
        ApprovalBindingV2::Ingress {
            pending_ingress_id: Digest32V2::new([0x20; 32]),
            ingress_subject_digest: Digest32V2::new([0x21; 32]),
            channel_commitments_digest: Digest32V2::new([0x22; 32]),
            source_provenance_digest: Digest32V2::new([0x23; 32]),
        },
        principal,
        Digest32V2::new([0x24; 32]),
        approval_display_digest_v2(&display_bytes),
        display_bytes.clone(),
        None,
        ServiceIdentityV2::new([0x26; 32]),
        UnixMillisV2::new(100),
        UnixMillisV2::new(200),
    )
    .unwrap();
    assert_eq!(approval_unsigned.display_bytes(), display_bytes);
    assert!(UnsignedApprovalEnvelopeV2::new(
        installation,
        manifest,
        7,
        ApprovalPurposeV2::Ingress,
        Nonce32V2::new([0x18; 32]),
        Nonce32V2::new([0x19; 32]),
        ApprovalBindingV2::Ingress {
            pending_ingress_id: Digest32V2::new([0x20; 32]),
            ingress_subject_digest: Digest32V2::new([0x21; 32]),
            channel_commitments_digest: Digest32V2::new([0x22; 32]),
            source_provenance_digest: Digest32V2::new([0x23; 32]),
        },
        principal,
        Digest32V2::new([0x24; 32]),
        approval_display_digest_v2(&display_bytes),
        vec![0x81, 0x03],
        None,
        ServiceIdentityV2::new([0x26; 32]),
        UnixMillisV2::new(100),
        UnixMillisV2::new(200),
    )
    .is_err());
    let approval_signed = SignedApprovalEnvelopeV2::sign(approval_unsigned.clone(), &key).unwrap();
    let approval_verified = approval_signed
        .verify(
            derive_ed25519_key_id_v2(key.verifying_key().to_bytes()),
            key.verifying_key().to_bytes(),
            installation,
            manifest,
            7,
            ApprovalPurposeV2::Ingress,
            principal,
            UnixMillisV2::new(150),
        )
        .unwrap();
    assert_eq!(approval_verified.binding(), approval_unsigned.binding());
}

#[test]
fn approval_signed_wire_round_trips_bounded_display_larger_than_ui_auth_limit() {
    let key = SigningKey::from_bytes(&[0xa1; 32]);
    let installation = Digest32V2::new([0xa2; 32]);
    let manifest = Digest32V2::new([0xa3; 32]);
    let principal = PrincipalIdV2::new([0xa4; 32]);
    let display_bytes = vec![0x5a; 16 * 1024];
    let unsigned = UnsignedApprovalEnvelopeV2::new(
        installation,
        manifest,
        9,
        ApprovalPurposeV2::Ingress,
        Nonce32V2::new([0xa5; 32]),
        Nonce32V2::new([0xa6; 32]),
        ApprovalBindingV2::Ingress {
            pending_ingress_id: Digest32V2::new([0xa7; 32]),
            ingress_subject_digest: Digest32V2::new([0xa8; 32]),
            channel_commitments_digest: Digest32V2::new([0xa9; 32]),
            source_provenance_digest: Digest32V2::new([0xaa; 32]),
        },
        principal,
        Digest32V2::new([0xab; 32]),
        approval_display_digest_v2(&display_bytes),
        display_bytes.clone(),
        None,
        ServiceIdentityV2::new([0xac; 32]),
        UnixMillisV2::new(100),
        UnixMillisV2::new(200),
    )
    .unwrap();
    let signed = SignedApprovalEnvelopeV2::sign(unsigned, &key).unwrap();
    let canonical = encode_signed_approval_envelope_v2(&signed).unwrap();
    let decoded = decode_signed_approval_envelope_v2(&canonical).unwrap();
    let verified = decoded
        .verify(
            derive_ed25519_key_id_v2(key.verifying_key().to_bytes()),
            key.verifying_key().to_bytes(),
            installation,
            manifest,
            9,
            ApprovalPurposeV2::Ingress,
            principal,
            UnixMillisV2::new(150),
        )
        .unwrap();
    assert_eq!(verified.display_bytes(), display_bytes);
}
