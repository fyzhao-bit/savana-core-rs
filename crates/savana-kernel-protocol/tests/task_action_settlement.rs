use ed25519_dalek::SigningKey;
use savana_kernel_protocol::v2::*;

fn d(n: u8) -> Digest32V2 {
    Digest32V2::new([n; 32])
}
fn envelope() -> UnsignedApprovalEnvelopeV2 {
    let text = BoundedApprovalDisplayTextV2::new("Send A to Alice; 1 item".into()).unwrap();
    let semantic = ToolExecutionSemanticBindingV2::new(
        PlanRevisionDigestV2::new([1; 32]),
        InternalStepIdV2::new([2; 32]),
        d(3),
        d(4),
        d(5),
        d(6),
        d(7),
        d(8),
        d(9),
        d(10),
        AttemptKindV2::new(1),
    )
    .unwrap();
    UnsignedApprovalEnvelopeV2::new(
        d(11),
        d(12),
        7,
        ApprovalPurposeV2::ToolExecution,
        Nonce32V2::new([13; 32]),
        Nonce32V2::new([14; 32]),
        ApprovalBindingV2::ToolExecution {
            action_intent_id: ActionIntentIdV2::new([15; 32]),
            binding: semantic,
        },
        PrincipalIdV2::new([16; 32]),
        d(17),
        approval_display_digest_v2(text.as_bytes()),
        text,
        Some(d(18)),
        ServiceIdentityV2::new([19; 32]),
        UnixMillisV2::new(100),
        UnixMillisV2::new(1000),
    )
    .unwrap()
    .with_task_action_binding(
        TaskActionApprovalBindingV2::new(d(20), d(21), 1, DurableTaskIdV2::new([22; 32])).unwrap(),
    )
    .unwrap()
}

#[test]
fn task_action_envelope_and_settlement_bind_distinct_exact_context() {
    let issuer = SigningKey::from_bytes(&[30; 32]);
    let approval_key = SigningKey::from_bytes(&[31; 32]);
    let original = envelope();
    let signed = SignedApprovalEnvelopeV2::sign(original.clone(), &issuer).unwrap();
    let bytes = encode_signed_approval_envelope_v2(&signed).unwrap();
    let decoded = decode_signed_approval_envelope_v2(&bytes)
        .unwrap()
        .unverified_material()
        .unwrap();
    assert_eq!(decoded, original);
    let generic = UnsignedApprovalSettlementV2::new(
        d(11),
        d(12),
        7,
        ApprovalPurposeV2::ToolExecution,
        signed.envelope_digest().unwrap(),
        ApprovalDecisionV2::Approve,
        PrincipalIdV2::new([16; 32]),
        d(32),
        d(33),
        true,
        true,
        false,
        false,
        2,
        Nonce32V2::new([14; 32]),
        Nonce32V2::new([34; 32]),
        UnixMillisV2::new(200),
        UnixMillisV2::new(900),
    )
    .unwrap();
    let context = original.task_action_context(&generic).unwrap();
    assert_eq!(context.content_digest, d(20));
    assert_eq!(context.settlement_nonce, d(34));
    let exact = sign_task_action_approval_v2(
        TaskActionApprovalV2::new(
            context.clone(),
            TaskActionApprovalDecisionV2::Approve,
            generic.issued_at(),
            generic.expires_at(),
        )
        .unwrap(),
        &approval_key,
    )
    .unwrap();
    let receipt = SignedApprovalSettlementV2::sign(generic, &approval_key)
        .unwrap()
        .with_task_action_approval(exact)
        .unwrap();
    let encoded = encode_signed_approval_settlement_v2(&receipt).unwrap();
    let restored = decode_signed_approval_settlement_v2(&encoded).unwrap();
    assert_eq!(restored, receipt);
    let verified = verify_task_action_approval_v2(
        restored.task_action_approval().unwrap(),
        &approval_key.verifying_key(),
        &context,
        UnixMillisV2::new(201),
    )
    .unwrap();
    assert_ne!(verified.digest(), restored.settlement_digest().unwrap());
    for field in 0..4 {
        let mut wrong = context.clone();
        match field {
            0 => wrong.content_digest = d(40),
            1 => wrong.authorization_revision += 1,
            2 => wrong.deployment_generation += 1,
            _ => wrong.settlement_nonce = d(41),
        }
        assert!(verify_task_action_approval_v2(
            restored.task_action_approval().unwrap(),
            &approval_key.verifying_key(),
            &wrong,
            UnixMillisV2::new(201)
        )
        .is_err());
    }
    for end in 0..encoded.len() {
        assert!(decode_signed_approval_settlement_v2(&encoded[..end]).is_err());
    }
    let mut trailing = encoded;
    trailing.push(0);
    assert!(decode_signed_approval_settlement_v2(&trailing).is_err());
    // The old signed decision is not upgraded to new evidence by decoding.
    let old = SignedApprovalSettlementV2::sign(generic, &approval_key).unwrap();
    assert!(decode_signed_approval_settlement_v2(
        &encode_signed_approval_settlement_v2(&old).unwrap()
    )
    .unwrap()
    .task_action_approval()
    .is_none());
}
