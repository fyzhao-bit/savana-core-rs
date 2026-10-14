// Included in protocol_service::tests. No live credentials or services are used.
use savana_kernel_protocol::v2::{ApprovalSettlementViewV2, EndpointRoleV2};

pub(crate) fn delivery_pair() -> (SignedApprovalEnvelopeV2, SignedUiAuthenticationEnvelopeV2) {
    let service = enrollment_service();
    let key = SigningKey::from_bytes(&[0x71; 32]);
    let display = BoundedApprovalDisplayTextV2::new("Exact private delivery".into()).unwrap();
    let digest = savana_kernel_protocol::v2::approval_display_digest_v2(display.as_bytes());
    let approval = SignedApprovalEnvelopeV2::sign(
        UnsignedApprovalEnvelopeV2::new(
            service.installation_id,
            service.active_state_manifest_digest,
            9,
            ApprovalPurposeV2::TaskAuthorization,
            Nonce32V2::new([0xa1; 32]),
            Nonce32V2::new([0xa2; 32]),
            ApprovalBindingV2::TaskAuthorization {
                authorization_id: Digest32V2::new([0xa3; 32]),
                task: DurableTaskIdV2::new([0xa4; 32]),
                revision: 1,
                change: savana_kernel_protocol::v2::TaskAuthorizationChangeV2::Create,
                draft_digest: Digest32V2::new([0xa5; 32]),
            },
            PrincipalIdV2::new([0xa6; 32]),
            Digest32V2::new([0xa7; 32]),
            digest,
            display,
            Some(Digest32V2::new([0xa8; 32])),
            service.approvald_endpoint_identity,
            UnixMillisV2::new(100),
            UnixMillisV2::new(1000),
        )
        .unwrap(),
        &key,
    )
    .unwrap();
    let ui = delivery_display(&approval, 0xa9, 100, 1000);
    (approval, ui)
}

pub(crate) fn kernel_release_delivery_pair(
    exact: bool,
) -> (SignedApprovalEnvelopeV2, SignedUiAuthenticationEnvelopeV2) {
    use savana_kernel_protocol::v2::*;
    let base = delivery_pair().0.unverified_material().unwrap();
    let d = |n| Digest32V2::new([n; 32]);
    let display = BoundedApprovalDisplayTextV2::new("Publish exact final result".into()).unwrap();
    let binding = FinalReleaseSemanticBindingV2::from_nonzero_components(
        DurableReleaseIdV2::new([1; 32]),
        d(2),
        d(3),
        d(4),
        d(5),
        d(6),
        d(7),
        d(8),
        approval_display_digest_v2(display.as_bytes()),
        d(10),
        d(11),
    )
    .unwrap();
    let mut raw = UnsignedApprovalEnvelopeV2::new(
        base.installation_id(),
        base.active_state_manifest_digest(),
        9,
        ApprovalPurposeV2::FinalRelease,
        Nonce32V2::new([0xd1; 32]),
        Nonce32V2::new([0xd2; 32]),
        ApprovalBindingV2::FinalRelease { binding },
        base.expected_principal(),
        d(0xd4),
        approval_display_digest_v2(display.as_bytes()),
        display,
        Some(d(0xd5)),
        enrollment_service().approvald_endpoint_identity,
        UnixMillisV2::new(100),
        UnixMillisV2::new(1000),
    )
    .unwrap();
    if exact {
        raw = raw
            .with_task_action_binding(
                TaskActionApprovalBindingV2::new(
                    d(0xd6),
                    d(0xb7),
                    1,
                    DurableTaskIdV2::new([0xa4; 32]),
                )
                .unwrap(),
            )
            .unwrap();
    }
    let envelope =
        SignedApprovalEnvelopeV2::sign(raw, &SigningKey::from_bytes(&[0x71; 32])).unwrap();
    let display = delivery_display(&envelope, 0xd8, 100, 1000);
    (envelope, display)
}

#[test]
fn kernel_release_delivery_is_task_bound_and_role_bound_across_restore() {
    let mut service = enrollment_service();
    let (unbound, display) = kernel_release_delivery_pair(false);
    assert!(service
        .register_approval_pair(
            EndpointRoleV2::KernelApproval,
            &unbound,
            &display,
            UnixMillisV2::new(200)
        )
        .is_err());
    let (approval, display) = kernel_release_delivery_pair(true);
    let wrong_display = kernel_delivery_pair(true).1;
    assert!(service
        .register_approval_pair(
            EndpointRoleV2::KernelApproval,
            &approval,
            &wrong_display,
            UnixMillisV2::new(200)
        )
        .is_err());
    assert!(service.approval_envelopes.is_empty());
    service
        .register_approval_pair(
            EndpointRoleV2::KernelApproval,
            &approval,
            &display,
            UnixMillisV2::new(200),
        )
        .unwrap();
    let snapshot = service.encode_mutable_state().unwrap();
    let mut restored =
        ProtocolApprovalServiceV2::restore_mutable_state(enrollment_service(), &snapshot).unwrap();
    assert_eq!(snapshot, restored.encode_mutable_state().unwrap());
    assert!(restored
        .register_approval_pair(
            EndpointRoleV2::AgentApproval,
            &approval,
            &display,
            UnixMillisV2::new(300)
        )
        .is_err());
    restored
        .register_approval_pair(
            EndpointRoleV2::KernelApproval,
            &approval,
            &display,
            UnixMillisV2::new(300),
        )
        .unwrap();
}

pub(crate) fn kernel_delivery_pair(
    exact: bool,
) -> (SignedApprovalEnvelopeV2, SignedUiAuthenticationEnvelopeV2) {
    use savana_kernel_protocol::v2::*;
    let base = delivery_pair().0.unverified_material().unwrap();
    let d = |n| Digest32V2::new([n; 32]);
    let display = BoundedApprovalDisplayTextV2::new("Send exact private item".into()).unwrap();
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
    let mut raw = UnsignedApprovalEnvelopeV2::new(
        base.installation_id(),
        base.active_state_manifest_digest(),
        9,
        ApprovalPurposeV2::ToolExecution,
        Nonce32V2::new([0xb1; 32]),
        Nonce32V2::new([0xb2; 32]),
        ApprovalBindingV2::ToolExecution {
            action_intent_id: ActionIntentIdV2::new([0xb3; 32]),
            binding: semantic,
        },
        base.expected_principal(),
        d(0xb4),
        approval_display_digest_v2(display.as_bytes()),
        display,
        Some(d(0xb5)),
        enrollment_service().approvald_endpoint_identity,
        UnixMillisV2::new(100),
        UnixMillisV2::new(1000),
    )
    .unwrap();
    if exact {
        raw = raw
            .with_task_action_binding(
                TaskActionApprovalBindingV2::new(
                    d(0xb6),
                    d(0xb7),
                    1,
                    DurableTaskIdV2::new([0xa4; 32]),
                )
                .unwrap(),
            )
            .unwrap();
    }
    let envelope =
        SignedApprovalEnvelopeV2::sign(raw, &SigningKey::from_bytes(&[0x71; 32])).unwrap();
    let display = delivery_display(&envelope, 0xb8, 100, 1000);
    (envelope, display)
}

#[test]
fn kernel_delivery_requires_exact_tool_and_preserves_origin_after_restore() {
    let mut service = enrollment_service();
    for (envelope, display) in [delivery_pair(), kernel_delivery_pair(false)] {
        assert!(service
            .register_approval_pair(
                EndpointRoleV2::KernelApproval,
                &envelope,
                &display,
                UnixMillisV2::new(200)
            )
            .is_err());
    }
    assert!(service.approval_envelopes.is_empty());
    let (envelope, display) = kernel_delivery_pair(true);
    service
        .register_approval_pair(
            EndpointRoleV2::KernelApproval,
            &envelope,
            &display,
            UnixMillisV2::new(200),
        )
        .unwrap();
    let snapshot = service.encode_mutable_state().unwrap();
    let mut restored =
        ProtocolApprovalServiceV2::restore_mutable_state(enrollment_service(), &snapshot).unwrap();
    assert_eq!(restored.encode_mutable_state().unwrap(), snapshot);
    assert!(restored
        .register_approval_pair(
            EndpointRoleV2::AgentApproval,
            &envelope,
            &display,
            UnixMillisV2::new(300)
        )
        .is_err());
    restored
        .register_approval_pair(
            EndpointRoleV2::KernelApproval,
            &envelope,
            &display,
            UnixMillisV2::new(300),
        )
        .unwrap();
    // Schema 4 has no delivery role; legacy tool records stay Agent-owned.
    let old = service.encode_mutable_state_schema(4).unwrap();
    let mut legacy =
        ProtocolApprovalServiceV2::restore_mutable_state(enrollment_service(), &old).unwrap();
    assert!(legacy
        .register_approval_pair(
            EndpointRoleV2::KernelApproval,
            &envelope,
            &display,
            UnixMillisV2::new(300)
        )
        .is_err());
}

pub(crate) fn delivery_display(
    approval: &SignedApprovalEnvelopeV2,
    nonce: u8,
    issued: u64,
    expires: u64,
) -> SignedUiAuthenticationEnvelopeV2 {
    let material = approval.unverified_material().unwrap();
    SignedUiAuthenticationEnvelopeV2::sign(
        UnsignedUiAuthenticationEnvelopeV2::new(
            material.installation_id(),
            material.active_state_manifest_digest(),
            9,
            UiAuthenticationPurposeV2::ApprovalDisplay,
            UiAuthenticationBindingV2::ApprovalDisplay {
                durable_task_id: DurableTaskIdV2::new([0xa4; 32]),
                approval_envelope_digest: approval.envelope_digest().unwrap(),
                approval_purpose: material.purpose(),
                display_digest: material.display_digest(),
            },
            Some(material.expected_principal()),
            FixedOriginV2::Approval8766,
            FixedOriginV2::Approval8766,
            Nonce32V2::new([nonce; 32]),
            UnixMillisV2::new(issued),
            UnixMillisV2::new(expires),
        )
        .unwrap(),
        &SigningKey::from_bytes(&[0x71; 32]),
    )
    .unwrap()
}

#[test]
fn approval_pair_delivery_is_immutable_across_restart_and_standalone_registration() {
    let (approval, display) = delivery_pair();
    let mut service = enrollment_service();
    let pair = service
        .register_approval_pair(
            EndpointRoleV2::IngressApproval,
            &approval,
            &display,
            UnixMillisV2::new(200),
        )
        .unwrap();
    let saved = service.encode_mutable_state().unwrap();
    for reopen in [false, true] {
        if reopen {
            service =
                ProtocolApprovalServiceV2::restore_mutable_state(enrollment_service(), &saved)
                    .unwrap();
        }
        assert_eq!(
            service
                .register_approval_pair(
                    EndpointRoleV2::IngressApproval,
                    &approval,
                    &display,
                    UnixMillisV2::new(300)
                )
                .unwrap(),
            pair
        );
        let changed = delivery_display(&approval, 0xaa, 100, 1000);
        assert!(service
            .register_approval_pair(
                EndpointRoleV2::IngressApproval,
                &approval,
                &changed,
                UnixMillisV2::new(300)
            )
            .is_err());
        assert!(service
            .register_ui_authentication_envelope(&changed, UnixMillisV2::new(300))
            .is_err());
        assert!(service
            .register_approval_pair(
                EndpointRoleV2::AgentApproval,
                &approval,
                &display,
                UnixMillisV2::new(300)
            )
            .is_err());
        assert_eq!(service.encode_mutable_state().unwrap(), saved);
    }
}

#[test]
fn approval_pair_second_insert_failure_is_atomic_and_time_is_not_extended() {
    let (approval, _) = delivery_pair();
    for case in 0..4 {
        let mut service = enrollment_service();
        if case == 0 {
            service.maximum_records = 1;
        }
        let display = match case {
            1 => delivery_display(&approval, 0xa1, 100, 1000), // same nonce as approval
            2 => delivery_display(&approval, 0xa9, 99, 1000),
            3 => delivery_display(&approval, 0xa9, 100, 1001),
            _ => delivery_display(&approval, 0xa9, 100, 1000),
        };
        let before = service.encode_mutable_state().unwrap();
        assert!(service
            .register_approval_pair(
                EndpointRoleV2::IngressApproval,
                &approval,
                &display,
                UnixMillisV2::new(200)
            )
            .is_err());
        assert_eq!(before, service.encode_mutable_state().unwrap());
        assert!(service.approval_envelopes.is_empty());
        assert!(service.ui_authentication_envelopes.is_empty());
    }
}

#[test]
fn approval_pair_schema_four_migration_requires_unique_signed_pair() {
    let (approval, display) = delivery_pair();
    let mut service = enrollment_service();
    service
        .register_approval_pair(
            EndpointRoleV2::IngressApproval,
            &approval,
            &display,
            UnixMillisV2::new(200),
        )
        .unwrap();
    let legacy = service.encode_mutable_state_schema(4).unwrap();
    let current = service.encode_mutable_state().unwrap();
    let mut restored =
        ProtocolApprovalServiceV2::restore_mutable_state(enrollment_service(), &legacy).unwrap();
    assert_eq!(restored.encode_mutable_state().unwrap(), current);
    assert!(restored
        .register_approval_pair(
            EndpointRoleV2::IngressApproval,
            &approval,
            &delivery_display(&approval, 0xaa, 100, 1000),
            UnixMillisV2::new(300)
        )
        .is_err());
    // Construct the ambiguous legacy image which the old implementation could
    // accept. Migration must not choose the first matching display arbitrarily.
    let other = delivery_display(&approval, 0xaa, 100, 1000);
    service
        .ui_authentication_envelopes
        .push(super::ProtocolUiAuthenticationRecordV2 {
            unsigned: other.unverified_material().unwrap(),
            envelope_digest: other.envelope_digest().unwrap(),
            canonical_envelope:
                savana_kernel_protocol::v2::encode_signed_ui_authentication_envelope_v2(&other)
                    .unwrap(),
            settlement: None,
        });
    assert!(ProtocolApprovalServiceV2::restore_mutable_state(
        enrollment_service(),
        &service.encode_mutable_state_schema(4).unwrap()
    )
    .is_err());
    // No approval/display pair in an old image does not create one on restore.
    let legacy_empty = enrollment_service().encode_mutable_state_schema(4).unwrap();
    let restored =
        ProtocolApprovalServiceV2::restore_mutable_state(enrollment_service(), &legacy_empty)
            .unwrap();
    assert!(restored.approval_envelopes.is_empty());
}

#[test]
fn approval_pair_restore_rejects_wrong_delivery_role_digest_or_missing_display() {
    let (approval, display) = delivery_pair();
    for case in 0..3 {
        let mut service = enrollment_service();
        service
            .register_approval_pair(
                EndpointRoleV2::IngressApproval,
                &approval,
                &display,
                UnixMillisV2::new(200),
            )
            .unwrap();
        match case {
            0 => {
                service.approval_envelopes[0]
                    .delivery_binding
                    .as_mut()
                    .unwrap()
                    .role = EndpointRoleV2::AgentApproval
            }
            1 => {
                service.approval_envelopes[0]
                    .delivery_binding
                    .as_mut()
                    .unwrap()
                    .display_envelope_digest = Digest32V2::new([0xff; 32])
            }
            _ => service.ui_authentication_envelopes.clear(),
        }
        assert!(ProtocolApprovalServiceV2::restore_mutable_state(
            enrollment_service(),
            &service.encode_mutable_state().unwrap()
        )
        .is_err());
    }
}

#[test]
fn approval_pair_reregistration_never_resets_signed_approval_or_denial() {
    use savana_kernel_protocol::v2::ApprovalDecisionV2;
    for (role, (approval, display)) in [
        (EndpointRoleV2::IngressApproval, delivery_pair()),
        (
            EndpointRoleV2::KernelApproval,
            kernel_release_delivery_pair(true),
        ),
    ] {
        let material = approval.unverified_material().unwrap();
        for decision in [ApprovalDecisionV2::Approve, ApprovalDecisionV2::Deny] {
            let mut service = enrollment_service();
            let p256 = P256SigningKey::from_slice(&[0xb1; 32]).unwrap();
            let credential = Digest32V2::new([0xb2; 32]);
            service
                .load_verified_hardware_credential(
                    credential,
                    material.expected_principal(),
                    [0xb3; 16],
                    p256.verifying_key()
                        .to_encoded_point(false)
                        .as_bytes()
                        .try_into()
                        .unwrap(),
                    1,
                )
                .unwrap();
            let pair = service
                .register_approval_pair(role, &approval, &display, UnixMillisV2::new(200))
                .unwrap();
            let receipt = service
                .settle_approval(
                    pair.0,
                    decision,
                    &assertion(
                        &p256,
                        credential,
                        material.expected_principal(),
                        material.decision_challenge(),
                        2,
                    ),
                    UnixMillisV2::new(300),
                )
                .unwrap();
            let before = service.encode_mutable_state().unwrap();
            assert_eq!(receipt.purpose(), material.purpose());
            if role == EndpointRoleV2::KernelApproval {
                assert_eq!(
                    receipt.task_action_approval().is_some(),
                    decision == ApprovalDecisionV2::Approve
                );
            }
            let mut restored =
                ProtocolApprovalServiceV2::restore_mutable_state(enrollment_service(), &before)
                    .unwrap();
            restored
                .register_approval_pair(role, &approval, &display, UnixMillisV2::new(400))
                .unwrap();
            let view = restored
                .approval_settlement_view(pair.0, UnixMillisV2::new(400))
                .unwrap();
            assert_eq!(
                view,
                if decision == ApprovalDecisionV2::Approve {
                    ApprovalSettlementViewV2::Approved {
                        settlement: receipt,
                    }
                } else {
                    ApprovalSettlementViewV2::Denied {
                        settlement: receipt,
                    }
                }
            );
            assert_eq!(before, restored.encode_mutable_state().unwrap());
            assert!(restored
                .register_approval_pair(role, &approval, &display, UnixMillisV2::new(1000))
                .is_err());
        }
    }
}
