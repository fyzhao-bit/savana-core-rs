// Typed debug transport fixture: production G5/G6 and receipt signatures are
// real, but this is not an installed daemon or browser ceremony test.
#[cfg(feature = "test-support")]
fn private_approval_delivery_case(case: u8) {
    use savana_kernel_protocol::v2::{
        encode_approval_settlement_view_v2, encode_registered_approval_v2,
        ApprovalDisplayAuthenticationTransferCapabilityV2, ApprovalServiceOperationV2 as Op,
        ApprovalSettlementViewV2 as View, RegisteredApprovalV2, ToolApprovalRecordHandleV2,
    };
    let mut f = approval_recovery_fixture();
    let (action, _, envelope) = pending_private_approval(&mut f);
    let display = f.authority.tool_approvals[0].display_authentication.clone();
    let manifest = f.authority.sessions[0].active_state_manifest_digest;
    let receipt =
        signed_private_settlement(&f, &envelope, case != 1, if case == 4 { 205 } else { 340 });
    let edge = KernelServiceHandshakeEdgeV2::from_verified_deployment(
        if case == 6 {
            EndpointRoleV2::AgentApproval
        } else {
            EndpointRoleV2::KernelApproval
        },
        f.authority.config.installation_id,
        f.authority.config.kerneld_identity,
        f.authority.config.approvald_identity,
        derive_ed25519_key_id_v2(
            SigningKey::from_bytes(&[0xe1; 32])
                .verifying_key()
                .to_bytes(),
        ),
        derive_ed25519_key_id_v2(
            SigningKey::from_bytes(&[0xe2; 32])
                .verifying_key()
                .to_bytes(),
        ),
        f.authority.config.approvald_boot_id,
        1,
        if case == 5 {
            Digest32V2::new([0xee; 32])
        } else {
            manifest
        },
        7,
        8,
        Digest32V2::new([1; 32]),
        Digest32V2::new([2; 32]),
        Digest32V2::new([3; 32]),
        Digest32V2::new([4; 32]),
        Digest32V2::new([5; 32]),
        Digest32V2::new([6; 32]),
    )
    .unwrap();
    let calls = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen = calls.clone();
    let exact = envelope.clone();
    let exact_display = display.clone();
    let handle = ToolApprovalRecordHandleV2::from_authority_entropy([0xe3; 32]).unwrap();
    let client = savana_approvald::ApprovalSuiteOneClientV2::from_verified_deployment(
        edge,
        f.authority.config.kerneld_server_boot_id,
        PeerIdentityBindingV2::linux(501, 502, 503, 504, Digest32V2::new([7; 32])).unwrap(),
        SigningKey::from_bytes(&[0xe1; 32]),
        SigningKey::from_bytes(&[0xe2; 32])
            .verifying_key()
            .to_bytes(),
    )
    .unwrap()
    .with_operation_exchange_for_test_support(move |_, op| {
        seen.lock().unwrap().push(op.tag());
        match op {
            Op::RegisterKernelApproval {
                envelope,
                display_authentication,
            } => {
                assert_eq!(envelope, exact);
                assert_eq!(display_authentication, exact_display);
                if case == 3 {
                    return Err(savana_approvald::ApprovalSuiteOneClientErrorV2::Unavailable);
                }
                Ok(encode_registered_approval_v2(RegisteredApprovalV2::Tool {
                    approval: handle,
                    display_authentication:
                        ApprovalDisplayAuthenticationTransferCapabilityV2::from_authority_entropy(
                            [0xe4; 32],
                        )
                        .unwrap(),
                })
                .unwrap())
            }
            Op::GetKernelApprovalSettlement { approval } => {
                assert_eq!(approval, handle);
                // Case 1 deliberately labels a signed denial as Approved: the
                // G6 decision must come from the receipt, not this outer enum.
                let view = if case == 2 {
                    View::Pending
                } else {
                    View::Approved {
                        settlement: receipt.clone(),
                    }
                };
                Ok(encode_approval_settlement_view_v2(&view).unwrap())
            }
            _ => panic!("not a kernel-only operation"),
        }
    });
    let before = f.authority.encode_recovery_snapshot().unwrap();
    let installed = f
        .authority
        .policy
        .as_mut()
        .unwrap()
        .install_fused_approval_client_v04(client, edge);
    if case == 6 {
        assert!(installed.is_err());
        assert!(calls.lock().unwrap().is_empty());
        return;
    }
    installed.unwrap();
    let mut times = if case == 7 {
        vec![204, 350]
    } else if case == 8 {
        vec![204, 203]
    } else {
        vec![204, 205, 206]
    }
    .into_iter();
    if case == 9 {
        f.authority
            .policy
            .as_mut()
            .unwrap()
            .install_g7(test_g7_runtime(
                f.authority.config.installation_id,
                manifest,
                7,
                8,
            ))
            .unwrap();
        let mut now = 204;
        f.authority
            .tick_fused_actions_v04(&mut f.values, &mut || {
                now += 1;
                UnixMillisV2::new(now)
            })
            .unwrap();
        assert_eq!(*calls.lock().unwrap(), vec![20, 21]);
        assert_eq!(f.authority.execution_tickets.len(), 1);
        assert!(f.authority.executions.is_empty());
        return;
    }
    let result = f.authority.deliver_fused_approval_v04(
        &action,
        envelope.clone(),
        display.clone(),
        manifest,
        7,
        UnixMillisV2::new(203),
        &mut || UnixMillisV2::new(times.next().unwrap()),
    );
    assert_eq!(result.is_ok(), matches!(case, 0 | 2));
    assert_eq!(f.authority.execution_tickets.len(), usize::from(case == 0));
    assert!(f.authority.executions.is_empty());
    if matches!(case, 0 | 1) {
        assert_ne!(f.authority.encode_recovery_snapshot().unwrap(), before);
        assert!(f.authority.tool_approvals[0].consumed);
    } else {
        assert_eq!(f.authority.encode_recovery_snapshot().unwrap(), before);
        assert!(!f.authority.tool_approvals[0].consumed);
    }
    let expected = match case {
        5 => vec![],
        3 | 7 | 8 => vec![20],
        _ => vec![20, 21],
    };
    assert_eq!(*calls.lock().unwrap(), expected);
    if case == 2 {
        f.authority
            .deliver_fused_approval_v04(
                &action,
                envelope,
                display,
                manifest,
                7,
                UnixMillisV2::new(207),
                &mut || UnixMillisV2::new(208),
            )
            .unwrap();
        assert_eq!(*calls.lock().unwrap(), vec![20, 21, 20, 21]);
        assert_eq!(f.authority.encode_recovery_snapshot().unwrap(), before);
    }
}

#[cfg(feature = "test-support")]
#[test]
fn fused_approval_delivery_verifies_receipt_and_retains_real_denial() {
    private_approval_delivery_case(0);
    private_approval_delivery_case(1);
}
#[cfg(feature = "test-support")]
#[test]
fn fused_approval_delivery_pending_and_outage_do_not_renew_or_authorize() {
    private_approval_delivery_case(2);
    private_approval_delivery_case(3);
}
#[cfg(feature = "test-support")]
#[test]
fn fused_approval_delivery_rejects_expiry_wrong_deployment_and_agent_edge() {
    for case in 4..=6 {
        private_approval_delivery_case(case);
    }
}
#[cfg(feature = "test-support")]
#[test]
fn fused_approval_delivery_checks_time_again_between_transport_stages() {
    private_approval_delivery_case(7);
    private_approval_delivery_case(8);
}

#[cfg(feature = "test-support")]
#[test]
fn fused_action_driver_polls_kernel_approval_before_any_dispatch() {
    private_approval_delivery_case(9);
}

#[test]
fn fused_approval_delivery_without_configuration_keeps_original_pending_state() {
    let mut f = approval_recovery_fixture();
    let (action, _, envelope) = pending_private_approval(&mut f);
    let display = f.authority.tool_approvals[0].display_authentication.clone();
    let manifest = f.authority.sessions[0].active_state_manifest_digest;
    let before = f.authority.encode_recovery_snapshot().unwrap();
    f.authority
        .deliver_fused_approval_v04(
            &action,
            envelope,
            display,
            manifest,
            7,
            UnixMillisV2::new(203),
            &mut || UnixMillisV2::new(204),
        )
        .unwrap();
    assert_eq!(f.authority.encode_recovery_snapshot().unwrap(), before);
    assert!(f.authority.execution_tickets.is_empty());
    assert!(f.authority.executions.is_empty());
}
