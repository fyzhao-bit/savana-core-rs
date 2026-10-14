use super::*;
use crate::protocol_service::tests::{delivery_display, delivery_pair, enrollment_service};
use crate::{
    ApprovalErrorV2, ApprovalRollbackAnchorV2, ApprovalStateHeadV2, DurableApprovalNamespaceV2,
};
use std::os::unix::fs::PermissionsExt as _;
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone, Default)]
pub(crate) struct Anchor(Arc<Mutex<ApprovalStateHeadV2>>);
impl ApprovalRollbackAnchorV2 for Anchor {
    fn current_head(&self) -> Result<ApprovalStateHeadV2, ApprovalErrorV2> {
        Ok(*self.0.lock().unwrap())
    }
    fn compare_and_advance(
        &mut self,
        expected: ApprovalStateHeadV2,
        next: ApprovalStateHeadV2,
    ) -> Result<(), ApprovalErrorV2> {
        let mut head = self.0.lock().unwrap();
        if *head != expected || next.sequence() != expected.sequence() + 1 {
            return Err(ApprovalErrorV2::RollbackDetected);
        }
        *head = next;
        Ok(())
    }
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}

#[test]
fn private_handoff_never_opens_the_legacy_ui_or_grants_a_vote() {
    let root = directory();
    let authority = open(root.path(), Anchor::default());
    let (approval, display) = crate::protocol_service::tests::kernel_delivery_pair(true);
    let RegisteredApprovalV2::Tool {
        approval: handle,
        display_authentication: transfer,
    } = authority
        .register_approval(
            EndpointRoleV2::KernelApproval,
            approval,
            display,
            UnixMillisV2::new(200),
            deadline(),
        )
        .unwrap()
    else {
        panic!("tool approval")
    };
    assert!(authority
        .accept_approval_display_transfer(transfer)
        .is_err());
    assert!(authority.records.lock().unwrap()[0]
        .pre_authentication
        .is_none());
    let accepted = authority
        .accept_kernel_approval_display_transfer_v04(transfer, UnixMillisV2::new(201), deadline())
        .unwrap();
    assert_eq!(
        accepted,
        authority
            .accept_kernel_approval_display_transfer_v04(
                transfer,
                UnixMillisV2::new(202),
                deadline()
            )
            .unwrap()
    );
    let records = authority.records.lock().unwrap();
    assert!(records[0].approval_tab.is_none());
    assert!(records[0].settlement.is_none());
    assert!(records[0].decision.is_none());
    drop(records);
    assert_eq!(
        authority
            .get_kernel_approval_settlement(handle, UnixMillisV2::new(203), deadline())
            .unwrap(),
        ApprovalSettlementViewV2::Pending
    );
    assert!(authority
        .accept_kernel_approval_display_transfer_v04(transfer, UnixMillisV2::new(1000), deadline())
        .is_err());
}

#[test]
fn private_handoff_rejects_public_roles_and_expired_or_unknown_transfers() {
    let root = directory();
    let authority = open(root.path(), Anchor::default());
    let (approval, display) = delivery_pair();
    let RegisteredApprovalV2::TaskAuthorization {
        display_authentication: transfer,
        ..
    } = authority
        .register_approval(
            EndpointRoleV2::IngressApproval,
            approval,
            display,
            UnixMillisV2::new(200),
            deadline(),
        )
        .unwrap()
    else {
        panic!("task approval")
    };
    assert!(authority
        .accept_kernel_approval_display_transfer_v04(transfer, UnixMillisV2::new(201), deadline())
        .is_err());
    assert!(authority.records.lock().unwrap()[0]
        .pre_authentication
        .is_none());
    assert!(authority.accept_approval_display_transfer(transfer).is_ok());
    let unknown =
        ApprovalDisplayAuthenticationTransferCapabilityV2::from_authority_entropy([0xef; 32])
            .unwrap();
    assert!(authority
        .accept_kernel_approval_display_transfer_v04(unknown, UnixMillisV2::new(201), deadline())
        .is_err());

    let (approval, display) = crate::protocol_service::tests::kernel_delivery_pair(true);
    let RegisteredApprovalV2::Tool {
        display_authentication: transfer,
        ..
    } = authority
        .register_approval(
            EndpointRoleV2::KernelApproval,
            approval,
            display,
            UnixMillisV2::new(200),
            deadline(),
        )
        .unwrap()
    else {
        panic!("tool approval")
    };
    for now in [99, 1000, 1001] {
        assert!(authority
            .accept_kernel_approval_display_transfer_v04(
                transfer,
                UnixMillisV2::new(now),
                deadline()
            )
            .is_err());
        assert!(authority.records.lock().unwrap()[1]
            .pre_authentication
            .is_none());
    }
}

#[test]
fn private_handoff_after_reopen_requires_new_transfer_and_original_pair() {
    let root = directory();
    let anchor = Anchor::default();
    let authority = open(root.path(), anchor.clone());
    let (approval, display) = crate::protocol_service::tests::kernel_delivery_pair(true);
    let RegisteredApprovalV2::Tool {
        display_authentication: transfer,
        ..
    } = authority
        .register_approval(
            EndpointRoleV2::KernelApproval,
            approval.clone(),
            display.clone(),
            UnixMillisV2::new(200),
            deadline(),
        )
        .unwrap()
    else {
        panic!("tool approval")
    };
    authority
        .accept_kernel_approval_display_transfer_v04(transfer, UnixMillisV2::new(201), deadline())
        .unwrap();
    drop(authority);
    let authority = open(root.path(), anchor);
    assert!(authority
        .accept_kernel_approval_display_transfer_v04(transfer, UnixMillisV2::new(202), deadline())
        .is_err());
    let RegisteredApprovalV2::Tool {
        display_authentication: fresh,
        ..
    } = authority
        .register_approval(
            EndpointRoleV2::KernelApproval,
            approval,
            display,
            UnixMillisV2::new(203),
            deadline(),
        )
        .unwrap()
    else {
        panic!("tool approval")
    };
    assert_ne!(fresh, transfer);
    assert!(authority.accept_approval_display_transfer(fresh).is_err());
    assert!(authority
        .accept_kernel_approval_display_transfer_v04(fresh, UnixMillisV2::new(204), deadline())
        .is_ok());
}
pub(crate) fn open(root: &std::path::Path, anchor: Anchor) -> ApprovalUiAuthorityV2 {
    let deployment = enrollment_service();
    let state = ProtocolApprovalStateOwnerV2::open(
        &root.join("approval-protocol-state-v2.cbor"),
        [0xe1; 32],
        DurableApprovalNamespaceV2::from_verified_installation(
            deployment.installation_id(),
            Digest32V2::new([0xe2; 32]),
        )
        .unwrap(),
        Box::new(anchor),
        deployment,
        16,
    )
    .unwrap();
    // No enrollment is tested or enabled. This unit fixture constructs the
    // authority directly; production new() still requires verified roots.
    ApprovalUiAuthorityV2 {
        state,
        records: Mutex::new(Vec::new()),
        approvals: Mutex::new(Vec::new()),
        enrollments: Mutex::new(Vec::new()),
        private_sessions: Mutex::new(Vec::new()),
        attestation_roots: Vec::new(),
        maximum_records: 32,
    }
}
pub(crate) fn directory() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    root
}

#[test]
fn kernel_approval_handles_are_role_scoped_even_after_encrypted_reopen() {
    let root = directory();
    let anchor = Anchor::default();
    let authority = open(root.path(), anchor.clone());
    let (envelope, display) = crate::protocol_service::tests::kernel_delivery_pair(true);
    let registered = authority
        .register_approval(
            EndpointRoleV2::KernelApproval,
            envelope.clone(),
            display.clone(),
            UnixMillisV2::new(200),
            deadline(),
        )
        .unwrap();
    let RegisteredApprovalV2::Tool { approval, .. } = registered else {
        panic!("tool only")
    };
    assert_eq!(
        authority
            .get_kernel_approval_settlement(approval, UnixMillisV2::new(201), deadline())
            .unwrap(),
        ApprovalSettlementViewV2::Pending
    );
    assert!(authority
        .get_agent_approval_settlement(
            AgentApprovalRecordTargetV2::Tool(approval),
            UnixMillisV2::new(201),
            deadline()
        )
        .is_err());
    assert!(authority
        .register(
            EndpointRoleV2::KernelApproval,
            display.clone(),
            UnixMillisV2::new(201),
            deadline()
        )
        .is_err());
    drop(authority);
    let authority = open(root.path(), anchor);
    assert!(authority
        .get_kernel_approval_settlement(approval, UnixMillisV2::new(202), deadline())
        .is_err());
    assert!(authority
        .register_approval(
            EndpointRoleV2::AgentApproval,
            envelope.clone(),
            display.clone(),
            UnixMillisV2::new(202),
            deadline()
        )
        .is_err());
    let registered = authority
        .register_approval(
            EndpointRoleV2::KernelApproval,
            envelope,
            display,
            UnixMillisV2::new(202),
            deadline(),
        )
        .unwrap();
    let RegisteredApprovalV2::Tool {
        approval: fresh, ..
    } = registered
    else {
        panic!("tool only")
    };
    assert_ne!(approval, fresh);
    assert_eq!(
        authority
            .get_kernel_approval_settlement(fresh, UnixMillisV2::new(203), deadline())
            .unwrap(),
        ApprovalSettlementViewV2::Pending
    );
}

#[test]
fn cached_approval_delivery_rechecks_both_signatures_pair_and_expiry() {
    let root = directory();
    let anchor = Anchor::default();
    let authority = open(root.path(), anchor.clone());
    let (envelope, display) = delivery_pair();
    let first = authority
        .register_approval(
            EndpointRoleV2::IngressApproval,
            envelope.clone(),
            display.clone(),
            UnixMillisV2::new(200),
            deadline(),
        )
        .unwrap();
    let head = *anchor.0.lock().unwrap();
    let bytes = std::fs::read(root.path().join("approval-protocol-state-v2.cbor")).unwrap();
    let replay = authority
        .register_approval(
            EndpointRoleV2::IngressApproval,
            envelope.clone(),
            display.clone(),
            UnixMillisV2::new(300),
            deadline(),
        )
        .unwrap();
    assert_eq!(first, replay);
    let wrong_key = ed25519_dalek::SigningKey::from_bytes(&[0xee; 32]);
    // A payload digest does not authenticate the signature. Both forged values
    // retain the same digest as the already cached valid envelope.
    let bad_envelope =
        SignedApprovalEnvelopeV2::sign(envelope.unverified_material().unwrap(), &wrong_key)
            .unwrap();
    let bad_display =
        SignedUiAuthenticationEnvelopeV2::sign(display.unverified_material().unwrap(), &wrong_key)
            .unwrap();
    assert_eq!(
        bad_envelope.envelope_digest().unwrap(),
        envelope.envelope_digest().unwrap()
    );
    assert!(authority
        .register_approval(
            EndpointRoleV2::IngressApproval,
            bad_envelope,
            display.clone(),
            UnixMillisV2::new(300),
            deadline()
        )
        .is_err());
    assert!(authority
        .register_approval(
            EndpointRoleV2::IngressApproval,
            envelope.clone(),
            bad_display,
            UnixMillisV2::new(300),
            deadline()
        )
        .is_err());
    assert!(authority
        .register_approval(
            EndpointRoleV2::IngressApproval,
            envelope.clone(),
            delivery_display(&envelope, 0xaa, 100, 1000),
            UnixMillisV2::new(300),
            deadline()
        )
        .is_err());
    assert!(authority
        .register_approval(
            EndpointRoleV2::IngressApproval,
            envelope.clone(),
            display.clone(),
            UnixMillisV2::new(1000),
            deadline()
        )
        .is_err());
    assert!(authority
        .register_approval(
            EndpointRoleV2::AgentApproval,
            envelope,
            display,
            UnixMillisV2::new(300),
            deadline()
        )
        .is_err());
    assert_eq!(head, *anchor.0.lock().unwrap());
    assert_eq!(
        bytes,
        std::fs::read(root.path().join("approval-protocol-state-v2.cbor")).unwrap()
    );
    assert_eq!(authority.approvals.lock().unwrap().len(), 1);
    assert_eq!(authority.records.lock().unwrap().len(), 1);
}

#[test]
fn approval_delivery_encrypted_reopen_rebinds_only_the_original_signed_pair() {
    let root = directory();
    let anchor = Anchor::default();
    let (envelope, display) = delivery_pair();
    let first = {
        let authority = open(root.path(), anchor.clone());
        authority
            .register_approval(
                EndpointRoleV2::IngressApproval,
                envelope.clone(),
                display.clone(),
                UnixMillisV2::new(200),
                deadline(),
            )
            .unwrap()
    };
    let before = std::fs::read(root.path().join("approval-protocol-state-v2.cbor")).unwrap();
    assert!(!before
        .windows(b"Exact private delivery".len())
        .any(|w| w == b"Exact private delivery"));
    let head = *anchor.0.lock().unwrap();
    let recovered = open(root.path(), anchor.clone());
    assert!(recovered.approvals.lock().unwrap().is_empty());
    assert!(recovered
        .register_approval(
            EndpointRoleV2::IngressApproval,
            envelope.clone(),
            delivery_display(&envelope, 0xaa, 100, 1000),
            UnixMillisV2::new(300),
            deadline()
        )
        .is_err());
    assert!(recovered.approvals.lock().unwrap().is_empty());
    let second = recovered
        .register_approval(
            EndpointRoleV2::IngressApproval,
            envelope,
            display,
            UnixMillisV2::new(300),
            deadline(),
        )
        .unwrap();
    assert_ne!(first, second);
    let RegisteredApprovalV2::TaskAuthorization { approval: old, .. } = first else {
        panic!("task root")
    };
    let RegisteredApprovalV2::TaskAuthorization {
        approval: current, ..
    } = second
    else {
        panic!("task root")
    };
    assert!(recovered
        .get_task_authorization_approval_settlement(old, UnixMillisV2::new(301), deadline())
        .is_err());
    assert_eq!(
        recovered
            .get_task_authorization_approval_settlement(current, UnixMillisV2::new(301), deadline())
            .unwrap(),
        ApprovalSettlementViewV2::Pending
    );
    assert_eq!(head, *anchor.0.lock().unwrap());
    assert_eq!(
        before,
        std::fs::read(root.path().join("approval-protocol-state-v2.cbor")).unwrap()
    );
}

#[test]
fn cached_approval_delivery_never_masks_a_poisoned_durable_owner() {
    let root = directory();
    let anchor = Anchor::default();
    let authority = open(root.path(), anchor.clone());
    let (envelope, display) = delivery_pair();
    authority
        .register_approval(
            EndpointRoleV2::IngressApproval,
            envelope.clone(),
            display.clone(),
            UnixMillisV2::new(200),
            deadline(),
        )
        .unwrap();
    *anchor.0.lock().unwrap() = ApprovalStateHeadV2::new(9, Digest32V2::new([9; 32])).unwrap();
    assert!(authority
        .state
        .create_enrollment_code(
            EnrollmentProfileIdV2::new(1),
            savana_kernel_protocol::v2::Nonce32V2::new([0xef; 32]),
            UnixMillisV2::new(201),
            deadline()
        )
        .is_err());
    assert!(authority
        .register_approval(
            EndpointRoleV2::IngressApproval,
            envelope,
            display,
            UnixMillisV2::new(202),
            deadline()
        )
        .is_err());
}

#[test]
fn approval_display_cannot_bypass_pair_registration_via_generic_ui_route() {
    let root = directory();
    let authority = open(root.path(), Anchor::default());
    let (envelope, display) = delivery_pair();
    for paired in [false, true] {
        if paired {
            authority
                .register_approval(
                    EndpointRoleV2::IngressApproval,
                    envelope.clone(),
                    display.clone(),
                    UnixMillisV2::new(200),
                    deadline(),
                )
                .unwrap();
        }
        for role in [
            EndpointRoleV2::IngressApproval,
            EndpointRoleV2::AgentApproval,
        ] {
            assert!(authority
                .register(role, display.clone(), UnixMillisV2::new(201), deadline())
                .is_err());
        }
        assert_eq!(authority.records.lock().unwrap().len(), usize::from(paired));
    }
}

#[test]
fn ordinary_ui_cache_retry_also_rechecks_signature_role_and_expiry() {
    use savana_kernel_protocol::v2::{
        Nonce32V2, UiAuthenticationBindingV2, UnsignedUiAuthenticationEnvelopeV2,
    };
    let root = directory();
    let anchor = Anchor::default();
    let authority = open(root.path(), anchor.clone());
    let deployment = enrollment_service();
    let unsigned = UnsignedUiAuthenticationEnvelopeV2::new(
        deployment.installation_id(),
        Digest32V2::new([0x75; 32]),
        9,
        UiAuthenticationPurposeV2::IngressInput,
        UiAuthenticationBindingV2::IngressNewTask {
            durable_task_id: savana_kernel_protocol::v2::DurableTaskIdV2::new([0xd1; 32]),
            pending_task_digest: Digest32V2::new([0xd3; 32]),
            ingressd_identity: ServiceIdentityV2::new([0xd4; 32]),
        },
        None,
        FixedOriginV2::Approval8766,
        FixedOriginV2::Ingress8767,
        Nonce32V2::new([0xd2; 32]),
        UnixMillisV2::new(100),
        UnixMillisV2::new(1000),
    )
    .unwrap();
    let envelope = SignedUiAuthenticationEnvelopeV2::sign(
        unsigned,
        &ed25519_dalek::SigningKey::from_bytes(&[0x71; 32]),
    )
    .unwrap();
    let first = authority
        .register(
            EndpointRoleV2::IngressApproval,
            envelope.clone(),
            UnixMillisV2::new(200),
            deadline(),
        )
        .unwrap();
    let head = *anchor.0.lock().unwrap();
    assert_eq!(
        first,
        authority
            .register(
                EndpointRoleV2::IngressApproval,
                envelope.clone(),
                UnixMillisV2::new(201),
                deadline()
            )
            .unwrap()
    );
    let forged = SignedUiAuthenticationEnvelopeV2::sign(
        unsigned,
        &ed25519_dalek::SigningKey::from_bytes(&[0xee; 32]),
    )
    .unwrap();
    assert!(authority
        .register(
            EndpointRoleV2::IngressApproval,
            forged,
            UnixMillisV2::new(201),
            deadline()
        )
        .is_err());
    assert!(authority
        .register(
            EndpointRoleV2::AgentApproval,
            envelope.clone(),
            UnixMillisV2::new(201),
            deadline()
        )
        .is_err());
    assert!(authority
        .register(
            EndpointRoleV2::IngressApproval,
            envelope,
            UnixMillisV2::new(1000),
            deadline()
        )
        .is_err());
    assert_eq!(head, *anchor.0.lock().unwrap());
    assert_eq!(authority.records.lock().unwrap().len(), 1);
}
