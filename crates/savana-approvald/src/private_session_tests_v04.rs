use super::super::approval_delivery_tests::{directory, open, Anchor};
use super::*;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::SigningKey;
use p256::ecdsa::{signature::Signer as _, Signature, SigningKey as P256Key};
use savana_kernel_protocol::v2::*;
use sha2::Sha256;
use std::time::Duration;

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}
fn envelope(task: u8, principal: u8) -> SignedUiAuthenticationEnvelopeV2 {
    SignedUiAuthenticationEnvelopeV2::sign(
        UnsignedUiAuthenticationEnvelopeV2::new(
            Digest32V2::new([0x74; 32]),
            Digest32V2::new([0x75; 32]),
            9,
            UiAuthenticationPurposeV2::PrivateSessionV04,
            UiAuthenticationBindingV2::PrivateSessionV04 {
                durable_task_id: DurableTaskIdV2::new([task; 32]),
                durable_run_id: DurableRunIdV2::new([0xc2; 32]),
                task_authorization_digest: Digest32V2::new([0xc1; 32]),
                kerneld_boot_id: BootIdV2::new([0xc4; 32]),
            },
            Some(PrincipalIdV2::new([principal; 32])),
            FixedOriginV2::Approval8766,
            FixedOriginV2::Approval8766,
            Nonce32V2::new([0xc3; 32]),
            UnixMillisV2::new(100),
            UnixMillisV2::new(1000),
        )
        .unwrap(),
        &SigningKey::from_bytes(&[0x71; 32]),
    )
    .unwrap()
}
fn key() -> P256Key {
    P256Key::from_slice(&[0x79; 32]).unwrap()
}
fn assertion(challenge: u8, flags: u8) -> BrowserWebAuthnAssertionV2 {
    let principal = [0xa6; 32];
    let challenge = URL_SAFE_NO_PAD.encode([challenge; 32]);
    let client = format!(r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"http://localhost:8766","crossOrigin":false}}"#).into_bytes();
    let mut authenticator = Sha256::digest(b"localhost").to_vec();
    authenticator.push(flags);
    authenticator.extend(2u32.to_be_bytes());
    let mut signed = authenticator.clone();
    signed.extend(Sha256::digest(&client));
    let signature: Signature = key().sign(&signed);
    let signature = signature.normalize_s().unwrap_or(signature);
    BrowserWebAuthnAssertionV2::new(
        vec![0x79; 32],
        authenticator,
        client,
        signature.to_der().as_bytes().to_vec(),
        principal.to_vec(),
    )
    .unwrap()
}
fn register_credential(a: &ApprovalUiAuthorityV2) {
    a.state
        .load_verified_hardware_credential(
            webauthn_credential_digest_v2(&[0x79; 32]).unwrap(),
            PrincipalIdV2::new([0xa6; 32]),
            [0x7b; 16],
            key()
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes()
                .try_into()
                .unwrap(),
            1,
            deadline(),
        )
        .unwrap();
}

#[test]
fn private_publication_requires_live_owner_final_approval_and_exact_scope() {
    let dir = directory();
    let a = open(dir.path(), Anchor::default());
    register_credential(&a);
    let session = a
        .register_private_session_v04(envelope(0xa4, 0xa6), UnixMillisV2::new(200), deadline())
        .unwrap();
    let (e, d) = crate::protocol_service::tests::kernel_release_delivery_pair(true);
    let digest = e.envelope_digest().unwrap();
    let challenge = e.unverified_material().unwrap().decision_challenge();
    let RegisteredApprovalV2::Release { approval, .. } = a
        .register_approval(
            EndpointRoleV2::KernelApproval,
            e,
            d,
            UnixMillisV2::new(201),
            deadline(),
        )
        .unwrap()
    else {
        panic!("release required");
    };
    let publication = |task, root, approval, commit| {
        PrivatePublicationV04::new(
            DurableTaskIdV2::new([task; 32]),
            DurableRunIdV2::new([0xc2; 32]),
            Digest32V2::new([root; 32]),
            BootIdV2::new([0xc4; 32]),
            DurableReleaseIdV2::new([5; 32]),
            Digest32V2::new([6; 32]),
            Digest32V2::new([7; 32]),
            approval,
            Digest32V2::new([8; 32]),
            Digest32V2::new([9; 32]),
            Digest32V2::new([commit; 32]),
        )
        .unwrap()
    };
    let p = publication(0xa4, 0xc1, digest, 10);
    let attach =
        |p| a.attach_private_publication_v04(session.record, p, UnixMillisV2::new(210), deadline());
    assert!(attach(p).is_err());
    a.begin_private_session_v04(session.transfer, UnixMillisV2::new(202), deadline())
        .unwrap();
    let browser = a
        .finish_private_session_v04(
            session.transfer,
            assertion(0xc3, 5),
            Digest32V2::new([4; 32]),
            UnixMillisV2::new(203),
            deadline(),
        )
        .unwrap();
    assert!(attach(p).is_err());
    a.attach_private_release_approval_v04(
        session.record,
        approval,
        Digest32V2::new([0xc1; 32]),
        UnixMillisV2::new(204),
        deadline(),
    )
    .unwrap();
    assert!(
        attach(p).is_err(),
        "pending approval cannot mean completed publication"
    );

    let challenge = URL_SAFE_NO_PAD.encode(challenge.as_bytes());
    let client = format!(r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"http://localhost:8766","crossOrigin":false}}"#).into_bytes();
    let mut auth = Sha256::digest(b"localhost").to_vec();
    auth.push(5);
    auth.extend(3u32.to_be_bytes());
    let mut signed = auth.clone();
    signed.extend(Sha256::digest(&client));
    let signature: Signature = key().sign(&signed);
    let signature = signature.normalize_s().unwrap_or(signature);
    let proof = crate::WebAuthnAssertionV2::from_wire(
        webauthn_credential_digest_v2(&[0x79; 32]).unwrap(),
        PrincipalIdV2::new([0xa6; 32]),
        client,
        auth,
        signature.to_der().as_bytes().to_vec(),
    )
    .unwrap();
    a.state
        .settle_approval(
            digest,
            savana_kernel_protocol::v2::ApprovalDecisionV2::Approve,
            proof,
            UnixMillisV2::new(205),
            deadline(),
        )
        .unwrap();
    assert!(a
        .private_session_handoff_v04(browser, UnixMillisV2::new(206), deadline())
        .unwrap()
        .is_none());
    assert!(
        a.private_session_publication_v04(browser, UnixMillisV2::new(206), deadline())
            .unwrap()
            .is_none(),
        "approved plus empty queue is still not publication"
    );
    for bad in [
        publication(0xa5, 0xc1, digest, 10),
        publication(0xa4, 0xc0, digest, 10),
        publication(0xa4, 0xc1, Digest32V2::new([99; 32]), 10),
    ] {
        assert!(attach(bad).is_err());
    }
    // Run and boot are separate scope boundaries even for the same task/root.
    for field in [1, 3] {
        let mut bytes = encode_private_publication_v04(p).unwrap();
        let begin = 4 + field * 34;
        bytes[begin..begin + 32].fill(99);
        assert!(attach(decode_private_publication_v04(&bytes).unwrap()).is_err());
    }
    attach(p).unwrap();
    attach(p).unwrap();
    for field in 0..11 {
        let mut bytes = encode_private_publication_v04(p).unwrap();
        let begin = 4 + field * 34;
        bytes[begin..begin + 32].fill(99);
        assert!(
            attach(decode_private_publication_v04(&bytes).unwrap()).is_err(),
            "confirmed metadata is immutable"
        );
    }
    assert!(attach(publication(0xa4, 0xc1, digest, 11)).is_err());
    assert_eq!(
        a.private_session_publication_v04(browser, UnixMillisV2::new(211), deadline())
            .unwrap(),
        Some(p)
    );
    assert!(a
        .private_session_publication_v04(
            PrivateSessionBrowserCapabilityV04::from_authority_entropy([99; 32]).unwrap(),
            UnixMillisV2::new(211),
            deadline()
        )
        .is_err());
    assert!(a
        .private_session_publication_v04(browser, UnixMillisV2::new(1000), deadline())
        .is_err());
    a.state
        .revoke_credential(
            webauthn_credential_digest_v2(&[0x79; 32]).unwrap(),
            ClosedCredentialRevocationReasonV2::Compromised,
            deadline(),
        )
        .unwrap();
    assert!(a
        .private_session_publication_v04(browser, UnixMillisV2::new(212), deadline())
        .is_err());
    assert!(
        attach(p).is_err(),
        "revoked owner cannot receive even a retry notification"
    );
}

#[test]
fn private_release_handoff_is_separate_role_bound_and_cannot_replace_pending_tool() {
    for release_first in [true, false] {
        let dir = directory();
        let a = open(dir.path(), Anchor::default());
        register_credential(&a);
        let session = a
            .register_private_session_v04(envelope(0xa4, 0xa6), UnixMillisV2::new(200), deadline())
            .unwrap();
        let (e, d) = crate::protocol_service::tests::kernel_release_delivery_pair(true);
        let RegisteredApprovalV2::Release {
            approval: release,
            display_authentication: release_display,
        } = a
            .register_approval(
                EndpointRoleV2::KernelApproval,
                e,
                d,
                UnixMillisV2::new(201),
                deadline(),
            )
            .unwrap()
        else {
            panic!("release handle required")
        };
        assert!(a
            .attach_private_release_approval_v04(
                session.record,
                release,
                Digest32V2::new([0xc1; 32]),
                UnixMillisV2::new(202),
                deadline()
            )
            .is_err());
        assert!(a
            .get_agent_approval_settlement(
                AgentApprovalRecordTargetV2::Release(release),
                UnixMillisV2::new(202),
                deadline()
            )
            .is_err());
        // Identical entropy cannot cross the purpose-tagged handle boundary.
        let encoded = minicbor::to_vec(release).unwrap();
        let forged_tool = ToolApprovalRecordHandleV2::from_authority_entropy(
            minicbor::Decoder::new(&encoded)
                .bytes()
                .unwrap()
                .try_into()
                .unwrap(),
        )
        .unwrap();
        assert!(a
            .get_kernel_approval_settlement(forged_tool, UnixMillisV2::new(202), deadline())
            .is_err());
        let (e, d) = crate::protocol_service::tests::kernel_delivery_pair(true);
        let RegisteredApprovalV2::Tool {
            approval: tool,
            display_authentication: tool_display,
        } = a
            .register_approval(
                EndpointRoleV2::KernelApproval,
                e,
                d,
                UnixMillisV2::new(202),
                deadline(),
            )
            .unwrap()
        else {
            panic!("tool handle required")
        };
        a.begin_private_session_v04(session.transfer, UnixMillisV2::new(203), deadline())
            .unwrap();
        let browser = a
            .finish_private_session_v04(
                session.transfer,
                assertion(0xc3, 5),
                Digest32V2::new([4; 32]),
                UnixMillisV2::new(204),
                deadline(),
            )
            .unwrap();
        assert!(a
            .attach_private_release_approval_v04(
                session.record,
                release,
                Digest32V2::new([0xff; 32]),
                UnixMillisV2::new(205),
                deadline()
            )
            .is_err());
        assert_eq!(
            a.private_session_handoff_v04(browser, UnixMillisV2::new(205), deadline())
                .unwrap(),
            None
        );
        let attach_release = || {
            a.attach_private_release_approval_v04(
                session.record,
                release,
                Digest32V2::new([0xc1; 32]),
                UnixMillisV2::new(206),
                deadline(),
            )
        };
        let attach_tool = || {
            a.attach_private_approval_v04(
                session.record,
                tool,
                Digest32V2::new([0xc1; 32]),
                UnixMillisV2::new(206),
                deadline(),
            )
        };
        if release_first {
            attach_release().unwrap();
            attach_release().unwrap();
            assert!(a.accept_approval_display_transfer(release_display).is_err());
            a.accept_kernel_approval_display_transfer_v04(
                release_display,
                UnixMillisV2::new(206),
                deadline(),
            )
            .unwrap();
            // The private handoff opens pre-authentication only, never a vote.
            assert!(a
                .records
                .lock()
                .unwrap()
                .iter()
                .all(|r| r.approval_tab.is_none()
                    && r.decision.is_none()
                    && r.settlement.is_none()));
            assert!(matches!(
                attach_tool(),
                Err(ApprovalUiAuthorityErrorV2::Busy)
            ));
        } else {
            attach_tool().unwrap();
            assert!(matches!(
                attach_release(),
                Err(ApprovalUiAuthorityErrorV2::Busy)
            ));
        }
        assert_eq!(
            a.private_session_handoff_v04(browser, UnixMillisV2::new(207), deadline())
                .unwrap(),
            Some(if release_first {
                release_display
            } else {
                tool_display
            })
        );
        assert_eq!(
            a.get_kernel_release_approval_settlement(release, UnixMillisV2::new(207), deadline())
                .unwrap(),
            ApprovalSettlementViewV2::Pending
        );
        assert!(a
            .private_session_handoff_v04(browser, UnixMillisV2::new(1000), deadline())
            .is_err());
    }
}

#[test]
fn private_session_hardware_authentication_then_exact_kernel_handoff() {
    let dir = directory();
    let a = open(dir.path(), Anchor::default());
    register_credential(&a);
    let e = envelope(0xa4, 0xa6);
    let registered = a
        .register_private_session_v04(e.clone(), UnixMillisV2::new(200), deadline())
        .unwrap();
    assert_eq!(
        registered,
        a.register_private_session_v04(e, UnixMillisV2::new(201), deadline())
            .unwrap()
    );
    assert!(a
        .private_session_authentication_v04(registered.record, UnixMillisV2::new(201), deadline())
        .unwrap()
        .is_none());
    let (approval, display) = crate::protocol_service::tests::kernel_delivery_pair(true);
    let RegisteredApprovalV2::Tool {
        approval,
        display_authentication,
    } = a
        .register_approval(
            EndpointRoleV2::KernelApproval,
            approval,
            display,
            UnixMillisV2::new(202),
            deadline(),
        )
        .unwrap()
    else {
        panic!()
    };
    assert!(a
        .attach_private_approval_v04(
            registered.record,
            approval,
            Digest32V2::new([0xc1; 32]),
            UnixMillisV2::new(203),
            deadline()
        )
        .is_err());
    assert!(a
        .finish_private_session_v04(
            registered.transfer,
            assertion(0xc3, 5),
            Digest32V2::new([1; 32]),
            UnixMillisV2::new(203),
            deadline()
        )
        .is_err());
    let options = a
        .begin_private_session_v04(registered.transfer, UnixMillisV2::new(204), deadline())
        .unwrap();
    let options: serde_json::Value = serde_json::from_slice(&options).unwrap();
    assert_eq!(options["userVerification"], "required");
    assert!(a
        .finish_private_session_v04(
            registered.transfer,
            assertion(0xee, 5),
            Digest32V2::new([2; 32]),
            UnixMillisV2::new(205),
            deadline()
        )
        .is_err());
    assert!(a
        .finish_private_session_v04(
            registered.transfer,
            assertion(0xc3, 1),
            Digest32V2::new([3; 32]),
            UnixMillisV2::new(205),
            deadline()
        )
        .is_err());
    let cap = a
        .finish_private_session_v04(
            registered.transfer,
            assertion(0xc3, 5),
            Digest32V2::new([4; 32]),
            UnixMillisV2::new(206),
            deadline(),
        )
        .unwrap();
    assert_eq!(
        cap,
        a.finish_private_session_v04(
            registered.transfer,
            assertion(0xc3, 5),
            Digest32V2::new([4; 32]),
            UnixMillisV2::new(207),
            deadline()
        )
        .unwrap()
    );
    assert!(a
        .finish_private_session_v04(
            registered.transfer,
            assertion(0xc3, 5),
            Digest32V2::new([5; 32]),
            UnixMillisV2::new(207),
            deadline()
        )
        .is_err());
    let proof = a
        .private_session_authentication_v04(registered.record, UnixMillisV2::new(207), deadline())
        .unwrap()
        .unwrap();
    assert_eq!(
        proof.purpose(),
        UiAuthenticationPurposeV2::PrivateSessionV04
    );
    assert!(a
        .private_session_handoff_v04(cap, UnixMillisV2::new(207), deadline())
        .unwrap()
        .is_none());
    assert!(a
        .attach_private_approval_v04(
            registered.record,
            approval,
            Digest32V2::new([0xff; 32]),
            UnixMillisV2::new(208),
            deadline()
        )
        .is_err());
    a.attach_private_approval_v04(
        registered.record,
        approval,
        Digest32V2::new([0xc1; 32]),
        UnixMillisV2::new(208),
        deadline(),
    )
    .unwrap();
    assert_eq!(
        Some(display_authentication),
        a.private_session_handoff_v04(cap, UnixMillisV2::new(209), deadline())
            .unwrap()
    );
    // Identity authentication and notification do not produce any G6 vote.
    assert_eq!(
        a.get_kernel_approval_settlement(approval, UnixMillisV2::new(210), deadline())
            .unwrap(),
        ApprovalSettlementViewV2::Pending
    );
    a.state
        .revoke_credential(
            webauthn_credential_digest_v2(&[0x79; 32]).unwrap(),
            ClosedCredentialRevocationReasonV2::Compromised,
            deadline(),
        )
        .unwrap();
    assert!(a
        .private_session_authentication_v04(registered.record, UnixMillisV2::new(211), deadline())
        .is_err());
    assert!(a
        .private_session_handoff_v04(cap, UnixMillisV2::new(211), deadline())
        .is_err());
    assert!(a
        .finish_private_session_v04(
            registered.transfer,
            assertion(0xc3, 5),
            Digest32V2::new([4; 32]),
            UnixMillisV2::new(211),
            deadline()
        )
        .is_err());
}

#[test]
fn private_session_rejects_cross_task_expiry_and_boot_restart_handles() {
    let dir = directory();
    let anchor = Anchor::default();
    let a = open(dir.path(), anchor.clone());
    register_credential(&a);
    let e = envelope(0x99, 0xa6);
    let r = a
        .register_private_session_v04(e.clone(), UnixMillisV2::new(200), deadline())
        .unwrap();
    a.begin_private_session_v04(r.transfer, UnixMillisV2::new(201), deadline())
        .unwrap();
    let cap = a
        .finish_private_session_v04(
            r.transfer,
            assertion(0xc3, 5),
            Digest32V2::new([4; 32]),
            UnixMillisV2::new(202),
            deadline(),
        )
        .unwrap();
    let (approval, display) = crate::protocol_service::tests::kernel_delivery_pair(true);
    let RegisteredApprovalV2::Tool { approval, .. } = a
        .register_approval(
            EndpointRoleV2::KernelApproval,
            approval,
            display,
            UnixMillisV2::new(203),
            deadline(),
        )
        .unwrap()
    else {
        panic!()
    };
    assert!(a
        .attach_private_approval_v04(
            r.record,
            approval,
            Digest32V2::new([0xc1; 32]),
            UnixMillisV2::new(204),
            deadline()
        )
        .is_err());
    assert!(a
        .private_session_handoff_v04(cap, UnixMillisV2::new(1000), deadline())
        .is_err());
    drop(a);
    let a = open(dir.path(), anchor);
    assert!(a
        .private_session_handoff_v04(cap, UnixMillisV2::new(205), deadline())
        .is_err());
    assert!(a
        .private_session_authentication_v04(r.record, UnixMillisV2::new(205), deadline())
        .is_err());
    let next = a
        .register_private_session_v04(e, UnixMillisV2::new(206), deadline())
        .unwrap();
    assert_ne!(next, r);
    // A signed proof may be recovered by the kernel, but never turns an old
    // browser handle into a new logged-in browser or repeats its consumed challenge.
    assert!(a
        .begin_private_session_v04(next.transfer, UnixMillisV2::new(207), deadline())
        .is_err());
    assert!(a
        .attach_private_approval_v04(
            next.record,
            approval,
            Digest32V2::new([0xc1; 32]),
            UnixMillisV2::new(207),
            deadline()
        )
        .is_err());
}

#[test]
fn private_session_rejects_legacy_purpose_and_wrong_principal() {
    let dir = directory();
    let a = open(dir.path(), Anchor::default());
    register_credential(&a);
    let (_, legacy) = crate::protocol_service::tests::kernel_delivery_pair(true);
    assert!(a
        .register_private_session_v04(legacy, UnixMillisV2::new(200), deadline())
        .is_err());
    let r = a
        .register_private_session_v04(envelope(0xa4, 0x99), UnixMillisV2::new(200), deadline())
        .unwrap();
    a.begin_private_session_v04(r.transfer, UnixMillisV2::new(201), deadline())
        .unwrap();
    assert!(a
        .finish_private_session_v04(
            r.transfer,
            assertion(0xc3, 5),
            Digest32V2::new([4; 32]),
            UnixMillisV2::new(202),
            deadline()
        )
        .is_err());
    assert!(a
        .private_session_authentication_v04(r.record, UnixMillisV2::new(203), deadline())
        .unwrap()
        .is_none());
}
