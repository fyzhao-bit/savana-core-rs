use crate::{protocol_service::tests::enrollment_service, *};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::{Signature, SigningKey as P256Key};
use savana_kernel_protocol::v2::*;
use sha2::Sha256;
use std::os::unix::fs::PermissionsExt as _;
use std::sync::{Arc, Mutex};

const PASSKEY: AuthenticationAssuranceV04 = AuthenticationAssuranceV04::UserVerifiedPasskey;
const HARDWARE: AuthenticationAssuranceV04 = AuthenticationAssuranceV04::AttestedHardware;

fn key() -> P256Key {
    P256Key::from_slice(&[0x31; 32]).unwrap()
}
fn client(kind: &str, challenge: Nonce32V2, origin: &str) -> Vec<u8> {
    serde_json::to_vec(
        &serde_json::json!({"type": kind, "challenge": URL_SAFE_NO_PAD.encode(challenge.as_bytes()),
        "origin": origin, "crossOrigin": false}),
    )
    .unwrap()
}
fn object(flags: u8, counter: u32) -> Vec<u8> {
    let public = key().verifying_key().to_encoded_point(false);
    let mut cose = minicbor::Encoder::new(Vec::new());
    cose.map(5)
        .unwrap()
        .i32(1)
        .unwrap()
        .i32(2)
        .unwrap()
        .i32(3)
        .unwrap()
        .i32(-7)
        .unwrap()
        .i32(-1)
        .unwrap()
        .i32(1)
        .unwrap()
        .i32(-2)
        .unwrap()
        .bytes(public.x().unwrap())
        .unwrap()
        .i32(-3)
        .unwrap()
        .bytes(public.y().unwrap())
        .unwrap();
    let mut auth = Sha256::digest(b"localhost").to_vec();
    auth.push(flags);
    auth.extend(counter.to_be_bytes());
    auth.extend([0; 16]);
    auth.extend(32u16.to_be_bytes());
    auth.extend([0x32; 32]);
    auth.extend(cose.into_writer());
    let mut e = minicbor::Encoder::new(Vec::new());
    e.map(3)
        .unwrap()
        .str("fmt")
        .unwrap()
        .str("none")
        .unwrap()
        .str("authData")
        .unwrap()
        .bytes(&auth)
        .unwrap()
        .str("attStmt")
        .unwrap()
        .map(0)
        .unwrap();
    e.into_writer()
}
fn verified() -> VerifiedPasskeyRegistrationV04 {
    let challenge = Nonce32V2::new([0x33; 32]);
    verify_passkey_registration_v04(
        &[0x32; 32],
        &client("webauthn.create", challenge, APPROVAL_ORIGIN),
        &object(0x5d, 0),
        challenge,
    )
    .unwrap()
}
fn service() -> ProtocolApprovalServiceV2 {
    let mut s = enrollment_service();
    s.load_verified_enrollment_profile_with_assurance(
        EnrollmentProfileIdV2::new(2),
        10_000,
        5_000,
        PASSKEY,
    )
    .unwrap();
    s
}
fn enroll(s: &mut ProtocolApprovalServiceV2) -> PrincipalIdV2 {
    let (h, code, _) = s
        .create_enrollment_code(
            EnrollmentProfileIdV2::new(2),
            Nonce32V2::new([0x34; 32]),
            UnixMillisV2::new(100),
        )
        .unwrap()
        .into_parts();
    let grant = s
        .consume_enrollment_code(h, &code, UnixMillisV2::new(101))
        .unwrap();
    assert_eq!(grant.assurance(), PASSKEY);
    s.register_enrolled_passkey(h, digest(), verified())
        .unwrap();
    assert!(s
        .register_enrolled_passkey(h, digest(), verified())
        .is_err());
    grant.principal()
}
fn digest() -> Digest32V2 {
    webauthn_credential_digest_v2(&[0x32; 32]).unwrap()
}
fn assertion(
    principal: PrincipalIdV2,
    challenge: Nonce32V2,
    flags: u8,
    counter: u32,
) -> WebAuthnAssertionV2 {
    let c = client("webauthn.get", challenge, APPROVAL_ORIGIN);
    let mut auth = Sha256::digest(b"localhost").to_vec();
    auth.push(flags);
    auth.extend(counter.to_be_bytes());
    let mut signed = auth.clone();
    signed.extend(Sha256::digest(&c));
    let signature: Signature = key().sign(&signed);
    WebAuthnAssertionV2::from_wire(
        digest(),
        principal,
        c,
        auth,
        signature.to_der().as_bytes().to_vec(),
    )
    .unwrap()
}
fn envelope(
    principal: PrincipalIdV2,
    nonce: Nonce32V2,
) -> savana_kernel_protocol::v2::SignedUiAuthenticationEnvelopeV2 {
    savana_kernel_protocol::v2::SignedUiAuthenticationEnvelopeV2::sign(
        UnsignedUiAuthenticationEnvelopeV2::new(
            Digest32V2::new([0x74; 32]),
            Digest32V2::new([0x75; 32]),
            9,
            UiAuthenticationPurposeV2::PrivateSessionV04,
            UiAuthenticationBindingV2::PrivateSessionV04 {
                durable_task_id: DurableTaskIdV2::new([0x41; 32]),
                durable_run_id: DurableRunIdV2::new([0x42; 32]),
                task_authorization_digest: Digest32V2::new([0x43; 32]),
                kerneld_boot_id: BootIdV2::new([0x44; 32]),
            },
            Some(principal),
            FixedOriginV2::Approval8766,
            FixedOriginV2::Approval8766,
            nonce,
            UnixMillisV2::new(100),
            UnixMillisV2::new(1000),
        )
        .unwrap(),
        &ed25519_dalek::SigningKey::from_bytes(&[0x71; 32]),
    )
    .unwrap()
}

#[test]
fn passkey_registration_allows_synced_zero_counter_without_claiming_attestation() {
    let v = verified();
    assert!(v.backup_eligible);
    assert_eq!(v.signature_counter, 0);
    assert_eq!(v.aaguid, [0; 16]);
    let challenge = Nonce32V2::new([0x33; 32]);
    assert!(verify_enrollment_attestation_v2(
        &[0x32; 32],
        &client("webauthn.create", challenge, APPROVAL_ORIGIN),
        &object(0x5d, 0),
        challenge,
        &[],
        UnixMillisV2::new(100)
    )
    .is_err());
}

#[test]
fn passkey_registration_checks_flags_rp_challenge_origin_id_and_complete_cbor() {
    let ch = Nonce32V2::new([0x33; 32]);
    let c = client("webauthn.create", ch, APPROVAL_ORIGIN);
    for flags in [0x59, 0x5c, 0x55, 0xdd, 0x7d, 0x1d] {
        assert!(
            verify_passkey_registration_v04(&[0x32; 32], &c, &object(flags, 0), ch).is_err(),
            "{flags}"
        );
    }
    for bad in [
        client("webauthn.get", ch, APPROVAL_ORIGIN),
        client("webauthn.create", ch, "http://localhost:8771"),
        client(
            "webauthn.create",
            Nonce32V2::new([0x34; 32]),
            APPROVAL_ORIGIN,
        ),
    ] {
        assert!(verify_passkey_registration_v04(&[0x32; 32], &bad, &object(0x5d, 0), ch).is_err());
    }
    assert!(verify_passkey_registration_v04(&[0x35; 32], &c, &object(0x5d, 0), ch).is_err());
    let mut trailing = object(0x5d, 0);
    trailing.push(0);
    assert!(verify_passkey_registration_v04(&[0x32; 32], &c, &trailing, ch).is_err());
    let mut wrong_rp = object(0x5d, 0);
    let offset = wrong_rp
        .windows(32)
        .position(|w| w == Sha256::digest(b"localhost").as_slice())
        .unwrap();
    wrong_rp[offset] ^= 1;
    assert!(verify_passkey_registration_v04(&[0x32; 32], &c, &wrong_rp, ch).is_err());
}

#[test]
fn passkey_cannot_use_hardware_grant_and_hardware_cannot_use_passkey_grant() {
    let mut s = service();
    for profile in [1, 2] {
        let (h, code, _) = s
            .create_enrollment_code(
                EnrollmentProfileIdV2::new(profile),
                Nonce32V2::new([profile as u8; 32]),
                UnixMillisV2::new(100),
            )
            .unwrap()
            .into_parts();
        s.consume_enrollment_code(h, &code, UnixMillisV2::new(101))
            .unwrap();
        let public = key().verifying_key().to_encoded_point(false);
        if profile == 1 {
            assert!(s
                .register_enrolled_passkey(h, digest(), verified())
                .is_err());
        } else {
            assert!(s
                .register_enrolled_hardware_credential(
                    h,
                    digest(),
                    [1; 16],
                    public.as_bytes().try_into().unwrap(),
                    1
                )
                .is_err());
        }
    }
}

#[test]
fn passkey_zero_counter_settlement_is_signed_profile_bound_and_one_use_after_restore() {
    let mut s = service();
    let principal = enroll(&mut s);
    let nonce = Nonce32V2::new([0x45; 32]);
    let env = envelope(principal, nonce);
    let d = s
        .register_ui_authentication_envelope(&env, UnixMillisV2::new(200))
        .unwrap();
    let a = assertion(principal, nonce, 0x1d, 0);
    let settled = s
        .settle_ui_authentication(d, &a, UnixMillisV2::new(201))
        .unwrap();
    assert_eq!(settled.unsigned().assurance(), PASSKEY);
    assert_eq!(settled.unsigned().signature_counter(), 0);
    assert!(settled.unsigned().backup_eligible());
    assert!(settled.unsigned().backup_state());
    let wire = encode_signed_ui_authentication_settlement_v2(&settled).unwrap();
    assert_eq!(
        decode_signed_ui_authentication_settlement_v2(&wire).unwrap(),
        settled
    );
    let mut restored = ProtocolApprovalServiceV2::restore_mutable_state(
        service(),
        &s.encode_mutable_state().unwrap(),
    )
    .unwrap();
    assert_eq!(
        restored
            .settle_ui_authentication(d, &a, UnixMillisV2::new(202))
            .unwrap_err(),
        ApprovalErrorV2::AlreadyConsumed
    );
    assert!(restored
        .private_session_authentication_v04(d, UnixMillisV2::new(202))
        .unwrap()
        .is_some());
    // Same zero-counter authenticator works on a new challenge, not the old one.
    let next = Nonce32V2::new([0x46; 32]);
    let nd = restored
        .register_ui_authentication_envelope(&envelope(principal, next), UnixMillisV2::new(203))
        .unwrap();
    assert!(restored
        .settle_ui_authentication(nd, &a, UnixMillisV2::new(204))
        .is_err());
    restored
        .settle_ui_authentication(
            nd,
            &assertion(principal, next, 0x0d, 0),
            UnixMillisV2::new(205),
        )
        .unwrap();
    restored
        .revoke_credential(digest(), ClosedCredentialRevocationReasonV2::Compromised)
        .unwrap();
    let final_nonce = Nonce32V2::new([0x47; 32]);
    let fd = restored
        .register_ui_authentication_envelope(
            &envelope(principal, final_nonce),
            UnixMillisV2::new(206),
        )
        .unwrap();
    assert!(restored
        .settle_ui_authentication(
            fd,
            &assertion(principal, final_nonce, 0x1d, 0),
            UnixMillisV2::new(207)
        )
        .is_err());
}

#[test]
fn passkey_assertions_reject_flags_signature_principal_origin_and_expiry() {
    let mut s = service();
    let principal = enroll(&mut s);
    let nonce = Nonce32V2::new([0x45; 32]);
    let d = s
        .register_ui_authentication_envelope(&envelope(principal, nonce), UnixMillisV2::new(200))
        .unwrap();
    for flags in [0x19, 0x1c, 0x15, 0x05, 0x3d, 0x5d, 0x9d] {
        assert!(
            s.settle_ui_authentication(
                d,
                &assertion(principal, nonce, flags, 0),
                UnixMillisV2::new(201)
            )
            .is_err(),
            "{flags}"
        );
    }
    let mut a = assertion(principal, nonce, 0x1d, 0);
    a.der_signature[10] ^= 1;
    assert!(s
        .settle_ui_authentication(d, &a, UnixMillisV2::new(201))
        .is_err());
    let a = assertion(PrincipalIdV2::new([0x99; 32]), nonce, 0x1d, 0);
    assert!(s
        .settle_ui_authentication(d, &a, UnixMillisV2::new(201))
        .is_err());
    let mut a = assertion(principal, nonce, 0x1d, 0);
    a.client_data_json =
        zeroize::Zeroizing::new(client("webauthn.get", nonce, "http://localhost:8771"));
    assert!(s
        .settle_ui_authentication(d, &a, UnixMillisV2::new(201))
        .is_err());
    assert!(s
        .settle_ui_authentication(
            d,
            &assertion(principal, nonce, 0x1d, 0),
            UnixMillisV2::new(1000)
        )
        .is_err());
}

#[test]
fn passkey_recovery_rejects_removed_or_reinterpreted_deployment_profile() {
    let mut s = service();
    enroll(&mut s);
    let bytes = s.encode_mutable_state().unwrap();
    assert!(
        ProtocolApprovalServiceV2::restore_mutable_state(enrollment_service(), &bytes).is_err()
    );
    let mut changed = enrollment_service();
    changed
        .load_verified_enrollment_profile_with_assurance(
            EnrollmentProfileIdV2::new(2),
            10_000,
            5_000,
            HARDWARE,
        )
        .unwrap();
    assert!(ProtocolApprovalServiceV2::restore_mutable_state(changed, &bytes).is_err());
}

#[test]
fn passkey_accepts_valid_high_s_es256_signature_without_hardware_normalization_rule() {
    let mut s = service();
    let principal = enroll(&mut s);
    let nonce = Nonce32V2::new([0x45; 32]);
    let d = s
        .register_ui_authentication_envelope(&envelope(principal, nonce), UnixMillisV2::new(200))
        .unwrap();
    let mut a = assertion(principal, nonce, 0x1d, 0);
    let mut signature = Signature::from_der(&a.der_signature).unwrap();
    if signature.normalize_s().is_none() {
        let (r, scalar) = signature.split_scalars();
        signature = Signature::from_scalars(r.to_bytes(), (-*scalar).to_bytes()).unwrap();
    }
    assert!(signature.normalize_s().is_some());
    a.der_signature = signature.to_der().as_bytes().to_vec();
    assert!(s
        .settle_ui_authentication(d, &a, UnixMillisV2::new(201))
        .is_ok());
}

#[test]
fn passkey_login_never_substitutes_for_separate_root_approval_and_denial_is_durable() {
    use savana_kernel_protocol::v2::{
        ApprovalDecisionV2 as Decision, ApprovalPurposeV2 as Purpose,
        SignedApprovalEnvelopeV2 as Envelope,
    };
    let mut s = service();
    let principal = enroll(&mut s);
    let login_nonce = Nonce32V2::new([0x45; 32]);
    let login = assertion(principal, login_nonce, 0x1d, 0);
    let login_digest = s
        .register_ui_authentication_envelope(
            &envelope(principal, login_nonce),
            UnixMillisV2::new(200),
        )
        .unwrap();
    s.settle_ui_authentication(login_digest, &login, UnixMillisV2::new(201))
        .unwrap();
    let text =
        BoundedApprovalDisplayTextV2::new("Approve only this synthetic task root".into()).unwrap();
    let decision_nonce = Nonce32V2::new([0x51; 32]);
    let approval = Envelope::sign(
        UnsignedApprovalEnvelopeV2::new(
            Digest32V2::new([0x74; 32]),
            Digest32V2::new([0x75; 32]),
            9,
            Purpose::TaskAuthorization,
            Nonce32V2::new([0x52; 32]),
            decision_nonce,
            ApprovalBindingV2::TaskAuthorization {
                authorization_id: Digest32V2::new([0x53; 32]),
                task: DurableTaskIdV2::new([0x41; 32]),
                revision: 1,
                change: TaskAuthorizationChangeV2::Create,
                draft_digest: Digest32V2::new([0x54; 32]),
            },
            principal,
            Digest32V2::new([0x54; 32]),
            approval_display_digest_v2(text.as_bytes()),
            text,
            Some(Digest32V2::new([0x55; 32])),
            ServiceIdentityV2::new([0x77; 32]),
            UnixMillisV2::new(100),
            UnixMillisV2::new(1000),
        )
        .unwrap(),
        &ed25519_dalek::SigningKey::from_bytes(&[0x71; 32]),
    )
    .unwrap();
    let d = s
        .register_approval_envelope(&approval, UnixMillisV2::new(202))
        .unwrap();
    assert!(s
        .settle_approval(d, Decision::Approve, &login, UnixMillisV2::new(203))
        .is_err());
    let decision = assertion(principal, decision_nonce, 0x1d, 0);
    let receipt = s
        .settle_approval(d, Decision::Deny, &decision, UnixMillisV2::new(204))
        .unwrap();
    assert_eq!(receipt.unsigned().assurance(), PASSKEY);
    assert_eq!(receipt.unsigned().signature_counter(), 0);
    assert_eq!(receipt.unsigned().decision(), Decision::Deny);
    assert_eq!(
        decode_signed_approval_settlement_v2(
            &encode_signed_approval_settlement_v2(&receipt).unwrap()
        )
        .unwrap(),
        receipt
    );
    let mut reopened = ProtocolApprovalServiceV2::restore_mutable_state(
        service(),
        &s.encode_mutable_state().unwrap(),
    )
    .unwrap();
    assert_eq!(
        reopened
            .settle_approval(d, Decision::Approve, &decision, UnixMillisV2::new(205))
            .unwrap_err(),
        ApprovalErrorV2::AlreadyConsumed
    );
}

#[derive(Clone, Default)]
struct Anchor(Arc<Mutex<ApprovalStateHeadV2>>);
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
        if *head != expected {
            return Err(ApprovalErrorV2::RollbackDetected);
        }
        *head = next;
        Ok(())
    }
}

#[test]
fn passkey_encrypted_owner_reopen_keeps_zero_counter_challenge_consumed() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = dir.path().join("approval-protocol-state-v2.cbor");
    let anchor = Anchor::default();
    let namespace = DurableApprovalNamespaceV2::from_verified_installation(
        Digest32V2::new([0x74; 32]),
        Digest32V2::new([0x70; 32]),
    )
    .unwrap();
    let open = || {
        DurableProtocolApprovalServiceV2::open(
            &path,
            [0x69; 32],
            namespace,
            Box::new(anchor.clone()),
            service(),
        )
        .unwrap()
    };
    let mut s = open();
    let (h, code, _) = s
        .create_enrollment_code(
            EnrollmentProfileIdV2::new(2),
            Nonce32V2::new([0x34; 32]),
            UnixMillisV2::new(100),
        )
        .unwrap()
        .into_parts();
    let grant = s
        .consume_enrollment_code(h, &code, UnixMillisV2::new(101))
        .unwrap();
    s.register_enrolled_passkey(h, digest(), verified())
        .unwrap();
    let nonce = Nonce32V2::new([0x45; 32]);
    let d = s
        .register_ui_authentication_envelope(
            &envelope(grant.principal(), nonce),
            UnixMillisV2::new(200),
        )
        .unwrap();
    let a = assertion(grant.principal(), nonce, 0x1d, 0);
    s.settle_ui_authentication(d, &a, UnixMillisV2::new(201))
        .unwrap();
    drop(s);
    let mut reopened = open();
    assert_eq!(
        reopened
            .settle_ui_authentication(d, &a, UnixMillisV2::new(202))
            .unwrap_err(),
        ApprovalErrorV2::AlreadyConsumed
    );
    assert!(reopened
        .private_session_authentication_v04(d, UnixMillisV2::new(202))
        .unwrap()
        .is_some());
}

#[test]
fn passkey_browser_enrollment_uses_grant_selected_options_and_durable_owner() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let namespace = DurableApprovalNamespaceV2::from_verified_installation(
        Digest32V2::new([0x74; 32]),
        Digest32V2::new([0x70; 32]),
    )
    .unwrap();
    let owner = ProtocolApprovalStateOwnerV2::open(
        &dir.path().join("approval-protocol-state-v2.cbor"),
        [0x69; 32],
        namespace,
        Box::new(Anchor::default()),
        service(),
        16,
    )
    .unwrap();
    let deadline = || std::time::Instant::now() + std::time::Duration::from_secs(5);
    let (handle, code, _) = owner
        .create_enrollment_code(
            EnrollmentProfileIdV2::new(2),
            Nonce32V2::new([0x34; 32]),
            UnixMillisV2::new(100),
            deadline(),
        )
        .unwrap()
        .into_parts();
    let authority = ApprovalUiAuthorityV2::new(owner, 128, vec![]).unwrap();
    let (ceremony, json) = authority
        .begin_enrollment(
            BeginEnrollmentBrowserRequestV2::new(handle, Nonce32V2::new([0x35; 32]), code).unwrap(),
            UnixMillisV2::new(101),
            deadline(),
        )
        .unwrap()
        .into_parts();
    let options: serde_json::Value = serde_json::from_slice(&json).unwrap();
    assert_eq!(options["attestation"], "none");
    assert_eq!(options["authenticatorSelection"]["residentKey"], "required");
    assert_eq!(
        options["authenticatorSelection"]["userVerification"],
        "required"
    );
    assert!(options["authenticatorSelection"]
        .get("authenticatorAttachment")
        .is_none());
    let challenge = Nonce32V2::new(
        URL_SAFE_NO_PAD
            .decode(options["challenge"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
    );
    let request = |nonce| {
        FinishEnrollmentBrowserRequestV2::new(
            ceremony,
            Nonce32V2::new([nonce; 32]),
            vec![0x32; 32],
            client("webauthn.create", challenge, APPROVAL_ORIGIN),
            object(0x5d, 0),
        )
        .unwrap()
    };
    let response = authority
        .finish_enrollment(request(0x36), UnixMillisV2::new(102), deadline())
        .unwrap();
    assert_eq!(
        response,
        authority
            .finish_enrollment(request(0x36), UnixMillisV2::new(103), deadline())
            .unwrap()
    );
    assert!(authority
        .finish_enrollment(request(0x37), UnixMillisV2::new(103), deadline())
        .is_err());
}
