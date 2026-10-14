use ed25519_dalek::SigningKey;
use savana_kernel_protocol::v2::*;

fn ui(
    profile: AuthenticationAssuranceV04,
    be: bool,
    bs: bool,
    counter: u32,
) -> Result<UnsignedUiAuthenticationSettlementV2, savana_kernel_protocol::ProtocolError> {
    UnsignedUiAuthenticationSettlementV2::new_with_assurance(
        profile,
        Digest32V2::new([1; 32]),
        Digest32V2::new([2; 32]),
        1,
        UiAuthenticationPurposeV2::PrivateSessionV04,
        Digest32V2::new([3; 32]),
        Digest32V2::new([4; 32]),
        FixedOriginV2::Approval8766,
        FixedOriginV2::Approval8766,
        PrincipalIdV2::new([5; 32]),
        Digest32V2::new([6; 32]),
        Digest32V2::new([7; 32]),
        true,
        true,
        be,
        bs,
        counter,
        Nonce32V2::new([8; 32]),
        Nonce32V2::new([9; 32]),
        UnixMillisV2::new(100),
        UnixMillisV2::new(200),
    )
}

#[test]
fn passkey_profile_round_trips_and_is_in_signed_material() {
    let key = SigningKey::from_bytes(&[10; 32]);
    let u = ui(
        AuthenticationAssuranceV04::UserVerifiedPasskey,
        true,
        true,
        0,
    )
    .unwrap();
    let signed = SignedUiAuthenticationSettlementV2::sign(u, &key).unwrap();
    let wire = encode_signed_ui_authentication_settlement_v2(&signed).unwrap();
    let decoded = decode_signed_ui_authentication_settlement_v2(&wire).unwrap();
    let verify = |s: &SignedUiAuthenticationSettlementV2| {
        s.verify_private_session_v04(
            signed.key_id(),
            key.verifying_key().to_bytes(),
            Digest32V2::new([1; 32]),
            Digest32V2::new([2; 32]),
            1,
            UnixMillisV2::new(150),
        )
    };
    assert_eq!(
        verify(&decoded).unwrap().assurance(),
        AuthenticationAssuranceV04::UserVerifiedPasskey
    );
    // A signature from a passkey receipt cannot be relabeled hardware.
    let mislabeled = SignedUiAuthenticationSettlementV2::from_parts(
        ui(
            AuthenticationAssuranceV04::AttestedHardware,
            false,
            false,
            1,
        )
        .unwrap(),
        signed.key_id(),
        signed.signature(),
    )
    .unwrap();
    assert!(verify(&mislabeled).is_err());
    // No alternate profile/CBOR shape is accepted, including unknown tags.
    let mut d = minicbor::Decoder::new(&wire);
    assert_eq!(d.array().unwrap(), Some(3));
    let payload = d.bytes().unwrap();
    let offset = wire
        .windows(payload.len())
        .position(|w| w == payload)
        .unwrap();
    assert_eq!(&payload[..3], &[0x96, 3, 2]);
    for tag in [0, 1, 3, 23] {
        let mut bad = wire.clone();
        bad[offset + 2] = tag;
        assert!(decode_signed_ui_authentication_settlement_v2(&bad).is_err());
    }
}

#[test]
fn hardware_wire_stays_schema_two_and_retains_strict_evidence_checks() {
    for (be, bs, counter) in [(true, false, 1), (false, true, 1), (false, false, 0)] {
        assert!(ui(
            AuthenticationAssuranceV04::AttestedHardware,
            be,
            bs,
            counter
        )
        .is_err());
    }
    assert!(ui(
        AuthenticationAssuranceV04::UserVerifiedPasskey,
        false,
        true,
        0
    )
    .is_err());
    let key = SigningKey::from_bytes(&[10; 32]);
    let signed = SignedUiAuthenticationSettlementV2::sign(
        ui(
            AuthenticationAssuranceV04::AttestedHardware,
            false,
            false,
            1,
        )
        .unwrap(),
        &key,
    )
    .unwrap();
    let wire = encode_signed_ui_authentication_settlement_v2(&signed).unwrap();
    let mut d = minicbor::Decoder::new(&wire);
    d.array().unwrap();
    assert_eq!(&d.bytes().unwrap()[..2], &[0x95, 2]);
    assert_eq!(
        decode_signed_ui_authentication_settlement_v2(&wire).unwrap(),
        signed
    );
}

#[test]
fn passkey_action_settlement_preserves_real_flags_and_zero_counter() {
    let u = UnsignedApprovalSettlementV2::new_with_assurance(
        AuthenticationAssuranceV04::UserVerifiedPasskey,
        Digest32V2::new([1; 32]),
        Digest32V2::new([2; 32]),
        1,
        ApprovalPurposeV2::ToolExecution,
        Digest32V2::new([3; 32]),
        ApprovalDecisionV2::Approve,
        PrincipalIdV2::new([4; 32]),
        Digest32V2::new([5; 32]),
        Digest32V2::new([6; 32]),
        true,
        true,
        true,
        true,
        0,
        Nonce32V2::new([7; 32]),
        Nonce32V2::new([8; 32]),
        UnixMillisV2::new(100),
        UnixMillisV2::new(200),
    )
    .unwrap();
    let signed = SignedApprovalSettlementV2::sign(u, &SigningKey::from_bytes(&[9; 32])).unwrap();
    let wire = encode_signed_approval_settlement_v2(&signed).unwrap();
    assert_eq!(decode_signed_approval_settlement_v2(&wire).unwrap(), signed);
    assert_eq!(signed.unsigned().signature_counter(), 0);
    assert!(signed.unsigned().backup_state());
    assert_eq!(
        signed.unsigned().assurance(),
        AuthenticationAssuranceV04::UserVerifiedPasskey
    );
}

#[test]
fn neither_profile_ever_accepts_missing_presence_or_verification() {
    for profile in [
        AuthenticationAssuranceV04::AttestedHardware,
        AuthenticationAssuranceV04::UserVerifiedPasskey,
    ] {
        assert!(!profile.accepts_evidence(false, true, false, false, 1));
        assert!(!profile.accepts_evidence(true, false, false, false, 1));
        assert!(!profile.accepts_evidence(true, true, false, true, 1));
    }
}
