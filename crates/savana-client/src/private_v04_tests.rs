use super::*;

#[test]
fn private_v04_decoders_reject_noncanonical_trailing_and_wrong_version() {
    let options = encode_private_session_options_v04(b"{}").unwrap();
    assert_eq!(decode_options(&options).unwrap(), b"{}");
    let none = encode_private_session_handoff_v04(None).unwrap();
    assert!(decode_handoff(&none).unwrap().is_none());
    for mut frame in [options, none] {
        frame.push(0);
        assert!(decode_options(&frame).is_err());
        assert!(decode_handoff(&frame).is_err());
    }
    for bytes in [
        vec![],
        vec![0x82, 3, 0xf6],
        vec![0x82, 0x18, 4, 0xf6],
        vec![0; 9000],
    ] {
        assert!(decode_options(&bytes).is_err());
        assert!(decode_handoff(&bytes).is_err());
    }
}

#[test]
fn private_v04_transfer_is_not_a_url_or_public_bootstrap() {
    let token = URL_SAFE_NO_PAD.encode([1; 32]);
    assert!(parse_transfer(&token).is_ok());
    for token in [
        String::new(),
        format!("{token}="),
        format!("http://localhost/{token}"),
        URL_SAFE_NO_PAD.encode([0; 32]),
        "a".repeat(100_000),
    ] {
        assert!(parse_transfer(&token).is_err());
    }
}
