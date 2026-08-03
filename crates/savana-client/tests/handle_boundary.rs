use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use savana_client::{Handle, HandleKind, SessionBootstrap};

#[test]
fn control_plane_bootstrap_parser_accepts_only_nonzero_unpadded_32_bytes() {
    let token = URL_SAFE_NO_PAD.encode([0x5a; 32]);
    let bootstrap = SessionBootstrap::from_control_plane_token(&token).unwrap();
    let debug = format!("{bootstrap:?}");
    assert_eq!(debug, "SessionBootstrap(<opaque>)");
    assert!(!debug.contains(&token));

    for invalid in [
        URL_SAFE_NO_PAD.encode([0_u8; 32]),
        URL_SAFE_NO_PAD.encode([0x5a; 31]),
        format!("{token}="),
        "not base64url!".to_owned(),
    ] {
        assert!(SessionBootstrap::from_control_plane_token(&invalid).is_err());
    }
}

#[test]
fn handle_public_surface_is_kind_checked_without_a_public_constructor() {
    let _kind_method: fn(&Handle) -> HandleKind = Handle::kind;
    assert_eq!(HandleKind::Document.as_str(), "document");
    assert_eq!(HandleKind::PlanStep.as_str(), "plan-step");
}
