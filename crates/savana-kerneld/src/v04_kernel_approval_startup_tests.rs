use super::*;

#[test]
fn kernel_approval_handshake_keys_are_distinct_and_exact() {
    let seed = [0xd1; 32];
    let public = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    let server = SigningKey::from_bytes(&[0xd2; 32])
        .verifying_key()
        .to_bytes();
    let client_id = derive_ed25519_key_id_v2(public);
    let server_id = derive_ed25519_key_id_v2(server);
    assert!(
        validate_kernel_approval_keys(&seed, client_id, server, server_id, &[[0xd3; 32]]).is_ok()
    );
    for duplicate in [seed, public, server] {
        assert!(
            validate_kernel_approval_keys(&seed, client_id, server, server_id, &[duplicate])
                .is_err()
        );
    }
    assert!(validate_kernel_approval_keys(&seed, server_id, server, server_id, &[]).is_err());
    assert!(validate_kernel_approval_keys(&seed, client_id, server, client_id, &[]).is_err());
    assert!(validate_kernel_approval_keys(&seed, client_id, public, client_id, &[]).is_err());
    assert!(validate_kernel_approval_keys(&[0; 32], client_id, server, server_id, &[]).is_err());
    assert!(validate_kernel_approval_keys(&seed, client_id, [0; 32], server_id, &[]).is_err());
}

#[test]
fn kernel_approval_bootstrap_has_no_endpoint_or_key_path_override() {
    let valid = br#"{"client_key_id":"id","server_key_id":"id","server_public_key_path":"/etc/savana/keys/approval-server-v2.pub"}"#;
    assert!(serde_json::from_slice::<KernelApprovalDtoV04>(valid).is_ok());
    for extra in [
        "socket_path",
        "client_seed_path",
        "skip_peer_validation",
        "allow_unsigned",
    ] {
        let mut document: serde_json::Value = serde_json::from_slice(valid).unwrap();
        document
            .as_object_mut()
            .unwrap()
            .insert(extra.into(), serde_json::Value::Bool(true));
        assert!(serde_json::from_value::<KernelApprovalDtoV04>(document).is_err());
    }
    assert!(serde_json::from_slice::<KernelApprovalDtoV04>(br#"{"client_key_id":"id"}"#).is_err());
}
