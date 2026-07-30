use ed25519_dalek::SigningKey;
use savana_kernel_protocol::v2::{
    decode_signed_agent_authentication_closure_descriptor_v2,
    encode_signed_agent_authentication_closure_descriptor_v2, BootIdV2, Digest32V2, DurableRunIdV2,
    DurableTaskIdV2, Nonce32V2, PrincipalIdV2, ServiceIdentityV2,
    SignedAgentAuthenticationClosureDescriptorV2, UnixMillisV2,
    UnsignedAgentAuthenticationClosureDescriptorV2,
};

fn bytes(value: u8) -> [u8; 32] {
    [value; 32]
}

fn unsigned() -> UnsignedAgentAuthenticationClosureDescriptorV2 {
    UnsignedAgentAuthenticationClosureDescriptorV2::new(
        Digest32V2::new(bytes(1)),
        Digest32V2::new(bytes(2)),
        7,
        Digest32V2::new(bytes(2)),
        7,
        None,
        DurableTaskIdV2::new(bytes(3)),
        DurableRunIdV2::new(bytes(4)),
        Digest32V2::new(bytes(5)),
        Digest32V2::new(bytes(6)),
        PrincipalIdV2::new(bytes(7)),
        ServiceIdentityV2::new(bytes(8)),
        BootIdV2::new(bytes(9)),
        ServiceIdentityV2::new(bytes(10)),
        BootIdV2::new(bytes(11)),
        ServiceIdentityV2::new(bytes(12)),
        Nonce32V2::new(bytes(13)),
        Digest32V2::new(bytes(14)),
        Digest32V2::new(bytes(15)),
        Digest32V2::new(bytes(16)),
        Nonce32V2::new(bytes(17)),
        UnixMillisV2::new(1_000),
        UnixMillisV2::new(2_000),
    )
    .unwrap()
}

#[test]
fn closure_descriptor_is_canonical_signed_and_tamper_evident() {
    let key = SigningKey::from_bytes(&bytes(21));
    let signed = SignedAgentAuthenticationClosureDescriptorV2::sign(unsigned(), &key).unwrap();
    let encoded = encode_signed_agent_authentication_closure_descriptor_v2(&signed).unwrap();
    assert_eq!(
        decode_signed_agent_authentication_closure_descriptor_v2(&encoded).unwrap(),
        signed
    );
    assert_eq!(
        signed
            .verify(
                signed.key_id(),
                key.verifying_key().to_bytes(),
                UnixMillisV2::new(1_500),
            )
            .unwrap(),
        unsigned()
    );

    let mut tampered = encoded;
    let index = tampered.len() / 2;
    tampered[index] ^= 1;
    assert!(
        decode_signed_agent_authentication_closure_descriptor_v2(&tampered)
            .and_then(|value| value.verify(
                signed.key_id(),
                key.verifying_key().to_bytes(),
                UnixMillisV2::new(1_500),
            ))
            .is_err()
    );
}

#[test]
fn closure_manifest_matrix_is_closed() {
    assert!(UnsignedAgentAuthenticationClosureDescriptorV2::new(
        Digest32V2::new(bytes(1)),
        Digest32V2::new(bytes(2)),
        7,
        Digest32V2::new(bytes(3)),
        8,
        None,
        DurableTaskIdV2::new(bytes(4)),
        DurableRunIdV2::new(bytes(5)),
        Digest32V2::new(bytes(6)),
        Digest32V2::new(bytes(7)),
        PrincipalIdV2::new(bytes(8)),
        ServiceIdentityV2::new(bytes(9)),
        BootIdV2::new(bytes(10)),
        ServiceIdentityV2::new(bytes(11)),
        BootIdV2::new(bytes(12)),
        ServiceIdentityV2::new(bytes(13)),
        Nonce32V2::new(bytes(14)),
        Digest32V2::new(bytes(15)),
        Digest32V2::new(bytes(16)),
        Digest32V2::new(bytes(17)),
        Nonce32V2::new(bytes(18)),
        UnixMillisV2::new(1_000),
        UnixMillisV2::new(2_000),
    )
    .is_err());
}
