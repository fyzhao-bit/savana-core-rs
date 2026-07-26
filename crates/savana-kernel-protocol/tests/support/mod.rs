use ed25519_dalek::{Signer, SigningKey};
use savana_kernel_protocol::{
    BootId, ClientHelloV1, ClientId, Digest32, EffectiveLimits, HandshakeTranscriptV1, HardLimits,
    KeyId, Nonce32, ProtocolVersion, RequestedMode, ResourceLimitsV1, ServerIdentityV1,
    ServerMessageV1, Signature64, SignedServerHelloV1,
};

#[allow(dead_code)]
pub(crate) fn compiled_effective_limits() -> EffectiveLimits {
    let limits = HardLimits::COMPILED;
    let requested = ResourceLimitsV1 {
        frame_bytes: limits.frame_bytes(),
        cbor_depth: limits.cbor_depth(),
        pages: limits.pages(),
        chars_per_page: limits.chars_per_page(),
        chars_per_document: limits.chars_per_document(),
        observations: limits.observations(),
        vault_entries: limits.vault_entries(),
        vault_raw_bytes: limits.vault_raw_bytes(),
        runs_per_client: limits.runs_per_client(),
        vaults_per_client: limits.vaults_per_client(),
        approval_ledger_entries: limits.approval_ledger_entries(),
        model_manifest_bytes: limits.model_manifest_bytes(),
        model_assets: limits.model_assets(),
        model_tensor_contracts: limits.model_tensor_contracts(),
        model_tensor_rank: limits.model_tensor_rank(),
        single_model_asset_bytes: limits.single_model_asset_bytes(),
        total_model_asset_bytes: limits.total_model_asset_bytes(),
        ner_workers: limits.ner_workers(),
        ner_queue: limits.ner_queue(),
        ner_text_bytes: limits.ner_text_bytes(),
        model_probes: limits.model_probes(),
        model_probe_spans: limits.model_probe_spans(),
        ner_failure_threshold: limits.ner_failure_threshold(),
        request_deadline_ms: limits.request_deadline_ms(),
    };
    HardLimits::COMPILED
        .lower(&requested)
        .expect("compiled limits lower to themselves")
}

#[allow(dead_code)]
pub(crate) fn client_hello() -> ClientHelloV1 {
    ClientHelloV1 {
        client_nonce: Nonce32::new([0x11; 32]),
        supported_versions: vec![ProtocolVersion::new(1, 0)],
        client_id: ClientId::try_from("fixture-client").expect("fixture client ID is valid"),
        client_key_id: KeyId::try_from("fixture-client-key").expect("fixture key ID is valid"),
        requested_mode: RequestedMode::Required,
    }
}

#[allow(dead_code)]
pub(crate) fn server_identity() -> ServerIdentityV1 {
    ServerIdentityV1 {
        daemon_key_id: KeyId::try_from("fixture-daemon-key").expect("fixture key ID is valid"),
        boot_id: BootId::new([0x22; 32]),
        protocol: ProtocolVersion::new(1, 0),
        release_digest: Digest32::new([0x31; 32]),
        policy_digest: Digest32::new([0x32; 32]),
        policy_version: 7,
        model_manifest_digest: Digest32::new([0x33; 32]),
        approval_key_set_digest: Digest32::new([0x34; 32]),
        resource_profile_digest: Digest32::new([0x35; 32]),
    }
}

#[allow(dead_code)]
pub(crate) fn server_message() -> ServerMessageV1 {
    let transcript = HandshakeTranscriptV1 {
        client: client_hello(),
        server_nonce: Nonce32::new([0x44; 32]),
        server: server_identity(),
    };
    let canonical = minicbor::to_vec(&transcript).expect("fixed transcript encodes");
    let mut signature_input = b"SAVANA_DAEMON_HELLO_V1\0".to_vec();
    signature_input.extend_from_slice(&canonical);
    let signature = SigningKey::from_bytes(&[0x61; 32]).sign(&signature_input);
    ServerMessageV1::Hello(SignedServerHelloV1 {
        transcript,
        signature: Signature64::new(signature.to_bytes()),
    })
}

#[allow(dead_code)]
pub(crate) fn encoded_hello_with_versions(versions: &[ProtocolVersion]) -> Vec<u8> {
    let hello = client_hello();
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder.array(2).unwrap().u8(0).unwrap().array(5).unwrap();
    encoder
        .encode(hello.client_nonce)
        .unwrap()
        .array(versions.len() as u64)
        .unwrap();
    for version in versions {
        encoder.encode(version).unwrap();
    }
    encoder
        .encode(&hello.client_id)
        .unwrap()
        .encode(&hello.client_key_id)
        .unwrap()
        .encode(hello.requested_mode)
        .unwrap();
    encoder.into_writer()
}

#[allow(dead_code)]
pub(crate) fn rewrite_protocol_minor_as_non_shortest(mut encoded: Vec<u8>) -> Vec<u8> {
    let mut decoder = minicbor::Decoder::new(&encoded);
    assert_eq!(decoder.array().unwrap(), Some(2));
    assert_eq!(decoder.u8().unwrap(), 0);
    assert_eq!(decoder.array().unwrap(), Some(5));
    decoder.bytes().unwrap();
    assert_eq!(decoder.array().unwrap(), Some(1));
    assert_eq!(decoder.array().unwrap(), Some(2));
    assert_eq!(decoder.u16().unwrap(), 1);
    let minor_position = decoder.position();
    assert_eq!(decoder.u16().unwrap(), 0);
    assert_eq!(encoded[minor_position], 0);
    encoded.splice(minor_position..minor_position + 1, [0x18, 0x00]);
    encoded
}
