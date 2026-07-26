#![allow(dead_code)]

use ed25519_dalek::{Signer, SigningKey};
use savana_kernel_protocol::{
    BootId, ClientHelloV1, ClientId, ConversationId, Digest32, EffectiveLimits,
    HandshakeTranscriptV1, HardLimits, IngressEnvelopeV1, KeyId, Nonce32, PrincipalId,
    ProtocolVersion, RegistrySnapshotV1, RequestedMode, ResourceLimitsV1, RoleId, RunHandle,
    ServerIdentityV1, ServerMessageV1, Signature64, SignedIngressEnvelopeV1,
    SignedRegistrySnapshotV1, SignedServerHelloV1, UnixMillis,
};

pub(crate) fn decode_hex(input: &str) -> Vec<u8> {
    assert_eq!(input.len() % 2, 0);
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).unwrap();
            u8::from_str_radix(pair, 16).unwrap()
        })
        .collect()
}

pub(crate) fn digest32_from_hex(input: &str) -> Digest32 {
    Digest32::new(decode_hex(input).try_into().unwrap())
}

pub(crate) fn run_handle_with_byte(byte: u8) -> RunHandle {
    let mut encoded = Vec::with_capacity(34);
    encoded.extend_from_slice(&[0x58, 0x20]);
    encoded.extend_from_slice(&[byte; 32]);
    minicbor::decode(&encoded).unwrap()
}

pub(crate) fn signed_ingress() -> SignedIngressEnvelopeV1 {
    SignedIngressEnvelopeV1 {
        unsigned: IngressEnvelopeV1 {
            principal: PrincipalId::try_from("principal-1").unwrap(),
            conversation_id: ConversationId::try_from("conversation-1").unwrap(),
            request_digest: Digest32::new([0x21; 32]),
            issued_at: UnixMillis::new(1_000),
            expires_at: UnixMillis::new(3_000),
            nonce: Nonce32::new([0x22; 32]),
            authority_session_id: Nonce32::new([0x23; 32]),
            authentication_context_digest: Digest32::new([0x24; 32]),
            role: RoleId::try_from("operator").unwrap(),
            policy_digest: Digest32::new([0x25; 32]),
            boot_id: BootId::new([0x26; 32]),
            connection_binding_digest: Digest32::new([0x27; 32]),
        },
        key_id: KeyId::try_from("ingress-key").unwrap(),
        signature: Signature64::new([0x28; 64]),
    }
}

pub(crate) fn signed_registry() -> SignedRegistrySnapshotV1 {
    SignedRegistrySnapshotV1 {
        unsigned: RegistrySnapshotV1 {
            version: 1,
            previous_digest: None,
            tools: Vec::new(),
            issued_at: UnixMillis::new(1_000),
            expires_at: UnixMillis::new(3_000),
        },
        key_id: KeyId::try_from("registry-key").unwrap(),
        signature: Signature64::new([0x29; 64]),
    }
}

pub(crate) fn legacy_eight_item_ingress_bytes() -> Vec<u8> {
    let ingress = signed_ingress().unsigned;
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(8)
        .unwrap()
        .encode(ingress.principal)
        .unwrap()
        .encode(ingress.conversation_id)
        .unwrap()
        .encode(ingress.request_digest)
        .unwrap()
        .encode(ingress.issued_at)
        .unwrap()
        .encode(ingress.expires_at)
        .unwrap()
        .encode(ingress.nonce)
        .unwrap()
        .encode(ingress.authority_session_id)
        .unwrap()
        .encode(ingress.authentication_context_digest)
        .unwrap();
    encoder.into_writer()
}

pub(crate) fn thirteen_item_ingress_bytes() -> Vec<u8> {
    let ingress = signed_ingress().unsigned;
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(13)
        .unwrap()
        .encode(ingress.principal)
        .unwrap()
        .encode(ingress.conversation_id)
        .unwrap()
        .encode(ingress.request_digest)
        .unwrap()
        .encode(ingress.issued_at)
        .unwrap()
        .encode(ingress.expires_at)
        .unwrap()
        .encode(ingress.nonce)
        .unwrap()
        .encode(ingress.authority_session_id)
        .unwrap()
        .encode(ingress.authentication_context_digest)
        .unwrap()
        .encode(ingress.role)
        .unwrap()
        .encode(ingress.policy_digest)
        .unwrap()
        .encode(ingress.boot_id)
        .unwrap()
        .encode(ingress.connection_binding_digest)
        .unwrap()
        .null()
        .unwrap();
    encoder.into_writer()
}

pub(crate) fn legacy_begin_with_role_text_bytes() -> Vec<u8> {
    let ingress = signed_ingress();
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(3)
        .unwrap()
        .encode(ingress)
        .unwrap()
        .encode(RoleId::try_from("operator").unwrap())
        .unwrap()
        .encode(signed_registry())
        .unwrap();
    encoder.into_writer()
}

pub(crate) fn legacy_two_item_ingest_bytes() -> Vec<u8> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(2)
        .unwrap()
        .encode(run_handle_with_byte(0x70))
        .unwrap()
        .encode(signed_ingress())
        .unwrap();
    encoder.into_writer()
}

#[allow(dead_code)]
pub(crate) fn compiled_request() -> ResourceLimitsV1 {
    let limits = HardLimits::COMPILED;
    ResourceLimitsV1 {
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
        ingress_replay_entries_per_client: limits.ingress_replay_entries_per_client(),
    }
}

#[allow(dead_code)]
pub(crate) fn compiled_effective_limits() -> EffectiveLimits {
    HardLimits::COMPILED
        .lower(&compiled_request())
        .expect("compiled limits lower to themselves")
}

pub(crate) fn resource_limit_map_keys(encoded: &[u8]) -> Vec<u64> {
    let mut decoder = minicbor::Decoder::new(encoded);
    let entries = decoder
        .map()
        .unwrap()
        .expect("resource limits use a definite map");
    let mut keys = Vec::with_capacity(entries.try_into().unwrap());
    for _ in 0..entries {
        keys.push(decoder.u64().unwrap());
        decoder.u64().unwrap();
    }
    assert_eq!(decoder.position(), encoded.len());
    keys
}

pub(crate) fn resource_limits_without_key_24(encoded: &[u8]) -> Vec<u8> {
    let mut decoder = minicbor::Decoder::new(encoded);
    let entries = decoder
        .map()
        .unwrap()
        .expect("resource limits use a definite map");
    let mut pairs = Vec::with_capacity(entries.try_into().unwrap());
    let mut found_key_24 = false;
    for _ in 0..entries {
        let key = decoder.u64().unwrap();
        let value = decoder.u64().unwrap();
        found_key_24 |= key == 24;
        if key != 24 {
            pairs.push((key, value));
        }
    }
    assert_eq!(decoder.position(), encoded.len());
    assert!(found_key_24);
    assert_eq!(pairs.len() as u64, entries - 1);

    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder.map(entries - 1).unwrap();
    for (key, value) in pairs {
        encoder.u64(key).unwrap().u64(value).unwrap();
    }
    encoder.into_writer()
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

pub(crate) fn handshake_transcript() -> HandshakeTranscriptV1 {
    let message = server_message();
    assert_eq!(
        minicbor::to_vec(&message).unwrap().as_slice(),
        include_bytes!("../../../../vectors/kerneld/server-hello-v1.cbor")
    );
    match message {
        ServerMessageV1::Hello(hello) => hello.transcript,
        _ => unreachable!("server_message fixture is the committed hello"),
    }
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
