use ed25519_dalek::{Signature, SigningKey};
use savana_kernel_protocol::{
    encode_client_message, encode_server_message, AttemptKindV1, ClientMessageV1, ConstraintId,
    HardLimits, ResourceLimitsV1, StableCode, ToolName, ValidatorId, PROTOCOL_MAJOR,
    PROTOCOL_MINOR,
};

mod support;

type OneOverCase = (&'static str, fn(&mut ResourceLimitsV1));

fn compiled_request() -> ResourceLimitsV1 {
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
    }
}

#[test]
fn committed_handshake_vectors_match_the_v1_encoders() {
    let expected_client = include_bytes!("../../../vectors/kerneld/client-hello-v1.cbor");
    let client = encode_client_message(&ClientMessageV1::Hello(support::client_hello())).unwrap();
    assert_eq!(client.as_slice(), expected_client);

    let expected_server = include_bytes!("../../../vectors/kerneld/server-hello-v1.cbor");
    let server_message = support::server_message();
    let server = encode_server_message(&server_message).unwrap();
    assert_eq!(server.as_slice(), expected_server);

    let savana_kernel_protocol::ServerMessageV1::Hello(signed_hello) = server_message else {
        panic!("fixed server vector is a hello");
    };
    let transcript = minicbor::to_vec(&signed_hello.transcript).unwrap();
    let mut signature_input = b"SAVANA_DAEMON_HELLO_V1\0".to_vec();
    signature_input.extend_from_slice(&transcript);
    SigningKey::from_bytes(&[0x61; 32])
        .verifying_key()
        .verify_strict(
            &signature_input,
            &Signature::from_bytes(signed_hello.signature.as_bytes()),
        )
        .unwrap();
}

fn lowered_request() -> ResourceLimitsV1 {
    ResourceLimitsV1 {
        frame_bytes: 7_000_001,
        cbor_depth: 17,
        pages: 1_901,
        chars_per_page: 40_001,
        chars_per_document: 900_001,
        observations: 90_001,
        vault_entries: 19_001,
        vault_raw_bytes: 30_000_001,
        runs_per_client: 101,
        vaults_per_client: 401,
        approval_ledger_entries: 60_001,
        model_manifest_bytes: 200_001,
        model_assets: 23,
        model_tensor_contracts: 22,
        model_tensor_rank: 7,
        single_model_asset_bytes: 200_000_001,
        total_model_asset_bytes: 500_000_001,
        ner_workers: 3,
        ner_queue: 119,
        ner_text_bytes: 190_001,
        model_probes: 15,
        model_probe_spans: 500,
        ner_failure_threshold: 21,
        request_deadline_ms: 110_001,
    }
}

#[test]
fn v1_constants_are_frozen() {
    assert_eq!((PROTOCOL_MAJOR, PROTOCOL_MINOR), (1, 0));
    let limits = HardLimits::COMPILED;
    assert_eq!(limits.frame_bytes(), 8 * 1024 * 1024);
    assert_eq!(limits.cbor_depth(), 32);
    assert_eq!(limits.pages(), 2_048);
    assert_eq!(limits.chars_per_page(), 50_000);
    assert_eq!(limits.chars_per_document(), 1_000_000);
    assert_eq!(limits.observations(), 100_000);
    assert_eq!(limits.vault_entries(), 20_000);
    assert_eq!(limits.vault_raw_bytes(), 32 * 1024 * 1024);
    assert_eq!(limits.runs_per_client(), 128);
    assert_eq!(limits.vaults_per_client(), 512);
    assert_eq!(limits.approval_ledger_entries(), 65_536);
    assert_eq!(limits.model_manifest_bytes(), 256 * 1024);
    assert_eq!(limits.model_assets(), 32);
    assert_eq!(limits.model_tensor_contracts(), 32);
    assert_eq!(limits.model_tensor_rank(), 8);
    assert_eq!(limits.single_model_asset_bytes(), 256 * 1024 * 1024);
    assert_eq!(limits.total_model_asset_bytes(), 512 * 1024 * 1024);
    assert_eq!(limits.ner_workers(), 4);
    assert_eq!(limits.ner_queue(), 128);
    assert_eq!(limits.ner_text_bytes(), 200_000);
    assert_eq!(limits.model_probes(), 16);
    assert_eq!(limits.model_probe_spans(), 512);
    assert_eq!(limits.ner_failure_threshold(), 32);
    assert_eq!(limits.request_deadline_ms(), 120_000);
    assert_eq!(limits.policy_tools(), 256);
    assert_eq!(limits.policy_authorities(), 64);
    assert_eq!(limits.policy_error_mappings(), 256);
    assert_eq!(limits.policy_model_digests(), 32);
    assert_eq!(limits.policy_tool_name_set(), 256);
    assert_eq!(limits.policy_valid_pairs(), 1_536);
    assert_eq!(limits.policy_attempt_limits(), 6);
    assert_eq!(limits.policy_snapshot_authorities(), 16);
    assert_eq!(limits.policy_validator_requirements(), 256);
    assert_eq!(limits.policy_validators_per_tool(), 32);
    assert_eq!(limits.policy_constraints_per_tool(), 64);
    assert_eq!(limits.policy_release_targets(), 16);
}

#[test]
fn policy_identifier_and_attempt_primitives_are_closed() {
    assert_eq!(
        ToolName::try_from("tool-name").unwrap().as_str(),
        "tool-name"
    );
    assert_eq!(
        ValidatorId::try_from("validator-id").unwrap().as_str(),
        "validator-id"
    );
    assert_eq!(
        ConstraintId::try_from("constraint-id").unwrap().as_str(),
        "constraint-id"
    );
    for invalid in ["", "contains\0nul", &"x".repeat(129)] {
        assert_eq!(
            ToolName::try_from(invalid).unwrap_err().code(),
            StableCode::ProtocolMalformedCbor
        );
    }

    let attempts = [
        AttemptKindV1::Read,
        AttemptKindV1::Create,
        AttemptKindV1::Update,
        AttemptKindV1::Delete,
        AttemptKindV1::Send,
        AttemptKindV1::Execute,
    ];
    for (expected_tag, attempt) in (0_u8..).zip(attempts) {
        let encoded = minicbor::to_vec(attempt).unwrap();
        assert_eq!(encoded, [expected_tag]);
        assert_eq!(
            minicbor::decode::<AttemptKindV1>(&encoded).unwrap(),
            attempt
        );
    }
    assert!(minicbor::decode::<AttemptKindV1>(&[6]).is_err());
}

#[test]
fn stable_codes_are_wire_strings() {
    assert_eq!(
        StableCode::ProtocolFrameTooLarge.as_str(),
        "PROTOCOL_FRAME_TOO_LARGE"
    );
    assert_eq!(
        StableCode::IdentityInvalidSignature.as_str(),
        "IDENTITY_INVALID_SIGNATURE"
    );
    assert_eq!(StableCode::KernelUnavailable.as_str(), "KERNEL_UNAVAILABLE");
}

#[test]
fn resource_limit_decode_rejects_unknown_cbor_fields_with_stable_code() {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder.map(25).unwrap();
    for field in 0_u8..=24 {
        encoder.u8(field).unwrap().u8(1).unwrap();
    }

    let error = minicbor::decode::<ResourceLimitsV1>(&encoder.into_writer())
        .expect_err("unknown resource-limit field must be rejected");
    assert!(error
        .to_string()
        .contains(StableCode::ProtocolUnknownField.as_str()));
}

#[test]
fn resource_limit_decode_rejects_duplicate_and_missing_fields() {
    let mut duplicate = minicbor::Encoder::new(Vec::new());
    duplicate.map(24).unwrap();
    for field in 0_u8..=22 {
        duplicate.u8(field).unwrap().u8(1).unwrap();
    }
    duplicate.u8(0).unwrap().u8(1).unwrap();
    let duplicate_error = minicbor::decode::<ResourceLimitsV1>(&duplicate.into_writer())
        .expect_err("duplicate resource-limit field must be rejected");
    assert!(duplicate_error
        .to_string()
        .contains(StableCode::ProtocolMalformedCbor.as_str()));

    let mut missing = minicbor::Encoder::new(Vec::new());
    missing.map(23).unwrap();
    for field in 0_u8..=22 {
        missing.u8(field).unwrap().u8(1).unwrap();
    }
    let missing_error = minicbor::decode::<ResourceLimitsV1>(&missing.into_writer())
        .expect_err("missing resource-limit field must be rejected");
    assert!(missing_error
        .to_string()
        .contains(StableCode::ProtocolMalformedCbor.as_str()));
}

#[test]
fn lowered_limits_preserve_every_requested_value() {
    let requested = lowered_request();
    let effective = HardLimits::COMPILED.lower(&requested).unwrap();

    assert_eq!(effective.frame_bytes(), requested.frame_bytes);
    assert_eq!(effective.cbor_depth(), requested.cbor_depth);
    assert_eq!(effective.pages(), requested.pages);
    assert_eq!(effective.chars_per_page(), requested.chars_per_page);
    assert_eq!(effective.chars_per_document(), requested.chars_per_document);
    assert_eq!(effective.observations(), requested.observations);
    assert_eq!(effective.vault_entries(), requested.vault_entries);
    assert_eq!(effective.vault_raw_bytes(), requested.vault_raw_bytes);
    assert_eq!(effective.runs_per_client(), requested.runs_per_client);
    assert_eq!(effective.vaults_per_client(), requested.vaults_per_client);
    assert_eq!(
        effective.approval_ledger_entries(),
        requested.approval_ledger_entries
    );
    assert_eq!(
        effective.model_manifest_bytes(),
        requested.model_manifest_bytes
    );
    assert_eq!(effective.model_assets(), requested.model_assets);
    assert_eq!(
        effective.model_tensor_contracts(),
        requested.model_tensor_contracts
    );
    assert_eq!(effective.model_tensor_rank(), requested.model_tensor_rank);
    assert_eq!(
        effective.single_model_asset_bytes(),
        requested.single_model_asset_bytes
    );
    assert_eq!(
        effective.total_model_asset_bytes(),
        requested.total_model_asset_bytes
    );
    assert_eq!(effective.ner_workers(), requested.ner_workers);
    assert_eq!(effective.ner_queue(), requested.ner_queue);
    assert_eq!(effective.ner_text_bytes(), requested.ner_text_bytes);
    assert_eq!(effective.model_probes(), requested.model_probes);
    assert_eq!(effective.model_probe_spans(), requested.model_probe_spans);
    assert_eq!(
        effective.ner_failure_threshold(),
        requested.ner_failure_threshold
    );
    assert_eq!(
        effective.request_deadline_ms(),
        requested.request_deadline_ms
    );
}

#[test]
fn every_one_over_compiled_limit_is_rejected() {
    let cases: [OneOverCase; 24] = [
        ("frame_bytes", |requested| requested.frame_bytes += 1),
        ("cbor_depth", |requested| requested.cbor_depth += 1),
        ("pages", |requested| requested.pages += 1),
        ("chars_per_page", |requested| requested.chars_per_page += 1),
        ("chars_per_document", |requested| {
            requested.chars_per_document += 1
        }),
        ("observations", |requested| requested.observations += 1),
        ("vault_entries", |requested| requested.vault_entries += 1),
        ("vault_raw_bytes", |requested| {
            requested.vault_raw_bytes += 1
        }),
        ("runs_per_client", |requested| {
            requested.runs_per_client += 1
        }),
        ("vaults_per_client", |requested| {
            requested.vaults_per_client += 1
        }),
        ("approval_ledger_entries", |requested| {
            requested.approval_ledger_entries += 1
        }),
        ("model_manifest_bytes", |requested| {
            requested.model_manifest_bytes += 1
        }),
        ("model_assets", |requested| requested.model_assets += 1),
        ("model_tensor_contracts", |requested| {
            requested.model_tensor_contracts += 1
        }),
        ("model_tensor_rank", |requested| {
            requested.model_tensor_rank += 1
        }),
        ("single_model_asset_bytes", |requested| {
            requested.single_model_asset_bytes += 1
        }),
        ("total_model_asset_bytes", |requested| {
            requested.total_model_asset_bytes += 1
        }),
        ("ner_workers", |requested| requested.ner_workers += 1),
        ("ner_queue", |requested| requested.ner_queue += 1),
        ("ner_text_bytes", |requested| requested.ner_text_bytes += 1),
        ("model_probes", |requested| requested.model_probes += 1),
        ("model_probe_spans", |requested| {
            requested.model_probe_spans += 1
        }),
        ("ner_failure_threshold", |requested| {
            requested.ner_failure_threshold += 1
        }),
        ("request_deadline_ms", |requested| {
            requested.request_deadline_ms += 1
        }),
    ];

    for (field, raise_one) in cases {
        let mut requested = compiled_request();
        raise_one(&mut requested);
        let error = HardLimits::COMPILED.lower(&requested).unwrap_err();
        assert_eq!(
            error.code(),
            StableCode::PolicyLimitExceeded,
            "{field} must reject one-over-cap requests"
        );
    }
}
