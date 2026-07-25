#![allow(dead_code)]

use ed25519_dalek::{Signer, SigningKey};
use savana_kernel_protocol::{
    Digest32, HardLimits, KeyId, ResourceLimitsV1, Signature64, StableCode, UnixMillis,
};
use savana_policy_core::{PolicyTrustRootV1, PolicyVerifier};

pub const POLICY_DOMAIN: &[u8] = b"SAVANA_POLICY_V1\0";
pub const RELEASE_DOMAIN: &[u8] = b"SAVANA_RELEASE_V1\0";
pub const NOW: u64 = 2_000;

#[derive(Clone)]
pub struct ProtocolRange {
    pub major: u16,
    pub minimum_minor: u16,
    pub maximum_minor: u16,
}

#[derive(Clone)]
pub struct Dataflow {
    pub no_side_effect_tools: Vec<String>,
    pub consent_overridable_tools: Vec<String>,
    pub high_risk_tools: Vec<String>,
}

#[derive(Clone)]
pub struct ToolAttempt {
    pub tool: String,
    pub attempt: u8,
}

#[derive(Clone)]
pub struct AttemptLimit {
    pub attempt: u8,
    pub maximum_per_run: u32,
}

#[derive(Clone)]
pub struct Attempts {
    pub valid_pairs: Vec<ToolAttempt>,
    pub limits: Vec<AttemptLimit>,
    pub cloud_blocked: Vec<u8>,
}

#[derive(Clone)]
pub struct Ontology {
    pub snapshot_authority_key_ids: Vec<String>,
    pub max_snapshot_entries: u32,
    pub max_constraints_per_tool: u16,
}

#[derive(Clone)]
pub struct ValidatorRequirement {
    pub tool: String,
    pub validator_ids: Vec<String>,
}

#[derive(Clone)]
pub struct Sink {
    pub validator_requirements: Vec<ValidatorRequirement>,
    pub deny_on_missing_attestation: bool,
}

#[derive(Clone)]
pub struct Release {
    pub challenge_ttl_seconds: u32,
    pub receipt_ttl_seconds: u32,
    pub require_authenticated_user_assertion: bool,
    pub consume_vault_on_success: bool,
    pub compatible_release_target_ids: Vec<[u8; 32]>,
}

#[derive(Clone)]
pub struct Tool {
    pub name: String,
    pub descriptor_digest: [u8; 32],
    pub attempt: u8,
    pub constraint_ids: Vec<String>,
    pub validator_ids: Vec<String>,
}

#[derive(Clone)]
pub struct Authority {
    pub key_id: String,
    pub role: u8,
    pub public_key: [u8; 32],
    pub epoch: u64,
    pub not_before: u64,
    pub not_after: u64,
    pub revoked: bool,
}

#[derive(Clone)]
pub struct ErrorMapping {
    pub policy_reason_tag: u16,
    pub stable_code: StableCode,
}

#[derive(Clone)]
pub struct TestPolicy {
    pub schema_version: u16,
    pub protocol: ProtocolRange,
    pub policy_version: u64,
    pub key_epoch: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub signing_key_id: String,
    pub dataflow: Dataflow,
    pub attempts: Attempts,
    pub ontology: Ontology,
    pub sink: Sink,
    pub release: Release,
    pub tools: Vec<Tool>,
    pub authorities: Vec<Authority>,
    pub resources: ResourceLimitsV1,
    pub accepted_model_manifest_digests: Vec<[u8; 32]>,
    pub error_map: Vec<ErrorMapping>,
}

pub fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[0x42; 32])
}

pub fn alternate_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[0x43; 32])
}

pub fn active_target() -> Digest32 {
    Digest32::new([0xa0; 32])
}

pub fn trust_root(key_id: &str, key: &SigningKey, epoch: u64, revoked: bool) -> PolicyTrustRootV1 {
    PolicyTrustRootV1 {
        key_id: KeyId::try_from(key_id).expect("fixture key ID"),
        public_key: key.verifying_key().to_bytes(),
        epoch,
        revoked,
    }
}

pub fn verifier() -> PolicyVerifier {
    PolicyVerifier::new(
        vec![trust_root("policy-root", &signing_key(), 3, false)],
        active_target(),
    )
    .expect("valid fixture verifier")
}

pub fn verifier_with_roots(roots: Vec<PolicyTrustRootV1>) -> PolicyVerifier {
    PolicyVerifier::new(roots, active_target()).expect("valid fixture verifier")
}

pub fn valid_policy(policy_version: u64, key_epoch: u64) -> TestPolicy {
    let authorities = (0_u8..8)
        .map(|role| Authority {
            key_id: format!("role-0{role}"),
            role,
            public_key: [role + 1; 32],
            epoch: 1,
            not_before: 900,
            not_after: 4_100,
            revoked: false,
        })
        .collect();
    TestPolicy {
        schema_version: 1,
        protocol: ProtocolRange {
            major: 1,
            minimum_minor: 0,
            maximum_minor: 0,
        },
        policy_version,
        key_epoch,
        issued_at: 1_000,
        expires_at: 4_000,
        signing_key_id: "policy-root".to_owned(),
        dataflow: Dataflow {
            no_side_effect_tools: vec!["tool-00".to_owned()],
            consent_overridable_tools: vec!["tool-01".to_owned()],
            high_risk_tools: vec!["tool-01".to_owned()],
        },
        attempts: Attempts {
            valid_pairs: vec![
                ToolAttempt {
                    tool: "tool-00".to_owned(),
                    attempt: 0,
                },
                ToolAttempt {
                    tool: "tool-01".to_owned(),
                    attempt: 4,
                },
            ],
            limits: vec![
                AttemptLimit {
                    attempt: 0,
                    maximum_per_run: 5,
                },
                AttemptLimit {
                    attempt: 4,
                    maximum_per_run: 2,
                },
            ],
            cloud_blocked: vec![3, 4],
        },
        ontology: Ontology {
            snapshot_authority_key_ids: vec!["role-03".to_owned()],
            max_snapshot_entries: 50_000,
            max_constraints_per_tool: 32,
        },
        sink: Sink {
            validator_requirements: vec![ValidatorRequirement {
                tool: "tool-01".to_owned(),
                validator_ids: vec!["role-04".to_owned()],
            }],
            deny_on_missing_attestation: true,
        },
        release: Release {
            challenge_ttl_seconds: 60,
            receipt_ttl_seconds: 60,
            require_authenticated_user_assertion: true,
            consume_vault_on_success: true,
            compatible_release_target_ids: vec![[0xa0; 32]],
        },
        tools: vec![
            Tool {
                name: "tool-00".to_owned(),
                descriptor_digest: [0x21; 32],
                attempt: 0,
                constraint_ids: vec!["constraint-00".to_owned()],
                validator_ids: Vec::new(),
            },
            Tool {
                name: "tool-01".to_owned(),
                descriptor_digest: [0x22; 32],
                attempt: 4,
                constraint_ids: vec!["constraint-01".to_owned()],
                validator_ids: vec!["role-04".to_owned()],
            },
        ],
        authorities,
        resources: compiled_resources(),
        accepted_model_manifest_digests: vec![[0xb0; 32]],
        error_map: vec![
            ErrorMapping {
                policy_reason_tag: 1,
                stable_code: StableCode::KernelUnavailable,
            },
            ErrorMapping {
                policy_reason_tag: 2,
                stable_code: StableCode::KernelUnavailable,
            },
        ],
    }
}

pub fn compiled_resources() -> ResourceLimitsV1 {
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

pub fn encode_policy(policy: &TestPolicy) -> Vec<u8> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(17)
        .unwrap()
        .u16(policy.schema_version)
        .unwrap();
    encode_protocol(&mut encoder, &policy.protocol);
    encoder
        .u64(policy.policy_version)
        .unwrap()
        .u64(policy.key_epoch)
        .unwrap()
        .u64(policy.issued_at)
        .unwrap()
        .u64(policy.expires_at)
        .unwrap()
        .str(&policy.signing_key_id)
        .unwrap();
    encode_dataflow(&mut encoder, &policy.dataflow);
    encode_attempts(&mut encoder, &policy.attempts);
    encode_ontology(&mut encoder, &policy.ontology);
    encode_sink(&mut encoder, &policy.sink);
    encode_release(&mut encoder, &policy.release);
    encode_tools(&mut encoder, &policy.tools);
    encode_authorities(&mut encoder, &policy.authorities);
    encoder.encode(policy.resources).unwrap();
    encode_digests(&mut encoder, &policy.accepted_model_manifest_digests);
    encoder.array(policy.error_map.len() as u64).unwrap();
    for mapping in &policy.error_map {
        encoder
            .array(2)
            .unwrap()
            .u16(mapping.policy_reason_tag)
            .unwrap()
            .encode(mapping.stable_code)
            .unwrap();
    }
    encoder.into_writer()
}

pub fn signed(policy: &TestPolicy) -> (Vec<u8>, Signature64) {
    signed_with_domain(policy, POLICY_DOMAIN, &signing_key())
}

pub fn signed_with_key(policy: &TestPolicy, key: &SigningKey) -> (Vec<u8>, Signature64) {
    signed_with_domain(policy, POLICY_DOMAIN, key)
}

pub fn signed_with_domain(
    policy: &TestPolicy,
    domain: &[u8],
    key: &SigningKey,
) -> (Vec<u8>, Signature64) {
    let bytes = encode_policy(policy);
    let signature = detached_signature(domain, &bytes, key);
    (bytes, signature)
}

pub fn detached_signature(domain: &[u8], bytes: &[u8], key: &SigningKey) -> Signature64 {
    let mut message = Vec::with_capacity(domain.len() + bytes.len());
    message.extend_from_slice(domain);
    message.extend_from_slice(bytes);
    Signature64::new(key.sign(&message).to_bytes())
}

pub fn unix_now() -> UnixMillis {
    UnixMillis::new(NOW)
}

pub fn encode_ledger(version: u64, epoch: u64, digest: [u8; 32]) -> Vec<u8> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(4)
        .unwrap()
        .u16(1)
        .unwrap()
        .u64(version)
        .unwrap()
        .u64(epoch)
        .unwrap()
        .bytes(&digest)
        .unwrap();
    encoder.into_writer()
}

fn encode_protocol(encoder: &mut minicbor::Encoder<Vec<u8>>, value: &ProtocolRange) {
    encoder
        .array(3)
        .unwrap()
        .u16(value.major)
        .unwrap()
        .u16(value.minimum_minor)
        .unwrap()
        .u16(value.maximum_minor)
        .unwrap();
}

fn encode_string_array(encoder: &mut minicbor::Encoder<Vec<u8>>, values: &[String]) {
    encoder.array(values.len() as u64).unwrap();
    for value in values {
        encoder.str(value).unwrap();
    }
}

fn encode_dataflow(encoder: &mut minicbor::Encoder<Vec<u8>>, value: &Dataflow) {
    encoder.array(3).unwrap();
    encode_string_array(encoder, &value.no_side_effect_tools);
    encode_string_array(encoder, &value.consent_overridable_tools);
    encode_string_array(encoder, &value.high_risk_tools);
}

fn encode_attempts(encoder: &mut minicbor::Encoder<Vec<u8>>, value: &Attempts) {
    encoder
        .array(3)
        .unwrap()
        .array(value.valid_pairs.len() as u64)
        .unwrap();
    for pair in &value.valid_pairs {
        encoder
            .array(2)
            .unwrap()
            .str(&pair.tool)
            .unwrap()
            .u8(pair.attempt)
            .unwrap();
    }
    encoder.array(value.limits.len() as u64).unwrap();
    for limit in &value.limits {
        encoder
            .array(2)
            .unwrap()
            .u8(limit.attempt)
            .unwrap()
            .u32(limit.maximum_per_run)
            .unwrap();
    }
    encoder.array(value.cloud_blocked.len() as u64).unwrap();
    for attempt in &value.cloud_blocked {
        encoder.u8(*attempt).unwrap();
    }
}

fn encode_ontology(encoder: &mut minicbor::Encoder<Vec<u8>>, value: &Ontology) {
    encoder.array(3).unwrap();
    encode_string_array(encoder, &value.snapshot_authority_key_ids);
    encoder
        .u32(value.max_snapshot_entries)
        .unwrap()
        .u16(value.max_constraints_per_tool)
        .unwrap();
}

fn encode_sink(encoder: &mut minicbor::Encoder<Vec<u8>>, value: &Sink) {
    encoder
        .array(2)
        .unwrap()
        .array(value.validator_requirements.len() as u64)
        .unwrap();
    for requirement in &value.validator_requirements {
        encoder.array(2).unwrap().str(&requirement.tool).unwrap();
        encode_string_array(encoder, &requirement.validator_ids);
    }
    encoder.bool(value.deny_on_missing_attestation).unwrap();
}

fn encode_release(encoder: &mut minicbor::Encoder<Vec<u8>>, value: &Release) {
    encoder
        .array(5)
        .unwrap()
        .u32(value.challenge_ttl_seconds)
        .unwrap()
        .u32(value.receipt_ttl_seconds)
        .unwrap()
        .bool(value.require_authenticated_user_assertion)
        .unwrap()
        .bool(value.consume_vault_on_success)
        .unwrap();
    encode_digests(encoder, &value.compatible_release_target_ids);
}

fn encode_tools(encoder: &mut minicbor::Encoder<Vec<u8>>, values: &[Tool]) {
    encoder.array(values.len() as u64).unwrap();
    for tool in values {
        encoder
            .array(5)
            .unwrap()
            .str(&tool.name)
            .unwrap()
            .bytes(&tool.descriptor_digest)
            .unwrap()
            .u8(tool.attempt)
            .unwrap();
        encode_string_array(encoder, &tool.constraint_ids);
        encode_string_array(encoder, &tool.validator_ids);
    }
}

fn encode_authorities(encoder: &mut minicbor::Encoder<Vec<u8>>, values: &[Authority]) {
    encoder.array(values.len() as u64).unwrap();
    for authority in values {
        encoder
            .array(7)
            .unwrap()
            .str(&authority.key_id)
            .unwrap()
            .u8(authority.role)
            .unwrap()
            .bytes(&authority.public_key)
            .unwrap()
            .u64(authority.epoch)
            .unwrap()
            .u64(authority.not_before)
            .unwrap()
            .u64(authority.not_after)
            .unwrap()
            .bool(authority.revoked)
            .unwrap();
    }
}

fn encode_digests(encoder: &mut minicbor::Encoder<Vec<u8>>, values: &[[u8; 32]]) {
    encoder.array(values.len() as u64).unwrap();
    for digest in values {
        encoder.bytes(digest).unwrap();
    }
}
