use std::cmp::Ordering;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use savana_kernel_protocol::{
    ApprovalChallengeV1, ApprovalPurposeV1, ApprovalSubjectV1, ArtifactId, BootId, BoundedText,
    Digest32, HardLimits, KernelValue, KeyId, MaskedDisplayBundleV1, Nonce32, PrincipalId,
    ProtocolVersion, RunId, ServerIdentityV1, Signature64, SignedApprovalEnvelopeV1, StableCode,
    TaskId, ToolExecutionIdentity, ToolName, UnixMillis, UnsignedApprovalEnvelopeV1,
};
use savana_policy_core::{PolicyVerifier, ReleaseTrustRootV1, ReleaseVerifier};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

#[path = "support/mod.rs"]
mod policy_support;

const RELEASE_DOMAIN: &[u8] = b"SAVANA_RELEASE_V1\0";
const RELEASE_TARGET_DOMAIN: &[u8] = b"SAVANA_RELEASE_TARGET_V1\0";
const APPROVAL_ENVELOPE_DOMAIN: &[u8] = b"SAVANA_APPROVAL_ENVELOPE_V1\0";
const APPROVAL_RECEIPT_DOMAIN: &[u8] = b"SAVANA_APPROVAL_RECEIPT_V1\0";
const APPROVAL_DISPLAY_DOMAIN: &[u8] = b"SAVANA_APPROVAL_DISPLAY_V1\0";
const NOW: u64 = 2_000;

type ManifestMutation = Box<dyn Fn(&mut TestManifest)>;
type ManifestCase = (&'static str, ManifestMutation);
type CodedManifestCase = (&'static str, StableCode, ManifestMutation);
type ProfileMutation = Box<dyn Fn(&mut TestProfile)>;
type ProfileCase = (&'static str, ProfileMutation);

#[derive(Clone)]
struct TestPublicKey {
    key_id: String,
    public_key: [u8; 32],
}

#[derive(Clone)]
struct TestClient {
    client_id: String,
    key_id: String,
    public_key: Vec<u8>,
    role: u8,
    peer_uid: u32,
    peer_gid: u32,
}

#[derive(Clone)]
struct TestPolicyRoot {
    key_id: String,
    public_key: Vec<u8>,
    epoch: u64,
    revoked: bool,
}

#[derive(Clone)]
struct TestProfile {
    schema_version: u16,
    installation_id: [u8; 32],
    platform: u8,
    daemon_identity: TestPublicKey,
    daemon_clients: Vec<TestClient>,
    policy_trust_roots: Vec<TestPolicyRoot>,
    daemon_uid: u32,
    daemon_gid: u32,
    jarvis_uid: u32,
    socket_path: String,
    selected_policy_path: String,
    selected_policy_signature_path: String,
    socket_parent_mode: u16,
    socket_mode: u16,
}

#[derive(Clone)]
struct TestReleaseFile {
    relative_path: String,
    byte_length: u64,
    sha256: [u8; 32],
}

#[derive(Clone)]
struct TestManifest {
    schema_version: u16,
    release_version: String,
    release_sequence: u64,
    release_target_id: [u8; 32],
    source_commit: String,
    signing_key_id: String,
    binary_sha256: [u8; 32],
    cargo_lock_sha256: [u8; 32],
    rust_toolchain_sha256: [u8; 32],
    protocol_major: u16,
    minimum_minor: u16,
    maximum_minor: u16,
    supported_policy_schemas: Vec<u16>,
    supported_model_schemas: Vec<u16>,
    policy_trust_roots_digest: [u8; 32],
    minimum_policy_version: u64,
    model_manifest_digest: [u8; 32],
    producer_registry_digest: [u8; 32],
    ontology_digest: [u8; 32],
    approval_key_set_digest: [u8; 32],
    resource_profile_digest: [u8; 32],
    installation_profile_digest: [u8; 32],
    payloads: Vec<TestReleaseFile>,
    issued_at: u64,
    expires_at: u64,
}

struct ReleaseFixture {
    _stage: TempDir,
    manifest_value: TestManifest,
    manifest_bytes: Vec<u8>,
    manifest_path: PathBuf,
    signature_bytes: Signature64,
    signature_path: PathBuf,
    binary: PathBuf,
    release_key: SigningKey,
}

impl ReleaseFixture {
    fn verifier(&self) -> ReleaseVerifier {
        ReleaseVerifier::new(
            vec![self.release_root(false, 500, 5_000)],
            vec![sha256(&self.manifest_bytes)],
        )
        .expect("valid release verifier fixture")
    }

    fn release_root(&self, revoked: bool, not_before: u64, not_after: u64) -> ReleaseTrustRootV1 {
        ReleaseTrustRootV1 {
            key_id: KeyId::try_from("release-root").unwrap(),
            public_key: self.release_key.verifying_key().to_bytes(),
            not_before: UnixMillis::new(not_before),
            not_after: UnixMillis::new(not_after),
            revoked,
        }
    }

    fn verify(&self) -> Result<savana_policy_core::VerifiedReleaseIdentity, StableCode> {
        self.verifier()
            .verify_installed(
                &self.manifest_path,
                &self.signature_path,
                &self.binary,
                UnixMillis::new(NOW),
            )
            .map_err(|error| error.code())
    }

    fn stage_root(&self) -> &Path {
        self._stage.path()
    }

    fn replace_signed_manifest(&mut self, bytes: Vec<u8>, signing_key: &SigningKey) {
        self.signature_bytes = detached_signature(RELEASE_DOMAIN, &bytes, signing_key);
        self.manifest_bytes = bytes;
        fs::write(&self.manifest_path, &self.manifest_bytes).unwrap();
        fs::write(&self.signature_path, self.signature_bytes.as_bytes()).unwrap();
    }
}

#[test]
fn committed_release_vector_and_signature_match_the_v1_fixture() {
    let fixture = release_fixture(default_profile(), |_| {}, |_| {});
    assert_eq!(
        fixture.manifest_bytes.as_slice(),
        include_bytes!("../../../vectors/kerneld/release-manifest-v1.cbor")
    );
    assert_eq!(
        fixture.signature_bytes.as_bytes(),
        include_bytes!("../../../vectors/kerneld/release-manifest-v1.sig")
    );
}

#[test]
fn installed_binary_must_match_signed_and_pinned_manifest() {
    let fixture = release_fixture(default_profile(), |_| {}, |_| {});
    let verified = fixture.verify().unwrap();
    assert_eq!(
        verified.binary_digest(),
        Digest32::new(fixture.manifest_value.binary_sha256)
    );
    assert_eq!(verified.release_digest(), sha256(&fixture.manifest_bytes));
    assert_eq!(
        verified.release_target_id(),
        Digest32::new(fixture.manifest_value.release_target_id)
    );
    assert_eq!(
        verified.installation_profile_digest(),
        Digest32::new(fixture.manifest_value.installation_profile_digest)
    );

    fs::write(&fixture.binary, b"changed").unwrap();
    assert_eq!(
        fixture.verify().unwrap_err(),
        StableCode::IdentityReleaseMismatch
    );
}

fn signed_approval_envelope(
    release: &savana_policy_core::VerifiedReleaseIdentity,
    policy: &savana_policy_core::VerifiedPolicyV1,
    domain: &[u8],
) -> Vec<u8> {
    let display = MaskedDisplayBundleV1 {
        purpose_label: BoundedText::try_from("final release").unwrap(),
        tool_label: BoundedText::try_from("download").unwrap(),
        masked_destination: KernelValue::Null,
        masked_output: KernelValue::Text(BoundedText::try_from("masked").unwrap()),
    };
    let display_digest = {
        let canonical = minicbor::to_vec(&display).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(APPROVAL_DISPLAY_DOMAIN);
        hasher.update(canonical);
        Digest32::new(hasher.finalize().into())
    };
    let unsigned = UnsignedApprovalEnvelopeV1 {
        daemon_identity: ServerIdentityV1 {
            daemon_key_id: KeyId::try_from("daemon-key").unwrap(),
            boot_id: BootId::new([0x91; 32]),
            protocol: ProtocolVersion::new(1, 0),
            release_digest: release.release_digest(),
            policy_digest: policy.identity().digest,
            policy_version: policy.identity().policy_version,
            model_manifest_digest: release.model_manifest_digest(),
            approval_key_set_digest: release.approval_key_set_digest(),
            resource_profile_digest: policy.resource_profile_digest(),
        },
        challenge: ApprovalChallengeV1 {
            challenge_id: Nonce32::new([0x93; 32]),
            purpose: ApprovalPurposeV1::FinalRelease,
            subject: ApprovalSubjectV1::VaultRelease {
                vault_session_id: Nonce32::new([0x94; 32]),
                evidence_digest: Digest32::new([0x95; 32]),
                masked_output_digest: Digest32::new([0x96; 32]),
                token_set_digest: Digest32::new([0x97; 32]),
                artifact_id: ArtifactId::try_from("artifact-1").unwrap(),
                artifact_generation: 1,
            },
            boot_id: BootId::new([0x91; 32]),
            run_id: RunId::new([0x98; 32]),
            principal: PrincipalId::try_from("principal-1").unwrap(),
            conversation_id: "conversation-1".try_into().unwrap(),
            task_id: TaskId::try_from("task-1").unwrap(),
            tool: ToolExecutionIdentity {
                name: ToolName::try_from("final-release").unwrap(),
                descriptor_digest: Digest32::new([0x99; 32]),
                registry_version: 1,
            },
            destination_digest: Digest32::new([0x9a; 32]),
            policy_version: policy.identity().policy_version,
            issued_at: UnixMillis::new(1_000),
            expires_at: UnixMillis::new(3_000),
            nonce: Nonce32::new([0x9b; 32]),
        },
        display,
        display_digest,
    };
    let payload = minicbor::to_vec(&unsigned).unwrap();
    let signature = detached_signature(domain, &payload, &SigningKey::from_bytes(&[0x61; 32]));
    minicbor::to_vec(SignedApprovalEnvelopeV1 {
        unsigned,
        daemon_key_id: KeyId::try_from("daemon-key").unwrap(),
        signature,
    })
    .unwrap()
}

#[test]
fn approval_envelope_uses_the_release_pinned_daemon_identity_and_domain() {
    let mut policy_value = policy_support::valid_policy(7, 3);
    let (template_bytes, template_signature) = policy_support::signed(&policy_value);
    let template_policy = policy_support::verifier()
        .verify(
            &template_bytes,
            &template_signature,
            policy_support::unix_now(),
        )
        .unwrap();
    let resource_profile_digest = template_policy.resource_profile_digest();
    let fixture = release_fixture(
        default_profile(),
        |_| {},
        |manifest| {
            manifest.resource_profile_digest = *resource_profile_digest.as_bytes();
            manifest.release_target_id = compute_release_target(
                manifest.protocol_major,
                manifest.minimum_minor,
                manifest.maximum_minor,
                &manifest.supported_policy_schemas,
                manifest.policy_trust_roots_digest,
                manifest.resource_profile_digest,
                manifest.installation_profile_digest,
            );
        },
    );
    let release = fixture.verify().unwrap();
    policy_value.release.compatible_release_target_ids =
        vec![*release.release_target_id().as_bytes()];
    let (policy_bytes, policy_signature) = policy_support::signed(&policy_value);
    let policy = PolicyVerifier::new(
        vec![policy_support::trust_root(
            "policy-root",
            &policy_support::signing_key(),
            3,
            false,
        )],
        release.release_target_id(),
    )
    .unwrap()
    .verify(&policy_bytes, &policy_signature, policy_support::unix_now())
    .unwrap();
    let encoded = signed_approval_envelope(&release, &policy, APPROVAL_ENVELOPE_DOMAIN);
    let verified = release
        .verify_approval_envelope(&policy, &encoded, UnixMillis::new(NOW))
        .unwrap();
    assert_eq!(verified.daemon_key_id().as_str(), "daemon-key");
    assert_ne!(verified.display_digest(), Digest32::new([0; 32]));

    for now in [999, 3_000] {
        assert_eq!(
            release
                .verify_approval_envelope(&policy, &encoded, UnixMillis::new(now))
                .unwrap_err()
                .code(),
            StableCode::AttestationExpired
        );
    }
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert_eq!(
        release
            .verify_approval_envelope(&policy, &trailing, UnixMillis::new(NOW))
            .unwrap_err()
            .code(),
        StableCode::ProtocolMalformedCbor
    );

    assert_eq!(
        release
            .verify_approval_envelope(
                &policy,
                &signed_approval_envelope(&release, &policy, APPROVAL_RECEIPT_DOMAIN),
                UnixMillis::new(NOW),
            )
            .unwrap_err()
            .code(),
        StableCode::ApprovalInvalidSignature
    );

    let mut wrong_display: SignedApprovalEnvelopeV1 = minicbor::decode(&encoded).unwrap();
    wrong_display.unsigned.display_digest = Digest32::new([0xff; 32]);
    let payload = minicbor::to_vec(&wrong_display.unsigned).unwrap();
    wrong_display.signature = detached_signature(
        APPROVAL_ENVELOPE_DOMAIN,
        &payload,
        &SigningKey::from_bytes(&[0x61; 32]),
    );
    assert_eq!(
        release
            .verify_approval_envelope(
                &policy,
                &minicbor::to_vec(wrong_display).unwrap(),
                UnixMillis::new(NOW),
            )
            .unwrap_err()
            .code(),
        StableCode::ApprovalBindingMismatch
    );

    let mut zero_challenge_nonce: SignedApprovalEnvelopeV1 = minicbor::decode(&encoded).unwrap();
    zero_challenge_nonce.unsigned.challenge.nonce = Nonce32::new([0; 32]);
    let payload = minicbor::to_vec(&zero_challenge_nonce.unsigned).unwrap();
    zero_challenge_nonce.signature = detached_signature(
        APPROVAL_ENVELOPE_DOMAIN,
        &payload,
        &SigningKey::from_bytes(&[0x61; 32]),
    );
    assert_eq!(
        release
            .verify_approval_envelope(
                &policy,
                &minicbor::to_vec(zero_challenge_nonce).unwrap(),
                UnixMillis::new(NOW),
            )
            .unwrap_err()
            .code(),
        StableCode::ApprovalBindingMismatch
    );

    let mut next_policy_value = policy_support::valid_policy(8, 3);
    next_policy_value.release.compatible_release_target_ids =
        vec![*release.release_target_id().as_bytes()];
    let (next_policy_bytes, next_policy_signature) = policy_support::signed(&next_policy_value);
    let next_policy = PolicyVerifier::new(
        vec![policy_support::trust_root(
            "policy-root",
            &policy_support::signing_key(),
            3,
            false,
        )],
        release.release_target_id(),
    )
    .unwrap()
    .verify(
        &next_policy_bytes,
        &next_policy_signature,
        policy_support::unix_now(),
    )
    .unwrap();
    assert_eq!(
        release
            .verify_approval_envelope(&next_policy, &encoded, UnixMillis::new(NOW))
            .unwrap_err()
            .code(),
        StableCode::ApprovalBindingMismatch
    );

    let mut relabeled: SignedApprovalEnvelopeV1 = minicbor::decode(&encoded).unwrap();
    relabeled.daemon_key_id = KeyId::try_from("other-daemon").unwrap();
    assert_eq!(
        release
            .verify_approval_envelope(
                &policy,
                &minicbor::to_vec(relabeled).unwrap(),
                UnixMillis::new(NOW),
            )
            .unwrap_err()
            .code(),
        StableCode::ApprovalInvalidSignature
    );
}

#[test]
fn approval_envelope_obeys_the_current_policy_effective_frame_limit() {
    let mut policy_value = policy_support::valid_policy(7, 3);
    policy_value.resources.frame_bytes = 1;
    let (template_bytes, template_signature) = policy_support::signed(&policy_value);
    let template_policy = policy_support::verifier()
        .verify(
            &template_bytes,
            &template_signature,
            policy_support::unix_now(),
        )
        .unwrap();
    let resource_profile_digest = template_policy.resource_profile_digest();
    let fixture = release_fixture(
        default_profile(),
        |_| {},
        |manifest| {
            manifest.resource_profile_digest = *resource_profile_digest.as_bytes();
            manifest.release_target_id = compute_release_target(
                manifest.protocol_major,
                manifest.minimum_minor,
                manifest.maximum_minor,
                &manifest.supported_policy_schemas,
                manifest.policy_trust_roots_digest,
                manifest.resource_profile_digest,
                manifest.installation_profile_digest,
            );
        },
    );
    let release = fixture.verify().unwrap();
    policy_value.release.compatible_release_target_ids =
        vec![*release.release_target_id().as_bytes()];
    let (policy_bytes, policy_signature) = policy_support::signed(&policy_value);
    let policy = PolicyVerifier::new(
        vec![policy_support::trust_root(
            "policy-root",
            &policy_support::signing_key(),
            3,
            false,
        )],
        release.release_target_id(),
    )
    .unwrap()
    .verify(&policy_bytes, &policy_signature, policy_support::unix_now())
    .unwrap();
    let encoded = signed_approval_envelope(&release, &policy, APPROVAL_ENVELOPE_DOMAIN);
    assert!(
        u64::try_from(encoded.len()).unwrap() > policy.effective_limits().frame_bytes(),
        "the correctly signed envelope must exercise the lowered policy limit"
    );

    assert_eq!(
        release
            .verify_approval_envelope(&policy, &encoded, UnixMillis::new(NOW))
            .unwrap_err()
            .code(),
        StableCode::PolicyLimitExceeded
    );
}

#[test]
fn manifest_signature_domain_key_and_validity_are_strict() {
    let mut mutated = release_fixture(default_profile(), |_| {}, |_| {});
    let original_signature = mutated.signature_bytes;
    mutated.manifest_value.release_version = "1.0.1".to_owned();
    mutated.manifest_bytes = encode_manifest(&mutated.manifest_value);
    fs::write(&mutated.manifest_path, &mutated.manifest_bytes).unwrap();
    fs::write(&mutated.signature_path, original_signature.as_bytes()).unwrap();
    assert_eq!(
        mutated
            .verifier()
            .verify_installed(
                &mutated.manifest_path,
                &mutated.signature_path,
                &mutated.binary,
                UnixMillis::new(NOW),
            )
            .unwrap_err()
            .code(),
        StableCode::IdentityInvalidSignature
    );

    let fixture = release_fixture(default_profile(), |_| {}, |_| {});
    let wrong_domain = detached_signature(
        b"SAVANA_POLICY_V1\0",
        &fixture.manifest_bytes,
        &fixture.release_key,
    );
    fs::write(&fixture.signature_path, wrong_domain.as_bytes()).unwrap();
    assert_eq!(
        fixture
            .verifier()
            .verify_installed(
                &fixture.manifest_path,
                &fixture.signature_path,
                &fixture.binary,
                UnixMillis::new(NOW),
            )
            .unwrap_err()
            .code(),
        StableCode::IdentityInvalidSignature
    );

    let unknown = ReleaseVerifier::new(
        vec![ReleaseTrustRootV1 {
            key_id: KeyId::try_from("unknown-root").unwrap(),
            public_key: fixture.release_key.verifying_key().to_bytes(),
            not_before: UnixMillis::new(500),
            not_after: UnixMillis::new(5_000),
            revoked: false,
        }],
        vec![sha256(&fixture.manifest_bytes)],
    )
    .unwrap();
    assert_release_error(&fixture, &unknown, StableCode::IdentityInvalidSignature);

    for root in [
        fixture.release_root(true, 500, 5_000),
        fixture.release_root(false, NOW + 1, 5_000),
        fixture.release_root(false, 500, NOW),
        ReleaseTrustRootV1 {
            key_id: KeyId::try_from("release-root").unwrap(),
            public_key: [0xff; 32],
            not_before: UnixMillis::new(500),
            not_after: UnixMillis::new(5_000),
            revoked: false,
        },
    ] {
        let verifier =
            ReleaseVerifier::new(vec![root], vec![sha256(&fixture.manifest_bytes)]).unwrap();
        assert_release_error(&fixture, &verifier, StableCode::IdentityInvalidSignature);
    }
}

#[test]
fn release_digest_and_lifetime_are_installation_pinned() {
    let fixture = release_fixture(default_profile(), |_| {}, |_| {});
    let unpinned = ReleaseVerifier::new(
        vec![fixture.release_root(false, 500, 5_000)],
        vec![Digest32::new([0xee; 32])],
    )
    .unwrap();
    assert_release_error(&fixture, &unpinned, StableCode::IdentityReleaseMismatch);

    for now in [999, 4_000] {
        assert_eq!(
            fixture
                .verifier()
                .verify_installed(
                    &fixture.manifest_path,
                    &fixture.signature_path,
                    &fixture.binary,
                    UnixMillis::new(now),
                )
                .unwrap_err()
                .code(),
            StableCode::IdentityReleaseMismatch
        );
    }
}

#[test]
fn manifest_schema_protocol_scalars_and_target_are_refused_exactly() {
    let cases: Vec<CodedManifestCase> = vec![
        (
            "manifest schema",
            StableCode::ProtocolUnsupportedVersion,
            Box::new(|manifest| manifest.schema_version = 2),
        ),
        (
            "protocol major",
            StableCode::ProtocolUnsupportedVersion,
            Box::new(|manifest| manifest.protocol_major = 2),
        ),
        (
            "protocol minimum",
            StableCode::ProtocolUnsupportedVersion,
            Box::new(|manifest| manifest.minimum_minor = 1),
        ),
        (
            "policy schema",
            StableCode::ProtocolUnsupportedVersion,
            Box::new(|manifest| manifest.supported_policy_schemas = vec![2]),
        ),
        (
            "model schema",
            StableCode::ProtocolUnsupportedVersion,
            Box::new(|manifest| manifest.supported_model_schemas = vec![2]),
        ),
        (
            "zero sequence",
            StableCode::ProtocolMalformedCbor,
            Box::new(|manifest| manifest.release_sequence = 0),
        ),
        (
            "zero minimum policy",
            StableCode::ProtocolMalformedCbor,
            Box::new(|manifest| manifest.minimum_policy_version = 0),
        ),
        (
            "bad source commit",
            StableCode::ProtocolMalformedCbor,
            Box::new(|manifest| manifest.source_commit = "ABC".to_owned()),
        ),
        (
            "inverted manifest lifetime",
            StableCode::ProtocolMalformedCbor,
            Box::new(|manifest| manifest.expires_at = manifest.issued_at),
        ),
        (
            "target mismatch",
            StableCode::IdentityReleaseMismatch,
            Box::new(|manifest| manifest.release_target_id = [0xfe; 32]),
        ),
        (
            "profile digest mismatch",
            StableCode::IdentityReleaseMismatch,
            Box::new(|manifest| manifest.installation_profile_digest = [0xfd; 32]),
        ),
        (
            "policy roots digest mismatch",
            StableCode::IdentityReleaseMismatch,
            Box::new(|manifest| manifest.policy_trust_roots_digest = [0xfc; 32]),
        ),
        (
            "zero digest",
            StableCode::ProtocolMalformedCbor,
            Box::new(|manifest| manifest.approval_key_set_digest = [0; 32]),
        ),
    ];

    for (label, expected, mutate) in cases {
        let fixture = release_fixture(default_profile(), |_| {}, |manifest| mutate(manifest));
        assert_eq!(fixture.verify().unwrap_err(), expected, "{label}");
    }
}

#[test]
fn source_commit_accepts_64_lowercase_hex_and_rejects_other_lengths_or_non_hex() {
    let accepted = release_fixture(
        default_profile(),
        |_| {},
        |manifest| {
            manifest.source_commit = "a".repeat(64);
        },
    );
    assert!(accepted.verify().is_ok());

    for source_commit in [
        "a".repeat(39),
        "a".repeat(41),
        "a".repeat(63),
        "a".repeat(65),
        "A".repeat(40),
        "g".repeat(40),
    ] {
        let rejected = release_fixture(
            default_profile(),
            |_| {},
            move |manifest| {
                manifest.source_commit = source_commit;
            },
        );
        assert_eq!(
            rejected.verify().unwrap_err(),
            StableCode::ProtocolMalformedCbor
        );
    }
}

#[test]
fn manifest_and_profile_noncanonical_encodings_are_distinguished() {
    let mut fixture = release_fixture(default_profile(), |_| {}, |_| {});
    let mut noncanonical_manifest = fixture.manifest_bytes.clone();
    let mut decoder = minicbor::Decoder::new(&fixture.manifest_bytes);
    assert_eq!(decoder.array().unwrap(), Some(25));
    assert_eq!(decoder.u16().unwrap(), 1);
    decoder.str().unwrap();
    let sequence_position = decoder.position();
    assert_eq!(decoder.u64().unwrap(), 1);
    noncanonical_manifest.splice(sequence_position..sequence_position + 1, [0x18, 0x01]);
    let release_key = fixture.release_key.clone();
    fixture.replace_signed_manifest(noncanonical_manifest, &release_key);
    assert_eq!(
        fixture.verify().unwrap_err(),
        StableCode::ProtocolNonCanonicalCbor
    );

    let profile = default_profile();
    let canonical_profile = encode_profile(&profile);
    assert_eq!(canonical_profile[0], 0x8e);
    assert_eq!(canonical_profile[1], 0x01);
    let mut noncanonical_profile = canonical_profile;
    noncanonical_profile.splice(1..2, [0x18, 0x01]);
    let fixture = release_fixture_with_profile_bytes(profile, noncanonical_profile, |_| {}, |_| {});
    assert_eq!(
        fixture.verify().unwrap_err(),
        StableCode::ProtocolNonCanonicalCbor
    );
}

#[test]
fn profile_client_root_platform_path_and_mode_contract_is_closed() {
    let cases: Vec<ProfileCase> = vec![
        (
            "profile schema",
            Box::new(|profile| profile.schema_version = 2),
        ),
        (
            "zero installation ID",
            Box::new(|profile| profile.installation_id = [0; 32]),
        ),
        ("unknown platform", Box::new(|profile| profile.platform = 2)),
        (
            "zero daemon public key",
            Box::new(|profile| profile.daemon_identity.public_key = [0; 32]),
        ),
        (
            "empty clients",
            Box::new(|profile| profile.daemon_clients.clear()),
        ),
        (
            "too many clients",
            Box::new(|profile| {
                let socket_client_gid = profile.daemon_clients[0].peer_gid;
                profile.daemon_clients = (0..17)
                    .map(|index| TestClient {
                        client_id: format!("client-{index:02}"),
                        key_id: format!("key-{index:02}"),
                        public_key: vec![index as u8 + 1; 32],
                        role: 0,
                        peer_uid: profile.jarvis_uid,
                        peer_gid: socket_client_gid,
                    })
                    .collect()
            }),
        ),
        (
            "duplicate client ID",
            Box::new(|profile| {
                let mut duplicate = profile.daemon_clients[0].clone();
                duplicate.key_id = "jarvis-key-02".to_owned();
                duplicate.public_key = vec![0x93; 32];
                profile.daemon_clients.push(duplicate);
            }),
        ),
        (
            "unsorted clients",
            Box::new(|profile| {
                let mut first = profile.daemon_clients[0].clone();
                first.client_id = "zz".to_owned();
                first.key_id = "zz-key".to_owned();
                first.public_key = vec![0x91; 32];
                let mut second = first.clone();
                second.client_id = "aa".to_owned();
                second.key_id = "aa-key".to_owned();
                second.public_key = vec![0x92; 32];
                profile.daemon_clients = vec![first, second];
            }),
        ),
        (
            "duplicate client key ID",
            Box::new(|profile| {
                let mut duplicate = profile.daemon_clients[0].clone();
                duplicate.client_id = "jarvis-02".to_owned();
                duplicate.public_key = vec![0x94; 32];
                profile.daemon_clients.push(duplicate);
            }),
        ),
        (
            "wrong client key length",
            Box::new(|profile| {
                profile.daemon_clients[0].public_key.pop();
            }),
        ),
        (
            "unknown client role",
            Box::new(|profile| profile.daemon_clients[0].role = 1),
        ),
        (
            "wrong client peer UID",
            Box::new(|profile| profile.daemon_clients[0].peer_uid += 1),
        ),
        (
            "zero client peer GID",
            Box::new(|profile| profile.daemon_clients[0].peer_gid = 0),
        ),
        (
            "daemon/client key reuse",
            Box::new(|profile| {
                profile.daemon_clients[0].key_id = profile.daemon_identity.key_id.clone()
            }),
        ),
        (
            "empty policy roots",
            Box::new(|profile| profile.policy_trust_roots.clear()),
        ),
        (
            "too many policy roots",
            Box::new(|profile| {
                profile.policy_trust_roots = (0..17)
                    .map(|index| TestPolicyRoot {
                        key_id: format!("root-{index:02}"),
                        public_key: vec![index as u8 + 1; 32],
                        epoch: 1,
                        revoked: false,
                    })
                    .collect()
            }),
        ),
        (
            "duplicate policy root",
            Box::new(|profile| {
                profile
                    .policy_trust_roots
                    .push(profile.policy_trust_roots[0].clone())
            }),
        ),
        (
            "zero policy root epoch",
            Box::new(|profile| profile.policy_trust_roots[0].epoch = 0),
        ),
        (
            "wrong policy root key length",
            Box::new(|profile| profile.policy_trust_roots[0].public_key.push(1)),
        ),
        (
            "wrong socket path",
            Box::new(|profile| profile.socket_path.push_str(".alternate")),
        ),
        (
            "wrong selected policy path",
            Box::new(|profile| profile.selected_policy_path.push_str(".alternate")),
        ),
        (
            "wrong signature path",
            Box::new(|profile| {
                profile
                    .selected_policy_signature_path
                    .push_str(".alternate")
            }),
        ),
        (
            "relative socket path",
            Box::new(|profile| profile.socket_path = "run/savana/kernel/kerneld.sock".to_owned()),
        ),
        (
            "control character in selected policy path",
            Box::new(|profile| profile.selected_policy_path.push('\n')),
        ),
        (
            "wrong parent mode",
            Box::new(|profile| profile.socket_parent_mode = 0o755),
        ),
        (
            "wrong socket mode",
            Box::new(|profile| profile.socket_mode = 0o666),
        ),
        (
            "daemon and JARVIS UID collide",
            Box::new(|profile| profile.jarvis_uid = profile.daemon_uid),
        ),
    ];

    for (label, mutate) in cases {
        let mut profile = default_profile();
        mutate(&mut profile);
        let fixture = release_fixture(profile, |_| {}, |_| {});
        let expected = match label {
            "profile schema" => StableCode::ProtocolUnsupportedVersion,
            "wrong socket path"
            | "wrong selected policy path"
            | "wrong signature path"
            | "wrong parent mode"
            | "wrong socket mode" => StableCode::IdentityReleaseMismatch,
            _ => StableCode::ProtocolMalformedCbor,
        };
        assert_eq!(fixture.verify().unwrap_err(), expected, "{label}");
    }
}

#[test]
fn profile_clients_share_one_non_daemon_socket_group() {
    let mut mixed_groups = default_profile();
    let mut second = mixed_groups.daemon_clients[0].clone();
    second.client_id = "jarvis-client-02".to_owned();
    second.key_id = "jarvis-key-02".to_owned();
    second.public_key = SigningKey::from_bytes(&[0x63; 32])
        .verifying_key()
        .to_bytes()
        .to_vec();
    second.peer_gid = mixed_groups.daemon_clients[0].peer_gid + 1;
    mixed_groups.daemon_clients.push(second);
    assert_eq!(
        release_fixture(mixed_groups, |_| {}, |_| {})
            .verify()
            .unwrap_err(),
        StableCode::ProtocolMalformedCbor
    );

    let mut daemon_group = default_profile();
    daemon_group.daemon_clients[0].peer_gid = daemon_group.daemon_gid;
    assert_eq!(
        release_fixture(daemon_group, |_| {}, |_| {})
            .verify()
            .unwrap_err(),
        StableCode::ProtocolMalformedCbor
    );
}

#[test]
fn profile_ed25519_public_keys_must_be_usable_before_startup() {
    let unusable = (1_u8..=u8::MAX)
        .map(|byte| [byte; 32])
        .find(|candidate| VerifyingKey::from_bytes(candidate).is_err())
        .expect("at least one repeated-byte encoding is not an Ed25519 point");
    let mut weak = [0_u8; 32];
    weak[0] = 1;
    assert!(VerifyingKey::from_bytes(&weak)
        .expect("compressed Edwards identity is an encoded point")
        .is_weak());
    for public_key in [unusable, weak] {
        for target in 0..3 {
            let mut profile = default_profile();
            match target {
                0 => profile.daemon_identity.public_key = public_key,
                1 => profile.daemon_clients[0].public_key = public_key.to_vec(),
                2 => profile.policy_trust_roots[0].public_key = public_key.to_vec(),
                _ => unreachable!(),
            }
            let fixture = release_fixture(profile, |_| {}, |_| {});
            assert_eq!(
                fixture.verify().unwrap_err(),
                StableCode::IdentityReleaseMismatch
            );
        }
    }
}

#[test]
fn schema_sets_payload_table_and_relative_paths_are_bounded_and_sorted() {
    let cases: Vec<ManifestCase> = vec![
        (
            "empty policy schemas",
            Box::new(|manifest| manifest.supported_policy_schemas.clear()),
        ),
        (
            "duplicate policy schema",
            Box::new(|manifest| manifest.supported_policy_schemas = vec![1, 1]),
        ),
        (
            "unsorted model schemas",
            Box::new(|manifest| manifest.supported_model_schemas = vec![2, 1]),
        ),
        (
            "too many schemas",
            Box::new(|manifest| manifest.supported_policy_schemas = (1..=17).collect()),
        ),
        (
            "unsorted payloads",
            Box::new(|manifest| manifest.payloads.swap(0, 1)),
        ),
        (
            "duplicate payload",
            Box::new(|manifest| manifest.payloads.insert(1, manifest.payloads[0].clone())),
        ),
        (
            "absolute payload",
            Box::new(|manifest| manifest.payloads[0].relative_path = "/absolute".to_owned()),
        ),
        (
            "parent traversal",
            Box::new(|manifest| manifest.payloads[0].relative_path = "model/../asset".to_owned()),
        ),
        (
            "backslash path",
            Box::new(|manifest| manifest.payloads[0].relative_path = "model\\asset".to_owned()),
        ),
        (
            "unknown payload",
            Box::new(|manifest| manifest.payloads[0].relative_path = "unknown/file".to_owned()),
        ),
        (
            "oversized path",
            Box::new(|manifest| manifest.payloads[0].relative_path = "x".repeat(257)),
        ),
    ];

    for (label, mutate) in cases {
        let fixture = release_fixture(default_profile(), |_| {}, |manifest| mutate(manifest));
        assert_eq!(
            fixture.verify().unwrap_err(),
            StableCode::ProtocolMalformedCbor,
            "{label}"
        );
    }
}

#[test]
fn complete_payload_tree_hash_length_layout_and_symlinks_are_verified() {
    let fixture = release_fixture(default_profile(), |_| {}, |_| {});
    fs::write(
        fixture
            .stage_root()
            .join("model/signed-model-manifest-v1.cbor"),
        b"changed",
    )
    .unwrap();
    assert_eq!(
        fixture.verify().unwrap_err(),
        StableCode::IdentityReleaseMismatch
    );

    let fixture = release_fixture(default_profile(), |_| {}, |_| {});
    fs::remove_file(fixture.stage_root().join("approval/ontology-v1.cbor")).unwrap();
    assert_eq!(
        fixture.verify().unwrap_err(),
        StableCode::IdentityReleaseMismatch
    );

    let fixture = release_fixture(default_profile(), |_| {}, |_| {});
    fs::write(
        fixture.stage_root().join("model/assets/hidden.bin"),
        b"hidden",
    )
    .unwrap();
    assert_eq!(
        fixture.verify().unwrap_err(),
        StableCode::IdentityReleaseMismatch
    );

    let fixture = release_fixture(default_profile(), |_| {}, |_| {});
    fs::remove_file(fixture.stage_root().join("model/assets/model.bin")).unwrap();
    symlink(
        fixture.stage_root().join("bin/savana-kerneld"),
        fixture.stage_root().join("model/assets/model.bin"),
    )
    .unwrap();
    assert_eq!(
        fixture.verify().unwrap_err(),
        StableCode::IdentityReleaseMismatch
    );

    let fixture = release_fixture(default_profile(), |_| {}, |_| {});
    fs::remove_file(&fixture.binary).unwrap();
    symlink(
        fixture.stage_root().join("policy/default-policy-v1.cbor"),
        &fixture.binary,
    )
    .unwrap();
    assert_eq!(
        fixture.verify().unwrap_err(),
        StableCode::IdentityReleaseMismatch
    );
}

#[test]
fn nested_model_asset_suffixes_are_part_of_the_frozen_layout() {
    let fixture = release_fixture(
        default_profile(),
        |files| {
            files
                .iter_mut()
                .find(|(path, _)| path == "model/assets/model.bin")
                .unwrap()
                .0 = "model/assets/en/model.bin".to_owned();
        },
        |_| {},
    );
    fixture.verify().unwrap();
}

#[test]
fn manifest_bound_profile_mutation_is_a_release_mismatch() {
    let fixture = release_fixture(default_profile(), |_| {}, |_| {});
    let profile_path = fixture
        .stage_root()
        .join("installation/kernel-installation-profile-v1.cbor");
    let mut bytes = fs::read(&profile_path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    fs::write(profile_path, bytes).unwrap();
    assert_eq!(
        fixture.verify().unwrap_err(),
        StableCode::IdentityReleaseMismatch
    );
}

#[test]
fn release_verifier_inputs_are_bounded_sorted_unique_and_nonzero() {
    let fixture = release_fixture(default_profile(), |_| {}, |_| {});
    assert_eq!(
        ReleaseVerifier::new(Vec::new(), vec![sha256(&fixture.manifest_bytes)])
            .unwrap_err()
            .code(),
        StableCode::ProtocolMalformedCbor
    );
    assert_eq!(
        ReleaseVerifier::new(vec![fixture.release_root(false, 500, 5_000)], Vec::new(),)
            .unwrap_err()
            .code(),
        StableCode::ProtocolMalformedCbor
    );
    assert_eq!(
        ReleaseVerifier::new(
            vec![fixture.release_root(false, 500, 5_000)],
            vec![Digest32::new([0; 32])],
        )
        .unwrap_err()
        .code(),
        StableCode::ProtocolMalformedCbor
    );

    let root = fixture.release_root(false, 500, 5_000);
    assert_eq!(
        ReleaseVerifier::new(
            vec![root.clone(), root],
            vec![sha256(&fixture.manifest_bytes)],
        )
        .unwrap_err()
        .code(),
        StableCode::ProtocolMalformedCbor
    );
    assert_eq!(
        ReleaseVerifier::new(
            vec![fixture.release_root(false, 5_000, 5_000)],
            vec![sha256(&fixture.manifest_bytes)],
        )
        .unwrap_err()
        .code(),
        StableCode::ProtocolMalformedCbor
    );
}

#[test]
fn canonical_release_trust_root_loader_is_closed_and_bounded() {
    let fixture = release_fixture(default_profile(), |_| {}, |_| {});
    let release_digest = sha256(&fixture.manifest_bytes);
    let root = fixture.release_root(false, 500, 5_000);
    let canonical = encode_release_trust_roots(&[root.clone()]);
    let verifier =
        ReleaseVerifier::from_canonical_trust_roots(&canonical, vec![release_digest]).unwrap();
    verifier
        .verify_installed(
            &fixture.manifest_path,
            &fixture.signature_path,
            &fixture.binary,
            UnixMillis::new(NOW),
        )
        .unwrap();

    assert_eq!(&canonical[..2], &[0x81, 0x85]);
    let mut wrong_record_length = canonical.clone();
    wrong_record_length[1] = 0x84;

    let mut indefinite = canonical.clone();
    indefinite[0] = 0x9f;
    indefinite.push(0xff);

    let timestamp = canonical
        .windows(3)
        .position(|window| window == [0x19, 0x01, 0xf4])
        .expect("canonical fixture contains not-before=500");
    let mut noncanonical = Vec::with_capacity(canonical.len() + 2);
    noncanonical.extend_from_slice(&canonical[..timestamp]);
    noncanonical.extend_from_slice(&[0x1a, 0x00, 0x00, 0x01, 0xf4]);
    noncanonical.extend_from_slice(&canonical[timestamp + 3..]);

    let mut first = root.clone();
    first.key_id = KeyId::try_from("z").unwrap();
    let mut second = root.clone();
    second.key_id = KeyId::try_from("a").unwrap();
    let unsorted = encode_release_trust_roots(&[first, second]);
    let duplicate = encode_release_trust_roots(&[root.clone(), root]);

    let maximum = usize::try_from(HardLimits::COMPILED.frame_bytes()).unwrap();
    let oversized = vec![0_u8; maximum + 1];
    for (label, bytes, expected) in [
        (
            "wrong record length",
            wrong_record_length,
            StableCode::ProtocolMalformedCbor,
        ),
        (
            "indefinite root set",
            indefinite,
            StableCode::ProtocolMalformedCbor,
        ),
        (
            "noncanonical integer",
            noncanonical,
            StableCode::ProtocolNonCanonicalCbor,
        ),
        (
            "unsorted roots",
            unsorted,
            StableCode::ProtocolMalformedCbor,
        ),
        (
            "duplicate roots",
            duplicate,
            StableCode::ProtocolMalformedCbor,
        ),
        (
            "oversized root set",
            oversized,
            StableCode::ProtocolMalformedCbor,
        ),
    ] {
        assert_eq!(
            ReleaseVerifier::from_canonical_trust_roots(&bytes, vec![release_digest])
                .unwrap_err()
                .code(),
            expected,
            "{label}"
        );
    }
}

fn assert_release_error(
    fixture: &ReleaseFixture,
    verifier: &ReleaseVerifier,
    expected: StableCode,
) {
    assert_eq!(
        verifier
            .verify_installed(
                &fixture.manifest_path,
                &fixture.signature_path,
                &fixture.binary,
                UnixMillis::new(NOW),
            )
            .unwrap_err()
            .code(),
        expected
    );
}

fn default_profile() -> TestProfile {
    let daemon_key = SigningKey::from_bytes(&[0x61; 32]);
    let client_key = SigningKey::from_bytes(&[0x62; 32]);
    let policy_key = SigningKey::from_bytes(&[0x42; 32]);
    TestProfile {
        schema_version: 1,
        installation_id: [0x71; 32],
        platform: 0,
        daemon_identity: TestPublicKey {
            key_id: "daemon-key".to_owned(),
            public_key: daemon_key.verifying_key().to_bytes(),
        },
        daemon_clients: vec![TestClient {
            client_id: "jarvis-client".to_owned(),
            key_id: "jarvis-key".to_owned(),
            public_key: client_key.verifying_key().to_bytes().to_vec(),
            role: 0,
            peer_uid: 1_001,
            peer_gid: 1_003,
        }],
        policy_trust_roots: vec![TestPolicyRoot {
            key_id: "policy-root".to_owned(),
            public_key: policy_key.verifying_key().to_bytes().to_vec(),
            epoch: 3,
            revoked: false,
        }],
        daemon_uid: 1_002,
        daemon_gid: 1_002,
        jarvis_uid: 1_001,
        socket_path: "/run/savana/kernel/kerneld.sock".to_owned(),
        selected_policy_path: "/etc/savana/kernel/selected-policy-v1.cbor".to_owned(),
        selected_policy_signature_path: "/etc/savana/kernel/selected-policy-v1.sig".to_owned(),
        socket_parent_mode: 0o750,
        socket_mode: 0o660,
    }
}

fn release_fixture<PayloadEdit, ManifestEdit>(
    profile: TestProfile,
    payload_edit: PayloadEdit,
    manifest_edit: ManifestEdit,
) -> ReleaseFixture
where
    PayloadEdit: FnOnce(&mut Vec<(String, Vec<u8>)>),
    ManifestEdit: FnOnce(&mut TestManifest),
{
    let profile_bytes = encode_profile(&profile);
    release_fixture_with_profile_bytes(profile, profile_bytes, payload_edit, manifest_edit)
}

fn release_fixture_with_profile_bytes<PayloadEdit, ManifestEdit>(
    profile: TestProfile,
    profile_bytes: Vec<u8>,
    payload_edit: PayloadEdit,
    manifest_edit: ManifestEdit,
) -> ReleaseFixture
where
    PayloadEdit: FnOnce(&mut Vec<(String, Vec<u8>)>),
    ManifestEdit: FnOnce(&mut TestManifest),
{
    let stage = tempfile::tempdir().unwrap();
    let mut files = vec![
        ("bin/savana-kerneld".to_owned(), b"kernel-binary".to_vec()),
        (
            "policy/default-policy-v1.cbor".to_owned(),
            b"default-policy".to_vec(),
        ),
        ("policy/default-policy-v1.sig".to_owned(), vec![0x81; 64]),
        (
            "approval/producer-registry-v1.cbor".to_owned(),
            b"producer-registry".to_vec(),
        ),
        ("approval/ontology-v1.cbor".to_owned(), b"ontology".to_vec()),
        (
            "approval/approval-key-set-v1.cbor".to_owned(),
            b"approval-keys".to_vec(),
        ),
        (
            "model/signed-model-manifest-v1.cbor".to_owned(),
            b"model-manifest".to_vec(),
        ),
        (
            "installation/kernel-installation-profile-v1.cbor".to_owned(),
            profile_bytes.clone(),
        ),
        (
            if profile.platform == 1 {
                "runtime/libonnxruntime.dylib".to_owned()
            } else {
                "runtime/libonnxruntime.so".to_owned()
            },
            b"onnx-runtime".to_vec(),
        ),
        ("model/assets/model.bin".to_owned(), b"model-asset".to_vec()),
    ];
    payload_edit(&mut files);
    for (relative, bytes) in &files {
        let path = stage.path().join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }

    let mut payloads: Vec<TestReleaseFile> = files
        .iter()
        .map(|(relative_path, bytes)| TestReleaseFile {
            relative_path: relative_path.clone(),
            byte_length: bytes.len() as u64,
            sha256: *sha256(bytes).as_bytes(),
        })
        .collect();
    payloads.sort_by(|left, right| canonical_text_cmp(&left.relative_path, &right.relative_path));

    let lookup = |path: &str| {
        files
            .iter()
            .find(|(candidate, _)| candidate == path)
            .map(|(_, bytes)| *sha256(bytes).as_bytes())
            .unwrap_or([0xa5; 32])
    };
    let roots_digest = sha256(&encode_policy_roots(&profile.policy_trust_roots));
    let profile_digest = sha256(&profile_bytes);
    let resource_profile_digest = [0x31; 32];
    let supported_policy_schemas = vec![1];
    let release_target_id = compute_release_target(
        1,
        0,
        0,
        &supported_policy_schemas,
        *roots_digest.as_bytes(),
        resource_profile_digest,
        *profile_digest.as_bytes(),
    );
    let mut manifest = TestManifest {
        schema_version: 1,
        release_version: "1.0.0".to_owned(),
        release_sequence: 1,
        release_target_id,
        source_commit: "a".repeat(40),
        signing_key_id: "release-root".to_owned(),
        binary_sha256: lookup("bin/savana-kerneld"),
        cargo_lock_sha256: [0xc1; 32],
        rust_toolchain_sha256: [0xc2; 32],
        protocol_major: 1,
        minimum_minor: 0,
        maximum_minor: 0,
        supported_policy_schemas,
        supported_model_schemas: vec![1],
        policy_trust_roots_digest: *roots_digest.as_bytes(),
        minimum_policy_version: 1,
        // These are logical identities inside later signed envelopes, not the
        // hashes of the envelope payload files authenticated by this table.
        model_manifest_digest: [0xd1; 32],
        producer_registry_digest: [0xd2; 32],
        ontology_digest: [0xd3; 32],
        approval_key_set_digest: [0xd4; 32],
        resource_profile_digest,
        installation_profile_digest: *profile_digest.as_bytes(),
        payloads,
        issued_at: 1_000,
        expires_at: 4_000,
    };
    manifest_edit(&mut manifest);
    let manifest_bytes = encode_manifest(&manifest);
    let release_key = SigningKey::from_bytes(&[0x51; 32]);
    let signature = detached_signature(RELEASE_DOMAIN, &manifest_bytes, &release_key);
    fs::create_dir_all(stage.path().join("release")).unwrap();
    let manifest_path = stage.path().join("release/release-manifest-v1.cbor");
    let signature_path = stage.path().join("release/release-manifest-v1.sig");
    fs::write(&manifest_path, &manifest_bytes).unwrap();
    fs::write(&signature_path, signature.as_bytes()).unwrap();

    let binary = stage.path().join("bin/savana-kerneld");
    ReleaseFixture {
        _stage: stage,
        manifest_value: manifest,
        manifest_bytes,
        manifest_path,
        signature_bytes: signature,
        signature_path,
        binary,
        release_key,
    }
}

fn encode_manifest(value: &TestManifest) -> Vec<u8> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(25)
        .unwrap()
        .u16(value.schema_version)
        .unwrap()
        .str(&value.release_version)
        .unwrap()
        .u64(value.release_sequence)
        .unwrap()
        .bytes(&value.release_target_id)
        .unwrap()
        .str(&value.source_commit)
        .unwrap()
        .str(&value.signing_key_id)
        .unwrap()
        .bytes(&value.binary_sha256)
        .unwrap()
        .bytes(&value.cargo_lock_sha256)
        .unwrap()
        .bytes(&value.rust_toolchain_sha256)
        .unwrap()
        .u16(value.protocol_major)
        .unwrap()
        .u16(value.minimum_minor)
        .unwrap()
        .u16(value.maximum_minor)
        .unwrap();
    encode_u16_array(&mut encoder, &value.supported_policy_schemas);
    encode_u16_array(&mut encoder, &value.supported_model_schemas);
    encoder
        .bytes(&value.policy_trust_roots_digest)
        .unwrap()
        .u64(value.minimum_policy_version)
        .unwrap()
        .bytes(&value.model_manifest_digest)
        .unwrap()
        .bytes(&value.producer_registry_digest)
        .unwrap()
        .bytes(&value.ontology_digest)
        .unwrap()
        .bytes(&value.approval_key_set_digest)
        .unwrap()
        .bytes(&value.resource_profile_digest)
        .unwrap()
        .bytes(&value.installation_profile_digest)
        .unwrap()
        .array(value.payloads.len() as u64)
        .unwrap();
    for payload in &value.payloads {
        encoder
            .array(3)
            .unwrap()
            .str(&payload.relative_path)
            .unwrap()
            .u64(payload.byte_length)
            .unwrap()
            .bytes(&payload.sha256)
            .unwrap();
    }
    encoder
        .u64(value.issued_at)
        .unwrap()
        .u64(value.expires_at)
        .unwrap();
    encoder.into_writer()
}

fn encode_profile(value: &TestProfile) -> Vec<u8> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(14)
        .unwrap()
        .u16(value.schema_version)
        .unwrap()
        .bytes(&value.installation_id)
        .unwrap()
        .u8(value.platform)
        .unwrap()
        .array(2)
        .unwrap()
        .str(&value.daemon_identity.key_id)
        .unwrap()
        .bytes(&value.daemon_identity.public_key)
        .unwrap()
        .array(value.daemon_clients.len() as u64)
        .unwrap();
    for client in &value.daemon_clients {
        encoder
            .array(6)
            .unwrap()
            .str(&client.client_id)
            .unwrap()
            .str(&client.key_id)
            .unwrap()
            .bytes(&client.public_key)
            .unwrap()
            .u8(client.role)
            .unwrap()
            .u32(client.peer_uid)
            .unwrap()
            .u32(client.peer_gid)
            .unwrap();
    }
    encode_policy_roots_into(&mut encoder, &value.policy_trust_roots);
    encoder
        .u32(value.daemon_uid)
        .unwrap()
        .u32(value.daemon_gid)
        .unwrap()
        .u32(value.jarvis_uid)
        .unwrap()
        .str(&value.socket_path)
        .unwrap()
        .str(&value.selected_policy_path)
        .unwrap()
        .str(&value.selected_policy_signature_path)
        .unwrap()
        .u16(value.socket_parent_mode)
        .unwrap()
        .u16(value.socket_mode)
        .unwrap();
    encoder.into_writer()
}

fn encode_policy_roots(values: &[TestPolicyRoot]) -> Vec<u8> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encode_policy_roots_into(&mut encoder, values);
    encoder.into_writer()
}

fn encode_release_trust_roots(values: &[ReleaseTrustRootV1]) -> Vec<u8> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder.array(values.len() as u64).unwrap();
    for root in values {
        encoder
            .array(5)
            .unwrap()
            .str(root.key_id.as_str())
            .unwrap()
            .bytes(&root.public_key)
            .unwrap()
            .u64(root.not_before.get())
            .unwrap()
            .u64(root.not_after.get())
            .unwrap()
            .bool(root.revoked)
            .unwrap();
    }
    encoder.into_writer()
}

fn encode_policy_roots_into(encoder: &mut minicbor::Encoder<Vec<u8>>, values: &[TestPolicyRoot]) {
    encoder.array(values.len() as u64).unwrap();
    for root in values {
        encoder
            .array(4)
            .unwrap()
            .str(&root.key_id)
            .unwrap()
            .bytes(&root.public_key)
            .unwrap()
            .u64(root.epoch)
            .unwrap()
            .bool(root.revoked)
            .unwrap();
    }
}

fn encode_u16_array(encoder: &mut minicbor::Encoder<Vec<u8>>, values: &[u16]) {
    encoder.array(values.len() as u64).unwrap();
    for value in values {
        encoder.u16(*value).unwrap();
    }
}

fn compute_release_target(
    protocol_major: u16,
    minimum_minor: u16,
    maximum_minor: u16,
    policy_schemas: &[u16],
    roots_digest: [u8; 32],
    resource_digest: [u8; 32],
    profile_digest: [u8; 32],
) -> [u8; 32] {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(7)
        .unwrap()
        .u16(protocol_major)
        .unwrap()
        .u16(minimum_minor)
        .unwrap()
        .u16(maximum_minor)
        .unwrap();
    encode_u16_array(&mut encoder, policy_schemas);
    encoder
        .bytes(&roots_digest)
        .unwrap()
        .bytes(&resource_digest)
        .unwrap()
        .bytes(&profile_digest)
        .unwrap();
    let tuple = encoder.into_writer();
    let mut hash = Sha256::new();
    hash.update(RELEASE_TARGET_DOMAIN);
    hash.update(tuple);
    hash.finalize().into()
}

fn detached_signature(domain: &[u8], bytes: &[u8], key: &SigningKey) -> Signature64 {
    let mut message = Vec::with_capacity(domain.len() + bytes.len());
    message.extend_from_slice(domain);
    message.extend_from_slice(bytes);
    Signature64::new(key.sign(&message).to_bytes())
}

fn sha256(bytes: &[u8]) -> Digest32 {
    Digest32::new(Sha256::digest(bytes).into())
}

fn canonical_text_cmp(left: &str, right: &str) -> Ordering {
    left.len()
        .cmp(&right.len())
        .then_with(|| left.as_bytes().cmp(right.as_bytes()))
}
