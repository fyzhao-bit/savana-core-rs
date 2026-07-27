#![allow(dead_code)]

use ed25519_dalek::{Signer, SigningKey};
use savana_kernel_protocol::{
    ingress_request_digest, AttemptKindV1, BeginRunRequest, BootId, BoundedText, ClientId,
    ConversationId, Digest32, HardLimits, IngestUserInputRequest, IngressEnvelopeV1,
    IngressRequestCommitmentV1, KernelValue, KeyId, Nonce32, PrincipalId, RegistrySnapshotV1,
    ResourceLimitsV1, RoleId, Signature64, SignedIngressEnvelopeV1, SignedRegistrySnapshotV1,
    StableCode, ToolDescriptorV1, ToolExecutionIdentity, ToolName, UnixMillis,
};
use savana_policy_core::{
    AuthenticatedCallContext, AuthenticatedContextIssuer, Clock, CurrentPolicyCapability,
    PolicyEngine, PolicyIdentity, PolicyStore, PolicyTrustRootV1, PolicyVerifier, RandomSource,
    ReleaseStage, ReleaseTrustRootV1, ReleaseVerifier, VerifiedReleaseIdentity,
};
use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

pub const POLICY_DOMAIN: &[u8] = b"SAVANA_POLICY_V1\0";
pub const RELEASE_DOMAIN: &[u8] = b"SAVANA_RELEASE_V1\0";
pub const NOW: u64 = 2_000;

#[derive(Debug, Clone, Copy)]
pub enum RandomBehavior {
    Full,
    Filled(u8),
    Error,
    Short(usize),
    Zeros(usize),
}

pub struct TestClock {
    wall: AtomicU64,
    monotonic: AtomicU64,
    fail_wall: AtomicBool,
}

impl TestClock {
    pub fn now(&self) -> u64 {
        self.wall.load(Ordering::SeqCst)
    }

    pub fn fail_wall(&self) {
        self.fail_wall.store(true, Ordering::SeqCst);
    }

    pub fn restore_wall_and_regress_monotonic(&self) {
        self.fail_wall.store(false, Ordering::SeqCst);
        self.monotonic.store(99, Ordering::SeqCst);
    }

    pub fn set(&self, wall: u64, monotonic: u64) {
        self.wall.store(wall, Ordering::SeqCst);
        self.monotonic.store(monotonic, Ordering::SeqCst);
    }
}

impl Clock for TestClock {
    fn wall_now(&self) -> Result<UnixMillis, StableCode> {
        if self.fail_wall.load(Ordering::SeqCst) {
            return Err(StableCode::ProtocolIo);
        }
        Ok(UnixMillis::new(self.wall.load(Ordering::SeqCst)))
    }

    fn monotonic_now_millis(&self) -> Result<u64, StableCode> {
        Ok(self.monotonic.load(Ordering::SeqCst))
    }
}

struct TestRandom {
    behavior: RandomBehavior,
}

impl RandomSource for TestRandom {
    fn fill(&self, output: &mut [u8]) -> Result<usize, StableCode> {
        match self.behavior {
            RandomBehavior::Full => {
                output.fill(0x5a);
                Ok(output.len())
            }
            RandomBehavior::Filled(byte) => {
                output.fill(byte);
                Ok(output.len())
            }
            RandomBehavior::Error => Err(StableCode::ProtocolIo),
            RandomBehavior::Short(written) => {
                let filled = written.min(output.len());
                output[..filled].fill(0x5a);
                Ok(written)
            }
            RandomBehavior::Zeros(written) => Ok(written),
        }
    }
}

pub fn clock() -> Arc<TestClock> {
    Arc::new(TestClock {
        wall: AtomicU64::new(NOW),
        monotonic: AtomicU64::new(100),
        fail_wall: AtomicBool::new(false),
    })
}

pub fn random(behavior: RandomBehavior) -> Arc<dyn RandomSource + Send + Sync> {
    Arc::new(TestRandom { behavior })
}

pub fn healthy_dependencies() -> (
    Arc<dyn Clock + Send + Sync>,
    Arc<dyn RandomSource + Send + Sync>,
) {
    (clock(), random(RandomBehavior::Full))
}

pub fn fresh_current_policy() -> CurrentPolicyCapability {
    current_policy_and_identity().0
}

pub fn current_policy_and_identity() -> (CurrentPolicyCapability, savana_policy_core::PolicyIdentity)
{
    let fixture = current_policy_fixture();
    let release = fixture.release();
    let identity = release
        .policy_verifier()
        .expect("fixture release verifier")
        .verify(
            fixture.policy_bytes(),
            fixture.policy_signature(),
            fixture.now(),
        )
        .expect("verify fixture policy")
        .identity();
    let store = PolicyStore::open(
        fixture.ledger_path(),
        release.policy_verifier().expect("fixture release verifier"),
    )
    .expect("open fixture policy store");
    let current = store
        .verify_and_accept_initial(
            release,
            fixture.policy_bytes(),
            fixture.policy_signature(),
            fixture.now(),
        )
        .expect("mint fixture current policy");
    (current, identity)
}

pub fn current_policy_and_identity_from(
    mut policy: TestPolicy,
) -> (CurrentPolicyCapability, PolicyIdentity) {
    let root = tempfile::tempdir().unwrap();
    let root_path = fs::canonicalize(root.path()).unwrap();
    let canonical_resources = minicbor::to_vec(policy.resources).unwrap();
    let mut resource_hasher = Sha256::new();
    resource_hasher.update(b"SAVANA_RESOURCE_PROFILE_V1\0");
    resource_hasher.update(canonical_resources);
    let resource_digest: [u8; 32] = resource_hasher.finalize().into();
    let profile_digest: [u8; 32] = Sha256::digest(fixture_profile()).into();
    let roots_digest: [u8; 32] = Sha256::digest(fixture_policy_roots()).into();
    let target = Digest32::new(compute_fixture_release_target(
        roots_digest,
        resource_digest,
        profile_digest,
    ));
    policy.release.compatible_release_target_ids = vec![*target.as_bytes()];
    let (policy_bytes, policy_signature) = signed(&policy);
    let release = build_verified_release(
        &root_path,
        "release-custom",
        b'e',
        resource_digest,
        4_000,
        NOW,
    );
    let verifier = release.policy_verifier().unwrap();
    let identity = verifier
        .verify(&policy_bytes, &policy_signature, UnixMillis::new(NOW))
        .unwrap()
        .identity();
    let store = PolicyStore::open(&root_path.join("policy.ledger"), verifier).unwrap();
    let current = store
        .verify_and_accept_initial(
            release,
            &policy_bytes,
            &policy_signature,
            UnixMillis::new(NOW),
        )
        .unwrap();
    (current, identity)
}

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

pub fn offline_verifier() -> PolicyVerifier {
    PolicyVerifier::new(
        vec![trust_root("policy-root", &signing_key(), 3, false)],
        current_release_target(),
    )
    .expect("valid offline fixture verifier")
}

pub fn read_optional_ledger(path: &Path) -> Option<Vec<u8>> {
    match fs::read(path) {
        Ok(bytes) => Some(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => panic!("read ledger fixture: {error}"),
    }
}

pub struct CurrentPolicyFixture {
    _root: Option<tempfile::TempDir>,
    ledger: PathBuf,
    release: VerifiedReleaseIdentity,
    other_release: VerifiedReleaseIdentity,
    wrong_resource_release: VerifiedReleaseIdentity,
    expired_release: VerifiedReleaseIdentity,
    policy_bytes: Vec<u8>,
    policy_signature: Signature64,
}

impl CurrentPolicyFixture {
    pub fn ledger_path(&self) -> &Path {
        &self.ledger
    }

    pub fn release(&self) -> VerifiedReleaseIdentity {
        self.release.clone()
    }

    pub fn other_release(&self) -> VerifiedReleaseIdentity {
        self.other_release.clone()
    }

    pub fn release_with_wrong_resource_digest(&self) -> VerifiedReleaseIdentity {
        self.wrong_resource_release.clone()
    }

    pub fn expired_release(&self) -> VerifiedReleaseIdentity {
        self.expired_release.clone()
    }

    pub fn policy_bytes(&self) -> &[u8] {
        &self.policy_bytes
    }

    pub const fn policy_signature(&self) -> &Signature64 {
        &self.policy_signature
    }

    pub const fn now(&self) -> UnixMillis {
        UnixMillis::new(NOW)
    }
}

pub fn current_policy_fixture() -> CurrentPolicyFixture {
    let root = tempfile::tempdir().unwrap();
    let mut fixture = current_policy_fixture_at(root.path());
    fixture._root = Some(root);
    fixture
}

pub fn current_policy_fixture_at(root: &Path) -> CurrentPolicyFixture {
    fs::create_dir_all(root).unwrap();
    let root = fs::canonicalize(root).unwrap();
    let resource_digest = fixture_resource_digest();
    let target = current_release_target();
    let mut policy = valid_policy(7, 3);
    policy.release.compatible_release_target_ids = vec![*target.as_bytes()];
    let (policy_bytes, policy_signature) = signed(&policy);
    let release = build_verified_release(&root, "release-a", b'a', resource_digest, 4_000, NOW);
    let other_release =
        build_verified_release(&root, "release-b", b'b', resource_digest, 4_000, NOW);
    let wrong_resource_release = build_verified_release(
        &root,
        "release-wrong-resource",
        b'c',
        [0xf3; 32],
        4_000,
        NOW,
    );
    let expired_release = build_verified_release(
        &root,
        "release-expired",
        b'd',
        resource_digest,
        1_900,
        1_500,
    );
    CurrentPolicyFixture {
        ledger: root.join("policy.ledger"),
        _root: None,
        release,
        other_release,
        wrong_resource_release,
        expired_release,
        policy_bytes,
        policy_signature,
    }
}

fn fixture_resource_digest() -> [u8; 32] {
    let canonical = minicbor::to_vec(compiled_resources()).unwrap();
    let mut hasher = Sha256::new();
    hasher.update(b"SAVANA_RESOURCE_PROFILE_V1\0");
    hasher.update(canonical);
    hasher.finalize().into()
}

fn current_release_target() -> Digest32 {
    let profile = fixture_profile();
    let profile_digest: [u8; 32] = Sha256::digest(&profile).into();
    let roots = fixture_policy_roots();
    let roots_digest: [u8; 32] = Sha256::digest(&roots).into();
    Digest32::new(compute_fixture_release_target(
        roots_digest,
        fixture_resource_digest(),
        profile_digest,
    ))
}

fn fixture_policy_roots() -> Vec<u8> {
    let key = signing_key();
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(1)
        .unwrap()
        .array(4)
        .unwrap()
        .str("policy-root")
        .unwrap()
        .bytes(&key.verifying_key().to_bytes())
        .unwrap()
        .u64(3)
        .unwrap()
        .bool(false)
        .unwrap();
    encoder.into_writer()
}

fn fixture_profile() -> Vec<u8> {
    let daemon = SigningKey::from_bytes(&[0x61; 32]);
    let client = SigningKey::from_bytes(&[0x62; 32]);
    let platform = if cfg!(target_os = "macos") { 1 } else { 0 };
    let (socket, policy, signature) = if cfg!(target_os = "macos") {
        (
            "/var/run/savana/kernel/kerneld.sock",
            "/Library/Application Support/Savana/Kernel/selected-policy-v1.cbor",
            "/Library/Application Support/Savana/Kernel/selected-policy-v1.sig",
        )
    } else {
        (
            "/run/savana/kernel/kerneld.sock",
            "/etc/savana/kernel/selected-policy-v1.cbor",
            "/etc/savana/kernel/selected-policy-v1.sig",
        )
    };
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(14)
        .unwrap()
        .u16(1)
        .unwrap()
        .bytes(&[0x71; 32])
        .unwrap()
        .u8(platform)
        .unwrap()
        .array(2)
        .unwrap()
        .str("daemon-key")
        .unwrap()
        .bytes(&daemon.verifying_key().to_bytes())
        .unwrap()
        .array(1)
        .unwrap()
        .array(6)
        .unwrap()
        .str("jarvis-client")
        .unwrap()
        .str("jarvis-key")
        .unwrap()
        .bytes(&client.verifying_key().to_bytes())
        .unwrap()
        .u8(0)
        .unwrap()
        .u32(1_001)
        .unwrap()
        .u32(1_003)
        .unwrap();
    let roots = fixture_policy_roots();
    let mut decoder = minicbor::Decoder::new(&roots);
    let root_count = decoder.array().unwrap().unwrap();
    assert_eq!(root_count, 1);
    encoder
        .array(1)
        .unwrap()
        .array(4)
        .unwrap()
        .str("policy-root")
        .unwrap()
        .bytes(&signing_key().verifying_key().to_bytes())
        .unwrap()
        .u64(3)
        .unwrap()
        .bool(false)
        .unwrap()
        .u32(1_002)
        .unwrap()
        .u32(1_002)
        .unwrap()
        .u32(1_001)
        .unwrap()
        .str(socket)
        .unwrap()
        .str(policy)
        .unwrap()
        .str(signature)
        .unwrap()
        .u16(0o750)
        .unwrap()
        .u16(0o660)
        .unwrap();
    encoder.into_writer()
}

fn compute_fixture_release_target(
    roots_digest: [u8; 32],
    resource_digest: [u8; 32],
    profile_digest: [u8; 32],
) -> [u8; 32] {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(7)
        .unwrap()
        .u16(1)
        .unwrap()
        .u16(0)
        .unwrap()
        .u16(0)
        .unwrap()
        .array(1)
        .unwrap()
        .u16(1)
        .unwrap()
        .bytes(&roots_digest)
        .unwrap()
        .bytes(&resource_digest)
        .unwrap()
        .bytes(&profile_digest)
        .unwrap();
    let mut hasher = Sha256::new();
    hasher.update(b"SAVANA_RELEASE_TARGET_V1\0");
    hasher.update(encoder.into_writer());
    hasher.finalize().into()
}

fn build_verified_release(
    root: &Path,
    name: &str,
    source_marker: u8,
    resource_digest: [u8; 32],
    expires_at: u64,
    verification_now: u64,
) -> VerifiedReleaseIdentity {
    let stage = root.join(name);
    let profile = fixture_profile();
    let profile_digest: [u8; 32] = Sha256::digest(&profile).into();
    let roots_digest: [u8; 32] = Sha256::digest(fixture_policy_roots()).into();
    let release_target =
        compute_fixture_release_target(roots_digest, resource_digest, profile_digest);
    let runtime_path = if cfg!(target_os = "macos") {
        "runtime/libonnxruntime.dylib"
    } else {
        "runtime/libonnxruntime.so"
    };
    let mut files = vec![
        ("bin/savana-kerneld", b"kernel-binary".to_vec()),
        ("policy/default-policy-v1.cbor", b"default-policy".to_vec()),
        ("policy/default-policy-v1.sig", vec![0x81; 64]),
        (
            "approval/producer-registry-v1.cbor",
            b"producer-registry".to_vec(),
        ),
        ("approval/ontology-v1.cbor", b"ontology".to_vec()),
        (
            "approval/approval-key-set-v1.cbor",
            b"approval-keys".to_vec(),
        ),
        (
            "model/signed-model-manifest-v1.cbor",
            b"model-manifest".to_vec(),
        ),
        ("installation/kernel-installation-profile-v1.cbor", profile),
        (runtime_path, b"onnx-runtime".to_vec()),
        ("model/assets/model.bin", b"model-asset".to_vec()),
    ];
    files.sort_by(|left, right| {
        left.0
            .len()
            .cmp(&right.0.len())
            .then_with(|| left.0.as_bytes().cmp(right.0.as_bytes()))
    });
    for (relative, bytes) in &files {
        let path = stage.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(
            &path,
            fs::Permissions::from_mode(if *relative == "bin/savana-kerneld" {
                0o555
            } else {
                0o444
            }),
        )
        .unwrap();
    }
    set_directory_modes(&stage);

    let binary_digest: [u8; 32] = Sha256::digest(b"kernel-binary").into();
    let mut manifest = minicbor::Encoder::new(Vec::new());
    manifest
        .array(25)
        .unwrap()
        .u16(1)
        .unwrap()
        .str("1.0.0")
        .unwrap()
        .u64(1)
        .unwrap()
        .bytes(&release_target)
        .unwrap()
        .str(&String::from_utf8(vec![source_marker; 40]).unwrap())
        .unwrap()
        .str("release-root")
        .unwrap()
        .bytes(&binary_digest)
        .unwrap()
        .bytes(&[0xc1; 32])
        .unwrap()
        .bytes(&[0xc2; 32])
        .unwrap()
        .u16(1)
        .unwrap()
        .u16(0)
        .unwrap()
        .u16(0)
        .unwrap()
        .array(1)
        .unwrap()
        .u16(1)
        .unwrap()
        .array(1)
        .unwrap()
        .u16(1)
        .unwrap()
        .bytes(&roots_digest)
        .unwrap()
        .u64(1)
        .unwrap()
        .bytes(&[0xd1; 32])
        .unwrap()
        .bytes(&[0xd2; 32])
        .unwrap()
        .bytes(&[0xd3; 32])
        .unwrap()
        .bytes(&[0xd4; 32])
        .unwrap()
        .bytes(&resource_digest)
        .unwrap()
        .bytes(&profile_digest)
        .unwrap()
        .array(files.len() as u64)
        .unwrap();
    for (relative, bytes) in &files {
        let digest: [u8; 32] = Sha256::digest(bytes).into();
        manifest
            .array(3)
            .unwrap()
            .str(relative)
            .unwrap()
            .u64(bytes.len() as u64)
            .unwrap()
            .bytes(&digest)
            .unwrap();
    }
    manifest.u64(1_000).unwrap().u64(expires_at).unwrap();
    let manifest_bytes = manifest.into_writer();
    let release_key = SigningKey::from_bytes(&[0x51; 32]);
    let release_signature = detached_signature(RELEASE_DOMAIN, &manifest_bytes, &release_key);
    let release_dir = stage.join("release");
    fs::create_dir_all(&release_dir).unwrap();
    let manifest_path = release_dir.join("release-manifest-v1.cbor");
    let signature_path = release_dir.join("release-manifest-v1.sig");
    fs::write(&manifest_path, &manifest_bytes).unwrap();
    fs::write(&signature_path, release_signature.as_bytes()).unwrap();
    for path in [&manifest_path, &signature_path] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o444)).unwrap();
    }
    set_directory_modes(&stage);
    let digest = Digest32::new(Sha256::digest(&manifest_bytes).into());
    let verifier = ReleaseVerifier::new(
        vec![ReleaseTrustRootV1 {
            key_id: KeyId::try_from("release-root").unwrap(),
            public_key: release_key.verifying_key().to_bytes(),
            not_before: UnixMillis::new(500),
            not_after: UnixMillis::new(5_000),
            revoked: false,
        }],
        vec![digest],
    )
    .unwrap();
    let metadata = fs::metadata(&stage).unwrap();
    let mapped = ReleaseStage::open_mapped_for_test_support(
        &stage,
        &stage.join("bin/savana-kerneld"),
        metadata.uid(),
        metadata.gid(),
    )
    .unwrap();
    verifier
        .verify_stage(&mapped, UnixMillis::new(verification_now))
        .unwrap()
}

fn set_directory_modes(root: &Path) {
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o755)).unwrap();
        for entry in fs::read_dir(&directory).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                pending.push(path);
            }
        }
    }
}

pub fn verifier_with_roots(roots: Vec<PolicyTrustRootV1>) -> PolicyVerifier {
    PolicyVerifier::new(roots, active_target()).expect("valid fixture verifier")
}

pub fn valid_policy(policy_version: u64, key_epoch: u64) -> TestPolicy {
    let authorities = (0_u8..8)
        .map(|role| Authority {
            key_id: format!("role-0{role}"),
            role,
            public_key: SigningKey::from_bytes(&[0x70 + role; 32])
                .verifying_key()
                .to_bytes(),
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
        ingress_replay_entries_per_client: limits.ingress_replay_entries_per_client(),
    }
}

const INGRESS_DOMAIN: &[u8] = b"SAVANA_INGRESS_V1\0";
const REGISTRY_DOMAIN: &[u8] = b"SAVANA_REGISTRY_V1\0";

struct SequenceRandom {
    next: AtomicU64,
}

impl RandomSource for SequenceRandom {
    fn fill(&self, output: &mut [u8]) -> Result<usize, StableCode> {
        let value = self.next.fetch_add(1, Ordering::SeqCst);
        let mut block = [0_u8; 32];
        block[..8].copy_from_slice(&value.to_be_bytes());
        output.copy_from_slice(&block);
        Ok(output.len())
    }
}

pub struct IngressFixture {
    pub engine: PolicyEngine,
    pub issuer: AuthenticatedContextIssuer,
    pub context: AuthenticatedCallContext,
    pub identity: PolicyIdentity,
    pub boot_id: BootId,
    pub connection_binding: Digest32,
    pub clock: Arc<TestClock>,
    next_nonce: AtomicU64,
}

impl IngressFixture {
    pub fn new() -> Self {
        Self::from_current(current_policy_and_identity())
    }

    pub fn with_limits(runs_per_client: u64, replay_per_client: u64) -> Self {
        let mut policy = valid_policy(7, 3);
        policy.resources.runs_per_client = runs_per_client;
        policy.resources.ingress_replay_entries_per_client = replay_per_client;
        Self::with_policy(policy)
    }

    pub fn with_policy(policy: TestPolicy) -> Self {
        Self::from_current(current_policy_and_identity_from(policy))
    }

    fn from_current((current, identity): (CurrentPolicyCapability, PolicyIdentity)) -> Self {
        let clock = clock();
        let boot_id = BootId::new([0x41; 32]);
        let random: Arc<dyn RandomSource + Send + Sync> = Arc::new(SequenceRandom {
            next: AtomicU64::new(1),
        });
        let (engine, issuer) = PolicyEngine::new(
            current,
            boot_id,
            Arc::clone(&clock) as Arc<dyn Clock + Send + Sync>,
            random,
        )
        .unwrap();
        let connection_binding = Digest32::new([0x44; 32]);
        let context = issuer
            .bind(
                ClientId::new("jarvis-client").unwrap(),
                Nonce32::new([0x33; 32]),
                connection_binding,
                identity,
                boot_id,
                1_001,
                UnixMillis::new(3_000),
            )
            .unwrap();
        Self {
            engine,
            issuer,
            context,
            identity,
            boot_id,
            connection_binding,
            clock,
            next_nonce: AtomicU64::new(0x80),
        }
    }

    pub fn begin_request(&self, role: &str, input: KernelValue) -> BeginRunRequest {
        self.begin_request_for(role, input, self.connection_binding)
    }

    pub fn begin_request_for(
        &self,
        role: &str,
        input: KernelValue,
        connection_binding: Digest32,
    ) -> BeginRunRequest {
        let commitment = IngressRequestCommitmentV1::BeginRun {
            input: input.clone(),
        };
        BeginRunRequest {
            ingress: self.ingress(
                role,
                ingress_request_digest(&commitment).unwrap(),
                self.next_nonce(),
                connection_binding,
            ),
            input,
            registry: signed_registry(),
        }
    }

    pub fn ingest_request(
        &self,
        run: savana_kernel_protocol::RunHandle,
        input: KernelValue,
    ) -> IngestUserInputRequest {
        self.ingest_request_for(run, input, self.connection_binding)
    }

    pub fn ingest_request_for(
        &self,
        run: savana_kernel_protocol::RunHandle,
        input: KernelValue,
        connection_binding: Digest32,
    ) -> IngestUserInputRequest {
        let commitment = IngressRequestCommitmentV1::IngestUserInput {
            run,
            input: input.clone(),
        };
        IngestUserInputRequest {
            run,
            envelope: self.ingress(
                "operator",
                ingress_request_digest(&commitment).unwrap(),
                self.next_nonce(),
                connection_binding,
            ),
            input,
        }
    }

    pub fn bind(
        &self,
        client_id: &str,
        connection_byte: u8,
        binding_byte: u8,
    ) -> (AuthenticatedCallContext, Digest32) {
        let binding = Digest32::new([binding_byte; 32]);
        (
            self.issuer
                .bind(
                    ClientId::new(client_id).unwrap(),
                    Nonce32::new([connection_byte; 32]),
                    binding,
                    self.identity,
                    self.boot_id,
                    1_001,
                    UnixMillis::new(3_000),
                )
                .unwrap(),
            binding,
        )
    }

    pub fn ingress(
        &self,
        role: &str,
        request_digest: Digest32,
        nonce: Nonce32,
        connection_binding: Digest32,
    ) -> SignedIngressEnvelopeV1 {
        let unsigned = IngressEnvelopeV1 {
            principal: PrincipalId::new("principal-1").unwrap(),
            conversation_id: ConversationId::new("conversation-1").unwrap(),
            request_digest,
            issued_at: UnixMillis::new(1_900),
            expires_at: UnixMillis::new(3_000),
            nonce,
            authority_session_id: Nonce32::new([0x66; 32]),
            authentication_context_digest: Digest32::new([0x55; 32]),
            role: RoleId::new(role).unwrap(),
            policy_digest: self.identity.digest,
            boot_id: self.boot_id,
            connection_binding_digest: connection_binding,
        };
        SignedIngressEnvelopeV1 {
            signature: sign_value(
                INGRESS_DOMAIN,
                &unsigned,
                &SigningKey::from_bytes(&[0x70; 32]),
            ),
            unsigned,
            key_id: KeyId::new("role-00").unwrap(),
        }
    }

    pub fn next_nonce(&self) -> Nonce32 {
        let value = self.next_nonce.fetch_add(1, Ordering::SeqCst);
        let mut bytes = [0_u8; 32];
        bytes[..8].copy_from_slice(&value.to_be_bytes());
        Nonce32::new(bytes)
    }
}

pub fn signed_registry() -> SignedRegistrySnapshotV1 {
    let unsigned = RegistrySnapshotV1 {
        version: 1,
        previous_digest: None,
        tools: vec![ToolDescriptorV1 {
            identity: ToolExecutionIdentity {
                name: ToolName::new("tool-00").unwrap(),
                descriptor_digest: Digest32::new([0x21; 32]),
                registry_version: 1,
            },
            provider_id: BoundedText::try_from("provider-1").unwrap(),
            roles: vec![RoleId::new("operator").unwrap()],
            input_schema_digest: Digest32::new([0x31; 32]),
            output_schema_digest: Digest32::new([0x32; 32]),
            attempt: AttemptKindV1::Read,
            constraint_ids: Vec::new(),
            validator_ids: Vec::new(),
            projection_digest: Digest32::new([0x33; 32]),
        }],
        issued_at: UnixMillis::new(1_900),
        expires_at: UnixMillis::new(3_000),
    };
    SignedRegistrySnapshotV1 {
        signature: sign_value(
            REGISTRY_DOMAIN,
            &unsigned,
            &SigningKey::from_bytes(&[0x72; 32]),
        ),
        unsigned,
        key_id: KeyId::new("role-02").unwrap(),
    }
}

pub fn resign_ingress(value: &mut SignedIngressEnvelopeV1) {
    value.signature = sign_value(
        INGRESS_DOMAIN,
        &value.unsigned,
        &SigningKey::from_bytes(&[0x70; 32]),
    );
}

pub fn resign_registry(value: &mut SignedRegistrySnapshotV1) {
    value.signature = sign_value(
        REGISTRY_DOMAIN,
        &value.unsigned,
        &SigningKey::from_bytes(&[0x72; 32]),
    );
}

fn sign_value<T: minicbor::Encode<()>>(domain: &[u8], value: &T, key: &SigningKey) -> Signature64 {
    let payload = minicbor::to_vec(value).unwrap();
    let mut message = Vec::with_capacity(domain.len() + payload.len());
    message.extend_from_slice(domain);
    message.extend_from_slice(&payload);
    Signature64::new(key.sign(&message).to_bytes())
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
