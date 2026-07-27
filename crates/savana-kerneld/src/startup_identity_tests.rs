#[path = "../../savana-policy-core/tests/support/mod.rs"]
pub(crate) mod policy_support;

use std::fs::{self, OpenOptions};
use std::os::fd::OwnedFd;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    mpsc::{self, RecvTimeoutError},
    Arc, MutexGuard,
};
use std::thread;
use std::time::Duration;

use crate::key_file::DaemonKeyCapability;
use crate::{DaemonConfig, DaemonError, DaemonSigningIdentity};
use ed25519_dalek::{Signer, SigningKey};
use nix::fcntl::{Flock, FlockArg};
use nix::sys::stat::{umask, Mode};
use savana_kernel_protocol::{Digest32, KeyId, Signature64, StableCode, UnixMillis};
use savana_policy_core::{
    Clock, PolicyVerifier, RandomSource, ReleaseTrustRootV1, ReleaseVerifier, VerifiedPolicyV1,
    VerifiedReleaseIdentity,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

use crate::audit::AuditSink;
use crate::bootstrap::{BootstrapEvent, BootstrapTraceGuard, PreparedRuntime};
use crate::selected_policy::{SelectedPolicySource, UpdateLockRacePoint};
use crate::server::ServerLifecycle;

const RELEASE_DOMAIN: &[u8] = b"SAVANA_RELEASE_V1\0";
const TARGET_DOMAIN: &[u8] = b"SAVANA_RELEASE_TARGET_V1\0";
const RESOURCE_DOMAIN: &[u8] = b"SAVANA_RESOURCE_PROFILE_V1\0";
const NOW: u64 = 2_000;

#[derive(Debug, Clone, Serialize)]
struct LockPublicKey {
    key_id: String,
    public_key: String,
}

#[derive(Debug, Clone, Serialize)]
struct LockClient {
    client_id: String,
    key_id: String,
    public_key: String,
    role: String,
    peer_uid: u32,
    peer_gid: u32,
}

#[derive(Debug, Clone, Serialize)]
struct LockPolicyRoot {
    key_id: String,
    public_key: String,
    epoch: u64,
    revoked: bool,
}

#[derive(Debug, Clone, Serialize)]
struct TestLock {
    schema_version: u16,
    protocol_major: u16,
    minimum_minor: u16,
    maximum_minor: u16,
    allowed_release_digests: Vec<String>,
    release_signature_digest: String,
    release_target_id: String,
    source_commit: String,
    installation_profile_digest: String,
    installation_id: String,
    platform: String,
    daemon_identity: LockPublicKey,
    daemon_clients: Vec<LockClient>,
    policy_trust_roots: Vec<LockPolicyRoot>,
    daemon_uid: u32,
    daemon_gid: u32,
    jarvis_uid: u32,
    socket_path: String,
    selected_policy_path: String,
    selected_policy_signature_path: String,
    socket_parent_mode: u16,
    socket_mode: u16,
    minimum_policy_version: u64,
    selected_policy_digest: String,
    selected_policy_signature_digest: String,
    selected_policy_version: u64,
    selected_policy_signing_key_id: String,
    selected_policy_key_epoch: u64,
    model_manifest_digest: String,
    producer_registry_digest: String,
    ontology_digest: String,
    approval_key_set_digest: String,
    resource_profile_digest: String,
}

struct StartupFixture {
    _stage: TempDir,
    stage_path: PathBuf,
    _key_dir: TempDir,
    release: VerifiedReleaseIdentity,
    policy: VerifiedPolicyV1,
    policy_signature: Signature64,
    lock: TestLock,
    key_path: PathBuf,
    expected_uid: u32,
    _process_guard: MutexGuard<'static, ()>,
}

struct TestUmaskGuard {
    previous: Mode,
}

impl TestUmaskGuard {
    fn install(mask: Mode) -> Self {
        Self {
            previous: umask(mask),
        }
    }
}

impl Drop for TestUmaskGuard {
    fn drop(&mut self) {
        umask(self.previous);
    }
}

impl StartupFixture {
    fn lock_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&self.lock).unwrap()
    }

    fn config(&self) -> Result<DaemonConfig, StableCode> {
        DaemonConfig::from_verified(
            &self.lock_bytes(),
            &self.release,
            &self.policy,
            &self.policy_signature,
        )
        .map_err(|error| error.code())
    }

    fn config_with_lock(&self, lock: &TestLock) -> Result<DaemonConfig, StableCode> {
        DaemonConfig::from_verified(
            &serde_json::to_vec(lock).unwrap(),
            &self.release,
            &self.policy,
            &self.policy_signature,
        )
        .map_err(|error| error.code())
    }
}

#[test]
fn startup_fixture_waits_for_process_global_mutation_lock() {
    let process_guard = crate::socket::PROCESS_TEST_LOCK.lock().unwrap();
    let umask_guard = TestUmaskGuard::install(Mode::from_bits_truncate(0o117));
    let (fixture_ready_tx, fixture_ready_rx) = mpsc::sync_channel(1);
    let (finish_tx, finish_rx) = mpsc::sync_channel(0);

    let worker = thread::spawn(move || {
        let fixture = startup_fixture();
        fixture_ready_tx.send(()).unwrap();
        finish_rx.recv().unwrap();
        drop(fixture);
    });

    match fixture_ready_rx.recv_timeout(Duration::from_millis(100)) {
        Err(RecvTimeoutError::Timeout) => {}
        Err(RecvTimeoutError::Disconnected) => {
            panic!("startup fixture exited while the process-global lock was held")
        }
        Ok(()) => panic!("startup fixture ran while the process-global lock was held"),
    }

    drop(umask_guard);
    drop(process_guard);

    fixture_ready_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("startup fixture should run after the process-global lock is released");
    finish_tx.send(()).unwrap();
    worker.join().unwrap();
}

#[test]
fn verified_identity_debug_views_do_not_expose_private_object_graphs() {
    let fixture = startup_fixture();
    let config = fixture.config().unwrap();

    assert_eq!(
        format!("{:?}", fixture.release),
        "VerifiedReleaseIdentity(<verified>)"
    );
    assert_eq!(
        format!("{:?}", fixture.policy),
        "VerifiedPolicyV1(<verified>)"
    );
    assert_eq!(format!("{config:?}"), "DaemonConfig(<verified>)");
}

#[test]
fn verified_lock_key_and_policy_produce_the_canonical_runtime_config() {
    let fixture = startup_fixture();
    let config = fixture.config().unwrap();
    let signing = load_daemon_signing_key(&fixture.key_path, fixture.expected_uid).unwrap();
    assert_eq!(format!("{signing:?}"), "DaemonSigningIdentity(<redacted>)");

    assert_eq!(
        config.daemon_clients()[0].peer_uid(),
        fixture.lock.jarvis_uid
    );
    assert_eq!(config.socket_path(), fixture.lock.socket_path);
    assert_eq!(config.daemon_clients().len(), 1);
}

#[test]
fn private_key_permissions_owner_shape_links_and_parent_are_strict() {
    let fixture = startup_fixture();

    fs::set_permissions(&fixture.key_path, PermissionsExt::from_mode(0o640)).unwrap();
    assert_key_error(
        &fixture.key_path,
        fixture.expected_uid,
        StableCode::IdentityKeyPermissions,
    );
    fs::set_permissions(&fixture.key_path, PermissionsExt::from_mode(0o600)).unwrap();

    assert_key_error(
        &fixture.key_path,
        fixture.expected_uid.wrapping_add(1),
        StableCode::IdentityKeyPermissions,
    );

    for bytes in [vec![0x61; 31], vec![0x61; 33]] {
        fs::write(&fixture.key_path, bytes).unwrap();
        assert_key_error(
            &fixture.key_path,
            fixture.expected_uid,
            StableCode::IdentityKeyPermissions,
        );
    }
    fs::write(&fixture.key_path, [0x61; 32]).unwrap();

    let hard_link_path = fixture.key_path.with_file_name("daemon-hard-link.seed");
    fs::hard_link(&fixture.key_path, &hard_link_path).unwrap();
    assert_key_error(
        &fixture.key_path,
        fixture.expected_uid,
        StableCode::IdentityKeyPermissions,
    );
    fs::remove_file(hard_link_path).unwrap();

    let symlink_path = fixture.key_path.with_file_name("daemon-symlink.seed");
    symlink(&fixture.key_path, &symlink_path).unwrap();
    assert_key_error(
        &symlink_path,
        fixture.expected_uid,
        StableCode::IdentityKeyPermissions,
    );

    let real_parent = tempfile::tempdir().unwrap();
    let parent_seed = real_parent.path().join("daemon.seed");
    fs::write(&parent_seed, [0x61; 32]).unwrap();
    fs::set_permissions(&parent_seed, PermissionsExt::from_mode(0o600)).unwrap();
    let alias_root = tempfile::tempdir().unwrap();
    let parent_alias = alias_root.path().join("linked-parent");
    symlink(real_parent.path(), &parent_alias).unwrap();
    assert_key_error(
        &parent_alias.join("daemon.seed"),
        fs::metadata(&parent_seed).unwrap().uid(),
        StableCode::IdentityKeyPermissions,
    );

    assert_key_error(
        &fixture.key_path.with_file_name("missing.seed"),
        fixture.expected_uid,
        StableCode::IdentityKeyPermissions,
    );
}

#[test]
fn kernel_lock_missing_unknown_duplicate_and_noncanonical_json_are_rejected() {
    let fixture = startup_fixture();
    let canonical = fixture.lock_bytes();

    let mut missing: serde_json::Value = serde_json::from_slice(&canonical).unwrap();
    missing.as_object_mut().unwrap().remove("source_commit");
    let missing = serde_json::to_vec(&missing).unwrap();
    assert_lock_bytes_error(&fixture, &missing);

    let mut unknown = canonical.clone();
    unknown.pop();
    unknown.extend_from_slice(b",\"unknown\":1}");
    assert_lock_bytes_error(&fixture, &unknown);

    let mut duplicate = b"{\"schema_version\":1,".to_vec();
    duplicate.extend_from_slice(&canonical[1..]);
    assert_lock_bytes_error(&fixture, &duplicate);

    let mut whitespace = vec![b' '];
    whitespace.extend_from_slice(&canonical);
    assert_lock_bytes_error(&fixture, &whitespace);

    let mut newline = canonical.clone();
    newline.push(b'\n');
    assert_lock_bytes_error(&fixture, &newline);

    let first_field = b"\"schema_version\":1";
    let first_field_with_delimiters = b"{\"schema_version\":1,";
    assert!(canonical.starts_with(first_field_with_delimiters));
    let mut reordered = vec![b'{'];
    reordered.extend_from_slice(&canonical[first_field_with_delimiters.len()..canonical.len() - 1]);
    reordered.push(b',');
    reordered.extend_from_slice(first_field);
    reordered.push(b'}');
    assert_ne!(reordered, canonical);
    assert_lock_bytes_error(&fixture, &reordered);

    let mut oversized = canonical;
    oversized.resize(256 * 1024 + 1, b' ');
    assert_lock_bytes_error(&fixture, &oversized);
}

#[test]
fn every_lock_manifest_profile_and_policy_identity_is_cross_checked() {
    type Mutation = Box<dyn Fn(&mut TestLock)>;
    let cases: Vec<(&str, Mutation)> = vec![
        ("lock schema", Box::new(|lock| lock.schema_version = 2)),
        ("protocol major", Box::new(|lock| lock.protocol_major = 2)),
        ("minimum minor", Box::new(|lock| lock.minimum_minor = 1)),
        ("maximum minor", Box::new(|lock| lock.maximum_minor = 1)),
        (
            "allowed release digest",
            Box::new(|lock| lock.allowed_release_digests[0] = hex([0xe1; 32])),
        ),
        (
            "multiple release digests",
            Box::new(|lock| lock.allowed_release_digests.push(hex([0xe2; 32]))),
        ),
        (
            "release signature digest",
            Box::new(|lock| lock.release_signature_digest = hex([0xe3; 32])),
        ),
        (
            "release target",
            Box::new(|lock| lock.release_target_id = hex([0xe4; 32])),
        ),
        (
            "source commit",
            Box::new(|lock| lock.source_commit = "b".repeat(40)),
        ),
        (
            "installation profile digest",
            Box::new(|lock| lock.installation_profile_digest = hex([0xe5; 32])),
        ),
        (
            "installation ID",
            Box::new(|lock| lock.installation_id = hex([0xe6; 32])),
        ),
        (
            "platform",
            Box::new(|lock| lock.platform = other_platform_name().to_owned()),
        ),
        (
            "daemon key ID",
            Box::new(|lock| lock.daemon_identity.key_id = "other-daemon".to_owned()),
        ),
        (
            "daemon public key",
            Box::new(|lock| lock.daemon_identity.public_key = hex([0xe7; 32])),
        ),
        (
            "client ID",
            Box::new(|lock| lock.daemon_clients[0].client_id = "other-client".to_owned()),
        ),
        (
            "client key ID",
            Box::new(|lock| lock.daemon_clients[0].key_id = "other-key".to_owned()),
        ),
        (
            "client public key",
            Box::new(|lock| lock.daemon_clients[0].public_key = hex([0xe8; 32])),
        ),
        (
            "client role",
            Box::new(|lock| lock.daemon_clients[0].role = "other".to_owned()),
        ),
        (
            "client peer UID",
            Box::new(|lock| lock.daemon_clients[0].peer_uid += 1),
        ),
        (
            "client peer GID",
            Box::new(|lock| lock.daemon_clients[0].peer_gid += 1),
        ),
        (
            "policy root key",
            Box::new(|lock| lock.policy_trust_roots[0].key_id = "other-root".to_owned()),
        ),
        (
            "policy root public key",
            Box::new(|lock| lock.policy_trust_roots[0].public_key = hex([0xe9; 32])),
        ),
        (
            "policy root epoch",
            Box::new(|lock| lock.policy_trust_roots[0].epoch += 1),
        ),
        (
            "policy root revoked",
            Box::new(|lock| lock.policy_trust_roots[0].revoked = true),
        ),
        ("daemon UID", Box::new(|lock| lock.daemon_uid += 1)),
        ("daemon GID", Box::new(|lock| lock.daemon_gid += 1)),
        ("JARVIS UID", Box::new(|lock| lock.jarvis_uid += 1)),
        (
            "socket path",
            Box::new(|lock| lock.socket_path.push_str(".other")),
        ),
        (
            "selected policy path",
            Box::new(|lock| lock.selected_policy_path.push_str(".other")),
        ),
        (
            "selected signature path",
            Box::new(|lock| lock.selected_policy_signature_path.push_str(".other")),
        ),
        (
            "socket parent mode",
            Box::new(|lock| lock.socket_parent_mode = 0o755),
        ),
        ("socket mode", Box::new(|lock| lock.socket_mode = 0o666)),
        (
            "minimum policy version",
            Box::new(|lock| lock.minimum_policy_version += 1),
        ),
        (
            "selected policy digest",
            Box::new(|lock| lock.selected_policy_digest = hex([0xea; 32])),
        ),
        (
            "selected policy signature digest",
            Box::new(|lock| lock.selected_policy_signature_digest = hex([0xeb; 32])),
        ),
        (
            "selected policy version",
            Box::new(|lock| lock.selected_policy_version += 1),
        ),
        (
            "selected policy key ID",
            Box::new(|lock| lock.selected_policy_signing_key_id = "other-root".to_owned()),
        ),
        (
            "selected policy key epoch",
            Box::new(|lock| lock.selected_policy_key_epoch += 1),
        ),
        (
            "model manifest identity",
            Box::new(|lock| lock.model_manifest_digest = hex([0xec; 32])),
        ),
        (
            "producer registry identity",
            Box::new(|lock| lock.producer_registry_digest = hex([0xed; 32])),
        ),
        (
            "ontology identity",
            Box::new(|lock| lock.ontology_digest = hex([0xee; 32])),
        ),
        (
            "approval key-set identity",
            Box::new(|lock| lock.approval_key_set_digest = hex([0xef; 32])),
        ),
        (
            "resource profile identity",
            Box::new(|lock| lock.resource_profile_digest = hex([0xf0; 32])),
        ),
    ];

    for (label, mutate) in cases {
        let fixture = startup_fixture();
        let mut lock = fixture.lock.clone();
        mutate(&mut lock);
        assert_eq!(
            fixture.config_with_lock(&lock).unwrap_err(),
            StableCode::IdentityReleaseMismatch,
            "{label}"
        );
    }
}

#[test]
fn lock_hex_strings_are_exact_lowercase_and_fixed_width() {
    let fixture = startup_fixture();
    for replacement in [
        fixture.lock.release_target_id.to_uppercase(),
        "ab".repeat(31),
        "gg".repeat(32),
    ] {
        let mut lock = fixture.lock.clone();
        lock.release_target_id = replacement;
        assert_eq!(
            fixture.config_with_lock(&lock).unwrap_err(),
            StableCode::IdentityReleaseMismatch
        );
    }
}

#[test]
fn selected_policy_must_contain_the_release_target() {
    let fixture = startup_fixture();
    let mut policy = policy_support::valid_policy(7, 3);
    policy.release.compatible_release_target_ids = vec![[0xfe; 32]];
    let (bytes, signature) = policy_support::signed(&policy);
    assert_eq!(
        fixture
            .release
            .policy_verifier()
            .unwrap()
            .verify(&bytes, &signature, UnixMillis::new(NOW))
            .unwrap_err()
            .code(),
        StableCode::PolicyReleaseIncompatible
    );
}

#[test]
fn selected_policy_signer_epoch_and_resource_are_lock_bound() {
    let fixture = startup_fixture();
    assert_eq!(fixture.policy.signing_key_id().as_str(), "policy-root");
    assert_eq!(
        fixture.policy.resource_profile_digest(),
        Digest32::new(hex_digest(&fixture.lock.resource_profile_digest))
    );

    let mut key_mismatch = fixture.lock.clone();
    key_mismatch.selected_policy_signing_key_id = "unknown-root".to_owned();
    assert_eq!(
        fixture.config_with_lock(&key_mismatch).unwrap_err(),
        StableCode::IdentityReleaseMismatch
    );

    let mut epoch_mismatch = fixture.lock.clone();
    epoch_mismatch.selected_policy_key_epoch += 1;
    assert_eq!(
        fixture.config_with_lock(&epoch_mismatch).unwrap_err(),
        StableCode::IdentityReleaseMismatch
    );
}

#[test]
fn selected_policy_signature_cannot_be_mixed_with_another_verified_policy() {
    let fixture = startup_fixture();
    let unrelated_signature = Signature64::new([0x99; 64]);
    let mut lock = fixture.lock.clone();
    lock.selected_policy_signature_digest = hex(sha256(unrelated_signature.as_bytes()));
    assert_eq!(
        DaemonConfig::from_verified(
            &serde_json::to_vec(&lock).unwrap(),
            &fixture.release,
            &fixture.policy,
            &unrelated_signature,
        )
        .unwrap_err()
        .code(),
        StableCode::IdentityReleaseMismatch
    );
}

#[test]
fn selected_policy_cannot_come_from_another_release_target_verifier() {
    let fixture = startup_fixture();
    let other_target = Digest32::new([0xf1; 32]);
    let mut other_policy_value = policy_support::valid_policy(7, 3);
    other_policy_value.release.compatible_release_target_ids = vec![*other_target.as_bytes()];
    let (other_policy_bytes, other_signature) = policy_support::signed(&other_policy_value);
    let other_policy = PolicyVerifier::new(
        vec![policy_support::trust_root(
            "policy-root",
            &policy_support::signing_key(),
            3,
            false,
        )],
        other_target,
    )
    .unwrap()
    .verify(&other_policy_bytes, &other_signature, UnixMillis::new(NOW))
    .unwrap();
    let mut lock = fixture.lock.clone();
    lock.selected_policy_digest = hex(*other_policy.identity().digest.as_bytes());
    lock.selected_policy_signature_digest = hex(sha256(other_signature.as_bytes()));
    lock.selected_policy_version = other_policy.identity().policy_version;
    lock.selected_policy_signing_key_id = other_policy.signing_key_id().as_str().to_owned();
    lock.selected_policy_key_epoch = other_policy.identity().key_epoch;
    assert_eq!(
        DaemonConfig::from_verified(
            &serde_json::to_vec(&lock).unwrap(),
            &fixture.release,
            &other_policy,
            &other_signature,
        )
        .unwrap_err()
        .code(),
        StableCode::IdentityReleaseMismatch
    );
}

#[test]
fn selected_policy_must_be_verified_by_the_exact_profile_root_public_key() {
    let fixture = startup_fixture();
    let target = Digest32::new(hex_digest(&fixture.lock.release_target_id));
    let attacker_key = policy_support::alternate_signing_key();
    let mut policy_value = policy_support::valid_policy(7, 3);
    policy_value.release.compatible_release_target_ids = vec![*target.as_bytes()];
    let (policy_bytes, policy_signature) =
        policy_support::signed_with_key(&policy_value, &attacker_key);
    let policy = PolicyVerifier::new(
        vec![policy_support::trust_root(
            "policy-root",
            &attacker_key,
            3,
            false,
        )],
        target,
    )
    .unwrap()
    .verify(&policy_bytes, &policy_signature, UnixMillis::new(NOW))
    .unwrap();

    let mut lock = fixture.lock.clone();
    lock.selected_policy_digest = hex(*policy.identity().digest.as_bytes());
    lock.selected_policy_signature_digest = hex(sha256(policy_signature.as_bytes()));
    assert_eq!(
        DaemonConfig::from_verified(
            &serde_json::to_vec(&lock).unwrap(),
            &fixture.release,
            &policy,
            &policy_signature,
        )
        .unwrap_err()
        .code(),
        StableCode::IdentityReleaseMismatch
    );
}

fn assert_key_error(path: &Path, expected_uid: u32, expected: StableCode) {
    assert_eq!(
        load_daemon_signing_key(path, expected_uid)
            .unwrap_err()
            .code(),
        expected
    );
}

fn load_daemon_signing_key(
    path: &Path,
    expected_uid: u32,
) -> Result<DaemonSigningIdentity, DaemonError> {
    let parent = path
        .parent()
        .ok_or_else(|| DaemonError::stable(StableCode::IdentityKeyPermissions))?;
    let parent_gid = fs::metadata(parent)
        .map_err(|_| DaemonError::stable(StableCode::IdentityKeyPermissions))?
        .gid();
    let capability =
        DaemonKeyCapability::open(path, expected_uid, parent_gid, expected_uid, parent_gid)?;
    let expected_public_key = SigningKey::from_bytes(&[0x61; 32])
        .verifying_key()
        .to_bytes();
    capability.load(&expected_public_key)
}

fn assert_lock_bytes_error(fixture: &StartupFixture, bytes: &[u8]) {
    assert_eq!(
        DaemonConfig::from_verified(
            bytes,
            &fixture.release,
            &fixture.policy,
            &fixture.policy_signature,
        )
        .unwrap_err()
        .code(),
        StableCode::IdentityReleaseMismatch
    );
}

fn startup_fixture() -> StartupFixture {
    let process_guard = crate::socket::PROCESS_TEST_LOCK.lock().unwrap();
    let stage = tempfile::tempdir().unwrap();
    let stage_path = fs::canonicalize(stage.path()).unwrap();
    let key_dir = tempfile::tempdir().unwrap();
    fs::set_permissions(key_dir.path(), PermissionsExt::from_mode(0o750)).unwrap();
    let owner = fs::metadata(key_dir.path()).unwrap();
    let daemon_uid = owner.uid();
    let daemon_gid = owner.gid();
    assert_ne!(daemon_uid, 0, "Task 4 tests require an unprivileged runner");
    assert_ne!(daemon_gid, 0, "Task 4 tests require an unprivileged runner");
    let jarvis_uid = daemon_uid.checked_add(1).unwrap();
    let socket_client_gid = daemon_gid.checked_add(1).unwrap();

    let daemon_key = SigningKey::from_bytes(&[0x61; 32]);
    let client_key = SigningKey::from_bytes(&[0x62; 32]);
    let policy_key = policy_support::signing_key();
    let release_key = SigningKey::from_bytes(&[0x51; 32]);

    let resources = policy_support::compiled_resources();
    let resource_bytes = minicbor::to_vec(resources).unwrap();
    let resource_digest = domain_digest(RESOURCE_DOMAIN, &resource_bytes);

    let policy_root_bytes = encode_policy_roots(
        "policy-root",
        &policy_key.verifying_key().to_bytes(),
        3,
        false,
    );
    let policy_roots_digest = sha256(&policy_root_bytes);
    let profile_bytes = encode_profile(
        daemon_uid,
        daemon_gid,
        socket_client_gid,
        jarvis_uid,
        &daemon_key.verifying_key().to_bytes(),
        &client_key.verifying_key().to_bytes(),
        &policy_key.verifying_key().to_bytes(),
    );
    let profile_digest = sha256(&profile_bytes);
    let release_target = compute_target(policy_roots_digest, resource_digest, profile_digest);

    let mut policy_value = policy_support::valid_policy(7, 3);
    policy_value.release.compatible_release_target_ids = vec![release_target];
    let (policy_bytes, policy_signature) = policy_support::signed(&policy_value);

    let mut files = vec![
        ("bin/savana-kerneld", b"kernel-binary".to_vec()),
        ("policy/default-policy-v1.cbor", policy_bytes.clone()),
        (
            "policy/default-policy-v1.sig",
            policy_signature.as_bytes().to_vec(),
        ),
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
            b"model-envelope".to_vec(),
        ),
        (
            "installation/kernel-installation-profile-v1.cbor",
            profile_bytes,
        ),
        (runtime_library_path(), b"onnx-runtime".to_vec()),
        ("model/assets/model.bin", b"model-asset".to_vec()),
    ];
    files.sort_by(|left, right| canonical_text_cmp(left.0, right.0));
    for (path, bytes) in &files {
        let destination = stage.path().join(path);
        fs::create_dir_all(destination.parent().unwrap()).unwrap();
        fs::write(destination, bytes).unwrap();
    }

    let manifest_bytes = encode_manifest(
        &files,
        release_target,
        policy_roots_digest,
        resource_digest,
        profile_digest,
    );
    let release_signature = detached_signature(RELEASE_DOMAIN, &manifest_bytes, &release_key);
    let release_dir = stage.path().join("release");
    fs::create_dir_all(&release_dir).unwrap();
    let manifest_path = release_dir.join("release-manifest-v1.cbor");
    let signature_path = release_dir.join("release-manifest-v1.sig");
    fs::write(&manifest_path, &manifest_bytes).unwrap();
    fs::write(&signature_path, release_signature.as_bytes()).unwrap();
    let binary = stage.path().join("bin/savana-kerneld");

    let release_digest = sha256(&manifest_bytes);
    let verifier = ReleaseVerifier::new(
        vec![ReleaseTrustRootV1 {
            key_id: KeyId::try_from("release-root").unwrap(),
            public_key: release_key.verifying_key().to_bytes(),
            not_before: UnixMillis::new(500),
            not_after: UnixMillis::new(5_000),
            revoked: false,
        }],
        vec![Digest32::new(release_digest)],
    )
    .unwrap();
    let release = verifier
        .verify_installed(
            &manifest_path,
            &signature_path,
            &binary,
            UnixMillis::new(NOW),
        )
        .unwrap();
    let policy = release
        .policy_verifier()
        .unwrap()
        .verify(&policy_bytes, &policy_signature, UnixMillis::new(NOW))
        .unwrap();

    let key_path = fs::canonicalize(key_dir.path())
        .unwrap()
        .join("daemon.seed");
    fs::write(&key_path, [0x61; 32]).unwrap();
    fs::set_permissions(&key_path, PermissionsExt::from_mode(0o600)).unwrap();

    let lock = TestLock {
        schema_version: 1,
        protocol_major: 1,
        minimum_minor: 0,
        maximum_minor: 0,
        allowed_release_digests: vec![hex(release_digest)],
        release_signature_digest: hex(sha256(release_signature.as_bytes())),
        release_target_id: hex(release_target),
        source_commit: "a".repeat(40),
        installation_profile_digest: hex(profile_digest),
        installation_id: hex([0x71; 32]),
        platform: compiled_platform_name().to_owned(),
        daemon_identity: LockPublicKey {
            key_id: "daemon-key".to_owned(),
            public_key: hex(daemon_key.verifying_key().to_bytes()),
        },
        daemon_clients: vec![LockClient {
            client_id: "jarvis-client".to_owned(),
            key_id: "jarvis-key".to_owned(),
            public_key: hex(client_key.verifying_key().to_bytes()),
            role: "jarvis_kernel_client".to_owned(),
            peer_uid: jarvis_uid,
            peer_gid: socket_client_gid,
        }],
        policy_trust_roots: vec![LockPolicyRoot {
            key_id: "policy-root".to_owned(),
            public_key: hex(policy_key.verifying_key().to_bytes()),
            epoch: 3,
            revoked: false,
        }],
        daemon_uid,
        daemon_gid,
        jarvis_uid,
        socket_path: socket_path().to_owned(),
        selected_policy_path: selected_policy_path().to_owned(),
        selected_policy_signature_path: selected_policy_signature_path().to_owned(),
        socket_parent_mode: 0o750,
        socket_mode: 0o660,
        minimum_policy_version: 1,
        selected_policy_digest: hex(*policy.identity().digest.as_bytes()),
        selected_policy_signature_digest: hex(sha256(policy_signature.as_bytes())),
        selected_policy_version: policy.identity().policy_version,
        selected_policy_signing_key_id: "policy-root".to_owned(),
        selected_policy_key_epoch: policy.identity().key_epoch,
        model_manifest_digest: hex([0xd1; 32]),
        producer_registry_digest: hex([0xd2; 32]),
        ontology_digest: hex([0xd3; 32]),
        approval_key_set_digest: hex([0xd4; 32]),
        resource_profile_digest: hex(resource_digest),
    };

    StartupFixture {
        _stage: stage,
        stage_path,
        _key_dir: key_dir,
        release,
        policy,
        policy_signature,
        lock,
        key_path,
        expected_uid: daemon_uid,
        _process_guard: process_guard,
    }
}

fn encode_profile(
    daemon_uid: u32,
    daemon_gid: u32,
    socket_client_gid: u32,
    jarvis_uid: u32,
    daemon_key: &[u8; 32],
    client_key: &[u8; 32],
    policy_key: &[u8; 32],
) -> Vec<u8> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(14)
        .unwrap()
        .u16(1)
        .unwrap()
        .bytes(&[0x71; 32])
        .unwrap()
        .u8(compiled_platform_tag())
        .unwrap()
        .array(2)
        .unwrap()
        .str("daemon-key")
        .unwrap()
        .bytes(daemon_key)
        .unwrap()
        .array(1)
        .unwrap()
        .array(6)
        .unwrap()
        .str("jarvis-client")
        .unwrap()
        .str("jarvis-key")
        .unwrap()
        .bytes(client_key)
        .unwrap()
        .u8(0)
        .unwrap()
        .u32(jarvis_uid)
        .unwrap()
        .u32(socket_client_gid)
        .unwrap();
    let roots = encode_policy_roots("policy-root", policy_key, 3, false);
    encoder.writer_mut().extend_from_slice(&roots);
    encoder
        .u32(daemon_uid)
        .unwrap()
        .u32(daemon_gid)
        .unwrap()
        .u32(jarvis_uid)
        .unwrap()
        .str(socket_path())
        .unwrap()
        .str(selected_policy_path())
        .unwrap()
        .str(selected_policy_signature_path())
        .unwrap()
        .u16(0o750)
        .unwrap()
        .u16(0o660)
        .unwrap();
    encoder.into_writer()
}

fn encode_policy_roots(key_id: &str, public_key: &[u8; 32], epoch: u64, revoked: bool) -> Vec<u8> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(1)
        .unwrap()
        .array(4)
        .unwrap()
        .str(key_id)
        .unwrap()
        .bytes(public_key)
        .unwrap()
        .u64(epoch)
        .unwrap()
        .bool(revoked)
        .unwrap();
    encoder.into_writer()
}

fn encode_manifest(
    files: &[(&str, Vec<u8>)],
    target: [u8; 32],
    roots_digest: [u8; 32],
    resource_digest: [u8; 32],
    profile_digest: [u8; 32],
) -> Vec<u8> {
    let binary_digest = sha256(
        &files
            .iter()
            .find(|(path, _)| *path == "bin/savana-kerneld")
            .unwrap()
            .1,
    );
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(25)
        .unwrap()
        .u16(1)
        .unwrap()
        .str("1.0.0")
        .unwrap()
        .u64(1)
        .unwrap()
        .bytes(&target)
        .unwrap()
        .str(&"a".repeat(40))
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
    for (path, bytes) in files {
        encoder
            .array(3)
            .unwrap()
            .str(path)
            .unwrap()
            .u64(bytes.len() as u64)
            .unwrap()
            .bytes(&sha256(bytes))
            .unwrap();
    }
    encoder.u64(1_000).unwrap().u64(4_000).unwrap();
    encoder.into_writer()
}

fn compute_target(
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
    domain_digest(TARGET_DOMAIN, &encoder.into_writer())
}

fn detached_signature(domain: &[u8], bytes: &[u8], key: &SigningKey) -> Signature64 {
    let mut message = Vec::with_capacity(domain.len() + bytes.len());
    message.extend_from_slice(domain);
    message.extend_from_slice(bytes);
    Signature64::new(key.sign(&message).to_bytes())
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn domain_digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(bytes);
    hash.finalize().into()
}

fn canonical_text_cmp(left: &str, right: &str) -> std::cmp::Ordering {
    left.len()
        .cmp(&right.len())
        .then_with(|| left.as_bytes().cmp(right.as_bytes()))
}

fn hex(bytes: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn hex_digest(value: &str) -> [u8; 32] {
    let mut bytes = [0_u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = decode_nibble(chunk[0]);
        let low = decode_nibble(chunk[1]);
        bytes[index] = (high << 4) | low;
    }
    bytes
}

fn decode_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => panic!("fixture hex is lowercase"),
    }
}

#[test]
fn update_lock_requires_exact_inode_owner_group_mode_link_and_length() {
    for corruption in [
        UpdateLockCorruption::Symlink,
        UpdateLockCorruption::Directory,
        UpdateLockCorruption::WrongOwner,
        UpdateLockCorruption::WrongGroup,
        UpdateLockCorruption::Mode0600,
        UpdateLockCorruption::Mode0644,
        UpdateLockCorruption::HardLink,
        UpdateLockCorruption::NonEmpty,
    ] {
        let installation = MappedInstallation::new();
        assert_eq!(
            installation
                .prepare_after_update_lock_corruption(corruption)
                .unwrap_err()
                .code(),
            StableCode::KernelUnavailable,
            "{corruption:?}"
        );
        assert_eq!(
            installation.ledger_bytes(),
            installation.initial_ledger_bytes()
        );
    }
}

#[test]
fn active_exclusive_updater_makes_daemon_shared_lock_fail_closed() {
    let installation = MappedInstallation::new();
    let exclusive = installation.lock_update_file_exclusive();
    assert_eq!(
        installation.prepare().unwrap_err().code(),
        StableCode::KernelUnavailable
    );
    assert_eq!(
        installation.ledger_bytes(),
        installation.initial_ledger_bytes()
    );
    drop(exclusive);
}

#[test]
fn replacing_update_lock_inode_before_or_after_flock_is_rejected() {
    for point in [
        UpdateLockRacePoint::BeforeSharedFlock,
        UpdateLockRacePoint::AfterSharedFlock,
    ] {
        let installation = MappedInstallation::new();
        assert_eq!(
            installation
                .prepare_with_update_lock_race(point)
                .unwrap_err()
                .code(),
            StableCode::KernelUnavailable
        );
        assert_eq!(
            installation.ledger_bytes(),
            installation.initial_ledger_bytes()
        );
    }
}

#[test]
fn initial_boot_order_and_shared_guard_lifetime_are_exact() {
    let installation = MappedInstallation::new();
    let trace = BootstrapTraceGuard::install();
    let mut prepared = installation
        .prepare()
        .unwrap_or_else(|error| panic!("{error:?}; trace: {:?}", trace.events()));
    let probe = prepared.selected_artifact_drop_probe();
    assert_eq!(probe.load(Ordering::Acquire), 1);
    assert_eq!(
        trace.events(),
        vec![
            BootstrapEvent::ReleaseVerified,
            BootstrapEvent::ReleaseVerifierBound,
            BootstrapEvent::LedgerLifetimeLockAcquired,
            BootstrapEvent::SelectedUpdateSharedLockAcquired,
            BootstrapEvent::CandidateRead,
            BootstrapEvent::CandidateStatelesslyVerified,
            BootstrapEvent::FixedLockVerified,
            BootstrapEvent::FinalDescriptorRecheck,
            BootstrapEvent::LedgerPersisted,
            BootstrapEvent::CurrentCapabilityReturned,
            BootstrapEvent::DaemonKeyLoaded,
            BootstrapEvent::EngineConstructed,
        ]
    );
    assert!(!installation.socket.exists());
    assert!(!installation.update_lock_exclusive_is_available());

    let mut lifecycle = ImmediateShutdownLifecycle {
        update_lock: installation.update_lock.clone(),
        saw_guard_held: false,
    };
    if installation.supports_socket_binding() {
        let (audit, _audit_reader) = installation.audit();
        let bound = prepared.bind(audit).unwrap();
        assert!(installation.socket.exists());
        assert!(!installation.update_lock_exclusive_is_available());
        bound.run(&mut lifecycle).unwrap();
    } else {
        prepared
            .exercise_startup_guard_for_test(&mut lifecycle)
            .unwrap();
    }
    assert!(lifecycle.saw_guard_held);
    assert_eq!(probe.load(Ordering::Acquire), 0);
    assert!(!installation.socket.exists());
    assert!(installation.update_lock_exclusive_is_available());
    let events = trace.events();
    assert_eq!(
        &events[events.len() - 2..],
        &[
            BootstrapEvent::WorkersActivated,
            BootstrapEvent::SelectedUpdateSharedLockReleased,
        ]
    );
}

#[test]
fn candidate_descriptors_are_not_lifetime_retained_after_activation() {
    let installation = MappedInstallation::new();
    let mut prepared = installation.prepare().unwrap();
    let probe = prepared.selected_artifact_drop_probe();
    assert_eq!(probe.load(Ordering::Acquire), 1);
    let mut lifecycle = ImmediateShutdownLifecycle {
        update_lock: installation.update_lock.clone(),
        saw_guard_held: false,
    };
    if installation.supports_socket_binding() {
        let (audit, _audit_reader) = installation.audit();
        let bound = prepared.bind(audit).unwrap();
        bound.run(&mut lifecycle).unwrap();
    } else {
        prepared
            .exercise_startup_guard_for_test(&mut lifecycle)
            .unwrap();
    }
    assert!(lifecycle.saw_guard_held);
    assert_eq!(probe.load(Ordering::Acquire), 0);
    installation.install_next_candidate_under_exclusive_lock();
    assert_ne!(
        fs::metadata(&installation.selected_policy).unwrap().ino(),
        installation.initial_selected_policy_inode
    );
}

#[test]
fn failed_worker_activation_keeps_the_guard_until_server_cleanup() {
    let installation = MappedInstallation::new();
    let mut prepared = installation.prepare().unwrap();
    let probe = prepared.selected_artifact_drop_probe();
    let mut lifecycle = FailingActivationLifecycle {
        update_lock: installation.update_lock.clone(),
        saw_guard_held: false,
    };
    if installation.supports_socket_binding() {
        let (audit, _audit_reader) = installation.audit();
        let bound = prepared.bind(audit).unwrap();
        assert_eq!(
            bound.run(&mut lifecycle).unwrap_err().code(),
            StableCode::KernelUnavailable
        );
    } else {
        assert_eq!(
            prepared
                .exercise_startup_guard_for_test(&mut lifecycle)
                .unwrap_err()
                .code(),
            StableCode::KernelUnavailable
        );
    }
    assert!(lifecycle.saw_guard_held);
    assert_eq!(probe.load(Ordering::Acquire), 0);
    assert!(!installation.socket.exists());
    assert!(installation.update_lock_exclusive_is_available());
}

#[derive(Debug, Clone, Copy)]
enum UpdateLockCorruption {
    Symlink,
    Directory,
    WrongOwner,
    WrongGroup,
    Mode0600,
    Mode0644,
    HardLink,
    NonEmpty,
}

pub(crate) struct MappedInstallation {
    _fixture: StartupFixture,
    _root: TempDir,
    config: PathBuf,
    kernel_lock: PathBuf,
    selected_policy: PathBuf,
    selected_signature: PathBuf,
    update_lock: PathBuf,
    ledger: PathBuf,
    socket: PathBuf,
    initial_selected_policy_inode: u64,
    uid: u32,
    gid: u32,
}

impl MappedInstallation {
    pub(crate) fn new() -> Self {
        let fixture = startup_fixture();
        let root = tempfile::Builder::new()
            .prefix("skd-")
            .tempdir_in("/private/tmp")
            .unwrap();
        let root_path = fs::canonicalize(root.path()).unwrap();
        nix::unistd::chown(
            &root_path,
            None,
            Some(nix::unistd::Gid::from_raw(nix::unistd::getegid().as_raw())),
        )
        .unwrap();
        fs::set_permissions(&root_path, PermissionsExt::from_mode(0o700)).unwrap();
        let owner = fs::metadata(&root_path).unwrap();
        let uid = owner.uid();
        let gid = owner.gid();

        let release_stage = mapped_path(&root_path, release_stage_path());
        copy_release_stage(&fixture.stage_path, &release_stage);

        let config = mapped_path(&root_path, "/etc/savana/kerneld-bootstrap-v1.json");
        let kernel_lock = mapped_path(&root_path, "/etc/savana/kernel-lock.json");
        let selected_policy = mapped_path(&root_path, selected_policy_path());
        let selected_signature = mapped_path(&root_path, selected_policy_signature_path());
        let update_lock = selected_policy
            .parent()
            .unwrap()
            .join(".selected-policy-v1.update.lock");
        let daemon_key = mapped_path(&root_path, daemon_key_path());
        let ledger = mapped_path(&root_path, ledger_path());
        let socket = mapped_path(&root_path, socket_path());

        ensure_directory(config.parent().unwrap(), 0o755);
        ensure_directory(kernel_lock.parent().unwrap(), 0o755);
        ensure_directory(selected_policy.parent().unwrap(), 0o755);
        ensure_directory(daemon_key.parent().unwrap(), 0o750);
        ensure_directory(ledger.parent().unwrap(), 0o700);
        ensure_directory(socket.parent().unwrap(), 0o750);
        ensure_directory(ledger.parent().unwrap().parent().unwrap(), 0o755);

        write_mapped_file(
            &config,
            &bootstrap_anchor_bytes(fixture.release.release_digest()),
            0o444,
        );
        write_mapped_file(&kernel_lock, &fixture.lock_bytes(), 0o444);
        write_mapped_file(
            &selected_policy,
            &fs::read(fixture.stage_path.join("policy/default-policy-v1.cbor")).unwrap(),
            0o444,
        );
        write_mapped_file(
            &selected_signature,
            &fs::read(fixture.stage_path.join("policy/default-policy-v1.sig")).unwrap(),
            0o444,
        );
        write_mapped_file(&update_lock, &[], 0o640);
        write_mapped_file(&daemon_key, &[0x61; 32], 0o600);

        let initial_selected_policy_inode = fs::metadata(&selected_policy).unwrap().ino();
        Self {
            _fixture: fixture,
            _root: root,
            config,
            kernel_lock,
            selected_policy,
            selected_signature,
            update_lock,
            ledger,
            socket,
            initial_selected_policy_inode,
            uid,
            gid,
        }
    }

    pub(crate) fn prepare(&self) -> Result<PreparedRuntime, DaemonError> {
        PreparedRuntime::prepare_with_dependencies(
            &self.config,
            savana_kernel_protocol::BootId::new([0x31; 32]),
            Arc::new(FixedClock::default()),
            Arc::new(FixedRandom),
        )
    }

    pub(crate) fn prepare_with_clock_for_test(
        &self,
        clock: Arc<dyn Clock + Send + Sync>,
    ) -> Result<PreparedRuntime, DaemonError> {
        PreparedRuntime::prepare_with_dependencies(
            &self.config,
            savana_kernel_protocol::BootId::new([0x31; 32]),
            clock,
            Arc::new(FixedRandom),
        )
    }

    pub(crate) fn prepare_with_random_for_entropy_test(
        &self,
        boot_id: savana_kernel_protocol::BootId,
        random: Arc<dyn RandomSource + Send + Sync>,
    ) -> Result<PreparedRuntime, DaemonError> {
        PreparedRuntime::prepare_with_dependencies(
            &self.config,
            boot_id,
            Arc::new(FixedClock::default()),
            random,
        )
    }

    fn prepare_after_update_lock_corruption(
        &self,
        corruption: UpdateLockCorruption,
    ) -> Result<PreparedRuntime, DaemonError> {
        self.corrupt_update_lock(corruption);
        match corruption {
            UpdateLockCorruption::WrongOwner => self.prepare_with_source_hook(Box::new({
                let uid = self.uid.wrapping_add(1);
                let gid = self.gid;
                move |source| source.install_update_lock_owner_override(uid, gid)
            })),
            UpdateLockCorruption::WrongGroup => self.prepare_with_source_hook(Box::new({
                let uid = self.uid;
                let gid = self.gid.wrapping_add(1);
                move |source| source.install_update_lock_owner_override(uid, gid)
            })),
            _ => self.prepare(),
        }
    }

    fn prepare_with_update_lock_race(
        &self,
        point: UpdateLockRacePoint,
    ) -> Result<PreparedRuntime, DaemonError> {
        let replacement = self.update_lock.with_extension("replacement");
        write_mapped_file(&replacement, &[], 0o640);
        let update_lock = self.update_lock.clone();
        self.prepare_with_source_hook(Box::new(move |source| {
            source.install_update_lock_race_hook(
                point,
                Box::new(move || fs::rename(&replacement, update_lock).unwrap()),
            );
        }))
    }

    fn prepare_with_source_hook(
        &self,
        source_hook: Box<dyn FnOnce(&SelectedPolicySource) + Send>,
    ) -> Result<PreparedRuntime, DaemonError> {
        PreparedRuntime::prepare_with_source_hook_for_test(
            &self.config,
            savana_kernel_protocol::BootId::new([0x31; 32]),
            Arc::new(FixedClock::default()),
            Arc::new(FixedRandom),
            source_hook,
        )
    }

    fn corrupt_update_lock(&self, corruption: UpdateLockCorruption) {
        match corruption {
            UpdateLockCorruption::Symlink => {
                fs::remove_file(&self.update_lock).unwrap();
                symlink("selected-policy-v1.cbor", &self.update_lock).unwrap();
            }
            UpdateLockCorruption::Directory => {
                fs::remove_file(&self.update_lock).unwrap();
                fs::create_dir(&self.update_lock).unwrap();
            }
            UpdateLockCorruption::WrongOwner | UpdateLockCorruption::WrongGroup => {}
            UpdateLockCorruption::Mode0600 => set_mode(&self.update_lock, 0o600),
            UpdateLockCorruption::Mode0644 => set_mode(&self.update_lock, 0o644),
            UpdateLockCorruption::HardLink => {
                fs::hard_link(
                    &self.update_lock,
                    self.update_lock.with_extension("hard-link"),
                )
                .unwrap();
            }
            UpdateLockCorruption::NonEmpty => {
                set_mode(&self.update_lock, 0o640);
                fs::write(&self.update_lock, b"not empty").unwrap();
                set_mode(&self.update_lock, 0o640);
            }
        }
    }

    fn lock_update_file_exclusive(&self) -> Flock<std::fs::File> {
        Flock::lock(
            OpenOptions::new()
                .read(true)
                .open(&self.update_lock)
                .unwrap(),
            FlockArg::LockExclusiveNonblock,
        )
        .unwrap()
    }

    fn update_lock_exclusive_is_available(&self) -> bool {
        match Flock::lock(
            OpenOptions::new()
                .read(true)
                .open(&self.update_lock)
                .unwrap(),
            FlockArg::LockExclusiveNonblock,
        ) {
            Ok(lock) => {
                drop(lock);
                true
            }
            Err(_) => false,
        }
    }

    fn supports_socket_binding(&self) -> bool {
        match std::os::unix::net::UnixListener::bind(&self.socket) {
            Ok(listener) => {
                drop(listener);
                fs::remove_file(&self.socket).unwrap();
                true
            }
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => false,
            Err(error) => {
                panic!("fixture Unix-socket capability probe failed unexpectedly: {error}")
            }
        }
    }

    pub(crate) fn ledger_bytes(&self) -> Option<Vec<u8>> {
        match fs::read(&self.ledger) {
            Ok(bytes) => Some(bytes),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => panic!("could not read fixture ledger: {error}"),
        }
    }

    const fn initial_ledger_bytes(&self) -> Option<Vec<u8>> {
        None
    }

    fn audit(&self) -> (Arc<AuditSink>, std::os::unix::net::UnixStream) {
        let (reader, writer) = std::os::unix::net::UnixStream::pair().unwrap();
        let writer: OwnedFd = writer.into();
        let audit = AuditSink::from_owned_for_test(
            crate::runtime_deps::AuditSecret::from_test_bytes([0xa5; 32]),
            writer,
            Duration::from_millis(100),
        )
        .unwrap();
        (Arc::new(audit), reader)
    }

    fn install_next_candidate_under_exclusive_lock(&self) {
        let exclusive = self.lock_update_file_exclusive();
        let replacement = self.selected_policy.with_extension("next");
        write_mapped_file(
            &replacement,
            &fs::read(&self.selected_policy).unwrap(),
            0o444,
        );
        fs::rename(&replacement, &self.selected_policy).unwrap();
        drop(exclusive);
    }

    pub(crate) fn install_next_candidate(&self) -> savana_policy_core::PolicyIdentity {
        self.install_candidate_for_test(8, 1_000)
    }

    pub(crate) fn install_candidate_for_test(
        &self,
        policy_version: u64,
        issued_at: u64,
    ) -> savana_policy_core::PolicyIdentity {
        let mut policy = policy_support::valid_policy(policy_version, 3);
        policy.issued_at = issued_at;
        policy.release.compatible_release_target_ids =
            vec![*self._fixture.release.release_target_id().as_bytes()];
        let (policy_bytes, signature) = policy_support::signed(&policy);
        let identity = self
            ._fixture
            .release
            .policy_verifier()
            .unwrap()
            .verify(&policy_bytes, &signature, UnixMillis::new(NOW))
            .unwrap()
            .identity();
        let mut lock = self._fixture.lock.clone();
        lock.selected_policy_digest = hex(*identity.digest.as_bytes());
        lock.selected_policy_signature_digest = hex(sha256(signature.as_bytes()));
        lock.selected_policy_version = identity.policy_version;
        lock.selected_policy_key_epoch = identity.key_epoch;
        let lock_bytes = serde_json::to_vec(&lock).unwrap();

        let lock_next = self.kernel_lock.with_file_name("kernel-lock.json.next");
        let policy_next = self
            .selected_policy
            .with_file_name("selected-policy-v1.cbor.next");
        let signature_next = self
            .selected_signature
            .with_file_name("selected-policy-v1.sig.next");
        write_mapped_file(&lock_next, &lock_bytes, 0o444);
        write_mapped_file(&policy_next, &policy_bytes, 0o444);
        write_mapped_file(&signature_next, signature.as_bytes(), 0o444);
        let exclusive = self.lock_update_file_exclusive();
        fs::rename(lock_next, &self.kernel_lock).unwrap();
        fs::rename(policy_next, &self.selected_policy).unwrap();
        fs::rename(signature_next, &self.selected_signature).unwrap();
        drop(exclusive);
        identity
    }
}

struct ImmediateShutdownLifecycle {
    update_lock: PathBuf,
    saw_guard_held: bool,
}

impl ServerLifecycle for ImmediateShutdownLifecycle {
    fn workers_started(&mut self) -> Result<(), StableCode> {
        self.saw_guard_held = !update_lock_exclusive_is_available(&self.update_lock);
        Ok(())
    }

    fn poll_shutdown(&mut self) -> Result<bool, StableCode> {
        Ok(true)
    }
}

struct FailingActivationLifecycle {
    update_lock: PathBuf,
    saw_guard_held: bool,
}

impl ServerLifecycle for FailingActivationLifecycle {
    fn workers_started(&mut self) -> Result<(), StableCode> {
        self.saw_guard_held = !update_lock_exclusive_is_available(&self.update_lock);
        Err(StableCode::KernelUnavailable)
    }

    fn poll_shutdown(&mut self) -> Result<bool, StableCode> {
        Ok(false)
    }
}

#[derive(Default)]
struct FixedClock {
    monotonic: AtomicU64,
}

impl Clock for FixedClock {
    fn wall_now(&self) -> Result<UnixMillis, StableCode> {
        Ok(UnixMillis::new(NOW))
    }

    fn monotonic_now_millis(&self) -> Result<u64, StableCode> {
        Ok(self.monotonic.fetch_add(1, Ordering::AcqRel))
    }
}

struct FixedRandom;

impl RandomSource for FixedRandom {
    fn fill(&self, output: &mut [u8]) -> Result<usize, StableCode> {
        output.fill(0x41);
        Ok(output.len())
    }
}

#[derive(Serialize)]
struct BootstrapFixtureTrustRoot {
    key_id: String,
    public_key: String,
    not_before_unix_ms: u64,
    not_after_unix_ms: u64,
    revoked: bool,
}

#[derive(Serialize)]
struct BootstrapFixture {
    schema_version: u16,
    platform: &'static str,
    release_trust_roots: Vec<BootstrapFixtureTrustRoot>,
    allowed_release_digest: String,
}

fn bootstrap_anchor_bytes(release_digest: Digest32) -> Vec<u8> {
    let release_key = SigningKey::from_bytes(&[0x51; 32]);
    serde_json::to_vec(&BootstrapFixture {
        schema_version: 1,
        platform: compiled_platform_name(),
        release_trust_roots: vec![BootstrapFixtureTrustRoot {
            key_id: "release-root".to_owned(),
            public_key: hex(release_key.verifying_key().to_bytes()),
            not_before_unix_ms: 500,
            not_after_unix_ms: 5_000,
            revoked: false,
        }],
        allowed_release_digest: hex(*release_digest.as_bytes()),
    })
    .unwrap()
}

fn mapped_path(root: &Path, production_path: &str) -> PathBuf {
    root.join(production_path.trim_start_matches('/'))
}

#[cfg(target_os = "linux")]
const fn compiled_platform_name() -> &'static str {
    "linux"
}

#[cfg(target_os = "macos")]
const fn compiled_platform_name() -> &'static str {
    "macos"
}

#[cfg(target_os = "linux")]
const fn other_platform_name() -> &'static str {
    "macos"
}

#[cfg(target_os = "macos")]
const fn other_platform_name() -> &'static str {
    "linux"
}

#[cfg(target_os = "linux")]
const fn compiled_platform_tag() -> u8 {
    0
}

#[cfg(target_os = "macos")]
const fn compiled_platform_tag() -> u8 {
    1
}

#[cfg(target_os = "linux")]
const fn runtime_library_path() -> &'static str {
    "runtime/libonnxruntime.so"
}

#[cfg(target_os = "macos")]
const fn runtime_library_path() -> &'static str {
    "runtime/libonnxruntime.dylib"
}

#[cfg(target_os = "linux")]
const fn release_stage_path() -> &'static str {
    "/opt/savana/kernel/release"
}

#[cfg(target_os = "macos")]
const fn release_stage_path() -> &'static str {
    "/Library/Application Support/Savana/Kernel/release"
}

#[cfg(target_os = "linux")]
const fn daemon_key_path() -> &'static str {
    "/var/lib/savana/kernel/private/daemon-identity-v1.seed"
}

#[cfg(target_os = "macos")]
const fn daemon_key_path() -> &'static str {
    "/Library/Application Support/Savana/Kernel/private/daemon-identity-v1.seed"
}

#[cfg(target_os = "linux")]
const fn ledger_path() -> &'static str {
    "/var/lib/savana/kernel/state/policy-ledger-v1.cbor"
}

#[cfg(target_os = "macos")]
const fn ledger_path() -> &'static str {
    "/Library/Application Support/Savana/Kernel/state/policy-ledger-v1.cbor"
}

#[cfg(target_os = "linux")]
const fn selected_policy_path() -> &'static str {
    "/etc/savana/kernel/selected-policy-v1.cbor"
}

#[cfg(target_os = "macos")]
const fn selected_policy_path() -> &'static str {
    "/Library/Application Support/Savana/Kernel/selected-policy-v1.cbor"
}

#[cfg(target_os = "linux")]
const fn selected_policy_signature_path() -> &'static str {
    "/etc/savana/kernel/selected-policy-v1.sig"
}

#[cfg(target_os = "macos")]
const fn selected_policy_signature_path() -> &'static str {
    "/Library/Application Support/Savana/Kernel/selected-policy-v1.sig"
}

#[cfg(target_os = "linux")]
const fn socket_path() -> &'static str {
    "/run/savana/kernel/kerneld.sock"
}

#[cfg(target_os = "macos")]
const fn socket_path() -> &'static str {
    "/var/run/savana/kernel/kerneld.sock"
}

fn ensure_directory(path: &Path, mode: u32) {
    fs::create_dir_all(path).unwrap();
    set_mode(path, mode);
}

fn write_mapped_file(path: &Path, bytes: &[u8], mode: u32) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap_or_else(|error| {
        let parent = fs::metadata(path.parent().unwrap()).expect("fixture parent metadata");
        panic!(
            "write mapped fixture file {} (parent mode {:o}, uid {}, gid {}): {error}",
            path.display(),
            parent.mode() & 0o7777,
            parent.uid(),
            parent.gid(),
        )
    });
    set_mode(path, mode);
}

fn copy_release_stage(source: &Path, destination: &Path) {
    ensure_directory(destination, 0o755);
    for entry in fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let metadata = entry.metadata().unwrap();
        if metadata.is_dir() {
            copy_release_stage(&source_path, &destination_path);
        } else {
            fs::copy(&source_path, &destination_path).unwrap();
            let mode = if source_path
                .file_name()
                .is_some_and(|name| name == "savana-kerneld")
                && source_path
                    .parent()
                    .and_then(Path::file_name)
                    .is_some_and(|name| name == "bin")
            {
                0o555
            } else {
                0o444
            };
            set_mode(&destination_path, mode);
        }
    }
}

fn update_lock_exclusive_is_available(path: &Path) -> bool {
    match Flock::lock(
        OpenOptions::new().read(true).open(path).unwrap(),
        FlockArg::LockExclusiveNonblock,
    ) {
        Ok(lock) => {
            drop(lock);
            true
        }
        Err(_) => false,
    }
}

fn set_mode(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}
