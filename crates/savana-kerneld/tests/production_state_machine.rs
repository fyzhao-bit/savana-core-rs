#![cfg(feature = "test-support")]

#[path = "../../savana-policy-core/tests/support/mod.rs"]
mod policy_support;

use std::fs;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, Signer, SigningKey};
use nix::sys::signal::{kill, Signal};
use nix::unistd::{getegid, geteuid, Pid};
use savana_kernel_protocol::{
    decode_server_message, encode_client_message, read_frame, write_frame, BootId, ClientFinishV1,
    ClientHelloV1, ClientMessageV1, Digest32, HardLimits, Nonce32, OperationV1, ProtocolVersion,
    RequestEnvelopeV1, RequestId, RequestedMode, ResponseBodyV1, ResponsePayloadV1,
    ServerMessageV1, Signature64, StableCode, UnixMillis,
};
use savana_policy_core::{Clock, RandomSource};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

const RELEASE_DOMAIN: &[u8] = b"SAVANA_RELEASE_V1\0";
const TARGET_DOMAIN: &[u8] = b"SAVANA_RELEASE_TARGET_V1\0";
const RESOURCE_DOMAIN: &[u8] = b"SAVANA_RESOURCE_PROFILE_V1\0";
const DAEMON_HELLO_DOMAIN: &[u8] = b"SAVANA_DAEMON_HELLO_V1\0";
const CLIENT_FINISH_DOMAIN: &[u8] = b"SAVANA_CLIENT_FINISH_V1\0";
const POLICY_VERSION: u64 = 7;
const POLICY_EPOCH: u64 = 3;

#[derive(Serialize)]
struct BootstrapTrustRoot {
    key_id: String,
    public_key: String,
    not_before_unix_ms: u64,
    not_after_unix_ms: u64,
    revoked: bool,
}

#[derive(Serialize)]
struct Bootstrap {
    schema_version: u16,
    platform: String,
    release_trust_roots: Vec<BootstrapTrustRoot>,
    allowed_release_digest: String,
}

#[derive(Clone, Serialize)]
struct LockPublicKey {
    key_id: String,
    public_key: String,
}

#[derive(Clone, Serialize)]
struct LockClient {
    client_id: String,
    key_id: String,
    public_key: String,
    role: String,
    peer_uid: u32,
    peer_gid: u32,
}

#[derive(Clone, Serialize)]
struct LockPolicyRoot {
    key_id: String,
    public_key: String,
    epoch: u64,
    revoked: bool,
}

#[derive(Serialize)]
struct KernelLock {
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

struct Installation {
    _temporary: TempDir,
    config: PathBuf,
    executable: PathBuf,
    release_manifest: PathBuf,
    selected_policy: PathBuf,
    daemon_key: PathBuf,
    socket: PathBuf,
    ledger: PathBuf,
    state_lock: PathBuf,
    kernel_lock: PathBuf,
    kernel_lock_bytes: Vec<u8>,
    expected_ledger: Vec<u8>,
    release_digest: Digest32,
    policy_digest: Digest32,
    resource_profile_digest: Digest32,
    canary: String,
}

#[derive(Debug, Clone, Copy)]
enum Corruption {
    Bootstrap,
    ReleaseManifest,
    SelectedPolicy,
    DaemonKey,
}

impl Corruption {
    const ALL: [Self; 4] = [
        Self::Bootstrap,
        Self::ReleaseManifest,
        Self::SelectedPolicy,
        Self::DaemonKey,
    ];
}

#[test]
fn complete_mapped_installation_authenticates_health_and_retains_durable_state() {
    let installation = Installation::build();
    let host_socket_available = host_supports_unix_listener();
    let mut child = Command::new(&installation.executable)
        .arg("--config")
        .arg(&installation.config)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut authenticated_health = false;
    loop {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        if installation.socket.exists() {
            assert_authenticated_health(&installation);
            authenticated_health = true;
            kill(
                Pid::from_raw(i32::try_from(child.id()).unwrap()),
                Signal::SIGTERM,
            )
            .unwrap();
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let output = child.wait_with_output().unwrap();
            panic!(
                "mapped daemon neither exited nor bound before deadline: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        thread::sleep(Duration::from_millis(10));
    }

    let output = child.wait_with_output().unwrap();
    assert_process_result(&output, authenticated_health, host_socket_available);
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&output.stderr).contains(&installation.canary));
    assert!(!installation.socket.exists());

    assert_eq!(
        fs::read(&installation.ledger).unwrap(),
        installation.expected_ledger
    );
    assert_regular_mode(&installation.ledger, 0o600);
    assert_regular_mode(&installation.state_lock, 0o600);
    assert_eq!(
        fs::read(&installation.kernel_lock).unwrap(),
        installation.kernel_lock_bytes
    );
    assert_regular_mode(&installation.kernel_lock, 0o444);
}

#[test]
fn corrupt_bootstrap_release_policy_and_key_never_leave_a_socket() {
    for corruption in Corruption::ALL {
        let installation = Installation::build();
        installation.corrupt(corruption);
        let output = installation.spawn_and_wait();
        assert!(!output.status.success(), "{corruption:?}");
        assert!(output.stdout.is_empty(), "{corruption:?}");
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert_eq!(stderr.lines().count(), 1, "{corruption:?}: {stderr}");
        assert!(
            stderr.starts_with(r#"{"event":"BootstrapFailed","code":""#),
            "{corruption:?}: {stderr}"
        );
        assert!(stderr.ends_with("\"}\n"), "{corruption:?}: {stderr}");
        assert!(
            !stderr.contains("IDENTITY_SOCKET_PERMISSIONS"),
            "{corruption:?}: {stderr}"
        );
        assert!(!stderr.contains(&installation.canary), "{corruption:?}");
        assert!(!installation.socket.exists(), "{corruption:?}");
        if matches!(corruption, Corruption::DaemonKey) {
            assert_eq!(
                fs::read(&installation.ledger).unwrap(),
                installation.expected_ledger,
                "{corruption:?}"
            );
        } else {
            assert!(!installation.ledger.exists(), "{corruption:?}");
        }
    }
}

#[test]
fn socket_permission_fallback_requires_an_independent_host_denial() {
    assert!(socket_permission_fallback_allowed(false));
    assert!(!socket_permission_fallback_allowed(true));
}

#[test]
fn daemon_implements_core_dependencies_and_pins_one_boot_across_components() {
    let installation = Installation::build();
    let identities = installation
        .prepare_with_fault(DependencyFault::Healthy)
        .unwrap();
    assert_ne!(identities.engine_boot_id.as_bytes(), &[0; 32]);
    assert_eq!(identities.engine_boot_id, identities.handshake_boot_id);
    assert_eq!(
        identities.engine_policy_identity,
        identities.handshake_policy_identity
    );

    for fault in [
        DependencyFault::WallError(StableCode::PolicyExpired),
        DependencyFault::RandomError(StableCode::ProtocolIo),
        DependencyFault::RandomShort,
        DependencyFault::RandomZero,
        DependencyFault::MonotonicRegression,
    ] {
        let installation = Installation::build();
        assert_eq!(
            installation.prepare_with_fault(fault).unwrap_err().code(),
            StableCode::KernelUnavailable
        );
        assert!(!installation.socket.exists());
    }
}

#[derive(Debug, Clone, Copy)]
enum DependencyFault {
    Healthy,
    WallError(StableCode),
    RandomError(StableCode),
    RandomShort,
    RandomZero,
    MonotonicRegression,
}

struct TestDependencies {
    fault: DependencyFault,
    monotonic_calls: AtomicUsize,
}

impl TestDependencies {
    const fn new(fault: DependencyFault) -> Self {
        Self {
            fault,
            monotonic_calls: AtomicUsize::new(0),
        }
    }
}

impl Clock for TestDependencies {
    fn wall_now(&self) -> Result<UnixMillis, StableCode> {
        match self.fault {
            DependencyFault::WallError(code) => Err(code),
            _ => Ok(UnixMillis::new(system_now_ms())),
        }
    }

    fn monotonic_now_millis(&self) -> Result<u64, StableCode> {
        let call = self.monotonic_calls.fetch_add(1, Ordering::AcqRel);
        match self.fault {
            DependencyFault::MonotonicRegression => Ok(if call == 0 { 9 } else { 8 }),
            _ => Ok(u64::try_from(call).unwrap()),
        }
    }
}

impl RandomSource for TestDependencies {
    fn fill(&self, output: &mut [u8]) -> Result<usize, StableCode> {
        match self.fault {
            DependencyFault::RandomError(code) => Err(code),
            DependencyFault::RandomShort => {
                output.fill(0x41);
                Ok(output.len().saturating_sub(1))
            }
            DependencyFault::RandomZero => {
                output.fill(0);
                Ok(output.len())
            }
            _ => {
                output.fill(0x41);
                Ok(output.len())
            }
        }
    }
}

#[test]
fn durable_policy_rejection_precedes_daemon_seed_read_in_real_startup() {
    let installation = Installation::build();
    let newer_ledger = policy_support::encode_ledger(POLICY_VERSION + 1, POLICY_EPOCH, [0xe1; 32]);
    fs::write(&installation.ledger, &newer_ledger).unwrap();
    set_mode(&installation.ledger, 0o600);
    installation.corrupt(Corruption::DaemonKey);

    let output = installation.spawn_and_wait();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        "{\"event\":\"BootstrapFailed\",\"code\":\"POLICY_ROLLBACK\"}\n"
    );
    assert_eq!(fs::read(&installation.ledger).unwrap(), newer_ledger);
    assert!(!installation.socket.exists());
}

fn host_supports_unix_listener() -> bool {
    let temporary = tempfile::tempdir().unwrap();
    let socket = temporary.path().join("capability.sock");
    match UnixListener::bind(&socket) {
        Ok(listener) => {
            drop(listener);
            true
        }
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => false,
        Err(error) => panic!("independent Unix-listener probe failed unexpectedly: {error}"),
    }
}

const fn socket_permission_fallback_allowed(host_socket_available: bool) -> bool {
    !host_socket_available
}

fn assert_authenticated_health(installation: &Installation) {
    let limits = HardLimits::COMPILED
        .lower(&policy_support::compiled_resources())
        .unwrap();
    let mut stream = UnixStream::connect(&installation.socket).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();

    let client_key = SigningKey::from_bytes(&[0x62; 32]);
    let hello = ClientHelloV1 {
        client_nonce: Nonce32::new([0x91; 32]),
        supported_versions: vec![ProtocolVersion::new(1, 0)],
        client_id: "jarvis-client".try_into().unwrap(),
        client_key_id: "jarvis-key".try_into().unwrap(),
        requested_mode: RequestedMode::Required,
    };
    write_client(&mut stream, &ClientMessageV1::Hello(hello.clone()), &limits);
    let signed = match read_server(&mut stream, &limits) {
        ServerMessageV1::Hello(signed) => signed,
        other => panic!("expected signed server hello, got {other:?}"),
    };
    assert_eq!(signed.transcript.client, hello);

    let transcript_bytes = minicbor::to_vec(&signed.transcript).unwrap();
    let mut daemon_signature_input =
        Vec::with_capacity(DAEMON_HELLO_DOMAIN.len() + transcript_bytes.len());
    daemon_signature_input.extend_from_slice(DAEMON_HELLO_DOMAIN);
    daemon_signature_input.extend_from_slice(&transcript_bytes);
    SigningKey::from_bytes(&[0x61; 32])
        .verifying_key()
        .verify_strict(
            &daemon_signature_input,
            &Signature::from_bytes(signed.signature.as_bytes()),
        )
        .unwrap();

    let identity = &signed.transcript.server;
    assert_eq!(identity.daemon_key_id.as_str(), "daemon-key");
    assert_eq!(identity.protocol, ProtocolVersion::new(1, 0));
    assert_eq!(identity.release_digest, installation.release_digest);
    assert_eq!(identity.policy_digest, installation.policy_digest);
    assert_eq!(identity.policy_version, POLICY_VERSION);
    assert_eq!(identity.model_manifest_digest, Digest32::new([0xd1; 32]));
    assert_eq!(identity.approval_key_set_digest, Digest32::new([0xd4; 32]));
    assert_eq!(
        identity.resource_profile_digest,
        installation.resource_profile_digest
    );

    let transcript_digest = Digest32::new(Sha256::digest(&transcript_bytes).into());
    let mut finish_input = Vec::with_capacity(CLIENT_FINISH_DOMAIN.len() + 32);
    finish_input.extend_from_slice(CLIENT_FINISH_DOMAIN);
    finish_input.extend_from_slice(transcript_digest.as_bytes());
    write_client(
        &mut stream,
        &ClientMessageV1::Finish(ClientFinishV1 {
            transcript_digest,
            signature: Signature64::new(client_key.sign(&finish_input).to_bytes()),
        }),
        &limits,
    );
    match read_server(&mut stream, &limits) {
        ServerMessageV1::Accepted(accepted) => {
            assert_eq!(accepted.boot_id, identity.boot_id);
            assert_eq!(accepted.protocol, identity.protocol);
        }
        other => panic!("expected handshake acceptance, got {other:?}"),
    }

    let request_id = RequestId::new([0xa1; 16]);
    write_client(
        &mut stream,
        &ClientMessageV1::Request(RequestEnvelopeV1 {
            version: ProtocolVersion::new(1, 0),
            request_id,
            deadline_unix_ms: UnixMillis::new(system_now_ms().checked_add(30_000).unwrap()),
            operation: OperationV1::Health,
        }),
        &limits,
    );
    let response = match read_server(&mut stream, &limits) {
        ServerMessageV1::Response(response) => response,
        other => panic!("expected Health response, got {other:?}"),
    };
    assert_eq!(response.version, ProtocolVersion::new(1, 0));
    assert_eq!(response.request_id, request_id);
    match response.body {
        ResponseBodyV1::Ok(ResponsePayloadV1::Health(snapshot)) => {
            assert!(!snapshot.ready);
            assert_eq!(snapshot.identity, *identity);
            assert_eq!(snapshot.last_error, None);
        }
        other => panic!("expected Health success, got {other:?}"),
    }
    assert_eq!(stream.read(&mut [0_u8; 1]).unwrap(), 0);
}

fn write_client(
    stream: &mut UnixStream,
    message: &ClientMessageV1,
    limits: &savana_kernel_protocol::EffectiveLimits,
) {
    let payload = encode_client_message(message).unwrap();
    write_frame(stream, &payload, limits).unwrap();
}

fn read_server(
    stream: &mut UnixStream,
    limits: &savana_kernel_protocol::EffectiveLimits,
) -> ServerMessageV1 {
    let payload = read_frame(stream, limits).unwrap();
    decode_server_message(&payload, limits).unwrap()
}

fn system_now_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

fn assert_process_result(output: &Output, authenticated_health: bool, host_socket_available: bool) {
    let stderr = String::from_utf8(output.stderr.clone()).unwrap();
    if authenticated_health {
        assert!(output.status.success(), "{stderr}");
        let lines: Vec<_> = stderr.lines().collect();
        assert_eq!(lines.len(), 2, "{stderr}");
        assert!(lines[0].starts_with(r#"{"event":"Started","#), "{stderr}");
        assert_eq!(lines[1], r#"{"event":"Stopped","reason":"sigterm"}"#);
    } else {
        assert!(
            socket_permission_fallback_allowed(host_socket_available),
            "daemon failed at socket bind on a host whose independent UDS probe succeeded: {stderr}"
        );
        assert_eq!(output.status.code(), Some(1), "{stderr}");
        assert_eq!(
            stderr,
            "{\"event\":\"BootstrapFailed\",\"code\":\"IDENTITY_SOCKET_PERMISSIONS\"}\n"
        );
    }
}

impl Installation {
    fn prepare_with_fault(
        &self,
        fault: DependencyFault,
    ) -> Result<savana_kerneld::test_support::RuntimeIdentities, savana_kerneld::DaemonError> {
        let dependencies: Arc<dyn Clock + Send + Sync> = Arc::new(TestDependencies::new(fault));
        let random: Arc<dyn RandomSource + Send + Sync> = Arc::new(TestDependencies::new(fault));
        savana_kerneld::test_support::prepare_with_dependencies(
            &self.config,
            BootId::new([0x61; 32]),
            dependencies,
            random,
        )
    }

    fn spawn_and_wait(&self) -> Output {
        let mut child = Command::new(&self.executable)
            .arg("--config")
            .arg(&self.config)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if child.try_wait().unwrap().is_some() {
                return child.wait_with_output().unwrap();
            }
            if self.socket.exists() {
                let _ = kill(
                    Pid::from_raw(i32::try_from(child.id()).unwrap()),
                    Signal::SIGTERM,
                );
                let output = child.wait_with_output().unwrap();
                panic!(
                    "corrupted installation reached socket bind: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "corrupted installation neither exited nor bound: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn corrupt(&self, corruption: Corruption) {
        match corruption {
            Corruption::Bootstrap => mutate_file(&self.config, 0o444),
            Corruption::ReleaseManifest => mutate_file(&self.release_manifest, 0o444),
            Corruption::SelectedPolicy => mutate_file(&self.selected_policy, 0o444),
            Corruption::DaemonKey => {
                set_mode(&self.daemon_key, 0o600);
                fs::write(&self.daemon_key, [0x63; 32]).unwrap();
                set_mode(&self.daemon_key, 0o600);
            }
        }
    }

    fn build() -> Self {
        let canary = "mapped-secret-canary";
        let temporary = tempfile::Builder::new().prefix(canary).tempdir().unwrap();
        let root = fs::canonicalize(temporary.path()).unwrap();
        set_mode(&root, 0o700);

        let now = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
        .unwrap();
        let issued_at = now.saturating_sub(60_000);
        let expires_at = now.checked_add(3_600_000).unwrap();

        let jarvis_uid = geteuid().as_raw();
        let socket_client_gid = getegid().as_raw();
        let daemon_uid = different_id(jarvis_uid);
        let daemon_gid = different_id(socket_client_gid);
        let daemon_key = SigningKey::from_bytes(&[0x61; 32]);
        let client_key = SigningKey::from_bytes(&[0x62; 32]);
        let policy_key = policy_support::signing_key();
        let release_key = SigningKey::from_bytes(&[0x51; 32]);

        let resources = policy_support::compiled_resources();
        let resource_bytes = minicbor::to_vec(resources).unwrap();
        let resource_digest = domain_digest(RESOURCE_DOMAIN, &resource_bytes);
        let roots_bytes = encode_policy_roots(
            "policy-root",
            &policy_key.verifying_key().to_bytes(),
            POLICY_EPOCH,
            false,
        );
        let roots_digest = sha256(&roots_bytes);
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
        let release_target = compute_target(roots_digest, resource_digest, profile_digest);

        let mut policy = policy_support::valid_policy(POLICY_VERSION, POLICY_EPOCH);
        policy.issued_at = issued_at;
        policy.expires_at = expires_at;
        policy.release.compatible_release_target_ids = vec![release_target];
        for authority in &mut policy.authorities {
            authority.not_before = issued_at;
            authority.not_after = expires_at;
        }
        let (policy_bytes, policy_signature) = policy_support::signed(&policy);

        let stage = mapped(&root, release_stage_path());
        ensure_directory(&stage, 0o755);
        let executable = stage.join("bin/savana-kerneld");
        ensure_directory(executable.parent().unwrap(), 0o755);
        fs::copy(env!("CARGO_BIN_EXE_savana-kerneld"), &executable).unwrap();
        set_mode(&executable, 0o555);
        let executable_bytes = fs::read(&executable).unwrap();

        let mut payloads = vec![
            ("bin/savana-kerneld".to_owned(), executable_bytes),
            (
                "policy/default-policy-v1.cbor".to_owned(),
                policy_bytes.clone(),
            ),
            (
                "policy/default-policy-v1.sig".to_owned(),
                policy_signature.as_bytes().to_vec(),
            ),
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
                b"model-envelope".to_vec(),
            ),
            (
                "installation/kernel-installation-profile-v1.cbor".to_owned(),
                profile_bytes,
            ),
            (runtime_path().to_owned(), b"onnx-runtime".to_vec()),
            ("model/assets/model.bin".to_owned(), b"model-asset".to_vec()),
        ];
        payloads.sort_by(|left, right| canonical_text_cmp(&left.0, &right.0));
        for (relative, bytes) in &payloads {
            if relative != "bin/savana-kerneld" {
                write_file(&stage.join(relative), bytes, 0o444);
            }
        }
        for relative in [
            "release",
            "bin",
            "policy",
            "approval",
            "model",
            "model/assets",
            "installation",
            "runtime",
        ] {
            ensure_directory(&stage.join(relative), 0o755);
        }

        let manifest_bytes = encode_manifest(
            &payloads,
            release_target,
            roots_digest,
            resource_digest,
            profile_digest,
            issued_at,
            expires_at,
        );
        let release_signature = detached_signature(RELEASE_DOMAIN, &manifest_bytes, &release_key);
        let release_manifest = stage.join("release/release-manifest-v1.cbor");
        write_file(&release_manifest, &manifest_bytes, 0o444);
        write_file(
            &stage.join("release/release-manifest-v1.sig"),
            release_signature.as_bytes(),
            0o444,
        );
        let release_digest = sha256(&manifest_bytes);

        let selected_policy = mapped(&root, selected_policy_path());
        let selected_signature = mapped(&root, selected_policy_signature_path());
        ensure_directory(selected_policy.parent().unwrap(), 0o755);
        write_file(&selected_policy, &policy_bytes, 0o444);
        write_file(&selected_signature, policy_signature.as_bytes(), 0o444);
        write_file(
            &selected_policy
                .parent()
                .unwrap()
                .join(".selected-policy-v1.update.lock"),
            &[],
            0o640,
        );

        let key = mapped(&root, daemon_key_path());
        ensure_directory(key.parent().unwrap(), 0o750);
        write_file(&key, &[0x61; 32], 0o600);
        set_mode(key.parent().unwrap(), 0o750);

        let ledger = mapped(&root, ledger_path());
        let state = ledger.parent().unwrap();
        ensure_directory(state.parent().unwrap(), 0o755);
        ensure_directory(state, 0o700);
        let state_lock = state.join(".policy-ledger-v1.cbor.lock");

        let socket = mapped(&root, socket_path());
        ensure_directory(socket.parent().unwrap(), 0o750);

        let kernel_lock = mapped(&root, "/etc/savana/kernel-lock.json");
        ensure_directory(kernel_lock.parent().unwrap(), 0o755);
        let lock = KernelLock {
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
            platform: platform_name().to_owned(),
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
                epoch: POLICY_EPOCH,
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
            selected_policy_digest: hex(sha256(&policy_bytes)),
            selected_policy_signature_digest: hex(sha256(policy_signature.as_bytes())),
            selected_policy_version: POLICY_VERSION,
            selected_policy_signing_key_id: "policy-root".to_owned(),
            selected_policy_key_epoch: POLICY_EPOCH,
            model_manifest_digest: hex([0xd1; 32]),
            producer_registry_digest: hex([0xd2; 32]),
            ontology_digest: hex([0xd3; 32]),
            approval_key_set_digest: hex([0xd4; 32]),
            resource_profile_digest: hex(resource_digest),
        };
        let kernel_lock_bytes = serde_json::to_vec(&lock).unwrap();
        write_file(&kernel_lock, &kernel_lock_bytes, 0o444);

        let config = mapped(&root, "/etc/savana/kerneld-bootstrap-v1.json");
        let bootstrap = Bootstrap {
            schema_version: 1,
            platform: platform_name().to_owned(),
            release_trust_roots: vec![BootstrapTrustRoot {
                key_id: "release-root".to_owned(),
                public_key: hex(release_key.verifying_key().to_bytes()),
                not_before_unix_ms: issued_at,
                not_after_unix_ms: expires_at,
                revoked: false,
            }],
            allowed_release_digest: hex(release_digest),
        };
        write_file(&config, &serde_json::to_vec(&bootstrap).unwrap(), 0o444);

        Self {
            _temporary: temporary,
            config,
            executable,
            release_manifest,
            selected_policy,
            daemon_key: key,
            socket,
            ledger,
            state_lock,
            kernel_lock,
            kernel_lock_bytes,
            expected_ledger: policy_support::encode_ledger(
                POLICY_VERSION,
                POLICY_EPOCH,
                sha256(&policy_bytes),
            ),
            release_digest: Digest32::new(release_digest),
            policy_digest: Digest32::new(sha256(&policy_bytes)),
            resource_profile_digest: Digest32::new(resource_digest),
            canary: canary.to_owned(),
        }
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
        .u8(platform_tag())
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
    encoder.writer_mut().extend_from_slice(&encode_policy_roots(
        "policy-root",
        policy_key,
        POLICY_EPOCH,
        false,
    ));
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

#[allow(clippy::too_many_arguments)]
fn encode_manifest(
    files: &[(String, Vec<u8>)],
    target: [u8; 32],
    roots_digest: [u8; 32],
    resource_digest: [u8; 32],
    profile_digest: [u8; 32],
    issued_at: u64,
    expires_at: u64,
) -> Vec<u8> {
    let binary_digest = sha256(
        &files
            .iter()
            .find(|(path, _)| path == "bin/savana-kerneld")
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
    encoder.u64(issued_at).unwrap().u64(expires_at).unwrap();
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

fn mapped(root: &Path, production: &str) -> PathBuf {
    root.join(production.trim_start_matches('/'))
}

fn ensure_directory(path: &Path, mode: u32) {
    fs::create_dir_all(path).unwrap();
    set_mode(path, mode);
}

fn write_file(path: &Path, bytes: &[u8], mode: u32) {
    ensure_directory(path.parent().unwrap(), 0o755);
    fs::write(path, bytes).unwrap();
    set_mode(path, mode);
}

fn set_mode(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

fn mutate_file(path: &Path, final_mode: u32) {
    let mut bytes = fs::read(path).unwrap();
    let index = bytes.len() / 2;
    bytes[index] ^= 1;
    set_mode(path, final_mode | 0o200);
    fs::write(path, bytes).unwrap();
    set_mode(path, final_mode);
}

const fn different_id(value: u32) -> u32 {
    if value == u32::MAX {
        value - 1
    } else {
        value + 1
    }
}

fn assert_regular_mode(path: &Path, mode: u32) {
    let metadata = fs::symlink_metadata(path).unwrap();
    assert!(metadata.is_file());
    assert_eq!(metadata.mode() & 0o7777, mode);
    assert_eq!(metadata.nlink(), 1);
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

#[cfg(target_os = "linux")]
const fn runtime_path() -> &'static str {
    "runtime/libonnxruntime.so"
}

#[cfg(target_os = "macos")]
const fn runtime_path() -> &'static str {
    "runtime/libonnxruntime.dylib"
}

#[cfg(target_os = "linux")]
const fn platform_tag() -> u8 {
    0
}

#[cfg(target_os = "macos")]
const fn platform_tag() -> u8 {
    1
}

#[cfg(target_os = "linux")]
const fn platform_name() -> &'static str {
    "linux"
}

#[cfg(target_os = "macos")]
const fn platform_name() -> &'static str {
    "macos"
}
