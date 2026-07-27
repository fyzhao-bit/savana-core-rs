#![cfg(feature = "test-support")]

mod support;

use support::{
    assert_regular_mode, mutate_file, policy_support, set_mode, Installation, POLICY_EPOCH,
    POLICY_VERSION,
};

use std::fs;
use std::io::Read;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, Signer, SigningKey};
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use savana_kernel_protocol::{
    decode_server_message, encode_client_message, read_frame, write_frame, BootId, ClientFinishV1,
    ClientHelloV1, ClientMessageV1, Digest32, HardLimits, Nonce32, OperationV1, ProtocolVersion,
    RequestEnvelopeV1, RequestId, RequestedMode, ResponseBodyV1, ResponsePayloadV1,
    ServerMessageV1, Signature64, StableCode, UnixMillis,
};
use savana_policy_core::{Clock, RandomSource};
use sha2::{Digest, Sha256};

const DAEMON_HELLO_DOMAIN: &[u8] = b"SAVANA_DAEMON_HELLO_V1\0";
const CLIENT_FINISH_DOMAIN: &[u8] = b"SAVANA_CLIENT_FINISH_V1\0";
const TEST_PROCESS_ENTROPY_ENV: &str = "SAVANA_TEST_PROCESS_ENTROPY";
const LIFECYCLE_CONTROL_ENV: &str = "SAVANA_TEST_LIFECYCLE_CONTROL";
const POLICY_CORE_LIVE_PERSISTENCE_FAULT_ENV: &str =
    "SAVANA_TEST_POLICY_CORE_LIVE_PERSISTENCE_FAULT";

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
    let mut child = Command::new(&installation.executable)
        .arg("--config")
        .arg(&installation.config)
        .env_remove(TEST_PROCESS_ENTROPY_ENV)
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
    assert_process_result(&output, authenticated_health);
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

#[test]
fn two_process_starts_get_distinct_nonzero_boot_ids() {
    let installation = Installation::build();
    let first = installation.start_query_and_stop();
    let second = installation.start_query_and_stop();
    assert_ne!(first.as_bytes(), &[0; 32]);
    assert_ne!(second.as_bytes(), &[0; 32]);
    assert_ne!(first, second);
}

#[test]
fn scripted_zero_short_and_failed_process_entropy_never_accepts() {
    for script in [
        "fail-boot",
        "short-boot",
        "zero-boot",
        "fail-audit",
        "short-audit",
        "zero-audit",
        "fail-engine",
        "short-engine",
        "zero-engine",
        "unknown-script",
    ] {
        let installation = Installation::build();
        let output = installation.spawn_with_entropy_script(script);
        assert!(!output.status.success(), "{script}");
        assert!(!installation.socket_accepts(), "{script}");
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

fn assert_authenticated_health(installation: &Installation) -> BootId {
    let limits = HardLimits::COMPILED
        .lower(&policy_support::compiled_resources())
        .unwrap();
    let mut stream = connect_when_listening(&installation.socket);
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
    let boot_id = identity.boot_id;
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
            assert!(snapshot.ready);
            assert_eq!(snapshot.identity, *identity);
            assert_eq!(snapshot.last_error, None);
        }
        other => panic!("expected Health success, got {other:?}"),
    }
    assert_eq!(stream.read(&mut [0_u8; 1]).unwrap(), 0);
    boot_id
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

fn connect_when_listening(path: &Path) -> UnixStream {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match UnixStream::connect(path) {
            Ok(stream) => return stream,
            Err(error)
                if error.kind() == std::io::ErrorKind::ConnectionRefused
                    && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("connect mapped daemon: {error}"),
        }
    }
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

fn assert_process_result(output: &Output, authenticated_health: bool) {
    let stderr = String::from_utf8(output.stderr.clone()).unwrap();
    assert!(
        authenticated_health,
        "mapped daemon failed before authenticated Health: {stderr}"
    );
    assert!(output.status.success(), "{stderr}");
    let lines: Vec<_> = stderr.lines().collect();
    assert_eq!(lines.len(), 3, "{stderr}");
    assert!(lines[0].starts_with(r#"{"event":"Started","#), "{stderr}");
    assert!(
        lines[1]
            .starts_with(r#"{"event":"RequestCompleted","operation_tag":"health","code":"OK","#),
        "{stderr}"
    );
    assert_eq!(lines[2], r#"{"event":"Stopped","reason":"sigterm"}"#);
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
            .env_remove(TEST_PROCESS_ENTROPY_ENV)
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

    fn start_query_and_stop(&self) -> BootId {
        let mut child = Command::new(&self.executable)
            .arg("--config")
            .arg(&self.config)
            .env_remove(TEST_PROCESS_ENTROPY_ENV)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                let output = child.wait_with_output().unwrap();
                panic!(
                    "daemon exited before authenticated health ({status}): {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            if self.socket.exists() {
                let boot_id = assert_authenticated_health(self);
                kill(
                    Pid::from_raw(i32::try_from(child.id()).unwrap()),
                    Signal::SIGTERM,
                )
                .unwrap();
                let output = child.wait_with_output().unwrap();
                assert!(
                    output.status.success(),
                    "{}",
                    String::from_utf8_lossy(&output.stderr)
                );
                return boot_id;
            }
            assert!(Instant::now() < deadline, "daemon did not bind");
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn spawn_with_entropy_script(&self, script: &str) -> Output {
        let mut child = Command::new(&self.executable)
            .arg("--config")
            .arg(&self.config)
            .env_remove(LIFECYCLE_CONTROL_ENV)
            .env_remove(POLICY_CORE_LIVE_PERSISTENCE_FAULT_ENV)
            .env(TEST_PROCESS_ENTROPY_ENV, script)
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
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "entropy-faulted daemon reached socket bind ({script}): {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "entropy-faulted daemon neither exited nor bound ({script}): {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn socket_accepts(&self) -> bool {
        UnixStream::connect(&self.socket).is_ok()
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
}
