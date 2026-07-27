#![allow(dead_code)]

#[path = "../../../savana-policy-core/tests/support/mod.rs"]
pub mod policy_support;

use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::{mpsc, Arc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signer, SigningKey};
use nix::fcntl::{Flock, FlockArg};
use nix::libc::{O_CLOEXEC, O_NOFOLLOW};
use nix::unistd::{chown, getegid, geteuid};
use savana_kernel_protocol::{Digest32, Signature64, UnixMillis};
use savana_policy_core::PolicyIdentity;
use serde::Serialize;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

const RELEASE_DOMAIN: &[u8] = b"SAVANA_RELEASE_V1\0";
const TARGET_DOMAIN: &[u8] = b"SAVANA_RELEASE_TARGET_V1\0";
const RESOURCE_DOMAIN: &[u8] = b"SAVANA_RESOURCE_PROFILE_V1\0";
pub const POLICY_VERSION: u64 = 7;
pub const POLICY_EPOCH: u64 = 3;
pub const NEXT_POLICY_VERSION: u64 = POLICY_VERSION + 1;

const LIFECYCLE_CONTROL_ENV: &str = "SAVANA_TEST_LIFECYCLE_CONTROL";
const LIFECYCLE_CONTROL_MODE: &str = "stdio-v1";
const POLICY_CORE_LIVE_PERSISTENCE_FAULT_ENV: &str =
    "SAVANA_TEST_POLICY_CORE_LIVE_PERSISTENCE_FAULT";
const TEST_PROCESS_ENTROPY_ENV: &str = "SAVANA_TEST_PROCESS_ENTROPY";
const CONTROL_RESPONSE_BYTES: usize = 72;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LivePersistenceFault {
    BeforeRename,
    AfterRename,
}

impl LivePersistenceFault {
    const fn environment_value(self) -> &'static str {
        match self {
            Self::BeforeRename => "before-rename-v1",
            Self::AfterRename => "after-rename-v1",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ControlOpcode {
    StartupReady = 0x00,
    ContinueStartup = 0x01,
    Refresh = 0x02,
    PauseBegin = 0x03,
    ReleaseBegin = 0x04,
    ProbeAdmission = 0x05,
    Observe = 0x06,
    UseOldContext = 0x07,
    SubmitOldIngress = 0x08,
    UseOldRun = 0x09,
    PreRenameFault = 0x0a,
    DropPublicationGuard = 0x0b,
    PostSwapFault = 0x0c,
    QueryPolicy = 0x0d,
    ObserveReplayTombstone = 0x0e,
    CaptureOldArtifacts = 0x0f,
    PostRenameFault = 0x10,
    Shutdown = 0xff,
}

impl ControlOpcode {
    fn decode(byte: u8) -> Option<Self> {
        Some(match byte {
            0x00 => Self::StartupReady,
            0x01 => Self::ContinueStartup,
            0x02 => Self::Refresh,
            0x03 => Self::PauseBegin,
            0x04 => Self::ReleaseBegin,
            0x05 => Self::ProbeAdmission,
            0x06 => Self::Observe,
            0x07 => Self::UseOldContext,
            0x08 => Self::SubmitOldIngress,
            0x09 => Self::UseOldRun,
            0x0a => Self::PreRenameFault,
            0x0b => Self::DropPublicationGuard,
            0x0c => Self::PostSwapFault,
            0x0d => Self::QueryPolicy,
            0x0e => Self::ObserveReplayTombstone,
            0x0f => Self::CaptureOldArtifacts,
            0x10 => Self::PostRenameFault,
            0xff => Self::Shutdown,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ControlStatus {
    Ok = 0,
    Ready = 1,
    Unchanged = 2,
    Published = 3,
    KernelUnavailable = 4,
    IdentityTranscriptMismatch = 5,
    AttestationBindingMismatch = 6,
    HandleStalePolicy = 7,
}

impl ControlStatus {
    fn decode(byte: u8) -> Option<Self> {
        Some(match byte {
            0 => Self::Ok,
            1 => Self::Ready,
            2 => Self::Unchanged,
            3 => Self::Published,
            4 => Self::KernelUnavailable,
            5 => Self::IdentityTranscriptMismatch,
            6 => Self::AttestationBindingMismatch,
            7 => Self::HandleStalePolicy,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlResponse {
    pub opcode: ControlOpcode,
    pub status: ControlStatus,
    pub generation: u64,
    pub policy_version: u64,
    pub key_epoch: u64,
    pub expires_at: u64,
    pub digest: Digest32,
    pub frame_limit: u32,
}

impl ControlResponse {
    pub const fn identity(self) -> PolicyIdentity {
        PolicyIdentity {
            digest: self.digest,
            policy_version: self.policy_version,
            key_epoch: self.key_epoch,
            expires_at: UnixMillis::new(self.expires_at),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdaterEvent {
    ExclusiveLock,
    TemporaryFilesSynced,
    KernelLockRenamed,
    PolicyRenamed,
    SignatureRenamed,
    KernelLockParentSynced,
    PolicyParentSynced,
    ExclusiveLockReleased,
}

pub const STRICT_UPDATER_EVENTS: [UpdaterEvent; 8] = [
    UpdaterEvent::ExclusiveLock,
    UpdaterEvent::TemporaryFilesSynced,
    UpdaterEvent::KernelLockRenamed,
    UpdaterEvent::PolicyRenamed,
    UpdaterEvent::SignatureRenamed,
    UpdaterEvent::KernelLockParentSynced,
    UpdaterEvent::PolicyParentSynced,
    UpdaterEvent::ExclusiveLockReleased,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrictUpdaterError {
    Io,
    UpdateLockChanged,
}

#[derive(Debug, Clone)]
pub struct CandidateFiles {
    pub kernel_lock: Vec<u8>,
    pub policy: Vec<u8>,
    pub signature: Signature64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpdateLockIdentity {
    file_type: u32,
    uid: u32,
    gid: u32,
    mode: u32,
    nlink: u64,
    device: u64,
    inode: u64,
    length: u64,
}

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

#[derive(Clone, Serialize)]
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

pub struct Installation {
    _temporary: TempDir,
    root: PathBuf,
    pub config: PathBuf,
    pub executable: PathBuf,
    pub release_manifest: PathBuf,
    pub selected_policy: PathBuf,
    pub selected_signature: PathBuf,
    pub update_lock: PathBuf,
    pub daemon_key: PathBuf,
    pub socket: PathBuf,
    pub ledger: PathBuf,
    pub state_lock: PathBuf,
    pub kernel_lock: PathBuf,
    pub kernel_lock_bytes: Vec<u8>,
    pub expected_ledger: Vec<u8>,
    pub release_digest: Digest32,
    pub policy_digest: Digest32,
    pub resource_profile_digest: Digest32,
    pub canary: String,
    initial_identity: PolicyIdentity,
    next_identity: PolicyIdentity,
    next_candidate: CandidateFiles,
    update_lock_identity: UpdateLockIdentity,
}

impl Installation {
    pub fn build() -> Self {
        let canary = "mapped-secret-canary";
        let temporary = tempfile::Builder::new()
            .prefix(canary)
            .tempdir_in("/tmp")
            .unwrap();
        let root = fs::canonicalize(temporary.path()).unwrap();
        chown(&root, None, Some(getegid())).unwrap();
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
        let client_b_key = SigningKey::from_bytes(&[0x63; 32]);
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
            &client_b_key.verifying_key().to_bytes(),
            &policy_key.verifying_key().to_bytes(),
        );
        let profile_digest = sha256(&profile_bytes);
        let release_target = compute_target(roots_digest, resource_digest, profile_digest);

        let policy = installation_policy(POLICY_VERSION, issued_at, expires_at, release_target);
        let (policy_bytes, policy_signature) = policy_support::signed(&policy);
        let initial_policy_digest = sha256(&policy_bytes);
        let initial_identity = PolicyIdentity {
            digest: Digest32::new(initial_policy_digest),
            policy_version: POLICY_VERSION,
            key_epoch: POLICY_EPOCH,
            expires_at: UnixMillis::new(expires_at),
        };

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
        let update_lock = selected_policy
            .parent()
            .unwrap()
            .join(".selected-policy-v1.update.lock");
        write_file(&update_lock, &[], 0o640);
        let update_lock_identity = read_update_lock_identity(&update_lock).unwrap();

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
            daemon_clients: vec![
                LockClient {
                    client_id: "jarvis-client".to_owned(),
                    key_id: "jarvis-key".to_owned(),
                    public_key: hex(client_key.verifying_key().to_bytes()),
                    role: "jarvis_kernel_client".to_owned(),
                    peer_uid: jarvis_uid,
                    peer_gid: socket_client_gid,
                },
                LockClient {
                    client_id: "jarvis-client-b".to_owned(),
                    key_id: "jarvis-key-b".to_owned(),
                    public_key: hex(client_b_key.verifying_key().to_bytes()),
                    role: "jarvis_kernel_client".to_owned(),
                    peer_uid: jarvis_uid,
                    peer_gid: socket_client_gid,
                },
            ],
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
            selected_policy_digest: hex(initial_policy_digest),
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

        let next_policy =
            installation_policy(NEXT_POLICY_VERSION, issued_at, expires_at, release_target);
        let (next_policy_bytes, next_signature) = policy_support::signed(&next_policy);
        let next_policy_digest = sha256(&next_policy_bytes);
        let next_identity = PolicyIdentity {
            digest: Digest32::new(next_policy_digest),
            policy_version: NEXT_POLICY_VERSION,
            key_epoch: POLICY_EPOCH,
            expires_at: UnixMillis::new(expires_at),
        };
        let mut next_lock = lock.clone();
        next_lock.selected_policy_digest = hex(next_policy_digest);
        next_lock.selected_policy_signature_digest = hex(sha256(next_signature.as_bytes()));
        next_lock.selected_policy_version = NEXT_POLICY_VERSION;
        next_lock.selected_policy_key_epoch = POLICY_EPOCH;
        let next_candidate = CandidateFiles {
            kernel_lock: serde_json::to_vec(&next_lock).unwrap(),
            policy: next_policy_bytes,
            signature: next_signature,
        };

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
            root,
            config,
            executable,
            release_manifest,
            selected_policy,
            selected_signature,
            update_lock,
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
            policy_digest: Digest32::new(initial_policy_digest),
            resource_profile_digest: Digest32::new(resource_digest),
            canary: canary.to_owned(),
            initial_identity,
            next_identity,
            next_candidate,
            update_lock_identity,
        }
    }
}

impl Installation {
    pub const fn initial_identity(&self) -> PolicyIdentity {
        self.initial_identity
    }

    pub const fn next_identity(&self) -> PolicyIdentity {
        self.next_identity
    }

    pub const fn next_candidate(&self) -> &CandidateFiles {
        &self.next_candidate
    }

    pub fn ledger_bytes(&self) -> Option<Vec<u8>> {
        match fs::read(&self.ledger) {
            Ok(bytes) => Some(bytes),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => panic!("read mapped policy ledger: {error}"),
        }
    }

    pub fn next_ledger_bytes(&self) -> Vec<u8> {
        policy_support::encode_ledger(
            NEXT_POLICY_VERSION,
            POLICY_EPOCH,
            sha256(&self.next_candidate.policy),
        )
    }

    pub fn update_lock_identity(&self) -> UpdateLockIdentity {
        read_update_lock_identity(&self.update_lock).unwrap()
    }

    pub fn acquire_strict_update_lock(&self) -> Result<StrictUpdateLock, StrictUpdaterError> {
        let path_before = read_update_lock_identity(&self.update_lock)?;
        require_same_update_lock(path_before, self.update_lock_identity)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(O_NOFOLLOW | O_CLOEXEC)
            .open(&self.update_lock)
            .map_err(|_| StrictUpdaterError::Io)?;
        let descriptor_before = update_lock_identity_from_metadata(
            &file.metadata().map_err(|_| StrictUpdaterError::Io)?,
        );
        validate_update_lock_identity(descriptor_before)?;
        require_same_update_lock(descriptor_before, self.update_lock_identity)?;
        let lock = Flock::lock(file, FlockArg::LockExclusive)
            .map_err(|(_file, _error)| StrictUpdaterError::Io)?;
        let descriptor_after = update_lock_identity_from_metadata(
            &lock.metadata().map_err(|_| StrictUpdaterError::Io)?,
        );
        let path_after = read_update_lock_identity(&self.update_lock)?;
        require_same_update_lock(descriptor_after, self.update_lock_identity)?;
        require_same_update_lock(path_after, self.update_lock_identity)?;
        Ok(StrictUpdateLock {
            lock: Some(lock),
            path: self.update_lock.clone(),
            expected: self.update_lock_identity,
        })
    }

    pub fn install_next_candidate_strictly(&self) -> Result<Vec<UpdaterEvent>, StrictUpdaterError> {
        self.install_candidate_strictly_with_observer(&self.next_candidate, |_| {})
    }

    fn install_candidate_strictly_with_observer(
        &self,
        candidate: &CandidateFiles,
        mut observer: impl FnMut(UpdaterEvent),
    ) -> Result<Vec<UpdaterEvent>, StrictUpdaterError> {
        let mut exclusive = self.acquire_strict_update_lock()?;
        let mut events = vec![UpdaterEvent::ExclusiveLock];
        observer(UpdaterEvent::ExclusiveLock);

        let lock_parent = self.kernel_lock.parent().ok_or(StrictUpdaterError::Io)?;
        let policy_parent = self
            .selected_policy
            .parent()
            .ok_or(StrictUpdaterError::Io)?;
        let lock_temp = write_synced_temp(
            lock_parent,
            "kernel-lock.json.next",
            &candidate.kernel_lock,
            0o444,
        )?;
        let policy_temp = write_synced_temp(
            policy_parent,
            "selected-policy-v1.cbor.next",
            &candidate.policy,
            0o444,
        )?;
        let signature_temp = write_synced_temp(
            policy_parent,
            "selected-policy-v1.sig.next",
            candidate.signature.as_bytes(),
            0o444,
        )?;
        push_updater_event(
            &mut events,
            UpdaterEvent::TemporaryFilesSynced,
            &mut observer,
        );

        rename_candidate(&lock_temp, &self.kernel_lock, &candidate.kernel_lock, 0o444)?;
        push_updater_event(&mut events, UpdaterEvent::KernelLockRenamed, &mut observer);
        rename_candidate(
            &policy_temp,
            &self.selected_policy,
            &candidate.policy,
            0o444,
        )?;
        push_updater_event(&mut events, UpdaterEvent::PolicyRenamed, &mut observer);
        rename_candidate(
            &signature_temp,
            &self.selected_signature,
            candidate.signature.as_bytes(),
            0o444,
        )?;
        push_updater_event(&mut events, UpdaterEvent::SignatureRenamed, &mut observer);

        sync_parent(lock_parent)?;
        push_updater_event(
            &mut events,
            UpdaterEvent::KernelLockParentSynced,
            &mut observer,
        );
        sync_parent(policy_parent)?;
        push_updater_event(&mut events, UpdaterEvent::PolicyParentSynced, &mut observer);
        exclusive.recheck()?;
        exclusive.release()?;
        push_updater_event(
            &mut events,
            UpdaterEvent::ExclusiveLockReleased,
            &mut observer,
        );
        Ok(events)
    }

    pub fn replace_update_lock_inode(&self) {
        let replacement = self.update_lock.with_extension("replacement");
        write_synced_temp(
            replacement.parent().unwrap(),
            replacement.file_name().unwrap().to_str().unwrap(),
            &[],
            0o640,
        )
        .unwrap();
        fs::rename(&replacement, &self.update_lock).unwrap();
        sync_parent(self.update_lock.parent().unwrap()).unwrap();
    }

    pub fn spawn_paused_strict_install(self: &Arc<Self>) -> PausedStrictInstall {
        let (event_sender, event_receiver) = mpsc::sync_channel(1);
        let (continue_sender, continue_receiver) = mpsc::sync_channel(1);
        let (result_sender, result_receiver) = mpsc::sync_channel(1);
        let installation = Arc::clone(self);
        let join = thread::spawn(move || {
            let result = installation.install_candidate_strictly_with_observer(
                &installation.next_candidate,
                |event| {
                    if matches!(
                        event,
                        UpdaterEvent::KernelLockRenamed
                            | UpdaterEvent::PolicyRenamed
                            | UpdaterEvent::SignatureRenamed
                    ) {
                        event_sender.send(event).unwrap();
                        continue_receiver.recv().unwrap();
                    }
                },
            );
            result_sender.send(result).unwrap();
        });
        PausedStrictInstall {
            event_receiver,
            continue_sender,
            result_receiver,
            join: Some(join),
            waiting: false,
        }
    }

    pub fn spawn_lifecycle_daemon(&self) -> LifecycleDaemon {
        self.spawn_lifecycle_daemon_with_persistence_fault(None)
    }

    pub fn spawn_lifecycle_daemon_with_persistence_fault(
        &self,
        fault: Option<LivePersistenceFault>,
    ) -> LifecycleDaemon {
        let mut command = Command::new(&self.executable);
        command
            .arg("--config")
            .arg(&self.config)
            .env(LIFECYCLE_CONTROL_ENV, LIFECYCLE_CONTROL_MODE)
            .env_remove(POLICY_CORE_LIVE_PERSISTENCE_FAULT_ENV)
            .env_remove(TEST_PROCESS_ENTROPY_ENV)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(fault) = fault {
            command.env(
                POLICY_CORE_LIVE_PERSISTENCE_FAULT_ENV,
                fault.environment_value(),
            );
        }
        let mut child = command.spawn().unwrap();
        let stdin = child.stdin.take().unwrap();
        let mut stdout = child.stdout.take().unwrap();
        let mut stderr = child.stderr.take().unwrap();
        let (response_sender, response_receiver) = mpsc::channel();
        let stdout_reader = thread::spawn(move || loop {
            let mut encoded = [0_u8; CONTROL_RESPONSE_BYTES];
            match stdout.read_exact(&mut encoded[..1]) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(error) => panic!("read lifecycle response opcode: {error}"),
            }
            stdout
                .read_exact(&mut encoded[1..])
                .unwrap_or_else(|error| panic!("read complete lifecycle response: {error}"));
            response_sender
                .send(decode_control_response(&encoded))
                .unwrap();
        });
        let stderr_reader = thread::spawn(move || {
            let mut bytes = Vec::new();
            stderr.read_to_end(&mut bytes).unwrap();
            bytes
        });
        let mut daemon = LifecycleDaemon {
            child: Some(child),
            stdin: Some(stdin),
            responses: response_receiver,
            buffered: VecDeque::new(),
            stdout_reader: Some(stdout_reader),
            stderr_reader: Some(stderr_reader),
        };
        let ready =
            daemon.receive_with_timeout(ControlOpcode::StartupReady, Duration::from_secs(10));
        assert_eq!(ready.status, ControlStatus::Ready);
        daemon
    }
}

pub struct StrictUpdateLock {
    lock: Option<Flock<File>>,
    path: PathBuf,
    expected: UpdateLockIdentity,
}

impl StrictUpdateLock {
    fn recheck(&self) -> Result<(), StrictUpdaterError> {
        let lock = self.lock.as_ref().ok_or(StrictUpdaterError::Io)?;
        let descriptor = update_lock_identity_from_metadata(
            &lock.metadata().map_err(|_| StrictUpdaterError::Io)?,
        );
        let path = read_update_lock_identity(&self.path)?;
        require_same_update_lock(descriptor, self.expected)?;
        require_same_update_lock(path, self.expected)
    }

    fn release(&mut self) -> Result<(), StrictUpdaterError> {
        self.recheck()?;
        drop(self.lock.take());
        Ok(())
    }
}

pub struct PausedStrictInstall {
    event_receiver: mpsc::Receiver<UpdaterEvent>,
    continue_sender: mpsc::SyncSender<()>,
    result_receiver: mpsc::Receiver<Result<Vec<UpdaterEvent>, StrictUpdaterError>>,
    join: Option<JoinHandle<()>>,
    waiting: bool,
}

impl PausedStrictInstall {
    pub fn advance_until(&mut self, expected: UpdaterEvent) {
        if self.waiting {
            self.continue_sender.send(()).unwrap();
        }
        let observed = self
            .event_receiver
            .recv_timeout(Duration::from_secs(2))
            .unwrap();
        assert_eq!(observed, expected);
        self.waiting = true;
    }

    pub fn finish(mut self) -> Result<Vec<UpdaterEvent>, StrictUpdaterError> {
        if self.waiting {
            self.continue_sender.send(()).unwrap();
            self.waiting = false;
        }
        let result = self
            .result_receiver
            .recv_timeout(Duration::from_secs(2))
            .unwrap();
        self.join.take().unwrap().join().unwrap();
        result
    }
}

pub struct LifecycleDaemon {
    child: Option<Child>,
    stdin: Option<ChildStdin>,
    responses: mpsc::Receiver<ControlResponse>,
    buffered: VecDeque<ControlResponse>,
    stdout_reader: Option<JoinHandle<()>>,
    stderr_reader: Option<JoinHandle<Vec<u8>>>,
}

impl LifecycleDaemon {
    pub fn continue_startup(&mut self) {
        self.command_expect(ControlOpcode::ContinueStartup, ControlStatus::Ok);
    }

    pub fn send(&mut self, opcode: ControlOpcode) {
        let stdin = self.stdin.as_mut().expect("lifecycle stdin remains open");
        stdin
            .write_all(&[opcode as u8])
            .unwrap_or_else(|error| panic!("send lifecycle opcode {opcode:?}: {error}"));
        stdin.flush().unwrap();
    }

    pub fn command(&mut self, opcode: ControlOpcode) -> ControlResponse {
        self.command_with_timeout(opcode, Duration::from_secs(10))
    }

    pub fn command_with_timeout(
        &mut self,
        opcode: ControlOpcode,
        timeout: Duration,
    ) -> ControlResponse {
        self.send(opcode);
        self.receive_with_timeout(opcode, timeout)
    }

    pub fn command_expect(&mut self, opcode: ControlOpcode, expected: ControlStatus) {
        let response = self.command(opcode);
        assert_eq!(response.status, expected, "{opcode:?}: {response:?}");
    }

    pub fn receive(&mut self, opcode: ControlOpcode) -> ControlResponse {
        self.receive_with_timeout(opcode, Duration::from_secs(10))
    }

    pub fn receive_for(
        &mut self,
        opcode: ControlOpcode,
        timeout: Duration,
    ) -> Option<ControlResponse> {
        if let Some(index) = self
            .buffered
            .iter()
            .position(|response| response.opcode == opcode)
        {
            return self.buffered.remove(index);
        }
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return None;
            }
            match self.responses.recv_timeout(remaining) {
                Ok(response) if response.opcode == opcode => return Some(response),
                Ok(response) => self.buffered.push_back(response),
                Err(mpsc::RecvTimeoutError::Timeout) => return None,
                Err(mpsc::RecvTimeoutError::Disconnected) => return None,
            }
        }
    }

    fn receive_with_timeout(
        &mut self,
        opcode: ControlOpcode,
        timeout: Duration,
    ) -> ControlResponse {
        self.receive_for(opcode, timeout)
            .unwrap_or_else(|| panic!("no lifecycle response for {opcode:?} within {timeout:?}"))
    }

    pub fn shutdown(mut self) {
        self.command_expect(ControlOpcode::Shutdown, ControlStatus::Ok);
        let (status, stderr) = self.wait_inner();
        assert!(
            status.success(),
            "mapped lifecycle daemon shutdown failed: {}",
            String::from_utf8_lossy(&stderr)
        );
    }

    pub fn wait(mut self) -> ExitStatus {
        self.wait_inner().0
    }

    fn wait_inner(&mut self) -> (ExitStatus, Vec<u8>) {
        let status = self.child.as_mut().unwrap().wait().unwrap();
        self.child.take();
        self.stdin.take();
        self.stdout_reader.take().unwrap().join().unwrap();
        let stderr = self.stderr_reader.take().unwrap().join().unwrap();
        (status, stderr)
    }
}

impl Drop for LifecycleDaemon {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            if child.try_wait().ok().flatten().is_none() {
                let _ = child.kill();
            }
            let _ = child.wait();
        }
        self.stdin.take();
        if let Some(reader) = self.stdout_reader.take() {
            let _ = reader.join();
        }
        if let Some(reader) = self.stderr_reader.take() {
            let _ = reader.join();
        }
    }
}

fn installation_policy(
    version: u64,
    issued_at: u64,
    expires_at: u64,
    release_target: [u8; 32],
) -> policy_support::TestPolicy {
    let mut policy = policy_support::valid_policy(version, POLICY_EPOCH);
    policy.dataflow.no_side_effect_tools[0] = "operator-tool".to_owned();
    policy.attempts.valid_pairs[0].tool = "operator-tool".to_owned();
    policy.tools[0].name = "operator-tool".to_owned();
    policy.attempts.valid_pairs.swap(0, 1);
    policy.tools.swap(0, 1);
    policy.issued_at = issued_at;
    policy.expires_at = expires_at;
    policy.release.compatible_release_target_ids = vec![release_target];
    for authority in &mut policy.authorities {
        authority.not_before = issued_at;
        authority.not_after = expires_at;
    }
    policy
}

#[allow(clippy::too_many_arguments)]
fn encode_profile(
    daemon_uid: u32,
    daemon_gid: u32,
    socket_client_gid: u32,
    jarvis_uid: u32,
    daemon_key: &[u8; 32],
    client_key: &[u8; 32],
    client_b_key: &[u8; 32],
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
        .array(2)
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
    encoder
        .array(6)
        .unwrap()
        .str("jarvis-client-b")
        .unwrap()
        .str("jarvis-key-b")
        .unwrap()
        .bytes(client_b_key)
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

fn read_update_lock_identity(path: &Path) -> Result<UpdateLockIdentity, StrictUpdaterError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| StrictUpdaterError::Io)?;
    let identity = update_lock_identity_from_metadata(&metadata);
    validate_update_lock_identity(identity)?;
    Ok(identity)
}

fn update_lock_identity_from_metadata(metadata: &fs::Metadata) -> UpdateLockIdentity {
    UpdateLockIdentity {
        file_type: metadata.mode() & u32::from(nix::libc::S_IFMT),
        uid: metadata.uid(),
        gid: metadata.gid(),
        mode: metadata.mode() & 0o7777,
        nlink: metadata.nlink(),
        device: metadata.dev(),
        inode: metadata.ino(),
        length: metadata.len(),
    }
}

fn validate_update_lock_identity(identity: UpdateLockIdentity) -> Result<(), StrictUpdaterError> {
    if identity.file_type != u32::from(nix::libc::S_IFREG)
        || identity.mode != 0o640
        || identity.nlink != 1
        || identity.length != 0
    {
        return Err(StrictUpdaterError::UpdateLockChanged);
    }
    Ok(())
}

fn require_same_update_lock(
    actual: UpdateLockIdentity,
    expected: UpdateLockIdentity,
) -> Result<(), StrictUpdaterError> {
    validate_update_lock_identity(actual)?;
    if actual != expected {
        return Err(StrictUpdaterError::UpdateLockChanged);
    }
    Ok(())
}

fn write_synced_temp(
    parent: &Path,
    leaf: &str,
    bytes: &[u8],
    mode: u32,
) -> Result<PathBuf, StrictUpdaterError> {
    let path = parent.join(leaf);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(O_NOFOLLOW | O_CLOEXEC)
        .open(&path)
        .map_err(|_| StrictUpdaterError::Io)?;
    file.set_permissions(fs::Permissions::from_mode(mode))
        .map_err(|_| StrictUpdaterError::Io)?;
    file.write_all(bytes).map_err(|_| StrictUpdaterError::Io)?;
    file.sync_all().map_err(|_| StrictUpdaterError::Io)?;
    let metadata = file.metadata().map_err(|_| StrictUpdaterError::Io)?;
    if !metadata.is_file()
        || metadata.mode() & 0o7777 != mode
        || metadata.nlink() != 1
        || metadata.len() != u64::try_from(bytes.len()).map_err(|_| StrictUpdaterError::Io)?
    {
        return Err(StrictUpdaterError::Io);
    }
    Ok(path)
}

fn rename_candidate(
    temporary: &Path,
    destination: &Path,
    expected_bytes: &[u8],
    expected_mode: u32,
) -> Result<(), StrictUpdaterError> {
    fs::rename(temporary, destination).map_err(|_| StrictUpdaterError::Io)?;
    let metadata = fs::symlink_metadata(destination).map_err(|_| StrictUpdaterError::Io)?;
    if !metadata.is_file()
        || metadata.mode() & 0o7777 != expected_mode
        || metadata.nlink() != 1
        || metadata.len()
            != u64::try_from(expected_bytes.len()).map_err(|_| StrictUpdaterError::Io)?
        || fs::read(destination).map_err(|_| StrictUpdaterError::Io)? != expected_bytes
    {
        return Err(StrictUpdaterError::Io);
    }
    Ok(())
}

fn sync_parent(parent: &Path) -> Result<(), StrictUpdaterError> {
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| StrictUpdaterError::Io)
}

fn push_updater_event(
    events: &mut Vec<UpdaterEvent>,
    event: UpdaterEvent,
    observer: &mut impl FnMut(UpdaterEvent),
) {
    events.push(event);
    observer(event);
}

fn decode_control_response(encoded: &[u8; CONTROL_RESPONSE_BYTES]) -> ControlResponse {
    assert_eq!(&encoded[2..4], &[0, 0], "reserved lifecycle bytes");
    let opcode = ControlOpcode::decode(encoded[0])
        .unwrap_or_else(|| panic!("unknown lifecycle response opcode {}", encoded[0]));
    let status = ControlStatus::decode(encoded[1])
        .unwrap_or_else(|| panic!("unknown lifecycle response status {}", encoded[1]));
    let generation = u64::from_be_bytes(encoded[4..12].try_into().unwrap());
    let policy_version = u64::from_be_bytes(encoded[12..20].try_into().unwrap());
    let key_epoch = u64::from_be_bytes(encoded[20..28].try_into().unwrap());
    let expires_at = u64::from_be_bytes(encoded[28..36].try_into().unwrap());
    let digest = Digest32::new(encoded[36..68].try_into().unwrap());
    let frame_limit = u32::from_be_bytes(encoded[68..72].try_into().unwrap());
    ControlResponse {
        opcode,
        status,
        generation,
        policy_version,
        key_epoch,
        expires_at,
        digest,
        frame_limit,
    }
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

pub fn set_mode(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

pub fn mutate_file(path: &Path, final_mode: u32) {
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

pub fn assert_regular_mode(path: &Path, mode: u32) {
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
