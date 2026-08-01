#[cfg(test)]
use std::cell::RefCell;
#[cfg(any(test, feature = "test-support"))]
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
#[cfg(any(test, feature = "test-support"))]
use std::path::Component;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::sync::Arc;
#[cfg(test)]
use std::sync::Mutex;

use nix::unistd::{getegid, geteuid};
use savana_kernel_protocol::{Digest32, KeyId, StableCode, UnixMillis};
use savana_policy_core::{
    Clock, PolicyEngine, PolicyStateCapability, PolicyStore, PolicyVerifier, RandomSource,
    ReleaseStage, ReleaseTrustRootV1, ReleaseVerifier, VerifiedReleaseIdentity,
};
use serde::{Deserialize, Serialize};

use crate::audit::{AuditEvent, AuditSink};
use crate::fs_cap::{DirectoryCapability, FileCapability, FileExpectation, LengthRule};
use crate::handshake::HandshakeService;
use crate::key_file::DaemonKeyCapability;
#[cfg(all(feature = "test-support", debug_assertions))]
use crate::lifecycle_control::{TestLifecycle, TestLifecycleControl};
use crate::policy_runtime::{
    CandidateRuntimeData, DaemonPolicyRuntimeSnapshot, PolicyRolloverCoordinator, PolicyRuntime,
};
use crate::runtime_deps::checked_clock;
use crate::selected_policy::{SelectedPolicySource, SelectedPolicyUpdateGuard};
use crate::server::{KernelServer, ServerLifecycle};
use crate::socket::{preflight_socket, SocketConfig, SocketPreflight};
use crate::{DaemonConfig, DaemonError};

const PRODUCTION_BOOTSTRAP_PATH: &str = "/etc/savana/kerneld-bootstrap-v1.json";
const KERNEL_LOCK_PATH: &str = "/etc/savana/kernel-lock.json";
const MAXIMUM_BOOTSTRAP_BYTES: usize = 64 * 1024;
const MAXIMUM_BOOTSTRAP_BYTES_U64: u64 = 64 * 1024;
const DOCUMENTED_FIXTURE_PUBLIC_KEYS: [&str; 4] = [
    "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12",
    "c050c5637a44fa8629fff3cccce2300cb362a63d99d95fc54145266f4332445a",
    "af06a3e3291714e4f356c19c9b15cd1951ec6e6662aa77be07547f289383341d",
    "2df04125f0015afb47ce853aef8772094ff9498c14cb1b9e12973c2927da0fa6",
];

static RUN_OWNED: AtomicBool = AtomicBool::new(false);

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BootstrapEvent {
    ReleaseVerified,
    ReleaseVerifierBound,
    LedgerLifetimeLockAcquired,
    SelectedUpdateSharedLockAcquired,
    CandidateRead,
    CandidateStatelesslyVerified,
    FixedLockVerified,
    FinalDescriptorRecheck,
    LedgerPersisted,
    CurrentCapabilityReturned,
    DaemonKeyLoaded,
    EngineConstructed,
    WorkersActivated,
    SelectedUpdateSharedLockReleased,
}

#[cfg(test)]
thread_local! {
    static BOOTSTRAP_TRACE: RefCell<Option<Arc<Mutex<Vec<BootstrapEvent>>>>> = const { RefCell::new(None) };
}

#[cfg(test)]
pub(crate) struct BootstrapTraceGuard {
    trace: Arc<Mutex<Vec<BootstrapEvent>>>,
}

#[cfg(test)]
impl BootstrapTraceGuard {
    pub(crate) fn install() -> Self {
        let trace = Arc::new(Mutex::new(Vec::new()));
        BOOTSTRAP_TRACE.with(|slot| {
            assert!(
                slot.borrow().is_none(),
                "a bootstrap trace is already installed"
            );
            *slot.borrow_mut() = Some(Arc::clone(&trace));
        });
        Self { trace }
    }

    pub(crate) fn events(&self) -> Vec<BootstrapEvent> {
        self.trace
            .lock()
            .expect("bootstrap trace mutex is not poisoned")
            .clone()
    }
}

#[cfg(test)]
impl Drop for BootstrapTraceGuard {
    fn drop(&mut self) {
        BOOTSTRAP_TRACE.with(|slot| *slot.borrow_mut() = None);
    }
}

#[cfg(test)]
fn trace_bootstrap(event: BootstrapEvent) {
    BOOTSTRAP_TRACE.with(|slot| {
        if let Some(trace) = slot.borrow().as_ref() {
            trace
                .lock()
                .expect("bootstrap trace mutex is not poisoned")
                .push(event);
        }
    });
}

macro_rules! bootstrap_trace {
    ($event:expr) => {{
        #[cfg(test)]
        trace_bootstrap($event);
    }};
}

#[cfg(test)]
type SelectedPolicySourceHook = Box<dyn FnOnce(&SelectedPolicySource) + Send>;

pub(crate) fn acquire_run_ownership() -> Result<(), DaemonError> {
    RUN_OWNED
        .compare_exchange(false, true, AtomicOrdering::AcqRel, AtomicOrdering::Acquire)
        .map(|_| ())
        .map_err(|_| DaemonError::stable(StableCode::KernelUnavailable))
}

#[cfg(target_os = "linux")]
const RELEASE_STAGE_PATH: &str = "/opt/savana/kernel/release";
#[cfg(target_os = "linux")]
const DAEMON_KEY_PATH: &str = "/var/lib/savana/kernel/private/daemon-identity-v1.seed";
#[cfg(target_os = "linux")]
const LEDGER_PATH: &str = "/var/lib/savana/kernel/state/policy-ledger-v1.cbor";
#[cfg(target_os = "linux")]
const SELECTED_POLICY_PATH: &str = "/etc/savana/kernel/selected-policy-v1.cbor";
#[cfg(target_os = "linux")]
const SELECTED_POLICY_SIGNATURE_PATH: &str = "/etc/savana/kernel/selected-policy-v1.sig";
#[cfg(target_os = "linux")]
const SOCKET_PATH: &str = "/run/savana/kernel/kerneld.sock";

#[cfg(target_os = "macos")]
const RELEASE_STAGE_PATH: &str = "/Library/Application Support/Savana/Kernel/release";
#[cfg(target_os = "macos")]
const DAEMON_KEY_PATH: &str =
    "/Library/Application Support/Savana/Kernel/private/daemon-identity-v1.seed";
#[cfg(target_os = "macos")]
const LEDGER_PATH: &str = "/Library/Application Support/Savana/Kernel/state/policy-ledger-v1.cbor";
#[cfg(target_os = "macos")]
const SELECTED_POLICY_PATH: &str =
    "/Library/Application Support/Savana/Kernel/selected-policy-v1.cbor";
#[cfg(target_os = "macos")]
const SELECTED_POLICY_SIGNATURE_PATH: &str =
    "/Library/Application Support/Savana/Kernel/selected-policy-v1.sig";
#[cfg(target_os = "macos")]
const SOCKET_PATH: &str = "/var/run/savana/kernel/kerneld.sock";

struct FixedLayout {
    bootstrap: PathBuf,
    release_stage: PathBuf,
    release_manifest: PathBuf,
    release_signature: PathBuf,
    executable: PathBuf,
    kernel_lock: PathBuf,
    selected_policy: PathBuf,
    selected_policy_signature: PathBuf,
    daemon_key: PathBuf,
    ledger: PathBuf,
    socket: PathBuf,
}

impl std::fmt::Debug for FixedLayout {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("FixedLayout(<compiled>)")
    }
}

impl FixedLayout {
    fn production() -> Self {
        let release_stage = PathBuf::from(RELEASE_STAGE_PATH);
        Self {
            bootstrap: PathBuf::from(PRODUCTION_BOOTSTRAP_PATH),
            release_manifest: release_stage.join("release/release-manifest-v1.cbor"),
            release_signature: release_stage.join("release/release-manifest-v1.sig"),
            executable: release_stage.join("bin/savana-kerneld"),
            release_stage,
            kernel_lock: PathBuf::from(KERNEL_LOCK_PATH),
            selected_policy: PathBuf::from(SELECTED_POLICY_PATH),
            selected_policy_signature: PathBuf::from(SELECTED_POLICY_SIGNATURE_PATH),
            daemon_key: PathBuf::from(DAEMON_KEY_PATH),
            ledger: PathBuf::from(LEDGER_PATH),
            socket: PathBuf::from(SOCKET_PATH),
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    fn mapped(root: &MappedRoot, config_path: &Path) -> Result<Self, DaemonError> {
        let expected_config = map_under(&root.path, PRODUCTION_BOOTSTRAP_PATH);
        if expected_config.as_os_str().as_bytes() != config_path.as_os_str().as_bytes() {
            return Err(release_mismatch());
        }
        let release_stage = map_under(&root.path, RELEASE_STAGE_PATH);
        Ok(Self {
            bootstrap: config_path.to_path_buf(),
            release_manifest: release_stage.join("release/release-manifest-v1.cbor"),
            release_signature: release_stage.join("release/release-manifest-v1.sig"),
            executable: release_stage.join("bin/savana-kerneld"),
            release_stage,
            kernel_lock: map_under(&root.path, KERNEL_LOCK_PATH),
            selected_policy: map_under(&root.path, SELECTED_POLICY_PATH),
            selected_policy_signature: map_under(&root.path, SELECTED_POLICY_SIGNATURE_PATH),
            daemon_key: map_under(&root.path, DAEMON_KEY_PATH),
            ledger: map_under(&root.path, LEDGER_PATH),
            socket: map_under(&root.path, SOCKET_PATH),
        })
    }
}

#[cfg(any(test, feature = "test-support"))]
fn valid_mapped_root(bytes: &[u8]) -> bool {
    if bytes.len() <= 1
        || bytes.first() != Some(&b'/')
        || bytes.last() == Some(&b'/')
        || bytes.windows(2).any(|pair| pair == b"//")
    {
        return false;
    }
    Path::new(OsStr::from_bytes(bytes))
        .components()
        .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

#[cfg(any(test, feature = "test-support"))]
fn map_under(root: &Path, production: &str) -> PathBuf {
    root.join(production.trim_start_matches('/'))
}

#[cfg(any(test, feature = "test-support"))]
struct MappedRoot {
    path: PathBuf,
    capability: DirectoryCapability,
    uid: u32,
    gid: u32,
}

#[cfg(any(test, feature = "test-support"))]
impl std::fmt::Debug for MappedRoot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("MappedRoot(<verified>)")
    }
}

#[cfg(any(test, feature = "test-support"))]
impl MappedRoot {
    fn open(config_path: &Path) -> Result<Self, DaemonError> {
        let root_bytes = config_path
            .as_os_str()
            .as_bytes()
            .strip_suffix(PRODUCTION_BOOTSTRAP_PATH.as_bytes())
            .filter(|root| valid_mapped_root(root))
            .ok_or_else(release_mismatch)?;
        let path = PathBuf::from(OsStr::from_bytes(root_bytes));
        let uid = geteuid().as_raw();
        let gid = getegid().as_raw();
        let capability = DirectoryCapability::open_final(
            &path,
            uid,
            gid,
            0o700,
            StableCode::IdentityReleaseMismatch,
        )?;
        Ok(Self {
            path,
            capability,
            uid,
            gid,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum CompiledPlatform {
    Linux,
    Macos,
}

impl CompiledPlatform {
    #[cfg(target_os = "linux")]
    const fn current() -> Self {
        Self::Linux
    }

    #[cfg(target_os = "macos")]
    const fn current() -> Self {
        Self::Macos
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Linux => "linux",
            Self::Macos => "macos",
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("savana-kerneld supports only Linux and macOS");

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BootstrapTrustRootDto {
    key_id: String,
    public_key: String,
    not_before_unix_ms: u64,
    not_after_unix_ms: u64,
    revoked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BootstrapDto {
    schema_version: u16,
    platform: CompiledPlatform,
    release_trust_roots: Vec<BootstrapTrustRootDto>,
    allowed_release_digest: String,
}

struct BootstrapAnchor {
    platform: CompiledPlatform,
    allowed_release_digest: Digest32,
    release_verifier: ReleaseVerifier,
}

#[derive(Clone, Copy)]
enum BootstrapTrustRootSource {
    ProductionFixedPath,
    #[cfg(any(test, feature = "test-support"))]
    MappedTestSupport,
}

impl BootstrapTrustRootSource {
    const fn rejects_documented_fixture_keys(self) -> bool {
        match self {
            Self::ProductionFixedPath => true,
            #[cfg(any(test, feature = "test-support"))]
            Self::MappedTestSupport => false,
        }
    }
}

pub(crate) struct BootstrapContext {
    layout: FixedLayout,
    anchor: BootstrapAnchor,
    bootstrap_parent: DirectoryCapability,
    bootstrap_file: FileCapability,
    owner_uid: u32,
    owner_gid: u32,
    #[cfg(any(test, feature = "test-support"))]
    mapped_root: Option<MappedRoot>,
}

impl std::fmt::Debug for BootstrapContext {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("BootstrapContext(<verified>)")
    }
}

impl BootstrapContext {
    pub(crate) fn open(config_path: &Path) -> Result<Self, DaemonError> {
        #[cfg(not(any(test, feature = "test-support")))]
        let (layout, owner_uid, owner_gid, ()) = select_layout(config_path)?;
        #[cfg(any(test, feature = "test-support"))]
        let (layout, owner_uid, owner_gid, mapped_root) = select_layout(config_path)?;
        let parent_path = layout.bootstrap.parent().ok_or_else(release_mismatch)?;
        let leaf = layout.bootstrap.file_name().ok_or_else(release_mismatch)?;
        let bootstrap_parent = DirectoryCapability::open_final(
            parent_path,
            owner_uid,
            owner_gid,
            0o755,
            StableCode::IdentityReleaseMismatch,
        )?;
        let bootstrap_file = bootstrap_parent.open_file(
            leaf,
            FileExpectation {
                owner_uid,
                owner_gid,
                permissions: 0o444,
                length: LengthRule::Maximum(MAXIMUM_BOOTSTRAP_BYTES_U64),
            },
        )?;
        let bytes = bootstrap_file.read_bounded(MAXIMUM_BOOTSTRAP_BYTES_U64)?;
        #[cfg(not(any(test, feature = "test-support")))]
        let anchor = BootstrapAnchor::parse(&bytes)?;
        #[cfg(any(test, feature = "test-support"))]
        let anchor = if mapped_root.is_some() {
            BootstrapAnchor::parse_mapped_test_support(&bytes)?
        } else {
            BootstrapAnchor::parse(&bytes)?
        };
        bootstrap_file.recheck()?;
        bootstrap_parent.recheck()?;
        #[cfg(any(test, feature = "test-support"))]
        if let Some(root) = &mapped_root {
            root.capability.recheck()?;
        }
        Ok(Self {
            layout,
            anchor,
            bootstrap_parent,
            bootstrap_file,
            owner_uid,
            owner_gid,
            #[cfg(any(test, feature = "test-support"))]
            mapped_root,
        })
    }

    fn recheck(&self) -> Result<(), DaemonError> {
        self.bootstrap_file.recheck()?;
        self.bootstrap_parent.recheck()?;
        #[cfg(any(test, feature = "test-support"))]
        if let Some(root) = &self.mapped_root {
            root.capability.recheck()?;
        }
        Ok(())
    }

    fn verify_current_release(
        &self,
        now: UnixMillis,
    ) -> Result<VerifiedReleaseIdentity, DaemonError> {
        let current_executable = {
            #[cfg(any(test, feature = "test-support"))]
            if self.mapped_root.is_some() {
                self.layout.release_stage.join("bin/savana-kerneld")
            } else {
                std::env::current_exe().map_err(|_| release_mismatch())?
            }
            #[cfg(not(any(test, feature = "test-support")))]
            std::env::current_exe().map_err(|_| release_mismatch())?
        };
        #[cfg(any(test, feature = "test-support"))]
        let stage = if self.mapped_root.is_some() {
            ReleaseStage::open_mapped_for_test_support(
                &self.layout.release_stage,
                &current_executable,
                self.owner_uid,
                self.owner_gid,
            )
        } else {
            ReleaseStage::open_compiled(&current_executable)
        }
        .map_err(|error| DaemonError::stable(error.code()))?;
        #[cfg(not(any(test, feature = "test-support")))]
        let stage = ReleaseStage::open_compiled(&current_executable)
            .map_err(|error| DaemonError::stable(error.code()))?;
        let verified = self
            .anchor
            .release_verifier()
            .verify_stage(&stage, now)
            .map_err(|error| DaemonError::stable(error.code()))?;
        self.recheck()?;
        Ok(verified)
    }

    fn open_selected_policy_source(
        &self,
        release: &VerifiedReleaseIdentity,
    ) -> Result<Arc<SelectedPolicySource>, DaemonError> {
        let mapped = self.uses_mapped_layout();
        let update_lock_owner_uid = if mapped { self.owner_uid } else { 0 };
        let update_lock_owner_gid = if mapped {
            self.owner_gid
        } else {
            release.daemon_gid()
        };
        let source = SelectedPolicySource::open(
            &self.layout.kernel_lock,
            &self.layout.selected_policy,
            &self.layout.selected_policy_signature,
            self.owner_uid,
            self.owner_gid,
            update_lock_owner_uid,
            update_lock_owner_gid,
        )?;
        self.recheck()?;
        Ok(source)
    }

    fn open_daemon_key(
        &self,
        release: &VerifiedReleaseIdentity,
    ) -> Result<DaemonKeyCapability, DaemonError> {
        let mapped = self.uses_mapped_layout();
        let parent_uid = if mapped { self.owner_uid } else { 0 };
        let parent_gid = if mapped {
            self.owner_gid
        } else {
            release.daemon_gid()
        };
        let key_uid = if mapped {
            self.owner_uid
        } else {
            release.daemon_uid()
        };
        let key_gid = if mapped {
            self.owner_gid
        } else {
            release.daemon_gid()
        };
        let capability = DaemonKeyCapability::open(
            &self.layout.daemon_key,
            parent_uid,
            parent_gid,
            key_uid,
            key_gid,
        )?;
        self.recheck()?;
        Ok(capability)
    }

    fn open_policy_state(
        &self,
        release: &VerifiedReleaseIdentity,
    ) -> Result<OpenedPolicyState, DaemonError> {
        let mapped = self.uses_mapped_layout();
        let state_path = self.layout.ledger.parent().ok_or_else(release_mismatch)?;
        let common_path = state_path.parent().ok_or_else(release_mismatch)?;
        let common_uid = if mapped { self.owner_uid } else { 0 };
        let common_gid = if mapped { self.owner_gid } else { 0 };
        let state_uid = if mapped {
            self.owner_uid
        } else {
            release.daemon_uid()
        };
        let state_gid = if mapped {
            self.owner_gid
        } else {
            release.daemon_gid()
        };
        let common = DirectoryCapability::open_final(
            common_path,
            common_uid,
            common_gid,
            0o755,
            StableCode::ProtocolIo,
        )?;
        let capability = PolicyStateCapability::open(&self.layout.ledger, state_uid, state_gid)
            .map_err(|error| DaemonError::stable(error.code()))?;
        common.recheck()?;
        self.recheck()?;
        Ok(OpenedPolicyState { common, capability })
    }

    fn verify_process_identity(
        &self,
        release: &VerifiedReleaseIdentity,
    ) -> Result<(), DaemonError> {
        let mapped = self.uses_mapped_layout();
        let expected_uid = if mapped {
            self.owner_uid
        } else {
            release.daemon_uid()
        };
        let expected_gid = if mapped {
            self.owner_gid
        } else {
            release.daemon_gid()
        };
        if geteuid().as_raw() != expected_uid || getegid().as_raw() != expected_gid {
            return Err(DaemonError::stable(StableCode::IdentitySocketPermissions));
        }
        let logical_socket_gid = release
            .daemon_clients()
            .first()
            .map(savana_policy_core::InstallationClientV1::peer_gid)
            .ok_or_else(release_mismatch)?;
        let physical_socket_gid = if mapped {
            self.owner_gid
        } else {
            logical_socket_gid
        };
        let supplementary = rustix::process::getgroups()
            .map_err(|_| DaemonError::stable(StableCode::KernelUnavailable))?;
        let member = supplementary
            .iter()
            .any(|gid| gid.as_raw() == physical_socket_gid);
        if !(member || mapped && getegid().as_raw() == physical_socket_gid) {
            return Err(DaemonError::stable(StableCode::IdentitySocketPermissions));
        }
        Ok(())
    }

    fn preflight_socket(
        &self,
        release: &VerifiedReleaseIdentity,
    ) -> Result<SocketPreflight, DaemonError> {
        let mapped = self.uses_mapped_layout();
        #[cfg(any(test, feature = "test-support"))]
        let config = if mapped {
            SocketConfig::from_mapped_release(
                release,
                self.layout.socket.clone(),
                self.owner_uid,
                self.owner_gid,
            )
        } else {
            SocketConfig::from_release(release)
        }
        .map_err(DaemonError::stable)?;
        #[cfg(not(any(test, feature = "test-support")))]
        let config = {
            let _ = mapped;
            SocketConfig::from_release(release).map_err(DaemonError::stable)?
        };
        if !self.uses_mapped_layout()
            && Path::new(release.socket_path()).as_os_str().as_bytes()
                != self.layout.socket.as_os_str().as_bytes()
        {
            return Err(release_mismatch());
        }
        let preflight = preflight_socket(&config).map_err(DaemonError::stable)?;
        self.recheck()?;
        Ok(preflight)
    }

    fn verify_signed_fixed_paths(&self, config: &DaemonConfig) -> Result<(), DaemonError> {
        if config.release_digest() != self.anchor.allowed_release_digest()
            || Path::new(config.selected_policy_path())
                .as_os_str()
                .as_bytes()
                != SELECTED_POLICY_PATH.as_bytes()
            || Path::new(config.selected_policy_signature_path())
                .as_os_str()
                .as_bytes()
                != SELECTED_POLICY_SIGNATURE_PATH.as_bytes()
            || Path::new(config.socket_path()).as_os_str().as_bytes() != SOCKET_PATH.as_bytes()
        {
            return Err(release_mismatch());
        }
        Ok(())
    }

    pub(crate) const fn uses_mapped_layout(&self) -> bool {
        #[cfg(any(test, feature = "test-support"))]
        {
            self.mapped_root.is_some()
        }
        #[cfg(not(any(test, feature = "test-support")))]
        {
            false
        }
    }
}

struct OpenedPolicyState {
    common: DirectoryCapability,
    capability: PolicyStateCapability,
}

impl std::fmt::Debug for OpenedPolicyState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("OpenedPolicyState(<verified>)")
    }
}

impl OpenedPolicyState {
    fn into_store(self, verifier: PolicyVerifier) -> Result<OpenedPolicyStore, DaemonError> {
        self.common.recheck()?;
        let store = PolicyStore::open_capability(self.capability, verifier)
            .map_err(|error| DaemonError::stable(error.code()))?;
        self.common.recheck()?;
        Ok(OpenedPolicyStore {
            common: self.common,
            store,
        })
    }
}

struct OpenedPolicyStore {
    common: DirectoryCapability,
    store: PolicyStore,
}

impl std::fmt::Debug for OpenedPolicyStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("OpenedPolicyStore(<locked>)")
    }
}

impl OpenedPolicyStore {
    fn into_parts(self) -> (DirectoryCapability, PolicyStore) {
        (self.common, self.store)
    }
}

/// Builds the single coordinator used to publish verified V2 deployment
/// successors. Keeping construction here prevents startup paths from growing
/// an independent rules-only rollover surface.
pub(crate) fn v2_policy_rollover_coordinator(
    runtime: Arc<crate::policy_runtime::V2GenerationRuntime>,
) -> Arc<PolicyRolloverCoordinator> {
    Arc::new(PolicyRolloverCoordinator::new_v2(runtime))
}

pub(crate) struct PreparedRuntime {
    context: BootstrapContext,
    daemon_key: DaemonKeyCapability,
    state_common: DirectoryCapability,
    config: DaemonConfig,
    service: HandshakeService,
    socket: SocketPreflight,
    clock: Arc<dyn Clock + Send + Sync>,
    runtime: Arc<PolicyRuntime>,
    rollover: Arc<PolicyRolloverCoordinator>,
    selected_guard: Option<SelectedPolicyUpdateGuard>,
}

impl std::fmt::Debug for PreparedRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PreparedRuntime(<verified>)")
    }
}

fn finish_policy_acceptance_before_key_load<P, K, A, L>(
    accept_policy: A,
    load_key: L,
) -> Result<(P, K), DaemonError>
where
    A: FnOnce() -> Result<P, DaemonError>,
    L: FnOnce() -> Result<K, DaemonError>,
{
    let accepted_policy = accept_policy()?;
    let signing_identity = load_key()?;
    Ok((accepted_policy, signing_identity))
}

impl PreparedRuntime {
    pub(crate) fn prepare_with_dependencies(
        config_path: &Path,
        boot_id: savana_kernel_protocol::BootId,
        clock: Arc<dyn Clock + Send + Sync>,
        random: Arc<dyn RandomSource + Send + Sync>,
    ) -> Result<Self, DaemonError> {
        let context = BootstrapContext::open(config_path)?;
        Self::prepare_from_context(context, boot_id, clock, random)
    }

    pub(crate) fn prepare_from_context(
        context: BootstrapContext,
        boot_id: savana_kernel_protocol::BootId,
        clock: Arc<dyn Clock + Send + Sync>,
        random: Arc<dyn RandomSource + Send + Sync>,
    ) -> Result<Self, DaemonError> {
        #[cfg(test)]
        return Self::prepare_inner(context, boot_id, clock, random, None);
        #[cfg(not(test))]
        Self::prepare_inner(context, boot_id, clock, random)
    }

    fn prepare_inner(
        context: BootstrapContext,
        boot_id: savana_kernel_protocol::BootId,
        clock: Arc<dyn Clock + Send + Sync>,
        random: Arc<dyn RandomSource + Send + Sync>,
        #[cfg(test)] source_hook: Option<SelectedPolicySourceHook>,
    ) -> Result<Self, DaemonError> {
        if boot_id.as_bytes() == &[0; 32] {
            return Err(unavailable());
        }
        let clock = checked_clock(clock);
        let startup_now = clock.wall_now().map_err(|_| unavailable())?;
        let release = context.verify_current_release(startup_now)?;
        let rollover_release = release.clone();
        bootstrap_trace!(BootstrapEvent::ReleaseVerified);
        context.verify_process_identity(&release)?;
        let policy_verifier = release
            .policy_verifier()
            .map_err(|error| DaemonError::stable(error.code()))?;
        bootstrap_trace!(BootstrapEvent::ReleaseVerifierBound);
        let policy_state = context.open_policy_state(&release)?;
        let opened_store = policy_state.into_store(policy_verifier.clone())?;
        bootstrap_trace!(BootstrapEvent::LedgerLifetimeLockAcquired);
        let (state_common, policy_store) = opened_store.into_parts();
        let selected_source = context.open_selected_policy_source(&release)?;
        #[cfg(test)]
        if let Some(source_hook) = source_hook {
            source_hook(&selected_source);
        }
        let selected_guard = selected_source.acquire()?;
        bootstrap_trace!(BootstrapEvent::SelectedUpdateSharedLockAcquired);
        let candidate = selected_guard.read_candidate()?;
        bootstrap_trace!(BootstrapEvent::CandidateRead);
        let stateless_policy = policy_verifier
            .verify(&candidate.policy_bytes, &candidate.signature, startup_now)
            .map_err(|error| DaemonError::stable(error.code()))?;
        bootstrap_trace!(BootstrapEvent::CandidateStatelesslyVerified);
        let config = DaemonConfig::from_verified(
            &candidate.kernel_lock_bytes,
            &release,
            &stateless_policy,
            &candidate.signature,
        )?;
        let candidate_runtime =
            CandidateRuntimeData::from_config_and_candidate(&config, &stateless_policy)
                .map_err(DaemonError::stable)?;
        bootstrap_trace!(BootstrapEvent::FixedLockVerified);
        context.verify_signed_fixed_paths(&config)?;
        if startup_now.get() >= release.expires_at().get() {
            return Err(release_mismatch());
        }
        let daemon_key = context.open_daemon_key(&release)?;
        let socket = context.preflight_socket(&release)?;
        context.recheck()?;
        daemon_key.recheck()?;
        state_common.recheck()?;
        socket.recheck().map_err(DaemonError::stable)?;
        selected_guard.final_recheck()?;
        bootstrap_trace!(BootstrapEvent::FinalDescriptorRecheck);
        let daemon_public_key = *release.daemon_identity().public_key();
        let current = policy_store
            .verify_and_accept_initial(
                release,
                &candidate.policy_bytes,
                &candidate.signature,
                startup_now,
            )
            .map_err(|error| DaemonError::stable(error.code()))?;
        bootstrap_trace!(BootstrapEvent::LedgerPersisted);
        bootstrap_trace!(BootstrapEvent::CurrentCapabilityReturned);
        let signing_identity = daemon_key.load(&daemon_public_key)?;
        bootstrap_trace!(BootstrapEvent::DaemonKeyLoaded);
        let (engine, issuer) =
            PolicyEngine::new(current, boot_id, Arc::clone(&clock), Arc::clone(&random))
                .map_err(|error| DaemonError::stable(error.code()))?;
        bootstrap_trace!(BootstrapEvent::EngineConstructed);
        let policy_identity = engine.current_policy_identity();
        let effective_limits = engine.effective_limits();
        let snapshot = Arc::new(
            DaemonPolicyRuntimeSnapshot::initial(
                candidate_runtime,
                policy_identity,
                effective_limits,
            )
            .map_err(DaemonError::stable)?,
        );
        let runtime = Arc::new(PolicyRuntime::new(snapshot, engine, Arc::new(issuer)));
        let rollover = Arc::new(PolicyRolloverCoordinator::new(
            Arc::clone(&selected_source),
            rollover_release,
            Arc::clone(&runtime),
            Arc::clone(&clock),
        ));
        clock.monotonic_now_millis().map_err(|_| unavailable())?;
        let service = HandshakeService::new(
            Arc::clone(&runtime),
            signing_identity,
            startup_now,
            boot_id,
            Arc::clone(&random),
        )
        .map_err(DaemonError::stable)?;
        let pre_bind_now = clock.wall_now().map_err(|_| unavailable())?;
        service
            .refresh_before_bind(pre_bind_now)
            .map_err(DaemonError::stable)?;

        context.recheck()?;
        daemon_key.recheck()?;
        state_common.recheck()?;
        socket.recheck().map_err(DaemonError::stable)?;

        Ok(Self {
            context,
            daemon_key,
            state_common,
            config,
            service,
            socket,
            clock,
            runtime,
            rollover,
            selected_guard: Some(selected_guard),
        })
    }

    #[cfg(test)]
    pub(crate) fn prepare_with_source_hook_for_test(
        config_path: &Path,
        boot_id: savana_kernel_protocol::BootId,
        clock: Arc<dyn Clock + Send + Sync>,
        random: Arc<dyn RandomSource + Send + Sync>,
        source_hook: SelectedPolicySourceHook,
    ) -> Result<Self, DaemonError> {
        let context = BootstrapContext::open(config_path)?;
        Self::prepare_inner(context, boot_id, clock, random, Some(source_hook))
    }

    #[cfg(test)]
    pub(crate) fn live_selected_artifact_descriptor_sets(&self) -> usize {
        self.selected_guard
            .as_ref()
            .map_or(0, SelectedPolicyUpdateGuard::live_artifact_sets)
    }

    #[cfg(test)]
    pub(crate) fn selected_artifact_drop_probe(&self) -> Arc<std::sync::atomic::AtomicUsize> {
        self.selected_guard
            .as_ref()
            .expect("prepared runtime retains the selected-policy guard")
            .artifact_drop_probe()
    }

    #[cfg(test)]
    pub(crate) fn refresh_selected_policy_for_test(
        &self,
    ) -> Result<crate::policy_runtime::RefreshOutcome, StableCode> {
        self.rollover.refresh_selected_policy()
    }

    #[cfg(test)]
    pub(crate) fn policy_runtime_for_test(&self) -> &Arc<PolicyRuntime> {
        &self.runtime
    }

    #[cfg(test)]
    pub(crate) fn rollover_probe_counts_for_test(&self) -> (usize, usize, usize, usize) {
        let probe = self.rollover.probe_snapshot();
        (
            probe.snapshot_prebuilds,
            probe.dispatch_close_attempts,
            probe.handshake_write_locks,
            probe.engine_prepares,
        )
    }

    #[cfg(test)]
    pub(crate) fn rollover_lock_trace_for_test(&self) -> Vec<crate::policy_runtime::LockEvent> {
        self.rollover.lock_trace()
    }

    #[cfg(test)]
    pub(crate) fn exercise_startup_guard_for_test(
        &mut self,
        lifecycle: &mut dyn ServerLifecycle,
    ) -> Result<(), DaemonError> {
        let selected_guard = self.selected_guard.take().ok_or_else(unavailable)?;
        let mut guarded = StartupGuardLifecycle {
            inner: lifecycle,
            selected_guard: Some(selected_guard),
        };
        let result = guarded.workers_started();
        drop(guarded);
        result.map_err(DaemonError::stable)
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn prepare_with_test_dependencies(
        config_path: &Path,
        boot_id: savana_kernel_protocol::BootId,
        clock: Arc<dyn Clock + Send + Sync>,
        random: Arc<dyn RandomSource + Send + Sync>,
    ) -> Result<Self, DaemonError> {
        Self::prepare_with_dependencies(config_path, boot_id, clock, random)
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn test_identities(
        &self,
    ) -> Result<
        (
            savana_kernel_protocol::BootId,
            savana_kernel_protocol::BootId,
            savana_policy_core::PolicyIdentity,
            savana_policy_core::PolicyIdentity,
        ),
        DaemonError,
    > {
        let handshake = self
            .service
            .started_identity()
            .map_err(DaemonError::stable)?;
        Ok((
            self.runtime.engine().boot_id_for_test(),
            handshake.boot_id,
            self.runtime.engine().current_policy_identity(),
            self.service.policy_identity_for_test(),
        ))
    }

    #[cfg(all(feature = "test-support", debug_assertions))]
    pub(crate) fn begin_test_lifecycle_control(&self) -> Result<TestLifecycleControl, DaemonError> {
        if !self.context.uses_mapped_layout() {
            return Err(unavailable());
        }
        Ok(TestLifecycleControl::new(
            Arc::clone(&self.runtime),
            Arc::clone(&self.rollover),
            Arc::clone(&self.clock),
        ))
    }

    pub(crate) const fn release_digest(&self) -> Digest32 {
        self.config.release_digest()
    }

    pub(crate) fn bind(self, audit: Arc<AuditSink>) -> Result<BoundRuntime, DaemonError> {
        let identity = self
            .service
            .started_identity()
            .map_err(DaemonError::stable)?;
        let Self {
            context,
            daemon_key,
            state_common,
            service,
            socket,
            clock,
            runtime,
            rollover,
            selected_guard,
            ..
        } = self;
        let retained = RuntimeRetention {
            context,
            daemon_key,
            state_common,
        };
        retained.recheck()?;
        let server = KernelServer::new_preflight(service, socket, Arc::clone(&audit), clock)
            .map_err(DaemonError::stable)?;
        Ok(BoundRuntime {
            server,
            retained,
            audit,
            identity,
            selected_guard,
            runtime,
            rollover,
        })
    }
}

pub(crate) struct BoundRuntime {
    server: KernelServer,
    retained: RuntimeRetention,
    audit: Arc<AuditSink>,
    identity: savana_kernel_protocol::ServerIdentityV1,
    selected_guard: Option<SelectedPolicyUpdateGuard>,
    runtime: Arc<PolicyRuntime>,
    rollover: Arc<PolicyRolloverCoordinator>,
}

impl std::fmt::Debug for BoundRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("BoundRuntime(<listening>)")
    }
}

impl BoundRuntime {
    pub(crate) fn run(self, lifecycle: &mut dyn ServerLifecycle) -> Result<(), DaemonError> {
        let Self {
            server,
            retained,
            audit,
            identity,
            selected_guard,
            runtime,
            rollover,
        } = self;
        if audit
            .emit(AuditEvent::Started {
                identity: &identity,
            })
            .is_err()
        {
            let _ = server.close();
            let _ = retained.recheck();
            return Err(DaemonError::stable(StableCode::KernelUnavailable));
        }

        let mut lifecycle = StartupGuardLifecycle {
            inner: lifecycle,
            selected_guard,
        };
        let server_result = server.run_with_lifecycle(&mut lifecycle);
        drop(lifecycle);
        let _ = (&runtime, &rollover);
        let retained_result = retained.recheck();
        if let Err(code) = server_result {
            return Err(DaemonError::stable(code));
        }
        retained_result
    }

    #[cfg(all(feature = "test-support", debug_assertions))]
    pub(crate) fn run_with_test_lifecycle(
        self,
        lifecycle: &mut dyn ServerLifecycle,
        control: TestLifecycleControl,
    ) -> Result<(), DaemonError> {
        let Self {
            server,
            retained,
            audit,
            identity,
            selected_guard,
            runtime,
            rollover,
        } = self;
        if audit
            .emit(AuditEvent::Started {
                identity: &identity,
            })
            .is_err()
        {
            let _ = server.close();
            let _ = retained.recheck();
            return Err(DaemonError::stable(StableCode::KernelUnavailable));
        }
        control
            .attach_handshake_service(server.test_lifecycle_handshake_service())
            .map_err(DaemonError::stable)?;
        let mut controlled = TestLifecycle::new(lifecycle, control);
        let mut guarded = StartupGuardLifecycle {
            inner: &mut controlled,
            selected_guard,
        };
        let server_result = server.run_with_lifecycle(&mut guarded);
        drop(guarded);
        if let Err(code) = server_result {
            controlled.report_startup_failure(code);
        }
        drop(controlled);
        let _ = (&runtime, &rollover);
        let retained_result = retained.recheck();
        if let Err(code) = server_result {
            return Err(DaemonError::stable(code));
        }
        retained_result
    }
}

struct RuntimeRetention {
    context: BootstrapContext,
    daemon_key: DaemonKeyCapability,
    state_common: DirectoryCapability,
}

impl RuntimeRetention {
    fn recheck(&self) -> Result<(), DaemonError> {
        self.context.recheck()?;
        self.daemon_key.recheck()?;
        self.state_common.recheck()
    }
}

struct StartupGuardLifecycle<'lifecycle> {
    inner: &'lifecycle mut dyn ServerLifecycle,
    selected_guard: Option<SelectedPolicyUpdateGuard>,
}

impl ServerLifecycle for StartupGuardLifecycle<'_> {
    fn workers_started(&mut self) -> Result<(), StableCode> {
        self.inner.workers_started()?;
        bootstrap_trace!(BootstrapEvent::WorkersActivated);
        drop(self.selected_guard.take());
        bootstrap_trace!(BootstrapEvent::SelectedUpdateSharedLockReleased);
        self.inner.activation_completed()
    }

    fn poll_shutdown(&mut self) -> Result<bool, StableCode> {
        self.inner.poll_shutdown()
    }
}

const fn unavailable() -> DaemonError {
    DaemonError::stable(StableCode::KernelUnavailable)
}

#[cfg(not(any(test, feature = "test-support")))]
fn select_layout(config_path: &Path) -> Result<(FixedLayout, u32, u32, ()), DaemonError> {
    validate_production_config_path(config_path)?;
    Ok((FixedLayout::production(), 0, 0, ()))
}

#[cfg(any(test, feature = "test-support"))]
fn select_layout(
    config_path: &Path,
) -> Result<(FixedLayout, u32, u32, Option<MappedRoot>), DaemonError> {
    if validate_production_config_path(config_path).is_ok() {
        return Ok((FixedLayout::production(), 0, 0, None));
    }
    let root = MappedRoot::open(config_path)?;
    let layout = FixedLayout::mapped(&root, config_path)?;
    Ok((layout, root.uid, root.gid, Some(root)))
}

impl std::fmt::Debug for BootstrapAnchor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("BootstrapAnchor(<verified>)")
    }
}

impl BootstrapAnchor {
    fn parse(bytes: &[u8]) -> Result<Self, DaemonError> {
        Self::parse_from(bytes, BootstrapTrustRootSource::ProductionFixedPath)
    }

    #[cfg(any(test, feature = "test-support"))]
    fn parse_mapped_test_support(bytes: &[u8]) -> Result<Self, DaemonError> {
        Self::parse_from(bytes, BootstrapTrustRootSource::MappedTestSupport)
    }

    fn parse_from(
        bytes: &[u8],
        trust_root_source: BootstrapTrustRootSource,
    ) -> Result<Self, DaemonError> {
        if bytes.len() > MAXIMUM_BOOTSTRAP_BYTES {
            return Err(release_mismatch());
        }
        let dto: BootstrapDto = serde_json::from_slice(bytes).map_err(|_| release_mismatch())?;
        let canonical = serde_json::to_vec(&dto).map_err(|_| release_mismatch())?;
        if canonical != bytes
            || dto.schema_version != 1
            || dto.platform != CompiledPlatform::current()
        {
            return Err(release_mismatch());
        }

        let roots = dto
            .release_trust_roots
            .into_iter()
            .map(|root| {
                if trust_root_source.rejects_documented_fixture_keys()
                    && DOCUMENTED_FIXTURE_PUBLIC_KEYS.contains(&root.public_key.as_str())
                {
                    return Err(release_mismatch());
                }
                Ok(ReleaseTrustRootV1 {
                    key_id: KeyId::try_from(root.key_id).map_err(|_| release_mismatch())?,
                    public_key: decode_hex32(&root.public_key)?,
                    not_before: UnixMillis::new(root.not_before_unix_ms),
                    not_after: UnixMillis::new(root.not_after_unix_ms),
                    revoked: root.revoked,
                })
            })
            .collect::<Result<Vec<_>, DaemonError>>()?;
        let allowed_release_digest = Digest32::new(decode_hex32(&dto.allowed_release_digest)?);
        let release_verifier = ReleaseVerifier::new(roots, vec![allowed_release_digest])
            .map_err(|_| release_mismatch())?;

        Ok(Self {
            platform: dto.platform,
            allowed_release_digest,
            release_verifier,
        })
    }

    const fn platform(&self) -> CompiledPlatform {
        self.platform
    }

    const fn allowed_release_digest(&self) -> Digest32 {
        self.allowed_release_digest
    }

    fn release_verifier(&self) -> &ReleaseVerifier {
        &self.release_verifier
    }
}

fn validate_production_config_path(path: &Path) -> Result<(), DaemonError> {
    if path.as_os_str().as_bytes() == PRODUCTION_BOOTSTRAP_PATH.as_bytes() {
        Ok(())
    } else {
        Err(release_mismatch())
    }
}

fn decode_hex32(value: &str) -> Result<[u8; 32], DaemonError> {
    if value.len() != 64
        || !value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(release_mismatch());
    }
    let mut decoded = [0_u8; 32];
    for (target, pair) in decoded.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        *target = (decode_nibble(pair[0]) << 4) | decode_nibble(pair[1]);
    }
    Ok(decoded)
}

const fn decode_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => 0,
    }
}

const fn release_mismatch() -> DaemonError {
    DaemonError::stable(StableCode::IdentityReleaseMismatch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use savana_kernel_protocol::{Digest32, StableCode};
    use std::cell::{Cell, RefCell};
    use std::ffi::OsString;
    use std::fs;
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::path::{Path, PathBuf};

    #[test]
    fn canonical_bootstrap_builds_the_compiled_singleton_trust_anchor() {
        let bytes = canonical_bootstrap();
        let anchor = BootstrapAnchor::parse(&bytes).unwrap();

        assert_eq!(anchor.allowed_release_digest(), Digest32::new([0xa1; 32]));
        assert_eq!(anchor.platform(), CompiledPlatform::current());
        let _ = anchor.release_verifier();
        assert_eq!(
            validate_production_config_path(Path::new("/etc/savana/kerneld-bootstrap-v1.json")),
            Ok(())
        );
        assert_eq!(
            validate_production_config_path(Path::new(
                "/etc/savana/../savana/kerneld-bootstrap-v1.json"
            ))
            .unwrap_err()
            .code(),
            StableCode::IdentityReleaseMismatch
        );
    }

    #[test]
    fn production_bootstrap_rejects_every_documented_fixture_public_key() {
        let fixture_public_keys = [
            "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12",
            "c050c5637a44fa8629fff3cccce2300cb362a63d99d95fc54145266f4332445a",
            "af06a3e3291714e4f356c19c9b15cd1951ec6e6662aa77be07547f289383341d",
            "2df04125f0015afb47ce853aef8772094ff9498c14cb1b9e12973c2927da0fa6",
        ];

        for public_key in fixture_public_keys {
            let bootstrap =
                bootstrap_with_roots(vec![root_json_with_public_key("fixture-root", public_key)]);
            assert_eq!(
                BootstrapAnchor::parse(&bootstrap).unwrap_err().code(),
                StableCode::IdentityReleaseMismatch
            );
        }

        BootstrapAnchor::parse(&bootstrap_with_roots(vec![root_json(
            "production-root",
            "51",
        )]))
        .unwrap();
    }

    #[test]
    fn mapped_test_support_bootstrap_accepts_documented_fixture_public_keys() {
        for public_key in DOCUMENTED_FIXTURE_PUBLIC_KEYS {
            let bootstrap =
                bootstrap_with_roots(vec![root_json_with_public_key("fixture-root", public_key)]);
            BootstrapAnchor::parse_mapped_test_support(&bootstrap).unwrap();
        }
    }

    #[test]
    fn ledger_acceptance_failure_does_not_invoke_private_key_load_seam() {
        let key_load_invoked = Cell::new(false);
        let result: Result<((), ()), DaemonError> = finish_policy_acceptance_before_key_load(
            || Err(DaemonError::stable(StableCode::PolicyRollback)),
            || {
                key_load_invoked.set(true);
                Ok(())
            },
        );

        assert_eq!(result.unwrap_err().code(), StableCode::PolicyRollback);
        assert!(!key_load_invoked.get());
    }

    #[test]
    fn private_key_load_seam_runs_only_after_policy_acceptance_completes() {
        let events = RefCell::new(Vec::new());
        finish_policy_acceptance_before_key_load(
            || {
                events.borrow_mut().push("policy-accepted");
                Ok(())
            },
            || {
                assert_eq!(events.borrow().as_slice(), ["policy-accepted"]);
                events.borrow_mut().push("key-loaded");
                Ok(())
            },
        )
        .unwrap();

        assert_eq!(events.into_inner(), vec!["policy-accepted", "key-loaded"]);
    }

    #[test]
    fn compiled_layout_has_no_caller_selected_production_paths() {
        let layout = FixedLayout::production();

        assert_eq!(
            layout.bootstrap,
            Path::new("/etc/savana/kerneld-bootstrap-v1.json")
        );
        assert_eq!(
            layout.kernel_lock,
            Path::new("/etc/savana/kernel-lock.json")
        );
        assert_eq!(
            layout.release_manifest,
            layout
                .release_stage
                .join("release/release-manifest-v1.cbor")
        );
        assert_eq!(
            layout.release_signature,
            layout.release_stage.join("release/release-manifest-v1.sig")
        );
        assert_eq!(
            layout.executable,
            layout.release_stage.join("bin/savana-kerneld")
        );

        #[cfg(target_os = "linux")]
        {
            assert_eq!(
                layout.release_stage,
                Path::new("/opt/savana/kernel/release")
            );
            assert_eq!(
                layout.daemon_key,
                Path::new("/var/lib/savana/kernel/private/daemon-identity-v1.seed")
            );
            assert_eq!(
                layout.ledger,
                Path::new("/var/lib/savana/kernel/state/policy-ledger-v1.cbor")
            );
        }

        #[cfg(target_os = "macos")]
        {
            assert_eq!(
                layout.release_stage,
                Path::new("/Library/Application Support/Savana/Kernel/release")
            );
            assert_eq!(
                layout.daemon_key,
                Path::new(
                    "/Library/Application Support/Savana/Kernel/private/daemon-identity-v1.seed"
                )
            );
            assert_eq!(
                layout.ledger,
                Path::new("/Library/Application Support/Savana/Kernel/state/policy-ledger-v1.cbor")
            );
        }
    }

    #[test]
    fn production_config_path_requires_exact_original_unix_bytes() {
        let non_utf8 = PathBuf::from(OsString::from_vec(
            b"/etc/savana/kerneld-bootstrap-v1.json\xff".to_vec(),
        ));
        let rejected = [
            Path::new("//etc/savana/kerneld-bootstrap-v1.json"),
            Path::new("/etc//savana/kerneld-bootstrap-v1.json"),
            Path::new("/etc/./savana/kerneld-bootstrap-v1.json"),
            non_utf8.as_path(),
        ];

        for path in rejected {
            assert_eq!(
                validate_production_config_path(path).unwrap_err().code(),
                StableCode::IdentityReleaseMismatch
            );
        }
    }

    #[test]
    fn private_test_mapper_derives_every_path_from_the_exact_config_suffix() {
        let temporary = tempfile::tempdir().unwrap();
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let root = fs::canonicalize(temporary.path()).unwrap();
        let config = root.join("etc/savana/kerneld-bootstrap-v1.json");
        let mapped_root = MappedRoot::open(&config).unwrap();
        let layout = FixedLayout::mapped(&mapped_root, &config).unwrap();

        assert_eq!(layout.bootstrap, config);
        assert_eq!(
            layout.release_stage,
            root.join(RELEASE_STAGE_PATH.trim_start_matches('/'))
        );
        assert_eq!(
            layout.kernel_lock,
            root.join(KERNEL_LOCK_PATH.trim_start_matches('/'))
        );
        assert_eq!(
            layout.daemon_key,
            root.join(DAEMON_KEY_PATH.trim_start_matches('/'))
        );
        assert_eq!(
            layout.ledger,
            root.join(LEDGER_PATH.trim_start_matches('/'))
        );
        assert_eq!(
            layout.socket,
            root.join(SOCKET_PATH.trim_start_matches('/'))
        );

        let rejected = [
            root.join("etc/savana/other.json"),
            root.join("../mapped-root/etc/savana/kerneld-bootstrap-v1.json"),
            PathBuf::from(format!(
                "{}//etc/savana/kerneld-bootstrap-v1.json",
                root.display()
            )),
        ];
        for rejected in &rejected {
            assert_eq!(
                MappedRoot::open(rejected).unwrap_err().code(),
                StableCode::IdentityReleaseMismatch
            );
        }
    }

    #[test]
    fn bootstrap_parser_has_an_inclusive_64_kib_input_ceiling() {
        assert_eq!(MAXIMUM_BOOTSTRAP_BYTES, 64 * 1024);
        let oversized = vec![b' '; MAXIMUM_BOOTSTRAP_BYTES + 1];
        assert_eq!(
            BootstrapAnchor::parse(&oversized).unwrap_err().code(),
            StableCode::IdentityReleaseMismatch
        );
    }

    #[test]
    fn bootstrap_schema_canonicality_roots_and_digest_are_closed() {
        let canonical = String::from_utf8(canonical_bootstrap()).unwrap();
        let platform = CompiledPlatform::current().as_str();
        let other_platform = if platform == "linux" {
            "macos"
        } else {
            "linux"
        };
        let mut cases = vec![
            format!(" {canonical}").into_bytes(),
            format!("{canonical}\n").into_bytes(),
            canonical
                .replacen('{', "{\"schema_version\":1,", 1)
                .into_bytes(),
            canonical
                .replacen('{', "{\"unknown\":true,", 1)
                .into_bytes(),
            canonical
                .replacen(
                    &format!("{{\"schema_version\":1,\"platform\":\"{platform}\","),
                    &format!("{{\"platform\":\"{platform}\",\"schema_version\":1,"),
                    1,
                )
                .into_bytes(),
            canonical
                .replacen("\"schema_version\":1", "\"schema_version\":2", 1)
                .into_bytes(),
            canonical
                .replacen(
                    &format!("\"platform\":\"{platform}\""),
                    &format!("\"platform\":\"{other_platform}\""),
                    1,
                )
                .into_bytes(),
            canonical
                .replacen(&"51".repeat(32), &"00".repeat(32), 1)
                .into_bytes(),
            canonical
                .replacen(&"a1".repeat(32), &"00".repeat(32), 1)
                .into_bytes(),
            canonical
                .replacen(&"a1".repeat(32), &"A1".repeat(32), 1)
                .into_bytes(),
            canonical
                .replacen("\"not_after_unix_ms\":5000", "\"not_after_unix_ms\":1000", 1)
                .into_bytes(),
            canonical
                .replacen(
                    &format!(
                        "[{{\"key_id\":\"release-root\",\"public_key\":\"{}\",\"not_before_unix_ms\":1000,\"not_after_unix_ms\":5000,\"revoked\":false}}]",
                        "51".repeat(32)
                    ),
                    "[]",
                    1,
                )
                .into_bytes(),
        ];
        cases.push(bootstrap_with_roots(vec![
            root_json("root-b", "52"),
            root_json("root-a", "51"),
        ]));
        cases.push(bootstrap_with_roots(
            (0..17)
                .map(|index| root_json(&format!("root-{index:02}"), "51"))
                .collect(),
        ));

        for bytes in cases {
            assert_eq!(
                BootstrapAnchor::parse(&bytes).unwrap_err().code(),
                StableCode::IdentityReleaseMismatch
            );
        }

        let unusable_but_well_formed = canonical
            .replacen(&"51".repeat(32), &"ff".repeat(32), 1)
            .into_bytes();
        BootstrapAnchor::parse(&unusable_but_well_formed).unwrap();
    }

    #[test]
    fn mapped_bootstrap_is_opened_through_verified_root_parent_and_leaf_capabilities() {
        let (_root, config) = mapped_bootstrap_fixture();

        let context = BootstrapContext::open(&config).unwrap();
        assert_eq!(
            context.anchor.allowed_release_digest(),
            Digest32::new([0xa1; 32])
        );
        assert_eq!(context.layout.bootstrap, config);
        context.recheck().unwrap();
    }

    #[test]
    fn mapped_bootstrap_capabilities_reject_metadata_links_size_and_replacement() {
        let (root, config) = mapped_bootstrap_fixture();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert_bootstrap_open_rejected(&config);

        let (_root, config) = mapped_bootstrap_fixture();
        fs::set_permissions(config.parent().unwrap(), fs::Permissions::from_mode(0o775)).unwrap();
        assert_bootstrap_open_rejected(&config);

        let (_root, config) = mapped_bootstrap_fixture();
        fs::set_permissions(&config, fs::Permissions::from_mode(0o644)).unwrap();
        assert_bootstrap_open_rejected(&config);

        let (root, config) = mapped_bootstrap_fixture();
        fs::hard_link(&config, root.path().join("bootstrap-hard-link")).unwrap();
        assert_bootstrap_open_rejected(&config);

        let (_root, config) = mapped_bootstrap_fixture();
        fs::remove_file(&config).unwrap();
        symlink("/dev/null", &config).unwrap();
        assert_bootstrap_open_rejected(&config);

        let (_root, config) = mapped_bootstrap_fixture();
        fs::set_permissions(&config, fs::Permissions::from_mode(0o644)).unwrap();
        fs::write(&config, vec![b' '; MAXIMUM_BOOTSTRAP_BYTES + 1]).unwrap();
        fs::set_permissions(&config, fs::Permissions::from_mode(0o444)).unwrap();
        assert_bootstrap_open_rejected(&config);

        let (_root, config) = mapped_bootstrap_fixture();
        let context = BootstrapContext::open(&config).unwrap();
        let replaced = config.with_extension("replaced");
        fs::rename(&config, &replaced).unwrap();
        fs::copy(&replaced, &config).unwrap();
        fs::set_permissions(&config, fs::Permissions::from_mode(0o444)).unwrap();
        assert_eq!(
            context.recheck().unwrap_err().code(),
            StableCode::IdentityReleaseMismatch
        );
    }

    #[test]
    fn root_owned_lock_and_selected_policy_are_held_and_bounded_before_verification() {
        let (root, config) = mapped_bootstrap_fixture();
        let lock = root.path().join(KERNEL_LOCK_PATH.trim_start_matches('/'));
        fs::write(&lock, b"{\"lock\":true}").unwrap();
        fs::set_permissions(&lock, fs::Permissions::from_mode(0o444)).unwrap();

        let policy = root
            .path()
            .join(SELECTED_POLICY_PATH.trim_start_matches('/'));
        let signature = root
            .path()
            .join(SELECTED_POLICY_SIGNATURE_PATH.trim_start_matches('/'));
        fs::create_dir_all(policy.parent().unwrap()).unwrap();
        fs::set_permissions(policy.parent().unwrap(), fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(&policy, b"selected-policy").unwrap();
        fs::write(&signature, [0x73; 64]).unwrap();
        fs::set_permissions(&policy, fs::Permissions::from_mode(0o444)).unwrap();
        fs::set_permissions(&signature, fs::Permissions::from_mode(0o444)).unwrap();

        let update_lock = policy
            .parent()
            .unwrap()
            .join(".selected-policy-v1.update.lock");
        fs::write(&update_lock, []).unwrap();
        fs::set_permissions(&update_lock, fs::Permissions::from_mode(0o640)).unwrap();

        let context = BootstrapContext::open(&config).unwrap();
        let source = SelectedPolicySource::open(
            &context.layout.kernel_lock,
            &context.layout.selected_policy,
            &context.layout.selected_policy_signature,
            context.owner_uid,
            context.owner_gid,
            context.owner_uid,
            context.owner_gid,
        )
        .unwrap();
        let guard = source.acquire().unwrap();
        let candidate = guard.read_candidate().unwrap();
        assert_eq!(candidate.kernel_lock_bytes, b"{\"lock\":true}");
        assert_eq!(candidate.policy_bytes, b"selected-policy");
        assert_eq!(candidate.signature.as_bytes(), &[0x73; 64]);
        guard.final_recheck().unwrap();
    }

    #[test]
    fn process_global_run_ownership_is_never_reset_after_acquisition() {
        acquire_run_ownership().unwrap();
        assert_eq!(
            acquire_run_ownership().unwrap_err().code(),
            StableCode::KernelUnavailable
        );
    }

    fn mapped_bootstrap_fixture() -> (tempfile::TempDir, PathBuf) {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let parent = root.path().join("etc/savana");
        fs::create_dir_all(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o755)).unwrap();
        let config = parent.join("kerneld-bootstrap-v1.json");
        fs::write(&config, canonical_bootstrap()).unwrap();
        fs::set_permissions(&config, fs::Permissions::from_mode(0o444)).unwrap();
        (root, config)
    }

    fn assert_bootstrap_open_rejected(config: &Path) {
        assert_eq!(
            BootstrapContext::open(config).unwrap_err().code(),
            StableCode::IdentityReleaseMismatch
        );
    }

    fn canonical_bootstrap() -> Vec<u8> {
        bootstrap_with_roots(vec![root_json("release-root", "51")])
    }

    fn bootstrap_with_roots(roots: Vec<String>) -> Vec<u8> {
        format!(
            concat!(
                "{{",
                "\"schema_version\":1,",
                "\"platform\":\"{}\",",
                "\"release_trust_roots\":[{}],",
                "\"allowed_release_digest\":\"{}\"",
                "}}"
            ),
            CompiledPlatform::current().as_str(),
            roots.join(","),
            "a1".repeat(32),
        )
        .into_bytes()
    }

    fn root_json(key_id: &str, byte: &str) -> String {
        root_json_with_public_key(key_id, &byte.repeat(32))
    }

    fn root_json_with_public_key(key_id: &str, public_key: &str) -> String {
        format!(
            concat!(
                "{{",
                "\"key_id\":\"{}\",",
                "\"public_key\":\"{}\",",
                "\"not_before_unix_ms\":1000,",
                "\"not_after_unix_ms\":5000,",
                "\"revoked\":false",
                "}}"
            ),
            key_id, public_key,
        )
    }
}
