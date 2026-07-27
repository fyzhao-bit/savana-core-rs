use std::ffi::OsString;
use std::path::Path;
use std::sync::Arc;
#[cfg(test)]
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Mutex,
};

use nix::fcntl::{Flock, FlockArg};
use savana_kernel_protocol::{Signature64, StableCode};

use crate::fs_cap::{DirectoryCapability, FileCapability, FileExpectation, LengthRule};
use crate::DaemonError;

const SELECTED_POLICY_UPDATE_LOCK_LEAF: &str = ".selected-policy-v1.update.lock";
const MAXIMUM_KERNEL_LOCK_BYTES: u64 = 256 * 1024;
const MAXIMUM_SELECTED_POLICY_BYTES: u64 = 8 * 1024 * 1024;

#[cfg(test)]
type UpdateLockRaceHook = (UpdateLockRacePoint, Box<dyn FnOnce() + Send>);

pub(crate) struct SelectedPolicySource {
    lock_parent: DirectoryCapability,
    policy_parent: DirectoryCapability,
    lock_leaf: OsString,
    policy_leaf: OsString,
    signature_leaf: OsString,
    update_lock_leaf: OsString,
    artifact_owner_uid: u32,
    artifact_owner_gid: u32,
    update_lock_owner_uid: u32,
    update_lock_owner_gid: u32,
    #[cfg(test)]
    race_hook: Mutex<Option<UpdateLockRaceHook>>,
    #[cfg(test)]
    live_artifact_sets: Arc<AtomicUsize>,
    #[cfg(test)]
    update_lock_owner_override: Mutex<Option<(u32, u32)>>,
}

impl std::fmt::Debug for SelectedPolicySource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SelectedPolicySource(<verified>)")
    }
}

impl SelectedPolicySource {
    pub(crate) fn open(
        kernel_lock: &Path,
        selected_policy: &Path,
        selected_signature: &Path,
        artifact_owner_uid: u32,
        artifact_owner_gid: u32,
        update_lock_owner_uid: u32,
        update_lock_owner_gid: u32,
    ) -> Result<Arc<Self>, DaemonError> {
        let lock_parent_path = kernel_lock.parent().ok_or_else(release_mismatch)?;
        let policy_parent_path = selected_policy.parent().ok_or_else(release_mismatch)?;
        if selected_signature.parent() != Some(policy_parent_path) {
            return Err(release_mismatch());
        }
        let lock_leaf = kernel_lock.file_name().ok_or_else(release_mismatch)?;
        let policy_leaf = selected_policy.file_name().ok_or_else(release_mismatch)?;
        let signature_leaf = selected_signature
            .file_name()
            .ok_or_else(release_mismatch)?;
        let lock_parent = DirectoryCapability::open_final(
            lock_parent_path,
            artifact_owner_uid,
            artifact_owner_gid,
            0o755,
            StableCode::IdentityReleaseMismatch,
        )?;
        let policy_parent = DirectoryCapability::open_final(
            policy_parent_path,
            artifact_owner_uid,
            artifact_owner_gid,
            0o755,
            StableCode::IdentityReleaseMismatch,
        )?;
        lock_parent.recheck()?;
        policy_parent.recheck()?;
        Ok(Arc::new(Self {
            lock_parent,
            policy_parent,
            lock_leaf: lock_leaf.to_os_string(),
            policy_leaf: policy_leaf.to_os_string(),
            signature_leaf: signature_leaf.to_os_string(),
            update_lock_leaf: OsString::from(SELECTED_POLICY_UPDATE_LOCK_LEAF),
            artifact_owner_uid,
            artifact_owner_gid,
            update_lock_owner_uid,
            update_lock_owner_gid,
            #[cfg(test)]
            race_hook: Mutex::new(None),
            #[cfg(test)]
            live_artifact_sets: Arc::new(AtomicUsize::new(0)),
            #[cfg(test)]
            update_lock_owner_override: Mutex::new(None),
        }))
    }

    pub(crate) fn acquire(self: &Arc<Self>) -> Result<SelectedPolicyUpdateGuard, DaemonError> {
        #[cfg(test)]
        let (update_lock_owner_uid, update_lock_owner_gid) = self
            .update_lock_owner_override
            .lock()
            .expect("test update-lock owner override mutex is not poisoned")
            .as_ref()
            .copied()
            .unwrap_or((self.update_lock_owner_uid, self.update_lock_owner_gid));
        #[cfg(not(test))]
        let (update_lock_owner_uid, update_lock_owner_gid) =
            (self.update_lock_owner_uid, self.update_lock_owner_gid);
        let update_lock = self
            .policy_parent
            .open_file(
                &self.update_lock_leaf,
                FileExpectation {
                    owner_uid: update_lock_owner_uid,
                    owner_gid: update_lock_owner_gid,
                    permissions: 0o640,
                    length: LengthRule::Exact(0),
                },
            )
            .map_err(|_| unavailable())?;
        update_lock.recheck().map_err(|_| unavailable())?;
        #[cfg(test)]
        self.run_update_lock_race_hook(UpdateLockRacePoint::BeforeSharedFlock);
        update_lock.recheck().map_err(|_| unavailable())?;
        let lock_file = update_lock.try_clone_file().map_err(|_| unavailable())?;
        let shared_flock = Flock::lock(lock_file, FlockArg::LockSharedNonblock)
            .map_err(|(_file, _errno)| unavailable())?;
        update_lock.recheck().map_err(|_| unavailable())?;
        #[cfg(test)]
        self.run_update_lock_race_hook(UpdateLockRacePoint::AfterSharedFlock);
        update_lock.recheck().map_err(|_| unavailable())?;
        let artifacts = self.open_artifacts_after_lock()?;
        Ok(SelectedPolicyUpdateGuard {
            source: Arc::clone(self),
            update_lock,
            shared_flock: Some(shared_flock),
            artifacts,
        })
    }

    fn open_artifacts_after_lock(&self) -> Result<SelectedPolicyArtifacts, DaemonError> {
        let kernel_lock = self.lock_parent.open_file(
            &self.lock_leaf,
            FileExpectation {
                owner_uid: self.artifact_owner_uid,
                owner_gid: self.artifact_owner_gid,
                permissions: 0o444,
                length: LengthRule::Maximum(MAXIMUM_KERNEL_LOCK_BYTES),
            },
        )?;
        let selected_policy = self.policy_parent.open_file(
            &self.policy_leaf,
            FileExpectation {
                owner_uid: self.artifact_owner_uid,
                owner_gid: self.artifact_owner_gid,
                permissions: 0o444,
                length: LengthRule::Maximum(MAXIMUM_SELECTED_POLICY_BYTES),
            },
        )?;
        let selected_signature = self.policy_parent.open_file(
            &self.signature_leaf,
            FileExpectation {
                owner_uid: self.artifact_owner_uid,
                owner_gid: self.artifact_owner_gid,
                permissions: 0o444,
                length: LengthRule::Exact(64),
            },
        )?;
        self.lock_parent.recheck()?;
        self.policy_parent.recheck()?;
        #[cfg(test)]
        self.live_artifact_sets.fetch_add(1, Ordering::AcqRel);
        Ok(SelectedPolicyArtifacts {
            kernel_lock,
            selected_policy,
            selected_signature,
            #[cfg(test)]
            live_artifact_sets: Arc::clone(&self.live_artifact_sets),
        })
    }

    fn recheck_parents(&self) -> Result<(), DaemonError> {
        self.lock_parent.recheck()?;
        self.policy_parent.recheck()
    }

    #[cfg(test)]
    pub(crate) fn install_update_lock_race_hook(
        &self,
        point: UpdateLockRacePoint,
        hook: Box<dyn FnOnce() + Send>,
    ) {
        *self
            .race_hook
            .lock()
            .expect("test race hook mutex is not poisoned") = Some((point, hook));
    }

    #[cfg(test)]
    pub(crate) fn live_artifact_sets(&self) -> usize {
        self.live_artifact_sets.load(Ordering::Acquire)
    }

    #[cfg(test)]
    pub(crate) fn install_update_lock_owner_override(&self, uid: u32, gid: u32) {
        *self
            .update_lock_owner_override
            .lock()
            .expect("test update-lock owner override mutex is not poisoned") = Some((uid, gid));
    }

    #[cfg(test)]
    fn artifact_drop_probe(&self) -> Arc<AtomicUsize> {
        Arc::clone(&self.live_artifact_sets)
    }

    #[cfg(test)]
    fn run_update_lock_race_hook(&self, point: UpdateLockRacePoint) {
        let hook = {
            let mut hook = self
                .race_hook
                .lock()
                .expect("test race hook mutex is not poisoned");
            match hook.as_ref().map(|(configured, _)| *configured == point) {
                Some(true) => hook.take().map(|(_, hook)| hook),
                Some(false) | None => None,
            }
        };
        if let Some(hook) = hook {
            hook();
        }
    }
}

pub(crate) struct SelectedPolicyUpdateGuard {
    source: Arc<SelectedPolicySource>,
    update_lock: FileCapability,
    shared_flock: Option<Flock<std::fs::File>>,
    artifacts: SelectedPolicyArtifacts,
}

impl std::fmt::Debug for SelectedPolicyUpdateGuard {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SelectedPolicyUpdateGuard(<held>)")
    }
}

impl SelectedPolicyUpdateGuard {
    #[cfg(test)]
    pub(crate) fn live_artifact_sets(&self) -> usize {
        self.source.live_artifact_sets()
    }

    #[cfg(test)]
    pub(crate) fn artifact_drop_probe(&self) -> Arc<AtomicUsize> {
        self.source.artifact_drop_probe()
    }

    pub(crate) fn read_candidate(&self) -> Result<SelectedPolicyCandidate, DaemonError> {
        let kernel_lock_bytes = self
            .artifacts
            .kernel_lock
            .read_bounded(MAXIMUM_KERNEL_LOCK_BYTES)?;
        let policy_bytes = self
            .artifacts
            .selected_policy
            .read_bounded(MAXIMUM_SELECTED_POLICY_BYTES)?;
        let mut signature = [0_u8; 64];
        self.artifacts
            .selected_signature
            .read_exact_into(&mut signature)?;
        self.source.recheck_parents()?;
        Ok(SelectedPolicyCandidate {
            kernel_lock_bytes,
            policy_bytes,
            signature: Signature64::new(signature),
        })
    }

    pub(crate) fn final_recheck(&self) -> Result<(), DaemonError> {
        self.source.recheck_parents()?;
        self.artifacts.kernel_lock.recheck()?;
        self.artifacts.selected_policy.recheck()?;
        self.artifacts.selected_signature.recheck()?;
        self.update_lock.recheck().map_err(|_| unavailable())?;
        if self.shared_flock.is_none() {
            return Err(unavailable());
        }
        Ok(())
    }
}

pub(crate) struct SelectedPolicyArtifacts {
    kernel_lock: FileCapability,
    selected_policy: FileCapability,
    selected_signature: FileCapability,
    #[cfg(test)]
    live_artifact_sets: Arc<AtomicUsize>,
}

#[cfg(test)]
impl Drop for SelectedPolicyArtifacts {
    fn drop(&mut self) {
        self.live_artifact_sets.fetch_sub(1, Ordering::AcqRel);
    }
}

pub(crate) struct SelectedPolicyCandidate {
    pub(crate) kernel_lock_bytes: Vec<u8>,
    pub(crate) policy_bytes: Vec<u8>,
    pub(crate) signature: Signature64,
}

const fn unavailable() -> DaemonError {
    DaemonError::stable(StableCode::KernelUnavailable)
}

const fn release_mismatch() -> DaemonError {
    DaemonError::stable(StableCode::IdentityReleaseMismatch)
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UpdateLockRacePoint {
    BeforeSharedFlock,
    AfterSharedFlock,
}
