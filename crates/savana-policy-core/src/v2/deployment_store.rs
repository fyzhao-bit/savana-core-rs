use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::Read as _;
use std::os::unix::fs::MetadataExt as _;
#[cfg(any(
    target_os = "linux",
    target_os = "macos",
    test,
    feature = "test-support"
))]
use std::path::Path;
use std::path::PathBuf;

#[cfg(any(
    target_os = "linux",
    target_os = "macos",
    test,
    feature = "test-support"
))]
use rustix::fs::open;
use rustix::fs::{openat, statat, AtFlags, FileType, Mode, OFlags};
use rustix::io::Errno;
use savana_kernel_protocol::v2::Digest32V2;
pub use savana_platform_identity::NativeRollbackAuthorityV2;
#[cfg(any(test, feature = "test-support"))]
pub use savana_platform_identity::TestNativeRollbackAuthorityV2;

use crate::atomic_file::{self, AtomicReplaceBoundary};
use crate::lock_file::LedgerLock;

use super::deployment_transition_store::{
    DeploymentDurabilityObserverV2, DeploymentDurabilityPointV2,
};
use super::{
    select_authenticated_ledger_slot_v2, DeploymentActivationVerifierV2, DeploymentBranchV2,
    DeploymentControlErrorV2, DeploymentLedgerProjectionV2, DeploymentLedgerRecordV2,
    LedgerSlotIdV2, NativeDeploymentSigningAuthorityV2, SignedLedgerSlotV2, VerifiedLedgerSlotV2,
};

#[cfg(target_os = "linux")]
const LINUX_LEDGER_DIRECTORY_V2: &str = "/var/lib/savana/deployment";
#[cfg(target_os = "macos")]
const MACOS_LEDGER_DIRECTORY_V2: &str = "/Library/Application Support/Savana/Deployment";
const LEDGER_SLOT_A_LEAF_V2: &str = "ledger-a.cbor";
const LEDGER_SLOT_B_LEAF_V2: &str = "ledger-b.cbor";
const DEPLOYMENT_MUTEX_LEAF_V2: &str = ".deployment-v2.lock";
const MAX_LEDGER_SLOT_BYTES_V2: u64 = 4 * 1024 * 1024 + 1024;

pub struct DeploymentLedgerStoreV2 {
    parent: File,
    parent_path: PathBuf,
    parent_dev: u64,
    parent_ino: u64,
    owner_uid: u32,
    owner_gid: u32,
    deployment_mutex_anchor: File,
    verifier: DeploymentActivationVerifierV2,
    expected_rollback_authority_identity: Digest32V2,
}

#[derive(Debug, Clone)]
pub struct AuthenticatedDeploymentLedgerSnapshotV2 {
    selected_record: DeploymentLedgerRecordV2,
    predecessor_record: Option<DeploymentLedgerRecordV2>,
}

impl AuthenticatedDeploymentLedgerSnapshotV2 {
    pub const fn selected_record(&self) -> &DeploymentLedgerRecordV2 {
        &self.selected_record
    }

    pub const fn predecessor_record(&self) -> Option<&DeploymentLedgerRecordV2> {
        self.predecessor_record.as_ref()
    }
}

impl std::fmt::Debug for DeploymentLedgerStoreV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DeploymentLedgerStoreV2")
            .field("parent_path", &self.parent_path)
            .field("activation_key_id", &self.verifier.key_id())
            .field("installation_epoch", &self.verifier.key_epoch())
            .finish_non_exhaustive()
    }
}

impl DeploymentLedgerStoreV2 {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub fn open_fixed_platform(
        verifier: DeploymentActivationVerifierV2,
        expected_rollback_authority_identity: Digest32V2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        #[cfg(target_os = "linux")]
        let directory = Path::new(LINUX_LEDGER_DIRECTORY_V2);
        #[cfg(target_os = "macos")]
        let directory = Path::new(MACOS_LEDGER_DIRECTORY_V2);
        Self::open_anchored(
            directory,
            0,
            0,
            verifier,
            expected_rollback_authority_identity,
        )
    }

    #[cfg(target_os = "linux")]
    pub fn open_fixed_linux(
        verifier: DeploymentActivationVerifierV2,
        expected_rollback_authority_identity: Digest32V2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        Self::open_anchored(
            Path::new(LINUX_LEDGER_DIRECTORY_V2),
            0,
            0,
            verifier,
            expected_rollback_authority_identity,
        )
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn open_for_test(
        directory: &Path,
        verifier: DeploymentActivationVerifierV2,
        expected_rollback_authority_identity: Digest32V2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        let metadata = fs::symlink_metadata(directory)
            .map_err(|_| DeploymentControlErrorV2::DeploymentLedgerIo)?;
        Self::open_anchored(
            directory,
            metadata.uid(),
            metadata.gid(),
            verifier,
            expected_rollback_authority_identity,
        )
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "macos",
        test,
        feature = "test-support"
    ))]
    fn open_anchored(
        directory: &Path,
        expected_uid: u32,
        expected_gid: u32,
        verifier: DeploymentActivationVerifierV2,
        expected_rollback_authority_identity: Digest32V2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        if !directory.is_absolute()
            || expected_rollback_authority_identity
                .as_bytes()
                .iter()
                .all(|byte| *byte == 0)
        {
            return Err(DeploymentControlErrorV2::DeploymentLedgerIo);
        }
        let before = fs::symlink_metadata(directory)
            .map_err(|_| DeploymentControlErrorV2::DeploymentLedgerIo)?;
        if before.file_type().is_symlink()
            || !before.is_dir()
            || before.uid() != expected_uid
            || before.gid() != expected_gid
            || before.mode() & 0o7777 != 0o700
        {
            return Err(DeploymentControlErrorV2::DeploymentLedgerIo);
        }
        let descriptor = open(
            directory,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| DeploymentControlErrorV2::DeploymentLedgerIo)?;
        let parent = File::from(descriptor);
        let opened = parent
            .metadata()
            .map_err(|_| DeploymentControlErrorV2::DeploymentLedgerIo)?;
        if !opened.is_dir()
            || opened.dev() != before.dev()
            || opened.ino() != before.ino()
            || opened.uid() != expected_uid
            || opened.gid() != expected_gid
            || opened.mode() & 0o7777 != 0o700
        {
            return Err(DeploymentControlErrorV2::DeploymentLedgerIo);
        }
        let initial_mutex = LedgerLock::acquire_at(
            &parent,
            OsStr::new(DEPLOYMENT_MUTEX_LEAF_V2),
            expected_uid,
            expected_gid,
        )
        .map_err(|_| DeploymentControlErrorV2::DeploymentMutexUnavailable)?;
        let deployment_mutex_anchor = File::from(
            openat(
                &parent,
                OsStr::new(DEPLOYMENT_MUTEX_LEAF_V2),
                OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| DeploymentControlErrorV2::DeploymentMutexUnavailable)?,
        );
        validate_deployment_mutex_anchor(
            &parent,
            &deployment_mutex_anchor,
            expected_uid,
            expected_gid,
        )?;
        if !initial_mutex
            .matches_file(&deployment_mutex_anchor)
            .map_err(|_| DeploymentControlErrorV2::DeploymentMutexUnavailable)?
        {
            return Err(DeploymentControlErrorV2::DeploymentMutexUnavailable);
        }
        initial_mutex
            .recheck()
            .map_err(|_| DeploymentControlErrorV2::DeploymentMutexUnavailable)?;
        drop(initial_mutex);
        let store = Self {
            parent,
            parent_path: directory.to_owned(),
            parent_dev: opened.dev(),
            parent_ino: opened.ino(),
            owner_uid: expected_uid,
            owner_gid: expected_gid,
            deployment_mutex_anchor,
            verifier,
            expected_rollback_authority_identity,
        };
        store.recheck_parent()?;
        Ok(store)
    }

    pub fn load_selected(
        &self,
        authority: &mut dyn NativeRollbackAuthorityV2,
    ) -> Result<DeploymentLedgerProjectionV2, DeploymentControlErrorV2> {
        Ok(self
            .load_selected_authenticated(authority)?
            .selected_record
            .projection()
            .clone())
    }

    pub(super) fn acquire_deployment_mutex(&self) -> Result<LedgerLock, DeploymentControlErrorV2> {
        self.recheck_parent()
            .map_err(|_| DeploymentControlErrorV2::DeploymentMutexUnavailable)?;
        let lock = LedgerLock::acquire_at(
            &self.parent,
            OsStr::new(DEPLOYMENT_MUTEX_LEAF_V2),
            self.owner_uid,
            self.owner_gid,
        )
        .map_err(|_| DeploymentControlErrorV2::DeploymentMutexUnavailable)?;
        validate_deployment_mutex_anchor(
            &self.parent,
            &self.deployment_mutex_anchor,
            self.owner_uid,
            self.owner_gid,
        )?;
        if !lock
            .matches_file(&self.deployment_mutex_anchor)
            .map_err(|_| DeploymentControlErrorV2::DeploymentMutexUnavailable)?
        {
            return Err(DeploymentControlErrorV2::DeploymentMutexUnavailable);
        }
        self.recheck_parent()
            .map_err(|_| DeploymentControlErrorV2::DeploymentMutexUnavailable)?;
        lock.recheck()
            .map_err(|_| DeploymentControlErrorV2::DeploymentMutexUnavailable)?;
        Ok(lock)
    }

    pub(super) const fn activation_verifier(&self) -> &DeploymentActivationVerifierV2 {
        &self.verifier
    }

    pub fn load_selected_authenticated(
        &self,
        authority: &mut dyn NativeRollbackAuthorityV2,
    ) -> Result<AuthenticatedDeploymentLedgerSnapshotV2, DeploymentControlErrorV2> {
        self.require_authority_identity(authority)?;
        let slots = self.read_slots()?;
        let selected_slot = slots.select_slot()?;
        let selected = selected_slot.record().clone();
        let selected_record = selected_slot.authenticated_record()?.clone();
        let predecessor_record = slots
            .predecessor_for(&selected)
            .map(VerifiedLedgerSlotV2::authenticated_record)
            .transpose()?
            .cloned();
        let observed = authority
            .read_generation(
                *selected.installation_id().as_bytes(),
                selected.installation_epoch(),
            )
            .map_err(|_| DeploymentControlErrorV2::NativeRollbackAuthorityUnavailable)?;
        if observed == selected.generation() {
            return Ok(AuthenticatedDeploymentLedgerSnapshotV2 {
                selected_record,
                predecessor_record,
            });
        }
        let adjacent = observed
            .checked_add(1)
            .is_some_and(|generation| generation == selected.generation())
            && slots.contains_generation_linked_to(observed, &selected);
        if !adjacent {
            return Err(DeploymentControlErrorV2::NativeRollbackGenerationMismatch);
        }
        authority
            .compare_and_advance(
                *selected.installation_id().as_bytes(),
                selected.installation_epoch(),
                observed,
                selected.generation(),
            )
            .map_err(|_| DeploymentControlErrorV2::NativeRollbackAuthorityUnavailable)?;
        Ok(AuthenticatedDeploymentLedgerSnapshotV2 {
            selected_record,
            predecessor_record,
        })
    }

    fn write_successor_observed(
        &self,
        candidate_slot_bytes: &[u8],
        branch: DeploymentBranchV2,
        authority: &mut dyn NativeRollbackAuthorityV2,
        observer: &mut dyn DeploymentDurabilityObserverV2,
    ) -> Result<DeploymentLedgerProjectionV2, DeploymentControlErrorV2> {
        self.require_authority_identity(authority)?;
        let slots = self.read_slots()?;
        let current_slot = slots.select_slot()?;
        let current = current_slot.record();
        let target_slot = slots.overwrite_target()?;
        let candidate =
            SignedLedgerSlotV2::verify_canonical_bytes(candidate_slot_bytes, &self.verifier)?;
        if candidate.slot_id() != target_slot {
            return Err(DeploymentControlErrorV2::LedgerConflict);
        }
        current_slot
            .authenticated_record()?
            .validate_successor(candidate.authenticated_record()?, branch)?;
        let observed = authority
            .read_generation(
                *current.installation_id().as_bytes(),
                current.installation_epoch(),
            )
            .map_err(|_| DeploymentControlErrorV2::NativeRollbackAuthorityUnavailable)?;
        if observed != current.generation() {
            return Err(DeploymentControlErrorV2::NativeRollbackGenerationMismatch);
        }

        self.recheck_parent()?;
        observer.reached(DeploymentDurabilityPointV2::BeforeLedgerWrite)?;
        atomic_file::replace_at_observed(
            &self.parent,
            slot_leaf(target_slot),
            candidate_slot_bytes,
            self.owner_uid,
            self.owner_gid,
            || {
                self.recheck_parent()
                    .map_err(|_| crate::PolicyError::io("deployment ledger parent changed"))
            },
            |boundary| {
                let point = match boundary {
                    AtomicReplaceBoundary::FileFlushed => {
                        DeploymentDurabilityPointV2::LedgerFileFlushed
                    }
                    AtomicReplaceBoundary::RenamedBeforeDirectoryFlush => {
                        DeploymentDurabilityPointV2::LedgerRenamedBeforeDirectoryFlush
                    }
                    AtomicReplaceBoundary::DirectoryFlushed => {
                        DeploymentDurabilityPointV2::LedgerDirectoryFlushed
                    }
                };
                observer
                    .reached(point)
                    .map_err(|_| crate::PolicyError::io("injected deployment durability fault"))
            },
        )
        .map_err(|_| DeploymentControlErrorV2::DeploymentLedgerIo)?;
        self.recheck_parent()?;

        let reopened_bytes = self
            .read_slot_bytes(slot_leaf(target_slot))?
            .ok_or(DeploymentControlErrorV2::DeploymentLedgerIo)?;
        if reopened_bytes != candidate_slot_bytes {
            return Err(DeploymentControlErrorV2::DeploymentLedgerIo);
        }
        let reopened = SignedLedgerSlotV2::verify_canonical_bytes(&reopened_bytes, &self.verifier)?;
        if reopened.record() != candidate.record() {
            return Err(DeploymentControlErrorV2::DeploymentLedgerIo);
        }
        observer.reached(DeploymentDurabilityPointV2::LedgerReopened)?;
        authority
            .compare_and_advance(
                *current.installation_id().as_bytes(),
                current.installation_epoch(),
                current.generation(),
                reopened.record().generation(),
            )
            .map_err(|_| DeploymentControlErrorV2::NativeRollbackAuthorityUnavailable)?;
        observer.reached(DeploymentDurabilityPointV2::CounterAdvanced)?;
        Ok(reopened.record().clone())
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn write_successor_record(
        &self,
        candidate_record: &DeploymentLedgerRecordV2,
        branch: DeploymentBranchV2,
        signing_authority: &mut dyn NativeDeploymentSigningAuthorityV2,
        rollback_authority: &mut dyn NativeRollbackAuthorityV2,
    ) -> Result<DeploymentLedgerProjectionV2, DeploymentControlErrorV2> {
        let lock = self.acquire_deployment_mutex()?;
        let result = self.write_successor_record_observed(
            candidate_record,
            branch,
            signing_authority,
            rollback_authority,
            &mut super::deployment_transition_store::NoDeploymentCrashV2,
        );
        lock.recheck()
            .map_err(|_| DeploymentControlErrorV2::DeploymentMutexUnavailable)?;
        result
    }

    pub(super) fn write_successor_record_observed(
        &self,
        candidate_record: &DeploymentLedgerRecordV2,
        branch: DeploymentBranchV2,
        signing_authority: &mut dyn NativeDeploymentSigningAuthorityV2,
        rollback_authority: &mut dyn NativeRollbackAuthorityV2,
        observer: &mut dyn DeploymentDurabilityObserverV2,
    ) -> Result<DeploymentLedgerProjectionV2, DeploymentControlErrorV2> {
        let slots = self.read_slots()?;
        let target_slot = slots.overwrite_target()?;
        slots
            .select_slot()?
            .authenticated_record()?
            .validate_successor(candidate_record, branch)?;
        let signed_slot = SignedLedgerSlotV2::new_signed_with_authority(
            target_slot,
            candidate_record,
            signing_authority,
            &self.verifier,
        )?;
        self.write_successor_observed(
            signed_slot.canonical_bytes(),
            branch,
            rollback_authority,
            observer,
        )
    }

    fn require_authority_identity(
        &self,
        authority: &dyn NativeRollbackAuthorityV2,
    ) -> Result<(), DeploymentControlErrorV2> {
        if authority.authority_identity() != *self.expected_rollback_authority_identity.as_bytes() {
            return Err(DeploymentControlErrorV2::NativeRollbackAuthorityUnavailable);
        }
        Ok(())
    }

    fn read_slots(&self) -> Result<SlotSnapshotV2, DeploymentControlErrorV2> {
        self.recheck_parent()?;
        let a = self.read_verified_slot(LedgerSlotIdV2::A)?;
        let b = self.read_verified_slot(LedgerSlotIdV2::B)?;
        self.recheck_parent()?;
        Ok(SlotSnapshotV2 { a, b })
    }

    fn read_verified_slot(
        &self,
        slot_id: LedgerSlotIdV2,
    ) -> Result<Option<VerifiedLedgerSlotV2>, DeploymentControlErrorV2> {
        let Some(bytes) = self.read_slot_bytes(slot_leaf(slot_id))? else {
            return Ok(None);
        };
        match SignedLedgerSlotV2::verify_canonical_bytes(&bytes, &self.verifier) {
            Ok(slot) => Ok(Some(slot)),
            Err(_) => Ok(None),
        }
    }

    fn read_slot_bytes(&self, leaf: &OsStr) -> Result<Option<Vec<u8>>, DeploymentControlErrorV2> {
        let before = match statat(&self.parent, leaf, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => stat,
            Err(Errno::NOENT) => return Ok(None),
            Err(_) => return Err(DeploymentControlErrorV2::DeploymentLedgerIo),
        };
        if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
            || before.st_uid != self.owner_uid
            || before.st_gid != self.owner_gid
            || before.st_mode & 0o7777 != 0o600
            || before.st_nlink != 1
            || before.st_size < 0
            || u64::try_from(before.st_size)
                .ok()
                .is_none_or(|size| size == 0 || size > MAX_LEDGER_SLOT_BYTES_V2)
        {
            return Err(DeploymentControlErrorV2::DeploymentLedgerIo);
        }
        let descriptor = openat(
            &self.parent,
            leaf,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| DeploymentControlErrorV2::DeploymentLedgerIo)?;
        let mut file = File::from(descriptor);
        let opened = file
            .metadata()
            .map_err(|_| DeploymentControlErrorV2::DeploymentLedgerIo)?;
        let expected_length = usize::try_from(opened.len())
            .map_err(|_| DeploymentControlErrorV2::DeploymentLedgerIo)?;
        if !opened.is_file()
            || opened.dev() as i128 != before.st_dev as i128
            || opened.ino() != before.st_ino
            || opened.uid() != self.owner_uid
            || opened.gid() != self.owner_gid
            || opened.mode() & 0o7777 != 0o600
            || opened.nlink() != 1
            || opened.len() == 0
            || opened.len() > MAX_LEDGER_SLOT_BYTES_V2
        {
            return Err(DeploymentControlErrorV2::DeploymentLedgerIo);
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(expected_length)
            .map_err(|_| DeploymentControlErrorV2::DeploymentLedgerIo)?;
        file.read_to_end(&mut bytes)
            .map_err(|_| DeploymentControlErrorV2::DeploymentLedgerIo)?;
        let after = statat(&self.parent, leaf, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| DeploymentControlErrorV2::DeploymentLedgerIo)?;
        if bytes.len() != expected_length
            || after.st_dev as i128 != before.st_dev as i128
            || after.st_ino != before.st_ino
            || after.st_size != before.st_size
        {
            return Err(DeploymentControlErrorV2::DeploymentLedgerIo);
        }
        Ok(Some(bytes))
    }

    fn recheck_parent(&self) -> Result<(), DeploymentControlErrorV2> {
        let opened = self
            .parent
            .metadata()
            .map_err(|_| DeploymentControlErrorV2::DeploymentLedgerIo)?;
        let linked = fs::symlink_metadata(&self.parent_path)
            .map_err(|_| DeploymentControlErrorV2::DeploymentLedgerIo)?;
        if linked.file_type().is_symlink()
            || !linked.is_dir()
            || opened.dev() != self.parent_dev
            || opened.ino() != self.parent_ino
            || linked.dev() != self.parent_dev
            || linked.ino() != self.parent_ino
            || linked.uid() != self.owner_uid
            || linked.gid() != self.owner_gid
            || linked.mode() & 0o7777 != 0o700
        {
            return Err(DeploymentControlErrorV2::DeploymentLedgerIo);
        }
        Ok(())
    }
}

fn validate_deployment_mutex_anchor(
    parent: &File,
    anchor: &File,
    owner_uid: u32,
    owner_gid: u32,
) -> Result<(), DeploymentControlErrorV2> {
    let opened = anchor
        .metadata()
        .map_err(|_| DeploymentControlErrorV2::DeploymentMutexUnavailable)?;
    let linked = statat(
        parent,
        OsStr::new(DEPLOYMENT_MUTEX_LEAF_V2),
        AtFlags::SYMLINK_NOFOLLOW,
    )
    .map_err(|_| DeploymentControlErrorV2::DeploymentMutexUnavailable)?;
    if !opened.is_file()
        || opened.uid() != owner_uid
        || opened.gid() != owner_gid
        || opened.mode() & 0o7777 != 0o600
        || opened.nlink() != 1
        || FileType::from_raw_mode(linked.st_mode) != FileType::RegularFile
        || linked.st_dev as i128 != opened.dev() as i128
        || linked.st_ino != opened.ino()
        || linked.st_uid != owner_uid
        || linked.st_gid != owner_gid
        || linked.st_mode & 0o7777 != 0o600
        || linked.st_nlink != 1
    {
        return Err(DeploymentControlErrorV2::DeploymentMutexUnavailable);
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct SlotSnapshotV2 {
    a: Option<VerifiedLedgerSlotV2>,
    b: Option<VerifiedLedgerSlotV2>,
}

impl SlotSnapshotV2 {
    fn select(&self) -> Result<DeploymentLedgerProjectionV2, DeploymentControlErrorV2> {
        select_authenticated_ledger_slot_v2(self.a.clone(), self.b.clone())
    }

    fn select_slot(&self) -> Result<&VerifiedLedgerSlotV2, DeploymentControlErrorV2> {
        let selected = self.select()?;
        self.a
            .iter()
            .chain(self.b.iter())
            .find(|slot| {
                slot.record().generation() == selected.generation()
                    && slot.record().record_payload_digest() == selected.record_payload_digest()
            })
            .ok_or(DeploymentControlErrorV2::LedgerConflict)
    }

    fn overwrite_target(&self) -> Result<LedgerSlotIdV2, DeploymentControlErrorV2> {
        match (&self.a, &self.b) {
            (None, None) => Err(DeploymentControlErrorV2::LedgerConflict),
            (None, Some(_)) => Ok(LedgerSlotIdV2::A),
            (Some(_), None) => Ok(LedgerSlotIdV2::B),
            (Some(a), Some(b)) if a.record().generation() == b.record().generation() => {
                self.select()?;
                Ok(LedgerSlotIdV2::A)
            }
            (Some(a), Some(b)) if a.record().generation() < b.record().generation() => {
                self.select()?;
                Ok(LedgerSlotIdV2::A)
            }
            (Some(_), Some(_)) => {
                self.select()?;
                Ok(LedgerSlotIdV2::B)
            }
        }
    }

    fn contains_generation_linked_to(
        &self,
        generation: u64,
        selected: &DeploymentLedgerProjectionV2,
    ) -> bool {
        self.a.iter().chain(self.b.iter()).any(|slot| {
            slot.record().generation() == generation
                && selected.previous_record_digest() == slot.record().record_payload_digest()
        })
    }

    fn predecessor_for(
        &self,
        selected: &DeploymentLedgerProjectionV2,
    ) -> Option<&VerifiedLedgerSlotV2> {
        self.a.iter().chain(self.b.iter()).find(|slot| {
            slot.record().generation().checked_add(1) == Some(selected.generation())
                && selected.previous_record_digest() == slot.record().record_payload_digest()
        })
    }
}

fn slot_leaf(slot_id: LedgerSlotIdV2) -> &'static OsStr {
    match slot_id {
        LedgerSlotIdV2::A => OsStr::new(LEDGER_SLOT_A_LEAF_V2),
        LedgerSlotIdV2::B => OsStr::new(LEDGER_SLOT_B_LEAF_V2),
    }
}
