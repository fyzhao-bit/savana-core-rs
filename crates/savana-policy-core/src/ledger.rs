use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use rustix::fs::{open as rustix_open, openat, statat, AtFlags, FileType, Mode, OFlags, Stat};
use rustix::io::Errno;
use savana_kernel_protocol::{Digest32, Signature64, StableCode, UnixMillis};
use sha2::{Digest, Sha256};

use crate::atomic_file::{self, PersistencePhase};
use crate::lock_file::LedgerLock;
use crate::{
    CurrentPolicyCapability, PolicyError, PolicyVerifier, VerifiedPolicyV1, VerifiedReleaseIdentity,
};

#[cfg(test)]
#[path = "ledger/acceptance_tests.rs"]
mod acceptance_tests;

const LEDGER_SCHEMA_VERSION: u16 = 1;
const MAXIMUM_LEDGER_BYTES: u64 = 128;
const LEDGER_DOMAIN: &[u8] = b"SAVANA_POLICY_LEDGER_V1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RollbackLedgerV1 {
    schema_version: u16,
    highest_policy_version: u64,
    highest_key_epoch: u64,
    highest_policy_digest: Digest32,
}

impl RollbackLedgerV1 {
    const GENESIS: Self = Self {
        schema_version: LEDGER_SCHEMA_VERSION,
        highest_policy_version: 0,
        highest_key_epoch: 0,
        highest_policy_digest: Digest32::new([0; 32]),
    };

    fn from_verified(policy: &VerifiedPolicyV1) -> Self {
        let identity = policy.identity();
        Self {
            schema_version: LEDGER_SCHEMA_VERSION,
            highest_policy_version: identity.policy_version,
            highest_key_epoch: identity.key_epoch,
            highest_policy_digest: identity.digest,
        }
    }

    fn canonical_bytes(self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(64);
        self.encode_into(&mut encoded);
        encoded
    }

    fn try_canonical_bytes(self) -> Result<Vec<u8>, PolicyError> {
        let mut encoded = Vec::new();
        encoded
            .try_reserve_exact(64)
            .map_err(|_| PolicyError::stable(StableCode::KernelUnavailable))?;
        self.encode_into(&mut encoded);
        Ok(encoded)
    }

    fn encode_into(self, encoded: &mut Vec<u8>) {
        encoded.push(0x84);
        push_unsigned(encoded, u64::from(self.schema_version));
        push_unsigned(encoded, self.highest_policy_version);
        push_unsigned(encoded, self.highest_key_epoch);
        encoded.extend_from_slice(&[0x58, 0x20]);
        encoded.extend_from_slice(self.highest_policy_digest.as_bytes());
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyLedgerIdentity {
    pub highest_policy_version: u64,
    pub highest_key_epoch: u64,
    pub highest_policy_digest: Digest32,
    pub canonical_ledger_digest: Digest32,
}

impl PolicyLedgerIdentity {
    fn from_preencoded(
        ledger: RollbackLedgerV1,
        canonical: &[u8],
        identity: crate::PolicyIdentity,
    ) -> Result<Self, PolicyError> {
        if ledger.highest_policy_version != identity.policy_version
            || ledger.highest_key_epoch != identity.key_epoch
            || ledger.highest_policy_digest != identity.digest
            || ledger.try_canonical_bytes()? != canonical
        {
            return Err(PolicyError::stable(StableCode::ProtocolIo));
        }
        let mut hasher = Sha256::new();
        hasher.update(LEDGER_DOMAIN);
        hasher.update(canonical);
        Ok(Self {
            highest_policy_version: ledger.highest_policy_version,
            highest_key_epoch: ledger.highest_key_epoch,
            highest_policy_digest: ledger.highest_policy_digest,
            canonical_ledger_digest: Digest32::new(hasher.finalize().into()),
        })
    }
}

#[derive(Debug)]
struct InitialAcceptanceCommitGuard {
    armed: bool,
}

pub(crate) enum LedgerAcceptanceFailure {
    Rejected(PolicyError),
    CommitUncertain(PolicyError),
}

pub(crate) struct DurableAcceptanceGuard {
    armed: bool,
}

impl DurableAcceptanceGuard {
    pub(crate) fn complete(mut self) {
        self.armed = false;
    }
}

impl Drop for DurableAcceptanceGuard {
    fn drop(&mut self) {
        if self.armed {
            std::process::abort();
        }
    }
}

pub(crate) struct LivePolicyAcceptance {
    pub(crate) policy: VerifiedPolicyV1,
    pub(crate) ledger_identity: PolicyLedgerIdentity,
    pub(crate) resource_profile_digest: Digest32,
    pub(crate) durable: DurableAcceptanceGuard,
}

impl InitialAcceptanceCommitGuard {
    fn complete(mut self) {
        self.armed = false;
    }
}

impl Drop for InitialAcceptanceCommitGuard {
    fn drop(&mut self) {
        if self.armed {
            std::process::abort();
        }
    }
}

pub struct PolicyStore {
    verifier: PolicyVerifier,
    ledger_path: PathBuf,
    anchored: Option<AnchoredState>,
    ledger: RollbackLedgerV1,
    poisoned: bool,
    _lock: LedgerLock,
    #[cfg(test)]
    live_persistence_fault: Option<PersistencePhase>,
}

pub struct PolicyStateCapability {
    ledger_path: PathBuf,
    state: AnchoredState,
}

impl std::fmt::Debug for PolicyStateCapability {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PolicyStateCapability(<verified>)")
    }
}

impl PolicyStateCapability {
    pub fn open(ledger_path: &Path, owner_uid: u32, owner_gid: u32) -> Result<Self, PolicyError> {
        if ledger_path.file_name() != Some(OsStr::new("policy-ledger-v1.cbor")) {
            return Err(PolicyError::stable(StableCode::ProtocolIo));
        }
        let state = AnchoredState::open(ledger_path, owner_uid, owner_gid)?;
        state.preflight()?;
        Ok(Self {
            ledger_path: ledger_path.to_owned(),
            state,
        })
    }
}

impl std::fmt::Debug for PolicyStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PolicyStore")
            .finish_non_exhaustive()
    }
}

impl PolicyStore {
    pub fn open(ledger_path: &Path, verifier: PolicyVerifier) -> Result<Self, PolicyError> {
        Self::open_with_parent_sync(ledger_path, verifier, atomic_file::sync_directory)
    }

    fn open_with_parent_sync<F>(
        ledger_path: &Path,
        verifier: PolicyVerifier,
        sync_parent: F,
    ) -> Result<Self, PolicyError>
    where
        F: FnOnce(&Path) -> Result<(), PolicyError>,
    {
        let lock = LedgerLock::acquire(ledger_path)?;
        let ledger = match fs::symlink_metadata(ledger_path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
                    return Err(PolicyError::stable(StableCode::ProtocolIo));
                }
                let ledger = read_existing_ledger(ledger_path, &metadata)?;
                sync_parent(atomic_file::normalized_parent(ledger_path)?)?;
                ledger
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => RollbackLedgerV1::GENESIS,
            Err(error) => return Err(PolicyError::io(error)),
        };
        Ok(Self {
            verifier,
            ledger_path: ledger_path.to_owned(),
            anchored: None,
            ledger,
            poisoned: false,
            _lock: lock,
            #[cfg(test)]
            live_persistence_fault: None,
        })
    }

    pub fn open_anchored(
        ledger_path: &Path,
        owner_uid: u32,
        owner_gid: u32,
        verifier: PolicyVerifier,
    ) -> Result<Self, PolicyError> {
        let capability = PolicyStateCapability::open(ledger_path, owner_uid, owner_gid)?;
        Self::open_capability(capability, verifier)
    }

    pub fn open_capability(
        capability: PolicyStateCapability,
        verifier: PolicyVerifier,
    ) -> Result<Self, PolicyError> {
        let PolicyStateCapability { ledger_path, state } = capability;
        let lock = LedgerLock::acquire_at(
            &state.parent,
            OsStr::new(".policy-ledger-v1.cbor.lock"),
            state.owner_uid,
            state.owner_gid,
        )?;
        state.recheck_parent()?;
        let ledger = match state.read_existing()? {
            Some(ledger) => {
                state.parent.sync_all().map_err(PolicyError::io)?;
                ledger
            }
            None => RollbackLedgerV1::GENESIS,
        };
        state.recheck_parent()?;
        Ok(Self {
            verifier,
            ledger_path,
            anchored: Some(state),
            ledger,
            poisoned: false,
            _lock: lock,
            #[cfg(test)]
            live_persistence_fault: None,
        })
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn verify_and_accept(
        &mut self,
        canonical_bundle: &[u8],
        signature: &Signature64,
        now: UnixMillis,
    ) -> Result<VerifiedPolicyV1, PolicyError> {
        self.ensure_usable()?;
        let verified = self.verifier.verify(canonical_bundle, signature, now)?;
        let next = self.validate_ledger_transition(&verified)?;
        if next == self.ledger {
            return Ok(verified);
        }
        let canonical = next.canonical_bytes();
        let durable = self.persist_prevalidated(next, &canonical)?;
        durable.complete();
        Ok(verified)
    }

    pub fn verify_and_accept_initial(
        mut self,
        release: VerifiedReleaseIdentity,
        policy_bytes: &[u8],
        signature: &Signature64,
        now: UnixMillis,
    ) -> Result<CurrentPolicyCapability, PolicyError> {
        self.ensure_usable()?;
        if !self.verifier.is_bound_to(&release)
            || now.get() < release.issued_at().get()
            || now.get() >= release.expires_at().get()
        {
            return Err(PolicyError::stable(StableCode::IdentityReleaseMismatch));
        }
        let policy = self.verifier.verify(policy_bytes, signature, now)?;
        release.verify_selected_policy_binding(&policy, signature)?;
        release.recheck_retained_stage()?;
        let identity = policy.identity();
        let next = self.validate_ledger_transition(&policy)?;
        let canonical_ledger = next.try_canonical_bytes()?;
        let ledger_identity =
            PolicyLedgerIdentity::from_preencoded(next, &canonical_ledger, identity)?;
        let resource_profile_digest = policy.resource_profile_digest();
        let durable = self.persist_prevalidated(next, &canonical_ledger)?;
        #[cfg(test)]
        acceptance_test_post_persistence_hook();
        let current = CurrentPolicyCapability {
            store: self,
            policy,
            ledger_identity,
            release,
            resource_profile_digest,
        };
        durable.complete();
        Ok(current)
    }

    pub(crate) fn verify_live_candidate(
        &self,
        policy_bytes: &[u8],
        signature: &Signature64,
        now: UnixMillis,
    ) -> Result<VerifiedPolicyV1, PolicyError> {
        self.ensure_usable()?;
        self.verifier.verify(policy_bytes, signature, now)
    }

    pub(crate) fn accept_verified_live(
        &mut self,
        policy: VerifiedPolicyV1,
    ) -> Result<LivePolicyAcceptance, LedgerAcceptanceFailure> {
        self.ensure_usable()
            .map_err(LedgerAcceptanceFailure::Rejected)?;
        let identity = policy.identity();
        let next = self
            .validate_ledger_transition(&policy)
            .map_err(LedgerAcceptanceFailure::Rejected)?;
        let canonical_ledger = next
            .try_canonical_bytes()
            .map_err(LedgerAcceptanceFailure::Rejected)?;
        let ledger_identity =
            PolicyLedgerIdentity::from_preencoded(next, &canonical_ledger, identity)
                .map_err(LedgerAcceptanceFailure::Rejected)?;
        let resource_profile_digest = policy.resource_profile_digest();
        let durable = self.persist_live_prevalidated(next, &canonical_ledger)?;
        Ok(LivePolicyAcceptance {
            policy,
            ledger_identity,
            resource_profile_digest,
            durable,
        })
    }

    #[cfg(test)]
    pub(crate) fn inject_live_persistence_fault(&mut self, phase: PersistencePhase) {
        self.live_persistence_fault = Some(phase);
    }

    #[cfg(test)]
    pub(crate) fn raise_ledger_epoch_for_rollover_test(&mut self) {
        self.ledger.highest_key_epoch = self.ledger.highest_key_epoch.checked_add(1).unwrap();
    }

    fn validate_ledger_transition(
        &self,
        verified: &VerifiedPolicyV1,
    ) -> Result<RollbackLedgerV1, PolicyError> {
        let identity = verified.identity();
        if identity.policy_version < self.ledger.highest_policy_version {
            return Err(PolicyError::stable(StableCode::PolicyRollback));
        }
        if identity.policy_version == self.ledger.highest_policy_version {
            if identity.key_epoch == self.ledger.highest_key_epoch
                && identity.digest == self.ledger.highest_policy_digest
            {
                return Ok(self.ledger);
            }
            return Err(PolicyError::stable(StableCode::PolicyEquivocation));
        }
        if identity.key_epoch < self.ledger.highest_key_epoch {
            return Err(PolicyError::stable(StableCode::PolicyRollback));
        }

        Ok(RollbackLedgerV1::from_verified(verified))
    }

    pub fn ledger_identity(&self) -> Result<PolicyLedgerIdentity, PolicyError> {
        self.ensure_usable()?;
        let canonical = self.ledger.canonical_bytes();
        let mut hasher = Sha256::new();
        hasher.update(LEDGER_DOMAIN);
        hasher.update(&canonical);
        Ok(PolicyLedgerIdentity {
            highest_policy_version: self.ledger.highest_policy_version,
            highest_key_epoch: self.ledger.highest_key_epoch,
            highest_policy_digest: self.ledger.highest_policy_digest,
            canonical_ledger_digest: Digest32::new(hasher.finalize().into()),
        })
    }

    pub fn recheck_storage(&self) -> Result<(), PolicyError> {
        self.ensure_usable()?;
        self._lock.recheck()?;
        if let Some(state) = &self.anchored {
            state.recheck_parent()?;
            state.validate_optional_leaf(OsStr::new(".policy-ledger-v1.cbor.lock"), None)?;
        }
        Ok(())
    }

    fn ensure_usable(&self) -> Result<(), PolicyError> {
        if self.poisoned {
            Err(PolicyError::stable(StableCode::ProtocolIo))
        } else {
            Ok(())
        }
    }

    fn persist_prevalidated(
        &mut self,
        next: RollbackLedgerV1,
        canonical: &[u8],
    ) -> Result<InitialAcceptanceCommitGuard, PolicyError> {
        let result = match &self.anchored {
            Some(state) => state.replace(canonical),
            None => atomic_file::replace(&self.ledger_path, canonical),
        };
        match result {
            Ok(()) => {
                let guard = InitialAcceptanceCommitGuard { armed: true };
                self.ledger = next;
                Ok(guard)
            }
            Err(error) => {
                if error.phase() == PersistencePhase::AfterRename {
                    self.poisoned = true;
                }
                Err(error.into_policy_error())
            }
        }
    }

    fn persist_live_prevalidated(
        &mut self,
        next: RollbackLedgerV1,
        canonical: &[u8],
    ) -> Result<DurableAcceptanceGuard, LedgerAcceptanceFailure> {
        #[cfg(test)]
        let injected = self.live_persistence_fault.take().map(|phase| match phase {
            PersistencePhase::BeforeRename => atomic_file::ReplaceError::before_rename(
                PolicyError::stable(StableCode::ProtocolIo),
            ),
            PersistencePhase::AfterRename => {
                atomic_file::ReplaceError::after_rename(PolicyError::stable(StableCode::ProtocolIo))
            }
        });
        #[cfg(not(test))]
        let injected: Option<atomic_file::ReplaceError> = None;

        let result = if let Some(error) = injected {
            Err(error)
        } else {
            match &self.anchored {
                Some(state) => state.replace(canonical),
                None => atomic_file::replace(&self.ledger_path, canonical),
            }
        };
        match result {
            Ok(()) => {
                let guard = DurableAcceptanceGuard { armed: true };
                self.ledger = next;
                Ok(guard)
            }
            Err(error) => {
                let phase = error.phase();
                let error = error.into_policy_error();
                match phase {
                    PersistencePhase::BeforeRename => Err(LedgerAcceptanceFailure::Rejected(error)),
                    PersistencePhase::AfterRename => {
                        self.poisoned = true;
                        Err(LedgerAcceptanceFailure::CommitUncertain(error))
                    }
                }
            }
        }
    }

    #[cfg(test)]
    fn persist_candidate_with<F>(
        &mut self,
        next: RollbackLedgerV1,
        persist: F,
    ) -> Result<(), PolicyError>
    where
        F: FnOnce(&Path, &[u8]) -> Result<(), atomic_file::ReplaceError>,
    {
        match persist(&self.ledger_path, &next.canonical_bytes()) {
            Ok(()) => {
                self.ledger = next;
                Ok(())
            }
            Err(error) => {
                if error.phase() == PersistencePhase::AfterRename {
                    self.poisoned = true;
                }
                Err(error.into_policy_error())
            }
        }
    }
}

#[cfg(test)]
fn acceptance_test_post_persistence_hook() {
    if std::env::var_os("SAVANA_TEST_INITIAL_ACCEPTANCE_PANIC").is_some() {
        panic!("injected post-persistence panic");
    }
}

struct AnchoredState {
    parent: File,
    parent_path: PathBuf,
    parent_identity: StateIdentity,
    ledger_leaf: OsString,
    owner_uid: u32,
    owner_gid: u32,
}

impl AnchoredState {
    fn open(ledger_path: &Path, owner_uid: u32, owner_gid: u32) -> Result<Self, PolicyError> {
        if !ledger_path.is_absolute() {
            return Err(PolicyError::stable(StableCode::ProtocolIo));
        }
        let parent_path = ledger_path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .ok_or_else(|| PolicyError::stable(StableCode::ProtocolIo))?;
        let ledger_leaf = ledger_path
            .file_name()
            .ok_or_else(|| PolicyError::stable(StableCode::ProtocolIo))?
            .to_os_string();
        let before = fs::symlink_metadata(parent_path).map_err(PolicyError::io)?;
        if before.file_type().is_symlink() {
            return Err(PolicyError::stable(StableCode::ProtocolIo));
        }
        let descriptor = rustix_open(
            parent_path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(PolicyError::io)?;
        let parent = File::from(descriptor);
        let metadata = parent.metadata().map_err(PolicyError::io)?;
        let parent_identity = StateIdentity::from_metadata(&metadata);
        if !metadata.is_dir()
            || !parent_identity.same_directory(StateIdentity::from_metadata(&before))
            || parent_identity.uid != owner_uid
            || parent_identity.gid != owner_gid
            || parent_identity.permissions() != 0o700
        {
            return Err(PolicyError::stable(StableCode::ProtocolIo));
        }
        let state = Self {
            parent,
            parent_path: parent_path.to_owned(),
            parent_identity,
            ledger_leaf,
            owner_uid,
            owner_gid,
        };
        state.recheck_parent()?;
        Ok(state)
    }

    fn recheck_parent(&self) -> Result<(), PolicyError> {
        let descriptor =
            StateIdentity::from_metadata(&self.parent.metadata().map_err(PolicyError::io)?);
        let pathname = fs::symlink_metadata(&self.parent_path).map_err(PolicyError::io)?;
        if pathname.file_type().is_symlink()
            || !descriptor.same_directory(self.parent_identity)
            || !StateIdentity::from_metadata(&pathname).same_directory(self.parent_identity)
        {
            return Err(PolicyError::stable(StableCode::ProtocolIo));
        }
        Ok(())
    }

    fn read_existing(&self) -> Result<Option<RollbackLedgerV1>, PolicyError> {
        let before = match statat(&self.parent, &self.ledger_leaf, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => stat,
            Err(Errno::NOENT) => return Ok(None),
            Err(error) => return Err(PolicyError::io(error)),
        };
        if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile {
            return Err(PolicyError::stable(StableCode::ProtocolIo));
        }
        let before = StateIdentity::from_stat(&before)?;
        let descriptor = openat(
            &self.parent,
            &self.ledger_leaf,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(PolicyError::io)?;
        let file = File::from(descriptor);
        let metadata = file.metadata().map_err(PolicyError::io)?;
        let opened = StateIdentity::from_metadata(&metadata);
        if opened != before
            || !metadata.is_file()
            || opened.uid != self.owner_uid
            || opened.gid != self.owner_gid
            || opened.permissions() != 0o600
            || opened.nlink != 1
            || opened.length > MAXIMUM_LEDGER_BYTES
        {
            return Err(PolicyError::stable(StableCode::ProtocolIo));
        }
        let capacity = usize::try_from(opened.length).map_err(PolicyError::io)?;
        let mut bytes = Vec::with_capacity(capacity);
        file.take(MAXIMUM_LEDGER_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(PolicyError::io)?;
        if u64::try_from(bytes.len()).map_or(true, |length| length > MAXIMUM_LEDGER_BYTES) {
            return Err(malformed());
        }
        let after = statat(&self.parent, &self.ledger_leaf, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(PolicyError::io)?;
        if StateIdentity::from_stat(&after)? != opened {
            return Err(PolicyError::stable(StableCode::ProtocolIo));
        }
        self.recheck_parent()?;
        decode_ledger(&bytes).map(Some)
    }

    fn preflight(&self) -> Result<(), PolicyError> {
        self.validate_optional_leaf(&self.ledger_leaf, Some(MAXIMUM_LEDGER_BYTES))?;
        self.validate_optional_leaf(OsStr::new(".policy-ledger-v1.cbor.lock"), None)?;
        self.recheck_parent()
    }

    fn validate_optional_leaf(
        &self,
        leaf: &OsStr,
        maximum_length: Option<u64>,
    ) -> Result<(), PolicyError> {
        let stat = match statat(&self.parent, leaf, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => stat,
            Err(Errno::NOENT) => return Ok(()),
            Err(error) => return Err(PolicyError::io(error)),
        };
        let identity = StateIdentity::from_stat(&stat)?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
            || identity.uid != self.owner_uid
            || identity.gid != self.owner_gid
            || identity.permissions() != 0o600
            || identity.nlink != 1
            || maximum_length.is_some_and(|maximum| identity.length > maximum)
        {
            return Err(PolicyError::stable(StableCode::ProtocolIo));
        }
        Ok(())
    }

    fn replace(&self, bytes: &[u8]) -> Result<(), atomic_file::ReplaceError> {
        atomic_file::replace_at(
            &self.parent,
            &self.ledger_leaf,
            bytes,
            self.owner_uid,
            self.owner_gid,
            || self.recheck_parent(),
        )?;
        self.recheck_parent()
            .map_err(atomic_file::ReplaceError::after_rename)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct StateIdentity {
    dev: i128,
    ino: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    nlink: u64,
    length: u64,
}

impl StateIdentity {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            dev: i128::from(metadata.dev()),
            ino: metadata.ino(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            mode: metadata.mode(),
            nlink: metadata.nlink(),
            length: metadata.len(),
        }
    }

    fn from_stat(stat: &Stat) -> Result<Self, PolicyError> {
        Ok(Self {
            dev: i128::from(stat.st_dev),
            ino: checked_u64(stat.st_ino)?,
            uid: checked_u32(stat.st_uid)?,
            gid: checked_u32(stat.st_gid)?,
            mode: checked_u32(stat.st_mode)?,
            nlink: checked_u64(stat.st_nlink)?,
            length: checked_u64(stat.st_size)?,
        })
    }

    const fn permissions(self) -> u32 {
        self.mode & 0o7777
    }

    const fn same_directory(self, other: Self) -> bool {
        self.dev == other.dev
            && self.ino == other.ino
            && self.uid == other.uid
            && self.gid == other.gid
            && self.mode == other.mode
    }
}

fn checked_u64<T: TryInto<u64>>(value: T) -> Result<u64, PolicyError> {
    value.try_into().map_err(PolicyError::io)
}

fn checked_u32<T: TryInto<u32>>(value: T) -> Result<u32, PolicyError> {
    value.try_into().map_err(PolicyError::io)
}

fn read_existing_ledger(
    path: &Path,
    path_metadata: &fs::Metadata,
) -> Result<RollbackLedgerV1, PolicyError> {
    if path_metadata.len() > MAXIMUM_LEDGER_BYTES {
        return Err(PolicyError::stable(StableCode::ProtocolMalformedCbor));
    }
    let file = File::open(path).map_err(PolicyError::io)?;
    let opened_metadata = file.metadata().map_err(PolicyError::io)?;
    if !opened_metadata.file_type().is_file()
        || opened_metadata.dev() != path_metadata.dev()
        || opened_metadata.ino() != path_metadata.ino()
    {
        return Err(PolicyError::stable(StableCode::ProtocolIo));
    }
    let final_metadata = fs::symlink_metadata(path).map_err(PolicyError::io)?;
    if final_metadata.file_type().is_symlink()
        || !final_metadata.file_type().is_file()
        || final_metadata.dev() != opened_metadata.dev()
        || final_metadata.ino() != opened_metadata.ino()
    {
        return Err(PolicyError::stable(StableCode::ProtocolIo));
    }
    let capacity = bounded_ledger_capacity(path_metadata.len(), opened_metadata.len())?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(MAXIMUM_LEDGER_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(PolicyError::io)?;
    if bytes.len() as u64 > MAXIMUM_LEDGER_BYTES {
        return Err(PolicyError::stable(StableCode::ProtocolMalformedCbor));
    }
    decode_ledger(&bytes)
}

fn bounded_ledger_capacity(path_length: u64, opened_length: u64) -> Result<usize, PolicyError> {
    if path_length > MAXIMUM_LEDGER_BYTES || opened_length > MAXIMUM_LEDGER_BYTES {
        return Err(PolicyError::stable(StableCode::ProtocolMalformedCbor));
    }
    usize::try_from(opened_length)
        .map_err(|_| PolicyError::stable(StableCode::ProtocolMalformedCbor))
}

fn decode_ledger(bytes: &[u8]) -> Result<RollbackLedgerV1, PolicyError> {
    let mut decoder = minicbor::Decoder::new(bytes);
    match decoder.array().map_err(|_| malformed())? {
        Some(4) => {}
        _ => return Err(malformed()),
    }
    let schema_version = decoder.u16().map_err(|_| malformed())?;
    let highest_policy_version = decoder.u64().map_err(|_| malformed())?;
    let highest_key_epoch = decoder.u64().map_err(|_| malformed())?;
    let highest_policy_digest =
        Digest32::try_from(decoder.bytes().map_err(|_| malformed())?).map_err(PolicyError::from)?;
    if decoder.position() != bytes.len() {
        return Err(malformed());
    }
    let ledger = RollbackLedgerV1 {
        schema_version,
        highest_policy_version,
        highest_key_epoch,
        highest_policy_digest,
    };
    if ledger.canonical_bytes() != bytes {
        return Err(malformed());
    }
    if schema_version != LEDGER_SCHEMA_VERSION {
        return Err(PolicyError::stable(StableCode::ProtocolUnsupportedVersion));
    }
    let zero_digest = ledger.highest_policy_digest == Digest32::new([0; 32]);
    let genesis_consistent =
        ledger.highest_policy_version == 0 && ledger.highest_key_epoch == 0 && zero_digest;
    let accepted_consistent =
        ledger.highest_policy_version != 0 && ledger.highest_key_epoch != 0 && !zero_digest;
    if !genesis_consistent && !accepted_consistent {
        return Err(malformed());
    }
    Ok(ledger)
}

fn push_unsigned(output: &mut Vec<u8>, value: u64) {
    match value {
        0..=23 => output.push(value as u8),
        24..=0xff => {
            output.push(0x18);
            output.push(value as u8);
        }
        0x100..=0xffff => {
            output.push(0x19);
            output.extend_from_slice(&(value as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            output.push(0x1a);
            output.extend_from_slice(&(value as u32).to_be_bytes());
        }
        _ => {
            output.push(0x1b);
            output.extend_from_slice(&value.to_be_bytes());
        }
    }
}

fn malformed() -> PolicyError {
    PolicyError::stable(StableCode::ProtocolMalformedCbor)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    use ed25519_dalek::SigningKey;
    use savana_kernel_protocol::KeyId;

    use super::*;
    use crate::PolicyTrustRootV1;

    #[test]
    fn anchored_store_holds_the_exact_state_directory_and_sibling_lock() {
        let root = tempfile::tempdir().unwrap();
        let state = root.path().join("state");
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        let metadata = fs::metadata(&state).unwrap();
        let ledger = state.join("policy-ledger-v1.cbor");
        let verifier = verifier();

        let first =
            PolicyStore::open_anchored(&ledger, metadata.uid(), metadata.gid(), verifier.clone())
                .unwrap();
        let lock = state.join(".policy-ledger-v1.cbor.lock");
        let lock_metadata = fs::symlink_metadata(&lock).unwrap();
        assert!(lock_metadata.is_file());
        assert_eq!(lock_metadata.uid(), metadata.uid());
        assert_eq!(lock_metadata.gid(), metadata.gid());
        assert_eq!(lock_metadata.mode() & 0o7777, 0o600);
        assert_eq!(lock_metadata.nlink(), 1);
        assert_eq!(
            PolicyStore::open_anchored(&ledger, metadata.uid(), metadata.gid(), verifier)
                .unwrap_err()
                .code(),
            StableCode::ProtocolIo
        );
        drop(first);
    }

    #[test]
    fn state_capability_preflight_is_read_only_until_store_lock_acquisition() {
        let root = tempfile::tempdir().unwrap();
        let state = root.path().join("state");
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        let metadata = fs::metadata(&state).unwrap();
        let ledger = state.join("policy-ledger-v1.cbor");
        let lock = state.join(".policy-ledger-v1.cbor.lock");

        let capability =
            PolicyStateCapability::open(&ledger, metadata.uid(), metadata.gid()).unwrap();
        assert!(!lock.exists());
        let store = PolicyStore::open_capability(capability, verifier()).unwrap();
        assert!(lock.exists());
        drop(store);
    }

    #[test]
    fn anchored_store_rechecks_the_held_lock_pathname() {
        let root = tempfile::tempdir().unwrap();
        let state = root.path().join("state");
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        let metadata = fs::metadata(&state).unwrap();
        let ledger = state.join("policy-ledger-v1.cbor");
        let store = PolicyStore::open_anchored(&ledger, metadata.uid(), metadata.gid(), verifier())
            .unwrap();
        let lock = state.join(".policy-ledger-v1.cbor.lock");
        let displaced = state.join(".policy-ledger-v1.cbor.lock.displaced");
        fs::rename(&lock, &displaced).unwrap();
        fs::write(&lock, []).unwrap();
        fs::set_permissions(&lock, fs::Permissions::from_mode(0o600)).unwrap();

        assert_eq!(
            store.recheck_storage().unwrap_err().code(),
            StableCode::ProtocolIo
        );
    }

    #[test]
    fn anchored_persistence_refuses_a_replaced_state_path_before_rename() {
        let root = tempfile::tempdir().unwrap();
        let state = root.path().join("state");
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        let metadata = fs::metadata(&state).unwrap();
        let ledger = state.join("policy-ledger-v1.cbor");
        let mut store =
            PolicyStore::open_anchored(&ledger, metadata.uid(), metadata.gid(), verifier())
                .unwrap();

        let held_state = root.path().join("held-state");
        fs::rename(&state, &held_state).unwrap();
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        let next = RollbackLedgerV1 {
            schema_version: 1,
            highest_policy_version: 7,
            highest_key_epoch: 3,
            highest_policy_digest: Digest32::new([1; 32]),
        };

        let canonical = next.canonical_bytes();
        assert_eq!(
            store
                .persist_prevalidated(next, &canonical)
                .unwrap_err()
                .code(),
            StableCode::ProtocolIo
        );
        assert!(!held_state.join("policy-ledger-v1.cbor").exists());
        assert!(!state.join("policy-ledger-v1.cbor").exists());
    }

    #[test]
    fn opened_ledger_growth_is_rejected_before_capacity_is_chosen() {
        assert_eq!(bounded_ledger_capacity(64, 128).unwrap(), 128);
        assert_eq!(
            bounded_ledger_capacity(64, 129).unwrap_err().code(),
            StableCode::ProtocolMalformedCbor
        );
    }

    #[test]
    fn post_rename_failure_poison_requires_reopen_reconciliation() {
        let dir = tempfile::tempdir().unwrap();
        let ledger_path = dir.path().join("policy.ledger");
        let signing_key = SigningKey::from_bytes(&[0x42; 32]);
        let verifier = || {
            PolicyVerifier::new(
                vec![PolicyTrustRootV1 {
                    key_id: KeyId::try_from("policy-root").unwrap(),
                    public_key: signing_key.verifying_key().to_bytes(),
                    epoch: 3,
                    revoked: false,
                }],
                Digest32::new([0xa0; 32]),
            )
            .unwrap()
        };
        let mut store = PolicyStore::open(&ledger_path, verifier()).unwrap();
        let next = RollbackLedgerV1 {
            schema_version: 1,
            highest_policy_version: 7,
            highest_key_epoch: 3,
            highest_policy_digest: Digest32::new([1; 32]),
        };

        let error = store
            .persist_candidate_with(next, |path, bytes| {
                atomic_file::replace_with_parent_sync(path, bytes, |_parent| {
                    Err(PolicyError::stable(StableCode::ProtocolIo))
                })
            })
            .unwrap_err();

        assert_eq!(error.code(), StableCode::ProtocolIo);
        assert_eq!(store.ledger, RollbackLedgerV1::GENESIS);
        assert!(store.poisoned);
        assert_eq!(
            store.ledger_identity().unwrap_err().code(),
            StableCode::ProtocolIo
        );
        assert_eq!(
            store
                .verify_and_accept(&[], &Signature64::new([0; 64]), UnixMillis::new(0))
                .unwrap_err()
                .code(),
            StableCode::ProtocolIo
        );
        drop(store);

        assert_eq!(
            PolicyStore::open_with_parent_sync(&ledger_path, verifier(), |_parent| {
                Err(PolicyError::stable(StableCode::ProtocolIo))
            })
            .unwrap_err()
            .code(),
            StableCode::ProtocolIo
        );

        let reopened = PolicyStore::open(&ledger_path, verifier()).unwrap();
        assert_eq!(
            reopened.ledger_identity().unwrap().highest_policy_version,
            7
        );
    }

    fn verifier() -> PolicyVerifier {
        let signing_key = SigningKey::from_bytes(&[0x42; 32]);
        PolicyVerifier::new(
            vec![PolicyTrustRootV1 {
                key_id: KeyId::try_from("policy-root").unwrap(),
                public_key: signing_key.verifying_key().to_bytes(),
                epoch: 3,
                revoked: false,
            }],
            Digest32::new([0xa0; 32]),
        )
        .unwrap()
    }
}
