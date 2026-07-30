use std::collections::BTreeMap;
use std::ffi::{CStr, OsStr, OsString};
use std::fs::{self, File};
use std::io::{Read as _, Write as _};
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
use rustix::fs::{
    fchmod, openat, renameat_with, statat, unlinkat, AtFlags, Dir, FileType, Mode, OFlags,
    RenameFlags,
};
use rustix::io::Errno;
use savana_kernel_protocol::v2::Digest32V2;

use crate::lock_file::LedgerLock;

use super::{
    DeploymentActivationVerifierV2, DeploymentControlErrorV2, DeploymentHardLimitsV2,
    InstallationEvidenceEnvelopeV2,
};

#[cfg(target_os = "linux")]
const LINUX_INSTALLATION_EVIDENCE_DIRECTORY_V2: &str = "/var/lib/savana/deployment/evidence";
#[cfg(target_os = "macos")]
const MACOS_INSTALLATION_EVIDENCE_DIRECTORY_V2: &str =
    "/Library/Application Support/Savana/Deployment/evidence";
const INSTALLATION_EVIDENCE_MUTEX_LEAF_V2: &str = ".installation-evidence-v2.lock";
const MAX_INSTALLATION_EVIDENCE_RECORDS_V2: usize = 4096;
const MAX_INSTALLATION_EVIDENCE_ENVELOPE_BYTES_V2: u64 = 16 * 1024 * 1024 + 1024;
const TEMPORARY_NAME_ATTEMPTS_V2: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InstallationEvidenceDurabilityPointV2 {
    BeforeWrite,
    FileFlushed,
    RenamedBeforeDirectoryFlush,
    DirectoryFlushed,
    Reopened,
}

trait InstallationEvidenceDurabilityObserverV2 {
    fn reached(
        &mut self,
        point: InstallationEvidenceDurabilityPointV2,
    ) -> Result<(), DeploymentControlErrorV2>;
}

struct NoInstallationEvidenceCrashV2;

impl InstallationEvidenceDurabilityObserverV2 for NoInstallationEvidenceCrashV2 {
    fn reached(
        &mut self,
        _point: InstallationEvidenceDurabilityPointV2,
    ) -> Result<(), DeploymentControlErrorV2> {
        Ok(())
    }
}

#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TestInstallationEvidenceCrashPointV2 {
    BeforeWrite,
    FileFlushed,
    RenamedBeforeDirectoryFlush,
    DirectoryFlushed,
    Reopened,
}

#[cfg(any(test, feature = "test-support"))]
impl TestInstallationEvidenceCrashPointV2 {
    pub const ALL: [Self; 5] = [
        Self::BeforeWrite,
        Self::FileFlushed,
        Self::RenamedBeforeDirectoryFlush,
        Self::DirectoryFlushed,
        Self::Reopened,
    ];

    const fn internal(self) -> InstallationEvidenceDurabilityPointV2 {
        match self {
            Self::BeforeWrite => InstallationEvidenceDurabilityPointV2::BeforeWrite,
            Self::FileFlushed => InstallationEvidenceDurabilityPointV2::FileFlushed,
            Self::RenamedBeforeDirectoryFlush => {
                InstallationEvidenceDurabilityPointV2::RenamedBeforeDirectoryFlush
            }
            Self::DirectoryFlushed => InstallationEvidenceDurabilityPointV2::DirectoryFlushed,
            Self::Reopened => InstallationEvidenceDurabilityPointV2::Reopened,
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
struct OneInstallationEvidenceCrashV2 {
    crash_at: InstallationEvidenceDurabilityPointV2,
}

#[cfg(any(test, feature = "test-support"))]
impl InstallationEvidenceDurabilityObserverV2 for OneInstallationEvidenceCrashV2 {
    fn reached(
        &mut self,
        point: InstallationEvidenceDurabilityPointV2,
    ) -> Result<(), DeploymentControlErrorV2> {
        if point == self.crash_at {
            return Err(DeploymentControlErrorV2::InstallationEvidenceIo);
        }
        Ok(())
    }
}

pub struct DurableInstallationEvidenceStoreV2 {
    parent: File,
    parent_path: PathBuf,
    parent_dev: u64,
    parent_ino: u64,
    owner_uid: u32,
    owner_gid: u32,
    verifier: DeploymentActivationVerifierV2,
}

impl std::fmt::Debug for DurableInstallationEvidenceStoreV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DurableInstallationEvidenceStoreV2")
            .field("parent_path", &self.parent_path)
            .field("activation_key_id", &self.verifier.key_id())
            .field("installation_epoch", &self.verifier.key_epoch())
            .finish_non_exhaustive()
    }
}

impl DurableInstallationEvidenceStoreV2 {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub fn open_fixed_platform(
        verifier: DeploymentActivationVerifierV2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        #[cfg(target_os = "linux")]
        let directory = Path::new(LINUX_INSTALLATION_EVIDENCE_DIRECTORY_V2);
        #[cfg(target_os = "macos")]
        let directory = Path::new(MACOS_INSTALLATION_EVIDENCE_DIRECTORY_V2);
        Self::open_anchored(directory, 0, 0, verifier)
    }

    #[cfg(target_os = "linux")]
    pub fn open_fixed_linux(
        verifier: DeploymentActivationVerifierV2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        Self::open_anchored(
            Path::new(LINUX_INSTALLATION_EVIDENCE_DIRECTORY_V2),
            0,
            0,
            verifier,
        )
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn open_for_test(
        directory: &Path,
        verifier: DeploymentActivationVerifierV2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        let metadata = fs::symlink_metadata(directory)
            .map_err(|_| DeploymentControlErrorV2::InstallationEvidenceIo)?;
        Self::open_anchored(directory, metadata.uid(), metadata.gid(), verifier)
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
    ) -> Result<Self, DeploymentControlErrorV2> {
        if !directory.is_absolute() {
            return Err(DeploymentControlErrorV2::InstallationEvidenceIo);
        }
        let before = fs::symlink_metadata(directory)
            .map_err(|_| DeploymentControlErrorV2::InstallationEvidenceIo)?;
        if before.file_type().is_symlink()
            || !before.is_dir()
            || before.uid() != expected_uid
            || before.gid() != expected_gid
            || before.mode() & 0o7777 != 0o700
        {
            return Err(DeploymentControlErrorV2::InstallationEvidenceIo);
        }
        let parent = File::from(
            open(
                directory,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| DeploymentControlErrorV2::InstallationEvidenceIo)?,
        );
        let opened = parent
            .metadata()
            .map_err(|_| DeploymentControlErrorV2::InstallationEvidenceIo)?;
        if !opened.is_dir()
            || opened.dev() != before.dev()
            || opened.ino() != before.ino()
            || opened.uid() != expected_uid
            || opened.gid() != expected_gid
            || opened.mode() & 0o7777 != 0o700
        {
            return Err(DeploymentControlErrorV2::InstallationEvidenceIo);
        }
        let store = Self {
            parent,
            parent_path: directory.to_owned(),
            parent_dev: opened.dev(),
            parent_ino: opened.ino(),
            owner_uid: expected_uid,
            owner_gid: expected_gid,
            verifier,
        };
        store.recheck_parent()?;
        Ok(store)
    }

    pub fn append(
        &self,
        envelope: &InstallationEvidenceEnvelopeV2,
    ) -> Result<Digest32V2, DeploymentControlErrorV2> {
        self.append_observed(envelope, &mut NoInstallationEvidenceCrashV2)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn append_with_crash_for_test(
        &self,
        envelope: &InstallationEvidenceEnvelopeV2,
        crash_at: TestInstallationEvidenceCrashPointV2,
    ) -> Result<Digest32V2, DeploymentControlErrorV2> {
        self.append_observed(
            envelope,
            &mut OneInstallationEvidenceCrashV2 {
                crash_at: crash_at.internal(),
            },
        )
    }

    fn append_observed(
        &self,
        envelope: &InstallationEvidenceEnvelopeV2,
        observer: &mut dyn InstallationEvidenceDurabilityObserverV2,
    ) -> Result<Digest32V2, DeploymentControlErrorV2> {
        let mutex = self.acquire_mutex()?;
        self.recheck_parent()?;
        let authenticated = InstallationEvidenceEnvelopeV2::from_canonical_bytes(
            envelope.canonical_bytes(),
            &self.verifier,
        )?;
        let chain = self.load_chain_locked(true)?;
        let signed_digest = authenticated.signed_digest();
        if let Some(existing) = chain.get(&authenticated.evidence_sequence()) {
            if existing.signed_digest() != signed_digest
                || existing.canonical_bytes() != authenticated.canonical_bytes()
            {
                return Err(DeploymentControlErrorV2::InvalidInstallationEvidenceEnvelope);
            }
            mutex
                .recheck()
                .map_err(|_| DeploymentControlErrorV2::InstallationEvidenceIo)?;
            return Ok(signed_digest);
        }

        let expected_sequence = u64::try_from(chain.len())
            .ok()
            .and_then(|value| value.checked_add(1))
            .ok_or(DeploymentControlErrorV2::InstallationEvidenceIo)?;
        if authenticated.evidence_sequence() != expected_sequence {
            return Err(DeploymentControlErrorV2::InvalidInstallationEvidenceEnvelope);
        }
        let expected_previous = chain
            .values()
            .next_back()
            .map(|value| value.signed_digest());
        if authenticated.previous_evidence_signed_digest() != expected_previous {
            return Err(DeploymentControlErrorV2::InvalidInstallationEvidenceEnvelope);
        }

        observer.reached(InstallationEvidenceDurabilityPointV2::BeforeWrite)?;
        let leaf = evidence_leaf(signed_digest);
        let (temporary_leaf, mut temporary) = self.create_temporary(&leaf)?;
        let write_result = (|| {
            temporary
                .write_all(authenticated.canonical_bytes())
                .map_err(|_| DeploymentControlErrorV2::InstallationEvidenceIo)?;
            temporary
                .sync_all()
                .map_err(|_| DeploymentControlErrorV2::InstallationEvidenceIo)?;
            observer.reached(InstallationEvidenceDurabilityPointV2::FileFlushed)?;
            self.validate_linked_file(
                &temporary_leaf,
                &temporary,
                u64::try_from(authenticated.canonical_bytes().len())
                    .map_err(|_| DeploymentControlErrorV2::InstallationEvidenceIo)?,
            )?;
            self.recheck_parent()
        })();
        if let Err(error) = write_result {
            let _ = unlinkat(&self.parent, &temporary_leaf, AtFlags::empty());
            return Err(error);
        }
        match renameat_with(
            &self.parent,
            &temporary_leaf,
            &self.parent,
            &leaf,
            RenameFlags::NOREPLACE,
        ) {
            Ok(()) => {}
            Err(Errno::EXIST) => {
                let _ = unlinkat(&self.parent, &temporary_leaf, AtFlags::empty());
                let existing = self.load_signed_digest_locked(signed_digest)?;
                if existing.canonical_bytes() != authenticated.canonical_bytes() {
                    return Err(DeploymentControlErrorV2::InvalidInstallationEvidenceEnvelope);
                }
            }
            Err(_) => {
                let _ = unlinkat(&self.parent, &temporary_leaf, AtFlags::empty());
                return Err(DeploymentControlErrorV2::InstallationEvidenceIo);
            }
        }
        observer.reached(InstallationEvidenceDurabilityPointV2::RenamedBeforeDirectoryFlush)?;
        self.parent
            .sync_all()
            .map_err(|_| DeploymentControlErrorV2::InstallationEvidenceIo)?;
        observer.reached(InstallationEvidenceDurabilityPointV2::DirectoryFlushed)?;
        self.recheck_parent()?;
        let reopened = self.load_signed_digest_locked(signed_digest)?;
        if reopened.canonical_bytes() != authenticated.canonical_bytes() {
            return Err(DeploymentControlErrorV2::InstallationEvidenceIo);
        }
        observer.reached(InstallationEvidenceDurabilityPointV2::Reopened)?;
        let committed_chain = self.load_chain_locked(true)?;
        if committed_chain
            .get(&authenticated.evidence_sequence())
            .map(InstallationEvidenceEnvelopeV2::signed_digest)
            != Some(signed_digest)
        {
            return Err(DeploymentControlErrorV2::InstallationEvidenceIo);
        }
        mutex
            .recheck()
            .map_err(|_| DeploymentControlErrorV2::InstallationEvidenceIo)?;
        Ok(signed_digest)
    }

    pub fn load_signed_digest(
        &self,
        signed_digest: Digest32V2,
    ) -> Result<InstallationEvidenceEnvelopeV2, DeploymentControlErrorV2> {
        if is_zero(signed_digest.as_bytes()) {
            return Err(DeploymentControlErrorV2::InvalidInstallationEvidenceEnvelope);
        }
        let mutex = self.acquire_mutex()?;
        self.recheck_parent()?;
        let chain = self.load_chain_locked(true)?;
        let envelope = chain
            .into_values()
            .find(|value| value.signed_digest() == signed_digest)
            .ok_or(DeploymentControlErrorV2::InstallationEvidenceIo)?;
        mutex
            .recheck()
            .map_err(|_| DeploymentControlErrorV2::InstallationEvidenceIo)?;
        Ok(envelope)
    }

    pub fn load_latest(
        &self,
    ) -> Result<Option<InstallationEvidenceEnvelopeV2>, DeploymentControlErrorV2> {
        let mutex = self.acquire_mutex()?;
        self.recheck_parent()?;
        let latest = self.load_chain_locked(true)?.into_values().next_back();
        mutex
            .recheck()
            .map_err(|_| DeploymentControlErrorV2::InstallationEvidenceIo)?;
        Ok(latest)
    }

    fn acquire_mutex(&self) -> Result<LedgerLock, DeploymentControlErrorV2> {
        self.recheck_parent()?;
        LedgerLock::acquire_at(
            &self.parent,
            OsStr::new(INSTALLATION_EVIDENCE_MUTEX_LEAF_V2),
            self.owner_uid,
            self.owner_gid,
        )
        .map_err(|_| DeploymentControlErrorV2::InstallationEvidenceIo)
    }

    fn load_chain_locked(
        &self,
        cleanup_temporary: bool,
    ) -> Result<BTreeMap<u64, InstallationEvidenceEnvelopeV2>, DeploymentControlErrorV2> {
        let directory = Dir::read_from(&self.parent)
            .map_err(|_| DeploymentControlErrorV2::InstallationEvidenceIo)?;
        let mut chain = BTreeMap::new();
        let mut entry_count = 0_usize;
        let mut removed_temporary = false;
        for entry in directory {
            let entry = entry.map_err(|_| DeploymentControlErrorV2::InstallationEvidenceIo)?;
            let name = entry.file_name();
            let bytes = name.to_bytes();
            if matches!(bytes, b"." | b"..")
                || bytes == INSTALLATION_EVIDENCE_MUTEX_LEAF_V2.as_bytes()
            {
                continue;
            }
            if is_temporary_leaf(bytes) {
                if !cleanup_temporary {
                    return Err(DeploymentControlErrorV2::InstallationEvidenceIo);
                }
                self.validate_temporary_for_cleanup(name)?;
                unlinkat(&self.parent, name, AtFlags::empty())
                    .map_err(|_| DeploymentControlErrorV2::InstallationEvidenceIo)?;
                removed_temporary = true;
                continue;
            }
            entry_count = entry_count
                .checked_add(1)
                .ok_or(DeploymentControlErrorV2::InstallationEvidenceIo)?;
            if entry_count > MAX_INSTALLATION_EVIDENCE_RECORDS_V2 {
                return Err(DeploymentControlErrorV2::InstallationEvidenceIo);
            }
            let digest = parse_evidence_leaf(bytes)
                .ok_or(DeploymentControlErrorV2::InstallationEvidenceIo)?;
            let envelope = self.load_signed_digest_locked(digest)?;
            if envelope.signed_digest() != digest
                || chain
                    .insert(envelope.evidence_sequence(), envelope)
                    .is_some()
            {
                return Err(DeploymentControlErrorV2::InvalidInstallationEvidenceEnvelope);
            }
        }
        if removed_temporary {
            self.parent
                .sync_all()
                .map_err(|_| DeploymentControlErrorV2::InstallationEvidenceIo)?;
        }
        let mut previous = None;
        for (index, envelope) in chain.values().enumerate() {
            let sequence = u64::try_from(index)
                .ok()
                .and_then(|value| value.checked_add(1))
                .ok_or(DeploymentControlErrorV2::InstallationEvidenceIo)?;
            if envelope.evidence_sequence() != sequence
                || envelope.previous_evidence_signed_digest() != previous
            {
                return Err(DeploymentControlErrorV2::InvalidInstallationEvidenceEnvelope);
            }
            previous = Some(envelope.signed_digest());
        }
        self.recheck_parent()?;
        Ok(chain)
    }

    fn load_signed_digest_locked(
        &self,
        signed_digest: Digest32V2,
    ) -> Result<InstallationEvidenceEnvelopeV2, DeploymentControlErrorV2> {
        let leaf = evidence_leaf(signed_digest);
        let bytes = self.read_envelope_bytes(&leaf)?;
        let envelope =
            InstallationEvidenceEnvelopeV2::from_canonical_bytes(&bytes, &self.verifier)?;
        if envelope.signed_digest() != signed_digest {
            return Err(DeploymentControlErrorV2::InvalidInstallationEvidenceEnvelope);
        }
        Ok(envelope)
    }

    fn create_temporary(
        &self,
        final_leaf: &OsStr,
    ) -> Result<(OsString, File), DeploymentControlErrorV2> {
        for _ in 0..TEMPORARY_NAME_ATTEMPTS_V2 {
            let mut random = [0_u8; 16];
            getrandom::getrandom(&mut random)
                .map_err(|_| DeploymentControlErrorV2::InstallationEvidenceIo)?;
            let mut temporary_leaf = OsString::from(".");
            temporary_leaf.push(final_leaf);
            temporary_leaf.push(".tmp-");
            temporary_leaf.push(hex(&random));
            match openat(
                &self.parent,
                &temporary_leaf,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_bits_truncate(0o600),
            ) {
                Ok(descriptor) => {
                    let file = File::from(descriptor);
                    fchmod(&file, Mode::from_bits_truncate(0o600))
                        .map_err(|_| DeploymentControlErrorV2::InstallationEvidenceIo)?;
                    self.validate_linked_file(&temporary_leaf, &file, 0)?;
                    return Ok((temporary_leaf, file));
                }
                Err(Errno::EXIST) => {}
                Err(_) => return Err(DeploymentControlErrorV2::InstallationEvidenceIo),
            }
        }
        Err(DeploymentControlErrorV2::InstallationEvidenceIo)
    }

    fn read_envelope_bytes(&self, leaf: &OsStr) -> Result<Vec<u8>, DeploymentControlErrorV2> {
        let before = statat(&self.parent, leaf, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| DeploymentControlErrorV2::InstallationEvidenceIo)?;
        if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
            || before.st_uid != self.owner_uid
            || before.st_gid != self.owner_gid
            || before.st_mode & 0o7777 != 0o600
            || before.st_nlink != 1
            || before.st_size <= 0
            || u64::try_from(before.st_size)
                .ok()
                .is_none_or(|size| size > MAX_INSTALLATION_EVIDENCE_ENVELOPE_BYTES_V2)
        {
            return Err(DeploymentControlErrorV2::InstallationEvidenceIo);
        }
        let file = File::from(
            openat(
                &self.parent,
                leaf,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| DeploymentControlErrorV2::InstallationEvidenceIo)?,
        );
        let opened = file
            .metadata()
            .map_err(|_| DeploymentControlErrorV2::InstallationEvidenceIo)?;
        self.validate_linked_file(leaf, &file, opened.len())?;
        if opened.dev() as i128 != before.st_dev as i128
            || opened.ino() != before.st_ino
            || i128::from(opened.len()) != i128::from(before.st_size)
        {
            return Err(DeploymentControlErrorV2::InstallationEvidenceIo);
        }
        let maximum = usize::try_from(
            DeploymentHardLimitsV2::compiled()
                .max_attestation_bytes()
                .saturating_add(1024),
        )
        .map_err(|_| DeploymentControlErrorV2::InstallationEvidenceIo)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(
                usize::try_from(opened.len())
                    .map_err(|_| DeploymentControlErrorV2::InstallationEvidenceIo)?,
            )
            .map_err(|_| DeploymentControlErrorV2::InstallationEvidenceIo)?;
        file.take(
            u64::try_from(maximum)
                .map_err(|_| DeploymentControlErrorV2::InstallationEvidenceIo)?
                .saturating_add(1),
        )
        .read_to_end(&mut bytes)
        .map_err(|_| DeploymentControlErrorV2::InstallationEvidenceIo)?;
        let after = statat(&self.parent, leaf, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| DeploymentControlErrorV2::InstallationEvidenceIo)?;
        if bytes.len() > maximum
            || u64::try_from(bytes.len())
                .map_err(|_| DeploymentControlErrorV2::InstallationEvidenceIo)?
                != opened.len()
            || after.st_dev as i128 != before.st_dev as i128
            || after.st_ino != before.st_ino
            || after.st_size != before.st_size
        {
            return Err(DeploymentControlErrorV2::InstallationEvidenceIo);
        }
        Ok(bytes)
    }

    fn validate_linked_file(
        &self,
        leaf: &OsStr,
        file: &File,
        expected_length: u64,
    ) -> Result<(), DeploymentControlErrorV2> {
        let opened = file
            .metadata()
            .map_err(|_| DeploymentControlErrorV2::InstallationEvidenceIo)?;
        let linked = statat(&self.parent, leaf, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| DeploymentControlErrorV2::InstallationEvidenceIo)?;
        if !opened.is_file()
            || opened.uid() != self.owner_uid
            || opened.gid() != self.owner_gid
            || opened.mode() & 0o7777 != 0o600
            || opened.nlink() != 1
            || opened.len() != expected_length
            || FileType::from_raw_mode(linked.st_mode) != FileType::RegularFile
            || linked.st_dev as i128 != opened.dev() as i128
            || linked.st_ino != opened.ino()
            || linked.st_uid != self.owner_uid
            || linked.st_gid != self.owner_gid
            || linked.st_mode & 0o7777 != 0o600
            || linked.st_nlink != 1
            || linked.st_size < 0
            || u64::try_from(linked.st_size).ok() != Some(expected_length)
        {
            return Err(DeploymentControlErrorV2::InstallationEvidenceIo);
        }
        Ok(())
    }

    fn validate_temporary_for_cleanup(&self, leaf: &CStr) -> Result<(), DeploymentControlErrorV2> {
        let linked = statat(&self.parent, leaf, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| DeploymentControlErrorV2::InstallationEvidenceIo)?;
        if FileType::from_raw_mode(linked.st_mode) != FileType::RegularFile
            || linked.st_uid != self.owner_uid
            || linked.st_gid != self.owner_gid
            || linked.st_mode & 0o7777 != 0o600
            || linked.st_nlink != 1
            || linked.st_size < 0
            || u64::try_from(linked.st_size)
                .ok()
                .is_none_or(|size| size > MAX_INSTALLATION_EVIDENCE_ENVELOPE_BYTES_V2)
        {
            return Err(DeploymentControlErrorV2::InstallationEvidenceIo);
        }
        Ok(())
    }

    fn recheck_parent(&self) -> Result<(), DeploymentControlErrorV2> {
        let opened = self
            .parent
            .metadata()
            .map_err(|_| DeploymentControlErrorV2::InstallationEvidenceIo)?;
        let current = fs::symlink_metadata(&self.parent_path)
            .map_err(|_| DeploymentControlErrorV2::InstallationEvidenceIo)?;
        if !opened.is_dir()
            || current.file_type().is_symlink()
            || !current.is_dir()
            || opened.dev() != self.parent_dev
            || opened.ino() != self.parent_ino
            || current.dev() != self.parent_dev
            || current.ino() != self.parent_ino
            || opened.uid() != self.owner_uid
            || opened.gid() != self.owner_gid
            || current.uid() != self.owner_uid
            || current.gid() != self.owner_gid
            || opened.mode() & 0o7777 != 0o700
            || current.mode() & 0o7777 != 0o700
        {
            return Err(DeploymentControlErrorV2::InstallationEvidenceIo);
        }
        Ok(())
    }
}

fn evidence_leaf(signed_digest: Digest32V2) -> OsString {
    let mut leaf = OsString::from(hex(signed_digest.as_bytes()));
    leaf.push(".cbor");
    leaf
}

fn parse_evidence_leaf(name: &[u8]) -> Option<Digest32V2> {
    if name.len() != 69 || &name[64..] != b".cbor" {
        return None;
    }
    let mut bytes = [0_u8; 32];
    for (index, pair) in name[..64].chunks_exact(2).enumerate() {
        bytes[index] = decode_hex(pair[0])?
            .checked_mul(16)?
            .checked_add(decode_hex(pair[1])?)?;
    }
    Some(Digest32V2::new(bytes))
}

fn is_temporary_leaf(name: &[u8]) -> bool {
    name.len() == 107
        && name.first() == Some(&b'.')
        && &name[65..70] == b".cbor"
        && &name[70..75] == b".tmp-"
        && name[1..65].iter().all(|byte| decode_hex(*byte).is_some())
        && name[75..].iter().all(|byte| decode_hex(*byte).is_some())
}

fn decode_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        value.push(char::from(DIGITS[usize::from(byte >> 4)]));
        value.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    value
}

fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}
