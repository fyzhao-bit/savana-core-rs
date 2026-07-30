use std::ffi::{OsStr, OsString};
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
    fchmod, openat, renameat_with, statat, AtFlags, Dir, FileType, Mode, OFlags, RenameFlags,
};
use rustix::io::Errno;
use savana_kernel_protocol::v2::Digest32V2;

use super::deployment_transition_store::{
    DeploymentDurabilityObserverV2, DeploymentDurabilityPointV2, NoDeploymentCrashV2,
};
use super::{
    DeploymentActivationVerifierV2, DeploymentControlErrorV2, EvidenceGcCheckpointV2,
    InstallationEvidenceEnvelopeV2,
};

#[cfg(target_os = "linux")]
const LINUX_EVIDENCE_GC_CHECKPOINT_DIRECTORY_V2: &str =
    "/var/lib/savana/deployment/evidence-gc-checkpoints";
#[cfg(target_os = "macos")]
const MACOS_EVIDENCE_GC_CHECKPOINT_DIRECTORY_V2: &str =
    "/Library/Application Support/Savana/Deployment/evidence-gc-checkpoints";
const MAX_CHECKPOINT_ENVELOPE_BYTES_V2: u64 = 16 * 1024 * 1024 + 1024;
const MAX_CHECKPOINT_RECORDS_V2: usize = 4096;
const TEMPORARY_NAME_ATTEMPTS_V2: usize = 16;

pub struct DurableEvidenceGcCheckpointStoreV2 {
    parent: File,
    parent_path: PathBuf,
    parent_dev: u64,
    parent_ino: u64,
    owner_uid: u32,
    owner_gid: u32,
    verifier: DeploymentActivationVerifierV2,
}

impl std::fmt::Debug for DurableEvidenceGcCheckpointStoreV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DurableEvidenceGcCheckpointStoreV2")
            .field("parent_path", &self.parent_path)
            .field("activation_key_id", &self.verifier.key_id())
            .field("installation_epoch", &self.verifier.key_epoch())
            .finish_non_exhaustive()
    }
}

impl DurableEvidenceGcCheckpointStoreV2 {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub fn open_fixed_platform(
        verifier: DeploymentActivationVerifierV2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        #[cfg(target_os = "linux")]
        let directory = Path::new(LINUX_EVIDENCE_GC_CHECKPOINT_DIRECTORY_V2);
        #[cfg(target_os = "macos")]
        let directory = Path::new(MACOS_EVIDENCE_GC_CHECKPOINT_DIRECTORY_V2);
        Self::open_anchored(directory, 0, 0, verifier)
    }

    #[cfg(target_os = "linux")]
    pub fn open_fixed_linux(
        verifier: DeploymentActivationVerifierV2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        Self::open_anchored(
            Path::new(LINUX_EVIDENCE_GC_CHECKPOINT_DIRECTORY_V2),
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
            .map_err(|_| DeploymentControlErrorV2::EvidenceGcCheckpointIo)?;
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
            return Err(DeploymentControlErrorV2::EvidenceGcCheckpointIo);
        }
        let before = fs::symlink_metadata(directory)
            .map_err(|_| DeploymentControlErrorV2::EvidenceGcCheckpointIo)?;
        if before.file_type().is_symlink()
            || !before.is_dir()
            || before.uid() != expected_uid
            || before.gid() != expected_gid
            || before.mode() & 0o7777 != 0o700
        {
            return Err(DeploymentControlErrorV2::EvidenceGcCheckpointIo);
        }
        let parent = File::from(
            open(
                directory,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| DeploymentControlErrorV2::EvidenceGcCheckpointIo)?,
        );
        let opened = parent
            .metadata()
            .map_err(|_| DeploymentControlErrorV2::EvidenceGcCheckpointIo)?;
        if !opened.is_dir()
            || opened.dev() != before.dev()
            || opened.ino() != before.ino()
            || opened.uid() != expected_uid
            || opened.gid() != expected_gid
            || opened.mode() & 0o7777 != 0o700
        {
            return Err(DeploymentControlErrorV2::EvidenceGcCheckpointIo);
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

    pub fn append_aborted_checkpoint(
        &self,
        envelope: &InstallationEvidenceEnvelopeV2,
    ) -> Result<(), DeploymentControlErrorV2> {
        self.append_aborted_checkpoint_observed(envelope, &mut NoDeploymentCrashV2)
    }

    pub(super) fn append_aborted_checkpoint_observed(
        &self,
        envelope: &InstallationEvidenceEnvelopeV2,
        observer: &mut dyn DeploymentDurabilityObserverV2,
    ) -> Result<(), DeploymentControlErrorV2> {
        self.recheck_parent()?;
        let authenticated = InstallationEvidenceEnvelopeV2::from_canonical_bytes(
            envelope.canonical_bytes(),
            &self.verifier,
        )?;
        let checkpoint = authenticated.evidence_gc_checkpoint(&self.verifier)?;
        let aborted_digest = checkpoint
            .compacted_transaction_provenance()
            .aborted_ledger_record_digest()
            .ok_or(DeploymentControlErrorV2::InvalidCompactedTransactionProvenance)?;
        let leaf = checkpoint_leaf(aborted_digest);
        match statat(&self.parent, &leaf, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(_) => {
                let existing = self.load_aborted_checkpoint_envelope(aborted_digest)?;
                if existing.canonical_bytes() != authenticated.canonical_bytes() {
                    return Err(DeploymentControlErrorV2::InvalidCompactedTransactionProvenance);
                }
                observer.reached(DeploymentDurabilityPointV2::CheckpointReopened)?;
                return Ok(());
            }
            Err(Errno::NOENT) => {}
            Err(_) => return Err(DeploymentControlErrorV2::EvidenceGcCheckpointIo),
        }

        observer.reached(DeploymentDurabilityPointV2::BeforeCheckpointWrite)?;
        let (temporary_leaf, mut temporary) = self.create_temporary(&leaf)?;
        let write_result = (|| {
            temporary
                .write_all(authenticated.canonical_bytes())
                .map_err(|_| DeploymentControlErrorV2::EvidenceGcCheckpointIo)?;
            temporary
                .sync_all()
                .map_err(|_| DeploymentControlErrorV2::EvidenceGcCheckpointIo)?;
            observer.reached(DeploymentDurabilityPointV2::CheckpointFileFlushed)?;
            self.validate_linked_file(
                &temporary_leaf,
                &temporary,
                u64::try_from(authenticated.canonical_bytes().len())
                    .map_err(|_| DeploymentControlErrorV2::EvidenceGcCheckpointIo)?,
            )?;
            self.recheck_parent()
        })();
        if let Err(error) = write_result {
            let _ = rustix::fs::unlinkat(&self.parent, &temporary_leaf, AtFlags::empty());
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
                let _ = rustix::fs::unlinkat(&self.parent, &temporary_leaf, AtFlags::empty());
                let existing = self.load_aborted_checkpoint_envelope(aborted_digest)?;
                if existing.canonical_bytes() != authenticated.canonical_bytes() {
                    return Err(DeploymentControlErrorV2::InvalidCompactedTransactionProvenance);
                }
                observer.reached(DeploymentDurabilityPointV2::CheckpointReopened)?;
                return Ok(());
            }
            Err(_) => {
                let _ = rustix::fs::unlinkat(&self.parent, &temporary_leaf, AtFlags::empty());
                return Err(DeploymentControlErrorV2::EvidenceGcCheckpointIo);
            }
        }
        observer.reached(DeploymentDurabilityPointV2::CheckpointRenamedBeforeDirectoryFlush)?;
        self.parent
            .sync_all()
            .map_err(|_| DeploymentControlErrorV2::EvidenceGcCheckpointIo)?;
        observer.reached(DeploymentDurabilityPointV2::CheckpointDirectoryFlushed)?;
        self.recheck_parent()?;
        let reopened = self.load_aborted_checkpoint_envelope(aborted_digest)?;
        if reopened.canonical_bytes() != authenticated.canonical_bytes() {
            return Err(DeploymentControlErrorV2::EvidenceGcCheckpointIo);
        }
        observer.reached(DeploymentDurabilityPointV2::CheckpointReopened)?;
        Ok(())
    }

    pub fn load_aborted_checkpoint(
        &self,
        aborted_ledger_record_digest: Digest32V2,
    ) -> Result<EvidenceGcCheckpointV2, DeploymentControlErrorV2> {
        self.load_aborted_checkpoint_envelope(aborted_ledger_record_digest)?
            .evidence_gc_checkpoint(&self.verifier)
    }

    pub fn load_aborted_checkpoint_envelope(
        &self,
        aborted_ledger_record_digest: Digest32V2,
    ) -> Result<InstallationEvidenceEnvelopeV2, DeploymentControlErrorV2> {
        if is_zero(aborted_ledger_record_digest.as_bytes()) {
            return Err(DeploymentControlErrorV2::InvalidCompactedTransactionProvenance);
        }
        self.recheck_parent()?;
        let leaf = checkpoint_leaf(aborted_ledger_record_digest);
        let bytes = self.read_checkpoint_bytes(&leaf)?;
        self.recheck_parent()?;
        let envelope =
            InstallationEvidenceEnvelopeV2::from_canonical_bytes(&bytes, &self.verifier)?;
        let checkpoint = envelope.evidence_gc_checkpoint(&self.verifier)?;
        if checkpoint
            .compacted_transaction_provenance()
            .aborted_ledger_record_digest()
            != Some(aborted_ledger_record_digest)
        {
            return Err(DeploymentControlErrorV2::InvalidCompactedTransactionProvenance);
        }
        Ok(envelope)
    }

    pub(super) fn retained_aborted_final_heads(
        &self,
    ) -> Result<Vec<Digest32V2>, DeploymentControlErrorV2> {
        self.recheck_parent()?;
        let directory = Dir::read_from(&self.parent)
            .map_err(|_| DeploymentControlErrorV2::EvidenceGcCheckpointIo)?;
        let mut entries = 0_usize;
        let mut retained = Vec::new();
        retained
            .try_reserve(MAX_CHECKPOINT_RECORDS_V2)
            .map_err(|_| DeploymentControlErrorV2::EvidenceGcCheckpointIo)?;
        for entry in directory {
            let entry = entry.map_err(|_| DeploymentControlErrorV2::EvidenceGcCheckpointIo)?;
            let name = entry.file_name().to_bytes();
            if matches!(name, b"." | b"..") {
                continue;
            }
            entries = entries
                .checked_add(1)
                .ok_or(DeploymentControlErrorV2::EvidenceGcCheckpointIo)?;
            if entries > MAX_CHECKPOINT_RECORDS_V2 {
                return Err(DeploymentControlErrorV2::EvidenceGcCheckpointIo);
            }
            let aborted_digest = parse_checkpoint_leaf(name)
                .ok_or(DeploymentControlErrorV2::EvidenceGcCheckpointIo)?;
            let envelope = self.load_aborted_checkpoint_envelope(aborted_digest)?;
            let checkpoint = envelope.evidence_gc_checkpoint(&self.verifier)?;
            let final_head = checkpoint
                .compacted_transaction_provenance()
                .final_transaction_head_signed_digest()
                .ok_or(DeploymentControlErrorV2::InvalidCompactedTransactionProvenance)?;
            retained.push(final_head);
        }
        retained.sort_unstable_by_key(|digest| *digest.as_bytes());
        retained.dedup();
        self.recheck_parent()?;
        Ok(retained)
    }

    fn create_temporary(
        &self,
        final_leaf: &OsStr,
    ) -> Result<(OsString, File), DeploymentControlErrorV2> {
        for _ in 0..TEMPORARY_NAME_ATTEMPTS_V2 {
            let mut random = [0_u8; 16];
            getrandom::getrandom(&mut random)
                .map_err(|_| DeploymentControlErrorV2::EvidenceGcCheckpointIo)?;
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
                        .map_err(|_| DeploymentControlErrorV2::EvidenceGcCheckpointIo)?;
                    self.validate_linked_file(&temporary_leaf, &file, 0)?;
                    return Ok((temporary_leaf, file));
                }
                Err(Errno::EXIST) => {}
                Err(_) => return Err(DeploymentControlErrorV2::EvidenceGcCheckpointIo),
            }
        }
        Err(DeploymentControlErrorV2::EvidenceGcCheckpointIo)
    }

    fn read_checkpoint_bytes(&self, leaf: &OsStr) -> Result<Vec<u8>, DeploymentControlErrorV2> {
        let before = statat(&self.parent, leaf, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| DeploymentControlErrorV2::EvidenceGcCheckpointIo)?;
        if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
            || before.st_uid != self.owner_uid
            || before.st_gid != self.owner_gid
            || before.st_mode & 0o7777 != 0o600
            || before.st_nlink != 1
            || before.st_size <= 0
            || u64::try_from(before.st_size)
                .ok()
                .is_none_or(|size| size > MAX_CHECKPOINT_ENVELOPE_BYTES_V2)
        {
            return Err(DeploymentControlErrorV2::EvidenceGcCheckpointIo);
        }
        let mut file = File::from(
            openat(
                &self.parent,
                leaf,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| DeploymentControlErrorV2::EvidenceGcCheckpointIo)?,
        );
        let opened = file
            .metadata()
            .map_err(|_| DeploymentControlErrorV2::EvidenceGcCheckpointIo)?;
        self.validate_linked_file(leaf, &file, opened.len())?;
        if opened.dev() as i128 != before.st_dev as i128
            || opened.ino() != before.st_ino
            || i128::from(opened.len()) != i128::from(before.st_size)
        {
            return Err(DeploymentControlErrorV2::EvidenceGcCheckpointIo);
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(
                usize::try_from(opened.len())
                    .map_err(|_| DeploymentControlErrorV2::EvidenceGcCheckpointIo)?,
            )
            .map_err(|_| DeploymentControlErrorV2::EvidenceGcCheckpointIo)?;
        file.read_to_end(&mut bytes)
            .map_err(|_| DeploymentControlErrorV2::EvidenceGcCheckpointIo)?;
        let after = statat(&self.parent, leaf, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| DeploymentControlErrorV2::EvidenceGcCheckpointIo)?;
        if u64::try_from(bytes.len())
            .map_err(|_| DeploymentControlErrorV2::EvidenceGcCheckpointIo)?
            != opened.len()
            || after.st_dev as i128 != before.st_dev as i128
            || after.st_ino != before.st_ino
            || after.st_size != before.st_size
        {
            return Err(DeploymentControlErrorV2::EvidenceGcCheckpointIo);
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
            .map_err(|_| DeploymentControlErrorV2::EvidenceGcCheckpointIo)?;
        let linked = statat(&self.parent, leaf, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| DeploymentControlErrorV2::EvidenceGcCheckpointIo)?;
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
            return Err(DeploymentControlErrorV2::EvidenceGcCheckpointIo);
        }
        Ok(())
    }

    fn recheck_parent(&self) -> Result<(), DeploymentControlErrorV2> {
        let opened = self
            .parent
            .metadata()
            .map_err(|_| DeploymentControlErrorV2::EvidenceGcCheckpointIo)?;
        let current = fs::symlink_metadata(&self.parent_path)
            .map_err(|_| DeploymentControlErrorV2::EvidenceGcCheckpointIo)?;
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
            return Err(DeploymentControlErrorV2::EvidenceGcCheckpointIo);
        }
        Ok(())
    }
}

fn checkpoint_leaf(aborted_ledger_record_digest: Digest32V2) -> OsString {
    let mut leaf = OsString::from(hex(aborted_ledger_record_digest.as_bytes()));
    leaf.push(".cbor");
    leaf
}

fn parse_checkpoint_leaf(name: &[u8]) -> Option<Digest32V2> {
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
