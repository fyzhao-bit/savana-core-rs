use std::collections::HashSet;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io::{Read as _, Write as _};
use std::os::unix::ffi::OsStrExt as _;
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

use super::deployment_transition_store::{
    DeploymentDurabilityObserverV2, DeploymentDurabilityPointV2, NoDeploymentCrashV2,
};
use super::{
    AuthenticatedDeploymentLedgerSnapshotV2, DeploymentActivationVerifierV2, DeploymentBranchV2,
    DeploymentControlErrorV2, DeploymentPhaseV2, DurableDeploymentTransactionRecordV2,
};

#[cfg(target_os = "linux")]
const LINUX_TRANSACTION_HEAD_DIRECTORY_V2: &str = "/var/lib/savana/deployment/transaction-heads";
#[cfg(target_os = "macos")]
const MACOS_TRANSACTION_HEAD_DIRECTORY_V2: &str =
    "/Library/Application Support/Savana/Deployment/transaction-heads";
const MAX_DURABLE_HEAD_BYTES_V2: u64 = 1024 * 1024;
const MAX_DURABLE_HEAD_CHAIN_RECORDS_V2: usize = 4096;
const TEMPORARY_NAME_ATTEMPTS_V2: usize = 16;

pub struct DurableDeploymentTransactionStoreV2 {
    parent: File,
    parent_path: PathBuf,
    parent_dev: u64,
    parent_ino: u64,
    owner_uid: u32,
    owner_gid: u32,
    verifier: DeploymentActivationVerifierV2,
}

impl std::fmt::Debug for DurableDeploymentTransactionStoreV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DurableDeploymentTransactionStoreV2")
            .field("parent_path", &self.parent_path)
            .field("activation_key_id", &self.verifier.key_id())
            .field("installation_epoch", &self.verifier.key_epoch())
            .finish_non_exhaustive()
    }
}

impl DurableDeploymentTransactionStoreV2 {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub fn open_fixed_platform(
        verifier: DeploymentActivationVerifierV2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        #[cfg(target_os = "linux")]
        let directory = Path::new(LINUX_TRANSACTION_HEAD_DIRECTORY_V2);
        #[cfg(target_os = "macos")]
        let directory = Path::new(MACOS_TRANSACTION_HEAD_DIRECTORY_V2);
        Self::open_anchored(directory, 0, 0, verifier)
    }

    #[cfg(target_os = "linux")]
    pub fn open_fixed_linux(
        verifier: DeploymentActivationVerifierV2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        Self::open_anchored(
            Path::new(LINUX_TRANSACTION_HEAD_DIRECTORY_V2),
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
            .map_err(|_| DeploymentControlErrorV2::DeploymentTransactionIo)?;
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
            return Err(DeploymentControlErrorV2::DeploymentTransactionIo);
        }
        let before = fs::symlink_metadata(directory)
            .map_err(|_| DeploymentControlErrorV2::DeploymentTransactionIo)?;
        if before.file_type().is_symlink()
            || !before.is_dir()
            || before.uid() != expected_uid
            || before.gid() != expected_gid
            || before.mode() & 0o7777 != 0o700
        {
            return Err(DeploymentControlErrorV2::DeploymentTransactionIo);
        }
        let descriptor = open(
            directory,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| DeploymentControlErrorV2::DeploymentTransactionIo)?;
        let parent = File::from(descriptor);
        let opened = parent
            .metadata()
            .map_err(|_| DeploymentControlErrorV2::DeploymentTransactionIo)?;
        if !opened.is_dir()
            || opened.dev() != before.dev()
            || opened.ino() != before.ino()
            || opened.uid() != expected_uid
            || opened.gid() != expected_gid
            || opened.mode() & 0o7777 != 0o700
        {
            return Err(DeploymentControlErrorV2::DeploymentTransactionIo);
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

    pub fn append_head(
        &self,
        head: &DurableDeploymentTransactionRecordV2,
    ) -> Result<Digest32V2, DeploymentControlErrorV2> {
        self.append_head_observed(head, &mut NoDeploymentCrashV2)
    }

    pub(super) fn append_head_observed(
        &self,
        head: &DurableDeploymentTransactionRecordV2,
        observer: &mut dyn DeploymentDurabilityObserverV2,
    ) -> Result<Digest32V2, DeploymentControlErrorV2> {
        self.recheck_parent()?;
        let authenticated = DurableDeploymentTransactionRecordV2::from_canonical_bytes(
            head.canonical_bytes(),
            &self.verifier,
        )?;
        if authenticated.signed_digest() != head.signed_digest() {
            return Err(DeploymentControlErrorV2::InvalidDurableDeploymentHead);
        }
        let leaf = head_leaf(head.signed_digest());
        match statat(&self.parent, &leaf, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(_) => {
                let reopened = self.load_existing_identical(&leaf, head)?;
                observer.reached(DeploymentDurabilityPointV2::HeadReopened)?;
                return Ok(reopened);
            }
            Err(Errno::NOENT) => {}
            Err(_) => return Err(DeploymentControlErrorV2::DeploymentTransactionIo),
        }

        observer.reached(DeploymentDurabilityPointV2::BeforeHeadWrite)?;
        let (temporary_leaf, mut temporary) = self.create_temporary(&leaf)?;
        let write_result = (|| {
            temporary
                .write_all(head.canonical_bytes())
                .map_err(|_| DeploymentControlErrorV2::DeploymentTransactionIo)?;
            temporary
                .sync_all()
                .map_err(|_| DeploymentControlErrorV2::DeploymentTransactionIo)?;
            observer.reached(DeploymentDurabilityPointV2::HeadFileFlushed)?;
            self.validate_linked_file(
                &temporary_leaf,
                &temporary,
                u64::try_from(head.canonical_bytes().len())
                    .map_err(|_| DeploymentControlErrorV2::DeploymentTransactionIo)?,
            )?;
            self.recheck_parent()?;
            Ok(())
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
                let reopened = self.load_existing_identical(&leaf, head)?;
                observer.reached(DeploymentDurabilityPointV2::HeadReopened)?;
                return Ok(reopened);
            }
            Err(_) => {
                let _ = unlinkat(&self.parent, &temporary_leaf, AtFlags::empty());
                return Err(DeploymentControlErrorV2::DeploymentTransactionIo);
            }
        }
        observer.reached(DeploymentDurabilityPointV2::HeadRenamedBeforeDirectoryFlush)?;
        self.parent
            .sync_all()
            .map_err(|_| DeploymentControlErrorV2::DeploymentTransactionIo)?;
        observer.reached(DeploymentDurabilityPointV2::HeadDirectoryFlushed)?;
        self.recheck_parent()?;
        let reopened = self.load_existing_identical(&leaf, head)?;
        observer.reached(DeploymentDurabilityPointV2::HeadReopened)?;
        Ok(reopened)
    }

    pub fn load_head(
        &self,
        signed_digest: Digest32V2,
    ) -> Result<DurableDeploymentTransactionRecordV2, DeploymentControlErrorV2> {
        if signed_digest.as_bytes().iter().all(|byte| *byte == 0) {
            return Err(DeploymentControlErrorV2::DeploymentTransactionIo);
        }
        self.recheck_parent()?;
        let bytes = self.read_head_bytes(&head_leaf(signed_digest))?;
        self.recheck_parent()?;
        let head =
            DurableDeploymentTransactionRecordV2::from_canonical_bytes(&bytes, &self.verifier)
                .map_err(|_| DeploymentControlErrorV2::DeploymentTransactionIo)?;
        if head.signed_digest() != signed_digest {
            return Err(DeploymentControlErrorV2::DeploymentTransactionIo);
        }
        Ok(head)
    }

    pub fn load_chain(
        &self,
        selected_head_digest: Digest32V2,
        maximum_records: usize,
        branch: DeploymentBranchV2,
    ) -> Result<Vec<DurableDeploymentTransactionRecordV2>, DeploymentControlErrorV2> {
        if maximum_records == 0 || maximum_records > MAX_DURABLE_HEAD_CHAIN_RECORDS_V2 {
            return Err(DeploymentControlErrorV2::InvalidDurableDeploymentHead);
        }
        let mut reversed = Vec::new();
        reversed
            .try_reserve_exact(maximum_records)
            .map_err(|_| DeploymentControlErrorV2::DeploymentTransactionIo)?;
        let mut seen = HashSet::new();
        seen.try_reserve(maximum_records)
            .map_err(|_| DeploymentControlErrorV2::DeploymentTransactionIo)?;
        let mut next_digest = Some(selected_head_digest);
        while let Some(digest) = next_digest {
            if reversed.len() == maximum_records || !seen.insert(digest) {
                return Err(DeploymentControlErrorV2::InvalidDurableDeploymentHead);
            }
            let head = self.load_head(digest)?;
            next_digest = head.previous_head_digest();
            reversed.push(head);
        }
        reversed.reverse();
        for pair in reversed.windows(2) {
            pair[0].validate_successor(&pair[1], branch)?;
        }
        Ok(reversed)
    }

    pub fn load_selected_chain(
        &self,
        ledger: &AuthenticatedDeploymentLedgerSnapshotV2,
        maximum_records: usize,
        branch: DeploymentBranchV2,
    ) -> Result<Vec<DurableDeploymentTransactionRecordV2>, DeploymentControlErrorV2> {
        let selected = ledger.selected_record().projection();
        let Some(selected_head_digest) = selected.transaction_head_digest() else {
            if selected.transaction_id().is_none()
                && matches!(
                    selected.phase(),
                    DeploymentPhaseV2::Idle | DeploymentPhaseV2::BootstrapBridge
                )
            {
                return Ok(Vec::new());
            }
            return Err(DeploymentControlErrorV2::InvalidDurableDeploymentHead);
        };
        let transaction_id = selected
            .transaction_id()
            .ok_or(DeploymentControlErrorV2::InvalidDurableDeploymentHead)?;
        let chain = self.load_chain(selected_head_digest, maximum_records, branch)?;
        let selected_head = chain
            .last()
            .ok_or(DeploymentControlErrorV2::InvalidDurableDeploymentHead)?;
        if selected_head.signed_digest() != selected_head_digest
            || selected_head.transaction_id() != transaction_id
            || selected_head.target_phase() != selected.phase()
        {
            return Err(DeploymentControlErrorV2::TransactionBindingMismatch);
        }
        let predecessor = ledger
            .predecessor_record()
            .ok_or(DeploymentControlErrorV2::LedgerConflict)?;
        selected_head.validate_expected_previous_ledger(predecessor)?;
        Ok(chain)
    }

    pub(super) fn load_chain_any_branch(
        &self,
        selected_head_digest: Digest32V2,
        maximum_records: usize,
    ) -> Result<Vec<DurableDeploymentTransactionRecordV2>, DeploymentControlErrorV2> {
        let normal = self.load_chain(
            selected_head_digest,
            maximum_records,
            DeploymentBranchV2::Normal,
        );
        let bridge = self.load_chain(
            selected_head_digest,
            maximum_records,
            DeploymentBranchV2::BootstrapBridgeRestore,
        );
        match (normal, bridge) {
            (Ok(normal), Ok(bridge)) => {
                if normal
                    .iter()
                    .map(DurableDeploymentTransactionRecordV2::signed_digest)
                    .eq(bridge
                        .iter()
                        .map(DurableDeploymentTransactionRecordV2::signed_digest))
                {
                    Ok(normal)
                } else {
                    Err(DeploymentControlErrorV2::InvalidDurableDeploymentHead)
                }
            }
            (Ok(chain), Err(_)) | (Err(_), Ok(chain)) => Ok(chain),
            (Err(_), Err(_)) => Err(DeploymentControlErrorV2::InvalidDurableDeploymentHead),
        }
    }

    pub(super) fn gc_unreferenced_heads_observed(
        &self,
        retained: &HashSet<Digest32V2>,
        current_ledger_record_digest: Digest32V2,
        current_ledger_generation: u64,
        observer: &mut dyn DeploymentDurabilityObserverV2,
    ) -> Result<usize, DeploymentControlErrorV2> {
        self.recheck_parent()?;
        let mut directory = Dir::read_from(&self.parent)
            .map_err(|_| DeploymentControlErrorV2::DeploymentTransactionIo)?;
        let mut deletion = Vec::new();
        let mut observed_entries = 0_usize;
        for entry in directory.by_ref() {
            let entry = entry.map_err(|_| DeploymentControlErrorV2::DeploymentTransactionIo)?;
            let name = entry.file_name().to_bytes();
            if matches!(name, b"." | b"..") {
                continue;
            }
            observed_entries = observed_entries
                .checked_add(1)
                .ok_or(DeploymentControlErrorV2::DeploymentTransactionIo)?;
            if observed_entries > MAX_DURABLE_HEAD_CHAIN_RECORDS_V2 {
                return Err(DeploymentControlErrorV2::DeploymentTransactionIo);
            }
            let leaf = OsStr::from_bytes(name).to_os_string();
            match classify_head_directory_leaf(name) {
                Some(HeadDirectoryLeafV2::Published(digest)) => {
                    let head = self.load_head(digest)?;
                    if head.signed_digest() != digest {
                        return Err(DeploymentControlErrorV2::DeploymentTransactionIo);
                    }
                    if !retained.contains(&digest)
                        && head.expected_previous_ledger_record_digest()
                            == current_ledger_record_digest
                        && head.expected_previous_ledger_generation() == current_ledger_generation
                    {
                        deletion.push(leaf);
                    }
                }
                Some(HeadDirectoryLeafV2::Temporary) => {
                    self.validate_temporary_leaf(&leaf)?;
                    deletion.push(leaf);
                }
                None => return Err(DeploymentControlErrorV2::DeploymentTransactionIo),
            }
        }
        drop(directory);
        deletion.sort();
        for leaf in &deletion {
            observer.reached(DeploymentDurabilityPointV2::BeforeUnreferencedHeadUnlink)?;
            unlinkat(&self.parent, leaf, AtFlags::empty())
                .map_err(|_| DeploymentControlErrorV2::DeploymentTransactionIo)?;
            observer.reached(DeploymentDurabilityPointV2::AfterUnreferencedHeadUnlink)?;
        }
        if !deletion.is_empty() {
            self.parent
                .sync_all()
                .map_err(|_| DeploymentControlErrorV2::DeploymentTransactionIo)?;
            observer.reached(DeploymentDurabilityPointV2::UnreferencedHeadDirectoryFlushed)?;
        }
        self.recheck_parent()?;
        Ok(deletion.len())
    }

    fn load_existing_identical(
        &self,
        leaf: &OsStr,
        expected: &DurableDeploymentTransactionRecordV2,
    ) -> Result<Digest32V2, DeploymentControlErrorV2> {
        let reopened = self.load_head(expected.signed_digest())?;
        if leaf != head_leaf(expected.signed_digest())
            || reopened.canonical_bytes() != expected.canonical_bytes()
        {
            return Err(DeploymentControlErrorV2::DeploymentTransactionIo);
        }
        Ok(reopened.signed_digest())
    }

    fn create_temporary(
        &self,
        final_leaf: &OsStr,
    ) -> Result<(OsString, File), DeploymentControlErrorV2> {
        for _ in 0..TEMPORARY_NAME_ATTEMPTS_V2 {
            let mut random = [0_u8; 16];
            getrandom::getrandom(&mut random)
                .map_err(|_| DeploymentControlErrorV2::DeploymentTransactionIo)?;
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
                        .map_err(|_| DeploymentControlErrorV2::DeploymentTransactionIo)?;
                    self.validate_linked_file(&temporary_leaf, &file, 0)?;
                    return Ok((temporary_leaf, file));
                }
                Err(Errno::EXIST) => {}
                Err(_) => return Err(DeploymentControlErrorV2::DeploymentTransactionIo),
            }
        }
        Err(DeploymentControlErrorV2::DeploymentTransactionIo)
    }

    fn read_head_bytes(&self, leaf: &OsStr) -> Result<Vec<u8>, DeploymentControlErrorV2> {
        let before = statat(&self.parent, leaf, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| DeploymentControlErrorV2::DeploymentTransactionIo)?;
        if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
            || before.st_uid != self.owner_uid
            || before.st_gid != self.owner_gid
            || before.st_mode & 0o7777 != 0o600
            || before.st_nlink != 1
            || before.st_size <= 0
            || u64::try_from(before.st_size)
                .ok()
                .is_none_or(|size| size > MAX_DURABLE_HEAD_BYTES_V2)
        {
            return Err(DeploymentControlErrorV2::DeploymentTransactionIo);
        }
        let descriptor = openat(
            &self.parent,
            leaf,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| DeploymentControlErrorV2::DeploymentTransactionIo)?;
        let mut file = File::from(descriptor);
        let opened = file
            .metadata()
            .map_err(|_| DeploymentControlErrorV2::DeploymentTransactionIo)?;
        self.validate_linked_file(leaf, &file, opened.len())?;
        if opened.dev() as i128 != before.st_dev as i128
            || opened.ino() != before.st_ino
            || i128::from(opened.len()) != i128::from(before.st_size)
        {
            return Err(DeploymentControlErrorV2::DeploymentTransactionIo);
        }
        let expected_length = usize::try_from(opened.len())
            .map_err(|_| DeploymentControlErrorV2::DeploymentTransactionIo)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(expected_length)
            .map_err(|_| DeploymentControlErrorV2::DeploymentTransactionIo)?;
        file.read_to_end(&mut bytes)
            .map_err(|_| DeploymentControlErrorV2::DeploymentTransactionIo)?;
        let after = statat(&self.parent, leaf, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| DeploymentControlErrorV2::DeploymentTransactionIo)?;
        if bytes.len() != expected_length
            || after.st_dev as i128 != before.st_dev as i128
            || after.st_ino != before.st_ino
            || after.st_size != before.st_size
        {
            return Err(DeploymentControlErrorV2::DeploymentTransactionIo);
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
            .map_err(|_| DeploymentControlErrorV2::DeploymentTransactionIo)?;
        let linked = statat(&self.parent, leaf, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| DeploymentControlErrorV2::DeploymentTransactionIo)?;
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
            return Err(DeploymentControlErrorV2::DeploymentTransactionIo);
        }
        Ok(())
    }

    fn validate_temporary_leaf(&self, leaf: &OsStr) -> Result<(), DeploymentControlErrorV2> {
        let linked = statat(&self.parent, leaf, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| DeploymentControlErrorV2::DeploymentTransactionIo)?;
        if FileType::from_raw_mode(linked.st_mode) != FileType::RegularFile
            || linked.st_uid != self.owner_uid
            || linked.st_gid != self.owner_gid
            || linked.st_mode & 0o7777 != 0o600
            || linked.st_nlink != 1
            || linked.st_size < 0
            || u64::try_from(linked.st_size)
                .ok()
                .is_none_or(|size| size > MAX_DURABLE_HEAD_BYTES_V2)
        {
            return Err(DeploymentControlErrorV2::DeploymentTransactionIo);
        }
        Ok(())
    }

    fn recheck_parent(&self) -> Result<(), DeploymentControlErrorV2> {
        let opened = self
            .parent
            .metadata()
            .map_err(|_| DeploymentControlErrorV2::DeploymentTransactionIo)?;
        let linked = fs::symlink_metadata(&self.parent_path)
            .map_err(|_| DeploymentControlErrorV2::DeploymentTransactionIo)?;
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
            return Err(DeploymentControlErrorV2::DeploymentTransactionIo);
        }
        Ok(())
    }
}

enum HeadDirectoryLeafV2 {
    Published(Digest32V2),
    Temporary,
}

fn classify_head_directory_leaf(name: &[u8]) -> Option<HeadDirectoryLeafV2> {
    if let Some(digest) = decode_published_head_leaf(name) {
        return Some(HeadDirectoryLeafV2::Published(digest));
    }
    if name.len() == 107
        && name[0] == b'.'
        && decode_published_head_leaf(&name[1..70]).is_some()
        && &name[70..75] == b".tmp-"
        && name[75..].iter().all(|byte| is_lower_hex(*byte))
    {
        return Some(HeadDirectoryLeafV2::Temporary);
    }
    None
}

fn decode_published_head_leaf(name: &[u8]) -> Option<Digest32V2> {
    if name.len() != 69 || &name[64..] != b".cbor" {
        return None;
    }
    let mut bytes = [0_u8; 32];
    for (index, pair) in name[..64].chunks_exact(2).enumerate() {
        bytes[index] = (decode_lower_hex(pair[0])? << 4) | decode_lower_hex(pair[1])?;
    }
    Some(Digest32V2::new(bytes))
}

const fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')
}

const fn decode_lower_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn head_leaf(signed_digest: Digest32V2) -> OsString {
    let mut leaf = OsString::from(hex(signed_digest.as_bytes()));
    leaf.push(".cbor");
    leaf
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
