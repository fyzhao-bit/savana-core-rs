use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use nix::fcntl::{Flock, FlockArg};
use rustix::fs::{
    fchmod, open as rustix_open, openat, renameat, statat, unlinkat, AtFlags, FileType, Mode,
    OFlags,
};
use rustix::io::Errno;
use savana_kernel_protocol::v2::Digest32V2;

use super::{is_zero, ApprovalErrorV2};

const MAX_STATE_BYTES: u64 = 64 * 1024 * 1024;
const TEMP_ATTEMPTS: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApprovalStateHeadV2 {
    sequence: u64,
    state_digest: Digest32V2,
}

impl Default for ApprovalStateHeadV2 {
    fn default() -> Self {
        Self::GENESIS
    }
}

impl ApprovalStateHeadV2 {
    const GENESIS: Self = Self {
        sequence: 0,
        state_digest: Digest32V2::new([0; 32]),
    };

    pub fn new(sequence: u64, state_digest: Digest32V2) -> Result<Self, ApprovalErrorV2> {
        if (sequence == 0 && !is_zero(state_digest.as_bytes()))
            || (sequence != 0 && is_zero(state_digest.as_bytes()))
        {
            return Err(ApprovalErrorV2::RollbackDetected);
        }
        Ok(Self {
            sequence,
            state_digest,
        })
    }

    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    pub const fn state_digest(self) -> Digest32V2 {
        self.state_digest
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DurableApprovalNamespaceV2 {
    installation_id: Digest32V2,
    store_id: Digest32V2,
}

impl DurableApprovalNamespaceV2 {
    pub fn from_verified_installation(
        installation_id: Digest32V2,
        store_id: Digest32V2,
    ) -> Result<Self, ApprovalErrorV2> {
        if is_zero(installation_id.as_bytes()) || is_zero(store_id.as_bytes()) {
            return Err(ApprovalErrorV2::DurableState);
        }
        Ok(Self {
            installation_id,
            store_id,
        })
    }

    pub const fn installation_id(self) -> Digest32V2 {
        self.installation_id
    }

    pub const fn store_id(self) -> Digest32V2 {
        self.store_id
    }
}

pub trait ApprovalRollbackAnchorV2: Send {
    fn current_head(&self) -> Result<ApprovalStateHeadV2, ApprovalErrorV2>;

    fn compare_and_advance(
        &mut self,
        expected: ApprovalStateHeadV2,
        next: ApprovalStateHeadV2,
    ) -> Result<(), ApprovalErrorV2>;
}

pub(super) struct AnchoredPathV2 {
    pub(super) parent: File,
    parent_path: PathBuf,
    parent_dev: u64,
    parent_ino: u64,
    leaf: OsString,
    pub(super) owner_uid: u32,
    pub(super) owner_gid: u32,
}

impl AnchoredPathV2 {
    pub(super) fn open(path: &Path) -> Result<Self, ApprovalErrorV2> {
        if !path.is_absolute() {
            return Err(ApprovalErrorV2::DurableState);
        }
        let parent_path = path.parent().ok_or(ApprovalErrorV2::DurableState)?;
        let leaf = path
            .file_name()
            .ok_or(ApprovalErrorV2::DurableState)?
            .to_os_string();
        let before =
            fs::symlink_metadata(parent_path).map_err(|_| ApprovalErrorV2::DurableState)?;
        if before.file_type().is_symlink() {
            return Err(ApprovalErrorV2::DurableState);
        }
        let descriptor = rustix_open(
            parent_path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| ApprovalErrorV2::DurableState)?;
        let parent = File::from(descriptor);
        let opened = parent
            .metadata()
            .map_err(|_| ApprovalErrorV2::DurableState)?;
        if !opened.is_dir()
            || opened.dev() != before.dev()
            || opened.ino() != before.ino()
            || opened.uid() != before.uid()
            || opened.gid() != before.gid()
            || opened.mode() & 0o7777 != 0o700
        {
            return Err(ApprovalErrorV2::DurableState);
        }
        let anchored = Self {
            parent,
            parent_path: parent_path.to_owned(),
            parent_dev: opened.dev(),
            parent_ino: opened.ino(),
            leaf,
            owner_uid: opened.uid(),
            owner_gid: opened.gid(),
        };
        anchored.recheck_parent()?;
        Ok(anchored)
    }

    pub(super) fn recheck_parent(&self) -> Result<(), ApprovalErrorV2> {
        let opened = self
            .parent
            .metadata()
            .map_err(|_| ApprovalErrorV2::DurableState)?;
        let linked =
            fs::symlink_metadata(&self.parent_path).map_err(|_| ApprovalErrorV2::DurableState)?;
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
            return Err(ApprovalErrorV2::DurableState);
        }
        Ok(())
    }

    pub(super) fn read_existing(&self) -> Result<Option<Vec<u8>>, ApprovalErrorV2> {
        let before = match statat(&self.parent, &self.leaf, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => stat,
            Err(Errno::NOENT) => return Ok(None),
            Err(_) => return Err(ApprovalErrorV2::DurableState),
        };
        if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile {
            return Err(ApprovalErrorV2::DurableState);
        }
        let descriptor = openat(
            &self.parent,
            &self.leaf,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| ApprovalErrorV2::DurableState)?;
        let mut file = File::from(descriptor);
        let opened = file.metadata().map_err(|_| ApprovalErrorV2::DurableState)?;
        if !opened.is_file()
            || i128::from(before.st_dev) != i128::from(opened.dev())
            || before.st_ino != opened.ino()
            || before.st_uid != self.owner_uid
            || before.st_gid != self.owner_gid
            || opened.uid() != self.owner_uid
            || opened.gid() != self.owner_gid
            || opened.mode() & 0o7777 != 0o600
            || opened.nlink() != 1
            || opened.len() > MAX_STATE_BYTES
        {
            return Err(ApprovalErrorV2::DurableState);
        }
        let capacity = usize::try_from(opened.len()).map_err(|_| ApprovalErrorV2::DurableState)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(capacity)
            .map_err(|_| ApprovalErrorV2::AllocationFailure)?;
        file.read_to_end(&mut bytes)
            .map_err(|_| ApprovalErrorV2::DurableState)?;
        let after = statat(&self.parent, &self.leaf, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| ApprovalErrorV2::DurableState)?;
        if bytes.len() != capacity
            || i128::from(after.st_dev) != i128::from(opened.dev())
            || after.st_ino != opened.ino()
            || u64::try_from(after.st_size).ok() != Some(opened.len())
        {
            return Err(ApprovalErrorV2::DurableState);
        }
        self.recheck_parent()?;
        Ok(Some(bytes))
    }

    pub(super) fn replace(&self, bytes: &[u8]) -> Result<(), bool> {
        let (temporary_leaf, mut temporary) =
            create_temporary(&self.parent, &self.leaf, self.owner_uid, self.owner_gid)
                .map_err(|_| false)?;
        let before_rename = (|| {
            temporary
                .write_all(bytes)
                .map_err(|_| ApprovalErrorV2::DurableState)?;
            temporary
                .sync_all()
                .map_err(|_| ApprovalErrorV2::DurableState)?;
            validate_file_at(
                &self.parent,
                &temporary_leaf,
                &temporary,
                self.owner_uid,
                self.owner_gid,
                u64::try_from(bytes.len()).map_err(|_| ApprovalErrorV2::DurableState)?,
            )?;
            self.recheck_parent()
        })();
        if before_rename.is_err() {
            let _ = unlinkat(&self.parent, &temporary_leaf, AtFlags::empty());
            return Err(false);
        }
        if renameat(&self.parent, &temporary_leaf, &self.parent, &self.leaf).is_err() {
            let _ = unlinkat(&self.parent, &temporary_leaf, AtFlags::empty());
            return Err(false);
        }
        validate_file_at(
            &self.parent,
            &self.leaf,
            &temporary,
            self.owner_uid,
            self.owner_gid,
            u64::try_from(bytes.len()).map_err(|_| true)?,
        )
        .map_err(|_| true)?;
        self.parent.sync_all().map_err(|_| true)?;
        self.recheck_parent().map_err(|_| true)
    }
}

fn create_temporary(
    parent: &File,
    final_leaf: &OsStr,
    owner_uid: u32,
    owner_gid: u32,
) -> Result<(OsString, File), ApprovalErrorV2> {
    for _ in 0..TEMP_ATTEMPTS {
        let mut random = [0_u8; 16];
        getrandom::getrandom(&mut random).map_err(|_| ApprovalErrorV2::DurableState)?;
        let mut temporary_leaf = OsString::from(".");
        temporary_leaf.push(final_leaf);
        temporary_leaf.push(".tmp-");
        temporary_leaf.push(hex(&random));
        match openat(
            parent,
            &temporary_leaf,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_bits_truncate(0o600),
        ) {
            Ok(descriptor) => {
                let file = File::from(descriptor);
                fchmod(&file, Mode::from_bits_truncate(0o600))
                    .map_err(|_| ApprovalErrorV2::DurableState)?;
                validate_file_at(parent, &temporary_leaf, &file, owner_uid, owner_gid, 0)?;
                return Ok((temporary_leaf, file));
            }
            Err(Errno::EXIST) => {}
            Err(_) => return Err(ApprovalErrorV2::DurableState),
        }
    }
    Err(ApprovalErrorV2::DurableState)
}

fn validate_file_at(
    parent: &File,
    leaf: &OsStr,
    file: &File,
    owner_uid: u32,
    owner_gid: u32,
    expected_length: u64,
) -> Result<(), ApprovalErrorV2> {
    let opened = file.metadata().map_err(|_| ApprovalErrorV2::DurableState)?;
    let linked = statat(parent, leaf, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| ApprovalErrorV2::DurableState)?;
    if !opened.is_file()
        || opened.uid() != owner_uid
        || opened.gid() != owner_gid
        || opened.mode() & 0o7777 != 0o600
        || opened.nlink() != 1
        || opened.len() != expected_length
        || FileType::from_raw_mode(linked.st_mode) != FileType::RegularFile
        || i128::from(linked.st_dev) != i128::from(opened.dev())
        || linked.st_ino != opened.ino()
        || linked.st_uid != owner_uid
        || linked.st_gid != owner_gid
        || linked.st_mode & 0o7777 != 0o600
        || linked.st_nlink != 1
        || u64::try_from(linked.st_size).ok() != Some(expected_length)
    {
        return Err(ApprovalErrorV2::DurableState);
    }
    Ok(())
}

pub(super) struct StateLockV2 {
    file: Flock<File>,
    parent: File,
    leaf: OsString,
    owner_uid: u32,
    owner_gid: u32,
}

impl StateLockV2 {
    pub(super) fn acquire(
        parent: &File,
        leaf: &OsStr,
        owner_uid: u32,
        owner_gid: u32,
    ) -> Result<Self, ApprovalErrorV2> {
        let descriptor = openat(
            parent,
            leaf,
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::from_bits_truncate(0o600),
        )
        .map_err(|_| ApprovalErrorV2::DurableState)?;
        let file = File::from(descriptor);
        fchmod(&file, Mode::from_bits_truncate(0o600))
            .map_err(|_| ApprovalErrorV2::DurableState)?;
        validate_file_at(parent, leaf, &file, owner_uid, owner_gid, 0)?;
        let file = Flock::lock(file, FlockArg::LockExclusiveNonblock)
            .map_err(|_| ApprovalErrorV2::DurableState)?;
        validate_file_at(parent, leaf, &file, owner_uid, owner_gid, 0)?;
        parent
            .sync_all()
            .map_err(|_| ApprovalErrorV2::DurableState)?;
        Ok(Self {
            file,
            parent: parent
                .try_clone()
                .map_err(|_| ApprovalErrorV2::DurableState)?,
            leaf: leaf.to_os_string(),
            owner_uid,
            owner_gid,
        })
    }

    pub(super) fn recheck(&self) -> Result<(), ApprovalErrorV2> {
        validate_file_at(
            &self.parent,
            &self.leaf,
            &self.file,
            self.owner_uid,
            self.owner_gid,
            0,
        )
    }
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}
