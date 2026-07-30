use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Component, Path, PathBuf};

use rustix::fs::{open, openat, statat, AtFlags, FileType, Mode, OFlags, Stat};
use savana_kernel_protocol::StableCode;

use crate::DaemonError;

#[derive(Clone, Copy, PartialEq, Eq)]
struct NodeIdentity {
    dev: i128,
    ino: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    nlink: u64,
    length: u64,
}

impl NodeIdentity {
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

    fn from_stat(stat: &Stat, failure: StableCode) -> Result<Self, DaemonError> {
        Ok(Self {
            dev: i128::from(stat.st_dev),
            ino: checked_u64(stat.st_ino, failure)?,
            uid: checked_u32(stat.st_uid, failure)?,
            gid: checked_u32(stat.st_gid, failure)?,
            mode: checked_u32(stat.st_mode, failure)?,
            nlink: checked_u64(stat.st_nlink, failure)?,
            length: checked_u64(stat.st_size, failure)?,
        })
    }

    const fn permissions(self) -> u32 {
        self.mode & 0o7777
    }
}

fn checked_u64<T: TryInto<u64>>(value: T, failure: StableCode) -> Result<u64, DaemonError> {
    value.try_into().map_err(|_| DaemonError::stable(failure))
}

fn checked_u32<T: TryInto<u32>>(value: T, failure: StableCode) -> Result<u32, DaemonError> {
    value.try_into().map_err(|_| DaemonError::stable(failure))
}

pub(crate) struct DirectoryCapability {
    file: File,
    path: PathBuf,
    identity: NodeIdentity,
    failure: StableCode,
}

impl std::fmt::Debug for DirectoryCapability {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DirectoryCapability(<verified>)")
    }
}

impl DirectoryCapability {
    pub(crate) fn open_final(
        path: &Path,
        owner_uid: u32,
        owner_gid: u32,
        permissions: u32,
        failure: StableCode,
    ) -> Result<Self, DaemonError> {
        if !path.is_absolute() {
            return Err(DaemonError::stable(failure));
        }
        let before = fs::symlink_metadata(path).map_err(|_| DaemonError::stable(failure))?;
        if before.file_type().is_symlink() {
            return Err(DaemonError::stable(failure));
        }
        let descriptor = open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| DaemonError::stable(failure))?;
        let file = File::from(descriptor);
        let metadata = file.metadata().map_err(|_| DaemonError::stable(failure))?;
        let identity = NodeIdentity::from_metadata(&metadata);
        if !metadata.is_dir()
            || identity != NodeIdentity::from_metadata(&before)
            || identity.uid != owner_uid
            || identity.gid != owner_gid
            || identity.permissions() != permissions
        {
            return Err(DaemonError::stable(failure));
        }
        let after = fs::symlink_metadata(path).map_err(|_| DaemonError::stable(failure))?;
        if after.file_type().is_symlink() || NodeIdentity::from_metadata(&after) != identity {
            return Err(DaemonError::stable(failure));
        }
        Ok(Self {
            file,
            path: path.to_path_buf(),
            identity,
            failure,
        })
    }

    pub(crate) fn open_file(
        &self,
        leaf: &OsStr,
        expectation: FileExpectation,
    ) -> Result<FileCapability, DaemonError> {
        ensure_normal_leaf(leaf, self.failure)?;
        let before = statat(&self.file, leaf, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| DaemonError::stable(self.failure))?;
        if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile {
            return Err(DaemonError::stable(self.failure));
        }
        let before = NodeIdentity::from_stat(&before, self.failure)?;
        let descriptor = openat(
            &self.file,
            leaf,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| DaemonError::stable(self.failure))?;
        let file = File::from(descriptor);
        let metadata = file
            .metadata()
            .map_err(|_| DaemonError::stable(self.failure))?;
        let identity = NodeIdentity::from_metadata(&metadata);
        if identity != before
            || !metadata.is_file()
            || identity.uid != expectation.owner_uid
            || identity.gid != expectation.owner_gid
            || identity.permissions() != expectation.permissions
            || identity.nlink != 1
            || !expectation.length.accepts(identity.length)
        {
            return Err(DaemonError::stable(self.failure));
        }
        let after = stat_identity(&self.file, leaf, self.failure)?;
        if after != identity {
            return Err(DaemonError::stable(self.failure));
        }
        Ok(FileCapability {
            file,
            parent: self
                .file
                .try_clone()
                .map_err(|_| DaemonError::stable(self.failure))?,
            leaf: leaf.to_os_string(),
            identity,
            failure: self.failure,
        })
    }

    pub(crate) fn recheck(&self) -> Result<(), DaemonError> {
        let descriptor = NodeIdentity::from_metadata(
            &self
                .file
                .metadata()
                .map_err(|_| DaemonError::stable(self.failure))?,
        );
        let pathname =
            fs::symlink_metadata(&self.path).map_err(|_| DaemonError::stable(self.failure))?;
        if pathname.file_type().is_symlink()
            || descriptor != self.identity
            || NodeIdentity::from_metadata(&pathname) != self.identity
        {
            return Err(DaemonError::stable(self.failure));
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
pub(crate) struct FileExpectation {
    pub(crate) owner_uid: u32,
    pub(crate) owner_gid: u32,
    pub(crate) permissions: u32,
    pub(crate) length: LengthRule,
}

#[derive(Clone, Copy)]
pub(crate) enum LengthRule {
    Exact(u64),
    Maximum(u64),
}

impl LengthRule {
    const fn accepts(self, actual: u64) -> bool {
        match self {
            Self::Exact(expected) => actual == expected,
            Self::Maximum(maximum) => actual <= maximum,
        }
    }
}

pub(crate) struct FileCapability {
    file: File,
    parent: File,
    leaf: OsString,
    identity: NodeIdentity,
    failure: StableCode,
}

impl std::fmt::Debug for FileCapability {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("FileCapability(<verified>)")
    }
}

impl FileCapability {
    pub(crate) fn try_clone_file(&self) -> Result<File, DaemonError> {
        self.recheck()?;
        let duplicate = self
            .file
            .try_clone()
            .map_err(|_| DaemonError::stable(self.failure))?;
        let duplicate_identity = NodeIdentity::from_metadata(
            &duplicate
                .metadata()
                .map_err(|_| DaemonError::stable(self.failure))?,
        );
        if duplicate_identity != self.identity {
            return Err(DaemonError::stable(self.failure));
        }
        Ok(duplicate)
    }

    pub(crate) fn read_bounded(&self, maximum: u64) -> Result<Vec<u8>, DaemonError> {
        self.recheck()?;
        if self.identity.length > maximum {
            return Err(DaemonError::stable(self.failure));
        }
        let length =
            usize::try_from(self.identity.length).map_err(|_| DaemonError::stable(self.failure))?;
        let mut bytes = vec![0_u8; length];
        let mut offset = 0_usize;
        while offset < bytes.len() {
            let file_offset =
                u64::try_from(offset).map_err(|_| DaemonError::stable(self.failure))?;
            let read = self
                .file
                .read_at(&mut bytes[offset..], file_offset)
                .map_err(|_| DaemonError::stable(self.failure))?;
            if read == 0 {
                return Err(DaemonError::stable(self.failure));
            }
            offset = offset
                .checked_add(read)
                .ok_or_else(|| DaemonError::stable(self.failure))?;
        }
        self.recheck()?;
        Ok(bytes)
    }

    pub(crate) fn read_exact_into(&self, output: &mut [u8]) -> Result<(), DaemonError> {
        self.recheck()?;
        if self.identity.length
            != u64::try_from(output.len()).map_err(|_| DaemonError::stable(self.failure))?
        {
            return Err(DaemonError::stable(self.failure));
        }
        let mut offset = 0_usize;
        while offset < output.len() {
            let file_offset =
                u64::try_from(offset).map_err(|_| DaemonError::stable(self.failure))?;
            let read = self
                .file
                .read_at(&mut output[offset..], file_offset)
                .map_err(|_| DaemonError::stable(self.failure))?;
            if read == 0 {
                return Err(DaemonError::stable(self.failure));
            }
            offset = offset
                .checked_add(read)
                .ok_or_else(|| DaemonError::stable(self.failure))?;
        }
        self.recheck()
    }

    pub(crate) fn recheck(&self) -> Result<(), DaemonError> {
        let descriptor = NodeIdentity::from_metadata(
            &self
                .file
                .metadata()
                .map_err(|_| DaemonError::stable(self.failure))?,
        );
        let pathname = stat_identity(&self.parent, &self.leaf, self.failure)?;
        if descriptor != self.identity || pathname != self.identity {
            return Err(DaemonError::stable(self.failure));
        }
        Ok(())
    }
}

fn stat_identity(
    parent: &File,
    leaf: &OsStr,
    failure: StableCode,
) -> Result<NodeIdentity, DaemonError> {
    let stat = statat(parent, leaf, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| DaemonError::stable(failure))?;
    NodeIdentity::from_stat(&stat, failure)
}

fn ensure_normal_leaf(leaf: &OsStr, failure: StableCode) -> Result<(), DaemonError> {
    let mut components = Path::new(leaf).components();
    if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
        return Err(DaemonError::stable(failure));
    }
    Ok(())
}
