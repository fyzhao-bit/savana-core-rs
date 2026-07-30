use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use nix::fcntl::{Flock, FlockArg};
use nix::libc::{O_CLOEXEC, O_NOFOLLOW, O_NONBLOCK};
use rustix::fs::{
    fchmod, openat, statat, AtFlags as RustixAtFlags, FileType, Mode as RustixMode, OFlags,
};
use rustix::io::Errno;
use savana_kernel_protocol::StableCode;

use crate::atomic_file;
use crate::PolicyError;

#[derive(Debug)]
pub(crate) struct LedgerLock {
    _file: Flock<File>,
    anchored: Option<AnchoredLock>,
}

#[derive(Debug)]
struct AnchoredLock {
    parent: File,
    leaf: OsString,
    owner_uid: u32,
    owner_gid: u32,
}

impl LedgerLock {
    pub(crate) fn acquire(ledger_path: &Path) -> Result<Self, PolicyError> {
        let lock_path = lock_path(ledger_path)?;
        let (file, created) = open_lock_file(&lock_path)?;
        if created {
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(PolicyError::io)?;
        }
        validate_opened_file(&lock_path, &file)?;

        let locked = Flock::lock(file, FlockArg::LockExclusiveNonblock)
            .map_err(|(_file, error)| PolicyError::io(error))?;
        validate_opened_file(&lock_path, &locked)?;

        if created {
            locked.sync_all().map_err(PolicyError::io)?;
            atomic_file::sync_directory(atomic_file::normalized_parent(&lock_path)?)?;
        }

        Ok(Self {
            _file: locked,
            anchored: None,
        })
    }

    pub(crate) fn acquire_at(
        parent: &File,
        leaf: &std::ffi::OsStr,
        owner_uid: u32,
        owner_gid: u32,
    ) -> Result<Self, PolicyError> {
        let create_flags = OFlags::RDWR
            | OFlags::CREATE
            | OFlags::EXCL
            | OFlags::NOFOLLOW
            | OFlags::NONBLOCK
            | OFlags::CLOEXEC;
        let (file, created) = match openat(
            parent,
            leaf,
            create_flags,
            RustixMode::from_bits_truncate(0o600),
        ) {
            Ok(descriptor) => (File::from(descriptor), true),
            Err(Errno::EXIST) => {
                let descriptor = openat(
                    parent,
                    leaf,
                    OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                    RustixMode::empty(),
                )
                .map_err(PolicyError::io)?;
                (File::from(descriptor), false)
            }
            Err(error) => return Err(PolicyError::io(error)),
        };
        if created {
            fchmod(&file, RustixMode::from_bits_truncate(0o600)).map_err(PolicyError::io)?;
        }
        validate_opened_at(parent, leaf, &file, owner_uid, owner_gid)?;
        let locked = Flock::lock(file, FlockArg::LockExclusiveNonblock)
            .map_err(|(_file, error)| PolicyError::io(error))?;
        validate_opened_at(parent, leaf, &locked, owner_uid, owner_gid)?;
        if created {
            locked.sync_all().map_err(PolicyError::io)?;
            parent.sync_all().map_err(PolicyError::io)?;
        }
        let anchored = AnchoredLock {
            parent: parent.try_clone().map_err(PolicyError::io)?,
            leaf: leaf.to_os_string(),
            owner_uid,
            owner_gid,
        };
        Ok(Self {
            _file: locked,
            anchored: Some(anchored),
        })
    }

    pub(crate) fn recheck(&self) -> Result<(), PolicyError> {
        if let Some(anchor) = &self.anchored {
            validate_opened_at(
                &anchor.parent,
                &anchor.leaf,
                &self._file,
                anchor.owner_uid,
                anchor.owner_gid,
            )?;
        }
        Ok(())
    }

    pub(crate) fn matches_file(&self, expected: &File) -> Result<bool, PolicyError> {
        let locked = self._file.metadata().map_err(PolicyError::io)?;
        let expected = expected.metadata().map_err(PolicyError::io)?;
        Ok(locked.dev() == expected.dev() && locked.ino() == expected.ino())
    }
}

fn validate_opened_at(
    parent: &File,
    leaf: &std::ffi::OsStr,
    file: &File,
    owner_uid: u32,
    owner_gid: u32,
) -> Result<(), PolicyError> {
    let opened = file.metadata().map_err(PolicyError::io)?;
    if !opened.is_file()
        || opened.uid() != owner_uid
        || opened.gid() != owner_gid
        || opened.mode() & 0o7777 != 0o600
        || opened.nlink() != 1
    {
        return Err(PolicyError::stable(StableCode::ProtocolIo));
    }
    let linked = statat(parent, leaf, RustixAtFlags::SYMLINK_NOFOLLOW).map_err(PolicyError::io)?;
    if FileType::from_raw_mode(linked.st_mode) != FileType::RegularFile
        || i128::from(linked.st_dev) != i128::from(opened.dev())
        || checked_u64(linked.st_ino)? != opened.ino()
        || checked_u32(linked.st_uid)? != owner_uid
        || checked_u32(linked.st_gid)? != owner_gid
        || checked_u32(linked.st_mode)? & 0o7777 != 0o600
        || checked_u64(linked.st_nlink)? != 1
    {
        return Err(PolicyError::stable(StableCode::ProtocolIo));
    }
    Ok(())
}

fn checked_u64<T: TryInto<u64>>(value: T) -> Result<u64, PolicyError> {
    value.try_into().map_err(PolicyError::io)
}

fn checked_u32<T: TryInto<u32>>(value: T) -> Result<u32, PolicyError> {
    value.try_into().map_err(PolicyError::io)
}

fn lock_path(ledger_path: &Path) -> Result<PathBuf, PolicyError> {
    let parent = atomic_file::normalized_parent(ledger_path)?;
    let ledger_name = ledger_path
        .file_name()
        .ok_or_else(|| PolicyError::io("missing ledger name"))?;
    let mut lock_name = OsString::from(".");
    lock_name.push(ledger_name);
    lock_name.push(".lock");
    Ok(parent.join(lock_name))
}

fn open_lock_file(path: &Path) -> Result<(File, bool), PolicyError> {
    match lock_options(true).open(path) {
        Ok(file) => Ok((file, true)),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => lock_options(false)
            .open(path)
            .map(|file| (file, false))
            .map_err(PolicyError::io),
        Err(error) => Err(PolicyError::io(error)),
    }
}

fn lock_options(create_new: bool) -> OpenOptions {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if create_new {
        options.create_new(true);
    }
    options
}

fn validate_opened_file(path: &Path, file: &File) -> Result<(), PolicyError> {
    let opened = file.metadata().map_err(PolicyError::io)?;
    if !opened.file_type().is_file() || opened.mode() & 0o7777 != 0o600 {
        return Err(PolicyError::stable(StableCode::ProtocolIo));
    }

    let linked = fs::symlink_metadata(path).map_err(PolicyError::io)?;
    if linked.file_type().is_symlink()
        || !linked.file_type().is_file()
        || linked.dev() != opened.dev()
        || linked.ino() != opened.ino()
        || linked.mode() & 0o7777 != 0o600
    {
        return Err(PolicyError::stable(StableCode::ProtocolIo));
    }
    Ok(())
}
