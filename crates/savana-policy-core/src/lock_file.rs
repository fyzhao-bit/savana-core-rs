use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use nix::fcntl::{Flock, FlockArg};
use nix::libc::{O_CLOEXEC, O_NOFOLLOW, O_NONBLOCK};
use savana_kernel_protocol::StableCode;

use crate::atomic_file;
use crate::PolicyError;

#[derive(Debug)]
pub(crate) struct LedgerLock {
    _file: Flock<File>,
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

        Ok(Self { _file: locked })
    }
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
