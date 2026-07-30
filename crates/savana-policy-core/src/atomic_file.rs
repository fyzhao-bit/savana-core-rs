use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use rustix::fs::{fchmod, openat, renameat, statat, unlinkat, AtFlags, FileType, Mode, OFlags};

use crate::PolicyError;

const TEMP_ATTEMPTS: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AtomicReplaceBoundary {
    FileFlushed,
    RenamedBeforeDirectoryFlush,
    DirectoryFlushed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PersistencePhase {
    BeforeRename,
    AfterRename,
}

#[derive(Debug)]
pub(crate) struct ReplaceError {
    error: PolicyError,
    phase: PersistencePhase,
}

impl ReplaceError {
    pub(crate) fn before_rename(error: PolicyError) -> Self {
        Self {
            error,
            phase: PersistencePhase::BeforeRename,
        }
    }

    pub(crate) fn after_rename(error: PolicyError) -> Self {
        Self {
            error,
            phase: PersistencePhase::AfterRename,
        }
    }

    pub(crate) const fn phase(&self) -> PersistencePhase {
        self.phase
    }

    pub(crate) const fn into_policy_error(self) -> PolicyError {
        self.error
    }
}

pub(crate) fn replace(path: &Path, bytes: &[u8]) -> Result<(), ReplaceError> {
    replace_with_parent_sync(path, bytes, sync_directory)
}

pub(crate) fn replace_at<F>(
    parent: &File,
    final_leaf: &std::ffi::OsStr,
    bytes: &[u8],
    owner_uid: u32,
    owner_gid: u32,
    pre_rename: F,
) -> Result<(), ReplaceError>
where
    F: FnOnce() -> Result<(), PolicyError>,
{
    replace_at_observed(
        parent,
        final_leaf,
        bytes,
        owner_uid,
        owner_gid,
        pre_rename,
        |_| Ok(()),
    )
}

pub(crate) fn replace_at_observed<F, O>(
    parent: &File,
    final_leaf: &std::ffi::OsStr,
    bytes: &[u8],
    owner_uid: u32,
    owner_gid: u32,
    pre_rename: F,
    mut observe: O,
) -> Result<(), ReplaceError>
where
    F: FnOnce() -> Result<(), PolicyError>,
    O: FnMut(AtomicReplaceBoundary) -> Result<(), PolicyError>,
{
    let (temporary_leaf, mut temporary) =
        create_temporary_at(parent, final_leaf, owner_uid, owner_gid)
            .map_err(ReplaceError::before_rename)?;
    let before_rename = (|| {
        temporary.write_all(bytes).map_err(PolicyError::io)?;
        temporary.sync_all().map_err(PolicyError::io)?;
        observe(AtomicReplaceBoundary::FileFlushed)?;
        validate_at(
            parent,
            &temporary_leaf,
            &temporary,
            owner_uid,
            owner_gid,
            u64::try_from(bytes.len()).map_err(PolicyError::io)?,
        )?;
        pre_rename()?;
        Ok(())
    })();
    if let Err(error) = before_rename {
        let _ = unlinkat(parent, &temporary_leaf, AtFlags::empty());
        return Err(ReplaceError::before_rename(error));
    }

    if let Err(error) = renameat(parent, &temporary_leaf, parent, final_leaf) {
        let _ = unlinkat(parent, &temporary_leaf, AtFlags::empty());
        return Err(ReplaceError::before_rename(PolicyError::io(error)));
    }
    observe(AtomicReplaceBoundary::RenamedBeforeDirectoryFlush)
        .map_err(ReplaceError::after_rename)?;
    validate_at(
        parent,
        final_leaf,
        &temporary,
        owner_uid,
        owner_gid,
        u64::try_from(bytes.len())
            .map_err(|error| ReplaceError::after_rename(PolicyError::io(error)))?,
    )
    .map_err(ReplaceError::after_rename)?;
    parent
        .sync_all()
        .map_err(PolicyError::io)
        .map_err(ReplaceError::after_rename)?;
    observe(AtomicReplaceBoundary::DirectoryFlushed).map_err(ReplaceError::after_rename)
}

pub(crate) fn replace_with_parent_sync<F>(
    path: &Path,
    bytes: &[u8],
    sync_parent: F,
) -> Result<(), ReplaceError>
where
    F: FnOnce(&Path) -> Result<(), PolicyError>,
{
    let parent = normalized_parent(path).map_err(ReplaceError::before_rename)?;
    let file_name = path
        .file_name()
        .ok_or_else(|| ReplaceError::before_rename(PolicyError::io("missing name")))?;
    let (temporary_path, mut temporary) =
        create_temporary(parent, file_name).map_err(ReplaceError::before_rename)?;

    if let Err(error) = temporary.write_all(bytes).map_err(PolicyError::io) {
        let _cleanup_result = fs::remove_file(&temporary_path);
        return Err(ReplaceError::before_rename(error));
    }
    if let Err(error) = temporary.sync_all().map_err(PolicyError::io) {
        let _cleanup_result = fs::remove_file(&temporary_path);
        return Err(ReplaceError::before_rename(error));
    }
    if let Err(error) = fs::rename(&temporary_path, path).map_err(PolicyError::io) {
        let _cleanup_result = fs::remove_file(&temporary_path);
        return Err(ReplaceError::before_rename(error));
    }
    sync_parent(parent).map_err(ReplaceError::after_rename)
}

fn create_temporary(
    parent: &Path,
    file_name: &std::ffi::OsStr,
) -> Result<(PathBuf, File), PolicyError> {
    for _ in 0..TEMP_ATTEMPTS {
        let mut random = [0_u8; 16];
        getrandom::getrandom(&mut random).map_err(PolicyError::io)?;
        let mut temporary_name = OsString::from(".");
        temporary_name.push(file_name);
        temporary_name.push(".tmp-");
        temporary_name.push(hex(&random));
        let temporary_path = parent.join(temporary_name);
        let opened = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary_path);
        match opened {
            Ok(file) => {
                if let Err(error) = file.set_permissions(fs::Permissions::from_mode(0o600)) {
                    let _cleanup_result = fs::remove_file(&temporary_path);
                    return Err(PolicyError::io(error));
                }
                return Ok((temporary_path, file));
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(PolicyError::io(error)),
        }
    }
    Err(PolicyError::io("temporary name collisions"))
}

fn create_temporary_at(
    parent: &File,
    final_leaf: &std::ffi::OsStr,
    owner_uid: u32,
    owner_gid: u32,
) -> Result<(OsString, File), PolicyError> {
    for _ in 0..TEMP_ATTEMPTS {
        let mut random = [0_u8; 16];
        getrandom::getrandom(&mut random).map_err(PolicyError::io)?;
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
                fchmod(&file, Mode::from_bits_truncate(0o600)).map_err(PolicyError::io)?;
                validate_at(parent, &temporary_leaf, &file, owner_uid, owner_gid, 0)?;
                return Ok((temporary_leaf, file));
            }
            Err(rustix::io::Errno::EXIST) => {}
            Err(error) => return Err(PolicyError::io(error)),
        }
    }
    Err(PolicyError::io("temporary name collisions"))
}

fn validate_at(
    parent: &File,
    leaf: &std::ffi::OsStr,
    file: &File,
    owner_uid: u32,
    owner_gid: u32,
    expected_length: u64,
) -> Result<(), PolicyError> {
    let opened = file.metadata().map_err(PolicyError::io)?;
    let linked = statat(parent, leaf, AtFlags::SYMLINK_NOFOLLOW).map_err(PolicyError::io)?;
    if !opened.is_file()
        || opened.uid() != owner_uid
        || opened.gid() != owner_gid
        || opened.mode() & 0o7777 != 0o600
        || opened.nlink() != 1
        || opened.len() != expected_length
        || FileType::from_raw_mode(linked.st_mode) != FileType::RegularFile
        || i128::from(linked.st_dev) != i128::from(opened.dev())
        || checked_u64(linked.st_ino)? != opened.ino()
        || checked_u32(linked.st_uid)? != owner_uid
        || checked_u32(linked.st_gid)? != owner_gid
        || checked_u32(linked.st_mode)? & 0o7777 != 0o600
        || checked_u64(linked.st_nlink)? != 1
        || checked_u64(linked.st_size)? != expected_length
    {
        return Err(PolicyError::io("atomic file identity mismatch"));
    }
    Ok(())
}

fn checked_u64<T: TryInto<u64>>(value: T) -> Result<u64, PolicyError> {
    value.try_into().map_err(PolicyError::io)
}

fn checked_u32<T: TryInto<u32>>(value: T) -> Result<u32, PolicyError> {
    value.try_into().map_err(PolicyError::io)
}

pub(crate) fn normalized_parent(path: &Path) -> Result<&Path, PolicyError> {
    let parent = path
        .parent()
        .ok_or_else(|| PolicyError::io("missing parent"))?;
    if parent.as_os_str().is_empty() {
        Ok(Path::new("."))
    } else {
        Ok(parent)
    }
}

pub(crate) fn sync_directory(path: &Path) -> Result<(), PolicyError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(PolicyError::io)
}

fn hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(hex_digit(byte >> 4));
        encoded.push(hex_digit(byte & 0x0f));
    }
    encoded
}

fn hex_digit(nibble: u8) -> char {
    match nibble {
        0..=9 => char::from(b'0' + nibble),
        10..=15 => char::from(b'a' + (nibble - 10)),
        _ => '?',
    }
}
