use std::ffi::OsString;
use std::fs::File;
use std::io::Write;
use std::os::unix::fs::MetadataExt;

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

/// Which side of the rename a failed replacement stopped on: callers only need
/// to know whether the new bytes may already be visible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReplaceError {
    phase: PersistencePhase,
}

impl ReplaceError {
    pub(crate) const fn before_rename() -> Self {
        Self {
            phase: PersistencePhase::BeforeRename,
        }
    }

    pub(crate) const fn after_rename() -> Self {
        Self {
            phase: PersistencePhase::AfterRename,
        }
    }

    pub(crate) const fn phase(&self) -> PersistencePhase {
        self.phase
    }
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
            .map_err(|_| ReplaceError::before_rename())?;
    let before_rename = (|| -> Result<(), PolicyError> {
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
    if before_rename.is_err() {
        let _ = unlinkat(parent, &temporary_leaf, AtFlags::empty());
        return Err(ReplaceError::before_rename());
    }

    if renameat(parent, &temporary_leaf, parent, final_leaf).is_err() {
        let _ = unlinkat(parent, &temporary_leaf, AtFlags::empty());
        return Err(ReplaceError::before_rename());
    }
    observe(AtomicReplaceBoundary::RenamedBeforeDirectoryFlush)
        .map_err(|_| ReplaceError::after_rename())?;
    validate_at(
        parent,
        final_leaf,
        &temporary,
        owner_uid,
        owner_gid,
        u64::try_from(bytes.len()).map_err(|_| ReplaceError::after_rename())?,
    )
    .map_err(|_| ReplaceError::after_rename())?;
    parent
        .sync_all()
        .map_err(|_| ReplaceError::after_rename())?;
    observe(AtomicReplaceBoundary::DirectoryFlushed).map_err(|_| ReplaceError::after_rename())
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
