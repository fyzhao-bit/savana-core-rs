use std::cell::RefCell;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Component, Path, PathBuf};

use rustix::fs::{
    fchmod, open, openat, renameat, renameat_with, statat, AtFlags, Dir, FileType, Mode, OFlags,
    RenameFlags, Stat,
};
use rustix::io::Errno;

const TEMPORARY_NAME_ATTEMPTS: usize = 16;
const TEMPORARY_MODE: u32 = 0o600;
const VECTOR_MODE: u32 = 0o644;

#[derive(Clone, Copy, PartialEq, Eq)]
struct DirectoryIdentity {
    device: i128,
    inode: u64,
}

impl DirectoryIdentity {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: i128::from(metadata.dev()),
            inode: metadata.ino(),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    device: i128,
    inode: u64,
    owner_uid: u32,
    owner_gid: u32,
    mode: u32,
    links: u64,
    length: u64,
}

impl FileIdentity {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: i128::from(metadata.dev()),
            inode: metadata.ino(),
            owner_uid: metadata.uid(),
            owner_gid: metadata.gid(),
            mode: metadata.mode(),
            links: metadata.nlink(),
            length: metadata.len(),
        }
    }

    fn from_stat(stat: &Stat) -> io::Result<Self> {
        Ok(Self {
            device: i128::from(stat.st_dev),
            inode: checked_u64(stat.st_ino)?,
            owner_uid: checked_u32(stat.st_uid)?,
            owner_gid: checked_u32(stat.st_gid)?,
            mode: checked_u32(stat.st_mode)?,
            links: checked_u64(stat.st_nlink)?,
            length: checked_u64(stat.st_size)?,
        })
    }

    const fn permissions(self) -> u32 {
        self.mode & 0o7777
    }
}

pub(crate) struct OutputDirectory {
    directory: File,
    requested_path: PathBuf,
    identity: DirectoryIdentity,
    installed: RefCell<Vec<InstalledEntry>>,
}

impl OutputDirectory {
    pub(crate) fn prepare(
        requested_path: &Path,
        overwrite: bool,
        known_files: &[&str],
    ) -> io::Result<Self> {
        let requested_path = absolute_path(requested_path)?;
        match fs::symlink_metadata(&requested_path) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(invalid("output must be a real directory"));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(invalid("output directory must already exist"));
            }
            Err(error) => return Err(error),
        }
        let before = fs::symlink_metadata(&requested_path)?;
        if before.file_type().is_symlink() || !before.is_dir() {
            return Err(invalid("output must be a real directory"));
        }

        let descriptor = open(
            &requested_path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(io::Error::from)?;
        let directory = File::from(descriptor);
        let metadata = directory.metadata()?;
        if !metadata.is_dir() {
            return Err(invalid("output must be a real directory"));
        }
        let identity = DirectoryIdentity::from_metadata(&metadata);
        if DirectoryIdentity::from_metadata(&before) != identity {
            return Err(invalid("output directory identity changed"));
        }
        let output = Self {
            directory,
            requested_path,
            identity,
            installed: RefCell::new(Vec::new()),
        };
        output.recheck_path()?;
        output.validate_entries(overwrite, known_files)?;
        output.recheck_path()?;
        Ok(output)
    }

    pub(crate) fn write_vector(&self, name: &str, bytes: &[u8], overwrite: bool) -> io::Result<()> {
        self.write_vector_inner(name, bytes, overwrite, |_, _| Ok(()))
    }

    #[cfg(test)]
    pub(crate) fn write_vector_with_hook<F>(
        &self,
        name: &str,
        bytes: &[u8],
        overwrite: bool,
        before_rename: F,
    ) -> io::Result<()>
    where
        F: FnOnce(&File, &OsStr) -> io::Result<()>,
    {
        self.write_vector_inner(name, bytes, overwrite, before_rename)
    }

    pub(crate) fn finish(&self, known_files: &[&str]) -> io::Result<()> {
        self.recheck_path()?;
        self.validate_entries(true, known_files)?;
        self.validate_installed()?;
        self.directory.sync_all()?;
        self.validate_installed()?;
        self.recheck_path()
    }

    fn write_vector_inner<F>(
        &self,
        name: &str,
        bytes: &[u8],
        overwrite: bool,
        before_rename: F,
    ) -> io::Result<()>
    where
        F: FnOnce(&File, &OsStr) -> io::Result<()>,
    {
        ensure_normal_leaf(name)?;
        self.recheck_path()?;
        validate_target(&self.directory, OsStr::new(name), overwrite)?;

        let mut temporary = TemporaryEntry::create(&self.directory, name)?;
        temporary.file.write_all(bytes)?;
        temporary.file.flush()?;
        fchmod(&temporary.file, Mode::from_bits_truncate(0o644)).map_err(io::Error::from)?;
        temporary.file.sync_all()?;
        validate_linked_file(
            &self.directory,
            &temporary.leaf,
            &temporary.file,
            bytes,
            VECTOR_MODE,
        )?;
        let installed_file = temporary.file.try_clone()?;
        before_rename(&self.directory, &temporary.leaf)?;

        temporary.rename_to(OsStr::new(name), overwrite)?;
        validate_linked_file(
            &self.directory,
            OsStr::new(name),
            &temporary.file,
            bytes,
            VECTOR_MODE,
        )?;
        self.directory.sync_all()?;
        validate_linked_file(
            &self.directory,
            OsStr::new(name),
            &temporary.file,
            bytes,
            VECTOR_MODE,
        )?;
        self.recheck_path()?;
        self.installed.borrow_mut().push(InstalledEntry {
            leaf: OsString::from(name),
            file: installed_file,
            bytes: bytes.to_vec(),
        });
        Ok(())
    }

    fn validate_entries(&self, allow_entries: bool, known_files: &[&str]) -> io::Result<()> {
        let entries = Dir::read_from(&self.directory).map_err(io::Error::from)?;
        let mut saw_entry = false;
        for entry in entries {
            let entry = entry.map_err(io::Error::from)?;
            let name_bytes = entry.file_name().to_bytes();
            if matches!(name_bytes, b"." | b"..") {
                continue;
            }
            saw_entry = true;
            let name =
                std::str::from_utf8(name_bytes).map_err(|_| invalid("non-UTF-8 output entry"))?;
            if !known_files.contains(&name) {
                return Err(invalid("output contains an unknown entry"));
            }
            let leaf = OsStr::from_bytes(name_bytes);
            let stat = statat(&self.directory, leaf, AtFlags::SYMLINK_NOFOLLOW)
                .map_err(io::Error::from)?;
            if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
                return Err(invalid("output entry is not a regular file"));
            }
        }
        if saw_entry && !allow_entries {
            return Err(invalid(
                "output directory must be empty without --overwrite",
            ));
        }
        Ok(())
    }

    fn recheck_path(&self) -> io::Result<()> {
        let opened = self.directory.metadata()?;
        let linked = fs::symlink_metadata(&self.requested_path)?;
        if !opened.is_dir()
            || linked.file_type().is_symlink()
            || !linked.is_dir()
            || DirectoryIdentity::from_metadata(&opened) != self.identity
            || DirectoryIdentity::from_metadata(&linked) != self.identity
        {
            return Err(invalid("output directory identity changed"));
        }
        Ok(())
    }

    fn validate_installed(&self) -> io::Result<()> {
        for installed in self.installed.borrow().iter() {
            validate_linked_file(
                &self.directory,
                &installed.leaf,
                &installed.file,
                &installed.bytes,
                VECTOR_MODE,
            )?;
        }
        Ok(())
    }
}

struct InstalledEntry {
    leaf: OsString,
    file: File,
    bytes: Vec<u8>,
}

struct TemporaryEntry<'directory> {
    directory: &'directory File,
    leaf: OsString,
    file: File,
}

impl<'directory> TemporaryEntry<'directory> {
    fn create(directory: &'directory File, final_name: &str) -> io::Result<Self> {
        for _ in 0..TEMPORARY_NAME_ATTEMPTS {
            let mut random = [0_u8; 16];
            getrandom::getrandom(&mut random)
                .map_err(|_| io::Error::other("secure temporary name generation failed"))?;
            let mut leaf = OsString::from(".");
            leaf.push(final_name);
            leaf.push(".tmp-");
            leaf.push(hex(&random));
            match openat(
                directory,
                &leaf,
                OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_bits_truncate(0o600),
            ) {
                Ok(descriptor) => {
                    let file = File::from(descriptor);
                    let temporary = Self {
                        directory,
                        leaf,
                        file,
                    };
                    fchmod(&temporary.file, Mode::from_bits_truncate(0o600))
                        .map_err(io::Error::from)?;
                    validate_linked_file(
                        directory,
                        &temporary.leaf,
                        &temporary.file,
                        &[],
                        TEMPORARY_MODE,
                    )?;
                    return Ok(temporary);
                }
                Err(Errno::EXIST) => {}
                Err(error) => return Err(io::Error::from(error)),
            }
        }
        Err(invalid("secure temporary name collisions"))
    }

    fn rename_to(&mut self, final_leaf: &OsStr, overwrite: bool) -> io::Result<()> {
        let result = if overwrite {
            renameat(self.directory, &self.leaf, self.directory, final_leaf)
        } else {
            renameat_with(
                self.directory,
                &self.leaf,
                self.directory,
                final_leaf,
                RenameFlags::NOREPLACE,
            )
        };
        result.map_err(io::Error::from)?;
        Ok(())
    }
}

fn validate_target(directory: &File, leaf: &OsStr, overwrite: bool) -> io::Result<()> {
    match statat(directory, leaf, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile => {
            Err(invalid("vector target is not a regular file"))
        }
        Ok(_) if !overwrite => Err(invalid("vector exists; pass --overwrite")),
        Ok(_) | Err(Errno::NOENT) => Ok(()),
        Err(error) => Err(io::Error::from(error)),
    }
}

fn validate_linked_file(
    directory: &File,
    leaf: &OsStr,
    opened: &File,
    expected_bytes: &[u8],
    expected_mode: u32,
) -> io::Result<()> {
    let metadata = opened.metadata()?;
    let opened_identity = FileIdentity::from_metadata(&metadata);
    let linked = statat(directory, leaf, AtFlags::SYMLINK_NOFOLLOW).map_err(io::Error::from)?;
    let linked_identity = FileIdentity::from_stat(&linked)?;
    if !metadata.is_file()
        || FileType::from_raw_mode(linked.st_mode) != FileType::RegularFile
        || opened_identity != linked_identity
        || opened_identity.permissions() != expected_mode
        || opened_identity.links != 1
        || opened_identity.length
            != u64::try_from(expected_bytes.len())
                .map_err(|_| invalid("vector length does not fit u64"))?
    {
        return Err(invalid("vector file identity mismatch"));
    }
    validate_contents(opened, expected_bytes)
}

fn validate_contents(file: &File, expected: &[u8]) -> io::Result<()> {
    let mut observed = vec![0_u8; expected.len()];
    let mut offset = 0;
    while offset < observed.len() {
        let read = file.read_at(
            &mut observed[offset..],
            u64::try_from(offset).map_err(|_| invalid("vector offset does not fit u64"))?,
        )?;
        if read == 0 {
            return Err(invalid("vector file was truncated"));
        }
        offset += read;
    }
    if observed != expected {
        return Err(invalid("vector file contents changed"));
    }
    Ok(())
}

fn absolute_path(path: &Path) -> io::Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::RootDir => normalized.push(Path::new("/")),
            Component::Normal(value) => normalized.push(value),
            Component::CurDir => {}
            Component::ParentDir | Component::Prefix(_) => {
                return Err(invalid("output path must not contain parent components"));
            }
        }
    }
    Ok(normalized)
}

fn ensure_normal_leaf(name: &str) -> io::Result<()> {
    let mut components = Path::new(name).components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(component)), None) if component == OsStr::new(name) => Ok(()),
        _ => Err(invalid(
            "vector name must be a single normal path component",
        )),
    }
}

fn checked_u64<T: TryInto<u64>>(value: T) -> io::Result<u64> {
    value
        .try_into()
        .map_err(|_| invalid("filesystem value does not fit u64"))
}

fn checked_u32<T: TryInto<u32>>(value: T) -> io::Result<u32> {
    value
        .try_into()
        .map_err(|_| invalid("filesystem value does not fit u32"))
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
        10..=15 => char::from(b'a' + nibble - 10),
        _ => unreachable!("nibble is four bits"),
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
