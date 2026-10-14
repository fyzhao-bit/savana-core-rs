//! Fixed root-owned state directory, descriptor-relative no-follow IO, durable
//! prepare, and an exclusive lifetime lock. No application-provided path.
use crate::tpm_nv::Journal;
use crate::TpmSignatureErrorV3 as Error;
use rustix::fs::{flock, open, openat, renameat, FlockOperation, Mode, OFlags};
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;

pub(crate) struct DiskJournal {
    directory: File,
    _lock: File,
    prefix: String,
}
pub(crate) fn root_dir(path: &str) -> Result<File, Error> {
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW;
    let mut directory =
        File::from(open("/", flags, Mode::empty()).map_err(|_| Error::Unavailable)?);
    for part in path.split('/').filter(|p| !p.is_empty()) {
        if part == "." || part == ".." {
            return Err(Error::Malformed);
        }
        directory = File::from(
            openat(&directory, part, flags, Mode::empty()).map_err(|_| Error::Unavailable)?,
        );
        let meta = directory.metadata().map_err(|_| Error::Unavailable)?;
        if meta.uid() != 0 || meta.gid() != 0 || meta.mode() & 0o022 != 0 {
            return Err(Error::Unavailable);
        }
    }
    Ok(directory)
}
pub(crate) fn check_file(file: &File, max: u64) -> Result<(), Error> {
    let meta = file.metadata().map_err(|_| Error::Unavailable)?;
    if !meta.is_file()
        || meta.uid() != 0
        || meta.gid() != 0
        || meta.nlink() != 1
        || !matches!(meta.mode() & 0o7777, 0o400 | 0o600)
        || meta.len() > max
    {
        return Err(Error::Unavailable);
    }
    Ok(())
}
impl DiskJournal {
    pub(crate) fn open(index: u32) -> Result<Self, Error> {
        let directory = root_dir("/var/lib/savana/tpm-v3")?;
        let prefix = format!("nv-{index:08x}");
        let lock = File::from(
            openat(
                &directory,
                format!("{prefix}.lock"),
                OFlags::RDWR | OFlags::CREATE | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::RUSR | Mode::WUSR,
            )
            .map_err(|_| Error::Unavailable)?,
        );
        check_file(&lock, 0)?;
        flock(&lock, FlockOperation::NonBlockingLockExclusive).map_err(|_| Error::Unavailable)?;
        Ok(Self {
            directory,
            _lock: lock,
            prefix,
        })
    }
}
impl Journal for DiskJournal {
    fn load(&self, slot: usize) -> Result<Option<Vec<u8>>, Error> {
        if slot > 1 {
            return Err(Error::Malformed);
        }
        let file = match openat(
            &self.directory,
            format!("{}.{}.head", self.prefix, slot),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => File::from(fd),
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(_) => return Err(Error::Unavailable),
        };
        check_file(&file, 108)?;
        let mut bytes = Vec::new();
        file.take(109)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::Unavailable)?;
        Ok(Some(bytes))
    }
    fn store(&mut self, slot: usize, bytes: &[u8]) -> Result<(), Error> {
        if slot > 1 || bytes.len() != 108 {
            return Err(Error::Malformed);
        }
        // Stale temp is not authority. It is opened without truncate, checked,
        // then replaced under the lifetime lock. No untrusted hardlinks followed.
        let temporary = format!("{}.prepare", self.prefix);
        let mut file = File::from(
            openat(
                &self.directory,
                &temporary,
                OFlags::WRONLY | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            )
            .map_err(|_| Error::Unavailable)?,
        );
        check_file(&file, 108)?;
        file.set_len(0).map_err(|_| Error::Unavailable)?;
        file.write_all(bytes).map_err(|_| Error::Unavailable)?;
        file.sync_all().map_err(|_| Error::Unavailable)?;
        renameat(
            &self.directory,
            &temporary,
            &self.directory,
            format!("{}.{}.head", self.prefix, slot),
        )
        .map_err(|_| Error::Unavailable)?;
        self.directory.sync_all().map_err(|_| Error::Unavailable)
    }
}
