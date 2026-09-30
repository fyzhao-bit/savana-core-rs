//! Fixed-path V3 evidence journal for the measured root deployer only.
//! Not a V2 store importer, installer transaction driver, or kernel boot permit.
use crate::deployment_record_v3::{
    runtime::{Authority, Journal, Storage},
    MAX_RECORD,
};
use crate::linux_tpm_journal::{check_file, root_dir};
use crate::{
    DeploymentJournalSnapshotV3, DeploymentRecordScopeV3, LinuxTpmAuthorityClientV3,
    TpmEnrollmentV3, TpmSignatureEnvelopeV3, TpmSignatureErrorV3 as Error, TpmSignatureRequestV3,
    TpmStateHeadV3, TpmStoreV3, VerifiedDeploymentRecordEnvelopeV3,
};
use rustix::fs::{
    flock, openat, renameat, renameat_with, FlockOperation, Mode, OFlags, RenameFlags,
};
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::time::{SystemTime, UNIX_EPOCH};

const DIRECTORY: &str = "/var/lib/savana/deployment-v3";
const SLOTS: [&str; 2] = ["record-a.v3", "record-b.v3"];
const LOCK: &str = ".journal.lock";
impl Authority for LinuxTpmAuthorityClientV3 {
    fn enrollment(&self) -> &TpmEnrollmentV3 {
        self.enrollment()
    }
    fn head(&mut self) -> Result<TpmStateHeadV3, Error> {
        self.current_head(TpmStoreV3::Deployment)
    }
    fn sign(&mut self, request: TpmSignatureRequestV3) -> Result<TpmSignatureEnvelopeV3, Error> {
        self.sign(request)
    }
    fn advance(&mut self, expected: TpmStateHeadV3, next: TpmStateHeadV3) -> Result<(), Error> {
        self.compare_and_advance(TpmStoreV3::Deployment, expected, next)
    }
}
fn now() -> Result<u64, Error> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| Error::Unavailable)
}
struct Disk {
    directory: File,
    lock: File,
}
impl Disk {
    fn open() -> Result<Self, Error> {
        if !nix::unistd::geteuid().is_root() || nix::unistd::getegid().as_raw() != 0 {
            return Err(Error::Unavailable);
        }
        // V3 is not an implicit reset/import of an existing V2 deployment.
        match std::fs::symlink_metadata("/var/lib/savana/deployment") {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            _ => return Err(Error::BindingMismatch),
        }
        let directory = root_dir(DIRECTORY)?;
        if directory.metadata().map_err(|_| Error::Unavailable)?.mode() & 0o7777 != 0o700 {
            return Err(Error::Unavailable);
        }
        let lock = File::from(
            openat(
                &directory,
                LOCK,
                OFlags::RDWR
                    | OFlags::CREATE
                    | OFlags::CLOEXEC
                    | OFlags::NOFOLLOW
                    | OFlags::NONBLOCK,
                Mode::RUSR | Mode::WUSR,
            )
            .map_err(|_| Error::Unavailable)?,
        );
        check_file(&lock, 0)?;
        flock(&lock, FlockOperation::NonBlockingLockExclusive).map_err(|_| Error::Unavailable)?;
        let value = Self { directory, lock };
        value.recheck()?;
        Ok(value)
    }
    fn recheck(&self) -> Result<(), Error> {
        let path = root_dir(DIRECTORY)?;
        let pinned = self.directory.metadata().map_err(|_| Error::Unavailable)?;
        let current = path.metadata().map_err(|_| Error::Unavailable)?;
        if (pinned.dev(), pinned.ino()) != (current.dev(), current.ino())
            || current.mode() & 0o7777 != 0o700
        {
            return Err(Error::Unavailable);
        }
        let lock = File::from(
            openat(
                &path,
                LOCK,
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
                Mode::empty(),
            )
            .map_err(|_| Error::Unavailable)?,
        );
        check_file(&lock, 0)?;
        let current = lock.metadata().map_err(|_| Error::Unavailable)?;
        let pinned = self.lock.metadata().map_err(|_| Error::Unavailable)?;
        if (pinned.dev(), pinned.ino()) != (current.dev(), current.ino()) {
            return Err(Error::Unavailable);
        }
        Ok(())
    }
}
impl Disk {
    fn read_named(&self, name: &str) -> Result<Option<Vec<u8>>, Error> {
        self.recheck()?;
        let file = match openat(
            &self.directory,
            name,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        ) {
            Ok(f) => File::from(f),
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(_) => return Err(Error::Unavailable),
        };
        check_file(&file, MAX_RECORD as u64)?;
        let mut bytes = Vec::new();
        file.take(MAX_RECORD as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::Unavailable)?;
        if bytes.is_empty() || bytes.len() > MAX_RECORD {
            return Err(Error::Malformed);
        }
        self.recheck()?;
        Ok(Some(bytes))
    }
    fn write_named(&mut self, name: &str, bytes: &[u8], immutable: bool) -> Result<(), Error> {
        if bytes.is_empty() || bytes.len() > MAX_RECORD {
            return Err(Error::Malformed);
        }
        self.recheck()?;
        // Check even the replaced object: no symlink/hardlink or unsafe file may
        // be silently removed. A stale temporary is never selected as authority.
        let old = self.read_named(name)?;
        if immutable {
            if let Some(old) = old {
                if old != bytes {
                    return Err(Error::BindingMismatch);
                }
                self.directory
                    .sync_all()
                    .map_err(|_| Error::OperationFailed)?;
                return self.recheck();
            }
        }
        let temporary = ".record.prepare";
        let mut file = File::from(
            openat(
                &self.directory,
                temporary,
                OFlags::WRONLY
                    | OFlags::CREATE
                    | OFlags::CLOEXEC
                    | OFlags::NOFOLLOW
                    | OFlags::NONBLOCK,
                Mode::RUSR | Mode::WUSR,
            )
            .map_err(|_| Error::Unavailable)?,
        );
        check_file(&file, MAX_RECORD as u64)?;
        file.set_len(0).map_err(|_| Error::OperationFailed)?;
        file.write_all(bytes).map_err(|_| Error::OperationFailed)?;
        file.sync_all().map_err(|_| Error::OperationFailed)?;
        self.recheck()?;
        if immutable {
            renameat_with(
                &self.directory,
                temporary,
                &self.directory,
                name,
                RenameFlags::NOREPLACE,
            )
            .map_err(|_| Error::OperationFailed)?;
        } else {
            renameat(&self.directory, temporary, &self.directory, name)
                .map_err(|_| Error::OperationFailed)?;
        }
        self.directory
            .sync_all()
            .map_err(|_| Error::OperationFailed)?;
        self.recheck()
    }
}
fn archive_name(head: TpmStateHeadV3) -> Result<String, Error> {
    use std::fmt::Write;
    if head == TpmStateHeadV3::GENESIS {
        return Err(Error::Malformed);
    }
    let mut name = format!("evidence-{:016x}-", head.sequence());
    for b in head.digest() {
        write!(&mut name, "{b:02x}").map_err(|_| Error::Malformed)?;
    }
    name.push_str(".v3");
    Ok(name)
}
impl Storage for Disk {
    fn read(&self, slot: usize) -> Result<Option<Vec<u8>>, Error> {
        self.read_named(SLOTS.get(slot).ok_or(Error::Malformed)?)
    }
    fn write(&mut self, slot: usize, bytes: &[u8]) -> Result<(), Error> {
        self.write_named(SLOTS.get(slot).ok_or(Error::Malformed)?, bytes, false)
    }
    fn read_archive(&self, head: TpmStateHeadV3) -> Result<Option<Vec<u8>>, Error> {
        self.read_named(&archive_name(head)?)
    }
    fn write_archive(&mut self, head: TpmStateHeadV3, bytes: &[u8]) -> Result<(), Error> {
        self.write_named(&archive_name(head)?, bytes, true)
    }
}

/// The only production constructor uses the fixed native authority and fixed
/// protected directory. No transport, signer, path, clock or software fallback
/// can be supplied. Every operation also authenticates the live authority peer.
pub struct LinuxDeploymentJournalV3 {
    inner: Journal<LinuxTpmAuthorityClientV3, Disk>,
}
impl LinuxDeploymentJournalV3 {
    pub fn open_fixed(enrollment: TpmEnrollmentV3) -> Result<Self, Error> {
        let disk = Disk::open()?;
        let authority = LinuxTpmAuthorityClientV3::new(enrollment)?;
        Ok(Self {
            inner: Journal::open(authority, disk, now()?)?,
        })
    }
    pub fn snapshot(&mut self) -> Result<DeploymentJournalSnapshotV3, Error> {
        self.inner.snapshot(now()?)
    }
    /// Return the exact archived chain selected by the live TPM head. Prepared
    /// or orphan files are not included, and no history is synthesized from A/B.
    pub fn history(&mut self) -> Result<Vec<VerifiedDeploymentRecordEnvelopeV3>, Error> {
        self.inner.history(now()?)
    }
    pub fn append(
        &mut self,
        expected: TpmStateHeadV3,
        scope: DeploymentRecordScopeV3,
        canonical_evidence: &[u8],
    ) -> Result<VerifiedDeploymentRecordEnvelopeV3, Error> {
        self.inner
            .append(expected, scope, canonical_evidence, now()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    #[test]
    #[ignore = "requires root in an explicitly marked disposable container with fresh tmpfs"]
    fn disposable_root_disk_contract() {
        assert!(std::path::Path::new("/.dockerenv").is_file());
        assert!(std::path::Path::new("/run/savana-deployment-disk-test-only").is_file());
        assert!(!std::path::Path::new("/dev/tpmrm0").exists());
        assert!(!std::path::Path::new(DIRECTORY).exists());
        assert!(nix::unistd::geteuid().is_root());
        std::fs::create_dir(DIRECTORY).unwrap();
        std::fs::set_permissions(DIRECTORY, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut disk = Disk::open().unwrap();
        assert!(Disk::open().is_err());
        disk.write(1, b"synthetic durable record").unwrap();
        assert_eq!(disk.read(1).unwrap().unwrap(), b"synthetic durable record");
        let record = format!("{DIRECTORY}/{}", SLOTS[1]);
        std::fs::set_permissions(&record, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(disk.read(1).is_err());
        std::fs::set_permissions(&record, std::fs::Permissions::from_mode(0o600)).unwrap();
        let hardlink = format!("{DIRECTORY}/test-hardlink");
        std::fs::hard_link(&record, &hardlink).unwrap();
        assert!(disk.read(1).is_err());
        std::fs::remove_file(&hardlink).unwrap();
        let empty_slot = format!("{DIRECTORY}/{}", SLOTS[0]);
        symlink(&record, &empty_slot).unwrap();
        assert!(disk.read(0).is_err());
        assert!(disk.write(0, b"must not replace symlink").is_err());
        std::fs::remove_file(&empty_slot).unwrap();
        // Opening an invalid special file must not wait for a FIFO peer before
        // the regular-file check can reject it.
        nix::unistd::mkfifo(empty_slot.as_str(), nix::sys::stat::Mode::S_IRUSR).unwrap();
        assert!(disk.read(0).is_err());
        assert!(disk.write(0, b"must not replace fifo").is_err());
        std::fs::remove_file(&empty_slot).unwrap();
        let temporary = format!("{DIRECTORY}/.record.prepare");
        nix::unistd::mkfifo(temporary.as_str(), nix::sys::stat::Mode::S_IWUSR).unwrap();
        assert!(disk.write(0, b"must not block on temporary fifo").is_err());
        std::fs::remove_file(&temporary).unwrap();
        let lock = format!("{DIRECTORY}/{LOCK}");
        let saved_lock = format!("{DIRECTORY}/test-old-lock");
        std::fs::rename(&lock, &saved_lock).unwrap();
        let fake = File::create(&lock).unwrap();
        fake.set_permissions(std::fs::Permissions::from_mode(0o600))
            .unwrap();
        assert!(disk.read(1).is_err());
        drop(fake);
        std::fs::remove_file(&lock).unwrap();
        std::fs::rename(&saved_lock, &lock).unwrap();
        let moved = "/var/lib/savana/deployment-v3-test-moved";
        assert!(!std::path::Path::new(moved).exists());
        std::fs::rename(DIRECTORY, moved).unwrap();
        std::fs::create_dir(DIRECTORY).unwrap();
        std::fs::set_permissions(DIRECTORY, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(disk.read(1).is_err());
        std::fs::remove_dir(DIRECTORY).unwrap();
        std::fs::rename(moved, DIRECTORY).unwrap();
        disk.write(0, b"second synthetic record").unwrap();
        assert!(disk.write(0, &vec![0; MAX_RECORD + 1]).is_err());
        assert!(disk.read(2).is_err());
        let head = TpmStateHeadV3::new(1, [7; 32]).unwrap();
        disk.write_archive(head, b"synthetic immutable history")
            .unwrap();
        disk.write_archive(head, b"synthetic immutable history")
            .unwrap();
        assert!(disk.write_archive(head, b"changed history").is_err());
        assert_eq!(
            disk.read_archive(head).unwrap().unwrap(),
            b"synthetic immutable history"
        );
        let archived = format!("{DIRECTORY}/{}", archive_name(head).unwrap());
        let linked = format!("{DIRECTORY}/test-archive-link");
        std::fs::hard_link(&archived, &linked).unwrap();
        assert!(disk.read_archive(head).is_err());
        std::fs::remove_file(&linked).unwrap();
        assert!(disk.read_archive(TpmStateHeadV3::GENESIS).is_err());
        drop(disk);
        let legacy = "/var/lib/savana/deployment";
        assert!(!std::path::Path::new(legacy).exists());
        std::fs::create_dir(legacy).unwrap();
        assert!(Disk::open().is_err());
        std::fs::remove_dir(legacy).unwrap();
        assert_eq!(
            Disk::open().unwrap().read(0).unwrap().unwrap(),
            b"second synthetic record"
        );
        // Remaining synthetic files live only in the container's disposable tmpfs.
    }
}
