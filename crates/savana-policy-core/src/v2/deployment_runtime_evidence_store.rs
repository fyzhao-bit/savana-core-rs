use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io::{Read as _, Write as _};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use rustix::fs::{
    open, openat, renameat_with, statat, unlinkat, AtFlags, Mode, OFlags, RenameFlags,
};
use rustix::io::Errno;
use savana_kernel_protocol::v2::Digest32V2;

use super::{
    BootstrapBridgeRestoreIntegrityV2, DeploymentControlErrorV2, FrozenEffectWorkSetV2,
    NativeControlMeasurementSetV2, RoleJournalReconciliationV2,
};

#[cfg(target_os = "linux")]
const FIXED_AUXILIARY_EVIDENCE_DIRECTORY_V2: &str = "/var/lib/savana/deployment/auxiliary-evidence";
#[cfg(target_os = "macos")]
const FIXED_AUXILIARY_EVIDENCE_DIRECTORY_V2: &str =
    "/Library/Application Support/Savana/Deployment/auxiliary-evidence";
const MAX_AUXILIARY_EVIDENCE_BYTES_V2: u64 = 16 * 1024 * 1024;
const TEMPORARY_NAME_ATTEMPTS_V2: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
enum AuxiliaryEvidenceKindV2 {
    NativeControlMeasurementSet = 2,
    FrozenEffectWorkSet = 3,
    RoleJournalReconciliation = 4,
    BootstrapBridgeRestoreIntegrity = 8,
}

impl AuxiliaryEvidenceKindV2 {
    const fn tag(self) -> u16 {
        self as u16
    }
}

pub struct DurableDeploymentAuxiliaryEvidenceStoreV2 {
    parent: File,
    parent_path: PathBuf,
    parent_dev: u64,
    parent_ino: u64,
    owner_uid: u32,
    owner_gid: u32,
}

impl std::fmt::Debug for DurableDeploymentAuxiliaryEvidenceStoreV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DurableDeploymentAuxiliaryEvidenceStoreV2")
            .field("parent_path", &self.parent_path)
            .finish_non_exhaustive()
    }
}

impl DurableDeploymentAuxiliaryEvidenceStoreV2 {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub fn open_fixed_platform() -> Result<Self, DeploymentControlErrorV2> {
        Self::open_anchored(Path::new(FIXED_AUXILIARY_EVIDENCE_DIRECTORY_V2), 0, 0)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn open_for_test(directory: &Path) -> Result<Self, DeploymentControlErrorV2> {
        let metadata = fs::symlink_metadata(directory)
            .map_err(|_| DeploymentControlErrorV2::DeploymentAuxiliaryEvidenceIo)?;
        Self::open_anchored(directory, metadata.uid(), metadata.gid())
    }

    fn open_anchored(
        directory: &Path,
        expected_uid: u32,
        expected_gid: u32,
    ) -> Result<Self, DeploymentControlErrorV2> {
        if !directory.is_absolute() {
            return Err(DeploymentControlErrorV2::DeploymentAuxiliaryEvidenceIo);
        }
        let before = fs::symlink_metadata(directory)
            .map_err(|_| DeploymentControlErrorV2::DeploymentAuxiliaryEvidenceIo)?;
        if before.file_type().is_symlink()
            || !before.is_dir()
            || before.uid() != expected_uid
            || before.gid() != expected_gid
            || before.mode() & 0o7777 != 0o700
        {
            return Err(DeploymentControlErrorV2::DeploymentAuxiliaryEvidenceIo);
        }
        let parent = File::from(
            open(
                directory,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| DeploymentControlErrorV2::DeploymentAuxiliaryEvidenceIo)?,
        );
        let opened = parent
            .metadata()
            .map_err(|_| DeploymentControlErrorV2::DeploymentAuxiliaryEvidenceIo)?;
        if !opened.is_dir()
            || opened.dev() != before.dev()
            || opened.ino() != before.ino()
            || opened.uid() != expected_uid
            || opened.gid() != expected_gid
            || opened.mode() & 0o7777 != 0o700
        {
            return Err(DeploymentControlErrorV2::DeploymentAuxiliaryEvidenceIo);
        }
        let store = Self {
            parent,
            parent_path: directory.to_owned(),
            parent_dev: opened.dev(),
            parent_ino: opened.ino(),
            owner_uid: expected_uid,
            owner_gid: expected_gid,
        };
        store.recheck_parent()?;
        Ok(store)
    }

    pub fn append_native_control_measurement_set(
        &self,
        evidence: &NativeControlMeasurementSetV2,
    ) -> Result<Digest32V2, DeploymentControlErrorV2> {
        let decoded =
            NativeControlMeasurementSetV2::from_canonical_bytes(evidence.canonical_bytes())?;
        self.append_authenticated(
            AuxiliaryEvidenceKindV2::NativeControlMeasurementSet,
            decoded.digest(),
            decoded.canonical_bytes(),
        )
    }

    pub fn load_native_control_measurement_set(
        &self,
        digest: Digest32V2,
    ) -> Result<NativeControlMeasurementSetV2, DeploymentControlErrorV2> {
        let bytes = self.load_authenticated_bytes(
            AuxiliaryEvidenceKindV2::NativeControlMeasurementSet,
            digest,
        )?;
        let value = NativeControlMeasurementSetV2::from_canonical_bytes(&bytes)?;
        self.require_digest(value.digest(), digest)?;
        Ok(value)
    }

    pub fn append_frozen_effect_work_set(
        &self,
        evidence: &FrozenEffectWorkSetV2,
    ) -> Result<Digest32V2, DeploymentControlErrorV2> {
        let decoded = FrozenEffectWorkSetV2::from_canonical_bytes(evidence.canonical_bytes())?;
        self.append_authenticated(
            AuxiliaryEvidenceKindV2::FrozenEffectWorkSet,
            decoded.digest(),
            decoded.canonical_bytes(),
        )
    }

    pub fn load_frozen_effect_work_set(
        &self,
        digest: Digest32V2,
    ) -> Result<FrozenEffectWorkSetV2, DeploymentControlErrorV2> {
        let bytes =
            self.load_authenticated_bytes(AuxiliaryEvidenceKindV2::FrozenEffectWorkSet, digest)?;
        let value = FrozenEffectWorkSetV2::from_canonical_bytes(&bytes)?;
        self.require_digest(value.digest(), digest)?;
        Ok(value)
    }

    pub fn append_role_journal_reconciliation(
        &self,
        evidence: &RoleJournalReconciliationV2,
    ) -> Result<Digest32V2, DeploymentControlErrorV2> {
        let decoded =
            RoleJournalReconciliationV2::from_canonical_bytes(evidence.canonical_bytes())?;
        self.append_authenticated(
            AuxiliaryEvidenceKindV2::RoleJournalReconciliation,
            decoded.digest(),
            decoded.canonical_bytes(),
        )
    }

    pub fn load_role_journal_reconciliation(
        &self,
        digest: Digest32V2,
    ) -> Result<RoleJournalReconciliationV2, DeploymentControlErrorV2> {
        let bytes = self
            .load_authenticated_bytes(AuxiliaryEvidenceKindV2::RoleJournalReconciliation, digest)?;
        let value = RoleJournalReconciliationV2::from_canonical_bytes(&bytes)?;
        self.require_digest(value.digest(), digest)?;
        Ok(value)
    }

    pub fn append_bootstrap_bridge_restore_integrity(
        &self,
        evidence: &BootstrapBridgeRestoreIntegrityV2,
    ) -> Result<Digest32V2, DeploymentControlErrorV2> {
        let decoded =
            BootstrapBridgeRestoreIntegrityV2::from_canonical_bytes(evidence.canonical_bytes())?;
        self.append_authenticated(
            AuxiliaryEvidenceKindV2::BootstrapBridgeRestoreIntegrity,
            decoded.digest(),
            decoded.canonical_bytes(),
        )
    }

    pub fn load_bootstrap_bridge_restore_integrity(
        &self,
        digest: Digest32V2,
    ) -> Result<BootstrapBridgeRestoreIntegrityV2, DeploymentControlErrorV2> {
        let bytes = self.load_authenticated_bytes(
            AuxiliaryEvidenceKindV2::BootstrapBridgeRestoreIntegrity,
            digest,
        )?;
        let value = BootstrapBridgeRestoreIntegrityV2::from_canonical_bytes(&bytes)?;
        self.require_digest(value.digest(), digest)?;
        Ok(value)
    }

    fn append_authenticated(
        &self,
        kind: AuxiliaryEvidenceKindV2,
        digest: Digest32V2,
        canonical_bytes: &[u8],
    ) -> Result<Digest32V2, DeploymentControlErrorV2> {
        if is_zero(digest) || canonical_bytes.is_empty() {
            return Err(DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence);
        }
        let length = u64::try_from(canonical_bytes.len())
            .map_err(|_| DeploymentControlErrorV2::DeploymentAuxiliaryEvidenceIo)?;
        if length > MAX_AUXILIARY_EVIDENCE_BYTES_V2 {
            return Err(DeploymentControlErrorV2::DeploymentAuxiliaryEvidenceIo);
        }
        self.recheck_parent()?;
        let leaf = evidence_leaf(kind, digest);
        match statat(&self.parent, &leaf, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(_) => return self.load_existing_identical(kind, digest, canonical_bytes),
            Err(Errno::NOENT) => {}
            Err(_) => return Err(DeploymentControlErrorV2::DeploymentAuxiliaryEvidenceIo),
        }
        let (temporary_leaf, mut temporary) = self.create_temporary(&leaf)?;
        let result = (|| {
            temporary
                .write_all(canonical_bytes)
                .and_then(|()| temporary.sync_all())
                .map_err(|_| DeploymentControlErrorV2::DeploymentAuxiliaryEvidenceIo)?;
            self.validate_linked_file(&temporary_leaf, &temporary, length)?;
            self.recheck_parent()?;
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
                    return self.load_existing_identical(kind, digest, canonical_bytes);
                }
                Err(_) => {
                    return Err(DeploymentControlErrorV2::DeploymentAuxiliaryEvidenceIo);
                }
            }
            self.parent
                .sync_all()
                .map_err(|_| DeploymentControlErrorV2::DeploymentAuxiliaryEvidenceIo)?;
            self.load_existing_identical(kind, digest, canonical_bytes)
        })();
        if result.is_err() {
            let _ = unlinkat(&self.parent, &temporary_leaf, AtFlags::empty());
        }
        result
    }

    fn load_authenticated_bytes(
        &self,
        kind: AuxiliaryEvidenceKindV2,
        digest: Digest32V2,
    ) -> Result<Vec<u8>, DeploymentControlErrorV2> {
        if is_zero(digest) {
            return Err(DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence);
        }
        self.recheck_parent()?;
        let bytes = self.read_file(&evidence_leaf(kind, digest))?;
        self.recheck_parent()?;
        Ok(bytes)
    }

    fn load_existing_identical(
        &self,
        kind: AuxiliaryEvidenceKindV2,
        digest: Digest32V2,
        expected: &[u8],
    ) -> Result<Digest32V2, DeploymentControlErrorV2> {
        let bytes = self.load_authenticated_bytes(kind, digest)?;
        if bytes != expected {
            return Err(DeploymentControlErrorV2::DeploymentAuxiliaryEvidenceIo);
        }
        Ok(digest)
    }

    fn require_digest(
        &self,
        actual: Digest32V2,
        expected: Digest32V2,
    ) -> Result<(), DeploymentControlErrorV2> {
        if actual != expected {
            return Err(DeploymentControlErrorV2::DeploymentAuxiliaryEvidenceIo);
        }
        Ok(())
    }

    fn read_file(&self, leaf: &OsStr) -> Result<Vec<u8>, DeploymentControlErrorV2> {
        let descriptor = openat(
            &self.parent,
            leaf,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| DeploymentControlErrorV2::DeploymentAuxiliaryEvidenceIo)?;
        let mut file = File::from(descriptor);
        let metadata = file
            .metadata()
            .map_err(|_| DeploymentControlErrorV2::DeploymentAuxiliaryEvidenceIo)?;
        self.validate_metadata(&metadata)?;
        if metadata.len() == 0 || metadata.len() > MAX_AUXILIARY_EVIDENCE_BYTES_V2 {
            return Err(DeploymentControlErrorV2::DeploymentAuxiliaryEvidenceIo);
        }
        let length = usize::try_from(metadata.len())
            .map_err(|_| DeploymentControlErrorV2::DeploymentAuxiliaryEvidenceIo)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|_| DeploymentControlErrorV2::DeploymentAuxiliaryEvidenceIo)?;
        file.read_to_end(&mut bytes)
            .map_err(|_| DeploymentControlErrorV2::DeploymentAuxiliaryEvidenceIo)?;
        if bytes.len() != length {
            return Err(DeploymentControlErrorV2::DeploymentAuxiliaryEvidenceIo);
        }
        Ok(bytes)
    }

    fn create_temporary(
        &self,
        target_leaf: &OsStr,
    ) -> Result<(OsString, File), DeploymentControlErrorV2> {
        for _ in 0..TEMPORARY_NAME_ATTEMPTS_V2 {
            let mut random = [0_u8; 16];
            getrandom::getrandom(&mut random)
                .map_err(|_| DeploymentControlErrorV2::DeploymentAuxiliaryEvidenceIo)?;
            let leaf = temporary_leaf(target_leaf, &random);
            match openat(
                &self.parent,
                &leaf,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_bits_retain(0o600),
            ) {
                Ok(descriptor) => return Ok((leaf, File::from(descriptor))),
                Err(Errno::EXIST) => {}
                Err(_) => {
                    return Err(DeploymentControlErrorV2::DeploymentAuxiliaryEvidenceIo);
                }
            }
        }
        Err(DeploymentControlErrorV2::DeploymentAuxiliaryEvidenceIo)
    }

    fn validate_linked_file(
        &self,
        leaf: &OsStr,
        file: &File,
        expected_length: u64,
    ) -> Result<(), DeploymentControlErrorV2> {
        let descriptor_metadata = file
            .metadata()
            .map_err(|_| DeploymentControlErrorV2::DeploymentAuxiliaryEvidenceIo)?;
        self.validate_metadata(&descriptor_metadata)?;
        let linked = statat(&self.parent, leaf, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| DeploymentControlErrorV2::DeploymentAuxiliaryEvidenceIo)?;
        if linked.st_dev as i128 != descriptor_metadata.dev() as i128
            || linked.st_ino as i128 != descriptor_metadata.ino() as i128
            || linked.st_size < 0
            || linked.st_size as u64 != expected_length
        {
            return Err(DeploymentControlErrorV2::DeploymentAuxiliaryEvidenceIo);
        }
        Ok(())
    }

    fn validate_metadata(&self, metadata: &fs::Metadata) -> Result<(), DeploymentControlErrorV2> {
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.uid() != self.owner_uid
            || metadata.gid() != self.owner_gid
            || metadata.mode() & 0o7777 != 0o600
            || metadata.dev() != self.parent_dev
        {
            return Err(DeploymentControlErrorV2::DeploymentAuxiliaryEvidenceIo);
        }
        Ok(())
    }

    fn recheck_parent(&self) -> Result<(), DeploymentControlErrorV2> {
        let descriptor = self
            .parent
            .metadata()
            .map_err(|_| DeploymentControlErrorV2::DeploymentAuxiliaryEvidenceIo)?;
        let path = fs::symlink_metadata(&self.parent_path)
            .map_err(|_| DeploymentControlErrorV2::DeploymentAuxiliaryEvidenceIo)?;
        if path.file_type().is_symlink()
            || !path.is_dir()
            || descriptor.dev() != self.parent_dev
            || descriptor.ino() != self.parent_ino
            || path.dev() != self.parent_dev
            || path.ino() != self.parent_ino
            || path.uid() != self.owner_uid
            || path.gid() != self.owner_gid
            || path.mode() & 0o7777 != 0o700
        {
            return Err(DeploymentControlErrorV2::DeploymentAuxiliaryEvidenceIo);
        }
        Ok(())
    }
}

fn evidence_leaf(kind: AuxiliaryEvidenceKindV2, digest: Digest32V2) -> OsString {
    let mut bytes = Vec::with_capacity(12 + 2 + 1 + 64 + 5);
    bytes.extend_from_slice(b"evidence-");
    let tag = kind.tag();
    bytes.push(b'0' + ((tag / 10) as u8));
    bytes.push(b'0' + ((tag % 10) as u8));
    bytes.push(b'-');
    append_hex(&mut bytes, digest.as_bytes());
    bytes.extend_from_slice(b".cbor");
    OsStr::from_bytes(&bytes).to_owned()
}

fn temporary_leaf(target: &OsStr, random: &[u8; 16]) -> OsString {
    let mut bytes = Vec::with_capacity(target.as_bytes().len() + 1 + 32);
    bytes.extend_from_slice(target.as_bytes());
    bytes.push(b'.');
    append_hex(&mut bytes, random);
    OsStr::from_bytes(&bytes).to_owned()
}

fn append_hex(output: &mut Vec<u8>, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize]);
        output.push(HEX[(byte & 0x0f) as usize]);
    }
}

fn is_zero(digest: Digest32V2) -> bool {
    digest.as_bytes().iter().all(|byte| *byte == 0)
}
