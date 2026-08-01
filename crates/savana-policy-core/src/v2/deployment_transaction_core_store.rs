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
    DeploymentActivationVerifierV2, DeploymentAuthorizationKeyRefsV2,
    DeploymentAuthorizationVerifierV2, DeploymentControlErrorV2,
    DurableDeploymentTransactionCoreV2, OperationalTrustRootSetV2, ReleaseTrustRootSetV2,
};

#[cfg(target_os = "linux")]
const FIXED_CORE_DIRECTORY_V2: &str = "/var/lib/savana/deployment/transaction-cores";
#[cfg(target_os = "macos")]
const FIXED_CORE_DIRECTORY_V2: &str =
    "/Library/Application Support/Savana/Deployment/transaction-cores";
const MAX_CORE_BYTES_V2: u64 = 16 * 1024 * 1024;
const TEMPORARY_NAME_ATTEMPTS_V2: usize = 16;

/// Read-only, activation-authenticated bootstrap view used by recovery to
/// discover the exact transaction authorization keys before opening the full
/// canonical core store. It exposes no append or fully decoded core method.
pub struct DurableDeploymentCoreKeyDiscoveryStoreV2 {
    parent: File,
    parent_path: PathBuf,
    parent_dev: u64,
    parent_ino: u64,
    owner_uid: u32,
    owner_gid: u32,
    activation_verifier: DeploymentActivationVerifierV2,
}

impl std::fmt::Debug for DurableDeploymentCoreKeyDiscoveryStoreV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DurableDeploymentCoreKeyDiscoveryStoreV2")
            .field("parent_path", &self.parent_path)
            .field("activation_key_id", &self.activation_verifier.key_id())
            .finish_non_exhaustive()
    }
}

impl DurableDeploymentCoreKeyDiscoveryStoreV2 {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub fn open_fixed_platform(
        activation_verifier: DeploymentActivationVerifierV2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        Self::open_anchored(
            Path::new(FIXED_CORE_DIRECTORY_V2),
            0,
            0,
            activation_verifier,
        )
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn open_for_test(
        directory: &Path,
        activation_verifier: DeploymentActivationVerifierV2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        let metadata = fs::symlink_metadata(directory)
            .map_err(|_| DeploymentControlErrorV2::DeploymentTransactionIo)?;
        Self::open_anchored(
            directory,
            metadata.uid(),
            metadata.gid(),
            activation_verifier,
        )
    }

    fn open_anchored(
        directory: &Path,
        expected_uid: u32,
        expected_gid: u32,
        activation_verifier: DeploymentActivationVerifierV2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        if !directory.is_absolute() {
            return Err(DeploymentControlErrorV2::DeploymentTransactionIo);
        }
        let before = fs::symlink_metadata(directory)
            .map_err(|_| DeploymentControlErrorV2::DeploymentTransactionIo)?;
        if before.file_type().is_symlink()
            || !before.is_dir()
            || before.uid() != expected_uid
            || before.gid() != expected_gid
            || before.mode() & 0o7777 != 0o700
        {
            return Err(DeploymentControlErrorV2::DeploymentTransactionIo);
        }
        let parent = File::from(
            open(
                directory,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| DeploymentControlErrorV2::DeploymentTransactionIo)?,
        );
        let opened = parent
            .metadata()
            .map_err(|_| DeploymentControlErrorV2::DeploymentTransactionIo)?;
        if !opened.is_dir()
            || opened.dev() != before.dev()
            || opened.ino() != before.ino()
            || opened.uid() != expected_uid
            || opened.gid() != expected_gid
            || opened.mode() & 0o7777 != 0o700
        {
            return Err(DeploymentControlErrorV2::DeploymentTransactionIo);
        }
        let value = Self {
            parent,
            parent_path: directory.to_owned(),
            parent_dev: opened.dev(),
            parent_ino: opened.ino(),
            owner_uid: expected_uid,
            owner_gid: expected_gid,
            activation_verifier,
        };
        value.recheck_parent()?;
        Ok(value)
    }

    pub fn load_authorization_key_refs(
        &self,
        signed_digest: Digest32V2,
    ) -> Result<DeploymentAuthorizationKeyRefsV2, DeploymentControlErrorV2> {
        self.recheck_parent()?;
        let bytes = self.read_file(&core_leaf(signed_digest))?;
        self.recheck_parent()?;
        DurableDeploymentTransactionCoreV2::authenticated_authorization_key_refs_for_signed_digest(
            &bytes,
            signed_digest,
            &self.activation_verifier,
        )
    }

    fn read_file(&self, leaf: &OsStr) -> Result<Vec<u8>, DeploymentControlErrorV2> {
        let descriptor = openat(
            &self.parent,
            leaf,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| DeploymentControlErrorV2::DeploymentTransactionIo)?;
        let mut file = File::from(descriptor);
        let metadata = file
            .metadata()
            .map_err(|_| DeploymentControlErrorV2::DeploymentTransactionIo)?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.uid() != self.owner_uid
            || metadata.gid() != self.owner_gid
            || metadata.mode() & 0o7777 != 0o600
            || metadata.dev() != self.parent_dev
            || metadata.len() == 0
            || metadata.len() > MAX_CORE_BYTES_V2
        {
            return Err(DeploymentControlErrorV2::DeploymentTransactionIo);
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(metadata.len() as usize)
            .map_err(|_| DeploymentControlErrorV2::DeploymentTransactionIo)?;
        file.read_to_end(&mut bytes)
            .map_err(|_| DeploymentControlErrorV2::DeploymentTransactionIo)?;
        if bytes.len() as u64 != metadata.len() {
            return Err(DeploymentControlErrorV2::DeploymentTransactionIo);
        }
        Ok(bytes)
    }

    fn recheck_parent(&self) -> Result<(), DeploymentControlErrorV2> {
        let descriptor = self
            .parent
            .metadata()
            .map_err(|_| DeploymentControlErrorV2::DeploymentTransactionIo)?;
        let path = fs::symlink_metadata(&self.parent_path)
            .map_err(|_| DeploymentControlErrorV2::DeploymentTransactionIo)?;
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
            return Err(DeploymentControlErrorV2::DeploymentTransactionIo);
        }
        Ok(())
    }
}

pub struct DurableDeploymentTransactionCoreStoreV2 {
    parent: File,
    parent_path: PathBuf,
    parent_dev: u64,
    parent_ino: u64,
    owner_uid: u32,
    owner_gid: u32,
    activation_verifier: DeploymentActivationVerifierV2,
    rollback_grant_verifier: DeploymentAuthorizationVerifierV2,
    transaction_authorization_verifier: DeploymentAuthorizationVerifierV2,
    deployment_trust_root_set: Option<OperationalTrustRootSetV2>,
    activation_trust_root_set: Option<OperationalTrustRootSetV2>,
    declassification_trust_root_set: Option<OperationalTrustRootSetV2>,
    release_trust_root_set: ReleaseTrustRootSetV2,
}

impl std::fmt::Debug for DurableDeploymentTransactionCoreStoreV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DurableDeploymentTransactionCoreStoreV2")
            .field("parent_path", &self.parent_path)
            .field("activation_key_id", &self.activation_verifier.key_id())
            .field(
                "has_complete_operational_trust",
                &self.deployment_trust_root_set.is_some(),
            )
            .finish_non_exhaustive()
    }
}

impl DurableDeploymentTransactionCoreStoreV2 {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub fn open_fixed_platform(
        activation_verifier: DeploymentActivationVerifierV2,
        rollback_grant_verifier: DeploymentAuthorizationVerifierV2,
        transaction_authorization_verifier: DeploymentAuthorizationVerifierV2,
        deployment_trust_root_set: OperationalTrustRootSetV2,
        activation_trust_root_set: OperationalTrustRootSetV2,
        declassification_trust_root_set: OperationalTrustRootSetV2,
        release_trust_root_set: ReleaseTrustRootSetV2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        Self::open_anchored(
            Path::new(FIXED_CORE_DIRECTORY_V2),
            0,
            0,
            activation_verifier,
            rollback_grant_verifier,
            transaction_authorization_verifier,
            Some(deployment_trust_root_set),
            Some(activation_trust_root_set),
            Some(declassification_trust_root_set),
            release_trust_root_set,
        )
    }

    #[cfg(any(test, feature = "test-support"))]
    #[allow(clippy::too_many_arguments)]
    pub fn open_for_test(
        directory: &Path,
        activation_verifier: DeploymentActivationVerifierV2,
        rollback_grant_verifier: DeploymentAuthorizationVerifierV2,
        transaction_authorization_verifier: DeploymentAuthorizationVerifierV2,
        release_trust_root_set: ReleaseTrustRootSetV2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        let metadata = fs::symlink_metadata(directory)
            .map_err(|_| DeploymentControlErrorV2::DeploymentTransactionIo)?;
        Self::open_anchored(
            directory,
            metadata.uid(),
            metadata.gid(),
            activation_verifier,
            rollback_grant_verifier,
            transaction_authorization_verifier,
            None,
            None,
            None,
            release_trust_root_set,
        )
    }

    #[cfg(any(test, feature = "test-support"))]
    #[allow(clippy::too_many_arguments)]
    pub fn open_for_test_with_complete_trust(
        directory: &Path,
        activation_verifier: DeploymentActivationVerifierV2,
        rollback_grant_verifier: DeploymentAuthorizationVerifierV2,
        transaction_authorization_verifier: DeploymentAuthorizationVerifierV2,
        deployment_trust_root_set: OperationalTrustRootSetV2,
        activation_trust_root_set: OperationalTrustRootSetV2,
        declassification_trust_root_set: OperationalTrustRootSetV2,
        release_trust_root_set: ReleaseTrustRootSetV2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        let metadata = fs::symlink_metadata(directory)
            .map_err(|_| DeploymentControlErrorV2::DeploymentTransactionIo)?;
        Self::open_anchored(
            directory,
            metadata.uid(),
            metadata.gid(),
            activation_verifier,
            rollback_grant_verifier,
            transaction_authorization_verifier,
            Some(deployment_trust_root_set),
            Some(activation_trust_root_set),
            Some(declassification_trust_root_set),
            release_trust_root_set,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn open_anchored(
        directory: &Path,
        expected_uid: u32,
        expected_gid: u32,
        activation_verifier: DeploymentActivationVerifierV2,
        rollback_grant_verifier: DeploymentAuthorizationVerifierV2,
        transaction_authorization_verifier: DeploymentAuthorizationVerifierV2,
        deployment_trust_root_set: Option<OperationalTrustRootSetV2>,
        activation_trust_root_set: Option<OperationalTrustRootSetV2>,
        declassification_trust_root_set: Option<OperationalTrustRootSetV2>,
        release_trust_root_set: ReleaseTrustRootSetV2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        if !directory.is_absolute() {
            return Err(DeploymentControlErrorV2::DeploymentTransactionIo);
        }
        let before = fs::symlink_metadata(directory)
            .map_err(|_| DeploymentControlErrorV2::DeploymentTransactionIo)?;
        if before.file_type().is_symlink()
            || !before.is_dir()
            || before.uid() != expected_uid
            || before.gid() != expected_gid
            || before.mode() & 0o7777 != 0o700
        {
            return Err(DeploymentControlErrorV2::DeploymentTransactionIo);
        }
        let descriptor = open(
            directory,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| DeploymentControlErrorV2::DeploymentTransactionIo)?;
        let parent = File::from(descriptor);
        let opened = parent
            .metadata()
            .map_err(|_| DeploymentControlErrorV2::DeploymentTransactionIo)?;
        if !opened.is_dir()
            || opened.dev() != before.dev()
            || opened.ino() != before.ino()
            || opened.uid() != expected_uid
            || opened.gid() != expected_gid
            || opened.mode() & 0o7777 != 0o700
        {
            return Err(DeploymentControlErrorV2::DeploymentTransactionIo);
        }
        Ok(Self {
            parent,
            parent_path: directory.to_owned(),
            parent_dev: opened.dev(),
            parent_ino: opened.ino(),
            owner_uid: expected_uid,
            owner_gid: expected_gid,
            activation_verifier,
            rollback_grant_verifier,
            transaction_authorization_verifier,
            deployment_trust_root_set,
            activation_trust_root_set,
            declassification_trust_root_set,
            release_trust_root_set,
        })
    }

    pub fn append_core(
        &self,
        core: &DurableDeploymentTransactionCoreV2,
    ) -> Result<Digest32V2, DeploymentControlErrorV2> {
        self.recheck_parent()?;
        let authenticated = self.decode(core.canonical_bytes())?;
        if authenticated.signed_digest() != core.signed_digest() {
            return Err(DeploymentControlErrorV2::InvalidDeploymentTransaction);
        }
        let leaf = core_leaf(core.signed_digest());
        match statat(&self.parent, &leaf, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(_) => return self.load_existing_identical(&leaf, core),
            Err(Errno::NOENT) => {}
            Err(_) => return Err(DeploymentControlErrorV2::DeploymentTransactionIo),
        }
        let (temporary_leaf, mut temporary) = self.create_temporary(&leaf)?;
        let result = (|| {
            temporary
                .write_all(core.canonical_bytes())
                .and_then(|()| temporary.sync_all())
                .map_err(|_| DeploymentControlErrorV2::DeploymentTransactionIo)?;
            self.validate_linked_file(
                &temporary_leaf,
                &temporary,
                core.canonical_bytes().len() as u64,
            )?;
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
                    return self.load_existing_identical(&leaf, core);
                }
                Err(_) => return Err(DeploymentControlErrorV2::DeploymentTransactionIo),
            }
            self.parent
                .sync_all()
                .map_err(|_| DeploymentControlErrorV2::DeploymentTransactionIo)?;
            self.load_existing_identical(&leaf, core)
        })();
        if result.is_err() {
            let _ = unlinkat(&self.parent, &temporary_leaf, AtFlags::empty());
        }
        result
    }

    pub fn load_core(
        &self,
        signed_digest: Digest32V2,
    ) -> Result<DurableDeploymentTransactionCoreV2, DeploymentControlErrorV2> {
        if signed_digest.as_bytes().iter().all(|byte| *byte == 0) {
            return Err(DeploymentControlErrorV2::DeploymentTransactionIo);
        }
        self.recheck_parent()?;
        let bytes = self.read_file(&core_leaf(signed_digest))?;
        self.recheck_parent()?;
        let core = self.decode(&bytes)?;
        if core.signed_digest() != signed_digest {
            return Err(DeploymentControlErrorV2::DeploymentTransactionIo);
        }
        Ok(core)
    }

    fn decode(
        &self,
        bytes: &[u8],
    ) -> Result<DurableDeploymentTransactionCoreV2, DeploymentControlErrorV2> {
        match (
            self.deployment_trust_root_set.as_ref(),
            self.activation_trust_root_set.as_ref(),
            self.declassification_trust_root_set.as_ref(),
        ) {
            (Some(deployment), Some(activation), Some(declassification)) => {
                DurableDeploymentTransactionCoreV2::from_canonical_bytes_with_complete_trust(
                    bytes,
                    &self.activation_verifier,
                    &self.rollback_grant_verifier,
                    &self.transaction_authorization_verifier,
                    deployment,
                    activation,
                    declassification,
                    &self.release_trust_root_set,
                )
            }
            #[cfg(any(test, feature = "test-support"))]
            (None, None, None) => DurableDeploymentTransactionCoreV2::from_canonical_bytes(
                bytes,
                &self.activation_verifier,
                &self.rollback_grant_verifier,
                &self.transaction_authorization_verifier,
                &self.release_trust_root_set,
            ),
            _ => Err(DeploymentControlErrorV2::DeploymentTransactionIo),
        }
    }

    fn load_existing_identical(
        &self,
        leaf: &OsStr,
        expected: &DurableDeploymentTransactionCoreV2,
    ) -> Result<Digest32V2, DeploymentControlErrorV2> {
        let bytes = self.read_file(leaf)?;
        if bytes != expected.canonical_bytes() {
            return Err(DeploymentControlErrorV2::DeploymentTransactionIo);
        }
        let reopened = self.decode(&bytes)?;
        if reopened.signed_digest() != expected.signed_digest() {
            return Err(DeploymentControlErrorV2::DeploymentTransactionIo);
        }
        Ok(reopened.signed_digest())
    }

    fn read_file(&self, leaf: &OsStr) -> Result<Vec<u8>, DeploymentControlErrorV2> {
        let descriptor = openat(
            &self.parent,
            leaf,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| DeploymentControlErrorV2::DeploymentTransactionIo)?;
        let mut file = File::from(descriptor);
        let metadata = file
            .metadata()
            .map_err(|_| DeploymentControlErrorV2::DeploymentTransactionIo)?;
        self.validate_metadata(&metadata)?;
        if metadata.len() == 0 || metadata.len() > MAX_CORE_BYTES_V2 {
            return Err(DeploymentControlErrorV2::DeploymentTransactionIo);
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(metadata.len() as usize)
            .map_err(|_| DeploymentControlErrorV2::DeploymentTransactionIo)?;
        file.read_to_end(&mut bytes)
            .map_err(|_| DeploymentControlErrorV2::DeploymentTransactionIo)?;
        if bytes.len() as u64 != metadata.len() {
            return Err(DeploymentControlErrorV2::DeploymentTransactionIo);
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
                .map_err(|_| DeploymentControlErrorV2::DeploymentTransactionIo)?;
            let leaf = temporary_leaf(target_leaf, &random);
            match openat(
                &self.parent,
                &leaf,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_bits_retain(0o600),
            ) {
                Ok(descriptor) => return Ok((leaf, File::from(descriptor))),
                Err(Errno::EXIST) => {}
                Err(_) => return Err(DeploymentControlErrorV2::DeploymentTransactionIo),
            }
        }
        Err(DeploymentControlErrorV2::DeploymentTransactionIo)
    }

    fn validate_linked_file(
        &self,
        leaf: &OsStr,
        file: &File,
        expected_length: u64,
    ) -> Result<(), DeploymentControlErrorV2> {
        let descriptor_metadata = file
            .metadata()
            .map_err(|_| DeploymentControlErrorV2::DeploymentTransactionIo)?;
        self.validate_metadata(&descriptor_metadata)?;
        let linked = statat(&self.parent, leaf, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| DeploymentControlErrorV2::DeploymentTransactionIo)?;
        if linked.st_dev as i128 != descriptor_metadata.dev() as i128
            || linked.st_ino as i128 != descriptor_metadata.ino() as i128
            || linked.st_size < 0
            || linked.st_size as u64 != expected_length
        {
            return Err(DeploymentControlErrorV2::DeploymentTransactionIo);
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
            return Err(DeploymentControlErrorV2::DeploymentTransactionIo);
        }
        Ok(())
    }

    fn recheck_parent(&self) -> Result<(), DeploymentControlErrorV2> {
        let descriptor = self
            .parent
            .metadata()
            .map_err(|_| DeploymentControlErrorV2::DeploymentTransactionIo)?;
        let path = fs::symlink_metadata(&self.parent_path)
            .map_err(|_| DeploymentControlErrorV2::DeploymentTransactionIo)?;
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
            return Err(DeploymentControlErrorV2::DeploymentTransactionIo);
        }
        Ok(())
    }
}

fn core_leaf(digest: Digest32V2) -> OsString {
    let mut bytes = Vec::with_capacity(5 + 64 + 5);
    bytes.extend_from_slice(b"core-");
    for byte in digest.as_bytes() {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        bytes.push(HEX[(byte >> 4) as usize]);
        bytes.push(HEX[(byte & 0x0f) as usize]);
    }
    bytes.extend_from_slice(b".cbor");
    OsStr::from_bytes(&bytes).to_owned()
}

fn temporary_leaf(target: &OsStr, random: &[u8; 16]) -> OsString {
    let mut bytes = Vec::with_capacity(target.as_bytes().len() + 1 + 32);
    bytes.extend_from_slice(target.as_bytes());
    bytes.push(b'.');
    for byte in random {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        bytes.push(HEX[(byte >> 4) as usize]);
        bytes.push(HEX[(byte & 0x0f) as usize]);
    }
    OsStr::from_bytes(&bytes).to_owned()
}
