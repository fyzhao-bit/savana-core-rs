use std::cmp::Ordering;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use ed25519_dalek::{Signature, VerifyingKey};
use nix::fcntl::OFlag;
use rustix::fs::{open as rustix_open, openat, statat, AtFlags, Dir, FileType, Mode, OFlags, Stat};
use savana_kernel_protocol::{
    ClientId, Digest32, HardLimits, KeyId, Signature64, StableCode, UnixMillis, PROTOCOL_MAJOR,
    PROTOCOL_MINOR,
};
use sha2::{Digest, Sha256};

use crate::{PolicyError, PolicyTrustRootV1, PolicyVerifier, VerifiedPolicyV1};

const RELEASE_DOMAIN: &[u8] = b"SAVANA_RELEASE_V1\0";
const RELEASE_TARGET_DOMAIN: &[u8] = b"SAVANA_RELEASE_TARGET_V1\0";
const MAXIMUM_RELEASE_ROOTS: usize = 16;
const MAXIMUM_ALLOWED_RELEASES: usize = 16;
const MAXIMUM_SCHEMA_VERSIONS: u64 = 16;
const MAXIMUM_CLIENTS: u64 = 16;
const MAXIMUM_POLICY_ROOTS: u64 = 16;
const MAXIMUM_RELATIVE_PATH_BYTES: usize = 256;
const MAXIMUM_RELEASE_MANIFEST_BYTES: u64 = 8 * 1024 * 1024;
const MAXIMUM_INSTALLATION_PROFILE_BYTES: u64 = 8 * 1024 * 1024;
const MAXIMUM_DEFAULT_POLICY_BYTES: u64 = 8 * 1024 * 1024;
const MAXIMUM_SIGNED_MODEL_MANIFEST_BYTES: u64 = 256 * 1024;
const MAXIMUM_MODEL_ASSET_BYTES: u64 = 256 * 1024 * 1024;
const MAXIMUM_MODEL_ASSETS_TOTAL_BYTES: u64 = 512 * 1024 * 1024;
const MAXIMUM_DAEMON_EXECUTABLE_BYTES: u64 = 128 * 1024 * 1024;
const MAXIMUM_RUNTIME_BYTES: u64 = 256 * 1024 * 1024;
const MAXIMUM_OTHER_PAYLOAD_BYTES: u64 = 64 * 1024 * 1024;
const MAXIMUM_COMPLETE_STAGE_BYTES: u64 = 1024 * 1024 * 1024;

#[cfg(target_os = "linux")]
const COMPILED_RELEASE_STAGE_PATH: &str = "/opt/savana/kernel/release";
#[cfg(target_os = "macos")]
const COMPILED_RELEASE_STAGE_PATH: &str = "/Library/Application Support/Savana/Kernel/release";

const LINUX_SOCKET_PATH: &str = "/run/savana/kernel/kerneld.sock";
const LINUX_POLICY_PATH: &str = "/etc/savana/kernel/selected-policy-v1.cbor";
const LINUX_POLICY_SIGNATURE_PATH: &str = "/etc/savana/kernel/selected-policy-v1.sig";
const MACOS_SOCKET_PATH: &str = "/var/run/savana/kernel/kerneld.sock";
const MACOS_POLICY_PATH: &str =
    "/Library/Application Support/Savana/Kernel/selected-policy-v1.cbor";
const MACOS_POLICY_SIGNATURE_PATH: &str =
    "/Library/Application Support/Savana/Kernel/selected-policy-v1.sig";

const FIXED_PAYLOAD_PATHS: [&str; 8] = [
    "bin/savana-kerneld",
    "policy/default-policy-v1.cbor",
    "policy/default-policy-v1.sig",
    "approval/producer-registry-v1.cbor",
    "approval/ontology-v1.cbor",
    "approval/approval-key-set-v1.cbor",
    "model/signed-model-manifest-v1.cbor",
    "installation/kernel-installation-profile-v1.cbor",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseTrustRootV1 {
    pub key_id: KeyId,
    pub public_key: [u8; 32],
    pub not_before: UnixMillis,
    pub not_after: UnixMillis,
    pub revoked: bool,
}

#[derive(Debug, Clone)]
pub struct ReleaseVerifier {
    roots: Vec<ReleaseTrustRootV1>,
    allowed_release_digests: Vec<Digest32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

    fn from_stat(stat: &Stat) -> Result<Self, PolicyError> {
        Ok(Self {
            dev: i128::from(stat.st_dev),
            ino: checked_u64(stat.st_ino)?,
            uid: checked_u32(stat.st_uid)?,
            gid: checked_u32(stat.st_gid)?,
            mode: checked_u32(stat.st_mode)?,
            nlink: checked_u64(stat.st_nlink)?,
            length: checked_u64(stat.st_size)?,
        })
    }

    const fn same_inode(self, other: Self) -> bool {
        self.dev == other.dev && self.ino == other.ino
    }

    const fn permissions(self) -> u32 {
        self.mode & 0o7777
    }
}

fn checked_u64<T: TryInto<u64>>(value: T) -> Result<u64, PolicyError> {
    value.try_into().map_err(|_| release_mismatch())
}

fn checked_u32<T: TryInto<u32>>(value: T) -> Result<u32, PolicyError> {
    value.try_into().map_err(|_| release_mismatch())
}

struct HeldFile {
    file: File,
    parent: File,
    leaf: OsString,
    identity: NodeIdentity,
}

impl HeldFile {
    fn try_clone(&self) -> Result<Self, PolicyError> {
        Ok(Self {
            file: self.file.try_clone().map_err(|_| release_mismatch())?,
            parent: self.parent.try_clone().map_err(|_| release_mismatch())?,
            leaf: self.leaf.clone(),
            identity: self.identity,
        })
    }

    fn recheck(&self) -> Result<(), PolicyError> {
        let descriptor_identity =
            NodeIdentity::from_metadata(&self.file.metadata().map_err(|_| release_mismatch())?);
        let pathname_identity = stat_identity(&self.parent, &self.leaf)?;
        if descriptor_identity != self.identity || pathname_identity != self.identity {
            return Err(release_mismatch());
        }
        Ok(())
    }

    fn read_bounded(&self, maximum: u64) -> Result<Vec<u8>, PolicyError> {
        self.recheck()?;
        if self.identity.length > maximum {
            return Err(release_mismatch());
        }
        let capacity = usize::try_from(self.identity.length).map_err(|_| release_mismatch())?;
        let mut bytes = vec![0_u8; capacity];
        let mut offset = 0_usize;
        while offset < bytes.len() {
            let file_offset = u64::try_from(offset).map_err(|_| release_mismatch())?;
            let read = self
                .file
                .read_at(&mut bytes[offset..], file_offset)
                .map_err(|_| release_mismatch())?;
            if read == 0 {
                return Err(release_mismatch());
            }
            offset = offset.checked_add(read).ok_or_else(release_mismatch)?;
        }
        self.recheck()?;
        Ok(bytes)
    }

    fn hash_exact(&self, expected_length: u64) -> Result<Digest32, PolicyError> {
        self.recheck()?;
        if self.identity.length != expected_length {
            return Err(release_mismatch());
        }
        let mut hasher = Sha256::new();
        let mut offset = 0_u64;
        let mut buffer = [0_u8; 16 * 1024];
        while offset < expected_length {
            let remaining = expected_length
                .checked_sub(offset)
                .ok_or_else(release_mismatch)?;
            let wanted = usize::try_from(remaining.min(buffer.len() as u64))
                .map_err(|_| release_mismatch())?;
            let read = self
                .file
                .read_at(&mut buffer[..wanted], offset)
                .map_err(|_| release_mismatch())?;
            if read == 0 {
                return Err(release_mismatch());
            }
            hasher.update(&buffer[..read]);
            offset = offset
                .checked_add(u64::try_from(read).map_err(|_| release_mismatch())?)
                .ok_or_else(release_mismatch)?;
        }
        self.recheck()?;
        Ok(Digest32::new(hasher.finalize().into()))
    }
}

struct ReleaseStageRetention {
    stage: File,
    stage_path: PathBuf,
    stage_identity: NodeIdentity,
    manifest: HeldFile,
    signature: HeldFile,
    executable: HeldFile,
    payloads: Vec<HeldFile>,
}

impl ReleaseStageRetention {
    fn capture(stage: &ReleaseStage, manifest: &ReleaseManifestV1) -> Result<Self, PolicyError> {
        let mut payloads = Vec::new();
        payloads
            .try_reserve_exact(manifest.payloads.len())
            .map_err(|_| release_mismatch())?;
        for payload in &manifest.payloads {
            let held = stage.open_payload(payload)?;
            if held.hash_exact(payload.byte_length)? != payload.sha256 {
                return Err(release_mismatch());
            }
            stage.recheck_payload_path(payload, held.identity)?;
            payloads.push(held);
        }
        let retention = Self {
            stage: stage.stage.try_clone().map_err(|_| release_mismatch())?,
            stage_path: stage.stage_path.clone(),
            stage_identity: stage.stage_identity,
            manifest: stage.manifest.try_clone()?,
            signature: stage.signature.try_clone()?,
            executable: stage.executable.try_clone()?,
            payloads,
        };
        retention.recheck(manifest)?;
        Ok(retention)
    }

    fn capture_installed(
        stage_path: &Path,
        manifest: &ReleaseManifestV1,
        release_digest: Digest32,
        release_signature_digest: Digest32,
    ) -> Result<Self, PolicyError> {
        let stage_path = fs::canonicalize(stage_path).map_err(|_| release_mismatch())?;
        let stage = open_absolute_directory_chain(&stage_path)?;
        let stage_identity =
            NodeIdentity::from_metadata(&stage.metadata().map_err(|_| release_mismatch())?);
        let manifest_file = open_retained_file(&stage, "release/release-manifest-v1.cbor")?;
        let signature = open_retained_file(&stage, "release/release-manifest-v1.sig")?;
        let executable = open_retained_file(&stage, "bin/savana-kerneld")?;
        if manifest_file.hash_exact(manifest_file.identity.length)? != release_digest
            || signature.hash_exact(64)? != release_signature_digest
        {
            return Err(release_mismatch());
        }
        let mut payloads = Vec::new();
        payloads
            .try_reserve_exact(manifest.payloads.len())
            .map_err(|_| release_mismatch())?;
        for payload in &manifest.payloads {
            let held = open_retained_file(&stage, &payload.relative_path)?;
            if held.hash_exact(payload.byte_length)? != payload.sha256 {
                return Err(release_mismatch());
            }
            payloads.push(held);
        }
        let retention = Self {
            stage,
            stage_path,
            stage_identity,
            manifest: manifest_file,
            signature,
            executable,
            payloads,
        };
        retention.recheck(manifest)?;
        Ok(retention)
    }

    fn recheck(&self, manifest: &ReleaseManifestV1) -> Result<(), PolicyError> {
        let reopened = open_absolute_directory_chain(&self.stage_path)?;
        let pathname_identity =
            NodeIdentity::from_metadata(&reopened.metadata().map_err(|_| release_mismatch())?);
        let descriptor_identity =
            NodeIdentity::from_metadata(&self.stage.metadata().map_err(|_| release_mismatch())?);
        if pathname_identity != self.stage_identity || descriptor_identity != self.stage_identity {
            return Err(release_mismatch());
        }
        self.recheck_path("release/release-manifest-v1.cbor", &self.manifest)?;
        self.recheck_path("release/release-manifest-v1.sig", &self.signature)?;
        self.recheck_path("bin/savana-kerneld", &self.executable)?;
        if self.payloads.len() != manifest.payloads.len() {
            return Err(release_mismatch());
        }
        for (payload, held) in manifest.payloads.iter().zip(&self.payloads) {
            self.recheck_path(&payload.relative_path, held)?;
        }
        Ok(())
    }

    fn recheck_path(&self, relative_path: &str, held: &HeldFile) -> Result<(), PolicyError> {
        held.recheck()?;
        let reopened = open_retained_file(&self.stage, relative_path)?;
        if reopened.identity != held.identity {
            return Err(release_mismatch());
        }
        Ok(())
    }
}

fn open_retained_file(stage: &File, relative_path: &str) -> Result<HeldFile, PolicyError> {
    if !valid_relative_path(relative_path) {
        return Err(release_mismatch());
    }
    let mut parent = stage.try_clone().map_err(|_| release_mismatch())?;
    let mut components = Path::new(relative_path).components().peekable();
    while let Some(component) = components.next() {
        let Component::Normal(leaf) = component else {
            return Err(release_mismatch());
        };
        if components.peek().is_some() {
            let descriptor = openat(
                &parent,
                leaf,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| release_mismatch())?;
            parent = File::from(descriptor);
            continue;
        }
        let before = stat_identity(&parent, leaf)?;
        let descriptor = openat(
            &parent,
            leaf,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| release_mismatch())?;
        let file = File::from(descriptor);
        let metadata = file.metadata().map_err(|_| release_mismatch())?;
        let identity = NodeIdentity::from_metadata(&metadata);
        let after = stat_identity(&parent, leaf)?;
        if !metadata.is_file()
            || identity.nlink != 1
            || !before.same_inode(identity)
            || !identity.same_inode(after)
        {
            return Err(release_mismatch());
        }
        return Ok(HeldFile {
            file,
            parent,
            leaf: leaf.to_os_string(),
            identity,
        });
    }
    Err(release_mismatch())
}

pub struct ReleaseStage {
    stage: File,
    stage_path: PathBuf,
    stage_identity: NodeIdentity,
    owner_uid: u32,
    owner_gid: u32,
    manifest: HeldFile,
    signature: HeldFile,
    executable: HeldFile,
}

impl std::fmt::Debug for ReleaseStage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ReleaseStage(<descriptor-anchored>)")
    }
}

impl ReleaseStage {
    pub fn open_compiled(current_executable: &Path) -> Result<Self, PolicyError> {
        Self::open_at(
            Path::new(COMPILED_RELEASE_STAGE_PATH),
            current_executable,
            0,
            0,
        )
    }

    #[cfg(test)]
    fn open_for_test(
        stage_path: &Path,
        current_executable: &Path,
        owner_uid: u32,
        owner_gid: u32,
    ) -> Result<Self, PolicyError> {
        Self::open_at(stage_path, current_executable, owner_uid, owner_gid)
    }

    #[cfg(any(debug_assertions, feature = "test-support"))]
    #[doc(hidden)]
    pub fn open_mapped_for_test_support(
        stage_path: &Path,
        current_executable: &Path,
        owner_uid: u32,
        owner_gid: u32,
    ) -> Result<Self, PolicyError> {
        Self::open_at(stage_path, current_executable, owner_uid, owner_gid)
    }

    fn open_at(
        stage_path: &Path,
        current_executable: &Path,
        owner_uid: u32,
        owner_gid: u32,
    ) -> Result<Self, PolicyError> {
        let expected_executable = stage_path.join("bin/savana-kerneld");
        if current_executable.as_os_str().as_bytes() != expected_executable.as_os_str().as_bytes() {
            return Err(release_mismatch());
        }

        let stage = open_absolute_directory_chain(stage_path)?;
        let stage_metadata = stage.metadata().map_err(|_| release_mismatch())?;
        let stage_identity = NodeIdentity::from_metadata(&stage_metadata);
        validate_directory(&stage_metadata, stage_identity, owner_uid, owner_gid)?;

        let release = open_verified_directory(&stage, OsStr::new("release"), owner_uid, owner_gid)?;
        let manifest = open_verified_file(
            &release,
            OsStr::new("release-manifest-v1.cbor"),
            owner_uid,
            owner_gid,
            0o444,
            FileLength::Maximum(MAXIMUM_RELEASE_MANIFEST_BYTES),
        )?;
        let signature = open_verified_file(
            &release,
            OsStr::new("release-manifest-v1.sig"),
            owner_uid,
            owner_gid,
            0o444,
            FileLength::Exact(64),
        )?;
        let bin = open_verified_directory(&stage, OsStr::new("bin"), owner_uid, owner_gid)?;
        let executable = open_verified_file(
            &bin,
            OsStr::new("savana-kerneld"),
            owner_uid,
            owner_gid,
            0o555,
            FileLength::Maximum(MAXIMUM_DAEMON_EXECUTABLE_BYTES),
        )?;

        Ok(Self {
            stage,
            stage_path: stage_path.to_path_buf(),
            stage_identity,
            owner_uid,
            owner_gid,
            manifest,
            signature,
            executable,
        })
    }

    fn open_payload(&self, payload: &ReleaseFileV1) -> Result<HeldFile, PolicyError> {
        if !valid_relative_path(&payload.relative_path)
            || !allowed_payload_path(&payload.relative_path)
        {
            return Err(release_mismatch());
        }
        let mut parent = self.stage.try_clone().map_err(|_| release_mismatch())?;
        let mut components = Path::new(&payload.relative_path).components().peekable();
        while let Some(component) = components.next() {
            let Component::Normal(component) = component else {
                return Err(release_mismatch());
            };
            if components.peek().is_none() {
                let permissions = if payload.relative_path == "bin/savana-kerneld" {
                    0o555
                } else {
                    0o444
                };
                return open_verified_file(
                    &parent,
                    component,
                    self.owner_uid,
                    self.owner_gid,
                    permissions,
                    FileLength::Exact(payload.byte_length),
                );
            }
            parent = open_verified_directory(&parent, component, self.owner_uid, self.owner_gid)?;
        }
        Err(release_mismatch())
    }

    fn recheck_payload_path(
        &self,
        payload: &ReleaseFileV1,
        identity: NodeIdentity,
    ) -> Result<(), PolicyError> {
        let reopened = self.open_payload(payload)?;
        if reopened.identity != identity {
            return Err(release_mismatch());
        }
        Ok(())
    }

    fn recheck_stage_path(&self) -> Result<(), PolicyError> {
        let reopened = open_absolute_directory_chain(&self.stage_path)?;
        let identity =
            NodeIdentity::from_metadata(&reopened.metadata().map_err(|_| release_mismatch())?);
        let held =
            NodeIdentity::from_metadata(&self.stage.metadata().map_err(|_| release_mismatch())?);
        if identity != self.stage_identity || held != self.stage_identity {
            return Err(release_mismatch());
        }
        Ok(())
    }
}

enum FileLength {
    Exact(u64),
    Maximum(u64),
}

fn open_absolute_directory_chain(path: &Path) -> Result<File, PolicyError> {
    if !path.is_absolute() {
        return Err(release_mismatch());
    }
    let root = rustix_open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| release_mismatch())?;
    let mut current = File::from(root);
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(component) => {
                let next = openat(
                    &current,
                    component,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|_| release_mismatch())?;
                current = File::from(next);
            }
            _ => return Err(release_mismatch()),
        }
    }
    Ok(current)
}

fn open_verified_directory(
    parent: &File,
    leaf: &OsStr,
    owner_uid: u32,
    owner_gid: u32,
) -> Result<File, PolicyError> {
    ensure_normal_leaf(leaf)?;
    let before = stat_identity(parent, leaf)?;
    let descriptor = openat(
        parent,
        leaf,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| release_mismatch())?;
    let directory = File::from(descriptor);
    let metadata = directory.metadata().map_err(|_| release_mismatch())?;
    let identity = NodeIdentity::from_metadata(&metadata);
    if !before.same_inode(identity) {
        return Err(release_mismatch());
    }
    validate_directory(&metadata, identity, owner_uid, owner_gid)?;
    let after = stat_identity(parent, leaf)?;
    if !identity.same_inode(after) {
        return Err(release_mismatch());
    }
    Ok(directory)
}

fn open_verified_file(
    parent: &File,
    leaf: &OsStr,
    owner_uid: u32,
    owner_gid: u32,
    permissions: u32,
    length: FileLength,
) -> Result<HeldFile, PolicyError> {
    ensure_normal_leaf(leaf)?;
    let before = stat_identity(parent, leaf)?;
    let descriptor = openat(
        parent,
        leaf,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| release_mismatch())?;
    let file = File::from(descriptor);
    let metadata = file.metadata().map_err(|_| release_mismatch())?;
    let identity = NodeIdentity::from_metadata(&metadata);
    if !before.same_inode(identity)
        || !metadata.is_file()
        || identity.uid != owner_uid
        || identity.gid != owner_gid
        || identity.permissions() != permissions
        || identity.nlink != 1
        || match length {
            FileLength::Exact(expected) => identity.length != expected,
            FileLength::Maximum(maximum) => identity.length > maximum,
        }
    {
        return Err(release_mismatch());
    }
    let after = stat_identity(parent, leaf)?;
    if !identity.same_inode(after) {
        return Err(release_mismatch());
    }
    Ok(HeldFile {
        file,
        parent: parent.try_clone().map_err(|_| release_mismatch())?,
        leaf: leaf.to_os_string(),
        identity,
    })
}

fn validate_directory(
    metadata: &fs::Metadata,
    identity: NodeIdentity,
    owner_uid: u32,
    owner_gid: u32,
) -> Result<(), PolicyError> {
    if !metadata.is_dir()
        || identity.uid != owner_uid
        || identity.gid != owner_gid
        || identity.permissions() != 0o755
    {
        return Err(release_mismatch());
    }
    Ok(())
}

fn stat_identity(parent: &File, leaf: &OsStr) -> Result<NodeIdentity, PolicyError> {
    let stat = statat(parent, leaf, AtFlags::SYMLINK_NOFOLLOW).map_err(|_| release_mismatch())?;
    NodeIdentity::from_stat(&stat)
}

fn ensure_normal_leaf(leaf: &OsStr) -> Result<(), PolicyError> {
    let mut components = Path::new(leaf).components();
    if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
        return Err(release_mismatch());
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallationPlatformV1 {
    Linux,
    MacOs,
}

impl InstallationPlatformV1 {
    pub const fn as_lock_str(self) -> &'static str {
        match self {
            Self::Linux => "linux",
            Self::MacOs => "macos",
        }
    }

    const fn tag(self) -> u8 {
        match self {
            Self::Linux => 0,
            Self::MacOs => 1,
        }
    }

    const fn runtime_path(self) -> &'static str {
        match self {
            Self::Linux => "runtime/libonnxruntime.so",
            Self::MacOs => "runtime/libonnxruntime.dylib",
        }
    }

    const fn socket_path(self) -> &'static str {
        match self {
            Self::Linux => LINUX_SOCKET_PATH,
            Self::MacOs => MACOS_SOCKET_PATH,
        }
    }

    const fn selected_policy_path(self) -> &'static str {
        match self {
            Self::Linux => LINUX_POLICY_PATH,
            Self::MacOs => MACOS_POLICY_PATH,
        }
    }

    const fn selected_policy_signature_path(self) -> &'static str {
        match self {
            Self::Linux => LINUX_POLICY_SIGNATURE_PATH,
            Self::MacOs => MACOS_POLICY_SIGNATURE_PATH,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallationClientRoleV1 {
    JarvisKernelClient,
}

impl InstallationClientRoleV1 {
    pub const fn as_lock_str(self) -> &'static str {
        "jarvis_kernel_client"
    }

    const fn tag(self) -> u8 {
        0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallationPublicKeyV1 {
    key_id: KeyId,
    public_key: [u8; 32],
}

impl InstallationPublicKeyV1 {
    pub const fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    pub const fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallationClientV1 {
    client_id: ClientId,
    key_id: KeyId,
    public_key: [u8; 32],
    role: InstallationClientRoleV1,
    peer_uid: u32,
    peer_gid: u32,
}

impl InstallationClientV1 {
    pub const fn client_id(&self) -> &ClientId {
        &self.client_id
    }

    pub const fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    pub const fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    pub const fn role(&self) -> InstallationClientRoleV1 {
        self.role
    }

    pub const fn peer_uid(&self) -> u32 {
        self.peer_uid
    }

    pub const fn peer_gid(&self) -> u32 {
        self.peer_gid
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReleaseFileV1 {
    relative_path: String,
    byte_length: u64,
    sha256: Digest32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReleaseManifestV1 {
    schema_version: u16,
    release_version: String,
    release_sequence: u64,
    release_target_id: Digest32,
    source_commit: String,
    signing_key_id: KeyId,
    binary_sha256: Digest32,
    cargo_lock_sha256: Digest32,
    rust_toolchain_sha256: Digest32,
    protocol_major: u16,
    minimum_minor: u16,
    maximum_minor: u16,
    supported_policy_schemas: Vec<u16>,
    supported_model_schemas: Vec<u16>,
    policy_trust_roots_digest: Digest32,
    minimum_policy_version: u64,
    model_manifest_digest: Digest32,
    producer_registry_digest: Digest32,
    ontology_digest: Digest32,
    approval_key_set_digest: Digest32,
    resource_profile_digest: Digest32,
    installation_profile_digest: Digest32,
    payloads: Vec<ReleaseFileV1>,
    issued_at: UnixMillis,
    expires_at: UnixMillis,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct KernelInstallationProfileV1 {
    schema_version: u16,
    installation_id: Digest32,
    platform: InstallationPlatformV1,
    daemon_identity: InstallationPublicKeyV1,
    daemon_clients: Vec<InstallationClientV1>,
    policy_trust_roots: Vec<PolicyTrustRootV1>,
    daemon_uid: u32,
    daemon_gid: u32,
    jarvis_uid: u32,
    socket_path: String,
    selected_policy_path: String,
    selected_policy_signature_path: String,
    socket_parent_mode: u16,
    socket_mode: u16,
}

#[derive(Clone)]
pub struct VerifiedReleaseIdentity {
    manifest: ReleaseManifestV1,
    profile: KernelInstallationProfileV1,
    release_digest: Digest32,
    release_signature_digest: Digest32,
    retention: Arc<ReleaseStageRetention>,
}

impl std::fmt::Debug for VerifiedReleaseIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("VerifiedReleaseIdentity(<verified>)")
    }
}

impl VerifiedReleaseIdentity {
    pub const fn binary_digest(&self) -> Digest32 {
        self.manifest.binary_sha256
    }

    pub const fn release_digest(&self) -> Digest32 {
        self.release_digest
    }

    pub const fn release_signature_digest(&self) -> Digest32 {
        self.release_signature_digest
    }

    pub const fn release_target_id(&self) -> Digest32 {
        self.manifest.release_target_id
    }

    pub const fn installation_profile_digest(&self) -> Digest32 {
        self.manifest.installation_profile_digest
    }

    pub fn source_commit(&self) -> &str {
        &self.manifest.source_commit
    }

    pub const fn protocol_major(&self) -> u16 {
        self.manifest.protocol_major
    }

    pub const fn minimum_minor(&self) -> u16 {
        self.manifest.minimum_minor
    }

    pub const fn maximum_minor(&self) -> u16 {
        self.manifest.maximum_minor
    }

    pub const fn expires_at(&self) -> UnixMillis {
        self.manifest.expires_at
    }

    pub(crate) const fn issued_at(&self) -> UnixMillis {
        self.manifest.issued_at
    }

    pub const fn minimum_policy_version(&self) -> u64 {
        self.manifest.minimum_policy_version
    }

    pub const fn model_manifest_digest(&self) -> Digest32 {
        self.manifest.model_manifest_digest
    }

    pub const fn producer_registry_digest(&self) -> Digest32 {
        self.manifest.producer_registry_digest
    }

    pub const fn ontology_digest(&self) -> Digest32 {
        self.manifest.ontology_digest
    }

    pub const fn approval_key_set_digest(&self) -> Digest32 {
        self.manifest.approval_key_set_digest
    }

    pub const fn resource_profile_digest(&self) -> Digest32 {
        self.manifest.resource_profile_digest
    }

    pub const fn installation_id(&self) -> Digest32 {
        self.profile.installation_id
    }

    pub const fn platform(&self) -> InstallationPlatformV1 {
        self.profile.platform
    }

    pub const fn daemon_identity(&self) -> &InstallationPublicKeyV1 {
        &self.profile.daemon_identity
    }

    pub fn daemon_clients(&self) -> &[InstallationClientV1] {
        &self.profile.daemon_clients
    }

    pub fn policy_trust_roots(&self) -> &[PolicyTrustRootV1] {
        &self.profile.policy_trust_roots
    }

    pub const fn daemon_uid(&self) -> u32 {
        self.profile.daemon_uid
    }

    pub const fn daemon_gid(&self) -> u32 {
        self.profile.daemon_gid
    }

    pub const fn jarvis_uid(&self) -> u32 {
        self.profile.jarvis_uid
    }

    pub fn socket_path(&self) -> &str {
        &self.profile.socket_path
    }

    pub fn selected_policy_path(&self) -> &str {
        &self.profile.selected_policy_path
    }

    pub fn selected_policy_signature_path(&self) -> &str {
        &self.profile.selected_policy_signature_path
    }

    pub const fn socket_parent_mode(&self) -> u16 {
        self.profile.socket_parent_mode
    }

    pub const fn socket_mode(&self) -> u16 {
        self.profile.socket_mode
    }

    pub fn supports_policy_schema(&self, schema: u16) -> bool {
        self.manifest.supported_policy_schemas.contains(&schema)
    }

    pub fn policy_verifier(&self) -> Result<PolicyVerifier, PolicyError> {
        PolicyVerifier::for_release(
            self.profile.policy_trust_roots.clone(),
            self.manifest.release_target_id,
            self.release_digest,
            self.manifest.installation_profile_digest,
        )
    }

    pub(crate) fn recheck_retained_stage(&self) -> Result<(), PolicyError> {
        self.retention.recheck(&self.manifest)
    }

    pub fn verify_selected_policy_binding(
        &self,
        policy: &VerifiedPolicyV1,
        signature: &Signature64,
    ) -> Result<(), PolicyError> {
        let identity = policy.identity();
        let signing_root = self
            .profile
            .policy_trust_roots
            .iter()
            .find(|root| root.key_id == *policy.signing_key_id())
            .filter(|root| !root.revoked && root.epoch == identity.key_epoch)
            .ok_or_else(release_mismatch)?;
        if signing_root.public_key != *policy.signing_public_key()
            || policy.signature_digest() != hash_bytes(signature.as_bytes())
            || policy.active_release_target_id() != self.manifest.release_target_id
            || identity.policy_version < self.manifest.minimum_policy_version
            || policy.resource_profile_digest() != self.manifest.resource_profile_digest
            || !self.supports_policy_schema(1)
        {
            return Err(release_mismatch());
        }
        Ok(())
    }
}

impl ReleaseVerifier {
    /// Constructs a verifier from already-decoded, trusted installation input.
    ///
    /// Serialized installation input must use
    /// [`Self::from_canonical_trust_roots`] instead.
    pub fn new(
        roots: Vec<ReleaseTrustRootV1>,
        allowed_release_digests: Vec<Digest32>,
    ) -> Result<Self, PolicyError> {
        validate_release_roots(&roots)?;
        validate_allowed_releases(&allowed_release_digests)?;
        Ok(Self {
            roots,
            allowed_release_digests,
        })
    }

    pub fn from_canonical_trust_roots(
        canonical_roots: &[u8],
        allowed_release_digests: Vec<Digest32>,
    ) -> Result<Self, PolicyError> {
        let roots = decode_release_trust_roots(canonical_roots)?;
        Self::new(roots, allowed_release_digests)
    }

    pub fn verify_installed(
        &self,
        manifest_path: &Path,
        signature_path: &Path,
        installed_binary: &Path,
        now: UnixMillis,
    ) -> Result<VerifiedReleaseIdentity, PolicyError> {
        let stage_root = derive_stage_root(manifest_path, signature_path)?;
        ensure_stage_member_chain(&stage_root, Path::new("release/release-manifest-v1.cbor"))?;
        ensure_stage_member_chain(&stage_root, Path::new("release/release-manifest-v1.sig"))?;

        let manifest_bytes = read_bounded_regular(
            manifest_path,
            HardLimits::COMPILED.frame_bytes(),
            StableCode::ProtocolIo,
        )?;
        let manifest = decode_manifest(&manifest_bytes)?;
        let release_digest = hash_bytes(&manifest_bytes);
        if self
            .allowed_release_digests
            .binary_search_by(|candidate| candidate.as_bytes().cmp(release_digest.as_bytes()))
            .is_err()
        {
            return Err(release_mismatch());
        }

        let root = self
            .roots
            .iter()
            .find(|root| root.key_id == manifest.signing_key_id)
            .filter(|root| {
                !root.revoked
                    && root.not_before.get() <= now.get()
                    && now.get() < root.not_after.get()
            })
            .ok_or_else(invalid_signature)?;
        let signature_bytes =
            read_bounded_regular(signature_path, 64, StableCode::IdentityInvalidSignature)?;
        let signature_array: [u8; 64] = signature_bytes
            .as_slice()
            .try_into()
            .map_err(|_| invalid_signature())?;
        verify_release_signature(root, &manifest_bytes, &signature_array)?;
        validate_manifest(&manifest, now)?;

        let profile_path = stage_root.join("installation/kernel-installation-profile-v1.cbor");
        let profile_bytes = read_bounded_regular(
            &profile_path,
            HardLimits::COMPILED.frame_bytes(),
            StableCode::IdentityReleaseMismatch,
        )?;
        let profile_digest = hash_bytes(&profile_bytes);
        if profile_digest != manifest.installation_profile_digest {
            return Err(release_mismatch());
        }
        let profile = decode_profile(&profile_bytes)?;
        validate_profile(&profile)?;

        let canonical_roots = encode_policy_roots(&profile.policy_trust_roots)?;
        if hash_bytes(&canonical_roots) != manifest.policy_trust_roots_digest {
            return Err(release_mismatch());
        }
        let target = compute_release_target(&manifest)?;
        if target != manifest.release_target_id {
            return Err(release_mismatch());
        }

        validate_payload_layout(&manifest, &profile)?;
        verify_stage_tree(&stage_root, &manifest, &manifest_bytes, &signature_array)?;
        verify_installed_binary(installed_binary, &manifest)?;

        let retention = Arc::new(ReleaseStageRetention::capture_installed(
            &stage_root,
            &manifest,
            release_digest,
            hash_bytes(&signature_array),
        )?);
        Ok(VerifiedReleaseIdentity {
            manifest,
            profile,
            release_digest,
            release_signature_digest: hash_bytes(&signature_array),
            retention,
        })
    }

    pub fn verify_stage(
        &self,
        stage: &ReleaseStage,
        now: UnixMillis,
    ) -> Result<VerifiedReleaseIdentity, PolicyError> {
        let manifest_bytes = stage
            .manifest
            .read_bounded(MAXIMUM_RELEASE_MANIFEST_BYTES)?;
        let manifest = decode_manifest(&manifest_bytes)?;
        let release_digest = hash_bytes(&manifest_bytes);
        if self
            .allowed_release_digests
            .binary_search_by(|candidate| candidate.as_bytes().cmp(release_digest.as_bytes()))
            .is_err()
        {
            return Err(release_mismatch());
        }

        let root = self
            .roots
            .iter()
            .find(|root| root.key_id == manifest.signing_key_id)
            .filter(|root| {
                !root.revoked
                    && root.not_before.get() <= now.get()
                    && now.get() < root.not_after.get()
            })
            .ok_or_else(invalid_signature)?;
        let signature_bytes = stage.signature.read_bounded(64)?;
        let signature_array: [u8; 64] = signature_bytes
            .as_slice()
            .try_into()
            .map_err(|_| invalid_signature())?;
        verify_release_signature(root, &manifest_bytes, &signature_array)?;
        validate_manifest(&manifest, now)?;
        let declared_stage_length = validate_stage_payload_limits(stage, &manifest)?;

        let profile_payload = payload(
            &manifest,
            "installation/kernel-installation-profile-v1.cbor",
        )
        .ok_or_else(release_mismatch)?;
        let held_profile = stage.open_payload(profile_payload)?;
        let profile_bytes = held_profile.read_bounded(MAXIMUM_INSTALLATION_PROFILE_BYTES)?;
        stage.recheck_payload_path(profile_payload, held_profile.identity)?;
        if hash_bytes(&profile_bytes) != manifest.installation_profile_digest {
            return Err(release_mismatch());
        }
        let profile = decode_profile(&profile_bytes)?;
        validate_profile(&profile)?;
        if !is_compiled_platform(profile.platform) {
            return Err(release_mismatch());
        }

        let canonical_roots = encode_policy_roots(&profile.policy_trust_roots)?;
        if hash_bytes(&canonical_roots) != manifest.policy_trust_roots_digest {
            return Err(release_mismatch());
        }
        if compute_release_target(&manifest)? != manifest.release_target_id {
            return Err(release_mismatch());
        }
        validate_payload_layout(&manifest, &profile)?;

        enumerate_verified_stage(stage, &manifest, declared_stage_length)?;

        stage.manifest.recheck()?;
        stage.signature.recheck()?;
        stage.executable.recheck()?;
        stage.recheck_stage_path()?;

        let retention = Arc::new(ReleaseStageRetention::capture(stage, &manifest)?);
        Ok(VerifiedReleaseIdentity {
            manifest,
            profile,
            release_digest,
            release_signature_digest: hash_bytes(&signature_array),
            retention,
        })
    }
}

fn validate_stage_payload_limits(
    stage: &ReleaseStage,
    manifest: &ReleaseManifestV1,
) -> Result<u64, PolicyError> {
    let mut complete_length = stage
        .manifest
        .identity
        .length
        .checked_add(stage.signature.identity.length)
        .ok_or_else(release_mismatch)?;
    let mut model_assets_length = 0_u64;
    for payload in &manifest.payloads {
        if payload.byte_length == 0 {
            return Err(release_mismatch());
        }
        let maximum = payload_maximum(&payload.relative_path);
        if payload.byte_length > maximum {
            return Err(release_mismatch());
        }
        if payload.relative_path == "policy/default-policy-v1.sig" && payload.byte_length != 64 {
            return Err(release_mismatch());
        }
        if payload.relative_path.starts_with("model/assets/") {
            model_assets_length = model_assets_length
                .checked_add(payload.byte_length)
                .ok_or_else(release_mismatch)?;
            if model_assets_length > MAXIMUM_MODEL_ASSETS_TOTAL_BYTES {
                return Err(release_mismatch());
            }
        }
        complete_length = complete_length
            .checked_add(payload.byte_length)
            .ok_or_else(release_mismatch)?;
        if complete_length > MAXIMUM_COMPLETE_STAGE_BYTES {
            return Err(release_mismatch());
        }
    }
    Ok(complete_length)
}

fn payload_maximum(relative_path: &str) -> u64 {
    match relative_path {
        "bin/savana-kerneld" => MAXIMUM_DAEMON_EXECUTABLE_BYTES,
        "installation/kernel-installation-profile-v1.cbor" => MAXIMUM_INSTALLATION_PROFILE_BYTES,
        "policy/default-policy-v1.cbor" => MAXIMUM_DEFAULT_POLICY_BYTES,
        "policy/default-policy-v1.sig" => 64,
        "model/signed-model-manifest-v1.cbor" => MAXIMUM_SIGNED_MODEL_MANIFEST_BYTES,
        path if path.starts_with("model/assets/") => MAXIMUM_MODEL_ASSET_BYTES,
        path if path.starts_with("runtime/") => MAXIMUM_RUNTIME_BYTES,
        _ => MAXIMUM_OTHER_PAYLOAD_BYTES,
    }
}

#[cfg(target_os = "linux")]
const fn is_compiled_platform(platform: InstallationPlatformV1) -> bool {
    matches!(platform, InstallationPlatformV1::Linux)
}

#[cfg(target_os = "macos")]
const fn is_compiled_platform(platform: InstallationPlatformV1) -> bool {
    matches!(platform, InstallationPlatformV1::MacOs)
}

fn enumerate_verified_stage(
    stage: &ReleaseStage,
    manifest: &ReleaseManifestV1,
    declared_stage_length: u64,
) -> Result<(), PolicyError> {
    let mut allowed_directories = vec!["release".to_owned()];
    for payload in &manifest.payloads {
        let mut parent = Path::new(&payload.relative_path).parent();
        while let Some(directory) = parent {
            let value = directory.to_str().ok_or_else(release_mismatch)?;
            if value.is_empty() {
                break;
            }
            if !allowed_directories.iter().any(|allowed| allowed == value) {
                allowed_directories.push(value.to_owned());
            }
            parent = directory.parent();
        }
    }

    let maximum_files = manifest
        .payloads
        .len()
        .checked_add(2)
        .ok_or_else(release_mismatch)?;
    let mut discovered_files = Vec::with_capacity(maximum_files);
    let mut actual_stage_length = 0_u64;
    walk_held_stage(
        stage,
        manifest,
        &stage.stage,
        "",
        &allowed_directories,
        maximum_files,
        &mut discovered_files,
        &mut actual_stage_length,
    )?;

    if discovered_files.len() != maximum_files
        || actual_stage_length != declared_stage_length
        || !manifest.payloads.iter().all(|payload| {
            discovered_files
                .iter()
                .any(|discovered| discovered == &payload.relative_path)
        })
        || !discovered_files
            .iter()
            .any(|path| path == "release/release-manifest-v1.cbor")
        || !discovered_files
            .iter()
            .any(|path| path == "release/release-manifest-v1.sig")
    {
        return Err(release_mismatch());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn walk_held_stage(
    stage: &ReleaseStage,
    manifest: &ReleaseManifestV1,
    directory: &File,
    prefix: &str,
    allowed_directories: &[String],
    maximum_files: usize,
    discovered_files: &mut Vec<String>,
    actual_stage_length: &mut u64,
) -> Result<(), PolicyError> {
    let entries = Dir::read_from(directory).map_err(|_| release_mismatch())?;
    for entry in entries {
        let entry = entry.map_err(|_| release_mismatch())?;
        let name_bytes = entry.file_name().to_bytes();
        if matches!(name_bytes, b"." | b"..") {
            continue;
        }
        let name = std::str::from_utf8(name_bytes).map_err(|_| release_mismatch())?;
        if name.is_empty() || name.contains('/') {
            return Err(release_mismatch());
        }
        let relative_path = if prefix.is_empty() {
            name.to_owned()
        } else {
            let mut value = String::with_capacity(prefix.len() + 1 + name.len());
            value.push_str(prefix);
            value.push('/');
            value.push_str(name);
            value
        };
        if relative_path.len() > MAXIMUM_RELATIVE_PATH_BYTES {
            return Err(release_mismatch());
        }

        let leaf = OsStr::from_bytes(name_bytes);
        let stat =
            statat(directory, leaf, AtFlags::SYMLINK_NOFOLLOW).map_err(|_| release_mismatch())?;
        match FileType::from_raw_mode(stat.st_mode) {
            FileType::Directory => {
                if !allowed_directories
                    .iter()
                    .any(|allowed| allowed == &relative_path)
                {
                    return Err(release_mismatch());
                }
                let child =
                    open_verified_directory(directory, leaf, stage.owner_uid, stage.owner_gid)?;
                let child_identity =
                    NodeIdentity::from_metadata(&child.metadata().map_err(|_| release_mismatch())?);
                walk_held_stage(
                    stage,
                    manifest,
                    &child,
                    &relative_path,
                    allowed_directories,
                    maximum_files,
                    discovered_files,
                    actual_stage_length,
                )?;
                let descriptor_identity =
                    NodeIdentity::from_metadata(&child.metadata().map_err(|_| release_mismatch())?);
                let pathname_identity = stat_identity(directory, leaf)?;
                if descriptor_identity != child_identity || pathname_identity != child_identity {
                    return Err(release_mismatch());
                }
            }
            FileType::RegularFile => {
                if discovered_files.len() >= maximum_files {
                    return Err(release_mismatch());
                }
                let length =
                    verify_enumerated_stage_file(stage, manifest, directory, leaf, &relative_path)?;
                *actual_stage_length = actual_stage_length
                    .checked_add(length)
                    .ok_or_else(release_mismatch)?;
                if *actual_stage_length > MAXIMUM_COMPLETE_STAGE_BYTES {
                    return Err(release_mismatch());
                }
                discovered_files.push(relative_path);
            }
            _ => return Err(release_mismatch()),
        }
    }
    Ok(())
}

fn verify_enumerated_stage_file(
    stage: &ReleaseStage,
    manifest: &ReleaseManifestV1,
    directory: &File,
    leaf: &OsStr,
    relative_path: &str,
) -> Result<u64, PolicyError> {
    if relative_path == "release/release-manifest-v1.cbor" {
        let held = open_verified_file(
            directory,
            leaf,
            stage.owner_uid,
            stage.owner_gid,
            0o444,
            FileLength::Exact(stage.manifest.identity.length),
        )?;
        if held.identity != stage.manifest.identity {
            return Err(release_mismatch());
        }
        held.recheck()?;
        return Ok(held.identity.length);
    }
    if relative_path == "release/release-manifest-v1.sig" {
        let held = open_verified_file(
            directory,
            leaf,
            stage.owner_uid,
            stage.owner_gid,
            0o444,
            FileLength::Exact(64),
        )?;
        if held.identity != stage.signature.identity {
            return Err(release_mismatch());
        }
        held.recheck()?;
        return Ok(held.identity.length);
    }

    let expected = payload(manifest, relative_path).ok_or_else(release_mismatch)?;
    let permissions = if relative_path == "bin/savana-kerneld" {
        0o555
    } else {
        0o444
    };
    let held = open_verified_file(
        directory,
        leaf,
        stage.owner_uid,
        stage.owner_gid,
        permissions,
        FileLength::Exact(expected.byte_length),
    )?;
    if relative_path == "bin/savana-kerneld" && held.identity != stage.executable.identity {
        return Err(release_mismatch());
    }
    if held.hash_exact(expected.byte_length)? != expected.sha256 {
        return Err(release_mismatch());
    }
    stage.recheck_payload_path(expected, held.identity)?;
    Ok(held.identity.length)
}

fn validate_release_roots(roots: &[ReleaseTrustRootV1]) -> Result<(), PolicyError> {
    if !(1..=MAXIMUM_RELEASE_ROOTS).contains(&roots.len())
        || !roots.windows(2).all(|pair| {
            matches!(
                pair,
                [left, right]
                    if canonical_text_cmp(left.key_id.as_str(), right.key_id.as_str())
                        == Ordering::Less
            )
        })
        || roots
            .iter()
            .any(|root| root.public_key == [0; 32] || root.not_before.get() >= root.not_after.get())
    {
        return Err(malformed());
    }
    Ok(())
}

fn validate_allowed_releases(values: &[Digest32]) -> Result<(), PolicyError> {
    if !(1..=MAXIMUM_ALLOWED_RELEASES).contains(&values.len())
        || values.iter().any(|value| value.as_bytes() == &[0; 32])
        || !values
            .windows(2)
            .all(|pair| matches!(pair, [left, right] if left.as_bytes() < right.as_bytes()))
    {
        return Err(malformed());
    }
    Ok(())
}

fn verify_release_signature(
    root: &ReleaseTrustRootV1,
    manifest: &[u8],
    signature: &[u8; 64],
) -> Result<(), PolicyError> {
    let verifying_key =
        VerifyingKey::from_bytes(&root.public_key).map_err(|_| invalid_signature())?;
    let signature = Signature::from_bytes(signature);
    let mut signed = Vec::with_capacity(RELEASE_DOMAIN.len() + manifest.len());
    signed.extend_from_slice(RELEASE_DOMAIN);
    signed.extend_from_slice(manifest);
    verifying_key
        .verify_strict(&signed, &signature)
        .map_err(|_| invalid_signature())
}

fn validate_manifest(manifest: &ReleaseManifestV1, now: UnixMillis) -> Result<(), PolicyError> {
    if manifest.schema_version != 1
        || manifest.protocol_major != PROTOCOL_MAJOR
        || manifest.minimum_minor > PROTOCOL_MINOR
        || !manifest.supported_policy_schemas.contains(&1)
        || !manifest.supported_model_schemas.contains(&1)
    {
        return Err(PolicyError::stable(StableCode::ProtocolUnsupportedVersion));
    }
    if manifest.release_sequence == 0
        || manifest.minimum_policy_version == 0
        || manifest.issued_at.get() >= manifest.expires_at.get()
        || !valid_source_commit(&manifest.source_commit)
        || manifest.release_target_id.as_bytes() == &[0; 32]
        || manifest.binary_sha256.as_bytes() == &[0; 32]
        || manifest.cargo_lock_sha256.as_bytes() == &[0; 32]
        || manifest.rust_toolchain_sha256.as_bytes() == &[0; 32]
        || manifest.policy_trust_roots_digest.as_bytes() == &[0; 32]
        || manifest.model_manifest_digest.as_bytes() == &[0; 32]
        || manifest.producer_registry_digest.as_bytes() == &[0; 32]
        || manifest.ontology_digest.as_bytes() == &[0; 32]
        || manifest.approval_key_set_digest.as_bytes() == &[0; 32]
        || manifest.resource_profile_digest.as_bytes() == &[0; 32]
        || manifest.installation_profile_digest.as_bytes() == &[0; 32]
        || manifest
            .payloads
            .iter()
            .any(|payload| payload.sha256.as_bytes() == &[0; 32])
    {
        return Err(malformed());
    }
    if now.get() < manifest.issued_at.get() || now.get() >= manifest.expires_at.get() {
        return Err(release_mismatch());
    }
    Ok(())
}

fn validate_profile(profile: &KernelInstallationProfileV1) -> Result<(), PolicyError> {
    if profile.schema_version != 1 {
        return Err(PolicyError::stable(StableCode::ProtocolUnsupportedVersion));
    }
    if profile.installation_id.as_bytes() == &[0; 32]
        || profile.daemon_identity.public_key == [0; 32]
        || profile.daemon_uid == 0
        || profile.daemon_gid == 0
        || profile.jarvis_uid == 0
        || profile.daemon_uid == profile.jarvis_uid
    {
        return Err(malformed());
    }
    if profile.socket_parent_mode != 0o750
        || profile.socket_mode != 0o660
        || profile.socket_path != profile.platform.socket_path()
        || profile.selected_policy_path != profile.platform.selected_policy_path()
        || profile.selected_policy_signature_path
            != profile.platform.selected_policy_signature_path()
    {
        return Err(release_mismatch());
    }
    if !profile.daemon_clients.windows(2).all(|pair| {
        matches!(
            pair,
            [left, right]
                if canonical_text_cmp(left.client_id.as_str(), right.client_id.as_str())
                    == Ordering::Less
        )
    }) {
        return Err(malformed());
    }
    let socket_client_gid = profile
        .daemon_clients
        .first()
        .map(|client| client.peer_gid)
        .ok_or_else(malformed)?;
    if socket_client_gid == profile.daemon_gid
        || profile
            .daemon_clients
            .iter()
            .any(|client| client.peer_gid != socket_client_gid)
    {
        return Err(malformed());
    }
    for (index, client) in profile.daemon_clients.iter().enumerate() {
        if client.public_key == [0; 32]
            || client.peer_gid == 0
            || client.peer_uid != profile.jarvis_uid
            || client.role != InstallationClientRoleV1::JarvisKernelClient
            || client.key_id == profile.daemon_identity.key_id
            || client.public_key == profile.daemon_identity.public_key
            || profile.daemon_clients[..index]
                .iter()
                .any(|prior| prior.key_id == client.key_id || prior.public_key == client.public_key)
        {
            return Err(malformed());
        }
    }
    if !profile.policy_trust_roots.windows(2).all(|pair| {
        matches!(
            pair,
            [left, right]
                if canonical_text_cmp(left.key_id.as_str(), right.key_id.as_str())
                    == Ordering::Less
        )
    }) || profile
        .policy_trust_roots
        .iter()
        .any(|root| root.public_key == [0; 32] || root.epoch == 0)
    {
        return Err(malformed());
    }
    if !usable_verifying_key(&profile.daemon_identity.public_key)
        || profile
            .daemon_clients
            .iter()
            .any(|client| !usable_verifying_key(&client.public_key))
        || profile
            .policy_trust_roots
            .iter()
            .any(|root| !usable_verifying_key(&root.public_key))
    {
        return Err(release_mismatch());
    }
    Ok(())
}

fn usable_verifying_key(public_key: &[u8; 32]) -> bool {
    VerifyingKey::from_bytes(public_key).is_ok_and(|key| !key.is_weak())
}

fn validate_payload_layout(
    manifest: &ReleaseManifestV1,
    profile: &KernelInstallationProfileV1,
) -> Result<(), PolicyError> {
    for required in FIXED_PAYLOAD_PATHS {
        if !manifest
            .payloads
            .iter()
            .any(|payload| payload.relative_path == required)
        {
            return Err(release_mismatch());
        }
    }
    let runtime_count = manifest
        .payloads
        .iter()
        .filter(|payload| payload.relative_path.starts_with("runtime/"))
        .count();
    if runtime_count != 1
        || !manifest
            .payloads
            .iter()
            .any(|payload| payload.relative_path == profile.platform.runtime_path())
    {
        return Err(release_mismatch());
    }
    let asset_count = manifest
        .payloads
        .iter()
        .filter(|payload| payload.relative_path.starts_with("model/assets/"))
        .count();
    let maximum_assets =
        usize::try_from(HardLimits::COMPILED.model_assets()).map_err(|_| malformed())?;
    if !(1..=maximum_assets).contains(&asset_count) {
        return Err(release_mismatch());
    }
    let binary = payload(manifest, "bin/savana-kerneld").ok_or_else(release_mismatch)?;
    if binary.sha256 != manifest.binary_sha256 {
        return Err(release_mismatch());
    }
    let profile_payload = payload(manifest, "installation/kernel-installation-profile-v1.cbor")
        .ok_or_else(release_mismatch)?;
    if profile_payload.sha256 != manifest.installation_profile_digest {
        return Err(release_mismatch());
    }
    Ok(())
}

fn verify_stage_tree(
    stage_root: &Path,
    manifest: &ReleaseManifestV1,
    manifest_bytes: &[u8],
    signature_bytes: &[u8; 64],
) -> Result<(), PolicyError> {
    let root_metadata = fs::symlink_metadata(stage_root).map_err(|_| release_mismatch())?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        return Err(release_mismatch());
    }

    let mut allowed_directories = vec!["release".to_owned()];
    for payload in &manifest.payloads {
        let mut parent = Path::new(&payload.relative_path).parent();
        while let Some(directory) = parent {
            let value = directory.to_str().ok_or_else(release_mismatch)?;
            if value.is_empty() {
                break;
            }
            if !allowed_directories.iter().any(|allowed| allowed == value) {
                allowed_directories.push(value.to_owned());
            }
            parent = directory.parent();
        }
    }
    let mut discovered_files = Vec::new();
    let maximum_files = manifest
        .payloads
        .len()
        .checked_add(3)
        .ok_or_else(release_mismatch)?;
    walk_stage(
        stage_root,
        stage_root,
        &allowed_directories,
        maximum_files,
        &mut discovered_files,
    )?;
    let mut allowed_files: Vec<&str> = manifest
        .payloads
        .iter()
        .map(|payload| payload.relative_path.as_str())
        .collect();
    allowed_files.extend([
        "release/release-manifest-v1.cbor",
        "release/release-manifest-v1.sig",
        "kernel-lock.json",
    ]);
    if discovered_files
        .iter()
        .any(|path| !allowed_files.contains(&path.as_str()))
    {
        return Err(release_mismatch());
    }

    for payload in &manifest.payloads {
        let path = stage_root.join(&payload.relative_path);
        ensure_stage_member_chain(stage_root, Path::new(&payload.relative_path))?;
        let digest = hash_regular_file(&path, payload.byte_length)?;
        if digest != payload.sha256 {
            return Err(release_mismatch());
        }
    }
    let stored_manifest = read_bounded_regular(
        &stage_root.join("release/release-manifest-v1.cbor"),
        HardLimits::COMPILED.frame_bytes(),
        StableCode::IdentityReleaseMismatch,
    )?;
    let stored_signature = read_bounded_regular(
        &stage_root.join("release/release-manifest-v1.sig"),
        64,
        StableCode::IdentityReleaseMismatch,
    )?;
    if stored_manifest != manifest_bytes || stored_signature.as_slice() != signature_bytes {
        return Err(release_mismatch());
    }
    Ok(())
}

fn walk_stage(
    stage_root: &Path,
    directory: &Path,
    allowed_directories: &[String],
    maximum_files: usize,
    files: &mut Vec<String>,
) -> Result<(), PolicyError> {
    for entry in fs::read_dir(directory).map_err(|_| release_mismatch())? {
        let entry = entry.map_err(|_| release_mismatch())?;
        let metadata = fs::symlink_metadata(entry.path()).map_err(|_| release_mismatch())?;
        if metadata.file_type().is_symlink() {
            return Err(release_mismatch());
        }
        let relative = entry
            .path()
            .strip_prefix(stage_root)
            .map_err(|_| release_mismatch())?
            .to_str()
            .ok_or_else(release_mismatch)?
            .to_owned();
        if metadata.is_dir() {
            if !allowed_directories
                .iter()
                .any(|allowed| allowed == &relative)
            {
                return Err(release_mismatch());
            }
            walk_stage(
                stage_root,
                &entry.path(),
                allowed_directories,
                maximum_files,
                files,
            )?;
        } else if metadata.is_file() {
            if files.len() >= maximum_files {
                return Err(release_mismatch());
            }
            files.push(relative);
        } else {
            return Err(release_mismatch());
        }
    }
    Ok(())
}

fn verify_installed_binary(
    installed_binary: &Path,
    manifest: &ReleaseManifestV1,
) -> Result<(), PolicyError> {
    let expected = payload(manifest, "bin/savana-kerneld").ok_or_else(release_mismatch)?;
    let digest = hash_regular_file(installed_binary, expected.byte_length)?;
    if digest != expected.sha256 || digest != manifest.binary_sha256 {
        return Err(release_mismatch());
    }
    Ok(())
}

fn payload<'manifest>(
    manifest: &'manifest ReleaseManifestV1,
    relative_path: &str,
) -> Option<&'manifest ReleaseFileV1> {
    manifest
        .payloads
        .iter()
        .find(|payload| payload.relative_path == relative_path)
}

fn derive_stage_root(manifest: &Path, signature: &Path) -> Result<PathBuf, PolicyError> {
    if manifest.file_name().and_then(|name| name.to_str()) != Some("release-manifest-v1.cbor")
        || signature.file_name().and_then(|name| name.to_str()) != Some("release-manifest-v1.sig")
    {
        return Err(release_mismatch());
    }
    let release_directory = manifest.parent().ok_or_else(release_mismatch)?;
    if release_directory.file_name().and_then(|name| name.to_str()) != Some("release")
        || signature.parent() != Some(release_directory)
    {
        return Err(release_mismatch());
    }
    release_directory
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(release_mismatch)
}

fn ensure_stage_member_chain(stage_root: &Path, relative: &Path) -> Result<(), PolicyError> {
    let mut current = stage_root.to_path_buf();
    let root = fs::symlink_metadata(&current).map_err(|_| release_mismatch())?;
    if root.file_type().is_symlink() || !root.is_dir() {
        return Err(release_mismatch());
    }
    let component_count = relative.components().count();
    for (index, component) in relative.components().enumerate() {
        let Component::Normal(component) = component else {
            return Err(release_mismatch());
        };
        current.push(component);
        let metadata = fs::symlink_metadata(&current).map_err(|_| release_mismatch())?;
        if metadata.file_type().is_symlink() {
            return Err(release_mismatch());
        }
        if index + 1 == component_count {
            if !metadata.is_file() {
                return Err(release_mismatch());
            }
        } else if !metadata.is_dir() {
            return Err(release_mismatch());
        }
    }
    Ok(())
}

fn hash_regular_file(path: &Path, expected_length: u64) -> Result<Digest32, PolicyError> {
    let file = open_no_follow(path).map_err(|_| release_mismatch())?;
    let metadata = file.metadata().map_err(|_| release_mismatch())?;
    if !metadata.is_file() || metadata.len() != expected_length {
        return Err(release_mismatch());
    }
    let read_limit = expected_length
        .checked_add(1)
        .ok_or_else(release_mismatch)?;
    let mut reader = file.take(read_limit);
    let mut hasher = Sha256::new();
    let mut length = 0_u64;
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = reader.read(&mut buffer).map_err(|_| release_mismatch())?;
        if read == 0 {
            break;
        }
        length = length
            .checked_add(u64::try_from(read).map_err(|_| release_mismatch())?)
            .ok_or_else(release_mismatch)?;
        hasher.update(&buffer[..read]);
    }
    if length != expected_length {
        return Err(release_mismatch());
    }
    Ok(Digest32::new(hasher.finalize().into()))
}

fn read_bounded_regular(
    path: &Path,
    maximum: u64,
    failure: StableCode,
) -> Result<Vec<u8>, PolicyError> {
    let file = open_no_follow(path).map_err(|_| PolicyError::stable(failure))?;
    let metadata = file.metadata().map_err(|_| PolicyError::stable(failure))?;
    if !metadata.is_file() || metadata.len() > maximum {
        return Err(PolicyError::stable(failure));
    }
    let capacity = usize::try_from(metadata.len()).map_err(|_| PolicyError::stable(failure))?;
    let mut bytes = Vec::with_capacity(capacity);
    let read_limit = maximum
        .checked_add(1)
        .ok_or_else(|| PolicyError::stable(failure))?;
    file.take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(|_| PolicyError::stable(failure))?;
    if u64::try_from(bytes.len()).map_or(true, |length| length > maximum) {
        return Err(PolicyError::stable(failure));
    }
    Ok(bytes)
}

fn open_no_follow(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags((OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC).bits())
        .open(path)
}

fn decode_manifest(bytes: &[u8]) -> Result<ReleaseManifestV1, PolicyError> {
    if u64::try_from(bytes.len()).map_or(true, |length| length > HardLimits::COMPILED.frame_bytes())
    {
        return Err(malformed());
    }
    let mut decoder = minicbor::Decoder::new(bytes);
    expect_array(&mut decoder, 25)?;
    let manifest = ReleaseManifestV1 {
        schema_version: decode_u16(&mut decoder)?,
        release_version: decode_bounded_text(&mut decoder)?,
        release_sequence: decode_u64(&mut decoder)?,
        release_target_id: decode_digest(&mut decoder)?,
        source_commit: decode_source_commit_text(&mut decoder)?,
        signing_key_id: decode_key_id(&mut decoder)?,
        binary_sha256: decode_digest(&mut decoder)?,
        cargo_lock_sha256: decode_digest(&mut decoder)?,
        rust_toolchain_sha256: decode_digest(&mut decoder)?,
        protocol_major: decode_u16(&mut decoder)?,
        minimum_minor: decode_u16(&mut decoder)?,
        maximum_minor: decode_u16(&mut decoder)?,
        supported_policy_schemas: decode_schema_versions(&mut decoder)?,
        supported_model_schemas: decode_schema_versions(&mut decoder)?,
        policy_trust_roots_digest: decode_digest(&mut decoder)?,
        minimum_policy_version: decode_u64(&mut decoder)?,
        model_manifest_digest: decode_digest(&mut decoder)?,
        producer_registry_digest: decode_digest(&mut decoder)?,
        ontology_digest: decode_digest(&mut decoder)?,
        approval_key_set_digest: decode_digest(&mut decoder)?,
        resource_profile_digest: decode_digest(&mut decoder)?,
        installation_profile_digest: decode_digest(&mut decoder)?,
        payloads: decode_release_files(&mut decoder)?,
        issued_at: UnixMillis::new(decode_u64(&mut decoder)?),
        expires_at: UnixMillis::new(decode_u64(&mut decoder)?),
    };
    require_end_and_canonical(&decoder, bytes, &encode_manifest(&manifest)?)?;
    Ok(manifest)
}

fn decode_release_trust_roots(bytes: &[u8]) -> Result<Vec<ReleaseTrustRootV1>, PolicyError> {
    if u64::try_from(bytes.len()).map_or(true, |length| length > HardLimits::COMPILED.frame_bytes())
    {
        return Err(malformed());
    }
    let mut decoder = minicbor::Decoder::new(bytes);
    let length = decode_bounded_array_length(&mut decoder, 1, MAXIMUM_RELEASE_ROOTS as u64)?;
    let mut roots = Vec::with_capacity(length);
    for _ in 0..length {
        expect_array(&mut decoder, 5)?;
        roots.push(ReleaseTrustRootV1 {
            key_id: decode_key_id(&mut decoder)?,
            public_key: decode_public_key(&mut decoder)?,
            not_before: UnixMillis::new(decode_u64(&mut decoder)?),
            not_after: UnixMillis::new(decode_u64(&mut decoder)?),
            revoked: decoder.bool().map_err(|_| malformed())?,
        });
    }
    require_end_and_canonical(&decoder, bytes, &encode_release_trust_roots(&roots)?)?;
    Ok(roots)
}

fn decode_profile(bytes: &[u8]) -> Result<KernelInstallationProfileV1, PolicyError> {
    if u64::try_from(bytes.len()).map_or(true, |length| length > HardLimits::COMPILED.frame_bytes())
    {
        return Err(malformed());
    }
    let mut decoder = minicbor::Decoder::new(bytes);
    expect_array(&mut decoder, 14)?;
    let schema_version = decode_u16(&mut decoder)?;
    let installation_id = decode_digest(&mut decoder)?;
    let platform = match decoder.u8().map_err(|_| malformed())? {
        0 => InstallationPlatformV1::Linux,
        1 => InstallationPlatformV1::MacOs,
        _ => return Err(malformed()),
    };
    let daemon_identity = decode_installation_public_key(&mut decoder)?;
    let daemon_clients = decode_clients(&mut decoder)?;
    let policy_trust_roots = decode_policy_roots(&mut decoder)?;
    let profile = KernelInstallationProfileV1 {
        schema_version,
        installation_id,
        platform,
        daemon_identity,
        daemon_clients,
        policy_trust_roots,
        daemon_uid: decode_u32(&mut decoder)?,
        daemon_gid: decode_u32(&mut decoder)?,
        jarvis_uid: decode_u32(&mut decoder)?,
        socket_path: decode_path_text(&mut decoder)?,
        selected_policy_path: decode_path_text(&mut decoder)?,
        selected_policy_signature_path: decode_path_text(&mut decoder)?,
        socket_parent_mode: decode_u16(&mut decoder)?,
        socket_mode: decode_u16(&mut decoder)?,
    };
    require_end_and_canonical(&decoder, bytes, &encode_profile(&profile)?)?;
    Ok(profile)
}

fn decode_installation_public_key(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<InstallationPublicKeyV1, PolicyError> {
    expect_array(decoder, 2)?;
    Ok(InstallationPublicKeyV1 {
        key_id: decode_key_id(decoder)?,
        public_key: decode_public_key(decoder)?,
    })
}

fn decode_clients(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<Vec<InstallationClientV1>, PolicyError> {
    let length = decode_bounded_array_length(decoder, 1, MAXIMUM_CLIENTS)?;
    let mut clients = Vec::with_capacity(length);
    for _ in 0..length {
        expect_array(decoder, 6)?;
        clients.push(InstallationClientV1 {
            client_id: decode_client_id(decoder)?,
            key_id: decode_key_id(decoder)?,
            public_key: decode_public_key(decoder)?,
            role: match decoder.u8().map_err(|_| malformed())? {
                0 => InstallationClientRoleV1::JarvisKernelClient,
                _ => return Err(malformed()),
            },
            peer_uid: decode_u32(decoder)?,
            peer_gid: decode_u32(decoder)?,
        });
    }
    Ok(clients)
}

fn decode_policy_roots(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<Vec<PolicyTrustRootV1>, PolicyError> {
    let length = decode_bounded_array_length(decoder, 1, MAXIMUM_POLICY_ROOTS)?;
    let mut roots = Vec::with_capacity(length);
    for _ in 0..length {
        expect_array(decoder, 4)?;
        roots.push(PolicyTrustRootV1 {
            key_id: decode_key_id(decoder)?,
            public_key: decode_public_key(decoder)?,
            epoch: decode_u64(decoder)?,
            revoked: decoder.bool().map_err(|_| malformed())?,
        });
    }
    Ok(roots)
}

fn decode_release_files(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<Vec<ReleaseFileV1>, PolicyError> {
    let maximum = HardLimits::COMPILED
        .model_assets()
        .checked_add(16)
        .ok_or_else(malformed)?;
    let length = decode_bounded_array_length(decoder, 1, maximum)?;
    let mut files = Vec::with_capacity(length);
    for _ in 0..length {
        expect_array(decoder, 3)?;
        let relative_path = decode_relative_path(decoder)?;
        files.push(ReleaseFileV1 {
            relative_path,
            byte_length: decode_u64(decoder)?,
            sha256: decode_digest(decoder)?,
        });
    }
    if !files.windows(2).all(|pair| {
        matches!(
            pair,
            [left, right]
                if canonical_text_cmp(&left.relative_path, &right.relative_path)
                    == Ordering::Less
        )
    }) {
        return Err(malformed());
    }
    Ok(files)
}

fn decode_schema_versions(decoder: &mut minicbor::Decoder<'_>) -> Result<Vec<u16>, PolicyError> {
    let length = decode_bounded_array_length(decoder, 1, MAXIMUM_SCHEMA_VERSIONS)?;
    let mut values = Vec::with_capacity(length);
    for _ in 0..length {
        values.push(decode_u16(decoder)?);
    }
    if !values
        .windows(2)
        .all(|pair| matches!(pair, [left, right] if left < right))
    {
        return Err(malformed());
    }
    Ok(values)
}

fn encode_manifest(manifest: &ReleaseManifestV1) -> Result<Vec<u8>, PolicyError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(25)
        .map_err(PolicyError::io)?
        .u16(manifest.schema_version)
        .map_err(PolicyError::io)?
        .str(&manifest.release_version)
        .map_err(PolicyError::io)?
        .u64(manifest.release_sequence)
        .map_err(PolicyError::io)?
        .bytes(manifest.release_target_id.as_bytes())
        .map_err(PolicyError::io)?
        .str(&manifest.source_commit)
        .map_err(PolicyError::io)?
        .str(manifest.signing_key_id.as_str())
        .map_err(PolicyError::io)?
        .bytes(manifest.binary_sha256.as_bytes())
        .map_err(PolicyError::io)?
        .bytes(manifest.cargo_lock_sha256.as_bytes())
        .map_err(PolicyError::io)?
        .bytes(manifest.rust_toolchain_sha256.as_bytes())
        .map_err(PolicyError::io)?
        .u16(manifest.protocol_major)
        .map_err(PolicyError::io)?
        .u16(manifest.minimum_minor)
        .map_err(PolicyError::io)?
        .u16(manifest.maximum_minor)
        .map_err(PolicyError::io)?;
    encode_u16_array(&mut encoder, &manifest.supported_policy_schemas)?;
    encode_u16_array(&mut encoder, &manifest.supported_model_schemas)?;
    encoder
        .bytes(manifest.policy_trust_roots_digest.as_bytes())
        .map_err(PolicyError::io)?
        .u64(manifest.minimum_policy_version)
        .map_err(PolicyError::io)?
        .bytes(manifest.model_manifest_digest.as_bytes())
        .map_err(PolicyError::io)?
        .bytes(manifest.producer_registry_digest.as_bytes())
        .map_err(PolicyError::io)?
        .bytes(manifest.ontology_digest.as_bytes())
        .map_err(PolicyError::io)?
        .bytes(manifest.approval_key_set_digest.as_bytes())
        .map_err(PolicyError::io)?
        .bytes(manifest.resource_profile_digest.as_bytes())
        .map_err(PolicyError::io)?
        .bytes(manifest.installation_profile_digest.as_bytes())
        .map_err(PolicyError::io)?
        .array(manifest.payloads.len() as u64)
        .map_err(PolicyError::io)?;
    for payload in &manifest.payloads {
        encoder
            .array(3)
            .map_err(PolicyError::io)?
            .str(&payload.relative_path)
            .map_err(PolicyError::io)?
            .u64(payload.byte_length)
            .map_err(PolicyError::io)?
            .bytes(payload.sha256.as_bytes())
            .map_err(PolicyError::io)?;
    }
    encoder
        .u64(manifest.issued_at.get())
        .map_err(PolicyError::io)?
        .u64(manifest.expires_at.get())
        .map_err(PolicyError::io)?;
    Ok(encoder.into_writer())
}

fn encode_profile(profile: &KernelInstallationProfileV1) -> Result<Vec<u8>, PolicyError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(14)
        .map_err(PolicyError::io)?
        .u16(profile.schema_version)
        .map_err(PolicyError::io)?
        .bytes(profile.installation_id.as_bytes())
        .map_err(PolicyError::io)?
        .u8(profile.platform.tag())
        .map_err(PolicyError::io)?;
    encode_installation_public_key(&mut encoder, &profile.daemon_identity)?;
    encoder
        .array(profile.daemon_clients.len() as u64)
        .map_err(PolicyError::io)?;
    for client in &profile.daemon_clients {
        encoder
            .array(6)
            .map_err(PolicyError::io)?
            .str(client.client_id.as_str())
            .map_err(PolicyError::io)?
            .str(client.key_id.as_str())
            .map_err(PolicyError::io)?
            .bytes(&client.public_key)
            .map_err(PolicyError::io)?
            .u8(client.role.tag())
            .map_err(PolicyError::io)?
            .u32(client.peer_uid)
            .map_err(PolicyError::io)?
            .u32(client.peer_gid)
            .map_err(PolicyError::io)?;
    }
    encode_policy_roots_into(&mut encoder, &profile.policy_trust_roots)?;
    encoder
        .u32(profile.daemon_uid)
        .map_err(PolicyError::io)?
        .u32(profile.daemon_gid)
        .map_err(PolicyError::io)?
        .u32(profile.jarvis_uid)
        .map_err(PolicyError::io)?
        .str(&profile.socket_path)
        .map_err(PolicyError::io)?
        .str(&profile.selected_policy_path)
        .map_err(PolicyError::io)?
        .str(&profile.selected_policy_signature_path)
        .map_err(PolicyError::io)?
        .u16(profile.socket_parent_mode)
        .map_err(PolicyError::io)?
        .u16(profile.socket_mode)
        .map_err(PolicyError::io)?;
    Ok(encoder.into_writer())
}

fn encode_release_trust_roots(roots: &[ReleaseTrustRootV1]) -> Result<Vec<u8>, PolicyError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder.array(roots.len() as u64).map_err(PolicyError::io)?;
    for root in roots {
        encoder
            .array(5)
            .map_err(PolicyError::io)?
            .str(root.key_id.as_str())
            .map_err(PolicyError::io)?
            .bytes(&root.public_key)
            .map_err(PolicyError::io)?
            .u64(root.not_before.get())
            .map_err(PolicyError::io)?
            .u64(root.not_after.get())
            .map_err(PolicyError::io)?
            .bool(root.revoked)
            .map_err(PolicyError::io)?;
    }
    Ok(encoder.into_writer())
}

fn encode_installation_public_key(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    value: &InstallationPublicKeyV1,
) -> Result<(), PolicyError> {
    encoder
        .array(2)
        .map_err(PolicyError::io)?
        .str(value.key_id.as_str())
        .map_err(PolicyError::io)?
        .bytes(&value.public_key)
        .map_err(PolicyError::io)?;
    Ok(())
}

fn encode_policy_roots(values: &[PolicyTrustRootV1]) -> Result<Vec<u8>, PolicyError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encode_policy_roots_into(&mut encoder, values)?;
    Ok(encoder.into_writer())
}

fn encode_policy_roots_into(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    values: &[PolicyTrustRootV1],
) -> Result<(), PolicyError> {
    encoder
        .array(values.len() as u64)
        .map_err(PolicyError::io)?;
    for root in values {
        encoder
            .array(4)
            .map_err(PolicyError::io)?
            .str(root.key_id.as_str())
            .map_err(PolicyError::io)?
            .bytes(&root.public_key)
            .map_err(PolicyError::io)?
            .u64(root.epoch)
            .map_err(PolicyError::io)?
            .bool(root.revoked)
            .map_err(PolicyError::io)?;
    }
    Ok(())
}

fn compute_release_target(manifest: &ReleaseManifestV1) -> Result<Digest32, PolicyError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(7)
        .map_err(PolicyError::io)?
        .u16(manifest.protocol_major)
        .map_err(PolicyError::io)?
        .u16(manifest.minimum_minor)
        .map_err(PolicyError::io)?
        .u16(manifest.maximum_minor)
        .map_err(PolicyError::io)?;
    encode_u16_array(&mut encoder, &manifest.supported_policy_schemas)?;
    encoder
        .bytes(manifest.policy_trust_roots_digest.as_bytes())
        .map_err(PolicyError::io)?
        .bytes(manifest.resource_profile_digest.as_bytes())
        .map_err(PolicyError::io)?
        .bytes(manifest.installation_profile_digest.as_bytes())
        .map_err(PolicyError::io)?;
    Ok(domain_hash(RELEASE_TARGET_DOMAIN, &encoder.into_writer()))
}

fn encode_u16_array(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    values: &[u16],
) -> Result<(), PolicyError> {
    encoder
        .array(values.len() as u64)
        .map_err(PolicyError::io)?;
    for value in values {
        encoder.u16(*value).map_err(PolicyError::io)?;
    }
    Ok(())
}

fn require_end_and_canonical(
    decoder: &minicbor::Decoder<'_>,
    original: &[u8],
    canonical: &[u8],
) -> Result<(), PolicyError> {
    if decoder.position() != original.len() {
        return Err(malformed());
    }
    if original != canonical {
        return Err(PolicyError::stable(StableCode::ProtocolNonCanonicalCbor));
    }
    Ok(())
}

fn decode_bounded_array_length(
    decoder: &mut minicbor::Decoder<'_>,
    minimum: u64,
    maximum: u64,
) -> Result<usize, PolicyError> {
    let length = decoder
        .array()
        .map_err(|_| malformed())?
        .ok_or_else(malformed)?;
    if !(minimum..=maximum).contains(&length) {
        return Err(malformed());
    }
    usize::try_from(length).map_err(|_| malformed())
}

fn expect_array(decoder: &mut minicbor::Decoder<'_>, expected: u64) -> Result<(), PolicyError> {
    match decoder.array().map_err(|_| malformed())? {
        Some(actual) if actual == expected => Ok(()),
        _ => Err(malformed()),
    }
}

fn decode_digest(decoder: &mut minicbor::Decoder<'_>) -> Result<Digest32, PolicyError> {
    let bytes: [u8; 32] = decoder
        .bytes()
        .map_err(|_| malformed())?
        .try_into()
        .map_err(|_| malformed())?;
    Ok(Digest32::new(bytes))
}

fn decode_public_key(decoder: &mut minicbor::Decoder<'_>) -> Result<[u8; 32], PolicyError> {
    decoder
        .bytes()
        .map_err(|_| malformed())?
        .try_into()
        .map_err(|_| malformed())
}

fn decode_key_id(decoder: &mut minicbor::Decoder<'_>) -> Result<KeyId, PolicyError> {
    let value = decoder.str().map_err(|_| malformed())?;
    KeyId::try_from(value).map_err(PolicyError::from)
}

fn decode_client_id(decoder: &mut minicbor::Decoder<'_>) -> Result<ClientId, PolicyError> {
    let value = decoder.str().map_err(|_| malformed())?;
    ClientId::try_from(value).map_err(PolicyError::from)
}

fn decode_bounded_text(decoder: &mut minicbor::Decoder<'_>) -> Result<String, PolicyError> {
    let value = decoder.str().map_err(|_| malformed())?;
    if !(1..=128).contains(&value.len()) || value.chars().any(char::is_control) {
        return Err(malformed());
    }
    Ok(value.to_owned())
}

fn decode_source_commit_text(decoder: &mut minicbor::Decoder<'_>) -> Result<String, PolicyError> {
    let value = decoder.str().map_err(|_| malformed())?;
    if !valid_source_commit(value) {
        return Err(malformed());
    }
    Ok(value.to_owned())
}

fn decode_path_text(decoder: &mut minicbor::Decoder<'_>) -> Result<String, PolicyError> {
    let value = decoder.str().map_err(|_| malformed())?;
    if value.is_empty()
        || value.len() > MAXIMUM_RELATIVE_PATH_BYTES
        || !value.starts_with('/')
        || value.chars().any(char::is_control)
    {
        return Err(malformed());
    }
    Ok(value.to_owned())
}

fn decode_relative_path(decoder: &mut minicbor::Decoder<'_>) -> Result<String, PolicyError> {
    let value = decoder.str().map_err(|_| malformed())?;
    if !valid_relative_path(value) || !allowed_payload_path(value) {
        return Err(malformed());
    }
    Ok(value.to_owned())
}

fn decode_u16(decoder: &mut minicbor::Decoder<'_>) -> Result<u16, PolicyError> {
    decoder.u16().map_err(|_| malformed())
}

fn decode_u32(decoder: &mut minicbor::Decoder<'_>) -> Result<u32, PolicyError> {
    decoder.u32().map_err(|_| malformed())
}

fn decode_u64(decoder: &mut minicbor::Decoder<'_>) -> Result<u64, PolicyError> {
    decoder.u64().map_err(|_| malformed())
}

fn valid_source_commit(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

fn valid_relative_path(value: &str) -> bool {
    if value.is_empty()
        || value.len() > MAXIMUM_RELATIVE_PATH_BYTES
        || value.starts_with('/')
        || value.contains('\\')
        || value.contains('\0')
        || value.chars().any(char::is_control)
    {
        return false;
    }
    value
        .split('/')
        .all(|component| !component.is_empty() && component != "." && component != "..")
}

fn allowed_payload_path(value: &str) -> bool {
    FIXED_PAYLOAD_PATHS.contains(&value)
        || matches!(
            value,
            "runtime/libonnxruntime.so" | "runtime/libonnxruntime.dylib"
        )
        || value.starts_with("model/assets/")
}

fn canonical_text_cmp(left: &str, right: &str) -> Ordering {
    left.len()
        .cmp(&right.len())
        .then_with(|| left.as_bytes().cmp(right.as_bytes()))
}

fn hash_bytes(bytes: &[u8]) -> Digest32 {
    Digest32::new(Sha256::digest(bytes).into())
}

fn domain_hash(domain: &[u8], bytes: &[u8]) -> Digest32 {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    Digest32::new(hasher.finalize().into())
}

fn malformed() -> PolicyError {
    PolicyError::stable(StableCode::ProtocolMalformedCbor)
}

fn invalid_signature() -> PolicyError {
    PolicyError::stable(StableCode::IdentityInvalidSignature)
}

fn release_mismatch() -> PolicyError {
    PolicyError::stable(StableCode::IdentityReleaseMismatch)
}

#[cfg(test)]
mod release_stage_tests;
