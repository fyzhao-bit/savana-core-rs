use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io::Read as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;
use std::path::PathBuf;

#[cfg(any(
    target_os = "linux",
    target_os = "macos",
    test,
    feature = "test-support"
))]
use rustix::fs::open;
use rustix::fs::{openat, statat, AtFlags, FileType, Mode, OFlags};

use crate::NativeIdentityErrorV2;

const TRANSACTION_DESCRIPTOR_LEAF_V2: &str = "DeploymentTransactionV2.cbor";
const MAX_TRANSACTION_DESCRIPTOR_BYTES_V2: u64 = 1_048_576;

#[cfg(target_os = "linux")]
#[path = "linux_staging_v3.rs"]
mod staging_v3;
#[cfg(target_os = "linux")]
pub use staging_v3::{LinuxMeasuredStagingTreeV3, MeasuredStagingEntryV3};

pub fn harden_root_deployment_process_v2() -> Result<(), NativeIdentityErrorV2> {
    if rustix::process::geteuid().as_raw() != 0 {
        return Err(NativeIdentityErrorV2::InvalidDeploymentInvocation);
    }
    rustix::process::umask(Mode::from_bits_truncate(0o077));
    std::env::set_current_dir(Path::new("/"))
        .map_err(|_| NativeIdentityErrorV2::InvalidDeploymentInvocation)?;
    for key in std::env::vars_os().map(|(key, _)| key).collect::<Vec<_>>() {
        std::env::remove_var(key);
    }
    let maximum = nix::unistd::sysconf(nix::unistd::SysconfVar::OPEN_MAX)
        .map_err(|_| NativeIdentityErrorV2::InvalidDeploymentInvocation)?
        .ok_or(NativeIdentityErrorV2::InvalidDeploymentInvocation)?;
    let maximum =
        i32::try_from(maximum).map_err(|_| NativeIdentityErrorV2::InvalidDeploymentInvocation)?;
    for descriptor in 0..maximum {
        if descriptor != 2 {
            let _ = nix::unistd::close(descriptor);
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeploymentApplySelectorV2([u8; 32]);

impl DeploymentApplySelectorV2 {
    pub fn parse_arguments(
        mut arguments: impl Iterator<Item = OsString>,
    ) -> Result<Self, NativeIdentityErrorV2> {
        let program = arguments
            .next()
            .ok_or(NativeIdentityErrorV2::InvalidDeploymentInvocation)?;
        let verb = arguments
            .next()
            .ok_or(NativeIdentityErrorV2::InvalidDeploymentInvocation)?;
        let selector = arguments
            .next()
            .ok_or(NativeIdentityErrorV2::InvalidDeploymentInvocation)?;
        if program.is_empty() || verb != OsStr::new("apply") || arguments.next().is_some() {
            return Err(NativeIdentityErrorV2::InvalidDeploymentInvocation);
        }
        let selector = selector
            .to_str()
            .ok_or(NativeIdentityErrorV2::InvalidDeploymentInvocation)?;
        if selector.len() != 64
            || !selector
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(NativeIdentityErrorV2::InvalidDeploymentInvocation);
        }
        let mut bytes = [0_u8; 32];
        for (index, pair) in selector.as_bytes().chunks_exact(2).enumerate() {
            bytes[index] = (decode_hex_nibble(pair[0])
                .ok_or(NativeIdentityErrorV2::InvalidDeploymentInvocation)?
                << 4)
                | decode_hex_nibble(pair[1])
                    .ok_or(NativeIdentityErrorV2::InvalidDeploymentInvocation)?;
        }
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(NativeIdentityErrorV2::InvalidDeploymentInvocation);
        }
        Ok(Self(bytes))
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    fn leaf(self) -> String {
        hex(&self.0)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct StagedDeploymentTransactionBytesV2 {
    staging_id: DeploymentApplySelectorV2,
    descriptor_bytes: Vec<u8>,
}

impl std::fmt::Debug for StagedDeploymentTransactionBytesV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StagedDeploymentTransactionBytesV2")
            .field("staging_id", &self.staging_id)
            .field("descriptor_length", &self.descriptor_bytes.len())
            .finish_non_exhaustive()
    }
}

impl StagedDeploymentTransactionBytesV2 {
    pub const fn staging_id(&self) -> DeploymentApplySelectorV2 {
        self.staging_id
    }

    pub fn descriptor_bytes(&self) -> &[u8] {
        &self.descriptor_bytes
    }
}

pub struct FixedDeploymentSpoolV2 {
    ready: File,
    ready_path: PathBuf,
    ready_dev: u64,
    ready_ino: u64,
    owner_uid: u32,
    owner_gid: u32,
}

impl std::fmt::Debug for FixedDeploymentSpoolV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FixedDeploymentSpoolV2")
            .field("ready_path", &self.ready_path)
            .finish_non_exhaustive()
    }
}

impl FixedDeploymentSpoolV2 {
    pub fn open_fixed_platform() -> Result<Self, NativeIdentityErrorV2> {
        #[cfg(target_os = "linux")]
        {
            Self::open_fixed_linux()
        }
        #[cfg(target_os = "macos")]
        {
            Self::open_fixed_macos()
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            Err(NativeIdentityErrorV2::InvalidDeploymentInvocation)
        }
    }

    #[cfg(target_os = "linux")]
    pub fn open_fixed_linux() -> Result<Self, NativeIdentityErrorV2> {
        if rustix::process::geteuid().as_raw() != 0 {
            return Err(NativeIdentityErrorV2::InvalidDeploymentInvocation);
        }
        Self::open_component_chain(
            Path::new("/"),
            0,
            0,
            &["var", "lib", "savana-deploy", "spool", "ready"],
            2,
        )
    }

    #[cfg(target_os = "macos")]
    pub fn open_fixed_macos() -> Result<Self, NativeIdentityErrorV2> {
        if rustix::process::geteuid().as_raw() != 0 {
            return Err(NativeIdentityErrorV2::InvalidDeploymentInvocation);
        }
        Self::open_component_chain(
            Path::new("/"),
            0,
            0,
            &[
                "Library",
                "Application Support",
                "Savana",
                "Deployment",
                "spool",
                "ready",
            ],
            2,
        )
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn open_for_test(ready_path: &Path) -> Result<Self, NativeIdentityErrorV2> {
        let metadata = fs::symlink_metadata(ready_path)
            .map_err(|_| NativeIdentityErrorV2::UnsafeDeploymentSpool)?;
        Self::open_anchored(ready_path, metadata.uid(), metadata.gid())
    }

    #[cfg(test)]
    pub(crate) fn open_compiled_chain_for_test(
        root: &Path,
        components: &[&str],
    ) -> Result<Self, NativeIdentityErrorV2> {
        let metadata =
            fs::symlink_metadata(root).map_err(|_| NativeIdentityErrorV2::UnsafeDeploymentSpool)?;
        Self::open_component_chain(root, metadata.uid(), metadata.gid(), components, 0)
    }

    #[cfg(any(target_os = "linux", target_os = "macos", test))]
    fn open_component_chain(
        root: &Path,
        owner_uid: u32,
        owner_gid: u32,
        components: &[&str],
        private_component_index: usize,
    ) -> Result<Self, NativeIdentityErrorV2> {
        if !root.is_absolute()
            || components.is_empty()
            || components.len() > 8
            || private_component_index >= components.len()
            || components
                .iter()
                .any(|component| component.is_empty() || !valid_compiled_component(component))
        {
            return Err(NativeIdentityErrorV2::UnsafeDeploymentSpool);
        }
        let root_metadata =
            fs::symlink_metadata(root).map_err(|_| NativeIdentityErrorV2::UnsafeDeploymentSpool)?;
        if root_metadata.file_type().is_symlink()
            || !root_metadata.is_dir()
            || root_metadata.uid() != owner_uid
            || root_metadata.gid() != owner_gid
            || root_metadata.mode() & 0o022 != 0
        {
            return Err(NativeIdentityErrorV2::UnsafeDeploymentSpool);
        }
        let descriptor = open(
            root,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| NativeIdentityErrorV2::UnsafeDeploymentSpool)?;
        let mut parent = File::from(descriptor);
        let opened_root = parent
            .metadata()
            .map_err(|_| NativeIdentityErrorV2::UnsafeDeploymentSpool)?;
        if !opened_root.is_dir()
            || opened_root.dev() != root_metadata.dev()
            || opened_root.ino() != root_metadata.ino()
            || opened_root.uid() != owner_uid
            || opened_root.gid() != owner_gid
            || opened_root.mode() & 0o022 != 0
        {
            return Err(NativeIdentityErrorV2::UnsafeDeploymentSpool);
        }

        let mut private_dev = None;
        let mut ready_path = root.to_owned();
        for (index, component) in components.iter().enumerate() {
            let linked = statat(&parent, *component, AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|_| NativeIdentityErrorV2::UnsafeDeploymentSpool)?;
            let private = index >= private_component_index;
            if FileType::from_raw_mode(linked.st_mode) != FileType::Directory
                || linked.st_uid != owner_uid
                || linked.st_gid != owner_gid
                || (private && linked.st_mode & 0o7777 != 0o700)
                || (!private && linked.st_mode & 0o022 != 0)
                || private_dev.is_some_and(|dev| linked.st_dev != dev)
            {
                return Err(NativeIdentityErrorV2::UnsafeDeploymentSpool);
            }
            let descriptor = openat(
                &parent,
                *component,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| NativeIdentityErrorV2::UnsafeDeploymentSpool)?;
            let opened = File::from(descriptor);
            let metadata = opened
                .metadata()
                .map_err(|_| NativeIdentityErrorV2::UnsafeDeploymentSpool)?;
            if !metadata.is_dir()
                || metadata.dev() as i128 != linked.st_dev as i128
                || metadata.ino() != linked.st_ino
                || metadata.uid() != owner_uid
                || metadata.gid() != owner_gid
                || (private && metadata.mode() & 0o7777 != 0o700)
                || (!private && metadata.mode() & 0o022 != 0)
            {
                return Err(NativeIdentityErrorV2::UnsafeDeploymentSpool);
            }
            if index == private_component_index {
                private_dev = Some(linked.st_dev);
            }
            ready_path.push(component);
            parent = opened;
        }
        Self::from_opened_ready(parent, ready_path, owner_uid, owner_gid)
    }

    #[cfg(any(test, feature = "test-support"))]
    fn open_anchored(
        ready_path: &Path,
        owner_uid: u32,
        owner_gid: u32,
    ) -> Result<Self, NativeIdentityErrorV2> {
        if !ready_path.is_absolute() {
            return Err(NativeIdentityErrorV2::UnsafeDeploymentSpool);
        }
        let before = fs::symlink_metadata(ready_path)
            .map_err(|_| NativeIdentityErrorV2::UnsafeDeploymentSpool)?;
        if before.file_type().is_symlink()
            || !before.is_dir()
            || before.uid() != owner_uid
            || before.gid() != owner_gid
            || before.mode() & 0o7777 != 0o700
        {
            return Err(NativeIdentityErrorV2::UnsafeDeploymentSpool);
        }
        let descriptor = open(
            ready_path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| NativeIdentityErrorV2::UnsafeDeploymentSpool)?;
        let ready = File::from(descriptor);
        let opened = ready
            .metadata()
            .map_err(|_| NativeIdentityErrorV2::UnsafeDeploymentSpool)?;
        if !opened.is_dir()
            || opened.dev() != before.dev()
            || opened.ino() != before.ino()
            || opened.uid() != owner_uid
            || opened.gid() != owner_gid
            || opened.mode() & 0o7777 != 0o700
        {
            return Err(NativeIdentityErrorV2::UnsafeDeploymentSpool);
        }
        let value = Self::from_opened_ready(ready, ready_path.to_owned(), owner_uid, owner_gid)?;
        value.recheck_ready()?;
        Ok(value)
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "macos",
        test,
        feature = "test-support"
    ))]
    fn from_opened_ready(
        ready: File,
        ready_path: PathBuf,
        owner_uid: u32,
        owner_gid: u32,
    ) -> Result<Self, NativeIdentityErrorV2> {
        let opened = ready
            .metadata()
            .map_err(|_| NativeIdentityErrorV2::UnsafeDeploymentSpool)?;
        if !opened.is_dir()
            || opened.uid() != owner_uid
            || opened.gid() != owner_gid
            || opened.mode() & 0o7777 != 0o700
        {
            return Err(NativeIdentityErrorV2::UnsafeDeploymentSpool);
        }
        let value = Self {
            ready,
            ready_path,
            ready_dev: opened.dev(),
            ready_ino: opened.ino(),
            owner_uid,
            owner_gid,
        };
        value.recheck_ready()?;
        Ok(value)
    }

    pub fn open_transaction(
        &self,
        selector: DeploymentApplySelectorV2,
    ) -> Result<StagedDeploymentTransactionBytesV2, NativeIdentityErrorV2> {
        self.recheck_ready()?;
        let selector_leaf = selector.leaf();
        let before = statat(
            &self.ready,
            selector_leaf.as_str(),
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|_| NativeIdentityErrorV2::UnsafeDeploymentSpool)?;
        if FileType::from_raw_mode(before.st_mode) != FileType::Directory
            || before.st_uid != self.owner_uid
            || before.st_gid != self.owner_gid
            || before.st_mode & 0o7777 != 0o700
            || before.st_dev as i128 != self.ready_dev as i128
        {
            return Err(NativeIdentityErrorV2::UnsafeDeploymentSpool);
        }
        let descriptor = openat(
            &self.ready,
            selector_leaf.as_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| NativeIdentityErrorV2::UnsafeDeploymentSpool)?;
        let staged = File::from(descriptor);
        let opened = staged
            .metadata()
            .map_err(|_| NativeIdentityErrorV2::UnsafeDeploymentSpool)?;
        if !opened.is_dir()
            || opened.dev() != self.ready_dev
            || opened.dev() as i128 != before.st_dev as i128
            || opened.ino() != before.st_ino
            || opened.uid() != self.owner_uid
            || opened.gid() != self.owner_gid
            || opened.mode() & 0o7777 != 0o700
        {
            return Err(NativeIdentityErrorV2::UnsafeDeploymentSpool);
        }

        let descriptor_bytes =
            read_fixed_descriptor(&staged, self.owner_uid, self.owner_gid, opened.dev())?;
        let after = statat(
            &self.ready,
            selector_leaf.as_str(),
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|_| NativeIdentityErrorV2::UnsafeDeploymentSpool)?;
        if after.st_dev != before.st_dev
            || after.st_ino != before.st_ino
            || after.st_mode != before.st_mode
            || after.st_uid != before.st_uid
            || after.st_gid != before.st_gid
        {
            return Err(NativeIdentityErrorV2::UnsafeDeploymentSpool);
        }
        self.recheck_ready()?;
        Ok(StagedDeploymentTransactionBytesV2 {
            staging_id: selector,
            descriptor_bytes,
        })
    }

    fn recheck_ready(&self) -> Result<(), NativeIdentityErrorV2> {
        let opened = self
            .ready
            .metadata()
            .map_err(|_| NativeIdentityErrorV2::UnsafeDeploymentSpool)?;
        let linked = fs::symlink_metadata(&self.ready_path)
            .map_err(|_| NativeIdentityErrorV2::UnsafeDeploymentSpool)?;
        if linked.file_type().is_symlink()
            || !linked.is_dir()
            || opened.dev() != self.ready_dev
            || opened.ino() != self.ready_ino
            || linked.dev() != self.ready_dev
            || linked.ino() != self.ready_ino
            || linked.uid() != self.owner_uid
            || linked.gid() != self.owner_gid
            || linked.mode() & 0o7777 != 0o700
        {
            return Err(NativeIdentityErrorV2::UnsafeDeploymentSpool);
        }
        Ok(())
    }
}

fn valid_compiled_component(component: &str) -> bool {
    let bytes = component.as_bytes();
    !bytes.is_empty()
        && bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b' '))
        && !bytes.windows(2).any(|pair| pair == b"  ")
}

fn read_fixed_descriptor(
    staged: &File,
    owner_uid: u32,
    owner_gid: u32,
    expected_dev: u64,
) -> Result<Vec<u8>, NativeIdentityErrorV2> {
    let leaf = OsStr::new(TRANSACTION_DESCRIPTOR_LEAF_V2);
    let before = statat(staged, leaf, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| NativeIdentityErrorV2::UnsafeDeploymentSpool)?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || before.st_uid != owner_uid
        || before.st_gid != owner_gid
        || before.st_mode & 0o7777 != 0o400
        || before.st_nlink != 1
        || before.st_dev as i128 != expected_dev as i128
        || before.st_size <= 0
        || u64::try_from(before.st_size)
            .ok()
            .is_none_or(|size| size > MAX_TRANSACTION_DESCRIPTOR_BYTES_V2)
    {
        return Err(NativeIdentityErrorV2::UnsafeDeploymentSpool);
    }
    let descriptor = openat(
        staged,
        leaf,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| NativeIdentityErrorV2::UnsafeDeploymentSpool)?;
    let mut file = File::from(descriptor);
    let opened = file
        .metadata()
        .map_err(|_| NativeIdentityErrorV2::UnsafeDeploymentSpool)?;
    if !opened.is_file()
        || opened.dev() != expected_dev
        || opened.dev() as i128 != before.st_dev as i128
        || opened.ino() != before.st_ino
        || opened.uid() != owner_uid
        || opened.gid() != owner_gid
        || opened.mode() & 0o7777 != 0o400
        || opened.nlink() != 1
        || opened.len() == 0
        || opened.len() > MAX_TRANSACTION_DESCRIPTOR_BYTES_V2
    {
        return Err(NativeIdentityErrorV2::UnsafeDeploymentSpool);
    }
    let expected_length =
        usize::try_from(opened.len()).map_err(|_| NativeIdentityErrorV2::UnsafeDeploymentSpool)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(expected_length)
        .map_err(|_| NativeIdentityErrorV2::UnsafeDeploymentSpool)?;
    file.read_to_end(&mut bytes)
        .map_err(|_| NativeIdentityErrorV2::UnsafeDeploymentSpool)?;
    let after = statat(staged, leaf, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| NativeIdentityErrorV2::UnsafeDeploymentSpool)?;
    if bytes.len() != expected_length
        || after.st_dev != before.st_dev
        || after.st_ino != before.st_ino
        || after.st_mode != before.st_mode
        || after.st_uid != before.st_uid
        || after.st_gid != before.st_gid
        || after.st_nlink != before.st_nlink
        || after.st_size != before.st_size
    {
        return Err(NativeIdentityErrorV2::UnsafeDeploymentSpool);
    }
    Ok(bytes)
}

const fn decode_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        value.push(char::from(DIGITS[usize::from(byte >> 4)]));
        value.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    value
}
