use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

use ed25519_dalek::SigningKey;
use nix::fcntl::OFlag;
use savana_kernel_protocol::StableCode;
use zeroize::Zeroizing;

use crate::DaemonError;

pub struct DaemonSigningIdentity {
    signing_key: SigningKey,
}

impl DaemonSigningIdentity {
    pub(crate) fn public_key(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }
}

impl std::fmt::Debug for DaemonSigningIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DaemonSigningIdentity(<redacted>)")
    }
}

pub fn load_daemon_signing_key(
    path: &Path,
    expected_uid: u32,
) -> Result<DaemonSigningIdentity, DaemonError> {
    validate_path_components(path)?;
    let mut file = open_no_follow(path).map_err(|_| key_permissions())?;
    let metadata = file.metadata().map_err(|_| key_permissions())?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != expected_uid
        || metadata.mode() & 0o7777 != 0o600
    {
        return Err(key_permissions());
    }

    let mut seed = Zeroizing::new([0_u8; 32]);
    file.read_exact(seed.as_mut())
        .map_err(|_| key_permissions())?;
    let mut trailing = [0_u8; 1];
    if file.read(&mut trailing).map_err(|_| key_permissions())? != 0 {
        return Err(key_permissions());
    }
    Ok(DaemonSigningIdentity {
        signing_key: SigningKey::from_bytes(&seed),
    })
}

fn validate_path_components(path: &Path) -> Result<(), DaemonError> {
    if !path.is_absolute() {
        return Err(key_permissions());
    }
    let mut current = PathBuf::from("/");
    let components: Vec<_> = path.components().collect();
    for (index, component) in components.iter().enumerate() {
        match component {
            Component::RootDir => continue,
            Component::Normal(value) => current.push(value),
            _ => return Err(key_permissions()),
        }
        let metadata = std::fs::symlink_metadata(&current).map_err(|_| key_permissions())?;
        if metadata.file_type().is_symlink() {
            return Err(key_permissions());
        }
        let is_final = index + 1 == components.len();
        if (is_final && !metadata.is_file()) || (!is_final && !metadata.is_dir()) {
            return Err(key_permissions());
        }
    }
    Ok(())
}

fn open_no_follow(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags((OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC).bits())
        .open(path)
}

fn key_permissions() -> DaemonError {
    DaemonError::stable(StableCode::IdentityKeyPermissions)
}
