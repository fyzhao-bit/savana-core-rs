use std::fs::{self, File};
use std::io::Write as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::PathBuf;

use hmac::{Hmac, Mac as _};
use savana_kernel_protocol::v2::Digest32V2;
use sha2::Sha256;
use zeroize::Zeroizing;

const ANCHOR_BYTES_V2: usize = 80;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AuthenticatedFileAnchorErrorV2 {
    #[error("authenticated rollback anchor binding is invalid")]
    InvalidBinding,
    #[error("authenticated rollback anchor failed authentication")]
    Authentication,
    #[error("authenticated rollback anchor detected rollback")]
    Rollback,
    #[error("authenticated rollback anchor commit outcome is uncertain")]
    CommitUncertain,
}

/// Authenticated, atomically replaced rollback-head file.
///
/// This is the filesystem backend used only when the signed deployment names
/// the matching rollback authority. Hardware/native authorities can keep the
/// same compare-and-advance surface without exposing their secret.
pub struct AuthenticatedFileAnchorV2 {
    path: PathBuf,
    installation_id: Digest32V2,
    store_id: Digest32V2,
    authentication_key: Zeroizing<[u8; 32]>,
    mac_domain: &'static [u8],
    magic: [u8; 8],
}

impl std::fmt::Debug for AuthenticatedFileAnchorV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthenticatedFileAnchorV2")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl AuthenticatedFileAnchorV2 {
    pub fn new(
        path: PathBuf,
        installation_id: Digest32V2,
        store_id: Digest32V2,
        authentication_key: [u8; 32],
        mac_domain: &'static [u8],
        magic: [u8; 8],
    ) -> Result<Self, AuthenticatedFileAnchorErrorV2> {
        if !path.is_absolute()
            || installation_id.as_bytes() == &[0; 32]
            || store_id.as_bytes() == &[0; 32]
            || authentication_key == [0; 32]
            || mac_domain.is_empty()
            || magic == [0; 8]
        {
            return Err(AuthenticatedFileAnchorErrorV2::InvalidBinding);
        }
        Ok(Self {
            path,
            installation_id,
            store_id,
            authentication_key: Zeroizing::new(authentication_key),
            mac_domain,
            magic,
        })
    }

    pub fn current_head(&self) -> Result<(u64, Digest32V2), AuthenticatedFileAnchorErrorV2> {
        let metadata = match fs::symlink_metadata(&self.path) {
            Ok(value) => value,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok((0, Digest32V2::new([0; 32])));
            }
            Err(_) => return Err(AuthenticatedFileAnchorErrorV2::Authentication),
        };
        let parent = self
            .path
            .parent()
            .ok_or(AuthenticatedFileAnchorErrorV2::Authentication)?;
        let parent_metadata = fs::symlink_metadata(parent)
            .map_err(|_| AuthenticatedFileAnchorErrorV2::Authentication)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.mode() & 0o7777 != 0o600
            || metadata.uid() != parent_metadata.uid()
            || metadata.gid() != parent_metadata.gid()
            || usize::try_from(metadata.len()).ok() != Some(ANCHOR_BYTES_V2)
        {
            return Err(AuthenticatedFileAnchorErrorV2::Authentication);
        }
        let bytes =
            fs::read(&self.path).map_err(|_| AuthenticatedFileAnchorErrorV2::Authentication)?;
        if bytes.len() != ANCHOR_BYTES_V2 || bytes.get(..8) != Some(self.magic.as_slice()) {
            return Err(AuthenticatedFileAnchorErrorV2::Authentication);
        }
        let sequence = u64::from_be_bytes(
            bytes[8..16]
                .try_into()
                .map_err(|_| AuthenticatedFileAnchorErrorV2::Authentication)?,
        );
        let digest = Digest32V2::new(
            bytes[16..48]
                .try_into()
                .map_err(|_| AuthenticatedFileAnchorErrorV2::Authentication)?,
        );
        self.verify_mac(sequence, digest, &bytes[48..80])?;
        if (sequence == 0) != (digest == Digest32V2::new([0; 32])) {
            return Err(AuthenticatedFileAnchorErrorV2::Authentication);
        }
        Ok((sequence, digest))
    }

    pub fn compare_and_advance(
        &self,
        expected: (u64, Digest32V2),
        next: (u64, Digest32V2),
    ) -> Result<(), AuthenticatedFileAnchorErrorV2> {
        if self.current_head()? != expected
            || next.0
                != expected
                    .0
                    .checked_add(1)
                    .ok_or(AuthenticatedFileAnchorErrorV2::Rollback)?
            || next.1 == Digest32V2::new([0; 32])
        {
            return Err(AuthenticatedFileAnchorErrorV2::Rollback);
        }
        self.write_head(next.0, next.1)?;
        if self.current_head()? != next {
            return Err(AuthenticatedFileAnchorErrorV2::CommitUncertain);
        }
        Ok(())
    }

    fn verify_mac(
        &self,
        sequence: u64,
        digest: Digest32V2,
        candidate: &[u8],
    ) -> Result<(), AuthenticatedFileAnchorErrorV2> {
        let mut mac = Hmac::<Sha256>::new_from_slice(self.authentication_key.as_ref())
            .map_err(|_| AuthenticatedFileAnchorErrorV2::Authentication)?;
        mac.update(self.mac_domain);
        mac.update(self.installation_id.as_bytes());
        mac.update(self.store_id.as_bytes());
        mac.update(&sequence.to_be_bytes());
        mac.update(digest.as_bytes());
        mac.verify_slice(candidate)
            .map_err(|_| AuthenticatedFileAnchorErrorV2::Authentication)
    }

    fn mac(
        &self,
        sequence: u64,
        digest: Digest32V2,
    ) -> Result<[u8; 32], AuthenticatedFileAnchorErrorV2> {
        let mut mac = Hmac::<Sha256>::new_from_slice(self.authentication_key.as_ref())
            .map_err(|_| AuthenticatedFileAnchorErrorV2::Authentication)?;
        mac.update(self.mac_domain);
        mac.update(self.installation_id.as_bytes());
        mac.update(self.store_id.as_bytes());
        mac.update(&sequence.to_be_bytes());
        mac.update(digest.as_bytes());
        Ok(mac.finalize().into_bytes().into())
    }

    fn write_head(
        &self,
        sequence: u64,
        digest: Digest32V2,
    ) -> Result<(), AuthenticatedFileAnchorErrorV2> {
        let parent = self
            .path
            .parent()
            .ok_or(AuthenticatedFileAnchorErrorV2::CommitUncertain)?;
        let parent_metadata = fs::symlink_metadata(parent)
            .map_err(|_| AuthenticatedFileAnchorErrorV2::CommitUncertain)?;
        if parent_metadata.file_type().is_symlink()
            || !parent_metadata.is_dir()
            || parent_metadata.mode() & 0o022 != 0
        {
            return Err(AuthenticatedFileAnchorErrorV2::CommitUncertain);
        }
        let mut bytes = Vec::with_capacity(ANCHOR_BYTES_V2);
        bytes.extend_from_slice(&self.magic);
        bytes.extend_from_slice(&sequence.to_be_bytes());
        bytes.extend_from_slice(digest.as_bytes());
        bytes.extend_from_slice(&self.mac(sequence, digest)?);
        let mut entropy = [0_u8; 8];
        getrandom::getrandom(&mut entropy)
            .map_err(|_| AuthenticatedFileAnchorErrorV2::CommitUncertain)?;
        let file_name = self
            .path
            .file_name()
            .ok_or(AuthenticatedFileAnchorErrorV2::CommitUncertain)?
            .to_string_lossy();
        let temporary = parent.join(format!(
            ".{file_name}.tmp.{}.{:016x}",
            std::process::id(),
            u64::from_be_bytes(entropy)
        ));
        let result = (|| {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temporary)
                .map_err(|_| AuthenticatedFileAnchorErrorV2::CommitUncertain)?;
            file.write_all(&bytes)
                .and_then(|()| file.sync_all())
                .map_err(|_| AuthenticatedFileAnchorErrorV2::CommitUncertain)?;
            fs::rename(&temporary, &self.path)
                .map_err(|_| AuthenticatedFileAnchorErrorV2::CommitUncertain)?;
            File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|_| AuthenticatedFileAnchorErrorV2::CommitUncertain)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }
}
