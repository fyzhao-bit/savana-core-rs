use std::path::Path;

use ed25519_dalek::{Signer, SigningKey};
use savana_kernel_protocol::{HandshakeTranscriptV1, Signature64, StableCode};
use zeroize::Zeroizing;

use crate::fs_cap::{DirectoryCapability, FileCapability, FileExpectation, LengthRule};
use crate::DaemonError;

pub(crate) struct DaemonSigningIdentity {
    signing_key: SigningKey,
}

impl DaemonSigningIdentity {
    pub(crate) fn public_key(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    pub(crate) fn sign_daemon_hello(
        &self,
        transcript: &HandshakeTranscriptV1,
    ) -> Result<Signature64, DaemonError> {
        let transcript = minicbor::to_vec(transcript)
            .map_err(|_| DaemonError::stable(StableCode::KernelUnavailable))?;
        let mut signed = Vec::with_capacity(b"SAVANA_DAEMON_HELLO_V1\0".len() + transcript.len());
        signed.extend_from_slice(b"SAVANA_DAEMON_HELLO_V1\0");
        signed.extend_from_slice(&transcript);
        Ok(Signature64::new(self.signing_key.sign(&signed).to_bytes()))
    }

    #[cfg(test)]
    pub(crate) fn from_seed_for_test(seed: [u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(&seed),
        }
    }
}

impl std::fmt::Debug for DaemonSigningIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DaemonSigningIdentity(<redacted>)")
    }
}

pub(crate) struct DaemonKeyCapability {
    parent: DirectoryCapability,
    seed: FileCapability,
}

impl std::fmt::Debug for DaemonKeyCapability {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DaemonKeyCapability(<verified>)")
    }
}

impl DaemonKeyCapability {
    pub(crate) fn open(
        path: &Path,
        parent_uid: u32,
        parent_gid: u32,
        key_uid: u32,
        key_gid: u32,
    ) -> Result<Self, DaemonError> {
        let parent_path = path.parent().ok_or_else(key_permissions)?;
        let leaf = path.file_name().ok_or_else(key_permissions)?;
        let parent = DirectoryCapability::open_final(
            parent_path,
            parent_uid,
            parent_gid,
            0o750,
            StableCode::IdentityKeyPermissions,
        )?;
        let seed = parent.open_file(
            leaf,
            FileExpectation {
                owner_uid: key_uid,
                owner_gid: key_gid,
                permissions: 0o600,
                length: LengthRule::Exact(32),
            },
        )?;
        Ok(Self { parent, seed })
    }

    pub(crate) fn load(
        &self,
        expected_public_key: &[u8; 32],
    ) -> Result<DaemonSigningIdentity, DaemonError> {
        let mut seed = Zeroizing::new([0_u8; 32]);
        self.seed.read_exact_into(seed.as_mut())?;
        let signing_key = SigningKey::from_bytes(&seed);
        if signing_key.verifying_key().to_bytes() != *expected_public_key {
            return Err(key_permissions());
        }
        self.recheck()?;
        Ok(DaemonSigningIdentity { signing_key })
    }

    pub(crate) fn recheck(&self) -> Result<(), DaemonError> {
        self.seed.recheck()?;
        self.parent.recheck()
    }
}

fn key_permissions() -> DaemonError {
    DaemonError::stable(StableCode::IdentityKeyPermissions)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    #[test]
    fn daemon_key_is_loaded_from_held_parent_and_exact_leaf_capabilities() {
        let root = tempfile::tempdir().unwrap();
        let parent = root.path().join("private");
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o750)).unwrap();
        let seed = [0x61; 32];
        let path = parent.join("daemon-identity-v1.seed");
        fs::write(&path, seed).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let metadata = fs::metadata(&path).unwrap();
        let expected_public = SigningKey::from_bytes(&seed).verifying_key().to_bytes();

        let capability = DaemonKeyCapability::open(
            &path,
            metadata.uid(),
            metadata.gid(),
            metadata.uid(),
            metadata.gid(),
        )
        .unwrap();
        let identity = capability.load(&expected_public).unwrap();
        assert_eq!(identity.public_key(), expected_public);
        capability.recheck().unwrap();
    }
}
