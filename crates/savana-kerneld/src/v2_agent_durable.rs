use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};

use chacha20poly1305::aead::{Aead as _, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit as _, Nonce};
use savana_kernel_protocol::v2::Digest32V2;
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

const STATE_FILE_NAME_V2: &str = "kernel-agent-authority-state-v2.cbor";
const MAX_STATE_BYTES_V2: usize = 128 * 1024 * 1024;
const STATE_AAD_DOMAIN_V2: &[u8] = b"SAVANA_KERNEL_AGENT_AUTHORITY_STATE_AAD_V2\0";
const STATE_HEAD_DOMAIN_V2: &[u8] = b"SAVANA_KERNEL_AGENT_AUTHORITY_STATE_HEAD_V2\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct KernelAgentAuthorityStateHeadV2 {
    sequence: u64,
    digest: Digest32V2,
}

impl Default for KernelAgentAuthorityStateHeadV2 {
    fn default() -> Self {
        Self {
            sequence: 0,
            digest: Digest32V2::new([0; 32]),
        }
    }
}

impl KernelAgentAuthorityStateHeadV2 {
    pub(crate) fn new(sequence: u64, digest: Digest32V2) -> Result<Self, ()> {
        if (sequence == 0) != (digest == Digest32V2::new([0; 32])) {
            return Err(());
        }
        Ok(Self { sequence, digest })
    }

    pub(crate) const fn sequence(self) -> u64 {
        self.sequence
    }

    pub(crate) const fn digest(self) -> Digest32V2 {
        self.digest
    }
}

pub(crate) trait KernelAgentAuthorityRollbackAnchorV2: Send {
    fn current_head(&self) -> Result<KernelAgentAuthorityStateHeadV2, ()>;

    fn compare_and_advance(
        &mut self,
        expected: KernelAgentAuthorityStateHeadV2,
        next: KernelAgentAuthorityStateHeadV2,
    ) -> Result<(), ()>;
}

pub(crate) struct DurableKernelAgentAuthorityStateV2 {
    path: PathBuf,
    installation_id: Digest32V2,
    store_id: Digest32V2,
    key: Zeroizing<[u8; 32]>,
    sequence: u64,
    head: KernelAgentAuthorityStateHeadV2,
    anchor: Box<dyn KernelAgentAuthorityRollbackAnchorV2>,
    poisoned: bool,
}

type OpenedKernelAgentAuthorityStateV2 = (
    DurableKernelAgentAuthorityStateV2,
    Option<Zeroizing<Vec<u8>>>,
);

impl std::fmt::Debug for DurableKernelAgentAuthorityStateV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DurableKernelAgentAuthorityStateV2")
            .field("path", &self.path)
            .field("sequence", &self.sequence)
            .field("poisoned", &self.poisoned)
            .finish_non_exhaustive()
    }
}

impl DurableKernelAgentAuthorityStateV2 {
    pub(crate) fn open(
        path: &Path,
        key: [u8; 32],
        installation_id: Digest32V2,
        store_id: Digest32V2,
        mut anchor: Box<dyn KernelAgentAuthorityRollbackAnchorV2>,
    ) -> Result<OpenedKernelAgentAuthorityStateV2, ()> {
        if path.file_name().and_then(|name| name.to_str()) != Some(STATE_FILE_NAME_V2)
            || !path.is_absolute()
            || key == [0; 32]
            || installation_id == Digest32V2::new([0; 32])
            || store_id == Digest32V2::new([0; 32])
        {
            return Err(());
        }
        validate_parent(path)?;
        let anchored = anchor.current_head()?;
        let (sequence, head, state) = match read_existing(path)? {
            None if anchored == KernelAgentAuthorityStateHeadV2::default() => (0, anchored, None),
            None => return Err(()),
            Some(bytes) => {
                let (sequence, previous, state) =
                    decrypt_snapshot(&bytes, &key, installation_id, store_id)?;
                let head = KernelAgentAuthorityStateHeadV2::new(
                    sequence,
                    state_head(installation_id, store_id, &bytes),
                )?;
                if head == anchored {
                    if sequence > 1 && previous == Digest32V2::new([0; 32]) {
                        return Err(());
                    }
                } else if sequence == anchored.sequence().checked_add(1).ok_or(())?
                    && previous == anchored.digest()
                {
                    anchor.compare_and_advance(anchored, head)?;
                } else {
                    return Err(());
                }
                (sequence, head, Some(state))
            }
        };
        Ok((
            Self {
                path: path.to_owned(),
                installation_id,
                store_id,
                key: Zeroizing::new(key),
                sequence,
                head,
                anchor,
                poisoned: false,
            },
            state,
        ))
    }

    pub(crate) fn commit(&mut self, state: &[u8]) -> Result<(), ()> {
        if self.poisoned || state.is_empty() || state.len() > MAX_STATE_BYTES_V2 {
            return Err(());
        }
        let sequence = self.sequence.checked_add(1).ok_or(())?;
        let bytes = encrypt_snapshot(
            sequence,
            self.head.digest(),
            state,
            &self.key,
            self.installation_id,
            self.store_id,
        )?;
        let next = KernelAgentAuthorityStateHeadV2::new(
            sequence,
            state_head(self.installation_id, self.store_id, &bytes),
        )?;
        if replace_file(&self.path, &bytes).is_err()
            || self.anchor.compare_and_advance(self.head, next).is_err()
        {
            self.poisoned = true;
            return Err(());
        }
        self.sequence = sequence;
        self.head = next;
        Ok(())
    }
}

fn encrypt_snapshot(
    sequence: u64,
    previous: Digest32V2,
    state: &[u8],
    key: &[u8; 32],
    installation_id: Digest32V2,
    store_id: Digest32V2,
) -> Result<Vec<u8>, ()> {
    let mut nonce = [0_u8; 12];
    getrandom::getrandom(&mut nonce).map_err(|_| ())?;
    if nonce == [0; 12] {
        return Err(());
    }
    let aad = snapshot_aad(installation_id, store_id, sequence, previous, &nonce);
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| ())?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: state,
                aad: &aad,
            },
        )
        .map_err(|_| ())?;
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(6)
        .and_then(|encoder| encoder.u16(2))
        .and_then(|encoder| encoder.u64(sequence))
        .and_then(|encoder| encoder.bytes(previous.as_bytes()))
        .and_then(|encoder| encoder.bytes(&nonce))
        .and_then(|encoder| encoder.bytes(&ciphertext))
        .and_then(|encoder| encoder.bytes(store_id.as_bytes()))
        .map_err(|_| ())?;
    Ok(encoder.into_writer())
}

fn decrypt_snapshot(
    bytes: &[u8],
    key: &[u8; 32],
    installation_id: Digest32V2,
    store_id: Digest32V2,
) -> Result<(u64, Digest32V2, Zeroizing<Vec<u8>>), ()> {
    if bytes.is_empty() || bytes.len() > MAX_STATE_BYTES_V2 {
        return Err(());
    }
    let mut decoder = minicbor::Decoder::new(bytes);
    if decoder.array().map_err(|_| ())? != Some(6) || decoder.u16().map_err(|_| ())? != 2 {
        return Err(());
    }
    let sequence = decoder.u64().map_err(|_| ())?;
    let previous = Digest32V2::new(decode_fixed::<32>(&mut decoder)?);
    let nonce = decode_fixed::<12>(&mut decoder)?;
    let ciphertext = decoder.bytes().map_err(|_| ())?;
    let encoded_store = Digest32V2::new(decode_fixed::<32>(&mut decoder)?);
    if sequence == 0
        || encoded_store != store_id
        || ciphertext.is_empty()
        || ciphertext.len() > MAX_STATE_BYTES_V2
        || decoder.position() != bytes.len()
    {
        return Err(());
    }
    let aad = snapshot_aad(installation_id, store_id, sequence, previous, &nonce);
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| ())?;
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| ())?;
    if plaintext.is_empty() || plaintext.len() > MAX_STATE_BYTES_V2 {
        return Err(());
    }
    Ok((sequence, previous, Zeroizing::new(plaintext)))
}

fn snapshot_aad(
    installation_id: Digest32V2,
    store_id: Digest32V2,
    sequence: u64,
    previous: Digest32V2,
    nonce: &[u8; 12],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(STATE_AAD_DOMAIN_V2.len() + 32 + 32 + 8 + 32 + 12);
    aad.extend_from_slice(STATE_AAD_DOMAIN_V2);
    aad.extend_from_slice(installation_id.as_bytes());
    aad.extend_from_slice(store_id.as_bytes());
    aad.extend_from_slice(&sequence.to_be_bytes());
    aad.extend_from_slice(previous.as_bytes());
    aad.extend_from_slice(nonce);
    aad
}

fn state_head(installation_id: Digest32V2, store_id: Digest32V2, bytes: &[u8]) -> Digest32V2 {
    let mut hasher = Sha256::new();
    hasher.update(STATE_HEAD_DOMAIN_V2);
    hasher.update(installation_id.as_bytes());
    hasher.update(store_id.as_bytes());
    hasher.update(bytes);
    Digest32V2::new(hasher.finalize().into())
}

fn read_existing(path: &Path) -> Result<Option<Vec<u8>>, ()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(()),
    };
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != 0o600
        || usize::try_from(metadata.len()).map_or(true, |length| length > MAX_STATE_BYTES_V2)
    {
        return Err(());
    }
    fs::read(path).map(Some).map_err(|_| ())
}

fn validate_parent(path: &Path) -> Result<(), ()> {
    let parent = path.parent().ok_or(())?;
    let metadata = fs::symlink_metadata(parent).map_err(|_| ())?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() || metadata.mode() & 0o022 != 0 {
        return Err(());
    }
    Ok(())
}

fn replace_file(path: &Path, bytes: &[u8]) -> Result<(), ()> {
    validate_parent(path)?;
    let parent = path.parent().ok_or(())?;
    let mut entropy = [0_u8; 8];
    getrandom::getrandom(&mut entropy).map_err(|_| ())?;
    let leaf = path.file_name().and_then(|name| name.to_str()).ok_or(())?;
    let temporary = parent.join(format!(
        ".{leaf}.tmp.{}.{:016x}",
        std::process::id(),
        u64::from_be_bytes(entropy)
    ));
    let result = (|| {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(|_| ())?;
        file.write_all(bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| ())?;
        fs::rename(&temporary, path).map_err(|_| ())?;
        fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| ())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

fn decode_fixed<const N: usize>(decoder: &mut minicbor::Decoder<'_>) -> Result<[u8; N], ()> {
    decoder.bytes().map_err(|_| ())?.try_into().map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;
    use std::sync::{Arc, Mutex};

    use super::*;

    #[derive(Clone, Default)]
    struct Anchor(Arc<Mutex<KernelAgentAuthorityStateHeadV2>>);

    impl KernelAgentAuthorityRollbackAnchorV2 for Anchor {
        fn current_head(&self) -> Result<KernelAgentAuthorityStateHeadV2, ()> {
            self.0.lock().map(|head| *head).map_err(|_| ())
        }

        fn compare_and_advance(
            &mut self,
            expected: KernelAgentAuthorityStateHeadV2,
            next: KernelAgentAuthorityStateHeadV2,
        ) -> Result<(), ()> {
            let mut head = self.0.lock().map_err(|_| ())?;
            if *head != expected || next.sequence() != expected.sequence() + 1 {
                return Err(());
            }
            *head = next;
            Ok(())
        }
    }

    #[test]
    fn encrypted_state_reopens_and_anchor_rejects_rollback() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory
            .path()
            .join(STATE_FILE_NAME_V2)
            .canonicalize()
            .unwrap_or_else(|_| directory.path().join(STATE_FILE_NAME_V2));
        let anchor = Anchor::default();
        let mut state = DurableKernelAgentAuthorityStateV2::open(
            &path,
            [1; 32],
            Digest32V2::new([2; 32]),
            Digest32V2::new([3; 32]),
            Box::new(anchor.clone()),
        )
        .unwrap()
        .0;
        state.commit(b"recovery state").unwrap();
        let rolled_back_bytes = fs::read(&path).unwrap();
        state.commit(b"newer recovery state").unwrap();
        let (_, restored) = DurableKernelAgentAuthorityStateV2::open(
            &path,
            [1; 32],
            Digest32V2::new([2; 32]),
            Digest32V2::new([3; 32]),
            Box::new(anchor.clone()),
        )
        .unwrap();
        assert_eq!(restored.unwrap().as_slice(), b"newer recovery state");
        fs::write(&path, rolled_back_bytes).unwrap();
        assert!(DurableKernelAgentAuthorityStateV2::open(
            &path,
            [1; 32],
            Digest32V2::new([2; 32]),
            Digest32V2::new([3; 32]),
            Box::new(anchor),
        )
        .is_err());
    }
}
