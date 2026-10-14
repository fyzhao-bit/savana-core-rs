//! Concrete encrypted storage for the bounded prototype. The rollback anchor
//! is supplied by the trusted host; there is deliberately no in-file/default
//! "rollback protection". Uses the same anchor interface as the production G4 owner.
use crate::{decode, hash, hex, json, Digest, Error};
use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit, Nonce,
};
use nix::fcntl::{Flock, FlockArg};
use savana_policy_core::v2::{RollbackProtectedStateAnchorV2, RollbackProtectedStateHeadV2};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const MAX_STATE: usize = 8 * 1024 * 1024;
const MAX_ENVELOPE: usize = MAX_STATE * 4;

/// Trusted durability adapter. Commit success MUST mean the entire replacement
/// is durable; uncertain failures must not be reported as success. A single
/// owner must exclusively hold a store. Test doubles are not durable deployments.
pub trait StateStore {
    fn load(&self) -> Result<Option<Vec<u8>>, Error>;
    fn commit(&mut self, state: &[u8]) -> Result<(), Error>;
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    schema: u8,
    namespace: Digest,
    sequence: u64,
    previous: Digest,
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
}

pub struct FileStore {
    directory: PathBuf,
    directory_identity: (u64, u64),
    key: Zeroizing<Digest>,
    namespace: Digest,
    anchor: Box<dyn RollbackProtectedStateAnchorV2>,
    head: RollbackProtectedStateHeadV2,
    state: Option<Zeroizing<Vec<u8>>>,
    poisoned: bool,
    lock: Flock<File>,
}
impl FileStore {
    /// `directory` must be a pre-created, canonical, private 0700 directory.
    /// Namespace must uniquely bind this installation/task/store. The same
    /// external anchor must be retained across all reopen attempts.
    pub fn open(
        directory: &Path,
        key: Digest,
        namespace: Digest,
        mut anchor: Box<dyn RollbackProtectedStateAnchorV2>,
    ) -> Result<Self, Error> {
        if key == [0; 32]
            || namespace == [0; 32]
            || fs::canonicalize(directory).map_err(storage)? != directory
        {
            return Err(Error::Storage);
        }
        let d = fs::symlink_metadata(directory).map_err(storage)?;
        if !d.is_dir()
            || d.mode() & 0o7777 != 0o700
            || d.uid() != nix::unistd::Uid::effective().as_raw()
        {
            return Err(Error::Storage);
        }
        let lock_path = directory.join("continuation.lock");
        let lock_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC | nix::libc::O_NONBLOCK)
            .open(&lock_path)
            .map_err(storage)?;
        validate_file(&lock_path, &lock_file)?;
        let lock =
            Flock::lock(lock_file, FlockArg::LockExclusiveNonblock).map_err(|_| Error::Storage)?;
        validate_file(&lock_path, &lock)?;
        lock.sync_all().map_err(storage)?;
        File::open(directory)
            .and_then(|f| f.sync_all())
            .map_err(storage)?;
        let mut head = anchor.current_head().map_err(storage)?;
        let state_path = directory.join("continuation-state.json.aead");
        let state = match read_file(&state_path)? {
            None => {
                if head.sequence() != 0 {
                    return Err(Error::Storage);
                }
                None
            }
            Some(bytes) => {
                let e: Envelope = decode(&bytes, MAX_ENVELOPE).map_err(storage)?;
                if e.schema != 1 || e.namespace != namespace || e.sequence == 0 {
                    return Err(Error::Storage);
                }
                let cipher = Aes256Gcm::new_from_slice(&key).map_err(storage)?;
                let plain = cipher
                    .decrypt(
                        Nonce::from_slice(&e.nonce),
                        Payload {
                            msg: &e.ciphertext,
                            aad: &aad(namespace, e.sequence, e.previous),
                        },
                    )
                    .map_err(storage)?;
                if plain.is_empty() || plain.len() > MAX_STATE {
                    return Err(Error::Storage);
                }
                let observed = RollbackProtectedStateHeadV2::new(
                    e.sequence,
                    savana_kernel_protocol::v2::Digest32V2::new(hash(
                        b"SAVANA_PRIVATE_CONTINUATION_STATE_HEAD_V1\0",
                        &[&bytes],
                    )),
                )
                .map_err(storage)?;
                if observed != head {
                    // Recover exactly the authenticated adjacent replacement
                    // after rename succeeded but the external anchor did not.
                    if head.sequence().checked_add(1) != Some(e.sequence)
                        || head.state_digest().as_bytes() != &e.previous
                    {
                        return Err(Error::Storage);
                    }
                    anchor
                        .compare_and_advance(head, observed)
                        .map_err(storage)?;
                    head = observed;
                }
                Some(Zeroizing::new(plain))
            }
        };
        Ok(Self {
            directory: directory.into(),
            directory_identity: (d.dev(), d.ino()),
            key: Zeroizing::new(key),
            namespace,
            anchor,
            head,
            state,
            poisoned: false,
            lock,
        })
    }
    fn recheck(&self) -> Result<(), Error> {
        let d = fs::symlink_metadata(&self.directory).map_err(storage)?;
        if !d.is_dir()
            || (d.dev(), d.ino()) != self.directory_identity
            || d.mode() & 0o7777 != 0o700
            || d.uid() != nix::unistd::Uid::effective().as_raw()
            || self.anchor.current_head().map_err(storage)? != self.head
        {
            return Err(Error::Storage);
        }
        validate_file(&self.directory.join("continuation.lock"), &self.lock)
    }
    fn replace(&mut self, state: &[u8]) -> Result<(), Error> {
        self.recheck()?;
        if state.is_empty() || state.len() > MAX_STATE {
            return Err(Error::Storage);
        }
        let sequence = self.head.sequence().checked_add(1).ok_or(Error::Storage)?;
        let previous = *self.head.state_digest().as_bytes();
        let mut nonce = [0; 12];
        getrandom::getrandom(&mut nonce).map_err(storage)?;
        let ciphertext = Aes256Gcm::new_from_slice(self.key.as_ref())
            .map_err(storage)?
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: state,
                    aad: &aad(self.namespace, sequence, previous),
                },
            )
            .map_err(storage)?;
        let bytes = json(&Envelope {
            schema: 1,
            namespace: self.namespace,
            sequence,
            previous,
            nonce,
            ciphertext,
        })?;
        if bytes.len() > MAX_ENVELOPE {
            return Err(Error::Storage);
        }
        let next = RollbackProtectedStateHeadV2::new(
            sequence,
            savana_kernel_protocol::v2::Digest32V2::new(hash(
                b"SAVANA_PRIVATE_CONTINUATION_STATE_HEAD_V1\0",
                &[&bytes],
            )),
        )
        .map_err(storage)?;
        let temporary = self
            .directory
            .join(format!(".continuation-{}.tmp", hex(&nonce)));
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC | nix::libc::O_NONBLOCK)
            .open(&temporary)
            .map_err(storage)?;
        let result = (|| {
            f.write_all(&bytes)
                .and_then(|_| f.sync_all())
                .map_err(storage)?;
            self.recheck()?;
            fs::rename(
                &temporary,
                self.directory.join("continuation-state.json.aead"),
            )
            .map_err(storage)?;
            File::open(&self.directory)
                .and_then(|f| f.sync_all())
                .map_err(storage)?;
            self.anchor
                .compare_and_advance(self.head, next)
                .map_err(storage)?;
            Ok(())
        })();
        // Only the uniquely created temporary file is removed, never state/anchor.
        if temporary.exists() {
            let _ = fs::remove_file(&temporary);
        }
        result?;
        self.head = next;
        self.state = Some(Zeroizing::new(state.to_vec()));
        Ok(())
    }
}
impl StateStore for FileStore {
    fn load(&self) -> Result<Option<Vec<u8>>, Error> {
        if self.poisoned {
            return Err(Error::Storage);
        }
        self.recheck()?;
        Ok(self.state.as_ref().map(|s| s.to_vec()))
    }
    fn commit(&mut self, state: &[u8]) -> Result<(), Error> {
        if self.poisoned {
            return Err(Error::Storage);
        }
        let result = self.replace(state);
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
}
fn aad(namespace: Digest, sequence: u64, previous: Digest) -> Vec<u8> {
    let mut b = b"SAVANA_PRIVATE_CONTINUATION_AEAD_V1\0".to_vec();
    b.extend_from_slice(&namespace);
    b.extend_from_slice(&sequence.to_be_bytes());
    b.extend_from_slice(&previous);
    b
}
fn validate_file(path: &Path, file: &File) -> Result<(), Error> {
    let m = file.metadata().map_err(storage)?;
    let p = fs::symlink_metadata(path).map_err(storage)?;
    if !m.is_file()
        || !p.is_file()
        || (m.dev(), m.ino()) != (p.dev(), p.ino())
        || m.nlink() != 1
        || m.mode() & 0o7777 != 0o600
        || m.uid() != nix::unistd::Uid::effective().as_raw()
    {
        return Err(Error::Storage);
    }
    Ok(())
}
fn read_file(path: &Path) -> Result<Option<Vec<u8>>, Error> {
    let file = match OpenOptions::new()
        .read(true)
        // Refuse a substituted FIFO without waiting for a writer before the
        // regular-file check. O_NONBLOCK has no effect on valid regular files.
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC | nix::libc::O_NONBLOCK)
        .open(path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(Error::Storage),
    };
    validate_file(path, &file)?;
    if file.metadata().map_err(storage)?.len() > MAX_ENVELOPE as u64 {
        return Err(Error::Storage);
    }
    let mut bytes = Vec::new();
    file.take((MAX_ENVELOPE + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(storage)?;
    if bytes.len() > MAX_ENVELOPE {
        return Err(Error::Storage);
    }
    Ok(Some(bytes))
}
fn storage<T>(_: T) -> Error {
    Error::Storage
}
