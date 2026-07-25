use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use savana_kernel_protocol::{Digest32, Signature64, StableCode, UnixMillis};
use sha2::{Digest, Sha256};

use crate::atomic_file;
use crate::lock_file::LedgerLock;
use crate::{PolicyError, PolicyVerifier, VerifiedPolicyV1};

const LEDGER_SCHEMA_VERSION: u16 = 1;
const MAXIMUM_LEDGER_BYTES: u64 = 128;
const LEDGER_DOMAIN: &[u8] = b"SAVANA_POLICY_LEDGER_V1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RollbackLedgerV1 {
    schema_version: u16,
    highest_policy_version: u64,
    highest_key_epoch: u64,
    highest_policy_digest: Digest32,
}

impl RollbackLedgerV1 {
    const GENESIS: Self = Self {
        schema_version: LEDGER_SCHEMA_VERSION,
        highest_policy_version: 0,
        highest_key_epoch: 0,
        highest_policy_digest: Digest32::new([0; 32]),
    };

    fn from_verified(policy: &VerifiedPolicyV1) -> Self {
        let identity = policy.identity();
        Self {
            schema_version: LEDGER_SCHEMA_VERSION,
            highest_policy_version: identity.policy_version,
            highest_key_epoch: identity.key_epoch,
            highest_policy_digest: identity.digest,
        }
    }

    fn canonical_bytes(self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(64);
        encoded.push(0x84);
        push_unsigned(&mut encoded, u64::from(self.schema_version));
        push_unsigned(&mut encoded, self.highest_policy_version);
        push_unsigned(&mut encoded, self.highest_key_epoch);
        encoded.extend_from_slice(&[0x58, 0x20]);
        encoded.extend_from_slice(self.highest_policy_digest.as_bytes());
        encoded
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyLedgerIdentity {
    pub highest_policy_version: u64,
    pub highest_key_epoch: u64,
    pub highest_policy_digest: Digest32,
    pub canonical_ledger_digest: Digest32,
}

pub struct PolicyStore {
    verifier: PolicyVerifier,
    ledger_path: PathBuf,
    ledger: RollbackLedgerV1,
    poisoned: bool,
    _lock: LedgerLock,
}

impl std::fmt::Debug for PolicyStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PolicyStore")
            .finish_non_exhaustive()
    }
}

impl PolicyStore {
    pub fn open(ledger_path: &Path, verifier: PolicyVerifier) -> Result<Self, PolicyError> {
        Self::open_with_parent_sync(ledger_path, verifier, atomic_file::sync_directory)
    }

    fn open_with_parent_sync<F>(
        ledger_path: &Path,
        verifier: PolicyVerifier,
        sync_parent: F,
    ) -> Result<Self, PolicyError>
    where
        F: FnOnce(&Path) -> Result<(), PolicyError>,
    {
        let lock = LedgerLock::acquire(ledger_path)?;
        let ledger = match fs::symlink_metadata(ledger_path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
                    return Err(PolicyError::stable(StableCode::ProtocolIo));
                }
                let ledger = read_existing_ledger(ledger_path, &metadata)?;
                sync_parent(atomic_file::normalized_parent(ledger_path)?)?;
                ledger
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => RollbackLedgerV1::GENESIS,
            Err(error) => return Err(PolicyError::io(error)),
        };
        Ok(Self {
            verifier,
            ledger_path: ledger_path.to_owned(),
            ledger,
            poisoned: false,
            _lock: lock,
        })
    }

    pub fn verify_and_accept(
        &mut self,
        canonical_bundle: &[u8],
        signature: &Signature64,
        now: UnixMillis,
    ) -> Result<VerifiedPolicyV1, PolicyError> {
        self.ensure_usable()?;
        let verified = self.verifier.verify(canonical_bundle, signature, now)?;
        let identity = verified.identity();
        if identity.policy_version < self.ledger.highest_policy_version {
            return Err(PolicyError::stable(StableCode::PolicyRollback));
        }
        if identity.policy_version == self.ledger.highest_policy_version {
            if identity.key_epoch == self.ledger.highest_key_epoch
                && identity.digest == self.ledger.highest_policy_digest
            {
                return Ok(verified);
            }
            return Err(PolicyError::stable(StableCode::PolicyEquivocation));
        }
        if identity.key_epoch < self.ledger.highest_key_epoch {
            return Err(PolicyError::stable(StableCode::PolicyRollback));
        }

        let next = RollbackLedgerV1::from_verified(&verified);
        self.persist_candidate_with(next, atomic_file::replace)?;
        Ok(verified)
    }

    pub fn ledger_identity(&self) -> Result<PolicyLedgerIdentity, PolicyError> {
        self.ensure_usable()?;
        let canonical = self.ledger.canonical_bytes();
        let mut hasher = Sha256::new();
        hasher.update(LEDGER_DOMAIN);
        hasher.update(&canonical);
        Ok(PolicyLedgerIdentity {
            highest_policy_version: self.ledger.highest_policy_version,
            highest_key_epoch: self.ledger.highest_key_epoch,
            highest_policy_digest: self.ledger.highest_policy_digest,
            canonical_ledger_digest: Digest32::new(hasher.finalize().into()),
        })
    }

    fn ensure_usable(&self) -> Result<(), PolicyError> {
        if self.poisoned {
            Err(PolicyError::stable(StableCode::ProtocolIo))
        } else {
            Ok(())
        }
    }

    fn persist_candidate_with<F>(
        &mut self,
        next: RollbackLedgerV1,
        persist: F,
    ) -> Result<(), PolicyError>
    where
        F: FnOnce(&Path, &[u8]) -> Result<(), atomic_file::ReplaceError>,
    {
        match persist(&self.ledger_path, &next.canonical_bytes()) {
            Ok(()) => {
                self.ledger = next;
                Ok(())
            }
            Err(error) => {
                if error.renamed() {
                    self.poisoned = true;
                }
                Err(error.into_policy_error())
            }
        }
    }
}

fn read_existing_ledger(
    path: &Path,
    path_metadata: &fs::Metadata,
) -> Result<RollbackLedgerV1, PolicyError> {
    if path_metadata.len() > MAXIMUM_LEDGER_BYTES {
        return Err(PolicyError::stable(StableCode::ProtocolMalformedCbor));
    }
    let file = File::open(path).map_err(PolicyError::io)?;
    let opened_metadata = file.metadata().map_err(PolicyError::io)?;
    if !opened_metadata.file_type().is_file()
        || opened_metadata.dev() != path_metadata.dev()
        || opened_metadata.ino() != path_metadata.ino()
    {
        return Err(PolicyError::stable(StableCode::ProtocolIo));
    }
    let final_metadata = fs::symlink_metadata(path).map_err(PolicyError::io)?;
    if final_metadata.file_type().is_symlink()
        || !final_metadata.file_type().is_file()
        || final_metadata.dev() != opened_metadata.dev()
        || final_metadata.ino() != opened_metadata.ino()
    {
        return Err(PolicyError::stable(StableCode::ProtocolIo));
    }
    let capacity = bounded_ledger_capacity(path_metadata.len(), opened_metadata.len())?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(MAXIMUM_LEDGER_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(PolicyError::io)?;
    if bytes.len() as u64 > MAXIMUM_LEDGER_BYTES {
        return Err(PolicyError::stable(StableCode::ProtocolMalformedCbor));
    }
    decode_ledger(&bytes)
}

fn bounded_ledger_capacity(path_length: u64, opened_length: u64) -> Result<usize, PolicyError> {
    if path_length > MAXIMUM_LEDGER_BYTES || opened_length > MAXIMUM_LEDGER_BYTES {
        return Err(PolicyError::stable(StableCode::ProtocolMalformedCbor));
    }
    usize::try_from(opened_length)
        .map_err(|_| PolicyError::stable(StableCode::ProtocolMalformedCbor))
}

fn decode_ledger(bytes: &[u8]) -> Result<RollbackLedgerV1, PolicyError> {
    let mut decoder = minicbor::Decoder::new(bytes);
    match decoder.array().map_err(|_| malformed())? {
        Some(4) => {}
        _ => return Err(malformed()),
    }
    let schema_version = decoder.u16().map_err(|_| malformed())?;
    let highest_policy_version = decoder.u64().map_err(|_| malformed())?;
    let highest_key_epoch = decoder.u64().map_err(|_| malformed())?;
    let highest_policy_digest =
        Digest32::try_from(decoder.bytes().map_err(|_| malformed())?).map_err(PolicyError::from)?;
    if decoder.position() != bytes.len() {
        return Err(malformed());
    }
    let ledger = RollbackLedgerV1 {
        schema_version,
        highest_policy_version,
        highest_key_epoch,
        highest_policy_digest,
    };
    if ledger.canonical_bytes() != bytes {
        return Err(malformed());
    }
    if schema_version != LEDGER_SCHEMA_VERSION {
        return Err(PolicyError::stable(StableCode::ProtocolUnsupportedVersion));
    }
    let zero_digest = ledger.highest_policy_digest == Digest32::new([0; 32]);
    let genesis_consistent =
        ledger.highest_policy_version == 0 && ledger.highest_key_epoch == 0 && zero_digest;
    let accepted_consistent =
        ledger.highest_policy_version != 0 && ledger.highest_key_epoch != 0 && !zero_digest;
    if !genesis_consistent && !accepted_consistent {
        return Err(malformed());
    }
    Ok(ledger)
}

fn push_unsigned(output: &mut Vec<u8>, value: u64) {
    match value {
        0..=23 => output.push(value as u8),
        24..=0xff => {
            output.push(0x18);
            output.push(value as u8);
        }
        0x100..=0xffff => {
            output.push(0x19);
            output.extend_from_slice(&(value as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            output.push(0x1a);
            output.extend_from_slice(&(value as u32).to_be_bytes());
        }
        _ => {
            output.push(0x1b);
            output.extend_from_slice(&value.to_be_bytes());
        }
    }
}

fn malformed() -> PolicyError {
    PolicyError::stable(StableCode::ProtocolMalformedCbor)
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use savana_kernel_protocol::KeyId;

    use super::*;
    use crate::PolicyTrustRootV1;

    #[test]
    fn opened_ledger_growth_is_rejected_before_capacity_is_chosen() {
        assert_eq!(bounded_ledger_capacity(64, 128).unwrap(), 128);
        assert_eq!(
            bounded_ledger_capacity(64, 129).unwrap_err().code(),
            StableCode::ProtocolMalformedCbor
        );
    }

    #[test]
    fn post_rename_failure_poison_requires_reopen_reconciliation() {
        let dir = tempfile::tempdir().unwrap();
        let ledger_path = dir.path().join("policy.ledger");
        let signing_key = SigningKey::from_bytes(&[0x42; 32]);
        let verifier = || {
            PolicyVerifier::new(
                vec![PolicyTrustRootV1 {
                    key_id: KeyId::try_from("policy-root").unwrap(),
                    public_key: signing_key.verifying_key().to_bytes(),
                    epoch: 3,
                    revoked: false,
                }],
                Digest32::new([0xa0; 32]),
            )
            .unwrap()
        };
        let mut store = PolicyStore::open(&ledger_path, verifier()).unwrap();
        let next = RollbackLedgerV1 {
            schema_version: 1,
            highest_policy_version: 7,
            highest_key_epoch: 3,
            highest_policy_digest: Digest32::new([1; 32]),
        };

        let error = store
            .persist_candidate_with(next, |path, bytes| {
                atomic_file::replace_with_parent_sync(path, bytes, |_parent| {
                    Err(PolicyError::stable(StableCode::ProtocolIo))
                })
            })
            .unwrap_err();

        assert_eq!(error.code(), StableCode::ProtocolIo);
        assert_eq!(store.ledger, RollbackLedgerV1::GENESIS);
        assert!(store.poisoned);
        assert_eq!(
            store.ledger_identity().unwrap_err().code(),
            StableCode::ProtocolIo
        );
        assert_eq!(
            store
                .verify_and_accept(&[], &Signature64::new([0; 64]), UnixMillis::new(0))
                .unwrap_err()
                .code(),
            StableCode::ProtocolIo
        );
        drop(store);

        assert_eq!(
            PolicyStore::open_with_parent_sync(&ledger_path, verifier(), |_parent| {
                Err(PolicyError::stable(StableCode::ProtocolIo))
            })
            .unwrap_err()
            .code(),
            StableCode::ProtocolIo
        );

        let reopened = PolicyStore::open(&ledger_path, verifier()).unwrap();
        assert_eq!(
            reopened.ledger_identity().unwrap().highest_policy_version,
            7
        );
    }
}
