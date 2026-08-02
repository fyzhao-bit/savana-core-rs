use std::ffi::OsStr;
use std::path::Path;

use aes_gcm::aead::{Aead as _, Payload};
use aes_gcm::{Aes256Gcm, KeyInit as _, Nonce};
use hmac::{Hmac, Mac as _};
use savana_kernel_protocol::v2::Digest32V2;
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::atomic_file::{AtomicReplaceBoundary, PersistencePhase};
use crate::lock_file::LedgerLock;
use crate::PolicyError;

use super::durable::DurableAnchoredPathV2;
use super::{
    ConnectorRegistryStateV2, DurableStateNamespaceV2, G4Error, RollbackProtectedStateAnchorV2,
    RollbackProtectedStateHeadV2,
};

const STATE_FILE_NAME_V2: &str = "connector-registry-v2.cbor";
const STATE_LOCK_FILE_NAME_V2: &str = ".connector-registry-v2.cbor.lock";
const STATE_SCHEMA_VERSION_V2: u16 = 1;
const SNAPSHOT_SCHEMA_VERSION_V2: u16 = 1;
const STATE_ENCRYPTION_DOMAIN_V2: &[u8] = b"SAVANA_CONNECTOR_REGISTRY_STORE_ENCRYPTION_V2\0";
const STATE_KEY_DERIVATION_DOMAIN_V2: &[u8] =
    b"SAVANA_CONNECTOR_REGISTRY_STORE_KEY_DERIVATION_V2\0";
const STATE_HEAD_DOMAIN_V2: &[u8] = b"SAVANA_CONNECTOR_REGISTRY_STORE_HEAD_V2\0";
const AUTHORITY_STATE_DIGEST_DOMAIN_V2: &[u8] =
    b"SAVANA_CONNECTOR_REGISTRY_AUTHORITY_STATE_DIGEST_V2\0";
#[cfg(any(test, feature = "test-support"))]
const TEST_STORE_ID_DOMAIN_V2: &[u8] = b"SAVANA_CONNECTOR_REGISTRY_TEST_STORE_ID_V2\0";
const NONCE_BYTES_V2: usize = 12;
const MAX_STATE_BYTES_V2: usize = 64 * 1024 * 1024;
pub const MAX_CONNECTOR_AUTHORITY_STATE_BYTES_V2: usize = 16 * 1024 * 1024;
const MAX_JOURNAL_DELTAS_V2: usize = 4_096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectorStoreDurabilityPointV2 {
    BeforeWrite,
    FileFlushed,
    RenamedBeforeDirectoryFlush,
    DirectoryFlushed,
    Reopened,
    HighWaterAdvanced,
}

trait ConnectorStoreDurabilityObserverV2 {
    fn reached(&mut self, point: ConnectorStoreDurabilityPointV2) -> Result<(), G4Error>;
}

struct NoConnectorStoreCrashV2;

impl ConnectorStoreDurabilityObserverV2 for NoConnectorStoreCrashV2 {
    fn reached(&mut self, _point: ConnectorStoreDurabilityPointV2) -> Result<(), G4Error> {
        Ok(())
    }
}

#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestConnectorStoreCrashPointV2 {
    BeforeWrite,
    FileFlushed,
    RenamedBeforeDirectoryFlush,
    DirectoryFlushed,
    Reopened,
    HighWaterAdvanced,
}

#[cfg(any(test, feature = "test-support"))]
impl TestConnectorStoreCrashPointV2 {
    pub const ALL: [Self; 6] = [
        Self::BeforeWrite,
        Self::FileFlushed,
        Self::RenamedBeforeDirectoryFlush,
        Self::DirectoryFlushed,
        Self::Reopened,
        Self::HighWaterAdvanced,
    ];

    const fn internal(self) -> ConnectorStoreDurabilityPointV2 {
        match self {
            Self::BeforeWrite => ConnectorStoreDurabilityPointV2::BeforeWrite,
            Self::FileFlushed => ConnectorStoreDurabilityPointV2::FileFlushed,
            Self::RenamedBeforeDirectoryFlush => {
                ConnectorStoreDurabilityPointV2::RenamedBeforeDirectoryFlush
            }
            Self::DirectoryFlushed => ConnectorStoreDurabilityPointV2::DirectoryFlushed,
            Self::Reopened => ConnectorStoreDurabilityPointV2::Reopened,
            Self::HighWaterAdvanced => ConnectorStoreDurabilityPointV2::HighWaterAdvanced,
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
struct OneConnectorStoreCrashV2 {
    crash_at: ConnectorStoreDurabilityPointV2,
}

#[cfg(any(test, feature = "test-support"))]
impl ConnectorStoreDurabilityObserverV2 for OneConnectorStoreCrashV2 {
    fn reached(&mut self, point: ConnectorStoreDurabilityPointV2) -> Result<(), G4Error> {
        if point == self.crash_at {
            Err(G4Error::DurableStateIo)
        } else {
            Ok(())
        }
    }
}

struct DecodedConnectorSnapshotV2 {
    durable_sequence: u64,
    previous_state_digest: Digest32V2,
    previous_authority_state_digest: Digest32V2,
    registry: ConnectorRegistryStateV2,
    authority_state: Zeroizing<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectorStoreRevisionV2 {
    durable_sequence: u64,
    authority_state_digest: Digest32V2,
}

impl ConnectorStoreRevisionV2 {
    pub const fn durable_sequence(self) -> u64 {
        self.durable_sequence
    }

    pub const fn authority_state_digest(self) -> Digest32V2 {
        self.authority_state_digest
    }
}

pub struct DurableConnectorRegistryStoreV2 {
    anchored_path: DurableAnchoredPathV2,
    namespace: DurableStateNamespaceV2,
    encryption_key: Zeroizing<[u8; 32]>,
    genesis: ConnectorRegistryStateV2,
    registry: ConnectorRegistryStateV2,
    authority_state: Zeroizing<Vec<u8>>,
    durable_sequence: u64,
    current_head: RollbackProtectedStateHeadV2,
    previous_authority_state_digest: Digest32V2,
    rollback_anchor: Box<dyn RollbackProtectedStateAnchorV2>,
    poisoned: bool,
    lock: LedgerLock,
}

impl std::fmt::Debug for DurableConnectorRegistryStoreV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DurableConnectorRegistryStoreV2")
            .field("durable_sequence", &self.durable_sequence)
            .field("registry_sequence", &self.registry.sequence())
            .field("registry_head", &self.registry.head_digest())
            .field("poisoned", &self.poisoned)
            .finish_non_exhaustive()
    }
}

impl DurableConnectorRegistryStoreV2 {
    pub fn open(
        path: &Path,
        master_encryption_key: [u8; 32],
        namespace: DurableStateNamespaceV2,
        mut rollback_anchor: Box<dyn RollbackProtectedStateAnchorV2>,
        genesis: ConnectorRegistryStateV2,
    ) -> Result<Self, G4Error> {
        validate_genesis(&genesis)?;
        if path.file_name().and_then(|name| name.to_str()) != Some(STATE_FILE_NAME_V2)
            || master_encryption_key == [0; 32]
        {
            return Err(G4Error::DurableStateIo);
        }
        let master_encryption_key = Zeroizing::new(master_encryption_key);
        let anchored_path = DurableAnchoredPathV2::open(path)?;
        let lock = LedgerLock::acquire_at(
            anchored_path.parent(),
            OsStr::new(STATE_LOCK_FILE_NAME_V2),
            anchored_path.owner_uid(),
            anchored_path.owner_gid(),
        )
        .map_err(|_| G4Error::DurableStateIo)?;
        anchored_path.recheck_parent()?;
        let encryption_key = derive_encryption_key(&master_encryption_key, namespace)?;
        let anchored_head = rollback_anchor.current_head()?;

        let (
            registry,
            authority_state,
            durable_sequence,
            current_head,
            previous_authority_state_digest,
        ) = match anchored_path.read_existing()? {
            None if anchored_head == genesis_store_head()? => (
                genesis.clone(),
                Zeroizing::new(Vec::new()),
                0,
                genesis_store_head()?,
                authority_state_digest(namespace, &[]),
            ),
            None => return Err(G4Error::DurableStateRollback),
            Some(bytes) => {
                let decoded =
                    match decode_encrypted_snapshot(&bytes, &encryption_key, namespace, &genesis) {
                        Ok(decoded) => decoded,
                        Err(G4Error::DurableStateAuthentication)
                            if anchored_head == genesis_store_head()? =>
                        {
                            return Ok(Self {
                                anchored_path,
                                namespace,
                                encryption_key,
                                genesis: genesis.clone(),
                                registry: genesis,
                                authority_state: Zeroizing::new(Vec::new()),
                                durable_sequence: 0,
                                current_head: genesis_store_head()?,
                                previous_authority_state_digest: authority_state_digest(
                                    namespace,
                                    &[],
                                ),
                                rollback_anchor,
                                poisoned: false,
                                lock,
                            });
                        }
                        Err(G4Error::DurableStateAuthentication) => {
                            return Err(G4Error::DurableStateRollback);
                        }
                        Err(error) => return Err(error),
                    };
                let snapshot_head = RollbackProtectedStateHeadV2::new(
                    decoded.durable_sequence,
                    state_head_digest(namespace, &bytes),
                )?;
                if snapshot_head == anchored_head {
                    (
                        decoded.registry,
                        decoded.authority_state,
                        decoded.durable_sequence,
                        snapshot_head,
                        decoded.previous_authority_state_digest,
                    )
                } else if decoded.durable_sequence
                    == anchored_head
                        .sequence()
                        .checked_add(1)
                        .ok_or(G4Error::DurableStateRollback)?
                    && decoded.previous_state_digest == anchored_head.state_digest()
                {
                    rollback_anchor.compare_and_advance(anchored_head, snapshot_head)?;
                    (
                        decoded.registry,
                        decoded.authority_state,
                        decoded.durable_sequence,
                        snapshot_head,
                        decoded.previous_authority_state_digest,
                    )
                } else {
                    return Err(G4Error::DurableStateRollback);
                }
            }
        };

        Ok(Self {
            anchored_path,
            namespace,
            encryption_key,
            genesis,
            registry,
            authority_state,
            durable_sequence,
            current_head,
            previous_authority_state_digest,
            rollback_anchor,
            poisoned: false,
            lock,
        })
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn open_for_test(
        directory: &Path,
        genesis: ConnectorRegistryStateV2,
        rollback_anchor: Box<dyn RollbackProtectedStateAnchorV2>,
    ) -> Result<Self, G4Error> {
        let store_id = domain_hash(TEST_STORE_ID_DOMAIN_V2, genesis.genesis_digest().as_bytes());
        let namespace = DurableStateNamespaceV2::from_verified_installation(
            genesis.genesis_digest(),
            store_id,
        )?;
        Self::open(
            &directory.join(STATE_FILE_NAME_V2),
            [0xc7; 32],
            namespace,
            rollback_anchor,
            genesis,
        )
    }

    pub fn snapshot(&self) -> Result<ConnectorRegistryStateV2, G4Error> {
        self.ensure_usable()?;
        Ok(self.registry.clone())
    }

    pub fn authority_state(&self) -> Result<&[u8], G4Error> {
        self.ensure_usable()?;
        Ok(self.authority_state.as_slice())
    }

    pub fn revision(&self) -> Result<ConnectorStoreRevisionV2, G4Error> {
        self.ensure_usable()?;
        Ok(self.current_revision())
    }

    pub fn commit(
        &mut self,
        expected_registry_head: Digest32V2,
        expected_revision: ConnectorStoreRevisionV2,
        canonical_delta: Option<&[u8]>,
        authority_state: &[u8],
    ) -> Result<ConnectorRegistryStateV2, G4Error> {
        self.ensure_usable()?;
        if authority_state.len() > MAX_CONNECTOR_AUTHORITY_STATE_BYTES_V2 {
            return Err(G4Error::DescriptorLimitExceeded);
        }

        if expected_revision != self.current_revision() {
            if self.is_exact_predecessor_retry(
                expected_registry_head,
                expected_revision,
                canonical_delta,
                authority_state,
            ) {
                return Ok(self.registry.clone());
            }
            return Err(if canonical_delta.is_some() {
                G4Error::IdempotencyConflict
            } else {
                G4Error::StateConflict
            });
        }

        if let Some(delta) = canonical_delta {
            if let Some(existing) = self
                .registry
                .deltas()
                .last()
                .filter(|existing| existing.canonical_bytes() == delta)
            {
                if expected_registry_head != self.registry.head_digest()
                    && expected_registry_head != existing.previous_head_digest()
                {
                    return Err(G4Error::IdempotencyConflict);
                }
                if self.authority_state.as_slice() != authority_state {
                    return Err(G4Error::IdempotencyConflict);
                }
                return Ok(self.registry.clone());
            }
        }
        if self.registry.head_digest() != expected_registry_head {
            return Err(if canonical_delta.is_some() {
                G4Error::IdempotencyConflict
            } else {
                G4Error::StateConflict
            });
        }

        let mut next_registry = self.registry.clone();
        if let Some(delta) = canonical_delta {
            if next_registry.deltas().len() == MAX_JOURNAL_DELTAS_V2 {
                return Err(G4Error::DescriptorLimitExceeded);
            }
            next_registry.apply_canonical_delta(delta)?;
        }
        if canonical_delta.is_none() && self.authority_state.as_slice() == authority_state {
            return Ok(self.registry.clone());
        }
        self.commit_observed(
            next_registry,
            Zeroizing::new(authority_state.to_vec()),
            &mut NoConnectorStoreCrashV2,
        )
    }

    pub fn append_canonical_delta(
        &mut self,
        canonical_delta: &[u8],
    ) -> Result<ConnectorRegistryStateV2, G4Error> {
        let expected_head = self.registry.head_digest();
        let expected_revision = self.current_revision();
        let authority_state = self.authority_state.clone();
        self.commit(
            expected_head,
            expected_revision,
            Some(canonical_delta),
            &authority_state,
        )
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn append_canonical_delta_with_crash_for_test(
        &mut self,
        canonical_delta: &[u8],
        crash_at: TestConnectorStoreCrashPointV2,
    ) -> Result<ConnectorRegistryStateV2, G4Error> {
        self.ensure_usable()?;
        if self.registry.deltas().len() == MAX_JOURNAL_DELTAS_V2 {
            return Err(G4Error::DescriptorLimitExceeded);
        }
        let mut next_registry = self.registry.clone();
        next_registry.apply_canonical_delta(canonical_delta)?;
        self.commit_observed(
            next_registry,
            self.authority_state.clone(),
            &mut OneConnectorStoreCrashV2 {
                crash_at: crash_at.internal(),
            },
        )
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn commit_with_crash_for_test(
        &mut self,
        expected_registry_head: Digest32V2,
        expected_revision: ConnectorStoreRevisionV2,
        canonical_delta: Option<&[u8]>,
        authority_state: &[u8],
        crash_at: TestConnectorStoreCrashPointV2,
    ) -> Result<ConnectorRegistryStateV2, G4Error> {
        self.ensure_usable()?;
        if authority_state.len() > MAX_CONNECTOR_AUTHORITY_STATE_BYTES_V2 {
            return Err(G4Error::DescriptorLimitExceeded);
        }
        if expected_revision != self.current_revision()
            || self.registry.head_digest() != expected_registry_head
        {
            return Err(if canonical_delta.is_some() {
                G4Error::IdempotencyConflict
            } else {
                G4Error::StateConflict
            });
        }

        let mut next_registry = self.registry.clone();
        if let Some(delta) = canonical_delta {
            if next_registry.deltas().len() == MAX_JOURNAL_DELTAS_V2 {
                return Err(G4Error::DescriptorLimitExceeded);
            }
            next_registry.apply_canonical_delta(delta)?;
        }
        self.commit_observed(
            next_registry,
            Zeroizing::new(authority_state.to_vec()),
            &mut OneConnectorStoreCrashV2 {
                crash_at: crash_at.internal(),
            },
        )
    }

    fn commit_observed(
        &mut self,
        next_registry: ConnectorRegistryStateV2,
        next_authority_state: Zeroizing<Vec<u8>>,
        observer: &mut dyn ConnectorStoreDurabilityObserverV2,
    ) -> Result<ConnectorRegistryStateV2, G4Error> {
        let durable_sequence = self
            .durable_sequence
            .checked_add(1)
            .ok_or(G4Error::DurableStateCorrupt)?;
        let previous_state_digest = self.current_head.state_digest();
        let previous_authority_state_digest =
            authority_state_digest(self.namespace, self.authority_state.as_slice());
        let bytes = encode_encrypted_snapshot(
            durable_sequence,
            previous_state_digest,
            previous_authority_state_digest,
            &next_registry,
            &next_authority_state,
            &self.encryption_key,
            self.namespace,
        )?;
        let next_head = RollbackProtectedStateHeadV2::new(
            durable_sequence,
            state_head_digest(self.namespace, &bytes),
        )?;

        observer.reached(ConnectorStoreDurabilityPointV2::BeforeWrite)?;
        self.lock.recheck().map_err(|_| G4Error::DurableStateIo)?;
        let replace_result = self.anchored_path.replace_observed(&bytes, |boundary| {
            let point = match boundary {
                AtomicReplaceBoundary::FileFlushed => ConnectorStoreDurabilityPointV2::FileFlushed,
                AtomicReplaceBoundary::RenamedBeforeDirectoryFlush => {
                    ConnectorStoreDurabilityPointV2::RenamedBeforeDirectoryFlush
                }
                AtomicReplaceBoundary::DirectoryFlushed => {
                    ConnectorStoreDurabilityPointV2::DirectoryFlushed
                }
            };
            observer
                .reached(point)
                .map_err(|_| PolicyError::io("injected connector store durability fault"))
        });
        if let Err(error) = replace_result {
            if error.phase() == PersistencePhase::AfterRename {
                self.poisoned = true;
                return Err(G4Error::DurableCommitUncertain);
            }
            return Err(G4Error::DurableStateIo);
        }

        let reopened_bytes = match self.anchored_path.read_existing() {
            Ok(Some(reopened)) if reopened == bytes => reopened,
            Ok(_) | Err(_) => {
                self.poisoned = true;
                return Err(G4Error::DurableCommitUncertain);
            }
        };
        let reopened = match decode_encrypted_snapshot(
            &reopened_bytes,
            &self.encryption_key,
            self.namespace,
            &self.genesis,
        ) {
            Ok(reopened) => reopened,
            Err(_) => {
                self.poisoned = true;
                return Err(G4Error::DurableCommitUncertain);
            }
        };
        if reopened.durable_sequence != durable_sequence
            || reopened.previous_state_digest != previous_state_digest
            || !reopened
                .registry
                .has_same_verified_registered_chain(&next_registry)
            || reopened.authority_state.as_slice() != next_authority_state.as_slice()
        {
            self.poisoned = true;
            return Err(G4Error::DurableCommitUncertain);
        }
        if observer
            .reached(ConnectorStoreDurabilityPointV2::Reopened)
            .is_err()
        {
            self.poisoned = true;
            return Err(G4Error::DurableCommitUncertain);
        }
        if self
            .rollback_anchor
            .compare_and_advance(self.current_head, next_head)
            .is_err()
        {
            self.poisoned = true;
            return Err(G4Error::DurableCommitUncertain);
        }
        if observer
            .reached(ConnectorStoreDurabilityPointV2::HighWaterAdvanced)
            .is_err()
        {
            self.poisoned = true;
            return Err(G4Error::DurableCommitUncertain);
        }
        if self.lock.recheck().is_err() {
            self.poisoned = true;
            return Err(G4Error::DurableCommitUncertain);
        }

        self.registry = next_registry;
        self.authority_state = next_authority_state;
        self.durable_sequence = durable_sequence;
        self.current_head = next_head;
        self.previous_authority_state_digest = previous_authority_state_digest;
        Ok(self.registry.clone())
    }

    fn ensure_usable(&self) -> Result<(), G4Error> {
        if self.poisoned {
            Err(G4Error::DurableCommitUncertain)
        } else {
            Ok(())
        }
    }

    fn current_revision(&self) -> ConnectorStoreRevisionV2 {
        ConnectorStoreRevisionV2 {
            durable_sequence: self.durable_sequence,
            authority_state_digest: authority_state_digest(
                self.namespace,
                self.authority_state.as_slice(),
            ),
        }
    }

    fn is_exact_predecessor_retry(
        &self,
        expected_registry_head: Digest32V2,
        expected_revision: ConnectorStoreRevisionV2,
        canonical_delta: Option<&[u8]>,
        authority_state: &[u8],
    ) -> bool {
        if expected_revision.durable_sequence.checked_add(1) != Some(self.durable_sequence)
            || expected_revision.authority_state_digest != self.previous_authority_state_digest
            || authority_state != self.authority_state.as_slice()
        {
            return false;
        }
        match canonical_delta {
            Some(delta) => self.registry.deltas().last().is_some_and(|existing| {
                existing.canonical_bytes() == delta
                    && (expected_registry_head == self.registry.head_digest()
                        || expected_registry_head == existing.previous_head_digest())
            }),
            None => expected_registry_head == self.registry.head_digest(),
        }
    }
}

fn validate_genesis(genesis: &ConnectorRegistryStateV2) -> Result<(), G4Error> {
    if genesis.sequence() != 0
        || genesis.head_digest() != genesis.genesis_digest()
        || !genesis.deltas().is_empty()
    {
        return Err(G4Error::DurableStateCorrupt);
    }
    Ok(())
}

fn genesis_store_head() -> Result<RollbackProtectedStateHeadV2, G4Error> {
    RollbackProtectedStateHeadV2::new(0, Digest32V2::new([0; 32]))
}

fn derive_encryption_key(
    master_key: &[u8; 32],
    namespace: DurableStateNamespaceV2,
) -> Result<Zeroizing<[u8; 32]>, G4Error> {
    let mut mac = <Hmac<Sha256> as hmac::Mac>::new_from_slice(master_key)
        .map_err(|_| G4Error::DurableStateIo)?;
    mac.update(STATE_KEY_DERIVATION_DOMAIN_V2);
    mac.update(namespace.installation_id().as_bytes());
    mac.update(namespace.store_id().as_bytes());
    Ok(Zeroizing::new(mac.finalize().into_bytes().into()))
}

fn encode_encrypted_snapshot(
    durable_sequence: u64,
    previous_state_digest: Digest32V2,
    previous_authority_state_digest: Digest32V2,
    registry: &ConnectorRegistryStateV2,
    authority_state: &[u8],
    encryption_key: &[u8; 32],
    namespace: DurableStateNamespaceV2,
) -> Result<Vec<u8>, G4Error> {
    let plaintext = encode_snapshot_payload(
        durable_sequence,
        previous_state_digest,
        previous_authority_state_digest,
        registry,
        authority_state,
    )?;
    let mut nonce = [0_u8; NONCE_BYTES_V2];
    getrandom::getrandom(&mut nonce).map_err(|_| G4Error::DurableStateIo)?;
    if nonce == [0; NONCE_BYTES_V2] {
        return Err(G4Error::DurableStateIo);
    }
    let aad = encryption_aad(namespace, durable_sequence, previous_state_digest, &nonce);
    let cipher = Aes256Gcm::new_from_slice(encryption_key).map_err(|_| G4Error::DurableStateIo)?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext.as_slice(),
                aad: &aad,
            },
        )
        .map_err(|_| G4Error::DurableStateIo)?;
    encode_encrypted_envelope(
        durable_sequence,
        previous_state_digest,
        &nonce,
        &ciphertext,
        namespace.store_id(),
    )
}

fn decode_encrypted_snapshot(
    bytes: &[u8],
    encryption_key: &[u8; 32],
    namespace: DurableStateNamespaceV2,
    genesis: &ConnectorRegistryStateV2,
) -> Result<DecodedConnectorSnapshotV2, G4Error> {
    let (durable_sequence, previous_state_digest, nonce, ciphertext) =
        decode_encrypted_envelope(bytes, namespace)?;
    let aad = encryption_aad(namespace, durable_sequence, previous_state_digest, &nonce);
    let cipher = Aes256Gcm::new_from_slice(encryption_key)
        .map_err(|_| G4Error::DurableStateAuthentication)?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| G4Error::DurableStateAuthentication)?,
    );
    decode_snapshot_payload(
        &plaintext,
        durable_sequence,
        previous_state_digest,
        namespace,
        genesis,
    )
}

fn encode_encrypted_envelope(
    durable_sequence: u64,
    previous_state_digest: Digest32V2,
    nonce: &[u8; NONCE_BYTES_V2],
    ciphertext: &[u8],
    store_id: Digest32V2,
) -> Result<Vec<u8>, G4Error> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(6)
        .and_then(|encoder| encoder.u16(STATE_SCHEMA_VERSION_V2))
        .and_then(|encoder| encoder.u64(durable_sequence))
        .and_then(|encoder| encoder.bytes(previous_state_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(nonce))
        .and_then(|encoder| encoder.bytes(ciphertext))
        .and_then(|encoder| encoder.bytes(store_id.as_bytes()))
        .map_err(|_| G4Error::DurableStateIo)?;
    let bytes = encoder.into_writer();
    if durable_sequence == 0 || bytes.len() > MAX_STATE_BYTES_V2 {
        return Err(G4Error::DurableStateCorrupt);
    }
    Ok(bytes)
}

fn decode_encrypted_envelope(
    bytes: &[u8],
    namespace: DurableStateNamespaceV2,
) -> Result<(u64, Digest32V2, [u8; NONCE_BYTES_V2], Vec<u8>), G4Error> {
    if bytes.is_empty() || bytes.len() > MAX_STATE_BYTES_V2 {
        return Err(G4Error::DurableStateAuthentication);
    }
    let mut decoder = minicbor::Decoder::new(bytes);
    let parsed = (|| {
        if decoder.array().ok()? != Some(6) || decoder.u16().ok()? != STATE_SCHEMA_VERSION_V2 {
            return None;
        }
        let durable_sequence = decoder.u64().ok()?;
        let previous_state_digest = Digest32V2::new(decoder.bytes().ok()?.try_into().ok()?);
        let nonce = decoder.bytes().ok()?.try_into().ok()?;
        let ciphertext = decoder.bytes().ok()?.to_vec();
        let store_id = Digest32V2::new(decoder.bytes().ok()?.try_into().ok()?);
        if decoder.position() != bytes.len()
            || durable_sequence == 0
            || ciphertext.is_empty()
            || ciphertext.len() > MAX_STATE_BYTES_V2
            || store_id != namespace.store_id()
        {
            return None;
        }
        Some((
            durable_sequence,
            previous_state_digest,
            nonce,
            ciphertext,
            store_id,
        ))
    })()
    .ok_or(G4Error::DurableStateAuthentication)?;
    let canonical = encode_encrypted_envelope(parsed.0, parsed.1, &parsed.2, &parsed.3, parsed.4)
        .map_err(|_| G4Error::DurableStateAuthentication)?;
    if canonical.as_slice() != bytes {
        return Err(G4Error::DurableStateAuthentication);
    }
    Ok((parsed.0, parsed.1, parsed.2, parsed.3))
}

fn encode_snapshot_payload(
    durable_sequence: u64,
    previous_state_digest: Digest32V2,
    previous_authority_state_digest: Digest32V2,
    registry: &ConnectorRegistryStateV2,
    authority_state: &[u8],
) -> Result<Zeroizing<Vec<u8>>, G4Error> {
    if durable_sequence == 0
        || registry.deltas().len() > MAX_JOURNAL_DELTAS_V2
        || authority_state.len() > MAX_CONNECTOR_AUTHORITY_STATE_BYTES_V2
    {
        return Err(G4Error::DurableStateCorrupt);
    }
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(10)
        .and_then(|encoder| encoder.u16(SNAPSHOT_SCHEMA_VERSION_V2))
        .and_then(|encoder| encoder.u64(durable_sequence))
        .and_then(|encoder| encoder.bytes(previous_state_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(previous_authority_state_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(registry.genesis_digest().as_bytes()))
        .and_then(|encoder| encoder.bytes(&registry.connector_authority_public_key()))
        .and_then(|encoder| encoder.u64(registry.sequence()))
        .and_then(|encoder| encoder.bytes(registry.head_digest().as_bytes()))
        .and_then(|encoder| encoder.array(registry.deltas().len() as u64))
        .map_err(|_| G4Error::DurableStateCorrupt)?;
    for delta in registry.deltas() {
        encoder
            .bytes(delta.canonical_bytes())
            .map_err(|_| G4Error::DurableStateCorrupt)?;
    }
    encoder
        .bytes(authority_state)
        .map_err(|_| G4Error::DurableStateCorrupt)?;
    let bytes = encoder.into_writer();
    if bytes.len() > MAX_STATE_BYTES_V2 {
        return Err(G4Error::DescriptorLimitExceeded);
    }
    Ok(Zeroizing::new(bytes))
}

fn decode_snapshot_payload(
    bytes: &[u8],
    expected_durable_sequence: u64,
    expected_previous_state_digest: Digest32V2,
    namespace: DurableStateNamespaceV2,
    genesis: &ConnectorRegistryStateV2,
) -> Result<DecodedConnectorSnapshotV2, G4Error> {
    if bytes.is_empty() || bytes.len() > MAX_STATE_BYTES_V2 {
        return Err(G4Error::DurableStateCorrupt);
    }
    let mut decoder = minicbor::Decoder::new(bytes);
    if decoder.array().map_err(|_| G4Error::DurableStateCorrupt)? != Some(10)
        || decoder.u16().map_err(|_| G4Error::DurableStateCorrupt)? != SNAPSHOT_SCHEMA_VERSION_V2
    {
        return Err(G4Error::DurableStateCorrupt);
    }
    let durable_sequence = decoder.u64().map_err(|_| G4Error::DurableStateCorrupt)?;
    let previous_state_digest = decode_digest(&mut decoder)?;
    let previous_authority_state_digest = decode_digest(&mut decoder)?;
    let stored_genesis_digest = decode_digest(&mut decoder)?;
    let stored_authority_public_key = decode_fixed::<32>(&mut decoder)?;
    let stored_registry_sequence = decoder.u64().map_err(|_| G4Error::DurableStateCorrupt)?;
    let stored_registry_head = decode_digest(&mut decoder)?;
    let delta_count = decoder
        .array()
        .map_err(|_| G4Error::DurableStateCorrupt)?
        .and_then(|count| usize::try_from(count).ok())
        .ok_or(G4Error::DurableStateCorrupt)?;
    if delta_count > MAX_JOURNAL_DELTAS_V2 {
        return Err(G4Error::DurableStateCorrupt);
    }
    let mut deltas = Vec::new();
    deltas
        .try_reserve_exact(delta_count)
        .map_err(|_| G4Error::AllocationFailure)?;
    for _ in 0..delta_count {
        deltas.push(
            decoder
                .bytes()
                .map_err(|_| G4Error::DurableStateCorrupt)?
                .to_vec(),
        );
    }
    let authority_state = decoder.bytes().map_err(|_| G4Error::DurableStateCorrupt)?;
    if authority_state.len() > MAX_CONNECTOR_AUTHORITY_STATE_BYTES_V2
        || decoder.position() != bytes.len()
        || durable_sequence != expected_durable_sequence
        || previous_state_digest != expected_previous_state_digest
        || (durable_sequence == 1
            && previous_authority_state_digest != authority_state_digest(namespace, &[]))
        || stored_genesis_digest != genesis.genesis_digest()
        || stored_authority_public_key != genesis.connector_authority_public_key()
    {
        return Err(G4Error::DurableStateCorrupt);
    }

    let mut registry = genesis.clone();
    for delta in &deltas {
        registry
            .replay_canonical_delta(delta)
            .map_err(|_| G4Error::DurableStateCorrupt)?;
    }
    if registry.sequence() != stored_registry_sequence
        || registry.head_digest() != stored_registry_head
    {
        return Err(G4Error::DurableStateCorrupt);
    }
    let canonical = encode_snapshot_payload(
        durable_sequence,
        previous_state_digest,
        previous_authority_state_digest,
        &registry,
        authority_state,
    )?;
    if canonical.as_slice() != bytes {
        return Err(G4Error::DurableStateCorrupt);
    }
    Ok(DecodedConnectorSnapshotV2 {
        durable_sequence,
        previous_state_digest,
        previous_authority_state_digest,
        registry,
        authority_state: Zeroizing::new(authority_state.to_vec()),
    })
}

fn decode_digest(decoder: &mut minicbor::Decoder<'_>) -> Result<Digest32V2, G4Error> {
    Ok(Digest32V2::new(decode_fixed::<32>(decoder)?))
}

fn decode_fixed<const N: usize>(decoder: &mut minicbor::Decoder<'_>) -> Result<[u8; N], G4Error> {
    decoder
        .bytes()
        .map_err(|_| G4Error::DurableStateCorrupt)?
        .try_into()
        .map_err(|_| G4Error::DurableStateCorrupt)
}

fn encryption_aad(
    namespace: DurableStateNamespaceV2,
    durable_sequence: u64,
    previous_state_digest: Digest32V2,
    nonce: &[u8; NONCE_BYTES_V2],
) -> Vec<u8> {
    let mut aad =
        Vec::with_capacity(STATE_ENCRYPTION_DOMAIN_V2.len() + 32 + 32 + 8 + 32 + NONCE_BYTES_V2);
    aad.extend_from_slice(STATE_ENCRYPTION_DOMAIN_V2);
    aad.extend_from_slice(namespace.installation_id().as_bytes());
    aad.extend_from_slice(namespace.store_id().as_bytes());
    aad.extend_from_slice(&durable_sequence.to_be_bytes());
    aad.extend_from_slice(previous_state_digest.as_bytes());
    aad.extend_from_slice(nonce);
    aad
}

fn state_head_digest(namespace: DurableStateNamespaceV2, bytes: &[u8]) -> Digest32V2 {
    let mut hasher = Sha256::new();
    hasher.update(STATE_HEAD_DOMAIN_V2);
    hasher.update(namespace.installation_id().as_bytes());
    hasher.update(namespace.store_id().as_bytes());
    hasher.update(bytes);
    Digest32V2::new(hasher.finalize().into())
}

fn authority_state_digest(namespace: DurableStateNamespaceV2, bytes: &[u8]) -> Digest32V2 {
    let mut hasher = Sha256::new();
    hasher.update(AUTHORITY_STATE_DIGEST_DOMAIN_V2);
    hasher.update(namespace.installation_id().as_bytes());
    hasher.update(namespace.store_id().as_bytes());
    hasher.update(bytes);
    Digest32V2::new(hasher.finalize().into())
}

#[cfg(any(test, feature = "test-support"))]
fn domain_hash(domain: &[u8], bytes: &[u8]) -> Digest32V2 {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    Digest32V2::new(hasher.finalize().into())
}
