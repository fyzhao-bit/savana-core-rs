use std::collections::{HashMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use aes_gcm::aead::{Aead as _, Payload};
use aes_gcm::{Aes256Gcm, KeyInit as _, Nonce};
use hmac::{Hmac, Mac as _};
use minicbor::data::Type;
use minicbor::Encode as _;
use nix::fcntl::{Flock, FlockArg};
use rustix::fs::{
    fchmod, open as rustix_open, openat, renameat, statat, unlinkat, AtFlags, FileType, Mode,
    OFlags,
};
use rustix::io::Errno;
use savana_kernel_protocol::v2::{
    Digest32V2, ExecutorFailureClassV2, Nonce32V2, SignedExecutorEffectStartedReceiptV2,
    UnixMillisV2,
};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use super::{
    decode_signed_receipt, is_zero, verify_persisted_dispatch_envelope, ArmedEffectV2,
    DispatchEnvelopeKindV2, ExecdErrorV2, ExecdJournalEntryV2, ExecdJournalStateV2, ExecdQueryV2,
    ExecdServiceV2, ExecutorReceiptKindV2, ProviderAttemptPredecessorV2,
    RetainedProviderResponseV2, SignedDispatchAdmissionV2, SignedExecutorReceiptV2,
    StoredExecutorCompletionV2, VerifiedExecdDeploymentV2,
};

const JOURNAL_FILE_NAME: &str = "execd-journal-v2.cbor";
const LOCK_FILE_NAME: &str = ".execd-journal-v2.cbor.lock";
const SCHEMA_VERSION: u16 = 6;
const ENCRYPTION_DOMAIN: &[u8] = b"SAVANA_EXECD_JOURNAL_ENCRYPTION_V2\0";
const KEY_DERIVATION_DOMAIN: &[u8] = b"SAVANA_EXECD_JOURNAL_KEY_DERIVATION_V2\0";
const HEAD_DOMAIN: &[u8] = b"SAVANA_EXECD_JOURNAL_HEAD_V2\0";
const NONCE_BYTES: usize = 12;
const MAX_JOURNAL_BYTES: u64 = 64 * 1024 * 1024;
const MAX_ENTRIES: usize = 65_536;
const MAX_RECEIPT_BYTES: usize = 1024 * 1024;
const TEMP_ATTEMPTS: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecdStateHeadV2 {
    sequence: u64,
    state_digest: Digest32V2,
}

impl Default for ExecdStateHeadV2 {
    fn default() -> Self {
        Self::GENESIS
    }
}

impl ExecdStateHeadV2 {
    const GENESIS: Self = Self {
        sequence: 0,
        state_digest: Digest32V2::new([0; 32]),
    };

    pub fn new(sequence: u64, state_digest: Digest32V2) -> Result<Self, ExecdErrorV2> {
        if (sequence == 0 && !is_zero(state_digest.as_bytes()))
            || (sequence != 0 && is_zero(state_digest.as_bytes()))
        {
            return Err(ExecdErrorV2::RollbackDetected);
        }
        Ok(Self {
            sequence,
            state_digest,
        })
    }

    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    pub const fn state_digest(self) -> Digest32V2 {
        self.state_digest
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DurableExecdNamespaceV2 {
    installation_id: Digest32V2,
    store_id: Digest32V2,
}

impl DurableExecdNamespaceV2 {
    pub fn from_verified_installation(
        installation_id: Digest32V2,
        store_id: Digest32V2,
    ) -> Result<Self, ExecdErrorV2> {
        if is_zero(installation_id.as_bytes()) || is_zero(store_id.as_bytes()) {
            return Err(ExecdErrorV2::DurableState);
        }
        Ok(Self {
            installation_id,
            store_id,
        })
    }

    pub const fn installation_id(self) -> Digest32V2 {
        self.installation_id
    }

    pub const fn store_id(self) -> Digest32V2 {
        self.store_id
    }
}

pub trait ExecdRollbackAnchorV2: Send {
    fn current_head(&self) -> Result<ExecdStateHeadV2, ExecdErrorV2>;

    fn compare_and_advance(
        &mut self,
        expected: ExecdStateHeadV2,
        next: ExecdStateHeadV2,
    ) -> Result<(), ExecdErrorV2>;
}

pub struct DurableExecdServiceV2 {
    path: PathBuf,
    anchored_path: AnchoredPathV2,
    namespace: DurableExecdNamespaceV2,
    encryption_key: Zeroizing<[u8; 32]>,
    sequence: u64,
    previous_state_digest: Digest32V2,
    current_head: ExecdStateHeadV2,
    rollback_anchor: Box<dyn ExecdRollbackAnchorV2>,
    /// Fully validated when loaded and on every commit; never mutated in place.
    service: ExecdServiceV2,
    service_digest: Digest32V2,
    poisoned: bool,
    lock: JournalLockV2,
}

impl std::fmt::Debug for DurableExecdServiceV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DurableExecdServiceV2")
            .field("path", &self.path)
            .field("sequence", &self.sequence)
            .field("poisoned", &self.poisoned)
            .finish_non_exhaustive()
    }
}

impl DurableExecdServiceV2 {
    pub fn open(
        path: &Path,
        master_encryption_key: [u8; 32],
        namespace: DurableExecdNamespaceV2,
        mut rollback_anchor: Box<dyn ExecdRollbackAnchorV2>,
        deployment: VerifiedExecdDeploymentV2,
    ) -> Result<Self, ExecdErrorV2> {
        if path.file_name().and_then(|name| name.to_str()) != Some(JOURNAL_FILE_NAME)
            || master_encryption_key == [0; 32]
            || deployment.installation_id != namespace.installation_id
        {
            return Err(ExecdErrorV2::DurableState);
        }
        let anchored_path = AnchoredPathV2::open(path)?;
        let lock = JournalLockV2::acquire(
            &anchored_path.parent,
            OsStr::new(LOCK_FILE_NAME),
            anchored_path.owner_uid,
            anchored_path.owner_gid,
        )?;
        anchored_path.recheck_parent()?;
        let encryption_key = derive_encryption_key(&master_encryption_key, namespace)?;
        let anchored_head = rollback_anchor.current_head()?;
        let (sequence, previous_state_digest, service, current_head) =
            match anchored_path.read_existing()? {
                Some(bytes) => {
                    let (sequence, previous_state_digest, service) =
                        decode_encrypted_snapshot(&bytes, &encryption_key, namespace, deployment)?;
                    let snapshot_head = ExecdStateHeadV2 {
                        sequence,
                        state_digest: state_head_digest(namespace, &bytes),
                    };
                    if snapshot_head == anchored_head {
                        (sequence, previous_state_digest, service, snapshot_head)
                    } else if sequence
                        == anchored_head
                            .sequence
                            .checked_add(1)
                            .ok_or(ExecdErrorV2::RollbackDetected)?
                        && previous_state_digest == anchored_head.state_digest
                    {
                        rollback_anchor.compare_and_advance(anchored_head, snapshot_head)?;
                        (sequence, previous_state_digest, service, snapshot_head)
                    } else {
                        return Err(ExecdErrorV2::RollbackDetected);
                    }
                }
                None => {
                    if anchored_head != ExecdStateHeadV2::GENESIS {
                        return Err(ExecdErrorV2::RollbackDetected);
                    }
                    (
                        0,
                        Digest32V2::new([0; 32]),
                        ExecdServiceV2::new(deployment),
                        ExecdStateHeadV2::GENESIS,
                    )
                }
            };
        let service_digest = service_state_digest(&service)?;
        Ok(Self {
            path: path.to_owned(),
            anchored_path,
            namespace,
            encryption_key,
            sequence,
            previous_state_digest,
            current_head,
            rollback_anchor,
            service,
            service_digest,
            poisoned: false,
            lock,
        })
    }

    pub fn query(&self, nonce: Nonce32V2) -> Result<ExecdQueryV2, ExecdErrorV2> {
        self.ensure_usable()?;
        self.service.query(nonce)
    }

    pub(crate) fn sealed_execution_envelope(
        &self,
        nonce: Nonce32V2,
    ) -> Result<Zeroizing<Vec<u8>>, ExecdErrorV2> {
        self.ensure_usable()?;
        self.service.sealed_execution_envelope(nonce)
    }

    pub fn recovery_projection(&self) -> Result<Vec<ExecdQueryV2>, ExecdErrorV2> {
        self.ensure_usable()?;
        self.service.recovery_projection()
    }

    pub fn terminal_receipt(
        &self,
        nonce: Nonce32V2,
    ) -> Result<SignedExecutorReceiptV2, ExecdErrorV2> {
        self.ensure_usable()?;
        self.service.terminal_receipt(nonce)
    }

    pub fn effect_started_receipt(
        &self,
        nonce: Nonce32V2,
    ) -> Result<SignedExecutorEffectStartedReceiptV2, ExecdErrorV2> {
        self.ensure_usable()?;
        self.service.effect_started_receipt(nonce)
    }

    pub fn retained_provider_response(
        &self,
        nonce: Nonce32V2,
    ) -> Result<RetainedProviderResponseV2, ExecdErrorV2> {
        self.ensure_usable()?;
        self.service.retained_provider_response(nonce)
    }

    pub fn completion(&self, nonce: Nonce32V2) -> Result<StoredExecutorCompletionV2, ExecdErrorV2> {
        self.ensure_usable()?;
        self.service.completion(nonce)
    }

    #[cfg(test)]
    pub fn accept_signed_dispatch(
        &mut self,
        canonical_envelope: &[u8],
        now: UnixMillisV2,
    ) -> Result<ExecdQueryV2, ExecdErrorV2> {
        self.mutate(|service| service.accept_signed_dispatch(canonical_envelope, now))
    }

    pub(crate) fn classify_signed_dispatch(
        &self,
        canonical_envelope: &[u8],
        now: UnixMillisV2,
    ) -> Result<SignedDispatchAdmissionV2, ExecdErrorV2> {
        self.ensure_usable()?;
        self.service
            .classify_signed_dispatch(canonical_envelope, now)
    }

    pub(crate) fn commit_new_signed_dispatch(
        &mut self,
        verified: super::VerifiedSignedDispatchEnvelopeV2,
    ) -> Result<ExecdQueryV2, ExecdErrorV2> {
        self.mutate(move |service| service.accept_verified_dispatch(verified))
    }

    pub fn prepare_provider_attempt(
        &mut self,
        nonce: Nonce32V2,
        prepared_request_digest: Digest32V2,
        now: UnixMillisV2,
    ) -> Result<ProviderAttemptPredecessorV2, ExecdErrorV2> {
        self.mutate(|service| service.prepare_provider_attempt(nonce, prepared_request_digest, now))
    }

    pub fn record_effect_started(
        &mut self,
        predecessor: ProviderAttemptPredecessorV2,
        now: UnixMillisV2,
    ) -> Result<ArmedEffectV2, ExecdErrorV2> {
        self.mutate(|service| service.record_effect_started(predecessor, now))
    }

    pub fn record_provider_response(
        &mut self,
        nonce: Nonce32V2,
        response: Vec<u8>,
    ) -> Result<RetainedProviderResponseV2, ExecdErrorV2> {
        self.mutate(move |service| service.record_provider_response(nonce, response))
    }

    pub fn prepare_final_release_evidence(
        &mut self,
        nonce: Nonce32V2,
        provider_evidence: Vec<u8>,
        audit_evidence: Vec<u8>,
        now: UnixMillisV2,
    ) -> Result<Digest32V2, ExecdErrorV2> {
        self.mutate(move |service| {
            service.prepare_final_release_evidence(nonce, provider_evidence, audit_evidence, now)
        })
    }

    #[cfg(test)]
    pub fn record_known_success(
        &mut self,
        nonce: Nonce32V2,
        evidence_digest: Digest32V2,
        now: UnixMillisV2,
    ) -> Result<SignedExecutorReceiptV2, ExecdErrorV2> {
        self.mutate(|service| service.record_known_success(nonce, evidence_digest, now))
    }

    pub fn record_tool_completion(
        &mut self,
        nonce: Nonce32V2,
        result: Vec<u8>,
        evidence_digest: Digest32V2,
        now: UnixMillisV2,
    ) -> Result<StoredExecutorCompletionV2, ExecdErrorV2> {
        self.mutate(|service| service.record_tool_completion(nonce, result, evidence_digest, now))
    }

    pub fn record_final_release_completion(
        &mut self,
        nonce: Nonce32V2,
        now: UnixMillisV2,
    ) -> Result<StoredExecutorCompletionV2, ExecdErrorV2> {
        self.mutate(|service| service.record_final_release_completion(nonce, now))
    }

    pub fn record_failed_no_effect(
        &mut self,
        nonce: Nonce32V2,
        class: ExecutorFailureClassV2,
        evidence_digest: Digest32V2,
        now: UnixMillisV2,
    ) -> Result<SignedExecutorReceiptV2, ExecdErrorV2> {
        self.mutate(|service| service.record_failed_no_effect(nonce, class, evidence_digest, now))
    }

    pub fn record_failed_no_effect_recovery(
        &mut self,
        nonce: Nonce32V2,
        class: ExecutorFailureClassV2,
        evidence_digest: Digest32V2,
        now: UnixMillisV2,
    ) -> Result<SignedExecutorReceiptV2, ExecdErrorV2> {
        self.mutate(|service| {
            service.record_failed_no_effect_recovery(nonce, class, evidence_digest, now)
        })
    }

    pub fn record_indeterminate(
        &mut self,
        nonce: Nonce32V2,
        evidence_digest: Digest32V2,
        now: UnixMillisV2,
    ) -> Result<SignedExecutorReceiptV2, ExecdErrorV2> {
        self.mutate(|service| service.record_indeterminate(nonce, evidence_digest, now))
    }

    pub fn record_indeterminate_recovery(
        &mut self,
        nonce: Nonce32V2,
        evidence_digest: Digest32V2,
        now: UnixMillisV2,
    ) -> Result<SignedExecutorReceiptV2, ExecdErrorV2> {
        self.mutate(|service| service.record_indeterminate_recovery(nonce, evidence_digest, now))
    }

    pub fn acknowledge_completion(
        &mut self,
        nonce: Nonce32V2,
        kernel_commit_digest: Digest32V2,
    ) -> Result<(), ExecdErrorV2> {
        self.mutate(|service| service.acknowledge_completion(nonce, kernel_commit_digest))
    }

    fn mutate<T>(
        &mut self,
        operation: impl FnOnce(&mut ExecdServiceV2) -> Result<T, ExecdErrorV2>,
    ) -> Result<T, ExecdErrorV2> {
        self.ensure_usable()?;
        let mut next = self.service.clone();
        let result = operation(&mut next)?;
        let next_digest = service_state_digest(&next)?;
        if next_digest != self.service_digest {
            self.commit(next, next_digest)?;
        }
        Ok(result)
    }

    fn ensure_usable(&self) -> Result<(), ExecdErrorV2> {
        if self.poisoned {
            Err(ExecdErrorV2::CommitUncertain)
        } else {
            Ok(())
        }
    }

    fn commit(
        &mut self,
        next: ExecdServiceV2,
        next_digest: Digest32V2,
    ) -> Result<(), ExecdErrorV2> {
        let sequence = self
            .sequence
            .checked_add(1)
            .ok_or(ExecdErrorV2::DurableState)?;
        let previous_state_digest = self.current_head.state_digest;
        validate_service_change(&self.service, &next)?;
        let bytes = encode_encrypted_snapshot(
            sequence,
            previous_state_digest,
            &next,
            &self.encryption_key,
            self.namespace,
        )?;
        let next_head = ExecdStateHeadV2 {
            sequence,
            state_digest: state_head_digest(self.namespace, &bytes),
        };
        self.lock.recheck()?;
        match self.anchored_path.replace(&bytes) {
            Ok(()) => {
                if self
                    .rollback_anchor
                    .compare_and_advance(self.current_head, next_head)
                    .is_err()
                {
                    self.poisoned = true;
                    return Err(ExecdErrorV2::CommitUncertain);
                }
                self.service = next;
                self.service_digest = next_digest;
                self.sequence = sequence;
                self.previous_state_digest = previous_state_digest;
                self.current_head = next_head;
                Ok(())
            }
            Err(after_rename) => {
                if after_rename {
                    self.poisoned = true;
                    Err(ExecdErrorV2::CommitUncertain)
                } else {
                    Err(ExecdErrorV2::DurableState)
                }
            }
        }
    }
}

fn encode_encrypted_snapshot(
    sequence: u64,
    previous_state_digest: Digest32V2,
    service: &ExecdServiceV2,
    key: &[u8; 32],
    namespace: DurableExecdNamespaceV2,
) -> Result<Vec<u8>, ExecdErrorV2> {
    let payload = encode_snapshot_payload(sequence, previous_state_digest, service)?;
    let mut nonce = [0_u8; NONCE_BYTES];
    getrandom::getrandom(&mut nonce).map_err(|_| ExecdErrorV2::DurableState)?;
    if nonce == [0; NONCE_BYTES] {
        return Err(ExecdErrorV2::DurableState);
    }
    let aad = encryption_aad(namespace, sequence, previous_state_digest, &nonce);
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| ExecdErrorV2::DurableAuthentication)?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: payload.as_slice(),
                aad: &aad,
            },
        )
        .map_err(|_| ExecdErrorV2::DurableAuthentication)?;
    encode_encrypted_envelope(sequence, previous_state_digest, &nonce, &ciphertext)
}

fn decode_encrypted_snapshot(
    bytes: &[u8],
    key: &[u8; 32],
    namespace: DurableExecdNamespaceV2,
    deployment: VerifiedExecdDeploymentV2,
) -> Result<(u64, Digest32V2, ExecdServiceV2), ExecdErrorV2> {
    if bytes.len() as u64 > MAX_JOURNAL_BYTES {
        return Err(ExecdErrorV2::DurableState);
    }
    let mut decoder = minicbor::Decoder::new(bytes);
    require_array(&mut decoder, 5)?;
    if decoder.u16().map_err(|_| ExecdErrorV2::DurableState)? != SCHEMA_VERSION {
        return Err(ExecdErrorV2::DurableState);
    }
    let sequence = decoder.u64().map_err(|_| ExecdErrorV2::DurableState)?;
    let previous_state_digest = Digest32V2::new(decode_fixed::<32>(&mut decoder)?);
    let nonce = decode_fixed::<NONCE_BYTES>(&mut decoder)?;
    let ciphertext = decoder.bytes().map_err(|_| ExecdErrorV2::DurableState)?;
    if decoder.position() != bytes.len()
        || encode_encrypted_envelope(sequence, previous_state_digest, &nonce, ciphertext)? != bytes
    {
        return Err(ExecdErrorV2::DurableState);
    }
    let aad = encryption_aad(namespace, sequence, previous_state_digest, &nonce);
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| ExecdErrorV2::DurableAuthentication)?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| ExecdErrorV2::DurableAuthentication)?,
    );
    let service = decode_snapshot_payload(&plaintext, sequence, previous_state_digest, deployment)?;
    if encode_snapshot_payload(sequence, previous_state_digest, &service)?.as_slice()
        != plaintext.as_slice()
    {
        return Err(ExecdErrorV2::DurableState);
    }
    Ok((sequence, previous_state_digest, service))
}

fn encode_encrypted_envelope(
    sequence: u64,
    previous_state_digest: Digest32V2,
    nonce: &[u8; NONCE_BYTES],
    ciphertext: &[u8],
) -> Result<Vec<u8>, ExecdErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(5)
        .and_then(|encoder| encoder.u16(SCHEMA_VERSION))
        .and_then(|encoder| encoder.u64(sequence))
        .map_err(|_| ExecdErrorV2::AllocationFailure)?;
    previous_state_digest
        .encode(&mut encoder, &mut ())
        .map_err(|_| ExecdErrorV2::AllocationFailure)?;
    encoder
        .bytes(nonce)
        .and_then(|encoder| encoder.bytes(ciphertext))
        .map_err(|_| ExecdErrorV2::AllocationFailure)?;
    let bytes = encoder.into_writer();
    if bytes.len() as u64 > MAX_JOURNAL_BYTES {
        return Err(ExecdErrorV2::Capacity);
    }
    Ok(bytes)
}

/// Encodes `service` as persisted. Callers persist only a state that
/// `validate_service` (on load) or `validate_service_change` (on commit)
/// accepted; the digest used for change detection encodes any state.
fn encode_snapshot_payload(
    sequence: u64,
    previous_state_digest: Digest32V2,
    service: &ExecdServiceV2,
) -> Result<Zeroizing<Vec<u8>>, ExecdErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(4)
        .and_then(|encoder| encoder.u16(SCHEMA_VERSION))
        .and_then(|encoder| encoder.u64(sequence))
        .map_err(|_| ExecdErrorV2::AllocationFailure)?;
    previous_state_digest
        .encode(&mut encoder, &mut ())
        .map_err(|_| ExecdErrorV2::AllocationFailure)?;
    encoder
        .array(service.entries.len() as u64)
        .map_err(|_| ExecdErrorV2::AllocationFailure)?;
    for entry in &service.entries {
        encode_entry(&mut encoder, entry)?;
    }
    Ok(Zeroizing::new(encoder.into_writer()))
}

fn encode_entry(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    entry: &ExecdJournalEntryV2,
) -> Result<(), ExecdErrorV2> {
    encoder
        .array(14)
        .and_then(|encoder| encoder.bytes(&entry.canonical_envelope))
        .map_err(|_| ExecdErrorV2::AllocationFailure)?;
    entry
        .exact_envelope_digest
        .encode(encoder, &mut ())
        .map_err(|_| ExecdErrorV2::AllocationFailure)?;
    encoder
        .u16(state_tag(entry.state))
        .map_err(|_| ExecdErrorV2::AllocationFailure)?;
    encode_optional_digest(encoder, entry.provider_attempt_predecessor_digest)?;
    encode_optional_digest(encoder, entry.prepared_request_digest)?;
    encode_optional_effect_receipt(encoder, entry.effect_started_receipt.as_ref())?;
    encode_optional_bytes(
        encoder,
        entry
            .retained_provider_response
            .as_ref()
            .map(|bytes| bytes.as_slice()),
    )?;
    encode_optional_bytes(
        encoder,
        entry
            .completion
            .as_ref()
            .map(StoredExecutorCompletionV2::canonical_payload),
    )?;
    encode_optional_receipt(encoder, entry.terminal_receipt.as_ref())?;
    encoder
        .u16(entry.payload.kind.tag())
        .map_err(|_| ExecdErrorV2::AllocationFailure)?;
    encode_optional_failure_class(encoder, entry.failure_class)?;
    encode_optional_digest(encoder, entry.release_evidence_prepared_digest)?;
    encode_optional_bytes(
        encoder,
        entry
            .release_provider_evidence
            .as_ref()
            .map(|bytes| bytes.as_slice()),
    )?;
    encode_optional_bytes(
        encoder,
        entry
            .release_audit_evidence
            .as_ref()
            .map(|bytes| bytes.as_slice()),
    )?;
    Ok(())
}

fn decode_snapshot_payload(
    bytes: &[u8],
    expected_sequence: u64,
    expected_previous_state_digest: Digest32V2,
    deployment: VerifiedExecdDeploymentV2,
) -> Result<ExecdServiceV2, ExecdErrorV2> {
    let mut decoder = minicbor::Decoder::new(bytes);
    require_array(&mut decoder, 4)?;
    if decoder.u16().map_err(|_| ExecdErrorV2::DurableState)? != SCHEMA_VERSION
        || decoder.u64().map_err(|_| ExecdErrorV2::DurableState)? != expected_sequence
        || Digest32V2::new(decode_fixed::<32>(&mut decoder)?) != expected_previous_state_digest
    {
        return Err(ExecdErrorV2::DurableState);
    }
    let count = decoder
        .array()
        .map_err(|_| ExecdErrorV2::DurableState)?
        .ok_or(ExecdErrorV2::DurableState)?;
    let count = usize::try_from(count).map_err(|_| ExecdErrorV2::Capacity)?;
    if count > MAX_ENTRIES {
        return Err(ExecdErrorV2::Capacity);
    }
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(count)
        .map_err(|_| ExecdErrorV2::AllocationFailure)?;
    for _ in 0..count {
        require_array(&mut decoder, 14)?;
        let canonical_envelope = decoder
            .bytes()
            .map_err(|_| ExecdErrorV2::DurableState)?
            .to_vec();
        let verified = verify_persisted_dispatch_envelope(&canonical_envelope, &deployment)?;
        let exact_envelope_digest = Digest32V2::new(decode_fixed::<32>(&mut decoder)?);
        if exact_envelope_digest != verified.exact_envelope_digest {
            return Err(ExecdErrorV2::DurableState);
        }
        let state = decode_state(decoder.u16().map_err(|_| ExecdErrorV2::DurableState)?)?;
        let provider_attempt_predecessor_digest = decode_optional_digest(&mut decoder)?;
        let prepared_request_digest = decode_optional_digest(&mut decoder)?;
        let effect_started_receipt = decode_optional_effect_receipt(&mut decoder)?;
        let retained_provider_response = decode_optional_bytes(&mut decoder)?;
        let completion = match decode_optional_bytes(&mut decoder)? {
            Some(bytes) => {
                let payload =
                    savana_kernel_protocol::v2::decode_executor_completion_payload_v2(&bytes)
                        .map_err(|_| ExecdErrorV2::DurableState)?;
                Some(StoredExecutorCompletionV2::new(
                    payload
                        .descriptor()
                        .map_err(|_| ExecdErrorV2::DurableState)?,
                    bytes.to_vec(),
                )?)
            }
            None => None,
        };
        let terminal_receipt = decode_optional_receipt(&mut decoder)?;
        let stored_kind = DispatchEnvelopeKindV2::from_tag(
            decoder.u16().map_err(|_| ExecdErrorV2::DurableState)?,
        )?;
        if stored_kind != verified.payload.kind {
            return Err(ExecdErrorV2::DurableState);
        }
        let failure_class = decode_optional_failure_class(&mut decoder)?;
        let release_evidence_prepared_digest = decode_optional_digest(&mut decoder)?;
        let release_provider_evidence = decode_optional_bytes(&mut decoder)?;
        let release_audit_evidence = decode_optional_bytes(&mut decoder)?;
        entries.push(ExecdJournalEntryV2 {
            payload: verified.payload,
            exact_envelope_digest,
            canonical_envelope: verified.canonical_envelope,
            state,
            failure_class,
            prepared_request_digest,
            provider_attempt_predecessor_digest,
            effect_started_receipt,
            retained_provider_response,
            release_evidence_prepared_digest,
            release_provider_evidence,
            release_audit_evidence,
            completion,
            terminal_receipt,
        });
    }
    if decoder.position() != bytes.len() {
        return Err(ExecdErrorV2::DurableState);
    }
    let service = ExecdServiceV2 {
        deployment,
        entries,
    };
    validate_service(&service)?;
    Ok(service)
}

fn validate_service(service: &ExecdServiceV2) -> Result<(), ExecdErrorV2> {
    if service.entries.len() > MAX_ENTRIES {
        return Err(ExecdErrorV2::Capacity);
    }
    for (index, entry) in service.entries.iter().enumerate() {
        if service.entries[..index].iter().any(|candidate| {
            candidate.payload.execution_nonce == entry.payload.execution_nonce
                || candidate.exact_envelope_digest == entry.exact_envelope_digest
        }) {
            return Err(ExecdErrorV2::NonceRebinding);
        }
        validate_entry(entry, &service.deployment)?;
    }
    Ok(())
}

/// `validate_service` for a state derived from `previous`, which was itself
/// fully validated when it was loaded or committed. Every entry's shape and
/// uniqueness are checked; the signatures an entry carries are verified again
/// only if the entry is new, or differs in any persisted byte or in its
/// envelope payload from the verified entry with the same envelope digest.
/// A commit then costs work proportional to what it changed, not to the
/// length of the journal's history.
pub(super) fn validate_service_change(
    previous: &ExecdServiceV2,
    next: &ExecdServiceV2,
) -> Result<(), ExecdErrorV2> {
    if !same_deployment(&previous.deployment, &next.deployment) {
        return validate_service(next);
    }
    if next.entries.len() > MAX_ENTRIES {
        return Err(ExecdErrorV2::Capacity);
    }
    let mut nonces = HashSet::new();
    let mut digests = HashSet::new();
    let mut verified = HashMap::new();
    nonces
        .try_reserve(next.entries.len())
        .and_then(|()| digests.try_reserve(next.entries.len()))
        .and_then(|()| verified.try_reserve(previous.entries.len()))
        .map_err(|_| ExecdErrorV2::AllocationFailure)?;
    verified.extend(
        previous
            .entries
            .iter()
            .map(|entry| (*entry.exact_envelope_digest.as_bytes(), entry)),
    );
    for entry in &next.entries {
        if !nonces.insert(*entry.payload.execution_nonce.as_bytes())
            || !digests.insert(*entry.exact_envelope_digest.as_bytes())
        {
            return Err(ExecdErrorV2::NonceRebinding);
        }
        match verified.get(entry.exact_envelope_digest.as_bytes()) {
            Some(known) if same_entry(known, entry)? => validate_entry_state(entry)?,
            _ => validate_entry(entry, &next.deployment)?,
        }
    }
    Ok(())
}

fn validate_entry(
    entry: &ExecdJournalEntryV2,
    deployment: &VerifiedExecdDeploymentV2,
) -> Result<(), ExecdErrorV2> {
    #[cfg(test)]
    FULL_ENTRY_VALIDATIONS.with(|count| count.set(count.get() + 1));
    let verified = verify_persisted_dispatch_envelope(&entry.canonical_envelope, deployment)?;
    if verified.payload.execution_nonce != entry.payload.execution_nonce
        || verified.exact_envelope_digest != entry.exact_envelope_digest
    {
        return Err(ExecdErrorV2::DurableState);
    }
    validate_entry_state(entry)?;
    validate_effect_receipt_for_entry(entry, entry.effect_started_receipt.as_ref(), deployment)?;
    let terminal_kind = match entry.state {
        ExecdJournalStateV2::CompletionAvailable | ExecdJournalStateV2::Acknowledged => {
            Some(ExecutorReceiptKindV2::KnownSuccess)
        }
        ExecdJournalStateV2::FailedNoEffect => Some(ExecutorReceiptKindV2::FailedNoEffect),
        ExecdJournalStateV2::Indeterminate => Some(ExecutorReceiptKindV2::Indeterminate),
        _ => None,
    };
    validate_receipt_for_entry(
        entry,
        entry.terminal_receipt.as_ref(),
        terminal_kind,
        deployment,
    )
}

#[cfg(test)]
thread_local! {
    static FULL_ENTRY_VALIDATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Entries whose envelope and receipt signatures were verified on this thread.
#[cfg(test)]
pub(super) fn full_entry_validations_for_test() -> usize {
    FULL_ENTRY_VALIDATIONS.with(std::cell::Cell::get)
}

fn same_deployment(left: &VerifiedExecdDeploymentV2, right: &VerifiedExecdDeploymentV2) -> bool {
    left.installation_id == right.installation_id
        && left.active_state_manifest_digest == right.active_state_manifest_digest
        && left.deployment_generation == right.deployment_generation
        && left.effect_fence_epoch == right.effect_fence_epoch
        && left.executor_identity_digest == right.executor_identity_digest
        && left.kernel_envelope_key_id == right.kernel_envelope_key_id
        && left.kernel_envelope_verifying_key == right.kernel_envelope_verifying_key
        && left.effect_receipt_key_id == right.effect_receipt_key_id
        && left.effect_receipt_signing_key.verifying_key()
            == right.effect_receipt_signing_key.verifying_key()
}

fn same_entry(
    left: &ExecdJournalEntryV2,
    right: &ExecdJournalEntryV2,
) -> Result<bool, ExecdErrorV2> {
    if left.payload != right.payload {
        return Ok(false);
    }
    let mut left_bytes = minicbor::Encoder::new(Vec::new());
    let mut right_bytes = minicbor::Encoder::new(Vec::new());
    encode_entry(&mut left_bytes, left)?;
    encode_entry(&mut right_bytes, right)?;
    let left_bytes = Zeroizing::new(left_bytes.into_writer());
    let right_bytes = Zeroizing::new(right_bytes.into_writer());
    Ok(left_bytes.as_slice() == right_bytes.as_slice())
}

fn validate_entry_state(entry: &ExecdJournalEntryV2) -> Result<(), ExecdErrorV2> {
    let predecessor = entry.provider_attempt_predecessor_digest.is_some();
    let prepared_request = entry.prepared_request_digest.is_some();
    let effect = entry.effect_started_receipt.is_some();
    let retained = entry.retained_provider_response.is_some();
    let release_digest = entry.release_evidence_prepared_digest.is_some();
    let release_provider = entry.release_provider_evidence.is_some();
    let release_audit = entry.release_audit_evidence.is_some();
    let release = release_digest && release_provider && release_audit;
    let partial_release = release_digest || release_provider || release_audit;
    let completion = entry.completion.is_some();
    let terminal = entry.terminal_receipt.is_some();
    let failed = entry.failure_class.is_some();
    let valid = match entry.state {
        ExecdJournalStateV2::Prepared => {
            !predecessor
                && !prepared_request
                && !effect
                && !retained
                && !partial_release
                && !completion
                && !terminal
                && !failed
        }
        ExecdJournalStateV2::ProviderAttemptPrepared => {
            predecessor
                && prepared_request
                && !effect
                && !retained
                && !partial_release
                && !completion
                && !terminal
                && !failed
        }
        ExecdJournalStateV2::EffectStarted => {
            predecessor
                && prepared_request
                && effect
                && !retained
                && !partial_release
                && !completion
                && !terminal
                && !failed
        }
        ExecdJournalStateV2::ProviderResponseRetained => {
            predecessor
                && prepared_request
                && effect
                && retained
                && !partial_release
                && !completion
                && !terminal
                && !failed
        }
        ExecdJournalStateV2::ReleaseEvidencePrepared => {
            entry.payload.kind == DispatchEnvelopeKindV2::FinalRelease
                && predecessor
                && prepared_request
                && effect
                && retained
                && release
                && !completion
                && !terminal
                && !failed
        }
        ExecdJournalStateV2::CompletionAvailable | ExecdJournalStateV2::Acknowledged => {
            let release_shape = match entry.payload.kind {
                DispatchEnvelopeKindV2::ToolExecution => !partial_release,
                DispatchEnvelopeKindV2::FinalRelease => release,
            };
            predecessor
                && prepared_request
                && effect
                && retained
                && release_shape
                && (completion || cfg!(test))
                && terminal
                && !failed
        }
        ExecdJournalStateV2::FailedNoEffect => {
            !effect && !retained && !partial_release && !completion && terminal && failed
        }
        ExecdJournalStateV2::Indeterminate => {
            predecessor && prepared_request && !completion && terminal && !failed
        }
    };
    if valid {
        Ok(())
    } else {
        Err(ExecdErrorV2::DurableState)
    }
}

fn validate_receipt_for_entry(
    entry: &ExecdJournalEntryV2,
    receipt: Option<&SignedExecutorReceiptV2>,
    exact_kind: Option<ExecutorReceiptKindV2>,
    deployment: &VerifiedExecdDeploymentV2,
) -> Result<(), ExecdErrorV2> {
    let Some(receipt) = receipt else {
        return Ok(());
    };
    receipt.verify(
        deployment.effect_receipt_key_id,
        &deployment.effect_receipt_signing_key.verifying_key(),
    )?;
    let decoded = decode_signed_receipt(receipt.canonical_bytes())?;
    if exact_kind.is_some_and(|kind| decoded.kind != kind) {
        return Err(ExecdErrorV2::InvalidReceipt);
    }
    if decoded.installation_id != entry.payload.installation_id
        || decoded.active_state_manifest_digest != entry.payload.active_state_manifest_digest
        || decoded.deployment_generation != entry.payload.deployment_generation
        || decoded.effect_fence_epoch != entry.payload.effect_fence_epoch
        || decoded.execution_nonce != entry.payload.execution_nonce
        || decoded.dispatch_core_digest != entry.payload.dispatch_core_digest
        || decoded.dispatch_subject_digest != entry.payload.dispatch_subject_digest
        || is_zero(decoded.evidence_digest.as_bytes())
        || decoded.issued_at.get() < entry.payload.issued_at.get()
        || (decoded.kind == ExecutorReceiptKindV2::EffectStarted
            && Some(decoded.evidence_digest) != entry.provider_attempt_predecessor_digest)
    {
        return Err(ExecdErrorV2::InvalidReceipt);
    }
    Ok(())
}

fn validate_effect_receipt_for_entry(
    entry: &ExecdJournalEntryV2,
    receipt: Option<&SignedExecutorEffectStartedReceiptV2>,
    deployment: &VerifiedExecdDeploymentV2,
) -> Result<(), ExecdErrorV2> {
    let Some(receipt) = receipt else {
        return Ok(());
    };
    receipt
        .verify(
            deployment.effect_receipt_key_id,
            deployment
                .effect_receipt_signing_key
                .verifying_key()
                .to_bytes(),
        )
        .map_err(|_| ExecdErrorV2::InvalidReceipt)?;
    let unsigned = receipt.unsigned();
    if unsigned.installation_id() != entry.payload.installation_id
        || unsigned.active_state_manifest_digest() != entry.payload.active_state_manifest_digest
        || unsigned.deployment_generation() != entry.payload.deployment_generation
        || unsigned.effect_fence_epoch() != entry.payload.effect_fence_epoch
        || unsigned.execution_nonce() != entry.payload.execution_nonce
        || unsigned.dispatch_core_digest() != entry.payload.dispatch_core_digest
        || unsigned.dispatch_subject_digest() != entry.payload.dispatch_subject_digest
        || unsigned.executor_identity()
            != savana_kernel_protocol::v2::ExecutorIdentityV2::new(
                *entry.payload.executor_identity_digest.as_bytes(),
            )
        || Some(unsigned.provider_attempt_prepared_journal_record_digest())
            != entry.provider_attempt_predecessor_digest
        || unsigned.started_at().get() < entry.payload.issued_at.get()
    {
        return Err(ExecdErrorV2::InvalidReceipt);
    }
    Ok(())
}

fn service_state_digest(service: &ExecdServiceV2) -> Result<Digest32V2, ExecdErrorV2> {
    let payload = encode_snapshot_payload(0, Digest32V2::new([0; 32]), service)?;
    let mut hasher = Sha256::new();
    hasher.update(b"SAVANA_EXECD_SERVICE_STATE_V2\0");
    hasher.update(payload.as_slice());
    Ok(Digest32V2::new(hasher.finalize().into()))
}

fn encode_optional_digest(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    value: Option<Digest32V2>,
) -> Result<(), ExecdErrorV2> {
    match value {
        Some(value) => value
            .encode(encoder, &mut ())
            .map_err(|_| ExecdErrorV2::AllocationFailure),
        None => encoder
            .null()
            .map(|_| ())
            .map_err(|_| ExecdErrorV2::AllocationFailure),
    }
}

fn decode_optional_digest(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<Option<Digest32V2>, ExecdErrorV2> {
    match decoder.datatype().map_err(|_| ExecdErrorV2::DurableState)? {
        Type::Null => {
            decoder.null().map_err(|_| ExecdErrorV2::DurableState)?;
            Ok(None)
        }
        Type::Bytes => Ok(Some(Digest32V2::new(decode_fixed::<32>(decoder)?))),
        _ => Err(ExecdErrorV2::DurableState),
    }
}

fn encode_optional_failure_class(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    class: Option<ExecutorFailureClassV2>,
) -> Result<(), ExecdErrorV2> {
    match class {
        Some(class) => encoder
            .u16(class.tag())
            .map(|_| ())
            .map_err(|_| ExecdErrorV2::AllocationFailure),
        None => encoder
            .null()
            .map(|_| ())
            .map_err(|_| ExecdErrorV2::AllocationFailure),
    }
}

fn decode_optional_failure_class(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<Option<ExecutorFailureClassV2>, ExecdErrorV2> {
    match decoder.datatype().map_err(|_| ExecdErrorV2::DurableState)? {
        Type::Null => {
            decoder.null().map_err(|_| ExecdErrorV2::DurableState)?;
            Ok(None)
        }
        Type::U8 | Type::U16 => {
            let tag = decoder.u16().map_err(|_| ExecdErrorV2::DurableState)?;
            Ok(Some(match tag {
                1 => ExecutorFailureClassV2::EnvelopeRejectedBeforeEffect,
                2 => ExecutorFailureClassV2::FencedBeforeEffect,
                3 => ExecutorFailureClassV2::ConnectorUnavailableBeforeEffect,
                4 => ExecutorFailureClassV2::ConnectorRejectedBeforeEffect,
                5 => ExecutorFailureClassV2::ResourceFailureBeforeEffect,
                _ => return Err(ExecdErrorV2::DurableState),
            }))
        }
        _ => Err(ExecdErrorV2::DurableState),
    }
}

fn encode_optional_receipt(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    receipt: Option<&SignedExecutorReceiptV2>,
) -> Result<(), ExecdErrorV2> {
    match receipt {
        Some(receipt) => encoder
            .bytes(receipt.canonical_bytes())
            .map(|_| ())
            .map_err(|_| ExecdErrorV2::AllocationFailure),
        None => encoder
            .null()
            .map(|_| ())
            .map_err(|_| ExecdErrorV2::AllocationFailure),
    }
}

fn encode_optional_effect_receipt(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    receipt: Option<&SignedExecutorEffectStartedReceiptV2>,
) -> Result<(), ExecdErrorV2> {
    match receipt {
        Some(receipt) => encoder
            .bytes(
                &receipt
                    .canonical_bytes()
                    .map_err(|_| ExecdErrorV2::InvalidReceipt)?,
            )
            .map(|_| ())
            .map_err(|_| ExecdErrorV2::AllocationFailure),
        None => encoder
            .null()
            .map(|_| ())
            .map_err(|_| ExecdErrorV2::AllocationFailure),
    }
}

fn decode_optional_receipt(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<Option<SignedExecutorReceiptV2>, ExecdErrorV2> {
    match decoder.datatype().map_err(|_| ExecdErrorV2::DurableState)? {
        Type::Null => {
            decoder.null().map_err(|_| ExecdErrorV2::DurableState)?;
            Ok(None)
        }
        Type::Bytes => {
            let bytes = decoder.bytes().map_err(|_| ExecdErrorV2::DurableState)?;
            if bytes.is_empty() || bytes.len() > MAX_RECEIPT_BYTES {
                return Err(ExecdErrorV2::DurableState);
            }
            let decoded = decode_signed_receipt(bytes)?;
            Ok(Some(SignedExecutorReceiptV2 {
                canonical_bytes: bytes.to_vec(),
                kind: decoded.kind,
            }))
        }
        _ => Err(ExecdErrorV2::DurableState),
    }
}

fn decode_optional_effect_receipt(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<Option<SignedExecutorEffectStartedReceiptV2>, ExecdErrorV2> {
    match decoder.datatype().map_err(|_| ExecdErrorV2::DurableState)? {
        Type::Null => {
            decoder.null().map_err(|_| ExecdErrorV2::DurableState)?;
            Ok(None)
        }
        Type::Bytes => {
            let bytes = decoder.bytes().map_err(|_| ExecdErrorV2::DurableState)?;
            if bytes.is_empty() || bytes.len() > MAX_RECEIPT_BYTES {
                return Err(ExecdErrorV2::DurableState);
            }
            SignedExecutorEffectStartedReceiptV2::from_canonical_bytes(bytes)
                .map(Some)
                .map_err(|_| ExecdErrorV2::InvalidReceipt)
        }
        _ => Err(ExecdErrorV2::DurableState),
    }
}

fn encode_optional_bytes(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    bytes: Option<&[u8]>,
) -> Result<(), ExecdErrorV2> {
    match bytes {
        Some(bytes)
            if !bytes.is_empty()
                && bytes.len() <= crate::worker_protocol::MAX_CONNECTOR_RESPONSE_BYTES =>
        {
            encoder
                .bytes(bytes)
                .map(|_| ())
                .map_err(|_| ExecdErrorV2::AllocationFailure)
        }
        Some(_) => Err(ExecdErrorV2::DurableState),
        None => encoder
            .null()
            .map(|_| ())
            .map_err(|_| ExecdErrorV2::AllocationFailure),
    }
}

fn decode_optional_bytes(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<Option<Zeroizing<Vec<u8>>>, ExecdErrorV2> {
    match decoder.datatype().map_err(|_| ExecdErrorV2::DurableState)? {
        Type::Null => {
            decoder.null().map_err(|_| ExecdErrorV2::DurableState)?;
            Ok(None)
        }
        Type::Bytes => {
            let bytes = decoder.bytes().map_err(|_| ExecdErrorV2::DurableState)?;
            if bytes.is_empty()
                || bytes.len() > crate::worker_protocol::MAX_CONNECTOR_RESPONSE_BYTES
            {
                return Err(ExecdErrorV2::DurableState);
            }
            Ok(Some(Zeroizing::new(bytes.to_vec())))
        }
        _ => Err(ExecdErrorV2::DurableState),
    }
}

fn state_tag(state: ExecdJournalStateV2) -> u16 {
    match state {
        ExecdJournalStateV2::Prepared => 1,
        ExecdJournalStateV2::ProviderAttemptPrepared => 2,
        ExecdJournalStateV2::EffectStarted => 3,
        ExecdJournalStateV2::ProviderResponseRetained => 4,
        ExecdJournalStateV2::ReleaseEvidencePrepared => 5,
        ExecdJournalStateV2::CompletionAvailable => 6,
        ExecdJournalStateV2::FailedNoEffect => 7,
        ExecdJournalStateV2::Indeterminate => 8,
        ExecdJournalStateV2::Acknowledged => 9,
    }
}

fn decode_state(tag: u16) -> Result<ExecdJournalStateV2, ExecdErrorV2> {
    match tag {
        1 => Ok(ExecdJournalStateV2::Prepared),
        2 => Ok(ExecdJournalStateV2::ProviderAttemptPrepared),
        3 => Ok(ExecdJournalStateV2::EffectStarted),
        4 => Ok(ExecdJournalStateV2::ProviderResponseRetained),
        5 => Ok(ExecdJournalStateV2::ReleaseEvidencePrepared),
        6 => Ok(ExecdJournalStateV2::CompletionAvailable),
        7 => Ok(ExecdJournalStateV2::FailedNoEffect),
        8 => Ok(ExecdJournalStateV2::Indeterminate),
        9 => Ok(ExecdJournalStateV2::Acknowledged),
        _ => Err(ExecdErrorV2::DurableState),
    }
}

fn derive_encryption_key(
    master: &[u8; 32],
    namespace: DurableExecdNamespaceV2,
) -> Result<Zeroizing<[u8; 32]>, ExecdErrorV2> {
    let mut mac = <Hmac<Sha256> as hmac::Mac>::new_from_slice(master)
        .map_err(|_| ExecdErrorV2::DurableState)?;
    mac.update(KEY_DERIVATION_DOMAIN);
    mac.update(namespace.installation_id.as_bytes());
    mac.update(namespace.store_id.as_bytes());
    Ok(Zeroizing::new(mac.finalize().into_bytes().into()))
}

fn encryption_aad(
    namespace: DurableExecdNamespaceV2,
    sequence: u64,
    previous_state_digest: Digest32V2,
    nonce: &[u8; NONCE_BYTES],
) -> Vec<u8> {
    let mut aad = Vec::from(ENCRYPTION_DOMAIN);
    aad.extend_from_slice(namespace.installation_id.as_bytes());
    aad.extend_from_slice(namespace.store_id.as_bytes());
    aad.extend_from_slice(&sequence.to_be_bytes());
    aad.extend_from_slice(previous_state_digest.as_bytes());
    aad.extend_from_slice(nonce);
    aad
}

fn state_head_digest(namespace: DurableExecdNamespaceV2, bytes: &[u8]) -> Digest32V2 {
    let mut hasher = Sha256::new();
    hasher.update(HEAD_DOMAIN);
    hasher.update(namespace.installation_id.as_bytes());
    hasher.update(namespace.store_id.as_bytes());
    hasher.update(bytes);
    Digest32V2::new(hasher.finalize().into())
}

struct AnchoredPathV2 {
    parent: File,
    parent_path: PathBuf,
    parent_dev: u64,
    parent_ino: u64,
    leaf: OsString,
    owner_uid: u32,
    owner_gid: u32,
}

impl AnchoredPathV2 {
    fn open(path: &Path) -> Result<Self, ExecdErrorV2> {
        if !path.is_absolute() {
            return Err(ExecdErrorV2::DurableState);
        }
        let parent_path = path.parent().ok_or(ExecdErrorV2::DurableState)?;
        let leaf = path
            .file_name()
            .ok_or(ExecdErrorV2::DurableState)?
            .to_os_string();
        let before = fs::symlink_metadata(parent_path).map_err(|_| ExecdErrorV2::DurableState)?;
        if before.file_type().is_symlink() {
            return Err(ExecdErrorV2::DurableState);
        }
        let descriptor = rustix_open(
            parent_path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| ExecdErrorV2::DurableState)?;
        let parent = File::from(descriptor);
        let opened = parent.metadata().map_err(|_| ExecdErrorV2::DurableState)?;
        if !opened.is_dir()
            || opened.dev() != before.dev()
            || opened.ino() != before.ino()
            || opened.uid() != before.uid()
            || opened.gid() != before.gid()
            || opened.mode() & 0o7777 != 0o700
        {
            return Err(ExecdErrorV2::DurableState);
        }
        let anchored = Self {
            parent,
            parent_path: parent_path.to_owned(),
            parent_dev: opened.dev(),
            parent_ino: opened.ino(),
            leaf,
            owner_uid: opened.uid(),
            owner_gid: opened.gid(),
        };
        anchored.recheck_parent()?;
        Ok(anchored)
    }

    fn recheck_parent(&self) -> Result<(), ExecdErrorV2> {
        let opened = self
            .parent
            .metadata()
            .map_err(|_| ExecdErrorV2::DurableState)?;
        let linked =
            fs::symlink_metadata(&self.parent_path).map_err(|_| ExecdErrorV2::DurableState)?;
        if linked.file_type().is_symlink()
            || !linked.is_dir()
            || opened.dev() != self.parent_dev
            || opened.ino() != self.parent_ino
            || linked.dev() != self.parent_dev
            || linked.ino() != self.parent_ino
            || linked.uid() != self.owner_uid
            || linked.gid() != self.owner_gid
            || linked.mode() & 0o7777 != 0o700
        {
            return Err(ExecdErrorV2::DurableState);
        }
        Ok(())
    }

    fn read_existing(&self) -> Result<Option<Vec<u8>>, ExecdErrorV2> {
        let before = match statat(&self.parent, &self.leaf, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => stat,
            Err(Errno::NOENT) => return Ok(None),
            Err(_) => return Err(ExecdErrorV2::DurableState),
        };
        if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile {
            return Err(ExecdErrorV2::DurableState);
        }
        let descriptor = openat(
            &self.parent,
            &self.leaf,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| ExecdErrorV2::DurableState)?;
        let mut file = File::from(descriptor);
        let opened = file.metadata().map_err(|_| ExecdErrorV2::DurableState)?;
        if !opened.is_file()
            || i128::from(before.st_dev) != i128::from(opened.dev())
            || before.st_ino != opened.ino()
            || before.st_uid != self.owner_uid
            || before.st_gid != self.owner_gid
            || opened.uid() != self.owner_uid
            || opened.gid() != self.owner_gid
            || opened.mode() & 0o7777 != 0o600
            || opened.nlink() != 1
            || opened.len() > MAX_JOURNAL_BYTES
        {
            return Err(ExecdErrorV2::DurableState);
        }
        let capacity = usize::try_from(opened.len()).map_err(|_| ExecdErrorV2::DurableState)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(capacity)
            .map_err(|_| ExecdErrorV2::AllocationFailure)?;
        file.read_to_end(&mut bytes)
            .map_err(|_| ExecdErrorV2::DurableState)?;
        let after = statat(&self.parent, &self.leaf, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| ExecdErrorV2::DurableState)?;
        if bytes.len() != capacity
            || i128::from(after.st_dev) != i128::from(opened.dev())
            || after.st_ino != opened.ino()
            || u64::try_from(after.st_size).ok() != Some(opened.len())
        {
            return Err(ExecdErrorV2::DurableState);
        }
        self.recheck_parent()?;
        Ok(Some(bytes))
    }

    fn replace(&self, bytes: &[u8]) -> Result<(), bool> {
        let (temporary_leaf, mut temporary) =
            create_temporary(&self.parent, &self.leaf, self.owner_uid, self.owner_gid)
                .map_err(|_| false)?;
        let before_rename = (|| {
            temporary
                .write_all(bytes)
                .map_err(|_| ExecdErrorV2::DurableState)?;
            temporary
                .sync_all()
                .map_err(|_| ExecdErrorV2::DurableState)?;
            validate_file_at(
                &self.parent,
                &temporary_leaf,
                &temporary,
                self.owner_uid,
                self.owner_gid,
                u64::try_from(bytes.len()).map_err(|_| ExecdErrorV2::DurableState)?,
            )?;
            self.recheck_parent()
        })();
        if before_rename.is_err() {
            let _ = unlinkat(&self.parent, &temporary_leaf, AtFlags::empty());
            return Err(false);
        }
        if renameat(&self.parent, &temporary_leaf, &self.parent, &self.leaf).is_err() {
            let _ = unlinkat(&self.parent, &temporary_leaf, AtFlags::empty());
            return Err(false);
        }
        validate_file_at(
            &self.parent,
            &self.leaf,
            &temporary,
            self.owner_uid,
            self.owner_gid,
            u64::try_from(bytes.len()).map_err(|_| true)?,
        )
        .map_err(|_| true)?;
        self.parent.sync_all().map_err(|_| true)?;
        self.recheck_parent().map_err(|_| true)
    }
}

fn create_temporary(
    parent: &File,
    final_leaf: &OsStr,
    owner_uid: u32,
    owner_gid: u32,
) -> Result<(OsString, File), ExecdErrorV2> {
    for _ in 0..TEMP_ATTEMPTS {
        let mut random = [0_u8; 16];
        getrandom::getrandom(&mut random).map_err(|_| ExecdErrorV2::DurableState)?;
        let mut temporary_leaf = OsString::from(".");
        temporary_leaf.push(final_leaf);
        temporary_leaf.push(".tmp-");
        temporary_leaf.push(hex(&random));
        match openat(
            parent,
            &temporary_leaf,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_bits_truncate(0o600),
        ) {
            Ok(descriptor) => {
                let file = File::from(descriptor);
                fchmod(&file, Mode::from_bits_truncate(0o600))
                    .map_err(|_| ExecdErrorV2::DurableState)?;
                validate_file_at(parent, &temporary_leaf, &file, owner_uid, owner_gid, 0)?;
                return Ok((temporary_leaf, file));
            }
            Err(Errno::EXIST) => {}
            Err(_) => return Err(ExecdErrorV2::DurableState),
        }
    }
    Err(ExecdErrorV2::DurableState)
}

fn validate_file_at(
    parent: &File,
    leaf: &OsStr,
    file: &File,
    owner_uid: u32,
    owner_gid: u32,
    expected_length: u64,
) -> Result<(), ExecdErrorV2> {
    let opened = file.metadata().map_err(|_| ExecdErrorV2::DurableState)?;
    let linked =
        statat(parent, leaf, AtFlags::SYMLINK_NOFOLLOW).map_err(|_| ExecdErrorV2::DurableState)?;
    if !opened.is_file()
        || opened.uid() != owner_uid
        || opened.gid() != owner_gid
        || opened.mode() & 0o7777 != 0o600
        || opened.nlink() != 1
        || opened.len() != expected_length
        || FileType::from_raw_mode(linked.st_mode) != FileType::RegularFile
        || i128::from(linked.st_dev) != i128::from(opened.dev())
        || linked.st_ino != opened.ino()
        || linked.st_uid != owner_uid
        || linked.st_gid != owner_gid
        || linked.st_mode & 0o7777 != 0o600
        || linked.st_nlink != 1
        || u64::try_from(linked.st_size).ok() != Some(expected_length)
    {
        return Err(ExecdErrorV2::DurableState);
    }
    Ok(())
}

struct JournalLockV2 {
    file: Flock<File>,
    parent: File,
    leaf: OsString,
    owner_uid: u32,
    owner_gid: u32,
}

impl JournalLockV2 {
    fn acquire(
        parent: &File,
        leaf: &OsStr,
        owner_uid: u32,
        owner_gid: u32,
    ) -> Result<Self, ExecdErrorV2> {
        let flags =
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
        let descriptor = openat(parent, leaf, flags, Mode::from_bits_truncate(0o600))
            .map_err(|_| ExecdErrorV2::DurableState)?;
        let file = File::from(descriptor);
        fchmod(&file, Mode::from_bits_truncate(0o600)).map_err(|_| ExecdErrorV2::DurableState)?;
        validate_file_at(parent, leaf, &file, owner_uid, owner_gid, 0)?;
        let file = Flock::lock(file, FlockArg::LockExclusiveNonblock)
            .map_err(|_| ExecdErrorV2::DurableState)?;
        validate_file_at(parent, leaf, &file, owner_uid, owner_gid, 0)?;
        parent.sync_all().map_err(|_| ExecdErrorV2::DurableState)?;
        Ok(Self {
            file,
            parent: parent.try_clone().map_err(|_| ExecdErrorV2::DurableState)?,
            leaf: leaf.to_os_string(),
            owner_uid,
            owner_gid,
        })
    }

    fn recheck(&self) -> Result<(), ExecdErrorV2> {
        validate_file_at(
            &self.parent,
            &self.leaf,
            &self.file,
            self.owner_uid,
            self.owner_gid,
            0,
        )
    }
}

fn require_array(decoder: &mut minicbor::Decoder<'_>, expected: u64) -> Result<(), ExecdErrorV2> {
    if decoder.array().map_err(|_| ExecdErrorV2::DurableState)? != Some(expected) {
        return Err(ExecdErrorV2::DurableState);
    }
    Ok(())
}

fn decode_fixed<const N: usize>(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<[u8; N], ExecdErrorV2> {
    decoder
        .bytes()
        .map_err(|_| ExecdErrorV2::DurableState)?
        .try_into()
        .map_err(|_| ExecdErrorV2::DurableState)
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}
