use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use savana_policy_core::v2::BoundedConnectorUrlV2;
use zeroize::Zeroizing;

use crate::request::{
    domain_hash, encode_canonical, payload_hash, wire_hash, CanonicalRequestFields,
};
use crate::{VerifiedReleaseRequest, MAX_RELEASE_PAYLOAD_BYTES};

const JOURNAL_VERSION: u16 = 1;
const MAX_JOURNAL_BYTES: usize = MAX_RELEASE_PAYLOAD_BYTES + 8 * 1024;
const MAX_RECENT_WIRE_DIGESTS: usize = 64;
const PREPARED_REQUEST_DOMAIN: &[u8] = b"SAVANA_PREPARED_PROVIDER_REQUEST_V2\0";

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReservationId([u8; 32]);

impl fmt::Debug for ReservationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReservationId([redacted])")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ReservationError {
    #[error("another final release is already in flight")]
    Busy,
    #[error("the final-release receiver is sealed pending reconciliation")]
    Sealed,
    #[error("the final-release reservation expired")]
    Expired,
    #[error("the operation does not match the active turn")]
    CrossTurn,
    #[error("the final-release request is a duplicate")]
    DuplicateDelivery,
    #[error("there is no active final-release reservation")]
    NoReservation,
    #[error("the final-release reservation has already been claimed")]
    AlreadyClaimed,
    #[error("the final-release payload is not available")]
    NotClaimed,
    #[error("the final-release journal is unavailable")]
    DurableState,
    #[error("secure reservation entropy is unavailable")]
    EntropyUnavailable,
}

pub struct ReleasedPayload {
    turn_binding: [u8; 32],
    payload: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for ReleasedPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReleasedPayload")
            .field("turn_binding", &"[redacted digest]")
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

impl ReleasedPayload {
    pub const fn turn_binding(&self) -> &[u8; 32] {
        &self.turn_binding
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

pub struct ReleaseReservationStore {
    path: PathBuf,
    journal: Mutex<Journal>,
}

impl fmt::Debug for ReleaseReservationStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReleaseReservationStore")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl ReleaseReservationStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ReservationError> {
        let path = path.as_ref().to_owned();
        let journal = match read_journal(&path) {
            Ok(journal) => journal,
            Err(ReadJournalError::NotFound) => {
                let journal = Journal::empty();
                persist_journal(&path, &journal)?;
                journal
            }
            Err(ReadJournalError::Invalid) => return Err(ReservationError::DurableState),
        };
        Ok(Self {
            path,
            journal: Mutex::new(journal),
        })
    }

    pub fn reserve(
        &self,
        turn_binding: [u8; 32],
        now_unix_ms: u64,
        expires_at_unix_ms: u64,
    ) -> Result<ReservationId, ReservationError> {
        if is_zero(&turn_binding) || expires_at_unix_ms <= now_unix_ms {
            return Err(ReservationError::Expired);
        }
        let reservation_id = ReservationId(random_nonzero_32()?);
        self.transition(|journal| match journal.state {
            ReservationState::Empty => {
                journal.state = ReservationState::Reserved(Reserved {
                    reservation_id,
                    turn_binding,
                    expires_at_unix_ms,
                });
                Ok(reservation_id)
            }
            ReservationState::Sealed(_) => Err(ReservationError::Sealed),
            ReservationState::Reserved(_) | ReservationState::Claimed(_) => {
                Err(ReservationError::Busy)
            }
        })
    }

    /// Claims the one globally reserved release. The request itself carries no
    /// caller-selected turn identifier; ordering is therefore enforced by the
    /// single-flight journal and the opaque id required to read the result.
    pub fn claim_next(
        &self,
        now_unix_ms: u64,
        request: VerifiedReleaseRequest,
    ) -> Result<(), ReservationError> {
        let wire_digest = *request.wire_digest();
        self.transition(|journal| match journal.state.clone() {
            ReservationState::Empty => {
                journal.state = ReservationState::Sealed(SealReason::UnexpectedDelivery);
                Err(ReservationError::NoReservation)
            }
            ReservationState::Sealed(_) => Err(ReservationError::Sealed),
            ReservationState::Claimed(ref claimed) => {
                if claimed.wire_digest == wire_digest {
                    Err(ReservationError::DuplicateDelivery)
                } else {
                    journal.state = ReservationState::Sealed(SealReason::UnexpectedDelivery);
                    Err(ReservationError::AlreadyClaimed)
                }
            }
            ReservationState::Reserved(reserved) => {
                if now_unix_ms >= reserved.expires_at_unix_ms {
                    journal.state = ReservationState::Sealed(SealReason::Expired);
                    return Err(ReservationError::Expired);
                }
                if journal.recent_wire_digests.contains(&wire_digest) {
                    journal.state = ReservationState::Sealed(SealReason::DuplicateDelivery);
                    return Err(ReservationError::DuplicateDelivery);
                }
                journal.state = ReservationState::Claimed(Box::new(Claimed {
                    reservation_id: reserved.reservation_id,
                    turn_binding: reserved.turn_binding,
                    expires_at_unix_ms: reserved.expires_at_unix_ms,
                    canonical_url: request.canonical_url().to_owned(),
                    tls_identity_pin: *request.tls_identity_pin(),
                    execution_nonce: *request.execution_nonce(),
                    dispatch_core_digest: *request.dispatch_core_digest(),
                    dispatch_subject_digest: *request.dispatch_subject_digest(),
                    credential_free_request_digest: *request.credential_free_request_digest(),
                    payload_digest: *request.payload_digest(),
                    wire_digest,
                    payload: Zeroizing::new(request.payload().to_vec()),
                }));
                Ok(())
            }
        })
    }

    pub fn read_delivery(
        &self,
        reservation_id: &ReservationId,
    ) -> Result<ReleasedPayload, ReservationError> {
        let journal = self
            .journal
            .lock()
            .map_err(|_| ReservationError::DurableState)?;
        match &journal.state {
            ReservationState::Claimed(claimed) if claimed.reservation_id == *reservation_id => {
                Ok(ReleasedPayload {
                    turn_binding: claimed.turn_binding,
                    payload: Zeroizing::new(claimed.payload.to_vec()),
                })
            }
            ReservationState::Claimed(_) | ReservationState::Reserved(_) => {
                Err(ReservationError::CrossTurn)
            }
            ReservationState::Empty => Err(ReservationError::NotClaimed),
            ReservationState::Sealed(_) => Err(ReservationError::Sealed),
        }
    }

    pub fn complete_delivery(
        &self,
        reservation_id: &ReservationId,
    ) -> Result<(), ReservationError> {
        self.transition(|journal| match journal.state.clone() {
            ReservationState::Claimed(claimed) if claimed.reservation_id == *reservation_id => {
                journal.recent_wire_digests.push(claimed.wire_digest);
                if journal.recent_wire_digests.len() > MAX_RECENT_WIRE_DIGESTS {
                    journal.recent_wire_digests.remove(0);
                }
                journal.state = ReservationState::Empty;
                Ok(())
            }
            ReservationState::Claimed(_) | ReservationState::Reserved(_) => {
                Err(ReservationError::CrossTurn)
            }
            ReservationState::Empty => Err(ReservationError::NotClaimed),
            ReservationState::Sealed(_) => Err(ReservationError::Sealed),
        })
    }

    pub fn clear_failed_no_effect(
        &self,
        reservation_id: &ReservationId,
    ) -> Result<(), ReservationError> {
        self.transition(|journal| match journal.state.clone() {
            ReservationState::Reserved(reserved) if reserved.reservation_id == *reservation_id => {
                journal.state = ReservationState::Empty;
                Ok(())
            }
            ReservationState::Claimed(claimed) if claimed.reservation_id == *reservation_id => {
                journal.state = ReservationState::Sealed(SealReason::ClaimedFailure);
                Err(ReservationError::AlreadyClaimed)
            }
            ReservationState::Reserved(_) | ReservationState::Claimed(_) => {
                Err(ReservationError::CrossTurn)
            }
            ReservationState::Empty => Err(ReservationError::NoReservation),
            ReservationState::Sealed(_) => Err(ReservationError::Sealed),
        })
    }

    pub fn seal_indeterminate(
        &self,
        reservation_id: &ReservationId,
    ) -> Result<(), ReservationError> {
        self.transition(|journal| match journal.state.clone() {
            ReservationState::Reserved(reserved) if reserved.reservation_id == *reservation_id => {
                journal.state = ReservationState::Sealed(SealReason::Indeterminate);
                Ok(())
            }
            ReservationState::Claimed(claimed) if claimed.reservation_id == *reservation_id => {
                journal.state = ReservationState::Sealed(SealReason::Indeterminate);
                Ok(())
            }
            ReservationState::Reserved(_) | ReservationState::Claimed(_) => {
                Err(ReservationError::CrossTurn)
            }
            ReservationState::Empty => Err(ReservationError::NoReservation),
            ReservationState::Sealed(_) => Err(ReservationError::Sealed),
        })
    }

    pub fn reconcile_after_operator_review(&self) -> Result<(), ReservationError> {
        self.transition(|journal| {
            if !matches!(journal.state, ReservationState::Sealed(_)) {
                return Err(ReservationError::Busy);
            }
            journal.state = ReservationState::Empty;
            Ok(())
        })
    }

    pub fn is_sealed(&self) -> Result<bool, ReservationError> {
        self.journal
            .lock()
            .map(|journal| matches!(journal.state, ReservationState::Sealed(_)))
            .map_err(|_| ReservationError::DurableState)
    }

    fn transition<T>(
        &self,
        operation: impl FnOnce(&mut Journal) -> Result<T, ReservationError>,
    ) -> Result<T, ReservationError> {
        let mut current = self
            .journal
            .lock()
            .map_err(|_| ReservationError::DurableState)?;
        let mut next = current.clone();
        let result = operation(&mut next);
        if next != *current {
            next.sequence = next
                .sequence
                .checked_add(1)
                .ok_or(ReservationError::DurableState)?;
            if persist_journal(&self.path, &next).is_err() {
                current.state = ReservationState::Sealed(SealReason::DurableFailure);
                return Err(ReservationError::DurableState);
            }
            *current = next;
        }
        result
    }
}

#[derive(Clone, PartialEq, Eq)]
struct Journal {
    sequence: u64,
    state: ReservationState,
    recent_wire_digests: Vec<[u8; 32]>,
}

impl Journal {
    fn empty() -> Self {
        Self {
            sequence: 0,
            state: ReservationState::Empty,
            recent_wire_digests: Vec::new(),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
enum ReservationState {
    Empty,
    Reserved(Reserved),
    Claimed(Box<Claimed>),
    Sealed(SealReason),
}

#[derive(Clone, PartialEq, Eq)]
struct Reserved {
    reservation_id: ReservationId,
    turn_binding: [u8; 32],
    expires_at_unix_ms: u64,
}

#[derive(Clone, PartialEq, Eq)]
struct Claimed {
    reservation_id: ReservationId,
    turn_binding: [u8; 32],
    expires_at_unix_ms: u64,
    canonical_url: String,
    tls_identity_pin: [u8; 32],
    execution_nonce: [u8; 32],
    dispatch_core_digest: [u8; 32],
    dispatch_subject_digest: [u8; 32],
    credential_free_request_digest: [u8; 32],
    payload_digest: [u8; 32],
    wire_digest: [u8; 32],
    payload: Zeroizing<Vec<u8>>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SealReason {
    Expired = 1,
    Indeterminate = 2,
    UnexpectedDelivery = 3,
    DuplicateDelivery = 4,
    ClaimedFailure = 5,
    DurableFailure = 6,
}

fn random_nonzero_32() -> Result<[u8; 32], ReservationError> {
    for _ in 0..4 {
        let mut bytes = [0_u8; 32];
        getrandom::getrandom(&mut bytes).map_err(|_| ReservationError::EntropyUnavailable)?;
        if !is_zero(&bytes) {
            return Ok(bytes);
        }
    }
    Err(ReservationError::EntropyUnavailable)
}

fn persist_journal(path: &Path, journal: &Journal) -> Result<(), ReservationError> {
    let parent = path.parent().ok_or(ReservationError::DurableState)?;
    if !parent.is_dir() {
        return Err(ReservationError::DurableState);
    }
    let encoded = encode_journal(journal)?;
    let mut random = [0_u8; 16];
    getrandom::getrandom(&mut random).map_err(|_| ReservationError::EntropyUnavailable)?;
    let temporary = parent.join(format!(".savana-release-{}.tmp", hex(&random)));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(&temporary)
        .map_err(|_| ReservationError::DurableState)?;
    let result = file
        .write_all(&encoded)
        .and_then(|()| file.sync_all())
        .and_then(|()| fs::rename(&temporary, path))
        .and_then(|()| File::open(parent)?.sync_all());
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
        return Err(ReservationError::DurableState);
    }
    Ok(())
}

enum ReadJournalError {
    NotFound,
    Invalid,
}

fn read_journal(path: &Path) -> Result<Journal, ReadJournalError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            return Err(ReadJournalError::Invalid)
        }
        Ok(_) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => {
            return Err(ReadJournalError::NotFound)
        }
        Err(_) => return Err(ReadJournalError::Invalid),
    }
    let mut bytes = Vec::new();
    File::open(path)
        .and_then(|file| {
            file.take((MAX_JOURNAL_BYTES + 1) as u64)
                .read_to_end(&mut bytes)
        })
        .map_err(|_| ReadJournalError::Invalid)?;
    if bytes.is_empty() || bytes.len() > MAX_JOURNAL_BYTES {
        return Err(ReadJournalError::Invalid);
    }
    decode_journal(&bytes).map_err(|_| ReadJournalError::Invalid)
}

fn encode_journal(journal: &Journal) -> Result<Vec<u8>, ReservationError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(4)
        .and_then(|encoder| encoder.u16(JOURNAL_VERSION))
        .and_then(|encoder| encoder.u64(journal.sequence))
        .map_err(|_| ReservationError::DurableState)?;
    encode_state(&mut encoder, &journal.state)?;
    encoder
        .array(journal.recent_wire_digests.len() as u64)
        .map_err(|_| ReservationError::DurableState)?;
    for digest in &journal.recent_wire_digests {
        encoder
            .bytes(digest)
            .map_err(|_| ReservationError::DurableState)?;
    }
    let encoded = encoder.into_writer();
    if encoded.len() > MAX_JOURNAL_BYTES {
        return Err(ReservationError::DurableState);
    }
    Ok(encoded)
}

fn encode_state(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    state: &ReservationState,
) -> Result<(), ReservationError> {
    match state {
        ReservationState::Empty => {
            encoder
                .array(1)
                .and_then(|encoder| encoder.u8(0))
                .map_err(|_| ReservationError::DurableState)?;
        }
        ReservationState::Reserved(reserved) => {
            encoder
                .array(4)
                .and_then(|encoder| encoder.u8(1))
                .and_then(|encoder| encoder.bytes(&reserved.reservation_id.0))
                .and_then(|encoder| encoder.bytes(&reserved.turn_binding))
                .and_then(|encoder| encoder.u64(reserved.expires_at_unix_ms))
                .map_err(|_| ReservationError::DurableState)?;
        }
        ReservationState::Claimed(claimed) => {
            encoder
                .array(13)
                .and_then(|encoder| encoder.u8(2))
                .and_then(|encoder| encoder.bytes(&claimed.reservation_id.0))
                .and_then(|encoder| encoder.bytes(&claimed.turn_binding))
                .and_then(|encoder| encoder.u64(claimed.expires_at_unix_ms))
                .and_then(|encoder| encoder.str(&claimed.canonical_url))
                .and_then(|encoder| encoder.bytes(&claimed.tls_identity_pin))
                .and_then(|encoder| encoder.bytes(&claimed.execution_nonce))
                .and_then(|encoder| encoder.bytes(&claimed.dispatch_core_digest))
                .and_then(|encoder| encoder.bytes(&claimed.dispatch_subject_digest))
                .and_then(|encoder| encoder.bytes(&claimed.credential_free_request_digest))
                .and_then(|encoder| encoder.bytes(&claimed.payload_digest))
                .and_then(|encoder| encoder.bytes(&claimed.wire_digest))
                .and_then(|encoder| encoder.bytes(&claimed.payload))
                .map_err(|_| ReservationError::DurableState)?;
        }
        ReservationState::Sealed(reason) => {
            encoder
                .array(2)
                .and_then(|encoder| encoder.u8(3))
                .and_then(|encoder| encoder.u8(*reason as u8))
                .map_err(|_| ReservationError::DurableState)?;
        }
    }
    Ok(())
}

fn decode_journal(bytes: &[u8]) -> Result<Journal, ReservationError> {
    let mut decoder = minicbor::Decoder::new(bytes);
    if decoder.array().ok() != Some(Some(4)) || decoder.u16().ok() != Some(JOURNAL_VERSION) {
        return Err(ReservationError::DurableState);
    }
    let sequence = decoder.u64().map_err(|_| ReservationError::DurableState)?;
    let state = decode_state(&mut decoder)?;
    let recent_len = decoder
        .array()
        .map_err(|_| ReservationError::DurableState)?
        .ok_or(ReservationError::DurableState)? as usize;
    if recent_len > MAX_RECENT_WIRE_DIGESTS {
        return Err(ReservationError::DurableState);
    }
    let mut recent_wire_digests = Vec::with_capacity(recent_len);
    for _ in 0..recent_len {
        let digest = decode_32(&mut decoder)?;
        if is_zero(&digest) || recent_wire_digests.contains(&digest) {
            return Err(ReservationError::DurableState);
        }
        recent_wire_digests.push(digest);
    }
    if decoder.position() != bytes.len() {
        return Err(ReservationError::DurableState);
    }
    let journal = Journal {
        sequence,
        state,
        recent_wire_digests,
    };
    if encode_journal(&journal)?.as_slice() != bytes {
        return Err(ReservationError::DurableState);
    }
    Ok(journal)
}

fn decode_state(decoder: &mut minicbor::Decoder<'_>) -> Result<ReservationState, ReservationError> {
    let length = decoder
        .array()
        .map_err(|_| ReservationError::DurableState)?
        .ok_or(ReservationError::DurableState)?;
    let tag = decoder.u8().map_err(|_| ReservationError::DurableState)?;
    match (tag, length) {
        (0, 1) => Ok(ReservationState::Empty),
        (1, 4) => {
            let reservation_id = ReservationId(decode_nonzero_32(decoder)?);
            let turn_binding = decode_nonzero_32(decoder)?;
            let expires_at_unix_ms = decoder.u64().map_err(|_| ReservationError::DurableState)?;
            Ok(ReservationState::Reserved(Reserved {
                reservation_id,
                turn_binding,
                expires_at_unix_ms,
            }))
        }
        (2, 13) => {
            let reservation_id = ReservationId(decode_nonzero_32(decoder)?);
            let turn_binding = decode_nonzero_32(decoder)?;
            let expires_at_unix_ms = decoder.u64().map_err(|_| ReservationError::DurableState)?;
            let encoded_url = decoder.str().map_err(|_| ReservationError::DurableState)?;
            let canonical_url = BoundedConnectorUrlV2::new(encoded_url)
                .map_err(|_| ReservationError::DurableState)?;
            if canonical_url.as_str() != encoded_url {
                return Err(ReservationError::DurableState);
            }
            let tls_identity_pin = decode_nonzero_32(decoder)?;
            let execution_nonce = decode_nonzero_32(decoder)?;
            let dispatch_core_digest = decode_nonzero_32(decoder)?;
            let dispatch_subject_digest = decode_nonzero_32(decoder)?;
            let credential_free_request_digest = decode_32(decoder)?;
            let payload_digest = decode_32(decoder)?;
            let wire_digest = decode_nonzero_32(decoder)?;
            let payload = decoder
                .bytes()
                .map_err(|_| ReservationError::DurableState)?;
            if payload.is_empty() || payload.len() > MAX_RELEASE_PAYLOAD_BYTES {
                return Err(ReservationError::DurableState);
            }
            if credential_free_request_digest != domain_hash(PREPARED_REQUEST_DOMAIN, payload)
                || payload_digest != payload_hash(payload)
            {
                return Err(ReservationError::DurableState);
            }
            let canonical_request = encode_canonical(CanonicalRequestFields {
                canonical_url: canonical_url.as_str(),
                tls_identity_pin: &tls_identity_pin,
                execution_nonce: &execution_nonce,
                dispatch_core_digest: &dispatch_core_digest,
                dispatch_subject_digest: &dispatch_subject_digest,
                payload_length: payload.len() as u32,
                credential_free_request_digest: &credential_free_request_digest,
                payload_digest: &payload_digest,
                payload,
            })
            .map_err(|_| ReservationError::DurableState)?;
            if wire_digest != wire_hash(&canonical_request) {
                return Err(ReservationError::DurableState);
            }
            Ok(ReservationState::Claimed(Box::new(Claimed {
                reservation_id,
                turn_binding,
                expires_at_unix_ms,
                canonical_url: canonical_url.as_str().to_owned(),
                tls_identity_pin,
                execution_nonce,
                dispatch_core_digest,
                dispatch_subject_digest,
                credential_free_request_digest,
                payload_digest,
                wire_digest,
                payload: Zeroizing::new(payload.to_vec()),
            })))
        }
        (3, 2) => {
            let reason = match decoder.u8().map_err(|_| ReservationError::DurableState)? {
                1 => SealReason::Expired,
                2 => SealReason::Indeterminate,
                3 => SealReason::UnexpectedDelivery,
                4 => SealReason::DuplicateDelivery,
                5 => SealReason::ClaimedFailure,
                6 => SealReason::DurableFailure,
                _ => return Err(ReservationError::DurableState),
            };
            Ok(ReservationState::Sealed(reason))
        }
        _ => Err(ReservationError::DurableState),
    }
}

fn decode_nonzero_32(decoder: &mut minicbor::Decoder<'_>) -> Result<[u8; 32], ReservationError> {
    let bytes = decode_32(decoder)?;
    if is_zero(&bytes) {
        return Err(ReservationError::DurableState);
    }
    Ok(bytes)
}

fn decode_32(decoder: &mut minicbor::Decoder<'_>) -> Result<[u8; 32], ReservationError> {
    decoder
        .bytes()
        .map_err(|_| ReservationError::DurableState)?
        .try_into()
        .map_err(|_| ReservationError::DurableState)
}

fn is_zero(bytes: &[u8; 32]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}
