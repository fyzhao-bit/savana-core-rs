use std::fmt;

use savana_policy_core::v2::BoundedConnectorUrlV2;
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

pub const MAX_RELEASE_PAYLOAD_BYTES: usize = 1024 * 1024;
pub const MAX_RELEASE_REQUEST_BYTES: usize = MAX_RELEASE_PAYLOAD_BYTES + 4_096 + 256;

const REQUEST_VERSION: u16 = 2;
const REQUEST_KIND: u16 = 1;
const PREPARED_REQUEST_DOMAIN: &[u8] = b"SAVANA_PREPARED_PROVIDER_REQUEST_V2\0";
const PAYLOAD_DOMAIN: &[u8] = b"SAVANA_PROVIDER_REQUEST_PAYLOAD_V2\0";
const WIRE_DOMAIN: &[u8] = b"SAVANA_BOUND_PROVIDER_REQUEST_WIRE_V2\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ReleaseRequestError {
    #[error("release request is malformed or noncanonical")]
    NonCanonical,
    #[error("release request exceeded its compiled bound")]
    TooLarge,
}

/// A canonical request emitted by execd's verified provider transport.
///
/// The payload is zeroized on drop and intentionally omitted from `Debug`.
pub struct VerifiedReleaseRequest {
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

impl fmt::Debug for VerifiedReleaseRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedReleaseRequest")
            .field("canonical_url", &self.canonical_url)
            .field("tls_identity_pin", &"[redacted digest]")
            .field("execution_nonce", &"[redacted nonce]")
            .field("dispatch_core_digest", &"[redacted digest]")
            .field("dispatch_subject_digest", &"[redacted digest]")
            .field("payload_len", &self.payload.len())
            .finish_non_exhaustive()
    }
}

impl VerifiedReleaseRequest {
    pub fn decode(bytes: &[u8]) -> Result<Self, ReleaseRequestError> {
        if bytes.len() > MAX_RELEASE_REQUEST_BYTES {
            return Err(ReleaseRequestError::TooLarge);
        }
        if bytes.is_empty() {
            return Err(ReleaseRequestError::NonCanonical);
        }

        let mut decoder = minicbor::Decoder::new(bytes);
        if decoder
            .array()
            .map_err(|_| ReleaseRequestError::NonCanonical)?
            != Some(11)
            || decoder
                .u16()
                .map_err(|_| ReleaseRequestError::NonCanonical)?
                != REQUEST_VERSION
            || decoder
                .u16()
                .map_err(|_| ReleaseRequestError::NonCanonical)?
                != REQUEST_KIND
        {
            return Err(ReleaseRequestError::NonCanonical);
        }

        let encoded_url = decoder
            .str()
            .map_err(|_| ReleaseRequestError::NonCanonical)?;
        let canonical_url = BoundedConnectorUrlV2::new(encoded_url)
            .map_err(|_| ReleaseRequestError::NonCanonical)?;
        if canonical_url.as_str() != encoded_url {
            return Err(ReleaseRequestError::NonCanonical);
        }

        let tls_identity_pin = decode_digest(&mut decoder)?;
        let execution_nonce = decode_digest(&mut decoder)?;
        let dispatch_core_digest = decode_digest(&mut decoder)?;
        let dispatch_subject_digest = decode_digest(&mut decoder)?;
        if is_zero(&tls_identity_pin)
            || is_zero(&execution_nonce)
            || is_zero(&dispatch_core_digest)
            || is_zero(&dispatch_subject_digest)
        {
            return Err(ReleaseRequestError::NonCanonical);
        }

        let payload_length = decoder
            .u32()
            .map_err(|_| ReleaseRequestError::NonCanonical)? as usize;
        if payload_length == 0 || payload_length > MAX_RELEASE_PAYLOAD_BYTES {
            return Err(ReleaseRequestError::TooLarge);
        }
        let credential_free_request_digest = decode_digest(&mut decoder)?;
        let payload_digest = decode_digest(&mut decoder)?;
        let payload = decoder
            .bytes()
            .map_err(|_| ReleaseRequestError::NonCanonical)?;
        if decoder.position() != bytes.len() || payload.len() != payload_length {
            return Err(ReleaseRequestError::NonCanonical);
        }
        if credential_free_request_digest != domain_hash(PREPARED_REQUEST_DOMAIN, payload)
            || payload_digest != payload_hash(payload)
        {
            return Err(ReleaseRequestError::NonCanonical);
        }

        let canonical = encode_canonical(CanonicalRequestFields {
            canonical_url: canonical_url.as_str(),
            tls_identity_pin: &tls_identity_pin,
            execution_nonce: &execution_nonce,
            dispatch_core_digest: &dispatch_core_digest,
            dispatch_subject_digest: &dispatch_subject_digest,
            payload_length: payload_length as u32,
            credential_free_request_digest: &credential_free_request_digest,
            payload_digest: &payload_digest,
            payload,
        })?;
        if canonical.as_slice() != bytes {
            return Err(ReleaseRequestError::NonCanonical);
        }

        Ok(Self {
            canonical_url: canonical_url.as_str().to_owned(),
            tls_identity_pin,
            execution_nonce,
            dispatch_core_digest,
            dispatch_subject_digest,
            credential_free_request_digest,
            payload_digest,
            wire_digest: wire_hash(bytes),
            payload: Zeroizing::new(payload.to_vec()),
        })
    }

    pub fn canonical_url(&self) -> &str {
        &self.canonical_url
    }

    pub const fn tls_identity_pin(&self) -> &[u8; 32] {
        &self.tls_identity_pin
    }

    pub const fn execution_nonce(&self) -> &[u8; 32] {
        &self.execution_nonce
    }

    pub const fn dispatch_core_digest(&self) -> &[u8; 32] {
        &self.dispatch_core_digest
    }

    pub const fn dispatch_subject_digest(&self) -> &[u8; 32] {
        &self.dispatch_subject_digest
    }

    pub const fn credential_free_request_digest(&self) -> &[u8; 32] {
        &self.credential_free_request_digest
    }

    pub const fn payload_digest(&self) -> &[u8; 32] {
        &self.payload_digest
    }

    pub const fn wire_digest(&self) -> &[u8; 32] {
        &self.wire_digest
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

fn decode_digest(decoder: &mut minicbor::Decoder<'_>) -> Result<[u8; 32], ReleaseRequestError> {
    decoder
        .bytes()
        .map_err(|_| ReleaseRequestError::NonCanonical)?
        .try_into()
        .map_err(|_| ReleaseRequestError::NonCanonical)
}

pub(crate) struct CanonicalRequestFields<'a> {
    pub canonical_url: &'a str,
    pub tls_identity_pin: &'a [u8; 32],
    pub execution_nonce: &'a [u8; 32],
    pub dispatch_core_digest: &'a [u8; 32],
    pub dispatch_subject_digest: &'a [u8; 32],
    pub payload_length: u32,
    pub credential_free_request_digest: &'a [u8; 32],
    pub payload_digest: &'a [u8; 32],
    pub payload: &'a [u8],
}

pub(crate) fn encode_canonical(
    fields: CanonicalRequestFields<'_>,
) -> Result<Vec<u8>, ReleaseRequestError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(11)
        .and_then(|encoder| encoder.u16(REQUEST_VERSION))
        .and_then(|encoder| encoder.u16(REQUEST_KIND))
        .and_then(|encoder| encoder.str(fields.canonical_url))
        .and_then(|encoder| encoder.bytes(fields.tls_identity_pin))
        .and_then(|encoder| encoder.bytes(fields.execution_nonce))
        .and_then(|encoder| encoder.bytes(fields.dispatch_core_digest))
        .and_then(|encoder| encoder.bytes(fields.dispatch_subject_digest))
        .and_then(|encoder| encoder.u32(fields.payload_length))
        .and_then(|encoder| encoder.bytes(fields.credential_free_request_digest))
        .and_then(|encoder| encoder.bytes(fields.payload_digest))
        .and_then(|encoder| encoder.bytes(fields.payload))
        .map_err(|_| ReleaseRequestError::NonCanonical)?;
    Ok(encoder.into_writer())
}

pub(crate) fn domain_hash(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    hasher.finalize().into()
}

pub(crate) fn payload_hash(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PAYLOAD_DOMAIN);
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    hasher.finalize().into()
}

pub(crate) fn wire_hash(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(WIRE_DOMAIN);
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    hasher.finalize().into()
}

fn is_zero(bytes: &[u8; 32]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}
