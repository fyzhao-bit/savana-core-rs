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
use savana_kernel_protocol::v2::{Digest32V2, PrincipalIdV2, UnixMillisV2};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use super::{
    decode_fixed, decode_settlement_payload, domain_hash, is_zero, ActiveHardwareCredentialV2,
    ApprovalDecisionV2, ApprovalErrorV2, ApprovalPurposeV2, ApprovalServiceV2,
    ConsumedApprovalSettlementV2, RegisteredEnvelopeV2, SignedApprovalEnvelopeV2,
    SignedApprovalSettlementV2, WebAuthnAssertionV2,
};

const STATE_FILE_NAME: &str = "approval-state-v2.cbor";
const LOCK_FILE_NAME: &str = ".approval-state-v2.cbor.lock";
const SCHEMA_VERSION: u16 = 2;
const ENCRYPTION_DOMAIN: &[u8] = b"SAVANA_APPROVAL_STATE_ENCRYPTION_V2\0";
const KEY_DERIVATION_DOMAIN: &[u8] = b"SAVANA_APPROVAL_STATE_KEY_DERIVATION_V2\0";
const HEAD_DOMAIN: &[u8] = b"SAVANA_APPROVAL_STATE_HEAD_V2\0";
const NONCE_BYTES: usize = 12;
const MAX_STATE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_CREDENTIALS: usize = 4_096;
const MAX_ENVELOPES: usize = 65_536;
const MAX_RECORD_BYTES: usize = 1024 * 1024;
const TEMP_ATTEMPTS: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApprovalStateHeadV2 {
    sequence: u64,
    state_digest: Digest32V2,
}

impl Default for ApprovalStateHeadV2 {
    fn default() -> Self {
        Self::GENESIS
    }
}

impl ApprovalStateHeadV2 {
    const GENESIS: Self = Self {
        sequence: 0,
        state_digest: Digest32V2::new([0; 32]),
    };

    pub fn new(sequence: u64, state_digest: Digest32V2) -> Result<Self, ApprovalErrorV2> {
        if (sequence == 0 && !is_zero(state_digest.as_bytes()))
            || (sequence != 0 && is_zero(state_digest.as_bytes()))
        {
            return Err(ApprovalErrorV2::RollbackDetected);
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
pub struct DurableApprovalNamespaceV2 {
    installation_id: Digest32V2,
    store_id: Digest32V2,
}

impl DurableApprovalNamespaceV2 {
    pub fn from_verified_installation(
        installation_id: Digest32V2,
        store_id: Digest32V2,
    ) -> Result<Self, ApprovalErrorV2> {
        if is_zero(installation_id.as_bytes()) || is_zero(store_id.as_bytes()) {
            return Err(ApprovalErrorV2::DurableState);
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

pub trait ApprovalRollbackAnchorV2: Send {
    fn current_head(&self) -> Result<ApprovalStateHeadV2, ApprovalErrorV2>;

    fn compare_and_advance(
        &mut self,
        expected: ApprovalStateHeadV2,
        next: ApprovalStateHeadV2,
    ) -> Result<(), ApprovalErrorV2>;
}

pub struct DurableApprovalServiceV2 {
    path: PathBuf,
    anchored_path: AnchoredPathV2,
    namespace: DurableApprovalNamespaceV2,
    encryption_key: Zeroizing<[u8; 32]>,
    sequence: u64,
    previous_state_digest: Digest32V2,
    current_head: ApprovalStateHeadV2,
    rollback_anchor: Box<dyn ApprovalRollbackAnchorV2>,
    service: ApprovalServiceV2,
    poisoned: bool,
    lock: StateLockV2,
}

impl std::fmt::Debug for DurableApprovalServiceV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DurableApprovalServiceV2")
            .field("path", &self.path)
            .field("sequence", &self.sequence)
            .field("poisoned", &self.poisoned)
            .finish_non_exhaustive()
    }
}

impl DurableApprovalServiceV2 {
    pub fn open(
        path: &Path,
        master_encryption_key: [u8; 32],
        namespace: DurableApprovalNamespaceV2,
        mut rollback_anchor: Box<dyn ApprovalRollbackAnchorV2>,
        deployment: ApprovalServiceV2,
    ) -> Result<Self, ApprovalErrorV2> {
        if path.file_name().and_then(|name| name.to_str()) != Some(STATE_FILE_NAME)
            || master_encryption_key == [0; 32]
            || deployment.installation_id != namespace.installation_id
            || !deployment.credentials.is_empty()
            || !deployment.envelopes.is_empty()
        {
            return Err(ApprovalErrorV2::DurableState);
        }
        let anchored_path = AnchoredPathV2::open(path)?;
        let lock = StateLockV2::acquire(
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
                    let snapshot_head = ApprovalStateHeadV2 {
                        sequence,
                        state_digest: state_head_digest(namespace, &bytes),
                    };
                    if snapshot_head == anchored_head {
                        (sequence, previous_state_digest, service, snapshot_head)
                    } else if sequence
                        == anchored_head
                            .sequence
                            .checked_add(1)
                            .ok_or(ApprovalErrorV2::RollbackDetected)?
                        && previous_state_digest == anchored_head.state_digest
                    {
                        rollback_anchor.compare_and_advance(anchored_head, snapshot_head)?;
                        (sequence, previous_state_digest, service, snapshot_head)
                    } else {
                        return Err(ApprovalErrorV2::RollbackDetected);
                    }
                }
                None => {
                    if anchored_head != ApprovalStateHeadV2::GENESIS {
                        return Err(ApprovalErrorV2::RollbackDetected);
                    }
                    (
                        0,
                        Digest32V2::new([0; 32]),
                        deployment,
                        ApprovalStateHeadV2::GENESIS,
                    )
                }
            };
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
            poisoned: false,
            lock,
        })
    }

    pub fn load_verified_hardware_credential(
        &mut self,
        credential_digest: Digest32V2,
        principal: PrincipalIdV2,
        aaguid: [u8; 16],
        p256_sec1_public_key: [u8; 65],
        signature_counter: u32,
    ) -> Result<(), ApprovalErrorV2> {
        self.mutate(|service| {
            service.load_verified_hardware_credential(
                credential_digest,
                principal,
                aaguid,
                p256_sec1_public_key,
                signature_counter,
            )
        })
    }

    pub fn register_envelope(
        &mut self,
        envelope: &SignedApprovalEnvelopeV2,
        now: UnixMillisV2,
    ) -> Result<Digest32V2, ApprovalErrorV2> {
        self.mutate(|service| service.register_envelope(envelope, now))
    }

    pub fn settle(
        &mut self,
        envelope_digest: Digest32V2,
        decision: ApprovalDecisionV2,
        assertion: &WebAuthnAssertionV2,
        now: UnixMillisV2,
    ) -> Result<SignedApprovalSettlementV2, ApprovalErrorV2> {
        self.mutate(|service| service.settle(envelope_digest, decision, assertion, now))
    }

    pub fn consume_settlement(
        &mut self,
        envelope_digest: Digest32V2,
        settlement_digest: Digest32V2,
        now: UnixMillisV2,
    ) -> Result<ConsumedApprovalSettlementV2, ApprovalErrorV2> {
        self.mutate(|service| service.consume_settlement(envelope_digest, settlement_digest, now))
    }

    fn mutate<T>(
        &mut self,
        operation: impl FnOnce(&mut ApprovalServiceV2) -> Result<T, ApprovalErrorV2>,
    ) -> Result<T, ApprovalErrorV2> {
        self.ensure_usable()?;
        let before = service_state_digest(&self.service)?;
        let mut next = self.service.clone();
        let result = operation(&mut next)?;
        if service_state_digest(&next)? != before {
            self.commit(next)?;
        }
        Ok(result)
    }

    fn ensure_usable(&self) -> Result<(), ApprovalErrorV2> {
        if self.poisoned {
            Err(ApprovalErrorV2::CommitUncertain)
        } else {
            Ok(())
        }
    }

    fn commit(&mut self, next: ApprovalServiceV2) -> Result<(), ApprovalErrorV2> {
        let sequence = self
            .sequence
            .checked_add(1)
            .ok_or(ApprovalErrorV2::DurableState)?;
        let previous_state_digest = self.current_head.state_digest;
        validate_service(&next)?;
        let bytes = encode_encrypted_snapshot(
            sequence,
            previous_state_digest,
            &next,
            &self.encryption_key,
            self.namespace,
        )?;
        let next_head = ApprovalStateHeadV2 {
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
                    return Err(ApprovalErrorV2::CommitUncertain);
                }
                self.service = next;
                self.sequence = sequence;
                self.previous_state_digest = previous_state_digest;
                self.current_head = next_head;
                Ok(())
            }
            Err(after_rename) => {
                if after_rename {
                    self.poisoned = true;
                    Err(ApprovalErrorV2::CommitUncertain)
                } else {
                    Err(ApprovalErrorV2::DurableState)
                }
            }
        }
    }
}

fn encode_encrypted_snapshot(
    sequence: u64,
    previous_state_digest: Digest32V2,
    service: &ApprovalServiceV2,
    key: &[u8; 32],
    namespace: DurableApprovalNamespaceV2,
) -> Result<Vec<u8>, ApprovalErrorV2> {
    let payload = encode_snapshot_payload(sequence, previous_state_digest, service)?;
    let mut nonce = [0_u8; NONCE_BYTES];
    getrandom::getrandom(&mut nonce).map_err(|_| ApprovalErrorV2::DurableState)?;
    if nonce == [0; NONCE_BYTES] {
        return Err(ApprovalErrorV2::DurableState);
    }
    let aad = encryption_aad(namespace, sequence, previous_state_digest, &nonce);
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|_| ApprovalErrorV2::DurableAuthentication)?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: payload.as_slice(),
                aad: &aad,
            },
        )
        .map_err(|_| ApprovalErrorV2::DurableAuthentication)?;
    encode_encrypted_envelope(sequence, previous_state_digest, &nonce, &ciphertext)
}

fn decode_encrypted_snapshot(
    bytes: &[u8],
    key: &[u8; 32],
    namespace: DurableApprovalNamespaceV2,
    deployment: ApprovalServiceV2,
) -> Result<(u64, Digest32V2, ApprovalServiceV2), ApprovalErrorV2> {
    if bytes.len() as u64 > MAX_STATE_BYTES {
        return Err(ApprovalErrorV2::DurableState);
    }
    let mut decoder = minicbor::Decoder::new(bytes);
    require_array(&mut decoder, 5)?;
    if decoder.u16().map_err(|_| ApprovalErrorV2::DurableState)? != SCHEMA_VERSION {
        return Err(ApprovalErrorV2::DurableState);
    }
    let sequence = decoder.u64().map_err(|_| ApprovalErrorV2::DurableState)?;
    let previous_state_digest = Digest32V2::new(decode_state_fixed::<32>(&mut decoder)?);
    let nonce = decode_state_fixed::<NONCE_BYTES>(&mut decoder)?;
    let ciphertext = decoder.bytes().map_err(|_| ApprovalErrorV2::DurableState)?;
    if decoder.position() != bytes.len()
        || encode_encrypted_envelope(sequence, previous_state_digest, &nonce, ciphertext)? != bytes
    {
        return Err(ApprovalErrorV2::DurableState);
    }
    let aad = encryption_aad(namespace, sequence, previous_state_digest, &nonce);
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|_| ApprovalErrorV2::DurableAuthentication)?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| ApprovalErrorV2::DurableAuthentication)?,
    );
    let service = decode_snapshot_payload(&plaintext, sequence, previous_state_digest, deployment)?;
    if encode_snapshot_payload(sequence, previous_state_digest, &service)?.as_slice()
        != plaintext.as_slice()
    {
        return Err(ApprovalErrorV2::DurableState);
    }
    Ok((sequence, previous_state_digest, service))
}

fn encode_encrypted_envelope(
    sequence: u64,
    previous_state_digest: Digest32V2,
    nonce: &[u8; NONCE_BYTES],
    ciphertext: &[u8],
) -> Result<Vec<u8>, ApprovalErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(5)
        .and_then(|encoder| encoder.u16(SCHEMA_VERSION))
        .and_then(|encoder| encoder.u64(sequence))
        .map_err(|_| ApprovalErrorV2::AllocationFailure)?;
    previous_state_digest
        .encode(&mut encoder, &mut ())
        .map_err(|_| ApprovalErrorV2::AllocationFailure)?;
    encoder
        .bytes(nonce)
        .and_then(|encoder| encoder.bytes(ciphertext))
        .map_err(|_| ApprovalErrorV2::AllocationFailure)?;
    let bytes = encoder.into_writer();
    if bytes.len() as u64 > MAX_STATE_BYTES {
        return Err(ApprovalErrorV2::AllocationFailure);
    }
    Ok(bytes)
}

fn encode_snapshot_payload(
    sequence: u64,
    previous_state_digest: Digest32V2,
    service: &ApprovalServiceV2,
) -> Result<Zeroizing<Vec<u8>>, ApprovalErrorV2> {
    validate_service(service)?;
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(5)
        .and_then(|encoder| encoder.u16(SCHEMA_VERSION))
        .and_then(|encoder| encoder.u64(sequence))
        .map_err(|_| ApprovalErrorV2::AllocationFailure)?;
    previous_state_digest
        .encode(&mut encoder, &mut ())
        .map_err(|_| ApprovalErrorV2::AllocationFailure)?;
    encoder
        .array(service.credentials.len() as u64)
        .map_err(|_| ApprovalErrorV2::AllocationFailure)?;
    for credential in &service.credentials {
        encoder
            .array(5)
            .map_err(|_| ApprovalErrorV2::AllocationFailure)?;
        credential
            .credential_digest
            .encode(&mut encoder, &mut ())
            .map_err(|_| ApprovalErrorV2::AllocationFailure)?;
        credential
            .principal
            .encode(&mut encoder, &mut ())
            .map_err(|_| ApprovalErrorV2::AllocationFailure)?;
        encoder
            .bytes(&credential.aaguid)
            .and_then(|encoder| encoder.bytes(&credential.p256_sec1_public_key))
            .and_then(|encoder| encoder.u32(credential.signature_counter))
            .map_err(|_| ApprovalErrorV2::AllocationFailure)?;
    }
    encoder
        .array(service.envelopes.len() as u64)
        .map_err(|_| ApprovalErrorV2::AllocationFailure)?;
    for envelope in &service.envelopes {
        encoder
            .array(5)
            .and_then(|encoder| encoder.bytes(&envelope.signed_envelope))
            .and_then(|encoder| encoder.bool(envelope.consumed))
            .map_err(|_| ApprovalErrorV2::AllocationFailure)?;
        encode_optional_settlement(&mut encoder, envelope.settlement.as_ref())?;
        encoder
            .bool(envelope.settlement_consumed)
            .map_err(|_| ApprovalErrorV2::AllocationFailure)?;
        envelope
            .envelope_digest
            .encode(&mut encoder, &mut ())
            .map_err(|_| ApprovalErrorV2::AllocationFailure)?;
    }
    Ok(Zeroizing::new(encoder.into_writer()))
}

fn decode_snapshot_payload(
    bytes: &[u8],
    expected_sequence: u64,
    expected_previous_state_digest: Digest32V2,
    mut service: ApprovalServiceV2,
) -> Result<ApprovalServiceV2, ApprovalErrorV2> {
    let mut decoder = minicbor::Decoder::new(bytes);
    require_array(&mut decoder, 5)?;
    if decoder.u16().map_err(|_| ApprovalErrorV2::DurableState)? != SCHEMA_VERSION
        || decoder.u64().map_err(|_| ApprovalErrorV2::DurableState)? != expected_sequence
        || Digest32V2::new(decode_state_fixed::<32>(&mut decoder)?)
            != expected_previous_state_digest
    {
        return Err(ApprovalErrorV2::DurableState);
    }
    let credential_count = decode_count(&mut decoder, MAX_CREDENTIALS)?;
    for _ in 0..credential_count {
        require_array(&mut decoder, 5)?;
        let credential_digest = Digest32V2::new(decode_state_fixed::<32>(&mut decoder)?);
        let principal = PrincipalIdV2::new(decode_state_fixed::<32>(&mut decoder)?);
        let aaguid = decode_state_fixed::<16>(&mut decoder)?;
        let public_key = decode_state_fixed::<65>(&mut decoder)?;
        let counter = decoder.u32().map_err(|_| ApprovalErrorV2::DurableState)?;
        service.load_verified_hardware_credential(
            credential_digest,
            principal,
            aaguid,
            public_key,
            counter,
        )?;
    }
    let envelope_count = decode_count(&mut decoder, MAX_ENVELOPES)?;
    for _ in 0..envelope_count {
        require_array(&mut decoder, 5)?;
        let signed_bytes = decoder.bytes().map_err(|_| ApprovalErrorV2::DurableState)?;
        if signed_bytes.is_empty() || signed_bytes.len() > MAX_RECORD_BYTES {
            return Err(ApprovalErrorV2::DurableState);
        }
        let signed = SignedApprovalEnvelopeV2::from_canonical_bytes(signed_bytes)?;
        let payload = super::decode_envelope_payload(&signed.canonical_payload)?;
        let consumed = decoder.bool().map_err(|_| ApprovalErrorV2::DurableState)?;
        let settlement = decode_optional_settlement(&mut decoder)?;
        let settlement_consumed = decoder.bool().map_err(|_| ApprovalErrorV2::DurableState)?;
        let stored_envelope_digest = Digest32V2::new(decode_state_fixed::<32>(&mut decoder)?);
        let envelope_digest = service.register_envelope(&signed, payload.issued_at)?;
        if envelope_digest != stored_envelope_digest {
            return Err(ApprovalErrorV2::DurableState);
        }
        let entry = service
            .envelopes
            .last_mut()
            .ok_or(ApprovalErrorV2::DurableState)?;
        entry.consumed = consumed;
        entry.settlement = settlement;
        entry.settlement_consumed = settlement_consumed;
    }
    if decoder.position() != bytes.len() {
        return Err(ApprovalErrorV2::DurableState);
    }
    validate_service(&service)?;
    Ok(service)
}

fn validate_service(service: &ApprovalServiceV2) -> Result<(), ApprovalErrorV2> {
    if service.credentials.len() > MAX_CREDENTIALS || service.envelopes.len() > MAX_ENVELOPES {
        return Err(ApprovalErrorV2::DurableState);
    }
    for (index, credential) in service.credentials.iter().enumerate() {
        ActiveHardwareCredentialV2::from_verified_enrollment(
            credential.credential_digest,
            credential.principal,
            credential.aaguid,
            credential.p256_sec1_public_key,
            credential.signature_counter,
        )?;
        if service.credentials[..index]
            .iter()
            .any(|candidate| candidate.credential_digest == credential.credential_digest)
        {
            return Err(ApprovalErrorV2::DurableState);
        }
    }
    for (index, envelope) in service.envelopes.iter().enumerate() {
        if service.envelopes[..index].iter().any(|candidate| {
            candidate.envelope_digest == envelope.envelope_digest
                || candidate.payload.envelope_nonce == envelope.payload.envelope_nonce
                || candidate.payload.decision_challenge == envelope.payload.decision_challenge
        }) {
            return Err(ApprovalErrorV2::DurableState);
        }
        let signed = SignedApprovalEnvelopeV2::from_canonical_bytes(&envelope.signed_envelope)?;
        let payload = super::decode_envelope_payload(&signed.canonical_payload)?;
        if payload.binding_digest != envelope.payload.binding_digest
            || domain_hash(payload.purpose.envelope_domain(), &signed.canonical_payload)
                != envelope.envelope_digest
            || envelope.consumed != envelope.settlement.is_some()
            || envelope.settlement_consumed && envelope.settlement.is_none()
        {
            return Err(ApprovalErrorV2::DurableState);
        }
        if let Some(settlement) = &envelope.settlement {
            validate_settlement(service, envelope, settlement)?;
        }
    }
    Ok(())
}

fn validate_settlement(
    service: &ApprovalServiceV2,
    envelope: &RegisteredEnvelopeV2,
    settlement: &SignedApprovalSettlementV2,
) -> Result<(), ApprovalErrorV2> {
    let payload = decode_settlement_payload(&settlement.canonical_payload)?;
    if settlement.key_id != service.settlement_key_id
        || payload.installation_id != service.installation_id
        || payload.active_state_manifest_digest != service.active_state_manifest_digest
        || payload.deployment_generation != service.deployment_generation
        || payload.purpose != envelope.payload.purpose
        || payload.envelope_digest != envelope.envelope_digest
        || payload.authenticated_principal != envelope.payload.expected_principal
        || payload.decision_challenge != envelope.payload.decision_challenge
        || settlement.settlement_digest
            != domain_hash(
                payload.purpose.settlement_domain(),
                &settlement.canonical_payload,
            )
    {
        return Err(ApprovalErrorV2::DurableState);
    }
    settlement_signature_valid(service, settlement, payload.purpose)?;
    let credential = service
        .credentials
        .iter()
        .find(|credential| {
            credential.credential_digest == payload.credential_digest
                && credential.principal == payload.authenticated_principal
        })
        .ok_or(ApprovalErrorV2::InvalidCredential)?;
    if credential.signature_counter < payload.signature_counter {
        return Err(ApprovalErrorV2::CounterReplay);
    }
    if envelope.settlement_consumed && payload.decision != ApprovalDecisionV2::Approve {
        return Err(ApprovalErrorV2::DurableState);
    }
    Ok(())
}

fn settlement_signature_valid(
    service: &ApprovalServiceV2,
    settlement: &SignedApprovalSettlementV2,
    purpose: ApprovalPurposeV2,
) -> Result<(), ApprovalErrorV2> {
    let digest = domain_hash(purpose.settlement_domain(), &settlement.canonical_payload);
    let mut signature_input = Vec::from(purpose.settlement_domain());
    signature_input.extend_from_slice(digest.as_bytes());
    service
        .settlement_signing_key
        .verifying_key()
        .verify_strict(
            &signature_input,
            &ed25519_dalek::Signature::from_bytes(&settlement.signature),
        )
        .map_err(|_| ApprovalErrorV2::InvalidEnvelopeSignature)
}

fn encode_optional_settlement(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    settlement: Option<&SignedApprovalSettlementV2>,
) -> Result<(), ApprovalErrorV2> {
    match settlement {
        Some(settlement) => encoder
            .bytes(&settlement.canonical_bytes()?)
            .map(|_| ())
            .map_err(|_| ApprovalErrorV2::AllocationFailure),
        None => encoder
            .null()
            .map(|_| ())
            .map_err(|_| ApprovalErrorV2::AllocationFailure),
    }
}

fn decode_optional_settlement(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<Option<SignedApprovalSettlementV2>, ApprovalErrorV2> {
    match decoder
        .datatype()
        .map_err(|_| ApprovalErrorV2::DurableState)?
    {
        Type::Null => {
            decoder.null().map_err(|_| ApprovalErrorV2::DurableState)?;
            Ok(None)
        }
        Type::Bytes => {
            let bytes = decoder.bytes().map_err(|_| ApprovalErrorV2::DurableState)?;
            if bytes.is_empty() || bytes.len() > MAX_RECORD_BYTES {
                return Err(ApprovalErrorV2::DurableState);
            }
            Ok(Some(SignedApprovalSettlementV2::from_canonical_bytes(
                bytes,
            )?))
        }
        _ => Err(ApprovalErrorV2::DurableState),
    }
}

fn service_state_digest(service: &ApprovalServiceV2) -> Result<Digest32V2, ApprovalErrorV2> {
    let payload = encode_snapshot_payload(0, Digest32V2::new([0; 32]), service)?;
    let mut hasher = Sha256::new();
    hasher.update(b"SAVANA_APPROVAL_SERVICE_STATE_V2\0");
    hasher.update(payload.as_slice());
    Ok(Digest32V2::new(hasher.finalize().into()))
}

fn decode_count(
    decoder: &mut minicbor::Decoder<'_>,
    maximum: usize,
) -> Result<usize, ApprovalErrorV2> {
    let count = decoder
        .array()
        .map_err(|_| ApprovalErrorV2::DurableState)?
        .ok_or(ApprovalErrorV2::DurableState)?;
    let count = usize::try_from(count).map_err(|_| ApprovalErrorV2::DurableState)?;
    if count > maximum {
        return Err(ApprovalErrorV2::DurableState);
    }
    Ok(count)
}

fn derive_encryption_key(
    master: &[u8; 32],
    namespace: DurableApprovalNamespaceV2,
) -> Result<Zeroizing<[u8; 32]>, ApprovalErrorV2> {
    let mut mac = <Hmac<Sha256> as hmac::Mac>::new_from_slice(master)
        .map_err(|_| ApprovalErrorV2::DurableState)?;
    mac.update(KEY_DERIVATION_DOMAIN);
    mac.update(namespace.installation_id.as_bytes());
    mac.update(namespace.store_id.as_bytes());
    Ok(Zeroizing::new(mac.finalize().into_bytes().into()))
}

fn encryption_aad(
    namespace: DurableApprovalNamespaceV2,
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

fn state_head_digest(namespace: DurableApprovalNamespaceV2, bytes: &[u8]) -> Digest32V2 {
    let mut hasher = Sha256::new();
    hasher.update(HEAD_DOMAIN);
    hasher.update(namespace.installation_id.as_bytes());
    hasher.update(namespace.store_id.as_bytes());
    hasher.update(bytes);
    Digest32V2::new(hasher.finalize().into())
}

pub(super) struct AnchoredPathV2 {
    pub(super) parent: File,
    parent_path: PathBuf,
    parent_dev: u64,
    parent_ino: u64,
    leaf: OsString,
    pub(super) owner_uid: u32,
    pub(super) owner_gid: u32,
}

impl AnchoredPathV2 {
    pub(super) fn open(path: &Path) -> Result<Self, ApprovalErrorV2> {
        if !path.is_absolute() {
            return Err(ApprovalErrorV2::DurableState);
        }
        let parent_path = path.parent().ok_or(ApprovalErrorV2::DurableState)?;
        let leaf = path
            .file_name()
            .ok_or(ApprovalErrorV2::DurableState)?
            .to_os_string();
        let before =
            fs::symlink_metadata(parent_path).map_err(|_| ApprovalErrorV2::DurableState)?;
        if before.file_type().is_symlink() {
            return Err(ApprovalErrorV2::DurableState);
        }
        let descriptor = rustix_open(
            parent_path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| ApprovalErrorV2::DurableState)?;
        let parent = File::from(descriptor);
        let opened = parent
            .metadata()
            .map_err(|_| ApprovalErrorV2::DurableState)?;
        if !opened.is_dir()
            || opened.dev() != before.dev()
            || opened.ino() != before.ino()
            || opened.uid() != before.uid()
            || opened.gid() != before.gid()
            || opened.mode() & 0o7777 != 0o700
        {
            return Err(ApprovalErrorV2::DurableState);
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

    pub(super) fn recheck_parent(&self) -> Result<(), ApprovalErrorV2> {
        let opened = self
            .parent
            .metadata()
            .map_err(|_| ApprovalErrorV2::DurableState)?;
        let linked =
            fs::symlink_metadata(&self.parent_path).map_err(|_| ApprovalErrorV2::DurableState)?;
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
            return Err(ApprovalErrorV2::DurableState);
        }
        Ok(())
    }

    pub(super) fn read_existing(&self) -> Result<Option<Vec<u8>>, ApprovalErrorV2> {
        let before = match statat(&self.parent, &self.leaf, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => stat,
            Err(Errno::NOENT) => return Ok(None),
            Err(_) => return Err(ApprovalErrorV2::DurableState),
        };
        if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile {
            return Err(ApprovalErrorV2::DurableState);
        }
        let descriptor = openat(
            &self.parent,
            &self.leaf,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| ApprovalErrorV2::DurableState)?;
        let mut file = File::from(descriptor);
        let opened = file.metadata().map_err(|_| ApprovalErrorV2::DurableState)?;
        if !opened.is_file()
            || i128::from(before.st_dev) != i128::from(opened.dev())
            || before.st_ino != opened.ino()
            || before.st_uid != self.owner_uid
            || before.st_gid != self.owner_gid
            || opened.uid() != self.owner_uid
            || opened.gid() != self.owner_gid
            || opened.mode() & 0o7777 != 0o600
            || opened.nlink() != 1
            || opened.len() > MAX_STATE_BYTES
        {
            return Err(ApprovalErrorV2::DurableState);
        }
        let capacity = usize::try_from(opened.len()).map_err(|_| ApprovalErrorV2::DurableState)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(capacity)
            .map_err(|_| ApprovalErrorV2::AllocationFailure)?;
        file.read_to_end(&mut bytes)
            .map_err(|_| ApprovalErrorV2::DurableState)?;
        let after = statat(&self.parent, &self.leaf, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| ApprovalErrorV2::DurableState)?;
        if bytes.len() != capacity
            || i128::from(after.st_dev) != i128::from(opened.dev())
            || after.st_ino != opened.ino()
            || u64::try_from(after.st_size).ok() != Some(opened.len())
        {
            return Err(ApprovalErrorV2::DurableState);
        }
        self.recheck_parent()?;
        Ok(Some(bytes))
    }

    pub(super) fn replace(&self, bytes: &[u8]) -> Result<(), bool> {
        let (temporary_leaf, mut temporary) =
            create_temporary(&self.parent, &self.leaf, self.owner_uid, self.owner_gid)
                .map_err(|_| false)?;
        let before_rename = (|| {
            temporary
                .write_all(bytes)
                .map_err(|_| ApprovalErrorV2::DurableState)?;
            temporary
                .sync_all()
                .map_err(|_| ApprovalErrorV2::DurableState)?;
            validate_file_at(
                &self.parent,
                &temporary_leaf,
                &temporary,
                self.owner_uid,
                self.owner_gid,
                u64::try_from(bytes.len()).map_err(|_| ApprovalErrorV2::DurableState)?,
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
) -> Result<(OsString, File), ApprovalErrorV2> {
    for _ in 0..TEMP_ATTEMPTS {
        let mut random = [0_u8; 16];
        getrandom::getrandom(&mut random).map_err(|_| ApprovalErrorV2::DurableState)?;
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
                    .map_err(|_| ApprovalErrorV2::DurableState)?;
                validate_file_at(parent, &temporary_leaf, &file, owner_uid, owner_gid, 0)?;
                return Ok((temporary_leaf, file));
            }
            Err(Errno::EXIST) => {}
            Err(_) => return Err(ApprovalErrorV2::DurableState),
        }
    }
    Err(ApprovalErrorV2::DurableState)
}

fn validate_file_at(
    parent: &File,
    leaf: &OsStr,
    file: &File,
    owner_uid: u32,
    owner_gid: u32,
    expected_length: u64,
) -> Result<(), ApprovalErrorV2> {
    let opened = file.metadata().map_err(|_| ApprovalErrorV2::DurableState)?;
    let linked = statat(parent, leaf, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| ApprovalErrorV2::DurableState)?;
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
        return Err(ApprovalErrorV2::DurableState);
    }
    Ok(())
}

pub(super) struct StateLockV2 {
    file: Flock<File>,
    parent: File,
    leaf: OsString,
    owner_uid: u32,
    owner_gid: u32,
}

impl StateLockV2 {
    pub(super) fn acquire(
        parent: &File,
        leaf: &OsStr,
        owner_uid: u32,
        owner_gid: u32,
    ) -> Result<Self, ApprovalErrorV2> {
        let descriptor = openat(
            parent,
            leaf,
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::from_bits_truncate(0o600),
        )
        .map_err(|_| ApprovalErrorV2::DurableState)?;
        let file = File::from(descriptor);
        fchmod(&file, Mode::from_bits_truncate(0o600))
            .map_err(|_| ApprovalErrorV2::DurableState)?;
        validate_file_at(parent, leaf, &file, owner_uid, owner_gid, 0)?;
        let file = Flock::lock(file, FlockArg::LockExclusiveNonblock)
            .map_err(|_| ApprovalErrorV2::DurableState)?;
        validate_file_at(parent, leaf, &file, owner_uid, owner_gid, 0)?;
        parent
            .sync_all()
            .map_err(|_| ApprovalErrorV2::DurableState)?;
        Ok(Self {
            file,
            parent: parent
                .try_clone()
                .map_err(|_| ApprovalErrorV2::DurableState)?,
            leaf: leaf.to_os_string(),
            owner_uid,
            owner_gid,
        })
    }

    pub(super) fn recheck(&self) -> Result<(), ApprovalErrorV2> {
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

fn require_array(
    decoder: &mut minicbor::Decoder<'_>,
    expected: u64,
) -> Result<(), ApprovalErrorV2> {
    if decoder.array().map_err(|_| ApprovalErrorV2::DurableState)? != Some(expected) {
        return Err(ApprovalErrorV2::DurableState);
    }
    Ok(())
}

fn decode_state_fixed<const N: usize>(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<[u8; N], ApprovalErrorV2> {
    decode_fixed(decoder).map_err(|_| ApprovalErrorV2::DurableState)
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
