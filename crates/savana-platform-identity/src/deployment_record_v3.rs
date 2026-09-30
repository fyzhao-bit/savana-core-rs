//! V3 deployment evidence envelopes and whole-record durable journal.
//! This authenticates evidence BYTES, not the evidence's business semantics.
//! A verified envelope is not a verified V2 ledger, transition, or boot permit.
use crate::tpm_wire::Reader;
use crate::{
    NativeDeploymentSignatureDomainV2 as Domain, TpmEnrollmentV3, TpmSignatureEnvelopeV3,
    TpmSignatureErrorV3 as Error, TpmSignatureRequestV3, TpmStateHeadV3, TpmStoreV3,
};
use sha2::{Digest, Sha256};

pub(crate) const MAX_PAYLOAD: usize = 1024 * 1024;
pub(crate) const MAX_RECORD: usize = MAX_PAYLOAD + 204 + 176;
#[cfg(any(test, target_os = "linux"))]
pub(crate) const MAX_HISTORY_RECORDS: u64 = 4096;
#[cfg(any(test, target_os = "linux"))]
pub(crate) const MAX_HISTORY_BYTES: usize = 16 * 1024 * 1024;

/// Context is supplied by the typed deployment consumer, not inferred from a
/// record's self-declared purpose. A zero transaction means installation scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeploymentRecordScopeV3 {
    domain: Domain,
    generation: u64,
    transaction: [u8; 32],
}
impl DeploymentRecordScopeV3 {
    pub fn new(domain: Domain, generation: u64, transaction: [u8; 32]) -> Result<Self, Error> {
        if generation == 0 {
            return Err(Error::Malformed);
        }
        Ok(Self {
            domain,
            generation,
            transaction,
        })
    }
    pub const fn domain(self) -> Domain {
        self.domain
    }
    pub const fn generation(self) -> u64 {
        self.generation
    }
    pub const fn transaction(self) -> [u8; 32] {
        self.transaction
    }
}

/// Cryptographic authentication only. This type deliberately has no conversion
/// into legacy verified deployment records or daemon-startup authority.
#[derive(Clone)]
pub struct VerifiedDeploymentRecordEnvelopeV3 {
    bytes: Vec<u8>,
    scope: DeploymentRecordScopeV3,
    head: TpmStateHeadV3,
    previous: TpmStateHeadV3,
    written_at: u64,
    installation: [u8; 32],
    epoch: u64,
    enrollment: [u8; 32],
    payload: Vec<u8>,
}
impl VerifiedDeploymentRecordEnvelopeV3 {
    pub fn verify_for(
        bytes: &[u8],
        enrollment: &TpmEnrollmentV3,
        expected_scope: DeploymentRecordScopeV3,
        expected_previous: TpmStateHeadV3,
        now: u64,
    ) -> Result<Self, Error> {
        let value = Self::decode(bytes, enrollment, now)?;
        if value.scope != expected_scope || value.previous != expected_previous {
            return Err(Error::BindingMismatch);
        }
        Ok(value)
    }
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn authenticated_payload(&self) -> &[u8] {
        &self.payload
    }
    pub const fn scope(&self) -> DeploymentRecordScopeV3 {
        self.scope
    }
    pub const fn head(&self) -> TpmStateHeadV3 {
        self.head
    }
    pub const fn previous_head(&self) -> TpmStateHeadV3 {
        self.previous
    }
    pub const fn written_at(&self) -> u64 {
        self.written_at
    }
    pub const fn installation_id(&self) -> [u8; 32] {
        self.installation
    }
    pub const fn installation_epoch(&self) -> u64 {
        self.epoch
    }
    pub const fn enrollment_digest(&self) -> [u8; 32] {
        self.enrollment
    }

    fn decode(bytes: &[u8], enrollment: &TpmEnrollmentV3, now: u64) -> Result<Self, Error> {
        enrollment.check_time(now)?;
        if bytes.len() > MAX_RECORD || bytes.len() < 381 {
            return Err(Error::Malformed);
        }
        let (unsigned, signature) = bytes.split_at(bytes.len() - 176);
        let mut r = Reader::new(unsigned);
        if r.take(4)? != b"SDR3" || r.u16()? != 3 {
            return Err(Error::Malformed);
        }
        let domain = domain(r.u16()?)?;
        let binding = enrollment.signing_binding();
        if r.fixed::<32>()? != enrollment.digest()
            || r.fixed::<32>()? != binding.installation_id()
            || u64::from_be_bytes(r.fixed()?) != binding.epoch()
            || r.fixed::<32>()? != enrollment.store_binding(TpmStoreV3::Deployment).store_id()
        {
            return Err(Error::BindingMismatch);
        }
        let sequence = u64::from_be_bytes(r.fixed()?);
        let previous_digest = r.fixed()?;
        let generation = u64::from_be_bytes(r.fixed()?);
        let transaction = r.fixed()?;
        let written_at = u64::from_be_bytes(r.fixed()?);
        let len = r.u32()? as usize;
        if sequence == 0 || written_at == 0 || written_at > now || len == 0 || len > MAX_PAYLOAD {
            return Err(Error::Malformed);
        }
        // A signature cannot make an out-of-validity timestamp meaningful.
        enrollment.check_time(written_at)?;
        let previous = TpmStateHeadV3::new(sequence - 1, previous_digest)?;
        let scope = DeploymentRecordScopeV3::new(domain, generation, transaction)?;
        let payload = r.take(len)?.to_vec();
        r.end()?;
        TpmSignatureEnvelopeV3::from_bytes(signature)?.verify(
            binding.public(),
            TpmSignatureRequestV3::new(
                domain,
                binding.installation_id(),
                binding.epoch(),
                hash(b"savana.deployment-record.v3.unsigned\0", unsigned),
            )?,
        )?;
        Ok(Self {
            bytes: bytes.to_vec(),
            scope,
            previous,
            written_at,
            payload,
            installation: binding.installation_id(),
            epoch: binding.epoch(),
            enrollment: enrollment.digest(),
            head: TpmStateHeadV3::new(
                sequence,
                hash(b"savana.deployment-record.v3.signed\0", bytes),
            )?,
        })
    }
}
fn hash(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(domain);
    h.update(bytes);
    h.finalize().into()
}
fn domain(tag: u16) -> Result<Domain, Error> {
    Ok(match tag {
        5 => Domain::LedgerActivation,
        6 => Domain::InstallationEpochActivation,
        8 => Domain::StoreCompatibility,
        9 => Domain::VerificationEvidence,
        10 => Domain::CommitAttestation,
        13 => Domain::EvidenceGcCheckpoint,
        17 => Domain::RollbackVerificationEvidence,
        18 => Domain::RollbackVerificationAttestation,
        21 => Domain::LedgerSlot,
        22 => Domain::InstallationEvidenceEnvelope,
        25 => Domain::DurableDeploymentTransactionCore,
        26 => Domain::DurableDeploymentTransactionRecord,
        27 => Domain::RecoveryRollbackReadinessEvidence,
        _ => return Err(Error::Malformed),
    })
}

#[cfg(any(test, target_os = "linux"))]
pub(crate) mod runtime {
    use super::*;
    // Private traits: software authorities and arbitrary paths cannot be injected
    // through the native public constructor. Fault injection lives in tests only.
    pub(crate) trait Authority {
        fn enrollment(&self) -> &TpmEnrollmentV3;
        fn head(&mut self) -> Result<TpmStateHeadV3, Error>;
        fn sign(&mut self, request: TpmSignatureRequestV3)
            -> Result<TpmSignatureEnvelopeV3, Error>;
        fn advance(&mut self, expected: TpmStateHeadV3, next: TpmStateHeadV3) -> Result<(), Error>;
    }
    pub(crate) trait Storage {
        fn read(&self, slot: usize) -> Result<Option<Vec<u8>>, Error>;
        /// Return only after file and directory durability barriers completed.
        fn write(&mut self, slot: usize, bytes: &[u8]) -> Result<(), Error>;
        fn read_archive(&self, head: TpmStateHeadV3) -> Result<Option<Vec<u8>>, Error>;
        /// Immutable content-addressed publication, durable before returning.
        fn write_archive(&mut self, head: TpmStateHeadV3, bytes: &[u8]) -> Result<(), Error>;
    }
    pub(crate) struct Journal<A, S> {
        authority: A,
        storage: S,
        usable: bool,
    }
    /// Prepared is not committed and must never be used as boot/transition evidence.
    pub struct DeploymentJournalSnapshotV3 {
        committed: Option<VerifiedDeploymentRecordEnvelopeV3>,
        prepared: Option<VerifiedDeploymentRecordEnvelopeV3>,
    }
    impl DeploymentJournalSnapshotV3 {
        pub fn committed(&self) -> Option<&VerifiedDeploymentRecordEnvelopeV3> {
            self.committed.as_ref()
        }
        pub fn prepared(&self) -> Option<&VerifiedDeploymentRecordEnvelopeV3> {
            self.prepared.as_ref()
        }
        pub fn head(&self) -> TpmStateHeadV3 {
            self.committed
                .as_ref()
                .map_or(TpmStateHeadV3::GENESIS, |r| r.head)
        }
    }
    impl<A: Authority, S: Storage> Journal<A, S> {
        pub(crate) fn open(authority: A, storage: S, now: u64) -> Result<Self, Error> {
            let mut value = Self {
                authority,
                storage,
                usable: true,
            };
            value.history(now)?;
            Ok(value)
        }
        pub(crate) fn history(
            &mut self,
            now: u64,
        ) -> Result<Vec<VerifiedDeploymentRecordEnvelopeV3>, Error> {
            if !self.usable {
                return Err(Error::Unavailable);
            }
            let result = self
                .load(now)
                .and_then(|snapshot| self.history_from(snapshot.head(), now));
            if result.is_err() {
                self.usable = false;
            }
            result
        }
        fn history_from(
            &mut self,
            head: TpmStateHeadV3,
            now: u64,
        ) -> Result<Vec<VerifiedDeploymentRecordEnvelopeV3>, Error> {
            if head.sequence() > MAX_HISTORY_RECORDS {
                return Err(Error::Malformed);
            }
            let mut current = head;
            let mut records = Vec::new();
            let mut bytes_total = 0usize;
            let mut last_time = now;
            while current != TpmStateHeadV3::GENESIS {
                let bytes = self
                    .storage
                    .read_archive(current)?
                    .ok_or(Error::BindingMismatch)?;
                bytes_total = bytes_total
                    .checked_add(bytes.len())
                    .ok_or(Error::Malformed)?;
                if bytes_total > MAX_HISTORY_BYTES {
                    return Err(Error::Malformed);
                }
                let record = VerifiedDeploymentRecordEnvelopeV3::decode(
                    &bytes,
                    self.authority.enrollment(),
                    now,
                )?;
                if record.head != current || record.written_at > last_time {
                    return Err(Error::BindingMismatch);
                }
                current = record.previous;
                last_time = record.written_at;
                records.push(record);
            }
            if self.authority.head()? != head {
                return Err(Error::BindingMismatch);
            }
            records.reverse();
            Ok(records)
        }
        pub(crate) fn snapshot(&mut self, now: u64) -> Result<DeploymentJournalSnapshotV3, Error> {
            if !self.usable {
                return Err(Error::Unavailable);
            }
            let result = self.load(now);
            if result.is_err() {
                self.usable = false;
            }
            result
        }
        fn load(&mut self, now: u64) -> Result<DeploymentJournalSnapshotV3, Error> {
            self.authority.enrollment().check_time(now)?;
            let head = self.authority.head()?;
            let mut records = Vec::new();
            for slot in 0..2 {
                if let Some(bytes) = self.storage.read(slot)? {
                    let record = VerifiedDeploymentRecordEnvelopeV3::decode(
                        &bytes,
                        self.authority.enrollment(),
                        now,
                    )?;
                    if record.head.sequence() % 2 != slot as u64 {
                        return Err(Error::BindingMismatch);
                    }
                    records.push(record);
                }
            }
            let committed = records.iter().find(|r| r.head == head).cloned();
            if head != TpmStateHeadV3::GENESIS && committed.is_none() {
                return Err(Error::BindingMismatch);
            }
            let mut prepared = None;
            for record in records {
                if record.head == head {
                    continue;
                }
                if record.previous == head
                    && head.sequence().checked_add(1) == Some(record.head.sequence())
                {
                    if prepared.replace(record).is_some() {
                        return Err(Error::BindingMismatch);
                    }
                } else if let Some(current) = &committed {
                    if record.head != current.previous {
                        return Err(Error::BindingMismatch);
                    }
                } else {
                    return Err(Error::BindingMismatch);
                }
            }
            // Detect a different writer changing the anchor during the disk read.
            if self.authority.head()? != head {
                return Err(Error::BindingMismatch);
            }
            Ok(DeploymentJournalSnapshotV3 {
                committed,
                prepared,
            })
        }
        pub(crate) fn append(
            &mut self,
            expected: TpmStateHeadV3,
            scope: DeploymentRecordScopeV3,
            payload: &[u8],
            now: u64,
        ) -> Result<VerifiedDeploymentRecordEnvelopeV3, Error> {
            if !self.usable {
                return Err(Error::Unavailable);
            }
            let result = self.append_inner(expected, scope, payload, now);
            if result.is_err() {
                self.usable = false;
            }
            result
        }
        fn append_inner(
            &mut self,
            expected: TpmStateHeadV3,
            scope: DeploymentRecordScopeV3,
            payload: &[u8],
            now: u64,
        ) -> Result<VerifiedDeploymentRecordEnvelopeV3, Error> {
            if payload.is_empty() || payload.len() > MAX_PAYLOAD {
                return Err(Error::Malformed);
            }
            let snapshot = self.load(now)?;
            if snapshot.head() != expected {
                return Err(Error::BindingMismatch);
            }
            let history = self.history_from(expected, now)?;
            if expected.sequence() >= MAX_HISTORY_RECORDS {
                return Err(Error::Malformed);
            }
            let archived_bytes: usize = history.iter().map(|r| r.canonical_bytes().len()).sum();
            if archived_bytes
                .checked_add(payload.len() + 204 + 176)
                .map_or(true, |n| n > MAX_HISTORY_BYTES)
            {
                return Err(Error::Malformed);
            }
            let record = if let Some(prepared) = snapshot.prepared {
                // Reuse the original signature/bytes. Never silently discard a
                // different prepared record after an interrupted deployment step.
                if prepared.scope != scope || prepared.payload != payload {
                    return Err(Error::BindingMismatch);
                }
                prepared
            } else {
                let enrollment = self.authority.enrollment();
                let binding = enrollment.signing_binding();
                let sequence = expected.sequence().checked_add(1).ok_or(Error::Malformed)?;
                let mut bytes = b"SDR3".to_vec();
                bytes.extend_from_slice(&3_u16.to_be_bytes());
                bytes.extend_from_slice(&(scope.domain as u16).to_be_bytes());
                bytes.extend_from_slice(&enrollment.digest());
                bytes.extend_from_slice(&binding.installation_id());
                bytes.extend_from_slice(&binding.epoch().to_be_bytes());
                bytes.extend_from_slice(
                    &enrollment.store_binding(TpmStoreV3::Deployment).store_id(),
                );
                bytes.extend_from_slice(&sequence.to_be_bytes());
                bytes.extend_from_slice(&expected.digest());
                bytes.extend_from_slice(&scope.generation.to_be_bytes());
                bytes.extend_from_slice(&scope.transaction);
                bytes.extend_from_slice(&now.to_be_bytes());
                bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
                bytes.extend_from_slice(payload);
                let request = TpmSignatureRequestV3::new(
                    scope.domain,
                    binding.installation_id(),
                    binding.epoch(),
                    hash(b"savana.deployment-record.v3.unsigned\0", &bytes),
                )?;
                let signature = self.authority.sign(request)?;
                bytes.extend_from_slice(&signature.to_bytes());
                VerifiedDeploymentRecordEnvelopeV3::verify_for(
                    &bytes,
                    self.authority.enrollment(),
                    scope,
                    expected,
                    now,
                )?
            };
            self.storage.write_archive(record.head, &record.bytes)?;
            self.storage
                .write((record.head.sequence() % 2) as usize, &record.bytes)?;
            self.authority.advance(expected, record.head)?;
            if self.authority.head()? != record.head {
                return Err(Error::BindingMismatch);
            }
            Ok(record)
        }
    }
}

#[cfg(test)]
#[path = "deployment_record_v3_tests.rs"]
pub(crate) mod tests;
