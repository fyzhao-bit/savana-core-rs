//! TPM-authenticated deployment ledger semantics, separate from V2 signatures.
//!
//! These types validate records and their sequence relation, NOT installation
//! measurements, transaction-head evidence, present NV commitment or startup.
//! There is deliberately no conversion into a runtime activation capability.
use super::{
    ActiveActivationV2, ClosedSecurityDomainV2, DeploymentBranchV2,
    DeploymentControlErrorV2 as Error, DeploymentLedgerProjectionV2, DeploymentPhaseV2 as Phase,
    HighWaterEntryV2, HighestEverV2, RollbackGrantStateV2 as Grant,
    RollbackOriginPhaseV2 as Origin,
};
use savana_kernel_protocol::v2::{Digest32V2, Nonce32V2};
use savana_platform_identity::{
    DeploymentRecordScopeV3, NativeDeploymentSignatureDomainV2 as Domain, TpmStateHeadV3,
    VerifiedDeploymentRecordEnvelopeV3,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

const MAGIC: &[u8] = b"SLV3\0";
const MAX_BYTES: usize = 4096;
const MAX_INTERVENING: usize = 64;
const MAX_HISTORY: usize = 4096;
const MAX_HISTORY_BYTES: usize = 16 * 1024 * 1024;

/// Unsigned input. Constructing this value confers no authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeploymentLedgerMaterialV3 {
    pub installation: Digest32V2,
    pub epoch: u64,
    pub generation: u64,
    pub written_at_ms: u64,
    pub phase: Phase,
    pub transaction: Option<Nonce32V2>,
    pub effects_fenced: bool,
    pub fence_epoch: u64,
    pub active_manifest: Digest32V2,
    pub active_activation: ActiveActivationV2,
    pub identity_profile: Digest32V2,
    pub bootstrap_tcb_lock: Digest32V2,
    pub highest_ever: HighestEverV2,
    pub grant: Grant,
    pub rollback_grant_id: Option<Digest32V2>,
    pub rollback_origin: Option<Origin>,
    pub transaction_head: Option<Digest32V2>,
    pub previous_payload: Digest32V2,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeploymentLedgerStateV3 {
    material: DeploymentLedgerMaterialV3,
    canonical: Vec<u8>,
    projection: DeploymentLedgerProjectionV2,
}
impl DeploymentLedgerStateV3 {
    pub fn new(material: DeploymentLedgerMaterialV3) -> Result<Self, Error> {
        validate_shape(&material)?;
        let canonical = encode(&material)?;
        let digest = digest(&canonical);
        let projection = DeploymentLedgerProjectionV2::from_authenticated_record(
            material.installation,
            material.epoch,
            material.generation,
            material.previous_payload,
            digest,
            material.phase,
            material.transaction,
            material.effects_fenced,
            material.fence_epoch,
            material.grant,
            material.transaction_head,
        )?;
        Ok(Self {
            material,
            canonical,
            projection,
        })
    }
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let value = Self::new(decode(bytes)?)?;
        if value.canonical != bytes {
            return Err(Error::NonCanonicalLedgerEncoding);
        }
        Ok(value)
    }
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }
    pub fn material(&self) -> &DeploymentLedgerMaterialV3 {
        &self.material
    }
    pub fn projection(&self) -> &DeploymentLedgerProjectionV2 {
        &self.projection
    }
    pub fn payload_digest(&self) -> Digest32V2 {
        self.projection.record_payload_digest()
    }
    pub fn scope(&self) -> DeploymentRecordScopeV3 {
        DeploymentRecordScopeV3::new(
            Domain::LedgerActivation,
            self.material.generation,
            self.material
                .transaction
                .map_or([0; 32], |id| *id.as_bytes()),
        )
        .expect("validated generation")
    }
    /// A shape check, not installer authorization of the initial manifest.
    pub fn validate_fresh_genesis(&self) -> Result<(), Error> {
        let m = &self.material;
        if m.epoch != 1
            || m.generation != 1
            || m.fence_epoch != 1
            || m.previous_payload.as_bytes() != &[0; 32]
            || m.phase != Phase::Idle
            || m.active_activation != ActiveActivationV2::Normal
        {
            return Err(Error::InvalidLedgerRecord);
        }
        Ok(())
    }
    pub fn validate_successor(&self, next: &Self) -> Result<(), Error> {
        let c = &self.material;
        let n = &next.material;
        // The shared frozen V2 graph/fence/grant rules have no crypto dependency.
        self.projection
            .validate_successor(&next.projection, DeploymentBranchV2::Normal)?;
        if n.written_at_ms < c.written_at_ms
            || n.identity_profile != c.identity_profile
            || n.bootstrap_tcb_lock != c.bootstrap_tcb_lock
        {
            return Err(Error::ActiveStateMismatch);
        }
        // A new deployment transaction cannot reuse the preceding transaction ID.
        if n.phase == Phase::Prepared
            && (n.transaction == c.transaction || n.rollback_grant_id == c.rollback_grant_id)
        {
            return Err(Error::TransactionBindingMismatch);
        }
        if !matches!(n.phase, Phase::Prepared | Phase::Idle)
            && n.rollback_grant_id != c.rollback_grant_id
        {
            return Err(Error::RollbackGrantMismatch);
        }
        let activation_ok = match n.phase {
            Phase::Committed => {
                n.active_manifest != c.active_manifest
                    && n.active_activation == ActiveActivationV2::Normal
            }
            Phase::RolledBack => matches!(&n.active_activation,
                ActiveActivationV2::ConsumedRollback { failed_transaction_id, .. }
                    if Some(*failed_transaction_id) == c.transaction),
            _ => {
                n.active_manifest == c.active_manifest && n.active_activation == c.active_activation
            }
        };
        if !activation_ok {
            return Err(Error::ActiveStateMismatch);
        }
        let origin = match n.phase {
            Phase::RollbackPrepared => Some(match c.phase {
                Phase::Armed => Origin::Armed,
                Phase::Quiesced => Origin::Quiesced,
                Phase::Installed => Origin::Installed,
                Phase::Verified => Origin::Verified,
                _ => return Err(Error::RollbackOriginMismatch),
            }),
            Phase::RollbackInstalled
            | Phase::RollbackVerified
            | Phase::RolledBack
            | Phase::FailedSafe => c.rollback_origin,
            _ => None,
        };
        if n.rollback_origin != origin {
            return Err(Error::RollbackOriginMismatch);
        }
        for (old, new) in c
            .highest_ever
            .entries()
            .iter()
            .zip(n.highest_ever.entries())
        {
            if new.sequence() < old.sequence()
                || new.key_epoch() < old.key_epoch()
                || (new.sequence() == old.sequence() && new != old)
            {
                return Err(Error::HighestEverMismatch);
            }
        }
        Ok(())
    }
}

/// Authenticated shape and context. An individual record does not prove history
/// or that it is currently committed. Callers must also check the live anchor.
#[derive(Clone)]
pub struct VerifiedDeploymentLedgerRecordV3 {
    record: VerifiedDeploymentRecordEnvelopeV3,
    state: DeploymentLedgerStateV3,
}

/// Replayed history ending at a caller-supplied live anchor. This is not an
/// attestation of where that anchor came from and is not a daemon boot permit.
pub struct DeploymentLedgerHistoryV3 {
    latest: VerifiedDeploymentLedgerRecordV3,
    trailing: Vec<VerifiedDeploymentRecordEnvelopeV3>,
    head: TpmStateHeadV3,
    records: Vec<VerifiedDeploymentRecordEnvelopeV3>,
}
impl DeploymentLedgerHistoryV3 {
    /// Measured root deployment-reader path. The expected genesis must come from
    /// reviewed installer material. No native startup gate is opened by this.
    #[cfg(target_os = "linux")]
    pub fn load_native(
        journal: &mut savana_platform_identity::LinuxDeploymentJournalV3,
        expected_genesis_payload: Digest32V2,
    ) -> Result<Self, Error> {
        let records = journal
            .history()
            .map_err(|_| Error::NativeSigningAuthorityUnavailable)?;
        let live = journal
            .snapshot()
            .map_err(|_| Error::NativeSigningAuthorityUnavailable)?
            .head();
        Self::verify(&records, expected_genesis_payload, live)
    }
    pub fn verify(
        records: &[VerifiedDeploymentRecordEnvelopeV3],
        expected_genesis_payload: Digest32V2,
        live_head: TpmStateHeadV3,
    ) -> Result<Self, Error> {
        if records.is_empty()
            || records.len() > MAX_HISTORY
            || records
                .iter()
                .try_fold(0usize, |sum, r| sum.checked_add(r.canonical_bytes().len()))
                .map_or(true, |sum| sum > MAX_HISTORY_BYTES)
        {
            return Err(Error::LedgerConflict);
        }
        let mut latest = VerifiedDeploymentLedgerRecordV3::verify(records[0].clone())?;
        latest.validate_fresh_genesis()?;
        if latest.state.payload_digest() != expected_genesis_payload {
            return Err(Error::LedgerConflict);
        }
        let mut head = latest.record.head();
        let mut time = latest.record.written_at();
        let mut pending = Vec::new();
        let mut transactions = BTreeSet::new();
        let mut used_grants = BTreeSet::new();
        for record in &records[1..] {
            if record.previous_head() != head
                || record.enrollment_digest() != latest.record.enrollment_digest()
                || record.written_at() < time
            {
                return Err(Error::LedgerConflict);
            }
            if record.scope().domain() == Domain::LedgerActivation {
                let next = VerifiedDeploymentLedgerRecordV3::verify(record.clone())?;
                latest.validate_successor(&next, &pending)?;
                let m = next.state.material();
                if m.phase == Phase::Prepared
                    && !transactions.insert(
                        *m.transaction
                            .ok_or(Error::TransactionBindingMismatch)?
                            .as_bytes(),
                    )
                {
                    return Err(Error::TransactionBindingMismatch);
                }
                if m.phase == Phase::Prepared
                    && !used_grants.insert(
                        *m.rollback_grant_id
                            .ok_or(Error::RollbackGrantMismatch)?
                            .as_bytes(),
                    )
                {
                    return Err(Error::RollbackGrantMismatch);
                }
                latest = next;
                pending.clear();
            } else {
                if pending.len() >= MAX_INTERVENING {
                    return Err(Error::LedgerConflict);
                }
                pending.push(record.clone());
            }
            head = record.head();
            time = record.written_at();
        }
        if head != live_head {
            return Err(Error::LedgerConflict);
        }
        Ok(Self {
            latest,
            trailing: pending,
            head,
            records: records.to_vec(),
        })
    }
    pub fn latest_ledger(&self) -> &VerifiedDeploymentLedgerRecordV3 {
        &self.latest
    }
    /// Callers must classify/verify these purposes before deciding how to resume.
    /// A trailing signature cannot be silently promoted into a ledger phase.
    pub fn trailing_evidence(&self) -> &[VerifiedDeploymentRecordEnvelopeV3] {
        &self.trailing
    }
    pub fn head(&self) -> TpmStateHeadV3 {
        self.head
    }
    /// Preparation only, never recovery/resume. Reject old IDs even when a
    /// caller presents a newly signed transaction or a currently valid grant.
    pub fn validate_new_transaction(
        &self,
        transaction: &super::DeploymentTransactionV2,
        platform: &super::PlatformLockV2,
        now_ms: u64,
        completed: Option<(
            &super::VerifiedVerificationEvidenceV3,
            &super::VerifiedCommitAttestationV3,
        )>,
    ) -> Result<(), Error> {
        let intent = transaction.intent().material();
        let ledger = self.latest.state.material();
        if &intent.target_platform != platform
            || intent.recovery_target.tag() != 1
            || now_ms < intent.not_before_unix_ms
            || now_ms >= intent.expires_at_unix_ms
            || now_ms < ledger.written_at_ms
            || self
                .records
                .last()
                .is_some_and(|r| now_ms / 1000 < r.written_at())
            || !matches!(ledger.phase, Phase::Idle | Phase::Committed)
            || ledger.effects_fenced
        {
            return Err(Error::TransactionBindingMismatch);
        }
        // A purpose tag is not proof of completed deployment. For Committed,
        // require the typed evidence already checked against actual measurements.
        // RolledBack/bridge preparation needs its own typed evidence integration.
        match (ledger.phase, completed) {
            (Phase::Idle, None) if self.trailing.is_empty() => (),
            (Phase::Committed, Some((verification, commit)))
                if commit.claims().platform() == platform =>
            {
                self.validate_normal_commit(verification, commit)?
            }
            _ => return Err(Error::TransactionBindingMismatch),
        }
        for record in &self.records {
            if record.scope().domain() != Domain::LedgerActivation {
                continue;
            }
            let state =
                DeploymentLedgerStateV3::from_canonical_bytes(record.authenticated_payload())?;
            let m = state.material();
            if m.transaction == Some(intent.transaction_id)
                || m.rollback_grant_id == Some(transaction.rollback_grant().grant_id())
            {
                return Err(Error::TransactionBindingMismatch);
            }
        }
        Ok(())
    }
    /// Compose the two typed consumers with this exact anchored history. Native
    /// measurements, release/transaction authorization and service bootstrap are
    /// still separate obligations; success is not a kernel startup capability.
    pub fn validate_normal_commit(
        &self,
        verification: &super::VerifiedVerificationEvidenceV3,
        commit: &super::VerifiedCommitAttestationV3,
    ) -> Result<(), Error> {
        if self.head != commit.record().head()
            || commit
                .claims()
                .digest(super::ClosedCommitDigestFieldV2::VerificationEvidence)
                != verification.record_digest()
        {
            return Err(Error::InvalidCommitAttestation);
        }
        let ledger_index = self
            .records
            .iter()
            .position(|r| r.head() == self.latest.record.head())
            .ok_or(Error::LedgerConflict)?;
        let verification_index = self
            .records
            .iter()
            .position(|r| r.head() == verification.record().head())
            .ok_or(Error::LedgerConflict)?;
        let installed_index = self.records[..verification_index]
            .iter()
            .rposition(|r| r.scope().domain() == Domain::LedgerActivation)
            .ok_or(Error::LedgerConflict)?;
        let installed =
            VerifiedDeploymentLedgerRecordV3::verify(self.records[installed_index].clone())?;
        verification.validate_installed_ledger(
            &installed,
            &self.records[installed_index + 1..verification_index],
        )?;
        if ledger_index >= self.records.len() - 1 || verification_index >= ledger_index {
            return Err(Error::LedgerConflict);
        }
        commit.validate_committed_ledger(
            &self.latest,
            &self.records[ledger_index + 1..self.records.len() - 1],
        )
    }
}
impl VerifiedDeploymentLedgerRecordV3 {
    pub fn verify(record: VerifiedDeploymentRecordEnvelopeV3) -> Result<Self, Error> {
        let state = DeploymentLedgerStateV3::from_canonical_bytes(record.authenticated_payload())?;
        let m = state.material();
        if record.scope() != state.scope()
            || record.installation_id() != *m.installation.as_bytes()
            || record.installation_epoch() != m.epoch
            || record
                .written_at()
                .checked_mul(1000)
                .and_then(|v| v.checked_add(999))
                .map_or(true, |end| m.written_at_ms > end)
        {
            return Err(Error::InstallationTupleMismatch);
        }
        Ok(Self { record, state })
    }
    pub fn state(&self) -> &DeploymentLedgerStateV3 {
        &self.state
    }
    pub fn record(&self) -> &VerifiedDeploymentRecordEnvelopeV3 {
        &self.record
    }
    pub fn validate_fresh_genesis(&self) -> Result<(), Error> {
        self.state.validate_fresh_genesis()?;
        if self.record.previous_head() != TpmStateHeadV3::GENESIS {
            return Err(Error::LedgerConflict);
        }
        Ok(())
    }
    /// Auxiliary evidence may occupy the NV journal between ledger updates.
    /// Require the entire contiguous intervening chain; sequence comparison alone
    /// is not ancestry. These records still need purpose-specific consumers.
    pub fn validate_successor(
        &self,
        next: &Self,
        intervening: &[VerifiedDeploymentRecordEnvelopeV3],
    ) -> Result<(), Error> {
        if intervening.len() > MAX_INTERVENING {
            return Err(Error::LedgerConflict);
        }
        let mut head = self.record.head();
        let mut time = self.record.written_at();
        for record in intervening.iter().chain(std::iter::once(&next.record)) {
            if record.previous_head() != head
                || record.enrollment_digest() != self.record.enrollment_digest()
                || record.written_at() < time
            {
                return Err(Error::LedgerConflict);
            }
            head = record.head();
            time = record.written_at();
        }
        if intervening
            .iter()
            .any(|r| r.scope().domain() == Domain::LedgerActivation)
        {
            return Err(Error::LedgerConflict);
        }
        self.state.validate_successor(&next.state)
    }
}

fn validate_shape(m: &DeploymentLedgerMaterialV3) -> Result<(), Error> {
    if m.transaction.is_some() != m.rollback_grant_id.is_some()
        || m.rollback_grant_id
            .is_some_and(|id| id.as_bytes() == &[0; 32])
    {
        return Err(Error::RollbackGrantMismatch);
    }
    if m.written_at_ms == 0
        || [
            m.installation,
            m.active_manifest,
            m.identity_profile,
            m.bootstrap_tcb_lock,
        ]
        .iter()
        .any(|d| d.as_bytes() == &[0; 32])
        || (m.generation == 1) != (m.previous_payload.as_bytes() == &[0; 32])
        || (m.generation == 1 && m.phase != Phase::Idle)
    {
        return Err(Error::InvalidLedgerRecord);
    }
    // Bridge/epoch migration needs its own continuity proof; never reinterpret
    // old V2 bridge state as a fresh V3 installation.
    if matches!(
        m.phase,
        Phase::BootstrapBridge
            | Phase::BridgeRestorePrepared
            | Phase::BridgeRestoreInstalled
            | Phase::BridgeRestoreVerified
    ) || matches!(m.active_activation, ActiveActivationV2::BootstrapBridge(_))
    {
        return Err(Error::InvalidLedgerRecord);
    }
    m.active_activation.canonical_bytes()?;
    let rollback = matches!(
        m.phase,
        Phase::RollbackPrepared
            | Phase::RollbackInstalled
            | Phase::RollbackVerified
            | Phase::RolledBack
    );
    if (m.phase != Phase::FailedSafe && rollback != m.rollback_origin.is_some())
        || (m.phase == Phase::RolledBack
            && !matches!(&m.active_activation,
            ActiveActivationV2::ConsumedRollback { failed_transaction_id, rollback_grant_id }
                if Some(*failed_transaction_id) == m.transaction && Some(*rollback_grant_id) == m.rollback_grant_id))
        || (m.phase == Phase::Committed && m.active_activation != ActiveActivationV2::Normal)
    {
        return Err(Error::InvalidLedgerRecord);
    }
    Ok(())
}
fn digest(bytes: &[u8]) -> Digest32V2 {
    let mut h = Sha256::new();
    h.update(b"savana.deployment-ledger.v3.payload\0");
    h.update(bytes);
    Digest32V2::new(h.finalize().into())
}
fn option(b: &mut Vec<u8>, value: Option<&[u8; 32]>) {
    b.push(u8::from(value.is_some()));
    if let Some(value) = value {
        b.extend_from_slice(value);
    }
}
fn encode(m: &DeploymentLedgerMaterialV3) -> Result<Vec<u8>, Error> {
    let mut b = MAGIC.to_vec();
    b.extend_from_slice(m.installation.as_bytes());
    for n in [m.epoch, m.generation, m.written_at_ms] {
        b.extend_from_slice(&n.to_be_bytes());
    }
    b.extend_from_slice(&(m.phase as u16).to_be_bytes());
    option(&mut b, m.transaction.as_ref().map(Nonce32V2::as_bytes));
    b.push(u8::from(m.effects_fenced));
    b.extend_from_slice(&m.fence_epoch.to_be_bytes());
    b.extend_from_slice(m.active_manifest.as_bytes());
    let a = m.active_activation.canonical_bytes()?;
    b.extend_from_slice(&(a.len() as u32).to_be_bytes());
    b.extend_from_slice(&a);
    b.extend_from_slice(m.identity_profile.as_bytes());
    b.extend_from_slice(m.bootstrap_tcb_lock.as_bytes());
    for domain in ClosedSecurityDomainV2::ALL {
        let entry = m.highest_ever.entry(domain);
        b.extend_from_slice(&domain.tag().to_be_bytes());
        b.extend_from_slice(&entry.sequence().to_be_bytes());
        b.extend_from_slice(entry.content_digest().as_bytes());
        b.extend_from_slice(&entry.key_epoch().to_be_bytes());
    }
    b.extend_from_slice(&(m.grant as u16).to_be_bytes());
    option(
        &mut b,
        m.rollback_grant_id.as_ref().map(Digest32V2::as_bytes),
    );
    b.push(m.rollback_origin.map_or(0, |v| v as u8));
    option(
        &mut b,
        m.transaction_head.as_ref().map(Digest32V2::as_bytes),
    );
    b.extend_from_slice(m.previous_payload.as_bytes());
    if b.len() > MAX_BYTES {
        return Err(Error::InvalidLedgerRecord);
    }
    Ok(b)
}
struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if n > self.0.len() {
            return Err(Error::InvalidLedgerRecord);
        }
        let (v, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(v)
    }
    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.take(N)?
            .try_into()
            .map_err(|_| Error::InvalidLedgerRecord)
    }
    fn byte(&mut self) -> Result<u8, Error> {
        Ok(self.fixed::<1>()?[0])
    }
    fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_be_bytes(self.fixed()?))
    }
    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_be_bytes(self.fixed()?))
    }
    fn boolean(&mut self) -> Result<bool, Error> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::InvalidLedgerRecord),
        }
    }
    fn optional(&mut self) -> Result<Option<[u8; 32]>, Error> {
        if self.boolean()? {
            Ok(Some(self.fixed()?))
        } else {
            Ok(None)
        }
    }
}
fn decode(bytes: &[u8]) -> Result<DeploymentLedgerMaterialV3, Error> {
    if bytes.len() > MAX_BYTES {
        return Err(Error::InvalidLedgerRecord);
    }
    let mut r = Reader(bytes);
    if r.take(MAGIC.len())? != MAGIC {
        return Err(Error::InvalidLedgerRecord);
    }
    let installation = Digest32V2::new(r.fixed()?);
    let epoch = r.u64()?;
    let generation = r.u64()?;
    let written_at_ms = r.u64()?;
    let phase = match r.u16()? {
        1 => Phase::Idle,
        2 => Phase::Prepared,
        3 => Phase::Armed,
        4 => Phase::Quiesced,
        5 => Phase::Installed,
        6 => Phase::Verified,
        7 => Phase::Committed,
        8 => Phase::Aborted,
        9 => Phase::RollbackPrepared,
        10 => Phase::RollbackInstalled,
        11 => Phase::RollbackVerified,
        12 => Phase::RolledBack,
        13 => Phase::FailedSafe,
        _ => return Err(Error::InvalidLedgerRecord),
    };
    let transaction = r.optional()?.map(Nonce32V2::new);
    let effects_fenced = r.boolean()?;
    let fence_epoch = r.u64()?;
    let active_manifest = Digest32V2::new(r.fixed()?);
    let size = u32::from_be_bytes(r.fixed()?) as usize;
    let active_activation = ActiveActivationV2::from_canonical_bytes(r.take(size)?)?;
    let identity_profile = Digest32V2::new(r.fixed()?);
    let bootstrap_tcb_lock = Digest32V2::new(r.fixed()?);
    let mut high = Vec::with_capacity(29);
    for domain in ClosedSecurityDomainV2::ALL {
        if r.u16()? != domain.tag() {
            return Err(Error::HighestEverMismatch);
        }
        high.push(HighWaterEntryV2::new(
            r.u64()?,
            Digest32V2::new(r.fixed()?),
            r.u64()?,
        )?);
    }
    let highest_ever =
        HighestEverV2::new(high.try_into().map_err(|_| Error::HighestEverMismatch)?)?;
    let grant = match r.u16()? {
        0 => Grant::None,
        1 => Grant::Prearmed,
        2 => Grant::Consuming,
        3 => Grant::Consumed,
        4 => Grant::Burned,
        _ => return Err(Error::RollbackGrantMismatch),
    };
    let rollback_grant_id = r.optional()?.map(Digest32V2::new);
    let rollback_origin = match r.byte()? {
        0 => None,
        1 => Some(Origin::Armed),
        2 => Some(Origin::Quiesced),
        3 => Some(Origin::Installed),
        4 => Some(Origin::Verified),
        _ => return Err(Error::RollbackOriginMismatch),
    };
    let transaction_head = r.optional()?.map(Digest32V2::new);
    let previous_payload = Digest32V2::new(r.fixed()?);
    if !r.0.is_empty() {
        return Err(Error::NonCanonicalLedgerEncoding);
    }
    Ok(DeploymentLedgerMaterialV3 {
        installation,
        epoch,
        generation,
        written_at_ms,
        phase,
        transaction,
        effects_fenced,
        fence_epoch,
        active_manifest,
        active_activation,
        identity_profile,
        bootstrap_tcb_lock,
        highest_ever,
        grant,
        rollback_grant_id,
        rollback_origin,
        transaction_head,
        previous_payload,
    })
}

#[cfg(test)]
#[path = "deployment_ledger_v3_tests.rs"]
mod tests;
