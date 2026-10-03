//! Root-bound continuation storage and optional additional G7 accounting.
//! Registration alone issues no execution/disclosure permission and extends no
//! V2 root. Existing G1–G7 checks and authenticated host admission remain required.
use super::continuation_dispatch::{self, AccountedDispatchV04, DispatchAccountingV04};
use super::dispatch::{KernelDispatchJournalEntryV2, KernelDispatchJournalV2};
use super::task_state::TaskLedgerV2;
use super::{ContinuationResourceEvidenceV04, VerifiedContinuationDispatchPolicyV04};
use super::{G4Error, VerifiedTaskAuthorizationV2};
use ed25519_dalek::{Signature, VerifyingKey};
use savana_continuation_core::ledger::{DomainLimit, Ledger, Reservation, TaskKey};
use savana_continuation_core::observation::{Observations, PinnedInput, Scope, Slot};
use savana_kernel_protocol::v2::{Digest32V2, DurableTaskIdV2, UnixMillisV2};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

const MAX_PROFILE_BYTES: usize = 128 * 1024;
const MAX_TABLE_BYTES: usize = 8 * 1024 * 1024;
const MAX_ENTRIES: usize = 32;

/// Signed by a deployment-selected host authority, not by the planner. This
/// signature authorizes bounded local bookkeeping ONLY, not new disclosure.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContinuationStorageProfileV04 {
    pub schema: u16,
    pub installation: [u8; 32],
    pub task: [u8; 32],
    pub parent_authorization: [u8; 32],
    pub not_before: u64,
    pub expires_at: u64,
    pub observer_scope: [u8; 32],
    pub renderer: [u8; 32],
    pub domains: Vec<DomainLimit>,
    pub max_executions: usize,
    pub slots: Vec<Slot>,
}

fn hash(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"SAVANA_CONTINUATION_STORAGE_PROFILE_V04\0");
    h.update((bytes.len() as u64).to_be_bytes());
    h.update(bytes);
    h.finalize().into()
}

impl ContinuationStorageProfileV04 {
    pub fn signing_digest(&self) -> Result<[u8; 32], G4Error> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| G4Error::StateConflict)?;
        if bytes.len() > MAX_PROFILE_BYTES {
            return Err(G4Error::StateConflict);
        }
        Ok(hash(&bytes))
    }
    fn validate(&self) -> Result<(), G4Error> {
        if self.schema != 1
            || self.not_before >= self.expires_at
            || [
                self.installation,
                self.task,
                self.parent_authorization,
                self.observer_scope,
                self.renderer,
            ]
            .contains(&[0; 32])
            || self.domains.len() > 8
            || self.max_executions > 256
            || self.slots.len() > 32
        {
            return Err(G4Error::StateConflict);
        }
        Ledger::new(
            self.task_key(),
            self.parent_authorization,
            self.domains.clone(),
            self.max_executions,
        )
        .map_err(|_| G4Error::StateConflict)?;
        // Dummy nonzero policy only for structural validation, not publication.
        Observations::new(self.scope([1; 32]), self.slots.clone())
            .map_err(|_| G4Error::StateConflict)?;
        Ok(())
    }
    fn task_key(&self) -> TaskKey {
        TaskKey {
            installation_lineage: self.installation,
            task_lineage: self.task,
        }
    }
    fn scope(&self, profile: [u8; 32]) -> Scope {
        Scope {
            root: self.parent_authorization,
            policy: profile,
            observer_scope: self.observer_scope,
            renderer: self.renderer,
        }
    }
    fn matches(&self, parent: &VerifiedTaskAuthorizationV2) -> bool {
        let m = parent.material();
        self.parent_authorization == *parent.digest().as_bytes()
            && self.installation == *m.installation_digest().as_bytes()
            && self.task == *m.task().as_bytes()
            && self.not_before >= m.not_before().get()
            && self.expires_at <= m.expires_at().get()
    }
}

/// Non-forgeable proof object. No Deserialize, public fields or unchecked path.
#[derive(Clone)]
pub struct VerifiedContinuationStorageV04 {
    profile: ContinuationStorageProfileV04,
    digest: [u8; 32],
}
impl VerifiedContinuationStorageV04 {
    /// The trusted host selects issuer_key and expected parent BEFORE reading
    /// candidate bytes. A caller-chosen key is not a valid trust policy.
    pub fn verify(
        bytes: &[u8],
        signature: &[u8; 64],
        issuer_key: &VerifyingKey,
        parent: &VerifiedTaskAuthorizationV2,
        now: UnixMillisV2,
    ) -> Result<Self, G4Error> {
        if bytes.len() > MAX_PROFILE_BYTES {
            return Err(G4Error::StateConflict);
        }
        let profile: ContinuationStorageProfileV04 =
            serde_json::from_slice(bytes).map_err(|_| G4Error::StateConflict)?;
        if serde_json::to_vec(&profile).map_err(|_| G4Error::StateConflict)? != bytes
            || !profile.matches(parent)
            || now.get() < profile.not_before
            || now.get() >= profile.expires_at
        {
            return Err(G4Error::StateConflict);
        }
        let digest = profile.signing_digest()?;
        issuer_key
            .verify_strict(&digest, &Signature::from_bytes(signature))
            .map_err(|_| G4Error::StateConflict)?;
        Ok(Self { profile, digest })
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    profile: ContinuationStorageProfileV04,
    revision: u64,
    ledger: Vec<u8>,
    observations: Vec<u8>,
    observation_commitment: [u8; 32],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    dispatch: Option<DispatchAccountingV04>,
}
impl Record {
    fn restore(&self) -> Result<(Ledger, Observations), G4Error> {
        let digest = self.profile.signing_digest()?;
        let ledger = Ledger::restore(
            &self.ledger,
            self.profile.task_key(),
            self.profile.parent_authorization,
            &self.profile.domains,
            self.profile.max_executions,
        )
        .map_err(|_| G4Error::DurableStateCorrupt)?;
        let observations = Observations::restore(
            &self.observations,
            &self.profile.scope(digest),
            &self.profile.slots,
            self.observation_commitment,
        )
        .map_err(|_| G4Error::DurableStateCorrupt)?;
        Ok((ledger, observations))
    }
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ContinuationTableV04 {
    records: Vec<Record>,
    #[serde(
        default,
        skip_serializing_if = "super::fused_planning::FusedPlanningTableV04::is_empty"
    )]
    pub(super) planning: super::fused_planning::FusedPlanningTableV04,
    #[serde(
        default,
        skip_serializing_if = "super::managed_admin::ManagedAdminJournalV04::is_empty"
    )]
    pub(super) admin: super::managed_admin::ManagedAdminJournalV04,
    #[serde(
        default,
        skip_serializing_if = "super::managed_resource::ManagedSourcesV04::is_empty"
    )]
    pub(super) managed: super::managed_resource::ManagedSourcesV04,
}
impl std::fmt::Debug for ContinuationTableV04 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContinuationTableV04")
            .finish_non_exhaustive()
    }
}

/// These are private host state transitions, not Agent commands or permissions.
pub enum ContinuationStorageUpdateV04 {
    RecordReservation(Reservation),
    Pin {
        slot: u16,
        logical_round: u32,
        input: PinnedInput,
    },
    Freeze {
        slot: u16,
    },
}

/// Read-only PRIVATE host view. Frozen bytes still require current release gates.
pub struct ContinuationStorageViewV04 {
    pub revision: u64,
    pub ledger: Ledger,
    pub observations: Observations,
}

impl ContinuationTableV04 {
    pub(crate) fn validate(&self, tasks: &TaskLedgerV2) -> Result<(), G4Error> {
        self.planning.validate(tasks)?;
        self.admin.validate()?;
        self.managed.validate()?;
        if self.records.len() > MAX_ENTRIES {
            return Err(G4Error::DurableStateCorrupt);
        }
        for (i, r) in self.records.iter().enumerate() {
            if r.revision == 0
                || self.records[..i]
                    .iter()
                    .any(|x| x.profile.task == r.profile.task)
            {
                return Err(G4Error::DurableStateCorrupt);
            }
            let parent = tasks
                .historical(Digest32V2::new(r.profile.parent_authorization))
                .ok_or(G4Error::DurableStateCorrupt)?;
            if !r.profile.matches(parent) {
                return Err(G4Error::DurableStateCorrupt);
            }
            r.restore()?;
        }
        for result in self.admin.results() {
            use super::managed_admin::ManagedAdminResultV04 as R;
            let valid = match result {
                R::SourceRegistered { source, namespace } => {
                    self.managed.has_source(*source, *namespace)
                }
                R::ResourceCreated { resource } => {
                    self.managed.retained_revision(*resource).is_ok()
                }
                R::ResourceUpdated { resource, revision } => self
                    .managed
                    .retained_revision(*resource)
                    .is_ok_and(|current| current >= *revision),
                R::TaskEnrolled { task, profile } => self.records.iter().any(|r| {
                    r.profile.task == *task
                        && r.profile.signing_digest().ok() == Some(*profile)
                        && r.dispatch.is_some()
                }),
                R::PlanningEnrolled { task, profile } => self.planning.has_profile(*task, *profile),
                R::PlanningRecipesApproved { task, approval } => {
                    self.planning.has_recipe_approval(*task, *approval)
                }
                R::PlanningExecutionPrepared { task, approval, .. } => {
                    self.planning.has_profile(*task, approval.profile)
                        && self
                            .planning
                            .inputs_pinned(savana_kernel_protocol::v2::DurableTaskIdV2::new(*task))
                }
            };
            if !valid {
                return Err(G4Error::DurableStateCorrupt);
            }
        }
        if self.encode()?.len() > MAX_TABLE_BYTES {
            return Err(G4Error::DurableStateCorrupt);
        }
        Ok(())
    }
    pub(crate) fn encode(&self) -> Result<Vec<u8>, G4Error> {
        serde_json::to_vec(self).map_err(|_| G4Error::DurableStateCorrupt)
    }
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, G4Error> {
        if bytes.len() > MAX_TABLE_BYTES {
            return Err(G4Error::DurableStateCorrupt);
        }
        let value: Self =
            serde_json::from_slice(bytes).map_err(|_| G4Error::DurableStateCorrupt)?;
        if value.encode()? != bytes {
            return Err(G4Error::DurableStateCorrupt);
        }
        Ok(value)
    }
    fn current(
        tasks: &TaskLedgerV2,
        profile: &ContinuationStorageProfileV04,
        now: UnixMillisV2,
    ) -> Result<(), G4Error> {
        let state = tasks
            .current(DurableTaskIdV2::new(profile.task))?
            .ok_or(G4Error::StateConflict)?;
        if state.revoked()
            || !profile.matches(state.authorization())
            || now.get() < profile.not_before
            || now.get() >= profile.expires_at
        {
            return Err(G4Error::StateConflict);
        }
        Ok(())
    }
    pub(crate) fn install(
        &mut self,
        verified: VerifiedContinuationStorageV04,
        tasks: &TaskLedgerV2,
        now: UnixMillisV2,
    ) -> Result<bool, G4Error> {
        Self::current(tasks, &verified.profile, now)?;
        if let Some(r) = self
            .records
            .iter()
            .find(|r| r.profile.task == verified.profile.task)
        {
            return if r.profile == verified.profile {
                Ok(false)
            } else {
                Err(G4Error::StateConflict)
            };
        }
        if self.records.len() >= MAX_ENTRIES {
            return Err(G4Error::StateConflict);
        }
        let p = verified.profile;
        let ledger = Ledger::new(
            p.task_key(),
            p.parent_authorization,
            p.domains.clone(),
            p.max_executions,
        )
        .map_err(|_| G4Error::StateConflict)?;
        let observations = Observations::new(p.scope(verified.digest), p.slots.clone())
            .map_err(|_| G4Error::StateConflict)?;
        self.records.push(Record {
            profile: p,
            revision: 1,
            ledger: ledger.snapshot().map_err(|_| G4Error::StateConflict)?,
            observations: observations
                .snapshot()
                .map_err(|_| G4Error::StateConflict)?,
            observation_commitment: observations.state_commitment(),
            dispatch: None,
        });
        Ok(true)
    }
    pub(crate) fn update(
        &mut self,
        task: DurableTaskIdV2,
        expected: u64,
        updates: Vec<ContinuationStorageUpdateV04>,
        tasks: &TaskLedgerV2,
        now: UnixMillisV2,
    ) -> Result<bool, G4Error> {
        if updates.is_empty() || updates.len() > 16 {
            return Err(G4Error::StateConflict);
        }
        let r = self
            .records
            .iter_mut()
            .find(|r| r.profile.task == *task.as_bytes())
            .ok_or(G4Error::StateConflict)?;
        Self::current(tasks, &r.profile, now)?;
        if expected != r.revision {
            return Err(G4Error::StateConflict);
        }
        let (mut ledger, mut observations) = r.restore()?;
        for update in updates {
            match update {
                ContinuationStorageUpdateV04::RecordReservation(request) => {
                    // Once enrolled, only the real G7 transaction may debit.
                    if r.dispatch.is_some() {
                        return Err(G4Error::StateConflict);
                    }
                    let prepared = ledger
                        .prepare(request)
                        .map_err(|_| G4Error::StateConflict)?;
                    ledger.apply(prepared).map_err(|_| G4Error::StateConflict)?;
                }
                ContinuationStorageUpdateV04::Pin {
                    slot,
                    logical_round,
                    input,
                } => observations
                    .pin(slot, logical_round, input)
                    .map_err(|_| G4Error::StateConflict)?,
                ContinuationStorageUpdateV04::Freeze { slot } => observations
                    .freeze(slot)
                    .map_err(|_| G4Error::StateConflict)?,
            }
        }
        let ledger = ledger.snapshot().map_err(|_| G4Error::StateConflict)?;
        let bytes = observations
            .snapshot()
            .map_err(|_| G4Error::StateConflict)?;
        if ledger == r.ledger && bytes == r.observations {
            return Ok(false);
        }
        let revision = r.revision.checked_add(1).ok_or(G4Error::StateConflict)?;
        r.revision = revision;
        r.ledger = ledger;
        r.observations = bytes;
        r.observation_commitment = observations.state_commitment();
        Ok(true)
    }
    pub(crate) fn view(
        &self,
        task: DurableTaskIdV2,
    ) -> Result<ContinuationStorageViewV04, G4Error> {
        let r = self
            .records
            .iter()
            .find(|r| r.profile.task == *task.as_bytes())
            .ok_or(G4Error::StateConflict)?;
        let (ledger, observations) = r.restore()?;
        Ok(ContinuationStorageViewV04 {
            revision: r.revision,
            ledger,
            observations,
        })
    }
    pub(crate) fn is_empty(&self) -> bool {
        self.records.is_empty() && self.managed.is_empty() && self.planning.is_empty()
    }

    pub(super) fn install_managed_source(
        &mut self,
        source: super::VerifiedManagedSourceV04,
        installation: Digest32V2,
        now: UnixMillisV2,
    ) -> Result<bool, G4Error> {
        let scope = source.scope();
        let mut next = self.managed.clone();
        let changed = next.install(source, installation, now)?;
        // Never reinterpret an existing external source as owner-managed.
        if changed
            && self.records.iter().any(|r| {
                r.dispatch
                    .as_ref()
                    .is_some_and(|d| (d.policy.source, d.policy.namespace) == scope)
            })
        {
            return Err(G4Error::StateConflict);
        }
        self.managed = next;
        Ok(changed)
    }

    pub(super) fn managed_fact(
        &self,
        tasks: &TaskLedgerV2,
        task: DurableTaskIdV2,
        action: &savana_kernel_protocol::v2::ActionContentV2,
        key: savana_continuation_core::ledger::ResourceKey,
        now: UnixMillisV2,
    ) -> Result<super::ContinuationResourceFactV04, G4Error> {
        let r = self
            .records
            .iter()
            .find(|r| r.profile.task == *task.as_bytes())
            .ok_or(G4Error::StateConflict)?;
        Self::current(tasks, &r.profile, now)?;
        let d = r.dispatch.as_ref().ok_or(G4Error::StateConflict)?;
        d.policy.current(now)?;
        self.managed.prepare_fact(&d.policy, action, key, now)
    }

    pub(super) fn resource_issuer(&self, task: DurableTaskIdV2) -> Result<[u8; 32], G4Error> {
        self.records
            .iter()
            .find(|r| r.profile.task == *task.as_bytes())
            .and_then(|r| r.dispatch.as_ref())
            .map(|d| d.policy.resource_issuer)
            .ok_or(G4Error::StateConflict)
    }

    pub(super) fn managed_admission_key(
        &self,
        tasks: &TaskLedgerV2,
        task: DurableTaskIdV2,
        payload: &savana_kernel_protocol::v2::TaskExecutionPayloadV2,
        now: UnixMillisV2,
    ) -> Result<savana_continuation_core::ledger::ResourceKey, G4Error> {
        let r = self
            .records
            .iter()
            .find(|r| r.profile.task == *task.as_bytes())
            .ok_or(G4Error::StateConflict)?;
        Self::current(tasks, &r.profile, now)?;
        let d = r.dispatch.as_ref().ok_or(G4Error::StateConflict)?;
        d.policy.current(now)?;
        self.managed.admission_key(&d.policy, payload, now)
    }

    pub(crate) fn has_dispatch_policies(&self) -> bool {
        self.records.iter().any(|r| r.dispatch.is_some())
    }

    pub(super) fn has_execution_snapshots(&self) -> bool {
        self.records
            .iter()
            .filter_map(|r| r.dispatch.as_ref())
            .any(|d| d.snapshot_start.is_some() || d.records.iter().any(|r| r.snapshot.is_some()))
    }

    pub(super) fn check_execution_handoff(
        &self,
        entry: &KernelDispatchJournalEntryV2,
        tasks: &TaskLedgerV2,
        bytes: &[u8],
        provenance: Digest32V2,
        now: UnixMillisV2,
    ) -> Result<(), G4Error> {
        let Some(r) = self
            .records
            .iter()
            .find(|r| r.profile.task == *entry.core.durable_task_id.as_bytes())
        else {
            return Ok(());
        };
        let Some(d) = &r.dispatch else {
            return Ok(());
        };
        let a = d
            .records
            .iter()
            .find(|a| a.execution == *entry.core.execution_nonce.as_bytes())
            .ok_or(G4Error::StateConflict)?;
        if a.evidence.fact.managed_revision.is_none() {
            return Ok(());
        }
        Self::current(tasks, &r.profile, now)?;
        d.policy.current(now)?;
        let snapshot = a.snapshot.as_ref().ok_or(G4Error::StateConflict)?;
        if now.get() >= entry.core.expires_at.get()
            || entry.state != super::dispatch::KernelDispatchStateV2::Prepared
            || *provenance.as_bytes() == [0; 32]
            || savana_kernel_protocol::v2::presealed_tool_payload_digest_v2(bytes, provenance)
                != entry.sealed_envelope_digest
        {
            return Err(G4Error::StateConflict);
        }
        let payload = savana_kernel_protocol::v2::decode_task_execution_payload_v2(bytes)
            .map_err(|_| G4Error::StateConflict)?;
        let binding = tasks
            .binding(entry.core.execution_nonce)
            .ok_or(G4Error::StateConflict)?;
        if payload.content() != binding.content() {
            return Err(G4Error::StateConflict);
        }
        self.managed
            .check_execution_handoff(snapshot, &payload, now)
    }

    pub(super) fn execution_snapshot(
        &self,
        task: DurableTaskIdV2,
        execution: savana_kernel_protocol::v2::Nonce32V2,
    ) -> Result<super::ManagedExecutionSnapshotV04, G4Error> {
        let d = self
            .records
            .iter()
            .find(|r| r.profile.task == *task.as_bytes())
            .and_then(|r| r.dispatch.as_ref())
            .ok_or(G4Error::StateConflict)?;
        let a = d
            .records
            .iter()
            .find(|r| r.execution == *execution.as_bytes())
            .ok_or(G4Error::StateConflict)?;
        // Private audit access may outlive source deletion or task revocation.
        // It does not admit an effect. In particular, never synthesize a missing pin.
        a.snapshot
            .as_ref()
            .map(|p| p.private_view())
            .ok_or(G4Error::StateConflict)
    }

    pub(crate) fn dispatch_enabled(&self, task: DurableTaskIdV2) -> bool {
        self.records
            .iter()
            .any(|r| r.profile.task == *task.as_bytes() && r.dispatch.is_some())
    }

    pub(crate) fn install_dispatch(
        &mut self,
        verified: VerifiedContinuationDispatchPolicyV04,
        tasks: &TaskLedgerV2,
        journal: &KernelDispatchJournalV2,
        now: UnixMillisV2,
    ) -> Result<bool, G4Error> {
        let p = verified.policy;
        let r = self
            .records
            .iter_mut()
            .find(|r| r.profile.task == p.task)
            .ok_or(G4Error::StateConflict)?;
        Self::current(tasks, &r.profile, now)?;
        p.validate_profile(&r.profile)?;
        self.managed.policy_matches(&p, r.profile.installation)?;
        p.current(now)?;
        if let Some(old) = &r.dispatch {
            return if old.policy == p {
                Ok(false)
            } else {
                Err(G4Error::StateConflict)
            };
        }
        // No silent migration of past effects into a fresh stable ledger.
        if r.restore()?.0.revision() != 0
            || journal
                .entries
                .iter()
                .any(|e| *e.core.durable_task_id.as_bytes() == p.task)
        {
            return Err(G4Error::StateConflict);
        }
        r.revision = r.revision.checked_add(1).ok_or(G4Error::StateConflict)?;
        r.dispatch = Some(DispatchAccountingV04 {
            policy: p,
            records: vec![],
            snapshot_start: None,
        });
        Ok(true)
    }

    pub(crate) fn prepare_dispatch(
        &mut self,
        entry: &KernelDispatchJournalEntryV2,
        tasks: &TaskLedgerV2,
        evidence: Option<&ContinuationResourceEvidenceV04>,
        now: UnixMillisV2,
        replay: bool,
    ) -> Result<(), G4Error> {
        let r = self
            .records
            .iter_mut()
            .find(|r| r.profile.task == *entry.core.durable_task_id.as_bytes());
        let r = match r {
            Some(r) if r.dispatch.is_some() => r,
            _ => {
                return if evidence.is_none() {
                    Ok(())
                } else {
                    Err(G4Error::StateConflict)
                }
            }
        };
        Self::current(tasks, &r.profile, now)?;
        let (mut ledger, _) = r.restore()?;
        let d = r.dispatch.as_mut().ok_or(G4Error::StateConflict)?;
        d.policy.current(now)?;
        let binding = tasks
            .binding(entry.core.execution_nonce)
            .ok_or(G4Error::StateConflict)?;
        if *binding.contract_digest().as_bytes() != r.profile.parent_authorization {
            return Err(G4Error::StateConflict);
        }
        if replay {
            let original = d
                .records
                .iter()
                .find(|x| x.execution == *entry.core.execution_nonce.as_bytes())
                .ok_or(G4Error::StateConflict)?;
            if evidence.is_some_and(|e| e != &original.evidence) {
                return Err(G4Error::StateConflict);
            }
            self.managed.check_fact(
                &d.policy,
                &original.evidence.fact,
                binding.content(),
                UnixMillisV2::new(original.admitted_at),
                true,
            )?;
            let expected = continuation_dispatch::reservation(
                &d.policy,
                &original.evidence,
                entry,
                binding,
                UnixMillisV2::new(original.admitted_at),
            )?;
            if ledger.reservation(&original.execution) != Some(&expected) {
                return Err(G4Error::StateConflict);
            }
            return Ok(());
        }
        let evidence = evidence.ok_or(G4Error::StateConflict)?;
        self.managed
            .check_fact(&d.policy, &evidence.fact, binding.content(), now, false)?;
        let reservation =
            continuation_dispatch::reservation(&d.policy, evidence, entry, binding, now)?;
        if ledger.reservation(&reservation.execution).is_some() {
            return Err(G4Error::StateConflict);
        }
        let snapshot = self
            .managed
            .freeze_execution(&d.policy, &reservation, &evidence.fact)?;
        if snapshot.is_some() && d.snapshot_start.is_none() {
            d.snapshot_start = Some(d.records.len());
        }
        let update = ledger
            .prepare(reservation)
            .map_err(|_| G4Error::StateConflict)?;
        ledger.apply(update).map_err(|_| G4Error::StateConflict)?;
        d.records.push(AccountedDispatchV04 {
            execution: *entry.core.execution_nonce.as_bytes(),
            admitted_at: now.get(),
            evidence: evidence.clone(),
            snapshot,
        });
        r.ledger = ledger.snapshot().map_err(|_| G4Error::StateConflict)?;
        r.revision = r.revision.checked_add(1).ok_or(G4Error::StateConflict)?;
        Ok(())
    }

    /// Revalidate the one-to-one persisted relation, not only counter totals.
    pub(crate) fn validate_dispatch(
        &self,
        tasks: &TaskLedgerV2,
        journal: &KernelDispatchJournalV2,
    ) -> Result<(), G4Error> {
        for r in &self.records {
            let Some(d) = &r.dispatch else { continue };
            self.managed
                .policy_matches(&d.policy, r.profile.installation)
                .map_err(|_| G4Error::DurableStateCorrupt)?;
            d.policy
                .validate_profile(&r.profile)
                .map_err(|_| G4Error::DurableStateCorrupt)?;
            let (ledger, _) = r.restore()?;
            if d.snapshot_start
                .is_some_and(|start| start >= d.records.len())
            {
                return Err(G4Error::DurableStateCorrupt);
            }
            if d.records.len() > r.profile.max_executions
                || ledger.revision() != d.records.len() as u64
                || journal
                    .entries
                    .iter()
                    .filter(|e| *e.core.durable_task_id.as_bytes() == r.profile.task)
                    .count()
                    != d.records.len()
            {
                return Err(G4Error::DurableStateCorrupt);
            }
            for (i, a) in d.records.iter().enumerate() {
                if a.snapshot.is_some() != d.snapshot_start.is_some_and(|start| i >= start) {
                    return Err(G4Error::DurableStateCorrupt);
                }
                if d.records[..i].iter().any(|b| b.execution == a.execution) {
                    return Err(G4Error::DurableStateCorrupt);
                }
                let entry = journal
                    .entries
                    .iter()
                    .find(|e| *e.core.execution_nonce.as_bytes() == a.execution)
                    .ok_or(G4Error::DurableStateCorrupt)?;
                let binding = tasks
                    .binding(entry.core.execution_nonce)
                    .ok_or(G4Error::DurableStateCorrupt)?;
                if *binding.contract_digest().as_bytes() != r.profile.parent_authorization {
                    return Err(G4Error::DurableStateCorrupt);
                }
                self.managed
                    .check_fact(
                        &d.policy,
                        &a.evidence.fact,
                        binding.content(),
                        UnixMillisV2::new(a.admitted_at),
                        true,
                    )
                    .map_err(|_| G4Error::DurableStateCorrupt)?;
                let expected = continuation_dispatch::reservation(
                    &d.policy,
                    &a.evidence,
                    entry,
                    binding,
                    UnixMillisV2::new(a.admitted_at),
                )
                .map_err(|_| G4Error::DurableStateCorrupt)?;
                if ledger.reservation(&a.execution) != Some(&expected) {
                    return Err(G4Error::DurableStateCorrupt);
                }
                if let Some(snapshot) = &a.snapshot {
                    self.managed
                        .validate_execution_snapshot(
                            &d.policy,
                            &expected,
                            &a.evidence.fact,
                            snapshot,
                        )
                        .map_err(|_| G4Error::DurableStateCorrupt)?;
                }
            }
        }
        Ok(())
    }
}
