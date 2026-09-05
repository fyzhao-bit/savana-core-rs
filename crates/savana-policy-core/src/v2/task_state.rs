//! Bounded task accounting owned exclusively by the durable G7 snapshot.
//! This module has no independent persistence or dispatch path.
use super::dispatch::{
    DispatchSubjectV2, KernelDispatchJournalEntryV2, KernelDispatchJournalV2,
    KernelDispatchStateV2, VerifiedExecutorDispositionV2,
};
use super::task_authorization::hash_parts;
use super::{
    authorization_digest_v2, ControlEndorsementV2, G4Error, TaskMatchContextV2,
    VerifiedTaskAuthorizationV2, VerifiedTaskMatchV2,
};
use savana_kernel_protocol::v2::{
    decode_action_content_v2, decode_task_authorization_v2, encode_action_content_v2,
    encode_task_authorization_v2, ActionContentV2, Digest32V2, DurableTaskIdV2, Nonce32V2,
    TaskEffectV2, UnixMillisV2, MAX_TASK_AUTHORIZATION_BYTES_V2,
};

const MAX_TASKS: usize = 4096;
const MAX_HISTORY: usize = 4096;
const MAX_RECORDS: usize = 65_536;

/// Static verified inputs, not an executable capability. The owner rechecks all
/// evidence against its current state under the same guard used for the commit.
#[derive(Debug, Clone)]
pub struct TaskDispatchAuthorizationV2 {
    pub(crate) matched: VerifiedTaskMatchV2,
    pub(crate) endorsements: [ControlEndorsementV2; 7],
}
impl TaskDispatchAuthorizationV2 {
    pub fn new(matched: VerifiedTaskMatchV2, endorsements: [ControlEndorsementV2; 7]) -> Self {
        Self {
            matched,
            endorsements,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TaskAuthorizationStateV2 {
    state: TaskStateV2,
    digest: Digest32V2,
}
impl TaskAuthorizationStateV2 {
    pub fn authorization(&self) -> &VerifiedTaskAuthorizationV2 {
        self.state.current()
    }
    pub fn digest(&self) -> Digest32V2 {
        self.digest
    }
    pub fn revision(&self) -> u64 {
        self.state.revision
    }
    pub fn revoked(&self) -> bool {
        self.state.revoked
    }
    pub fn completion_epoch(&self) -> u64 {
        self.state.completion_epoch
    }
    /// (permanent attempts, currently charged magnitude), including tombstones.
    pub fn clause_consumption(&self, id: u64) -> Option<(u64, u64)> {
        self.state
            .counters
            .iter()
            .find(|c| c.id == id)
            .map(|c| (c.attempts, c.magnitude))
    }
}

/// Exact persisted association. It is returned only after the snapshot commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskDispatchBindingV2 {
    pub(crate) content: ActionContentV2,
    pub(crate) contract_digest: Digest32V2,
    pub(crate) authorization_digest: Digest32V2,
    pub(crate) transition_digest: Digest32V2,
    pub(crate) policy_identity: Digest32V2,
    pub(crate) endorsement_digests: [Digest32V2; 7],
    pub(crate) settlement: Option<(Digest32V2, Nonce32V2)>,
}
impl TaskDispatchBindingV2 {
    pub fn content(&self) -> &ActionContentV2 {
        &self.content
    }
    pub fn contract_digest(&self) -> Digest32V2 {
        self.contract_digest
    }
    pub fn authorization_digest(&self) -> Digest32V2 {
        self.authorization_digest
    }
    pub fn transition_digest(&self) -> Digest32V2 {
        self.transition_digest
    }
}

/// Only expected-key signed, exact dispatch-bound terminal verification creates
/// this proof. Executor/provider success interpretation is integrated in Task 6.
#[derive(Debug, Clone)]
pub struct VerifiedTaskOutcomeV2 {
    pub(crate) proof: VerifiedExecutorDispositionV2,
    pub(crate) authorization_digest: Digest32V2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ClauseCounter {
    id: u64,
    unit: u16,
    attempts: u64,
    magnitude: u64,
}
#[derive(Debug, Clone)]
struct Reservation {
    completion_epoch: u64,
    binding: TaskDispatchBindingV2,
    nonce: Nonce32V2,
    core: Digest32V2,
    subject: Digest32V2,
    // 0 prepared, 1 effect started, 2 verified success, 3 verified no effect,
    // 4 indeterminate. Terminal evidence is only populated by verified proof.
    status: u16,
    evidence: Option<Digest32V2>,
    refunded: bool,
}
#[derive(Debug, Clone)]
struct TaskStateV2 {
    completion_epoch: u64,
    history: Vec<VerifiedTaskAuthorizationV2>,
    revision: u64,
    revoked: bool,
    counters: Vec<ClauseCounter>,
    reservations: Vec<Reservation>,
}
impl TaskStateV2 {
    fn current(&self) -> &VerifiedTaskAuthorizationV2 {
        self.history.last().expect("validated nonempty history")
    }
    fn digest(&self) -> Result<Digest32V2, G4Error> {
        let mut e = minicbor::Encoder::new(Vec::new());
        encode_task(&mut e, self)?;
        Ok(hash_parts(
            b"SAVANA_TASK_STATE_V2_SCHEMA1\0",
            &[&e.into_writer()],
        ))
    }
    fn context(
        &self,
        generation: u64,
        now: UnixMillisV2,
    ) -> Result<TaskMatchContextV2<'_>, G4Error> {
        if self.revoked {
            return Err(G4Error::StateConflict);
        }
        Ok(TaskMatchContextV2 {
            current_authorization: Some(self.current()),
            pre_state_digest: self.digest()?,
            pre_state_revision: self.revision,
            deployment_generation: generation,
            now,
        })
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct TaskLedgerV2 {
    tasks: Vec<TaskStateV2>,
}
impl TaskLedgerV2 {
    pub(crate) fn historical(&self, digest: Digest32V2) -> Option<&VerifiedTaskAuthorizationV2> {
        self.tasks
            .iter()
            .flat_map(|s| &s.history)
            .find(|a| a.digest() == digest)
    }
    pub(crate) fn current(
        &self,
        task: DurableTaskIdV2,
    ) -> Result<Option<TaskAuthorizationStateV2>, G4Error> {
        if self
            .tasks
            .iter()
            .any(|s| s.current().material().task() == task)
        {
            self.projection(task).map(Some)
        } else {
            Ok(None)
        }
    }
    pub(crate) fn projection(
        &self,
        task: DurableTaskIdV2,
    ) -> Result<TaskAuthorizationStateV2, G4Error> {
        let state = self
            .tasks
            .iter()
            .find(|s| s.current().material().task() == task)
            .ok_or(G4Error::StateConflict)?;
        Ok(TaskAuthorizationStateV2 {
            state: state.clone(),
            digest: state.digest()?,
        })
    }
    pub(crate) fn install(
        &mut self,
        authorization: VerifiedTaskAuthorizationV2,
        installation: Digest32V2,
    ) -> Result<bool, G4Error> {
        let m = authorization.material();
        if m.installation_digest() != installation {
            return Err(G4Error::StateConflict);
        }
        // Task identity is global in this store, never namespaced by principal.
        if let Some(state) = self
            .tasks
            .iter_mut()
            .find(|s| s.current().material().task() == m.task())
        {
            let old = state.current().material();
            if old.authorization_id() != m.authorization_id()
                || old.principal() != m.principal()
                || old.installation_digest() != m.installation_digest()
            {
                return Err(G4Error::StateConflict);
            }
            if state.current() == &authorization {
                return Ok(false);
            }
            if state.revoked
                || m.revision()
                    != old
                        .revision()
                        .checked_add(1)
                        .ok_or(G4Error::StateConflict)?
                || state.history.len() >= MAX_HISTORY
            {
                return Err(G4Error::StateConflict);
            }
            if !same_skeleton(old, m) {
                state.completion_epoch = state
                    .completion_epoch
                    .checked_add(1)
                    .ok_or(G4Error::StateConflict)?;
            }
            for c in m.clauses() {
                if let Some(charged) = state.counters.iter_mut().find(|v| v.id == c.clause_id()) {
                    if charged.attempts > c.maximum_attempts()
                        || charged.magnitude > c.total_magnitude_budget()
                        || (charged.attempts > 0
                            && charged.unit != c.alternatives()[0].magnitude_unit() as u16)
                    {
                        return Err(G4Error::StateConflict);
                    }
                    charged.unit = c.alternatives()[0].magnitude_unit() as u16;
                } else {
                    if state.counters.len() >= MAX_HISTORY {
                        return Err(G4Error::StateConflict);
                    }
                    state.counters.push(ClauseCounter {
                        id: c.clause_id(),
                        unit: c.alternatives()[0].magnitude_unit() as u16,
                        attempts: 0,
                        magnitude: 0,
                    });
                }
            }
            state.counters.sort_by_key(|c| c.id);
            state.revision = state
                .revision
                .checked_add(1)
                .ok_or(G4Error::StateConflict)?;
            state.history.push(authorization);
        } else {
            if self.tasks.len() >= MAX_TASKS
                || self
                    .tasks
                    .iter()
                    .any(|s| s.current().material().authorization_id() == m.authorization_id())
            {
                return Err(G4Error::StateConflict);
            }
            let counters = m
                .clauses()
                .iter()
                .map(|c| ClauseCounter {
                    id: c.clause_id(),
                    unit: c.alternatives()[0].magnitude_unit() as u16,
                    attempts: 0,
                    magnitude: 0,
                })
                .collect();
            self.tasks.push(TaskStateV2 {
                history: vec![authorization],
                revision: 1,
                completion_epoch: 1,
                revoked: false,
                counters,
                reservations: vec![],
            });
            self.tasks
                .sort_by_key(|s| *s.current().material().task().as_bytes());
        }
        Ok(true)
    }
    pub(crate) fn revoke(&mut self, task: DurableTaskIdV2) -> Result<bool, G4Error> {
        let state = self
            .tasks
            .iter_mut()
            .find(|s| s.current().material().task() == task)
            .ok_or(G4Error::StateConflict)?;
        if state.revoked {
            return Ok(false);
        }
        state.revoked = true;
        state.revision = state
            .revision
            .checked_add(1)
            .ok_or(G4Error::StateConflict)?;
        Ok(true)
    }
    pub(crate) fn binding(&self, nonce: Nonce32V2) -> Option<&TaskDispatchBindingV2> {
        self.tasks
            .iter()
            .flat_map(|s| &s.reservations)
            .find(|r| r.nonce == nonce)
            .map(|r| &r.binding)
    }
    pub(crate) fn prepare(
        &mut self,
        request: &TaskDispatchAuthorizationV2,
        entry: &mut KernelDispatchJournalEntryV2,
        installation: Digest32V2,
        policy: Digest32V2,
        now: UnixMillisV2,
        replay: bool,
    ) -> Result<(), G4Error> {
        let m = &request.matched;
        let contract = m.authorization().material();
        // This entry is still inside the owner's private cloned snapshot. Its
        // final core is bound only after acyclic authorization derivation below,
        // before either snapshot or preparation can escape the transaction.
        let core = entry.core.clone();
        if installation != core.installation_id
            || contract.installation_digest() != core.installation_id
            || contract.task() != core.durable_task_id
            || contract.manifest_digest() != core.active_state_manifest_digest
            || m.deployment_generation() != core.deployment_generation
            || now.get() >= core.expires_at.get()
        {
            return Err(G4Error::StateConflict);
        }
        match &core.subject {
            DispatchSubjectV2::ToolExecution { binding, .. } => {
                if m.content().action().tool_descriptor_digest() != binding.tool_descriptor_digest()
                    || m.content().plan_revision_digest().as_bytes()
                        != binding.plan_revision_digest().as_bytes()
                    || m.content().action().effect() == TaskEffectV2::FinalRelease
                {
                    return Err(G4Error::StateConflict);
                }
            }
            DispatchSubjectV2::FinalRelease { .. } => {
                if m.content().action().effect() != TaskEffectV2::FinalRelease {
                    return Err(G4Error::StateConflict);
                }
                // No descriptor/plan fields exist on legacy release semantics.
                // Do not equate preseal payload hashes with action payload hashes.
            }
        }
        let settlements = match (
            request.endorsements[0].settlement_digest(),
            request.endorsements[0].settlement_nonce(),
        ) {
            (None, None) => None,
            (Some(d), Some(n)) => Some((d, Nonce32V2::new(*n.as_bytes()))),
            _ => return Err(G4Error::StateConflict),
        };
        if !replay
            && self.tasks.iter().flat_map(|s| &s.reservations).any(|r| {
                settlements.is_some_and(|(d, n)| {
                    r.binding
                        .settlement
                        .is_some_and(|(rd, rn)| d == rd || n == rn)
                })
            })
        {
            return Err(G4Error::StateConflict);
        }
        let state = self
            .tasks
            .iter_mut()
            .find(|s| s.current().material().task() == core.durable_task_id)
            .ok_or(G4Error::StateConflict)?;
        if replay {
            let r = state
                .reservations
                .iter()
                .find(|r| r.nonce == core.execution_nonce)
                .ok_or(G4Error::StateConflict)?;
            let wire = core.task_binding.ok_or(G4Error::StateConflict)?;
            if wire.content_digest() != m.content_digest()
                || wire.authorization_digest() != r.binding.authorization_digest
                || wire.presealed_payload_digest() != entry.sealed_envelope_digest
                || r.binding.content != *m.content()
                || r.binding.contract_digest != m.authorization().digest()
                || r.binding.policy_identity != policy
                || r.core != entry.core_digest
                || r.subject != core.dispatch_subject_digest
                || r.binding.endorsement_digests != request.endorsements.clone().map(|e| e.digest())
                || r.binding.settlement != settlements
            {
                return Err(G4Error::StateConflict);
            }
            // Replay uses original immutable evidence/state, not current budgets.
            let current = TaskMatchContextV2 {
                current_authorization: Some(m.authorization()),
                pre_state_digest: r.binding.content.pre_state_digest(),
                pre_state_revision: r.binding.content.pre_state_revision(),
                deployment_generation: core.deployment_generation,
                now,
            };
            let digest = authorization_digest_v2(
                m,
                &request.endorsements,
                policy,
                r.binding.transition_digest,
                &current,
            )
            .map_err(|_| G4Error::StateConflict)?;
            if digest.digest() != r.binding.authorization_digest {
                return Err(G4Error::StateConflict);
            }
            return Ok(());
        }
        let current = state.context(core.deployment_generation, now)?;
        m.recheck(&current).map_err(|_| G4Error::StateConflict)?;
        let clause = m.clause();
        for dep in clause.predecessor_clause_ids() {
            if !state.reservations.iter().any(|r| {
                r.binding.content.clause_id() == *dep
                    && r.completion_epoch == state.completion_epoch
                    && r.status == 2
                    && r.evidence.is_some()
            }) {
                return Err(G4Error::StateConflict);
            }
        }
        let charged = state
            .counters
            .iter()
            .find(|c| c.id == clause.clause_id())
            .ok_or(G4Error::StateConflict)?;
        let attempts = charged
            .attempts
            .checked_add(1)
            .ok_or(G4Error::StateConflict)?;
        let magnitude = charged
            .magnitude
            .checked_add(m.content().magnitude())
            .ok_or(G4Error::StateConflict)?;
        if attempts > clause.maximum_attempts()
            || magnitude > clause.total_magnitude_budget()
            || state.reservations.len() >= MAX_RECORDS
        {
            return Err(G4Error::StateConflict);
        }
        let revision = state
            .revision
            .checked_add(1)
            .ok_or(G4Error::StateConflict)?;
        let transition = hash_parts(
            b"SAVANA_TASK_TRANSITION_V2_SCHEMA1\0",
            &[
                current.pre_state_digest.as_bytes(),
                &state.revision.to_be_bytes(),
                m.authorization().digest().as_bytes(),
                &clause.clause_id().to_be_bytes(),
                &1u64.to_be_bytes(),
                &m.content().magnitude().to_be_bytes(),
                &revision.to_be_bytes(),
            ],
        );
        let digest =
            authorization_digest_v2(m, &request.endorsements, policy, transition, &current)
                .map_err(|_| G4Error::StateConflict)?;
        let binding = TaskDispatchBindingV2 {
            content: m.content().clone(),
            contract_digest: m.authorization().digest(),
            authorization_digest: digest.digest(),
            transition_digest: transition,
            policy_identity: policy,
            endorsement_digests: request.endorsements.clone().map(|e| e.digest()),
            settlement: settlements,
        };
        if entry.core.task_binding.is_some() {
            return Err(G4Error::StateConflict);
        }
        entry.core.task_binding = Some(
            savana_kernel_protocol::v2::DispatchTaskBindingV2::new(
                m.content_digest(),
                binding.authorization_digest,
                entry.sealed_envelope_digest,
            )
            .map_err(|_| G4Error::StateConflict)?,
        );
        entry.core_digest = super::dispatch::dispatch_core_digest(&entry.core)?;
        let charged = state
            .counters
            .iter_mut()
            .find(|c| c.id == clause.clause_id())
            .ok_or(G4Error::StateConflict)?;
        charged.attempts = attempts;
        charged.magnitude = magnitude;
        state.revision = revision;
        state.reservations.push(Reservation {
            binding,
            completion_epoch: state.completion_epoch,
            nonce: core.execution_nonce,
            core: entry.core_digest,
            subject: core.dispatch_subject_digest,
            status: 0,
            evidence: None,
            refunded: false,
        });
        Ok(())
    }
    pub(crate) fn reconcile(
        &mut self,
        proof: VerifiedExecutorDispositionV2,
        verified_terminal: bool,
    ) -> Result<(), G4Error> {
        use super::quota::AuthenticatedEffectDispositionKindV2::*;
        let Some(state) = self.tasks.iter_mut().find(|s| {
            s.reservations
                .iter()
                .any(|r| r.nonce == proof.execution_nonce)
        }) else {
            return Ok(());
        };
        let r = state
            .reservations
            .iter_mut()
            .find(|r| r.nonce == proof.execution_nonce)
            .ok_or(G4Error::StateConflict)?;
        if r.core != proof.dispatch_core_digest || r.subject != proof.dispatch_subject_digest {
            return Err(G4Error::StateConflict);
        }
        let status = match proof.disposition.kind() {
            EffectStarted => 1,
            KnownSuccess => 2,
            FailedNoEffect => 3,
            Indeterminate => 4,
        };
        if matches!(status, 2 | 3) && !verified_terminal {
            return Err(G4Error::StateConflict);
        }
        if r.status == status && r.evidence == Some(proof.evidence_digest) {
            return Ok(());
        }
        if matches!(r.status, 2 | 3 | 4) {
            return Err(G4Error::StateConflict);
        }
        if status == 3 {
            // Existing quota rules reject no-effect after effect start, retained.
            if r.status != 0 {
                return Err(G4Error::StateConflict);
            }
            let contract = state
                .history
                .iter()
                .find(|a| a.digest() == r.binding.contract_digest)
                .ok_or(G4Error::StateConflict)?;
            let clause = contract
                .material()
                .clauses()
                .iter()
                .find(|c| c.clause_id() == r.binding.content.clause_id())
                .ok_or(G4Error::StateConflict)?;
            if clause.retry_after_proven_no_effect() && !r.refunded {
                let c = state
                    .counters
                    .iter_mut()
                    .find(|c| c.id == clause.clause_id())
                    .ok_or(G4Error::StateConflict)?;
                c.magnitude = c
                    .magnitude
                    .checked_sub(r.binding.content.magnitude())
                    .ok_or(G4Error::StateConflict)?;
                r.refunded = true;
            }
        }
        r.status = status;
        r.evidence = Some(proof.evidence_digest);
        state.revision = state
            .revision
            .checked_add(1)
            .ok_or(G4Error::StateConflict)?;
        Ok(())
    }
    pub(crate) fn validate(&self, dispatch: &KernelDispatchJournalV2) -> Result<(), G4Error> {
        let mut ids = std::collections::HashSet::new();
        let mut tasks = std::collections::HashSet::new();
        let mut nonces = std::collections::HashSet::new();
        let mut settlement_nonces = std::collections::HashSet::new();
        let mut settlement_digests = std::collections::HashSet::new();
        for s in &self.tasks {
            if s.revision == 0
                || !ids.insert(*s.current().material().authorization_id().as_bytes())
                || !tasks.insert(*s.current().material().task().as_bytes())
            {
                return Err(G4Error::DurableStateCorrupt);
            }
            let mut epoch = 1u64;
            for pair in s.history.windows(2) {
                let (a, b) = (pair[0].material(), pair[1].material());
                if a.revision().checked_add(1) != Some(b.revision())
                    || a.authorization_id() != b.authorization_id()
                    || a.principal() != b.principal()
                    || a.task() != b.task()
                    || a.installation_digest() != b.installation_digest()
                {
                    return Err(G4Error::DurableStateCorrupt);
                }
                if !same_skeleton(a, b) {
                    epoch = epoch.checked_add(1).ok_or(G4Error::DurableStateCorrupt)?;
                }
            }
            if s.completion_epoch != epoch {
                return Err(G4Error::DurableStateCorrupt);
            }
            for c in &s.counters {
                let mut attempts = 0u64;
                let mut magnitude = 0u64;
                for r in s
                    .reservations
                    .iter()
                    .filter(|r| r.binding.content.clause_id() == c.id)
                {
                    if c.unit != r.binding.content.action().magnitude_unit() as u16 {
                        return Err(G4Error::DurableStateCorrupt);
                    }
                    attempts = attempts
                        .checked_add(1)
                        .ok_or(G4Error::DurableStateCorrupt)?;
                    if !r.refunded {
                        magnitude = magnitude
                            .checked_add(r.binding.content.magnitude())
                            .ok_or(G4Error::DurableStateCorrupt)?;
                    }
                }
                if attempts != c.attempts || magnitude != c.magnitude {
                    return Err(G4Error::DurableStateCorrupt);
                }
                if let Some(clause) = s
                    .current()
                    .material()
                    .clauses()
                    .iter()
                    .find(|cl| cl.clause_id() == c.id)
                {
                    if c.attempts > clause.maximum_attempts()
                        || c.magnitude > clause.total_magnitude_budget()
                    {
                        return Err(G4Error::DurableStateCorrupt);
                    }
                }
            }
            for r in &s.reservations {
                let mut expected_epoch = 1u64;
                for pair in s.history.windows(2) {
                    if pair[1].material().revision() > r.binding.content.authorization_revision() {
                        break;
                    }
                    if !same_skeleton(pair[0].material(), pair[1].material()) {
                        expected_epoch += 1;
                    }
                }
                if r.completion_epoch != expected_epoch {
                    return Err(G4Error::DurableStateCorrupt);
                }
                let a = s
                    .history
                    .iter()
                    .find(|a| a.digest() == r.binding.contract_digest)
                    .ok_or(G4Error::DurableStateCorrupt)?;
                let clause = a
                    .material()
                    .clauses()
                    .iter()
                    .find(|c| c.clause_id() == r.binding.content.clause_id())
                    .ok_or(G4Error::DurableStateCorrupt)?;
                if !nonces.insert(*r.nonce.as_bytes())
                    || !s.counters.iter().any(|c| c.id == clause.clause_id())
                    || r.binding.content.authorization_id() != a.material().authorization_id()
                    || r.binding.content.authorization_revision() != a.material().revision()
                    || clause
                        .alternatives()
                        .get(r.binding.content.alternative_index() as usize)
                        != Some(r.binding.content.action())
                    || r.binding.content.magnitude() > clause.maximum_single_magnitude()
                    || (r.refunded && (r.status != 3 || !clause.retry_after_proven_no_effect()))
                {
                    return Err(G4Error::DurableStateCorrupt);
                }
                if let Some((d, n)) = r.binding.settlement {
                    if !settlement_digests.insert(*d.as_bytes())
                        || !settlement_nonces.insert(*n.as_bytes())
                    {
                        return Err(G4Error::DurableStateCorrupt);
                    }
                }
                let entry = dispatch
                    .entries
                    .iter()
                    .find(|e| e.core.execution_nonce == r.nonce)
                    .ok_or(G4Error::DurableStateCorrupt)?;
                let expected = match entry.state {
                    KernelDispatchStateV2::Prepared => 0,
                    KernelDispatchStateV2::Dispatching | KernelDispatchStateV2::EffectStarted => 1,
                    KernelDispatchStateV2::CompletionCommitted => 2,
                    KernelDispatchStateV2::FailedNoEffect => 3,
                    KernelDispatchStateV2::Indeterminate => 4,
                };
                if let Some(wire) = entry.core.task_binding {
                    if wire.content_digest()
                        != savana_kernel_protocol::v2::action_content_digest_v2(&r.binding.content)
                            .map_err(corrupt)?
                        || wire.authorization_digest() != r.binding.authorization_digest
                        || wire.presealed_payload_digest() != entry.sealed_envelope_digest
                    {
                        return Err(G4Error::DurableStateCorrupt);
                    }
                }
                if expected != r.status
                    || r.evidence != entry.effect_evidence_digest
                    || r.core != entry.core_digest
                    || r.subject != entry.core.dispatch_subject_digest
                    || a.material().task() != entry.core.durable_task_id
                    || a.material().installation_digest() != entry.core.installation_id
                    || a.material().manifest_digest() != entry.core.active_state_manifest_digest
                {
                    return Err(G4Error::DurableStateCorrupt);
                }
            }
        }
        // The reverse association is mandatory too: a schema-3 dispatch cannot
        // survive recovery after its task reservation/accounting was removed.
        if dispatch.entries.iter().any(|entry| {
            entry.core.task_binding.is_some()
                && !nonces.contains(entry.core.execution_nonce.as_bytes())
        }) {
            return Err(G4Error::DurableStateCorrupt);
        }
        Ok(())
    }
    pub(crate) fn encode(&self) -> Result<Vec<u8>, G4Error> {
        let mut e = minicbor::Encoder::new(Vec::new());
        e.array(self.tasks.len() as u64).map_err(corrupt)?;
        for task in &self.tasks {
            encode_task(&mut e, task)?;
        }
        Ok(e.into_writer())
    }
    /// Called only after snapshot AEAD verification; not a public authority constructor.
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, G4Error> {
        let mut d = minicbor::Decoder::new(bytes);
        let mut tasks = Vec::new();
        for _ in 0..array(&mut d, MAX_TASKS)? {
            exact(&mut d, 6)?;
            let revision = d.u64().map_err(corrupt)?;
            let completion_epoch = d.u64().map_err(corrupt)?;
            let revoked = d.bool().map_err(corrupt)?;
            let mut history = Vec::new();
            for _ in 0..array(&mut d, MAX_HISTORY)? {
                let raw = d.bytes().map_err(corrupt)?;
                if raw.len() > MAX_TASK_AUTHORIZATION_BYTES_V2 {
                    return Err(G4Error::DurableStateCorrupt);
                }
                let material = decode_task_authorization_v2(raw).map_err(corrupt)?;
                history.push(VerifiedTaskAuthorizationV2::from_authenticated_snapshot(
                    material,
                )?);
            }
            if history.is_empty() {
                return Err(G4Error::DurableStateCorrupt);
            }
            let mut counters = Vec::new();
            for _ in 0..array(&mut d, MAX_HISTORY)? {
                exact(&mut d, 4)?;
                let c = ClauseCounter {
                    id: d.u64().map_err(corrupt)?,
                    unit: d.u16().map_err(corrupt)?,
                    attempts: d.u64().map_err(corrupt)?,
                    magnitude: d.u64().map_err(corrupt)?,
                };
                if c.id == 0
                    || !matches!(c.unit, 1 | 2)
                    || counters
                        .last()
                        .is_some_and(|last: &ClauseCounter| last.id >= c.id)
                {
                    return Err(G4Error::DurableStateCorrupt);
                }
                counters.push(c);
            }
            let mut reservations = Vec::new();
            for _ in 0..array(&mut d, MAX_RECORDS)? {
                exact(&mut d, 14)?;
                let reservation_epoch = d.u64().map_err(corrupt)?;
                let content =
                    decode_action_content_v2(d.bytes().map_err(corrupt)?).map_err(corrupt)?;
                let contract_digest = digest(&mut d)?;
                let authorization_digest = digest(&mut d)?;
                let transition_digest = digest(&mut d)?;
                let policy_identity = digest(&mut d)?;
                exact(&mut d, 7)?;
                let mut endorsement_digests = [Digest32V2::new([0; 32]); 7];
                for e in &mut endorsement_digests {
                    *e = digest(&mut d)?;
                }
                let settlement = match array(&mut d, 2)? {
                    0 => None,
                    2 => Some((digest(&mut d)?, Nonce32V2::new(*digest(&mut d)?.as_bytes()))),
                    _ => return Err(G4Error::DurableStateCorrupt),
                };
                let nonce = Nonce32V2::new(*digest(&mut d)?.as_bytes());
                let core = digest(&mut d)?;
                let subject = digest(&mut d)?;
                let status = d.u16().map_err(corrupt)?;
                let evidence = match array(&mut d, 1)? {
                    0 => None,
                    _ => Some(digest(&mut d)?),
                };
                let refunded = d.bool().map_err(corrupt)?;
                if status > 4 || (status == 0) != evidence.is_none() {
                    return Err(G4Error::DurableStateCorrupt);
                }
                reservations.push(Reservation {
                    completion_epoch: reservation_epoch,
                    binding: TaskDispatchBindingV2 {
                        content,
                        contract_digest,
                        authorization_digest,
                        transition_digest,
                        policy_identity,
                        endorsement_digests,
                        settlement,
                    },
                    nonce,
                    core,
                    subject,
                    status,
                    evidence,
                    refunded,
                });
            }
            if tasks.last().is_some_and(|s: &TaskStateV2| {
                s.current().material().task().as_bytes()
                    >= history.last().unwrap().material().task().as_bytes()
            }) {
                return Err(G4Error::DurableStateCorrupt);
            }
            tasks.push(TaskStateV2 {
                history,
                revision,
                completion_epoch,
                revoked,
                counters,
                reservations,
            });
        }
        let result = Self { tasks };
        if d.position() != bytes.len() || result.encode()? != bytes {
            return Err(G4Error::DurableStateCorrupt);
        }
        Ok(result)
    }
}
fn corrupt<E>(_: E) -> G4Error {
    G4Error::DurableStateCorrupt
}
fn same_skeleton(
    a: &savana_kernel_protocol::v2::TaskAuthorizationV2,
    b: &savana_kernel_protocol::v2::TaskAuthorizationV2,
) -> bool {
    a.clauses().len() == b.clauses().len()
        && a.clauses().iter().zip(b.clauses()).all(|(a, b)| {
            a.clause_id() == b.clause_id()
                && a.alternatives() == b.alternatives()
                && a.predecessor_clause_ids() == b.predecessor_clause_ids()
        })
}
fn array(d: &mut minicbor::Decoder<'_>, max: usize) -> Result<usize, G4Error> {
    let n = d
        .array()
        .map_err(corrupt)?
        .ok_or(G4Error::DurableStateCorrupt)?;
    if n > max as u64 {
        return Err(G4Error::DurableStateCorrupt);
    }
    Ok(n as usize)
}
fn exact(d: &mut minicbor::Decoder<'_>, n: usize) -> Result<(), G4Error> {
    if array(d, n)? != n {
        Err(G4Error::DurableStateCorrupt)
    } else {
        Ok(())
    }
}
fn digest(d: &mut minicbor::Decoder<'_>) -> Result<Digest32V2, G4Error> {
    let bytes: [u8; 32] = d.bytes().map_err(corrupt)?.try_into().map_err(corrupt)?;
    if bytes == [0; 32] {
        return Err(G4Error::DurableStateCorrupt);
    }
    Ok(Digest32V2::new(bytes))
}
fn encode_task(e: &mut minicbor::Encoder<Vec<u8>>, s: &TaskStateV2) -> Result<(), G4Error> {
    e.array(6)
        .and_then(|e| e.u64(s.revision))
        .and_then(|e| e.u64(s.completion_epoch))
        .and_then(|e| e.bool(s.revoked))
        .and_then(|e| e.array(s.history.len() as u64))
        .map_err(corrupt)?;
    for a in &s.history {
        e.bytes(&encode_task_authorization_v2(a.material()).map_err(corrupt)?)
            .map_err(corrupt)?;
    }
    e.array(s.counters.len() as u64).map_err(corrupt)?;
    for c in &s.counters {
        e.array(4)
            .and_then(|e| e.u64(c.id))
            .and_then(|e| e.u16(c.unit))
            .and_then(|e| e.u64(c.attempts))
            .and_then(|e| e.u64(c.magnitude))
            .map_err(corrupt)?;
    }
    e.array(s.reservations.len() as u64).map_err(corrupt)?;
    for r in &s.reservations {
        e.array(14)
            .and_then(|e| e.u64(r.completion_epoch))
            .and_then(|e| {
                e.bytes(&encode_action_content_v2(&r.binding.content).expect("validated content"))
            })
            .map_err(corrupt)?;
        for v in [
            r.binding.contract_digest,
            r.binding.authorization_digest,
            r.binding.transition_digest,
            r.binding.policy_identity,
        ] {
            e.bytes(v.as_bytes()).map_err(corrupt)?;
        }
        e.array(7).map_err(corrupt)?;
        for v in r.binding.endorsement_digests {
            e.bytes(v.as_bytes()).map_err(corrupt)?;
        }
        if let Some((d, n)) = r.binding.settlement {
            e.array(2)
                .and_then(|e| e.bytes(d.as_bytes()))
                .and_then(|e| e.bytes(n.as_bytes()))
                .map_err(corrupt)?;
        } else {
            e.array(0).map_err(corrupt)?;
        }
        for v in [r.nonce.as_bytes(), r.core.as_bytes(), r.subject.as_bytes()] {
            e.bytes(v).map_err(corrupt)?;
        }
        e.u16(r.status).map_err(corrupt)?;
        if let Some(d) = r.evidence {
            e.array(1)
                .and_then(|e| e.bytes(d.as_bytes()))
                .map_err(corrupt)?;
        } else {
            e.array(0).map_err(corrupt)?;
        }
        e.bool(r.refunded).map_err(corrupt)?;
    }
    Ok(())
}
