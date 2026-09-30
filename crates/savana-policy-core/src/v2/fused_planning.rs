//! Private fused-planning owner integration. No Agent RPC or egress permission.
use super::task_state::TaskLedgerV2;
use super::{G4Error, VerifiedTaskAuthorizationV2};
use ed25519_dalek::{Signature, VerifyingKey};
use savana_continuation_core::planning::{CompiledPlan, ModelView, PlanningState, Policy, Role};
use savana_kernel_protocol::v2::{Digest32V2, DurableTaskIdV2, UnixMillisV2};
use serde::{Deserialize, Serialize};

const MAX_PROFILE: usize = 256 * 1024;
const MAX_TASKS: usize = 32;
fn is_false(value: &bool) -> bool {
    !*value
}
fn is_zero(value: &u16) -> bool {
    *value == 0
}

/// Public, signed transmission windows. Missed windows are never replayed.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FusedDeliverySlotV04 {
    pub id: u16,
    pub round: u16,
    pub role: Role,
    pub opens_at: u64,
    pub closes_at: u64,
}

/// Signed bookkeeping/compiler opt-in, not a new task root or disclosure grant.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FusedPlanningProfileV04 {
    pub schema: u16,
    pub installation: [u8; 32],
    pub task: [u8; 32],
    pub not_before: u64,
    pub expires_at: u64,
    pub policy: Policy,
    /// Optional, independently signed exact local execution commitments. Empty
    /// means protocol-only: it must not permit any business effect.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub execution_bindings: Vec<FusedExecutionBindingV04>,
    /// Explicit approval of the complete fixed views and public protocol
    /// metadata in this profile. Still requires a separately signed G3 rule.
    #[serde(default, skip_serializing_if = "is_false")]
    pub release_model_views: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub delivery_schedule: Vec<FusedDeliverySlotV04>,
    /// Retain one signed terminal source for the private publication owner.
    /// This is not permission to disclose its bytes or a final-release grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub final_result_source: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub final_release: Option<FusedFinalReleaseV04>,
}

/// Explicit signed selector for a separate root clause; never a model tool.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FusedFinalReleaseV04 {
    pub clause: u64,
    pub descriptor: [u8; 32],
    pub turn: [u8; 32],
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FusedExecutionBindingV04 {
    pub operation: u16,
    pub commitment: [u8; 32],
}

/// An untrusted selector, not a capability. G7 checks current activation,
/// signed exact material, original execution identity, and dependencies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FusedOperationRefV04 {
    pub plan_revision: u64,
    pub operation: u16,
}

/// Host-private preparation of a commitment for explicit profile approval.
/// Only top-level plan/step identity is abstracted. Embedded task relations and
/// rendered display commitments remain exact: recompiling after a plan/pre-state
/// change is NOT promised to preserve this commitment. Arguments (including original value IDs), provenance, tokens, selected
/// descriptor, destination, display, retry policy, and action content remain bound.
/// This function neither signs a profile nor confers root authority.
pub fn fused_execution_commitment_v04(
    material: &super::VerifiedActionIntentMaterialV2,
    content: &savana_kernel_protocol::v2::ActionContentV2,
) -> Result<[u8; 32], G4Error> {
    let mut stable = material.clone();
    stable.binding.plan_revision_digest =
        savana_kernel_protocol::v2::PlanRevisionDigestV2::new([1; 32]);
    stable.binding.internal_step_id = savana_kernel_protocol::v2::InternalStepIdV2::new([1; 32]);
    let material = super::intent::action_intent_material_digest_v2(&stable)?;
    // G7 separately rechecks the live plan and pre-state. Do not freeze those
    // changing counters into a reusable operation commitment.
    let stable_content = savana_kernel_protocol::v2::ActionContentV2::new(
        content.authorization_id(),
        content.authorization_revision(),
        content.clause_id(),
        content.alternative_index(),
        content.action().clone(),
        content.magnitude(),
        content.payload_digest(),
        content.provenance_digest(),
        Digest32V2::new([1; 32]),
        content.candidate_domain_digest(),
        Digest32V2::new([1; 32]),
        0,
    )
    .map_err(|_| G4Error::StateConflict)?;
    let content = savana_kernel_protocol::v2::action_content_digest_v2(&stable_content)
        .map_err(|_| G4Error::StateConflict)?;
    Ok(*super::task_authorization::hash_parts(
        b"SAVANA_FUSED_EXECUTION_COMMITMENT_V04\0",
        &[material.as_bytes(), content.as_bytes()],
    )
    .as_bytes())
}
impl FusedPlanningProfileV04 {
    pub fn signing_digest(&self) -> Result<[u8; 32], G4Error> {
        self.policy.validate().map_err(|_| G4Error::StateConflict)?;
        if self.delivery_schedule.len() > 256
            || (!self.delivery_schedule.is_empty() && !self.release_model_views)
        {
            return Err(G4Error::StateConflict);
        }
        for (i, slot) in self.delivery_schedule.iter().enumerate() {
            let round = self
                .policy
                .rounds
                .iter()
                .find(|r| r.id == slot.round)
                .ok_or(G4Error::StateConflict)?;
            let (open, close) = match slot.role {
                Role::Advisor if round.advisor.is_some() => (round.opens_at, round.advice_cut),
                Role::Planner => (round.advice_cut, round.closes_at),
                _ => return Err(G4Error::StateConflict),
            };
            if slot.id == 0
                || slot.opens_at >= slot.closes_at
                || slot.opens_at < open
                || slot.closes_at > close
                || (i > 0
                    && (self.delivery_schedule[i - 1].id >= slot.id
                        || self.delivery_schedule[i - 1].closes_at > slot.opens_at))
                || self
                    .delivery_schedule
                    .iter()
                    .filter(|s| s.round == slot.round && s.role == slot.role)
                    .count()
                    > usize::from(round.max_deliveries)
            {
                return Err(G4Error::StateConflict);
            }
        }
        if self.release_model_views
            && self
                .policy
                .rounds
                .iter()
                .any(|r| std::str::from_utf8(&r.public_view).is_err())
        {
            return Err(G4Error::StateConflict);
        }
        if !self.execution_bindings.is_empty()
            && (self.execution_bindings.len() != self.policy.operations.len()
                || self
                    .execution_bindings
                    .iter()
                    .zip(&self.policy.operations)
                    .any(|(b, op)| b.operation != op.id || b.commitment == [0; 32]))
        {
            return Err(G4Error::StateConflict);
        }
        let dynamic = self
            .policy
            .rounds
            .iter()
            .any(|r| !r.observations.is_empty());
        if let Some(source) = self.final_result_source {
            if !matches!(self.schema, 3 | 4)
                || !self.policy.operations.iter().any(|o| o.id == source)
                || self
                    .policy
                    .templates
                    .iter()
                    .any(|t| t.order.last() != Some(&source))
            {
                return Err(G4Error::StateConflict);
            }
        }
        if self.final_release.as_ref().is_some_and(|r| {
            self.schema != 4
                || self.final_result_source.is_none()
                || r.clause == 0
                || r.descriptor == [0; 32]
                || r.turn == [0; 32]
        }) {
            return Err(G4Error::StateConflict);
        }
        if !matches!(self.schema, 1 | 2 | 3 | 4)
            || (dynamic
                && (!matches!(self.schema, 2 | 3 | 4)
                    || !self.release_model_views
                    || self.delivery_schedule.is_empty()))
            || [self.installation, self.task].contains(&[0; 32])
            || self.not_before >= self.expires_at
            || self
                .policy
                .rounds
                .iter()
                .any(|r| r.opens_at < self.not_before || r.closes_at > self.expires_at)
        {
            return Err(G4Error::StateConflict);
        }
        let bytes = serde_json::to_vec(self).map_err(|_| G4Error::StateConflict)?;
        if bytes.len() > MAX_PROFILE {
            return Err(G4Error::StateConflict);
        }
        Ok(*super::task_authorization::hash_parts(
            b"SAVANA_FUSED_PLANNING_PROFILE_V04\0",
            &[&bytes],
        )
        .as_bytes())
    }
    fn matches(&self, parent: &VerifiedTaskAuthorizationV2) -> bool {
        let m = parent.material();
        self.policy.root == *parent.digest().as_bytes()
            && self.installation == *m.installation_digest().as_bytes()
            && self.task == *m.task().as_bytes()
            && self.not_before >= m.not_before().get()
            && self.expires_at <= m.expires_at().get()
    }
}

pub struct VerifiedFusedPlanningProfileV04(FusedPlanningProfileV04);
impl VerifiedFusedPlanningProfileV04 {
    /// Crate-private path used only after authenticating a signed administrator
    /// CompilePlanning command and compiling it against the current registry.
    pub(super) fn from_compiled_admin(
        profile: FusedPlanningProfileV04,
        parent: &VerifiedTaskAuthorizationV2,
        now: UnixMillisV2,
    ) -> Result<Self, G4Error> {
        profile.signing_digest()?;
        if !profile.matches(parent)
            || now.get() < profile.not_before
            || now.get() >= profile.expires_at
        {
            return Err(G4Error::StateConflict);
        }
        Ok(Self(profile))
    }
    /// Trust is selected by the authenticated host, never supplied by a model.
    pub fn verify(
        bytes: &[u8],
        signature: &[u8; 64],
        issuer: &VerifyingKey,
        parent: &VerifiedTaskAuthorizationV2,
        now: UnixMillisV2,
    ) -> Result<Self, G4Error> {
        if bytes.len() > MAX_PROFILE || issuer.is_weak() {
            return Err(G4Error::StateConflict);
        }
        let profile: FusedPlanningProfileV04 =
            serde_json::from_slice(bytes).map_err(|_| G4Error::StateConflict)?;
        if serde_json::to_vec(&profile).map_err(|_| G4Error::StateConflict)? != bytes
            || !profile.matches(parent)
            || now.get() < profile.not_before
            || now.get() >= profile.expires_at
        {
            return Err(G4Error::StateConflict);
        }
        issuer
            .verify_strict(
                &profile.signing_digest()?,
                &Signature::from_bytes(signature),
            )
            .map_err(|_| G4Error::StateConflict)?;
        Ok(Self(profile))
    }
    pub(super) fn task(&self) -> DurableTaskIdV2 {
        DurableTaskIdV2::new(self.0.task)
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    inputs: Option<super::fused_inputs::InputSnapshot>,
    profile: FusedPlanningProfileV04,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    recipe_approval: Option<super::FusedRecipeApprovalV04>,
    revision: u64,
    clock_floor: u64,
    state: PlanningState,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    executions: Vec<ExecutionBinding>,
    #[serde(default, skip_serializing_if = "is_zero")]
    schedule_cursor: u16,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    scheduled_reservations: Vec<u16>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecutionBinding {
    operation: u16,
    revision: u64,
    execution: [u8; 32],
    intent: [u8; 32],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    recipe: Option<RecipeExecutionReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    result_scope: Option<super::fused_execution_recovery::ResultScopeRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    result_commit: Option<[u8; 32]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    result_value: Option<super::fused_inputs::Input>,
}

fn result_is_required(profile: &FusedPlanningProfileV04, operation: u16) -> bool {
    profile.final_result_source == Some(operation)
        || profile
            .policy
            .operations
            .iter()
            .flat_map(|o| &o.bindings)
            .any(|b| b.result_of == Some(operation))
        || profile
            .policy
            .rounds
            .iter()
            .flat_map(|r| &r.observations)
            .any(|o| o.source == operation)
}

fn freeze_result_observation(
    state: &mut PlanningState,
    executions: &[ExecutionBinding],
    round: u16,
    now: UnixMillisV2,
) -> Result<(), G4Error> {
    let r = state
        .policy()
        .rounds
        .iter()
        .find(|r| r.id == round)
        .ok_or(G4Error::StateConflict)?;
    if r.observations.is_empty()
        || state
            .observations_frozen(round)
            .map_err(|_| G4Error::StateConflict)?
    {
        return Ok(());
    }
    let sources: std::collections::BTreeSet<_> = r.observations.iter().map(|o| o.source).collect();
    let mut inputs = Vec::new();
    for source in sources {
        let bytes = if let Some(e) = executions
            .iter()
            .find(|e| e.operation == source && e.result_commit.is_some())
        {
            let input = e.result_value.as_ref().ok_or(G4Error::StateConflict)?;
            input.check_result_time(now.get())?;
            let (value, _) = input.decode()?;
            Some(
                value
                    .as_bytes_value()
                    .ok_or(G4Error::StateConflict)?
                    .to_vec(),
            )
        } else {
            None
        };
        inputs.push(
            savana_continuation_core::planning_observation::ObservationSource { source, bytes },
        );
    }
    state
        .freeze_observations(round, inputs, now.get())
        .map_err(|_| G4Error::StateConflict)?;
    Ok(())
}

/// Owner-authenticated historical assertion: exact witness verification passed
/// in the same transaction as this execution reservation. Not deserializable
/// as a live FusedExecutionRecipeV04 and not a reusable authorization token.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecipeExecutionReceipt {
    schema: u16,
    approval: [u8; 32],
    recipe: [u8; 32],
    material: [u8; 32],
    content: [u8; 32],
    admitted_at: u64,
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FusedPlanningTableV04 {
    records: Vec<Record>,
}

/// Host-private protocol requests. No model-selected template contains tool args.
pub enum FusedPlanningUpdateV04 {
    /// Clock-only progress while no worker/session is available. Never reserves
    /// or returns bytes; missing cloud configuration is not a fake delivery.
    SkipExpiredDeliveries,
    /// Host clock tick only; never selected by a model reply or task progress.
    ClaimScheduledDelivery {
        recipient: [u8; 32],
    },
    FreezeEnvelope {
        round: u16,
    },
    ReserveDelivery {
        round: u16,
        role: Role,
        recipient: [u8; 32],
    },
    AcceptAdvice {
        round: u16,
        sender: [u8; 32],
        bytes: Vec<u8>,
    },
    AcceptPlan {
        round: u16,
        sender: [u8; 32],
        bytes: Vec<u8>,
    },
    Activate {
        round: u16,
        expected_plan_revision: u64,
    },
}

/// Result stays inside the trusted host. A view is NOT an outbound capability.
/// Deliberately no Debug/Serialize implementation or public network response.
pub struct FusedPlanningResultV04 {
    revision: u64,
    view: Option<ModelView>,
    scheduled_slot: Option<FusedDeliverySlotV04>,
}
/// Private recovery information, not model-visible progress or a permission.
pub struct FusedPlanningStatusV04 {
    pub revision: u64,
    pub active_plan_revision: u64,
}
/// Private compilation snapshot. Not serializable and not an execution grant;
/// every effect must recheck live activation and exact signed material at G7.
pub struct ActiveFusedPlanV04 {
    input_commitment: Option<[u8; 32]>,
    next_operation: Option<u16>,
    compiled: CompiledPlan,
    revision: u64,
    profile: [u8; 32],
    expires_at: UnixMillisV2,
    bindings: Vec<FusedExecutionBindingV04>,
    recipe_approval: Option<super::FusedRecipeApprovalV04>,
}
impl ActiveFusedPlanV04 {
    pub fn input_commitment(&self) -> Option<[u8; 32]> {
        self.input_commitment
    }
    /// First operation not yet reserved by G7, selected by owner state only.
    pub fn next_operation(&self) -> Option<u16> {
        self.next_operation
    }
    pub fn recipe_deadline(&self) -> Option<UnixMillisV2> {
        self.recipe_approval
            .as_ref()
            .map(|a| UnixMillisV2::new(a.expires_at.min(self.expires_at.get())))
    }
    pub fn compiled(&self) -> &CompiledPlan {
        &self.compiled
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn profile_digest(&self) -> [u8; 32] {
        self.profile
    }
    pub fn expires_at(&self) -> UnixMillisV2 {
        self.expires_at
    }
    pub fn approved_commitment(&self, operation: u16) -> Option<[u8; 32]> {
        self.bindings
            .iter()
            .find(|b| b.operation == operation)
            .map(|b| b.commitment)
    }

    /// Private draft comparison only. Does not settle G6 or allow G7 dispatch.
    /// The host must hold the actual deployment lease and rebuild exact G4.
    pub fn recipe_approved(
        &self,
        operation: u16,
        recipe: &super::FusedExecutionRecipeV04,
        deployment_generation: u64,
        now: UnixMillisV2,
    ) -> bool {
        self.recipe_approval.as_ref().is_some_and(|a| {
            a.deployment_generation == deployment_generation
                && now.get() >= a.not_before
                && now.get() < a.expires_at
                && self
                    .compiled
                    .operations()
                    .iter()
                    .find(|o| o.id == operation)
                    .is_some_and(|op| a.permits_recipe(self.profile, op, recipe.commitment()))
        })
    }
}
/// Host-private scheduler metadata. Not a model RPC, view or send capability.
pub struct FusedScheduledWorkV04 {
    pub task: DurableTaskIdV2,
    pub revision: u64,
    pub recipient: Option<[u8; 32]>,
    pub round: Option<u16>,
    /// Persisted accepted candidate awaiting private activation, independent of
    /// whether all transmission slots have already been consumed.
    pub activation_round: Option<u16>,
}
impl FusedPlanningResultV04 {
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn view_for_release_check(&self) -> Option<&ModelView> {
        self.view.as_ref()
    }
    pub(super) fn scheduled_slot(&self) -> Option<&FusedDeliverySlotV04> {
        self.scheduled_slot.as_ref()
    }
}

fn current(
    profile: &FusedPlanningProfileV04,
    tasks: &TaskLedgerV2,
    now: UnixMillisV2,
) -> Result<(), G4Error> {
    let task = tasks
        .current(DurableTaskIdV2::new(profile.task))?
        .ok_or(G4Error::StateConflict)?;
    if task.revoked()
        || !profile.matches(task.authorization())
        || now.get() < profile.not_before
        || now.get() >= profile.expires_at
    {
        return Err(G4Error::StateConflict);
    }
    Ok(())
}

impl FusedPlanningTableV04 {
    pub(super) fn final_result(
        &self,
        task: DurableTaskIdV2,
        tasks: &TaskLedgerV2,
        journal: &super::dispatch::KernelDispatchJournalV2,
        now: UnixMillisV2,
    ) -> Result<super::FusedFinalResultCandidateV04, G4Error> {
        let r = self
            .records
            .iter()
            .find(|r| r.profile.task == *task.as_bytes())
            .ok_or(G4Error::StateConflict)?;
        current(&r.profile, tasks, now)?;
        let source = r
            .profile
            .final_result_source
            .ok_or(G4Error::StateConflict)?;
        if now.get() < r.clock_floor {
            return Err(G4Error::StateConflict);
        }
        let round = r.state.active_round().ok_or(G4Error::StateConflict)?;
        let plan = r
            .state
            .compiled(round)
            .map_err(|_| G4Error::StateConflict)?;
        if plan.operations().last().map(|o| o.id) != Some(source)
            || plan.operations().len() != r.executions.len()
        {
            return Err(G4Error::StateConflict);
        }
        // "Started" and even "effect succeeded" are insufficient: every
        // original completion must have its durable result checkpoint.
        let mut selected = None;
        let mut run = None;
        for (op, execution) in plan.operations().iter().zip(&r.executions) {
            let nonce = savana_kernel_protocol::v2::Nonce32V2::new(execution.execution);
            let entry = journal
                .entries
                .iter()
                .find(|e| e.core.execution_nonce == nonce)
                .ok_or(G4Error::StateConflict)?;
            let binding = tasks.binding(nonce).ok_or(G4Error::StateConflict)?;
            if op.id != execution.operation
                || execution.result_commit.is_none()
                || entry.state != super::KernelDispatchStateV2::CompletionCommitted
                || entry.core.durable_task_id != task
                || binding.contract_digest().as_bytes() != &r.profile.policy.root
                || run.is_some_and(|id| id != entry.core.durable_run_id)
            {
                return Err(G4Error::StateConflict);
            }
            run = Some(entry.core.durable_run_id);
            if op.id == source {
                selected = Some((execution, entry));
            }
        }
        let (execution, entry) = selected.ok_or(G4Error::StateConflict)?;
        let input = execution
            .result_value
            .as_ref()
            .ok_or(G4Error::StateConflict)?;
        Self::check_result_value(execution, entry, input)?;
        input.check_result_time(now.get())?;
        let (value, provenance) = input.decode()?;
        super::FusedFinalResultCandidateV04::from_owned_result(
            task,
            Digest32V2::new(r.profile.policy.root),
            Digest32V2::new(r.profile.signing_digest()?),
            source,
            entry.core.clone(),
            Digest32V2::new(execution.result_commit.ok_or(G4Error::StateConflict)?),
            value,
            provenance,
            r.profile.final_release.clone(),
        )
    }

    pub(super) fn has_inputs(&self) -> bool {
        self.records.iter().any(|r| r.inputs.is_some())
    }
    pub(super) fn inputs_pinned(&self, task: DurableTaskIdV2) -> bool {
        self.records
            .iter()
            .any(|r| r.profile.task == *task.as_bytes() && r.inputs.is_some())
    }
    pub(super) fn pin_inputs(
        &mut self,
        task: DurableTaskIdV2,
        mut inputs: super::fused_inputs::InputSnapshot,
        tasks: &TaskLedgerV2,
        now: UnixMillisV2,
    ) -> Result<bool, G4Error> {
        let r = self
            .records
            .iter_mut()
            .find(|r| r.profile.task == *task.as_bytes())
            .ok_or(G4Error::StateConflict)?;
        current(&r.profile, tasks, now)?;
        if now.get() < r.clock_floor {
            return Err(G4Error::StateConflict);
        }
        let root = tasks.current(task)?.ok_or(G4Error::StateConflict)?;
        inputs.bind_profile(&r.profile)?;
        inputs.validate(
            &r.profile,
            root.authorization().material().manifest_digest(),
        )?;
        if let Some(old) = &r.inputs {
            return if old.same_inputs(&inputs) {
                Ok(false)
            } else {
                Err(G4Error::StateConflict)
            };
        }
        if r.recipe_approval.is_some()
            || !r.profile.execution_bindings.is_empty()
            || !r.executions.is_empty()
        {
            return Err(G4Error::StateConflict);
        }
        r.inputs = Some(inputs);
        r.clock_floor = now.get();
        r.revision = r.revision.checked_add(1).ok_or(G4Error::StateConflict)?;
        Ok(true)
    }
    pub(super) fn recover_inputs(
        &self,
        task: DurableTaskIdV2,
        generation: u64,
        tasks: &TaskLedgerV2,
        now: UnixMillisV2,
    ) -> Result<super::RecoveredFusedInputsV04, G4Error> {
        let r = self
            .records
            .iter()
            .find(|r| r.profile.task == *task.as_bytes())
            .ok_or(G4Error::StateConflict)?;
        current(&r.profile, tasks, now)?;
        if now.get() < r.clock_floor {
            return Err(G4Error::StateConflict);
        }
        let mut recovered = r
            .inputs
            .as_ref()
            .ok_or(G4Error::StateConflict)?
            .recover(generation, now.get())?;
        let mut slots = std::collections::BTreeSet::new();
        for b in r.profile.policy.operations.iter().flat_map(|o| &o.bindings) {
            if let Some(source) = b.result_of {
                if !slots.insert(b.slot) {
                    continue;
                }
                if let Some(e) = r
                    .executions
                    .iter()
                    .find(|e| e.operation == source && e.result_commit.is_some())
                {
                    let extract = b
                        .result_path
                        .as_deref()
                        .zip(b.result_max_bytes)
                        .map(|(path, max)| (path, max));
                    recovered.add_result(
                        b.slot,
                        e.result_value.as_ref().ok_or(G4Error::StateConflict)?,
                        extract,
                        now.get(),
                    )?;
                }
            }
        }
        Ok(recovered)
    }
    pub(super) fn active_plan(
        &self,
        task: DurableTaskIdV2,
        tasks: &TaskLedgerV2,
        now: UnixMillisV2,
    ) -> Result<ActiveFusedPlanV04, G4Error> {
        let record = self
            .records
            .iter()
            .find(|r| r.profile.task == *task.as_bytes())
            .ok_or(G4Error::StateConflict)?;
        current(&record.profile, tasks, now)?;
        if now.get() < record.clock_floor {
            return Err(G4Error::StateConflict);
        }
        let round = record.state.active_round().ok_or(G4Error::StateConflict)?;
        let compiled = record
            .state
            .compiled(round)
            .map_err(|_| G4Error::StateConflict)?;
        Ok(ActiveFusedPlanV04 {
            input_commitment: record.inputs.as_ref().map(|i| i.commitment()).transpose()?,
            next_operation: compiled
                .operations()
                .get(record.executions.len())
                .map(|o| o.id),
            compiled,
            revision: record.state.active_revision(),
            profile: record.profile.signing_digest()?,
            expires_at: UnixMillisV2::new(record.profile.expires_at),
            bindings: record.profile.execution_bindings.clone(),
            recipe_approval: record.recipe_approval.clone(),
        })
    }

    /// Resolve only from durable activation and an already frozen G4 intent.
    /// The host supplies neither an operation number nor a fresh value mapping.
    /// This read does not reserve an attempt: G7 repeats the check at commit.
    // Keep the owner-held live context explicit at this private security boundary.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn select_execution(
        &self,
        intent: &super::ActionIntentRecordV2,
        content: &savana_kernel_protocol::v2::ActionContentV2,
        journal: &super::dispatch::KernelDispatchJournalV2,
        tasks: &TaskLedgerV2,
        recipe: Option<&super::FusedExecutionRecipeV04>,
        generation: u64,
        now: UnixMillisV2,
    ) -> Result<(FusedOperationRefV04, bool), G4Error> {
        let record = self
            .records
            .iter()
            .find(|r| r.profile.task == *intent.durable_task_id.as_bytes())
            .ok_or(G4Error::StateConflict)?;
        current(&record.profile, tasks, now)?;
        if now.get() < record.clock_floor {
            return Err(G4Error::StateConflict);
        }
        if let Some(original) = record
            .executions
            .iter()
            .find(|e| e.intent == *intent.action_intent_id.as_bytes())
        {
            let entry = journal
                .entries
                .iter()
                .find(|e| e.core.execution_nonce.as_bytes() == &original.execution)
                .ok_or(G4Error::StateConflict)?;
            if entry.core.subject.tool_action_intent_id() != Some(intent.action_intent_id)
                || entry.core.durable_task_id != intent.durable_task_id
                || tasks
                    .binding(entry.core.execution_nonce)
                    .ok_or(G4Error::StateConflict)?
                    .content()
                    != content
            {
                return Err(G4Error::StateConflict);
            }
            Self::check_recorded_execution(
                record,
                original,
                intent,
                entry,
                tasks
                    .binding(entry.core.execution_nonce)
                    .ok_or(G4Error::StateConflict)?,
            )?;
            Self::check_optional_replay_recipe(original, recipe, intent, content, generation)?;
            if original.recipe.is_some()
                && (generation != entry.core.deployment_generation
                    || now.get() >= entry.core.expires_at.get())
            {
                return Err(G4Error::StateConflict);
            }
            return Ok((
                FusedOperationRefV04 {
                    plan_revision: original.revision,
                    operation: original.operation,
                },
                true,
            ));
        }
        let round = record.state.active_round().ok_or(G4Error::StateConflict)?;
        let compiled = record
            .state
            .compiled(round)
            .map_err(|_| G4Error::StateConflict)?;
        let operation = compiled
            .operations()
            .get(record.executions.len())
            .ok_or(G4Error::StateConflict)?;
        let reference = FusedOperationRefV04 {
            plan_revision: record.state.active_revision(),
            operation: operation.id,
        };
        Self::check_new_execution(
            record, reference, intent, content, journal, recipe, generation, now,
        )?;
        Ok((reference, false))
    }

    #[allow(clippy::too_many_arguments)]
    fn check_new_execution(
        record: &Record,
        reference: FusedOperationRefV04,
        intent: &super::ActionIntentRecordV2,
        content: &savana_kernel_protocol::v2::ActionContentV2,
        journal: &super::dispatch::KernelDispatchJournalV2,
        recipe: Option<&super::FusedExecutionRecipeV04>,
        generation: u64,
        now: UnixMillisV2,
    ) -> Result<(), G4Error> {
        let round = record.state.active_round().ok_or(G4Error::StateConflict)?;
        let compiled = record
            .state
            .compiled(round)
            .map_err(|_| G4Error::StateConflict)?;
        let operation = compiled
            .operations()
            .get(record.executions.len())
            .ok_or(G4Error::StateConflict)?;
        if reference.plan_revision == 0
            || record.state.active_revision() != reference.plan_revision
            || operation.id != reference.operation
            || record.executions.iter().any(|e| {
                e.operation == reference.operation
                    || e.intent == *intent.action_intent_id.as_bytes()
            })
        {
            return Err(G4Error::StateConflict);
        }
        Self::check_operation_material(record, reference.operation, intent)?;
        for b in &operation.bindings {
            if let Some(source) = b.result_of {
                record
                    .executions
                    .iter()
                    .find(|e| e.operation == source)
                    .and_then(|e| e.result_value.as_ref())
                    .ok_or(G4Error::StateConflict)?
                    .check_result_time(now.get())?;
            }
        }
        if let Some(inputs) = &record.inputs {
            inputs.execution_expiry(generation, now.get())?;
        }
        if let Some(a) = &record.recipe_approval {
            let recipe = recipe.ok_or(G4Error::StateConflict)?;
            Self::check_recipe_identity(record, reference, intent, content)?;
            if recipe.root.as_bytes() != &a.root
                || recipe.generation != generation
                || a.deployment_generation != generation
                || now.get() < a.not_before
                || now.get() >= a.expires_at
                || !recipe.matches_exact_draft(&intent.material, content)?
                || !a.permits_recipe(
                    record.profile.signing_digest()?,
                    operation,
                    recipe.commitment(),
                )
            {
                return Err(G4Error::StateConflict);
            }
        } else {
            if recipe.is_some() {
                return Err(G4Error::StateConflict);
            }
            Self::check_execution_material(record, reference.operation, intent, content)?;
        }
        for predecessor in &operation.after {
            let previous = record
                .executions
                .iter()
                .find(|e| e.operation == *predecessor)
                .ok_or(G4Error::StateConflict)?;
            if !journal.entries.iter().any(|e| {
                e.core.execution_nonce.as_bytes() == &previous.execution
                    && e.core.subject.tool_action_intent_id()
                        == Some(savana_kernel_protocol::v2::ActionIntentIdV2::new(
                            previous.intent,
                        ))
                    && e.core.durable_task_id == intent.durable_task_id
                    && e.state == super::dispatch::KernelDispatchStateV2::CompletionCommitted
            }) {
                return Err(G4Error::StateConflict);
            }
        }
        Ok(())
    }

    pub(super) fn scheduled_work(
        &self,
        tasks: &TaskLedgerV2,
        now: UnixMillisV2,
    ) -> Vec<FusedScheduledWorkV04> {
        self.records
            .iter()
            .filter_map(|r| {
                if r.profile.delivery_schedule.is_empty()
                    || now.get() < r.clock_floor
                    || current(&r.profile, tasks, now).is_err()
                {
                    return None;
                }
                let remaining = &r.profile.delivery_schedule[usize::from(r.schedule_cursor)..];
                let activation_round = r
                    .profile
                    .policy
                    .rounds
                    .iter()
                    .rev()
                    .find(|round| {
                        r.state
                            .active_round()
                            .is_none_or(|active| round.id > active)
                            && r.state.compiled(round.id).is_ok()
                    })
                    .map(|round| round.id);
                if remaining.is_empty() && activation_round.is_none() {
                    return None;
                }
                let due = remaining
                    .iter()
                    .find(|s| now.get() < s.closes_at)
                    .filter(|s| now.get() >= s.opens_at);
                let recipient = due.and_then(|s| {
                    r.profile
                        .policy
                        .rounds
                        .iter()
                        .find(|round| round.id == s.round)
                        .and_then(|round| match s.role {
                            Role::Advisor => round.advisor,
                            Role::Planner => Some(round.planner),
                        })
                });
                Some(FusedScheduledWorkV04 {
                    task: DurableTaskIdV2::new(r.profile.task),
                    revision: r.revision,
                    recipient,
                    round: due.map(|s| s.round),
                    activation_round,
                })
            })
            .collect()
    }
    pub(super) fn observation_parents(
        &self,
        task: DurableTaskIdV2,
        round: u16,
        tasks: &TaskLedgerV2,
        now: UnixMillisV2,
    ) -> Result<Vec<super::ProvenanceRecordV2>, G4Error> {
        let r = self
            .records
            .iter()
            .find(|r| r.profile.task == *task.as_bytes())
            .ok_or(G4Error::StateConflict)?;
        current(&r.profile, tasks, now)?;
        if now.get() < r.clock_floor {
            return Err(G4Error::StateConflict);
        }
        let policy_round = r
            .profile
            .policy
            .rounds
            .iter()
            .find(|r| r.id == round)
            .ok_or(G4Error::StateConflict)?;
        if policy_round.observations.is_empty() {
            return Ok(vec![]);
        }
        let frozen = r.state.frozen_observations();
        let (_, _, inputs) = frozen
            .iter()
            .find(|(id, _, _)| *id == round)
            .ok_or(G4Error::StateConflict)?;
        let mut parents = Vec::new();
        for input in *inputs {
            if let Some(bytes) = &input.bytes {
                let e = r
                    .executions
                    .iter()
                    .find(|e| e.operation == input.source && e.result_commit.is_some())
                    .ok_or(G4Error::StateConflict)?;
                let value = e.result_value.as_ref().ok_or(G4Error::StateConflict)?;
                value.check_result_time(now.get())?;
                let (raw, provenance) = value.decode()?;
                if raw.as_bytes_value() != Some(bytes.as_slice()) {
                    return Err(G4Error::StateConflict);
                }
                parents.push(provenance);
            }
        }
        Ok(parents)
    }

    pub(super) fn release_binding(
        &self,
        task: DurableTaskIdV2,
        tasks: &TaskLedgerV2,
        now: UnixMillisV2,
    ) -> Result<[u8; 32], G4Error> {
        let r = self
            .records
            .iter()
            .find(|r| r.profile.task == *task.as_bytes())
            .ok_or(G4Error::StateConflict)?;
        current(&r.profile, tasks, now)?;
        if !r.profile.release_model_views || now.get() < r.clock_floor {
            return Err(G4Error::StateConflict);
        }
        r.profile.signing_digest()
    }
    /// Runs only on the prospective owner snapshot, inside the G7 transaction.
    /// No mutation becomes visible unless dispatch, quota and this link commit.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn prepare_execution(
        &mut self,
        reference: Option<FusedOperationRefV04>,
        recipe: Option<&super::FusedExecutionRecipeV04>,
        result_scope: Option<&super::FusedResultScopeV04>,
        intent: &super::ActionIntentRecordV2,
        journal: &super::dispatch::KernelDispatchJournalV2,
        tasks: &TaskLedgerV2,
        nonce: savana_kernel_protocol::v2::Nonce32V2,
        replay: bool,
        now: UnixMillisV2,
    ) -> Result<(), G4Error> {
        let Some(record) = self
            .records
            .iter_mut()
            .find(|r| r.profile.task == *intent.durable_task_id.as_bytes())
        else {
            return if reference.is_none() && recipe.is_none() && result_scope.is_none() {
                Ok(())
            } else {
                Err(G4Error::StateConflict)
            };
        };
        current(&record.profile, tasks, now)?;
        if now.get() < record.clock_floor {
            return Err(G4Error::StateConflict);
        }
        let reference = reference.ok_or(G4Error::StateConflict)?;
        let binding = tasks.binding(nonce).ok_or(G4Error::StateConflict)?;
        let entry = journal
            .entries
            .iter()
            .find(|e| e.core.execution_nonce == nonce)
            .ok_or(G4Error::StateConflict)?;
        if replay {
            // Re-observing an original reservation after replacement is not new
            // work; retain its original revision/intent/nonce, never remint them.
            let original = record
                .executions
                .iter()
                .find(|e| {
                    e.operation == reference.operation
                        && e.revision == reference.plan_revision
                        && e.execution == *nonce.as_bytes()
                        && e.intent == *intent.action_intent_id.as_bytes()
                })
                .ok_or(G4Error::StateConflict)?;
            Self::check_recorded_execution(record, original, intent, entry, binding)?;
            if result_scope.is_some_and(|s| original.result_scope.as_ref() != Some(&s.0)) {
                return Err(G4Error::StateConflict);
            }
            return Self::check_optional_replay_recipe(
                original,
                recipe,
                intent,
                binding.content(),
                entry.core.deployment_generation,
            );
        }
        Self::check_new_execution(
            record,
            reference,
            intent,
            binding.content(),
            journal,
            recipe,
            entry.core.deployment_generation,
            now,
        )?;
        let recipe_receipt = if let Some(a) = &record.recipe_approval {
            Self::check_result_windows(
                record,
                reference.operation,
                now.get(),
                entry.core.expires_at.get(),
            )?;
            if let Some(inputs) = &record.inputs {
                if entry.core.expires_at.get()
                    > inputs.execution_expiry(entry.core.deployment_generation, now.get())?
                {
                    return Err(G4Error::StateConflict);
                }
            }
            if entry.core.expires_at.get() > a.expires_at {
                return Err(G4Error::StateConflict);
            }
            Some(RecipeExecutionReceipt {
                schema: 1,
                approval: a.signing_digest()?,
                recipe: recipe.ok_or(G4Error::StateConflict)?.commitment(),
                material: *super::intent::action_intent_material_digest_v2(&intent.material)?
                    .as_bytes(),
                content: *savana_kernel_protocol::v2::action_content_digest_v2(binding.content())
                    .map_err(|_| G4Error::StateConflict)?
                    .as_bytes(),
                admitted_at: now.get(),
            })
        } else {
            None
        };
        if record
            .executions
            .iter()
            .any(|e| e.execution == *nonce.as_bytes())
        {
            return Err(G4Error::StateConflict);
        }
        if result_is_required(&record.profile, reference.operation) && result_scope.is_none() {
            // Never start an effect whose mandatory retained result cannot be
            // authenticated later. A source declaration is not result scope.
            return Err(G4Error::StateConflict);
        }
        if let Some(scope) = result_scope {
            if record.inputs.is_none() || recipe_receipt.is_none() {
                return Err(G4Error::StateConflict);
            }
            scope.0.validate(
                tasks
                    .historical(binding.contract_digest())
                    .ok_or(G4Error::StateConflict)?,
                now.get(),
            )?;
        }
        record
            .state
            .retain_started(
                reference.plan_revision,
                reference.operation,
                *nonce.as_bytes(),
            )
            .map_err(|_| G4Error::StateConflict)?;
        record.executions.push(ExecutionBinding {
            operation: reference.operation,
            revision: reference.plan_revision,
            execution: *nonce.as_bytes(),
            intent: *intent.action_intent_id.as_bytes(),
            recipe: recipe_receipt,
            result_scope: result_scope.map(|s| s.0.clone()),
            result_commit: None,
            result_value: None,
        });
        record.revision = record
            .revision
            .checked_add(1)
            .ok_or(G4Error::StateConflict)?;
        record.clock_floor = now.get();
        Ok(())
    }

    fn check_execution_material(
        record: &Record,
        operation: u16,
        intent: &super::ActionIntentRecordV2,
        content: &savana_kernel_protocol::v2::ActionContentV2,
    ) -> Result<(), G4Error> {
        let approved = record
            .profile
            .execution_bindings
            .iter()
            .find(|b| b.operation == operation)
            .ok_or(G4Error::StateConflict)?;
        Self::check_operation_material(record, operation, intent)?;
        if record.recipe_approval.is_some()
            || fused_execution_commitment_v04(&intent.material, content)? != approved.commitment
        {
            return Err(G4Error::StateConflict);
        }
        Ok(())
    }

    fn check_operation_material(
        record: &Record,
        operation: u16,
        intent: &super::ActionIntentRecordV2,
    ) -> Result<(), G4Error> {
        let op = record
            .profile
            .policy
            .operations
            .iter()
            .find(|o| o.id == operation)
            .ok_or(G4Error::StateConflict)?;
        let descriptor = super::descriptor::decode_unsigned_descriptor(
            intent.material.selected_descriptor_canonical(),
        )?;
        if let Some(inputs) = &record.inputs {
            inputs.check_operation(op, intent)?;
        }
        for b in &op.bindings {
            if let Some(source) = b.result_of {
                use savana_kernel_protocol::v2::BusinessFieldRoleV2;
                let field = descriptor
                    .require_business_profile()?
                    .fields()
                    .iter()
                    .find(|f| f.name() == b.argument)
                    .ok_or(G4Error::StateConflict)?;
                // A whole-result edge fills only the payload; a path edge fills a
                // Resource/Destination/Parameter, never the payload or magnitude.
                let role_ok = if b.result_path.is_some() {
                    !matches!(
                        field.role(),
                        BusinessFieldRoleV2::Payload | BusinessFieldRoleV2::Magnitude
                    )
                } else {
                    field.role() == BusinessFieldRoleV2::Payload
                };
                if !role_ok {
                    return Err(G4Error::StateConflict);
                }
                let e = record
                    .executions
                    .iter()
                    .find(|e| e.operation == source && e.result_commit.is_some())
                    .ok_or(G4Error::StateConflict)?;
                let argument = intent
                    .material
                    .normalized_arguments()
                    .iter()
                    .find(|a| a.argument_name().as_str() == b.argument)
                    .ok_or(G4Error::StateConflict)?;
                let extract = b.result_path.as_deref().zip(b.result_max_bytes);
                e.result_value
                    .as_ref()
                    .ok_or(G4Error::StateConflict)?
                    .check_result_argument(b.slot, argument, extract)?;
            }
        }
        let mut actual_names: Vec<_> = intent
            .material
            .normalized_arguments()
            .iter()
            .map(|a| a.argument_name().as_str())
            .collect();
        let mut expected_names: Vec<_> = op.bindings.iter().map(|b| b.argument.as_str()).collect();
        actual_names.sort_unstable();
        expected_names.sort_unstable();
        if descriptor.tool_class().get() != u32::from(op.tool_class)
            || descriptor.action_template().get() != u32::from(op.action_template)
            || actual_names != expected_names
        {
            return Err(G4Error::StateConflict);
        }
        Ok(())
    }

    fn check_recipe_identity(
        record: &Record,
        reference: FusedOperationRefV04,
        intent: &super::ActionIntentRecordV2,
        content: &savana_kernel_protocol::v2::ActionContentV2,
    ) -> Result<(), G4Error> {
        let policy = record
            .profile
            .policy
            .commitment()
            .map_err(|_| G4Error::StateConflict)?;
        let plan = super::task_authorization::hash_parts(
            b"SAVANA_FUSED_LOCAL_PLAN_V04\0",
            &[&policy, &reference.plan_revision.to_be_bytes()],
        );
        let step = super::task_authorization::hash_parts(
            b"SAVANA_FUSED_LOCAL_OPERATION_V04\0",
            &[&policy, &reference.operation.to_be_bytes()],
        );
        if reference.plan_revision == 0
            || content.plan_revision_digest() != plan
            || intent.material.binding.plan_revision_digest.as_bytes() != plan.as_bytes()
            || intent.material.binding.internal_step_id.as_bytes() != step.as_bytes()
        {
            return Err(G4Error::StateConflict);
        }
        Ok(())
    }

    fn check_optional_replay_recipe(
        original: &ExecutionBinding,
        recipe: Option<&super::FusedExecutionRecipeV04>,
        intent: &super::ActionIntentRecordV2,
        content: &savana_kernel_protocol::v2::ActionContentV2,
        generation: u64,
    ) -> Result<(), G4Error> {
        if let Some(proof) = recipe {
            let receipt = original.recipe.as_ref().ok_or(G4Error::StateConflict)?;
            if receipt.recipe != proof.commitment()
                || proof.generation != generation
                || !proof.matches_exact_draft(&intent.material, content)?
            {
                return Err(G4Error::StateConflict);
            }
        }
        Ok(())
    }

    fn check_recorded_execution(
        record: &Record,
        original: &ExecutionBinding,
        intent: &super::ActionIntentRecordV2,
        entry: &super::dispatch::KernelDispatchJournalEntryV2,
        binding: &super::TaskDispatchBindingV2,
    ) -> Result<(), G4Error> {
        let Some(receipt) = &original.recipe else {
            return Self::check_execution_material(
                record,
                original.operation,
                intent,
                binding.content(),
            );
        };
        let a = record
            .recipe_approval
            .as_ref()
            .ok_or(G4Error::StateConflict)?;
        Self::check_result_windows(
            record,
            original.operation,
            receipt.admitted_at,
            entry.core.expires_at.get(),
        )?;
        if let Some(inputs) = &record.inputs {
            if entry.core.expires_at.get()
                > inputs.execution_expiry(entry.core.deployment_generation, receipt.admitted_at)?
            {
                return Err(G4Error::StateConflict);
            }
        }
        Self::check_operation_material(record, original.operation, intent)?;
        Self::check_recipe_identity(
            record,
            FusedOperationRefV04 {
                operation: original.operation,
                plan_revision: original.revision,
            },
            intent,
            binding.content(),
        )?;
        if receipt.schema != 1
            || receipt.approval != a.signing_digest()?
            || !a.permits_recipe(
                record.profile.signing_digest()?,
                record
                    .profile
                    .policy
                    .operations
                    .iter()
                    .find(|o| o.id == original.operation)
                    .ok_or(G4Error::StateConflict)?,
                receipt.recipe,
            )
            || receipt.material
                != *super::intent::action_intent_material_digest_v2(&intent.material)?.as_bytes()
            || receipt.content
                != *savana_kernel_protocol::v2::action_content_digest_v2(binding.content())
                    .map_err(|_| G4Error::StateConflict)?
                    .as_bytes()
            || receipt.admitted_at < a.not_before
            || receipt.admitted_at >= a.expires_at
            || receipt.admitted_at > record.clock_floor
            || binding.contract_digest().as_bytes() != &a.root
            || entry.core.deployment_generation != a.deployment_generation
            || entry.core.expires_at.get() > a.expires_at
            || entry.core.expires_at.get() <= receipt.admitted_at
        {
            return Err(G4Error::StateConflict);
        }
        Ok(())
    }

    fn check_result_windows(
        record: &Record,
        operation: u16,
        admitted: u64,
        expiry: u64,
    ) -> Result<(), G4Error> {
        let op = record
            .profile
            .policy
            .operations
            .iter()
            .find(|o| o.id == operation)
            .ok_or(G4Error::StateConflict)?;
        for source in op.bindings.iter().filter_map(|b| b.result_of) {
            record
                .executions
                .iter()
                .find(|e| e.operation == source)
                .and_then(|e| e.result_value.as_ref())
                .ok_or(G4Error::StateConflict)?
                .check_result_window(admitted, expiry)?;
        }
        Ok(())
    }

    /// Restore checks both directions: no dangling link and no unbound effect.
    pub(super) fn validate_executions(
        &self,
        tasks: &TaskLedgerV2,
        journal: &super::dispatch::KernelDispatchJournalV2,
        intents: &super::intent::ActionIntentIndexV2,
    ) -> Result<(), G4Error> {
        let corrupt = || G4Error::DurableStateCorrupt;
        for r in &self.records {
            if r.executions
                .iter()
                .filter_map(|e| e.result_value.as_ref())
                .map(|v| v.storage_bytes())
                .sum::<usize>()
                > 256 * 1024
            {
                return Err(corrupt());
            }
            if r.state.started_operations()
                != r.executions
                    .iter()
                    .map(|e| (e.operation, e.execution))
                    .collect::<Vec<_>>()
            {
                return Err(corrupt());
            }
            for (i, e) in r.executions.iter().enumerate() {
                if e.revision == 0
                    || e.revision > r.state.active_revision()
                    || r.executions[..i].iter().any(|p| {
                        p.intent == e.intent
                            || p.execution == e.execution
                            || p.operation == e.operation
                    })
                {
                    return Err(corrupt());
                }
                let entry = journal
                    .entries
                    .iter()
                    .find(|j| j.core.execution_nonce.as_bytes() == &e.execution)
                    .ok_or_else(corrupt)?;
                let intent = intents
                    .intents
                    .iter()
                    .find(|v| v.record.action_intent_id.as_bytes() == &e.intent)
                    .ok_or_else(corrupt)?;
                if entry.core.durable_task_id.as_bytes() != &r.profile.task
                    || intent.record.durable_task_id.as_bytes() != &r.profile.task
                    || entry.core.subject.tool_action_intent_id()
                        != Some(intent.record.action_intent_id)
                {
                    return Err(corrupt());
                }
                let binding = tasks
                    .binding(entry.core.execution_nonce)
                    .ok_or_else(corrupt)?;
                Self::check_recorded_execution(r, e, &intent.record, entry, binding)
                    .map_err(|_| corrupt())?;
                if let Some(scope) = &e.result_scope {
                    if r.inputs.is_none() {
                        return Err(corrupt());
                    }
                    let receipt = e.recipe.as_ref().ok_or_else(corrupt)?;
                    scope
                        .validate(
                            tasks
                                .historical(binding.contract_digest())
                                .ok_or_else(corrupt)?,
                            receipt.admitted_at,
                        )
                        .map_err(|_| corrupt())?;
                }
                if let Some(commit) = e.result_commit {
                    if commit == [0; 32]
                        || e.result_scope.is_none()
                        || entry.state != super::KernelDispatchStateV2::CompletionCommitted
                        || (e.result_value.is_none() && result_is_required(&r.profile, e.operation))
                    {
                        return Err(corrupt());
                    }
                }
                if let Some(value) = &e.result_value {
                    if e.result_commit.is_none() {
                        return Err(corrupt());
                    }
                    Self::check_result_value(e, entry, value).map_err(|_| corrupt())?;
                }
            }
            // Frozen observations must still name the original authenticated
            // execution result. Missing-at-freeze stays missing after late IO.
            for (_, frozen_at, inputs) in r.state.frozen_observations() {
                if frozen_at > r.clock_floor {
                    return Err(corrupt());
                }
                for input in inputs {
                    if let Some(bytes) = &input.bytes {
                        let e = r
                            .executions
                            .iter()
                            .find(|e| e.operation == input.source && e.result_commit.is_some())
                            .ok_or_else(corrupt)?;
                        let value = e.result_value.as_ref().ok_or_else(corrupt)?;
                        value.check_result_time(frozen_at).map_err(|_| corrupt())?;
                        if value.decode().map_err(|_| corrupt())?.0.as_bytes_value()
                            != Some(bytes.as_slice())
                        {
                            return Err(corrupt());
                        }
                    }
                }
            }
            let releases = journal
                .entries
                .iter()
                .filter(|j| {
                    j.core.durable_task_id.as_bytes() == &r.profile.task
                        && matches!(
                            j.core.subject,
                            super::DispatchSubjectV2::FinalRelease { .. }
                        )
                })
                .collect::<Vec<_>>();
            if releases.len() > 1 {
                return Err(corrupt());
            }
            for release in &releases {
                let spec = r.profile.final_release.as_ref().ok_or_else(corrupt)?;
                let source = r.profile.final_result_source.ok_or_else(corrupt)?;
                let original = r
                    .executions
                    .last()
                    .filter(|e| e.operation == source && e.result_commit.is_some())
                    .ok_or_else(corrupt)?;
                if r.executions.len() != r.profile.policy.operations.len()
                    || r.executions.iter().any(|e| e.result_commit.is_none())
                {
                    return Err(corrupt());
                }
                let input = original.result_value.as_ref().ok_or_else(corrupt)?;
                let (value, provenance) = input.decode().map_err(|_| corrupt())?;
                let bytes = value.as_bytes_value().ok_or_else(corrupt)?;
                let evidence = super::evidence_digest_v2(&[super::EvidenceDigestEntryV2::new(
                    super::value_digest_v2(&value).map_err(|_| corrupt())?,
                    provenance.provenance_digest(),
                )])
                .map_err(|_| corrupt())?;
                let matched = tasks
                    .binding(release.core.execution_nonce)
                    .ok_or_else(corrupt)?;
                let super::DispatchSubjectV2::FinalRelease { binding, .. } = &release.core.subject
                else {
                    unreachable!()
                };
                if matched.contract_digest().as_bytes() != &r.profile.policy.root
                    || matched.content().clause_id() != spec.clause
                    || matched
                        .content()
                        .action()
                        .tool_descriptor_digest()
                        .as_bytes()
                        != &spec.descriptor
                    || matched.content().action().effect()
                        != savana_kernel_protocol::v2::TaskEffectV2::FinalRelease
                    || matched.content().provenance_digest() != evidence
                    || binding.evidence_digest() != evidence
                    || binding.release_payload_digest()
                        != super::task_authorization::hash_parts(
                            b"SAVANA_FINAL_RELEASE_PAYLOAD_V2\0",
                            &[bytes],
                        )
                    || release.core.durable_run_id != provenance.run_internal_id()
                    || release.core.active_state_manifest_digest
                        != provenance.active_state_manifest_digest()
                    || release.core.expires_at.get() > provenance.expires_at().get()
                {
                    return Err(corrupt());
                }
            }
            if journal
                .entries
                .iter()
                .filter(|j| j.core.durable_task_id.as_bytes() == &r.profile.task)
                .count()
                != r.executions.len() + releases.len()
            {
                return Err(corrupt());
            }
        }
        Ok(())
    }
    pub(super) fn status(
        &self,
        task: DurableTaskIdV2,
        tasks: &TaskLedgerV2,
        now: UnixMillisV2,
    ) -> Result<FusedPlanningStatusV04, G4Error> {
        let record = self
            .records
            .iter()
            .find(|r| r.profile.task == *task.as_bytes())
            .ok_or(G4Error::StateConflict)?;
        current(&record.profile, tasks, now)?;
        if now.get() < record.clock_floor {
            return Err(G4Error::StateConflict);
        }
        Ok(FusedPlanningStatusV04 {
            revision: record.revision,
            active_plan_revision: record.state.active_revision(),
        })
    }
    pub(super) fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub(super) fn has_result_scopes(&self) -> bool {
        self.records
            .iter()
            .any(|r| r.executions.iter().any(|e| e.result_scope.is_some()))
    }

    pub(super) fn needs_result_value(
        &self,
        task: DurableTaskIdV2,
        nonce: savana_kernel_protocol::v2::Nonce32V2,
    ) -> Result<bool, G4Error> {
        let record = self
            .records
            .iter()
            .find(|r| r.profile.task == *task.as_bytes())
            .ok_or(G4Error::StateConflict)?;
        let execution = record
            .executions
            .iter()
            .find(|e| e.execution == *nonce.as_bytes())
            .ok_or(G4Error::StateConflict)?;
        Ok(result_is_required(&record.profile, execution.operation))
    }

    pub(super) fn record_result_commit(
        &mut self,
        task: DurableTaskIdV2,
        nonce: savana_kernel_protocol::v2::Nonce32V2,
        commit: Digest32V2,
        journal: &super::dispatch::KernelDispatchJournalV2,
        value: Option<super::fused_inputs::Input>,
    ) -> Result<bool, G4Error> {
        let record = self
            .records
            .iter_mut()
            .find(|r| r.profile.task == *task.as_bytes())
            .ok_or(G4Error::StateConflict)?;
        let execution = record
            .executions
            .iter_mut()
            .find(|e| e.execution == *nonce.as_bytes())
            .ok_or(G4Error::StateConflict)?;
        let entry = journal
            .entries
            .iter()
            .find(|e| e.core.execution_nonce == nonce)
            .ok_or(G4Error::StateConflict)?;
        if commit.as_bytes() == &[0; 32]
            || execution.result_scope.is_none()
            || entry.core.durable_task_id != task
            || entry.state != super::KernelDispatchStateV2::CompletionCommitted
        {
            return Err(G4Error::StateConflict);
        }
        let required = result_is_required(&record.profile, execution.operation);
        let value = if required {
            let value = value.ok_or(G4Error::StateConflict)?;
            Self::check_result_value(execution, entry, &value)?;
            Some(value)
        } else {
            None
        };
        if let Some(existing) = execution.result_commit {
            return if existing == *commit.as_bytes() && execution.result_value == value {
                Ok(false)
            } else {
                Err(G4Error::StateConflict)
            };
        }
        execution.result_commit = Some(*commit.as_bytes());
        execution.result_value = value;
        if record
            .executions
            .iter()
            .filter_map(|e| e.result_value.as_ref())
            .map(|v| v.storage_bytes())
            .sum::<usize>()
            > 256 * 1024
        {
            return Err(G4Error::StateConflict);
        }
        Ok(true)
    }

    fn check_result_value(
        execution: &ExecutionBinding,
        entry: &super::dispatch::KernelDispatchJournalEntryV2,
        value: &super::fused_inputs::Input,
    ) -> Result<(), G4Error> {
        let (raw, p) = value.decode()?;
        let scope = super::FusedResultScopeV04(
            execution
                .result_scope
                .clone()
                .ok_or(G4Error::StateConflict)?,
        );
        let expected_nonce = super::task_authorization::hash_parts(
            b"SAVANA_EXECUTION_NONCE_DIGEST_V2\0",
            &[&execution.execution],
        );
        if entry.state != super::KernelDispatchStateV2::CompletionCommitted
            || raw.as_bytes_value().is_none()
            || p.run_internal_id() != entry.core.durable_run_id
            || p.active_state_manifest_digest() != entry.core.active_state_manifest_digest
            || p.producer_identity() != scope.producer()
            || p.expires_at() != scope.expires_at()
            || p.label()
                != super::SecurityLabelV2::from_verified_source(
                    super::IntegrityV2::ExternalUntrusted,
                    super::ConfidentialityV2::VaultBound,
                    super::ReaderSetV2::KERNEL,
                    scope.effects(),
                )
            || !matches!(p.source_kind(), super::SourceKindV2::ToolResult { action_intent, execution_nonce_digest }
                if action_intent.as_bytes() == &execution.intent && *execution_nonce_digest == expected_nonce)
        {
            return Err(G4Error::StateConflict);
        }
        Ok(())
    }

    /// Historical projection deliberately does not require an unexpired/current
    /// root: revocation stops new effects, not settlement of an existing one.
    pub(super) fn recover_executions(
        &self,
        task: DurableTaskIdV2,
        tasks: &TaskLedgerV2,
        journal: &super::dispatch::KernelDispatchJournalV2,
        intents: &super::intent::ActionIntentIndexV2,
    ) -> Result<Vec<super::RecoveredFusedExecutionV04>, G4Error> {
        self.recover_execution_records(Some(task), false, tasks, journal, intents)
    }

    pub(super) fn recover_scoped_executions(
        &self,
        tasks: &TaskLedgerV2,
        journal: &super::dispatch::KernelDispatchJournalV2,
        intents: &super::intent::ActionIntentIndexV2,
    ) -> Result<Vec<super::RecoveredFusedExecutionV04>, G4Error> {
        self.recover_execution_records(None, true, tasks, journal, intents)
    }

    fn recover_execution_records(
        &self,
        task: Option<DurableTaskIdV2>,
        scoped_only: bool,
        tasks: &TaskLedgerV2,
        journal: &super::dispatch::KernelDispatchJournalV2,
        intents: &super::intent::ActionIntentIndexV2,
    ) -> Result<Vec<super::RecoveredFusedExecutionV04>, G4Error> {
        self.validate_executions(tasks, journal, intents)?;
        if task.is_some_and(|task| {
            !self
                .records
                .iter()
                .any(|r| r.profile.task == *task.as_bytes())
        }) {
            return Err(G4Error::StateConflict);
        }
        self.records
            .iter()
            .filter(|r| task.is_none_or(|task| r.profile.task == *task.as_bytes()))
            .flat_map(|r| &r.executions)
            .filter(|e| !scoped_only || e.result_scope.is_some())
            .map(|e| {
                let entry = journal
                    .entries
                    .iter()
                    .find(|j| j.core.execution_nonce.as_bytes() == &e.execution)
                    .ok_or(G4Error::StateConflict)?;
                let intent = intents
                    .intents
                    .iter()
                    .find(|i| i.record.action_intent_id.as_bytes() == &e.intent)
                    .ok_or(G4Error::StateConflict)?;
                Ok(super::RecoveredFusedExecutionV04 {
                    core: entry.core.clone(),
                    core_digest: entry.core_digest,
                    intent: intent.record.action_intent_id,
                    descriptor: intent.record.binding().tool_descriptor_digest(),
                    material: super::intent::action_intent_material_digest_v2(
                        &intent.record.material,
                    )?,
                    scope: super::FusedResultScopeV04(
                        e.result_scope.clone().ok_or(G4Error::StateConflict)?,
                    ),
                    state: entry.state,
                    result_commit: e.result_commit.map(Digest32V2::new),
                })
            })
            .collect()
    }
    pub(super) fn has_execution_bindings(&self) -> bool {
        self.records
            .iter()
            .any(|r| !r.profile.execution_bindings.is_empty() || !r.executions.is_empty())
    }
    pub(super) fn has_delivery_schedule(&self) -> bool {
        self.records
            .iter()
            .any(|r| !r.profile.delivery_schedule.is_empty())
    }
    pub(super) fn has_recipe_approvals(&self) -> bool {
        self.records.iter().any(|r| r.recipe_approval.is_some())
    }
    pub(super) fn has_recipe_executions(&self) -> bool {
        self.records
            .iter()
            .any(|r| r.executions.iter().any(|e| e.recipe.is_some()))
    }
    pub(super) fn has_recipe_approval(&self, task: [u8; 32], approval: [u8; 32]) -> bool {
        self.records.iter().any(|r| {
            r.profile.task == task
                && r.recipe_approval
                    .as_ref()
                    .is_some_and(|a| a.signing_digest().ok() == Some(approval))
        })
    }

    pub(super) fn install_recipe_approval(
        &mut self,
        proof: super::fused_recipe_approval::VerifiedFusedRecipeApprovalV04,
        tasks: &TaskLedgerV2,
        now: UnixMillisV2,
    ) -> Result<(), G4Error> {
        let a = proof.0;
        let record = self
            .records
            .iter_mut()
            .find(|r| r.profile.task == a.task)
            .ok_or(G4Error::StateConflict)?;
        current(&record.profile, tasks, now)?;
        a.matches_profile(&record.profile)?;
        if a.recipe_schema == 2
            && a.inputs_digest != record.inputs.as_ref().map(|i| i.commitment()).transpose()?
        {
            return Err(G4Error::StateConflict);
        }
        let parent = tasks
            .current(DurableTaskIdV2::new(a.task))?
            .ok_or(G4Error::StateConflict)?;
        if a.manifest
            != *parent
                .authorization()
                .material()
                .manifest_digest()
                .as_bytes()
            || now.get() < record.clock_floor
            || now.get() < a.not_before
            || now.get() >= a.expires_at
            || !record.executions.is_empty()
            || record.recipe_approval.is_some()
            || record
                .inputs
                .as_ref()
                .is_some_and(|inputs| inputs.generation() != a.deployment_generation)
        {
            return Err(G4Error::StateConflict);
        }
        record.revision = record
            .revision
            .checked_add(1)
            .ok_or(G4Error::StateConflict)?;
        record.clock_floor = now.get();
        record.recipe_approval = Some(a);
        Ok(())
    }
    pub(super) fn enrolled(&self, task: DurableTaskIdV2) -> bool {
        self.records
            .iter()
            .any(|r| r.profile.task == *task.as_bytes())
    }
    pub(super) fn has_profile(&self, task: [u8; 32], digest: [u8; 32]) -> bool {
        self.records
            .iter()
            .any(|r| r.profile.task == task && r.profile.signing_digest().ok() == Some(digest))
    }
    pub(super) fn validate(&self, tasks: &TaskLedgerV2) -> Result<(), G4Error> {
        if self.records.len() > MAX_TASKS {
            return Err(G4Error::DurableStateCorrupt);
        }
        for (i, r) in self.records.iter().enumerate() {
            let parent = tasks
                .historical(Digest32V2::new(r.profile.policy.root))
                .ok_or(G4Error::DurableStateCorrupt)?;
            r.profile
                .signing_digest()
                .map_err(|_| G4Error::DurableStateCorrupt)?;
            if let Some(a) = &r.recipe_approval {
                a.matches_profile(&r.profile)
                    .map_err(|_| G4Error::DurableStateCorrupt)?;
                if a.manifest != *parent.material().manifest_digest().as_bytes()
                    || (a.recipe_schema == 2
                        && a.inputs_digest
                            != r.inputs.as_ref().map(|i| i.commitment()).transpose()?)
                    || r.inputs
                        .as_ref()
                        .is_some_and(|inputs| inputs.generation() != a.deployment_generation)
                    || r.clock_floor < a.not_before
                    || r.revision < 2
                {
                    return Err(G4Error::DurableStateCorrupt);
                }
            }
            if let Some(inputs) = &r.inputs {
                inputs
                    .validate(&r.profile, parent.material().manifest_digest())
                    .map_err(|_| G4Error::DurableStateCorrupt)?;
                if inputs.captured_at > r.clock_floor || r.revision < 2 {
                    return Err(G4Error::DurableStateCorrupt);
                }
            }
            if !r.profile.matches(parent)
                || r.revision == 0
                || r.clock_floor < r.profile.not_before
                || r.clock_floor >= r.profile.expires_at
                || r.state.policy() != &r.profile.policy
                || self.records[..i]
                    .iter()
                    .any(|old| old.profile.task == r.profile.task)
            {
                return Err(G4Error::DurableStateCorrupt);
            }
            r.state
                .validate()
                .map_err(|_| G4Error::DurableStateCorrupt)?;
            let cursor = usize::from(r.schedule_cursor);
            if cursor > r.profile.delivery_schedule.len()
                || r.scheduled_reservations.windows(2).any(|p| p[0] >= p[1])
                || r.scheduled_reservations.iter().any(|id| {
                    !r.profile.delivery_schedule[..cursor]
                        .iter()
                        .any(|s| s.id == *id)
                })
                || r.profile.delivery_schedule[..cursor].iter().any(|s| {
                    if r.scheduled_reservations.contains(&s.id) {
                        s.opens_at > r.clock_floor
                    } else {
                        s.closes_at > r.clock_floor
                    }
                })
            {
                return Err(G4Error::DurableStateCorrupt);
            }
            if !r.profile.delivery_schedule.is_empty() {
                for round in &r.profile.policy.rounds {
                    for role in [Role::Advisor, Role::Planner] {
                        let count = r.profile.delivery_schedule[..cursor]
                            .iter()
                            .filter(|s| {
                                s.round == round.id
                                    && s.role == role
                                    && r.scheduled_reservations.contains(&s.id)
                            })
                            .count();
                        if usize::from(
                            r.state
                                .delivery_attempts(round.id, role)
                                .map_err(|_| G4Error::DurableStateCorrupt)?,
                        ) != count
                        {
                            return Err(G4Error::DurableStateCorrupt);
                        }
                    }
                }
            }
        }
        Ok(())
    }
    pub(super) fn install(
        &mut self,
        verified: VerifiedFusedPlanningProfileV04,
        tasks: &TaskLedgerV2,
        now: UnixMillisV2,
    ) -> Result<bool, G4Error> {
        let p = verified.0;
        current(&p, tasks, now)?;
        if let Some(old) = self.records.iter().find(|r| r.profile.task == p.task) {
            return if old.profile == p {
                Ok(false)
            } else {
                Err(G4Error::StateConflict)
            };
        }
        if self.records.len() >= MAX_TASKS {
            return Err(G4Error::StateConflict);
        }
        let mut jobs = Vec::new();
        for round in &p.policy.rounds {
            let random = || {
                let mut bytes = [0; 16];
                getrandom::getrandom(&mut bytes).map_err(|_| G4Error::StateConflict)?;
                Ok::<_, G4Error>(bytes)
            };
            jobs.push((
                if round.advisor.is_some() {
                    Some(random()?)
                } else {
                    None
                },
                random()?,
            ));
        }
        let state =
            PlanningState::new(p.policy.clone(), jobs).map_err(|_| G4Error::StateConflict)?;
        self.records.push(Record {
            inputs: None,
            profile: p,
            recipe_approval: None,
            revision: 1,
            clock_floor: now.get(),
            state,
            executions: vec![],
            schedule_cursor: 0,
            scheduled_reservations: vec![],
        });
        Ok(true)
    }
    pub(super) fn update(
        &mut self,
        task: DurableTaskIdV2,
        expected: u64,
        update: FusedPlanningUpdateV04,
        tasks: &TaskLedgerV2,
        now: UnixMillisV2,
    ) -> Result<(bool, FusedPlanningResultV04), G4Error> {
        let record = self
            .records
            .iter_mut()
            .find(|r| r.profile.task == *task.as_bytes())
            .ok_or(G4Error::StateConflict)?;
        current(&record.profile, tasks, now)?;
        if record.revision != expected || now.get() < record.clock_floor {
            return Err(G4Error::StateConflict);
        }
        let state = &mut record.state;
        let mut scheduled_slot = None;
        use FusedPlanningUpdateV04 as U;
        let is_tick = matches!(
            &update,
            U::ClaimScheduledDelivery { .. } | U::SkipExpiredDeliveries
        );
        let outcome = match update {
            U::SkipExpiredDeliveries => {
                if record.profile.delivery_schedule.is_empty() {
                    return Err(G4Error::StateConflict);
                }
                let old = record.schedule_cursor;
                while record
                    .profile
                    .delivery_schedule
                    .get(usize::from(record.schedule_cursor))
                    .is_some_and(|s| now.get() >= s.closes_at)
                {
                    record.schedule_cursor += 1;
                }
                Ok((old != record.schedule_cursor, None))
            }
            U::ClaimScheduledDelivery { recipient } => {
                if record.profile.delivery_schedule.is_empty() {
                    return Err(G4Error::StateConflict);
                }
                let old_cursor = record.schedule_cursor;
                while let Some(slot) = record
                    .profile
                    .delivery_schedule
                    .get(usize::from(record.schedule_cursor))
                {
                    if now.get() < slot.closes_at {
                        break;
                    }
                    record.schedule_cursor += 1;
                }
                let slot = record
                    .profile
                    .delivery_schedule
                    .get(usize::from(record.schedule_cursor));
                if let Some(slot) = slot.filter(|s| now.get() >= s.opens_at) {
                    freeze_result_observation(state, &record.executions, slot.round, now)?;
                    if slot.role == Role::Planner {
                        state
                            .freeze_envelope(slot.round, now.get())
                            .map_err(|_| G4Error::StateConflict)?;
                    }
                    let view = state
                        .reserve_delivery(slot.round, slot.role, recipient, now.get())
                        .map_err(|_| G4Error::StateConflict)?;
                    record.schedule_cursor += 1;
                    record.scheduled_reservations.push(slot.id);
                    scheduled_slot = Some(slot.clone());
                    Ok((true, Some(view)))
                } else {
                    Ok((old_cursor != record.schedule_cursor, None))
                }
            }
            U::FreezeEnvelope { round } => {
                if !record.profile.delivery_schedule.is_empty() {
                    return Err(G4Error::StateConflict);
                }
                state.freeze_envelope(round, now.get()).map(|c| (c, None))
            }
            U::ReserveDelivery {
                round,
                role,
                recipient,
            } => {
                if !record.profile.delivery_schedule.is_empty() {
                    return Err(G4Error::StateConflict);
                }
                state
                    .reserve_delivery(round, role, recipient, now.get())
                    .map(|v| (true, Some(v)))
            }
            U::AcceptAdvice {
                round,
                sender,
                bytes,
            } => state
                .accept_advice(round, sender, &bytes, now.get())
                .map(|c| (c, None)),
            U::AcceptPlan {
                round,
                sender,
                bytes,
            } => state
                .accept_plan(round, sender, &bytes, now.get())
                .map(|c| (c, None)),
            U::Activate {
                round,
                expected_plan_revision,
            } => state
                .activate(round, expected_plan_revision)
                .map(|c| (c, None)),
        }
        .map_err(|_| G4Error::StateConflict)?;
        // Empty schedule ticks must not manufacture writes or revisions.
        let changed = outcome.0 || (!is_tick && record.clock_floor != now.get());
        if changed {
            record.revision = record
                .revision
                .checked_add(1)
                .ok_or(G4Error::StateConflict)?;
            record.clock_floor = now.get();
        }
        Ok((
            changed,
            FusedPlanningResultV04 {
                revision: record.revision,
                view: outcome.1,
                scheduled_slot,
            },
        ))
    }
    pub(super) fn compiled(
        &self,
        task: DurableTaskIdV2,
        round: u16,
        tasks: &TaskLedgerV2,
        now: UnixMillisV2,
    ) -> Result<CompiledPlan, G4Error> {
        let record = self
            .records
            .iter()
            .find(|r| r.profile.task == *task.as_bytes())
            .ok_or(G4Error::StateConflict)?;
        current(&record.profile, tasks, now)?;
        if now.get() < record.clock_floor {
            return Err(G4Error::StateConflict);
        }
        record
            .state
            .compiled(round)
            .map_err(|_| G4Error::StateConflict)
    }
}
