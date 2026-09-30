use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io::Read as _;
use std::os::unix::fs::MetadataExt as _;
#[cfg(test)]
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::sync::{Arc, Mutex};

use aes_gcm::aead::{Aead as _, Payload};
use aes_gcm::{Aes256Gcm, KeyInit as _, Nonce};
use hmac::{Hmac, Mac as _};
use minicbor::Encode as _;
use rustix::fs::{open as rustix_open, openat, statat, AtFlags, FileType, Mode, OFlags};
use rustix::io::Errno;
use savana_kernel_protocol::v2::{
    ActionIntentIdV2, Digest32V2, DisplayProjectionIdV2, DurableReleaseIdV2, DurableRunIdV2,
    DurableTaskIdV2, Ed25519KeyIdV2, ExecutorIdentityV2, InternalSlotDigestV2, InternalStepIdV2,
    Nonce32V2, PlanRevisionDigestV2, ProjectionIdV2, RequestIdV2,
    SignedExecutorEffectStartedReceiptV2, ValueInternalIdV2,
};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use super::continuation_state::{
    ContinuationStorageUpdateV04, ContinuationStorageViewV04, ContinuationTableV04,
    VerifiedContinuationStorageV04,
};
use super::descriptor::decode_unsigned_descriptor;
use super::digest::{
    argument_digest_v2, provenance_set_digest_v2, token_set_digest_v2, ArgumentDigestEntryV2,
    ProvenanceSetDigestEntryV2, TokenSetDigestEntryV2,
};
use super::dispatch::{
    dispatch_core_digest, dispatch_subject_digest, DispatchCoreV2, DispatchPreparationKindV2,
    DispatchPreparationV2, DispatchSubjectV2, KernelDispatchJournalEntryV2,
    KernelDispatchJournalV2, KernelDispatchStateV2, SignedExecutorDispositionReceiptV2,
    VerifiedApprovalSettlementBindingV2, VerifiedEffectGateAuthorityV2, VerifiedExecutionTicketV2,
    VerifiedExecutorDispositionV2, VerifiedFinalReleaseApprovalBindingV2,
    VerifiedFinalReleaseDispatchV2, VerifiedFinalReleaseTicketV2,
};
use super::intent::{
    action_intent_id_v2, action_intent_material_digest_v2, projection_output_digest,
    tool_execution_semantic_binding_digest_v2, ActionIntentEntryV2, ActionIntentIndexV2,
    IntentReplayEntryV2, VerifiedToolProposalV2,
};
use super::ontology::OntologyEvaluationV2;
use super::quota::{
    AuthenticatedEffectDispositionKindV2, DispatchQuotaCounterEntryV2, DispatchQuotaLedgerEntryV2,
    DispatchQuotaLedgerV2,
};
use super::task_issuance::{PendingTaskAuthorizationV2, TaskIssuanceLedgerV2};
use super::task_state::TaskLedgerV2;
use super::validator::{decision_record_digest, G5DecisionEntryV2};
use super::{
    descriptor_digest_v2, ActionIntentRecordV2, ActionIntentResolutionV2, ActionIntentStateV2,
    AttemptKindV2, AuthenticatedEffectDispositionV2, BoundedConnectorRetryPolicyV2,
    DispatchQuotaCounterV2, DispatchQuotaMutationKindV2, DispatchQuotaMutationV2,
    DispatchQuotaReservationStateV2, DispatchQuotaReservationV2, DispatchQuotaSubjectV2,
    FinalReleaseSemanticBindingV2, G4Error, G5DecisionBranchV2, G5DecisionIndexV2,
    G5DecisionResolutionKindV2, G5DecisionResolutionV2, G5Error, G5PolicyDispositionV2,
    IdentifierV2, PendingCallStateRecordV2, PendingCallStateV2, PublicTaskStateRecordV2,
    PublicTaskStateV2, ResolvedStoredTokenV2, StableActionArgumentBindingV2,
    ToolExecutionSemanticBindingV2, VerifiedActionIntentMaterialV2, VerifiedG5EvaluationInputV2,
    VerifiedInternalValidatorRegistryV2, VerifiedProjectionOutputsV2, VerifiedQuotaLimitV2,
    VerifiedStoredBindingsV2,
};
use super::{
    TaskAuthorizationStateV2, TaskDispatchAuthorizationV2, TaskDispatchBindingV2,
    VerifiedTaskAuthorizationV2, VerifiedTaskOutcomeV2,
};
use crate::atomic_file::{self, PersistencePhase};
use crate::lock_file::LedgerLock;
use savana_kernel_protocol::v2::UnixMillisV2;
use savana_kernel_protocol::v2::{SignedApprovalEnvelopeV2, TaskAuthorizationDraftV2};

const STATE_FILE_NAME: &str = "kernel-g4-state-v2.cbor";
const STATE_LOCK_FILE_NAME: &str = ".kernel-g4-state-v2.cbor.lock";
const STATE_SCHEMA_VERSION: u16 = 2;
const PAYLOAD_SCHEMA_VERSION: u16 = 4;
const STATE_ENCRYPTION_AAD_DOMAIN: &[u8] = b"SAVANA_KERNEL_G4_STATE_ENCRYPTION_V2\0";
const STATE_HEAD_DOMAIN: &[u8] = b"SAVANA_KERNEL_G4_STATE_HEAD_V2\0";
const STATE_KEY_DERIVATION_DOMAIN: &[u8] = b"SAVANA_KERNEL_G4_STATE_KEY_DERIVATION_V2\0";
const STATE_NONCE_BYTES: usize = 12;
const MAX_STATE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_DESCRIPTOR_BYTES: usize = 8 * 1024 * 1024;
const MAX_INTENTS: usize = 4_096;
const MAX_REPLAY: usize = 65_536;
const MAX_COUNTERS: usize = 65_536;
const MAX_RESERVATIONS: usize = 65_536;
const MAX_G5_DECISIONS: usize = 4_096;
const MAX_DISPATCH_ENTRIES: usize = 65_536;
const MAX_ARGUMENTS: usize = 256;
const MAX_TOKENS: usize = 64;
const MAX_PROJECTION_OUTPUT_BYTES: usize = 8 * 1024 * 1024;
const DESTINATION_DIGEST_DOMAIN: &[u8] = b"SAVANA_DESTINATION_V2\0";
const DISPLAY_DIGEST_DOMAIN: &[u8] = b"SAVANA_DISPLAY_V2\0";
#[cfg(test)]
#[path = "durable_continuation_dispatch_tests.rs"]
mod continuation_dispatch_tests;
#[cfg(test)]
#[path = "durable_continuation_tests.rs"]
mod continuation_tests;
#[cfg(test)]
#[path = "durable_fused_planning_tests.rs"]
mod fused_planning_tests;
#[cfg(test)]
#[path = "durable_task_tests.rs"]
mod task_tests;

#[derive(Debug, Clone)]
struct DurableG4SnapshotV2 {
    payload_schema: u16,
    legacy_intents: Vec<ActionIntentIdV2>,
    sequence: u64,
    previous_state_digest: Digest32V2,
    intents: ActionIntentIndexV2,
    quota: DispatchQuotaLedgerV2,
    decisions: G5DecisionIndexV2,
    dispatch: KernelDispatchJournalV2,
    tasks: TaskLedgerV2,
    issuance: TaskIssuanceLedgerV2,
    continuations: ContinuationTableV04,
}

impl Default for DurableG4SnapshotV2 {
    fn default() -> Self {
        Self {
            payload_schema: PAYLOAD_SCHEMA_VERSION,
            legacy_intents: Vec::new(),
            sequence: 0,
            previous_state_digest: Digest32V2::new([0; 32]),
            intents: ActionIntentIndexV2::default(),
            quota: DispatchQuotaLedgerV2::default(),
            decisions: G5DecisionIndexV2::default(),
            dispatch: KernelDispatchJournalV2::default(),
            tasks: TaskLedgerV2::default(),
            issuance: TaskIssuanceLedgerV2::default(),
            continuations: ContinuationTableV04::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RollbackProtectedStateHeadV2 {
    sequence: u64,
    state_digest: Digest32V2,
}

impl RollbackProtectedStateHeadV2 {
    const GENESIS: Self = Self {
        sequence: 0,
        state_digest: Digest32V2::new([0; 32]),
    };

    pub fn new(sequence: u64, state_digest: Digest32V2) -> Result<Self, G4Error> {
        if (sequence == 0 && !is_zero(state_digest.as_bytes()))
            || (sequence > 0 && is_zero(state_digest.as_bytes()))
        {
            return Err(G4Error::DurableStateRollback);
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
pub struct DurableStateNamespaceV2 {
    installation_id: Digest32V2,
    store_id: Digest32V2,
}

impl DurableStateNamespaceV2 {
    pub fn from_verified_installation(
        installation_id: Digest32V2,
        store_id: Digest32V2,
    ) -> Result<Self, G4Error> {
        if is_zero(installation_id.as_bytes()) || is_zero(store_id.as_bytes()) {
            return Err(G4Error::DurableStateIo);
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

    #[cfg(test)]
    pub(crate) fn new_for_test(installation_seed: u8, store_seed: u8) -> Self {
        Self::from_verified_installation(
            Digest32V2::new([installation_seed; 32]),
            Digest32V2::new([store_seed; 32]),
        )
        .unwrap()
    }
}

pub trait RollbackProtectedStateAnchorV2: Send {
    fn current_head(&self) -> Result<RollbackProtectedStateHeadV2, G4Error>;

    fn compare_and_advance(
        &mut self,
        expected: RollbackProtectedStateHeadV2,
        next: RollbackProtectedStateHeadV2,
    ) -> Result<(), G4Error>;
}

pub struct DurableG4StateV2 {
    path: PathBuf,
    anchored_path: DurableAnchoredPathV2,
    namespace: DurableStateNamespaceV2,
    encryption_key: Zeroizing<[u8; 32]>,
    snapshot: DurableG4SnapshotV2,
    current_head: RollbackProtectedStateHeadV2,
    rollback_anchor: Box<dyn RollbackProtectedStateAnchorV2>,
    poisoned: bool,
    #[cfg(test)]
    before_next_commit_hook: Option<Box<dyn FnOnce() -> Result<(), G4Error> + Send>>,
    _lock: LedgerLock,
}

struct VerifiedReceiptEntryV2 {
    core: DispatchCoreV2,
    proof: VerifiedExecutorDispositionV2,
}

impl std::fmt::Debug for DurableG4StateV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DurableG4StateV2")
            .field("path", &self.path)
            .field("poisoned", &self.poisoned)
            .finish_non_exhaustive()
    }
}

impl DurableG4StateV2 {
    /// Only the trusted host scheduler reads this; no private progress is sent
    /// to models. Revoked, expired and authority-replaced tasks are excluded.
    pub fn scheduled_fused_work_v04(
        &self,
        now: UnixMillisV2,
    ) -> Result<Vec<super::FusedScheduledWorkV04>, G4Error> {
        self.ensure_usable()?;
        Ok(self
            .snapshot
            .continuations
            .planning
            .scheduled_work(&self.snapshot.tasks, now))
    }
    pub(super) fn fused_observation_parents_v04(
        &self,
        task: DurableTaskIdV2,
        round: u16,
        now: UnixMillisV2,
    ) -> Result<Vec<super::ProvenanceRecordV2>, G4Error> {
        self.ensure_usable()?;
        self.snapshot.continuations.planning.observation_parents(
            task,
            round,
            &self.snapshot.tasks,
            now,
        )
    }

    pub(super) fn fused_model_release_binding_v04(
        &self,
        task: DurableTaskIdV2,
        now: UnixMillisV2,
    ) -> Result<[u8; 32], G4Error> {
        self.ensure_usable()?;
        self.snapshot
            .continuations
            .planning
            .release_binding(task, &self.snapshot.tasks, now)
    }
    /// Private mode-selection guard. Enrollment is not inferred from a model or
    /// request flag; it is read from the authenticated durable owner.
    pub fn fused_planning_enrolled_v04(&self, task: DurableTaskIdV2) -> Result<bool, G4Error> {
        self.ensure_usable()?;
        Ok(self.snapshot.continuations.planning.enrolled(task))
    }

    /// Signed private planning opt-in. Does not activate strict inference or
    /// install a network publisher. Original task authority is mandatory.
    pub fn install_fused_planning_v04(
        &mut self,
        profile: super::VerifiedFusedPlanningProfileV04,
        now: UnixMillisV2,
    ) -> Result<(), G4Error> {
        self.ensure_usable()?;
        // Historical effects cannot be retroactively assigned to new operations.
        if self
            .snapshot
            .dispatch
            .entries
            .iter()
            .any(|e| e.core.durable_task_id == profile.task())
        {
            return Err(G4Error::StateConflict);
        }
        let mut next = self.snapshot.clone();
        if next
            .continuations
            .planning
            .install(profile, &next.tasks, now)?
        {
            self.commit(next)?;
        }
        Ok(())
    }

    /// Commit and anchor before returning a frozen view to the private release
    /// checker. Failure/uncertainty returns no view. This is NOT a send grant.
    pub fn update_fused_planning_v04(
        &mut self,
        task: DurableTaskIdV2,
        expected_revision: u64,
        update: super::FusedPlanningUpdateV04,
        now: UnixMillisV2,
    ) -> Result<super::FusedPlanningResultV04, G4Error> {
        self.ensure_usable()?;
        // The active started-prefix is advanced by the same commit as G7. A
        // replacement cannot manufacture a fresh view of outstanding work.
        let mut next = self.snapshot.clone();
        let (changed, result) = next.continuations.planning.update(
            task,
            expected_revision,
            update,
            &next.tasks,
            now,
        )?;
        if changed {
            self.commit(next)?;
        }
        Ok(result)
    }

    /// Private candidate read, not an executable grant or an activated plan.
    pub fn compiled_fused_plan_v04(
        &self,
        task: DurableTaskIdV2,
        round: u16,
        now: UnixMillisV2,
    ) -> Result<savana_continuation_core::planning::CompiledPlan, G4Error> {
        self.ensure_usable()?;
        self.snapshot
            .continuations
            .planning
            .compiled(task, round, &self.snapshot.tasks, now)
    }

    /// Read only the active candidate, never the latest unactivated proposal.
    /// A returned snapshot is not a grant and may be superseded before G7.
    pub fn active_fused_plan_v04(
        &self,
        task: DurableTaskIdV2,
        now: UnixMillisV2,
    ) -> Result<super::ActiveFusedPlanV04, G4Error> {
        self.ensure_usable()?;
        self.snapshot
            .continuations
            .planning
            .active_plan(task, &self.snapshot.tasks, now)
    }

    /// Read-only private recovery after a lost response; no new job or send.
    pub fn fused_planning_status_v04(
        &self,
        task: DurableTaskIdV2,
        now: UnixMillisV2,
    ) -> Result<super::FusedPlanningStatusV04, G4Error> {
        self.ensure_usable()?;
        self.snapshot
            .continuations
            .planning
            .status(task, &self.snapshot.tasks, now)
    }

    /// Host-private bridge from a frozen G4 intent to the exact active operation.
    /// No model-selected IDs, implicit value rebinding, reservation or I/O. G7
    /// repeats activation/material/dependency checks under its commit guard.
    /// Original dispatches retain their original selector after replacement.
    pub fn bind_fused_dispatch_v04(
        &self,
        action_intent_id: ActionIntentIdV2,
        mut task: TaskDispatchAuthorizationV2,
        deployment_generation: u64,
        now: UnixMillisV2,
    ) -> Result<TaskDispatchAuthorizationV2, G4Error> {
        self.ensure_usable()?;
        let task_id = task.matched.authorization().material().task();
        let intent = &self
            .snapshot
            .intents
            .intents
            .iter()
            .find(|e| e.record.action_intent_id == action_intent_id)
            .ok_or(G4Error::IntentNotFound)?
            .record;
        let authorization = task.matched.authorization().material();
        if intent.durable_task_id != task_id
            || intent.installation_id != self.namespace.installation_id()
            || intent.installation_id != authorization.installation_digest()
            || intent.active_state_manifest_digest != authorization.manifest_digest()
            || task.matched.deployment_generation() != deployment_generation
            || self.snapshot.legacy_intents.contains(&action_intent_id)
        {
            return Err(G4Error::StateConflict);
        }
        // Mode comes from the intent's durable task, not an unrelated root
        // passed to make an enrolled operation look like a legacy operation.
        if !self
            .snapshot
            .continuations
            .planning
            .enrolled(intent.durable_task_id)
        {
            return if task.fused_operation.is_none() && task.fused_recipe.is_none() {
                Ok(task)
            } else {
                Err(G4Error::StateConflict)
            };
        }
        let (reference, replay) = self.snapshot.continuations.planning.select_execution(
            intent,
            task.matched.content(),
            &self.snapshot.dispatch,
            &self.snapshot.tasks,
            task.fused_recipe.as_ref(),
            deployment_generation,
            now,
        )?;
        if task.fused_operation.is_some_and(|hint| hint != reference) {
            return Err(G4Error::StateConflict);
        }
        if !replay {
            let state = self.task_authorization_state(task_id)?;
            if state.revoked() {
                return Err(G4Error::StateConflict);
            }
            task.matched
                .recheck(&super::TaskMatchContextV2 {
                    current_authorization: Some(state.authorization()),
                    pre_state_digest: state.digest(),
                    pre_state_revision: state.revision(),
                    deployment_generation,
                    now,
                })
                .map_err(|_| G4Error::StateConflict)?;
        }
        task.fused_operation = Some(reference);
        Ok(task)
    }

    /// Host-only pin of already G1–G4-owned inputs, never an untrusted ingress.
    /// The host holds its current deployment lease and authenticates the run.
    pub fn pin_fused_inputs_v04(
        &mut self,
        task: DurableTaskIdV2,
        run: DurableRunIdV2,
        generation: u64,
        inputs: Vec<super::FusedOwnedInputV04>,
        now: UnixMillisV2,
    ) -> Result<(), G4Error> {
        self.ensure_usable()?;
        let root = self
            .snapshot
            .tasks
            .current(task)?
            .ok_or(G4Error::StateConflict)?;
        let snapshot = super::fused_inputs::InputSnapshot::new(
            run,
            root.authorization().material().manifest_digest(),
            generation,
            now.get(),
            inputs,
        );
        let mut next = self.snapshot.clone();
        if next
            .continuations
            .planning
            .pin_inputs(task, snapshot, &next.tasks, now)?
        {
            self.commit(next)?;
        }
        Ok(())
    }
    /// Authenticated private recovery, not disclosure or permission to execute.
    pub fn fused_inputs_pinned_v04(&self, task: DurableTaskIdV2) -> Result<bool, G4Error> {
        self.ensure_usable()?;
        Ok(self.snapshot.continuations.planning.inputs_pinned(task))
    }
    /// Only call for the authenticated task under a current deployment lease.
    pub fn recover_fused_inputs_v04(
        &self,
        task: DurableTaskIdV2,
        generation: u64,
        now: UnixMillisV2,
    ) -> Result<super::RecoveredFusedInputsV04, G4Error> {
        self.ensure_usable()?;
        self.snapshot.continuations.planning.recover_inputs(
            task,
            generation,
            &self.snapshot.tasks,
            now,
        )
    }

    /// Signed private administrator operations and their exact retry receipt are
    /// committed atomically. This never installs a root authorization, resets
    /// consumption, executes a tool, or publishes a value to the Agent.
    pub fn apply_managed_admin_v04(
        &mut self,
        proof: &super::VerifiedManagedAdminCommandV04,
        now: UnixMillisV2,
    ) -> Result<super::ManagedAdminReceiptV04, G4Error> {
        self.apply_managed_admin_inner_v04(proof, None, None, now)
    }

    /// Native host entry with its live role-filtered tool registry. The registry
    /// and role are deployment objects, never decoded from administrator bytes.
    pub fn apply_managed_admin_with_tools_v04(
        &mut self,
        proof: &super::VerifiedManagedAdminCommandV04,
        registry: &super::ActiveToolRegistryV2,
        role: savana_kernel_protocol::v2::RoleIdV2,
        now: UnixMillisV2,
    ) -> Result<super::ManagedAdminReceiptV04, G4Error> {
        self.apply_managed_admin_inner_v04(proof, Some((registry, role)), None, now)
    }

    /// Private historical replay, including after expiry. No new authority.
    pub fn managed_admin_receipt_v04(&self, proof: &super::VerifiedManagedAdminCommandV04)
        -> Result<Option<super::ManagedAdminReceiptV04>, G4Error> {
        self.ensure_usable()?;
        if proof.command.installation != *self.namespace.installation_id().as_bytes()
            || proof.command.store != *self.namespace.store_id().as_bytes() { return Err(G4Error::StateConflict); }
        self.snapshot.continuations.admin.replay(proof)
    }

    /// The host supplies a draft built from owned, pinned inputs and real G4
    /// material. Persisting this review is NOT installation of its approval.
    pub fn record_fused_execution_review_v04(&mut self,
        proof: &super::VerifiedManagedAdminCommandV04,
        run: DurableRunIdV2, approval: super::FusedRecipeApprovalV04, now: UnixMillisV2,
    ) -> Result<super::ManagedAdminReceiptV04, G4Error> {
        self.apply_managed_admin_inner_v04(proof, None, Some((run, approval)), now)
    }

    fn apply_managed_admin_inner_v04(
        &mut self,
        proof: &super::VerifiedManagedAdminCommandV04,
        tools: Option<(
            &super::ActiveToolRegistryV2,
            savana_kernel_protocol::v2::RoleIdV2,
        )>,
        prepared: Option<(DurableRunIdV2, super::FusedRecipeApprovalV04)>,
        now: UnixMillisV2,
    ) -> Result<super::ManagedAdminReceiptV04, G4Error> {
        use super::managed_admin::{
            signature, ManagedAdminOperationV04 as Op, ManagedAdminResultV04 as ResultValue,
        };
        self.ensure_usable()?;
        if proof.command.installation != *self.namespace.installation_id().as_bytes()
            || proof.command.store != *self.namespace.store_id().as_bytes()
        {
            return Err(G4Error::StateConflict);
        }
        if let Some(receipt) = self.snapshot.continuations.admin.replay(proof)? {
            return Ok(receipt); // historical observation only; no authority restored
        }
        proof.current(now)?;
        let mut next = self.snapshot.clone();
        let result = match &proof.command.operation {
            Op::PreparePlanningExecution { task, root } => {
                let (run, approval) = prepared.ok_or(G4Error::StateConflict)?;
                let task_id = DurableTaskIdV2::new(*task);
                let state = next.tasks.current(task_id)?.ok_or(G4Error::StateConflict)?;
                let active = next.continuations.planning.active_plan(task_id, &next.tasks, now)?;
                let inputs = next.continuations.planning.recover_inputs(task_id,
                    approval.deployment_generation, &next.tasks, now)?;
                approval.signing_digest()?;
                if state.revoked() || state.authorization().digest().as_bytes() != root
                    || approval.task != *task || approval.root != *root
                    || approval.installation != proof.command.installation
                    || approval.manifest != *inputs.manifest().as_bytes()
                    || inputs.run() != run || approval.profile != active.profile_digest()
                    || approval.recipe_schema != 2 || approval.inputs_digest != active.input_commitment()
                    || approval.not_before != proof.command.not_before
                    || approval.expires_at > active.expires_at().get()
                    || approval.expires_at > proof.command.expires_at
                    || next.dispatch.entries.iter().any(|e| e.core.durable_task_id == task_id) {
                    return Err(G4Error::StateConflict);
                }
                ResultValue::PlanningExecutionPrepared { task: *task, run: *run.as_bytes(), approval: Box::new(approval) }
            }
            Op::CompilePlanning { task, draft } => {
                let task_id = DurableTaskIdV2::new(*task);
                if next
                    .dispatch
                    .entries
                    .iter()
                    .any(|e| e.core.durable_task_id == task_id)
                {
                    return Err(G4Error::StateConflict);
                }
                let (registry, role) = tools.ok_or(G4Error::StateConflict)?;
                let parent = next.tasks.current(task_id)?.ok_or(G4Error::StateConflict)?;
                if parent.revoked() {
                    return Err(G4Error::StateConflict);
                }
                let profile = super::compile_fused_task_v04(
                    draft,
                    parent.authorization(),
                    registry,
                    role,
                    now,
                )?;
                let digest = profile.signing_digest()?;
                let verified = super::VerifiedFusedPlanningProfileV04::from_compiled_admin(
                    profile,
                    parent.authorization(),
                    now,
                )?;
                next.continuations
                    .planning
                    .install(verified, &next.tasks, now)?;
                ResultValue::PlanningEnrolled {
                    task: *task,
                    profile: digest,
                }
            }
            Op::ApprovePlanningRecipes {
                approval,
                approval_signature,
            } => {
                let task = DurableTaskIdV2::new(approval.task);
                if next
                    .dispatch
                    .entries
                    .iter()
                    .any(|e| e.core.durable_task_id == task)
                {
                    return Err(G4Error::StateConflict);
                }
                let verified =
                    super::fused_recipe_approval::VerifiedFusedRecipeApprovalV04::verify(
                        &serde_json::to_vec(approval).map_err(|_| G4Error::StateConflict)?,
                        &signature(approval_signature)?,
                        &proof.issuer,
                    )?;
                next.continuations
                    .planning
                    .install_recipe_approval(verified, &next.tasks, now)?;
                ResultValue::PlanningRecipesApproved {
                    task: approval.task,
                    approval: approval.signing_digest()?,
                }
            }
            Op::EnrollPlanning {
                profile,
                profile_signature,
            } => {
                let task = DurableTaskIdV2::new(profile.task);
                if next
                    .dispatch
                    .entries
                    .iter()
                    .any(|e| e.core.durable_task_id == task)
                {
                    return Err(G4Error::StateConflict);
                }
                let parent = next.tasks.current(task)?.ok_or(G4Error::StateConflict)?;
                let verified = super::VerifiedFusedPlanningProfileV04::verify(
                    &serde_json::to_vec(profile).map_err(|_| G4Error::StateConflict)?,
                    &signature(profile_signature)?,
                    &proof.issuer,
                    parent.authorization(),
                    now,
                )?;
                next.continuations
                    .planning
                    .install(verified, &next.tasks, now)?;
                ResultValue::PlanningEnrolled {
                    task: profile.task,
                    profile: profile.signing_digest()?,
                }
            }
            Op::RegisterSource {
                policy,
                signature: sig,
            } => {
                if policy.resource_issuer == proof.issuer.to_bytes() {
                    return Err(G4Error::StateConflict);
                }
                let verified = super::VerifiedManagedSourceV04::verify(
                    &serde_json::to_vec(policy).map_err(|_| G4Error::StateConflict)?,
                    &signature(sig)?,
                    &proof.issuer,
                    self.namespace.installation_id(),
                    now,
                )?;
                next.continuations.install_managed_source(
                    verified,
                    self.namespace.installation_id(),
                    now,
                )?;
                ResultValue::SourceRegistered {
                    source: policy.source,
                    namespace: policy.namespace,
                }
            }
            Op::CreateResource {
                source,
                namespace,
                label,
                content,
            } => {
                let resource = next
                    .continuations
                    .managed
                    .create(*source, *namespace, label, content, now)?;
                ResultValue::ResourceCreated { resource }
            }
            Op::UpdateResource {
                resource,
                expected_revision,
                value,
            } => {
                next.continuations.managed.update(
                    *resource,
                    *expected_revision,
                    value
                        .as_ref()
                        .map(|v| (v.label.as_str(), v.content.as_slice())),
                    now,
                )?;
                let revision = next.continuations.managed.view(*resource)?.revision;
                ResultValue::ResourceUpdated {
                    resource: *resource,
                    revision,
                }
            }
            Op::EnrollTask {
                profile,
                profile_signature,
                dispatch,
                dispatch_signature,
            } => {
                if dispatch.resource_issuer == proof.issuer.to_bytes() {
                    return Err(G4Error::StateConflict);
                }
                next.continuations
                    .managed
                    .require_registered_policy(dispatch, profile.installation)?;
                let state = next
                    .tasks
                    .current(DurableTaskIdV2::new(profile.task))?
                    .ok_or(G4Error::StateConflict)?;
                let storage = super::VerifiedContinuationStorageV04::verify(
                    &serde_json::to_vec(profile).map_err(|_| G4Error::StateConflict)?,
                    &signature(profile_signature)?,
                    &proof.issuer,
                    state.authorization(),
                    now,
                )?;
                let accounting = super::VerifiedContinuationDispatchPolicyV04::verify(
                    &serde_json::to_vec(dispatch).map_err(|_| G4Error::StateConflict)?,
                    &signature(dispatch_signature)?,
                    &proof.issuer,
                    profile,
                    now,
                )?;
                next.continuations.install(storage, &next.tasks, now)?;
                next.continuations.install_dispatch(
                    accounting,
                    &next.tasks,
                    &next.dispatch,
                    now,
                )?;
                ResultValue::TaskEnrolled {
                    task: profile.task,
                    profile: profile.signing_digest()?,
                }
            }
        };
        let receipt = next.continuations.admin.append(proof, result)?;
        self.commit(next)?;
        Ok(receipt)
    }

    /// Trusted host admission, after authentication/task matching/G3 and before
    /// G7. No caller-provided source, revision, signature or fallback key. This
    /// read-only step does not debit; G7 rechecks the issued revision atomically.
    pub fn bind_managed_dispatch_input_v04(
        &self,
        intent: ActionIntentIdV2,
        request: TaskDispatchAuthorizationV2,
        exact_plaintext: &[u8],
        signer: Option<&ed25519_dalek::SigningKey>,
        now: UnixMillisV2,
    ) -> Result<TaskDispatchAuthorizationV2, G4Error> {
        self.ensure_usable()?;
        if request.continuation_resource.is_some() {
            return Err(G4Error::StateConflict);
        }
        let intent_record = self
            .snapshot
            .intents
            .intents
            .iter()
            .find(|r| r.record.action_intent_id == intent)
            .ok_or(G4Error::IntentNotFound)?;
        let task = intent_record.record.durable_task_id;
        if request.matched.authorization().material().task() != task {
            return Err(G4Error::StateConflict);
        }
        if !self.snapshot.continuations.dispatch_enabled(task) {
            return Ok(request);
        }
        let payload = savana_kernel_protocol::v2::decode_task_execution_payload_v2(exact_plaintext)
            .map_err(|_| G4Error::StateConflict)?;
        if payload.content() != request.matched.content() {
            return Err(G4Error::StateConflict);
        }
        // The original G7 record, not a fresh source lookup, owns replay input.
        // G7 and the post-G3 pre-seal check still validate that original record.
        if self
            .snapshot
            .dispatch
            .entries
            .iter()
            .any(|e| e.core.subject.tool_action_intent_id() == Some(intent))
        {
            return Ok(request);
        }
        let key = self.snapshot.continuations.managed_admission_key(
            &self.snapshot.tasks,
            task,
            &payload,
            now,
        )?;
        let evidence = self.issue_managed_resource_evidence_v04(
            task,
            request.matched.content(),
            key,
            signer.ok_or(G4Error::StateConflict)?,
            now,
        )?;
        Ok(request.with_continuation_resource(evidence))
    }

    /// Additional pre-seal check for managed source inputs. Call only AFTER the
    /// current G3/reader gate. Success is not a transferable execution capability.
    /// External/non-managed tasks retain their existing path.
    pub fn check_managed_execution_handoff_v04(
        &self,
        prepared: &super::KernelPreparedDispatchV2,
        exact_plaintext: &[u8],
        declassification_node: Digest32V2,
        now: UnixMillisV2,
    ) -> Result<(), G4Error> {
        self.ensure_usable()?;
        let entry = self
            .snapshot
            .dispatch
            .entries
            .iter()
            .find(|e| e.core.execution_nonce == prepared.preparation().execution_nonce())
            .ok_or(G4Error::StateConflict)?;
        if entry.core_digest != prepared.preparation().dispatch_core_digest()
            || entry.core.durable_task_id != prepared.core().durable_task_id()
            || entry.sealed_envelope_digest != prepared.sealed_envelope_digest()
            || entry.consumed_ticket_digest != prepared.consumed_ticket_digest()
        {
            return Err(G4Error::StateConflict);
        }
        self.snapshot.continuations.check_execution_handoff(
            entry,
            &self.snapshot.tasks,
            exact_plaintext,
            declassification_node,
            now,
        )
    }

    /// Private original-input read for host audit/bridge code. Checks exact task,
    /// original nonce and dispatch-core identity; never refreshes a missing pin.
    /// This is NOT a G3 handoff, executor ticket or effect-time authorization.
    pub fn managed_execution_snapshot_v04(
        &self,
        task: DurableTaskIdV2,
        execution: Nonce32V2,
        expected_core: Digest32V2,
    ) -> Result<super::ManagedExecutionSnapshotV04, G4Error> {
        self.ensure_usable()?;
        let entry = self
            .snapshot
            .dispatch
            .entries
            .iter()
            .find(|e| e.core.execution_nonce == execution)
            .ok_or(G4Error::StateConflict)?;
        if entry.core.durable_task_id != task || entry.core_digest != expected_core {
            return Err(G4Error::StateConflict);
        }
        self.snapshot
            .continuations
            .execution_snapshot(task, execution)
    }

    /// Private authenticated source administration; not an Agent tool. This
    /// registers a first-party source, never an arbitrary path-based adapter.
    pub fn install_managed_source_v04(
        &mut self,
        source: super::VerifiedManagedSourceV04,
        now: UnixMillisV2,
    ) -> Result<(), G4Error> {
        self.ensure_usable()?;
        let mut next = self.snapshot.clone();
        if next.continuations.install_managed_source(
            source,
            self.namespace.installation_id(),
            now,
        )? {
            self.commit(next)?;
        }
        Ok(())
    }

    /// Private source ingestion. The host must authenticate the writer. No
    /// business-effect permission is implied by creating an object here.
    pub fn create_managed_resource_v04(
        &mut self,
        source: [u8; 32],
        namespace: [u8; 32],
        label: &str,
        content: &[u8],
        now: UnixMillisV2,
    ) -> Result<savana_continuation_core::ledger::ResourceKey, G4Error> {
        self.ensure_usable()?;
        let mut next = self.snapshot.clone();
        let key = next
            .continuations
            .managed
            .create(source, namespace, label, content, now)?;
        self.commit(next)?;
        Ok(key)
    }

    /// Private authenticated source edit/delete with optimistic revision. None
    /// deletes current content but retains the ID forever within this source.
    pub fn update_managed_resource_v04(
        &mut self,
        key: savana_continuation_core::ledger::ResourceKey,
        expected_revision: u64,
        value: Option<(&str, &[u8])>,
        now: UnixMillisV2,
    ) -> Result<(), G4Error> {
        self.ensure_usable()?;
        let mut next = self.snapshot.clone();
        if next
            .continuations
            .managed
            .update(key, expected_revision, value, now)?
        {
            self.commit(next)?;
        }
        Ok(())
    }

    /// Private read; never serialize this to the model or public status channel.
    pub fn managed_resource_v04(
        &self,
        key: savana_continuation_core::ledger::ResourceKey,
    ) -> Result<super::ManagedResourceViewV04, G4Error> {
        self.ensure_usable()?;
        self.snapshot.continuations.managed.view(key)
    }

    /// Source identity evidence, not execution authority. The trusted host
    /// supplies a separately provisioned issuer key. G7 rechecks current object
    /// revision under its owner transaction; no read/issue TOCTOU exemption.
    pub fn issue_managed_resource_evidence_v04(
        &self,
        task: DurableTaskIdV2,
        action: &savana_kernel_protocol::v2::ActionContentV2,
        key: savana_continuation_core::ledger::ResourceKey,
        signer: &ed25519_dalek::SigningKey,
        now: UnixMillisV2,
    ) -> Result<super::ContinuationResourceEvidenceV04, G4Error> {
        use ed25519_dalek::Signer;
        self.ensure_usable()?;
        if signer.verifying_key().to_bytes() != self.snapshot.continuations.resource_issuer(task)? {
            return Err(G4Error::StateConflict);
        }
        let fact = self.snapshot.continuations.managed_fact(
            &self.snapshot.tasks,
            task,
            action,
            key,
            now,
        )?;
        let signature = signer.sign(&fact.signing_digest()?).to_bytes();
        super::ContinuationResourceEvidenceV04::from_signed(
            &serde_json::to_vec(&fact).map_err(|_| G4Error::StateConflict)?,
            &signature,
        )
    }

    /// Enroll an unused task in additional G7 stable-resource accounting. This
    /// does not issue any execution permission or reset pre-existing history.
    pub fn install_continuation_dispatch_policy_v04(
        &mut self,
        policy: super::VerifiedContinuationDispatchPolicyV04,
        now: UnixMillisV2,
    ) -> Result<(), G4Error> {
        self.ensure_usable()?;
        let mut next = self.snapshot.clone();
        if next
            .continuations
            .install_dispatch(policy, &next.tasks, &next.dispatch, now)?
        {
            self.commit(next)?;
        }
        Ok(())
    }

    /// Signed bounded STORAGE registration. No execution/disclosure authority.
    /// The trusted host authenticates the administrator and selects issuer trust.
    pub fn install_continuation_storage_v04(
        &mut self,
        profile: VerifiedContinuationStorageV04,
        now: UnixMillisV2,
    ) -> Result<(), G4Error> {
        self.ensure_usable()?;
        let mut next = self.snapshot.clone();
        if next.continuations.install(profile, &next.tasks, now)? {
            self.commit(next)?;
        }
        Ok(())
    }

    /// Atomic with this owner's encrypted state and anti-rollback anchor.
    /// A recorded reservation is bookkeeping, NOT a substitute for G7 prepare.
    pub fn update_continuation_storage_v04(
        &mut self,
        task: DurableTaskIdV2,
        expected_revision: u64,
        updates: Vec<ContinuationStorageUpdateV04>,
        now: UnixMillisV2,
    ) -> Result<(), G4Error> {
        self.ensure_usable()?;
        let mut next = self.snapshot.clone();
        if next
            .continuations
            .update(task, expected_revision, updates, &next.tasks, now)?
        {
            self.commit(next)?;
        }
        Ok(())
    }

    /// Private audit/recovery view, including retained history after revocation.
    /// The caller authenticates the reader; bytes are not an outbound capability.
    pub fn continuation_storage_v04(
        &self,
        task: DurableTaskIdV2,
    ) -> Result<ContinuationStorageViewV04, G4Error> {
        self.ensure_usable()?;
        self.snapshot.continuations.view(task)
    }

    /// Persist before showing approval. This stores unprivileged material only.
    pub fn record_pending_task_authorization(
        &mut self,
        draft: TaskAuthorizationDraftV2,
        request_digest: Digest32V2,
    ) -> Result<PendingTaskAuthorizationV2, G4Error> {
        self.ensure_usable()?;
        if draft.installation_digest() != self.namespace.installation_id() {
            return Err(G4Error::StateConflict);
        }
        if let Some(existing) = self.snapshot.issuance.find(request_digest) {
            return if existing.draft() == &draft {
                Ok(existing.clone())
            } else {
                Err(G4Error::StateConflict)
            };
        }
        let previous = match self.snapshot.tasks.current(draft.task())? {
            None if draft.revision() == 1 => None,
            Some(s)
                if !s.revoked()
                    && s.authorization().material().authorization_id()
                        == draft.authorization_id()
                    && s.authorization().material().principal() == draft.principal()
                    && s.authorization().material().revision().checked_add(1)
                        == Some(draft.revision()) =>
            {
                Some(s.authorization().digest())
            }
            _ => return Err(G4Error::StateConflict),
        };
        let mut next = self.snapshot.clone();
        next.issuance.record(draft, request_digest, previous)?;
        let record = next
            .issuance
            .find(request_digest)
            .cloned()
            .ok_or(G4Error::StateConflict)?;
        self.commit(next)?;
        Ok(record)
    }
    pub fn pending_task_authorization(
        &self,
        request: Digest32V2,
    ) -> Result<Option<&PendingTaskAuthorizationV2>, G4Error> {
        self.ensure_usable()?;
        Ok(self.snapshot.issuance.find(request))
    }
    /// Read-only issuance history. Callers must authenticate the principal before
    /// exposing even request identifiers; this API does not grant recovery rights.
    pub fn task_authorization_issuance_history(
        &self,
        task: DurableTaskIdV2,
    ) -> Result<Vec<&PendingTaskAuthorizationV2>, G4Error> {
        self.ensure_usable()?;
        Ok(self.snapshot.issuance.for_task(task).collect())
    }
    pub fn installed_task_authorization_draft(
        &self,
        digest: Digest32V2,
    ) -> Result<Option<&TaskAuthorizationDraftV2>, G4Error> {
        self.ensure_usable()?;
        Ok(self.snapshot.issuance.installed_draft(digest))
    }
    pub fn attach_task_authorization_approval(
        &mut self,
        request: Digest32V2,
        envelope: SignedApprovalEnvelopeV2,
        display_authentication: savana_kernel_protocol::v2::SignedUiAuthenticationEnvelopeV2,
    ) -> Result<(), G4Error> {
        self.ensure_usable()?;
        let mut next = self.snapshot.clone();
        if next
            .issuance
            .attach_envelope(request, envelope, display_authentication)?
        {
            self.commit(next)?;
        }
        Ok(())
    }
    /// Grant installation and pending-record settlement are one owner commit.
    pub fn install_pending_task_authorization(
        &mut self,
        request: Digest32V2,
        authorization: VerifiedTaskAuthorizationV2,
    ) -> Result<(), G4Error> {
        self.ensure_usable()?;
        let current = self
            .snapshot
            .tasks
            .current(authorization.material().task())?
            .map(|s| s.authorization().digest());
        let mut next = self.snapshot.clone();
        if next.issuance.finish(request, &authorization, current)? {
            next.tasks
                .install(authorization, self.namespace.installation_id())?;
            self.commit(next)?;
        }
        Ok(())
    }
    pub fn install_verified_task_authorization(
        &mut self,
        authorization: VerifiedTaskAuthorizationV2,
    ) -> Result<(), G4Error> {
        self.ensure_usable()?;
        let mut next = self.snapshot.clone();
        if next
            .tasks
            .install(authorization, self.namespace.installation_id())?
        {
            self.commit(next)?;
        }
        Ok(())
    }
    pub fn revoke_task_authorization(&mut self, task: DurableTaskIdV2) -> Result<(), G4Error> {
        self.ensure_usable()?;
        let mut next = self.snapshot.clone();
        if next.tasks.revoke(task)? {
            self.commit(next)?;
        }
        Ok(())
    }
    pub fn task_authorization_state(
        &self,
        task: DurableTaskIdV2,
    ) -> Result<TaskAuthorizationStateV2, G4Error> {
        self.ensure_usable()?;
        self.snapshot.tasks.projection(task)
    }
    /// Missing authority is distinct from a corrupt or unavailable owner.
    pub fn find_task_authorization_state(
        &self,
        task: DurableTaskIdV2,
    ) -> Result<Option<TaskAuthorizationStateV2>, G4Error> {
        self.ensure_usable()?;
        match self.snapshot.tasks.current(task)? {
            Some(_) => self.snapshot.tasks.projection(task).map(Some),
            None => Ok(None),
        }
    }
    pub fn task_dispatch_binding(
        &self,
        nonce: Nonce32V2,
    ) -> Result<&TaskDispatchBindingV2, G4Error> {
        self.ensure_usable()?;
        self.snapshot
            .tasks
            .binding(nonce)
            .ok_or(G4Error::StateConflict)
    }
    pub fn open(
        path: &Path,
        master_encryption_key: [u8; 32],
        namespace: DurableStateNamespaceV2,
        rollback_anchor: Box<dyn RollbackProtectedStateAnchorV2>,
    ) -> Result<Self, G4Error> {
        Self::open_with_anchor(path, master_encryption_key, rollback_anchor, namespace)
    }

    fn open_with_anchor(
        path: &Path,
        master_encryption_key: [u8; 32],
        mut rollback_anchor: Box<dyn RollbackProtectedStateAnchorV2>,
        namespace: DurableStateNamespaceV2,
    ) -> Result<Self, G4Error> {
        if path.file_name().and_then(|name| name.to_str()) != Some(STATE_FILE_NAME)
            || master_encryption_key.iter().all(|byte| *byte == 0)
        {
            return Err(G4Error::DurableStateIo);
        }
        let master_encryption_key = Zeroizing::new(master_encryption_key);
        let encryption_key = derive_state_encryption_key(&master_encryption_key, namespace)?;
        let anchored_path = DurableAnchoredPathV2::open(path)?;
        let lock = LedgerLock::acquire_at(
            &anchored_path.parent,
            OsStr::new(STATE_LOCK_FILE_NAME),
            anchored_path.owner_uid,
            anchored_path.owner_gid,
        )
        .map_err(|_| G4Error::DurableStateIo)?;
        anchored_path.recheck_parent()?;
        let anchored_head = rollback_anchor.current_head()?;
        let (snapshot, current_head) = match anchored_path.read_existing()? {
            Some(bytes) => {
                let snapshot = decode_encrypted_snapshot(&bytes, &encryption_key, namespace)?;
                let snapshot_head = RollbackProtectedStateHeadV2 {
                    sequence: snapshot.sequence,
                    state_digest: state_head_digest(namespace, &bytes),
                };
                if snapshot_head == anchored_head {
                    (snapshot, snapshot_head)
                } else if snapshot.sequence
                    == anchored_head
                        .sequence
                        .checked_add(1)
                        .ok_or(G4Error::DurableStateRollback)?
                    && snapshot.previous_state_digest == anchored_head.state_digest
                {
                    rollback_anchor.compare_and_advance(anchored_head, snapshot_head)?;
                    (snapshot, snapshot_head)
                } else {
                    return Err(G4Error::DurableStateRollback);
                }
            }
            None => {
                if anchored_head != RollbackProtectedStateHeadV2::GENESIS {
                    return Err(G4Error::DurableStateRollback);
                }
                (
                    DurableG4SnapshotV2::default(),
                    RollbackProtectedStateHeadV2::GENESIS,
                )
            }
        };
        Ok(Self {
            path: path.to_owned(),
            anchored_path,
            namespace,
            encryption_key,
            snapshot,
            current_head,
            rollback_anchor,
            poisoned: false,
            #[cfg(test)]
            before_next_commit_hook: None,
            _lock: lock,
        })
    }

    #[cfg(test)]
    pub(crate) fn open_for_test(
        path: &Path,
        encryption_key: [u8; 32],
        rollback_anchor: TestRollbackProtectedStateAnchorV2,
    ) -> Result<Self, G4Error> {
        Self::open_for_test_in_namespace(
            path,
            encryption_key,
            rollback_anchor,
            DurableStateNamespaceV2::new_for_test(0xd4, 0x54),
        )
    }

    #[cfg(test)]
    pub(crate) fn open_for_test_in_namespace(
        path: &Path,
        encryption_key: [u8; 32],
        rollback_anchor: TestRollbackProtectedStateAnchorV2,
        namespace: DurableStateNamespaceV2,
    ) -> Result<Self, G4Error> {
        let parent = path.parent().ok_or(G4Error::DurableStateIo)?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
            .map_err(|_| G4Error::DurableStateIo)?;
        Self::open_with_anchor(path, encryption_key, Box::new(rollback_anchor), namespace)
    }

    #[cfg(test)]
    pub(crate) fn set_before_next_commit_hook_for_test(
        &mut self,
        hook: impl FnOnce() -> Result<(), G4Error> + Send + 'static,
    ) {
        self.before_next_commit_hook = Some(Box::new(hook));
    }

    pub(crate) fn create_or_replay_intent(
        &mut self,
        proposal: VerifiedToolProposalV2,
        material: VerifiedActionIntentMaterialV2,
    ) -> Result<ActionIntentResolutionV2, G4Error> {
        self.ensure_usable()?;
        if proposal.action_material_digest != action_intent_material_digest_v2(&material)? {
            return Err(G4Error::InvalidIntentBinding);
        }
        let mut next = self.snapshot.clone();
        let prior_intents = next.intents.intents.len();
        let prior_replay = next.intents.replay.len();
        let resolution = next.intents.create_or_replay(
            proposal.request_id,
            proposal.proposal_request_digest,
            proposal.installation_id,
            proposal.active_state_manifest_digest,
            proposal.durable_run_id,
            proposal.durable_task_id,
            material,
        )?;
        if next.intents.intents.len() != prior_intents || next.intents.replay.len() != prior_replay
        {
            self.commit(next)?;
        }
        Ok(resolution)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_or_replay_verified_intent(
        &mut self,
        request_id: RequestIdV2,
        authenticated_canonical_request: &[u8],
        installation_id: Digest32V2,
        active_state_manifest_digest: Digest32V2,
        durable_run_id: DurableRunIdV2,
        durable_task_id: DurableTaskIdV2,
        material: VerifiedActionIntentMaterialV2,
    ) -> Result<ActionIntentResolutionV2, G4Error> {
        let proposal = VerifiedToolProposalV2::from_authenticated_decoded_request(
            request_id,
            authenticated_canonical_request,
            installation_id,
            active_state_manifest_digest,
            durable_run_id,
            durable_task_id,
            &material,
        )?;
        self.create_or_replay_intent(proposal, material)
    }

    pub(crate) fn reserve_quota(
        &mut self,
        verified_limit: VerifiedQuotaLimitV2,
        durable_run_id: DurableRunIdV2,
        subject: DispatchQuotaSubjectV2,
        dispatch_subject_digest: Digest32V2,
        execution_nonce: Nonce32V2,
    ) -> Result<DispatchQuotaMutationV2, G4Error> {
        self.ensure_usable()?;
        let mut next = self.snapshot.clone();
        let mutation = next.quota.reserve_or_replay(
            verified_limit,
            durable_run_id,
            subject,
            dispatch_subject_digest,
            execution_nonce,
        )?;
        if mutation.kind() == DispatchQuotaMutationKindV2::Applied {
            self.commit(next)?;
        }
        Ok(mutation)
    }

    pub(crate) fn transition_quota(
        &mut self,
        execution_nonce: Nonce32V2,
        dispatch_subject_digest: Digest32V2,
        disposition: AuthenticatedEffectDispositionV2,
    ) -> Result<DispatchQuotaMutationV2, G4Error> {
        self.ensure_usable()?;
        let mut next = self.snapshot.clone();
        let mutation = next.quota.transition_or_replay(
            execution_nonce,
            dispatch_subject_digest,
            disposition,
        )?;
        if mutation.kind() == DispatchQuotaMutationKindV2::Applied {
            self.commit(next)?;
        }
        Ok(mutation)
    }

    pub fn quota_counter(
        &self,
        durable_run_id: DurableRunIdV2,
        subject: DispatchQuotaSubjectV2,
    ) -> Result<DispatchQuotaCounterV2, G4Error> {
        self.ensure_usable()?;
        self.snapshot.quota.counter(durable_run_id, subject)
    }

    /// Historical query-only records. Does not create a ticket, renew a session
    /// or require today's root/plan to authorize yesterday's effect settlement.
    pub fn recover_fused_executions_v04(
        &self,
        task: DurableTaskIdV2,
    ) -> Result<Vec<super::RecoveredFusedExecutionV04>, G4Error> {
        self.ensure_usable()?;
        self.snapshot.continuations.planning.recover_executions(
            task,
            &self.snapshot.tasks,
            &self.snapshot.dispatch,
            &self.snapshot.intents,
        )
    }

    /// Trusted scheduler inventory, including revoked/expired historical tasks.
    /// Old executions without a persisted result scope are never reconstructed.
    /// This carries no authority to resend or to publish an observation.
    pub fn recover_all_scoped_fused_executions_v04(
        &self,
    ) -> Result<Vec<super::RecoveredFusedExecutionV04>, G4Error> {
        self.ensure_usable()?;
        self.snapshot
            .continuations
            .planning
            .recover_scoped_executions(
                &self.snapshot.tasks,
                &self.snapshot.dispatch,
                &self.snapshot.intents,
            )
    }

    /// Host-private checkpoint after the exact signed outcome and vault commit,
    /// before executor cleanup. A reference cannot be replaced or attached to
    /// an uncompleted effect. It stores no plaintext or process document handle.
    pub fn record_fused_result_commit_v04(
        &mut self,
        task: DurableTaskIdV2,
        nonce: Nonce32V2,
        commit: Digest32V2,
    ) -> Result<(), G4Error> {
        self.ensure_usable()?;
        let mut next = self.snapshot.clone();
        if !next.continuations.planning.record_result_commit(
            task,
            nonce,
            commit,
            &next.dispatch,
            None,
        )? {
            return Ok(());
        }
        self.commit(next)
    }

    /// Commit downstream data and its original success checkpoint atomically,
    /// before executor cleanup. Never a model/public input or effect grant.
    pub fn record_fused_result_value_v04(
        &mut self,
        task: DurableTaskIdV2,
        nonce: Nonce32V2,
        commit: Digest32V2,
        value: super::FusedOwnedResultV04,
    ) -> Result<(), G4Error> {
        self.ensure_usable()?;
        let mut next = self.snapshot.clone();
        if !next.continuations.planning.record_result_commit(
            task,
            nonce,
            commit,
            &next.dispatch,
            Some(value.0),
        )? {
            return Ok(());
        }
        self.commit(next)
    }

    /// Trusted host query; only declared downstream edges require retaining
    /// bounded result data. Ordinary terminal results keep their existing path.
    pub fn fused_execution_needs_result_v04(
        &self,
        task: DurableTaskIdV2,
        nonce: Nonce32V2,
    ) -> Result<bool, G4Error> {
        self.ensure_usable()?;
        self.snapshot
            .continuations
            .planning
            .needs_result_value(task, nonce)
    }

    /// Private candidate only: this never declassifies, charges a publication,
    /// signs an approval, creates a vault release or returns a public response.
    pub fn fused_final_result_candidate_v04(
        &self,
        task: DurableTaskIdV2,
        now: UnixMillisV2,
    ) -> Result<super::FusedFinalResultCandidateV04, G4Error> {
        self.ensure_usable()?;
        self.snapshot.continuations.planning.final_result(
            task,
            &self.snapshot.tasks,
            &self.snapshot.dispatch,
            now,
        )
    }

    pub fn recovery_projection(
        &self,
    ) -> Result<Vec<super::KernelDispatchRecoveryProjectionV2>, G4Error> {
        self.ensure_usable()?;
        self.snapshot.dispatch.recovery_projection()
    }

    /// Historical metadata only; confers no send or plaintext authority.
    pub fn recover_final_release_core_v04(
        &self,
        release: savana_kernel_protocol::v2::DurableReleaseIdV2,
    ) -> Result<Option<DispatchCoreV2>, G4Error> {
        self.ensure_usable()?;
        let mut cores = self.snapshot.dispatch.entries.iter().filter(|e|
            matches!(&e.core.subject, DispatchSubjectV2::FinalRelease { binding, .. } if binding.durable_release_id() == release));
        let result = cores.next().map(|e| e.core.clone());
        if cores.next().is_some() {
            return Err(G4Error::DurableStateCorrupt);
        }
        Ok(result)
    }

    pub fn authenticated_state_head(&self) -> Result<RollbackProtectedStateHeadV2, G4Error> {
        self.ensure_usable()?;
        Ok(self.current_head)
    }

    pub(crate) fn evaluate_g5(
        &mut self,
        registry: &VerifiedInternalValidatorRegistryV2,
        action_intent_id: ActionIntentIdV2,
        stored: &VerifiedStoredBindingsV2<'_>,
        ontology_evaluation: OntologyEvaluationV2,
        policy_disposition: G5PolicyDispositionV2,
    ) -> Result<G5DecisionResolutionV2, G4Error> {
        self.ensure_usable()?;
        let mut next = self.snapshot.clone();
        let record = next
            .intents
            .intents
            .iter()
            .find(|entry| entry.record.action_intent_id == action_intent_id)
            .map(|entry| entry.record.clone())
            .ok_or(G4Error::IntentNotFound)?;
        let input = VerifiedG5EvaluationInputV2::from_verified_g4(
            &record,
            stored,
            ontology_evaluation,
            policy_disposition,
        )
        .map_err(|_| G4Error::EvaluationError)?;
        let resolution = next
            .decisions
            .evaluate_or_replay(registry, input)
            .map_err(|error| match error {
                G5Error::StateConflict => G4Error::StateConflict,
                _ => G4Error::EvaluationError,
            })?;
        if resolution.kind() == G5DecisionResolutionKindV2::Created {
            next.intents
                .advance_verified(action_intent_id, ActionIntentStateV2::Evaluating)?;
            let decision_state = match resolution.branch() {
                G5DecisionBranchV2::Permit => ActionIntentStateV2::AuthorizedPolicy,
                G5DecisionBranchV2::RequireApproval => ActionIntentStateV2::NeedsApproval,
                G5DecisionBranchV2::Deny => ActionIntentStateV2::Denied,
            };
            next.intents
                .advance_verified(action_intent_id, decision_state)?;
            self.commit(next)?;
        }
        Ok(resolution)
    }

    pub fn evaluate_verified_g5(
        &mut self,
        registry: &VerifiedInternalValidatorRegistryV2,
        action_intent_id: ActionIntentIdV2,
        stored: &VerifiedStoredBindingsV2<'_>,
        ontology_evaluation: super::VerifiedOntologyEvaluationV2,
        policy_disposition: super::VerifiedPolicyDispositionV2,
    ) -> Result<G5DecisionResolutionV2, G4Error> {
        self.evaluate_g5(
            registry,
            action_intent_id,
            stored,
            ontology_evaluation.inner,
            policy_disposition.inner,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare_tool_dispatch(
        &mut self,
        action_intent_id: ActionIntentIdV2,
        verified_limit: VerifiedQuotaLimitV2,
        approval: Option<VerifiedApprovalSettlementBindingV2>,
        ticket: VerifiedExecutionTicketV2,
        authority: VerifiedEffectGateAuthorityV2,
        sealed_envelope_digest: Digest32V2,
        task: &TaskDispatchAuthorizationV2,
        now: UnixMillisV2,
    ) -> Result<DispatchPreparationV2, G4Error> {
        self.ensure_usable()?;
        let guard_authority = authority.clone();
        guard_authority.while_current_connector_registry_head(|connector_registry_digest| {
            let mut next = self.snapshot.clone();
            if next.legacy_intents.contains(&action_intent_id) {
                return Err(G4Error::StateConflict);
            }
            let intent = next
                .intents
                .intents
                .iter()
                .find(|entry| entry.record.action_intent_id == action_intent_id)
                .cloned()
                .ok_or(G4Error::IntentNotFound)?;
            let decision = next
                .decisions
                .entries
                .iter()
                .find(|entry| entry.action_intent_id == action_intent_id)
                .map(|entry| entry.branch)
                .ok_or(G4Error::StateConflict)?;
            let preparation = next.dispatch.prepare_tool_or_replay_at_current_head(
                &intent.record,
                decision,
                approval,
                ticket,
                authority,
                sealed_envelope_digest,
                connector_registry_digest,
            )?;
            let journal_entry = next
                .dispatch
                .entries
                .iter_mut()
                .find(|e| e.core.execution_nonce == preparation.execution_nonce())
                .ok_or(G4Error::StateConflict)?;
            next.tasks.prepare(
                task,
                journal_entry,
                self.namespace.installation_id(),
                verified_limit.policy_binding_digest(),
                now,
                preparation.kind() == DispatchPreparationKindV2::Replay,
            )?;
            let preparation = super::dispatch::preparation(journal_entry, preparation.kind());
            next.continuations.prepare_dispatch(
                journal_entry,
                &next.tasks,
                task.continuation_resource.as_ref(),
                now,
                preparation.kind() == DispatchPreparationKindV2::Replay,
            )?;
            next.continuations.planning.prepare_execution(
                task.fused_operation,
                task.fused_recipe.as_ref(),
                task.fused_result_scope.as_ref(),
                &intent.record,
                &next.dispatch,
                &next.tasks,
                preparation.execution_nonce(),
                preparation.kind() == DispatchPreparationKindV2::Replay,
                now,
            )?;
            if preparation.kind() == DispatchPreparationKindV2::Replay {
                return Ok(preparation);
            }
            next.quota.reserve_or_replay(
                verified_limit,
                intent.record.durable_run_id,
                next.dispatch
                    .entries
                    .iter()
                    .find(|e| e.core.execution_nonce == preparation.execution_nonce())
                    .ok_or(G4Error::StateConflict)?
                    .quota_subject,
                preparation.dispatch_subject_digest(),
                preparation.execution_nonce(),
            )?;
            if decision == G5DecisionBranchV2::RequireApproval {
                next.intents
                    .advance_verified(action_intent_id, ActionIntentStateV2::AuthorizedApproval)?;
            }
            next.intents
                .advance_verified(action_intent_id, ActionIntentStateV2::DispatchPrepared)?;
            self.commit(next)?;
            Ok(preparation)
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn prepare_verified_tool_dispatch(
        &mut self,
        _action_intent_id: ActionIntentIdV2,
        _verified_limit: VerifiedQuotaLimitV2,
        _approval: Option<super::VerifiedToolApprovalSettlementV2>,
        _ticket: super::ResolvedExecutionTicketV2,
        _authority: super::VerifiedEffectGateLeaseV2,
        _sealed_envelope_digest: Digest32V2,
    ) -> Result<super::KernelPreparedDispatchV2, G4Error> {
        // Staged compatibility entry point: never mint missing task authority.
        self.ensure_usable()?;
        Err(G4Error::StateConflict)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn prepare_task_bound_tool_dispatch(
        &mut self,
        action_intent_id: ActionIntentIdV2,
        verified_limit: VerifiedQuotaLimitV2,
        approval: Option<super::VerifiedToolApprovalSettlementV2>,
        ticket: super::ResolvedExecutionTicketV2,
        authority: super::VerifiedEffectGateLeaseV2,
        sealed_envelope_digest: Digest32V2,
        task: &TaskDispatchAuthorizationV2,
        now: UnixMillisV2,
    ) -> Result<super::KernelPreparedDispatchV2, G4Error> {
        let super::ResolvedExecutionTicketV2 {
            inner: ticket,
            ticket_digest,
        } = ticket;
        let preparation = self.prepare_tool_dispatch(
            action_intent_id,
            verified_limit,
            approval.map(|value| value.inner),
            ticket,
            authority.inner,
            sealed_envelope_digest,
            task,
            now,
        )?;
        let core = self.dispatch_core(preparation.execution_nonce())?;
        Ok(super::KernelPreparedDispatchV2::new(
            preparation,
            core,
            ticket_digest,
            sealed_envelope_digest,
            self.task_dispatch_binding(preparation.execution_nonce())?
                .clone(),
        ))
    }

    pub(crate) fn prepare_final_release_dispatch(
        &mut self,
        release: &VerifiedFinalReleaseDispatchV2,
        verified_limit: VerifiedQuotaLimitV2,
        approval: VerifiedFinalReleaseApprovalBindingV2,
        ticket: VerifiedFinalReleaseTicketV2,
        authority: VerifiedEffectGateAuthorityV2,
        sealed_envelope_digest: Digest32V2,
        task: &TaskDispatchAuthorizationV2,
        now: UnixMillisV2,
    ) -> Result<DispatchPreparationV2, G4Error> {
        self.ensure_usable()?;
        // Continuation-resource publishing remains unsupported. Fused terminal
        // publishing has its own checked path, never an ordinary release bypass.
        if self
            .snapshot
            .continuations
            .dispatch_enabled(task.matched.authorization().material().task())
            || task.continuation_resource.is_some()
        {
            return Err(G4Error::StateConflict);
        }
        let enrolled = self
            .snapshot
            .continuations
            .planning
            .enrolled(task.matched.authorization().material().task());
        if enrolled != task.fused_final_result.is_some() {
            return Err(G4Error::StateConflict);
        }
        if let Some((digest, request)) = &task.fused_final_result {
            let candidate = self.fused_final_result_candidate_v04(
                task.matched.authorization().material().task(),
                now,
            )?;
            let spec = candidate.release().ok_or(G4Error::StateConflict)?;
            let original = self
                .recover_fused_executions_v04(candidate.task())?
                .into_iter()
                .find(|e| e.core() == candidate.core())
                .ok_or(G4Error::StateConflict)?;
            let resource = savana_kernel_protocol::v2::fused_final_result_resource_v04(
                candidate.task(),
                candidate.source(),
                original.descriptor(),
            )
            .map_err(|_| G4Error::StateConflict)?;
            let delivery = savana_kernel_protocol::v2::decode_final_result_release_delivery_v04(
                &request.canonical_json(),
            )
            .map_err(|_| G4Error::StateConflict)?;
            if candidate.digest() != *digest
                || candidate.root() != task.matched.authorization().digest()
                || candidate.core().durable_run_id() != release.durable_run_id()
                || spec.clause != task.matched.content().clause_id()
                || delivery.resource() != resource
                || delivery.turn_binding().as_bytes() != &spec.turn
                || delivery.payload() != candidate.private_payload()
                || task.matched.content().action()
                    != &request
                        .action_alternative(Digest32V2::new(spec.descriptor))
                        .map_err(|_| G4Error::StateConflict)?
                || task.matched.content().payload_digest() != request.payload_digest()
                || request.profile()
                    != &savana_kernel_protocol::v2::final_result_release_business_profile_v04(
                        request.profile().target_identity(),
                        request.profile().credential_identity(),
                    )
                    .map_err(|_| G4Error::StateConflict)?
                || release.binding().release_payload_digest()
                    != super::task_authorization::hash_parts(
                        b"SAVANA_FINAL_RELEASE_PAYLOAD_V2\0",
                        &[candidate.private_payload()],
                    )
            {
                return Err(G4Error::StateConflict);
            }
        }
        let guard_authority = authority.clone();
        guard_authority.while_current_connector_registry_head(|connector_registry_digest| {
            let mut next = self.snapshot.clone();
            let preparation = next
                .dispatch
                .prepare_final_release_or_replay_at_current_head(
                    release,
                    approval,
                    ticket,
                    authority,
                    sealed_envelope_digest,
                    connector_registry_digest,
                )?;
            let journal_entry = next
                .dispatch
                .entries
                .iter_mut()
                .find(|e| e.core.execution_nonce == preparation.execution_nonce())
                .ok_or(G4Error::StateConflict)?;
            next.tasks.prepare(
                task,
                journal_entry,
                self.namespace.installation_id(),
                verified_limit.policy_binding_digest(),
                now,
                preparation.kind() == DispatchPreparationKindV2::Replay,
            )?;
            let preparation = super::dispatch::preparation(journal_entry, preparation.kind());
            if preparation.kind() == DispatchPreparationKindV2::Replay {
                return Ok(preparation);
            }
            next.quota.reserve_or_replay(
                verified_limit,
                release.durable_run_id(),
                journal_entry.quota_subject,
                preparation.dispatch_subject_digest(),
                preparation.execution_nonce(),
            )?;
            self.commit(next)?;
            Ok(preparation)
        })
    }

    pub fn prepare_verified_final_release_dispatch(
        &mut self,
        _release: &super::VerifiedFinalReleaseRecordV2,
        _verified_limit: VerifiedQuotaLimitV2,
        _approval: &super::VerifiedFinalReleaseSettlementV2,
        _ticket: super::ResolvedFinalReleaseTicketV2,
        _authority: super::VerifiedEffectGateLeaseV2,
        _sealed_envelope_digest: Digest32V2,
    ) -> Result<super::KernelPreparedDispatchV2, G4Error> {
        self.ensure_usable()?;
        Err(G4Error::StateConflict)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn prepare_task_bound_final_release_dispatch(
        &mut self,
        release: &super::VerifiedFinalReleaseRecordV2,
        verified_limit: VerifiedQuotaLimitV2,
        approval: &super::VerifiedFinalReleaseSettlementV2,
        ticket: super::ResolvedFinalReleaseTicketV2,
        authority: super::VerifiedEffectGateLeaseV2,
        sealed_envelope_digest: Digest32V2,
        task: &TaskDispatchAuthorizationV2,
        now: UnixMillisV2,
    ) -> Result<super::KernelPreparedDispatchV2, G4Error> {
        let expected_subject = DispatchQuotaSubjectV2::final_release(
            release.inner.binding().release_quota_subject_digest(),
        );
        let verified_limit =
            super::production::validate_quota_subject(verified_limit, expected_subject)?;
        let super::ResolvedFinalReleaseTicketV2 {
            inner: ticket,
            ticket_digest,
        } = ticket;
        let preparation = self.prepare_final_release_dispatch(
            &release.inner,
            verified_limit,
            approval.inner,
            ticket,
            authority.inner,
            sealed_envelope_digest,
            task,
            now,
        )?;
        let core = self.dispatch_core(preparation.execution_nonce())?;
        Ok(super::KernelPreparedDispatchV2::new(
            preparation,
            core,
            ticket_digest,
            sealed_envelope_digest,
            self.task_dispatch_binding(preparation.execution_nonce())?
                .clone(),
        ))
    }

    pub fn reconcile_signed_tool_dispatch(
        &mut self,
        receipt: &SignedExecutorDispositionReceiptV2,
        expected_key_id: Ed25519KeyIdV2,
        public_key: [u8; 32],
        now: savana_kernel_protocol::v2::UnixMillisV2,
    ) -> Result<KernelDispatchStateV2, G4Error> {
        let entry = self.dispatch_entry_for_receipt(receipt, expected_key_id, public_key, now)?;
        if !matches!(entry.core.subject, DispatchSubjectV2::ToolExecution { .. }) {
            return Err(G4Error::StateConflict);
        }
        self.reconcile_tool_dispatch_with_outcome(entry.proof, true)
    }

    pub fn reconcile_signed_final_release_dispatch(
        &mut self,
        receipt: &SignedExecutorDispositionReceiptV2,
        expected_key_id: Ed25519KeyIdV2,
        public_key: [u8; 32],
        now: savana_kernel_protocol::v2::UnixMillisV2,
    ) -> Result<KernelDispatchStateV2, G4Error> {
        let entry = self.dispatch_entry_for_receipt(receipt, expected_key_id, public_key, now)?;
        if !matches!(entry.core.subject, DispatchSubjectV2::FinalRelease { .. }) {
            return Err(G4Error::StateConflict);
        }
        self.reconcile_final_release_dispatch_with_outcome(entry.proof, true)
    }

    pub fn verify_task_outcome(
        &self,
        receipt: &SignedExecutorDispositionReceiptV2,
        expected_key_id: Ed25519KeyIdV2,
        public_key: [u8; 32],
        now: UnixMillisV2,
    ) -> Result<VerifiedTaskOutcomeV2, G4Error> {
        self.ensure_usable()?;
        let entry = self
            .snapshot
            .dispatch
            .entries
            .iter()
            .find_map(|entry| {
                receipt
                    .verify_terminal_for_entry(entry, expected_key_id, public_key, now)
                    .ok()
                    .map(|proof| VerifiedReceiptEntryV2 {
                        core: entry.core.clone(),
                        proof,
                    })
            })
            .ok_or(G4Error::StateConflict)?;
        if !matches!(
            entry.proof.disposition.kind(),
            AuthenticatedEffectDispositionKindV2::KnownSuccess
                | AuthenticatedEffectDispositionKindV2::FailedNoEffect
        ) {
            return Err(G4Error::StateConflict);
        }
        Ok(VerifiedTaskOutcomeV2 {
            proof: entry.proof,
            authorization_digest: self
                .task_dispatch_binding(entry.proof.execution_nonce)?
                .authorization_digest(),
        })
    }

    pub fn reconcile_task_outcome(
        &mut self,
        outcome: VerifiedTaskOutcomeV2,
    ) -> Result<KernelDispatchStateV2, G4Error> {
        if self
            .task_dispatch_binding(outcome.proof.execution_nonce)?
            .authorization_digest()
            != outcome.authorization_digest
        {
            return Err(G4Error::StateConflict);
        }
        let core = self.dispatch_core(outcome.proof.execution_nonce)?;
        if matches!(core.subject, DispatchSubjectV2::ToolExecution { .. }) {
            self.reconcile_tool_dispatch_with_outcome(outcome.proof, true)
        } else {
            self.reconcile_final_release_dispatch_with_outcome(outcome.proof, true)
        }
    }

    pub fn reconcile_typed_effect_started_final_release_dispatch(
        &mut self,
        receipt: &SignedExecutorEffectStartedReceiptV2,
        expected_key_id: Ed25519KeyIdV2,
        public_key: [u8; 32],
        now: savana_kernel_protocol::v2::UnixMillisV2,
    ) -> Result<KernelDispatchStateV2, G4Error> {
        let entry = self.dispatch_entry_for_typed_effect_receipt(
            receipt,
            expected_key_id,
            public_key,
            Some(now),
        )?;
        if !matches!(entry.core.subject, DispatchSubjectV2::FinalRelease { .. }) {
            return Err(G4Error::StateConflict);
        }
        self.reconcile_final_release_dispatch(entry.proof)
    }

    pub fn reconcile_typed_effect_started_tool_dispatch(
        &mut self,
        receipt: &SignedExecutorEffectStartedReceiptV2,
        expected_key_id: Ed25519KeyIdV2,
        public_key: [u8; 32],
        now: savana_kernel_protocol::v2::UnixMillisV2,
    ) -> Result<KernelDispatchStateV2, G4Error> {
        let entry = self.dispatch_entry_for_typed_effect_receipt(
            receipt,
            expected_key_id,
            public_key,
            Some(now),
        )?;
        if !matches!(entry.core.subject, DispatchSubjectV2::ToolExecution { .. }) {
            return Err(G4Error::StateConflict);
        }
        self.reconcile_tool_dispatch(entry.proof)
    }

    pub fn reconcile_authenticated_completion(
        &mut self,
        receipt: &SignedExecutorEffectStartedReceiptV2,
        expected_key_id: Ed25519KeyIdV2,
        public_key: [u8; 32],
        completion_evidence_digest: Digest32V2,
        now: savana_kernel_protocol::v2::UnixMillisV2,
    ) -> Result<KernelDispatchStateV2, G4Error> {
        if is_zero(completion_evidence_digest.as_bytes()) {
            return Err(G4Error::StateConflict);
        }
        let entry = self.dispatch_entry_for_typed_effect_receipt(
            receipt,
            expected_key_id,
            public_key,
            Some(now),
        )?;
        let proof = VerifiedExecutorDispositionV2 {
            execution_nonce: entry.proof.execution_nonce,
            dispatch_core_digest: entry.proof.dispatch_core_digest,
            dispatch_subject_digest: entry.proof.dispatch_subject_digest,
            evidence_digest: completion_evidence_digest,
            disposition: AuthenticatedEffectDispositionV2::from_verified_known_success(),
        };
        if matches!(entry.core.subject, DispatchSubjectV2::ToolExecution { .. }) {
            self.reconcile_tool_dispatch(proof)
        } else {
            self.reconcile_final_release_dispatch(proof)
        }
    }

    pub fn reconcile_authenticated_failed_no_effect(
        &mut self,
        execution_nonce: Nonce32V2,
        dispatch_core_digest: Digest32V2,
        dispatch_subject_digest: Digest32V2,
        evidence_digest: Digest32V2,
    ) -> Result<KernelDispatchStateV2, G4Error> {
        self.reconcile_authenticated_exact_disposition(
            execution_nonce,
            dispatch_core_digest,
            dispatch_subject_digest,
            evidence_digest,
            AuthenticatedEffectDispositionV2::from_verified_failed_no_effect(),
        )
    }

    pub fn reconcile_authenticated_indeterminate(
        &mut self,
        execution_nonce: Nonce32V2,
        dispatch_core_digest: Digest32V2,
        dispatch_subject_digest: Digest32V2,
        evidence_digest: Digest32V2,
    ) -> Result<KernelDispatchStateV2, G4Error> {
        self.reconcile_authenticated_exact_disposition(
            execution_nonce,
            dispatch_core_digest,
            dispatch_subject_digest,
            evidence_digest,
            AuthenticatedEffectDispositionV2::from_verified_indeterminate(),
        )
    }

    fn reconcile_authenticated_exact_disposition(
        &mut self,
        execution_nonce: Nonce32V2,
        dispatch_core_digest: Digest32V2,
        dispatch_subject_digest: Digest32V2,
        evidence_digest: Digest32V2,
        disposition: AuthenticatedEffectDispositionV2,
    ) -> Result<KernelDispatchStateV2, G4Error> {
        self.ensure_usable()?;
        if [
            execution_nonce.as_bytes(),
            dispatch_core_digest.as_bytes(),
            dispatch_subject_digest.as_bytes(),
            evidence_digest.as_bytes(),
        ]
        .iter()
        .any(|value| is_zero(value))
        {
            return Err(G4Error::StateConflict);
        }
        let entry = self
            .snapshot
            .dispatch
            .entries
            .iter()
            .find(|entry| entry.core.execution_nonce == execution_nonce)
            .ok_or(G4Error::StateConflict)?;
        if entry.core_digest != dispatch_core_digest
            || entry.core.dispatch_subject_digest != dispatch_subject_digest
        {
            return Err(G4Error::StateConflict);
        }
        let proof = VerifiedExecutorDispositionV2 {
            execution_nonce,
            dispatch_core_digest,
            dispatch_subject_digest,
            evidence_digest,
            disposition,
        };
        if matches!(entry.core.subject, DispatchSubjectV2::ToolExecution { .. }) {
            self.reconcile_tool_dispatch(proof)
        } else {
            self.reconcile_final_release_dispatch(proof)
        }
    }

    pub fn reconcile_stored_typed_effect_started_final_release_dispatch(
        &mut self,
        receipt: &SignedExecutorEffectStartedReceiptV2,
        expected_key_id: Ed25519KeyIdV2,
        public_key: [u8; 32],
    ) -> Result<KernelDispatchStateV2, G4Error> {
        let entry = self.dispatch_entry_for_typed_effect_receipt(
            receipt,
            expected_key_id,
            public_key,
            None,
        )?;
        if !matches!(entry.core.subject, DispatchSubjectV2::FinalRelease { .. }) {
            return Err(G4Error::StateConflict);
        }
        self.reconcile_final_release_dispatch(entry.proof)
    }

    pub fn reconcile_stored_signed_tool_dispatch(
        &mut self,
        receipt: &SignedExecutorDispositionReceiptV2,
        expected_key_id: Ed25519KeyIdV2,
        public_key: [u8; 32],
    ) -> Result<KernelDispatchStateV2, G4Error> {
        let entry = self.dispatch_entry_for_stored_receipt(receipt, expected_key_id, public_key)?;
        if !matches!(entry.core.subject, DispatchSubjectV2::ToolExecution { .. }) {
            return Err(G4Error::StateConflict);
        }
        self.reconcile_tool_dispatch_with_outcome(entry.proof, true)
    }

    pub fn reconcile_stored_signed_final_release_dispatch(
        &mut self,
        receipt: &SignedExecutorDispositionReceiptV2,
        expected_key_id: Ed25519KeyIdV2,
        public_key: [u8; 32],
    ) -> Result<KernelDispatchStateV2, G4Error> {
        let entry = self.dispatch_entry_for_stored_receipt(receipt, expected_key_id, public_key)?;
        if !matches!(entry.core.subject, DispatchSubjectV2::FinalRelease { .. }) {
            return Err(G4Error::StateConflict);
        }
        self.reconcile_final_release_dispatch_with_outcome(entry.proof, true)
    }

    /// Records kernel-local no-effect recovery for legacy, non-task-bound rows
    /// only while the dispatch WAL proves execution never crossed effect start.
    /// Task-bound rows reject this bare recovery claim and require an expected-key
    /// signed no-effect receipt through the verified outcome/reconciliation path.
    ///
    /// This path is used when the executor has no journal row after a crash;
    /// it cannot produce an executor receipt because no executor operation
    /// existed. Exact nonce/core/subject matching prevents recovery from
    /// selecting or minting a different dispatch.
    pub fn abort_dispatch_before_effect(
        &mut self,
        execution_nonce: Nonce32V2,
        dispatch_core_digest: Digest32V2,
        dispatch_subject_digest: Digest32V2,
        recovery_evidence_digest: Digest32V2,
    ) -> Result<KernelDispatchStateV2, G4Error> {
        self.ensure_usable()?;
        if [
            execution_nonce.as_bytes(),
            dispatch_core_digest.as_bytes(),
            dispatch_subject_digest.as_bytes(),
            recovery_evidence_digest.as_bytes(),
        ]
        .iter()
        .any(|value| is_zero(value))
        {
            return Err(G4Error::StateConflict);
        }
        let entry = self
            .snapshot
            .dispatch
            .entries
            .iter()
            .find(|entry| entry.core.execution_nonce == execution_nonce)
            .ok_or(G4Error::StateConflict)?;
        if entry.core_digest != dispatch_core_digest
            || entry.core.dispatch_subject_digest != dispatch_subject_digest
            || !matches!(
                entry.state,
                KernelDispatchStateV2::Prepared | KernelDispatchStateV2::Dispatching
            )
            || entry.effect_evidence_digest.is_some()
        {
            return Err(G4Error::StateConflict);
        }
        let tool_execution = matches!(entry.core.subject, DispatchSubjectV2::ToolExecution { .. });
        let proof = VerifiedExecutorDispositionV2 {
            execution_nonce,
            dispatch_core_digest,
            dispatch_subject_digest,
            evidence_digest: recovery_evidence_digest,
            disposition: AuthenticatedEffectDispositionV2::from_verified_failed_no_effect(),
        };
        if tool_execution {
            self.reconcile_tool_dispatch(proof)
        } else {
            self.reconcile_final_release_dispatch(proof)
        }
    }

    pub(crate) fn reconcile_tool_dispatch(
        &mut self,
        proof: VerifiedExecutorDispositionV2,
    ) -> Result<KernelDispatchStateV2, G4Error> {
        self.reconcile_tool_dispatch_with_outcome(proof, false)
    }

    fn reconcile_tool_dispatch_with_outcome(
        &mut self,
        proof: VerifiedExecutorDispositionV2,
        verified_terminal: bool,
    ) -> Result<KernelDispatchStateV2, G4Error> {
        self.ensure_usable()?;
        let mut next = self.snapshot.clone();
        next.tasks.reconcile(proof, verified_terminal)?;
        let entry = next
            .dispatch
            .entries
            .iter()
            .find(|entry| entry.core.execution_nonce == proof.execution_nonce)
            .cloned()
            .ok_or(G4Error::StateConflict)?;
        let state = next.dispatch.reconcile(proof)?;
        next.quota.transition_or_replay(
            entry.core.execution_nonce,
            entry.core.dispatch_subject_digest,
            proof.disposition,
        )?;
        let action_intent_id = entry
            .core
            .subject
            .tool_action_intent_id()
            .ok_or(G4Error::StateConflict)?;
        let intent_state = match state {
            KernelDispatchStateV2::Prepared => return Err(G4Error::StateConflict),
            KernelDispatchStateV2::Dispatching | KernelDispatchStateV2::EffectStarted => {
                ActionIntentStateV2::Dispatching
            }
            KernelDispatchStateV2::CompletionCommitted => ActionIntentStateV2::Succeeded,
            KernelDispatchStateV2::FailedNoEffect => ActionIntentStateV2::FailedNoEffect,
            KernelDispatchStateV2::Indeterminate => ActionIntentStateV2::Indeterminate,
        };
        let current_intent_state = next
            .intents
            .intents
            .iter()
            .find(|intent| intent.record.action_intent_id == action_intent_id)
            .ok_or(G4Error::IntentNotFound)?
            .current_state;
        // A verified terminal receipt can be the first response observed after
        // prepare (the dispatch/effect-start acknowledgement may have been lost).
        // Advance both intent stages in this same atomic snapshot; never invent
        // a separate effect-start receipt or loosen ordinary intent transitions.
        if verified_terminal
            && current_intent_state == ActionIntentStateV2::DispatchPrepared
            && intent_state == ActionIntentStateV2::Succeeded
        {
            next.intents
                .advance_verified(action_intent_id, ActionIntentStateV2::Dispatching)?;
        }
        // Task, dispatch and quota reconciliation above have already verified
        // the exact replay. A repeated receipt must not fail at the intent index.
        if current_intent_state != intent_state {
            next.intents
                .advance_verified(action_intent_id, intent_state)?;
        }
        self.commit(next)?;
        Ok(state)
    }

    pub(crate) fn reconcile_final_release_dispatch(
        &mut self,
        proof: VerifiedExecutorDispositionV2,
    ) -> Result<KernelDispatchStateV2, G4Error> {
        self.reconcile_final_release_dispatch_with_outcome(proof, false)
    }

    fn reconcile_final_release_dispatch_with_outcome(
        &mut self,
        proof: VerifiedExecutorDispositionV2,
        verified_terminal: bool,
    ) -> Result<KernelDispatchStateV2, G4Error> {
        self.ensure_usable()?;
        let mut next = self.snapshot.clone();
        next.tasks.reconcile(proof, verified_terminal)?;
        let entry = next
            .dispatch
            .entries
            .iter()
            .find(|entry| entry.core.execution_nonce == proof.execution_nonce)
            .cloned()
            .ok_or(G4Error::StateConflict)?;
        if !matches!(entry.core.subject, DispatchSubjectV2::FinalRelease { .. }) {
            return Err(G4Error::StateConflict);
        }
        let state = next.dispatch.reconcile(proof)?;
        next.quota.transition_or_replay(
            entry.core.execution_nonce,
            entry.core.dispatch_subject_digest,
            proof.disposition,
        )?;
        self.commit(next)?;
        Ok(state)
    }

    #[cfg(test)]
    pub(crate) fn advance_intent_for_test(
        &mut self,
        action_intent_id: ActionIntentIdV2,
        state: ActionIntentStateV2,
    ) -> Result<(), G4Error> {
        self.ensure_usable()?;
        let mut next = self.snapshot.clone();
        next.intents.advance_for_test(action_intent_id, state)?;
        self.commit(next)
    }

    fn ensure_usable(&self) -> Result<(), G4Error> {
        if self.poisoned {
            Err(G4Error::DurableCommitUncertain)
        } else {
            Ok(())
        }
    }

    fn dispatch_core(&self, nonce: Nonce32V2) -> Result<DispatchCoreV2, G4Error> {
        self.snapshot
            .dispatch
            .entries
            .iter()
            .find(|entry| entry.core.execution_nonce == nonce)
            .map(|entry| entry.core.clone())
            .ok_or(G4Error::StateConflict)
    }

    fn dispatch_entry_for_receipt(
        &self,
        receipt: &SignedExecutorDispositionReceiptV2,
        expected_key_id: Ed25519KeyIdV2,
        public_key: [u8; 32],
        now: savana_kernel_protocol::v2::UnixMillisV2,
    ) -> Result<VerifiedReceiptEntryV2, G4Error> {
        self.ensure_usable()?;
        for entry in &self.snapshot.dispatch.entries {
            if let Ok(proof) = receipt.verify_for_entry(entry, expected_key_id, public_key, now) {
                return Ok(VerifiedReceiptEntryV2 {
                    core: entry.core.clone(),
                    proof,
                });
            }
        }
        Err(G4Error::StateConflict)
    }

    fn dispatch_entry_for_stored_receipt(
        &self,
        receipt: &SignedExecutorDispositionReceiptV2,
        expected_key_id: Ed25519KeyIdV2,
        public_key: [u8; 32],
    ) -> Result<VerifiedReceiptEntryV2, G4Error> {
        self.ensure_usable()?;
        for entry in &self.snapshot.dispatch.entries {
            if let Ok(proof) = receipt.verify_stored_for_entry(entry, expected_key_id, public_key) {
                return Ok(VerifiedReceiptEntryV2 {
                    core: entry.core.clone(),
                    proof,
                });
            }
        }
        Err(G4Error::StateConflict)
    }

    fn dispatch_entry_for_typed_effect_receipt(
        &self,
        receipt: &SignedExecutorEffectStartedReceiptV2,
        expected_key_id: Ed25519KeyIdV2,
        public_key: [u8; 32],
        now: Option<savana_kernel_protocol::v2::UnixMillisV2>,
    ) -> Result<VerifiedReceiptEntryV2, G4Error> {
        self.ensure_usable()?;
        receipt
            .verify(expected_key_id, public_key)
            .map_err(|_| G4Error::StateConflict)?;
        let unsigned = *receipt.unsigned();
        let entry = self
            .snapshot
            .dispatch
            .entries
            .iter()
            .find(|entry| entry.core.execution_nonce == unsigned.execution_nonce())
            .ok_or(G4Error::StateConflict)?;
        if unsigned.installation_id() != entry.core.installation_id
            || unsigned.active_state_manifest_digest() != entry.core.active_state_manifest_digest
            || unsigned.deployment_generation() != entry.core.deployment_generation
            || unsigned.effect_fence_epoch() != entry.core.effect_fence_epoch
            || unsigned.dispatch_core_digest() != entry.core_digest
            || unsigned.dispatch_subject_digest() != entry.core.dispatch_subject_digest
            || unsigned.executor_identity() != entry.core.executor_identity
            || now.is_some_and(|now| {
                unsigned.started_at().get() > now.get() || now.get() >= entry.core.expires_at.get()
            })
        {
            return Err(G4Error::StateConflict);
        }
        Ok(VerifiedReceiptEntryV2 {
            core: entry.core.clone(),
            proof: VerifiedExecutorDispositionV2 {
                execution_nonce: unsigned.execution_nonce(),
                dispatch_core_digest: unsigned.dispatch_core_digest(),
                dispatch_subject_digest: unsigned.dispatch_subject_digest(),
                evidence_digest: receipt.digest(),
                disposition: AuthenticatedEffectDispositionV2::from_verified_effect_started_receipt(
                ),
            },
        })
    }

    fn commit(&mut self, mut next: DurableG4SnapshotV2) -> Result<(), G4Error> {
        // Migration happens only as part of an ordinary successful transaction.
        // Existing deployments stay schema 4 until explicitly installing the
        // signed v0.4 storage (5), dispatch (6), source (7), execution pin (8),
        // explicit managed input handoff policy (9), admin retry journal (10),
        // fused-planning outbox (11), exact fused execution bindings (12),
        // signed delivery slots and durable scheduler cursor (13), or separate
        // immutable recipe approval (14), atomic recipe execution receipt (15),
        // immutable owner-authenticated local inputs (16), or historical fused
        // result scopes/checkpoints (17).
        // Recipe approval alone grants no effect.
        // Never downgrade and never backfill historical inputs from current data.
        next.payload_schema = if next.continuations.planning.has_result_scopes()
            || self.snapshot.payload_schema >= 17
        {
            17
        } else if next.continuations.planning.has_inputs() || self.snapshot.payload_schema >= 16 {
            16
        } else if next.continuations.planning.has_recipe_executions()
            || self.snapshot.payload_schema >= 15
        {
            15
        } else if next.continuations.planning.has_recipe_approvals()
            || self.snapshot.payload_schema >= 14
        {
            14
        } else if next.continuations.planning.has_delivery_schedule()
            || self.snapshot.payload_schema >= 13
        {
            13
        } else if next.continuations.planning.has_execution_bindings()
            || self.snapshot.payload_schema >= 12
        {
            12
        } else if !next.continuations.planning.is_empty() || self.snapshot.payload_schema >= 11 {
            11
        } else if !next.continuations.admin.is_empty() || self.snapshot.payload_schema >= 10 {
            10
        } else if next.continuations.managed.has_handoff_policy()
            || self.snapshot.payload_schema >= 9
        {
            9
        } else if next.continuations.has_execution_snapshots() || self.snapshot.payload_schema >= 8
        {
            8
        } else if !next.continuations.managed.is_empty() || self.snapshot.payload_schema >= 7 {
            7
        } else if next.continuations.has_dispatch_policies() || self.snapshot.payload_schema >= 6 {
            6
        } else if !next.continuations.is_empty() || self.snapshot.payload_schema >= 5 {
            5
        } else {
            PAYLOAD_SCHEMA_VERSION
        };
        next.sequence = self
            .current_head
            .sequence
            .checked_add(1)
            .ok_or(G4Error::DurableStateCorrupt)?;
        next.previous_state_digest = self.current_head.state_digest;
        validate_snapshot(&next)?;
        let bytes = encode_encrypted_snapshot(&next, &self.encryption_key, self.namespace)?;
        let next_head = RollbackProtectedStateHeadV2 {
            sequence: next.sequence,
            state_digest: state_head_digest(self.namespace, &bytes),
        };
        #[cfg(test)]
        if let Some(hook) = self.before_next_commit_hook.take() {
            hook()?;
        }
        self._lock.recheck().map_err(|_| G4Error::DurableStateIo)?;
        match self.anchored_path.replace(&bytes) {
            Ok(()) => {
                if self
                    .rollback_anchor
                    .compare_and_advance(self.current_head, next_head)
                    .is_err()
                {
                    self.poisoned = true;
                    return Err(G4Error::DurableCommitUncertain);
                }
                self.snapshot = next;
                self.current_head = next_head;
                Ok(())
            }
            Err(error) => {
                if error.phase() == PersistencePhase::AfterRename {
                    self.poisoned = true;
                    Err(G4Error::DurableCommitUncertain)
                } else {
                    Err(G4Error::DurableStateIo)
                }
            }
        }
    }
}

fn encode_encrypted_snapshot(
    snapshot: &DurableG4SnapshotV2,
    key: &[u8; 32],
    namespace: DurableStateNamespaceV2,
) -> Result<Vec<u8>, G4Error> {
    let payload = encode_snapshot_payload(snapshot)?;
    let mut nonce = [0_u8; STATE_NONCE_BYTES];
    getrandom::getrandom(&mut nonce).map_err(|_| G4Error::DurableStateIo)?;
    let aad = state_encryption_aad(
        namespace,
        snapshot.sequence,
        snapshot.previous_state_digest,
        &nonce,
    );
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| G4Error::DurableStateIo)?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: payload.as_slice(),
                aad: &aad,
            },
        )
        .map_err(|_| G4Error::DurableStateIo)?;
    encode_encrypted_envelope(
        snapshot.sequence,
        snapshot.previous_state_digest,
        &nonce,
        &ciphertext,
    )
}

fn encode_encrypted_envelope(
    sequence: u64,
    previous_state_digest: Digest32V2,
    nonce: &[u8; STATE_NONCE_BYTES],
    ciphertext: &[u8],
) -> Result<Vec<u8>, G4Error> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(5)
        .and_then(|encoder| encoder.u16(STATE_SCHEMA_VERSION))
        .and_then(|encoder| encoder.u64(sequence))
        .map_err(|_| G4Error::DurableStateCorrupt)?;
    previous_state_digest
        .encode(&mut encoder, &mut ())
        .map_err(|_| G4Error::DurableStateCorrupt)?;
    encoder
        .bytes(nonce)
        .and_then(|encoder| encoder.bytes(ciphertext))
        .map_err(|_| G4Error::DurableStateCorrupt)?;
    let bytes = encoder.into_writer();
    if bytes.len() as u64 > MAX_STATE_BYTES {
        return Err(G4Error::IntentLimitExceeded);
    }
    Ok(bytes)
}

fn decode_encrypted_snapshot(
    bytes: &[u8],
    key: &[u8; 32],
    namespace: DurableStateNamespaceV2,
) -> Result<DurableG4SnapshotV2, G4Error> {
    if bytes.len() as u64 > MAX_STATE_BYTES {
        return Err(G4Error::DurableStateCorrupt);
    }
    let mut decoder = minicbor::Decoder::new(bytes);
    require_array(&mut decoder, 5)?;
    if decoder.u16().map_err(|_| G4Error::DurableStateCorrupt)? != STATE_SCHEMA_VERSION {
        return Err(G4Error::DurableStateCorrupt);
    }
    let sequence = decoder.u64().map_err(|_| G4Error::DurableStateCorrupt)?;
    let previous_state_digest = Digest32V2::new(decode_fixed::<32>(&mut decoder)?);
    let nonce = decode_fixed::<STATE_NONCE_BYTES>(&mut decoder)?;
    let ciphertext = decoder.bytes().map_err(|_| G4Error::DurableStateCorrupt)?;
    if decoder.position() != bytes.len() {
        return Err(G4Error::DurableStateCorrupt);
    }
    if encode_encrypted_envelope(sequence, previous_state_digest, &nonce, ciphertext)? != bytes {
        return Err(G4Error::DurableStateCorrupt);
    }
    let aad = state_encryption_aad(namespace, sequence, previous_state_digest, &nonce);
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| G4Error::DurableStateIo)?;
    let payload = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| G4Error::DurableStateAuthentication)?,
    );
    let snapshot = decode_snapshot_payload(&payload)?;
    if snapshot.sequence != sequence
        || snapshot.previous_state_digest != previous_state_digest
        || encode_snapshot_payload(&snapshot)?.as_slice() != payload.as_slice()
    {
        return Err(G4Error::DurableStateCorrupt);
    }
    Ok(snapshot)
}

fn encode_snapshot_payload(snapshot: &DurableG4SnapshotV2) -> Result<Zeroizing<Vec<u8>>, G4Error> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(match snapshot.payload_schema {
            2 => 9,
            3 => 11,
            4 => 12,
            5..=17 => 13,
            _ => return Err(G4Error::DurableStateCorrupt),
        })
        .and_then(|encoder| encoder.u16(snapshot.payload_schema))
        .and_then(|encoder| encoder.u64(snapshot.sequence))
        .map_err(|_| G4Error::DurableStateCorrupt)?;
    snapshot
        .previous_state_digest
        .encode(&mut encoder, &mut ())
        .map_err(|_| G4Error::DurableStateCorrupt)?;
    encode_intents(&mut encoder, &snapshot.intents)?;
    encode_replay(&mut encoder, &snapshot.intents)?;
    encode_counters(&mut encoder, &snapshot.quota)?;
    encode_reservations(&mut encoder, &snapshot.quota)?;
    encode_g5_decisions(&mut encoder, &snapshot.decisions)?;
    encode_dispatch_entries(&mut encoder, &snapshot.dispatch)?;
    if snapshot.payload_schema >= 3 {
        encoder
            .bytes(&snapshot.tasks.encode()?)
            .map_err(|_| G4Error::DurableStateCorrupt)?;
        encoder
            .array(snapshot.legacy_intents.len() as u64)
            .map_err(|_| G4Error::DurableStateCorrupt)?;
        for id in &snapshot.legacy_intents {
            encoder
                .bytes(id.as_bytes())
                .map_err(|_| G4Error::DurableStateCorrupt)?;
        }
    }
    if snapshot.payload_schema >= 4 {
        encoder
            .bytes(&snapshot.issuance.encode()?)
            .map_err(|_| G4Error::DurableStateCorrupt)?;
    }
    if snapshot.payload_schema >= 5 {
        encoder
            .bytes(&snapshot.continuations.encode()?)
            .map_err(|_| G4Error::DurableStateCorrupt)?;
    }
    Ok(Zeroizing::new(encoder.into_writer()))
}

fn encode_intents(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    index: &ActionIntentIndexV2,
) -> Result<(), G4Error> {
    encoder
        .array(index.intents.len() as u64)
        .map_err(|_| G4Error::DurableStateCorrupt)?;
    for entry in &index.intents {
        let record = &entry.record;
        encoder
            .array(11)
            .map_err(|_| G4Error::DurableStateCorrupt)?;
        record
            .action_intent_id
            .encode(encoder, &mut ())
            .map_err(|_| G4Error::DurableStateCorrupt)?;
        record
            .installation_id
            .encode(encoder, &mut ())
            .map_err(|_| G4Error::DurableStateCorrupt)?;
        record
            .active_state_manifest_digest
            .encode(encoder, &mut ())
            .map_err(|_| G4Error::DurableStateCorrupt)?;
        record
            .durable_run_id
            .encode(encoder, &mut ())
            .map_err(|_| G4Error::DurableStateCorrupt)?;
        record
            .durable_task_id
            .encode(encoder, &mut ())
            .map_err(|_| G4Error::DurableStateCorrupt)?;
        record
            .stable_proposal_digest
            .encode(encoder, &mut ())
            .map_err(|_| G4Error::DurableStateCorrupt)?;
        record
            .semantic_binding_digest
            .encode(encoder, &mut ())
            .map_err(|_| G4Error::DurableStateCorrupt)?;
        encode_material(encoder, &record.material)?;
        encode_pending_call_state(encoder, record.pending_call_state)?;
        encode_public_task_state(encoder, record.public_task_state)?;
        encoder
            .u16(entry.current_state.tag())
            .map_err(|_| G4Error::DurableStateCorrupt)?;
    }
    Ok(())
}

fn encode_material(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    material: &VerifiedActionIntentMaterialV2,
) -> Result<(), G4Error> {
    encoder.array(9).map_err(|_| G4Error::DurableStateCorrupt)?;
    material
        .binding
        .encode(encoder, &mut ())
        .map_err(|_| G4Error::DurableStateCorrupt)?;
    encoder
        .bytes(&material.selected_descriptor_canonical)
        .map_err(|_| G4Error::DurableStateCorrupt)?;
    material
        .descriptor_publisher_key_id
        .encode(encoder, &mut ())
        .map_err(|_| G4Error::DurableStateCorrupt)?;
    encoder
        .u32(material.registry_ordinal)
        .map_err(|_| G4Error::DurableStateCorrupt)?;
    material
        .policy_activation_digest
        .encode(encoder, &mut ())
        .map_err(|_| G4Error::DurableStateCorrupt)?;
    material
        .effective_retry_policy
        .encode(encoder, &mut ())
        .map_err(|_| G4Error::DurableStateCorrupt)?;
    encoder
        .array(material.normalized_arguments.len() as u64)
        .map_err(|_| G4Error::DurableStateCorrupt)?;
    for argument in &material.normalized_arguments {
        encoder.array(5).map_err(|_| G4Error::DurableStateCorrupt)?;
        argument
            .argument_name
            .encode(encoder, &mut ())
            .map_err(|_| G4Error::DurableStateCorrupt)?;
        argument
            .internal_slot_digest
            .encode(encoder, &mut ())
            .map_err(|_| G4Error::DurableStateCorrupt)?;
        argument
            .value_internal_id
            .encode(encoder, &mut ())
            .map_err(|_| G4Error::DurableStateCorrupt)?;
        argument
            .value_digest
            .encode(encoder, &mut ())
            .map_err(|_| G4Error::DurableStateCorrupt)?;
        argument
            .provenance_digest
            .encode(encoder, &mut ())
            .map_err(|_| G4Error::DurableStateCorrupt)?;
    }
    encoder
        .array(material.token_bindings.len() as u64)
        .map_err(|_| G4Error::DurableStateCorrupt)?;
    for token in &material.token_bindings {
        encoder.array(4).map_err(|_| G4Error::DurableStateCorrupt)?;
        token
            .token_slot_id
            .encode(encoder, &mut ())
            .map_err(|_| G4Error::DurableStateCorrupt)?;
        token
            .vault_segment_internal_id
            .encode(encoder, &mut ())
            .map_err(|_| G4Error::DurableStateCorrupt)?;
        token
            .credential_version_digest
            .encode(encoder, &mut ())
            .map_err(|_| G4Error::DurableStateCorrupt)?;
        token
            .executor_identity_digest
            .encode(encoder, &mut ())
            .map_err(|_| G4Error::DurableStateCorrupt)?;
    }
    let projection = &material.projection_outputs;
    encoder.array(9).map_err(|_| G4Error::DurableStateCorrupt)?;
    projection
        .tool_descriptor_digest
        .encode(encoder, &mut ())
        .map_err(|_| G4Error::DurableStateCorrupt)?;
    projection
        .destination_projection
        .encode(encoder, &mut ())
        .map_err(|_| G4Error::DurableStateCorrupt)?;
    projection
        .destination_projection_digest
        .encode(encoder, &mut ())
        .map_err(|_| G4Error::DurableStateCorrupt)?;
    encoder
        .bytes(projection.destination_canonical())
        .map_err(|_| G4Error::DurableStateCorrupt)?;
    projection
        .destination_digest
        .encode(encoder, &mut ())
        .map_err(|_| G4Error::DurableStateCorrupt)?;
    projection
        .display_projection
        .encode(encoder, &mut ())
        .map_err(|_| G4Error::DurableStateCorrupt)?;
    projection
        .display_projection_digest
        .encode(encoder, &mut ())
        .map_err(|_| G4Error::DurableStateCorrupt)?;
    encoder
        .bytes(projection.display_canonical())
        .map_err(|_| G4Error::DurableStateCorrupt)?;
    projection
        .display_digest
        .encode(encoder, &mut ())
        .map_err(|_| G4Error::DurableStateCorrupt)?;
    Ok(())
}

fn encode_pending_call_state(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    record: PendingCallStateRecordV2,
) -> Result<(), G4Error> {
    encoder.array(2).map_err(|_| G4Error::DurableStateCorrupt)?;
    record
        .action_intent_id
        .encode(encoder, &mut ())
        .map_err(|_| G4Error::DurableStateCorrupt)?;
    encoder
        .u16(record.state.tag())
        .map_err(|_| G4Error::DurableStateCorrupt)?;
    Ok(())
}

fn encode_public_task_state(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    record: PublicTaskStateRecordV2,
) -> Result<(), G4Error> {
    encoder.array(3).map_err(|_| G4Error::DurableStateCorrupt)?;
    record
        .durable_task_id
        .encode(encoder, &mut ())
        .map_err(|_| G4Error::DurableStateCorrupt)?;
    record
        .action_intent_id
        .encode(encoder, &mut ())
        .map_err(|_| G4Error::DurableStateCorrupt)?;
    encoder
        .u16(record.state.tag())
        .map_err(|_| G4Error::DurableStateCorrupt)?;
    Ok(())
}

fn encode_replay(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    index: &ActionIntentIndexV2,
) -> Result<(), G4Error> {
    encoder
        .array(index.replay.len() as u64)
        .map_err(|_| G4Error::DurableStateCorrupt)?;
    for replay in &index.replay {
        encoder.array(3).map_err(|_| G4Error::DurableStateCorrupt)?;
        replay
            .request_id
            .encode(encoder, &mut ())
            .map_err(|_| G4Error::DurableStateCorrupt)?;
        replay
            .stable_proposal_digest
            .encode(encoder, &mut ())
            .map_err(|_| G4Error::DurableStateCorrupt)?;
        replay
            .action_intent_id
            .encode(encoder, &mut ())
            .map_err(|_| G4Error::DurableStateCorrupt)?;
    }
    Ok(())
}

fn encode_counters(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    quota: &DispatchQuotaLedgerV2,
) -> Result<(), G4Error> {
    encoder
        .array(quota.counters.len() as u64)
        .map_err(|_| G4Error::DurableStateCorrupt)?;
    for entry in &quota.counters {
        encoder.array(4).map_err(|_| G4Error::DurableStateCorrupt)?;
        entry
            .durable_run_id
            .encode(encoder, &mut ())
            .map_err(|_| G4Error::DurableStateCorrupt)?;
        entry
            .subject
            .encode(encoder, &mut ())
            .map_err(|_| G4Error::DurableStateCorrupt)?;
        entry
            .verified_limit
            .encode(encoder, &mut ())
            .map_err(|_| G4Error::DurableStateCorrupt)?;
        entry
            .counter
            .encode(encoder, &mut ())
            .map_err(|_| G4Error::DurableStateCorrupt)?;
    }
    Ok(())
}

fn encode_reservations(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    quota: &DispatchQuotaLedgerV2,
) -> Result<(), G4Error> {
    encoder
        .array(quota.reservations.len() as u64)
        .map_err(|_| G4Error::DurableStateCorrupt)?;
    for entry in &quota.reservations {
        encoder.array(2).map_err(|_| G4Error::DurableStateCorrupt)?;
        entry
            .reservation
            .encode(encoder, &mut ())
            .map_err(|_| G4Error::DurableStateCorrupt)?;
        match entry.last_disposition {
            Some(disposition) => encoder
                .u16(effect_disposition_tag(disposition))
                .map_err(|_| G4Error::DurableStateCorrupt)?,
            None => encoder.null().map_err(|_| G4Error::DurableStateCorrupt)?,
        };
    }
    Ok(())
}

fn encode_g5_decisions(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    decisions: &G5DecisionIndexV2,
) -> Result<(), G4Error> {
    encoder
        .array(decisions.entries.len() as u64)
        .map_err(|_| G4Error::DurableStateCorrupt)?;
    for entry in &decisions.entries {
        encoder.array(5).map_err(|_| G4Error::DurableStateCorrupt)?;
        entry
            .action_intent_id
            .encode(encoder, &mut ())
            .map_err(|_| G4Error::DurableStateCorrupt)?;
        entry
            .evaluation_input_digest
            .encode(encoder, &mut ())
            .map_err(|_| G4Error::DurableStateCorrupt)?;
        encoder
            .u16(entry.branch.tag())
            .and_then(|encoder| encoder.array(entry.validator_decision_digests.len() as u64))
            .map_err(|_| G4Error::DurableStateCorrupt)?;
        for digest in &entry.validator_decision_digests {
            digest
                .encode(encoder, &mut ())
                .map_err(|_| G4Error::DurableStateCorrupt)?;
        }
        entry
            .decision_record_digest
            .encode(encoder, &mut ())
            .map_err(|_| G4Error::DurableStateCorrupt)?;
    }
    Ok(())
}

fn encode_dispatch_entries(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    dispatch: &KernelDispatchJournalV2,
) -> Result<(), G4Error> {
    encoder
        .array(dispatch.entries.len() as u64)
        .map_err(|_| G4Error::DurableStateCorrupt)?;
    for entry in &dispatch.entries {
        encoder.array(7).map_err(|_| G4Error::DurableStateCorrupt)?;
        entry
            .core
            .encode(encoder, &mut ())
            .map_err(|_| G4Error::DurableStateCorrupt)?;
        entry
            .core_digest
            .encode(encoder, &mut ())
            .map_err(|_| G4Error::DurableStateCorrupt)?;
        entry
            .quota_subject
            .encode(encoder, &mut ())
            .map_err(|_| G4Error::DurableStateCorrupt)?;
        entry
            .sealed_envelope_digest
            .encode(encoder, &mut ())
            .map_err(|_| G4Error::DurableStateCorrupt)?;
        entry
            .consumed_ticket_digest
            .encode(encoder, &mut ())
            .map_err(|_| G4Error::DurableStateCorrupt)?;
        encoder
            .u16(dispatch_state_tag(entry.state))
            .map_err(|_| G4Error::DurableStateCorrupt)?;
        match entry.effect_evidence_digest {
            Some(digest) => {
                digest
                    .encode(encoder, &mut ())
                    .map_err(|_| G4Error::DurableStateCorrupt)?;
            }
            None => {
                encoder.null().map_err(|_| G4Error::DurableStateCorrupt)?;
            }
        };
    }
    Ok(())
}

fn decode_snapshot_payload(payload: &[u8]) -> Result<DurableG4SnapshotV2, G4Error> {
    let mut decoder = minicbor::Decoder::new(payload);
    let fields = decoder.array().map_err(|_| G4Error::DurableStateCorrupt)?;
    let payload_schema = decoder.u16().map_err(|_| G4Error::DurableStateCorrupt)?;
    if !matches!(
        (payload_schema, fields),
        (2, Some(9)) | (3, Some(11)) | (4, Some(12)) | (5..=17, Some(13))
    ) {
        return Err(G4Error::DurableStateCorrupt);
    }
    let sequence = decoder.u64().map_err(|_| G4Error::DurableStateCorrupt)?;
    let previous_state_digest = Digest32V2::new(decode_fixed::<32>(&mut decoder)?);
    let intents = decode_intents(&mut decoder)?;
    let replay = decode_replay(&mut decoder)?;
    let counters = decode_counters(&mut decoder)?;
    let reservations = decode_reservations(&mut decoder)?;
    let decisions = decode_g5_decisions(&mut decoder)?;
    let dispatch = decode_dispatch_entries(&mut decoder)?;
    let tasks = if payload_schema >= 3 {
        TaskLedgerV2::decode(decoder.bytes().map_err(|_| G4Error::DurableStateCorrupt)?)?
    } else {
        TaskLedgerV2::default()
    };
    let legacy_intents = if payload_schema == 2 {
        intents.iter().map(|i| i.record.action_intent_id).collect()
    } else {
        let mut ids = Vec::new();
        for _ in 0..bounded_array(&mut decoder, MAX_INTENTS)? {
            ids.push(ActionIntentIdV2::new(decode_fixed::<32>(&mut decoder)?));
        }
        ids
    };
    let issuance = if payload_schema >= 4 {
        TaskIssuanceLedgerV2::decode(decoder.bytes().map_err(|_| G4Error::DurableStateCorrupt)?)?
    } else {
        TaskIssuanceLedgerV2::default()
    };
    let continuations = if payload_schema >= 5 {
        ContinuationTableV04::decode(decoder.bytes().map_err(|_| G4Error::DurableStateCorrupt)?)?
    } else {
        ContinuationTableV04::default()
    };
    if decoder.position() != payload.len() {
        return Err(G4Error::DurableStateCorrupt);
    }
    let snapshot = DurableG4SnapshotV2 {
        payload_schema,
        tasks,
        issuance,
        continuations,
        legacy_intents,
        sequence,
        previous_state_digest,
        intents: ActionIntentIndexV2 { intents, replay },
        quota: DispatchQuotaLedgerV2 {
            counters,
            reservations,
        },
        decisions: G5DecisionIndexV2 { entries: decisions },
        dispatch,
    };
    validate_snapshot(&snapshot)?;
    Ok(snapshot)
}

fn decode_intents(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<Vec<ActionIntentEntryV2>, G4Error> {
    let count = bounded_array(decoder, MAX_INTENTS)?;
    let mut intents = Vec::new();
    intents
        .try_reserve_exact(count)
        .map_err(|_| G4Error::AllocationFailure)?;
    for _ in 0..count {
        require_array(decoder, 11)?;
        let action_intent_id = ActionIntentIdV2::new(decode_fixed::<32>(decoder)?);
        let installation_id = Digest32V2::new(decode_fixed::<32>(decoder)?);
        let active_state_manifest_digest = Digest32V2::new(decode_fixed::<32>(decoder)?);
        let durable_run_id = DurableRunIdV2::new(decode_fixed::<32>(decoder)?);
        let durable_task_id = DurableTaskIdV2::new(decode_fixed::<32>(decoder)?);
        let stable_proposal_digest = Digest32V2::new(decode_fixed::<32>(decoder)?);
        let semantic_binding_digest = Digest32V2::new(decode_fixed::<32>(decoder)?);
        let material = decode_material(decoder)?;
        let pending_call_state = decode_pending_call_state(decoder)?;
        let public_task_state = decode_public_task_state(decoder)?;
        let current_state =
            decode_action_state(decoder.u16().map_err(|_| G4Error::DurableStateCorrupt)?)?;
        intents.push(ActionIntentEntryV2 {
            record: ActionIntentRecordV2 {
                action_intent_id,
                installation_id,
                active_state_manifest_digest,
                durable_run_id,
                durable_task_id,
                stable_proposal_digest,
                semantic_binding_digest,
                material,
                pending_call_state,
                public_task_state,
            },
            current_state,
        });
    }
    Ok(intents)
}

fn decode_material(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<VerifiedActionIntentMaterialV2, G4Error> {
    require_array(decoder, 9)?;
    let binding = decode_binding(decoder)?;
    let selected_descriptor_canonical = decoder
        .bytes()
        .map_err(|_| G4Error::DurableStateCorrupt)?
        .to_vec();
    if selected_descriptor_canonical.is_empty()
        || selected_descriptor_canonical.len() > MAX_DESCRIPTOR_BYTES
    {
        return Err(G4Error::DurableStateCorrupt);
    }
    let descriptor_publisher_key_id = Ed25519KeyIdV2::new(decode_fixed::<32>(decoder)?);
    let registry_ordinal = decoder.u32().map_err(|_| G4Error::DurableStateCorrupt)?;
    let policy_activation_digest = Digest32V2::new(decode_fixed::<32>(decoder)?);
    let descriptor = decode_unsigned_descriptor(&selected_descriptor_canonical)
        .map_err(|_| G4Error::DurableStateCorrupt)?;
    require_array(decoder, 2)?;
    let maximum_attempts = decoder.u16().map_err(|_| G4Error::DurableStateCorrupt)?;
    let maximum_elapsed_ns = decoder.u64().map_err(|_| G4Error::DurableStateCorrupt)?;
    let effective_retry_policy = BoundedConnectorRetryPolicyV2::new(
        descriptor.idempotency_contract(),
        maximum_attempts,
        maximum_elapsed_ns,
    )
    .map_err(|_| G4Error::DurableStateCorrupt)?;

    let argument_count = bounded_array(decoder, MAX_ARGUMENTS)?;
    let mut normalized_arguments = Vec::new();
    normalized_arguments
        .try_reserve_exact(argument_count)
        .map_err(|_| G4Error::AllocationFailure)?;
    for _ in 0..argument_count {
        require_array(decoder, 5)?;
        normalized_arguments.push(StableActionArgumentBindingV2 {
            argument_name: decode_argument_name(decoder)?,
            internal_slot_digest: InternalSlotDigestV2::new(decode_fixed::<32>(decoder)?),
            value_internal_id: ValueInternalIdV2::new(decode_fixed::<32>(decoder)?),
            value_digest: Digest32V2::new(decode_fixed::<32>(decoder)?),
            provenance_digest: Digest32V2::new(decode_fixed::<32>(decoder)?),
        });
    }

    let token_count = bounded_array(decoder, MAX_TOKENS)?;
    let mut token_bindings = Vec::new();
    token_bindings
        .try_reserve_exact(token_count)
        .map_err(|_| G4Error::AllocationFailure)?;
    for _ in 0..token_count {
        require_array(decoder, 4)?;
        token_bindings.push(ResolvedStoredTokenV2 {
            token_slot_id: decode_identifier(decoder)?,
            vault_segment_internal_id: Digest32V2::new(decode_fixed::<32>(decoder)?),
            credential_version_digest: Digest32V2::new(decode_fixed::<32>(decoder)?),
            executor_identity_digest: Digest32V2::new(decode_fixed::<32>(decoder)?),
        });
    }

    require_array(decoder, 9)?;
    let tool_descriptor_digest = Digest32V2::new(decode_fixed::<32>(decoder)?);
    let destination_projection =
        ProjectionIdV2::new(decoder.u32().map_err(|_| G4Error::DurableStateCorrupt)?);
    let destination_projection_digest = Digest32V2::new(decode_fixed::<32>(decoder)?);
    let destination_canonical = decode_bounded_sensitive_bytes(decoder)?;
    let destination_digest = Digest32V2::new(decode_fixed::<32>(decoder)?);
    let display_projection =
        DisplayProjectionIdV2::new(decoder.u32().map_err(|_| G4Error::DurableStateCorrupt)?);
    let display_projection_digest = Digest32V2::new(decode_fixed::<32>(decoder)?);
    let display_canonical = decode_bounded_sensitive_bytes(decoder)?;
    let display_digest = Digest32V2::new(decode_fixed::<32>(decoder)?);
    let projection_outputs = VerifiedProjectionOutputsV2 {
        tool_descriptor_digest,
        destination_projection,
        destination_projection_digest,
        destination_canonical,
        destination_digest,
        display_projection,
        display_projection_digest,
        display_canonical,
        display_digest,
    };
    let material = VerifiedActionIntentMaterialV2 {
        binding,
        selected_descriptor_canonical,
        descriptor_publisher_key_id,
        registry_ordinal,
        policy_activation_digest,
        effective_retry_policy,
        normalized_arguments,
        token_bindings,
        projection_outputs,
    };
    validate_material(&material)?;
    Ok(material)
}

fn decode_binding(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<ToolExecutionSemanticBindingV2, G4Error> {
    require_array(decoder, 11)?;
    let plan_revision_digest = PlanRevisionDigestV2::new(decode_fixed::<32>(decoder)?);
    let internal_step_id = InternalStepIdV2::new(decode_fixed::<32>(decoder)?);
    let tool_descriptor_digest = Digest32V2::new(decode_fixed::<32>(decoder)?);
    let argument_digest = Digest32V2::new(decode_fixed::<32>(decoder)?);
    let provenance_set_digest = Digest32V2::new(decode_fixed::<32>(decoder)?);
    let token_set_digest = Digest32V2::new(decode_fixed::<32>(decoder)?);
    let destination_digest = Digest32V2::new(decode_fixed::<32>(decoder)?);
    let display_projection_digest = Digest32V2::new(decode_fixed::<32>(decoder)?);
    let display_digest = Digest32V2::new(decode_fixed::<32>(decoder)?);
    let executor_identity_digest = Digest32V2::new(decode_fixed::<32>(decoder)?);
    let attempt_kind = decode_attempt_kind(decoder)?;
    ToolExecutionSemanticBindingV2::from_verified_authorization(
        plan_revision_digest,
        internal_step_id,
        tool_descriptor_digest,
        argument_digest,
        provenance_set_digest,
        token_set_digest,
        destination_digest,
        display_projection_digest,
        display_digest,
        ExecutorIdentityV2::new(*executor_identity_digest.as_bytes()),
        attempt_kind,
    )
    .map_err(|_| G4Error::DurableStateCorrupt)
}

fn decode_pending_call_state(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<PendingCallStateRecordV2, G4Error> {
    require_array(decoder, 2)?;
    Ok(PendingCallStateRecordV2 {
        action_intent_id: ActionIntentIdV2::new(decode_fixed::<32>(decoder)?),
        state: decode_pending_call_state_tag(
            decoder.u16().map_err(|_| G4Error::DurableStateCorrupt)?,
        )?,
    })
}

fn decode_public_task_state(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<PublicTaskStateRecordV2, G4Error> {
    require_array(decoder, 3)?;
    Ok(PublicTaskStateRecordV2 {
        durable_task_id: DurableTaskIdV2::new(decode_fixed::<32>(decoder)?),
        action_intent_id: ActionIntentIdV2::new(decode_fixed::<32>(decoder)?),
        state: decode_public_task_state_tag(
            decoder.u16().map_err(|_| G4Error::DurableStateCorrupt)?,
        )?,
    })
}

fn decode_replay(decoder: &mut minicbor::Decoder<'_>) -> Result<Vec<IntentReplayEntryV2>, G4Error> {
    let count = bounded_array(decoder, MAX_REPLAY)?;
    let mut replay = Vec::new();
    replay
        .try_reserve_exact(count)
        .map_err(|_| G4Error::AllocationFailure)?;
    for _ in 0..count {
        require_array(decoder, 3)?;
        replay.push(IntentReplayEntryV2 {
            request_id: RequestIdV2::new(decode_fixed::<16>(decoder)?),
            stable_proposal_digest: Digest32V2::new(decode_fixed::<32>(decoder)?),
            action_intent_id: ActionIntentIdV2::new(decode_fixed::<32>(decoder)?),
        });
    }
    Ok(replay)
}

fn decode_counters(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<Vec<DispatchQuotaCounterEntryV2>, G4Error> {
    let count = bounded_array(decoder, MAX_COUNTERS)?;
    let mut counters = Vec::new();
    counters
        .try_reserve_exact(count)
        .map_err(|_| G4Error::AllocationFailure)?;
    for _ in 0..count {
        require_array(decoder, 4)?;
        counters.push(DispatchQuotaCounterEntryV2 {
            durable_run_id: DurableRunIdV2::new(decode_fixed::<32>(decoder)?),
            subject: decode_quota_subject(decoder)?,
            verified_limit: decode_verified_quota_limit(decoder)?,
            counter: decode_quota_counter(decoder)?,
        });
    }
    Ok(counters)
}

fn decode_reservations(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<Vec<DispatchQuotaLedgerEntryV2>, G4Error> {
    let count = bounded_array(decoder, MAX_RESERVATIONS)?;
    let mut reservations = Vec::new();
    reservations
        .try_reserve_exact(count)
        .map_err(|_| G4Error::AllocationFailure)?;
    for _ in 0..count {
        require_array(decoder, 2)?;
        require_array(decoder, 5)?;
        let reservation = DispatchQuotaReservationV2 {
            durable_run_id: DurableRunIdV2::new(decode_fixed::<32>(decoder)?),
            quota_subject: decode_quota_subject(decoder)?,
            dispatch_subject_digest: Digest32V2::new(decode_fixed::<32>(decoder)?),
            execution_nonce: Nonce32V2::new(decode_fixed::<32>(decoder)?),
            state: decode_reservation_state(decoder)?,
        };
        let last_disposition = if decoder
            .datatype()
            .map_err(|_| G4Error::DurableStateCorrupt)?
            == minicbor::data::Type::Null
        {
            decoder.null().map_err(|_| G4Error::DurableStateCorrupt)?;
            None
        } else {
            Some(decode_effect_disposition(
                decoder.u16().map_err(|_| G4Error::DurableStateCorrupt)?,
            )?)
        };
        reservations.push(DispatchQuotaLedgerEntryV2 {
            reservation,
            last_disposition,
        });
    }
    Ok(reservations)
}

fn decode_g5_decisions(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<Vec<G5DecisionEntryV2>, G4Error> {
    let count = bounded_array(decoder, MAX_G5_DECISIONS)?;
    let mut decisions = Vec::new();
    decisions
        .try_reserve_exact(count)
        .map_err(|_| G4Error::AllocationFailure)?;
    for _ in 0..count {
        require_array(decoder, 5)?;
        let action_intent_id = ActionIntentIdV2::new(decode_fixed::<32>(decoder)?);
        let evaluation_input_digest = Digest32V2::new(decode_fixed::<32>(decoder)?);
        let branch =
            decode_g5_decision_branch(decoder.u16().map_err(|_| G4Error::DurableStateCorrupt)?)?;
        let digest_count = bounded_array(decoder, 32)?;
        let mut validator_decision_digests = Vec::new();
        validator_decision_digests
            .try_reserve_exact(digest_count)
            .map_err(|_| G4Error::AllocationFailure)?;
        for _ in 0..digest_count {
            validator_decision_digests.push(Digest32V2::new(decode_fixed::<32>(decoder)?));
        }
        let decision_record_digest = Digest32V2::new(decode_fixed::<32>(decoder)?);
        decisions.push(G5DecisionEntryV2 {
            action_intent_id,
            evaluation_input_digest,
            branch,
            validator_decision_digests,
            decision_record_digest,
        });
    }
    Ok(decisions)
}

fn decode_dispatch_entries(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<KernelDispatchJournalV2, G4Error> {
    let count = bounded_array(decoder, MAX_DISPATCH_ENTRIES)?;
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(count)
        .map_err(|_| G4Error::AllocationFailure)?;
    for _ in 0..count {
        require_array(decoder, 7)?;
        let core = decode_dispatch_core(decoder)?;
        let core_digest = Digest32V2::new(decode_fixed::<32>(decoder)?);
        let quota_subject = decode_quota_subject(decoder)?;
        let sealed_envelope_digest = Digest32V2::new(decode_fixed::<32>(decoder)?);
        let consumed_ticket_digest = Digest32V2::new(decode_fixed::<32>(decoder)?);
        let state =
            decode_dispatch_state(decoder.u16().map_err(|_| G4Error::DurableStateCorrupt)?)?;
        let effect_evidence_digest = if decoder
            .datatype()
            .map_err(|_| G4Error::DurableStateCorrupt)?
            == minicbor::data::Type::Null
        {
            decoder.null().map_err(|_| G4Error::DurableStateCorrupt)?;
            None
        } else {
            Some(Digest32V2::new(decode_fixed::<32>(decoder)?))
        };
        entries.push(KernelDispatchJournalEntryV2 {
            core,
            core_digest,
            quota_subject,
            sealed_envelope_digest,
            consumed_ticket_digest,
            state,
            effect_evidence_digest,
        });
    }
    Ok(KernelDispatchJournalV2 { entries })
}

fn decode_dispatch_core(decoder: &mut minicbor::Decoder<'_>) -> Result<DispatchCoreV2, G4Error> {
    let length = decoder.array().map_err(|_| G4Error::DurableStateCorrupt)?;
    let schema = decoder.u16().map_err(|_| G4Error::DurableStateCorrupt)?;
    if !matches!((length, schema), (Some(14), 2) | (Some(15), 3)) {
        return Err(G4Error::DurableStateCorrupt);
    }
    let installation_id = Digest32V2::new(decode_fixed::<32>(decoder)?);
    let active_state_manifest_digest = Digest32V2::new(decode_fixed::<32>(decoder)?);
    let deployment_generation = decoder.u64().map_err(|_| G4Error::DurableStateCorrupt)?;
    let effect_fence_epoch = decoder.u64().map_err(|_| G4Error::DurableStateCorrupt)?;
    let durable_task_id = DurableTaskIdV2::new(decode_fixed::<32>(decoder)?);
    let durable_run_id = DurableRunIdV2::new(decode_fixed::<32>(decoder)?);
    let execution_nonce = Nonce32V2::new(decode_fixed::<32>(decoder)?);
    let subject = decode_dispatch_subject(decoder)?;
    let dispatch_subject_digest = Digest32V2::new(decode_fixed::<32>(decoder)?);
    let executor_identity = ExecutorIdentityV2::new(decode_fixed::<32>(decoder)?);
    let executor_key_id =
        savana_kernel_protocol::v2::HpkeX25519KeyIdV2::new(decode_fixed::<32>(decoder)?);
    let executor_connector_registry_digest = Digest32V2::new(decode_fixed::<32>(decoder)?);
    let expires_at = savana_kernel_protocol::v2::UnixMillisV2::new(
        decoder.u64().map_err(|_| G4Error::DurableStateCorrupt)?,
    );
    let task_binding = if schema == 3 {
        Some(
            decoder
                .decode_with(&mut savana_kernel_protocol::v2::V2DecodeContext)
                .map_err(|_| G4Error::DurableStateCorrupt)?,
        )
    } else {
        None
    };
    Ok(DispatchCoreV2 {
        installation_id,
        active_state_manifest_digest,
        deployment_generation,
        effect_fence_epoch,
        durable_task_id,
        durable_run_id,
        execution_nonce,
        subject,
        dispatch_subject_digest,
        executor_identity,
        executor_key_id,
        executor_connector_registry_digest,
        expires_at,
        task_binding,
    })
}

fn decode_dispatch_subject(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<DispatchSubjectV2, G4Error> {
    let Some(length) = decoder.array().map_err(|_| G4Error::DurableStateCorrupt)? else {
        return Err(G4Error::DurableStateCorrupt);
    };
    match decoder.u16().map_err(|_| G4Error::DurableStateCorrupt)? {
        1 => {
            if length != 4 {
                return Err(G4Error::DurableStateCorrupt);
            }
            let action_intent_id = ActionIntentIdV2::new(decode_fixed::<32>(decoder)?);
            let binding = decode_binding(decoder)?;
            let approval_settlement_digest = if decoder
                .datatype()
                .map_err(|_| G4Error::DurableStateCorrupt)?
                == minicbor::data::Type::Null
            {
                decoder.null().map_err(|_| G4Error::DurableStateCorrupt)?;
                None
            } else {
                Some(Digest32V2::new(decode_fixed::<32>(decoder)?))
            };
            Ok(DispatchSubjectV2::ToolExecution {
                action_intent_id,
                binding,
                approval_settlement_digest,
            })
        }
        2 => {
            if length != 3 {
                return Err(G4Error::DurableStateCorrupt);
            }
            let binding = decode_final_release_binding(decoder)?;
            let approval_settlement_digest = Digest32V2::new(decode_fixed::<32>(decoder)?);
            if is_zero(approval_settlement_digest.as_bytes()) {
                return Err(G4Error::DurableStateCorrupt);
            }
            Ok(DispatchSubjectV2::FinalRelease {
                binding,
                approval_settlement_digest,
            })
        }
        _ => Err(G4Error::DurableStateCorrupt),
    }
}

fn decode_final_release_binding(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<FinalReleaseSemanticBindingV2, G4Error> {
    require_array(decoder, 11)?;
    FinalReleaseSemanticBindingV2::from_nonzero_components(
        DurableReleaseIdV2::new(decode_fixed::<32>(decoder)?),
        Digest32V2::new(decode_fixed::<32>(decoder)?),
        Digest32V2::new(decode_fixed::<32>(decoder)?),
        Digest32V2::new(decode_fixed::<32>(decoder)?),
        Digest32V2::new(decode_fixed::<32>(decoder)?),
        Digest32V2::new(decode_fixed::<32>(decoder)?),
        Digest32V2::new(decode_fixed::<32>(decoder)?),
        Digest32V2::new(decode_fixed::<32>(decoder)?),
        Digest32V2::new(decode_fixed::<32>(decoder)?),
        Digest32V2::new(decode_fixed::<32>(decoder)?),
        Digest32V2::new(decode_fixed::<32>(decoder)?),
    )
    .ok_or(G4Error::DurableStateCorrupt)
}

fn validate_snapshot(snapshot: &DurableG4SnapshotV2) -> Result<(), G4Error> {
    if (snapshot.payload_schema < 12 && snapshot.continuations.planning.has_execution_bindings())
        || (snapshot.payload_schema == 12
            && !snapshot.continuations.planning.has_execution_bindings())
        || (snapshot.payload_schema < 13 && snapshot.continuations.planning.has_delivery_schedule())
        || (snapshot.payload_schema == 13
            && !snapshot.continuations.planning.has_delivery_schedule())
        || (snapshot.payload_schema < 14 && snapshot.continuations.planning.has_recipe_approvals())
        || (snapshot.payload_schema == 14
            && !snapshot.continuations.planning.has_recipe_approvals())
        || (snapshot.payload_schema < 15 && snapshot.continuations.planning.has_recipe_executions())
        || (snapshot.payload_schema == 15
            && !snapshot.continuations.planning.has_recipe_executions())
        || ((snapshot.payload_schema >= 16) != snapshot.continuations.planning.has_inputs())
        || ((snapshot.payload_schema >= 17) != snapshot.continuations.planning.has_result_scopes())
    {
        return Err(G4Error::DurableStateCorrupt);
    }
    if snapshot.payload_schema < 11 && !snapshot.continuations.planning.is_empty() {
        return Err(G4Error::DurableStateCorrupt);
    }
    if snapshot.payload_schema < 10 && !snapshot.continuations.admin.is_empty() {
        return Err(G4Error::DurableStateCorrupt);
    }
    if snapshot.payload_schema < 9 && snapshot.continuations.managed.has_handoff_policy() {
        return Err(G4Error::DurableStateCorrupt);
    }
    if snapshot.payload_schema < 8 && snapshot.continuations.has_execution_snapshots() {
        return Err(G4Error::DurableStateCorrupt);
    }
    if snapshot.payload_schema < 7 && !snapshot.continuations.managed.is_empty() {
        return Err(G4Error::DurableStateCorrupt);
    }
    if snapshot.payload_schema < 6 && snapshot.continuations.has_dispatch_policies() {
        return Err(G4Error::DurableStateCorrupt);
    }
    if snapshot.payload_schema < 5 && !snapshot.continuations.is_empty() {
        return Err(G4Error::DurableStateCorrupt);
    }
    snapshot.continuations.validate(&snapshot.tasks)?;
    snapshot.continuations.planning.validate_executions(
        &snapshot.tasks,
        &snapshot.dispatch,
        &snapshot.intents,
    )?;
    snapshot
        .continuations
        .validate_dispatch(&snapshot.tasks, &snapshot.dispatch)?;
    snapshot.tasks.validate(&snapshot.dispatch)?;
    snapshot.issuance.validate()?;
    snapshot
        .issuance
        .validate_authority_references(&snapshot.tasks)?;
    for (index, id) in snapshot.legacy_intents.iter().enumerate() {
        if snapshot.legacy_intents[..index].contains(id)
            || !snapshot
                .intents
                .intents
                .iter()
                .any(|i| i.record.action_intent_id == *id)
            || snapshot.dispatch.entries.iter().any(|e| {
                e.core.subject.tool_action_intent_id() == Some(*id)
                    && snapshot.tasks.binding(e.core.execution_nonce).is_some()
            })
        {
            return Err(G4Error::DurableStateCorrupt);
        }
    }
    if snapshot.sequence == 0
        || (snapshot.sequence == 1 && !is_zero(snapshot.previous_state_digest.as_bytes()))
        || (snapshot.sequence > 1 && is_zero(snapshot.previous_state_digest.as_bytes()))
    {
        return Err(G4Error::DurableStateCorrupt);
    }
    validate_intent_index(&snapshot.intents)?;
    validate_quota_ledger(&snapshot.quota)?;
    validate_g5_decisions(&snapshot.intents, &snapshot.decisions)?;
    validate_dispatch_journal(
        &snapshot.intents,
        &snapshot.quota,
        &snapshot.decisions,
        &snapshot.dispatch,
    )
}

fn validate_dispatch_journal(
    intents: &ActionIntentIndexV2,
    quota: &DispatchQuotaLedgerV2,
    decisions: &G5DecisionIndexV2,
    dispatch: &KernelDispatchJournalV2,
) -> Result<(), G4Error> {
    if dispatch.entries.len() > MAX_DISPATCH_ENTRIES {
        return Err(G4Error::DurableStateCorrupt);
    }
    for (position, entry) in dispatch.entries.iter().enumerate() {
        let reservation = quota
            .reservations
            .iter()
            .find(|reservation| {
                reservation.reservation.execution_nonce == entry.core.execution_nonce
            })
            .ok_or(G4Error::DurableStateCorrupt)?;
        let quota_state_matches = matches!(
            (
                entry.state,
                reservation.reservation.state,
                entry.effect_evidence_digest
            ),
            (
                KernelDispatchStateV2::Prepared,
                DispatchQuotaReservationStateV2::Reserved,
                None
            ) | (
                KernelDispatchStateV2::Dispatching,
                DispatchQuotaReservationStateV2::Reserved,
                None
            ) | (
                KernelDispatchStateV2::EffectStarted,
                DispatchQuotaReservationStateV2::Spent,
                Some(_)
            ) | (
                KernelDispatchStateV2::CompletionCommitted,
                DispatchQuotaReservationStateV2::Spent,
                Some(_)
            ) | (
                KernelDispatchStateV2::FailedNoEffect,
                DispatchQuotaReservationStateV2::ReleasedNoEffect,
                Some(_)
            ) | (
                KernelDispatchStateV2::Indeterminate,
                DispatchQuotaReservationStateV2::IndeterminateSpent,
                Some(_)
            )
        );
        let subject_matches = match &entry.core.subject {
            DispatchSubjectV2::ToolExecution {
                action_intent_id,
                binding,
                approval_settlement_digest,
            } => {
                let intent = intents
                    .intents
                    .iter()
                    .find(|intent| intent.record.action_intent_id == *action_intent_id)
                    .ok_or(G4Error::DurableStateCorrupt)?;
                let decision = decisions
                    .entries
                    .iter()
                    .find(|decision| decision.action_intent_id == *action_intent_id)
                    .ok_or(G4Error::DurableStateCorrupt)?;
                let approval_matches = matches!(
                    (decision.branch, approval_settlement_digest),
                    (G5DecisionBranchV2::Permit, None)
                        | (G5DecisionBranchV2::RequireApproval, Some(_))
                );
                let intent_state_matches = matches!(
                    (entry.state, intent.current_state),
                    (
                        KernelDispatchStateV2::Prepared,
                        ActionIntentStateV2::DispatchPrepared
                    ) | (
                        KernelDispatchStateV2::Dispatching | KernelDispatchStateV2::EffectStarted,
                        ActionIntentStateV2::Dispatching
                    ) | (
                        KernelDispatchStateV2::CompletionCommitted,
                        ActionIntentStateV2::Succeeded
                    ) | (
                        KernelDispatchStateV2::FailedNoEffect,
                        ActionIntentStateV2::FailedNoEffect
                    ) | (
                        KernelDispatchStateV2::Indeterminate,
                        ActionIntentStateV2::Indeterminate
                    )
                );
                approval_matches
                    && binding == &intent.record.material.binding
                    && entry.core.installation_id == intent.record.installation_id
                    && entry.core.active_state_manifest_digest
                        == intent.record.active_state_manifest_digest
                    && entry.core.durable_task_id == intent.record.durable_task_id
                    && entry.core.durable_run_id == intent.record.durable_run_id
                    && Digest32V2::new(*entry.core.executor_identity.as_bytes())
                        == binding.executor_identity_digest()
                    && entry.quota_subject
                        == DispatchQuotaSubjectV2::tool_attempt(binding.attempt_kind())
                    && intent_state_matches
            }
            DispatchSubjectV2::FinalRelease {
                binding,
                approval_settlement_digest,
                ..
            } => {
                !is_zero(approval_settlement_digest.as_bytes())
                    && Digest32V2::new(*entry.core.executor_identity.as_bytes())
                        == binding.executor_identity_digest()
                    && entry.quota_subject
                        == DispatchQuotaSubjectV2::final_release(
                            binding.release_quota_subject_digest(),
                        )
                    && !is_zero(entry.core.durable_task_id.as_bytes())
                    && !is_zero(entry.core.durable_run_id.as_bytes())
            }
        };
        let duplicate = dispatch.entries[..position].iter().any(|prior| {
            prior.core.execution_nonce == entry.core.execution_nonce
                || prior.consumed_ticket_digest == entry.consumed_ticket_digest
                || match (&prior.core.subject, &entry.core.subject) {
                    (
                        DispatchSubjectV2::ToolExecution {
                            action_intent_id: left,
                            ..
                        },
                        DispatchSubjectV2::ToolExecution {
                            action_intent_id: right,
                            ..
                        },
                    ) => left == right,
                    (
                        DispatchSubjectV2::FinalRelease { binding: left, .. },
                        DispatchSubjectV2::FinalRelease { binding: right, .. },
                    ) => left.durable_release_id() == right.durable_release_id(),
                    _ => false,
                }
        });
        if !subject_matches
            || entry.core.dispatch_subject_digest
                != dispatch_subject_digest(&entry.core.subject)
                    .map_err(|_| G4Error::DurableStateCorrupt)?
            || entry.core_digest
                != dispatch_core_digest(&entry.core).map_err(|_| G4Error::DurableStateCorrupt)?
            || is_zero(entry.sealed_envelope_digest.as_bytes())
            || is_zero(entry.consumed_ticket_digest.as_bytes())
            || duplicate
            || reservation.reservation.dispatch_subject_digest != entry.core.dispatch_subject_digest
            || reservation.reservation.quota_subject != entry.quota_subject
            || !quota_state_matches
        {
            return Err(G4Error::DurableStateCorrupt);
        }
    }
    Ok(())
}

fn validate_g5_decisions(
    intents: &ActionIntentIndexV2,
    decisions: &G5DecisionIndexV2,
) -> Result<(), G4Error> {
    if decisions.entries.len() > MAX_G5_DECISIONS {
        return Err(G4Error::DurableStateCorrupt);
    }
    for (position, entry) in decisions.entries.iter().enumerate() {
        if is_zero(entry.action_intent_id.as_bytes())
            || is_zero(entry.evaluation_input_digest.as_bytes())
            || is_zero(entry.decision_record_digest.as_bytes())
            || entry.validator_decision_digests.len() > 32
            || entry
                .validator_decision_digests
                .iter()
                .any(|digest| is_zero(digest.as_bytes()))
            || decisions.entries[..position]
                .iter()
                .any(|prior| prior.action_intent_id == entry.action_intent_id)
            || !intents
                .intents
                .iter()
                .any(|intent| intent.record.action_intent_id == entry.action_intent_id)
            || decision_record_digest(
                entry.action_intent_id,
                entry.evaluation_input_digest,
                entry.branch,
                &entry.validator_decision_digests,
            )
            .map_err(|_| G4Error::DurableStateCorrupt)?
                != entry.decision_record_digest
        {
            return Err(G4Error::DurableStateCorrupt);
        }
    }
    Ok(())
}

fn validate_intent_index(index: &ActionIntentIndexV2) -> Result<(), G4Error> {
    if index.intents.len() > MAX_INTENTS || index.replay.len() > MAX_REPLAY {
        return Err(G4Error::DurableStateCorrupt);
    }
    for (position, entry) in index.intents.iter().enumerate() {
        let record = &entry.record;
        validate_material(&record.material)?;
        if is_zero(record.stable_proposal_digest.as_bytes())
            || record.pending_call_state.action_intent_id != record.action_intent_id
            || record.public_task_state.action_intent_id != record.action_intent_id
            || record.public_task_state.durable_task_id != record.durable_task_id
            || !state_records_match(
                entry.current_state,
                record.pending_call_state.state,
                record.public_task_state.state,
            )
            || index.intents[..position].iter().any(|prior| {
                prior.record.action_intent_id == record.action_intent_id
                    || (prior.record.durable_run_id == record.durable_run_id
                        && prior.record.material.binding.plan_revision_digest
                            == record.material.binding.plan_revision_digest
                        && prior.record.material.binding.internal_step_id
                            == record.material.binding.internal_step_id)
            })
        {
            return Err(G4Error::DurableStateCorrupt);
        }
        let semantic = tool_execution_semantic_binding_digest_v2(&record.material.binding)
            .map_err(|_| G4Error::DurableStateCorrupt)?;
        let action = action_intent_id_v2(
            record.installation_id,
            record.active_state_manifest_digest,
            record.durable_run_id,
            record.durable_task_id,
            &record.material.binding,
        )
        .map_err(|_| G4Error::DurableStateCorrupt)?;
        if semantic != record.semantic_binding_digest || action != record.action_intent_id {
            return Err(G4Error::DurableStateCorrupt);
        }
    }
    for (position, replay) in index.replay.iter().enumerate() {
        if is_zero(replay.stable_proposal_digest.as_bytes())
            || index.replay[..position]
                .iter()
                .any(|prior| prior.request_id == replay.request_id)
        {
            return Err(G4Error::DurableStateCorrupt);
        }
        let Some(intent) = index
            .intents
            .iter()
            .find(|entry| entry.record.action_intent_id == replay.action_intent_id)
        else {
            return Err(G4Error::DurableStateCorrupt);
        };
        if intent.record.stable_proposal_digest != replay.stable_proposal_digest {
            return Err(G4Error::DurableStateCorrupt);
        }
    }
    if index.intents.iter().any(|intent| {
        !index
            .replay
            .iter()
            .any(|replay| replay.action_intent_id == intent.record.action_intent_id)
    }) {
        return Err(G4Error::DurableStateCorrupt);
    }
    Ok(())
}

fn validate_material(material: &VerifiedActionIntentMaterialV2) -> Result<(), G4Error> {
    let descriptor = decode_unsigned_descriptor(&material.selected_descriptor_canonical)
        .map_err(|_| G4Error::DurableStateCorrupt)?;
    if minicbor::to_vec(&descriptor).map_err(|_| G4Error::DurableStateCorrupt)?
        != material.selected_descriptor_canonical
        || descriptor_digest_v2(&descriptor).map_err(|_| G4Error::DurableStateCorrupt)?
            != material.binding.tool_descriptor_digest
        || is_zero(material.descriptor_publisher_key_id.as_bytes())
        || is_zero(material.policy_activation_digest.as_bytes())
        || descriptor.executor_identity().as_bytes()
            != material.binding.executor_identity_digest.as_bytes()
        || descriptor.attempt_kind() != material.binding.attempt_kind
        || descriptor.destination_projection() != material.projection_outputs.destination_projection
        || descriptor.destination_projection_digest()
            != material.projection_outputs.destination_projection_digest
        || descriptor.display_projection() != material.projection_outputs.display_projection
        || descriptor.display_projection_digest()
            != material.projection_outputs.display_projection_digest
        || material.projection_outputs.tool_descriptor_digest
            != material.binding.tool_descriptor_digest
        || material.projection_outputs.destination_digest != material.binding.destination_digest
        || projection_output_digest(
            DESTINATION_DIGEST_DOMAIN,
            material.projection_outputs.destination_projection_digest,
            material.projection_outputs.destination_canonical(),
        ) != material.projection_outputs.destination_digest
        || material.projection_outputs.display_projection_digest
            != material.binding.display_projection_digest
        || material.projection_outputs.display_digest != material.binding.display_digest
        || projection_output_digest(
            DISPLAY_DIGEST_DOMAIN,
            material.projection_outputs.display_projection_digest,
            material.projection_outputs.display_canonical(),
        ) != material.projection_outputs.display_digest
        || material.effective_retry_policy.maximum_attempts()
            > descriptor.connector_retry_policy().maximum_attempts()
        || material.effective_retry_policy.maximum_elapsed_ns()
            > descriptor.connector_retry_policy().maximum_elapsed_ns()
    {
        return Err(G4Error::DurableStateCorrupt);
    }

    if material
        .normalized_arguments
        .windows(2)
        .any(|pair| pair[0].argument_name.as_str() >= pair[1].argument_name.as_str())
        || material.normalized_arguments.iter().any(|argument| {
            is_zero(argument.internal_slot_digest.as_bytes())
                || is_zero(argument.value_internal_id.as_bytes())
                || is_zero(argument.value_digest.as_bytes())
                || is_zero(argument.provenance_digest.as_bytes())
        })
    {
        return Err(G4Error::DurableStateCorrupt);
    }
    let argument_entries = material
        .normalized_arguments
        .iter()
        .map(|argument| {
            ArgumentDigestEntryV2::new(
                argument.argument_name.clone(),
                argument.value_internal_id,
                argument.value_digest,
                argument.provenance_digest,
            )
        })
        .collect::<Vec<_>>();
    let mut provenance_entries = material
        .normalized_arguments
        .iter()
        .map(|argument| {
            ProvenanceSetDigestEntryV2::new(
                argument.value_internal_id,
                argument.value_digest,
                argument.provenance_digest,
            )
        })
        .collect::<Vec<_>>();
    provenance_entries.sort_unstable_by(provenance_entry_cmp);
    if argument_digest_v2(&argument_entries).map_err(|_| G4Error::DurableStateCorrupt)?
        != material.binding.argument_digest
        || provenance_set_digest_v2(&argument_entries, &provenance_entries)
            .map_err(|_| G4Error::DurableStateCorrupt)?
            != material.binding.provenance_set_digest
    {
        return Err(G4Error::DurableStateCorrupt);
    }

    if material.token_bindings.windows(2).any(|pair| {
        pair[0].token_slot_id.as_str().as_bytes() >= pair[1].token_slot_id.as_str().as_bytes()
    }) {
        return Err(G4Error::DurableStateCorrupt);
    }
    let mut token_entries = Vec::new();
    token_entries
        .try_reserve_exact(material.token_bindings.len())
        .map_err(|_| G4Error::AllocationFailure)?;
    for token in &material.token_bindings {
        if is_zero(token.vault_segment_internal_id.as_bytes())
            || is_zero(token.credential_version_digest.as_bytes())
            || token.executor_identity_digest != material.binding.executor_identity_digest
        {
            return Err(G4Error::DurableStateCorrupt);
        }
        token_entries.push(TokenSetDigestEntryV2::new(
            token.token_slot_id.clone(),
            token.vault_segment_internal_id,
            token.credential_version_digest,
            ExecutorIdentityV2::new(*token.executor_identity_digest.as_bytes()),
        ));
    }
    if token_set_digest_v2(&token_entries).map_err(|_| G4Error::DurableStateCorrupt)?
        != material.binding.token_set_digest
    {
        return Err(G4Error::DurableStateCorrupt);
    }
    Ok(())
}

fn validate_quota_ledger(ledger: &DispatchQuotaLedgerV2) -> Result<(), G4Error> {
    if ledger.counters.len() > MAX_COUNTERS || ledger.reservations.len() > MAX_RESERVATIONS {
        return Err(G4Error::DurableStateCorrupt);
    }
    for (position, counter) in ledger.counters.iter().enumerate() {
        if is_zero(counter.durable_run_id.as_bytes())
            || !valid_quota_subject(counter.subject)
            || counter.verified_limit.limit() == 0
            || is_zero(counter.verified_limit.policy_binding_digest().as_bytes())
            || counter.verified_limit.subject() != counter.subject
            || ledger.counters[..position].iter().any(|prior| {
                prior.durable_run_id == counter.durable_run_id && prior.subject == counter.subject
            })
        {
            return Err(G4Error::DurableStateCorrupt);
        }
        let mut expected_reserved = 0_u32;
        let mut expected_spent = 0_u32;
        for entry in &ledger.reservations {
            let reservation = entry.reservation;
            if reservation.durable_run_id == counter.durable_run_id
                && reservation.quota_subject == counter.subject
            {
                match reservation.state {
                    DispatchQuotaReservationStateV2::Reserved => {
                        expected_reserved = expected_reserved
                            .checked_add(1)
                            .ok_or(G4Error::DurableStateCorrupt)?;
                    }
                    DispatchQuotaReservationStateV2::Spent
                    | DispatchQuotaReservationStateV2::IndeterminateSpent => {
                        expected_spent = expected_spent
                            .checked_add(1)
                            .ok_or(G4Error::DurableStateCorrupt)?;
                    }
                    DispatchQuotaReservationStateV2::ReleasedNoEffect => {}
                }
            }
        }
        let expected_used = expected_reserved
            .checked_add(expected_spent)
            .ok_or(G4Error::DurableStateCorrupt)?;
        if counter.counter != DispatchQuotaCounterV2::new(expected_reserved, expected_spent)
            || expected_used > counter.verified_limit.limit()
        {
            return Err(G4Error::DurableStateCorrupt);
        }
    }
    for (position, entry) in ledger.reservations.iter().enumerate() {
        let reservation = entry.reservation;
        let disposition_matches = matches!(
            (
                reservation.state,
                entry
                    .last_disposition
                    .map(AuthenticatedEffectDispositionV2::kind)
            ),
            (DispatchQuotaReservationStateV2::Reserved, None)
                | (
                    DispatchQuotaReservationStateV2::Spent,
                    Some(
                        AuthenticatedEffectDispositionKindV2::EffectStarted
                            | AuthenticatedEffectDispositionKindV2::KnownSuccess
                    )
                )
                | (
                    DispatchQuotaReservationStateV2::ReleasedNoEffect,
                    Some(AuthenticatedEffectDispositionKindV2::FailedNoEffect)
                )
                | (
                    DispatchQuotaReservationStateV2::IndeterminateSpent,
                    Some(AuthenticatedEffectDispositionKindV2::Indeterminate)
                )
        );
        if is_zero(reservation.durable_run_id.as_bytes())
            || is_zero(reservation.dispatch_subject_digest.as_bytes())
            || is_zero(reservation.execution_nonce.as_bytes())
            || !valid_quota_subject(reservation.quota_subject)
            || !disposition_matches
            || ledger.reservations[..position].iter().any(|prior| {
                prior.reservation.execution_nonce == reservation.execution_nonce
                    || prior.reservation.dispatch_subject_digest
                        == reservation.dispatch_subject_digest
            })
            || !ledger.counters.iter().any(|counter| {
                counter.durable_run_id == reservation.durable_run_id
                    && counter.subject == reservation.quota_subject
            })
        {
            return Err(G4Error::DurableStateCorrupt);
        }
    }
    Ok(())
}

fn valid_quota_subject(subject: DispatchQuotaSubjectV2) -> bool {
    match subject {
        DispatchQuotaSubjectV2::ToolAttempt { .. } => true,
        DispatchQuotaSubjectV2::FinalRelease {
            release_quota_subject_digest,
        } => !is_zero(release_quota_subject_digest.as_bytes()),
    }
}

fn decode_quota_subject(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<DispatchQuotaSubjectV2, G4Error> {
    require_array(decoder, 2)?;
    match decoder.u16().map_err(|_| G4Error::DurableStateCorrupt)? {
        1 => Ok(DispatchQuotaSubjectV2::tool_attempt(decode_attempt_kind(
            decoder,
        )?)),
        2 => Ok(DispatchQuotaSubjectV2::final_release(Digest32V2::new(
            decode_fixed::<32>(decoder)?,
        ))),
        _ => Err(G4Error::DurableStateCorrupt),
    }
}

fn decode_quota_counter(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<DispatchQuotaCounterV2, G4Error> {
    require_array(decoder, 2)?;
    Ok(DispatchQuotaCounterV2::new(
        decoder.u32().map_err(|_| G4Error::DurableStateCorrupt)?,
        decoder.u32().map_err(|_| G4Error::DurableStateCorrupt)?,
    ))
}

fn decode_verified_quota_limit(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<VerifiedQuotaLimitV2, G4Error> {
    require_array(decoder, 3)?;
    VerifiedQuotaLimitV2::from_verified_policy(
        decoder.u32().map_err(|_| G4Error::DurableStateCorrupt)?,
        Digest32V2::new(decode_fixed::<32>(decoder)?),
        decode_quota_subject(decoder)?,
    )
    .map_err(|_| G4Error::DurableStateCorrupt)
}

fn decode_reservation_state(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<DispatchQuotaReservationStateV2, G4Error> {
    require_array(decoder, 1)?;
    match decoder.u16().map_err(|_| G4Error::DurableStateCorrupt)? {
        1 => Ok(DispatchQuotaReservationStateV2::Reserved),
        2 => Ok(DispatchQuotaReservationStateV2::Spent),
        3 => Ok(DispatchQuotaReservationStateV2::ReleasedNoEffect),
        4 => Ok(DispatchQuotaReservationStateV2::IndeterminateSpent),
        _ => Err(G4Error::DurableStateCorrupt),
    }
}

fn decode_attempt_kind(decoder: &mut minicbor::Decoder<'_>) -> Result<AttemptKindV2, G4Error> {
    require_array(decoder, 1)?;
    match decoder.u16().map_err(|_| G4Error::DurableStateCorrupt)? {
        1 => Ok(AttemptKindV2::ToolRead),
        2 => Ok(AttemptKindV2::ToolWrite),
        3 => Ok(AttemptKindV2::ToolIrreversible),
        _ => Err(G4Error::DurableStateCorrupt),
    }
}

fn decode_action_state(tag: u16) -> Result<ActionIntentStateV2, G4Error> {
    match tag {
        1 => Ok(ActionIntentStateV2::Proposed),
        2 => Ok(ActionIntentStateV2::Evaluating),
        3 => Ok(ActionIntentStateV2::Denied),
        4 => Ok(ActionIntentStateV2::NeedsApproval),
        5 => Ok(ActionIntentStateV2::AuthorizedApproval),
        6 => Ok(ActionIntentStateV2::AuthorizedPolicy),
        7 => Ok(ActionIntentStateV2::DispatchPrepared),
        8 => Ok(ActionIntentStateV2::Dispatching),
        9 => Ok(ActionIntentStateV2::FailedNoEffect),
        10 => Ok(ActionIntentStateV2::Indeterminate),
        11 => Ok(ActionIntentStateV2::ResultGatePending),
        12 => Ok(ActionIntentStateV2::Succeeded),
        13 => Ok(ActionIntentStateV2::EffectSucceededOutputQuarantined),
        _ => Err(G4Error::DurableStateCorrupt),
    }
}

fn decode_g5_decision_branch(tag: u16) -> Result<G5DecisionBranchV2, G4Error> {
    match tag {
        1 => Ok(G5DecisionBranchV2::Permit),
        2 => Ok(G5DecisionBranchV2::RequireApproval),
        3 => Ok(G5DecisionBranchV2::Deny),
        _ => Err(G4Error::DurableStateCorrupt),
    }
}

fn decode_pending_call_state_tag(tag: u16) -> Result<PendingCallStateV2, G4Error> {
    match tag {
        1 => Ok(PendingCallStateV2::Evaluating),
        2 => Ok(PendingCallStateV2::AwaitingApproval),
        3 => Ok(PendingCallStateV2::Authorized),
        4 => Ok(PendingCallStateV2::DispatchPrepared),
        5 => Ok(PendingCallStateV2::Dispatching),
        6 => Ok(PendingCallStateV2::ResultGatePending),
        7 => Ok(PendingCallStateV2::TerminalDenied),
        8 => Ok(PendingCallStateV2::TerminalFailedNoEffect),
        9 => Ok(PendingCallStateV2::TerminalIndeterminate),
        10 => Ok(PendingCallStateV2::TerminalSucceeded),
        11 => Ok(PendingCallStateV2::TerminalOutputQuarantined),
        _ => Err(G4Error::DurableStateCorrupt),
    }
}

fn decode_public_task_state_tag(tag: u16) -> Result<PublicTaskStateV2, G4Error> {
    match tag {
        1 => Ok(PublicTaskStateV2::Evaluating),
        2 => Ok(PublicTaskStateV2::AwaitingApproval),
        3 => Ok(PublicTaskStateV2::Authorized),
        4 => Ok(PublicTaskStateV2::Executing),
        5 => Ok(PublicTaskStateV2::Failed),
        6 => Ok(PublicTaskStateV2::Indeterminate),
        7 => Ok(PublicTaskStateV2::Succeeded),
        8 => Ok(PublicTaskStateV2::OutputQuarantined),
        _ => Err(G4Error::DurableStateCorrupt),
    }
}

fn state_records_match(
    action: ActionIntentStateV2,
    pending: PendingCallStateV2,
    public: PublicTaskStateV2,
) -> bool {
    matches!(
        (action, pending, public),
        (
            ActionIntentStateV2::Proposed | ActionIntentStateV2::Evaluating,
            PendingCallStateV2::Evaluating,
            PublicTaskStateV2::Evaluating
        ) | (
            ActionIntentStateV2::Denied,
            PendingCallStateV2::TerminalDenied,
            PublicTaskStateV2::Failed
        ) | (
            ActionIntentStateV2::NeedsApproval,
            PendingCallStateV2::AwaitingApproval,
            PublicTaskStateV2::AwaitingApproval
        ) | (
            ActionIntentStateV2::AuthorizedApproval | ActionIntentStateV2::AuthorizedPolicy,
            PendingCallStateV2::Authorized,
            PublicTaskStateV2::Authorized
        ) | (
            ActionIntentStateV2::DispatchPrepared,
            PendingCallStateV2::DispatchPrepared,
            PublicTaskStateV2::Executing
        ) | (
            ActionIntentStateV2::Dispatching,
            PendingCallStateV2::Dispatching,
            PublicTaskStateV2::Executing
        ) | (
            ActionIntentStateV2::FailedNoEffect,
            PendingCallStateV2::TerminalFailedNoEffect,
            PublicTaskStateV2::Failed
        ) | (
            ActionIntentStateV2::Indeterminate,
            PendingCallStateV2::TerminalIndeterminate,
            PublicTaskStateV2::Indeterminate
        ) | (
            ActionIntentStateV2::ResultGatePending,
            PendingCallStateV2::ResultGatePending,
            PublicTaskStateV2::Executing
        ) | (
            ActionIntentStateV2::Succeeded,
            PendingCallStateV2::TerminalSucceeded,
            PublicTaskStateV2::Succeeded
        ) | (
            ActionIntentStateV2::EffectSucceededOutputQuarantined,
            PendingCallStateV2::TerminalOutputQuarantined,
            PublicTaskStateV2::OutputQuarantined
        )
    )
}

fn effect_disposition_tag(disposition: AuthenticatedEffectDispositionV2) -> u16 {
    match disposition.kind() {
        AuthenticatedEffectDispositionKindV2::EffectStarted => 1,
        AuthenticatedEffectDispositionKindV2::KnownSuccess => 2,
        AuthenticatedEffectDispositionKindV2::FailedNoEffect => 3,
        AuthenticatedEffectDispositionKindV2::Indeterminate => 4,
    }
}

fn decode_effect_disposition(tag: u16) -> Result<AuthenticatedEffectDispositionV2, G4Error> {
    match tag {
        1 => Ok(AuthenticatedEffectDispositionV2::from_verified_effect_started_receipt()),
        2 => Ok(AuthenticatedEffectDispositionV2::from_verified_known_success()),
        3 => Ok(AuthenticatedEffectDispositionV2::from_verified_failed_no_effect()),
        4 => Ok(AuthenticatedEffectDispositionV2::from_verified_indeterminate()),
        _ => Err(G4Error::DurableStateCorrupt),
    }
}

const fn dispatch_state_tag(state: KernelDispatchStateV2) -> u16 {
    match state {
        KernelDispatchStateV2::Prepared => 1,
        KernelDispatchStateV2::Dispatching => 2,
        KernelDispatchStateV2::EffectStarted => 3,
        KernelDispatchStateV2::CompletionCommitted => 4,
        KernelDispatchStateV2::FailedNoEffect => 5,
        KernelDispatchStateV2::Indeterminate => 6,
    }
}

fn decode_dispatch_state(tag: u16) -> Result<KernelDispatchStateV2, G4Error> {
    match tag {
        1 => Ok(KernelDispatchStateV2::Prepared),
        2 => Ok(KernelDispatchStateV2::Dispatching),
        3 => Ok(KernelDispatchStateV2::EffectStarted),
        4 => Ok(KernelDispatchStateV2::CompletionCommitted),
        5 => Ok(KernelDispatchStateV2::FailedNoEffect),
        6 => Ok(KernelDispatchStateV2::Indeterminate),
        _ => Err(G4Error::DurableStateCorrupt),
    }
}

fn decode_argument_name(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<super::ArgumentNameV2, G4Error> {
    super::ArgumentNameV2::new(decoder.str().map_err(|_| G4Error::DurableStateCorrupt)?)
        .map_err(|_| G4Error::DurableStateCorrupt)
}

fn decode_identifier(decoder: &mut minicbor::Decoder<'_>) -> Result<IdentifierV2, G4Error> {
    IdentifierV2::new(decoder.str().map_err(|_| G4Error::DurableStateCorrupt)?)
        .map_err(|_| G4Error::DurableStateCorrupt)
}

fn bounded_array(decoder: &mut minicbor::Decoder<'_>, maximum: usize) -> Result<usize, G4Error> {
    let Some(length) = decoder.array().map_err(|_| G4Error::DurableStateCorrupt)? else {
        return Err(G4Error::DurableStateCorrupt);
    };
    let length = usize::try_from(length).map_err(|_| G4Error::DurableStateCorrupt)?;
    if length > maximum {
        return Err(G4Error::DurableStateCorrupt);
    }
    Ok(length)
}

fn require_array(decoder: &mut minicbor::Decoder<'_>, expected: u64) -> Result<(), G4Error> {
    if decoder.array().map_err(|_| G4Error::DurableStateCorrupt)? != Some(expected) {
        return Err(G4Error::DurableStateCorrupt);
    }
    Ok(())
}

fn decode_fixed<const N: usize>(decoder: &mut minicbor::Decoder<'_>) -> Result<[u8; N], G4Error> {
    decoder
        .bytes()
        .map_err(|_| G4Error::DurableStateCorrupt)?
        .try_into()
        .map_err(|_| G4Error::DurableStateCorrupt)
}

fn decode_bounded_sensitive_bytes(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<Zeroizing<Vec<u8>>, G4Error> {
    let bytes = decoder.bytes().map_err(|_| G4Error::DurableStateCorrupt)?;
    if bytes.is_empty() || bytes.len() > MAX_PROJECTION_OUTPUT_BYTES {
        return Err(G4Error::DurableStateCorrupt);
    }
    let mut owned = Vec::new();
    owned
        .try_reserve_exact(bytes.len())
        .map_err(|_| G4Error::AllocationFailure)?;
    owned.extend_from_slice(bytes);
    Ok(Zeroizing::new(owned))
}

fn derive_state_encryption_key(
    master_key: &[u8; 32],
    namespace: DurableStateNamespaceV2,
) -> Result<Zeroizing<[u8; 32]>, G4Error> {
    let mut mac = <Hmac<Sha256> as hmac::Mac>::new_from_slice(master_key)
        .map_err(|_| G4Error::DurableStateIo)?;
    mac.update(STATE_KEY_DERIVATION_DOMAIN);
    mac.update(&STATE_SCHEMA_VERSION.to_be_bytes());
    mac.update(namespace.installation_id.as_bytes());
    mac.update(namespace.store_id.as_bytes());
    let derived: [u8; 32] = mac.finalize().into_bytes().into();
    Ok(Zeroizing::new(derived))
}

fn state_head_digest(namespace: DurableStateNamespaceV2, authenticated_state: &[u8]) -> Digest32V2 {
    let mut hasher = Sha256::new();
    hasher.update(STATE_HEAD_DOMAIN);
    hasher.update(STATE_SCHEMA_VERSION.to_be_bytes());
    hasher.update(namespace.installation_id.as_bytes());
    hasher.update(namespace.store_id.as_bytes());
    hasher.update(authenticated_state);
    Digest32V2::new(hasher.finalize().into())
}

fn state_encryption_aad(
    namespace: DurableStateNamespaceV2,
    sequence: u64,
    previous_state_digest: Digest32V2,
    nonce: &[u8; STATE_NONCE_BYTES],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(
        STATE_ENCRYPTION_AAD_DOMAIN.len()
            + std::mem::size_of::<u16>()
            + namespace.installation_id.as_bytes().len()
            + namespace.store_id.as_bytes().len()
            + std::mem::size_of::<u64>()
            + previous_state_digest.as_bytes().len()
            + nonce.len(),
    );
    aad.extend_from_slice(STATE_ENCRYPTION_AAD_DOMAIN);
    aad.extend_from_slice(&STATE_SCHEMA_VERSION.to_be_bytes());
    aad.extend_from_slice(namespace.installation_id.as_bytes());
    aad.extend_from_slice(namespace.store_id.as_bytes());
    aad.extend_from_slice(&sequence.to_be_bytes());
    aad.extend_from_slice(previous_state_digest.as_bytes());
    aad.extend_from_slice(nonce);
    aad
}

#[cfg(test)]
#[derive(Debug, Clone)]
pub(crate) struct TestRollbackProtectedStateAnchorV2 {
    head: Arc<Mutex<RollbackProtectedStateHeadV2>>,
}

#[cfg(test)]
impl Default for TestRollbackProtectedStateAnchorV2 {
    fn default() -> Self {
        Self {
            head: Arc::new(Mutex::new(RollbackProtectedStateHeadV2::GENESIS)),
        }
    }
}

#[cfg(test)]
impl RollbackProtectedStateAnchorV2 for TestRollbackProtectedStateAnchorV2 {
    fn current_head(&self) -> Result<RollbackProtectedStateHeadV2, G4Error> {
        self.head
            .lock()
            .map(|head| *head)
            .map_err(|_| G4Error::DurableStateIo)
    }

    fn compare_and_advance(
        &mut self,
        expected: RollbackProtectedStateHeadV2,
        next: RollbackProtectedStateHeadV2,
    ) -> Result<(), G4Error> {
        if next.sequence
            != expected
                .sequence
                .checked_add(1)
                .ok_or(G4Error::DurableStateRollback)?
        {
            return Err(G4Error::DurableStateRollback);
        }
        let mut head = self.head.lock().map_err(|_| G4Error::DurableStateIo)?;
        if *head != expected {
            return Err(G4Error::DurableStateRollback);
        }
        *head = next;
        Ok(())
    }
}

fn provenance_entry_cmp(
    left: &ProvenanceSetDigestEntryV2,
    right: &ProvenanceSetDigestEntryV2,
) -> std::cmp::Ordering {
    minicbor::to_vec(left)
        .unwrap_or_default()
        .cmp(&minicbor::to_vec(right).unwrap_or_default())
}

pub(crate) struct DurableAnchoredPathV2 {
    parent: File,
    parent_path: PathBuf,
    parent_dev: u64,
    parent_ino: u64,
    leaf: OsString,
    owner_uid: u32,
    owner_gid: u32,
}

impl DurableAnchoredPathV2 {
    pub(crate) fn open(path: &Path) -> Result<Self, G4Error> {
        if !path.is_absolute() {
            return Err(G4Error::DurableStateIo);
        }
        let parent_path = path.parent().ok_or(G4Error::DurableStateIo)?;
        let leaf = path
            .file_name()
            .ok_or(G4Error::DurableStateIo)?
            .to_os_string();
        let before = fs::symlink_metadata(parent_path).map_err(|_| G4Error::DurableStateIo)?;
        if before.file_type().is_symlink() {
            return Err(G4Error::DurableStateIo);
        }
        let descriptor = rustix_open(
            parent_path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| G4Error::DurableStateIo)?;
        let parent = File::from(descriptor);
        let opened = parent.metadata().map_err(|_| G4Error::DurableStateIo)?;
        if !opened.is_dir()
            || opened.dev() != before.dev()
            || opened.ino() != before.ino()
            || opened.uid() != before.uid()
            || opened.gid() != before.gid()
            || opened.mode() & 0o7777 != 0o700
        {
            return Err(G4Error::DurableStateIo);
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

    pub(crate) fn recheck_parent(&self) -> Result<(), G4Error> {
        let opened = self
            .parent
            .metadata()
            .map_err(|_| G4Error::DurableStateIo)?;
        let linked =
            fs::symlink_metadata(&self.parent_path).map_err(|_| G4Error::DurableStateIo)?;
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
            return Err(G4Error::DurableStateIo);
        }
        Ok(())
    }

    pub(crate) fn read_existing(&self) -> Result<Option<Vec<u8>>, G4Error> {
        let before = match statat(&self.parent, &self.leaf, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => stat,
            Err(Errno::NOENT) => return Ok(None),
            Err(_) => return Err(G4Error::DurableStateIo),
        };
        if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile {
            return Err(G4Error::DurableStateIo);
        }
        let descriptor = openat(
            &self.parent,
            &self.leaf,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| G4Error::DurableStateIo)?;
        let mut file = File::from(descriptor);
        let opened = file.metadata().map_err(|_| G4Error::DurableStateIo)?;
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
            return Err(G4Error::DurableStateIo);
        }
        let capacity = usize::try_from(opened.len()).map_err(|_| G4Error::DurableStateIo)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(capacity)
            .map_err(|_| G4Error::AllocationFailure)?;
        file.read_to_end(&mut bytes)
            .map_err(|_| G4Error::DurableStateIo)?;
        let after = statat(&self.parent, &self.leaf, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| G4Error::DurableStateIo)?;
        if bytes.len() != capacity
            || i128::from(after.st_dev) != i128::from(opened.dev())
            || after.st_ino != opened.ino()
            || u64::try_from(after.st_size).ok() != Some(opened.len())
        {
            return Err(G4Error::DurableStateIo);
        }
        self.parent
            .sync_all()
            .map_err(|_| G4Error::DurableStateIo)?;
        self.recheck_parent()?;
        Ok(Some(bytes))
    }

    fn replace(&self, bytes: &[u8]) -> Result<(), atomic_file::ReplaceError> {
        atomic_file::replace_at(
            &self.parent,
            &self.leaf,
            bytes,
            self.owner_uid,
            self.owner_gid,
            || {
                self.recheck_parent()
                    .map_err(|_| crate::PolicyError::io("durable parent identity changed"))
            },
        )?;
        self.recheck_parent().map_err(|_| {
            atomic_file::ReplaceError::after_rename(crate::PolicyError::io(
                "durable parent identity changed",
            ))
        })
    }

    pub(crate) fn replace_observed<O>(
        &self,
        bytes: &[u8],
        observe: O,
    ) -> Result<(), atomic_file::ReplaceError>
    where
        O: FnMut(atomic_file::AtomicReplaceBoundary) -> Result<(), crate::PolicyError>,
    {
        atomic_file::replace_at_observed(
            &self.parent,
            &self.leaf,
            bytes,
            self.owner_uid,
            self.owner_gid,
            || {
                self.recheck_parent()
                    .map_err(|_| crate::PolicyError::io("durable parent identity changed"))
            },
            observe,
        )?;
        self.recheck_parent().map_err(|_| {
            atomic_file::ReplaceError::after_rename(crate::PolicyError::io(
                "durable parent identity changed",
            ))
        })
    }

    pub(crate) const fn parent(&self) -> &File {
        &self.parent
    }

    pub(crate) fn owner_uid(&self) -> u32 {
        self.owner_uid
    }

    pub(crate) fn owner_gid(&self) -> u32 {
        self.owner_gid
    }
}

fn is_zero<const N: usize>(bytes: &[u8; N]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}
