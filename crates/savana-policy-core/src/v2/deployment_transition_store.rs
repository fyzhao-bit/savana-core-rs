use std::collections::HashSet;

use super::{
    AuthenticatedDeploymentLedgerSnapshotV2, DeploymentBranchV2, DeploymentControlErrorV2,
    DeploymentHardLimitsV2, DeploymentLedgerRecordV2, DeploymentLedgerStoreV2, DeploymentPhaseV2,
    DeploymentTransitionV2, DurableDeploymentAuxiliaryEvidenceStoreV2,
    DurableDeploymentEvidenceRefV2, DurableDeploymentRecoveryTargetV2,
    DurableDeploymentTransactionCoreStoreV2, DurableDeploymentTransactionRecordV2,
    DurableDeploymentTransactionStoreV2, DurableEvidenceGcCheckpointStoreV2,
    DurableInstallationEvidenceStoreV2, InstallationEvidenceEnvelopeV2,
    NativeDeploymentSigningAuthorityV2, NativeRollbackAuthorityV2, TransitionAuditV2,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DeploymentDurabilityPointV2 {
    BeforeCheckpointWrite,
    CheckpointFileFlushed,
    CheckpointRenamedBeforeDirectoryFlush,
    CheckpointDirectoryFlushed,
    CheckpointReopened,
    BeforeHeadWrite,
    HeadFileFlushed,
    HeadRenamedBeforeDirectoryFlush,
    HeadDirectoryFlushed,
    HeadReopened,
    BeforeLedgerWrite,
    LedgerFileFlushed,
    LedgerRenamedBeforeDirectoryFlush,
    LedgerDirectoryFlushed,
    LedgerReopened,
    CounterAdvanced,
    CommitReloaded,
    BeforeUnreferencedHeadUnlink,
    AfterUnreferencedHeadUnlink,
    UnreferencedHeadDirectoryFlushed,
}

#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TestAbortedCompactionCrashPointV2 {
    BeforeCheckpointWrite,
    CheckpointFileFlushed,
    CheckpointRenamedBeforeDirectoryFlush,
    CheckpointDirectoryFlushed,
    CheckpointReopened,
    BeforeLedgerWrite,
    LedgerFileFlushed,
    LedgerRenamedBeforeDirectoryFlush,
    LedgerDirectoryFlushed,
    LedgerReopened,
    CounterAdvanced,
    CommitReloaded,
}

#[cfg(any(test, feature = "test-support"))]
impl TestAbortedCompactionCrashPointV2 {
    pub const ALL: [Self; 12] = [
        Self::BeforeCheckpointWrite,
        Self::CheckpointFileFlushed,
        Self::CheckpointRenamedBeforeDirectoryFlush,
        Self::CheckpointDirectoryFlushed,
        Self::CheckpointReopened,
        Self::BeforeLedgerWrite,
        Self::LedgerFileFlushed,
        Self::LedgerRenamedBeforeDirectoryFlush,
        Self::LedgerDirectoryFlushed,
        Self::LedgerReopened,
        Self::CounterAdvanced,
        Self::CommitReloaded,
    ];

    const fn internal(self) -> DeploymentDurabilityPointV2 {
        match self {
            Self::BeforeCheckpointWrite => DeploymentDurabilityPointV2::BeforeCheckpointWrite,
            Self::CheckpointFileFlushed => DeploymentDurabilityPointV2::CheckpointFileFlushed,
            Self::CheckpointRenamedBeforeDirectoryFlush => {
                DeploymentDurabilityPointV2::CheckpointRenamedBeforeDirectoryFlush
            }
            Self::CheckpointDirectoryFlushed => {
                DeploymentDurabilityPointV2::CheckpointDirectoryFlushed
            }
            Self::CheckpointReopened => DeploymentDurabilityPointV2::CheckpointReopened,
            Self::BeforeLedgerWrite => DeploymentDurabilityPointV2::BeforeLedgerWrite,
            Self::LedgerFileFlushed => DeploymentDurabilityPointV2::LedgerFileFlushed,
            Self::LedgerRenamedBeforeDirectoryFlush => {
                DeploymentDurabilityPointV2::LedgerRenamedBeforeDirectoryFlush
            }
            Self::LedgerDirectoryFlushed => DeploymentDurabilityPointV2::LedgerDirectoryFlushed,
            Self::LedgerReopened => DeploymentDurabilityPointV2::LedgerReopened,
            Self::CounterAdvanced => DeploymentDurabilityPointV2::CounterAdvanced,
            Self::CommitReloaded => DeploymentDurabilityPointV2::CommitReloaded,
        }
    }
}

pub(super) trait DeploymentDurabilityObserverV2 {
    fn reached(
        &mut self,
        point: DeploymentDurabilityPointV2,
    ) -> Result<(), DeploymentControlErrorV2>;
}

pub(super) struct NoDeploymentCrashV2;

impl DeploymentDurabilityObserverV2 for NoDeploymentCrashV2 {
    fn reached(
        &mut self,
        _point: DeploymentDurabilityPointV2,
    ) -> Result<(), DeploymentControlErrorV2> {
        Ok(())
    }
}

#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TestDeploymentCrashPointV2 {
    BeforeHeadWrite,
    HeadFileFlushed,
    HeadRenamedBeforeDirectoryFlush,
    HeadDirectoryFlushed,
    HeadReopened,
    BeforeLedgerWrite,
    LedgerFileFlushed,
    LedgerRenamedBeforeDirectoryFlush,
    LedgerDirectoryFlushed,
    LedgerReopened,
    CounterAdvanced,
    CommitReloaded,
}

#[cfg(any(test, feature = "test-support"))]
impl TestDeploymentCrashPointV2 {
    pub const ALL: [Self; 12] = [
        Self::BeforeHeadWrite,
        Self::HeadFileFlushed,
        Self::HeadRenamedBeforeDirectoryFlush,
        Self::HeadDirectoryFlushed,
        Self::HeadReopened,
        Self::BeforeLedgerWrite,
        Self::LedgerFileFlushed,
        Self::LedgerRenamedBeforeDirectoryFlush,
        Self::LedgerDirectoryFlushed,
        Self::LedgerReopened,
        Self::CounterAdvanced,
        Self::CommitReloaded,
    ];

    const fn internal(self) -> DeploymentDurabilityPointV2 {
        match self {
            Self::BeforeHeadWrite => DeploymentDurabilityPointV2::BeforeHeadWrite,
            Self::HeadFileFlushed => DeploymentDurabilityPointV2::HeadFileFlushed,
            Self::HeadRenamedBeforeDirectoryFlush => {
                DeploymentDurabilityPointV2::HeadRenamedBeforeDirectoryFlush
            }
            Self::HeadDirectoryFlushed => DeploymentDurabilityPointV2::HeadDirectoryFlushed,
            Self::HeadReopened => DeploymentDurabilityPointV2::HeadReopened,
            Self::BeforeLedgerWrite => DeploymentDurabilityPointV2::BeforeLedgerWrite,
            Self::LedgerFileFlushed => DeploymentDurabilityPointV2::LedgerFileFlushed,
            Self::LedgerRenamedBeforeDirectoryFlush => {
                DeploymentDurabilityPointV2::LedgerRenamedBeforeDirectoryFlush
            }
            Self::LedgerDirectoryFlushed => DeploymentDurabilityPointV2::LedgerDirectoryFlushed,
            Self::LedgerReopened => DeploymentDurabilityPointV2::LedgerReopened,
            Self::CounterAdvanced => DeploymentDurabilityPointV2::CounterAdvanced,
            Self::CommitReloaded => DeploymentDurabilityPointV2::CommitReloaded,
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestDeploymentGcCrashPointV2 {
    BeforeUnreferencedHeadUnlink,
    AfterUnreferencedHeadUnlink,
    UnreferencedHeadDirectoryFlushed,
}

#[cfg(any(test, feature = "test-support"))]
impl TestDeploymentGcCrashPointV2 {
    pub const ALL: [Self; 3] = [
        Self::BeforeUnreferencedHeadUnlink,
        Self::AfterUnreferencedHeadUnlink,
        Self::UnreferencedHeadDirectoryFlushed,
    ];

    const fn internal(self) -> DeploymentDurabilityPointV2 {
        match self {
            Self::BeforeUnreferencedHeadUnlink => {
                DeploymentDurabilityPointV2::BeforeUnreferencedHeadUnlink
            }
            Self::AfterUnreferencedHeadUnlink => {
                DeploymentDurabilityPointV2::AfterUnreferencedHeadUnlink
            }
            Self::UnreferencedHeadDirectoryFlushed => {
                DeploymentDurabilityPointV2::UnreferencedHeadDirectoryFlushed
            }
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
struct OneDeploymentCrashV2 {
    crash_at: DeploymentDurabilityPointV2,
}

#[cfg(any(test, feature = "test-support"))]
impl DeploymentDurabilityObserverV2 for OneDeploymentCrashV2 {
    fn reached(
        &mut self,
        point: DeploymentDurabilityPointV2,
    ) -> Result<(), DeploymentControlErrorV2> {
        if point == self.crash_at {
            return Err(DeploymentControlErrorV2::DeploymentTransactionIo);
        }
        Ok(())
    }
}

pub struct DurableDeploymentTransitionStoreV2 {
    ledger: DeploymentLedgerStoreV2,
    transaction_heads: DurableDeploymentTransactionStoreV2,
    transaction_cores: Option<DurableDeploymentTransactionCoreStoreV2>,
    aborted_compaction_checkpoints: Option<DurableEvidenceGcCheckpointStoreV2>,
    installation_evidence: Option<DurableInstallationEvidenceStoreV2>,
    auxiliary_evidence: Option<DurableDeploymentAuxiliaryEvidenceStoreV2>,
}

impl std::fmt::Debug for DurableDeploymentTransitionStoreV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DurableDeploymentTransitionStoreV2")
            .field("ledger", &self.ledger)
            .field("transaction_heads", &self.transaction_heads)
            .field(
                "has_transaction_core_store",
                &self.transaction_cores.is_some(),
            )
            .field(
                "has_aborted_compaction_checkpoint_store",
                &self.aborted_compaction_checkpoints.is_some(),
            )
            .field(
                "has_installation_evidence_store",
                &self.installation_evidence.is_some(),
            )
            .field(
                "has_auxiliary_evidence_store",
                &self.auxiliary_evidence.is_some(),
            )
            .finish()
    }
}

impl DurableDeploymentTransitionStoreV2 {
    #[cfg(any(test, feature = "test-support"))]
    pub fn new(
        ledger: DeploymentLedgerStoreV2,
        transaction_heads: DurableDeploymentTransactionStoreV2,
    ) -> Self {
        Self {
            ledger,
            transaction_heads,
            transaction_cores: None,
            aborted_compaction_checkpoints: None,
            installation_evidence: None,
            auxiliary_evidence: None,
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn new_with_aborted_compaction_checkpoints(
        ledger: DeploymentLedgerStoreV2,
        transaction_heads: DurableDeploymentTransactionStoreV2,
        aborted_compaction_checkpoints: DurableEvidenceGcCheckpointStoreV2,
    ) -> Self {
        Self {
            ledger,
            transaction_heads,
            transaction_cores: None,
            aborted_compaction_checkpoints: Some(aborted_compaction_checkpoints),
            installation_evidence: None,
            auxiliary_evidence: None,
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn new_with_installation_evidence(
        ledger: DeploymentLedgerStoreV2,
        transaction_heads: DurableDeploymentTransactionStoreV2,
        installation_evidence: DurableInstallationEvidenceStoreV2,
    ) -> Self {
        Self {
            ledger,
            transaction_heads,
            transaction_cores: None,
            aborted_compaction_checkpoints: None,
            installation_evidence: Some(installation_evidence),
            auxiliary_evidence: None,
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn new_with_evidence_stores(
        ledger: DeploymentLedgerStoreV2,
        transaction_heads: DurableDeploymentTransactionStoreV2,
        aborted_compaction_checkpoints: DurableEvidenceGcCheckpointStoreV2,
        installation_evidence: DurableInstallationEvidenceStoreV2,
    ) -> Self {
        Self {
            ledger,
            transaction_heads,
            transaction_cores: None,
            aborted_compaction_checkpoints: Some(aborted_compaction_checkpoints),
            installation_evidence: Some(installation_evidence),
            auxiliary_evidence: None,
        }
    }

    pub fn new_with_core_and_installation_evidence(
        ledger: DeploymentLedgerStoreV2,
        transaction_heads: DurableDeploymentTransactionStoreV2,
        transaction_cores: DurableDeploymentTransactionCoreStoreV2,
        installation_evidence: DurableInstallationEvidenceStoreV2,
        auxiliary_evidence: DurableDeploymentAuxiliaryEvidenceStoreV2,
    ) -> Self {
        Self {
            ledger,
            transaction_heads,
            transaction_cores: Some(transaction_cores),
            aborted_compaction_checkpoints: None,
            installation_evidence: Some(installation_evidence),
            auxiliary_evidence: Some(auxiliary_evidence),
        }
    }

    pub fn new_with_core_and_evidence_stores(
        ledger: DeploymentLedgerStoreV2,
        transaction_heads: DurableDeploymentTransactionStoreV2,
        transaction_cores: DurableDeploymentTransactionCoreStoreV2,
        aborted_compaction_checkpoints: DurableEvidenceGcCheckpointStoreV2,
        installation_evidence: DurableInstallationEvidenceStoreV2,
        auxiliary_evidence: DurableDeploymentAuxiliaryEvidenceStoreV2,
    ) -> Self {
        Self {
            ledger,
            transaction_heads,
            transaction_cores: Some(transaction_cores),
            aborted_compaction_checkpoints: Some(aborted_compaction_checkpoints),
            installation_evidence: Some(installation_evidence),
            auxiliary_evidence: Some(auxiliary_evidence),
        }
    }

    pub fn load_authenticated(
        &self,
        rollback_authority: &mut dyn NativeRollbackAuthorityV2,
    ) -> Result<AuthenticatedDeploymentLedgerSnapshotV2, DeploymentControlErrorV2> {
        self.ledger.load_selected_authenticated(rollback_authority)
    }

    pub fn load_recovery_plan(
        &self,
        rollback_authority: &mut dyn NativeRollbackAuthorityV2,
    ) -> Result<super::AuthenticatedDeploymentRecoveryPlanV2, DeploymentControlErrorV2> {
        let snapshot = self.load_authenticated(rollback_authority)?;
        let projection = snapshot.selected_record().projection();
        match (
            projection.transaction_id(),
            projection.transaction_head_digest(),
        ) {
            (None, None) => super::AuthenticatedDeploymentRecoveryPlanV2::without_transaction(
                projection.phase(),
            ),
            (Some(transaction_id), Some(head_digest)) => {
                let core_store = self
                    .transaction_cores
                    .as_ref()
                    .ok_or(DeploymentControlErrorV2::DeploymentTransactionIo)?;
                let selected_head = self.transaction_heads.load_head(head_digest)?;
                if selected_head.transaction_id() != transaction_id {
                    return Err(DeploymentControlErrorV2::TransactionBindingMismatch);
                }
                let core = core_store.load_core(selected_head.core_signed_digest())?;
                let branch = if core.material().recovery_target.is_normal() {
                    DeploymentBranchV2::Normal
                } else {
                    DeploymentBranchV2::BootstrapBridgeRestore
                };
                let chain = self.authenticate_selected_chain(&snapshot, branch)?;
                let authenticated_head = chain
                    .last()
                    .ok_or(DeploymentControlErrorV2::InvalidDurableDeploymentHead)?;
                if authenticated_head.canonical_bytes() != selected_head.canonical_bytes() {
                    return Err(DeploymentControlErrorV2::InvalidDurableDeploymentHead);
                }
                super::AuthenticatedDeploymentRecoveryPlanV2::with_transaction(
                    projection.phase(),
                    branch,
                    authenticated_head,
                    &core,
                )
            }
            _ => Err(DeploymentControlErrorV2::TransactionBindingMismatch),
        }
    }

    pub fn authenticate_selected_chain(
        &self,
        snapshot: &AuthenticatedDeploymentLedgerSnapshotV2,
        branch: DeploymentBranchV2,
    ) -> Result<Vec<DurableDeploymentTransactionRecordV2>, DeploymentControlErrorV2> {
        let maximum =
            usize::try_from(DeploymentHardLimitsV2::compiled().max_transaction_head_records())
                .map_err(|_| DeploymentControlErrorV2::InvalidDurableDeploymentHead)?;
        self.transaction_heads
            .load_selected_chain(snapshot, maximum, branch)
    }

    pub fn load_aborted_compaction_checkpoint(
        &self,
        aborted_ledger_record_digest: savana_kernel_protocol::v2::Digest32V2,
    ) -> Result<InstallationEvidenceEnvelopeV2, DeploymentControlErrorV2> {
        self.aborted_compaction_checkpoints
            .as_ref()
            .ok_or(DeploymentControlErrorV2::EvidenceGcCheckpointIo)?
            .load_aborted_checkpoint_envelope(aborted_ledger_record_digest)
    }

    pub fn compact_aborted_to_idle(
        &self,
        checkpoint_envelope: &InstallationEvidenceEnvelopeV2,
        written_at_unix_ms: u64,
        signing_authority: &mut dyn NativeDeploymentSigningAuthorityV2,
        rollback_authority: &mut dyn NativeRollbackAuthorityV2,
    ) -> Result<AuthenticatedDeploymentLedgerSnapshotV2, DeploymentControlErrorV2> {
        self.compact_aborted_to_idle_observed(
            checkpoint_envelope,
            written_at_unix_ms,
            signing_authority,
            rollback_authority,
            &mut NoDeploymentCrashV2,
        )
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn compact_aborted_to_idle_with_crash_for_test(
        &self,
        checkpoint_envelope: &InstallationEvidenceEnvelopeV2,
        written_at_unix_ms: u64,
        signing_authority: &mut dyn NativeDeploymentSigningAuthorityV2,
        rollback_authority: &mut dyn NativeRollbackAuthorityV2,
        crash_at: TestAbortedCompactionCrashPointV2,
    ) -> Result<AuthenticatedDeploymentLedgerSnapshotV2, DeploymentControlErrorV2> {
        self.compact_aborted_to_idle_observed(
            checkpoint_envelope,
            written_at_unix_ms,
            signing_authority,
            rollback_authority,
            &mut OneDeploymentCrashV2 {
                crash_at: crash_at.internal(),
            },
        )
    }

    fn compact_aborted_to_idle_observed(
        &self,
        checkpoint_envelope: &InstallationEvidenceEnvelopeV2,
        written_at_unix_ms: u64,
        signing_authority: &mut dyn NativeDeploymentSigningAuthorityV2,
        rollback_authority: &mut dyn NativeRollbackAuthorityV2,
        observer: &mut dyn DeploymentDurabilityObserverV2,
    ) -> Result<AuthenticatedDeploymentLedgerSnapshotV2, DeploymentControlErrorV2> {
        let checkpoint_store = self
            .aborted_compaction_checkpoints
            .as_ref()
            .ok_or(DeploymentControlErrorV2::EvidenceGcCheckpointIo)?;
        checkpoint_store.append_aborted_checkpoint_observed(checkpoint_envelope, observer)?;

        let deployment_mutex = self.ledger.acquire_deployment_mutex()?;
        let snapshot = self
            .ledger
            .load_selected_authenticated(rollback_authority)?;
        let current = snapshot.selected_record();
        if current.projection().phase() != DeploymentPhaseV2::Aborted {
            return Err(DeploymentControlErrorV2::IllegalPhaseTransition);
        }
        let chain = self.authenticate_selected_chain(&snapshot, DeploymentBranchV2::Normal)?;
        let checkpoint =
            checkpoint_envelope.evidence_gc_checkpoint(self.ledger.activation_verifier())?;
        checkpoint.validate_aborted_binding(current, &chain)?;
        let durable_envelope =
            checkpoint_store.load_aborted_checkpoint_envelope(current.signed_record_digest())?;
        if durable_envelope.canonical_bytes() != checkpoint_envelope.canonical_bytes() {
            return Err(DeploymentControlErrorV2::InvalidCompactedTransactionProvenance);
        }
        let durable_checkpoint =
            durable_envelope.evidence_gc_checkpoint(self.ledger.activation_verifier())?;
        let candidate = DeploymentLedgerRecordV2::new_idle_successor_signed_with_authority(
            current,
            &durable_checkpoint,
            &chain,
            written_at_unix_ms,
            signing_authority,
            self.ledger.activation_verifier(),
        )?;
        self.ledger.write_successor_record_observed(
            &candidate,
            DeploymentBranchV2::Normal,
            signing_authority,
            rollback_authority,
            observer,
        )?;
        let committed = self
            .ledger
            .load_selected_authenticated(rollback_authority)?;
        observer.reached(DeploymentDurabilityPointV2::CommitReloaded)?;
        if committed.selected_record().signed_record_digest() != candidate.signed_record_digest() {
            return Err(DeploymentControlErrorV2::LedgerConflict);
        }
        deployment_mutex
            .recheck()
            .map_err(|_| DeploymentControlErrorV2::DeploymentMutexUnavailable)?;
        Ok(committed)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn commit_transition(
        &self,
        current_branch: Option<DeploymentBranchV2>,
        next_branch: DeploymentBranchV2,
        candidate_head: &DurableDeploymentTransactionRecordV2,
        candidate_record: &DeploymentLedgerRecordV2,
        signing_authority: &mut dyn NativeDeploymentSigningAuthorityV2,
        rollback_authority: &mut dyn NativeRollbackAuthorityV2,
    ) -> Result<AuthenticatedDeploymentLedgerSnapshotV2, DeploymentControlErrorV2> {
        self.commit_transition_observed(
            current_branch,
            next_branch,
            candidate_head,
            candidate_record,
            signing_authority,
            rollback_authority,
            &mut NoDeploymentCrashV2,
        )
    }

    #[cfg(any(test, feature = "test-support"))]
    #[allow(clippy::too_many_arguments)]
    pub fn commit_transition_with_crash_for_test(
        &self,
        current_branch: Option<DeploymentBranchV2>,
        next_branch: DeploymentBranchV2,
        candidate_head: &DurableDeploymentTransactionRecordV2,
        candidate_record: &DeploymentLedgerRecordV2,
        signing_authority: &mut dyn NativeDeploymentSigningAuthorityV2,
        rollback_authority: &mut dyn NativeRollbackAuthorityV2,
        crash_at: TestDeploymentCrashPointV2,
    ) -> Result<AuthenticatedDeploymentLedgerSnapshotV2, DeploymentControlErrorV2> {
        self.commit_transition_observed(
            current_branch,
            next_branch,
            candidate_head,
            candidate_record,
            signing_authority,
            rollback_authority,
            &mut OneDeploymentCrashV2 {
                crash_at: crash_at.internal(),
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn commit_transition_observed(
        &self,
        current_branch: Option<DeploymentBranchV2>,
        next_branch: DeploymentBranchV2,
        candidate_head: &DurableDeploymentTransactionRecordV2,
        candidate_record: &DeploymentLedgerRecordV2,
        signing_authority: &mut dyn NativeDeploymentSigningAuthorityV2,
        rollback_authority: &mut dyn NativeRollbackAuthorityV2,
        observer: &mut dyn DeploymentDurabilityObserverV2,
    ) -> Result<AuthenticatedDeploymentLedgerSnapshotV2, DeploymentControlErrorV2> {
        let deployment_mutex = self.ledger.acquire_deployment_mutex()?;
        let snapshot = self
            .ledger
            .load_selected_authenticated(rollback_authority)?;
        let current = snapshot.selected_record();
        let current_projection = current.projection();
        let current_chain = match (
            current_projection.transaction_id(),
            current_projection.transaction_head_digest(),
            current_branch,
        ) {
            (None, None, None) => Vec::new(),
            (Some(_), Some(_), Some(branch)) => {
                self.authenticate_selected_chain(&snapshot, branch)?
            }
            _ => return Err(DeploymentControlErrorV2::TransactionBindingMismatch),
        };

        candidate_head.validate_expected_previous_ledger(current)?;
        self.validate_transaction_core(candidate_head, current)?;
        let continuing_transaction =
            current_projection.transaction_id() == Some(candidate_head.transaction_id());
        if continuing_transaction {
            if current_branch != Some(next_branch) {
                return Err(DeploymentControlErrorV2::TransactionBindingMismatch);
            }
            current_chain
                .last()
                .ok_or(DeploymentControlErrorV2::InvalidDurableDeploymentHead)?
                .validate_successor(candidate_head, next_branch)?;
        } else if candidate_head.head_sequence() != 1
            || candidate_head.previous_head_digest().is_some()
            || candidate_head.target_phase() != DeploymentPhaseV2::Prepared
        {
            return Err(DeploymentControlErrorV2::TransactionBindingMismatch);
        }

        if candidate_record.projection().transaction_id() != Some(candidate_head.transaction_id())
            || candidate_record.projection().transaction_head_digest()
                != Some(candidate_head.signed_digest())
            || candidate_record.projection().phase() != candidate_head.target_phase()
        {
            return Err(DeploymentControlErrorV2::TransactionBindingMismatch);
        }
        current.validate_successor(candidate_record, next_branch)?;
        self.validate_evidence_refs(current, &current_chain, candidate_head, next_branch)?;
        self.validate_failed_safe_evidence_binding(
            current,
            &current_chain,
            candidate_head,
            next_branch,
        )?;
        if self.transaction_cores.is_some() {
            self.append_transition_audit(
                current,
                candidate_head,
                candidate_record,
                next_branch,
                signing_authority,
            )?;
        }

        let appended = self
            .transaction_heads
            .append_head_observed(candidate_head, observer)?;
        if appended != candidate_head.signed_digest()
            || self
                .transaction_heads
                .load_head(appended)?
                .canonical_bytes()
                != candidate_head.canonical_bytes()
        {
            return Err(DeploymentControlErrorV2::DeploymentTransactionIo);
        }
        self.ledger.write_successor_record_observed(
            candidate_record,
            next_branch,
            signing_authority,
            rollback_authority,
            observer,
        )?;
        let committed = self
            .ledger
            .load_selected_authenticated(rollback_authority)?;
        observer.reached(DeploymentDurabilityPointV2::CommitReloaded)?;
        if committed.selected_record().signed_record_digest()
            != candidate_record.signed_record_digest()
        {
            return Err(DeploymentControlErrorV2::LedgerConflict);
        }
        deployment_mutex
            .recheck()
            .map_err(|_| DeploymentControlErrorV2::DeploymentMutexUnavailable)?;
        Ok(committed)
    }

    fn validate_transaction_core(
        &self,
        candidate_head: &DurableDeploymentTransactionRecordV2,
        current: &DeploymentLedgerRecordV2,
    ) -> Result<(), DeploymentControlErrorV2> {
        let Some(store) = self.transaction_cores.as_ref() else {
            #[cfg(any(test, feature = "test-support"))]
            {
                return Ok(());
            }
            #[cfg(not(any(test, feature = "test-support")))]
            {
                return Err(DeploymentControlErrorV2::DeploymentTransactionIo);
            }
        };
        let core = store.load_core(candidate_head.core_signed_digest())?;
        if core.signed_digest() != candidate_head.core_signed_digest()
            || core.transaction_id() != candidate_head.transaction_id()
            || core.material().installation_id != candidate_head.installation_id()
            || core.material().installation_epoch != candidate_head.installation_epoch()
        {
            return Err(DeploymentControlErrorV2::TransactionBindingMismatch);
        }
        if candidate_head.head_sequence() == 1 {
            core.validate_selected_ledger_pre_state(current)?;
        }
        Ok(())
    }

    fn append_transition_audit(
        &self,
        current: &DeploymentLedgerRecordV2,
        candidate_head: &DurableDeploymentTransactionRecordV2,
        candidate_record: &DeploymentLedgerRecordV2,
        branch: DeploymentBranchV2,
        signing_authority: &mut dyn NativeDeploymentSigningAuthorityV2,
    ) -> Result<(), DeploymentControlErrorV2> {
        let store = self
            .installation_evidence
            .as_ref()
            .ok_or(DeploymentControlErrorV2::InstallationEvidenceIo)?;
        let current_projection = current.projection();
        let candidate_projection = candidate_record.projection();
        let audit = TransitionAuditV2::new(
            candidate_head.installation_id(),
            candidate_head.installation_epoch(),
            candidate_head.transaction_id(),
            candidate_head.core_signed_digest(),
            branch,
            current_projection.phase(),
            candidate_projection.phase(),
            current.signed_record_digest(),
            current_projection.generation(),
            current_projection.transaction_head_digest(),
            candidate_head.signed_digest(),
            candidate_head.head_sequence(),
            candidate_record.signed_record_digest(),
            candidate_projection.generation(),
            candidate_projection.effects_fenced(),
            candidate_projection.effect_fence_epoch(),
            candidate_record.written_at_unix_ms(),
        )?;
        let previous = store.load_latest()?;
        let sequence = previous
            .as_ref()
            .map(InstallationEvidenceEnvelopeV2::evidence_sequence)
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(DeploymentControlErrorV2::InstallationEvidenceIo)?;
        let previous_digest = previous.map(|envelope| envelope.signed_digest());
        let envelope = InstallationEvidenceEnvelopeV2::new_transition_audit_signed_with_authority(
            sequence,
            previous_digest,
            &audit,
            signing_authority,
            self.ledger.activation_verifier(),
        )?;
        let signed_digest = store.append(&envelope)?;
        let reopened = store.load_signed_digest(signed_digest)?;
        if reopened.canonical_bytes() != envelope.canonical_bytes()
            || reopened.transition_audit()? != audit
        {
            return Err(DeploymentControlErrorV2::InstallationEvidenceIo);
        }
        Ok(())
    }

    fn validate_evidence_refs(
        &self,
        current: &DeploymentLedgerRecordV2,
        current_chain: &[DurableDeploymentTransactionRecordV2],
        candidate_head: &DurableDeploymentTransactionRecordV2,
        next_branch: DeploymentBranchV2,
    ) -> Result<(), DeploymentControlErrorV2> {
        self.validate_auxiliary_evidence_refs(current, current_chain, candidate_head, next_branch)?;
        let previous_refs = current_chain
            .last()
            .map(DurableDeploymentTransactionRecordV2::evidence_refs)
            .unwrap_or_default();
        let requires_envelope_store = candidate_head
            .evidence_refs()
            .iter()
            .filter(|reference| !previous_refs.contains(reference))
            .any(|reference| matches!(reference.tag(), 1 | 5 | 6 | 7 | 9));
        let Some(store) = self.installation_evidence.as_ref() else {
            #[cfg(any(test, feature = "test-support"))]
            {
                return Ok(());
            }
            #[cfg(not(any(test, feature = "test-support")))]
            {
                return if requires_envelope_store {
                    Err(DeploymentControlErrorV2::InstallationEvidenceIo)
                } else {
                    Ok(())
                };
            }
        };
        if !requires_envelope_store {
            return Ok(());
        }
        for reference in candidate_head.evidence_refs() {
            if previous_refs.contains(reference) {
                continue;
            }
            let digest = reference.digest();
            match reference {
                DurableDeploymentEvidenceRefV2::StoreCompatibility(_)
                | DurableDeploymentEvidenceRefV2::VerificationEvidence(_)
                | DurableDeploymentEvidenceRefV2::RollbackVerificationEvidence(_)
                | DurableDeploymentEvidenceRefV2::RecoveryRollbackReadinessEvidence(_)
                | DurableDeploymentEvidenceRefV2::DeploymentFailure(_) => {}
                _ => continue,
            }
            let envelope_result = store.load_signed_digest(digest);
            #[cfg(any(test, feature = "test-support"))]
            let envelope = match envelope_result {
                Ok(envelope) => envelope,
                Err(_)
                    if !matches!(
                        reference,
                        DurableDeploymentEvidenceRefV2::DeploymentFailure(_)
                    ) =>
                {
                    continue;
                }
                Err(error) => return Err(error),
            };
            #[cfg(not(any(test, feature = "test-support")))]
            let envelope = envelope_result?;
            if envelope.signed_digest() != digest {
                return Err(DeploymentControlErrorV2::InstallationEvidenceIo);
            }
            match reference {
                DurableDeploymentEvidenceRefV2::StoreCompatibility(_) => {
                    envelope.store_compatibility_attestation(self.ledger.activation_verifier())?;
                }
                DurableDeploymentEvidenceRefV2::VerificationEvidence(_) => {
                    let evidence =
                        envelope.verification_evidence(self.ledger.activation_verifier())?;
                    if evidence.transaction_id() != candidate_head.transaction_id()
                        || evidence.verified_at_unix_ms() > candidate_head.written_at_unix_ms()
                    {
                        return Err(DeploymentControlErrorV2::InvalidVerificationEvidence);
                    }
                }
                DurableDeploymentEvidenceRefV2::RollbackVerificationEvidence(_) => {
                    let evidence = envelope
                        .rollback_verification_evidence(self.ledger.activation_verifier())?;
                    if evidence.transaction_id() != candidate_head.transaction_id()
                        || evidence.verified_at_unix_ms() > candidate_head.written_at_unix_ms()
                    {
                        return Err(DeploymentControlErrorV2::InvalidRollbackVerificationEvidence);
                    }
                }
                DurableDeploymentEvidenceRefV2::RecoveryRollbackReadinessEvidence(_) => {
                    let evidence = envelope
                        .recovery_rollback_readiness_evidence(self.ledger.activation_verifier())?;
                    if evidence.transaction_id() != candidate_head.transaction_id()
                        || evidence.verified_at_unix_ms() > candidate_head.written_at_unix_ms()
                    {
                        return Err(
                            DeploymentControlErrorV2::InvalidRecoveryRollbackReadinessEvidence,
                        );
                    }
                }
                DurableDeploymentEvidenceRefV2::DeploymentFailure(_) => {
                    envelope.deployment_failure_evidence()?;
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn validate_auxiliary_evidence_refs(
        &self,
        current: &DeploymentLedgerRecordV2,
        current_chain: &[DurableDeploymentTransactionRecordV2],
        candidate_head: &DurableDeploymentTransactionRecordV2,
        next_branch: DeploymentBranchV2,
    ) -> Result<(), DeploymentControlErrorV2> {
        let previous_refs = current_chain
            .last()
            .map(DurableDeploymentTransactionRecordV2::evidence_refs)
            .unwrap_or_default();
        let requires_store = candidate_head
            .evidence_refs()
            .iter()
            .filter(|reference| !previous_refs.contains(reference))
            .any(|reference| matches!(reference.tag(), 2 | 3 | 4 | 8));
        let Some(store) = self.auxiliary_evidence.as_ref() else {
            #[cfg(any(test, feature = "test-support"))]
            {
                return Ok(());
            }
            #[cfg(not(any(test, feature = "test-support")))]
            {
                return if requires_store {
                    Err(DeploymentControlErrorV2::DeploymentAuxiliaryEvidenceIo)
                } else {
                    Ok(())
                };
            }
        };
        if !requires_store {
            return Ok(());
        }
        for reference in candidate_head.evidence_refs() {
            if previous_refs.contains(reference) {
                continue;
            }
            match reference {
                DurableDeploymentEvidenceRefV2::NativeControlMeasurementSet(digest) => {
                    let evidence = store.load_native_control_measurement_set(*digest)?;
                    if evidence.digest() != *digest {
                        return Err(DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence);
                    }
                }
                DurableDeploymentEvidenceRefV2::FrozenEffectWorkSet(digest) => {
                    let frozen = store.load_frozen_effect_work_set(*digest)?;
                    if frozen.digest() != *digest
                        || frozen.installation_id() != candidate_head.installation_id()
                        || frozen.transaction_id() != candidate_head.transaction_id()
                        || frozen.pre_arm_ledger_record_digest() != current.signed_record_digest()
                        || frozen.pre_arm_generation() != current.projection().generation()
                        || frozen.pre_arm_effect_fence_epoch()
                            != current.projection().effect_fence_epoch()
                    {
                        return Err(DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence);
                    }
                }
                DurableDeploymentEvidenceRefV2::RoleJournalReconciliation(digest) => {
                    let reconciliation = store.load_role_journal_reconciliation(*digest)?;
                    let frozen_digest = candidate_head
                        .evidence_refs()
                        .iter()
                        .find_map(|reference| match reference {
                            DurableDeploymentEvidenceRefV2::FrozenEffectWorkSet(digest) => {
                                Some(*digest)
                            }
                            _ => None,
                        })
                        .ok_or(DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?;
                    let frozen = store.load_frozen_effect_work_set(frozen_digest)?;
                    reconciliation.validate_frozen_set(&frozen)?;
                    if reconciliation.digest() != *digest
                        || reconciliation.installation_id() != candidate_head.installation_id()
                        || reconciliation.transaction_id() != candidate_head.transaction_id()
                        || reconciliation.armed_ledger_record_signed_digest()
                            != current.signed_record_digest()
                        || reconciliation.armed_ledger_generation()
                            != current.projection().generation()
                        || reconciliation.reconciled_at_unix_ms()
                            > candidate_head.written_at_unix_ms()
                    {
                        return Err(DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence);
                    }
                }
                DurableDeploymentEvidenceRefV2::BootstrapBridgeRestoreIntegrity(digest) => {
                    self.validate_bridge_restore_integrity(
                        store,
                        *digest,
                        current,
                        candidate_head,
                        next_branch,
                    )?;
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn validate_bridge_restore_integrity(
        &self,
        store: &DurableDeploymentAuxiliaryEvidenceStoreV2,
        digest: savana_kernel_protocol::v2::Digest32V2,
        current: &DeploymentLedgerRecordV2,
        candidate_head: &DurableDeploymentTransactionRecordV2,
        next_branch: DeploymentBranchV2,
    ) -> Result<(), DeploymentControlErrorV2> {
        let evidence = store.load_bootstrap_bridge_restore_integrity(digest)?;
        let core = self
            .transaction_cores
            .as_ref()
            .ok_or(DeploymentControlErrorV2::DeploymentTransactionIo)?
            .load_core(candidate_head.core_signed_digest())?;
        let intent = core.material().signed_transaction.intent();
        let DurableDeploymentRecoveryTargetV2::BootstrapBridgeRestore {
            bridge_manifest,
            maintenance_intent_signed_digest: _,
            bridge_genesis_ledger_record_signed_digest,
            bootstrap_slot_closure_digest,
            premaintenance_runtime_manifest_digest,
        } = &core.material().recovery_target
        else {
            return Err(DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence);
        };
        let role_digest = candidate_head
            .evidence_refs()
            .iter()
            .find_map(|reference| match reference {
                DurableDeploymentEvidenceRefV2::RoleJournalReconciliation(digest) => Some(*digest),
                _ => None,
            })
            .ok_or(DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?;
        let native_digest = candidate_head
            .evidence_refs()
            .iter()
            .find_map(|reference| match reference {
                DurableDeploymentEvidenceRefV2::NativeControlMeasurementSet(digest) => {
                    Some(*digest)
                }
                _ => None,
            })
            .ok_or(DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?;
        let highest_ever_digest = current.highest_ever().digest()?;
        if evidence.digest() != digest
            || next_branch != DeploymentBranchV2::BootstrapBridgeRestore
            || candidate_head.target_phase() != DeploymentPhaseV2::BridgeRestoreVerified
            || evidence.installation_id() != candidate_head.installation_id()
            || evidence.installation_epoch() != candidate_head.installation_epoch()
            || evidence.transaction_id() != candidate_head.transaction_id()
            || evidence.transaction_intent_digest() != intent.intent_digest()
            || evidence.recovery_target_digest() != intent.recovery_target().digest()
            || evidence.restore_origin_phase()
                != current
                    .rollback_origin_phase()
                    .ok_or(DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?
            || evidence.bridge_restore_installed_ledger_generation()
                != current.projection().generation()
            || evidence.bridge_restore_installed_effect_fence_epoch()
                != current.projection().effect_fence_epoch()
            || !current.projection().effects_fenced()
            || evidence.bridge_manifest_digest() != bridge_manifest.signed_digest()
            || evidence.bridge_genesis_ledger_record_signed_digest()
                != *bridge_genesis_ledger_record_signed_digest
            || evidence.bootstrap_slot_closure_digest() != *bootstrap_slot_closure_digest
            || evidence.premaintenance_runtime_manifest_digest()
                != *premaintenance_runtime_manifest_digest
            || evidence.retained_highest_ever_digest() != highest_ever_digest
            || evidence.role_journal_reconciliation_digest() != role_digest
            || evidence.native_effect_fence_measurement_digest() != native_digest
            || evidence.verified_at_unix_ms() > candidate_head.written_at_unix_ms()
        {
            return Err(DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence);
        }
        Ok(())
    }

    fn validate_failed_safe_evidence_binding(
        &self,
        current: &DeploymentLedgerRecordV2,
        current_chain: &[DurableDeploymentTransactionRecordV2],
        candidate_head: &DurableDeploymentTransactionRecordV2,
        next_branch: DeploymentBranchV2,
    ) -> Result<(), DeploymentControlErrorV2> {
        if candidate_head.target_phase() != DeploymentPhaseV2::FailedSafe {
            return Ok(());
        }
        let failure_digest = candidate_head
            .evidence_refs()
            .iter()
            .find_map(|reference| match reference {
                DurableDeploymentEvidenceRefV2::DeploymentFailure(digest) => Some(*digest),
                _ => None,
            })
            .ok_or(DeploymentControlErrorV2::InvalidDeploymentFailureEvidence)?;
        let envelope = self
            .installation_evidence
            .as_ref()
            .ok_or(DeploymentControlErrorV2::InstallationEvidenceIo)?
            .load_signed_digest(failure_digest)?;
        if envelope.signed_digest() != failure_digest {
            return Err(DeploymentControlErrorV2::InvalidDeploymentFailureEvidence);
        }
        let failure = envelope.deployment_failure_evidence()?;
        let source_head = current_chain
            .last()
            .ok_or(DeploymentControlErrorV2::InvalidDeploymentFailureEvidence)?;
        let projection = current.projection();
        if failure.installation_id() != projection.installation_id()
            || failure.installation_epoch() != projection.installation_epoch()
            || failure.transaction_id() != candidate_head.transaction_id()
            || failure.core_signed_digest() != candidate_head.core_signed_digest()
            || failure.source_head_signed_digest() != source_head.signed_digest()
            || failure.source_phase() != projection.phase()
            || failure.observed_at_unix_ms() > candidate_head.written_at_unix_ms()
        {
            return Err(DeploymentControlErrorV2::InvalidDeploymentFailureEvidence);
        }
        DeploymentTransitionV2::new(
            next_branch,
            failure.source_phase(),
            failure.failed_transition_target(),
        )
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentFailureEvidence)?;
        Ok(())
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn hold_deployment_mutex_for_test(
        &self,
        acquired: &std::sync::Barrier,
        release: &std::sync::Barrier,
    ) -> Result<(), DeploymentControlErrorV2> {
        let deployment_mutex = self.ledger.acquire_deployment_mutex()?;
        acquired.wait();
        release.wait();
        deployment_mutex
            .recheck()
            .map_err(|_| DeploymentControlErrorV2::DeploymentMutexUnavailable)
    }

    pub fn gc_current_generation_orphan_heads(
        &self,
        branch: DeploymentBranchV2,
        rollback_authority: &mut dyn NativeRollbackAuthorityV2,
    ) -> Result<usize, DeploymentControlErrorV2> {
        self.gc_current_generation_orphan_heads_observed(
            branch,
            rollback_authority,
            &mut NoDeploymentCrashV2,
        )
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn gc_current_generation_orphan_heads_with_crash_for_test(
        &self,
        branch: DeploymentBranchV2,
        rollback_authority: &mut dyn NativeRollbackAuthorityV2,
        crash_at: TestDeploymentGcCrashPointV2,
    ) -> Result<usize, DeploymentControlErrorV2> {
        self.gc_current_generation_orphan_heads_observed(
            branch,
            rollback_authority,
            &mut OneDeploymentCrashV2 {
                crash_at: crash_at.internal(),
            },
        )
    }

    fn gc_current_generation_orphan_heads_observed(
        &self,
        branch: DeploymentBranchV2,
        rollback_authority: &mut dyn NativeRollbackAuthorityV2,
        observer: &mut dyn DeploymentDurabilityObserverV2,
    ) -> Result<usize, DeploymentControlErrorV2> {
        let deployment_mutex = self.ledger.acquire_deployment_mutex()?;
        let snapshot = self
            .ledger
            .load_selected_authenticated(rollback_authority)?;
        let maximum =
            usize::try_from(DeploymentHardLimitsV2::compiled().max_transaction_head_records())
                .map_err(|_| DeploymentControlErrorV2::InvalidDurableDeploymentHead)?;
        let selected_chain = self.authenticate_selected_chain(&snapshot, branch)?;
        let mut retained = HashSet::new();
        retained
            .try_reserve(maximum)
            .map_err(|_| DeploymentControlErrorV2::DeploymentTransactionIo)?;
        retained.extend(
            selected_chain
                .iter()
                .map(DurableDeploymentTransactionRecordV2::signed_digest),
        );

        if let Some(predecessor) = snapshot.predecessor_record() {
            let projection = predecessor.projection();
            match (
                projection.transaction_id(),
                projection.transaction_head_digest(),
            ) {
                (None, None) => {}
                (Some(transaction_id), Some(head_digest)) => {
                    let chain = self
                        .transaction_heads
                        .load_chain_any_branch(head_digest, maximum)?;
                    let head = chain
                        .last()
                        .ok_or(DeploymentControlErrorV2::InvalidDurableDeploymentHead)?;
                    if head.signed_digest() != head_digest
                        || head.transaction_id() != transaction_id
                        || head.target_phase() != projection.phase()
                    {
                        return Err(DeploymentControlErrorV2::TransactionBindingMismatch);
                    }
                    retained.extend(
                        chain
                            .iter()
                            .map(DurableDeploymentTransactionRecordV2::signed_digest),
                    );
                }
                _ => return Err(DeploymentControlErrorV2::TransactionBindingMismatch),
            }
        }
        if let Some(checkpoints) = &self.aborted_compaction_checkpoints {
            for head_digest in checkpoints.retained_aborted_final_heads()? {
                let chain = self.transaction_heads.load_chain(
                    head_digest,
                    maximum,
                    DeploymentBranchV2::Normal,
                )?;
                retained.extend(
                    chain
                        .iter()
                        .map(DurableDeploymentTransactionRecordV2::signed_digest),
                );
            }
        }
        let deleted = self.transaction_heads.gc_unreferenced_heads_observed(
            &retained,
            snapshot.selected_record().signed_record_digest(),
            snapshot.selected_record().projection().generation(),
            observer,
        )?;
        deployment_mutex
            .recheck()
            .map_err(|_| DeploymentControlErrorV2::DeploymentMutexUnavailable)?;
        Ok(deleted)
    }
}
