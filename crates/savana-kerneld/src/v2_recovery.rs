use std::sync::Arc;
use std::time::{Duration, Instant};

use savana_kernel_protocol::v2::{
    Digest32V2, DurableReleaseIdV2, Ed25519KeyIdV2, ExecutorFailureClassV2, Nonce32V2, UnixMillisV2,
};
use savana_policy_core::v2::{
    DispatchRecoverySubjectKindV2, KernelDispatchRecoveryProjectionV2, KernelDispatchStateV2,
    SignedExecutorDispositionReceiptV2,
};
use savana_vault::{VaultReleaseRecoveryProjectionV2, VaultReleaseRecoveryStateV2};
use sha2::{Digest as _, Sha256};

use crate::v2_state_owner::{StateOwnerErrorV2, StateOwnerV2};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecoveryErrorV2 {
    InvalidIdentity,
    Contradiction,
    AllocationFailure,
    BackendUnavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RecoveryIdentityV2 {
    execution_nonce: Nonce32V2,
    dispatch_core_digest: Digest32V2,
    dispatch_subject_digest: Digest32V2,
}

impl RecoveryIdentityV2 {
    pub(crate) fn new(
        execution_nonce: Nonce32V2,
        dispatch_core_digest: Digest32V2,
        dispatch_subject_digest: Digest32V2,
    ) -> Result<Self, RecoveryErrorV2> {
        if is_zero(execution_nonce.as_bytes())
            || is_zero(dispatch_core_digest.as_bytes())
            || is_zero(dispatch_subject_digest.as_bytes())
        {
            return Err(RecoveryErrorV2::InvalidIdentity);
        }
        Ok(Self {
            execution_nonce,
            dispatch_core_digest,
            dispatch_subject_digest,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KernelRecoveryStateV2 {
    Prepared,
    Dispatching,
    EffectStarted,
    CompletionCommitted,
    FailedNoEffect,
    Indeterminate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExecdRecoveryStateV2 {
    Absent,
    Prepared,
    ProviderAttemptPrepared,
    EffectStarted,
    KnownSuccess,
    FailedNoEffect,
    Indeterminate,
    Acknowledged,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VaultRecoveryStateV2 {
    NotApplicable,
    Authorized,
    Prepared,
    Dispatching,
    Released,
    FailedNoEffect,
    Indeterminate,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecoverySubjectKindV2 {
    ToolExecution,
    FinalRelease,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecoverySubjectV2 {
    ToolExecution,
    FinalRelease(DurableReleaseIdV2),
}

impl RecoverySubjectV2 {
    const fn kind(self) -> RecoverySubjectKindV2 {
        match self {
            Self::ToolExecution => RecoverySubjectKindV2::ToolExecution,
            Self::FinalRelease(_) => RecoverySubjectKindV2::FinalRelease,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct KernelRecoveryRecordV2 {
    identity: RecoveryIdentityV2,
    state: KernelRecoveryStateV2,
    subject: RecoverySubjectV2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ExecdRecoveryRecordV2 {
    identity: RecoveryIdentityV2,
    state: ExecdRecoveryStateV2,
    subject: RecoverySubjectKindV2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct VaultRecoveryRecordV2 {
    durable_release_id: DurableReleaseIdV2,
    identity: Option<RecoveryIdentityV2>,
    state: VaultRecoveryStateV2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RecoverySnapshotV2 {
    identity: RecoveryIdentityV2,
    kernel: KernelRecoveryStateV2,
    execd: ExecdRecoveryStateV2,
    vault: VaultRecoveryStateV2,
}

impl RecoverySnapshotV2 {
    pub(crate) const fn new(
        identity: RecoveryIdentityV2,
        kernel: KernelRecoveryStateV2,
        execd: ExecdRecoveryStateV2,
        vault: VaultRecoveryStateV2,
    ) -> Self {
        Self {
            identity,
            kernel,
            execd,
            vault,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecoveryActionV2 {
    CompleteKnownSuccess { identity: RecoveryIdentityV2 },
    CompleteKnownNoEffect { identity: RecoveryIdentityV2 },
    QuarantineIndeterminate { identity: RecoveryIdentityV2 },
    AbortBeforeEffect { identity: RecoveryIdentityV2 },
    Noop,
}

pub(crate) struct RecoveryCoordinatorV2;

impl RecoveryCoordinatorV2 {
    pub(crate) fn scan(snapshot: RecoverySnapshotV2) -> Result<RecoveryActionV2, RecoveryErrorV2> {
        use ExecdRecoveryStateV2 as Execd;
        use KernelRecoveryStateV2 as Kernel;
        use VaultRecoveryStateV2 as Vault;

        let action = match (snapshot.kernel, snapshot.execd, snapshot.vault) {
            (
                Kernel::CompletionCommitted,
                Execd::KnownSuccess | Execd::Acknowledged,
                Vault::NotApplicable | Vault::Released,
            ) => RecoveryActionV2::Noop,
            (
                Kernel::CompletionCommitted,
                Execd::KnownSuccess | Execd::Acknowledged,
                Vault::Prepared | Vault::Dispatching,
            ) => RecoveryActionV2::CompleteKnownSuccess {
                identity: snapshot.identity,
            },
            (
                Kernel::FailedNoEffect,
                Execd::FailedNoEffect,
                Vault::NotApplicable | Vault::FailedNoEffect,
            ) => RecoveryActionV2::Noop,
            (
                Kernel::Indeterminate,
                Execd::Indeterminate,
                Vault::NotApplicable | Vault::Indeterminate,
            ) => RecoveryActionV2::Noop,
            (
                Kernel::Prepared | Kernel::Dispatching | Kernel::EffectStarted,
                Execd::KnownSuccess,
                Vault::NotApplicable | Vault::Prepared | Vault::Dispatching | Vault::Released,
            ) => RecoveryActionV2::CompleteKnownSuccess {
                identity: snapshot.identity,
            },
            (
                Kernel::Prepared | Kernel::Dispatching,
                Execd::FailedNoEffect,
                Vault::NotApplicable | Vault::Authorized | Vault::Prepared,
            ) => RecoveryActionV2::CompleteKnownNoEffect {
                identity: snapshot.identity,
            },
            (
                Kernel::EffectStarted,
                Execd::EffectStarted | Execd::Indeterminate,
                Vault::NotApplicable | Vault::Prepared | Vault::Dispatching | Vault::Indeterminate,
            )
            | (
                Kernel::Prepared | Kernel::Dispatching,
                Execd::Indeterminate,
                Vault::NotApplicable | Vault::Prepared | Vault::Dispatching | Vault::Indeterminate,
            ) => RecoveryActionV2::QuarantineIndeterminate {
                identity: snapshot.identity,
            },
            (
                Kernel::Prepared | Kernel::Dispatching,
                Execd::Absent | Execd::Prepared | Execd::ProviderAttemptPrepared,
                Vault::NotApplicable | Vault::Authorized | Vault::Prepared,
            ) => RecoveryActionV2::AbortBeforeEffect {
                identity: snapshot.identity,
            },
            _ => return Err(RecoveryErrorV2::Contradiction),
        };
        Ok(action)
    }

    pub(crate) fn join_projections(
        agent: &[savana_agentd::AgentTaskRecoveryProjectionV2],
        kernel: &[KernelDispatchRecoveryProjectionV2],
        execd: &[savana_execd::ExecdQueryV2],
        vault: &[VaultReleaseRecoveryProjectionV2],
    ) -> Result<Vec<RecoveryActionV2>, RecoveryErrorV2> {
        require_strict_task_order(agent.iter().map(|record| record.durable_task_id()))?;
        for record in kernel {
            agent
                .binary_search_by(|candidate| {
                    candidate
                        .durable_task_id()
                        .as_bytes()
                        .cmp(record.durable_task_id().as_bytes())
                })
                .map_err(|_| RecoveryErrorV2::Contradiction)?;
        }

        let mut kernel_records = Vec::new();
        kernel_records
            .try_reserve(kernel.len())
            .map_err(|_| RecoveryErrorV2::AllocationFailure)?;
        for record in kernel {
            kernel_records.push(KernelRecoveryRecordV2 {
                identity: RecoveryIdentityV2::new(
                    record.execution_nonce(),
                    record.dispatch_core_digest(),
                    record.dispatch_subject_digest(),
                )?,
                state: map_kernel_state(record.state()),
                subject: match record.subject_kind() {
                    DispatchRecoverySubjectKindV2::ToolExecution => {
                        if record.durable_release_id().is_some() {
                            return Err(RecoveryErrorV2::Contradiction);
                        }
                        RecoverySubjectV2::ToolExecution
                    }
                    DispatchRecoverySubjectKindV2::FinalRelease => RecoverySubjectV2::FinalRelease(
                        record
                            .durable_release_id()
                            .ok_or(RecoveryErrorV2::Contradiction)?,
                    ),
                },
            });
        }

        let mut execd_records = Vec::new();
        execd_records
            .try_reserve(execd.len())
            .map_err(|_| RecoveryErrorV2::AllocationFailure)?;
        for record in execd {
            execd_records.push(ExecdRecoveryRecordV2 {
                identity: RecoveryIdentityV2::new(
                    record.execution_nonce(),
                    record.dispatch_core_digest(),
                    record.dispatch_subject_digest(),
                )?,
                state: map_execd_state(record.state()),
                subject: match record.kind() {
                    savana_execd::DispatchEnvelopeKindV2::ToolExecution => {
                        RecoverySubjectKindV2::ToolExecution
                    }
                    savana_execd::DispatchEnvelopeKindV2::FinalRelease => {
                        RecoverySubjectKindV2::FinalRelease
                    }
                },
            });
        }

        let mut vault_records = Vec::new();
        vault_records
            .try_reserve(vault.len())
            .map_err(|_| RecoveryErrorV2::AllocationFailure)?;
        for record in vault {
            let identity = match (
                record.execution_nonce(),
                record.dispatch_core_digest(),
                record.dispatch_subject_digest(),
            ) {
                (Some(nonce), Some(core), Some(subject)) => {
                    Some(RecoveryIdentityV2::new(nonce, core, subject)?)
                }
                (None, None, None) => None,
                _ => return Err(RecoveryErrorV2::Contradiction),
            };
            vault_records.push(VaultRecoveryRecordV2 {
                durable_release_id: record.durable_release_id(),
                identity,
                state: map_vault_state(record.state()),
            });
        }

        Self::join_records(&kernel_records, &execd_records, &vault_records)
    }

    fn join_records(
        kernel: &[KernelRecoveryRecordV2],
        execd: &[ExecdRecoveryRecordV2],
        vault: &[VaultRecoveryRecordV2],
    ) -> Result<Vec<RecoveryActionV2>, RecoveryErrorV2> {
        require_strict_nonce_order(kernel.iter().map(|record| record.identity.execution_nonce))?;
        require_strict_nonce_order(execd.iter().map(|record| record.identity.execution_nonce))?;
        require_strict_release_order(vault.iter().map(|record| record.durable_release_id))?;

        for executor_record in execd {
            let kernel_index = kernel
                .binary_search_by(|record| {
                    record
                        .identity
                        .execution_nonce
                        .as_bytes()
                        .cmp(executor_record.identity.execution_nonce.as_bytes())
                })
                .map_err(|_| RecoveryErrorV2::Contradiction)?;
            let kernel_record = kernel[kernel_index];
            if kernel_record.identity != executor_record.identity
                || kernel_record.subject.kind() != executor_record.subject
            {
                return Err(RecoveryErrorV2::Contradiction);
            }
        }

        for vault_record in vault.iter().filter(|record| record.identity.is_some()) {
            let identity = vault_record
                .identity
                .ok_or(RecoveryErrorV2::Contradiction)?;
            let kernel_index = kernel
                .binary_search_by(|record| {
                    record
                        .identity
                        .execution_nonce
                        .as_bytes()
                        .cmp(identity.execution_nonce.as_bytes())
                })
                .map_err(|_| RecoveryErrorV2::Contradiction)?;
            let kernel_record = kernel[kernel_index];
            if kernel_record.identity != identity
                || kernel_record.subject
                    != RecoverySubjectV2::FinalRelease(vault_record.durable_release_id)
            {
                return Err(RecoveryErrorV2::Contradiction);
            }
        }

        let mut actions = Vec::new();
        actions
            .try_reserve(kernel.len())
            .map_err(|_| RecoveryErrorV2::AllocationFailure)?;
        for kernel_record in kernel {
            let execd_state = match execd.binary_search_by(|record| {
                record
                    .identity
                    .execution_nonce
                    .as_bytes()
                    .cmp(kernel_record.identity.execution_nonce.as_bytes())
            }) {
                Ok(index) => {
                    let record = execd[index];
                    if record.identity != kernel_record.identity
                        || record.subject != kernel_record.subject.kind()
                    {
                        return Err(RecoveryErrorV2::Contradiction);
                    }
                    record.state
                }
                Err(_) => ExecdRecoveryStateV2::Absent,
            };
            let vault_state = match kernel_record.subject {
                RecoverySubjectV2::ToolExecution => VaultRecoveryStateV2::NotApplicable,
                RecoverySubjectV2::FinalRelease(durable_release_id) => {
                    let index = vault
                        .binary_search_by(|record| {
                            record
                                .durable_release_id
                                .as_bytes()
                                .cmp(durable_release_id.as_bytes())
                        })
                        .map_err(|_| RecoveryErrorV2::Contradiction)?;
                    let record = vault[index];
                    if let Some(identity) = record.identity {
                        if identity != kernel_record.identity {
                            return Err(RecoveryErrorV2::Contradiction);
                        }
                    } else if !matches!(
                        record.state,
                        VaultRecoveryStateV2::Authorized | VaultRecoveryStateV2::FailedNoEffect
                    ) {
                        return Err(RecoveryErrorV2::Contradiction);
                    }
                    record.state
                }
            };
            actions.push(Self::scan(RecoverySnapshotV2::new(
                kernel_record.identity,
                kernel_record.state,
                execd_state,
                vault_state,
            ))?);
        }
        Ok(actions)
    }
}

enum RecoveryOwnerCommandV2 {
    Projections {
        agent: Vec<savana_agentd::AgentTaskRecoveryProjectionV2>,
        kernel: Vec<KernelDispatchRecoveryProjectionV2>,
        execd: Vec<savana_execd::ExecdQueryV2>,
        vault: Vec<VaultReleaseRecoveryProjectionV2>,
    },
    #[cfg(test)]
    Records {
        kernel: Vec<KernelRecoveryRecordV2>,
        execd: Vec<ExecdRecoveryRecordV2>,
        vault: Vec<VaultRecoveryRecordV2>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecoveryRuntimeErrorV2 {
    Busy,
    DeadlineExceeded,
    Unavailable,
    Recovery(RecoveryErrorV2),
}

pub(crate) struct RecoveryStateOwnerV2 {
    owner: StateOwnerV2<RecoveryOwnerCommandV2, Result<Vec<RecoveryActionV2>, RecoveryErrorV2>>,
}

impl RecoveryStateOwnerV2 {
    pub(crate) fn spawn(
        capacity: usize,
        mut apply: impl FnMut(RecoveryActionV2) -> Result<(), RecoveryErrorV2> + Send + 'static,
    ) -> Result<Self, RecoveryRuntimeErrorV2> {
        let owner = StateOwnerV2::spawn("savana-v2-recovery-owner", capacity, move |command| {
            let result = (|| {
                let actions = match command {
                    RecoveryOwnerCommandV2::Projections {
                        agent,
                        kernel,
                        execd,
                        vault,
                    } => RecoveryCoordinatorV2::join_projections(&agent, &kernel, &execd, &vault)?,
                    #[cfg(test)]
                    RecoveryOwnerCommandV2::Records {
                        kernel,
                        execd,
                        vault,
                    } => RecoveryCoordinatorV2::join_records(&kernel, &execd, &vault)?,
                };
                for action in actions.iter().copied() {
                    if action != RecoveryActionV2::Noop {
                        apply(action)?;
                    }
                }
                Ok(actions)
            })();
            Ok(result)
        })
        .map_err(map_owner_error)?;
        Ok(Self { owner })
    }

    pub(crate) fn reconcile_projections(
        &self,
        agent: Vec<savana_agentd::AgentTaskRecoveryProjectionV2>,
        kernel: Vec<KernelDispatchRecoveryProjectionV2>,
        execd: Vec<savana_execd::ExecdQueryV2>,
        vault: Vec<VaultReleaseRecoveryProjectionV2>,
        deadline: Instant,
    ) -> Result<Vec<RecoveryActionV2>, RecoveryRuntimeErrorV2> {
        self.owner
            .request(
                RecoveryOwnerCommandV2::Projections {
                    agent,
                    kernel,
                    execd,
                    vault,
                },
                deadline,
            )
            .map_err(map_owner_error)?
            .map_err(RecoveryRuntimeErrorV2::Recovery)
    }

    #[cfg(test)]
    fn spawn_for_test(
        capacity: usize,
        apply: impl FnMut(RecoveryActionV2) -> Result<(), RecoveryErrorV2> + Send + 'static,
    ) -> Result<Self, RecoveryRuntimeErrorV2> {
        Self::spawn(capacity, apply)
    }

    #[cfg(test)]
    fn reconcile_records_for_test(
        &self,
        kernel: Vec<KernelRecoveryRecordV2>,
        execd: Vec<ExecdRecoveryRecordV2>,
        vault: Vec<VaultRecoveryRecordV2>,
        deadline: Instant,
    ) -> Result<Vec<RecoveryActionV2>, RecoveryRuntimeErrorV2> {
        self.owner
            .request(
                RecoveryOwnerCommandV2::Records {
                    kernel,
                    execd,
                    vault,
                },
                deadline,
            )
            .map_err(map_owner_error)?
            .map_err(RecoveryRuntimeErrorV2::Recovery)
    }
}

pub(crate) struct RecoveryProjectionSetV2 {
    pub(crate) agent: Vec<savana_agentd::AgentTaskRecoveryProjectionV2>,
    pub(crate) kernel: Vec<KernelDispatchRecoveryProjectionV2>,
    pub(crate) execd: Vec<savana_execd::ExecdQueryV2>,
    pub(crate) vault: Vec<VaultReleaseRecoveryProjectionV2>,
}

pub(crate) trait RecoveryBackendV2: Send {
    fn snapshot(&mut self) -> Result<RecoveryProjectionSetV2, RecoveryErrorV2>;

    /// Persists the exact role-owned transition and does not return until its
    /// authenticated durable head is visible to the next `snapshot` call.
    /// Both methods live on one backend so no durable service is shared
    /// through a second mutex or a second owner thread.
    fn apply(&mut self, action: RecoveryActionV2) -> Result<(), RecoveryErrorV2>;
}

/// Concrete startup/runtime recovery adapter over the real authenticated
/// stores and daemon owner threads.
///
/// Kernel policy and vault stores are owned directly by this backend; agentd
/// and execd remain behind their bounded single-owner threads. No capability
/// or nonce is present in the recovery command surface.
pub(crate) struct ProductionRecoveryBackendV2 {
    agent: Arc<savana_agentd::AgentTaskStateOwnerV2>,
    execd: Arc<savana_execd::ExecdStateOwnerV2>,
    policy: savana_policy_core::v2::DurableG4StateV2,
    vault: savana_vault::DurableVaultServiceV2,
    executor_receipt_key_id: Ed25519KeyIdV2,
    executor_receipt_public_key: [u8; 32],
    now: UnixMillisV2,
    request_timeout: Duration,
}

impl std::fmt::Debug for ProductionRecoveryBackendV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProductionRecoveryBackendV2")
            .field("now", &self.now)
            .field("request_timeout", &self.request_timeout)
            .finish_non_exhaustive()
    }
}

impl ProductionRecoveryBackendV2 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_verified_services(
        agent: Arc<savana_agentd::AgentTaskStateOwnerV2>,
        execd: Arc<savana_execd::ExecdStateOwnerV2>,
        policy: savana_policy_core::v2::DurableG4StateV2,
        vault: savana_vault::DurableVaultServiceV2,
        executor_receipt_key_id: Ed25519KeyIdV2,
        executor_receipt_public_key: [u8; 32],
        now: UnixMillisV2,
        request_timeout: Duration,
    ) -> Result<Self, RecoveryErrorV2> {
        if is_zero(executor_receipt_key_id.as_bytes())
            || is_zero(&executor_receipt_public_key)
            || now.get() == 0
            || request_timeout.is_zero()
        {
            return Err(RecoveryErrorV2::InvalidIdentity);
        }
        Ok(Self {
            agent,
            execd,
            policy,
            vault,
            executor_receipt_key_id,
            executor_receipt_public_key,
            now,
            request_timeout,
        })
    }

    pub(crate) fn recover_until_stable(
        &mut self,
    ) -> Result<Vec<RecoveryActionV2>, RecoveryErrorV2> {
        reconcile_backend_until_stable(self)
    }

    pub(crate) fn into_kernel_stores(
        self,
    ) -> (
        savana_policy_core::v2::DurableG4StateV2,
        savana_vault::DurableVaultServiceV2,
    ) {
        (self.policy, self.vault)
    }

    fn deadline(&self) -> Instant {
        Instant::now() + self.request_timeout
    }

    fn context(
        &self,
        identity: RecoveryIdentityV2,
    ) -> Result<
        (
            KernelDispatchRecoveryProjectionV2,
            Option<savana_execd::ExecdQueryV2>,
            Option<VaultReleaseRecoveryProjectionV2>,
        ),
        RecoveryErrorV2,
    > {
        let kernel = self
            .policy
            .recovery_projection()
            .map_err(|_| RecoveryErrorV2::BackendUnavailable)?
            .into_iter()
            .find(|record| record.execution_nonce() == identity.execution_nonce)
            .ok_or(RecoveryErrorV2::Contradiction)?;
        require_kernel_identity(kernel, identity)?;
        let execd = match self.execd.query(identity.execution_nonce, self.deadline()) {
            Ok(record) => {
                require_execd_identity(record, identity)?;
                Some(record)
            }
            Err(savana_execd::ExecdStateOwnerErrorV2::Runtime(
                savana_execd::ExecdRuntimeErrorV2::Journal(savana_execd::ExecdErrorV2::NotFound),
            )) => None,
            Err(_) => return Err(RecoveryErrorV2::BackendUnavailable),
        };
        let vault = match kernel.durable_release_id() {
            Some(release_id) => {
                let record = self
                    .vault
                    .recovery_projection()
                    .map_err(|_| RecoveryErrorV2::BackendUnavailable)?
                    .into_iter()
                    .find(|record| record.durable_release_id() == release_id)
                    .ok_or(RecoveryErrorV2::Contradiction)?;
                require_vault_identity(record, identity)?;
                Some(record)
            }
            None => None,
        };
        Ok((kernel, execd, vault))
    }

    fn terminal_receipt(
        &self,
        identity: RecoveryIdentityV2,
    ) -> Result<savana_execd::SignedExecutorReceiptV2, RecoveryErrorV2> {
        self.execd
            .terminal_receipt(identity.execution_nonce, self.deadline())
            .map_err(|_| RecoveryErrorV2::BackendUnavailable)
    }

    fn reconcile_receipt(
        &mut self,
        kernel: KernelDispatchRecoveryProjectionV2,
        receipt: &savana_execd::SignedExecutorReceiptV2,
    ) -> Result<KernelDispatchStateV2, RecoveryErrorV2> {
        let receipt =
            SignedExecutorDispositionReceiptV2::from_canonical_bytes(receipt.canonical_bytes())
                .map_err(|_| RecoveryErrorV2::Contradiction)?;
        match kernel.subject_kind() {
            DispatchRecoverySubjectKindV2::ToolExecution => self
                .policy
                .reconcile_stored_signed_tool_dispatch(
                    &receipt,
                    self.executor_receipt_key_id,
                    self.executor_receipt_public_key,
                )
                .map_err(|_| RecoveryErrorV2::Contradiction),
            DispatchRecoverySubjectKindV2::FinalRelease => self
                .policy
                .reconcile_stored_signed_final_release_dispatch(
                    &receipt,
                    self.executor_receipt_key_id,
                    self.executor_receipt_public_key,
                )
                .map_err(|_| RecoveryErrorV2::Contradiction),
        }
    }

    fn apply_known_success(&mut self, identity: RecoveryIdentityV2) -> Result<(), RecoveryErrorV2> {
        let (kernel, execd, vault) = self.context(identity)?;
        let execd = execd.ok_or(RecoveryErrorV2::Contradiction)?;
        if !matches!(
            execd.state(),
            savana_execd::ExecdJournalStateV2::CompletionAvailable
                | savana_execd::ExecdJournalStateV2::Acknowledged
        ) {
            return Err(RecoveryErrorV2::Contradiction);
        }
        let receipt = self.terminal_receipt(identity)?;
        if self.reconcile_receipt(kernel, &receipt)? != KernelDispatchStateV2::CompletionCommitted {
            return Err(RecoveryErrorV2::Contradiction);
        }
        let policy_head = self
            .policy
            .authenticated_state_head()
            .map_err(|_| RecoveryErrorV2::BackendUnavailable)?
            .state_digest();
        if let (Some(release_id), Some(vault_record)) = (kernel.durable_release_id(), vault) {
            if vault_record.state() != VaultReleaseRecoveryStateV2::Released {
                let audit_digest = recovery_digest(
                    b"SAVANA_RECOVERY_FINAL_RELEASE_AUDIT_V2\0",
                    identity,
                    &[receipt.digest(), policy_head],
                );
                self.vault
                    .commit_known_release_by_identity(
                        release_id,
                        identity.execution_nonce,
                        identity.dispatch_core_digest,
                        identity.dispatch_subject_digest,
                        receipt.digest(),
                        audit_digest,
                        self.now,
                    )
                    .map_err(|_| RecoveryErrorV2::Contradiction)?;
            }
        }
        if execd.state() == savana_execd::ExecdJournalStateV2::CompletionAvailable {
            let vault_head = self
                .vault
                .authenticated_state_head()
                .map_err(|_| RecoveryErrorV2::BackendUnavailable)?
                .state_digest();
            let commit_digest = recovery_digest(
                b"SAVANA_RECOVERY_KERNEL_COMMIT_V2\0",
                identity,
                &[policy_head, vault_head],
            );
            self.execd
                .acknowledge_completion(identity.execution_nonce, commit_digest, self.deadline())
                .map_err(|_| RecoveryErrorV2::BackendUnavailable)?;
        }
        Ok(())
    }

    fn apply_known_no_effect(
        &mut self,
        identity: RecoveryIdentityV2,
        allow_absent_executor: bool,
    ) -> Result<(), RecoveryErrorV2> {
        let (kernel, execd, vault) = self.context(identity)?;
        let evidence = recovery_digest(b"SAVANA_RECOVERY_KNOWN_NO_EFFECT_V2\0", identity, &[]);
        match execd {
            Some(record) => {
                if !matches!(
                    record.state(),
                    savana_execd::ExecdJournalStateV2::Prepared
                        | savana_execd::ExecdJournalStateV2::ProviderAttemptPrepared
                        | savana_execd::ExecdJournalStateV2::FailedNoEffect
                ) {
                    return Err(RecoveryErrorV2::Contradiction);
                }
                let receipt = if record.state() == savana_execd::ExecdJournalStateV2::FailedNoEffect
                {
                    self.terminal_receipt(identity)?
                } else {
                    self.execd
                        .record_failed_no_effect_recovery(
                            identity.execution_nonce,
                            ExecutorFailureClassV2::ResourceFailureBeforeEffect,
                            evidence,
                            self.now,
                            self.deadline(),
                        )
                        .map_err(|_| RecoveryErrorV2::BackendUnavailable)?
                };
                if self.reconcile_receipt(kernel, &receipt)?
                    != KernelDispatchStateV2::FailedNoEffect
                {
                    return Err(RecoveryErrorV2::Contradiction);
                }
            }
            None if allow_absent_executor => {
                if self
                    .policy
                    .abort_dispatch_before_effect(
                        identity.execution_nonce,
                        identity.dispatch_core_digest,
                        identity.dispatch_subject_digest,
                        evidence,
                    )
                    .map_err(|_| RecoveryErrorV2::Contradiction)?
                    != KernelDispatchStateV2::FailedNoEffect
                {
                    return Err(RecoveryErrorV2::Contradiction);
                }
            }
            None => return Err(RecoveryErrorV2::Contradiction),
        }
        if let (Some(release_id), Some(vault_record)) = (kernel.durable_release_id(), vault) {
            if vault_record.state() != VaultReleaseRecoveryStateV2::FailedNoEffect {
                self.vault
                    .mark_failed_no_effect_by_identity(
                        release_id,
                        identity.execution_nonce,
                        identity.dispatch_core_digest,
                        identity.dispatch_subject_digest,
                        self.now,
                    )
                    .map_err(|_| RecoveryErrorV2::Contradiction)?;
            }
        }
        Ok(())
    }

    fn apply_indeterminate(&mut self, identity: RecoveryIdentityV2) -> Result<(), RecoveryErrorV2> {
        let (kernel, execd, vault) = self.context(identity)?;
        let execd = execd.ok_or(RecoveryErrorV2::Contradiction)?;
        let evidence = recovery_digest(b"SAVANA_RECOVERY_INDETERMINATE_V2\0", identity, &[]);
        let receipt = match execd.state() {
            savana_execd::ExecdJournalStateV2::EffectStarted => self
                .execd
                .record_indeterminate_recovery(
                    identity.execution_nonce,
                    evidence,
                    self.now,
                    self.deadline(),
                )
                .map_err(|_| RecoveryErrorV2::BackendUnavailable)?,
            savana_execd::ExecdJournalStateV2::Indeterminate => self.terminal_receipt(identity)?,
            _ => return Err(RecoveryErrorV2::Contradiction),
        };
        if self.reconcile_receipt(kernel, &receipt)? != KernelDispatchStateV2::Indeterminate {
            return Err(RecoveryErrorV2::Contradiction);
        }
        if let (Some(release_id), Some(vault_record)) = (kernel.durable_release_id(), vault) {
            if vault_record.state() != VaultReleaseRecoveryStateV2::Indeterminate {
                self.vault
                    .mark_indeterminate_by_identity(
                        release_id,
                        identity.execution_nonce,
                        identity.dispatch_core_digest,
                        identity.dispatch_subject_digest,
                        self.now,
                    )
                    .map_err(|_| RecoveryErrorV2::Contradiction)?;
            }
        }
        Ok(())
    }
}

impl RecoveryBackendV2 for ProductionRecoveryBackendV2 {
    fn snapshot(&mut self) -> Result<RecoveryProjectionSetV2, RecoveryErrorV2> {
        let deadline = self.deadline();
        Ok(RecoveryProjectionSetV2 {
            agent: self
                .agent
                .recovery_projection(deadline)
                .map_err(|_| RecoveryErrorV2::BackendUnavailable)?,
            kernel: self
                .policy
                .recovery_projection()
                .map_err(|_| RecoveryErrorV2::BackendUnavailable)?,
            execd: self
                .execd
                .recovery_projection(deadline)
                .map_err(|_| RecoveryErrorV2::BackendUnavailable)?,
            vault: self
                .vault
                .recovery_projection()
                .map_err(|_| RecoveryErrorV2::BackendUnavailable)?,
        })
    }

    fn apply(&mut self, action: RecoveryActionV2) -> Result<(), RecoveryErrorV2> {
        match action {
            RecoveryActionV2::CompleteKnownSuccess { identity } => {
                self.apply_known_success(identity)
            }
            RecoveryActionV2::CompleteKnownNoEffect { identity } => {
                self.apply_known_no_effect(identity, false)
            }
            RecoveryActionV2::QuarantineIndeterminate { identity } => {
                self.apply_indeterminate(identity)
            }
            RecoveryActionV2::AbortBeforeEffect { identity } => {
                self.apply_known_no_effect(identity, true)
            }
            RecoveryActionV2::Noop => Ok(()),
        }
    }
}

pub(crate) struct RescanningRecoveryStateOwnerV2 {
    owner: StateOwnerV2<(), Result<Vec<RecoveryActionV2>, RecoveryErrorV2>>,
}

impl RescanningRecoveryStateOwnerV2 {
    pub(crate) fn spawn(
        capacity: usize,
        mut backend: Box<dyn RecoveryBackendV2>,
    ) -> Result<Self, RecoveryRuntimeErrorV2> {
        let owner =
            StateOwnerV2::spawn("savana-v2-rescanning-recovery-owner", capacity, move |()| {
                Ok(reconcile_backend_until_stable(backend.as_mut()))
            })
            .map_err(map_owner_error)?;
        Ok(Self { owner })
    }

    pub(crate) fn reconcile(
        &self,
        deadline: Instant,
    ) -> Result<Vec<RecoveryActionV2>, RecoveryRuntimeErrorV2> {
        self.owner
            .request((), deadline)
            .map_err(map_owner_error)?
            .map_err(RecoveryRuntimeErrorV2::Recovery)
    }

    #[cfg(test)]
    fn spawn_for_test(
        capacity: usize,
        mut scan: impl FnMut() -> Result<Vec<RecoveryActionV2>, RecoveryErrorV2> + Send + 'static,
        mut apply: impl FnMut(RecoveryActionV2) -> Result<(), RecoveryErrorV2> + Send + 'static,
    ) -> Result<Self, RecoveryRuntimeErrorV2> {
        let owner = StateOwnerV2::spawn(
            "savana-v2-rescanning-recovery-test-owner",
            capacity,
            move |()| Ok(reconcile_until_stable(&mut scan, &mut apply)),
        )
        .map_err(map_owner_error)?;
        Ok(Self { owner })
    }
}

fn reconcile_backend_until_stable(
    backend: &mut dyn RecoveryBackendV2,
) -> Result<Vec<RecoveryActionV2>, RecoveryErrorV2> {
    const MAX_RECOVERY_TRANSITIONS: usize = 65_536;

    let mut applied = Vec::new();
    let mut previous = None;
    for _ in 0..MAX_RECOVERY_TRANSITIONS {
        let snapshot = backend.snapshot()?;
        let actions = RecoveryCoordinatorV2::join_projections(
            &snapshot.agent,
            &snapshot.kernel,
            &snapshot.execd,
            &snapshot.vault,
        )?;
        let next = actions
            .into_iter()
            .find(|action| *action != RecoveryActionV2::Noop);
        let Some(next) = next else {
            return Ok(applied);
        };
        if previous == Some(next) {
            return Err(RecoveryErrorV2::Contradiction);
        }
        applied
            .try_reserve(1)
            .map_err(|_| RecoveryErrorV2::AllocationFailure)?;
        backend.apply(next)?;
        applied.push(next);
        previous = Some(next);
    }
    Err(RecoveryErrorV2::Contradiction)
}

fn reconcile_until_stable(
    mut scan: impl FnMut() -> Result<Vec<RecoveryActionV2>, RecoveryErrorV2>,
    mut apply: impl FnMut(RecoveryActionV2) -> Result<(), RecoveryErrorV2>,
) -> Result<Vec<RecoveryActionV2>, RecoveryErrorV2> {
    const MAX_RECOVERY_TRANSITIONS: usize = 65_536;

    let mut applied = Vec::new();
    let mut previous = None;
    for _ in 0..MAX_RECOVERY_TRANSITIONS {
        let actions = scan()?;
        let next = actions
            .into_iter()
            .find(|action| *action != RecoveryActionV2::Noop);
        let Some(next) = next else {
            return Ok(applied);
        };
        if previous == Some(next) {
            return Err(RecoveryErrorV2::Contradiction);
        }
        applied
            .try_reserve(1)
            .map_err(|_| RecoveryErrorV2::AllocationFailure)?;
        apply(next)?;
        applied.push(next);
        previous = Some(next);
    }
    Err(RecoveryErrorV2::Contradiction)
}

const fn map_owner_error(error: StateOwnerErrorV2) -> RecoveryRuntimeErrorV2 {
    match error {
        StateOwnerErrorV2::RuntimeBusy => RecoveryRuntimeErrorV2::Busy,
        StateOwnerErrorV2::DeadlineExceeded => RecoveryRuntimeErrorV2::DeadlineExceeded,
        StateOwnerErrorV2::RuntimeUnavailable => RecoveryRuntimeErrorV2::Unavailable,
    }
}

const fn map_kernel_state(state: KernelDispatchStateV2) -> KernelRecoveryStateV2 {
    match state {
        KernelDispatchStateV2::Prepared => KernelRecoveryStateV2::Prepared,
        KernelDispatchStateV2::Dispatching => KernelRecoveryStateV2::Dispatching,
        KernelDispatchStateV2::EffectStarted => KernelRecoveryStateV2::EffectStarted,
        KernelDispatchStateV2::CompletionCommitted => KernelRecoveryStateV2::CompletionCommitted,
        KernelDispatchStateV2::FailedNoEffect => KernelRecoveryStateV2::FailedNoEffect,
        KernelDispatchStateV2::Indeterminate => KernelRecoveryStateV2::Indeterminate,
    }
}

const fn map_execd_state(state: savana_execd::ExecdJournalStateV2) -> ExecdRecoveryStateV2 {
    match state {
        savana_execd::ExecdJournalStateV2::Prepared => ExecdRecoveryStateV2::Prepared,
        savana_execd::ExecdJournalStateV2::ProviderAttemptPrepared => {
            ExecdRecoveryStateV2::ProviderAttemptPrepared
        }
        savana_execd::ExecdJournalStateV2::EffectStarted => ExecdRecoveryStateV2::EffectStarted,
        savana_execd::ExecdJournalStateV2::ProviderResponseRetained
        | savana_execd::ExecdJournalStateV2::ReleaseEvidencePrepared => {
            // Execd must normally reconstruct a terminal completion from these
            // durable states before advertising Ready. If kerneld observes
            // either state during a startup race, treating it as indeterminate
            // prevents a second effect and fails closed.
            ExecdRecoveryStateV2::Indeterminate
        }
        savana_execd::ExecdJournalStateV2::CompletionAvailable => {
            ExecdRecoveryStateV2::KnownSuccess
        }
        savana_execd::ExecdJournalStateV2::FailedNoEffect => ExecdRecoveryStateV2::FailedNoEffect,
        savana_execd::ExecdJournalStateV2::Indeterminate => ExecdRecoveryStateV2::Indeterminate,
        savana_execd::ExecdJournalStateV2::Acknowledged => ExecdRecoveryStateV2::Acknowledged,
    }
}

const fn map_vault_state(state: VaultReleaseRecoveryStateV2) -> VaultRecoveryStateV2 {
    match state {
        VaultReleaseRecoveryStateV2::Authorized => VaultRecoveryStateV2::Authorized,
        VaultReleaseRecoveryStateV2::DispatchPrepared => VaultRecoveryStateV2::Prepared,
        VaultReleaseRecoveryStateV2::Dispatching => VaultRecoveryStateV2::Dispatching,
        VaultReleaseRecoveryStateV2::Released => VaultRecoveryStateV2::Released,
        VaultReleaseRecoveryStateV2::FailedNoEffect => VaultRecoveryStateV2::FailedNoEffect,
        VaultReleaseRecoveryStateV2::Indeterminate => VaultRecoveryStateV2::Indeterminate,
        VaultReleaseRecoveryStateV2::PendingApproval
        | VaultReleaseRecoveryStateV2::Revoked
        | VaultReleaseRecoveryStateV2::Expired
        | VaultReleaseRecoveryStateV2::RestartInvalidated => VaultRecoveryStateV2::Unavailable,
    }
}

fn require_strict_nonce_order(
    mut nonces: impl Iterator<Item = Nonce32V2>,
) -> Result<(), RecoveryErrorV2> {
    let Some(mut previous) = nonces.next() else {
        return Ok(());
    };
    for current in nonces {
        if previous.as_bytes() >= current.as_bytes() {
            return Err(RecoveryErrorV2::Contradiction);
        }
        previous = current;
    }
    Ok(())
}

fn require_strict_release_order(
    mut release_ids: impl Iterator<Item = DurableReleaseIdV2>,
) -> Result<(), RecoveryErrorV2> {
    let Some(mut previous) = release_ids.next() else {
        return Ok(());
    };
    for current in release_ids {
        if previous.as_bytes() >= current.as_bytes() {
            return Err(RecoveryErrorV2::Contradiction);
        }
        previous = current;
    }
    Ok(())
}

fn require_strict_task_order(
    mut task_ids: impl Iterator<Item = savana_kernel_protocol::v2::DurableTaskIdV2>,
) -> Result<(), RecoveryErrorV2> {
    let Some(mut previous) = task_ids.next() else {
        return Ok(());
    };
    for current in task_ids {
        if previous.as_bytes() >= current.as_bytes() {
            return Err(RecoveryErrorV2::Contradiction);
        }
        previous = current;
    }
    Ok(())
}

fn require_kernel_identity(
    record: KernelDispatchRecoveryProjectionV2,
    identity: RecoveryIdentityV2,
) -> Result<(), RecoveryErrorV2> {
    if record.execution_nonce() == identity.execution_nonce
        && record.dispatch_core_digest() == identity.dispatch_core_digest
        && record.dispatch_subject_digest() == identity.dispatch_subject_digest
    {
        Ok(())
    } else {
        Err(RecoveryErrorV2::Contradiction)
    }
}

fn require_execd_identity(
    record: savana_execd::ExecdQueryV2,
    identity: RecoveryIdentityV2,
) -> Result<(), RecoveryErrorV2> {
    if record.execution_nonce() == identity.execution_nonce
        && record.dispatch_core_digest() == identity.dispatch_core_digest
        && record.dispatch_subject_digest() == identity.dispatch_subject_digest
    {
        Ok(())
    } else {
        Err(RecoveryErrorV2::Contradiction)
    }
}

fn require_vault_identity(
    record: VaultReleaseRecoveryProjectionV2,
    identity: RecoveryIdentityV2,
) -> Result<(), RecoveryErrorV2> {
    match (
        record.execution_nonce(),
        record.dispatch_core_digest(),
        record.dispatch_subject_digest(),
    ) {
        (Some(nonce), Some(core), Some(subject))
            if nonce == identity.execution_nonce
                && core == identity.dispatch_core_digest
                && subject == identity.dispatch_subject_digest =>
        {
            Ok(())
        }
        (None, None, None) if record.state() == VaultReleaseRecoveryStateV2::Authorized => Ok(()),
        _ => Err(RecoveryErrorV2::Contradiction),
    }
}

fn recovery_digest(
    domain: &[u8],
    identity: RecoveryIdentityV2,
    additional: &[Digest32V2],
) -> Digest32V2 {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(identity.execution_nonce.as_bytes());
    hasher.update(identity.dispatch_core_digest.as_bytes());
    hasher.update(identity.dispatch_subject_digest.as_bytes());
    for digest in additional {
        hasher.update(digest.as_bytes());
    }
    Digest32V2::new(hasher.finalize().into())
}

fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use savana_kernel_protocol::v2::{Digest32V2, DurableReleaseIdV2, Nonce32V2};

    use super::{
        ExecdRecoveryRecordV2, ExecdRecoveryStateV2, KernelRecoveryRecordV2, KernelRecoveryStateV2,
        RecoveryActionV2, RecoveryCoordinatorV2, RecoveryErrorV2, RecoveryIdentityV2,
        RecoveryRuntimeErrorV2, RecoverySnapshotV2, RecoveryStateOwnerV2, RecoverySubjectKindV2,
        RecoverySubjectV2, RescanningRecoveryStateOwnerV2, VaultRecoveryRecordV2,
        VaultRecoveryStateV2,
    };

    fn identity(seed: u8) -> RecoveryIdentityV2 {
        RecoveryIdentityV2::new(
            Nonce32V2::new([seed; 32]),
            Digest32V2::new([seed.wrapping_add(1); 32]),
            Digest32V2::new([seed.wrapping_add(2); 32]),
        )
        .unwrap()
    }

    fn snapshot(
        kernel: KernelRecoveryStateV2,
        execd: ExecdRecoveryStateV2,
        vault: VaultRecoveryStateV2,
    ) -> RecoverySnapshotV2 {
        RecoverySnapshotV2::new(identity(0x31), kernel, execd, vault)
    }

    #[test]
    fn recovery_never_replays_an_effect_from_pre_effect_states() {
        let cases = [
            snapshot(
                KernelRecoveryStateV2::Prepared,
                ExecdRecoveryStateV2::Absent,
                VaultRecoveryStateV2::NotApplicable,
            ),
            snapshot(
                KernelRecoveryStateV2::Dispatching,
                ExecdRecoveryStateV2::Prepared,
                VaultRecoveryStateV2::NotApplicable,
            ),
            snapshot(
                KernelRecoveryStateV2::Dispatching,
                ExecdRecoveryStateV2::ProviderAttemptPrepared,
                VaultRecoveryStateV2::NotApplicable,
            ),
        ];

        for value in cases {
            assert_eq!(
                RecoveryCoordinatorV2::scan(value).unwrap(),
                RecoveryActionV2::AbortBeforeEffect {
                    identity: identity(0x31)
                }
            );
        }
    }

    #[test]
    fn authenticated_terminal_executor_states_are_completed_without_a_new_nonce() {
        assert_eq!(
            RecoveryCoordinatorV2::scan(snapshot(
                KernelRecoveryStateV2::EffectStarted,
                ExecdRecoveryStateV2::KnownSuccess,
                VaultRecoveryStateV2::NotApplicable,
            ))
            .unwrap(),
            RecoveryActionV2::CompleteKnownSuccess {
                identity: identity(0x31)
            }
        );
        assert_eq!(
            RecoveryCoordinatorV2::scan(snapshot(
                KernelRecoveryStateV2::Dispatching,
                ExecdRecoveryStateV2::FailedNoEffect,
                VaultRecoveryStateV2::NotApplicable,
            ))
            .unwrap(),
            RecoveryActionV2::CompleteKnownNoEffect {
                identity: identity(0x31)
            }
        );
    }

    #[test]
    fn effect_started_without_a_terminal_receipt_is_quarantined_indeterminate() {
        for execd in [
            ExecdRecoveryStateV2::EffectStarted,
            ExecdRecoveryStateV2::Indeterminate,
        ] {
            assert_eq!(
                RecoveryCoordinatorV2::scan(snapshot(
                    KernelRecoveryStateV2::EffectStarted,
                    execd,
                    VaultRecoveryStateV2::NotApplicable,
                ))
                .unwrap(),
                RecoveryActionV2::QuarantineIndeterminate {
                    identity: identity(0x31)
                }
            );
        }
    }

    #[test]
    fn final_release_success_requires_a_matching_vault_transition() {
        assert_eq!(
            RecoveryCoordinatorV2::scan(snapshot(
                KernelRecoveryStateV2::EffectStarted,
                ExecdRecoveryStateV2::KnownSuccess,
                VaultRecoveryStateV2::Dispatching,
            ))
            .unwrap(),
            RecoveryActionV2::CompleteKnownSuccess {
                identity: identity(0x31)
            }
        );
        assert_eq!(
            RecoveryCoordinatorV2::scan(snapshot(
                KernelRecoveryStateV2::EffectStarted,
                ExecdRecoveryStateV2::KnownSuccess,
                VaultRecoveryStateV2::Authorized,
            ))
            .unwrap_err(),
            RecoveryErrorV2::Contradiction
        );
    }

    #[test]
    fn contradictory_terminal_states_fail_closed() {
        let cases = [
            snapshot(
                KernelRecoveryStateV2::CompletionCommitted,
                ExecdRecoveryStateV2::FailedNoEffect,
                VaultRecoveryStateV2::NotApplicable,
            ),
            snapshot(
                KernelRecoveryStateV2::FailedNoEffect,
                ExecdRecoveryStateV2::KnownSuccess,
                VaultRecoveryStateV2::NotApplicable,
            ),
            snapshot(
                KernelRecoveryStateV2::Indeterminate,
                ExecdRecoveryStateV2::KnownSuccess,
                VaultRecoveryStateV2::NotApplicable,
            ),
        ];
        for value in cases {
            assert_eq!(
                RecoveryCoordinatorV2::scan(value).unwrap_err(),
                RecoveryErrorV2::Contradiction
            );
        }
    }

    #[test]
    fn exact_terminal_replays_are_noops() {
        for value in [
            snapshot(
                KernelRecoveryStateV2::CompletionCommitted,
                ExecdRecoveryStateV2::KnownSuccess,
                VaultRecoveryStateV2::NotApplicable,
            ),
            snapshot(
                KernelRecoveryStateV2::FailedNoEffect,
                ExecdRecoveryStateV2::FailedNoEffect,
                VaultRecoveryStateV2::NotApplicable,
            ),
            snapshot(
                KernelRecoveryStateV2::FailedNoEffect,
                ExecdRecoveryStateV2::FailedNoEffect,
                VaultRecoveryStateV2::FailedNoEffect,
            ),
            snapshot(
                KernelRecoveryStateV2::Indeterminate,
                ExecdRecoveryStateV2::Indeterminate,
                VaultRecoveryStateV2::NotApplicable,
            ),
        ] {
            assert_eq!(
                RecoveryCoordinatorV2::scan(value).unwrap(),
                RecoveryActionV2::Noop
            );
        }
    }

    #[test]
    fn recovery_records_join_only_on_full_nonce_core_and_subject_identity() {
        let expected = identity(0xc1);
        let release_id = DurableReleaseIdV2::new([0xc4; 32]);
        let kernel = [KernelRecoveryRecordV2 {
            identity: expected,
            state: KernelRecoveryStateV2::EffectStarted,
            subject: RecoverySubjectV2::FinalRelease(release_id),
        }];
        let execd = [ExecdRecoveryRecordV2 {
            identity: expected,
            state: ExecdRecoveryStateV2::KnownSuccess,
            subject: RecoverySubjectKindV2::FinalRelease,
        }];
        let vault = [VaultRecoveryRecordV2 {
            durable_release_id: release_id,
            identity: Some(expected),
            state: VaultRecoveryStateV2::Dispatching,
        }];

        assert_eq!(
            RecoveryCoordinatorV2::join_records(&kernel, &execd, &vault).unwrap(),
            vec![RecoveryActionV2::CompleteKnownSuccess { identity: expected }]
        );

        let rebound = [ExecdRecoveryRecordV2 {
            identity: RecoveryIdentityV2::new(
                expected.execution_nonce,
                Digest32V2::new([0xff; 32]),
                expected.dispatch_subject_digest,
            )
            .unwrap(),
            state: ExecdRecoveryStateV2::KnownSuccess,
            subject: RecoverySubjectKindV2::FinalRelease,
        }];
        assert_eq!(
            RecoveryCoordinatorV2::join_records(&kernel, &rebound, &vault).unwrap_err(),
            RecoveryErrorV2::Contradiction
        );
    }

    #[test]
    fn orphan_executor_or_identity_bearing_vault_records_fail_closed() {
        let expected = identity(0xd1);
        let execd = [ExecdRecoveryRecordV2 {
            identity: expected,
            state: ExecdRecoveryStateV2::Prepared,
            subject: RecoverySubjectKindV2::ToolExecution,
        }];
        assert_eq!(
            RecoveryCoordinatorV2::join_records(&[], &execd, &[]).unwrap_err(),
            RecoveryErrorV2::Contradiction
        );

        let vault = [VaultRecoveryRecordV2 {
            durable_release_id: DurableReleaseIdV2::new([0xd4; 32]),
            identity: Some(expected),
            state: VaultRecoveryStateV2::Prepared,
        }];
        assert_eq!(
            RecoveryCoordinatorV2::join_records(&[], &[], &vault).unwrap_err(),
            RecoveryErrorV2::Contradiction
        );
    }

    #[test]
    fn recovery_actions_are_validated_then_applied_on_the_state_owner() {
        let applied = Arc::new(Mutex::new(Vec::new()));
        let applied_by_owner = Arc::clone(&applied);
        let owner = RecoveryStateOwnerV2::spawn_for_test(4, move |action| {
            applied_by_owner.lock().unwrap().push(action);
            Ok(())
        })
        .unwrap();
        let kernel = vec![
            KernelRecoveryRecordV2 {
                identity: identity(0xe1),
                state: KernelRecoveryStateV2::Prepared,
                subject: RecoverySubjectV2::ToolExecution,
            },
            KernelRecoveryRecordV2 {
                identity: identity(0xe2),
                state: KernelRecoveryStateV2::Dispatching,
                subject: RecoverySubjectV2::ToolExecution,
            },
        ];

        let actions = owner
            .reconcile_records_for_test(
                kernel,
                Vec::new(),
                Vec::new(),
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();

        assert_eq!(actions.len(), 2);
        assert_eq!(*applied.lock().unwrap(), actions);
    }

    #[test]
    fn recovery_contradiction_is_detected_before_any_action_is_applied() {
        let applied = Arc::new(Mutex::new(Vec::new()));
        let applied_by_owner = Arc::clone(&applied);
        let owner = RecoveryStateOwnerV2::spawn_for_test(4, move |action| {
            applied_by_owner.lock().unwrap().push(action);
            Ok(())
        })
        .unwrap();
        let orphan = vec![ExecdRecoveryRecordV2 {
            identity: identity(0xf1),
            state: ExecdRecoveryStateV2::KnownSuccess,
            subject: RecoverySubjectKindV2::ToolExecution,
        }];

        assert!(owner
            .reconcile_records_for_test(
                Vec::new(),
                orphan,
                Vec::new(),
                Instant::now() + Duration::from_secs(1),
            )
            .is_err());
        assert!(applied.lock().unwrap().is_empty());
    }

    #[test]
    fn recovery_rescans_after_every_durable_action_until_all_rows_are_noops() {
        let phase = Arc::new(Mutex::new(0_u8));
        let scan_phase = Arc::clone(&phase);
        let apply_phase = Arc::clone(&phase);
        let applied = Arc::new(Mutex::new(Vec::new()));
        let applied_by_owner = Arc::clone(&applied);
        let owner = RescanningRecoveryStateOwnerV2::spawn_for_test(
            2,
            move || {
                let phase = *scan_phase.lock().unwrap();
                Ok(if phase == 0 {
                    vec![RecoveryActionV2::AbortBeforeEffect {
                        identity: identity(0xa1),
                    }]
                } else {
                    vec![RecoveryActionV2::Noop]
                })
            },
            move |action| {
                applied_by_owner.lock().unwrap().push(action);
                *apply_phase.lock().unwrap() = 1;
                Ok(())
            },
        )
        .unwrap();

        assert_eq!(
            owner
                .reconcile(Instant::now() + Duration::from_secs(1))
                .unwrap(),
            vec![RecoveryActionV2::AbortBeforeEffect {
                identity: identity(0xa1)
            }]
        );
        assert_eq!(applied.lock().unwrap().len(), 1);
    }

    #[test]
    fn recovery_that_does_not_make_durable_progress_fails_closed() {
        let action = RecoveryActionV2::QuarantineIndeterminate {
            identity: identity(0xb1),
        };
        let owner =
            RescanningRecoveryStateOwnerV2::spawn_for_test(2, move || Ok(vec![action]), |_| Ok(()))
                .unwrap();

        assert_eq!(
            owner
                .reconcile(Instant::now() + Duration::from_secs(1))
                .unwrap_err(),
            RecoveryRuntimeErrorV2::Recovery(RecoveryErrorV2::Contradiction)
        );
    }
}
