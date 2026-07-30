use std::fs::File;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Instant;

use savana_kernel_protocol::v2::{
    Digest32V2, EffectLedgerProjectionBindingV2, ExecutorFailureClassV2, Nonce32V2,
    SignedExecutorEffectStartedReceiptV2, UnixMillisV2,
};

use crate::{
    ArmedEffectV2, DurableExecdNamespaceV2, DurableExecdServiceV2, EffectGatedExecdRuntimeV2,
    ExecdErrorV2, ExecdQueryV2, ExecdRollbackAnchorV2, ExecdRuntimeErrorV2,
    ProviderAttemptPredecessorV2, RetainedProviderResponseV2, SignedExecutorReceiptV2,
    StoredExecutorCompletionV2, VerifiedExecdDeploymentV2,
};

const OWNER_RUNNING: u8 = 1;
const OWNER_CLOSING: u8 = 2;
const OWNER_FAILED: u8 = 3;
const OWNER_STOPPED: u8 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ExecdStateOwnerErrorV2 {
    #[error("executor state owner is busy")]
    Busy,
    #[error("executor state owner deadline was exceeded")]
    DeadlineExceeded,
    #[error("executor state owner is unavailable")]
    Unavailable,
    #[error("executor runtime operation failed")]
    Runtime(ExecdRuntimeErrorV2),
}

enum ExecdOwnerCommandV2 {
    Query(Nonce32V2),
    SealedExecutionEnvelope(Nonce32V2),
    RecoveryProjection,
    Accept {
        canonical_envelope: Vec<u8>,
        now: UnixMillisV2,
        deadline: Instant,
    },
    PrepareProviderAttempt {
        nonce: Nonce32V2,
        prepared_request_digest: Digest32V2,
        now: UnixMillisV2,
    },
    RecordEffectStarted {
        predecessor: ProviderAttemptPredecessorV2,
        now: UnixMillisV2,
    },
    RecordProviderResponse {
        nonce: Nonce32V2,
        response: Vec<u8>,
    },
    PrepareFinalReleaseEvidence {
        nonce: Nonce32V2,
        provider_evidence: Vec<u8>,
        audit_evidence: Vec<u8>,
        now: UnixMillisV2,
    },
    RetainedProviderResponse(Nonce32V2),
    Completion(Nonce32V2),
    RecordToolCompletion {
        nonce: Nonce32V2,
        result: Vec<u8>,
        evidence_digest: Digest32V2,
        now: UnixMillisV2,
    },
    RecordFinalReleaseCompletion {
        nonce: Nonce32V2,
        now: UnixMillisV2,
    },
    #[cfg(test)]
    RecordKnownSuccess {
        nonce: Nonce32V2,
        evidence_digest: Digest32V2,
        now: UnixMillisV2,
    },
    RecordFailedNoEffect {
        nonce: Nonce32V2,
        class: ExecutorFailureClassV2,
        evidence_digest: Digest32V2,
        now: UnixMillisV2,
    },
    RecordFailedNoEffectRecovery {
        nonce: Nonce32V2,
        class: ExecutorFailureClassV2,
        evidence_digest: Digest32V2,
        now: UnixMillisV2,
    },
    RecordIndeterminate {
        nonce: Nonce32V2,
        evidence_digest: Digest32V2,
        now: UnixMillisV2,
    },
    RecordIndeterminateRecovery {
        nonce: Nonce32V2,
        evidence_digest: Digest32V2,
        now: UnixMillisV2,
    },
    TerminalReceipt(Nonce32V2),
    EffectStartedReceipt(Nonce32V2),
    Acknowledge {
        nonce: Nonce32V2,
        kernel_commit_digest: Digest32V2,
    },
    Fence(Instant),
    #[cfg(test)]
    ActiveGuardCount,
}

enum ExecdOwnerResponseV2 {
    Query(ExecdQueryV2),
    SealedExecutionEnvelope(zeroize::Zeroizing<Vec<u8>>),
    RecoveryProjection(Vec<ExecdQueryV2>),
    Predecessor(ProviderAttemptPredecessorV2),
    Armed(ArmedEffectV2),
    Digest(Digest32V2),
    Retained(RetainedProviderResponseV2),
    Receipt(SignedExecutorReceiptV2),
    EffectReceipt(SignedExecutorEffectStartedReceiptV2),
    Completion(StoredExecutorCompletionV2),
    Unit,
    #[cfg(test)]
    Count(usize),
}

enum ExecdOwnerMessageV2 {
    Execute {
        command: ExecdOwnerCommandV2,
        deadline: Instant,
        response: SyncSender<Result<ExecdOwnerResponseV2, ExecdStateOwnerErrorV2>>,
    },
    Shutdown,
}

/// The only production owner of execd's durable journal and EffectGate state.
///
/// Callers can submit closed commands through a bounded queue, but cannot
/// borrow the runtime, journal, rollback anchor, signing key, or gate
/// descriptor.
pub struct ExecdStateOwnerV2 {
    sender: SyncSender<ExecdOwnerMessageV2>,
    lifecycle: Arc<AtomicU8>,
    owner: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for ExecdStateOwnerV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExecdStateOwnerV2")
            .field("lifecycle", &self.lifecycle.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

impl ExecdStateOwnerV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn open(
        journal_path: &Path,
        master_encryption_key: [u8; 32],
        namespace: DurableExecdNamespaceV2,
        rollback_anchor: Box<dyn ExecdRollbackAnchorV2>,
        deployment: VerifiedExecdDeploymentV2,
        shared_only_effect_gate_descriptor: File,
        read_only_ledger_projection_descriptor: File,
        projection_binding: EffectLedgerProjectionBindingV2,
        recovery_deadline: Instant,
        capacity: usize,
    ) -> Result<Self, ExecdStateOwnerErrorV2> {
        let durable = DurableExecdServiceV2::open(
            journal_path,
            master_encryption_key,
            namespace,
            rollback_anchor,
            deployment,
        )
        .map_err(|error| ExecdStateOwnerErrorV2::Runtime(ExecdRuntimeErrorV2::Journal(error)))?;
        let runtime = EffectGatedExecdRuntimeV2::from_durable_service(
            durable,
            shared_only_effect_gate_descriptor,
            read_only_ledger_projection_descriptor,
            projection_binding,
            recovery_deadline,
        )
        .map_err(ExecdStateOwnerErrorV2::Runtime)?;
        Self::spawn(runtime, capacity)
    }

    pub(crate) fn spawn(
        runtime: EffectGatedExecdRuntimeV2,
        capacity: usize,
    ) -> Result<Self, ExecdStateOwnerErrorV2> {
        if capacity == 0 {
            return Err(ExecdStateOwnerErrorV2::Unavailable);
        }
        let (sender, receiver) = mpsc::sync_channel(capacity);
        let lifecycle = Arc::new(AtomicU8::new(OWNER_RUNNING));
        let owner_lifecycle = Arc::clone(&lifecycle);
        let owner = thread::Builder::new()
            .name("savana-execd-state-v2".to_owned())
            .spawn(move || owner_loop(receiver, owner_lifecycle, runtime))
            .map_err(|_| ExecdStateOwnerErrorV2::Unavailable)?;
        Ok(Self {
            sender,
            lifecycle,
            owner: Some(owner),
        })
    }

    pub fn query(
        &self,
        nonce: Nonce32V2,
        deadline: Instant,
    ) -> Result<ExecdQueryV2, ExecdStateOwnerErrorV2> {
        match self.request(ExecdOwnerCommandV2::Query(nonce), deadline)? {
            ExecdOwnerResponseV2::Query(value) => Ok(value),
            _ => Err(ExecdStateOwnerErrorV2::Unavailable),
        }
    }

    pub(crate) fn sealed_execution_envelope(
        &self,
        nonce: Nonce32V2,
        deadline: Instant,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, ExecdStateOwnerErrorV2> {
        match self.request(
            ExecdOwnerCommandV2::SealedExecutionEnvelope(nonce),
            deadline,
        )? {
            ExecdOwnerResponseV2::SealedExecutionEnvelope(value) => Ok(value),
            _ => Err(ExecdStateOwnerErrorV2::Unavailable),
        }
    }

    pub fn recovery_projection(
        &self,
        deadline: Instant,
    ) -> Result<Vec<ExecdQueryV2>, ExecdStateOwnerErrorV2> {
        match self.request(ExecdOwnerCommandV2::RecoveryProjection, deadline)? {
            ExecdOwnerResponseV2::RecoveryProjection(value) => Ok(value),
            _ => Err(ExecdStateOwnerErrorV2::Unavailable),
        }
    }

    pub fn accept_signed_dispatch(
        &self,
        canonical_envelope: Vec<u8>,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<ExecdQueryV2, ExecdStateOwnerErrorV2> {
        match self.request(
            ExecdOwnerCommandV2::Accept {
                canonical_envelope,
                now,
                deadline,
            },
            deadline,
        )? {
            ExecdOwnerResponseV2::Query(value) => Ok(value),
            _ => Err(ExecdStateOwnerErrorV2::Unavailable),
        }
    }

    pub fn prepare_provider_attempt(
        &self,
        nonce: Nonce32V2,
        prepared_request_digest: Digest32V2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<ProviderAttemptPredecessorV2, ExecdStateOwnerErrorV2> {
        match self.request(
            ExecdOwnerCommandV2::PrepareProviderAttempt {
                nonce,
                prepared_request_digest,
                now,
            },
            deadline,
        )? {
            ExecdOwnerResponseV2::Predecessor(value) => Ok(value),
            _ => Err(ExecdStateOwnerErrorV2::Unavailable),
        }
    }

    pub fn record_effect_started(
        &self,
        predecessor: ProviderAttemptPredecessorV2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<ArmedEffectV2, ExecdStateOwnerErrorV2> {
        match self.request(
            ExecdOwnerCommandV2::RecordEffectStarted { predecessor, now },
            deadline,
        )? {
            ExecdOwnerResponseV2::Armed(value) => Ok(value),
            _ => Err(ExecdStateOwnerErrorV2::Unavailable),
        }
    }

    pub fn record_provider_response(
        &self,
        nonce: Nonce32V2,
        response: Vec<u8>,
        deadline: Instant,
    ) -> Result<RetainedProviderResponseV2, ExecdStateOwnerErrorV2> {
        match self.request(
            ExecdOwnerCommandV2::RecordProviderResponse { nonce, response },
            deadline,
        )? {
            ExecdOwnerResponseV2::Retained(value) => Ok(value),
            _ => Err(ExecdStateOwnerErrorV2::Unavailable),
        }
    }

    pub fn retained_provider_response(
        &self,
        nonce: Nonce32V2,
        deadline: Instant,
    ) -> Result<RetainedProviderResponseV2, ExecdStateOwnerErrorV2> {
        match self.request(
            ExecdOwnerCommandV2::RetainedProviderResponse(nonce),
            deadline,
        )? {
            ExecdOwnerResponseV2::Retained(value) => Ok(value),
            _ => Err(ExecdStateOwnerErrorV2::Unavailable),
        }
    }

    pub fn prepare_final_release_evidence(
        &self,
        nonce: Nonce32V2,
        provider_evidence: Vec<u8>,
        audit_evidence: Vec<u8>,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<Digest32V2, ExecdStateOwnerErrorV2> {
        match self.request(
            ExecdOwnerCommandV2::PrepareFinalReleaseEvidence {
                nonce,
                provider_evidence,
                audit_evidence,
                now,
            },
            deadline,
        )? {
            ExecdOwnerResponseV2::Digest(value) => Ok(value),
            _ => Err(ExecdStateOwnerErrorV2::Unavailable),
        }
    }

    pub fn completion(
        &self,
        nonce: Nonce32V2,
        deadline: Instant,
    ) -> Result<StoredExecutorCompletionV2, ExecdStateOwnerErrorV2> {
        match self.request(ExecdOwnerCommandV2::Completion(nonce), deadline)? {
            ExecdOwnerResponseV2::Completion(value) => Ok(value),
            _ => Err(ExecdStateOwnerErrorV2::Unavailable),
        }
    }

    pub fn record_tool_completion(
        &self,
        nonce: Nonce32V2,
        result: Vec<u8>,
        evidence_digest: Digest32V2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<StoredExecutorCompletionV2, ExecdStateOwnerErrorV2> {
        match self.request(
            ExecdOwnerCommandV2::RecordToolCompletion {
                nonce,
                result,
                evidence_digest,
                now,
            },
            deadline,
        )? {
            ExecdOwnerResponseV2::Completion(value) => Ok(value),
            _ => Err(ExecdStateOwnerErrorV2::Unavailable),
        }
    }

    pub fn record_final_release_completion(
        &self,
        nonce: Nonce32V2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<StoredExecutorCompletionV2, ExecdStateOwnerErrorV2> {
        match self.request(
            ExecdOwnerCommandV2::RecordFinalReleaseCompletion { nonce, now },
            deadline,
        )? {
            ExecdOwnerResponseV2::Completion(value) => Ok(value),
            _ => Err(ExecdStateOwnerErrorV2::Unavailable),
        }
    }

    #[cfg(test)]
    pub fn record_known_success(
        &self,
        nonce: Nonce32V2,
        evidence_digest: Digest32V2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<SignedExecutorReceiptV2, ExecdStateOwnerErrorV2> {
        self.record_terminal(
            ExecdOwnerCommandV2::RecordKnownSuccess {
                nonce,
                evidence_digest,
                now,
            },
            deadline,
        )
    }

    pub fn record_failed_no_effect(
        &self,
        nonce: Nonce32V2,
        class: ExecutorFailureClassV2,
        evidence_digest: Digest32V2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<SignedExecutorReceiptV2, ExecdStateOwnerErrorV2> {
        self.record_terminal(
            ExecdOwnerCommandV2::RecordFailedNoEffect {
                nonce,
                class,
                evidence_digest,
                now,
            },
            deadline,
        )
    }

    pub fn record_failed_no_effect_recovery(
        &self,
        nonce: Nonce32V2,
        class: ExecutorFailureClassV2,
        evidence_digest: Digest32V2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<SignedExecutorReceiptV2, ExecdStateOwnerErrorV2> {
        self.record_terminal(
            ExecdOwnerCommandV2::RecordFailedNoEffectRecovery {
                nonce,
                class,
                evidence_digest,
                now,
            },
            deadline,
        )
    }

    pub fn record_indeterminate(
        &self,
        nonce: Nonce32V2,
        evidence_digest: Digest32V2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<SignedExecutorReceiptV2, ExecdStateOwnerErrorV2> {
        self.record_terminal(
            ExecdOwnerCommandV2::RecordIndeterminate {
                nonce,
                evidence_digest,
                now,
            },
            deadline,
        )
    }

    pub fn record_indeterminate_recovery(
        &self,
        nonce: Nonce32V2,
        evidence_digest: Digest32V2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<SignedExecutorReceiptV2, ExecdStateOwnerErrorV2> {
        self.record_terminal(
            ExecdOwnerCommandV2::RecordIndeterminateRecovery {
                nonce,
                evidence_digest,
                now,
            },
            deadline,
        )
    }

    pub fn terminal_receipt(
        &self,
        nonce: Nonce32V2,
        deadline: Instant,
    ) -> Result<SignedExecutorReceiptV2, ExecdStateOwnerErrorV2> {
        match self.request(ExecdOwnerCommandV2::TerminalReceipt(nonce), deadline)? {
            ExecdOwnerResponseV2::Receipt(value) => Ok(value),
            _ => Err(ExecdStateOwnerErrorV2::Unavailable),
        }
    }

    pub fn effect_started_receipt(
        &self,
        nonce: Nonce32V2,
        deadline: Instant,
    ) -> Result<SignedExecutorEffectStartedReceiptV2, ExecdStateOwnerErrorV2> {
        match self.request(ExecdOwnerCommandV2::EffectStartedReceipt(nonce), deadline)? {
            ExecdOwnerResponseV2::EffectReceipt(value) => Ok(value),
            _ => Err(ExecdStateOwnerErrorV2::Unavailable),
        }
    }

    pub fn acknowledge_completion(
        &self,
        nonce: Nonce32V2,
        kernel_commit_digest: Digest32V2,
        deadline: Instant,
    ) -> Result<(), ExecdStateOwnerErrorV2> {
        match self.request(
            ExecdOwnerCommandV2::Acknowledge {
                nonce,
                kernel_commit_digest,
            },
            deadline,
        )? {
            ExecdOwnerResponseV2::Unit => Ok(()),
            _ => Err(ExecdStateOwnerErrorV2::Unavailable),
        }
    }

    pub fn fence(&self, deadline: Instant) -> Result<(), ExecdStateOwnerErrorV2> {
        match self.request(ExecdOwnerCommandV2::Fence(deadline), deadline)? {
            ExecdOwnerResponseV2::Unit => Ok(()),
            _ => Err(ExecdStateOwnerErrorV2::Unavailable),
        }
    }

    fn record_terminal(
        &self,
        command: ExecdOwnerCommandV2,
        deadline: Instant,
    ) -> Result<SignedExecutorReceiptV2, ExecdStateOwnerErrorV2> {
        match self.request(command, deadline)? {
            ExecdOwnerResponseV2::Receipt(value) => Ok(value),
            _ => Err(ExecdStateOwnerErrorV2::Unavailable),
        }
    }

    fn request(
        &self,
        command: ExecdOwnerCommandV2,
        deadline: Instant,
    ) -> Result<ExecdOwnerResponseV2, ExecdStateOwnerErrorV2> {
        if Instant::now() >= deadline {
            return Err(ExecdStateOwnerErrorV2::DeadlineExceeded);
        }
        if self.lifecycle.load(Ordering::Acquire) != OWNER_RUNNING {
            return Err(ExecdStateOwnerErrorV2::Unavailable);
        }
        let (response, received) = mpsc::sync_channel(1);
        match self.sender.try_send(ExecdOwnerMessageV2::Execute {
            command,
            deadline,
            response,
        }) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => return Err(ExecdStateOwnerErrorV2::Busy),
            Err(TrySendError::Disconnected(_)) => {
                self.lifecycle.store(OWNER_FAILED, Ordering::Release);
                return Err(ExecdStateOwnerErrorV2::Unavailable);
            }
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(ExecdStateOwnerErrorV2::DeadlineExceeded);
        }
        match received.recv_timeout(remaining) {
            Ok(result) => result,
            Err(RecvTimeoutError::Timeout) => Err(ExecdStateOwnerErrorV2::DeadlineExceeded),
            Err(RecvTimeoutError::Disconnected) => {
                self.lifecycle.store(OWNER_FAILED, Ordering::Release);
                Err(ExecdStateOwnerErrorV2::Unavailable)
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn active_guard_count_for_test(&self) -> usize {
        let deadline = Instant::now() + std::time::Duration::from_secs(1);
        match self
            .request(ExecdOwnerCommandV2::ActiveGuardCount, deadline)
            .unwrap()
        {
            ExecdOwnerResponseV2::Count(value) => value,
            _ => panic!("unexpected execd owner response"),
        }
    }
}

impl Drop for ExecdStateOwnerV2 {
    fn drop(&mut self) {
        if self
            .lifecycle
            .compare_exchange(
                OWNER_RUNNING,
                OWNER_CLOSING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            let _ = self.sender.send(ExecdOwnerMessageV2::Shutdown);
        }
        if let Some(owner) = self.owner.take() {
            if owner.join().is_err() {
                self.lifecycle.store(OWNER_FAILED, Ordering::Release);
            }
        }
    }
}

fn owner_loop(
    receiver: Receiver<ExecdOwnerMessageV2>,
    lifecycle: Arc<AtomicU8>,
    mut runtime: EffectGatedExecdRuntimeV2,
) {
    while let Ok(message) = receiver.recv() {
        match message {
            ExecdOwnerMessageV2::Execute {
                command,
                deadline,
                response,
            } => {
                if lifecycle.load(Ordering::Acquire) != OWNER_RUNNING {
                    let _ = response.send(Err(ExecdStateOwnerErrorV2::Unavailable));
                    continue;
                }
                if Instant::now() >= deadline {
                    let _ = response.send(Err(ExecdStateOwnerErrorV2::DeadlineExceeded));
                    continue;
                }
                let result = catch_unwind(AssertUnwindSafe(|| dispatch(&mut runtime, command)))
                    .unwrap_or(Err(ExecdStateOwnerErrorV2::Unavailable));
                let fatal = result.as_ref().is_err_and(is_fatal);
                let _ = response.send(result);
                if fatal {
                    lifecycle.store(OWNER_FAILED, Ordering::Release);
                    return;
                }
            }
            ExecdOwnerMessageV2::Shutdown => {
                lifecycle.store(OWNER_STOPPED, Ordering::Release);
                return;
            }
        }
    }
    if lifecycle.load(Ordering::Acquire) != OWNER_CLOSING {
        lifecycle.store(OWNER_FAILED, Ordering::Release);
    }
}

fn dispatch(
    runtime: &mut EffectGatedExecdRuntimeV2,
    command: ExecdOwnerCommandV2,
) -> Result<ExecdOwnerResponseV2, ExecdStateOwnerErrorV2> {
    let response = match command {
        ExecdOwnerCommandV2::Query(nonce) => {
            ExecdOwnerResponseV2::Query(runtime.query(nonce).map_err(runtime_error)?)
        }
        ExecdOwnerCommandV2::SealedExecutionEnvelope(nonce) => {
            ExecdOwnerResponseV2::SealedExecutionEnvelope(
                runtime
                    .sealed_execution_envelope(nonce)
                    .map_err(runtime_error)?,
            )
        }
        ExecdOwnerCommandV2::RecoveryProjection => ExecdOwnerResponseV2::RecoveryProjection(
            runtime.recovery_projection().map_err(runtime_error)?,
        ),
        ExecdOwnerCommandV2::Accept {
            canonical_envelope,
            now,
            deadline,
        } => ExecdOwnerResponseV2::Query(
            runtime
                .accept_signed_dispatch(&canonical_envelope, now, deadline)
                .map_err(runtime_error)?,
        ),
        ExecdOwnerCommandV2::PrepareProviderAttempt {
            nonce,
            prepared_request_digest,
            now,
        } => ExecdOwnerResponseV2::Predecessor(
            runtime
                .prepare_provider_attempt(nonce, prepared_request_digest, now)
                .map_err(runtime_error)?,
        ),
        ExecdOwnerCommandV2::RecordEffectStarted { predecessor, now } => {
            ExecdOwnerResponseV2::Armed(
                runtime
                    .record_effect_started(predecessor, now)
                    .map_err(runtime_error)?,
            )
        }
        ExecdOwnerCommandV2::RecordProviderResponse { nonce, response } => {
            ExecdOwnerResponseV2::Retained(
                runtime
                    .record_provider_response(nonce, response)
                    .map_err(runtime_error)?,
            )
        }
        ExecdOwnerCommandV2::PrepareFinalReleaseEvidence {
            nonce,
            provider_evidence,
            audit_evidence,
            now,
        } => ExecdOwnerResponseV2::Digest(
            runtime
                .prepare_final_release_evidence(nonce, provider_evidence, audit_evidence, now)
                .map_err(runtime_error)?,
        ),
        ExecdOwnerCommandV2::RetainedProviderResponse(nonce) => ExecdOwnerResponseV2::Retained(
            runtime
                .retained_provider_response(nonce)
                .map_err(runtime_error)?,
        ),
        ExecdOwnerCommandV2::Completion(nonce) => {
            ExecdOwnerResponseV2::Completion(runtime.completion(nonce).map_err(runtime_error)?)
        }
        ExecdOwnerCommandV2::RecordToolCompletion {
            nonce,
            result,
            evidence_digest,
            now,
        } => ExecdOwnerResponseV2::Completion(
            runtime
                .record_tool_completion(nonce, result, evidence_digest, now)
                .map_err(runtime_error)?,
        ),
        ExecdOwnerCommandV2::RecordFinalReleaseCompletion { nonce, now } => {
            ExecdOwnerResponseV2::Completion(
                runtime
                    .record_final_release_completion(nonce, now)
                    .map_err(runtime_error)?,
            )
        }
        #[cfg(test)]
        ExecdOwnerCommandV2::RecordKnownSuccess {
            nonce,
            evidence_digest,
            now,
        } => ExecdOwnerResponseV2::Receipt(
            runtime
                .record_known_success(nonce, evidence_digest, now)
                .map_err(runtime_error)?,
        ),
        ExecdOwnerCommandV2::RecordFailedNoEffect {
            nonce,
            class,
            evidence_digest,
            now,
        } => ExecdOwnerResponseV2::Receipt(
            runtime
                .record_failed_no_effect(nonce, class, evidence_digest, now)
                .map_err(runtime_error)?,
        ),
        ExecdOwnerCommandV2::RecordFailedNoEffectRecovery {
            nonce,
            class,
            evidence_digest,
            now,
        } => ExecdOwnerResponseV2::Receipt(
            runtime
                .record_failed_no_effect_recovery(nonce, class, evidence_digest, now)
                .map_err(runtime_error)?,
        ),
        ExecdOwnerCommandV2::RecordIndeterminate {
            nonce,
            evidence_digest,
            now,
        } => ExecdOwnerResponseV2::Receipt(
            runtime
                .record_indeterminate(nonce, evidence_digest, now)
                .map_err(runtime_error)?,
        ),
        ExecdOwnerCommandV2::RecordIndeterminateRecovery {
            nonce,
            evidence_digest,
            now,
        } => ExecdOwnerResponseV2::Receipt(
            runtime
                .record_indeterminate_recovery(nonce, evidence_digest, now)
                .map_err(runtime_error)?,
        ),
        ExecdOwnerCommandV2::TerminalReceipt(nonce) => {
            ExecdOwnerResponseV2::Receipt(runtime.terminal_receipt(nonce).map_err(runtime_error)?)
        }
        ExecdOwnerCommandV2::EffectStartedReceipt(nonce) => ExecdOwnerResponseV2::EffectReceipt(
            runtime
                .effect_started_receipt(nonce)
                .map_err(runtime_error)?,
        ),
        ExecdOwnerCommandV2::Acknowledge {
            nonce,
            kernel_commit_digest,
        } => {
            runtime
                .acknowledge_completion(nonce, kernel_commit_digest)
                .map_err(runtime_error)?;
            ExecdOwnerResponseV2::Unit
        }
        ExecdOwnerCommandV2::Fence(deadline) => {
            runtime.fence(deadline).map_err(runtime_error)?;
            ExecdOwnerResponseV2::Unit
        }
        #[cfg(test)]
        ExecdOwnerCommandV2::ActiveGuardCount => {
            ExecdOwnerResponseV2::Count(runtime.active_guard_count_for_test())
        }
    };
    Ok(response)
}

const fn runtime_error(error: ExecdRuntimeErrorV2) -> ExecdStateOwnerErrorV2 {
    ExecdStateOwnerErrorV2::Runtime(error)
}

fn is_fatal(error: &ExecdStateOwnerErrorV2) -> bool {
    matches!(
        error,
        ExecdStateOwnerErrorV2::Unavailable
            | ExecdStateOwnerErrorV2::Runtime(
                ExecdRuntimeErrorV2::EffectGateUnavailable
                    | ExecdRuntimeErrorV2::GuardInvariant
                    | ExecdRuntimeErrorV2::Journal(
                        ExecdErrorV2::DurableState
                            | ExecdErrorV2::DurableAuthentication
                            | ExecdErrorV2::RollbackDetected
                            | ExecdErrorV2::CommitUncertain
                    )
            )
    )
}
