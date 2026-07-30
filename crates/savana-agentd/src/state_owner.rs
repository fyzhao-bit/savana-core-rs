use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Instant;

use savana_kernel_protocol::v2::{
    BootstrapKindV2, CancelTaskRequestV2, CancelTaskResponseV2, GetTaskStatusRequestV2,
    GetTaskStatusResponseV2, JarvisBootstrapSelectorV2, Nonce32V2, PrepareIngressResponseV2,
    UnixMillisV2,
};

use crate::{
    AgentTaskErrorV2, AgentTaskRecoveryProjectionV2, AgentTaskRollbackAnchorV2, AgentTaskServiceV2,
    AuthenticatedJarvisControlV2, DurableAgentTaskNamespaceV2, DurableAgentTaskServiceV2,
    PendingTaskCancellationV2, PendingTaskStatusQueryV2, ResolvedJarvisBootstrapV2,
    VerifiedKernelCancellationV2, VerifiedKernelTaskPreparationV2, VerifiedKernelTaskStatusV2,
};

const OWNER_RUNNING: u8 = 1;
const OWNER_CLOSING: u8 = 2;
const OWNER_FAILED: u8 = 3;
const OWNER_STOPPED: u8 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AgentTaskStateOwnerErrorV2 {
    #[error("agent task state owner is busy")]
    Busy,
    #[error("agent task state owner deadline was exceeded")]
    DeadlineExceeded,
    #[error("agent task state owner is unavailable")]
    Unavailable,
    #[error("agent task operation failed")]
    Task(AgentTaskErrorV2),
}

enum AgentTaskOwnerCommandV2 {
    PrepareIngress {
        context: AuthenticatedJarvisControlV2,
        client_request_nonce: Nonce32V2,
        preparation: Box<VerifiedKernelTaskPreparationV2>,
        now: UnixMillisV2,
    },
    GetTaskStatus {
        context: AuthenticatedJarvisControlV2,
        request: GetTaskStatusRequestV2,
        now: UnixMillisV2,
    },
    InspectBootstrap {
        kind: BootstrapKindV2,
        selector: JarvisBootstrapSelectorV2,
        now: UnixMillisV2,
    },
    ContinueBootstrap {
        kind: BootstrapKindV2,
        selector: JarvisBootstrapSelectorV2,
        now: UnixMillisV2,
    },
    PrepareStatusQuery {
        context: AuthenticatedJarvisControlV2,
        request: GetTaskStatusRequestV2,
        now: UnixMillisV2,
    },
    ApplyKernelStatus {
        verified: VerifiedKernelTaskStatusV2,
        now: UnixMillisV2,
    },
    PrepareCancel {
        context: AuthenticatedJarvisControlV2,
        request: CancelTaskRequestV2,
        now: UnixMillisV2,
    },
    CommitCancellation {
        pending: Box<PendingTaskCancellationV2>,
        verified: VerifiedKernelCancellationV2,
        now: UnixMillisV2,
    },
    RecoveryProjection,
}

enum AgentTaskOwnerResponseV2 {
    PrepareIngress(PrepareIngressResponseV2),
    GetTaskStatus(GetTaskStatusResponseV2),
    Bootstrap(Box<ResolvedJarvisBootstrapV2>),
    PendingStatusQuery(Box<PendingTaskStatusQueryV2>),
    PendingCancellation(Box<PendingTaskCancellationV2>),
    CancelTask(CancelTaskResponseV2),
    RecoveryProjection(Vec<AgentTaskRecoveryProjectionV2>),
    Unit,
}

enum AgentTaskOwnerMessageV2 {
    Execute {
        command: Box<AgentTaskOwnerCommandV2>,
        deadline: Instant,
        response: SyncSender<Result<AgentTaskOwnerResponseV2, AgentTaskStateOwnerErrorV2>>,
    },
    Shutdown,
}

/// The bounded, single-thread ownership boundary for agentd task state.
pub struct AgentTaskStateOwnerV2 {
    sender: SyncSender<AgentTaskOwnerMessageV2>,
    lifecycle: Arc<AtomicU8>,
    owner: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for AgentTaskStateOwnerV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AgentTaskStateOwnerV2")
            .field("lifecycle", &self.lifecycle.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

impl AgentTaskStateOwnerV2 {
    pub fn open(
        state_path: &Path,
        master_encryption_key: [u8; 32],
        namespace: DurableAgentTaskNamespaceV2,
        rollback_anchor: Box<dyn AgentTaskRollbackAnchorV2>,
        deployment: AgentTaskServiceV2,
        capacity: usize,
    ) -> Result<Self, AgentTaskStateOwnerErrorV2> {
        if capacity == 0 {
            return Err(AgentTaskStateOwnerErrorV2::Unavailable);
        }
        let durable = DurableAgentTaskServiceV2::open(
            state_path,
            master_encryption_key,
            namespace,
            rollback_anchor,
            deployment,
        )
        .map_err(AgentTaskStateOwnerErrorV2::Task)?;
        let (sender, receiver) = mpsc::sync_channel(capacity);
        let lifecycle = Arc::new(AtomicU8::new(OWNER_RUNNING));
        let owner_lifecycle = Arc::clone(&lifecycle);
        let owner = thread::Builder::new()
            .name("savana-agentd-state-v2".to_owned())
            .spawn(move || owner_loop(receiver, owner_lifecycle, durable))
            .map_err(|_| AgentTaskStateOwnerErrorV2::Unavailable)?;
        Ok(Self {
            sender,
            lifecycle,
            owner: Some(owner),
        })
    }

    pub fn prepare_ingress(
        &self,
        context: AuthenticatedJarvisControlV2,
        client_request_nonce: Nonce32V2,
        preparation: VerifiedKernelTaskPreparationV2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<PrepareIngressResponseV2, AgentTaskStateOwnerErrorV2> {
        match self.request(
            AgentTaskOwnerCommandV2::PrepareIngress {
                context,
                client_request_nonce,
                preparation: Box::new(preparation),
                now,
            },
            deadline,
        )? {
            AgentTaskOwnerResponseV2::PrepareIngress(value) => Ok(value),
            _ => Err(AgentTaskStateOwnerErrorV2::Unavailable),
        }
    }

    pub fn get_task_status(
        &self,
        context: AuthenticatedJarvisControlV2,
        request: GetTaskStatusRequestV2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<GetTaskStatusResponseV2, AgentTaskStateOwnerErrorV2> {
        match self.request(
            AgentTaskOwnerCommandV2::GetTaskStatus {
                context,
                request,
                now,
            },
            deadline,
        )? {
            AgentTaskOwnerResponseV2::GetTaskStatus(value) => Ok(value),
            _ => Err(AgentTaskStateOwnerErrorV2::Unavailable),
        }
    }

    pub fn inspect_bootstrap(
        &self,
        kind: BootstrapKindV2,
        selector: JarvisBootstrapSelectorV2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<(), AgentTaskStateOwnerErrorV2> {
        match self.request(
            AgentTaskOwnerCommandV2::InspectBootstrap {
                kind,
                selector,
                now,
            },
            deadline,
        )? {
            AgentTaskOwnerResponseV2::Unit => Ok(()),
            _ => Err(AgentTaskStateOwnerErrorV2::Unavailable),
        }
    }

    pub fn continue_bootstrap(
        &self,
        kind: BootstrapKindV2,
        selector: JarvisBootstrapSelectorV2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<ResolvedJarvisBootstrapV2, AgentTaskStateOwnerErrorV2> {
        match self.request(
            AgentTaskOwnerCommandV2::ContinueBootstrap {
                kind,
                selector,
                now,
            },
            deadline,
        )? {
            AgentTaskOwnerResponseV2::Bootstrap(value) => Ok(*value),
            _ => Err(AgentTaskStateOwnerErrorV2::Unavailable),
        }
    }

    pub fn apply_verified_kernel_status(
        &self,
        verified: VerifiedKernelTaskStatusV2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<(), AgentTaskStateOwnerErrorV2> {
        match self.request(
            AgentTaskOwnerCommandV2::ApplyKernelStatus { verified, now },
            deadline,
        )? {
            AgentTaskOwnerResponseV2::Unit => Ok(()),
            _ => Err(AgentTaskStateOwnerErrorV2::Unavailable),
        }
    }

    pub fn prepare_status_query(
        &self,
        context: AuthenticatedJarvisControlV2,
        request: GetTaskStatusRequestV2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<PendingTaskStatusQueryV2, AgentTaskStateOwnerErrorV2> {
        match self.request(
            AgentTaskOwnerCommandV2::PrepareStatusQuery {
                context,
                request,
                now,
            },
            deadline,
        )? {
            AgentTaskOwnerResponseV2::PendingStatusQuery(value) => Ok(*value),
            _ => Err(AgentTaskStateOwnerErrorV2::Unavailable),
        }
    }

    pub fn prepare_cancel(
        &self,
        context: AuthenticatedJarvisControlV2,
        request: CancelTaskRequestV2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<PendingTaskCancellationV2, AgentTaskStateOwnerErrorV2> {
        match self.request(
            AgentTaskOwnerCommandV2::PrepareCancel {
                context,
                request,
                now,
            },
            deadline,
        )? {
            AgentTaskOwnerResponseV2::PendingCancellation(value) => Ok(*value),
            _ => Err(AgentTaskStateOwnerErrorV2::Unavailable),
        }
    }

    pub fn commit_verified_cancellation(
        &self,
        pending: PendingTaskCancellationV2,
        verified: VerifiedKernelCancellationV2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<CancelTaskResponseV2, AgentTaskStateOwnerErrorV2> {
        match self.request(
            AgentTaskOwnerCommandV2::CommitCancellation {
                pending: Box::new(pending),
                verified,
                now,
            },
            deadline,
        )? {
            AgentTaskOwnerResponseV2::CancelTask(value) => Ok(value),
            _ => Err(AgentTaskStateOwnerErrorV2::Unavailable),
        }
    }

    pub fn recovery_projection(
        &self,
        deadline: Instant,
    ) -> Result<Vec<AgentTaskRecoveryProjectionV2>, AgentTaskStateOwnerErrorV2> {
        match self.request(AgentTaskOwnerCommandV2::RecoveryProjection, deadline)? {
            AgentTaskOwnerResponseV2::RecoveryProjection(value) => Ok(value),
            _ => Err(AgentTaskStateOwnerErrorV2::Unavailable),
        }
    }

    fn request(
        &self,
        command: AgentTaskOwnerCommandV2,
        deadline: Instant,
    ) -> Result<AgentTaskOwnerResponseV2, AgentTaskStateOwnerErrorV2> {
        if Instant::now() >= deadline {
            return Err(AgentTaskStateOwnerErrorV2::DeadlineExceeded);
        }
        if self.lifecycle.load(Ordering::Acquire) != OWNER_RUNNING {
            return Err(AgentTaskStateOwnerErrorV2::Unavailable);
        }
        let (response, received) = mpsc::sync_channel(1);
        match self.sender.try_send(AgentTaskOwnerMessageV2::Execute {
            command: Box::new(command),
            deadline,
            response,
        }) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => return Err(AgentTaskStateOwnerErrorV2::Busy),
            Err(TrySendError::Disconnected(_)) => {
                self.lifecycle.store(OWNER_FAILED, Ordering::Release);
                return Err(AgentTaskStateOwnerErrorV2::Unavailable);
            }
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(AgentTaskStateOwnerErrorV2::DeadlineExceeded);
        }
        match received.recv_timeout(remaining) {
            Ok(result) => result,
            Err(RecvTimeoutError::Timeout) => Err(AgentTaskStateOwnerErrorV2::DeadlineExceeded),
            Err(RecvTimeoutError::Disconnected) => {
                self.lifecycle.store(OWNER_FAILED, Ordering::Release);
                Err(AgentTaskStateOwnerErrorV2::Unavailable)
            }
        }
    }
}

impl Drop for AgentTaskStateOwnerV2 {
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
            let _ = self.sender.send(AgentTaskOwnerMessageV2::Shutdown);
        }
        if let Some(owner) = self.owner.take() {
            if owner.join().is_err() {
                self.lifecycle.store(OWNER_FAILED, Ordering::Release);
            }
        }
    }
}

fn owner_loop(
    receiver: Receiver<AgentTaskOwnerMessageV2>,
    lifecycle: Arc<AtomicU8>,
    mut durable: DurableAgentTaskServiceV2,
) {
    while let Ok(message) = receiver.recv() {
        match message {
            AgentTaskOwnerMessageV2::Execute {
                command,
                deadline,
                response,
            } => {
                if lifecycle.load(Ordering::Acquire) != OWNER_RUNNING {
                    let _ = response.send(Err(AgentTaskStateOwnerErrorV2::Unavailable));
                    continue;
                }
                if Instant::now() >= deadline {
                    let _ = response.send(Err(AgentTaskStateOwnerErrorV2::DeadlineExceeded));
                    continue;
                }
                let result = catch_unwind(AssertUnwindSafe(|| dispatch(&mut durable, *command)))
                    .unwrap_or(Err(AgentTaskStateOwnerErrorV2::Unavailable));
                let fatal = result.as_ref().is_err_and(is_fatal);
                let _ = response.send(result);
                if fatal {
                    lifecycle.store(OWNER_FAILED, Ordering::Release);
                    return;
                }
            }
            AgentTaskOwnerMessageV2::Shutdown => {
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
    durable: &mut DurableAgentTaskServiceV2,
    command: AgentTaskOwnerCommandV2,
) -> Result<AgentTaskOwnerResponseV2, AgentTaskStateOwnerErrorV2> {
    let response = match command {
        AgentTaskOwnerCommandV2::PrepareIngress {
            context,
            client_request_nonce,
            preparation,
            now,
        } => AgentTaskOwnerResponseV2::PrepareIngress(
            durable
                .prepare_ingress(context, client_request_nonce, *preparation, now)
                .map_err(AgentTaskStateOwnerErrorV2::Task)?,
        ),
        AgentTaskOwnerCommandV2::GetTaskStatus {
            context,
            request,
            now,
        } => AgentTaskOwnerResponseV2::GetTaskStatus(
            durable
                .get_task_status(context, request, now)
                .map_err(AgentTaskStateOwnerErrorV2::Task)?,
        ),
        AgentTaskOwnerCommandV2::InspectBootstrap {
            kind,
            selector,
            now,
        } => {
            durable
                .inspect_bootstrap(kind, selector, now)
                .map_err(AgentTaskStateOwnerErrorV2::Task)?;
            AgentTaskOwnerResponseV2::Unit
        }
        AgentTaskOwnerCommandV2::ContinueBootstrap {
            kind,
            selector,
            now,
        } => AgentTaskOwnerResponseV2::Bootstrap(Box::new(
            durable
                .continue_bootstrap(kind, selector, now)
                .map_err(AgentTaskStateOwnerErrorV2::Task)?,
        )),
        AgentTaskOwnerCommandV2::PrepareStatusQuery {
            context,
            request,
            now,
        } => AgentTaskOwnerResponseV2::PendingStatusQuery(Box::new(
            durable
                .prepare_status_query(context, request, now)
                .map_err(AgentTaskStateOwnerErrorV2::Task)?,
        )),
        AgentTaskOwnerCommandV2::ApplyKernelStatus { verified, now } => {
            durable
                .apply_verified_kernel_status(verified, now)
                .map_err(AgentTaskStateOwnerErrorV2::Task)?;
            AgentTaskOwnerResponseV2::Unit
        }
        AgentTaskOwnerCommandV2::PrepareCancel {
            context,
            request,
            now,
        } => AgentTaskOwnerResponseV2::PendingCancellation(Box::new(
            durable
                .prepare_cancel(context, request, now)
                .map_err(AgentTaskStateOwnerErrorV2::Task)?,
        )),
        AgentTaskOwnerCommandV2::CommitCancellation {
            pending,
            verified,
            now,
        } => AgentTaskOwnerResponseV2::CancelTask(
            durable
                .commit_verified_cancellation(*pending, verified, now)
                .map_err(AgentTaskStateOwnerErrorV2::Task)?,
        ),
        AgentTaskOwnerCommandV2::RecoveryProjection => {
            AgentTaskOwnerResponseV2::RecoveryProjection(
                durable
                    .recovery_projection()
                    .map_err(AgentTaskStateOwnerErrorV2::Task)?,
            )
        }
    };
    Ok(response)
}

fn is_fatal(error: &AgentTaskStateOwnerErrorV2) -> bool {
    matches!(
        error,
        AgentTaskStateOwnerErrorV2::Unavailable
            | AgentTaskStateOwnerErrorV2::Task(
                AgentTaskErrorV2::DurableState
                    | AgentTaskErrorV2::DurableAuthentication
                    | AgentTaskErrorV2::RollbackDetected
                    | AgentTaskErrorV2::CommitUncertain
            )
    )
}
