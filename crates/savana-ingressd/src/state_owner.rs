use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Instant;

use savana_kernel_protocol::v2::{Digest32V2, Nonce32V2, UnixMillisV2};

use crate::{
    AuthenticatedKernelIngressReceiverV2, ContentKindV2, FinalizedIngressV2, IngressAppendAckV2,
    IngressBeginAckV2, IngressBrowserContextV2, IngressErrorV2, IngressKernelTransferV2,
    IngressPublicStateV2, IngressServiceV2, IngressTabSessionCapabilityV2,
    VerifiedIngressUiAuthorizationV2,
};

const OWNER_RUNNING: u8 = 1;
const OWNER_CLOSING: u8 = 2;
const OWNER_FAILED: u8 = 3;
const OWNER_STOPPED: u8 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum IngressStateOwnerErrorV2 {
    #[error("ingress state owner is busy")]
    Busy,
    #[error("ingress state owner deadline was exceeded")]
    DeadlineExceeded,
    #[error("ingress state owner is unavailable")]
    Unavailable,
    #[error("ingress operation failed")]
    Ingress(IngressErrorV2),
}

enum IngressOwnerCommandV2 {
    OpenAuthenticatedTab {
        authorization: VerifiedIngressUiAuthorizationV2,
        browser_context: IngressBrowserContextV2,
        now: UnixMillisV2,
    },
    Begin {
        tab: IngressTabSessionCapabilityV2,
        browser_context: IngressBrowserContextV2,
        client_request_nonce: Nonce32V2,
        content_kind: ContentKindV2,
        declared_total_bytes: u64,
        declared_content_digest: Option<Digest32V2>,
        now: UnixMillisV2,
    },
    Append {
        tab: IngressTabSessionCapabilityV2,
        browser_context: IngressBrowserContextV2,
        client_request_nonce: Nonce32V2,
        sequence: u32,
        chunk: Vec<u8>,
        now: UnixMillisV2,
    },
    Finalize {
        tab: IngressTabSessionCapabilityV2,
        browser_context: IngressBrowserContextV2,
        client_request_nonce: Nonce32V2,
        declared_content_digest: Digest32V2,
        now: UnixMillisV2,
    },
    ConsumeForKernel {
        finalized: FinalizedIngressV2,
        receiver: AuthenticatedKernelIngressReceiverV2,
        now: UnixMillisV2,
    },
    Abort {
        tab: IngressTabSessionCapabilityV2,
        browser_context: IngressBrowserContextV2,
        client_request_nonce: Nonce32V2,
        now: UnixMillisV2,
    },
    State {
        tab: IngressTabSessionCapabilityV2,
        browser_context: IngressBrowserContextV2,
        now: UnixMillisV2,
    },
}

enum IngressOwnerResponseV2 {
    Tab(IngressTabSessionCapabilityV2),
    Begin(IngressBeginAckV2),
    Append(IngressAppendAckV2),
    Finalized(FinalizedIngressV2),
    Transfer(IngressKernelTransferV2),
    State(IngressPublicStateV2),
}

enum IngressOwnerMessageV2 {
    Execute {
        command: Box<IngressOwnerCommandV2>,
        deadline: Instant,
        response: SyncSender<Result<IngressOwnerResponseV2, IngressStateOwnerErrorV2>>,
    },
    Shutdown,
}

/// Bounded, single-thread owner for all mutable ingress bytes and capabilities.
pub struct IngressStateOwnerV2 {
    sender: SyncSender<IngressOwnerMessageV2>,
    lifecycle: Arc<AtomicU8>,
    owner: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for IngressStateOwnerV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IngressStateOwnerV2")
            .field("lifecycle", &self.lifecycle.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

impl IngressStateOwnerV2 {
    pub fn spawn(
        service: IngressServiceV2,
        capacity: usize,
    ) -> Result<Self, IngressStateOwnerErrorV2> {
        if capacity == 0 {
            return Err(IngressStateOwnerErrorV2::Unavailable);
        }
        let (sender, receiver) = mpsc::sync_channel(capacity);
        let lifecycle = Arc::new(AtomicU8::new(OWNER_RUNNING));
        let owner_lifecycle = Arc::clone(&lifecycle);
        let owner = thread::Builder::new()
            .name("savana-ingressd-state-v2".to_owned())
            .spawn(move || owner_loop(receiver, owner_lifecycle, service))
            .map_err(|_| IngressStateOwnerErrorV2::Unavailable)?;
        Ok(Self {
            sender,
            lifecycle,
            owner: Some(owner),
        })
    }

    pub fn open_authenticated_tab(
        &self,
        authorization: VerifiedIngressUiAuthorizationV2,
        browser_context: IngressBrowserContextV2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<IngressTabSessionCapabilityV2, IngressStateOwnerErrorV2> {
        match self.request(
            IngressOwnerCommandV2::OpenAuthenticatedTab {
                authorization,
                browser_context,
                now,
            },
            deadline,
        )? {
            IngressOwnerResponseV2::Tab(value) => Ok(value),
            _ => Err(IngressStateOwnerErrorV2::Unavailable),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn begin(
        &self,
        tab: IngressTabSessionCapabilityV2,
        browser_context: IngressBrowserContextV2,
        client_request_nonce: Nonce32V2,
        content_kind: ContentKindV2,
        declared_total_bytes: u64,
        declared_content_digest: Option<Digest32V2>,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<IngressBeginAckV2, IngressStateOwnerErrorV2> {
        match self.request(
            IngressOwnerCommandV2::Begin {
                tab,
                browser_context,
                client_request_nonce,
                content_kind,
                declared_total_bytes,
                declared_content_digest,
                now,
            },
            deadline,
        )? {
            IngressOwnerResponseV2::Begin(value) => Ok(value),
            _ => Err(IngressStateOwnerErrorV2::Unavailable),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn append(
        &self,
        tab: IngressTabSessionCapabilityV2,
        browser_context: IngressBrowserContextV2,
        client_request_nonce: Nonce32V2,
        sequence: u32,
        chunk: Vec<u8>,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<IngressAppendAckV2, IngressStateOwnerErrorV2> {
        match self.request(
            IngressOwnerCommandV2::Append {
                tab,
                browser_context,
                client_request_nonce,
                sequence,
                chunk,
                now,
            },
            deadline,
        )? {
            IngressOwnerResponseV2::Append(value) => Ok(value),
            _ => Err(IngressStateOwnerErrorV2::Unavailable),
        }
    }

    pub fn finalize(
        &self,
        tab: IngressTabSessionCapabilityV2,
        browser_context: IngressBrowserContextV2,
        client_request_nonce: Nonce32V2,
        declared_content_digest: Digest32V2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<FinalizedIngressV2, IngressStateOwnerErrorV2> {
        match self.request(
            IngressOwnerCommandV2::Finalize {
                tab,
                browser_context,
                client_request_nonce,
                declared_content_digest,
                now,
            },
            deadline,
        )? {
            IngressOwnerResponseV2::Finalized(value) => Ok(value),
            _ => Err(IngressStateOwnerErrorV2::Unavailable),
        }
    }

    pub fn consume_for_kernel(
        &self,
        finalized: FinalizedIngressV2,
        receiver: AuthenticatedKernelIngressReceiverV2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<IngressKernelTransferV2, IngressStateOwnerErrorV2> {
        match self.request(
            IngressOwnerCommandV2::ConsumeForKernel {
                finalized,
                receiver,
                now,
            },
            deadline,
        )? {
            IngressOwnerResponseV2::Transfer(value) => Ok(value),
            _ => Err(IngressStateOwnerErrorV2::Unavailable),
        }
    }

    pub fn abort(
        &self,
        tab: IngressTabSessionCapabilityV2,
        browser_context: IngressBrowserContextV2,
        client_request_nonce: Nonce32V2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<IngressPublicStateV2, IngressStateOwnerErrorV2> {
        match self.request(
            IngressOwnerCommandV2::Abort {
                tab,
                browser_context,
                client_request_nonce,
                now,
            },
            deadline,
        )? {
            IngressOwnerResponseV2::State(value) => Ok(value),
            _ => Err(IngressStateOwnerErrorV2::Unavailable),
        }
    }

    pub fn state(
        &self,
        tab: IngressTabSessionCapabilityV2,
        browser_context: IngressBrowserContextV2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<IngressPublicStateV2, IngressStateOwnerErrorV2> {
        match self.request(
            IngressOwnerCommandV2::State {
                tab,
                browser_context,
                now,
            },
            deadline,
        )? {
            IngressOwnerResponseV2::State(value) => Ok(value),
            _ => Err(IngressStateOwnerErrorV2::Unavailable),
        }
    }

    fn request(
        &self,
        command: IngressOwnerCommandV2,
        deadline: Instant,
    ) -> Result<IngressOwnerResponseV2, IngressStateOwnerErrorV2> {
        if Instant::now() >= deadline {
            return Err(IngressStateOwnerErrorV2::DeadlineExceeded);
        }
        if self.lifecycle.load(Ordering::Acquire) != OWNER_RUNNING {
            return Err(IngressStateOwnerErrorV2::Unavailable);
        }
        let (response, received) = mpsc::sync_channel(1);
        match self.sender.try_send(IngressOwnerMessageV2::Execute {
            command: Box::new(command),
            deadline,
            response,
        }) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => return Err(IngressStateOwnerErrorV2::Busy),
            Err(TrySendError::Disconnected(_)) => {
                self.lifecycle.store(OWNER_FAILED, Ordering::Release);
                return Err(IngressStateOwnerErrorV2::Unavailable);
            }
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(IngressStateOwnerErrorV2::DeadlineExceeded);
        }
        match received.recv_timeout(remaining) {
            Ok(result) => result,
            Err(RecvTimeoutError::Timeout) => Err(IngressStateOwnerErrorV2::DeadlineExceeded),
            Err(RecvTimeoutError::Disconnected) => {
                self.lifecycle.store(OWNER_FAILED, Ordering::Release);
                Err(IngressStateOwnerErrorV2::Unavailable)
            }
        }
    }
}

impl Drop for IngressStateOwnerV2 {
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
            let _ = self.sender.send(IngressOwnerMessageV2::Shutdown);
        }
        if let Some(owner) = self.owner.take() {
            if owner.join().is_err() {
                self.lifecycle.store(OWNER_FAILED, Ordering::Release);
            }
        }
    }
}

fn owner_loop(
    receiver: Receiver<IngressOwnerMessageV2>,
    lifecycle: Arc<AtomicU8>,
    mut service: IngressServiceV2,
) {
    while let Ok(message) = receiver.recv() {
        match message {
            IngressOwnerMessageV2::Execute {
                command,
                deadline,
                response,
            } => {
                if lifecycle.load(Ordering::Acquire) != OWNER_RUNNING {
                    let _ = response.send(Err(IngressStateOwnerErrorV2::Unavailable));
                    continue;
                }
                if Instant::now() >= deadline {
                    let _ = response.send(Err(IngressStateOwnerErrorV2::DeadlineExceeded));
                    continue;
                }
                let result = catch_unwind(AssertUnwindSafe(|| dispatch(&mut service, *command)))
                    .unwrap_or(Err(IngressStateOwnerErrorV2::Unavailable));
                let fatal = result.as_ref().is_err_and(is_fatal);
                let _ = response.send(result);
                if fatal {
                    lifecycle.store(OWNER_FAILED, Ordering::Release);
                    return;
                }
            }
            IngressOwnerMessageV2::Shutdown => {
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
    service: &mut IngressServiceV2,
    command: IngressOwnerCommandV2,
) -> Result<IngressOwnerResponseV2, IngressStateOwnerErrorV2> {
    let response = match command {
        IngressOwnerCommandV2::OpenAuthenticatedTab {
            authorization,
            browser_context,
            now,
        } => IngressOwnerResponseV2::Tab(
            service
                .open_authenticated_tab(authorization, browser_context, now)
                .map_err(IngressStateOwnerErrorV2::Ingress)?,
        ),
        IngressOwnerCommandV2::Begin {
            tab,
            browser_context,
            client_request_nonce,
            content_kind,
            declared_total_bytes,
            declared_content_digest,
            now,
        } => IngressOwnerResponseV2::Begin(
            service
                .begin(
                    &tab,
                    browser_context,
                    client_request_nonce,
                    content_kind,
                    declared_total_bytes,
                    declared_content_digest,
                    now,
                )
                .map_err(IngressStateOwnerErrorV2::Ingress)?,
        ),
        IngressOwnerCommandV2::Append {
            tab,
            browser_context,
            client_request_nonce,
            sequence,
            chunk,
            now,
        } => IngressOwnerResponseV2::Append(
            service
                .append(
                    &tab,
                    browser_context,
                    client_request_nonce,
                    sequence,
                    chunk,
                    now,
                )
                .map_err(IngressStateOwnerErrorV2::Ingress)?,
        ),
        IngressOwnerCommandV2::Finalize {
            tab,
            browser_context,
            client_request_nonce,
            declared_content_digest,
            now,
        } => IngressOwnerResponseV2::Finalized(
            service
                .finalize(
                    &tab,
                    browser_context,
                    client_request_nonce,
                    declared_content_digest,
                    now,
                )
                .map_err(IngressStateOwnerErrorV2::Ingress)?,
        ),
        IngressOwnerCommandV2::ConsumeForKernel {
            finalized,
            receiver,
            now,
        } => IngressOwnerResponseV2::Transfer(
            service
                .consume_for_kernel(finalized, receiver, now)
                .map_err(IngressStateOwnerErrorV2::Ingress)?,
        ),
        IngressOwnerCommandV2::Abort {
            tab,
            browser_context,
            client_request_nonce,
            now,
        } => IngressOwnerResponseV2::State(
            service
                .abort(&tab, browser_context, client_request_nonce, now)
                .map_err(IngressStateOwnerErrorV2::Ingress)?,
        ),
        IngressOwnerCommandV2::State {
            tab,
            browser_context,
            now,
        } => IngressOwnerResponseV2::State(
            service
                .state(&tab, browser_context, now)
                .map_err(IngressStateOwnerErrorV2::Ingress)?,
        ),
    };
    Ok(response)
}

fn is_fatal(error: &IngressStateOwnerErrorV2) -> bool {
    matches!(
        error,
        IngressStateOwnerErrorV2::Unavailable
            | IngressStateOwnerErrorV2::Ingress(IngressErrorV2::ClockRollback)
    )
}
