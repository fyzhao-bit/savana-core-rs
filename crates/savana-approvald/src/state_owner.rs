use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Instant;

use savana_kernel_protocol::v2::{Digest32V2, PrincipalIdV2, UnixMillisV2};

use crate::{
    ApprovalDecisionV2, ApprovalErrorV2, ApprovalRollbackAnchorV2, ApprovalServiceV2,
    ConsumedApprovalSettlementV2, DurableApprovalNamespaceV2, DurableApprovalServiceV2,
    SignedApprovalEnvelopeV2, SignedApprovalSettlementV2, WebAuthnAssertionV2,
};

const OWNER_RUNNING: u8 = 1;
const OWNER_CLOSING: u8 = 2;
const OWNER_FAILED: u8 = 3;
const OWNER_STOPPED: u8 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ApprovalStateOwnerErrorV2 {
    #[error("approval state owner is busy")]
    Busy,
    #[error("approval state owner deadline was exceeded")]
    DeadlineExceeded,
    #[error("approval state owner is unavailable")]
    Unavailable,
    #[error("approval operation failed")]
    Approval(ApprovalErrorV2),
}

enum ApprovalOwnerCommandV2 {
    LoadCredential {
        credential_digest: Digest32V2,
        principal: PrincipalIdV2,
        aaguid: [u8; 16],
        p256_sec1_public_key: [u8; 65],
        signature_counter: u32,
    },
    RegisterEnvelope {
        envelope: SignedApprovalEnvelopeV2,
        now: UnixMillisV2,
    },
    Settle {
        envelope_digest: Digest32V2,
        decision: ApprovalDecisionV2,
        assertion: WebAuthnAssertionV2,
        now: UnixMillisV2,
    },
    ConsumeSettlement {
        envelope_digest: Digest32V2,
        settlement_digest: Digest32V2,
        now: UnixMillisV2,
    },
}

enum ApprovalOwnerResponseV2 {
    Digest(Digest32V2),
    Settlement(SignedApprovalSettlementV2),
    Consumed(ConsumedApprovalSettlementV2),
    Unit,
}

enum ApprovalOwnerMessageV2 {
    Execute {
        command: Box<ApprovalOwnerCommandV2>,
        deadline: Instant,
        response: SyncSender<Result<ApprovalOwnerResponseV2, ApprovalStateOwnerErrorV2>>,
    },
    Shutdown,
}

/// Bounded, single-thread owner for approval credentials and durable settlements.
pub struct ApprovalStateOwnerV2 {
    sender: SyncSender<ApprovalOwnerMessageV2>,
    lifecycle: Arc<AtomicU8>,
    owner: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for ApprovalStateOwnerV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ApprovalStateOwnerV2")
            .field("lifecycle", &self.lifecycle.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

impl ApprovalStateOwnerV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn open(
        state_path: &Path,
        master_encryption_key: [u8; 32],
        namespace: DurableApprovalNamespaceV2,
        rollback_anchor: Box<dyn ApprovalRollbackAnchorV2>,
        deployment: ApprovalServiceV2,
        capacity: usize,
    ) -> Result<Self, ApprovalStateOwnerErrorV2> {
        if capacity == 0 {
            return Err(ApprovalStateOwnerErrorV2::Unavailable);
        }
        let durable = DurableApprovalServiceV2::open(
            state_path,
            master_encryption_key,
            namespace,
            rollback_anchor,
            deployment,
        )
        .map_err(ApprovalStateOwnerErrorV2::Approval)?;
        let (sender, receiver) = mpsc::sync_channel(capacity);
        let lifecycle = Arc::new(AtomicU8::new(OWNER_RUNNING));
        let owner_lifecycle = Arc::clone(&lifecycle);
        let owner = thread::Builder::new()
            .name("savana-approvald-state-v2".to_owned())
            .spawn(move || owner_loop(receiver, owner_lifecycle, durable))
            .map_err(|_| ApprovalStateOwnerErrorV2::Unavailable)?;
        Ok(Self {
            sender,
            lifecycle,
            owner: Some(owner),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn load_verified_hardware_credential(
        &self,
        credential_digest: Digest32V2,
        principal: PrincipalIdV2,
        aaguid: [u8; 16],
        p256_sec1_public_key: [u8; 65],
        signature_counter: u32,
        deadline: Instant,
    ) -> Result<(), ApprovalStateOwnerErrorV2> {
        match self.request(
            ApprovalOwnerCommandV2::LoadCredential {
                credential_digest,
                principal,
                aaguid,
                p256_sec1_public_key,
                signature_counter,
            },
            deadline,
        )? {
            ApprovalOwnerResponseV2::Unit => Ok(()),
            _ => Err(ApprovalStateOwnerErrorV2::Unavailable),
        }
    }

    pub fn register_envelope(
        &self,
        envelope: SignedApprovalEnvelopeV2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<Digest32V2, ApprovalStateOwnerErrorV2> {
        match self.request(
            ApprovalOwnerCommandV2::RegisterEnvelope { envelope, now },
            deadline,
        )? {
            ApprovalOwnerResponseV2::Digest(value) => Ok(value),
            _ => Err(ApprovalStateOwnerErrorV2::Unavailable),
        }
    }

    pub fn settle(
        &self,
        envelope_digest: Digest32V2,
        decision: ApprovalDecisionV2,
        assertion: WebAuthnAssertionV2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<SignedApprovalSettlementV2, ApprovalStateOwnerErrorV2> {
        match self.request(
            ApprovalOwnerCommandV2::Settle {
                envelope_digest,
                decision,
                assertion,
                now,
            },
            deadline,
        )? {
            ApprovalOwnerResponseV2::Settlement(value) => Ok(value),
            _ => Err(ApprovalStateOwnerErrorV2::Unavailable),
        }
    }

    pub fn consume_settlement(
        &self,
        envelope_digest: Digest32V2,
        settlement_digest: Digest32V2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<ConsumedApprovalSettlementV2, ApprovalStateOwnerErrorV2> {
        match self.request(
            ApprovalOwnerCommandV2::ConsumeSettlement {
                envelope_digest,
                settlement_digest,
                now,
            },
            deadline,
        )? {
            ApprovalOwnerResponseV2::Consumed(value) => Ok(value),
            _ => Err(ApprovalStateOwnerErrorV2::Unavailable),
        }
    }

    fn request(
        &self,
        command: ApprovalOwnerCommandV2,
        deadline: Instant,
    ) -> Result<ApprovalOwnerResponseV2, ApprovalStateOwnerErrorV2> {
        if Instant::now() >= deadline {
            return Err(ApprovalStateOwnerErrorV2::DeadlineExceeded);
        }
        if self.lifecycle.load(Ordering::Acquire) != OWNER_RUNNING {
            return Err(ApprovalStateOwnerErrorV2::Unavailable);
        }
        let (response, received) = mpsc::sync_channel(1);
        match self.sender.try_send(ApprovalOwnerMessageV2::Execute {
            command: Box::new(command),
            deadline,
            response,
        }) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => return Err(ApprovalStateOwnerErrorV2::Busy),
            Err(TrySendError::Disconnected(_)) => {
                self.lifecycle.store(OWNER_FAILED, Ordering::Release);
                return Err(ApprovalStateOwnerErrorV2::Unavailable);
            }
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(ApprovalStateOwnerErrorV2::DeadlineExceeded);
        }
        match received.recv_timeout(remaining) {
            Ok(result) => result,
            Err(RecvTimeoutError::Timeout) => Err(ApprovalStateOwnerErrorV2::DeadlineExceeded),
            Err(RecvTimeoutError::Disconnected) => {
                self.lifecycle.store(OWNER_FAILED, Ordering::Release);
                Err(ApprovalStateOwnerErrorV2::Unavailable)
            }
        }
    }
}

impl Drop for ApprovalStateOwnerV2 {
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
            let _ = self.sender.send(ApprovalOwnerMessageV2::Shutdown);
        }
        if let Some(owner) = self.owner.take() {
            if owner.join().is_err() {
                self.lifecycle.store(OWNER_FAILED, Ordering::Release);
            }
        }
    }
}

fn owner_loop(
    receiver: Receiver<ApprovalOwnerMessageV2>,
    lifecycle: Arc<AtomicU8>,
    mut durable: DurableApprovalServiceV2,
) {
    while let Ok(message) = receiver.recv() {
        match message {
            ApprovalOwnerMessageV2::Execute {
                command,
                deadline,
                response,
            } => {
                if lifecycle.load(Ordering::Acquire) != OWNER_RUNNING {
                    let _ = response.send(Err(ApprovalStateOwnerErrorV2::Unavailable));
                    continue;
                }
                if Instant::now() >= deadline {
                    let _ = response.send(Err(ApprovalStateOwnerErrorV2::DeadlineExceeded));
                    continue;
                }
                let result = catch_unwind(AssertUnwindSafe(|| dispatch(&mut durable, *command)))
                    .unwrap_or(Err(ApprovalStateOwnerErrorV2::Unavailable));
                let fatal = result.as_ref().is_err_and(is_fatal);
                let _ = response.send(result);
                if fatal {
                    lifecycle.store(OWNER_FAILED, Ordering::Release);
                    return;
                }
            }
            ApprovalOwnerMessageV2::Shutdown => {
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
    durable: &mut DurableApprovalServiceV2,
    command: ApprovalOwnerCommandV2,
) -> Result<ApprovalOwnerResponseV2, ApprovalStateOwnerErrorV2> {
    let response = match command {
        ApprovalOwnerCommandV2::LoadCredential {
            credential_digest,
            principal,
            aaguid,
            p256_sec1_public_key,
            signature_counter,
        } => {
            durable
                .load_verified_hardware_credential(
                    credential_digest,
                    principal,
                    aaguid,
                    p256_sec1_public_key,
                    signature_counter,
                )
                .map_err(ApprovalStateOwnerErrorV2::Approval)?;
            ApprovalOwnerResponseV2::Unit
        }
        ApprovalOwnerCommandV2::RegisterEnvelope { envelope, now } => {
            ApprovalOwnerResponseV2::Digest(
                durable
                    .register_envelope(&envelope, now)
                    .map_err(ApprovalStateOwnerErrorV2::Approval)?,
            )
        }
        ApprovalOwnerCommandV2::Settle {
            envelope_digest,
            decision,
            assertion,
            now,
        } => ApprovalOwnerResponseV2::Settlement(
            durable
                .settle(envelope_digest, decision, &assertion, now)
                .map_err(ApprovalStateOwnerErrorV2::Approval)?,
        ),
        ApprovalOwnerCommandV2::ConsumeSettlement {
            envelope_digest,
            settlement_digest,
            now,
        } => ApprovalOwnerResponseV2::Consumed(
            durable
                .consume_settlement(envelope_digest, settlement_digest, now)
                .map_err(ApprovalStateOwnerErrorV2::Approval)?,
        ),
    };
    Ok(response)
}

fn is_fatal(error: &ApprovalStateOwnerErrorV2) -> bool {
    matches!(
        error,
        ApprovalStateOwnerErrorV2::Unavailable
            | ApprovalStateOwnerErrorV2::Approval(
                ApprovalErrorV2::DurableState
                    | ApprovalErrorV2::DurableAuthentication
                    | ApprovalErrorV2::RollbackDetected
                    | ApprovalErrorV2::CommitUncertain
            )
    )
}
