use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Instant;

use savana_kernel_protocol::v2::{
    ApprovalDecisionV2, ApprovalPurposeV2, ApprovalSettlementViewV2,
    ClosedCredentialRevocationReasonV2, CreateEnrollmentCodeResponseV2, CredentialPublicStateV2,
    Digest32V2, EndpointRoleV2, EnrollmentHandleV2, EnrollmentProfileIdV2, Nonce32V2,
    PrincipalIdV2, ServiceIdentityV2, SignedAgentAuthenticationAttemptClosureProofV2,
    SignedAgentAuthenticationClosureDescriptorV2,
    SignedApprovalEnvelopeV2 as ProtocolSignedApprovalEnvelopeV2,
    SignedApprovalSettlementV2 as ProtocolSignedApprovalSettlementV2,
    SignedUiAuthenticationEnvelopeV2 as ProtocolSignedUiAuthenticationEnvelopeV2,
    SignedUiAuthenticationSettlementV2 as ProtocolSignedUiAuthenticationSettlementV2, UnixMillisV2,
    ZeroizingTextV2,
};

use crate::{
    ApprovalChallengeProjectionV2, ApprovalErrorV2, ApprovalRollbackAnchorV2,
    ConsumedEnrollmentCodeV2, DurableApprovalNamespaceV2, DurableProtocolApprovalServiceV2,
    ProtocolApprovalServiceV2, UiAuthenticationChallengeProjectionV2, WebAuthnAssertionV2,
};

const OWNER_RUNNING: u8 = 1;
const OWNER_CLOSING: u8 = 2;
const OWNER_FAILED: u8 = 3;
const OWNER_STOPPED: u8 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ProtocolApprovalStateOwnerErrorV2 {
    #[error("protocol approval state owner is busy")]
    Busy,
    #[error("protocol approval state owner deadline was exceeded")]
    DeadlineExceeded,
    #[error("protocol approval state owner is unavailable")]
    Unavailable,
    #[error("protocol approval operation failed")]
    Approval(ApprovalErrorV2),
}

enum CommandV2 {
    RegisterPasskey {
        enrollment: EnrollmentHandleV2,
        credential_digest: Digest32V2,
        verified: crate::VerifiedPasskeyRegistrationV04,
    },
    PrivateSessionV04 {
        digest: Digest32V2,
        now: UnixMillisV2,
    },
    LoadCredential {
        credential_digest: Digest32V2,
        principal: PrincipalIdV2,
        aaguid: [u8; 16],
        p256_sec1_public_key: [u8; 65],
        signature_counter: u32,
    },
    RegisterApproval {
        envelope: ProtocolSignedApprovalEnvelopeV2,
        now: UnixMillisV2,
    },
    RegisterApprovalPair {
        role: EndpointRoleV2,
        envelope: ProtocolSignedApprovalEnvelopeV2,
        display_authentication: ProtocolSignedUiAuthenticationEnvelopeV2,
        now: UnixMillisV2,
    },
    SettleApproval {
        envelope_digest: Digest32V2,
        decision: ApprovalDecisionV2,
        assertion: WebAuthnAssertionV2,
        now: UnixMillisV2,
    },
    InspectApproval {
        envelope_digest: Digest32V2,
        now: UnixMillisV2,
    },
    QueryApproval {
        envelope_digest: Digest32V2,
        now: UnixMillisV2,
    },
    RegisterUi {
        envelope: ProtocolSignedUiAuthenticationEnvelopeV2,
        now: UnixMillisV2,
    },
    SettleUi {
        envelope_digest: Digest32V2,
        assertion: WebAuthnAssertionV2,
        now: UnixMillisV2,
    },
    InspectUi {
        envelope_digest: Digest32V2,
        now: UnixMillisV2,
    },
    CloseAgentAuthenticationAttempt {
        descriptor: Box<SignedAgentAuthenticationClosureDescriptorV2>,
        caller_identity: ServiceIdentityV2,
        now: UnixMillisV2,
    },
    CreateEnrollmentCode {
        profile: EnrollmentProfileIdV2,
        client_request_nonce: Nonce32V2,
        now: UnixMillisV2,
    },
    ConsumeEnrollmentCode {
        handle: EnrollmentHandleV2,
        code: ZeroizingTextV2,
        now: UnixMillisV2,
    },
    RegisterEnrolledCredential {
        enrollment: EnrollmentHandleV2,
        credential_digest: Digest32V2,
        aaguid: [u8; 16],
        p256_sec1_public_key: [u8; 65],
        signature_counter: u32,
    },
    RevokeCredential {
        credential_digest: Digest32V2,
        reason: ClosedCredentialRevocationReasonV2,
    },
}

enum ResponseV2 {
    PrivateSessionV04(Option<ProtocolSignedUiAuthenticationSettlementV2>),
    Digest(Digest32V2),
    ApprovalPair(Digest32V2, Digest32V2, ApprovalPurposeV2),
    ApprovalSettlement(ProtocolSignedApprovalSettlementV2),
    ApprovalChallenge(ApprovalChallengeProjectionV2),
    ApprovalView(ApprovalSettlementViewV2),
    UiSettlement(ProtocolSignedUiAuthenticationSettlementV2),
    UiChallenge(UiAuthenticationChallengeProjectionV2),
    AgentAuthenticationClosureProof(Box<SignedAgentAuthenticationAttemptClosureProofV2>),
    EnrollmentCode(CreateEnrollmentCodeResponseV2),
    ConsumedEnrollment(ConsumedEnrollmentCodeV2),
    CredentialState(CredentialPublicStateV2),
    Unit,
}

enum MessageV2 {
    Execute {
        command: Box<CommandV2>,
        deadline: Instant,
        response: SyncSender<Result<ResponseV2, ProtocolApprovalStateOwnerErrorV2>>,
    },
    Shutdown,
}

/// Bounded single-thread owner for the rollback-protected protocol-native
/// approval service.
pub struct ProtocolApprovalStateOwnerV2 {
    sender: SyncSender<MessageV2>,
    lifecycle: Arc<AtomicU8>,
    owner: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for ProtocolApprovalStateOwnerV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProtocolApprovalStateOwnerV2")
            .field("lifecycle", &self.lifecycle.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

impl ProtocolApprovalStateOwnerV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn open(
        state_path: &Path,
        master_encryption_key: [u8; 32],
        namespace: DurableApprovalNamespaceV2,
        rollback_anchor: Box<dyn ApprovalRollbackAnchorV2>,
        deployment: ProtocolApprovalServiceV2,
        capacity: usize,
    ) -> Result<Self, ProtocolApprovalStateOwnerErrorV2> {
        if capacity == 0 {
            return Err(ProtocolApprovalStateOwnerErrorV2::Unavailable);
        }
        let durable = DurableProtocolApprovalServiceV2::open(
            state_path,
            master_encryption_key,
            namespace,
            rollback_anchor,
            deployment,
        )
        .map_err(ProtocolApprovalStateOwnerErrorV2::Approval)?;
        let (sender, receiver) = mpsc::sync_channel(capacity);
        let lifecycle = Arc::new(AtomicU8::new(OWNER_RUNNING));
        let owner_lifecycle = Arc::clone(&lifecycle);
        let owner = thread::Builder::new()
            .name("savana-approvald-protocol-state-v2".to_owned())
            .spawn(move || owner_loop(receiver, owner_lifecycle, durable))
            .map_err(|_| ProtocolApprovalStateOwnerErrorV2::Unavailable)?;
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
    ) -> Result<(), ProtocolApprovalStateOwnerErrorV2> {
        match self.request(
            CommandV2::LoadCredential {
                credential_digest,
                principal,
                aaguid,
                p256_sec1_public_key,
                signature_counter,
            },
            deadline,
        )? {
            ResponseV2::Unit => Ok(()),
            _ => Err(ProtocolApprovalStateOwnerErrorV2::Unavailable),
        }
    }

    pub fn register_approval_envelope(
        &self,
        envelope: ProtocolSignedApprovalEnvelopeV2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<Digest32V2, ProtocolApprovalStateOwnerErrorV2> {
        match self.request(CommandV2::RegisterApproval { envelope, now }, deadline)? {
            ResponseV2::Digest(digest) => Ok(digest),
            _ => Err(ProtocolApprovalStateOwnerErrorV2::Unavailable),
        }
    }

    pub fn register_approval_pair(
        &self,
        role: EndpointRoleV2,
        envelope: ProtocolSignedApprovalEnvelopeV2,
        display_authentication: ProtocolSignedUiAuthenticationEnvelopeV2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<(Digest32V2, Digest32V2, ApprovalPurposeV2), ProtocolApprovalStateOwnerErrorV2>
    {
        match self.request(
            CommandV2::RegisterApprovalPair {
                role,
                envelope,
                display_authentication,
                now,
            },
            deadline,
        )? {
            ResponseV2::ApprovalPair(approval, display, purpose) => {
                Ok((approval, display, purpose))
            }
            _ => Err(ProtocolApprovalStateOwnerErrorV2::Unavailable),
        }
    }

    pub fn settle_approval(
        &self,
        envelope_digest: Digest32V2,
        decision: ApprovalDecisionV2,
        assertion: WebAuthnAssertionV2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<ProtocolSignedApprovalSettlementV2, ProtocolApprovalStateOwnerErrorV2> {
        match self.request(
            CommandV2::SettleApproval {
                envelope_digest,
                decision,
                assertion,
                now,
            },
            deadline,
        )? {
            ResponseV2::ApprovalSettlement(settlement) => Ok(settlement),
            _ => Err(ProtocolApprovalStateOwnerErrorV2::Unavailable),
        }
    }

    pub fn approval_challenge(
        &self,
        envelope_digest: Digest32V2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<ApprovalChallengeProjectionV2, ProtocolApprovalStateOwnerErrorV2> {
        match self.request(
            CommandV2::InspectApproval {
                envelope_digest,
                now,
            },
            deadline,
        )? {
            ResponseV2::ApprovalChallenge(challenge) => Ok(challenge),
            _ => Err(ProtocolApprovalStateOwnerErrorV2::Unavailable),
        }
    }

    pub fn approval_settlement_view(
        &self,
        envelope_digest: Digest32V2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<ApprovalSettlementViewV2, ProtocolApprovalStateOwnerErrorV2> {
        match self.request(
            CommandV2::QueryApproval {
                envelope_digest,
                now,
            },
            deadline,
        )? {
            ResponseV2::ApprovalView(view) => Ok(view),
            _ => Err(ProtocolApprovalStateOwnerErrorV2::Unavailable),
        }
    }

    pub fn register_ui_authentication_envelope(
        &self,
        envelope: ProtocolSignedUiAuthenticationEnvelopeV2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<Digest32V2, ProtocolApprovalStateOwnerErrorV2> {
        match self.request(CommandV2::RegisterUi { envelope, now }, deadline)? {
            ResponseV2::Digest(digest) => Ok(digest),
            _ => Err(ProtocolApprovalStateOwnerErrorV2::Unavailable),
        }
    }

    pub fn settle_ui_authentication(
        &self,
        envelope_digest: Digest32V2,
        assertion: WebAuthnAssertionV2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<ProtocolSignedUiAuthenticationSettlementV2, ProtocolApprovalStateOwnerErrorV2> {
        match self.request(
            CommandV2::SettleUi {
                envelope_digest,
                assertion,
                now,
            },
            deadline,
        )? {
            ResponseV2::UiSettlement(settlement) => Ok(settlement),
            _ => Err(ProtocolApprovalStateOwnerErrorV2::Unavailable),
        }
    }

    pub fn private_session_authentication_v04(
        &self,
        digest: Digest32V2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<Option<ProtocolSignedUiAuthenticationSettlementV2>, ProtocolApprovalStateOwnerErrorV2>
    {
        match self.request(CommandV2::PrivateSessionV04 { digest, now }, deadline)? {
            ResponseV2::PrivateSessionV04(s) => Ok(s),
            _ => Err(ProtocolApprovalStateOwnerErrorV2::Unavailable),
        }
    }

    pub fn ui_authentication_challenge(
        &self,
        envelope_digest: Digest32V2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<UiAuthenticationChallengeProjectionV2, ProtocolApprovalStateOwnerErrorV2> {
        match self.request(
            CommandV2::InspectUi {
                envelope_digest,
                now,
            },
            deadline,
        )? {
            ResponseV2::UiChallenge(challenge) => Ok(challenge),
            _ => Err(ProtocolApprovalStateOwnerErrorV2::Unavailable),
        }
    }

    pub fn close_agent_authentication_attempt(
        &self,
        descriptor: SignedAgentAuthenticationClosureDescriptorV2,
        caller_identity: ServiceIdentityV2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<SignedAgentAuthenticationAttemptClosureProofV2, ProtocolApprovalStateOwnerErrorV2>
    {
        match self.request(
            CommandV2::CloseAgentAuthenticationAttempt {
                descriptor: Box::new(descriptor),
                caller_identity,
                now,
            },
            deadline,
        )? {
            ResponseV2::AgentAuthenticationClosureProof(proof) => Ok(*proof),
            _ => Err(ProtocolApprovalStateOwnerErrorV2::Unavailable),
        }
    }

    pub fn create_enrollment_code(
        &self,
        profile: EnrollmentProfileIdV2,
        client_request_nonce: Nonce32V2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<CreateEnrollmentCodeResponseV2, ProtocolApprovalStateOwnerErrorV2> {
        match self.request(
            CommandV2::CreateEnrollmentCode {
                profile,
                client_request_nonce,
                now,
            },
            deadline,
        )? {
            ResponseV2::EnrollmentCode(response) => Ok(response),
            _ => Err(ProtocolApprovalStateOwnerErrorV2::Unavailable),
        }
    }

    pub fn consume_enrollment_code(
        &self,
        handle: EnrollmentHandleV2,
        code: ZeroizingTextV2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<ConsumedEnrollmentCodeV2, ProtocolApprovalStateOwnerErrorV2> {
        match self.request(
            CommandV2::ConsumeEnrollmentCode { handle, code, now },
            deadline,
        )? {
            ResponseV2::ConsumedEnrollment(response) => Ok(response),
            _ => Err(ProtocolApprovalStateOwnerErrorV2::Unavailable),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn register_enrolled_hardware_credential(
        &self,
        enrollment: EnrollmentHandleV2,
        credential_digest: Digest32V2,
        aaguid: [u8; 16],
        p256_sec1_public_key: [u8; 65],
        signature_counter: u32,
        deadline: Instant,
    ) -> Result<CredentialPublicStateV2, ProtocolApprovalStateOwnerErrorV2> {
        match self.request(
            CommandV2::RegisterEnrolledCredential {
                enrollment,
                credential_digest,
                aaguid,
                p256_sec1_public_key,
                signature_counter,
            },
            deadline,
        )? {
            ResponseV2::CredentialState(state) => Ok(state),
            _ => Err(ProtocolApprovalStateOwnerErrorV2::Unavailable),
        }
    }

    pub fn register_enrolled_passkey(
        &self,
        enrollment: EnrollmentHandleV2,
        credential_digest: Digest32V2,
        verified: crate::VerifiedPasskeyRegistrationV04,
        deadline: Instant,
    ) -> Result<CredentialPublicStateV2, ProtocolApprovalStateOwnerErrorV2> {
        match self.request(
            CommandV2::RegisterPasskey {
                enrollment,
                credential_digest,
                verified,
            },
            deadline,
        )? {
            ResponseV2::CredentialState(state) => Ok(state),
            _ => Err(ProtocolApprovalStateOwnerErrorV2::Unavailable),
        }
    }

    pub fn revoke_credential(
        &self,
        credential_digest: Digest32V2,
        reason: ClosedCredentialRevocationReasonV2,
        deadline: Instant,
    ) -> Result<CredentialPublicStateV2, ProtocolApprovalStateOwnerErrorV2> {
        match self.request(
            CommandV2::RevokeCredential {
                credential_digest,
                reason,
            },
            deadline,
        )? {
            ResponseV2::CredentialState(state) => Ok(state),
            _ => Err(ProtocolApprovalStateOwnerErrorV2::Unavailable),
        }
    }

    fn request(
        &self,
        command: CommandV2,
        deadline: Instant,
    ) -> Result<ResponseV2, ProtocolApprovalStateOwnerErrorV2> {
        if Instant::now() >= deadline {
            return Err(ProtocolApprovalStateOwnerErrorV2::DeadlineExceeded);
        }
        if self.lifecycle.load(Ordering::Acquire) != OWNER_RUNNING {
            return Err(ProtocolApprovalStateOwnerErrorV2::Unavailable);
        }
        let (response, received) = mpsc::sync_channel(1);
        match self.sender.try_send(MessageV2::Execute {
            command: Box::new(command),
            deadline,
            response,
        }) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => return Err(ProtocolApprovalStateOwnerErrorV2::Busy),
            Err(TrySendError::Disconnected(_)) => {
                self.lifecycle.store(OWNER_FAILED, Ordering::Release);
                return Err(ProtocolApprovalStateOwnerErrorV2::Unavailable);
            }
        }
        let wait = deadline.saturating_duration_since(Instant::now());
        match received.recv_timeout(wait) {
            Ok(result) => result,
            Err(RecvTimeoutError::Timeout) => {
                Err(ProtocolApprovalStateOwnerErrorV2::DeadlineExceeded)
            }
            Err(RecvTimeoutError::Disconnected) => {
                self.lifecycle.store(OWNER_FAILED, Ordering::Release);
                Err(ProtocolApprovalStateOwnerErrorV2::Unavailable)
            }
        }
    }
}

impl Drop for ProtocolApprovalStateOwnerV2 {
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
            let _ = self.sender.send(MessageV2::Shutdown);
        }
        if let Some(owner) = self.owner.take() {
            let _ = owner.join();
        }
    }
}

fn owner_loop(
    receiver: Receiver<MessageV2>,
    lifecycle: Arc<AtomicU8>,
    mut durable: DurableProtocolApprovalServiceV2,
) {
    while let Ok(message) = receiver.recv() {
        match message {
            MessageV2::Shutdown => break,
            MessageV2::Execute {
                command,
                deadline,
                response,
            } => {
                let result = if Instant::now() >= deadline {
                    Err(ProtocolApprovalStateOwnerErrorV2::DeadlineExceeded)
                } else {
                    catch_unwind(AssertUnwindSafe(|| execute(&mut durable, *command)))
                        .unwrap_or(Err(ProtocolApprovalStateOwnerErrorV2::Unavailable))
                };
                let failed = matches!(result, Err(ProtocolApprovalStateOwnerErrorV2::Unavailable));
                let _ = response.send(result);
                if failed {
                    lifecycle.store(OWNER_FAILED, Ordering::Release);
                    return;
                }
            }
        }
    }
    lifecycle.store(OWNER_STOPPED, Ordering::Release);
}

fn execute(
    durable: &mut DurableProtocolApprovalServiceV2,
    command: CommandV2,
) -> Result<ResponseV2, ProtocolApprovalStateOwnerErrorV2> {
    let response = match command {
        CommandV2::PrivateSessionV04 { digest, now } => {
            ResponseV2::PrivateSessionV04(durable.private_session_authentication_v04(digest, now)?)
        }
        CommandV2::LoadCredential {
            credential_digest,
            principal,
            aaguid,
            p256_sec1_public_key,
            signature_counter,
        } => {
            durable.load_verified_hardware_credential(
                credential_digest,
                principal,
                aaguid,
                p256_sec1_public_key,
                signature_counter,
            )?;
            ResponseV2::Unit
        }
        CommandV2::RegisterApproval { envelope, now } => {
            ResponseV2::Digest(durable.register_approval_envelope(&envelope, now)?)
        }
        CommandV2::RegisterApprovalPair {
            role,
            envelope,
            display_authentication,
            now,
        } => {
            let (approval, display, purpose) =
                durable.register_approval_pair(role, &envelope, &display_authentication, now)?;
            ResponseV2::ApprovalPair(approval, display, purpose)
        }
        CommandV2::SettleApproval {
            envelope_digest,
            decision,
            assertion,
            now,
        } => ResponseV2::ApprovalSettlement(durable.settle_approval(
            envelope_digest,
            decision,
            &assertion,
            now,
        )?),
        CommandV2::InspectApproval {
            envelope_digest,
            now,
        } => ResponseV2::ApprovalChallenge(durable.approval_challenge(envelope_digest, now)?),
        CommandV2::QueryApproval {
            envelope_digest,
            now,
        } => ResponseV2::ApprovalView(durable.approval_settlement_view(envelope_digest, now)?),
        CommandV2::RegisterUi { envelope, now } => {
            ResponseV2::Digest(durable.register_ui_authentication_envelope(&envelope, now)?)
        }
        CommandV2::SettleUi {
            envelope_digest,
            assertion,
            now,
        } => ResponseV2::UiSettlement(durable.settle_ui_authentication(
            envelope_digest,
            &assertion,
            now,
        )?),
        CommandV2::InspectUi {
            envelope_digest,
            now,
        } => ResponseV2::UiChallenge(durable.ui_authentication_challenge(envelope_digest, now)?),
        CommandV2::CloseAgentAuthenticationAttempt {
            descriptor,
            caller_identity,
            now,
        } => ResponseV2::AgentAuthenticationClosureProof(Box::new(
            durable.close_agent_authentication_attempt(&descriptor, caller_identity, now)?,
        )),
        CommandV2::CreateEnrollmentCode {
            profile,
            client_request_nonce,
            now,
        } => ResponseV2::EnrollmentCode(durable.create_enrollment_code(
            profile,
            client_request_nonce,
            now,
        )?),
        CommandV2::ConsumeEnrollmentCode { handle, code, now } => {
            ResponseV2::ConsumedEnrollment(durable.consume_enrollment_code(handle, &code, now)?)
        }
        CommandV2::RegisterEnrolledCredential {
            enrollment,
            credential_digest,
            aaguid,
            p256_sec1_public_key,
            signature_counter,
        } => ResponseV2::CredentialState(durable.register_enrolled_hardware_credential(
            enrollment,
            credential_digest,
            aaguid,
            p256_sec1_public_key,
            signature_counter,
        )?),
        CommandV2::RegisterPasskey {
            enrollment,
            credential_digest,
            verified,
        } => ResponseV2::CredentialState(durable.register_enrolled_passkey(
            enrollment,
            credential_digest,
            verified,
        )?),
        CommandV2::RevokeCredential {
            credential_digest,
            reason,
        } => ResponseV2::CredentialState(durable.revoke_credential(credential_digest, reason)?),
    };
    Ok(response)
}

impl From<ApprovalErrorV2> for ProtocolApprovalStateOwnerErrorV2 {
    fn from(error: ApprovalErrorV2) -> Self {
        Self::Approval(error)
    }
}
