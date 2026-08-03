use std::io::{Read as _, Write as _};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(all(feature = "test-support", debug_assertions))]
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use savana_kernel_protocol::v2::{
    decode_approval_health_response_v2, decode_approval_settlement_view_v2,
    decode_consumed_ui_authentication_settlement_v2, decode_create_enrollment_code_response_v2,
    decode_kernel_service_application_response_v2, decode_registered_approval_v2,
    decode_registered_ui_authentication_v2, decode_revoke_credential_response_v2,
    decode_signed_agent_authentication_attempt_closure_proof_v2,
    encode_approval_service_request_v2, AgentApprovalRecordTargetV2,
    AgentUiAuthenticationSettlementTransferCapabilityV2, ApprovalHealthResponseV2,
    ApprovalServiceOperationV2, ApprovalServiceRequestV2, ApprovalSettlementViewV2,
    ApprovalUiRecordHandleV2, BootIdV2, ClosedCredentialRevocationReasonV2,
    ConsumedUiAuthenticationSettlementV2, CreateEnrollmentCodeResponseV2, CredentialPublicStateV2,
    Digest32V2, EndpointRoleV2, EnrollmentProfileIdV2, IngressApprovalRecordHandleV2,
    IngressUiAuthenticationSettlementTransferCapabilityV2, KernelServiceApplicationResponseBodyV2,
    KernelServiceHandshakeEdgeV2, Nonce32V2, PeerIdentityBindingV2, PublicStableCodeV2,
    RegisteredApprovalV2, RegisteredUiAuthenticationV2, RequestIdV2,
    SignedAgentAuthenticationAttemptClosureProofV2, SignedAgentAuthenticationClosureDescriptorV2,
    SignedApprovalEnvelopeV2, SignedUiAuthenticationEnvelopeV2, UnixMillisV2, V2ClientHandshake,
    HANDSHAKE_FRAME_HEADER_BYTES_V2, MAX_HANDSHAKE_BODY_BYTES_V2, MAX_RECORD_CIPHERTEXT_BYTES_V2,
    MAX_RECORD_HEADER_BYTES_V2, RECORD_FRAME_HEADER_BYTES_V2,
};
use sha2::{Digest as _, Sha256};
use x25519_dalek::StaticSecret;

const AGENT_APPROVAL_SOCKET_PATH_V2: &str = "/run/savana/approvald/agentd/approvald.sock";
const INGRESS_APPROVAL_SOCKET_PATH_V2: &str = "/run/savana/approvald/ingressd/approvald.sock";
const ADMIN_APPROVAL_SOCKET_PATH_V2: &str = "/run/savana/approvald/admin/approvald.sock";
const HANDSHAKE_MAGIC_V2: &[u8; 8] = b"SAVANA2\0";
const RECORD_MAGIC_V2: &[u8; 4] = b"SV2R";
const MAX_CONNECTION_DURATION_V2: Duration = Duration::from_secs(5);
const REQUEST_ID_DOMAIN_V2: &[u8] = b"SAVANA_APPROVAL_CLIENT_REQUEST_ID_V2\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ApprovalSuiteOneClientErrorV2 {
    #[error("approval request deadline was exceeded")]
    DeadlineExceeded,
    #[error("approval request was rejected")]
    Rejected(PublicStableCodeV2),
    #[error("approval service is unavailable")]
    Unavailable,
}

pub struct ApprovalSuiteOneClientV2 {
    edge: KernelServiceHandshakeEdgeV2,
    client_boot_id: BootIdV2,
    expected_observed_peer: PeerIdentityBindingV2,
    client_signing_key: SigningKey,
    server_public_key: [u8; 32],
    socket_path: PathBuf,
    #[cfg(all(feature = "test-support", debug_assertions))]
    operation_exchange_for_test: Option<Arc<TestApprovalOperationExchangeV2>>,
}

#[cfg(all(feature = "test-support", debug_assertions))]
type TestApprovalOperationExchangeV2 = dyn Fn(UnixMillisV2, ApprovalServiceOperationV2) -> Result<Vec<u8>, ApprovalSuiteOneClientErrorV2>
    + Send
    + Sync;

impl core::fmt::Debug for ApprovalSuiteOneClientV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ApprovalSuiteOneClientV2(<deployment-bound-keys-redacted>)")
    }
}

impl ApprovalSuiteOneClientV2 {
    pub fn from_verified_deployment(
        edge: KernelServiceHandshakeEdgeV2,
        client_boot_id: BootIdV2,
        expected_observed_peer: PeerIdentityBindingV2,
        client_signing_key: SigningKey,
        server_public_key: [u8; 32],
    ) -> Result<Self, ApprovalSuiteOneClientErrorV2> {
        let socket_path = match edge.role() {
            EndpointRoleV2::AgentApproval => AGENT_APPROVAL_SOCKET_PATH_V2,
            EndpointRoleV2::IngressApproval => INGRESS_APPROVAL_SOCKET_PATH_V2,
            EndpointRoleV2::ApprovalAdmin => ADMIN_APPROVAL_SOCKET_PATH_V2,
            _ => return Err(ApprovalSuiteOneClientErrorV2::Unavailable),
        };
        if client_boot_id.as_bytes() == &[0; 32] || server_public_key == [0; 32] {
            return Err(ApprovalSuiteOneClientErrorV2::Unavailable);
        }
        Ok(Self {
            edge,
            client_boot_id,
            expected_observed_peer,
            client_signing_key,
            server_public_key,
            socket_path: PathBuf::from(socket_path),
            #[cfg(all(feature = "test-support", debug_assertions))]
            operation_exchange_for_test: None,
        })
    }

    /// Installs a typed in-process operation exchange for debug-only product-path tests.
    ///
    /// The override sits below the public methods' response decoders, so tests still
    /// exercise canonical response validation. It cannot be compiled into release builds.
    #[cfg(all(feature = "test-support", debug_assertions))]
    #[doc(hidden)]
    pub fn with_operation_exchange_for_test_support<F>(mut self, exchange: F) -> Self
    where
        F: Fn(
                UnixMillisV2,
                ApprovalServiceOperationV2,
            ) -> Result<Vec<u8>, ApprovalSuiteOneClientErrorV2>
            + Send
            + Sync
            + 'static,
    {
        self.operation_exchange_for_test = Some(Arc::new(exchange));
        self
    }

    pub fn health(
        &self,
        deadline: UnixMillisV2,
    ) -> Result<ApprovalHealthResponseV2, ApprovalSuiteOneClientErrorV2> {
        let operation = match self.edge.role() {
            EndpointRoleV2::AgentApproval => ApprovalServiceOperationV2::AgentHealth,
            EndpointRoleV2::IngressApproval => ApprovalServiceOperationV2::IngressHealth,
            EndpointRoleV2::ApprovalAdmin => ApprovalServiceOperationV2::AdminHealth,
            _ => return Err(ApprovalSuiteOneClientErrorV2::Unavailable),
        };
        let body = self.exchange(operation, deadline)?;
        decode_approval_health_response_v2(&body)
            .map_err(|_| ApprovalSuiteOneClientErrorV2::Unavailable)
    }

    pub fn register_ui_authentication(
        &self,
        envelope: SignedUiAuthenticationEnvelopeV2,
        deadline: UnixMillisV2,
    ) -> Result<RegisteredUiAuthenticationV2, ApprovalSuiteOneClientErrorV2> {
        let operation = match self.edge.role() {
            EndpointRoleV2::AgentApproval => {
                ApprovalServiceOperationV2::RegisterAgentUiAuthentication { envelope }
            }
            EndpointRoleV2::IngressApproval => {
                ApprovalServiceOperationV2::RegisterIngressUiAuthentication { envelope }
            }
            _ => return Err(ApprovalSuiteOneClientErrorV2::Unavailable),
        };
        let body = self.exchange(operation, deadline)?;
        decode_registered_ui_authentication_v2(&body, self.edge.role())
            .map_err(|_| ApprovalSuiteOneClientErrorV2::Unavailable)
    }

    pub fn register_approval(
        &self,
        envelope: SignedApprovalEnvelopeV2,
        display_authentication: SignedUiAuthenticationEnvelopeV2,
        deadline: UnixMillisV2,
    ) -> Result<RegisteredApprovalV2, ApprovalSuiteOneClientErrorV2> {
        let operation = match self.edge.role() {
            EndpointRoleV2::AgentApproval => ApprovalServiceOperationV2::RegisterAgentApproval {
                envelope,
                display_authentication,
            },
            EndpointRoleV2::IngressApproval => {
                ApprovalServiceOperationV2::RegisterIngressApproval {
                    envelope,
                    display_authentication,
                }
            }
            _ => return Err(ApprovalSuiteOneClientErrorV2::Unavailable),
        };
        let body = self.exchange(operation, deadline)?;
        decode_registered_approval_v2(&body, self.edge.role())
            .map_err(|_| ApprovalSuiteOneClientErrorV2::Unavailable)
    }

    pub fn get_ingress_approval_settlement(
        &self,
        approval: IngressApprovalRecordHandleV2,
        deadline: UnixMillisV2,
    ) -> Result<ApprovalSettlementViewV2, ApprovalSuiteOneClientErrorV2> {
        if self.edge.role() != EndpointRoleV2::IngressApproval {
            return Err(ApprovalSuiteOneClientErrorV2::Unavailable);
        }
        let body = self.exchange(
            ApprovalServiceOperationV2::GetIngressApprovalSettlement { approval },
            deadline,
        )?;
        decode_approval_settlement_view_v2(&body)
            .map_err(|_| ApprovalSuiteOneClientErrorV2::Unavailable)
    }

    pub fn get_agent_approval_settlement(
        &self,
        approval: AgentApprovalRecordTargetV2,
        deadline: UnixMillisV2,
    ) -> Result<ApprovalSettlementViewV2, ApprovalSuiteOneClientErrorV2> {
        if self.edge.role() != EndpointRoleV2::AgentApproval {
            return Err(ApprovalSuiteOneClientErrorV2::Unavailable);
        }
        let body = self.exchange(
            ApprovalServiceOperationV2::GetAgentApprovalSettlement { approval },
            deadline,
        )?;
        decode_approval_settlement_view_v2(&body)
            .map_err(|_| ApprovalSuiteOneClientErrorV2::Unavailable)
    }

    pub fn consume_agent_ui_authentication(
        &self,
        record: ApprovalUiRecordHandleV2,
        transfer: AgentUiAuthenticationSettlementTransferCapabilityV2,
        deadline: UnixMillisV2,
    ) -> Result<ConsumedUiAuthenticationSettlementV2, ApprovalSuiteOneClientErrorV2> {
        if self.edge.role() != EndpointRoleV2::AgentApproval {
            return Err(ApprovalSuiteOneClientErrorV2::Unavailable);
        }
        let body = self.exchange(
            ApprovalServiceOperationV2::ConsumeAgentUiAuthenticationSettlement { record, transfer },
            deadline,
        )?;
        decode_consumed_ui_authentication_settlement_v2(&body)
            .map_err(|_| ApprovalSuiteOneClientErrorV2::Unavailable)
    }

    pub fn close_agent_authentication_attempt(
        &self,
        descriptor: SignedAgentAuthenticationClosureDescriptorV2,
        deadline: UnixMillisV2,
    ) -> Result<SignedAgentAuthenticationAttemptClosureProofV2, ApprovalSuiteOneClientErrorV2> {
        if self.edge.role() != EndpointRoleV2::AgentApproval {
            return Err(ApprovalSuiteOneClientErrorV2::Unavailable);
        }
        let body = self.exchange(
            ApprovalServiceOperationV2::CloseAgentAuthenticationAttempt { descriptor },
            deadline,
        )?;
        decode_signed_agent_authentication_attempt_closure_proof_v2(&body)
            .map_err(|_| ApprovalSuiteOneClientErrorV2::Unavailable)
    }

    pub fn consume_ingress_ui_authentication(
        &self,
        record: ApprovalUiRecordHandleV2,
        transfer: IngressUiAuthenticationSettlementTransferCapabilityV2,
        deadline: UnixMillisV2,
    ) -> Result<ConsumedUiAuthenticationSettlementV2, ApprovalSuiteOneClientErrorV2> {
        if self.edge.role() != EndpointRoleV2::IngressApproval {
            return Err(ApprovalSuiteOneClientErrorV2::Unavailable);
        }
        let body = self.exchange(
            ApprovalServiceOperationV2::ConsumeIngressUiAuthenticationSettlement {
                record,
                transfer,
            },
            deadline,
        )?;
        decode_consumed_ui_authentication_settlement_v2(&body)
            .map_err(|_| ApprovalSuiteOneClientErrorV2::Unavailable)
    }

    pub fn create_enrollment_code(
        &self,
        profile: EnrollmentProfileIdV2,
        client_request_nonce: Nonce32V2,
        deadline: UnixMillisV2,
    ) -> Result<CreateEnrollmentCodeResponseV2, ApprovalSuiteOneClientErrorV2> {
        if self.edge.role() != EndpointRoleV2::ApprovalAdmin {
            return Err(ApprovalSuiteOneClientErrorV2::Unavailable);
        }
        let body = self.exchange(
            ApprovalServiceOperationV2::CreateEnrollmentCode {
                enrollment_profile: profile,
                client_request_nonce,
            },
            deadline,
        )?;
        decode_create_enrollment_code_response_v2(&body)
            .map_err(|_| ApprovalSuiteOneClientErrorV2::Unavailable)
    }

    pub fn revoke_credential(
        &self,
        credential_digest: Digest32V2,
        reason: ClosedCredentialRevocationReasonV2,
        deadline: UnixMillisV2,
    ) -> Result<CredentialPublicStateV2, ApprovalSuiteOneClientErrorV2> {
        if self.edge.role() != EndpointRoleV2::ApprovalAdmin {
            return Err(ApprovalSuiteOneClientErrorV2::Unavailable);
        }
        let body = self.exchange(
            ApprovalServiceOperationV2::RevokeCredential {
                credential_digest,
                reason,
            },
            deadline,
        )?;
        decode_revoke_credential_response_v2(&body)
            .map(|response| response.state())
            .map_err(|_| ApprovalSuiteOneClientErrorV2::Unavailable)
    }

    fn exchange(
        &self,
        operation: ApprovalServiceOperationV2,
        deadline: UnixMillisV2,
    ) -> Result<Vec<u8>, ApprovalSuiteOneClientErrorV2> {
        if operation.role() != self.edge.role() {
            return Err(ApprovalSuiteOneClientErrorV2::Unavailable);
        }
        #[cfg(all(feature = "test-support", debug_assertions))]
        if let Some(exchange) = &self.operation_exchange_for_test {
            return exchange(deadline, operation);
        }
        let io_deadline = io_deadline(deadline)?;
        let mut stream = UnixStream::connect(&self.socket_path)
            .map_err(|_| ApprovalSuiteOneClientErrorV2::Unavailable)?;
        let result = (|| {
            let request_id = stable_request_id(&operation)?;
            let client_nonce = Nonce32V2::new(random_nonzero_32()?);
            let ephemeral_secret = StaticSecret::from(random_nonzero_32()?);
            let (pending, hello) = V2ClientHandshake::start(
                self.edge,
                self.client_boot_id,
                client_nonce,
                self.expected_observed_peer.clone(),
                ephemeral_secret,
                &self.client_signing_key,
            )
            .map_err(|_| ApprovalSuiteOneClientErrorV2::Unavailable)?;
            write_handshake_frame(&mut stream, &hello, io_deadline)?;
            let server_hello = read_handshake_frame(&mut stream, io_deadline)?;
            let (finish, mut session) = pending
                .accept_server_hello(
                    &server_hello,
                    self.server_public_key,
                    &self.client_signing_key,
                )
                .map_err(|_| ApprovalSuiteOneClientErrorV2::Unavailable)?;
            write_handshake_frame(&mut stream, &finish, io_deadline)?;
            let confirmation = read_record_frame(&mut stream, io_deadline)?;
            session
                .accept_server_confirmation(&confirmation)
                .map_err(|_| ApprovalSuiteOneClientErrorV2::Unavailable)?;

            let operation_tag = operation.tag();
            let request = ApprovalServiceRequestV2::new(request_id, deadline, operation)
                .map_err(|_| ApprovalSuiteOneClientErrorV2::Unavailable)?;
            let plaintext = encode_approval_service_request_v2(&request)
                .map_err(|_| ApprovalSuiteOneClientErrorV2::Unavailable)?;
            let record = session
                .seal_application_request(request_id, operation_tag, &plaintext)
                .map_err(|_| ApprovalSuiteOneClientErrorV2::Unavailable)?;
            write_record_frame(&mut stream, &record, io_deadline)?;
            let response_record = read_record_frame(&mut stream, io_deadline)?;
            let opened = session
                .open_application_response(&response_record)
                .map_err(|_| ApprovalSuiteOneClientErrorV2::Unavailable)?;
            let response = decode_kernel_service_application_response_v2(
                opened.plaintext(),
                self.edge.role(),
                operation_tag,
            )
            .map_err(|_| ApprovalSuiteOneClientErrorV2::Unavailable)?;
            if response.request_id() != request_id || response.operation_tag() != operation_tag {
                return Err(ApprovalSuiteOneClientErrorV2::Unavailable);
            }
            match response.body() {
                KernelServiceApplicationResponseBodyV2::Success(body) => Ok(body.to_vec()),
                KernelServiceApplicationResponseBodyV2::Error(
                    PublicStableCodeV2::DeadlineExceeded,
                ) => Err(ApprovalSuiteOneClientErrorV2::DeadlineExceeded),
                KernelServiceApplicationResponseBodyV2::Error(code) => {
                    Err(ApprovalSuiteOneClientErrorV2::Rejected(*code))
                }
            }
        })();
        let _ = stream.shutdown(Shutdown::Both);
        result
    }
}

fn io_deadline(deadline: UnixMillisV2) -> Result<Instant, ApprovalSuiteOneClientErrorV2> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ApprovalSuiteOneClientErrorV2::Unavailable)?;
    let now_millis =
        u64::try_from(now.as_millis()).map_err(|_| ApprovalSuiteOneClientErrorV2::Unavailable)?;
    let remaining = deadline
        .get()
        .checked_sub(now_millis)
        .filter(|value| *value != 0)
        .ok_or(ApprovalSuiteOneClientErrorV2::DeadlineExceeded)?;
    Ok(Instant::now() + Duration::from_millis(remaining).min(MAX_CONNECTION_DURATION_V2))
}

fn random_nonzero_32() -> Result<[u8; 32], ApprovalSuiteOneClientErrorV2> {
    let mut bytes = [0_u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|_| ApprovalSuiteOneClientErrorV2::Unavailable)?;
    if bytes == [0; 32] {
        Err(ApprovalSuiteOneClientErrorV2::Unavailable)
    } else {
        Ok(bytes)
    }
}

fn stable_request_id(
    operation: &ApprovalServiceOperationV2,
) -> Result<RequestIdV2, ApprovalSuiteOneClientErrorV2> {
    let canonical = encode_approval_service_request_v2(
        &ApprovalServiceRequestV2::new(
            RequestIdV2::new([1; 16]),
            UnixMillisV2::new(1),
            operation.clone(),
        )
        .map_err(|_| ApprovalSuiteOneClientErrorV2::Unavailable)?,
    )
    .map_err(|_| ApprovalSuiteOneClientErrorV2::Unavailable)?;
    let mut hasher = Sha256::new();
    hasher.update(REQUEST_ID_DOMAIN_V2);
    hasher.update(canonical);
    let digest: [u8; 32] = hasher.finalize().into();
    let mut request_id = [0_u8; 16];
    request_id.copy_from_slice(&digest[..16]);
    if request_id == [0; 16] {
        request_id[15] = 1;
    }
    Ok(RequestIdV2::new(request_id))
}

fn set_deadline(
    stream: &UnixStream,
    deadline: Instant,
) -> Result<(), ApprovalSuiteOneClientErrorV2> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(ApprovalSuiteOneClientErrorV2::DeadlineExceeded);
    }
    stream
        .set_read_timeout(Some(remaining))
        .and_then(|()| stream.set_write_timeout(Some(remaining)))
        .map_err(|_| ApprovalSuiteOneClientErrorV2::Unavailable)
}

fn read_handshake_frame(
    stream: &mut UnixStream,
    deadline: Instant,
) -> Result<Vec<u8>, ApprovalSuiteOneClientErrorV2> {
    set_deadline(stream, deadline)?;
    let mut header = [0_u8; HANDSHAKE_FRAME_HEADER_BYTES_V2];
    stream
        .read_exact(&mut header)
        .map_err(|_| ApprovalSuiteOneClientErrorV2::Unavailable)?;
    if &header[..8] != HANDSHAKE_MAGIC_V2 {
        return Err(ApprovalSuiteOneClientErrorV2::Unavailable);
    }
    let length = u32::from_be_bytes(
        header[HANDSHAKE_FRAME_HEADER_BYTES_V2 - 4..]
            .try_into()
            .map_err(|_| ApprovalSuiteOneClientErrorV2::Unavailable)?,
    ) as usize;
    if length == 0 || length > MAX_HANDSHAKE_BODY_BYTES_V2 {
        return Err(ApprovalSuiteOneClientErrorV2::Unavailable);
    }
    let total = HANDSHAKE_FRAME_HEADER_BYTES_V2
        .checked_add(length)
        .ok_or(ApprovalSuiteOneClientErrorV2::Unavailable)?;
    let mut frame = header.to_vec();
    frame.resize(total, 0);
    stream
        .read_exact(&mut frame[HANDSHAKE_FRAME_HEADER_BYTES_V2..])
        .map_err(|_| ApprovalSuiteOneClientErrorV2::Unavailable)?;
    Ok(frame)
}

fn write_handshake_frame(
    stream: &mut UnixStream,
    frame: &[u8],
    deadline: Instant,
) -> Result<(), ApprovalSuiteOneClientErrorV2> {
    if frame.len() <= HANDSHAKE_FRAME_HEADER_BYTES_V2
        || frame.len() > HANDSHAKE_FRAME_HEADER_BYTES_V2 + MAX_HANDSHAKE_BODY_BYTES_V2
        || &frame[..8] != HANDSHAKE_MAGIC_V2
    {
        return Err(ApprovalSuiteOneClientErrorV2::Unavailable);
    }
    set_deadline(stream, deadline)?;
    stream
        .write_all(frame)
        .and_then(|()| stream.flush())
        .map_err(|_| ApprovalSuiteOneClientErrorV2::Unavailable)
}

fn read_record_frame(
    stream: &mut UnixStream,
    deadline: Instant,
) -> Result<Vec<u8>, ApprovalSuiteOneClientErrorV2> {
    set_deadline(stream, deadline)?;
    let mut header = [0_u8; RECORD_FRAME_HEADER_BYTES_V2];
    stream
        .read_exact(&mut header)
        .map_err(|_| ApprovalSuiteOneClientErrorV2::Unavailable)?;
    let (header_length, ciphertext_length) = record_lengths(&header)?;
    let total = RECORD_FRAME_HEADER_BYTES_V2
        .checked_add(header_length)
        .and_then(|value| value.checked_add(ciphertext_length))
        .ok_or(ApprovalSuiteOneClientErrorV2::Unavailable)?;
    let mut frame = Vec::new();
    frame
        .try_reserve_exact(total)
        .map_err(|_| ApprovalSuiteOneClientErrorV2::Unavailable)?;
    frame.extend_from_slice(&header);
    frame.resize(total, 0);
    stream
        .read_exact(&mut frame[RECORD_FRAME_HEADER_BYTES_V2..])
        .map_err(|_| ApprovalSuiteOneClientErrorV2::Unavailable)?;
    Ok(frame)
}

fn write_record_frame(
    stream: &mut UnixStream,
    frame: &[u8],
    deadline: Instant,
) -> Result<(), ApprovalSuiteOneClientErrorV2> {
    if frame.len() < RECORD_FRAME_HEADER_BYTES_V2 {
        return Err(ApprovalSuiteOneClientErrorV2::Unavailable);
    }
    let (header_length, ciphertext_length) =
        record_lengths(&frame[..RECORD_FRAME_HEADER_BYTES_V2])?;
    if frame.len() != RECORD_FRAME_HEADER_BYTES_V2 + header_length + ciphertext_length {
        return Err(ApprovalSuiteOneClientErrorV2::Unavailable);
    }
    set_deadline(stream, deadline)?;
    stream
        .write_all(frame)
        .and_then(|()| stream.flush())
        .map_err(|_| ApprovalSuiteOneClientErrorV2::Unavailable)
}

fn record_lengths(header: &[u8]) -> Result<(usize, usize), ApprovalSuiteOneClientErrorV2> {
    if header.len() != RECORD_FRAME_HEADER_BYTES_V2 || &header[..4] != RECORD_MAGIC_V2 {
        return Err(ApprovalSuiteOneClientErrorV2::Unavailable);
    }
    let header_length = usize::from(u16::from_be_bytes(
        header[4..6]
            .try_into()
            .map_err(|_| ApprovalSuiteOneClientErrorV2::Unavailable)?,
    ));
    let ciphertext_length = u32::from_be_bytes(
        header[6..10]
            .try_into()
            .map_err(|_| ApprovalSuiteOneClientErrorV2::Unavailable)?,
    ) as usize;
    if header_length == 0
        || header_length > MAX_RECORD_HEADER_BYTES_V2
        || !(16..=MAX_RECORD_CIPHERTEXT_BYTES_V2).contains(&ciphertext_length)
    {
        return Err(ApprovalSuiteOneClientErrorV2::Unavailable);
    }
    Ok((header_length, ciphertext_length))
}
