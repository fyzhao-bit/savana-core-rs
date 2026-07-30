use std::io::{Read as _, Write as _};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use ed25519_dalek::SigningKey;
use savana_kernel_protocol::v2::{
    decode_approval_service_request_v2, encode_approval_health_response_v2,
    encode_approval_settlement_view_v2, encode_consumed_ui_authentication_settlement_v2,
    encode_create_enrollment_code_response_v2, encode_kernel_service_application_response_v2,
    encode_registered_approval_v2, encode_registered_ui_authentication_v2,
    encode_revoke_credential_response_v2,
    encode_signed_agent_authentication_attempt_closure_proof_v2, ApprovalHealthResponseV2,
    ApprovalServiceOperationV2, BootIdV2, ConsumedUiAuthenticationSettlementV2, EndpointRoleV2,
    KernelServiceApplicationResponseV2, KernelServiceHandshakeEdgeV2, Nonce32V2,
    PeerIdentityBindingV2, PublicServiceStateV2, PublicStableCodeV2, UnixMillisV2,
    V2PendingServerHandshake, V2ServerHandshake, HANDSHAKE_FRAME_HEADER_BYTES_V2,
    MAX_HANDSHAKE_BODY_BYTES_V2, MAX_RECORD_CIPHERTEXT_BYTES_V2, MAX_RECORD_HEADER_BYTES_V2,
    RECORD_FRAME_HEADER_BYTES_V2,
};
use x25519_dalek::StaticSecret;

use crate::{ApprovalUiAuthorityErrorV2, ApprovalUiAuthorityV2};

const HANDSHAKE_MAGIC_V2: &[u8; 8] = b"SAVANA2\0";
const RECORD_MAGIC_V2: &[u8; 4] = b"SV2R";
const MAX_HANDSHAKE_REPLAYS_V2: usize = 65_536;
const MAX_VERIFIED_PROCESS_BINDINGS_V2: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ApprovalSuiteOneServiceErrorV2 {
    #[error("approval Suite-1 request was malformed")]
    Malformed,
    #[error("approval Suite-1 peer identity was rejected")]
    IdentityRejected,
    #[error("approval Suite-1 handshake was replayed")]
    Replay,
    #[error("approval Suite-1 service is busy")]
    Busy,
    #[error("approval Suite-1 deadline was exceeded")]
    DeadlineExceeded,
    #[error("approval Suite-1 service is unavailable")]
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HandshakeReplayKeyV2 {
    observed_peer: PeerIdentityBindingV2,
    client_boot_id: BootIdV2,
    client_nonce: Nonce32V2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct VerifiedProcessBootV2 {
    observed_peer: PeerIdentityBindingV2,
    client_boot_id: BootIdV2,
}

#[derive(Default)]
struct ReplayStateV2 {
    replay: Vec<HandshakeReplayKeyV2>,
    process_boots: Vec<VerifiedProcessBootV2>,
}

pub struct ApprovalSuiteOneServerV2 {
    edge: KernelServiceHandshakeEdgeV2,
    client_public_key: [u8; 32],
    server_signing_key: SigningKey,
    replay_capacity: usize,
    replay_state: Mutex<ReplayStateV2>,
    authority: Arc<ApprovalUiAuthorityV2>,
}

impl core::fmt::Debug for ApprovalSuiteOneServerV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ApprovalSuiteOneServerV2")
            .field("role", &self.edge.role())
            .field("replay_capacity", &self.replay_capacity)
            .finish_non_exhaustive()
    }
}

impl ApprovalSuiteOneServerV2 {
    pub fn new(
        edge: KernelServiceHandshakeEdgeV2,
        client_public_key: [u8; 32],
        server_signing_key: SigningKey,
        replay_capacity: usize,
        authority: Arc<ApprovalUiAuthorityV2>,
    ) -> Result<Self, ApprovalSuiteOneServiceErrorV2> {
        if !matches!(
            edge.role(),
            EndpointRoleV2::AgentApproval
                | EndpointRoleV2::IngressApproval
                | EndpointRoleV2::ApprovalAdmin
        ) || client_public_key == [0; 32]
            || replay_capacity == 0
            || replay_capacity > MAX_HANDSHAKE_REPLAYS_V2
        {
            return Err(ApprovalSuiteOneServiceErrorV2::IdentityRejected);
        }
        Ok(Self {
            edge,
            client_public_key,
            server_signing_key,
            replay_capacity,
            replay_state: Mutex::new(ReplayStateV2::default()),
            authority,
        })
    }

    pub fn serve_stream(
        &self,
        mut stream: UnixStream,
        observed_peer: PeerIdentityBindingV2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<(), ApprovalSuiteOneServiceErrorV2> {
        let result = (|| {
            let client_hello = read_handshake_frame(&mut stream, deadline)?;
            let (pending, server_hello) =
                self.start_handshake(observed_peer.clone(), &client_hello)?;
            write_frame(&mut stream, &server_hello, deadline, FrameKindV2::Handshake)?;
            let client_finish = read_handshake_frame(&mut stream, deadline)?;
            let (confirmation, mut session) =
                self.finish_handshake(observed_peer, pending, &client_finish)?;
            write_frame(&mut stream, &confirmation, deadline, FrameKindV2::Record)?;

            let request_record = read_record_frame(&mut stream, deadline)?;
            let opened = session
                .open_application_request(&request_record)
                .map_err(|_| ApprovalSuiteOneServiceErrorV2::Malformed)?;
            let request = decode_approval_service_request_v2(
                opened.plaintext(),
                self.edge.role(),
                opened.operation_tag(),
            )
            .map_err(|_| ApprovalSuiteOneServiceErrorV2::Malformed)?;
            if request.request_id() != opened.request_id()
                || request.role() != self.edge.role()
                || request.operation().tag() != opened.operation_tag()
            {
                return Err(ApprovalSuiteOneServiceErrorV2::IdentityRejected);
            }
            let request_id = request.request_id();
            let operation_tag = request.operation().tag();
            let response = if request.deadline().get() < now.get() || Instant::now() >= deadline {
                error_response(
                    self.edge.role(),
                    request_id,
                    operation_tag,
                    PublicStableCodeV2::DeadlineExceeded,
                )?
            } else {
                match self.execute(request.into_operation(), now, deadline) {
                    Ok(body) => KernelServiceApplicationResponseV2::success(
                        self.edge.role(),
                        request_id,
                        operation_tag,
                        body,
                    )
                    .map_err(|_| ApprovalSuiteOneServiceErrorV2::Unavailable)?,
                    Err(error) => error_response(
                        self.edge.role(),
                        request_id,
                        operation_tag,
                        map_authority_error(error),
                    )?,
                }
            };
            let plaintext = encode_kernel_service_application_response_v2(&response)
                .map_err(|_| ApprovalSuiteOneServiceErrorV2::Unavailable)?;
            let record = session
                .seal_application_response(request_id, operation_tag, &plaintext)
                .map_err(|_| ApprovalSuiteOneServiceErrorV2::Unavailable)?;
            write_frame(&mut stream, &record, deadline, FrameKindV2::Record)
        })();
        let _ = stream.shutdown(Shutdown::Both);
        result
    }

    fn execute(
        &self,
        operation: ApprovalServiceOperationV2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<Vec<u8>, ApprovalUiAuthorityErrorV2> {
        match operation {
            ApprovalServiceOperationV2::AgentHealth
            | ApprovalServiceOperationV2::IngressHealth
            | ApprovalServiceOperationV2::AdminHealth => encode_approval_health_response_v2(
                ApprovalHealthResponseV2::new(PublicServiceStateV2::Ready),
            )
            .map_err(|_| ApprovalUiAuthorityErrorV2::Unavailable),
            ApprovalServiceOperationV2::RegisterAgentApproval {
                envelope,
                display_authentication,
            } => {
                let registered = self.authority.register_approval(
                    EndpointRoleV2::AgentApproval,
                    envelope,
                    display_authentication,
                    now,
                    deadline,
                )?;
                encode_registered_approval_v2(registered)
                    .map_err(|_| ApprovalUiAuthorityErrorV2::Unavailable)
            }
            ApprovalServiceOperationV2::GetAgentApprovalSettlement { approval } => {
                let view = self
                    .authority
                    .get_agent_approval_settlement(approval, now, deadline)?;
                encode_approval_settlement_view_v2(&view)
                    .map_err(|_| ApprovalUiAuthorityErrorV2::Unavailable)
            }
            ApprovalServiceOperationV2::RegisterIngressApproval {
                envelope,
                display_authentication,
            } => {
                let registered = self.authority.register_approval(
                    EndpointRoleV2::IngressApproval,
                    envelope,
                    display_authentication,
                    now,
                    deadline,
                )?;
                encode_registered_approval_v2(registered)
                    .map_err(|_| ApprovalUiAuthorityErrorV2::Unavailable)
            }
            ApprovalServiceOperationV2::GetIngressApprovalSettlement { approval } => {
                let view = self
                    .authority
                    .get_ingress_approval_settlement(approval, now, deadline)?;
                encode_approval_settlement_view_v2(&view)
                    .map_err(|_| ApprovalUiAuthorityErrorV2::Unavailable)
            }
            ApprovalServiceOperationV2::RegisterAgentUiAuthentication { envelope } => {
                let registered = self.authority.register(
                    EndpointRoleV2::AgentApproval,
                    envelope,
                    now,
                    deadline,
                )?;
                encode_registered_ui_authentication_v2(registered)
                    .map_err(|_| ApprovalUiAuthorityErrorV2::Unavailable)
            }
            ApprovalServiceOperationV2::RegisterIngressUiAuthentication { envelope } => {
                let registered = self.authority.register(
                    EndpointRoleV2::IngressApproval,
                    envelope,
                    now,
                    deadline,
                )?;
                encode_registered_ui_authentication_v2(registered)
                    .map_err(|_| ApprovalUiAuthorityErrorV2::Unavailable)
            }
            ApprovalServiceOperationV2::ConsumeAgentUiAuthenticationSettlement {
                record,
                transfer,
            } => {
                let settlement = self.authority.consume_agent_settlement(record, transfer)?;
                encode_consumed_ui_authentication_settlement_v2(
                    &ConsumedUiAuthenticationSettlementV2::new(settlement),
                )
                .map_err(|_| ApprovalUiAuthorityErrorV2::Unavailable)
            }
            ApprovalServiceOperationV2::ConsumeIngressUiAuthenticationSettlement {
                record,
                transfer,
            } => {
                let settlement = self
                    .authority
                    .consume_ingress_settlement(record, transfer)?;
                encode_consumed_ui_authentication_settlement_v2(
                    &ConsumedUiAuthenticationSettlementV2::new(settlement),
                )
                .map_err(|_| ApprovalUiAuthorityErrorV2::Unavailable)
            }
            ApprovalServiceOperationV2::CloseAgentAuthenticationAttempt { descriptor } => {
                let proof = self.authority.close_agent_authentication_attempt(
                    descriptor,
                    self.edge.client_identity(),
                    now,
                    deadline,
                )?;
                encode_signed_agent_authentication_attempt_closure_proof_v2(&proof)
                    .map_err(|_| ApprovalUiAuthorityErrorV2::Unavailable)
            }
            ApprovalServiceOperationV2::CreateEnrollmentCode {
                enrollment_profile,
                client_request_nonce,
            } => {
                let response = self.authority.create_enrollment_code(
                    enrollment_profile,
                    client_request_nonce,
                    now,
                    deadline,
                )?;
                encode_create_enrollment_code_response_v2(&response)
                    .map_err(|_| ApprovalUiAuthorityErrorV2::Unavailable)
            }
            ApprovalServiceOperationV2::RevokeCredential {
                credential_digest,
                reason,
            } => {
                let state =
                    self.authority
                        .revoke_credential(credential_digest, reason, deadline)?;
                encode_revoke_credential_response_v2(
                    savana_kernel_protocol::v2::RevokeCredentialResponseV2::new(state),
                )
                .map_err(|_| ApprovalUiAuthorityErrorV2::Unavailable)
            }
        }
    }

    fn start_handshake(
        &self,
        observed_peer: PeerIdentityBindingV2,
        client_hello: &[u8],
    ) -> Result<(V2PendingServerHandshake, Vec<u8>), ApprovalSuiteOneServiceErrorV2> {
        let server_nonce = Nonce32V2::new(draw_nonzero()?);
        let ephemeral_secret = StaticSecret::from(draw_nonzero()?);
        let (pending, server_hello) = V2ServerHandshake::accept_client_hello(
            self.edge,
            observed_peer.clone(),
            client_hello,
            server_nonce,
            ephemeral_secret,
            self.client_public_key,
            &self.server_signing_key,
        )
        .map_err(|_| ApprovalSuiteOneServiceErrorV2::IdentityRejected)?;
        let mut state = self
            .replay_state
            .lock()
            .map_err(|_| ApprovalSuiteOneServiceErrorV2::Unavailable)?;
        if state.replay.len() >= self.replay_capacity {
            return Err(ApprovalSuiteOneServiceErrorV2::Busy);
        }
        if state.process_boots.iter().any(|entry| {
            entry.observed_peer == observed_peer && entry.client_boot_id != pending.client_boot_id()
        }) {
            return Err(ApprovalSuiteOneServiceErrorV2::IdentityRejected);
        }
        let replay = HandshakeReplayKeyV2 {
            observed_peer,
            client_boot_id: pending.client_boot_id(),
            client_nonce: pending.client_nonce(),
        };
        if state.replay.iter().any(|entry| entry == &replay) {
            return Err(ApprovalSuiteOneServiceErrorV2::Replay);
        }
        state
            .replay
            .try_reserve(1)
            .map_err(|_| ApprovalSuiteOneServiceErrorV2::Unavailable)?;
        state.replay.push(replay);
        Ok((pending, server_hello))
    }

    fn finish_handshake(
        &self,
        observed_peer: PeerIdentityBindingV2,
        pending: V2PendingServerHandshake,
        client_finish: &[u8],
    ) -> Result<
        (
            Vec<u8>,
            savana_kernel_protocol::v2::V2ServerTransportSession,
        ),
        ApprovalSuiteOneServiceErrorV2,
    > {
        let (confirmation, session, peer) = pending
            .accept_client_finish(client_finish)
            .map_err(|_| ApprovalSuiteOneServiceErrorV2::IdentityRejected)?;
        if peer.role() != self.edge.role() {
            return Err(ApprovalSuiteOneServiceErrorV2::IdentityRejected);
        }
        let mut state = self
            .replay_state
            .lock()
            .map_err(|_| ApprovalSuiteOneServiceErrorV2::Unavailable)?;
        if let Some(existing) = state
            .process_boots
            .iter()
            .find(|entry| entry.observed_peer == observed_peer)
        {
            if existing.client_boot_id != peer.client_boot_id() {
                return Err(ApprovalSuiteOneServiceErrorV2::IdentityRejected);
            }
        } else {
            if state.process_boots.len() >= MAX_VERIFIED_PROCESS_BINDINGS_V2 {
                return Err(ApprovalSuiteOneServiceErrorV2::Busy);
            }
            state
                .process_boots
                .try_reserve(1)
                .map_err(|_| ApprovalSuiteOneServiceErrorV2::Unavailable)?;
            state.process_boots.push(VerifiedProcessBootV2 {
                observed_peer,
                client_boot_id: peer.client_boot_id(),
            });
        }
        Ok((confirmation, session))
    }
}

fn error_response(
    role: EndpointRoleV2,
    request_id: savana_kernel_protocol::v2::RequestIdV2,
    operation_tag: u16,
    code: PublicStableCodeV2,
) -> Result<KernelServiceApplicationResponseV2, ApprovalSuiteOneServiceErrorV2> {
    KernelServiceApplicationResponseV2::error(
        role,
        request_id,
        operation_tag,
        if operation_tag == 0 {
            PublicStableCodeV2::ServiceUnavailable
        } else {
            code
        },
    )
    .map_err(|_| ApprovalSuiteOneServiceErrorV2::Unavailable)
}

const fn map_authority_error(error: ApprovalUiAuthorityErrorV2) -> PublicStableCodeV2 {
    match error {
        ApprovalUiAuthorityErrorV2::InvalidReference => PublicStableCodeV2::ApprovalBindingMismatch,
        ApprovalUiAuthorityErrorV2::AlreadyConsumed => PublicStableCodeV2::ApprovalReplay,
        ApprovalUiAuthorityErrorV2::Busy => PublicStableCodeV2::Overloaded,
        ApprovalUiAuthorityErrorV2::DeadlineExceeded => PublicStableCodeV2::DeadlineExceeded,
        ApprovalUiAuthorityErrorV2::Unavailable => PublicStableCodeV2::ServiceUnavailable,
    }
}

fn draw_nonzero() -> Result<[u8; 32], ApprovalSuiteOneServiceErrorV2> {
    for _ in 0..4 {
        let mut bytes = [0_u8; 32];
        getrandom::getrandom(&mut bytes)
            .map_err(|_| ApprovalSuiteOneServiceErrorV2::Unavailable)?;
        if bytes != [0; 32] {
            return Ok(bytes);
        }
    }
    Err(ApprovalSuiteOneServiceErrorV2::Unavailable)
}

#[derive(Debug, Clone, Copy)]
enum FrameKindV2 {
    Handshake,
    Record,
}

fn set_deadline(
    stream: &UnixStream,
    deadline: Instant,
) -> Result<(), ApprovalSuiteOneServiceErrorV2> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(ApprovalSuiteOneServiceErrorV2::DeadlineExceeded);
    }
    stream
        .set_read_timeout(Some(remaining))
        .and_then(|_| stream.set_write_timeout(Some(remaining)))
        .map_err(|_| ApprovalSuiteOneServiceErrorV2::Unavailable)
}

fn read_handshake_frame(
    stream: &mut UnixStream,
    deadline: Instant,
) -> Result<Vec<u8>, ApprovalSuiteOneServiceErrorV2> {
    set_deadline(stream, deadline)?;
    let mut header = [0_u8; HANDSHAKE_FRAME_HEADER_BYTES_V2];
    stream
        .read_exact(&mut header)
        .map_err(|_| ApprovalSuiteOneServiceErrorV2::Malformed)?;
    if &header[..8] != HANDSHAKE_MAGIC_V2 {
        return Err(ApprovalSuiteOneServiceErrorV2::Malformed);
    }
    let body_length = u32::from_be_bytes(
        header[HANDSHAKE_FRAME_HEADER_BYTES_V2 - 4..]
            .try_into()
            .map_err(|_| ApprovalSuiteOneServiceErrorV2::Malformed)?,
    ) as usize;
    if body_length == 0 || body_length > MAX_HANDSHAKE_BODY_BYTES_V2 {
        return Err(ApprovalSuiteOneServiceErrorV2::Malformed);
    }
    let total = HANDSHAKE_FRAME_HEADER_BYTES_V2
        .checked_add(body_length)
        .ok_or(ApprovalSuiteOneServiceErrorV2::Malformed)?;
    let mut frame = Vec::new();
    frame
        .try_reserve_exact(total)
        .map_err(|_| ApprovalSuiteOneServiceErrorV2::Unavailable)?;
    frame.extend_from_slice(&header);
    frame.resize(total, 0);
    stream
        .read_exact(&mut frame[HANDSHAKE_FRAME_HEADER_BYTES_V2..])
        .map_err(|_| ApprovalSuiteOneServiceErrorV2::Malformed)?;
    Ok(frame)
}

fn read_record_frame(
    stream: &mut UnixStream,
    deadline: Instant,
) -> Result<Vec<u8>, ApprovalSuiteOneServiceErrorV2> {
    set_deadline(stream, deadline)?;
    let mut header = [0_u8; RECORD_FRAME_HEADER_BYTES_V2];
    stream
        .read_exact(&mut header)
        .map_err(|_| ApprovalSuiteOneServiceErrorV2::Malformed)?;
    let (header_length, ciphertext_length) = record_lengths(&header)?;
    let total = RECORD_FRAME_HEADER_BYTES_V2
        .checked_add(header_length)
        .and_then(|value| value.checked_add(ciphertext_length))
        .ok_or(ApprovalSuiteOneServiceErrorV2::Malformed)?;
    let mut frame = Vec::new();
    frame
        .try_reserve_exact(total)
        .map_err(|_| ApprovalSuiteOneServiceErrorV2::Unavailable)?;
    frame.extend_from_slice(&header);
    frame.resize(total, 0);
    stream
        .read_exact(&mut frame[RECORD_FRAME_HEADER_BYTES_V2..])
        .map_err(|_| ApprovalSuiteOneServiceErrorV2::Malformed)?;
    Ok(frame)
}

fn write_frame(
    stream: &mut UnixStream,
    frame: &[u8],
    deadline: Instant,
    kind: FrameKindV2,
) -> Result<(), ApprovalSuiteOneServiceErrorV2> {
    match kind {
        FrameKindV2::Handshake
            if frame.len() < HANDSHAKE_FRAME_HEADER_BYTES_V2
                || &frame[..8] != HANDSHAKE_MAGIC_V2 =>
        {
            return Err(ApprovalSuiteOneServiceErrorV2::Unavailable)
        }
        FrameKindV2::Record if frame.len() < RECORD_FRAME_HEADER_BYTES_V2 => {
            return Err(ApprovalSuiteOneServiceErrorV2::Unavailable)
        }
        FrameKindV2::Record => {
            let (header_length, ciphertext_length) =
                record_lengths(&frame[..RECORD_FRAME_HEADER_BYTES_V2])?;
            if frame.len() != RECORD_FRAME_HEADER_BYTES_V2 + header_length + ciphertext_length {
                return Err(ApprovalSuiteOneServiceErrorV2::Unavailable);
            }
        }
        FrameKindV2::Handshake => {}
    }
    set_deadline(stream, deadline)?;
    stream
        .write_all(frame)
        .and_then(|_| stream.flush())
        .map_err(|_| ApprovalSuiteOneServiceErrorV2::Unavailable)
}

fn record_lengths(header: &[u8]) -> Result<(usize, usize), ApprovalSuiteOneServiceErrorV2> {
    if header.len() != RECORD_FRAME_HEADER_BYTES_V2 || &header[..4] != RECORD_MAGIC_V2 {
        return Err(ApprovalSuiteOneServiceErrorV2::Malformed);
    }
    let header_length = usize::from(u16::from_be_bytes(
        header[4..6]
            .try_into()
            .map_err(|_| ApprovalSuiteOneServiceErrorV2::Malformed)?,
    ));
    let ciphertext_length = u32::from_be_bytes(
        header[6..10]
            .try_into()
            .map_err(|_| ApprovalSuiteOneServiceErrorV2::Malformed)?,
    ) as usize;
    if header_length == 0
        || header_length > MAX_RECORD_HEADER_BYTES_V2
        || !(16..=MAX_RECORD_CIPHERTEXT_BYTES_V2).contains(&ciphertext_length)
    {
        return Err(ApprovalSuiteOneServiceErrorV2::Malformed);
    }
    Ok((header_length, ciphertext_length))
}
