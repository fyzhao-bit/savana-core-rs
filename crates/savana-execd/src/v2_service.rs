use std::io::{Read as _, Write as _};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::sync::Mutex;
use std::time::Instant;

use ed25519_dalek::SigningKey;
use savana_kernel_protocol::v2::{
    decode_kernel_service_application_request_v2, encode_kernel_service_application_response_v2,
    peek_kernel_service_application_request_v2, BootIdV2, EndpointRoleV2,
    KernelServiceApplicationResponseV2, KernelServiceHandshakeEdgeV2, KernelServiceOperationV2,
    Nonce32V2, PeerIdentityBindingV2, PublicStableCodeV2, UnixMillisV2, V2PendingServerHandshake,
    V2ServerHandshake, VerifiedV2HandshakePeer, HANDSHAKE_FRAME_HEADER_BYTES_V2,
    MAX_HANDSHAKE_BODY_BYTES_V2, MAX_RECORD_CIPHERTEXT_BYTES_V2, MAX_RECORD_HEADER_BYTES_V2,
    RECORD_FRAME_HEADER_BYTES_V2,
};
use x25519_dalek::StaticSecret;

use crate::{ExecdProtocolServiceErrorV2, ExecdProtocolServiceV2, ExecdStateOwnerErrorV2};

const HANDSHAKE_MAGIC_V2: &[u8; 8] = b"SAVANA2\0";
const RECORD_MAGIC_V2: &[u8; 4] = b"SV2R";
const MAX_HANDSHAKE_REPLAYS_V2: usize = 65_536;
const MAX_VERIFIED_PROCESS_BINDINGS_V2: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ExecdSuiteOneServiceErrorV2 {
    #[error("executor Suite-1 request was malformed")]
    Malformed,
    #[error("executor Suite-1 peer identity was rejected")]
    IdentityRejected,
    #[error("executor Suite-1 handshake was replayed")]
    Replay,
    #[error("executor Suite-1 service is busy")]
    Busy,
    #[error("executor Suite-1 deadline was exceeded")]
    DeadlineExceeded,
    #[error("executor Suite-1 service is unavailable")]
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
struct HandshakeReplayStateV2 {
    replay: Vec<HandshakeReplayKeyV2>,
    process_boots: Vec<VerifiedProcessBootV2>,
}

impl std::fmt::Debug for HandshakeReplayStateV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HandshakeReplayStateV2")
            .field("replay_count", &self.replay.len())
            .field("verified_process_count", &self.process_boots.len())
            .finish()
    }
}

/// Execd's only authenticated application server.
///
/// One connection performs one mutually authenticated Suite-1 handshake,
/// opens one encrypted KernelExecutor request, emits at most one encrypted
/// response, and then closes.
pub struct ExecdSuiteOneServerV2 {
    edge: KernelServiceHandshakeEdgeV2,
    client_public_key: [u8; 32],
    server_signing_key: SigningKey,
    replay_capacity: usize,
    replay_state: Mutex<HandshakeReplayStateV2>,
    service: ExecdOperationServiceV2,
}

enum ExecdOperationServiceV2 {
    Production(ExecdProtocolServiceV2),
    #[cfg(test)]
    Test(
        fn(
            savana_kernel_protocol::v2::KernelExecutorOperationV2,
            UnixMillisV2,
            Instant,
        ) -> Result<Vec<u8>, ExecdProtocolServiceErrorV2>,
    ),
}

impl ExecdOperationServiceV2 {
    fn execute(
        &self,
        operation: savana_kernel_protocol::v2::KernelExecutorOperationV2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<Vec<u8>, ExecdProtocolServiceErrorV2> {
        match self {
            Self::Production(service) => service.execute(operation, now, deadline),
            #[cfg(test)]
            Self::Test(handler) => handler(operation, now, deadline),
        }
    }
}

impl std::fmt::Debug for ExecdSuiteOneServerV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExecdSuiteOneServerV2")
            .field("role", &self.edge.role())
            .field("replay_capacity", &self.replay_capacity)
            .finish_non_exhaustive()
    }
}

impl ExecdSuiteOneServerV2 {
    pub fn new(
        edge: KernelServiceHandshakeEdgeV2,
        client_public_key: [u8; 32],
        server_signing_key: SigningKey,
        replay_capacity: usize,
        service: ExecdProtocolServiceV2,
    ) -> Result<Self, ExecdSuiteOneServiceErrorV2> {
        if edge.role() != EndpointRoleV2::KernelExecutor
            || client_public_key == [0; 32]
            || replay_capacity == 0
            || replay_capacity > MAX_HANDSHAKE_REPLAYS_V2
        {
            return Err(ExecdSuiteOneServiceErrorV2::IdentityRejected);
        }
        Ok(Self {
            edge,
            client_public_key,
            server_signing_key,
            replay_capacity,
            replay_state: Mutex::new(HandshakeReplayStateV2::default()),
            service: ExecdOperationServiceV2::Production(service),
        })
    }

    #[cfg(test)]
    fn new_for_test(
        edge: KernelServiceHandshakeEdgeV2,
        client_public_key: [u8; 32],
        server_signing_key: SigningKey,
        handler: fn(
            savana_kernel_protocol::v2::KernelExecutorOperationV2,
            UnixMillisV2,
            Instant,
        ) -> Result<Vec<u8>, ExecdProtocolServiceErrorV2>,
    ) -> Self {
        Self {
            edge,
            client_public_key,
            server_signing_key,
            replay_capacity: 16,
            replay_state: Mutex::new(HandshakeReplayStateV2::default()),
            service: ExecdOperationServiceV2::Test(handler),
        }
    }

    pub fn serve_stream(
        &self,
        mut stream: UnixStream,
        observed_peer: PeerIdentityBindingV2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<(), ExecdSuiteOneServiceErrorV2> {
        let result = (|| {
            let client_hello = read_handshake_frame(&mut stream, deadline)?;
            let (pending, server_hello) =
                self.start_handshake(observed_peer.clone(), &client_hello)?;
            write_frame(&mut stream, &server_hello, deadline, FrameKindV2::Handshake)?;

            let client_finish = read_handshake_frame(&mut stream, deadline)?;
            let (confirmation, mut session, peer) =
                self.finish_handshake(observed_peer, pending, &client_finish)?;
            write_frame(&mut stream, &confirmation, deadline, FrameKindV2::Record)?;

            let request_record = read_record_frame(&mut stream, deadline)?;
            let opened = session
                .open_application_request(&request_record)
                .map_err(|_| ExecdSuiteOneServiceErrorV2::Malformed)?;
            let routing = peek_kernel_service_application_request_v2(opened.plaintext())
                .map_err(|_| ExecdSuiteOneServiceErrorV2::Malformed)?;
            if peer.role() != EndpointRoleV2::KernelExecutor
                || routing.role() != EndpointRoleV2::KernelExecutor
                || routing.request_id() != opened.request_id()
                || routing.operation_tag() != opened.operation_tag()
            {
                return Err(ExecdSuiteOneServiceErrorV2::IdentityRejected);
            }
            let request = decode_kernel_service_application_request_v2(opened.plaintext())
                .map_err(|_| ExecdSuiteOneServiceErrorV2::Malformed)?;
            let (_, request_id, request_deadline, operation) = request.into_parts();
            let operation_tag = operation.tag();
            let response = if request_deadline.get() < now.get() || Instant::now() >= deadline {
                executor_error_response(
                    request_id,
                    operation_tag,
                    PublicStableCodeV2::DeadlineExceeded,
                )?
            } else {
                let operation = match operation {
                    KernelServiceOperationV2::Executor(operation) => operation,
                    KernelServiceOperationV2::Agent(_)
                    | KernelServiceOperationV2::Connector(_)
                    | KernelServiceOperationV2::Ingress(_) => {
                        return Err(ExecdSuiteOneServiceErrorV2::IdentityRejected);
                    }
                };
                match self.service.execute(operation, now, deadline) {
                    Ok(body) => KernelServiceApplicationResponseV2::success(
                        EndpointRoleV2::KernelExecutor,
                        request_id,
                        operation_tag,
                        body,
                    )
                    .map_err(|_| ExecdSuiteOneServiceErrorV2::Unavailable)?,
                    Err(error) => executor_error_response(
                        request_id,
                        operation_tag,
                        map_service_error(operation_tag, error),
                    )?,
                }
            };
            let plaintext = encode_kernel_service_application_response_v2(&response)
                .map_err(|_| ExecdSuiteOneServiceErrorV2::Unavailable)?;
            let record = session
                .seal_application_response(request_id, operation_tag, &plaintext)
                .map_err(|_| ExecdSuiteOneServiceErrorV2::Unavailable)?;
            write_frame(&mut stream, &record, deadline, FrameKindV2::Record)
        })();
        let _ = stream.shutdown(Shutdown::Both);
        result
    }

    fn start_handshake(
        &self,
        observed_peer: PeerIdentityBindingV2,
        client_hello: &[u8],
    ) -> Result<(V2PendingServerHandshake, Vec<u8>), ExecdSuiteOneServiceErrorV2> {
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
        .map_err(|_| ExecdSuiteOneServiceErrorV2::IdentityRejected)?;
        let mut state = self
            .replay_state
            .lock()
            .map_err(|_| ExecdSuiteOneServiceErrorV2::Unavailable)?;
        if state.replay.len() >= self.replay_capacity {
            return Err(ExecdSuiteOneServiceErrorV2::Busy);
        }
        if state.process_boots.iter().any(|entry| {
            entry.observed_peer == observed_peer && entry.client_boot_id != pending.client_boot_id()
        }) {
            return Err(ExecdSuiteOneServiceErrorV2::IdentityRejected);
        }
        let replay = HandshakeReplayKeyV2 {
            observed_peer,
            client_boot_id: pending.client_boot_id(),
            client_nonce: pending.client_nonce(),
        };
        if state.replay.iter().any(|entry| entry == &replay) {
            return Err(ExecdSuiteOneServiceErrorV2::Replay);
        }
        state
            .replay
            .try_reserve(1)
            .map_err(|_| ExecdSuiteOneServiceErrorV2::Unavailable)?;
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
            VerifiedV2HandshakePeer,
        ),
        ExecdSuiteOneServiceErrorV2,
    > {
        let (confirmation, session, peer) = pending
            .accept_client_finish(client_finish)
            .map_err(|_| ExecdSuiteOneServiceErrorV2::IdentityRejected)?;
        if peer.role() != EndpointRoleV2::KernelExecutor {
            return Err(ExecdSuiteOneServiceErrorV2::IdentityRejected);
        }
        let mut state = self
            .replay_state
            .lock()
            .map_err(|_| ExecdSuiteOneServiceErrorV2::Unavailable)?;
        if let Some(existing) = state
            .process_boots
            .iter()
            .find(|entry| entry.observed_peer == observed_peer)
        {
            if existing.client_boot_id != peer.client_boot_id() {
                return Err(ExecdSuiteOneServiceErrorV2::IdentityRejected);
            }
        } else {
            if state.process_boots.len() >= MAX_VERIFIED_PROCESS_BINDINGS_V2 {
                return Err(ExecdSuiteOneServiceErrorV2::Busy);
            }
            state
                .process_boots
                .try_reserve(1)
                .map_err(|_| ExecdSuiteOneServiceErrorV2::Unavailable)?;
            state.process_boots.push(VerifiedProcessBootV2 {
                observed_peer,
                client_boot_id: peer.client_boot_id(),
            });
        }
        Ok((confirmation, session, peer))
    }
}

fn executor_error_response(
    request_id: savana_kernel_protocol::v2::RequestIdV2,
    operation_tag: u16,
    code: PublicStableCodeV2,
) -> Result<KernelServiceApplicationResponseV2, ExecdSuiteOneServiceErrorV2> {
    KernelServiceApplicationResponseV2::error(
        EndpointRoleV2::KernelExecutor,
        request_id,
        operation_tag,
        if operation_tag == 0 {
            PublicStableCodeV2::ServiceUnavailable
        } else {
            code
        },
    )
    .map_err(|_| ExecdSuiteOneServiceErrorV2::Unavailable)
}

const fn map_service_error(
    operation_tag: u16,
    error: ExecdProtocolServiceErrorV2,
) -> PublicStableCodeV2 {
    match error {
        ExecdProtocolServiceErrorV2::Protocol | ExecdProtocolServiceErrorV2::Binding => {
            PublicStableCodeV2::InvalidReference
        }
        ExecdProtocolServiceErrorV2::ResultUnavailable => {
            if operation_tag == 61 {
                PublicStableCodeV2::InvalidReference
            } else {
                PublicStableCodeV2::ResultUnavailable
            }
        }
        ExecdProtocolServiceErrorV2::Owner(ExecdStateOwnerErrorV2::Busy) => {
            if operation_tag == 61 {
                PublicStableCodeV2::ServiceUnavailable
            } else {
                PublicStableCodeV2::Overloaded
            }
        }
        ExecdProtocolServiceErrorV2::Owner(ExecdStateOwnerErrorV2::DeadlineExceeded) => {
            PublicStableCodeV2::DeadlineExceeded
        }
        ExecdProtocolServiceErrorV2::Owner(
            ExecdStateOwnerErrorV2::Unavailable | ExecdStateOwnerErrorV2::Runtime(_),
        ) => PublicStableCodeV2::ServiceUnavailable,
    }
}

fn draw_nonzero() -> Result<[u8; 32], ExecdSuiteOneServiceErrorV2> {
    for _ in 0..4 {
        let mut bytes = [0_u8; 32];
        getrandom::getrandom(&mut bytes).map_err(|_| ExecdSuiteOneServiceErrorV2::Unavailable)?;
        if bytes != [0; 32] {
            return Ok(bytes);
        }
    }
    Err(ExecdSuiteOneServiceErrorV2::Unavailable)
}

#[derive(Debug, Clone, Copy)]
enum FrameKindV2 {
    Handshake,
    Record,
}

fn set_deadline(stream: &UnixStream, deadline: Instant) -> Result<(), ExecdSuiteOneServiceErrorV2> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(ExecdSuiteOneServiceErrorV2::DeadlineExceeded);
    }
    stream
        .set_read_timeout(Some(remaining))
        .and_then(|_| stream.set_write_timeout(Some(remaining)))
        .map_err(|_| ExecdSuiteOneServiceErrorV2::Unavailable)
}

fn read_handshake_frame(
    stream: &mut UnixStream,
    deadline: Instant,
) -> Result<Vec<u8>, ExecdSuiteOneServiceErrorV2> {
    set_deadline(stream, deadline)?;
    let mut header = [0_u8; HANDSHAKE_FRAME_HEADER_BYTES_V2];
    stream
        .read_exact(&mut header)
        .map_err(|_| ExecdSuiteOneServiceErrorV2::Malformed)?;
    if &header[..8] != HANDSHAKE_MAGIC_V2 {
        return Err(ExecdSuiteOneServiceErrorV2::Malformed);
    }
    let body_length = u32::from_be_bytes(
        header[HANDSHAKE_FRAME_HEADER_BYTES_V2 - 4..]
            .try_into()
            .map_err(|_| ExecdSuiteOneServiceErrorV2::Malformed)?,
    ) as usize;
    if body_length == 0 || body_length > MAX_HANDSHAKE_BODY_BYTES_V2 {
        return Err(ExecdSuiteOneServiceErrorV2::Malformed);
    }
    let total = HANDSHAKE_FRAME_HEADER_BYTES_V2
        .checked_add(body_length)
        .ok_or(ExecdSuiteOneServiceErrorV2::Malformed)?;
    let mut frame = Vec::new();
    frame
        .try_reserve_exact(total)
        .map_err(|_| ExecdSuiteOneServiceErrorV2::Unavailable)?;
    frame.extend_from_slice(&header);
    frame.resize(total, 0);
    stream
        .read_exact(&mut frame[HANDSHAKE_FRAME_HEADER_BYTES_V2..])
        .map_err(|_| ExecdSuiteOneServiceErrorV2::Malformed)?;
    Ok(frame)
}

fn read_record_frame(
    stream: &mut UnixStream,
    deadline: Instant,
) -> Result<Vec<u8>, ExecdSuiteOneServiceErrorV2> {
    set_deadline(stream, deadline)?;
    let mut header = [0_u8; RECORD_FRAME_HEADER_BYTES_V2];
    stream
        .read_exact(&mut header)
        .map_err(|_| ExecdSuiteOneServiceErrorV2::Malformed)?;
    let (header_length, ciphertext_length) = record_lengths(&header)?;
    let total = RECORD_FRAME_HEADER_BYTES_V2
        .checked_add(header_length)
        .and_then(|value| value.checked_add(ciphertext_length))
        .ok_or(ExecdSuiteOneServiceErrorV2::Malformed)?;
    let mut frame = Vec::new();
    frame
        .try_reserve_exact(total)
        .map_err(|_| ExecdSuiteOneServiceErrorV2::Unavailable)?;
    frame.extend_from_slice(&header);
    frame.resize(total, 0);
    stream
        .read_exact(&mut frame[RECORD_FRAME_HEADER_BYTES_V2..])
        .map_err(|_| ExecdSuiteOneServiceErrorV2::Malformed)?;
    Ok(frame)
}

fn write_frame(
    stream: &mut UnixStream,
    frame: &[u8],
    deadline: Instant,
    kind: FrameKindV2,
) -> Result<(), ExecdSuiteOneServiceErrorV2> {
    match kind {
        FrameKindV2::Handshake => {
            if frame.len() < HANDSHAKE_FRAME_HEADER_BYTES_V2 || &frame[..8] != HANDSHAKE_MAGIC_V2 {
                return Err(ExecdSuiteOneServiceErrorV2::Unavailable);
            }
        }
        FrameKindV2::Record => {
            if frame.len() < RECORD_FRAME_HEADER_BYTES_V2 {
                return Err(ExecdSuiteOneServiceErrorV2::Unavailable);
            }
            let (header_length, ciphertext_length) =
                record_lengths(&frame[..RECORD_FRAME_HEADER_BYTES_V2])?;
            if frame.len() != RECORD_FRAME_HEADER_BYTES_V2 + header_length + ciphertext_length {
                return Err(ExecdSuiteOneServiceErrorV2::Unavailable);
            }
        }
    }
    set_deadline(stream, deadline)?;
    stream
        .write_all(frame)
        .and_then(|_| stream.flush())
        .map_err(|_| ExecdSuiteOneServiceErrorV2::Unavailable)
}

fn record_lengths(header: &[u8]) -> Result<(usize, usize), ExecdSuiteOneServiceErrorV2> {
    if header.len() != RECORD_FRAME_HEADER_BYTES_V2 || &header[..4] != RECORD_MAGIC_V2 {
        return Err(ExecdSuiteOneServiceErrorV2::Malformed);
    }
    let header_length = usize::from(u16::from_be_bytes(
        header[4..6]
            .try_into()
            .map_err(|_| ExecdSuiteOneServiceErrorV2::Malformed)?,
    ));
    let ciphertext_length = u32::from_be_bytes(
        header[6..10]
            .try_into()
            .map_err(|_| ExecdSuiteOneServiceErrorV2::Malformed)?,
    ) as usize;
    if header_length == 0
        || header_length > MAX_RECORD_HEADER_BYTES_V2
        || !(16..=MAX_RECORD_CIPHERTEXT_BYTES_V2).contains(&ciphertext_length)
    {
        return Err(ExecdSuiteOneServiceErrorV2::Malformed);
    }
    Ok((header_length, ciphertext_length))
}

#[cfg(test)]
mod tests {
    use std::io::Read as _;
    use std::os::unix::net::UnixStream;
    use std::thread;
    use std::time::{Duration, Instant};

    use ed25519_dalek::SigningKey;
    use savana_kernel_protocol::v2::{
        decode_executor_health_response_v2, decode_kernel_service_application_response_v2,
        derive_ed25519_key_id_v2, encode_executor_health_response_v2,
        encode_kernel_service_application_request_v2, BootIdV2, Digest32V2, EndpointRoleV2,
        ExecutorHealthRequestV2, ExecutorHealthResponseV2, ExecutorIdentityV2, HpkeX25519KeyIdV2,
        KernelExecutorOperationV2, KernelServiceApplicationRequestV2,
        KernelServiceApplicationResponseBodyV2, KernelServiceHandshakeEdgeV2,
        KernelServiceOperationV2, Nonce32V2, PeerIdentityBindingV2, RequestIdV2, ServiceIdentityV2,
        UnixMillisV2, V2ClientHandshake,
    };
    use x25519_dalek::StaticSecret;

    use super::{
        read_handshake_frame, read_record_frame, write_frame, ExecdSuiteOneServerV2, FrameKindV2,
    };
    use crate::ExecdProtocolServiceErrorV2;

    fn edge(client_key: &SigningKey, server_key: &SigningKey) -> KernelServiceHandshakeEdgeV2 {
        KernelServiceHandshakeEdgeV2::from_verified_deployment(
            EndpointRoleV2::KernelExecutor,
            Digest32V2::new([1; 32]),
            ServiceIdentityV2::new([2; 32]),
            ServiceIdentityV2::new([3; 32]),
            derive_ed25519_key_id_v2(client_key.verifying_key().to_bytes()),
            derive_ed25519_key_id_v2(server_key.verifying_key().to_bytes()),
            BootIdV2::new([4; 32]),
            5,
            Digest32V2::new([6; 32]),
            7,
            8,
            Digest32V2::new([9; 32]),
            Digest32V2::new([10; 32]),
            Digest32V2::new([11; 32]),
            Digest32V2::new([12; 32]),
            Digest32V2::new([13; 32]),
            Digest32V2::new([14; 32]),
        )
        .unwrap()
    }

    fn observed() -> PeerIdentityBindingV2 {
        PeerIdentityBindingV2::linux(501, 502, 503, 504, Digest32V2::new([15; 32])).unwrap()
    }

    fn health_handler(
        operation: KernelExecutorOperationV2,
        _now: UnixMillisV2,
        _deadline: Instant,
    ) -> Result<Vec<u8>, ExecdProtocolServiceErrorV2> {
        assert!(matches!(
            operation,
            KernelExecutorOperationV2::Health(ExecutorHealthRequestV2)
        ));
        encode_executor_health_response_v2(
            &ExecutorHealthResponseV2::new(
                true,
                Digest32V2::new([16; 32]),
                7,
                8,
                ExecutorIdentityV2::new([17; 32]),
                HpkeX25519KeyIdV2::new([18; 32]),
                2,
                3,
                Digest32V2::new([19; 32]),
                0,
                None,
            )
            .unwrap(),
        )
        .map_err(|_| ExecdProtocolServiceErrorV2::Protocol)
    }

    #[test]
    fn suite_one_executor_server_authenticates_encrypts_dispatches_once_and_closes() {
        let client_key = SigningKey::from_bytes(&[0x21; 32]);
        let server_key = SigningKey::from_bytes(&[0x22; 32]);
        let server_public_key = server_key.verifying_key().to_bytes();
        let edge = edge(&client_key, &server_key);
        let server = ExecdSuiteOneServerV2::new_for_test(
            edge,
            client_key.verifying_key().to_bytes(),
            server_key,
            health_handler,
        );
        let (mut client_stream, server_stream) = UnixStream::pair().unwrap();
        let server_thread = thread::spawn(move || {
            server
                .serve_stream(
                    server_stream,
                    observed(),
                    UnixMillisV2::new(100),
                    Instant::now() + Duration::from_secs(2),
                )
                .unwrap();
        });
        let io_deadline = Instant::now() + Duration::from_secs(2);
        let (pending, hello) = V2ClientHandshake::start(
            edge,
            BootIdV2::new([0x23; 32]),
            Nonce32V2::new([0x24; 32]),
            observed(),
            StaticSecret::from([0x25; 32]),
            &client_key,
        )
        .unwrap();
        write_frame(
            &mut client_stream,
            &hello,
            io_deadline,
            FrameKindV2::Handshake,
        )
        .unwrap();
        let server_hello = read_handshake_frame(&mut client_stream, io_deadline).unwrap();
        let (finish, mut session) = pending
            .accept_server_hello(&server_hello, server_public_key, &client_key)
            .unwrap();
        write_frame(
            &mut client_stream,
            &finish,
            io_deadline,
            FrameKindV2::Handshake,
        )
        .unwrap();
        let confirmation = read_record_frame(&mut client_stream, io_deadline).unwrap();
        session.accept_server_confirmation(&confirmation).unwrap();

        let request_id = RequestIdV2::new([0x26; 16]);
        let request = KernelServiceApplicationRequestV2::new(
            EndpointRoleV2::KernelExecutor,
            request_id,
            UnixMillisV2::new(200),
            KernelServiceOperationV2::executor(KernelExecutorOperationV2::Health(
                ExecutorHealthRequestV2,
            )),
        )
        .unwrap();
        let plaintext = encode_kernel_service_application_request_v2(&request).unwrap();
        let record = session
            .seal_application_request(request_id, 0, &plaintext)
            .unwrap();
        write_frame(
            &mut client_stream,
            &record,
            io_deadline,
            FrameKindV2::Record,
        )
        .unwrap();
        let response_record = read_record_frame(&mut client_stream, io_deadline).unwrap();
        let opened = session.open_application_response(&response_record).unwrap();
        let response = decode_kernel_service_application_response_v2(
            opened.plaintext(),
            EndpointRoleV2::KernelExecutor,
            0,
        )
        .unwrap();
        let body = match response.body() {
            KernelServiceApplicationResponseBodyV2::Success(body) => body,
            KernelServiceApplicationResponseBodyV2::Error(code) => {
                panic!("unexpected executor health error: {code:?}")
            }
        };
        decode_executor_health_response_v2(body).unwrap();
        server_thread.join().unwrap();

        let mut trailing = [0_u8; 1];
        assert_eq!(client_stream.read(&mut trailing).unwrap(), 0);
    }
}
