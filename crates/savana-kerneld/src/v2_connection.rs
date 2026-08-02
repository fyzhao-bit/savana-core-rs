use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::time::Instant;

use savana_kernel_protocol::v2::{
    decode_kernel_service_application_request_v2, peek_kernel_service_application_request_v2,
    PeerIdentityBindingV2, PublicStableCodeV2, UnixMillisV2,
};

use crate::policy_runtime::V2GenerationLease;
use crate::v2_channel::{ChannelErrorV2, UnixV2FrameChannel, V2FrameChannel};
use crate::v2_dispatch::{
    KernelServiceDispatchErrorV2, KernelServiceDispatcherV2, SuiteOneResponseSessionSlotV2,
    VerifiedKernelServicePeerV2,
};
use crate::v2_transport_owner::{KernelV2HandshakeError, KernelV2HandshakeOwner};

const MAX_KERNEL_SERVICE_FRAME_BYTES: usize = 8 * 1024 * 1024 + 4 * 1024;

/// Serves exactly one already-authenticated V2 application request.
///
/// Handshake and OS-peer authentication happen before this boundary. The
/// stream is always consumed by value, emits at most one signed response, and
/// is shut down before the function returns.
pub(crate) fn serve_one_authenticated_v2_connection(
    mut stream: UnixStream,
    peer: VerifiedKernelServicePeerV2,
    lease: V2GenerationLease,
    dispatcher: &KernelServiceDispatcherV2,
    now: UnixMillisV2,
    deadline: Instant,
) -> Result<(), KernelServiceDispatchErrorV2> {
    let result = (|| {
        set_deadline(&stream, deadline)?;
        let request = read_one_frame(&mut stream)?;
        let response = dispatcher.dispatch_one_signed(peer, lease, &request, now, deadline)?;
        set_deadline(&stream, deadline)?;
        write_one_frame(&mut stream, &response)?;
        stream
            .flush()
            .map_err(|_| KernelServiceDispatchErrorV2::Unavailable)
    })();
    let _ = stream.shutdown(Shutdown::Both);
    result
}

/// Serves one complete mutually authenticated Suite-1 connection.
///
/// Handshake signing and replay state remain inside `handshake_owner`. Only
/// the connection-local traffic session is transferred to this worker after
/// mutual confirmation, and it can open one request and seal one response.
pub(crate) fn serve_one_suite_one_v2_connection(
    stream: UnixStream,
    observed_peer: PeerIdentityBindingV2,
    lease: V2GenerationLease,
    handshake_owner: &KernelV2HandshakeOwner,
    dispatcher: &KernelServiceDispatcherV2,
    now: UnixMillisV2,
    deadline: Instant,
) -> Result<(), KernelServiceDispatchErrorV2> {
    let mut channel = UnixV2FrameChannel::new(stream);
    let result = serve_one_suite_one_v2_channel(
        &mut channel,
        observed_peer,
        lease,
        handshake_owner,
        dispatcher,
        now,
        deadline,
    );
    channel.close();
    result
}

pub(crate) fn serve_one_suite_one_v2_channel(
    channel: &mut dyn V2FrameChannel,
    observed_peer: PeerIdentityBindingV2,
    lease: V2GenerationLease,
    handshake_owner: &KernelV2HandshakeOwner,
    dispatcher: &KernelServiceDispatcherV2,
    now: UnixMillisV2,
    deadline: Instant,
) -> Result<(), KernelServiceDispatchErrorV2> {
    (|| {
        let client_hello = channel
            .read_handshake_frame(deadline)
            .map_err(map_channel_error)?;
        let started = handshake_owner
            .start(observed_peer, client_hello, deadline)
            .map_err(map_handshake_error)?;

        channel
            .write_handshake_frame(started.server_hello(), deadline)
            .map_err(map_channel_error)?;

        let client_finish = channel
            .read_handshake_frame(deadline)
            .map_err(map_channel_error)?;
        let completed = handshake_owner
            .finish(started, client_finish, deadline)
            .map_err(map_handshake_error)?;
        let (accepted_record, mut session, handshake_peer) = completed.into_parts();
        let peer = VerifiedKernelServicePeerV2::from_mutual_authentication(
            handshake_peer.role(),
            handshake_peer.client_boot_id(),
            handshake_peer.client_identity(),
        )?;

        channel
            .write_record_frame(&accepted_record, deadline)
            .map_err(map_channel_error)?;

        let request_record = channel
            .read_record_frame(deadline)
            .map_err(map_channel_error)?;
        let opened = session
            .open_application_request(&request_record)
            .map_err(|_| KernelServiceDispatchErrorV2::Malformed)?;
        let routing = peek_kernel_service_application_request_v2(opened.plaintext())
            .map_err(|_| KernelServiceDispatchErrorV2::Malformed)?;
        if routing.request_id() != opened.request_id()
            || routing.operation_tag() != opened.operation_tag()
            || routing.role() != handshake_peer.role()
        {
            return Err(KernelServiceDispatchErrorV2::IdentityRejected);
        }
        let request = decode_kernel_service_application_request_v2(opened.plaintext())
            .map_err(|_| KernelServiceDispatchErrorV2::Malformed)?;
        let response_session = SuiteOneResponseSessionSlotV2::new(session);
        let response_record = match dispatcher.dispatch_one_suite_one(
            peer,
            lease,
            request,
            response_session.clone(),
            now,
            deadline,
        ) {
            Ok(record) => record,
            Err(KernelServiceDispatchErrorV2::Busy) => response_session.seal_public_error(
                routing.role(),
                routing.request_id(),
                routing.operation_tag(),
                PublicStableCodeV2::Overloaded,
            )?,
            Err(KernelServiceDispatchErrorV2::DeadlineExceeded) => response_session
                .cancel_staged_and_seal_public_error(
                    routing.role(),
                    routing.request_id(),
                    routing.operation_tag(),
                    PublicStableCodeV2::DeadlineExceeded,
                )
                .map_err(|_| KernelServiceDispatchErrorV2::DeadlineExceeded)?,
            Err(KernelServiceDispatchErrorV2::Unavailable) => response_session.seal_public_error(
                routing.role(),
                routing.request_id(),
                routing.operation_tag(),
                PublicStableCodeV2::ServiceUnavailable,
            )?,
            Err(
                KernelServiceDispatchErrorV2::Malformed
                | KernelServiceDispatchErrorV2::IdentityRejected
                | KernelServiceDispatchErrorV2::Operation(_),
            ) => return Err(KernelServiceDispatchErrorV2::IdentityRejected),
        };

        channel
            .write_record_frame(&response_record, deadline)
            .map_err(map_channel_error)
    })()
}

fn set_deadline(
    stream: &UnixStream,
    deadline: Instant,
) -> Result<(), KernelServiceDispatchErrorV2> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(KernelServiceDispatchErrorV2::DeadlineExceeded);
    }
    stream
        .set_read_timeout(Some(remaining))
        .and_then(|_| stream.set_write_timeout(Some(remaining)))
        .map_err(|_| KernelServiceDispatchErrorV2::Unavailable)
}

fn read_one_frame(stream: &mut UnixStream) -> Result<Vec<u8>, KernelServiceDispatchErrorV2> {
    let mut header = [0_u8; 4];
    stream
        .read_exact(&mut header)
        .map_err(|_| KernelServiceDispatchErrorV2::Malformed)?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > MAX_KERNEL_SERVICE_FRAME_BYTES {
        return Err(KernelServiceDispatchErrorV2::Malformed);
    }
    let mut body = Vec::new();
    body.try_reserve_exact(length)
        .map_err(|_| KernelServiceDispatchErrorV2::Unavailable)?;
    body.resize(length, 0);
    stream
        .read_exact(&mut body)
        .map_err(|_| KernelServiceDispatchErrorV2::Malformed)?;
    Ok(body)
}

fn write_one_frame(
    stream: &mut UnixStream,
    payload: &[u8],
) -> Result<(), KernelServiceDispatchErrorV2> {
    if payload.is_empty() || payload.len() > MAX_KERNEL_SERVICE_FRAME_BYTES {
        return Err(KernelServiceDispatchErrorV2::Unavailable);
    }
    let length =
        u32::try_from(payload.len()).map_err(|_| KernelServiceDispatchErrorV2::Unavailable)?;
    stream
        .write_all(&length.to_be_bytes())
        .and_then(|_| stream.write_all(payload))
        .map_err(|_| KernelServiceDispatchErrorV2::Unavailable)
}

const fn map_channel_error(error: ChannelErrorV2) -> KernelServiceDispatchErrorV2 {
    match error {
        ChannelErrorV2::Malformed => KernelServiceDispatchErrorV2::Malformed,
        ChannelErrorV2::DeadlineExceeded => KernelServiceDispatchErrorV2::DeadlineExceeded,
        ChannelErrorV2::Unavailable => KernelServiceDispatchErrorV2::Unavailable,
    }
}

const fn map_handshake_error(error: KernelV2HandshakeError) -> KernelServiceDispatchErrorV2 {
    match error {
        KernelV2HandshakeError::Malformed | KernelV2HandshakeError::Replay => {
            KernelServiceDispatchErrorV2::Malformed
        }
        KernelV2HandshakeError::IdentityRejected => KernelServiceDispatchErrorV2::IdentityRejected,
        KernelV2HandshakeError::Busy => KernelServiceDispatchErrorV2::Busy,
        KernelV2HandshakeError::DeadlineExceeded => KernelServiceDispatchErrorV2::DeadlineExceeded,
        KernelV2HandshakeError::Unavailable => KernelServiceDispatchErrorV2::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, Instant};

    use ed25519_dalek::SigningKey;
    use savana_kernel_protocol::v2::{
        decode_kernel_service_application_response_v2, derive_ed25519_key_id_v2,
        encode_kernel_service_application_request_v2, encode_kernel_service_request_envelope_v2,
        verify_kernel_service_response_envelope_v2, BootIdV2, Digest32V2,
        DispatchExecutionRequestV2, Ed25519KeyIdV2, EndpointRoleV2, ExecutionTicketHandleV2,
        KernelAgentOperationV2, KernelServiceApplicationRequestV2,
        KernelServiceApplicationResponseBodyV2, KernelServiceHandshakeEdgeV2,
        KernelServiceOperationV2, KernelServiceRequestEnvelopeV2, Nonce32V2, PeerIdentityBindingV2,
        RequestIdV2, ServiceIdentityV2, UnixMillisV2, V2ClientHandshake,
    };
    use x25519_dalek::StaticSecret;

    use super::{serve_one_authenticated_v2_connection, serve_one_suite_one_v2_connection};
    use crate::policy_runtime::V2GenerationLease;
    use crate::v2_channel::{UnixV2FrameChannel, V2FrameChannel};
    use crate::v2_dispatch::{
        KernelServiceDeploymentV2, KernelServiceDispatchErrorV2, KernelServiceDispatcherV2,
        KernelServiceResponseBodyV2, VerifiedKernelServicePeerV2,
    };
    use crate::v2_kernel_owner::KernelRuntimeOwnerV2;
    use crate::v2_transport_owner::KernelV2HandshakeOwner;

    fn agent_dispatch_operation() -> KernelServiceOperationV2 {
        KernelServiceOperationV2::agent(KernelAgentOperationV2::DispatchExecution(
            DispatchExecutionRequestV2::new(
                ExecutionTicketHandleV2::from_authority_entropy([29; 32]).unwrap(),
            ),
        ))
    }

    #[test]
    fn connection_processes_one_request_writes_one_signed_response_and_closes() {
        let key_id = Ed25519KeyIdV2::new([8; 32]);
        let key = SigningKey::from_bytes(&[9; 32]);
        let public_key = key.verifying_key().to_bytes();
        let calls = Arc::new(AtomicUsize::new(0));
        let handled = Arc::clone(&calls);
        let owner = KernelRuntimeOwnerV2::spawn_for_test(4, move |_| {
            handled.fetch_add(1, Ordering::SeqCst);
            Ok(KernelServiceResponseBodyV2::from_typed_handler(vec![0x80]).unwrap())
        })
        .unwrap();
        let dispatcher = Arc::new(
            KernelServiceDispatcherV2::spawn(
                KernelServiceDeploymentV2::from_verified_startup(
                    BootIdV2::new([1; 32]),
                    ServiceIdentityV2::new([2; 32]),
                    Digest32V2::new([3; 32]),
                    4,
                )
                .unwrap(),
                key_id,
                key,
                owner,
            )
            .unwrap(),
        );
        let peer = VerifiedKernelServicePeerV2::from_mutual_authentication(
            EndpointRoleV2::AgentKernel,
            BootIdV2::new([5; 32]),
            ServiceIdentityV2::new([6; 32]),
        )
        .unwrap();
        let request = encode_kernel_service_request_envelope_v2(
            &KernelServiceRequestEnvelopeV2::from_authenticated_connection(
                EndpointRoleV2::AgentKernel,
                RequestIdV2::new([7; 16]),
                BootIdV2::new([5; 32]),
                BootIdV2::new([1; 32]),
                ServiceIdentityV2::new([6; 32]),
                ServiceIdentityV2::new([2; 32]),
                Digest32V2::new([3; 32]),
                4,
                UnixMillisV2::new(1_000),
                agent_dispatch_operation(),
            )
            .unwrap(),
        )
        .unwrap();
        let (mut client, server) = UnixStream::pair().unwrap();
        let serving = Arc::clone(&dispatcher);
        let server_thread = thread::spawn(move || {
            serve_one_authenticated_v2_connection(
                server,
                peer,
                V2GenerationLease::for_dispatch_test(Digest32V2::new([3; 32]), 4),
                serving.as_ref(),
                UnixMillisV2::new(100),
                Instant::now() + Duration::from_secs(2),
            )
        });

        for _ in 0..2 {
            client
                .write_all(&(request.len() as u32).to_be_bytes())
                .unwrap();
            client.write_all(&request).unwrap();
        }
        let mut header = [0_u8; 4];
        client.read_exact(&mut header).unwrap();
        let mut response = vec![0; u32::from_be_bytes(header) as usize];
        client.read_exact(&mut response).unwrap();
        let decoded =
            verify_kernel_service_response_envelope_v2(&response, key_id, public_key).unwrap();
        assert_eq!(decoded.operation_tag(), 29);
        let mut eof = [0_u8; 1];
        // The second request above is written deliberately and never read: the
        // server answers exactly one and closes. Closing a stream socket that
        // still holds unread data resets the connection on Linux and reports a
        // clean EOF on macOS, so accept either. Both say the server closed
        // after one response without consuming the second request.
        match client.read(&mut eof) {
            Ok(read) => assert_eq!(read, 0),
            Err(error) => assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset),
        }
        assert_eq!(server_thread.join().unwrap(), Ok(()));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn suite_one_connection_authenticates_encrypts_dispatches_once_and_closes() {
        let client_key = SigningKey::from_bytes(&[0x31; 32]);
        let server_key = SigningKey::from_bytes(&[0x32; 32]);
        let server_public_key = server_key.verifying_key().to_bytes();
        let edge = KernelServiceHandshakeEdgeV2::from_verified_deployment(
            EndpointRoleV2::AgentKernel,
            Digest32V2::new([1; 32]),
            ServiceIdentityV2::new([2; 32]),
            ServiceIdentityV2::new([3; 32]),
            derive_ed25519_key_id_v2(client_key.verifying_key().to_bytes()),
            derive_ed25519_key_id_v2(server_public_key),
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
        .unwrap();
        let observed =
            PeerIdentityBindingV2::linux(501, 502, 503, 504, Digest32V2::new([15; 32])).unwrap();
        let handshake_owner = Arc::new(
            KernelV2HandshakeOwner::spawn(
                edge,
                client_key.verifying_key().to_bytes(),
                server_key,
                4,
            )
            .unwrap(),
        );
        let calls = Arc::new(AtomicUsize::new(0));
        let handled = Arc::clone(&calls);
        let owner = KernelRuntimeOwnerV2::spawn_for_test(4, move |_| {
            handled.fetch_add(1, Ordering::SeqCst);
            Ok(KernelServiceResponseBodyV2::from_typed_handler(vec![0x80]).unwrap())
        })
        .unwrap();
        let dispatcher = Arc::new(
            KernelServiceDispatcherV2::spawn(
                KernelServiceDeploymentV2::from_verified_startup(
                    BootIdV2::new([4; 32]),
                    ServiceIdentityV2::new([3; 32]),
                    Digest32V2::new([6; 32]),
                    7,
                )
                .unwrap(),
                Ed25519KeyIdV2::new([16; 32]),
                SigningKey::from_bytes(&[17; 32]),
                owner,
            )
            .unwrap(),
        );
        let (client, server) = UnixStream::pair().unwrap();
        let mut client_channel = UnixV2FrameChannel::new(client);
        let serving_owner = Arc::clone(&handshake_owner);
        let serving_dispatcher = Arc::clone(&dispatcher);
        let server_observed = observed.clone();
        let server_thread = thread::spawn(move || {
            serve_one_suite_one_v2_connection(
                server,
                server_observed,
                V2GenerationLease::for_dispatch_test(Digest32V2::new([6; 32]), 7),
                serving_owner.as_ref(),
                serving_dispatcher.as_ref(),
                UnixMillisV2::new(100),
                Instant::now() + Duration::from_secs(2),
            )
        });

        let (client_pending, hello) = V2ClientHandshake::start(
            edge,
            BootIdV2::new([0x33; 32]),
            Nonce32V2::new([0x34; 32]),
            observed,
            StaticSecret::from([0x35; 32]),
            &client_key,
        )
        .unwrap();
        client_channel
            .write_handshake_frame(&hello, Instant::now() + Duration::from_secs(2))
            .unwrap();
        let server_hello = client_channel
            .read_handshake_frame(Instant::now() + Duration::from_secs(2))
            .unwrap();
        let (finish, mut session) = client_pending
            .accept_server_hello(&server_hello, server_public_key, &client_key)
            .unwrap();
        client_channel
            .write_handshake_frame(&finish, Instant::now() + Duration::from_secs(2))
            .unwrap();
        let accepted = client_channel
            .read_record_frame(Instant::now() + Duration::from_secs(2))
            .unwrap();
        session.accept_server_confirmation(&accepted).unwrap();

        let request_id = RequestIdV2::new([0x36; 16]);
        let request = KernelServiceApplicationRequestV2::new(
            EndpointRoleV2::AgentKernel,
            request_id,
            UnixMillisV2::new(1_000),
            agent_dispatch_operation(),
        )
        .unwrap();
        let request_bytes = encode_kernel_service_application_request_v2(&request).unwrap();
        let request_record = session
            .seal_application_request(request_id, 29, &request_bytes)
            .unwrap();
        client_channel
            .write_record_frame(&request_record, Instant::now() + Duration::from_secs(2))
            .unwrap();
        let response_record = client_channel
            .read_record_frame(Instant::now() + Duration::from_secs(2))
            .unwrap();
        let opened = session.open_application_response(&response_record).unwrap();
        let response = decode_kernel_service_application_response_v2(
            opened.plaintext(),
            EndpointRoleV2::AgentKernel,
            29,
        )
        .unwrap();
        assert!(matches!(
            response.body(),
            KernelServiceApplicationResponseBodyV2::Success(body) if body == &[0x80]
        ));
        let mut client = client_channel.into_inner();
        let mut eof = [0_u8; 1];
        assert_eq!(client.read(&mut eof).unwrap(), 0);
        assert_eq!(server_thread.join().unwrap(), Ok(()));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn v1_prefix_gets_no_response_and_never_reaches_suite_one_dispatch() {
        let client_key = SigningKey::from_bytes(&[0x41; 32]);
        let server_key = SigningKey::from_bytes(&[0x42; 32]);
        let edge = KernelServiceHandshakeEdgeV2::from_verified_deployment(
            EndpointRoleV2::AgentKernel,
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
        .unwrap();
        let handshake_owner = Arc::new(
            KernelV2HandshakeOwner::spawn(
                edge,
                client_key.verifying_key().to_bytes(),
                server_key,
                4,
            )
            .unwrap(),
        );
        let calls = Arc::new(AtomicUsize::new(0));
        let handled = Arc::clone(&calls);
        let owner = KernelRuntimeOwnerV2::spawn_for_test(4, move |_| {
            handled.fetch_add(1, Ordering::SeqCst);
            Ok(KernelServiceResponseBodyV2::from_typed_handler(vec![0x80]).unwrap())
        })
        .unwrap();
        let dispatcher = Arc::new(
            KernelServiceDispatcherV2::spawn(
                KernelServiceDeploymentV2::from_verified_startup(
                    BootIdV2::new([4; 32]),
                    ServiceIdentityV2::new([3; 32]),
                    Digest32V2::new([6; 32]),
                    7,
                )
                .unwrap(),
                Ed25519KeyIdV2::new([16; 32]),
                SigningKey::from_bytes(&[17; 32]),
                owner,
            )
            .unwrap(),
        );
        let observed =
            PeerIdentityBindingV2::linux(501, 502, 503, 504, Digest32V2::new([15; 32])).unwrap();
        let (mut client, server) = UnixStream::pair().unwrap();
        let server_thread = thread::spawn(move || {
            serve_one_suite_one_v2_connection(
                server,
                observed,
                V2GenerationLease::for_dispatch_test(Digest32V2::new([6; 32]), 7),
                handshake_owner.as_ref(),
                dispatcher.as_ref(),
                UnixMillisV2::new(100),
                Instant::now() + Duration::from_secs(2),
            )
        });

        client.write_all(b"SAVANA1\0").unwrap();
        client.write_all(&[0_u8; 12]).unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        let mut byte = [0_u8; 1];
        assert_eq!(client.read(&mut byte).unwrap(), 0);
        assert_eq!(
            server_thread.join().unwrap(),
            Err(KernelServiceDispatchErrorV2::Malformed)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}
