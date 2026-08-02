use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use savana_kernel_protocol::v2::{
    decode_acknowledge_committed_completion_response_v2,
    decode_connector_registry_sync_response_v2, decode_dispatch_response_v2,
    decode_fetch_completion_response_v2, decode_kernel_service_application_response_v2,
    decode_query_by_execution_nonce_response_v2, encode_kernel_service_application_request_v2,
    AcknowledgeCommittedCompletionRequestV2, AcknowledgeCommittedCompletionResponseV2, BootIdV2,
    ConnectorRegistrySyncRequestV2, ConnectorRegistrySyncResponseV2, DispatchRequestV2,
    DispatchResponseV2, EndpointRoleV2, FetchCompletionRequestV2, FetchCompletionResponseV2,
    KernelExecutorOperationV2, KernelServiceApplicationRequestV2,
    KernelServiceApplicationResponseBodyV2, KernelServiceHandshakeEdgeV2, KernelServiceOperationV2,
    Nonce32V2, PeerIdentityBindingV2, PublicStableCodeV2, QueryByExecutionNonceRequestV2,
    QueryByExecutionNonceResponseV2, RequestIdV2, UnixMillisV2, V2ClientHandshake,
};
use x25519_dalek::StaticSecret;

use crate::v2_channel::{UnixV2FrameChannel, V2FrameChannel};

const KERNEL_EXECUTOR_SOCKET_PATH_V2: &str = "/run/savana/execd/kerneld/execd.sock";
const MAX_CONNECTION_DURATION_V2: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum KernelExecutorClientErrorV2 {
    #[error("kernel executor request deadline was exceeded")]
    DeadlineExceeded,
    #[error("kernel executor rejected the request")]
    Remote(PublicStableCodeV2),
    #[error("kernel executor connection is unavailable")]
    Unavailable,
}

/// The only kerneld-to-execd client. Every call uses one fresh Suite-1
/// connection and closes after one authenticated response.
pub(crate) struct SuiteOneKernelExecutorClientV2 {
    edge: KernelServiceHandshakeEdgeV2,
    client_boot_id: BootIdV2,
    expected_observed_peer: PeerIdentityBindingV2,
    client_signing_key: SigningKey,
    server_public_key: [u8; 32],
    socket_path: PathBuf,
}

impl std::fmt::Debug for SuiteOneKernelExecutorClientV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SuiteOneKernelExecutorClientV2(<deployment-bound-keys-redacted>)")
    }
}

impl SuiteOneKernelExecutorClientV2 {
    pub(crate) fn from_verified_deployment(
        edge: KernelServiceHandshakeEdgeV2,
        client_boot_id: BootIdV2,
        expected_observed_peer: PeerIdentityBindingV2,
        client_signing_key: SigningKey,
        server_public_key: [u8; 32],
    ) -> Result<Self, KernelExecutorClientErrorV2> {
        if edge.role() != EndpointRoleV2::KernelExecutor
            || client_boot_id.as_bytes() == &[0; 32]
            || server_public_key == [0; 32]
        {
            return Err(KernelExecutorClientErrorV2::Unavailable);
        }
        Ok(Self {
            edge,
            client_boot_id,
            expected_observed_peer,
            client_signing_key,
            server_public_key,
            socket_path: PathBuf::from(KERNEL_EXECUTOR_SOCKET_PATH_V2),
        })
    }

    // Retained for tests that need to redirect the fixed production socket
    // path; no current test exercises it.
    #[cfg(test)]
    #[allow(dead_code)]
    fn with_socket_path_for_test(mut self, socket_path: PathBuf) -> Self {
        self.socket_path = socket_path;
        self
    }

    pub(crate) fn dispatch(
        &self,
        request_id: RequestIdV2,
        deadline: UnixMillisV2,
        request: DispatchRequestV2,
    ) -> Result<DispatchResponseV2, KernelExecutorClientErrorV2> {
        let body = self.exchange(
            request_id,
            deadline,
            KernelExecutorOperationV2::Dispatch(request),
        )?;
        decode_dispatch_response_v2(&body).map_err(|_| KernelExecutorClientErrorV2::Unavailable)
    }

    pub(crate) fn query(
        &self,
        request_id: RequestIdV2,
        deadline: UnixMillisV2,
        request: QueryByExecutionNonceRequestV2,
    ) -> Result<QueryByExecutionNonceResponseV2, KernelExecutorClientErrorV2> {
        let body = self.exchange(
            request_id,
            deadline,
            KernelExecutorOperationV2::QueryByExecutionNonce(request),
        )?;
        decode_query_by_execution_nonce_response_v2(&body)
            .map_err(|_| KernelExecutorClientErrorV2::Unavailable)
    }

    pub(crate) fn acknowledge(
        &self,
        request_id: RequestIdV2,
        deadline: UnixMillisV2,
        request: AcknowledgeCommittedCompletionRequestV2,
    ) -> Result<AcknowledgeCommittedCompletionResponseV2, KernelExecutorClientErrorV2> {
        let body = self.exchange(
            request_id,
            deadline,
            KernelExecutorOperationV2::AcknowledgeCommittedCompletion(request),
        )?;
        decode_acknowledge_committed_completion_response_v2(&body)
            .map_err(|_| KernelExecutorClientErrorV2::Unavailable)
    }

    pub(crate) fn fetch_completion(
        &self,
        request_id: RequestIdV2,
        deadline: UnixMillisV2,
        request: FetchCompletionRequestV2,
    ) -> Result<FetchCompletionResponseV2, KernelExecutorClientErrorV2> {
        let body = self.exchange(
            request_id,
            deadline,
            KernelExecutorOperationV2::FetchCompletion(request),
        )?;
        decode_fetch_completion_response_v2(&body)
            .map_err(|_| KernelExecutorClientErrorV2::Unavailable)
    }

    pub(crate) fn synchronize_connector_registry(
        &self,
        request_id: RequestIdV2,
        deadline: UnixMillisV2,
        request: ConnectorRegistrySyncRequestV2,
    ) -> Result<ConnectorRegistrySyncResponseV2, KernelExecutorClientErrorV2> {
        let body = self.exchange(
            request_id,
            deadline,
            KernelExecutorOperationV2::ConnectorRegistrySync(request),
        )?;
        decode_connector_registry_sync_response_v2(&body)
            .map_err(|_| KernelExecutorClientErrorV2::Unavailable)
    }

    #[cfg(test)]
    fn synchronize_connector_registry_over_stream_for_test(
        &self,
        stream: UnixStream,
        request_id: RequestIdV2,
        deadline: UnixMillisV2,
        io_deadline: Instant,
        request: ConnectorRegistrySyncRequestV2,
    ) -> Result<ConnectorRegistrySyncResponseV2, KernelExecutorClientErrorV2> {
        let body = self.exchange_over_stream(
            stream,
            request_id,
            deadline,
            io_deadline,
            KernelExecutorOperationV2::ConnectorRegistrySync(request),
        )?;
        decode_connector_registry_sync_response_v2(&body)
            .map_err(|_| KernelExecutorClientErrorV2::Unavailable)
    }

    fn exchange(
        &self,
        request_id: RequestIdV2,
        deadline: UnixMillisV2,
        operation: KernelExecutorOperationV2,
    ) -> Result<Vec<u8>, KernelExecutorClientErrorV2> {
        let io_deadline = io_deadline(deadline)?;
        let stream = UnixStream::connect(&self.socket_path)
            .map_err(|_| KernelExecutorClientErrorV2::Unavailable)?;
        self.exchange_over_stream(stream, request_id, deadline, io_deadline, operation)
    }

    fn exchange_over_stream(
        &self,
        stream: UnixStream,
        request_id: RequestIdV2,
        deadline: UnixMillisV2,
        io_deadline: Instant,
        operation: KernelExecutorOperationV2,
    ) -> Result<Vec<u8>, KernelExecutorClientErrorV2> {
        let mut channel = UnixV2FrameChannel::new(stream);
        let result = (|| {
            let client_nonce = Nonce32V2::new(draw_nonzero()?);
            let ephemeral_secret = StaticSecret::from(draw_nonzero()?);
            let (pending, hello) = V2ClientHandshake::start(
                self.edge,
                self.client_boot_id,
                client_nonce,
                self.expected_observed_peer.clone(),
                ephemeral_secret,
                &self.client_signing_key,
            )
            .map_err(|_| KernelExecutorClientErrorV2::Unavailable)?;
            channel
                .write_handshake_frame(&hello, io_deadline)
                .map_err(|_| KernelExecutorClientErrorV2::Unavailable)?;
            let server_hello = channel
                .read_handshake_frame(io_deadline)
                .map_err(|_| KernelExecutorClientErrorV2::Unavailable)?;
            let (finish, mut session) = pending
                .accept_server_hello(
                    &server_hello,
                    self.server_public_key,
                    &self.client_signing_key,
                )
                .map_err(|_| KernelExecutorClientErrorV2::Unavailable)?;
            channel
                .write_handshake_frame(&finish, io_deadline)
                .map_err(|_| KernelExecutorClientErrorV2::Unavailable)?;
            let confirmation = channel
                .read_record_frame(io_deadline)
                .map_err(|_| KernelExecutorClientErrorV2::Unavailable)?;
            session
                .accept_server_confirmation(&confirmation)
                .map_err(|_| KernelExecutorClientErrorV2::Unavailable)?;

            let operation_tag = operation.tag();
            let request = KernelServiceApplicationRequestV2::new(
                EndpointRoleV2::KernelExecutor,
                request_id,
                deadline,
                KernelServiceOperationV2::executor(operation),
            )
            .map_err(|_| KernelExecutorClientErrorV2::Unavailable)?;
            let plaintext = encode_kernel_service_application_request_v2(&request)
                .map_err(|_| KernelExecutorClientErrorV2::Unavailable)?;
            let record = session
                .seal_application_request(request_id, operation_tag, &plaintext)
                .map_err(|_| KernelExecutorClientErrorV2::Unavailable)?;
            channel
                .write_record_frame(&record, io_deadline)
                .map_err(|_| KernelExecutorClientErrorV2::Unavailable)?;
            let response_record = channel
                .read_record_frame(io_deadline)
                .map_err(|_| KernelExecutorClientErrorV2::Unavailable)?;
            let opened = session
                .open_application_response(&response_record)
                .map_err(|_| KernelExecutorClientErrorV2::Unavailable)?;
            let response = decode_kernel_service_application_response_v2(
                opened.plaintext(),
                EndpointRoleV2::KernelExecutor,
                operation_tag,
            )
            .map_err(|_| KernelExecutorClientErrorV2::Unavailable)?;
            if response.request_id() != request_id || response.operation_tag() != operation_tag {
                return Err(KernelExecutorClientErrorV2::Unavailable);
            }
            match response.body() {
                KernelServiceApplicationResponseBodyV2::Success(body) => Ok(body.to_vec()),
                KernelServiceApplicationResponseBodyV2::Error(
                    PublicStableCodeV2::DeadlineExceeded,
                ) => Err(KernelExecutorClientErrorV2::DeadlineExceeded),
                KernelServiceApplicationResponseBodyV2::Error(code) => {
                    Err(KernelExecutorClientErrorV2::Remote(*code))
                }
            }
        })();
        channel.close();
        result
    }
}

fn io_deadline(deadline: UnixMillisV2) -> Result<Instant, KernelExecutorClientErrorV2> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| KernelExecutorClientErrorV2::Unavailable)?;
    let now_millis =
        u64::try_from(now.as_millis()).map_err(|_| KernelExecutorClientErrorV2::Unavailable)?;
    let remaining_millis = deadline
        .get()
        .checked_sub(now_millis)
        .ok_or(KernelExecutorClientErrorV2::DeadlineExceeded)?;
    if remaining_millis == 0 {
        return Err(KernelExecutorClientErrorV2::DeadlineExceeded);
    }
    Ok(Instant::now() + Duration::from_millis(remaining_millis).min(MAX_CONNECTION_DURATION_V2))
}

fn draw_nonzero() -> Result<[u8; 32], KernelExecutorClientErrorV2> {
    for _ in 0..4 {
        let mut bytes = [0_u8; 32];
        getrandom::getrandom(&mut bytes).map_err(|_| KernelExecutorClientErrorV2::Unavailable)?;
        if bytes != [0; 32] {
            return Ok(bytes);
        }
    }
    Err(KernelExecutorClientErrorV2::Unavailable)
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixStream;
    use std::thread;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use ed25519_dalek::SigningKey;
    use savana_kernel_protocol::v2::{
        decode_kernel_service_application_request_v2, decode_query_by_execution_nonce_response_v2,
        derive_ed25519_key_id_v2, encode_connector_registry_sync_response_v2,
        encode_kernel_service_application_response_v2, encode_query_by_execution_nonce_response_v2,
        BootIdV2, ConnectorRegistrySyncModeV2, ConnectorRegistrySyncRequestV2,
        ConnectorRegistrySyncResponseV2, ConnectorRegistrySyncScopeV2,
        ConnectorRegistrySyncStatusV2, Digest32V2, Ed25519KeyIdV2, EndpointRoleV2,
        ExecutorStatusV2, FixedBytes32V2, KernelExecutorOperationV2,
        KernelServiceApplicationResponseV2, KernelServiceHandshakeEdgeV2, Nonce32V2,
        PeerIdentityBindingV2, QueryByExecutionNonceRequestV2, QueryByExecutionNonceResponseV2,
        RequestIdV2, ServiceIdentityV2, UnixMillisV2, V2ServerHandshake,
    };
    use x25519_dalek::StaticSecret;

    use super::SuiteOneKernelExecutorClientV2;
    use crate::v2_channel::{UnixV2FrameChannel, V2FrameChannel};

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

    fn wall_clock_deadline() -> UnixMillisV2 {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        UnixMillisV2::new(u64::try_from(now.as_millis()).unwrap() + 2_000)
    }

    #[test]
    fn fixed_kernel_executor_client_verifies_encrypted_query_response_binding() {
        let client_key = SigningKey::from_bytes(&[0x21; 32]);
        let server_key = SigningKey::from_bytes(&[0x22; 32]);
        let server_public_key = server_key.verifying_key().to_bytes();
        let edge = edge(&client_key, &server_key);
        let client = SuiteOneKernelExecutorClientV2::from_verified_deployment(
            edge,
            BootIdV2::new([0x23; 32]),
            observed(),
            client_key.clone(),
            server_public_key,
        )
        .unwrap();
        let (client_stream, server_stream) = UnixStream::pair().unwrap();
        let io_deadline = Instant::now() + Duration::from_secs(2);
        let request_id = RequestIdV2::new([0x24; 16]);
        let operation = KernelExecutorOperationV2::QueryByExecutionNonce(
            QueryByExecutionNonceRequestV2::new(
                Nonce32V2::new([0x25; 32]),
                Digest32V2::new([0x26; 32]),
                Digest32V2::new([0x27; 32]),
            )
            .unwrap(),
        );

        let server = thread::spawn(move || {
            let mut channel = UnixV2FrameChannel::new(server_stream);
            let hello = channel.read_handshake_frame(io_deadline).unwrap();
            let (pending, server_hello) = V2ServerHandshake::accept_client_hello(
                edge,
                observed(),
                &hello,
                Nonce32V2::new([0x28; 32]),
                StaticSecret::from([0x29; 32]),
                client_key.verifying_key().to_bytes(),
                &server_key,
            )
            .unwrap();
            channel
                .write_handshake_frame(&server_hello, io_deadline)
                .unwrap();
            let finish = channel.read_handshake_frame(io_deadline).unwrap();
            let (confirmation, mut session, _) = pending.accept_client_finish(&finish).unwrap();
            channel
                .write_record_frame(&confirmation, io_deadline)
                .unwrap();
            let record = channel.read_record_frame(io_deadline).unwrap();
            let opened = session.open_application_request(&record).unwrap();
            let request = decode_kernel_service_application_request_v2(opened.plaintext()).unwrap();
            assert_eq!(request.operation().tag(), 61);
            assert_eq!(request.request_id(), request_id);
            let body = encode_query_by_execution_nonce_response_v2(
                &QueryByExecutionNonceResponseV2::new(ExecutorStatusV2::Prepared),
            )
            .unwrap();
            let response = KernelServiceApplicationResponseV2::success(
                EndpointRoleV2::KernelExecutor,
                request_id,
                61,
                body,
            )
            .unwrap();
            let plaintext = encode_kernel_service_application_response_v2(&response).unwrap();
            let record = session
                .seal_application_response(request_id, 61, &plaintext)
                .unwrap();
            channel.write_record_frame(&record, io_deadline).unwrap();
            channel.close();
        });
        let body = client
            .exchange_over_stream(
                client_stream,
                request_id,
                wall_clock_deadline(),
                io_deadline,
                operation,
            )
            .unwrap();
        assert_eq!(
            decode_query_by_execution_nonce_response_v2(&body)
                .unwrap()
                .status(),
            &ExecutorStatusV2::Prepared
        );
        server.join().unwrap();
    }

    #[test]
    fn fixed_kernel_executor_client_verifies_encrypted_registry_sync_response_binding() {
        let client_key = SigningKey::from_bytes(&[0x31; 32]);
        let server_key = SigningKey::from_bytes(&[0x32; 32]);
        let edge = edge(&client_key, &server_key);
        let client = SuiteOneKernelExecutorClientV2::from_verified_deployment(
            edge,
            BootIdV2::new([0x33; 32]),
            observed(),
            client_key.clone(),
            server_key.verifying_key().to_bytes(),
        )
        .unwrap();
        let (client_stream, server_stream) = UnixStream::pair().unwrap();
        let io_deadline = Instant::now() + Duration::from_secs(2);
        let request_id = RequestIdV2::new([0x34; 16]);
        let genesis = Digest32V2::new([0x35; 32]);
        let request = ConnectorRegistrySyncRequestV2::new(
            ConnectorRegistrySyncScopeV2::new(
                Digest32V2::new([1; 32]),
                Digest32V2::new([6; 32]),
                7,
                genesis,
                Ed25519KeyIdV2::new([0; 32]),
                FixedBytes32V2::new([0; 32]),
                Digest32V2::new([0x36; 32]),
            )
            .unwrap(),
            ConnectorRegistrySyncModeV2::Probe,
        )
        .unwrap();

        let server = thread::spawn(move || {
            let mut channel = UnixV2FrameChannel::new(server_stream);
            let hello = channel.read_handshake_frame(io_deadline).unwrap();
            let (pending, server_hello) = V2ServerHandshake::accept_client_hello(
                edge,
                observed(),
                &hello,
                Nonce32V2::new([0x37; 32]),
                StaticSecret::from([0x38; 32]),
                client_key.verifying_key().to_bytes(),
                &server_key,
            )
            .unwrap();
            channel
                .write_handshake_frame(&server_hello, io_deadline)
                .unwrap();
            let finish = channel.read_handshake_frame(io_deadline).unwrap();
            let (confirmation, mut session, _) = pending.accept_client_finish(&finish).unwrap();
            channel
                .write_record_frame(&confirmation, io_deadline)
                .unwrap();
            let record = channel.read_record_frame(io_deadline).unwrap();
            let opened = session.open_application_request(&record).unwrap();
            let request = decode_kernel_service_application_request_v2(opened.plaintext()).unwrap();
            assert_eq!(request.operation().tag(), 64);
            assert_eq!(request.request_id(), request_id);
            let body = encode_connector_registry_sync_response_v2(
                &ConnectorRegistrySyncResponseV2::new(
                    ConnectorRegistrySyncStatusV2::DisabledGenesisOnly,
                    0,
                    genesis,
                )
                .unwrap(),
            )
            .unwrap();
            let response = KernelServiceApplicationResponseV2::success(
                EndpointRoleV2::KernelExecutor,
                request_id,
                64,
                body,
            )
            .unwrap();
            let plaintext = encode_kernel_service_application_response_v2(&response).unwrap();
            let record = session
                .seal_application_response(request_id, 64, &plaintext)
                .unwrap();
            channel.write_record_frame(&record, io_deadline).unwrap();
            channel.close();
        });

        let response = client
            .synchronize_connector_registry_over_stream_for_test(
                client_stream,
                request_id,
                wall_clock_deadline(),
                io_deadline,
                request,
            )
            .unwrap();
        assert_eq!(
            response.status(),
            ConnectorRegistrySyncStatusV2::DisabledGenesisOnly
        );
        assert_eq!(response.local_sequence(), 0);
        assert_eq!(response.local_head_digest(), genesis);
        server.join().unwrap();
    }
}
