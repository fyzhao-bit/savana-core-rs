use std::io::{Read as _, Write as _};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use savana_kernel_protocol::v2::{
    decode_abort_input_response_v2, decode_append_input_chunk_response_v2,
    decode_append_parser_worker_page_frame_response_v2, decode_authenticate_ingress_ui_response_v2,
    decode_begin_input_response_v2, decode_commit_input_settlement_response_v2,
    decode_commit_parser_worker_result_response_v2, decode_finalize_input_response_v2,
    decode_get_input_status_response_v2, decode_kernel_ingress_health_response_v2,
    decode_kernel_service_application_request_v2, decode_kernel_service_application_response_v2,
    decode_prepare_ingress_ui_authentication_response_v2,
    decode_register_parser_worker_job_response_v2, encode_kernel_service_application_request_v2,
    AbortInputRequestV2, AbortInputResponseV2, AppendInputChunkRequestV2,
    AppendInputChunkResponseV2, AppendParserWorkerPageFrameRequestV2,
    AppendParserWorkerPageFrameResponseV2, AuthenticateIngressUiRequestV2,
    AuthenticateIngressUiResponseV2, BeginInputRequestV2, BeginInputResponseV2, BootIdV2,
    CommitInputSettlementRequestV2, CommitInputSettlementResponseV2,
    CommitParserWorkerResultRequestV2, CommitParserWorkerResultResponseV2, EndpointRoleV2,
    FinalizeInputRequestV2, FinalizeInputResponseV2, GetInputStatusRequestV2,
    GetInputStatusResponseV2, KernelIngressHealthRequestV2, KernelIngressHealthResponseV2,
    KernelIngressOperationV2, KernelServiceApplicationRequestV2,
    KernelServiceApplicationResponseBodyV2, KernelServiceHandshakeEdgeV2, KernelServiceOperationV2,
    Nonce32V2, PeerIdentityBindingV2, PrepareIngressUiAuthenticationRequestV2,
    PrepareIngressUiAuthenticationResponseV2, PublicStableCodeV2, RegisterParserWorkerJobRequestV2,
    RegisterParserWorkerJobResponseV2, RequestIdV2, UnixMillisV2, V2ClientHandshake,
    HANDSHAKE_FRAME_HEADER_BYTES_V2, MAX_HANDSHAKE_BODY_BYTES_V2, MAX_RECORD_CIPHERTEXT_BYTES_V2,
    MAX_RECORD_HEADER_BYTES_V2, RECORD_FRAME_HEADER_BYTES_V2,
};
use sha2::{Digest as _, Sha256};
use x25519_dalek::StaticSecret;

const INGRESS_KERNEL_SOCKET_PATH_V2: &str = "/run/savana/kerneld/ingressd/kerneld.sock";
const HANDSHAKE_MAGIC_V2: &[u8; 8] = b"SAVANA2\0";
const RECORD_MAGIC_V2: &[u8; 4] = b"SV2R";
const MAX_CONNECTION_DURATION_V2: Duration = Duration::from_secs(5);
const REQUEST_ID_DOMAIN_V2: &[u8] = b"SAVANA_INGRESSD_KERNEL_REQUEST_ID_V2\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum IngressKernelClientErrorV2 {
    #[error("ingress kernel request deadline was exceeded")]
    DeadlineExceeded,
    #[error("ingress kernel service is unavailable")]
    Unavailable,
}

pub struct SuiteOneIngressKernelClientV2 {
    edge: KernelServiceHandshakeEdgeV2,
    client_boot_id: BootIdV2,
    expected_observed_peer: PeerIdentityBindingV2,
    client_signing_key: SigningKey,
    server_public_key: [u8; 32],
    socket_path: PathBuf,
}

impl std::fmt::Debug for SuiteOneIngressKernelClientV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SuiteOneIngressKernelClientV2(<deployment-bound-keys-redacted>)")
    }
}

impl SuiteOneIngressKernelClientV2 {
    pub fn from_verified_deployment(
        edge: KernelServiceHandshakeEdgeV2,
        client_boot_id: BootIdV2,
        expected_observed_peer: PeerIdentityBindingV2,
        client_signing_key: SigningKey,
        server_public_key: [u8; 32],
    ) -> Result<Self, IngressKernelClientErrorV2> {
        if edge.role() != EndpointRoleV2::IngressKernel
            || client_boot_id.as_bytes() == &[0; 32]
            || server_public_key == [0; 32]
        {
            return Err(IngressKernelClientErrorV2::Unavailable);
        }
        Ok(Self {
            edge,
            client_boot_id,
            expected_observed_peer,
            client_signing_key,
            server_public_key,
            socket_path: PathBuf::from(INGRESS_KERNEL_SOCKET_PATH_V2),
        })
    }

    pub fn health(
        &self,
        deadline: UnixMillisV2,
    ) -> Result<KernelIngressHealthResponseV2, IngressKernelClientErrorV2> {
        let body = self.exchange(
            KernelIngressOperationV2::Health(KernelIngressHealthRequestV2),
            deadline,
        )?;
        decode_kernel_ingress_health_response_v2(&body)
            .map_err(|_| IngressKernelClientErrorV2::Unavailable)
    }

    pub fn prepare_ui_authentication(
        &self,
        request: PrepareIngressUiAuthenticationRequestV2,
        deadline: UnixMillisV2,
    ) -> Result<PrepareIngressUiAuthenticationResponseV2, IngressKernelClientErrorV2> {
        let body = self.exchange(
            KernelIngressOperationV2::PrepareIngressUiAuthentication(request),
            deadline,
        )?;
        decode_prepare_ingress_ui_authentication_response_v2(&body)
            .map_err(|_| IngressKernelClientErrorV2::Unavailable)
    }

    pub fn authenticate_ui(
        &self,
        request: AuthenticateIngressUiRequestV2,
        deadline: UnixMillisV2,
    ) -> Result<AuthenticateIngressUiResponseV2, IngressKernelClientErrorV2> {
        let body = self.exchange(
            KernelIngressOperationV2::AuthenticateIngressUi(request),
            deadline,
        )?;
        decode_authenticate_ingress_ui_response_v2(&body)
            .map_err(|_| IngressKernelClientErrorV2::Unavailable)
    }

    pub fn begin_input(
        &self,
        request: BeginInputRequestV2,
        deadline: UnixMillisV2,
    ) -> Result<BeginInputResponseV2, IngressKernelClientErrorV2> {
        let body = self.exchange(KernelIngressOperationV2::BeginInput(request), deadline)?;
        decode_begin_input_response_v2(&body).map_err(|_| IngressKernelClientErrorV2::Unavailable)
    }

    pub fn append_input_chunk(
        &self,
        request: AppendInputChunkRequestV2,
        deadline: UnixMillisV2,
    ) -> Result<AppendInputChunkResponseV2, IngressKernelClientErrorV2> {
        let body = self.exchange(
            KernelIngressOperationV2::AppendInputChunk(request),
            deadline,
        )?;
        decode_append_input_chunk_response_v2(&body)
            .map_err(|_| IngressKernelClientErrorV2::Unavailable)
    }

    pub fn finalize_input(
        &self,
        request: FinalizeInputRequestV2,
        deadline: UnixMillisV2,
    ) -> Result<FinalizeInputResponseV2, IngressKernelClientErrorV2> {
        let body = self.exchange(KernelIngressOperationV2::FinalizeInput(request), deadline)?;
        decode_finalize_input_response_v2(&body)
            .map_err(|_| IngressKernelClientErrorV2::Unavailable)
    }

    pub fn commit_input_settlement(
        &self,
        request: CommitInputSettlementRequestV2,
        deadline: UnixMillisV2,
    ) -> Result<CommitInputSettlementResponseV2, IngressKernelClientErrorV2> {
        let body = self.exchange(
            KernelIngressOperationV2::CommitInputSettlement(request),
            deadline,
        )?;
        decode_commit_input_settlement_response_v2(&body)
            .map_err(|_| IngressKernelClientErrorV2::Unavailable)
    }

    pub fn abort_input(
        &self,
        request: AbortInputRequestV2,
        deadline: UnixMillisV2,
    ) -> Result<AbortInputResponseV2, IngressKernelClientErrorV2> {
        let body = self.exchange(KernelIngressOperationV2::AbortInput(request), deadline)?;
        decode_abort_input_response_v2(&body).map_err(|_| IngressKernelClientErrorV2::Unavailable)
    }

    pub fn get_input_status(
        &self,
        request: GetInputStatusRequestV2,
        deadline: UnixMillisV2,
    ) -> Result<GetInputStatusResponseV2, IngressKernelClientErrorV2> {
        let body = self.exchange(KernelIngressOperationV2::GetInputStatus(request), deadline)?;
        decode_get_input_status_response_v2(&body)
            .map_err(|_| IngressKernelClientErrorV2::Unavailable)
    }

    pub fn register_parser_worker_job(
        &self,
        request: RegisterParserWorkerJobRequestV2,
        deadline: UnixMillisV2,
    ) -> Result<RegisterParserWorkerJobResponseV2, IngressKernelClientErrorV2> {
        let body = self.exchange(
            KernelIngressOperationV2::RegisterParserWorkerJob(request),
            deadline,
        )?;
        decode_register_parser_worker_job_response_v2(&body)
            .map_err(|_| IngressKernelClientErrorV2::Unavailable)
    }

    pub fn append_parser_worker_page_frame(
        &self,
        request: AppendParserWorkerPageFrameRequestV2,
        deadline: UnixMillisV2,
    ) -> Result<AppendParserWorkerPageFrameResponseV2, IngressKernelClientErrorV2> {
        let body = self.exchange(
            KernelIngressOperationV2::AppendParserWorkerPageFrame(request),
            deadline,
        )?;
        decode_append_parser_worker_page_frame_response_v2(&body)
            .map_err(|_| IngressKernelClientErrorV2::Unavailable)
    }

    pub fn commit_parser_worker_result(
        &self,
        request: CommitParserWorkerResultRequestV2,
        deadline: UnixMillisV2,
    ) -> Result<CommitParserWorkerResultResponseV2, IngressKernelClientErrorV2> {
        let body = self.exchange(
            KernelIngressOperationV2::CommitParserWorkerResult(request),
            deadline,
        )?;
        decode_commit_parser_worker_result_response_v2(&body)
            .map_err(|_| IngressKernelClientErrorV2::Unavailable)
    }

    fn exchange(
        &self,
        operation: KernelIngressOperationV2,
        deadline: UnixMillisV2,
    ) -> Result<Vec<u8>, IngressKernelClientErrorV2> {
        let io_deadline = io_deadline(deadline)?;
        let mut stream = UnixStream::connect(&self.socket_path)
            .map_err(|_| IngressKernelClientErrorV2::Unavailable)?;
        let result = (|| {
            let provisional = KernelServiceApplicationRequestV2::new(
                EndpointRoleV2::IngressKernel,
                RequestIdV2::new([1; 16]),
                UnixMillisV2::new(1),
                KernelServiceOperationV2::ingress(operation),
            )
            .map_err(|_| IngressKernelClientErrorV2::Unavailable)?;
            let canonical = encode_kernel_service_application_request_v2(&provisional)
                .map_err(|_| IngressKernelClientErrorV2::Unavailable)?;
            let mut hasher = Sha256::new();
            hasher.update(REQUEST_ID_DOMAIN_V2);
            hasher.update(&canonical);
            let digest: [u8; 32] = hasher.finalize().into();
            let mut request_id = [0_u8; 16];
            request_id.copy_from_slice(&digest[..16]);
            if request_id == [0; 16] {
                request_id[15] = 1;
            }
            let request_id = RequestIdV2::new(request_id);
            let (_, _, _, operation) = decode_kernel_service_application_request_v2(&canonical)
                .map_err(|_| IngressKernelClientErrorV2::Unavailable)?
                .into_parts();
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
            .map_err(|_| IngressKernelClientErrorV2::Unavailable)?;
            write_handshake_frame(&mut stream, &hello, io_deadline)?;
            let server_hello = read_handshake_frame(&mut stream, io_deadline)?;
            let (finish, mut session) = pending
                .accept_server_hello(
                    &server_hello,
                    self.server_public_key,
                    &self.client_signing_key,
                )
                .map_err(|_| IngressKernelClientErrorV2::Unavailable)?;
            write_handshake_frame(&mut stream, &finish, io_deadline)?;
            let confirmation = read_record_frame(&mut stream, io_deadline)?;
            session
                .accept_server_confirmation(&confirmation)
                .map_err(|_| IngressKernelClientErrorV2::Unavailable)?;

            let operation_tag = operation.tag();
            let request = KernelServiceApplicationRequestV2::new(
                EndpointRoleV2::IngressKernel,
                request_id,
                deadline,
                operation,
            )
            .map_err(|_| IngressKernelClientErrorV2::Unavailable)?;
            let plaintext = encode_kernel_service_application_request_v2(&request)
                .map_err(|_| IngressKernelClientErrorV2::Unavailable)?;
            let record = session
                .seal_application_request(request_id, operation_tag, &plaintext)
                .map_err(|_| IngressKernelClientErrorV2::Unavailable)?;
            write_record_frame(&mut stream, &record, io_deadline)?;
            let response_record = read_record_frame(&mut stream, io_deadline)?;
            let opened = session
                .open_application_response(&response_record)
                .map_err(|_| IngressKernelClientErrorV2::Unavailable)?;
            let response = decode_kernel_service_application_response_v2(
                opened.plaintext(),
                EndpointRoleV2::IngressKernel,
                operation_tag,
            )
            .map_err(|_| IngressKernelClientErrorV2::Unavailable)?;
            if response.request_id() != request_id || response.operation_tag() != operation_tag {
                return Err(IngressKernelClientErrorV2::Unavailable);
            }
            match response.body() {
                KernelServiceApplicationResponseBodyV2::Success(body) => Ok(body.to_vec()),
                KernelServiceApplicationResponseBodyV2::Error(
                    PublicStableCodeV2::DeadlineExceeded,
                ) => Err(IngressKernelClientErrorV2::DeadlineExceeded),
                KernelServiceApplicationResponseBodyV2::Error(_) => {
                    Err(IngressKernelClientErrorV2::Unavailable)
                }
            }
        })();
        let _ = stream.shutdown(Shutdown::Both);
        result
    }
}

fn io_deadline(deadline: UnixMillisV2) -> Result<Instant, IngressKernelClientErrorV2> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| IngressKernelClientErrorV2::Unavailable)?;
    let now_millis =
        u64::try_from(now.as_millis()).map_err(|_| IngressKernelClientErrorV2::Unavailable)?;
    let remaining = deadline
        .get()
        .checked_sub(now_millis)
        .filter(|value| *value != 0)
        .ok_or(IngressKernelClientErrorV2::DeadlineExceeded)?;
    Ok(Instant::now() + Duration::from_millis(remaining).min(MAX_CONNECTION_DURATION_V2))
}

fn random_nonzero_32() -> Result<[u8; 32], IngressKernelClientErrorV2> {
    let mut bytes = [0_u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|_| IngressKernelClientErrorV2::Unavailable)?;
    if bytes == [0; 32] {
        Err(IngressKernelClientErrorV2::Unavailable)
    } else {
        Ok(bytes)
    }
}

fn set_deadline(stream: &UnixStream, deadline: Instant) -> Result<(), IngressKernelClientErrorV2> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(IngressKernelClientErrorV2::DeadlineExceeded);
    }
    stream
        .set_read_timeout(Some(remaining))
        .and_then(|()| stream.set_write_timeout(Some(remaining)))
        .map_err(|_| IngressKernelClientErrorV2::Unavailable)
}

fn read_handshake_frame(
    stream: &mut UnixStream,
    deadline: Instant,
) -> Result<Vec<u8>, IngressKernelClientErrorV2> {
    set_deadline(stream, deadline)?;
    let mut header = [0_u8; HANDSHAKE_FRAME_HEADER_BYTES_V2];
    stream
        .read_exact(&mut header)
        .map_err(|_| IngressKernelClientErrorV2::Unavailable)?;
    if &header[..8] != HANDSHAKE_MAGIC_V2 {
        return Err(IngressKernelClientErrorV2::Unavailable);
    }
    let length = u32::from_be_bytes(
        header[HANDSHAKE_FRAME_HEADER_BYTES_V2 - 4..]
            .try_into()
            .map_err(|_| IngressKernelClientErrorV2::Unavailable)?,
    ) as usize;
    if length == 0 || length > MAX_HANDSHAKE_BODY_BYTES_V2 {
        return Err(IngressKernelClientErrorV2::Unavailable);
    }
    let mut frame = header.to_vec();
    frame.resize(
        HANDSHAKE_FRAME_HEADER_BYTES_V2
            .checked_add(length)
            .ok_or(IngressKernelClientErrorV2::Unavailable)?,
        0,
    );
    stream
        .read_exact(&mut frame[HANDSHAKE_FRAME_HEADER_BYTES_V2..])
        .map_err(|_| IngressKernelClientErrorV2::Unavailable)?;
    Ok(frame)
}

fn write_handshake_frame(
    stream: &mut UnixStream,
    frame: &[u8],
    deadline: Instant,
) -> Result<(), IngressKernelClientErrorV2> {
    if frame.len() <= HANDSHAKE_FRAME_HEADER_BYTES_V2
        || frame.len() > HANDSHAKE_FRAME_HEADER_BYTES_V2 + MAX_HANDSHAKE_BODY_BYTES_V2
        || &frame[..8] != HANDSHAKE_MAGIC_V2
    {
        return Err(IngressKernelClientErrorV2::Unavailable);
    }
    set_deadline(stream, deadline)?;
    stream
        .write_all(frame)
        .and_then(|()| stream.flush())
        .map_err(|_| IngressKernelClientErrorV2::Unavailable)
}

fn read_record_frame(
    stream: &mut UnixStream,
    deadline: Instant,
) -> Result<Vec<u8>, IngressKernelClientErrorV2> {
    set_deadline(stream, deadline)?;
    let mut header = [0_u8; RECORD_FRAME_HEADER_BYTES_V2];
    stream
        .read_exact(&mut header)
        .map_err(|_| IngressKernelClientErrorV2::Unavailable)?;
    let (header_length, ciphertext_length) = record_lengths(&header)?;
    let total = RECORD_FRAME_HEADER_BYTES_V2
        .checked_add(header_length)
        .and_then(|value| value.checked_add(ciphertext_length))
        .ok_or(IngressKernelClientErrorV2::Unavailable)?;
    let mut frame = Vec::new();
    frame
        .try_reserve_exact(total)
        .map_err(|_| IngressKernelClientErrorV2::Unavailable)?;
    frame.extend_from_slice(&header);
    frame.resize(total, 0);
    stream
        .read_exact(&mut frame[RECORD_FRAME_HEADER_BYTES_V2..])
        .map_err(|_| IngressKernelClientErrorV2::Unavailable)?;
    Ok(frame)
}

fn write_record_frame(
    stream: &mut UnixStream,
    frame: &[u8],
    deadline: Instant,
) -> Result<(), IngressKernelClientErrorV2> {
    if frame.len() < RECORD_FRAME_HEADER_BYTES_V2 {
        return Err(IngressKernelClientErrorV2::Unavailable);
    }
    let (header_length, ciphertext_length) =
        record_lengths(&frame[..RECORD_FRAME_HEADER_BYTES_V2])?;
    if frame.len() != RECORD_FRAME_HEADER_BYTES_V2 + header_length + ciphertext_length {
        return Err(IngressKernelClientErrorV2::Unavailable);
    }
    set_deadline(stream, deadline)?;
    stream
        .write_all(frame)
        .and_then(|()| stream.flush())
        .map_err(|_| IngressKernelClientErrorV2::Unavailable)
}

fn record_lengths(header: &[u8]) -> Result<(usize, usize), IngressKernelClientErrorV2> {
    if header.len() != RECORD_FRAME_HEADER_BYTES_V2 || &header[..4] != RECORD_MAGIC_V2 {
        return Err(IngressKernelClientErrorV2::Unavailable);
    }
    let header_length = usize::from(u16::from_be_bytes(
        header[4..6]
            .try_into()
            .map_err(|_| IngressKernelClientErrorV2::Unavailable)?,
    ));
    let ciphertext_length = u32::from_be_bytes(
        header[6..10]
            .try_into()
            .map_err(|_| IngressKernelClientErrorV2::Unavailable)?,
    ) as usize;
    if header_length == 0
        || header_length > MAX_RECORD_HEADER_BYTES_V2
        || !(16..=MAX_RECORD_CIPHERTEXT_BYTES_V2).contains(&ciphertext_length)
    {
        return Err(IngressKernelClientErrorV2::Unavailable);
    }
    Ok((header_length, ciphertext_length))
}
