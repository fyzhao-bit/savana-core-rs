#![cfg(feature = "test-support")]

mod support;

use support::{policy_support, Installation};

use std::io::{ErrorKind, Read};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use savana_kernel_protocol::{
    connection_binding_digest, decode_server_message, encode_client_message,
    ingress_request_digest, read_frame, write_frame, BeginRunRequest, ClientFinishV1,
    ClientHelloV1, ClientMessageV1, ConversationId, Digest32, HardLimits, IngestUserInputRequest,
    IngressEnvelopeV1, IngressRequestCommitmentV1, KernelValue, KeyId, Nonce32, OperationV1,
    PrincipalId, ProtocolVersion, RequestEnvelopeV1, RequestId, RequestedMode, ResponseBodyV1,
    ResponsePayloadV1, RoleId, ServerMessageV1, Signature64, SignedIngressEnvelopeV1, StableCode,
    ToolName, UnixMillis,
};
use sha2::Digest;

const DAEMON_HELLO_DOMAIN: &[u8] = b"SAVANA_DAEMON_HELLO_V1\0";
const CLIENT_FINISH_DOMAIN: &[u8] = b"SAVANA_CLIENT_FINISH_V1\0";
const INGRESS_DOMAIN: &[u8] = b"SAVANA_INGRESS_V1\0";

#[test]
fn begin_and_ingest_dispatch_through_authenticated_context() {
    let installation = Installation::build();
    let mut daemon = RunningDaemon::start(&installation);
    let limits = HardLimits::COMPILED
        .lower(&policy_support::compiled_resources())
        .expect("fixture limits");
    let mut client_a = authenticated_connection(&installation, &limits, Client::A, 0x91);
    let begin = expect_begin(&mut client_a, &limits, 0xa1);
    assert_eof(&mut client_a.stream);
    drop(client_a);
    let mut client_a_fresh = authenticated_connection(&installation, &limits, Client::A, 0x92);
    let ingest = ingest_request(&client_a_fresh, begin.run, 0xa2);
    let ingested = request_once(&mut client_a_fresh.stream, &limits, ingest);
    match ingested.body {
        ResponseBodyV1::Ok(ResponsePayloadV1::IngestUserInput(value)) => {
            assert_ne!(value, begin.initial_value);
        }
        other => panic!("expected IngestUserInput success, got {other:?}"),
    }
    assert_eof(&mut client_a_fresh.stream);
    daemon.stop();
}

#[test]
fn policy_handles_follow_authenticated_client_not_original_connection() {
    let installation = Installation::build();
    let mut daemon = RunningDaemon::start(&installation);
    let limits = HardLimits::COMPILED
        .lower(&policy_support::compiled_resources())
        .expect("fixture limits");
    let mut client_a = authenticated_connection(&installation, &limits, Client::A, 0x92);
    let begin = expect_begin(&mut client_a, &limits, 0xa2);
    assert_eof(&mut client_a.stream);
    drop(client_a);

    let mut client_a_fresh = authenticated_connection(&installation, &limits, Client::A, 0x93);
    let accepted = ingest_request(&client_a_fresh, begin.run, 0xa3);
    assert!(matches!(
        request_once(&mut client_a_fresh.stream, &limits, accepted).body,
        ResponseBodyV1::Ok(ResponsePayloadV1::IngestUserInput(_))
    ));
    assert_eof(&mut client_a_fresh.stream);
    drop(client_a_fresh);

    let mut client_b = authenticated_connection(&installation, &limits, Client::B, 0x94);
    let cross_client_ingest = ingest_request(&client_b, begin.run, 0xa3);
    let rejected = request_once(&mut client_b.stream, &limits, cross_client_ingest);
    assert_eq!(
        rejected.body,
        ResponseBodyV1::Err(StableCode::HandleWrongClient)
    );
    assert_ne!(
        rejected.body,
        ResponseBodyV1::Err(StableCode::HandleWrongConnection)
    );
    assert_eof(&mut client_b.stream);
    daemon.stop();
}

#[test]
fn every_policy_connection_still_has_exactly_one_request_and_response() {
    let installation = Installation::build();
    let mut daemon = RunningDaemon::start(&installation);
    let limits = HardLimits::COMPILED
        .lower(&policy_support::compiled_resources())
        .expect("fixture limits");
    let mut client_a = authenticated_connection(&installation, &limits, Client::A, 0x95);
    let begin = expect_begin(&mut client_a, &limits, 0xa4);
    assert_eof(&mut client_a.stream);
    drop(client_a);
    let mut client_a_fresh = authenticated_connection(&installation, &limits, Client::A, 0x96);
    let ingest = ingest_request(&client_a_fresh, begin.run, 0xa5);
    assert!(matches!(
        request_once(&mut client_a_fresh.stream, &limits, ingest).body,
        ResponseBodyV1::Ok(ResponsePayloadV1::IngestUserInput(_))
    ));
    assert_eof(&mut client_a_fresh.stream);
    daemon.stop();
}

struct RunningDaemon {
    child: Option<Child>,
}

impl RunningDaemon {
    fn start(installation: &Installation) -> Self {
        let mut child = Command::new(&installation.executable)
            .arg("--config")
            .arg(&installation.config)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start fixture daemon");
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = child.try_wait().expect("poll fixture daemon") {
                let output = child.wait_with_output().expect("daemon output");
                panic!(
                    "fixture daemon exited before bind ({status}): {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            if installation.socket.exists() {
                return Self { child: Some(child) };
            }
            assert!(Instant::now() < deadline, "fixture daemon did not bind");
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn stop(&mut self) {
        let Some(child) = self.child.take() else {
            return;
        };
        kill(
            Pid::from_raw(i32::try_from(child.id()).expect("child pid")),
            Signal::SIGTERM,
        )
        .expect("stop fixture daemon");
        let output = child.wait_with_output().expect("wait fixture daemon");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

impl Drop for RunningDaemon {
    fn drop(&mut self) {
        self.stop();
    }
}

#[derive(Clone, Copy)]
enum Client {
    A,
    B,
}

impl Client {
    const fn seed(self) -> u8 {
        match self {
            Self::A => 0x62,
            Self::B => 0x63,
        }
    }

    fn id(self) -> savana_kernel_protocol::ClientId {
        match self {
            Self::A => "jarvis-client".try_into().expect("client id"),
            Self::B => "jarvis-client-b".try_into().expect("client id"),
        }
    }

    fn key_id(self) -> KeyId {
        match self {
            Self::A => "jarvis-key".try_into().expect("client key id"),
            Self::B => "jarvis-key-b".try_into().expect("client key id"),
        }
    }
}

struct AuthenticatedConnection {
    stream: UnixStream,
    transcript: savana_kernel_protocol::HandshakeTranscriptV1,
}

fn authenticated_connection(
    installation: &Installation,
    limits: &savana_kernel_protocol::EffectiveLimits,
    client: Client,
    nonce: u8,
) -> AuthenticatedConnection {
    let mut stream = connect_when_listening(&installation.socket);
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("read timeout");
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .expect("write timeout");
    let hello = ClientHelloV1 {
        client_nonce: Nonce32::new([nonce; 32]),
        supported_versions: vec![ProtocolVersion::new(1, 0)],
        client_id: client.id(),
        client_key_id: client.key_id(),
        requested_mode: RequestedMode::Required,
    };
    write_client(&mut stream, &ClientMessageV1::Hello(hello.clone()), limits);
    let signed = match read_server(&mut stream, limits) {
        ServerMessageV1::Hello(signed) => signed,
        other => panic!("expected signed hello, got {other:?}"),
    };
    assert_eq!(signed.transcript.client, hello);
    assert_eq!(
        signed.transcript.server.release_digest,
        installation.release_digest
    );
    assert_eq!(
        signed.transcript.server.policy_digest,
        installation.policy_digest
    );
    assert_eq!(
        signed.transcript.server.resource_profile_digest,
        installation.resource_profile_digest
    );
    let transcript_bytes = minicbor::to_vec(&signed.transcript).expect("canonical transcript");
    let mut daemon_input = Vec::with_capacity(DAEMON_HELLO_DOMAIN.len() + transcript_bytes.len());
    daemon_input.extend_from_slice(DAEMON_HELLO_DOMAIN);
    daemon_input.extend_from_slice(&transcript_bytes);
    SigningKey::from_bytes(&[0x61; 32])
        .verifying_key()
        .verify(
            &daemon_input,
            &Signature::from_bytes(signed.signature.as_bytes()),
        )
        .expect("daemon transcript signature");
    let transcript_digest = Digest32::new(sha2::Sha256::digest(&transcript_bytes).into());
    let mut finish_input = Vec::with_capacity(CLIENT_FINISH_DOMAIN.len() + 32);
    finish_input.extend_from_slice(CLIENT_FINISH_DOMAIN);
    finish_input.extend_from_slice(transcript_digest.as_bytes());
    let key = SigningKey::from_bytes(&[client.seed(); 32]);
    write_client(
        &mut stream,
        &ClientMessageV1::Finish(ClientFinishV1 {
            transcript_digest,
            signature: Signature64::new(key.sign(&finish_input).to_bytes()),
        }),
        limits,
    );
    match read_server(&mut stream, limits) {
        ServerMessageV1::Accepted(accepted) => {
            assert_eq!(accepted.boot_id, signed.transcript.server.boot_id);
            assert_eq!(accepted.protocol, signed.transcript.server.protocol);
        }
        other => panic!("expected acceptance, got {other:?}"),
    }
    AuthenticatedConnection {
        stream,
        transcript: signed.transcript,
    }
}

fn begin_request(connection: &AuthenticatedConnection, request_id: u8) -> RequestEnvelopeV1 {
    let input = KernelValue::Text("begin".try_into().expect("input"));
    let commitment = IngressRequestCommitmentV1::BeginRun {
        input: input.clone(),
    };
    let ingress = signed_ingress(
        connection,
        ingress_request_digest(&commitment).expect("begin commitment"),
        request_id,
    );
    let mut registry = policy_support::signed_registry();
    registry.unsigned.tools[0].identity.name = ToolName::new("operator-tool").expect("tool name");
    let now = system_now_ms();
    registry.unsigned.issued_at = UnixMillis::new(now.saturating_sub(1));
    registry.unsigned.expires_at = UnixMillis::new(now.checked_add(10_000).expect("expiry"));
    policy_support::resign_registry(&mut registry);
    RequestEnvelopeV1 {
        version: ProtocolVersion::new(1, 0),
        request_id: RequestId::new([request_id; 16]),
        deadline_unix_ms: UnixMillis::new(now.checked_add(20_000).expect("deadline")),
        operation: OperationV1::BeginRun(BeginRunRequest {
            ingress,
            input,
            registry,
        }),
    }
}

fn expect_begin(
    connection: &mut AuthenticatedConnection,
    limits: &savana_kernel_protocol::EffectiveLimits,
    request_id: u8,
) -> savana_kernel_protocol::BeginRunResponse {
    let request = begin_request(connection, request_id);
    match request_once(&mut connection.stream, limits, request).body {
        ResponseBodyV1::Ok(ResponsePayloadV1::BeginRun(response)) => {
            assert_eq!(response.active_tools.len(), 1);
            assert_eq!(
                response.active_tools[0].identity.name.as_str(),
                "operator-tool"
            );
            response
        }
        other => panic!("expected BeginRun success, got {other:?}"),
    }
}

fn ingest_request(
    connection: &AuthenticatedConnection,
    run: savana_kernel_protocol::RunHandle,
    request_id: u8,
) -> RequestEnvelopeV1 {
    let input = KernelValue::Text("ingest".try_into().expect("input"));
    let commitment = IngressRequestCommitmentV1::IngestUserInput {
        run,
        input: input.clone(),
    };
    RequestEnvelopeV1 {
        version: ProtocolVersion::new(1, 0),
        request_id: RequestId::new([request_id; 16]),
        deadline_unix_ms: UnixMillis::new(system_now_ms().checked_add(20_000).expect("deadline")),
        operation: OperationV1::IngestUserInput(IngestUserInputRequest {
            run,
            envelope: signed_ingress(
                connection,
                ingress_request_digest(&commitment).expect("ingest commitment"),
                request_id,
            ),
            input,
        }),
    }
}

fn signed_ingress(
    connection: &AuthenticatedConnection,
    request_digest: Digest32,
    nonce: u8,
) -> SignedIngressEnvelopeV1 {
    let now = system_now_ms();
    let unsigned = IngressEnvelopeV1 {
        principal: PrincipalId::new("principal-1").expect("principal"),
        conversation_id: ConversationId::new("conversation-1").expect("conversation"),
        request_digest,
        issued_at: UnixMillis::new(now.saturating_sub(1)),
        expires_at: UnixMillis::new(now.checked_add(10_000).expect("ingress expiry")),
        nonce: Nonce32::new([nonce; 32]),
        authority_session_id: Nonce32::new([0x66; 32]),
        authentication_context_digest: Digest32::new([0x55; 32]),
        role: RoleId::new("operator").expect("role"),
        policy_digest: connection.transcript.server.policy_digest,
        boot_id: connection.transcript.server.boot_id,
        connection_binding_digest: connection_binding_digest(&connection.transcript)
            .expect("connection binding"),
    };
    let payload = minicbor::to_vec(&unsigned).expect("canonical ingress");
    let mut signature_input = Vec::with_capacity(INGRESS_DOMAIN.len() + payload.len());
    signature_input.extend_from_slice(INGRESS_DOMAIN);
    signature_input.extend_from_slice(&payload);
    SignedIngressEnvelopeV1 {
        unsigned,
        key_id: KeyId::new("role-00").expect("role key"),
        signature: Signature64::new(
            SigningKey::from_bytes(&[0x70; 32])
                .sign(&signature_input)
                .to_bytes(),
        ),
    }
}

fn request_once(
    stream: &mut UnixStream,
    limits: &savana_kernel_protocol::EffectiveLimits,
    request: RequestEnvelopeV1,
) -> savana_kernel_protocol::ResponseEnvelopeV1 {
    write_client(stream, &ClientMessageV1::Request(request), limits);
    match read_server(stream, limits) {
        ServerMessageV1::Response(response) => response,
        other => panic!("expected exactly one response, got {other:?}"),
    }
}

fn assert_eof(stream: &mut UnixStream) {
    let mut byte = [0_u8; 1];
    match stream.read(&mut byte) {
        Ok(0) => {}
        Ok(count) => panic!("expected EOF after response, got {count} bytes"),
        Err(error) => panic!("expected EOF after response, got {error}"),
    }
}

fn write_client(
    stream: &mut UnixStream,
    message: &ClientMessageV1,
    limits: &savana_kernel_protocol::EffectiveLimits,
) {
    let payload = encode_client_message(message).expect("encode client message");
    write_frame(stream, &payload, limits).expect("write client frame");
}

fn read_server(
    stream: &mut UnixStream,
    limits: &savana_kernel_protocol::EffectiveLimits,
) -> ServerMessageV1 {
    let payload = read_frame(stream, limits).expect("read server frame");
    decode_server_message(&payload, limits).expect("decode server message")
}

fn system_now_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_millis(),
    )
    .expect("millisecond clock")
}

fn connect_when_listening(path: &std::path::Path) -> UnixStream {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match UnixStream::connect(path) {
            Ok(stream) => return stream,
            Err(error)
                if error.kind() == ErrorKind::ConnectionRefused && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("connect fixture daemon: {error}"),
        }
    }
}
