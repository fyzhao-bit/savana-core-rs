use std::fmt::Write as FmtWrite;
use std::fs::File;
use std::io::Write as IoWrite;
use std::os::fd::OwnedFd;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use rustix::event::{poll, PollFd, PollFlags, Timespec};
use rustix::fs::{fcntl_getfl, fcntl_setfl, fstat, FileType, OFlags};
use rustix::io::{fcntl_dupfd_cloexec, fcntl_getfd, fcntl_setfd, write, Errno, FdFlags};
use savana_kernel_protocol::{
    BootId, ClientId, Digest32, Nonce32, RunHandle, ServerIdentityV1, StableCode,
};

use crate::handshake::ConnectionContext;
use crate::runtime_deps::AuditSecret;

const MAXIMUM_AUDIT_LINE_BYTES: usize = 1024;
const AUDIT_IO_DEADLINE: Duration = Duration::from_secs(5);
const AUDIT_CONNECTION_DOMAIN: &[u8] = b"SAVANA_AUDIT_CONNECTION_V1\0";
const AUDIT_RUN_DOMAIN: &[u8] = b"SAVANA_AUDIT_RUN_V1\0";

type HmacSha256 = hmac::Hmac<sha2::Sha256>;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct AuditId(Digest32);

impl std::fmt::Debug for AuditId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AuditId(<opaque>)")
    }
}

#[cfg(test)]
impl AuditId {
    fn to_hex(self) -> String {
        let mut output = String::with_capacity(64);
        push_hex(&mut output, self.0.as_bytes());
        output
    }
}

struct AuditConnectionIdentity {
    boot_id: BootId,
    generation: u64,
    client_id: ClientId,
    peer_uid: u32,
    connection_id: Nonce32,
}

impl AuditConnectionIdentity {
    fn from_context(context: &ConnectionContext) -> Self {
        Self {
            boot_id: context.boot_id(),
            generation: context.generation(),
            client_id: context.client_id().clone(),
            peer_uid: context.peer().uid(),
            connection_id: context.connection_id(),
        }
    }

    #[cfg(test)]
    fn new(
        boot_id: BootId,
        generation: u64,
        client_id: ClientId,
        peer_uid: u32,
        connection_id: Nonce32,
    ) -> Self {
        Self {
            boot_id,
            generation,
            client_id,
            peer_uid,
            connection_id,
        }
    }

    fn canonical(&self) -> Result<Vec<u8>, StableCode> {
        minicbor::to_vec(CanonicalAuditConnectionIdentity {
            boot_id: self.boot_id,
            generation: self.generation,
            client_id: &self.client_id,
            peer_uid: self.peer_uid,
            connection_id: self.connection_id,
        })
        .map_err(|_| StableCode::KernelUnavailable)
    }
}

struct AuditRunIdentity {
    boot_id: BootId,
    generation: u64,
    run_handle: RunHandle,
}

impl AuditRunIdentity {
    fn from_connection(context: &ConnectionContext, run_handle: RunHandle) -> Self {
        Self {
            boot_id: context.boot_id(),
            generation: context.generation(),
            run_handle,
        }
    }

    #[cfg(test)]
    fn new(boot_id: BootId, generation: u64, run_handle: RunHandle) -> Self {
        Self {
            boot_id,
            generation,
            run_handle,
        }
    }

    fn canonical(&self) -> Result<Vec<u8>, StableCode> {
        minicbor::to_vec(CanonicalAuditRunIdentity {
            boot_id: self.boot_id,
            generation: self.generation,
            run_handle: self.run_handle,
        })
        .map_err(|_| StableCode::KernelUnavailable)
    }
}

#[derive(minicbor::Encode)]
#[cbor(array)]
struct CanonicalAuditConnectionIdentity<'a> {
    #[n(0)]
    boot_id: BootId,
    #[n(1)]
    generation: u64,
    #[n(2)]
    client_id: &'a ClientId,
    #[n(3)]
    peer_uid: u32,
    #[n(4)]
    connection_id: Nonce32,
}

#[derive(minicbor::Encode)]
#[cbor(array)]
struct CanonicalAuditRunIdentity {
    #[n(0)]
    boot_id: BootId,
    #[n(1)]
    generation: u64,
    #[n(2)]
    run_handle: RunHandle,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum OperationTag {
    Health,
    BeginRun,
    IngestUserInput,
    PreparePlannerCall,
    CommitPlannerValue,
    DeriveValue,
    ProposeToolCall,
    EvaluateToolCall,
    AuthorizeToolCall,
    MaterializeExecution,
    CommitToolResult,
}

impl OperationTag {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Health => "health",
            Self::BeginRun => "begin_run",
            Self::IngestUserInput => "ingest_user_input",
            Self::PreparePlannerCall => "prepare_planner_call",
            Self::CommitPlannerValue => "commit_planner_value",
            Self::DeriveValue => "derive_value",
            Self::ProposeToolCall => "propose_tool_call",
            Self::EvaluateToolCall => "evaluate_tool_call",
            Self::AuthorizeToolCall => "authorize_tool_call",
            Self::MaterializeExecution => "materialize_execution",
            Self::CommitToolResult => "commit_tool_result",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum RequestCode {
    Ok,
    Error(StableCode),
}

impl RequestCode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "OK",
            Self::Error(code) => code.as_str(),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ShutdownReason {
    Sigterm,
    Sigint,
}

impl ShutdownReason {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Sigterm => "sigterm",
            Self::Sigint => "sigint",
        }
    }
}

pub(crate) enum AuditEvent<'identity> {
    BootstrapFailed {
        code: StableCode,
    },
    Started {
        identity: &'identity ServerIdentityV1,
    },
    HandshakeRejected {
        code: StableCode,
    },
    RequestCompleted {
        operation_tag: OperationTag,
        code: RequestCode,
        latency_ms: u64,
        connection_audit_id: AuditId,
        run_audit_id: Option<AuditId>,
    },
    Fatal {
        code: StableCode,
    },
    Stopped {
        reason: ShutdownReason,
    },
}

struct AuditWriter {
    file: File,
    timeout: Duration,
}

pub(crate) struct AuditSink {
    writer: Mutex<AuditWriter>,
    secret: AuditSecret,
}

impl std::fmt::Debug for AuditSink {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AuditSink(<bounded-stderr>)")
    }
}

impl AuditSink {
    pub(crate) fn establish(secret: AuditSecret) -> Result<(Self, OwnedFd), StableCode> {
        let owned = fcntl_dupfd_cloexec(rustix::stdio::stderr(), 3)
            .map_err(|_| StableCode::KernelUnavailable)?;
        let sink = Self::from_owned(secret, owned, AUDIT_IO_DEADLINE)?;
        let panic_descriptor = sink.duplicate_for_panic()?;
        Ok((sink, panic_descriptor))
    }

    #[cfg(test)]
    pub(crate) fn from_owned_for_test(
        secret: AuditSecret,
        owned: OwnedFd,
        timeout: Duration,
    ) -> Result<Self, StableCode> {
        Self::from_owned(secret, owned, timeout)
    }

    #[cfg(test)]
    fn with_secret_for_test(secret: [u8; 32], timeout: Duration) -> Result<Self, StableCode> {
        let (writer, reader) =
            std::os::unix::net::UnixStream::pair().map_err(|_| StableCode::KernelUnavailable)?;
        drop(reader);
        Self::from_owned(AuditSecret::from_test_bytes(secret), writer.into(), timeout)
    }

    fn from_owned(
        secret: AuditSecret,
        owned: OwnedFd,
        timeout: Duration,
    ) -> Result<Self, StableCode> {
        if timeout.is_zero() || timeout > AUDIT_IO_DEADLINE {
            return Err(StableCode::KernelUnavailable);
        }
        let stat = fstat(&owned).map_err(|_| StableCode::KernelUnavailable)?;
        let file_type = FileType::from_raw_mode(stat.st_mode);
        if !(file_type.is_fifo() || file_type.is_socket() || file_type.is_char_device()) {
            return Err(StableCode::KernelUnavailable);
        }

        let descriptor_flags =
            fcntl_getfd(&owned).map_err(|_| StableCode::KernelUnavailable)? | FdFlags::CLOEXEC;
        fcntl_setfd(&owned, descriptor_flags).map_err(|_| StableCode::KernelUnavailable)?;
        let status =
            fcntl_getfl(&owned).map_err(|_| StableCode::KernelUnavailable)? | OFlags::NONBLOCK;
        fcntl_setfl(&owned, status).map_err(|_| StableCode::KernelUnavailable)?;
        if !fcntl_getfd(&owned)
            .map_err(|_| StableCode::KernelUnavailable)?
            .contains(FdFlags::CLOEXEC)
            || !fcntl_getfl(&owned)
                .map_err(|_| StableCode::KernelUnavailable)?
                .contains(OFlags::NONBLOCK)
        {
            return Err(StableCode::KernelUnavailable);
        }

        let file = File::from(owned);
        if file_type.is_char_device() {
            probe_character_sink(&file)?;
        }
        Ok(Self {
            writer: Mutex::new(AuditWriter { file, timeout }),
            secret,
        })
    }

    pub(crate) fn emit(&self, event: AuditEvent<'_>) -> Result<(), StableCode> {
        let line = encode_event(event)?;
        let mut writer = self
            .writer
            .lock()
            .map_err(|_| StableCode::KernelUnavailable)?;
        writer.write_line(&line)
    }

    pub(crate) fn duplicate_for_panic(&self) -> Result<OwnedFd, StableCode> {
        let writer = self
            .writer
            .lock()
            .map_err(|_| StableCode::KernelUnavailable)?;
        fcntl_dupfd_cloexec(&writer.file, 3).map_err(|_| StableCode::KernelUnavailable)
    }

    fn connection_audit_id(
        &self,
        identity: &AuditConnectionIdentity,
    ) -> Result<AuditId, StableCode> {
        self.correlate(AUDIT_CONNECTION_DOMAIN, &identity.canonical()?)
    }

    fn run_audit_id(&self, identity: &AuditRunIdentity) -> Result<AuditId, StableCode> {
        self.correlate(AUDIT_RUN_DOMAIN, &identity.canonical()?)
    }

    pub(crate) fn connection_audit_id_for_context(
        &self,
        context: &ConnectionContext,
    ) -> Result<AuditId, StableCode> {
        self.connection_audit_id(&AuditConnectionIdentity::from_context(context))
    }

    pub(crate) fn run_audit_id_for_context(
        &self,
        context: &ConnectionContext,
        run_handle: RunHandle,
    ) -> Result<AuditId, StableCode> {
        self.run_audit_id(&AuditRunIdentity::from_connection(context, run_handle))
    }

    fn correlate(&self, domain: &'static [u8], canonical: &[u8]) -> Result<AuditId, StableCode> {
        use hmac::Mac;

        let mut mac = HmacSha256::new_from_slice(self.secret.as_bytes())
            .map_err(|_| StableCode::KernelUnavailable)?;
        mac.update(domain);
        mac.update(canonical);
        Ok(AuditId(Digest32::new(mac.finalize().into_bytes().into())))
    }
}

impl AuditWriter {
    fn write_line(&mut self, line: &[u8]) -> Result<(), StableCode> {
        let deadline = Instant::now()
            .checked_add(self.timeout)
            .ok_or(StableCode::KernelUnavailable)?;
        let mut offset = 0;
        while offset < line.len() {
            wait_writable(&self.file, deadline)?;
            match write(&self.file, &line[offset..]) {
                Ok(0) => return Err(StableCode::KernelUnavailable),
                Ok(written) => {
                    offset = offset
                        .checked_add(written)
                        .ok_or(StableCode::KernelUnavailable)?;
                }
                Err(error) if error == Errno::INTR || error == Errno::AGAIN => {}
                Err(_) => return Err(StableCode::KernelUnavailable),
            }
        }
        if Instant::now() >= deadline {
            return Err(StableCode::KernelUnavailable);
        }
        self.file
            .flush()
            .map_err(|_| StableCode::KernelUnavailable)?;
        if Instant::now() > deadline {
            return Err(StableCode::KernelUnavailable);
        }
        Ok(())
    }
}

fn probe_character_sink(file: &File) -> Result<(), StableCode> {
    let mut descriptor = [PollFd::new(file, PollFlags::OUT)];
    let timeout = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let ready = poll(&mut descriptor, Some(&timeout)).map_err(|_| StableCode::KernelUnavailable)?;
    let events = descriptor[0].revents();
    if ready != 1
        || !events.contains(PollFlags::OUT)
        || events.intersects(PollFlags::ERR | PollFlags::HUP | PollFlags::NVAL)
    {
        return Err(StableCode::KernelUnavailable);
    }
    Ok(())
}

fn wait_writable(file: &File, deadline: Instant) -> Result<(), StableCode> {
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(StableCode::KernelUnavailable)?;
        let timeout = Timespec::try_from(remaining).map_err(|_| StableCode::KernelUnavailable)?;
        let mut descriptor = [PollFd::new(file, PollFlags::OUT)];
        match poll(&mut descriptor, Some(&timeout)) {
            Ok(0) => return Err(StableCode::KernelUnavailable),
            Ok(_) => {
                let events = descriptor[0].revents();
                if events.intersects(PollFlags::ERR | PollFlags::HUP | PollFlags::NVAL)
                    || !events.contains(PollFlags::OUT)
                {
                    return Err(StableCode::KernelUnavailable);
                }
                return Ok(());
            }
            Err(error) if error == Errno::INTR => {}
            Err(_) => return Err(StableCode::KernelUnavailable),
        }
    }
}

fn encode_event(event: AuditEvent<'_>) -> Result<Vec<u8>, StableCode> {
    let mut output = String::with_capacity(512);
    match event {
        AuditEvent::BootstrapFailed { code } => {
            write!(
                output,
                r#"{{"event":"BootstrapFailed","code":"{}"}}"#,
                code.as_str()
            )
            .map_err(|_| StableCode::KernelUnavailable)?;
        }
        AuditEvent::Started { identity } => {
            output.push_str(r#"{"event":"Started","boot_id":""#);
            push_hex(&mut output, identity.boot_id.as_bytes());
            write!(
                output,
                r#"","protocol_major":{},"protocol_minor":{},"release_digest":""#,
                identity.protocol.major, identity.protocol.minor
            )
            .map_err(|_| StableCode::KernelUnavailable)?;
            push_hex(&mut output, identity.release_digest.as_bytes());
            output.push_str(r#"","policy_digest":""#);
            push_hex(&mut output, identity.policy_digest.as_bytes());
            write!(
                output,
                r#"","policy_version":{},"model_manifest_digest":""#,
                identity.policy_version
            )
            .map_err(|_| StableCode::KernelUnavailable)?;
            push_hex(&mut output, identity.model_manifest_digest.as_bytes());
            output.push_str(r#"","approval_key_set_digest":""#);
            push_hex(&mut output, identity.approval_key_set_digest.as_bytes());
            output.push_str(r#"","resource_profile_digest":""#);
            push_hex(&mut output, identity.resource_profile_digest.as_bytes());
            output.push_str(r#""}"#);
        }
        AuditEvent::HandshakeRejected { code } => {
            write!(
                output,
                r#"{{"event":"HandshakeRejected","code":"{}"}}"#,
                code.as_str()
            )
            .map_err(|_| StableCode::KernelUnavailable)?;
        }
        AuditEvent::RequestCompleted {
            operation_tag,
            code,
            latency_ms,
            connection_audit_id,
            run_audit_id,
        } => {
            write!(
                output,
                concat!(
                    r#"{{"event":"RequestCompleted","operation_tag":"{}","#,
                    r#""code":"{}","latency_ms":{},"connection_audit_id":""#
                ),
                operation_tag.as_str(),
                code.as_str(),
                latency_ms
            )
            .map_err(|_| StableCode::KernelUnavailable)?;
            push_hex(&mut output, connection_audit_id.0.as_bytes());
            output.push('"');
            if let Some(run_audit_id) = run_audit_id {
                output.push_str(r#","run_audit_id":""#);
                push_hex(&mut output, run_audit_id.0.as_bytes());
                output.push('"');
            }
            output.push('}');
        }
        AuditEvent::Fatal { code } => {
            write!(output, r#"{{"event":"Fatal","code":"{}"}}"#, code.as_str())
                .map_err(|_| StableCode::KernelUnavailable)?;
        }
        AuditEvent::Stopped { reason } => {
            write!(
                output,
                r#"{{"event":"Stopped","reason":"{}"}}"#,
                reason.as_str()
            )
            .map_err(|_| StableCode::KernelUnavailable)?;
        }
    }
    output.push('\n');
    if output.len() > MAXIMUM_AUDIT_LINE_BYTES {
        return Err(StableCode::KernelUnavailable);
    }
    Ok(output.into_bytes())
}

fn push_hex(output: &mut String, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    use savana_kernel_protocol::{
        BootId, ClientId, Digest32, KeyId, Nonce32, ProtocolVersion, RunHandle, ServerIdentityV1,
        StableCode,
    };
    #[cfg(target_os = "macos")]
    use std::fs::File;

    use super::*;

    fn test_secret() -> AuditSecret {
        AuditSecret::from_test_bytes([0xa5; 32])
    }

    fn test_audit_id(byte: u8) -> AuditId {
        AuditId(Digest32::new([byte; 32]))
    }

    #[test]
    fn audit_hmac_vectors_and_domains_are_exact() {
        let sink = AuditSink::with_secret_for_test([0xa5; 32], Duration::from_millis(100)).unwrap();
        let connection = AuditConnectionIdentity::new(
            BootId::new([0x01; 32]),
            1,
            ClientId::try_from("client-a").unwrap(),
            501,
            Nonce32::new([0x02; 32]),
        );
        let run = AuditRunIdentity::new(BootId::new([0x01; 32]), 1, run_handle_with_byte(0x03));
        assert_eq!(
            sink.connection_audit_id(&connection).unwrap().to_hex(),
            "e7777129814628ad7123004249636a39bad3560a51eb0debbb2290ea7a52ca75"
        );
        assert_eq!(
            sink.run_audit_id(&run).unwrap().to_hex(),
            "2e1162eca89842ce32fc77ca0478da873321eb15328219447217718d83809263"
        );
        assert_ne!(
            sink.connection_audit_id(&connection).unwrap().to_hex(),
            sink.run_audit_id(&run).unwrap().to_hex()
        );
    }

    #[test]
    fn correlation_is_stable_within_one_boot_and_unlinkable_across_boots() {
        let identity = AuditConnectionIdentity::new(
            BootId::new([0x11; 32]),
            7,
            ClientId::try_from("client-a").unwrap(),
            501,
            Nonce32::new([0x22; 32]),
        );
        let first =
            AuditSink::with_secret_for_test([0x61; 32], Duration::from_millis(100)).unwrap();
        let second =
            AuditSink::with_secret_for_test([0x62; 32], Duration::from_millis(100)).unwrap();
        assert_eq!(
            first.connection_audit_id(&identity).unwrap(),
            first.connection_audit_id(&identity).unwrap()
        );
        assert_ne!(
            first.connection_audit_id(&identity).unwrap(),
            second.connection_audit_id(&identity).unwrap()
        );
    }

    fn run_handle_with_byte(byte: u8) -> RunHandle {
        let mut encoded = Vec::with_capacity(34);
        encoded.extend_from_slice(&[0x58, 0x20]);
        encoded.extend_from_slice(&[byte; 32]);
        minicbor::decode(&encoded).unwrap()
    }

    #[test]
    fn closed_events_have_fixed_order_bounded_redacted_json_lines() {
        let (writer, mut reader) = UnixStream::pair().unwrap();
        let writer: OwnedFd = writer.into();
        let sink =
            AuditSink::from_owned_for_test(test_secret(), writer, Duration::from_millis(100))
                .unwrap();
        let identity = ServerIdentityV1 {
            daemon_key_id: KeyId::try_from("not-emitted").unwrap(),
            boot_id: BootId::new([0x01; 32]),
            protocol: ProtocolVersion::new(1, 0),
            release_digest: Digest32::new([0x02; 32]),
            policy_digest: Digest32::new([0x03; 32]),
            policy_version: 7,
            model_manifest_digest: Digest32::new([0x04; 32]),
            approval_key_set_digest: Digest32::new([0x05; 32]),
            resource_profile_digest: Digest32::new([0x06; 32]),
        };

        sink.emit(AuditEvent::BootstrapFailed {
            code: StableCode::IdentityReleaseMismatch,
        })
        .unwrap();
        sink.emit(AuditEvent::Started {
            identity: &identity,
        })
        .unwrap();
        sink.emit(AuditEvent::HandshakeRejected {
            code: StableCode::IdentityPeerRejected,
        })
        .unwrap();
        sink.emit(AuditEvent::RequestCompleted {
            operation_tag: OperationTag::Health,
            code: RequestCode::Ok,
            latency_ms: 9,
            connection_audit_id: test_audit_id(0x07),
            run_audit_id: None,
        })
        .unwrap();
        sink.emit(AuditEvent::Fatal {
            code: StableCode::KernelUnavailable,
        })
        .unwrap();
        sink.emit(AuditEvent::Stopped {
            reason: ShutdownReason::Sigterm,
        })
        .unwrap();
        drop(sink);

        let mut output = String::new();
        reader.read_to_string(&mut output).unwrap();
        let lines: Vec<_> = output.lines().collect();
        assert_eq!(lines.len(), 6);
        assert_eq!(
            lines[0],
            r#"{"event":"BootstrapFailed","code":"IDENTITY_RELEASE_MISMATCH"}"#
        );
        let expected_started = format!(
            concat!(
                r#"{{"event":"Started","boot_id":"{}","#,
                r#""protocol_major":1,"protocol_minor":0,"release_digest":"{}","#,
                r#""policy_digest":"{}","policy_version":7,"model_manifest_digest":"{}","#,
                r#""approval_key_set_digest":"{}","resource_profile_digest":"{}"}}"#
            ),
            "01".repeat(32),
            "02".repeat(32),
            "03".repeat(32),
            "04".repeat(32),
            "05".repeat(32),
            "06".repeat(32),
        );
        assert_eq!(lines[1], expected_started);
        assert_eq!(
            lines[2],
            r#"{"event":"HandshakeRejected","code":"IDENTITY_PEER_REJECTED"}"#
        );
        assert_eq!(
            lines[3],
            format!(
                concat!(
                    r#"{{"event":"RequestCompleted","operation_tag":"health","code":"OK","latency_ms":9,"#,
                    r#""connection_audit_id":"{}"}}"#
                ),
                "07".repeat(32)
            )
        );
        assert_eq!(lines[4], r#"{"event":"Fatal","code":"KERNEL_UNAVAILABLE"}"#);
        assert_eq!(lines[5], r#"{"event":"Stopped","reason":"sigterm"}"#);
        assert!(lines.iter().all(|line| line.len() < 1024));
        assert!(!output.contains("not-emitted"));
    }

    #[test]
    fn regular_file_sink_is_rejected() {
        let file = tempfile::tempfile().unwrap();
        let owned: OwnedFd = file.into();

        assert_eq!(
            AuditSink::from_owned_for_test(test_secret(), owned, Duration::from_millis(100))
                .err()
                .unwrap(),
            StableCode::KernelUnavailable
        );
    }

    #[test]
    fn a_poisoned_audit_mutex_fails_closed() {
        let _panic_guard = crate::panic_report::PROCESS_PANIC_TEST_LOCK.lock().unwrap();
        let (writer, _reader) = UnixStream::pair().unwrap();
        let writer: OwnedFd = writer.into();
        let sink =
            AuditSink::from_owned_for_test(test_secret(), writer, Duration::from_millis(100))
                .unwrap();

        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = sink.writer.lock().unwrap();
            panic!("poison audit mutex");
        }));

        assert_eq!(
            sink.emit(AuditEvent::Fatal {
                code: StableCode::KernelUnavailable,
            }),
            Err(StableCode::KernelUnavailable)
        );
    }

    #[test]
    fn closed_sink_write_failure_is_global() {
        let (writer, reader) = UnixStream::pair().unwrap();
        drop(reader);
        let writer: OwnedFd = writer.into();
        let sink =
            AuditSink::from_owned_for_test(test_secret(), writer, Duration::from_millis(100))
                .unwrap();

        assert_eq!(
            sink.emit(AuditEvent::Fatal {
                code: StableCode::KernelUnavailable,
            }),
            Err(StableCode::KernelUnavailable)
        );
    }

    #[test]
    fn one_deadline_bounds_a_full_nonblocking_sink() {
        let (writer, _reader) = UnixStream::pair().unwrap();
        let status = fcntl_getfl(&writer).unwrap() | OFlags::NONBLOCK;
        fcntl_setfl(&writer, status).unwrap();
        let block = [0xa5; 4096];
        loop {
            match write(&writer, &block) {
                Ok(_) => {}
                Err(error) if error == Errno::AGAIN => break,
                Err(error) => panic!("failed to fill audit socket: {error}"),
            }
        }
        let writer: OwnedFd = writer.into();
        let sink = AuditSink::from_owned_for_test(test_secret(), writer, Duration::from_millis(10))
            .unwrap();
        let started = Instant::now();

        assert_eq!(
            sink.emit(AuditEvent::Fatal {
                code: StableCode::KernelUnavailable,
            }),
            Err(StableCode::KernelUnavailable)
        );
        assert!(started.elapsed() < Duration::from_millis(250));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_dev_null_is_not_accepted_as_an_audit_poll_bypass() {
        let file = File::options().write(true).open("/dev/null").unwrap();
        let owned: OwnedFd = file.into();

        assert_eq!(
            AuditSink::from_owned_for_test(test_secret(), owned, Duration::from_millis(100))
                .err()
                .unwrap(),
            StableCode::KernelUnavailable
        );
    }
}
