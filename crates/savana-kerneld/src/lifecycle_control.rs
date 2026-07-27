//! Debug-only mapped-installation lifecycle control used by subprocess tests.
//!
//! This is deliberately not a protocol operation, signal action, watcher, or
//! public Rust API.  The reader only accepts one-byte jobs on stdin; all jobs
//! which can wait on the daemon are executed away from the reader and stdout
//! responses have a fixed, non-secret binary layout.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, TryRecvError, TrySendError};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::thread;

use ed25519_dalek::{Signer, SigningKey};
use savana_kernel_protocol::{
    ingress_request_digest, AttemptKindV1, BeginRunRequest, BoundedText, ConstraintId, Digest32,
    IngestUserInputRequest, IngressEnvelopeV1, IngressRequestCommitmentV1, KernelValue, KeyId,
    Nonce32, PrincipalId, RegistrySnapshotV1, RoleId, RunHandle, Signature64,
    SignedIngressEnvelopeV1, SignedRegistrySnapshotV1, StableCode, ToolDescriptorV1,
    ToolExecutionIdentity, ToolName, UnixMillis,
};
use savana_policy_core::Clock;

use crate::handshake::{ConnectionContext, HandshakeService, TestLifecycleHandshake};
use crate::policy_runtime::{PolicyRolloverCoordinator, PolicyRuntime, RefreshOutcome};
use crate::server::ServerLifecycle;

pub(crate) const LIFECYCLE_CONTROL_ENV: &str = "SAVANA_TEST_LIFECYCLE_CONTROL";
const LIFECYCLE_CONTROL_MODE: &str = "stdio-v1";
const RESPONSE_BYTES: usize = 72;
const CONTROL_QUEUE_CAPACITY: usize = 32;
const MAX_DEFERRED_COMMANDS: usize = 32;
const MAX_ASYNCHRONOUS_JOBS: usize = 32;

const STARTUP_READY: u8 = 0x00;
const CONTINUE_STARTUP: u8 = 0x01;
const REFRESH: u8 = 0x02;
const PAUSE_BEGIN: u8 = 0x03;
const RELEASE_BEGIN: u8 = 0x04;
const PROBE_ADMISSION: u8 = 0x05;
const OBSERVE: u8 = 0x06;
const USE_OLD_CONTEXT: u8 = 0x07;
const SUBMIT_OLD_INGRESS: u8 = 0x08;
const USE_OLD_RUN: u8 = 0x09;
const PRE_RENAME_FAULT: u8 = 0x0a;
const DROP_PUBLICATION_GUARD: u8 = 0x0b;
const POST_SWAP_FAULT: u8 = 0x0c;
const QUERY_POLICY: u8 = 0x0d;
const OBSERVE_REPLAY_TOMBSTONE: u8 = 0x0e;
const CAPTURE_OLD_ARTIFACTS: u8 = 0x0f;
const POST_RENAME_FAULT: u8 = 0x10;
const SHUTDOWN: u8 = 0xff;

const STATUS_OK: u8 = 0;
const STATUS_READY: u8 = 1;
const STATUS_UNCHANGED: u8 = 2;
const STATUS_PUBLISHED: u8 = 3;
const STATUS_KERNEL_UNAVAILABLE: u8 = 4;
const STATUS_IDENTITY_TRANSCRIPT_MISMATCH: u8 = 5;
const STATUS_ATTESTATION_BINDING_MISMATCH: u8 = 6;
const STATUS_HANDLE_STALE_POLICY: u8 = 7;

const INGRESS_DOMAIN: &[u8] = b"SAVANA_INGRESS_V1\0";
const REGISTRY_DOMAIN: &[u8] = b"SAVANA_REGISTRY_V1\0";

pub(crate) fn requested() -> Result<bool, StableCode> {
    match std::env::var_os(LIFECYCLE_CONTROL_ENV) {
        None => Ok(false),
        Some(value) if value == LIFECYCLE_CONTROL_MODE => Ok(true),
        Some(_) => Err(StableCode::KernelUnavailable),
    }
}

struct CapturedArtifacts {
    context: ConnectionContext,
    client_nonce: Nonce32,
    begin: BeginRunRequest,
    run: RunHandle,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PausedBeginState {
    Idle,
    Starting,
    Held,
    Released,
}

struct PausedBeginControl {
    state: Mutex<PausedBeginState>,
    changed: Condvar,
}

impl PausedBeginControl {
    fn reserve(self: &Arc<Self>) -> Result<PausedBeginReservation, StableCode> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| StableCode::KernelUnavailable)?;
        if *state != PausedBeginState::Idle {
            return Err(StableCode::KernelUnavailable);
        }
        *state = PausedBeginState::Starting;
        Ok(PausedBeginReservation {
            control: Arc::clone(self),
            announced: false,
        })
    }

    fn release(&self) -> Result<(), StableCode> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| StableCode::KernelUnavailable)?;
        if *state != PausedBeginState::Held {
            return Err(StableCode::KernelUnavailable);
        }
        *state = PausedBeginState::Released;
        self.changed.notify_all();
        Ok(())
    }
}

struct PausedBeginReservation {
    control: Arc<PausedBeginControl>,
    announced: bool,
}

impl PausedBeginReservation {
    fn announce_ready(&mut self) -> Result<(), StableCode> {
        let mut state = self
            .control
            .state
            .lock()
            .map_err(|_| StableCode::KernelUnavailable)?;
        if *state != PausedBeginState::Starting {
            return Err(StableCode::KernelUnavailable);
        }
        *state = PausedBeginState::Held;
        self.announced = true;
        self.control.changed.notify_all();
        Ok(())
    }

    fn wait_for_release(&self) -> Result<(), StableCode> {
        let mut state = self
            .control
            .state
            .lock()
            .map_err(|_| StableCode::KernelUnavailable)?;
        while *state == PausedBeginState::Held {
            state = self
                .control
                .changed
                .wait(state)
                .map_err(|_| StableCode::KernelUnavailable)?;
        }
        if *state == PausedBeginState::Released {
            Ok(())
        } else {
            Err(StableCode::KernelUnavailable)
        }
    }
}

impl Drop for PausedBeginReservation {
    fn drop(&mut self) {
        if let Ok(mut state) = self.control.state.lock() {
            *state = PausedBeginState::Idle;
            self.control.changed.notify_all();
        }
    }
}

struct AsyncJobGate {
    active: AtomicUsize,
}

impl AsyncJobGate {
    fn try_reserve(self: &Arc<Self>) -> Result<AsyncJobReservation, StableCode> {
        let mut active = self.active.load(Ordering::Acquire);
        loop {
            if active >= MAX_ASYNCHRONOUS_JOBS {
                return Err(StableCode::KernelUnavailable);
            }
            match self.active.compare_exchange_weak(
                active,
                active + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Ok(AsyncJobReservation {
                        gate: Arc::clone(self),
                    });
                }
                Err(observed) => active = observed,
            }
        }
    }
}

struct AsyncJobReservation {
    gate: Arc<AsyncJobGate>,
}

impl Drop for AsyncJobReservation {
    fn drop(&mut self) {
        let previous = self.gate.active.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0, "asynchronous job reservation underflow");
    }
}

struct ControlInner {
    runtime: Arc<PolicyRuntime>,
    rollover: Arc<PolicyRolloverCoordinator>,
    clock: Arc<dyn Clock + Send + Sync>,
    service: OnceLock<Arc<HandshakeService>>,
    output: Mutex<std::io::Stdout>,
    artifacts: Mutex<Option<CapturedArtifacts>>,
    paused_begin: Arc<PausedBeginControl>,
    async_jobs: Arc<AsyncJobGate>,
    async_response_failed: AtomicBool,
    ingress_nonce: AtomicU64,
    graceful_shutdown: Arc<AtomicBool>,
}

impl ControlInner {
    fn service(&self) -> Result<&Arc<HandshakeService>, StableCode> {
        self.service.get().ok_or(StableCode::KernelUnavailable)
    }

    fn now(&self) -> Result<UnixMillis, StableCode> {
        self.clock
            .wall_now()
            .map_err(|_| StableCode::KernelUnavailable)
    }

    fn response(&self, opcode: u8, status: u8) -> Result<(), StableCode> {
        let snapshot = self.runtime.snapshot();
        let mut bytes = [0_u8; RESPONSE_BYTES];
        bytes[0] = opcode;
        bytes[1] = status;
        if let Ok(snapshot) = snapshot {
            let identity = snapshot.policy_identity();
            bytes[4..12].copy_from_slice(&snapshot.generation().to_be_bytes());
            bytes[12..20].copy_from_slice(&identity.policy_version.to_be_bytes());
            bytes[20..28].copy_from_slice(&identity.key_epoch.to_be_bytes());
            bytes[28..36].copy_from_slice(&identity.expires_at.get().to_be_bytes());
            bytes[36..68].copy_from_slice(identity.digest.as_bytes());
            let frame_limit = u32::try_from(snapshot.effective_limits().frame_bytes())
                .map_err(|_| StableCode::KernelUnavailable)?;
            bytes[68..72].copy_from_slice(&frame_limit.to_be_bytes());
        }
        let mut output = self
            .output
            .lock()
            .map_err(|_| StableCode::KernelUnavailable)?;
        output
            .write_all(&bytes)
            .and_then(|_| output.flush())
            .map_err(|_| StableCode::KernelUnavailable)
    }

    fn response_for_code(
        &self,
        opcode: u8,
        result: Result<(), StableCode>,
    ) -> Result<(), StableCode> {
        match result {
            Ok(()) => self.response(opcode, STATUS_OK),
            Err(code) => self.response(opcode, control_status(code)),
        }
    }

    // Async jobs cannot return write errors to the server loop directly.  A
    // response failure is therefore latched here and observed by
    // TestLifecycle::poll_shutdown before it polls the underlying lifecycle.
    fn response_from_async(&self, opcode: u8, status: u8) -> bool {
        match self.response(opcode, status) {
            Ok(()) => true,
            Err(_) => {
                self.async_response_failed.store(true, Ordering::Release);
                false
            }
        }
    }

    fn has_async_response_failure(&self) -> bool {
        self.async_response_failed.load(Ordering::Acquire)
    }

    fn deadline(
        &self,
        now: UnixMillis,
        identity_expires: UnixMillis,
    ) -> Result<UnixMillis, StableCode> {
        let snapshot = self.runtime.snapshot()?;
        let limit = snapshot.effective_limits().request_deadline_ms();
        let remaining = identity_expires
            .get()
            .checked_sub(now.get())
            .ok_or(StableCode::DeadlineExceeded)?;
        let delta = limit.min(remaining).min(1_000);
        if delta == 0 {
            return Err(StableCode::DeadlineExceeded);
        }
        now.get()
            .checked_add(delta)
            .map(UnixMillis::new)
            .ok_or(StableCode::KernelUnavailable)
    }

    fn bind(
        &self,
        context: &ConnectionContext,
        now: UnixMillis,
    ) -> Result<savana_policy_core::AuthenticatedCallContext, StableCode> {
        let deadline = self.deadline(now, context.expires_at())?;
        self.runtime
            .issuer()
            .bind(
                context.client_id().clone(),
                context.connection_id(),
                context.connection_binding_digest(),
                context.policy_identity(),
                context.boot_id(),
                context.peer().uid(),
                deadline,
            )
            .map_err(|error| error.code())
    }

    fn next_ingress_nonce(&self) -> Nonce32 {
        let value = self.ingress_nonce.fetch_add(1, Ordering::AcqRel);
        let mut bytes = [0_u8; 32];
        bytes[..8].copy_from_slice(&value.to_be_bytes());
        Nonce32::new(bytes)
    }

    fn signed_ingress(
        &self,
        context: &ConnectionContext,
        identity: savana_policy_core::PolicyIdentity,
        request_digest: Digest32,
        now: UnixMillis,
    ) -> Result<SignedIngressEnvelopeV1, StableCode> {
        let unsigned = IngressEnvelopeV1 {
            principal: PrincipalId::new("lifecycle-principal")
                .map_err(|_| StableCode::KernelUnavailable)?,
            conversation_id: "lifecycle-conversation"
                .try_into()
                .map_err(|_| StableCode::KernelUnavailable)?,
            request_digest,
            issued_at: now,
            expires_at: identity.expires_at,
            nonce: self.next_ingress_nonce(),
            authority_session_id: Nonce32::new([0x66; 32]),
            authentication_context_digest: Digest32::new([0x55; 32]),
            role: RoleId::new("operator").map_err(|_| StableCode::KernelUnavailable)?,
            policy_digest: identity.digest,
            boot_id: context.boot_id(),
            connection_binding_digest: context.connection_binding_digest(),
        };
        Ok(SignedIngressEnvelopeV1 {
            signature: sign_value(
                INGRESS_DOMAIN,
                &unsigned,
                &SigningKey::from_bytes(&[0x70; 32]),
            )?,
            unsigned,
            key_id: KeyId::new("role-00").map_err(|_| StableCode::KernelUnavailable)?,
        })
    }

    fn signed_registry(
        &self,
        identity: savana_policy_core::PolicyIdentity,
        now: UnixMillis,
    ) -> Result<SignedRegistrySnapshotV1, StableCode> {
        let unsigned = RegistrySnapshotV1 {
            version: 1,
            previous_digest: None,
            tools: vec![ToolDescriptorV1 {
                identity: ToolExecutionIdentity {
                    name: ToolName::new("operator-tool")
                        .map_err(|_| StableCode::KernelUnavailable)?,
                    descriptor_digest: Digest32::new([0x21; 32]),
                    registry_version: 1,
                },
                provider_id: BoundedText::new("lifecycle-provider")
                    .map_err(|_| StableCode::KernelUnavailable)?,
                roles: vec![RoleId::new("operator").map_err(|_| StableCode::KernelUnavailable)?],
                input_schema_digest: Digest32::new([0x31; 32]),
                output_schema_digest: Digest32::new([0x32; 32]),
                attempt: AttemptKindV1::Read,
                constraint_ids: vec![ConstraintId::new("constraint-00")
                    .map_err(|_| StableCode::KernelUnavailable)?],
                validator_ids: Vec::new(),
                projection_digest: Digest32::new([0x33; 32]),
            }],
            issued_at: now,
            expires_at: identity.expires_at,
        };
        Ok(SignedRegistrySnapshotV1 {
            signature: sign_value(
                REGISTRY_DOMAIN,
                &unsigned,
                &SigningKey::from_bytes(&[0x72; 32]),
            )?,
            unsigned,
            key_id: KeyId::new("role-02").map_err(|_| StableCode::KernelUnavailable)?,
        })
    }

    fn begin_request(
        &self,
        context: &ConnectionContext,
        identity: savana_policy_core::PolicyIdentity,
        now: UnixMillis,
    ) -> Result<BeginRunRequest, StableCode> {
        let input = KernelValue::Null;
        let commitment = IngressRequestCommitmentV1::BeginRun {
            input: input.clone(),
        };
        let digest = ingress_request_digest(&commitment).map_err(|error| error.code())?;
        Ok(BeginRunRequest {
            ingress: self.signed_ingress(context, identity, digest, now)?,
            input,
            registry: self.signed_registry(identity, now)?,
        })
    }

    fn capture_old_artifacts(&self) -> Result<(), StableCode> {
        let now = self.now()?;
        // Match the server request path: admission is established first, then
        // the authenticated handshake runs against that leased snapshot.
        let dispatch = self.runtime.dispatch_lease()?;
        let snapshot = Arc::clone(dispatch.snapshot());
        let TestLifecycleHandshake {
            context,
            client_nonce,
        } = self.service()?.establish_test_lifecycle_context(now)?;
        self.service()?
            .validate_context_identity_in_snapshot(&context, now, snapshot.as_ref())?;
        let authenticated = self.bind(&context, now)?;
        let begin = self.begin_request(&context, snapshot.policy_identity(), now)?;
        let response = self
            .runtime
            .engine()
            .begin_run(&authenticated, begin.clone())
            .map_err(|error| error.code())?;
        drop(dispatch);
        let mut artifacts = self
            .artifacts
            .lock()
            .map_err(|_| StableCode::KernelUnavailable)?;
        if artifacts.is_some() {
            return Err(StableCode::KernelUnavailable);
        }
        *artifacts = Some(CapturedArtifacts {
            context,
            client_nonce,
            begin,
            run: response.run,
        });
        Ok(())
    }

    fn use_old_context(&self) -> Result<(), StableCode> {
        let now = self.now()?;
        let artifacts = self
            .artifacts
            .lock()
            .map_err(|_| StableCode::KernelUnavailable)?;
        let artifacts = artifacts.as_ref().ok_or(StableCode::KernelUnavailable)?;
        match self
            .service()?
            .validate_context_identity(&artifacts.context, now)
        {
            Err(code) => Err(code),
            Ok(_) => Err(StableCode::KernelUnavailable),
        }
    }

    fn submit_old_ingress(&self) -> Result<(), StableCode> {
        let now = self.now()?;
        let artifacts = self
            .artifacts
            .lock()
            .map_err(|_| StableCode::KernelUnavailable)?;
        let artifacts = artifacts.as_ref().ok_or(StableCode::KernelUnavailable)?;
        let current = self
            .service()?
            .establish_test_lifecycle_context(now)?
            .context;
        let authenticated = self.bind(&current, now)?;
        self.runtime
            .engine()
            .begin_run(&authenticated, artifacts.begin.clone())
            .map(|_| ())
            .map_err(|error| error.code())
    }

    fn use_old_run(&self) -> Result<(), StableCode> {
        let now = self.now()?;
        let artifacts = self
            .artifacts
            .lock()
            .map_err(|_| StableCode::KernelUnavailable)?;
        let artifacts = artifacts.as_ref().ok_or(StableCode::KernelUnavailable)?;
        let current = self
            .service()?
            .establish_test_lifecycle_context(now)?
            .context;
        let snapshot = self.runtime.snapshot()?;
        let authenticated = self.bind(&current, now)?;
        let input = KernelValue::Null;
        let commitment = IngressRequestCommitmentV1::IngestUserInput {
            run: artifacts.run,
            input: input.clone(),
        };
        let digest = ingress_request_digest(&commitment).map_err(|error| error.code())?;
        let envelope = self.signed_ingress(&current, snapshot.policy_identity(), digest, now)?;
        self.runtime
            .engine()
            .ingest_user_input(
                &authenticated,
                IngestUserInputRequest {
                    run: artifacts.run,
                    envelope,
                    input,
                },
            )
            .map(|_| ())
            .map_err(|error| error.code())
    }

    fn observe_replay_tombstone(&self) -> Result<(), StableCode> {
        let now = self.now()?;
        let artifacts = self
            .artifacts
            .lock()
            .map_err(|_| StableCode::KernelUnavailable)?;
        let artifacts = artifacts.as_ref().ok_or(StableCode::KernelUnavailable)?;
        if self
            .service()?
            .test_lifecycle_replay_is_retained(artifacts.client_nonce, now)?
        {
            Ok(())
        } else {
            Err(StableCode::KernelUnavailable)
        }
    }

    fn observe(&self) -> Result<(), StableCode> {
        let now = self.now()?;
        let context = self
            .service()?
            .establish_test_lifecycle_context(now)?
            .context;
        self.service()?.validate_context_identity(&context, now)?;
        Ok(())
    }

    fn query_policy(&self) -> Result<(), StableCode> {
        let snapshot = self.runtime.snapshot()?;
        if snapshot.policy_identity() == self.runtime.engine().current_policy_identity()
            && snapshot.effective_limits() == self.runtime.engine().effective_limits()
        {
            Ok(())
        } else {
            Err(StableCode::KernelUnavailable)
        }
    }
}

pub(crate) struct TestLifecycleControl {
    inner: Arc<ControlInner>,
    receiver: Receiver<u8>,
    deferred: VecDeque<u8>,
}

impl TestLifecycleControl {
    pub(crate) fn new(
        runtime: Arc<PolicyRuntime>,
        rollover: Arc<PolicyRolloverCoordinator>,
        clock: Arc<dyn Clock + Send + Sync>,
    ) -> Self {
        let (sender, receiver) = mpsc::sync_channel(CONTROL_QUEUE_CAPACITY);
        thread::Builder::new()
            .name("savana-kerneld-lifecycle-reader".to_owned())
            .spawn(move || {
                let mut stdin = std::io::stdin();
                let mut command = [0_u8; 1];
                while stdin.read_exact(&mut command).is_ok() {
                    match sender.try_send(command[0]) {
                        Ok(()) => {}
                        // An opcode flood must not create an unbounded control
                        // queue.  Closing the sender turns the exhausted queue
                        // into the existing fatal/disconnected control path.
                        Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => return,
                    }
                }
            })
            .unwrap_or_else(|_| std::process::abort());
        Self {
            inner: Arc::new(ControlInner {
                runtime,
                rollover,
                clock,
                service: OnceLock::new(),
                output: Mutex::new(std::io::stdout()),
                artifacts: Mutex::new(None),
                paused_begin: Arc::new(PausedBeginControl {
                    state: Mutex::new(PausedBeginState::Idle),
                    changed: Condvar::new(),
                }),
                async_jobs: Arc::new(AsyncJobGate {
                    active: AtomicUsize::new(0),
                }),
                async_response_failed: AtomicBool::new(false),
                ingress_nonce: AtomicU64::new(0xa000),
                graceful_shutdown: Arc::new(AtomicBool::new(false)),
            }),
            receiver,
            deferred: VecDeque::new(),
        }
    }

    pub(crate) fn wait_for_continue(&mut self) -> Result<(), StableCode> {
        self.inner.response(STARTUP_READY, STATUS_READY)?;
        loop {
            let command = self
                .receiver
                .recv()
                .map_err(|_| StableCode::KernelUnavailable)?;
            match command {
                CONTINUE_STARTUP => return Ok(()),
                SHUTDOWN => return Err(StableCode::KernelUnavailable),
                other => {
                    if self.deferred.len() >= MAX_DEFERRED_COMMANDS {
                        return Err(StableCode::KernelUnavailable);
                    }
                    self.deferred.push_back(other);
                }
            }
        }
    }

    pub(crate) fn attach_handshake_service(
        &self,
        service: Arc<HandshakeService>,
    ) -> Result<(), StableCode> {
        self.inner
            .service
            .set(service)
            .map_err(|_| StableCode::KernelUnavailable)
    }

    pub(crate) fn graceful_completion_marker(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.inner.graceful_shutdown)
    }

    pub(crate) fn report_pre_activation_failure(&self, code: StableCode) {
        let _ = self.inner.response(CONTINUE_STARTUP, control_status(code));
    }

    fn next_command(&mut self) -> Result<Option<u8>, StableCode> {
        if let Some(command) = self.deferred.pop_front() {
            return Ok(Some(command));
        }
        match self.receiver.try_recv() {
            Ok(command) => Ok(Some(command)),
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => Err(StableCode::KernelUnavailable),
        }
    }

    fn reserve_async_job(&self) -> Result<AsyncJobReservation, StableCode> {
        self.inner.async_jobs.try_reserve()
    }

    fn spawn_refresh(&self, opcode: u8) -> Result<(), StableCode> {
        let reservation = self.reserve_async_job()?;
        self.spawn_refresh_with_reservation(opcode, reservation)
    }

    fn spawn_refresh_with_reservation(
        &self,
        opcode: u8,
        reservation: AsyncJobReservation,
    ) -> Result<(), StableCode> {
        let inner = Arc::clone(&self.inner);
        thread::Builder::new()
            .name("savana-kerneld-rollover-job".to_owned())
            .spawn(move || {
                let _reservation = reservation;
                let status = match inner.rollover.refresh_selected_policy() {
                    Ok(RefreshOutcome::Unchanged(_)) => STATUS_UNCHANGED,
                    Ok(RefreshOutcome::Published(_)) => STATUS_PUBLISHED,
                    Err(code) => control_status(code),
                };
                inner.response_from_async(opcode, status);
            })
            .map(|_| ())
            .map_err(|_| StableCode::KernelUnavailable)
    }

    fn spawn_admission_probe(&self) -> Result<(), StableCode> {
        let reservation = self.reserve_async_job()?;
        let inner = Arc::clone(&self.inner);
        thread::Builder::new()
            .name("savana-kerneld-admission-probe".to_owned())
            .spawn(move || {
                let _reservation = reservation;
                let result = inner.runtime.admission_lease().map(drop);
                let status = match result {
                    Ok(()) => STATUS_OK,
                    Err(code) => control_status(code),
                };
                inner.response_from_async(PROBE_ADMISSION, status);
            })
            .map(|_| ())
            .map_err(|_| StableCode::KernelUnavailable)
    }

    fn spawn_paused_begin(&self) -> Result<(), StableCode> {
        let async_reservation = self.reserve_async_job()?;
        let reservation = self.inner.paused_begin.reserve()?;
        let inner = Arc::clone(&self.inner);
        thread::Builder::new()
            .name("savana-kerneld-paused-begin".to_owned())
            .spawn(move || {
                let _async_reservation = async_reservation;
                let mut reservation = reservation;
                let mut released = false;
                let result = (|| {
                    // This is intentionally the actual normal order: lease the
                    // dispatch generation, perform the real handshake, bind an
                    // issuer context, then prepare a genuine BeginRun request.
                    let now = inner.now()?;
                    let dispatch = inner.runtime.dispatch_lease()?;
                    let snapshot = Arc::clone(dispatch.snapshot());
                    let TestLifecycleHandshake { context, .. } =
                        inner.service()?.establish_test_lifecycle_context(now)?;
                    inner.service()?.validate_context_identity_in_snapshot(
                        &context,
                        now,
                        snapshot.as_ref(),
                    )?;
                    let authenticated = inner.bind(&context, now)?;
                    let begin = inner.begin_request(&context, snapshot.policy_identity(), now)?;
                    reservation.announce_ready()?;
                    if !inner.response_from_async(PAUSE_BEGIN, STATUS_READY) {
                        return Err(StableCode::KernelUnavailable);
                    }
                    reservation.wait_for_release()?;
                    released = true;
                    inner
                        .runtime
                        .engine()
                        .begin_run(&authenticated, begin)
                        .map_err(|error| error.code())?;
                    drop(dispatch);
                    Ok(())
                })();
                // Before Ready, PAUSE_BEGIN has a single definitive response.
                // Once released, report RELEASE_BEGIN only after the genuine
                // BeginRun has completed and its dispatch lease has dropped.
                match result {
                    Err(code) if !reservation.announced => {
                        inner.response_from_async(PAUSE_BEGIN, control_status(code));
                    }
                    Err(code) if released => {
                        inner.response_from_async(RELEASE_BEGIN, control_status(code));
                    }
                    Ok(()) if released => {
                        inner.response_from_async(RELEASE_BEGIN, STATUS_OK);
                    }
                    _ => {}
                }
            })
            .map(|_| ())
            .map_err(|_| StableCode::KernelUnavailable)
    }

    fn process_command(&mut self, command: u8) -> Result<bool, StableCode> {
        match command {
            REFRESH => {
                if let Err(code) = self.spawn_refresh(REFRESH) {
                    self.inner.response(REFRESH, control_status(code))?;
                }
                Ok(false)
            }
            PAUSE_BEGIN => {
                if let Err(code) = self.spawn_paused_begin() {
                    self.inner.response(PAUSE_BEGIN, control_status(code))?;
                }
                Ok(false)
            }
            RELEASE_BEGIN => {
                if let Err(code) = self.inner.paused_begin.release() {
                    self.inner.response(RELEASE_BEGIN, control_status(code))?;
                }
                Ok(false)
            }
            PROBE_ADMISSION => {
                if let Err(code) = self.spawn_admission_probe() {
                    self.inner.response(PROBE_ADMISSION, control_status(code))?;
                }
                Ok(false)
            }
            OBSERVE => {
                self.inner
                    .response_for_code(OBSERVE, self.inner.observe())?;
                Ok(false)
            }
            QUERY_POLICY => {
                self.inner
                    .response_for_code(QUERY_POLICY, self.inner.query_policy())?;
                Ok(false)
            }
            CAPTURE_OLD_ARTIFACTS => {
                self.inner
                    .response_for_code(CAPTURE_OLD_ARTIFACTS, self.inner.capture_old_artifacts())?;
                Ok(false)
            }
            USE_OLD_CONTEXT => {
                self.inner
                    .response_for_code(USE_OLD_CONTEXT, self.inner.use_old_context())?;
                Ok(false)
            }
            SUBMIT_OLD_INGRESS => {
                self.inner
                    .response_for_code(SUBMIT_OLD_INGRESS, self.inner.submit_old_ingress())?;
                Ok(false)
            }
            USE_OLD_RUN => {
                self.inner
                    .response_for_code(USE_OLD_RUN, self.inner.use_old_run())?;
                Ok(false)
            }
            OBSERVE_REPLAY_TOMBSTONE => {
                self.inner.response_for_code(
                    OBSERVE_REPLAY_TOMBSTONE,
                    self.inner.observe_replay_tombstone(),
                )?;
                Ok(false)
            }
            PRE_RENAME_FAULT | POST_RENAME_FAULT => {
                let reservation = match self.reserve_async_job() {
                    Ok(reservation) => reservation,
                    Err(code) => {
                        self.inner.response(command, control_status(code))?;
                        return Ok(false);
                    }
                };
                if let Err(code) = self.spawn_refresh_with_reservation(command, reservation) {
                    self.inner.response(command, control_status(code))?;
                }
                Ok(false)
            }
            DROP_PUBLICATION_GUARD | POST_SWAP_FAULT => {
                let reservation = match self.reserve_async_job() {
                    Ok(reservation) => reservation,
                    Err(code) => {
                        self.inner.response(command, control_status(code))?;
                        return Ok(false);
                    }
                };
                self.inner.rollover.arm_fault_for_test_lifecycle(command)?;
                if let Err(code) = self.spawn_refresh_with_reservation(command, reservation) {
                    self.inner.response(command, control_status(code))?;
                }
                Ok(false)
            }
            SHUTDOWN => {
                self.inner.response(SHUTDOWN, STATUS_OK)?;
                self.inner.graceful_shutdown.store(true, Ordering::Release);
                Ok(true)
            }
            _ => {
                self.inner.response(command, STATUS_KERNEL_UNAVAILABLE)?;
                Ok(false)
            }
        }
    }
}

pub(crate) struct TestLifecycle<'lifecycle> {
    inner: &'lifecycle mut dyn ServerLifecycle,
    control: TestLifecycleControl,
    activated: bool,
}

impl<'lifecycle> TestLifecycle<'lifecycle> {
    pub(crate) fn new(
        inner: &'lifecycle mut dyn ServerLifecycle,
        control: TestLifecycleControl,
    ) -> Self {
        Self {
            inner,
            control,
            activated: false,
        }
    }

    pub(crate) fn report_startup_failure(&self, code: StableCode) {
        if !self.activated {
            let _ = self
                .control
                .inner
                .response(CONTINUE_STARTUP, control_status(code));
        }
    }
}

impl ServerLifecycle for TestLifecycle<'_> {
    fn workers_started(&mut self) -> Result<(), StableCode> {
        self.inner.workers_started()
    }

    fn activation_completed(&mut self) -> Result<(), StableCode> {
        self.inner.activation_completed()?;
        self.control.inner.response(CONTINUE_STARTUP, STATUS_OK)?;
        self.activated = true;
        Ok(())
    }

    fn poll_shutdown(&mut self) -> Result<bool, StableCode> {
        if self.control.inner.has_async_response_failure() {
            return Err(StableCode::KernelUnavailable);
        }
        let inner_shutdown = self.inner.poll_shutdown()?;
        if inner_shutdown {
            return Ok(true);
        }
        while let Some(command) = self.control.next_command()? {
            if self.control.process_command(command)? {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

fn control_status(code: StableCode) -> u8 {
    match code {
        StableCode::IdentityTranscriptMismatch => STATUS_IDENTITY_TRANSCRIPT_MISMATCH,
        StableCode::AttestationBindingMismatch => STATUS_ATTESTATION_BINDING_MISMATCH,
        StableCode::HandleStalePolicy => STATUS_HANDLE_STALE_POLICY,
        _ => STATUS_KERNEL_UNAVAILABLE,
    }
}

fn sign_value<T: minicbor::Encode<()>>(
    domain: &[u8],
    value: &T,
    key: &SigningKey,
) -> Result<Signature64, StableCode> {
    let payload = minicbor::to_vec(value).map_err(|_| StableCode::KernelUnavailable)?;
    let mut message = Vec::with_capacity(domain.len() + payload.len());
    message.extend_from_slice(domain);
    message.extend_from_slice(&payload);
    Ok(Signature64::new(key.sign(&message).to_bytes()))
}
