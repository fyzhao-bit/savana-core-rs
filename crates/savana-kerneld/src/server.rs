use std::io::{self, Read, Write};
use std::num::NonZeroUsize;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
#[cfg(test)]
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use nix::fcntl::{fcntl, FcntlArg, FdFlag};
use savana_kernel_protocol::{
    decode_client_message, encode_server_message, read_frame, write_frame, ClientMessageV1,
    EffectiveLimits, HealthSnapshotV1, OperationV1, RequestEnvelopeV1, ResponseBodyV1,
    ResponseEnvelopeV1, ResponsePayloadV1, ServerIdentityV1, ServerMessageV1, StableCode,
    UnixMillis,
};
use savana_policy_core::Clock;

use crate::audit::{AuditEvent, AuditSink, OperationTag, RequestCode};
use crate::handshake::{ConnectionContext, HandshakeService};
use crate::peer::peer_identity;
use crate::policy_runtime::{DispatchLease, PolicyRuntime};
use crate::socket::{bind_preflight, BoundListener, SocketPreflight};
#[cfg(test)]
use crate::socket::{bind_socket, SocketConfig};

#[cfg(test)]
struct SpawnFailureOrderObserver {
    sequence: AtomicUsize,
    worker_join_completed: [AtomicUsize; 4],
    cleanup_started: AtomicUsize,
    cleanup_completed: AtomicUsize,
}

#[cfg(test)]
impl SpawnFailureOrderObserver {
    fn new() -> Self {
        Self {
            sequence: AtomicUsize::new(0),
            worker_join_completed: std::array::from_fn(|_| AtomicUsize::new(0)),
            cleanup_started: AtomicUsize::new(0),
            cleanup_completed: AtomicUsize::new(0),
        }
    }

    fn next_sequence(&self) -> usize {
        self.sequence.fetch_add(1, Ordering::AcqRel) + 1
    }

    fn record_worker_join_completed(&self, worker_index: usize) {
        self.worker_join_completed[worker_index].store(self.next_sequence(), Ordering::Release);
    }

    fn record_cleanup_started(&self) {
        self.cleanup_started
            .store(self.next_sequence(), Ordering::Release);
    }

    fn record_cleanup_completed(&self) {
        self.cleanup_completed
            .store(self.next_sequence(), Ordering::Release);
    }

    fn worker_join_completed(&self, worker_index: usize) -> usize {
        self.worker_join_completed[worker_index].load(Ordering::Acquire)
    }

    fn cleanup_started(&self) -> usize {
        self.cleanup_started.load(Ordering::Acquire)
    }

    fn cleanup_completed(&self) -> usize {
        self.cleanup_completed.load(Ordering::Acquire)
    }
}

#[derive(Clone)]
struct ServerLimits {
    workers: NonZeroUsize,
    queued_connections: usize,
    listener_backlog: usize,
    frame_io_deadline: Duration,
    accept_poll_interval: Duration,
    #[cfg(test)]
    fail_worker_spawn_at: Option<usize>,
    #[cfg(test)]
    inject_shutdown_after_loop_entry: bool,
    #[cfg(test)]
    peer_lookup_failures: Option<Arc<AtomicUsize>>,
    #[cfg(test)]
    spawn_failure_order_observer: Option<Arc<SpawnFailureOrderObserver>>,
    #[cfg(test)]
    worker_connection_observer: Option<WorkerConnectionObserver>,
}

impl ServerLimits {
    fn production() -> Self {
        Self {
            workers: NonZeroUsize::new(4).unwrap_or(NonZeroUsize::MIN),
            queued_connections: 64,
            listener_backlog: 64,
            frame_io_deadline: Duration::from_millis(5_000),
            accept_poll_interval: Duration::from_millis(25),
            #[cfg(test)]
            fail_worker_spawn_at: None,
            #[cfg(test)]
            inject_shutdown_after_loop_entry: false,
            #[cfg(test)]
            peer_lookup_failures: None,
            #[cfg(test)]
            spawn_failure_order_observer: None,
            #[cfg(test)]
            worker_connection_observer: None,
        }
    }

    #[cfg(test)]
    fn for_test(workers: usize, queued_connections: usize, frame_io_deadline: Duration) -> Self {
        let production = Self::production();
        assert!(workers <= production.workers.get());
        assert!(queued_connections <= production.queued_connections);
        assert!(frame_io_deadline <= production.frame_io_deadline);
        Self {
            workers: NonZeroUsize::new(workers).expect("test worker count must be nonzero"),
            queued_connections,
            listener_backlog: production.listener_backlog,
            frame_io_deadline,
            accept_poll_interval: Duration::from_millis(5),
            fail_worker_spawn_at: None,
            inject_shutdown_after_loop_entry: false,
            peer_lookup_failures: None,
            spawn_failure_order_observer: None,
            worker_connection_observer: None,
        }
    }

    #[cfg(test)]
    const fn with_worker_spawn_failure(mut self, index: usize) -> Self {
        self.fail_worker_spawn_at = Some(index);
        self
    }

    #[cfg(test)]
    fn with_spawn_failure_order_observer(
        mut self,
        observer: Arc<SpawnFailureOrderObserver>,
    ) -> Self {
        self.spawn_failure_order_observer = Some(observer);
        self
    }

    #[cfg(test)]
    const fn with_shutdown_after_loop_entry(mut self) -> Self {
        self.inject_shutdown_after_loop_entry = true;
        self
    }

    #[cfg(test)]
    fn with_peer_lookup_failures(mut self, count: usize) -> Self {
        self.peer_lookup_failures = Some(Arc::new(AtomicUsize::new(count)));
        self
    }

    #[cfg(test)]
    fn with_worker_connection_observer(mut self, observer: WorkerConnectionObserver) -> Self {
        self.worker_connection_observer = Some(observer);
        self
    }
}

struct ServerControl {
    shutdown: AtomicBool,
    fatal: AtomicBool,
}

#[derive(Clone)]
struct Shutdown {
    control: Arc<ServerControl>,
}

impl Shutdown {
    fn new() -> Self {
        Self {
            control: Arc::new(ServerControl {
                shutdown: AtomicBool::new(false),
                fatal: AtomicBool::new(false),
            }),
        }
    }

    fn is_requested(&self) -> bool {
        self.control.shutdown.load(Ordering::Acquire)
    }

    fn request(&self) {
        self.control.shutdown.store(true, Ordering::Release);
    }

    fn fail(&self) {
        self.control.fatal.store(true, Ordering::Release);
        self.request();
    }

    fn is_fatal(&self) -> bool {
        self.control.fatal.load(Ordering::Acquire)
    }
}

pub(crate) trait ServerLifecycle {
    fn workers_started(&mut self) -> Result<(), StableCode>;

    fn activation_completed(&mut self) -> Result<(), StableCode> {
        Ok(())
    }

    fn poll_shutdown(&mut self) -> Result<bool, StableCode>;
}

struct NoopLifecycle;

impl ServerLifecycle for NoopLifecycle {
    fn workers_started(&mut self) -> Result<(), StableCode> {
        Ok(())
    }

    fn poll_shutdown(&mut self) -> Result<bool, StableCode> {
        Ok(false)
    }
}

fn activate_lifecycle(lifecycle: &mut dyn ServerLifecycle, shutdown: &Shutdown) {
    if lifecycle.workers_started().is_err() {
        shutdown.fail();
    }
}

fn poll_lifecycle(lifecycle: &mut dyn ServerLifecycle, shutdown: &Shutdown) {
    match lifecycle.poll_shutdown() {
        Ok(true) => shutdown.request(),
        Ok(false) => {}
        Err(_) => shutdown.fail(),
    }
}

pub(crate) struct KernelServer {
    bound: BoundListener,
    service: Arc<HandshakeService>,
    runtime: Arc<PolicyRuntime>,
    limits: ServerLimits,
    clock: Arc<dyn Clock + Send + Sync>,
    shutdown: Shutdown,
    audit: Option<Arc<AuditSink>>,
}

impl KernelServer {
    pub(crate) fn new_preflight(
        service: HandshakeService,
        socket: SocketPreflight,
        audit: Arc<AuditSink>,
        clock: Arc<dyn Clock + Send + Sync>,
    ) -> Result<Self, StableCode> {
        let bound = bind_preflight(socket)?;
        let service = Arc::new(service);
        let runtime = Arc::clone(service.runtime());
        Ok(Self {
            bound,
            service,
            runtime,
            limits: ServerLimits::production(),
            clock,
            shutdown: Shutdown::new(),
            audit: Some(audit),
        })
    }

    #[cfg(test)]
    fn new_for_test(
        socket_config: SocketConfig,
        service: HandshakeService,
        effective_limits: EffectiveLimits,
        limits: ServerLimits,
        clock: Arc<dyn Clock + Send + Sync>,
    ) -> Result<(Self, Shutdown), StableCode> {
        let bound = bind_socket(&socket_config)?;
        let shutdown = Shutdown::new();
        let service = Arc::new(service);
        let runtime = Arc::clone(service.runtime());
        let old_snapshot = runtime.snapshot()?;
        runtime.force_replace_snapshot_for_test(
            old_snapshot.with_limit_for_test(effective_limits, old_snapshot.generation()),
        )?;
        Ok((
            Self {
                bound,
                service,
                runtime,
                limits,
                clock,
                shutdown: shutdown.clone(),
                audit: None,
            },
            shutdown,
        ))
    }

    pub(crate) fn close(self) -> Result<(), StableCode> {
        self.bound.close()
    }

    #[cfg(all(feature = "test-support", debug_assertions))]
    pub(crate) fn test_lifecycle_handshake_service(&self) -> Arc<HandshakeService> {
        Arc::clone(&self.service)
    }

    pub(crate) fn run(self) -> Result<(), StableCode> {
        self.run_with_lifecycle(&mut NoopLifecycle)
    }

    pub(crate) fn run_with_lifecycle(
        mut self,
        lifecycle: &mut dyn ServerLifecycle,
    ) -> Result<(), StableCode> {
        if self.limits.listener_backlog != 64 {
            return Err(StableCode::KernelUnavailable);
        }
        let (sender, receiver) = sync_channel(self.limits.queued_connections);
        let receiver = Arc::new(Mutex::new(receiver));
        let mut workers = Vec::with_capacity(self.limits.workers.get());
        for _index in 0..self.limits.workers.get() {
            #[cfg(test)]
            let worker = if self.limits.fail_worker_spawn_at == Some(_index) {
                Err(StableCode::KernelUnavailable)
            } else {
                spawn_worker(
                    Arc::clone(&receiver),
                    Arc::clone(&self.service),
                    Arc::clone(&self.runtime),
                    self.limits.clone(),
                    Arc::clone(&self.clock),
                    self.shutdown.clone(),
                    self.audit.clone(),
                )
            };
            #[cfg(not(test))]
            let worker = spawn_worker(
                Arc::clone(&receiver),
                Arc::clone(&self.service),
                Arc::clone(&self.runtime),
                self.limits.clone(),
                Arc::clone(&self.clock),
                self.shutdown.clone(),
                self.audit.clone(),
            );
            match worker {
                Ok(worker) => workers.push(worker),
                Err(_) => {
                    #[cfg(test)]
                    let ordering = self.limits.spawn_failure_order_observer.clone();
                    self.shutdown.fail();
                    if self.bound.stop_accepting().is_err() {
                        self.shutdown.fail();
                    }
                    drop(sender);
                    drop(receiver);
                    #[cfg(test)]
                    for (worker_index, worker) in workers.into_iter().enumerate() {
                        let join_result = worker.join();
                        if join_result.is_ok() {
                            if let Some(ordering) = ordering.as_deref() {
                                ordering.record_worker_join_completed(worker_index);
                            }
                        }
                        if join_result.is_err() {
                            self.shutdown.fail();
                        }
                    }
                    #[cfg(not(test))]
                    for worker in workers {
                        if worker.join().is_err() {
                            self.shutdown.fail();
                        }
                    }
                    #[cfg(test)]
                    if let Some(ordering) = ordering.as_deref() {
                        ordering.record_cleanup_started();
                    }
                    let cleanup_result = self.bound.close();
                    #[cfg(test)]
                    if let Some(ordering) = ordering.as_deref() {
                        ordering.record_cleanup_completed();
                    }
                    if cleanup_result.is_err() {
                        self.shutdown.fail();
                    }
                    return Err(StableCode::KernelUnavailable);
                }
            }
        }

        activate_lifecycle(lifecycle, &self.shutdown);
        while !self.shutdown.is_requested() {
            poll_lifecycle(lifecycle, &self.shutdown);
            if self.shutdown.is_requested() {
                break;
            }
            #[cfg(test)]
            if self.limits.inject_shutdown_after_loop_entry {
                self.shutdown.request();
                while !workers.iter().any(JoinHandle::is_finished) {
                    thread::yield_now();
                }
            }
            if workers.iter().any(JoinHandle::is_finished) {
                if !self.shutdown.is_requested() {
                    self.shutdown.fail();
                }
                break;
            }
            let listener = match self.bound.listener() {
                Ok(listener) => listener,
                Err(_) => {
                    self.shutdown.fail();
                    break;
                }
            };
            match listener.accept() {
                Ok((stream, _address)) => {
                    let admission = match self.runtime.admission_lease() {
                        Ok(admission) => admission,
                        Err(_) => {
                            self.shutdown.fail();
                            break;
                        }
                    };
                    let admitted = admit(&sender, stream);
                    drop(admission);
                    match admitted {
                        Ok(()) | Err(StableCode::KernelOverloaded) => {}
                        Err(_) => {
                            self.shutdown.fail();
                            break;
                        }
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::park_timeout(self.limits.accept_poll_interval);
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => {
                    self.shutdown.fail();
                    break;
                }
            }
        }

        self.shutdown.request();
        if self.bound.stop_accepting().is_err() {
            self.shutdown.fail();
        }
        drop(sender);
        drop(receiver);
        for worker in workers {
            if worker.join().is_err() {
                self.shutdown.fail();
            }
        }
        if self.bound.close().is_err() {
            self.shutdown.fail();
        }
        if self.shutdown.is_fatal() {
            Err(StableCode::KernelUnavailable)
        } else {
            Ok(())
        }
    }
}

fn spawn_worker(
    receiver: Arc<Mutex<Receiver<UnixStream>>>,
    service: Arc<HandshakeService>,
    runtime: Arc<PolicyRuntime>,
    limits: ServerLimits,
    clock: Arc<dyn Clock + Send + Sync>,
    shutdown: Shutdown,
    audit: Option<Arc<AuditSink>>,
) -> Result<JoinHandle<()>, StableCode> {
    thread::Builder::new()
        .name("savana-kerneld-worker".to_owned())
        .spawn(move || {
            worker_loop(
                &receiver,
                &service,
                runtime.as_ref(),
                limits,
                clock.as_ref(),
                &shutdown,
                audit.as_deref(),
            );
        })
        .map_err(|_| StableCode::KernelUnavailable)
}

fn worker_loop(
    receiver: &Mutex<Receiver<UnixStream>>,
    service: &HandshakeService,
    runtime: &PolicyRuntime,
    limits: ServerLimits,
    clock: &dyn Clock,
    shutdown: &Shutdown,
    audit: Option<&AuditSink>,
) {
    loop {
        if shutdown.is_requested() {
            return;
        }
        let received = match receiver.lock() {
            Ok(receiver) => receiver.recv_timeout(limits.accept_poll_interval),
            Err(_) => {
                shutdown.fail();
                return;
            }
        };
        let stream = match received {
            Ok(stream) => stream,
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => {
                if !shutdown.is_requested() {
                    shutdown.fail();
                }
                return;
            }
        };
        if shutdown.is_requested() {
            drop(stream);
            return;
        }
        let stream = stream;
        if configure_stream(&stream, limits.frame_io_deadline).is_err() {
            continue;
        }
        let outcome = handle_connection(
            stream,
            service,
            ConnectionRuntime {
                frame_io_deadline: limits.frame_io_deadline,
                clock,
                shutdown,
                audit,
                runtime,
                #[cfg(test)]
                peer_lookup_failures: limits.peer_lookup_failures.as_deref(),
            },
        );
        #[cfg(test)]
        if let Some(observer) = limits.worker_connection_observer.as_ref() {
            let _ = observer.outcomes.send(WorkerConnectionOutcome {
                worker: thread::current().id(),
                result: outcome,
            });
        }
        match outcome {
            Ok(()) | Err(ConnectionFailure::Local(_)) => {}
            Err(ConnectionFailure::Fatal(_)) => shutdown.fail(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectionFailure {
    Local(StableCode),
    Fatal(StableCode),
}

#[cfg(test)]
#[derive(Clone)]
struct WorkerConnectionObserver {
    outcomes: std::sync::mpsc::Sender<WorkerConnectionOutcome>,
}

#[cfg(test)]
#[derive(Debug)]
struct WorkerConnectionOutcome {
    worker: thread::ThreadId,
    result: Result<(), ConnectionFailure>,
}

struct ConnectionRuntime<'runtime> {
    frame_io_deadline: Duration,
    clock: &'runtime dyn Clock,
    shutdown: &'runtime Shutdown,
    audit: Option<&'runtime AuditSink>,
    runtime: &'runtime PolicyRuntime,
    #[cfg(test)]
    peer_lookup_failures: Option<&'runtime AtomicUsize>,
}

struct LeasedConnection<'runtime> {
    stream: Option<UnixStream>,
    dispatch: DispatchLease<'runtime>,
    #[cfg(test)]
    stream_closed_probe: Option<LeasedConnectionDropProbe>,
}

#[cfg(test)]
struct LeasedConnectionDropProbe {
    stream_closed: SyncSender<()>,
    resume_drop: Receiver<()>,
}

impl Drop for LeasedConnection<'_> {
    fn drop(&mut self) {
        drop(self.stream.take());
        #[cfg(test)]
        if let Some(probe) = self.stream_closed_probe.take() {
            probe.stream_closed.send(()).unwrap();
            probe.resume_drop.recv().unwrap();
        }
    }
}

fn handle_connection(
    stream: UnixStream,
    service: &HandshakeService,
    runtime: ConnectionRuntime<'_>,
) -> Result<(), ConnectionFailure> {
    let ConnectionRuntime {
        frame_io_deadline,
        clock,
        shutdown,
        audit,
        runtime: policy_runtime,
        #[cfg(test)]
        peer_lookup_failures,
    } = runtime;
    let dispatch = policy_runtime
        .dispatch_lease()
        .map_err(|code| handshake_rejection(audit, code))?;
    let snapshot = Arc::clone(dispatch.snapshot());
    let effective_limits = snapshot.effective_limits();
    let mut leased = LeasedConnection {
        stream: Some(stream),
        dispatch,
        #[cfg(test)]
        stream_closed_probe: None,
    };
    let stream = leased
        .stream
        .as_mut()
        .ok_or(ConnectionFailure::Fatal(StableCode::KernelUnavailable))?;
    #[cfg(test)]
    if let Some(failures) = peer_lookup_failures {
        if failures
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
        {
            return Err(handshake_rejection(audit, StableCode::KernelUnavailable));
        }
    }
    let peer = peer_identity(stream).map_err(|code| handshake_rejection(audit, code))?;
    service
        .preauthorize_peer(&peer)
        .map_err(|code| handshake_service_failure(audit, code))?;

    let hello = match read_client_message(stream, &effective_limits, frame_io_deadline, shutdown)
        .map_err(|failure| audit_handshake_failure(audit, failure))?
    {
        ClientMessageV1::Hello(hello) => hello,
        ClientMessageV1::Finish(_) | ClientMessageV1::Request(_) => {
            return Err(handshake_rejection(
                audit,
                StableCode::IdentityTranscriptMismatch,
            ));
        }
    };
    let now = clock
        .wall_now()
        .map_err(|_| ConnectionFailure::Fatal(StableCode::KernelUnavailable))?;
    let (pending, signed_hello) = service
        .start(&peer, hello, now)
        .map_err(|code| handshake_service_failure(audit, code))?;
    write_server_message(
        stream,
        &ServerMessageV1::Hello(signed_hello),
        &effective_limits,
        frame_io_deadline,
        shutdown,
    )
    .map_err(|failure| audit_handshake_failure(audit, failure))?;

    let finish = match read_client_message(stream, &effective_limits, frame_io_deadline, shutdown)
        .map_err(|failure| audit_handshake_failure(audit, failure))?
    {
        ClientMessageV1::Finish(finish) => finish,
        ClientMessageV1::Hello(_) | ClientMessageV1::Request(_) => {
            return Err(handshake_rejection(
                audit,
                StableCode::IdentityTranscriptMismatch,
            ));
        }
    };
    let now = clock
        .wall_now()
        .map_err(|_| ConnectionFailure::Fatal(StableCode::KernelUnavailable))?;
    let context = service
        .finish(&peer, pending, finish, now)
        .map_err(|code| handshake_service_failure(audit, code))?;
    let connection_audit_id = audit
        .map(|sink| sink.connection_audit_id_for_context(&context))
        .transpose()
        .map_err(ConnectionFailure::Fatal)?;
    write_server_message(
        stream,
        &ServerMessageV1::Accepted(context.accepted()),
        &effective_limits,
        frame_io_deadline,
        shutdown,
    )
    .map_err(|failure| audit_handshake_failure(audit, failure))?;

    let request = match read_client_message(stream, &effective_limits, frame_io_deadline, shutdown)?
    {
        ClientMessageV1::Request(request) => request,
        ClientMessageV1::Hello(_) | ClientMessageV1::Finish(_) => {
            return Err(ConnectionFailure::Local(
                StableCode::IdentityTranscriptMismatch,
            ));
        }
    };
    let request_started = Instant::now();
    let operation_tag = match &request.operation {
        OperationV1::Health => OperationTag::Health,
        OperationV1::BeginRun(_) => OperationTag::BeginRun,
        OperationV1::IngestUserInput(_) => OperationTag::IngestUserInput,
        OperationV1::PreparePlannerCall(_) => OperationTag::PreparePlannerCall,
        OperationV1::CommitPlannerValue(_) => OperationTag::CommitPlannerValue,
        OperationV1::DeriveValue(_) => OperationTag::DeriveValue,
        OperationV1::ProposeToolCall(_) => OperationTag::ProposeToolCall,
        OperationV1::EvaluateToolCall(_) => OperationTag::EvaluateToolCall,
        OperationV1::AuthorizeToolCall(_) => OperationTag::AuthorizeToolCall,
        OperationV1::MaterializeExecution(_) => OperationTag::MaterializeExecution,
        OperationV1::CommitToolResult(_) => OperationTag::CommitToolResult,
    };
    let requested_run_audit_id = match &request.operation {
        OperationV1::IngestUserInput(request) => audit
            .map(|sink| sink.run_audit_id_for_context(&context, request.run))
            .transpose()
            .map_err(ConnectionFailure::Fatal)?,
        _ => None,
    };
    let now = match clock.wall_now() {
        Ok(now) => now,
        Err(code) => {
            record_request_completion(
                audit,
                operation_tag,
                RequestCode::Error(code),
                request_started,
                connection_audit_id,
                requested_run_audit_id,
            )?;
            return Err(ConnectionFailure::Fatal(code));
        }
    };
    let response = match service.validate_context_identity_in_snapshot(&context, now, &snapshot) {
        Ok(identity) => response_for_request(
            policy_runtime,
            &context,
            identity,
            request,
            now,
            &effective_limits,
        ),
        Err(code @ StableCode::PolicyExpired) => ResponseEnvelopeV1 {
            version: context.protocol(),
            request_id: request.request_id,
            body: ResponseBodyV1::Err(code),
        },
        Err(code) => {
            record_request_completion(
                audit,
                operation_tag,
                RequestCode::Error(code),
                request_started,
                connection_audit_id,
                requested_run_audit_id,
            )?;
            return Err(classify_service_failure(code));
        }
    };
    let response_code = match &response.body {
        ResponseBodyV1::Ok(_) => RequestCode::Ok,
        ResponseBodyV1::Err(code) => RequestCode::Error(*code),
    };
    let completed_run_audit_id = match &response.body {
        ResponseBodyV1::Ok(ResponsePayloadV1::BeginRun(begin)) => audit
            .map(|sink| sink.run_audit_id_for_context(&context, begin.run))
            .transpose()
            .map_err(ConnectionFailure::Fatal)?,
        _ => requested_run_audit_id,
    };
    let write_result = write_server_message(
        stream,
        &ServerMessageV1::Response(response),
        &effective_limits,
        frame_io_deadline,
        shutdown,
    );
    let completion_code = match write_result {
        Ok(()) => response_code,
        Err(ConnectionFailure::Local(code) | ConnectionFailure::Fatal(code)) => {
            RequestCode::Error(code)
        }
    };
    record_request_completion(
        audit,
        operation_tag,
        completion_code,
        request_started,
        connection_audit_id,
        completed_run_audit_id,
    )?;
    write_result
}

fn handshake_service_failure(audit: Option<&AuditSink>, code: StableCode) -> ConnectionFailure {
    audit_handshake_failure(audit, classify_service_failure(code))
}

fn audit_handshake_failure(
    audit: Option<&AuditSink>,
    failure: ConnectionFailure,
) -> ConnectionFailure {
    match failure {
        ConnectionFailure::Local(code) => handshake_rejection(audit, code),
        ConnectionFailure::Fatal(code) => ConnectionFailure::Fatal(code),
    }
}

fn handshake_rejection(audit: Option<&AuditSink>, code: StableCode) -> ConnectionFailure {
    if audit.is_some_and(|sink| sink.emit(AuditEvent::HandshakeRejected { code }).is_err()) {
        ConnectionFailure::Fatal(StableCode::KernelUnavailable)
    } else {
        ConnectionFailure::Local(code)
    }
}

fn record_request_completion(
    audit: Option<&AuditSink>,
    operation_tag: OperationTag,
    code: RequestCode,
    started: Instant,
    connection_audit_id: Option<crate::audit::AuditId>,
    run_audit_id: Option<crate::audit::AuditId>,
) -> Result<(), ConnectionFailure> {
    let latency_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    if let Some(sink) = audit {
        let connection_audit_id =
            connection_audit_id.ok_or(ConnectionFailure::Fatal(StableCode::KernelUnavailable))?;
        sink.emit(AuditEvent::RequestCompleted {
            operation_tag,
            code,
            latency_ms,
            connection_audit_id,
            run_audit_id,
        })
        .map_err(ConnectionFailure::Fatal)?;
    }
    Ok(())
}

fn response_for_request(
    runtime: &PolicyRuntime,
    context: &ConnectionContext,
    identity: ServerIdentityV1,
    request: RequestEnvelopeV1,
    now: UnixMillis,
    effective_limits: &EffectiveLimits,
) -> ResponseEnvelopeV1 {
    let error = if request.version != context.protocol() {
        Some(StableCode::ProtocolUnsupportedVersion)
    } else if request.deadline_unix_ms.get() <= now.get()
        || request
            .deadline_unix_ms
            .get()
            .checked_sub(now.get())
            .is_none_or(|remaining| remaining > effective_limits.request_deadline_ms())
        || request.deadline_unix_ms.get() > context.expires_at().get()
    {
        Some(StableCode::DeadlineExceeded)
    } else {
        None
    };

    let body = match error {
        Some(code) => ResponseBodyV1::Err(code),
        None => match request.operation {
            OperationV1::Health => {
                ResponseBodyV1::Ok(ResponsePayloadV1::Health(HealthSnapshotV1 {
                    ready: true,
                    identity,
                    last_error: None,
                }))
            }
            operation => match bind_authenticated(runtime, context, request.deadline_unix_ms) {
                Ok(authenticated) => {
                    crate::ops::policy::dispatch(runtime.engine(), &authenticated, operation)
                }
                Err(code) => ResponseBodyV1::Err(code),
            },
        },
    };
    #[cfg(test)]
    if matches!(&body, ResponseBodyV1::Ok(ResponsePayloadV1::BeginRun(_))) {
        // The actual operation dispatcher has accepted a BeginRun; this is
        // deliberately recorded after dispatch rather than synthesized by a
        // lock-order test.
        runtime.record_engine_write_for_test();
    }
    ResponseEnvelopeV1 {
        version: context.protocol(),
        request_id: request.request_id,
        body,
    }
}

fn bind_authenticated(
    runtime: &PolicyRuntime,
    context: &ConnectionContext,
    request_deadline: UnixMillis,
) -> Result<savana_policy_core::AuthenticatedCallContext, StableCode> {
    #[cfg(test)]
    if runtime.is_synthetic_for_handshake_test() {
        return Err(StableCode::KernelUnavailable);
    }
    runtime
        .issuer()
        .bind(
            context.client_id().clone(),
            context.connection_id(),
            context.connection_binding_digest(),
            context.policy_identity(),
            context.boot_id(),
            context.peer().uid(),
            request_deadline,
        )
        .map_err(|error| error.code())
}

fn read_client_message(
    stream: &mut UnixStream,
    effective_limits: &EffectiveLimits,
    frame_io_deadline: Duration,
    shutdown: &Shutdown,
) -> Result<ClientMessageV1, ConnectionFailure> {
    if shutdown.is_requested() {
        return Err(ConnectionFailure::Local(StableCode::KernelUnavailable));
    }
    let payload = read_frame_with_deadline(stream, effective_limits, frame_io_deadline, shutdown)
        .map_err(ConnectionFailure::Local)?;
    decode_client_message(&payload, effective_limits)
        .map_err(|error| ConnectionFailure::Local(error.code()))
}

fn write_server_message(
    stream: &mut UnixStream,
    message: &ServerMessageV1,
    effective_limits: &EffectiveLimits,
    frame_io_deadline: Duration,
    shutdown: &Shutdown,
) -> Result<(), ConnectionFailure> {
    if shutdown.is_requested() {
        return Err(ConnectionFailure::Local(StableCode::KernelUnavailable));
    }
    let payload = encode_server_message(message)
        .map_err(|_| ConnectionFailure::Fatal(StableCode::KernelUnavailable))?;
    write_frame_with_deadline(
        stream,
        &payload,
        effective_limits,
        frame_io_deadline,
        shutdown,
    )
    .map_err(|code| match code {
        StableCode::DeadlineExceeded | StableCode::ProtocolIo => ConnectionFailure::Local(code),
        _ => ConnectionFailure::Fatal(StableCode::KernelUnavailable),
    })
}

fn classify_service_failure(code: StableCode) -> ConnectionFailure {
    if code == StableCode::KernelUnavailable {
        ConnectionFailure::Fatal(code)
    } else {
        ConnectionFailure::Local(code)
    }
}

fn configure_stream(stream: &UnixStream, frame_io_deadline: Duration) -> Result<(), StableCode> {
    let raw = stream.as_raw_fd();
    let mut flags = FdFlag::from_bits_truncate(
        fcntl(raw, FcntlArg::F_GETFD).map_err(|_| StableCode::KernelUnavailable)?,
    );
    if !flags.contains(FdFlag::FD_CLOEXEC) {
        flags.insert(FdFlag::FD_CLOEXEC);
        fcntl(raw, FcntlArg::F_SETFD(flags)).map_err(|_| StableCode::KernelUnavailable)?;
    }
    let verified = FdFlag::from_bits_truncate(
        fcntl(raw, FcntlArg::F_GETFD).map_err(|_| StableCode::KernelUnavailable)?,
    );
    if !verified.contains(FdFlag::FD_CLOEXEC) {
        return Err(StableCode::KernelUnavailable);
    }
    stream
        .set_nonblocking(false)
        .and_then(|_| stream.set_read_timeout(Some(frame_io_deadline)))
        .and_then(|_| stream.set_write_timeout(Some(frame_io_deadline)))
        .map_err(|_| StableCode::KernelUnavailable)
}

fn admit(sender: &SyncSender<UnixStream>, stream: UnixStream) -> Result<(), StableCode> {
    sender.try_send(stream).map_err(|error| match error {
        TrySendError::Full(_) => StableCode::KernelOverloaded,
        TrySendError::Disconnected(_) => StableCode::KernelUnavailable,
    })
}

struct DeadlineReader<'stream> {
    stream: &'stream mut UnixStream,
    deadline: Instant,
    shutdown: &'stream Shutdown,
}

impl Read for DeadlineReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.shutdown.is_requested() {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "shutdown"));
        }
        let remaining = self
            .deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "frame read deadline"))?;
        self.stream.set_read_timeout(Some(remaining))?;
        self.stream.read(buffer)
    }
}

struct DeadlineWriter<'stream> {
    stream: &'stream mut UnixStream,
    deadline: Instant,
    shutdown: &'stream Shutdown,
}

impl Write for DeadlineWriter<'_> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if self.shutdown.is_requested() {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "shutdown"));
        }
        let remaining = self
            .deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "frame write deadline"))?;
        self.stream.set_write_timeout(Some(remaining))?;
        self.stream.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

fn read_frame_with_deadline(
    stream: &mut UnixStream,
    limits: &EffectiveLimits,
    timeout: Duration,
    shutdown: &Shutdown,
) -> Result<Vec<u8>, StableCode> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or(StableCode::KernelUnavailable)?;
    read_frame(
        &mut DeadlineReader {
            stream,
            deadline,
            shutdown,
        },
        limits,
    )
    .map_err(|error| error.code())
}

fn write_frame_with_deadline(
    stream: &mut UnixStream,
    payload: &[u8],
    limits: &EffectiveLimits,
    timeout: Duration,
    shutdown: &Shutdown,
) -> Result<(), StableCode> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or(StableCode::KernelUnavailable)?;
    write_frame(
        &mut DeadlineWriter {
            stream,
            deadline,
            shutdown,
        },
        payload,
        limits,
    )
    .map_err(|error| error.code())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::{Read, Write};
    use std::net::Shutdown as NetworkShutdown;
    use std::os::fd::OwnedFd;
    use std::os::unix::fs::{chown, PermissionsExt};
    use std::os::unix::net::UnixStream;
    use std::sync::atomic::AtomicU64;
    use std::sync::mpsc::{channel, sync_channel};
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, Instant};

    use ed25519_dalek::{Signer, SigningKey};
    use nix::unistd::{getegid, geteuid};
    use savana_kernel_protocol::{
        decode_client_message, decode_server_message, encode_client_message,
        ingress_request_digest, AttemptKindV1, BeginRunRequest, BootId, BoundedText,
        ClientFinishV1, ClientHelloV1, ClientMessageV1, ConstraintId, Digest32,
        HandshakeAcceptedV1, HardLimits, IngressEnvelopeV1, IngressRequestCommitmentV1,
        KernelValue, KeyId, Nonce32, OperationV1, PrincipalId, ProtocolVersion, RegistrySnapshotV1,
        RequestEnvelopeV1, RequestId, RequestedMode, ResourceLimitsV1, ResponseBodyV1,
        ResponseEnvelopeV1, ResponsePayloadV1, RoleId, ServerMessageV1, Signature64,
        SignedIngressEnvelopeV1, SignedRegistrySnapshotV1, SignedServerHelloV1, StableCode,
        ToolDescriptorV1, ToolExecutionIdentity, ToolName, UnixMillis,
    };
    use savana_policy_core::PolicyIdentity;
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::audit::AuditSink;
    use crate::handshake::HandshakeService;
    use crate::peer::PeerIdentity;
    use crate::policy_runtime::LockEvent;
    use crate::runtime_deps::AuditSecret;
    use crate::socket::{SocketConfig, PROCESS_TEST_LOCK};

    #[test]
    fn production_admission_and_timing_limits_are_frozen() {
        let limits = ServerLimits::production();
        assert_eq!(limits.workers.get(), 4);
        assert_eq!(limits.queued_connections, 64);
        assert_eq!(limits.listener_backlog, 64);
        assert_eq!(limits.frame_io_deadline, Duration::from_millis(5_000));
        assert_eq!(limits.accept_poll_interval, Duration::from_millis(25));
    }

    #[test]
    fn workers_never_keep_startup_copied_policy_limits() {
        let client_key = SigningKey::from_bytes(&[0x6a; 32]);
        let service = Arc::new(
            HandshakeService::new_for_transport_test(
                client_key.verifying_key().to_bytes(),
                PeerIdentity::new_for_test(geteuid().as_raw(), getegid().as_raw()),
                UnixMillis::new(1_000),
                UnixMillis::new(20_000),
            )
            .unwrap(),
        );
        service.force_effective_limits_for_transport_test(effective_limits(4_096, 2_000));
        let runtime = Arc::clone(service.runtime());
        let (sender, receiver) = sync_channel(1);
        let (outcome_tx, outcome_rx) = channel();
        let shutdown = Shutdown::new();
        let worker = spawn_worker(
            Arc::new(Mutex::new(receiver)),
            Arc::clone(&service),
            Arc::clone(&runtime),
            ServerLimits::for_test(1, 1, Duration::from_secs(1)).with_worker_connection_observer(
                WorkerConnectionObserver {
                    outcomes: outcome_tx,
                },
            ),
            Arc::new(TestClock::new(2_000)),
            shutdown.clone(),
            None,
        )
        .unwrap();

        let (mut old_client, old_server) = UnixStream::pair().unwrap();
        sender.try_send(old_server).unwrap();
        old_client.write_all(&1_025_u32.to_be_bytes()).unwrap();
        old_client.shutdown(NetworkShutdown::Write).unwrap();
        let old_outcome = outcome_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(
            old_outcome.result,
            Err(ConnectionFailure::Local(StableCode::ProtocolTruncatedFrame))
        );

        let closed = runtime.close_and_drain().unwrap();
        let old_snapshot = runtime.snapshot().unwrap();
        assert_eq!(old_snapshot.generation(), 1);
        assert_eq!(old_snapshot.effective_limits().frame_bytes(), 4_096);
        let new_generation = old_snapshot.generation().checked_add(1).unwrap();
        runtime
            .force_replace_snapshot_for_test(
                old_snapshot.with_limit_for_test(effective_limits(1_024, 2_000), new_generation),
            )
            .unwrap();
        let published = runtime.snapshot().unwrap();
        assert_eq!(published.generation(), 2);
        assert_eq!(published.effective_limits().frame_bytes(), 1_024);
        closed.reopen();

        let (mut new_client, new_server) = UnixStream::pair().unwrap();
        sender.try_send(new_server).unwrap();
        new_client.write_all(&1_025_u32.to_be_bytes()).unwrap();
        new_client.shutdown(NetworkShutdown::Write).unwrap();
        let new_outcome = outcome_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(new_outcome.worker, old_outcome.worker);
        assert_eq!(
            new_outcome.result,
            Err(ConnectionFailure::Local(StableCode::ProtocolFrameTooLarge))
        );

        shutdown.request();
        drop(old_client);
        drop(new_client);
        drop(sender);
        worker.join().unwrap();
        assert!(!shutdown.is_fatal());
    }

    #[test]
    fn normal_request_lock_order_is_exact() {
        let (runtime, clock) =
            crate::policy_runtime::PolicyRuntime::new_for_server_lock_trace_test(1_001, 1_003);
        let service = HandshakeService::new(
            Arc::clone(&runtime),
            crate::DaemonSigningIdentity::from_seed_for_test([0x61; 32]),
            UnixMillis::new(2_000),
            BootId::new([0xa1; 32]),
            crate::startup_identity_tests::policy_support::random(
                crate::startup_identity_tests::policy_support::RandomBehavior::Filled(0x5a),
            ),
        )
        .expect("real handshake service");
        let peer = PeerIdentity::new_for_test(1_001, 1_003);

        // This is the real normal request ordering: hold the dispatch
        // generation before handshake state, then pass the authenticated
        // BeginRun through the normal policy operation dispatcher.
        let dispatch = runtime.dispatch_lease().unwrap();
        let snapshot = Arc::clone(dispatch.snapshot());
        let client_key = SigningKey::from_bytes(&[0x62; 32]);
        let hello = ClientHelloV1 {
            client_nonce: Nonce32::new([0x91; 32]),
            supported_versions: vec![ProtocolVersion::new(1, 0)],
            client_id: "jarvis-client".try_into().unwrap(),
            client_key_id: "jarvis-key".try_into().unwrap(),
            requested_mode: RequestedMode::Required,
        };
        let now = UnixMillis::new(clock.now());
        let (pending, signed) = service.start(&peer, hello, now).unwrap();
        let transcript = minicbor::to_vec(&signed.transcript).unwrap();
        let digest = Digest32::new(Sha256::digest(transcript).into());
        let mut finish_message = b"SAVANA_CLIENT_FINISH_V1\0".to_vec();
        finish_message.extend_from_slice(digest.as_bytes());
        let context = service
            .finish(
                &peer,
                pending,
                ClientFinishV1 {
                    transcript_digest: digest,
                    signature: Signature64::new(client_key.sign(&finish_message).to_bytes()),
                },
                now,
            )
            .unwrap();
        let identity = service
            .validate_context_identity_in_snapshot(&context, now, snapshot.as_ref())
            .unwrap();
        let request = RequestEnvelopeV1 {
            version: ProtocolVersion::new(1, 0),
            request_id: RequestId::new([0x91; 16]),
            deadline_unix_ms: UnixMillis::new(2_500),
            operation: OperationV1::BeginRun(real_begin_request(
                &context,
                snapshot.policy_identity(),
            )),
        };
        let response = response_for_request(
            runtime.as_ref(),
            &context,
            identity,
            request,
            now,
            &snapshot.effective_limits(),
        );
        assert!(
            matches!(
                response.body,
                ResponseBodyV1::Ok(ResponsePayloadV1::BeginRun(_))
            ),
            "unexpected normal BeginRun response: {response:?}"
        );
        drop(dispatch);
        assert_eq!(
            runtime.normal_lock_trace_for_test(),
            vec![
                LockEvent::DispatchLease,
                LockEvent::HandshakeRuntimeRead,
                LockEvent::HandshakeReplay,
                LockEvent::EngineWrite,
            ]
        );
    }

    #[test]
    fn lifecycle_starts_after_workers_and_requests_shutdown_only_from_a_poll() {
        struct RecordingLifecycle {
            started: bool,
            polls: usize,
        }

        impl ServerLifecycle for RecordingLifecycle {
            fn workers_started(&mut self) -> Result<(), StableCode> {
                self.started = true;
                Ok(())
            }

            fn poll_shutdown(&mut self) -> Result<bool, StableCode> {
                assert!(self.started);
                self.polls += 1;
                Ok(self.polls == 2)
            }
        }

        let shutdown = Shutdown::new();
        let mut lifecycle = RecordingLifecycle {
            started: false,
            polls: 0,
        };

        activate_lifecycle(&mut lifecycle, &shutdown);
        assert!(lifecycle.started);
        assert!(!shutdown.is_requested());
        poll_lifecycle(&mut lifecycle, &shutdown);
        assert!(!shutdown.is_requested());
        poll_lifecycle(&mut lifecycle, &shutdown);
        assert!(shutdown.is_requested());
        assert!(!shutdown.is_fatal());
    }

    #[test]
    fn lifecycle_failure_is_a_global_fatal() {
        struct FailingLifecycle;

        impl ServerLifecycle for FailingLifecycle {
            fn workers_started(&mut self) -> Result<(), StableCode> {
                Err(StableCode::KernelUnavailable)
            }

            fn poll_shutdown(&mut self) -> Result<bool, StableCode> {
                Ok(false)
            }
        }

        let shutdown = Shutdown::new();
        activate_lifecycle(&mut FailingLifecycle, &shutdown);

        assert!(shutdown.is_requested());
        assert!(shutdown.is_fatal());
    }

    #[test]
    fn admission_distinguishes_full_from_disconnected_without_spawning() {
        let (full_tx, full_rx) = sync_channel(1);
        let (first, _peer) = UnixStream::pair().unwrap();
        full_tx.try_send(first).unwrap();
        let (second, _peer) = UnixStream::pair().unwrap();
        assert_eq!(
            admit(&full_tx, second).unwrap_err(),
            StableCode::KernelOverloaded
        );
        drop(full_rx);

        let (closed_tx, closed_rx) = sync_channel(1);
        drop(closed_rx);
        let (stream, _peer) = UnixStream::pair().unwrap();
        assert_eq!(
            admit(&closed_tx, stream).unwrap_err(),
            StableCode::KernelUnavailable
        );
    }

    #[test]
    fn leased_connection_closes_its_stream_before_releasing_the_dispatch_lease() {
        let client_key = SigningKey::from_bytes(&[0x62; 32]);
        let service = HandshakeService::new_for_transport_test(
            client_key.verifying_key().to_bytes(),
            PeerIdentity::new_for_test(geteuid().as_raw(), getegid().as_raw()),
            UnixMillis::new(1_000),
            UnixMillis::new(5_000),
        )
        .unwrap();
        let runtime = Arc::clone(service.runtime());
        let dispatch = runtime.dispatch_lease().unwrap();
        let (mut client, server) = UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let (stream_closed_tx, stream_closed_rx) = sync_channel(0);
        let (resume_tx, resume_rx) = sync_channel(0);
        let leased = LeasedConnection {
            stream: Some(server),
            dispatch,
            stream_closed_probe: Some(LeasedConnectionDropProbe {
                stream_closed: stream_closed_tx,
                resume_drop: resume_rx,
            }),
        };
        let (close_tx, close_rx) = sync_channel(0);

        thread::scope(|scope| {
            scope.spawn(|| drop(leased));
            let runtime = Arc::clone(&runtime);
            scope.spawn(move || {
                let guard = runtime.close_and_drain().unwrap();
                close_tx.send(()).unwrap();
                drop(guard);
            });
            stream_closed_rx
                .recv_timeout(Duration::from_secs(1))
                .unwrap();
            assert_eq!(client.read(&mut [0_u8; 1]).unwrap(), 0);
            assert!(close_rx.recv_timeout(Duration::from_millis(50)).is_err());
            resume_tx.send(()).unwrap();
            close_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        });
    }

    #[test]
    fn partial_worker_spawn_failure_joins_started_workers_before_socket_cleanup() {
        let _process_guard = PROCESS_TEST_LOCK.lock().unwrap();
        let root = tempfile::tempdir().unwrap();
        let parent = root.path().join("socket-parent");
        fs::create_dir(&parent).unwrap();
        let daemon_gid = getegid().as_raw();
        let socket_client_gid = rustix::process::getgroups()
            .unwrap()
            .into_iter()
            .map(|gid| gid.as_raw())
            .find(|gid| *gid != daemon_gid)
            .unwrap();
        chown(&parent, None, Some(socket_client_gid)).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o750)).unwrap();
        let socket_path = parent.join("kerneld.sock");
        let socket_config = SocketConfig::for_test(
            socket_path.clone(),
            geteuid().as_raw(),
            daemon_gid,
            socket_client_gid,
        );
        let client_key = SigningKey::from_bytes(&[0x70; 32]);
        let service = HandshakeService::new_for_transport_test(
            client_key.verifying_key().to_bytes(),
            PeerIdentity::new_for_test(geteuid().as_raw(), daemon_gid),
            UnixMillis::new(1_000),
            UnixMillis::new(20_000),
        )
        .unwrap();
        let ordering = Arc::new(SpawnFailureOrderObserver::new());
        let limits = ServerLimits::for_test(4, 4, Duration::from_millis(100))
            .with_worker_spawn_failure(3)
            .with_spawn_failure_order_observer(Arc::clone(&ordering));
        let (server, _shutdown) = KernelServer::new_for_test(
            socket_config,
            service,
            effective_limits(1024, 2_000),
            limits,
            Arc::new(TestClock::new(2_000)),
        )
        .unwrap();

        assert_eq!(server.run(), Err(StableCode::KernelUnavailable));
        assert!(!socket_path.exists());
        let cleanup_started = ordering.cleanup_started();
        let cleanup_completed = ordering.cleanup_completed();
        for worker_index in 0..3 {
            let join_completed = ordering.worker_join_completed(worker_index);
            assert_ne!(join_completed, 0);
            assert!(join_completed < cleanup_started);
        }
        assert_eq!(ordering.worker_join_completed(3), 0);
        assert!(cleanup_started < cleanup_completed);
    }

    #[test]
    fn shutdown_racing_with_expected_worker_exit_remains_graceful() {
        let _process_guard = PROCESS_TEST_LOCK.lock().unwrap();
        let (_root, socket_path, socket_config, service, _client_key) =
            server_fixture(0x72, UnixMillis::new(20_000));
        let limits = ServerLimits::for_test(2, 4, Duration::from_millis(100))
            .with_shutdown_after_loop_entry();
        let (server, _shutdown) = KernelServer::new_for_test(
            socket_config,
            service,
            effective_limits(1024, 2_000),
            limits,
            Arc::new(TestClock::new(2_000)),
        )
        .unwrap();

        assert_eq!(server.run(), Ok(()));
        assert!(!socket_path.exists());
    }

    #[test]
    fn shutdown_is_not_reported_as_retryable_interrupted_frame_io() {
        let effective = effective_limits(1024, 2_000);
        let shutdown = Shutdown::new();
        shutdown.request();
        let (mut reader, _writer) = UnixStream::pair().unwrap();
        let started = Instant::now();
        assert_eq!(
            read_frame_with_deadline(&mut reader, &effective, Duration::from_secs(1), &shutdown,)
                .unwrap_err(),
            StableCode::DeadlineExceeded
        );
        assert!(started.elapsed() < Duration::from_millis(100));

        let (mut writer, _reader) = UnixStream::pair().unwrap();
        let started = Instant::now();
        assert_eq!(
            write_frame_with_deadline(
                &mut writer,
                &[0x51; 64],
                &effective,
                Duration::from_secs(1),
                &shutdown,
            )
            .unwrap_err(),
            StableCode::DeadlineExceeded
        );
        assert!(started.elapsed() < Duration::from_millis(100));
    }

    #[test]
    fn shutdown_while_worker_is_blocked_on_first_frame_has_bounded_join() {
        let _process_guard = PROCESS_TEST_LOCK.lock().unwrap();
        let (_root, socket_path, socket_config, service, _client_key) =
            server_fixture(0x73, UnixMillis::new(20_000));
        let (server, shutdown) = KernelServer::new_for_test(
            socket_config,
            service,
            effective_limits(1024, 2_000),
            ServerLimits::for_test(1, 1, Duration::from_millis(100)),
            Arc::new(TestClock::new(2_000)),
        )
        .unwrap();
        let server_thread = thread::spawn(move || server.run());
        let _slow = UnixStream::connect(&socket_path).unwrap();
        thread::sleep(Duration::from_millis(20));

        let started = Instant::now();
        shutdown.request();
        assert_eq!(server_thread.join().unwrap(), Ok(()));
        assert!(started.elapsed() < Duration::from_millis(500));
        assert!(!socket_path.exists());
    }

    #[test]
    fn queue_full_drops_new_connection_and_shutdown_drains_without_growth() {
        let _process_guard = PROCESS_TEST_LOCK.lock().unwrap();
        let (_root, socket_path, socket_config, service, _client_key) =
            server_fixture(0x74, UnixMillis::new(20_000));
        let (server, shutdown) = KernelServer::new_for_test(
            socket_config,
            service,
            effective_limits(1024, 2_000),
            ServerLimits::for_test(1, 1, Duration::from_millis(100)),
            Arc::new(TestClock::new(2_000)),
        )
        .unwrap();
        let server_thread = thread::spawn(move || server.run());

        let _active = UnixStream::connect(&socket_path).unwrap();
        thread::sleep(Duration::from_millis(20));
        let _queued = UnixStream::connect(&socket_path).unwrap();
        thread::sleep(Duration::from_millis(20));
        let mut overloaded = UnixStream::connect(&socket_path).unwrap();
        overloaded
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        assert_eq!(overloaded.read(&mut [0_u8; 1]).unwrap(), 0);

        let started = Instant::now();
        shutdown.request();
        assert_eq!(server_thread.join().unwrap(), Ok(()));
        assert!(started.elapsed() < Duration::from_millis(500));
        assert!(!socket_path.exists());
    }

    #[test]
    fn server_can_report_exact_cleanup_before_workers_start() {
        let _process_guard = PROCESS_TEST_LOCK.lock().unwrap();
        let (_root, socket_path, socket_config, service, _client_key) =
            server_fixture(0x75, UnixMillis::new(20_000));
        let (server, _shutdown) = KernelServer::new_for_test(
            socket_config,
            service,
            effective_limits(1024, 2_000),
            ServerLimits::for_test(1, 1, Duration::from_millis(100)),
            Arc::new(TestClock::new(2_000)),
        )
        .unwrap();

        assert_eq!(server.close(), Ok(()));
        assert!(!socket_path.exists());
    }

    #[test]
    fn slow_header_and_body_use_one_absolute_deadline_per_frame() {
        let limits = effective_limits(1024 * 1024, 10_000);
        for body_prefix in [false, true] {
            let (mut writer, mut reader) = UnixStream::pair().unwrap();
            let sender = thread::spawn(move || {
                if body_prefix {
                    writer.write_all(&8_u32.to_be_bytes()).unwrap();
                    writer.write_all(&[0x82]).unwrap();
                } else {
                    writer.write_all(&[0, 0]).unwrap();
                }
                thread::sleep(Duration::from_millis(80));
                let _ = writer.write_all(&[0; 8]);
            });
            let started = Instant::now();
            let error = read_frame_with_deadline(
                &mut reader,
                &limits,
                Duration::from_millis(30),
                &Shutdown::new(),
            )
            .unwrap_err();
            assert_eq!(error, StableCode::DeadlineExceeded);
            assert!(started.elapsed() < Duration::from_millis(75));
            sender.join().unwrap();
        }
    }

    #[test]
    fn blocked_frame_write_obeys_one_absolute_deadline() {
        let limits = effective_limits(8 * 1024 * 1024, 10_000);
        let (mut writer, _reader) = UnixStream::pair().unwrap();
        let payload = vec![0x5a; 8 * 1024 * 1024];
        let started = Instant::now();
        let error = write_frame_with_deadline(
            &mut writer,
            &payload,
            &limits,
            Duration::from_millis(30),
            &Shutdown::new(),
        )
        .unwrap_err();

        assert_eq!(error, StableCode::DeadlineExceeded);
        assert!(started.elapsed() < Duration::from_millis(250));
    }

    #[test]
    fn internally_oversized_server_frame_is_a_global_invariant_failure() {
        let limits = effective_limits(1, 10_000);
        let (mut writer, _reader) = UnixStream::pair().unwrap();
        let error = write_server_message(
            &mut writer,
            &ServerMessageV1::Accepted(HandshakeAcceptedV1 {
                boot_id: BootId::new([0x31; 32]),
                protocol: ProtocolVersion::new(1, 0),
            }),
            &limits,
            Duration::from_millis(100),
            &Shutdown::new(),
        )
        .unwrap_err();

        assert_eq!(
            error,
            ConnectionFailure::Fatal(StableCode::KernelUnavailable)
        );
    }

    #[test]
    fn unauthorized_peer_is_rejected_before_any_attacker_byte_is_read() {
        let client_key = SigningKey::from_bytes(&[0x76; 32]);
        let actual_uid = geteuid().as_raw();
        let actual_gid = getegid().as_raw();
        let expected = PeerIdentity::new_for_test(actual_uid.wrapping_add(1), actual_gid);
        let service = HandshakeService::new_for_transport_test(
            client_key.verifying_key().to_bytes(),
            expected,
            UnixMillis::new(1_000),
            UnixMillis::new(20_000),
        )
        .unwrap();
        let (mut client, server) = UnixStream::pair().unwrap();
        let attacker_bytes = [0xde, 0xad, 0xbe, 0xef];
        client.write_all(&attacker_bytes).unwrap();

        assert_eq!(
            handle_connection(
                server,
                &service,
                ConnectionRuntime {
                    frame_io_deadline: Duration::from_millis(100),
                    clock: &TestClock::new(2_000),
                    shutdown: &Shutdown::new(),
                    audit: None,
                    runtime: service.runtime().as_ref(),
                    peer_lookup_failures: None,
                },
            )
            .unwrap_err(),
            ConnectionFailure::Local(StableCode::IdentityPeerRejected)
        );
    }

    #[test]
    fn unauthorized_peer_emits_only_the_typed_handshake_rejection() {
        let client_key = SigningKey::from_bytes(&[0x76; 32]);
        let actual_uid = geteuid().as_raw();
        let actual_gid = getegid().as_raw();
        let expected = PeerIdentity::new_for_test(actual_uid.wrapping_add(1), actual_gid);
        let service = HandshakeService::new_for_transport_test(
            client_key.verifying_key().to_bytes(),
            expected,
            UnixMillis::new(1_000),
            UnixMillis::new(20_000),
        )
        .unwrap();
        let (_client, server) = UnixStream::pair().unwrap();
        let (audit_writer, mut audit_reader) = UnixStream::pair().unwrap();
        let audit_writer: OwnedFd = audit_writer.into();
        let audit = AuditSink::from_owned_for_test(
            AuditSecret::from_test_bytes([0xa5; 32]),
            audit_writer,
            Duration::from_millis(100),
        )
        .unwrap();

        assert_eq!(
            handle_connection(
                server,
                &service,
                ConnectionRuntime {
                    frame_io_deadline: Duration::from_millis(100),
                    clock: &TestClock::new(2_000),
                    shutdown: &Shutdown::new(),
                    audit: Some(&audit),
                    runtime: service.runtime().as_ref(),
                    peer_lookup_failures: None,
                },
            )
            .unwrap_err(),
            ConnectionFailure::Local(StableCode::IdentityPeerRejected)
        );
        drop(audit);
        let mut output = String::new();
        audit_reader.read_to_string(&mut output).unwrap();
        assert_eq!(
            output,
            "{\"event\":\"HandshakeRejected\",\"code\":\"IDENTITY_PEER_REJECTED\"}\n"
        );
    }

    #[test]
    fn handshake_audit_failure_is_a_global_fatal() {
        let client_key = SigningKey::from_bytes(&[0x76; 32]);
        let actual_uid = geteuid().as_raw();
        let actual_gid = getegid().as_raw();
        let expected = PeerIdentity::new_for_test(actual_uid.wrapping_add(1), actual_gid);
        let service = HandshakeService::new_for_transport_test(
            client_key.verifying_key().to_bytes(),
            expected,
            UnixMillis::new(1_000),
            UnixMillis::new(20_000),
        )
        .unwrap();
        let (_client, server) = UnixStream::pair().unwrap();
        let (audit_writer, audit_reader) = UnixStream::pair().unwrap();
        drop(audit_reader);
        let audit_writer: OwnedFd = audit_writer.into();
        let audit = AuditSink::from_owned_for_test(
            AuditSecret::from_test_bytes([0xa5; 32]),
            audit_writer,
            Duration::from_millis(100),
        )
        .unwrap();

        assert_eq!(
            handle_connection(
                server,
                &service,
                ConnectionRuntime {
                    frame_io_deadline: Duration::from_millis(100),
                    clock: &TestClock::new(2_000),
                    shutdown: &Shutdown::new(),
                    audit: Some(&audit),
                    runtime: service.runtime().as_ref(),
                    peer_lookup_failures: None,
                },
            ),
            Err(ConnectionFailure::Fatal(StableCode::KernelUnavailable))
        );
    }

    #[test]
    fn credential_lookup_failure_is_local_and_worker_serves_the_next_connection() {
        let effective = effective_limits(1024 * 1024, 2_000);
        let client_key = SigningKey::from_bytes(&[0x76; 32]);
        let service = HandshakeService::new_for_transport_test(
            client_key.verifying_key().to_bytes(),
            PeerIdentity::new_for_test(geteuid().as_raw(), getegid().as_raw()),
            UnixMillis::new(1_000),
            UnixMillis::new(20_000),
        )
        .unwrap();

        let (mut attacker, direct_server) = UnixStream::pair().unwrap();
        attacker.write_all(&[0xaa, 0xbb, 0xcc, 0xdd]).unwrap();
        let injected = AtomicUsize::new(1);
        assert_eq!(
            handle_connection(
                direct_server,
                &service,
                ConnectionRuntime {
                    frame_io_deadline: Duration::from_millis(100),
                    clock: &TestClock::new(2_000),
                    shutdown: &Shutdown::new(),
                    audit: None,
                    runtime: service.runtime().as_ref(),
                    peer_lookup_failures: Some(&injected),
                },
            )
            .unwrap_err(),
            ConnectionFailure::Local(StableCode::KernelUnavailable)
        );

        let (sender, receiver) = sync_channel(2);
        let (mut failed_client, failed_server) = UnixStream::pair().unwrap();
        let (mut healthy_client, healthy_server) = UnixStream::pair().unwrap();
        failed_client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        healthy_client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        healthy_client
            .set_write_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        sender.send(failed_server).unwrap();
        sender.send(healthy_server).unwrap();

        let shutdown = Shutdown::new();
        let worker_shutdown = shutdown.clone();
        let limits =
            ServerLimits::for_test(1, 2, Duration::from_millis(500)).with_peer_lookup_failures(1);
        let worker = thread::spawn(move || {
            worker_loop(
                &Mutex::new(receiver),
                &service,
                service.runtime().as_ref(),
                limits,
                &TestClock::new(2_000),
                &worker_shutdown,
                None,
            );
        });
        assert_silent_close(&mut failed_client);

        complete_client_handshake(
            &mut healthy_client,
            &client_key,
            &effective,
            RequestedMode::Required,
            0x29,
        );
        write_client(
            &mut healthy_client,
            &ClientMessageV1::Request(valid_request(
                ProtocolVersion::new(1, 0),
                UnixMillis::new(3_000),
                0x2a,
            )),
            &effective,
        );
        let response = match read_server(&mut healthy_client, &effective) {
            ServerMessageV1::Response(response) => response,
            other => panic!("expected response, got {other:?}"),
        };
        assert!(matches!(
            response.body,
            ResponseBodyV1::Ok(ResponsePayloadV1::Health(_))
        ));
        assert_silent_close(&mut healthy_client);

        shutdown.request();
        drop(sender);
        worker.join().unwrap();
        assert!(!shutdown.is_fatal());
    }

    #[test]
    fn every_wrong_message_variant_at_every_state_closes_silently() {
        let effective = effective_limits(1024 * 1024, 2_000);

        for wrong in 0..2 {
            let (mut client, _key, handle) =
                spawn_session(0x77 + wrong, UnixMillis::new(20_000), effective);
            let message = if wrong == 0 {
                ClientMessageV1::Finish(fake_finish())
            } else {
                ClientMessageV1::Request(valid_request(
                    ProtocolVersion::new(1, 0),
                    UnixMillis::new(3_000),
                    0x11,
                ))
            };
            write_client(&mut client, &message, &effective);
            assert_silent_close(&mut client);
            assert_eq!(
                handle.join().unwrap(),
                Err(ConnectionFailure::Local(
                    StableCode::IdentityTranscriptMismatch
                ))
            );
        }

        for wrong in 0..2 {
            let (mut client, _key, handle) =
                spawn_session(0x79 + wrong, UnixMillis::new(20_000), effective);
            let _signed =
                start_client_handshake(&mut client, &effective, RequestedMode::Required, 0x31);
            let message = if wrong == 0 {
                ClientMessageV1::Hello(valid_hello(RequestedMode::Required, 0x32))
            } else {
                ClientMessageV1::Request(valid_request(
                    ProtocolVersion::new(1, 0),
                    UnixMillis::new(3_000),
                    0x12,
                ))
            };
            write_client(&mut client, &message, &effective);
            assert_silent_close(&mut client);
            assert_eq!(
                handle.join().unwrap(),
                Err(ConnectionFailure::Local(
                    StableCode::IdentityTranscriptMismatch
                ))
            );
        }

        for wrong in 0..2 {
            let (mut client, key, handle) =
                spawn_session(0x7b + wrong, UnixMillis::new(20_000), effective);
            complete_client_handshake(&mut client, &key, &effective, RequestedMode::Required, 0x41);
            let message = if wrong == 0 {
                ClientMessageV1::Hello(valid_hello(RequestedMode::Required, 0x42))
            } else {
                ClientMessageV1::Finish(fake_finish())
            };
            write_client(&mut client, &message, &effective);
            assert_silent_close(&mut client);
            assert_eq!(
                handle.join().unwrap(),
                Err(ConnectionFailure::Local(
                    StableCode::IdentityTranscriptMismatch
                ))
            );
        }
    }

    #[test]
    fn disconnect_at_each_flight_is_connection_local() {
        let effective = effective_limits(1024 * 1024, 2_000);

        let (client, _key, handle) = spawn_session(0x7d, UnixMillis::new(20_000), effective);
        client.shutdown(NetworkShutdown::Write).unwrap();
        assert_eq!(
            handle.join().unwrap(),
            Err(ConnectionFailure::Local(StableCode::ProtocolTruncatedFrame))
        );

        let (mut client, _key, handle) = spawn_session(0x7e, UnixMillis::new(20_000), effective);
        start_client_handshake(&mut client, &effective, RequestedMode::Required, 0x51);
        client.shutdown(NetworkShutdown::Write).unwrap();
        assert_eq!(
            handle.join().unwrap(),
            Err(ConnectionFailure::Local(StableCode::ProtocolTruncatedFrame))
        );

        let (mut client, key, handle) = spawn_session(0x7f, UnixMillis::new(20_000), effective);
        complete_client_handshake(&mut client, &key, &effective, RequestedMode::Required, 0x52);
        client.shutdown(NetworkShutdown::Write).unwrap();
        assert_eq!(
            handle.join().unwrap(),
            Err(ConnectionFailure::Local(StableCode::ProtocolTruncatedFrame))
        );
    }

    #[test]
    fn hostile_frames_are_bounded_and_close_without_a_response() {
        let effective = effective_limits(1024, 2_000);
        let mut deep = vec![0x81; HardLimits::COMPILED.cbor_depth() as usize + 1];
        deep.push(0xf6);
        let noncanonical = noncanonical_hello_payload();
        let cases = vec![
            (
                0_u32.to_be_bytes().to_vec(),
                StableCode::ProtocolMalformedFrame,
            ),
            (
                (effective.frame_bytes() + 1)
                    .try_into()
                    .unwrap_or(u32::MAX)
                    .to_be_bytes()
                    .to_vec(),
                StableCode::ProtocolFrameTooLarge,
            ),
            (framed(&[0xff]), StableCode::ProtocolMalformedCbor),
            (framed(&noncanonical), StableCode::ProtocolNonCanonicalCbor),
            (framed(&deep), StableCode::ProtocolNestingTooDeep),
            (
                framed(&[0x82, 0x18, 0x63, 0x80]),
                StableCode::ProtocolUnknownOperation,
            ),
        ];

        for (index, (bytes, expected)) in cases.into_iter().enumerate() {
            let seed = 0x80_u8.wrapping_add(u8::try_from(index).unwrap());
            let (mut client, _key, handle) =
                spawn_session(seed, UnixMillis::new(20_000), effective);
            client.write_all(&bytes).unwrap();
            client.shutdown(NetworkShutdown::Write).unwrap();
            assert_silent_close(&mut client);
            assert_eq!(
                handle.join().unwrap(),
                Err(ConnectionFailure::Local(expected))
            );
        }

        for bytes in [
            vec![0x00, 0x00],
            [8_u32.to_be_bytes().as_slice(), &[0x81]].concat(),
        ] {
            let (mut client, _key, handle) =
                spawn_session(0x88, UnixMillis::new(20_000), effective);
            client.write_all(&bytes).unwrap();
            client.shutdown(NetworkShutdown::Write).unwrap();
            assert_silent_close(&mut client);
            assert_eq!(
                handle.join().unwrap(),
                Err(ConnectionFailure::Local(StableCode::ProtocolTruncatedFrame))
            );
        }
    }

    #[test]
    fn authenticated_v1_tag_20_has_no_trusted_response_id() {
        let effective = effective_limits(1024 * 1024, 2_000);
        let (mut client, key, handle) = spawn_session(0x89, UnixMillis::new(20_000), effective);
        complete_client_handshake(&mut client, &key, &effective, RequestedMode::Required, 0x61);
        let mut payload = encode_client_message(&ClientMessageV1::Request(valid_request(
            ProtocolVersion::new(1, 0),
            UnixMillis::new(3_000),
            0x21,
        )))
        .unwrap();
        let operation = payload
            .windows(3)
            .rposition(|window| window == [0x82, 0x00, 0x80])
            .unwrap();
        payload[operation + 1] = 20;
        client.write_all(&framed(&payload)).unwrap();
        assert_silent_close(&mut client);
        assert_eq!(
            handle.join().unwrap(),
            Err(ConnectionFailure::Local(
                StableCode::ProtocolUnknownOperation
            ))
        );
    }

    #[test]
    fn decoded_request_errors_echo_id_once_then_close() {
        let cases = [
            (
                ProtocolVersion::new(9, 9),
                UnixMillis::new(3_000),
                UnixMillis::new(20_000),
                2_000,
                StableCode::ProtocolUnsupportedVersion,
            ),
            (
                ProtocolVersion::new(1, 0),
                UnixMillis::new(2_002),
                UnixMillis::new(20_000),
                2_000,
                StableCode::DeadlineExceeded,
            ),
            (
                ProtocolVersion::new(1, 0),
                UnixMillis::new(5_000),
                UnixMillis::new(20_000),
                2_000,
                StableCode::DeadlineExceeded,
            ),
            (
                ProtocolVersion::new(1, 0),
                UnixMillis::new(2_600),
                UnixMillis::new(2_500),
                10_000,
                StableCode::DeadlineExceeded,
            ),
        ];

        for (index, (version, deadline, expiry, maximum, expected)) in cases.into_iter().enumerate()
        {
            let request_id = RequestId::new([0x31 + u8::try_from(index).unwrap(); 16]);
            let (response, result) = request_round_trip(
                0x90 + u8::try_from(index).unwrap(),
                expiry,
                maximum,
                RequestEnvelopeV1 {
                    version,
                    request_id,
                    deadline_unix_ms: deadline,
                    operation: OperationV1::Health,
                },
            );
            assert_eq!(response.version, ProtocolVersion::new(1, 0));
            assert_eq!(response.request_id, request_id);
            assert_eq!(response.body, ResponseBodyV1::Err(expected));
            assert_eq!(result, Ok(()));
        }
    }

    #[test]
    fn policy_tags_10_through_19_fail_closed_until_policy_dispatch_is_integrated() {
        let effective = effective_limits(1024 * 1024, 2_000);
        let mut corpus = minicbor::Decoder::new(include_bytes!(
            "../../../vectors/kerneld/policy-flow-v1.cbor"
        ));
        assert_eq!(corpus.array().unwrap(), Some(12));

        for index in 0_u8..10 {
            let encoded = corpus.bytes().unwrap();
            let operation = match decode_client_message(encoded, &effective).unwrap() {
                ClientMessageV1::Request(request) => request.operation,
                other => panic!("expected policy request, got {other:?}"),
            };
            let request_id = RequestId::new([0xa0 + index; 16]);
            let (response, result) = request_round_trip(
                0xb0 + index,
                UnixMillis::new(20_000),
                2_000,
                RequestEnvelopeV1 {
                    version: ProtocolVersion::new(1, 0),
                    request_id,
                    deadline_unix_ms: UnixMillis::new(3_000),
                    operation,
                },
            );
            assert_eq!(response.request_id, request_id);
            assert_eq!(
                response.body,
                ResponseBodyV1::Err(StableCode::KernelUnavailable)
            );
            assert_eq!(result, Ok(()));
        }
    }

    #[test]
    fn decoded_request_emits_one_redacted_completion_event() {
        let effective = effective_limits(1024 * 1024, 2_000);
        let client_key = SigningKey::from_bytes(&[0x96; 32]);
        let service = HandshakeService::new_for_transport_test(
            client_key.verifying_key().to_bytes(),
            PeerIdentity::new_for_test(geteuid().as_raw(), getegid().as_raw()),
            UnixMillis::new(1_000),
            UnixMillis::new(20_000),
        )
        .unwrap();
        let (mut client, server) = UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        client
            .set_write_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let (audit_writer, mut audit_reader) = UnixStream::pair().unwrap();
        let audit_writer: OwnedFd = audit_writer.into();
        let audit = Arc::new(
            AuditSink::from_owned_for_test(
                AuditSecret::from_test_bytes([0xa5; 32]),
                audit_writer,
                Duration::from_millis(100),
            )
            .unwrap(),
        );
        let worker_audit = Arc::clone(&audit);
        let handle = thread::spawn(move || {
            handle_connection(
                server,
                &service,
                ConnectionRuntime {
                    frame_io_deadline: Duration::from_millis(500),
                    clock: &TestClock::new(2_000),
                    shutdown: &Shutdown::new(),
                    audit: Some(worker_audit.as_ref()),
                    runtime: service.runtime().as_ref(),
                    peer_lookup_failures: None,
                },
            )
        });

        complete_client_handshake(
            &mut client,
            &client_key,
            &effective,
            RequestedMode::Required,
            0x75,
        );
        write_client(
            &mut client,
            &ClientMessageV1::Request(valid_request(
                ProtocolVersion::new(9, 9),
                UnixMillis::new(3_000),
                0x44,
            )),
            &effective,
        );
        let response = match read_server(&mut client, &effective) {
            ServerMessageV1::Response(response) => response,
            other => panic!("expected response, got {other:?}"),
        };
        assert_eq!(
            response.body,
            ResponseBodyV1::Err(StableCode::ProtocolUnsupportedVersion)
        );
        assert_eq!(handle.join().unwrap(), Ok(()));
        drop(audit);

        let mut output = String::new();
        audit_reader.read_to_string(&mut output).unwrap();
        assert!(output.starts_with(concat!(
            r#"{"event":"RequestCompleted","operation_tag":"health","#,
            r#""code":"PROTOCOL_UNSUPPORTED_VERSION","latency_ms":"#
        )));
        assert!(output.ends_with("}\n"));
        assert!(!output.contains("transport-client"));
        assert!(!output.contains(&"44".repeat(16)));
    }

    #[test]
    fn release_expiry_after_handshake_closes_without_response() {
        let effective = effective_limits(1024 * 1024, 2_000);
        let (mut client, key, handle) = spawn_session(0x95, UnixMillis::new(2_002), effective);
        complete_client_handshake(&mut client, &key, &effective, RequestedMode::Required, 0x71);
        write_client(
            &mut client,
            &ClientMessageV1::Request(valid_request(
                ProtocolVersion::new(1, 0),
                UnixMillis::new(2_100),
                0x41,
            )),
            &effective,
        );
        assert_silent_close(&mut client);
        assert_eq!(
            handle.join().unwrap(),
            Err(ConnectionFailure::Local(
                StableCode::IdentityReleaseMismatch
            ))
        );
    }

    #[test]
    fn policy_expiry_after_handshake_returns_stable_error_then_closes() {
        let effective = effective_limits(1024 * 1024, 2_000);
        let (mut client, key, handle) = spawn_session_with_expiries(
            0x96,
            UnixMillis::new(20_000),
            UnixMillis::new(2_002),
            effective,
        );
        complete_client_handshake(&mut client, &key, &effective, RequestedMode::Required, 0x72);
        write_client(
            &mut client,
            &ClientMessageV1::Request(valid_request(
                ProtocolVersion::new(1, 0),
                UnixMillis::new(2_100),
                0x42,
            )),
            &effective,
        );
        let response = match read_server(&mut client, &effective) {
            ServerMessageV1::Response(response) => response,
            other => panic!("expected policy-expired response, got {other:?}"),
        };
        assert_eq!(response.request_id, RequestId::new([0x42; 16]));
        assert_eq!(
            response.body,
            ResponseBodyV1::Err(StableCode::PolicyExpired)
        );
        assert_silent_close(&mut client);
        assert_eq!(handle.join().unwrap(), Ok(()));
    }

    #[test]
    fn real_signed_required_and_shadow_health_close_after_one_response() {
        let _process_guard = PROCESS_TEST_LOCK.lock().unwrap();
        let root = tempfile::tempdir().unwrap();
        let parent = root.path().join("socket-parent");
        fs::create_dir(&parent).unwrap();
        let daemon_gid = getegid().as_raw();
        let socket_client_gid = rustix::process::getgroups()
            .unwrap()
            .into_iter()
            .map(|gid| gid.as_raw())
            .find(|gid| *gid != daemon_gid)
            .unwrap();
        chown(&parent, None, Some(socket_client_gid)).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o750)).unwrap();
        let socket_path = parent.join("kerneld.sock");
        let socket_config = SocketConfig::for_test(
            socket_path.clone(),
            geteuid().as_raw(),
            daemon_gid,
            socket_client_gid,
        );
        let client_key = SigningKey::from_bytes(&[0x71; 32]);
        // An unprivileged POSIX process cannot switch its effective GID to an
        // arbitrary supplementary GID. Keep the real socket group distinct,
        // but make this cfg(test)-only handshake fixture expect the process's
        // actual credentials so the production peer extraction is exercised.
        let peer = PeerIdentity::new_for_test(geteuid().as_raw(), daemon_gid);
        let service = HandshakeService::new_for_transport_test(
            client_key.verifying_key().to_bytes(),
            peer,
            UnixMillis::new(1_000),
            UnixMillis::new(20_000),
        )
        .unwrap();
        let effective = effective_limits(1024 * 1024, 2_000);
        let clock = Arc::new(TestClock::new(2_000));
        let (server, shutdown) = KernelServer::new_for_test(
            socket_config,
            service,
            effective,
            ServerLimits::for_test(2, 4, Duration::from_millis(500)),
            clock,
        )
        .unwrap();
        let server_thread = thread::spawn(move || server.run());

        let mut wrong_flight = UnixStream::connect(&socket_path).unwrap();
        write_client(
            &mut wrong_flight,
            &ClientMessageV1::Finish(ClientFinishV1 {
                transcript_digest: Digest32::new([0x41; 32]),
                signature: Signature64::new([0x42; 64]),
            }),
            &effective,
        );
        wrong_flight
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        assert_eq!(wrong_flight.read(&mut [0_u8; 1]).unwrap(), 0);

        for (index, mode) in [RequestedMode::Required, RequestedMode::Shadow]
            .into_iter()
            .enumerate()
        {
            let mut stream = UnixStream::connect(&socket_path).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            let hello = ClientHelloV1 {
                client_nonce: Nonce32::new([0x51 + u8::try_from(index).unwrap(); 32]),
                supported_versions: vec![ProtocolVersion::new(1, 0)],
                client_id: "transport-client".try_into().unwrap(),
                client_key_id: "transport-client-key".try_into().unwrap(),
                requested_mode: mode,
            };
            write_client(&mut stream, &ClientMessageV1::Hello(hello), &effective);
            let signed = match read_server(&mut stream, &effective) {
                ServerMessageV1::Hello(signed) => signed,
                other => panic!("expected signed hello, got {other:?}"),
            };
            let transcript_bytes = minicbor::to_vec(&signed.transcript).unwrap();
            let digest = Digest32::new(Sha256::digest(&transcript_bytes).into());
            let mut signature_input = b"SAVANA_CLIENT_FINISH_V1\0".to_vec();
            signature_input.extend_from_slice(digest.as_bytes());
            write_client(
                &mut stream,
                &ClientMessageV1::Finish(ClientFinishV1 {
                    transcript_digest: digest,
                    signature: Signature64::new(client_key.sign(&signature_input).to_bytes()),
                }),
                &effective,
            );
            match read_server(&mut stream, &effective) {
                ServerMessageV1::Accepted(accepted) => {
                    assert_eq!(accepted.boot_id, signed.transcript.server.boot_id);
                    assert_eq!(accepted.protocol, ProtocolVersion::new(1, 0));
                }
                other => panic!("expected accepted, got {other:?}"),
            }

            let request_id = RequestId::new([0x61 + u8::try_from(index).unwrap(); 16]);
            write_client(
                &mut stream,
                &ClientMessageV1::Request(RequestEnvelopeV1 {
                    version: ProtocolVersion::new(1, 0),
                    request_id,
                    deadline_unix_ms: UnixMillis::new(3_500),
                    operation: OperationV1::Health,
                }),
                &effective,
            );
            let response = match read_server(&mut stream, &effective) {
                ServerMessageV1::Response(response) => response,
                other => panic!("expected response, got {other:?}"),
            };
            assert_eq!(response.version, ProtocolVersion::new(1, 0));
            assert_eq!(response.request_id, request_id);
            match response.body {
                ResponseBodyV1::Ok(ResponsePayloadV1::Health(snapshot)) => {
                    assert!(snapshot.ready);
                    assert_eq!(snapshot.identity, signed.transcript.server);
                    assert_eq!(snapshot.last_error, None);
                }
                other => panic!("expected Health success, got {other:?}"),
            }
            assert_eq!(stream.read(&mut [0_u8; 1]).unwrap(), 0);
        }

        shutdown.request();
        assert_eq!(server_thread.join().unwrap(), Ok(()));
        assert!(!socket_path.exists());
    }

    struct TestClock {
        next: AtomicU64,
    }

    impl TestClock {
        fn new(start: u64) -> Self {
            Self {
                next: AtomicU64::new(start),
            }
        }
    }

    impl Clock for TestClock {
        fn wall_now(&self) -> Result<UnixMillis, StableCode> {
            Ok(UnixMillis::new(self.next.fetch_add(1, Ordering::AcqRel)))
        }

        fn monotonic_now_millis(&self) -> Result<u64, StableCode> {
            Ok(self.next.fetch_add(1, Ordering::AcqRel))
        }
    }

    fn write_client(stream: &mut UnixStream, message: &ClientMessageV1, limits: &EffectiveLimits) {
        let payload = encode_client_message(message).unwrap();
        write_frame(stream, &payload, limits).unwrap();
    }

    fn read_server(stream: &mut UnixStream, limits: &EffectiveLimits) -> ServerMessageV1 {
        let payload = read_frame(stream, limits).unwrap();
        decode_server_message(&payload, limits).unwrap()
    }

    fn server_fixture(
        client_seed: u8,
        expires_at: UnixMillis,
    ) -> (
        tempfile::TempDir,
        std::path::PathBuf,
        SocketConfig,
        HandshakeService,
        SigningKey,
    ) {
        let root = tempfile::tempdir().unwrap();
        let parent = root.path().join("socket-parent");
        fs::create_dir(&parent).unwrap();
        let daemon_gid = getegid().as_raw();
        let socket_client_gid = rustix::process::getgroups()
            .unwrap()
            .into_iter()
            .map(|gid| gid.as_raw())
            .find(|gid| *gid != daemon_gid)
            .unwrap();
        chown(&parent, None, Some(socket_client_gid)).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o750)).unwrap();
        let socket_path = parent.join("kerneld.sock");
        let socket_config = SocketConfig::for_test(
            socket_path.clone(),
            geteuid().as_raw(),
            daemon_gid,
            socket_client_gid,
        );
        let client_key = SigningKey::from_bytes(&[client_seed; 32]);
        let service = HandshakeService::new_for_transport_test(
            client_key.verifying_key().to_bytes(),
            PeerIdentity::new_for_test(geteuid().as_raw(), daemon_gid),
            UnixMillis::new(1_000),
            expires_at,
        )
        .unwrap();
        (root, socket_path, socket_config, service, client_key)
    }

    fn spawn_session(
        client_seed: u8,
        expires_at: UnixMillis,
        effective: EffectiveLimits,
    ) -> (
        UnixStream,
        SigningKey,
        thread::JoinHandle<Result<(), ConnectionFailure>>,
    ) {
        spawn_session_with_expiries(client_seed, expires_at, expires_at, effective)
    }

    fn spawn_session_with_expiries(
        client_seed: u8,
        release_expires_at: UnixMillis,
        policy_expires_at: UnixMillis,
        effective: EffectiveLimits,
    ) -> (
        UnixStream,
        SigningKey,
        thread::JoinHandle<Result<(), ConnectionFailure>>,
    ) {
        let client_key = SigningKey::from_bytes(&[client_seed; 32]);
        let service = HandshakeService::new_for_transport_test_with_expiries(
            client_key.verifying_key().to_bytes(),
            PeerIdentity::new_for_test(geteuid().as_raw(), getegid().as_raw()),
            UnixMillis::new(1_000),
            release_expires_at,
            policy_expires_at,
        )
        .unwrap();
        service.force_effective_limits_for_transport_test(effective);
        let (client, server) = UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        client
            .set_write_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let handle = thread::spawn(move || {
            handle_connection(
                server,
                &service,
                ConnectionRuntime {
                    frame_io_deadline: Duration::from_millis(500),
                    clock: &TestClock::new(2_000),
                    shutdown: &Shutdown::new(),
                    audit: None,
                    runtime: service.runtime().as_ref(),
                    peer_lookup_failures: None,
                },
            )
        });
        (client, client_key, handle)
    }

    fn valid_hello(mode: RequestedMode, nonce: u8) -> ClientHelloV1 {
        ClientHelloV1 {
            client_nonce: Nonce32::new([nonce; 32]),
            supported_versions: vec![ProtocolVersion::new(1, 0)],
            client_id: "transport-client".try_into().unwrap(),
            client_key_id: "transport-client-key".try_into().unwrap(),
            requested_mode: mode,
        }
    }

    fn valid_request(
        version: ProtocolVersion,
        deadline: UnixMillis,
        request_id: u8,
    ) -> RequestEnvelopeV1 {
        RequestEnvelopeV1 {
            version,
            request_id: RequestId::new([request_id; 16]),
            deadline_unix_ms: deadline,
            operation: OperationV1::Health,
        }
    }

    fn real_begin_request(
        context: &crate::handshake::ConnectionContext,
        identity: PolicyIdentity,
    ) -> BeginRunRequest {
        let input = KernelValue::Null;
        let commitment = IngressRequestCommitmentV1::BeginRun {
            input: input.clone(),
        };
        let unsigned = IngressEnvelopeV1 {
            principal: PrincipalId::new("principal-1").unwrap(),
            conversation_id: "conversation-1".try_into().unwrap(),
            request_digest: ingress_request_digest(&commitment).unwrap(),
            issued_at: UnixMillis::new(1_900),
            expires_at: identity.expires_at,
            nonce: Nonce32::new([0x93; 32]),
            authority_session_id: Nonce32::new([0x66; 32]),
            authentication_context_digest: Digest32::new([0x55; 32]),
            role: RoleId::new("operator").unwrap(),
            policy_digest: identity.digest,
            boot_id: context.boot_id(),
            connection_binding_digest: context.connection_binding_digest(),
        };
        let ingress_key = SigningKey::from_bytes(&[0x70; 32]);
        let mut signed = b"SAVANA_INGRESS_V1\0".to_vec();
        signed.extend_from_slice(&minicbor::to_vec(&unsigned).unwrap());
        BeginRunRequest {
            ingress: SignedIngressEnvelopeV1 {
                signature: Signature64::new(ingress_key.sign(&signed).to_bytes()),
                unsigned,
                key_id: KeyId::new("role-00").unwrap(),
            },
            input,
            registry: real_registry(identity),
        }
    }

    fn real_registry(identity: PolicyIdentity) -> SignedRegistrySnapshotV1 {
        let unsigned = RegistrySnapshotV1 {
            version: 1,
            previous_digest: None,
            tools: vec![ToolDescriptorV1 {
                identity: ToolExecutionIdentity {
                    name: ToolName::new("tool-00").unwrap(),
                    descriptor_digest: Digest32::new([0x21; 32]),
                    registry_version: 1,
                },
                provider_id: BoundedText::new("provider-1").unwrap(),
                roles: vec![RoleId::new("operator").unwrap()],
                input_schema_digest: Digest32::new([0x31; 32]),
                output_schema_digest: Digest32::new([0x32; 32]),
                attempt: AttemptKindV1::Read,
                constraint_ids: vec![ConstraintId::new("constraint-00").unwrap()],
                validator_ids: Vec::new(),
                projection_digest: Digest32::new([0x33; 32]),
            }],
            issued_at: UnixMillis::new(1_900),
            expires_at: identity.expires_at,
        };
        let signer = SigningKey::from_bytes(&[0x72; 32]);
        let mut signed = b"SAVANA_REGISTRY_V1\0".to_vec();
        signed.extend_from_slice(&minicbor::to_vec(&unsigned).unwrap());
        SignedRegistrySnapshotV1 {
            signature: Signature64::new(signer.sign(&signed).to_bytes()),
            unsigned,
            key_id: KeyId::new("role-02").unwrap(),
        }
    }

    fn fake_finish() -> ClientFinishV1 {
        ClientFinishV1 {
            transcript_digest: Digest32::new([0x41; 32]),
            signature: Signature64::new([0x42; 64]),
        }
    }

    fn start_client_handshake(
        stream: &mut UnixStream,
        effective: &EffectiveLimits,
        mode: RequestedMode,
        nonce: u8,
    ) -> SignedServerHelloV1 {
        write_client(
            stream,
            &ClientMessageV1::Hello(valid_hello(mode, nonce)),
            effective,
        );
        match read_server(stream, effective) {
            ServerMessageV1::Hello(signed) => signed,
            other => panic!("expected signed hello, got {other:?}"),
        }
    }

    fn complete_client_handshake(
        stream: &mut UnixStream,
        client_key: &SigningKey,
        effective: &EffectiveLimits,
        mode: RequestedMode,
        nonce: u8,
    ) -> SignedServerHelloV1 {
        let signed = start_client_handshake(stream, effective, mode, nonce);
        let transcript_bytes = minicbor::to_vec(&signed.transcript).unwrap();
        let digest = Digest32::new(Sha256::digest(&transcript_bytes).into());
        let mut signature_input = b"SAVANA_CLIENT_FINISH_V1\0".to_vec();
        signature_input.extend_from_slice(digest.as_bytes());
        write_client(
            stream,
            &ClientMessageV1::Finish(ClientFinishV1 {
                transcript_digest: digest,
                signature: Signature64::new(client_key.sign(&signature_input).to_bytes()),
            }),
            effective,
        );
        match read_server(stream, effective) {
            ServerMessageV1::Accepted(accepted) => {
                assert_eq!(accepted.boot_id, signed.transcript.server.boot_id);
                assert_eq!(accepted.protocol, signed.transcript.server.protocol);
            }
            other => panic!("expected accepted, got {other:?}"),
        }
        signed
    }

    fn request_round_trip(
        client_seed: u8,
        expires_at: UnixMillis,
        request_deadline_ms: u64,
        request: RequestEnvelopeV1,
    ) -> (ResponseEnvelopeV1, Result<(), ConnectionFailure>) {
        let effective = effective_limits(1024 * 1024, request_deadline_ms);
        let (mut client, key, handle) = spawn_session(client_seed, expires_at, effective);
        complete_client_handshake(&mut client, &key, &effective, RequestedMode::Required, 0x73);
        write_client(&mut client, &ClientMessageV1::Request(request), &effective);
        let response = match read_server(&mut client, &effective) {
            ServerMessageV1::Response(response) => response,
            other => panic!("expected response, got {other:?}"),
        };
        assert_silent_close(&mut client);
        (response, handle.join().unwrap())
    }

    fn assert_silent_close(stream: &mut UnixStream) {
        assert_eq!(stream.read(&mut [0_u8; 1]).unwrap(), 0);
    }

    fn framed(payload: &[u8]) -> Vec<u8> {
        let length = u32::try_from(payload.len()).unwrap();
        [length.to_be_bytes().as_slice(), payload].concat()
    }

    fn noncanonical_hello_payload() -> Vec<u8> {
        let mut payload = encode_client_message(&ClientMessageV1::Hello(valid_hello(
            RequestedMode::Required,
            0x74,
        )))
        .unwrap();
        let version = payload
            .windows(4)
            .position(|window| window == [0x81, 0x82, 0x01, 0x00])
            .unwrap();
        payload.splice(version + 3..version + 4, [0x18, 0x00]);
        payload
    }

    fn effective_limits(frame_bytes: u64, request_deadline_ms: u64) -> EffectiveLimits {
        let hard = HardLimits::COMPILED;
        hard.lower(&ResourceLimitsV1 {
            frame_bytes,
            cbor_depth: hard.cbor_depth(),
            pages: hard.pages(),
            chars_per_page: hard.chars_per_page(),
            chars_per_document: hard.chars_per_document(),
            observations: hard.observations(),
            vault_entries: hard.vault_entries(),
            vault_raw_bytes: hard.vault_raw_bytes(),
            runs_per_client: hard.runs_per_client(),
            vaults_per_client: hard.vaults_per_client(),
            approval_ledger_entries: hard.approval_ledger_entries(),
            model_manifest_bytes: hard.model_manifest_bytes(),
            model_assets: hard.model_assets(),
            model_tensor_contracts: hard.model_tensor_contracts(),
            model_tensor_rank: hard.model_tensor_rank(),
            single_model_asset_bytes: hard.single_model_asset_bytes(),
            total_model_asset_bytes: hard.total_model_asset_bytes(),
            ner_workers: hard.ner_workers(),
            ner_queue: hard.ner_queue(),
            ner_text_bytes: hard.ner_text_bytes(),
            model_probes: hard.model_probes(),
            model_probe_spans: hard.model_probe_spans(),
            ner_failure_threshold: hard.ner_failure_threshold(),
            request_deadline_ms,
            ingress_replay_entries_per_client: hard.ingress_replay_entries_per_client(),
        })
        .unwrap()
    }
}
