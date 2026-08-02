use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const OWNER_RUNNING: u8 = 1;
const OWNER_CLOSING: u8 = 2;
const OWNER_FAILED: u8 = 3;
const OWNER_STOPPED: u8 = 4;

const REQUEST_OPEN: u8 = 1;
const REQUEST_CANCELLED: u8 = 2;
const REQUEST_COMMIT_OWNED: u8 = 3;
const REQUEST_DURABLE_COMPLETE: u8 = 4;
const REQUEST_COMPLETE: u8 = 5;
const REQUEST_ABANDONED: u8 = 6;
const POST_COMMIT_COMPLETION_GRACE: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StateOwnerErrorV2 {
    RuntimeBusy,
    DeadlineExceeded,
    RuntimeUnavailable,
}

enum OwnerMessageV2<Command, Response> {
    Execute {
        command: Command,
        deadline: Instant,
        completion: Arc<RequestCompletionV2<Response>>,
    },
    Shutdown,
}

struct RequestDecisionV2 {
    state: AtomicU8,
    deadline: Instant,
    durable_recovery_identity: Mutex<Option<[u8; 32]>>,
}

struct RequestCompletionV2<Response> {
    decision: Arc<RequestDecisionV2>,
    result: Mutex<Option<Result<Response, StateOwnerErrorV2>>>,
    wake: Condvar,
}

impl<Response> RequestCompletionV2<Response> {
    fn new(deadline: Instant) -> Self {
        Self {
            decision: Arc::new(RequestDecisionV2 {
                state: AtomicU8::new(REQUEST_OPEN),
                deadline,
                durable_recovery_identity: Mutex::new(None),
            }),
            result: Mutex::new(None),
            wake: Condvar::new(),
        }
    }

    fn commit_handle(&self) -> StateOwnerCommitV2 {
        StateOwnerCommitV2 {
            decision: Arc::clone(&self.decision),
        }
    }

    fn cancel(&self) {
        let _ = self.decision.state.compare_exchange(
            REQUEST_OPEN,
            REQUEST_CANCELLED,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        self.wake.notify_all();
    }

    fn complete(&self, result: Result<Response, StateOwnerErrorV2>) {
        let mut stored = lock_unpoisoned(&self.result);
        match self.decision.state.load(Ordering::Acquire) {
            REQUEST_OPEN => {
                if self
                    .decision
                    .state
                    .compare_exchange(
                        REQUEST_OPEN,
                        REQUEST_COMPLETE,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_ok()
                {
                    *stored = Some(result);
                }
            }
            REQUEST_COMMIT_OWNED | REQUEST_DURABLE_COMPLETE | REQUEST_ABANDONED => {
                *stored = Some(result);
                self.decision
                    .state
                    .store(REQUEST_COMPLETE, Ordering::Release);
            }
            REQUEST_CANCELLED | REQUEST_COMPLETE => {}
            _ => {
                self.decision
                    .state
                    .store(REQUEST_COMPLETE, Ordering::Release);
                *stored = Some(Err(StateOwnerErrorV2::RuntimeUnavailable));
            }
        }
        self.wake.notify_all();
    }

    fn has_durable_recovery(&self) -> bool {
        lock_unpoisoned(&self.decision.durable_recovery_identity).is_some()
    }

    fn wait(&self) -> Result<Response, StateOwnerErrorV2> {
        let mut stored = lock_unpoisoned(&self.result);
        loop {
            if let Some(result) = stored.take() {
                return result;
            }
            match self.decision.state.load(Ordering::Acquire) {
                REQUEST_CANCELLED => return Err(StateOwnerErrorV2::DeadlineExceeded),
                REQUEST_ABANDONED => return Err(StateOwnerErrorV2::RuntimeUnavailable),
                REQUEST_COMPLETE => return Err(StateOwnerErrorV2::RuntimeUnavailable),
                REQUEST_OPEN => {
                    let remaining = self
                        .decision
                        .deadline
                        .saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        match self.decision.state.compare_exchange(
                            REQUEST_OPEN,
                            REQUEST_CANCELLED,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        ) {
                            Ok(_) => {
                                self.wake.notify_all();
                                return Err(StateOwnerErrorV2::DeadlineExceeded);
                            }
                            Err(_) => continue,
                        }
                    }
                    stored = wait_timeout_unpoisoned(&self.wake, stored, remaining);
                }
                REQUEST_COMMIT_OWNED | REQUEST_DURABLE_COMPLETE => {
                    let grace_deadline = self
                        .decision
                        .deadline
                        .checked_add(POST_COMMIT_COMPLETION_GRACE)
                        .unwrap_or_else(|| Instant::now() + POST_COMMIT_COMPLETION_GRACE);
                    loop {
                        if let Some(result) = stored.take() {
                            return result;
                        }
                        if self.decision.state.load(Ordering::Acquire) == REQUEST_COMPLETE {
                            continue;
                        }
                        let remaining = grace_deadline.saturating_duration_since(Instant::now());
                        if remaining.is_zero() {
                            let state = self.decision.state.load(Ordering::Acquire);
                            match state {
                                REQUEST_COMMIT_OWNED | REQUEST_DURABLE_COMPLETE => {
                                    if self
                                        .decision
                                        .state
                                        .compare_exchange(
                                            state,
                                            REQUEST_ABANDONED,
                                            Ordering::AcqRel,
                                            Ordering::Acquire,
                                        )
                                        .is_ok()
                                    {
                                        return Err(StateOwnerErrorV2::RuntimeUnavailable);
                                    }
                                }
                                REQUEST_COMPLETE => continue,
                                REQUEST_ABANDONED => {
                                    return Err(StateOwnerErrorV2::RuntimeUnavailable)
                                }
                                _ => break,
                            }
                        }
                        stored = wait_timeout_unpoisoned(&self.wake, stored, remaining);
                    }
                }
                _ => return Err(StateOwnerErrorV2::RuntimeUnavailable),
            }
        }
    }
}

pub(crate) struct StateOwnerCommitV2 {
    decision: Arc<RequestDecisionV2>,
}

impl StateOwnerCommitV2 {
    pub(crate) fn claim(&self) -> Result<(), StateOwnerErrorV2> {
        if Instant::now() >= self.decision.deadline {
            let _ = self.decision.state.compare_exchange(
                REQUEST_OPEN,
                REQUEST_CANCELLED,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
            return Err(match self.decision.state.load(Ordering::Acquire) {
                REQUEST_COMMIT_OWNED
                | REQUEST_DURABLE_COMPLETE
                | REQUEST_COMPLETE
                | REQUEST_ABANDONED => StateOwnerErrorV2::RuntimeUnavailable,
                _ => StateOwnerErrorV2::DeadlineExceeded,
            });
        }
        match self.decision.state.compare_exchange(
            REQUEST_OPEN,
            REQUEST_COMMIT_OWNED,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => Ok(()),
            Err(REQUEST_CANCELLED) => Err(StateOwnerErrorV2::DeadlineExceeded),
            Err(_) => Err(StateOwnerErrorV2::RuntimeUnavailable),
        }
    }

    pub(crate) fn mark_durable_complete(
        &self,
        proof: &crate::v2_ingress_authority::PublishedFinalizeRecoveryProofV2,
    ) -> Result<(), StateOwnerErrorV2> {
        let identity_commitment = proof.identity_commitment();
        if identity_commitment.iter().all(|byte| *byte == 0) {
            return Err(StateOwnerErrorV2::RuntimeUnavailable);
        }
        *lock_unpoisoned(&self.decision.durable_recovery_identity) = Some(identity_commitment);
        loop {
            let state = self.decision.state.load(Ordering::Acquire);
            match state {
                REQUEST_COMMIT_OWNED | REQUEST_ABANDONED => {
                    if self
                        .decision
                        .state
                        .compare_exchange(
                            state,
                            REQUEST_DURABLE_COMPLETE,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        return Ok(());
                    }
                }
                REQUEST_DURABLE_COMPLETE | REQUEST_COMPLETE => return Ok(()),
                REQUEST_OPEN | REQUEST_CANCELLED => {
                    *lock_unpoisoned(&self.decision.durable_recovery_identity) = None;
                    return Err(StateOwnerErrorV2::RuntimeUnavailable);
                }
                _ => return Err(StateOwnerErrorV2::RuntimeUnavailable),
            }
        }
    }
}

fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn wait_timeout_unpoisoned<'a, T>(
    wake: &Condvar,
    guard: MutexGuard<'a, T>,
    timeout: Duration,
) -> MutexGuard<'a, T> {
    wake.wait_timeout(guard, timeout)
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .0
}

pub(crate) struct StateOwnerV2<Command, Response> {
    admission: Arc<Mutex<Option<SyncSender<OwnerMessageV2<Command, Response>>>>>,
    lifecycle: Arc<AtomicU8>,
    queued: Arc<AtomicUsize>,
    owner: Option<JoinHandle<()>>,
}

impl<Command, Response> std::fmt::Debug for StateOwnerV2<Command, Response> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StateOwnerV2")
            .field("lifecycle", &self.lifecycle.load(Ordering::Acquire))
            .field("queued", &self.queued.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

impl<Command, Response> StateOwnerV2<Command, Response>
where
    Command: Send + 'static,
    Response: Send + 'static,
{
    pub(crate) fn spawn(
        name: &str,
        capacity: usize,
        mut handler: impl FnMut(Command) -> Result<Response, StateOwnerErrorV2> + Send + 'static,
    ) -> Result<Self, StateOwnerErrorV2> {
        Self::spawn_transactional(name, capacity, move |command, _commit| handler(command))
    }

    pub(crate) fn spawn_transactional(
        name: &str,
        capacity: usize,
        handler: impl FnMut(Command, StateOwnerCommitV2) -> Result<Response, StateOwnerErrorV2>
            + Send
            + 'static,
    ) -> Result<Self, StateOwnerErrorV2> {
        Self::spawn_transactional_inner(name, capacity, handler, None)
    }

    #[cfg(test)]
    fn spawn_with_fatal_publication_hook(
        name: &str,
        capacity: usize,
        mut handler: impl FnMut(Command) -> Result<Response, StateOwnerErrorV2> + Send + 'static,
        fatal_publication_hook: impl Fn() + Send + 'static,
    ) -> Result<Self, StateOwnerErrorV2> {
        Self::spawn_transactional_inner(
            name,
            capacity,
            move |command, _commit| handler(command),
            Some(Box::new(fatal_publication_hook)),
        )
    }

    fn spawn_transactional_inner(
        name: &str,
        capacity: usize,
        handler: impl FnMut(Command, StateOwnerCommitV2) -> Result<Response, StateOwnerErrorV2>
            + Send
            + 'static,
        fatal_publication_hook: Option<Box<dyn Fn() + Send + 'static>>,
    ) -> Result<Self, StateOwnerErrorV2> {
        if name.is_empty() || capacity == 0 {
            return Err(StateOwnerErrorV2::RuntimeUnavailable);
        }
        let (sender, receiver) = mpsc::sync_channel(capacity);
        let admission = Arc::new(Mutex::new(Some(sender)));
        let lifecycle = Arc::new(AtomicU8::new(OWNER_RUNNING));
        let queued = Arc::new(AtomicUsize::new(0));
        let owner_admission = Arc::clone(&admission);
        let owner_lifecycle = Arc::clone(&lifecycle);
        let owner_queued = Arc::clone(&queued);
        let owner = thread::Builder::new()
            .name(name.to_owned())
            .spawn(move || {
                owner_loop(
                    receiver,
                    owner_admission,
                    owner_lifecycle,
                    owner_queued,
                    handler,
                    fatal_publication_hook,
                )
            })
            .map_err(|_| StateOwnerErrorV2::RuntimeUnavailable)?;
        Ok(Self {
            admission,
            lifecycle,
            queued,
            owner: Some(owner),
        })
    }

    pub(crate) fn request(
        &self,
        command: Command,
        deadline: Instant,
    ) -> Result<Response, StateOwnerErrorV2> {
        if Instant::now() >= deadline {
            return Err(StateOwnerErrorV2::DeadlineExceeded);
        }
        let mut admission = lock_unpoisoned(&self.admission);
        if self.lifecycle.load(Ordering::Acquire) != OWNER_RUNNING || admission.as_ref().is_none() {
            return Err(StateOwnerErrorV2::RuntimeUnavailable);
        }
        if Instant::now() >= deadline {
            return Err(StateOwnerErrorV2::DeadlineExceeded);
        }
        let completion = Arc::new(RequestCompletionV2::new(deadline));
        self.queued.fetch_add(1, Ordering::AcqRel);
        let send_result = admission
            .as_ref()
            .expect("running admission owns its sender")
            .try_send(OwnerMessageV2::Execute {
                command,
                deadline,
                completion: Arc::clone(&completion),
            });
        match send_result {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                self.queued.fetch_sub(1, Ordering::AcqRel);
                return Err(StateOwnerErrorV2::RuntimeBusy);
            }
            Err(TrySendError::Disconnected(_)) => {
                self.queued.fetch_sub(1, Ordering::AcqRel);
                self.lifecycle.store(OWNER_FAILED, Ordering::Release);
                *admission = None;
                return Err(StateOwnerErrorV2::RuntimeUnavailable);
            }
        }
        drop(admission);
        completion.wait()
    }

    #[cfg(test)]
    pub(crate) fn queued_for_test(&self) -> usize {
        self.queued.load(Ordering::Acquire)
    }
}

impl<Command, Response> Drop for StateOwnerV2<Command, Response> {
    fn drop(&mut self) {
        let sender = {
            let mut admission = lock_unpoisoned(&self.admission);
            if self
                .lifecycle
                .compare_exchange(
                    OWNER_RUNNING,
                    OWNER_CLOSING,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                admission.take()
            } else {
                None
            }
        };
        if let Some(sender) = sender {
            let _ = sender.send(OwnerMessageV2::Shutdown);
        }
        if let Some(owner) = self.owner.take() {
            if owner.join().is_err() {
                self.lifecycle.store(OWNER_FAILED, Ordering::Release);
            }
        }
    }
}

fn owner_loop<Command, Response>(
    receiver: Receiver<OwnerMessageV2<Command, Response>>,
    admission: Arc<Mutex<Option<SyncSender<OwnerMessageV2<Command, Response>>>>>,
    lifecycle: Arc<AtomicU8>,
    queued: Arc<AtomicUsize>,
    mut handler: impl FnMut(Command, StateOwnerCommitV2) -> Result<Response, StateOwnerErrorV2>,
    fatal_publication_hook: Option<Box<dyn Fn() + Send + 'static>>,
) {
    while let Ok(message) = receiver.recv() {
        match message {
            OwnerMessageV2::Execute {
                command,
                deadline,
                completion,
            } => {
                queued.fetch_sub(1, Ordering::AcqRel);
                if lifecycle.load(Ordering::Acquire) != OWNER_RUNNING {
                    completion.complete(Err(StateOwnerErrorV2::RuntimeUnavailable));
                    continue;
                }
                if Instant::now() >= deadline {
                    completion.cancel();
                    continue;
                }
                let commit = completion.commit_handle();
                let result = catch_unwind(AssertUnwindSafe(|| handler(command, commit)))
                    .unwrap_or(Err(StateOwnerErrorV2::RuntimeUnavailable));
                let fatal = matches!(result, Err(StateOwnerErrorV2::RuntimeUnavailable))
                    && !completion.has_durable_recovery();
                if fatal {
                    close_failed_owner_admission(&admission, &lifecycle);
                    completion.complete(result);
                    if let Some(hook) = fatal_publication_hook.as_ref() {
                        hook();
                    }
                    drain_failed_owner_queue(&receiver, &queued);
                    return;
                }
                completion.complete(result);
            }
            OwnerMessageV2::Shutdown => {
                lifecycle.store(OWNER_STOPPED, Ordering::Release);
                return;
            }
        }
    }
    if lifecycle.load(Ordering::Acquire) != OWNER_CLOSING {
        close_failed_owner_admission(&admission, &lifecycle);
        drain_failed_owner_queue(&receiver, &queued);
    }
}

fn close_failed_owner_admission<Command, Response>(
    admission: &Mutex<Option<SyncSender<OwnerMessageV2<Command, Response>>>>,
    lifecycle: &AtomicU8,
) {
    let mut sender = lock_unpoisoned(admission);
    lifecycle.store(OWNER_FAILED, Ordering::Release);
    *sender = None;
}

fn drain_failed_owner_queue<Command, Response>(
    receiver: &Receiver<OwnerMessageV2<Command, Response>>,
    queued: &AtomicUsize,
) {
    while let Ok(message) = receiver.try_recv() {
        match message {
            OwnerMessageV2::Execute { completion, .. } => {
                queued.fetch_sub(1, Ordering::AcqRel);
                completion.complete(Err(StateOwnerErrorV2::RuntimeUnavailable));
            }
            OwnerMessageV2::Shutdown => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{mpsc, Arc, Barrier};
    use std::thread;
    use std::time::{Duration, Instant};

    use super::{StateOwnerErrorV2, StateOwnerV2};

    #[test]
    fn concurrent_callers_never_overlap_the_state_handler() {
        const CALLERS: usize = 128;

        let active = Arc::new(AtomicUsize::new(0));
        let maximum = Arc::new(AtomicUsize::new(0));
        let active_for_handler = Arc::clone(&active);
        let maximum_for_handler = Arc::clone(&maximum);
        let owner = Arc::new(
            StateOwnerV2::spawn("v2-owner-serialization", CALLERS, move |value| {
                let now_active = active_for_handler.fetch_add(1, Ordering::AcqRel) + 1;
                maximum_for_handler.fetch_max(now_active, Ordering::AcqRel);
                thread::yield_now();
                active_for_handler.fetch_sub(1, Ordering::AcqRel);
                Ok(value)
            })
            .unwrap(),
        );
        let barrier = Arc::new(Barrier::new(CALLERS + 1));
        let mut callers = Vec::with_capacity(CALLERS);
        for value in 0..CALLERS {
            let owner = Arc::clone(&owner);
            let barrier = Arc::clone(&barrier);
            callers.push(thread::spawn(move || {
                barrier.wait();
                owner.request(value, Instant::now() + Duration::from_secs(5))
            }));
        }
        barrier.wait();

        let mut observed = Vec::with_capacity(CALLERS);
        for caller in callers {
            observed.push(caller.join().unwrap().unwrap());
        }
        observed.sort_unstable();
        assert_eq!(observed, (0..CALLERS).collect::<Vec<_>>());
        assert_eq!(maximum.load(Ordering::Acquire), 1);
    }

    #[test]
    fn a_full_bounded_queue_rejects_without_running_the_extra_command() {
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let executions = Arc::new(AtomicUsize::new(0));
        let executions_for_handler = Arc::clone(&executions);
        let owner = Arc::new(
            StateOwnerV2::spawn("v2-owner-capacity", 1, move |value| {
                executions_for_handler.fetch_add(1, Ordering::AcqRel);
                if value == 1 {
                    entered_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                }
                Ok(value)
            })
            .unwrap(),
        );

        let first_owner = Arc::clone(&owner);
        let first =
            thread::spawn(move || first_owner.request(1, Instant::now() + Duration::from_secs(5)));
        entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();

        let second_owner = Arc::clone(&owner);
        let second =
            thread::spawn(move || second_owner.request(2, Instant::now() + Duration::from_secs(5)));
        let deadline = Instant::now() + Duration::from_secs(1);
        while owner.queued_for_test() == 0 && Instant::now() < deadline {
            thread::yield_now();
        }

        assert_eq!(
            owner
                .request(3, Instant::now() + Duration::from_secs(1))
                .unwrap_err(),
            StateOwnerErrorV2::RuntimeBusy
        );
        release_tx.send(()).unwrap();
        assert_eq!(first.join().unwrap().unwrap(), 1);
        assert_eq!(second.join().unwrap().unwrap(), 2);
        assert_eq!(executions.load(Ordering::Acquire), 2);
    }

    #[test]
    fn an_expired_command_is_rejected_without_invoking_the_handler() {
        let executions = Arc::new(AtomicUsize::new(0));
        let executions_for_handler = Arc::clone(&executions);
        let owner = StateOwnerV2::spawn("v2-owner-deadline", 1, move |value: u8| {
            executions_for_handler.fetch_add(1, Ordering::AcqRel);
            Ok(value)
        })
        .unwrap();

        assert_eq!(
            owner.request(7, Instant::now()).unwrap_err(),
            StateOwnerErrorV2::DeadlineExceeded
        );
        assert_eq!(executions.load(Ordering::Acquire), 0);
    }

    #[test]
    fn deadline_cancellation_wins_before_commit_and_lost_receiver_cannot_mutate() {
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let (finished_tx, finished_rx) = mpsc::channel();
        let mutations = Arc::new(AtomicUsize::new(0));
        let mutations_for_handler = Arc::clone(&mutations);
        let owner = Arc::new(
            StateOwnerV2::spawn_transactional(
                "v2-owner-cancel-linearization",
                1,
                move |value, commit| {
                    entered_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    let claim = commit.claim();
                    if claim.is_ok() {
                        mutations_for_handler.fetch_add(1, Ordering::AcqRel);
                    }
                    finished_tx.send(claim).unwrap();
                    Ok(value)
                },
            )
            .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_millis(50);
        let requesting = {
            let owner = Arc::clone(&owner);
            thread::spawn(move || owner.request(7_u8, deadline))
        };
        entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(
            requesting.join().unwrap(),
            Err(StateOwnerErrorV2::DeadlineExceeded),
        );
        release_tx.send(()).unwrap();
        assert_eq!(
            finished_rx.recv_timeout(Duration::from_secs(1)).unwrap(),
            Err(StateOwnerErrorV2::DeadlineExceeded),
        );
        assert_eq!(mutations.load(Ordering::Acquire), 0);
        assert_eq!(owner.queued_for_test(), 0);
    }

    #[test]
    fn commit_ownership_wins_before_deadline_and_caller_receives_result_after_deadline() {
        let (release_commit_tx, release_commit_rx) = mpsc::channel();
        let (committed_tx, committed_rx) = mpsc::channel();
        let (release_completion_tx, release_completion_rx) = mpsc::channel();
        let mutations = Arc::new(AtomicUsize::new(0));
        let mutations_for_handler = Arc::clone(&mutations);
        let owner = Arc::new(
            StateOwnerV2::spawn_transactional(
                "v2-owner-commit-linearization",
                1,
                move |value, commit| {
                    release_commit_rx.recv().unwrap();
                    commit.claim()?;
                    mutations_for_handler.fetch_add(1, Ordering::AcqRel);
                    committed_tx.send(()).unwrap();
                    release_completion_rx.recv().unwrap();
                    Ok(value)
                },
            )
            .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_millis(100);
        let requesting = {
            let owner = Arc::clone(&owner);
            thread::spawn(move || owner.request(9_u8, deadline))
        };
        release_commit_tx.send(()).unwrap();
        committed_rx
            .recv_timeout(Duration::from_millis(50))
            .unwrap();
        while Instant::now() < deadline + Duration::from_millis(20) {
            thread::yield_now();
        }
        release_completion_tx.send(()).unwrap();
        assert_eq!(requesting.join().unwrap(), Ok(9));
        assert_eq!(mutations.load(Ordering::Acquire), 1);
        assert_eq!(owner.queued_for_test(), 0);
    }

    #[test]
    fn a_fatal_handler_result_permanently_fails_the_owner() {
        let owner: StateOwnerV2<u8, u8> = StateOwnerV2::spawn("v2-owner-fatal", 1, |_: u8| {
            Err(StateOwnerErrorV2::RuntimeUnavailable)
        })
        .unwrap();

        assert_eq!(
            owner
                .request(1, Instant::now() + Duration::from_secs(1))
                .unwrap_err(),
            StateOwnerErrorV2::RuntimeUnavailable
        );
        assert_eq!(
            owner
                .request(2, Instant::now() + Duration::from_secs(1))
                .unwrap_err(),
            StateOwnerErrorV2::RuntimeUnavailable
        );
    }

    #[test]
    fn fatal_handler_drains_every_already_enqueued_caller_as_runtime_unavailable() {
        let (active_entered_tx, active_entered_rx) = mpsc::channel();
        let (release_active_tx, release_active_rx) = mpsc::channel();
        let owner: Arc<StateOwnerV2<u8, u8>> = Arc::new(
            StateOwnerV2::spawn("v2-owner-fatal-drain", 3, move |value: u8| {
                assert_eq!(
                    value, 1,
                    "queued commands must never execute after fatal exit"
                );
                active_entered_tx.send(()).unwrap();
                release_active_rx.recv().unwrap();
                Err(StateOwnerErrorV2::RuntimeUnavailable)
            })
            .unwrap(),
        );

        let active = {
            let owner = Arc::clone(&owner);
            thread::spawn(move || owner.request(1, Instant::now() + Duration::from_secs(2)))
        };
        active_entered_rx
            .recv_timeout(Duration::from_secs(1))
            .unwrap();

        let queued_deadline = Instant::now() + Duration::from_millis(400);
        let first_queued = {
            let owner = Arc::clone(&owner);
            thread::spawn(move || owner.request(2, queued_deadline))
        };
        let second_queued = {
            let owner = Arc::clone(&owner);
            thread::spawn(move || owner.request(3, queued_deadline))
        };
        let enqueue_deadline = Instant::now() + Duration::from_secs(1);
        while owner.queued_for_test() != 2 && Instant::now() < enqueue_deadline {
            thread::yield_now();
        }
        assert_eq!(owner.queued_for_test(), 2);

        release_active_tx.send(()).unwrap();
        let active_result = active.join().unwrap();
        let first_result = first_queued.join().unwrap();
        let second_result = second_queued.join().unwrap();

        assert_eq!(active_result, Err(StateOwnerErrorV2::RuntimeUnavailable));
        assert_eq!(first_result, Err(StateOwnerErrorV2::RuntimeUnavailable));
        assert_eq!(second_result, Err(StateOwnerErrorV2::RuntimeUnavailable));
        assert_eq!(owner.lifecycle.load(Ordering::Acquire), super::OWNER_FAILED);
        assert_eq!(owner.queued_for_test(), 0);
        assert_eq!(
            owner.request(4, Instant::now() + Duration::from_secs(1)),
            Err(StateOwnerErrorV2::RuntimeUnavailable),
        );
        assert_eq!(owner.queued_for_test(), 0);
    }

    #[test]
    fn fatal_completion_is_not_observable_before_admission_closes() {
        let (hook_entered_tx, hook_entered_rx) = mpsc::channel();
        let (release_hook_tx, release_hook_rx) = mpsc::channel();
        let owner: Arc<StateOwnerV2<u8, u8>> = Arc::new(
            StateOwnerV2::spawn_with_fatal_publication_hook(
                "v2-owner-fatal-publication-order",
                1,
                |_| Err(StateOwnerErrorV2::RuntimeUnavailable),
                move || {
                    hook_entered_tx.send(()).unwrap();
                    release_hook_rx.recv().unwrap();
                },
            )
            .unwrap(),
        );

        let active = {
            let owner = Arc::clone(&owner);
            thread::spawn(move || owner.request(1, Instant::now() + Duration::from_secs(1)))
        };
        hook_entered_rx
            .recv_timeout(Duration::from_secs(1))
            .unwrap();
        assert_eq!(
            active.join().unwrap(),
            Err(StateOwnerErrorV2::RuntimeUnavailable),
        );

        let late_result = owner.request(2, Instant::now() + Duration::from_millis(50));
        release_hook_tx.send(()).unwrap();
        let drain_deadline = Instant::now() + Duration::from_secs(1);
        while owner.queued_for_test() != 0 && Instant::now() < drain_deadline {
            thread::yield_now();
        }

        assert_eq!(late_result, Err(StateOwnerErrorV2::RuntimeUnavailable));
        assert_eq!(owner.lifecycle.load(Ordering::Acquire), super::OWNER_FAILED);
        assert_eq!(owner.queued_for_test(), 0);
    }

    #[test]
    fn panic_before_commit_claim_fails_closed_and_permanently_stops_the_owner() {
        let owner: StateOwnerV2<u8, u8> =
            StateOwnerV2::spawn_transactional("v2-owner-panic-before-claim", 1, |_, _| {
                panic!("injected preclaim panic")
            })
            .unwrap();

        assert_eq!(
            owner.request(1, Instant::now() + Duration::from_secs(1)),
            Err(StateOwnerErrorV2::RuntimeUnavailable),
        );
        assert_eq!(
            owner.request(2, Instant::now() + Duration::from_secs(1)),
            Err(StateOwnerErrorV2::RuntimeUnavailable),
        );
    }

    #[test]
    fn panic_after_claim_without_durable_completion_remains_fail_stop() {
        let owner: StateOwnerV2<u8, u8> =
            StateOwnerV2::spawn_transactional("v2-owner-panic-after-claim", 1, |_, commit| {
                commit.claim()?;
                panic!("injected panic before durable completion")
            })
            .unwrap();

        assert_eq!(
            owner.request(1, Instant::now() + Duration::from_secs(1)),
            Err(StateOwnerErrorV2::RuntimeUnavailable),
        );
        assert_eq!(
            owner.request(2, Instant::now() + Duration::from_secs(1)),
            Err(StateOwnerErrorV2::RuntimeUnavailable),
        );
    }
}
