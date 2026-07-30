use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Instant;

const OWNER_RUNNING: u8 = 1;
const OWNER_CLOSING: u8 = 2;
const OWNER_FAILED: u8 = 3;
const OWNER_STOPPED: u8 = 4;

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
        response: SyncSender<Result<Response, StateOwnerErrorV2>>,
    },
    Shutdown,
}

pub(crate) struct StateOwnerV2<Command, Response> {
    sender: SyncSender<OwnerMessageV2<Command, Response>>,
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
        handler: impl FnMut(Command) -> Result<Response, StateOwnerErrorV2> + Send + 'static,
    ) -> Result<Self, StateOwnerErrorV2> {
        if name.is_empty() || capacity == 0 {
            return Err(StateOwnerErrorV2::RuntimeUnavailable);
        }
        let (sender, receiver) = mpsc::sync_channel(capacity);
        let lifecycle = Arc::new(AtomicU8::new(OWNER_RUNNING));
        let queued = Arc::new(AtomicUsize::new(0));
        let owner_lifecycle = Arc::clone(&lifecycle);
        let owner_queued = Arc::clone(&queued);
        let owner = thread::Builder::new()
            .name(name.to_owned())
            .spawn(move || owner_loop(receiver, owner_lifecycle, owner_queued, handler))
            .map_err(|_| StateOwnerErrorV2::RuntimeUnavailable)?;
        Ok(Self {
            sender,
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
        if self.lifecycle.load(Ordering::Acquire) != OWNER_RUNNING {
            return Err(StateOwnerErrorV2::RuntimeUnavailable);
        }
        let (response, received) = mpsc::sync_channel(1);
        self.queued.fetch_add(1, Ordering::AcqRel);
        match self.sender.try_send(OwnerMessageV2::Execute {
            command,
            deadline,
            response,
        }) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                self.queued.fetch_sub(1, Ordering::AcqRel);
                return Err(StateOwnerErrorV2::RuntimeBusy);
            }
            Err(TrySendError::Disconnected(_)) => {
                self.queued.fetch_sub(1, Ordering::AcqRel);
                self.lifecycle.store(OWNER_FAILED, Ordering::Release);
                return Err(StateOwnerErrorV2::RuntimeUnavailable);
            }
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(StateOwnerErrorV2::DeadlineExceeded);
        }
        match received.recv_timeout(remaining) {
            Ok(result) => result,
            Err(RecvTimeoutError::Timeout) => Err(StateOwnerErrorV2::DeadlineExceeded),
            Err(RecvTimeoutError::Disconnected) => {
                self.lifecycle.store(OWNER_FAILED, Ordering::Release);
                Err(StateOwnerErrorV2::RuntimeUnavailable)
            }
        }
    }

    #[cfg(test)]
    fn queued_for_test(&self) -> usize {
        self.queued.load(Ordering::Acquire)
    }
}

impl<Command, Response> Drop for StateOwnerV2<Command, Response> {
    fn drop(&mut self) {
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
            let _ = self.sender.send(OwnerMessageV2::Shutdown);
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
    lifecycle: Arc<AtomicU8>,
    queued: Arc<AtomicUsize>,
    mut handler: impl FnMut(Command) -> Result<Response, StateOwnerErrorV2>,
) {
    while let Ok(message) = receiver.recv() {
        match message {
            OwnerMessageV2::Execute {
                command,
                deadline,
                response,
            } => {
                queued.fetch_sub(1, Ordering::AcqRel);
                if lifecycle.load(Ordering::Acquire) != OWNER_RUNNING {
                    let _ = response.send(Err(StateOwnerErrorV2::RuntimeUnavailable));
                    continue;
                }
                if Instant::now() >= deadline {
                    let _ = response.send(Err(StateOwnerErrorV2::DeadlineExceeded));
                    continue;
                }
                let result = catch_unwind(AssertUnwindSafe(|| handler(command)))
                    .unwrap_or(Err(StateOwnerErrorV2::RuntimeUnavailable));
                let fatal = matches!(result, Err(StateOwnerErrorV2::RuntimeUnavailable));
                let _ = response.send(result);
                if fatal {
                    lifecycle.store(OWNER_FAILED, Ordering::Release);
                    return;
                }
            }
            OwnerMessageV2::Shutdown => {
                lifecycle.store(OWNER_STOPPED, Ordering::Release);
                return;
            }
        }
    }
    if lifecycle.load(Ordering::Acquire) != OWNER_CLOSING {
        lifecycle.store(OWNER_FAILED, Ordering::Release);
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
}
