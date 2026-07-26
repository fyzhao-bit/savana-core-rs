use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use nix::sys::signal::{SigSet, SigmaskHow, Signal};
use savana_kernel_protocol::StableCode;
use signal_hook::consts::signal::{SIGINT, SIGPIPE, SIGTERM};
use signal_hook::iterator::Signals;
use signal_hook::{flag as signal_flag, low_level, SigId};

use crate::audit::ShutdownReason;
use crate::server::ServerLifecycle;

#[derive(Clone, Copy, PartialEq, Eq)]
enum MaskState {
    Blocked,
    Unblocked,
    RestoreAttempted,
}

pub(crate) struct SignalMaskGuard {
    previous: SigSet,
    shutdown: SigSet,
    state: MaskState,
}

impl std::fmt::Debug for SignalMaskGuard {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SignalMaskGuard(<restorable>)")
    }
}

impl SignalMaskGuard {
    pub(crate) fn block_shutdown() -> Result<Self, StableCode> {
        let mut shutdown = SigSet::empty();
        shutdown.add(Signal::SIGTERM);
        shutdown.add(Signal::SIGINT);
        let previous = shutdown
            .thread_swap_mask(SigmaskHow::SIG_BLOCK)
            .map_err(|_| StableCode::KernelUnavailable)?;
        Ok(Self {
            previous,
            shutdown,
            state: MaskState::Blocked,
        })
    }

    pub(crate) fn unblock_shutdown(&mut self) -> Result<(), StableCode> {
        if self.state != MaskState::Blocked {
            return Err(StableCode::KernelUnavailable);
        }
        self.shutdown
            .thread_unblock()
            .map_err(|_| StableCode::KernelUnavailable)?;
        self.state = MaskState::Unblocked;
        Ok(())
    }

    pub(crate) fn restore(&mut self) -> Result<(), StableCode> {
        if self.state == MaskState::RestoreAttempted {
            return Err(StableCode::KernelUnavailable);
        }
        self.state = MaskState::RestoreAttempted;
        self.previous
            .thread_set_mask()
            .map_err(|_| StableCode::KernelUnavailable)
    }

    fn restore_if_needed(&mut self) -> Result<(), StableCode> {
        if self.state == MaskState::RestoreAttempted {
            Ok(())
        } else {
            self.restore()
        }
    }
}

impl Drop for SignalMaskGuard {
    fn drop(&mut self) {
        if self.state != MaskState::RestoreAttempted {
            self.state = MaskState::RestoreAttempted;
            let _ = self.previous.thread_set_mask();
        }
    }
}

pub(crate) struct SigpipeGuard {
    registration: Option<SigId>,
    _flag: Arc<AtomicBool>,
}

impl std::fmt::Debug for SigpipeGuard {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SigpipeGuard(<registered>)")
    }
}

impl SigpipeGuard {
    pub(crate) fn install() -> Result<Self, StableCode> {
        let flag = Arc::new(AtomicBool::new(false));
        let registration = signal_flag::register(SIGPIPE, Arc::clone(&flag))
            .map_err(|_| StableCode::KernelUnavailable)?;
        Ok(Self {
            registration: Some(registration),
            _flag: flag,
        })
    }

    pub(crate) fn unregister(&mut self) -> Result<(), StableCode> {
        match self.registration.take() {
            Some(registration) if low_level::unregister(registration) => Ok(()),
            Some(_) | None => Err(StableCode::KernelUnavailable),
        }
    }
}

impl Drop for SigpipeGuard {
    fn drop(&mut self) {
        if let Some(registration) = self.registration.take() {
            let _ = low_level::unregister(registration);
        }
    }
}

pub(crate) struct SignalController {
    signals: Option<Signals>,
    mask: SignalMaskGuard,
    sigpipe: SigpipeGuard,
    reason: Option<ShutdownReason>,
}

impl std::fmt::Debug for SignalController {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SignalController(<private>)")
    }
}

impl SignalController {
    pub(crate) fn install(
        mask: SignalMaskGuard,
        sigpipe: SigpipeGuard,
    ) -> Result<Self, (StableCode, SignalMaskGuard, SigpipeGuard)> {
        if mask.state != MaskState::Blocked {
            return Err((StableCode::KernelUnavailable, mask, sigpipe));
        }
        let signals = match Signals::new([SIGTERM, SIGINT]) {
            Ok(signals) => signals,
            Err(_) => return Err((StableCode::KernelUnavailable, mask, sigpipe)),
        };
        Ok(Self {
            signals: Some(signals),
            mask,
            sigpipe,
            reason: None,
        })
    }

    pub(crate) const fn shutdown_reason(&self) -> Option<ShutdownReason> {
        self.reason
    }

    pub(crate) fn final_drain_and_restore(&mut self) -> Result<(), StableCode> {
        self.drain()?;
        self.mask.restore()
    }

    pub(crate) fn unregister(mut self) -> Result<(), StableCode> {
        if self.mask.state != MaskState::RestoreAttempted {
            return Err(StableCode::KernelUnavailable);
        }
        drop(self.signals.take());
        self.sigpipe.unregister()
    }

    fn drain(&mut self) -> Result<(), StableCode> {
        let signals = self.signals.as_mut().ok_or(StableCode::KernelUnavailable)?;
        let mut saw_term = false;
        let mut saw_int = false;
        for signal in signals.pending() {
            match signal {
                SIGTERM => saw_term = true,
                SIGINT => saw_int = true,
                _ => return Err(StableCode::KernelUnavailable),
            }
        }
        if self.reason.is_none() {
            self.reason = if saw_term {
                Some(ShutdownReason::Sigterm)
            } else if saw_int {
                Some(ShutdownReason::Sigint)
            } else {
                None
            };
        }
        Ok(())
    }
}

impl ServerLifecycle for SignalController {
    fn workers_started(&mut self) -> Result<(), StableCode> {
        self.mask.unblock_shutdown()
    }

    fn poll_shutdown(&mut self) -> Result<bool, StableCode> {
        self.drain()?;
        Ok(self.reason.is_some())
    }
}

impl Drop for SignalController {
    fn drop(&mut self) {
        let _ = self.mask.restore_if_needed();
        drop(self.signals.take());
        if let Some(registration) = self.sigpipe.registration.take() {
            let _ = low_level::unregister(registration);
        }
    }
}

#[cfg(test)]
static PROCESS_SIGNAL_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;
    use nix::sys::signal::{SigSet, Signal};

    #[test]
    fn mask_is_blocked_unblocked_and_restored_exactly() {
        let _process_guard = PROCESS_SIGNAL_TEST_LOCK.lock().unwrap();
        let before = SigSet::thread_get_mask().unwrap();
        let mut guard = SignalMaskGuard::block_shutdown().unwrap();
        let blocked = SigSet::thread_get_mask().unwrap();
        assert!(blocked.contains(Signal::SIGTERM));
        assert!(blocked.contains(Signal::SIGINT));

        guard.unblock_shutdown().unwrap();
        let unblocked = SigSet::thread_get_mask().unwrap();
        assert!(!unblocked.contains(Signal::SIGTERM));
        assert!(!unblocked.contains(Signal::SIGINT));

        guard.restore().unwrap();
        assert_eq!(SigSet::thread_get_mask().unwrap(), before);
    }

    #[test]
    fn pending_term_wins_and_the_first_shutdown_reason_is_frozen() {
        let _process_guard = PROCESS_SIGNAL_TEST_LOCK.lock().unwrap();
        let before = SigSet::thread_get_mask().unwrap();
        let mask = SignalMaskGuard::block_shutdown().unwrap();
        let sigpipe = SigpipeGuard::install().unwrap();
        let mut controller = SignalController::install(mask, sigpipe).unwrap();

        signal_hook::low_level::raise(SIGINT).unwrap();
        signal_hook::low_level::raise(SIGTERM).unwrap();
        controller.workers_started().unwrap();
        assert!(controller.poll_shutdown().unwrap());
        assert!(matches!(
            controller.shutdown_reason(),
            Some(ShutdownReason::Sigterm)
        ));

        signal_hook::low_level::raise(SIGINT).unwrap();
        assert!(controller.poll_shutdown().unwrap());
        assert!(matches!(
            controller.shutdown_reason(),
            Some(ShutdownReason::Sigterm)
        ));

        controller.final_drain_and_restore().unwrap();
        assert_eq!(SigSet::thread_get_mask().unwrap(), before);
        controller.unregister().unwrap();
    }
}
