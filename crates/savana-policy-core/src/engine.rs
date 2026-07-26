use std::sync::{Arc, RwLock};

use savana_kernel_protocol::{BootId, StableCode};

use crate::current_policy::AcceptedCurrentPolicy;
use crate::runtime::{AuthenticatedCallContext, AuthenticatedContextIssuer, Clock, RandomSource};
use crate::{CurrentPolicyCapability, PolicyError};

mod ingress;
mod rollover;

#[allow(dead_code)]
pub struct PolicyEngine {
    inner: Arc<EngineInner>,
}

#[allow(dead_code)]
pub(crate) struct EngineInner {
    pub(crate) state: RwLock<EngineState>,
    pub(crate) clock: Arc<dyn Clock + Send + Sync>,
    pub(crate) random: Arc<dyn RandomSource + Send + Sync>,
    pub(crate) boot_id: BootId,
    pub(crate) instance_tag: [u8; 32],
    #[cfg(test)]
    bind_pre_state_lock_hook: std::sync::Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

#[allow(dead_code)]
pub(crate) struct EngineState {
    pub(crate) current: AcceptedCurrentPolicy,
    pub(crate) generation: u64,
    pub(crate) last_monotonic_ms: u64,
    pub(crate) poisoned: bool,
}

impl PolicyEngine {
    pub fn new(
        current: CurrentPolicyCapability,
        boot_id: BootId,
        clock: Arc<dyn Clock + Send + Sync>,
        random: Arc<dyn RandomSource + Send + Sync>,
    ) -> Result<(Self, AuthenticatedContextIssuer), PolicyError> {
        let mut instance_tag = [0_u8; 32];
        let written = random.fill(&mut instance_tag).map_err(|_| unavailable())?;
        if written != instance_tag.len() || instance_tag == [0; 32] {
            return Err(unavailable());
        }
        let initial_monotonic = clock.monotonic_now_millis().map_err(|_| unavailable())?;
        let accepted = current.into_accepted();
        let inner = Arc::new(EngineInner::new(
            accepted,
            boot_id,
            clock,
            random,
            instance_tag,
            initial_monotonic,
        )?);
        let issuer = AuthenticatedContextIssuer {
            engine: Arc::downgrade(&inner),
            instance_tag,
        };
        Ok((Self { inner }, issuer))
    }
}

impl EngineInner {
    fn new(
        current: AcceptedCurrentPolicy,
        boot_id: BootId,
        clock: Arc<dyn Clock + Send + Sync>,
        random: Arc<dyn RandomSource + Send + Sync>,
        instance_tag: [u8; 32],
        initial_monotonic: u64,
    ) -> Result<Self, PolicyError> {
        Ok(Self {
            state: RwLock::new(EngineState {
                current,
                generation: 0,
                last_monotonic_ms: initial_monotonic,
                poisoned: false,
            }),
            clock,
            random,
            boot_id,
            instance_tag,
            #[cfg(test)]
            bind_pre_state_lock_hook: std::sync::Mutex::new(None),
        })
    }

    #[cfg(test)]
    pub(crate) fn install_bind_pre_state_lock_hook(&self, hook: Box<dyn FnOnce() + Send>) {
        let mut installed = self.bind_pre_state_lock_hook.lock().unwrap();
        assert!(installed.is_none(), "bind pre-state-lock hook already set");
        *installed = Some(hook);
    }

    #[cfg(test)]
    pub(crate) fn run_bind_pre_state_lock_hook(&self) {
        let hook = self.bind_pre_state_lock_hook.lock().unwrap().take();
        if let Some(hook) = hook {
            hook();
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn validate_context(
        &self,
        context: &AuthenticatedCallContext,
    ) -> Result<(), PolicyError> {
        let mut state = self.state.write().map_err(|_| unavailable())?;
        if state.poisoned {
            return Err(unavailable());
        }
        let monotonic = self
            .clock
            .monotonic_now_millis()
            .map_err(|_| unavailable())?;
        let wall = self.clock.wall_now().map_err(|_| unavailable())?;
        state.observe_monotonic(monotonic)?;
        let current = state.current.policy.identity();
        if wall.get() >= current.expires_at.get() {
            return Err(policy_expired());
        }
        if context.instance_tag != self.instance_tag
            || context.boot_id != self.boot_id
            || context.policy_identity != current
        {
            return Err(binding_mismatch());
        }
        if monotonic >= context.monotonic_deadline_ms {
            return Err(deadline_exceeded());
        }
        Ok(())
    }
}

impl EngineState {
    pub(crate) fn observe_monotonic(&mut self, monotonic: u64) -> Result<(), PolicyError> {
        if self.poisoned || monotonic < self.last_monotonic_ms {
            return Err(unavailable());
        }
        self.last_monotonic_ms = monotonic;
        Ok(())
    }
}

pub(crate) fn unavailable() -> PolicyError {
    PolicyError::stable(StableCode::KernelUnavailable)
}

pub(crate) fn binding_mismatch() -> PolicyError {
    PolicyError::stable(StableCode::AttestationBindingMismatch)
}

pub(crate) fn deadline_exceeded() -> PolicyError {
    PolicyError::stable(StableCode::DeadlineExceeded)
}

pub(crate) fn policy_expired() -> PolicyError {
    PolicyError::stable(StableCode::PolicyExpired)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::{AuthenticatedContextIssuer, Clock};
    use crate::test_support;
    use savana_kernel_protocol::{BootId, ClientId, Digest32, Nonce32, StableCode, UnixMillis};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{mpsc, Arc};
    use std::time::Duration;

    struct Fixture {
        engine: PolicyEngine,
        issuer: AuthenticatedContextIssuer,
        clock: Arc<test_support::TestClock>,
        identity: crate::PolicyIdentity,
        boot_id: BootId,
    }

    fn fixture() -> Fixture {
        static NEXT_TAG: AtomicU64 = AtomicU64::new(1);
        let (current, identity) = test_support::current_policy_and_identity();
        let clock = test_support::clock();
        let boot_id = BootId::new([0x41; 32]);
        let tag = NEXT_TAG.fetch_add(1, Ordering::SeqCst) as u8;
        let (engine, issuer) = PolicyEngine::new(
            current,
            boot_id,
            Arc::clone(&clock) as Arc<dyn Clock + Send + Sync>,
            test_support::random(test_support::RandomBehavior::Filled(tag)),
        )
        .unwrap();
        Fixture {
            engine,
            issuer,
            clock,
            identity,
            boot_id,
        }
    }

    fn bind(
        issuer: &AuthenticatedContextIssuer,
        identity: crate::PolicyIdentity,
        boot_id: BootId,
        deadline: u64,
    ) -> Result<crate::AuthenticatedCallContext, crate::PolicyError> {
        issuer.bind(
            ClientId::new("client-a").unwrap(),
            Nonce32::new([0x22; 32]),
            Digest32::new([0x33; 32]),
            identity,
            boot_id,
            501,
            UnixMillis::new(deadline),
        )
    }

    #[test]
    fn issuer_rejects_wrong_boot_policy_engine_and_deadline() {
        let first = fixture();
        let second = fixture();
        let valid = bind(
            &first.issuer,
            first.identity,
            first.boot_id,
            first.clock.now() + 1_000,
        )
        .unwrap();
        assert_eq!(
            second
                .engine
                .inner
                .validate_context(&valid)
                .unwrap_err()
                .code(),
            StableCode::AttestationBindingMismatch
        );
        assert_eq!(
            bind(
                &first.issuer,
                first.identity,
                BootId::new([0x99; 32]),
                first.clock.now() + 1_000,
            )
            .unwrap_err()
            .code(),
            StableCode::AttestationBindingMismatch
        );
        assert_eq!(
            bind(
                &first.issuer,
                crate::PolicyIdentity {
                    digest: Digest32::new([0x77; 32]),
                    ..second.identity
                },
                first.boot_id,
                first.clock.now() + 1_000,
            )
            .unwrap_err()
            .code(),
            StableCode::AttestationBindingMismatch
        );
        assert_eq!(
            bind(
                &first.issuer,
                first.identity,
                first.boot_id,
                first.clock.now(),
            )
            .unwrap_err()
            .code(),
            StableCode::DeadlineExceeded
        );
        assert_eq!(
            bind(
                &first.issuer,
                first.identity,
                first.boot_id,
                first.clock.now() + 120_001,
            )
            .unwrap_err()
            .code(),
            StableCode::DeadlineExceeded
        );
    }

    #[test]
    fn dependency_errors_and_monotonic_regression_are_unavailable() {
        let fixture = fixture();
        fixture.clock.fail_wall();
        assert_eq!(
            bind(
                &fixture.issuer,
                fixture.identity,
                fixture.boot_id,
                fixture.clock.now() + 1,
            )
            .unwrap_err()
            .code(),
            StableCode::KernelUnavailable
        );
        fixture.clock.restore_wall_and_regress_monotonic();
        assert_eq!(
            bind(
                &fixture.issuer,
                fixture.identity,
                fixture.boot_id,
                fixture.clock.now() + 1,
            )
            .unwrap_err()
            .code(),
            StableCode::KernelUnavailable
        );
    }

    struct BlockingFirstBindClock {
        calls: AtomicU64,
        first_entered: mpsc::SyncSender<()>,
        release_first: std::sync::Mutex<mpsc::Receiver<()>>,
        later_monotonic_entered: mpsc::SyncSender<()>,
        wall_entered: mpsc::SyncSender<()>,
    }

    impl Clock for BlockingFirstBindClock {
        fn wall_now(&self) -> Result<UnixMillis, StableCode> {
            self.wall_entered.send(()).unwrap();
            Ok(UnixMillis::new(2_000))
        }

        fn monotonic_now_millis(&self) -> Result<u64, StableCode> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            match call {
                0 => Ok(100),
                1 => {
                    self.first_entered.send(()).unwrap();
                    self.release_first
                        .lock()
                        .unwrap()
                        .recv_timeout(Duration::from_secs(2))
                        .expect("first clock read release timed out");
                    Ok(100)
                }
                _ => {
                    self.later_monotonic_entered.send(()).unwrap();
                    Ok(101)
                }
            }
        }
    }

    #[test]
    fn concurrent_monotonic_observations_are_serialized_not_false_regressions() {
        let (first_entered_tx, first_entered_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let (later_monotonic_entered_tx, later_monotonic_entered_rx) = mpsc::sync_channel(1);
        let (wall_entered_tx, wall_entered_rx) = mpsc::sync_channel(2);
        let clock = Arc::new(BlockingFirstBindClock {
            calls: AtomicU64::new(0),
            first_entered: first_entered_tx,
            release_first: std::sync::Mutex::new(release_rx),
            later_monotonic_entered: later_monotonic_entered_tx,
            wall_entered: wall_entered_tx,
        });
        let (current, identity) = test_support::current_policy_and_identity();
        let boot_id = BootId::new([0x41; 32]);
        let (engine, issuer) = PolicyEngine::new(
            current,
            boot_id,
            Arc::clone(&clock) as Arc<dyn Clock + Send + Sync>,
            test_support::random(test_support::RandomBehavior::Full),
        )
        .unwrap();
        let engine = Arc::new(engine);
        let issuer = Arc::new(issuer);

        let first_issuer = Arc::clone(&issuer);
        let first = std::thread::spawn(move || bind(&first_issuer, identity, boot_id, 3_000));
        first_entered_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("first clock read never blocked");

        let (second_pre_lock_tx, second_pre_lock_rx) = mpsc::sync_channel(1);
        engine
            .inner
            .install_bind_pre_state_lock_hook(Box::new(move || {
                second_pre_lock_tx.send(()).unwrap();
            }));
        let second_issuer = Arc::clone(&issuer);
        let second = std::thread::spawn(move || bind(&second_issuer, identity, boot_id, 3_000));
        second_pre_lock_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("second bind never reached the pre-state-lock hook");
        assert!(
            later_monotonic_entered_rx.try_recv().is_err(),
            "second monotonic read entered before the first released engine state"
        );
        assert!(
            wall_entered_rx.try_recv().is_err(),
            "wall clock entered before the first released engine state"
        );
        release_tx.send(()).unwrap();
        assert!(first.join().unwrap().is_ok());
        assert!(second.join().unwrap().is_ok());
        drop(engine);
    }
}
