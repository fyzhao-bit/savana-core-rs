use std::fmt;
use std::sync::Weak;

use savana_kernel_protocol::{BootId, ClientId, Digest32, Nonce32, StableCode, UnixMillis};

use crate::engine::{
    binding_mismatch, deadline_exceeded, policy_expired, unavailable, EngineInner,
};
use crate::{PolicyError, PolicyIdentity};

pub trait Clock: Send + Sync {
    fn wall_now(&self) -> Result<UnixMillis, StableCode>;
    fn monotonic_now_millis(&self) -> Result<u64, StableCode>;
}

pub trait RandomSource: Send + Sync {
    fn fill(&self, output: &mut [u8]) -> Result<usize, StableCode>;
}

pub struct AuthenticatedContextIssuer {
    pub(crate) engine: Weak<EngineInner>,
    pub(crate) instance_tag: [u8; 32],
}

#[allow(dead_code)]
pub struct AuthenticatedCallContext {
    pub(crate) client_id: ClientId,
    pub(crate) connection_id: Nonce32,
    pub(crate) connection_binding_digest: Digest32,
    pub(crate) policy_identity: PolicyIdentity,
    pub(crate) boot_id: BootId,
    pub(crate) peer_uid: u32,
    pub(crate) monotonic_deadline_ms: u64,
    pub(crate) instance_tag: [u8; 32],
}

impl fmt::Debug for AuthenticatedContextIssuer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthenticatedContextIssuer(<bound>)")
    }
}

impl fmt::Debug for AuthenticatedCallContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthenticatedCallContext(<authenticated>)")
    }
}

impl AuthenticatedContextIssuer {
    #[allow(clippy::too_many_arguments)]
    pub fn bind(
        &self,
        client_id: ClientId,
        connection_id: Nonce32,
        connection_binding_digest: Digest32,
        handshake_policy: PolicyIdentity,
        connection_boot_id: BootId,
        peer_uid: u32,
        request_deadline: UnixMillis,
    ) -> Result<AuthenticatedCallContext, PolicyError> {
        let engine = self.engine.upgrade().ok_or_else(unavailable)?;
        if self.instance_tag != engine.instance_tag
            || connection_boot_id != engine.boot_id
            || connection_id.as_bytes() == &[0; 32]
            || connection_binding_digest.as_bytes() == &[0; 32]
        {
            return Err(binding_mismatch());
        }

        #[cfg(test)]
        engine.run_bind_pre_state_lock_hook();
        let mut state = engine.state.write().map_err(|_| unavailable())?;
        let monotonic = engine
            .clock
            .monotonic_now_millis()
            .map_err(|_| unavailable())?;
        let wall = engine.clock.wall_now().map_err(|_| unavailable())?;
        state.observe_monotonic(monotonic)?;

        let current = state.current.policy.identity();
        if wall.get() >= current.expires_at.get() {
            return Err(policy_expired());
        }
        if handshake_policy != current {
            return Err(binding_mismatch());
        }
        if request_deadline.get() > current.expires_at.get() {
            return Err(deadline_exceeded());
        }
        let remaining = request_deadline
            .get()
            .checked_sub(wall.get())
            .filter(|remaining| *remaining > 0)
            .ok_or_else(deadline_exceeded)?;
        if remaining
            > state
                .current
                .policy
                .effective_limits()
                .request_deadline_ms()
        {
            return Err(deadline_exceeded());
        }
        let monotonic_deadline_ms = monotonic.checked_add(remaining).ok_or_else(unavailable)?;

        Ok(AuthenticatedCallContext {
            client_id,
            connection_id,
            connection_binding_digest,
            policy_identity: current,
            boot_id: engine.boot_id,
            peer_uid,
            monotonic_deadline_ms,
            instance_tag: engine.instance_tag,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::engine::PolicyEngine;
    use crate::runtime::{AuthenticatedContextIssuer, Clock};
    use crate::test_support;
    use savana_kernel_protocol::{BootId, ClientId, Digest32, Nonce32, StableCode, UnixMillis};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{mpsc, Arc};
    use std::time::Duration;

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
    fn bind_waiting_for_engine_state_cannot_cross_policy_expiry() {
        let (current, identity) = test_support::current_policy_and_identity();
        let clock = Arc::new(ManualClock::new(2_000, 100));
        let boot_id = BootId::new([0x41; 32]);
        let (_engine, issuer) = PolicyEngine::new(
            current,
            boot_id,
            Arc::clone(&clock) as Arc<dyn Clock + Send + Sync>,
            test_support::random(test_support::RandomBehavior::Full),
        )
        .unwrap();
        let inner = issuer.engine.upgrade().unwrap();
        let state = inner.state.write().unwrap();
        let (pre_lock_tx, pre_lock_rx) = mpsc::sync_channel(1);
        inner.install_bind_pre_state_lock_hook(Box::new(move || {
            pre_lock_tx.send(()).unwrap();
        }));
        let waiting = std::thread::spawn(move || bind(&issuer, identity, boot_id, 4_000));
        pre_lock_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("waiting bind never reached the pre-state-lock hook");
        clock.set(4_000, 2_100);
        drop(state);
        assert_eq!(
            waiting.join().unwrap().unwrap_err().code(),
            StableCode::PolicyExpired
        );
    }

    #[test]
    fn bind_lock_wait_never_extends_the_caller_deadline() {
        let (current, identity) = test_support::current_policy_and_identity();
        let clock = Arc::new(ManualClock::new(2_000, 100));
        let boot_id = BootId::new([0x41; 32]);
        let (_engine, issuer) = PolicyEngine::new(
            current,
            boot_id,
            Arc::clone(&clock) as Arc<dyn Clock + Send + Sync>,
            test_support::random(test_support::RandomBehavior::Full),
        )
        .unwrap();
        let inner = issuer.engine.upgrade().unwrap();
        let state = inner.state.write().unwrap();
        let (pre_lock_tx, pre_lock_rx) = mpsc::sync_channel(1);
        inner.install_bind_pre_state_lock_hook(Box::new(move || {
            pre_lock_tx.send(()).unwrap();
        }));
        let waiting = std::thread::spawn(move || bind(&issuer, identity, boot_id, 2_200));
        pre_lock_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("waiting bind never reached the pre-state-lock hook");
        clock.set(2_201, 301);
        drop(state);
        assert_eq!(
            waiting.join().unwrap().unwrap_err().code(),
            StableCode::DeadlineExceeded
        );
    }

    struct ManualClock {
        wall: AtomicU64,
        monotonic: AtomicU64,
    }

    impl ManualClock {
        const fn new(wall: u64, monotonic: u64) -> Self {
            Self {
                wall: AtomicU64::new(wall),
                monotonic: AtomicU64::new(monotonic),
            }
        }

        fn set(&self, wall: u64, monotonic: u64) {
            self.wall.store(wall, Ordering::SeqCst);
            self.monotonic.store(monotonic, Ordering::SeqCst);
        }
    }

    impl Clock for ManualClock {
        fn wall_now(&self) -> Result<UnixMillis, StableCode> {
            Ok(UnixMillis::new(self.wall.load(Ordering::SeqCst)))
        }

        fn monotonic_now_millis(&self) -> Result<u64, StableCode> {
            Ok(self.monotonic.load(Ordering::SeqCst))
        }
    }

    struct PausingWallClock {
        wall: AtomicU64,
        monotonic: AtomicU64,
        wall_entered: mpsc::SyncSender<()>,
        release_wall: std::sync::Mutex<mpsc::Receiver<()>>,
    }

    impl Clock for PausingWallClock {
        fn wall_now(&self) -> Result<UnixMillis, StableCode> {
            self.wall_entered.send(()).unwrap();
            self.release_wall
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(2))
                .expect("wall release timed out");
            Ok(UnixMillis::new(self.wall.load(Ordering::SeqCst)))
        }

        fn monotonic_now_millis(&self) -> Result<u64, StableCode> {
            Ok(self.monotonic.load(Ordering::SeqCst))
        }
    }

    #[test]
    fn bind_interclock_pause_can_only_shorten_the_deadline() {
        let (wall_entered_tx, wall_entered_rx) = mpsc::sync_channel(1);
        let (release_wall_tx, release_wall_rx) = mpsc::sync_channel(1);
        let clock = Arc::new(PausingWallClock {
            wall: AtomicU64::new(1_000),
            monotonic: AtomicU64::new(100),
            wall_entered: wall_entered_tx,
            release_wall: std::sync::Mutex::new(release_wall_rx),
        });
        let (current, identity) = test_support::current_policy_and_identity();
        let boot_id = BootId::new([0x41; 32]);
        let (_engine, issuer) = PolicyEngine::new(
            current,
            boot_id,
            Arc::clone(&clock) as Arc<dyn Clock + Send + Sync>,
            test_support::random(test_support::RandomBehavior::Full),
        )
        .unwrap();
        let binding = std::thread::spawn(move || bind(&issuer, identity, boot_id, 1_200));
        wall_entered_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("wall call never blocked");
        clock.wall.store(1_100, Ordering::SeqCst);
        clock.monotonic.store(200, Ordering::SeqCst);
        release_wall_tx.send(()).unwrap();
        let context = binding.join().unwrap().unwrap();
        assert_eq!(context.monotonic_deadline_ms, 200);
    }
}
