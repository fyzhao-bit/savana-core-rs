use std::sync::{Arc, Condvar, Mutex, RwLock};

use savana_kernel_protocol::{Digest32, EffectiveLimits, StableCode};
use savana_policy_core::{
    AuthenticatedContextIssuer, PolicyEngine, PolicyIdentity, VerifiedPolicyV1,
};

use crate::handshake::RuntimeIdentity;
use crate::DaemonConfig;

#[derive(Clone)]
pub(crate) struct DaemonPolicyRuntimeSnapshot {
    runtime_identity: RuntimeIdentity,
    policy_identity: PolicyIdentity,
    effective_limits: EffectiveLimits,
    generation: u64,
}

impl DaemonPolicyRuntimeSnapshot {
    pub(crate) fn initial(
        candidate: CandidateRuntimeData,
        engine_policy_identity: PolicyIdentity,
        engine_effective_limits: EffectiveLimits,
    ) -> Result<Self, StableCode> {
        if candidate.policy_identity != engine_policy_identity
            || candidate.effective_limits != engine_effective_limits
            || candidate.runtime_identity.policy_digest() != candidate.policy_identity.digest
            || candidate.runtime_identity.policy_version()
                != candidate.policy_identity.policy_version
            || candidate.runtime_identity.policy_key_epoch() != candidate.policy_identity.key_epoch
            || candidate.runtime_identity.policy_expires_at()
                != candidate.policy_identity.expires_at
            || candidate.runtime_identity.resource_profile_digest()
                != candidate.resource_profile_digest
        {
            return Err(StableCode::KernelUnavailable);
        }
        Ok(Self {
            runtime_identity: candidate.runtime_identity,
            policy_identity: engine_policy_identity,
            effective_limits: engine_effective_limits,
            generation: 1,
        })
    }

    pub(crate) const fn runtime_identity(&self) -> &RuntimeIdentity {
        &self.runtime_identity
    }

    pub(crate) const fn policy_identity(&self) -> PolicyIdentity {
        self.policy_identity
    }

    pub(crate) const fn effective_limits(&self) -> EffectiveLimits {
        self.effective_limits
    }

    pub(crate) const fn generation(&self) -> u64 {
        self.generation
    }

    #[cfg(test)]
    pub(crate) fn with_limit_for_test(
        &self,
        effective_limits: EffectiveLimits,
        generation: u64,
    ) -> Self {
        Self {
            runtime_identity: self.runtime_identity.clone(),
            policy_identity: self.policy_identity,
            effective_limits,
            generation,
        }
    }
}

#[cfg(test)]
use crate::startup_identity_tests::policy_support as policy_test_support;

#[derive(Clone)]
pub(crate) struct CandidateRuntimeData {
    runtime_identity: RuntimeIdentity,
    policy_identity: PolicyIdentity,
    effective_limits: EffectiveLimits,
    resource_profile_digest: Digest32,
}

impl CandidateRuntimeData {
    pub(crate) fn from_config_and_candidate(
        config: &DaemonConfig,
        candidate: &VerifiedPolicyV1,
    ) -> Result<Self, StableCode> {
        let policy_identity = candidate.identity();
        let resource_profile_digest = candidate.resource_profile_digest();
        Ok(Self {
            runtime_identity: RuntimeIdentity::from_config_and_candidate(config, candidate),
            policy_identity,
            effective_limits: *candidate.effective_limits(),
            resource_profile_digest,
        })
    }
}

pub(crate) struct PolicyRuntime {
    dispatch_gate: DispatchGate,
    snapshot: RwLock<Arc<DaemonPolicyRuntimeSnapshot>>,
    engine: PolicyEngine,
    issuer: Arc<AuthenticatedContextIssuer>,
    #[cfg(test)]
    synthetic_for_handshake_test: bool,
}

impl std::fmt::Debug for PolicyRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PolicyRuntime(<generation-scoped>)")
    }
}

impl PolicyRuntime {
    pub(crate) fn new(
        snapshot: Arc<DaemonPolicyRuntimeSnapshot>,
        engine: PolicyEngine,
        issuer: Arc<AuthenticatedContextIssuer>,
    ) -> Self {
        Self {
            dispatch_gate: DispatchGate::new(),
            snapshot: RwLock::new(snapshot),
            engine,
            issuer,
            #[cfg(test)]
            synthetic_for_handshake_test: false,
        }
    }

    pub(crate) fn dispatch_lease(&self) -> Result<DispatchLease<'_>, StableCode> {
        self.dispatch_gate.lease(self)
    }

    pub(crate) fn admission_lease(&self) -> Result<AdmissionLease<'_>, StableCode> {
        self.dispatch_gate.admission_lease()
    }

    pub(crate) fn close_and_drain(&self) -> Result<ClosedDispatchGate<'_>, StableCode> {
        self.dispatch_gate.close_and_drain()
    }

    pub(crate) fn snapshot(&self) -> Result<Arc<DaemonPolicyRuntimeSnapshot>, StableCode> {
        self.snapshot
            .read()
            .map(|snapshot| Arc::clone(&snapshot))
            .map_err(|_| StableCode::KernelUnavailable)
    }

    pub(crate) const fn engine(&self) -> &PolicyEngine {
        &self.engine
    }

    pub(crate) fn issuer(&self) -> &AuthenticatedContextIssuer {
        self.issuer.as_ref()
    }

    #[cfg(test)]
    pub(crate) fn force_replace_snapshot_for_test(
        &self,
        snapshot: DaemonPolicyRuntimeSnapshot,
    ) -> Result<(), StableCode> {
        let mut current = self
            .snapshot
            .write()
            .map_err(|_| StableCode::KernelUnavailable)?;
        *current = Arc::new(snapshot);
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn new_for_handshake_test(runtime_identity: RuntimeIdentity) -> Self {
        let (current, _) = policy_test_support::current_policy_and_identity();
        let clock = policy_test_support::clock();
        let (engine, issuer) = PolicyEngine::new(
            current,
            savana_kernel_protocol::BootId::new([0xa1; 32]),
            Arc::clone(&clock) as Arc<dyn savana_policy_core::Clock + Send + Sync>,
            policy_test_support::random(policy_test_support::RandomBehavior::Filled(0x5a)),
        )
        .expect("handshake test policy engine");
        let policy_identity = PolicyIdentity {
            digest: runtime_identity.policy_digest(),
            policy_version: runtime_identity.policy_version(),
            key_epoch: runtime_identity.policy_key_epoch(),
            expires_at: runtime_identity.policy_expires_at(),
        };
        let mut runtime = Self::new(
            Arc::new(DaemonPolicyRuntimeSnapshot {
                runtime_identity,
                policy_identity,
                effective_limits: engine.effective_limits(),
                generation: 1,
            }),
            engine,
            Arc::new(issuer),
        );
        runtime.synthetic_for_handshake_test = true;
        runtime
    }

    #[cfg(test)]
    pub(crate) const fn is_synthetic_for_handshake_test(&self) -> bool {
        self.synthetic_for_handshake_test
    }
}

pub(crate) struct DispatchLease<'gate> {
    gate: &'gate DispatchGate,
    snapshot: Arc<DaemonPolicyRuntimeSnapshot>,
}

impl DispatchLease<'_> {
    pub(crate) const fn snapshot(&self) -> &Arc<DaemonPolicyRuntimeSnapshot> {
        &self.snapshot
    }
}

impl Drop for DispatchLease<'_> {
    fn drop(&mut self) {
        self.gate.release();
    }
}

pub(crate) struct AdmissionLease<'gate> {
    gate: &'gate DispatchGate,
}

impl Drop for AdmissionLease<'_> {
    fn drop(&mut self) {
        self.gate.release();
    }
}

pub(crate) struct ClosedDispatchGate<'gate> {
    gate: &'gate DispatchGate,
    armed: bool,
}

impl ClosedDispatchGate<'_> {
    pub(crate) fn reopen(mut self) {
        self.gate.reopen();
        self.armed = false;
    }
}

impl Drop for ClosedDispatchGate<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.gate.reopen();
        }
    }
}

pub(crate) struct DispatchGate {
    state: Mutex<DispatchGateState>,
    changed: Condvar,
}

struct DispatchGateState {
    closing: bool,
    closed_guard_active: bool,
    active: usize,
}

impl DispatchGate {
    const fn new() -> Self {
        Self {
            state: Mutex::new(DispatchGateState {
                closing: false,
                closed_guard_active: false,
                active: 0,
            }),
            changed: Condvar::new(),
        }
    }

    fn lease<'gate>(
        &'gate self,
        runtime: &'gate PolicyRuntime,
    ) -> Result<DispatchLease<'gate>, StableCode> {
        let mut state = self.lock_until_open()?;
        state.active = state
            .active
            .checked_add(1)
            .ok_or(StableCode::KernelUnavailable)?;
        let snapshot = runtime
            .snapshot
            .read()
            .map(|snapshot| Arc::clone(&snapshot))
            .map_err(|_| StableCode::KernelUnavailable);
        match snapshot {
            Ok(snapshot) => Ok(DispatchLease {
                gate: self,
                snapshot,
            }),
            Err(code) => {
                state.active = state.active.saturating_sub(1);
                if state.active == 0 {
                    self.changed.notify_all();
                }
                Err(code)
            }
        }
    }

    fn admission_lease(&self) -> Result<AdmissionLease<'_>, StableCode> {
        let mut state = self.lock_until_open()?;
        state.active = state
            .active
            .checked_add(1)
            .ok_or(StableCode::KernelUnavailable)?;
        Ok(AdmissionLease { gate: self })
    }

    fn close_and_drain(&self) -> Result<ClosedDispatchGate<'_>, StableCode> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| StableCode::KernelUnavailable)?;
        if state.closing || state.closed_guard_active {
            return Err(StableCode::KernelUnavailable);
        }
        state.closing = true;
        while state.active != 0 {
            state = self
                .changed
                .wait(state)
                .map_err(|_| StableCode::KernelUnavailable)?;
        }
        state.closed_guard_active = true;
        Ok(ClosedDispatchGate {
            gate: self,
            armed: true,
        })
    }

    fn lock_until_open(&self) -> Result<std::sync::MutexGuard<'_, DispatchGateState>, StableCode> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| StableCode::KernelUnavailable)?;
        while state.closing {
            state = self
                .changed
                .wait(state)
                .map_err(|_| StableCode::KernelUnavailable)?;
        }
        Ok(state)
    }

    fn release(&self) {
        let Ok(mut state) = self.state.lock() else {
            std::process::abort();
        };
        if state.active == 0 {
            std::process::abort();
        }
        state.active -= 1;
        if state.active == 0 {
            self.changed.notify_all();
        }
    }

    fn reopen(&self) {
        let Ok(mut state) = self.state.lock() else {
            std::process::abort();
        };
        state.closing = false;
        state.closed_guard_active = false;
        self.changed.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{mpsc, Arc};
    use std::thread;
    use std::time::Duration;

    use nix::sys::stat::{umask, Mode};
    use savana_kernel_protocol::{
        BootId, Digest32, EffectiveLimits, HardLimits, ResourceLimitsV1, StableCode, UnixMillis,
    };
    use savana_policy_core::PolicyEngine;

    use super::*;
    use crate::handshake::RuntimeIdentity;
    use crate::socket::PROCESS_TEST_LOCK;

    struct RuntimeFixture {
        runtime: Arc<PolicyRuntime>,
    }

    impl RuntimeFixture {
        fn snapshot_with_frame_limit(
            &self,
            frame_bytes: u64,
            generation: u64,
        ) -> DaemonPolicyRuntimeSnapshot {
            let old = self.runtime.snapshot().unwrap();
            old.with_limit_for_test(
                lowered_limits(old.effective_limits(), frame_bytes),
                generation,
            )
        }
    }

    fn runtime_fixture() -> RuntimeFixture {
        let mut policy = policy_test_support::valid_policy(7, 3);
        policy.resources.frame_bytes = 4_096;
        let (current, identity) = policy_test_support::current_policy_and_identity_from(policy);
        let clock = policy_test_support::clock();
        let (engine, issuer) = PolicyEngine::new(
            current,
            BootId::new([0x91; 32]),
            Arc::clone(&clock) as Arc<dyn savana_policy_core::Clock + Send + Sync>,
            policy_test_support::random(policy_test_support::RandomBehavior::Full),
        )
        .unwrap();
        let candidate = CandidateRuntimeData {
            runtime_identity: test_runtime_identity(identity),
            policy_identity: identity,
            effective_limits: engine.effective_limits(),
            resource_profile_digest: Digest32::new([0x63; 32]),
        };
        let snapshot = Arc::new(
            DaemonPolicyRuntimeSnapshot::initial(
                candidate,
                engine.current_policy_identity(),
                engine.effective_limits(),
            )
            .unwrap(),
        );
        RuntimeFixture {
            runtime: Arc::new(PolicyRuntime::new(snapshot, engine, Arc::new(issuer))),
        }
    }

    fn test_runtime_identity(identity: PolicyIdentity) -> RuntimeIdentity {
        RuntimeIdentity::for_policy_runtime_test(identity, Digest32::new([0x63; 32]))
    }

    fn lowered_limits(current: EffectiveLimits, frame_bytes: u64) -> EffectiveLimits {
        HardLimits::COMPILED
            .lower(&ResourceLimitsV1 {
                frame_bytes,
                cbor_depth: current.cbor_depth(),
                pages: current.pages(),
                chars_per_page: current.chars_per_page(),
                chars_per_document: current.chars_per_document(),
                observations: current.observations(),
                vault_entries: current.vault_entries(),
                vault_raw_bytes: current.vault_raw_bytes(),
                runs_per_client: current.runs_per_client(),
                vaults_per_client: current.vaults_per_client(),
                approval_ledger_entries: current.approval_ledger_entries(),
                model_manifest_bytes: current.model_manifest_bytes(),
                model_assets: current.model_assets(),
                model_tensor_contracts: current.model_tensor_contracts(),
                model_tensor_rank: current.model_tensor_rank(),
                single_model_asset_bytes: current.single_model_asset_bytes(),
                total_model_asset_bytes: current.total_model_asset_bytes(),
                ner_workers: current.ner_workers(),
                ner_queue: current.ner_queue(),
                ner_text_bytes: current.ner_text_bytes(),
                model_probes: current.model_probes(),
                model_probe_spans: current.model_probe_spans(),
                ner_failure_threshold: current.ner_failure_threshold(),
                request_deadline_ms: current.request_deadline_ms(),
                ingress_replay_entries_per_client: current.ingress_replay_entries_per_client(),
            })
            .unwrap()
    }

    #[test]
    fn one_snapshot_carries_handshake_identity_policy_limits_and_generation() {
        let fixture = runtime_fixture();
        let lease = fixture.runtime.dispatch_lease().unwrap();
        assert_eq!(lease.snapshot().generation(), 1);
        assert_eq!(
            lease.snapshot().policy_identity(),
            fixture.runtime.engine.current_policy_identity()
        );
        assert_eq!(
            lease.snapshot().effective_limits(),
            fixture.runtime.engine.effective_limits()
        );
        assert_eq!(
            lease.snapshot().runtime_identity().policy_digest(),
            fixture.runtime.engine.current_policy_identity().digest
        );
    }

    #[test]
    fn a_connection_lease_freezes_all_frame_limits_until_close() {
        let fixture = runtime_fixture();
        let old = fixture.runtime.dispatch_lease().unwrap();
        let new_snapshot = fixture.snapshot_with_frame_limit(1_024, 2);
        fixture
            .runtime
            .force_replace_snapshot_for_test(new_snapshot)
            .unwrap();
        assert_eq!(old.snapshot().effective_limits().frame_bytes(), 4_096);
        drop(old);
        assert_eq!(
            fixture
                .runtime
                .dispatch_lease()
                .unwrap()
                .snapshot()
                .effective_limits()
                .frame_bytes(),
            1_024
        );
    }

    #[test]
    fn fresh_dispatch_reads_the_published_policy_limits() {
        let fixture = runtime_fixture();
        let initial = fixture.runtime.dispatch_lease().unwrap();
        assert_eq!(initial.snapshot().effective_limits().frame_bytes(), 4_096);
        drop(initial);

        fixture
            .runtime
            .force_replace_snapshot_for_test(fixture.snapshot_with_frame_limit(1_024, 2))
            .unwrap();
        let fresh = fixture.runtime.dispatch_lease().unwrap();
        assert_eq!(fresh.snapshot().generation(), 2);
        assert_eq!(fresh.snapshot().effective_limits().frame_bytes(), 1_024);
    }

    #[test]
    fn one_connection_cannot_mix_generation_identity_and_limits() {
        let fixture = runtime_fixture();
        let connection = fixture.runtime.dispatch_lease().unwrap();
        let before = Arc::clone(connection.snapshot());
        let mut next_policy = before.policy_identity();
        next_policy.key_epoch += 1;
        let next = DaemonPolicyRuntimeSnapshot {
            runtime_identity: RuntimeIdentity::for_policy_runtime_test(
                next_policy,
                before.runtime_identity().resource_profile_digest(),
            ),
            policy_identity: next_policy,
            effective_limits: lowered_limits(before.effective_limits(), 1_024),
            generation: 2,
        };
        let runtime = Arc::clone(&fixture.runtime);
        let (published_tx, published_rx) = mpsc::channel();
        let publisher = thread::spawn(move || {
            let closed = runtime.close_and_drain().unwrap();
            runtime.force_replace_snapshot_for_test(next).unwrap();
            published_tx.send(()).unwrap();
            closed.reopen();
        });

        wait_until_closing(&fixture.runtime);
        assert!(published_rx
            .recv_timeout(Duration::from_millis(50))
            .is_err());

        assert_eq!(connection.snapshot().generation(), 1);
        assert_eq!(
            connection.snapshot().policy_identity(),
            before.policy_identity()
        );
        assert_eq!(
            connection.snapshot().effective_limits(),
            before.effective_limits()
        );
        drop(connection);
        published_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        publisher.join().unwrap();

        let fresh = fixture.runtime.dispatch_lease().unwrap();
        assert_eq!(fresh.snapshot().generation(), 2);
        assert_eq!(fresh.snapshot().policy_identity(), next_policy);
        assert_eq!(fresh.snapshot().effective_limits().frame_bytes(), 1_024);
    }

    #[test]
    fn initial_snapshot_rejects_every_mutated_policy_projection() {
        let fixture = runtime_fixture();
        let snapshot = fixture.runtime.snapshot().unwrap();
        let identity = snapshot.policy_identity();
        let candidate = CandidateRuntimeData {
            runtime_identity: snapshot.runtime_identity().clone(),
            policy_identity: identity,
            effective_limits: snapshot.effective_limits(),
            resource_profile_digest: snapshot.runtime_identity().resource_profile_digest(),
        };
        let engine_identity = fixture.runtime.engine.current_policy_identity();
        let engine_limits = fixture.runtime.engine.effective_limits();

        let mut wrong_digest = candidate.clone();
        wrong_digest.policy_identity.digest = Digest32::new([0x71; 32]);
        assert!(matches!(
            DaemonPolicyRuntimeSnapshot::initial(wrong_digest, engine_identity, engine_limits),
            Err(StableCode::KernelUnavailable)
        ));

        let mut wrong_version = candidate.clone();
        wrong_version.policy_identity.policy_version += 1;
        assert!(matches!(
            DaemonPolicyRuntimeSnapshot::initial(wrong_version, engine_identity, engine_limits),
            Err(StableCode::KernelUnavailable)
        ));

        let mut wrong_key_epoch = candidate.clone();
        wrong_key_epoch.policy_identity.key_epoch += 1;
        assert!(matches!(
            DaemonPolicyRuntimeSnapshot::initial(wrong_key_epoch, engine_identity, engine_limits),
            Err(StableCode::KernelUnavailable)
        ));

        let mut wrong_expiry = candidate.clone();
        wrong_expiry.policy_identity.expires_at = UnixMillis::new(4_001);
        assert!(matches!(
            DaemonPolicyRuntimeSnapshot::initial(wrong_expiry, engine_identity, engine_limits),
            Err(StableCode::KernelUnavailable)
        ));

        let mut wrong_resource = candidate.clone();
        wrong_resource.resource_profile_digest = Digest32::new([0x72; 32]);
        assert!(matches!(
            DaemonPolicyRuntimeSnapshot::initial(wrong_resource, engine_identity, engine_limits),
            Err(StableCode::KernelUnavailable)
        ));

        let mut wrong_limits = candidate;
        wrong_limits.effective_limits = lowered_limits(engine_limits, 1_024);
        assert!(matches!(
            DaemonPolicyRuntimeSnapshot::initial(wrong_limits, engine_identity, engine_limits),
            Err(StableCode::KernelUnavailable)
        ));
    }

    #[test]
    fn close_intent_blocks_dispatch_and_guard_drop_reopens_without_barging() {
        let fixture = runtime_fixture();
        let active = fixture.runtime.dispatch_lease().unwrap();
        let runtime = Arc::clone(&fixture.runtime);
        let (closed_tx, closed_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let closer = thread::spawn(move || {
            let guard = runtime.close_and_drain().unwrap();
            closed_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            drop(guard);
        });
        wait_until_closing(&fixture.runtime);
        assert!(closed_rx.recv_timeout(Duration::from_millis(50)).is_err());
        drop(active);
        closed_rx.recv_timeout(Duration::from_secs(1)).unwrap();

        let runtime = Arc::clone(&fixture.runtime);
        let (dispatch_tx, dispatch_rx) = mpsc::channel();
        let waiter = thread::spawn(move || {
            let lease = runtime.dispatch_lease().unwrap();
            dispatch_tx.send(lease.snapshot().generation()).unwrap();
        });
        let runtime = Arc::clone(&fixture.runtime);
        let (admission_tx, admission_rx) = mpsc::channel();
        let admission_waiter = thread::spawn(move || {
            let lease = runtime.admission_lease().unwrap();
            admission_tx.send(()).unwrap();
            drop(lease);
        });
        assert!(dispatch_rx.recv_timeout(Duration::from_millis(50)).is_err());
        assert!(admission_rx
            .recv_timeout(Duration::from_millis(50))
            .is_err());
        release_tx.send(()).unwrap();
        assert_eq!(dispatch_rx.recv_timeout(Duration::from_secs(1)).unwrap(), 1);
        admission_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        closer.join().unwrap();
        waiter.join().unwrap();
        admission_waiter.join().unwrap();
    }

    #[test]
    fn a_second_close_cannot_obtain_a_parallel_closed_guard() {
        let fixture = runtime_fixture();
        let active = fixture.runtime.dispatch_lease().unwrap();
        let runtime = Arc::clone(&fixture.runtime);
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let closer = thread::spawn(move || {
            started_tx.send(()).unwrap();
            let guard = runtime.close_and_drain().unwrap();
            release_rx.recv().unwrap();
            drop(guard);
        });
        started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        wait_until_closing(&fixture.runtime);
        assert!(matches!(
            fixture.runtime.close_and_drain(),
            Err(StableCode::KernelUnavailable)
        ));
        drop(active);
        release_tx.send(()).unwrap();
        closer.join().unwrap();
    }

    fn wait_until_closing(runtime: &PolicyRuntime) {
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        loop {
            if runtime.dispatch_gate.state.lock().unwrap().closing {
                return;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "close intent was not published"
            );
            thread::yield_now();
        }
    }

    #[test]
    fn policy_runtime_fixture_repairs_directory_modes_under_socket_umask() {
        struct UmaskRestore(Mode);

        impl Drop for UmaskRestore {
            fn drop(&mut self) {
                umask(self.0);
            }
        }

        let _process_guard = PROCESS_TEST_LOCK.lock().unwrap();
        let restore = UmaskRestore(umask(Mode::from_bits_truncate(0o117)));
        let fixture = runtime_fixture();
        assert_eq!(fixture.runtime.snapshot().unwrap().generation(), 1);
        drop(fixture);
        drop(restore);
    }
}
