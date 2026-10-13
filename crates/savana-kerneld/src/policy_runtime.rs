use std::{
    sync::{Arc, Condvar, Mutex},
    time::Instant,
};

use savana_kernel_protocol::v2::EndpointRoleV2;
use savana_kernel_protocol::StableCode;
use savana_policy_core::Clock;

use crate::v2_declassification_policy::{
    ActiveDeclassificationRuleSetV2, VerifiedV2DeclassificationSuccessorV2,
};
use crate::v2_dispatch::KernelServiceDispatcherV2;
use crate::v2_edge::{V2ActiveGenerationSnapshot, VerifiedServiceEdgeV2};
use crate::v2_transport_owner::KernelV2HandshakeOwner;

/// The only daemon-side declassification-rule rollover point.
///
/// It remains crate-private because an authenticated socket client must never
/// be able to select rule bytes or trigger a generation transition.
pub(crate) struct PolicyRolloverCoordinator {
    serialization: Mutex<()>,
    runtime: Arc<V2GenerationRuntime>,
    clock: Arc<dyn Clock + Send + Sync>,
}

impl std::fmt::Debug for PolicyRolloverCoordinator {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PolicyRolloverCoordinator(<private>)")
    }
}

impl PolicyRolloverCoordinator {
    pub(crate) fn new_v2(runtime: Arc<V2GenerationRuntime>) -> Self {
        Self::new_v2_with_clock(runtime, Arc::new(crate::runtime_deps::SystemClock::new()))
    }

    fn new_v2_with_clock(
        runtime: Arc<V2GenerationRuntime>,
        clock: Arc<dyn Clock + Send + Sync>,
    ) -> Self {
        Self {
            serialization: Mutex::new(()),
            runtime,
            clock,
        }
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn new_v2_with_clock_for_test_support(
        runtime: Arc<V2GenerationRuntime>,
        clock: Arc<dyn Clock + Send + Sync>,
    ) -> Self {
        Self::new_v2_with_clock(runtime, clock)
    }

    pub(crate) fn publish_v2_declassification_successor(
        &self,
        successor: VerifiedV2DeclassificationSuccessorV2,
    ) -> Result<(), StableCode> {
        let _serialization = self
            .serialization
            .lock()
            .map_err(|_| StableCode::KernelUnavailable)?;
        let closed = self.runtime.close_and_drain()?;
        let now_unix_ms = self.clock.wall_now()?.get();
        successor
            .validate_fresh_at(now_unix_ms)
            .map_err(|_| StableCode::KernelUnavailable)?;
        self.runtime.publish_verified_successor(successor)?;
        closed.reopen();
        Ok(())
    }
}

pub(crate) struct V2GenerationRuntime {
    dispatch_gate: Arc<DispatchGate>,
    active: ActiveDeclassificationRuleSetV2,
}

impl std::fmt::Debug for V2GenerationRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("V2GenerationRuntime(<generation-scoped>)")
    }
}

impl V2GenerationRuntime {
    pub(crate) fn new() -> Self {
        Self {
            dispatch_gate: Arc::new(DispatchGate::new()),
            active: ActiveDeclassificationRuleSetV2::empty(),
        }
    }

    #[cfg(test)]
    pub(crate) fn acquire(
        &self,
        edge: &VerifiedServiceEdgeV2,
        deadline: Instant,
    ) -> Result<V2GenerationLease, StableCode> {
        if Instant::now() >= deadline {
            return Err(StableCode::DeadlineExceeded);
        }
        let dispatch = self.dispatch_gate.v2_lease()?;
        let active = self
            .active
            .generation_snapshot()
            .map_err(|_| StableCode::KernelUnavailable)?;
        if !active.matches_edge(edge) {
            return Err(StableCode::IdentityReleaseMismatch);
        }
        Ok(V2GenerationLease {
            _dispatch: dispatch,
            active,
            edge_digest: edge.edge_digest(),
        })
    }

    pub(crate) fn acquire_endpoint(
        &self,
        role: EndpointRoleV2,
        deadline: Instant,
    ) -> Result<V2EndpointGenerationLease, StableCode> {
        if Instant::now() >= deadline {
            return Err(StableCode::DeadlineExceeded);
        }
        let dispatch = self.dispatch_gate.v2_lease()?;
        let (active, edge, handshake, dispatcher) = self
            .active
            .endpoint_snapshot(role)
            .map_err(|_| StableCode::KernelUnavailable)?;
        if edge.role() != role || !active.matches_edge(&edge) {
            return Err(StableCode::IdentityReleaseMismatch);
        }
        let lease = V2GenerationLease {
            _dispatch: dispatch,
            active,
            edge_digest: edge.edge_digest(),
        };
        Ok(V2EndpointGenerationLease {
            edge,
            handshake,
            dispatcher,
            lease,
        })
    }

    pub(crate) fn close_and_drain(&self) -> Result<ClosedDispatchGate<'_>, StableCode> {
        self.dispatch_gate.close_and_drain()
    }

    pub(crate) fn active_declassification_rules(&self) -> ActiveDeclassificationRuleSetV2 {
        self.active.clone()
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn admission_resumed_for_test_support(&self) -> bool {
        self.dispatch_gate
            .state
            .lock()
            .map(|state| !state.closing && !state.closed_guard_active)
            .unwrap_or(false)
    }

    fn publish_verified_successor(
        &self,
        successor: VerifiedV2DeclassificationSuccessorV2,
    ) -> Result<(), StableCode> {
        self.active
            .publish_verified_successor(successor)
            .map_err(|_| StableCode::KernelUnavailable)
    }

    #[cfg(test)]
    pub(crate) fn activate_for_test(
        &self,
        active: V2ActiveGenerationSnapshot,
    ) -> Result<(), StableCode> {
        self.active
            .activate_generation_for_test(active)
            .map_err(|_| StableCode::IdentityReleaseMismatch)
    }
}

pub(crate) struct V2GenerationLease {
    /// Held for its drop: the gate drains until every lease is gone.
    _dispatch: V2DispatchLease,
    active: Arc<V2ActiveGenerationSnapshot>,
    edge_digest: savana_kernel_protocol::v2::Digest32V2,
}

pub(crate) struct V2EndpointGenerationLease {
    edge: Arc<VerifiedServiceEdgeV2>,
    handshake: Arc<KernelV2HandshakeOwner>,
    dispatcher: Arc<KernelServiceDispatcherV2>,
    lease: V2GenerationLease,
}

impl V2EndpointGenerationLease {
    pub(crate) fn into_parts(
        self,
    ) -> (
        Arc<VerifiedServiceEdgeV2>,
        Arc<KernelV2HandshakeOwner>,
        Arc<KernelServiceDispatcherV2>,
        V2GenerationLease,
    ) {
        (self.edge, self.handshake, self.dispatcher, self.lease)
    }
}

impl V2GenerationLease {
    pub(crate) fn deployment_generation(&self) -> u64 {
        self.active.deployment_generation()
    }

    pub(crate) fn effect_fence_epoch(&self) -> u64 {
        self.active.effect_fence_epoch()
    }

    pub(crate) fn active_state_manifest_digest(&self) -> savana_kernel_protocol::v2::Digest32V2 {
        self.active.active_state_manifest_digest()
    }

    pub(crate) fn protocol_abi_digest(&self) -> savana_kernel_protocol::v2::Digest32V2 {
        self.active.protocol_abi_digest()
    }

    pub(crate) const fn edge_digest(&self) -> savana_kernel_protocol::v2::Digest32V2 {
        self.edge_digest
    }

    #[cfg(test)]
    pub(crate) fn revalidate(&self, active: &V2ActiveGenerationSnapshot) -> Result<(), StableCode> {
        if active == self.active.as_ref() {
            Ok(())
        } else {
            Err(StableCode::IdentityReleaseMismatch)
        }
    }

    #[cfg(test)]
    pub(crate) fn for_dispatch_test(
        active_state_manifest_digest: savana_kernel_protocol::v2::Digest32V2,
        deployment_generation: u64,
    ) -> Self {
        Self::for_dispatch_test_with_fence(active_state_manifest_digest, deployment_generation, 1)
    }

    #[cfg(test)]
    pub(crate) fn for_dispatch_test_with_fence(
        active_state_manifest_digest: savana_kernel_protocol::v2::Digest32V2,
        deployment_generation: u64,
        effect_fence_epoch: u64,
    ) -> Self {
        let dispatch = Arc::new(DispatchGate::new())
            .v2_lease()
            .expect("synthetic V2 dispatch lease");
        let active = V2ActiveGenerationSnapshot::for_dispatch_test(
            active_state_manifest_digest,
            deployment_generation,
        )
        .with_fence_for_test(effect_fence_epoch);
        Self {
            _dispatch: dispatch,
            active: Arc::new(active),
            edge_digest: savana_kernel_protocol::v2::Digest32V2::new([0xd6; 32]),
        }
    }
}

pub(crate) struct V2DispatchLease {
    gate: Arc<DispatchGate>,
}

impl Drop for V2DispatchLease {
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

    fn v2_lease(self: &Arc<Self>) -> Result<V2DispatchLease, StableCode> {
        let mut state = self.lock_until_open()?;
        state.active = state
            .active
            .checked_add(1)
            .ok_or(StableCode::KernelUnavailable)?;
        Ok(V2DispatchLease {
            gate: Arc::clone(self),
        })
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

    use super::*;
    use crate::deployment_trust::ClosedServiceEdgeIdV2;

    fn generation_fixture() -> (
        Arc<V2GenerationRuntime>,
        Arc<VerifiedServiceEdgeV2>,
        V2ActiveGenerationSnapshot,
    ) {
        let edge = Arc::new(VerifiedServiceEdgeV2::for_generation_test(
            ClosedServiceEdgeIdV2::AgentKernel,
            7,
            8,
            0x91,
        ));
        let active = V2ActiveGenerationSnapshot::for_generation_test(&edge);
        let runtime = Arc::new(V2GenerationRuntime::new());
        runtime.activate_for_test(active.clone()).unwrap();
        (runtime, edge, active)
    }

    fn lease(runtime: &V2GenerationRuntime, edge: &VerifiedServiceEdgeV2) -> V2GenerationLease {
        runtime
            .acquire(edge, std::time::Instant::now() + Duration::from_secs(10))
            .unwrap()
    }

    fn wait_until_closing(runtime: &V2GenerationRuntime) {
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
    fn generation_lease_binds_the_edge_and_holds_the_rollover_drain() {
        let (runtime, edge, active) = generation_fixture();
        let held = lease(&runtime, &edge);
        assert_eq!(held.deployment_generation(), 7);
        assert_eq!(held.effect_fence_epoch(), 8);
        held.revalidate(&active).unwrap();
        assert_eq!(
            held.revalidate(&active.with_fence_for_test(9)),
            Err(StableCode::IdentityReleaseMismatch)
        );

        let closing = Arc::clone(&runtime);
        let (drained_tx, drained_rx) = mpsc::channel();
        let closer = thread::spawn(move || {
            let closed = closing.close_and_drain().unwrap();
            drained_tx.send(()).unwrap();
            closed.reopen();
        });
        wait_until_closing(&runtime);
        assert!(drained_rx.recv_timeout(Duration::from_millis(50)).is_err());
        drop(held);
        drained_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        closer.join().unwrap();
    }

    #[test]
    fn generation_lease_is_owned_and_can_cross_the_state_owner_boundary() {
        let (runtime, edge, _) = generation_fixture();
        let held = lease(&runtime, &edge);
        thread::spawn(move || drop(held)).join().unwrap();
    }

    #[test]
    fn close_intent_blocks_new_leases_and_guard_drop_reopens_without_barging() {
        let (runtime, edge, _) = generation_fixture();
        let active = lease(&runtime, &edge);
        let closing = Arc::clone(&runtime);
        let (closed_tx, closed_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let closer = thread::spawn(move || {
            let guard = closing.close_and_drain().unwrap();
            closed_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            drop(guard);
        });
        wait_until_closing(&runtime);
        assert!(closed_rx.recv_timeout(Duration::from_millis(50)).is_err());
        drop(active);
        closed_rx.recv_timeout(Duration::from_secs(1)).unwrap();

        let waiting = Arc::clone(&runtime);
        let waiting_edge = edge.clone();
        let (entered_tx, entered_rx) = mpsc::channel();
        let waiter = thread::spawn(move || {
            let held = lease(&waiting, &waiting_edge);
            entered_tx.send(held.deployment_generation()).unwrap();
        });
        assert!(entered_rx.recv_timeout(Duration::from_millis(50)).is_err());
        release_tx.send(()).unwrap();
        assert_eq!(entered_rx.recv_timeout(Duration::from_secs(1)).unwrap(), 7);
        closer.join().unwrap();
        waiter.join().unwrap();
    }

    #[test]
    fn writer_intent_prevents_128_new_leases_from_barging() {
        const CONTENDERS: usize = 128;

        let (runtime, edge, _) = generation_fixture();
        let active = lease(&runtime, &edge);
        let closing = Arc::clone(&runtime);
        let (closed_tx, closed_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let closer = thread::spawn(move || {
            let guard = closing.close_and_drain().unwrap();
            closed_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            drop(guard);
        });
        wait_until_closing(&runtime);

        let barrier = Arc::new(std::sync::Barrier::new(CONTENDERS + 1));
        let (attempt_tx, attempt_rx) = mpsc::channel();
        let (entered_tx, entered_rx) = mpsc::channel();
        let mut contenders = Vec::with_capacity(CONTENDERS);
        for index in 0..CONTENDERS {
            let runtime = Arc::clone(&runtime);
            let edge = edge.clone();
            let barrier = Arc::clone(&barrier);
            let attempt_tx = attempt_tx.clone();
            let entered_tx = entered_tx.clone();
            contenders.push(thread::spawn(move || {
                barrier.wait();
                attempt_tx.send(index).unwrap();
                let held = lease(&runtime, &edge);
                entered_tx.send(held.deployment_generation()).unwrap();
                drop(held);
            }));
        }
        drop(attempt_tx);
        drop(entered_tx);
        barrier.wait();
        for _ in 0..CONTENDERS {
            attempt_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        }

        assert!(entered_rx.recv_timeout(Duration::from_millis(100)).is_err());
        assert!(closed_rx.recv_timeout(Duration::from_millis(100)).is_err());
        drop(active);
        closed_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(entered_rx.recv_timeout(Duration::from_millis(100)).is_err());

        release_tx.send(()).unwrap();
        for _ in 0..CONTENDERS {
            entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        }
        closer.join().unwrap();
        for contender in contenders {
            contender.join().unwrap();
        }
    }

    #[test]
    fn a_second_close_cannot_obtain_a_parallel_closed_guard() {
        let (runtime, edge, _) = generation_fixture();
        let active = lease(&runtime, &edge);
        let closing = Arc::clone(&runtime);
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let closer = thread::spawn(move || {
            started_tx.send(()).unwrap();
            let guard = closing.close_and_drain().unwrap();
            release_rx.recv().unwrap();
            drop(guard);
        });
        started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        wait_until_closing(&runtime);
        assert!(matches!(
            runtime.close_and_drain(),
            Err(StableCode::KernelUnavailable)
        ));
        drop(active);
        release_tx.send(()).unwrap();
        closer.join().unwrap();
    }
}
