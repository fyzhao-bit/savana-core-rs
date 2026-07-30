use std::{
    sync::{Arc, Condvar, Mutex, RwLock, RwLockWriteGuard},
    time::Instant,
};

use savana_kernel_protocol::{Digest32, EffectiveLimits, Signature64, StableCode};
use savana_policy_core::{
    AuthenticatedContextIssuer, Clock, CommittedPolicyRollover, PolicyEngine, PolicyIdentity,
    PolicyRolloverDisposition, PolicyRolloverFailure, VerifiedPolicyV1, VerifiedReleaseIdentity,
};

use crate::deployment_trust::VerifiedDaemonStartupV2;
use crate::handshake::RuntimeIdentity;
use crate::selected_policy::{SelectedPolicySource, SelectedPolicyUpdateGuard};
use crate::v2_edge::{V2ActiveGenerationSnapshot, VerifiedServiceEdgeV2};
use crate::DaemonConfig;

#[cfg(test)]
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

#[cfg(all(feature = "test-support", debug_assertions))]
use std::sync::atomic::{AtomicU8, Ordering as AtomicOrdering};

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LockEvent {
    DispatchLease,
    HandshakeRuntimeRead,
    HandshakeReplay,
    EngineWrite,
    RolloverMutex,
    SelectedShared,
    DispositionRead,
    DispatchCloseIntent,
    HandshakeRuntimeWrite,
}

#[cfg(test)]
#[derive(Default)]
struct RolloverProbe {
    snapshot_prebuilds: AtomicUsize,
    dispatch_close_attempts: AtomicUsize,
    handshake_write_locks: AtomicUsize,
    engine_prepares: AtomicUsize,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RolloverProbeSnapshot {
    pub(crate) snapshot_prebuilds: usize,
    pub(crate) dispatch_close_attempts: usize,
    pub(crate) handshake_write_locks: usize,
    pub(crate) engine_prepares: usize,
}

#[cfg(test)]
impl RolloverProbeSnapshot {
    const fn snapshot_prebuilds(self) -> usize {
        self.snapshot_prebuilds
    }

    const fn dispatch_close_attempts(self) -> usize {
        self.dispatch_close_attempts
    }

    const fn handshake_write_locks(self) -> usize {
        self.handshake_write_locks
    }

    const fn engine_prepares(self) -> usize {
        self.engine_prepares
    }
}

#[cfg(test)]
impl RolloverProbe {
    fn snapshot(&self) -> RolloverProbeSnapshot {
        RolloverProbeSnapshot {
            snapshot_prebuilds: self.snapshot_prebuilds.load(Ordering::SeqCst),
            dispatch_close_attempts: self.dispatch_close_attempts.load(Ordering::SeqCst),
            handshake_write_locks: self.handshake_write_locks.load(Ordering::SeqCst),
            engine_prepares: self.engine_prepares.load(Ordering::SeqCst),
        }
    }
}

#[cfg(test)]
struct ServerLockTraceRandom {
    next: AtomicU64,
}

#[cfg(test)]
impl ServerLockTraceRandom {
    const fn new() -> Self {
        Self {
            next: AtomicU64::new(1),
        }
    }
}

#[cfg(test)]
impl savana_policy_core::RandomSource for ServerLockTraceRandom {
    fn fill(&self, output: &mut [u8]) -> Result<usize, StableCode> {
        let value = self.next.fetch_add(1, Ordering::SeqCst);
        let mut bytes = [0_u8; 32];
        bytes[..8].copy_from_slice(&value.to_be_bytes());
        output.copy_from_slice(&bytes);
        Ok(output.len())
    }
}

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

    pub(crate) fn next(
        candidate: CandidateRuntimeData,
        expected_identity: PolicyIdentity,
        expected_effective_limits: EffectiveLimits,
        expected_resource_profile_digest: Digest32,
        generation: u64,
    ) -> Result<Self, StableCode> {
        if generation == 0
            || candidate.policy_identity != expected_identity
            || candidate.effective_limits != expected_effective_limits
            || candidate.resource_profile_digest != expected_resource_profile_digest
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
            policy_identity: candidate.policy_identity,
            effective_limits: candidate.effective_limits,
            generation,
        })
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
        // A live candidate is already bound to the retained release's resource
        // profile.  Rollover may publish a fresh verified policy atomically,
        // but it must never cross a release/resource-profile boundary.
        Ok(Self {
            runtime_identity: RuntimeIdentity::from_config_and_candidate(config, candidate),
            policy_identity,
            effective_limits: *candidate.effective_limits(),
            resource_profile_digest,
        })
    }

    fn from_verified(
        kernel_lock_bytes: &[u8],
        release: &VerifiedReleaseIdentity,
        candidate: &VerifiedPolicyV1,
        signature: &Signature64,
    ) -> Result<Self, StableCode> {
        let config = DaemonConfig::from_verified(kernel_lock_bytes, release, candidate, signature)
            .map_err(|error| error.code())?;
        Self::from_config_and_candidate(&config, candidate)
    }
}

struct PreflightPolicyCandidate {
    selected_guard: SelectedPolicyUpdateGuard,
    kernel_lock_bytes: Vec<u8>,
    policy_bytes: Vec<u8>,
    signature: Signature64,
    expected_identity: PolicyIdentity,
    verified_policy: VerifiedPolicyV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RefreshOutcome {
    Unchanged(PolicyIdentity),
    Published(PolicyIdentity),
}

#[cfg(all(feature = "test-support", debug_assertions))]
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum RolloverFault {
    None = 0,
    DropDaemonPublicationGuard = 1,
    AfterDaemonSnapshotSwap = 2,
}

#[cfg(all(feature = "test-support", debug_assertions))]
struct RolloverTestHooks {
    fault: AtomicU8,
}

#[cfg(all(feature = "test-support", debug_assertions))]
impl Default for RolloverTestHooks {
    fn default() -> Self {
        Self {
            fault: AtomicU8::new(RolloverFault::None as u8),
        }
    }
}

#[cfg(all(feature = "test-support", debug_assertions))]
impl RolloverTestHooks {
    fn arm_fault(&self, fault: RolloverFault) -> Result<(), StableCode> {
        self.fault
            .compare_exchange(
                RolloverFault::None as u8,
                fault as u8,
                AtomicOrdering::AcqRel,
                AtomicOrdering::Acquire,
            )
            .map(|_| ())
            .map_err(|_| StableCode::KernelUnavailable)
    }

    fn take_fault(&self) -> RolloverFault {
        match self
            .fault
            .swap(RolloverFault::None as u8, AtomicOrdering::AcqRel)
        {
            value if value == RolloverFault::DropDaemonPublicationGuard as u8 => {
                RolloverFault::DropDaemonPublicationGuard
            }
            value if value == RolloverFault::AfterDaemonSnapshotSwap as u8 => {
                RolloverFault::AfterDaemonSnapshotSwap
            }
            _ => RolloverFault::None,
        }
    }
}

/// The only daemon-side policy-refresh integration point.
///
/// It remains crate-private because an authenticated socket client must never
/// be able to select policy bytes or trigger a policy transition.
pub(crate) struct PolicyRolloverCoordinator {
    serialization: Mutex<()>,
    selected_source: Arc<SelectedPolicySource>,
    release: VerifiedReleaseIdentity,
    runtime: Arc<PolicyRuntime>,
    clock: Arc<dyn Clock + Send + Sync>,
    #[cfg(all(feature = "test-support", debug_assertions))]
    test_hooks: RolloverTestHooks,
    #[cfg(test)]
    probe: RolloverProbe,
    #[cfg(test)]
    lock_trace: Arc<Mutex<Vec<LockEvent>>>,
}

impl std::fmt::Debug for PolicyRolloverCoordinator {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PolicyRolloverCoordinator(<private>)")
    }
}

impl PolicyRolloverCoordinator {
    pub(crate) fn new(
        selected_source: Arc<SelectedPolicySource>,
        release: VerifiedReleaseIdentity,
        runtime: Arc<PolicyRuntime>,
        clock: Arc<dyn Clock + Send + Sync>,
    ) -> Self {
        #[cfg(test)]
        let lock_trace = runtime.lock_trace_for_test();
        Self {
            serialization: Mutex::new(()),
            selected_source,
            release,
            runtime,
            clock,
            #[cfg(all(feature = "test-support", debug_assertions))]
            test_hooks: RolloverTestHooks::default(),
            #[cfg(test)]
            probe: RolloverProbe::default(),
            #[cfg(test)]
            lock_trace,
        }
    }

    pub(crate) fn refresh_selected_policy(&self) -> Result<RefreshOutcome, StableCode> {
        let _serialization = self
            .serialization
            .lock()
            .map_err(|_| StableCode::KernelUnavailable)?;
        #[cfg(test)]
        self.record_lock(LockEvent::RolloverMutex);
        let candidate = self.preflight_candidate()?;
        #[cfg(test)]
        self.record_lock(LockEvent::SelectedShared);

        let disposition = self
            .runtime
            .engine()
            .rollover_disposition(candidate.expected_identity)
            .map_err(|error| error.code())?;
        #[cfg(test)]
        self.record_lock(LockEvent::DispositionRead);
        match disposition {
            PolicyRolloverDisposition::Unchanged(identity) => {
                candidate
                    .selected_guard
                    .final_recheck()
                    .map_err(|error| error.code())?;
                Ok(RefreshOutcome::Unchanged(identity))
            }
            PolicyRolloverDisposition::Advance(identity) => {
                if identity != candidate.expected_identity {
                    return Err(StableCode::KernelUnavailable);
                }
                self.publish_advance(candidate)
            }
        }
    }

    fn preflight_candidate(&self) -> Result<PreflightPolicyCandidate, StableCode> {
        let selected_guard = self
            .selected_source
            .acquire()
            .map_err(|error| error.code())?;
        let candidate = selected_guard
            .read_candidate()
            .map_err(|error| error.code())?;
        let now = self
            .clock
            .wall_now()
            .map_err(|_| StableCode::KernelUnavailable)?;
        let verifier = self
            .release
            .policy_verifier()
            .map_err(|error| error.code())?;
        let verified_policy = verifier
            .verify(&candidate.policy_bytes, &candidate.signature, now)
            .map_err(|error| error.code())?;
        self.release
            .verify_selected_policy_binding(&verified_policy, &candidate.signature)
            .map_err(|error| error.code())?;
        self.release
            .ensure_valid_at(now)
            .map_err(|error| error.code())?;
        DaemonConfig::verify_candidate(
            &candidate.kernel_lock_bytes,
            &self.release,
            &verified_policy,
            &candidate.signature,
        )
        .map_err(|error| error.code())?;
        Ok(PreflightPolicyCandidate {
            selected_guard,
            kernel_lock_bytes: candidate.kernel_lock_bytes,
            policy_bytes: candidate.policy_bytes,
            signature: candidate.signature,
            expected_identity: verified_policy.identity(),
            verified_policy,
        })
    }

    fn publish_advance(
        &self,
        candidate: PreflightPolicyCandidate,
    ) -> Result<RefreshOutcome, StableCode> {
        let current = self.runtime.snapshot()?;
        let next_generation = current
            .generation()
            .checked_add(1)
            .ok_or(StableCode::KernelUnavailable)?;
        let candidate_runtime = CandidateRuntimeData::from_verified(
            &candidate.kernel_lock_bytes,
            &self.release,
            &candidate.verified_policy,
            &candidate.signature,
        )?;
        #[cfg(test)]
        self.probe.snapshot_prebuilds.fetch_add(1, Ordering::SeqCst);
        let next_snapshot = Arc::new(DaemonPolicyRuntimeSnapshot::next(
            candidate_runtime,
            candidate.expected_identity,
            *candidate.verified_policy.effective_limits(),
            candidate.verified_policy.resource_profile_digest(),
            next_generation,
        )?);

        #[cfg(test)]
        self.probe
            .dispatch_close_attempts
            .fetch_add(1, Ordering::SeqCst);
        let closed_dispatch = self.runtime.close_and_drain()?;
        #[cfg(test)]
        self.record_lock(LockEvent::DispatchCloseIntent);
        let snapshot_write = self.runtime.snapshot_write()?;
        #[cfg(test)]
        {
            self.probe
                .handshake_write_locks
                .fetch_add(1, Ordering::SeqCst);
            self.record_lock(LockEvent::HandshakeRuntimeWrite);
        }
        #[cfg(test)]
        self.probe.engine_prepares.fetch_add(1, Ordering::SeqCst);
        let engine_guard = self
            .runtime
            .engine()
            .prepare_rollover(candidate.expected_identity)
            .map_err(|error| error.code())?;
        #[cfg(test)]
        self.record_lock(LockEvent::EngineWrite);
        candidate
            .selected_guard
            .final_recheck()
            .map_err(|error| error.code())?;
        #[cfg(all(feature = "test-support", debug_assertions))]
        let fault = self.test_hooks.take_fault();
        let now = self
            .clock
            .wall_now()
            .map_err(|_| StableCode::KernelUnavailable)?;
        let committed = match engine_guard.verify_accept_and_commit(
            &candidate.policy_bytes,
            &candidate.signature,
            now,
            candidate.expected_identity,
        ) {
            Ok(committed) => committed,
            Err(PolicyRolloverFailure::Rejected(error)) => return Err(error.code()),
            Err(PolicyRolloverFailure::CommitUncertain(_)) => std::process::abort(),
        };

        let publication = DaemonPublicationGuard::new(snapshot_write, next_snapshot).arm(committed);
        #[cfg(all(feature = "test-support", debug_assertions))]
        if fault == RolloverFault::DropDaemonPublicationGuard {
            drop(publication);
            unreachable!("dropping an armed publication guard aborts the process");
        }
        #[cfg(all(feature = "test-support", debug_assertions))]
        let publication =
            publication.with_post_swap_abort(fault == RolloverFault::AfterDaemonSnapshotSwap);
        let published = publication.complete();
        closed_dispatch.reopen();
        Ok(RefreshOutcome::Published(published))
    }

    #[cfg(test)]
    pub(crate) fn probe_snapshot(&self) -> RolloverProbeSnapshot {
        self.probe.snapshot()
    }

    #[cfg(test)]
    pub(crate) fn lock_trace(&self) -> Vec<LockEvent> {
        self.lock_trace
            .lock()
            .expect("rollover lock trace mutex is not poisoned")
            .clone()
    }

    #[cfg(test)]
    fn record_lock(&self, event: LockEvent) {
        self.lock_trace
            .lock()
            .expect("rollover lock trace mutex is not poisoned")
            .push(event);
    }

    #[cfg(all(feature = "test-support", debug_assertions))]
    pub(crate) fn arm_fault_for_test_lifecycle(&self, opcode: u8) -> Result<(), StableCode> {
        let fault = match opcode {
            0x0b => RolloverFault::DropDaemonPublicationGuard,
            0x0c => RolloverFault::AfterDaemonSnapshotSwap,
            _ => return Err(StableCode::KernelUnavailable),
        };
        self.test_hooks.arm_fault(fault)
    }
}

struct DaemonPublicationGuard<'runtime, 'engine> {
    snapshot: Option<RwLockWriteGuard<'runtime, Arc<DaemonPolicyRuntimeSnapshot>>>,
    next: Option<Arc<DaemonPolicyRuntimeSnapshot>>,
    old: Option<Arc<DaemonPolicyRuntimeSnapshot>>,
    committed: Option<CommittedPolicyRollover<'engine>>,
    armed: bool,
    #[cfg(all(feature = "test-support", debug_assertions))]
    post_swap_abort: bool,
}

impl<'runtime, 'engine> DaemonPublicationGuard<'runtime, 'engine> {
    fn new(
        snapshot: RwLockWriteGuard<'runtime, Arc<DaemonPolicyRuntimeSnapshot>>,
        next: Arc<DaemonPolicyRuntimeSnapshot>,
    ) -> Self {
        Self {
            snapshot: Some(snapshot),
            next: Some(next),
            old: None,
            committed: None,
            armed: false,
            #[cfg(all(feature = "test-support", debug_assertions))]
            post_swap_abort: false,
        }
    }

    fn arm(mut self, committed: CommittedPolicyRollover<'engine>) -> Self {
        self.committed = Some(committed);
        self.armed = true;
        self
    }

    #[cfg(all(feature = "test-support", debug_assertions))]
    fn with_post_swap_abort(mut self, post_swap_abort: bool) -> Self {
        self.post_swap_abort = post_swap_abort;
        self
    }

    fn complete(mut self) -> PolicyIdentity {
        let next = self.next.take().unwrap_or_else(|| std::process::abort());
        let expected = next.policy_identity();
        let snapshot = self
            .snapshot
            .as_mut()
            .unwrap_or_else(|| std::process::abort());
        self.old = Some(std::mem::replace(&mut **snapshot, next));
        #[cfg(all(feature = "test-support", debug_assertions))]
        if self.post_swap_abort {
            std::process::abort();
        }
        let committed = self
            .committed
            .take()
            .unwrap_or_else(|| std::process::abort());
        if committed.identity() != expected {
            std::process::abort();
        }
        let published = committed.complete_daemon_publication();
        if published != expected {
            std::process::abort();
        }
        self.armed = false;
        drop(self.snapshot.take());
        drop(self.old.take());
        published
    }
}

impl Drop for DaemonPublicationGuard<'_, '_> {
    fn drop(&mut self) {
        if self.armed {
            std::process::abort();
        }
    }
}

pub(crate) struct PolicyRuntime {
    dispatch_gate: Arc<DispatchGate>,
    snapshot: RwLock<Arc<DaemonPolicyRuntimeSnapshot>>,
    v2_generation: RwLock<Option<Arc<V2ActiveGenerationSnapshot>>>,
    engine: PolicyEngine,
    issuer: Arc<AuthenticatedContextIssuer>,
    #[cfg(test)]
    synthetic_for_handshake_test: bool,
    #[cfg(test)]
    lock_trace: Arc<Mutex<Vec<LockEvent>>>,
}

impl std::fmt::Debug for PolicyRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PolicyRuntime(<generation-scoped>)")
    }
}

pub(crate) struct V2GenerationRuntime {
    dispatch_gate: Arc<DispatchGate>,
    active: RwLock<Option<Arc<V2ActiveGenerationSnapshot>>>,
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
            active: RwLock::new(None),
        }
    }

    pub(crate) fn activate(&self, startup: &VerifiedDaemonStartupV2) -> Result<(), StableCode> {
        let active = V2ActiveGenerationSnapshot::from_verified_startup(startup)
            .map_err(|_| StableCode::IdentityReleaseMismatch)?;
        self.activate_snapshot(active)
    }

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
            .read()
            .map_err(|_| StableCode::KernelUnavailable)?
            .as_ref()
            .cloned()
            .ok_or(StableCode::KernelUnavailable)?;
        if !active.matches_edge(edge) {
            return Err(StableCode::IdentityReleaseMismatch);
        }
        Ok(V2GenerationLease {
            dispatch,
            active,
            edge_digest: edge.edge_digest(),
        })
    }

    pub(crate) fn close_and_drain(&self) -> Result<ClosedDispatchGate<'_>, StableCode> {
        self.dispatch_gate.close_and_drain()
    }

    fn activate_snapshot(&self, active: V2ActiveGenerationSnapshot) -> Result<(), StableCode> {
        let mut current = self
            .active
            .write()
            .map_err(|_| StableCode::KernelUnavailable)?;
        if current.is_some() {
            return Err(StableCode::IdentityReleaseMismatch);
        }
        *current = Some(Arc::new(active));
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn activate_for_test(
        &self,
        active: V2ActiveGenerationSnapshot,
    ) -> Result<(), StableCode> {
        self.activate_snapshot(active)
    }
}

impl PolicyRuntime {
    pub(crate) fn new(
        snapshot: Arc<DaemonPolicyRuntimeSnapshot>,
        engine: PolicyEngine,
        issuer: Arc<AuthenticatedContextIssuer>,
    ) -> Self {
        Self {
            dispatch_gate: Arc::new(DispatchGate::new()),
            snapshot: RwLock::new(snapshot),
            v2_generation: RwLock::new(None),
            engine,
            issuer,
            #[cfg(test)]
            synthetic_for_handshake_test: false,
            #[cfg(test)]
            lock_trace: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub(crate) fn dispatch_lease(&self) -> Result<DispatchLease, StableCode> {
        self.dispatch_gate.lease(self)
    }

    pub(crate) fn admission_lease(&self) -> Result<AdmissionLease<'_>, StableCode> {
        self.dispatch_gate.admission_lease()
    }

    pub(crate) fn close_and_drain(&self) -> Result<ClosedDispatchGate<'_>, StableCode> {
        self.dispatch_gate.close_and_drain()
    }

    pub(crate) fn activate_v2_generation(
        &self,
        startup: &VerifiedDaemonStartupV2,
    ) -> Result<(), StableCode> {
        let generation = Arc::new(
            V2ActiveGenerationSnapshot::from_verified_startup(startup)
                .map_err(|_| StableCode::IdentityReleaseMismatch)?,
        );
        let mut current = self
            .v2_generation
            .write()
            .map_err(|_| StableCode::KernelUnavailable)?;
        if current.is_some() {
            return Err(StableCode::IdentityReleaseMismatch);
        }
        *current = Some(generation);
        Ok(())
    }

    pub(crate) fn acquire_v2_generation_lease(
        &self,
        edge: &VerifiedServiceEdgeV2,
        deadline: Instant,
    ) -> Result<V2GenerationLease, StableCode> {
        if Instant::now() >= deadline {
            return Err(StableCode::DeadlineExceeded);
        }
        let dispatch = self.dispatch_gate.v2_lease()?;
        let active = self
            .v2_generation
            .read()
            .map_err(|_| StableCode::KernelUnavailable)?
            .as_ref()
            .cloned()
            .ok_or(StableCode::KernelUnavailable)?;
        if !active.matches_edge(edge) {
            return Err(StableCode::IdentityReleaseMismatch);
        }
        Ok(V2GenerationLease {
            dispatch,
            active,
            edge_digest: edge.edge_digest(),
        })
    }

    pub(crate) fn v2_generation_snapshot(
        &self,
    ) -> Result<Arc<V2ActiveGenerationSnapshot>, StableCode> {
        self.v2_generation
            .read()
            .map_err(|_| StableCode::KernelUnavailable)?
            .as_ref()
            .cloned()
            .ok_or(StableCode::KernelUnavailable)
    }

    pub(crate) fn snapshot(&self) -> Result<Arc<DaemonPolicyRuntimeSnapshot>, StableCode> {
        self.snapshot
            .read()
            .map(|snapshot| Arc::clone(&snapshot))
            .map_err(|_| StableCode::KernelUnavailable)
    }

    pub(crate) fn handshake_snapshot(
        &self,
    ) -> Result<Arc<DaemonPolicyRuntimeSnapshot>, StableCode> {
        let snapshot = self.snapshot()?;
        #[cfg(test)]
        self.record_lock(LockEvent::HandshakeRuntimeRead);
        Ok(snapshot)
    }

    fn snapshot_write(
        &self,
    ) -> Result<RwLockWriteGuard<'_, Arc<DaemonPolicyRuntimeSnapshot>>, StableCode> {
        self.snapshot
            .write()
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
    pub(crate) fn activate_v2_generation_for_test(
        &self,
        generation: V2ActiveGenerationSnapshot,
    ) -> Result<(), StableCode> {
        let mut current = self
            .v2_generation
            .write()
            .map_err(|_| StableCode::KernelUnavailable)?;
        if current.is_some() {
            return Err(StableCode::IdentityReleaseMismatch);
        }
        *current = Some(Arc::new(generation));
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
    pub(crate) fn new_for_server_lock_trace_test(
        peer_uid: u32,
        peer_gid: u32,
    ) -> (Arc<Self>, Arc<policy_test_support::TestClock>) {
        let (current, policy_identity) = policy_test_support::current_policy_and_identity();
        let clock = policy_test_support::clock();
        let (engine, issuer) = PolicyEngine::new(
            current,
            savana_kernel_protocol::BootId::new([0xa1; 32]),
            Arc::clone(&clock) as Arc<dyn savana_policy_core::Clock + Send + Sync>,
            Arc::new(ServerLockTraceRandom::new())
                as Arc<dyn savana_policy_core::RandomSource + Send + Sync>,
        )
        .expect("normal lock trace policy engine");
        let runtime_identity = RuntimeIdentity::for_server_lock_trace_test(
            policy_identity,
            Digest32::new([0x41; 32]),
            peer_uid,
            peer_gid,
        );
        let snapshot = DaemonPolicyRuntimeSnapshot {
            runtime_identity,
            policy_identity,
            effective_limits: engine.effective_limits(),
            generation: 1,
        };
        (
            Arc::new(Self::new(snapshot.into(), engine, Arc::new(issuer))),
            clock,
        )
    }

    #[cfg(test)]
    pub(crate) const fn is_synthetic_for_handshake_test(&self) -> bool {
        self.synthetic_for_handshake_test
    }

    #[cfg(test)]
    fn lock_trace_for_test(&self) -> Arc<Mutex<Vec<LockEvent>>> {
        Arc::clone(&self.lock_trace)
    }

    #[cfg(test)]
    pub(crate) fn record_replay_lock_for_test(&self) {
        self.record_lock(LockEvent::HandshakeReplay);
    }

    #[cfg(test)]
    pub(crate) fn record_engine_write_for_test(&self) {
        self.record_lock(LockEvent::EngineWrite);
    }

    #[cfg(test)]
    pub(crate) fn normal_lock_trace_for_test(&self) -> Vec<LockEvent> {
        self.lock_trace
            .lock()
            .expect("lock trace mutex is not poisoned")
            .clone()
    }

    #[cfg(test)]
    fn record_lock(&self, event: LockEvent) {
        self.lock_trace
            .lock()
            .expect("lock trace mutex is not poisoned")
            .push(event);
    }
}

pub(crate) struct DispatchLease {
    gate: Arc<DispatchGate>,
    snapshot: Arc<DaemonPolicyRuntimeSnapshot>,
}

impl DispatchLease {
    pub(crate) const fn snapshot(&self) -> &Arc<DaemonPolicyRuntimeSnapshot> {
        &self.snapshot
    }
}

impl Drop for DispatchLease {
    fn drop(&mut self) {
        self.gate.release();
    }
}

pub(crate) struct V2GenerationLease {
    dispatch: V2DispatchLease,
    active: Arc<V2ActiveGenerationSnapshot>,
    edge_digest: savana_kernel_protocol::v2::Digest32V2,
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
        let dispatch = Arc::new(DispatchGate::new())
            .v2_lease()
            .expect("synthetic V2 dispatch lease");
        Self {
            dispatch,
            active: Arc::new(V2ActiveGenerationSnapshot::for_dispatch_test(
                active_state_manifest_digest,
                deployment_generation,
            )),
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

    fn lease(self: &Arc<Self>, runtime: &PolicyRuntime) -> Result<DispatchLease, StableCode> {
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
            Ok(snapshot) => {
                #[cfg(test)]
                runtime.record_lock(LockEvent::DispatchLease);
                Ok(DispatchLease {
                    gate: Arc::clone(self),
                    snapshot,
                })
            }
            Err(code) => {
                state.active = state.active.saturating_sub(1);
                if state.active == 0 {
                    self.changed.notify_all();
                }
                Err(code)
            }
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
    use crate::deployment_trust::ClosedServiceEdgeIdV2;
    use crate::handshake::RuntimeIdentity;
    use crate::server::ServerLifecycle;
    use crate::socket::PROCESS_TEST_LOCK;
    use crate::startup_identity_tests::MappedInstallation;
    use crate::v2_edge::{V2ActiveGenerationSnapshot, VerifiedServiceEdgeV2};

    struct RolloverFixture {
        installation: MappedInstallation,
        prepared: crate::bootstrap::PreparedRuntime,
        old_identity: PolicyIdentity,
        clock: Arc<policy_test_support::TestClock>,
    }

    struct StartupComplete;

    impl ServerLifecycle for StartupComplete {
        fn workers_started(&mut self) -> Result<(), StableCode> {
            Ok(())
        }

        fn poll_shutdown(&mut self) -> Result<bool, StableCode> {
            Ok(true)
        }
    }

    impl RolloverFixture {
        fn new(generation: u64) -> Self {
            Self::new_with_policy_issued_at(generation, 1_000)
        }

        fn new_with_policy_issued_at(generation: u64, issued_at: u64) -> Self {
            let installation = MappedInstallation::new();
            installation.install_candidate_for_test(7, issued_at);
            let clock = policy_test_support::clock();
            let mut prepared = installation
                .prepare_with_clock_for_test(
                    Arc::clone(&clock) as Arc<dyn savana_policy_core::Clock + Send + Sync>
                )
                .expect("mapped rollover preparation");
            prepared
                .exercise_startup_guard_for_test(&mut StartupComplete)
                .expect("release startup selected-policy guard");
            if generation != 1 {
                let runtime = prepared.policy_runtime_for_test();
                let current = runtime.snapshot().expect("initial snapshot");
                runtime
                    .force_replace_snapshot_for_test(
                        current.with_limit_for_test(current.effective_limits(), generation),
                    )
                    .expect("test generation publication");
            }
            let old_identity = prepared
                .policy_runtime_for_test()
                .engine()
                .current_policy_identity();
            Self {
                installation,
                prepared,
                old_identity,
                clock,
            }
        }

        fn snapshot_everything(
            &self,
        ) -> (
            PolicyIdentity,
            EffectiveLimits,
            u64,
            PolicyIdentity,
            Option<Vec<u8>>,
            usize,
        ) {
            let snapshot = self
                .prepared
                .policy_runtime_for_test()
                .snapshot()
                .expect("snapshot");
            (
                snapshot.policy_identity(),
                snapshot.effective_limits(),
                snapshot.generation(),
                self.prepared
                    .policy_runtime_for_test()
                    .engine()
                    .current_policy_identity(),
                self.installation.ledger_bytes(),
                self.prepared.live_selected_artifact_descriptor_sets(),
            )
        }

        fn refresh_selected_policy(&self) -> Result<RefreshOutcome, StableCode> {
            self.prepared.refresh_selected_policy_for_test()
        }

        fn current_identity(&self) -> PolicyIdentity {
            self.prepared
                .policy_runtime_for_test()
                .engine()
                .current_policy_identity()
        }

        fn old_identity(&self) -> PolicyIdentity {
            self.old_identity
        }

        fn engine_identity(&self) -> PolicyIdentity {
            self.current_identity()
        }

        fn ledger_bytes(&self) -> Option<Vec<u8>> {
            self.installation.ledger_bytes()
        }

        fn install_next_candidate(&self) -> PolicyIdentity {
            self.installation.install_next_candidate()
        }

        fn install_next_candidate_issued_at(&self, issued_at: u64) -> PolicyIdentity {
            self.installation.install_candidate_for_test(8, issued_at)
        }

        fn rewind_before_release_issue(&self) {
            self.clock.set(999, 100);
        }

        fn probes(&self) -> RolloverProbeSnapshot {
            let (
                snapshot_prebuilds,
                dispatch_close_attempts,
                handshake_write_locks,
                engine_prepares,
            ) = self.prepared.rollover_probe_counts_for_test();
            RolloverProbeSnapshot {
                snapshot_prebuilds,
                dispatch_close_attempts,
                handshake_write_locks,
                engine_prepares,
            }
        }

        fn rollover_lock_trace(&self) -> Vec<LockEvent> {
            self.prepared.rollover_lock_trace_for_test()
        }
    }

    fn rollover_fixture() -> RolloverFixture {
        RolloverFixture::new(1)
    }

    fn rollover_fixture_with_generation(generation: u64) -> RolloverFixture {
        RolloverFixture::new(generation)
    }

    fn rollover_fixture_with_lock_trace() -> RolloverFixture {
        RolloverFixture::new(1)
    }

    fn rollover_fixture_with_policy_issued_at(issued_at: u64) -> RolloverFixture {
        RolloverFixture::new_with_policy_issued_at(1, issued_at)
    }

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
    fn v2_generation_lease_binds_edge_and_participates_in_rollover_drain() {
        let fixture = runtime_fixture();
        let edge = VerifiedServiceEdgeV2::for_generation_test(
            ClosedServiceEdgeIdV2::AgentKernel,
            7,
            8,
            0x91,
        );
        let active = V2ActiveGenerationSnapshot::for_generation_test(&edge);
        fixture
            .runtime
            .activate_v2_generation_for_test(active.clone())
            .unwrap();
        let lease = fixture
            .runtime
            .acquire_v2_generation_lease(&edge, std::time::Instant::now() + Duration::from_secs(1))
            .unwrap();
        assert_eq!(lease.deployment_generation(), 7);
        assert_eq!(lease.effect_fence_epoch(), 8);
        lease.revalidate(&active).unwrap();

        let stale = active.with_fence_for_test(9);
        assert_eq!(
            lease.revalidate(&stale),
            Err(StableCode::IdentityReleaseMismatch)
        );

        let runtime = Arc::clone(&fixture.runtime);
        let (drained_tx, drained_rx) = mpsc::channel();
        let closer = thread::spawn(move || {
            let closed = runtime.close_and_drain().unwrap();
            drained_tx.send(()).unwrap();
            closed.reopen();
        });
        wait_until_closing(&fixture.runtime);
        assert!(drained_rx.recv_timeout(Duration::from_millis(50)).is_err());
        drop(lease);
        drained_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        closer.join().unwrap();
    }

    #[test]
    fn v2_only_generation_runtime_needs_no_v1_policy_snapshot_and_still_drains() {
        let edge = VerifiedServiceEdgeV2::for_generation_test(
            ClosedServiceEdgeIdV2::AgentKernel,
            7,
            8,
            0x91,
        );
        let active = V2ActiveGenerationSnapshot::for_generation_test(&edge);
        let runtime = Arc::new(V2GenerationRuntime::new());
        runtime.activate_for_test(active.clone()).unwrap();
        let lease = runtime
            .acquire(&edge, std::time::Instant::now() + Duration::from_secs(1))
            .unwrap();
        assert_eq!(lease.deployment_generation(), 7);
        lease.revalidate(&active).unwrap();

        let closing = Arc::clone(&runtime);
        let (drained_tx, drained_rx) = mpsc::channel();
        let closer = thread::spawn(move || {
            let closed = closing.close_and_drain().unwrap();
            drained_tx.send(()).unwrap();
            closed.reopen();
        });
        assert!(drained_rx.recv_timeout(Duration::from_millis(50)).is_err());
        drop(lease);
        drained_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        closer.join().unwrap();
    }

    #[test]
    fn v2_generation_lease_is_owned_and_can_cross_the_state_owner_boundary() {
        let fixture = runtime_fixture();
        let edge = VerifiedServiceEdgeV2::for_generation_test(
            ClosedServiceEdgeIdV2::AgentKernel,
            7,
            8,
            0x91,
        );
        fixture
            .runtime
            .activate_v2_generation_for_test(V2ActiveGenerationSnapshot::for_generation_test(&edge))
            .unwrap();
        let lease = fixture
            .runtime
            .acquire_v2_generation_lease(&edge, std::time::Instant::now() + Duration::from_secs(1))
            .unwrap();

        thread::spawn(move || drop(lease)).join().unwrap();
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
    fn next_snapshot_rejects_every_mutated_runtime_projection() {
        let fixture = runtime_fixture();
        let snapshot = fixture.runtime.snapshot().unwrap();
        let identity = snapshot.policy_identity();
        let candidate = CandidateRuntimeData {
            runtime_identity: snapshot.runtime_identity().clone(),
            policy_identity: identity,
            effective_limits: snapshot.effective_limits(),
            resource_profile_digest: snapshot.runtime_identity().resource_profile_digest(),
        };
        let expected_limits = snapshot.effective_limits();
        let expected_resource = snapshot.runtime_identity().resource_profile_digest();

        let mut wrong_digest = candidate.clone();
        let mut changed = identity;
        changed.digest = Digest32::new([0x81; 32]);
        wrong_digest.runtime_identity = test_runtime_identity(changed);
        assert!(matches!(
            DaemonPolicyRuntimeSnapshot::next(
                wrong_digest,
                identity,
                expected_limits,
                expected_resource,
                2
            ),
            Err(StableCode::KernelUnavailable)
        ));

        let mut wrong_version = candidate.clone();
        let mut changed = identity;
        changed.policy_version += 1;
        wrong_version.runtime_identity = test_runtime_identity(changed);
        assert!(matches!(
            DaemonPolicyRuntimeSnapshot::next(
                wrong_version,
                identity,
                expected_limits,
                expected_resource,
                2
            ),
            Err(StableCode::KernelUnavailable)
        ));

        let mut wrong_epoch = candidate.clone();
        let mut changed = identity;
        changed.key_epoch += 1;
        wrong_epoch.runtime_identity = test_runtime_identity(changed);
        assert!(matches!(
            DaemonPolicyRuntimeSnapshot::next(
                wrong_epoch,
                identity,
                expected_limits,
                expected_resource,
                2
            ),
            Err(StableCode::KernelUnavailable)
        ));

        let mut wrong_expiry = candidate.clone();
        let mut changed = identity;
        changed.expires_at = UnixMillis::new(changed.expires_at.get() + 1);
        wrong_expiry.runtime_identity = test_runtime_identity(changed);
        assert!(matches!(
            DaemonPolicyRuntimeSnapshot::next(
                wrong_expiry,
                identity,
                expected_limits,
                expected_resource,
                2
            ),
            Err(StableCode::KernelUnavailable)
        ));

        let mut wrong_resource = candidate.clone();
        wrong_resource.runtime_identity =
            RuntimeIdentity::for_policy_runtime_test(identity, Digest32::new([0x82; 32]));
        assert!(matches!(
            DaemonPolicyRuntimeSnapshot::next(
                wrong_resource,
                identity,
                expected_limits,
                expected_resource,
                2
            ),
            Err(StableCode::KernelUnavailable)
        ));

        let mut wrong_limits = candidate;
        wrong_limits.effective_limits = lowered_limits(expected_limits, 1_024);
        assert!(matches!(
            DaemonPolicyRuntimeSnapshot::next(
                wrong_limits,
                identity,
                expected_limits,
                expected_resource,
                2,
            ),
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
    fn writer_intent_prevents_128_new_dispatch_leases_from_barging() {
        const CONTENDERS: usize = 128;

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

        let barrier = Arc::new(std::sync::Barrier::new(CONTENDERS + 1));
        let (attempt_tx, attempt_rx) = mpsc::channel();
        let (entered_tx, entered_rx) = mpsc::channel();
        let mut contenders = Vec::with_capacity(CONTENDERS);
        for index in 0..CONTENDERS {
            let runtime = Arc::clone(&fixture.runtime);
            let barrier = Arc::clone(&barrier);
            let attempt_tx = attempt_tx.clone();
            let entered_tx = entered_tx.clone();
            contenders.push(thread::spawn(move || {
                barrier.wait();
                attempt_tx.send(index).unwrap();
                if index % 2 == 0 {
                    let lease = runtime.dispatch_lease().unwrap();
                    entered_tx.send(lease.snapshot().generation()).unwrap();
                    drop(lease);
                } else {
                    let lease = runtime.admission_lease().unwrap();
                    entered_tx.send(0).unwrap();
                    drop(lease);
                }
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

    #[test]
    fn exact_equal_candidate_is_a_daemon_wide_read_only_no_op() {
        let fixture = rollover_fixture();
        let before = fixture.snapshot_everything();

        assert_eq!(
            fixture.refresh_selected_policy().unwrap(),
            RefreshOutcome::Unchanged(fixture.current_identity())
        );
        assert_eq!(fixture.snapshot_everything(), before);
        assert_eq!(fixture.probes().snapshot_prebuilds(), 0);
        assert_eq!(fixture.probes().dispatch_close_attempts(), 0);
        assert_eq!(fixture.probes().handshake_write_locks(), 0);
        assert_eq!(fixture.probes().engine_prepares(), 0);
    }

    #[test]
    fn exact_equal_candidate_before_release_issue_fails_before_any_publication_work() {
        let fixture = rollover_fixture_with_policy_issued_at(900);
        let before = fixture.snapshot_everything();
        fixture.rewind_before_release_issue();

        assert_eq!(
            fixture.refresh_selected_policy().unwrap_err(),
            StableCode::IdentityReleaseMismatch
        );
        assert_eq!(fixture.snapshot_everything(), before);
        assert_eq!(fixture.probes().snapshot_prebuilds(), 0);
        assert_eq!(fixture.probes().dispatch_close_attempts(), 0);
        assert_eq!(fixture.probes().handshake_write_locks(), 0);
        assert_eq!(fixture.probes().engine_prepares(), 0);
    }

    #[test]
    fn advance_candidate_before_release_issue_fails_before_any_publication_work() {
        let fixture = rollover_fixture_with_policy_issued_at(900);
        fixture.install_next_candidate_issued_at(900);
        let before = fixture.snapshot_everything();
        fixture.rewind_before_release_issue();

        assert_eq!(
            fixture.refresh_selected_policy().unwrap_err(),
            StableCode::IdentityReleaseMismatch
        );
        assert_eq!(fixture.snapshot_everything(), before);
        assert_eq!(fixture.probes().snapshot_prebuilds(), 0);
        assert_eq!(fixture.probes().dispatch_close_attempts(), 0);
        assert_eq!(fixture.probes().handshake_write_locks(), 0);
        assert_eq!(fixture.probes().engine_prepares(), 0);
    }

    #[test]
    fn handshake_generation_overflow_precedes_gate_and_ledger() {
        let fixture = rollover_fixture_with_generation(u64::MAX);
        fixture.install_next_candidate();
        let ledger_before = fixture.ledger_bytes();

        assert_eq!(
            fixture.refresh_selected_policy().unwrap_err(),
            StableCode::KernelUnavailable
        );
        assert_eq!(fixture.ledger_bytes(), ledger_before);
        assert_eq!(fixture.probes().dispatch_close_attempts(), 0);
        assert_eq!(fixture.engine_identity(), fixture.old_identity());
    }

    #[test]
    fn rollover_lock_order_is_exact_after_real_coordinator_acquisition() {
        let fixture = rollover_fixture_with_lock_trace();
        fixture.install_next_candidate();
        fixture.refresh_selected_policy().unwrap();
        assert_eq!(
            fixture.rollover_lock_trace(),
            &[
                LockEvent::RolloverMutex,
                LockEvent::SelectedShared,
                LockEvent::DispositionRead,
                LockEvent::DispatchCloseIntent,
                LockEvent::HandshakeRuntimeWrite,
                LockEvent::EngineWrite,
            ]
        );
    }
}
