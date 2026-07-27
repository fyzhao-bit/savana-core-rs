use std::collections::HashMap;
#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::RwLockWriteGuard;

use savana_kernel_protocol::{EffectiveLimits, HardLimits, Signature64, StableCode, UnixMillis};

use super::{
    checked_engine_limits, unavailable, EngineInner, EngineState, HandleKind, HandleToken,
    IngressReplayEntry, IngressReplayKey, RunRecord, StaleHandleRecord, ToolRecord, ValueRecord,
};
use crate::ledger::{DurableAcceptanceGuard, LedgerAcceptanceFailure, LivePolicyAcceptance};
use crate::{PolicyError, PolicyIdentity};

const MAX_STALE_HANDLES: usize = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyRolloverDisposition {
    Unchanged(PolicyIdentity),
    Advance(PolicyIdentity),
}

pub enum PolicyRolloverFailure {
    Rejected(PolicyError),
    CommitUncertain(PolicyError),
}

impl std::fmt::Debug for PolicyRolloverFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rejected(_) => formatter.write_str("PolicyRolloverFailure::Rejected(<redacted>)"),
            Self::CommitUncertain(_) => {
                formatter.write_str("PolicyRolloverFailure::CommitUncertain(<redacted>)")
            }
        }
    }
}

pub struct PolicyRolloverGuard<'engine> {
    engine: &'engine EngineInner,
    state: Option<RwLockWriteGuard<'engine, EngineState>>,
    expected_identity: PolicyIdentity,
    next_generation: u64,
    prepared_stale: Vec<StaleHandleRecord>,
    replacement: EmptyGenerationState,
}

pub struct CommittedPolicyRollover<'engine> {
    state: Option<RwLockWriteGuard<'engine, EngineState>>,
    identity: PolicyIdentity,
    durable: Option<DurableAcceptanceGuard>,
}

impl std::fmt::Debug for PolicyRolloverGuard<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PolicyRolloverGuard(<armed>)")
    }
}

impl std::fmt::Debug for CommittedPolicyRollover<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CommittedPolicyRollover(<armed>)")
    }
}

struct EmptyGenerationState {
    runs: HashMap<HandleToken, RunRecord>,
    values: HashMap<HandleToken, ValueRecord>,
    tools: HashMap<HandleToken, ToolRecord>,
    handle_kinds: HashMap<HandleToken, HandleKind>,
    ingress_replay: HashMap<IngressReplayKey, IngressReplayEntry>,
    replay_per_client: HashMap<savana_kernel_protocol::ClientId, u64>,
}

#[cfg(test)]
#[derive(Default)]
pub(crate) struct RolloverProbe {
    prebuild_calls: AtomicUsize,
    capacity_scans: AtomicUsize,
}

#[cfg(test)]
impl RolloverProbe {
    pub(crate) fn prebuild_calls(&self) -> usize {
        self.prebuild_calls.load(Ordering::SeqCst)
    }

    pub(crate) fn capacity_scans(&self) -> usize {
        self.capacity_scans.load(Ordering::SeqCst)
    }
}

impl crate::PolicyEngine {
    pub fn rollover_disposition(
        &self,
        expected_identity: PolicyIdentity,
    ) -> Result<PolicyRolloverDisposition, PolicyError> {
        let state = self.inner.state.read().map_err(|_| unavailable())?;
        state.ensure_available()?;
        let current = state.current.policy.identity();
        if expected_identity == current {
            return Ok(PolicyRolloverDisposition::Unchanged(current));
        }
        require_strict_advance(expected_identity, current)?;
        Ok(PolicyRolloverDisposition::Advance(expected_identity))
    }

    pub fn prepare_rollover(
        &self,
        expected_identity: PolicyIdentity,
    ) -> Result<PolicyRolloverGuard<'_>, PolicyError> {
        #[cfg(test)]
        self.inner.run_rollover_pre_state_lock_hook();
        let mut state = self.inner.state.write().map_err(|_| unavailable())?;
        let monotonic = self
            .inner
            .clock
            .monotonic_now_millis()
            .map_err(|_| unavailable())?;
        let now = self.inner.clock.wall_now().map_err(|_| unavailable())?;
        state.observe_monotonic(monotonic)?;
        state.ensure_available()?;
        require_strict_advance(expected_identity, state.current.policy.identity())?;

        state
            .stale_handles
            .retain(|record| now.get() < record.expires_at.get());
        let next_generation = state.generation.checked_add(1).ok_or_else(unavailable)?;
        let becoming_stale = state.handle_kinds.len();
        let retained = state.stale_handles.len();
        let stale_total = retained
            .checked_add(becoming_stale)
            .ok_or_else(unavailable)?;
        #[cfg(test)]
        self.inner
            .rollover_probe
            .capacity_scans
            .fetch_add(1, Ordering::SeqCst);
        if stale_total > MAX_STALE_HANDLES {
            return Err(PolicyError::stable(StableCode::KernelOverloaded));
        }

        validate_live_handle_indexes(&state)?;
        #[cfg(test)]
        self.inner
            .rollover_probe
            .prebuild_calls
            .fetch_add(1, Ordering::SeqCst);
        let prepared_stale = prepare_stale_handles(&state, stale_total)?;
        let replacement = EmptyGenerationState::prebuild(&state)?;
        Ok(PolicyRolloverGuard {
            engine: &self.inner,
            state: Some(state),
            expected_identity,
            next_generation,
            prepared_stale,
            replacement,
        })
    }

    pub fn current_policy_identity(&self) -> PolicyIdentity {
        self.inner
            .state
            .read()
            .unwrap_or_else(|_| std::process::abort())
            .current
            .policy
            .identity()
    }

    pub fn effective_limits(&self) -> EffectiveLimits {
        *self
            .inner
            .state
            .read()
            .unwrap_or_else(|_| std::process::abort())
            .current
            .policy
            .effective_limits()
    }
}

impl EngineState {
    fn ensure_available(&self) -> Result<(), PolicyError> {
        if self.poisoned {
            Err(unavailable())
        } else {
            Ok(())
        }
    }
}

impl EmptyGenerationState {
    fn prebuild(state: &EngineState) -> Result<Self, PolicyError> {
        let client_count = state.current.release.daemon_clients().len();
        let hard = HardLimits::COMPILED;
        let (maximum_replay, maximum_runs) = checked_engine_limits(
            client_count,
            hard.ingress_replay_entries_per_client(),
            hard.runs_per_client(),
        )?;
        let maximum_handles = maximum_runs.checked_mul(3).ok_or_else(unavailable)?;
        let mut runs = HashMap::new();
        runs.try_reserve(maximum_runs).map_err(|_| unavailable())?;
        let mut values = HashMap::new();
        values
            .try_reserve(maximum_runs)
            .map_err(|_| unavailable())?;
        let mut tools = HashMap::new();
        tools.try_reserve(maximum_runs).map_err(|_| unavailable())?;
        let mut handle_kinds = HashMap::new();
        handle_kinds
            .try_reserve(maximum_handles)
            .map_err(|_| unavailable())?;
        let mut ingress_replay = HashMap::new();
        ingress_replay
            .try_reserve(maximum_replay)
            .map_err(|_| unavailable())?;
        let mut replay_per_client = HashMap::new();
        replay_per_client
            .try_reserve(client_count)
            .map_err(|_| unavailable())?;
        Ok(Self {
            runs,
            values,
            tools,
            handle_kinds,
            ingress_replay,
            replay_per_client,
        })
    }
}

impl<'engine> PolicyRolloverGuard<'engine> {
    pub fn verify_accept_and_commit(
        mut self,
        policy_bytes: &[u8],
        signature: &Signature64,
        now: UnixMillis,
        expected_identity: PolicyIdentity,
    ) -> Result<CommittedPolicyRollover<'engine>, PolicyRolloverFailure> {
        if expected_identity != self.expected_identity {
            return Err(PolicyRolloverFailure::Rejected(PolicyError::stable(
                StableCode::AttestationBindingMismatch,
            )));
        }
        let mut state = self.state.take().unwrap_or_else(|| std::process::abort());
        if now.get() < state.current.release.issued_at().get()
            || now.get() >= state.current.release.expires_at().get()
        {
            return Err(PolicyRolloverFailure::Rejected(PolicyError::stable(
                StableCode::IdentityReleaseMismatch,
            )));
        }
        let policy = state
            .current
            .store
            .verify_live_candidate(policy_bytes, signature, now)
            .map_err(PolicyRolloverFailure::Rejected)?;
        if policy.identity() != expected_identity {
            return Err(PolicyRolloverFailure::Rejected(PolicyError::stable(
                StableCode::IdentityReleaseMismatch,
            )));
        }
        state
            .current
            .release
            .verify_selected_policy_binding(&policy, signature)
            .map_err(PolicyRolloverFailure::Rejected)?;
        state
            .current
            .release
            .recheck_retained_stage()
            .map_err(PolicyRolloverFailure::Rejected)?;
        let client_count = state.current.release.daemon_clients().len();
        let (global_replay_limit, global_run_limit) = checked_engine_limits(
            client_count,
            policy
                .effective_limits()
                .ingress_replay_entries_per_client(),
            policy.effective_limits().runs_per_client(),
        )
        .map_err(PolicyRolloverFailure::Rejected)?;
        let accepted = match state.current.store.accept_verified_live(policy) {
            Ok(accepted) => accepted,
            Err(LedgerAcceptanceFailure::Rejected(error)) => {
                return Err(PolicyRolloverFailure::Rejected(error));
            }
            Err(LedgerAcceptanceFailure::CommitUncertain(error)) => {
                state.poisoned = true;
                return Err(PolicyRolloverFailure::CommitUncertain(error));
            }
        };
        #[cfg(test)]
        post_acceptance_test_hook();
        let LivePolicyAcceptance {
            policy,
            ledger_identity,
            resource_profile_digest,
            durable,
        } = accepted;
        let EmptyGenerationState {
            runs,
            values,
            tools,
            handle_kinds,
            ingress_replay,
            replay_per_client,
        } = self.replacement;
        state.runs = runs;
        state.values = values;
        state.tools = tools;
        state.handle_kinds = handle_kinds;
        state.stale_handles = self.prepared_stale;
        state.ingress_replay = ingress_replay;
        state.replay_per_client = replay_per_client;
        state.registry = None;
        state.current.policy = policy;
        state.current.ledger_identity = ledger_identity;
        state.current.resource_profile_digest = resource_profile_digest;
        state.generation = self.next_generation;
        state.global_replay_limit = global_replay_limit;
        state.global_run_limit = global_run_limit;
        let _engine = self.engine;
        Ok(CommittedPolicyRollover {
            state: Some(state),
            identity: expected_identity,
            durable: Some(durable),
        })
    }
}

impl CommittedPolicyRollover<'_> {
    pub const fn identity(&self) -> PolicyIdentity {
        self.identity
    }

    pub fn complete_daemon_publication(mut self) -> PolicyIdentity {
        let durable = self.durable.take().unwrap_or_else(|| std::process::abort());
        durable.complete();
        drop(self.state.take());
        self.identity
    }
}

impl Drop for CommittedPolicyRollover<'_> {
    fn drop(&mut self) {
        if self.durable.is_some() {
            std::process::abort();
        }
    }
}

fn require_strict_advance(
    expected_identity: PolicyIdentity,
    current: PolicyIdentity,
) -> Result<(), PolicyError> {
    if expected_identity.policy_version < current.policy_version {
        return Err(PolicyError::stable(StableCode::PolicyRollback));
    }
    if expected_identity.policy_version == current.policy_version {
        return Err(PolicyError::stable(StableCode::PolicyEquivocation));
    }
    Ok(())
}

fn validate_live_handle_indexes(state: &EngineState) -> Result<(), PolicyError> {
    let concrete_total = state
        .runs
        .len()
        .checked_add(state.values.len())
        .and_then(|total| total.checked_add(state.tools.len()))
        .ok_or_else(unavailable)?;
    if concrete_total != state.handle_kinds.len() {
        return Err(unavailable());
    }
    for (token, kind) in &state.handle_kinds {
        let concrete = (
            state.runs.get(token),
            state.values.get(token),
            state.tools.get(token),
        );
        match (kind, concrete) {
            (HandleKind::Run, (Some(_), None, None))
            | (HandleKind::Value, (None, Some(_), None))
            | (HandleKind::Tool, (None, None, Some(_))) => {}
            _ => return Err(unavailable()),
        }
    }
    Ok(())
}

fn prepare_stale_handles(
    state: &EngineState,
    stale_total: usize,
) -> Result<Vec<StaleHandleRecord>, PolicyError> {
    let mut prepared = Vec::new();
    prepared
        .try_reserve_exact(stale_total)
        .map_err(|_| unavailable())?;
    prepared.extend(state.stale_handles.iter().cloned());
    let policy_expiry = state.current.policy.identity().expires_at.get();
    for (token, kind) in &state.handle_kinds {
        let expires_at = match kind {
            HandleKind::Run => state.runs.get(token).map(|record| record.expires_at),
            HandleKind::Value => state.values.get(token).map(|record| record.expires_at),
            HandleKind::Tool => state.tools.get(token).map(|record| record.expires_at),
        }
        .ok_or_else(unavailable)?;
        prepared.push(StaleHandleRecord {
            token: token.clone(),
            kind: *kind,
            expires_at: UnixMillis::new(expires_at.get().min(policy_expiry)),
        });
    }
    prepared.sort_unstable_by(|left, right| left.token.0.cmp(&right.token.0));
    if prepared
        .windows(2)
        .any(|pair| pair[0].token == pair[1].token)
    {
        return Err(unavailable());
    }
    Ok(prepared)
}

#[cfg(test)]
fn post_acceptance_test_hook() {
    if std::env::var_os("SAVANA_TEST_ROLLOVER_POST_ACCEPT_PANIC").is_some() {
        panic!("injected post-live-acceptance panic");
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{mpsc, Arc};
    use std::time::Duration;

    use savana_kernel_protocol::{KernelValue, StableCode, UnixMillis};

    use super::*;
    use crate::atomic_file::PersistencePhase;
    use crate::engine::{HandleToken, StaleHandleRecord};
    use crate::runtime::Clock;
    use crate::test_support as support;
    use crate::{PolicyEngine, RandomSource};

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct StateSnapshot {
        identity: crate::PolicyIdentity,
        effective_limits: savana_kernel_protocol::EffectiveLimits,
        ledger_identity: crate::PolicyLedgerIdentity,
        store_ledger_identity: crate::PolicyLedgerIdentity,
        resource_profile_digest: savana_kernel_protocol::Digest32,
        generation: u64,
        last_monotonic_ms: u64,
        poisoned: bool,
        runs: Vec<(HandleToken, crate::engine::RunRecord)>,
        values: Vec<(HandleToken, crate::engine::ValueRecord)>,
        tools: Vec<(HandleToken, crate::engine::ToolRecord)>,
        handle_kinds: Vec<(HandleToken, crate::engine::HandleKind)>,
        stale_handles: Vec<StaleHandleRecord>,
        ingress_replay: Vec<(
            crate::engine::IngressReplayKey,
            crate::engine::IngressReplayEntry,
        )>,
        replay_per_client: Vec<(savana_kernel_protocol::ClientId, u64)>,
        registry: Option<crate::engine::RegistryState>,
        global_replay_limit: usize,
        global_run_limit: usize,
    }

    fn snapshot(fixture: &support::RolloverFixture) -> StateSnapshot {
        let state = fixture.engine.inner.state.read().unwrap();
        let mut runs: Vec<_> = state
            .runs
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        runs.sort_by(|left, right| left.0 .0.cmp(&right.0 .0));
        let mut values: Vec<_> = state
            .values
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        values.sort_by(|left, right| left.0 .0.cmp(&right.0 .0));
        let mut tools: Vec<_> = state
            .tools
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        tools.sort_by(|left, right| left.0 .0.cmp(&right.0 .0));
        let mut handle_kinds: Vec<_> = state
            .handle_kinds
            .iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect();
        handle_kinds.sort_by(|left, right| left.0 .0.cmp(&right.0 .0));
        let mut ingress_replay: Vec<_> = state
            .ingress_replay
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        ingress_replay.sort_by(|left, right| {
            left.0
                .authority_key_id
                .as_str()
                .cmp(right.0.authority_key_id.as_str())
                .then_with(|| left.0.nonce.as_bytes().cmp(right.0.nonce.as_bytes()))
        });
        let mut replay_per_client: Vec<_> = state
            .replay_per_client
            .iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect();
        replay_per_client.sort_by(|left, right| left.0.as_str().cmp(right.0.as_str()));
        StateSnapshot {
            identity: state.current.policy.identity(),
            effective_limits: *state.current.policy.effective_limits(),
            ledger_identity: state.current.ledger_identity,
            store_ledger_identity: state.current.store.ledger_identity().unwrap(),
            resource_profile_digest: state.current.resource_profile_digest,
            generation: state.generation,
            last_monotonic_ms: state.last_monotonic_ms,
            poisoned: state.poisoned,
            runs,
            values,
            tools,
            handle_kinds,
            stale_handles: state.stale_handles.clone(),
            ingress_replay,
            replay_per_client,
            registry: state.registry.clone(),
            global_replay_limit: state.global_replay_limit,
            global_run_limit: state.global_run_limit,
        }
    }

    fn push_stale(state: &mut crate::engine::EngineState, count: usize, expires_at: u64) {
        state.stale_handles.try_reserve_exact(count).unwrap();
        for index in 0..count {
            let mut token = [0_u8; 32];
            token[..8].copy_from_slice(&(index as u64).to_be_bytes());
            token[8] = 0xfe;
            state.stale_handles.push(StaleHandleRecord {
                token: HandleToken(token),
                kind: crate::engine::HandleKind::Run,
                expires_at: UnixMillis::new(expires_at),
            });
        }
    }

    fn retain_one_live_handle(state: &mut crate::engine::EngineState) {
        let token = state.handle_kinds.keys().next().unwrap().clone();
        let kind = state.handle_kinds[&token];
        state
            .handle_kinds
            .retain(|candidate, _| *candidate == token);
        state
            .runs
            .retain(|candidate, _| kind == HandleKind::Run && *candidate == token);
        state
            .values
            .retain(|candidate, _| kind == HandleKind::Value && *candidate == token);
        state
            .tools
            .retain(|candidate, _| kind == HandleKind::Tool && *candidate == token);
    }

    fn handle_token<T: minicbor::Encode<()>>(handle: &T) -> HandleToken {
        let encoded = minicbor::to_vec(handle).unwrap();
        assert_eq!(encoded.len(), 34);
        assert_eq!(&encoded[..2], &[0x58, 0x20]);
        HandleToken(encoded[2..].try_into().unwrap())
    }

    #[test]
    fn exact_equal_rollover_is_a_read_only_no_op() {
        let fixture = support::RolloverFixture::new();
        let before = snapshot(&fixture);
        assert_eq!(
            fixture
                .engine
                .rollover_disposition(fixture.current_identity())
                .unwrap(),
            PolicyRolloverDisposition::Unchanged(fixture.current_identity())
        );
        assert_eq!(snapshot(&fixture), before);
        assert_eq!(fixture.engine.inner.rollover_probe.prebuild_calls(), 0);
        assert_eq!(fixture.engine.inner.rollover_probe.capacity_scans(), 0);
    }

    #[test]
    fn differing_same_or_lower_version_never_prepares() {
        let fixture = support::RolloverFixture::new();
        assert_eq!(
            fixture
                .engine
                .rollover_disposition(fixture.same_version_different_identity())
                .unwrap_err()
                .code(),
            StableCode::PolicyEquivocation
        );
        assert_eq!(
            fixture
                .engine
                .rollover_disposition(fixture.lower_identity())
                .unwrap_err()
                .code(),
            StableCode::PolicyRollback
        );
        assert_eq!(fixture.engine.inner.rollover_probe.prebuild_calls(), 0);
    }

    #[test]
    fn every_same_version_identity_mutation_is_equivocation_and_lower_is_rollback() {
        let fixture = support::RolloverFixture::new();
        let current = fixture.current_identity();
        for candidate in [
            crate::PolicyIdentity {
                digest: savana_kernel_protocol::Digest32::new([0x91; 32]),
                ..current
            },
            crate::PolicyIdentity {
                key_epoch: current.key_epoch + 1,
                ..current
            },
            crate::PolicyIdentity {
                expires_at: UnixMillis::new(current.expires_at.get() + 1),
                ..current
            },
        ] {
            assert_eq!(
                fixture
                    .engine
                    .rollover_disposition(candidate)
                    .unwrap_err()
                    .code(),
                StableCode::PolicyEquivocation
            );
        }
        assert_eq!(
            fixture
                .engine
                .rollover_disposition(crate::PolicyIdentity {
                    policy_version: current.policy_version - 1,
                    key_epoch: current.key_epoch + 1,
                    digest: savana_kernel_protocol::Digest32::new([0x92; 32]),
                    expires_at: UnixMillis::new(current.expires_at.get() + 1),
                })
                .unwrap_err()
                .code(),
            StableCode::PolicyRollback
        );
    }

    #[test]
    fn stale_capacity_boundary_accepts_exactly_65_536_and_rejects_one_more() {
        for (stale, live, accepted) in [
            (65_536, false, true),
            (65_535, true, true),
            (65_536, true, false),
        ] {
            let fixture = support::RolloverFixture::new();
            if live {
                fixture.begin_current();
                retain_one_live_handle(&mut fixture.engine.inner.state.write().unwrap());
            }
            push_stale(
                &mut fixture.engine.inner.state.write().unwrap(),
                stale,
                3_000,
            );
            let result = fixture.engine.prepare_rollover(fixture.next_identity());
            if accepted {
                drop(result.unwrap());
            } else {
                assert_eq!(result.unwrap_err().code(), StableCode::KernelOverloaded);
            }
        }
    }

    #[test]
    fn stale_capacity_and_generation_overflow_precede_ledger_write() {
        for (generation, stale, expected) in [
            (0, 65_536, StableCode::KernelOverloaded),
            (u64::MAX, 0, StableCode::KernelUnavailable),
        ] {
            let fixture = support::RolloverFixture::new();
            if stale != 0 {
                fixture.begin_current();
            }
            {
                let mut state = fixture.engine.inner.state.write().unwrap();
                state.generation = generation;
                push_stale(&mut state, stale, 3_000);
            }
            let before = fixture.ledger_bytes();
            let failure = fixture.commit_next().unwrap_err();
            match failure {
                PolicyRolloverFailure::Rejected(error) => assert_eq!(error.code(), expected),
                PolicyRolloverFailure::CommitUncertain(_) => {
                    panic!("preflight failure cannot be commit-uncertain")
                }
            }
            assert_eq!(fixture.ledger_bytes(), before);
            assert_eq!(
                fixture.engine.current_policy_identity(),
                fixture.current_identity()
            );
        }
    }

    #[test]
    fn prepare_validates_every_live_index_before_durable_acceptance() {
        let fixture = support::RolloverFixture::new();
        fixture.begin_current();
        let before = fixture.ledger_bytes();
        fixture.engine.inner.state.write().unwrap().runs.clear();
        assert_eq!(
            fixture
                .engine
                .prepare_rollover(fixture.next_identity())
                .unwrap_err()
                .code(),
            StableCode::KernelUnavailable
        );
        assert_eq!(fixture.ledger_bytes(), before);
        assert_eq!(
            fixture.engine.current_policy_identity(),
            fixture.current_identity()
        );
    }

    #[test]
    fn every_live_handle_index_corruption_fails_closed_before_ledger_write() {
        for corruption in ["missing", "duplicate", "wrong-kind"] {
            let fixture = support::RolloverFixture::new();
            let response = fixture.begin_current();
            let run = handle_token(&response.run);
            let before = fixture.ledger_bytes();
            let mut state = fixture.engine.inner.state.write().unwrap();
            match corruption {
                "missing" => {
                    state.handle_kinds.remove(&run);
                }
                "duplicate" => {
                    let value = state
                        .values
                        .get(&handle_token(&response.initial_value))
                        .unwrap()
                        .clone();
                    state.values.insert(run.clone(), value);
                }
                "wrong-kind" => {
                    state.handle_kinds.insert(run.clone(), HandleKind::Value);
                }
                _ => unreachable!(),
            }
            drop(state);
            let before_state = snapshot(&fixture);
            assert_eq!(
                fixture
                    .engine
                    .prepare_rollover(fixture.next_identity())
                    .unwrap_err()
                    .code(),
                StableCode::KernelUnavailable,
            );
            assert_eq!(fixture.ledger_bytes(), before, "{corruption}");
            assert_eq!(snapshot(&fixture), before_state, "{corruption}");
        }
    }

    #[test]
    fn higher_version_lower_ledger_epoch_advances_disposition_but_rejects_commit() {
        let fixture = support::RolloverFixture::new();
        {
            let mut state = fixture.engine.inner.state.write().unwrap();
            state.current.store.raise_ledger_epoch_for_rollover_test();
        }
        let before_state = snapshot(&fixture);
        let before_ledger = fixture.ledger_bytes();
        assert_eq!(
            fixture
                .engine
                .rollover_disposition(fixture.next_identity())
                .unwrap(),
            PolicyRolloverDisposition::Advance(fixture.next_identity()),
        );
        let failure = fixture
            .engine
            .prepare_rollover(fixture.next_identity())
            .unwrap()
            .verify_accept_and_commit(
                fixture.next_policy_bytes(),
                fixture.next_policy_signature(),
                support::unix_now(),
                fixture.next_identity(),
            )
            .unwrap_err();
        match failure {
            PolicyRolloverFailure::Rejected(error) => {
                assert_eq!(error.code(), StableCode::PolicyRollback);
            }
            PolicyRolloverFailure::CommitUncertain(_) => {
                panic!("ledger comparison must reject before persistence")
            }
        }
        assert_eq!(snapshot(&fixture), before_state);
        assert_eq!(fixture.ledger_bytes(), before_ledger);
    }

    #[test]
    fn consecutive_rollovers_keep_unexpired_prior_generation_tombstones() {
        let fixture = support::RolloverFixture::new();
        let first_run = fixture.begin_current().run;
        fixture.commit_next().unwrap().complete_daemon_publication();
        let second_context = fixture.next_context();
        let second_run = fixture
            .engine
            .begin_run(
                &second_context,
                fixture.begin_request(fixture.next_identity(), KernelValue::Null),
            )
            .unwrap()
            .run;
        fixture
            .commit_third()
            .unwrap()
            .complete_daemon_publication();

        let first = handle_token(&first_run);
        let second = handle_token(&second_run);
        let state = fixture.engine.inner.state.read().unwrap();
        assert!(state
            .stale_handles
            .iter()
            .any(|record| record.token == first));
        assert!(state
            .stale_handles
            .iter()
            .any(|record| record.token == second));
        drop(state);

        let third_context = fixture.third_context();
        assert_eq!(
            fixture
                .ingest_third_with_expiry(&third_context, first_run, 3_900)
                .unwrap_err()
                .code(),
            StableCode::HandleStalePolicy,
        );
        fixture.clock.set(3_000, 101);
        assert_eq!(
            fixture
                .ingest_third_with_expiry(&third_context, second_run, 3_900)
                .unwrap_err()
                .code(),
            StableCode::HandleUnknown,
        );
    }

    #[test]
    fn pre_rename_failure_resumes_old_policy_but_post_rename_is_uncertain() {
        let recoverable = support::RolloverFixture::new();
        {
            let mut state = recoverable.engine.inner.state.write().unwrap();
            state
                .current
                .store
                .inject_live_persistence_fault(PersistencePhase::BeforeRename);
        }
        assert!(matches!(
            recoverable.commit_next().unwrap_err(),
            PolicyRolloverFailure::Rejected(_)
        ));
        assert!(recoverable
            .engine
            .begin_run(
                &recoverable.current_context,
                recoverable.begin_request(recoverable.current_identity(), KernelValue::Null),
            )
            .is_ok());

        let uncertain = support::RolloverFixture::new();
        {
            let mut state = uncertain.engine.inner.state.write().unwrap();
            state
                .current
                .store
                .inject_live_persistence_fault(PersistencePhase::AfterRename);
        }
        assert!(matches!(
            uncertain.commit_next().unwrap_err(),
            PolicyRolloverFailure::CommitUncertain(_)
        ));
        assert_eq!(
            uncertain
                .engine
                .rollover_disposition(uncertain.next_identity())
                .unwrap_err()
                .code(),
            StableCode::KernelUnavailable
        );
        assert_eq!(
            uncertain
                .engine
                .begin_run(
                    &uncertain.current_context,
                    uncertain.begin_request(uncertain.current_identity(), KernelValue::Null),
                )
                .unwrap_err()
                .code(),
            StableCode::KernelUnavailable
        );
    }

    #[test]
    fn rejected_verification_preserves_every_nonexpired_state_field() {
        let fixture = support::RolloverFixture::new();
        fixture.begin_current();
        let before_state = snapshot(&fixture);
        let before_ledger = fixture.ledger_bytes();
        let failure = fixture
            .engine
            .prepare_rollover(fixture.next_identity())
            .unwrap()
            .verify_accept_and_commit(
                &[],
                fixture.next_policy_signature(),
                support::unix_now(),
                fixture.next_identity(),
            )
            .unwrap_err();
        assert!(matches!(failure, PolicyRolloverFailure::Rejected(_)));
        assert_eq!(snapshot(&fixture), before_state);
        assert_eq!(fixture.ledger_bytes(), before_ledger);
    }

    #[test]
    fn expected_identity_mismatch_precedes_candidate_verification() {
        let fixture = support::RolloverFixture::new();
        let before_state = snapshot(&fixture);
        let before_ledger = fixture.ledger_bytes();
        let failure = fixture
            .engine
            .prepare_rollover(fixture.next_identity())
            .unwrap()
            .verify_accept_and_commit(
                &[],
                fixture.next_policy_signature(),
                support::unix_now(),
                fixture.same_version_different_identity(),
            )
            .unwrap_err();
        match failure {
            PolicyRolloverFailure::Rejected(error) => {
                assert_eq!(error.code(), StableCode::AttestationBindingMismatch);
            }
            PolicyRolloverFailure::CommitUncertain(_) => {
                panic!("captured expected identity must reject before persistence")
            }
        }
        assert_eq!(snapshot(&fixture), before_state);
        assert_eq!(fixture.ledger_bytes(), before_ledger);
    }

    #[test]
    fn release_window_precedes_candidate_verification_and_preserves_state() {
        let fixture = support::RolloverFixture::new();
        let before_state = snapshot(&fixture);
        let before_ledger = fixture.ledger_bytes();
        let failure = fixture
            .engine
            .prepare_rollover(fixture.next_identity())
            .unwrap()
            .verify_accept_and_commit(
                &[],
                fixture.next_policy_signature(),
                UnixMillis::new(4_000),
                fixture.next_identity(),
            )
            .unwrap_err();
        match failure {
            PolicyRolloverFailure::Rejected(error) => {
                assert_eq!(error.code(), StableCode::IdentityReleaseMismatch);
            }
            PolicyRolloverFailure::CommitUncertain(_) => {
                panic!("release window must reject before persistence")
            }
        }
        assert_eq!(snapshot(&fixture), before_state);
        assert_eq!(fixture.ledger_bytes(), before_ledger);
    }

    #[test]
    fn committed_policy_is_installed_while_dispatch_remains_paused() {
        let fixture = support::RolloverFixture::new();
        fixture.begin_current();
        let committed = fixture.commit_next().unwrap();
        assert_eq!(committed.identity(), fixture.next_identity());
        assert!(fixture.engine.inner.state.try_read().is_err());
        let state = committed.state.as_ref().unwrap();
        assert_eq!(state.current.policy.identity(), fixture.next_identity());
        assert_eq!(
            state.current.ledger_identity,
            state.current.store.ledger_identity().unwrap()
        );
        assert_eq!(
            state.current.resource_profile_digest,
            state.current.policy.resource_profile_digest()
        );
        assert!(state.runs.is_empty());
        assert!(state.values.is_empty());
        assert!(state.tools.is_empty());
        assert!(state.handle_kinds.is_empty());
        assert!(state.ingress_replay.is_empty());
        assert!(state.replay_per_client.is_empty());
        assert!(state.registry.is_none());
        assert_eq!(state.stale_handles.len(), 3);
        assert_eq!(
            committed.complete_daemon_publication(),
            fixture.next_identity()
        );
        assert_eq!(
            fixture.engine.current_policy_identity(),
            fixture.next_identity()
        );
    }

    #[test]
    fn expired_stale_tombstones_do_not_consume_rollover_capacity() {
        let fixture = support::RolloverFixture::new();
        fixture.begin_current();
        let live = fixture
            .engine
            .inner
            .state
            .read()
            .unwrap()
            .handle_kinds
            .len();
        {
            let mut state = fixture.engine.inner.state.write().unwrap();
            push_stale(&mut state, 65_536, support::NOW);
        }
        let guard = fixture
            .engine
            .prepare_rollover(fixture.next_identity())
            .unwrap();
        assert_eq!(guard.prepared_stale.len(), live);
        let committed = guard
            .verify_accept_and_commit(
                fixture.next_policy_bytes(),
                fixture.next_policy_signature(),
                support::unix_now(),
                fixture.next_identity(),
            )
            .unwrap();
        committed.complete_daemon_publication();
    }

    struct OrderedClock {
        calls: AtomicU64,
        monotonic_entered: mpsc::SyncSender<()>,
        wall_entered: mpsc::SyncSender<()>,
    }

    impl Clock for OrderedClock {
        fn wall_now(&self) -> Result<UnixMillis, StableCode> {
            self.wall_entered.send(()).unwrap();
            Ok(UnixMillis::new(support::NOW))
        }

        fn monotonic_now_millis(&self) -> Result<u64, StableCode> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            if call != 0 {
                self.monotonic_entered.send(()).unwrap();
            }
            Ok(100 + call)
        }
    }

    #[test]
    fn prepare_takes_state_lock_before_monotonic_then_wall_clock() {
        let (monotonic_tx, monotonic_rx) = mpsc::sync_channel(1);
        let (wall_tx, wall_rx) = mpsc::sync_channel(1);
        let clock = Arc::new(OrderedClock {
            calls: AtomicU64::new(0),
            monotonic_entered: monotonic_tx,
            wall_entered: wall_tx,
        });
        let (current, identity) = support::current_policy_and_identity();
        let (engine, _) = PolicyEngine::new(
            current,
            savana_kernel_protocol::BootId::new([0x41; 32]),
            Arc::clone(&clock) as Arc<dyn Clock + Send + Sync>,
            support::random(support::RandomBehavior::Full) as Arc<dyn RandomSource + Send + Sync>,
        )
        .unwrap();
        let engine = Arc::new(engine);
        let held = engine.inner.state.write().unwrap();
        let (hook_entered_tx, hook_entered_rx) = mpsc::sync_channel(1);
        let (release_hook_tx, release_hook_rx) = mpsc::sync_channel(1);
        engine
            .inner
            .install_rollover_pre_state_lock_hook(Box::new(move || {
                hook_entered_tx.send(()).unwrap();
                release_hook_rx
                    .recv_timeout(Duration::from_secs(2))
                    .expect("rollover hook release timed out");
            }));
        let candidate = crate::PolicyIdentity {
            policy_version: identity.policy_version + 1,
            digest: savana_kernel_protocol::Digest32::new([0xee; 32]),
            ..identity
        };
        let worker_engine = Arc::clone(&engine);
        let worker =
            std::thread::spawn(move || worker_engine.prepare_rollover(candidate).map(drop));
        hook_entered_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("rollover did not reach pre-state-lock boundary");
        assert!(monotonic_rx.try_recv().is_err());
        assert!(wall_rx.try_recv().is_err());
        release_hook_tx.send(()).unwrap();
        assert!(monotonic_rx.try_recv().is_err());
        assert!(wall_rx.try_recv().is_err());
        drop(held);
        monotonic_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("monotonic clock was not observed after lock release");
        assert!(
            wall_rx.recv_timeout(Duration::from_secs(2)).is_ok(),
            "wall clock must follow monotonic clock"
        );
        assert!(worker.join().unwrap().is_ok());
    }

    #[test]
    fn wall_clock_failure_does_not_advance_the_monotonic_floor() {
        let fixture = support::RolloverFixture::new();
        let before = fixture.engine.inner.state.read().unwrap().last_monotonic_ms;
        fixture.clock.set(support::NOW, before + 1);
        fixture.clock.fail_wall();
        assert_eq!(
            fixture
                .engine
                .prepare_rollover(fixture.next_identity())
                .unwrap_err()
                .code(),
            StableCode::KernelUnavailable
        );
        assert_eq!(
            fixture.engine.inner.state.read().unwrap().last_monotonic_ms,
            before
        );
    }

    #[test]
    fn success_replaces_limits_and_recomputes_global_bounds_from_candidate() {
        let fixture = support::RolloverFixture::new();
        let candidate_limits = fixture.next_limits();
        let mut lowered = support::compiled_resources();
        lowered.runs_per_client -= 1;
        lowered.ingress_replay_entries_per_client -= 1;
        let old_limits = HardLimits::COMPILED.lower(&lowered).unwrap();
        {
            let mut state = fixture.engine.inner.state.write().unwrap();
            state
                .current
                .policy
                .overwrite_effective_limits_for_rollover_test(old_limits);
            state.global_run_limit = 1;
            state.global_replay_limit = 1;
        }
        assert_ne!(old_limits, candidate_limits);
        let committed = fixture.commit_next().unwrap();
        let state = committed.state.as_ref().unwrap();
        assert_eq!(*state.current.policy.effective_limits(), candidate_limits);
        assert_eq!(
            state.global_run_limit,
            usize::try_from(candidate_limits.runs_per_client()).unwrap()
        );
        assert_eq!(
            state.global_replay_limit,
            usize::try_from(candidate_limits.ingress_replay_entries_per_client()).unwrap()
        );
        committed.complete_daemon_publication();
    }

    #[test]
    fn durable_success_before_committed_guard_aborts() {
        const CHILD: &str = "SAVANA_TEST_ROLLOVER_POST_DURABLE_PANIC";
        if std::env::var_os(CHILD).is_some() {
            let fixture = support::RolloverFixture::new();
            std::env::set_var("SAVANA_TEST_ROLLOVER_POST_ACCEPT_PANIC", "1");
            let _ = fixture.commit_next();
            std::process::exit(99);
        }
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("engine::rollover::tests::durable_success_before_committed_guard_aborts")
            .arg("--nocapture")
            .env(CHILD, "1")
            .status()
            .unwrap();
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(status.signal(), Some(nix::libc::SIGABRT));
    }
}
