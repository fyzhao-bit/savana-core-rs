use std::collections::HashMap;

use savana_kernel_protocol::{
    ingress_request_digest, ActiveToolView, BeginRunRequest, BeginRunResponse, BootId, Digest32,
    IngestUserInputRequest, IngressRequestCommitmentV1, RunHandle, StableCode, ToolHandle,
    UnixMillis, ValueHandle,
};

use crate::engine::{
    unavailable, EngineInner, EngineState, HandleKind, HandleToken, IngressReplayEntry,
    IngressReplayKey, RegistryIdentity, RegistryState, RunRecord, StaleHandleRecord, ToolRecord,
    ValueRecord,
};
use crate::provenance::require_current_policy;
use crate::runtime::{AuthenticatedCallContext, RandomSource};
use crate::validate::{
    registry_identity_digest, PolicyIdentity, VerifiedIngressV1, VerifiedRegistrySnapshotV1,
};
use crate::PolicyError;

const MAX_LIVE_HANDLES: usize = 65_536;
const MAX_STALE_HANDLES: usize = 65_536;

pub(crate) fn begin_run_locked(
    inner: &EngineInner,
    state: &mut EngineState,
    context: &AuthenticatedCallContext,
    request: BeginRunRequest,
    wall: UnixMillis,
) -> Result<BeginRunResponse, PolicyError> {
    let current_policy = &state.current.policy;
    let current_identity = current_policy.identity();

    let ingress_bytes = minicbor::to_vec(&request.ingress).map_err(|_| unavailable())?;
    let verified = current_policy.verify_ingress(&ingress_bytes, wall)?;
    require_current_policy(&verified, current_identity)?;
    let request_digest = ingress_request_digest(&IngressRequestCommitmentV1::BeginRun {
        input: request.input.clone(),
    })?;
    require_ingress_binding(
        inner.boot_id,
        current_identity,
        context,
        &verified,
        request_digest,
    )?;

    let registry_bytes = minicbor::to_vec(&request.registry).map_err(|_| unavailable())?;
    let registry = current_policy.verify_registry_snapshot(&registry_bytes, wall)?;
    require_registry_policy(&registry, current_identity)?;
    if state
        .registry
        .as_ref()
        .is_some_and(|current| current.policy_identity != current_identity)
    {
        return Err(PolicyError::stable(StableCode::AttestationBindingMismatch));
    }
    let registry_identity = RegistryIdentity {
        digest: registry_identity_digest(registry.snapshot())?,
        version: registry.snapshot().version,
    };
    validate_registry_transition(state.registry.as_ref(), &registry, registry_identity)?;

    let mut active_identities = Vec::new();
    active_identities
        .try_reserve_exact(registry.snapshot().tools.len())
        .map_err(|_| unavailable())?;
    for tool in &registry.snapshot().tools {
        if tool.roles.iter().any(|role| role == verified.role())
            && current_policy.allows_registry_tool(tool)
        {
            active_identities.push((tool.identity.clone(), tool.identity.clone()));
        }
    }

    sweep_expired_security_state(state, wall)?;
    let replay_key = replay_key(&verified);
    require_fresh_replay(state, &replay_key)?;
    require_replay_capacity(state, context)?;
    require_run_capacity(state, context)?;
    require_handle_capacity(
        state,
        2_usize
            .checked_add(active_identities.len())
            .ok_or_else(unavailable)?,
    )?;

    let expires_at = UnixMillis::new(
        verified
            .expires_at()
            .get()
            .min(registry.snapshot().expires_at.get())
            .min(current_identity.expires_at.get()),
    );
    let run_record = RunRecord {
        boot_id: inner.boot_id,
        client_id: context.client_id.clone(),
        peer_uid: context.peer_uid,
        policy_identity: current_identity,
        generation: state.generation,
        principal: verified.principal().clone(),
        conversation_id: verified.conversation_id().clone(),
        role: verified.role().clone(),
        authority_session_id: verified.authority_session_id(),
        authentication_context_digest: verified.authentication_context_digest(),
        ingress_key_id: verified.key_id().clone(),
        ingress_nonce: verified.nonce(),
        registry_identity,
        expires_at,
    };
    let value_client = context.client_id.clone();
    let registry_state = RegistryState {
        identity: registry_identity,
        policy_identity: current_identity,
        expires_at: registry.snapshot().expires_at,
    };
    let replay_entry = IngressReplayEntry {
        client_id: context.client_id.clone(),
        expires_at: verified.expires_at(),
    };
    let replay_client = context.client_id.clone();
    let mut prepared_tools = Vec::new();
    prepared_tools
        .try_reserve_exact(active_identities.len())
        .map_err(|_| unavailable())?;
    for (view_identity, record_identity) in active_identities {
        prepared_tools.push((view_identity, record_identity, context.client_id.clone()));
    }

    state.runs.try_reserve(1).map_err(|_| unavailable())?;
    state.values.try_reserve(1).map_err(|_| unavailable())?;
    state
        .tools
        .try_reserve(prepared_tools.len())
        .map_err(|_| unavailable())?;
    state
        .handle_kinds
        .try_reserve(
            2_usize
                .checked_add(prepared_tools.len())
                .ok_or_else(unavailable)?,
        )
        .map_err(|_| unavailable())?;
    state
        .ingress_replay
        .try_reserve(1)
        .map_err(|_| unavailable())?;
    state
        .replay_per_client
        .try_reserve(1)
        .map_err(|_| unavailable())?;

    let handle_count = 2_usize
        .checked_add(prepared_tools.len())
        .ok_or_else(unavailable)?;
    let mut transaction_tokens = Vec::new();
    transaction_tokens
        .try_reserve_exact(handle_count)
        .map_err(|_| unavailable())?;
    let mut active_tools = Vec::new();
    active_tools
        .try_reserve_exact(prepared_tools.len())
        .map_err(|_| unavailable())?;
    let mut issued_tools = Vec::new();
    issued_tools
        .try_reserve_exact(prepared_tools.len())
        .map_err(|_| unavailable())?;
    let (run, run_token): (RunHandle, _) = issue_handle(
        inner.random.as_ref(),
        &state.handle_kinds,
        &state.stale_handles,
        &mut transaction_tokens,
    )?;
    let (initial_value, value_token): (ValueHandle, _) = issue_handle(
        inner.random.as_ref(),
        &state.handle_kinds,
        &state.stale_handles,
        &mut transaction_tokens,
    )?;
    for (view_identity, record_identity, tool_client) in prepared_tools {
        let (handle, token): (ToolHandle, _) = issue_handle(
            inner.random.as_ref(),
            &state.handle_kinds,
            &state.stale_handles,
            &mut transaction_tokens,
        )?;
        active_tools.push(ActiveToolView {
            handle,
            identity: view_identity,
        });
        issued_tools.push((token, record_identity, tool_client));
    }

    let value_record = ValueRecord {
        run,
        client_id: value_client,
        policy_identity: current_identity,
        value: request.input,
        provenance_digest: request_digest,
        expires_at,
    };
    state.registry = Some(registry_state);
    state
        .handle_kinds
        .insert(run_token.clone(), HandleKind::Run);
    state.runs.insert(run_token, run_record);
    state
        .handle_kinds
        .insert(value_token.clone(), HandleKind::Value);
    state.values.insert(value_token, value_record);
    for ((token, identity, client_id), view) in issued_tools.into_iter().zip(&active_tools) {
        state.handle_kinds.insert(token.clone(), HandleKind::Tool);
        state.tools.insert(
            token,
            ToolRecord {
                run,
                client_id,
                policy_identity: current_identity,
                identity,
                expires_at,
            },
        );
        debug_assert_eq!(view.identity.registry_version, registry_identity.version);
    }
    state.ingress_replay.insert(replay_key, replay_entry);
    *state.replay_per_client.entry(replay_client).or_insert(0) += 1;

    Ok(BeginRunResponse {
        run,
        initial_value,
        active_tools,
    })
}

pub(crate) fn ingest_user_input_locked(
    inner: &EngineInner,
    state: &mut EngineState,
    context: &AuthenticatedCallContext,
    request: IngestUserInputRequest,
    wall: UnixMillis,
) -> Result<ValueHandle, PolicyError> {
    let current_identity = state.current.policy.identity();
    let ingress_bytes = minicbor::to_vec(&request.envelope).map_err(|_| unavailable())?;
    let verified = state.current.policy.verify_ingress(&ingress_bytes, wall)?;
    require_current_policy(&verified, current_identity)?;
    let request_digest = ingress_request_digest(&IngressRequestCommitmentV1::IngestUserInput {
        run: request.run,
        input: request.input.clone(),
    })?;
    require_ingress_binding(
        inner.boot_id,
        current_identity,
        context,
        &verified,
        request_digest,
    )?;

    let run_token = handle_token(&request.run)?;
    let run = resolve_run(
        state,
        &run_token,
        context,
        &verified,
        current_identity,
        wall,
    )?;
    let run_expiry = run.expires_at;
    let run_handle = request.run;

    sweep_expired_security_state(state, wall)?;
    let replay_key = replay_key(&verified);
    require_fresh_replay(state, &replay_key)?;
    require_replay_capacity(state, context)?;
    require_handle_capacity(state, 1)?;
    let value_client = context.client_id.clone();
    let replay_client = context.client_id.clone();
    let replay_entry_client = context.client_id.clone();
    state.values.try_reserve(1).map_err(|_| unavailable())?;
    state
        .handle_kinds
        .try_reserve(1)
        .map_err(|_| unavailable())?;
    state
        .ingress_replay
        .try_reserve(1)
        .map_err(|_| unavailable())?;
    state
        .replay_per_client
        .try_reserve(1)
        .map_err(|_| unavailable())?;

    let mut transaction_tokens = Vec::new();
    transaction_tokens
        .try_reserve_exact(1)
        .map_err(|_| unavailable())?;
    let (value, value_token): (ValueHandle, _) = issue_handle(
        inner.random.as_ref(),
        &state.handle_kinds,
        &state.stale_handles,
        &mut transaction_tokens,
    )?;
    let expires_at = UnixMillis::new(
        run_expiry
            .get()
            .min(verified.expires_at().get())
            .min(current_identity.expires_at.get()),
    );
    let value_record = ValueRecord {
        run: run_handle,
        client_id: value_client,
        policy_identity: current_identity,
        value: request.input,
        provenance_digest: request_digest,
        expires_at,
    };
    let replay_entry = IngressReplayEntry {
        client_id: replay_entry_client,
        expires_at: verified.expires_at(),
    };

    state
        .handle_kinds
        .insert(value_token.clone(), HandleKind::Value);
    state.values.insert(value_token, value_record);
    state.ingress_replay.insert(replay_key, replay_entry);
    *state.replay_per_client.entry(replay_client).or_insert(0) += 1;
    Ok(value)
}

fn require_ingress_binding(
    engine_boot_id: BootId,
    current_policy: PolicyIdentity,
    context: &AuthenticatedCallContext,
    verified: &VerifiedIngressV1,
    expected_request_digest: Digest32,
) -> Result<(), PolicyError> {
    if verified.policy_digest() != current_policy.digest
        || verified.boot_id() != engine_boot_id
        || verified.connection_binding_digest() != context.connection_binding_digest
        || verified.request_digest() != expected_request_digest
        || verified.nonce().as_bytes() == &[0; 32]
        || verified.authority_session_id().as_bytes() == &[0; 32]
    {
        return Err(PolicyError::stable(StableCode::AttestationBindingMismatch));
    }
    Ok(())
}

fn require_registry_policy(
    verified: &VerifiedRegistrySnapshotV1,
    current: PolicyIdentity,
) -> Result<(), PolicyError> {
    require_current_policy(verified, current)
}

fn validate_registry_transition(
    current: Option<&RegistryState>,
    verified: &VerifiedRegistrySnapshotV1,
    next: RegistryIdentity,
) -> Result<(), PolicyError> {
    let snapshot = verified.snapshot();
    match current {
        None if snapshot.previous_digest.is_none() => Ok(()),
        None => Err(PolicyError::stable(StableCode::RegistryEquivocation)),
        Some(current) if next.version < current.identity.version => {
            Err(PolicyError::stable(StableCode::RegistryEquivocation))
        }
        Some(current) if next.version == current.identity.version => {
            if next.digest == current.identity.digest {
                Ok(())
            } else {
                Err(PolicyError::stable(StableCode::RegistryEquivocation))
            }
        }
        Some(current) if snapshot.previous_digest == Some(current.identity.digest) => Ok(()),
        Some(_) => Err(PolicyError::stable(StableCode::RegistryEquivocation)),
    }
}

fn resolve_run<'state>(
    state: &'state EngineState,
    token: &HandleToken,
    context: &AuthenticatedCallContext,
    ingress: &VerifiedIngressV1,
    current: PolicyIdentity,
    wall: UnixMillis,
) -> Result<&'state RunRecord, PolicyError> {
    match state.handle_kinds.get(token) {
        Some(HandleKind::Run) => {}
        Some(_) => return Err(PolicyError::stable(StableCode::HandleWrongType)),
        None if state
            .stale_handles
            .iter()
            .any(|record| record.token == *token) =>
        {
            return Err(PolicyError::stable(StableCode::HandleStalePolicy));
        }
        None => return Err(PolicyError::stable(StableCode::HandleUnknown)),
    }
    let run = state.runs.get(token).ok_or_else(unavailable)?;
    if run.client_id != context.client_id || run.peer_uid != context.peer_uid {
        return Err(PolicyError::stable(StableCode::HandleWrongClient));
    }
    if wall.get() >= run.expires_at.get() {
        return Err(PolicyError::stable(StableCode::AttestationExpired));
    }
    if run.boot_id != context.boot_id
        || run.policy_identity != current
        || run.generation != state.generation
        || run.principal != *ingress.principal()
        || run.conversation_id != *ingress.conversation_id()
        || run.role != *ingress.role()
        || run.authority_session_id != ingress.authority_session_id()
        || run.authentication_context_digest != ingress.authentication_context_digest()
        || run.boot_id != ingress.boot_id()
    {
        return Err(PolicyError::stable(StableCode::AttestationBindingMismatch));
    }
    Ok(run)
}

fn replay_key(verified: &VerifiedIngressV1) -> IngressReplayKey {
    IngressReplayKey {
        authority_key_id: verified.key_id().clone(),
        nonce: verified.nonce(),
    }
}

fn require_fresh_replay(state: &EngineState, key: &IngressReplayKey) -> Result<(), PolicyError> {
    if state.ingress_replay.contains_key(key) {
        return Err(PolicyError::stable(StableCode::AttestationBindingMismatch));
    }
    Ok(())
}

fn require_replay_capacity(
    state: &EngineState,
    context: &AuthenticatedCallContext,
) -> Result<(), PolicyError> {
    let per_client_limit = state
        .current
        .policy
        .effective_limits()
        .ingress_replay_entries_per_client();
    if state.ingress_replay.len() >= state.global_replay_limit
        || state
            .replay_per_client
            .get(&context.client_id)
            .copied()
            .unwrap_or(0)
            >= per_client_limit
    {
        return Err(PolicyError::stable(StableCode::KernelOverloaded));
    }
    Ok(())
}

fn require_run_capacity(
    state: &EngineState,
    context: &AuthenticatedCallContext,
) -> Result<(), PolicyError> {
    let per_client_limit = state.current.policy.effective_limits().runs_per_client();
    let client_runs = state
        .runs
        .values()
        .filter(|run| run.client_id == context.client_id)
        .count();
    if state.runs.len() >= state.global_run_limit
        || u64::try_from(client_runs).map_err(|_| unavailable())? >= per_client_limit
    {
        return Err(PolicyError::stable(StableCode::KernelOverloaded));
    }
    Ok(())
}

fn require_handle_capacity(state: &EngineState, additional: usize) -> Result<(), PolicyError> {
    let next = state
        .handle_kinds
        .len()
        .checked_add(additional)
        .ok_or_else(unavailable)?;
    let total = next
        .checked_add(state.stale_handles.len())
        .ok_or_else(unavailable)?;
    if next > MAX_LIVE_HANDLES
        || state.stale_handles.len() > MAX_STALE_HANDLES
        || total > MAX_STALE_HANDLES
    {
        return Err(PolicyError::stable(StableCode::KernelOverloaded));
    }
    Ok(())
}

fn sweep_expired_security_state(
    state: &mut EngineState,
    wall: UnixMillis,
) -> Result<(), PolicyError> {
    for (client, expected) in &state.replay_per_client {
        let actual = state
            .ingress_replay
            .values()
            .filter(|entry| entry.client_id == *client)
            .count();
        if u64::try_from(actual).map_err(|_| unavailable())? != *expected {
            return Err(unavailable());
        }
    }
    if state
        .ingress_replay
        .values()
        .any(|entry| !state.replay_per_client.contains_key(&entry.client_id))
    {
        return Err(unavailable());
    }
    state
        .ingress_replay
        .retain(|_, entry| entry.expires_at.get() > wall.get());
    state.replay_per_client.clear();
    for entry in state.ingress_replay.values() {
        let count = state
            .replay_per_client
            .entry(entry.client_id.clone())
            .or_insert(0);
        *count = count.checked_add(1).ok_or_else(unavailable)?;
    }
    state
        .stale_handles
        .retain(|record| record.expires_at.get() > wall.get());
    Ok(())
}

fn handle_token<T: minicbor::Encode<()>>(handle: &T) -> Result<HandleToken, PolicyError> {
    let encoded = minicbor::to_vec(handle).map_err(|_| unavailable())?;
    if encoded.len() != 34 || encoded[0] != 0x58 || encoded[1] != 0x20 {
        return Err(unavailable());
    }
    let bytes: [u8; 32] = encoded[2..].try_into().map_err(|_| unavailable())?;
    Ok(HandleToken(bytes))
}

fn issue_handle<T>(
    random: &dyn RandomSource,
    occupied: &HashMap<HandleToken, HandleKind>,
    stale: &[StaleHandleRecord],
    transaction_tokens: &mut Vec<HandleToken>,
) -> Result<(T, HandleToken), PolicyError>
where
    for<'bytes> T: minicbor::Decode<'bytes, ()>,
{
    let mut token = [0_u8; 32];
    let written = random.fill(&mut token).map_err(|_| unavailable())?;
    if written != token.len() || token == [0; 32] {
        return Err(unavailable());
    }
    let key = HandleToken(token);
    if occupied.contains_key(&key)
        || stale.iter().any(|record| record.token == key)
        || transaction_tokens.contains(&key)
    {
        return Err(unavailable());
    }
    let mut encoded = [0_u8; 34];
    encoded[0] = 0x58;
    encoded[1] = 0x20;
    encoded[2..].copy_from_slice(&key.0);
    let handle = minicbor::decode::<T>(&encoded).map_err(|_| unavailable())?;
    transaction_tokens.push(key.clone());
    Ok((handle, key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use savana_kernel_protocol::{KernelValue, Nonce32, RegistrySnapshotV1, Signature64};
    use sha2::{Digest, Sha256};
    use std::sync::{mpsc, Arc};
    use std::time::Duration;

    #[test]
    fn empty_registry_identity_matches_the_normative_vector() {
        let snapshot = RegistrySnapshotV1 {
            version: 1,
            previous_digest: None,
            tools: Vec::new(),
            issued_at: UnixMillis::new(1_000),
            expires_at: UnixMillis::new(3_000),
        };
        assert_eq!(
            hex(&minicbor::to_vec(&snapshot).unwrap()),
            "8501f6801903e8190bb8"
        );
        assert_eq!(
            hex(registry_identity_digest(&snapshot).unwrap().as_bytes()),
            "f7cd24b33cd5cbfa8c04d913f55175c6dd3d54fa6873a3c3d541dddc233acc38"
        );
    }

    #[test]
    fn registry_signature_is_over_signing_bytes_not_identity_digest() {
        let snapshot = RegistrySnapshotV1 {
            version: 1,
            previous_digest: None,
            tools: Vec::new(),
            issued_at: UnixMillis::new(1_000),
            expires_at: UnixMillis::new(3_000),
        };
        let key = SigningKey::from_bytes(&[0x72; 32]);
        let message = crate::validate::registry_signing_bytes(&snapshot).unwrap();
        let signature = Signature64::new(key.sign(&message).to_bytes());
        crate::signature::verify_signature_message(
            &message,
            &signature,
            &key.verifying_key().to_bytes(),
            StableCode::RegistryInvalidSignature,
        )
        .unwrap();
        let digest = Sha256::digest(&message);
        assert_eq!(
            crate::signature::verify_signature_message(
                &digest,
                &signature,
                &key.verifying_key().to_bytes(),
                StableCode::RegistryInvalidSignature,
            )
            .unwrap_err()
            .code(),
            StableCode::RegistryInvalidSignature
        );
    }

    #[test]
    fn handle_issuance_rejects_live_stale_and_same_transaction_collisions() {
        struct Fixed([u8; 32]);
        impl RandomSource for Fixed {
            fn fill(&self, output: &mut [u8]) -> Result<usize, StableCode> {
                output.copy_from_slice(&self.0);
                Ok(output.len())
            }
        }
        let token = HandleToken([7; 32]);
        let mut occupied = HashMap::new();
        occupied.insert(token.clone(), HandleKind::Run);
        let mut transaction = Vec::with_capacity(1);
        assert_eq!(
            issue_handle::<RunHandle>(&Fixed([7; 32]), &occupied, &[], &mut transaction)
                .unwrap_err()
                .code(),
            StableCode::KernelUnavailable
        );
        occupied.clear();
        let stale = [StaleHandleRecord {
            token: token.clone(),
            kind: HandleKind::Run,
            expires_at: UnixMillis::new(3_000),
        }];
        assert_eq!(
            issue_handle::<RunHandle>(&Fixed([7; 32]), &occupied, &stale, &mut transaction)
                .unwrap_err()
                .code(),
            StableCode::KernelUnavailable
        );
        transaction.push(token);
        assert_eq!(
            issue_handle::<RunHandle>(&Fixed([7; 32]), &occupied, &[], &mut transaction)
                .unwrap_err()
                .code(),
            StableCode::KernelUnavailable
        );
    }

    #[test]
    fn run_and_replay_limits_are_independent_and_exact() {
        let fixture = crate::test_support::IngressFixture::with_limits(1, 2);
        let first = fixture
            .engine
            .begin_run(
                &fixture.context,
                fixture.begin_request("operator", KernelValue::Null),
            )
            .unwrap();
        assert_eq!(
            fixture
                .engine
                .begin_run(
                    &fixture.context,
                    fixture.begin_request("operator", KernelValue::Null),
                )
                .unwrap_err()
                .code(),
            StableCode::KernelOverloaded
        );
        {
            let mut state = fixture.engine.inner.state.write().unwrap();
            let token = handle_token(&first.run).unwrap();
            state.runs.remove(&token);
            state.handle_kinds.remove(&token);
        }
        assert!(fixture
            .engine
            .begin_run(
                &fixture.context,
                fixture.begin_request("operator", KernelValue::Null),
            )
            .is_ok());
        assert_eq!(
            fixture
                .engine
                .begin_run(
                    &fixture.context,
                    fixture.begin_request("operator", KernelValue::Null),
                )
                .unwrap_err()
                .code(),
            StableCode::KernelOverloaded
        );
        let state = fixture.engine.inner.state.read().unwrap();
        assert_eq!(state.ingress_replay.len(), 2);
        assert_eq!(state.runs.len(), 1);
    }

    #[test]
    fn dispatch_waiting_for_engine_state_rechecks_wall_expiry() {
        for case in [
            "begin-policy",
            "begin-ingress",
            "begin-registry",
            "ingest-policy",
            "ingest-ingress",
        ] {
            let fixture = Arc::new(crate::test_support::IngressFixture::new());
            let run = if case.starts_with("ingest") {
                Some(
                    fixture
                        .engine
                        .begin_run(
                            &fixture.context,
                            fixture.begin_request("operator", KernelValue::Null),
                        )
                        .unwrap()
                        .run,
                )
            } else {
                None
            };
            let mut begin = fixture.begin_request("operator", KernelValue::Null);
            let ingest = run.map(|run| fixture.ingest_request(run, KernelValue::Bool(true)));
            let exact_wall = match case {
                "begin-registry" => {
                    begin.registry.unsigned.expires_at = UnixMillis::new(2_500);
                    crate::test_support::resign_registry(&mut begin.registry);
                    2_500
                }
                value if value.ends_with("policy") => 4_000,
                _ => 3_000,
            };
            let before = security_counts(&fixture.engine.inner.state.read().unwrap());
            let held = fixture.engine.inner.state.write().unwrap();
            let (entered_tx, entered_rx) = mpsc::sync_channel(1);
            fixture
                .engine
                .inner
                .install_dispatch_pre_state_lock_hook(Box::new(move || {
                    entered_tx.send(()).unwrap();
                }));
            let waiting_fixture = Arc::clone(&fixture);
            let waiting = std::thread::spawn(move || match ingest {
                Some(request) => waiting_fixture
                    .engine
                    .ingest_user_input(&waiting_fixture.context, request)
                    .map(|_| ()),
                None => waiting_fixture
                    .engine
                    .begin_run(&waiting_fixture.context, begin)
                    .map(|_| ()),
            });
            entered_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("dispatch never reached state-lock boundary");
            fixture.clock.set(exact_wall, 200);
            drop(held);
            let expected = if case.ends_with("policy") {
                StableCode::PolicyExpired
            } else {
                StableCode::AttestationExpired
            };
            assert_eq!(
                waiting.join().unwrap().unwrap_err().code(),
                expected,
                "{case}"
            );
            assert_eq!(
                security_counts(&fixture.engine.inner.state.read().unwrap()),
                before,
                "{case}"
            );
        }
    }

    #[test]
    fn pairwise_faults_freeze_ingress_registry_replay_and_capacity_precedence() {
        let fixture = crate::test_support::IngressFixture::new();
        let mut bad_signature = fixture.begin_request("operator", KernelValue::Null);
        bad_signature.ingress.signature = Signature64::new([0; 64]);
        fixture.clock.set(4_000, 200);
        assert_eq!(
            fixture
                .engine
                .begin_run(&fixture.context, bad_signature)
                .unwrap_err()
                .code(),
            StableCode::PolicyExpired
        );
        assert_eq!(
            security_counts(&fixture.engine.inner.state.read().unwrap()),
            (0, 0, 0, 0, 0, 0)
        );

        let fixture = crate::test_support::IngressFixture::new();
        let mut expired_and_bad = fixture.begin_request("operator", KernelValue::Null);
        expired_and_bad.ingress.unsigned.expires_at = UnixMillis::new(2_000);
        expired_and_bad.ingress.signature = Signature64::new([0; 64]);
        assert_eq!(
            fixture
                .engine
                .begin_run(&fixture.context, expired_and_bad)
                .unwrap_err()
                .code(),
            StableCode::AttestationInvalidSignature
        );

        let fixture = crate::test_support::IngressFixture::new();
        let mut expired_and_wrong = fixture.begin_request("operator", KernelValue::Null);
        expired_and_wrong.ingress.unsigned.expires_at = UnixMillis::new(2_000);
        expired_and_wrong.ingress.unsigned.connection_binding_digest = Digest32::new([9; 32]);
        crate::test_support::resign_ingress(&mut expired_and_wrong.ingress);
        assert_eq!(
            fixture
                .engine
                .begin_run(&fixture.context, expired_and_wrong)
                .unwrap_err()
                .code(),
            StableCode::AttestationExpired
        );

        let fixture = crate::test_support::IngressFixture::new();
        let mut wrong_and_bad_registry = fixture.begin_request("operator", KernelValue::Null);
        wrong_and_bad_registry
            .ingress
            .unsigned
            .connection_binding_digest = Digest32::new([9; 32]);
        crate::test_support::resign_ingress(&mut wrong_and_bad_registry.ingress);
        wrong_and_bad_registry.registry.signature = Signature64::new([0; 64]);
        assert_eq!(
            fixture
                .engine
                .begin_run(&fixture.context, wrong_and_bad_registry)
                .unwrap_err()
                .code(),
            StableCode::AttestationBindingMismatch
        );

        let fixture = crate::test_support::IngressFixture::with_limits(1, 2);
        let request = fixture.begin_request("operator", KernelValue::Null);
        fixture
            .engine
            .begin_run(&fixture.context, request.clone())
            .unwrap();
        let mut bad_registry = request.clone();
        bad_registry.registry.signature = Signature64::new([0; 64]);
        assert_eq!(
            fixture
                .engine
                .begin_run(&fixture.context, bad_registry)
                .unwrap_err()
                .code(),
            StableCode::RegistryInvalidSignature
        );
        assert_eq!(
            fixture
                .engine
                .begin_run(&fixture.context, request.clone())
                .unwrap_err()
                .code(),
            StableCode::AttestationBindingMismatch
        );
        let mut equivocation = request;
        equivocation.registry.unsigned.expires_at = UnixMillis::new(2_999);
        crate::test_support::resign_registry(&mut equivocation.registry);
        assert_eq!(
            fixture
                .engine
                .begin_run(&fixture.context, equivocation)
                .unwrap_err()
                .code(),
            StableCode::RegistryEquivocation
        );
        assert_eq!(
            security_counts(&fixture.engine.inner.state.read().unwrap()),
            (1, 1, 1, 1, 3, 1)
        );
    }

    #[test]
    fn remaining_pairwise_faults_keep_security_state_unchanged() {
        let fixture = crate::test_support::IngressFixture::new();
        let mut expired_zero = fixture.begin_request("operator", KernelValue::Null);
        expired_zero.ingress.unsigned.expires_at = UnixMillis::new(2_000);
        expired_zero.ingress.unsigned.nonce = Nonce32::new([0; 32]);
        crate::test_support::resign_ingress(&mut expired_zero.ingress);
        let before = security_counts(&fixture.engine.inner.state.read().unwrap());
        assert_eq!(
            fixture
                .engine
                .begin_run(&fixture.context, expired_zero)
                .unwrap_err()
                .code(),
            StableCode::AttestationExpired
        );
        assert_eq!(
            security_counts(&fixture.engine.inner.state.read().unwrap()),
            before
        );

        let fixture = crate::test_support::IngressFixture::new();
        let request = fixture.begin_request("operator", KernelValue::Null);
        fixture
            .engine
            .begin_run(&fixture.context, request.clone())
            .unwrap();
        let mut wrong_binding = request.clone();
        wrong_binding.ingress.unsigned.connection_binding_digest = Digest32::new([0x93; 32]);
        crate::test_support::resign_ingress(&mut wrong_binding.ingress);
        let before = security_counts(&fixture.engine.inner.state.read().unwrap());
        assert_eq!(
            fixture
                .engine
                .begin_run(&fixture.context, wrong_binding)
                .unwrap_err()
                .code(),
            StableCode::AttestationBindingMismatch
        );
        assert_eq!(
            security_counts(&fixture.engine.inner.state.read().unwrap()),
            before
        );

        let fixture = crate::test_support::IngressFixture::new();
        let mut bad_and_expired_registry = fixture.begin_request("operator", KernelValue::Null);
        bad_and_expired_registry.registry.unsigned.expires_at = UnixMillis::new(2_000);
        bad_and_expired_registry.registry.signature = Signature64::new([0; 64]);
        let before = security_counts(&fixture.engine.inner.state.read().unwrap());
        assert_eq!(
            fixture
                .engine
                .begin_run(&fixture.context, bad_and_expired_registry)
                .unwrap_err()
                .code(),
            StableCode::RegistryInvalidSignature
        );
        assert_eq!(
            security_counts(&fixture.engine.inner.state.read().unwrap()),
            before
        );

        let fixture = crate::test_support::IngressFixture::new();
        let request = fixture.begin_request("operator", KernelValue::Null);
        fixture
            .engine
            .begin_run(&fixture.context, request.clone())
            .unwrap();
        let mut expired_registry = request.clone();
        expired_registry.registry.unsigned.expires_at = UnixMillis::new(2_000);
        crate::test_support::resign_registry(&mut expired_registry.registry);
        let before = security_counts(&fixture.engine.inner.state.read().unwrap());
        assert_eq!(
            fixture
                .engine
                .begin_run(&fixture.context, expired_registry)
                .unwrap_err()
                .code(),
            StableCode::AttestationExpired
        );
        assert_eq!(
            security_counts(&fixture.engine.inner.state.read().unwrap()),
            before
        );

        let fixture = crate::test_support::IngressFixture::new();
        let request = fixture.begin_request("operator", KernelValue::Null);
        fixture
            .engine
            .begin_run(&fixture.context, request.clone())
            .unwrap();
        {
            let mut state = fixture.engine.inner.state.write().unwrap();
            state.registry.as_mut().unwrap().policy_identity.expires_at = UnixMillis::new(3_999);
        }
        let before = security_counts(&fixture.engine.inner.state.read().unwrap());
        assert_eq!(
            fixture
                .engine
                .begin_run(&fixture.context, request)
                .unwrap_err()
                .code(),
            StableCode::AttestationBindingMismatch
        );
        assert_eq!(
            security_counts(&fixture.engine.inner.state.read().unwrap()),
            before
        );

        let fixture = crate::test_support::IngressFixture::with_limits(1, 2);
        let request = fixture.begin_request("operator", KernelValue::Null);
        fixture
            .engine
            .begin_run(&fixture.context, request.clone())
            .unwrap();
        let before = security_counts(&fixture.engine.inner.state.read().unwrap());
        assert_eq!(
            fixture
                .engine
                .begin_run(&fixture.context, request)
                .unwrap_err()
                .code(),
            StableCode::AttestationBindingMismatch
        );
        assert_eq!(
            security_counts(&fixture.engine.inner.state.read().unwrap()),
            before
        );
    }

    #[test]
    fn ingest_rejects_role_session_auth_context_and_cross_run_substitution() {
        let fixture = crate::test_support::IngressFixture::new();
        let run = fixture
            .engine
            .begin_run(
                &fixture.context,
                fixture.begin_request("operator", KernelValue::Null),
            )
            .unwrap()
            .run;
        let other = fixture
            .engine
            .begin_run(
                &fixture.context,
                fixture.begin_request("operator", KernelValue::Null),
            )
            .unwrap()
            .run;
        for mutation in 0..4 {
            let mut request = fixture.ingest_request(run, KernelValue::Bool(true));
            match mutation {
                0 => {
                    request.envelope.unsigned.role =
                        savana_kernel_protocol::RoleId::new("other").unwrap()
                }
                1 => request.envelope.unsigned.authority_session_id = Nonce32::new([0x91; 32]),
                2 => {
                    request.envelope.unsigned.authentication_context_digest =
                        Digest32::new([0x92; 32])
                }
                3 => request.run = other,
                _ => unreachable!(),
            }
            crate::test_support::resign_ingress(&mut request.envelope);
            assert_eq!(
                fixture
                    .engine
                    .ingest_user_input(&fixture.context, request)
                    .unwrap_err()
                    .code(),
                StableCode::AttestationBindingMismatch
            );
        }
    }

    #[test]
    fn zero_nonce_and_exact_replay_boundary_fail_closed() {
        let fixture = crate::test_support::IngressFixture::new();
        let mut zero = fixture.begin_request("operator", KernelValue::Null);
        zero.ingress.unsigned.nonce = Nonce32::new([0; 32]);
        crate::test_support::resign_ingress(&mut zero.ingress);
        assert_eq!(
            fixture
                .engine
                .begin_run(&fixture.context, zero)
                .unwrap_err()
                .code(),
            StableCode::AttestationBindingMismatch
        );
        {
            let mut state = fixture.engine.inner.state.write().unwrap();
            for value in 10_000_u64..14_096 {
                let mut nonce = [0_u8; 32];
                nonce[..8].copy_from_slice(&value.to_be_bytes());
                state.ingress_replay.insert(
                    IngressReplayKey {
                        authority_key_id: savana_kernel_protocol::KeyId::new("role-00").unwrap(),
                        nonce: Nonce32::new(nonce),
                    },
                    IngressReplayEntry {
                        client_id: savana_kernel_protocol::ClientId::new("jarvis-client").unwrap(),
                        expires_at: UnixMillis::new(3_000),
                    },
                );
            }
            state.replay_per_client.insert(
                savana_kernel_protocol::ClientId::new("jarvis-client").unwrap(),
                4_096,
            );
        }
        assert_eq!(
            fixture
                .engine
                .begin_run(
                    &fixture.context,
                    fixture.begin_request("operator", KernelValue::Null),
                )
                .unwrap_err()
                .code(),
            StableCode::KernelOverloaded
        );
        let state = fixture.engine.inner.state.read().unwrap();
        assert_eq!(state.ingress_replay.len(), 4_096);
        assert!(state.runs.is_empty());
        assert!(state.handle_kinds.is_empty());
    }

    #[test]
    fn checked_global_initialization_accepts_only_the_frozen_envelope() {
        assert_eq!(
            crate::engine::checked_engine_limits(16, 4_096, 128).unwrap(),
            (65_536, 2_048)
        );
        assert_eq!(
            crate::engine::checked_engine_limits(17, 1, 1)
                .unwrap_err()
                .code(),
            StableCode::KernelUnavailable
        );
        assert_eq!(
            crate::engine::checked_engine_limits(16, 4_097, 1)
                .unwrap_err()
                .code(),
            StableCode::KernelUnavailable
        );
        assert_eq!(
            crate::engine::checked_engine_limits(0, 4_096, 128)
                .unwrap_err()
                .code(),
            StableCode::KernelUnavailable
        );
    }

    fn security_counts(state: &EngineState) -> (usize, usize, usize, usize, usize, usize) {
        (
            state.runs.len(),
            state.values.len(),
            state.tools.len(),
            state.ingress_replay.len(),
            state.handle_kinds.len(),
            usize::from(state.registry.is_some()),
        )
    }

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;

        bytes.iter().fold(String::new(), |mut output, byte| {
            write!(output, "{byte:02x}").unwrap();
            output
        })
    }
}
