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

    let replay_key = replay_key(&verified);
    let next_replay_per_client =
        prepare_replay_commit(state, &replay_key, &context.client_id, wall)?;
    require_run_capacity(state, context)?;
    require_handle_capacity(
        state,
        2_usize
            .checked_add(active_identities.len())
            .ok_or_else(unavailable)?,
        wall,
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
        wall,
        &mut transaction_tokens,
    )?;
    let (initial_value, value_token): (ValueHandle, _) = issue_handle(
        inner.random.as_ref(),
        &state.handle_kinds,
        &state.stale_handles,
        wall,
        &mut transaction_tokens,
    )?;
    for (view_identity, record_identity, tool_client) in prepared_tools {
        let (handle, token): (ToolHandle, _) = issue_handle(
            inner.random.as_ref(),
            &state.handle_kinds,
            &state.stale_handles,
            wall,
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
    commit_expired_security_state(state, wall, next_replay_per_client);
    state.registry = Some(registry_state);
    state
        .handle_kinds
        .insert(run_token.clone(), HandleKind::Run);
    state.runs.insert(run_token, run_record);
    state
        .handle_kinds
        .insert(value_token.clone(), HandleKind::Value);
    state.values.insert(value_token, value_record);
    for (token, identity, client_id) in issued_tools {
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
    }
    state.ingress_replay.insert(replay_key, replay_entry);

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

    let replay_key = replay_key(&verified);
    let next_replay_per_client =
        prepare_replay_commit(state, &replay_key, &context.client_id, wall)?;
    require_handle_capacity(state, 1, wall)?;
    let value_client = context.client_id.clone();
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

    let mut transaction_tokens = Vec::new();
    transaction_tokens
        .try_reserve_exact(1)
        .map_err(|_| unavailable())?;
    let (value, value_token): (ValueHandle, _) = issue_handle(
        inner.random.as_ref(),
        &state.handle_kinds,
        &state.stale_handles,
        wall,
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

    commit_expired_security_state(state, wall, next_replay_per_client);
    state
        .handle_kinds
        .insert(value_token.clone(), HandleKind::Value);
    state.values.insert(value_token, value_record);
    state.ingress_replay.insert(replay_key, replay_entry);
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
    require_client_handle_kind(state, token, HandleKind::Run, wall, &context.client_id)?;
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

fn require_client_handle_kind(
    state: &EngineState,
    token: &HandleToken,
    expected: HandleKind,
    wall: UnixMillis,
    client_id: &savana_kernel_protocol::ClientId,
) -> Result<(), PolicyError> {
    let kind = state.handle_kinds.get(token);
    let owner = live_handle_owner(state, token)?;
    let (kind, (record_kind, record_client)) = match (kind, owner) {
        (None, None) => return require_handle_kind(state, token, expected, wall),
        (Some(kind), Some(owner)) => (kind, owner),
        _ => return Err(unavailable()),
    };
    if *kind != record_kind {
        return Err(unavailable());
    }
    if record_client != client_id {
        return Err(PolicyError::stable(StableCode::HandleWrongClient));
    }
    if *kind != expected {
        return Err(PolicyError::stable(StableCode::HandleWrongType));
    }
    Ok(())
}

fn live_handle_owner<'state>(
    state: &'state EngineState,
    token: &HandleToken,
) -> Result<Option<(HandleKind, &'state savana_kernel_protocol::ClientId)>, PolicyError> {
    match (
        state.runs.get(token),
        state.values.get(token),
        state.tools.get(token),
    ) {
        (None, None, None) => Ok(None),
        (Some(record), None, None) => Ok(Some((HandleKind::Run, &record.client_id))),
        (None, Some(record), None) => Ok(Some((HandleKind::Value, &record.client_id))),
        (None, None, Some(record)) => Ok(Some((HandleKind::Tool, &record.client_id))),
        _ => Err(unavailable()),
    }
}

fn require_handle_kind(
    state: &EngineState,
    token: &HandleToken,
    expected: HandleKind,
    wall: UnixMillis,
) -> Result<(), PolicyError> {
    match state.handle_kinds.get(token) {
        Some(kind) if *kind == expected => Ok(()),
        Some(_) => Err(PolicyError::stable(StableCode::HandleWrongType)),
        None if state
            .stale_handles
            .iter()
            .any(|record| record.expires_at.get() > wall.get() && record.token == *token) =>
        {
            Err(PolicyError::stable(StableCode::HandleStalePolicy))
        }
        None => Err(PolicyError::stable(StableCode::HandleUnknown)),
    }
}

fn replay_key(verified: &VerifiedIngressV1) -> IngressReplayKey {
    IngressReplayKey {
        authority_key_id: verified.key_id().clone(),
        nonce: verified.nonce(),
    }
}

fn prepare_replay_commit(
    state: &EngineState,
    key: &IngressReplayKey,
    client_id: &savana_kernel_protocol::ClientId,
    wall: UnixMillis,
) -> Result<HashMap<savana_kernel_protocol::ClientId, u64>, PolicyError> {
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
    if state
        .ingress_replay
        .get(key)
        .is_some_and(|entry| entry.expires_at.get() > wall.get())
    {
        return Err(PolicyError::stable(StableCode::AttestationBindingMismatch));
    }

    let mut next = HashMap::new();
    next.try_reserve(
        state
            .replay_per_client
            .len()
            .checked_add(1)
            .ok_or_else(unavailable)?,
    )
    .map_err(|_| unavailable())?;
    let mut active = 0_usize;
    for entry in state
        .ingress_replay
        .values()
        .filter(|entry| entry.expires_at.get() > wall.get())
    {
        active = active.checked_add(1).ok_or_else(unavailable)?;
        let count = next.entry(entry.client_id.clone()).or_insert(0_u64);
        *count = count.checked_add(1).ok_or_else(unavailable)?;
    }
    let per_client_limit = state
        .current
        .policy
        .effective_limits()
        .ingress_replay_entries_per_client();
    if active >= state.global_replay_limit
        || next.get(client_id).copied().unwrap_or(0) >= per_client_limit
    {
        return Err(PolicyError::stable(StableCode::KernelOverloaded));
    }
    let count = next.entry(client_id.clone()).or_insert(0);
    *count = count.checked_add(1).ok_or_else(unavailable)?;
    Ok(next)
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

fn require_handle_capacity(
    state: &EngineState,
    additional: usize,
    wall: UnixMillis,
) -> Result<(), PolicyError> {
    let next = state
        .handle_kinds
        .len()
        .checked_add(additional)
        .ok_or_else(unavailable)?;
    let active_stale = state
        .stale_handles
        .iter()
        .filter(|record| record.expires_at.get() > wall.get())
        .count();
    let total = next.checked_add(active_stale).ok_or_else(unavailable)?;
    if next > MAX_LIVE_HANDLES || active_stale > MAX_STALE_HANDLES || total > MAX_STALE_HANDLES {
        return Err(PolicyError::stable(StableCode::KernelOverloaded));
    }
    Ok(())
}

fn commit_expired_security_state(
    state: &mut EngineState,
    wall: UnixMillis,
    next_replay_per_client: HashMap<savana_kernel_protocol::ClientId, u64>,
) {
    state
        .ingress_replay
        .retain(|_, entry| entry.expires_at.get() > wall.get());
    state.replay_per_client = next_replay_per_client;
    state
        .stale_handles
        .retain(|record| record.expires_at.get() > wall.get());
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
    wall: UnixMillis,
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
        || stale
            .iter()
            .any(|record| record.expires_at.get() > wall.get() && record.token == key)
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
    use crate::{Clock, PolicyEngine};
    use ed25519_dalek::{Signer, SigningKey};
    use savana_kernel_protocol::{KernelValue, Nonce32, RegistrySnapshotV1, Signature64};
    use sha2::{Digest, Sha256};
    use std::collections::VecDeque;
    use std::sync::{mpsc, Arc, Barrier, Mutex};
    use std::time::Duration;

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct SecuritySnapshot {
        replay: Vec<(IngressReplayKey, IngressReplayEntry)>,
        replay_per_client: Vec<(savana_kernel_protocol::ClientId, u64)>,
        stale: Vec<StaleHandleRecord>,
        registry: Option<RegistryState>,
        handle_kinds: Vec<(HandleToken, HandleKind)>,
        runs: Vec<(HandleToken, RunRecord)>,
        values: Vec<(HandleToken, ValueRecord)>,
        tools: Vec<(HandleToken, ToolRecord)>,
    }

    enum RandomStep {
        Fill([u8; 32]),
        Error,
    }

    struct ScriptedRandom(Mutex<VecDeque<RandomStep>>);

    impl ScriptedRandom {
        fn new(steps: impl IntoIterator<Item = RandomStep>) -> Self {
            Self(Mutex::new(steps.into_iter().collect()))
        }
    }

    impl RandomSource for ScriptedRandom {
        fn fill(&self, output: &mut [u8]) -> Result<usize, StableCode> {
            match self
                .0
                .lock()
                .unwrap()
                .pop_front()
                .expect("random script exhausted")
            {
                RandomStep::Fill(bytes) => {
                    output.copy_from_slice(&bytes);
                    Ok(output.len())
                }
                RandomStep::Error => Err(StableCode::ProtocolIo),
            }
        }
    }

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
    fn role_intersection_requires_policy_name_digest_and_exact_role_bytes() {
        for mutation in 0..3 {
            let fixture = crate::test_support::IngressFixture::new();
            let mut request = fixture.begin_request("operator", KernelValue::Null);
            match mutation {
                0 => {
                    request.registry.unsigned.tools[0].identity.name =
                        savana_kernel_protocol::ToolName::new("evil").unwrap();
                    request.registry.unsigned.tools[0]
                        .identity
                        .descriptor_digest = Digest32::new([0xe1; 32]);
                }
                1 => {
                    request.registry.unsigned.tools[0]
                        .identity
                        .descriptor_digest = Digest32::new([0xe2; 32]);
                }
                2 => {
                    request.registry.unsigned.tools[0].roles =
                        vec![savana_kernel_protocol::RoleId::new("Operator").unwrap()];
                }
                _ => unreachable!(),
            }
            crate::test_support::resign_registry(&mut request.registry);
            assert!(
                fixture
                    .engine
                    .begin_run(&fixture.context, request)
                    .unwrap()
                    .active_tools
                    .is_empty(),
                "mutation {mutation} must not activate a tool"
            );
        }
    }

    #[test]
    fn registry_chain_accepts_only_initial_equal_and_exact_higher_transitions() {
        let fixture = crate::test_support::IngressFixture::new();
        let mut forbidden_initial = fixture.begin_request("operator", KernelValue::Null);
        forbidden_initial.registry.unsigned.previous_digest = Some(Digest32::new([0xf1; 32]));
        crate::test_support::resign_registry(&mut forbidden_initial.registry);
        assert_eq!(
            fixture
                .engine
                .begin_run(&fixture.context, forbidden_initial)
                .unwrap_err()
                .code(),
            StableCode::RegistryEquivocation
        );
        assert!(fixture
            .engine
            .inner
            .state
            .read()
            .unwrap()
            .registry
            .is_none());

        let initial = crate::test_support::signed_registry();
        let initial_digest = registry_identity_digest(&initial.unsigned).unwrap();
        let mut first = fixture.begin_request("operator", KernelValue::Null);
        first.registry = initial.clone();
        fixture.engine.begin_run(&fixture.context, first).unwrap();

        let mut equal = fixture.begin_request("operator", KernelValue::Null);
        equal.registry = initial.clone();
        fixture.engine.begin_run(&fixture.context, equal).unwrap();

        let mut changed = fixture.begin_request("operator", KernelValue::Null);
        changed.registry.unsigned.expires_at = UnixMillis::new(2_999);
        crate::test_support::resign_registry(&mut changed.registry);
        let before_changed = security_snapshot(&fixture.engine.inner.state.read().unwrap());
        assert_eq!(
            fixture
                .engine
                .begin_run(&fixture.context, changed)
                .unwrap_err()
                .code(),
            StableCode::RegistryEquivocation
        );
        assert_eq!(
            security_snapshot(&fixture.engine.inner.state.read().unwrap()),
            before_changed
        );

        let mut higher = fixture.begin_request("operator", KernelValue::Null);
        higher.registry.unsigned.version = 2;
        higher.registry.unsigned.previous_digest = Some(initial_digest);
        higher.registry.unsigned.tools[0].identity.registry_version = 2;
        crate::test_support::resign_registry(&mut higher.registry);
        fixture.engine.begin_run(&fixture.context, higher).unwrap();

        let mut wrong_previous = fixture.begin_request("operator", KernelValue::Null);
        wrong_previous.registry.unsigned.version = 3;
        wrong_previous.registry.unsigned.previous_digest = Some(Digest32::new([0xf2; 32]));
        wrong_previous.registry.unsigned.tools[0]
            .identity
            .registry_version = 3;
        crate::test_support::resign_registry(&mut wrong_previous.registry);
        assert_eq!(
            fixture
                .engine
                .begin_run(&fixture.context, wrong_previous)
                .unwrap_err()
                .code(),
            StableCode::RegistryEquivocation
        );

        let mut lower = fixture.begin_request("operator", KernelValue::Null);
        lower.registry = initial;
        assert_eq!(
            fixture
                .engine
                .begin_run(&fixture.context, lower)
                .unwrap_err()
                .code(),
            StableCode::RegistryEquivocation
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
            issue_handle::<RunHandle>(
                &Fixed([7; 32]),
                &occupied,
                &[],
                UnixMillis::new(2_000),
                &mut transaction,
            )
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
            issue_handle::<RunHandle>(
                &Fixed([7; 32]),
                &occupied,
                &stale,
                UnixMillis::new(2_000),
                &mut transaction,
            )
            .unwrap_err()
            .code(),
            StableCode::KernelUnavailable
        );
        transaction.push(token);
        assert_eq!(
            issue_handle::<RunHandle>(
                &Fixed([7; 32]),
                &occupied,
                &[],
                UnixMillis::new(2_000),
                &mut transaction,
            )
            .unwrap_err()
            .code(),
            StableCode::KernelUnavailable
        );
    }

    #[test]
    fn collision_failure_preserves_the_exact_security_state_including_expired_entries() {
        let fixture = crate::test_support::IngressFixture::new();
        {
            let mut state = fixture.engine.inner.state.write().unwrap();
            state
                .handle_kinds
                .insert(HandleToken(u64_token(2)), HandleKind::Run);
            state.stale_handles.push(StaleHandleRecord {
                token: HandleToken([0x91; 32]),
                kind: HandleKind::Value,
                expires_at: UnixMillis::new(1_999),
            });
            let client = savana_kernel_protocol::ClientId::new("jarvis-client").unwrap();
            state.ingress_replay.insert(
                IngressReplayKey {
                    authority_key_id: savana_kernel_protocol::KeyId::new("role-00").unwrap(),
                    nonce: Nonce32::new([0x92; 32]),
                },
                IngressReplayEntry {
                    client_id: client.clone(),
                    expires_at: UnixMillis::new(1_999),
                },
            );
            state.replay_per_client.insert(client, 1);
        }
        let before = security_snapshot(&fixture.engine.inner.state.read().unwrap());
        assert_eq!(
            fixture
                .engine
                .begin_run(
                    &fixture.context,
                    fixture.begin_request("operator", KernelValue::Null),
                )
                .unwrap_err()
                .code(),
            StableCode::KernelUnavailable
        );
        assert_eq!(
            security_snapshot(&fixture.engine.inner.state.read().unwrap()),
            before
        );
    }

    #[test]
    fn entropy_transaction_and_stale_collisions_preserve_exact_state_and_stale_resolution() {
        let cases = [
            vec![RandomStep::Fill([1; 32]), RandomStep::Error],
            vec![
                RandomStep::Fill([1; 32]),
                RandomStep::Fill([2; 32]),
                RandomStep::Fill([2; 32]),
            ],
        ];
        for script in cases {
            let fixture = crate::test_support::IngressFixture::with_random(Arc::new(
                ScriptedRandom::new(script),
            ));
            let before = security_snapshot(&fixture.engine.inner.state.read().unwrap());
            assert_eq!(
                fixture
                    .engine
                    .begin_run(
                        &fixture.context,
                        fixture.begin_request("operator", KernelValue::Null),
                    )
                    .unwrap_err()
                    .code(),
                StableCode::KernelUnavailable
            );
            assert_eq!(
                security_snapshot(&fixture.engine.inner.state.read().unwrap()),
                before
            );
        }

        let fixture =
            crate::test_support::IngressFixture::with_random(Arc::new(ScriptedRandom::new([
                RandomStep::Fill([1; 32]),
                RandomStep::Fill([9; 32]),
            ])));
        let stale_token = HandleToken([9; 32]);
        {
            fixture
                .engine
                .inner
                .state
                .write()
                .unwrap()
                .stale_handles
                .push(StaleHandleRecord {
                    token: stale_token.clone(),
                    kind: HandleKind::Run,
                    expires_at: UnixMillis::new(3_000),
                });
        }
        let before = security_snapshot(&fixture.engine.inner.state.read().unwrap());
        assert_eq!(
            fixture
                .engine
                .begin_run(
                    &fixture.context,
                    fixture.begin_request("operator", KernelValue::Null),
                )
                .unwrap_err()
                .code(),
            StableCode::KernelUnavailable
        );
        let state = fixture.engine.inner.state.read().unwrap();
        assert_eq!(security_snapshot(&state), before);
        assert_eq!(
            require_handle_kind(
                &state,
                &stale_token,
                HandleKind::Run,
                UnixMillis::new(2_000),
            )
            .unwrap_err()
            .code(),
            StableCode::HandleStalePolicy
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
    fn cross_client_global_replay_charges_only_the_atomic_winner() {
        let fixture = Arc::new(crate::test_support::IngressFixture::new());
        let (other_context, other_binding) = fixture.bind("other-client", 0x35, 0x46);
        let input = KernelValue::Null;
        let digest = ingress_request_digest(&IngressRequestCommitmentV1::BeginRun {
            input: input.clone(),
        })
        .unwrap();
        let nonce = Nonce32::new([0xa5; 32]);
        let attempts = [
            (
                savana_kernel_protocol::ClientId::new("jarvis-client").unwrap(),
                fixture.ingress("operator", digest, nonce, fixture.connection_binding),
                None,
            ),
            (
                savana_kernel_protocol::ClientId::new("other-client").unwrap(),
                fixture.ingress("operator", digest, nonce, other_binding),
                Some(Arc::new(other_context)),
            ),
        ];
        let barrier = Arc::new(Barrier::new(3));
        let joins = attempts.map(|(client, ingress, other)| {
            let fixture = Arc::clone(&fixture);
            let barrier = Arc::clone(&barrier);
            let input = input.clone();
            std::thread::spawn(move || {
                barrier.wait();
                let request = BeginRunRequest {
                    ingress,
                    input,
                    registry: crate::test_support::signed_registry(),
                };
                let result = match other {
                    Some(context) => fixture.engine.begin_run(context.as_ref(), request),
                    None => fixture.engine.begin_run(&fixture.context, request),
                };
                (client, result)
            })
        });
        barrier.wait();
        let outcomes = joins.map(|join| join.join().unwrap());
        let winner = outcomes
            .iter()
            .find_map(|(client, outcome)| outcome.is_ok().then_some(client))
            .unwrap();
        let loser = outcomes
            .iter()
            .find_map(|(client, outcome)| outcome.is_err().then_some(client))
            .unwrap();
        let state = fixture.engine.inner.state.read().unwrap();
        assert_eq!(state.replay_per_client.get(winner), Some(&1));
        assert_eq!(state.replay_per_client.get(loser).copied().unwrap_or(0), 0);
        assert_eq!(state.ingress_replay.len(), 1);
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
        for mutation in 0..6 {
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
                4 => {
                    request.envelope.unsigned.principal =
                        savana_kernel_protocol::PrincipalId::new("other-principal").unwrap()
                }
                5 => {
                    request.envelope.unsigned.conversation_id =
                        savana_kernel_protocol::ConversationId::new("other-conversation").unwrap()
                }
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

        let (wrong_peer, binding) = fixture.bind_with_peer("jarvis-client", 0x39, 0x49, 2_002);
        assert_eq!(
            fixture
                .engine
                .ingest_user_input(
                    &wrong_peer,
                    fixture.ingest_request_for(run, KernelValue::Bool(true), binding),
                )
                .unwrap_err()
                .code(),
            StableCode::HandleWrongClient
        );
    }

    #[test]
    fn bad_ingress_signature_precedes_a_known_wrong_type_handle() {
        let fixture = crate::test_support::IngressFixture::new();
        let response = fixture
            .engine
            .begin_run(
                &fixture.context,
                fixture.begin_request("operator", KernelValue::Null),
            )
            .unwrap();
        let known_wrong_type: RunHandle =
            minicbor::decode(&minicbor::to_vec(response.initial_value).unwrap()).unwrap();
        let mut request = fixture.ingest_request(known_wrong_type, KernelValue::Null);
        request.envelope.signature = Signature64::new([0; 64]);

        assert_ingest_failure_preserves_security_snapshot(
            &fixture,
            &fixture.context,
            request,
            StableCode::AttestationInvalidSignature,
        );
    }

    #[test]
    fn expired_ingress_precedes_an_unknown_handle() {
        let fixture = crate::test_support::IngressFixture::new();
        let mut request = fixture.ingest_request(run_handle([0xaa; 32]), KernelValue::Null);
        request.envelope.unsigned.expires_at = UnixMillis::new(2_000);
        crate::test_support::resign_ingress(&mut request.envelope);

        assert_ingest_failure_preserves_security_snapshot(
            &fixture,
            &fixture.context,
            request,
            StableCode::AttestationExpired,
        );
    }

    #[test]
    fn wrong_ingress_binding_precedes_a_stale_handle() {
        let fixture = crate::test_support::IngressFixture::new();
        let stale = run_handle([0xbb; 32]);
        fixture
            .engine
            .inner
            .state
            .write()
            .unwrap()
            .stale_handles
            .push(StaleHandleRecord {
                token: HandleToken([0xbb; 32]),
                kind: HandleKind::Tool,
                expires_at: UnixMillis::new(3_000),
            });
        let request =
            fixture.ingest_request_for(stale, KernelValue::Null, Digest32::new([0x93; 32]));

        assert_ingest_failure_preserves_security_snapshot(
            &fixture,
            &fixture.context,
            request,
            StableCode::AttestationBindingMismatch,
        );
    }

    #[test]
    fn cross_client_live_wrong_type_handle_precedes_type_disclosure() {
        let fixture = crate::test_support::IngressFixture::new();
        let response = fixture
            .engine
            .begin_run(
                &fixture.context,
                fixture.begin_request("operator", KernelValue::Null),
            )
            .unwrap();
        let cross_client_value: RunHandle =
            minicbor::decode(&minicbor::to_vec(response.initial_value).unwrap()).unwrap();
        let (other_context, other_binding) = fixture.bind("other-client", 0x3a, 0x4a);
        let request =
            fixture.ingest_request_for(cross_client_value, KernelValue::Null, other_binding);

        assert_ingest_failure_preserves_security_snapshot(
            &fixture,
            &other_context,
            request,
            StableCode::HandleWrongClient,
        );
    }

    #[test]
    fn stale_handle_kind_never_discloses_a_type_mismatch() {
        let fixture = crate::test_support::IngressFixture::new();
        let stale = run_handle([0xbc; 32]);
        fixture
            .engine
            .inner
            .state
            .write()
            .unwrap()
            .stale_handles
            .push(StaleHandleRecord {
                token: HandleToken([0xbc; 32]),
                kind: HandleKind::Value,
                expires_at: UnixMillis::new(3_000),
            });
        let request = fixture.ingest_request(stale, KernelValue::Null);

        assert_ingest_failure_preserves_security_snapshot(
            &fixture,
            &fixture.context,
            request,
            StableCode::HandleStalePolicy,
        );
    }

    #[test]
    fn inconsistent_live_handle_indexes_fail_closed() {
        let fixture = crate::test_support::IngressFixture::new();
        let run = fixture
            .engine
            .begin_run(
                &fixture.context,
                fixture.begin_request("operator", KernelValue::Null),
            )
            .unwrap()
            .run;
        let token = handle_token(&run).unwrap();
        fixture
            .engine
            .inner
            .state
            .write()
            .unwrap()
            .handle_kinds
            .remove(&token);
        let request = fixture.ingest_request(run, KernelValue::Null);

        assert_ingest_failure_preserves_security_snapshot(
            &fixture,
            &fixture.context,
            request,
            StableCode::KernelUnavailable,
        );

        let fixture = crate::test_support::IngressFixture::new();
        let run = fixture
            .engine
            .begin_run(
                &fixture.context,
                fixture.begin_request("operator", KernelValue::Null),
            )
            .unwrap()
            .run;
        let token = handle_token(&run).unwrap();
        fixture
            .engine
            .inner
            .state
            .write()
            .unwrap()
            .runs
            .remove(&token);
        let request = fixture.ingest_request(run, KernelValue::Null);

        assert_ingest_failure_preserves_security_snapshot(
            &fixture,
            &fixture.context,
            request,
            StableCode::KernelUnavailable,
        );

        let fixture = crate::test_support::IngressFixture::new();
        let run = fixture
            .engine
            .begin_run(
                &fixture.context,
                fixture.begin_request("operator", KernelValue::Null),
            )
            .unwrap()
            .run;
        let token = handle_token(&run).unwrap();
        fixture
            .engine
            .inner
            .state
            .write()
            .unwrap()
            .handle_kinds
            .insert(token, HandleKind::Value);
        let request = fixture.ingest_request(run, KernelValue::Null);

        assert_ingest_failure_preserves_security_snapshot(
            &fixture,
            &fixture.context,
            request,
            StableCode::KernelUnavailable,
        );
    }

    #[test]
    fn duplicate_concrete_handle_records_fail_closed() {
        for duplicate_kind in [HandleKind::Value, HandleKind::Tool] {
            let fixture = crate::test_support::IngressFixture::new();
            let response = fixture
                .engine
                .begin_run(
                    &fixture.context,
                    fixture.begin_request("operator", KernelValue::Null),
                )
                .unwrap();
            let run = response.run;
            let run_token = handle_token(&run).unwrap();
            {
                let mut state = fixture.engine.inner.state.write().unwrap();
                match duplicate_kind {
                    HandleKind::Value => {
                        let value_token = handle_token(&response.initial_value).unwrap();
                        let duplicate = state.values.get(&value_token).unwrap().clone();
                        state.values.insert(run_token, duplicate);
                    }
                    HandleKind::Tool => {
                        let tool_token = handle_token(&response.active_tools[0].handle).unwrap();
                        let duplicate = state.tools.get(&tool_token).unwrap().clone();
                        state.tools.insert(run_token, duplicate);
                    }
                    HandleKind::Run => unreachable!(),
                }
            }
            let request = fixture.ingest_request(run, KernelValue::Null);

            assert_ingest_failure_preserves_security_snapshot(
                &fixture,
                &fixture.context,
                request,
                StableCode::KernelUnavailable,
            );
        }
    }

    #[test]
    fn ingest_resolves_live_wrong_type_unknown_and_stale_handles_in_order() {
        let fixture = crate::test_support::IngressFixture::new();
        let response = fixture
            .engine
            .begin_run(
                &fixture.context,
                fixture.begin_request("operator", KernelValue::Null),
            )
            .unwrap();
        let wrong_type: RunHandle =
            minicbor::decode(&minicbor::to_vec(response.initial_value).unwrap()).unwrap();
        assert_eq!(
            fixture
                .engine
                .ingest_user_input(
                    &fixture.context,
                    fixture.ingest_request(wrong_type, KernelValue::Null),
                )
                .unwrap_err()
                .code(),
            StableCode::HandleWrongType
        );

        let unknown = run_handle([0xaa; 32]);
        assert_eq!(
            fixture
                .engine
                .ingest_user_input(
                    &fixture.context,
                    fixture.ingest_request(unknown, KernelValue::Null),
                )
                .unwrap_err()
                .code(),
            StableCode::HandleUnknown
        );

        let stale = run_handle([0xbb; 32]);
        fixture
            .engine
            .inner
            .state
            .write()
            .unwrap()
            .stale_handles
            .push(StaleHandleRecord {
                token: HandleToken([0xbb; 32]),
                kind: HandleKind::Run,
                expires_at: UnixMillis::new(3_000),
            });
        assert_eq!(
            fixture
                .engine
                .ingest_user_input(
                    &fixture.context,
                    fixture.ingest_request(stale, KernelValue::Null),
                )
                .unwrap_err()
                .code(),
            StableCode::HandleStalePolicy
        );
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
            for value in 10_000_u64..14_095 {
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
                4_095,
            );
        }
        assert!(fixture
            .engine
            .begin_run(
                &fixture.context,
                fixture.begin_request("operator", KernelValue::Null),
            )
            .is_ok());
        let before_overflow = security_snapshot(&fixture.engine.inner.state.read().unwrap());
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
        assert_eq!(security_snapshot(&state), before_overflow);
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

    #[test]
    fn verified_release_with_sixteen_canonical_clients_sets_the_global_replay_ceiling() {
        let (current, _) = crate::test_support::current_policy_and_identity_with_clients(16);
        let clock = crate::test_support::clock();
        let (engine, _) = PolicyEngine::new(
            current,
            BootId::new([0x41; 32]),
            Arc::clone(&clock) as Arc<dyn Clock + Send + Sync>,
            crate::test_support::random(crate::test_support::RandomBehavior::Filled(0xa4)),
        )
        .unwrap();

        let state = engine.inner.state.read().unwrap();
        assert_eq!(state.global_replay_limit, 65_536);
        assert_eq!(state.global_run_limit, 2_048);
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

    fn assert_ingest_failure_preserves_security_snapshot(
        fixture: &crate::test_support::IngressFixture,
        context: &AuthenticatedCallContext,
        request: IngestUserInputRequest,
        expected: StableCode,
    ) {
        let before = security_snapshot(&fixture.engine.inner.state.read().unwrap());
        assert_eq!(
            fixture
                .engine
                .ingest_user_input(context, request)
                .unwrap_err()
                .code(),
            expected
        );
        assert_eq!(
            security_snapshot(&fixture.engine.inner.state.read().unwrap()),
            before
        );
    }

    fn security_snapshot(state: &EngineState) -> SecuritySnapshot {
        let mut replay = state
            .ingress_replay
            .iter()
            .map(|(key, entry)| (key.clone(), entry.clone()))
            .collect::<Vec<_>>();
        replay.sort_by(|left, right| {
            left.0
                .authority_key_id
                .as_str()
                .cmp(right.0.authority_key_id.as_str())
                .then_with(|| left.0.nonce.as_bytes().cmp(right.0.nonce.as_bytes()))
        });
        let mut replay_per_client = state
            .replay_per_client
            .iter()
            .map(|(client, count)| (client.clone(), *count))
            .collect::<Vec<_>>();
        replay_per_client.sort_by(|left, right| left.0.as_str().cmp(right.0.as_str()));
        let mut stale = state.stale_handles.clone();
        stale.sort_by(|left, right| left.token.0.cmp(&right.token.0));
        let mut handle_kinds = state
            .handle_kinds
            .iter()
            .map(|(token, kind)| (token.clone(), *kind))
            .collect::<Vec<_>>();
        handle_kinds.sort_by(|left, right| left.0 .0.cmp(&right.0 .0));
        let mut runs = state
            .runs
            .iter()
            .map(|(token, record)| (token.clone(), record.clone()))
            .collect::<Vec<_>>();
        runs.sort_by(|left, right| left.0 .0.cmp(&right.0 .0));
        let mut values = state
            .values
            .iter()
            .map(|(token, record)| (token.clone(), record.clone()))
            .collect::<Vec<_>>();
        values.sort_by(|left, right| left.0 .0.cmp(&right.0 .0));
        let mut tools = state
            .tools
            .iter()
            .map(|(token, record)| (token.clone(), record.clone()))
            .collect::<Vec<_>>();
        tools.sort_by(|left, right| left.0 .0.cmp(&right.0 .0));
        SecuritySnapshot {
            replay,
            replay_per_client,
            stale,
            registry: state.registry.clone(),
            handle_kinds,
            runs,
            values,
            tools,
        }
    }

    fn u64_token(value: u64) -> [u8; 32] {
        let mut token = [0_u8; 32];
        token[..8].copy_from_slice(&value.to_be_bytes());
        token
    }

    fn run_handle(token: [u8; 32]) -> RunHandle {
        let mut encoded = [0_u8; 34];
        encoded[0] = 0x58;
        encoded[1] = 0x20;
        encoded[2..].copy_from_slice(&token);
        minicbor::decode(&encoded).unwrap()
    }

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;

        bytes.iter().fold(String::new(), |mut output, byte| {
            write!(output, "{byte:02x}").unwrap();
            output
        })
    }
}
