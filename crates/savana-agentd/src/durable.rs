use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use aes_gcm::aead::{Aead as _, Payload};
use aes_gcm::{Aes256Gcm, KeyInit as _, Nonce};
use hmac::{Hmac, Mac as _};
use minicbor::{Decode as _, Encode as _};
use nix::fcntl::{Flock, FlockArg};
use rustix::fs::{
    fchmod, open as rustix_open, openat, renameat, statat, unlinkat, AtFlags, FileType, Mode,
    OFlags,
};
use rustix::io::Errno;
use savana_kernel_protocol::v2::{
    decode_public_task_status_v2, decode_signed_durable_task_correlation_v2,
    encode_public_task_status_v2, encode_signed_durable_task_correlation_v2, BootIdV2,
    BootstrapKindV2, Digest32V2, DurableTaskIdV2, JarvisBootstrapActionV2,
    JarvisBootstrapSelectorV2, JarvisBootstrapUrlV2, KernelIngressBootstrapTransferCapabilityV2,
    NewTaskPreparationHandleV2, Nonce32V2, PrepareIngressResponseV2, PublicTaskStatusV2,
    ServiceIdentityV2, TaskHandleV2, UnixMillisV2, V2DecodeContext,
};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use super::{
    is_zero, task_handle_digest, AgentTaskErrorV2, AgentTaskRecoveryProjectionV2,
    AgentTaskServiceV2, AuthenticatedJarvisControlV2, PrepareReplayRecordV2, TaskOriginBootV2,
    TaskResolverRecordV2, VerifiedKernelCancellationV2, VerifiedKernelTaskPreparationV2,
    VerifiedKernelTaskStatusV2, MAX_PREPARE_REPLAYS,
};
use savana_kernel_protocol::v2::{
    CancelTaskRequestV2, CancelTaskResponseV2, GetTaskStatusRequestV2, GetTaskStatusResponseV2,
};

const STATE_FILE_NAME: &str = "agent-task-state-v2.cbor";
const LOCK_FILE_NAME: &str = ".agent-task-state-v2.cbor.lock";
const SCHEMA_VERSION: u16 = 4;
const ENCRYPTION_DOMAIN: &[u8] = b"SAVANA_AGENT_TASK_STATE_ENCRYPTION_V2\0";
const KEY_DERIVATION_DOMAIN: &[u8] = b"SAVANA_AGENT_TASK_STATE_KEY_DERIVATION_V2\0";
const HEAD_DOMAIN: &[u8] = b"SAVANA_AGENT_TASK_STATE_HEAD_V2\0";
const NONCE_BYTES: usize = 12;
const MAX_STATE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_TASKS: usize = 65_536;
const TEMP_ATTEMPTS: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentTaskStateHeadV2 {
    sequence: u64,
    state_digest: Digest32V2,
}

impl Default for AgentTaskStateHeadV2 {
    fn default() -> Self {
        Self::GENESIS
    }
}

impl AgentTaskStateHeadV2 {
    const GENESIS: Self = Self {
        sequence: 0,
        state_digest: Digest32V2::new([0; 32]),
    };

    pub fn new(sequence: u64, state_digest: Digest32V2) -> Result<Self, AgentTaskErrorV2> {
        if (sequence == 0 && !is_zero(state_digest.as_bytes()))
            || (sequence != 0 && is_zero(state_digest.as_bytes()))
        {
            return Err(AgentTaskErrorV2::RollbackDetected);
        }
        Ok(Self {
            sequence,
            state_digest,
        })
    }

    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    pub const fn state_digest(self) -> Digest32V2 {
        self.state_digest
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DurableAgentTaskNamespaceV2 {
    installation_id: Digest32V2,
    store_id: Digest32V2,
}

impl DurableAgentTaskNamespaceV2 {
    pub fn from_verified_installation(
        installation_id: Digest32V2,
        store_id: Digest32V2,
    ) -> Result<Self, AgentTaskErrorV2> {
        if is_zero(installation_id.as_bytes()) || is_zero(store_id.as_bytes()) {
            return Err(AgentTaskErrorV2::DurableState);
        }
        Ok(Self {
            installation_id,
            store_id,
        })
    }

    pub const fn installation_id(self) -> Digest32V2 {
        self.installation_id
    }

    pub const fn store_id(self) -> Digest32V2 {
        self.store_id
    }
}

pub trait AgentTaskRollbackAnchorV2: Send {
    fn current_head(&self) -> Result<AgentTaskStateHeadV2, AgentTaskErrorV2>;

    fn compare_and_advance(
        &mut self,
        expected: AgentTaskStateHeadV2,
        next: AgentTaskStateHeadV2,
    ) -> Result<(), AgentTaskErrorV2>;
}

pub struct DurableAgentTaskServiceV2 {
    path: PathBuf,
    anchored_path: AnchoredPathV2,
    namespace: DurableAgentTaskNamespaceV2,
    encryption_key: Zeroizing<[u8; 32]>,
    sequence: u64,
    previous_state_digest: Digest32V2,
    current_head: AgentTaskStateHeadV2,
    rollback_anchor: Box<dyn AgentTaskRollbackAnchorV2>,
    service: AgentTaskServiceV2,
    poisoned: bool,
    lock: StateLockV2,
}

impl std::fmt::Debug for DurableAgentTaskServiceV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DurableAgentTaskServiceV2")
            .field("path", &self.path)
            .field("sequence", &self.sequence)
            .field("task_count", &self.service.tasks.len())
            .field("poisoned", &self.poisoned)
            .finish_non_exhaustive()
    }
}

impl DurableAgentTaskServiceV2 {
    pub fn open(
        path: &Path,
        master_encryption_key: [u8; 32],
        namespace: DurableAgentTaskNamespaceV2,
        mut rollback_anchor: Box<dyn AgentTaskRollbackAnchorV2>,
        deployment: AgentTaskServiceV2,
    ) -> Result<Self, AgentTaskErrorV2> {
        if path.file_name().and_then(|name| name.to_str()) != Some(STATE_FILE_NAME)
            || master_encryption_key == [0; 32]
            || deployment.installation_id != namespace.installation_id
            || !deployment.tasks.is_empty()
            || !deployment.prepare_replays.is_empty()
            || deployment.accepted_time_floor_ms != 0
        {
            return Err(AgentTaskErrorV2::DurableState);
        }
        let anchored_path = AnchoredPathV2::open(path)?;
        let lock = StateLockV2::acquire(
            &anchored_path.parent,
            OsStr::new(LOCK_FILE_NAME),
            anchored_path.owner_uid,
            anchored_path.owner_gid,
        )?;
        anchored_path.recheck_parent()?;
        let encryption_key = derive_encryption_key(&master_encryption_key, namespace)?;
        let anchored_head = rollback_anchor.current_head()?;
        let (sequence, previous_state_digest, service, current_head) =
            match anchored_path.read_existing()? {
                Some(bytes) => {
                    let (sequence, previous_state_digest, service) =
                        decode_encrypted_snapshot(&bytes, &encryption_key, namespace, deployment)?;
                    let snapshot_head = AgentTaskStateHeadV2 {
                        sequence,
                        state_digest: state_head_digest(namespace, &bytes),
                    };
                    if snapshot_head == anchored_head {
                        (sequence, previous_state_digest, service, snapshot_head)
                    } else if sequence
                        == anchored_head
                            .sequence
                            .checked_add(1)
                            .ok_or(AgentTaskErrorV2::RollbackDetected)?
                        && previous_state_digest == anchored_head.state_digest
                    {
                        rollback_anchor.compare_and_advance(anchored_head, snapshot_head)?;
                        (sequence, previous_state_digest, service, snapshot_head)
                    } else {
                        return Err(AgentTaskErrorV2::RollbackDetected);
                    }
                }
                None => {
                    if anchored_head != AgentTaskStateHeadV2::GENESIS {
                        return Err(AgentTaskErrorV2::RollbackDetected);
                    }
                    (
                        0,
                        Digest32V2::new([0; 32]),
                        deployment,
                        AgentTaskStateHeadV2::GENESIS,
                    )
                }
            };
        Ok(Self {
            path: path.to_owned(),
            anchored_path,
            namespace,
            encryption_key,
            sequence,
            previous_state_digest,
            current_head,
            rollback_anchor,
            service,
            poisoned: false,
            lock,
        })
    }

    #[cfg(test)]
    pub fn task_count(&self) -> usize {
        self.service.tasks.len()
    }

    pub fn recovery_projection(
        &self,
    ) -> Result<Vec<AgentTaskRecoveryProjectionV2>, AgentTaskErrorV2> {
        self.ensure_usable()?;
        self.service.recovery_projection()
    }

    pub fn prepare_ingress(
        &mut self,
        context: AuthenticatedJarvisControlV2,
        client_request_nonce: Nonce32V2,
        preparation: VerifiedKernelTaskPreparationV2,
        now: UnixMillisV2,
    ) -> Result<PrepareIngressResponseV2, AgentTaskErrorV2> {
        self.mutate(|service| {
            service.prepare_ingress(context, client_request_nonce, preparation, now)
        })
    }

    pub fn get_task_status(
        &mut self,
        context: AuthenticatedJarvisControlV2,
        request: GetTaskStatusRequestV2,
        now: UnixMillisV2,
    ) -> Result<GetTaskStatusResponseV2, AgentTaskErrorV2> {
        self.mutate(|service| service.get_task_status(context, request, now))
    }

    pub fn inspect_bootstrap(
        &mut self,
        kind: savana_kernel_protocol::v2::BootstrapKindV2,
        selector: savana_kernel_protocol::v2::JarvisBootstrapSelectorV2,
        now: UnixMillisV2,
    ) -> Result<(), AgentTaskErrorV2> {
        self.mutate(|service| service.inspect_bootstrap(kind, selector, now))
    }

    pub fn continue_bootstrap(
        &mut self,
        kind: savana_kernel_protocol::v2::BootstrapKindV2,
        selector: savana_kernel_protocol::v2::JarvisBootstrapSelectorV2,
        now: UnixMillisV2,
    ) -> Result<super::ResolvedJarvisBootstrapV2, AgentTaskErrorV2> {
        self.mutate(|service| service.continue_bootstrap(kind, selector, now))
    }

    pub fn prepare_status_query(
        &mut self,
        context: AuthenticatedJarvisControlV2,
        request: GetTaskStatusRequestV2,
        now: UnixMillisV2,
    ) -> Result<super::PendingTaskStatusQueryV2, AgentTaskErrorV2> {
        self.mutate(|service| service.prepare_status_query(context, request, now))
    }

    pub fn apply_verified_kernel_status(
        &mut self,
        verified: VerifiedKernelTaskStatusV2,
        now: UnixMillisV2,
    ) -> Result<(), AgentTaskErrorV2> {
        self.mutate(|service| service.apply_verified_kernel_status(verified, now))
    }

    pub fn prepare_cancel(
        &mut self,
        context: AuthenticatedJarvisControlV2,
        request: CancelTaskRequestV2,
        now: UnixMillisV2,
    ) -> Result<super::PendingTaskCancellationV2, AgentTaskErrorV2> {
        self.mutate(|service| service.prepare_cancel(context, request, now))
    }

    pub fn commit_verified_cancellation(
        &mut self,
        pending: super::PendingTaskCancellationV2,
        verified: VerifiedKernelCancellationV2,
        now: UnixMillisV2,
    ) -> Result<CancelTaskResponseV2, AgentTaskErrorV2> {
        self.mutate(|service| service.commit_verified_cancellation(pending, verified, now))
    }

    fn mutate<T>(
        &mut self,
        operation: impl FnOnce(&mut AgentTaskServiceV2) -> Result<T, AgentTaskErrorV2>,
    ) -> Result<T, AgentTaskErrorV2> {
        self.ensure_usable()?;
        let mut next = self.service.clone();
        match operation(&mut next) {
            Ok(result) => {
                self.commit(next)?;
                Ok(result)
            }
            Err(operation_error) => {
                if next.accepted_time_floor_ms > self.service.accepted_time_floor_ms {
                    let mut floor_only = self.service.clone();
                    floor_only.accepted_time_floor_ms = next.accepted_time_floor_ms;
                    self.commit(floor_only)?;
                }
                Err(operation_error)
            }
        }
    }

    fn ensure_usable(&self) -> Result<(), AgentTaskErrorV2> {
        if self.poisoned {
            Err(AgentTaskErrorV2::CommitUncertain)
        } else {
            Ok(())
        }
    }

    fn commit(&mut self, next: AgentTaskServiceV2) -> Result<(), AgentTaskErrorV2> {
        let sequence = self
            .sequence
            .checked_add(1)
            .ok_or(AgentTaskErrorV2::DurableState)?;
        let previous_state_digest = self.current_head.state_digest;
        validate_service(&next)?;
        let bytes = encode_encrypted_snapshot(
            sequence,
            previous_state_digest,
            &next,
            &self.encryption_key,
            self.namespace,
        )?;
        let next_head = AgentTaskStateHeadV2 {
            sequence,
            state_digest: state_head_digest(self.namespace, &bytes),
        };
        self.lock.recheck()?;
        match self.anchored_path.replace(&bytes) {
            Ok(()) => {
                if self
                    .rollback_anchor
                    .compare_and_advance(self.current_head, next_head)
                    .is_err()
                {
                    self.poisoned = true;
                    return Err(AgentTaskErrorV2::CommitUncertain);
                }
                self.service = next;
                self.sequence = sequence;
                self.previous_state_digest = previous_state_digest;
                self.current_head = next_head;
                Ok(())
            }
            Err(after_rename) => {
                if after_rename {
                    self.poisoned = true;
                    Err(AgentTaskErrorV2::CommitUncertain)
                } else {
                    Err(AgentTaskErrorV2::DurableState)
                }
            }
        }
    }
}

fn encode_encrypted_snapshot(
    sequence: u64,
    previous_state_digest: Digest32V2,
    service: &AgentTaskServiceV2,
    key: &[u8; 32],
    namespace: DurableAgentTaskNamespaceV2,
) -> Result<Vec<u8>, AgentTaskErrorV2> {
    let payload = encode_snapshot_payload(sequence, previous_state_digest, service)?;
    let mut nonce = [0_u8; NONCE_BYTES];
    getrandom::getrandom(&mut nonce).map_err(|_| AgentTaskErrorV2::DurableState)?;
    if nonce == [0; NONCE_BYTES] {
        return Err(AgentTaskErrorV2::DurableState);
    }
    let aad = encryption_aad(namespace, sequence, previous_state_digest, &nonce);
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|_| AgentTaskErrorV2::DurableAuthentication)?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: payload.as_slice(),
                aad: &aad,
            },
        )
        .map_err(|_| AgentTaskErrorV2::DurableAuthentication)?;
    encode_encrypted_envelope(sequence, previous_state_digest, &nonce, &ciphertext)
}

fn decode_encrypted_snapshot(
    bytes: &[u8],
    key: &[u8; 32],
    namespace: DurableAgentTaskNamespaceV2,
    deployment: AgentTaskServiceV2,
) -> Result<(u64, Digest32V2, AgentTaskServiceV2), AgentTaskErrorV2> {
    if bytes.len() as u64 > MAX_STATE_BYTES {
        return Err(AgentTaskErrorV2::DurableState);
    }
    let mut decoder = minicbor::Decoder::new(bytes);
    require_array(&mut decoder, 5)?;
    if decoder.u16().map_err(|_| AgentTaskErrorV2::DurableState)? != SCHEMA_VERSION {
        return Err(AgentTaskErrorV2::DurableState);
    }
    let sequence = decoder.u64().map_err(|_| AgentTaskErrorV2::DurableState)?;
    let previous_state_digest = Digest32V2::new(decode_fixed::<32>(&mut decoder)?);
    let nonce = decode_fixed::<NONCE_BYTES>(&mut decoder)?;
    let ciphertext = decoder
        .bytes()
        .map_err(|_| AgentTaskErrorV2::DurableState)?;
    if decoder.position() != bytes.len()
        || encode_encrypted_envelope(sequence, previous_state_digest, &nonce, ciphertext)? != bytes
    {
        return Err(AgentTaskErrorV2::DurableState);
    }
    let aad = encryption_aad(namespace, sequence, previous_state_digest, &nonce);
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|_| AgentTaskErrorV2::DurableAuthentication)?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| AgentTaskErrorV2::DurableAuthentication)?,
    );
    let service = decode_snapshot_payload(&plaintext, sequence, previous_state_digest, deployment)?;
    if encode_snapshot_payload(sequence, previous_state_digest, &service)?.as_slice()
        != plaintext.as_slice()
    {
        return Err(AgentTaskErrorV2::DurableState);
    }
    Ok((sequence, previous_state_digest, service))
}

fn encode_encrypted_envelope(
    sequence: u64,
    previous_state_digest: Digest32V2,
    nonce: &[u8; NONCE_BYTES],
    ciphertext: &[u8],
) -> Result<Vec<u8>, AgentTaskErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(5)
        .and_then(|encoder| encoder.u16(SCHEMA_VERSION))
        .and_then(|encoder| encoder.u64(sequence))
        .map_err(|_| AgentTaskErrorV2::AllocationFailure)?;
    previous_state_digest
        .encode(&mut encoder, &mut ())
        .map_err(|_| AgentTaskErrorV2::AllocationFailure)?;
    encoder
        .bytes(nonce)
        .and_then(|encoder| encoder.bytes(ciphertext))
        .map_err(|_| AgentTaskErrorV2::AllocationFailure)?;
    let bytes = encoder.into_writer();
    if bytes.len() as u64 > MAX_STATE_BYTES {
        return Err(AgentTaskErrorV2::AllocationFailure);
    }
    Ok(bytes)
}

fn encode_snapshot_payload(
    sequence: u64,
    previous_state_digest: Digest32V2,
    service: &AgentTaskServiceV2,
) -> Result<Zeroizing<Vec<u8>>, AgentTaskErrorV2> {
    validate_service(service)?;
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(14)
        .and_then(|encoder| encoder.u16(SCHEMA_VERSION))
        .and_then(|encoder| encoder.u64(sequence))
        .map_err(|_| AgentTaskErrorV2::AllocationFailure)?;
    for digest in [
        previous_state_digest,
        service.installation_id,
        service.active_state_manifest_digest,
    ] {
        digest
            .encode(&mut encoder, &mut ())
            .map_err(|_| AgentTaskErrorV2::AllocationFailure)?;
    }
    encoder
        .u64(service.deployment_generation)
        .map_err(|_| AgentTaskErrorV2::AllocationFailure)?;
    service
        .protocol_abi_digest
        .encode(&mut encoder, &mut ())
        .map_err(|_| AgentTaskErrorV2::AllocationFailure)?;
    service
        .agentd_identity
        .encode(&mut encoder, &mut ())
        .map_err(|_| AgentTaskErrorV2::AllocationFailure)?;
    service
        .kernel_task_authority_key_id
        .encode(&mut encoder, &mut ())
        .map_err(|_| AgentTaskErrorV2::AllocationFailure)?;
    service
        .kernel_task_authority_binding_digest
        .encode(&mut encoder, &mut ())
        .map_err(|_| AgentTaskErrorV2::AllocationFailure)?;
    encoder
        .u32(
            u32::try_from(service.maximum_tasks)
                .map_err(|_| AgentTaskErrorV2::AllocationFailure)?,
        )
        .and_then(|encoder| encoder.u64(service.accepted_time_floor_ms))
        .and_then(|encoder| encoder.array(service.tasks.len() as u64))
        .map_err(|_| AgentTaskErrorV2::AllocationFailure)?;
    for task in &service.tasks {
        encode_task(&mut encoder, task)?;
    }
    encoder
        .array(service.prepare_replays.len() as u64)
        .map_err(|_| AgentTaskErrorV2::AllocationFailure)?;
    for replay in &service.prepare_replays {
        encode_replay(&mut encoder, replay)?;
    }
    Ok(Zeroizing::new(encoder.into_writer()))
}

fn encode_task(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    task: &TaskResolverRecordV2,
) -> Result<(), AgentTaskErrorV2> {
    encoder
        .array(21)
        .map_err(|_| AgentTaskErrorV2::AllocationFailure)?;
    task.task_handle
        .encode(encoder, &mut ())
        .map_err(|_| AgentTaskErrorV2::AllocationFailure)?;
    for digest in [
        task.task_handle_digest,
        task.jarvis_principal,
        task.jarvis_os_peer_class,
    ] {
        digest
            .encode(encoder, &mut ())
            .map_err(|_| AgentTaskErrorV2::AllocationFailure)?;
    }
    encoder
        .array(4)
        .map_err(|_| AgentTaskErrorV2::AllocationFailure)?;
    for boot in [
        task.origin_boots.machine_boot_id,
        task.origin_boots.jarvis_control_client_boot_id,
        task.origin_boots.agentd_server_boot_id,
        task.origin_boots.kerneld_server_boot_id,
    ] {
        boot.encode(encoder, &mut ())
            .map_err(|_| AgentTaskErrorV2::AllocationFailure)?;
    }
    task.durable_task_id
        .encode(encoder, &mut ())
        .map_err(|_| AgentTaskErrorV2::AllocationFailure)?;
    for digest in [
        task.correlation_digest,
        task.kernel_bootstrap_binding_digest,
        task.creating_manifest_digest,
    ] {
        digest
            .encode(encoder, &mut ())
            .map_err(|_| AgentTaskErrorV2::AllocationFailure)?;
    }
    task.kernel_preparation
        .encode(encoder, &mut ())
        .map_err(|_| AgentTaskErrorV2::AllocationFailure)?;
    let kernel_correlation = encode_signed_durable_task_correlation_v2(&task.kernel_correlation)
        .map_err(|_| AgentTaskErrorV2::DurableState)?;
    encoder
        .bytes(&kernel_correlation)
        .map_err(|_| AgentTaskErrorV2::AllocationFailure)?;
    encoder
        .u64(task.creating_deployment_generation)
        .map_err(|_| AgentTaskErrorV2::AllocationFailure)?;
    task.protocol_abi_digest
        .encode(encoder, &mut ())
        .map_err(|_| AgentTaskErrorV2::AllocationFailure)?;
    let status = encode_public_task_status_v2(&super::strip_bootstrap(task.status))
        .map_err(|_| AgentTaskErrorV2::DurableState)?;
    encoder
        .u64(task.task_logical_expires_at.get())
        .and_then(|encoder| encoder.u64(task.status_retain_until.get()))
        .and_then(|encoder| encoder.bytes(&status))
        .and_then(|encoder| encoder.u64(task.public_state_revision))
        .map_err(|_| AgentTaskErrorV2::AllocationFailure)?;
    encode_optional_digest(encoder, task.cancellation_commit_digest)?;
    encode_optional_selector(encoder, task.bootstrap_selector)?;
    encode_optional_boot(encoder, task.bootstrap_agentd_boot_id)?;
    encode_optional_ingress_transfer(encoder, task.kernel_ingress_transfer)
}

fn encode_replay(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    replay: &PrepareReplayRecordV2,
) -> Result<(), AgentTaskErrorV2> {
    encoder
        .array(5)
        .map_err(|_| AgentTaskErrorV2::AllocationFailure)?;
    for digest in [
        replay.jarvis_principal,
        replay.jarvis_os_peer_class,
        Digest32V2::new(*replay.client_request_nonce.as_bytes()),
        replay.request_digest,
    ] {
        digest
            .encode(encoder, &mut ())
            .map_err(|_| AgentTaskErrorV2::AllocationFailure)?;
    }
    let response =
        minicbor::to_vec(replay.response).map_err(|_| AgentTaskErrorV2::AllocationFailure)?;
    encoder
        .bytes(&response)
        .map(|_| ())
        .map_err(|_| AgentTaskErrorV2::AllocationFailure)
}

fn decode_snapshot_payload(
    bytes: &[u8],
    expected_sequence: u64,
    expected_previous_state_digest: Digest32V2,
    mut service: AgentTaskServiceV2,
) -> Result<AgentTaskServiceV2, AgentTaskErrorV2> {
    let mut decoder = minicbor::Decoder::new(bytes);
    require_array(&mut decoder, 14)?;
    if decoder.u16().map_err(|_| AgentTaskErrorV2::DurableState)? != SCHEMA_VERSION
        || decoder.u64().map_err(|_| AgentTaskErrorV2::DurableState)? != expected_sequence
        || Digest32V2::new(decode_fixed::<32>(&mut decoder)?) != expected_previous_state_digest
        || Digest32V2::new(decode_fixed::<32>(&mut decoder)?) != service.installation_id
        || Digest32V2::new(decode_fixed::<32>(&mut decoder)?)
            != service.active_state_manifest_digest
        || decoder.u64().map_err(|_| AgentTaskErrorV2::DurableState)?
            != service.deployment_generation
        || Digest32V2::new(decode_fixed::<32>(&mut decoder)?) != service.protocol_abi_digest
        || ServiceIdentityV2::new(decode_fixed::<32>(&mut decoder)?) != service.agentd_identity
        || savana_kernel_protocol::v2::Ed25519KeyIdV2::new(decode_fixed::<32>(&mut decoder)?)
            != service.kernel_task_authority_key_id
        || Digest32V2::new(decode_fixed::<32>(&mut decoder)?)
            != service.kernel_task_authority_binding_digest
    {
        return Err(AgentTaskErrorV2::DurableState);
    }
    let maximum_tasks = decoder.u32().map_err(|_| AgentTaskErrorV2::DurableState)? as usize;
    if maximum_tasks != service.maximum_tasks {
        return Err(AgentTaskErrorV2::DurableState);
    }
    service.accepted_time_floor_ms = decoder.u64().map_err(|_| AgentTaskErrorV2::DurableState)?;
    let task_count = decode_count(&mut decoder, MAX_TASKS)?;
    service
        .tasks
        .try_reserve(task_count)
        .map_err(|_| AgentTaskErrorV2::AllocationFailure)?;
    for _ in 0..task_count {
        service.tasks.push(decode_task(&mut decoder)?);
    }
    let replay_count = decode_count(&mut decoder, MAX_PREPARE_REPLAYS)?;
    service
        .prepare_replays
        .try_reserve(replay_count)
        .map_err(|_| AgentTaskErrorV2::AllocationFailure)?;
    for _ in 0..replay_count {
        service.prepare_replays.push(decode_replay(&mut decoder)?);
    }
    if decoder.position() != bytes.len() {
        return Err(AgentTaskErrorV2::DurableState);
    }
    validate_service(&service)?;
    Ok(service)
}

fn decode_task(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<TaskResolverRecordV2, AgentTaskErrorV2> {
    require_array(decoder, 21)?;
    let task_handle = TaskHandleV2::from_authority_entropy(decode_fixed::<32>(decoder)?)
        .ok_or(AgentTaskErrorV2::DurableState)?;
    let task_handle_digest = Digest32V2::new(decode_fixed::<32>(decoder)?);
    let jarvis_principal = Digest32V2::new(decode_fixed::<32>(decoder)?);
    let jarvis_os_peer_class = Digest32V2::new(decode_fixed::<32>(decoder)?);
    require_array(decoder, 4)?;
    let origin_boots = TaskOriginBootV2 {
        machine_boot_id: BootIdV2::new(decode_fixed::<32>(decoder)?),
        jarvis_control_client_boot_id: BootIdV2::new(decode_fixed::<32>(decoder)?),
        agentd_server_boot_id: BootIdV2::new(decode_fixed::<32>(decoder)?),
        kerneld_server_boot_id: BootIdV2::new(decode_fixed::<32>(decoder)?),
    };
    let durable_task_id = DurableTaskIdV2::new(decode_fixed::<32>(decoder)?);
    let correlation_digest = Digest32V2::new(decode_fixed::<32>(decoder)?);
    let kernel_bootstrap_binding_digest = Digest32V2::new(decode_fixed::<32>(decoder)?);
    let creating_manifest_digest = Digest32V2::new(decode_fixed::<32>(decoder)?);
    let kernel_preparation =
        NewTaskPreparationHandleV2::from_authority_entropy(decode_fixed::<32>(decoder)?)
            .ok_or(AgentTaskErrorV2::DurableState)?;
    let kernel_correlation = decode_signed_durable_task_correlation_v2(
        decoder
            .bytes()
            .map_err(|_| AgentTaskErrorV2::DurableState)?,
    )
    .map_err(|_| AgentTaskErrorV2::DurableState)?;
    let creating_deployment_generation =
        decoder.u64().map_err(|_| AgentTaskErrorV2::DurableState)?;
    let protocol_abi_digest = Digest32V2::new(decode_fixed::<32>(decoder)?);
    let task_logical_expires_at =
        UnixMillisV2::new(decoder.u64().map_err(|_| AgentTaskErrorV2::DurableState)?);
    let status_retain_until =
        UnixMillisV2::new(decoder.u64().map_err(|_| AgentTaskErrorV2::DurableState)?);
    let status_bytes = decoder
        .bytes()
        .map_err(|_| AgentTaskErrorV2::DurableState)?;
    let mut status =
        decode_public_task_status_v2(status_bytes).map_err(|_| AgentTaskErrorV2::DurableState)?;
    if status != super::strip_bootstrap(status) {
        return Err(AgentTaskErrorV2::DurableState);
    }
    let public_state_revision = decoder.u64().map_err(|_| AgentTaskErrorV2::DurableState)?;
    let cancellation_commit_digest = decode_optional_digest(decoder)?;
    let bootstrap_selector = decode_optional_selector(decoder)?;
    let bootstrap_agentd_boot_id = decode_optional_boot(decoder)?;
    let kernel_ingress_transfer = decode_optional_ingress_transfer(decoder)?;
    match (
        bootstrap_selector,
        bootstrap_agentd_boot_id,
        kernel_ingress_transfer,
        status,
    ) {
        (Some(selector), Some(_), Some(_), PublicTaskStatusV2::AwaitingUiAuthentication { .. }) => {
            status = PublicTaskStatusV2::AwaitingUiAuthentication {
                bootstrap: Some(JarvisBootstrapActionV2::OpenIngress {
                    url: JarvisBootstrapUrlV2::from_agentd_selector(
                        BootstrapKindV2::Ingress,
                        selector,
                    ),
                }),
            };
        }
        (Some(selector), Some(_), None, PublicTaskStatusV2::Ready { .. }) => {
            status = PublicTaskStatusV2::Ready {
                bootstrap: Some(JarvisBootstrapActionV2::OpenAgent {
                    url: JarvisBootstrapUrlV2::from_agentd_selector(
                        BootstrapKindV2::Agent,
                        selector,
                    ),
                }),
            };
        }
        (None, None, None, _) => {}
        _ => return Err(AgentTaskErrorV2::DurableState),
    }
    Ok(TaskResolverRecordV2 {
        task_handle,
        task_handle_digest,
        jarvis_principal,
        jarvis_os_peer_class,
        origin_boots,
        durable_task_id,
        correlation_digest,
        kernel_bootstrap_binding_digest,
        bootstrap_selector,
        bootstrap_agentd_boot_id,
        kernel_ingress_transfer,
        kernel_preparation,
        kernel_correlation,
        creating_manifest_digest,
        creating_deployment_generation,
        protocol_abi_digest,
        task_logical_expires_at,
        status_retain_until,
        status,
        public_state_revision,
        pending_cancellation_digest: None,
        cancellation_commit_digest,
    })
}

fn decode_replay(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<PrepareReplayRecordV2, AgentTaskErrorV2> {
    require_array(decoder, 5)?;
    let jarvis_principal = Digest32V2::new(decode_fixed::<32>(decoder)?);
    let jarvis_os_peer_class = Digest32V2::new(decode_fixed::<32>(decoder)?);
    let client_request_nonce = Nonce32V2::new(decode_fixed::<32>(decoder)?);
    let request_digest = Digest32V2::new(decode_fixed::<32>(decoder)?);
    let response_bytes = decoder
        .bytes()
        .map_err(|_| AgentTaskErrorV2::DurableState)?;
    let mut response_decoder = minicbor::Decoder::new(response_bytes);
    let mut context = V2DecodeContext;
    let response = PrepareIngressResponseV2::decode(&mut response_decoder, &mut context)
        .map_err(|_| AgentTaskErrorV2::DurableState)?;
    if response_decoder.position() != response_bytes.len()
        || minicbor::to_vec(response).map_err(|_| AgentTaskErrorV2::DurableState)? != response_bytes
    {
        return Err(AgentTaskErrorV2::DurableState);
    }
    Ok(PrepareReplayRecordV2 {
        jarvis_principal,
        jarvis_os_peer_class,
        client_request_nonce,
        request_digest,
        response,
    })
}

fn validate_service(service: &AgentTaskServiceV2) -> Result<(), AgentTaskErrorV2> {
    if [
        service.installation_id.as_bytes(),
        service.active_state_manifest_digest.as_bytes(),
        service.protocol_abi_digest.as_bytes(),
        service.agentd_identity.as_bytes(),
        service.kernel_task_authority_key_id.as_bytes(),
        service.kernel_task_authority_binding_digest.as_bytes(),
        service.current_agentd_boot_id.as_bytes(),
        service.current_kerneld_boot_id.as_bytes(),
    ]
    .iter()
    .any(|value| is_zero(value))
        || service.deployment_generation == 0
        || service.maximum_tasks == 0
        || service.maximum_tasks > MAX_TASKS
        || service.tasks.len() > service.maximum_tasks
        || service.prepare_replays.len() > MAX_PREPARE_REPLAYS
    {
        return Err(AgentTaskErrorV2::DurableState);
    }
    for (index, task) in service.tasks.iter().enumerate() {
        if [
            task.task_handle_digest.as_bytes(),
            task.jarvis_principal.as_bytes(),
            task.jarvis_os_peer_class.as_bytes(),
            task.origin_boots.machine_boot_id.as_bytes(),
            task.origin_boots.jarvis_control_client_boot_id.as_bytes(),
            task.origin_boots.agentd_server_boot_id.as_bytes(),
            task.origin_boots.kerneld_server_boot_id.as_bytes(),
            task.durable_task_id.as_bytes(),
            task.correlation_digest.as_bytes(),
            task.kernel_bootstrap_binding_digest.as_bytes(),
            task.creating_manifest_digest.as_bytes(),
            task.protocol_abi_digest.as_bytes(),
        ]
        .iter()
        .any(|value| is_zero(value))
            || task.task_handle_digest != task_handle_digest(task.task_handle)?
            || task.creating_manifest_digest != service.active_state_manifest_digest
            || task.creating_deployment_generation != service.deployment_generation
            || task.protocol_abi_digest != service.protocol_abi_digest
            || task.creating_deployment_generation == 0
            || task.task_logical_expires_at.get() == 0
            || task.status_retain_until.get() <= task.task_logical_expires_at.get()
            || task.public_state_revision == 0
            || task
                .cancellation_commit_digest
                .is_some_and(|digest| is_zero(digest.as_bytes()))
            || !bootstrap_state_is_consistent(task)
            || task
                .kernel_correlation
                .correlation_digest()
                .map_err(|_| AgentTaskErrorV2::DurableState)?
                != task.correlation_digest
            || task.kernel_correlation.unsigned().durable_task_id() != task.durable_task_id
            || (task.status == savana_kernel_protocol::v2::PublicTaskStatusV2::Cancelled)
                != task.cancellation_commit_digest.is_some()
        {
            return Err(AgentTaskErrorV2::DurableState);
        }
        if service.tasks[..index].iter().any(|other| {
            other.task_handle_digest == task.task_handle_digest
                || other.durable_task_id == task.durable_task_id
                || other.correlation_digest == task.correlation_digest
        }) {
            return Err(AgentTaskErrorV2::DurableState);
        }
        encode_public_task_status_v2(&task.status).map_err(|_| AgentTaskErrorV2::DurableState)?;
    }
    for (index, replay) in service.prepare_replays.iter().enumerate() {
        if [
            replay.jarvis_principal.as_bytes(),
            replay.jarvis_os_peer_class.as_bytes(),
            replay.client_request_nonce.as_bytes(),
            replay.request_digest.as_bytes(),
        ]
        .iter()
        .any(|value| is_zero(value))
            || !service.tasks.iter().any(|task| {
                task.task_handle == replay.response.task()
                    && task.jarvis_principal == replay.jarvis_principal
                    && task.jarvis_os_peer_class == replay.jarvis_os_peer_class
            })
            || service.prepare_replays[..index].iter().any(|other| {
                other.jarvis_principal == replay.jarvis_principal
                    && other.jarvis_os_peer_class == replay.jarvis_os_peer_class
                    && other.client_request_nonce == replay.client_request_nonce
            })
        {
            return Err(AgentTaskErrorV2::DurableState);
        }
    }
    Ok(())
}

fn encode_optional_digest(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    value: Option<Digest32V2>,
) -> Result<(), AgentTaskErrorV2> {
    match value {
        Some(value) => value
            .encode(encoder, &mut ())
            .map_err(|_| AgentTaskErrorV2::AllocationFailure),
        None => encoder
            .null()
            .map(|_| ())
            .map_err(|_| AgentTaskErrorV2::AllocationFailure),
    }
}

fn encode_optional_selector(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    value: Option<JarvisBootstrapSelectorV2>,
) -> Result<(), AgentTaskErrorV2> {
    match value {
        Some(value) => value
            .encode(encoder, &mut ())
            .map_err(|_| AgentTaskErrorV2::AllocationFailure),
        None => encoder
            .null()
            .map(|_| ())
            .map_err(|_| AgentTaskErrorV2::AllocationFailure),
    }
}

fn encode_optional_boot(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    value: Option<BootIdV2>,
) -> Result<(), AgentTaskErrorV2> {
    match value {
        Some(value) => value
            .encode(encoder, &mut ())
            .map_err(|_| AgentTaskErrorV2::AllocationFailure),
        None => encoder
            .null()
            .map(|_| ())
            .map_err(|_| AgentTaskErrorV2::AllocationFailure),
    }
}

fn encode_optional_ingress_transfer(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    value: Option<KernelIngressBootstrapTransferCapabilityV2>,
) -> Result<(), AgentTaskErrorV2> {
    match value {
        Some(value) => value
            .encode(encoder, &mut ())
            .map_err(|_| AgentTaskErrorV2::AllocationFailure),
        None => encoder
            .null()
            .map(|_| ())
            .map_err(|_| AgentTaskErrorV2::AllocationFailure),
    }
}

fn decode_optional_selector(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<Option<JarvisBootstrapSelectorV2>, AgentTaskErrorV2> {
    decode_optional_typed(decoder)
}

fn decode_optional_boot(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<Option<BootIdV2>, AgentTaskErrorV2> {
    decode_optional_typed(decoder)
}

fn decode_optional_ingress_transfer(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<Option<KernelIngressBootstrapTransferCapabilityV2>, AgentTaskErrorV2> {
    decode_optional_typed(decoder)
}

fn decode_optional_typed<T>(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<Option<T>, AgentTaskErrorV2>
where
    for<'bytes> T: minicbor::Decode<'bytes, V2DecodeContext>,
{
    if decoder
        .datatype()
        .map_err(|_| AgentTaskErrorV2::DurableState)?
        == minicbor::data::Type::Null
    {
        decoder.null().map_err(|_| AgentTaskErrorV2::DurableState)?;
        Ok(None)
    } else {
        let mut context = V2DecodeContext;
        T::decode(decoder, &mut context)
            .map(Some)
            .map_err(|_| AgentTaskErrorV2::DurableState)
    }
}

fn bootstrap_state_is_consistent(task: &TaskResolverRecordV2) -> bool {
    match (
        task.bootstrap_selector,
        task.bootstrap_agentd_boot_id,
        task.kernel_ingress_transfer,
        task.status,
    ) {
        (
            Some(selector),
            Some(_),
            Some(_),
            savana_kernel_protocol::v2::PublicTaskStatusV2::AwaitingUiAuthentication {
                bootstrap: Some(JarvisBootstrapActionV2::OpenIngress { url }),
            },
        ) => url.kind() == BootstrapKindV2::Ingress && url.selector() == selector,
        (
            Some(selector),
            Some(_),
            None,
            savana_kernel_protocol::v2::PublicTaskStatusV2::Ready {
                bootstrap: Some(JarvisBootstrapActionV2::OpenAgent { url }),
            },
        ) => url.kind() == BootstrapKindV2::Agent && url.selector() == selector,
        (None, None, None, status) => status == super::strip_bootstrap(status),
        _ => false,
    }
}

fn derive_encryption_key(
    master: &[u8; 32],
    namespace: DurableAgentTaskNamespaceV2,
) -> Result<Zeroizing<[u8; 32]>, AgentTaskErrorV2> {
    let mut mac = <Hmac<Sha256> as hmac::Mac>::new_from_slice(master)
        .map_err(|_| AgentTaskErrorV2::DurableState)?;
    mac.update(KEY_DERIVATION_DOMAIN);
    mac.update(namespace.installation_id.as_bytes());
    mac.update(namespace.store_id.as_bytes());
    Ok(Zeroizing::new(mac.finalize().into_bytes().into()))
}

fn encryption_aad(
    namespace: DurableAgentTaskNamespaceV2,
    sequence: u64,
    previous_state_digest: Digest32V2,
    nonce: &[u8; NONCE_BYTES],
) -> Vec<u8> {
    let mut aad = Vec::from(ENCRYPTION_DOMAIN);
    aad.extend_from_slice(namespace.installation_id.as_bytes());
    aad.extend_from_slice(namespace.store_id.as_bytes());
    aad.extend_from_slice(&sequence.to_be_bytes());
    aad.extend_from_slice(previous_state_digest.as_bytes());
    aad.extend_from_slice(nonce);
    aad
}

fn state_head_digest(namespace: DurableAgentTaskNamespaceV2, bytes: &[u8]) -> Digest32V2 {
    let mut hasher = Sha256::new();
    hasher.update(HEAD_DOMAIN);
    hasher.update(namespace.installation_id.as_bytes());
    hasher.update(namespace.store_id.as_bytes());
    hasher.update(bytes);
    Digest32V2::new(hasher.finalize().into())
}

struct AnchoredPathV2 {
    parent: File,
    parent_path: PathBuf,
    parent_dev: u64,
    parent_ino: u64,
    leaf: OsString,
    owner_uid: u32,
    owner_gid: u32,
}

impl AnchoredPathV2 {
    fn open(path: &Path) -> Result<Self, AgentTaskErrorV2> {
        if !path.is_absolute() {
            return Err(AgentTaskErrorV2::DurableState);
        }
        let parent_path = path.parent().ok_or(AgentTaskErrorV2::DurableState)?;
        let leaf = path
            .file_name()
            .ok_or(AgentTaskErrorV2::DurableState)?
            .to_os_string();
        let before =
            fs::symlink_metadata(parent_path).map_err(|_| AgentTaskErrorV2::DurableState)?;
        if before.file_type().is_symlink() {
            return Err(AgentTaskErrorV2::DurableState);
        }
        let descriptor = rustix_open(
            parent_path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| AgentTaskErrorV2::DurableState)?;
        let parent = File::from(descriptor);
        let opened = parent
            .metadata()
            .map_err(|_| AgentTaskErrorV2::DurableState)?;
        if !opened.is_dir()
            || opened.dev() != before.dev()
            || opened.ino() != before.ino()
            || opened.uid() != before.uid()
            || opened.gid() != before.gid()
            || opened.mode() & 0o7777 != 0o700
        {
            return Err(AgentTaskErrorV2::DurableState);
        }
        let anchored = Self {
            parent,
            parent_path: parent_path.to_owned(),
            parent_dev: opened.dev(),
            parent_ino: opened.ino(),
            leaf,
            owner_uid: opened.uid(),
            owner_gid: opened.gid(),
        };
        anchored.recheck_parent()?;
        Ok(anchored)
    }

    fn recheck_parent(&self) -> Result<(), AgentTaskErrorV2> {
        let opened = self
            .parent
            .metadata()
            .map_err(|_| AgentTaskErrorV2::DurableState)?;
        let linked =
            fs::symlink_metadata(&self.parent_path).map_err(|_| AgentTaskErrorV2::DurableState)?;
        if linked.file_type().is_symlink()
            || !linked.is_dir()
            || opened.dev() != self.parent_dev
            || opened.ino() != self.parent_ino
            || linked.dev() != self.parent_dev
            || linked.ino() != self.parent_ino
            || linked.uid() != self.owner_uid
            || linked.gid() != self.owner_gid
            || linked.mode() & 0o7777 != 0o700
        {
            return Err(AgentTaskErrorV2::DurableState);
        }
        Ok(())
    }

    fn read_existing(&self) -> Result<Option<Vec<u8>>, AgentTaskErrorV2> {
        let before = match statat(&self.parent, &self.leaf, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => stat,
            Err(Errno::NOENT) => return Ok(None),
            Err(_) => return Err(AgentTaskErrorV2::DurableState),
        };
        if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile {
            return Err(AgentTaskErrorV2::DurableState);
        }
        let descriptor = openat(
            &self.parent,
            &self.leaf,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| AgentTaskErrorV2::DurableState)?;
        let mut file = File::from(descriptor);
        let opened = file
            .metadata()
            .map_err(|_| AgentTaskErrorV2::DurableState)?;
        if !opened.is_file()
            || i128::from(before.st_dev) != i128::from(opened.dev())
            || before.st_ino != opened.ino()
            || before.st_uid != self.owner_uid
            || before.st_gid != self.owner_gid
            || opened.uid() != self.owner_uid
            || opened.gid() != self.owner_gid
            || opened.mode() & 0o7777 != 0o600
            || opened.nlink() != 1
            || opened.len() > MAX_STATE_BYTES
        {
            return Err(AgentTaskErrorV2::DurableState);
        }
        let capacity = usize::try_from(opened.len()).map_err(|_| AgentTaskErrorV2::DurableState)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(capacity)
            .map_err(|_| AgentTaskErrorV2::AllocationFailure)?;
        file.read_to_end(&mut bytes)
            .map_err(|_| AgentTaskErrorV2::DurableState)?;
        let after = statat(&self.parent, &self.leaf, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| AgentTaskErrorV2::DurableState)?;
        if bytes.len() != capacity
            || i128::from(after.st_dev) != i128::from(opened.dev())
            || after.st_ino != opened.ino()
            || u64::try_from(after.st_size).ok() != Some(opened.len())
        {
            return Err(AgentTaskErrorV2::DurableState);
        }
        self.recheck_parent()?;
        Ok(Some(bytes))
    }

    fn replace(&self, bytes: &[u8]) -> Result<(), bool> {
        let (temporary_leaf, mut temporary) =
            create_temporary(&self.parent, &self.leaf, self.owner_uid, self.owner_gid)
                .map_err(|_| false)?;
        let before_rename = (|| {
            temporary
                .write_all(bytes)
                .map_err(|_| AgentTaskErrorV2::DurableState)?;
            temporary
                .sync_all()
                .map_err(|_| AgentTaskErrorV2::DurableState)?;
            validate_file_at(
                &self.parent,
                &temporary_leaf,
                &temporary,
                self.owner_uid,
                self.owner_gid,
                u64::try_from(bytes.len()).map_err(|_| AgentTaskErrorV2::DurableState)?,
            )?;
            self.recheck_parent()
        })();
        if before_rename.is_err() {
            let _ = unlinkat(&self.parent, &temporary_leaf, AtFlags::empty());
            return Err(false);
        }
        if renameat(&self.parent, &temporary_leaf, &self.parent, &self.leaf).is_err() {
            let _ = unlinkat(&self.parent, &temporary_leaf, AtFlags::empty());
            return Err(false);
        }
        validate_file_at(
            &self.parent,
            &self.leaf,
            &temporary,
            self.owner_uid,
            self.owner_gid,
            u64::try_from(bytes.len()).map_err(|_| true)?,
        )
        .map_err(|_| true)?;
        self.parent.sync_all().map_err(|_| true)?;
        self.recheck_parent().map_err(|_| true)
    }
}

fn create_temporary(
    parent: &File,
    final_leaf: &OsStr,
    owner_uid: u32,
    owner_gid: u32,
) -> Result<(OsString, File), AgentTaskErrorV2> {
    for _ in 0..TEMP_ATTEMPTS {
        let mut random = [0_u8; 16];
        getrandom::getrandom(&mut random).map_err(|_| AgentTaskErrorV2::DurableState)?;
        let mut temporary_leaf = OsString::from(".");
        temporary_leaf.push(final_leaf);
        temporary_leaf.push(".tmp-");
        temporary_leaf.push(hex(&random));
        match openat(
            parent,
            &temporary_leaf,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_bits_truncate(0o600),
        ) {
            Ok(descriptor) => {
                let file = File::from(descriptor);
                fchmod(&file, Mode::from_bits_truncate(0o600))
                    .map_err(|_| AgentTaskErrorV2::DurableState)?;
                validate_file_at(parent, &temporary_leaf, &file, owner_uid, owner_gid, 0)?;
                return Ok((temporary_leaf, file));
            }
            Err(Errno::EXIST) => {}
            Err(_) => return Err(AgentTaskErrorV2::DurableState),
        }
    }
    Err(AgentTaskErrorV2::DurableState)
}

fn validate_file_at(
    parent: &File,
    leaf: &OsStr,
    file: &File,
    owner_uid: u32,
    owner_gid: u32,
    expected_length: u64,
) -> Result<(), AgentTaskErrorV2> {
    let opened = file
        .metadata()
        .map_err(|_| AgentTaskErrorV2::DurableState)?;
    let linked = statat(parent, leaf, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| AgentTaskErrorV2::DurableState)?;
    if !opened.is_file()
        || opened.uid() != owner_uid
        || opened.gid() != owner_gid
        || opened.mode() & 0o7777 != 0o600
        || opened.nlink() != 1
        || opened.len() != expected_length
        || FileType::from_raw_mode(linked.st_mode) != FileType::RegularFile
        || i128::from(linked.st_dev) != i128::from(opened.dev())
        || linked.st_ino != opened.ino()
        || linked.st_uid != owner_uid
        || linked.st_gid != owner_gid
        || linked.st_mode & 0o7777 != 0o600
        || linked.st_nlink != 1
        || u64::try_from(linked.st_size).ok() != Some(expected_length)
    {
        return Err(AgentTaskErrorV2::DurableState);
    }
    Ok(())
}

struct StateLockV2 {
    file: Flock<File>,
    parent: File,
    leaf: OsString,
    owner_uid: u32,
    owner_gid: u32,
}

impl StateLockV2 {
    fn acquire(
        parent: &File,
        leaf: &OsStr,
        owner_uid: u32,
        owner_gid: u32,
    ) -> Result<Self, AgentTaskErrorV2> {
        let descriptor = openat(
            parent,
            leaf,
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::from_bits_truncate(0o600),
        )
        .map_err(|_| AgentTaskErrorV2::DurableState)?;
        let file = File::from(descriptor);
        fchmod(&file, Mode::from_bits_truncate(0o600))
            .map_err(|_| AgentTaskErrorV2::DurableState)?;
        validate_file_at(parent, leaf, &file, owner_uid, owner_gid, 0)?;
        let file = Flock::lock(file, FlockArg::LockExclusiveNonblock)
            .map_err(|_| AgentTaskErrorV2::DurableState)?;
        validate_file_at(parent, leaf, &file, owner_uid, owner_gid, 0)?;
        parent
            .sync_all()
            .map_err(|_| AgentTaskErrorV2::DurableState)?;
        Ok(Self {
            file,
            parent: parent
                .try_clone()
                .map_err(|_| AgentTaskErrorV2::DurableState)?,
            leaf: leaf.to_os_string(),
            owner_uid,
            owner_gid,
        })
    }

    fn recheck(&self) -> Result<(), AgentTaskErrorV2> {
        validate_file_at(
            &self.parent,
            &self.leaf,
            &self.file,
            self.owner_uid,
            self.owner_gid,
            0,
        )
    }
}

fn require_array(
    decoder: &mut minicbor::Decoder<'_>,
    expected: u64,
) -> Result<(), AgentTaskErrorV2> {
    if decoder
        .array()
        .map_err(|_| AgentTaskErrorV2::DurableState)?
        != Some(expected)
    {
        return Err(AgentTaskErrorV2::DurableState);
    }
    Ok(())
}

fn decode_count(
    decoder: &mut minicbor::Decoder<'_>,
    maximum: usize,
) -> Result<usize, AgentTaskErrorV2> {
    let count = decoder
        .array()
        .map_err(|_| AgentTaskErrorV2::DurableState)?
        .ok_or(AgentTaskErrorV2::DurableState)?;
    let count = usize::try_from(count).map_err(|_| AgentTaskErrorV2::DurableState)?;
    if count > maximum {
        return Err(AgentTaskErrorV2::DurableState);
    }
    Ok(count)
}

fn decode_fixed<const N: usize>(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<[u8; N], AgentTaskErrorV2> {
    decoder
        .bytes()
        .map_err(|_| AgentTaskErrorV2::DurableState)?
        .try_into()
        .map_err(|_| AgentTaskErrorV2::DurableState)
}

fn decode_optional_digest(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<Option<Digest32V2>, AgentTaskErrorV2> {
    if decoder
        .datatype()
        .map_err(|_| AgentTaskErrorV2::DurableState)?
        == minicbor::data::Type::Null
    {
        decoder.null().map_err(|_| AgentTaskErrorV2::DurableState)?;
        Ok(None)
    } else {
        Ok(Some(Digest32V2::new(decode_fixed::<32>(decoder)?)))
    }
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

#[cfg(test)]
mod tests {
    use crate::{
        AgentControlDeploymentV2, AgentControlDispatcherV2, AgentControlKernelClientErrorV2,
        AgentControlKernelClientV2, AgentTaskStateOwnerV2, KernelTaskAuthorityVerifierV2,
        KernelTaskCancellationRequestV2, KernelTaskPreparationRequestV2, KernelTaskStatusRequestV2,
        VerifiedAgentControlPeerV2,
    };
    use ed25519_dalek::SigningKey;
    use std::os::unix::fs::PermissionsExt as _;
    use std::sync::{Arc, Mutex};

    use super::*;
    use savana_kernel_protocol::v2::{
        decode_agent_control_response_envelope_v2, encode_agent_control_request_envelope_v2,
        AgentControlOperationV2, AgentControlRequestEnvelopeV2, AgentControlResponseV2,
        NewTaskPreparationHandleV2, PrepareIngressRequestV2, PublicServiceStateV2,
        PublicTaskStatusV2, RequestIdV2, SignedDurableTaskCorrelationV2,
        UnsignedDurableTaskCorrelationV2,
    };
    use savana_kernel_protocol::StableCode;

    struct NoopKernelClient;

    impl AgentControlKernelClientV2 for NoopKernelClient {
        fn health(
            &mut self,
            _request_id: RequestIdV2,
            _deadline: UnixMillisV2,
        ) -> Result<PublicServiceStateV2, AgentControlKernelClientErrorV2> {
            Err(AgentControlKernelClientErrorV2::Unavailable)
        }

        fn prepare_task(
            &mut self,
            _request: KernelTaskPreparationRequestV2,
        ) -> Result<VerifiedKernelTaskPreparationV2, AgentControlKernelClientErrorV2> {
            Err(AgentControlKernelClientErrorV2::Unavailable)
        }

        fn query_task(
            &mut self,
            _request: KernelTaskStatusRequestV2,
        ) -> Result<VerifiedKernelTaskStatusV2, AgentControlKernelClientErrorV2> {
            Err(AgentControlKernelClientErrorV2::Unavailable)
        }

        fn cancel_task(
            &mut self,
            _request: KernelTaskCancellationRequestV2,
        ) -> Result<VerifiedKernelCancellationV2, AgentControlKernelClientErrorV2> {
            Err(AgentControlKernelClientErrorV2::Unavailable)
        }
    }

    struct SigningKernelClient;

    impl AgentControlKernelClientV2 for SigningKernelClient {
        fn health(
            &mut self,
            _request_id: RequestIdV2,
            _deadline: UnixMillisV2,
        ) -> Result<PublicServiceStateV2, AgentControlKernelClientErrorV2> {
            Ok(PublicServiceStateV2::Ready)
        }

        fn prepare_task(
            &mut self,
            request: KernelTaskPreparationRequestV2,
        ) -> Result<VerifiedKernelTaskPreparationV2, AgentControlKernelClientErrorV2> {
            let unsigned = UnsignedDurableTaskCorrelationV2::new(
                Digest32V2::new([1; 32]),
                Digest32V2::new([2; 32]),
                3,
                DurableTaskIdV2::new([0x91; 32]),
                ServiceIdentityV2::new([5; 32]),
                BootIdV2::new([15; 32]),
                BootIdV2::new([16; 32]),
                request.machine_boot_id(),
                UnixMillisV2::new(1),
                UnixMillisV2::new(900),
                UnixMillisV2::new(1_100),
            )
            .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)?;
            let correlation =
                SignedDurableTaskCorrelationV2::sign(unsigned, &SigningKey::from_bytes(&[61; 32]))
                    .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)?;
            let correlation_digest = correlation
                .correlation_digest()
                .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)?;
            VerifiedKernelTaskPreparationV2::from_verified_kernel_response(
                DurableTaskIdV2::new([0x91; 32]),
                correlation_digest,
                Digest32V2::new([0x93; 32]),
                UnixMillisV2::new(900),
                UnixMillisV2::new(1_100),
                authority_binding_digest(),
                NewTaskPreparationHandleV2::from_authority_entropy([0x94; 32]).unwrap(),
                correlation,
                savana_kernel_protocol::v2::KernelIngressBootstrapTransferCapabilityV2::from_authority_entropy([0x95; 32])
                    .unwrap(),
            )
            .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)
        }

        fn cancel_task(
            &mut self,
            _request: KernelTaskCancellationRequestV2,
        ) -> Result<VerifiedKernelCancellationV2, AgentControlKernelClientErrorV2> {
            Err(AgentControlKernelClientErrorV2::Unavailable)
        }

        fn query_task(
            &mut self,
            request: KernelTaskStatusRequestV2,
        ) -> Result<VerifiedKernelTaskStatusV2, AgentControlKernelClientErrorV2> {
            VerifiedKernelTaskStatusV2::from_verified_query(
                request.durable_task_id(),
                request.correlation_digest(),
                PublicTaskStatusV2::AwaitingInput,
                request.status_revision() + 1,
                authority_binding_digest(),
            )
            .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)
        }
    }

    fn authority_key_id() -> savana_kernel_protocol::v2::Ed25519KeyIdV2 {
        savana_kernel_protocol::v2::Ed25519KeyIdV2::new([60; 32])
    }

    fn authority_public_key() -> [u8; 32] {
        SigningKey::from_bytes(&[61; 32]).verifying_key().to_bytes()
    }

    fn authority_binding_digest() -> Digest32V2 {
        crate::kernel_authority::kernel_task_authority_binding_digest(
            authority_key_id(),
            &authority_public_key(),
        )
    }

    #[derive(Clone)]
    struct MemoryAnchor(Arc<Mutex<AgentTaskStateHeadV2>>);

    impl MemoryAnchor {
        fn new() -> Self {
            Self(Arc::new(Mutex::new(AgentTaskStateHeadV2::default())))
        }
    }

    impl AgentTaskRollbackAnchorV2 for MemoryAnchor {
        fn current_head(&self) -> Result<AgentTaskStateHeadV2, AgentTaskErrorV2> {
            self.0
                .lock()
                .map(|head| *head)
                .map_err(|_| AgentTaskErrorV2::DurableState)
        }

        fn compare_and_advance(
            &mut self,
            expected: AgentTaskStateHeadV2,
            next: AgentTaskStateHeadV2,
        ) -> Result<(), AgentTaskErrorV2> {
            let mut head = self.0.lock().map_err(|_| AgentTaskErrorV2::DurableState)?;
            if *head != expected {
                return Err(AgentTaskErrorV2::RollbackDetected);
            }
            *head = next;
            Ok(())
        }
    }

    fn deployment(agent_boot: u8, kernel_boot: u8) -> AgentTaskServiceV2 {
        AgentTaskServiceV2::from_verified_deployment(
            Digest32V2::new([1; 32]),
            Digest32V2::new([2; 32]),
            3,
            Digest32V2::new([4; 32]),
            ServiceIdentityV2::new([5; 32]),
            BootIdV2::new([agent_boot; 32]),
            BootIdV2::new([kernel_boot; 32]),
            authority_key_id(),
            authority_public_key(),
            128,
        )
        .unwrap()
    }

    fn context(agent_boot: u8, kernel_boot: u8) -> AuthenticatedJarvisControlV2 {
        AuthenticatedJarvisControlV2::from_mutual_authentication(
            Digest32V2::new([1; 32]),
            Digest32V2::new([6; 32]),
            Digest32V2::new([7; 32]),
            BootIdV2::new([8; 32]),
            BootIdV2::new([9; 32]),
            BootIdV2::new([agent_boot; 32]),
            BootIdV2::new([kernel_boot; 32]),
        )
        .unwrap()
    }

    fn preparation() -> VerifiedKernelTaskPreparationV2 {
        let unsigned = UnsignedDurableTaskCorrelationV2::new(
            Digest32V2::new([1; 32]),
            Digest32V2::new([2; 32]),
            3,
            DurableTaskIdV2::new([10; 32]),
            ServiceIdentityV2::new([5; 32]),
            BootIdV2::new([13; 32]),
            BootIdV2::new([14; 32]),
            BootIdV2::new([8; 32]),
            UnixMillisV2::new(1),
            UnixMillisV2::new(10_000),
            UnixMillisV2::new(20_000),
        )
        .unwrap();
        let correlation =
            SignedDurableTaskCorrelationV2::sign(unsigned, &SigningKey::from_bytes(&[61; 32]))
                .unwrap();
        let correlation_digest = correlation.correlation_digest().unwrap();
        VerifiedKernelTaskPreparationV2::from_verified_kernel_response(
            DurableTaskIdV2::new([10; 32]),
            correlation_digest,
            Digest32V2::new([12; 32]),
            UnixMillisV2::new(10_000),
            UnixMillisV2::new(20_000),
            authority_binding_digest(),
            NewTaskPreparationHandleV2::from_authority_entropy([15; 32]).unwrap(),
            correlation,
            savana_kernel_protocol::v2::KernelIngressBootstrapTransferCapabilityV2::from_authority_entropy([16; 32]).unwrap(),
        )
        .unwrap()
    }

    fn store() -> (
        tempfile::TempDir,
        PathBuf,
        DurableAgentTaskNamespaceV2,
        MemoryAnchor,
    ) {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.path().join(STATE_FILE_NAME);
        let namespace = DurableAgentTaskNamespaceV2::from_verified_installation(
            Digest32V2::new([1; 32]),
            Digest32V2::new([13; 32]),
        )
        .unwrap();
        (directory, path, namespace, MemoryAnchor::new())
    }

    #[test]
    fn production_state_owner_exclusively_owns_the_durable_task_store() {
        let (_directory, path, namespace, anchor) = store();
        let owner = AgentTaskStateOwnerV2::open(
            &path,
            [0x71; 32],
            namespace,
            Box::new(anchor),
            deployment(15, 16),
            16,
        )
        .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);

        let response = owner
            .prepare_ingress(
                context(15, 16),
                Nonce32V2::new([0x72; 32]),
                preparation(),
                UnixMillisV2::new(100),
                deadline,
            )
            .unwrap();
        assert_eq!(
            owner
                .get_task_status(
                    context(15, 16),
                    GetTaskStatusRequestV2::new(response.task()),
                    UnixMillisV2::new(101),
                    std::time::Instant::now() + std::time::Duration::from_secs(1),
                )
                .unwrap()
                .status(),
            PublicTaskStatusV2::AwaitingUiAuthentication {
                bootstrap: Some(response.bootstrap())
            }
        );
        assert_eq!(
            owner
                .recovery_projection(std::time::Instant::now() + std::time::Duration::from_secs(1))
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn authenticated_agent_control_health_fails_closed_when_kernel_is_unavailable() {
        let (_directory, path, namespace, anchor) = store();
        let tasks = AgentTaskStateOwnerV2::open(
            &path,
            [0x73; 32],
            namespace,
            Box::new(anchor),
            deployment(15, 16),
            16,
        )
        .unwrap();
        let edge = AgentControlDeploymentV2::from_verified_deployment(
            Digest32V2::new([1; 32]),
            Digest32V2::new([2; 32]),
            3,
            Digest32V2::new([4; 32]),
            ServiceIdentityV2::new([5; 32]),
            BootIdV2::new([15; 32]),
            BootIdV2::new([16; 32]),
            ServiceIdentityV2::new([0x81; 32]),
        )
        .unwrap();
        let verifier = KernelTaskAuthorityVerifierV2::from_verified_deployment(
            Digest32V2::new([1; 32]),
            Digest32V2::new([2; 32]),
            3,
            Digest32V2::new([4; 32]),
            ServiceIdentityV2::new([5; 32]),
            BootIdV2::new([15; 32]),
            BootIdV2::new([16; 32]),
            authority_key_id(),
            authority_public_key(),
        )
        .unwrap();
        let dispatcher =
            AgentControlDispatcherV2::spawn(edge, tasks, verifier, NoopKernelClient, 16).unwrap();
        let peer = VerifiedAgentControlPeerV2::from_mutual_authentication(
            Digest32V2::new([6; 32]),
            Digest32V2::new([7; 32]),
            BootIdV2::new([8; 32]),
            BootIdV2::new([9; 32]),
            ServiceIdentityV2::new([0x81; 32]),
        )
        .unwrap();
        let request = AgentControlRequestEnvelopeV2::from_authenticated_connection(
            RequestIdV2::new([0x82; 16]),
            BootIdV2::new([9; 32]),
            BootIdV2::new([15; 32]),
            ServiceIdentityV2::new([0x81; 32]),
            ServiceIdentityV2::new([5; 32]),
            Digest32V2::new([2; 32]),
            3,
            UnixMillisV2::new(1_000),
            AgentControlOperationV2::Health,
        )
        .unwrap();

        let response = dispatcher
            .dispatch_canonical(
                &encode_agent_control_request_envelope_v2(&request).unwrap(),
                peer,
                UnixMillisV2::new(100),
                std::time::Instant::now() + std::time::Duration::from_secs(1),
            )
            .unwrap();

        assert_eq!(
            decode_agent_control_response_envelope_v2(&response)
                .unwrap()
                .response()
                .stable_error(),
            Some(StableCode::KernelUnavailable),
        );
    }

    #[test]
    fn authenticated_prepare_ingress_verifies_kernel_statement_and_returns_only_public_dto() {
        let (_directory, path, namespace, anchor) = store();
        let tasks = AgentTaskStateOwnerV2::open(
            &path,
            [0x74; 32],
            namespace,
            Box::new(anchor),
            deployment(15, 16),
            16,
        )
        .unwrap();
        let edge = AgentControlDeploymentV2::from_verified_deployment(
            Digest32V2::new([1; 32]),
            Digest32V2::new([2; 32]),
            3,
            Digest32V2::new([4; 32]),
            ServiceIdentityV2::new([5; 32]),
            BootIdV2::new([15; 32]),
            BootIdV2::new([16; 32]),
            ServiceIdentityV2::new([0x81; 32]),
        )
        .unwrap();
        let verifier = KernelTaskAuthorityVerifierV2::from_verified_deployment(
            Digest32V2::new([1; 32]),
            Digest32V2::new([2; 32]),
            3,
            Digest32V2::new([4; 32]),
            ServiceIdentityV2::new([5; 32]),
            BootIdV2::new([15; 32]),
            BootIdV2::new([16; 32]),
            authority_key_id(),
            authority_public_key(),
        )
        .unwrap();
        let dispatcher =
            AgentControlDispatcherV2::spawn(edge, tasks, verifier, SigningKernelClient, 16)
                .unwrap();
        let peer = VerifiedAgentControlPeerV2::from_mutual_authentication(
            Digest32V2::new([6; 32]),
            Digest32V2::new([7; 32]),
            BootIdV2::new([8; 32]),
            BootIdV2::new([9; 32]),
            ServiceIdentityV2::new([0x81; 32]),
        )
        .unwrap();
        let request = AgentControlRequestEnvelopeV2::from_authenticated_connection(
            RequestIdV2::new([0x83; 16]),
            BootIdV2::new([9; 32]),
            BootIdV2::new([15; 32]),
            ServiceIdentityV2::new([0x81; 32]),
            ServiceIdentityV2::new([5; 32]),
            Digest32V2::new([2; 32]),
            3,
            UnixMillisV2::new(800),
            AgentControlOperationV2::PrepareIngress(PrepareIngressRequestV2::new(Nonce32V2::new(
                [0x84; 32],
            ))),
        )
        .unwrap();

        let response = dispatcher
            .dispatch_canonical(
                &encode_agent_control_request_envelope_v2(&request).unwrap(),
                peer,
                UnixMillisV2::new(100),
                std::time::Instant::now() + std::time::Duration::from_secs(1),
            )
            .unwrap();
        let AgentControlResponseV2::PrepareIngress(prepared) =
            decode_agent_control_response_envelope_v2(&response)
                .unwrap()
                .response()
        else {
            panic!("dispatcher did not return prepare-ingress response");
        };

        assert_eq!(format!("{:?}", prepared.task()), "TaskHandleV2(<opaque>)");
        assert!(matches!(
            prepared.bootstrap(),
            JarvisBootstrapActionV2::OpenIngress { .. }
        ));
    }

    #[test]
    fn task_handle_and_kernel_cancel_authority_survive_restart_but_remain_unexposed() {
        let (_directory, path, namespace, anchor) = store();
        let key = [14; 32];
        let response = {
            let mut service = DurableAgentTaskServiceV2::open(
                &path,
                key,
                namespace,
                Box::new(anchor.clone()),
                deployment(15, 16),
            )
            .unwrap();
            service
                .prepare_ingress(
                    context(15, 16),
                    Nonce32V2::new([17; 32]),
                    preparation(),
                    UnixMillisV2::new(100),
                )
                .unwrap()
        };

        let encrypted = fs::read(&path).unwrap();
        assert!(!encrypted
            .windows(32)
            .any(|window| window == DurableTaskIdV2::new([10; 32]).as_bytes()));

        let mut restored = DurableAgentTaskServiceV2::open(
            &path,
            key,
            namespace,
            Box::new(anchor),
            deployment(18, 19),
        )
        .unwrap();
        assert_eq!(restored.task_count(), 1);
        let replay = restored
            .prepare_ingress(
                context(18, 19),
                Nonce32V2::new([17; 32]),
                preparation(),
                UnixMillisV2::new(101),
            )
            .unwrap();
        assert_eq!(replay.task(), response.task());
        assert_eq!(replay.bootstrap(), JarvisBootstrapActionV2::None);
        assert_eq!(
            restored
                .get_task_status(
                    context(18, 19),
                    GetTaskStatusRequestV2::new(response.task()),
                    UnixMillisV2::new(102),
                )
                .unwrap()
                .status(),
            PublicTaskStatusV2::AwaitingUiAuthentication { bootstrap: None }
        );
        assert_eq!(
            restored.prepare_cancel(
                context(18, 19),
                CancelTaskRequestV2::new(response.task()),
                UnixMillisV2::new(103),
            ),
            Err(AgentTaskErrorV2::CancellationTooLate)
        );
    }

    #[test]
    fn same_boot_restart_recovers_the_exact_kernel_cancel_authority() {
        let (_directory, path, namespace, anchor) = store();
        let key = [0x31; 32];
        let prepared = preparation();
        let response = {
            let mut service = DurableAgentTaskServiceV2::open(
                &path,
                key,
                namespace,
                Box::new(anchor.clone()),
                deployment(15, 16),
            )
            .unwrap();
            service
                .prepare_ingress(
                    context(15, 16),
                    Nonce32V2::new([0x32; 32]),
                    prepared.clone(),
                    UnixMillisV2::new(100),
                )
                .unwrap()
        };
        let mut restored = DurableAgentTaskServiceV2::open(
            &path,
            key,
            namespace,
            Box::new(anchor),
            deployment(15, 16),
        )
        .unwrap();

        let pending = restored
            .prepare_cancel(
                context(15, 16),
                CancelTaskRequestV2::new(response.task()),
                UnixMillisV2::new(101),
            )
            .unwrap();

        assert_eq!(
            pending.kernel_preparation,
            prepared.kernel_preparation().unwrap()
        );
        assert_eq!(
            &pending.kernel_correlation,
            prepared.kernel_correlation().unwrap()
        );
    }

    #[test]
    fn external_head_rejects_an_authenticated_old_snapshot() {
        let (_directory, path, namespace, anchor) = store();
        let key = [20; 32];
        let prepared = preparation();
        let old_snapshot = {
            let mut service = DurableAgentTaskServiceV2::open(
                &path,
                key,
                namespace,
                Box::new(anchor.clone()),
                deployment(21, 22),
            )
            .unwrap();
            service
                .prepare_ingress(
                    context(21, 22),
                    Nonce32V2::new([23; 32]),
                    prepared.clone(),
                    UnixMillisV2::new(200),
                )
                .unwrap();
            let old = fs::read(&path).unwrap();
            service
                .apply_verified_kernel_status(
                    VerifiedKernelTaskStatusV2::from_verified_query(
                        prepared.durable_task_id(),
                        prepared.correlation_digest(),
                        PublicTaskStatusV2::AwaitingInput,
                        2,
                        authority_binding_digest(),
                    )
                    .unwrap(),
                    UnixMillisV2::new(201),
                )
                .unwrap();
            old
        };
        fs::write(&path, old_snapshot).unwrap();
        assert_eq!(
            DurableAgentTaskServiceV2::open(
                &path,
                key,
                namespace,
                Box::new(anchor),
                deployment(21, 22),
            )
            .unwrap_err(),
            AgentTaskErrorV2::RollbackDetected
        );
    }

    #[test]
    fn wrong_key_cannot_authenticate_task_state() {
        let (_directory, path, namespace, anchor) = store();
        {
            let mut service = DurableAgentTaskServiceV2::open(
                &path,
                [24; 32],
                namespace,
                Box::new(anchor.clone()),
                deployment(25, 26),
            )
            .unwrap();
            service
                .prepare_ingress(
                    context(25, 26),
                    Nonce32V2::new([27; 32]),
                    preparation(),
                    UnixMillisV2::new(300),
                )
                .unwrap();
        }
        assert_eq!(
            DurableAgentTaskServiceV2::open(
                &path,
                [28; 32],
                namespace,
                Box::new(anchor),
                deployment(25, 26),
            )
            .unwrap_err(),
            AgentTaskErrorV2::DurableAuthentication
        );
    }

    #[test]
    fn rejected_durable_request_still_advances_the_clock_floor() {
        let (_directory, path, namespace, anchor) = store();
        let mut service = DurableAgentTaskServiceV2::open(
            &path,
            [29; 32],
            namespace,
            Box::new(anchor),
            deployment(30, 31),
        )
        .unwrap();
        let unknown = TaskHandleV2::from_authority_entropy([32; 32]).unwrap();
        assert_eq!(
            service.get_task_status(
                context(30, 31),
                GetTaskStatusRequestV2::new(unknown),
                UnixMillisV2::new(500),
            ),
            Err(AgentTaskErrorV2::InvalidReference)
        );
        assert_eq!(
            service.get_task_status(
                context(30, 31),
                GetTaskStatusRequestV2::new(unknown),
                UnixMillisV2::new(499),
            ),
            Err(AgentTaskErrorV2::ClockRollback)
        );
    }
}
