use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Instant;

use savana_kernel_protocol::v2::{
    decode_agent_control_request_envelope_v2, encode_agent_control_response_envelope_v2,
    AgentControlOperationV2, AgentControlRequestEnvelopeV2, AgentControlResponseEnvelopeV2,
    AgentControlResponseV2, BootIdV2, BootstrapKindV2, Digest32V2, DurableTaskIdV2,
    JarvisBootstrapSelectorV2, NewTaskPreparationHandleV2, Nonce32V2, PublicServiceStateV2,
    RequestIdV2, ServiceIdentityV2, SignedDurableTaskCorrelationV2, UnixMillisV2,
};
use savana_kernel_protocol::StableCode;

use crate::{
    is_zero, AgentTaskErrorV2, AgentTaskStateOwnerErrorV2, AgentTaskStateOwnerV2,
    AuthenticatedJarvisControlV2, KernelTaskAuthorityVerifierV2, ResolvedJarvisBootstrapV2,
    VerifiedKernelCancellationV2, VerifiedKernelTaskPreparationV2, VerifiedKernelTaskStatusV2,
};

const DISPATCH_RUNNING: u8 = 1;
const DISPATCH_CLOSING: u8 = 2;
const DISPATCH_FAILED: u8 = 3;
const DISPATCH_STOPPED: u8 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AgentControlDispatchErrorV2 {
    #[error("agent-control request protocol failed")]
    Protocol(StableCode),
    #[error("agent-control peer or request identity was rejected")]
    IdentityRejected,
    #[error("agent-control request deadline was exceeded")]
    DeadlineExceeded,
    #[error("agent-control deployment binding is invalid")]
    DeploymentBinding,
    #[error("agent-control runtime is overloaded")]
    Overloaded,
    #[error("agent-control runtime is unavailable")]
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernelTaskPreparationRequestV2 {
    request_id: RequestIdV2,
    client_request_nonce: Nonce32V2,
    machine_boot_id: BootIdV2,
    deadline: UnixMillisV2,
}

impl KernelTaskPreparationRequestV2 {
    pub(crate) fn from_authenticated_control(
        request_id: RequestIdV2,
        client_request_nonce: Nonce32V2,
        machine_boot_id: BootIdV2,
        deadline: UnixMillisV2,
    ) -> Result<Self, AgentControlDispatchErrorV2> {
        if deadline.get() == 0
            || [client_request_nonce.as_bytes(), machine_boot_id.as_bytes()]
                .iter()
                .any(|value| is_zero(value))
        {
            return Err(AgentControlDispatchErrorV2::IdentityRejected);
        }
        Ok(Self {
            request_id,
            client_request_nonce,
            machine_boot_id,
            deadline,
        })
    }

    pub const fn request_id(self) -> RequestIdV2 {
        self.request_id
    }

    pub const fn client_request_nonce(self) -> Nonce32V2 {
        self.client_request_nonce
    }

    pub const fn machine_boot_id(self) -> BootIdV2 {
        self.machine_boot_id
    }

    pub const fn deadline(self) -> UnixMillisV2 {
        self.deadline
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelTaskCancellationRequestV2 {
    request_id: RequestIdV2,
    durable_task_id: DurableTaskIdV2,
    correlation_digest: Digest32V2,
    status_revision: u64,
    kernel_preparation: NewTaskPreparationHandleV2,
    kernel_correlation: SignedDurableTaskCorrelationV2,
    deadline: UnixMillisV2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelTaskStatusRequestV2 {
    request_id: RequestIdV2,
    durable_task_id: DurableTaskIdV2,
    correlation_digest: Digest32V2,
    status_revision: u64,
    kernel_correlation: SignedDurableTaskCorrelationV2,
    deadline: UnixMillisV2,
}

impl KernelTaskStatusRequestV2 {
    pub(crate) fn from_pending(
        request_id: RequestIdV2,
        durable_task_id: DurableTaskIdV2,
        correlation_digest: Digest32V2,
        status_revision: u64,
        kernel_correlation: SignedDurableTaskCorrelationV2,
        deadline: UnixMillisV2,
    ) -> Result<Self, AgentControlKernelClientErrorV2> {
        if is_zero(durable_task_id.as_bytes())
            || is_zero(correlation_digest.as_bytes())
            || status_revision == 0
            || kernel_correlation
                .correlation_digest()
                .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)?
                != correlation_digest
            || kernel_correlation.unsigned().durable_task_id() != durable_task_id
        {
            return Err(AgentControlKernelClientErrorV2::Unavailable);
        }
        Ok(Self {
            request_id,
            durable_task_id,
            correlation_digest,
            status_revision,
            kernel_correlation,
            deadline,
        })
    }

    pub const fn request_id(&self) -> RequestIdV2 {
        self.request_id
    }

    pub const fn durable_task_id(&self) -> DurableTaskIdV2 {
        self.durable_task_id
    }

    pub const fn correlation_digest(&self) -> Digest32V2 {
        self.correlation_digest
    }

    pub const fn status_revision(&self) -> u64 {
        self.status_revision
    }

    pub const fn kernel_correlation(&self) -> &SignedDurableTaskCorrelationV2 {
        &self.kernel_correlation
    }

    pub const fn deadline(&self) -> UnixMillisV2 {
        self.deadline
    }
}

impl KernelTaskCancellationRequestV2 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_pending(
        request_id: RequestIdV2,
        durable_task_id: DurableTaskIdV2,
        correlation_digest: Digest32V2,
        status_revision: u64,
        kernel_preparation: NewTaskPreparationHandleV2,
        kernel_correlation: SignedDurableTaskCorrelationV2,
        deadline: UnixMillisV2,
    ) -> Result<Self, AgentControlKernelClientErrorV2> {
        if is_zero(durable_task_id.as_bytes())
            || is_zero(correlation_digest.as_bytes())
            || status_revision == 0
            || kernel_correlation
                .correlation_digest()
                .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)?
                != correlation_digest
            || kernel_correlation.unsigned().durable_task_id() != durable_task_id
        {
            return Err(AgentControlKernelClientErrorV2::Unavailable);
        }
        Ok(Self {
            request_id,
            durable_task_id,
            correlation_digest,
            status_revision,
            kernel_preparation,
            kernel_correlation,
            deadline,
        })
    }

    pub const fn request_id(&self) -> RequestIdV2 {
        self.request_id
    }

    pub const fn durable_task_id(&self) -> DurableTaskIdV2 {
        self.durable_task_id
    }

    pub const fn correlation_digest(&self) -> Digest32V2 {
        self.correlation_digest
    }

    pub const fn status_revision(&self) -> u64 {
        self.status_revision
    }

    pub const fn kernel_preparation(&self) -> NewTaskPreparationHandleV2 {
        self.kernel_preparation
    }

    pub const fn kernel_correlation(&self) -> &SignedDurableTaskCorrelationV2 {
        &self.kernel_correlation
    }

    pub const fn deadline(&self) -> UnixMillisV2 {
        self.deadline
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AgentControlKernelClientErrorV2 {
    #[error("kernel client deadline was exceeded")]
    DeadlineExceeded,
    #[error("kernel client is unavailable")]
    Unavailable,
}

pub trait AgentControlKernelClientV2: Send + 'static {
    fn health(
        &mut self,
        request_id: RequestIdV2,
        deadline: UnixMillisV2,
    ) -> Result<PublicServiceStateV2, AgentControlKernelClientErrorV2>;

    fn prepare_task(
        &mut self,
        request: KernelTaskPreparationRequestV2,
    ) -> Result<VerifiedKernelTaskPreparationV2, AgentControlKernelClientErrorV2>;

    fn query_task(
        &mut self,
        request: KernelTaskStatusRequestV2,
    ) -> Result<VerifiedKernelTaskStatusV2, AgentControlKernelClientErrorV2>;

    fn cancel_task(
        &mut self,
        request: KernelTaskCancellationRequestV2,
    ) -> Result<VerifiedKernelCancellationV2, AgentControlKernelClientErrorV2>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentControlDeploymentV2 {
    installation_id: Digest32V2,
    active_state_manifest_digest: Digest32V2,
    deployment_generation: u64,
    protocol_abi_digest: Digest32V2,
    agentd_identity: ServiceIdentityV2,
    agentd_server_boot_id: BootIdV2,
    kerneld_server_boot_id: BootIdV2,
    jarvis_control_identity: ServiceIdentityV2,
}

impl AgentControlDeploymentV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn from_verified_deployment(
        installation_id: Digest32V2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        protocol_abi_digest: Digest32V2,
        agentd_identity: ServiceIdentityV2,
        agentd_server_boot_id: BootIdV2,
        kerneld_server_boot_id: BootIdV2,
        jarvis_control_identity: ServiceIdentityV2,
    ) -> Result<Self, AgentControlDispatchErrorV2> {
        if deployment_generation == 0
            || [
                installation_id.as_bytes(),
                active_state_manifest_digest.as_bytes(),
                protocol_abi_digest.as_bytes(),
                agentd_identity.as_bytes(),
                agentd_server_boot_id.as_bytes(),
                kerneld_server_boot_id.as_bytes(),
                jarvis_control_identity.as_bytes(),
            ]
            .iter()
            .any(|value| is_zero(value))
        {
            return Err(AgentControlDispatchErrorV2::DeploymentBinding);
        }
        Ok(Self {
            installation_id,
            active_state_manifest_digest,
            deployment_generation,
            protocol_abi_digest,
            agentd_identity,
            agentd_server_boot_id,
            kerneld_server_boot_id,
            jarvis_control_identity,
        })
    }

    fn validate_envelope(
        self,
        envelope: AgentControlRequestEnvelopeV2,
        peer: VerifiedAgentControlPeerV2,
        now: UnixMillisV2,
    ) -> Result<(), AgentControlDispatchErrorV2> {
        if now.get() == 0 || now.get() >= envelope.deadline().get() {
            return Err(AgentControlDispatchErrorV2::DeadlineExceeded);
        }
        if peer.caller_identity != self.jarvis_control_identity
            || envelope.caller_identity() != peer.caller_identity
            || envelope.caller_boot_id() != peer.caller_boot_id
            || envelope.service_identity() != self.agentd_identity
            || envelope.service_boot_id() != self.agentd_server_boot_id
            || envelope.active_state_manifest_digest() != self.active_state_manifest_digest
            || envelope.deployment_generation() != self.deployment_generation
        {
            return Err(AgentControlDispatchErrorV2::IdentityRejected);
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn validate_envelope_for_test(
        self,
        envelope: AgentControlRequestEnvelopeV2,
        peer: VerifiedAgentControlPeerV2,
        now: UnixMillisV2,
    ) -> Result<(), AgentControlDispatchErrorV2> {
        self.validate_envelope(envelope, peer, now)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedAgentControlPeerV2 {
    jarvis_principal: Digest32V2,
    jarvis_os_peer_class: Digest32V2,
    machine_boot_id: BootIdV2,
    caller_boot_id: BootIdV2,
    caller_identity: ServiceIdentityV2,
}

impl VerifiedAgentControlPeerV2 {
    pub fn from_mutual_authentication(
        jarvis_principal: Digest32V2,
        jarvis_os_peer_class: Digest32V2,
        machine_boot_id: BootIdV2,
        caller_boot_id: BootIdV2,
        caller_identity: ServiceIdentityV2,
    ) -> Result<Self, AgentControlDispatchErrorV2> {
        if [
            jarvis_principal.as_bytes(),
            jarvis_os_peer_class.as_bytes(),
            machine_boot_id.as_bytes(),
            caller_boot_id.as_bytes(),
            caller_identity.as_bytes(),
        ]
        .iter()
        .any(|value| is_zero(value))
        {
            return Err(AgentControlDispatchErrorV2::IdentityRejected);
        }
        Ok(Self {
            jarvis_principal,
            jarvis_os_peer_class,
            machine_boot_id,
            caller_boot_id,
            caller_identity,
        })
    }
}

struct DispatchCommandV2 {
    envelope: AgentControlRequestEnvelopeV2,
    peer: VerifiedAgentControlPeerV2,
    now: UnixMillisV2,
}

enum DispatchMessageV2 {
    Execute {
        command: Box<DispatchCommandV2>,
        deadline: Instant,
        response: SyncSender<Result<Vec<u8>, AgentControlDispatchErrorV2>>,
    },
    InspectBootstrap {
        kind: BootstrapKindV2,
        selector: JarvisBootstrapSelectorV2,
        now: UnixMillisV2,
        deadline: Instant,
        response: SyncSender<Result<(), AgentControlDispatchErrorV2>>,
    },
    ContinueBootstrap {
        kind: BootstrapKindV2,
        selector: JarvisBootstrapSelectorV2,
        now: UnixMillisV2,
        deadline: Instant,
        response: SyncSender<Result<ResolvedJarvisBootstrapV2, AgentControlDispatchErrorV2>>,
    },
    Shutdown,
}

/// Bounded authenticated dispatcher for the JARVIS-to-agentd V2 edge.
pub struct AgentControlDispatcherV2 {
    sender: SyncSender<DispatchMessageV2>,
    lifecycle: Arc<AtomicU8>,
    owner: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for AgentControlDispatcherV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AgentControlDispatcherV2")
            .field("lifecycle", &self.lifecycle.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

impl AgentControlDispatcherV2 {
    pub fn spawn(
        deployment: AgentControlDeploymentV2,
        tasks: AgentTaskStateOwnerV2,
        verifier: KernelTaskAuthorityVerifierV2,
        kernel_client: impl AgentControlKernelClientV2,
        capacity: usize,
    ) -> Result<Self, AgentControlDispatchErrorV2> {
        if capacity == 0 {
            return Err(AgentControlDispatchErrorV2::Unavailable);
        }
        let (sender, receiver) = mpsc::sync_channel(capacity);
        let lifecycle = Arc::new(AtomicU8::new(DISPATCH_RUNNING));
        let owner_lifecycle = Arc::clone(&lifecycle);
        let owner = thread::Builder::new()
            .name("savana-agent-control-v2".to_owned())
            .spawn(move || {
                dispatcher_loop(
                    receiver,
                    owner_lifecycle,
                    deployment,
                    tasks,
                    verifier,
                    kernel_client,
                )
            })
            .map_err(|_| AgentControlDispatchErrorV2::Unavailable)?;
        Ok(Self {
            sender,
            lifecycle,
            owner: Some(owner),
        })
    }

    pub fn dispatch_canonical(
        &self,
        canonical_request: &[u8],
        peer: VerifiedAgentControlPeerV2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<Vec<u8>, AgentControlDispatchErrorV2> {
        let envelope = decode_agent_control_request_envelope_v2(canonical_request)
            .map_err(|error| AgentControlDispatchErrorV2::Protocol(error.code()))?;
        if Instant::now() >= deadline {
            return Err(AgentControlDispatchErrorV2::DeadlineExceeded);
        }
        if self.lifecycle.load(Ordering::Acquire) != DISPATCH_RUNNING {
            return Err(AgentControlDispatchErrorV2::Unavailable);
        }
        let (response, received) = mpsc::sync_channel(1);
        match self.sender.try_send(DispatchMessageV2::Execute {
            command: Box::new(DispatchCommandV2 {
                envelope,
                peer,
                now,
            }),
            deadline,
            response,
        }) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => return Err(AgentControlDispatchErrorV2::Overloaded),
            Err(TrySendError::Disconnected(_)) => {
                self.lifecycle.store(DISPATCH_FAILED, Ordering::Release);
                return Err(AgentControlDispatchErrorV2::Unavailable);
            }
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(AgentControlDispatchErrorV2::DeadlineExceeded);
        }
        match received.recv_timeout(remaining) {
            Ok(result) => result,
            Err(RecvTimeoutError::Timeout) => Err(AgentControlDispatchErrorV2::DeadlineExceeded),
            Err(RecvTimeoutError::Disconnected) => {
                self.lifecycle.store(DISPATCH_FAILED, Ordering::Release);
                Err(AgentControlDispatchErrorV2::Unavailable)
            }
        }
    }

    pub fn inspect_bootstrap(
        &self,
        kind: BootstrapKindV2,
        selector: JarvisBootstrapSelectorV2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<(), AgentControlDispatchErrorV2> {
        self.submit_bootstrap_inspection(kind, selector, now, deadline)
    }

    pub fn continue_bootstrap(
        &self,
        kind: BootstrapKindV2,
        selector: JarvisBootstrapSelectorV2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<ResolvedJarvisBootstrapV2, AgentControlDispatchErrorV2> {
        if Instant::now() >= deadline || self.lifecycle.load(Ordering::Acquire) != DISPATCH_RUNNING
        {
            return Err(AgentControlDispatchErrorV2::Unavailable);
        }
        let (response, received) = mpsc::sync_channel(1);
        match self.sender.try_send(DispatchMessageV2::ContinueBootstrap {
            kind,
            selector,
            now,
            deadline,
            response,
        }) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => return Err(AgentControlDispatchErrorV2::Overloaded),
            Err(TrySendError::Disconnected(_)) => {
                self.lifecycle.store(DISPATCH_FAILED, Ordering::Release);
                return Err(AgentControlDispatchErrorV2::Unavailable);
            }
        }
        receive_before_deadline(&self.lifecycle, received, deadline)
    }

    fn submit_bootstrap_inspection(
        &self,
        kind: BootstrapKindV2,
        selector: JarvisBootstrapSelectorV2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<(), AgentControlDispatchErrorV2> {
        if Instant::now() >= deadline || self.lifecycle.load(Ordering::Acquire) != DISPATCH_RUNNING
        {
            return Err(AgentControlDispatchErrorV2::Unavailable);
        }
        let (response, received) = mpsc::sync_channel(1);
        match self.sender.try_send(DispatchMessageV2::InspectBootstrap {
            kind,
            selector,
            now,
            deadline,
            response,
        }) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => return Err(AgentControlDispatchErrorV2::Overloaded),
            Err(TrySendError::Disconnected(_)) => {
                self.lifecycle.store(DISPATCH_FAILED, Ordering::Release);
                return Err(AgentControlDispatchErrorV2::Unavailable);
            }
        }
        receive_before_deadline(&self.lifecycle, received, deadline)
    }
}

fn receive_before_deadline<T>(
    lifecycle: &AtomicU8,
    received: Receiver<Result<T, AgentControlDispatchErrorV2>>,
    deadline: Instant,
) -> Result<T, AgentControlDispatchErrorV2> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(AgentControlDispatchErrorV2::DeadlineExceeded);
    }
    match received.recv_timeout(remaining) {
        Ok(result) => result,
        Err(RecvTimeoutError::Timeout) => Err(AgentControlDispatchErrorV2::DeadlineExceeded),
        Err(RecvTimeoutError::Disconnected) => {
            lifecycle.store(DISPATCH_FAILED, Ordering::Release);
            Err(AgentControlDispatchErrorV2::Unavailable)
        }
    }
}

impl Drop for AgentControlDispatcherV2 {
    fn drop(&mut self) {
        if self
            .lifecycle
            .compare_exchange(
                DISPATCH_RUNNING,
                DISPATCH_CLOSING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            let _ = self.sender.send(DispatchMessageV2::Shutdown);
        }
        if let Some(owner) = self.owner.take() {
            if owner.join().is_err() {
                self.lifecycle.store(DISPATCH_FAILED, Ordering::Release);
            }
        }
    }
}

fn dispatcher_loop(
    receiver: Receiver<DispatchMessageV2>,
    lifecycle: Arc<AtomicU8>,
    deployment: AgentControlDeploymentV2,
    tasks: AgentTaskStateOwnerV2,
    verifier: KernelTaskAuthorityVerifierV2,
    mut kernel_client: impl AgentControlKernelClientV2,
) {
    while let Ok(message) = receiver.recv() {
        match message {
            DispatchMessageV2::Execute {
                command,
                deadline,
                response,
            } => {
                if lifecycle.load(Ordering::Acquire) != DISPATCH_RUNNING {
                    let _ = response.send(Err(AgentControlDispatchErrorV2::Unavailable));
                    continue;
                }
                if Instant::now() >= deadline {
                    let _ = response.send(Err(AgentControlDispatchErrorV2::DeadlineExceeded));
                    continue;
                }
                let result = catch_unwind(AssertUnwindSafe(|| {
                    dispatch(
                        deployment,
                        &tasks,
                        &verifier,
                        &mut kernel_client,
                        *command,
                        deadline,
                    )
                }))
                .unwrap_or(Err(AgentControlDispatchErrorV2::Unavailable));
                let fatal = matches!(result, Err(AgentControlDispatchErrorV2::Unavailable));
                let _ = response.send(result);
                if fatal {
                    lifecycle.store(DISPATCH_FAILED, Ordering::Release);
                    return;
                }
            }
            DispatchMessageV2::InspectBootstrap {
                kind,
                selector,
                now,
                deadline,
                response,
            } => {
                let result = tasks
                    .inspect_bootstrap(kind, selector, now, deadline)
                    .map_err(map_bootstrap_owner_error);
                let _ = response.send(result);
            }
            DispatchMessageV2::ContinueBootstrap {
                kind,
                selector,
                now,
                deadline,
                response,
            } => {
                let result = tasks
                    .continue_bootstrap(kind, selector, now, deadline)
                    .map_err(map_bootstrap_owner_error);
                let _ = response.send(result);
            }
            DispatchMessageV2::Shutdown => {
                lifecycle.store(DISPATCH_STOPPED, Ordering::Release);
                return;
            }
        }
    }
    if lifecycle.load(Ordering::Acquire) != DISPATCH_CLOSING {
        lifecycle.store(DISPATCH_FAILED, Ordering::Release);
    }
}

fn map_bootstrap_owner_error(error: AgentTaskStateOwnerErrorV2) -> AgentControlDispatchErrorV2 {
    match error {
        AgentTaskStateOwnerErrorV2::Busy => AgentControlDispatchErrorV2::Overloaded,
        AgentTaskStateOwnerErrorV2::DeadlineExceeded => {
            AgentControlDispatchErrorV2::DeadlineExceeded
        }
        AgentTaskStateOwnerErrorV2::Unavailable => AgentControlDispatchErrorV2::Unavailable,
        AgentTaskStateOwnerErrorV2::Task(_) => AgentControlDispatchErrorV2::IdentityRejected,
    }
}

fn dispatch(
    deployment: AgentControlDeploymentV2,
    tasks: &AgentTaskStateOwnerV2,
    _verifier: &KernelTaskAuthorityVerifierV2,
    kernel_client: &mut impl AgentControlKernelClientV2,
    command: DispatchCommandV2,
    deadline: Instant,
) -> Result<Vec<u8>, AgentControlDispatchErrorV2> {
    deployment.validate_envelope(command.envelope, command.peer, command.now)?;
    let context = AuthenticatedJarvisControlV2::from_mutual_authentication(
        deployment.installation_id,
        command.peer.jarvis_principal,
        command.peer.jarvis_os_peer_class,
        command.peer.machine_boot_id,
        command.peer.caller_boot_id,
        deployment.agentd_server_boot_id,
        deployment.kerneld_server_boot_id,
    )
    .map_err(|_| AgentControlDispatchErrorV2::IdentityRejected)?;
    let response = match command.envelope.operation() {
        AgentControlOperationV2::Health => {
            match kernel_client.health(command.envelope.request_id(), command.envelope.deadline()) {
                Ok(state) => AgentControlResponseV2::health(state),
                Err(error) => AgentControlResponseV2::error(map_kernel_client_error(error)),
            }
        }
        AgentControlOperationV2::PrepareIngress(request) => {
            let kernel_request = KernelTaskPreparationRequestV2::from_authenticated_control(
                command.envelope.request_id(),
                *request.client_request_nonce(),
                command.peer.machine_boot_id,
                command.envelope.deadline(),
            )?;
            match kernel_client.prepare_task(kernel_request) {
                Ok(preparation) => match tasks.prepare_ingress(
                    context,
                    *request.client_request_nonce(),
                    preparation,
                    command.now,
                    deadline,
                ) {
                    Ok(response) => AgentControlResponseV2::prepare_ingress(response),
                    Err(error) => AgentControlResponseV2::error(map_task_owner_error(error)),
                },
                Err(error) => AgentControlResponseV2::error(map_kernel_client_error(error)),
            }
        }
        AgentControlOperationV2::GetTaskStatus(request) => {
            match tasks.prepare_status_query(context, request, command.now, deadline) {
                Ok(pending) => match KernelTaskStatusRequestV2::from_pending(
                    command.envelope.request_id(),
                    pending.durable_task_id,
                    pending.correlation_digest,
                    pending.status_revision,
                    pending.kernel_correlation,
                    command.envelope.deadline(),
                ) {
                    Ok(kernel_request) => match kernel_client.query_task(kernel_request) {
                        Ok(verified) => {
                            let synchronized =
                                tasks.apply_verified_kernel_status(verified, command.now, deadline);
                            match synchronized {
                                Ok(()) => match tasks.get_task_status(
                                    context,
                                    request,
                                    command.now,
                                    deadline,
                                ) {
                                    Ok(response) => {
                                        AgentControlResponseV2::get_task_status(response)
                                    }
                                    Err(error) => {
                                        AgentControlResponseV2::error(map_task_owner_error(error))
                                    }
                                },
                                Err(error) => {
                                    AgentControlResponseV2::error(map_task_owner_error(error))
                                }
                            }
                        }
                        Err(error) => AgentControlResponseV2::error(map_kernel_client_error(error)),
                    },
                    Err(error) => AgentControlResponseV2::error(map_kernel_client_error(error)),
                },
                Err(error) => AgentControlResponseV2::error(map_task_owner_error(error)),
            }
        }
        AgentControlOperationV2::CancelTask(request) => {
            match tasks.prepare_cancel(context, request, command.now, deadline) {
                Ok(pending) => {
                    match KernelTaskCancellationRequestV2::from_pending(
                        command.envelope.request_id(),
                        pending.durable_task_id,
                        pending.correlation_digest,
                        pending.status_revision,
                        pending.kernel_preparation,
                        pending.kernel_correlation.clone(),
                        command.envelope.deadline(),
                    ) {
                        Ok(kernel_request) => match kernel_client.cancel_task(kernel_request) {
                            Ok(verified) => match tasks.commit_verified_cancellation(
                                pending,
                                verified,
                                command.now,
                                deadline,
                            ) {
                                Ok(response) => AgentControlResponseV2::cancel_task(response),
                                Err(error) => {
                                    AgentControlResponseV2::error(map_task_owner_error(error))
                                }
                            },
                            Err(error) => {
                                AgentControlResponseV2::error(map_kernel_client_error(error))
                            }
                        },
                        Err(error) => AgentControlResponseV2::error(map_kernel_client_error(error)),
                    }
                }
                Err(error) => AgentControlResponseV2::error(map_task_owner_error(error)),
            }
        }
    };
    let response = AgentControlResponseEnvelopeV2::from_authenticated_connection(
        command.envelope.request_id(),
        deployment.agentd_server_boot_id,
        deployment.agentd_identity,
        deployment.active_state_manifest_digest,
        deployment.deployment_generation,
        response,
    )
    .map_err(|error| AgentControlDispatchErrorV2::Protocol(error.code()))?;
    encode_agent_control_response_envelope_v2(&response)
        .map_err(|error| AgentControlDispatchErrorV2::Protocol(error.code()))
}

const fn map_kernel_client_error(error: AgentControlKernelClientErrorV2) -> StableCode {
    match error {
        AgentControlKernelClientErrorV2::DeadlineExceeded => StableCode::DeadlineExceeded,
        AgentControlKernelClientErrorV2::Unavailable => StableCode::KernelUnavailable,
    }
}

const fn map_task_owner_error(error: AgentTaskStateOwnerErrorV2) -> StableCode {
    match error {
        AgentTaskStateOwnerErrorV2::Busy => StableCode::KernelOverloaded,
        AgentTaskStateOwnerErrorV2::DeadlineExceeded => StableCode::DeadlineExceeded,
        AgentTaskStateOwnerErrorV2::Unavailable => StableCode::KernelUnavailable,
        AgentTaskStateOwnerErrorV2::Task(task) => match task {
            AgentTaskErrorV2::InvalidInput => StableCode::ProtocolMalformedCbor,
            AgentTaskErrorV2::InvalidReference => StableCode::HandleUnknown,
            AgentTaskErrorV2::IdempotencyConflict => StableCode::IdentityReplay,
            AgentTaskErrorV2::CancellationTooLate => StableCode::CancellationTooLate,
            AgentTaskErrorV2::AllocationFailure => StableCode::KernelOverloaded,
            AgentTaskErrorV2::StateConflict
            | AgentTaskErrorV2::ClockRollback
            | AgentTaskErrorV2::DurableState
            | AgentTaskErrorV2::DurableAuthentication
            | AgentTaskErrorV2::RollbackDetected
            | AgentTaskErrorV2::CommitUncertain
            | AgentTaskErrorV2::KernelAuthentication => StableCode::KernelUnavailable,
        },
    }
}
