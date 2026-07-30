#![forbid(unsafe_code)]

#[cfg(all(feature = "macos-development-authority", not(debug_assertions)))]
compile_error!("macos-development-authority is forbidden in release builds");

#[allow(dead_code)] // Wired by the production agentd runtime owner.
mod effect_gate;
#[allow(dead_code)] // Wired by the production planner/kernel client.
mod effect_gated_kernel;

mod agent_control;
mod browser_authority;
mod daemon;
mod durable;
mod kernel_authority;
mod kernel_client;
mod planner_client;
mod state_owner;

use std::collections::HashSet;
use std::fmt;

use hmac::{Hmac, Mac as _};
use savana_kernel_protocol::v2::{
    BootIdV2, BootstrapKindV2, CancelTaskRequestV2, CancelTaskResponseV2, Digest32V2,
    DurableTaskIdV2, Ed25519KeyIdV2, GetTaskStatusRequestV2, GetTaskStatusResponseV2,
    JarvisBootstrapActionV2, JarvisBootstrapSelectorV2, JarvisBootstrapUrlV2,
    KernelIngressBootstrapTransferCapabilityV2, NewTaskPreparationHandleV2, Nonce32V2,
    PrepareIngressResponseV2, PublicTaskStatusV2, ServiceIdentityV2,
    SignedDurableTaskCorrelationV2, TaskHandleV2, UnixMillisV2,
};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

pub use agent_control::{
    AgentControlDeploymentV2, AgentControlDispatchErrorV2, AgentControlDispatcherV2,
    AgentControlKernelClientErrorV2, AgentControlKernelClientV2, KernelTaskCancellationRequestV2,
    KernelTaskPreparationRequestV2, KernelTaskStatusRequestV2, VerifiedAgentControlPeerV2,
};
pub use browser_authority::{AgentBrowserAuthorityErrorV2, AgentBrowserAuthorityV2};
pub use daemon::AgentdDaemonErrorV2;
use durable::DurableAgentTaskServiceV2;
pub use durable::{AgentTaskRollbackAnchorV2, AgentTaskStateHeadV2, DurableAgentTaskNamespaceV2};
pub use kernel_authority::{
    KernelTaskAuthorityVerifierV2, KernelTaskStatementV2, SignedKernelTaskStatementV2,
};
pub use kernel_client::SuiteOneAgentKernelClientV2;
pub use planner_client::{AgentPlannerClientErrorV2, PinnedMtlsAgentPlannerClientV2};
pub use state_owner::{AgentTaskStateOwnerErrorV2, AgentTaskStateOwnerV2};

pub fn run(config_path: &std::path::Path) -> Result<(), AgentdDaemonErrorV2> {
    daemon::run(config_path)
}

const TASK_HANDLE_DOMAIN: &[u8] = b"SAVANA_TASK_HANDLE_V2\0";
const PREPARE_REQUEST_DOMAIN: &[u8] = b"SAVANA_AGENTD_PREPARE_INGRESS_REQUEST_V2\0";
const CANCEL_CAPABILITY_DOMAIN: &[u8] = b"SAVANA_AGENTD_CANCEL_CAPABILITY_V2\0";
const CAPABILITY_DERIVATION_DOMAIN: &[u8] = b"SAVANA_AGENTD_CAPABILITY_DERIVATION_V2\0";
const MAX_PREPARE_REPLAYS: usize = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AgentTaskErrorV2 {
    #[error("agent task input is invalid")]
    InvalidInput,
    #[error("task reference is invalid for this principal or peer")]
    InvalidReference,
    #[error("request nonce was rebound to different preparation bytes")]
    IdempotencyConflict,
    #[error("task state transition conflicts with durable state")]
    StateConflict,
    #[error("task cancellation is no longer authorized")]
    CancellationTooLate,
    #[error("task allocation or entropy failed")]
    AllocationFailure,
    #[error("agent task clock moved below its accepted floor")]
    ClockRollback,
    #[error("agent task durable state is invalid or unavailable")]
    DurableState,
    #[error("agent task durable state authentication failed")]
    DurableAuthentication,
    #[error("agent task durable state rollback was detected")]
    RollbackDetected,
    #[error("agent task durable commit outcome is uncertain")]
    CommitUncertain,
    #[error("kernel task statement authentication failed")]
    KernelAuthentication,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskOriginBootV2 {
    machine_boot_id: BootIdV2,
    jarvis_control_client_boot_id: BootIdV2,
    agentd_server_boot_id: BootIdV2,
    kerneld_server_boot_id: BootIdV2,
}

impl TaskOriginBootV2 {
    pub const fn machine_boot_id(self) -> BootIdV2 {
        self.machine_boot_id
    }

    pub const fn jarvis_control_client_boot_id(self) -> BootIdV2 {
        self.jarvis_control_client_boot_id
    }

    pub const fn agentd_server_boot_id(self) -> BootIdV2 {
        self.agentd_server_boot_id
    }

    pub const fn kerneld_server_boot_id(self) -> BootIdV2 {
        self.kerneld_server_boot_id
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentTaskRecoveryProjectionV2 {
    durable_task_id: DurableTaskIdV2,
    correlation_digest: Digest32V2,
    origin_boots: TaskOriginBootV2,
    status: PublicTaskStatusV2,
    public_state_revision: u64,
    cancellation_pending: bool,
    cancellation_commit_digest: Option<Digest32V2>,
}

impl AgentTaskRecoveryProjectionV2 {
    pub const fn durable_task_id(self) -> DurableTaskIdV2 {
        self.durable_task_id
    }

    pub const fn correlation_digest(self) -> Digest32V2 {
        self.correlation_digest
    }

    pub const fn origin_boots(self) -> TaskOriginBootV2 {
        self.origin_boots
    }

    pub const fn status(self) -> PublicTaskStatusV2 {
        self.status
    }

    pub const fn public_state_revision(self) -> u64 {
        self.public_state_revision
    }

    pub const fn cancellation_pending(self) -> bool {
        self.cancellation_pending
    }

    pub const fn cancellation_commit_digest(self) -> Option<Digest32V2> {
        self.cancellation_commit_digest
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthenticatedJarvisControlV2 {
    installation_id: Digest32V2,
    jarvis_principal: Digest32V2,
    jarvis_os_peer_class: Digest32V2,
    origin_boots: TaskOriginBootV2,
}

impl AuthenticatedJarvisControlV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn from_mutual_authentication(
        installation_id: Digest32V2,
        jarvis_principal: Digest32V2,
        jarvis_os_peer_class: Digest32V2,
        machine_boot_id: BootIdV2,
        jarvis_control_client_boot_id: BootIdV2,
        agentd_server_boot_id: BootIdV2,
        kerneld_server_boot_id: BootIdV2,
    ) -> Result<Self, AgentTaskErrorV2> {
        if [
            installation_id.as_bytes(),
            jarvis_principal.as_bytes(),
            jarvis_os_peer_class.as_bytes(),
            machine_boot_id.as_bytes(),
            jarvis_control_client_boot_id.as_bytes(),
            agentd_server_boot_id.as_bytes(),
            kerneld_server_boot_id.as_bytes(),
        ]
        .iter()
        .any(|value| is_zero(value))
        {
            return Err(AgentTaskErrorV2::InvalidInput);
        }
        Ok(Self {
            installation_id,
            jarvis_principal,
            jarvis_os_peer_class,
            origin_boots: TaskOriginBootV2 {
                machine_boot_id,
                jarvis_control_client_boot_id,
                agentd_server_boot_id,
                kerneld_server_boot_id,
            },
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct KernelCancellationAuthorityV2 {
    preparation: NewTaskPreparationHandleV2,
    correlation: SignedDurableTaskCorrelationV2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedKernelTaskPreparationV2 {
    durable_task_id: DurableTaskIdV2,
    correlation_digest: Digest32V2,
    kernel_bootstrap_binding_digest: Digest32V2,
    task_logical_expires_at: UnixMillisV2,
    status_retain_until: UnixMillisV2,
    authority_binding_digest: Digest32V2,
    cancellation_authority: Option<KernelCancellationAuthorityV2>,
    ingress_transfer: Option<KernelIngressBootstrapTransferCapabilityV2>,
}

impl VerifiedKernelTaskPreparationV2 {
    pub(crate) fn from_verified_correlation(
        durable_task_id: DurableTaskIdV2,
        correlation_digest: Digest32V2,
        kernel_bootstrap_binding_digest: Digest32V2,
        task_logical_expires_at: UnixMillisV2,
        status_retain_until: UnixMillisV2,
        authority_binding_digest: Digest32V2,
    ) -> Result<Self, AgentTaskErrorV2> {
        if is_zero(durable_task_id.as_bytes())
            || is_zero(correlation_digest.as_bytes())
            || is_zero(kernel_bootstrap_binding_digest.as_bytes())
            || is_zero(authority_binding_digest.as_bytes())
            || task_logical_expires_at.get() == 0
            || status_retain_until.get() <= task_logical_expires_at.get()
        {
            return Err(AgentTaskErrorV2::InvalidInput);
        }
        Ok(Self {
            durable_task_id,
            correlation_digest,
            kernel_bootstrap_binding_digest,
            task_logical_expires_at,
            status_retain_until,
            authority_binding_digest,
            cancellation_authority: None,
            ingress_transfer: None,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_verified_kernel_response(
        durable_task_id: DurableTaskIdV2,
        correlation_digest: Digest32V2,
        kernel_bootstrap_binding_digest: Digest32V2,
        task_logical_expires_at: UnixMillisV2,
        status_retain_until: UnixMillisV2,
        authority_binding_digest: Digest32V2,
        preparation: NewTaskPreparationHandleV2,
        correlation: SignedDurableTaskCorrelationV2,
        ingress_transfer: KernelIngressBootstrapTransferCapabilityV2,
    ) -> Result<Self, AgentTaskErrorV2> {
        let mut verified = Self::from_verified_correlation(
            durable_task_id,
            correlation_digest,
            kernel_bootstrap_binding_digest,
            task_logical_expires_at,
            status_retain_until,
            authority_binding_digest,
        )?;
        if correlation
            .correlation_digest()
            .map_err(|_| AgentTaskErrorV2::InvalidInput)?
            != correlation_digest
            || correlation.unsigned().durable_task_id() != durable_task_id
        {
            return Err(AgentTaskErrorV2::InvalidInput);
        }
        verified.cancellation_authority = Some(KernelCancellationAuthorityV2 {
            preparation,
            correlation,
        });
        verified.ingress_transfer = Some(ingress_transfer);
        Ok(verified)
    }

    pub const fn durable_task_id(&self) -> DurableTaskIdV2 {
        self.durable_task_id
    }

    pub const fn correlation_digest(&self) -> Digest32V2 {
        self.correlation_digest
    }

    pub(crate) fn kernel_preparation(&self) -> Option<NewTaskPreparationHandleV2> {
        self.cancellation_authority
            .as_ref()
            .map(|authority| authority.preparation)
    }

    pub(crate) fn kernel_correlation(&self) -> Option<&SignedDurableTaskCorrelationV2> {
        self.cancellation_authority
            .as_ref()
            .map(|authority| &authority.correlation)
    }

    pub(crate) const fn ingress_transfer(
        &self,
    ) -> Option<KernelIngressBootstrapTransferCapabilityV2> {
        self.ingress_transfer
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedKernelTaskStatusV2 {
    durable_task_id: DurableTaskIdV2,
    correlation_digest: Digest32V2,
    status: PublicTaskStatusV2,
    public_state_revision: u64,
    authority_binding_digest: Digest32V2,
}

impl VerifiedKernelTaskStatusV2 {
    pub(crate) fn from_verified_query(
        durable_task_id: DurableTaskIdV2,
        correlation_digest: Digest32V2,
        status: PublicTaskStatusV2,
        public_state_revision: u64,
        authority_binding_digest: Digest32V2,
    ) -> Result<Self, AgentTaskErrorV2> {
        if is_zero(durable_task_id.as_bytes())
            || is_zero(correlation_digest.as_bytes())
            || is_zero(authority_binding_digest.as_bytes())
            || public_state_revision == 0
        {
            return Err(AgentTaskErrorV2::InvalidInput);
        }
        Ok(Self {
            durable_task_id,
            correlation_digest,
            status: strip_bootstrap(status),
            public_state_revision,
            authority_binding_digest,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedKernelCancellationV2 {
    durable_task_id: DurableTaskIdV2,
    correlation_digest: Digest32V2,
    cancellation_commit_digest: Digest32V2,
    authority_binding_digest: Digest32V2,
}

impl VerifiedKernelCancellationV2 {
    pub(crate) fn cancelled(
        durable_task_id: DurableTaskIdV2,
        correlation_digest: Digest32V2,
        cancellation_commit_digest: Digest32V2,
        authority_binding_digest: Digest32V2,
    ) -> Result<Self, AgentTaskErrorV2> {
        if is_zero(durable_task_id.as_bytes())
            || is_zero(correlation_digest.as_bytes())
            || is_zero(cancellation_commit_digest.as_bytes())
            || is_zero(authority_binding_digest.as_bytes())
        {
            return Err(AgentTaskErrorV2::InvalidInput);
        }
        Ok(Self {
            durable_task_id,
            correlation_digest,
            cancellation_commit_digest,
            authority_binding_digest,
        })
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PendingTaskCancellationV2 {
    token: [u8; 32],
    durable_task_id: DurableTaskIdV2,
    correlation_digest: Digest32V2,
    status_revision: u64,
    kernel_preparation: NewTaskPreparationHandleV2,
    kernel_correlation: SignedDurableTaskCorrelationV2,
}

#[derive(Clone, PartialEq, Eq)]
pub struct PendingTaskStatusQueryV2 {
    durable_task_id: DurableTaskIdV2,
    correlation_digest: Digest32V2,
    status: PublicTaskStatusV2,
    status_revision: u64,
    kernel_correlation: SignedDurableTaskCorrelationV2,
}

impl fmt::Debug for PendingTaskStatusQueryV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PendingTaskStatusQueryV2(<opaque>)")
    }
}

impl fmt::Debug for PendingTaskCancellationV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PendingTaskCancellationV2(<opaque>)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PrepareReplayRecordV2 {
    jarvis_principal: Digest32V2,
    jarvis_os_peer_class: Digest32V2,
    client_request_nonce: Nonce32V2,
    request_digest: Digest32V2,
    response: PrepareIngressResponseV2,
}

#[derive(Clone)]
struct TaskResolverRecordV2 {
    task_handle: TaskHandleV2,
    task_handle_digest: Digest32V2,
    jarvis_principal: Digest32V2,
    jarvis_os_peer_class: Digest32V2,
    origin_boots: TaskOriginBootV2,
    durable_task_id: DurableTaskIdV2,
    correlation_digest: Digest32V2,
    kernel_bootstrap_binding_digest: Digest32V2,
    bootstrap_selector: Option<JarvisBootstrapSelectorV2>,
    bootstrap_agentd_boot_id: Option<BootIdV2>,
    kernel_ingress_transfer: Option<KernelIngressBootstrapTransferCapabilityV2>,
    kernel_preparation: NewTaskPreparationHandleV2,
    kernel_correlation: SignedDurableTaskCorrelationV2,
    creating_manifest_digest: Digest32V2,
    creating_deployment_generation: u64,
    protocol_abi_digest: Digest32V2,
    task_logical_expires_at: UnixMillisV2,
    status_retain_until: UnixMillisV2,
    status: PublicTaskStatusV2,
    public_state_revision: u64,
    pending_cancellation_digest: Option<Digest32V2>,
    cancellation_commit_digest: Option<Digest32V2>,
}

impl fmt::Debug for TaskResolverRecordV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TaskResolverRecordV2")
            .field("task_handle", &self.task_handle)
            .field("durable_task_id", &self.durable_task_id)
            .field("status", &self.status)
            .field("public_state_revision", &self.public_state_revision)
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub struct AgentTaskServiceV2 {
    installation_id: Digest32V2,
    active_state_manifest_digest: Digest32V2,
    deployment_generation: u64,
    protocol_abi_digest: Digest32V2,
    agentd_identity: ServiceIdentityV2,
    kernel_task_authority_key_id: Ed25519KeyIdV2,
    kernel_task_authority_binding_digest: Digest32V2,
    current_agentd_boot_id: BootIdV2,
    current_kerneld_boot_id: BootIdV2,
    maximum_tasks: usize,
    accepted_time_floor_ms: u64,
    capability_key: Zeroizing<[u8; 32]>,
    tasks: Vec<TaskResolverRecordV2>,
    prepare_replays: Vec<PrepareReplayRecordV2>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
// Both branches are bounded opaque authority objects. Keeping the public
// projection inline avoids an extra allocation at the one-use bootstrap edge.
#[allow(clippy::large_enum_variant)]
pub enum ResolvedJarvisBootstrapV2 {
    Ingress {
        transfer: KernelIngressBootstrapTransferCapabilityV2,
    },
    Agent {
        preparation: NewTaskPreparationHandleV2,
        correlation: SignedDurableTaskCorrelationV2,
    },
}

impl ResolvedJarvisBootstrapV2 {
    pub const fn ingress_transfer(&self) -> Option<KernelIngressBootstrapTransferCapabilityV2> {
        match self {
            Self::Ingress { transfer } => Some(*transfer),
            Self::Agent { .. } => None,
        }
    }

    pub const fn agent_authority(
        &self,
    ) -> Option<(NewTaskPreparationHandleV2, &SignedDurableTaskCorrelationV2)> {
        match self {
            Self::Ingress { .. } => None,
            Self::Agent {
                preparation,
                correlation,
            } => Some((*preparation, correlation)),
        }
    }
}

impl fmt::Debug for AgentTaskServiceV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AgentTaskServiceV2")
            .field("agentd_identity", &self.agentd_identity)
            .field("task_count", &self.tasks.len())
            .field("accepted_time_floor_ms", &self.accepted_time_floor_ms)
            .finish_non_exhaustive()
    }
}

impl AgentTaskServiceV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn from_verified_deployment(
        installation_id: Digest32V2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        protocol_abi_digest: Digest32V2,
        agentd_identity: ServiceIdentityV2,
        current_agentd_boot_id: BootIdV2,
        current_kerneld_boot_id: BootIdV2,
        kernel_task_authority_key_id: Ed25519KeyIdV2,
        kernel_task_authority_public_key: [u8; 32],
        maximum_tasks: usize,
    ) -> Result<Self, AgentTaskErrorV2> {
        if [
            installation_id.as_bytes(),
            active_state_manifest_digest.as_bytes(),
            protocol_abi_digest.as_bytes(),
            agentd_identity.as_bytes(),
            current_agentd_boot_id.as_bytes(),
            current_kerneld_boot_id.as_bytes(),
            kernel_task_authority_key_id.as_bytes(),
            &kernel_task_authority_public_key,
        ]
        .iter()
        .any(|value| is_zero(value))
            || deployment_generation == 0
            || maximum_tasks == 0
            || maximum_tasks > 65_536
        {
            return Err(AgentTaskErrorV2::InvalidInput);
        }
        let mut capability_key = [0_u8; 32];
        getrandom::getrandom(&mut capability_key)
            .map_err(|_| AgentTaskErrorV2::AllocationFailure)?;
        if capability_key == [0; 32] {
            return Err(AgentTaskErrorV2::AllocationFailure);
        }
        ed25519_dalek::VerifyingKey::from_bytes(&kernel_task_authority_public_key)
            .map_err(|_| AgentTaskErrorV2::InvalidInput)?;
        let kernel_task_authority_binding_digest =
            kernel_authority::kernel_task_authority_binding_digest(
                kernel_task_authority_key_id,
                &kernel_task_authority_public_key,
            );
        Ok(Self {
            installation_id,
            active_state_manifest_digest,
            deployment_generation,
            protocol_abi_digest,
            agentd_identity,
            kernel_task_authority_key_id,
            kernel_task_authority_binding_digest,
            current_agentd_boot_id,
            current_kerneld_boot_id,
            maximum_tasks,
            accepted_time_floor_ms: 0,
            capability_key: Zeroizing::new(capability_key),
            tasks: Vec::new(),
            prepare_replays: Vec::new(),
        })
    }

    pub fn prepare_ingress(
        &mut self,
        context: AuthenticatedJarvisControlV2,
        client_request_nonce: Nonce32V2,
        preparation: VerifiedKernelTaskPreparationV2,
        now: UnixMillisV2,
    ) -> Result<PrepareIngressResponseV2, AgentTaskErrorV2> {
        self.validate_current_context(context)?;
        if preparation.authority_binding_digest != self.kernel_task_authority_binding_digest {
            return Err(AgentTaskErrorV2::KernelAuthentication);
        }
        let kernel_preparation = preparation
            .kernel_preparation()
            .ok_or(AgentTaskErrorV2::KernelAuthentication)?;
        let kernel_correlation = preparation
            .kernel_correlation()
            .cloned()
            .ok_or(AgentTaskErrorV2::KernelAuthentication)?;
        let kernel_ingress_transfer = preparation
            .ingress_transfer()
            .ok_or(AgentTaskErrorV2::KernelAuthentication)?;
        self.accept_time(now)?;
        self.prune_expired(now)?;
        if is_zero(client_request_nonce.as_bytes())
            || now.get() >= preparation.task_logical_expires_at.get()
        {
            return Err(AgentTaskErrorV2::InvalidInput);
        }
        let request_digest = prepare_request_digest(context, &preparation);
        if let Some(replay_index) = self.prepare_replays.iter().position(|record| {
            record.jarvis_principal == context.jarvis_principal
                && record.jarvis_os_peer_class == context.jarvis_os_peer_class
                && record.client_request_nonce == client_request_nonce
        }) {
            if self.prepare_replays[replay_index].request_digest == request_digest {
                let task_handle = self.prepare_replays[replay_index].response.task();
                let task = self
                    .tasks
                    .iter_mut()
                    .find(|task| task.task_handle == task_handle)
                    .ok_or(AgentTaskErrorV2::DurableState)?;
                normalize_bootstrap_for_current_boot(
                    task,
                    self.current_agentd_boot_id,
                    self.current_kerneld_boot_id,
                )?;
                let response = PrepareIngressResponseV2::new(
                    task.task_handle,
                    match task.status {
                        PublicTaskStatusV2::AwaitingUiAuthentication {
                            bootstrap: Some(bootstrap),
                        }
                        | PublicTaskStatusV2::Ready {
                            bootstrap: Some(bootstrap),
                        } => bootstrap,
                        _ => JarvisBootstrapActionV2::None,
                    },
                );
                self.prepare_replays[replay_index].response = response;
                return Ok(response);
            }
            return Err(AgentTaskErrorV2::IdempotencyConflict);
        }
        if self.tasks.len() >= self.maximum_tasks
            || self.prepare_replays.len() >= MAX_PREPARE_REPLAYS
            || self.tasks.iter().any(|task| {
                task.durable_task_id == preparation.durable_task_id
                    || task.correlation_digest == preparation.correlation_digest
            })
        {
            return Err(AgentTaskErrorV2::StateConflict);
        }
        let mut handle_entropy = [0_u8; 32];
        let mut selector_entropy = [0_u8; 32];
        getrandom::getrandom(&mut handle_entropy)
            .map_err(|_| AgentTaskErrorV2::AllocationFailure)?;
        getrandom::getrandom(&mut selector_entropy)
            .map_err(|_| AgentTaskErrorV2::AllocationFailure)?;
        let task_handle = TaskHandleV2::from_authority_entropy(handle_entropy)
            .ok_or(AgentTaskErrorV2::AllocationFailure)?;
        let selector = JarvisBootstrapSelectorV2::from_authority_entropy(selector_entropy)
            .ok_or(AgentTaskErrorV2::AllocationFailure)?;
        let bootstrap = JarvisBootstrapActionV2::OpenIngress {
            url: JarvisBootstrapUrlV2::from_agentd_selector(BootstrapKindV2::Ingress, selector),
        };
        let response = PrepareIngressResponseV2::new(task_handle, bootstrap);
        let task_handle_digest = task_handle_digest(task_handle)?;
        if self
            .tasks
            .iter()
            .any(|task| task.task_handle_digest == task_handle_digest)
        {
            return Err(AgentTaskErrorV2::AllocationFailure);
        }
        self.tasks
            .try_reserve(1)
            .map_err(|_| AgentTaskErrorV2::AllocationFailure)?;
        self.prepare_replays
            .try_reserve(1)
            .map_err(|_| AgentTaskErrorV2::AllocationFailure)?;
        self.tasks.push(TaskResolverRecordV2 {
            task_handle,
            task_handle_digest,
            jarvis_principal: context.jarvis_principal,
            jarvis_os_peer_class: context.jarvis_os_peer_class,
            origin_boots: context.origin_boots,
            durable_task_id: preparation.durable_task_id,
            correlation_digest: preparation.correlation_digest,
            kernel_bootstrap_binding_digest: preparation.kernel_bootstrap_binding_digest,
            bootstrap_selector: Some(selector),
            bootstrap_agentd_boot_id: Some(self.current_agentd_boot_id),
            kernel_ingress_transfer: Some(kernel_ingress_transfer),
            kernel_preparation,
            kernel_correlation,
            creating_manifest_digest: self.active_state_manifest_digest,
            creating_deployment_generation: self.deployment_generation,
            protocol_abi_digest: self.protocol_abi_digest,
            task_logical_expires_at: preparation.task_logical_expires_at,
            status_retain_until: preparation.status_retain_until,
            status: PublicTaskStatusV2::AwaitingUiAuthentication {
                bootstrap: Some(bootstrap),
            },
            public_state_revision: 1,
            pending_cancellation_digest: None,
            cancellation_commit_digest: None,
        });
        self.prepare_replays.push(PrepareReplayRecordV2 {
            jarvis_principal: context.jarvis_principal,
            jarvis_os_peer_class: context.jarvis_os_peer_class,
            client_request_nonce,
            request_digest,
            response,
        });
        Ok(response)
    }

    pub fn inspect_bootstrap(
        &mut self,
        kind: BootstrapKindV2,
        selector: JarvisBootstrapSelectorV2,
        now: UnixMillisV2,
    ) -> Result<(), AgentTaskErrorV2> {
        self.accept_time(now)?;
        self.prune_expired(now)?;
        if !self.tasks.iter().any(|task| {
            task.bootstrap_selector == Some(selector)
                && task.bootstrap_agentd_boot_id == Some(self.current_agentd_boot_id)
                && match kind {
                    BootstrapKindV2::Ingress => {
                        task.kernel_ingress_transfer.is_some()
                            && matches!(
                                task.status,
                                PublicTaskStatusV2::AwaitingUiAuthentication {
                                    bootstrap: Some(JarvisBootstrapActionV2::OpenIngress { .. })
                                }
                            )
                    }
                    BootstrapKindV2::Agent => {
                        task.kernel_ingress_transfer.is_none()
                            && matches!(
                                task.status,
                                PublicTaskStatusV2::Ready {
                                    bootstrap: Some(JarvisBootstrapActionV2::OpenAgent { .. })
                                }
                            )
                    }
                    BootstrapKindV2::Approval => false,
                }
                && now.get() < task.task_logical_expires_at.get()
        }) {
            return Err(AgentTaskErrorV2::InvalidReference);
        }
        Ok(())
    }

    pub fn continue_bootstrap(
        &mut self,
        kind: BootstrapKindV2,
        selector: JarvisBootstrapSelectorV2,
        now: UnixMillisV2,
    ) -> Result<ResolvedJarvisBootstrapV2, AgentTaskErrorV2> {
        self.inspect_bootstrap(kind, selector, now)?;
        let task = self
            .tasks
            .iter_mut()
            .find(|task| task.bootstrap_selector == Some(selector))
            .ok_or(AgentTaskErrorV2::InvalidReference)?;
        let resolved = match kind {
            BootstrapKindV2::Ingress => ResolvedJarvisBootstrapV2::Ingress {
                transfer: task
                    .kernel_ingress_transfer
                    .take()
                    .ok_or(AgentTaskErrorV2::StateConflict)?,
            },
            BootstrapKindV2::Agent => ResolvedJarvisBootstrapV2::Agent {
                preparation: task.kernel_preparation,
                correlation: task.kernel_correlation.clone(),
            },
            BootstrapKindV2::Approval => return Err(AgentTaskErrorV2::InvalidReference),
        };
        task.bootstrap_selector = None;
        task.bootstrap_agentd_boot_id = None;
        task.status = match task.status {
            PublicTaskStatusV2::AwaitingUiAuthentication { .. } => {
                PublicTaskStatusV2::AwaitingUiAuthentication { bootstrap: None }
            }
            PublicTaskStatusV2::Ready { .. } => PublicTaskStatusV2::Ready { bootstrap: None },
            status => status,
        };
        Ok(resolved)
    }

    pub fn recovery_projection(
        &self,
    ) -> Result<Vec<AgentTaskRecoveryProjectionV2>, AgentTaskErrorV2> {
        let mut projection = Vec::new();
        projection
            .try_reserve(self.tasks.len())
            .map_err(|_| AgentTaskErrorV2::AllocationFailure)?;
        projection.extend(self.tasks.iter().map(|task| AgentTaskRecoveryProjectionV2 {
            durable_task_id: task.durable_task_id,
            correlation_digest: task.correlation_digest,
            origin_boots: task.origin_boots,
            status: strip_bootstrap(task.status),
            public_state_revision: task.public_state_revision,
            cancellation_pending: task.pending_cancellation_digest.is_some(),
            cancellation_commit_digest: task.cancellation_commit_digest,
        }));
        projection.sort_unstable_by(|left, right| {
            left.durable_task_id
                .as_bytes()
                .cmp(right.durable_task_id.as_bytes())
        });
        Ok(projection)
    }

    pub fn get_task_status(
        &mut self,
        context: AuthenticatedJarvisControlV2,
        request: GetTaskStatusRequestV2,
        now: UnixMillisV2,
    ) -> Result<GetTaskStatusResponseV2, AgentTaskErrorV2> {
        self.validate_current_context(context)?;
        self.accept_time(now)?;
        self.prune_expired(now)?;
        let index = self.resolve_task(context, request.task())?;
        if now.get() >= self.tasks[index].task_logical_expires_at.get()
            && self.tasks[index].status != PublicTaskStatusV2::Expired
        {
            self.tasks[index].status = PublicTaskStatusV2::Expired;
            self.tasks[index].public_state_revision = self.tasks[index]
                .public_state_revision
                .checked_add(1)
                .ok_or(AgentTaskErrorV2::StateConflict)?;
            self.tasks[index].pending_cancellation_digest = None;
        }
        Ok(GetTaskStatusResponseV2::new(self.tasks[index].status))
    }

    pub fn apply_verified_kernel_status(
        &mut self,
        verified: VerifiedKernelTaskStatusV2,
        now: UnixMillisV2,
    ) -> Result<(), AgentTaskErrorV2> {
        if verified.authority_binding_digest != self.kernel_task_authority_binding_digest {
            return Err(AgentTaskErrorV2::KernelAuthentication);
        }
        self.accept_time(now)?;
        self.prune_expired(now)?;
        let task = self
            .tasks
            .iter_mut()
            .find(|task| {
                task.durable_task_id == verified.durable_task_id
                    && task.correlation_digest == verified.correlation_digest
            })
            .ok_or(AgentTaskErrorV2::InvalidReference)?;
        if verified.public_state_revision == task.public_state_revision {
            if verified.status != strip_bootstrap(task.status) {
                return Err(AgentTaskErrorV2::StateConflict);
            }
            if matches!(verified.status, PublicTaskStatusV2::Ready { .. })
                && (task.bootstrap_selector.is_none()
                    || task.bootstrap_agentd_boot_id != Some(self.current_agentd_boot_id))
            {
                mint_agent_bootstrap(task, self.current_agentd_boot_id)?;
            }
            return Ok(());
        }
        if verified.public_state_revision
            != task
                .public_state_revision
                .checked_add(1)
                .ok_or(AgentTaskErrorV2::StateConflict)?
            || !status_transition_allowed(task.status, verified.status)
        {
            return Err(AgentTaskErrorV2::StateConflict);
        }
        task.bootstrap_selector = None;
        task.bootstrap_agentd_boot_id = None;
        task.kernel_ingress_transfer = None;
        task.status = verified.status;
        task.public_state_revision = verified.public_state_revision;
        if matches!(task.status, PublicTaskStatusV2::Ready { .. }) {
            mint_agent_bootstrap(task, self.current_agentd_boot_id)?;
        }
        if status_terminal(task.status) {
            task.pending_cancellation_digest = None;
        }
        Ok(())
    }

    pub fn prepare_cancel(
        &mut self,
        context: AuthenticatedJarvisControlV2,
        request: CancelTaskRequestV2,
        now: UnixMillisV2,
    ) -> Result<PendingTaskCancellationV2, AgentTaskErrorV2> {
        self.validate_current_context(context)?;
        self.accept_time(now)?;
        self.prune_expired(now)?;
        let index = self.resolve_task(context, request.task())?;
        let origin_boots = self.tasks[index].origin_boots;
        let task_logical_expires_at = self.tasks[index].task_logical_expires_at;
        let status = self.tasks[index].status;
        let durable_task_id = self.tasks[index].durable_task_id;
        let correlation_digest = self.tasks[index].correlation_digest;
        let public_state_revision = self.tasks[index].public_state_revision;
        let kernel_preparation = self.tasks[index].kernel_preparation;
        let kernel_correlation = self.tasks[index].kernel_correlation.clone();
        let existing_pending = self.tasks[index].pending_cancellation_digest;
        if context.origin_boots != origin_boots
            || now.get() >= task_logical_expires_at.get()
            || !cancellation_pre_effect_state(status)
        {
            return Err(AgentTaskErrorV2::CancellationTooLate);
        }
        let token = derive_cancel_capability(
            &self.capability_key,
            durable_task_id,
            correlation_digest,
            public_state_revision,
        )?;
        let digest = domain_hash_many(
            CANCEL_CAPABILITY_DOMAIN,
            &[self.installation_id.as_bytes(), &token],
        );
        if existing_pending.is_some_and(|existing| existing != digest) {
            return Err(AgentTaskErrorV2::StateConflict);
        }
        self.tasks[index].pending_cancellation_digest = Some(digest);
        Ok(PendingTaskCancellationV2 {
            token,
            durable_task_id,
            correlation_digest,
            status_revision: public_state_revision,
            kernel_preparation,
            kernel_correlation,
        })
    }

    pub fn prepare_status_query(
        &mut self,
        context: AuthenticatedJarvisControlV2,
        request: GetTaskStatusRequestV2,
        now: UnixMillisV2,
    ) -> Result<PendingTaskStatusQueryV2, AgentTaskErrorV2> {
        self.validate_current_context(context)?;
        self.accept_time(now)?;
        self.prune_expired(now)?;
        let index = self.resolve_task(context, request.task())?;
        let task = &self.tasks[index];
        Ok(PendingTaskStatusQueryV2 {
            durable_task_id: task.durable_task_id,
            correlation_digest: task.correlation_digest,
            status: task.status,
            status_revision: task.public_state_revision,
            kernel_correlation: task.kernel_correlation.clone(),
        })
    }

    pub fn commit_verified_cancellation(
        &mut self,
        pending: PendingTaskCancellationV2,
        verified: VerifiedKernelCancellationV2,
        now: UnixMillisV2,
    ) -> Result<CancelTaskResponseV2, AgentTaskErrorV2> {
        if verified.authority_binding_digest != self.kernel_task_authority_binding_digest {
            return Err(AgentTaskErrorV2::KernelAuthentication);
        }
        self.accept_time(now)?;
        self.prune_expired(now)?;
        let pending_digest = domain_hash_many(
            CANCEL_CAPABILITY_DOMAIN,
            &[self.installation_id.as_bytes(), &pending.token],
        );
        let task = self
            .tasks
            .iter_mut()
            .find(|task| {
                task.durable_task_id == pending.durable_task_id
                    && task.correlation_digest == pending.correlation_digest
            })
            .ok_or(AgentTaskErrorV2::InvalidReference)?;
        if verified.durable_task_id != task.durable_task_id
            || verified.correlation_digest != task.correlation_digest
            || task.public_state_revision != pending.status_revision
            || task.pending_cancellation_digest != Some(pending_digest)
        {
            return Err(AgentTaskErrorV2::StateConflict);
        }
        if task.status == PublicTaskStatusV2::Cancelled {
            return if task.cancellation_commit_digest == Some(verified.cancellation_commit_digest) {
                Ok(CancelTaskResponseV2::new(PublicTaskStatusV2::Cancelled))
            } else {
                Err(AgentTaskErrorV2::StateConflict)
            };
        }
        if !cancellation_pre_effect_state(task.status) {
            return Err(AgentTaskErrorV2::CancellationTooLate);
        }
        task.status = PublicTaskStatusV2::Cancelled;
        task.public_state_revision = task
            .public_state_revision
            .checked_add(1)
            .ok_or(AgentTaskErrorV2::StateConflict)?;
        task.pending_cancellation_digest = None;
        task.cancellation_commit_digest = Some(verified.cancellation_commit_digest);
        Ok(CancelTaskResponseV2::new(PublicTaskStatusV2::Cancelled))
    }

    fn accept_time(&mut self, now: UnixMillisV2) -> Result<(), AgentTaskErrorV2> {
        if now.get() == 0 || now.get() < self.accepted_time_floor_ms {
            return Err(AgentTaskErrorV2::ClockRollback);
        }
        self.accepted_time_floor_ms = now.get();
        Ok(())
    }

    fn prune_expired(&mut self, now: UnixMillisV2) -> Result<(), AgentTaskErrorV2> {
        if !self
            .tasks
            .iter()
            .any(|task| task.status_retain_until.get() <= now.get())
        {
            return Ok(());
        }
        let live_count = self
            .tasks
            .iter()
            .filter(|task| task.status_retain_until.get() > now.get())
            .count();
        let mut live_handles = HashSet::new();
        live_handles
            .try_reserve(live_count)
            .map_err(|_| AgentTaskErrorV2::AllocationFailure)?;
        for task in &self.tasks {
            if task.status_retain_until.get() > now.get() {
                live_handles.insert(task.task_handle);
            }
        }
        self.tasks
            .retain(|task| task.status_retain_until.get() > now.get());
        self.prepare_replays
            .retain(|replay| live_handles.contains(&replay.response.task()));
        Ok(())
    }

    fn validate_current_context(
        &self,
        context: AuthenticatedJarvisControlV2,
    ) -> Result<(), AgentTaskErrorV2> {
        if context.installation_id != self.installation_id
            || context.origin_boots.agentd_server_boot_id != self.current_agentd_boot_id
            || context.origin_boots.kerneld_server_boot_id != self.current_kerneld_boot_id
        {
            return Err(AgentTaskErrorV2::InvalidReference);
        }
        Ok(())
    }

    fn resolve_task(
        &self,
        context: AuthenticatedJarvisControlV2,
        task_handle: TaskHandleV2,
    ) -> Result<usize, AgentTaskErrorV2> {
        let handle_digest = task_handle_digest(task_handle)?;
        self.tasks
            .iter()
            .position(|task| {
                task.task_handle_digest == handle_digest
                    && task.jarvis_principal == context.jarvis_principal
                    && task.jarvis_os_peer_class == context.jarvis_os_peer_class
                    && task.creating_manifest_digest == self.active_state_manifest_digest
                    && task.creating_deployment_generation == self.deployment_generation
                    && task.protocol_abi_digest == self.protocol_abi_digest
                    && !is_zero(task.kernel_bootstrap_binding_digest.as_bytes())
            })
            .ok_or(AgentTaskErrorV2::InvalidReference)
    }
}

fn prepare_request_digest(
    context: AuthenticatedJarvisControlV2,
    preparation: &VerifiedKernelTaskPreparationV2,
) -> Digest32V2 {
    domain_hash_many(
        PREPARE_REQUEST_DOMAIN,
        &[
            context.installation_id.as_bytes(),
            context.jarvis_principal.as_bytes(),
            context.jarvis_os_peer_class.as_bytes(),
            preparation.durable_task_id.as_bytes(),
            preparation.correlation_digest.as_bytes(),
            preparation.authority_binding_digest.as_bytes(),
        ],
    )
}

fn task_handle_digest(task: TaskHandleV2) -> Result<Digest32V2, AgentTaskErrorV2> {
    let bytes = minicbor::to_vec(task).map_err(|_| AgentTaskErrorV2::AllocationFailure)?;
    Ok(domain_hash_many(TASK_HANDLE_DOMAIN, &[&bytes]))
}

fn derive_cancel_capability(
    key: &[u8; 32],
    durable_task_id: DurableTaskIdV2,
    correlation_digest: Digest32V2,
    status_revision: u64,
) -> Result<[u8; 32], AgentTaskErrorV2> {
    let mut mac =
        <Hmac<Sha256>>::new_from_slice(key).map_err(|_| AgentTaskErrorV2::AllocationFailure)?;
    mac.update(CAPABILITY_DERIVATION_DOMAIN);
    mac.update(CANCEL_CAPABILITY_DOMAIN);
    mac.update(durable_task_id.as_bytes());
    mac.update(correlation_digest.as_bytes());
    mac.update(&status_revision.to_be_bytes());
    let token: [u8; 32] = mac.finalize().into_bytes().into();
    if token == [0; 32] {
        return Err(AgentTaskErrorV2::AllocationFailure);
    }
    Ok(token)
}

fn mint_agent_bootstrap(
    task: &mut TaskResolverRecordV2,
    current_agentd_boot_id: BootIdV2,
) -> Result<(), AgentTaskErrorV2> {
    let mut selector_entropy = [0_u8; 32];
    getrandom::getrandom(&mut selector_entropy).map_err(|_| AgentTaskErrorV2::AllocationFailure)?;
    let selector = JarvisBootstrapSelectorV2::from_authority_entropy(selector_entropy)
        .ok_or(AgentTaskErrorV2::AllocationFailure)?;
    let bootstrap = JarvisBootstrapActionV2::OpenAgent {
        url: JarvisBootstrapUrlV2::from_agentd_selector(BootstrapKindV2::Agent, selector),
    };
    task.bootstrap_selector = Some(selector);
    task.bootstrap_agentd_boot_id = Some(current_agentd_boot_id);
    task.kernel_ingress_transfer = None;
    task.status = PublicTaskStatusV2::Ready {
        bootstrap: Some(bootstrap),
    };
    Ok(())
}

fn mint_ingress_bootstrap(
    task: &mut TaskResolverRecordV2,
    current_agentd_boot_id: BootIdV2,
) -> Result<(), AgentTaskErrorV2> {
    if task.kernel_ingress_transfer.is_none() {
        return Err(AgentTaskErrorV2::StateConflict);
    }
    let mut selector_entropy = [0_u8; 32];
    getrandom::getrandom(&mut selector_entropy).map_err(|_| AgentTaskErrorV2::AllocationFailure)?;
    let selector = JarvisBootstrapSelectorV2::from_authority_entropy(selector_entropy)
        .ok_or(AgentTaskErrorV2::AllocationFailure)?;
    let bootstrap = JarvisBootstrapActionV2::OpenIngress {
        url: JarvisBootstrapUrlV2::from_agentd_selector(BootstrapKindV2::Ingress, selector),
    };
    task.bootstrap_selector = Some(selector);
    task.bootstrap_agentd_boot_id = Some(current_agentd_boot_id);
    task.status = PublicTaskStatusV2::AwaitingUiAuthentication {
        bootstrap: Some(bootstrap),
    };
    Ok(())
}

fn normalize_bootstrap_for_current_boot(
    task: &mut TaskResolverRecordV2,
    current_agentd_boot_id: BootIdV2,
    current_kerneld_boot_id: BootIdV2,
) -> Result<(), AgentTaskErrorV2> {
    if task.bootstrap_agentd_boot_id == Some(current_agentd_boot_id) {
        return Ok(());
    }
    match strip_bootstrap(task.status) {
        PublicTaskStatusV2::AwaitingUiAuthentication { .. }
            if task.origin_boots.kerneld_server_boot_id == current_kerneld_boot_id
                && task.kernel_ingress_transfer.is_some() =>
        {
            mint_ingress_bootstrap(task, current_agentd_boot_id)
        }
        PublicTaskStatusV2::Ready { .. } => mint_agent_bootstrap(task, current_agentd_boot_id),
        status => {
            task.bootstrap_selector = None;
            task.bootstrap_agentd_boot_id = None;
            task.kernel_ingress_transfer = None;
            task.status = status;
            Ok(())
        }
    }
}

fn strip_bootstrap(status: PublicTaskStatusV2) -> PublicTaskStatusV2 {
    match status {
        PublicTaskStatusV2::AwaitingUiAuthentication { .. } => {
            PublicTaskStatusV2::AwaitingUiAuthentication { bootstrap: None }
        }
        PublicTaskStatusV2::Ready { .. } => PublicTaskStatusV2::Ready { bootstrap: None },
        other => other,
    }
}

fn cancellation_pre_effect_state(status: PublicTaskStatusV2) -> bool {
    matches!(
        status,
        PublicTaskStatusV2::AwaitingUiAuthentication { .. }
            | PublicTaskStatusV2::AwaitingInput
            | PublicTaskStatusV2::Processing
            | PublicTaskStatusV2::AwaitingIngressApproval
            | PublicTaskStatusV2::Ready { .. }
    )
}

fn status_transition_allowed(current: PublicTaskStatusV2, next: PublicTaskStatusV2) -> bool {
    if status_terminal(current) {
        return current == next;
    }
    status_rank(next) >= status_rank(current)
}

fn status_terminal(status: PublicTaskStatusV2) -> bool {
    matches!(
        status,
        PublicTaskStatusV2::Succeeded
            | PublicTaskStatusV2::EffectSucceededOutputQuarantined { .. }
            | PublicTaskStatusV2::PolicyDenied { .. }
            | PublicTaskStatusV2::FailedNoEffect { .. }
            | PublicTaskStatusV2::Indeterminate
            | PublicTaskStatusV2::Cancelled
            | PublicTaskStatusV2::Expired
    )
}

fn status_rank(status: PublicTaskStatusV2) -> u16 {
    match status {
        PublicTaskStatusV2::AwaitingUiAuthentication { .. } => 1,
        PublicTaskStatusV2::AwaitingInput => 2,
        PublicTaskStatusV2::Processing => 3,
        PublicTaskStatusV2::AwaitingIngressApproval => 4,
        PublicTaskStatusV2::Ready { .. } => 5,
        PublicTaskStatusV2::Running => 6,
        PublicTaskStatusV2::Dispatching => 7,
        PublicTaskStatusV2::Succeeded
        | PublicTaskStatusV2::EffectSucceededOutputQuarantined { .. }
        | PublicTaskStatusV2::PolicyDenied { .. }
        | PublicTaskStatusV2::FailedNoEffect { .. }
        | PublicTaskStatusV2::Indeterminate
        | PublicTaskStatusV2::Cancelled
        | PublicTaskStatusV2::Expired => 8,
    }
}

fn domain_hash_many(domain: &[u8], fields: &[&[u8]]) -> Digest32V2 {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for field in fields {
        hasher.update(field);
    }
    Digest32V2::new(hasher.finalize().into())
}

fn is_zero(bytes: &[u8; 32]) -> bool {
    bytes == &[0; 32]
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use savana_kernel_protocol::v2::{
        AgentControlOperationV2, AgentControlRequestEnvelopeV2, BootIdV2, CancelTaskRequestV2,
        Digest32V2, DurableTaskIdV2, Ed25519KeyIdV2, GetTaskStatusRequestV2,
        NewTaskPreparationHandleV2, Nonce32V2, PublicTaskStatusV2, RequestIdV2, ServiceIdentityV2,
        SignedDurableTaskCorrelationV2, UnixMillisV2, UnsignedDurableTaskCorrelationV2,
    };

    use super::*;

    fn authority_key_id() -> Ed25519KeyIdV2 {
        Ed25519KeyIdV2::new([60; 32])
    }

    fn authority_public_key() -> [u8; 32] {
        SigningKey::from_bytes(&[61; 32]).verifying_key().to_bytes()
    }

    fn authority_binding_digest() -> Digest32V2 {
        kernel_authority::kernel_task_authority_binding_digest(
            authority_key_id(),
            &authority_public_key(),
        )
    }

    fn service(agent_boot: u8, kernel_boot: u8) -> AgentTaskServiceV2 {
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

    fn context(agent_boot: u8, kernel_boot: u8, peer: u8) -> AuthenticatedJarvisControlV2 {
        AuthenticatedJarvisControlV2::from_mutual_authentication(
            Digest32V2::new([1; 32]),
            Digest32V2::new([6; 32]),
            Digest32V2::new([peer; 32]),
            BootIdV2::new([7; 32]),
            BootIdV2::new([8; 32]),
            BootIdV2::new([agent_boot; 32]),
            BootIdV2::new([kernel_boot; 32]),
        )
        .unwrap()
    }

    fn preparation(seed: u8) -> VerifiedKernelTaskPreparationV2 {
        preparation_until(seed, 10_000, 20_000)
    }

    fn preparation_until(
        seed: u8,
        logical_expires_at: u64,
        retain_until: u64,
    ) -> VerifiedKernelTaskPreparationV2 {
        let unsigned = UnsignedDurableTaskCorrelationV2::new(
            Digest32V2::new([1; 32]),
            Digest32V2::new([2; 32]),
            3,
            DurableTaskIdV2::new([seed; 32]),
            ServiceIdentityV2::new([5; 32]),
            BootIdV2::new([9; 32]),
            BootIdV2::new([10; 32]),
            BootIdV2::new([7; 32]),
            UnixMillisV2::new(1),
            UnixMillisV2::new(logical_expires_at),
            UnixMillisV2::new(retain_until),
        )
        .unwrap();
        let correlation =
            SignedDurableTaskCorrelationV2::sign(unsigned, &SigningKey::from_bytes(&[61; 32]))
                .unwrap();
        let correlation_digest = correlation.correlation_digest().unwrap();
        VerifiedKernelTaskPreparationV2::from_verified_kernel_response(
            DurableTaskIdV2::new([seed; 32]),
            correlation_digest,
            Digest32V2::new([seed.wrapping_add(2); 32]),
            UnixMillisV2::new(logical_expires_at),
            UnixMillisV2::new(retain_until),
            authority_binding_digest(),
            NewTaskPreparationHandleV2::from_authority_entropy([seed.wrapping_add(3); 32]).unwrap(),
            correlation,
            KernelIngressBootstrapTransferCapabilityV2::from_authority_entropy(
                [seed.wrapping_add(4); 32],
            )
            .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn prepare_is_exact_replay_and_exposes_only_task_and_fixed_bootstrap() {
        let mut service = service(9, 10);
        let created = service
            .prepare_ingress(
                context(9, 10, 11),
                Nonce32V2::new([12; 32]),
                preparation(13),
                UnixMillisV2::new(100),
            )
            .unwrap();
        let replay = service
            .prepare_ingress(
                context(9, 10, 11),
                Nonce32V2::new([12; 32]),
                preparation(13),
                UnixMillisV2::new(101),
            )
            .unwrap();
        assert_eq!(created, replay);
        assert_eq!(format!("{:?}", created.task()), "TaskHandleV2(<opaque>)");
        let JarvisBootstrapActionV2::OpenIngress { url } = created.bootstrap() else {
            panic!("prepare ingress emitted the wrong fixed bootstrap action");
        };
        assert!(url.to_string().contains("localhost:8765"));
        assert_eq!(
            service.prepare_ingress(
                context(9, 10, 11),
                Nonce32V2::new([12; 32]),
                preparation(14),
                UnixMillisV2::new(102),
            ),
            Err(AgentTaskErrorV2::IdempotencyConflict)
        );
    }

    #[test]
    fn bootstrap_selector_is_boot_scoped_and_consumes_the_exact_kernel_transfer() {
        let mut service = service(9, 10);
        let expected =
            KernelIngressBootstrapTransferCapabilityV2::from_authority_entropy([17; 32]).unwrap();
        let mut verified = preparation(13);
        verified.ingress_transfer = Some(expected);
        let created = service
            .prepare_ingress(
                context(9, 10, 11),
                Nonce32V2::new([12; 32]),
                verified,
                UnixMillisV2::new(100),
            )
            .unwrap();
        let JarvisBootstrapActionV2::OpenIngress { url } = created.bootstrap() else {
            panic!("wrong bootstrap kind");
        };
        service
            .inspect_bootstrap(url.kind(), url.selector(), UnixMillisV2::new(101))
            .unwrap();
        let resolved = service
            .continue_bootstrap(url.kind(), url.selector(), UnixMillisV2::new(102))
            .unwrap();
        assert_eq!(resolved.ingress_transfer(), Some(expected));
        assert_eq!(
            service.continue_bootstrap(url.kind(), url.selector(), UnixMillisV2::new(103)),
            Err(AgentTaskErrorV2::InvalidReference)
        );
    }

    #[test]
    fn ready_status_mints_one_open_agent_selector_and_resolves_kernel_authority() {
        let mut service = service(9, 10);
        let prepared = preparation(23);
        let created = service
            .prepare_ingress(
                context(9, 10, 11),
                Nonce32V2::new([24; 32]),
                prepared.clone(),
                UnixMillisV2::new(100),
            )
            .unwrap();
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
                UnixMillisV2::new(101),
            )
            .unwrap();
        service
            .apply_verified_kernel_status(
                VerifiedKernelTaskStatusV2::from_verified_query(
                    prepared.durable_task_id(),
                    prepared.correlation_digest(),
                    PublicTaskStatusV2::Ready { bootstrap: None },
                    3,
                    authority_binding_digest(),
                )
                .unwrap(),
                UnixMillisV2::new(102),
            )
            .unwrap();
        let PublicTaskStatusV2::Ready {
            bootstrap: Some(JarvisBootstrapActionV2::OpenAgent { url }),
        } = service
            .get_task_status(
                context(9, 10, 11),
                GetTaskStatusRequestV2::new(created.task()),
                UnixMillisV2::new(103),
            )
            .unwrap()
            .status()
        else {
            panic!("ready task did not expose OpenAgent");
        };
        let resolved = service
            .continue_bootstrap(url.kind(), url.selector(), UnixMillisV2::new(104))
            .unwrap();
        let (preparation, correlation) = resolved.agent_authority().unwrap();
        assert_eq!(preparation, prepared.kernel_preparation().unwrap());
        assert_eq!(
            correlation.correlation_digest().unwrap(),
            prepared.correlation_digest()
        );
    }

    #[test]
    fn agent_control_dispatch_binding_rejects_wire_identity_substitution() {
        let deployment = AgentControlDeploymentV2::from_verified_deployment(
            Digest32V2::new([1; 32]),
            Digest32V2::new([2; 32]),
            3,
            Digest32V2::new([4; 32]),
            ServiceIdentityV2::new([5; 32]),
            BootIdV2::new([9; 32]),
            BootIdV2::new([10; 32]),
            ServiceIdentityV2::new([0x31; 32]),
        )
        .unwrap();
        let peer = VerifiedAgentControlPeerV2::from_mutual_authentication(
            Digest32V2::new([6; 32]),
            Digest32V2::new([7; 32]),
            BootIdV2::new([8; 32]),
            BootIdV2::new([0x30; 32]),
            ServiceIdentityV2::new([0x31; 32]),
        )
        .unwrap();
        let request = AgentControlRequestEnvelopeV2::from_authenticated_connection(
            RequestIdV2::new([0x32; 16]),
            BootIdV2::new([0x30; 32]),
            BootIdV2::new([9; 32]),
            ServiceIdentityV2::new([0x31; 32]),
            ServiceIdentityV2::new([5; 32]),
            Digest32V2::new([2; 32]),
            3,
            UnixMillisV2::new(1_000),
            AgentControlOperationV2::Health,
        )
        .unwrap();
        assert!(deployment
            .validate_envelope_for_test(request, peer, UnixMillisV2::new(999))
            .is_ok());

        let substituted = AgentControlRequestEnvelopeV2::from_authenticated_connection(
            RequestIdV2::new([0x32; 16]),
            BootIdV2::new([0x30; 32]),
            BootIdV2::new([9; 32]),
            ServiceIdentityV2::new([0x33; 32]),
            ServiceIdentityV2::new([5; 32]),
            Digest32V2::new([2; 32]),
            3,
            UnixMillisV2::new(1_000),
            AgentControlOperationV2::Health,
        )
        .unwrap();
        assert!(deployment
            .validate_envelope_for_test(substituted, peer, UnixMillisV2::new(999))
            .is_err());
    }

    #[test]
    fn recovery_projection_exposes_no_task_or_cancellation_capability() {
        let mut service = service(9, 10);
        let prepared = preparation(0x21);
        let response = service
            .prepare_ingress(
                context(9, 10, 11),
                Nonce32V2::new([0x22; 32]),
                prepared.clone(),
                UnixMillisV2::new(100),
            )
            .unwrap();
        service
            .prepare_cancel(
                context(9, 10, 11),
                CancelTaskRequestV2::new(response.task()),
                UnixMillisV2::new(101),
            )
            .unwrap();

        let projection = service.recovery_projection().unwrap();

        assert_eq!(projection.len(), 1);
        assert_eq!(projection[0].durable_task_id(), prepared.durable_task_id());
        assert_eq!(
            projection[0].correlation_digest(),
            prepared.correlation_digest()
        );
        assert_eq!(projection[0].public_state_revision(), 1);
        assert!(projection[0].cancellation_pending());
        let debug = format!("{projection:?}");
        assert!(!debug.contains("TaskHandleV2"));
        assert!(!debug.contains("PendingTaskCancellationV2"));
    }

    #[test]
    fn task_query_is_principal_peer_and_current_boot_bound() {
        let mut service = service(9, 10);
        let response = service
            .prepare_ingress(
                context(9, 10, 11),
                Nonce32V2::new([20; 32]),
                preparation(21),
                UnixMillisV2::new(200),
            )
            .unwrap();
        assert_eq!(
            service.get_task_status(
                context(9, 10, 12),
                GetTaskStatusRequestV2::new(response.task()),
                UnixMillisV2::new(201),
            ),
            Err(AgentTaskErrorV2::InvalidReference)
        );

        assert_eq!(
            service.get_task_status(
                context(30, 31, 11),
                GetTaskStatusRequestV2::new(response.task()),
                UnixMillisV2::new(202),
            ),
            Err(AgentTaskErrorV2::InvalidReference)
        );
    }

    #[test]
    fn verified_status_and_cancellation_are_exact_monotonic_transitions() {
        let mut service = service(9, 10);
        let prepared = preparation(40);
        let response = service
            .prepare_ingress(
                context(9, 10, 11),
                Nonce32V2::new([41; 32]),
                prepared.clone(),
                UnixMillisV2::new(300),
            )
            .unwrap();
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
                UnixMillisV2::new(301),
            )
            .unwrap();
        assert_eq!(
            service
                .get_task_status(
                    context(9, 10, 11),
                    GetTaskStatusRequestV2::new(response.task()),
                    UnixMillisV2::new(302),
                )
                .unwrap()
                .status(),
            PublicTaskStatusV2::AwaitingInput
        );

        let cancellation = service
            .prepare_cancel(
                context(9, 10, 11),
                CancelTaskRequestV2::new(response.task()),
                UnixMillisV2::new(303),
            )
            .unwrap();
        let committed = service
            .commit_verified_cancellation(
                cancellation,
                VerifiedKernelCancellationV2::cancelled(
                    prepared.durable_task_id(),
                    prepared.correlation_digest(),
                    Digest32V2::new([42; 32]),
                    authority_binding_digest(),
                )
                .unwrap(),
                UnixMillisV2::new(304),
            )
            .unwrap();
        assert_eq!(committed.status(), PublicTaskStatusV2::Cancelled);
        assert_eq!(
            service.apply_verified_kernel_status(
                VerifiedKernelTaskStatusV2::from_verified_query(
                    prepared.durable_task_id(),
                    prepared.correlation_digest(),
                    PublicTaskStatusV2::Running,
                    3,
                    authority_binding_digest(),
                )
                .unwrap(),
                UnixMillisV2::new(305),
            ),
            Err(AgentTaskErrorV2::StateConflict)
        );
    }

    #[test]
    fn logical_expiry_retains_only_closed_expired_status_until_tombstone_end() {
        let mut service = service(9, 10);
        let response = service
            .prepare_ingress(
                context(9, 10, 11),
                Nonce32V2::new([50; 32]),
                preparation(51),
                UnixMillisV2::new(400),
            )
            .unwrap();
        assert_eq!(
            service
                .get_task_status(
                    context(9, 10, 11),
                    GetTaskStatusRequestV2::new(response.task()),
                    UnixMillisV2::new(10_000),
                )
                .unwrap()
                .status(),
            PublicTaskStatusV2::Expired
        );
        assert_eq!(
            service.get_task_status(
                context(9, 10, 11),
                GetTaskStatusRequestV2::new(response.task()),
                UnixMillisV2::new(20_000),
            ),
            Err(AgentTaskErrorV2::InvalidReference)
        );
    }

    #[test]
    fn expired_tombstones_and_prepare_replays_release_bounded_capacity() {
        let mut service = service(9, 10);
        service.maximum_tasks = 1;
        service
            .prepare_ingress(
                context(9, 10, 11),
                Nonce32V2::new([52; 32]),
                preparation(53),
                UnixMillisV2::new(500),
            )
            .unwrap();
        service
            .prepare_ingress(
                context(9, 10, 11),
                Nonce32V2::new([54; 32]),
                preparation_until(55, 30_000, 40_000),
                UnixMillisV2::new(20_000),
            )
            .unwrap();
        assert_eq!(service.tasks.len(), 1);
        assert_eq!(service.prepare_replays.len(), 1);
    }
}
