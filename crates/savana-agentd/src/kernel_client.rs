use std::io::{Read as _, Write as _};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use minicbor::Encode as _;
use savana_kernel_protocol::v2::{
    decode_authenticate_agent_ui_response_v2, decode_authorize_release_response_v2,
    decode_authorize_tool_call_response_v2, decode_cancel_kernel_task_response_v2,
    decode_claim_agent_session_response_v2, decode_close_agent_session_response_v2,
    decode_commit_planner_value_response_v2, decode_dispatch_execution_response_v2,
    decode_dispatch_release_response_v2, decode_evaluate_tool_call_response_v2,
    decode_get_agent_session_status_response_v2, decode_get_execution_status_response_v2,
    decode_get_kernel_task_status_response_v2, decode_get_release_status_response_v2,
    decode_kernel_agent_health_response_v2, decode_kernel_service_application_request_v2,
    decode_kernel_service_application_response_v2,
    decode_prepare_connector_registration_response_v2, decode_prepare_followup_ingress_response_v2,
    decode_prepare_new_ingress_response_v2, decode_prepare_planner_call_response_v2,
    decode_prepare_release_response_v2, decode_propose_connector_registration_response_v2,
    decode_propose_tool_call_response_v2, decode_read_agent_view_response_v2,
    decode_resume_committed_agent_authentication_response_v2, decode_revoke_vault_response_v2,
    encode_kernel_service_application_request_v2, encode_signed_durable_task_correlation_v2,
    AgentUiAuthenticationPreparationHandleV2, AuthenticateAgentUiRequestV2,
    AuthenticateAgentUiResponseV2, AuthorizeReleaseRequestV2, AuthorizeReleaseResponseV2,
    AuthorizeToolCallRequestV2, AuthorizeToolCallResponseV2, BootIdV2, CancelKernelTaskRequestV2,
    ClaimAgentSessionRequestV2, ClaimAgentSessionResponseV2, CloseAgentSessionRequestV2,
    CloseAgentSessionResponseV2, CommitPlannerValueRequestV2, CommitPlannerValueResponseV2,
    Digest32V2, DispatchExecutionRequestV2, DispatchExecutionResponseV2, DispatchReleaseRequestV2,
    DispatchReleaseResponseV2, Ed25519KeyIdV2, EndpointRoleV2, EvaluateToolCallRequestV2,
    EvaluateToolCallResponseV2, GetAgentSessionStatusRequestV2, GetAgentSessionStatusResponseV2,
    GetExecutionStatusRequestV2, GetExecutionStatusResponseV2, GetKernelTaskStatusRequestV2,
    GetReleaseStatusRequestV2, GetReleaseStatusResponseV2, KernelAgentHealthRequestV2,
    KernelAgentOperationV2, KernelAgentViewCursorV2, KernelConnectorControlOperationV2,
    KernelServiceApplicationRequestV2, KernelServiceApplicationResponseBodyV2,
    KernelServiceHandshakeEdgeV2, KernelServiceOperationV2, MaskedDocumentHandleV2, Nonce32V2,
    PeerIdentityBindingV2, PrepareConnectorRegistrationRequestV2,
    PrepareConnectorRegistrationResponseV2, PrepareFollowupIngressRequestV2,
    PrepareFollowupIngressResponseV2, PrepareNewIngressRequestV2, PrepareNewIngressResponseV2,
    PreparePlannerCallRequestV2, PreparePlannerCallResponseV2, PrepareReleaseRequestV2,
    PrepareReleaseResponseV2, ProposeConnectorRegistrationRequestV2,
    ProposeConnectorRegistrationResponseV2, ProposeToolCallRequestV2, ProposeToolCallResponseV2,
    PublicServiceStateV2, PublicStableCodeV2, PublicTaskStatusV2, ReadAgentViewRequestV2,
    ReadAgentViewResponseV2, RequestIdV2, ResumeCommittedAgentAuthenticationRequestV2,
    ResumeCommittedAgentAuthenticationResponseV2, RevokeVaultRequestV2, RevokeVaultResponseV2,
    SignedAgentAuthenticationAttemptClosureProofV2, SignedDurableTaskCorrelationV2,
    SignedUiAuthenticationSettlementV2, UnixMillisV2, V2ClientHandshake,
    V2ServerHelloAcceptanceErrorV2, HANDSHAKE_FRAME_HEADER_BYTES_V2, MAX_HANDSHAKE_BODY_BYTES_V2,
    MAX_RECORD_CIPHERTEXT_BYTES_V2, MAX_RECORD_HEADER_BYTES_V2, RECORD_FRAME_HEADER_BYTES_V2,
};
use savana_policy_core::v2::{
    ClosedServiceEdgeIdV2, ClosedServiceIdV2, ServiceDeploymentLockV2, ServiceEdgeLockV2,
    VerifiedDaemonStartupV2,
};
use sha2::{Digest as _, Sha256};
use x25519_dalek::StaticSecret;

use crate::{
    AgentControlKernelClientErrorV2, AgentControlKernelClientV2, KernelTaskCancellationRequestV2,
    KernelTaskPreparationRequestV2, KernelTaskStatusRequestV2, VerifiedKernelCancellationV2,
    VerifiedKernelTaskPreparationV2, VerifiedKernelTaskStatusV2,
};

const AGENT_KERNEL_SOCKET_PATH_V2: &str = "/run/savana/kerneld/agentd/kerneld.sock";
const HANDSHAKE_MAGIC_V2: &[u8; 8] = b"SAVANA2\0";
const RECORD_MAGIC_V2: &[u8; 4] = b"SV2R";
const MAX_CONNECTION_DURATION_V2: Duration = Duration::from_secs(5);
const KERNEL_BOOTSTRAP_BINDING_DOMAIN_V2: &[u8] = b"SAVANA_KERNEL_BOOTSTRAP_BINDING_V2\0";
const KERNEL_TASK_AUTHORITY_BINDING_DOMAIN_V2: &[u8] =
    b"SAVANA_KERNEL_AGENT_TASK_AUTHORITY_BINDING_V2\0";
const KERNEL_CANCELLATION_COMMIT_DOMAIN_V2: &[u8] =
    b"SAVANA_AGENTD_KERNEL_CANCELLATION_COMMIT_V2\0";
const KERNEL_OPERATION_REQUEST_ID_DOMAIN_V2: &[u8] =
    b"SAVANA_AGENTD_KERNEL_OPERATION_REQUEST_ID_V2\0";

#[derive(Clone)]
pub struct SuiteOneAgentKernelClientV2 {
    shared: Arc<AgentKernelClientSharedV2>,
}

struct AgentKernelClientSharedV2 {
    authority: RwLock<Arc<AgentKernelGenerationAuthorityV2>>,
    reload_lock: Mutex<()>,
    client_boot_id: BootIdV2,
    server_boot_id: Option<BootIdV2>,
    expected_observed_peer: PeerIdentityBindingV2,
    client_signing_key: SigningKey,
    server_public_key: [u8; 32],
    socket_path: PathBuf,
    startup_loader: Option<Arc<VerifiedAgentKernelStartupLoaderV2>>,
    #[cfg(test)]
    successor_edge_for_test: Option<KernelServiceHandshakeEdgeV2>,
}

type VerifiedAgentKernelStartupLoaderV2 =
    dyn Fn() -> Result<VerifiedDaemonStartupV2, ()> + Send + Sync;

struct AgentKernelGenerationAuthorityV2 {
    edge: KernelServiceHandshakeEdgeV2,
    task_authority_key_id: Ed25519KeyIdV2,
    task_authority_public_key: [u8; 32],
    continuity: Option<AgentKernelContinuityV2>,
}

struct AgentKernelOperationResultV2 {
    body: Vec<u8>,
    authority: Arc<AgentKernelGenerationAuthorityV2>,
}

#[derive(Clone, PartialEq, Eq)]
struct AgentKernelContinuityV2 {
    installation_id: Digest32V2,
    active_state_manifest_sequence: u64,
    active_state_manifest_digest: Digest32V2,
    deployment_generation: u64,
    effect_fence_epoch: u64,
    protocol_abi_digest: Digest32V2,
    release_identity_digest: Digest32V2,
    model_set_identity_digest: Digest32V2,
    resource_profile_identity_digest: Digest32V2,
    approval_lock_identity_digest: Digest32V2,
    planner_lock_identity_digest: Digest32V2,
    executor_key_lock_identity_digest: Digest32V2,
    kernel_envelope_signing_key_id: Ed25519KeyIdV2,
    client_lock: ServiceDeploymentLockV2,
    server_lock: ServiceDeploymentLockV2,
    edge_lock: ServiceEdgeLockV2,
}

impl AgentKernelContinuityV2 {
    fn from_startup(
        startup: &VerifiedDaemonStartupV2,
    ) -> Result<Self, AgentControlKernelClientErrorV2> {
        Ok(Self {
            installation_id: startup.installation_id(),
            active_state_manifest_sequence: startup.active_state_manifest_sequence(),
            active_state_manifest_digest: startup.active_state_manifest_digest(),
            deployment_generation: startup.deployment_generation(),
            effect_fence_epoch: startup.effect_fence_epoch(),
            protocol_abi_digest: startup.protocol_abi_digest(),
            release_identity_digest: startup.release_identity_digest(),
            model_set_identity_digest: startup.model_set_identity_digest(),
            resource_profile_identity_digest: startup.resource_profile_identity_digest(),
            approval_lock_identity_digest: startup.approval_lock_identity_digest(),
            planner_lock_identity_digest: startup.planner_lock_identity_digest(),
            executor_key_lock_identity_digest: startup.executor_key_lock_identity_digest(),
            kernel_envelope_signing_key_id: startup.kernel_envelope_signing_key_id(),
            client_lock: *startup
                .service_lock(ClosedServiceIdV2::Agentd)
                .ok_or(AgentControlKernelClientErrorV2::Unavailable)?,
            server_lock: *startup
                .service_lock(ClosedServiceIdV2::Kerneld)
                .ok_or(AgentControlKernelClientErrorV2::Unavailable)?,
            edge_lock: startup
                .edge_lock(ClosedServiceEdgeIdV2::AgentKernel)
                .cloned()
                .ok_or(AgentControlKernelClientErrorV2::Unavailable)?,
        })
    }

    fn is_exact_successor_of(&self, predecessor: &Self) -> bool {
        predecessor
            .active_state_manifest_sequence
            .checked_add(1)
            .is_some_and(|value| value == self.active_state_manifest_sequence)
            && predecessor
                .deployment_generation
                .checked_add(1)
                .is_some_and(|value| value == self.deployment_generation)
            && predecessor
                .effect_fence_epoch
                .checked_add(1)
                .is_some_and(|value| value == self.effect_fence_epoch)
            && self.installation_id == predecessor.installation_id
            && self.protocol_abi_digest == predecessor.protocol_abi_digest
            && self.release_identity_digest == predecessor.release_identity_digest
            && self.model_set_identity_digest == predecessor.model_set_identity_digest
            && self.resource_profile_identity_digest == predecessor.resource_profile_identity_digest
            && self.approval_lock_identity_digest == predecessor.approval_lock_identity_digest
            && self.planner_lock_identity_digest == predecessor.planner_lock_identity_digest
            && self.executor_key_lock_identity_digest
                == predecessor.executor_key_lock_identity_digest
            && self.kernel_envelope_signing_key_id == predecessor.kernel_envelope_signing_key_id
            && self.client_lock == predecessor.client_lock
            && self.server_lock == predecessor.server_lock
            && self.edge_lock == predecessor.edge_lock
    }
}

impl std::fmt::Debug for SuiteOneAgentKernelClientV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SuiteOneAgentKernelClientV2(<deployment-bound-keys-redacted>)")
    }
}

impl SuiteOneAgentKernelClientV2 {
    pub fn from_verified_deployment(
        edge: KernelServiceHandshakeEdgeV2,
        client_boot_id: BootIdV2,
        expected_observed_peer: PeerIdentityBindingV2,
        client_signing_key: SigningKey,
        server_public_key: [u8; 32],
        task_authority_key_id: Ed25519KeyIdV2,
        task_authority_public_key: [u8; 32],
    ) -> Result<Self, AgentControlKernelClientErrorV2> {
        if edge.role() != EndpointRoleV2::AgentKernel
            || client_boot_id.as_bytes().iter().all(|byte| *byte == 0)
            || server_public_key.iter().all(|byte| *byte == 0)
            || savana_kernel_protocol::v2::derive_ed25519_key_id_v2(task_authority_public_key)
                != task_authority_key_id
        {
            return Err(AgentControlKernelClientErrorV2::Unavailable);
        }
        Ok(Self {
            shared: Arc::new(AgentKernelClientSharedV2 {
                authority: RwLock::new(Arc::new(AgentKernelGenerationAuthorityV2 {
                    edge,
                    task_authority_key_id,
                    task_authority_public_key,
                    continuity: None,
                })),
                reload_lock: Mutex::new(()),
                client_boot_id,
                server_boot_id: None,
                expected_observed_peer,
                client_signing_key,
                server_public_key,
                socket_path: PathBuf::from(AGENT_KERNEL_SOCKET_PATH_V2),
                startup_loader: None,
                #[cfg(test)]
                successor_edge_for_test: None,
            }),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_verified_startup<F>(
        startup: &VerifiedDaemonStartupV2,
        client_boot_id: BootIdV2,
        server_boot_id: BootIdV2,
        expected_observed_peer: PeerIdentityBindingV2,
        client_signing_key: SigningKey,
        server_public_key: [u8; 32],
        task_authority_key_id: Ed25519KeyIdV2,
        task_authority_public_key: [u8; 32],
        startup_loader: F,
    ) -> Result<Self, AgentControlKernelClientErrorV2>
    where
        F: Fn() -> Result<VerifiedDaemonStartupV2, ()> + Send + Sync + 'static,
    {
        let edge = startup
            .kernel_service_handshake_edge(ClosedServiceEdgeIdV2::AgentKernel, server_boot_id)
            .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)?;
        let continuity = AgentKernelContinuityV2::from_startup(startup)?;
        if continuity.edge_lock.client_handshake_key_id
            != savana_kernel_protocol::v2::derive_ed25519_key_id_v2(
                client_signing_key.verifying_key().to_bytes(),
            )
            || continuity.edge_lock.server_handshake_key_id
                != savana_kernel_protocol::v2::derive_ed25519_key_id_v2(server_public_key)
        {
            return Err(AgentControlKernelClientErrorV2::Unavailable);
        }
        let mut client = Self::from_verified_deployment(
            edge,
            client_boot_id,
            expected_observed_peer,
            client_signing_key,
            server_public_key,
            task_authority_key_id,
            task_authority_public_key,
        )?;
        let shared =
            Arc::get_mut(&mut client.shared).ok_or(AgentControlKernelClientErrorV2::Unavailable)?;
        shared.server_boot_id = Some(server_boot_id);
        shared.startup_loader = Some(Arc::new(startup_loader));
        shared.authority = RwLock::new(Arc::new(AgentKernelGenerationAuthorityV2 {
            edge,
            task_authority_key_id,
            task_authority_public_key,
            continuity: Some(continuity),
        }));
        Ok(client)
    }

    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    #[allow(clippy::too_many_arguments)]
    pub fn from_verified_startup_for_test_support<F>(
        startup: &VerifiedDaemonStartupV2,
        client_boot_id: BootIdV2,
        server_boot_id: BootIdV2,
        expected_observed_peer: PeerIdentityBindingV2,
        client_signing_key: SigningKey,
        server_public_key: [u8; 32],
        task_authority_key_id: Ed25519KeyIdV2,
        task_authority_public_key: [u8; 32],
        socket_path: PathBuf,
        startup_loader: F,
    ) -> Result<Self, AgentControlKernelClientErrorV2>
    where
        F: Fn() -> Result<VerifiedDaemonStartupV2, ()> + Send + Sync + 'static,
    {
        let mut client = Self::from_verified_startup(
            startup,
            client_boot_id,
            server_boot_id,
            expected_observed_peer,
            client_signing_key,
            server_public_key,
            task_authority_key_id,
            task_authority_public_key,
            startup_loader,
        )?;
        Arc::get_mut(&mut client.shared)
            .ok_or(AgentControlKernelClientErrorV2::Unavailable)?
            .socket_path = socket_path;
        Ok(client)
    }

    #[cfg(test)]
    fn with_socket_path_for_test(mut self, socket_path: PathBuf) -> Self {
        Arc::get_mut(&mut self.shared).unwrap().socket_path = socket_path;
        self
    }

    #[cfg(test)]
    fn with_successor_edge_for_test(
        mut self,
        successor_edge: KernelServiceHandshakeEdgeV2,
    ) -> Self {
        Arc::get_mut(&mut self.shared)
            .unwrap()
            .successor_edge_for_test = Some(successor_edge);
        self
    }

    fn authority(
        &self,
    ) -> Result<Arc<AgentKernelGenerationAuthorityV2>, AgentControlKernelClientErrorV2> {
        self.shared
            .authority
            .read()
            .map(|authority| Arc::clone(&authority))
            .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)
    }

    pub(crate) fn reload_verified_authority(&self) -> Result<(), AgentControlKernelClientErrorV2> {
        let current = self.authority()?;
        self.reload_after_handshake_rejection(&current)
    }

    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn reload_verified_authority_for_test_support(
        &self,
    ) -> Result<(), AgentControlKernelClientErrorV2> {
        self.reload_verified_authority()
    }

    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn active_generation_for_test_support(&self) -> Option<u64> {
        self.authority().ok().and_then(|authority| {
            authority
                .continuity
                .as_ref()
                .map(|value| value.deployment_generation)
        })
    }

    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn prepare_ingress_for_test_support(
        &self,
        request_id: RequestIdV2,
        client_request_nonce: Nonce32V2,
        machine_boot_id: BootIdV2,
        deadline: UnixMillisV2,
    ) -> Result<VerifiedKernelTaskPreparationV2, AgentControlKernelClientErrorV2> {
        let request = KernelTaskPreparationRequestV2::from_authenticated_control(
            request_id,
            client_request_nonce,
            machine_boot_id,
            deadline,
        )
        .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)?;
        let mut client = self.clone();
        client.prepare_task(request)
    }

    fn reload_after_handshake_rejection(
        &self,
        failed: &Arc<AgentKernelGenerationAuthorityV2>,
    ) -> Result<(), AgentControlKernelClientErrorV2> {
        let _reload = self
            .shared
            .reload_lock
            .lock()
            .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)?;
        let current = self.authority()?;
        if !Arc::ptr_eq(&current, failed) {
            return Ok(());
        }
        #[cfg(test)]
        if let Some(edge) = self.shared.successor_edge_for_test {
            let mut active = self
                .shared
                .authority
                .write()
                .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)?;
            if Arc::ptr_eq(&active, failed) {
                *active = Arc::new(AgentKernelGenerationAuthorityV2 {
                    edge,
                    task_authority_key_id: current.task_authority_key_id,
                    task_authority_public_key: current.task_authority_public_key,
                    continuity: None,
                });
            }
            return Ok(());
        }
        let loader = self
            .shared
            .startup_loader
            .as_ref()
            .ok_or(AgentControlKernelClientErrorV2::Unavailable)?;
        let startup = loader().map_err(|()| AgentControlKernelClientErrorV2::Unavailable)?;
        let candidate = self.authority_from_startup(&startup, &current)?;
        let mut active = self
            .shared
            .authority
            .write()
            .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)?;
        if !Arc::ptr_eq(&active, failed) {
            return Ok(());
        }
        let current_continuity = active
            .continuity
            .as_ref()
            .ok_or(AgentControlKernelClientErrorV2::Unavailable)?;
        let candidate_continuity = candidate
            .continuity
            .as_ref()
            .ok_or(AgentControlKernelClientErrorV2::Unavailable)?;
        if candidate_continuity == current_continuity {
            return Ok(());
        }
        if !candidate_continuity.is_exact_successor_of(current_continuity) {
            return Err(AgentControlKernelClientErrorV2::Unavailable);
        }
        *active = Arc::new(candidate);
        Ok(())
    }

    fn authority_from_startup(
        &self,
        startup: &VerifiedDaemonStartupV2,
        current: &AgentKernelGenerationAuthorityV2,
    ) -> Result<AgentKernelGenerationAuthorityV2, AgentControlKernelClientErrorV2> {
        let continuity = AgentKernelContinuityV2::from_startup(startup)?;
        if continuity.edge_lock.client_handshake_key_id
            != savana_kernel_protocol::v2::derive_ed25519_key_id_v2(
                self.shared.client_signing_key.verifying_key().to_bytes(),
            )
            || continuity.edge_lock.server_handshake_key_id
                != savana_kernel_protocol::v2::derive_ed25519_key_id_v2(
                    self.shared.server_public_key,
                )
        {
            return Err(AgentControlKernelClientErrorV2::Unavailable);
        }
        let edge = startup
            .kernel_service_handshake_edge(
                ClosedServiceEdgeIdV2::AgentKernel,
                self.shared
                    .server_boot_id
                    .ok_or(AgentControlKernelClientErrorV2::Unavailable)?,
            )
            .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)?;
        Ok(AgentKernelGenerationAuthorityV2 {
            edge,
            task_authority_key_id: current.task_authority_key_id,
            task_authority_public_key: current.task_authority_public_key,
            continuity: Some(continuity),
        })
    }

    fn health_exchange(
        &self,
        request_id: RequestIdV2,
        deadline: UnixMillisV2,
    ) -> Result<PublicServiceStateV2, AgentControlKernelClientErrorV2> {
        let io_deadline = io_deadline(deadline)?;
        let stream = UnixStream::connect(&self.shared.socket_path)
            .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)?;
        self.health_over_stream(stream, request_id, deadline, io_deadline)
    }

    fn health_over_stream(
        &self,
        stream: UnixStream,
        request_id: RequestIdV2,
        deadline: UnixMillisV2,
        io_deadline: Instant,
    ) -> Result<PublicServiceStateV2, AgentControlKernelClientErrorV2> {
        let body = self
            .operation_over_stream(
                stream,
                request_id,
                deadline,
                io_deadline,
                KernelServiceOperationV2::agent(KernelAgentOperationV2::Health(
                    KernelAgentHealthRequestV2,
                )),
            )?
            .body;
        let health = decode_kernel_agent_health_response_v2(&body)
            .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)?;
        Ok(health.state())
    }

    fn operation_exchange(
        &self,
        request_id: RequestIdV2,
        deadline: UnixMillisV2,
        operation: KernelServiceOperationV2,
    ) -> Result<Vec<u8>, AgentControlKernelClientErrorV2> {
        self.operation_exchange_with_authority(request_id, deadline, operation)
            .map(|result| result.body)
    }

    fn operation_exchange_with_authority(
        &self,
        request_id: RequestIdV2,
        deadline: UnixMillisV2,
        operation: KernelServiceOperationV2,
    ) -> Result<AgentKernelOperationResultV2, AgentControlKernelClientErrorV2> {
        let io_deadline = io_deadline(deadline)?;
        let stream = UnixStream::connect(&self.shared.socket_path)
            .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)?;
        self.operation_over_stream(stream, request_id, deadline, io_deadline, operation)
    }

    fn operation_exchange_stable(
        &self,
        deadline: UnixMillisV2,
        operation: KernelServiceOperationV2,
    ) -> Result<Vec<u8>, AgentControlKernelClientErrorV2> {
        let provisional = KernelServiceApplicationRequestV2::new(
            operation.role(),
            RequestIdV2::new([1; 16]),
            UnixMillisV2::new(1),
            operation,
        )
        .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)?;
        let canonical = encode_kernel_service_application_request_v2(&provisional)
            .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)?;
        let mut hasher = Sha256::new();
        hasher.update(KERNEL_OPERATION_REQUEST_ID_DOMAIN_V2);
        hasher.update(&canonical);
        let digest: [u8; 32] = hasher.finalize().into();
        let mut request_id = [0_u8; 16];
        request_id.copy_from_slice(&digest[..16]);
        if request_id == [0; 16] {
            request_id[15] = 1;
        }
        let (_, _, _, operation) = decode_kernel_service_application_request_v2(&canonical)
            .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)?
            .into_parts();
        self.operation_exchange(RequestIdV2::new(request_id), deadline, operation)
    }

    pub fn resume_committed_agent_authentication(
        &self,
        correlation: SignedDurableTaskCorrelationV2,
        client_request_nonce: Nonce32V2,
        prior_attempt_closure_proof: Option<SignedAgentAuthenticationAttemptClosureProofV2>,
        deadline: UnixMillisV2,
    ) -> Result<ResumeCommittedAgentAuthenticationResponseV2, AgentControlKernelClientErrorV2> {
        let request = ResumeCommittedAgentAuthenticationRequestV2::new(
            correlation,
            client_request_nonce,
            prior_attempt_closure_proof,
        )
        .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)?;
        let body = self.operation_exchange_stable(
            deadline,
            KernelServiceOperationV2::agent(
                KernelAgentOperationV2::ResumeCommittedAgentAuthentication(request),
            ),
        )?;
        decode_resume_committed_agent_authentication_response_v2(&body)
            .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)
    }

    pub fn authenticate_agent_ui(
        &self,
        authentication_preparation: AgentUiAuthenticationPreparationHandleV2,
        settlement: SignedUiAuthenticationSettlementV2,
        deadline: UnixMillisV2,
    ) -> Result<AuthenticateAgentUiResponseV2, AgentControlKernelClientErrorV2> {
        let request = AuthenticateAgentUiRequestV2::new(authentication_preparation, settlement)
            .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)?;
        let body = self.operation_exchange_stable(
            deadline,
            KernelServiceOperationV2::agent(KernelAgentOperationV2::AuthenticateAgentUi(request)),
        )?;
        decode_authenticate_agent_ui_response_v2(&body)
            .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)
    }

    pub fn claim_agent_session(
        &self,
        authorization: savana_kernel_protocol::v2::AgentUiAuthorizationHandleV2,
        deadline: UnixMillisV2,
    ) -> Result<ClaimAgentSessionResponseV2, AgentControlKernelClientErrorV2> {
        let body = self.operation_exchange_stable(
            deadline,
            KernelServiceOperationV2::agent(KernelAgentOperationV2::ClaimAgentSession(
                ClaimAgentSessionRequestV2::new(authorization),
            )),
        )?;
        decode_claim_agent_session_response_v2(&body)
            .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)
    }

    pub fn read_agent_view(
        &self,
        document: MaskedDocumentHandleV2,
        cursor: Option<KernelAgentViewCursorV2>,
        maximum_encoded_bytes: u32,
        client_request_nonce: Nonce32V2,
        deadline: UnixMillisV2,
    ) -> Result<ReadAgentViewResponseV2, AgentControlKernelClientErrorV2> {
        let request = ReadAgentViewRequestV2::new(
            document,
            cursor,
            maximum_encoded_bytes,
            client_request_nonce,
        )
        .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)?;
        let body = self.operation_exchange_stable(
            deadline,
            KernelServiceOperationV2::agent(KernelAgentOperationV2::ReadAgentView(request)),
        )?;
        decode_read_agent_view_response_v2(&body)
            .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)
    }

    pub fn prepare_followup_ingress(
        &self,
        request: PrepareFollowupIngressRequestV2,
        request_id: RequestIdV2,
        deadline: UnixMillisV2,
    ) -> Result<PrepareFollowupIngressResponseV2, AgentControlKernelClientErrorV2> {
        let body = self.operation_exchange(
            request_id,
            deadline,
            KernelServiceOperationV2::agent(KernelAgentOperationV2::PrepareFollowupIngress(
                request,
            )),
        )?;
        decode_prepare_followup_ingress_response_v2(&body)
            .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)
    }

    pub fn get_agent_session_status(
        &self,
        request: GetAgentSessionStatusRequestV2,
        request_id: RequestIdV2,
        deadline: UnixMillisV2,
    ) -> Result<GetAgentSessionStatusResponseV2, AgentControlKernelClientErrorV2> {
        let body = self.operation_exchange(
            request_id,
            deadline,
            KernelServiceOperationV2::agent(KernelAgentOperationV2::GetAgentSessionStatus(request)),
        )?;
        decode_get_agent_session_status_response_v2(&body)
            .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)
    }

    pub fn prepare_planner_call(
        &self,
        request: PreparePlannerCallRequestV2,
        request_id: RequestIdV2,
        deadline: UnixMillisV2,
    ) -> Result<PreparePlannerCallResponseV2, AgentControlKernelClientErrorV2> {
        let body = self.operation_exchange(
            request_id,
            deadline,
            KernelServiceOperationV2::agent(KernelAgentOperationV2::PreparePlannerCall(request)),
        )?;
        decode_prepare_planner_call_response_v2(&body)
            .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)
    }

    pub fn commit_planner_value(
        &self,
        request: CommitPlannerValueRequestV2,
        request_id: RequestIdV2,
        deadline: UnixMillisV2,
    ) -> Result<CommitPlannerValueResponseV2, AgentControlKernelClientErrorV2> {
        let body = self.operation_exchange(
            request_id,
            deadline,
            KernelServiceOperationV2::agent(KernelAgentOperationV2::CommitPlannerValue(request)),
        )?;
        decode_commit_planner_value_response_v2(&body)
            .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)
    }

    pub fn propose_tool_call(
        &self,
        request: ProposeToolCallRequestV2,
        request_id: RequestIdV2,
        deadline: UnixMillisV2,
    ) -> Result<ProposeToolCallResponseV2, AgentControlKernelClientErrorV2> {
        let body = self.operation_exchange(
            request_id,
            deadline,
            KernelServiceOperationV2::agent(KernelAgentOperationV2::ProposeToolCall(request)),
        )?;
        decode_propose_tool_call_response_v2(&body)
            .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)
    }

    pub fn evaluate_tool_call(
        &self,
        request: EvaluateToolCallRequestV2,
        request_id: RequestIdV2,
        deadline: UnixMillisV2,
    ) -> Result<EvaluateToolCallResponseV2, AgentControlKernelClientErrorV2> {
        let body = self.operation_exchange(
            request_id,
            deadline,
            KernelServiceOperationV2::agent(KernelAgentOperationV2::EvaluateToolCall(request)),
        )?;
        decode_evaluate_tool_call_response_v2(&body)
            .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)
    }

    pub fn authorize_tool_call(
        &self,
        request: AuthorizeToolCallRequestV2,
        request_id: RequestIdV2,
        deadline: UnixMillisV2,
    ) -> Result<AuthorizeToolCallResponseV2, AgentControlKernelClientErrorV2> {
        let body = self.operation_exchange(
            request_id,
            deadline,
            KernelServiceOperationV2::agent(KernelAgentOperationV2::AuthorizeToolCall(request)),
        )?;
        decode_authorize_tool_call_response_v2(&body)
            .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)
    }

    pub fn dispatch_execution(
        &self,
        request: DispatchExecutionRequestV2,
        request_id: RequestIdV2,
        deadline: UnixMillisV2,
    ) -> Result<DispatchExecutionResponseV2, AgentControlKernelClientErrorV2> {
        let body = self.operation_exchange(
            request_id,
            deadline,
            KernelServiceOperationV2::agent(KernelAgentOperationV2::DispatchExecution(request)),
        )?;
        decode_dispatch_execution_response_v2(&body)
            .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)
    }

    pub fn get_execution_status(
        &self,
        request: GetExecutionStatusRequestV2,
        request_id: RequestIdV2,
        deadline: UnixMillisV2,
    ) -> Result<GetExecutionStatusResponseV2, AgentControlKernelClientErrorV2> {
        let body = self.operation_exchange(
            request_id,
            deadline,
            KernelServiceOperationV2::agent(KernelAgentOperationV2::GetExecutionStatus(request)),
        )?;
        decode_get_execution_status_response_v2(&body)
            .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)
    }

    pub fn prepare_release(
        &self,
        request: PrepareReleaseRequestV2,
        request_id: RequestIdV2,
        deadline: UnixMillisV2,
    ) -> Result<PrepareReleaseResponseV2, AgentControlKernelClientErrorV2> {
        let body = self.operation_exchange(
            request_id,
            deadline,
            KernelServiceOperationV2::agent(KernelAgentOperationV2::PrepareRelease(request)),
        )?;
        decode_prepare_release_response_v2(&body)
            .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)
    }

    pub fn authorize_release(
        &self,
        request: AuthorizeReleaseRequestV2,
        request_id: RequestIdV2,
        deadline: UnixMillisV2,
    ) -> Result<AuthorizeReleaseResponseV2, AgentControlKernelClientErrorV2> {
        let body = self.operation_exchange(
            request_id,
            deadline,
            KernelServiceOperationV2::agent(KernelAgentOperationV2::AuthorizeRelease(request)),
        )?;
        decode_authorize_release_response_v2(&body)
            .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)
    }

    pub fn dispatch_release(
        &self,
        request: DispatchReleaseRequestV2,
        request_id: RequestIdV2,
        deadline: UnixMillisV2,
    ) -> Result<DispatchReleaseResponseV2, AgentControlKernelClientErrorV2> {
        let body = self.operation_exchange(
            request_id,
            deadline,
            KernelServiceOperationV2::agent(KernelAgentOperationV2::DispatchRelease(request)),
        )?;
        decode_dispatch_release_response_v2(&body)
            .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)
    }

    pub fn get_release_status(
        &self,
        request: GetReleaseStatusRequestV2,
        request_id: RequestIdV2,
        deadline: UnixMillisV2,
    ) -> Result<GetReleaseStatusResponseV2, AgentControlKernelClientErrorV2> {
        let body = self.operation_exchange(
            request_id,
            deadline,
            KernelServiceOperationV2::agent(KernelAgentOperationV2::GetReleaseStatus(request)),
        )?;
        decode_get_release_status_response_v2(&body)
            .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)
    }

    pub fn revoke_vault(
        &self,
        request: RevokeVaultRequestV2,
        request_id: RequestIdV2,
        deadline: UnixMillisV2,
    ) -> Result<RevokeVaultResponseV2, AgentControlKernelClientErrorV2> {
        let body = self.operation_exchange(
            request_id,
            deadline,
            KernelServiceOperationV2::agent(KernelAgentOperationV2::RevokeVault(request)),
        )?;
        decode_revoke_vault_response_v2(&body)
            .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)
    }

    pub fn close_agent_session(
        &self,
        request: CloseAgentSessionRequestV2,
        request_id: RequestIdV2,
        deadline: UnixMillisV2,
    ) -> Result<CloseAgentSessionResponseV2, AgentControlKernelClientErrorV2> {
        let body = self.operation_exchange(
            request_id,
            deadline,
            KernelServiceOperationV2::agent(KernelAgentOperationV2::CloseAgentSession(request)),
        )?;
        decode_close_agent_session_response_v2(&body)
            .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)
    }

    pub(crate) fn prepare_connector_registration(
        &self,
        request: PrepareConnectorRegistrationRequestV2,
        deadline: UnixMillisV2,
    ) -> Result<PrepareConnectorRegistrationResponseV2, AgentControlKernelClientErrorV2> {
        let body = self.operation_exchange_stable(
            deadline,
            KernelServiceOperationV2::connector(
                KernelConnectorControlOperationV2::PrepareRegistration(request),
            ),
        )?;
        decode_prepare_connector_registration_response_v2(&body)
            .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)
    }

    pub(crate) fn propose_connector_registration(
        &self,
        request: ProposeConnectorRegistrationRequestV2,
        deadline: UnixMillisV2,
    ) -> Result<ProposeConnectorRegistrationResponseV2, AgentControlKernelClientErrorV2> {
        let body = self.operation_exchange_stable(
            deadline,
            KernelServiceOperationV2::connector(
                KernelConnectorControlOperationV2::ProposeRegistration(request),
            ),
        )?;
        decode_propose_connector_registration_response_v2(&body)
            .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)
    }

    fn operation_over_stream(
        &self,
        stream: UnixStream,
        request_id: RequestIdV2,
        deadline: UnixMillisV2,
        io_deadline: Instant,
        operation: KernelServiceOperationV2,
    ) -> Result<AgentKernelOperationResultV2, AgentControlKernelClientErrorV2> {
        self.operation_over_stream_attempt(
            stream,
            request_id,
            deadline,
            io_deadline,
            operation,
            true,
        )
    }

    fn operation_over_stream_attempt(
        &self,
        mut stream: UnixStream,
        request_id: RequestIdV2,
        deadline: UnixMillisV2,
        io_deadline: Instant,
        operation: KernelServiceOperationV2,
        allow_reload: bool,
    ) -> Result<AgentKernelOperationResultV2, AgentControlKernelClientErrorV2> {
        let authority = self.authority()?;
        let result = (|| {
            let client_nonce = Nonce32V2::new(random_nonzero_32()?);
            let ephemeral_secret = StaticSecret::from(random_nonzero_32()?);
            let (pending, hello) = V2ClientHandshake::start(
                authority.edge,
                self.shared.client_boot_id,
                client_nonce,
                self.shared.expected_observed_peer.clone(),
                ephemeral_secret,
                &self.shared.client_signing_key,
            )
            .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)?;
            write_handshake_frame(&mut stream, &hello, io_deadline)?;
            let server_hello = read_handshake_frame(&mut stream, io_deadline)?;
            let (finish, mut session) = match pending.accept_server_hello_classified(
                &server_hello,
                self.shared.server_public_key,
                &self.shared.client_signing_key,
            ) {
                Ok(accepted) => accepted,
                Err(V2ServerHelloAcceptanceErrorV2::GenerationAuthorityMismatch)
                    if allow_reload =>
                {
                    let _ = stream.shutdown(Shutdown::Both);
                    self.reload_after_handshake_rejection(&authority)?;
                    let retry = UnixStream::connect(&self.shared.socket_path)
                        .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)?;
                    return self.operation_over_stream_attempt(
                        retry,
                        request_id,
                        deadline,
                        io_deadline,
                        operation,
                        false,
                    );
                }
                Err(_) => return Err(AgentControlKernelClientErrorV2::Unavailable),
            };
            write_handshake_frame(&mut stream, &finish, io_deadline)?;
            let confirmation = read_record_frame(&mut stream, io_deadline)?;
            session
                .accept_server_confirmation(&confirmation)
                .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)?;

            let operation_tag = operation.tag();
            let request = KernelServiceApplicationRequestV2::new(
                EndpointRoleV2::AgentKernel,
                request_id,
                deadline,
                operation,
            )
            .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)?;
            let plaintext = encode_kernel_service_application_request_v2(&request)
                .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)?;
            let record = session
                .seal_application_request(request_id, operation_tag, &plaintext)
                .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)?;
            write_record_frame(&mut stream, &record, io_deadline)?;
            let response_record = read_record_frame(&mut stream, io_deadline)?;
            let opened = session
                .open_application_response(&response_record)
                .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)?;
            let response = decode_kernel_service_application_response_v2(
                opened.plaintext(),
                EndpointRoleV2::AgentKernel,
                operation_tag,
            )
            .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)?;
            if response.request_id() != request_id || response.operation_tag() != operation_tag {
                return Err(AgentControlKernelClientErrorV2::Unavailable);
            }
            match response.body() {
                KernelServiceApplicationResponseBodyV2::Success(body) => {
                    Ok(AgentKernelOperationResultV2 {
                        body: body.to_vec(),
                        authority: Arc::clone(&authority),
                    })
                }
                KernelServiceApplicationResponseBodyV2::Error(
                    PublicStableCodeV2::DeadlineExceeded,
                ) => Err(AgentControlKernelClientErrorV2::DeadlineExceeded),
                KernelServiceApplicationResponseBodyV2::Error(_) => {
                    Err(AgentControlKernelClientErrorV2::Unavailable)
                }
            }
        })();
        let _ = stream.shutdown(Shutdown::Both);
        result
    }

    fn verify_preparation_response(
        &self,
        request: KernelTaskPreparationRequestV2,
        response: PrepareNewIngressResponseV2,
        now: UnixMillisV2,
        authority: &AgentKernelGenerationAuthorityV2,
    ) -> Result<VerifiedKernelTaskPreparationV2, AgentControlKernelClientErrorV2> {
        let (preparation, correlation, ingress_transfer) = match response {
            PrepareNewIngressResponseV2::Prepared {
                preparation,
                correlation,
                ingress_transfer,
            }
            | PrepareNewIngressResponseV2::Reconciled {
                preparation,
                correlation,
                ingress_transfer,
                ..
            } => (preparation, correlation, ingress_transfer),
        };
        let unsigned = correlation
            .verify(
                authority.task_authority_key_id,
                authority.task_authority_public_key,
                authority.edge.installation_id(),
                authority.edge.active_state_manifest_digest(),
                authority.edge.client_identity(),
                now,
            )
            .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)?;
        if unsigned.deployment_generation() != authority.edge.deployment_generation()
            || unsigned.agentd_kernel_client_boot_id() != self.shared.client_boot_id
            || unsigned.kerneld_server_boot_id() != authority.edge.server_boot_id()
            || unsigned.machine_boot_id() != request.machine_boot_id()
        {
            return Err(AgentControlKernelClientErrorV2::Unavailable);
        }
        let mut encoder = minicbor::Encoder::new(Vec::new());
        encoder
            .array(2)
            .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)?;
        preparation
            .encode(&mut encoder, &mut ())
            .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)?;
        ingress_transfer
            .encode(&mut encoder, &mut ())
            .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)?;
        let encoded_bootstrap = encoder.into_writer();
        let kernel_bootstrap_binding_digest =
            domain_digest(KERNEL_BOOTSTRAP_BINDING_DOMAIN_V2, &encoded_bootstrap);
        let correlation_digest = correlation
            .correlation_digest()
            .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)?;
        VerifiedKernelTaskPreparationV2::from_verified_kernel_response(
            unsigned.durable_task_id(),
            correlation_digest,
            kernel_bootstrap_binding_digest,
            unsigned.task_logical_expires_at(),
            unsigned.status_retain_until(),
            task_authority_binding_digest(
                authority.task_authority_key_id,
                authority.task_authority_public_key,
            ),
            preparation,
            correlation,
            ingress_transfer,
        )
        .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)
    }
}

impl AgentControlKernelClientV2 for SuiteOneAgentKernelClientV2 {
    fn health(
        &mut self,
        request_id: RequestIdV2,
        deadline: UnixMillisV2,
    ) -> Result<PublicServiceStateV2, AgentControlKernelClientErrorV2> {
        self.health_exchange(request_id, deadline)
    }

    fn prepare_task(
        &mut self,
        request: KernelTaskPreparationRequestV2,
    ) -> Result<VerifiedKernelTaskPreparationV2, AgentControlKernelClientErrorV2> {
        let operation = KernelServiceOperationV2::agent(KernelAgentOperationV2::PrepareNewIngress(
            PrepareNewIngressRequestV2::new(
                request.client_request_nonce(),
                request.client_request_nonce(),
            )
            .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)?,
        ));
        let result = self.operation_exchange_with_authority(
            request.request_id(),
            request.deadline(),
            operation,
        )?;
        let response = decode_prepare_new_ingress_response_v2(&result.body)
            .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)?;
        let now = current_unix_millis()?;
        self.verify_preparation_response(request, response, now, &result.authority)
    }

    fn cancel_task(
        &mut self,
        request: KernelTaskCancellationRequestV2,
    ) -> Result<VerifiedKernelCancellationV2, AgentControlKernelClientErrorV2> {
        let preparation = request.kernel_preparation();
        let correlation = request.kernel_correlation().clone();
        let canonical_correlation = encode_signed_durable_task_correlation_v2(&correlation)
            .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)?;
        let canonical_preparation = minicbor::to_vec(preparation)
            .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)?;
        let operation = KernelServiceOperationV2::agent(KernelAgentOperationV2::CancelKernelTask(
            CancelKernelTaskRequestV2::new(preparation, correlation),
        ));
        let result = self.operation_exchange_with_authority(
            request.request_id(),
            request.deadline(),
            operation,
        )?;
        let body = result.body;
        let response = decode_cancel_kernel_task_response_v2(&body)
            .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)?;
        if response.status() != PublicTaskStatusV2::Cancelled {
            return Err(AgentControlKernelClientErrorV2::Unavailable);
        }
        let mut hasher = Sha256::new();
        hasher.update(KERNEL_CANCELLATION_COMMIT_DOMAIN_V2);
        hasher.update(request.request_id().as_bytes());
        hasher.update(request.durable_task_id().as_bytes());
        hasher.update(request.correlation_digest().as_bytes());
        hasher.update(request.status_revision().to_be_bytes());
        hasher.update(&canonical_preparation);
        hasher.update(&canonical_correlation);
        hasher.update(&body);
        VerifiedKernelCancellationV2::cancelled(
            request.durable_task_id(),
            request.correlation_digest(),
            Digest32V2::new(hasher.finalize().into()),
            task_authority_binding_digest(
                result.authority.task_authority_key_id,
                result.authority.task_authority_public_key,
            ),
        )
        .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)
    }

    fn query_task(
        &mut self,
        request: KernelTaskStatusRequestV2,
    ) -> Result<VerifiedKernelTaskStatusV2, AgentControlKernelClientErrorV2> {
        let operation =
            KernelServiceOperationV2::agent(KernelAgentOperationV2::GetKernelTaskStatus(
                GetKernelTaskStatusRequestV2::new(request.kernel_correlation().clone()),
            ));
        let result = self.operation_exchange_with_authority(
            request.request_id(),
            request.deadline(),
            operation,
        )?;
        let response = decode_get_kernel_task_status_response_v2(&result.body)
            .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)?;
        let next_revision = request
            .status_revision()
            .checked_add(1)
            .ok_or(AgentControlKernelClientErrorV2::Unavailable)?;
        VerifiedKernelTaskStatusV2::from_verified_query(
            request.durable_task_id(),
            request.correlation_digest(),
            response.status(),
            next_revision,
            task_authority_binding_digest(
                result.authority.task_authority_key_id,
                result.authority.task_authority_public_key,
            ),
        )
        .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)
    }
}

fn io_deadline(deadline: UnixMillisV2) -> Result<Instant, AgentControlKernelClientErrorV2> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)?;
    let now_millis =
        u64::try_from(now.as_millis()).map_err(|_| AgentControlKernelClientErrorV2::Unavailable)?;
    let remaining_millis = deadline
        .get()
        .checked_sub(now_millis)
        .ok_or(AgentControlKernelClientErrorV2::DeadlineExceeded)?;
    if remaining_millis == 0 {
        return Err(AgentControlKernelClientErrorV2::DeadlineExceeded);
    }
    Ok(Instant::now() + Duration::from_millis(remaining_millis).min(MAX_CONNECTION_DURATION_V2))
}

fn current_unix_millis() -> Result<UnixMillisV2, AgentControlKernelClientErrorV2> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)?;
    let milliseconds =
        u64::try_from(now.as_millis()).map_err(|_| AgentControlKernelClientErrorV2::Unavailable)?;
    if milliseconds == 0 {
        return Err(AgentControlKernelClientErrorV2::Unavailable);
    }
    Ok(UnixMillisV2::new(milliseconds))
}

fn domain_digest(domain: &[u8], value: &[u8]) -> Digest32V2 {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
    Digest32V2::new(hasher.finalize().into())
}

fn task_authority_binding_digest(key_id: Ed25519KeyIdV2, public_key: [u8; 32]) -> Digest32V2 {
    let mut hasher = Sha256::new();
    hasher.update(KERNEL_TASK_AUTHORITY_BINDING_DOMAIN_V2);
    hasher.update(key_id.as_bytes());
    hasher.update(public_key);
    Digest32V2::new(hasher.finalize().into())
}

fn random_nonzero_32() -> Result<[u8; 32], AgentControlKernelClientErrorV2> {
    let mut bytes = [0_u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|_| AgentControlKernelClientErrorV2::Unavailable)?;
    if bytes.iter().all(|byte| *byte == 0) {
        return Err(AgentControlKernelClientErrorV2::Unavailable);
    }
    Ok(bytes)
}

fn set_deadline(
    stream: &UnixStream,
    deadline: Instant,
) -> Result<(), AgentControlKernelClientErrorV2> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(AgentControlKernelClientErrorV2::DeadlineExceeded);
    }
    stream
        .set_read_timeout(Some(remaining))
        .and_then(|_| stream.set_write_timeout(Some(remaining)))
        .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)
}

fn map_io_error(error: std::io::Error) -> AgentControlKernelClientErrorV2 {
    match error.kind() {
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => {
            AgentControlKernelClientErrorV2::DeadlineExceeded
        }
        _ => AgentControlKernelClientErrorV2::Unavailable,
    }
}

fn read_handshake_frame(
    stream: &mut UnixStream,
    deadline: Instant,
) -> Result<Vec<u8>, AgentControlKernelClientErrorV2> {
    set_deadline(stream, deadline)?;
    let mut header = [0_u8; HANDSHAKE_FRAME_HEADER_BYTES_V2];
    stream.read_exact(&mut header).map_err(map_io_error)?;
    if &header[..8] != HANDSHAKE_MAGIC_V2 {
        return Err(AgentControlKernelClientErrorV2::Unavailable);
    }
    let body_length = u32::from_be_bytes(
        header[HANDSHAKE_FRAME_HEADER_BYTES_V2 - 4..]
            .try_into()
            .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)?,
    ) as usize;
    if body_length == 0 || body_length > MAX_HANDSHAKE_BODY_BYTES_V2 {
        return Err(AgentControlKernelClientErrorV2::Unavailable);
    }
    let total = HANDSHAKE_FRAME_HEADER_BYTES_V2
        .checked_add(body_length)
        .ok_or(AgentControlKernelClientErrorV2::Unavailable)?;
    let mut frame = Vec::new();
    frame
        .try_reserve_exact(total)
        .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)?;
    frame.extend_from_slice(&header);
    frame.resize(total, 0);
    stream
        .read_exact(&mut frame[HANDSHAKE_FRAME_HEADER_BYTES_V2..])
        .map_err(map_io_error)?;
    Ok(frame)
}

fn write_handshake_frame(
    stream: &mut UnixStream,
    frame: &[u8],
    deadline: Instant,
) -> Result<(), AgentControlKernelClientErrorV2> {
    if frame.len() < HANDSHAKE_FRAME_HEADER_BYTES_V2 || &frame[..8] != HANDSHAKE_MAGIC_V2 {
        return Err(AgentControlKernelClientErrorV2::Unavailable);
    }
    let body_length = u32::from_be_bytes(
        frame[HANDSHAKE_FRAME_HEADER_BYTES_V2 - 4..HANDSHAKE_FRAME_HEADER_BYTES_V2]
            .try_into()
            .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)?,
    ) as usize;
    if body_length == 0
        || body_length > MAX_HANDSHAKE_BODY_BYTES_V2
        || frame.len() != HANDSHAKE_FRAME_HEADER_BYTES_V2 + body_length
    {
        return Err(AgentControlKernelClientErrorV2::Unavailable);
    }
    set_deadline(stream, deadline)?;
    stream
        .write_all(frame)
        .and_then(|_| stream.flush())
        .map_err(map_io_error)
}

fn read_record_frame(
    stream: &mut UnixStream,
    deadline: Instant,
) -> Result<Vec<u8>, AgentControlKernelClientErrorV2> {
    set_deadline(stream, deadline)?;
    let mut header = [0_u8; RECORD_FRAME_HEADER_BYTES_V2];
    stream.read_exact(&mut header).map_err(map_io_error)?;
    let (header_length, ciphertext_length) = record_lengths(&header)?;
    let total = RECORD_FRAME_HEADER_BYTES_V2
        .checked_add(header_length)
        .and_then(|value| value.checked_add(ciphertext_length))
        .ok_or(AgentControlKernelClientErrorV2::Unavailable)?;
    let mut frame = Vec::new();
    frame
        .try_reserve_exact(total)
        .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)?;
    frame.extend_from_slice(&header);
    frame.resize(total, 0);
    stream
        .read_exact(&mut frame[RECORD_FRAME_HEADER_BYTES_V2..])
        .map_err(map_io_error)?;
    Ok(frame)
}

fn write_record_frame(
    stream: &mut UnixStream,
    frame: &[u8],
    deadline: Instant,
) -> Result<(), AgentControlKernelClientErrorV2> {
    if frame.len() < RECORD_FRAME_HEADER_BYTES_V2 {
        return Err(AgentControlKernelClientErrorV2::Unavailable);
    }
    let (header_length, ciphertext_length) =
        record_lengths(&frame[..RECORD_FRAME_HEADER_BYTES_V2])?;
    if frame.len() != RECORD_FRAME_HEADER_BYTES_V2 + header_length + ciphertext_length {
        return Err(AgentControlKernelClientErrorV2::Unavailable);
    }
    set_deadline(stream, deadline)?;
    stream
        .write_all(frame)
        .and_then(|_| stream.flush())
        .map_err(map_io_error)
}

fn record_lengths(header: &[u8]) -> Result<(usize, usize), AgentControlKernelClientErrorV2> {
    if header.len() != RECORD_FRAME_HEADER_BYTES_V2 || &header[..4] != RECORD_MAGIC_V2 {
        return Err(AgentControlKernelClientErrorV2::Unavailable);
    }
    let header_length = usize::from(u16::from_be_bytes(
        header[4..6]
            .try_into()
            .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)?,
    ));
    let ciphertext_length = u32::from_be_bytes(
        header[6..10]
            .try_into()
            .map_err(|_| AgentControlKernelClientErrorV2::Unavailable)?,
    ) as usize;
    if header_length == 0
        || header_length > MAX_RECORD_HEADER_BYTES_V2
        || !(16..=MAX_RECORD_CIPHERTEXT_BYTES_V2).contains(&ciphertext_length)
    {
        return Err(AgentControlKernelClientErrorV2::Unavailable);
    }
    Ok((header_length, ciphertext_length))
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;

    use savana_kernel_protocol::v2::{
        decode_kernel_service_application_request_v2, derive_ed25519_key_id_v2,
        encode_cancel_kernel_task_response_v2, encode_kernel_agent_health_response_v2,
        encode_kernel_service_application_response_v2, encode_prepare_new_ingress_response_v2,
        CancelKernelTaskResponseV2, Digest32V2, DurableTaskIdV2, KernelAgentHealthResponseV2,
        KernelIngressBootstrapTransferCapabilityV2, KernelServiceApplicationResponseV2,
        NewTaskPreparationHandleV2, PublicServiceStateV2, ServiceIdentityV2,
        SignedDurableTaskCorrelationV2, UnsignedDurableTaskCorrelationV2, V2ServerHandshake,
    };

    use super::*;

    #[test]
    fn preexisting_client_adopts_verified_successor() {
        let directory = tempfile::tempdir().unwrap();
        let socket_path = directory.path().join("agent-kernel-rollover.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        let client_key = SigningKey::from_bytes(&[0x61; 32]);
        let server_key = SigningKey::from_bytes(&[0x62; 32]);
        let server_public_key = server_key.verifying_key().to_bytes();
        let task_authority_key = SigningKey::from_bytes(&[0x63; 32]);
        let task_authority_public_key = task_authority_key.verifying_key().to_bytes();
        let initial_edge = edge_at(&client_key, &server_key, 5, [6; 32], 7, 8);
        let successor_edge = edge_at(&client_key, &server_key, 6, [0x64; 32], 8, 9);
        let observed_peer =
            PeerIdentityBindingV2::linux(501, 20, 42, 99, Digest32V2::new([0x23; 32])).unwrap();
        let server_observed_peer = observed_peer.clone();
        let client_public_key = client_key.verifying_key().to_bytes();
        let server = thread::spawn(move || {
            let (mut stale, _) = listener.accept().unwrap();
            let io_deadline = Instant::now() + Duration::from_secs(2);
            let hello = read_handshake_frame(&mut stale, io_deadline).unwrap();
            let (_, stale_server_hello) = V2ServerHandshake::accept_client_hello(
                successor_edge,
                server_observed_peer.clone(),
                &hello,
                Nonce32V2::new([0x65; 32]),
                StaticSecret::from([0x66; 32]),
                client_public_key,
                &server_key,
            )
            .unwrap();
            write_handshake_frame(&mut stale, &stale_server_hello, io_deadline).unwrap();
            drop(stale);

            let (mut stream, _) = listener.accept().unwrap();
            let hello = read_handshake_frame(&mut stream, io_deadline).unwrap();
            let (pending, server_hello) = V2ServerHandshake::accept_client_hello(
                successor_edge,
                server_observed_peer,
                &hello,
                Nonce32V2::new([0x67; 32]),
                StaticSecret::from([0x68; 32]),
                client_public_key,
                &server_key,
            )
            .unwrap();
            write_handshake_frame(&mut stream, &server_hello, io_deadline).unwrap();
            let finish = read_handshake_frame(&mut stream, io_deadline).unwrap();
            let (accepted, mut session, _) = pending.accept_client_finish(&finish).unwrap();
            write_record_frame(&mut stream, &accepted, io_deadline).unwrap();
            let request_record = read_record_frame(&mut stream, io_deadline).unwrap();
            let opened = session.open_application_request(&request_record).unwrap();
            let health = encode_kernel_agent_health_response_v2(&KernelAgentHealthResponseV2::new(
                true,
                PublicServiceStateV2::Ready,
            ))
            .unwrap();
            let response = KernelServiceApplicationResponseV2::success(
                EndpointRoleV2::AgentKernel,
                opened.request_id(),
                opened.operation_tag(),
                health,
            )
            .unwrap();
            let plaintext = encode_kernel_service_application_response_v2(&response).unwrap();
            let response_record = session
                .seal_application_response(opened.request_id(), opened.operation_tag(), &plaintext)
                .unwrap();
            write_record_frame(&mut stream, &response_record, io_deadline).unwrap();
        });
        let client = SuiteOneAgentKernelClientV2::from_verified_deployment(
            initial_edge,
            BootIdV2::new([0x69; 32]),
            observed_peer,
            client_key,
            server_public_key,
            derive_ed25519_key_id_v2(task_authority_public_key),
            task_authority_public_key,
        )
        .unwrap()
        .with_socket_path_for_test(socket_path)
        .with_successor_edge_for_test(successor_edge);
        let mut request_client = client.clone();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        assert_eq!(
            request_client
                .health(RequestIdV2::new([0x6a; 16]), UnixMillisV2::new(now + 2_000),)
                .unwrap(),
            PublicServiceStateV2::Ready,
        );
        assert_eq!(client.authority().unwrap().edge, successor_edge);
        server.join().unwrap();
    }

    #[test]
    fn preexisting_client_prepares_task_with_the_successful_handshake_generation() {
        let directory = tempfile::tempdir().unwrap();
        let socket_path = directory.path().join("agent-kernel-task-rollover.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        let client_key = SigningKey::from_bytes(&[0x41; 32]);
        let server_key = SigningKey::from_bytes(&[0x42; 32]);
        let server_public_key = server_key.verifying_key().to_bytes();
        let task_authority_key = SigningKey::from_bytes(&[0x43; 32]);
        let task_authority_public_key = task_authority_key.verifying_key().to_bytes();
        let initial_edge = edge_at(&client_key, &server_key, 5, [6; 32], 7, 8);
        let successor_edge = edge_at(&client_key, &server_key, 6, [0x44; 32], 8, 9);
        let observed_peer =
            PeerIdentityBindingV2::linux(501, 20, 42, 99, Digest32V2::new([0x45; 32])).unwrap();
        let server_observed_peer = observed_peer.clone();
        let client_public_key = client_key.verifying_key().to_bytes();
        let client_boot_id = BootIdV2::new([0x46; 32]);
        let machine_boot_id = BootIdV2::new([0x47; 32]);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let server = thread::spawn(move || {
            let io_deadline = Instant::now() + Duration::from_secs(2);
            let (mut stale, _) = listener.accept().unwrap();
            let hello = read_handshake_frame(&mut stale, io_deadline).unwrap();
            let (_, stale_server_hello) = V2ServerHandshake::accept_client_hello(
                successor_edge,
                server_observed_peer.clone(),
                &hello,
                Nonce32V2::new([0x48; 32]),
                StaticSecret::from([0x49; 32]),
                client_public_key,
                &server_key,
            )
            .unwrap();
            write_handshake_frame(&mut stale, &stale_server_hello, io_deadline).unwrap();
            drop(stale);

            let (mut stream, _) = listener.accept().unwrap();
            let hello = read_handshake_frame(&mut stream, io_deadline).unwrap();
            let (pending, server_hello) = V2ServerHandshake::accept_client_hello(
                successor_edge,
                server_observed_peer,
                &hello,
                Nonce32V2::new([0x4a; 32]),
                StaticSecret::from([0x4b; 32]),
                client_public_key,
                &server_key,
            )
            .unwrap();
            write_handshake_frame(&mut stream, &server_hello, io_deadline).unwrap();
            let finish = read_handshake_frame(&mut stream, io_deadline).unwrap();
            let (accepted, mut session, _) = pending.accept_client_finish(&finish).unwrap();
            write_record_frame(&mut stream, &accepted, io_deadline).unwrap();
            let request_record = read_record_frame(&mut stream, io_deadline).unwrap();
            let opened = session.open_application_request(&request_record).unwrap();
            let request = decode_kernel_service_application_request_v2(opened.plaintext()).unwrap();
            assert!(matches!(
                request.operation(),
                KernelServiceOperationV2::Agent(KernelAgentOperationV2::PrepareNewIngress(_))
            ));
            let unsigned = UnsignedDurableTaskCorrelationV2::new(
                Digest32V2::new([1; 32]),
                Digest32V2::new([0x44; 32]),
                8,
                DurableTaskIdV2::new([0x4c; 32]),
                ServiceIdentityV2::new([2; 32]),
                client_boot_id,
                BootIdV2::new([4; 32]),
                machine_boot_id,
                UnixMillisV2::new(now.saturating_sub(1)),
                UnixMillisV2::new(now + 5_000),
                UnixMillisV2::new(now + 10_000),
            )
            .unwrap();
            let prepared = PrepareNewIngressResponseV2::Prepared {
                preparation: NewTaskPreparationHandleV2::from_authority_entropy([0x4d; 32])
                    .unwrap(),
                correlation: SignedDurableTaskCorrelationV2::sign(unsigned, &task_authority_key)
                    .unwrap(),
                ingress_transfer:
                    KernelIngressBootstrapTransferCapabilityV2::from_authority_entropy([0x4e; 32])
                        .unwrap(),
            };
            let body = encode_prepare_new_ingress_response_v2(&prepared).unwrap();
            let response = KernelServiceApplicationResponseV2::success(
                EndpointRoleV2::AgentKernel,
                opened.request_id(),
                opened.operation_tag(),
                body,
            )
            .unwrap();
            let plaintext = encode_kernel_service_application_response_v2(&response).unwrap();
            let response_record = session
                .seal_application_response(opened.request_id(), opened.operation_tag(), &plaintext)
                .unwrap();
            write_record_frame(&mut stream, &response_record, io_deadline).unwrap();
        });
        let mut client = SuiteOneAgentKernelClientV2::from_verified_deployment(
            initial_edge,
            client_boot_id,
            observed_peer,
            client_key,
            server_public_key,
            derive_ed25519_key_id_v2(task_authority_public_key),
            task_authority_public_key,
        )
        .unwrap()
        .with_socket_path_for_test(socket_path)
        .with_successor_edge_for_test(successor_edge);
        let stale_request = KernelTaskPreparationRequestV2::from_authenticated_control(
            RequestIdV2::new([0x4f; 16]),
            Nonce32V2::new([0x50; 32]),
            machine_boot_id,
            UnixMillisV2::new(now + 2_000),
        )
        .unwrap();

        assert!(client.prepare_task(stale_request).is_ok());
        assert_eq!(client.authority().unwrap().edge, successor_edge);
        server.join().unwrap();
    }

    #[test]
    fn server_hello_deadline_never_reloads_authority() {
        let directory = tempfile::tempdir().unwrap();
        let socket_path = directory.path().join("agent-kernel-deadline.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        let client_key = SigningKey::from_bytes(&[0x81; 32]);
        let server_key = SigningKey::from_bytes(&[0x82; 32]);
        let server_public_key = server_key.verifying_key().to_bytes();
        let task_authority_key = SigningKey::from_bytes(&[0x83; 32]);
        let task_authority_public_key = task_authority_key.verifying_key().to_bytes();
        let initial_edge = edge_at(&client_key, &server_key, 5, [6; 32], 7, 8);
        let successor_edge = edge_at(&client_key, &server_key, 6, [0x84; 32], 8, 9);
        let observed_peer =
            PeerIdentityBindingV2::linux(501, 20, 42, 99, Digest32V2::new([0x85; 32])).unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            read_handshake_frame(&mut stream, Instant::now() + Duration::from_secs(1)).unwrap();
            thread::sleep(Duration::from_millis(150));
        });
        let mut client = SuiteOneAgentKernelClientV2::from_verified_deployment(
            initial_edge,
            BootIdV2::new([0x86; 32]),
            observed_peer,
            client_key,
            server_public_key,
            derive_ed25519_key_id_v2(task_authority_public_key),
            task_authority_public_key,
        )
        .unwrap()
        .with_socket_path_for_test(socket_path)
        .with_successor_edge_for_test(successor_edge);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        assert_eq!(
            client.health(RequestIdV2::new([0x87; 16]), UnixMillisV2::new(now + 75),),
            Err(AgentControlKernelClientErrorV2::DeadlineExceeded),
        );
        assert_eq!(client.authority().unwrap().edge, initial_edge);
        server.join().unwrap();
    }

    #[test]
    fn server_hello_eof_never_reloads_authority() {
        let directory = tempfile::tempdir().unwrap();
        let socket_path = directory.path().join("agent-kernel-eof.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        let client_key = SigningKey::from_bytes(&[0xb1; 32]);
        let server_key = SigningKey::from_bytes(&[0xb2; 32]);
        let task_authority_key = SigningKey::from_bytes(&[0xb3; 32]);
        let task_authority_public_key = task_authority_key.verifying_key().to_bytes();
        let initial_edge = edge_at(&client_key, &server_key, 5, [6; 32], 7, 8);
        let successor_edge = edge_at(&client_key, &server_key, 6, [0xb4; 32], 8, 9);
        let observed_peer =
            PeerIdentityBindingV2::linux(501, 20, 42, 99, Digest32V2::new([0xb5; 32])).unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            read_handshake_frame(&mut stream, Instant::now() + Duration::from_secs(1)).unwrap();
        });
        let mut client = SuiteOneAgentKernelClientV2::from_verified_deployment(
            initial_edge,
            BootIdV2::new([0xb6; 32]),
            observed_peer,
            client_key,
            server_key.verifying_key().to_bytes(),
            derive_ed25519_key_id_v2(task_authority_public_key),
            task_authority_public_key,
        )
        .unwrap()
        .with_socket_path_for_test(socket_path)
        .with_successor_edge_for_test(successor_edge);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        assert_eq!(
            client.health(RequestIdV2::new([0xb7; 16]), UnixMillisV2::new(now + 1_000)),
            Err(AgentControlKernelClientErrorV2::Unavailable),
        );
        assert_eq!(client.authority().unwrap().edge, initial_edge);
        server.join().unwrap();
    }

    #[test]
    fn a_second_handshake_rejection_never_gets_a_third_attempt() {
        let directory = tempfile::tempdir().unwrap();
        let socket_path = directory.path().join("agent-kernel-retry-bound.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        let client_key = SigningKey::from_bytes(&[0x91; 32]);
        let server_key = SigningKey::from_bytes(&[0x92; 32]);
        let server_public_key = server_key.verifying_key().to_bytes();
        let task_authority_key = SigningKey::from_bytes(&[0x93; 32]);
        let task_authority_public_key = task_authority_key.verifying_key().to_bytes();
        let initial_edge = edge_at(&client_key, &server_key, 5, [6; 32], 7, 8);
        let successor_edge = edge_at(&client_key, &server_key, 6, [0x94; 32], 8, 9);
        let unexpected_edge = edge_at(&client_key, &server_key, 7, [0x95; 32], 9, 10);
        let observed_peer =
            PeerIdentityBindingV2::linux(501, 20, 42, 99, Digest32V2::new([0x96; 32])).unwrap();
        let server_observed_peer = observed_peer.clone();
        let client_public_key = client_key.verifying_key().to_bytes();
        let attempts = Arc::new(AtomicUsize::new(0));
        let server_attempts = Arc::clone(&attempts);
        let server = thread::spawn(move || {
            let io_deadline = Instant::now() + Duration::from_secs(2);
            for (index, edge) in [successor_edge, unexpected_edge].into_iter().enumerate() {
                let (mut stream, _) = listener.accept().unwrap();
                server_attempts.fetch_add(1, Ordering::SeqCst);
                let hello = read_handshake_frame(&mut stream, io_deadline).unwrap();
                let (_, server_hello) = V2ServerHandshake::accept_client_hello(
                    edge,
                    server_observed_peer.clone(),
                    &hello,
                    Nonce32V2::new([0x97 + index as u8; 32]),
                    StaticSecret::from([0x99 + index as u8; 32]),
                    client_public_key,
                    &server_key,
                )
                .unwrap();
                write_handshake_frame(&mut stream, &server_hello, io_deadline).unwrap();
            }
            thread::sleep(Duration::from_millis(100));
            listener.set_nonblocking(true).unwrap();
            assert!(matches!(
                listener.accept(),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
            ));
        });
        let mut client = SuiteOneAgentKernelClientV2::from_verified_deployment(
            initial_edge,
            BootIdV2::new([0x9b; 32]),
            observed_peer,
            client_key,
            server_public_key,
            derive_ed25519_key_id_v2(task_authority_public_key),
            task_authority_public_key,
        )
        .unwrap()
        .with_socket_path_for_test(socket_path)
        .with_successor_edge_for_test(successor_edge);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        assert_eq!(
            client.health(RequestIdV2::new([0x9c; 16]), UnixMillisV2::new(now + 2_000),),
            Err(AgentControlKernelClientErrorV2::Unavailable),
        );
        server.join().unwrap();
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
        assert_eq!(client.authority().unwrap().edge, successor_edge);
    }

    #[test]
    fn application_error_never_reloads_authority() {
        let directory = tempfile::tempdir().unwrap();
        let socket_path = directory.path().join("agent-kernel-application-error.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        let client_key = SigningKey::from_bytes(&[0xa1; 32]);
        let server_key = SigningKey::from_bytes(&[0xa2; 32]);
        let server_public_key = server_key.verifying_key().to_bytes();
        let task_authority_key = SigningKey::from_bytes(&[0xa3; 32]);
        let task_authority_public_key = task_authority_key.verifying_key().to_bytes();
        let initial_edge = edge_at(&client_key, &server_key, 5, [6; 32], 7, 8);
        let successor_edge = edge_at(&client_key, &server_key, 6, [0xa4; 32], 8, 9);
        let observed_peer =
            PeerIdentityBindingV2::linux(501, 20, 42, 99, Digest32V2::new([0xa5; 32])).unwrap();
        let server_observed_peer = observed_peer.clone();
        let client_public_key = client_key.verifying_key().to_bytes();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let io_deadline = Instant::now() + Duration::from_secs(2);
            let hello = read_handshake_frame(&mut stream, io_deadline).unwrap();
            let (pending, server_hello) = V2ServerHandshake::accept_client_hello(
                initial_edge,
                server_observed_peer,
                &hello,
                Nonce32V2::new([0xa6; 32]),
                StaticSecret::from([0xa7; 32]),
                client_public_key,
                &server_key,
            )
            .unwrap();
            write_handshake_frame(&mut stream, &server_hello, io_deadline).unwrap();
            let finish = read_handshake_frame(&mut stream, io_deadline).unwrap();
            let (accepted, mut session, _) = pending.accept_client_finish(&finish).unwrap();
            write_record_frame(&mut stream, &accepted, io_deadline).unwrap();
            let request_record = read_record_frame(&mut stream, io_deadline).unwrap();
            let opened = session.open_application_request(&request_record).unwrap();
            let response = KernelServiceApplicationResponseV2::error(
                EndpointRoleV2::AgentKernel,
                opened.request_id(),
                opened.operation_tag(),
                PublicStableCodeV2::ServiceUnavailable,
            )
            .unwrap();
            let plaintext = encode_kernel_service_application_response_v2(&response).unwrap();
            let record = session
                .seal_application_response(opened.request_id(), opened.operation_tag(), &plaintext)
                .unwrap();
            write_record_frame(&mut stream, &record, io_deadline).unwrap();
        });
        let mut client = SuiteOneAgentKernelClientV2::from_verified_deployment(
            initial_edge,
            BootIdV2::new([0xa8; 32]),
            observed_peer,
            client_key,
            server_public_key,
            derive_ed25519_key_id_v2(task_authority_public_key),
            task_authority_public_key,
        )
        .unwrap()
        .with_socket_path_for_test(socket_path)
        .with_successor_edge_for_test(successor_edge);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        assert_eq!(
            client.health(RequestIdV2::new([0xa9; 16]), UnixMillisV2::new(now + 2_000),),
            Err(AgentControlKernelClientErrorV2::Unavailable),
        );
        assert_eq!(client.authority().unwrap().edge, initial_edge);
        server.join().unwrap();
    }

    #[test]
    fn suite_one_health_uses_mutual_authentication_and_encrypted_records() {
        let directory = tempfile::tempdir().unwrap();
        let socket_path = directory.path().join("agent-kernel.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        let client_key = SigningKey::from_bytes(&[0x21; 32]);
        let server_key = SigningKey::from_bytes(&[0x22; 32]);
        let server_public_key = server_key.verifying_key().to_bytes();
        let task_authority_key = SigningKey::from_bytes(&[0x28; 32]);
        let task_authority_public_key = task_authority_key.verifying_key().to_bytes();
        let edge = edge(&client_key, &server_key);
        let observed_peer =
            PeerIdentityBindingV2::linux(501, 20, 42, 99, Digest32V2::new([0x23; 32])).unwrap();
        let server_observed_peer = observed_peer.clone();
        let client_public_key = client_key.verifying_key().to_bytes();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let io_deadline = Instant::now() + Duration::from_secs(2);
            let hello = read_handshake_frame(&mut stream, io_deadline).unwrap();
            let (pending, server_hello) = V2ServerHandshake::accept_client_hello(
                edge,
                server_observed_peer,
                &hello,
                Nonce32V2::new([0x24; 32]),
                StaticSecret::from([0x25; 32]),
                client_public_key,
                &server_key,
            )
            .unwrap();
            write_handshake_frame(&mut stream, &server_hello, io_deadline).unwrap();
            let finish = read_handshake_frame(&mut stream, io_deadline).unwrap();
            let (accepted, mut session, _) = pending.accept_client_finish(&finish).unwrap();
            write_record_frame(&mut stream, &accepted, io_deadline).unwrap();
            let request_record = read_record_frame(&mut stream, io_deadline).unwrap();
            let opened = session.open_application_request(&request_record).unwrap();
            let request = decode_kernel_service_application_request_v2(opened.plaintext()).unwrap();
            assert_eq!(request.role(), EndpointRoleV2::AgentKernel);
            assert_eq!(request.operation().tag(), 0);
            let health = encode_kernel_agent_health_response_v2(&KernelAgentHealthResponseV2::new(
                true,
                PublicServiceStateV2::Ready,
            ))
            .unwrap();
            let response = KernelServiceApplicationResponseV2::success(
                EndpointRoleV2::AgentKernel,
                opened.request_id(),
                opened.operation_tag(),
                health,
            )
            .unwrap();
            let plaintext = encode_kernel_service_application_response_v2(&response).unwrap();
            let response_record = session
                .seal_application_response(opened.request_id(), opened.operation_tag(), &plaintext)
                .unwrap();
            write_record_frame(&mut stream, &response_record, io_deadline).unwrap();
        });
        let mut client = SuiteOneAgentKernelClientV2::from_verified_deployment(
            edge,
            BootIdV2::new([0x26; 32]),
            observed_peer,
            client_key,
            server_public_key,
            derive_ed25519_key_id_v2(task_authority_public_key),
            task_authority_public_key,
        )
        .unwrap()
        .with_socket_path_for_test(socket_path);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        assert_eq!(
            client
                .health(RequestIdV2::new([0x27; 16]), UnixMillisV2::new(now + 2_000),)
                .unwrap(),
            PublicServiceStateV2::Ready,
        );
        server.join().unwrap();
    }

    #[test]
    fn suite_one_cancel_sends_exact_authority_and_accepts_only_authenticated_cancelled() {
        let directory = tempfile::tempdir().unwrap();
        let socket_path = directory.path().join("agent-kernel-cancel.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        let client_key = SigningKey::from_bytes(&[0x51; 32]);
        let server_key = SigningKey::from_bytes(&[0x52; 32]);
        let server_public_key = server_key.verifying_key().to_bytes();
        let task_authority_key = SigningKey::from_bytes(&[0x53; 32]);
        let task_authority_public_key = task_authority_key.verifying_key().to_bytes();
        let edge = edge(&client_key, &server_key);
        let observed_peer =
            PeerIdentityBindingV2::linux(501, 20, 42, 99, Digest32V2::new([0x54; 32])).unwrap();
        let server_observed_peer = observed_peer.clone();
        let client_public_key = client_key.verifying_key().to_bytes();
        let durable_task_id = DurableTaskIdV2::new([0x55; 32]);
        let preparation = NewTaskPreparationHandleV2::from_authority_entropy([0x56; 32]).unwrap();
        let unsigned = UnsignedDurableTaskCorrelationV2::new(
            Digest32V2::new([1; 32]),
            Digest32V2::new([6; 32]),
            7,
            durable_task_id,
            ServiceIdentityV2::new([2; 32]),
            BootIdV2::new([0x57; 32]),
            BootIdV2::new([4; 32]),
            BootIdV2::new([0x58; 32]),
            UnixMillisV2::new(1),
            UnixMillisV2::new(u64::MAX - 1),
            UnixMillisV2::new(u64::MAX),
        )
        .unwrap();
        let correlation =
            SignedDurableTaskCorrelationV2::sign(unsigned, &task_authority_key).unwrap();
        let correlation_digest = correlation.correlation_digest().unwrap();
        let expected_correlation = correlation.clone();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let io_deadline = Instant::now() + Duration::from_secs(2);
            let hello = read_handshake_frame(&mut stream, io_deadline).unwrap();
            let (pending, server_hello) = V2ServerHandshake::accept_client_hello(
                edge,
                server_observed_peer,
                &hello,
                Nonce32V2::new([0x59; 32]),
                StaticSecret::from([0x5a; 32]),
                client_public_key,
                &server_key,
            )
            .unwrap();
            write_handshake_frame(&mut stream, &server_hello, io_deadline).unwrap();
            let finish = read_handshake_frame(&mut stream, io_deadline).unwrap();
            let (accepted, mut session, _) = pending.accept_client_finish(&finish).unwrap();
            write_record_frame(&mut stream, &accepted, io_deadline).unwrap();
            let request_record = read_record_frame(&mut stream, io_deadline).unwrap();
            let opened = session.open_application_request(&request_record).unwrap();
            let request = decode_kernel_service_application_request_v2(opened.plaintext()).unwrap();
            let KernelServiceOperationV2::Agent(KernelAgentOperationV2::CancelKernelTask(cancel)) =
                request.operation()
            else {
                panic!("expected exact cancel operation");
            };
            assert_eq!(cancel.preparation(), preparation);
            assert_eq!(cancel.correlation(), &expected_correlation);
            let cancelled = encode_cancel_kernel_task_response_v2(
                &CancelKernelTaskResponseV2::new(PublicTaskStatusV2::Cancelled),
            )
            .unwrap();
            let response = KernelServiceApplicationResponseV2::success(
                EndpointRoleV2::AgentKernel,
                opened.request_id(),
                opened.operation_tag(),
                cancelled,
            )
            .unwrap();
            let plaintext = encode_kernel_service_application_response_v2(&response).unwrap();
            let response_record = session
                .seal_application_response(opened.request_id(), opened.operation_tag(), &plaintext)
                .unwrap();
            write_record_frame(&mut stream, &response_record, io_deadline).unwrap();
        });
        let mut client = SuiteOneAgentKernelClientV2::from_verified_deployment(
            edge,
            BootIdV2::new([0x57; 32]),
            observed_peer,
            client_key,
            server_public_key,
            derive_ed25519_key_id_v2(task_authority_public_key),
            task_authority_public_key,
        )
        .unwrap()
        .with_socket_path_for_test(socket_path);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let request = KernelTaskCancellationRequestV2::from_pending(
            RequestIdV2::new([0x5b; 16]),
            durable_task_id,
            correlation_digest,
            1,
            preparation,
            correlation,
            UnixMillisV2::new(now + 2_000),
        )
        .unwrap();

        assert!(client.cancel_task(request).is_ok());
        server.join().unwrap();
    }

    #[test]
    fn preparation_response_requires_the_exact_signed_deployment_and_boot_binding() {
        let client_key = SigningKey::from_bytes(&[0x31; 32]);
        let server_key = SigningKey::from_bytes(&[0x32; 32]);
        let task_authority_key = SigningKey::from_bytes(&[0x33; 32]);
        let task_authority_public_key = task_authority_key.verifying_key().to_bytes();
        let observed_peer =
            PeerIdentityBindingV2::linux(501, 20, 42, 99, Digest32V2::new([0x34; 32])).unwrap();
        let client = SuiteOneAgentKernelClientV2::from_verified_deployment(
            edge(&client_key, &server_key),
            BootIdV2::new([0x35; 32]),
            observed_peer,
            client_key,
            server_key.verifying_key().to_bytes(),
            derive_ed25519_key_id_v2(task_authority_public_key),
            task_authority_public_key,
        )
        .unwrap();
        let request = KernelTaskPreparationRequestV2::from_authenticated_control(
            RequestIdV2::new([0x36; 16]),
            Nonce32V2::new([0x37; 32]),
            BootIdV2::new([0x38; 32]),
            UnixMillisV2::new(500),
        )
        .unwrap();
        let unsigned = UnsignedDurableTaskCorrelationV2::new(
            Digest32V2::new([1; 32]),
            Digest32V2::new([6; 32]),
            7,
            DurableTaskIdV2::new([0x40; 32]),
            ServiceIdentityV2::new([2; 32]),
            BootIdV2::new([0x35; 32]),
            BootIdV2::new([4; 32]),
            request.machine_boot_id(),
            UnixMillisV2::new(90),
            UnixMillisV2::new(1_000),
            UnixMillisV2::new(2_000),
        )
        .unwrap();
        let response = PrepareNewIngressResponseV2::Prepared {
            preparation: NewTaskPreparationHandleV2::from_authority_entropy([0x41; 32]).unwrap(),
            correlation: SignedDurableTaskCorrelationV2::sign(unsigned, &task_authority_key)
                .unwrap(),
            ingress_transfer: KernelIngressBootstrapTransferCapabilityV2::from_authority_entropy(
                [0x42; 32],
            )
            .unwrap(),
        };
        let expected_correlation = match &response {
            PrepareNewIngressResponseV2::Prepared { correlation, .. }
            | PrepareNewIngressResponseV2::Reconciled { correlation, .. } => correlation.clone(),
        };
        let authority = client.authority().unwrap();
        let replacement_task_authority = SigningKey::from_bytes(&[0x44; 32]);
        let replacement_task_authority_public_key =
            replacement_task_authority.verifying_key().to_bytes();
        *client.shared.authority.write().unwrap() = Arc::new(AgentKernelGenerationAuthorityV2 {
            edge: authority.edge,
            task_authority_key_id: derive_ed25519_key_id_v2(replacement_task_authority_public_key),
            task_authority_public_key: replacement_task_authority_public_key,
            continuity: None,
        });
        assert!(client
            .verify_preparation_response(
                request,
                response.clone(),
                UnixMillisV2::new(100),
                &authority,
            )
            .is_ok_and(|verified| {
                verified.kernel_preparation()
                    == NewTaskPreparationHandleV2::from_authority_entropy([0x41; 32])
                    && verified.kernel_correlation() == Some(&expected_correlation)
            }));
        assert_eq!(
            client.verify_preparation_response(
                request,
                response,
                UnixMillisV2::new(100),
                &client.authority().unwrap(),
            ),
            Err(AgentControlKernelClientErrorV2::Unavailable),
        );

        let wrong_boot_unsigned = UnsignedDurableTaskCorrelationV2::new(
            Digest32V2::new([1; 32]),
            Digest32V2::new([6; 32]),
            7,
            DurableTaskIdV2::new([0x40; 32]),
            ServiceIdentityV2::new([2; 32]),
            BootIdV2::new([0x43; 32]),
            BootIdV2::new([4; 32]),
            request.machine_boot_id(),
            UnixMillisV2::new(90),
            UnixMillisV2::new(1_000),
            UnixMillisV2::new(2_000),
        )
        .unwrap();
        let wrong = PrepareNewIngressResponseV2::Prepared {
            preparation: NewTaskPreparationHandleV2::from_authority_entropy([0x41; 32]).unwrap(),
            correlation: SignedDurableTaskCorrelationV2::sign(
                wrong_boot_unsigned,
                &task_authority_key,
            )
            .unwrap(),
            ingress_transfer: KernelIngressBootstrapTransferCapabilityV2::from_authority_entropy(
                [0x42; 32],
            )
            .unwrap(),
        };
        assert_eq!(
            client.verify_preparation_response(request, wrong, UnixMillisV2::new(100), &authority,),
            Err(AgentControlKernelClientErrorV2::Unavailable)
        );
    }

    #[derive(Clone, Copy)]
    enum ServerHelloTerminalFailureV2 {
        MalformedFrame,
        MalformedCbor,
        InvalidSignature,
    }

    #[test]
    fn malformed_server_hello_frame_never_reloads_authority() {
        assert_terminal_server_hello_failure_does_not_reload(
            ServerHelloTerminalFailureV2::MalformedFrame,
        );
    }

    #[test]
    fn malformed_server_hello_cbor_never_reloads_authority() {
        assert_terminal_server_hello_failure_does_not_reload(
            ServerHelloTerminalFailureV2::MalformedCbor,
        );
    }

    #[test]
    fn invalid_server_hello_signature_never_reloads_authority() {
        assert_terminal_server_hello_failure_does_not_reload(
            ServerHelloTerminalFailureV2::InvalidSignature,
        );
    }

    fn assert_terminal_server_hello_failure_does_not_reload(failure: ServerHelloTerminalFailureV2) {
        let directory = tempfile::tempdir().unwrap();
        let socket_path = directory.path().join("agent-kernel-terminal-hello.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        let client_key = SigningKey::from_bytes(&[0xc1; 32]);
        let server_key = SigningKey::from_bytes(&[0xc2; 32]);
        let server_public_key = server_key.verifying_key().to_bytes();
        let task_authority_key = SigningKey::from_bytes(&[0xc3; 32]);
        let task_authority_public_key = task_authority_key.verifying_key().to_bytes();
        let initial_edge = edge_at(&client_key, &server_key, 5, [6; 32], 7, 8);
        let successor_edge = edge_at(&client_key, &server_key, 6, [0xc4; 32], 8, 9);
        let observed_peer =
            PeerIdentityBindingV2::linux(501, 20, 42, 99, Digest32V2::new([0xc5; 32])).unwrap();
        let server_observed_peer = observed_peer.clone();
        let client_public_key = client_key.verifying_key().to_bytes();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let io_deadline = Instant::now() + Duration::from_secs(1);
            let hello = read_handshake_frame(&mut stream, io_deadline).unwrap();
            if matches!(failure, ServerHelloTerminalFailureV2::MalformedFrame) {
                stream
                    .write_all(&[0; HANDSHAKE_FRAME_HEADER_BYTES_V2])
                    .unwrap();
                stream.flush().unwrap();
                return;
            }
            let (_, mut server_hello) = V2ServerHandshake::accept_client_hello(
                initial_edge,
                server_observed_peer,
                &hello,
                Nonce32V2::new([0xc6; 32]),
                StaticSecret::from([0xc7; 32]),
                client_public_key,
                &server_key,
            )
            .unwrap();
            match failure {
                ServerHelloTerminalFailureV2::MalformedFrame => unreachable!(),
                ServerHelloTerminalFailureV2::MalformedCbor => {
                    server_hello[HANDSHAKE_FRAME_HEADER_BYTES_V2] = 0xff;
                }
                ServerHelloTerminalFailureV2::InvalidSignature => {
                    *server_hello.last_mut().unwrap() ^= 1;
                }
            }
            write_handshake_frame(&mut stream, &server_hello, io_deadline).unwrap();
        });
        let mut client = SuiteOneAgentKernelClientV2::from_verified_deployment(
            initial_edge,
            BootIdV2::new([0xc8; 32]),
            observed_peer,
            client_key,
            server_public_key,
            derive_ed25519_key_id_v2(task_authority_public_key),
            task_authority_public_key,
        )
        .unwrap()
        .with_socket_path_for_test(socket_path)
        .with_successor_edge_for_test(successor_edge);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        assert_eq!(
            client.health(RequestIdV2::new([0xc9; 16]), UnixMillisV2::new(now + 1_000)),
            Err(AgentControlKernelClientErrorV2::Unavailable),
        );
        assert_eq!(client.authority().unwrap().edge, initial_edge);
        server.join().unwrap();
    }

    fn edge(client_key: &SigningKey, server_key: &SigningKey) -> KernelServiceHandshakeEdgeV2 {
        edge_at(client_key, server_key, 5, [6; 32], 7, 8)
    }

    fn edge_at(
        client_key: &SigningKey,
        server_key: &SigningKey,
        manifest_sequence: u64,
        manifest_digest: [u8; 32],
        deployment_generation: u64,
        effect_fence: u64,
    ) -> KernelServiceHandshakeEdgeV2 {
        KernelServiceHandshakeEdgeV2::from_verified_deployment(
            EndpointRoleV2::AgentKernel,
            Digest32V2::new([1; 32]),
            ServiceIdentityV2::new([2; 32]),
            ServiceIdentityV2::new([3; 32]),
            derive_ed25519_key_id_v2(client_key.verifying_key().to_bytes()),
            derive_ed25519_key_id_v2(server_key.verifying_key().to_bytes()),
            BootIdV2::new([4; 32]),
            manifest_sequence,
            Digest32V2::new(manifest_digest),
            deployment_generation,
            effect_fence,
            Digest32V2::new([9; 32]),
            Digest32V2::new([10; 32]),
            Digest32V2::new([11; 32]),
            Digest32V2::new([12; 32]),
            Digest32V2::new([13; 32]),
            Digest32V2::new([14; 32]),
        )
        .unwrap()
    }
}
