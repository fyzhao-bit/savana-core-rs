use std::io::{Read as _, Write as _};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use savana_kernel_protocol::v2::{
    decode_abort_input_response_v2, decode_append_input_chunk_response_v2,
    decode_append_parser_worker_page_frame_response_v2, decode_authenticate_ingress_ui_response_v2,
    decode_begin_input_response_v2, decode_commit_input_settlement_response_v2,
    decode_commit_parser_worker_result_response_v2, decode_finalize_input_response_v2,
    decode_get_input_status_response_v2, decode_kernel_ingress_health_response_v2,
    decode_kernel_service_application_request_v2, decode_kernel_service_application_response_v2,
    decode_prepare_ingress_ui_authentication_response_v2,
    decode_register_parser_worker_job_response_v2, encode_kernel_service_application_request_v2,
    AbortInputRequestV2, AbortInputResponseV2, AppendInputChunkRequestV2,
    AppendInputChunkResponseV2, AppendParserWorkerPageFrameRequestV2,
    AppendParserWorkerPageFrameResponseV2, AuthenticateIngressUiRequestV2,
    AuthenticateIngressUiResponseV2, BeginInputRequestV2, BeginInputResponseV2, BootIdV2,
    CommitInputSettlementRequestV2, CommitInputSettlementResponseV2,
    CommitParserWorkerResultRequestV2, CommitParserWorkerResultResponseV2, EndpointRoleV2,
    FinalizeInputRequestV2, FinalizeInputResponseV2, GetInputStatusRequestV2,
    GetInputStatusResponseV2, KernelIngressHealthRequestV2, KernelIngressHealthResponseV2,
    KernelIngressOperationV2, KernelServiceApplicationRequestV2,
    KernelServiceApplicationResponseBodyV2, KernelServiceHandshakeEdgeV2, KernelServiceOperationV2,
    Nonce32V2, PeerIdentityBindingV2, PrepareIngressUiAuthenticationRequestV2,
    PrepareIngressUiAuthenticationResponseV2, PublicStableCodeV2, RegisterParserWorkerJobRequestV2,
    RegisterParserWorkerJobResponseV2, RequestIdV2, UnixMillisV2, V2ClientHandshake,
    V2ServerHelloAcceptanceErrorV2, HANDSHAKE_FRAME_HEADER_BYTES_V2, MAX_HANDSHAKE_BODY_BYTES_V2,
    MAX_RECORD_CIPHERTEXT_BYTES_V2, MAX_RECORD_HEADER_BYTES_V2, RECORD_FRAME_HEADER_BYTES_V2,
};
use savana_policy_core::v2::{
    ClosedServiceEdgeIdV2, ClosedServiceIdV2, ServiceDeploymentLockV2, ServiceEdgeLockV2,
    VerifiedDaemonStartupV2,
};
use sha2::{Digest as _, Sha256};
use x25519_dalek::StaticSecret;

const INGRESS_KERNEL_SOCKET_PATH_V2: &str = "/run/savana/kerneld/ingressd/kerneld.sock";
const HANDSHAKE_MAGIC_V2: &[u8; 8] = b"SAVANA2\0";
const RECORD_MAGIC_V2: &[u8; 4] = b"SV2R";
const MAX_CONNECTION_DURATION_V2: Duration = Duration::from_secs(5);
const REQUEST_ID_DOMAIN_V2: &[u8] = b"SAVANA_INGRESSD_KERNEL_REQUEST_ID_V2\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum IngressKernelClientErrorV2 {
    #[error("ingress kernel request deadline was exceeded")]
    DeadlineExceeded,
    #[error("ingress kernel service is unavailable")]
    Unavailable,
}

#[derive(Clone)]
pub struct SuiteOneIngressKernelClientV2 {
    shared: Arc<IngressKernelClientSharedV2>,
}

struct IngressKernelClientSharedV2 {
    authority: RwLock<Arc<IngressKernelGenerationAuthorityV2>>,
    reload_lock: Mutex<()>,
    client_boot_id: BootIdV2,
    server_boot_id: Option<BootIdV2>,
    expected_observed_peer: PeerIdentityBindingV2,
    client_signing_key: SigningKey,
    server_public_key: [u8; 32],
    socket_path: PathBuf,
    startup_loader: Option<Arc<VerifiedIngressKernelStartupLoaderV2>>,
    #[cfg(test)]
    successor_edge_for_test: Option<KernelServiceHandshakeEdgeV2>,
}

type VerifiedIngressKernelStartupLoaderV2 =
    dyn Fn() -> Result<VerifiedDaemonStartupV2, ()> + Send + Sync;

struct IngressKernelGenerationAuthorityV2 {
    edge: KernelServiceHandshakeEdgeV2,
    continuity: Option<IngressKernelContinuityV2>,
}

#[derive(Clone, PartialEq, Eq)]
struct IngressKernelContinuityV2 {
    installation_id: savana_kernel_protocol::v2::Digest32V2,
    active_state_manifest_sequence: u64,
    active_state_manifest_digest: savana_kernel_protocol::v2::Digest32V2,
    deployment_generation: u64,
    effect_fence_epoch: u64,
    protocol_abi_digest: savana_kernel_protocol::v2::Digest32V2,
    release_identity_digest: savana_kernel_protocol::v2::Digest32V2,
    model_set_identity_digest: savana_kernel_protocol::v2::Digest32V2,
    resource_profile_identity_digest: savana_kernel_protocol::v2::Digest32V2,
    approval_lock_identity_digest: savana_kernel_protocol::v2::Digest32V2,
    planner_lock_identity_digest: savana_kernel_protocol::v2::Digest32V2,
    executor_key_lock_identity_digest: savana_kernel_protocol::v2::Digest32V2,
    kernel_envelope_signing_key_id: savana_kernel_protocol::v2::Ed25519KeyIdV2,
    client_lock: ServiceDeploymentLockV2,
    server_lock: ServiceDeploymentLockV2,
    edge_lock: ServiceEdgeLockV2,
}

impl IngressKernelContinuityV2 {
    fn from_startup(startup: &VerifiedDaemonStartupV2) -> Result<Self, IngressKernelClientErrorV2> {
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
                .service_lock(ClosedServiceIdV2::Ingressd)
                .ok_or(IngressKernelClientErrorV2::Unavailable)?,
            server_lock: *startup
                .service_lock(ClosedServiceIdV2::Kerneld)
                .ok_or(IngressKernelClientErrorV2::Unavailable)?,
            edge_lock: startup
                .edge_lock(ClosedServiceEdgeIdV2::IngressKernel)
                .cloned()
                .ok_or(IngressKernelClientErrorV2::Unavailable)?,
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

impl std::fmt::Debug for SuiteOneIngressKernelClientV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SuiteOneIngressKernelClientV2(<deployment-bound-keys-redacted>)")
    }
}

impl SuiteOneIngressKernelClientV2 {
    pub fn from_verified_deployment(
        edge: KernelServiceHandshakeEdgeV2,
        client_boot_id: BootIdV2,
        expected_observed_peer: PeerIdentityBindingV2,
        client_signing_key: SigningKey,
        server_public_key: [u8; 32],
    ) -> Result<Self, IngressKernelClientErrorV2> {
        if edge.role() != EndpointRoleV2::IngressKernel
            || client_boot_id.as_bytes() == &[0; 32]
            || server_public_key == [0; 32]
        {
            return Err(IngressKernelClientErrorV2::Unavailable);
        }
        Ok(Self {
            shared: Arc::new(IngressKernelClientSharedV2 {
                authority: RwLock::new(Arc::new(IngressKernelGenerationAuthorityV2 {
                    edge,
                    continuity: None,
                })),
                reload_lock: Mutex::new(()),
                client_boot_id,
                server_boot_id: None,
                expected_observed_peer,
                client_signing_key,
                server_public_key,
                socket_path: PathBuf::from(INGRESS_KERNEL_SOCKET_PATH_V2),
                startup_loader: None,
                #[cfg(test)]
                successor_edge_for_test: None,
            }),
        })
    }

    pub(crate) fn from_verified_startup<F>(
        startup: &VerifiedDaemonStartupV2,
        client_boot_id: BootIdV2,
        server_boot_id: BootIdV2,
        expected_observed_peer: PeerIdentityBindingV2,
        client_signing_key: SigningKey,
        server_public_key: [u8; 32],
        startup_loader: F,
    ) -> Result<Self, IngressKernelClientErrorV2>
    where
        F: Fn() -> Result<VerifiedDaemonStartupV2, ()> + Send + Sync + 'static,
    {
        let edge = startup
            .kernel_service_handshake_edge(ClosedServiceEdgeIdV2::IngressKernel, server_boot_id)
            .map_err(|_| IngressKernelClientErrorV2::Unavailable)?;
        let continuity = IngressKernelContinuityV2::from_startup(startup)?;
        if continuity.edge_lock.client_handshake_key_id
            != savana_kernel_protocol::v2::derive_ed25519_key_id_v2(
                client_signing_key.verifying_key().to_bytes(),
            )
            || continuity.edge_lock.server_handshake_key_id
                != savana_kernel_protocol::v2::derive_ed25519_key_id_v2(server_public_key)
        {
            return Err(IngressKernelClientErrorV2::Unavailable);
        }
        let mut client = Self::from_verified_deployment(
            edge,
            client_boot_id,
            expected_observed_peer,
            client_signing_key,
            server_public_key,
        )?;
        let shared =
            Arc::get_mut(&mut client.shared).ok_or(IngressKernelClientErrorV2::Unavailable)?;
        shared.server_boot_id = Some(server_boot_id);
        shared.startup_loader = Some(Arc::new(startup_loader));
        shared.authority = RwLock::new(Arc::new(IngressKernelGenerationAuthorityV2 {
            edge,
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
        socket_path: PathBuf,
        startup_loader: F,
    ) -> Result<Self, IngressKernelClientErrorV2>
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
            startup_loader,
        )?;
        Arc::get_mut(&mut client.shared)
            .ok_or(IngressKernelClientErrorV2::Unavailable)?
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
    ) -> Result<Arc<IngressKernelGenerationAuthorityV2>, IngressKernelClientErrorV2> {
        self.shared
            .authority
            .read()
            .map(|authority| Arc::clone(&authority))
            .map_err(|_| IngressKernelClientErrorV2::Unavailable)
    }

    pub(crate) fn reload_verified_authority(&self) -> Result<(), IngressKernelClientErrorV2> {
        let current = self.authority()?;
        self.reload_after_handshake_rejection(&current)
    }

    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn reload_verified_authority_for_test_support(
        &self,
    ) -> Result<(), IngressKernelClientErrorV2> {
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

    fn reload_after_handshake_rejection(
        &self,
        failed: &Arc<IngressKernelGenerationAuthorityV2>,
    ) -> Result<(), IngressKernelClientErrorV2> {
        let _reload = self
            .shared
            .reload_lock
            .lock()
            .map_err(|_| IngressKernelClientErrorV2::Unavailable)?;
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
                .map_err(|_| IngressKernelClientErrorV2::Unavailable)?;
            if Arc::ptr_eq(&active, failed) {
                *active = Arc::new(IngressKernelGenerationAuthorityV2 {
                    edge,
                    continuity: None,
                });
            }
            return Ok(());
        }
        let loader = self
            .shared
            .startup_loader
            .as_ref()
            .ok_or(IngressKernelClientErrorV2::Unavailable)?;
        let startup = loader().map_err(|()| IngressKernelClientErrorV2::Unavailable)?;
        let candidate = self.authority_from_startup(&startup)?;
        let mut active = self
            .shared
            .authority
            .write()
            .map_err(|_| IngressKernelClientErrorV2::Unavailable)?;
        if !Arc::ptr_eq(&active, failed) {
            return Ok(());
        }
        let current_continuity = active
            .continuity
            .as_ref()
            .ok_or(IngressKernelClientErrorV2::Unavailable)?;
        let candidate_continuity = candidate
            .continuity
            .as_ref()
            .ok_or(IngressKernelClientErrorV2::Unavailable)?;
        if candidate_continuity == current_continuity {
            return Ok(());
        }
        if !candidate_continuity.is_exact_successor_of(current_continuity) {
            return Err(IngressKernelClientErrorV2::Unavailable);
        }
        *active = Arc::new(candidate);
        Ok(())
    }

    fn authority_from_startup(
        &self,
        startup: &VerifiedDaemonStartupV2,
    ) -> Result<IngressKernelGenerationAuthorityV2, IngressKernelClientErrorV2> {
        let continuity = IngressKernelContinuityV2::from_startup(startup)?;
        if continuity.edge_lock.client_handshake_key_id
            != savana_kernel_protocol::v2::derive_ed25519_key_id_v2(
                self.shared.client_signing_key.verifying_key().to_bytes(),
            )
            || continuity.edge_lock.server_handshake_key_id
                != savana_kernel_protocol::v2::derive_ed25519_key_id_v2(
                    self.shared.server_public_key,
                )
        {
            return Err(IngressKernelClientErrorV2::Unavailable);
        }
        let edge = startup
            .kernel_service_handshake_edge(
                ClosedServiceEdgeIdV2::IngressKernel,
                self.shared
                    .server_boot_id
                    .ok_or(IngressKernelClientErrorV2::Unavailable)?,
            )
            .map_err(|_| IngressKernelClientErrorV2::Unavailable)?;
        Ok(IngressKernelGenerationAuthorityV2 {
            edge,
            continuity: Some(continuity),
        })
    }

    pub fn health(
        &self,
        deadline: UnixMillisV2,
    ) -> Result<KernelIngressHealthResponseV2, IngressKernelClientErrorV2> {
        let body = self.exchange(
            KernelIngressOperationV2::Health(KernelIngressHealthRequestV2),
            deadline,
        )?;
        decode_kernel_ingress_health_response_v2(&body)
            .map_err(|_| IngressKernelClientErrorV2::Unavailable)
    }

    pub fn prepare_ui_authentication(
        &self,
        request: PrepareIngressUiAuthenticationRequestV2,
        deadline: UnixMillisV2,
    ) -> Result<PrepareIngressUiAuthenticationResponseV2, IngressKernelClientErrorV2> {
        let body = self.exchange(
            KernelIngressOperationV2::PrepareIngressUiAuthentication(request),
            deadline,
        )?;
        decode_prepare_ingress_ui_authentication_response_v2(&body)
            .map_err(|_| IngressKernelClientErrorV2::Unavailable)
    }

    pub fn authenticate_ui(
        &self,
        request: AuthenticateIngressUiRequestV2,
        deadline: UnixMillisV2,
    ) -> Result<AuthenticateIngressUiResponseV2, IngressKernelClientErrorV2> {
        let body = self.exchange(
            KernelIngressOperationV2::AuthenticateIngressUi(request),
            deadline,
        )?;
        decode_authenticate_ingress_ui_response_v2(&body)
            .map_err(|_| IngressKernelClientErrorV2::Unavailable)
    }

    pub fn establish_task_authorization(
        &self,
        request: savana_kernel_protocol::v2::EstablishTaskAuthorizationRequestV2,
        deadline: UnixMillisV2,
    ) -> Result<
        savana_kernel_protocol::v2::EstablishTaskAuthorizationResponseV2,
        IngressKernelClientErrorV2,
    > {
        let body = self.exchange(
            KernelIngressOperationV2::EstablishTaskAuthorization(request),
            deadline,
        )?;
        savana_kernel_protocol::v2::decode_establish_task_authorization_response_v2(&body)
            .map_err(|_| IngressKernelClientErrorV2::Unavailable)
    }

    pub fn prepare_task_authorization_approval(
        &self,
        request: savana_kernel_protocol::v2::PrepareTaskAuthorizationApprovalRequestV2,
        deadline: UnixMillisV2,
    ) -> Result<
        savana_kernel_protocol::v2::PrepareTaskAuthorizationApprovalResponseV2,
        IngressKernelClientErrorV2,
    > {
        let body = self.exchange(
            KernelIngressOperationV2::PrepareTaskAuthorizationApproval(request),
            deadline,
        )?;
        savana_kernel_protocol::v2::decode_prepare_task_authorization_approval_response_v2(&body)
            .map_err(|_| IngressKernelClientErrorV2::Unavailable)
    }
    pub fn commit_task_authorization_approval(
        &self,
        request: savana_kernel_protocol::v2::CommitTaskAuthorizationApprovalRequestV2,
        deadline: UnixMillisV2,
    ) -> Result<
        savana_kernel_protocol::v2::EstablishTaskAuthorizationResponseV2,
        IngressKernelClientErrorV2,
    > {
        let body = self.exchange(
            KernelIngressOperationV2::CommitTaskAuthorizationApproval(request),
            deadline,
        )?;
        savana_kernel_protocol::v2::decode_establish_task_authorization_response_v2(&body)
            .map_err(|_| IngressKernelClientErrorV2::Unavailable)
    }

    pub fn revoke_task_authorization(
        &self,
        request: savana_kernel_protocol::v2::RevokeTaskAuthorizationRequestV2,
        deadline: UnixMillisV2,
    ) -> Result<
        savana_kernel_protocol::v2::RevokeTaskAuthorizationResponseV2,
        IngressKernelClientErrorV2,
    > {
        let body = self.exchange(
            KernelIngressOperationV2::RevokeTaskAuthorization(request),
            deadline,
        )?;
        savana_kernel_protocol::v2::decode_revoke_task_authorization_response_v2(&body)
            .map_err(|_| IngressKernelClientErrorV2::Unavailable)
    }

    pub fn recover_task_authorization(
        &self,
        request: savana_kernel_protocol::v2::RecoverTaskAuthorizationRequestV2,
        deadline: UnixMillisV2,
    ) -> Result<
        savana_kernel_protocol::v2::RecoverTaskAuthorizationResponseV2,
        IngressKernelClientErrorV2,
    > {
        let body = self.exchange(
            KernelIngressOperationV2::RecoverTaskAuthorization(request),
            deadline,
        )?;
        savana_kernel_protocol::v2::decode_recover_task_authorization_response_v2(&body)
            .map_err(|_| IngressKernelClientErrorV2::Unavailable)
    }

    pub fn task_authorization_context(
        &self,
        request: savana_kernel_protocol::v2::GetTaskAuthorizationContextRequestV2,
        deadline: UnixMillisV2,
    ) -> Result<savana_kernel_protocol::v2::TaskAuthorizationContextV2, IngressKernelClientErrorV2>
    {
        let body = self.exchange(
            KernelIngressOperationV2::GetTaskAuthorizationContext(request),
            deadline,
        )?;
        savana_kernel_protocol::v2::decode_task_authorization_context_v2(&body)
            .map_err(|_| IngressKernelClientErrorV2::Unavailable)
    }

    pub fn begin_input(
        &self,
        request: BeginInputRequestV2,
        deadline: UnixMillisV2,
    ) -> Result<BeginInputResponseV2, IngressKernelClientErrorV2> {
        let body = self.exchange(KernelIngressOperationV2::BeginInput(request), deadline)?;
        decode_begin_input_response_v2(&body).map_err(|_| IngressKernelClientErrorV2::Unavailable)
    }

    pub fn append_input_chunk(
        &self,
        request: AppendInputChunkRequestV2,
        deadline: UnixMillisV2,
    ) -> Result<AppendInputChunkResponseV2, IngressKernelClientErrorV2> {
        let body = self.exchange(
            KernelIngressOperationV2::AppendInputChunk(request),
            deadline,
        )?;
        decode_append_input_chunk_response_v2(&body)
            .map_err(|_| IngressKernelClientErrorV2::Unavailable)
    }

    pub fn finalize_input(
        &self,
        request: FinalizeInputRequestV2,
        deadline: UnixMillisV2,
    ) -> Result<FinalizeInputResponseV2, IngressKernelClientErrorV2> {
        let body = self.exchange(KernelIngressOperationV2::FinalizeInput(request), deadline)?;
        decode_finalize_input_response_v2(&body)
            .map_err(|_| IngressKernelClientErrorV2::Unavailable)
    }

    pub fn commit_input_settlement(
        &self,
        request: CommitInputSettlementRequestV2,
        deadline: UnixMillisV2,
    ) -> Result<CommitInputSettlementResponseV2, IngressKernelClientErrorV2> {
        let body = self.exchange(
            KernelIngressOperationV2::CommitInputSettlement(request),
            deadline,
        )?;
        decode_commit_input_settlement_response_v2(&body)
            .map_err(|_| IngressKernelClientErrorV2::Unavailable)
    }

    pub fn abort_input(
        &self,
        request: AbortInputRequestV2,
        deadline: UnixMillisV2,
    ) -> Result<AbortInputResponseV2, IngressKernelClientErrorV2> {
        let body = self.exchange(KernelIngressOperationV2::AbortInput(request), deadline)?;
        decode_abort_input_response_v2(&body).map_err(|_| IngressKernelClientErrorV2::Unavailable)
    }

    pub fn get_input_status(
        &self,
        request: GetInputStatusRequestV2,
        deadline: UnixMillisV2,
    ) -> Result<GetInputStatusResponseV2, IngressKernelClientErrorV2> {
        let body = self.exchange(KernelIngressOperationV2::GetInputStatus(request), deadline)?;
        decode_get_input_status_response_v2(&body)
            .map_err(|_| IngressKernelClientErrorV2::Unavailable)
    }

    pub fn register_parser_worker_job(
        &self,
        request: RegisterParserWorkerJobRequestV2,
        deadline: UnixMillisV2,
    ) -> Result<RegisterParserWorkerJobResponseV2, IngressKernelClientErrorV2> {
        let body = self.exchange(
            KernelIngressOperationV2::RegisterParserWorkerJob(request),
            deadline,
        )?;
        decode_register_parser_worker_job_response_v2(&body)
            .map_err(|_| IngressKernelClientErrorV2::Unavailable)
    }

    pub fn append_parser_worker_page_frame(
        &self,
        request: AppendParserWorkerPageFrameRequestV2,
        deadline: UnixMillisV2,
    ) -> Result<AppendParserWorkerPageFrameResponseV2, IngressKernelClientErrorV2> {
        let body = self.exchange(
            KernelIngressOperationV2::AppendParserWorkerPageFrame(request),
            deadline,
        )?;
        decode_append_parser_worker_page_frame_response_v2(&body)
            .map_err(|_| IngressKernelClientErrorV2::Unavailable)
    }

    pub fn commit_parser_worker_result(
        &self,
        request: CommitParserWorkerResultRequestV2,
        deadline: UnixMillisV2,
    ) -> Result<CommitParserWorkerResultResponseV2, IngressKernelClientErrorV2> {
        let body = self.exchange(
            KernelIngressOperationV2::CommitParserWorkerResult(request),
            deadline,
        )?;
        decode_commit_parser_worker_result_response_v2(&body)
            .map_err(|_| IngressKernelClientErrorV2::Unavailable)
    }

    fn exchange(
        &self,
        operation: KernelIngressOperationV2,
        deadline: UnixMillisV2,
    ) -> Result<Vec<u8>, IngressKernelClientErrorV2> {
        let io_deadline = io_deadline(deadline)?;
        let provisional = KernelServiceApplicationRequestV2::new(
            EndpointRoleV2::IngressKernel,
            RequestIdV2::new([1; 16]),
            UnixMillisV2::new(1),
            KernelServiceOperationV2::ingress(operation),
        )
        .map_err(|_| IngressKernelClientErrorV2::Unavailable)?;
        let canonical = encode_kernel_service_application_request_v2(&provisional)
            .map_err(|_| IngressKernelClientErrorV2::Unavailable)?;
        let mut hasher = Sha256::new();
        hasher.update(REQUEST_ID_DOMAIN_V2);
        hasher.update(&canonical);
        let digest: [u8; 32] = hasher.finalize().into();
        let mut request_id = [0_u8; 16];
        request_id.copy_from_slice(&digest[..16]);
        if request_id == [0; 16] {
            request_id[15] = 1;
        }
        let request_id = RequestIdV2::new(request_id);
        let (_, _, _, operation) = decode_kernel_service_application_request_v2(&canonical)
            .map_err(|_| IngressKernelClientErrorV2::Unavailable)?
            .into_parts();
        self.exchange_attempt(operation, request_id, deadline, io_deadline, true)
    }

    fn exchange_attempt(
        &self,
        operation: KernelServiceOperationV2,
        request_id: RequestIdV2,
        deadline: UnixMillisV2,
        io_deadline: Instant,
        allow_reload: bool,
    ) -> Result<Vec<u8>, IngressKernelClientErrorV2> {
        let authority = self.authority()?;
        let mut stream = UnixStream::connect(&self.shared.socket_path)
            .map_err(|_| IngressKernelClientErrorV2::Unavailable)?;
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
            .map_err(|_| IngressKernelClientErrorV2::Unavailable)?;
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
                    return self.exchange_attempt(
                        operation,
                        request_id,
                        deadline,
                        io_deadline,
                        false,
                    );
                }
                Err(_) => return Err(IngressKernelClientErrorV2::Unavailable),
            };
            write_handshake_frame(&mut stream, &finish, io_deadline)?;
            let confirmation = read_record_frame(&mut stream, io_deadline)?;
            session
                .accept_server_confirmation(&confirmation)
                .map_err(|_| IngressKernelClientErrorV2::Unavailable)?;

            let operation_tag = operation.tag();
            let request = KernelServiceApplicationRequestV2::new(
                EndpointRoleV2::IngressKernel,
                request_id,
                deadline,
                operation,
            )
            .map_err(|_| IngressKernelClientErrorV2::Unavailable)?;
            let plaintext = encode_kernel_service_application_request_v2(&request)
                .map_err(|_| IngressKernelClientErrorV2::Unavailable)?;
            let record = session
                .seal_application_request(request_id, operation_tag, &plaintext)
                .map_err(|_| IngressKernelClientErrorV2::Unavailable)?;
            write_record_frame(&mut stream, &record, io_deadline)?;
            let response_record = read_record_frame(&mut stream, io_deadline)?;
            let opened = session
                .open_application_response(&response_record)
                .map_err(|_| IngressKernelClientErrorV2::Unavailable)?;
            let response = decode_kernel_service_application_response_v2(
                opened.plaintext(),
                EndpointRoleV2::IngressKernel,
                operation_tag,
            )
            .map_err(|_| IngressKernelClientErrorV2::Unavailable)?;
            if response.request_id() != request_id || response.operation_tag() != operation_tag {
                return Err(IngressKernelClientErrorV2::Unavailable);
            }
            match response.body() {
                KernelServiceApplicationResponseBodyV2::Success(body) => Ok(body.to_vec()),
                KernelServiceApplicationResponseBodyV2::Error(
                    PublicStableCodeV2::DeadlineExceeded,
                ) => Err(IngressKernelClientErrorV2::DeadlineExceeded),
                KernelServiceApplicationResponseBodyV2::Error(_) => {
                    Err(IngressKernelClientErrorV2::Unavailable)
                }
            }
        })();
        let _ = stream.shutdown(Shutdown::Both);
        result
    }
}

fn io_deadline(deadline: UnixMillisV2) -> Result<Instant, IngressKernelClientErrorV2> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| IngressKernelClientErrorV2::Unavailable)?;
    let now_millis =
        u64::try_from(now.as_millis()).map_err(|_| IngressKernelClientErrorV2::Unavailable)?;
    let remaining = deadline
        .get()
        .checked_sub(now_millis)
        .filter(|value| *value != 0)
        .ok_or(IngressKernelClientErrorV2::DeadlineExceeded)?;
    Ok(Instant::now() + Duration::from_millis(remaining).min(MAX_CONNECTION_DURATION_V2))
}

fn random_nonzero_32() -> Result<[u8; 32], IngressKernelClientErrorV2> {
    let mut bytes = [0_u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|_| IngressKernelClientErrorV2::Unavailable)?;
    if bytes == [0; 32] {
        Err(IngressKernelClientErrorV2::Unavailable)
    } else {
        Ok(bytes)
    }
}

fn set_deadline(stream: &UnixStream, deadline: Instant) -> Result<(), IngressKernelClientErrorV2> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(IngressKernelClientErrorV2::DeadlineExceeded);
    }
    stream
        .set_read_timeout(Some(remaining))
        .and_then(|()| stream.set_write_timeout(Some(remaining)))
        .map_err(|_| IngressKernelClientErrorV2::Unavailable)
}

fn map_io_error(error: std::io::Error) -> IngressKernelClientErrorV2 {
    match error.kind() {
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => {
            IngressKernelClientErrorV2::DeadlineExceeded
        }
        _ => IngressKernelClientErrorV2::Unavailable,
    }
}

fn read_handshake_frame(
    stream: &mut UnixStream,
    deadline: Instant,
) -> Result<Vec<u8>, IngressKernelClientErrorV2> {
    set_deadline(stream, deadline)?;
    let mut header = [0_u8; HANDSHAKE_FRAME_HEADER_BYTES_V2];
    stream.read_exact(&mut header).map_err(map_io_error)?;
    if &header[..8] != HANDSHAKE_MAGIC_V2 {
        return Err(IngressKernelClientErrorV2::Unavailable);
    }
    let length = u32::from_be_bytes(
        header[HANDSHAKE_FRAME_HEADER_BYTES_V2 - 4..]
            .try_into()
            .map_err(|_| IngressKernelClientErrorV2::Unavailable)?,
    ) as usize;
    if length == 0 || length > MAX_HANDSHAKE_BODY_BYTES_V2 {
        return Err(IngressKernelClientErrorV2::Unavailable);
    }
    let mut frame = header.to_vec();
    frame.resize(
        HANDSHAKE_FRAME_HEADER_BYTES_V2
            .checked_add(length)
            .ok_or(IngressKernelClientErrorV2::Unavailable)?,
        0,
    );
    stream
        .read_exact(&mut frame[HANDSHAKE_FRAME_HEADER_BYTES_V2..])
        .map_err(map_io_error)?;
    Ok(frame)
}

fn write_handshake_frame(
    stream: &mut UnixStream,
    frame: &[u8],
    deadline: Instant,
) -> Result<(), IngressKernelClientErrorV2> {
    if frame.len() <= HANDSHAKE_FRAME_HEADER_BYTES_V2
        || frame.len() > HANDSHAKE_FRAME_HEADER_BYTES_V2 + MAX_HANDSHAKE_BODY_BYTES_V2
        || &frame[..8] != HANDSHAKE_MAGIC_V2
    {
        return Err(IngressKernelClientErrorV2::Unavailable);
    }
    set_deadline(stream, deadline)?;
    stream
        .write_all(frame)
        .and_then(|()| stream.flush())
        .map_err(map_io_error)
}

fn read_record_frame(
    stream: &mut UnixStream,
    deadline: Instant,
) -> Result<Vec<u8>, IngressKernelClientErrorV2> {
    set_deadline(stream, deadline)?;
    let mut header = [0_u8; RECORD_FRAME_HEADER_BYTES_V2];
    stream.read_exact(&mut header).map_err(map_io_error)?;
    let (header_length, ciphertext_length) = record_lengths(&header)?;
    let total = RECORD_FRAME_HEADER_BYTES_V2
        .checked_add(header_length)
        .and_then(|value| value.checked_add(ciphertext_length))
        .ok_or(IngressKernelClientErrorV2::Unavailable)?;
    let mut frame = Vec::new();
    frame
        .try_reserve_exact(total)
        .map_err(|_| IngressKernelClientErrorV2::Unavailable)?;
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
) -> Result<(), IngressKernelClientErrorV2> {
    if frame.len() < RECORD_FRAME_HEADER_BYTES_V2 {
        return Err(IngressKernelClientErrorV2::Unavailable);
    }
    let (header_length, ciphertext_length) =
        record_lengths(&frame[..RECORD_FRAME_HEADER_BYTES_V2])?;
    if frame.len() != RECORD_FRAME_HEADER_BYTES_V2 + header_length + ciphertext_length {
        return Err(IngressKernelClientErrorV2::Unavailable);
    }
    set_deadline(stream, deadline)?;
    stream
        .write_all(frame)
        .and_then(|()| stream.flush())
        .map_err(map_io_error)
}

fn record_lengths(header: &[u8]) -> Result<(usize, usize), IngressKernelClientErrorV2> {
    if header.len() != RECORD_FRAME_HEADER_BYTES_V2 || &header[..4] != RECORD_MAGIC_V2 {
        return Err(IngressKernelClientErrorV2::Unavailable);
    }
    let header_length = usize::from(u16::from_be_bytes(
        header[4..6]
            .try_into()
            .map_err(|_| IngressKernelClientErrorV2::Unavailable)?,
    ));
    let ciphertext_length = u32::from_be_bytes(
        header[6..10]
            .try_into()
            .map_err(|_| IngressKernelClientErrorV2::Unavailable)?,
    ) as usize;
    if header_length == 0
        || header_length > MAX_RECORD_HEADER_BYTES_V2
        || !(16..=MAX_RECORD_CIPHERTEXT_BYTES_V2).contains(&ciphertext_length)
    {
        return Err(IngressKernelClientErrorV2::Unavailable);
    }
    Ok((header_length, ciphertext_length))
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;

    use savana_kernel_protocol::v2::{
        derive_ed25519_key_id_v2, encode_kernel_ingress_health_response_v2,
        encode_kernel_service_application_response_v2, Digest32V2, KernelIngressHealthResponseV2,
        KernelServiceApplicationResponseV2, PublicServiceStateV2, ServiceIdentityV2,
        V2ServerHandshake,
    };

    use super::*;

    #[test]
    fn preexisting_client_adopts_verified_successor() {
        let directory = tempfile::tempdir().unwrap();
        let socket_path = directory.path().join("ingress-kernel-rollover.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        let client_key = SigningKey::from_bytes(&[0x71; 32]);
        let server_key = SigningKey::from_bytes(&[0x72; 32]);
        let server_public_key = server_key.verifying_key().to_bytes();
        let initial_edge = edge_at(&client_key, &server_key, 5, [6; 32], 7, 8);
        let successor_edge = edge_at(&client_key, &server_key, 6, [0x73; 32], 8, 9);
        let observed_peer =
            PeerIdentityBindingV2::linux(501, 20, 42, 99, Digest32V2::new([0x74; 32])).unwrap();
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
                Nonce32V2::new([0x75; 32]),
                StaticSecret::from([0x76; 32]),
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
                Nonce32V2::new([0x77; 32]),
                StaticSecret::from([0x78; 32]),
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
            let health = encode_kernel_ingress_health_response_v2(
                &KernelIngressHealthResponseV2::new(true, PublicServiceStateV2::Ready),
            )
            .unwrap();
            let response = KernelServiceApplicationResponseV2::success(
                EndpointRoleV2::IngressKernel,
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
        let client = SuiteOneIngressKernelClientV2::from_verified_deployment(
            initial_edge,
            BootIdV2::new([0x79; 32]),
            observed_peer,
            client_key,
            server_public_key,
        )
        .unwrap()
        .with_socket_path_for_test(socket_path)
        .with_successor_edge_for_test(successor_edge);
        let request_client = client.clone();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        assert_eq!(
            request_client
                .health(UnixMillisV2::new(now + 2_000))
                .unwrap(),
            KernelIngressHealthResponseV2::new(true, PublicServiceStateV2::Ready),
        );
        assert_eq!(client.authority().unwrap().edge, successor_edge);
        server.join().unwrap();
    }

    #[test]
    fn server_hello_deadline_never_reloads_authority() {
        let directory = tempfile::tempdir().unwrap();
        let socket_path = directory.path().join("ingress-kernel-deadline.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        let client_key = SigningKey::from_bytes(&[0x81; 32]);
        let server_key = SigningKey::from_bytes(&[0x82; 32]);
        let server_public_key = server_key.verifying_key().to_bytes();
        let initial_edge = edge_at(&client_key, &server_key, 5, [6; 32], 7, 8);
        let successor_edge = edge_at(&client_key, &server_key, 6, [0x83; 32], 8, 9);
        let observed_peer =
            PeerIdentityBindingV2::linux(501, 20, 42, 99, Digest32V2::new([0x84; 32])).unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            read_handshake_frame(&mut stream, Instant::now() + Duration::from_secs(1)).unwrap();
            thread::sleep(Duration::from_millis(150));
        });
        let client = SuiteOneIngressKernelClientV2::from_verified_deployment(
            initial_edge,
            BootIdV2::new([0x85; 32]),
            observed_peer,
            client_key,
            server_public_key,
        )
        .unwrap()
        .with_socket_path_for_test(socket_path)
        .with_successor_edge_for_test(successor_edge);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        assert_eq!(
            client.health(UnixMillisV2::new(now + 75)),
            Err(IngressKernelClientErrorV2::DeadlineExceeded),
        );
        assert_eq!(client.authority().unwrap().edge, initial_edge);
        server.join().unwrap();
    }

    #[test]
    fn a_second_handshake_rejection_never_gets_a_third_attempt() {
        let directory = tempfile::tempdir().unwrap();
        let socket_path = directory.path().join("ingress-kernel-retry-bound.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        let client_key = SigningKey::from_bytes(&[0x91; 32]);
        let server_key = SigningKey::from_bytes(&[0x92; 32]);
        let server_public_key = server_key.verifying_key().to_bytes();
        let initial_edge = edge_at(&client_key, &server_key, 5, [6; 32], 7, 8);
        let successor_edge = edge_at(&client_key, &server_key, 6, [0x93; 32], 8, 9);
        let unexpected_edge = edge_at(&client_key, &server_key, 7, [0x94; 32], 9, 10);
        let observed_peer =
            PeerIdentityBindingV2::linux(501, 20, 42, 99, Digest32V2::new([0x95; 32])).unwrap();
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
                    Nonce32V2::new([0x96 + index as u8; 32]),
                    StaticSecret::from([0x98 + index as u8; 32]),
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
        let client = SuiteOneIngressKernelClientV2::from_verified_deployment(
            initial_edge,
            BootIdV2::new([0x9a; 32]),
            observed_peer,
            client_key,
            server_public_key,
        )
        .unwrap()
        .with_socket_path_for_test(socket_path)
        .with_successor_edge_for_test(successor_edge);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        assert_eq!(
            client.health(UnixMillisV2::new(now + 2_000)),
            Err(IngressKernelClientErrorV2::Unavailable),
        );
        server.join().unwrap();
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
        assert_eq!(client.authority().unwrap().edge, successor_edge);
    }

    #[test]
    fn application_error_never_reloads_authority() {
        let directory = tempfile::tempdir().unwrap();
        let socket_path = directory
            .path()
            .join("ingress-kernel-application-error.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        let client_key = SigningKey::from_bytes(&[0xa1; 32]);
        let server_key = SigningKey::from_bytes(&[0xa2; 32]);
        let server_public_key = server_key.verifying_key().to_bytes();
        let initial_edge = edge_at(&client_key, &server_key, 5, [6; 32], 7, 8);
        let successor_edge = edge_at(&client_key, &server_key, 6, [0xa3; 32], 8, 9);
        let observed_peer =
            PeerIdentityBindingV2::linux(501, 20, 42, 99, Digest32V2::new([0xa4; 32])).unwrap();
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
                Nonce32V2::new([0xa5; 32]),
                StaticSecret::from([0xa6; 32]),
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
                EndpointRoleV2::IngressKernel,
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
        let client = SuiteOneIngressKernelClientV2::from_verified_deployment(
            initial_edge,
            BootIdV2::new([0xa7; 32]),
            observed_peer,
            client_key,
            server_public_key,
        )
        .unwrap()
        .with_socket_path_for_test(socket_path)
        .with_successor_edge_for_test(successor_edge);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        assert_eq!(
            client.health(UnixMillisV2::new(now + 2_000)),
            Err(IngressKernelClientErrorV2::Unavailable),
        );
        assert_eq!(client.authority().unwrap().edge, initial_edge);
        server.join().unwrap();
    }

    #[derive(Clone, Copy)]
    enum ServerHelloTerminalFailureV2 {
        Eof,
        MalformedFrame,
        MalformedCbor,
        InvalidSignature,
    }

    #[test]
    fn server_hello_eof_never_reloads_authority() {
        assert_terminal_server_hello_failure_does_not_reload(ServerHelloTerminalFailureV2::Eof);
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
        let socket_path = directory.path().join("ingress-kernel-terminal-hello.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        let client_key = SigningKey::from_bytes(&[0xb1; 32]);
        let server_key = SigningKey::from_bytes(&[0xb2; 32]);
        let server_public_key = server_key.verifying_key().to_bytes();
        let initial_edge = edge_at(&client_key, &server_key, 5, [6; 32], 7, 8);
        let successor_edge = edge_at(&client_key, &server_key, 6, [0xb3; 32], 8, 9);
        let observed_peer =
            PeerIdentityBindingV2::linux(501, 20, 42, 99, Digest32V2::new([0xb4; 32])).unwrap();
        let server_observed_peer = observed_peer.clone();
        let client_public_key = client_key.verifying_key().to_bytes();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let io_deadline = Instant::now() + Duration::from_secs(1);
            let hello = read_handshake_frame(&mut stream, io_deadline).unwrap();
            match failure {
                ServerHelloTerminalFailureV2::Eof => return,
                ServerHelloTerminalFailureV2::MalformedFrame => {
                    stream
                        .write_all(&[0; HANDSHAKE_FRAME_HEADER_BYTES_V2])
                        .unwrap();
                    stream.flush().unwrap();
                    return;
                }
                ServerHelloTerminalFailureV2::MalformedCbor
                | ServerHelloTerminalFailureV2::InvalidSignature => {}
            }
            let (_, mut server_hello) = V2ServerHandshake::accept_client_hello(
                initial_edge,
                server_observed_peer,
                &hello,
                Nonce32V2::new([0xb5; 32]),
                StaticSecret::from([0xb6; 32]),
                client_public_key,
                &server_key,
            )
            .unwrap();
            match failure {
                ServerHelloTerminalFailureV2::MalformedCbor => {
                    server_hello[HANDSHAKE_FRAME_HEADER_BYTES_V2] = 0xff;
                }
                ServerHelloTerminalFailureV2::InvalidSignature => {
                    *server_hello.last_mut().unwrap() ^= 1;
                }
                ServerHelloTerminalFailureV2::Eof
                | ServerHelloTerminalFailureV2::MalformedFrame => unreachable!(),
            }
            write_handshake_frame(&mut stream, &server_hello, io_deadline).unwrap();
        });
        let client = SuiteOneIngressKernelClientV2::from_verified_deployment(
            initial_edge,
            BootIdV2::new([0xb7; 32]),
            observed_peer,
            client_key,
            server_public_key,
        )
        .unwrap()
        .with_socket_path_for_test(socket_path)
        .with_successor_edge_for_test(successor_edge);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        assert_eq!(
            client.health(UnixMillisV2::new(now + 1_000)),
            Err(IngressKernelClientErrorV2::Unavailable),
        );
        assert_eq!(client.authority().unwrap().edge, initial_edge);
        server.join().unwrap();
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
            EndpointRoleV2::IngressKernel,
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
