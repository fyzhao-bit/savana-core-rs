#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AgentdDaemonErrorV2 {
    #[error("agent production deployment is unavailable")]
    DeploymentUnavailable,
    #[error("agent durable state is unavailable")]
    DurableStateUnavailable,
    #[error("agent service endpoint is unavailable")]
    EndpointUnavailable,
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code, unused_imports))]
mod implementation {
    use std::fs::{self, File};
    use std::io::{Read as _, Write as _};
    use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
    use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
    #[cfg(target_os = "linux")]
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::{Path, PathBuf};
    use std::sync::{mpsc, Arc, Mutex};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use ed25519_dalek::SigningKey;
    #[cfg(target_os = "linux")]
    use nix::sys::socket::{getsockopt, sockopt::AcceptConn};
    #[cfg(target_os = "linux")]
    use rustix::fs::{fstat, FileType};
    use savana_approvald::ApprovalSuiteOneClientV2;
    use savana_kernel_protocol::v2::{
        decode_agent_browser_request_v2, decode_continue_jarvis_bootstrap_request_v2,
        derive_ed25519_key_id_v2, encode_agent_browser_mutation_response_v2,
        encode_agent_browser_read_view_response_v2, read_fixed_http_request_v2,
        render_agent_ui_authentication_form_v2, render_agent_workspace_v2,
        render_ingress_bootstrap_form_v2, write_fixed_http_response_v2,
        AgentUiAuthenticationSettlementTransferCapabilityV2, BootIdV2, BootstrapKindV2, Digest32V2,
        DisplayProjectionIdV2, Ed25519KeyIdV2, EndpointRoleV2, ExecutorIdentityV2,
        FixedHttpErrorV2, FixedHttpRouteV2, FixedHttpServiceV2, PeerIdentityBindingV2,
        PlannerRouteIdV2, ProjectionIdV2, ServiceIdentityV2, UnixMillisV2,
        SAVANA_BROWSER_SCRIPT_V2,
    };
    #[cfg(target_os = "linux")]
    use savana_platform_identity::{
        measure_linux_peer_v2, pin_current_linux_service_v2, verify_native_peer_v2,
        BoundedIdentityStringV2, NativePeerMeasurementV2, PinnedLinuxPeerMeasurementV2,
    };
    use savana_policy_core::v2::{
        decode_hex_32_v2, load_verified_filesystem_startup_v2, read_verified_regular_file_v2,
        AuthenticatedFileAnchorV2, ClosedServiceEdgeIdV2, ClosedServiceIdV2,
        FilesystemServiceObservationConfigV2, VerifiedDaemonStartupV2,
    };
    use serde::Deserialize;
    use sha2::{Digest as _, Sha256};
    use zeroize::Zeroizing;

    use super::AgentdDaemonErrorV2;
    use crate::{
        AgentBrowserAuthorityV2, AgentControlDeploymentV2, AgentControlDispatcherV2,
        AgentTaskErrorV2, AgentTaskRollbackAnchorV2, AgentTaskServiceV2, AgentTaskStateHeadV2,
        AgentTaskStateOwnerV2, DurableAgentTaskNamespaceV2, KernelTaskAuthorityVerifierV2,
        PinnedMtlsAgentPlannerClientV2, SuiteOneAgentKernelClientV2, VerifiedAgentControlPeerV2,
    };

    const PRODUCTION_BOOTSTRAP_PATH_V2: &str = "/etc/savana/agentd-bootstrap-v2.json";
    const MANIFEST_ROOT_PATH_V2: &str = "/etc/savana/trust/deployment-manifest-root-v2.json";
    const KERNEL_SERVER_PUBLIC_KEY_PATH_V2: &str = "/etc/savana/agentd/keys/kerneld-agent-v2.pub";
    const KERNEL_TASK_AUTHORITY_PUBLIC_KEY_PATH_V2: &str =
        "/etc/savana/agentd/keys/kerneld-task-authority-v2.pub";
    const APPROVAL_SERVER_PUBLIC_KEY_PATH_V2: &str =
        "/etc/savana/agentd/keys/approvald-agent-v2.pub";
    const CREDENTIAL_DIRECTORY_V2: &str = "/run/credentials/savana-agentd.service";
    const AGENT_CLIENT_SEED_CREDENTIAL_V2: &str = "agent-kernel-v2.seed";
    const APPROVAL_CLIENT_SEED_CREDENTIAL_V2: &str = "agent-approval-v2.seed";
    const STATE_ENCRYPTION_CREDENTIAL_V2: &str = "task-state-encryption-v2.key";
    const ANCHOR_AUTHENTICATION_CREDENTIAL_V2: &str = "task-anchor-authentication-v2.key";
    const AGENTD_BOOT_CREDENTIAL_V2: &str = "agentd-boot-v2.id";
    const KERNELD_BOOT_CREDENTIAL_V2: &str = "kerneld-boot-v2.id";
    const APPROVALD_BOOT_CREDENTIAL_V2: &str = "approvald-boot-v2.id";
    const PLANNER_ROOT_CERTIFICATE_CREDENTIAL_V2: &str = "planner-root-v2.der";
    const PLANNER_CLIENT_CERTIFICATE_CREDENTIAL_V2: &str = "planner-client-v2.der";
    const PLANNER_CLIENT_PRIVATE_KEY_CREDENTIAL_V2: &str = "planner-client-v2.pk8";
    const MACHINE_BOOT_CREDENTIAL_V2: &str = "machine-boot-v2.id";
    const JARVIS_BOOT_CREDENTIAL_V2: &str = "jarvis-boot-v2.id";
    const CONTROL_FD_NAME_V2: &str = "savana-jarvis-agent-control";
    const JARVIS_HTTP_FD_NAME_V2: &str = "savana-jarvis-http";
    const AGENT_HTTP_FD_NAME_V2: &str = "savana-agent-http";
    const CONTROL_SOCKET_PATH_V2: &str = "/run/savana/agentd/jarvis/control.sock";
    const MAX_BOOTSTRAP_BYTES_V2: usize = 128 * 1024;
    const MAX_TLS_CREDENTIAL_BYTES_V2: usize = 64 * 1024;
    const MAX_CONTROL_FRAME_BYTES_V2: usize = 1024 * 1024;
    const CONTROL_WORKERS_V2: usize = 8;
    const CONTROL_QUEUE_CAPACITY_V2: usize = 8;
    const HTTP_WORKERS_V2: usize = 8;
    const HTTP_QUEUE_CAPACITY_V2: usize = 16;
    const CONNECTION_DEADLINE_V2: Duration = Duration::from_secs(10);
    const SOCKET_PATH_DOMAIN_V2: &[u8] = b"SAVANA_SOCKET_PATH_IDENTITY_V2\0";
    const ANCHOR_DOMAIN_V2: &[u8] = b"SAVANA_AGENTD_TASK_ANCHOR_MAC_V2\0";
    const ANCHOR_MAGIC_V2: [u8; 8] = *b"ST2ANCH\0";
    const SHELL_HTML_V2: &[u8] = b"<!doctype html><html><head><meta charset=\"utf-8\"><title>Savana</title></head><body><main><h1>Savana secure kernel</h1><p>Use the task-specific bootstrap URL returned by JARVIS.</p><p id=\"savana-status\"></p></main><script src=\"/v2/savana-ui.js\" defer></script></body></html>";
    const BOOTSTRAP_HTML_V2: &[u8] = b"<!doctype html><html><head><meta charset=\"utf-8\"><title>Savana bootstrap</title></head><body><main data-bootstrap=\"true\"><h1>Secure kernel bootstrap</h1><p id=\"savana-status\">Validating the one-time selector...</p></main><script src=\"/v2/savana-ui.js\" defer></script></body></html>";

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct BootstrapDtoV2 {
        signed_manifest_path: PathBuf,
        effect_ledger_projection_path: PathBuf,
        effect_gate_path: PathBuf,
        services: Vec<FilesystemServiceObservationConfigV2>,
        task_state_path: PathBuf,
        rollback_anchor_path: PathBuf,
        store_id: String,
        kernel_task_authority_key_id: String,
        approval_client_key_id: String,
        approval_server_key_id: String,
        planner_host: String,
        planner_port: u16,
        planner_server_spki_sha256: String,
        planner_route_id: u32,
        release_executor_identity: String,
        release_destination_projection: u32,
        release_display_projection: u32,
        jarvis_control_identity: String,
        jarvis_principal: String,
        jarvis_os_peer_class: String,
        jarvis_expected_uid: u32,
        jarvis_expected_gid: u32,
        jarvis_executable_digest: String,
    }

    struct AgentTaskAnchorAdapterV2 {
        inner: AuthenticatedFileAnchorV2,
    }

    impl AgentTaskRollbackAnchorV2 for AgentTaskAnchorAdapterV2 {
        fn current_head(&self) -> Result<AgentTaskStateHeadV2, AgentTaskErrorV2> {
            let (sequence, digest) = self
                .inner
                .current_head()
                .map_err(|_| AgentTaskErrorV2::DurableAuthentication)?;
            AgentTaskStateHeadV2::new(sequence, digest)
        }

        fn compare_and_advance(
            &mut self,
            expected: AgentTaskStateHeadV2,
            next: AgentTaskStateHeadV2,
        ) -> Result<(), AgentTaskErrorV2> {
            self.inner
                .compare_and_advance(
                    (expected.sequence(), expected.state_digest()),
                    (next.sequence(), next.state_digest()),
                )
                .map_err(|error| match error {
                    savana_policy_core::v2::AuthenticatedFileAnchorErrorV2::Authentication => {
                        AgentTaskErrorV2::DurableAuthentication
                    }
                    savana_policy_core::v2::AuthenticatedFileAnchorErrorV2::Rollback => {
                        AgentTaskErrorV2::RollbackDetected
                    }
                    _ => AgentTaskErrorV2::CommitUncertain,
                })
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub(crate) fn run(_config_path: &Path) -> Result<(), AgentdDaemonErrorV2> {
        Err(AgentdDaemonErrorV2::DeploymentUnavailable)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn run(config_path: &Path) -> Result<(), AgentdDaemonErrorV2> {
        if config_path != Path::new(PRODUCTION_BOOTSTRAP_PATH_V2) {
            return Err(AgentdDaemonErrorV2::DeploymentUnavailable);
        }
        let bytes =
            read_verified_regular_file_v2(config_path, MAX_BOOTSTRAP_BYTES_V2, Some((0, 0, 0o444)))
                .map_err(|_| AgentdDaemonErrorV2::DeploymentUnavailable)?;
        let bootstrap: BootstrapDtoV2 = serde_json::from_slice(&bytes)
            .map_err(|_| AgentdDaemonErrorV2::DeploymentUnavailable)?;
        if !bootstrap.signed_manifest_path.is_absolute()
            || !bootstrap.effect_ledger_projection_path.is_absolute()
            || !bootstrap.effect_gate_path.is_absolute()
            || !bootstrap.task_state_path.is_absolute()
            || !bootstrap.rollback_anchor_path.is_absolute()
        {
            return Err(AgentdDaemonErrorV2::DeploymentUnavailable);
        }
        let startup = load_verified_filesystem_startup_v2(
            Path::new(MANIFEST_ROOT_PATH_V2),
            &bootstrap.signed_manifest_path,
            &bootstrap.effect_ledger_projection_path,
            &bootstrap.services,
        )
        .map_err(|_| AgentdDaemonErrorV2::DeploymentUnavailable)?;
        startup
            .verify_loaded_service_config_v2(ClosedServiceIdV2::Agentd, &bytes)
            .map_err(|_| AgentdDaemonErrorV2::DeploymentUnavailable)?;
        let self_lock = startup
            .service_lock(ClosedServiceIdV2::Agentd)
            .ok_or(AgentdDaemonErrorV2::DeploymentUnavailable)?;
        let self_process = pin_current_linux_service_v2(
            self_lock.uid,
            self_lock.gid,
            *self_lock.executable_digest.as_bytes(),
        )
        .map_err(|_| AgentdDaemonErrorV2::DeploymentUnavailable)?;
        let (control_listener, jarvis_http_listener, agent_http_listener) =
            take_verified_listeners(&startup)?;
        let agentd_boot_id = BootIdV2::new(read_credential_32(AGENTD_BOOT_CREDENTIAL_V2)?);
        let kerneld_boot_id = BootIdV2::new(read_credential_32(KERNELD_BOOT_CREDENTIAL_V2)?);
        let approvald_boot_id = BootIdV2::new(read_credential_32(APPROVALD_BOOT_CREDENTIAL_V2)?);
        let machine_boot_id = BootIdV2::new(read_credential_32(MACHINE_BOOT_CREDENTIAL_V2)?);
        let jarvis_boot_id = BootIdV2::new(read_credential_32(JARVIS_BOOT_CREDENTIAL_V2)?);
        let edge_lock = startup
            .edge_lock(ClosedServiceEdgeIdV2::AgentKernel)
            .ok_or(AgentdDaemonErrorV2::DeploymentUnavailable)?;
        let client_seed = Zeroizing::new(read_credential_32(AGENT_CLIENT_SEED_CREDENTIAL_V2)?);
        let client_signing_key = SigningKey::from_bytes(&client_seed);
        let server_public_key = read_public_key(Path::new(KERNEL_SERVER_PUBLIC_KEY_PATH_V2))?;
        if derive_ed25519_key_id_v2(client_signing_key.verifying_key().to_bytes())
            != edge_lock.client_handshake_key_id
            || derive_ed25519_key_id_v2(server_public_key) != edge_lock.server_handshake_key_id
        {
            return Err(AgentdDaemonErrorV2::DeploymentUnavailable);
        }
        let task_authority_public_key =
            read_public_key(Path::new(KERNEL_TASK_AUTHORITY_PUBLIC_KEY_PATH_V2))?;
        let task_authority_key_id = Ed25519KeyIdV2::new(
            decode_hex_32_v2(&bootstrap.kernel_task_authority_key_id)
                .map_err(|_| AgentdDaemonErrorV2::DeploymentUnavailable)?,
        );
        if derive_ed25519_key_id_v2(task_authority_public_key) != task_authority_key_id {
            return Err(AgentdDaemonErrorV2::DeploymentUnavailable);
        }
        let agentd_identity = startup
            .service_identity(ClosedServiceIdV2::Agentd)
            .ok_or(AgentdDaemonErrorV2::DeploymentUnavailable)?;
        let task_service = AgentTaskServiceV2::from_verified_deployment(
            startup.installation_id(),
            startup.active_state_manifest_digest(),
            startup.deployment_generation(),
            startup.protocol_abi_digest(),
            agentd_identity,
            agentd_boot_id,
            kerneld_boot_id,
            task_authority_key_id,
            task_authority_public_key,
            65_536,
        )
        .map_err(|_| AgentdDaemonErrorV2::DurableStateUnavailable)?;
        let namespace = DurableAgentTaskNamespaceV2::from_verified_installation(
            startup.installation_id(),
            Digest32V2::new(
                decode_hex_32_v2(&bootstrap.store_id)
                    .map_err(|_| AgentdDaemonErrorV2::DeploymentUnavailable)?,
            ),
        )
        .map_err(|_| AgentdDaemonErrorV2::DurableStateUnavailable)?;
        let anchor = AuthenticatedFileAnchorV2::new(
            bootstrap.rollback_anchor_path.clone(),
            namespace.installation_id(),
            namespace.store_id(),
            read_credential_32(ANCHOR_AUTHENTICATION_CREDENTIAL_V2)?,
            ANCHOR_DOMAIN_V2,
            ANCHOR_MAGIC_V2,
        )
        .map_err(|_| AgentdDaemonErrorV2::DurableStateUnavailable)?;
        let tasks = AgentTaskStateOwnerV2::open(
            &bootstrap.task_state_path,
            read_credential_32(STATE_ENCRYPTION_CREDENTIAL_V2)?,
            namespace,
            Box::new(AgentTaskAnchorAdapterV2 { inner: anchor }),
            task_service,
            128,
        )
        .map_err(|_| AgentdDaemonErrorV2::DurableStateUnavailable)?;
        let verifier = KernelTaskAuthorityVerifierV2::from_verified_deployment(
            startup.installation_id(),
            startup.active_state_manifest_digest(),
            startup.deployment_generation(),
            startup.protocol_abi_digest(),
            agentd_identity,
            agentd_boot_id,
            kerneld_boot_id,
            task_authority_key_id,
            task_authority_public_key,
        )
        .map_err(|_| AgentdDaemonErrorV2::DeploymentUnavailable)?;
        let handshake_edge = startup
            .kernel_service_handshake_edge(ClosedServiceEdgeIdV2::AgentKernel, kerneld_boot_id)
            .map_err(|_| AgentdDaemonErrorV2::DeploymentUnavailable)?;
        let self_binding = current_process_binding(edge_lock, &self_process)?;
        let kernel_client = SuiteOneAgentKernelClientV2::from_verified_deployment(
            handshake_edge,
            agentd_boot_id,
            self_binding.clone(),
            client_signing_key.clone(),
            server_public_key,
            task_authority_key_id,
            task_authority_public_key,
        )
        .map_err(|_| AgentdDaemonErrorV2::DeploymentUnavailable)?;
        let browser_kernel = SuiteOneAgentKernelClientV2::from_verified_deployment(
            handshake_edge,
            agentd_boot_id,
            self_binding.clone(),
            client_signing_key,
            server_public_key,
            task_authority_key_id,
            task_authority_public_key,
        )
        .map_err(|_| AgentdDaemonErrorV2::DeploymentUnavailable)?;
        let effect_gate =
            crate::effect_gate::EffectGateCoordinatorV2::from_shared_only_descriptors(
                open_read_only_single_link(&bootstrap.effect_gate_path)?,
                open_read_only_single_link(&bootstrap.effect_ledger_projection_path)?,
                startup.effect_ledger_projection_binding(),
            )
            .map_err(|_| AgentdDaemonErrorV2::DeploymentUnavailable)?;
        let approval_seed = Zeroizing::new(read_credential_32(APPROVAL_CLIENT_SEED_CREDENTIAL_V2)?);
        let approval_signing_key = SigningKey::from_bytes(&approval_seed);
        let approval_public_key = read_public_key(Path::new(APPROVAL_SERVER_PUBLIC_KEY_PATH_V2))?;
        let approval_client_key_id = Ed25519KeyIdV2::new(
            decode_hex_32_v2(&bootstrap.approval_client_key_id)
                .map_err(|_| AgentdDaemonErrorV2::DeploymentUnavailable)?,
        );
        let approval_server_key_id = Ed25519KeyIdV2::new(
            decode_hex_32_v2(&bootstrap.approval_server_key_id)
                .map_err(|_| AgentdDaemonErrorV2::DeploymentUnavailable)?,
        );
        if derive_ed25519_key_id_v2(approval_signing_key.verifying_key().to_bytes())
            != approval_client_key_id
            || derive_ed25519_key_id_v2(approval_public_key) != approval_server_key_id
        {
            return Err(AgentdDaemonErrorV2::DeploymentUnavailable);
        }
        let approval_edge = startup
            .approval_service_handshake_edge(
                EndpointRoleV2::AgentApproval,
                approval_client_key_id,
                approval_server_key_id,
                approvald_boot_id,
            )
            .map_err(|_| AgentdDaemonErrorV2::DeploymentUnavailable)?;
        let approval_client = ApprovalSuiteOneClientV2::from_verified_deployment(
            approval_edge,
            agentd_boot_id,
            self_binding,
            approval_signing_key,
            approval_public_key,
        )
        .map_err(|_| AgentdDaemonErrorV2::DeploymentUnavailable)?;
        let planner = PinnedMtlsAgentPlannerClientV2::from_verified_deployment(
            bootstrap.planner_host.clone(),
            bootstrap.planner_port,
            Digest32V2::new(
                decode_hex_32_v2(&bootstrap.planner_server_spki_sha256)
                    .map_err(|_| AgentdDaemonErrorV2::DeploymentUnavailable)?,
            ),
            read_credential_blob(
                PLANNER_ROOT_CERTIFICATE_CREDENTIAL_V2,
                MAX_TLS_CREDENTIAL_BYTES_V2,
            )?,
            read_credential_blob(
                PLANNER_CLIENT_CERTIFICATE_CREDENTIAL_V2,
                MAX_TLS_CREDENTIAL_BYTES_V2,
            )?,
            Zeroizing::new(read_credential_blob(
                PLANNER_CLIENT_PRIVATE_KEY_CREDENTIAL_V2,
                MAX_TLS_CREDENTIAL_BYTES_V2,
            )?),
        )
        .map_err(|_| AgentdDaemonErrorV2::DeploymentUnavailable)?;
        if bootstrap.planner_route_id == 0
            || bootstrap.release_destination_projection == 0
            || bootstrap.release_display_projection == 0
        {
            return Err(AgentdDaemonErrorV2::DeploymentUnavailable);
        }
        let browser = Arc::new(AgentBrowserAuthorityV2::new(
            effect_gate,
            browser_kernel,
            approval_client,
            planner,
            PlannerRouteIdV2::new(bootstrap.planner_route_id),
            ExecutorIdentityV2::new(
                decode_hex_32_v2(&bootstrap.release_executor_identity)
                    .map_err(|_| AgentdDaemonErrorV2::DeploymentUnavailable)?,
            ),
            ProjectionIdV2::new(bootstrap.release_destination_projection),
            DisplayProjectionIdV2::new(bootstrap.release_display_projection),
            agentd_boot_id,
        ));
        let jarvis_identity = ServiceIdentityV2::new(
            decode_hex_32_v2(&bootstrap.jarvis_control_identity)
                .map_err(|_| AgentdDaemonErrorV2::DeploymentUnavailable)?,
        );
        let deployment = AgentControlDeploymentV2::from_verified_deployment(
            startup.installation_id(),
            startup.active_state_manifest_digest(),
            startup.deployment_generation(),
            startup.protocol_abi_digest(),
            agentd_identity,
            agentd_boot_id,
            kerneld_boot_id,
            jarvis_identity,
        )
        .map_err(|_| AgentdDaemonErrorV2::DeploymentUnavailable)?;
        let dispatcher = Arc::new(
            AgentControlDispatcherV2::spawn(deployment, tasks, verifier, kernel_client, 128)
                .map_err(|_| AgentdDaemonErrorV2::EndpointUnavailable)?,
        );
        let peer_template = PeerTemplateV2 {
            jarvis_principal: Digest32V2::new(
                decode_hex_32_v2(&bootstrap.jarvis_principal)
                    .map_err(|_| AgentdDaemonErrorV2::DeploymentUnavailable)?,
            ),
            jarvis_os_peer_class: Digest32V2::new(
                decode_hex_32_v2(&bootstrap.jarvis_os_peer_class)
                    .map_err(|_| AgentdDaemonErrorV2::DeploymentUnavailable)?,
            ),
            machine_boot_id,
            jarvis_boot_id,
            jarvis_identity,
            expected_uid: bootstrap.jarvis_expected_uid,
            expected_gid: bootstrap.jarvis_expected_gid,
            expected_executable_digest: decode_hex_32_v2(&bootstrap.jarvis_executable_digest)
                .map_err(|_| AgentdDaemonErrorV2::DeploymentUnavailable)?,
        };
        serve(
            control_listener,
            jarvis_http_listener,
            agent_http_listener,
            dispatcher,
            browser,
            peer_template,
        )
    }

    #[cfg(target_os = "linux")]
    #[derive(Clone, Copy)]
    struct PeerTemplateV2 {
        jarvis_principal: Digest32V2,
        jarvis_os_peer_class: Digest32V2,
        machine_boot_id: BootIdV2,
        jarvis_boot_id: BootIdV2,
        jarvis_identity: ServiceIdentityV2,
        expected_uid: u32,
        expected_gid: u32,
        expected_executable_digest: [u8; 32],
    }

    #[cfg(target_os = "linux")]
    fn serve(
        control_listener: UnixListener,
        jarvis_http_listener: TcpListener,
        agent_http_listener: TcpListener,
        dispatcher: Arc<AgentControlDispatcherV2>,
        browser: Arc<AgentBrowserAuthorityV2>,
        peer: PeerTemplateV2,
    ) -> Result<(), AgentdDaemonErrorV2> {
        let (failures, terminated) = mpsc::sync_channel(3);
        let control_dispatcher = Arc::clone(&dispatcher);
        let control_failures = failures.clone();
        std::thread::Builder::new()
            .name("savana-agent-control-listener-v2".to_owned())
            .spawn(move || {
                let result = serve_control(control_listener, control_dispatcher, peer);
                let _ = control_failures.send(result);
            })
            .map_err(|_| AgentdDaemonErrorV2::EndpointUnavailable)?;
        let jarvis_dispatcher = Arc::clone(&dispatcher);
        let jarvis_browser = Arc::clone(&browser);
        let jarvis_failures = failures.clone();
        std::thread::Builder::new()
            .name("savana-jarvis-http-listener-v2".to_owned())
            .spawn(move || {
                let result = serve_http(
                    jarvis_http_listener,
                    FixedHttpServiceV2::Jarvis,
                    jarvis_dispatcher,
                    jarvis_browser,
                );
                let _ = jarvis_failures.send(result);
            })
            .map_err(|_| AgentdDaemonErrorV2::EndpointUnavailable)?;
        let agent_failures = failures;
        std::thread::Builder::new()
            .name("savana-agent-http-listener-v2".to_owned())
            .spawn(move || {
                let result = serve_http(
                    agent_http_listener,
                    FixedHttpServiceV2::Agent,
                    dispatcher,
                    browser,
                );
                let _ = agent_failures.send(result);
            })
            .map_err(|_| AgentdDaemonErrorV2::EndpointUnavailable)?;
        terminated
            .recv()
            .map_err(|_| AgentdDaemonErrorV2::EndpointUnavailable)?
    }

    #[cfg(target_os = "linux")]
    fn serve_control(
        listener: UnixListener,
        dispatcher: Arc<AgentControlDispatcherV2>,
        peer: PeerTemplateV2,
    ) -> Result<(), AgentdDaemonErrorV2> {
        let (sender, receiver) = mpsc::sync_channel(CONTROL_QUEUE_CAPACITY_V2);
        let receiver = Arc::new(Mutex::new(receiver));
        for worker_index in 0..CONTROL_WORKERS_V2 {
            let receiver = Arc::clone(&receiver);
            let dispatcher = Arc::clone(&dispatcher);
            std::thread::Builder::new()
                .name(format!("savana-agent-control-worker-{worker_index}-v2"))
                .spawn(move || control_worker_loop(receiver, dispatcher))
                .map_err(|_| AgentdDaemonErrorV2::EndpointUnavailable)?;
        }
        loop {
            let (stream, _) = listener
                .accept()
                .map_err(|_| AgentdDaemonErrorV2::EndpointUnavailable)?;
            let measurement = match measure_linux_peer_v2(&stream) {
                Ok(value) => value,
                Err(_) => continue,
            };
            if !matches!(
                measurement.measurement(),
                NativePeerMeasurementV2::Linux {
                    uid,
                    gid,
                    executable_measurement,
                    ..
                } if *uid == peer.expected_uid
                    && *gid == peer.expected_gid
                    && *executable_measurement == peer.expected_executable_digest
            ) {
                continue;
            }
            let verified_peer = VerifiedAgentControlPeerV2::from_mutual_authentication(
                peer.jarvis_principal,
                peer.jarvis_os_peer_class,
                peer.machine_boot_id,
                peer.jarvis_boot_id,
                peer.jarvis_identity,
            )
            .map_err(|_| AgentdDaemonErrorV2::EndpointUnavailable)?;
            if sender
                .try_send(ControlJobV2 {
                    stream,
                    measurement,
                    verified_peer,
                })
                .is_err()
            {
                continue;
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn serve_http(
        listener: TcpListener,
        service: FixedHttpServiceV2,
        dispatcher: Arc<AgentControlDispatcherV2>,
        browser: Arc<AgentBrowserAuthorityV2>,
    ) -> Result<(), AgentdDaemonErrorV2> {
        let (sender, receiver) = mpsc::sync_channel(HTTP_QUEUE_CAPACITY_V2);
        let receiver = Arc::new(Mutex::new(receiver));
        for worker_index in 0..HTTP_WORKERS_V2 {
            let receiver = Arc::clone(&receiver);
            let dispatcher = Arc::clone(&dispatcher);
            let browser = Arc::clone(&browser);
            std::thread::Builder::new()
                .name(format!("savana-http-{worker_index}-v2"))
                .spawn(move || http_worker_loop(receiver, service, dispatcher, browser))
                .map_err(|_| AgentdDaemonErrorV2::EndpointUnavailable)?;
        }
        loop {
            let (stream, remote) = listener
                .accept()
                .map_err(|_| AgentdDaemonErrorV2::EndpointUnavailable)?;
            if remote.ip() != Ipv4Addr::LOCALHOST {
                continue;
            }
            if sender.try_send(stream).is_err() {
                continue;
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn http_worker_loop(
        receiver: Arc<Mutex<mpsc::Receiver<TcpStream>>>,
        service: FixedHttpServiceV2,
        dispatcher: Arc<AgentControlDispatcherV2>,
        browser: Arc<AgentBrowserAuthorityV2>,
    ) {
        loop {
            let stream = match receiver.lock() {
                Ok(receiver) => receiver.recv(),
                Err(_) => return,
            };
            let Ok(stream) = stream else {
                return;
            };
            let _ = serve_http_stream(
                stream,
                service,
                Arc::clone(&dispatcher),
                Arc::clone(&browser),
            );
        }
    }

    #[cfg(target_os = "linux")]
    fn serve_http_stream(
        mut stream: TcpStream,
        service: FixedHttpServiceV2,
        dispatcher: Arc<AgentControlDispatcherV2>,
        browser: Arc<AgentBrowserAuthorityV2>,
    ) -> Result<(), AgentdDaemonErrorV2> {
        stream
            .set_read_timeout(Some(CONNECTION_DEADLINE_V2))
            .and_then(|()| stream.set_write_timeout(Some(CONNECTION_DEADLINE_V2)))
            .map_err(|_| AgentdDaemonErrorV2::EndpointUnavailable)?;
        let request = match read_fixed_http_request_v2(&mut stream, service) {
            Ok(request) => request,
            Err(FixedHttpErrorV2::NotFound) => {
                return write_http(&mut stream, 404, "text/plain; charset=utf-8", b"")
            }
            Err(FixedHttpErrorV2::UnauthorizedOrigin) => return Ok(()),
            Err(_) => return write_http(&mut stream, 400, "text/plain; charset=utf-8", b""),
        };
        let deadline = Instant::now()
            .checked_add(CONNECTION_DEADLINE_V2)
            .ok_or(AgentdDaemonErrorV2::EndpointUnavailable)?;
        match request.route() {
            FixedHttpRouteV2::BrowserScript => write_http(
                &mut stream,
                200,
                "application/javascript; charset=utf-8",
                SAVANA_BROWSER_SCRIPT_V2,
            ),
            FixedHttpRouteV2::JarvisShell => {
                write_http(&mut stream, 200, "text/html; charset=utf-8", SHELL_HTML_V2)
            }
            FixedHttpRouteV2::JarvisBootstrap { kind, selector } => {
                dispatcher
                    .inspect_bootstrap(kind, selector, current_unix_millis()?, deadline)
                    .map_err(|_| AgentdDaemonErrorV2::EndpointUnavailable)?;
                write_http(
                    &mut stream,
                    200,
                    "text/html; charset=utf-8",
                    BOOTSTRAP_HTML_V2,
                )
            }
            FixedHttpRouteV2::JarvisBootstrapContinue => {
                let decoded = decode_continue_jarvis_bootstrap_request_v2(request.body())
                    .map_err(|_| AgentdDaemonErrorV2::EndpointUnavailable)?;
                let now = current_unix_millis()?;
                let resolved = dispatcher
                    .continue_bootstrap(BootstrapKindV2::Ingress, decoded.selector(), now, deadline)
                    .or_else(|_| {
                        dispatcher.continue_bootstrap(
                            BootstrapKindV2::Agent,
                            decoded.selector(),
                            now,
                            deadline,
                        )
                    })
                    .map_err(|_| AgentdDaemonErrorV2::EndpointUnavailable)?;
                let body = if let Some(transfer) = resolved.ingress_transfer() {
                    render_ingress_bootstrap_form_v2(transfer)
                } else {
                    let (_, correlation) = resolved
                        .agent_authority()
                        .ok_or(AgentdDaemonErrorV2::EndpointUnavailable)?;
                    let transfer = browser
                        .prepare_authentication(
                            correlation.clone(),
                            decoded.client_request_nonce(),
                            request_deadline_unix_millis()?,
                        )
                        .map_err(|_| AgentdDaemonErrorV2::EndpointUnavailable)?;
                    render_agent_ui_authentication_form_v2(transfer)
                };
                write_http(&mut stream, 200, "text/html; charset=utf-8", &body)
            }
            FixedHttpRouteV2::AgentUiAuthenticationComplete => {
                let transfer =
                    AgentUiAuthenticationSettlementTransferCapabilityV2::from_authority_entropy(
                        decode_form_transfer(request.body())?,
                    )
                    .ok_or(AgentdDaemonErrorV2::EndpointUnavailable)?;
                let completed = browser
                    .complete_authentication(transfer, request_deadline_unix_millis()?)
                    .map_err(|_| AgentdDaemonErrorV2::EndpointUnavailable)?;
                let body = render_agent_workspace_v2(completed.tab(), completed.initial_document());
                write_http(&mut stream, 200, "text/html; charset=utf-8", &body)
            }
            FixedHttpRouteV2::AgentView => {
                let request = decode_agent_browser_request_v2(request.body())
                    .map_err(|_| AgentdDaemonErrorV2::EndpointUnavailable)?;
                let response = browser
                    .read_view(request, request_deadline_unix_millis()?)
                    .map_err(|_| AgentdDaemonErrorV2::EndpointUnavailable)?;
                let body = encode_agent_browser_read_view_response_v2(&response)
                    .map_err(|_| AgentdDaemonErrorV2::EndpointUnavailable)?;
                write_http(&mut stream, 200, "application/cbor", &body)
            }
            FixedHttpRouteV2::AgentAction => {
                let request = decode_agent_browser_request_v2(request.body())
                    .map_err(|_| AgentdDaemonErrorV2::EndpointUnavailable)?;
                let response = browser
                    .act(request, request_deadline_unix_millis()?)
                    .map_err(|_| AgentdDaemonErrorV2::EndpointUnavailable)?;
                let body = encode_agent_browser_mutation_response_v2(&response)
                    .map_err(|_| AgentdDaemonErrorV2::EndpointUnavailable)?;
                write_http(&mut stream, 200, "application/cbor", &body)
            }
            _ => write_http(&mut stream, 404, "text/plain; charset=utf-8", b""),
        }
    }

    #[cfg(target_os = "linux")]
    fn write_http(
        stream: &mut TcpStream,
        status: u16,
        content_type: &str,
        body: &[u8],
    ) -> Result<(), AgentdDaemonErrorV2> {
        write_fixed_http_response_v2(stream, status, content_type, body)
            .map_err(|_| AgentdDaemonErrorV2::EndpointUnavailable)
    }

    #[cfg(target_os = "linux")]
    struct ControlJobV2 {
        stream: UnixStream,
        measurement: savana_platform_identity::PinnedLinuxPeerMeasurementV2,
        verified_peer: VerifiedAgentControlPeerV2,
    }

    #[cfg(target_os = "linux")]
    fn control_worker_loop(
        receiver: Arc<Mutex<mpsc::Receiver<ControlJobV2>>>,
        dispatcher: Arc<AgentControlDispatcherV2>,
    ) {
        loop {
            let job = match receiver.lock() {
                Ok(receiver) => receiver.recv(),
                Err(_) => return,
            };
            let Ok(job) = job else {
                return;
            };
            let _pinned = job.measurement;
            let _ = serve_control_stream(job.stream, Arc::clone(&dispatcher), job.verified_peer);
        }
    }

    #[cfg(target_os = "linux")]
    fn serve_control_stream(
        mut stream: UnixStream,
        dispatcher: Arc<AgentControlDispatcherV2>,
        peer: VerifiedAgentControlPeerV2,
    ) -> Result<(), AgentdDaemonErrorV2> {
        let deadline = Instant::now()
            .checked_add(CONNECTION_DEADLINE_V2)
            .ok_or(AgentdDaemonErrorV2::EndpointUnavailable)?;
        stream
            .set_read_timeout(Some(CONNECTION_DEADLINE_V2))
            .and_then(|()| stream.set_write_timeout(Some(CONNECTION_DEADLINE_V2)))
            .map_err(|_| AgentdDaemonErrorV2::EndpointUnavailable)?;
        let request = read_frame(&mut stream)?;
        let response = dispatcher
            .dispatch_canonical(&request, peer, current_unix_millis()?, deadline)
            .map_err(|_| AgentdDaemonErrorV2::EndpointUnavailable)?;
        write_frame(&mut stream, &response)
    }

    #[cfg(target_os = "linux")]
    fn read_frame(stream: &mut UnixStream) -> Result<Vec<u8>, AgentdDaemonErrorV2> {
        let mut length = [0_u8; 4];
        stream
            .read_exact(&mut length)
            .map_err(|_| AgentdDaemonErrorV2::EndpointUnavailable)?;
        let length = u32::from_be_bytes(length) as usize;
        if length == 0 || length > MAX_CONTROL_FRAME_BYTES_V2 {
            return Err(AgentdDaemonErrorV2::EndpointUnavailable);
        }
        let mut bytes = vec![0_u8; length];
        stream
            .read_exact(&mut bytes)
            .map_err(|_| AgentdDaemonErrorV2::EndpointUnavailable)?;
        Ok(bytes)
    }

    #[cfg(target_os = "linux")]
    fn write_frame(stream: &mut UnixStream, bytes: &[u8]) -> Result<(), AgentdDaemonErrorV2> {
        let length =
            u32::try_from(bytes.len()).map_err(|_| AgentdDaemonErrorV2::EndpointUnavailable)?;
        if length == 0 || bytes.len() > MAX_CONTROL_FRAME_BYTES_V2 {
            return Err(AgentdDaemonErrorV2::EndpointUnavailable);
        }
        stream
            .write_all(&length.to_be_bytes())
            .and_then(|()| stream.write_all(bytes))
            .and_then(|()| stream.flush())
            .map_err(|_| AgentdDaemonErrorV2::EndpointUnavailable)
    }

    #[cfg(target_os = "linux")]
    fn current_process_binding(
        edge: &savana_policy_core::v2::ServiceEdgeLockV2,
        pinned: &PinnedLinuxPeerMeasurementV2,
    ) -> Result<PeerIdentityBindingV2, AgentdDaemonErrorV2> {
        let role = BoundedIdentityStringV2::new(
            ClosedServiceEdgeIdV2::AgentKernel
                .role_identity()
                .to_owned(),
        )
        .map_err(|_| AgentdDaemonErrorV2::DeploymentUnavailable)?;
        verify_native_peer_v2(&edge.expected_client, &role, pinned.measurement())
            .map_err(|_| AgentdDaemonErrorV2::DeploymentUnavailable)?;
        match pinned.measurement() {
            NativePeerMeasurementV2::Linux {
                uid,
                gid,
                pid,
                process_start_time,
                executable_measurement,
            } => PeerIdentityBindingV2::linux(
                *uid,
                *gid,
                *pid,
                *process_start_time,
                Digest32V2::new(*executable_measurement),
            )
            .map_err(|_| AgentdDaemonErrorV2::DeploymentUnavailable),
            _ => Err(AgentdDaemonErrorV2::DeploymentUnavailable),
        }
    }

    #[cfg(target_os = "linux")]
    fn take_verified_listeners(
        startup: &VerifiedDaemonStartupV2,
    ) -> Result<(UnixListener, TcpListener, TcpListener), AgentdDaemonErrorV2> {
        let inherited = savana_platform_identity::take_systemd_listeners_v2(&[
            CONTROL_FD_NAME_V2,
            JARVIS_HTTP_FD_NAME_V2,
            AGENT_HTTP_FD_NAME_V2,
        ])
        .map_err(|_| AgentdDaemonErrorV2::EndpointUnavailable)?;
        let mut inherited = inherited.into_iter();
        let (name, listener) = inherited
            .next()
            .ok_or(AgentdDaemonErrorV2::EndpointUnavailable)?
            .into_unix_listener();
        let (jarvis_name, jarvis_http) = inherited
            .next()
            .ok_or(AgentdDaemonErrorV2::EndpointUnavailable)?
            .into_tcp_listener();
        let (agent_name, agent_http) = inherited
            .next()
            .ok_or(AgentdDaemonErrorV2::EndpointUnavailable)?
            .into_tcp_listener();
        let path = Path::new(CONTROL_SOCKET_PATH_V2);
        let service = startup
            .service_lock(ClosedServiceIdV2::Agentd)
            .ok_or(AgentdDaemonErrorV2::DeploymentUnavailable)?;
        let metadata =
            fs::symlink_metadata(path).map_err(|_| AgentdDaemonErrorV2::EndpointUnavailable)?;
        let descriptor = fstat(&listener).map_err(|_| AgentdDaemonErrorV2::EndpointUnavailable)?;
        if inherited.next().is_some()
            || name != CONTROL_FD_NAME_V2
            || !getsockopt(&listener, AcceptConn)
                .map_err(|_| AgentdDaemonErrorV2::EndpointUnavailable)?
            || listener
                .local_addr()
                .map_err(|_| AgentdDaemonErrorV2::EndpointUnavailable)?
                .as_pathname()
                != Some(path)
            || FileType::from_raw_mode(descriptor.st_mode) != FileType::Socket
            || metadata.file_type().is_symlink()
            || !metadata.file_type().is_socket()
            || metadata.uid() != service.socket_uid
            || metadata.gid() != service.socket_gid
            || metadata.mode() & 0o7777 != service.socket_mode
            || path_digest(path)? != service.socket_path_digest
        {
            return Err(AgentdDaemonErrorV2::EndpointUnavailable);
        }
        verify_tcp_listener(&jarvis_http, jarvis_name, JARVIS_HTTP_FD_NAME_V2, 8765)?;
        verify_tcp_listener(&agent_http, agent_name, AGENT_HTTP_FD_NAME_V2, 8768)?;
        Ok((listener, jarvis_http, agent_http))
    }

    #[cfg(target_os = "linux")]
    fn verify_tcp_listener(
        listener: &TcpListener,
        actual_name: String,
        expected_name: &str,
        port: u16,
    ) -> Result<(), AgentdDaemonErrorV2> {
        let descriptor = fstat(listener).map_err(|_| AgentdDaemonErrorV2::EndpointUnavailable)?;
        if actual_name != expected_name
            || !getsockopt(listener, AcceptConn)
                .map_err(|_| AgentdDaemonErrorV2::EndpointUnavailable)?
            || FileType::from_raw_mode(descriptor.st_mode) != FileType::Socket
            || listener
                .local_addr()
                .map_err(|_| AgentdDaemonErrorV2::EndpointUnavailable)?
                != SocketAddr::from((Ipv4Addr::LOCALHOST, port))
        {
            return Err(AgentdDaemonErrorV2::EndpointUnavailable);
        }
        Ok(())
    }

    fn path_digest(path: &Path) -> Result<Digest32V2, AgentdDaemonErrorV2> {
        let value = path
            .to_str()
            .ok_or(AgentdDaemonErrorV2::DeploymentUnavailable)?;
        let mut hasher = Sha256::new();
        hasher.update(SOCKET_PATH_DOMAIN_V2);
        hasher.update((value.len() as u32).to_be_bytes());
        hasher.update(value.as_bytes());
        Ok(Digest32V2::new(hasher.finalize().into()))
    }

    fn read_public_key(path: &Path) -> Result<[u8; 32], AgentdDaemonErrorV2> {
        read_verified_regular_file_v2(path, 32, Some((0, 0, 0o444)))
            .map_err(|_| AgentdDaemonErrorV2::DeploymentUnavailable)?
            .try_into()
            .map_err(|_| AgentdDaemonErrorV2::DeploymentUnavailable)
    }

    fn open_read_only_single_link(path: &Path) -> Result<File, AgentdDaemonErrorV2> {
        let metadata =
            fs::symlink_metadata(path).map_err(|_| AgentdDaemonErrorV2::DeploymentUnavailable)?;
        if !path.is_absolute()
            || metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.mode() & 0o222 != 0
        {
            return Err(AgentdDaemonErrorV2::DeploymentUnavailable);
        }
        File::open(path).map_err(|_| AgentdDaemonErrorV2::DeploymentUnavailable)
    }

    fn read_credential_32(name: &str) -> Result<[u8; 32], AgentdDaemonErrorV2> {
        if name.is_empty() || name.contains('/') {
            return Err(AgentdDaemonErrorV2::DeploymentUnavailable);
        }
        let directory = Path::new(CREDENTIAL_DIRECTORY_V2);
        let metadata = fs::symlink_metadata(directory)
            .map_err(|_| AgentdDaemonErrorV2::DeploymentUnavailable)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
        {
            return Err(AgentdDaemonErrorV2::DeploymentUnavailable);
        }
        read_verified_regular_file_v2(&directory.join(name), 32, Some((0, 0, 0o400)))
            .map_err(|_| AgentdDaemonErrorV2::DeploymentUnavailable)?
            .try_into()
            .map_err(|_| AgentdDaemonErrorV2::DeploymentUnavailable)
    }

    fn read_credential_blob(
        name: &str,
        maximum_bytes: usize,
    ) -> Result<Vec<u8>, AgentdDaemonErrorV2> {
        if name.is_empty() || name.contains('/') || maximum_bytes == 0 {
            return Err(AgentdDaemonErrorV2::DeploymentUnavailable);
        }
        let directory = Path::new(CREDENTIAL_DIRECTORY_V2);
        let metadata = fs::symlink_metadata(directory)
            .map_err(|_| AgentdDaemonErrorV2::DeploymentUnavailable)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
        {
            return Err(AgentdDaemonErrorV2::DeploymentUnavailable);
        }
        let bytes = read_verified_regular_file_v2(
            &directory.join(name),
            maximum_bytes,
            Some((0, 0, 0o400)),
        )
        .map_err(|_| AgentdDaemonErrorV2::DeploymentUnavailable)?;
        if bytes.is_empty() {
            return Err(AgentdDaemonErrorV2::DeploymentUnavailable);
        }
        Ok(bytes)
    }

    fn current_unix_millis() -> Result<UnixMillisV2, AgentdDaemonErrorV2> {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| AgentdDaemonErrorV2::EndpointUnavailable)?
            .as_millis();
        let millis = u64::try_from(millis).map_err(|_| AgentdDaemonErrorV2::EndpointUnavailable)?;
        Ok(UnixMillisV2::new(millis))
    }

    #[cfg(target_os = "linux")]
    fn decode_form_transfer(body: &[u8]) -> Result<[u8; 32], AgentdDaemonErrorV2> {
        let encoded = body
            .strip_prefix(b"transfer=")
            .ok_or(AgentdDaemonErrorV2::EndpointUnavailable)?;
        if encoded.contains(&b'&') || encoded.contains(&b'%') || encoded.contains(&b'+') {
            return Err(AgentdDaemonErrorV2::EndpointUnavailable);
        }
        let decoded = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| AgentdDaemonErrorV2::EndpointUnavailable)?;
        let transfer: [u8; 32] = decoded
            .try_into()
            .map_err(|_| AgentdDaemonErrorV2::EndpointUnavailable)?;
        if transfer == [0; 32] {
            return Err(AgentdDaemonErrorV2::EndpointUnavailable);
        }
        Ok(transfer)
    }

    fn request_deadline_unix_millis() -> Result<UnixMillisV2, AgentdDaemonErrorV2> {
        let now = current_unix_millis()?.get();
        let deadline = now
            .checked_add(
                u64::try_from(CONNECTION_DEADLINE_V2.as_millis())
                    .map_err(|_| AgentdDaemonErrorV2::EndpointUnavailable)?,
            )
            .ok_or(AgentdDaemonErrorV2::EndpointUnavailable)?;
        Ok(UnixMillisV2::new(deadline))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn fixed_control_path_digest_is_domain_separated() {
            assert_ne!(
                path_digest(Path::new(CONTROL_SOCKET_PATH_V2)).unwrap(),
                Digest32V2::new(Sha256::digest(CONTROL_SOCKET_PATH_V2).into())
            );
        }
    }
}

pub(crate) use implementation::run;
