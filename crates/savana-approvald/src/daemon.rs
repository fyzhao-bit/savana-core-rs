#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ApprovaldDaemonErrorV2 {
    #[error("approval production deployment is unavailable")]
    DeploymentUnavailable,
    #[error("approval durable state is unavailable")]
    DurableStateUnavailable,
    #[error("approval service endpoint is unavailable")]
    EndpointUnavailable,
}

#[cfg_attr(
    not(any(target_os = "linux", target_os = "macos")),
    allow(dead_code, unused_imports)
)]
mod implementation {
    use std::fs;
    use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
    use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
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
    use savana_kernel_protocol::v2::{
        decode_approval_decision_browser_begin_request_v2,
        decode_approval_decision_browser_finish_request_v2,
        decode_approval_display_browser_request_v2, decode_begin_enrollment_browser_request_v2,
        decode_finish_enrollment_browser_request_v2,
        decode_ui_authentication_browser_begin_request_v2,
        decode_ui_authentication_browser_finish_request_v2, derive_ed25519_key_id_v2,
        encode_approval_decision_browser_begin_response_v2,
        encode_approval_decision_browser_finish_response_v2, encode_approval_display_view_v2,
        encode_begin_enrollment_browser_response_v2, encode_finish_enrollment_browser_response_v2,
        encode_ui_authentication_browser_begin_response_v2,
        encode_ui_authentication_browser_finish_response_v2, read_fixed_http_request_v2,
        write_fixed_http_response_v2, BootIdV2, Digest32V2, Ed25519KeyIdV2, EndpointRoleV2,
        EnrollmentProfileIdV2, FixedHttpErrorV2, FixedHttpRouteV2, FixedHttpServiceV2,
        PeerIdentityBindingV2, PrincipalIdV2, UnixMillisV2, SAVANA_BROWSER_SCRIPT_V2,
    };
    #[cfg(target_os = "linux")]
    use savana_platform_identity::measure_linux_peer_v2;
    use savana_platform_identity::NativePeerMeasurementV2;
    use savana_policy_core::v2::{
        decode_hex_32_v2, read_verified_regular_file_v2, AuthenticatedFileAnchorV2,
        ClosedServiceIdV2, FilesystemServiceObservationConfigV2, ServiceDeploymentLockV2,
        VerifiedDaemonStartupV2,
    };
    use serde::Deserialize;
    use sha2::{Digest as _, Sha256};
    use zeroize::Zeroizing;

    use super::ApprovaldDaemonErrorV2;
    use crate::{
        AcceptedUiAuthenticationV2, ApprovalErrorV2, ApprovalRollbackAnchorV2, ApprovalStateHeadV2,
        ApprovalSuiteOneServerV2, ApprovalUiAuthorityV2, DurableApprovalNamespaceV2,
        HardwareAttestationRootV2, ProtocolApprovalServiceV2, ProtocolApprovalStateOwnerV2,
    };

    #[cfg(target_os = "linux")]
    const NATIVE_BOOTSTRAP_PATH_V2: &str = "/etc/savana/approvald-bootstrap-v2.json";
    #[cfg(target_os = "macos")]
    const NATIVE_BOOTSTRAP_PATH_V2: &str =
        "/Library/Application Support/Savana/Development/config/approvald-bootstrap-v2.json";
    #[cfg(target_os = "linux")]
    const MANIFEST_ROOT_PATH_V2: &str = "/etc/savana/trust/deployment-manifest-root-v2.json";
    #[cfg(all(target_os = "macos", feature = "macos-development-authority"))]
    const MANIFEST_ROOT_PATH_V2: &str = "/Library/Application Support/Savana/Development/config/trust/deployment-manifest-root-v2.json";
    #[cfg(target_os = "linux")]
    const CREDENTIAL_DIRECTORY_V2: &str = "/run/credentials/savana-approvald.service";
    #[cfg(target_os = "macos")]
    const CREDENTIAL_DIRECTORY_V2: &str =
        "/Library/Application Support/Savana/Development/credentials/approvald";
    const APPROVALD_BOOT_CREDENTIAL_V2: &str = "approvald-boot-v2.id";
    const SERVER_SEED_CREDENTIAL_V2: &str = "approval-server-v2.seed";
    const SETTLEMENT_SEED_CREDENTIAL_V2: &str = "approval-settlement-v2.seed";
    const STATE_ENCRYPTION_CREDENTIAL_V2: &str = "approval-state-encryption-v2.key";
    const ANCHOR_AUTHENTICATION_CREDENTIAL_V2: &str = "approval-anchor-authentication-v2.key";
    const AGENT_FD_NAME_V2: &str = "savana-agent-approval";
    const INGRESS_FD_NAME_V2: &str = "savana-ingress-approval";
    const ADMIN_FD_NAME_V2: &str = "savana-admin-approval";
    const HTTP_FD_NAME_V2: &str = "savana-approval-http";
    #[cfg(target_os = "linux")]
    const AGENT_SOCKET_PATH_V2: &str = "/run/savana/approvald/agentd/approvald.sock";
    #[cfg(target_os = "macos")]
    const AGENT_SOCKET_PATH_V2: &str =
        "/Library/Application Support/Savana/Development/run/approvald/agentd/approvald.sock";
    #[cfg(target_os = "linux")]
    const INGRESS_SOCKET_PATH_V2: &str = "/run/savana/approvald/ingressd/approvald.sock";
    #[cfg(target_os = "macos")]
    const INGRESS_SOCKET_PATH_V2: &str =
        "/Library/Application Support/Savana/Development/run/approvald/ingressd/approvald.sock";
    #[cfg(target_os = "linux")]
    const ADMIN_SOCKET_PATH_V2: &str = "/run/savana/approvald/admin/approvald.sock";
    #[cfg(target_os = "macos")]
    const ADMIN_SOCKET_PATH_V2: &str =
        "/Library/Application Support/Savana/Development/run/approvald/admin/approvald.sock";
    const MAX_BOOTSTRAP_BYTES_V2: usize = 256 * 1024;
    const UDS_WORKERS_V2: usize = 8;
    const UDS_QUEUE_CAPACITY_V2: usize = 32;
    const HTTP_WORKERS_V2: usize = 8;
    const HTTP_QUEUE_CAPACITY_V2: usize = 32;
    const CONNECTION_DEADLINE_V2: Duration = Duration::from_secs(10);
    const ANCHOR_DOMAIN_V2: &[u8] = b"SAVANA_APPROVALD_STATE_ANCHOR_MAC_V2\0";
    const ANCHOR_MAGIC_V2: [u8; 8] = *b"SA2ANCH\0";
    const FINISH_REQUEST_DIGEST_DOMAIN_V2: &[u8] = b"SAVANA_UI_AUTH_FINISH_HTTP_REQUEST_V2\0";

    #[derive(Deserialize)]
    #[cfg_attr(
        all(target_os = "macos", not(feature = "macos-development-authority")),
        allow(dead_code)
    )]
    #[serde(deny_unknown_fields)]
    struct BootstrapDtoV2 {
        signed_manifest_path: PathBuf,
        effect_ledger_projection_path: PathBuf,
        services: Vec<FilesystemServiceObservationConfigV2>,
        state_path: PathBuf,
        rollback_anchor_path: PathBuf,
        store_id: String,
        kernel_envelope_public_key_path: PathBuf,
        kernel_correlation_public_key_path: PathBuf,
        kernel_correlation_key_id: String,
        settlement_key_id: String,
        settlement_key_epoch: u64,
        server_key_id: String,
        agent_client_public_key_path: PathBuf,
        agent_client_key_id: String,
        ingress_client_public_key_path: PathBuf,
        ingress_client_key_id: String,
        admin_client_public_key_path: PathBuf,
        admin_client_key_id: String,
        admin_client_identity: String,
        admin_expected_uid: u32,
        admin_expected_gid: u32,
        #[cfg_attr(target_os = "macos", allow(dead_code))]
        admin_executable_digest: String,
        #[cfg_attr(target_os = "linux", allow(dead_code))]
        #[serde(default)]
        admin_code_identity_digest: Option<String>,
        enrollment_profiles: Vec<EnrollmentProfileDtoV2>,
        attestation_roots: Vec<AttestationRootDtoV2>,
        hardware_credentials: Vec<HardwareCredentialDtoV2>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct EnrollmentProfileDtoV2 {
        profile: u32,
        code_lifetime_ms: u64,
        ceremony_lifetime_ms: u64,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct AttestationRootDtoV2 {
        aaguid: String,
        root_certificate_path: PathBuf,
        root_certificate_sha256: String,
        root_spki_sha256: String,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct HardwareCredentialDtoV2 {
        credential_digest: String,
        principal: String,
        aaguid: String,
        p256_sec1_public_key: String,
        signature_counter: u32,
    }

    struct ApprovalAnchorAdapterV2 {
        inner: AuthenticatedFileAnchorV2,
    }

    impl ApprovalRollbackAnchorV2 for ApprovalAnchorAdapterV2 {
        fn current_head(&self) -> Result<ApprovalStateHeadV2, ApprovalErrorV2> {
            let (sequence, digest) = self
                .inner
                .current_head()
                .map_err(|_| ApprovalErrorV2::DurableAuthentication)?;
            ApprovalStateHeadV2::new(sequence, digest)
        }

        fn compare_and_advance(
            &mut self,
            expected: ApprovalStateHeadV2,
            next: ApprovalStateHeadV2,
        ) -> Result<(), ApprovalErrorV2> {
            self.inner
                .compare_and_advance(
                    (expected.sequence(), expected.state_digest()),
                    (next.sequence(), next.state_digest()),
                )
                .map_err(|error| match error {
                    savana_policy_core::v2::AuthenticatedFileAnchorErrorV2::Authentication => {
                        ApprovalErrorV2::DurableAuthentication
                    }
                    savana_policy_core::v2::AuthenticatedFileAnchorErrorV2::Rollback => {
                        ApprovalErrorV2::RollbackDetected
                    }
                    _ => ApprovalErrorV2::CommitUncertain,
                })
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    pub(crate) fn run(_config_path: &Path) -> Result<(), ApprovaldDaemonErrorV2> {
        Err(ApprovaldDaemonErrorV2::DeploymentUnavailable)
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(crate) fn run(config_path: &Path) -> Result<(), ApprovaldDaemonErrorV2> {
        if config_path != Path::new(NATIVE_BOOTSTRAP_PATH_V2) {
            return Err(ApprovaldDaemonErrorV2::DeploymentUnavailable);
        }
        let bytes =
            read_verified_regular_file_v2(config_path, MAX_BOOTSTRAP_BYTES_V2, Some((0, 0, 0o444)))
                .map_err(|_| ApprovaldDaemonErrorV2::DeploymentUnavailable)?;
        let bootstrap: BootstrapDtoV2 = serde_json::from_slice(&bytes)
            .map_err(|_| ApprovaldDaemonErrorV2::DeploymentUnavailable)?;
        let startup = load_native_startup(&bootstrap)?;
        startup
            .verify_loaded_service_config_v2(ClosedServiceIdV2::Approvald, &bytes)
            .map_err(|_| ApprovaldDaemonErrorV2::DeploymentUnavailable)?;
        let self_lock = startup
            .service_lock(ClosedServiceIdV2::Approvald)
            .ok_or(ApprovaldDaemonErrorV2::DeploymentUnavailable)?;
        #[cfg(target_os = "linux")]
        let _self_process = savana_platform_identity::pin_current_linux_service_v2(
            self_lock.uid,
            self_lock.gid,
            *self_lock.executable_digest.as_bytes(),
        )
        .map_err(|_| ApprovaldDaemonErrorV2::DeploymentUnavailable)?;
        #[cfg(target_os = "macos")]
        let _self_process = savana_platform_identity::pin_current_macos_service_v2(
            self_lock.uid,
            self_lock.gid,
            *self_lock.executable_digest.as_bytes(),
            *self_lock.code_identity_digest.as_bytes(),
        )
        .map_err(|_| ApprovaldDaemonErrorV2::DeploymentUnavailable)?;
        let (agent_listener, ingress_listener, admin_listener, http_listener) =
            take_verified_listeners(&startup)?;
        let approvald_boot_id = BootIdV2::new(read_credential_32(APPROVALD_BOOT_CREDENTIAL_V2)?);
        let server_seed = Zeroizing::new(read_credential_32(SERVER_SEED_CREDENTIAL_V2)?);
        let server_key = SigningKey::from_bytes(&server_seed);
        let settlement_seed = Zeroizing::new(read_credential_32(SETTLEMENT_SEED_CREDENTIAL_V2)?);
        let server_key_id = Ed25519KeyIdV2::new(parse_hex_32(&bootstrap.server_key_id)?);
        let settlement_key_id = Ed25519KeyIdV2::new(parse_hex_32(&bootstrap.settlement_key_id)?);
        if derive_ed25519_key_id_v2(server_key.verifying_key().to_bytes()) != server_key_id
            || derive_ed25519_key_id_v2(
                SigningKey::from_bytes(&settlement_seed)
                    .verifying_key()
                    .to_bytes(),
            ) != settlement_key_id
        {
            return Err(ApprovaldDaemonErrorV2::DeploymentUnavailable);
        }
        let kernel_envelope_public_key =
            read_public_key(&bootstrap.kernel_envelope_public_key_path)?;
        if derive_ed25519_key_id_v2(kernel_envelope_public_key)
            != startup.kernel_envelope_signing_key_id()
        {
            return Err(ApprovaldDaemonErrorV2::DeploymentUnavailable);
        }
        let kernel_correlation_public_key =
            read_public_key(&bootstrap.kernel_correlation_public_key_path)?;
        let kernel_correlation_key_id =
            Ed25519KeyIdV2::new(parse_hex_32(&bootstrap.kernel_correlation_key_id)?);
        if derive_ed25519_key_id_v2(kernel_correlation_public_key) != kernel_correlation_key_id {
            return Err(ApprovaldDaemonErrorV2::DeploymentUnavailable);
        }
        let approvald_identity = startup
            .service_identity(ClosedServiceIdV2::Approvald)
            .ok_or(ApprovaldDaemonErrorV2::DeploymentUnavailable)?;
        let mut deployment = ProtocolApprovalServiceV2::from_verified_deployment(
            startup.installation_id(),
            startup.active_state_manifest_digest(),
            startup.deployment_generation(),
            approvald_boot_id,
            bootstrap.settlement_key_epoch,
            approvald_identity,
            startup.kernel_envelope_signing_key_id(),
            kernel_envelope_public_key,
            kernel_correlation_key_id,
            kernel_correlation_public_key,
            settlement_key_id,
            *settlement_seed,
            65_536,
        )
        .map_err(|_| ApprovaldDaemonErrorV2::DeploymentUnavailable)?;
        load_enrollment_profiles(&mut deployment, &bootstrap.enrollment_profiles)?;
        load_hardware_credentials(&mut deployment, &bootstrap.hardware_credentials)?;
        let attestation_roots = load_attestation_roots(&bootstrap.attestation_roots)?;
        let namespace = DurableApprovalNamespaceV2::from_verified_installation(
            startup.installation_id(),
            Digest32V2::new(parse_hex_32(&bootstrap.store_id)?),
        )
        .map_err(|_| ApprovaldDaemonErrorV2::DurableStateUnavailable)?;
        let anchor = AuthenticatedFileAnchorV2::new(
            bootstrap.rollback_anchor_path.clone(),
            namespace.installation_id(),
            namespace.store_id(),
            read_credential_32(ANCHOR_AUTHENTICATION_CREDENTIAL_V2)?,
            ANCHOR_DOMAIN_V2,
            ANCHOR_MAGIC_V2,
        )
        .map_err(|_| ApprovaldDaemonErrorV2::DurableStateUnavailable)?;
        let state = ProtocolApprovalStateOwnerV2::open(
            &bootstrap.state_path,
            read_credential_32(STATE_ENCRYPTION_CREDENTIAL_V2)?,
            namespace,
            Box::new(ApprovalAnchorAdapterV2 { inner: anchor }),
            deployment,
            128,
        )
        .map_err(|_| ApprovaldDaemonErrorV2::DurableStateUnavailable)?;
        let authority = Arc::new(
            ApprovalUiAuthorityV2::new(state, 65_536, attestation_roots)
                .map_err(|_| ApprovaldDaemonErrorV2::DurableStateUnavailable)?,
        );
        let agent_client_public_key = read_public_key(&bootstrap.agent_client_public_key_path)?;
        let ingress_client_public_key = read_public_key(&bootstrap.ingress_client_public_key_path)?;
        let admin_client_public_key = read_public_key(&bootstrap.admin_client_public_key_path)?;
        let agent_client_key_id =
            Ed25519KeyIdV2::new(parse_hex_32(&bootstrap.agent_client_key_id)?);
        let ingress_client_key_id =
            Ed25519KeyIdV2::new(parse_hex_32(&bootstrap.ingress_client_key_id)?);
        let admin_client_key_id =
            Ed25519KeyIdV2::new(parse_hex_32(&bootstrap.admin_client_key_id)?);
        if derive_ed25519_key_id_v2(agent_client_public_key) != agent_client_key_id
            || derive_ed25519_key_id_v2(ingress_client_public_key) != ingress_client_key_id
            || derive_ed25519_key_id_v2(admin_client_public_key) != admin_client_key_id
        {
            return Err(ApprovaldDaemonErrorV2::DeploymentUnavailable);
        }
        let agent_edge = startup
            .approval_service_handshake_edge(
                EndpointRoleV2::AgentApproval,
                agent_client_key_id,
                server_key_id,
                approvald_boot_id,
            )
            .map_err(|_| ApprovaldDaemonErrorV2::DeploymentUnavailable)?;
        let ingress_edge = startup
            .approval_service_handshake_edge(
                EndpointRoleV2::IngressApproval,
                ingress_client_key_id,
                server_key_id,
                approvald_boot_id,
            )
            .map_err(|_| ApprovaldDaemonErrorV2::DeploymentUnavailable)?;
        let admin_edge = startup
            .approval_admin_handshake_edge(
                savana_kernel_protocol::v2::ServiceIdentityV2::new(parse_hex_32(
                    &bootstrap.admin_client_identity,
                )?),
                admin_client_key_id,
                server_key_id,
                approvald_boot_id,
            )
            .map_err(|_| ApprovaldDaemonErrorV2::DeploymentUnavailable)?;
        let agent_server = Arc::new(
            ApprovalSuiteOneServerV2::new(
                agent_edge,
                agent_client_public_key,
                server_key.clone(),
                65_536,
                Arc::clone(&authority),
            )
            .map_err(|_| ApprovaldDaemonErrorV2::DeploymentUnavailable)?,
        );
        let ingress_server = Arc::new(
            ApprovalSuiteOneServerV2::new(
                ingress_edge,
                ingress_client_public_key,
                server_key.clone(),
                65_536,
                Arc::clone(&authority),
            )
            .map_err(|_| ApprovaldDaemonErrorV2::DeploymentUnavailable)?,
        );
        let admin_server = Arc::new(
            ApprovalSuiteOneServerV2::new(
                admin_edge,
                admin_client_public_key,
                server_key,
                65_536,
                Arc::clone(&authority),
            )
            .map_err(|_| ApprovaldDaemonErrorV2::DeploymentUnavailable)?,
        );
        let agent_peer = peer_policy(
            startup
                .service_lock(ClosedServiceIdV2::Agentd)
                .ok_or(ApprovaldDaemonErrorV2::DeploymentUnavailable)?,
        );
        let ingress_peer = peer_policy(
            startup
                .service_lock(ClosedServiceIdV2::Ingressd)
                .ok_or(ApprovaldDaemonErrorV2::DeploymentUnavailable)?,
        );
        #[cfg(target_os = "linux")]
        let admin_peer = PeerPolicyV2 {
            uid: bootstrap.admin_expected_uid,
            gid: bootstrap.admin_expected_gid,
            identity_digest: Digest32V2::new(parse_hex_32(&bootstrap.admin_executable_digest)?),
        };
        #[cfg(target_os = "macos")]
        let admin_peer = PeerPolicyV2 {
            uid: bootstrap.admin_expected_uid,
            gid: bootstrap.admin_expected_gid,
            identity_digest: Digest32V2::new(parse_hex_32(
                bootstrap
                    .admin_code_identity_digest
                    .as_deref()
                    .ok_or(ApprovaldDaemonErrorV2::DeploymentUnavailable)?,
            )?),
        };
        serve(
            agent_listener,
            ingress_listener,
            admin_listener,
            http_listener,
            agent_server,
            ingress_server,
            admin_server,
            authority,
            agent_peer,
            ingress_peer,
            admin_peer,
        )
    }

    #[cfg(target_os = "linux")]
    fn load_native_startup(
        bootstrap: &BootstrapDtoV2,
    ) -> Result<VerifiedDaemonStartupV2, ApprovaldDaemonErrorV2> {
        savana_policy_core::v2::load_verified_filesystem_startup_v2(
            Path::new(MANIFEST_ROOT_PATH_V2),
            &bootstrap.signed_manifest_path,
            &bootstrap.effect_ledger_projection_path,
            &bootstrap.services,
        )
        .map_err(|_| ApprovaldDaemonErrorV2::DeploymentUnavailable)
    }

    #[cfg(all(target_os = "macos", feature = "macos-development-authority"))]
    fn load_native_startup(
        bootstrap: &BootstrapDtoV2,
    ) -> Result<VerifiedDaemonStartupV2, ApprovaldDaemonErrorV2> {
        let root = Path::new("/Library/Application Support/Savana/Development");
        let mut paths = vec![
            &bootstrap.signed_manifest_path,
            &bootstrap.effect_ledger_projection_path,
            &bootstrap.state_path,
            &bootstrap.rollback_anchor_path,
            &bootstrap.kernel_envelope_public_key_path,
            &bootstrap.kernel_correlation_public_key_path,
            &bootstrap.agent_client_public_key_path,
            &bootstrap.ingress_client_public_key_path,
            &bootstrap.admin_client_public_key_path,
        ];
        paths.extend(
            bootstrap
                .attestation_roots
                .iter()
                .map(|entry| &entry.root_certificate_path),
        );
        if paths
            .into_iter()
            .any(|path| !closed_development_path(root, path))
        {
            return Err(ApprovaldDaemonErrorV2::DeploymentUnavailable);
        }
        savana_policy_core::load_verified_macos_development_startup_v2(
            Path::new(MANIFEST_ROOT_PATH_V2),
            &bootstrap.signed_manifest_path,
            &bootstrap.effect_ledger_projection_path,
            &bootstrap.services,
        )
        .map_err(|_| ApprovaldDaemonErrorV2::DeploymentUnavailable)
    }

    #[cfg(all(target_os = "macos", not(feature = "macos-development-authority")))]
    fn load_native_startup(
        _bootstrap: &BootstrapDtoV2,
    ) -> Result<VerifiedDaemonStartupV2, ApprovaldDaemonErrorV2> {
        Err(ApprovaldDaemonErrorV2::DeploymentUnavailable)
    }

    #[cfg(all(target_os = "macos", feature = "macos-development-authority"))]
    fn closed_development_path(root: &Path, path: &Path) -> bool {
        path.is_absolute()
            && path.starts_with(root)
            && !path.components().any(|component| {
                matches!(
                    component,
                    std::path::Component::ParentDir
                        | std::path::Component::CurDir
                        | std::path::Component::Prefix(_)
                )
            })
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[derive(Debug, Clone, Copy)]
    struct PeerPolicyV2 {
        uid: u32,
        gid: u32,
        identity_digest: Digest32V2,
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn peer_policy(lock: &ServiceDeploymentLockV2) -> PeerPolicyV2 {
        PeerPolicyV2 {
            uid: lock.uid,
            gid: lock.gid,
            #[cfg(target_os = "linux")]
            identity_digest: lock.executable_digest,
            #[cfg(target_os = "macos")]
            identity_digest: lock.code_identity_digest,
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[allow(clippy::too_many_arguments)]
    fn serve(
        agent_listener: UnixListener,
        ingress_listener: UnixListener,
        admin_listener: UnixListener,
        http_listener: TcpListener,
        agent_server: Arc<ApprovalSuiteOneServerV2>,
        ingress_server: Arc<ApprovalSuiteOneServerV2>,
        admin_server: Arc<ApprovalSuiteOneServerV2>,
        authority: Arc<ApprovalUiAuthorityV2>,
        agent_peer: PeerPolicyV2,
        ingress_peer: PeerPolicyV2,
        admin_peer: PeerPolicyV2,
    ) -> Result<(), ApprovaldDaemonErrorV2> {
        let (failures, terminated) = mpsc::sync_channel(4);
        let agent_failures = failures.clone();
        std::thread::Builder::new()
            .name("savana-agent-approval-listener-v2".to_owned())
            .spawn(move || {
                let result = serve_uds(agent_listener, agent_server, agent_peer);
                let _ = agent_failures.send(result);
            })
            .map_err(|_| ApprovaldDaemonErrorV2::EndpointUnavailable)?;
        let ingress_failures = failures.clone();
        std::thread::Builder::new()
            .name("savana-ingress-approval-listener-v2".to_owned())
            .spawn(move || {
                let result = serve_uds(ingress_listener, ingress_server, ingress_peer);
                let _ = ingress_failures.send(result);
            })
            .map_err(|_| ApprovaldDaemonErrorV2::EndpointUnavailable)?;
        let admin_failures = failures.clone();
        std::thread::Builder::new()
            .name("savana-admin-approval-listener-v2".to_owned())
            .spawn(move || {
                let result = serve_uds(admin_listener, admin_server, admin_peer);
                let _ = admin_failures.send(result);
            })
            .map_err(|_| ApprovaldDaemonErrorV2::EndpointUnavailable)?;
        std::thread::Builder::new()
            .name("savana-approval-http-listener-v2".to_owned())
            .spawn(move || {
                let result = serve_http(http_listener, authority);
                let _ = failures.send(result);
            })
            .map_err(|_| ApprovaldDaemonErrorV2::EndpointUnavailable)?;
        terminated
            .recv()
            .map_err(|_| ApprovaldDaemonErrorV2::EndpointUnavailable)?
    }

    #[cfg(target_os = "linux")]
    struct UdsJobV2 {
        stream: UnixStream,
        binding: PeerIdentityBindingV2,
        _measurement: savana_platform_identity::PinnedLinuxPeerMeasurementV2,
    }

    #[cfg(target_os = "macos")]
    struct UdsJobV2 {
        stream: UnixStream,
        binding: PeerIdentityBindingV2,
        _measurement: NativePeerMeasurementV2,
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn serve_uds(
        listener: UnixListener,
        server: Arc<ApprovalSuiteOneServerV2>,
        peer: PeerPolicyV2,
    ) -> Result<(), ApprovaldDaemonErrorV2> {
        let (sender, receiver) = mpsc::sync_channel(UDS_QUEUE_CAPACITY_V2);
        let receiver = Arc::new(Mutex::new(receiver));
        for worker_index in 0..UDS_WORKERS_V2 {
            let receiver = Arc::clone(&receiver);
            let server = Arc::clone(&server);
            std::thread::Builder::new()
                .name(format!("savana-approval-uds-worker-{worker_index}-v2"))
                .spawn(move || loop {
                    let job = match receiver.lock() {
                        Ok(receiver) => receiver.recv(),
                        Err(_) => return,
                    };
                    let Ok(job) = job else {
                        return;
                    };
                    let UdsJobV2 {
                        stream,
                        binding,
                        _measurement,
                    } = job;
                    let deadline = match Instant::now().checked_add(CONNECTION_DEADLINE_V2) {
                        Some(value) => value,
                        None => continue,
                    };
                    let _ = server.serve_stream(
                        stream,
                        binding,
                        match current_unix_millis() {
                            Ok(value) => value,
                            Err(_) => continue,
                        },
                        deadline,
                    );
                })
                .map_err(|_| ApprovaldDaemonErrorV2::EndpointUnavailable)?;
        }
        loop {
            let (stream, _) = listener
                .accept()
                .map_err(|_| ApprovaldDaemonErrorV2::EndpointUnavailable)?;
            #[cfg(target_os = "linux")]
            let measurement = match measure_linux_peer_v2(&stream) {
                Ok(value) => value,
                Err(_) => continue,
            };
            #[cfg(target_os = "linux")]
            let binding = match exact_peer_binding(measurement.measurement(), peer) {
                Some(value) => value,
                None => continue,
            };
            #[cfg(target_os = "macos")]
            let measurement = match savana_platform_identity::measure_macos_unix_peer_v2(&stream) {
                Ok(value) => value,
                Err(_) => continue,
            };
            #[cfg(target_os = "macos")]
            let binding = match exact_peer_binding(&measurement, peer) {
                Some(value) => value,
                None => continue,
            };
            if sender
                .try_send(UdsJobV2 {
                    stream,
                    binding,
                    _measurement: measurement,
                })
                .is_err()
            {
                continue;
            }
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn exact_peer_binding(
        measurement: &NativePeerMeasurementV2,
        policy: PeerPolicyV2,
    ) -> Option<PeerIdentityBindingV2> {
        match measurement {
            NativePeerMeasurementV2::Linux {
                uid,
                gid,
                pid,
                process_start_time,
                executable_measurement,
            } if *uid == policy.uid
                && *gid == policy.gid
                && Digest32V2::new(*executable_measurement) == policy.identity_digest =>
            {
                PeerIdentityBindingV2::linux(
                    *uid,
                    *gid,
                    *pid,
                    *process_start_time,
                    policy.identity_digest,
                )
                .ok()
            }
            NativePeerMeasurementV2::MacOs {
                audit_token,
                euid,
                egid,
                bundle_id,
                team_id,
                code_directory_measurement,
                ..
            } if *euid == policy.uid
                && *egid == policy.gid
                && Digest32V2::new(*code_directory_measurement) == policy.identity_digest =>
            {
                PeerIdentityBindingV2::macos(
                    *audit_token,
                    *euid,
                    *egid,
                    bundle_id.as_str().to_owned(),
                    team_id.as_str().to_owned(),
                    policy.identity_digest,
                )
                .ok()
            }
            _ => None,
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn serve_http(
        listener: TcpListener,
        authority: Arc<ApprovalUiAuthorityV2>,
    ) -> Result<(), ApprovaldDaemonErrorV2> {
        let (sender, receiver) = mpsc::sync_channel(HTTP_QUEUE_CAPACITY_V2);
        let receiver = Arc::new(Mutex::new(receiver));
        for worker_index in 0..HTTP_WORKERS_V2 {
            let receiver = Arc::clone(&receiver);
            let authority = Arc::clone(&authority);
            std::thread::Builder::new()
                .name(format!("savana-approval-http-worker-{worker_index}-v2"))
                .spawn(move || loop {
                    let stream = match receiver.lock() {
                        Ok(receiver) => receiver.recv(),
                        Err(_) => return,
                    };
                    let Ok(stream) = stream else {
                        return;
                    };
                    let _ = serve_http_stream(stream, Arc::clone(&authority));
                })
                .map_err(|_| ApprovaldDaemonErrorV2::EndpointUnavailable)?;
        }
        loop {
            let (stream, remote) = listener
                .accept()
                .map_err(|_| ApprovaldDaemonErrorV2::EndpointUnavailable)?;
            if remote.ip() != Ipv4Addr::LOCALHOST {
                continue;
            }
            if sender.try_send(stream).is_err() {
                continue;
            }
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn serve_http_stream(
        mut stream: TcpStream,
        authority: Arc<ApprovalUiAuthorityV2>,
    ) -> Result<(), ApprovaldDaemonErrorV2> {
        stream
            .set_read_timeout(Some(CONNECTION_DEADLINE_V2))
            .and_then(|()| stream.set_write_timeout(Some(CONNECTION_DEADLINE_V2)))
            .map_err(|_| ApprovaldDaemonErrorV2::EndpointUnavailable)?;
        let request = match read_fixed_http_request_v2(&mut stream, FixedHttpServiceV2::Approval) {
            Ok(request) => request,
            Err(FixedHttpErrorV2::NotFound) => {
                return write_http(&mut stream, 404, "text/plain; charset=utf-8", b"")
            }
            Err(FixedHttpErrorV2::UnauthorizedOrigin) => return Ok(()),
            Err(_) => return write_http(&mut stream, 400, "text/plain; charset=utf-8", b""),
        };
        let now = current_unix_millis()?;
        let deadline = Instant::now()
            .checked_add(CONNECTION_DEADLINE_V2)
            .ok_or(ApprovaldDaemonErrorV2::EndpointUnavailable)?;
        match request.route() {
            FixedHttpRouteV2::BrowserScript => write_http(
                &mut stream,
                200,
                "application/javascript; charset=utf-8",
                SAVANA_BROWSER_SCRIPT_V2,
            ),
            FixedHttpRouteV2::ApprovalUiAuthenticationAccept => {
                let transfer = decode_form_transfer(request.body())?;
                let display_transfer =
                    savana_kernel_protocol::v2::ApprovalDisplayAuthenticationTransferCapabilityV2::from_authority_entropy(transfer)
                        .ok_or(ApprovaldDaemonErrorV2::EndpointUnavailable)?;
                let accepted = match request.origin() {
                    Some(savana_kernel_protocol::v2::FixedOriginV2::Ingress8767) => {
                        let ingress_transfer =
                            savana_kernel_protocol::v2::IngressUiAuthenticationTransferCapabilityV2::from_authority_entropy(transfer)
                                .ok_or(ApprovaldDaemonErrorV2::EndpointUnavailable)?;
                        authority
                            .accept_approval_display_transfer(display_transfer)
                            .or_else(|_| authority.accept_ingress_transfer(ingress_transfer))
                    }
                    Some(
                        savana_kernel_protocol::v2::FixedOriginV2::Agent8768
                        | savana_kernel_protocol::v2::FixedOriginV2::Jarvis8765,
                    ) => {
                        let agent_transfer =
                            savana_kernel_protocol::v2::AgentUiAuthenticationTransferCapabilityV2::from_authority_entropy(transfer)
                                .ok_or(ApprovaldDaemonErrorV2::EndpointUnavailable)?;
                        authority
                            .accept_approval_display_transfer(display_transfer)
                            .or_else(|_| authority.accept_agent_transfer(agent_transfer))
                    }
                    _ => return Ok(()),
                }
                .map_err(|_| ApprovaldDaemonErrorV2::EndpointUnavailable)?;
                let body = render_authentication_shell(accepted)?;
                write_http(&mut stream, 200, "text/html; charset=utf-8", &body)
            }
            FixedHttpRouteV2::ApprovalUiAuthenticationBegin => {
                let decoded = decode_ui_authentication_browser_begin_request_v2(request.body())
                    .map_err(|_| ApprovaldDaemonErrorV2::EndpointUnavailable)?;
                let response = authority
                    .begin(decoded, now, deadline)
                    .map_err(|_| ApprovaldDaemonErrorV2::EndpointUnavailable)?;
                let body = encode_ui_authentication_browser_begin_response_v2(&response)
                    .map_err(|_| ApprovaldDaemonErrorV2::EndpointUnavailable)?;
                write_http(&mut stream, 200, "application/cbor", &body)
            }
            FixedHttpRouteV2::ApprovalUiAuthenticationFinish => {
                let digest = request_digest(request.body());
                let decoded = decode_ui_authentication_browser_finish_request_v2(request.body())
                    .map_err(|_| ApprovaldDaemonErrorV2::EndpointUnavailable)?;
                let response = authority
                    .finish(decoded, digest, now, deadline)
                    .map_err(|_| ApprovaldDaemonErrorV2::EndpointUnavailable)?;
                let body = encode_ui_authentication_browser_finish_response_v2(response)
                    .map_err(|_| ApprovaldDaemonErrorV2::EndpointUnavailable)?;
                write_http(&mut stream, 200, "application/cbor", &body)
            }
            FixedHttpRouteV2::ApprovalDisplay => {
                let decoded = decode_approval_display_browser_request_v2(request.body())
                    .map_err(|_| ApprovaldDaemonErrorV2::EndpointUnavailable)?;
                let view = authority
                    .approval_display(decoded.tab(), now, deadline)
                    .map_err(|_| ApprovaldDaemonErrorV2::EndpointUnavailable)?;
                let body = encode_approval_display_view_v2(view)
                    .map_err(|_| ApprovaldDaemonErrorV2::EndpointUnavailable)?;
                write_http(&mut stream, 200, "application/cbor", &body)
            }
            FixedHttpRouteV2::ApprovalDecisionBegin => {
                let decoded = decode_approval_decision_browser_begin_request_v2(request.body())
                    .map_err(|_| ApprovaldDaemonErrorV2::EndpointUnavailable)?;
                let response = authority
                    .begin_approval_decision(decoded, now, deadline)
                    .map_err(|_| ApprovaldDaemonErrorV2::EndpointUnavailable)?;
                let body = encode_approval_decision_browser_begin_response_v2(&response)
                    .map_err(|_| ApprovaldDaemonErrorV2::EndpointUnavailable)?;
                write_http(&mut stream, 200, "application/cbor", &body)
            }
            FixedHttpRouteV2::ApprovalDecisionFinish => {
                let digest = request_digest(request.body());
                let decoded = decode_approval_decision_browser_finish_request_v2(request.body())
                    .map_err(|_| ApprovaldDaemonErrorV2::EndpointUnavailable)?;
                let response = authority
                    .finish_approval_decision(decoded, digest, now, deadline)
                    .map_err(|_| ApprovaldDaemonErrorV2::EndpointUnavailable)?;
                let body = encode_approval_decision_browser_finish_response_v2(response)
                    .map_err(|_| ApprovaldDaemonErrorV2::EndpointUnavailable)?;
                write_http(&mut stream, 200, "application/cbor", &body)
            }
            FixedHttpRouteV2::ApprovalEnrollmentBootstrap => write_http(
                &mut stream,
                200,
                "text/html; charset=utf-8",
                b"<!doctype html><html><head><meta charset=\"utf-8\"><title>Savana enrollment</title></head><body><main data-enrollment=\"true\"><h1>Enroll hardware security key</h1><label for=\"savana-enrollment-handle\">Enrollment handle</label><input id=\"savana-enrollment-handle\" autocomplete=\"off\"><label for=\"savana-enrollment-code\">One-time code</label><input id=\"savana-enrollment-code\" type=\"password\" autocomplete=\"one-time-code\"><button id=\"savana-enrollment-start\" type=\"button\">Enroll security key</button><p id=\"savana-status\">Enrollment values stay in this page only.</p></main><script src=\"/v2/savana-ui.js\" defer></script></body></html>",
            ),
            FixedHttpRouteV2::ApprovalEnrollmentBegin => {
                let decoded = decode_begin_enrollment_browser_request_v2(request.body())
                    .map_err(|_| ApprovaldDaemonErrorV2::EndpointUnavailable)?;
                let response = authority
                    .begin_enrollment(decoded, now, deadline)
                    .map_err(|_| ApprovaldDaemonErrorV2::EndpointUnavailable)?;
                let body = encode_begin_enrollment_browser_response_v2(&response)
                    .map_err(|_| ApprovaldDaemonErrorV2::EndpointUnavailable)?;
                write_http(&mut stream, 200, "application/cbor", &body)
            }
            FixedHttpRouteV2::ApprovalEnrollmentFinish => {
                let decoded = decode_finish_enrollment_browser_request_v2(request.body())
                    .map_err(|_| ApprovaldDaemonErrorV2::EndpointUnavailable)?;
                let response = authority
                    .finish_enrollment(decoded, now, deadline)
                    .map_err(|_| ApprovaldDaemonErrorV2::EndpointUnavailable)?;
                let body = encode_finish_enrollment_browser_response_v2(response)
                    .map_err(|_| ApprovaldDaemonErrorV2::EndpointUnavailable)?;
                write_http(&mut stream, 200, "application/cbor", &body)
            }
            _ => write_http(&mut stream, 404, "text/plain; charset=utf-8", b""),
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn render_authentication_shell(
        accepted: AcceptedUiAuthenticationV2,
    ) -> Result<Vec<u8>, ApprovaldDaemonErrorV2> {
        let (purpose, encoded) = match accepted {
            AcceptedUiAuthenticationV2::Ingress { pre_authentication } => (
                "ingress",
                minicbor::to_vec(pre_authentication)
                    .map_err(|_| ApprovaldDaemonErrorV2::EndpointUnavailable)?,
            ),
            AcceptedUiAuthenticationV2::Agent { pre_authentication } => (
                "agent",
                minicbor::to_vec(pre_authentication)
                    .map_err(|_| ApprovaldDaemonErrorV2::EndpointUnavailable)?,
            ),
            AcceptedUiAuthenticationV2::ApprovalDisplay { pre_authentication } => (
                "approval-display",
                minicbor::to_vec(pre_authentication)
                    .map_err(|_| ApprovaldDaemonErrorV2::EndpointUnavailable)?,
            ),
        };
        let capability = URL_SAFE_NO_PAD.encode(encoded);
        Ok(format!(
            "<!doctype html><html><head><meta charset=\"utf-8\"><title>Savana authentication</title></head><body><main data-purpose=\"{purpose}\" data-pre-authentication=\"{capability}\"><h1>Hardware authentication required</h1><button id=\"savana-authenticate\" type=\"button\">Use security key</button><p id=\"savana-status\">The opaque capability is held only in this page.</p></main><script src=\"/v2/savana-ui.js\" defer></script></body></html>"
        )
        .into_bytes())
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn write_http(
        stream: &mut TcpStream,
        status: u16,
        content_type: &str,
        body: &[u8],
    ) -> Result<(), ApprovaldDaemonErrorV2> {
        write_fixed_http_response_v2(stream, status, content_type, body)
            .map_err(|_| ApprovaldDaemonErrorV2::EndpointUnavailable)
    }

    #[cfg(target_os = "linux")]
    fn take_verified_listeners(
        startup: &VerifiedDaemonStartupV2,
    ) -> Result<(UnixListener, UnixListener, UnixListener, TcpListener), ApprovaldDaemonErrorV2>
    {
        let inherited = savana_platform_identity::take_systemd_listeners_v2(&[
            AGENT_FD_NAME_V2,
            INGRESS_FD_NAME_V2,
            ADMIN_FD_NAME_V2,
            HTTP_FD_NAME_V2,
        ])
        .map_err(|_| ApprovaldDaemonErrorV2::EndpointUnavailable)?;
        let mut inherited = inherited.into_iter();
        let (agent_name, agent_listener) = inherited
            .next()
            .ok_or(ApprovaldDaemonErrorV2::EndpointUnavailable)?
            .into_unix_listener();
        let (ingress_name, ingress_listener) = inherited
            .next()
            .ok_or(ApprovaldDaemonErrorV2::EndpointUnavailable)?
            .into_unix_listener();
        let (admin_name, admin_listener) = inherited
            .next()
            .ok_or(ApprovaldDaemonErrorV2::EndpointUnavailable)?
            .into_unix_listener();
        let (http_name, http_listener) = inherited
            .next()
            .ok_or(ApprovaldDaemonErrorV2::EndpointUnavailable)?
            .into_tcp_listener();
        if inherited.next().is_some()
            || agent_name != AGENT_FD_NAME_V2
            || ingress_name != INGRESS_FD_NAME_V2
            || admin_name != ADMIN_FD_NAME_V2
            || http_name != HTTP_FD_NAME_V2
        {
            return Err(ApprovaldDaemonErrorV2::EndpointUnavailable);
        }
        let approval_service = startup
            .service_lock(ClosedServiceIdV2::Approvald)
            .ok_or(ApprovaldDaemonErrorV2::DeploymentUnavailable)?;
        let agent_service = startup
            .service_lock(ClosedServiceIdV2::Agentd)
            .ok_or(ApprovaldDaemonErrorV2::DeploymentUnavailable)?;
        let ingress_service = startup
            .service_lock(ClosedServiceIdV2::Ingressd)
            .ok_or(ApprovaldDaemonErrorV2::DeploymentUnavailable)?;
        verify_role_unix_listener(
            &agent_listener,
            Path::new(AGENT_SOCKET_PATH_V2),
            approval_service.uid,
            agent_service.gid,
        )?;
        verify_role_unix_listener(
            &ingress_listener,
            Path::new(INGRESS_SOCKET_PATH_V2),
            approval_service.uid,
            ingress_service.gid,
        )?;
        verify_admin_unix_listener(&admin_listener, Path::new(ADMIN_SOCKET_PATH_V2))?;
        if !getsockopt(&http_listener, AcceptConn)
            .map_err(|_| ApprovaldDaemonErrorV2::EndpointUnavailable)?
            || http_listener
                .local_addr()
                .map_err(|_| ApprovaldDaemonErrorV2::EndpointUnavailable)?
                != SocketAddr::from((Ipv4Addr::LOCALHOST, 8766))
        {
            return Err(ApprovaldDaemonErrorV2::EndpointUnavailable);
        }
        Ok((
            agent_listener,
            ingress_listener,
            admin_listener,
            http_listener,
        ))
    }

    #[cfg(target_os = "macos")]
    fn take_verified_listeners(
        startup: &VerifiedDaemonStartupV2,
    ) -> Result<(UnixListener, UnixListener, UnixListener, TcpListener), ApprovaldDaemonErrorV2>
    {
        let inherited = savana_platform_identity::take_launchd_unix_listeners_v2(&[
            AGENT_FD_NAME_V2,
            INGRESS_FD_NAME_V2,
            ADMIN_FD_NAME_V2,
        ])
        .map_err(|_| ApprovaldDaemonErrorV2::EndpointUnavailable)?;
        let mut inherited = inherited.into_iter();
        let (agent_name, agent_listener) = inherited
            .next()
            .ok_or(ApprovaldDaemonErrorV2::EndpointUnavailable)?
            .into_parts();
        let (ingress_name, ingress_listener) = inherited
            .next()
            .ok_or(ApprovaldDaemonErrorV2::EndpointUnavailable)?
            .into_parts();
        let (admin_name, admin_listener) = inherited
            .next()
            .ok_or(ApprovaldDaemonErrorV2::EndpointUnavailable)?
            .into_parts();
        let http = savana_platform_identity::take_launchd_tcp_listeners_v2(&[HTTP_FD_NAME_V2])
            .map_err(|_| ApprovaldDaemonErrorV2::EndpointUnavailable)?;
        let mut http = http.into_iter();
        let (http_name, http_listener) = http
            .next()
            .ok_or(ApprovaldDaemonErrorV2::EndpointUnavailable)?
            .into_parts();
        if inherited.next().is_some()
            || http.next().is_some()
            || agent_name != AGENT_FD_NAME_V2
            || ingress_name != INGRESS_FD_NAME_V2
            || admin_name != ADMIN_FD_NAME_V2
            || http_name != HTTP_FD_NAME_V2
        {
            return Err(ApprovaldDaemonErrorV2::EndpointUnavailable);
        }
        let approval_service = startup
            .service_lock(ClosedServiceIdV2::Approvald)
            .ok_or(ApprovaldDaemonErrorV2::DeploymentUnavailable)?;
        let agent_service = startup
            .service_lock(ClosedServiceIdV2::Agentd)
            .ok_or(ApprovaldDaemonErrorV2::DeploymentUnavailable)?;
        let ingress_service = startup
            .service_lock(ClosedServiceIdV2::Ingressd)
            .ok_or(ApprovaldDaemonErrorV2::DeploymentUnavailable)?;
        verify_role_unix_listener(
            &agent_listener,
            Path::new(AGENT_SOCKET_PATH_V2),
            approval_service.uid,
            agent_service.gid,
        )?;
        verify_role_unix_listener(
            &ingress_listener,
            Path::new(INGRESS_SOCKET_PATH_V2),
            approval_service.uid,
            ingress_service.gid,
        )?;
        verify_admin_unix_listener(&admin_listener, Path::new(ADMIN_SOCKET_PATH_V2))?;
        if http_listener
            .local_addr()
            .map_err(|_| ApprovaldDaemonErrorV2::EndpointUnavailable)?
            != SocketAddr::from((Ipv4Addr::LOCALHOST, 8766))
        {
            return Err(ApprovaldDaemonErrorV2::EndpointUnavailable);
        }
        Ok((
            agent_listener,
            ingress_listener,
            admin_listener,
            http_listener,
        ))
    }

    #[cfg(target_os = "linux")]
    fn verify_role_unix_listener(
        listener: &UnixListener,
        path: &Path,
        expected_uid: u32,
        expected_gid: u32,
    ) -> Result<(), ApprovaldDaemonErrorV2> {
        let metadata =
            fs::symlink_metadata(path).map_err(|_| ApprovaldDaemonErrorV2::EndpointUnavailable)?;
        let descriptor =
            fstat(listener).map_err(|_| ApprovaldDaemonErrorV2::EndpointUnavailable)?;
        if !getsockopt(listener, AcceptConn)
            .map_err(|_| ApprovaldDaemonErrorV2::EndpointUnavailable)?
            || listener
                .local_addr()
                .map_err(|_| ApprovaldDaemonErrorV2::EndpointUnavailable)?
                .as_pathname()
                != Some(path)
            || FileType::from_raw_mode(descriptor.st_mode) != FileType::Socket
            || metadata.file_type().is_symlink()
            || !metadata.file_type().is_socket()
            || metadata.uid() != expected_uid
            || metadata.gid() != expected_gid
            || metadata.mode() & 0o7777 != 0o660
        {
            return Err(ApprovaldDaemonErrorV2::EndpointUnavailable);
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn verify_admin_unix_listener(
        listener: &UnixListener,
        path: &Path,
    ) -> Result<(), ApprovaldDaemonErrorV2> {
        let metadata =
            fs::symlink_metadata(path).map_err(|_| ApprovaldDaemonErrorV2::EndpointUnavailable)?;
        let descriptor =
            fstat(listener).map_err(|_| ApprovaldDaemonErrorV2::EndpointUnavailable)?;
        if !getsockopt(listener, AcceptConn)
            .map_err(|_| ApprovaldDaemonErrorV2::EndpointUnavailable)?
            || listener
                .local_addr()
                .map_err(|_| ApprovaldDaemonErrorV2::EndpointUnavailable)?
                .as_pathname()
                != Some(path)
            || FileType::from_raw_mode(descriptor.st_mode) != FileType::Socket
            || metadata.file_type().is_symlink()
            || !metadata.file_type().is_socket()
            || metadata.uid() != 0
            || metadata.gid() != 0
            || metadata.mode() & 0o7777 != 0o600
        {
            return Err(ApprovaldDaemonErrorV2::EndpointUnavailable);
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn verify_role_unix_listener(
        listener: &UnixListener,
        path: &Path,
        expected_uid: u32,
        expected_gid: u32,
    ) -> Result<(), ApprovaldDaemonErrorV2> {
        let metadata =
            fs::symlink_metadata(path).map_err(|_| ApprovaldDaemonErrorV2::EndpointUnavailable)?;
        if listener
            .local_addr()
            .map_err(|_| ApprovaldDaemonErrorV2::EndpointUnavailable)?
            .as_pathname()
            != Some(path)
            || metadata.file_type().is_symlink()
            || !metadata.file_type().is_socket()
            || metadata.uid() != expected_uid
            || metadata.gid() != expected_gid
            || metadata.mode() & 0o7777 != 0o660
        {
            return Err(ApprovaldDaemonErrorV2::EndpointUnavailable);
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn verify_admin_unix_listener(
        listener: &UnixListener,
        path: &Path,
    ) -> Result<(), ApprovaldDaemonErrorV2> {
        let metadata =
            fs::symlink_metadata(path).map_err(|_| ApprovaldDaemonErrorV2::EndpointUnavailable)?;
        if listener
            .local_addr()
            .map_err(|_| ApprovaldDaemonErrorV2::EndpointUnavailable)?
            .as_pathname()
            != Some(path)
            || metadata.file_type().is_symlink()
            || !metadata.file_type().is_socket()
            || metadata.uid() != 0
            || metadata.gid() != 0
            || metadata.mode() & 0o7777 != 0o600
        {
            return Err(ApprovaldDaemonErrorV2::EndpointUnavailable);
        }
        Ok(())
    }

    fn load_hardware_credentials(
        deployment: &mut ProtocolApprovalServiceV2,
        credentials: &[HardwareCredentialDtoV2],
    ) -> Result<(), ApprovaldDaemonErrorV2> {
        if credentials.len() > 256 {
            return Err(ApprovaldDaemonErrorV2::DeploymentUnavailable);
        }
        for credential in credentials {
            deployment
                .load_verified_hardware_credential(
                    Digest32V2::new(parse_hex_32(&credential.credential_digest)?),
                    PrincipalIdV2::new(parse_hex_32(&credential.principal)?),
                    parse_hex_16(&credential.aaguid)?,
                    parse_hex_65(&credential.p256_sec1_public_key)?,
                    credential.signature_counter,
                )
                .map_err(|_| ApprovaldDaemonErrorV2::DeploymentUnavailable)?;
        }
        Ok(())
    }

    fn load_enrollment_profiles(
        deployment: &mut ProtocolApprovalServiceV2,
        profiles: &[EnrollmentProfileDtoV2],
    ) -> Result<(), ApprovaldDaemonErrorV2> {
        if profiles.is_empty() || profiles.len() > 64 {
            return Err(ApprovaldDaemonErrorV2::DeploymentUnavailable);
        }
        for profile in profiles {
            deployment
                .load_verified_enrollment_profile(
                    EnrollmentProfileIdV2::new(profile.profile),
                    profile.code_lifetime_ms,
                    profile.ceremony_lifetime_ms,
                )
                .map_err(|_| ApprovaldDaemonErrorV2::DeploymentUnavailable)?;
        }
        Ok(())
    }

    fn load_attestation_roots(
        roots: &[AttestationRootDtoV2],
    ) -> Result<Vec<HardwareAttestationRootV2>, ApprovaldDaemonErrorV2> {
        if roots.is_empty() || roots.len() > 256 {
            return Err(ApprovaldDaemonErrorV2::DeploymentUnavailable);
        }
        let mut loaded = Vec::new();
        loaded
            .try_reserve_exact(roots.len())
            .map_err(|_| ApprovaldDaemonErrorV2::DeploymentUnavailable)?;
        for root in roots {
            let certificate = read_verified_regular_file_v2(
                &root.root_certificate_path,
                64 * 1024,
                Some((0, 0, 0o444)),
            )
            .map_err(|_| ApprovaldDaemonErrorV2::DeploymentUnavailable)?;
            loaded.push(
                HardwareAttestationRootV2::new(
                    parse_hex_16(&root.aaguid)?,
                    Digest32V2::new(parse_hex_32(&root.root_certificate_sha256)?),
                    Digest32V2::new(parse_hex_32(&root.root_spki_sha256)?),
                    certificate,
                )
                .map_err(|_| ApprovaldDaemonErrorV2::DeploymentUnavailable)?,
            );
        }
        Ok(loaded)
    }

    fn read_public_key(path: &Path) -> Result<[u8; 32], ApprovaldDaemonErrorV2> {
        let bytes = read_verified_regular_file_v2(path, 64, Some((0, 0, 0o444)))
            .map_err(|_| ApprovaldDaemonErrorV2::DeploymentUnavailable)?;
        bytes
            .as_slice()
            .try_into()
            .map_err(|_| ApprovaldDaemonErrorV2::DeploymentUnavailable)
    }

    fn read_credential_32(name: &str) -> Result<[u8; 32], ApprovaldDaemonErrorV2> {
        let path = Path::new(CREDENTIAL_DIRECTORY_V2).join(name);
        #[cfg(target_os = "linux")]
        let identity = (0, 0, 0o400);
        #[cfg(target_os = "macos")]
        let identity = (0, nix::unistd::getegid().as_raw(), 0o440);
        let bytes = read_verified_regular_file_v2(&path, 32, Some(identity))
            .map_err(|_| ApprovaldDaemonErrorV2::DeploymentUnavailable)?;
        bytes
            .as_slice()
            .try_into()
            .map_err(|_| ApprovaldDaemonErrorV2::DeploymentUnavailable)
    }

    fn parse_hex_32(value: &str) -> Result<[u8; 32], ApprovaldDaemonErrorV2> {
        decode_hex_32_v2(value).map_err(|_| ApprovaldDaemonErrorV2::DeploymentUnavailable)
    }

    fn parse_hex_16(value: &str) -> Result<[u8; 16], ApprovaldDaemonErrorV2> {
        decode_hex(value)
    }

    fn parse_hex_65(value: &str) -> Result<[u8; 65], ApprovaldDaemonErrorV2> {
        decode_hex(value)
    }

    fn decode_hex<const N: usize>(value: &str) -> Result<[u8; N], ApprovaldDaemonErrorV2> {
        if value.len() != N * 2 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(ApprovaldDaemonErrorV2::DeploymentUnavailable);
        }
        let mut decoded = [0_u8; N];
        for (index, slot) in decoded.iter_mut().enumerate() {
            let offset = index * 2;
            *slot = u8::from_str_radix(&value[offset..offset + 2], 16)
                .map_err(|_| ApprovaldDaemonErrorV2::DeploymentUnavailable)?;
        }
        if decoded.iter().all(|byte| *byte == 0) {
            return Err(ApprovaldDaemonErrorV2::DeploymentUnavailable);
        }
        Ok(decoded)
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn decode_form_transfer(body: &[u8]) -> Result<[u8; 32], ApprovaldDaemonErrorV2> {
        let encoded = body
            .strip_prefix(b"transfer=")
            .ok_or(ApprovaldDaemonErrorV2::EndpointUnavailable)?;
        if encoded.contains(&b'&') || encoded.contains(&b'%') || encoded.contains(&b'+') {
            return Err(ApprovaldDaemonErrorV2::EndpointUnavailable);
        }
        let decoded = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| ApprovaldDaemonErrorV2::EndpointUnavailable)?;
        let transfer: [u8; 32] = decoded
            .try_into()
            .map_err(|_| ApprovaldDaemonErrorV2::EndpointUnavailable)?;
        if transfer == [0; 32] {
            return Err(ApprovaldDaemonErrorV2::EndpointUnavailable);
        }
        Ok(transfer)
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn request_digest(bytes: &[u8]) -> Digest32V2 {
        let mut hasher = Sha256::new();
        hasher.update(FINISH_REQUEST_DIGEST_DOMAIN_V2);
        hasher.update(bytes);
        Digest32V2::new(hasher.finalize().into())
    }

    fn current_unix_millis() -> Result<UnixMillisV2, ApprovaldDaemonErrorV2> {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ApprovaldDaemonErrorV2::EndpointUnavailable)?;
        let millis = u64::try_from(duration.as_millis())
            .map_err(|_| ApprovaldDaemonErrorV2::EndpointUnavailable)?;
        if millis == 0 {
            return Err(ApprovaldDaemonErrorV2::EndpointUnavailable);
        }
        Ok(UnixMillisV2::new(millis))
    }
}

pub fn run(config_path: &std::path::Path) -> Result<(), ApprovaldDaemonErrorV2> {
    implementation::run(config_path)
}
