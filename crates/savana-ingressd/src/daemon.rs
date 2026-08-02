#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum IngressdDaemonErrorV2 {
    #[error("ingress production deployment is unavailable")]
    DeploymentUnavailable,
    #[error("ingress service endpoint is unavailable")]
    EndpointUnavailable,
}

#[cfg_attr(
    not(any(target_os = "linux", target_os = "macos")),
    allow(dead_code, unused_imports)
)]
mod implementation {
    use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
    use std::path::{Path, PathBuf};
    use std::sync::{mpsc, Arc, Mutex};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use ed25519_dalek::SigningKey;
    #[cfg(target_os = "linux")]
    use nix::sys::socket::{getsockopt, sockopt::AcceptConn};
    use savana_approvald::ApprovalSuiteOneClientV2;
    use savana_kernel_protocol::v2::{
        decode_ingress_browser_request_v2, derive_ed25519_key_id_v2,
        encode_ingress_browser_mutation_response_v2, read_fixed_http_request_v2,
        render_ingress_ui_authentication_form_v2, render_ingress_workspace_v2,
        write_fixed_http_response_v2, BootIdV2, ClosedExtensionClassV2, ClosedMediaTypeV2,
        Digest32V2, Ed25519KeyIdV2, EndpointRoleV2, FixedHttpErrorV2, FixedHttpRouteV2,
        FixedHttpServiceV2, ImplementationIdV2, IngressBrowserRequestV2,
        IngressUiAuthenticationSettlementTransferCapabilityV2,
        KernelIngressBootstrapTransferCapabilityV2, PeerIdentityBindingV2, UnixMillisV2, VersionV2,
        SAVANA_BROWSER_SCRIPT_V2,
    };
    use savana_platform_identity::NativePeerMeasurementV2;
    #[cfg(target_os = "linux")]
    use savana_platform_identity::{pin_current_linux_service_v2, PinnedLinuxPeerMeasurementV2};
    #[cfg(target_os = "macos")]
    use savana_platform_identity::{pin_current_macos_service_v2, PinnedMacOsServiceV2};
    use savana_policy_core::v2::{
        decode_hex_32_v2, read_verified_regular_file_v2, ClosedServiceEdgeIdV2, ClosedServiceIdV2,
        FilesystemServiceObservationConfigV2, ServiceDeploymentLockV2, VerifiedDaemonStartupV2,
    };
    use serde::Deserialize;
    use sha2::{Digest as _, Sha256};
    use signal_hook::consts::signal::SIGHUP;
    use signal_hook::iterator::Signals;
    use zeroize::Zeroizing;

    use super::IngressdDaemonErrorV2;
    use crate::protocol_parser::{ParserProfileV2, ProtocolParserRuntimeV2};
    use crate::{IngressBrowserAuthorityV2, SuiteOneIngressKernelClientV2};

    #[cfg(target_os = "linux")]
    const NATIVE_BOOTSTRAP_PATH_V2: &str = "/etc/savana/ingressd-bootstrap-v2.json";
    #[cfg(target_os = "macos")]
    const NATIVE_BOOTSTRAP_PATH_V2: &str =
        "/Library/Application Support/Savana/Development/config/ingressd-bootstrap-v2.json";
    #[cfg(target_os = "linux")]
    const MANIFEST_ROOT_PATH_V2: &str = "/etc/savana/trust/deployment-manifest-root-v2.json";
    #[cfg(all(target_os = "macos", feature = "macos-development-authority"))]
    const MANIFEST_ROOT_PATH_V2: &str = "/Library/Application Support/Savana/Development/config/trust/deployment-manifest-root-v2.json";
    #[cfg(target_os = "linux")]
    const KERNEL_SERVER_PUBLIC_KEY_PATH_V2: &str =
        "/etc/savana/ingressd/keys/kerneld-ingress-v2.pub";
    #[cfg(target_os = "macos")]
    const KERNEL_SERVER_PUBLIC_KEY_PATH_V2: &str = "/Library/Application Support/Savana/Development/config/ingressd/keys/kerneld-ingress-v2.pub";
    #[cfg(target_os = "linux")]
    const APPROVAL_SERVER_PUBLIC_KEY_PATH_V2: &str = "/etc/savana/ingressd/keys/approvald-v2.pub";
    #[cfg(target_os = "macos")]
    const APPROVAL_SERVER_PUBLIC_KEY_PATH_V2: &str =
        "/Library/Application Support/Savana/Development/config/ingressd/keys/approvald-v2.pub";
    #[cfg(target_os = "linux")]
    const CREDENTIAL_DIRECTORY_V2: &str = "/run/credentials/savana-ingressd.service";
    #[cfg(target_os = "macos")]
    const CREDENTIAL_DIRECTORY_V2: &str =
        "/Library/Application Support/Savana/Development/credentials/ingressd";
    const KERNEL_CLIENT_SEED_CREDENTIAL_V2: &str = "ingress-kernel-v2.seed";
    const APPROVAL_CLIENT_SEED_CREDENTIAL_V2: &str = "ingress-approval-v2.seed";
    const PARSER_DESCRIPTOR_SEED_CREDENTIAL_V2: &str = "parser-descriptor-v2.seed";
    const INGRESSD_BOOT_CREDENTIAL_V2: &str = "ingressd-boot-v2.id";
    const KERNELD_BOOT_CREDENTIAL_V2: &str = "kerneld-boot-v2.id";
    const APPROVALD_BOOT_CREDENTIAL_V2: &str = "approvald-boot-v2.id";
    const HTTP_FD_NAME_V2: &str = "savana-ingress-http";
    const MAX_BOOTSTRAP_BYTES_V2: usize = 128 * 1024;
    const HTTP_WORKERS_V2: usize = 8;
    const HTTP_QUEUE_CAPACITY_V2: usize = 32;
    const CONNECTION_DEADLINE_V2: Duration = Duration::from_secs(10);
    const REQUEST_DIGEST_DOMAIN_V2: &[u8] = b"SAVANA_INGRESS_HTTP_REQUEST_V2\0";

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
        approval_client_key_id: String,
        approval_server_key_id: String,
        parser: ParserDtoV2,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ParserDtoV2 {
        descriptor_key_id: String,
        declared_media_type: u32,
        detected_media_type: u32,
        extension_class: u32,
        implementation_id: u32,
        semantic_version: [u16; 3],
        parser_code_digest: String,
        renderer_code_digest: Option<String>,
        ocr_model_set_digest: Option<String>,
        normalization_version: [u16; 3],
        worker_artifact_digest: String,
        output_limit_bytes: u32,
        maximum_pages: u32,
        output_limits_digest: String,
        sandbox_program_path: PathBuf,
        sandbox_program_digest: String,
        worker_program_path: PathBuf,
        sandbox_profile_path: PathBuf,
        sandbox_profile_digest: String,
        file_owner_uid: u32,
        file_owner_gid: u32,
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    pub(crate) fn run(_config_path: &Path) -> Result<(), IngressdDaemonErrorV2> {
        Err(IngressdDaemonErrorV2::DeploymentUnavailable)
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(crate) fn run(config_path: &Path) -> Result<(), IngressdDaemonErrorV2> {
        if config_path != Path::new(NATIVE_BOOTSTRAP_PATH_V2) {
            return Err(IngressdDaemonErrorV2::DeploymentUnavailable);
        }
        let reload_signals =
            Signals::new([SIGHUP]).map_err(|_| IngressdDaemonErrorV2::DeploymentUnavailable)?;
        let (_bytes, bootstrap, startup) = load_verified_fixed_startup()?;
        let listener = take_verified_listener()?;
        let ingressd_boot_id = BootIdV2::new(read_credential_32(INGRESSD_BOOT_CREDENTIAL_V2)?);
        let kerneld_boot_id = BootIdV2::new(read_credential_32(KERNELD_BOOT_CREDENTIAL_V2)?);
        let approvald_boot_id = BootIdV2::new(read_credential_32(APPROVALD_BOOT_CREDENTIAL_V2)?);
        let self_lock = startup
            .service_lock(ClosedServiceIdV2::Ingressd)
            .ok_or(IngressdDaemonErrorV2::DeploymentUnavailable)?;
        #[cfg(target_os = "linux")]
        let self_process = pin_current_linux_service_v2(
            self_lock.uid,
            self_lock.gid,
            *self_lock.executable_digest.as_bytes(),
        )
        .map_err(|_| IngressdDaemonErrorV2::DeploymentUnavailable)?;
        #[cfg(target_os = "macos")]
        let self_process = pin_current_macos_service_v2(
            self_lock.uid,
            self_lock.gid,
            *self_lock.executable_digest.as_bytes(),
            *self_lock.code_identity_digest.as_bytes(),
        )
        .map_err(|_| IngressdDaemonErrorV2::DeploymentUnavailable)?;
        let self_binding = current_process_binding(self_lock, &self_process)?;

        let kernel_edge_lock = startup
            .edge_lock(ClosedServiceEdgeIdV2::IngressKernel)
            .ok_or(IngressdDaemonErrorV2::DeploymentUnavailable)?;
        let kernel_seed = Zeroizing::new(read_credential_32(KERNEL_CLIENT_SEED_CREDENTIAL_V2)?);
        let kernel_signing_key = SigningKey::from_bytes(&kernel_seed);
        let kernel_public_key = read_public_key(Path::new(KERNEL_SERVER_PUBLIC_KEY_PATH_V2))?;
        if derive_ed25519_key_id_v2(kernel_signing_key.verifying_key().to_bytes())
            != kernel_edge_lock.client_handshake_key_id
            || derive_ed25519_key_id_v2(kernel_public_key)
                != kernel_edge_lock.server_handshake_key_id
        {
            return Err(IngressdDaemonErrorV2::DeploymentUnavailable);
        }
        let kernel = SuiteOneIngressKernelClientV2::from_verified_startup(
            &startup,
            ingressd_boot_id,
            kerneld_boot_id,
            self_binding.clone(),
            kernel_signing_key,
            kernel_public_key,
            move || {
                load_verified_fixed_startup()
                    .map(|(_, _, startup)| startup)
                    .map_err(|_| ())
            },
        )
        .map_err(|_| IngressdDaemonErrorV2::DeploymentUnavailable)?;
        spawn_kernel_reload_signal(reload_signals, kernel.clone())?;

        let approval_seed = Zeroizing::new(read_credential_32(APPROVAL_CLIENT_SEED_CREDENTIAL_V2)?);
        let approval_signing_key = SigningKey::from_bytes(&approval_seed);
        let approval_public_key = read_public_key(Path::new(APPROVAL_SERVER_PUBLIC_KEY_PATH_V2))?;
        let approval_client_key_id =
            Ed25519KeyIdV2::new(parse_hex_32(&bootstrap.approval_client_key_id)?);
        let approval_server_key_id =
            Ed25519KeyIdV2::new(parse_hex_32(&bootstrap.approval_server_key_id)?);
        if derive_ed25519_key_id_v2(approval_signing_key.verifying_key().to_bytes())
            != approval_client_key_id
            || derive_ed25519_key_id_v2(approval_public_key) != approval_server_key_id
        {
            return Err(IngressdDaemonErrorV2::DeploymentUnavailable);
        }
        let approval_edge = startup
            .approval_service_handshake_edge(
                EndpointRoleV2::IngressApproval,
                approval_client_key_id,
                approval_server_key_id,
                approvald_boot_id,
            )
            .map_err(|_| IngressdDaemonErrorV2::DeploymentUnavailable)?;
        let approval = ApprovalSuiteOneClientV2::from_verified_deployment(
            approval_edge,
            ingressd_boot_id,
            self_binding,
            approval_signing_key,
            approval_public_key,
        )
        .map_err(|_| IngressdDaemonErrorV2::DeploymentUnavailable)?;
        let parser = &bootstrap.parser;
        let parser_seed = Zeroizing::new(read_credential_32(PARSER_DESCRIPTOR_SEED_CREDENTIAL_V2)?);
        let parser_signing_key = SigningKey::from_bytes(&parser_seed);
        let parser_runtime = ProtocolParserRuntimeV2::from_verified_deployment(
            startup.installation_id(),
            startup.active_state_manifest_digest(),
            startup.deployment_generation(),
            startup
                .service_identity(ClosedServiceIdV2::Ingressd)
                .ok_or(IngressdDaemonErrorV2::DeploymentUnavailable)?,
            parser_signing_key,
            Ed25519KeyIdV2::new(parse_hex_32(&parser.descriptor_key_id)?),
            ParserProfileV2 {
                declared_media_type: ClosedMediaTypeV2::new(parser.declared_media_type),
                detected_media_type: ClosedMediaTypeV2::new(parser.detected_media_type),
                extension_class: ClosedExtensionClassV2::new(parser.extension_class),
                implementation_id: ImplementationIdV2::new(parser.implementation_id),
                semantic_version: VersionV2::new(
                    parser.semantic_version[0],
                    parser.semantic_version[1],
                    parser.semantic_version[2],
                ),
                parser_code_digest: Digest32V2::new(parse_hex_32(&parser.parser_code_digest)?),
                renderer_code_digest: parse_optional_digest(
                    parser.renderer_code_digest.as_deref(),
                )?,
                ocr_model_set_digest: parse_optional_digest(
                    parser.ocr_model_set_digest.as_deref(),
                )?,
                normalization_version: VersionV2::new(
                    parser.normalization_version[0],
                    parser.normalization_version[1],
                    parser.normalization_version[2],
                ),
                worker_artifact_digest: Digest32V2::new(parse_hex_32(
                    &parser.worker_artifact_digest,
                )?),
                output_limit_bytes: parser.output_limit_bytes,
                maximum_pages: parser.maximum_pages,
            },
            Digest32V2::new(parse_hex_32(&parser.output_limits_digest)?),
            parser.sandbox_program_path.clone(),
            Digest32V2::new(parse_hex_32(&parser.sandbox_program_digest)?),
            parser.worker_program_path.clone(),
            parser.sandbox_profile_path.clone(),
            Digest32V2::new(parse_hex_32(&parser.sandbox_profile_digest)?),
            parser.file_owner_uid,
            parser.file_owner_gid,
        )
        .map_err(|_| IngressdDaemonErrorV2::DeploymentUnavailable)?;
        let authority = Arc::new(
            IngressBrowserAuthorityV2::new(kernel, approval).with_verified_parser(parser_runtime),
        );
        serve_http(listener, authority)
    }

    #[cfg(target_os = "linux")]
    fn load_native_startup(
        bootstrap: &BootstrapDtoV2,
    ) -> Result<VerifiedDaemonStartupV2, IngressdDaemonErrorV2> {
        savana_policy_core::v2::load_verified_filesystem_startup_v2(
            Path::new(MANIFEST_ROOT_PATH_V2),
            &bootstrap.signed_manifest_path,
            &bootstrap.effect_ledger_projection_path,
            &bootstrap.services,
        )
        .map_err(|_| IngressdDaemonErrorV2::DeploymentUnavailable)
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn load_verified_fixed_startup(
    ) -> Result<(Vec<u8>, BootstrapDtoV2, VerifiedDaemonStartupV2), IngressdDaemonErrorV2> {
        let bytes = read_verified_regular_file_v2(
            Path::new(NATIVE_BOOTSTRAP_PATH_V2),
            MAX_BOOTSTRAP_BYTES_V2,
            Some((0, 0, 0o444)),
        )
        .map_err(|_| IngressdDaemonErrorV2::DeploymentUnavailable)?;
        let bootstrap: BootstrapDtoV2 = serde_json::from_slice(&bytes)
            .map_err(|_| IngressdDaemonErrorV2::DeploymentUnavailable)?;
        let startup = load_native_startup(&bootstrap)?;
        startup
            .verify_loaded_service_config_v2(ClosedServiceIdV2::Ingressd, &bytes)
            .map_err(|_| IngressdDaemonErrorV2::DeploymentUnavailable)?;
        Ok((bytes, bootstrap, startup))
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn spawn_kernel_reload_signal(
        mut signals: Signals,
        kernel: SuiteOneIngressKernelClientV2,
    ) -> Result<(), IngressdDaemonErrorV2> {
        std::thread::Builder::new()
            .name("savana-ingress-kernel-reload".to_owned())
            .spawn(move || {
                for signal in signals.forever() {
                    handle_kernel_reload_signal(signal, || {
                        let _ = kernel.reload_verified_authority();
                    });
                }
            })
            .map(|_| ())
            .map_err(|_| IngressdDaemonErrorV2::EndpointUnavailable)
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn handle_kernel_reload_signal(signal: i32, reload: impl FnOnce()) {
        if signal == SIGHUP {
            reload();
        }
    }

    #[cfg(all(target_os = "macos", feature = "macos-development-authority"))]
    fn load_native_startup(
        bootstrap: &BootstrapDtoV2,
    ) -> Result<VerifiedDaemonStartupV2, IngressdDaemonErrorV2> {
        let root = Path::new("/Library/Application Support/Savana/Development");
        let paths = [
            &bootstrap.signed_manifest_path,
            &bootstrap.effect_ledger_projection_path,
            &bootstrap.parser.sandbox_program_path,
            &bootstrap.parser.worker_program_path,
            &bootstrap.parser.sandbox_profile_path,
        ];
        if paths
            .into_iter()
            .any(|path| !closed_development_path(root, path))
        {
            return Err(IngressdDaemonErrorV2::DeploymentUnavailable);
        }
        savana_policy_core::load_verified_macos_development_startup_v2(
            Path::new(MANIFEST_ROOT_PATH_V2),
            &bootstrap.signed_manifest_path,
            &bootstrap.effect_ledger_projection_path,
            &bootstrap.services,
        )
        .map_err(|_| IngressdDaemonErrorV2::DeploymentUnavailable)
    }

    #[cfg(all(target_os = "macos", not(feature = "macos-development-authority")))]
    fn load_native_startup(
        _bootstrap: &BootstrapDtoV2,
    ) -> Result<VerifiedDaemonStartupV2, IngressdDaemonErrorV2> {
        Err(IngressdDaemonErrorV2::DeploymentUnavailable)
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
    fn serve_http(
        listener: TcpListener,
        authority: Arc<IngressBrowserAuthorityV2>,
    ) -> Result<(), IngressdDaemonErrorV2> {
        let (sender, receiver) = mpsc::sync_channel(HTTP_QUEUE_CAPACITY_V2);
        let receiver = Arc::new(Mutex::new(receiver));
        for worker_index in 0..HTTP_WORKERS_V2 {
            let receiver = Arc::clone(&receiver);
            let authority = Arc::clone(&authority);
            std::thread::Builder::new()
                .name(format!("savana-ingress-http-worker-{worker_index}-v2"))
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
                .map_err(|_| IngressdDaemonErrorV2::EndpointUnavailable)?;
        }
        loop {
            let (stream, remote) = listener
                .accept()
                .map_err(|_| IngressdDaemonErrorV2::EndpointUnavailable)?;
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
        authority: Arc<IngressBrowserAuthorityV2>,
    ) -> Result<(), IngressdDaemonErrorV2> {
        stream
            .set_read_timeout(Some(CONNECTION_DEADLINE_V2))
            .and_then(|()| stream.set_write_timeout(Some(CONNECTION_DEADLINE_V2)))
            .map_err(|_| IngressdDaemonErrorV2::EndpointUnavailable)?;
        let request = match read_fixed_http_request_v2(&mut stream, FixedHttpServiceV2::Ingress) {
            Ok(request) => request,
            Err(FixedHttpErrorV2::NotFound) => {
                return write_http(&mut stream, 404, "text/plain; charset=utf-8", b"")
            }
            Err(FixedHttpErrorV2::UnauthorizedOrigin) => return Ok(()),
            Err(_) => return write_http(&mut stream, 400, "text/plain; charset=utf-8", b""),
        };
        let deadline = deadline_unix_millis()?;
        match request.route() {
            FixedHttpRouteV2::BrowserScript => write_http(
                &mut stream,
                200,
                "application/javascript; charset=utf-8",
                SAVANA_BROWSER_SCRIPT_V2,
            ),
            FixedHttpRouteV2::IngressBootstrapAccept => {
                let transfer = KernelIngressBootstrapTransferCapabilityV2::from_authority_entropy(
                    decode_form_transfer(request.body())?,
                )
                .ok_or(IngressdDaemonErrorV2::EndpointUnavailable)?;
                let prepared = authority
                    .prepare_authentication(transfer, deadline)
                    .map_err(|_| IngressdDaemonErrorV2::EndpointUnavailable)?;
                let body = render_ingress_ui_authentication_form_v2(prepared.transfer());
                write_http(&mut stream, 200, "text/html; charset=utf-8", &body)
            }
            FixedHttpRouteV2::IngressUiAuthenticationComplete => {
                let transfer =
                    IngressUiAuthenticationSettlementTransferCapabilityV2::from_authority_entropy(
                        decode_form_transfer(request.body())?,
                    )
                    .ok_or(IngressdDaemonErrorV2::EndpointUnavailable)?;
                let tab = authority
                    .complete_authentication(transfer, deadline)
                    .map_err(|_| IngressdDaemonErrorV2::EndpointUnavailable)?;
                let body = render_ingress_workspace_v2(tab);
                write_http(&mut stream, 200, "text/html; charset=utf-8", &body)
            }
            route @ (FixedHttpRouteV2::IngressInputBegin
            | FixedHttpRouteV2::IngressInputChunk
            | FixedHttpRouteV2::IngressInputFinalize
            | FixedHttpRouteV2::IngressInputAbort) => {
                let decoded = decode_ingress_browser_request_v2(request.body())
                    .map_err(|_| IngressdDaemonErrorV2::EndpointUnavailable)?;
                if !route_matches_request(route, &decoded) {
                    return write_http(&mut stream, 400, "text/plain; charset=utf-8", b"");
                }
                let response = authority
                    .mutate(decoded, request_digest(request.body()), deadline)
                    .map_err(|_| IngressdDaemonErrorV2::EndpointUnavailable)?;
                let body = encode_ingress_browser_mutation_response_v2(response)
                    .map_err(|_| IngressdDaemonErrorV2::EndpointUnavailable)?;
                write_http(&mut stream, 200, "application/cbor", &body)
            }
            _ => write_http(&mut stream, 404, "text/plain; charset=utf-8", b""),
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn route_matches_request(route: FixedHttpRouteV2, request: &IngressBrowserRequestV2) -> bool {
        matches!(
            (route, request),
            (
                FixedHttpRouteV2::IngressInputBegin,
                IngressBrowserRequestV2::Begin { .. }
            ) | (
                FixedHttpRouteV2::IngressInputChunk,
                IngressBrowserRequestV2::Append { .. }
            ) | (
                FixedHttpRouteV2::IngressInputFinalize,
                IngressBrowserRequestV2::Finalize { .. }
            ) | (
                FixedHttpRouteV2::IngressInputAbort,
                IngressBrowserRequestV2::Abort { .. }
            )
        )
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn write_http(
        stream: &mut TcpStream,
        status: u16,
        content_type: &str,
        body: &[u8],
    ) -> Result<(), IngressdDaemonErrorV2> {
        write_fixed_http_response_v2(stream, status, content_type, body)
            .map_err(|_| IngressdDaemonErrorV2::EndpointUnavailable)
    }

    #[cfg(target_os = "linux")]
    fn take_verified_listener() -> Result<TcpListener, IngressdDaemonErrorV2> {
        let inherited = savana_platform_identity::take_systemd_listeners_v2(&[HTTP_FD_NAME_V2])
            .map_err(|_| IngressdDaemonErrorV2::EndpointUnavailable)?;
        let mut inherited = inherited.into_iter();
        let (name, listener) = inherited
            .next()
            .ok_or(IngressdDaemonErrorV2::EndpointUnavailable)?
            .into_tcp_listener();
        if inherited.next().is_some()
            || name != HTTP_FD_NAME_V2
            || !getsockopt(&listener, AcceptConn)
                .map_err(|_| IngressdDaemonErrorV2::EndpointUnavailable)?
            || listener
                .local_addr()
                .map_err(|_| IngressdDaemonErrorV2::EndpointUnavailable)?
                != SocketAddr::from((Ipv4Addr::LOCALHOST, 8767))
        {
            return Err(IngressdDaemonErrorV2::EndpointUnavailable);
        }
        Ok(listener)
    }

    #[cfg(target_os = "macos")]
    fn take_verified_listener() -> Result<TcpListener, IngressdDaemonErrorV2> {
        let inherited = savana_platform_identity::take_launchd_tcp_listeners_v2(&[HTTP_FD_NAME_V2])
            .map_err(|_| IngressdDaemonErrorV2::EndpointUnavailable)?;
        let mut inherited = inherited.into_iter();
        let (name, listener) = inherited
            .next()
            .ok_or(IngressdDaemonErrorV2::EndpointUnavailable)?
            .into_parts();
        if inherited.next().is_some()
            || name != HTTP_FD_NAME_V2
            || listener
                .local_addr()
                .map_err(|_| IngressdDaemonErrorV2::EndpointUnavailable)?
                != SocketAddr::from((Ipv4Addr::LOCALHOST, 8767))
        {
            return Err(IngressdDaemonErrorV2::EndpointUnavailable);
        }
        Ok(listener)
    }

    #[cfg(target_os = "linux")]
    fn current_process_binding(
        lock: &ServiceDeploymentLockV2,
        pinned: &PinnedLinuxPeerMeasurementV2,
    ) -> Result<PeerIdentityBindingV2, IngressdDaemonErrorV2> {
        match pinned.measurement() {
            NativePeerMeasurementV2::Linux {
                uid,
                gid,
                pid,
                process_start_time,
                executable_measurement,
            } if *uid == lock.uid
                && *gid == lock.gid
                && Digest32V2::new(*executable_measurement) == lock.executable_digest =>
            {
                PeerIdentityBindingV2::linux(
                    *uid,
                    *gid,
                    *pid,
                    *process_start_time,
                    lock.executable_digest,
                )
                .map_err(|_| IngressdDaemonErrorV2::DeploymentUnavailable)
            }
            _ => Err(IngressdDaemonErrorV2::DeploymentUnavailable),
        }
    }

    #[cfg(target_os = "macos")]
    fn current_process_binding(
        lock: &ServiceDeploymentLockV2,
        pinned: &PinnedMacOsServiceV2,
    ) -> Result<PeerIdentityBindingV2, IngressdDaemonErrorV2> {
        match pinned.measurement() {
            NativePeerMeasurementV2::MacOs {
                audit_token,
                euid,
                egid,
                bundle_id,
                team_id,
                code_directory_measurement,
                ..
            } if *euid == lock.uid
                && *egid == lock.gid
                && Digest32V2::new(*code_directory_measurement) == lock.code_identity_digest =>
            {
                PeerIdentityBindingV2::macos(
                    *audit_token,
                    *euid,
                    *egid,
                    bundle_id.as_str().to_owned(),
                    team_id.as_str().to_owned(),
                    lock.code_identity_digest,
                )
                .map_err(|_| IngressdDaemonErrorV2::DeploymentUnavailable)
            }
            _ => Err(IngressdDaemonErrorV2::DeploymentUnavailable),
        }
    }

    fn read_public_key(path: &Path) -> Result<[u8; 32], IngressdDaemonErrorV2> {
        let bytes = read_verified_regular_file_v2(path, 32, Some((0, 0, 0o444)))
            .map_err(|_| IngressdDaemonErrorV2::DeploymentUnavailable)?;
        bytes
            .as_slice()
            .try_into()
            .map_err(|_| IngressdDaemonErrorV2::DeploymentUnavailable)
    }

    fn read_credential_32(name: &str) -> Result<[u8; 32], IngressdDaemonErrorV2> {
        let path = Path::new(CREDENTIAL_DIRECTORY_V2).join(name);
        #[cfg(target_os = "linux")]
        let identity = (0, 0, 0o400);
        #[cfg(target_os = "macos")]
        let identity = (0, nix::unistd::getegid().as_raw(), 0o440);
        let bytes = read_verified_regular_file_v2(&path, 32, Some(identity))
            .map_err(|_| IngressdDaemonErrorV2::DeploymentUnavailable)?;
        bytes
            .as_slice()
            .try_into()
            .map_err(|_| IngressdDaemonErrorV2::DeploymentUnavailable)
    }

    fn parse_hex_32(value: &str) -> Result<[u8; 32], IngressdDaemonErrorV2> {
        decode_hex_32_v2(value).map_err(|_| IngressdDaemonErrorV2::DeploymentUnavailable)
    }

    fn parse_optional_digest(
        value: Option<&str>,
    ) -> Result<Option<Digest32V2>, IngressdDaemonErrorV2> {
        value
            .map(parse_hex_32)
            .transpose()
            .map(|value| value.map(Digest32V2::new))
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn decode_form_transfer(body: &[u8]) -> Result<[u8; 32], IngressdDaemonErrorV2> {
        let encoded = body
            .strip_prefix(b"transfer=")
            .ok_or(IngressdDaemonErrorV2::EndpointUnavailable)?;
        if encoded.contains(&b'&') || encoded.contains(&b'%') || encoded.contains(&b'+') {
            return Err(IngressdDaemonErrorV2::EndpointUnavailable);
        }
        let decoded = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| IngressdDaemonErrorV2::EndpointUnavailable)?;
        let transfer: [u8; 32] = decoded
            .try_into()
            .map_err(|_| IngressdDaemonErrorV2::EndpointUnavailable)?;
        if transfer == [0; 32] {
            return Err(IngressdDaemonErrorV2::EndpointUnavailable);
        }
        Ok(transfer)
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn request_digest(bytes: &[u8]) -> Digest32V2 {
        let mut hasher = Sha256::new();
        hasher.update(REQUEST_DIGEST_DOMAIN_V2);
        hasher.update(bytes);
        Digest32V2::new(hasher.finalize().into())
    }

    fn deadline_unix_millis() -> Result<UnixMillisV2, IngressdDaemonErrorV2> {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| IngressdDaemonErrorV2::EndpointUnavailable)?;
        let now = u64::try_from(duration.as_millis())
            .map_err(|_| IngressdDaemonErrorV2::EndpointUnavailable)?;
        let deadline = now
            .checked_add(
                u64::try_from(CONNECTION_DEADLINE_V2.as_millis())
                    .map_err(|_| IngressdDaemonErrorV2::EndpointUnavailable)?,
            )
            .ok_or(IngressdDaemonErrorV2::EndpointUnavailable)?;
        Ok(UnixMillisV2::new(deadline))
    }

    #[cfg(test)]
    mod tests {
        use std::sync::atomic::{AtomicUsize, Ordering};

        use super::*;

        #[test]
        fn only_sighup_invokes_the_kernel_reload_lifecycle_helper() {
            let calls = AtomicUsize::new(0);
            handle_kernel_reload_signal(SIGHUP, || {
                calls.fetch_add(1, Ordering::SeqCst);
            });
            handle_kernel_reload_signal(signal_hook::consts::signal::SIGTERM, || {
                calls.fetch_add(1, Ordering::SeqCst);
            });
            assert_eq!(calls.load(Ordering::SeqCst), 1);
        }
    }
}

pub fn run(config_path: &std::path::Path) -> Result<(), IngressdDaemonErrorV2> {
    implementation::run(config_path)
}
