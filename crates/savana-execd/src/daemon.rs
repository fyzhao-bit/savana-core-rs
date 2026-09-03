#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ExecdDaemonErrorV2 {
    #[error("executor production deployment is unavailable")]
    DeploymentUnavailable,
    #[error("executor durable state is unavailable")]
    DurableStateUnavailable,
    #[error("executor service endpoint is unavailable")]
    EndpointUnavailable,
}

#[cfg_attr(
    not(any(target_os = "linux", target_os = "macos")),
    allow(dead_code, unused_imports)
)]
mod implementation {
    use std::fs::{self, File};
    use std::io::Write as _;
    use std::net::SocketAddr;
    use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, OpenOptionsExt as _};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::{Path, PathBuf};
    use std::sync::{mpsc, Arc, Mutex};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use ed25519_dalek::SigningKey;
    use hmac::{Hmac, Mac as _};
    #[cfg(target_os = "linux")]
    use nix::sys::socket::{getsockopt, sockopt::AcceptConn};
    #[cfg(target_os = "linux")]
    use rustix::fs::{fstat, FileType};
    use savana_kernel_protocol::v2::{
        derive_ed25519_key_id_v2, BootIdV2, Digest32V2, Ed25519KeyIdV2, EndpointRoleV2,
        HpkeX25519KeyIdV2, PeerIdentityBindingV2, UnixMillisV2,
    };
    #[cfg(target_os = "linux")]
    use savana_platform_identity::{measure_linux_peer_v2, PinnedLinuxPeerMeasurementV2};
    use savana_platform_identity::{
        verify_native_peer_v2, BoundedIdentityStringV2, NativePeerMeasurementV2,
    };
    use savana_policy_core::v2::{
        listener_identity_digest_v2, BoundedConnectorHostV2, BoundedConnectorUrlV2,
        ClosedServiceEdgeIdV2, ClosedServiceIdV2, DurableStateNamespaceV2,
        FilesystemServiceObservationConfigV2, G4Error, RollbackProtectedStateAnchorV2,
        RollbackProtectedStateHeadV2, VerifiedDaemonStartupV2,
    };
    use serde::Deserialize;
    use sha2::{Digest as _, Sha256};
    use zeroize::Zeroizing;

    use super::ExecdDaemonErrorV2;
    use crate::connector_runtime::VerifiedConnectorExecutionRuntimeV2;
    use crate::provider_transport::VerifiedRustlsProviderTransportV2;
    use crate::sandbox_process::VerifiedConnectorSandboxProgramV2;
    use crate::worker_protocol::ConnectorJobDescriptorIssuerV2;
    use crate::worker_supervisor::ConnectorWorkerSupervisorV2;
    use crate::{
        DurableExecdNamespaceV2, ExecdConnectorRegistryTrustV2, ExecdConnectorRegistryV2,
        ExecdErrorV2, ExecdProtocolDeploymentV2, ExecdProtocolServiceV2, ExecdRollbackAnchorV2,
        ExecdStateHeadV2, ExecdStateOwnerV2, ExecdSuiteOneServerV2, VerifiedExecdDeploymentV2,
    };

    #[cfg(target_os = "linux")]
    const NATIVE_BOOTSTRAP_PATH_V2: &str = "/etc/savana/execd-bootstrap-v2.json";
    #[cfg(target_os = "macos")]
    const NATIVE_BOOTSTRAP_PATH_V2: &str =
        "/Library/Application Support/Savana/Development/config/execd-bootstrap-v2.json";
    const CONNECTOR_STORE_KEY_DERIVATION_DOMAIN_V2: &[u8] =
        b"SAVANA_EXECD_CONNECTOR_STORE_KEY_DERIVATION_V2\0";
    const CONNECTOR_ANCHOR_KEY_DERIVATION_DOMAIN_V2: &[u8] =
        b"SAVANA_EXECD_CONNECTOR_ANCHOR_KEY_DERIVATION_V2\0";
    #[cfg(target_os = "linux")]
    const MANIFEST_ROOT_PATH_V2: &str = "/etc/savana/trust/deployment-manifest-root-v2.json";
    #[cfg(all(target_os = "macos", feature = "macos-development-authority"))]
    const MANIFEST_ROOT_PATH_V2: &str = "/Library/Application Support/Savana/Development/config/trust/deployment-manifest-root-v2.json";
    #[cfg(target_os = "linux")]
    const KERNEL_CLIENT_PUBLIC_KEY_PATH_V2: &str = "/etc/savana/execd/keys/kerneld-executor-v2.pub";
    #[cfg(target_os = "macos")]
    const KERNEL_CLIENT_PUBLIC_KEY_PATH_V2: &str =
        "/Library/Application Support/Savana/Development/config/execd/keys/kerneld-executor-v2.pub";
    #[cfg(target_os = "linux")]
    const KERNEL_ENVELOPE_PUBLIC_KEY_PATH_V2: &str =
        "/etc/savana/execd/keys/kerneld-envelope-v2.pub";
    #[cfg(target_os = "macos")]
    const KERNEL_ENVELOPE_PUBLIC_KEY_PATH_V2: &str =
        "/Library/Application Support/Savana/Development/config/execd/keys/kerneld-envelope-v2.pub";
    #[cfg(target_os = "linux")]
    const SYSTEMD_CREDENTIAL_DIRECTORY_V2: &str = "/run/credentials/savana-execd.service";
    #[cfg(target_os = "macos")]
    const SYSTEMD_CREDENTIAL_DIRECTORY_V2: &str =
        "/Library/Application Support/Savana/Development/credentials/execd";
    const SERVER_SEED_CREDENTIAL_V2: &str = "executor-server-v2.seed";
    const BOOT_ID_CREDENTIAL_V2: &str = "execd-boot-v2.id";
    const EFFECT_RECEIPT_SEED_CREDENTIAL_V2: &str = "effect-receipt-v2.seed";
    const SEAL_PRIVATE_KEY_CREDENTIAL_V2: &str = "execution-seal-v2.key";
    const JOURNAL_ENCRYPTION_KEY_CREDENTIAL_V2: &str = "journal-encryption-v2.key";
    const ANCHOR_AUTHENTICATION_KEY_CREDENTIAL_V2: &str = "journal-anchor-authentication-v2.key";
    const CONNECTOR_DESCRIPTOR_SEED_CREDENTIAL_V2: &str = "connector-descriptor-v2.seed";
    const PROVIDER_TLS_PRIVATE_KEY_CREDENTIAL_V2: &str = "provider-tls-private-key-v2.der";
    const FINAL_RELEASE_PROVIDER_TLS_PRIVATE_KEY_CREDENTIAL_V2: &str =
        "final-release-provider-tls-private-key-v2.der";
    const EXECUTOR_FD_NAME_V2: &str = "savana-kernel-executor";
    #[cfg(target_os = "linux")]
    const EXECUTOR_SOCKET_PATH_V2: &str = "/run/savana/execd/kerneld/execd.sock";
    #[cfg(target_os = "macos")]
    const EXECUTOR_SOCKET_PATH_V2: &str =
        "/Library/Application Support/Savana/Development/run/execd/kerneld/execd.sock";
    const MAX_BOOTSTRAP_BYTES_V2: usize = 128 * 1024;
    const MAX_ARTIFACT_BYTES_V2: usize = 256 * 1024 * 1024;
    const MAX_CREDENTIAL_BYTES_V2: usize = 128 * 1024;
    const SERVICE_COUNT_V2: usize = 5;
    const WORKER_COUNT_V2: usize = 8;
    const CONNECTION_QUEUE_CAPACITY_V2: usize = 64;
    const CONNECTION_DEADLINE_V2: Duration = Duration::from_secs(35);
    const RECOVERY_DEADLINE_V2: Duration = Duration::from_secs(60);
    const ANCHOR_MAC_DOMAIN_V2: &[u8] = b"SAVANA_EXECD_ANCHOR_MAC_V2\0";
    const ANCHOR_MAGIC_V2: [u8; 8] = *b"SE2ANCH\0";
    const AUTHENTICATED_ANCHOR_BYTES_V2: usize = 80;

    #[derive(Clone, Deserialize)]
    #[cfg_attr(
        all(target_os = "macos", not(feature = "macos-development-authority")),
        allow(dead_code)
    )]
    #[serde(deny_unknown_fields)]
    struct BootstrapDtoV2 {
        signed_manifest_path: PathBuf,
        effect_ledger_projection_path: PathBuf,
        services: Vec<FilesystemServiceObservationConfigV2>,
        journal_path: PathBuf,
        rollback_anchor_path: PathBuf,
        store_id: String,
        effect_gate_path: PathBuf,
        executor_identity: String,
        effect_receipt_key_id: String,
        seal_key_id: String,
        connector_set_digest: String,
        connector_registry_path: PathBuf,
        connector_registry_anchor_path: PathBuf,
        connector_registry_store_id: String,
        connector_registry_genesis_digest: String,
        connector_authority_key_id: String,
        connector_authority_public_key: String,
        user_tier_host_allowlist: Vec<String>,
        journal_schema_version: u16,
        journal_key_epoch: u64,
        worker: WorkerDtoV2,
        #[serde(default)]
        provider_routing_mode: ProviderRoutingModeDtoV2,
        provider: ProviderDtoV2,
        #[serde(default)]
        final_release_provider: Option<ProviderDtoV2>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
    #[serde(rename_all = "kebab-case")]
    enum ProviderRoutingModeDtoV2 {
        #[default]
        LegacyShared,
        SplitFinalRelease,
    }

    #[derive(Clone, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct WorkerDtoV2 {
        sandbox_program_path: PathBuf,
        sandbox_program_digest: String,
        worker_program_path: PathBuf,
        worker_artifact_digest: String,
        no_network_profile_path: PathBuf,
        no_network_profile_digest: String,
        credential_absence_profile_path: PathBuf,
        credential_absence_profile_digest: String,
    }

    #[derive(Clone, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ProviderDtoV2 {
        address: String,
        server_name: String,
        canonical_url: String,
        server_spki_sha256: String,
        root_certificate_path: PathBuf,
        root_certificate_digest: String,
        client_certificate_paths: Vec<PathBuf>,
        client_certificate_digests: Vec<String>,
        alpn_protocol_hex: String,
        endpoint_binding_digest: String,
        credential_handle_identity_digest: String,
    }

    struct LoadedStartupV2 {
        startup: VerifiedDaemonStartupV2,
        bootstrap: BootstrapDtoV2,
        keys: KeyMaterialV2,
    }

    struct KeyMaterialV2 {
        boot_id: [u8; 32],
        kernel_client_public_key: [u8; 32],
        kernel_envelope_public_key: [u8; 32],
        server_signing_key: SigningKey,
        effect_receipt_signing_seed: [u8; 32],
        seal_private_key: [u8; 32],
        journal_encryption_key: [u8; 32],
        anchor_authentication_key: [u8; 32],
        connector_descriptor_seed: Zeroizing<[u8; 32]>,
        provider_tls_private_key: Zeroizing<Vec<u8>>,
        final_release_provider_tls_private_key: Option<Zeroizing<Vec<u8>>>,
    }

    fn validate_provider_routing_configuration(
        mode: ProviderRoutingModeDtoV2,
        provider: &ProviderDtoV2,
        final_release_provider: Option<&ProviderDtoV2>,
    ) -> Result<(), ExecdDaemonErrorV2> {
        match (mode, final_release_provider) {
            (ProviderRoutingModeDtoV2::LegacyShared, None) => Ok(()),
            (ProviderRoutingModeDtoV2::SplitFinalRelease, Some(release)) => {
                let client_leaf_path_matches = provider.client_certificate_paths.first()
                    == release.client_certificate_paths.first();
                let client_leaf_digest_matches = provider.client_certificate_digests.first()
                    == release.client_certificate_digests.first();
                if provider.address == release.address
                    || provider.server_name == release.server_name
                    || provider.canonical_url == release.canonical_url
                    || provider.server_spki_sha256 == release.server_spki_sha256
                    || provider.endpoint_binding_digest == release.endpoint_binding_digest
                    || provider.credential_handle_identity_digest
                        == release.credential_handle_identity_digest
                    || client_leaf_path_matches
                    || client_leaf_digest_matches
                {
                    return Err(ExecdDaemonErrorV2::DeploymentUnavailable);
                }
                Ok(())
            }
            _ => Err(ExecdDaemonErrorV2::DeploymentUnavailable),
        }
    }

    #[cfg(target_os = "linux")]
    struct VerifiedAcceptedConnectionV2 {
        stream: UnixStream,
        binding: PeerIdentityBindingV2,
        _pinned: PinnedLinuxPeerMeasurementV2,
    }

    #[cfg(target_os = "macos")]
    struct VerifiedAcceptedConnectionV2 {
        stream: UnixStream,
        binding: PeerIdentityBindingV2,
        _measurement: NativePeerMeasurementV2,
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    pub(crate) fn run(_config_path: &Path) -> Result<(), ExecdDaemonErrorV2> {
        Err(ExecdDaemonErrorV2::DeploymentUnavailable)
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(crate) fn run(config_path: &Path) -> Result<(), ExecdDaemonErrorV2> {
        let loaded = load_verified_startup(config_path)?;
        let self_lock = loaded
            .startup
            .service_lock(ClosedServiceIdV2::Execd)
            .ok_or(ExecdDaemonErrorV2::DeploymentUnavailable)?;
        #[cfg(target_os = "linux")]
        let _self_process = savana_platform_identity::pin_current_linux_service_v2(
            self_lock.uid,
            self_lock.gid,
            *self_lock.executable_digest.as_bytes(),
        )
        .map_err(|_| ExecdDaemonErrorV2::DeploymentUnavailable)?;
        #[cfg(target_os = "macos")]
        let _self_process = savana_platform_identity::pin_current_macos_service_v2(
            self_lock.uid,
            self_lock.gid,
            *self_lock.executable_digest.as_bytes(),
            *self_lock.code_identity_digest.as_bytes(),
        )
        .map_err(|_| ExecdDaemonErrorV2::DeploymentUnavailable)?;
        let edge = loaded
            .startup
            .edge_lock(ClosedServiceEdgeIdV2::KernelExecutor)
            .ok_or(ExecdDaemonErrorV2::DeploymentUnavailable)?
            .clone();
        let listener = take_verified_listener(&loaded.startup)?;
        let boot_id = BootIdV2::new(loaded.keys.boot_id);
        let handshake_edge = loaded
            .startup
            .kernel_service_handshake_edge(ClosedServiceEdgeIdV2::KernelExecutor, boot_id)
            .map_err(|_| ExecdDaemonErrorV2::DeploymentUnavailable)?;
        if derive_ed25519_key_id_v2(loaded.keys.kernel_client_public_key)
            != edge.client_handshake_key_id
            || derive_ed25519_key_id_v2(loaded.keys.server_signing_key.verifying_key().to_bytes())
                != edge.server_handshake_key_id
            || derive_ed25519_key_id_v2(loaded.keys.kernel_envelope_public_key)
                != loaded.startup.kernel_envelope_signing_key_id()
        {
            return Err(ExecdDaemonErrorV2::DeploymentUnavailable);
        }

        let executor_identity =
            Digest32V2::new(decode_hex_32(&loaded.bootstrap.executor_identity)?);
        let effect_receipt_key_id =
            Ed25519KeyIdV2::new(decode_hex_32(&loaded.bootstrap.effect_receipt_key_id)?);
        let deployment = VerifiedExecdDeploymentV2::from_verified_manifest(
            loaded.startup.installation_id(),
            loaded.startup.active_state_manifest_digest(),
            loaded.startup.deployment_generation(),
            loaded.startup.effect_fence_epoch(),
            executor_identity,
            loaded.startup.kernel_envelope_signing_key_id(),
            loaded.keys.kernel_envelope_public_key,
            effect_receipt_key_id,
            loaded.keys.effect_receipt_signing_seed,
        )
        .map_err(|_| ExecdDaemonErrorV2::DeploymentUnavailable)?;
        let seal_key_id = HpkeX25519KeyIdV2::new(decode_hex_32(&loaded.bootstrap.seal_key_id)?);
        let protocol_deployment = ExecdProtocolDeploymentV2::from_verified_deployment(
            &deployment,
            seal_key_id,
            loaded.keys.seal_private_key,
            loaded.bootstrap.journal_schema_version,
            loaded.bootstrap.journal_key_epoch,
            Digest32V2::new(decode_hex_32(&loaded.bootstrap.connector_set_digest)?),
        )
        .map_err(|_| ExecdDaemonErrorV2::DeploymentUnavailable)?;
        verify_runtime_paths(&loaded.bootstrap)?;
        let journal_store_id = Digest32V2::new(decode_hex_32(&loaded.bootstrap.store_id)?);
        let namespace = DurableExecdNamespaceV2::from_verified_installation(
            loaded.startup.installation_id(),
            journal_store_id,
        )
        .map_err(|_| ExecdDaemonErrorV2::DurableStateUnavailable)?;
        let connector_genesis = Digest32V2::new(decode_hex_32(
            &loaded.bootstrap.connector_registry_genesis_digest,
        )?);
        if connector_genesis
            != Digest32V2::new(decode_hex_32(&loaded.bootstrap.connector_set_digest)?)
        {
            return Err(ExecdDaemonErrorV2::DeploymentUnavailable);
        }
        let connector_authority_key_id =
            Ed25519KeyIdV2::new(decode_hex_32(&loaded.bootstrap.connector_authority_key_id)?);
        let connector_authority_public_key =
            decode_hex_32(&loaded.bootstrap.connector_authority_public_key)?;
        let connector_hosts = loaded
            .bootstrap
            .user_tier_host_allowlist
            .iter()
            .map(|host| {
                let canonical = BoundedConnectorHostV2::new(host)
                    .map_err(|_| ExecdDaemonErrorV2::DeploymentUnavailable)?;
                if canonical.as_str() != host {
                    return Err(ExecdDaemonErrorV2::DeploymentUnavailable);
                }
                Ok(canonical)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let connector_trust = ExecdConnectorRegistryTrustV2::from_authenticated_deployment(
            loaded.startup.installation_id(),
            loaded.startup.active_state_manifest_digest(),
            loaded.startup.deployment_generation(),
            connector_genesis,
            connector_authority_key_id,
            connector_authority_public_key,
            connector_hosts,
            vec![],
        )
        .map_err(|_| ExecdDaemonErrorV2::DeploymentUnavailable)?;
        let connector_store_id = Digest32V2::new(decode_hex_32(
            &loaded.bootstrap.connector_registry_store_id,
        )?);
        if connector_store_id == journal_store_id {
            return Err(ExecdDaemonErrorV2::DeploymentUnavailable);
        }
        let connector_namespace = DurableStateNamespaceV2::from_verified_installation(
            loaded.startup.installation_id(),
            connector_store_id,
        )
        .map_err(|_| ExecdDaemonErrorV2::DurableStateUnavailable)?;
        let connector_anchor_namespace = DurableExecdNamespaceV2::from_verified_installation(
            loaded.startup.installation_id(),
            connector_store_id,
        )
        .map_err(|_| ExecdDaemonErrorV2::DurableStateUnavailable)?;
        let connector_store_key = derive_connector_runtime_key_v2(
            &loaded.keys.journal_encryption_key,
            CONNECTOR_STORE_KEY_DERIVATION_DOMAIN_V2,
            loaded.startup.installation_id(),
            connector_store_id,
        )?;
        let connector_anchor_key = derive_connector_runtime_key_v2(
            &loaded.keys.anchor_authentication_key,
            CONNECTOR_ANCHOR_KEY_DERIVATION_DOMAIN_V2,
            loaded.startup.installation_id(),
            connector_store_id,
        )?;
        if connector_store_key == connector_anchor_key
            || connector_store_key == loaded.keys.journal_encryption_key
            || connector_store_key == loaded.keys.anchor_authentication_key
            || connector_anchor_key == loaded.keys.journal_encryption_key
            || connector_anchor_key == loaded.keys.anchor_authentication_key
        {
            return Err(ExecdDaemonErrorV2::DeploymentUnavailable);
        }
        let connector_anchor = LinuxAuthenticatedExecdAnchorV2::new(
            loaded.bootstrap.connector_registry_anchor_path.clone(),
            connector_anchor_namespace,
            connector_anchor_key,
        )?;
        let connector_registry = Arc::new(
            ExecdConnectorRegistryV2::open(
                &loaded.bootstrap.connector_registry_path,
                connector_store_key,
                connector_namespace,
                Box::new(connector_anchor),
                connector_trust,
            )
            .map_err(|_| ExecdDaemonErrorV2::DurableStateUnavailable)?,
        );
        let anchor = LinuxAuthenticatedExecdAnchorV2::new(
            loaded.bootstrap.rollback_anchor_path.clone(),
            namespace,
            loaded.keys.anchor_authentication_key,
        )?;
        let effect_gate = open_read_only_single_link(&loaded.bootstrap.effect_gate_path)?;
        let projection =
            open_read_only_single_link(&loaded.bootstrap.effect_ledger_projection_path)?;
        let recovery_deadline = Instant::now()
            .checked_add(RECOVERY_DEADLINE_V2)
            .ok_or(ExecdDaemonErrorV2::DurableStateUnavailable)?;
        let owner = ExecdStateOwnerV2::open(
            &loaded.bootstrap.journal_path,
            loaded.keys.journal_encryption_key,
            namespace,
            Box::new(anchor),
            deployment,
            effect_gate,
            projection,
            loaded.startup.effect_ledger_projection_binding(),
            recovery_deadline,
            128,
        )
        .map_err(|_| ExecdDaemonErrorV2::DurableStateUnavailable)?;
        let processor = build_connector_runtime(&loaded, executor_identity)?;
        let now = current_unix_millis()?;
        ExecdProtocolServiceV2::recover_prepared_with_connector_registry(
            &protocol_deployment,
            &owner,
            processor.as_ref(),
            &connector_registry,
            now,
            recovery_deadline,
        )
        .map_err(|_| ExecdDaemonErrorV2::DurableStateUnavailable)?;
        let protocol_service = ExecdProtocolServiceV2::new_with_connector_registry(
            protocol_deployment,
            owner,
            processor,
            connector_registry,
        )
        .map_err(|_| ExecdDaemonErrorV2::DurableStateUnavailable)?;
        let server = Arc::new(
            ExecdSuiteOneServerV2::new(
                handshake_edge,
                loaded.keys.kernel_client_public_key,
                loaded.keys.server_signing_key,
                65_536,
                protocol_service,
            )
            .map_err(|_| ExecdDaemonErrorV2::EndpointUnavailable)?,
        );
        serve(listener, edge.expected_client, server)
    }

    fn build_connector_runtime(
        loaded: &LoadedStartupV2,
        _executor_identity: Digest32V2,
    ) -> Result<Box<VerifiedConnectorExecutionRuntimeV2>, ExecdDaemonErrorV2> {
        let service = loaded
            .startup
            .service_lock(ClosedServiceIdV2::Execd)
            .ok_or(ExecdDaemonErrorV2::DeploymentUnavailable)?;
        let worker = &loaded.bootstrap.worker;
        let worker_artifact_digest =
            Digest32V2::new(decode_hex_32(&worker.worker_artifact_digest)?);
        let no_network_digest = Digest32V2::new(decode_hex_32(&worker.no_network_profile_digest)?);
        let credential_absence_digest =
            Digest32V2::new(decode_hex_32(&worker.credential_absence_profile_digest)?);
        let launcher = VerifiedConnectorSandboxProgramV2::from_verified_manifest(
            worker.sandbox_program_path.clone(),
            Digest32V2::new(decode_hex_32(&worker.sandbox_program_digest)?),
            worker.worker_program_path.clone(),
            worker_artifact_digest,
            worker.no_network_profile_path.clone(),
            no_network_digest,
            worker.credential_absence_profile_path.clone(),
            credential_absence_digest,
            service.uid,
            service.gid,
        )
        .map_err(|_| ExecdDaemonErrorV2::DeploymentUnavailable)?;
        let provider = &loaded.bootstrap.provider;
        let credential_identity =
            Digest32V2::new(decode_hex_32(&provider.credential_handle_identity_digest)?);
        let issuer = ConnectorJobDescriptorIssuerV2::from_verified_deployment(
            loaded.startup.installation_id(),
            loaded.startup.active_state_manifest_digest(),
            loaded.startup.deployment_generation(),
            loaded.startup.effect_fence_epoch(),
            worker_artifact_digest,
            no_network_digest,
            credential_absence_digest,
            credential_identity,
            loaded.keys.connector_descriptor_seed.clone(),
        )
        .map_err(|_| ExecdDaemonErrorV2::DeploymentUnavailable)?;
        let supervisor = ConnectorWorkerSupervisorV2::from_verified_launcher(
            issuer.trust(),
            Some(Box::new(launcher)),
        )
        .map_err(|_| ExecdDaemonErrorV2::DeploymentUnavailable)?;
        let transport = build_verified_provider_transport(
            provider,
            loaded.keys.provider_tls_private_key.clone(),
        )?;
        match loaded.bootstrap.provider_routing_mode {
            ProviderRoutingModeDtoV2::LegacyShared => Ok(Box::new(
                VerifiedConnectorExecutionRuntimeV2::from_verified_components(
                    supervisor,
                    issuer,
                    Box::new(transport),
                ),
            )),
            ProviderRoutingModeDtoV2::SplitFinalRelease => {
                let release_provider = loaded
                    .bootstrap
                    .final_release_provider
                    .as_ref()
                    .ok_or(ExecdDaemonErrorV2::DeploymentUnavailable)?;
                let release_key = loaded
                    .keys
                    .final_release_provider_tls_private_key
                    .as_ref()
                    .ok_or(ExecdDaemonErrorV2::DeploymentUnavailable)?;
                let release_credential_identity = Digest32V2::new(decode_hex_32(
                    &release_provider.credential_handle_identity_digest,
                )?);
                let release_issuer = ConnectorJobDescriptorIssuerV2::from_verified_deployment(
                    loaded.startup.installation_id(),
                    loaded.startup.active_state_manifest_digest(),
                    loaded.startup.deployment_generation(),
                    loaded.startup.effect_fence_epoch(),
                    worker_artifact_digest,
                    no_network_digest,
                    credential_absence_digest,
                    release_credential_identity,
                    loaded.keys.connector_descriptor_seed.clone(),
                )
                .map_err(|_| ExecdDaemonErrorV2::DeploymentUnavailable)?;
                let release_transport =
                    build_verified_provider_transport(release_provider, release_key.clone())?;
                Ok(Box::new(
                    VerifiedConnectorExecutionRuntimeV2::from_verified_split_components(
                        supervisor,
                        issuer,
                        release_issuer,
                        Box::new(transport),
                        Box::new(release_transport),
                    ),
                ))
            }
        }
    }

    fn build_verified_provider_transport(
        provider: &ProviderDtoV2,
        private_key: Zeroizing<Vec<u8>>,
    ) -> Result<VerifiedRustlsProviderTransportV2, ExecdDaemonErrorV2> {
        let root_certificate = read_digest_bound_file(
            &provider.root_certificate_path,
            MAX_ARTIFACT_BYTES_V2,
            &provider.root_certificate_digest,
        )?;
        if provider.client_certificate_paths.is_empty()
            || provider.client_certificate_paths.len() != provider.client_certificate_digests.len()
            || provider.client_certificate_paths.len() > 8
        {
            return Err(ExecdDaemonErrorV2::DeploymentUnavailable);
        }
        let client_certificates = provider
            .client_certificate_paths
            .iter()
            .zip(&provider.client_certificate_digests)
            .map(|(path, digest)| read_digest_bound_file(path, MAX_ARTIFACT_BYTES_V2, digest))
            .collect::<Result<Vec<_>, _>>()?;
        let credential_identity =
            Digest32V2::new(decode_hex_32(&provider.credential_handle_identity_digest)?);
        let transport = VerifiedRustlsProviderTransportV2::from_verified_manifest(
            provider
                .address
                .parse::<SocketAddr>()
                .map_err(|_| ExecdDaemonErrorV2::DeploymentUnavailable)?,
            provider.server_name.clone(),
            BoundedConnectorUrlV2::new(&provider.canonical_url)
                .map_err(|_| ExecdDaemonErrorV2::DeploymentUnavailable)?,
            Digest32V2::new(decode_hex_32(&provider.server_spki_sha256)?),
            root_certificate,
            client_certificates,
            private_key,
            decode_hex_bounded(&provider.alpn_protocol_hex, 255)?,
            Digest32V2::new(decode_hex_32(&provider.endpoint_binding_digest)?),
            credential_identity,
        )
        .map_err(|_| ExecdDaemonErrorV2::DeploymentUnavailable)?;
        Ok(transport)
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn serve(
        listener: UnixListener,
        expected_client: savana_platform_identity::ExpectedNativePeerV2,
        server: Arc<ExecdSuiteOneServerV2>,
    ) -> Result<(), ExecdDaemonErrorV2> {
        let (sender, receiver) =
            mpsc::sync_channel::<VerifiedAcceptedConnectionV2>(CONNECTION_QUEUE_CAPACITY_V2);
        let receiver = Arc::new(Mutex::new(receiver));
        for index in 0..WORKER_COUNT_V2 {
            let receiver = Arc::clone(&receiver);
            let server = Arc::clone(&server);
            std::thread::Builder::new()
                .name(format!("savana-execd-connection-v2-{index}"))
                .spawn(move || worker_loop(receiver, server))
                .map_err(|_| ExecdDaemonErrorV2::EndpointUnavailable)?;
        }
        let role_identity = BoundedIdentityStringV2::new(
            ClosedServiceEdgeIdV2::KernelExecutor
                .role_identity()
                .to_owned(),
        )
        .map_err(|_| ExecdDaemonErrorV2::DeploymentUnavailable)?;
        loop {
            let (stream, _) = listener
                .accept()
                .map_err(|_| ExecdDaemonErrorV2::EndpointUnavailable)?;
            #[cfg(target_os = "linux")]
            let pinned = match measure_linux_peer_v2(&stream) {
                Ok(value) => value,
                Err(_) => continue,
            };
            #[cfg(target_os = "linux")]
            if verify_native_peer_v2(&expected_client, &role_identity, pinned.measurement())
                .is_err()
            {
                continue;
            }
            #[cfg(target_os = "linux")]
            let binding = match peer_binding(pinned.measurement()) {
                Ok(value) => value,
                Err(()) => continue,
            };
            #[cfg(target_os = "linux")]
            let connection = VerifiedAcceptedConnectionV2 {
                stream,
                binding,
                _pinned: pinned,
            };
            #[cfg(target_os = "macos")]
            let measurement = match savana_platform_identity::measure_macos_unix_peer_v2(&stream) {
                Ok(value) => value,
                Err(_) => continue,
            };
            #[cfg(target_os = "macos")]
            if verify_native_peer_v2(&expected_client, &role_identity, &measurement).is_err() {
                continue;
            }
            #[cfg(target_os = "macos")]
            let binding = match peer_binding(&measurement) {
                Ok(value) => value,
                Err(()) => continue,
            };
            #[cfg(target_os = "macos")]
            let connection = VerifiedAcceptedConnectionV2 {
                stream,
                binding,
                _measurement: measurement,
            };
            if sender.try_send(connection).is_err() {
                continue;
            }
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn worker_loop(
        receiver: Arc<Mutex<mpsc::Receiver<VerifiedAcceptedConnectionV2>>>,
        server: Arc<ExecdSuiteOneServerV2>,
    ) {
        loop {
            let connection = match receiver.lock().ok().and_then(|value| value.recv().ok()) {
                Some(value) => value,
                None => return,
            };
            let now = match current_unix_millis() {
                Ok(value) => value,
                Err(_) => continue,
            };
            let Some(deadline) = Instant::now().checked_add(CONNECTION_DEADLINE_V2) else {
                continue;
            };
            let _ = server.serve_stream(connection.stream, connection.binding, now, deadline);
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn peer_binding(measurement: &NativePeerMeasurementV2) -> Result<PeerIdentityBindingV2, ()> {
        match measurement {
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
            .map_err(|_| ()),
            NativePeerMeasurementV2::MacOs {
                audit_token,
                euid,
                egid,
                bundle_id,
                team_id,
                code_directory_measurement,
                ..
            } => PeerIdentityBindingV2::macos(
                *audit_token,
                *euid,
                *egid,
                bundle_id.as_str().to_owned(),
                team_id.as_str().to_owned(),
                Digest32V2::new(*code_directory_measurement),
            )
            .map_err(|_| ()),
            _ => Err(()),
        }
    }

    #[cfg(target_os = "linux")]
    fn take_verified_listener(
        startup: &VerifiedDaemonStartupV2,
    ) -> Result<UnixListener, ExecdDaemonErrorV2> {
        let inherited =
            savana_platform_identity::take_systemd_unix_listeners_v2(&[EXECUTOR_FD_NAME_V2])
                .map_err(|_| ExecdDaemonErrorV2::EndpointUnavailable)?;
        let mut inherited = inherited.into_iter();
        let (name, listener) = inherited
            .next()
            .ok_or(ExecdDaemonErrorV2::EndpointUnavailable)?
            .into_parts();
        if inherited.next().is_some()
            || name != EXECUTOR_FD_NAME_V2
            || !getsockopt(&listener, AcceptConn)
                .map_err(|_| ExecdDaemonErrorV2::EndpointUnavailable)?
        {
            return Err(ExecdDaemonErrorV2::EndpointUnavailable);
        }
        let path = Path::new(EXECUTOR_SOCKET_PATH_V2);
        if listener
            .local_addr()
            .map_err(|_| ExecdDaemonErrorV2::EndpointUnavailable)?
            .as_pathname()
            != Some(path)
        {
            return Err(ExecdDaemonErrorV2::EndpointUnavailable);
        }
        let descriptor = fstat(&listener).map_err(|_| ExecdDaemonErrorV2::EndpointUnavailable)?;
        let metadata =
            fs::symlink_metadata(path).map_err(|_| ExecdDaemonErrorV2::EndpointUnavailable)?;
        let edge = startup
            .edge_lock(ClosedServiceEdgeIdV2::KernelExecutor)
            .ok_or(ExecdDaemonErrorV2::DeploymentUnavailable)?;
        let service = startup
            .service_lock(ClosedServiceIdV2::Execd)
            .ok_or(ExecdDaemonErrorV2::DeploymentUnavailable)?;
        let mode = metadata.mode() & 0o7777;
        if FileType::from_raw_mode(descriptor.st_mode) != FileType::Socket
            || metadata.file_type().is_symlink()
            || !metadata.file_type().is_socket()
            || metadata.uid() != service.socket_uid
            || metadata.gid() != service.socket_gid
            || mode != 0o660
            || listener_identity_digest_v2(
                EndpointRoleV2::KernelExecutor,
                path,
                metadata.uid(),
                metadata.gid(),
                mode,
            )
            .map_err(|_| ExecdDaemonErrorV2::EndpointUnavailable)?
                != edge.listener_identity_digest
        {
            return Err(ExecdDaemonErrorV2::EndpointUnavailable);
        }
        Ok(listener)
    }

    #[cfg(target_os = "macos")]
    fn take_verified_listener(
        startup: &VerifiedDaemonStartupV2,
    ) -> Result<UnixListener, ExecdDaemonErrorV2> {
        let inherited =
            savana_platform_identity::take_launchd_unix_listeners_v2(&[EXECUTOR_FD_NAME_V2])
                .map_err(|_| ExecdDaemonErrorV2::EndpointUnavailable)?;
        let mut inherited = inherited.into_iter();
        let (name, listener) = inherited
            .next()
            .ok_or(ExecdDaemonErrorV2::EndpointUnavailable)?
            .into_parts();
        let path = Path::new(EXECUTOR_SOCKET_PATH_V2);
        let metadata =
            fs::symlink_metadata(path).map_err(|_| ExecdDaemonErrorV2::EndpointUnavailable)?;
        let edge = startup
            .edge_lock(ClosedServiceEdgeIdV2::KernelExecutor)
            .ok_or(ExecdDaemonErrorV2::DeploymentUnavailable)?;
        let service = startup
            .service_lock(ClosedServiceIdV2::Execd)
            .ok_or(ExecdDaemonErrorV2::DeploymentUnavailable)?;
        let mode = metadata.mode() & 0o7777;
        if inherited.next().is_some()
            || name != EXECUTOR_FD_NAME_V2
            || listener
                .local_addr()
                .map_err(|_| ExecdDaemonErrorV2::EndpointUnavailable)?
                .as_pathname()
                .is_none_or(|actual| {
                    !savana_platform_identity::launchd_unix_socket_path_matches_v2(actual, path)
                })
            || metadata.file_type().is_symlink()
            || !metadata.file_type().is_socket()
            || metadata.uid() != service.socket_uid
            || metadata.gid() != service.socket_gid
            || mode != 0o660
            || listener_identity_digest_v2(
                EndpointRoleV2::KernelExecutor,
                path,
                metadata.uid(),
                metadata.gid(),
                mode,
            )
            .map_err(|_| ExecdDaemonErrorV2::EndpointUnavailable)?
                != edge.listener_identity_digest
        {
            return Err(ExecdDaemonErrorV2::EndpointUnavailable);
        }
        Ok(listener)
    }

    fn load_verified_startup(config_path: &Path) -> Result<LoadedStartupV2, ExecdDaemonErrorV2> {
        if config_path != Path::new(NATIVE_BOOTSTRAP_PATH_V2) {
            return Err(ExecdDaemonErrorV2::DeploymentUnavailable);
        }
        let bootstrap_bytes =
            read_regular_file(config_path, MAX_BOOTSTRAP_BYTES_V2, Some((0, 0, 0o444)))?;
        let bootstrap: BootstrapDtoV2 = serde_json::from_slice(&bootstrap_bytes)
            .map_err(|_| ExecdDaemonErrorV2::DeploymentUnavailable)?;
        validate_provider_routing_configuration(
            bootstrap.provider_routing_mode,
            &bootstrap.provider,
            bootstrap.final_release_provider.as_ref(),
        )?;
        if bootstrap.services.len() != SERVICE_COUNT_V2 {
            return Err(ExecdDaemonErrorV2::DeploymentUnavailable);
        }
        let startup = load_native_deployment_startup(&bootstrap)?;
        startup
            .verify_loaded_service_config_v2(ClosedServiceIdV2::Execd, &bootstrap_bytes)
            .map_err(|_| ExecdDaemonErrorV2::DeploymentUnavailable)?;
        let keys = load_key_material(&bootstrap)?;
        Ok(LoadedStartupV2 {
            startup,
            bootstrap,
            keys,
        })
    }

    #[cfg(target_os = "linux")]
    fn load_native_deployment_startup(
        bootstrap: &BootstrapDtoV2,
    ) -> Result<VerifiedDaemonStartupV2, ExecdDaemonErrorV2> {
        savana_policy_core::v2::load_verified_filesystem_startup_v2(
            Path::new(MANIFEST_ROOT_PATH_V2),
            &bootstrap.signed_manifest_path,
            &bootstrap.effect_ledger_projection_path,
            &bootstrap.services,
        )
        .map_err(|_| ExecdDaemonErrorV2::DeploymentUnavailable)
    }

    #[cfg(all(target_os = "macos", feature = "macos-development-authority"))]
    fn load_native_deployment_startup(
        bootstrap: &BootstrapDtoV2,
    ) -> Result<VerifiedDaemonStartupV2, ExecdDaemonErrorV2> {
        let root = Path::new("/Library/Application Support/Savana/Development");
        let mut paths = vec![
            &bootstrap.signed_manifest_path,
            &bootstrap.effect_ledger_projection_path,
            &bootstrap.journal_path,
            &bootstrap.rollback_anchor_path,
            &bootstrap.connector_registry_path,
            &bootstrap.connector_registry_anchor_path,
            &bootstrap.effect_gate_path,
            &bootstrap.worker.sandbox_program_path,
            &bootstrap.worker.worker_program_path,
            &bootstrap.worker.no_network_profile_path,
            &bootstrap.worker.credential_absence_profile_path,
            &bootstrap.provider.root_certificate_path,
        ];
        paths.extend(bootstrap.provider.client_certificate_paths.iter());
        if let Some(provider) = bootstrap.final_release_provider.as_ref() {
            paths.push(&provider.root_certificate_path);
            paths.extend(provider.client_certificate_paths.iter());
        }
        if paths
            .into_iter()
            .any(|path| !closed_development_path(root, path))
        {
            return Err(ExecdDaemonErrorV2::DeploymentUnavailable);
        }
        savana_policy_core::load_verified_macos_development_startup_v2(
            Path::new(MANIFEST_ROOT_PATH_V2),
            &bootstrap.signed_manifest_path,
            &bootstrap.effect_ledger_projection_path,
            &bootstrap.services,
        )
        .map_err(|_| ExecdDaemonErrorV2::DeploymentUnavailable)
    }

    #[cfg(all(target_os = "macos", not(feature = "macos-development-authority")))]
    fn load_native_deployment_startup(
        _bootstrap: &BootstrapDtoV2,
    ) -> Result<VerifiedDaemonStartupV2, ExecdDaemonErrorV2> {
        Err(ExecdDaemonErrorV2::DeploymentUnavailable)
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

    fn read_regular_file(
        path: &Path,
        maximum: usize,
        exact_identity: Option<(u32, u32, u32)>,
    ) -> Result<Vec<u8>, ExecdDaemonErrorV2> {
        if !path.is_absolute() {
            return Err(ExecdDaemonErrorV2::DeploymentUnavailable);
        }
        let before =
            fs::symlink_metadata(path).map_err(|_| ExecdDaemonErrorV2::DeploymentUnavailable)?;
        if before.file_type().is_symlink()
            || !before.is_file()
            || before.nlink() != 1
            || usize::try_from(before.len()).is_err()
            || usize::try_from(before.len()).unwrap_or(usize::MAX) > maximum
        {
            return Err(ExecdDaemonErrorV2::DeploymentUnavailable);
        }
        if let Some((uid, gid, mode)) = exact_identity {
            if before.uid() != uid || before.gid() != gid || before.mode() & 0o7777 != mode {
                return Err(ExecdDaemonErrorV2::DeploymentUnavailable);
            }
        }
        let bytes = fs::read(path).map_err(|_| ExecdDaemonErrorV2::DeploymentUnavailable)?;
        let after =
            fs::symlink_metadata(path).map_err(|_| ExecdDaemonErrorV2::DeploymentUnavailable)?;
        if before.dev() != after.dev()
            || before.ino() != after.ino()
            || before.len() != after.len()
            || bytes.len() > maximum
        {
            return Err(ExecdDaemonErrorV2::DeploymentUnavailable);
        }
        Ok(bytes)
    }

    fn read_digest_bound_file(
        path: &Path,
        maximum: usize,
        expected_digest: &str,
    ) -> Result<Vec<u8>, ExecdDaemonErrorV2> {
        let bytes = read_regular_file(path, maximum, None)?;
        if Sha256::digest(&bytes).as_slice() != decode_hex_32(expected_digest)? {
            return Err(ExecdDaemonErrorV2::DeploymentUnavailable);
        }
        Ok(bytes)
    }

    fn load_key_material(bootstrap: &BootstrapDtoV2) -> Result<KeyMaterialV2, ExecdDaemonErrorV2> {
        let server_seed = Zeroizing::new(read_exact_credential(SERVER_SEED_CREDENTIAL_V2)?);
        let provider_tls_private_key = Zeroizing::new(read_variable_credential(
            PROVIDER_TLS_PRIVATE_KEY_CREDENTIAL_V2,
            MAX_CREDENTIAL_BYTES_V2,
        )?);
        let final_release_provider_tls_private_key = match bootstrap.provider_routing_mode {
            ProviderRoutingModeDtoV2::LegacyShared => None,
            ProviderRoutingModeDtoV2::SplitFinalRelease => {
                let key = Zeroizing::new(read_variable_credential(
                    FINAL_RELEASE_PROVIDER_TLS_PRIVATE_KEY_CREDENTIAL_V2,
                    MAX_CREDENTIAL_BYTES_V2,
                )?);
                if key.as_slice() == provider_tls_private_key.as_slice() {
                    return Err(ExecdDaemonErrorV2::DeploymentUnavailable);
                }
                Some(key)
            }
        };
        Ok(KeyMaterialV2 {
            boot_id: read_exact_credential(BOOT_ID_CREDENTIAL_V2)?,
            kernel_client_public_key: read_exact_key(
                Path::new(KERNEL_CLIENT_PUBLIC_KEY_PATH_V2),
                0o444,
            )?,
            kernel_envelope_public_key: read_exact_key(
                Path::new(KERNEL_ENVELOPE_PUBLIC_KEY_PATH_V2),
                0o444,
            )?,
            server_signing_key: SigningKey::from_bytes(&server_seed),
            effect_receipt_signing_seed: read_exact_credential(EFFECT_RECEIPT_SEED_CREDENTIAL_V2)?,
            seal_private_key: read_exact_credential(SEAL_PRIVATE_KEY_CREDENTIAL_V2)?,
            journal_encryption_key: read_exact_credential(JOURNAL_ENCRYPTION_KEY_CREDENTIAL_V2)?,
            anchor_authentication_key: read_exact_credential(
                ANCHOR_AUTHENTICATION_KEY_CREDENTIAL_V2,
            )?,
            connector_descriptor_seed: Zeroizing::new(read_exact_credential(
                CONNECTOR_DESCRIPTOR_SEED_CREDENTIAL_V2,
            )?),
            provider_tls_private_key,
            final_release_provider_tls_private_key,
        })
    }

    fn credential_path(name: &str) -> Result<PathBuf, ExecdDaemonErrorV2> {
        if name.is_empty()
            || name.contains('/')
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
        {
            return Err(ExecdDaemonErrorV2::DeploymentUnavailable);
        }
        let directory = Path::new(SYSTEMD_CREDENTIAL_DIRECTORY_V2);
        let metadata = fs::symlink_metadata(directory)
            .map_err(|_| ExecdDaemonErrorV2::DeploymentUnavailable)?;
        #[cfg(target_os = "linux")]
        let valid_directory_identity = metadata.uid() == 0;
        #[cfg(target_os = "macos")]
        let valid_directory_identity =
            metadata.uid() == 0 && metadata.gid() == nix::unistd::getegid().as_raw();
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || !valid_directory_identity
            || metadata.mode() & 0o022 != 0
        {
            return Err(ExecdDaemonErrorV2::DeploymentUnavailable);
        }
        Ok(directory.join(name))
    }

    fn read_exact_credential(name: &str) -> Result<[u8; 32], ExecdDaemonErrorV2> {
        let path = credential_path(name)?;
        #[cfg(target_os = "linux")]
        let identity = (0, 0, 0o400);
        #[cfg(target_os = "macos")]
        let identity = (0, nix::unistd::getegid().as_raw(), 0o440);
        read_regular_file(&path, 32, Some(identity))?
            .try_into()
            .map_err(|_| ExecdDaemonErrorV2::DeploymentUnavailable)
    }

    fn read_variable_credential(name: &str, maximum: usize) -> Result<Vec<u8>, ExecdDaemonErrorV2> {
        let path = credential_path(name)?;
        let metadata =
            fs::symlink_metadata(&path).map_err(|_| ExecdDaemonErrorV2::DeploymentUnavailable)?;
        #[cfg(target_os = "linux")]
        let identity = (0, 0, 0o400);
        #[cfg(target_os = "macos")]
        let identity = (0, nix::unistd::getegid().as_raw(), 0o440);
        if metadata.uid() != identity.0
            || metadata.gid() != identity.1
            || metadata.mode() & 0o7777 != identity.2
        {
            return Err(ExecdDaemonErrorV2::DeploymentUnavailable);
        }
        let bytes = read_regular_file(&path, maximum, None)?;
        if bytes.is_empty() {
            return Err(ExecdDaemonErrorV2::DeploymentUnavailable);
        }
        Ok(bytes)
    }

    fn read_exact_key(path: &Path, mode: u32) -> Result<[u8; 32], ExecdDaemonErrorV2> {
        let metadata =
            fs::symlink_metadata(path).map_err(|_| ExecdDaemonErrorV2::DeploymentUnavailable)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.mode() & 0o7777 != mode
        {
            return Err(ExecdDaemonErrorV2::DeploymentUnavailable);
        }
        read_regular_file(path, 32, None)?
            .try_into()
            .map_err(|_| ExecdDaemonErrorV2::DeploymentUnavailable)
    }

    fn verify_runtime_paths(bootstrap: &BootstrapDtoV2) -> Result<(), ExecdDaemonErrorV2> {
        let durable_paths = [
            bootstrap.journal_path.as_path(),
            bootstrap.rollback_anchor_path.as_path(),
            bootstrap.connector_registry_path.as_path(),
            bootstrap.connector_registry_anchor_path.as_path(),
        ];
        let paths_are_normal = durable_paths.iter().all(|path| {
            path.is_absolute()
                && path.components().all(|component| {
                    matches!(
                        component,
                        std::path::Component::RootDir | std::path::Component::Normal(_)
                    )
                })
        });
        let paths_are_pairwise_distinct = durable_paths.iter().enumerate().all(|(index, path)| {
            durable_paths
                .iter()
                .skip(index + 1)
                .all(|other| path != other)
        });
        if !bootstrap.journal_path.is_absolute()
            || bootstrap
                .journal_path
                .file_name()
                .and_then(|name| name.to_str())
                != Some("execd-journal-v2.cbor")
            || !bootstrap.rollback_anchor_path.is_absolute()
            || !bootstrap.connector_registry_path.is_absolute()
            || bootstrap
                .connector_registry_path
                .file_name()
                .and_then(|name| name.to_str())
                != Some("connector-registry-v2.cbor")
            || !bootstrap.connector_registry_anchor_path.is_absolute()
            || !paths_are_normal
            || !paths_are_pairwise_distinct
            || !bootstrap.effect_gate_path.is_absolute()
            || !bootstrap.effect_ledger_projection_path.is_absolute()
            || bootstrap.journal_schema_version == 0
            || bootstrap.journal_key_epoch == 0
        {
            return Err(ExecdDaemonErrorV2::DeploymentUnavailable);
        }
        Ok(())
    }

    fn derive_connector_runtime_key_v2(
        master_key: &[u8; 32],
        domain: &[u8],
        installation_id: Digest32V2,
        store_id: Digest32V2,
    ) -> Result<[u8; 32], ExecdDaemonErrorV2> {
        let mut mac = Hmac::<Sha256>::new_from_slice(master_key)
            .map_err(|_| ExecdDaemonErrorV2::DeploymentUnavailable)?;
        mac.update(domain);
        mac.update(installation_id.as_bytes());
        mac.update(store_id.as_bytes());
        let derived: [u8; 32] = mac.finalize().into_bytes().into();
        if derived == [0; 32] {
            return Err(ExecdDaemonErrorV2::DeploymentUnavailable);
        }
        Ok(derived)
    }

    fn open_read_only_single_link(path: &Path) -> Result<File, ExecdDaemonErrorV2> {
        let metadata =
            fs::symlink_metadata(path).map_err(|_| ExecdDaemonErrorV2::DurableStateUnavailable)?;
        if !path.is_absolute()
            || metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.mode() & 0o222 != 0
        {
            return Err(ExecdDaemonErrorV2::DurableStateUnavailable);
        }
        File::open(path).map_err(|_| ExecdDaemonErrorV2::DurableStateUnavailable)
    }

    struct LinuxAuthenticatedExecdAnchorV2 {
        path: PathBuf,
        namespace: DurableExecdNamespaceV2,
        authentication_key: Zeroizing<[u8; 32]>,
    }

    impl LinuxAuthenticatedExecdAnchorV2 {
        fn new(
            path: PathBuf,
            namespace: DurableExecdNamespaceV2,
            authentication_key: [u8; 32],
        ) -> Result<Self, ExecdDaemonErrorV2> {
            if !path.is_absolute() || authentication_key == [0; 32] {
                return Err(ExecdDaemonErrorV2::DurableStateUnavailable);
            }
            Ok(Self {
                path,
                namespace,
                authentication_key: Zeroizing::new(authentication_key),
            })
        }

        fn read_raw_head(&self) -> Result<(u64, Digest32V2), ExecdErrorV2> {
            let metadata = match fs::symlink_metadata(&self.path) {
                Ok(value) => value,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Ok((0, Digest32V2::new([0; 32])));
                }
                Err(_) => return Err(ExecdErrorV2::DurableAuthentication),
            };
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || metadata.nlink() != 1
                || metadata.mode() & 0o7777 != 0o600
                || usize::try_from(metadata.len()).ok() != Some(AUTHENTICATED_ANCHOR_BYTES_V2)
            {
                return Err(ExecdErrorV2::DurableAuthentication);
            }
            let bytes = fs::read(&self.path).map_err(|_| ExecdErrorV2::DurableAuthentication)?;
            if bytes.len() != AUTHENTICATED_ANCHOR_BYTES_V2
                || bytes.get(..8) != Some(ANCHOR_MAGIC_V2.as_slice())
            {
                return Err(ExecdErrorV2::DurableAuthentication);
            }
            let sequence = u64::from_be_bytes(
                bytes[8..16]
                    .try_into()
                    .map_err(|_| ExecdErrorV2::DurableAuthentication)?,
            );
            let digest = Digest32V2::new(
                bytes[16..48]
                    .try_into()
                    .map_err(|_| ExecdErrorV2::DurableAuthentication)?,
            );
            self.verify_mac(sequence, digest, &bytes[48..80])?;
            if (sequence == 0) != (digest == Digest32V2::new([0; 32])) {
                return Err(ExecdErrorV2::DurableAuthentication);
            }
            Ok((sequence, digest))
        }

        fn mac(&self, sequence: u64, digest: Digest32V2) -> Result<[u8; 32], ExecdErrorV2> {
            let mut mac = Hmac::<Sha256>::new_from_slice(self.authentication_key.as_ref())
                .map_err(|_| ExecdErrorV2::DurableAuthentication)?;
            mac.update(ANCHOR_MAC_DOMAIN_V2);
            mac.update(self.namespace.installation_id().as_bytes());
            mac.update(self.namespace.store_id().as_bytes());
            mac.update(&sequence.to_be_bytes());
            mac.update(digest.as_bytes());
            Ok(mac.finalize().into_bytes().into())
        }

        fn verify_mac(
            &self,
            sequence: u64,
            digest: Digest32V2,
            candidate: &[u8],
        ) -> Result<(), ExecdErrorV2> {
            let mut mac = Hmac::<Sha256>::new_from_slice(self.authentication_key.as_ref())
                .map_err(|_| ExecdErrorV2::DurableAuthentication)?;
            mac.update(ANCHOR_MAC_DOMAIN_V2);
            mac.update(self.namespace.installation_id().as_bytes());
            mac.update(self.namespace.store_id().as_bytes());
            mac.update(&sequence.to_be_bytes());
            mac.update(digest.as_bytes());
            mac.verify_slice(candidate)
                .map_err(|_| ExecdErrorV2::DurableAuthentication)
        }

        fn write_raw_head(&self, sequence: u64, digest: Digest32V2) -> Result<(), ExecdErrorV2> {
            if (sequence == 0) != (digest == Digest32V2::new([0; 32])) {
                return Err(ExecdErrorV2::CommitUncertain);
            }
            let parent = self.path.parent().ok_or(ExecdErrorV2::CommitUncertain)?;
            let parent_metadata =
                fs::symlink_metadata(parent).map_err(|_| ExecdErrorV2::CommitUncertain)?;
            if parent_metadata.file_type().is_symlink()
                || !parent_metadata.is_dir()
                || parent_metadata.mode() & 0o022 != 0
            {
                return Err(ExecdErrorV2::CommitUncertain);
            }
            let mut bytes = Vec::with_capacity(AUTHENTICATED_ANCHOR_BYTES_V2);
            bytes.extend_from_slice(&ANCHOR_MAGIC_V2);
            bytes.extend_from_slice(&sequence.to_be_bytes());
            bytes.extend_from_slice(digest.as_bytes());
            bytes.extend_from_slice(&self.mac(sequence, digest)?);
            let entropy = u64::from_be_bytes(random_nonzero_8()?);
            let name = self
                .path
                .file_name()
                .ok_or(ExecdErrorV2::CommitUncertain)?
                .to_string_lossy();
            let temporary =
                parent.join(format!(".{name}.tmp.{}.{entropy:016x}", std::process::id()));
            let result = (|| {
                let mut file = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&temporary)
                    .map_err(|_| ExecdErrorV2::CommitUncertain)?;
                file.write_all(&bytes)
                    .and_then(|()| file.sync_all())
                    .map_err(|_| ExecdErrorV2::CommitUncertain)?;
                fs::rename(&temporary, &self.path).map_err(|_| ExecdErrorV2::CommitUncertain)?;
                File::open(parent)
                    .and_then(|directory| directory.sync_all())
                    .map_err(|_| ExecdErrorV2::CommitUncertain)
            })();
            if result.is_err() {
                let _ = fs::remove_file(&temporary);
            }
            result
        }
    }

    impl ExecdRollbackAnchorV2 for LinuxAuthenticatedExecdAnchorV2 {
        fn current_head(&self) -> Result<ExecdStateHeadV2, ExecdErrorV2> {
            let (sequence, digest) = self.read_raw_head()?;
            ExecdStateHeadV2::new(sequence, digest)
        }

        fn compare_and_advance(
            &mut self,
            expected: ExecdStateHeadV2,
            next: ExecdStateHeadV2,
        ) -> Result<(), ExecdErrorV2> {
            if self.read_raw_head()? != (expected.sequence(), expected.state_digest())
                || next.sequence()
                    != expected
                        .sequence()
                        .checked_add(1)
                        .ok_or(ExecdErrorV2::RollbackDetected)?
            {
                return Err(ExecdErrorV2::RollbackDetected);
            }
            self.write_raw_head(next.sequence(), next.state_digest())?;
            if self.read_raw_head()? != (next.sequence(), next.state_digest()) {
                return Err(ExecdErrorV2::CommitUncertain);
            }
            Ok(())
        }
    }

    impl RollbackProtectedStateAnchorV2 for LinuxAuthenticatedExecdAnchorV2 {
        fn current_head(&self) -> Result<RollbackProtectedStateHeadV2, G4Error> {
            let (sequence, digest) = self
                .read_raw_head()
                .map_err(|_| G4Error::DurableStateRollback)?;
            RollbackProtectedStateHeadV2::new(sequence, digest)
        }

        fn compare_and_advance(
            &mut self,
            expected: RollbackProtectedStateHeadV2,
            next: RollbackProtectedStateHeadV2,
        ) -> Result<(), G4Error> {
            if self
                .read_raw_head()
                .map_err(|_| G4Error::DurableStateRollback)?
                != (expected.sequence(), expected.state_digest())
                || next.sequence()
                    != expected
                        .sequence()
                        .checked_add(1)
                        .ok_or(G4Error::DurableStateRollback)?
            {
                return Err(G4Error::DurableStateRollback);
            }
            self.write_raw_head(next.sequence(), next.state_digest())
                .map_err(|_| G4Error::DurableStateIo)?;
            if self
                .read_raw_head()
                .map_err(|_| G4Error::DurableStateRollback)?
                != (next.sequence(), next.state_digest())
            {
                return Err(G4Error::DurableStateRollback);
            }
            Ok(())
        }
    }

    fn decode_hex_32(value: &str) -> Result<[u8; 32], ExecdDaemonErrorV2> {
        decode_hex_bounded(value, 32)?
            .try_into()
            .map_err(|_| ExecdDaemonErrorV2::DeploymentUnavailable)
    }

    fn decode_hex_bounded(
        value: &str,
        maximum_bytes: usize,
    ) -> Result<Vec<u8>, ExecdDaemonErrorV2> {
        if value.is_empty()
            || value.len() % 2 != 0
            || value.len() / 2 > maximum_bytes
            || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(ExecdDaemonErrorV2::DeploymentUnavailable);
        }
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let high = hex_nibble(pair[0])?;
                let low = hex_nibble(pair[1])?;
                Ok((high << 4) | low)
            })
            .collect()
    }

    fn hex_nibble(value: u8) -> Result<u8, ExecdDaemonErrorV2> {
        match value {
            b'0'..=b'9' => Ok(value - b'0'),
            b'a'..=b'f' => Ok(value - b'a' + 10),
            b'A'..=b'F' => Ok(value - b'A' + 10),
            _ => Err(ExecdDaemonErrorV2::DeploymentUnavailable),
        }
    }

    #[cfg(test)]
    fn hpke_x25519_key_id(public_key: [u8; 32]) -> HpkeX25519KeyIdV2 {
        let mut hasher = Sha256::new();
        hasher.update(b"SAVANA_HPKE_X25519_KEY_ID_V2\0");
        hasher.update(public_key);
        HpkeX25519KeyIdV2::new(hasher.finalize().into())
    }

    fn current_unix_millis() -> Result<UnixMillisV2, ExecdDaemonErrorV2> {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ExecdDaemonErrorV2::EndpointUnavailable)?
            .as_millis();
        let millis = u64::try_from(millis).map_err(|_| ExecdDaemonErrorV2::EndpointUnavailable)?;
        if millis == 0 {
            return Err(ExecdDaemonErrorV2::EndpointUnavailable);
        }
        Ok(UnixMillisV2::new(millis))
    }

    fn random_nonzero_8() -> Result<[u8; 8], ExecdErrorV2> {
        for _ in 0..4 {
            let mut bytes = [0_u8; 8];
            getrandom::getrandom(&mut bytes).map_err(|_| ExecdErrorV2::CommitUncertain)?;
            if bytes != [0; 8] {
                return Ok(bytes);
            }
        }
        Err(ExecdErrorV2::CommitUncertain)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

        #[test]
        fn runtime_paths_are_fixed_to_the_durable_journal_name() {
            let mut bootstrap = BootstrapDtoV2 {
                signed_manifest_path: "/signed".into(),
                effect_ledger_projection_path: "/projection".into(),
                services: Vec::new(),
                journal_path: "/var/lib/savana/execd/execd-journal-v2.cbor".into(),
                rollback_anchor_path: "/var/lib/savana/execd/anchor".into(),
                store_id: "11".repeat(32),
                effect_gate_path: "/run/savana/effect-gate".into(),
                executor_identity: "12".repeat(32),
                effect_receipt_key_id: "13".repeat(32),
                seal_key_id: "14".repeat(32),
                connector_set_digest: "15".repeat(32),
                connector_registry_path: "/var/lib/savana/execd/connector-registry-v2.cbor".into(),
                connector_registry_anchor_path:
                    "/var/lib/savana/execd/connector-registry-anchor-v2.bin".into(),
                connector_registry_store_id: "16".repeat(32),
                connector_registry_genesis_digest: "15".repeat(32),
                connector_authority_key_id: "00".repeat(32),
                connector_authority_public_key: "00".repeat(32),
                user_tier_host_allowlist: vec![],
                journal_schema_version: 2,
                journal_key_epoch: 1,
                worker: WorkerDtoV2 {
                    sandbox_program_path: "/sandbox".into(),
                    sandbox_program_digest: "21".repeat(32),
                    worker_program_path: "/worker".into(),
                    worker_artifact_digest: "22".repeat(32),
                    no_network_profile_path: "/no-network".into(),
                    no_network_profile_digest: "23".repeat(32),
                    credential_absence_profile_path: "/no-creds".into(),
                    credential_absence_profile_digest: "24".repeat(32),
                },
                provider_routing_mode: ProviderRoutingModeDtoV2::LegacyShared,
                provider: ProviderDtoV2 {
                    address: "127.0.0.1:443".to_owned(),
                    server_name: "provider.invalid".to_owned(),
                    canonical_url: "https://provider.invalid/".to_owned(),
                    server_spki_sha256: "30".repeat(32),
                    root_certificate_path: "/root.der".into(),
                    root_certificate_digest: "31".repeat(32),
                    client_certificate_paths: vec!["/client.der".into()],
                    client_certificate_digests: vec!["32".repeat(32)],
                    alpn_protocol_hex: "6832".to_owned(),
                    endpoint_binding_digest: "33".repeat(32),
                    credential_handle_identity_digest: "34".repeat(32),
                },
                final_release_provider: None,
            };
            assert!(verify_runtime_paths(&bootstrap).is_ok());
            bootstrap.journal_path = "/var/lib/savana/execd/renamed.cbor".into();
            assert_eq!(
                verify_runtime_paths(&bootstrap),
                Err(ExecdDaemonErrorV2::DeploymentUnavailable)
            );

            bootstrap.journal_path = "/var/lib/savana/execd/execd-journal-v2.cbor".into();
            bootstrap.connector_registry_path =
                "/var/lib/savana/execd/renamed-registry.cbor".into();
            assert_eq!(
                verify_runtime_paths(&bootstrap),
                Err(ExecdDaemonErrorV2::DeploymentUnavailable)
            );

            bootstrap.connector_registry_path = bootstrap.journal_path.clone();
            assert_eq!(
                verify_runtime_paths(&bootstrap),
                Err(ExecdDaemonErrorV2::DeploymentUnavailable)
            );

            bootstrap.connector_registry_path =
                "/var/lib/savana/execd/connector-registry-v2.cbor".into();
            bootstrap.connector_registry_anchor_path = bootstrap.rollback_anchor_path.clone();
            assert_eq!(
                verify_runtime_paths(&bootstrap),
                Err(ExecdDaemonErrorV2::DeploymentUnavailable)
            );

            let original = BootstrapDtoV2 {
                connector_registry_anchor_path:
                    "/var/lib/savana/execd/connector-registry-anchor-v2.bin".into(),
                ..bootstrap.clone()
            };
            for (left, right) in [
                ("journal", "rollback"),
                ("journal", "connector-anchor"),
                ("registry", "rollback"),
                ("registry", "connector-anchor"),
            ] {
                let mut aliased = original.clone();
                let value = match right {
                    "rollback" => aliased.rollback_anchor_path.clone(),
                    "connector-anchor" => aliased.connector_registry_anchor_path.clone(),
                    _ => unreachable!(),
                };
                match left {
                    "journal" => aliased.journal_path = value,
                    "registry" => aliased.connector_registry_path = value,
                    _ => unreachable!(),
                }
                assert_eq!(
                    verify_runtime_paths(&aliased),
                    Err(ExecdDaemonErrorV2::DeploymentUnavailable),
                    "{left} must not alias {right}"
                );
            }

            let mut non_normal = original;
            non_normal.connector_registry_anchor_path =
                "/var/lib/savana/execd/../execd/anchor".into();
            assert_eq!(
                verify_runtime_paths(&non_normal),
                Err(ExecdDaemonErrorV2::DeploymentUnavailable)
            );
        }

        #[test]
        fn connector_store_keys_are_domain_installation_and_namespace_separated() {
            let master = [0x41; 32];
            let installation = Digest32V2::new([0x42; 32]);
            let store = Digest32V2::new([0x43; 32]);
            let key = derive_connector_runtime_key_v2(
                &master,
                CONNECTOR_STORE_KEY_DERIVATION_DOMAIN_V2,
                installation,
                store,
            )
            .unwrap();
            assert_eq!(
                key,
                derive_connector_runtime_key_v2(
                    &master,
                    CONNECTOR_STORE_KEY_DERIVATION_DOMAIN_V2,
                    installation,
                    store,
                )
                .unwrap()
            );
            assert_ne!(key, [0; 32]);
            assert_ne!(key, master);
            assert_ne!(
                key,
                derive_connector_runtime_key_v2(
                    &master,
                    CONNECTOR_ANCHOR_KEY_DERIVATION_DOMAIN_V2,
                    installation,
                    store,
                )
                .unwrap()
            );
            assert_ne!(
                key,
                derive_connector_runtime_key_v2(
                    &master,
                    CONNECTOR_STORE_KEY_DERIVATION_DOMAIN_V2,
                    Digest32V2::new([0x44; 32]),
                    store,
                )
                .unwrap()
            );
            assert_ne!(
                key,
                derive_connector_runtime_key_v2(
                    &master,
                    CONNECTOR_STORE_KEY_DERIVATION_DOMAIN_V2,
                    installation,
                    Digest32V2::new([0x45; 32]),
                )
                .unwrap()
            );
        }

        #[test]
        fn provider_routing_mode_defaults_to_legacy_shared() {
            #[derive(Deserialize)]
            struct RoutingDefault {
                #[serde(default)]
                provider_routing_mode: ProviderRoutingModeDtoV2,
            }

            let parsed: RoutingDefault = serde_json::from_str("{}").unwrap();
            assert_eq!(
                parsed.provider_routing_mode,
                ProviderRoutingModeDtoV2::LegacyShared
            );
        }

        #[test]
        fn split_provider_routing_is_closed_and_requires_distinct_manifest_bindings() {
            let provider = ProviderDtoV2 {
                address: "127.0.0.1:9444".to_owned(),
                server_name: "provider.invalid".to_owned(),
                canonical_url: "https://provider.invalid:9444/mcp".to_owned(),
                server_spki_sha256: "30".repeat(32),
                root_certificate_path: "/tool-root.der".into(),
                root_certificate_digest: "31".repeat(32),
                client_certificate_paths: vec!["/tool-client.der".into()],
                client_certificate_digests: vec!["32".repeat(32)],
                alpn_protocol_hex: "736176616e612d70726f76696465722d7632".to_owned(),
                endpoint_binding_digest: "33".repeat(32),
                credential_handle_identity_digest: "34".repeat(32),
            };

            assert_eq!(
                validate_provider_routing_configuration(
                    ProviderRoutingModeDtoV2::SplitFinalRelease,
                    &provider,
                    None,
                ),
                Err(ExecdDaemonErrorV2::DeploymentUnavailable)
            );
            assert_eq!(
                validate_provider_routing_configuration(
                    ProviderRoutingModeDtoV2::LegacyShared,
                    &provider,
                    Some(&provider),
                ),
                Err(ExecdDaemonErrorV2::DeploymentUnavailable)
            );
            assert_eq!(
                validate_provider_routing_configuration(
                    ProviderRoutingModeDtoV2::SplitFinalRelease,
                    &provider,
                    Some(&provider),
                ),
                Err(ExecdDaemonErrorV2::DeploymentUnavailable)
            );

            let mut release = provider.clone();
            release.address = "127.0.0.1:43191".to_owned();
            release.server_name = "release.invalid".to_owned();
            release.canonical_url = "https://release.invalid:43191/savana/final-release".to_owned();
            release.server_spki_sha256 = "40".repeat(32);
            release.root_certificate_path = "/release-root.der".into();
            release.root_certificate_digest = "41".repeat(32);
            release.client_certificate_paths = vec!["/release-client.der".into()];
            release.client_certificate_digests = vec!["42".repeat(32)];
            release.endpoint_binding_digest = "43".repeat(32);
            release.credential_handle_identity_digest = "44".repeat(32);

            assert!(validate_provider_routing_configuration(
                ProviderRoutingModeDtoV2::SplitFinalRelease,
                &provider,
                Some(&release),
            )
            .is_ok());

            let shared_intermediate_path: PathBuf = "/shared-intermediate.der".into();
            let shared_intermediate_digest = "45".repeat(32);
            let mut provider_with_chain = provider.clone();
            provider_with_chain
                .client_certificate_paths
                .push(shared_intermediate_path.clone());
            provider_with_chain
                .client_certificate_digests
                .push(shared_intermediate_digest.clone());
            release
                .client_certificate_paths
                .push(shared_intermediate_path);
            release
                .client_certificate_digests
                .push(shared_intermediate_digest);
            assert!(validate_provider_routing_configuration(
                ProviderRoutingModeDtoV2::SplitFinalRelease,
                &provider_with_chain,
                Some(&release),
            )
            .is_ok());
        }

        #[test]
        fn seal_key_id_matches_the_protocol_derivation() {
            let secret = StaticSecret::from([0x55; 32]);
            let public = X25519PublicKey::from(&secret).to_bytes();
            assert_eq!(
                hpke_x25519_key_id(public),
                crate::protocol_service::hpke_x25519_key_id(public)
            );
        }
    }
}

pub(crate) use implementation::run;
