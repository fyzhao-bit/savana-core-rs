use std::path::Path;

use savana_kernel_protocol::v2::BootIdV2;
use savana_kernel_protocol::StableCode;

use crate::server::ServerLifecycle;

/// Starts the required-mode V2 runtime. Unsupported native platforms and any
/// missing deployment authority fail before readiness is published.
pub(crate) fn run(
    config_path: &Path,
    boot_id: BootIdV2,
    lifecycle: &mut dyn ServerLifecycle,
) -> Result<(), StableCode> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        native::run(config_path, boot_id, lifecycle)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (config_path, boot_id, lifecycle);
        Err(StableCode::KernelUnavailable)
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod native {
    use std::fs;
    use std::io::Write as _;
    use std::os::unix::fs::MetadataExt as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    use ed25519_dalek::SigningKey;
    use hmac::{Hmac, Mac as _};
    use savana_kernel_protocol::v2::{
        derive_ed25519_key_id_v2, BootIdV2, ClosedExtensionClassV2, Digest32V2, Ed25519KeyIdV2,
        ExecutorIdentityV2, HpkeX25519KeyIdV2, ImplementationIdV2, PeerIdentityBindingV2,
        ProducerIdentityV2, RoleIdV2, UnixMillisV2, VersionV2,
    };
    use savana_kernel_protocol::StableCode;
    use savana_policy_core::v2::{
        activate_internal_validator_registry, ActiveToolRegistryV2, ContextFieldV2,
        DurableG4StateV2, DurableStateNamespaceV2, FilesystemServiceObservationConfigV2,
        InternalValidatorBuildV2, InternalValidatorDeclarationV2,
        InternalValidatorImplementationKindV2, OntologyExprV2, OntologyOperandV2, OntologyScalarV2,
        SignedToolDescriptorV2, VerifiedInternalValidatorRegistryV2,
        VerifiedManifestToolConstraintSetV2, VerifiedManifestToolConstraintV2,
        VerifiedPolicyDispositionV2, VerifiedPolicyToolActivationV2, VerifiedPolicyToolSetV2,
        VerifiedRegistryPublisherV2, VerifiedToolRegistryV2,
    };
    use serde::Deserialize;
    use sha2::{Digest as _, Sha256};
    use zeroize::Zeroizing;

    use super::ServerLifecycle;
    use crate::deployment_trust::{
        ClosedServiceEdgeIdV2, ClosedServiceIdV2, VerifiedDaemonStartupV2,
    };
    use crate::policy_runtime::V2GenerationRuntime;
    #[cfg(target_os = "linux")]
    use crate::v2_activation::take_kerneld_systemd_listeners_v2;
    #[cfg(target_os = "macos")]
    use crate::v2_activation::{
        verify_kerneld_inherited_listeners_v2, InheritedListenerV2,
        VerifiedInheritedKerneldListenersV2, AGENT_KERNEL_FD_NAME_V2, INGRESS_KERNEL_FD_NAME_V2,
    };
    use crate::v2_agent_authority::{
        KernelAgentAuthorityV2, KernelAgentSecurityConfigV2, KernelG4G5RuntimeV2,
        KernelG7RuntimeV2, KernelToolApprovalConfigV2,
    };
    use crate::v2_core_services::CoreKernelRuntimeServicesV2;
    use crate::v2_data_plane::ProductionKernelDataPlaneV2;
    use crate::v2_dispatch::{KernelServiceDeploymentV2, KernelServiceDispatcherV2};
    use crate::v2_edge::VerifiedServiceEdgeV2;
    use crate::v2_executor_client::SuiteOneKernelExecutorClientV2;
    use crate::v2_ingress_authority::{KernelIngressAuthorityV2, KernelIngressSecurityConfigV2};
    use crate::v2_input_owner::KernelParserTrustV2;
    use crate::v2_kernel_owner::KernelRuntimeOwnerV2;
    use crate::v2_listener::KerneldV2EndpointListener;
    #[cfg(target_os = "linux")]
    use crate::v2_listener::LinuxNativeUnixPeerVerifierV2;
    #[cfg(target_os = "macos")]
    use crate::v2_listener::NativeUnixPeerVerifierV2;
    use crate::v2_server::run_kerneld_v2_workers;
    use crate::v2_transport_owner::KernelV2HandshakeOwner;

    #[cfg(target_os = "linux")]
    const NATIVE_BOOTSTRAP_PATH_V2: &str = "/etc/savana/kerneld-bootstrap-v2.json";
    #[cfg(target_os = "linux")]
    const MANIFEST_ROOT_PATH_V2: &str = "/etc/savana/trust/deployment-manifest-root-v2.json";
    #[cfg(target_os = "linux")]
    const AGENT_CLIENT_PUBLIC_KEY_PATH_V2: &str = "/etc/savana/kerneld/keys/agentd-kernel-v2.pub";
    #[cfg(target_os = "linux")]
    const INGRESS_CLIENT_PUBLIC_KEY_PATH_V2: &str =
        "/etc/savana/kerneld/keys/ingressd-kernel-v2.pub";
    #[cfg(target_os = "linux")]
    const NATIVE_CREDENTIAL_DIRECTORY_V2: &str = "/run/credentials/savana-kerneld.service";
    #[cfg(target_os = "linux")]
    const EXECUTOR_SERVER_PUBLIC_KEY_PATH_V2: &str = "/etc/savana/kerneld/keys/execd-kernel-v2.pub";

    #[cfg(all(target_os = "macos", feature = "macos-development-authority"))]
    const DEVELOPMENT_ROOT_V2: &str = "/Library/Application Support/Savana/Development";
    #[cfg(target_os = "macos")]
    const NATIVE_BOOTSTRAP_PATH_V2: &str =
        "/Library/Application Support/Savana/Development/config/kerneld-bootstrap-v2.json";
    #[cfg(all(target_os = "macos", feature = "macos-development-authority"))]
    const MANIFEST_ROOT_PATH_V2: &str = "/Library/Application Support/Savana/Development/config/trust/deployment-manifest-root-v2.json";
    #[cfg(target_os = "macos")]
    const AGENT_CLIENT_PUBLIC_KEY_PATH_V2: &str =
        "/Library/Application Support/Savana/Development/config/kerneld/keys/agentd-kernel-v2.pub";
    #[cfg(target_os = "macos")]
    const INGRESS_CLIENT_PUBLIC_KEY_PATH_V2: &str = "/Library/Application Support/Savana/Development/config/kerneld/keys/ingressd-kernel-v2.pub";
    #[cfg(target_os = "macos")]
    const EXECUTOR_SERVER_PUBLIC_KEY_PATH_V2: &str =
        "/Library/Application Support/Savana/Development/config/kerneld/keys/execd-kernel-v2.pub";
    #[cfg(target_os = "macos")]
    const NATIVE_CREDENTIAL_DIRECTORY_V2: &str =
        "/Library/Application Support/Savana/Development/credentials/kerneld";
    #[cfg(target_os = "macos")]
    const AGENT_KERNEL_SOCKET_PATH_V2: &str =
        "/Library/Application Support/Savana/Development/run/kerneld/agentd/kerneld.sock";
    #[cfg(target_os = "macos")]
    const INGRESS_KERNEL_SOCKET_PATH_V2: &str =
        "/Library/Application Support/Savana/Development/run/kerneld/ingressd/kerneld.sock";
    const AGENT_SERVER_SEED_CREDENTIAL_V2: &str = "agent-kernel-v2.seed";
    const KERNELD_BOOT_ID_CREDENTIAL_V2: &str = "kerneld-boot-v2.id";
    const INGRESS_SERVER_SEED_CREDENTIAL_V2: &str = "ingress-kernel-v2.seed";
    const ENVELOPE_SIGNING_SEED_CREDENTIAL_V2: &str = "envelope-signing-v2.seed";
    const AUTHORITY_ENVELOPE_SEED_CREDENTIAL_V2: &str = "authority-envelope-v2.seed";
    const TASK_CORRELATION_SEED_CREDENTIAL_V2: &str = "task-correlation-v2.seed";
    const VAULT_ENCRYPTION_KEY_CREDENTIAL_V2: &str = "vault-encryption-v2.key";
    const VAULT_ANCHOR_AUTHENTICATION_KEY_CREDENTIAL_V2: &str =
        "vault-anchor-authentication-v2.key";
    const AGENT_STATE_ENCRYPTION_KEY_CREDENTIAL_V2: &str =
        "agent-authority-state-encryption-v2.key";
    const AGENT_STATE_ANCHOR_AUTHENTICATION_KEY_CREDENTIAL_V2: &str =
        "agent-authority-anchor-authentication-v2.key";
    const G4_STATE_ENCRYPTION_KEY_CREDENTIAL_V2: &str = "g4-state-encryption-v2.key";
    const G4_STATE_ANCHOR_AUTHENTICATION_KEY_CREDENTIAL_V2: &str =
        "g4-anchor-authentication-v2.key";
    const EXECUTOR_CLIENT_SEED_CREDENTIAL_V2: &str = "executor-kernel-v2.seed";
    const MAX_BOOTSTRAP_BYTES_V2: usize = 128 * 1024;
    const MAX_ARTIFACT_BYTES_V2: usize = 256 * 1024 * 1024;
    const MAX_SERVICE_COUNT_V2: usize = 5;
    const VAULT_ANCHOR_MAC_DOMAIN_V2: &[u8] = b"SAVANA_VAULT_ANCHOR_MAC_V2\0";
    const AGENT_ANCHOR_MAC_DOMAIN_V2: &[u8] = b"SAVANA_AGENT_AUTHORITY_ANCHOR_MAC_V2\0";
    const G4_ANCHOR_MAC_DOMAIN_V2: &[u8] = b"SAVANA_G4_ANCHOR_MAC_V2\0";
    const VAULT_ANCHOR_MAGIC_V2: [u8; 8] = *b"SV2ANCH\0";
    const AGENT_ANCHOR_MAGIC_V2: [u8; 8] = *b"SA2ANCH\0";
    const G4_ANCHOR_MAGIC_V2: [u8; 8] = *b"SG2ANCH\0";
    const AUTHENTICATED_ANCHOR_BYTES_V2: usize = 80;

    #[derive(Deserialize)]
    #[cfg_attr(
        all(target_os = "macos", not(feature = "macos-development-authority")),
        allow(dead_code)
    )]
    #[serde(deny_unknown_fields)]
    struct BootstrapDtoV2 {
        #[cfg_attr(
            all(target_os = "macos", not(feature = "macos-development-authority")),
            allow(dead_code)
        )]
        signed_manifest_path: PathBuf,
        #[cfg_attr(
            all(target_os = "macos", not(feature = "macos-development-authority")),
            allow(dead_code)
        )]
        effect_ledger_projection_path: PathBuf,
        input_runtime_assets_path: PathBuf,
        input_runtime_publisher_key_id: String,
        input_runtime_publisher_public_key: String,
        ui_settlement_key_id: String,
        ui_settlement_public_key: String,
        ingress_settlement_key_id: String,
        ingress_settlement_public_key: String,
        agentd_boot_id: String,
        approvald_boot_id: String,
        machine_boot_id: String,
        agentd_peer_identity_digest: String,
        vault_state_path: PathBuf,
        vault_rollback_anchor_path: PathBuf,
        vault_store_id: String,
        agent_authority_state_path: PathBuf,
        agent_authority_rollback_anchor_path: PathBuf,
        agent_authority_store_id: String,
        g4_state_path: PathBuf,
        g4_rollback_anchor_path: PathBuf,
        g4_store_id: String,
        policy_allowed_effect_bits: u16,
        logical_run_ttl_ms: u64,
        policy_runtime: PolicyRuntimeDtoV2,
        parser_trust: ParserTrustDtoV2,
        services: Vec<FilesystemServiceObservationConfigV2>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct PolicyRuntimeDtoV2 {
        registry_version: [u16; 3],
        registry_publisher_key_id: String,
        registry_publisher_public_key: String,
        registry_not_before: u64,
        registry_expires_at: u64,
        signed_tool_descriptor_paths: Vec<PathBuf>,
        policy_activations: Vec<PolicyActivationDtoV2>,
        manifest_constraints: Vec<ManifestConstraintDtoV2>,
        validator_builds: Vec<ValidatorBuildDtoV2>,
        role_id: u32,
        disposition: String,
        tool_settlement_key_id: String,
        tool_settlement_public_key: String,
        quota_limit: u32,
        quota_policy_digest: String,
        execd_boot_id: String,
        executor_identity: String,
        executor_seal_key_id: String,
        executor_seal_public_key: String,
        executor_connector_registry_digest: String,
        executor_receipt_key_id: String,
        executor_receipt_public_key: String,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct PolicyActivationDtoV2 {
        descriptor_digest: String,
        registry_ordinal: u32,
        policy_activation_digest: String,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ManifestConstraintDtoV2 {
        descriptor_digest: String,
        maximum_attempts: u16,
        maximum_elapsed_ns: u64,
        internal_validators: Vec<ValidatorDeclarationDtoV2>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ValidatorDeclarationDtoV2 {
        implementation_id: u32,
        semantic_version: [u16; 3],
        build_manifest_digest: String,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ValidatorBuildDtoV2 {
        kind: u16,
        implementation_id: u32,
        semantic_version: [u16; 3],
        build_manifest_digest: String,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ParserTrustDtoV2 {
        descriptor_key_id: String,
        descriptor_public_key: String,
        worker_artifact_digest: String,
        implementation_id: u32,
        semantic_version: [u16; 3],
        parser_code_digest: String,
        renderer_code_digest: Option<String>,
        ocr_model_set_digest: Option<String>,
        normalization_version: [u16; 3],
        output_limits_digest: String,
        extension_class: u32,
        maximum_pages: u32,
        maximum_output_bytes: usize,
    }

    struct KernelKeyMaterialV2 {
        boot_id: [u8; 32],
        agent_client_public_key: [u8; 32],
        ingress_client_public_key: [u8; 32],
        agent_server_signing_key: SigningKey,
        ingress_server_signing_key: SigningKey,
        envelope_signing_key: SigningKey,
        authority_envelope_signing_key: SigningKey,
        task_correlation_signing_key: SigningKey,
        vault_encryption_key: [u8; 32],
        vault_anchor_authentication_key: [u8; 32],
        agent_state_encryption_key: [u8; 32],
        agent_state_anchor_authentication_key: [u8; 32],
        g4_state_encryption_key: [u8; 32],
        g4_anchor_authentication_key: [u8; 32],
        executor_client_signing_key: SigningKey,
        executor_server_public_key: [u8; 32],
    }

    struct RuntimeMaterialV2 {
        input_runtime_assets: Vec<u8>,
        input_runtime_publisher_key_id: Ed25519KeyIdV2,
        input_runtime_publisher_public_key: [u8; 32],
        ui_settlement_key_id: Ed25519KeyIdV2,
        ui_settlement_public_key: [u8; 32],
        ingress_settlement_key_id: Ed25519KeyIdV2,
        ingress_settlement_public_key: [u8; 32],
        agentd_boot_id: BootIdV2,
        approvald_boot_id: BootIdV2,
        machine_boot_id: BootIdV2,
        agentd_peer_identity_digest: Digest32V2,
        vault_state_path: PathBuf,
        vault_rollback_anchor_path: PathBuf,
        vault_store_id: Digest32V2,
        agent_authority_state_path: PathBuf,
        agent_authority_rollback_anchor_path: PathBuf,
        agent_authority_store_id: Digest32V2,
        g4_state_path: PathBuf,
        g4_rollback_anchor_path: PathBuf,
        g4_store_id: Digest32V2,
        policy_allowed_effects: savana_policy_core::v2::EffectSetV2,
        logical_run_ttl_ms: u64,
        policy: LoadedPolicyRuntimeV2,
        parser_trust: KernelParserTrustV2,
    }

    struct LoadedPolicyRuntimeV2 {
        active_tools: ActiveToolRegistryV2,
        validators: VerifiedInternalValidatorRegistryV2,
        role: RoleIdV2,
        ontology: OntologyExprV2,
        disposition: VerifiedPolicyDispositionV2,
        tool_settlement_key_id: Ed25519KeyIdV2,
        tool_settlement_public_key: [u8; 32],
        quota_limit: u32,
        quota_policy_digest: Digest32V2,
        execd_boot_id: BootIdV2,
        executor_identity: ExecutorIdentityV2,
        executor_seal_key_id: HpkeX25519KeyIdV2,
        executor_seal_public_key: [u8; 32],
        executor_connector_registry_digest: Digest32V2,
        executor_receipt_key_id: Ed25519KeyIdV2,
        executor_receipt_public_key: [u8; 32],
    }

    #[cfg(target_os = "macos")]
    struct MacOsNativeUnixPeerVerifierV2;

    #[cfg(target_os = "macos")]
    impl NativeUnixPeerVerifierV2 for MacOsNativeUnixPeerVerifierV2 {
        fn verify(
            &self,
            stream: &std::os::unix::net::UnixStream,
            edge: &VerifiedServiceEdgeV2,
        ) -> Result<
            crate::v2_edge::VerifiedAcceptedPeerV2,
            crate::deployment_trust::DeploymentTrustErrorV2,
        > {
            let measurement = savana_platform_identity::measure_macos_unix_peer_v2(stream)
                .map_err(|_| crate::deployment_trust::DeploymentTrustErrorV2::EdgeLockMismatch)?;
            edge.verify_native_peer(&measurement)
        }
    }

    #[cfg(target_os = "linux")]
    fn take_kerneld_native_listeners_v2(
        agent_listener_identity: Digest32V2,
        ingress_listener_identity: Digest32V2,
    ) -> Result<
        crate::v2_activation::VerifiedInheritedKerneldListenersV2,
        crate::deployment_trust::DeploymentTrustErrorV2,
    > {
        take_kerneld_systemd_listeners_v2(agent_listener_identity, ingress_listener_identity)
    }

    #[cfg(target_os = "macos")]
    fn take_kerneld_native_listeners_v2(
        agent_listener_identity: Digest32V2,
        ingress_listener_identity: Digest32V2,
    ) -> Result<VerifiedInheritedKerneldListenersV2, crate::deployment_trust::DeploymentTrustErrorV2>
    {
        let inherited = savana_platform_identity::take_launchd_unix_listeners_v2(&[
            AGENT_KERNEL_FD_NAME_V2,
            INGRESS_KERNEL_FD_NAME_V2,
        ])
        .map_err(|_| crate::deployment_trust::DeploymentTrustErrorV2::UnsafeSocket)?;
        let mut inherited = inherited.into_iter();
        let (agent_name, agent_listener) = inherited
            .next()
            .ok_or(crate::deployment_trust::DeploymentTrustErrorV2::UnsafeSocket)?
            .into_parts();
        let (ingress_name, ingress_listener) = inherited
            .next()
            .ok_or(crate::deployment_trust::DeploymentTrustErrorV2::UnsafeSocket)?
            .into_parts();
        if inherited.next().is_some()
            || agent_name != AGENT_KERNEL_FD_NAME_V2
            || ingress_name != INGRESS_KERNEL_FD_NAME_V2
        {
            return Err(crate::deployment_trust::DeploymentTrustErrorV2::UnsafeSocket);
        }
        verify_kerneld_inherited_listeners_v2(
            [
                InheritedListenerV2::new(AGENT_KERNEL_FD_NAME_V2, agent_listener),
                InheritedListenerV2::new(INGRESS_KERNEL_FD_NAME_V2, ingress_listener),
            ],
            (
                Path::new(AGENT_KERNEL_SOCKET_PATH_V2),
                agent_listener_identity,
            ),
            (
                Path::new(INGRESS_KERNEL_SOCKET_PATH_V2),
                ingress_listener_identity,
            ),
        )
    }

    pub(super) fn run(
        config_path: &Path,
        _process_boot_id: BootIdV2,
        lifecycle: &mut dyn ServerLifecycle,
    ) -> Result<(), StableCode> {
        let (startup, keys, runtime_material) = load_verified_startup(config_path)?;
        let self_lock = startup
            .service_lock(ClosedServiceIdV2::Kerneld)
            .ok_or(StableCode::KernelUnavailable)?;
        #[cfg(target_os = "linux")]
        let _self_process = savana_platform_identity::pin_current_linux_service_v2(
            self_lock.uid,
            self_lock.gid,
            *self_lock.executable_digest.as_bytes(),
        )
        .map_err(|_| StableCode::KernelUnavailable)?;
        #[cfg(target_os = "macos")]
        let _self_process = savana_platform_identity::pin_current_macos_service_v2(
            self_lock.uid,
            self_lock.gid,
            *self_lock.executable_digest.as_bytes(),
            *self_lock.code_identity_digest.as_bytes(),
        )
        .map_err(|_| StableCode::KernelUnavailable)?;
        let boot_id = BootIdV2::new(keys.boot_id);
        let agent_edge = Arc::new(
            VerifiedServiceEdgeV2::from_verified_startup(
                &startup,
                ClosedServiceEdgeIdV2::AgentKernel,
            )
            .map_err(|_| StableCode::KernelUnavailable)?,
        );
        let ingress_edge = Arc::new(
            VerifiedServiceEdgeV2::from_verified_startup(
                &startup,
                ClosedServiceEdgeIdV2::IngressKernel,
            )
            .map_err(|_| StableCode::KernelUnavailable)?,
        );
        let inherited = take_kerneld_native_listeners_v2(
            agent_edge.listener_identity_digest(),
            ingress_edge.listener_identity_digest(),
        )
        .map_err(|_| StableCode::KernelUnavailable)?;
        let (agent_listener, ingress_listener) = inherited.into_parts();

        let runtime = Arc::new(V2GenerationRuntime::new());
        runtime.activate(&startup)?;
        let kernel_identity = startup
            .service_identity(ClosedServiceIdV2::Kerneld)
            .ok_or(StableCode::KernelUnavailable)?;
        let deployment = KernelServiceDeploymentV2::from_verified_startup(
            boot_id,
            kernel_identity,
            startup.active_state_manifest_digest(),
            startup.deployment_generation(),
        )
        .map_err(|_| StableCode::KernelUnavailable)?;
        let (mut services, readiness) =
            CoreKernelRuntimeServicesV2::new_production_starting(128, 64 * 1024 * 1024, 256, 4096)?;
        let now = current_unix_millis()?;
        let agentd_identity = startup
            .service_identity(ClosedServiceIdV2::Agentd)
            .ok_or(StableCode::KernelUnavailable)?;
        let ingressd_identity = startup
            .service_identity(ClosedServiceIdV2::Ingressd)
            .ok_or(StableCode::KernelUnavailable)?;
        let approvald_identity = startup
            .service_identity(ClosedServiceIdV2::Approvald)
            .ok_or(StableCode::KernelUnavailable)?;
        let input_assets = savana_input_runtime::SignedInputRuntimeAssetsV2::from_canonical_bytes(
            &runtime_material.input_runtime_assets,
        )
        .map_err(|_| StableCode::KernelUnavailable)?;
        let verified_input_assets = savana_input_runtime::VerifiedInputRuntimeAssetsV2::verify(
            &input_assets,
            runtime_material.input_runtime_publisher_key_id,
            runtime_material.input_runtime_publisher_public_key,
            now,
        )
        .map_err(|_| StableCode::KernelUnavailable)?;
        let input_runtime = savana_input_runtime::InputRuntimeV2::new(verified_input_assets);
        let vault_namespace = savana_vault::DurableVaultNamespaceV2::from_verified_installation(
            startup.installation_id(),
            runtime_material.vault_store_id,
        )
        .map_err(|_| StableCode::KernelUnavailable)?;
        let vault_anchor = PosixAuthenticatedAnchorFileV2::new(
            runtime_material.vault_rollback_anchor_path,
            startup.installation_id(),
            runtime_material.vault_store_id,
            keys.vault_anchor_authentication_key,
            VAULT_ANCHOR_MAC_DOMAIN_V2,
            VAULT_ANCHOR_MAGIC_V2,
        )?;
        let vault = savana_vault::DurableVaultServiceV2::open(
            &runtime_material.vault_state_path,
            keys.vault_encryption_key,
            vault_namespace,
            Box::new(vault_anchor),
            savana_vault::VaultServiceV2::from_verified_deployment(
                startup.installation_id(),
                startup.active_state_manifest_digest(),
                boot_id,
                128,
            )
            .map_err(|_| StableCode::KernelUnavailable)?,
        )
        .map_err(|_| StableCode::KernelUnavailable)?;
        let agent_security = KernelAgentSecurityConfigV2::new(
            startup.installation_id(),
            kernel_identity,
            agentd_identity,
            approvald_identity,
            runtime_material.agentd_boot_id,
            boot_id,
            runtime_material.approvald_boot_id,
            runtime_material.machine_boot_id,
            keys.task_correlation_signing_key,
            keys.authority_envelope_signing_key.clone(),
            runtime_material.ui_settlement_key_id,
            runtime_material.ui_settlement_public_key,
        )
        .map_err(|_| StableCode::KernelUnavailable)?;
        let agent_anchor = PosixAuthenticatedAnchorFileV2::new(
            runtime_material.agent_authority_rollback_anchor_path,
            startup.installation_id(),
            runtime_material.agent_authority_store_id,
            keys.agent_state_anchor_authentication_key,
            AGENT_ANCHOR_MAC_DOMAIN_V2,
            AGENT_ANCHOR_MAGIC_V2,
        )?;
        let mut agent_authority = KernelAgentAuthorityV2::open_durable(
            agent_security,
            65_536,
            &runtime_material.agent_authority_state_path,
            keys.agent_state_encryption_key,
            runtime_material.agent_authority_store_id,
            Box::new(agent_anchor),
            now,
        )
        .map_err(|_| StableCode::KernelUnavailable)?;
        let g4_namespace = DurableStateNamespaceV2::from_verified_installation(
            startup.installation_id(),
            runtime_material.g4_store_id,
        )
        .map_err(|_| StableCode::KernelUnavailable)?;
        let g4_anchor = PosixAuthenticatedAnchorFileV2::new(
            runtime_material.g4_rollback_anchor_path,
            startup.installation_id(),
            runtime_material.g4_store_id,
            keys.g4_anchor_authentication_key,
            G4_ANCHOR_MAC_DOMAIN_V2,
            G4_ANCHOR_MAGIC_V2,
        )?;
        let g4_durable = DurableG4StateV2::open(
            &runtime_material.g4_state_path,
            keys.g4_state_encryption_key,
            g4_namespace,
            Box::new(g4_anchor),
        )
        .map_err(|_| StableCode::KernelUnavailable)?;
        let approval = KernelToolApprovalConfigV2::from_verified_manifest(
            approvald_identity,
            runtime_material.policy.tool_settlement_key_id,
            runtime_material.policy.tool_settlement_public_key,
        )
        .map_err(|_| StableCode::KernelUnavailable)?;
        let mut policy_runtime = KernelG4G5RuntimeV2::from_verified_policy(
            runtime_material.policy.active_tools,
            runtime_material.policy.validators,
            g4_durable,
            runtime_material.policy.role,
            runtime_material.policy.ontology,
            runtime_material.policy.disposition,
            approval,
        )
        .map_err(|_| StableCode::KernelUnavailable)?;
        let executor_edge = startup
            .kernel_service_handshake_edge(
                ClosedServiceEdgeIdV2::KernelExecutor,
                runtime_material.policy.execd_boot_id,
            )
            .map_err(|_| StableCode::KernelUnavailable)?;
        let executor_client = SuiteOneKernelExecutorClientV2::from_verified_deployment(
            executor_edge,
            boot_id,
            current_native_self_peer_binding()?,
            keys.executor_client_signing_key,
            keys.executor_server_public_key,
        )
        .map_err(|_| StableCode::KernelUnavailable)?;
        let projection = startup.verified_effect_ledger_projection();
        let g7_runtime = KernelG7RuntimeV2::from_verified_deployment(
            runtime_material.policy.quota_limit,
            runtime_material.policy.quota_policy_digest,
            runtime_material.policy.executor_identity,
            runtime_material.policy.executor_seal_key_id,
            runtime_material.policy.executor_seal_public_key,
            runtime_material.policy.executor_connector_registry_digest,
            projection,
            keys.envelope_signing_key.clone(),
            runtime_material.policy.executor_receipt_key_id,
            runtime_material.policy.executor_receipt_public_key,
            executor_client,
        )
        .map_err(|_| StableCode::KernelUnavailable)?;
        policy_runtime
            .install_g7(g7_runtime)
            .map_err(|_| StableCode::KernelUnavailable)?;
        agent_authority
            .install_g4_g5_runtime(policy_runtime)
            .map_err(|_| StableCode::KernelUnavailable)?;
        let ingress_security = KernelIngressSecurityConfigV2::new(
            startup.installation_id(),
            ingressd_identity,
            approvald_identity,
            keys.authority_envelope_signing_key,
            runtime_material.ui_settlement_key_id,
            runtime_material.ui_settlement_public_key,
            runtime_material.ingress_settlement_key_id,
            runtime_material.ingress_settlement_public_key,
        )
        .map_err(|_| StableCode::KernelUnavailable)?;
        let data_plane = ProductionKernelDataPlaneV2::new(
            input_runtime,
            vault,
            startup.installation_id(),
            ProducerIdentityV2::new(*ingressd_identity.as_bytes()),
            runtime_material.agentd_boot_id,
            agentd_identity,
            runtime_material.agentd_peer_identity_digest,
            runtime_material.policy_allowed_effects,
            runtime_material.logical_run_ttl_ms,
        )?;
        services.install_agent_security(agent_authority)?;
        services.install_ingress_security(
            KernelIngressAuthorityV2::new(ingress_security, 65_536)
                .map_err(|_| StableCode::KernelUnavailable)?,
            Box::new(data_plane),
        )?;
        services.install_parser_trust(runtime_material.parser_trust)?;
        services.verify_production_complete()?;
        let owner = KernelRuntimeOwnerV2::spawn(128, services)
            .map_err(|_| StableCode::KernelUnavailable)?;
        let envelope_key_id =
            derive_ed25519_key_id_v2(keys.envelope_signing_key.verifying_key().to_bytes());
        if envelope_key_id != startup.kernel_envelope_signing_key_id() {
            return Err(StableCode::KernelUnavailable);
        }
        let dispatcher = Arc::new(
            KernelServiceDispatcherV2::spawn(
                deployment,
                envelope_key_id,
                keys.envelope_signing_key,
                owner,
            )
            .map_err(|_| StableCode::KernelUnavailable)?,
        );
        let agent_handshake_edge = startup
            .kernel_service_handshake_edge(ClosedServiceEdgeIdV2::AgentKernel, boot_id)
            .map_err(|_| StableCode::KernelUnavailable)?;
        let ingress_handshake_edge = startup
            .kernel_service_handshake_edge(ClosedServiceEdgeIdV2::IngressKernel, boot_id)
            .map_err(|_| StableCode::KernelUnavailable)?;
        let agent_handshake = Arc::new(
            KernelV2HandshakeOwner::spawn(
                agent_handshake_edge,
                keys.agent_client_public_key,
                keys.agent_server_signing_key,
                128,
            )
            .map_err(|_| StableCode::KernelUnavailable)?,
        );
        let ingress_handshake = Arc::new(
            KernelV2HandshakeOwner::spawn(
                ingress_handshake_edge,
                keys.ingress_client_public_key,
                keys.ingress_server_signing_key,
                128,
            )
            .map_err(|_| StableCode::KernelUnavailable)?,
        );
        #[cfg(target_os = "linux")]
        let peer_verifier = Arc::new(LinuxNativeUnixPeerVerifierV2);
        #[cfg(target_os = "macos")]
        let peer_verifier = Arc::new(MacOsNativeUnixPeerVerifierV2);
        let agent = KerneldV2EndpointListener::new_agent(
            agent_listener,
            Arc::clone(&agent_edge),
            Arc::clone(&runtime),
            peer_verifier.clone(),
            agent_handshake,
            Arc::clone(&dispatcher),
        )
        .map_err(|_| StableCode::KernelUnavailable)?;
        let ingress = KerneldV2EndpointListener::new_ingress(
            ingress_listener,
            ingress_edge,
            Arc::clone(&runtime),
            peer_verifier,
            ingress_handshake,
            dispatcher,
        )
        .map_err(|_| StableCode::KernelUnavailable)?;
        run_kerneld_v2_workers(agent, ingress, runtime.as_ref(), readiness, lifecycle)
    }

    fn load_verified_startup(
        config_path: &Path,
    ) -> Result<
        (
            VerifiedDaemonStartupV2,
            KernelKeyMaterialV2,
            RuntimeMaterialV2,
        ),
        StableCode,
    > {
        if config_path != Path::new(NATIVE_BOOTSTRAP_PATH_V2) {
            return Err(StableCode::KernelUnavailable);
        }
        let bootstrap_bytes =
            read_regular_file(config_path, MAX_BOOTSTRAP_BYTES_V2, Some((0, 0, 0o444)))?;
        let bootstrap: BootstrapDtoV2 =
            serde_json::from_slice(&bootstrap_bytes).map_err(|_| StableCode::KernelUnavailable)?;
        if bootstrap.services.len() != MAX_SERVICE_COUNT_V2 {
            return Err(StableCode::KernelUnavailable);
        }
        let startup = load_native_deployment_startup(&bootstrap)?;
        startup
            .verify_loaded_service_config_v2(ClosedServiceIdV2::Kerneld, &bootstrap_bytes)
            .map_err(|_| StableCode::KernelUnavailable)?;
        let keys = load_key_material(&startup)?;
        let runtime = load_runtime_material(&bootstrap)?;
        Ok((startup, keys, runtime))
    }

    #[cfg(target_os = "linux")]
    fn load_native_deployment_startup(
        bootstrap: &BootstrapDtoV2,
    ) -> Result<VerifiedDaemonStartupV2, StableCode> {
        savana_policy_core::v2::load_verified_filesystem_startup_v2(
            Path::new(MANIFEST_ROOT_PATH_V2),
            &bootstrap.signed_manifest_path,
            &bootstrap.effect_ledger_projection_path,
            &bootstrap.services,
        )
        .map_err(|_| StableCode::KernelUnavailable)
    }

    #[cfg(all(target_os = "macos", feature = "macos-development-authority"))]
    fn load_native_deployment_startup(
        bootstrap: &BootstrapDtoV2,
    ) -> Result<VerifiedDaemonStartupV2, StableCode> {
        require_macos_development_bootstrap_paths(bootstrap)?;
        savana_policy_core::load_verified_macos_development_startup_v2(
            Path::new(MANIFEST_ROOT_PATH_V2),
            &bootstrap.signed_manifest_path,
            &bootstrap.effect_ledger_projection_path,
            &bootstrap.services,
        )
        .map_err(|_| StableCode::KernelUnavailable)
    }

    #[cfg(all(target_os = "macos", not(feature = "macos-development-authority")))]
    fn load_native_deployment_startup(
        _bootstrap: &BootstrapDtoV2,
    ) -> Result<VerifiedDaemonStartupV2, StableCode> {
        Err(StableCode::KernelUnavailable)
    }

    #[cfg(all(target_os = "macos", feature = "macos-development-authority"))]
    fn require_macos_development_bootstrap_paths(
        bootstrap: &BootstrapDtoV2,
    ) -> Result<(), StableCode> {
        let mut paths = vec![
            &bootstrap.signed_manifest_path,
            &bootstrap.effect_ledger_projection_path,
            &bootstrap.input_runtime_assets_path,
            &bootstrap.vault_state_path,
            &bootstrap.vault_rollback_anchor_path,
            &bootstrap.agent_authority_state_path,
            &bootstrap.agent_authority_rollback_anchor_path,
            &bootstrap.g4_state_path,
            &bootstrap.g4_rollback_anchor_path,
        ];
        paths.extend(bootstrap.policy_runtime.signed_tool_descriptor_paths.iter());
        if paths
            .into_iter()
            .all(|path| is_macos_development_path(path.as_path()))
        {
            Ok(())
        } else {
            Err(StableCode::KernelUnavailable)
        }
    }

    #[cfg(all(target_os = "macos", feature = "macos-development-authority"))]
    fn is_macos_development_path(path: &Path) -> bool {
        path.is_absolute()
            && path.starts_with(Path::new(DEVELOPMENT_ROOT_V2))
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
    ) -> Result<Vec<u8>, StableCode> {
        if !path.is_absolute() {
            return Err(StableCode::KernelUnavailable);
        }
        let before = fs::symlink_metadata(path).map_err(|_| StableCode::KernelUnavailable)?;
        if before.file_type().is_symlink()
            || !before.is_file()
            || before.nlink() != 1
            || usize::try_from(before.len()).map_or(true, |length| length > maximum)
        {
            return Err(StableCode::KernelUnavailable);
        }
        if let Some((uid, gid, mode)) = exact_identity {
            if before.uid() != uid || before.gid() != gid || before.mode() & 0o7777 != mode {
                return Err(StableCode::KernelUnavailable);
            }
        }
        let bytes = fs::read(path).map_err(|_| StableCode::KernelUnavailable)?;
        let after = fs::symlink_metadata(path).map_err(|_| StableCode::KernelUnavailable)?;
        if before.dev() != after.dev()
            || before.ino() != after.ino()
            || before.len() != after.len()
            || bytes.len() > maximum
        {
            return Err(StableCode::KernelUnavailable);
        }
        Ok(bytes)
    }

    fn load_key_material(
        startup: &VerifiedDaemonStartupV2,
    ) -> Result<KernelKeyMaterialV2, StableCode> {
        let agent_client_public_key =
            read_exact_key(Path::new(AGENT_CLIENT_PUBLIC_KEY_PATH_V2), 0o444)?;
        let ingress_client_public_key =
            read_exact_key(Path::new(INGRESS_CLIENT_PUBLIC_KEY_PATH_V2), 0o444)?;
        let executor_server_public_key =
            read_exact_key(Path::new(EXECUTOR_SERVER_PUBLIC_KEY_PATH_V2), 0o444)?;
        let agent_server_seed =
            Zeroizing::new(read_native_credential(AGENT_SERVER_SEED_CREDENTIAL_V2)?);
        let ingress_server_seed =
            Zeroizing::new(read_native_credential(INGRESS_SERVER_SEED_CREDENTIAL_V2)?);
        let envelope_seed =
            Zeroizing::new(read_native_credential(ENVELOPE_SIGNING_SEED_CREDENTIAL_V2)?);
        let authority_envelope_seed = Zeroizing::new(read_native_credential(
            AUTHORITY_ENVELOPE_SEED_CREDENTIAL_V2,
        )?);
        let task_correlation_seed =
            Zeroizing::new(read_native_credential(TASK_CORRELATION_SEED_CREDENTIAL_V2)?);
        let vault_encryption_key = read_native_credential(VAULT_ENCRYPTION_KEY_CREDENTIAL_V2)?;
        let vault_anchor_authentication_key =
            read_native_credential(VAULT_ANCHOR_AUTHENTICATION_KEY_CREDENTIAL_V2)?;
        let agent_state_encryption_key =
            read_native_credential(AGENT_STATE_ENCRYPTION_KEY_CREDENTIAL_V2)?;
        let agent_state_anchor_authentication_key =
            read_native_credential(AGENT_STATE_ANCHOR_AUTHENTICATION_KEY_CREDENTIAL_V2)?;
        let g4_state_encryption_key =
            read_native_credential(G4_STATE_ENCRYPTION_KEY_CREDENTIAL_V2)?;
        let g4_anchor_authentication_key =
            read_native_credential(G4_STATE_ANCHOR_AUTHENTICATION_KEY_CREDENTIAL_V2)?;
        let executor_client_seed =
            Zeroizing::new(read_native_credential(EXECUTOR_CLIENT_SEED_CREDENTIAL_V2)?);
        let agent_server_signing_key = SigningKey::from_bytes(&agent_server_seed);
        let ingress_server_signing_key = SigningKey::from_bytes(&ingress_server_seed);
        let envelope_signing_key = SigningKey::from_bytes(&envelope_seed);
        let authority_envelope_signing_key = SigningKey::from_bytes(&authority_envelope_seed);
        let task_correlation_signing_key = SigningKey::from_bytes(&task_correlation_seed);
        let executor_client_signing_key = SigningKey::from_bytes(&executor_client_seed);
        let agent = startup
            .edge_lock(ClosedServiceEdgeIdV2::AgentKernel)
            .ok_or(StableCode::KernelUnavailable)?;
        let ingress = startup
            .edge_lock(ClosedServiceEdgeIdV2::IngressKernel)
            .ok_or(StableCode::KernelUnavailable)?;
        let executor = startup
            .edge_lock(ClosedServiceEdgeIdV2::KernelExecutor)
            .ok_or(StableCode::KernelUnavailable)?;
        if derive_ed25519_key_id_v2(agent_client_public_key) != agent.client_handshake_key_id
            || derive_ed25519_key_id_v2(agent_server_signing_key.verifying_key().to_bytes())
                != agent.server_handshake_key_id
            || derive_ed25519_key_id_v2(ingress_client_public_key)
                != ingress.client_handshake_key_id
            || derive_ed25519_key_id_v2(ingress_server_signing_key.verifying_key().to_bytes())
                != ingress.server_handshake_key_id
            || derive_ed25519_key_id_v2(envelope_signing_key.verifying_key().to_bytes())
                != startup.kernel_envelope_signing_key_id()
            || derive_ed25519_key_id_v2(executor_client_signing_key.verifying_key().to_bytes())
                != executor.client_handshake_key_id
            || derive_ed25519_key_id_v2(executor_server_public_key)
                != executor.server_handshake_key_id
            || [
                vault_encryption_key,
                vault_anchor_authentication_key,
                agent_state_encryption_key,
                agent_state_anchor_authentication_key,
                g4_state_encryption_key,
                g4_anchor_authentication_key,
            ]
            .iter()
            .any(|key| *key == [0; 32])
        {
            return Err(StableCode::KernelUnavailable);
        }
        Ok(KernelKeyMaterialV2 {
            boot_id: read_native_credential(KERNELD_BOOT_ID_CREDENTIAL_V2)?,
            agent_client_public_key,
            ingress_client_public_key,
            agent_server_signing_key,
            ingress_server_signing_key,
            envelope_signing_key,
            authority_envelope_signing_key,
            task_correlation_signing_key,
            vault_encryption_key,
            vault_anchor_authentication_key,
            agent_state_encryption_key,
            agent_state_anchor_authentication_key,
            g4_state_encryption_key,
            g4_anchor_authentication_key,
            executor_client_signing_key,
            executor_server_public_key,
        })
    }

    fn load_runtime_material(bootstrap: &BootstrapDtoV2) -> Result<RuntimeMaterialV2, StableCode> {
        if !bootstrap.vault_state_path.is_absolute()
            || !bootstrap.vault_rollback_anchor_path.is_absolute()
            || !bootstrap.agent_authority_state_path.is_absolute()
            || !bootstrap.agent_authority_rollback_anchor_path.is_absolute()
            || !bootstrap.g4_state_path.is_absolute()
            || !bootstrap.g4_rollback_anchor_path.is_absolute()
            || bootstrap.logical_run_ttl_ms == 0
        {
            return Err(StableCode::KernelUnavailable);
        }
        let input_runtime_assets = read_regular_file(
            &bootstrap.input_runtime_assets_path,
            MAX_ARTIFACT_BYTES_V2,
            None,
        )?;
        let input_runtime_publisher_key_id =
            Ed25519KeyIdV2::new(decode_hex_32(&bootstrap.input_runtime_publisher_key_id)?);
        let input_runtime_publisher_public_key =
            decode_hex_32(&bootstrap.input_runtime_publisher_public_key)?;
        if derive_ed25519_key_id_v2(input_runtime_publisher_public_key)
            != input_runtime_publisher_key_id
        {
            return Err(StableCode::KernelUnavailable);
        }
        let ui_settlement_key_id =
            Ed25519KeyIdV2::new(decode_hex_32(&bootstrap.ui_settlement_key_id)?);
        let ui_settlement_public_key = decode_hex_32(&bootstrap.ui_settlement_public_key)?;
        let ingress_settlement_key_id =
            Ed25519KeyIdV2::new(decode_hex_32(&bootstrap.ingress_settlement_key_id)?);
        let ingress_settlement_public_key =
            decode_hex_32(&bootstrap.ingress_settlement_public_key)?;
        if derive_ed25519_key_id_v2(ui_settlement_public_key) != ui_settlement_key_id
            || derive_ed25519_key_id_v2(ingress_settlement_public_key) != ingress_settlement_key_id
        {
            return Err(StableCode::KernelUnavailable);
        }
        let parser = &bootstrap.parser_trust;
        let parser_public_key = decode_hex_32(&parser.descriptor_public_key)?;
        let parser_trust = KernelParserTrustV2::new(
            Ed25519KeyIdV2::new(decode_hex_32(&parser.descriptor_key_id)?),
            parser_public_key,
            Digest32V2::new(decode_hex_32(&parser.worker_artifact_digest)?),
            ImplementationIdV2::new(parser.implementation_id),
            VersionV2::new(
                parser.semantic_version[0],
                parser.semantic_version[1],
                parser.semantic_version[2],
            ),
            Digest32V2::new(decode_hex_32(&parser.parser_code_digest)?),
            parser
                .renderer_code_digest
                .as_deref()
                .map(decode_hex_32)
                .transpose()?
                .map(Digest32V2::new),
            parser
                .ocr_model_set_digest
                .as_deref()
                .map(decode_hex_32)
                .transpose()?
                .map(Digest32V2::new),
            VersionV2::new(
                parser.normalization_version[0],
                parser.normalization_version[1],
                parser.normalization_version[2],
            ),
            Digest32V2::new(decode_hex_32(&parser.output_limits_digest)?),
            ClosedExtensionClassV2::new(parser.extension_class),
            parser.maximum_pages,
            parser.maximum_output_bytes,
        )
        .map_err(|_| StableCode::KernelUnavailable)?;
        let policy = load_policy_runtime(&bootstrap.policy_runtime)?;
        Ok(RuntimeMaterialV2 {
            input_runtime_assets,
            input_runtime_publisher_key_id,
            input_runtime_publisher_public_key,
            ui_settlement_key_id,
            ui_settlement_public_key,
            ingress_settlement_key_id,
            ingress_settlement_public_key,
            agentd_boot_id: BootIdV2::new(decode_hex_32(&bootstrap.agentd_boot_id)?),
            approvald_boot_id: BootIdV2::new(decode_hex_32(&bootstrap.approvald_boot_id)?),
            machine_boot_id: BootIdV2::new(decode_hex_32(&bootstrap.machine_boot_id)?),
            agentd_peer_identity_digest: Digest32V2::new(decode_hex_32(
                &bootstrap.agentd_peer_identity_digest,
            )?),
            vault_state_path: bootstrap.vault_state_path.clone(),
            vault_rollback_anchor_path: bootstrap.vault_rollback_anchor_path.clone(),
            vault_store_id: Digest32V2::new(decode_hex_32(&bootstrap.vault_store_id)?),
            agent_authority_state_path: bootstrap.agent_authority_state_path.clone(),
            agent_authority_rollback_anchor_path: bootstrap
                .agent_authority_rollback_anchor_path
                .clone(),
            agent_authority_store_id: Digest32V2::new(decode_hex_32(
                &bootstrap.agent_authority_store_id,
            )?),
            g4_state_path: bootstrap.g4_state_path.clone(),
            g4_rollback_anchor_path: bootstrap.g4_rollback_anchor_path.clone(),
            g4_store_id: Digest32V2::new(decode_hex_32(&bootstrap.g4_store_id)?),
            policy_allowed_effects: savana_policy_core::v2::EffectSetV2::from_bits(
                bootstrap.policy_allowed_effect_bits,
            )
            .filter(|effects| *effects != savana_policy_core::v2::EffectSetV2::EMPTY)
            .ok_or(StableCode::KernelUnavailable)?,
            logical_run_ttl_ms: bootstrap.logical_run_ttl_ms,
            policy,
            parser_trust,
        })
    }

    fn load_policy_runtime(
        policy: &PolicyRuntimeDtoV2,
    ) -> Result<LoadedPolicyRuntimeV2, StableCode> {
        if policy.signed_tool_descriptor_paths.is_empty()
            || policy.signed_tool_descriptor_paths.len() > 4_096
            || policy.policy_activations.len() > 4_096
            || policy.manifest_constraints.len() > 4_096
            || policy.validator_builds.len() > 32
            || policy.role_id == 0
            || policy.quota_limit == 0
        {
            return Err(StableCode::KernelUnavailable);
        }
        let registry_version = VersionV2::new(
            policy.registry_version[0],
            policy.registry_version[1],
            policy.registry_version[2],
        );
        let publisher_key_id =
            Ed25519KeyIdV2::new(decode_hex_32(&policy.registry_publisher_key_id)?);
        let publisher_public_key = decode_hex_32(&policy.registry_publisher_public_key)?;
        if derive_ed25519_key_id_v2(publisher_public_key) != publisher_key_id {
            return Err(StableCode::KernelUnavailable);
        }
        let publisher = VerifiedRegistryPublisherV2::from_verified_manifest(
            publisher_key_id,
            publisher_public_key,
            UnixMillisV2::new(policy.registry_not_before),
            UnixMillisV2::new(policy.registry_expires_at),
        )
        .map_err(|_| StableCode::KernelUnavailable)?;
        let now = current_unix_millis()?;
        let mut descriptors = Vec::new();
        descriptors
            .try_reserve_exact(policy.signed_tool_descriptor_paths.len())
            .map_err(|_| StableCode::KernelUnavailable)?;
        for path in &policy.signed_tool_descriptor_paths {
            let bytes = read_regular_file(path, 8 * 1024 * 1024, None)?;
            descriptors.push(
                SignedToolDescriptorV2::from_canonical_bytes(&bytes)
                    .and_then(|descriptor| descriptor.verify(&publisher, registry_version, now))
                    .map_err(|_| StableCode::KernelUnavailable)?,
            );
        }
        let registry =
            VerifiedToolRegistryV2::from_verified_descriptors(registry_version, descriptors)
                .map_err(|_| StableCode::KernelUnavailable)?;
        let activations = policy
            .policy_activations
            .iter()
            .map(|entry| {
                Ok(VerifiedPolicyToolActivationV2::from_verified_policy(
                    Digest32V2::new(decode_hex_32(&entry.descriptor_digest)?),
                    entry.registry_ordinal,
                    Digest32V2::new(decode_hex_32(&entry.policy_activation_digest)?),
                ))
            })
            .collect::<Result<Vec<_>, StableCode>>()?;
        let policy_tools = VerifiedPolicyToolSetV2::from_verified_policy(activations)
            .map_err(|_| StableCode::KernelUnavailable)?;
        let constraints = policy
            .manifest_constraints
            .iter()
            .map(|entry| {
                VerifiedManifestToolConstraintV2::from_manifest(
                    Digest32V2::new(decode_hex_32(&entry.descriptor_digest)?),
                    entry.maximum_attempts,
                    entry.maximum_elapsed_ns,
                    load_validator_declarations(&entry.internal_validators)?,
                )
                .map_err(|_| StableCode::KernelUnavailable)
            })
            .collect::<Result<Vec<_>, StableCode>>()?;
        let constraints = VerifiedManifestToolConstraintSetV2::from_manifest(constraints)
            .map_err(|_| StableCode::KernelUnavailable)?;
        let active_tools = ActiveToolRegistryV2::intersect(&registry, &policy_tools, &constraints)
            .map_err(|_| StableCode::KernelUnavailable)?;
        if active_tools.is_empty() {
            return Err(StableCode::KernelUnavailable);
        }
        let validator_builds = policy
            .validator_builds
            .iter()
            .map(|build| {
                Ok(InternalValidatorBuildV2::new(
                    validator_kind(build.kind)?,
                    ImplementationIdV2::new(build.implementation_id),
                    VersionV2::new(
                        build.semantic_version[0],
                        build.semantic_version[1],
                        build.semantic_version[2],
                    ),
                    Digest32V2::new(decode_hex_32(&build.build_manifest_digest)?),
                ))
            })
            .collect::<Result<Vec<_>, StableCode>>()?;
        let validators = activate_internal_validator_registry(validator_builds)
            .map_err(|_| StableCode::KernelUnavailable)?;
        let role = RoleIdV2::new(policy.role_id);
        let ontology = OntologyExprV2::eq(
            OntologyOperandV2::context(ContextFieldV2::Role),
            OntologyOperandV2::literal(OntologyScalarV2::integer(i64::from(policy.role_id))),
        );
        let disposition = match policy.disposition.as_str() {
            "permit" => VerifiedPolicyDispositionV2::permit_from_verified_policy(),
            "require_approval" => {
                VerifiedPolicyDispositionV2::require_approval_from_verified_policy()
            }
            "deny" => VerifiedPolicyDispositionV2::deny_from_verified_policy(),
            _ => return Err(StableCode::KernelUnavailable),
        };
        let tool_settlement_key_id =
            Ed25519KeyIdV2::new(decode_hex_32(&policy.tool_settlement_key_id)?);
        let tool_settlement_public_key = decode_hex_32(&policy.tool_settlement_public_key)?;
        let executor_seal_key_id =
            HpkeX25519KeyIdV2::new(decode_hex_32(&policy.executor_seal_key_id)?);
        let executor_seal_public_key = decode_hex_32(&policy.executor_seal_public_key)?;
        let executor_receipt_key_id =
            Ed25519KeyIdV2::new(decode_hex_32(&policy.executor_receipt_key_id)?);
        let executor_receipt_public_key = decode_hex_32(&policy.executor_receipt_public_key)?;
        if derive_ed25519_key_id_v2(tool_settlement_public_key) != tool_settlement_key_id
            || hpke_x25519_key_id(executor_seal_public_key) != executor_seal_key_id
            || derive_ed25519_key_id_v2(executor_receipt_public_key) != executor_receipt_key_id
        {
            return Err(StableCode::KernelUnavailable);
        }
        Ok(LoadedPolicyRuntimeV2 {
            active_tools,
            validators,
            role,
            ontology,
            disposition,
            tool_settlement_key_id,
            tool_settlement_public_key,
            quota_limit: policy.quota_limit,
            quota_policy_digest: Digest32V2::new(decode_hex_32(&policy.quota_policy_digest)?),
            execd_boot_id: BootIdV2::new(decode_hex_32(&policy.execd_boot_id)?),
            executor_identity: ExecutorIdentityV2::new(decode_hex_32(&policy.executor_identity)?),
            executor_seal_key_id,
            executor_seal_public_key,
            executor_connector_registry_digest: Digest32V2::new(decode_hex_32(
                &policy.executor_connector_registry_digest,
            )?),
            executor_receipt_key_id,
            executor_receipt_public_key,
        })
    }

    fn load_validator_declarations(
        declarations: &[ValidatorDeclarationDtoV2],
    ) -> Result<Vec<InternalValidatorDeclarationV2>, StableCode> {
        if declarations.len() > 32 {
            return Err(StableCode::KernelUnavailable);
        }
        declarations
            .iter()
            .map(|declaration| {
                Ok(InternalValidatorDeclarationV2::new(
                    ImplementationIdV2::new(declaration.implementation_id),
                    VersionV2::new(
                        declaration.semantic_version[0],
                        declaration.semantic_version[1],
                        declaration.semantic_version[2],
                    ),
                    Digest32V2::new(decode_hex_32(&declaration.build_manifest_digest)?),
                ))
            })
            .collect()
    }

    fn validator_kind(tag: u16) -> Result<InternalValidatorImplementationKindV2, StableCode> {
        match tag {
            1 => Ok(InternalValidatorImplementationKindV2::ArgumentBindingIntegrity),
            2 => Ok(InternalValidatorImplementationKindV2::LabelEffectConfinement),
            3 => Ok(InternalValidatorImplementationKindV2::RootEvidencePresence),
            4 => Ok(InternalValidatorImplementationKindV2::ProjectionBindingIntegrity),
            5 => Ok(InternalValidatorImplementationKindV2::TokenExecutorBinding),
            6 => Ok(InternalValidatorImplementationKindV2::IntentFlowConfinement),
            _ => Err(StableCode::KernelUnavailable),
        }
    }

    fn read_native_credential(name: &str) -> Result<[u8; 32], StableCode> {
        if name.is_empty()
            || name.contains('/')
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
        {
            return Err(StableCode::KernelUnavailable);
        }
        let directory = Path::new(NATIVE_CREDENTIAL_DIRECTORY_V2);
        let directory_metadata =
            fs::symlink_metadata(directory).map_err(|_| StableCode::KernelUnavailable)?;
        #[cfg(target_os = "linux")]
        let valid_directory_identity = directory_metadata.uid() == 0;
        #[cfg(target_os = "macos")]
        let valid_directory_identity = directory_metadata.uid() == 0
            && directory_metadata.gid() == nix::unistd::getegid().as_raw()
            && directory_metadata.mode() & 0o7777 == 0o750;
        if directory_metadata.file_type().is_symlink()
            || !directory_metadata.is_dir()
            || !valid_directory_identity
            || directory_metadata.mode() & 0o022 != 0
        {
            return Err(StableCode::KernelUnavailable);
        }
        #[cfg(target_os = "linux")]
        let identity = (0, 0, 0o400);
        #[cfg(target_os = "macos")]
        let identity = (0, nix::unistd::getegid().as_raw(), 0o440);
        read_regular_file(&directory.join(name), 32, Some(identity))?
            .try_into()
            .map_err(|_| StableCode::KernelUnavailable)
    }

    fn read_exact_key(path: &Path, mode: u32) -> Result<[u8; 32], StableCode> {
        let metadata = fs::symlink_metadata(path).map_err(|_| StableCode::KernelUnavailable)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.mode() & 0o7777 != mode
        {
            return Err(StableCode::KernelUnavailable);
        }
        let bytes = read_regular_file(path, 32, None)?;
        bytes.try_into().map_err(|_| StableCode::KernelUnavailable)
    }

    struct PosixAuthenticatedAnchorFileV2 {
        path: PathBuf,
        installation_id: Digest32V2,
        store_id: Digest32V2,
        authentication_key: Zeroizing<[u8; 32]>,
        mac_domain: &'static [u8],
        magic: [u8; 8],
    }

    impl PosixAuthenticatedAnchorFileV2 {
        fn new(
            path: PathBuf,
            installation_id: Digest32V2,
            store_id: Digest32V2,
            authentication_key: [u8; 32],
            mac_domain: &'static [u8],
            magic: [u8; 8],
        ) -> Result<Self, StableCode> {
            if !path.is_absolute()
                || installation_id.as_bytes().iter().all(|byte| *byte == 0)
                || store_id.as_bytes().iter().all(|byte| *byte == 0)
                || authentication_key.iter().all(|byte| *byte == 0)
                || mac_domain.is_empty()
                || magic == [0; 8]
            {
                return Err(StableCode::KernelUnavailable);
            }
            Ok(Self {
                path,
                installation_id,
                store_id,
                authentication_key: Zeroizing::new(authentication_key),
                mac_domain,
                magic,
            })
        }

        fn read_raw_head(&self) -> Result<(u64, Digest32V2), ()> {
            let metadata = match fs::symlink_metadata(&self.path) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Ok((0, Digest32V2::new([0; 32])));
                }
                Err(_) => return Err(()),
            };
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || metadata.nlink() != 1
                || metadata.mode() & 0o7777 != 0o600
                || usize::try_from(metadata.len()).ok() != Some(AUTHENTICATED_ANCHOR_BYTES_V2)
            {
                return Err(());
            }
            let bytes = fs::read(&self.path).map_err(|_| ())?;
            if bytes.len() != AUTHENTICATED_ANCHOR_BYTES_V2
                || bytes.get(..8) != Some(self.magic.as_slice())
            {
                return Err(());
            }
            let sequence = u64::from_be_bytes(bytes[8..16].try_into().map_err(|_| ())?);
            let digest = Digest32V2::new(bytes[16..48].try_into().map_err(|_| ())?);
            self.verify_anchor_mac(sequence, digest, &bytes[48..80])?;
            if (sequence == 0) != (digest == Digest32V2::new([0; 32])) {
                return Err(());
            }
            Ok((sequence, digest))
        }

        fn anchor_mac(&self, sequence: u64, digest: Digest32V2) -> Result<[u8; 32], ()> {
            let mut mac =
                Hmac::<Sha256>::new_from_slice(self.authentication_key.as_ref()).map_err(|_| ())?;
            mac.update(self.mac_domain);
            mac.update(self.installation_id.as_bytes());
            mac.update(self.store_id.as_bytes());
            mac.update(&sequence.to_be_bytes());
            mac.update(digest.as_bytes());
            Ok(mac.finalize().into_bytes().into())
        }

        fn verify_anchor_mac(
            &self,
            sequence: u64,
            digest: Digest32V2,
            candidate: &[u8],
        ) -> Result<(), ()> {
            let mut mac =
                Hmac::<Sha256>::new_from_slice(self.authentication_key.as_ref()).map_err(|_| ())?;
            mac.update(self.mac_domain);
            mac.update(self.installation_id.as_bytes());
            mac.update(self.store_id.as_bytes());
            mac.update(&sequence.to_be_bytes());
            mac.update(digest.as_bytes());
            mac.verify_slice(candidate).map_err(|_| ())
        }

        fn write_raw_head(&self, sequence: u64, digest: Digest32V2) -> Result<(), ()> {
            if (sequence == 0) != (digest == Digest32V2::new([0; 32])) {
                return Err(());
            }
            let mut bytes = Vec::with_capacity(AUTHENTICATED_ANCHOR_BYTES_V2);
            bytes.extend_from_slice(&self.magic);
            bytes.extend_from_slice(&sequence.to_be_bytes());
            bytes.extend_from_slice(digest.as_bytes());
            bytes.extend_from_slice(&self.anchor_mac(sequence, digest)?);
            let parent = self.path.parent().ok_or(())?;
            let parent_metadata = fs::symlink_metadata(parent).map_err(|_| ())?;
            if parent_metadata.file_type().is_symlink()
                || !parent_metadata.is_dir()
                || parent_metadata.mode() & 0o022 != 0
            {
                return Err(());
            }
            let mut entropy = [0_u8; 8];
            getrandom::getrandom(&mut entropy).map_err(|_| ())?;
            let file_name = self.path.file_name().ok_or(())?.to_string_lossy();
            let temporary = parent.join(format!(
                ".{file_name}.tmp.{}.{:016x}",
                std::process::id(),
                u64::from_be_bytes(entropy)
            ));
            let result = (|| {
                let mut file = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&temporary)
                    .map_err(|_| ())?;
                file.write_all(&bytes)
                    .and_then(|_| file.sync_all())
                    .map_err(|_| ())?;
                fs::rename(&temporary, &self.path).map_err(|_| ())?;
                fs::File::open(parent)
                    .and_then(|directory| directory.sync_all())
                    .map_err(|_| ())
            })();
            if result.is_err() {
                let _ = fs::remove_file(&temporary);
            }
            result
        }
    }

    impl savana_vault::VaultRollbackAnchorV2 for PosixAuthenticatedAnchorFileV2 {
        fn current_head(
            &self,
        ) -> Result<savana_vault::VaultStateHeadV2, savana_vault::VaultErrorV2> {
            let (sequence, digest) = self
                .read_raw_head()
                .map_err(|_| savana_vault::VaultErrorV2::DurableAuthentication)?;
            savana_vault::VaultStateHeadV2::new(sequence, digest)
        }

        fn compare_and_advance(
            &mut self,
            expected: savana_vault::VaultStateHeadV2,
            next: savana_vault::VaultStateHeadV2,
        ) -> Result<(), savana_vault::VaultErrorV2> {
            if self
                .read_raw_head()
                .map_err(|_| savana_vault::VaultErrorV2::DurableAuthentication)?
                != (expected.sequence(), expected.state_digest())
                || next.sequence()
                    != expected
                        .sequence()
                        .checked_add(1)
                        .ok_or(savana_vault::VaultErrorV2::RollbackDetected)?
            {
                return Err(savana_vault::VaultErrorV2::RollbackDetected);
            }
            self.write_raw_head(next.sequence(), next.state_digest())
                .map_err(|_| savana_vault::VaultErrorV2::CommitUncertain)?;
            if self
                .read_raw_head()
                .map_err(|_| savana_vault::VaultErrorV2::CommitUncertain)?
                != (next.sequence(), next.state_digest())
            {
                return Err(savana_vault::VaultErrorV2::CommitUncertain);
            }
            Ok(())
        }
    }

    impl crate::v2_agent_durable::KernelAgentAuthorityRollbackAnchorV2
        for PosixAuthenticatedAnchorFileV2
    {
        fn current_head(
            &self,
        ) -> Result<crate::v2_agent_durable::KernelAgentAuthorityStateHeadV2, ()> {
            let (sequence, digest) = self.read_raw_head()?;
            crate::v2_agent_durable::KernelAgentAuthorityStateHeadV2::new(sequence, digest)
        }

        fn compare_and_advance(
            &mut self,
            expected: crate::v2_agent_durable::KernelAgentAuthorityStateHeadV2,
            next: crate::v2_agent_durable::KernelAgentAuthorityStateHeadV2,
        ) -> Result<(), ()> {
            if self.read_raw_head()? != (expected.sequence(), expected.digest())
                || next.sequence() != expected.sequence().checked_add(1).ok_or(())?
            {
                return Err(());
            }
            self.write_raw_head(next.sequence(), next.digest())?;
            if self.read_raw_head()? != (next.sequence(), next.digest()) {
                return Err(());
            }
            Ok(())
        }
    }

    impl savana_policy_core::v2::RollbackProtectedStateAnchorV2 for PosixAuthenticatedAnchorFileV2 {
        fn current_head(
            &self,
        ) -> Result<
            savana_policy_core::v2::RollbackProtectedStateHeadV2,
            savana_policy_core::v2::G4Error,
        > {
            let (sequence, digest) = self
                .read_raw_head()
                .map_err(|_| savana_policy_core::v2::G4Error::DurableStateAuthentication)?;
            savana_policy_core::v2::RollbackProtectedStateHeadV2::new(sequence, digest)
        }

        fn compare_and_advance(
            &mut self,
            expected: savana_policy_core::v2::RollbackProtectedStateHeadV2,
            next: savana_policy_core::v2::RollbackProtectedStateHeadV2,
        ) -> Result<(), savana_policy_core::v2::G4Error> {
            if self
                .read_raw_head()
                .map_err(|_| savana_policy_core::v2::G4Error::DurableStateAuthentication)?
                != (expected.sequence(), expected.state_digest())
                || next.sequence()
                    != expected
                        .sequence()
                        .checked_add(1)
                        .ok_or(savana_policy_core::v2::G4Error::DurableStateRollback)?
            {
                return Err(savana_policy_core::v2::G4Error::DurableStateRollback);
            }
            self.write_raw_head(next.sequence(), next.state_digest())
                .map_err(|_| savana_policy_core::v2::G4Error::DurableCommitUncertain)?;
            if self
                .read_raw_head()
                .map_err(|_| savana_policy_core::v2::G4Error::DurableCommitUncertain)?
                != (next.sequence(), next.state_digest())
            {
                return Err(savana_policy_core::v2::G4Error::DurableCommitUncertain);
            }
            Ok(())
        }
    }

    fn current_unix_millis() -> Result<UnixMillisV2, StableCode> {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| StableCode::KernelUnavailable)?;
        let milliseconds =
            u64::try_from(duration.as_millis()).map_err(|_| StableCode::KernelUnavailable)?;
        if milliseconds == 0 {
            return Err(StableCode::KernelUnavailable);
        }
        Ok(UnixMillisV2::new(milliseconds))
    }

    #[cfg(target_os = "linux")]
    fn current_native_self_peer_binding() -> Result<PeerIdentityBindingV2, StableCode> {
        let (left, right) =
            std::os::unix::net::UnixStream::pair().map_err(|_| StableCode::KernelUnavailable)?;
        let pinned = savana_platform_identity::measure_linux_peer_v2(&left)
            .map_err(|_| StableCode::KernelUnavailable)?;
        drop(right);
        match pinned.measurement() {
            savana_platform_identity::NativePeerMeasurementV2::Linux {
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
            .map_err(|_| StableCode::KernelUnavailable),
            _ => Err(StableCode::KernelUnavailable),
        }
    }

    #[cfg(target_os = "macos")]
    fn current_native_self_peer_binding() -> Result<PeerIdentityBindingV2, StableCode> {
        let audit_token = savana_platform_identity::current_process_audit_token_v2()
            .map_err(|_| StableCode::KernelUnavailable)?;
        let measurement = savana_platform_identity::measure_macos_peer_v2(audit_token)
            .map_err(|_| StableCode::KernelUnavailable)?;
        match measurement {
            savana_platform_identity::NativePeerMeasurementV2::MacOs {
                audit_token,
                euid,
                egid,
                bundle_id,
                team_id,
                code_directory_measurement,
                ..
            } => PeerIdentityBindingV2::macos(
                audit_token,
                euid,
                egid,
                bundle_id.as_str().to_owned(),
                team_id.as_str().to_owned(),
                Digest32V2::new(code_directory_measurement),
            )
            .map_err(|_| StableCode::KernelUnavailable),
            _ => Err(StableCode::KernelUnavailable),
        }
    }

    fn decode_hex_32(value: &str) -> Result<[u8; 32], StableCode> {
        if value.len() != 64 {
            return Err(StableCode::KernelUnavailable);
        }
        let mut output = [0_u8; 32];
        for (index, slot) in output.iter_mut().enumerate() {
            let offset = index * 2;
            *slot = u8::from_str_radix(&value[offset..offset + 2], 16)
                .map_err(|_| StableCode::KernelUnavailable)?;
        }
        if output.iter().all(|byte| *byte == 0) {
            return Err(StableCode::KernelUnavailable);
        }
        Ok(output)
    }

    fn hpke_x25519_key_id(public_key: [u8; 32]) -> HpkeX25519KeyIdV2 {
        let mut hasher = Sha256::new();
        hasher.update(b"SAVANA_HPKE_X25519_KEY_ID_V2\0");
        hasher.update(public_key);
        HpkeX25519KeyIdV2::new(hasher.finalize().into())
    }
}
