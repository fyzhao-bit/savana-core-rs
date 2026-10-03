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

#[cfg(feature = "test-support")]
pub(crate) fn probe_declassification_rollover(
    scenario: crate::test_support::V2DeclassificationRolloverScenario,
) -> crate::test_support::V2DeclassificationRolloverProbe {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        native::probe_declassification_rollover(scenario)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = scenario;
        unreachable!("V2 test support requires a native Unix target")
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod native {
    use std::fs;
    #[cfg(any(target_os = "macos", test, feature = "linux-file-backed-integration"))]
    use std::io::Write as _;
    use std::os::unix::fs::DirBuilderExt as _;
    use std::os::unix::fs::MetadataExt as _;
    #[cfg(any(target_os = "macos", test, feature = "linux-file-backed-integration"))]
    use std::os::unix::fs::OpenOptionsExt as _;
    #[cfg(feature = "test-support")]
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::{Path, PathBuf};
    #[cfg(feature = "test-support")]
    use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
    use std::sync::Arc;
    #[cfg(feature = "test-support")]
    use std::sync::Mutex;
    #[cfg(feature = "test-support")]
    use std::thread;
    #[cfg(feature = "test-support")]
    use std::time::{Duration, Instant};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[cfg(feature = "test-support")]
    use ed25519_dalek::Signer as _;
    use ed25519_dalek::SigningKey;
    use hmac::{Hmac, Mac as _};
    use savana_kernel_protocol::v2::{
        derive_ed25519_key_id_v2, BootIdV2, ClosedExtensionClassV2, Digest32V2, Ed25519KeyIdV2,
        ExecutorIdentityV2, HpkeX25519KeyIdV2, ImplementationIdV2, PeerIdentityBindingV2,
        ProducerIdentityV2, RoleIdV2, UnixMillisV2, VersionV2,
    };
    #[cfg(feature = "test-support")]
    use savana_kernel_protocol::v2::{
        encode_kernel_agent_health_response_v2, encode_kernel_ingress_health_response_v2,
        encode_prepare_new_ingress_response_v2, DurableTaskIdV2, EndpointRoleV2,
        KernelAgentHealthResponseV2, KernelAgentOperationV2,
        KernelIngressBootstrapTransferCapabilityV2, KernelIngressHealthResponseV2,
        KernelIngressOperationV2, KernelServiceOperationV2, NewTaskPreparationHandleV2,
        PrepareNewIngressResponseV2, PublicServiceStateV2, RequestIdV2,
        SignedDurableTaskCorrelationV2, UnsignedDurableTaskCorrelationV2,
    };
    use savana_kernel_protocol::StableCode;
    use savana_policy_core::v2::{
        activate_internal_validator_registry, ActiveToolRegistryV2, BoundedConnectorHostV2,
        ConnectorDescriptorV2, ConnectorRegistryStateV2, ContextFieldV2,
        DurableConnectorRegistryStoreV2, DurableG4StateV2, DurableStateNamespaceV2,
        FilesystemServiceObservationConfigV2, InstallerOrMdmVerifierV2, InternalValidatorBuildV2,
        InternalValidatorDeclarationV2, InternalValidatorImplementationKindV2, OntologyExprV2,
        OntologyOperandV2, OntologyScalarV2, OperationalTrustRootSetV2,
        SharedVerifiedConnectorRegistryV2, SignedToolDescriptorV2,
        VerifiedInternalValidatorRegistryV2, VerifiedManifestToolConstraintSetV2,
        VerifiedManifestToolConstraintV2, VerifiedPolicyDispositionV2,
        VerifiedPolicyToolActivationV2, VerifiedPolicyToolSetV2, VerifiedRegistryPublisherV2,
        VerifiedToolRegistryV2,
    };
    #[cfg(feature = "test-support")]
    use savana_policy_core::Clock;
    use serde::Deserialize;
    use sha2::{Digest as _, Sha256};
    use zeroize::Zeroizing;

    #[cfg(feature = "test-support")]
    use savana_agentd::{
        AgentControlKernelClientV2, AgentTaskServiceV2, AuthenticatedJarvisControlV2,
        SuiteOneAgentKernelClientV2,
    };
    #[cfg(feature = "test-support")]
    use savana_ingressd::SuiteOneIngressKernelClientV2;

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
    use crate::v2_connector_authority::KernelConnectorAuthorityV2;
    use crate::v2_core_services::CoreKernelRuntimeServicesV2;
    use crate::v2_data_plane::ProductionKernelDataPlaneV2;
    use crate::v2_declassification_policy::{
        V2LiveEndpointRuntimeV2, VerifiedV2DeclassificationSuccessorV2,
    };
    #[cfg(feature = "test-support")]
    use crate::v2_dispatch::KernelServiceResponseBodyV2;
    use crate::v2_edge::VerifiedServiceEdgeV2;
    use crate::v2_executor_client::SuiteOneKernelExecutorClientV2;
    use crate::v2_ingress_authority::{KernelIngressAuthorityV2, KernelIngressSecurityConfigV2};
    use crate::v2_input_owner::KernelParserTrustV2;
    use crate::v2_kernel_owner::KernelRuntimeOwnerV2;
    use crate::v2_listener::KerneldV2EndpointListener;
    #[cfg(target_os = "linux")]
    use crate::v2_listener::LinuxNativeUnixPeerVerifierV2;
    #[cfg(any(target_os = "macos", feature = "test-support"))]
    use crate::v2_listener::NativeUnixPeerVerifierV2;
    use crate::v2_server::{run_kerneld_v2_workers, V2VerifiedSuccessorPublisher};
    #[cfg(feature = "test-support")]
    use savana_platform_identity::NativePeerMeasurementV2;

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
    const TASK_AUTHORIZATION_SEED_CREDENTIAL_V2: &str = "task-authorization-v2.seed";
    const MANAGED_RESOURCE_SEED_CREDENTIAL_V04: &str = "managed-resource-v04.seed";
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
    const KERNEL_APPROVAL_SEED_CREDENTIAL_V04: &str = "kernel-approval-v04.seed";
    const CONNECTOR_AUTHORITY_SEED_CREDENTIAL_V2: &str = "connector-authority-v2.seed";
    const MAX_BOOTSTRAP_BYTES_V2: usize = 128 * 1024;
    const MAX_ARTIFACT_BYTES_V2: usize = 256 * 1024 * 1024;
    const MAX_DECLASSIFICATION_OBJECT_BYTES_V2: usize = 1024 * 1024;
    const MAX_SERVICE_COUNT_V2: usize = 5;
    #[cfg(any(target_os = "macos", feature = "linux-file-backed-integration"))]
    const VAULT_ANCHOR_MAC_DOMAIN_V2: &[u8] = b"SAVANA_VAULT_ANCHOR_MAC_V2\0";
    #[cfg(any(target_os = "macos", feature = "linux-file-backed-integration"))]
    const AGENT_ANCHOR_MAC_DOMAIN_V2: &[u8] = b"SAVANA_AGENT_AUTHORITY_ANCHOR_MAC_V2\0";
    #[cfg(any(target_os = "macos", feature = "linux-file-backed-integration"))]
    const G4_ANCHOR_MAC_DOMAIN_V2: &[u8] = b"SAVANA_G4_ANCHOR_MAC_V2\0";
    #[cfg(any(target_os = "macos", test, feature = "linux-file-backed-integration"))]
    const CONNECTOR_ANCHOR_MAC_DOMAIN_V2: &[u8] = b"SAVANA_CONNECTOR_REGISTRY_ANCHOR_MAC_V2\0";
    const CONNECTOR_STORE_ID_DOMAIN_V2: &[u8] = b"SAVANA_CONNECTOR_REGISTRY_STORE_ID_V2\0";
    const CONNECTOR_STORE_ENCRYPTION_DERIVATION_DOMAIN_V2: &[u8] =
        b"SAVANA_CONNECTOR_REGISTRY_STORE_ENCRYPTION_DERIVATION_V2\0";
    const CONNECTOR_STORE_ANCHOR_DERIVATION_DOMAIN_V2: &[u8] =
        b"SAVANA_CONNECTOR_REGISTRY_STORE_ANCHOR_DERIVATION_V2\0";
    const CONNECTOR_HANDLE_DERIVATION_DOMAIN_V2: &[u8] =
        b"SAVANA_CONNECTOR_REGISTRY_HANDLE_DERIVATION_V2\0";
    const CONNECTOR_DISABLED_HANDLE_DERIVATION_DOMAIN_V2: &[u8] =
        b"SAVANA_DISABLED_CONNECTOR_HANDLE_DERIVATION_V2\0";
    #[cfg(any(target_os = "macos", feature = "linux-file-backed-integration"))]
    const VAULT_ANCHOR_MAGIC_V2: [u8; 8] = *b"SV2ANCH\0";
    #[cfg(any(target_os = "macos", feature = "linux-file-backed-integration"))]
    const AGENT_ANCHOR_MAGIC_V2: [u8; 8] = *b"SA2ANCH\0";
    #[cfg(any(target_os = "macos", feature = "linux-file-backed-integration"))]
    const G4_ANCHOR_MAGIC_V2: [u8; 8] = *b"SG2ANCH\0";
    #[cfg(any(target_os = "macos", test, feature = "linux-file-backed-integration"))]
    const CONNECTOR_ANCHOR_MAGIC_V2: [u8; 8] = *b"SC2ANCH\0";
    #[cfg(any(target_os = "macos", test, feature = "linux-file-backed-integration"))]
    const AUTHENTICATED_ANCHOR_BYTES_V2: usize = 80;

    #[derive(Deserialize)]
    #[cfg_attr(
        all(target_os = "macos", not(feature = "macos-development-authority")),
        allow(dead_code)
    )]
    #[serde(deny_unknown_fields)]
    struct BootstrapDtoV2 {
        #[serde(default)]
        fused_model_workers: Vec<crate::v04_model_workers::WorkerConfigV04>,
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
        declassification_installer_root_path: PathBuf,
        declassification_trust_root_set_path: PathBuf,
        declassification_rule_set_path: PathBuf,
        input_runtime_assets_path: PathBuf,
        input_runtime_publisher_key_id: String,
        input_runtime_publisher_public_key: String,
        ui_settlement_key_id: String,
        ui_settlement_public_key: String,
        ingress_settlement_key_id: String,
        ingress_settlement_public_key: String,
        task_authorization_key_id: String,
        task_authorization_public_key: String,
        #[serde(default)]
        managed_resource_issuer: Option<ManagedResourceIssuerDtoV04>,
        #[serde(default)]
        managed_admin: Option<ManagedResourceIssuerDtoV04>,
        #[serde(default)]
        kernel_approval: Option<KernelApprovalDtoV04>,
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
    struct DeclassificationInstallerRootDtoV2 {
        key_id: String,
        key_epoch: u64,
        public_key: String,
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
        connector_registry_genesis_digest: String,
        connector_authority_key_id: String,
        connector_authority_public_key: String,
        user_tier_host_allowlist: Vec<String>,
        executor_receipt_key_id: String,
        executor_receipt_public_key: String,
        /// Canonical deployment-shipped connector descriptors (lowercase hex),
        /// authenticated by this measured configuration and bound to the
        /// connector genesis digest. Absent means the empty legacy set.
        #[serde(default)]
        deployment_shipped_connectors: Vec<String>,
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

    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ManagedResourceIssuerDtoV04 {
        key_id: String,
        public_key: String,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct KernelApprovalDtoV04 {
        client_key_id: String,
        server_key_id: String,
        server_public_key_path: PathBuf,
    }

    struct KernelApprovalMaterialV04 {
        edge: savana_kernel_protocol::v2::KernelServiceHandshakeEdgeV2,
        signing_key: SigningKey,
        server_public_key: [u8; 32],
    }

    struct KernelKeyMaterialV2 {
        #[cfg(all(target_os = "linux", not(feature = "linux-file-backed-integration")))]
        tpm_enrollment: savana_platform_identity::TpmEnrollmentV3,
        kernel_approval: Option<KernelApprovalMaterialV04>,
        boot_id: [u8; 32],
        agent_client_public_key: [u8; 32],
        ingress_client_public_key: [u8; 32],
        agent_server_signing_key: SigningKey,
        ingress_server_signing_key: SigningKey,
        envelope_signing_key: SigningKey,
        authority_envelope_signing_key: SigningKey,
        task_correlation_signing_key: SigningKey,
        task_authorization_signing_key: SigningKey,
        vault_encryption_key: [u8; 32],
        vault_anchor_authentication_key: [u8; 32],
        agent_state_encryption_key: [u8; 32],
        agent_state_anchor_authentication_key: [u8; 32],
        g4_state_encryption_key: [u8; 32],
        g4_anchor_authentication_key: [u8; 32],
        executor_client_signing_key: SigningKey,
        executor_server_public_key: [u8; 32],
        connector_authority_signing_key: Option<SigningKey>,
    }

    struct RuntimeMaterialV2 {
        fused_model_workers: crate::v04_model_workers::LoadedWorkersV04,
        input_runtime_assets: Vec<u8>,
        input_runtime_publisher_key_id: Ed25519KeyIdV2,
        input_runtime_publisher_public_key: [u8; 32],
        ui_settlement_key_id: Ed25519KeyIdV2,
        ui_settlement_public_key: [u8; 32],
        ingress_settlement_key_id: Ed25519KeyIdV2,
        ingress_settlement_public_key: [u8; 32],
        task_authorization_key_id: Ed25519KeyIdV2,
        task_authorization_public_key: [u8; 32],
        managed_resource_issuer: Option<(Ed25519KeyIdV2, [u8; 32])>,
        managed_admin: Option<(Ed25519KeyIdV2, [u8; 32])>,
        agentd_boot_id: BootIdV2,
        approvald_boot_id: BootIdV2,
        machine_boot_id: BootIdV2,
        agentd_peer_identity_digest: Digest32V2,
        vault_state_path: PathBuf,
        #[cfg(any(target_os = "macos", feature = "linux-file-backed-integration"))]
        vault_rollback_anchor_path: PathBuf,
        vault_store_id: Digest32V2,
        agent_authority_state_path: PathBuf,
        #[cfg(any(target_os = "macos", feature = "linux-file-backed-integration"))]
        agent_authority_rollback_anchor_path: PathBuf,
        agent_authority_store_id: Digest32V2,
        g4_state_path: PathBuf,
        #[cfg(any(target_os = "macos", feature = "linux-file-backed-integration"))]
        g4_rollback_anchor_path: PathBuf,
        g4_store_id: Digest32V2,
        policy_allowed_effects: savana_policy_core::v2::EffectSetV2,
        logical_run_ttl_ms: u64,
        connector_authority_distinct_public_keys: Vec<[u8; 32]>,
        declassification: DeclassificationMaterialV2,
        policy: LoadedPolicyRuntimeV2,
        parser_trust: KernelParserTrustV2,
    }

    struct DeclassificationMaterialV2 {
        canonical_rule_set: Vec<u8>,
        trust_roots: Arc<OperationalTrustRootSetV2>,
        installer_verifier: InstallerOrMdmVerifierV2,
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
        connector_registry_genesis_digest: Digest32V2,
        connector_authority_key_id: Ed25519KeyIdV2,
        connector_authority_public_key: [u8; 32],
        user_tier_host_allowlist: Vec<BoundedConnectorHostV2>,
        executor_receipt_key_id: Ed25519KeyIdV2,
        executor_receipt_public_key: [u8; 32],
        deployment_shipped_connectors: Vec<ConnectorDescriptorV2>,
    }

    struct ProductionV2SuccessorPublisher {
        fused_worker_fingerprint: [u8; 32],
        config_path: PathBuf,
        kernel_boot_id: BootIdV2,
        coordinator: Arc<crate::policy_runtime::PolicyRolloverCoordinator>,
        owner: Arc<KernelRuntimeOwnerV2>,
    }

    impl V2VerifiedSuccessorPublisher for ProductionV2SuccessorPublisher {
        fn tick_private_workflows(&self) -> Result<(), StableCode> {
            use crate::v2_kernel_owner::KernelRuntimeOwnerErrorV2 as E;
            match self
                .owner
                .tick_fused_planning(std::time::Instant::now() + std::time::Duration::from_secs(6))
            {
                Ok(())
                | Err(E::Busy | E::DeadlineExceeded | E::Operation(StableCode::PolicyDenied)) => {
                    Ok(())
                }
                Err(_) => Err(StableCode::KernelUnavailable),
            }
        }
        fn publish_next_verified_successor(&self) -> Result<(), StableCode> {
            let (startup, keys, runtime_material) = load_verified_startup(&self.config_path)?;
            // Transport credentials/endpoints are cold-start configuration.
            // Never publish a new config while silently retaining old workers.
            if runtime_material.fused_model_workers.fingerprint != self.fused_worker_fingerprint {
                return Err(StableCode::KernelUnavailable);
            }
            if BootIdV2::new(keys.boot_id) != self.kernel_boot_id {
                return Err(StableCode::KernelUnavailable);
            }
            let live_endpoints = Arc::new(
                V2LiveEndpointRuntimeV2::from_verified_deployment(
                    &startup,
                    self.kernel_boot_id,
                    keys.agent_client_public_key,
                    keys.agent_server_signing_key,
                    keys.ingress_client_public_key,
                    keys.ingress_server_signing_key,
                    keys.envelope_signing_key,
                    Arc::clone(&self.owner),
                )
                .map_err(|_| StableCode::KernelUnavailable)?,
            );
            let declassification = runtime_material.declassification;
            let successor = VerifiedV2DeclassificationSuccessorV2::from_verified_deployment(
                &startup,
                declassification.canonical_rule_set,
                declassification.trust_roots,
                current_unix_millis()?.get(),
                live_endpoints,
            )
            .map_err(|_| StableCode::KernelUnavailable)?;
            self.coordinator
                .publish_v2_declassification_successor(successor)
        }
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
        managed_admin: bool,
    ) -> Result<
        (
            crate::v2_activation::VerifiedInheritedKerneldListenersV2,
            Option<std::os::unix::net::UnixListener>,
        ),
        crate::deployment_trust::DeploymentTrustErrorV2,
    > {
        take_kerneld_systemd_listeners_v2(
            agent_listener_identity,
            ingress_listener_identity,
            managed_admin,
        )
    }

    #[cfg(target_os = "macos")]
    fn take_kerneld_native_listeners_v2(
        agent_listener_identity: Digest32V2,
        ingress_listener_identity: Digest32V2,
        managed_admin: bool,
    ) -> Result<
        (
            VerifiedInheritedKerneldListenersV2,
            Option<std::os::unix::net::UnixListener>,
        ),
        crate::deployment_trust::DeploymentTrustErrorV2,
    > {
        if managed_admin {
            return Err(crate::deployment_trust::DeploymentTrustErrorV2::UnsafeSocket);
        }
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
        let verified = verify_kerneld_inherited_listeners_v2(
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
        )?;
        Ok((verified, None))
    }

    pub(super) fn run(
        config_path: &Path,
        _process_boot_id: BootIdV2,
        lifecycle: &mut dyn ServerLifecycle,
    ) -> Result<(), StableCode> {
        let (startup, keys, runtime_material) = load_verified_startup(config_path)?;
        let task_issuer =
            load_task_authorization_issuer(&keys, &runtime_material, startup.installation_id())?;
        let managed_resource_issuer = load_managed_resource_issuer(&keys, &runtime_material)?;
        let managed_admin =
            load_managed_admin(&keys, &runtime_material, startup.installation_id())?;
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
        let (inherited, admin_listener) = take_kerneld_native_listeners_v2(
            agent_edge.listener_identity_digest(),
            ingress_edge.listener_identity_digest(),
            managed_admin.is_some(),
        )
        .map_err(|_| StableCode::KernelUnavailable)?;
        let (agent_listener, ingress_listener) = inherited.into_parts();

        let runtime = Arc::new(V2GenerationRuntime::new());
        let rollover = crate::bootstrap::v2_policy_rollover_coordinator(Arc::clone(&runtime));
        let declassification_rule_set = runtime.active_declassification_rules();
        let kernel_identity = startup
            .service_identity(ClosedServiceIdV2::Kerneld)
            .ok_or(StableCode::KernelUnavailable)?;
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
        #[cfg(all(target_os = "linux", not(feature = "linux-file-backed-integration")))]
        let vault_anchor = crate::tpm_anchor_v3::TpmAnchorV3::open(
            keys.tpm_enrollment.clone(),
            savana_platform_identity::TpmStoreV3::Vault,
            startup.installation_id(),
            runtime_material.vault_store_id,
        )
        .map_err(|_| StableCode::KernelUnavailable)?;
        #[cfg(any(target_os = "macos", feature = "linux-file-backed-integration"))]
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
            // Every vault context is issued and checked by the data plane for
            // the authenticated agentd kernel client. The vault must bind the
            // same boot identity, or committed input can never mint a document.
            savana_vault::VaultServiceV2::from_verified_deployment(
                startup.installation_id(),
                startup.active_state_manifest_digest(),
                runtime_material.agentd_boot_id,
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
        #[cfg(all(target_os = "linux", not(feature = "linux-file-backed-integration")))]
        let agent_anchor = crate::tpm_anchor_v3::TpmAnchorV3::open(
            keys.tpm_enrollment.clone(),
            savana_platform_identity::TpmStoreV3::Agent,
            startup.installation_id(),
            runtime_material.agent_authority_store_id,
        )
        .map_err(|_| StableCode::KernelUnavailable)?;
        #[cfg(any(target_os = "macos", feature = "linux-file-backed-integration"))]
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
        #[cfg(all(target_os = "linux", not(feature = "linux-file-backed-integration")))]
        let g4_anchor = crate::tpm_anchor_v3::TpmAnchorV3::open(
            keys.tpm_enrollment.clone(),
            savana_platform_identity::TpmStoreV3::G4,
            startup.installation_id(),
            runtime_material.g4_store_id,
        )
        .map_err(|_| StableCode::KernelUnavailable)?;
        #[cfg(any(target_os = "macos", feature = "linux-file-backed-integration"))]
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
            declassification_rule_set.clone(),
            runtime_material.policy.active_tools,
            runtime_material.policy.validators,
            g4_durable,
            runtime_material.policy.role,
            runtime_material.policy.ontology,
            runtime_material.policy.disposition,
            approval,
        )
        .map_err(|_| StableCode::KernelUnavailable)?;
        let fused_worker_fingerprint = runtime_material.fused_model_workers.fingerprint;
        policy_runtime
            .install_fused_workers_v04(runtime_material.fused_model_workers.workers)
            .map_err(|_| StableCode::KernelUnavailable)?;
        if let Some(material) = keys.kernel_approval {
            let client = savana_approvald::ApprovalSuiteOneClientV2::from_verified_deployment(
                material.edge,
                boot_id,
                current_native_self_peer_binding()?,
                material.signing_key,
                material.server_public_key,
            )
            .map_err(|_| StableCode::KernelUnavailable)?;
            policy_runtime.install_fused_approval_client_v04(client, material.edge)?;
        }
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
        let connector_genesis = ConnectorRegistryStateV2::from_verified_genesis(
            runtime_material.policy.connector_registry_genesis_digest,
            runtime_material.policy.connector_authority_public_key,
            runtime_material.policy.user_tier_host_allowlist,
            runtime_material.policy.deployment_shipped_connectors,
        )
        .map_err(|_| StableCode::KernelUnavailable)?;
        let connector_store_id = connector_store_id_v2(
            startup.installation_id(),
            connector_genesis.genesis_digest(),
            connector_genesis.connector_authority_public_key(),
        );
        let (connector_registry, connector_authority) = if let Some(signing_key) =
            keys.connector_authority_signing_key.as_ref()
        {
            let signing_seed = Zeroizing::new(signing_key.to_bytes());
            let encryption_key = derive_connector_runtime_secret_v2(
                &signing_seed,
                CONNECTOR_STORE_ENCRYPTION_DERIVATION_DOMAIN_V2,
                startup.installation_id(),
                connector_genesis.genesis_digest(),
                connector_store_id,
            )?;
            let anchor_key = derive_connector_runtime_secret_v2(
                &signing_seed,
                CONNECTOR_STORE_ANCHOR_DERIVATION_DOMAIN_V2,
                startup.installation_id(),
                connector_genesis.genesis_digest(),
                connector_store_id,
            )?;
            let handle_key = derive_connector_runtime_secret_v2(
                &signing_seed,
                CONNECTOR_HANDLE_DERIVATION_DOMAIN_V2,
                startup.installation_id(),
                connector_genesis.genesis_digest(),
                connector_store_id,
            )?;
            if encryption_key == anchor_key
                || encryption_key == handle_key
                || anchor_key == handle_key
                || encryption_key.as_slice() == signing_seed.as_slice()
                || anchor_key.as_slice() == signing_seed.as_slice()
                || handle_key.as_slice() == signing_seed.as_slice()
            {
                return Err(StableCode::KernelUnavailable);
            }
            let (state_path, _anchor_path) = connector_store_paths_v2(
                &runtime_material.agent_authority_state_path,
                connector_genesis.genesis_digest(),
            )?;
            let namespace = DurableStateNamespaceV2::from_verified_installation(
                startup.installation_id(),
                connector_store_id,
            )
            .map_err(|_| StableCode::KernelUnavailable)?;
            #[cfg(all(target_os = "linux", not(feature = "linux-file-backed-integration")))]
            let anchor = crate::tpm_anchor_v3::TpmAnchorV3::open(
                keys.tpm_enrollment.clone(),
                savana_platform_identity::TpmStoreV3::Connector,
                startup.installation_id(),
                connector_store_id,
            )
            .map_err(|_| StableCode::KernelUnavailable)?;
            #[cfg(any(target_os = "macos", feature = "linux-file-backed-integration"))]
            let anchor = PosixAuthenticatedAnchorFileV2::new(
                _anchor_path,
                startup.installation_id(),
                connector_store_id,
                anchor_key,
                CONNECTOR_ANCHOR_MAC_DOMAIN_V2,
                CONNECTOR_ANCHOR_MAGIC_V2,
            )?;
            let store = DurableConnectorRegistryStoreV2::open(
                &state_path,
                encryption_key,
                namespace,
                Box::new(anchor),
                connector_genesis,
            )
            .map_err(|_| StableCode::KernelUnavailable)?;
            let recovered = store
                .snapshot()
                .map_err(|_| StableCode::KernelUnavailable)?;
            let shared = SharedVerifiedConnectorRegistryV2::from_verified_state(recovered)
                .map_err(|_| StableCode::KernelUnavailable)?;
            let authority =
                KernelConnectorAuthorityV2::from_durable_store(store, shared.clone(), handle_key)
                    .map_err(|_| StableCode::KernelUnavailable)?;
            (shared, authority)
        } else {
            let disabled_seed = Zeroizing::new(keys.envelope_signing_key.to_bytes());
            let handle_key = derive_connector_runtime_secret_v2(
                &disabled_seed,
                CONNECTOR_DISABLED_HANDLE_DERIVATION_DOMAIN_V2,
                startup.installation_id(),
                connector_genesis.genesis_digest(),
                connector_store_id,
            )?;
            let shared = SharedVerifiedConnectorRegistryV2::from_verified_state(connector_genesis)
                .map_err(|_| StableCode::KernelUnavailable)?;
            let authority = KernelConnectorAuthorityV2::disabled(shared.clone(), handle_key)
                .map_err(|_| StableCode::KernelUnavailable)?;
            (shared, authority)
        };
        agent_authority
            .install_task_issuer(task_issuer)
            .map_err(|_| StableCode::KernelUnavailable)?;
        if let Some(issuer) = managed_resource_issuer {
            agent_authority
                .install_managed_resource_issuer(issuer)
                .map_err(|_| StableCode::KernelUnavailable)?;
        }
        if let Some(trust) = managed_admin {
            agent_authority.install_managed_admin(trust)?;
        }
        let g7_runtime = KernelG7RuntimeV2::from_verified_deployment(
            runtime_material.policy.quota_limit,
            runtime_material.policy.quota_policy_digest,
            runtime_material.policy.executor_identity,
            runtime_material.policy.executor_seal_key_id,
            runtime_material.policy.executor_seal_public_key,
            runtime_material.policy.connector_registry_genesis_digest,
            runtime_material.policy.connector_authority_key_id,
            runtime_material.policy.connector_authority_public_key,
            keys.connector_authority_signing_key,
            connector_registry,
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
            declassification_rule_set.clone(),
            runtime_material.policy_allowed_effects,
        )
        .map_err(|_| StableCode::KernelUnavailable)?;
        let data_plane = ProductionKernelDataPlaneV2::new(
            input_runtime,
            vault,
            declassification_rule_set,
            startup.installation_id(),
            ProducerIdentityV2::new(*ingressd_identity.as_bytes()),
            runtime_material.agentd_boot_id,
            agentd_identity,
            runtime_material.agentd_peer_identity_digest,
            runtime_material.policy_allowed_effects,
            runtime_material.logical_run_ttl_ms,
        )?;
        services.install_agent_security(agent_authority)?;
        services.install_connector_authority(connector_authority)?;
        services.install_ingress_security(
            KernelIngressAuthorityV2::new(ingress_security, 65_536)
                .map_err(|_| StableCode::KernelUnavailable)?,
            Box::new(data_plane),
        )?;
        services.install_parser_trust(runtime_material.parser_trust)?;
        services.verify_production_complete()?;
        let owner = Arc::new(
            KernelRuntimeOwnerV2::spawn(128, services)
                .map_err(|_| StableCode::KernelUnavailable)?,
        );
        let live_endpoints = Arc::new(
            V2LiveEndpointRuntimeV2::from_verified_deployment(
                &startup,
                boot_id,
                keys.agent_client_public_key,
                keys.agent_server_signing_key,
                keys.ingress_client_public_key,
                keys.ingress_server_signing_key,
                keys.envelope_signing_key,
                Arc::clone(&owner),
            )
            .map_err(|_| StableCode::KernelUnavailable)?,
        );
        let declassification = runtime_material.declassification;
        let successor = VerifiedV2DeclassificationSuccessorV2::from_verified_deployment(
            &startup,
            declassification.canonical_rule_set,
            declassification.trust_roots,
            current_unix_millis()?.get(),
            live_endpoints,
        )
        .map_err(|_| StableCode::KernelUnavailable)?;
        rollover.publish_v2_declassification_successor(successor)?;
        #[cfg(target_os = "linux")]
        let peer_verifier = Arc::new(LinuxNativeUnixPeerVerifierV2);
        #[cfg(target_os = "macos")]
        let peer_verifier = Arc::new(MacOsNativeUnixPeerVerifierV2);
        let agent = KerneldV2EndpointListener::new_agent(
            agent_listener,
            Arc::clone(&runtime),
            peer_verifier.clone(),
        )
        .map_err(|_| StableCode::KernelUnavailable)?;
        let ingress = KerneldV2EndpointListener::new_ingress(
            ingress_listener,
            Arc::clone(&runtime),
            peer_verifier,
        )
        .map_err(|_| StableCode::KernelUnavailable)?;
        let admin_endpoint = admin_listener
            .map(|listener| {
                crate::v04_managed_admin::AdminEndpointV04::new(listener, Arc::clone(&owner))
            })
            .transpose()?;
        let successor_publisher = ProductionV2SuccessorPublisher {
            fused_worker_fingerprint,
            config_path: config_path.to_path_buf(),
            kernel_boot_id: boot_id,
            coordinator: rollover,
            owner,
        };
        run_kerneld_v2_workers(
            agent,
            ingress,
            admin_endpoint,
            runtime.as_ref(),
            readiness,
            lifecycle,
            &successor_publisher,
        )
    }

    #[cfg(feature = "test-support")]
    pub(super) fn probe_declassification_rollover(
        scenario: crate::test_support::V2DeclassificationRolloverScenario,
    ) -> crate::test_support::V2DeclassificationRolloverProbe {
        use savana_policy_core::v2::{
            declassification_implementation_digest_v2, ClosedDeclassificationPurposeV2,
            DeclassificationRuleSetV2, DeclassificationRuleV2, LeakGateDutyV2,
            OperationalTrustRootPurposeV2, OperationalTrustRootSetItemV2,
        };

        let installer = SigningKey::from_bytes(&[0x31; 32]);
        let authority = SigningKey::from_bytes(&[0x32; 32]);
        let family = Digest32V2::new([0x33; 32]);
        let member = OperationalTrustRootSetItemV2::new(
            OperationalTrustRootPurposeV2::DeclassificationAuthority,
            authority.verifying_key().to_bytes(),
            1,
            5,
            100,
        )
        .expect("declassification rollover authority member");
        let roots = Arc::new(
            OperationalTrustRootSetV2::new_declassification_signed_for_test(
                family,
                1,
                None,
                vec![member],
                5,
                100,
                &installer,
                1,
            )
            .expect("declassification rollover roots"),
        );
        let signed_rules = |sequence, predecessor, not_before, not_after, now| {
            let rule = DeclassificationRuleV2::new_for_test(
                2,
                ClosedDeclassificationPurposeV2::PlannerCall,
                declassification_implementation_digest_v2(2)
                    .expect("planner implementation digest"),
                LeakGateDutyV2::BlocklistAndNoResidualPii,
                None,
                None,
                not_before,
                not_after,
            )
            .expect("declassification rollover rule");
            DeclassificationRuleSetV2::new_signed_for_test(
                family,
                sequence,
                predecessor,
                vec![rule],
                not_before,
                not_after,
                roots.as_ref(),
                &authority,
                1,
                now,
            )
            .expect("declassification rollover rule set")
        };

        let initial = signed_rules(7, Some(Digest32V2::new([0x34; 32])), 10, 90, 50);
        let old_digest = initial.signed_digest();
        let initial_startup = verified_rollover_startup(1, old_digest);
        let runtime = Arc::new(V2GenerationRuntime::new());
        let publication_clock = Arc::new(RolloverPublicationClockV2::new(50));
        let coordinator = Arc::new(
            crate::policy_runtime::PolicyRolloverCoordinator::new_v2_with_clock_for_test_support(
                Arc::clone(&runtime),
                Arc::clone(&publication_clock) as Arc<dyn Clock + Send + Sync>,
            ),
        );
        let active_rules = runtime.active_declassification_rules();
        let observations = Arc::new(Mutex::new(Vec::<RolloverDispatchObservationV2>::new()));
        let handler_observations = Arc::clone(&observations);
        let handler_rules = active_rules.clone();
        let task_authority = SigningKey::from_bytes(&[0xa6; 32]);
        let installation_id = initial_startup.installation_id();
        let agentd_identity = initial_startup
            .service_identity(ClosedServiceIdV2::Agentd)
            .expect("rollover agentd identity");
        let owner = Arc::new(
            KernelRuntimeOwnerV2::spawn_for_test_support(8, move |request| {
                let (peer, lease, _, _, _, _, operation) = request.into_parts();
                let rule_digest = handler_rules
                    .snapshot()
                    .map_err(|_| StableCode::KernelUnavailable)?
                    .signed_digest();
                handler_observations
                    .lock()
                    .map_err(|_| StableCode::KernelUnavailable)?
                    .push(RolloverDispatchObservationV2 {
                        role: peer.role(),
                        generation: lease.deployment_generation(),
                        rule_digest,
                    });
                let body = match operation {
                    KernelServiceOperationV2::Agent(KernelAgentOperationV2::Health(_)) => {
                        encode_kernel_agent_health_response_v2(&KernelAgentHealthResponseV2::new(
                            true,
                            PublicServiceStateV2::Ready,
                        ))
                    }
                    KernelServiceOperationV2::Agent(KernelAgentOperationV2::PrepareNewIngress(
                        _,
                    )) => {
                        let mut task_id = [0xe1; 32];
                        task_id[31] = u8::try_from(lease.deployment_generation())
                            .map_err(|_| StableCode::KernelUnavailable)?;
                        let unsigned = UnsignedDurableTaskCorrelationV2::new(
                            installation_id,
                            lease.active_state_manifest_digest(),
                            lease.deployment_generation(),
                            DurableTaskIdV2::new(task_id),
                            agentd_identity,
                            BootIdV2::new([0xd1; 32]),
                            BootIdV2::new([0xc1; 32]),
                            BootIdV2::new([0xd3; 32]),
                            UnixMillisV2::new(1),
                            UnixMillisV2::new(u64::MAX - 1),
                            UnixMillisV2::new(u64::MAX),
                        )
                        .map_err(|_| StableCode::KernelUnavailable)?;
                        let response = PrepareNewIngressResponseV2::Prepared {
                            preparation: NewTaskPreparationHandleV2::from_authority_entropy(
                                task_id,
                            )
                            .ok_or(StableCode::KernelUnavailable)?,
                            correlation: SignedDurableTaskCorrelationV2::sign(
                                unsigned,
                                &task_authority,
                            )
                            .map_err(|_| StableCode::KernelUnavailable)?,
                            ingress_transfer:
                                KernelIngressBootstrapTransferCapabilityV2::from_authority_entropy(
                                    [0xe2; 32],
                                )
                                .ok_or(StableCode::KernelUnavailable)?,
                        };
                        encode_prepare_new_ingress_response_v2(&response)
                    }
                    KernelServiceOperationV2::Ingress(KernelIngressOperationV2::Health(_)) => {
                        encode_kernel_ingress_health_response_v2(
                            &KernelIngressHealthResponseV2::new(true, PublicServiceStateV2::Ready),
                        )
                    }
                    _ => return Err(StableCode::KernelUnavailable),
                }
                .map_err(|_| StableCode::KernelUnavailable)?;
                KernelServiceResponseBodyV2::from_typed_handler(body)
                    .map_err(|_| StableCode::KernelUnavailable)
            })
            .expect("rollover runtime owner"),
        );
        let initial_endpoints = Arc::new(
            rollover_live_endpoints(&initial_startup, Arc::clone(&owner), false)
                .expect("complete initial endpoint runtime"),
        );
        coordinator
            .publish_v2_declassification_successor(
                VerifiedV2DeclassificationSuccessorV2::from_verified_deployment(
                    &initial_startup,
                    initial.canonical_bytes().to_vec(),
                    Arc::clone(&roots),
                    50,
                    initial_endpoints,
                )
                .expect("verified initial declassification deployment"),
            )
            .expect("publish initial declassification deployment");
        let client_source = Arc::new(Mutex::new(Some((1_u64, old_digest))));
        let mut live_clients =
            RolloverLiveClientsV2::new(&initial_startup, Arc::clone(&client_source));
        live_clients.exercise(Arc::clone(&runtime), &initial_startup);

        let successor = signed_rules(8, Some(old_digest), 20, 90, 50);
        let candidate_digest = successor.signed_digest();
        let (generation, manifest_pin, mut bytes, verification_time, incomplete_endpoints) =
            match scenario {
            crate::test_support::V2DeclassificationRolloverScenario::ValidSuccessor => (
                2,
                candidate_digest,
                successor.canonical_bytes().to_vec(),
                50,
                false,
            ),
            crate::test_support::V2DeclassificationRolloverScenario::RuleSetRollback => {
                (2, old_digest, initial.canonical_bytes().to_vec(), 50, false)
            }
            crate::test_support::V2DeclassificationRolloverScenario::WrongManifestPin => (
                2,
                Digest32V2::new([0x7f; 32]),
                successor.canonical_bytes().to_vec(),
                50,
                false,
            ),
            crate::test_support::V2DeclassificationRolloverScenario::BadRuleSetSignature => (
                2,
                candidate_digest,
                successor.canonical_bytes().to_vec(),
                50,
                false,
            ),
            crate::test_support::V2DeclassificationRolloverScenario::ExpiredRuleSet => (
                2,
                candidate_digest,
                successor.canonical_bytes().to_vec(),
                95,
                false,
            ),
            crate::test_support::V2DeclassificationRolloverScenario::ExpiresBeforePublication => (
                2,
                candidate_digest,
                successor.canonical_bytes().to_vec(),
                50,
                false,
            ),
            crate::test_support::V2DeclassificationRolloverScenario::IncompleteEndpointRuntime => (
                2,
                candidate_digest,
                successor.canonical_bytes().to_vec(),
                50,
                true,
            ),
            crate::test_support::V2DeclassificationRolloverScenario::GenerationGap => (
                3,
                candidate_digest,
                successor.canonical_bytes().to_vec(),
                50,
                false,
            ),
        };
        if scenario == crate::test_support::V2DeclassificationRolloverScenario::BadRuleSetSignature
        {
            *bytes.last_mut().expect("nonempty successor") ^= 1;
        }
        let startup = verified_rollover_startup(generation, manifest_pin);
        let candidate = rollover_live_endpoints(&startup, Arc::clone(&owner), incomplete_endpoints)
            .and_then(|endpoints| {
                VerifiedV2DeclassificationSuccessorV2::from_verified_deployment(
                    &startup,
                    bytes,
                    roots,
                    verification_time,
                    Arc::new(endpoints),
                )
            });
        let verified_successor_constructed = candidate.is_ok();
        if scenario
            == crate::test_support::V2DeclassificationRolloverScenario::ExpiresBeforePublication
        {
            publication_clock.set(95);
        }
        let result = candidate
            .map_err(|_| StableCode::KernelUnavailable)
            .and_then(|candidate| coordinator.publish_v2_declassification_successor(candidate));
        let serving_startup = if result.is_ok() {
            *client_source.lock().expect("rollover client source") =
                Some((generation, manifest_pin));
            &startup
        } else {
            *client_source.lock().expect("rollover client source") = None;
            live_clients.assert_rejected_reload_retains_generation(1);
            &initial_startup
        };
        live_clients.exercise(Arc::clone(&runtime), serving_startup);
        let observations = observations.lock().expect("rollover observations");
        let ingress = observations
            .iter()
            .rev()
            .find(|observation| observation.role == EndpointRoleV2::IngressKernel)
            .copied()
            .expect("real ingress dispatch observation");
        let agent = observations
            .iter()
            .rev()
            .find(|observation| observation.role == EndpointRoleV2::AgentKernel)
            .copied()
            .expect("real agent dispatch observation");
        let active_generation = runtime
            .active_declassification_rules()
            .generation_snapshot()
            .expect("active V2 generation")
            .deployment_generation();
        crate::test_support::V2DeclassificationRolloverProbe::new(
            result,
            old_digest,
            candidate_digest,
            verified_successor_constructed,
            ingress.rule_digest,
            agent.rule_digest,
            ingress.generation,
            agent.generation,
            active_generation,
            runtime.admission_resumed_for_test_support(),
        )
    }

    #[cfg(feature = "test-support")]
    #[derive(Clone, Copy)]
    struct RolloverDispatchObservationV2 {
        role: EndpointRoleV2,
        generation: u64,
        rule_digest: Digest32V2,
    }

    #[cfg(feature = "test-support")]
    struct RolloverPublicationClockV2(AtomicU64);

    #[cfg(feature = "test-support")]
    impl RolloverPublicationClockV2 {
        const fn new(now_unix_ms: u64) -> Self {
            Self(AtomicU64::new(now_unix_ms))
        }

        fn set(&self, now_unix_ms: u64) {
            self.0.store(now_unix_ms, AtomicOrdering::Release);
        }
    }

    #[cfg(feature = "test-support")]
    impl Clock for RolloverPublicationClockV2 {
        fn wall_now(
            &self,
        ) -> Result<savana_kernel_protocol::UnixMillis, savana_kernel_protocol::StableCode>
        {
            Ok(savana_kernel_protocol::UnixMillis::new(
                self.0.load(AtomicOrdering::Acquire),
            ))
        }

        fn monotonic_now_millis(&self) -> Result<u64, savana_kernel_protocol::StableCode> {
            Ok(self.0.load(AtomicOrdering::Acquire))
        }
    }

    #[cfg(feature = "test-support")]
    struct RolloverEndpointKeysV2 {
        agent_client: SigningKey,
        agent_server: SigningKey,
        ingress_client: SigningKey,
        ingress_server: SigningKey,
        envelope: SigningKey,
    }

    #[cfg(feature = "test-support")]
    fn rollover_endpoint_keys() -> RolloverEndpointKeysV2 {
        RolloverEndpointKeysV2 {
            agent_client: SigningKey::from_bytes(&[0xa1; 32]),
            agent_server: SigningKey::from_bytes(&[0xa2; 32]),
            ingress_client: SigningKey::from_bytes(&[0xa3; 32]),
            ingress_server: SigningKey::from_bytes(&[0xa4; 32]),
            envelope: SigningKey::from_bytes(&[0xa5; 32]),
        }
    }

    #[cfg(feature = "test-support")]
    fn rollover_live_endpoints(
        startup: &VerifiedDaemonStartupV2,
        owner: Arc<KernelRuntimeOwnerV2>,
        incomplete: bool,
    ) -> Result<V2LiveEndpointRuntimeV2, savana_policy_core::v2::DeploymentControlErrorV2> {
        let keys = rollover_endpoint_keys();
        let envelope = if incomplete {
            SigningKey::from_bytes(&[0xee; 32])
        } else {
            keys.envelope
        };
        V2LiveEndpointRuntimeV2::from_verified_deployment(
            startup,
            BootIdV2::new([0xc1; 32]),
            keys.agent_client.verifying_key().to_bytes(),
            keys.agent_server,
            keys.ingress_client.verifying_key().to_bytes(),
            keys.ingress_server,
            envelope,
            owner,
        )
    }

    #[cfg(feature = "test-support")]
    struct RolloverPeerVerifierV2 {
        agent: NativePeerMeasurementV2,
        ingress: NativePeerMeasurementV2,
    }

    #[cfg(feature = "test-support")]
    impl NativeUnixPeerVerifierV2 for RolloverPeerVerifierV2 {
        fn verify(
            &self,
            _stream: &UnixStream,
            edge: &VerifiedServiceEdgeV2,
        ) -> Result<
            crate::v2_edge::VerifiedAcceptedPeerV2,
            crate::deployment_trust::DeploymentTrustErrorV2,
        > {
            let measurement = match edge.role() {
                EndpointRoleV2::AgentKernel => &self.agent,
                EndpointRoleV2::IngressKernel => &self.ingress,
                _ => return Err(crate::deployment_trust::DeploymentTrustErrorV2::EdgeLockMismatch),
            };
            edge.verify_native_peer(measurement)
        }
    }

    #[cfg(feature = "test-support")]
    fn rollover_peer_measurement(
        startup: &VerifiedDaemonStartupV2,
        role: EndpointRoleV2,
    ) -> NativePeerMeasurementV2 {
        let service = match role {
            EndpointRoleV2::AgentKernel => ClosedServiceIdV2::Agentd,
            EndpointRoleV2::IngressKernel => ClosedServiceIdV2::Ingressd,
            _ => unreachable!("rollover probe has only agent and ingress roles"),
        };
        let lock = startup.service_lock(service).expect("rollover client lock");
        NativePeerMeasurementV2::linux(
            lock.uid,
            lock.gid,
            700 + u32::from(service.tag()),
            800 + u64::from(service.tag()),
            *lock.executable_digest.as_bytes(),
        )
        .expect("rollover native peer measurement")
    }

    #[cfg(feature = "test-support")]
    struct RolloverLiveClientsV2 {
        directory: PathBuf,
        agent_path: PathBuf,
        ingress_path: PathBuf,
        agent: SuiteOneAgentKernelClientV2,
        agent_tasks: AgentTaskServiceV2,
        ingress: SuiteOneIngressKernelClientV2,
    }

    #[cfg(feature = "test-support")]
    impl RolloverLiveClientsV2 {
        fn new(
            startup: &VerifiedDaemonStartupV2,
            source: Arc<Mutex<Option<(u64, Digest32V2)>>>,
        ) -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("rollover directory clock")
                .as_nanos();
            let directory =
                PathBuf::from("/tmp").join(format!("sv2-clients-{}-{nonce:x}", std::process::id()));
            fs::create_dir(&directory).expect("rollover listener directory");
            let agent_path = directory.join("agent.sock");
            let ingress_path = directory.join("ingress.sock");
            let keys = rollover_endpoint_keys();
            let task_authority = SigningKey::from_bytes(&[0xa6; 32]);
            let task_authority_public_key = task_authority.verifying_key().to_bytes();
            let task_authority_key_id = derive_ed25519_key_id_v2(task_authority_public_key);
            let agent_source = Arc::clone(&source);
            let agent = SuiteOneAgentKernelClientV2::from_verified_startup_for_test_support(
                startup,
                BootIdV2::new([0xd1; 32]),
                BootIdV2::new([0xc1; 32]),
                rollover_peer_binding(startup, EndpointRoleV2::AgentKernel),
                keys.agent_client,
                keys.agent_server.verifying_key().to_bytes(),
                task_authority_key_id,
                task_authority_public_key,
                agent_path.clone(),
                move || {
                    let (generation, digest) = (*agent_source.lock().map_err(|_| ())?).ok_or(())?;
                    Ok(verified_rollover_startup(generation, digest))
                },
            )
            .expect("verified agent rollover client");
            let agent_tasks = AgentTaskServiceV2::from_verified_deployment(
                startup.installation_id(),
                startup.active_state_manifest_digest(),
                startup.deployment_generation(),
                startup.protocol_abi_digest(),
                startup
                    .service_identity(ClosedServiceIdV2::Agentd)
                    .expect("rollover agentd identity"),
                BootIdV2::new([0xd1; 32]),
                BootIdV2::new([0xc1; 32]),
                task_authority_key_id,
                task_authority_public_key,
                128,
            )
            .expect("verified pre-rollover agent task service");
            let ingress_source = source;
            let ingress = SuiteOneIngressKernelClientV2::from_verified_startup_for_test_support(
                startup,
                BootIdV2::new([0xd2; 32]),
                BootIdV2::new([0xc1; 32]),
                rollover_peer_binding(startup, EndpointRoleV2::IngressKernel),
                keys.ingress_client,
                keys.ingress_server.verifying_key().to_bytes(),
                ingress_path.clone(),
                move || {
                    let (generation, digest) =
                        (*ingress_source.lock().map_err(|_| ())?).ok_or(())?;
                    Ok(verified_rollover_startup(generation, digest))
                },
            )
            .expect("verified ingress rollover client");
            Self {
                directory,
                agent_path,
                ingress_path,
                agent,
                agent_tasks,
                ingress,
            }
        }

        fn assert_rejected_reload_retains_generation(&self, generation: u64) {
            assert!(self
                .agent
                .reload_verified_authority_for_test_support()
                .is_err());
            assert!(self
                .ingress
                .reload_verified_authority_for_test_support()
                .is_err());
            assert_eq!(
                self.agent.active_generation_for_test_support(),
                Some(generation)
            );
            assert_eq!(
                self.ingress.active_generation_for_test_support(),
                Some(generation)
            );
        }

        fn exercise(
            &mut self,
            runtime: Arc<V2GenerationRuntime>,
            startup: &VerifiedDaemonStartupV2,
        ) {
            let verifier: Arc<dyn NativeUnixPeerVerifierV2> = Arc::new(RolloverPeerVerifierV2 {
                agent: rollover_peer_measurement(startup, EndpointRoleV2::AgentKernel),
                ingress: rollover_peer_measurement(startup, EndpointRoleV2::IngressKernel),
            });
            let agent_listener = KerneldV2EndpointListener::new_agent(
                UnixListener::bind(&self.agent_path).expect("agent rollover listener"),
                Arc::clone(&runtime),
                Arc::clone(&verifier),
            )
            .expect("agent rollover endpoint");
            let agent_connection_count = if startup.deployment_generation() == 1 {
                2
            } else {
                3
            };
            let agent_server = thread::spawn(move || {
                serve_rollover_connections(agent_listener, agent_connection_count)
            });
            let deadline = rollover_request_deadline();
            let agent_result = self.agent.health(RequestIdV2::new([0xd4; 16]), deadline);
            let mut request_id = [0xd5; 16];
            request_id[15] = u8::try_from(startup.deployment_generation())
                .expect("rollover generation fits request fixture");
            let mut request_nonce = [0xd6; 32];
            request_nonce[31] = u8::try_from(startup.deployment_generation())
                .expect("rollover generation fits nonce fixture");
            let task_result = self.agent.prepare_ingress_for_test_support(
                RequestIdV2::new(request_id),
                savana_kernel_protocol::v2::Nonce32V2::new(request_nonce),
                BootIdV2::new([0xd3; 32]),
                rollover_request_deadline(),
            );
            let agent_server_result = agent_server.join().expect("agent rollover listener thread");
            assert_eq!(
                agent_result,
                Ok(PublicServiceStateV2::Ready),
                "server result: {agent_server_result:?}",
            );
            let preparation = task_result.unwrap_or_else(|error| {
                panic!(
                    "post-rollover PrepareNewIngress failed: {error:?}; server result: {agent_server_result:?}"
                )
            });
            let context = AuthenticatedJarvisControlV2::from_mutual_authentication(
                startup.installation_id(),
                Digest32V2::new([0xd7; 32]),
                Digest32V2::new([0xd8; 32]),
                BootIdV2::new([0xd3; 32]),
                BootIdV2::new([0xd9; 32]),
                BootIdV2::new([0xd1; 32]),
                BootIdV2::new([0xc1; 32]),
            )
            .expect("rollover authenticated JARVIS context");
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("rollover task clock")
                .as_millis();
            let now = UnixMillisV2::new(u64::try_from(now).expect("rollover task time fits u64"));
            self.agent_tasks
                .prepare_ingress(
                    context,
                    savana_kernel_protocol::v2::Nonce32V2::new(request_nonce),
                    preparation,
                    now,
                )
                .expect("same pre-rollover agent task service accepts successor preparation");
            assert_eq!(agent_server_result, Ok(()));
            fs::remove_file(&self.agent_path).expect("remove agent rollover socket");

            let ingress_listener = KerneldV2EndpointListener::new_ingress(
                UnixListener::bind(&self.ingress_path).expect("ingress rollover listener"),
                runtime,
                verifier,
            )
            .expect("ingress rollover endpoint");
            let ingress_connection_count = if startup.deployment_generation() == 1 {
                1
            } else {
                2
            };
            let ingress_server = thread::spawn(move || {
                serve_rollover_connections(ingress_listener, ingress_connection_count)
            });
            let health = self
                .ingress
                .health(rollover_request_deadline())
                .expect("ingress rollover client health");
            assert!(health.ready());
            assert_eq!(health.state(), PublicServiceStateV2::Ready);
            assert_eq!(
                ingress_server
                    .join()
                    .expect("ingress rollover listener thread"),
                Ok(())
            );
            fs::remove_file(&self.ingress_path).expect("remove ingress rollover socket");
        }
    }

    #[cfg(feature = "test-support")]
    fn serve_rollover_connections(
        listener: KerneldV2EndpointListener,
        connection_count: usize,
    ) -> Result<(), crate::v2_listener::V2ListenerError> {
        for index in 0..connection_count {
            let result = listener.serve_one(
                UnixMillisV2::new(50),
                Instant::now() + Duration::from_secs(10),
            );
            if index + 1 == connection_count {
                return result;
            }
            assert!(
                result.is_ok()
                    || matches!(
                        result,
                        Err(crate::v2_listener::V2ListenerError::Connection(
                            crate::v2_dispatch::KernelServiceDispatchErrorV2::Malformed
                        ))
                    )
            );
        }
        unreachable!("rollover clients always require a connection")
    }

    #[cfg(feature = "test-support")]
    impl Drop for RolloverLiveClientsV2 {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.agent_path);
            let _ = fs::remove_file(&self.ingress_path);
            let _ = fs::remove_dir(&self.directory);
        }
    }

    #[cfg(feature = "test-support")]
    fn rollover_peer_binding(
        startup: &VerifiedDaemonStartupV2,
        role: EndpointRoleV2,
    ) -> PeerIdentityBindingV2 {
        let service = match role {
            EndpointRoleV2::AgentKernel => ClosedServiceIdV2::Agentd,
            EndpointRoleV2::IngressKernel => ClosedServiceIdV2::Ingressd,
            _ => unreachable!("rollover probe has only agent and ingress roles"),
        };
        let lock = startup.service_lock(service).expect("rollover client lock");
        PeerIdentityBindingV2::linux(
            lock.uid,
            lock.gid,
            700 + u32::from(service.tag()),
            800 + u64::from(service.tag()),
            lock.executable_digest,
        )
        .expect("rollover peer binding")
    }

    #[cfg(feature = "test-support")]
    fn rollover_request_deadline() -> UnixMillisV2 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("rollover request clock")
            .as_millis() as u64;
        // These fixtures do real signatures and socket I/O while other workspace
        // tests may saturate the host. Each operation gets its own test deadline;
        // this does not change the production client's bounded I/O timeout.
        UnixMillisV2::new(now + 10_000)
    }

    #[cfg(all(test, feature = "test-support"))]
    fn rollover_authority_test_clients<FA, FI>(
        startup: &VerifiedDaemonStartupV2,
        agent_loader: FA,
        ingress_loader: FI,
    ) -> (SuiteOneAgentKernelClientV2, SuiteOneIngressKernelClientV2)
    where
        FA: Fn() -> Result<VerifiedDaemonStartupV2, ()> + Send + Sync + 'static,
        FI: Fn() -> Result<VerifiedDaemonStartupV2, ()> + Send + Sync + 'static,
    {
        let keys = rollover_endpoint_keys();
        let task_authority = SigningKey::from_bytes(&[0xa6; 32]);
        let task_authority_public_key = task_authority.verifying_key().to_bytes();
        let agent = SuiteOneAgentKernelClientV2::from_verified_startup_for_test_support(
            startup,
            BootIdV2::new([0xd1; 32]),
            BootIdV2::new([0xc1; 32]),
            rollover_peer_binding(startup, EndpointRoleV2::AgentKernel),
            keys.agent_client,
            keys.agent_server.verifying_key().to_bytes(),
            derive_ed25519_key_id_v2(task_authority_public_key),
            task_authority_public_key,
            PathBuf::from("/tmp/savana-agent-rollover-unused.sock"),
            agent_loader,
        )
        .expect("verified agent rollover authority test client");
        let ingress = SuiteOneIngressKernelClientV2::from_verified_startup_for_test_support(
            startup,
            BootIdV2::new([0xd2; 32]),
            BootIdV2::new([0xc1; 32]),
            rollover_peer_binding(startup, EndpointRoleV2::IngressKernel),
            keys.ingress_client,
            keys.ingress_server.verifying_key().to_bytes(),
            PathBuf::from("/tmp/savana-ingress-rollover-unused.sock"),
            ingress_loader,
        )
        .expect("verified ingress rollover authority test client");
        (agent, ingress)
    }

    #[test]
    #[cfg(feature = "test-support")]
    fn client_rollover_loader_failure_keeps_old_authority() {
        let startup = verified_rollover_startup(1, Digest32V2::new([0x41; 32]));
        let (agent, ingress) = rollover_authority_test_clients(&startup, || Err(()), || Err(()));

        assert!(agent.reload_verified_authority_for_test_support().is_err());
        assert!(ingress
            .reload_verified_authority_for_test_support()
            .is_err());
        assert_eq!(agent.active_generation_for_test_support(), Some(1));
        assert_eq!(ingress.active_generation_for_test_support(), Some(1));
    }

    #[test]
    #[cfg(feature = "test-support")]
    fn client_rollover_generation_gap_keeps_old_authority() {
        let startup = verified_rollover_startup(1, Digest32V2::new([0x42; 32]));
        let (agent, ingress) = rollover_authority_test_clients(
            &startup,
            || Ok(verified_rollover_startup(3, Digest32V2::new([0x43; 32]))),
            || Ok(verified_rollover_startup(3, Digest32V2::new([0x43; 32]))),
        );

        assert!(agent.reload_verified_authority_for_test_support().is_err());
        assert!(ingress
            .reload_verified_authority_for_test_support()
            .is_err());
        assert_eq!(agent.active_generation_for_test_support(), Some(1));
        assert_eq!(ingress.active_generation_for_test_support(), Some(1));
    }

    #[test]
    #[cfg(feature = "test-support")]
    fn client_rollover_identity_change_keeps_old_authority() {
        let startup = verified_rollover_startup(1, Digest32V2::new([0x44; 32]));
        let (agent, ingress) = rollover_authority_test_clients(
            &startup,
            || {
                Ok(verified_rollover_startup_with_identity_change(
                    2,
                    Digest32V2::new([0x45; 32]),
                    true,
                ))
            },
            || {
                Ok(verified_rollover_startup_with_identity_change(
                    2,
                    Digest32V2::new([0x45; 32]),
                    true,
                ))
            },
        );

        assert!(agent.reload_verified_authority_for_test_support().is_err());
        assert!(ingress
            .reload_verified_authority_for_test_support()
            .is_err());
        assert_eq!(agent.active_generation_for_test_support(), Some(1));
        assert_eq!(ingress.active_generation_for_test_support(), Some(1));
    }

    #[test]
    #[cfg(feature = "test-support")]
    fn client_rollover_listener_change_keeps_old_authority() {
        let startup = verified_rollover_startup(1, Digest32V2::new([0x4a; 32]));
        let (agent, ingress) = rollover_authority_test_clients(
            &startup,
            || {
                Ok(verified_rollover_startup_with_mutation(
                    2,
                    Digest32V2::new([0x4b; 32]),
                    RolloverStartupMutationV2::ListenerIdentity,
                ))
            },
            || {
                Ok(verified_rollover_startup_with_mutation(
                    2,
                    Digest32V2::new([0x4b; 32]),
                    RolloverStartupMutationV2::ListenerIdentity,
                ))
            },
        );

        assert!(agent.reload_verified_authority_for_test_support().is_err());
        assert!(ingress
            .reload_verified_authority_for_test_support()
            .is_err());
        assert_eq!(agent.active_generation_for_test_support(), Some(1));
        assert_eq!(ingress.active_generation_for_test_support(), Some(1));
    }

    #[test]
    #[cfg(feature = "test-support")]
    fn client_rollover_handshake_key_change_keeps_old_authority() {
        let startup = verified_rollover_startup(1, Digest32V2::new([0x4c; 32]));
        let (agent, ingress) = rollover_authority_test_clients(
            &startup,
            || {
                Ok(verified_rollover_startup_with_mutation(
                    2,
                    Digest32V2::new([0x4d; 32]),
                    RolloverStartupMutationV2::HandshakeKeys,
                ))
            },
            || {
                Ok(verified_rollover_startup_with_mutation(
                    2,
                    Digest32V2::new([0x4d; 32]),
                    RolloverStartupMutationV2::HandshakeKeys,
                ))
            },
        );

        assert!(agent.reload_verified_authority_for_test_support().is_err());
        assert!(ingress
            .reload_verified_authority_for_test_support()
            .is_err());
        assert_eq!(agent.active_generation_for_test_support(), Some(1));
        assert_eq!(ingress.active_generation_for_test_support(), Some(1));
    }

    #[test]
    #[cfg(feature = "test-support")]
    fn client_rollover_same_generation_manifest_change_keeps_old_authority() {
        let startup = verified_rollover_startup(1, Digest32V2::new([0x4e; 32]));
        let (agent, ingress) = rollover_authority_test_clients(
            &startup,
            || {
                Ok(verified_rollover_startup_with_mutation(
                    1,
                    Digest32V2::new([0x4f; 32]),
                    RolloverStartupMutationV2::ActiveManifest,
                ))
            },
            || {
                Ok(verified_rollover_startup_with_mutation(
                    1,
                    Digest32V2::new([0x4f; 32]),
                    RolloverStartupMutationV2::ActiveManifest,
                ))
            },
        );

        assert!(agent.reload_verified_authority_for_test_support().is_err());
        assert!(ingress
            .reload_verified_authority_for_test_support()
            .is_err());
        assert_eq!(agent.active_generation_for_test_support(), Some(1));
        assert_eq!(ingress.active_generation_for_test_support(), Some(1));
    }

    #[test]
    #[cfg(feature = "test-support")]
    fn client_rollover_rollback_keeps_current_authority() {
        let startup = verified_rollover_startup(2, Digest32V2::new([0x46; 32]));
        let (agent, ingress) = rollover_authority_test_clients(
            &startup,
            || Ok(verified_rollover_startup(1, Digest32V2::new([0x47; 32]))),
            || Ok(verified_rollover_startup(1, Digest32V2::new([0x47; 32]))),
        );

        assert!(agent.reload_verified_authority_for_test_support().is_err());
        assert!(ingress
            .reload_verified_authority_for_test_support()
            .is_err());
        assert_eq!(agent.active_generation_for_test_support(), Some(2));
        assert_eq!(ingress.active_generation_for_test_support(), Some(2));
    }

    #[test]
    #[cfg(feature = "test-support")]
    fn concurrent_client_clones_share_one_successor_publication() {
        let startup = verified_rollover_startup(1, Digest32V2::new([0x48; 32]));
        let (agent, ingress) = rollover_authority_test_clients(
            &startup,
            || Ok(verified_rollover_startup(2, Digest32V2::new([0x49; 32]))),
            || Ok(verified_rollover_startup(2, Digest32V2::new([0x49; 32]))),
        );
        let agent_first = agent.clone();
        let agent_second = agent.clone();
        let ingress_first = ingress.clone();
        let ingress_second = ingress.clone();

        let agent_first_reload =
            thread::spawn(move || agent_first.reload_verified_authority_for_test_support());
        let agent_second_reload =
            thread::spawn(move || agent_second.reload_verified_authority_for_test_support());
        let ingress_first_reload =
            thread::spawn(move || ingress_first.reload_verified_authority_for_test_support());
        let ingress_second_reload =
            thread::spawn(move || ingress_second.reload_verified_authority_for_test_support());

        assert!(agent_first_reload
            .join()
            .expect("first agent reload")
            .is_ok());
        assert!(agent_second_reload
            .join()
            .expect("second agent reload")
            .is_ok());
        assert!(ingress_first_reload
            .join()
            .expect("first ingress reload")
            .is_ok());
        assert!(ingress_second_reload
            .join()
            .expect("second ingress reload")
            .is_ok());
        assert_eq!(agent.active_generation_for_test_support(), Some(2));
        assert_eq!(ingress.active_generation_for_test_support(), Some(2));
    }

    #[cfg(feature = "test-support")]
    fn verified_rollover_startup(
        deployment_generation: u64,
        declassification_rule_set_digest: Digest32V2,
    ) -> VerifiedDaemonStartupV2 {
        verified_rollover_startup_with_identity_change(
            deployment_generation,
            declassification_rule_set_digest,
            false,
        )
    }

    #[cfg(feature = "test-support")]
    fn verified_rollover_startup_with_identity_change(
        deployment_generation: u64,
        declassification_rule_set_digest: Digest32V2,
        identity_change: bool,
    ) -> VerifiedDaemonStartupV2 {
        verified_rollover_startup_with_mutation(
            deployment_generation,
            declassification_rule_set_digest,
            if identity_change {
                RolloverStartupMutationV2::ServiceIdentity
            } else {
                RolloverStartupMutationV2::None
            },
        )
    }

    #[cfg(feature = "test-support")]
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum RolloverStartupMutationV2 {
        None,
        ServiceIdentity,
        ListenerIdentity,
        HandshakeKeys,
        ActiveManifest,
    }

    #[cfg(feature = "test-support")]
    fn verified_rollover_startup_with_mutation(
        deployment_generation: u64,
        declassification_rule_set_digest: Digest32V2,
        mutation: RolloverStartupMutationV2,
    ) -> VerifiedDaemonStartupV2 {
        use savana_kernel_protocol::v2::{Ed25519KeyIdV2, EndpointRoleV2, ServiceIdentityV2};
        use savana_platform_identity::{BoundedIdentityStringV2, ExpectedNativePeerV2};
        use savana_policy_core::v2::{
            ClosedServiceEdgeIdV2, ClosedServiceIdV2, DeploymentTrustErrorV2,
            PlatformDeploymentTrustV2, PlatformServiceObservationV2, ServiceAuthorityHandlesV2,
            ServiceDeploymentLockV2, ServiceEdgeLockV2, VerifiedDeploymentManifestV2,
        };

        struct Platform {
            observations: Vec<PlatformServiceObservationV2>,
            authorities: Vec<ServiceAuthorityHandlesV2>,
            projection: Vec<u8>,
        }

        impl PlatformDeploymentTrustV2 for Platform {
            fn observe_service(
                &mut self,
                service: ClosedServiceIdV2,
            ) -> Result<PlatformServiceObservationV2, DeploymentTrustErrorV2> {
                self.observations
                    .iter()
                    .copied()
                    .find(|observed| observed.lock.service == service)
                    .ok_or(DeploymentTrustErrorV2::PlatformUnavailable)
            }

            fn acquire_service_authorities(
                &mut self,
                service: ClosedServiceIdV2,
            ) -> Result<ServiceAuthorityHandlesV2, DeploymentTrustErrorV2> {
                let index = self
                    .authorities
                    .iter()
                    .position(|authority| authority.service == service)
                    .ok_or(DeploymentTrustErrorV2::PlatformUnavailable)?;
                Ok(self.authorities.remove(index))
            }

            fn read_effect_ledger_projection(&mut self) -> Result<Vec<u8>, DeploymentTrustErrorV2> {
                Ok(self.projection.clone())
            }
        }

        let service_lock = |service: ClosedServiceIdV2| {
            let seed = service.tag() as u8;
            ServiceDeploymentLockV2 {
                service,
                service_identity: ServiceIdentityV2::new(
                    [seed + 80 + u8::from(mutation == RolloverStartupMutationV2::ServiceIdentity);
                        32],
                ),
                uid: 500 + u32::from(seed),
                gid: 600 + u32::from(seed),
                executable_digest: Digest32V2::new([seed; 32]),
                config_digest: Digest32V2::new([seed + 10; 32]),
                config_path_digest: Digest32V2::new([seed + 20; 32]),
                socket_path_digest: Digest32V2::new([seed + 30; 32]),
                socket_uid: 500 + u32::from(seed),
                socket_gid: 600 + u32::from(seed),
                socket_mode: 0o660,
                code_identity_digest: Digest32V2::new([seed + 40; 32]),
                sandbox_profile_digest: Digest32V2::new([seed + 50; 32]),
                keystore_authority_identity: Digest32V2::new([seed + 60; 32]),
                rollback_authority_identity: Digest32V2::new([seed + 70; 32]),
            }
        };
        let services: Vec<_> = ClosedServiceIdV2::ALL
            .iter()
            .copied()
            .map(service_lock)
            .collect();
        let endpoint_keys = rollover_endpoint_keys();
        let agent_client_key_id =
            derive_ed25519_key_id_v2(endpoint_keys.agent_client.verifying_key().to_bytes());
        let agent_server_key_id =
            derive_ed25519_key_id_v2(endpoint_keys.agent_server.verifying_key().to_bytes());
        let ingress_client_key_id =
            derive_ed25519_key_id_v2(endpoint_keys.ingress_client.verifying_key().to_bytes());
        let ingress_server_key_id =
            derive_ed25519_key_id_v2(endpoint_keys.ingress_server.verifying_key().to_bytes());
        let changed_agent_client_key_id = derive_ed25519_key_id_v2(
            SigningKey::from_bytes(&[0xb6; 32])
                .verifying_key()
                .to_bytes(),
        );
        let changed_agent_server_key_id = derive_ed25519_key_id_v2(
            SigningKey::from_bytes(&[0xb7; 32])
                .verifying_key()
                .to_bytes(),
        );
        let changed_ingress_client_key_id = derive_ed25519_key_id_v2(
            SigningKey::from_bytes(&[0xb8; 32])
                .verifying_key()
                .to_bytes(),
        );
        let changed_ingress_server_key_id = derive_ed25519_key_id_v2(
            SigningKey::from_bytes(&[0xb9; 32])
                .verifying_key()
                .to_bytes(),
        );
        let envelope_key_id =
            derive_ed25519_key_id_v2(endpoint_keys.envelope.verifying_key().to_bytes());
        let edges: Vec<_> = ClosedServiceEdgeIdV2::ALL
            .iter()
            .copied()
            .map(|edge_id| {
                let seed = edge_id.tag() as u8;
                let client = service_lock(edge_id.client_service());
                let (client_handshake_key_id, server_handshake_key_id) = match edge_id {
                    ClosedServiceEdgeIdV2::AgentKernel
                        if mutation == RolloverStartupMutationV2::HandshakeKeys =>
                    {
                        (changed_agent_client_key_id, changed_agent_server_key_id)
                    }
                    ClosedServiceEdgeIdV2::AgentKernel => {
                        (agent_client_key_id, agent_server_key_id)
                    }
                    ClosedServiceEdgeIdV2::IngressKernel
                        if mutation == RolloverStartupMutationV2::HandshakeKeys =>
                    {
                        (changed_ingress_client_key_id, changed_ingress_server_key_id)
                    }
                    ClosedServiceEdgeIdV2::IngressKernel => {
                        (ingress_client_key_id, ingress_server_key_id)
                    }
                    ClosedServiceEdgeIdV2::KernelExecutor => (
                        Ed25519KeyIdV2::new([0xb0 + seed * 2; 32]),
                        Ed25519KeyIdV2::new([0xb1 + seed * 2; 32]),
                    ),
                };
                ServiceEdgeLockV2 {
                    edge_id,
                    client_service: edge_id.client_service(),
                    server_service: edge_id.server_service(),
                    role: match edge_id {
                        ClosedServiceEdgeIdV2::AgentKernel => EndpointRoleV2::AgentKernel,
                        ClosedServiceEdgeIdV2::IngressKernel => EndpointRoleV2::IngressKernel,
                        ClosedServiceEdgeIdV2::KernelExecutor => EndpointRoleV2::KernelExecutor,
                    },
                    listener_identity_digest: Digest32V2::new(
                        [0xa0 + seed
                            + u8::from(mutation == RolloverStartupMutationV2::ListenerIdentity);
                            32],
                    ),
                    client_handshake_key_id,
                    server_handshake_key_id,
                    expected_client: ExpectedNativePeerV2::linux(
                        BoundedIdentityStringV2::new(edge_id.role_identity().to_owned())
                            .expect("rollover role identity"),
                        client.uid,
                        client.gid,
                        *client.executable_digest.as_bytes(),
                    )
                    .expect("rollover expected native peer"),
                }
            })
            .collect();
        let installation_id = Digest32V2::new([0x91; 32]);
        let active_manifest = Digest32V2::new(
            [deployment_generation as u8
                + 0x40
                + u8::from(mutation == RolloverStartupMutationV2::ActiveManifest); 32],
        );
        let protocol_abi = Digest32V2::new([0x93; 32]);
        let projection_identity = Digest32V2::new([0x94; 32]);
        let ledger_head = Digest32V2::new([0x97; 32]);
        let projection_key = SigningKey::from_bytes(&[0x98; 32]);
        let projection_key_id = Ed25519KeyIdV2::new([0x99; 32]);

        let payload = encode_rollover_manifest(
            installation_id,
            active_manifest,
            declassification_rule_set_digest,
            deployment_generation,
            protocol_abi,
            envelope_key_id,
            projection_identity,
            ledger_head,
            projection_key_id,
            projection_key.verifying_key().to_bytes(),
            &services,
            &edges,
        );
        let manifest_key = SigningKey::from_bytes(&[0x95; 32]);
        let manifest_key_id = Ed25519KeyIdV2::new([0x96; 32]);
        let digest: [u8; 32] = Sha256::digest(&payload).into();
        let mut signature_input =
            Vec::from(b"SAVANA_DEPLOYMENT_MANIFEST_SIGNATURE_V2\0".as_slice());
        signature_input.extend_from_slice(&digest);
        let signature = manifest_key.sign(&signature_input).to_bytes();
        let mut signed = minicbor::Encoder::new(Vec::new());
        signed
            .array(3)
            .expect("manifest outer")
            .bytes(&payload)
            .expect("manifest payload")
            .bytes(manifest_key_id.as_bytes())
            .expect("manifest key")
            .bytes(&signature)
            .expect("manifest signature");
        let manifest = VerifiedDeploymentManifestV2::verify(
            &signed.into_writer(),
            manifest_key_id,
            manifest_key.verifying_key().to_bytes(),
        )
        .expect("verified rollover deployment manifest");

        let projection = encode_rollover_projection(
            installation_id,
            active_manifest,
            deployment_generation,
            deployment_generation,
            projection_identity,
            ledger_head,
            projection_key_id,
            &projection_key,
        );
        let observations = services
            .iter()
            .copied()
            .map(|lock| PlatformServiceObservationV2 {
                lock,
                executable_is_regular_single_link: true,
                config_is_regular_single_link: true,
                executable_parent_root_owned_not_writable: true,
                config_parent_root_owned_not_writable: true,
                endpoint_identity_is_verified: true,
            })
            .collect();
        let authorities = services
            .iter()
            .map(|lock| ServiceAuthorityHandlesV2 {
                service: lock.service,
                keystore_authority_identity: lock.keystore_authority_identity,
                rollback_authority_identity: lock.rollback_authority_identity,
            })
            .collect();
        VerifiedDaemonStartupV2::verify(
            manifest,
            &mut Platform {
                observations,
                authorities,
                projection,
            },
        )
        .expect("verified rollover daemon startup")
    }

    #[cfg(feature = "test-support")]
    #[allow(clippy::too_many_arguments)]
    fn encode_rollover_manifest(
        installation_id: Digest32V2,
        active_manifest: Digest32V2,
        declassification_rule_set_digest: Digest32V2,
        deployment_generation: u64,
        protocol_abi: Digest32V2,
        envelope_key_id: Ed25519KeyIdV2,
        projection_identity: Digest32V2,
        ledger_head: Digest32V2,
        projection_key_id: Ed25519KeyIdV2,
        projection_public_key: [u8; 32],
        services: &[savana_policy_core::v2::ServiceDeploymentLockV2],
        edges: &[savana_policy_core::v2::ServiceEdgeLockV2],
    ) -> Vec<u8> {
        let mut encoder = minicbor::Encoder::new(Vec::new());
        encoder
            .array(21)
            .expect("manifest fields")
            .u16(2)
            .expect("manifest version")
            .bytes(installation_id.as_bytes())
            .expect("installation")
            .bytes(active_manifest.as_bytes())
            .expect("active manifest")
            .bytes(declassification_rule_set_digest.as_bytes())
            .expect("rule pin")
            .u64(deployment_generation)
            .expect("manifest sequence")
            .u64(deployment_generation)
            .expect("deployment generation")
            .u64(deployment_generation)
            .expect("fence")
            .bytes(protocol_abi.as_bytes())
            .expect("protocol ABI");
        for digest in [0x81_u8, 0x82, 0x83, 0x84, 0x85, 0x86] {
            encoder
                .bytes(&[digest; 32])
                .expect("manifest identity digest");
        }
        encoder
            .bytes(envelope_key_id.as_bytes())
            .expect("envelope key")
            .bytes(projection_identity.as_bytes())
            .expect("projection identity")
            .bytes(ledger_head.as_bytes())
            .expect("ledger head")
            .bytes(projection_key_id.as_bytes())
            .expect("projection key id")
            .bytes(&projection_public_key)
            .expect("projection public key")
            .array(services.len() as u64)
            .expect("service count");
        for service in services {
            encoder
                .array(15)
                .expect("service fields")
                .u16(service.service.tag())
                .expect("service tag")
                .bytes(service.service_identity.as_bytes())
                .expect("service identity")
                .u32(service.uid)
                .expect("service uid")
                .u32(service.gid)
                .expect("service gid")
                .bytes(service.executable_digest.as_bytes())
                .expect("executable")
                .bytes(service.config_digest.as_bytes())
                .expect("config")
                .bytes(service.config_path_digest.as_bytes())
                .expect("config path")
                .bytes(service.socket_path_digest.as_bytes())
                .expect("socket path")
                .u32(service.socket_uid)
                .expect("socket uid")
                .u32(service.socket_gid)
                .expect("socket gid")
                .u32(service.socket_mode)
                .expect("socket mode")
                .bytes(service.code_identity_digest.as_bytes())
                .expect("code identity")
                .bytes(service.sandbox_profile_digest.as_bytes())
                .expect("sandbox")
                .bytes(service.keystore_authority_identity.as_bytes())
                .expect("keystore")
                .bytes(service.rollback_authority_identity.as_bytes())
                .expect("rollback");
        }
        encoder.array(edges.len() as u64).expect("edge count");
        for edge in edges {
            encoder
                .array(8)
                .expect("edge fields")
                .u16(edge.edge_id.tag())
                .expect("edge id")
                .u16(edge.client_service.tag())
                .expect("edge client")
                .u16(edge.server_service.tag())
                .expect("edge server")
                .u16(edge.role.tag())
                .expect("edge role")
                .bytes(edge.listener_identity_digest.as_bytes())
                .expect("listener")
                .bytes(edge.client_handshake_key_id.as_bytes())
                .expect("client key")
                .bytes(edge.server_handshake_key_id.as_bytes())
                .expect("server key");
            match &edge.expected_client {
                savana_platform_identity::ExpectedNativePeerV2::Linux {
                    role_identity,
                    uid,
                    gid,
                    executable_measurement,
                } => {
                    encoder
                        .array(5)
                        .expect("peer fields")
                        .u16(1)
                        .expect("peer tag")
                        .str(role_identity.as_str())
                        .expect("peer role")
                        .u32(*uid)
                        .expect("peer uid")
                        .u32(*gid)
                        .expect("peer gid")
                        .bytes(executable_measurement)
                        .expect("peer executable");
                }
                _ => unreachable!("rollover fixture uses Linux identity projection"),
            }
        }
        encoder.into_writer()
    }

    #[cfg(feature = "test-support")]
    #[allow(clippy::too_many_arguments)]
    fn encode_rollover_projection(
        installation_id: Digest32V2,
        active_manifest: Digest32V2,
        deployment_generation: u64,
        effect_fence_epoch: u64,
        projection_identity: Digest32V2,
        ledger_head: Digest32V2,
        projection_key_id: Ed25519KeyIdV2,
        projection_key: &SigningKey,
    ) -> Vec<u8> {
        let mut payload = minicbor::Encoder::new(Vec::new());
        payload
            .array(11)
            .expect("projection fields")
            .u16(2)
            .expect("projection version")
            .bytes(installation_id.as_bytes())
            .expect("projection installation")
            .bytes(active_manifest.as_bytes())
            .expect("projection manifest")
            .u64(deployment_generation)
            .expect("projection generation")
            .u64(effect_fence_epoch)
            .expect("projection fence")
            .bytes(projection_identity.as_bytes())
            .expect("projection identity")
            .bytes(ledger_head.as_bytes())
            .expect("projection head")
            .bool(false)
            .expect("effects not fenced")
            .bool(true)
            .expect("terminal projection")
            .bytes(&[0x9a; 32])
            .expect("selected record")
            .bytes(&[0; 32])
            .expect("predecessor");
        let payload = payload.into_writer();
        let digest: [u8; 32] = Sha256::digest(&payload).into();
        let mut signature_input =
            Vec::from(b"SAVANA_EFFECT_LEDGER_PROJECTION_SIGNATURE_V2\0".as_slice());
        signature_input.extend_from_slice(&digest);
        let signature = projection_key.sign(&signature_input).to_bytes();
        let mut outer = minicbor::Encoder::new(Vec::new());
        outer
            .array(3)
            .expect("projection outer")
            .bytes(&payload)
            .expect("projection payload")
            .bytes(projection_key_id.as_bytes())
            .expect("projection key")
            .bytes(&signature)
            .expect("projection signature");
        outer.into_writer()
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
        let mut keys = load_key_material(&startup)?;
        let runtime = load_runtime_material(&bootstrap, &startup)?;
        keys.connector_authority_signing_key =
            load_connector_authority_signing_key(&keys, &runtime)?;
        keys.kernel_approval =
            load_kernel_approval_material(&bootstrap, &startup, &keys, &runtime)?;
        // Validate the purpose-separated issuer on initial load AND reload.
        let _ = load_task_authorization_issuer(&keys, &runtime, startup.installation_id())?;
        let _ = load_managed_resource_issuer(&keys, &runtime)?;
        let _ = load_managed_admin(&keys, &runtime, startup.installation_id())?;
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
            &bootstrap.declassification_installer_root_path,
            &bootstrap.declassification_trust_root_set_path,
            &bootstrap.declassification_rule_set_path,
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
        let task_authorization_seed = Zeroizing::new(read_native_credential(
            TASK_AUTHORIZATION_SEED_CREDENTIAL_V2,
        )?);
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
        let task_authorization_signing_key = SigningKey::from_bytes(&task_authorization_seed);
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
            #[cfg(all(target_os = "linux", not(feature = "linux-file-backed-integration")))]
            tpm_enrollment: load_tpm_enrollment_v3(startup)?,
            kernel_approval: None,
            boot_id: read_native_credential(KERNELD_BOOT_ID_CREDENTIAL_V2)?,
            agent_client_public_key,
            ingress_client_public_key,
            agent_server_signing_key,
            ingress_server_signing_key,
            envelope_signing_key,
            authority_envelope_signing_key,
            task_correlation_signing_key,
            task_authorization_signing_key,
            vault_encryption_key,
            vault_anchor_authentication_key,
            agent_state_encryption_key,
            agent_state_anchor_authentication_key,
            g4_state_encryption_key,
            g4_anchor_authentication_key,
            executor_client_signing_key,
            executor_server_public_key,
            connector_authority_signing_key: None,
        })
    }

    fn load_kernel_approval_material(
        bootstrap: &BootstrapDtoV2,
        startup: &VerifiedDaemonStartupV2,
        keys: &KernelKeyMaterialV2,
        runtime: &RuntimeMaterialV2,
    ) -> Result<Option<KernelApprovalMaterialV04>, StableCode> {
        let Some(config) = &bootstrap.kernel_approval else {
            if native_credential_present(KERNEL_APPROVAL_SEED_CREDENTIAL_V04)? {
                return Err(StableCode::KernelUnavailable);
            }
            return Ok(None);
        };
        if !cfg!(target_os = "linux") || !config.server_public_key_path.is_absolute() {
            return Err(StableCode::KernelUnavailable);
        }
        let seed = Zeroizing::new(read_native_credential(KERNEL_APPROVAL_SEED_CREDENTIAL_V04)?);
        let signing_key = SigningKey::from_bytes(&seed);
        let server_public_key: [u8; 32] =
            read_regular_file(&config.server_public_key_path, 32, Some((0, 0, 0o444)))?
                .try_into()
                .map_err(|_| StableCode::KernelUnavailable)?;
        let client_key_id = Ed25519KeyIdV2::new(decode_hex_32(&config.client_key_id)?);
        let server_key_id = Ed25519KeyIdV2::new(decode_hex_32(&config.server_key_id)?);
        let mut distinct = Zeroizing::new(connector_authority_distinct_material(keys, runtime));
        distinct.extend([
            keys.task_authorization_signing_key.to_bytes(),
            keys.task_authorization_signing_key
                .verifying_key()
                .to_bytes(),
        ]);
        if let Some(key) = &keys.connector_authority_signing_key {
            distinct.extend([key.to_bytes(), key.verifying_key().to_bytes()]);
        }
        validate_kernel_approval_keys(
            &seed,
            client_key_id,
            server_public_key,
            server_key_id,
            &distinct,
        )?;
        let edge = startup
            .approval_service_handshake_edge(
                savana_kernel_protocol::v2::EndpointRoleV2::KernelApproval,
                client_key_id,
                server_key_id,
                runtime.approvald_boot_id,
            )
            .map_err(|_| StableCode::KernelUnavailable)?;
        Ok(Some(KernelApprovalMaterialV04 {
            edge,
            signing_key,
            server_public_key,
        }))
    }

    fn validate_kernel_approval_keys(
        seed: &[u8; 32],
        client_key_id: Ed25519KeyIdV2,
        server_public_key: [u8; 32],
        server_key_id: Ed25519KeyIdV2,
        distinct: &[[u8; 32]],
    ) -> Result<(), StableCode> {
        let public = SigningKey::from_bytes(seed).verifying_key().to_bytes();
        if *seed == [0; 32]
            || server_public_key == [0; 32]
            || derive_ed25519_key_id_v2(public) != client_key_id
            || derive_ed25519_key_id_v2(server_public_key) != server_key_id
            || server_public_key == public
            || server_public_key == *seed
            || distinct.contains(seed)
            || distinct.contains(&public)
            || distinct.contains(&server_public_key)
        {
            return Err(StableCode::KernelUnavailable);
        }
        Ok(())
    }

    fn load_managed_admin(
        keys: &KernelKeyMaterialV2,
        runtime: &RuntimeMaterialV2,
        installation: Digest32V2,
    ) -> Result<Option<crate::v04_managed_admin::AdminTrustV04>, StableCode> {
        if runtime.managed_admin.is_some() && !cfg!(target_os = "linux") {
            return Err(StableCode::KernelUnavailable);
        }
        let mut distinct = Zeroizing::new(connector_authority_distinct_material(keys, runtime));
        distinct.push(runtime.task_authorization_public_key);
        distinct.push(runtime.policy.connector_authority_public_key);
        if let Some((_, public)) = runtime.managed_resource_issuer {
            distinct.push(public);
        }
        crate::v04_managed_admin::AdminTrustV04::from_deployment(
            runtime.managed_admin,
            installation,
            runtime.g4_store_id,
            &distinct,
        )
    }

    fn load_managed_resource_issuer(
        keys: &KernelKeyMaterialV2,
        runtime: &RuntimeMaterialV2,
    ) -> Result<Option<crate::v2_managed_resource::KernelManagedResourceIssuerV04>, StableCode>
    {
        // New activation targets Linux only; existing macOS boot remains unchanged.
        if !cfg!(target_os = "linux") {
            return if runtime.managed_resource_issuer.is_none() {
                Ok(None)
            } else {
                Err(StableCode::KernelUnavailable)
            };
        }
        let seed = Zeroizing::new(
            if native_credential_present(MANAGED_RESOURCE_SEED_CREDENTIAL_V04)? {
                Some(read_native_credential(
                    MANAGED_RESOURCE_SEED_CREDENTIAL_V04,
                )?)
            } else {
                None
            },
        );
        let mut distinct = Zeroizing::new(connector_authority_distinct_material(keys, runtime));
        distinct.extend_from_slice(&[
            keys.task_authorization_signing_key.to_bytes(),
            keys.task_authorization_signing_key
                .verifying_key()
                .to_bytes(),
            runtime.policy.connector_authority_public_key,
        ]);
        if let Some(key) = &keys.connector_authority_signing_key {
            distinct.push(key.to_bytes());
        }
        crate::v2_managed_resource::KernelManagedResourceIssuerV04::from_deployment(
            runtime.managed_resource_issuer,
            *seed,
            &distinct,
        )
        .map_err(|_| StableCode::KernelUnavailable)
    }

    fn load_task_authorization_issuer(
        keys: &KernelKeyMaterialV2,
        runtime: &RuntimeMaterialV2,
        installation: Digest32V2,
    ) -> Result<crate::v2_task_authority::KernelTaskAuthorizationIssuerV2, StableCode> {
        let mut distinct = Zeroizing::new(connector_authority_distinct_material(keys, runtime));
        distinct.push(runtime.policy.connector_authority_public_key);
        if let Some(k) = &keys.connector_authority_signing_key {
            distinct.push(k.to_bytes());
        }
        crate::v2_task_authority::KernelTaskAuthorizationIssuerV2::new(
            installation,
            keys.task_authorization_signing_key.clone(),
            runtime.task_authorization_key_id,
            runtime.task_authorization_public_key,
            keys.authority_envelope_signing_key
                .verifying_key()
                .to_bytes(),
            runtime.ingress_settlement_public_key,
            &distinct,
        )
        .map_err(|_| StableCode::KernelUnavailable)
    }

    fn load_connector_authority_signing_key(
        keys: &KernelKeyMaterialV2,
        runtime: &RuntimeMaterialV2,
    ) -> Result<Option<SigningKey>, StableCode> {
        let key_id = *runtime.policy.connector_authority_key_id.as_bytes();
        let public_key = runtime.policy.connector_authority_public_key;
        let authority_disabled = key_id == [0; 32] && public_key == [0; 32];
        let private_key = load_connector_authority_private_material(
            authority_disabled,
            || native_credential_present(CONNECTOR_AUTHORITY_SEED_CREDENTIAL_V2),
            || read_native_credential(CONNECTOR_AUTHORITY_SEED_CREDENTIAL_V2),
        )?;
        let mut distinct_material =
            Zeroizing::new(connector_authority_distinct_material(keys, runtime));
        distinct_material.push(keys.task_authorization_signing_key.to_bytes());
        distinct_material.push(
            keys.task_authorization_signing_key
                .verifying_key()
                .to_bytes(),
        );
        validate_connector_authority_material(key_id, public_key, private_key, &distinct_material)
    }

    fn load_connector_authority_private_material(
        authority_disabled: bool,
        credential_present: impl FnOnce() -> Result<bool, StableCode>,
        read_credential: impl FnOnce() -> Result<[u8; 32], StableCode>,
    ) -> Result<Option<[u8; 32]>, StableCode> {
        match (authority_disabled, credential_present()?) {
            (true, false) => Ok(None),
            (false, true) => read_credential().map(Some),
            (true, true) | (false, false) => Err(StableCode::KernelUnavailable),
        }
    }

    fn connector_authority_distinct_material(
        keys: &KernelKeyMaterialV2,
        runtime: &RuntimeMaterialV2,
    ) -> Vec<[u8; 32]> {
        let signing_keys = [
            &keys.agent_server_signing_key,
            &keys.ingress_server_signing_key,
            &keys.envelope_signing_key,
            &keys.authority_envelope_signing_key,
            &keys.task_correlation_signing_key,
            &keys.executor_client_signing_key,
        ];
        let mut material = Vec::with_capacity(32);
        for signing_key in signing_keys {
            material.push(signing_key.to_bytes());
            material.push(signing_key.verifying_key().to_bytes());
        }
        material.extend([
            keys.agent_client_public_key,
            keys.ingress_client_public_key,
            keys.vault_encryption_key,
            keys.vault_anchor_authentication_key,
            keys.agent_state_encryption_key,
            keys.agent_state_anchor_authentication_key,
            keys.g4_state_encryption_key,
            keys.g4_anchor_authentication_key,
            keys.executor_server_public_key,
            runtime.input_runtime_publisher_public_key,
            runtime.ui_settlement_public_key,
            runtime.ingress_settlement_public_key,
            runtime.policy.tool_settlement_public_key,
            runtime.policy.executor_seal_public_key,
            runtime.policy.executor_receipt_public_key,
        ]);
        material.extend_from_slice(&runtime.connector_authority_distinct_public_keys);
        if let Some(approval) = &keys.kernel_approval {
            material.extend([
                approval.signing_key.to_bytes(),
                approval.signing_key.verifying_key().to_bytes(),
                approval.server_public_key,
            ]);
        }
        material
    }

    fn load_runtime_material(
        bootstrap: &BootstrapDtoV2,
        startup: &VerifiedDaemonStartupV2,
    ) -> Result<RuntimeMaterialV2, StableCode> {
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
        let declassification = load_declassification_material(bootstrap)?;
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
        let mut connector_authority_distinct_public_keys = vec![
            parser_public_key,
            decode_hex_32(&bootstrap.policy_runtime.registry_publisher_public_key)?,
        ];
        connector_authority_distinct_public_keys.extend(
            authenticated_connector_authority_verification_keys(startup, &declassification)?,
        );
        Ok(RuntimeMaterialV2 {
            fused_model_workers: crate::v04_model_workers::load_workers(
                &bootstrap.fused_model_workers,
                read_fused_model_credential_v04,
            )?,
            input_runtime_assets,
            input_runtime_publisher_key_id,
            input_runtime_publisher_public_key,
            ui_settlement_key_id,
            ui_settlement_public_key,
            ingress_settlement_key_id,
            ingress_settlement_public_key,
            task_authorization_key_id: Ed25519KeyIdV2::new(decode_hex_32(
                &bootstrap.task_authorization_key_id,
            )?),
            task_authorization_public_key: decode_hex_32(&bootstrap.task_authorization_public_key)?,
            managed_resource_issuer: bootstrap
                .managed_resource_issuer
                .as_ref()
                .map(|issuer| {
                    Ok::<_, StableCode>((
                        Ed25519KeyIdV2::new(decode_hex_32(&issuer.key_id)?),
                        decode_hex_32(&issuer.public_key)?,
                    ))
                })
                .transpose()?,
            managed_admin: bootstrap
                .managed_admin
                .as_ref()
                .map(|admin| {
                    Ok::<_, StableCode>((
                        Ed25519KeyIdV2::new(decode_hex_32(&admin.key_id)?),
                        decode_hex_32(&admin.public_key)?,
                    ))
                })
                .transpose()?,
            agentd_boot_id: BootIdV2::new(decode_hex_32(&bootstrap.agentd_boot_id)?),
            approvald_boot_id: BootIdV2::new(decode_hex_32(&bootstrap.approvald_boot_id)?),
            machine_boot_id: BootIdV2::new(decode_hex_32(&bootstrap.machine_boot_id)?),
            agentd_peer_identity_digest: Digest32V2::new(decode_hex_32(
                &bootstrap.agentd_peer_identity_digest,
            )?),
            vault_state_path: bootstrap.vault_state_path.clone(),
            #[cfg(any(target_os = "macos", feature = "linux-file-backed-integration"))]
            vault_rollback_anchor_path: bootstrap.vault_rollback_anchor_path.clone(),
            vault_store_id: Digest32V2::new(decode_hex_32(&bootstrap.vault_store_id)?),
            agent_authority_state_path: bootstrap.agent_authority_state_path.clone(),
            #[cfg(any(target_os = "macos", feature = "linux-file-backed-integration"))]
            agent_authority_rollback_anchor_path: bootstrap
                .agent_authority_rollback_anchor_path
                .clone(),
            agent_authority_store_id: Digest32V2::new(decode_hex_32(
                &bootstrap.agent_authority_store_id,
            )?),
            g4_state_path: bootstrap.g4_state_path.clone(),
            #[cfg(any(target_os = "macos", feature = "linux-file-backed-integration"))]
            g4_rollback_anchor_path: bootstrap.g4_rollback_anchor_path.clone(),
            g4_store_id: Digest32V2::new(decode_hex_32(&bootstrap.g4_store_id)?),
            policy_allowed_effects: savana_policy_core::v2::EffectSetV2::from_bits(
                bootstrap.policy_allowed_effect_bits,
            )
            .filter(|effects| *effects != savana_policy_core::v2::EffectSetV2::EMPTY)
            .ok_or(StableCode::KernelUnavailable)?,
            logical_run_ttl_ms: bootstrap.logical_run_ttl_ms,
            connector_authority_distinct_public_keys,
            declassification,
            policy,
            parser_trust,
        })
    }

    fn load_declassification_material(
        bootstrap: &BootstrapDtoV2,
    ) -> Result<DeclassificationMaterialV2, StableCode> {
        if !bootstrap.declassification_installer_root_path.is_absolute()
            || !bootstrap.declassification_trust_root_set_path.is_absolute()
            || !bootstrap.declassification_rule_set_path.is_absolute()
        {
            return Err(StableCode::KernelUnavailable);
        }
        let root_material = read_regular_file(
            &bootstrap.declassification_installer_root_path,
            4096,
            Some((0, 0, 0o444)),
        )?;
        let root_material: DeclassificationInstallerRootDtoV2 =
            serde_json::from_slice(&root_material).map_err(|_| StableCode::KernelUnavailable)?;
        let installer_public_key = decode_hex_32(&root_material.public_key)?;
        let verifier = InstallerOrMdmVerifierV2::new(
            Ed25519KeyIdV2::new(decode_hex_32(&root_material.key_id)?),
            root_material.key_epoch,
            installer_public_key,
        )
        .map_err(|_| StableCode::KernelUnavailable)?;
        let root_bytes = read_regular_file(
            &bootstrap.declassification_trust_root_set_path,
            MAX_DECLASSIFICATION_OBJECT_BYTES_V2,
            None,
        )?;
        let root_set = OperationalTrustRootSetV2::from_canonical_bytes(&root_bytes, &verifier)
            .map_err(|_| StableCode::KernelUnavailable)?;
        let rule_bytes = read_regular_file(
            &bootstrap.declassification_rule_set_path,
            MAX_DECLASSIFICATION_OBJECT_BYTES_V2,
            None,
        )?;
        Ok(DeclassificationMaterialV2 {
            canonical_rule_set: rule_bytes,
            trust_roots: Arc::new(root_set),
            installer_verifier: verifier,
        })
    }

    fn authenticated_connector_authority_verification_keys(
        startup: &VerifiedDaemonStartupV2,
        declassification: &DeclassificationMaterialV2,
    ) -> Result<Vec<[u8; 32]>, StableCode> {
        let mut keys = Vec::new();
        keys.try_reserve_exact(3 + declassification.trust_roots.members().len())
            .map_err(|_| StableCode::KernelUnavailable)?;
        keys.push(startup.deployment_manifest_signing_public_key());
        keys.push(
            startup
                .effect_ledger_projection_binding()
                .signing_public_key(),
        );
        keys.push(declassification.installer_verifier.public_key());
        keys.extend(
            declassification
                .trust_roots
                .members()
                .iter()
                .map(|member| member.public_key()),
        );
        Ok(keys)
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
        let legacy_connector_registry_digest =
            Digest32V2::new(decode_hex_32(&policy.executor_connector_registry_digest)?);
        let connector_registry_genesis_digest =
            Digest32V2::new(decode_hex_32(&policy.connector_registry_genesis_digest)?);
        let connector_authority_key_id_bytes =
            decode_hex_32_allow_zero(&policy.connector_authority_key_id)?;
        let connector_authority_public_key =
            decode_hex_32_allow_zero(&policy.connector_authority_public_key)?;
        let connector_authority_key_id = Ed25519KeyIdV2::new(connector_authority_key_id_bytes);
        let connector_authority_disabled = connector_authority_key_id_bytes == [0; 32]
            && connector_authority_public_key == [0; 32];
        let user_tier_host_allowlist =
            decode_user_tier_host_allowlist(&policy.user_tier_host_allowlist)?;
        if derive_ed25519_key_id_v2(tool_settlement_public_key) != tool_settlement_key_id
            || hpke_x25519_key_id(executor_seal_public_key) != executor_seal_key_id
            || derive_ed25519_key_id_v2(executor_receipt_public_key) != executor_receipt_key_id
            || legacy_connector_registry_digest != connector_registry_genesis_digest
            || (!connector_authority_disabled
                && (connector_authority_key_id_bytes == [0; 32]
                    || connector_authority_public_key == [0; 32]
                    || derive_ed25519_key_id_v2(connector_authority_public_key)
                        != connector_authority_key_id))
        {
            return Err(StableCode::KernelUnavailable);
        }
        let deployment_shipped_connectors = load_deployment_shipped_connectors(
            &policy.deployment_shipped_connectors,
            connector_registry_genesis_digest,
            &user_tier_host_allowlist,
            &active_tools,
        )?;
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
            connector_registry_genesis_digest,
            connector_authority_key_id,
            connector_authority_public_key,
            user_tier_host_allowlist,
            executor_receipt_key_id,
            executor_receipt_public_key,
            deployment_shipped_connectors,
        })
    }

    /// Every shipped connector tool must be an active signed descriptor: the
    /// connector set can route an authorized tool, never introduce one.
    fn load_deployment_shipped_connectors(
        encoded: &[String],
        genesis_digest: Digest32V2,
        user_tier_host_allowlist: &[BoundedConnectorHostV2],
        active_tools: &ActiveToolRegistryV2,
    ) -> Result<Vec<ConnectorDescriptorV2>, StableCode> {
        const MAX_CONNECTORS: usize = 64;
        const MAX_CONNECTOR_BYTES: usize = 65_536;
        if encoded.len() > MAX_CONNECTORS {
            return Err(StableCode::KernelUnavailable);
        }
        let bytes = encoded
            .iter()
            .map(|value| {
                if value.is_empty()
                    || value.len() % 2 != 0
                    || value.len() / 2 > MAX_CONNECTOR_BYTES
                    || !value
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                {
                    return Err(StableCode::KernelUnavailable);
                }
                (0..value.len())
                    .step_by(2)
                    .map(|offset| {
                        u8::from_str_radix(&value[offset..offset + 2], 16)
                            .map_err(|_| StableCode::KernelUnavailable)
                    })
                    .collect::<Result<Vec<u8>, StableCode>>()
            })
            .collect::<Result<Vec<_>, StableCode>>()?;
        let connectors = ConnectorDescriptorV2::verified_deployment_set(
            genesis_digest,
            &bytes,
            user_tier_host_allowlist,
        )
        .map_err(|_| StableCode::KernelUnavailable)?;
        for tool in connectors
            .iter()
            .flat_map(ConnectorDescriptorV2::tool_descriptors)
        {
            if !active_tools
                .records()
                .iter()
                .any(|record| record.descriptor().unsigned() == tool)
            {
                return Err(StableCode::KernelUnavailable);
            }
        }
        Ok(connectors)
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

    fn native_credential_path(name: &str) -> Result<PathBuf, StableCode> {
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
        let valid_directory_identity =
            savana_platform_identity::validate_linux_kerneld_credential_directory_v3().is_ok();
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
        Ok(directory.join(name))
    }

    fn native_credential_present(name: &str) -> Result<bool, StableCode> {
        let path = native_credential_path(name)?;
        match fs::symlink_metadata(path) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(_) => Err(StableCode::KernelUnavailable),
        }
    }

    fn read_native_credential(name: &str) -> Result<[u8; 32], StableCode> {
        #[cfg(target_os = "linux")]
        {
            let bytes = savana_platform_identity::read_linux_kerneld_credential_v3(name, 32)
                .map_err(|_| StableCode::KernelUnavailable)?;
            bytes
                .as_slice()
                .try_into()
                .map_err(|_| StableCode::KernelUnavailable)
        }
        #[cfg(target_os = "macos")]
        {
            let path = native_credential_path(name)?;
            let identity = (0, nix::unistd::getegid().as_raw(), 0o440);
            read_regular_file(&path, 32, Some(identity))?
                .try_into()
                .map_err(|_| StableCode::KernelUnavailable)
        }
    }

    fn read_fused_model_credential_v04(name: &str) -> Result<Zeroizing<Vec<u8>>, StableCode> {
        #[cfg(target_os = "linux")]
        {
            savana_platform_identity::read_linux_service_credential_v2(
                savana_platform_identity::LinuxCredentialServiceV2::Kernel,
                name,
                16384,
            )
            .map_err(|_| StableCode::KernelUnavailable)
        }
        #[cfg(target_os = "macos")]
        {
            let path = native_credential_path(name)?;
            read_regular_file(
                &path,
                16384,
                Some((0, nix::unistd::getegid().as_raw(), 0o440)),
            )
            .map(Zeroizing::new)
        }
    }

    #[cfg(all(target_os = "linux", not(feature = "linux-file-backed-integration")))]
    fn load_tpm_enrollment_v3(
        startup: &VerifiedDaemonStartupV2,
    ) -> Result<savana_platform_identity::TpmEnrollmentV3, StableCode> {
        let root = read_native_credential("tpm-installer-v3.pub")?;
        let bytes = savana_platform_identity::read_linux_kerneld_credential_v3(
            "tpm-enrollment-v3.bin",
            2048,
        )
        .map_err(|_| StableCode::KernelUnavailable)?;
        let enrollment = savana_platform_identity::TpmEnrollmentV3::verify(
            &bytes,
            root,
            current_unix_millis()?.get() / 1000,
        )
        .map_err(|_| StableCode::KernelUnavailable)?;
        if enrollment.signing_binding().installation_id() != *startup.installation_id().as_bytes() {
            return Err(StableCode::KernelUnavailable);
        }
        let identity = enrollment.kernel_identity();
        savana_platform_identity::pin_current_linux_service_v2(
            identity.uid(),
            identity.gid(),
            identity.executable_digest(),
        )
        .map_err(|_| StableCode::KernelUnavailable)?;
        Ok(enrollment)
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

    fn connector_store_id_v2(
        installation_id: Digest32V2,
        genesis_digest: Digest32V2,
        authority_public_key: [u8; 32],
    ) -> Digest32V2 {
        let mut hasher = Sha256::new();
        hasher.update(CONNECTOR_STORE_ID_DOMAIN_V2);
        hasher.update(installation_id.as_bytes());
        hasher.update(genesis_digest.as_bytes());
        hasher.update(authority_public_key);
        Digest32V2::new(hasher.finalize().into())
    }

    fn derive_connector_runtime_secret_v2(
        source_secret: &[u8; 32],
        domain: &[u8],
        installation_id: Digest32V2,
        genesis_digest: Digest32V2,
        store_id: Digest32V2,
    ) -> Result<[u8; 32], StableCode> {
        if source_secret.iter().all(|byte| *byte == 0) || domain.is_empty() {
            return Err(StableCode::KernelUnavailable);
        }
        let mut mac = Hmac::<Sha256>::new_from_slice(source_secret)
            .map_err(|_| StableCode::KernelUnavailable)?;
        mac.update(domain);
        mac.update(installation_id.as_bytes());
        mac.update(genesis_digest.as_bytes());
        mac.update(store_id.as_bytes());
        let derived: [u8; 32] = mac.finalize().into_bytes().into();
        if derived == [0; 32] || derived == *source_secret {
            return Err(StableCode::KernelUnavailable);
        }
        Ok(derived)
    }

    fn connector_store_paths_v2(
        neighboring_state_path: &Path,
        genesis_digest: Digest32V2,
    ) -> Result<(PathBuf, PathBuf), StableCode> {
        if !neighboring_state_path.is_absolute() {
            return Err(StableCode::KernelUnavailable);
        }
        let base = neighboring_state_path
            .parent()
            .ok_or(StableCode::KernelUnavailable)?;
        let base_metadata =
            fs::symlink_metadata(base).map_err(|_| StableCode::KernelUnavailable)?;
        if base_metadata.file_type().is_symlink()
            || !base_metadata.is_dir()
            || base_metadata.mode() & 0o7777 != 0o700
        {
            return Err(StableCode::KernelUnavailable);
        }
        let mut suffix = String::with_capacity(64);
        for byte in genesis_digest.as_bytes() {
            use std::fmt::Write as _;
            write!(&mut suffix, "{byte:02x}").map_err(|_| StableCode::KernelUnavailable)?;
        }
        let directory = base.join(format!("connector-registry-{suffix}"));
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        match builder.create(&directory) {
            Ok(()) => {
                fs::File::open(base)
                    .and_then(|file| file.sync_all())
                    .map_err(|_| StableCode::KernelUnavailable)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(StableCode::KernelUnavailable),
        }
        let metadata =
            fs::symlink_metadata(&directory).map_err(|_| StableCode::KernelUnavailable)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.mode() & 0o7777 != 0o700
            || metadata.uid() != base_metadata.uid()
            || metadata.gid() != base_metadata.gid()
        {
            return Err(StableCode::KernelUnavailable);
        }
        Ok((
            directory.join("connector-registry-v2.cbor"),
            directory.join("connector-registry-anchor-v2.bin"),
        ))
    }

    #[cfg(any(target_os = "macos", test, feature = "linux-file-backed-integration"))]
    struct PosixAuthenticatedAnchorFileV2 {
        path: PathBuf,
        installation_id: Digest32V2,
        store_id: Digest32V2,
        authentication_key: Zeroizing<[u8; 32]>,
        mac_domain: &'static [u8],
        magic: [u8; 8],
    }

    #[cfg(any(target_os = "macos", test, feature = "linux-file-backed-integration"))]
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
            let parent = self.path.parent().ok_or(())?;
            let parent_metadata = fs::symlink_metadata(parent).map_err(|_| ())?;
            if parent_metadata.file_type().is_symlink()
                || !parent_metadata.is_dir()
                || parent_metadata.mode() & 0o7777 != 0o700
                || metadata.file_type().is_symlink()
                || !metadata.is_file()
                || metadata.nlink() != 1
                || metadata.mode() & 0o7777 != 0o600
                || metadata.uid() != parent_metadata.uid()
                || metadata.gid() != parent_metadata.gid()
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
                || parent_metadata.mode() & 0o7777 != 0o700
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

    #[cfg(any(target_os = "macos", test, feature = "linux-file-backed-integration"))]
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

    #[cfg(any(target_os = "macos", test, feature = "linux-file-backed-integration"))]
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

    #[cfg(any(target_os = "macos", test, feature = "linux-file-backed-integration"))]
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
        let output = decode_hex_32_allow_zero(value)?;
        if output.iter().all(|byte| *byte == 0) {
            return Err(StableCode::KernelUnavailable);
        }
        Ok(output)
    }

    fn decode_hex_32_allow_zero(value: &str) -> Result<[u8; 32], StableCode> {
        if value.len() != 64 {
            return Err(StableCode::KernelUnavailable);
        }
        let mut output = [0_u8; 32];
        for (index, slot) in output.iter_mut().enumerate() {
            let offset = index * 2;
            *slot = u8::from_str_radix(&value[offset..offset + 2], 16)
                .map_err(|_| StableCode::KernelUnavailable)?;
        }
        Ok(output)
    }

    fn validate_connector_authority_material(
        key_id: [u8; 32],
        public_key: [u8; 32],
        private_key: Option<[u8; 32]>,
        distinct_material: &[[u8; 32]],
    ) -> Result<Option<SigningKey>, StableCode> {
        let key_id_is_zero = key_id == [0; 32];
        let public_key_is_zero = public_key == [0; 32];
        match (key_id_is_zero, public_key_is_zero, private_key) {
            (true, true, None) => Ok(None),
            (false, false, Some(private_key)) => {
                if private_key == [0; 32]
                    || private_key == public_key
                    || distinct_material
                        .iter()
                        .any(|material| *material == private_key || *material == public_key)
                {
                    return Err(StableCode::KernelUnavailable);
                }
                let signing_key = SigningKey::from_bytes(&private_key);
                if signing_key.verifying_key().to_bytes() != public_key
                    || derive_ed25519_key_id_v2(public_key).as_bytes() != &key_id
                {
                    return Err(StableCode::KernelUnavailable);
                }
                Ok(Some(signing_key))
            }
            _ => Err(StableCode::KernelUnavailable),
        }
    }

    fn decode_user_tier_host_allowlist(
        hosts: &[String],
    ) -> Result<Vec<BoundedConnectorHostV2>, StableCode> {
        if hosts.len() > 4_096 {
            return Err(StableCode::KernelUnavailable);
        }
        let mut parsed = Vec::new();
        parsed
            .try_reserve_exact(hosts.len())
            .map_err(|_| StableCode::KernelUnavailable)?;
        let mut previous: Option<&str> = None;
        for host in hosts {
            if previous.is_some_and(|value| value >= host.as_str()) {
                return Err(StableCode::KernelUnavailable);
            }
            let bounded =
                BoundedConnectorHostV2::new(host).map_err(|_| StableCode::KernelUnavailable)?;
            if bounded.as_str() != host {
                return Err(StableCode::KernelUnavailable);
            }
            previous = Some(host);
            parsed.push(bounded);
        }
        Ok(parsed)
    }

    fn hpke_x25519_key_id(public_key: [u8; 32]) -> HpkeX25519KeyIdV2 {
        let mut hasher = Sha256::new();
        hasher.update(b"SAVANA_HPKE_X25519_KEY_ID_V2\0");
        hasher.update(public_key);
        HpkeX25519KeyIdV2::new(hasher.finalize().into())
    }

    #[cfg(test)]
    mod kernel_approval_startup_tests {
        include!("v04_kernel_approval_startup_tests.rs");
    }

    #[cfg(test)]
    mod connector_authority_tests {
        use std::os::unix::fs::symlink;
        use std::os::unix::fs::PermissionsExt as _;

        use super::*;

        fn test_connector_anchor(path: PathBuf) -> PosixAuthenticatedAnchorFileV2 {
            PosixAuthenticatedAnchorFileV2::new(
                path,
                Digest32V2::new([0x61; 32]),
                Digest32V2::new([0x62; 32]),
                [0x63; 32],
                CONNECTOR_ANCHOR_MAC_DOMAIN_V2,
                CONNECTOR_ANCHOR_MAGIC_V2,
            )
            .unwrap()
        }

        fn connector_anchor_head(
            sequence: u64,
            byte: u8,
        ) -> savana_policy_core::v2::RollbackProtectedStateHeadV2 {
            savana_policy_core::v2::RollbackProtectedStateHeadV2::new(
                sequence,
                Digest32V2::new(if sequence == 0 { [0; 32] } else { [byte; 32] }),
            )
            .unwrap()
        }

        fn enabled_material(seed: u8) -> ([u8; 32], [u8; 32], [u8; 32]) {
            let private = [seed; 32];
            let public = SigningKey::from_bytes(&private).verifying_key().to_bytes();
            let key_id = *derive_ed25519_key_id_v2(public).as_bytes();
            (key_id, public, private)
        }

        #[test]
        fn connector_authority_accepts_only_clean_disabled_or_exact_distinct_key() {
            let zero = [0_u8; 32];
            assert!(validate_connector_authority_material(zero, zero, None, &[])
                .unwrap()
                .is_none());

            let (key_id, public, private) = enabled_material(0x41);
            assert_eq!(
                validate_connector_authority_material(key_id, public, Some(private), &[])
                    .unwrap()
                    .unwrap()
                    .verifying_key()
                    .to_bytes(),
                public
            );

            let wrong_id = enabled_material(0x42).0;
            assert!(
                validate_connector_authority_material(wrong_id, public, Some(private), &[])
                    .is_err()
            );
            assert!(
                validate_connector_authority_material(key_id, public, Some([0x43; 32]), &[])
                    .is_err()
            );
            assert!(
                validate_connector_authority_material(zero, public, Some(private), &[]).is_err()
            );
            assert!(
                validate_connector_authority_material(key_id, zero, Some(private), &[]).is_err()
            );
            assert!(validate_connector_authority_material(key_id, public, None, &[]).is_err());
            assert!(validate_connector_authority_material(zero, zero, Some(private), &[]).is_err());
            assert!(validate_connector_authority_material(
                key_id,
                public,
                Some(private),
                &[private],
            )
            .is_err());
            assert!(validate_connector_authority_material(
                key_id,
                public,
                Some(private),
                &[public],
            )
            .is_err());
        }

        #[test]
        fn connector_authority_always_probes_optional_private_credential() {
            let mut disabled_probes = 0;
            let mut disabled_reads = 0;
            assert!(load_connector_authority_private_material(
                true,
                || {
                    disabled_probes += 1;
                    Ok(true)
                },
                || {
                    disabled_reads += 1;
                    Ok([0x44; 32])
                },
            )
            .is_err());
            assert_eq!(disabled_probes, 1);
            assert_eq!(disabled_reads, 0);

            let mut enabled_probes = 0;
            let mut enabled_reads = 0;
            assert!(load_connector_authority_private_material(
                false,
                || {
                    enabled_probes += 1;
                    Ok(false)
                },
                || {
                    enabled_reads += 1;
                    Ok([0x45; 32])
                },
            )
            .is_err());
            assert_eq!(enabled_probes, 1);
            assert_eq!(enabled_reads, 0);
        }

        #[test]
        fn connector_store_secrets_are_domain_and_deployment_separated() {
            let source = [0x51; 32];
            let installation = Digest32V2::new([0x52; 32]);
            let genesis = Digest32V2::new([0x53; 32]);
            let store = connector_store_id_v2(
                installation,
                genesis,
                SigningKey::from_bytes(&source).verifying_key().to_bytes(),
            );
            let encryption = derive_connector_runtime_secret_v2(
                &source,
                CONNECTOR_STORE_ENCRYPTION_DERIVATION_DOMAIN_V2,
                installation,
                genesis,
                store,
            )
            .unwrap();
            let anchor = derive_connector_runtime_secret_v2(
                &source,
                CONNECTOR_STORE_ANCHOR_DERIVATION_DOMAIN_V2,
                installation,
                genesis,
                store,
            )
            .unwrap();
            let handle = derive_connector_runtime_secret_v2(
                &source,
                CONNECTOR_HANDLE_DERIVATION_DOMAIN_V2,
                installation,
                genesis,
                store,
            )
            .unwrap();
            assert_ne!(encryption, anchor);
            assert_ne!(encryption, handle);
            assert_ne!(anchor, handle);
            assert_ne!(encryption, source);
            assert_ne!(anchor, source);
            assert_ne!(handle, source);
            assert_ne!(
                encryption,
                derive_connector_runtime_secret_v2(
                    &source,
                    CONNECTOR_STORE_ENCRYPTION_DERIVATION_DOMAIN_V2,
                    Digest32V2::new([0x54; 32]),
                    genesis,
                    store,
                )
                .unwrap()
            );
            assert!(derive_connector_runtime_secret_v2(
                &[0; 32],
                CONNECTOR_STORE_ENCRYPTION_DERIVATION_DOMAIN_V2,
                installation,
                genesis,
                store,
            )
            .is_err());
        }

        #[test]
        fn connector_store_paths_are_private_canonical_and_idempotent() {
            let directory = tempfile::tempdir().unwrap();
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
            let neighboring = directory.path().join("agent-authority-state-v2.cbor");
            let genesis = Digest32V2::new([0x5a; 32]);
            let expected_directory = directory
                .path()
                .join(format!("connector-registry-{}", "5a".repeat(32)));

            let first = connector_store_paths_v2(&neighboring, genesis).unwrap();
            let second = connector_store_paths_v2(&neighboring, genesis).unwrap();
            assert_eq!(first, second);
            assert_eq!(
                first.0,
                expected_directory.join("connector-registry-v2.cbor")
            );
            assert_eq!(
                first.1,
                expected_directory.join("connector-registry-anchor-v2.bin")
            );
            assert_eq!(
                fs::symlink_metadata(&expected_directory)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o7777,
                0o700
            );
            assert!(connector_store_paths_v2(Path::new("relative-state"), genesis).is_err());

            fs::set_permissions(&expected_directory, fs::Permissions::from_mode(0o750)).unwrap();
            assert!(connector_store_paths_v2(&neighboring, genesis).is_err());
        }

        #[test]
        fn connector_posix_anchor_rejects_permissions_links_and_partial_files() {
            use savana_policy_core::v2::RollbackProtectedStateAnchorV2 as _;

            let permissions = tempfile::tempdir().unwrap();
            fs::set_permissions(permissions.path(), fs::Permissions::from_mode(0o700)).unwrap();
            let mut anchor = test_connector_anchor(permissions.path().join("anchor.bin"));
            anchor
                .compare_and_advance(connector_anchor_head(0, 0), connector_anchor_head(1, 0x71))
                .unwrap();
            fs::set_permissions(
                permissions.path().join("anchor.bin"),
                fs::Permissions::from_mode(0o644),
            )
            .unwrap();
            assert!(anchor.current_head().is_err());

            let links = tempfile::tempdir().unwrap();
            fs::set_permissions(links.path(), fs::Permissions::from_mode(0o700)).unwrap();
            let mut original = test_connector_anchor(links.path().join("original.bin"));
            original
                .compare_and_advance(connector_anchor_head(0, 0), connector_anchor_head(1, 0x72))
                .unwrap();
            fs::hard_link(
                links.path().join("original.bin"),
                links.path().join("hard-link.bin"),
            )
            .unwrap();
            assert!(original.current_head().is_err());
            let hard_link = test_connector_anchor(links.path().join("hard-link.bin"));
            assert!(hard_link.current_head().is_err());

            let symlink_anchor = test_connector_anchor(links.path().join("symlink.bin"));
            symlink(
                links.path().join("original.bin"),
                links.path().join("symlink.bin"),
            )
            .unwrap();
            assert!(symlink_anchor.current_head().is_err());

            let partial = tempfile::tempdir().unwrap();
            fs::set_permissions(partial.path(), fs::Permissions::from_mode(0o700)).unwrap();
            let partial_path = partial.path().join("anchor.bin");
            fs::write(&partial_path, [0_u8; 17]).unwrap();
            fs::set_permissions(&partial_path, fs::Permissions::from_mode(0o600)).unwrap();
            assert!(test_connector_anchor(partial_path).current_head().is_err());
        }

        #[test]
        fn connector_posix_anchor_accepts_valid_old_file_crash_outcome_before_rename() {
            use savana_policy_core::v2::RollbackProtectedStateAnchorV2 as _;

            let directory = tempfile::tempdir().unwrap();
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
            let path = directory.path().join("anchor.bin");
            let mut anchor = test_connector_anchor(path.clone());
            let first = connector_anchor_head(1, 0x73);
            anchor
                .compare_and_advance(connector_anchor_head(0, 0), first)
                .unwrap();
            let old_file = fs::read(&path).unwrap();
            let second = connector_anchor_head(2, 0x74);
            anchor.compare_and_advance(first, second).unwrap();

            fs::write(&path, old_file).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            assert_eq!(anchor.current_head().unwrap(), first);
        }

        #[cfg(feature = "test-support")]
        #[test]
        fn connector_authority_rejects_every_authenticated_verification_key() {
            use savana_policy_core::v2::{
                OperationalTrustRootPurposeV2, OperationalTrustRootSetItemV2,
            };

            let installer = SigningKey::from_bytes(&[0x31; 32]);
            let declassification_authority = SigningKey::from_bytes(&[0x32; 32]);
            let installer_verifier = InstallerOrMdmVerifierV2::new(
                derive_ed25519_key_id_v2(installer.verifying_key().to_bytes()),
                1,
                installer.verifying_key().to_bytes(),
            )
            .unwrap();
            let member = OperationalTrustRootSetItemV2::new(
                OperationalTrustRootPurposeV2::DeclassificationAuthority,
                declassification_authority.verifying_key().to_bytes(),
                1,
                5,
                100,
            )
            .unwrap();
            let declassification = DeclassificationMaterialV2 {
                canonical_rule_set: Vec::new(),
                trust_roots: Arc::new(
                    OperationalTrustRootSetV2::new_declassification_signed_for_test(
                        Digest32V2::new([0x33; 32]),
                        1,
                        None,
                        vec![member],
                        5,
                        100,
                        &installer,
                        1,
                    )
                    .unwrap(),
                ),
                installer_verifier,
            };
            let startup = verified_rollover_startup(1, Digest32V2::new([0x34; 32]));
            let verification_keys =
                authenticated_connector_authority_verification_keys(&startup, &declassification)
                    .unwrap();
            let expected = vec![
                startup.deployment_manifest_signing_public_key(),
                startup
                    .effect_ledger_projection_binding()
                    .signing_public_key(),
                declassification.installer_verifier.public_key(),
                declassification.trust_roots.members()[0].public_key(),
            ];
            assert_eq!(verification_keys, expected);

            for private_key in [[0x95; 32], [0x98; 32], [0x31; 32], [0x32; 32]] {
                let public_key = SigningKey::from_bytes(&private_key)
                    .verifying_key()
                    .to_bytes();
                let key_id = *derive_ed25519_key_id_v2(public_key).as_bytes();
                assert!(validate_connector_authority_material(
                    key_id,
                    public_key,
                    Some(private_key),
                    &verification_keys,
                )
                .is_err());
            }
        }

        #[test]
        fn connector_host_allowlist_requires_sorted_unique_canonical_hosts() {
            let canonical = vec![
                "192.0.2.1".to_owned(),
                "example.com".to_owned(),
                "xn--bcher-kva.example".to_owned(),
            ];
            let loaded = decode_user_tier_host_allowlist(&canonical).unwrap();
            assert_eq!(
                loaded.iter().map(|host| host.as_str()).collect::<Vec<_>>(),
                ["192.0.2.1", "example.com", "xn--bcher-kva.example"]
            );

            for invalid in [
                vec!["example.com".to_owned(), "192.0.2.1".to_owned()],
                vec!["example.com".to_owned(), "example.com".to_owned()],
                vec!["EXAMPLE.com".to_owned()],
                vec!["example.com.".to_owned()],
                vec!["bad..example.com".to_owned()],
            ] {
                assert!(decode_user_tier_host_allowlist(&invalid).is_err());
            }
        }
    }
}
