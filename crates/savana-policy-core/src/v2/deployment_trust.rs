use std::collections::BTreeSet;

use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey as Ed25519VerifyingKey};
use savana_kernel_protocol::v2::{
    verify_effect_ledger_projection_v2, BootIdV2, Digest32V2, Ed25519KeyIdV2,
    EffectLedgerProjectionBindingV2, EndpointRoleV2, KernelServiceHandshakeEdgeV2,
    ServiceIdentityV2,
};
use savana_platform_identity::{BoundedIdentityStringV2, ExpectedNativePeerV2};
use sha2::{Digest as _, Sha256};

const MANIFEST_SIGNATURE_DOMAIN: &[u8] = b"SAVANA_DEPLOYMENT_MANIFEST_SIGNATURE_V2\0";
const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
const REQUIRED_SERVICE_COUNT: usize = 5;
const REQUIRED_EDGE_COUNT: usize = 3;
const LISTENER_IDENTITY_DOMAIN_V2: &[u8] = b"SAVANA_LISTENER_IDENTITY_V2\0";
const MAX_SOCKET_PATH_BYTES_V2: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DeploymentTrustErrorV2 {
    #[error("deployment manifest is malformed or noncanonical")]
    NonCanonicalManifest,
    #[error("deployment manifest signature is invalid")]
    InvalidManifestSignature,
    #[error("deployment manifest is incomplete")]
    IncompleteManifest,
    #[error("service identity or file measurement does not match")]
    ServiceMeasurementMismatch,
    #[error("service file ownership or parent permissions are unsafe")]
    UnsafeFilesystem,
    #[error("service socket ownership or mode is unsafe")]
    UnsafeSocket,
    #[error("service code identity or sandbox does not match")]
    SandboxMismatch,
    #[error("required platform keystore or rollback authority is absent")]
    MissingPlatformAuthority,
    #[error("effect ledger projection is stale, fenced, or mismatched")]
    EffectLedgerMismatch,
    #[error("kernel service edge lock is incomplete or mismatched")]
    EdgeLockMismatch,
    #[error("platform deployment observation is unavailable")]
    PlatformUnavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ClosedServiceIdV2 {
    Kerneld,
    Agentd,
    Ingressd,
    Approvald,
    Execd,
}

impl ClosedServiceIdV2 {
    pub const ALL: [Self; REQUIRED_SERVICE_COUNT] = [
        Self::Kerneld,
        Self::Agentd,
        Self::Ingressd,
        Self::Approvald,
        Self::Execd,
    ];

    pub const fn tag(self) -> u16 {
        match self {
            Self::Kerneld => 1,
            Self::Agentd => 2,
            Self::Ingressd => 3,
            Self::Approvald => 4,
            Self::Execd => 5,
        }
    }

    fn from_tag(tag: u16) -> Result<Self, DeploymentTrustErrorV2> {
        match tag {
            1 => Ok(Self::Kerneld),
            2 => Ok(Self::Agentd),
            3 => Ok(Self::Ingressd),
            4 => Ok(Self::Approvald),
            5 => Ok(Self::Execd),
            _ => Err(DeploymentTrustErrorV2::NonCanonicalManifest),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceDeploymentLockV2 {
    pub service: ClosedServiceIdV2,
    pub service_identity: ServiceIdentityV2,
    pub uid: u32,
    pub gid: u32,
    pub executable_digest: Digest32V2,
    pub config_digest: Digest32V2,
    pub config_path_digest: Digest32V2,
    pub socket_path_digest: Digest32V2,
    pub socket_uid: u32,
    pub socket_gid: u32,
    pub socket_mode: u32,
    pub code_identity_digest: Digest32V2,
    pub sandbox_profile_digest: Digest32V2,
    pub keystore_authority_identity: Digest32V2,
    pub rollback_authority_identity: Digest32V2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ClosedServiceEdgeIdV2 {
    AgentKernel,
    IngressKernel,
    KernelExecutor,
}

impl ClosedServiceEdgeIdV2 {
    pub const ALL: [Self; REQUIRED_EDGE_COUNT] =
        [Self::AgentKernel, Self::IngressKernel, Self::KernelExecutor];

    pub const fn tag(self) -> u16 {
        match self {
            Self::AgentKernel => 1,
            Self::IngressKernel => 2,
            Self::KernelExecutor => 3,
        }
    }

    fn from_tag(tag: u16) -> Result<Self, DeploymentTrustErrorV2> {
        match tag {
            1 => Ok(Self::AgentKernel),
            2 => Ok(Self::IngressKernel),
            3 => Ok(Self::KernelExecutor),
            _ => Err(DeploymentTrustErrorV2::NonCanonicalManifest),
        }
    }

    pub const fn role(self) -> EndpointRoleV2 {
        match self {
            Self::AgentKernel => EndpointRoleV2::AgentKernel,
            Self::IngressKernel => EndpointRoleV2::IngressKernel,
            Self::KernelExecutor => EndpointRoleV2::KernelExecutor,
        }
    }

    pub const fn client_service(self) -> ClosedServiceIdV2 {
        match self {
            Self::AgentKernel => ClosedServiceIdV2::Agentd,
            Self::IngressKernel => ClosedServiceIdV2::Ingressd,
            Self::KernelExecutor => ClosedServiceIdV2::Kerneld,
        }
    }

    pub const fn server_service(self) -> ClosedServiceIdV2 {
        match self {
            Self::AgentKernel | Self::IngressKernel => ClosedServiceIdV2::Kerneld,
            Self::KernelExecutor => ClosedServiceIdV2::Execd,
        }
    }

    pub const fn role_identity(self) -> &'static str {
        match self {
            Self::AgentKernel => "agent-kernel",
            Self::IngressKernel => "ingress-kernel",
            Self::KernelExecutor => "kernel-executor",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceEdgeLockV2 {
    pub edge_id: ClosedServiceEdgeIdV2,
    pub client_service: ClosedServiceIdV2,
    pub server_service: ClosedServiceIdV2,
    pub role: EndpointRoleV2,
    pub listener_identity_digest: Digest32V2,
    pub client_handshake_key_id: Ed25519KeyIdV2,
    pub server_handshake_key_id: Ed25519KeyIdV2,
    pub expected_client: ExpectedNativePeerV2,
}

#[derive(Debug)]
pub struct VerifiedDeploymentManifestV2 {
    installation_id: Digest32V2,
    active_state_manifest_digest: Digest32V2,
    declassification_rule_set_digest: Digest32V2,
    active_state_manifest_sequence: u64,
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
    ledger_projection_identity: Digest32V2,
    effect_ledger_head_digest: Digest32V2,
    ledger_projection_signing_key_id: Ed25519KeyIdV2,
    ledger_projection_signing_public_key: [u8; 32],
    services: Vec<ServiceDeploymentLockV2>,
    edges: Vec<ServiceEdgeLockV2>,
}

impl VerifiedDeploymentManifestV2 {
    pub fn verify(
        canonical_signed_manifest: &[u8],
        expected_key_id: Ed25519KeyIdV2,
        offline_public_key: [u8; 32],
    ) -> Result<Self, DeploymentTrustErrorV2> {
        if canonical_signed_manifest.is_empty()
            || canonical_signed_manifest.len() > MAX_MANIFEST_BYTES
            || is_zero(expected_key_id.as_bytes())
        {
            return Err(DeploymentTrustErrorV2::NonCanonicalManifest);
        }
        let verifying_key = Ed25519VerifyingKey::from_bytes(&offline_public_key)
            .map_err(|_| DeploymentTrustErrorV2::InvalidManifestSignature)?;
        let mut decoder = minicbor::Decoder::new(canonical_signed_manifest);
        require_array(&mut decoder, 3)?;
        let payload = decoder
            .bytes()
            .map_err(|_| DeploymentTrustErrorV2::NonCanonicalManifest)?
            .to_vec();
        let key_id = Ed25519KeyIdV2::new(decode_fixed::<32>(&mut decoder)?);
        let signature = decode_fixed::<64>(&mut decoder)?;
        if decoder.position() != canonical_signed_manifest.len()
            || key_id != expected_key_id
            || encode_signed_manifest(&payload, key_id, &signature)? != canonical_signed_manifest
        {
            return Err(DeploymentTrustErrorV2::NonCanonicalManifest);
        }
        let digest: [u8; 32] = Sha256::digest(&payload).into();
        let mut signature_input =
            Vec::with_capacity(MANIFEST_SIGNATURE_DOMAIN.len() + digest.len());
        signature_input.extend_from_slice(MANIFEST_SIGNATURE_DOMAIN);
        signature_input.extend_from_slice(&digest);
        verifying_key
            .verify_strict(&signature_input, &Ed25519Signature::from_bytes(&signature))
            .map_err(|_| DeploymentTrustErrorV2::InvalidManifestSignature)?;
        let manifest = decode_manifest_payload(&payload)?;
        if encode_manifest_payload(&manifest)? != payload {
            return Err(DeploymentTrustErrorV2::NonCanonicalManifest);
        }
        manifest.validate()?;
        Ok(manifest)
    }

    fn validate(&self) -> Result<(), DeploymentTrustErrorV2> {
        if [
            self.installation_id.as_bytes(),
            self.active_state_manifest_digest.as_bytes(),
            self.declassification_rule_set_digest.as_bytes(),
            self.protocol_abi_digest.as_bytes(),
            self.release_identity_digest.as_bytes(),
            self.model_set_identity_digest.as_bytes(),
            self.resource_profile_identity_digest.as_bytes(),
            self.approval_lock_identity_digest.as_bytes(),
            self.planner_lock_identity_digest.as_bytes(),
            self.executor_key_lock_identity_digest.as_bytes(),
            self.kernel_envelope_signing_key_id.as_bytes(),
            self.ledger_projection_identity.as_bytes(),
            self.effect_ledger_head_digest.as_bytes(),
            self.ledger_projection_signing_key_id.as_bytes(),
            &self.ledger_projection_signing_public_key,
        ]
        .iter()
        .any(|value| is_zero(*value))
            || self.active_state_manifest_sequence == 0
            || self.deployment_generation == 0
            || self.effect_fence_epoch == 0
            || self.services.len() != REQUIRED_SERVICE_COUNT
            || self.edges.len() != REQUIRED_EDGE_COUNT
        {
            return Err(DeploymentTrustErrorV2::IncompleteManifest);
        }
        let mut seen = BTreeSet::new();
        for (expected, service) in ClosedServiceIdV2::ALL.iter().zip(&self.services) {
            if service.service != *expected
                || !seen.insert(service.service)
                || is_zero(service.service_identity.as_bytes())
                || service.uid == 0
                || service.gid == 0
                || service.socket_uid != service.uid
                || service.socket_gid == 0
                || !matches!(service.socket_mode, 0 | 0o660)
                || (service.socket_mode == 0 && service.socket_gid != service.gid)
                || [
                    service.executable_digest.as_bytes(),
                    service.config_digest.as_bytes(),
                    service.config_path_digest.as_bytes(),
                    service.socket_path_digest.as_bytes(),
                    service.code_identity_digest.as_bytes(),
                    service.sandbox_profile_digest.as_bytes(),
                    service.keystore_authority_identity.as_bytes(),
                    service.rollback_authority_identity.as_bytes(),
                ]
                .iter()
                .any(|value| is_zero(*value))
            {
                return Err(DeploymentTrustErrorV2::IncompleteManifest);
            }
        }
        let mut seen_edges = BTreeSet::new();
        let mut seen_keys = BTreeSet::new();
        for (expected_id, edge) in ClosedServiceEdgeIdV2::ALL.iter().zip(&self.edges) {
            let expected_role_identity =
                BoundedIdentityStringV2::new(expected_id.role_identity().to_owned())
                    .map_err(|_| DeploymentTrustErrorV2::EdgeLockMismatch)?;
            let client_lock = self
                .services
                .iter()
                .find(|service| service.service == expected_id.client_service())
                .ok_or(DeploymentTrustErrorV2::EdgeLockMismatch)?;
            let expected_native_matches = match &edge.expected_client {
                ExpectedNativePeerV2::Linux {
                    role_identity,
                    uid,
                    gid,
                    executable_measurement,
                } => {
                    role_identity == &expected_role_identity
                        && *uid == client_lock.uid
                        && *gid == client_lock.gid
                        && executable_measurement == client_lock.executable_digest.as_bytes()
                }
                ExpectedNativePeerV2::MacOs {
                    role_identity,
                    euid,
                    egid,
                    code_directory_measurement,
                    ..
                } => {
                    role_identity == &expected_role_identity
                        && *euid == client_lock.uid
                        && *egid == client_lock.gid
                        && code_directory_measurement == client_lock.code_identity_digest.as_bytes()
                }
                _ => false,
            };
            if edge.edge_id != *expected_id
                || !seen_edges.insert(edge.edge_id)
                || edge.client_service != expected_id.client_service()
                || edge.server_service != expected_id.server_service()
                || edge.role != expected_id.role()
                || is_zero(edge.listener_identity_digest.as_bytes())
                || is_zero(edge.client_handshake_key_id.as_bytes())
                || is_zero(edge.server_handshake_key_id.as_bytes())
                || edge.client_handshake_key_id == edge.server_handshake_key_id
                || !seen_keys.insert(*edge.client_handshake_key_id.as_bytes())
                || !seen_keys.insert(*edge.server_handshake_key_id.as_bytes())
                || !expected_native_matches
            {
                return Err(DeploymentTrustErrorV2::EdgeLockMismatch);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PlatformServiceObservationV2 {
    pub lock: ServiceDeploymentLockV2,
    pub executable_is_regular_single_link: bool,
    pub config_is_regular_single_link: bool,
    pub executable_parent_root_owned_not_writable: bool,
    pub config_parent_root_owned_not_writable: bool,
    pub endpoint_identity_is_verified: bool,
}

pub struct ServiceAuthorityHandlesV2 {
    pub service: ClosedServiceIdV2,
    pub keystore_authority_identity: Digest32V2,
    pub rollback_authority_identity: Digest32V2,
}

impl std::fmt::Debug for ServiceAuthorityHandlesV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ServiceAuthorityHandlesV2")
            .field("service", &self.service)
            .finish_non_exhaustive()
    }
}

pub trait PlatformDeploymentTrustV2 {
    fn observe_service(
        &mut self,
        service: ClosedServiceIdV2,
    ) -> Result<PlatformServiceObservationV2, DeploymentTrustErrorV2>;

    fn acquire_service_authorities(
        &mut self,
        service: ClosedServiceIdV2,
    ) -> Result<ServiceAuthorityHandlesV2, DeploymentTrustErrorV2>;

    fn read_effect_ledger_projection(&mut self) -> Result<Vec<u8>, DeploymentTrustErrorV2>;
}

pub struct VerifiedDaemonStartupV2 {
    installation_id: Digest32V2,
    active_state_manifest_digest: Digest32V2,
    declassification_rule_set_digest: Digest32V2,
    active_state_manifest_sequence: u64,
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
    effect_ledger_head_digest: Digest32V2,
    effect_ledger_projection_binding: EffectLedgerProjectionBindingV2,
    verified_effect_ledger_projection: savana_kernel_protocol::v2::VerifiedEffectLedgerProjectionV2,
    service_authorities: Vec<ServiceAuthorityHandlesV2>,
    services: Vec<ServiceDeploymentLockV2>,
    edges: Vec<ServiceEdgeLockV2>,
}

impl std::fmt::Debug for VerifiedDaemonStartupV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifiedDaemonStartupV2")
            .field("deployment_generation", &self.deployment_generation)
            .field("effect_fence_epoch", &self.effect_fence_epoch)
            .finish_non_exhaustive()
    }
}

impl VerifiedDaemonStartupV2 {
    pub fn verify(
        manifest: VerifiedDeploymentManifestV2,
        platform: &mut dyn PlatformDeploymentTrustV2,
    ) -> Result<Self, DeploymentTrustErrorV2> {
        let mut service_authorities = Vec::new();
        service_authorities
            .try_reserve_exact(REQUIRED_SERVICE_COUNT)
            .map_err(|_| DeploymentTrustErrorV2::PlatformUnavailable)?;
        for expected in &manifest.services {
            let observed = platform.observe_service(expected.service)?;
            if observed.lock.service != expected.service
                || observed.lock.service_identity != expected.service_identity
                || observed.lock.uid != expected.uid
                || observed.lock.gid != expected.gid
                || observed.lock.executable_digest != expected.executable_digest
                || observed.lock.config_digest != expected.config_digest
                || observed.lock.config_path_digest != expected.config_path_digest
            {
                return Err(DeploymentTrustErrorV2::ServiceMeasurementMismatch);
            }
            if !observed.executable_is_regular_single_link
                || !observed.config_is_regular_single_link
                || !observed.executable_parent_root_owned_not_writable
                || !observed.config_parent_root_owned_not_writable
            {
                return Err(DeploymentTrustErrorV2::UnsafeFilesystem);
            }
            if !observed.endpoint_identity_is_verified
                || observed.lock.socket_path_digest != expected.socket_path_digest
                || observed.lock.socket_uid != expected.socket_uid
                || observed.lock.socket_gid != expected.socket_gid
                || observed.lock.socket_mode != expected.socket_mode
            {
                return Err(DeploymentTrustErrorV2::UnsafeSocket);
            }
            if observed.lock.code_identity_digest != expected.code_identity_digest
                || observed.lock.sandbox_profile_digest != expected.sandbox_profile_digest
            {
                return Err(DeploymentTrustErrorV2::SandboxMismatch);
            }
            let authorities = platform.acquire_service_authorities(expected.service)?;
            if authorities.service != expected.service
                || authorities.keystore_authority_identity != expected.keystore_authority_identity
                || authorities.rollback_authority_identity != expected.rollback_authority_identity
            {
                return Err(DeploymentTrustErrorV2::MissingPlatformAuthority);
            }
            service_authorities.push(authorities);
        }
        let projection_binding = EffectLedgerProjectionBindingV2::from_verified_deployment(
            manifest.installation_id,
            manifest.active_state_manifest_digest,
            manifest.deployment_generation,
            manifest.effect_fence_epoch,
            manifest.ledger_projection_identity,
            manifest.effect_ledger_head_digest,
            manifest.ledger_projection_signing_key_id,
            manifest.ledger_projection_signing_public_key,
        )
        .map_err(|_| DeploymentTrustErrorV2::EffectLedgerMismatch)?;
        let projection_bytes = platform.read_effect_ledger_projection()?;
        let projection = verify_effect_ledger_projection_v2(&projection_bytes, projection_binding)
            .map_err(|_| DeploymentTrustErrorV2::EffectLedgerMismatch)?;
        Ok(Self {
            installation_id: manifest.installation_id,
            active_state_manifest_digest: manifest.active_state_manifest_digest,
            declassification_rule_set_digest: manifest.declassification_rule_set_digest,
            active_state_manifest_sequence: manifest.active_state_manifest_sequence,
            deployment_generation: manifest.deployment_generation,
            effect_fence_epoch: manifest.effect_fence_epoch,
            protocol_abi_digest: manifest.protocol_abi_digest,
            release_identity_digest: manifest.release_identity_digest,
            model_set_identity_digest: manifest.model_set_identity_digest,
            resource_profile_identity_digest: manifest.resource_profile_identity_digest,
            approval_lock_identity_digest: manifest.approval_lock_identity_digest,
            planner_lock_identity_digest: manifest.planner_lock_identity_digest,
            executor_key_lock_identity_digest: manifest.executor_key_lock_identity_digest,
            kernel_envelope_signing_key_id: manifest.kernel_envelope_signing_key_id,
            effect_ledger_head_digest: projection.authenticated_head_digest(),
            effect_ledger_projection_binding: projection_binding,
            verified_effect_ledger_projection: projection,
            service_authorities,
            services: manifest.services,
            edges: manifest.edges,
        })
    }

    pub const fn effect_ledger_projection_binding(&self) -> EffectLedgerProjectionBindingV2 {
        self.effect_ledger_projection_binding
    }

    /// Binds the exact bootstrap bytes already parsed by a daemon to the
    /// config measurement in the signed deployment manifest. This closes the
    /// interval between the daemon's bounded read and the platform observer's
    /// independent file measurement.
    pub fn verify_loaded_service_config_v2(
        &self,
        service: ClosedServiceIdV2,
        loaded_config: &[u8],
    ) -> Result<(), DeploymentTrustErrorV2> {
        if loaded_config.is_empty() {
            return Err(DeploymentTrustErrorV2::ServiceMeasurementMismatch);
        }
        let expected = self
            .services
            .iter()
            .find(|candidate| candidate.service == service)
            .ok_or(DeploymentTrustErrorV2::ServiceMeasurementMismatch)?;
        let observed = Digest32V2::new(Sha256::digest(loaded_config).into());
        if observed != expected.config_digest {
            return Err(DeploymentTrustErrorV2::ServiceMeasurementMismatch);
        }
        Ok(())
    }

    pub const fn verified_effect_ledger_projection(
        &self,
    ) -> savana_kernel_protocol::v2::VerifiedEffectLedgerProjectionV2 {
        self.verified_effect_ledger_projection
    }

    pub const fn installation_id(&self) -> Digest32V2 {
        self.installation_id
    }

    pub const fn active_state_manifest_sequence(&self) -> u64 {
        self.active_state_manifest_sequence
    }

    pub const fn active_state_manifest_digest(&self) -> Digest32V2 {
        self.active_state_manifest_digest
    }

    pub const fn declassification_rule_set_digest(&self) -> Digest32V2 {
        self.declassification_rule_set_digest
    }

    pub const fn deployment_generation(&self) -> u64 {
        self.deployment_generation
    }

    pub const fn effect_fence_epoch(&self) -> u64 {
        self.effect_fence_epoch
    }

    pub const fn effect_ledger_head_digest(&self) -> Digest32V2 {
        self.effect_ledger_head_digest
    }

    pub const fn protocol_abi_digest(&self) -> Digest32V2 {
        self.protocol_abi_digest
    }

    pub const fn kernel_envelope_signing_key_id(&self) -> Ed25519KeyIdV2 {
        self.kernel_envelope_signing_key_id
    }

    pub const fn executor_key_lock_identity_digest(&self) -> Digest32V2 {
        self.executor_key_lock_identity_digest
    }

    pub fn kernel_service_handshake_edge(
        &self,
        edge: ClosedServiceEdgeIdV2,
        server_boot_id: BootIdV2,
    ) -> Result<KernelServiceHandshakeEdgeV2, DeploymentTrustErrorV2> {
        let lock = self
            .edge_lock(edge)
            .ok_or(DeploymentTrustErrorV2::EdgeLockMismatch)?;
        let client_identity = self
            .service_identity(edge.client_service())
            .ok_or(DeploymentTrustErrorV2::EdgeLockMismatch)?;
        let server_identity = self
            .service_identity(edge.server_service())
            .ok_or(DeploymentTrustErrorV2::EdgeLockMismatch)?;
        KernelServiceHandshakeEdgeV2::from_verified_deployment(
            lock.role,
            self.installation_id,
            client_identity,
            server_identity,
            lock.client_handshake_key_id,
            lock.server_handshake_key_id,
            server_boot_id,
            self.active_state_manifest_sequence,
            self.active_state_manifest_digest,
            self.deployment_generation,
            self.effect_fence_epoch,
            self.release_identity_digest,
            self.model_set_identity_digest,
            self.resource_profile_identity_digest,
            self.approval_lock_identity_digest,
            self.planner_lock_identity_digest,
            self.executor_key_lock_identity_digest,
        )
        .map_err(|_| DeploymentTrustErrorV2::EdgeLockMismatch)
    }

    pub fn approval_service_handshake_edge(
        &self,
        role: EndpointRoleV2,
        client_handshake_key_id: Ed25519KeyIdV2,
        server_handshake_key_id: Ed25519KeyIdV2,
        approvald_boot_id: BootIdV2,
    ) -> Result<KernelServiceHandshakeEdgeV2, DeploymentTrustErrorV2> {
        let client_service = match role {
            EndpointRoleV2::AgentApproval => ClosedServiceIdV2::Agentd,
            EndpointRoleV2::IngressApproval => ClosedServiceIdV2::Ingressd,
            _ => return Err(DeploymentTrustErrorV2::EdgeLockMismatch),
        };
        let client_identity = self
            .service_identity(client_service)
            .ok_or(DeploymentTrustErrorV2::EdgeLockMismatch)?;
        let server_identity = self
            .service_identity(ClosedServiceIdV2::Approvald)
            .ok_or(DeploymentTrustErrorV2::EdgeLockMismatch)?;
        KernelServiceHandshakeEdgeV2::from_verified_deployment(
            role,
            self.installation_id,
            client_identity,
            server_identity,
            client_handshake_key_id,
            server_handshake_key_id,
            approvald_boot_id,
            self.active_state_manifest_sequence,
            self.active_state_manifest_digest,
            self.deployment_generation,
            self.effect_fence_epoch,
            self.release_identity_digest,
            self.model_set_identity_digest,
            self.resource_profile_identity_digest,
            self.approval_lock_identity_digest,
            self.planner_lock_identity_digest,
            self.executor_key_lock_identity_digest,
        )
        .map_err(|_| DeploymentTrustErrorV2::EdgeLockMismatch)
    }

    pub fn approval_admin_handshake_edge(
        &self,
        client_identity: ServiceIdentityV2,
        client_handshake_key_id: Ed25519KeyIdV2,
        server_handshake_key_id: Ed25519KeyIdV2,
        approvald_boot_id: BootIdV2,
    ) -> Result<KernelServiceHandshakeEdgeV2, DeploymentTrustErrorV2> {
        if client_identity.as_bytes() == &[0; 32] {
            return Err(DeploymentTrustErrorV2::EdgeLockMismatch);
        }
        let server_identity = self
            .service_identity(ClosedServiceIdV2::Approvald)
            .ok_or(DeploymentTrustErrorV2::EdgeLockMismatch)?;
        KernelServiceHandshakeEdgeV2::from_verified_deployment(
            EndpointRoleV2::ApprovalAdmin,
            self.installation_id,
            client_identity,
            server_identity,
            client_handshake_key_id,
            server_handshake_key_id,
            approvald_boot_id,
            self.active_state_manifest_sequence,
            self.active_state_manifest_digest,
            self.deployment_generation,
            self.effect_fence_epoch,
            self.release_identity_digest,
            self.model_set_identity_digest,
            self.resource_profile_identity_digest,
            self.approval_lock_identity_digest,
            self.planner_lock_identity_digest,
            self.executor_key_lock_identity_digest,
        )
        .map_err(|_| DeploymentTrustErrorV2::EdgeLockMismatch)
    }

    pub fn service_identity(&self, service: ClosedServiceIdV2) -> Option<ServiceIdentityV2> {
        self.services
            .iter()
            .find(|lock| lock.service == service)
            .map(|lock| lock.service_identity)
    }

    pub fn service_lock(&self, service: ClosedServiceIdV2) -> Option<&ServiceDeploymentLockV2> {
        self.services.iter().find(|lock| lock.service == service)
    }

    pub fn service_authority_identities(
        &self,
        service: ClosedServiceIdV2,
    ) -> Option<(Digest32V2, Digest32V2)> {
        self.service_authorities
            .iter()
            .find(|authority| authority.service == service)
            .map(|authority| {
                (
                    authority.keystore_authority_identity,
                    authority.rollback_authority_identity,
                )
            })
    }

    pub fn edge_lock(&self, edge: ClosedServiceEdgeIdV2) -> Option<&ServiceEdgeLockV2> {
        self.edges.iter().find(|lock| lock.edge_id == edge)
    }
}

fn decode_manifest_payload(
    bytes: &[u8],
) -> Result<VerifiedDeploymentManifestV2, DeploymentTrustErrorV2> {
    let mut decoder = minicbor::Decoder::new(bytes);
    require_array(&mut decoder, 21)?;
    if decoder
        .u16()
        .map_err(|_| DeploymentTrustErrorV2::NonCanonicalManifest)?
        != 2
    {
        return Err(DeploymentTrustErrorV2::NonCanonicalManifest);
    }
    let installation_id = Digest32V2::new(decode_fixed::<32>(&mut decoder)?);
    let active_state_manifest_digest = Digest32V2::new(decode_fixed::<32>(&mut decoder)?);
    let declassification_rule_set_digest = Digest32V2::new(decode_fixed::<32>(&mut decoder)?);
    let active_state_manifest_sequence = decoder
        .u64()
        .map_err(|_| DeploymentTrustErrorV2::NonCanonicalManifest)?;
    let deployment_generation = decoder
        .u64()
        .map_err(|_| DeploymentTrustErrorV2::NonCanonicalManifest)?;
    let effect_fence_epoch = decoder
        .u64()
        .map_err(|_| DeploymentTrustErrorV2::NonCanonicalManifest)?;
    let protocol_abi_digest = Digest32V2::new(decode_fixed::<32>(&mut decoder)?);
    let release_identity_digest = Digest32V2::new(decode_fixed::<32>(&mut decoder)?);
    let model_set_identity_digest = Digest32V2::new(decode_fixed::<32>(&mut decoder)?);
    let resource_profile_identity_digest = Digest32V2::new(decode_fixed::<32>(&mut decoder)?);
    let approval_lock_identity_digest = Digest32V2::new(decode_fixed::<32>(&mut decoder)?);
    let planner_lock_identity_digest = Digest32V2::new(decode_fixed::<32>(&mut decoder)?);
    let executor_key_lock_identity_digest = Digest32V2::new(decode_fixed::<32>(&mut decoder)?);
    let kernel_envelope_signing_key_id = Ed25519KeyIdV2::new(decode_fixed::<32>(&mut decoder)?);
    let ledger_projection_identity = Digest32V2::new(decode_fixed::<32>(&mut decoder)?);
    let effect_ledger_head_digest = Digest32V2::new(decode_fixed::<32>(&mut decoder)?);
    let ledger_projection_signing_key_id = Ed25519KeyIdV2::new(decode_fixed::<32>(&mut decoder)?);
    let ledger_projection_signing_public_key = decode_fixed::<32>(&mut decoder)?;
    let count = decoder
        .array()
        .map_err(|_| DeploymentTrustErrorV2::NonCanonicalManifest)?
        .ok_or(DeploymentTrustErrorV2::NonCanonicalManifest)?;
    if count as usize != REQUIRED_SERVICE_COUNT {
        return Err(DeploymentTrustErrorV2::IncompleteManifest);
    }
    let mut services = Vec::new();
    services
        .try_reserve_exact(REQUIRED_SERVICE_COUNT)
        .map_err(|_| DeploymentTrustErrorV2::IncompleteManifest)?;
    for _ in 0..count {
        services.push(decode_service_lock(&mut decoder)?);
    }
    let edge_count = decoder
        .array()
        .map_err(|_| DeploymentTrustErrorV2::NonCanonicalManifest)?
        .ok_or(DeploymentTrustErrorV2::NonCanonicalManifest)?;
    if edge_count as usize != REQUIRED_EDGE_COUNT {
        return Err(DeploymentTrustErrorV2::EdgeLockMismatch);
    }
    let mut edges = Vec::new();
    edges
        .try_reserve_exact(REQUIRED_EDGE_COUNT)
        .map_err(|_| DeploymentTrustErrorV2::EdgeLockMismatch)?;
    for _ in 0..edge_count {
        edges.push(decode_edge_lock(&mut decoder)?);
    }
    if decoder.position() != bytes.len() {
        return Err(DeploymentTrustErrorV2::NonCanonicalManifest);
    }
    Ok(VerifiedDeploymentManifestV2 {
        installation_id,
        active_state_manifest_digest,
        declassification_rule_set_digest,
        active_state_manifest_sequence,
        deployment_generation,
        effect_fence_epoch,
        protocol_abi_digest,
        release_identity_digest,
        model_set_identity_digest,
        resource_profile_identity_digest,
        approval_lock_identity_digest,
        planner_lock_identity_digest,
        executor_key_lock_identity_digest,
        kernel_envelope_signing_key_id,
        ledger_projection_identity,
        effect_ledger_head_digest,
        ledger_projection_signing_key_id,
        ledger_projection_signing_public_key,
        services,
        edges,
    })
}

fn decode_service_lock(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<ServiceDeploymentLockV2, DeploymentTrustErrorV2> {
    require_array(decoder, 15)?;
    Ok(ServiceDeploymentLockV2 {
        service: ClosedServiceIdV2::from_tag(
            decoder
                .u16()
                .map_err(|_| DeploymentTrustErrorV2::NonCanonicalManifest)?,
        )?,
        service_identity: ServiceIdentityV2::new(decode_fixed::<32>(decoder)?),
        uid: decoder
            .u32()
            .map_err(|_| DeploymentTrustErrorV2::NonCanonicalManifest)?,
        gid: decoder
            .u32()
            .map_err(|_| DeploymentTrustErrorV2::NonCanonicalManifest)?,
        executable_digest: Digest32V2::new(decode_fixed::<32>(decoder)?),
        config_digest: Digest32V2::new(decode_fixed::<32>(decoder)?),
        config_path_digest: Digest32V2::new(decode_fixed::<32>(decoder)?),
        socket_path_digest: Digest32V2::new(decode_fixed::<32>(decoder)?),
        socket_uid: decoder
            .u32()
            .map_err(|_| DeploymentTrustErrorV2::NonCanonicalManifest)?,
        socket_gid: decoder
            .u32()
            .map_err(|_| DeploymentTrustErrorV2::NonCanonicalManifest)?,
        socket_mode: decoder
            .u32()
            .map_err(|_| DeploymentTrustErrorV2::NonCanonicalManifest)?,
        code_identity_digest: Digest32V2::new(decode_fixed::<32>(decoder)?),
        sandbox_profile_digest: Digest32V2::new(decode_fixed::<32>(decoder)?),
        keystore_authority_identity: Digest32V2::new(decode_fixed::<32>(decoder)?),
        rollback_authority_identity: Digest32V2::new(decode_fixed::<32>(decoder)?),
    })
}

fn decode_edge_lock(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<ServiceEdgeLockV2, DeploymentTrustErrorV2> {
    require_array(decoder, 8)?;
    let edge_id = ClosedServiceEdgeIdV2::from_tag(
        decoder
            .u16()
            .map_err(|_| DeploymentTrustErrorV2::NonCanonicalManifest)?,
    )?;
    let client_service = ClosedServiceIdV2::from_tag(
        decoder
            .u16()
            .map_err(|_| DeploymentTrustErrorV2::NonCanonicalManifest)?,
    )?;
    let server_service = ClosedServiceIdV2::from_tag(
        decoder
            .u16()
            .map_err(|_| DeploymentTrustErrorV2::NonCanonicalManifest)?,
    )?;
    let role = decode_endpoint_role(decoder)?;
    Ok(ServiceEdgeLockV2 {
        edge_id,
        client_service,
        server_service,
        role,
        listener_identity_digest: Digest32V2::new(decode_fixed::<32>(decoder)?),
        client_handshake_key_id: Ed25519KeyIdV2::new(decode_fixed::<32>(decoder)?),
        server_handshake_key_id: Ed25519KeyIdV2::new(decode_fixed::<32>(decoder)?),
        expected_client: decode_expected_native_peer(decoder)?,
    })
}

fn encode_manifest_payload(
    manifest: &VerifiedDeploymentManifestV2,
) -> Result<Vec<u8>, DeploymentTrustErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(21)
        .and_then(|encoder| encoder.u16(2))
        .and_then(|encoder| encoder.bytes(manifest.installation_id.as_bytes()))
        .and_then(|encoder| encoder.bytes(manifest.active_state_manifest_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(manifest.declassification_rule_set_digest.as_bytes()))
        .and_then(|encoder| encoder.u64(manifest.active_state_manifest_sequence))
        .and_then(|encoder| encoder.u64(manifest.deployment_generation))
        .and_then(|encoder| encoder.u64(manifest.effect_fence_epoch))
        .and_then(|encoder| encoder.bytes(manifest.protocol_abi_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(manifest.release_identity_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(manifest.model_set_identity_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(manifest.resource_profile_identity_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(manifest.approval_lock_identity_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(manifest.planner_lock_identity_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(manifest.executor_key_lock_identity_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(manifest.kernel_envelope_signing_key_id.as_bytes()))
        .and_then(|encoder| encoder.bytes(manifest.ledger_projection_identity.as_bytes()))
        .and_then(|encoder| encoder.bytes(manifest.effect_ledger_head_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(manifest.ledger_projection_signing_key_id.as_bytes()))
        .and_then(|encoder| encoder.bytes(&manifest.ledger_projection_signing_public_key))
        .and_then(|encoder| encoder.array(manifest.services.len() as u64))
        .map_err(|_| DeploymentTrustErrorV2::IncompleteManifest)?;
    for service in &manifest.services {
        encode_service_lock(&mut encoder, *service)?;
    }
    encoder
        .array(manifest.edges.len() as u64)
        .map_err(|_| DeploymentTrustErrorV2::IncompleteManifest)?;
    for edge in &manifest.edges {
        encode_edge_lock(&mut encoder, edge)?;
    }
    Ok(encoder.into_writer())
}

fn encode_service_lock(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    service: ServiceDeploymentLockV2,
) -> Result<(), DeploymentTrustErrorV2> {
    encoder
        .array(15)
        .and_then(|encoder| encoder.u16(service.service.tag()))
        .and_then(|encoder| encoder.bytes(service.service_identity.as_bytes()))
        .and_then(|encoder| encoder.u32(service.uid))
        .and_then(|encoder| encoder.u32(service.gid))
        .and_then(|encoder| encoder.bytes(service.executable_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(service.config_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(service.config_path_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(service.socket_path_digest.as_bytes()))
        .and_then(|encoder| encoder.u32(service.socket_uid))
        .and_then(|encoder| encoder.u32(service.socket_gid))
        .and_then(|encoder| encoder.u32(service.socket_mode))
        .and_then(|encoder| encoder.bytes(service.code_identity_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(service.sandbox_profile_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(service.keystore_authority_identity.as_bytes()))
        .and_then(|encoder| encoder.bytes(service.rollback_authority_identity.as_bytes()))
        .map_err(|_| DeploymentTrustErrorV2::IncompleteManifest)?;
    Ok(())
}

fn encode_edge_lock(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    edge: &ServiceEdgeLockV2,
) -> Result<(), DeploymentTrustErrorV2> {
    encoder
        .array(8)
        .and_then(|encoder| encoder.u16(edge.edge_id.tag()))
        .and_then(|encoder| encoder.u16(edge.client_service.tag()))
        .and_then(|encoder| encoder.u16(edge.server_service.tag()))
        .and_then(|encoder| encoder.u16(edge.role.tag()))
        .and_then(|encoder| encoder.bytes(edge.listener_identity_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(edge.client_handshake_key_id.as_bytes()))
        .and_then(|encoder| encoder.bytes(edge.server_handshake_key_id.as_bytes()))
        .map_err(|_| DeploymentTrustErrorV2::IncompleteManifest)?;
    encode_expected_native_peer(encoder, &edge.expected_client)
}

fn encode_expected_native_peer(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    expected: &ExpectedNativePeerV2,
) -> Result<(), DeploymentTrustErrorV2> {
    match expected {
        ExpectedNativePeerV2::Linux {
            role_identity,
            uid,
            gid,
            executable_measurement,
        } => {
            encoder
                .array(5)
                .and_then(|encoder| encoder.u16(1))
                .and_then(|encoder| encoder.str(role_identity.as_str()))
                .and_then(|encoder| encoder.u32(*uid))
                .and_then(|encoder| encoder.u32(*gid))
                .and_then(|encoder| encoder.bytes(executable_measurement))
                .map_err(|_| DeploymentTrustErrorV2::IncompleteManifest)?;
        }
        ExpectedNativePeerV2::MacOs {
            role_identity,
            euid,
            egid,
            bundle_id,
            team_id,
            code_directory_measurement,
            designated_requirement_measurement,
            entitlement_measurement,
        } => {
            encoder
                .array(9)
                .and_then(|encoder| encoder.u16(2))
                .and_then(|encoder| encoder.str(role_identity.as_str()))
                .and_then(|encoder| encoder.u32(*euid))
                .and_then(|encoder| encoder.u32(*egid))
                .and_then(|encoder| encoder.str(bundle_id.as_str()))
                .and_then(|encoder| encoder.str(team_id.as_str()))
                .and_then(|encoder| encoder.bytes(code_directory_measurement))
                .and_then(|encoder| encoder.bytes(designated_requirement_measurement))
                .and_then(|encoder| encoder.bytes(entitlement_measurement))
                .map_err(|_| DeploymentTrustErrorV2::IncompleteManifest)?;
        }
        _ => return Err(DeploymentTrustErrorV2::IncompleteManifest),
    }
    Ok(())
}

fn decode_expected_native_peer(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<ExpectedNativePeerV2, DeploymentTrustErrorV2> {
    let count = decoder
        .array()
        .map_err(|_| DeploymentTrustErrorV2::NonCanonicalManifest)?
        .ok_or(DeploymentTrustErrorV2::NonCanonicalManifest)?;
    let tag = decoder
        .u16()
        .map_err(|_| DeploymentTrustErrorV2::NonCanonicalManifest)?;
    let bounded = |value: &str| {
        BoundedIdentityStringV2::new(value.to_owned())
            .map_err(|_| DeploymentTrustErrorV2::EdgeLockMismatch)
    };
    match (count, tag) {
        (5, 1) => ExpectedNativePeerV2::linux(
            bounded(
                decoder
                    .str()
                    .map_err(|_| DeploymentTrustErrorV2::NonCanonicalManifest)?,
            )?,
            decoder
                .u32()
                .map_err(|_| DeploymentTrustErrorV2::NonCanonicalManifest)?,
            decoder
                .u32()
                .map_err(|_| DeploymentTrustErrorV2::NonCanonicalManifest)?,
            decode_fixed::<32>(decoder)?,
        )
        .map_err(|_| DeploymentTrustErrorV2::EdgeLockMismatch),
        (9, 2) => ExpectedNativePeerV2::macos(
            bounded(
                decoder
                    .str()
                    .map_err(|_| DeploymentTrustErrorV2::NonCanonicalManifest)?,
            )?,
            decoder
                .u32()
                .map_err(|_| DeploymentTrustErrorV2::NonCanonicalManifest)?,
            decoder
                .u32()
                .map_err(|_| DeploymentTrustErrorV2::NonCanonicalManifest)?,
            bounded(
                decoder
                    .str()
                    .map_err(|_| DeploymentTrustErrorV2::NonCanonicalManifest)?,
            )?,
            bounded(
                decoder
                    .str()
                    .map_err(|_| DeploymentTrustErrorV2::NonCanonicalManifest)?,
            )?,
            decode_fixed::<32>(decoder)?,
            decode_fixed::<32>(decoder)?,
            decode_fixed::<32>(decoder)?,
        )
        .map_err(|_| DeploymentTrustErrorV2::EdgeLockMismatch),
        _ => Err(DeploymentTrustErrorV2::NonCanonicalManifest),
    }
}

fn decode_endpoint_role(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<EndpointRoleV2, DeploymentTrustErrorV2> {
    match decoder
        .u16()
        .map_err(|_| DeploymentTrustErrorV2::NonCanonicalManifest)?
    {
        2 => Ok(EndpointRoleV2::AgentKernel),
        3 => Ok(EndpointRoleV2::IngressKernel),
        4 => Ok(EndpointRoleV2::KernelExecutor),
        _ => Err(DeploymentTrustErrorV2::EdgeLockMismatch),
    }
}

fn encode_signed_manifest(
    payload: &[u8],
    key_id: Ed25519KeyIdV2,
    signature: &[u8; 64],
) -> Result<Vec<u8>, DeploymentTrustErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(3)
        .and_then(|encoder| encoder.bytes(payload))
        .and_then(|encoder| encoder.bytes(key_id.as_bytes()))
        .and_then(|encoder| encoder.bytes(signature))
        .map_err(|_| DeploymentTrustErrorV2::IncompleteManifest)?;
    Ok(encoder.into_writer())
}

fn require_array(
    decoder: &mut minicbor::Decoder<'_>,
    expected: u64,
) -> Result<(), DeploymentTrustErrorV2> {
    if decoder
        .array()
        .map_err(|_| DeploymentTrustErrorV2::NonCanonicalManifest)?
        != Some(expected)
    {
        return Err(DeploymentTrustErrorV2::NonCanonicalManifest);
    }
    Ok(())
}

fn decode_fixed<const N: usize>(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<[u8; N], DeploymentTrustErrorV2> {
    decoder
        .bytes()
        .map_err(|_| DeploymentTrustErrorV2::NonCanonicalManifest)?
        .try_into()
        .map_err(|_| DeploymentTrustErrorV2::NonCanonicalManifest)
}

fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

pub fn listener_identity_digest_v2(
    role: EndpointRoleV2,
    path: &std::path::Path,
    uid: u32,
    gid: u32,
    mode: u32,
) -> Result<Digest32V2, DeploymentTrustErrorV2> {
    use std::os::unix::ffi::OsStrExt as _;

    let path = path.as_os_str().as_bytes();
    if !matches!(
        role,
        EndpointRoleV2::AgentKernel
            | EndpointRoleV2::IngressKernel
            | EndpointRoleV2::KernelExecutor
    ) || path.is_empty()
        || path.len() > MAX_SOCKET_PATH_BYTES_V2
        || path.contains(&0)
        || mode != 0o660
    {
        return Err(DeploymentTrustErrorV2::UnsafeSocket);
    }
    let path_length =
        u32::try_from(path.len()).map_err(|_| DeploymentTrustErrorV2::UnsafeSocket)?;
    let mut hasher = Sha256::new();
    hasher.update(LISTENER_IDENTITY_DOMAIN_V2);
    hasher.update(role.tag().to_be_bytes());
    hasher.update(path_length.to_be_bytes());
    hasher.update(path);
    hasher.update(uid.to_be_bytes());
    hasher.update(gid.to_be_bytes());
    hasher.update(mode.to_be_bytes());
    Ok(Digest32V2::new(hasher.finalize().into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};

    struct FakePlatform {
        observations: Vec<PlatformServiceObservationV2>,
        authorities: Vec<ServiceAuthorityHandlesV2>,
        projection: Vec<u8>,
    }

    impl PlatformDeploymentTrustV2 for FakePlatform {
        fn observe_service(
            &mut self,
            service: ClosedServiceIdV2,
        ) -> Result<PlatformServiceObservationV2, DeploymentTrustErrorV2> {
            self.observations
                .iter()
                .copied()
                .find(|value| value.lock.service == service)
                .ok_or(DeploymentTrustErrorV2::PlatformUnavailable)
        }

        fn acquire_service_authorities(
            &mut self,
            service: ClosedServiceIdV2,
        ) -> Result<ServiceAuthorityHandlesV2, DeploymentTrustErrorV2> {
            let index = self
                .authorities
                .iter()
                .position(|value| value.service == service)
                .ok_or(DeploymentTrustErrorV2::PlatformUnavailable)?;
            Ok(self.authorities.remove(index))
        }

        fn read_effect_ledger_projection(&mut self) -> Result<Vec<u8>, DeploymentTrustErrorV2> {
            Ok(self.projection.clone())
        }
    }

    fn service_lock(service: ClosedServiceIdV2) -> ServiceDeploymentLockV2 {
        let seed = service.tag() as u8;
        ServiceDeploymentLockV2 {
            service,
            service_identity: ServiceIdentityV2::new([seed + 80; 32]),
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
    }

    fn edge_lock(edge_id: ClosedServiceEdgeIdV2) -> ServiceEdgeLockV2 {
        let seed = edge_id.tag() as u8;
        let client = service_lock(edge_id.client_service());
        ServiceEdgeLockV2 {
            edge_id,
            client_service: edge_id.client_service(),
            server_service: edge_id.server_service(),
            role: edge_id.role(),
            listener_identity_digest: Digest32V2::new([0xa0 + seed; 32]),
            client_handshake_key_id: Ed25519KeyIdV2::new([0xb0 + seed * 2; 32]),
            server_handshake_key_id: Ed25519KeyIdV2::new([0xb1 + seed * 2; 32]),
            expected_client: ExpectedNativePeerV2::linux(
                BoundedIdentityStringV2::new(edge_id.role_identity().to_owned()).unwrap(),
                client.uid,
                client.gid,
                *client.executable_digest.as_bytes(),
            )
            .unwrap(),
        }
    }

    fn unsigned_manifest() -> VerifiedDeploymentManifestV2 {
        let projection_key = SigningKey::from_bytes(&[0x98; 32]);
        VerifiedDeploymentManifestV2 {
            installation_id: Digest32V2::new([0x91; 32]),
            active_state_manifest_digest: Digest32V2::new([0x92; 32]),
            declassification_rule_set_digest: Digest32V2::new([0x90; 32]),
            active_state_manifest_sequence: 6,
            deployment_generation: 7,
            effect_fence_epoch: 8,
            protocol_abi_digest: Digest32V2::new([0x93; 32]),
            release_identity_digest: Digest32V2::new([0x81; 32]),
            model_set_identity_digest: Digest32V2::new([0x82; 32]),
            resource_profile_identity_digest: Digest32V2::new([0x83; 32]),
            approval_lock_identity_digest: Digest32V2::new([0x84; 32]),
            planner_lock_identity_digest: Digest32V2::new([0x85; 32]),
            executor_key_lock_identity_digest: Digest32V2::new([0x86; 32]),
            kernel_envelope_signing_key_id: Ed25519KeyIdV2::new([0x87; 32]),
            ledger_projection_identity: Digest32V2::new([0x94; 32]),
            effect_ledger_head_digest: Digest32V2::new([0x97; 32]),
            ledger_projection_signing_key_id: Ed25519KeyIdV2::new([0x99; 32]),
            ledger_projection_signing_public_key: projection_key.verifying_key().to_bytes(),
            services: ClosedServiceIdV2::ALL
                .iter()
                .copied()
                .map(service_lock)
                .collect(),
            edges: ClosedServiceEdgeIdV2::ALL
                .iter()
                .copied()
                .map(edge_lock)
                .collect(),
        }
    }

    fn signed_manifest() -> (Vec<u8>, Ed25519KeyIdV2, [u8; 32]) {
        let manifest = unsigned_manifest();
        let payload = encode_manifest_payload(&manifest).unwrap();
        let key = SigningKey::from_bytes(&[0x95; 32]);
        let key_id = Ed25519KeyIdV2::new([0x96; 32]);
        let digest: [u8; 32] = Sha256::digest(&payload).into();
        let mut input = Vec::from(MANIFEST_SIGNATURE_DOMAIN);
        input.extend_from_slice(&digest);
        let signature = key.sign(&input).to_bytes();
        (
            encode_signed_manifest(&payload, key_id, &signature).unwrap(),
            key_id,
            key.verifying_key().to_bytes(),
        )
    }

    fn platform(manifest: &VerifiedDeploymentManifestV2) -> FakePlatform {
        FakePlatform {
            observations: manifest
                .services
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
                .collect(),
            authorities: manifest
                .services
                .iter()
                .map(|lock| ServiceAuthorityHandlesV2 {
                    service: lock.service,
                    keystore_authority_identity: lock.keystore_authority_identity,
                    rollback_authority_identity: lock.rollback_authority_identity,
                })
                .collect(),
            projection: signed_projection(manifest, manifest.effect_fence_epoch, false),
        }
    }

    fn signed_projection(
        manifest: &VerifiedDeploymentManifestV2,
        fence_epoch: u64,
        effects_fenced: bool,
    ) -> Vec<u8> {
        const DOMAIN: &[u8] = b"SAVANA_EFFECT_LEDGER_PROJECTION_SIGNATURE_V2\0";
        let key = SigningKey::from_bytes(&[0x98; 32]);
        let mut payload = minicbor::Encoder::new(Vec::new());
        payload
            .array(11)
            .unwrap()
            .u16(2)
            .unwrap()
            .bytes(manifest.installation_id.as_bytes())
            .unwrap()
            .bytes(manifest.active_state_manifest_digest.as_bytes())
            .unwrap()
            .u64(manifest.deployment_generation)
            .unwrap()
            .u64(fence_epoch)
            .unwrap()
            .bytes(manifest.ledger_projection_identity.as_bytes())
            .unwrap()
            .bytes(manifest.effect_ledger_head_digest.as_bytes())
            .unwrap()
            .bool(effects_fenced)
            .unwrap()
            .bool(true)
            .unwrap()
            .bytes(&[0x9a; 32])
            .unwrap()
            .bytes(&[0; 32])
            .unwrap();
        let payload = payload.into_writer();
        let digest: [u8; 32] = Sha256::digest(&payload).into();
        let mut input = Vec::from(DOMAIN);
        input.extend_from_slice(&digest);
        let signature = key.sign(&input).to_bytes();
        let mut outer = minicbor::Encoder::new(Vec::new());
        outer
            .array(3)
            .unwrap()
            .bytes(&payload)
            .unwrap()
            .bytes(manifest.ledger_projection_signing_key_id.as_bytes())
            .unwrap()
            .bytes(&signature)
            .unwrap();
        outer.into_writer()
    }

    fn fixture() -> (VerifiedDeploymentManifestV2, FakePlatform) {
        let (signed, key_id, public_key) = signed_manifest();
        let manifest = VerifiedDeploymentManifestV2::verify(&signed, key_id, public_key).unwrap();
        let platform = platform(&manifest);
        (manifest, platform)
    }

    #[test]
    fn complete_signed_deployment_measurement_constructs_startup_authority_once() {
        let (manifest, mut platform) = fixture();
        let startup = VerifiedDaemonStartupV2::verify(manifest, &mut platform).unwrap();
        assert_eq!(startup.deployment_generation, 7);
        assert_eq!(startup.effect_fence_epoch, 8);
        assert_eq!(startup.service_authorities.len(), REQUIRED_SERVICE_COUNT);
    }

    #[test]
    fn service_lock_accepts_role_specific_socket_groups_and_loopback_tcp() {
        let mut manifest = unsigned_manifest();
        manifest.services[0].socket_gid = 9_001;
        manifest.services[1].socket_gid = 9_002;
        manifest.services[2].socket_uid = manifest.services[2].uid;
        manifest.services[2].socket_gid = manifest.services[2].gid;
        manifest.services[2].socket_mode = 0;
        assert_eq!(manifest.validate(), Ok(()));
    }

    #[test]
    fn verified_startup_is_the_only_source_of_complete_handshake_edge_locks() {
        let (manifest, mut platform) = fixture();
        let startup = VerifiedDaemonStartupV2::verify(manifest, &mut platform).unwrap();
        let edge = startup
            .kernel_service_handshake_edge(
                ClosedServiceEdgeIdV2::AgentKernel,
                savana_kernel_protocol::v2::BootIdV2::new([0x71; 32]),
            )
            .unwrap();
        assert_eq!(edge.role(), EndpointRoleV2::AgentKernel);

        let mut manifest = unsigned_manifest();
        manifest.release_identity_digest = Digest32V2::new([0; 32]);
        assert_eq!(
            manifest.validate(),
            Err(DeploymentTrustErrorV2::IncompleteManifest)
        );
    }

    #[test]
    fn parsed_bootstrap_bytes_must_equal_the_manifest_bound_config_measurement() {
        let loaded = b"{\"policy\":\"manifest-bound\"}";
        let (mut manifest, mut platform) = fixture();
        let digest = Digest32V2::new(Sha256::digest(loaded).into());
        manifest.services[0].config_digest = digest;
        platform.observations[0].lock.config_digest = digest;
        let startup = VerifiedDaemonStartupV2::verify(manifest, &mut platform).unwrap();

        assert_eq!(
            startup.verify_loaded_service_config_v2(ClosedServiceIdV2::Kerneld, loaded),
            Ok(())
        );
        assert_eq!(
            startup.verify_loaded_service_config_v2(ClosedServiceIdV2::Kerneld, b"{\"policy\":0}"),
            Err(DeploymentTrustErrorV2::ServiceMeasurementMismatch)
        );
    }

    #[test]
    fn uid_parent_socket_code_and_authority_confusion_fail_before_startup() {
        let (manifest, mut platform) = fixture();
        platform.observations[1].lock.uid += 1;
        assert_eq!(
            VerifiedDaemonStartupV2::verify(manifest, &mut platform).unwrap_err(),
            DeploymentTrustErrorV2::ServiceMeasurementMismatch
        );

        let (manifest, mut platform) = fixture();
        platform.observations[2].config_parent_root_owned_not_writable = false;
        assert_eq!(
            VerifiedDaemonStartupV2::verify(manifest, &mut platform).unwrap_err(),
            DeploymentTrustErrorV2::UnsafeFilesystem
        );

        let (manifest, mut platform) = fixture();
        platform.observations[3].lock.socket_mode = 0o666;
        assert_eq!(
            VerifiedDaemonStartupV2::verify(manifest, &mut platform).unwrap_err(),
            DeploymentTrustErrorV2::UnsafeSocket
        );

        let (manifest, mut platform) = fixture();
        platform.observations[4].lock.sandbox_profile_digest = Digest32V2::new([0xee; 32]);
        assert_eq!(
            VerifiedDaemonStartupV2::verify(manifest, &mut platform).unwrap_err(),
            DeploymentTrustErrorV2::SandboxMismatch
        );

        let (manifest, mut platform) = fixture();
        platform.authorities[0].rollback_authority_identity = Digest32V2::new([0xef; 32]);
        assert_eq!(
            VerifiedDaemonStartupV2::verify(manifest, &mut platform).unwrap_err(),
            DeploymentTrustErrorV2::MissingPlatformAuthority
        );
    }

    #[test]
    fn stale_or_fenced_effect_projection_fails_closed() {
        let (manifest, mut platform) = fixture();
        platform.projection = signed_projection(&manifest, manifest.effect_fence_epoch + 1, false);
        assert_eq!(
            VerifiedDaemonStartupV2::verify(manifest, &mut platform).unwrap_err(),
            DeploymentTrustErrorV2::EffectLedgerMismatch
        );

        let (manifest, mut platform) = fixture();
        platform.projection = signed_projection(&manifest, manifest.effect_fence_epoch, true);
        assert_eq!(
            VerifiedDaemonStartupV2::verify(manifest, &mut platform).unwrap_err(),
            DeploymentTrustErrorV2::EffectLedgerMismatch
        );

        let (manifest, mut platform) = fixture();
        let last = platform.projection.len() - 1;
        platform.projection[last] ^= 1;
        assert_eq!(
            VerifiedDaemonStartupV2::verify(manifest, &mut platform).unwrap_err(),
            DeploymentTrustErrorV2::EffectLedgerMismatch
        );
    }

    #[test]
    fn manifest_signature_and_service_set_are_closed() {
        let (mut signed, key_id, public_key) = signed_manifest();
        let last = signed.len() - 1;
        signed[last] ^= 1;
        assert!(matches!(
            VerifiedDeploymentManifestV2::verify(&signed, key_id, public_key),
            Err(DeploymentTrustErrorV2::InvalidManifestSignature
                | DeploymentTrustErrorV2::NonCanonicalManifest)
        ));
    }

    #[test]
    fn edge_table_rejects_missing_reordered_role_swapped_and_reused_keys() {
        let mut manifest = unsigned_manifest();
        manifest.edges.pop();
        assert_eq!(
            manifest.validate(),
            Err(DeploymentTrustErrorV2::IncompleteManifest)
        );

        let mut manifest = unsigned_manifest();
        manifest.edges.swap(0, 1);
        assert_eq!(
            manifest.validate(),
            Err(DeploymentTrustErrorV2::EdgeLockMismatch)
        );

        let mut manifest = unsigned_manifest();
        manifest.edges[0].role = EndpointRoleV2::IngressKernel;
        assert_eq!(
            manifest.validate(),
            Err(DeploymentTrustErrorV2::EdgeLockMismatch)
        );

        let mut manifest = unsigned_manifest();
        manifest.edges[0].client_service = ClosedServiceIdV2::Kerneld;
        assert_eq!(
            manifest.validate(),
            Err(DeploymentTrustErrorV2::EdgeLockMismatch)
        );

        let mut manifest = unsigned_manifest();
        manifest.edges[1].client_handshake_key_id = manifest.edges[0].client_handshake_key_id;
        assert_eq!(
            manifest.validate(),
            Err(DeploymentTrustErrorV2::EdgeLockMismatch)
        );
    }

    #[test]
    fn edge_table_rejects_native_identity_and_abi_mutations() {
        let mut manifest = unsigned_manifest();
        let client = service_lock(ClosedServiceIdV2::Agentd);
        manifest.edges[0].expected_client = ExpectedNativePeerV2::linux(
            BoundedIdentityStringV2::new("agent-kernel".to_owned()).unwrap(),
            client.uid + 1,
            client.gid,
            *client.executable_digest.as_bytes(),
        )
        .unwrap();
        assert_eq!(
            manifest.validate(),
            Err(DeploymentTrustErrorV2::EdgeLockMismatch)
        );

        let mut manifest = unsigned_manifest();
        manifest.protocol_abi_digest = Digest32V2::new([0; 32]);
        assert_eq!(
            manifest.validate(),
            Err(DeploymentTrustErrorV2::IncompleteManifest)
        );

        let mut manifest = unsigned_manifest();
        manifest.effect_fence_epoch = 0;
        assert_eq!(
            manifest.validate(),
            Err(DeploymentTrustErrorV2::IncompleteManifest)
        );
    }
}
