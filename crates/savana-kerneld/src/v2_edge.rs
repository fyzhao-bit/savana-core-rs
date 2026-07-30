use savana_kernel_protocol::v2::{
    Digest32V2, Ed25519KeyIdV2, EndpointRoleV2, PeerIdentityBindingV2, ServiceIdentityV2,
};
use savana_platform_identity::{
    verify_native_peer_v2, BoundedIdentityStringV2, ExpectedNativePeerV2, NativePeerMeasurementV2,
};
use sha2::{Digest as _, Sha256};

use crate::deployment_trust::{
    ClosedServiceEdgeIdV2, DeploymentTrustErrorV2, ServiceEdgeLockV2, VerifiedDaemonStartupV2,
};

const EDGE_BINDING_DOMAIN_V2: &[u8] = b"SAVANA_VERIFIED_SERVICE_EDGE_BINDING_V2\0";

pub(crate) struct VerifiedServiceEdgeV2 {
    edge_id: ClosedServiceEdgeIdV2,
    role: EndpointRoleV2,
    client_identity: ServiceIdentityV2,
    server_identity: ServiceIdentityV2,
    listener_identity_digest: Digest32V2,
    client_handshake_key_id: Ed25519KeyIdV2,
    server_handshake_key_id: Ed25519KeyIdV2,
    expected_client: ExpectedNativePeerV2,
    active_state_manifest_digest: Digest32V2,
    deployment_generation: u64,
    effect_fence_epoch: u64,
    protocol_abi_digest: Digest32V2,
    edge_digest: Digest32V2,
}

impl std::fmt::Debug for VerifiedServiceEdgeV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifiedServiceEdgeV2")
            .field("edge_id", &self.edge_id)
            .field("role", &self.role)
            .field("deployment_generation", &self.deployment_generation)
            .field("effect_fence_epoch", &self.effect_fence_epoch)
            .finish_non_exhaustive()
    }
}

impl VerifiedServiceEdgeV2 {
    pub(crate) fn from_verified_startup(
        startup: &VerifiedDaemonStartupV2,
        edge_id: ClosedServiceEdgeIdV2,
    ) -> Result<Self, DeploymentTrustErrorV2> {
        let lock = startup
            .edge_lock(edge_id)
            .ok_or(DeploymentTrustErrorV2::EdgeLockMismatch)?;
        let client_identity = startup
            .service_identity(edge_id.client_service())
            .ok_or(DeploymentTrustErrorV2::EdgeLockMismatch)?;
        let server_identity = startup
            .service_identity(edge_id.server_service())
            .ok_or(DeploymentTrustErrorV2::EdgeLockMismatch)?;
        let edge_digest = edge_binding_digest(startup, lock, client_identity, server_identity)?;
        Ok(Self {
            edge_id,
            role: lock.role,
            client_identity,
            server_identity,
            listener_identity_digest: lock.listener_identity_digest,
            client_handshake_key_id: lock.client_handshake_key_id,
            server_handshake_key_id: lock.server_handshake_key_id,
            expected_client: lock.expected_client.clone(),
            active_state_manifest_digest: startup.active_state_manifest_digest(),
            deployment_generation: startup.deployment_generation(),
            effect_fence_epoch: startup.effect_fence_epoch(),
            protocol_abi_digest: startup.protocol_abi_digest(),
            edge_digest,
        })
    }

    pub(crate) const fn edge_id(&self) -> ClosedServiceEdgeIdV2 {
        self.edge_id
    }

    pub(crate) const fn role(&self) -> EndpointRoleV2 {
        self.role
    }

    pub(crate) const fn client_identity(&self) -> ServiceIdentityV2 {
        self.client_identity
    }

    pub(crate) const fn server_identity(&self) -> ServiceIdentityV2 {
        self.server_identity
    }

    pub(crate) const fn listener_identity_digest(&self) -> Digest32V2 {
        self.listener_identity_digest
    }

    pub(crate) const fn client_handshake_key_id(&self) -> Ed25519KeyIdV2 {
        self.client_handshake_key_id
    }

    pub(crate) const fn server_handshake_key_id(&self) -> Ed25519KeyIdV2 {
        self.server_handshake_key_id
    }

    pub(crate) const fn active_state_manifest_digest(&self) -> Digest32V2 {
        self.active_state_manifest_digest
    }

    pub(crate) const fn deployment_generation(&self) -> u64 {
        self.deployment_generation
    }

    pub(crate) const fn effect_fence_epoch(&self) -> u64 {
        self.effect_fence_epoch
    }

    pub(crate) const fn protocol_abi_digest(&self) -> Digest32V2 {
        self.protocol_abi_digest
    }

    pub(crate) const fn edge_digest(&self) -> Digest32V2 {
        self.edge_digest
    }

    pub(crate) fn verify_native_peer(
        &self,
        measurement: &NativePeerMeasurementV2,
    ) -> Result<VerifiedAcceptedPeerV2, DeploymentTrustErrorV2> {
        let role_identity = BoundedIdentityStringV2::new(self.edge_id.role_identity().to_owned())
            .map_err(|_| DeploymentTrustErrorV2::EdgeLockMismatch)?;
        verify_native_peer_v2(&self.expected_client, &role_identity, measurement)
            .map_err(|_| DeploymentTrustErrorV2::EdgeLockMismatch)?;
        let binding = match measurement {
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
            ),
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
            ),
            _ => return Err(DeploymentTrustErrorV2::EdgeLockMismatch),
        }
        .map_err(|_| DeploymentTrustErrorV2::EdgeLockMismatch)?;
        Ok(VerifiedAcceptedPeerV2 {
            role: self.role,
            client_identity: self.client_identity,
            edge_digest: self.edge_digest,
            binding,
        })
    }

    #[cfg(test)]
    pub(crate) fn for_generation_test(
        edge_id: ClosedServiceEdgeIdV2,
        deployment_generation: u64,
        effect_fence_epoch: u64,
        seed: u8,
    ) -> Self {
        let role_identity =
            BoundedIdentityStringV2::new(edge_id.role_identity().to_owned()).unwrap();
        Self {
            edge_id,
            role: edge_id.role(),
            client_identity: ServiceIdentityV2::new([seed; 32]),
            server_identity: ServiceIdentityV2::new([seed.wrapping_add(1); 32]),
            listener_identity_digest: Digest32V2::new([seed.wrapping_add(2); 32]),
            client_handshake_key_id: Ed25519KeyIdV2::new([seed.wrapping_add(3); 32]),
            server_handshake_key_id: Ed25519KeyIdV2::new([seed.wrapping_add(4); 32]),
            expected_client: ExpectedNativePeerV2::linux(
                role_identity,
                501,
                20,
                [seed.wrapping_add(5); 32],
            )
            .unwrap(),
            active_state_manifest_digest: Digest32V2::new([seed.wrapping_add(6); 32]),
            deployment_generation,
            effect_fence_epoch,
            protocol_abi_digest: Digest32V2::new([seed.wrapping_add(7); 32]),
            edge_digest: Digest32V2::new([seed.wrapping_add(8); 32]),
        }
    }
}

pub(crate) struct VerifiedAcceptedPeerV2 {
    role: EndpointRoleV2,
    client_identity: ServiceIdentityV2,
    edge_digest: Digest32V2,
    binding: PeerIdentityBindingV2,
}

impl std::fmt::Debug for VerifiedAcceptedPeerV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifiedAcceptedPeerV2")
            .field("role", &self.role)
            .field("client_identity", &self.client_identity)
            .field("edge_digest", &self.edge_digest)
            .field("binding", &"<redacted>")
            .finish()
    }
}

impl VerifiedAcceptedPeerV2 {
    pub(crate) const fn role(&self) -> EndpointRoleV2 {
        self.role
    }

    pub(crate) const fn client_identity(&self) -> ServiceIdentityV2 {
        self.client_identity
    }

    pub(crate) const fn edge_digest(&self) -> Digest32V2 {
        self.edge_digest
    }

    pub(crate) fn into_peer_binding(self) -> PeerIdentityBindingV2 {
        self.binding
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct V2ActiveGenerationSnapshot {
    active_state_manifest_digest: Digest32V2,
    deployment_generation: u64,
    effect_fence_epoch: u64,
    protocol_abi_digest: Digest32V2,
    edge_digests: [Digest32V2; 3],
}

impl V2ActiveGenerationSnapshot {
    pub(crate) fn from_verified_startup(
        startup: &VerifiedDaemonStartupV2,
    ) -> Result<Self, DeploymentTrustErrorV2> {
        let agent = VerifiedServiceEdgeV2::from_verified_startup(
            startup,
            ClosedServiceEdgeIdV2::AgentKernel,
        )?;
        let ingress = VerifiedServiceEdgeV2::from_verified_startup(
            startup,
            ClosedServiceEdgeIdV2::IngressKernel,
        )?;
        let executor = VerifiedServiceEdgeV2::from_verified_startup(
            startup,
            ClosedServiceEdgeIdV2::KernelExecutor,
        )?;
        Ok(Self {
            active_state_manifest_digest: startup.active_state_manifest_digest(),
            deployment_generation: startup.deployment_generation(),
            effect_fence_epoch: startup.effect_fence_epoch(),
            protocol_abi_digest: startup.protocol_abi_digest(),
            edge_digests: [
                agent.edge_digest(),
                ingress.edge_digest(),
                executor.edge_digest(),
            ],
        })
    }

    pub(crate) fn matches_edge(&self, edge: &VerifiedServiceEdgeV2) -> bool {
        self.active_state_manifest_digest == edge.active_state_manifest_digest
            && self.deployment_generation == edge.deployment_generation
            && self.effect_fence_epoch == edge.effect_fence_epoch
            && self.protocol_abi_digest == edge.protocol_abi_digest
            && self.edge_digests[usize::from(edge.edge_id.tag() - 1)] == edge.edge_digest
    }

    pub(crate) const fn active_state_manifest_digest(&self) -> Digest32V2 {
        self.active_state_manifest_digest
    }

    pub(crate) const fn deployment_generation(&self) -> u64 {
        self.deployment_generation
    }

    pub(crate) const fn effect_fence_epoch(&self) -> u64 {
        self.effect_fence_epoch
    }

    pub(crate) const fn protocol_abi_digest(&self) -> Digest32V2 {
        self.protocol_abi_digest
    }

    #[cfg(test)]
    pub(crate) fn for_generation_test(edge: &VerifiedServiceEdgeV2) -> Self {
        let mut edge_digests = [
            Digest32V2::new([0xe1; 32]),
            Digest32V2::new([0xe2; 32]),
            Digest32V2::new([0xe3; 32]),
        ];
        edge_digests[usize::from(edge.edge_id.tag() - 1)] = edge.edge_digest;
        Self {
            active_state_manifest_digest: edge.active_state_manifest_digest,
            deployment_generation: edge.deployment_generation,
            effect_fence_epoch: edge.effect_fence_epoch,
            protocol_abi_digest: edge.protocol_abi_digest,
            edge_digests,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_fence_for_test(&self, effect_fence_epoch: u64) -> Self {
        Self {
            effect_fence_epoch,
            ..self.clone()
        }
    }

    #[cfg(test)]
    pub(crate) fn for_dispatch_test(
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
    ) -> Self {
        Self {
            active_state_manifest_digest,
            deployment_generation,
            effect_fence_epoch: 1,
            protocol_abi_digest: Digest32V2::new([0xd1; 32]),
            edge_digests: [
                Digest32V2::new([0xd2; 32]),
                Digest32V2::new([0xd3; 32]),
                Digest32V2::new([0xd4; 32]),
            ],
        }
    }
}

fn edge_binding_digest(
    startup: &VerifiedDaemonStartupV2,
    edge: &ServiceEdgeLockV2,
    client_identity: ServiceIdentityV2,
    server_identity: ServiceIdentityV2,
) -> Result<Digest32V2, DeploymentTrustErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(14)
        .and_then(|encoder| encoder.u16(2))
        .and_then(|encoder| encoder.bytes(startup.installation_id().as_bytes()))
        .and_then(|encoder| encoder.bytes(startup.active_state_manifest_digest().as_bytes()))
        .and_then(|encoder| encoder.u64(startup.deployment_generation()))
        .and_then(|encoder| encoder.u64(startup.effect_fence_epoch()))
        .and_then(|encoder| encoder.bytes(startup.protocol_abi_digest().as_bytes()))
        .and_then(|encoder| encoder.u16(edge.edge_id.tag()))
        .and_then(|encoder| encoder.u16(edge.role.tag()))
        .and_then(|encoder| encoder.bytes(client_identity.as_bytes()))
        .and_then(|encoder| encoder.bytes(server_identity.as_bytes()))
        .and_then(|encoder| encoder.bytes(edge.listener_identity_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(edge.client_handshake_key_id.as_bytes()))
        .and_then(|encoder| encoder.bytes(edge.server_handshake_key_id.as_bytes()))
        .map_err(|_| DeploymentTrustErrorV2::EdgeLockMismatch)?;
    encode_expected_client(&mut encoder, &edge.expected_client)?;
    let payload = encoder.into_writer();
    let mut hasher = Sha256::new();
    hasher.update(EDGE_BINDING_DOMAIN_V2);
    hasher.update(payload);
    Ok(Digest32V2::new(hasher.finalize().into()))
}

fn encode_expected_client(
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
                .map_err(|_| DeploymentTrustErrorV2::EdgeLockMismatch)?;
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
                .map_err(|_| DeploymentTrustErrorV2::EdgeLockMismatch)?;
        }
        _ => return Err(DeploymentTrustErrorV2::EdgeLockMismatch),
    }
    Ok(())
}
