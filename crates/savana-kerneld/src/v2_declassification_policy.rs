use std::sync::{Arc, RwLock};

use ed25519_dalek::SigningKey;
use savana_kernel_protocol::v2::{derive_ed25519_key_id_v2, BootIdV2, Digest32V2, EndpointRoleV2};
use savana_policy_core::v2::{
    DeclassificationRuleSetV2, DeploymentControlErrorV2, OperationalTrustRootSetV2,
};

use crate::deployment_trust::{ClosedServiceEdgeIdV2, ClosedServiceIdV2, VerifiedDaemonStartupV2};
use crate::v2_dispatch::{KernelServiceDeploymentV2, KernelServiceDispatcherV2};
use crate::v2_edge::{V2ActiveGenerationSnapshot, VerifiedServiceEdgeV2};
use crate::v2_kernel_owner::KernelRuntimeOwnerV2;
use crate::v2_transport_owner::KernelV2HandshakeOwner;

pub(crate) struct V2LiveEndpointRuntimeV2 {
    generation: Arc<V2ActiveGenerationSnapshot>,
    active_state_manifest_sequence: u64,
    agent_edge: Arc<VerifiedServiceEdgeV2>,
    ingress_edge: Arc<VerifiedServiceEdgeV2>,
    agent_handshake: Arc<KernelV2HandshakeOwner>,
    ingress_handshake: Arc<KernelV2HandshakeOwner>,
    dispatcher: Arc<KernelServiceDispatcherV2>,
    runtime_identity_digests: [Digest32V2; 6],
}

impl V2LiveEndpointRuntimeV2 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_verified_deployment(
        startup: &VerifiedDaemonStartupV2,
        kernel_boot_id: BootIdV2,
        agent_client_public_key: [u8; 32],
        agent_server_signing_key: SigningKey,
        ingress_client_public_key: [u8; 32],
        ingress_server_signing_key: SigningKey,
        envelope_signing_key: SigningKey,
        owner: Arc<KernelRuntimeOwnerV2>,
    ) -> Result<Self, DeploymentControlErrorV2> {
        let invalid = || DeploymentControlErrorV2::InvalidDeclassificationRuleSet;
        let generation = Arc::new(
            V2ActiveGenerationSnapshot::from_verified_startup(startup).map_err(|_| invalid())?,
        );
        let agent_edge = Arc::new(
            VerifiedServiceEdgeV2::from_verified_startup(
                startup,
                ClosedServiceEdgeIdV2::AgentKernel,
            )
            .map_err(|_| invalid())?,
        );
        let ingress_edge = Arc::new(
            VerifiedServiceEdgeV2::from_verified_startup(
                startup,
                ClosedServiceEdgeIdV2::IngressKernel,
            )
            .map_err(|_| invalid())?,
        );
        if !generation.matches_edge(&agent_edge) || !generation.matches_edge(&ingress_edge) {
            return Err(invalid());
        }
        let agent_lock = startup
            .edge_lock(ClosedServiceEdgeIdV2::AgentKernel)
            .ok_or_else(invalid)?;
        let ingress_lock = startup
            .edge_lock(ClosedServiceEdgeIdV2::IngressKernel)
            .ok_or_else(invalid)?;
        if derive_ed25519_key_id_v2(agent_client_public_key) != agent_lock.client_handshake_key_id
            || derive_ed25519_key_id_v2(agent_server_signing_key.verifying_key().to_bytes())
                != agent_lock.server_handshake_key_id
            || derive_ed25519_key_id_v2(ingress_client_public_key)
                != ingress_lock.client_handshake_key_id
            || derive_ed25519_key_id_v2(ingress_server_signing_key.verifying_key().to_bytes())
                != ingress_lock.server_handshake_key_id
        {
            return Err(invalid());
        }
        let envelope_key_id =
            derive_ed25519_key_id_v2(envelope_signing_key.verifying_key().to_bytes());
        if envelope_key_id != startup.kernel_envelope_signing_key_id() {
            return Err(invalid());
        }
        let agent_handshake = Arc::new(
            KernelV2HandshakeOwner::spawn(
                startup
                    .kernel_service_handshake_edge(
                        ClosedServiceEdgeIdV2::AgentKernel,
                        kernel_boot_id,
                    )
                    .map_err(|_| invalid())?,
                agent_client_public_key,
                agent_server_signing_key,
                128,
            )
            .map_err(|_| invalid())?,
        );
        let ingress_handshake = Arc::new(
            KernelV2HandshakeOwner::spawn(
                startup
                    .kernel_service_handshake_edge(
                        ClosedServiceEdgeIdV2::IngressKernel,
                        kernel_boot_id,
                    )
                    .map_err(|_| invalid())?,
                ingress_client_public_key,
                ingress_server_signing_key,
                128,
            )
            .map_err(|_| invalid())?,
        );
        let kernel_identity = startup
            .service_identity(ClosedServiceIdV2::Kerneld)
            .ok_or_else(invalid)?;
        let dispatcher = Arc::new(
            KernelServiceDispatcherV2::spawn(
                KernelServiceDeploymentV2::from_verified_startup(
                    kernel_boot_id,
                    kernel_identity,
                    startup.active_state_manifest_digest(),
                    startup.deployment_generation(),
                )
                .map_err(|_| invalid())?,
                envelope_key_id,
                envelope_signing_key,
                owner,
            )
            .map_err(|_| invalid())?,
        );
        if !dispatcher.matches_generation(
            generation.active_state_manifest_digest(),
            generation.deployment_generation(),
        ) {
            return Err(invalid());
        }
        Ok(Self {
            generation,
            active_state_manifest_sequence: startup.active_state_manifest_sequence(),
            agent_edge,
            ingress_edge,
            agent_handshake,
            ingress_handshake,
            dispatcher,
            runtime_identity_digests: [
                startup.release_identity_digest(),
                startup.model_set_identity_digest(),
                startup.resource_profile_identity_digest(),
                startup.approval_lock_identity_digest(),
                startup.planner_lock_identity_digest(),
                startup.executor_key_lock_identity_digest(),
            ],
        })
    }

    fn matches_generation(&self, generation: &V2ActiveGenerationSnapshot) -> bool {
        self.generation.as_ref() == generation
            && generation.matches_edge(&self.agent_edge)
            && generation.matches_edge(&self.ingress_edge)
            && self.dispatcher.matches_generation(
                generation.active_state_manifest_digest(),
                generation.deployment_generation(),
            )
    }

    fn validate_live_predecessor(&self, previous: &Self) -> Result<(), DeploymentControlErrorV2> {
        let invalid = DeploymentControlErrorV2::InvalidDeclassificationRuleSet;
        if self.generation.deployment_generation()
            != previous
                .generation
                .deployment_generation()
                .checked_add(1)
                .ok_or(invalid)?
            || self.active_state_manifest_sequence
                != previous
                    .active_state_manifest_sequence
                    .checked_add(1)
                    .ok_or(invalid)?
            || self.generation.effect_fence_epoch()
                != previous
                    .generation
                    .effect_fence_epoch()
                    .checked_add(1)
                    .ok_or(invalid)?
            || self.generation.protocol_abi_digest() != previous.generation.protocol_abi_digest()
            || self.runtime_identity_digests != previous.runtime_identity_digests
            || self.agent_edge.server_identity() != previous.agent_edge.server_identity()
            || self.ingress_edge.server_identity() != previous.ingress_edge.server_identity()
            || self.agent_edge.listener_identity_digest()
                != previous.agent_edge.listener_identity_digest()
            || self.ingress_edge.listener_identity_digest()
                != previous.ingress_edge.listener_identity_digest()
        {
            return Err(invalid);
        }
        Ok(())
    }

    fn endpoint(
        &self,
        role: EndpointRoleV2,
    ) -> Option<(
        Arc<VerifiedServiceEdgeV2>,
        Arc<KernelV2HandshakeOwner>,
        Arc<KernelServiceDispatcherV2>,
    )> {
        match role {
            EndpointRoleV2::AgentKernel => Some((
                Arc::clone(&self.agent_edge),
                Arc::clone(&self.agent_handshake),
                Arc::clone(&self.dispatcher),
            )),
            EndpointRoleV2::IngressKernel => Some((
                Arc::clone(&self.ingress_edge),
                Arc::clone(&self.ingress_handshake),
                Arc::clone(&self.dispatcher),
            )),
            _ => None,
        }
    }
}

/// A successor envelope whose deployment identity has already passed the
/// complete platform/deployment verification path. Possessing this value also
/// proves that its rules and complete live endpoint runtime match that
/// deployment; only predecessor checks depend on the currently active bundle.
pub(crate) struct VerifiedV2DeclassificationSuccessorV2 {
    installation_id: Digest32V2,
    generation: V2ActiveGenerationSnapshot,
    declassification_rules: Arc<DeclassificationRuleSetV2>,
    trust_roots: Arc<OperationalTrustRootSetV2>,
    live_endpoints: Arc<V2LiveEndpointRuntimeV2>,
}

impl VerifiedV2DeclassificationSuccessorV2 {
    pub(crate) fn from_verified_deployment(
        startup: &VerifiedDaemonStartupV2,
        canonical_rule_set: Vec<u8>,
        trust_roots: Arc<OperationalTrustRootSetV2>,
        verification_time_unix_ms: u64,
        live_endpoints: Arc<V2LiveEndpointRuntimeV2>,
    ) -> Result<Self, DeploymentControlErrorV2> {
        let declassification_rules = Arc::new(DeclassificationRuleSetV2::from_canonical_bytes(
            &canonical_rule_set,
            &trust_roots,
            verification_time_unix_ms,
        )?);
        if declassification_rules.signed_digest() != startup.declassification_rule_set_digest() {
            return Err(DeploymentControlErrorV2::InvalidDeclassificationRuleSet);
        }
        let generation = V2ActiveGenerationSnapshot::from_verified_startup(startup)
            .map_err(|_| DeploymentControlErrorV2::InvalidDeclassificationRuleSet)?;
        if live_endpoints.active_state_manifest_sequence != startup.active_state_manifest_sequence()
            || !live_endpoints.matches_generation(&generation)
        {
            return Err(DeploymentControlErrorV2::InvalidDeclassificationRuleSet);
        }
        Ok(Self {
            installation_id: startup.installation_id(),
            generation,
            declassification_rules,
            trust_roots,
            live_endpoints,
        })
    }

    pub(crate) fn validate_fresh_at(
        &self,
        now_unix_ms: u64,
    ) -> Result<(), DeploymentControlErrorV2> {
        let reparsed = DeclassificationRuleSetV2::from_canonical_bytes(
            self.declassification_rules.canonical_bytes(),
            &self.trust_roots,
            now_unix_ms,
        )?;
        if reparsed.signed_digest() != self.declassification_rules.signed_digest() {
            return Err(DeploymentControlErrorV2::InvalidDeclassificationRuleSet);
        }
        Ok(())
    }
}

struct ActiveV2DeploymentBundle {
    installation_id: Digest32V2,
    generation: Arc<V2ActiveGenerationSnapshot>,
    declassification_rules: Option<Arc<DeclassificationRuleSetV2>>,
    trust_roots: Option<Arc<OperationalTrustRootSetV2>>,
    live_endpoints: Option<Arc<V2LiveEndpointRuntimeV2>>,
}

#[derive(Clone)]
pub(crate) struct ActiveDeclassificationRuleSetV2 {
    active: Arc<RwLock<Option<Arc<ActiveV2DeploymentBundle>>>>,
}

impl ActiveDeclassificationRuleSetV2 {
    pub(crate) fn empty() -> Self {
        Self {
            active: Arc::new(RwLock::new(None)),
        }
    }

    #[cfg(test)]
    pub(crate) fn new(
        initial: DeclassificationRuleSetV2,
        trust_roots: Arc<OperationalTrustRootSetV2>,
    ) -> Result<Self, DeploymentControlErrorV2> {
        if initial.trust_root_set_digest() != trust_roots.signed_digest()
            || initial.product_family_digest() != trust_roots.product_family_digest()
        {
            return Err(DeploymentControlErrorV2::InvalidDeclassificationRuleSet);
        }
        Ok(Self {
            active: Arc::new(RwLock::new(Some(Arc::new(ActiveV2DeploymentBundle {
                installation_id: Digest32V2::new([0x71; 32]),
                generation: Arc::new(V2ActiveGenerationSnapshot::for_dispatch_test(
                    Digest32V2::new([0x72; 32]),
                    1,
                )),
                declassification_rules: Some(Arc::new(initial)),
                trust_roots: Some(trust_roots),
                live_endpoints: None,
            })))),
        })
    }

    pub(crate) fn snapshot(
        &self,
    ) -> Result<Arc<DeclassificationRuleSetV2>, DeploymentControlErrorV2> {
        self.active
            .read()
            .map_err(|_| DeploymentControlErrorV2::InvalidDeclassificationRuleSet)?
            .as_ref()
            .and_then(|active| active.declassification_rules.as_ref())
            .cloned()
            .ok_or(DeploymentControlErrorV2::InvalidDeclassificationRuleSet)
    }

    pub(crate) fn generation_snapshot(
        &self,
    ) -> Result<Arc<V2ActiveGenerationSnapshot>, DeploymentControlErrorV2> {
        self.active
            .read()
            .map_err(|_| DeploymentControlErrorV2::InvalidDeclassificationRuleSet)
            .and_then(|active| {
                active
                    .as_ref()
                    .map(|active| Arc::clone(&active.generation))
                    .ok_or(DeploymentControlErrorV2::InvalidDeclassificationRuleSet)
            })
    }

    pub(crate) fn endpoint_snapshot(
        &self,
        role: EndpointRoleV2,
    ) -> Result<
        (
            Arc<V2ActiveGenerationSnapshot>,
            Arc<VerifiedServiceEdgeV2>,
            Arc<KernelV2HandshakeOwner>,
            Arc<KernelServiceDispatcherV2>,
        ),
        DeploymentControlErrorV2,
    > {
        let active = self
            .active
            .read()
            .map_err(|_| DeploymentControlErrorV2::InvalidDeclassificationRuleSet)?;
        let active = active
            .as_ref()
            .ok_or(DeploymentControlErrorV2::InvalidDeclassificationRuleSet)?;
        let endpoints = active
            .live_endpoints
            .as_ref()
            .ok_or(DeploymentControlErrorV2::InvalidDeclassificationRuleSet)?;
        let (edge, handshake, dispatcher) = endpoints
            .endpoint(role)
            .ok_or(DeploymentControlErrorV2::InvalidDeclassificationRuleSet)?;
        Ok((Arc::clone(&active.generation), edge, handshake, dispatcher))
    }

    pub(crate) fn publish_verified_successor(
        &self,
        successor: VerifiedV2DeclassificationSuccessorV2,
    ) -> Result<(), DeploymentControlErrorV2> {
        let mut active = self
            .active
            .write()
            .map_err(|_| DeploymentControlErrorV2::InvalidDeclassificationRuleSet)?;
        match active.as_deref() {
            // A fresh daemon may start from an already-advanced deployment.
            // There is no in-memory predecessor to compare on initial
            // activation; the deployment manifest pin and object signatures
            // are the authority until a live successor is published.
            None => {}
            Some(previous) => {
                let previous_rules = previous
                    .declassification_rules
                    .as_deref()
                    .ok_or(DeploymentControlErrorV2::InvalidDeclassificationRuleSet)?;
                let previous_roots = previous
                    .trust_roots
                    .as_deref()
                    .ok_or(DeploymentControlErrorV2::InvalidDeclassificationRuleSet)?;
                let previous_endpoints = previous
                    .live_endpoints
                    .as_deref()
                    .ok_or(DeploymentControlErrorV2::InvalidDeclassificationRuleSet)?;
                if successor.installation_id != previous.installation_id
                    || successor.generation.deployment_generation()
                        != previous
                            .generation
                            .deployment_generation()
                            .checked_add(1)
                            .ok_or(DeploymentControlErrorV2::InvalidDeclassificationRuleSet)?
                {
                    return Err(DeploymentControlErrorV2::InvalidDeclassificationRuleSet);
                }
                successor
                    .live_endpoints
                    .validate_live_predecessor(previous_endpoints)?;
                successor
                    .declassification_rules
                    .validate_predecessor(Some(previous_rules))?;
                if successor.trust_roots.signed_digest() != previous_roots.signed_digest() {
                    successor
                        .trust_roots
                        .validate_predecessor(Some(previous_roots))?;
                }
            }
        }
        *active = Some(Arc::new(ActiveV2DeploymentBundle {
            installation_id: successor.installation_id,
            generation: Arc::new(successor.generation),
            declassification_rules: Some(successor.declassification_rules),
            trust_roots: Some(successor.trust_roots),
            live_endpoints: Some(successor.live_endpoints),
        }));
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn activate_generation_for_test(
        &self,
        generation: V2ActiveGenerationSnapshot,
    ) -> Result<(), DeploymentControlErrorV2> {
        let mut active = self
            .active
            .write()
            .map_err(|_| DeploymentControlErrorV2::InvalidDeclassificationRuleSet)?;
        if active.is_some() {
            return Err(DeploymentControlErrorV2::InvalidDeclassificationRuleSet);
        }
        *active = Some(Arc::new(ActiveV2DeploymentBundle {
            installation_id: Digest32V2::new([0x73; 32]),
            generation: Arc::new(generation),
            declassification_rules: None,
            trust_roots: None,
            live_endpoints: None,
        }));
        Ok(())
    }
}
