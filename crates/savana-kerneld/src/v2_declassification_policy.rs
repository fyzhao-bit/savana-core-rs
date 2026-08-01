use std::sync::{Arc, RwLock};

use savana_kernel_protocol::v2::Digest32V2;
use savana_policy_core::v2::{
    DeclassificationRuleSetV2, DeploymentControlErrorV2, OperationalTrustRootSetV2,
};

use crate::deployment_trust::VerifiedDaemonStartupV2;
use crate::v2_edge::V2ActiveGenerationSnapshot;

/// A successor envelope whose deployment identity has already passed the
/// complete platform/deployment verification path.  Rule bytes deliberately
/// remain unparsed until the rollover coordinator has closed admission.
pub(crate) struct VerifiedV2DeclassificationSuccessorV2 {
    installation_id: Digest32V2,
    manifest_rule_set_digest: Digest32V2,
    generation: V2ActiveGenerationSnapshot,
    canonical_rule_set: Vec<u8>,
    trust_roots: Arc<OperationalTrustRootSetV2>,
    verification_time_unix_ms: u64,
}

impl VerifiedV2DeclassificationSuccessorV2 {
    pub(crate) fn from_verified_deployment(
        startup: &VerifiedDaemonStartupV2,
        canonical_rule_set: Vec<u8>,
        trust_roots: Arc<OperationalTrustRootSetV2>,
        verification_time_unix_ms: u64,
    ) -> Result<Self, DeploymentControlErrorV2> {
        if canonical_rule_set.is_empty() {
            return Err(DeploymentControlErrorV2::InvalidDeclassificationRuleSet);
        }
        let generation = V2ActiveGenerationSnapshot::from_verified_startup(startup)
            .map_err(|_| DeploymentControlErrorV2::InvalidDeclassificationRuleSet)?;
        Ok(Self {
            installation_id: startup.installation_id(),
            manifest_rule_set_digest: startup.declassification_rule_set_digest(),
            generation,
            canonical_rule_set,
            trust_roots,
            verification_time_unix_ms,
        })
    }
}

struct ActiveV2DeploymentBundle {
    installation_id: Digest32V2,
    generation: Arc<V2ActiveGenerationSnapshot>,
    declassification_rules: Option<Arc<DeclassificationRuleSetV2>>,
    trust_roots: Option<Arc<OperationalTrustRootSetV2>>,
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

    pub(crate) fn publish_verified_successor(
        &self,
        successor: VerifiedV2DeclassificationSuccessorV2,
    ) -> Result<(), DeploymentControlErrorV2> {
        let candidate = DeclassificationRuleSetV2::from_canonical_bytes(
            &successor.canonical_rule_set,
            &successor.trust_roots,
            successor.verification_time_unix_ms,
        )?;
        if candidate.signed_digest() != successor.manifest_rule_set_digest {
            return Err(DeploymentControlErrorV2::InvalidDeclassificationRuleSet);
        }
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
                candidate.validate_predecessor(Some(previous_rules))?;
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
            declassification_rules: Some(Arc::new(candidate)),
            trust_roots: Some(successor.trust_roots),
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
        }));
        Ok(())
    }
}
