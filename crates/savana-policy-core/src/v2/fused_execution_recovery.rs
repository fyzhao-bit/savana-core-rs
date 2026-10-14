//! Historical result context, not authority to send or publish an execution.
use super::{EffectSetV2, G4Error, KernelDispatchStateV2, VerifiedTaskAuthorizationV2};
use savana_kernel_protocol::v2::{
    ActionIntentIdV2, Digest32V2, PrincipalIdV2, ProducerIdentityV2, UnixMillisV2,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ResultScopeRecord {
    schema: u16,
    principal: [u8; 32],
    producer: [u8; 32],
    expires_at: u64,
    effects: u16,
}
impl ResultScopeRecord {
    pub(super) fn validate(
        &self,
        root: &VerifiedTaskAuthorizationV2,
        admitted_at: u64,
    ) -> Result<(), G4Error> {
        if self.schema != 1
            || self.principal != *root.material().principal().as_bytes()
            || self.producer == [0; 32]
            || self.expires_at <= admitted_at
            || self.expires_at > root.material().expires_at().get()
            || EffectSetV2::from_bits(self.effects).is_none()
        {
            return Err(G4Error::StateConflict);
        }
        Ok(())
    }
}

/// Construct only from the host's authenticated session. No Deserialize/RPC;
/// G7 rechecks principal and lifetime against the exact historical task root.
#[derive(Clone, PartialEq, Eq)]
pub struct FusedResultScopeV04(pub(super) ResultScopeRecord);
impl std::fmt::Debug for FusedResultScopeV04 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FusedResultScopeV04(<private>)")
    }
}
impl FusedResultScopeV04 {
    pub fn from_authenticated_session(
        principal: PrincipalIdV2,
        producer: ProducerIdentityV2,
        expires_at: UnixMillisV2,
        effects: EffectSetV2,
    ) -> Result<Self, G4Error> {
        if principal.as_bytes() == &[0; 32]
            || producer.as_bytes() == &[0; 32]
            || expires_at.get() == 0
        {
            return Err(G4Error::StateConflict);
        }
        Ok(Self(ResultScopeRecord {
            schema: 1,
            principal: *principal.as_bytes(),
            producer: *producer.as_bytes(),
            expires_at: expires_at.get(),
            effects: effects.bits(),
        }))
    }
    pub fn principal(&self) -> PrincipalIdV2 {
        PrincipalIdV2::new(self.0.principal)
    }
    pub fn producer(&self) -> ProducerIdentityV2 {
        ProducerIdentityV2::new(self.0.producer)
    }
    pub fn expires_at(&self) -> UnixMillisV2 {
        UnixMillisV2::new(self.0.expires_at)
    }
    pub fn effects(&self) -> EffectSetV2 {
        EffectSetV2::from_bits(self.0.effects).expect("validated scope")
    }
}

/// Only the authenticated durable owner constructs this projection. No caller
/// bytes, current plan, live approval or private input rehydration can mint it.
#[derive(Clone)]
pub struct RecoveredFusedExecutionV04 {
    pub(super) core: super::DispatchCoreV2,
    pub(super) core_digest: Digest32V2,
    pub(super) intent: ActionIntentIdV2,
    pub(super) descriptor: Digest32V2,
    pub(super) material: Digest32V2,
    pub(super) scope: FusedResultScopeV04,
    pub(super) state: KernelDispatchStateV2,
    pub(super) result_commit: Option<Digest32V2>,
}
impl RecoveredFusedExecutionV04 {
    pub fn core(&self) -> &super::DispatchCoreV2 {
        &self.core
    }
    pub fn core_digest(&self) -> Digest32V2 {
        self.core_digest
    }
    pub fn intent(&self) -> ActionIntentIdV2 {
        self.intent
    }
    pub fn descriptor(&self) -> Digest32V2 {
        self.descriptor
    }
    pub fn scope(&self) -> &FusedResultScopeV04 {
        &self.scope
    }
    pub fn state(&self) -> KernelDispatchStateV2 {
        self.state
    }
    pub fn result_commit(&self) -> Option<Digest32V2> {
        self.result_commit
    }
    /// Stable across process handles and vault commit response loss.
    pub fn result_binding(&self) -> Digest32V2 {
        super::task_authorization::hash_parts(
            b"SAVANA_FUSED_RESULT_INTENT_V04\0",
            &[
                self.intent.as_bytes(),
                self.material.as_bytes(),
                self.core_digest.as_bytes(),
            ],
        )
    }
}
