//! Additive, non-dispatching task-contract verification and whole-action matching.
//! Remaining budgets, dependencies, revocation storage and one-use consumption
//! belong to the atomic durable task owner, not to these static proofs.
use super::EffectSetV2;
use ed25519_dalek::VerifyingKey;
use savana_kernel_protocol::v2::{
    action_content_digest_v2, encode_task_authorization_v2, task_authorization_digest_v2,
    verify_task_authorization_v2, ActionContentV2, Digest32V2, DurableTaskIdV2, PrincipalIdV2,
    SignedTaskAuthorizationV2, TaskAuthorizationClauseV2, TaskAuthorizationV2, TaskEffectV2,
    UnixMillisV2,
};
use sha2::{Digest as _, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TaskAuthorizationErrorV2 {
    #[error("task authority verification failed")]
    Verification,
    #[error("task authority is not current")]
    StaleAuthority,
    #[error("action is outside the complete authorized relation")]
    ActionMismatch,
    #[error("candidate domain is not the complete current contract domain")]
    CandidateMismatch,
    #[error("task pre-state does not match")]
    StateMismatch,
    #[error("control selections are invalid or incomplete")]
    SelectionMismatch,
    #[error("control evidence is invalid")]
    EvidenceMismatch,
    #[error("authorization digest input is invalid")]
    InvalidDigestInput,
}
pub(super) fn hash_parts(domain: &[u8], parts: &[&[u8]]) -> Digest32V2 {
    // Every variable field is length-prefixed. No concatenation ambiguity.
    let mut h = Sha256::new();
    h.update(domain);
    for part in parts {
        h.update(
            u64::try_from(part.len())
                .expect("bounded in-memory slice")
                .to_be_bytes(),
        );
        h.update(part);
    }
    Digest32V2::new(h.finalize().into())
}
pub(super) fn is_zero(d: Digest32V2) -> bool {
    d.as_bytes().iter().all(|b| *b == 0)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedTaskAuthorizationV2 {
    material: TaskAuthorizationV2,
    digest: Digest32V2,
}
impl VerifiedTaskAuthorizationV2 {
    // The AEAD-validated durable snapshot is a separate, crate-private trust path.
    pub(crate) fn from_authenticated_snapshot(
        material: TaskAuthorizationV2,
    ) -> Result<Self, super::G4Error> {
        let digest = task_authorization_digest_v2(&material)
            .map_err(|_| super::G4Error::DurableStateCorrupt)?;
        Ok(Self { material, digest })
    }
    /// Trust context/key must be selected by the trusted owner, not the proposer.
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        signed: &SignedTaskAuthorizationV2,
        key: &VerifyingKey,
        principal: PrincipalIdV2,
        task: DurableTaskIdV2,
        installation: Digest32V2,
        manifest: Digest32V2,
        now: UnixMillisV2,
    ) -> Result<Self, TaskAuthorizationErrorV2> {
        let material =
            verify_task_authorization_v2(signed, key, principal, task, installation, manifest, now)
                .map_err(|_| TaskAuthorizationErrorV2::Verification)?;
        let digest = task_authorization_digest_v2(&material)
            .map_err(|_| TaskAuthorizationErrorV2::Verification)?;
        Ok(Self { material, digest })
    }
    pub fn material(&self) -> &TaskAuthorizationV2 {
        &self.material
    }
    pub fn digest(&self) -> Digest32V2 {
        self.digest
    }
    fn valid_at(&self, now: UnixMillisV2) -> Result<(), TaskAuthorizationErrorV2> {
        if now.get() < self.material.not_before().get()
            || now.get() >= self.material.expires_at().get()
        {
            Err(TaskAuthorizationErrorV2::StaleAuthority)
        } else {
            Ok(())
        }
    }
    fn clause(&self, id: u64) -> Result<&TaskAuthorizationClauseV2, TaskAuthorizationErrorV2> {
        self.material
            .clauses()
            .iter()
            .find(|c| c.clause_id() == id)
            .ok_or(TaskAuthorizationErrorV2::ActionMismatch)
    }
    /// The only candidate source is the entire signed contract. No API accepts
    /// subsets, search results, runtime values, or caller assertions of completeness.
    pub fn candidate_domain(
        &self,
        clause_id: u64,
        now: UnixMillisV2,
    ) -> Result<CompleteContractDomainV2, TaskAuthorizationErrorV2> {
        self.valid_at(now)?;
        let clause = self.clause(clause_id)?;
        let count = u64::try_from(clause.alternatives().len())
            .map_err(|_| TaskAuthorizationErrorV2::CandidateMismatch)?;
        let canonical = encode_task_authorization_v2(&self.material)
            .map_err(|_| TaskAuthorizationErrorV2::Verification)?;
        // Binding the entire canonical contract also binds every complete
        // alternative, its ordering, prerequisites, limits and validity window.
        let digest = hash_parts(
            b"SAVANA_COMPLETE_CONTRACT_DOMAIN_V2_SCHEMA1\0",
            &[
                self.digest.as_bytes(),
                &self.material.revision().to_be_bytes(),
                &clause_id.to_be_bytes(),
                &count.to_be_bytes(),
                &canonical,
            ],
        );
        Ok(CompleteContractDomainV2 {
            digest,
            source_digest: self.digest,
            epoch: self.material.revision(),
            clause_id,
            candidate_count: count,
            not_before: self.material.not_before(),
            expires_at: self.material.expires_at(),
        })
    }
    pub fn match_action(
        &self,
        content: &ActionContentV2,
        current: &TaskMatchContextV2<'_>,
    ) -> Result<VerifiedTaskMatchV2, TaskAuthorizationErrorV2> {
        self.valid_at(current.now)?;
        if current.deployment_generation == 0 {
            return Err(TaskAuthorizationErrorV2::StateMismatch);
        }
        if current.current_authorization.map(Self::digest) != Some(self.digest) {
            return Err(TaskAuthorizationErrorV2::StaleAuthority);
        }
        if content.authorization_id() != self.material.authorization_id()
            || content.authorization_revision() != self.material.revision()
        {
            return Err(TaskAuthorizationErrorV2::ActionMismatch);
        }
        if content.pre_state_digest() != current.pre_state_digest
            || content.pre_state_revision() != current.pre_state_revision
        {
            return Err(TaskAuthorizationErrorV2::StateMismatch);
        }
        let clause = self.clause(content.clause_id())?;
        let index = usize::try_from(content.alternative_index())
            .map_err(|_| TaskAuthorizationErrorV2::ActionMismatch)?;
        if clause.alternatives().get(index) != Some(content.action())
            || content.magnitude() > clause.maximum_single_magnitude()
        {
            return Err(TaskAuthorizationErrorV2::ActionMismatch);
        }
        let candidates = self.candidate_domain(content.clause_id(), current.now)?;
        if content.candidate_domain_digest() != candidates.digest {
            return Err(TaskAuthorizationErrorV2::CandidateMismatch);
        }
        let content_digest = action_content_digest_v2(content)
            .map_err(|_| TaskAuthorizationErrorV2::ActionMismatch)?;
        Ok(VerifiedTaskMatchV2 {
            authorization: self.clone(),
            content: content.clone(),
            content_digest,
            candidates,
            deployment_generation: current.deployment_generation,
        })
    }
}
/// A snapshot supplied by the trusted durable owner. This is not itself a proof
/// of remaining budget/dependency satisfaction, nor a dispatch capability.
#[derive(Debug, Clone, Copy)]
pub struct TaskMatchContextV2<'a> {
    pub current_authorization: Option<&'a VerifiedTaskAuthorizationV2>,
    pub pre_state_digest: Digest32V2,
    pub pre_state_revision: u64,
    pub deployment_generation: u64,
    pub now: UnixMillisV2,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompleteContractDomainV2 {
    digest: Digest32V2,
    source_digest: Digest32V2,
    epoch: u64,
    clause_id: u64,
    candidate_count: u64,
    not_before: UnixMillisV2,
    expires_at: UnixMillisV2,
}
impl CompleteContractDomainV2 {
    pub fn digest(&self) -> Digest32V2 {
        self.digest
    }
    pub fn source_digest(&self) -> Digest32V2 {
        self.source_digest
    }
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    pub fn clause_id(&self) -> u64 {
        self.clause_id
    }
    pub fn candidate_count(&self) -> u64 {
        self.candidate_count
    }
    pub fn not_before(&self) -> UnixMillisV2 {
        self.not_before
    }
    pub fn expires_at(&self) -> UnixMillisV2 {
        self.expires_at
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedTaskMatchV2 {
    authorization: VerifiedTaskAuthorizationV2,
    content: ActionContentV2,
    content_digest: Digest32V2,
    candidates: CompleteContractDomainV2,
    deployment_generation: u64,
}
impl VerifiedTaskMatchV2 {
    pub fn deployment_generation(&self) -> u64 {
        self.deployment_generation
    }
    pub fn authorization(&self) -> &VerifiedTaskAuthorizationV2 {
        &self.authorization
    }
    pub fn content(&self) -> &ActionContentV2 {
        &self.content
    }
    pub fn content_digest(&self) -> Digest32V2 {
        self.content_digest
    }
    pub fn candidates(&self) -> &CompleteContractDomainV2 {
        &self.candidates
    }
    pub fn clause(&self) -> &TaskAuthorizationClauseV2 {
        self.authorization
            .clause(self.content.clause_id())
            .expect("verified immutable clause")
    }
    pub fn recheck(
        &self,
        current: &TaskMatchContextV2<'_>,
    ) -> Result<(), TaskAuthorizationErrorV2> {
        if current.deployment_generation != self.deployment_generation {
            return Err(TaskAuthorizationErrorV2::StateMismatch);
        }
        self.authorization
            .match_action(&self.content, current)
            .map(|_| ())
    }
}
/// Wire effects are sequential enum tags; policy effects are bit masks.
pub const fn task_effect_set_v2(effect: TaskEffectV2) -> EffectSetV2 {
    match effect {
        TaskEffectV2::Read => EffectSetV2::READ,
        TaskEffectV2::Create => EffectSetV2::CREATE,
        TaskEffectV2::Update => EffectSetV2::UPDATE,
        TaskEffectV2::Delete => EffectSetV2::DELETE,
        TaskEffectV2::Send => EffectSetV2::SEND,
        TaskEffectV2::Execute => EffectSetV2::EXECUTE,
        TaskEffectV2::FinalRelease => EffectSetV2::FINAL_RELEASE,
    }
}
