use std::cmp::Ordering;

use minicbor::Encode as _;
use savana_kernel_protocol::v2::{ActionIntentIdV2, Digest32V2, ImplementationIdV2, VersionV2};
use sha2::{Digest as _, Sha256};

use super::descriptor::decode_unsigned_descriptor;
use super::intent::projection_output_digest;
use super::ontology::OntologyEvaluationV2;
use super::{
    action_intent_id_v2, tool_execution_semantic_binding_digest_v2, ActionIntentRecordV2,
    EffectSetV2, IntegrityV2, InternalValidatorDeclarationV2, VerifiedStoredBindingsV2,
};

const MAX_INTERNAL_VALIDATORS: usize = 32;
const MAX_G5_DECISIONS: usize = 4_096;
const IMPLEMENTATION_VERSION: VersionV2 = VersionV2::new(1, 0, 0);
const EVALUATION_INPUT_DOMAIN: &[u8] = b"SAVANA_G5_EVALUATION_INPUT_V2\0";
const VALIDATOR_DECISION_DOMAIN: &[u8] = b"SAVANA_G5_VALIDATOR_DECISION_V2\0";
const DECISION_RECORD_DOMAIN: &[u8] = b"SAVANA_G5_DECISION_RECORD_V2\0";
const DESTINATION_DIGEST_DOMAIN: &[u8] = b"SAVANA_DESTINATION_V2\0";
const DISPLAY_DIGEST_DOMAIN: &[u8] = b"SAVANA_DISPLAY_V2\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum G5Error {
    #[error("G5 validator registry exceeds the compiled limit")]
    ValidatorLimitExceeded,
    #[error("G5 validator registry order is not canonical")]
    NonCanonicalRegistry,
    #[error("G5 validator implementation is duplicated")]
    DuplicateImplementation,
    #[error("G5 validator implementation identity is invalid")]
    InvalidImplementationIdentity,
    #[error("G5 required validator implementation is missing")]
    MissingImplementation,
    #[error("G5 validator version or build identity does not match")]
    ImplementationIdentityMismatch,
    #[error("G5 fallible allocation failed")]
    AllocationFailure,
    #[error("G5 evaluation input is not an exact verified G4 binding")]
    InvalidEvaluationInput,
    #[error("G5 action intent was already evaluated with different immutable input")]
    StateConflict,
    #[error("G5 decision index exceeds the compiled limit")]
    DecisionLimitExceeded,
    #[error("G5 canonical decision digest computation failed")]
    DigestFailure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum InternalValidatorImplementationKindV2 {
    ArgumentBindingIntegrity,
    LabelEffectConfinement,
    RootEvidencePresence,
    ProjectionBindingIntegrity,
    TokenExecutorBinding,
    IntentFlowConfinement,
}

impl InternalValidatorImplementationKindV2 {
    pub const fn implementation_id(self) -> ImplementationIdV2 {
        ImplementationIdV2::new(match self {
            Self::ArgumentBindingIntegrity => 1,
            Self::LabelEffectConfinement => 2,
            Self::RootEvidencePresence => 3,
            Self::ProjectionBindingIntegrity => 4,
            Self::TokenExecutorBinding => 5,
            Self::IntentFlowConfinement => 6,
        })
    }

    /// The branch this validator yields when its fact does not hold.
    ///
    /// A validator that finds a broken binding denies: the call is malformed
    /// and no human answer can repair it. A validator that finds a well-formed
    /// but risky flow escalates instead, because the question it raises —
    /// "should untrusted data steer this effect?" — is one a person can answer.
    /// The five original validators all check bindings and keep denying.
    pub(crate) const fn failure_branch(self) -> G5DecisionBranchV2 {
        match self {
            Self::ArgumentBindingIntegrity
            | Self::LabelEffectConfinement
            | Self::RootEvidencePresence
            | Self::ProjectionBindingIntegrity
            | Self::TokenExecutorBinding => G5DecisionBranchV2::Deny,
            Self::IntentFlowConfinement => G5DecisionBranchV2::RequireApproval,
        }
    }
}

/// Effects that leave the kernel or mutate state outside it. An argument whose
/// integrity is `ExternalUntrusted` never authorizes one of these: planner
/// output and tool results carry that integrity, so a value fabricated by the
/// planner or lifted out of fetched content cannot select the destination of a
/// state-changing call. `READ` is deliberately absent — untrusted data may be
/// read and analysed, it just may not authorize an effect.
pub const EFFECT_AUTHORIZING_V2: EffectSetV2 = EffectSetV2::CREATE
    .union(EffectSetV2::UPDATE)
    .union(EffectSetV2::DELETE)
    .union(EffectSetV2::SEND)
    .union(EffectSetV2::EXECUTE)
    .union(EffectSetV2::FINAL_RELEASE);

/// Authorizing effects that change state outside the kernel. This is
/// [`EFFECT_AUTHORIZING_V2`] without `FINAL_RELEASE`: releasing a result is
/// governed by the G3 declassification path, not by a per-descriptor validator,
/// and the deployment's single final-release tool deliberately ships no
/// validator. A CREATE/UPDATE/DELETE/SEND/EXECUTE tool has no such separate
/// control, so a deployment that ships one must bind `IntentFlowConfinement`.
pub const EFFECT_STATE_CHANGING_V2: EffectSetV2 = EffectSetV2::CREATE
    .union(EffectSetV2::UPDATE)
    .union(EffectSetV2::DELETE)
    .union(EffectSetV2::SEND)
    .union(EffectSetV2::EXECUTE);

/// Deployment admission rule: a descriptor that carries a state-changing effect
/// must declare the `IntentFlowConfinement` validator, so that a call binding an
/// `ExternalUntrusted` argument (planner output, or a value the kernel lifted
/// out of a tool result) escalates to owner approval at G5 instead of executing
/// silently. Returns `true` when the descriptor is allowed to ship. Reads and
/// the final-release tool need no validator and always pass. This is not the
/// core [`crate::v2::UnsignedToolDescriptorV2`] shape check (which stays
/// permissive so existing write descriptors keep their own validators); it is a
/// stricter rule a deployment generator applies to every write tool it ships.
pub fn deployment_requires_intent_flow_confinement(
    effects: EffectSetV2,
    validators: &[InternalValidatorDeclarationV2],
) -> bool {
    if effects.intersection(EFFECT_STATE_CHANGING_V2) == EffectSetV2::EMPTY {
        return true;
    }
    let required = InternalValidatorImplementationKindV2::IntentFlowConfinement.implementation_id();
    validators
        .iter()
        .any(|declaration| declaration.implementation_id() == required)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ValidatorBuildManifestIdentityV2 {
    implementation_id: ImplementationIdV2,
    semantic_version: VersionV2,
    build_manifest_digest: Digest32V2,
}

impl ValidatorBuildManifestIdentityV2 {
    pub const fn implementation_id(self) -> ImplementationIdV2 {
        self.implementation_id
    }

    pub const fn semantic_version(self) -> VersionV2 {
        self.semantic_version
    }

    pub const fn build_manifest_digest(self) -> Digest32V2 {
        self.build_manifest_digest
    }

    pub(crate) fn from_reproducible_build_manifest(
        implementation_id: ImplementationIdV2,
        semantic_version: VersionV2,
        build_manifest_digest: Digest32V2,
    ) -> Result<Self, G5Error> {
        if implementation_id.get() == 0
            || semantic_version != IMPLEMENTATION_VERSION
            || is_zero(build_manifest_digest.as_bytes())
        {
            return Err(G5Error::InvalidImplementationIdentity);
        }
        Ok(Self {
            implementation_id,
            semantic_version,
            build_manifest_digest,
        })
    }

    #[cfg(test)]
    pub(crate) fn new_for_test(
        implementation_id: ImplementationIdV2,
        semantic_version: VersionV2,
        build_manifest_digest: Digest32V2,
    ) -> Result<Self, G5Error> {
        Self::from_reproducible_build_manifest(
            implementation_id,
            semantic_version,
            build_manifest_digest,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedInternalValidatorImplementationV2 {
    kind: InternalValidatorImplementationKindV2,
    identity: ValidatorBuildManifestIdentityV2,
}

impl VerifiedInternalValidatorImplementationV2 {
    pub(crate) fn from_build_manifest(
        kind: InternalValidatorImplementationKindV2,
        identity: ValidatorBuildManifestIdentityV2,
    ) -> Result<Self, G5Error> {
        if identity.implementation_id != kind.implementation_id()
            || identity.semantic_version != IMPLEMENTATION_VERSION
            || is_zero(identity.build_manifest_digest.as_bytes())
        {
            return Err(G5Error::InvalidImplementationIdentity);
        }
        Ok(Self { kind, identity })
    }

    pub const fn kind(&self) -> InternalValidatorImplementationKindV2 {
        self.kind
    }

    pub const fn declaration(&self) -> InternalValidatorDeclarationV2 {
        InternalValidatorDeclarationV2::new(
            self.identity.implementation_id,
            self.identity.semantic_version,
            self.identity.build_manifest_digest,
        )
    }
}

#[derive(Debug, Clone)]
pub struct VerifiedInternalValidatorRegistryV2 {
    implementations: Vec<VerifiedInternalValidatorImplementationV2>,
}

impl VerifiedInternalValidatorRegistryV2 {
    pub(crate) fn from_build_manifest(
        implementations: Vec<VerifiedInternalValidatorImplementationV2>,
    ) -> Result<Self, G5Error> {
        validate_registry_shape(&implementations)?;
        Ok(Self { implementations })
    }

    pub fn activate_exact(
        &self,
        required: &[InternalValidatorDeclarationV2],
    ) -> Result<VerifiedInternalValidatorSetV2, G5Error> {
        validate_required_shape(required)?;
        let mut selected = Vec::new();
        let mut kinds = Vec::new();
        selected
            .try_reserve_exact(required.len())
            .map_err(|_| G5Error::AllocationFailure)?;
        kinds
            .try_reserve_exact(required.len())
            .map_err(|_| G5Error::AllocationFailure)?;
        for declaration in required {
            let Some(implementation) = self.implementations.iter().find(|implementation| {
                implementation.identity.implementation_id == declaration.implementation_id()
            }) else {
                return Err(G5Error::MissingImplementation);
            };
            if implementation.declaration() != *declaration {
                return Err(G5Error::ImplementationIdentityMismatch);
            }
            selected.push(implementation.clone());
            kinds.push(implementation.kind);
        }
        Ok(VerifiedInternalValidatorSetV2 {
            implementations: selected,
            kinds,
        })
    }

    pub fn len(&self) -> usize {
        self.implementations.len()
    }

    pub fn is_empty(&self) -> bool {
        self.implementations.is_empty()
    }
}

#[derive(Debug, Clone)]
pub struct VerifiedInternalValidatorSetV2 {
    implementations: Vec<VerifiedInternalValidatorImplementationV2>,
    kinds: Vec<InternalValidatorImplementationKindV2>,
}

impl VerifiedInternalValidatorSetV2 {
    pub fn len(&self) -> usize {
        self.implementations.len()
    }

    pub fn is_empty(&self) -> bool {
        self.implementations.is_empty()
    }

    pub fn implementation_kinds(&self) -> &[InternalValidatorImplementationKindV2] {
        &self.kinds
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum G5PolicyDispositionKindV2 {
    Permit,
    RequireApproval,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct G5PolicyDispositionV2(G5PolicyDispositionKindV2);

impl G5PolicyDispositionV2 {
    pub(crate) const fn from_verified_policy_permit() -> Self {
        Self(G5PolicyDispositionKindV2::Permit)
    }

    pub(crate) const fn from_verified_policy_require_approval() -> Self {
        Self(G5PolicyDispositionKindV2::RequireApproval)
    }

    pub(crate) const fn from_verified_policy_deny() -> Self {
        Self(G5PolicyDispositionKindV2::Deny)
    }

    #[cfg(test)]
    pub(crate) const fn permit_for_test() -> Self {
        Self::from_verified_policy_permit()
    }

    #[cfg(test)]
    pub(crate) const fn require_approval_for_test() -> Self {
        Self::from_verified_policy_require_approval()
    }

    const fn tag(self) -> u16 {
        match self.0 {
            G5PolicyDispositionKindV2::Permit => 1,
            G5PolicyDispositionKindV2::RequireApproval => 2,
            G5PolicyDispositionKindV2::Deny => 3,
        }
    }
}

#[derive(Debug, Clone)]
pub struct VerifiedG5EvaluationInputV2 {
    action_intent_id: ActionIntentIdV2,
    evaluation_input_digest: Digest32V2,
    required_validators: Vec<InternalValidatorDeclarationV2>,
    ontology_evaluation: OntologyEvaluationV2,
    policy_disposition: G5PolicyDispositionV2,
    validator_facts: ClosedValidatorFactsV2,
}

#[derive(Debug, Clone, Copy)]
struct ClosedValidatorFactsV2 {
    argument_binding_integrity: bool,
    label_effect_confinement: bool,
    root_evidence_presence: bool,
    projection_binding_integrity: bool,
    token_executor_binding: bool,
    intent_flow_confinement: bool,
}

impl VerifiedG5EvaluationInputV2 {
    pub(crate) fn from_verified_g4(
        record: &ActionIntentRecordV2,
        stored: &VerifiedStoredBindingsV2<'_>,
        ontology_evaluation: OntologyEvaluationV2,
        policy_disposition: G5PolicyDispositionV2,
    ) -> Result<Self, G5Error> {
        let material = record.material();
        let binding = material.binding();
        let descriptor = decode_unsigned_descriptor(material.selected_descriptor_canonical())
            .map_err(|_| G5Error::InvalidEvaluationInput)?;
        let semantic_binding_digest = tool_execution_semantic_binding_digest_v2(binding)
            .map_err(|_| G5Error::InvalidEvaluationInput)?;
        let action_intent_id = action_intent_id_v2(
            record.installation_id,
            record.active_state_manifest_digest,
            record.durable_run_id,
            record.durable_task_id,
            binding,
        )
        .map_err(|_| G5Error::InvalidEvaluationInput)?;
        let exact_arguments = material.normalized_arguments().len() == stored.arguments().len()
            && material
                .normalized_arguments()
                .iter()
                .zip(stored.arguments())
                .all(|(stable, resolved)| {
                    stable.argument_name() == resolved.argument_name()
                        && stable.internal_slot_digest() == resolved.internal_slot_digest()
                        && stable.value_internal_id() == resolved.value_internal_id()
                        && stable.value_digest() == resolved.value_digest()
                        && stable.provenance_digest() == resolved.provenance_digest()
                });
        let exact_tokens = material.token_bindings() == stored.tokens();
        let argument_binding_integrity = action_intent_id == record.action_intent_id
            && semantic_binding_digest == record.semantic_binding_digest
            && binding.argument_digest() == stored.argument_digest()
            && binding.provenance_set_digest() == stored.provenance_set_digest()
            && binding.token_set_digest() == stored.token_set_digest()
            && binding.executor_identity_digest() == stored.executor_identity_digest()
            && exact_arguments
            && exact_tokens;
        if !argument_binding_integrity {
            return Err(G5Error::InvalidEvaluationInput);
        }

        let projection = material.projection_outputs();
        let projection_binding_integrity = projection.tool_descriptor_digest
            == binding.tool_descriptor_digest
            && projection.destination_projection == descriptor.destination_projection()
            && projection.destination_projection_digest
                == descriptor.destination_projection_digest()
            && projection.display_projection == descriptor.display_projection()
            && projection.display_projection_digest == descriptor.display_projection_digest()
            && projection_output_digest(
                DESTINATION_DIGEST_DOMAIN,
                projection.destination_projection_digest,
                projection.destination_canonical(),
            ) == projection.destination_digest
            && projection_output_digest(
                DISPLAY_DIGEST_DOMAIN,
                projection.display_projection_digest,
                projection.display_canonical(),
            ) == projection.display_digest
            && projection.destination_digest == binding.destination_digest
            && projection.display_projection_digest == binding.display_projection_digest
            && projection.display_digest == binding.display_digest;
        let label_effect_confinement = stored
            .arguments()
            .iter()
            .all(|argument| argument.label().effects().contains(descriptor.effects()));
        let root_evidence_presence = stored
            .arguments()
            .iter()
            .all(|argument| !argument.root_evidence().is_empty());
        let token_executor_binding = stored
            .tokens()
            .iter()
            .all(|token| token.executor_identity_digest() == binding.executor_identity_digest());
        // A call carrying an authorizing effect must not be steered by data the
        // kernel does not trust. `label_effect_confinement` above asks which
        // effect class a value may participate in; it does not ask where the
        // value came from, and the session-wide `policy_allowed_effects` grants
        // planner output and tool results the same effect set as user input.
        // This fact closes that gap: planner output and tool results are
        // `ExternalUntrusted`, while values the user supplied through ingress
        // stay `UserAuthorized` even when the planner selects them by internal
        // id, so ordinary calls are unaffected and fetched content cannot
        // choose the destination of a state-changing call.
        let intent_flow_confinement = intent_flow_is_confined(
            descriptor.effects(),
            stored
                .arguments()
                .iter()
                .map(|argument| argument.label().integrity()),
        );
        let validator_facts = ClosedValidatorFactsV2 {
            argument_binding_integrity,
            label_effect_confinement,
            root_evidence_presence,
            projection_binding_integrity,
            token_executor_binding,
            intent_flow_confinement,
        };
        let evaluation_input_digest = evaluation_input_digest(
            record,
            stored,
            ontology_evaluation,
            policy_disposition,
            validator_facts,
        )?;
        Ok(Self {
            action_intent_id,
            evaluation_input_digest,
            required_validators: descriptor.internal_validators().to_vec(),
            ontology_evaluation,
            policy_disposition,
            validator_facts,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum G5DecisionBranchV2 {
    Permit,
    RequireApproval,
    Deny,
}

impl G5DecisionBranchV2 {
    pub(crate) const fn tag(self) -> u16 {
        match self {
            Self::Permit => 1,
            Self::RequireApproval => 2,
            Self::Deny => 3,
        }
    }

    /// Authority order on the branch lattice: `Deny < RequireApproval < Permit`.
    const fn authority(self) -> u8 {
        match self {
            Self::Deny => 0,
            Self::RequireApproval => 1,
            Self::Permit => 2,
        }
    }

    /// Greatest lower bound: the stricter of two branches.
    ///
    /// Every contributor to a decision — the ontology gate, each activated
    /// validator, and the policy disposition — can only narrow the result.
    /// `meet(x, y)` is never more permissive than either input, so no
    /// validator can widen what policy allowed.
    pub(crate) const fn meet(self, other: Self) -> Self {
        if self.authority() <= other.authority() {
            self
        } else {
            other
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicDecisionTraceV2 {
    decision_record_digest: Digest32V2,
}

impl PublicDecisionTraceV2 {
    pub const fn decision_record_digest(self) -> Digest32V2 {
        self.decision_record_digest
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum G5DecisionResolutionKindV2 {
    Created,
    Replay,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct G5DecisionResolutionV2 {
    kind: G5DecisionResolutionKindV2,
    branch: G5DecisionBranchV2,
    trace: PublicDecisionTraceV2,
}

impl G5DecisionResolutionV2 {
    pub const fn kind(self) -> G5DecisionResolutionKindV2 {
        self.kind
    }

    pub const fn branch(self) -> G5DecisionBranchV2 {
        self.branch
    }

    pub const fn trace(self) -> PublicDecisionTraceV2 {
        self.trace
    }
}

#[derive(Debug, Clone)]
pub(crate) struct G5DecisionEntryV2 {
    pub(crate) action_intent_id: ActionIntentIdV2,
    pub(crate) evaluation_input_digest: Digest32V2,
    pub(crate) branch: G5DecisionBranchV2,
    pub(crate) validator_decision_digests: Vec<Digest32V2>,
    pub(crate) decision_record_digest: Digest32V2,
}

#[derive(Debug, Clone, Default)]
pub struct G5DecisionIndexV2 {
    pub(crate) entries: Vec<G5DecisionEntryV2>,
}

impl G5DecisionIndexV2 {
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn evaluate_or_replay(
        &mut self,
        registry: &VerifiedInternalValidatorRegistryV2,
        input: VerifiedG5EvaluationInputV2,
    ) -> Result<G5DecisionResolutionV2, G5Error> {
        if let Some(entry) = self
            .entries
            .iter()
            .find(|entry| entry.action_intent_id == input.action_intent_id)
        {
            if entry.evaluation_input_digest != input.evaluation_input_digest {
                return Err(G5Error::StateConflict);
            }
            return Ok(decision_resolution(
                entry,
                G5DecisionResolutionKindV2::Replay,
            ));
        }
        if self.entries.len() >= MAX_G5_DECISIONS {
            return Err(G5Error::DecisionLimitExceeded);
        }

        let mut validator_decision_digests = Vec::new();
        validator_decision_digests
            .try_reserve_exact(input.required_validators.len())
            .map_err(|_| G5Error::AllocationFailure)?;
        let exact_set = registry.activate_exact(&input.required_validators);
        let validator_branch = match exact_set {
            Ok(set) => {
                let mut branch = G5DecisionBranchV2::Permit;
                for kind in set.implementation_kinds() {
                    let outcome = evaluate_internal_validator(*kind, input.validator_facts);
                    branch = branch.meet(outcome.branch());
                    validator_decision_digests.push(validator_decision_digest(
                        input.evaluation_input_digest,
                        *kind,
                        outcome,
                    ));
                }
                branch
            }
            // A registry that cannot activate the exact required set is not a
            // risky flow a person can adjudicate — it denies, as before.
            Err(
                G5Error::MissingImplementation
                | G5Error::ImplementationIdentityMismatch
                | G5Error::InvalidImplementationIdentity
                | G5Error::DuplicateImplementation
                | G5Error::NonCanonicalRegistry
                | G5Error::ValidatorLimitExceeded,
            ) => G5DecisionBranchV2::Deny,
            Err(error) => return Err(error),
        };
        // Every contributor can only narrow: the ontology gate, the activated
        // validators, and the policy disposition are combined by greatest lower
        // bound, so the decision is never more permissive than what policy
        // allowed and no validator can widen it.
        let ontology_branch = if input.ontology_evaluation.permits() {
            G5DecisionBranchV2::Permit
        } else {
            G5DecisionBranchV2::Deny
        };
        let policy_branch = match input.policy_disposition.0 {
            G5PolicyDispositionKindV2::Permit => G5DecisionBranchV2::Permit,
            G5PolicyDispositionKindV2::RequireApproval => G5DecisionBranchV2::RequireApproval,
            G5PolicyDispositionKindV2::Deny => G5DecisionBranchV2::Deny,
        };
        let branch = ontology_branch.meet(validator_branch).meet(policy_branch);
        let decision_record_digest = decision_record_digest(
            input.action_intent_id,
            input.evaluation_input_digest,
            branch,
            &validator_decision_digests,
        )?;
        self.entries
            .try_reserve(1)
            .map_err(|_| G5Error::AllocationFailure)?;
        let entry = G5DecisionEntryV2 {
            action_intent_id: input.action_intent_id,
            evaluation_input_digest: input.evaluation_input_digest,
            branch,
            validator_decision_digests,
            decision_record_digest,
        };
        let resolution = decision_resolution(&entry, G5DecisionResolutionKindV2::Created);
        self.entries.push(entry);
        Ok(resolution)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PrivateValidatorOutcomeV2 {
    Permit,
    RequireApproval,
    Deny,
}

impl PrivateValidatorOutcomeV2 {
    const fn branch(self) -> G5DecisionBranchV2 {
        match self {
            Self::Permit => G5DecisionBranchV2::Permit,
            Self::RequireApproval => G5DecisionBranchV2::RequireApproval,
            Self::Deny => G5DecisionBranchV2::Deny,
        }
    }
}

/// `IntentFlowConfinement`: a call that carries an authorizing effect is
/// confined only when no argument steering it is `ExternalUntrusted`. A call
/// whose effects are entirely outside [`EFFECT_AUTHORIZING_V2`] — a read — is
/// confined regardless of argument integrity.
pub(crate) fn intent_flow_is_confined(
    descriptor_effects: EffectSetV2,
    mut argument_integrities: impl Iterator<Item = IntegrityV2>,
) -> bool {
    descriptor_effects.intersection(EFFECT_AUTHORIZING_V2) == EffectSetV2::EMPTY
        || !argument_integrities.any(|integrity| integrity == IntegrityV2::ExternalUntrusted)
}

fn evaluate_internal_validator(
    kind: InternalValidatorImplementationKindV2,
    facts: ClosedValidatorFactsV2,
) -> PrivateValidatorOutcomeV2 {
    let permits = match kind {
        InternalValidatorImplementationKindV2::ArgumentBindingIntegrity => {
            facts.argument_binding_integrity
        }
        InternalValidatorImplementationKindV2::LabelEffectConfinement => {
            facts.label_effect_confinement
        }
        InternalValidatorImplementationKindV2::RootEvidencePresence => facts.root_evidence_presence,
        InternalValidatorImplementationKindV2::ProjectionBindingIntegrity => {
            facts.projection_binding_integrity
        }
        InternalValidatorImplementationKindV2::TokenExecutorBinding => facts.token_executor_binding,
        InternalValidatorImplementationKindV2::IntentFlowConfinement => {
            facts.intent_flow_confinement
        }
    };
    if permits {
        PrivateValidatorOutcomeV2::Permit
    } else {
        match kind.failure_branch() {
            G5DecisionBranchV2::Permit => PrivateValidatorOutcomeV2::Permit,
            G5DecisionBranchV2::RequireApproval => PrivateValidatorOutcomeV2::RequireApproval,
            G5DecisionBranchV2::Deny => PrivateValidatorOutcomeV2::Deny,
        }
    }
}

fn evaluation_input_digest(
    record: &ActionIntentRecordV2,
    stored: &VerifiedStoredBindingsV2<'_>,
    ontology_evaluation: OntologyEvaluationV2,
    policy_disposition: G5PolicyDispositionV2,
    facts: ClosedValidatorFactsV2,
) -> Result<Digest32V2, G5Error> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder.array(15).map_err(|_| G5Error::DigestFailure)?;
    record
        .action_intent_id
        .encode(&mut encoder, &mut ())
        .map_err(|_| G5Error::DigestFailure)?;
    record
        .semantic_binding_digest
        .encode(&mut encoder, &mut ())
        .map_err(|_| G5Error::DigestFailure)?;
    stored
        .argument_digest()
        .encode(&mut encoder, &mut ())
        .map_err(|_| G5Error::DigestFailure)?;
    stored
        .provenance_set_digest()
        .encode(&mut encoder, &mut ())
        .map_err(|_| G5Error::DigestFailure)?;
    stored
        .evidence_digest()
        .encode(&mut encoder, &mut ())
        .map_err(|_| G5Error::DigestFailure)?;
    stored
        .token_set_digest()
        .encode(&mut encoder, &mut ())
        .map_err(|_| G5Error::DigestFailure)?;
    record
        .material
        .policy_activation_digest
        .encode(&mut encoder, &mut ())
        .map_err(|_| G5Error::DigestFailure)?;
    encoder
        .u16(ontology_evaluation_tag(ontology_evaluation))
        .and_then(|encoder| encoder.u16(policy_disposition.tag()))
        .and_then(|encoder| encoder.bool(facts.argument_binding_integrity))
        .and_then(|encoder| encoder.bool(facts.label_effect_confinement))
        .and_then(|encoder| encoder.bool(facts.root_evidence_presence))
        .and_then(|encoder| encoder.bool(facts.projection_binding_integrity))
        .and_then(|encoder| encoder.bool(facts.token_executor_binding))
        .and_then(|encoder| encoder.bool(facts.intent_flow_confinement))
        .map_err(|_| G5Error::DigestFailure)?;
    Ok(domain_hash(EVALUATION_INPUT_DOMAIN, &encoder.into_writer()))
}

fn validator_decision_digest(
    evaluation_input_digest: Digest32V2,
    kind: InternalValidatorImplementationKindV2,
    outcome: PrivateValidatorOutcomeV2,
) -> Digest32V2 {
    let mut canonical = Vec::with_capacity(36);
    canonical.extend_from_slice(evaluation_input_digest.as_bytes());
    canonical.extend_from_slice(&kind.implementation_id().get().to_be_bytes());
    canonical.extend_from_slice(
        // Permit and Deny keep their original tags so a decision digest over
        // the five binding validators is unchanged by the third outcome.
        &match outcome {
            PrivateValidatorOutcomeV2::Permit => 1_u16,
            PrivateValidatorOutcomeV2::Deny => 2_u16,
            PrivateValidatorOutcomeV2::RequireApproval => 3_u16,
        }
        .to_be_bytes(),
    );
    domain_hash(VALIDATOR_DECISION_DOMAIN, &canonical)
}

pub(crate) fn decision_record_digest(
    action_intent_id: ActionIntentIdV2,
    evaluation_input_digest: Digest32V2,
    branch: G5DecisionBranchV2,
    validator_decision_digests: &[Digest32V2],
) -> Result<Digest32V2, G5Error> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder.array(4).map_err(|_| G5Error::DigestFailure)?;
    action_intent_id
        .encode(&mut encoder, &mut ())
        .map_err(|_| G5Error::DigestFailure)?;
    evaluation_input_digest
        .encode(&mut encoder, &mut ())
        .map_err(|_| G5Error::DigestFailure)?;
    encoder
        .u16(branch.tag())
        .and_then(|encoder| encoder.array(validator_decision_digests.len() as u64))
        .map_err(|_| G5Error::DigestFailure)?;
    for digest in validator_decision_digests {
        digest
            .encode(&mut encoder, &mut ())
            .map_err(|_| G5Error::DigestFailure)?;
    }
    Ok(domain_hash(DECISION_RECORD_DOMAIN, &encoder.into_writer()))
}

fn decision_resolution(
    entry: &G5DecisionEntryV2,
    kind: G5DecisionResolutionKindV2,
) -> G5DecisionResolutionV2 {
    G5DecisionResolutionV2 {
        kind,
        branch: entry.branch,
        trace: PublicDecisionTraceV2 {
            decision_record_digest: entry.decision_record_digest,
        },
    }
}

const fn ontology_evaluation_tag(value: OntologyEvaluationV2) -> u16 {
    match value {
        OntologyEvaluationV2::Match => 1,
        OntologyEvaluationV2::NoMatch => 2,
        OntologyEvaluationV2::EvaluationError => 3,
    }
}

fn domain_hash(domain: &[u8], canonical: &[u8]) -> Digest32V2 {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(canonical);
    Digest32V2::new(hasher.finalize().into())
}

fn validate_registry_shape(
    implementations: &[VerifiedInternalValidatorImplementationV2],
) -> Result<(), G5Error> {
    if implementations.len() > MAX_INTERNAL_VALIDATORS {
        return Err(G5Error::ValidatorLimitExceeded);
    }
    for implementation in implementations {
        if implementation.identity.implementation_id != implementation.kind.implementation_id()
            || implementation.identity.semantic_version != IMPLEMENTATION_VERSION
            || is_zero(implementation.identity.build_manifest_digest.as_bytes())
        {
            return Err(G5Error::InvalidImplementationIdentity);
        }
    }
    for pair in implementations.windows(2) {
        if pair[0].identity.implementation_id == pair[1].identity.implementation_id {
            return Err(G5Error::DuplicateImplementation);
        }
        if implementation_cmp(&pair[0], &pair[1]) != Ordering::Less {
            return Err(G5Error::NonCanonicalRegistry);
        }
    }
    Ok(())
}

fn validate_required_shape(required: &[InternalValidatorDeclarationV2]) -> Result<(), G5Error> {
    if required.len() > MAX_INTERNAL_VALIDATORS {
        return Err(G5Error::ValidatorLimitExceeded);
    }
    for declaration in required {
        if declaration.implementation_id().get() == 0
            || is_zero(declaration.build_manifest_digest().as_bytes())
        {
            return Err(G5Error::InvalidImplementationIdentity);
        }
    }
    for pair in required.windows(2) {
        if pair[0].implementation_id() == pair[1].implementation_id() {
            return Err(G5Error::DuplicateImplementation);
        }
        if declaration_cmp(&pair[0], &pair[1]) != Ordering::Less {
            return Err(G5Error::NonCanonicalRegistry);
        }
    }
    Ok(())
}

fn implementation_cmp(
    left: &VerifiedInternalValidatorImplementationV2,
    right: &VerifiedInternalValidatorImplementationV2,
) -> Ordering {
    declaration_cmp(&left.declaration(), &right.declaration())
}

fn declaration_cmp(
    left: &InternalValidatorDeclarationV2,
    right: &InternalValidatorDeclarationV2,
) -> Ordering {
    left.implementation_id()
        .cmp(&right.implementation_id())
        .then_with(|| left.semantic_version().cmp(&right.semantic_version()))
        .then_with(|| {
            left.build_manifest_digest()
                .as_bytes()
                .cmp(right.build_manifest_digest().as_bytes())
        })
}

fn is_zero<const N: usize>(bytes: &[u8; N]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}
