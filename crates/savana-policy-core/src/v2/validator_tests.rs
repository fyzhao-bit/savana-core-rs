use savana_kernel_protocol::v2::{
    Digest32V2, DurableRunIdV2, DurableTaskIdV2, ExecutorIdentityV2, InternalStepIdV2,
    PlanRevisionDigestV2, VersionV2,
};

use super::{
    action_intent_id_v2, tool_execution_semantic_binding_digest_v2, ActionIntentRecordV2,
    G5DecisionBranchV2, G5DecisionIndexV2, G5DecisionResolutionKindV2, G5Error,
    G5PolicyDispositionV2, InternalValidatorImplementationKindV2, PendingCallStateRecordV2,
    PendingCallStateV2, PublicTaskStateRecordV2, PublicTaskStateV2, StoredBindingResolverV2,
    ToolExecutionSemanticBindingV2, ValidatorBuildManifestIdentityV2,
    VerifiedActionIntentMaterialV2, VerifiedG5EvaluationInputV2,
    VerifiedInternalValidatorImplementationV2, VerifiedInternalValidatorRegistryV2,
};
use crate::v2::ontology::OntologyEvaluationV2;
use crate::v2::{AttemptKindV2, InternalValidatorDeclarationV2};
use savana_kernel_protocol::v2::ImplementationIdV2;

#[test]
fn registry_activates_only_the_exact_manifest_bound_required_set() {
    let first = implementation(
        InternalValidatorImplementationKindV2::ArgumentBindingIntegrity,
        0x31,
    );
    let second = implementation(
        InternalValidatorImplementationKindV2::LabelEffectConfinement,
        0x32,
    );
    let registry = VerifiedInternalValidatorRegistryV2::from_build_manifest(vec![
        first.clone(),
        second.clone(),
    ])
    .unwrap();
    let required = vec![first.declaration(), second.declaration()];
    let active = registry.activate_exact(&required).unwrap();

    assert_eq!(active.len(), 2);
    assert_eq!(
        active.implementation_kinds(),
        &[
            InternalValidatorImplementationKindV2::ArgumentBindingIntegrity,
            InternalValidatorImplementationKindV2::LabelEffectConfinement,
        ]
    );
}

#[test]
fn registry_rejects_missing_version_build_and_implementation_mismatches() {
    let first = implementation(
        InternalValidatorImplementationKindV2::ArgumentBindingIntegrity,
        0x41,
    );
    let registry =
        VerifiedInternalValidatorRegistryV2::from_build_manifest(vec![first.clone()]).unwrap();

    assert_eq!(
        registry
            .activate_exact(&[InternalValidatorDeclarationV2::new(
                first.declaration().implementation_id(),
                VersionV2::new(1, 0, 1),
                first.declaration().build_manifest_digest(),
            )])
            .unwrap_err(),
        G5Error::ImplementationIdentityMismatch
    );
    assert_eq!(
        registry
            .activate_exact(&[InternalValidatorDeclarationV2::new(
                first.declaration().implementation_id(),
                first.declaration().semantic_version(),
                Digest32V2::new([0xee; 32]),
            )])
            .unwrap_err(),
        G5Error::ImplementationIdentityMismatch
    );
    assert_eq!(
        registry
            .activate_exact(&[InternalValidatorDeclarationV2::new(
                ImplementationIdV2::new(99),
                VersionV2::new(1, 0, 0),
                Digest32V2::new([0x55; 32]),
            )])
            .unwrap_err(),
        G5Error::MissingImplementation
    );
}

#[test]
fn registry_rejects_noncanonical_duplicate_and_over_limit_artifacts() {
    let first = implementation(
        InternalValidatorImplementationKindV2::ArgumentBindingIntegrity,
        0x61,
    );
    let second = implementation(
        InternalValidatorImplementationKindV2::LabelEffectConfinement,
        0x62,
    );
    assert_eq!(
        VerifiedInternalValidatorRegistryV2::from_build_manifest(vec![
            second.clone(),
            first.clone(),
        ])
        .unwrap_err(),
        G5Error::NonCanonicalRegistry
    );
    assert_eq!(
        VerifiedInternalValidatorRegistryV2::from_build_manifest(vec![
            first.clone(),
            first.clone(),
        ])
        .unwrap_err(),
        G5Error::DuplicateImplementation
    );
    assert_eq!(
        VerifiedInternalValidatorRegistryV2::from_build_manifest(vec![first; 33]).unwrap_err(),
        G5Error::ValidatorLimitExceeded
    );
}

#[test]
fn exact_internal_validator_set_produces_one_private_replayable_decision() {
    let implementation = implementation(
        InternalValidatorImplementationKindV2::ProjectionBindingIntegrity,
        0x71,
    );
    let registry =
        VerifiedInternalValidatorRegistryV2::from_build_manifest(vec![implementation.clone()])
            .unwrap();
    let (record, stored) = evaluation_fixture(vec![implementation.declaration()]);
    let input = VerifiedG5EvaluationInputV2::from_verified_g4(
        &record,
        &stored,
        OntologyEvaluationV2::Match,
        G5PolicyDispositionV2::permit_for_test(),
    )
    .unwrap();
    let mut decisions = G5DecisionIndexV2::new();
    let created = decisions.evaluate_or_replay(&registry, input).unwrap();
    assert_eq!(created.kind(), G5DecisionResolutionKindV2::Created);
    assert_eq!(created.branch(), G5DecisionBranchV2::Permit);
    assert_ne!(
        created.trace().decision_record_digest().as_bytes(),
        &[0; 32]
    );

    let replay_input = VerifiedG5EvaluationInputV2::from_verified_g4(
        &record,
        &stored,
        OntologyEvaluationV2::Match,
        G5PolicyDispositionV2::permit_for_test(),
    )
    .unwrap();
    let replay = decisions
        .evaluate_or_replay(&registry, replay_input)
        .unwrap();
    assert_eq!(replay.kind(), G5DecisionResolutionKindV2::Replay);
    assert_eq!(replay.branch(), created.branch());
    assert_eq!(replay.trace(), created.trace());
    assert_eq!(decisions.len(), 1);
}

#[test]
fn ontology_error_missing_implementation_and_changed_input_fail_closed() {
    let implementation = implementation(
        InternalValidatorImplementationKindV2::ProjectionBindingIntegrity,
        0x72,
    );
    let (record, stored) = evaluation_fixture(vec![implementation.declaration()]);
    let empty_registry =
        VerifiedInternalValidatorRegistryV2::from_build_manifest(Vec::new()).unwrap();
    let mut decisions = G5DecisionIndexV2::new();
    let missing = decisions
        .evaluate_or_replay(
            &empty_registry,
            VerifiedG5EvaluationInputV2::from_verified_g4(
                &record,
                &stored,
                OntologyEvaluationV2::EvaluationError,
                G5PolicyDispositionV2::permit_for_test(),
            )
            .unwrap(),
        )
        .unwrap();
    assert_eq!(missing.branch(), G5DecisionBranchV2::Deny);

    let registry =
        VerifiedInternalValidatorRegistryV2::from_build_manifest(vec![implementation]).unwrap();
    assert_eq!(
        decisions
            .evaluate_or_replay(
                &registry,
                VerifiedG5EvaluationInputV2::from_verified_g4(
                    &record,
                    &stored,
                    OntologyEvaluationV2::Match,
                    G5PolicyDispositionV2::require_approval_for_test(),
                )
                .unwrap(),
            )
            .unwrap_err(),
        G5Error::StateConflict
    );
    assert_eq!(decisions.len(), 1);
}

#[test]
fn evaluation_input_rejects_action_and_stored_binding_mismatch() {
    let (mut record, stored) = evaluation_fixture(Vec::new());
    record.material.binding.token_set_digest = Digest32V2::new([0xff; 32]);
    assert_eq!(
        VerifiedG5EvaluationInputV2::from_verified_g4(
            &record,
            &stored,
            OntologyEvaluationV2::Match,
            G5PolicyDispositionV2::permit_for_test(),
        )
        .unwrap_err(),
        G5Error::InvalidEvaluationInput
    );
}

pub(super) fn implementation(
    kind: InternalValidatorImplementationKindV2,
    build_seed: u8,
) -> VerifiedInternalValidatorImplementationV2 {
    let identity = ValidatorBuildManifestIdentityV2::new_for_test(
        kind.implementation_id(),
        VersionV2::new(1, 0, 0),
        Digest32V2::new([build_seed; 32]),
    )
    .unwrap();
    VerifiedInternalValidatorImplementationV2::from_build_manifest(kind, identity).unwrap()
}

pub(super) fn evaluation_fixture(
    required: Vec<InternalValidatorDeclarationV2>,
) -> (
    ActionIntentRecordV2,
    crate::v2::VerifiedStoredBindingsV2<'static>,
) {
    let run = DurableRunIdV2::new([4; 32]);
    let task = DurableTaskIdV2::new([5; 32]);
    let installation = Digest32V2::new([2; 32]);
    let manifest = Digest32V2::new([3; 32]);
    let executor = ExecutorIdentityV2::new([13; 32]);
    let stored =
        StoredBindingResolverV2::resolve(run, manifest, executor, &[], &[], &[], &[]).unwrap();
    let binding = ToolExecutionSemanticBindingV2::from_verified_authorization(
        PlanRevisionDigestV2::new([6; 32]),
        InternalStepIdV2::new([6; 32]),
        Digest32V2::new([7; 32]),
        stored.argument_digest(),
        stored.provenance_set_digest(),
        stored.token_set_digest(),
        Digest32V2::new([10; 32]),
        Digest32V2::new([11; 32]),
        Digest32V2::new([12; 32]),
        executor,
        AttemptKindV2::ToolWrite,
    )
    .unwrap();
    let material = VerifiedActionIntentMaterialV2::new_for_test_with_validators(
        binding,
        Vec::new(),
        6,
        required,
    );
    let semantic_binding_digest =
        tool_execution_semantic_binding_digest_v2(material.binding()).unwrap();
    let action_intent_id =
        action_intent_id_v2(installation, manifest, run, task, material.binding()).unwrap();
    (
        ActionIntentRecordV2 {
            action_intent_id,
            installation_id: installation,
            active_state_manifest_digest: manifest,
            durable_run_id: run,
            durable_task_id: task,
            stable_proposal_digest: Digest32V2::new([0x21; 32]),
            semantic_binding_digest,
            material,
            pending_call_state: PendingCallStateRecordV2 {
                action_intent_id,
                state: PendingCallStateV2::Evaluating,
            },
            public_task_state: PublicTaskStateRecordV2 {
                durable_task_id: task,
                action_intent_id,
                state: PublicTaskStateV2::Evaluating,
            },
        },
        stored,
    )
}

#[test]
fn intent_flow_confinement_blocks_untrusted_arguments_on_authorizing_effects() {
    use crate::v2::validator::intent_flow_is_confined;
    use crate::v2::{EffectSetV2, IntegrityV2};

    // Every authorizing effect refuses an `ExternalUntrusted` argument. These
    // are the integrities carried by planner output and by tool results, so
    // this is what stops fetched content from choosing the destination of a
    // state-changing call.
    for effect in [
        EffectSetV2::CREATE,
        EffectSetV2::UPDATE,
        EffectSetV2::DELETE,
        EffectSetV2::SEND,
        EffectSetV2::EXECUTE,
        EffectSetV2::FINAL_RELEASE,
    ] {
        assert!(
            !intent_flow_is_confined(effect, [IntegrityV2::ExternalUntrusted].into_iter()),
            "{effect:?} must refuse an ExternalUntrusted argument"
        );
        // One untrusted argument among trusted ones is still refused.
        assert!(!intent_flow_is_confined(
            effect,
            [
                IntegrityV2::UserAuthorized,
                IntegrityV2::ExternalUntrusted,
                IntegrityV2::KernelTrusted,
            ]
            .into_iter()
        ));
        // The ordinary path is unaffected: a recipient the user supplied
        // through ingress stays `UserAuthorized` even when the planner selects
        // it by internal id.
        assert!(intent_flow_is_confined(
            effect,
            [IntegrityV2::UserAuthorized, IntegrityV2::KernelTrusted].into_iter()
        ));
    }
}

#[test]
fn intent_flow_confinement_permits_reads_and_holds_over_effect_combinations() {
    use crate::v2::validator::intent_flow_is_confined;
    use crate::v2::{EffectSetV2, IntegrityV2};

    // A pure read may be steered by untrusted data — analysing fetched content
    // is the point. Only authorizing effects are confined.
    assert!(intent_flow_is_confined(
        EffectSetV2::READ,
        [IntegrityV2::ExternalUntrusted].into_iter()
    ));
    assert!(intent_flow_is_confined(
        EffectSetV2::EMPTY,
        [IntegrityV2::ExternalUntrusted].into_iter()
    ));
    // A read combined with any authorizing effect is confined, so a descriptor
    // cannot launder SEND past the check by also declaring READ.
    assert!(!intent_flow_is_confined(
        EffectSetV2::READ.union(EffectSetV2::SEND),
        [IntegrityV2::ExternalUntrusted].into_iter()
    ));
    assert!(!intent_flow_is_confined(
        EffectSetV2::ALL,
        [IntegrityV2::ExternalUntrusted].into_iter()
    ));
    // No arguments is vacuously confined; the fact only constrains steering
    // data that actually exists.
    assert!(intent_flow_is_confined(
        EffectSetV2::SEND,
        std::iter::empty()
    ));
}

#[test]
fn effect_authorizing_set_covers_every_effect_except_read() {
    use crate::v2::validator::EFFECT_AUTHORIZING_V2;
    use crate::v2::EffectSetV2;

    // Pin the partition so a new effect bit cannot silently land outside the
    // confined set: ALL minus READ must be exactly the authorizing set.
    assert_eq!(
        EFFECT_AUTHORIZING_V2.union(EffectSetV2::READ),
        EffectSetV2::ALL
    );
    assert!(!EFFECT_AUTHORIZING_V2.contains(EffectSetV2::READ));
    assert_eq!(
        EFFECT_AUTHORIZING_V2.bits(),
        EffectSetV2::ALL.bits() & !EffectSetV2::READ.bits()
    );
}

#[test]
fn deployment_write_tool_must_declare_intent_flow_confinement() {
    use crate::v2::validator::{
        deployment_requires_intent_flow_confinement, EFFECT_STATE_CHANGING_V2,
    };
    use crate::v2::EffectSetV2;

    let confinement = InternalValidatorDeclarationV2::new(
        InternalValidatorImplementationKindV2::IntentFlowConfinement.implementation_id(),
        VersionV2::new(1, 0, 0),
        Digest32V2::new([7; 32]),
    );
    let other = InternalValidatorDeclarationV2::new(
        InternalValidatorImplementationKindV2::ProjectionBindingIntegrity.implementation_id(),
        VersionV2::new(1, 0, 0),
        Digest32V2::new([9; 32]),
    );

    // The state-changing set is the authorizing set without final release.
    assert!(!EFFECT_STATE_CHANGING_V2.contains(EffectSetV2::FINAL_RELEASE));
    assert!(!EFFECT_STATE_CHANGING_V2.contains(EffectSetV2::READ));

    // Reads and the final-release tool ship with no validator.
    assert!(deployment_requires_intent_flow_confinement(
        EffectSetV2::READ,
        &[]
    ));
    assert!(deployment_requires_intent_flow_confinement(
        EffectSetV2::FINAL_RELEASE,
        &[]
    ));

    // Every state-changing effect needs the confinement validator; a different
    // validator (or none) is refused, the confinement one (even alongside
    // another) is accepted.
    for effect in [
        EffectSetV2::CREATE,
        EffectSetV2::UPDATE,
        EffectSetV2::DELETE,
        EffectSetV2::SEND,
        EffectSetV2::EXECUTE,
    ] {
        assert!(!deployment_requires_intent_flow_confinement(effect, &[]));
        assert!(!deployment_requires_intent_flow_confinement(
            effect,
            std::slice::from_ref(&other)
        ));
        assert!(deployment_requires_intent_flow_confinement(
            effect,
            std::slice::from_ref(&confinement)
        ));
        assert!(deployment_requires_intent_flow_confinement(
            effect,
            &[other, confinement]
        ));
        // A write that also reads still needs it.
        assert!(!deployment_requires_intent_flow_confinement(
            effect.union(EffectSetV2::READ),
            &[]
        ));
    }
}

#[test]
fn intent_flow_confinement_has_its_own_closed_implementation_id() {
    // The kind must be distinct from the five pre-existing validators and must
    // keep implementation id 6; `savana-kerneld`'s startup decoder maps that
    // tag, and a shifted id would silently activate the wrong validator.
    assert_eq!(
        InternalValidatorImplementationKindV2::IntentFlowConfinement
            .implementation_id()
            .get(),
        6
    );
    for other in [
        InternalValidatorImplementationKindV2::ArgumentBindingIntegrity,
        InternalValidatorImplementationKindV2::LabelEffectConfinement,
        InternalValidatorImplementationKindV2::RootEvidencePresence,
        InternalValidatorImplementationKindV2::ProjectionBindingIntegrity,
        InternalValidatorImplementationKindV2::TokenExecutorBinding,
    ] {
        assert_ne!(
            other.implementation_id().get(),
            InternalValidatorImplementationKindV2::IntentFlowConfinement
                .implementation_id()
                .get()
        );
    }
}

#[test]
fn decision_branch_meet_is_a_greatest_lower_bound() {
    use crate::v2::validator::G5DecisionBranchV2 as B;

    const ALL: [B; 3] = [B::Permit, B::RequireApproval, B::Deny];

    // Deny absorbs, Permit is the identity: the two properties the decision
    // path relies on when folding ontology, validators, and policy together.
    for branch in ALL {
        assert_eq!(B::Deny.meet(branch), B::Deny);
        assert_eq!(branch.meet(B::Deny), B::Deny);
        assert_eq!(B::Permit.meet(branch), branch);
        assert_eq!(branch.meet(B::Permit), branch);
        assert_eq!(branch.meet(branch), branch);
    }

    // Commutative and associative, so the fold order over the activated
    // validator set cannot change a decision.
    for left in ALL {
        for right in ALL {
            assert_eq!(left.meet(right), right.meet(left));
            for third in ALL {
                assert_eq!(
                    left.meet(right).meet(third),
                    left.meet(right.meet(third)),
                    "meet must be associative"
                );
            }
        }
    }

    assert_eq!(B::RequireApproval.meet(B::Permit), B::RequireApproval);
    assert_eq!(B::RequireApproval.meet(B::Deny), B::Deny);
}

#[test]
fn meet_never_widens_what_policy_allowed() {
    use crate::v2::validator::G5DecisionBranchV2 as B;

    const ALL: [B; 3] = [B::Permit, B::RequireApproval, B::Deny];

    // The safety invariant for the whole three-way mechanism: whatever the
    // validators say, the combined branch is never more permissive than the
    // policy disposition alone. A compromised or buggy validator can only
    // narrow authority, never grant it.
    for policy in ALL {
        for validators in ALL {
            for ontology in ALL {
                let combined = ontology.meet(validators).meet(policy);
                assert!(
                    rank(combined) <= rank(policy),
                    "combined {combined:?} must not outrank policy {policy:?}"
                );
                assert!(rank(combined) <= rank(validators));
                assert!(rank(combined) <= rank(ontology));
            }
        }
    }

    fn rank(branch: B) -> u8 {
        match branch {
            B::Deny => 0,
            B::RequireApproval => 1,
            B::Permit => 2,
        }
    }
}

#[test]
fn binding_validators_deny_and_flow_confinement_escalates() {
    use crate::v2::validator::G5DecisionBranchV2 as B;

    // The five original validators check bindings: a failure means the call is
    // malformed and no human answer repairs it, so their behaviour is
    // unchanged by the three-way mechanism.
    for kind in [
        InternalValidatorImplementationKindV2::ArgumentBindingIntegrity,
        InternalValidatorImplementationKindV2::LabelEffectConfinement,
        InternalValidatorImplementationKindV2::RootEvidencePresence,
        InternalValidatorImplementationKindV2::ProjectionBindingIntegrity,
        InternalValidatorImplementationKindV2::TokenExecutorBinding,
    ] {
        assert_eq!(kind.failure_branch(), B::Deny, "{kind:?} must keep denying");
    }

    // Intent flow confinement asks a question a person can answer — "should
    // untrusted data steer this effect?" — so it escalates instead.
    assert_eq!(
        InternalValidatorImplementationKindV2::IntentFlowConfinement.failure_branch(),
        B::RequireApproval
    );
}
