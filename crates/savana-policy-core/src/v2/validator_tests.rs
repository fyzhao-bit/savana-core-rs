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
