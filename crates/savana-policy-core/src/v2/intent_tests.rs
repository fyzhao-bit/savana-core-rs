use savana_kernel_protocol::v2::{
    Digest32V2, DisplayProjectionIdV2, DurableRunIdV2, DurableTaskIdV2, ExecutorIdentityV2,
    InternalSlotDigestV2, InternalStepIdV2, PlanRevisionDigestV2, ProjectionIdV2, RequestIdV2,
    ValueInternalIdV2,
};
use sha2::{Digest as _, Sha256};

use super::{
    action_intent_id_v2, tool_approval_binding_digest_v2,
    tool_execution_semantic_binding_digest_v2, ActionIntentIndexV2, ActionIntentResolutionKindV2,
    ActionIntentStateV2, StableActionArgumentBindingV2, ToolExecutionSemanticBindingV2,
    VerifiedActionIntentMaterialV2, VerifiedProjectionOutputsV2, VerifiedProposalRequestDigestV2,
};
use crate::v2::{ArgumentNameV2, AttemptKindV2, G4Error, KernelValueV2};

#[test]
fn semantic_binding_and_action_intent_use_the_exact_handle_free_domains() {
    let binding = binding(0x10);
    let binding_bytes = minicbor::to_vec(&binding).unwrap();
    let mut binding_hasher = Sha256::new();
    binding_hasher.update(b"SAVANA_TOOL_EXECUTION_SEMANTIC_BINDING_V2\0");
    binding_hasher.update(&binding_bytes);
    let expected_binding_digest = Digest32V2::new(binding_hasher.finalize().into());
    assert_eq!(
        tool_execution_semantic_binding_digest_v2(&binding).unwrap(),
        expected_binding_digest
    );

    let installation = Digest32V2::new([0x21; 32]);
    let manifest = Digest32V2::new([0x22; 32]);
    let run = DurableRunIdV2::new([0x23; 32]);
    let task = DurableTaskIdV2::new([0x24; 32]);
    let mut action_hasher = Sha256::new();
    action_hasher.update(b"SAVANA_ACTION_INTENT_V2\0");
    action_hasher.update(installation.as_bytes());
    action_hasher.update(manifest.as_bytes());
    action_hasher.update(run.as_bytes());
    action_hasher.update(task.as_bytes());
    action_hasher.update(expected_binding_digest.as_bytes());
    assert_eq!(
        action_intent_id_v2(installation, manifest, run, task, &binding).unwrap(),
        savana_kernel_protocol::v2::ActionIntentIdV2::new(action_hasher.finalize().into())
    );
    assert_eq!(binding_bytes.len(), 343);
}

#[test]
fn tool_approval_binding_cannot_move_between_tasks_with_the_same_semantics() {
    let binding = binding(0x30);
    let installation = Digest32V2::new([0x31; 32]);
    let manifest = Digest32V2::new([0x32; 32]);
    let run = DurableRunIdV2::new([0x33; 32]);
    let semantic = tool_execution_semantic_binding_digest_v2(&binding).unwrap();
    let first = action_intent_id_v2(
        installation,
        manifest,
        run,
        DurableTaskIdV2::new([0x34; 32]),
        &binding,
    )
    .unwrap();
    let second = action_intent_id_v2(
        installation,
        manifest,
        run,
        DurableTaskIdV2::new([0x35; 32]),
        &binding,
    )
    .unwrap();

    assert_ne!(first, second);
    assert_ne!(
        tool_approval_binding_digest_v2(first, semantic, manifest).unwrap(),
        tool_approval_binding_digest_v2(second, semantic, manifest).unwrap()
    );
}

#[test]
fn exact_replay_returns_the_same_intent_and_current_state() {
    let mut index = ActionIntentIndexV2::new();
    let first = index
        .create_or_replay(
            RequestIdV2::new([1; 16]),
            proposal(1),
            Digest32V2::new([2; 32]),
            Digest32V2::new([3; 32]),
            DurableRunIdV2::new([4; 32]),
            DurableTaskIdV2::new([5; 32]),
            material(6),
        )
        .unwrap();
    assert_eq!(first.kind(), ActionIntentResolutionKindV2::Created);
    index
        .advance_for_test(first.action_intent_id(), ActionIntentStateV2::NeedsApproval)
        .unwrap();

    let replay = index
        .create_or_replay(
            RequestIdV2::new([1; 16]),
            proposal(1),
            Digest32V2::new([2; 32]),
            Digest32V2::new([3; 32]),
            DurableRunIdV2::new([4; 32]),
            DurableTaskIdV2::new([5; 32]),
            material(6),
        )
        .unwrap();
    let new_request_replay = index
        .create_or_replay(
            RequestIdV2::new([9; 16]),
            proposal(1),
            Digest32V2::new([2; 32]),
            Digest32V2::new([3; 32]),
            DurableRunIdV2::new([4; 32]),
            DurableTaskIdV2::new([5; 32]),
            material(6),
        )
        .unwrap();

    assert_eq!(replay.kind(), ActionIntentResolutionKindV2::Replay);
    assert_eq!(replay.action_intent_id(), first.action_intent_id());
    assert_eq!(replay.current_state(), ActionIntentStateV2::NeedsApproval);
    assert_eq!(new_request_replay, replay);
    assert_eq!(index.intent_count(), 1);
    assert_eq!(index.replay_count(), 2);
}

#[test]
fn request_mutation_and_step_rebinding_fail_without_index_mutation() {
    let mut index = ActionIntentIndexV2::new();
    index
        .create_or_replay(
            RequestIdV2::new([1; 16]),
            proposal(1),
            Digest32V2::new([2; 32]),
            Digest32V2::new([3; 32]),
            DurableRunIdV2::new([4; 32]),
            DurableTaskIdV2::new([5; 32]),
            material(6),
        )
        .unwrap();
    let before = (index.intent_count(), index.replay_count());

    assert_eq!(
        index
            .create_or_replay(
                RequestIdV2::new([1; 16]),
                proposal(2),
                Digest32V2::new([2; 32]),
                Digest32V2::new([3; 32]),
                DurableRunIdV2::new([4; 32]),
                DurableTaskIdV2::new([5; 32]),
                material(7),
            )
            .unwrap_err(),
        G4Error::IdempotencyConflict
    );
    let mut rebound = material(8);
    rebound.binding.plan_revision_digest = PlanRevisionDigestV2::new([6; 32]);
    rebound.binding.internal_step_id = InternalStepIdV2::new([6; 32]);
    assert_eq!(
        index
            .create_or_replay(
                RequestIdV2::new([9; 16]),
                proposal(3),
                Digest32V2::new([2; 32]),
                Digest32V2::new([3; 32]),
                DurableRunIdV2::new([4; 32]),
                DurableTaskIdV2::new([5; 32]),
                rebound,
            )
            .unwrap_err(),
        G4Error::StateConflict
    );
    assert_eq!((index.intent_count(), index.replay_count()), before);
}

#[test]
fn byte_different_proposal_cannot_replay_the_same_semantic_intent() {
    let mut index = ActionIntentIndexV2::new();
    index
        .create_or_replay(
            RequestIdV2::new([1; 16]),
            proposal(1),
            Digest32V2::new([2; 32]),
            Digest32V2::new([3; 32]),
            DurableRunIdV2::new([4; 32]),
            DurableTaskIdV2::new([5; 32]),
            material(6),
        )
        .unwrap();
    assert_eq!(
        index
            .create_or_replay(
                RequestIdV2::new([1; 16]),
                proposal(2),
                Digest32V2::new([2; 32]),
                Digest32V2::new([3; 32]),
                DurableRunIdV2::new([4; 32]),
                DurableTaskIdV2::new([5; 32]),
                material(6),
            )
            .unwrap_err(),
        G4Error::IdempotencyConflict
    );
}

#[test]
fn same_request_and_bytes_cannot_replay_changed_verified_material() {
    let mut index = ActionIntentIndexV2::new();
    index
        .create_or_replay(
            RequestIdV2::new([1; 16]),
            proposal(1),
            Digest32V2::new([2; 32]),
            Digest32V2::new([3; 32]),
            DurableRunIdV2::new([4; 32]),
            DurableTaskIdV2::new([5; 32]),
            material(6),
        )
        .unwrap();
    let mut changed = material(6);
    changed.registry_ordinal = changed.registry_ordinal.saturating_add(1);

    assert_eq!(
        index
            .create_or_replay(
                RequestIdV2::new([1; 16]),
                proposal(1),
                Digest32V2::new([2; 32]),
                Digest32V2::new([3; 32]),
                DurableRunIdV2::new([4; 32]),
                DurableTaskIdV2::new([5; 32]),
                changed,
            )
            .unwrap_err(),
        G4Error::IdempotencyConflict
    );
    assert_eq!(index.intent_count(), 1);
    assert_eq!(index.replay_count(), 1);
}

#[test]
fn action_record_retains_the_complete_verified_material_and_rejects_material_rebinding() {
    let mut index = ActionIntentIndexV2::new();
    let original = material(6);
    let action = index
        .create_or_replay(
            RequestIdV2::new([1; 16]),
            proposal(1),
            Digest32V2::new([2; 32]),
            Digest32V2::new([3; 32]),
            DurableRunIdV2::new([4; 32]),
            DurableTaskIdV2::new([5; 32]),
            original.clone(),
        )
        .unwrap();
    let stored = index.record_for_test(action.action_intent_id()).unwrap();
    assert_eq!(stored.material(), &original);
    assert_eq!(
        stored.material().normalized_arguments()[0]
            .argument_name()
            .as_str(),
        "message"
    );
    assert!(!stored.material().selected_descriptor_canonical().is_empty());

    let mut rebound = original;
    rebound.normalized_arguments[0].internal_slot_digest = InternalSlotDigestV2::new([0xee; 32]);
    assert_eq!(
        index
            .create_or_replay(
                RequestIdV2::new([9; 16]),
                proposal(1),
                Digest32V2::new([2; 32]),
                Digest32V2::new([3; 32]),
                DurableRunIdV2::new([4; 32]),
                DurableTaskIdV2::new([5; 32]),
                rebound,
            )
            .unwrap_err(),
        G4Error::StateConflict
    );
}

#[test]
fn projection_outputs_use_exact_domains_and_forbid_internal_slots() {
    let destination = KernelValueV2::text("https://example.test").unwrap();
    let display = KernelValueV2::text("example.test").unwrap();
    let projection = VerifiedProjectionOutputsV2::new_for_test(
        Digest32V2::new([0x51; 32]),
        ProjectionIdV2::new(7),
        Digest32V2::new([0x52; 32]),
        DisplayProjectionIdV2::new(8),
        Digest32V2::new([0x53; 32]),
        &destination,
        &display,
    )
    .unwrap();
    let mut destination_hasher = Sha256::new();
    destination_hasher.update(b"SAVANA_DESTINATION_V2\0");
    destination_hasher.update([0x52; 32]);
    destination_hasher.update(minicbor::to_vec(&destination).unwrap());
    assert_eq!(
        projection.destination_digest(),
        Digest32V2::new(destination_hasher.finalize().into())
    );
    let mut display_hasher = Sha256::new();
    display_hasher.update(b"SAVANA_DISPLAY_V2\0");
    display_hasher.update([0x53; 32]);
    display_hasher.update(minicbor::to_vec(&display).unwrap());
    assert_eq!(
        projection.display_digest(),
        Digest32V2::new(display_hasher.finalize().into())
    );

    assert_eq!(
        VerifiedProjectionOutputsV2::new_for_test(
            Digest32V2::new([0x51; 32]),
            ProjectionIdV2::new(7),
            Digest32V2::new([0x52; 32]),
            DisplayProjectionIdV2::new(8),
            Digest32V2::new([0x53; 32]),
            &KernelValueV2::internal_slot(InternalSlotDigestV2::new([0x61; 32])),
            &display,
        )
        .unwrap_err(),
        G4Error::InvalidProjectionBinding
    );
}

fn proposal(seed: u8) -> VerifiedProposalRequestDigestV2 {
    VerifiedProposalRequestDigestV2::from_authenticated_canonical_request(&[seed; 8]).unwrap()
}

fn material(seed: u8) -> VerifiedActionIntentMaterialV2 {
    VerifiedActionIntentMaterialV2::new_for_test(
        binding(seed),
        vec![StableActionArgumentBindingV2::new_for_test(
            ArgumentNameV2::new("message").unwrap(),
            InternalSlotDigestV2::new([0x31; 32]),
            ValueInternalIdV2::new([0x32; 32]),
            Digest32V2::new([0x33; 32]),
            Digest32V2::new([0x34; 32]),
        )],
        seed,
    )
}

fn binding(seed: u8) -> ToolExecutionSemanticBindingV2 {
    ToolExecutionSemanticBindingV2::from_verified_authorization(
        PlanRevisionDigestV2::new([6; 32]),
        InternalStepIdV2::new([6; 32]),
        Digest32V2::new([seed; 32]),
        Digest32V2::new([7; 32]),
        Digest32V2::new([8; 32]),
        Digest32V2::new([9; 32]),
        Digest32V2::new([10; 32]),
        Digest32V2::new([11; 32]),
        Digest32V2::new([12; 32]),
        ExecutorIdentityV2::new([13; 32]),
        AttemptKindV2::ToolWrite,
    )
    .unwrap()
}
