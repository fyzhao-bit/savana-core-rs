//! Separate, exact-G4 recipe evidence. NOT a G6 approval or a G7 capability.
//!
//! The exact V04 execution commitment remains unchanged. This type requires
//! neutral owned-slot witnesses that reconstruct every exact task-linked G4
//! argument before it can describe a reusable business recipe. No raw digest,
//! JSON, model response or deserialized recipe can construct this type.
use minicbor::Encode as _;
use savana_kernel_protocol::v2::{ActionContentV2, Digest32V2};
use zeroize::Zeroizing;

use super::{
    G4Error, VerifiedActionIntentMaterialV2, VerifiedInternalSlotMaterialV2,
    VerifiedResolvedRelationSetV2, VerifiedTaskMatchV2,
};

/// Private exact-draft evidence; redacted Debug, no Serialize/Deserialize.
/// Matching evidence alone permits no execution and does not carry forward G6.
/// G7 additionally requires the signed recipe allowlist and all live gate checks.
#[derive(Clone)]
pub struct FusedExecutionRecipeV04 {
    commitment: [u8; 32],
    exact_material: Digest32V2,
    exact_content: Digest32V2,
    pub(super) root: Digest32V2,
    pub(super) generation: u64,
}

impl std::fmt::Debug for FusedExecutionRecipeV04 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FusedExecutionRecipeV04(<private checked evidence>)")
    }
}

impl FusedExecutionRecipeV04 {
    pub fn from_verified_g4(
        material: &VerifiedActionIntentMaterialV2,
        matched: &VerifiedTaskMatchV2,
        neutral_slots: &[VerifiedInternalSlotMaterialV2],
    ) -> Result<Self, G4Error> {
        let content = matched.content();
        if neutral_slots.is_empty()
            || neutral_slots.len() > 256
            || neutral_slots.len() != material.normalized_arguments.len()
            || material.binding.plan_revision_digest.as_bytes()
                != content.plan_revision_digest().as_bytes()
            || material.binding.provenance_set_digest != content.provenance_digest()
            || material.binding.tool_descriptor_digest != content.action().tool_descriptor_digest()
        {
            return Err(G4Error::InvalidIntentBinding);
        }
        let relations =
            VerifiedResolvedRelationSetV2::from_task_match(neutral_slots.len() as u16, matched)?;
        for (i, (slot, argument)) in neutral_slots
            .iter()
            .zip(&material.normalized_arguments)
            .enumerate()
        {
            slot.check_fused_recipe_witness(i, argument, &relations)?;
        }

        // Deliberately enumerate the semantic recipe. The actual intent, slot
        // relations, display and content are NEVER overwritten or reauthorized.
        // Keep the original logical step/request identity, root, deployment,
        // complete source witnesses, descriptors, tokens and effect parameters.
        let stable_content = ActionContentV2::new(
            content.authorization_id(),
            content.authorization_revision(),
            content.clause_id(),
            content.alternative_index(),
            content.action().clone(),
            content.magnitude(),
            content.payload_digest(),
            content.provenance_digest(),
            Digest32V2::new([1; 32]),
            content.candidate_domain_digest(),
            Digest32V2::new([1; 32]),
            0,
        )
        .map_err(|_| G4Error::InvalidIntentBinding)?;
        let stable_content_digest =
            savana_kernel_protocol::v2::action_content_digest_v2(&stable_content)
                .map_err(|_| G4Error::BindingDigestFailure)?;
        let mut bytes = Zeroizing::new(Vec::new());
        let mut encoder = minicbor::Encoder::new(&mut *bytes);
        let encoded = (|| {
            let e = &mut encoder;
            e.array(10)?.u16(1)?;
            matched.authorization().digest().encode(e, &mut ())?;
            e.u64(matched.deployment_generation())?;
            let b = &material.binding;
            // No plan revision or current rendered display result here. The
            // display implementation remains pinned, and G6 must use the exact
            // current display. This is not an approval to omit that check.
            e.array(9)?;
            b.internal_step_id.encode(e, &mut ())?;
            b.tool_descriptor_digest.encode(e, &mut ())?;
            b.argument_digest.encode(e, &mut ())?;
            b.provenance_set_digest.encode(e, &mut ())?;
            b.token_set_digest.encode(e, &mut ())?;
            b.destination_digest.encode(e, &mut ())?;
            b.display_projection_digest.encode(e, &mut ())?;
            b.executor_identity_digest.encode(e, &mut ())?;
            b.attempt_kind.encode(e, &mut ())?;
            e.bytes(&material.selected_descriptor_canonical)?;
            e.array(4)?;
            material.descriptor_publisher_key_id.encode(e, &mut ())?;
            e.u32(material.registry_ordinal)?;
            material.policy_activation_digest.encode(e, &mut ())?;
            material.effective_retry_policy.encode(e, &mut ())?;
            e.array(neutral_slots.len() as u64)?;
            for (slot, argument) in neutral_slots.iter().zip(&material.normalized_arguments) {
                e.array(2)?;
                argument.argument_name.encode(e, &mut ())?;
                // Includes run, installation, manifest, ordinal, type,
                // cardinality, confidentiality, value ID/digest and provenance.
                slot.encode(e, &mut ())?;
            }
            e.array(material.token_bindings.len() as u64)?;
            for token in &material.token_bindings {
                e.array(4)?;
                token.token_slot_id.encode(e, &mut ())?;
                token.vault_segment_internal_id.encode(e, &mut ())?;
                token.credential_version_digest.encode(e, &mut ())?;
                token.executor_identity_digest.encode(e, &mut ())?;
            }
            let p = &material.projection_outputs;
            e.array(7)?;
            p.tool_descriptor_digest.encode(e, &mut ())?;
            p.destination_projection.encode(e, &mut ())?;
            p.destination_projection_digest.encode(e, &mut ())?;
            e.bytes(p.destination_canonical())?;
            p.destination_digest.encode(e, &mut ())?;
            p.display_projection.encode(e, &mut ())?;
            p.display_projection_digest.encode(e, &mut ())?;
            stable_content_digest.encode(e, &mut ())
        })();
        encoded.map_err(|_| G4Error::BindingDigestFailure)?;
        Ok(Self {
            commitment: *super::task_authorization::hash_parts(
                b"SAVANA_FUSED_EXECUTION_RECIPE_V04_SCHEMA1\0",
                &[bytes.as_slice()],
            )
            .as_bytes(),
            exact_material: super::intent::action_intent_material_digest_v2(material)?,
            exact_content: matched.content_digest(),
            root: matched.authorization().digest(),
            generation: matched.deployment_generation(),
        })
    }

    /// For the separately versioned recipe-approval workflow only.
    /// Never insert this into legacy exact execution bindings.
    pub fn commitment(&self) -> [u8; 32] {
        self.commitment
    }

    /// Check that this private evidence has not been moved to another draft.
    /// Even a same-recipe recompile must construct its own exact evidence.
    pub fn matches_exact_draft(
        &self,
        material: &VerifiedActionIntentMaterialV2,
        content: &ActionContentV2,
    ) -> Result<bool, G4Error> {
        Ok(
            self.exact_material == super::intent::action_intent_material_digest_v2(material)?
                && self.exact_content
                    == savana_kernel_protocol::v2::action_content_digest_v2(content)
                        .map_err(|_| G4Error::BindingDigestFailure)?,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v2::*;
    use savana_kernel_protocol::v2::{
        ActionAlternativeV2, ActionCodecProfileV2, DurableRunIdV2, DurableTaskIdV2,
        ExecutorIdentityV2, InternalStepIdV2, MagnitudeUnitV2, PlanRevisionDigestV2, SlotKindV2,
        TaskEffectV2, UnixMillisV2, ValueInternalIdV2,
    };

    fn d(n: u8) -> Digest32V2 {
        Digest32V2::new([n; 32])
    }
    // Static proof fixture, not evidence of live durable/G7 acceptance. Real
    // owned-store G4 recompilation is covered by the kernel compiler tests.
    fn fixture(
        plan: u8,
        pre_state: u8,
        generation: u64,
        magnitude: u64,
        root_revision: u64,
    ) -> (
        VerifiedActionIntentMaterialV2,
        VerifiedTaskMatchV2,
        Vec<VerifiedInternalSlotMaterialV2>,
    ) {
        let neutral = VerifiedInternalSlotMaterialV2::from_resolved_envelope(
            d(2),
            d(3),
            DurableRunIdV2::new([40; 32]),
            0,
            SlotKindV2::new(1),
            ClosedCardinalityV2::ExactlyOne,
            PlannerSlotConfidentialityV2::ConfidentialAbstract,
            vec![],
            ValueInternalIdV2::new([41; 32]),
            d(42),
            d(43),
            &VerifiedResolvedRelationSetV2::from_verified_plan_envelope(1, vec![]).unwrap(),
        )
        .unwrap();
        let binding = ToolExecutionSemanticBindingV2::from_verified_authorization(
            PlanRevisionDigestV2::new([plan; 32]),
            InternalStepIdV2::new([5; 32]),
            d(6),
            d(7),
            d(8),
            d(9),
            d(10),
            d(11),
            d(12),
            ExecutorIdentityV2::new([13; 32]),
            AttemptKindV2::ToolWrite,
        )
        .unwrap();
        let mut material = VerifiedActionIntentMaterialV2::new_for_test(
            binding,
            vec![StableActionArgumentBindingV2::new_for_test(
                ArgumentNameV2::new("body").unwrap(),
                neutral.internal_slot_digest().unwrap(),
                ValueInternalIdV2::new([41; 32]),
                d(42),
                d(43),
            )],
            1,
        );
        let action = ActionAlternativeV2::new(
            material.binding.tool_descriptor_digest,
            ActionCodecProfileV2::FixedJsonPostV1,
            TaskEffectV2::Send,
            d(14),
            d(15),
            d(16),
            MagnitudeUnitV2::Count,
        )
        .unwrap();
        let root = crate::v2::durable_tests::signed_task(
            DurableTaskIdV2::new([17; 32]),
            root_revision,
            vec![crate::v2::durable_tests::task_clause(
                1,
                action.clone(),
                5,
                5,
                vec![],
                false,
            )],
        );
        let content = ActionContentV2::new(
            root.material().authorization_id(),
            root_revision,
            1,
            0,
            action,
            magnitude,
            d(18),
            material.binding.provenance_set_digest,
            d(plan),
            root.candidate_domain(1, UnixMillisV2::new(10))
                .unwrap()
                .digest(),
            d(pre_state),
            u64::from(pre_state),
        )
        .unwrap();
        let matched = root
            .match_action(
                &content,
                &TaskMatchContextV2 {
                    current_authorization: Some(&root),
                    pre_state_digest: d(pre_state),
                    pre_state_revision: u64::from(pre_state),
                    deployment_generation: generation,
                    now: UnixMillisV2::new(10),
                },
            )
            .unwrap();
        material.normalized_arguments[0].internal_slot_digest = neutral
            .clone()
            .with_task_relation(
                &VerifiedResolvedRelationSetV2::from_task_match(1, &matched).unwrap(),
            )
            .unwrap()
            .internal_slot_digest()
            .unwrap();
        (material, matched, vec![neutral])
    }

    #[test]
    fn recipe_changes_context_without_transferring_exact_approval() {
        let (a, am, slots) = fixture(20, 21, 7, 1, 1);
        let ra = FusedExecutionRecipeV04::from_verified_g4(&a, &am, &slots).unwrap();
        let (b, bm, bs) = fixture(22, 23, 7, 1, 1);
        let rb = FusedExecutionRecipeV04::from_verified_g4(&b, &bm, &bs).unwrap();
        assert_eq!(ra.commitment(), rb.commitment());
        assert_ne!(
            fused_execution_commitment_v04(&a, am.content()).unwrap(),
            fused_execution_commitment_v04(&b, bm.content()).unwrap()
        );
        assert!(ra.matches_exact_draft(&a, am.content()).unwrap());
        assert!(!ra.matches_exact_draft(&b, bm.content()).unwrap());
        // The task-bound slot proof cannot be paired with another current match.
        assert!(FusedExecutionRecipeV04::from_verified_g4(&a, &bm, &slots).is_err());
        for (generation, magnitude, revision) in [(8, 1, 1), (7, 2, 1), (7, 1, 2)] {
            let (m, matched, s) = fixture(22, 23, generation, magnitude, revision);
            assert_ne!(
                ra.commitment(),
                FusedExecutionRecipeV04::from_verified_g4(&m, &matched, &s)
                    .unwrap()
                    .commitment()
            );
        }
    }

    #[test]
    fn recipe_binds_security_fields_and_never_mutates_exact_material() {
        let (material, matched, slots) = fixture(20, 21, 7, 1, 1);
        let before = material.clone();
        let original =
            FusedExecutionRecipeV04::from_verified_g4(&material, &matched, &slots).unwrap();
        assert_eq!(before, material);
        for n in 0..20 {
            let mut changed = material.clone();
            match n {
                0 => changed.binding.internal_step_id = InternalStepIdV2::new([99; 32]),
                1 => changed.binding.executor_identity_digest = d(99),
                2 => changed.selected_descriptor_canonical.push(0),
                3 => changed.policy_activation_digest = d(99),
                4 => changed.registry_ordinal += 1,
                5 => {
                    changed.descriptor_publisher_key_id =
                        savana_kernel_protocol::v2::Ed25519KeyIdV2::new([99; 32])
                }
                6 => changed.binding.destination_digest = d(99),
                7 => changed.projection_outputs.destination_canonical.push(0),
                8 => changed.projection_outputs.destination_projection_digest = d(99),
                9 => changed.projection_outputs.display_projection_digest = d(99),
                10 => changed.binding.display_projection_digest = d(99),
                11 => {
                    changed.normalized_arguments[0].argument_name =
                        ArgumentNameV2::new("other").unwrap()
                }
                12 => changed.normalized_arguments[0].value_digest = d(99),
                13 => changed.normalized_arguments[0].provenance_digest = d(99),
                14 => {
                    changed.normalized_arguments[0].value_internal_id =
                        ValueInternalIdV2::new([99; 32])
                }
                15 => changed.binding.argument_digest = d(99),
                16 => changed.binding.token_set_digest = d(99),
                17 => {
                    changed.effective_retry_policy = BoundedConnectorRetryPolicyV2::new(
                        ExecutorIdempotencyContractV2::ConnectorIdempotentByExecutionNonce,
                        2,
                        1,
                    )
                    .unwrap()
                }
                18 => changed.token_bindings.push(ResolvedStoredTokenV2 {
                    token_slot_id: IdentifierV2::new("credential").unwrap(),
                    vault_segment_internal_id: d(96),
                    credential_version_digest: d(97),
                    executor_identity_digest: d(98),
                }),
                _ => changed.binding.attempt_kind = AttemptKindV2::ToolRead,
            }
            if let Ok(recipe) =
                FusedExecutionRecipeV04::from_verified_g4(&changed, &matched, &slots)
            {
                assert_ne!(original.commitment(), recipe.commitment(), "mutation {n}");
            }
            assert!(!original
                .matches_exact_draft(&changed, matched.content())
                .unwrap());
        }
        // A different rendered G6 display is allowed to describe the same
        // recipe, but it is emphatically NOT covered by the old exact evidence.
        let mut display = material.clone();
        display.projection_outputs.display_canonical.push(0);
        display.projection_outputs.display_digest = d(99);
        display.binding.display_digest = d(99);
        let recipe = FusedExecutionRecipeV04::from_verified_g4(&display, &matched, &slots).unwrap();
        assert_eq!(original.commitment(), recipe.commitment());
        assert!(!original
            .matches_exact_draft(&display, matched.content())
            .unwrap());
    }

    #[test]
    fn recipe_preserves_run_type_cardinality_and_confidentiality_in_slot_witnesses() {
        let (material, matched, slots) = fixture(20, 21, 7, 1, 1);
        let original =
            FusedExecutionRecipeV04::from_verified_g4(&material, &matched, &slots).unwrap();
        let empty = VerifiedResolvedRelationSetV2::from_verified_plan_envelope(1, vec![]).unwrap();
        let relation = VerifiedResolvedRelationSetV2::from_task_match(1, &matched).unwrap();
        for n in 0..4 {
            let slot = VerifiedInternalSlotMaterialV2::from_resolved_envelope(
                d(2),
                d(3),
                DurableRunIdV2::new([if n == 0 { 99 } else { 40 }; 32]),
                0,
                SlotKindV2::new(if n == 1 { 2 } else { 1 }),
                if n == 2 {
                    ClosedCardinalityV2::ZeroOrOne
                } else {
                    ClosedCardinalityV2::ExactlyOne
                },
                if n == 3 {
                    PlannerSlotConfidentialityV2::PublicStructural
                } else {
                    PlannerSlotConfidentialityV2::ConfidentialAbstract
                },
                vec![],
                ValueInternalIdV2::new([41; 32]),
                d(42),
                d(43),
                &empty,
            )
            .unwrap();
            assert!(FusedExecutionRecipeV04::from_verified_g4(
                &material,
                &matched,
                &[slot.clone()]
            )
            .is_err());
            let mut changed = material.clone();
            changed.normalized_arguments[0].internal_slot_digest = slot
                .clone()
                .with_task_relation(&relation)
                .unwrap()
                .internal_slot_digest()
                .unwrap();
            let recipe =
                FusedExecutionRecipeV04::from_verified_g4(&changed, &matched, &[slot]).unwrap();
            assert_ne!(original.commitment(), recipe.commitment(), "slot field {n}");
        }
    }
}
