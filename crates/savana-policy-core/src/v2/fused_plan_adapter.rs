//! Pure lowering into the existing V2 candidate format, never a commit or ticket.
use super::G4Error;
use savana_continuation_core::planning::CompiledPlan;
use savana_kernel_protocol::v2::{
    encode_planner_plan_v2, ActionTemplateIdV2, ActiveToolViewV2, ArgumentNameV2, Digest32V2,
    PlannerEnvelopeV2, PlannerPlanV2, PlannerSlotRefV2, PlannerStepV2, ToolClassIdV2, UnixMillisV2,
};
use std::collections::{BTreeMap, BTreeSet};

/// Local binding is provided by the trusted host, never accepted in model output.
/// Stable local slot keys are mapped to fresh slots from this kernel envelope.
/// Kernel-owned value binding and the per-action G4-G7 gates remain mandatory.
pub fn lower_fused_plan_v04(
    compiled: &CompiledPlan,
    expected_policy: Digest32V2,
    envelope: &PlannerEnvelopeV2,
    slot_bindings: &[([u8; 16], PlannerSlotRefV2)],
    active_tools: &[ActiveToolViewV2],
    now: UnixMillisV2,
) -> Result<PlannerPlanV2, G4Error> {
    if active_tools.len() > 4096 {
        return Err(G4Error::StateConflict);
    }
    let tools = active_tools
        .iter()
        .map(|t| (t.tool_class(), t.action_template()))
        .collect::<Vec<_>>();
    lower_fused_plan_with_tools_v04(
        compiled,
        expected_policy,
        envelope,
        slot_bindings,
        &tools,
        now,
    )
}

/// Host-private lowering without fabricating public tool handles. The caller
/// must obtain these pairs from its live role-filtered descriptor registry and
/// still resolve the exact descriptor at G4. This function issues no authority.
pub fn lower_fused_plan_with_tools_v04(
    compiled: &CompiledPlan,
    expected_policy: Digest32V2,
    envelope: &PlannerEnvelopeV2,
    slot_bindings: &[([u8; 16], PlannerSlotRefV2)],
    active_tools: &[(ToolClassIdV2, ActionTemplateIdV2)],
    now: UnixMillisV2,
) -> Result<PlannerPlanV2, G4Error> {
    let limits = envelope.effective_limits();
    if compiled.policy() != *expected_policy.as_bytes()
        || now.get() >= envelope.expires_at().get()
        || compiled.operations().len() > usize::from(limits.maximum_steps())
        || slot_bindings.len() > 256
        || active_tools.len() > 4096
    {
        return Err(G4Error::StateConflict);
    }
    let mut slots = BTreeMap::new();
    let mut actual_slots = BTreeSet::new();
    for (local, actual) in slot_bindings {
        if *local == [0; 16]
            || !envelope.slots().iter().any(|s| s.reference() == *actual)
            || slots.insert(*local, *actual).is_some()
            || !actual_slots.insert(*actual.as_bytes())
        {
            return Err(G4Error::StateConflict);
        }
    }
    let required_slots: BTreeSet<_> = compiled
        .operations()
        .iter()
        .flat_map(|o| o.bindings.iter().map(|b| b.slot))
        .collect();
    if slots.keys().copied().collect::<BTreeSet<_>>() != required_slots {
        return Err(G4Error::StateConflict);
    }
    let positions: BTreeMap<_, _> = compiled
        .operations()
        .iter()
        .enumerate()
        .map(|(i, o)| (o.id, (i + 1) as u16))
        .collect();
    let mut steps = Vec::new();
    for operation in compiled.operations() {
        let action = ActionTemplateIdV2::new(u32::from(operation.action_template));
        let class = ToolClassIdV2::new(u32::from(operation.tool_class));
        if !envelope.allowed_action_templates().contains(&action)
            || active_tools
                .iter()
                .filter(|(c, a)| *a == action && *c == class)
                .count()
                != 1
            || operation.after.len() > usize::from(limits.maximum_dependencies_per_step())
            || operation.bindings.len() > usize::from(limits.maximum_arguments_per_step())
        {
            return Err(G4Error::StateConflict);
        }
        let bindings = operation
            .bindings
            .iter()
            .map(|b| {
                Ok((
                    ArgumentNameV2::new(b.argument.clone()).map_err(|_| G4Error::StateConflict)?,
                    *slots.get(&b.slot).ok_or(G4Error::StateConflict)?,
                ))
            })
            .collect::<Result<Vec<_>, G4Error>>()?;
        let mut deps = operation
            .after
            .iter()
            .map(|id| positions.get(id).copied().ok_or(G4Error::StateConflict))
            .collect::<Result<Vec<_>, _>>()?;
        deps.sort_unstable();
        steps.push(
            PlannerStepV2::new(positions[&operation.id], action, class, bindings, deps)
                .map_err(|_| G4Error::StateConflict)?,
        );
    }
    let plan =
        PlannerPlanV2::new(envelope.envelope_nonce(), steps).map_err(|_| G4Error::StateConflict)?;
    if encode_planner_plan_v2(&plan)
        .map_err(|_| G4Error::StateConflict)?
        .len()
        > limits.maximum_encoded_plan_bytes() as usize
    {
        return Err(G4Error::StateConflict);
    }
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;
    use savana_continuation_core::planning::*;
    use savana_kernel_protocol::v2::*;

    fn compiled() -> CompiledPlan {
        let p = Policy {
            schema: 1,
            root: [1; 32],
            observer_scope: [2; 32],
            operations: (1..=2)
                .map(|id| Operation {
                    id,
                    tool_class: id,
                    action_template: id,
            bindings: vec![SlotBinding {
                result_of: None,
                result_path: None,
                result_max_bytes: None,
                        argument: "input".into(),
                        slot: [id as u8; 16],
                    }],
                    after: if id == 1 { vec![] } else { vec![1] },
                })
                .collect(),
            templates: vec![Template {
                id: 1,
                order: vec![1, 2],
            }],
            rounds: vec![Round {
                observations: vec![],
                id: 1,
                opens_at: 1,
                advice_cut: 1,
                closes_at: 10,
                advisor: None,
                planner: [3; 32],
                model_profile: 1,
                mode: Mode::RegisteredTemplateV04,
                public_view: vec![],
                template_ids: vec![1],
                question_codes: vec![],
                max_deliveries: 1,
            }],
            max_replacements: 0,
        };
        let mut s = PlanningState::new(p, vec![(None, [4; 16])]).unwrap();
        s.freeze_envelope(1, 1).unwrap();
        let v = s.reserve_delivery(1, Role::Planner, [3; 32], 1).unwrap();
        let proposal = PlanProposal {
            schema: 1,
            job: v.job,
            view: v.commitment(),
            choice: PlanChoice::RegisteredTemplate { template: 1 },
        };
        s.accept_plan(1, [3; 32], &serde_json::to_vec(&proposal).unwrap(), 1)
            .unwrap();
        s.compiled(1).unwrap()
    }
    fn envelope(limits: PlannerLimitsV2) -> PlannerEnvelopeV2 {
        PlannerEnvelopeV2::new(
            PlannerRouteIdV2::new(1),
            StaticTemplateIdV2::new(1),
            PlannerIntentKindV2::Search,
            vec![ActionTemplateIdV2::new(1), ActionTemplateIdV2::new(2)],
            (1..=2)
                .map(|id| {
                    PlannerAbstractSlotV2::new(
                        PlannerSlotRefV2::new([id + 10; 16]),
                        SlotKindV2::new(1),
                        PlannerSlotCardinalityV2::ExactlyOne,
                        PlannerSlotConfidentialityV2::ConfidentialAbstract,
                    )
                    .unwrap()
                })
                .collect(),
            vec![],
            limits,
            Nonce32V2::new([5; 32]),
            UnixMillisV2::new(100),
        )
        .unwrap()
    }
    fn tools() -> Vec<ActiveToolViewV2> {
        (1..=2)
            .map(|id| {
                ActiveToolViewV2::new(
                    ToolHandleV2::from_authority_entropy([id as u8; 32]).unwrap(),
                    ActionTemplateIdV2::new(id),
                    ToolClassIdV2::new(id),
                    StaticTemplateIdV2::new(1),
                )
                .unwrap()
            })
            .collect()
    }
    fn slots() -> Vec<([u8; 16], PlannerSlotRefV2)> {
        vec![
            ([1; 16], PlannerSlotRefV2::new([11; 16])),
            ([2; 16], PlannerSlotRefV2::new([12; 16])),
        ]
    }

    #[test]
    fn registry_pair_lowering_matches_legacy_view_lowering_and_refuses_ambiguity() {
        let c = compiled();
        let e = envelope(PlannerLimitsV2::new(4, 4, 4, 4096).unwrap());
        let views = tools();
        let mut pairs = views
            .iter()
            .map(|t| (t.tool_class(), t.action_template()))
            .collect::<Vec<_>>();
        let legacy = lower_fused_plan_v04(
            &c,
            Digest32V2::new(c.policy()),
            &e,
            &slots(),
            &views,
            UnixMillisV2::new(1),
        )
        .unwrap();
        let local = lower_fused_plan_with_tools_v04(
            &c,
            Digest32V2::new(c.policy()),
            &e,
            &slots(),
            &pairs,
            UnixMillisV2::new(1),
        )
        .unwrap();
        assert_eq!(
            encode_planner_plan_v2(&legacy).unwrap(),
            encode_planner_plan_v2(&local).unwrap()
        );
        pairs.push(pairs[0]);
        assert!(lower_fused_plan_with_tools_v04(
            &c,
            Digest32V2::new(c.policy()),
            &e,
            &slots(),
            &pairs,
            UnixMillisV2::new(1)
        )
        .is_err());
    }

    #[test]
    fn fused_lowering_preserves_nonce_dependencies_actions_and_local_mapping() {
        let c = compiled();
        let e = envelope(PlannerLimitsV2::new(4, 4, 4, 4096).unwrap());
        let p = lower_fused_plan_v04(
            &c,
            Digest32V2::new(c.policy()),
            &e,
            &slots(),
            &tools(),
            UnixMillisV2::new(1),
        )
        .unwrap();
        assert_eq!(p.envelope_nonce(), e.envelope_nonce());
        assert_eq!(p.steps()[1].dependencies(), &[1]);
        assert_eq!(
            p.steps()[0].slot_bindings()[0].1,
            PlannerSlotRefV2::new([11; 16])
        );
    }
    #[test]
    fn fused_lowering_rejects_foreign_policy_expiry_missing_tool_and_substituted_slot() {
        let c = compiled();
        let e = envelope(PlannerLimitsV2::new(4, 4, 4, 4096).unwrap());
        assert!(lower_fused_plan_v04(
            &c,
            Digest32V2::new([99; 32]),
            &e,
            &slots(),
            &tools(),
            UnixMillisV2::new(1)
        )
        .is_err());
        assert!(lower_fused_plan_v04(
            &c,
            Digest32V2::new(c.policy()),
            &e,
            &slots(),
            &tools(),
            UnixMillisV2::new(100)
        )
        .is_err());
        assert!(lower_fused_plan_v04(
            &c,
            Digest32V2::new(c.policy()),
            &e,
            &slots(),
            &[],
            UnixMillisV2::new(1)
        )
        .is_err());
        let mut bad = slots();
        bad[0].1 = PlannerSlotRefV2::new([99; 16]);
        assert!(lower_fused_plan_v04(
            &c,
            Digest32V2::new(c.policy()),
            &e,
            &bad,
            &tools(),
            UnixMillisV2::new(1)
        )
        .is_err());
    }
    #[test]
    fn fused_lowering_checks_step_byte_limits_and_duplicate_bindings() {
        let c = compiled();
        for limits in [
            PlannerLimitsV2::new(1, 4, 4, 4096).unwrap(),
            PlannerLimitsV2::new(4, 4, 4, 1).unwrap(),
        ] {
            assert!(lower_fused_plan_v04(
                &c,
                Digest32V2::new(c.policy()),
                &envelope(limits),
                &slots(),
                &tools(),
                UnixMillisV2::new(1)
            )
            .is_err());
        }
        let e = envelope(PlannerLimitsV2::new(4, 4, 4, 4096).unwrap());
        let mut bad = slots();
        bad.push(bad[0]);
        assert!(lower_fused_plan_v04(
            &c,
            Digest32V2::new(c.policy()),
            &e,
            &bad,
            &tools(),
            UnixMillisV2::new(1)
        )
        .is_err());
    }
}
