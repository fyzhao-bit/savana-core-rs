//! Deterministic private task/tool compilation. Never infer authority from prose,
//! a model, tool output, or an evaluator's expected answer.
use super::{
    ActiveToolRegistryV2, FusedDeliverySlotV04, FusedPlanningProfileV04, G4Error,
    VerifiedTaskAuthorizationV2,
};
use savana_continuation_core::planning::{Operation, Policy, Round, SlotBinding, Template};
use savana_kernel_protocol::v2::{BusinessFieldRoleV2, Digest32V2, RoleIdV2, UnixMillisV2};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// An administrator-authored finite task skeleton. Contains no raw data, signing
/// key, tool capability or tool schema asserted by the model. The signed live
/// descriptor, not this draft, determines argument roles and implementation.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FusedTaskDraftV04 {
    pub schema: u16,
    pub root: [u8; 32],
    pub observer_scope: [u8; 32],
    pub not_before: u64,
    pub expires_at: u64,
    pub operations: Vec<FusedTaskOperationV04>,
    pub templates: Vec<Template>,
    pub rounds: Vec<Round>,
    pub delivery_schedule: Vec<FusedDeliverySlotV04>,
    pub release_model_views: bool,
    pub max_replacements: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub final_result_source: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub final_release: Option<super::fused_planning::FusedFinalReleaseV04>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FusedTaskOperationV04 {
    pub id: u16,
    pub clause: u64,
    pub descriptor: [u8; 32],
    pub tool: String,
    pub bindings: Vec<SlotBinding>,
    /// Additional dependencies can restrict, never remove, signed prerequisites.
    pub after: Vec<u16>,
}

impl FusedTaskDraftV04 {
    pub fn signing_digest(&self) -> Result<[u8; 32], G4Error> {
        if !matches!(self.schema, 1 | 2 | 3)
            || (self.final_result_source.is_some() && !matches!(self.schema, 2 | 3))
            || self.final_release.as_ref().is_some_and(|r| {
                self.schema != 3
                    || self.final_result_source.is_none()
                    || r.clause == 0
                    || r.descriptor == [0; 32]
                    || r.turn == [0; 32]
            })
            || self.root == [0; 32]
            || self.observer_scope == [0; 32]
            || self.not_before >= self.expires_at
            || self.operations.is_empty()
            || self.operations.len() > 64
            || self.templates.len() > 32
            || self.rounds.len() > 16
            || self.delivery_schedule.len() > 256
            || self.operations.iter().any(|o| {
                o.id == 0
                    || o.clause == 0
                    || o.descriptor == [0; 32]
                    || o.tool.is_empty()
                    || o.tool.len() > 128
                    || o.bindings.len() > 16
                    || o.after.len() > 64
            })
            || self.operations.windows(2).any(|w| w[0].id >= w[1].id)
        {
            return Err(G4Error::StateConflict);
        }
        if let Some(source) = self.final_result_source {
            if !self.operations.iter().any(|o| o.id == source)
                || self.templates.is_empty()
                || self
                    .templates
                    .iter()
                    .any(|t| t.order.last() != Some(&source))
            {
                return Err(G4Error::StateConflict);
            }
        }
        let bytes = serde_json::to_vec(self).map_err(|_| G4Error::StateConflict)?;
        if bytes.len() > 256 * 1024 {
            return Err(G4Error::StateConflict);
        }
        Ok(
            *super::task_authorization::hash_parts(b"SAVANA_FUSED_TASK_DRAFT_V04\0", &[&bytes])
                .as_bytes(),
        )
    }
}

/// Compile a complete finite skeleton against an already authenticated root and
/// the role-filtered live registry. The result is still an UNSIGNED profile:
/// admission needs administrator approval, G3 needs its independent rules, and
/// every effect still needs owned values, matching controls and G4--G7.
/// The only non-empty model view an untrusted draft may carry: the owner's
/// committed request and the round's own template ids, in this fixed canonical
/// JSON (sorted keys, no whitespace). The kernel derives it from owner material;
/// a planner can neither add nor reword text the model reads.
pub fn fused_owner_view_v04(request: &str, template_ids: &[u16]) -> Result<Vec<u8>, G4Error> {
    #[derive(Serialize)]
    struct View<'a> {
        permitted_template_ids: &'a [u16],
        request: &'a str,
    }
    serde_json::to_vec(&View {
        permitted_template_ids: template_ids,
        request,
    })
    .map_err(|_| G4Error::StateConflict)
}

/// Host check before compiling an untrusted draft, which the pure compiler cannot
/// do because it never sees owner text. `request` is the task's committed owner
/// request, or None when the host holds none; then only empty views pass.
pub fn check_fused_owner_views_v04(
    draft: &FusedTaskDraftV04,
    request: Option<&str>,
) -> Result<(), G4Error> {
    for round in &draft.rounds {
        if round.public_view.is_empty() {
            continue;
        }
        let request = request.ok_or(G4Error::StateConflict)?;
        if round.public_view != fused_owner_view_v04(request, &round.template_ids)? {
            return Err(G4Error::StateConflict);
        }
    }
    Ok(())
}

pub fn compile_fused_task_v04(
    draft: &FusedTaskDraftV04,
    parent: &VerifiedTaskAuthorizationV2,
    registry: &ActiveToolRegistryV2,
    role: RoleIdV2,
    now: UnixMillisV2,
) -> Result<FusedPlanningProfileV04, G4Error> {
    draft.signing_digest()?;
    let root = parent.material();
    if draft.root != *parent.digest().as_bytes()
        || draft.not_before < root.not_before().get()
        || draft.expires_at > root.expires_at().get()
        || now.get() < draft.not_before
        || now.get() >= draft.expires_at
        || draft.operations.len() + usize::from(draft.final_release.is_some())
            != root.clauses().len()
    {
        return Err(G4Error::StateConflict);
    }
    // Source operation id -> its owner clause, so a result edge's source clause
    // is set by the compiler (never the planner) for G4 to rebuild the rule.
    let op_clause: BTreeMap<u16, u64> = draft.operations.iter().map(|o| (o.id, o.clause)).collect();
    let mut clause_ids = BTreeMap::new();
    for op in &draft.operations {
        if clause_ids.insert(op.clause, op.id).is_some() {
            return Err(G4Error::StateConflict);
        }
    }
    if clause_ids
        .keys()
        .copied()
        .chain(draft.final_release.iter().map(|r| r.clause))
        .collect::<BTreeSet<_>>()
        != root.clauses().iter().map(|c| c.clause_id()).collect()
    {
        return Err(G4Error::StateConflict);
    }
    if let Some(release) = &draft.final_release {
        use savana_kernel_protocol::v2::*;
        if clause_ids.contains_key(&release.clause) {
            return Err(G4Error::StateConflict);
        }
        let source = draft
            .operations
            .iter()
            .find(|o| Some(o.id) == draft.final_result_source)
            .ok_or(G4Error::StateConflict)?;
        let descriptor = registry
            .resolve(Digest32V2::new(release.descriptor), role, now)
            .ok_or(G4Error::DescriptorNotActive)?
            .descriptor();
        let unsigned = descriptor.unsigned();
        let profile = unsigned.require_business_profile()?;
        let request = final_result_release_business_request_v04(
            profile,
            "final-result",
            fused_final_result_resource_v04(
                root.task(),
                source.id,
                Digest32V2::new(source.descriptor),
            )
            .map_err(|_| G4Error::StateConflict)?,
            Digest32V2::new(release.turn),
            &[],
        )
        .map_err(|_| G4Error::InvalidDescriptor)?;
        let expected = request
            .action_alternative(descriptor.descriptor_digest())
            .map_err(|_| G4Error::StateConflict)?;
        let clause = root
            .clauses()
            .iter()
            .find(|c| c.clause_id() == release.clause)
            .ok_or(G4Error::StateConflict)?;
        // Every finite operation completes before publication. No release
        // alternative may be hidden in the model-selectable operation set.
        if clause.alternatives() != [expected]
            || clause.maximum_attempts() != 1
            || clause.maximum_single_magnitude() != 1
            || clause.total_magnitude_budget() != 1
            || clause.retry_after_proven_no_effect()
            || clause
                .predecessor_clause_ids()
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
                != clause_ids.keys().copied().collect()
            || draft.not_before < unsigned.not_before().get()
            || draft.expires_at > unsigned.expires_at().get()
        {
            return Err(G4Error::StateConflict);
        }
    }
    let mut operations = Vec::new();
    let mut owner_attempts = 0_u64;
    for op in &draft.operations {
        let descriptor = registry
            .resolve(Digest32V2::new(op.descriptor), role, now)
            .ok_or(G4Error::DescriptorNotActive)?
            .descriptor();
        let unsigned = descriptor.unsigned();
        let business = unsigned.require_business_profile()?;
        if business.effect() == savana_kernel_protocol::v2::TaskEffectV2::FinalRelease
            || op.tool != business.operation()
            || op.tool != unsigned.provider_tool_id().as_str()
            || draft.not_before < unsigned.not_before().get()
            || draft.expires_at > unsigned.expires_at().get()
            || registry
                .records()
                .iter()
                .filter(|r| {
                    let u = r.descriptor().unsigned();
                    u.tool_class() == unsigned.tool_class()
                        && u.action_template() == unsigned.action_template()
                })
                .count()
                != 1
            || op.bindings.len() != business.fields().len()
            || op
                .bindings
                .iter()
                .zip(business.fields())
                .any(|(binding, field)| {
                    binding.argument != field.name()
                        // A whole-result edge (no path) may only fill the
                        // payload. A path-extracted edge may fill a Resource,
                        // Destination or Parameter, never the payload or a
                        // magnitude. Whether the owner signed THIS path/bound is
                        // checked at G4 against the signed control (the compiler
                        // sees no owner values, only slots), so a mismatch fails
                        // there; this is the structural gate only.
                        || match (binding.result_of.is_some(), binding.result_path.is_some()) {
                            (false, _) => false,
                            (true, false) => field.role() != BusinessFieldRoleV2::Payload,
                            (true, true) => matches!(
                                field.role(),
                                BusinessFieldRoleV2::Payload | BusinessFieldRoleV2::Magnitude
                            ),
                        }
                })
        {
            return Err(G4Error::InvalidDescriptor);
        }
        let clause = root
            .clauses()
            .iter()
            .find(|c| c.clause_id() == op.clause)
            .ok_or(G4Error::StateConflict)?;
        if !clause.alternatives().iter().any(|a| {
            a.tool_descriptor_digest() == descriptor.descriptor_digest()
                && a.codec_profile() == business.codec()
                && a.effect() == business.effect()
        }) {
            return Err(G4Error::StateConflict);
        }
        owner_attempts = owner_attempts.saturating_add(clause.maximum_attempts());
        // Reject malformed explicit dependencies, do not silently repair them.
        if op.after.iter().any(|id| *id == 0 || *id == op.id)
            || op.after.windows(2).any(|w| w[0] >= w[1])
        {
            return Err(G4Error::StateConflict);
        }
        let mut after: BTreeSet<_> = op.after.iter().copied().collect();
        for predecessor in clause.predecessor_clause_ids() {
            after.insert(*clause_ids.get(predecessor).ok_or(G4Error::StateConflict)?);
        }
        operations.push(Operation {
            id: op.id,
            tool_class: u16::try_from(unsigned.tool_class().get())
                .map_err(|_| G4Error::StateConflict)?,
            action_template: u16::try_from(unsigned.action_template().get())
                .map_err(|_| G4Error::StateConflict)?,
            bindings: {
                let mut bindings = op.bindings.clone();
                for binding in &mut bindings {
                    // A path edge's source clause is authoritative from the
                    // compiler; a whole-result (payload) edge carries none.
                    binding.result_source_clause =
                        match (binding.result_of, binding.result_path.is_some()) {
                            (Some(source), true) => {
                                Some(*op_clause.get(&source).ok_or(G4Error::StateConflict)?)
                            }
                            _ => None,
                        };
                }
                bindings
            },
            after: after.into_iter().collect(),
        });
    }
    // Model interaction is bounded by the owner's root, not by the draft: each
    // model delivery (planner or advisor) must be able to lead to an attempt the
    // owner signed, and a replacement needs a later round. A draft cannot claim
    // budget its own structure and root leave unused.
    let deliveries: u64 = draft
        .rounds
        .iter()
        .map(|r| u64::from(r.max_deliveries) * if r.advisor.is_some() { 2 } else { 1 })
        .sum();
    if deliveries > owner_attempts || usize::from(draft.max_replacements) >= draft.rounds.len() {
        return Err(G4Error::StateConflict);
    }
    let dynamic = draft.rounds.iter().any(|r| !r.observations.is_empty());
    let profile = FusedPlanningProfileV04 {
        schema: if draft.final_release.is_some() {
            4
        } else if draft.final_result_source.is_some() {
            3
        } else if dynamic {
            2
        } else {
            1
        },
        final_result_source: draft.final_result_source,
        final_release: draft.final_release.clone(),
        installation: *root.installation_digest().as_bytes(),
        task: *root.task().as_bytes(),
        not_before: draft.not_before,
        expires_at: draft.expires_at,
        policy: Policy {
            schema: if dynamic { 3 } else { 2 },
            root: draft.root,
            observer_scope: draft.observer_scope,
            operations,
            templates: draft.templates.clone(),
            rounds: draft.rounds.clone(),
            max_replacements: draft.max_replacements,
        },
        execution_bindings: vec![],
        release_model_views: draft.release_model_views,
        delivery_schedule: draft.delivery_schedule.clone(),
    };
    profile.signing_digest()?;
    Ok(profile)
}

#[cfg(test)]
#[path = "fused_task_compiler_tests.rs"]
mod tests;

/// Prepare-time G4 structure check for an operation that consumes a
/// result-derived value, run before ANY operation of the task executes.
///
/// A derived field's control digest commits to the owner-signed RULE (source
/// clause, path, kind, bound), never to the value, so the owner's exact values
/// (already pinned) plus the plan's declared rules fully determine the action
/// alternative. It must be one the owner signed; otherwise a planner-chosen
/// edge (a literal target, another path or bound, a different source) is
/// refused here instead of when the write is proposed after the read ran.
pub fn check_result_operation_rule_v04(
    profile: &savana_kernel_protocol::v2::BusinessProfileV2,
    descriptor: Digest32V2,
    exact: &[(String, &super::KernelValueV2)],
    derived: &BTreeMap<String, savana_kernel_protocol::v2::ResultDerivedControlV2>,
    authorization: &savana_kernel_protocol::v2::TaskAuthorizationV2,
) -> Result<(), G4Error> {
    use savana_kernel_protocol::v2::BusinessControlsV2;
    let mut fields = Vec::new();
    for field in profile.fields() {
        if matches!(
            field.role(),
            BusinessFieldRoleV2::Payload | BusinessFieldRoleV2::Magnitude
        ) || derived.contains_key(field.name())
        {
            continue;
        }
        let value = exact
            .iter()
            .find(|(name, _)| name == field.name())
            .map(|(_, value)| value)
            .ok_or(G4Error::InvalidIntentBinding)?;
        fields.push((
            field.name().to_owned(),
            value
                .business_value()
                .ok_or(G4Error::InvalidIntentBinding)?,
        ));
    }
    let alternative =
        BusinessControlsV2::from_fields_with_derived(profile, fields, derived.clone())
            .and_then(|controls| controls.action_alternative(descriptor))
            .map_err(|_| G4Error::InvalidIntentBinding)?;
    if authorization
        .clauses()
        .iter()
        .any(|clause| clause.alternatives().contains(&alternative))
    {
        Ok(())
    } else {
        Err(G4Error::StateConflict)
    }
}

/// The owner-signed result-derived rules one compiled operation declares:
/// source clause and path/bound from the compiler-set binding, kind from the
/// signed descriptor field. G4 (at prepare and at dispatch) matches under
/// exactly these.
pub fn fused_operation_derived_rules_v04(
    operation: &Operation,
    profile: &savana_kernel_protocol::v2::BusinessProfileV2,
) -> Result<Vec<(String, savana_kernel_protocol::v2::ResultDerivedControlV2)>, G4Error> {
    let mut rules = Vec::new();
    for b in &operation.bindings {
        if let (Some(source_clause), Some(path), Some(max_bytes)) = (
            b.result_source_clause,
            b.result_path.as_ref(),
            b.result_max_bytes,
        ) {
            let field = profile
                .fields()
                .iter()
                .find(|f| f.name() == b.argument)
                .ok_or(G4Error::InvalidIntentBinding)?;
            // A list edge fills exactly a text-list field, and only a text
            // field can be computed: the binding cannot reshape the field.
            if b.result_list
                != (field.kind() == savana_kernel_protocol::v2::BusinessFieldTypeV2::TextList)
                || (b.result_compute.is_some()
                    && field.kind() != savana_kernel_protocol::v2::BusinessFieldTypeV2::Text)
            {
                return Err(G4Error::InvalidIntentBinding);
            }
            let mut rule = savana_kernel_protocol::v2::ResultDerivedControlV2::new(
                source_clause,
                path.clone(),
                field.kind(),
                max_bytes,
            )
            .map_err(|_| G4Error::InvalidIntentBinding)?;
            if let Some(compute) = b.result_compute {
                use savana_kernel_protocol::v2::{ResultComputeOpV2, ResultComputeV2};
                let op = ResultComputeOpV2::from_code(compute.op.code())
                    .ok_or(G4Error::InvalidIntentBinding)?;
                rule = rule
                    .with_compute(
                        ResultComputeV2::new(op, compute.amount)
                            .map_err(|_| G4Error::InvalidIntentBinding)?,
                    )
                    .map_err(|_| G4Error::InvalidIntentBinding)?;
            }
            rules.push((b.argument.clone(), rule));
        }
    }
    Ok(rules)
}
