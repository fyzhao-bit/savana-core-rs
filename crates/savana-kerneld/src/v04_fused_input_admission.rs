//! Root-only preparation from a live authenticated owner session. No arbitrary
//! administrator input values, fake provenance, automatic recipe signing or G6.
use super::*;
use savana_policy_core::v2::{FusedInputDocumentV04, FusedRecipeApprovalV04,
    FusedRecipeBindingV04, ManagedAdminReceiptV04, VerifiedManagedAdminCommandV04};

impl KernelAgentAuthorityV2 {
    pub(super) fn prepare_owner_execution_review_v04(&mut self,
        proof: &VerifiedManagedAdminCommandV04, task: [u8;32], root: [u8;32],
        values: &mut KernelValueOwnerV2, now: UnixMillisV2,
    ) -> Result<ManagedAdminReceiptV04, KernelAgentAuthorityErrorV2> {
        self.ensure_durable_available()?;
        let s = self.sessions.iter().find(|s| *s.durable_task_id.as_bytes() == task
            && s.task_authorization_digest == Some(Digest32V2::new(root))
            && matches!(s.status, AgentSessionStatusV2::Ready | AgentSessionStatusV2::Running))
            .ok_or(KernelAgentAuthorityErrorV2::InvalidReference)?;
        self.require_current_session_task_authorization(s, now)?;
        let (run, run_id, initial, manifest, session_expiry) =
            (s.run, s.durable_run_id, s.initial_value, s.active_state_manifest_digest, s.expires_at);
        let task_id = DurableTaskIdV2::new(task);
        let p = self.policy.as_ref().ok_or(KernelAgentAuthorityErrorV2::Unavailable)?;
        let current = p.declassification_rules.generation_snapshot()
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        if current.active_state_manifest_digest() != manifest
            || !p.durable.recover_fused_executions_v04(task_id)
                .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?.is_empty() {
            return Err(KernelAgentAuthorityErrorV2::StateConflict);
        }
        let generation = current.deployment_generation();
        let bindings = if p.durable.fused_inputs_pinned_v04(task_id)
            .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)? {
            // Never parse/overwrite a new document after the first durable pin.
            self.restore_active_fused_inputs_v04(run, values, manifest, generation, now)?
        } else {
            let active = p.durable.active_fused_plan_v04(task_id, now)
                .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?;
            let input = values.resolve_g4_value(run, initial, now).map_err(map_value_error)?;
            let document = FusedInputDocumentV04::from_owned_value(input.value())
                .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
            let expected = active.compiled().operations().iter().flat_map(|o| &o.bindings)
                .filter(|b| b.result_of.is_none()).map(|b| b.slot)
                .collect::<std::collections::BTreeSet<_>>();
            if expected.iter().copied().collect::<Vec<_>>() != document.inputs.iter().map(|i| i.slot).collect::<Vec<_>>() {
                return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
            }
            let mut bindings = Vec::new();
            for input in &document.inputs {
                let value = values.derive_owner_input_text_v04(run, initial, input.slot, now)
                    .map_err(map_value_error)?;
                bindings.push(fused_compiler::FusedLocalValueBindingV04 { slot: input.slot, value: value.handle() });
            }
            self.pin_active_fused_inputs_v04(run, &bindings, values, manifest, generation, now)?;
            bindings
        };
        let candidate = self.prepare_active_fused_actions_v04(run, &bindings, values, manifest, generation, now)?;
        let p = self.policy.as_ref().ok_or(KernelAgentAuthorityErrorV2::Unavailable)?;
        let active = p.durable.active_fused_plan_v04(task_id, now)
            .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?;
        let inputs = active.input_commitment().ok_or(KernelAgentAuthorityErrorV2::StateConflict)?;
        let mut recipes = Vec::new();
        for operation in active.compiled().operations() {
            let recipe = if operation.bindings.iter().any(|b| b.result_of.is_some()) {
                FusedRecipeApprovalV04::result_recipe(active.profile_digest(), inputs, operation)
                    .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?
            } else {
                candidate.actions.iter().find(|a| a.reference.operation == operation.id)
                    .ok_or(KernelAgentAuthorityErrorV2::BindingMismatch)?.recipe.commitment()
            };
            recipes.push(FusedRecipeBindingV04 { operation: operation.id, recipe });
        }
        recipes.sort_by_key(|b| b.operation);
        let (not_before, deadline) = proof.validity();
        let approval = FusedRecipeApprovalV04 { schema:1, recipe_schema:2, inputs_digest:Some(inputs),
            installation:*self.config.installation_id.as_bytes(), manifest:*manifest.as_bytes(),
            task, root, profile:active.profile_digest(), deployment_generation:generation, not_before,
            expires_at:deadline.min(active.expires_at().get()).min(session_expiry.get()), bindings:recipes };
        self.policy.as_mut().ok_or(KernelAgentAuthorityErrorV2::Unavailable)?.durable
            .record_fused_execution_review_v04(proof, run_id, approval, now)
            .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)
    }
}
