//! Private, read-only candidate -> concrete G4 material compiler.
//! No Agent RPC, public handle, signing authority, durable write or execution.
//! Resolves signed result edges only from authenticated durable result snapshots.
#![allow(dead_code)]
use super::*;
use savana_kernel_protocol::v2::RunHandleV2;
use savana_policy_core::v2::{fused_execution_commitment_v04, lower_fused_plan_with_tools_v04};
use std::collections::BTreeSet;

// These are local host objects, never decoded from a model response. Possession
// is not approval: G4 resolves ownership and G7 checks the signed exact material.
pub(super) struct FusedLocalValueBindingV04 {
    pub slot: [u8; 16],
    pub value: ValueHandleV2,
}

// Deliberately no Debug/Serialize and no public execution/approval handle.
pub(super) struct FusedPreparedActionV04 {
    pub step: PlanStepRecordV2,
    pub reference: savana_policy_core::v2::FusedOperationRefV04,
    pub internal_step_id: savana_kernel_protocol::v2::InternalStepIdV2,
    pub prepared: PreparedToolIntentV2,
    pub execution_commitment: [u8; 32],
    pub recipe: savana_policy_core::v2::FusedExecutionRecipeV04,
    pub matches_profile_approval: bool,
    pub matches_recipe_approval: bool,
}
pub(super) struct FusedPreparedCandidateV04 {
    pub task: DurableTaskIdV2,
    pub activation_revision: u64,
    pub profile_digest: [u8; 32],
    pub provenance: ProvenanceRecordV2,
    pub actions: Vec<FusedPreparedActionV04>,
}

impl KernelAgentAuthorityV2 {
    /// Private intake of values already admitted through the local value owner.
    /// Immutable pinning precedes recipe approval; this does not mint an effect.
    pub(super) fn pin_active_fused_inputs_v04(
        &mut self,
        run: RunHandleV2,
        bindings: &[FusedLocalValueBindingV04],
        values: &KernelValueOwnerV2,
        manifest: Digest32V2,
        generation: u64,
        now: UnixMillisV2,
    ) -> Result<(), KernelAgentAuthorityErrorV2> {
        self.ensure_durable_available()?;
        let active = self
            .policy
            .as_ref()
            .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?
            .declassification_rules
            .clone();
        active
            .with_current_fused_policy(
                self.config.installation_id,
                manifest,
                generation,
                now.get(),
                |_, expiry| {
                    // Compile under the same lease: ownership, full root matching and
                    // exact slot coverage are checked before any durable input mutation.
                    self.compile_active_fused_actions_v04(
                        run, bindings, values, manifest, generation, now, expiry,
                    )?;
                    let s = self
                        .sessions
                        .iter()
                        .find(|s| s.run == run)
                        .ok_or(KernelAgentAuthorityErrorV2::InvalidReference)?;
                    let mut inputs = Vec::new();
                    for b in bindings {
                        let v = values
                            .resolve_g4_value(run, b.value, now)
                            .map_err(map_value_error)?;
                        inputs.push(
                            savana_policy_core::v2::FusedOwnedInputV04::from_owned_value(
                                b.slot,
                                v.value_internal_id(),
                                v.value(),
                                v.provenance(),
                            )
                            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?,
                        );
                    }
                    self.policy
                        .as_mut()
                        .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?
                        .durable
                        .pin_fused_inputs_v04(
                            s.durable_task_id,
                            s.durable_run_id,
                            generation,
                            inputs,
                            now,
                        )
                        .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)
                },
            )
            .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?
    }

    /// Hydrate only into a current authenticated session of the original run.
    /// Recreates process handles, never task/session authentication or authority.
    pub(super) fn restore_active_fused_inputs_v04(
        &self,
        run: RunHandleV2,
        values: &mut KernelValueOwnerV2,
        manifest: Digest32V2,
        generation: u64,
        now: UnixMillisV2,
    ) -> Result<Vec<FusedLocalValueBindingV04>, KernelAgentAuthorityErrorV2> {
        self.ensure_durable_available()?;
        let p = self
            .policy
            .as_ref()
            .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?;
        p.declassification_rules
            .with_current_fused_policy(
                self.config.installation_id,
                manifest,
                generation,
                now.get(),
                |_, _| {
                    let s = self
                        .sessions
                        .iter()
                        .find(|s| {
                            s.run == run
                                && matches!(
                                    s.status,
                                    AgentSessionStatusV2::Ready | AgentSessionStatusV2::Running
                                )
                        })
                        .ok_or(KernelAgentAuthorityErrorV2::InvalidReference)?;
                    self.require_current_session_task_authorization(s, now)?;
                    let snapshot = p
                        .durable
                        .recover_fused_inputs_v04(s.durable_task_id, generation, now)
                        .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?;
                    if s.active_state_manifest_digest != manifest
                        || snapshot.manifest() != manifest
                        || snapshot.run() != s.durable_run_id
                    {
                        return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
                    }
                    Ok(values
                        .restore_fused_inputs(run, &snapshot, now)
                        .map_err(map_value_error)?
                        .into_iter()
                        .map(|(slot, value)| FusedLocalValueBindingV04 { slot, value })
                        .collect())
                },
            )
            .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?
    }
    /// Compile a snapshot of an activated, signed finite plan using local owned
    /// values. The output remains a draft even if its commitment is approved:
    /// no G5/G6 result, G7 reservation or current-policy lease is manufactured.
    pub(super) fn prepare_active_fused_actions_v04(
        &self,
        run: RunHandleV2,
        bindings: &[FusedLocalValueBindingV04],
        values: &KernelValueOwnerV2,
        manifest: Digest32V2,
        generation: u64,
        now: UnixMillisV2,
    ) -> Result<FusedPreparedCandidateV04, KernelAgentAuthorityErrorV2> {
        self.ensure_durable_available()?;
        let policy = self
            .policy
            .as_ref()
            .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?;
        policy
            .declassification_rules
            .with_current_fused_policy(
                self.config.installation_id,
                manifest,
                generation,
                now.get(),
                |_, expires| {
                    self.compile_active_fused_actions_v04(
                        run, bindings, values, manifest, generation, now, expires,
                    )
                },
            )
            .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn compile_active_fused_actions_v04(
        &self,
        run: RunHandleV2,
        bindings: &[FusedLocalValueBindingV04],
        values: &KernelValueOwnerV2,
        manifest: Digest32V2,
        generation: u64,
        now: UnixMillisV2,
        lease_expiry: u64,
    ) -> Result<FusedPreparedCandidateV04, KernelAgentAuthorityErrorV2> {
        self.compile_fused_actions_v04(
            run,
            bindings,
            values,
            manifest,
            generation,
            now,
            lease_expiry,
            false,
        )
    }

    /// Execution uses the durable owner's next operation, never a caller's
    /// choice. Completed operations retain their receipts and consumption; they
    /// must not be prepared again against the now-reduced authorization budget.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn compile_next_fused_action_v04(
        &self,
        run: RunHandleV2,
        bindings: &[FusedLocalValueBindingV04],
        values: &KernelValueOwnerV2,
        manifest: Digest32V2,
        generation: u64,
        now: UnixMillisV2,
        lease_expiry: u64,
    ) -> Result<FusedPreparedCandidateV04, KernelAgentAuthorityErrorV2> {
        self.compile_fused_actions_v04(
            run,
            bindings,
            values,
            manifest,
            generation,
            now,
            lease_expiry,
            true,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn compile_fused_actions_v04(
        &self,
        run: RunHandleV2,
        bindings: &[FusedLocalValueBindingV04],
        values: &KernelValueOwnerV2,
        manifest: Digest32V2,
        generation: u64,
        now: UnixMillisV2,
        lease_expiry: u64,
        next_only: bool,
    ) -> Result<FusedPreparedCandidateV04, KernelAgentAuthorityErrorV2> {
        if bindings.is_empty() || bindings.len() > 256 {
            return Err(KernelAgentAuthorityErrorV2::LimitExceeded);
        }
        let session = self
            .sessions
            .iter()
            .find(|s| {
                s.run == run
                    && matches!(
                        s.status,
                        AgentSessionStatusV2::Ready | AgentSessionStatusV2::Running
                    )
            })
            .ok_or(KernelAgentAuthorityErrorV2::InvalidReference)?;
        let root = self.require_current_session_task_authorization(session, now)?;
        if session.active_state_manifest_digest != manifest {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        let policy = self
            .policy
            .as_ref()
            .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?;
        let active = policy
            .durable
            .active_fused_plan_v04(session.durable_task_id, now)
            .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?;
        let selected = if next_only {
            Some(
                active
                    .next_operation()
                    .ok_or(KernelAgentAuthorityErrorV2::StateConflict)?,
            )
        } else {
            None
        };
        if policy
            .durable
            .fused_inputs_pinned_v04(session.durable_task_id)
            .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?
        {
            let pinned = policy
                .durable
                .recover_fused_inputs_v04(session.durable_task_id, generation, now)
                .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?;
            if pinned.run() != session.durable_run_id
                || pinned.manifest() != manifest
                || pinned.inputs().len() != bindings.len()
            {
                return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
            }
            for b in bindings {
                let original = pinned
                    .inputs()
                    .iter()
                    .find(|i| i.slot() == b.slot)
                    .ok_or(KernelAgentAuthorityErrorV2::BindingMismatch)?;
                let v = values
                    .resolve_g4_value(run, b.value, now)
                    .map_err(map_value_error)?;
                if v.value_internal_id() != original.identity()
                    || v.provenance() != original.provenance()
                    || v.value_digest() != original.provenance().value_digest()
                {
                    return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
                }
            }
        }
        let signed = &session.signed_planner_policy;
        let mut keys = BTreeSet::new();
        let mut handles = Vec::new();
        let mut slots = Vec::new();
        let mut local_slots = Vec::new();
        let mut parents = Vec::new();
        let mut expires_at = session
            .expires_at
            .get()
            .min(active.expires_at().get())
            .min(lease_expiry);
        for b in bindings {
            if b.slot == [0; 16] || !keys.insert(b.slot) || handles.contains(&b.value) {
                return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
            }
            let resolved = values
                .resolve_g4_value(run, b.value, now)
                .map_err(map_value_error)?;
            if resolved.durable_run_id() != session.durable_run_id
                || resolved.active_state_manifest_digest() != manifest
                || now.get() < resolved.provenance().created_at().get()
                || now.get() >= resolved.provenance().expires_at().get()
            {
                return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
            }
            expires_at = expires_at.min(resolved.provenance().expires_at().get());
            parents.push(resolved.provenance().clone());
            handles.push(b.value);
            let reference = PlannerSlotRefV2::new(b.slot);
            local_slots.push((b.slot, reference));
            slots.push(
                PlannerAbstractSlotV2::new(
                    reference,
                    SlotKindV2::new(1),
                    PlannerSlotCardinalityV2::ExactlyOne,
                    PlannerSlotConfidentialityV2::ConfidentialAbstract,
                )
                .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?,
            );
        }
        // The abstract shape is fixed before results exist. Missing future
        // slots have no value/handle and cannot be materialized into G4 yet.
        for b in active
            .compiled()
            .operations()
            .iter()
            .flat_map(|o| &o.bindings)
        {
            if keys.insert(b.slot) {
                if b.result_of.is_none() {
                    return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
                }
                let reference = PlannerSlotRefV2::new(b.slot);
                local_slots.push((b.slot, reference));
                slots.push(
                    PlannerAbstractSlotV2::new(
                        reference,
                        SlotKindV2::new(1),
                        PlannerSlotCardinalityV2::ExactlyOne,
                        PlannerSlotConfidentialityV2::ConfidentialAbstract,
                    )
                    .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?,
                );
            }
        }
        // All references have the same fixed-width canonical encoding.
        slots.sort_by_key(|s| *s.reference().as_bytes());
        let compiled = active.compiled();
        let policy_digest = Digest32V2::new(compiled.policy());
        let revision = active.revision();
        let plan_digest = domain_digest(
            b"SAVANA_FUSED_LOCAL_PLAN_V04\0",
            &[policy_digest.as_bytes(), &revision.to_be_bytes()],
        );
        let envelope = PlannerEnvelopeV2::new(
            signed.planner_route,
            signed.task_template,
            signed.intent,
            signed.allowed_action_templates.clone(),
            slots,
            vec![],
            signed.limits,
            Nonce32V2::new(*plan_digest.as_bytes()),
            UnixMillisV2::new(expires_at),
        )
        .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let tools = policy
            .active_tools
            .records()
            .iter()
            .filter(|a| {
                policy
                    .active_tools
                    .resolve(a.descriptor().descriptor_digest(), session.role, now)
                    .is_some()
            })
            .map(|a| {
                let d = a.descriptor().unsigned();
                (d.tool_class(), d.action_template())
            })
            .collect::<Vec<_>>();
        let plan = lower_fused_plan_with_tools_v04(
            compiled,
            policy_digest,
            &envelope,
            &local_slots,
            &tools,
            now,
        )
        .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let canonical = savana_kernel_protocol::v2::encode_planner_plan_v2(&plan)
            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let value = KernelValueV2::bytes(canonical.clone())
            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let context = ProvenanceContextV2::from_authenticated_runtime(
            session.producer_identity,
            session.durable_run_id,
            manifest,
            now,
            UnixMillisV2::new(expires_at),
        )
        .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        // Reuse the non-improving candidate provenance transition, not a G3
        // declassification. This local compilation performs no model handoff.
        let provenance = ProvenanceRecordV2::planner_output(
            &value,
            context,
            domain_digest(
                b"SAVANA_FUSED_LOCAL_COMPILER_V04\0",
                &[policy_digest.as_bytes()],
            ),
            Digest32V2::new(active.profile_digest()),
            domain_digest(b"SAVANA_FUSED_LOCAL_OUTPUT_V04\0", &[&canonical]),
            &parents.iter().collect::<Vec<_>>(),
            session.policy_allowed_effects,
        )
        .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let mut actions = Vec::new();
        for (operation, lowered) in compiled.operations().iter().zip(plan.steps()) {
            // Full plan shape, slot closure and provenance were checked above.
            // Only materialize a fresh G4 proposal for the unfinished operation.
            if selected.is_some_and(|id| id != operation.id) {
                continue;
            }
            if operation
                .bindings
                .iter()
                .any(|b| !bindings.iter().any(|v| v.slot == b.slot))
            {
                if next_only {
                    return Err(KernelAgentAuthorityErrorV2::StateConflict);
                }
                // Its derived value does not exist yet, but its RULE does: the
                // owner's pinned exact values plus the declared edges must form
                // an alternative the owner signed, before any operation runs.
                let descriptor = policy
                    .active_tools
                    .resolve_class(lowered.tool_class(), session.role, now)
                    .ok_or(KernelAgentAuthorityErrorV2::InvalidReference)?;
                let business = descriptor
                    .descriptor()
                    .unsigned()
                    .require_business_profile()
                    .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
                let derived: std::collections::BTreeMap<_, _> =
                    savana_policy_core::v2::fused_operation_derived_rules_v04(operation, business)
                        .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?
                        .into_iter()
                        .collect();
                let mut resolved = Vec::new();
                for b in operation.bindings.iter().filter(|b| b.result_of.is_none()) {
                    let handle = bindings
                        .iter()
                        .find(|v| v.slot == b.slot)
                        .ok_or(KernelAgentAuthorityErrorV2::BindingMismatch)?
                        .value;
                    resolved.push((
                        b.argument.clone(),
                        values.resolve_g4_value(run, handle, now).map_err(map_value_error)?,
                    ));
                }
                let exact: Vec<_> = resolved
                    .iter()
                    .map(|(name, value)| (name.clone(), value.value()))
                    .collect();
                let state = policy
                    .durable
                    .task_authorization_state(session.durable_task_id)
                    .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?;
                savana_policy_core::v2::check_result_operation_rule_v04(
                    business,
                    descriptor.descriptor().descriptor_digest(),
                    &exact,
                    &derived,
                    state.authorization().material(),
                )
                .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
                continue;
            }
            let descriptor = policy
                .active_tools
                .resolve_class(lowered.tool_class(), session.role, now)
                .ok_or(KernelAgentAuthorityErrorV2::InvalidReference)?;
            if descriptor.descriptor().unsigned().action_template() != lowered.action_template() {
                return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
            }
            let arguments = lowered
                .slot_bindings()
                .iter()
                .map(|(name, reference)| {
                    let b = bindings
                        .iter()
                        .find(|b| &b.slot == reference.as_bytes())
                        .ok_or(KernelAgentAuthorityErrorV2::InvalidReference)?;
                    let slot = envelope
                        .slots()
                        .iter()
                        .find(|s| s.reference() == *reference)
                        .ok_or(KernelAgentAuthorityErrorV2::InvalidReference)?;
                    Ok(PlanArgumentRecordV2 {
                        name: savana_policy_core::v2::ArgumentNameV2::new(name.as_str())
                            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?,
                        slot: *slot,
                        value: b.value,
                    })
                })
                .collect::<Result<Vec<_>, KernelAgentAuthorityErrorV2>>()?;
            // Owner-signed result-derived controls for this step: for each
            // binding that extracts a scalar from a prior result, rebuild the
            // rule the owner signed (source clause and path/bound from the
            // compiler-set binding, kind from the signed descriptor). G4 matches
            // the request alternative under these, so a mismatch fails there.
            let business = descriptor
                .descriptor()
                .unsigned()
                .require_business_profile()
                .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
            let derived_controls =
                savana_policy_core::v2::fused_operation_derived_rules_v04(operation, business)
                    .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
            // Logical operation identity is independent of its new ordinal or
            // plan version. Actual parameters remain bound in G4 and the profile.
            let identity = domain_digest(
                b"SAVANA_FUSED_LOCAL_OPERATION_V04\0",
                &[policy_digest.as_bytes(), &operation.id.to_be_bytes()],
            );
            let step = PlanStepRecordV2 {
                commitment: identity, // no handle is minted or registered
                run,
                durable_run_id: session.durable_run_id,
                durable_task_id: session.durable_task_id,
                principal: session.principal,
                role: session.role,
                plan_revision_digest: PlanRevisionDigestV2::new(*plan_digest.as_bytes()),
                internal_step_id: savana_kernel_protocol::v2::InternalStepIdV2::new(
                    *identity.as_bytes(),
                ),
                descriptor_digest: descriptor.descriptor().descriptor_digest(),
                task_authorization_digest: root,
                proposer_parent: provenance.provenance_digest(),
                arguments,
                derived_controls,
            };
            let prepared =
                self.prepare_tool_intent_material(&step, values, manifest, generation, now)?;
            let commitment =
                fused_execution_commitment_v04(&prepared.material, prepared.task_match.content())
                    .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
            let recipe = savana_policy_core::v2::FusedExecutionRecipeV04::from_verified_g4(
                &prepared.material,
                &prepared.task_match,
                &prepared.recipe_slots,
            )
            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
            actions.push(FusedPreparedActionV04 {
                step,
                reference: savana_policy_core::v2::FusedOperationRefV04 {
                    plan_revision: revision,
                    operation: operation.id,
                },
                internal_step_id: savana_kernel_protocol::v2::InternalStepIdV2::new(
                    *identity.as_bytes(),
                ),
                prepared,
                execution_commitment: commitment,
                matches_recipe_approval: active.recipe_approved(
                    operation.id,
                    &recipe,
                    generation,
                    now,
                ),
                recipe,
                matches_profile_approval: active.approved_commitment(operation.id)
                    == Some(commitment),
            });
        }
        if next_only && actions.len() != 1 {
            return Err(KernelAgentAuthorityErrorV2::StateConflict);
        }
        Ok(FusedPreparedCandidateV04 {
            task: session.durable_task_id,
            activation_revision: revision,
            profile_digest: active.profile_digest(),
            provenance,
            actions,
        })
    }
}
