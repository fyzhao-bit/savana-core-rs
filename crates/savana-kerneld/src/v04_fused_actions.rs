//! Private G4/G5/G6/G7 orchestration. No Agent RPC or public status.
//! Explicitly separate from the legacy entry route until exclusive publication
//! and authenticated session/approval recovery are wired end to end.
#![allow(dead_code)]
use super::*;

#[derive(Clone)]
pub(super) struct FusedIntentBindingV04 {
    pub(super) expires_at: UnixMillisV2,
    pub(super) reference: savana_policy_core::v2::FusedOperationRefV04,
    pub(super) recipe: savana_policy_core::v2::FusedExecutionRecipeV04,
}
// These wrappers deliberately have no public constructor, Debug, serde or RPC.
pub(super) struct FusedPrivateActionV04 {
    pub(super) intent: ActionIntentHandleV2,
}
pub(super) struct FusedPrivateEvaluationV04(pub(super) EvaluateToolCallResponseV2);
pub(super) struct FusedPrivateTicketV04(pub(super) ExecutionTicketHandleV2);
pub(super) struct FusedPrivateExecutionV04(pub(super) ExecutionHandleV2);
pub(super) struct FusedPrivateStatusV04(pub(super) GetExecutionStatusResponseV2);

#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum FusedRecoveryFaultV04 {
    G7Prepared,
    VaultCommitted,
    OutcomeCommitted,
    ResultCheckpointed,
}

impl KernelAgentAuthorityV2 {
    /// Recreate only private query identities from the authenticated G7 owner.
    /// This deliberately creates no session, action, approval, ticket or send.
    pub(super) fn restore_fused_execution_queries_v04(
        &mut self,
        task: DurableTaskIdV2,
        manifest: Digest32V2,
        generation: u64,
        fence: u64,
    ) -> Result<Vec<FusedPrivateExecutionV04>, KernelAgentAuthorityErrorV2> {
        self.ensure_durable_available()?;
        let recovered = self
            .policy
            .as_ref()
            .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?
            .durable
            .recover_fused_executions_v04(task)
            .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?;
        self.restore_fused_execution_records_v04(recovered, manifest, generation, fence)
    }

    pub(super) fn restore_fused_execution_records_v04(
        &mut self,
        recovered: Vec<savana_policy_core::v2::RecoveredFusedExecutionV04>,
        manifest: Digest32V2,
        generation: u64,
        fence: u64,
    ) -> Result<Vec<FusedPrivateExecutionV04>, KernelAgentAuthorityErrorV2> {
        self.ensure_durable_available()?;
        let mut additions = Vec::new();
        let mut handles = Vec::new();
        additions
            .try_reserve(recovered.len())
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        handles
            .try_reserve(recovered.len())
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        for record in recovered {
            let core = record.core();
            if core.installation_id() != self.config.installation_id
                || core.active_state_manifest_digest() != manifest
                || core.deployment_generation() != generation
                || core.effect_fence_epoch() != fence
            {
                return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
            }
            if let Some(existing) = self
                .executions
                .iter()
                .find(|e| e.execution_nonce == core.execution_nonce())
            {
                self.check_execution_context(existing, manifest, generation, fence)?;
                let prior = existing
                    .fused_recovery
                    .as_ref()
                    .ok_or(KernelAgentAuthorityErrorV2::BindingMismatch)?;
                if prior.result_binding() != record.result_binding()
                    || prior.scope() != record.scope()
                    || existing.action_intent_id != record.intent()
                    || existing.dispatch_core_digest != record.core_digest()
                    || existing.dispatch_subject_digest != core.dispatch_subject_digest()
                {
                    return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
                }
                handles.push(FusedPrivateExecutionV04(existing.execution));
                continue;
            }
            if self.executions.len() + additions.len() >= self.maximum_records {
                return Err(KernelAgentAuthorityErrorV2::LimitExceeded);
            }
            let execution = mint_handle(ExecutionHandleV2::from_authority_entropy)?;
            let status = match record.state() {
                savana_policy_core::v2::KernelDispatchStateV2::FailedNoEffect => {
                    PublicExecutionStatusV2::FailedNoEffect {
                        class: PublicFailureClassV2::Connector,
                    }
                }
                _ => PublicExecutionStatusV2::Dispatching,
            };
            additions.push(ExecutionRecordV2 {
                execution,
                commitment: execution.authority_commitment(&self.handle_key),
                ticket_commitment: None,
                action_intent_id: record.intent(),
                active_state_manifest_digest: manifest,
                deployment_generation: generation,
                effect_fence_epoch: fence,
                execution_nonce: core.execution_nonce(),
                dispatch_core_digest: record.core_digest(),
                dispatch_subject_digest: core.dispatch_subject_digest(),
                status,
                completion: None,
                fused_recovery: Some(record),
            });
            handles.push(FusedPrivateExecutionV04(execution));
        }
        // Validate and allocate everything before mutating the volatile table.
        self.executions
            .try_reserve(additions.len())
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        self.executions.extend(additions);
        Ok(handles)
    }

    /// Dispatch only the locally selected, evaluated action. Unknown transport
    /// results keep the original query identity; repeating this call never sends
    /// an already-recorded execution a second time.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn dispatch_fused_action_v04(
        &mut self,
        action: &FusedPrivateActionV04,
        request_id: savana_kernel_protocol::v2::RequestIdV2,
        manifest: Digest32V2,
        generation: u64,
        fence: u64,
        now: UnixMillisV2,
    ) -> Result<FusedPrivateExecutionV04, KernelAgentAuthorityErrorV2> {
        self.ensure_durable_available()?;
        let lease = self
            .policy
            .as_ref()
            .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?
            .declassification_rules
            .clone();
        lease
            .with_current_fused_dispatch_policy(
                self.config.installation_id,
                manifest,
                generation,
                fence,
                now.get(),
                |rules, expires| {
                    let intent = self
                        .intents
                        .iter()
                        .find(|i| i.intent == action.intent && i.fused.is_some())
                        .ok_or(KernelAgentAuthorityErrorV2::InvalidReference)?;
                    let ticket = self
                        .execution_tickets
                        .iter()
                        .find(|t| {
                            t.action_intent_id == intent.action_intent_id
                                && Some(t.commitment) == intent.ticket_commitment
                        })
                        .ok_or(KernelAgentAuthorityErrorV2::InvalidReference)?;
                    self.dispatch_execution_inner(
                        request_id,
                        savana_kernel_protocol::v2::DispatchExecutionRequestV2::new(ticket.ticket),
                        manifest,
                        generation,
                        fence,
                        now,
                        IntentAccessV2::PrivateFused,
                        Some((rules, expires)),
                    )
                    .map(|r| FusedPrivateExecutionV04(r.execution()))
                },
            )
            .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?
    }

    /// The result stays inside the trusted host. Neither its status nor vault
    /// document handle is a planner observation or a publication authorization.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn reconcile_fused_execution_v04(
        &mut self,
        execution: &FusedPrivateExecutionV04,
        request_id: savana_kernel_protocol::v2::RequestIdV2,
        vault: &mut dyn KernelIngressCommitSinkV2,
        manifest: Digest32V2,
        generation: u64,
        fence: u64,
        now: UnixMillisV2,
    ) -> Result<FusedPrivateStatusV04, KernelAgentAuthorityErrorV2> {
        self.execution_status_inner(
            request_id,
            GetExecutionStatusRequestV2::new(ExecutionStatusTargetV2::Execution(execution.0)),
            vault,
            manifest,
            generation,
            fence,
            now,
            IntentAccessV2::PrivateFused,
        )
        .map(FusedPrivateStatusV04)
    }

    /// Select the next unreserved operation from the durable active plan. The
    /// caller supplies no operation ID, plan, material, arguments or request ID.
    pub(super) fn prepare_next_fused_action_v04(
        &mut self,
        run: savana_kernel_protocol::v2::RunHandleV2,
        values: &mut KernelValueOwnerV2,
        manifest: Digest32V2,
        generation: u64,
        now: UnixMillisV2,
    ) -> Result<FusedPrivateActionV04, KernelAgentAuthorityErrorV2> {
        self.ensure_durable_available()?;
        let lease = self
            .policy
            .as_ref()
            .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?
            .declassification_rules
            .clone();
        lease
            .with_current_fused_policy(
                self.config.installation_id,
                manifest,
                generation,
                now.get(),
                |_, expires| {
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
                    self.require_current_session_task_authorization(session, now)?;
                    let owner = &self
                        .policy
                        .as_ref()
                        .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?
                        .durable;
                    let active = owner
                        .active_fused_plan_v04(session.durable_task_id, now)
                        .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?;
                    let operation = active
                        .next_operation()
                        .ok_or(KernelAgentAuthorityErrorV2::StateConflict)?;
                    // The private orchestrator never falls back to volatile/caller input.
                    let inputs = owner
                        .recover_fused_inputs_v04(session.durable_task_id, generation, now)
                        .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?;
                    if inputs.run() != session.durable_run_id || inputs.manifest() != manifest {
                        return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
                    }
                    let bindings = values
                        .restore_fused_inputs(run, &inputs, now)
                        .map_err(map_value_error)?
                        .into_iter()
                        .map(|(slot, value)| fused_compiler::FusedLocalValueBindingV04 {
                            slot,
                            value,
                        })
                        .collect::<Vec<_>>();
                    let candidate = self.compile_next_fused_action_v04(
                        run, &bindings, values, manifest, generation, now, expires,
                    )?;
                    let expires_at = UnixMillisV2::new(
                        candidate.provenance.expires_at().get().min(
                            active
                                .recipe_deadline()
                                .ok_or(KernelAgentAuthorityErrorV2::StateConflict)?
                                .get(),
                        ),
                    );
                    let action = candidate
                        .actions
                        .into_iter()
                        .find(|a| a.reference.operation == operation)
                        .ok_or(KernelAgentAuthorityErrorV2::StateConflict)?;
                    if !action.matches_recipe_approval
                        || action.reference.plan_revision != active.revision()
                    {
                        return Err(KernelAgentAuthorityErrorV2::StateConflict);
                    }
                    // The exact commitment plus current plan/step/content also pins the
                    // fields abstracted by the legacy exact-commitment helper.
                    let material = Digest32V2::new(action.execution_commitment);
                    let canonical = domain_digest(
                        b"SAVANA_PRIVATE_FUSED_PROPOSAL_V04\0",
                        &[
                            self.config.installation_id.as_bytes(),
                            manifest.as_bytes(),
                            action.step.durable_run_id.as_bytes(),
                            action.step.durable_task_id.as_bytes(),
                            &candidate.profile_digest,
                            &active.revision().to_be_bytes(),
                            &operation.to_be_bytes(),
                            material.as_bytes(),
                            action.prepared.task_match.content_digest().as_bytes(),
                        ],
                    );
                    let mut id = [0; 16];
                    id.copy_from_slice(&canonical.as_bytes()[..16]);
                    let result = self.commit_prepared_tool_intent(
                        savana_kernel_protocol::v2::RequestIdV2::new(id),
                        canonical.as_bytes(),
                        &action.step,
                        action.prepared,
                        Some(FusedIntentBindingV04 {
                            expires_at,
                            reference: action.reference,
                            recipe: action.recipe,
                        }),
                        manifest,
                    )?;
                    Ok(FusedPrivateActionV04 {
                        intent: result.intent(),
                    })
                },
            )
            .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?
    }

    pub(super) fn evaluate_fused_action_v04(
        &mut self,
        action: &FusedPrivateActionV04,
        values: &KernelValueOwnerV2,
        manifest: Digest32V2,
        generation: u64,
        now: UnixMillisV2,
    ) -> Result<FusedPrivateEvaluationV04, KernelAgentAuthorityErrorV2> {
        self.ensure_durable_available()?;
        let lease = self
            .policy
            .as_ref()
            .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?
            .declassification_rules
            .clone();
        lease
            .with_current_fused_policy(
                self.config.installation_id,
                manifest,
                generation,
                now.get(),
                |rules, _| {
                    let record = self
                        .intents
                        .iter()
                        .find(|i| i.intent == action.intent && i.fused.is_some())
                        .ok_or(KernelAgentAuthorityErrorV2::InvalidReference)?;
                    self.evaluate_tool_call_inner(
                        EvaluateToolCallRequestV2::new(record.pending),
                        values,
                        manifest,
                        generation,
                        now,
                        IntentAccessV2::PrivateFused,
                        Some(rules),
                    )
                    .map(FusedPrivateEvaluationV04)
                },
            )
            .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?
    }

    pub(super) fn authorize_fused_action_v04(
        &mut self,
        action: &FusedPrivateActionV04,
        receipt: savana_kernel_protocol::v2::SignedApprovalSettlementV2,
        manifest: Digest32V2,
        generation: u64,
        now: UnixMillisV2,
    ) -> Result<FusedPrivateTicketV04, KernelAgentAuthorityErrorV2> {
        self.ensure_durable_available()?;
        let lease = self
            .policy
            .as_ref()
            .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?
            .declassification_rules
            .clone();
        lease
            .with_current_fused_policy(
                self.config.installation_id,
                manifest,
                generation,
                now.get(),
                |_, _| {
                    let record = self
                        .intents
                        .iter()
                        .find(|i| i.intent == action.intent && i.fused.is_some())
                        .ok_or(KernelAgentAuthorityErrorV2::InvalidReference)?;
                    let approval = self
                        .tool_approvals
                        .iter()
                        .find(|a| {
                            Some(a.commitment) == record.approval_commitment
                                && a.pending_commitment == record.pending_commitment
                        })
                        .ok_or(KernelAgentAuthorityErrorV2::InvalidReference)?;
                    let request = savana_kernel_protocol::v2::AuthorizeToolCallRequestV2::new(
                        record.pending,
                        approval.approval,
                        receipt,
                    )
                    .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
                    self.authorize_tool_call_inner(
                        &request,
                        manifest,
                        generation,
                        now,
                        IntentAccessV2::PrivateFused,
                    )
                    .map(|r| FusedPrivateTicketV04(r.ticket()))
                },
            )
            .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?
    }
}
