//! Private owner-clock new-action driver. A signed recipe is not a G6 approval.
use super::*;
use savana_policy_core::v2::KernelDispatchStateV2;

impl KernelAgentAuthorityV2 {
    pub(super) fn tick_fused_actions_v04(
        &mut self,
        values: &mut KernelValueOwnerV2,
        clock: &mut impl FnMut() -> UnixMillisV2,
    ) -> Result<(), StableCode> {
        self.ensure_durable_available()
            .map_err(|_| StableCode::KernelUnavailable)?;
        let now = clock();
        if now.get() == 0 {
            return Err(StableCode::KernelUnavailable);
        }
        let Some(policy) = self.policy.as_ref() else {
            return Ok(());
        };
        policy
            .durable
            .authenticated_state_head()
            .map_err(|_| StableCode::KernelUnavailable)?;
        if policy.g7.is_none() || now.get() < policy.fused_action_not_before {
            return Ok(());
        }
        let generation = policy
            .declassification_rules
            .generation_snapshot()
            .map_err(|_| StableCode::KernelUnavailable)?;
        let manifest = generation.active_state_manifest_digest();
        let mut jobs = Vec::new();
        for session in &self.sessions {
            if session.active_state_manifest_digest != manifest
                || !matches!(
                    session.status,
                    AgentSessionStatusV2::Ready | AgentSessionStatusV2::Running
                )
                || self
                    .require_current_session_task_authorization(session, now)
                    .is_err()
                || !policy
                    .durable
                    .fused_planning_enrolled_v04(session.durable_task_id)
                    .map_err(|_| StableCode::KernelUnavailable)?
            {
                continue;
            }
            let Ok(plan) = policy
                .durable
                .active_fused_plan_v04(session.durable_task_id, now)
            else {
                continue;
            };
            if plan.next_operation().is_none() {
                continue;
            }
            // Deliberately serial within each task. Unknown or an uncheckpointed
            // result blocks new work, even when the next operation is independent.
            // Never guess no-effect or replace the previous execution's identity.
            let Ok(prior) = policy
                .durable
                .recover_fused_executions_v04(session.durable_task_id)
            else {
                continue;
            };
            if prior.iter().any(|r| {
                r.result_commit().is_none() && r.state() != KernelDispatchStateV2::FailedNoEffect
            }) {
                continue;
            }
            jobs.push((*session.durable_task_id.as_bytes(), session.run));
        }
        jobs.sort_by_key(|j| j.0);
        jobs.dedup_by_key(|j| j.0);
        let index = policy
            .fused_action_last_task
            .and_then(|last| jobs.iter().position(|j| j.0 > last))
            .unwrap_or(0);
        let selected = jobs.get(index).copied();
        let policy = self.policy.as_mut().ok_or(StableCode::KernelUnavailable)?;
        policy.fused_action_not_before = now.get().saturating_add(1_000);
        let Some((task, run)) = selected else {
            return Ok(());
        };
        policy.fused_action_last_task = Some(task);
        let action = match self.prepare_next_fused_action_v04(
            run,
            values,
            manifest,
            generation.deployment_generation(),
            now,
        ) {
            Ok(action) => action,
            Err(_) => return self.check_fused_action_owner_health_v04(),
        };
        let evaluated_at = clock();
        if evaluated_at.get() < now.get() {
            return Err(StableCode::KernelUnavailable);
        }
        let evaluation = self.evaluate_fused_action_v04(
            &action,
            values,
            manifest,
            generation.deployment_generation(),
            evaluated_at,
        );
        match evaluation {
            Ok(fused_actions::FusedPrivateEvaluationV04(
                EvaluateToolCallResponseV2::NeedsApproval {
                    envelope,
                    display_authentication,
                    ..
                },
            )) => {
                let _ = self.deliver_fused_approval_v04(
                    &action,
                    envelope,
                    display_authentication,
                    manifest,
                    generation.deployment_generation(),
                    evaluated_at,
                    clock,
                );
            }
            Ok(fused_actions::FusedPrivateEvaluationV04(EvaluateToolCallResponseV2::Allowed {
                ..
            })) => {
                let dispatch_at = clock();
                if dispatch_at.get() < evaluated_at.get() {
                    return Err(StableCode::KernelUnavailable);
                }
                let mut id = [0u8; 16];
                getrandom(&mut id).map_err(|_| StableCode::KernelUnavailable)?;
                if id == [0; 16] {
                    return Err(StableCode::KernelUnavailable);
                }
                // Each stage rechecks the current policy/root/content; no outer
                // policy lock is held across helpers that acquire their own lease.
                // G7 rechecks fence, dependencies, quota and exact approval again.
                let _ = self.dispatch_fused_action_v04(
                    &action,
                    savana_kernel_protocol::v2::RequestIdV2::new(id),
                    manifest,
                    generation.deployment_generation(),
                    generation.effect_fence_epoch(),
                    dispatch_at,
                );
            }
            // Keep denial/errors private. Do not synthesize approval,
            // publish a clarification, fall back to Agent, or dispatch a ticket.
            Ok(_) | Err(_) => (),
        }
        self.check_fused_action_owner_health_v04()
    }

    fn check_fused_action_owner_health_v04(&self) -> Result<(), StableCode> {
        self.ensure_durable_available()
            .map_err(|_| StableCode::KernelUnavailable)?;
        self.policy
            .as_ref()
            .ok_or(StableCode::KernelUnavailable)?
            .durable
            .authenticated_state_head()
            .map_err(|_| StableCode::KernelUnavailable)?;
        Ok(())
    }
}
