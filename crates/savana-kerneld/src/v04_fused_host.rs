//! Trusted owner-clock orchestration; no model/Agent-triggered scheduler RPC.
use super::*;
use savana_policy_core::v2::{
    exchange_scheduled_fused_model_v04, FusedModelExchangeOutcomeV04, FusedModelReleaseContextV04,
    FusedPlanningUpdateV04, G4Error,
};

impl KernelAgentAuthorityV2 {
    pub(crate) fn tick_fused_planning(
        &mut self,
        values: &KernelValueOwnerV2,
        mut clock: impl FnMut() -> UnixMillisV2,
    ) -> Result<(), StableCode> {
        self.ensure_durable_available()
            .map_err(|_| StableCode::KernelUnavailable)?;
        let Some(policy) = self.policy.as_mut() else {
            return Ok(());
        };
        let now = clock();
        let jobs = policy
            .durable
            .scheduled_fused_work_v04(now)
            .map_err(|_| StableCode::KernelUnavailable)?;
        if jobs.is_empty() {
            return Ok(());
        }
        // Bound each owner turn to one possible I/O. Round-robin fairness is
        // private scheduling, not a promise of exact observable timing.
        let index = policy
            .fused_last_task
            .and_then(|last| {
                jobs.iter()
                    .position(|j| j.task == last)
                    .map(|i| (i + 1) % jobs.len())
            })
            .unwrap_or(0);
        let job = &jobs[index];
        policy.fused_last_task = Some(job.task);
        if let Some(round) = job.activation_round {
            // Recover the exact accepted candidate after a crash between reply
            // settlement and activation; never resend or synthesize a proposal.
            let status = policy
                .durable
                .fused_planning_status_v04(job.task, now)
                .map_err(|_| StableCode::KernelUnavailable)?;
            match policy.durable.update_fused_planning_v04(
                job.task,
                status.revision,
                FusedPlanningUpdateV04::Activate {
                    round,
                    expected_plan_revision: status.active_plan_revision,
                },
                now,
            ) {
                Ok(_) => return Ok(()),
                // A prefix-incompatible candidate must not starve later public
                // slots that could produce a valid replacement.
                Err(G4Error::StateConflict) => (),
                Err(_) => return Err(StableCode::KernelUnavailable),
            }
        }
        let worker_index = job.recipient.and_then(|reader| {
            policy
                .fused_workers
                .iter()
                .position(|w| w.recipient_identity() == reader)
        });
        let session = self.sessions.iter().find(|s| {
            if s.durable_task_id != job.task
                || now.get() >= s.expires_at.get()
                || !matches!(
                    s.status,
                    AgentSessionStatusV2::Ready | AgentSessionStatusV2::Running
                )
            {
                return false;
            }
            let Ok(state) = policy.durable.task_authorization_state(job.task) else {
                return false;
            };
            let a = state.authorization();
            let m = a.material();
            !state.revoked()
                && m.principal() == s.principal
                && m.installation_digest() == self.config.installation_id
                && m.manifest_digest() == s.active_state_manifest_digest
                && now.get() >= m.not_before().get()
                && now.get() < m.expires_at().get()
                && s.task_authorization_digest.is_none_or(|d| d == a.digest())
        });
        let (Some(worker_index), Some(session)) = (worker_index, session) else {
            // Disabled cloud/missing private session is not a fabricated model
            // result or sent attempt. Only elapsed public windows advance.
            policy
                .durable
                .update_fused_planning_v04(
                    job.task,
                    job.revision,
                    FusedPlanningUpdateV04::SkipExpiredDeliveries,
                    now,
                )
                .map_err(|_| StableCode::KernelUnavailable)?;
            return Ok(());
        };
        let initial = match values.resolve_g4_value(session.run, session.initial_value, now) {
            Ok(v) => v,
            Err(_) => return Ok(()), // no reconstructed/fabricated provenance after restart
        };
        if initial.durable_run_id() != session.durable_run_id
            || initial.active_state_manifest_digest() != session.active_state_manifest_digest
        {
            return Ok(());
        }
        let active = policy.declassification_rules.clone();
        let generation = match active.generation_snapshot() {
            Ok(g) => g,
            Err(_) => return Ok(()),
        };
        let parent = initial.provenance();
        let parents = [parent];
        let result = active.with_current_fused_policy(
            self.config.installation_id,
            session.active_state_manifest_digest,
            generation.deployment_generation(),
            now.get(),
            |rules, lease_expiry| {
                let expires = lease_expiry
                    .min(session.expires_at.get())
                    .min(parent.expires_at().get());
                let context = ProvenanceContextV2::from_authenticated_runtime(
                    parent.producer_identity(),
                    session.durable_run_id,
                    session.active_state_manifest_digest,
                    now,
                    UnixMillisV2::new(expires),
                )
                .map_err(|_| G4Error::StateConflict)?;
                exchange_scheduled_fused_model_v04(
                    &mut policy.durable,
                    job.task,
                    job.revision,
                    FusedModelReleaseContextV04 {
                        rules,
                        provenance: context,
                        parents: &parents,
                        allowed_effects: session
                            .policy_allowed_effects
                            .intersection(parent.label().effects()),
                    },
                    policy.fused_workers[worker_index].as_mut(),
                    &mut clock,
                )
            },
        );
        match result {
            Ok(Ok(Some(FusedModelExchangeOutcomeV04::Accepted))) => {
                // Activation is not an effect ticket. Existing G7 commitments,
                // approval and exact started-prefix checks remain mandatory.
                if let Some(round) = job.round {
                    let at = clock();
                    let status = policy
                        .durable
                        .fused_planning_status_v04(job.task, at)
                        .map_err(|_| StableCode::PolicyDenied)?;
                    let result = policy.durable.update_fused_planning_v04(
                        job.task,
                        status.revision,
                        FusedPlanningUpdateV04::Activate {
                            round,
                            expected_plan_revision: status.active_plan_revision,
                        },
                        at,
                    );
                    match result {
                        Ok(_) | Err(G4Error::StateConflict) => (),
                        Err(_) => return Err(StableCode::KernelUnavailable),
                    }
                }
                Ok(())
            }
            Err(_) | Ok(Err(G4Error::StateConflict)) | Ok(Ok(_)) => Ok(()),
            Ok(Err(_)) => Err(StableCode::KernelUnavailable),
        }
    }
}
