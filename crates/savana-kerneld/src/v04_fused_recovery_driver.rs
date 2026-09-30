//! Owner-clock workflow rotation and historical reconciliation.
use super::*;
use savana_policy_core::v2::{KernelDispatchStateV2, RecoveredFusedExecutionV04};

impl KernelAgentAuthorityV2 {
    pub(crate) fn tick_private_workflows_v04(
        &mut self,
        values: &mut KernelValueOwnerV2,
        vault: Option<&mut dyn KernelIngressCommitSinkV2>,
        mut clock: impl FnMut() -> UnixMillisV2,
    ) -> Result<(), StableCode> {
        self.ensure_durable_available()
            .map_err(|_| StableCode::KernelUnavailable)?;
        let login_pending = self
            .private_session_authentications
            .iter()
            .any(|p| !p.consumed);
        let Some(policy) = self.policy.as_mut() else {
            return Ok(());
        };
        // Planning, recovery and new actions each get their own turn, never two network
        // pipelines under a single queue deadline. No missed-tick catch-up.
        let phase = policy.fused_workflow_phase;
        policy.fused_workflow_phase = (phase + 1) % if login_pending { 5 } else { 4 };
        if phase == 4 {
            return self.tick_private_sessions_v04(values, &mut clock);
        }
        if phase == 1 {
            return self.tick_fused_planning(values, clock);
        }
        let Some(vault) = vault else {
            return Ok(());
        };
        if phase == 3 {
            return self.tick_fused_releases_v04(vault, &mut clock);
        }
        if policy.g7.is_none() {
            return Ok(());
        }
        if phase == 2 {
            return self.tick_fused_actions_v04(values, &mut clock);
        }
        let active = policy.declassification_rules.clone();
        active
            .with_recovery_generation(|generation| {
                self.tick_fused_recovery_v04(
                    vault,
                    generation.active_state_manifest_digest(),
                    generation.deployment_generation(),
                    generation.effect_fence_epoch(),
                    clock(),
                )
            })
            .map_err(|_| StableCode::KernelUnavailable)?
    }

    /// One historical execution per turn, selected only from authenticated owner
    /// state. Errors on one job retain its reservation and do not starve others.
    pub(super) fn tick_fused_recovery_v04(
        &mut self,
        vault: &mut dyn KernelIngressCommitSinkV2,
        manifest: Digest32V2,
        generation: u64,
        fence: u64,
        now: UnixMillisV2,
    ) -> Result<(), StableCode> {
        self.ensure_durable_available()
            .map_err(|_| StableCode::KernelUnavailable)?;
        if now.get() == 0 {
            return Err(StableCode::KernelUnavailable);
        }
        let Some(policy) = self.policy.as_mut() else {
            return Ok(());
        };
        if now.get() < policy.fused_recovery_not_before {
            return Ok(());
        }
        // At most one recovery pipeline per second, even for a single unavailable
        // executor. Restart loses only this pacing cursor, never durable charges.
        policy.fused_recovery_not_before = now.get().saturating_add(1_000);
        let mut jobs = policy
            .durable
            .recover_all_scoped_fused_executions_v04()
            .map_err(|_| StableCode::KernelUnavailable)?;
        jobs.retain(|r| {
            let c = r.core();
            c.installation_id() == self.config.installation_id
                && c.active_state_manifest_digest() == manifest
                && c.deployment_generation() == generation
                && c.effect_fence_epoch() == fence
                && r.state() != KernelDispatchStateV2::FailedNoEffect
                && !policy
                    .fused_cleanup_confirmed
                    .contains(c.execution_nonce().as_bytes())
        });
        jobs.sort_by_key(|r| *r.core().execution_nonce().as_bytes());
        let selected = policy
            .fused_recovery_last_nonce
            .and_then(|last| {
                jobs.iter()
                    .position(|r| *r.core().execution_nonce().as_bytes() > last)
            })
            .unwrap_or(0);
        let Some(job) = jobs.get(selected).cloned() else {
            return Ok(());
        };
        policy.fused_recovery_last_nonce = Some(*job.core().execution_nonce().as_bytes());
        let mut entropy = [0u8; 16];
        getrandom(&mut entropy).map_err(|_| StableCode::KernelUnavailable)?;
        if entropy == [0; 16] {
            return Err(StableCode::KernelUnavailable);
        }
        let request_id = savana_kernel_protocol::v2::RequestIdV2::new(entropy);
        let result = if job.result_commit().is_some() {
            // No need to remint a document, fetch plaintext or extend retention
            // just to finish cleanup. The durable checkpoint proves prior commit.
            self.retry_fused_cleanup_v04(&job, request_id, now)
        } else {
            self.restore_fused_execution_records_v04(vec![job], manifest, generation, fence)
                .and_then(|handles| {
                    let execution = handles
                        .first()
                        .ok_or(KernelAgentAuthorityErrorV2::StateConflict)?;
                    self.reconcile_fused_execution_v04(
                        execution, request_id, vault, manifest, generation, fence, now,
                    )
                    .map(|_| ())
                })
        };
        // A transport timeout, invalid receipt, capacity refusal or expired result
        // is private job-local failure, not a public error or permission to retry
        // the provider effect. Poisoned storage, in contrast, stops the owner.
        let _ = result;
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

    fn retry_fused_cleanup_v04(
        &mut self,
        job: &RecoveredFusedExecutionV04,
        request_id: savana_kernel_protocol::v2::RequestIdV2,
        now: UnixMillisV2,
    ) -> Result<(), KernelAgentAuthorityErrorV2> {
        let c = job.core();
        let commit = job
            .result_commit()
            .ok_or(KernelAgentAuthorityErrorV2::StateConflict)?;
        let g7 = self
            .policy
            .as_ref()
            .and_then(|p| p.g7.as_ref())
            .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?;
        let deadline = checked_deadline(now, 5_000)?;
        let reply = g7
            .executor
            .query(
                request_id,
                deadline,
                QueryByExecutionNonceRequestV2::new(
                    c.execution_nonce(),
                    job.core_digest(),
                    c.dispatch_subject_digest(),
                )
                .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?,
            )
            .map_err(map_executor_client_error)?;
        match reply.status() {
            ExecutorStatusV2::Acknowledged => {
                // A lost acknowledgement response is resolved by an authenticated
                // query. This is only a cleanup cache, never new success evidence.
                self.policy
                    .as_mut()
                    .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?
                    .fused_cleanup_confirmed
                    .insert(*c.execution_nonce().as_bytes());
                Ok(())
            }
            ExecutorStatusV2::CompletionAvailable {
                effect_started_receipt: receipt,
                effect_started_receipt_digest: digest,
                completion,
            } => {
                let u = receipt.unsigned();
                if u.execution_nonce() != c.execution_nonce()
                    || u.dispatch_core_digest() != job.core_digest()
                    || u.dispatch_subject_digest() != c.dispatch_subject_digest()
                    || u.installation_id() != c.installation_id()
                    || u.active_state_manifest_digest() != c.active_state_manifest_digest()
                    || u.deployment_generation() != c.deployment_generation()
                    || u.effect_fence_epoch() != c.effect_fence_epoch()
                    || u.started_at().get() > now.get()
                    || receipt.digest() != *digest
                {
                    return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
                }
                receipt
                    .verify(g7.executor_receipt_key_id, g7.executor_receipt_public_key)
                    .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
                let result = completion
                    .tool_result_digest()
                    .ok_or(KernelAgentAuthorityErrorV2::BindingMismatch)?;
                let expected = domain_digest(
                    b"SAVANA_TOOL_RESULT_GATE_COMMIT_V2\0",
                    &[
                        job.core_digest().as_bytes(),
                        digest.as_bytes(),
                        result.as_bytes(),
                    ],
                );
                if expected != commit {
                    return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
                }
                // Repeat only this exact cleanup, never FetchCompletion or Dispatch.
                g7.executor
                    .acknowledge(
                        request_id,
                        deadline,
                        savana_kernel_protocol::v2::AcknowledgeCommittedCompletionRequestV2::new(
                            c.execution_nonce(),
                            job.core_digest(),
                            c.dispatch_subject_digest(),
                            *completion,
                            commit,
                        )
                        .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?,
                    )
                    .map_err(map_executor_client_error)?;
                // Confirm with Query on the next turn; no new durable schema or
                // unverified acknowledgement response is treated as result proof.
                Ok(())
            }
            _ => Err(KernelAgentAuthorityErrorV2::StateConflict),
        }
    }
}
