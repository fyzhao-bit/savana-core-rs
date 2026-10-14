//! Private publication scheduling. Preparation, approval and dispatch run on
//! separate turns; old dispatches can only be queried, never recreated.
use super::*;
use savana_kernel_protocol::v2::*;

impl KernelAgentAuthorityV2 {
    /// Returns true only when the owner's private session received it.
    fn notify_fused_publication_v04(
        &self,
        task: DurableTaskIdV2,
        now: UnixMillisV2,
    ) -> Result<bool, KernelAgentAuthorityErrorV2> {
        let Some(publication) = self.fused_publication_v04(task)? else {
            return Ok(false);
        };
        let Some(session) = self.private_session_authentications.iter().find(|s| {
            s.consumed
                && s.task == task
                && s.root == publication.root()
                && s.envelope.unverified_material().is_ok_and(|e| {
                    now.get() >= e.issued_at().get() && now.get() < e.expires_at().get()
                })
        }) else {
            return Ok(false);
        };
        let e = session
            .envelope
            .unverified_material()
            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let p = self
            .policy
            .as_ref()
            .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?;
        let g = p
            .declassification_rules
            .generation_snapshot()
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        if g.active_state_manifest_digest() != e.active_state_manifest_digest()
            || g.deployment_generation() != e.deployment_generation()
        {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        let client = p
            .fused_approval_client
            .as_ref()
            .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?;
        self.verify_private_approval_edge_v04(
            client,
            e.active_state_manifest_digest(),
            e.deployment_generation(),
        )?;
        client
            .attach_private_publication_v04(
                session.registered.record,
                publication,
                UnixMillisV2::new(now.get().saturating_add(5000).min(e.expires_at().get())),
            )
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        Ok(true)
    }

    pub(super) fn tick_fused_releases_v04(
        &mut self,
        vault: &mut dyn KernelIngressCommitSinkV2,
        clock: &mut impl FnMut() -> UnixMillisV2,
    ) -> Result<(), StableCode> {
        self.ensure_durable_available()
            .map_err(|_| StableCode::KernelUnavailable)?;
        let now = clock();
        self.restore_fused_release_dispatches_v04()
            .map_err(|_| StableCode::KernelUnavailable)?;
        let Some(p) = self.policy.as_mut() else {
            return Ok(());
        };
        if p.g7.is_none() || now.get() < p.fused_release_not_before {
            return Ok(());
        }
        p.fused_release_not_before = now.get().saturating_add(1000);
        let active = p.declassification_rules.clone();
        let g = active
            .generation_snapshot()
            .map_err(|_| StableCode::KernelUnavailable)?;
        let mut jobs = self.fused_release_jobs_v04(
            g.active_state_manifest_digest(),
            g.deployment_generation(),
            g.effect_fence_epoch(),
            now,
        );
        jobs.sort_by_key(|j| j.0);
        let p = self.policy.as_mut().ok_or(StableCode::KernelUnavailable)?;
        let index = p
            .fused_release_last_task
            .and_then(|last| jobs.iter().position(|j| j.0 > last))
            .unwrap_or(0);
        let Some((task, run, historical)) = jobs.get(index).copied() else {
            return Ok(());
        };
        p.fused_release_last_task = Some(task);
        let result = if let Some(index) = historical {
            // Committed and acknowledged history only still owes the owner a
            // notification; asking execd again would return the same status.
            if self.fused_release_recovery[index].commit.is_some()
                && self.fused_release_recovery[index].acknowledged
            {
                Ok(())
            } else {
                self.reconcile_fused_release_v04(index, vault, now)
            }
        } else {
            self.advance_fused_release_v04(
                run.unwrap(),
                vault,
                g.active_state_manifest_digest(),
                g.deployment_generation(),
                g.effect_fence_epoch(),
                now,
                clock,
            )
        };
        // A private job may be denied/unavailable. Never expose that as a model
        // observation or replace its approval, identity or budget.
        let _ = result;
        // Notification is a derived owner-only observation, never permission to
        // execute, release again or refund. Failure leaves the durable original
        // commit intact and a later paced tick may send the same metadata.
        if let Ok(true) = self.notify_fused_publication_v04(DurableTaskIdV2::new(task), clock()) {
            if let Some(r) = self.fused_release_recovery.iter_mut().find(|r| {
                r.dispatch
                    .is_some_and(|c| *c.durable_task_id().as_bytes() == task)
            }) {
                r.owner_notified = true;
            }
        }
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

    /// Whether an owner private session that could still receive this task's
    /// publication notice exists (the same session `notify_fused_publication_v04`
    /// would use: consumed, for this task, envelope not yet expired).
    fn owner_can_receive_publication_v04(&self, task: DurableTaskIdV2, now: UnixMillisV2) -> bool {
        self.private_session_authentications.iter().any(|s| {
            s.consumed
                && s.task == task
                && s.envelope.unverified_material().is_ok_and(|e| {
                    now.get() >= e.issued_at().get() && now.get() < e.expires_at().get()
                })
        })
    }

    /// Candidates for the one-job-per-tick release rotation: this
    /// generation's unsettled history, then sessions whose final release is
    /// prepared. Settled history (committed, acknowledged and delivered to the
    /// owner) is not work: rotating it would delay every live release by one
    /// turn per finished task until none completes within its authorization.
    /// Neither is committed and acknowledged history whose owner session can no
    /// longer receive the notice (it expired with its task): it would otherwise
    /// keep a turn forever, so every release on a long-running host waits one
    /// more turn per finished task. A task with a committed release is never
    /// prepared again either.
    pub(super) fn fused_release_jobs_v04(
        &self,
        manifest: Digest32V2,
        generation: u64,
        fence: u64,
        now: UnixMillisV2,
    ) -> Vec<([u8; 32], Option<RunHandleV2>, Option<usize>)> {
        let mut jobs = self
            .fused_release_recovery
            .iter()
            .enumerate()
            .filter(|(_, r)| !r.settled())
            .filter_map(|(i, r)| {
                let core = r.dispatch?;
                if r.commit.is_some()
                    && r.acknowledged
                    && !self.owner_can_receive_publication_v04(core.durable_task_id(), now)
                {
                    return None;
                }
                if core.active_state_manifest_digest() != manifest
                    || core.deployment_generation() != generation
                    || core.effect_fence_epoch() != fence
                {
                    return None;
                }
                Some((*core.durable_task_id().as_bytes(), None, Some(i)))
            })
            .collect::<Vec<_>>();
        for s in &self.sessions {
            if jobs.iter().any(|j| j.0 == *s.durable_task_id.as_bytes())
                || self.fused_release_recovery.iter().any(|r| {
                    (r.settled() || r.commit.is_some())
                        && r.dispatch
                            .is_some_and(|c| c.durable_task_id() == s.durable_task_id)
                })
            {
                continue;
            }
            if self
                .prepare_fused_final_result_v04(s.run, manifest, generation, fence, now)
                .is_ok_and(|c| c.release().is_some())
            {
                jobs.push((*s.durable_task_id.as_bytes(), Some(s.run), None));
            }
        }
        jobs
    }

    pub(super) fn restore_fused_release_dispatches_v04(
        &mut self,
    ) -> Result<(), KernelAgentAuthorityErrorV2> {
        let Some(p) = self.policy.as_ref() else {
            return Ok(());
        };
        let mut recovered = Vec::new();
        for (index, r) in self
            .fused_release_recovery
            .iter()
            .enumerate()
            .filter(|(_, r)| r.dispatch.is_none())
        {
            let m = r
                .envelope
                .unverified_material()
                .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
            let ApprovalBindingV2::FinalRelease { binding } = m.binding() else {
                return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
            };
            if let Some(core) = p
                .durable
                .recover_final_release_core_v04(binding.durable_release_id())
                .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?
            {
                let core = protocol_historical_dispatch_core(&core)?;
                if !matches!(core.subject(), ProtocolDispatchSubjectV2::FinalRelease { binding: saved, .. } if saved == binding)
                    || core.durable_task_id()
                        != m.task_action_binding()
                            .ok_or(KernelAgentAuthorityErrorV2::BindingMismatch)?
                            .task()
                    || r.settlement.is_none()
                {
                    return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
                }
                recovered.push((index, core));
            }
        }
        if recovered.is_empty() {
            return Ok(());
        }
        for (i, core) in recovered {
            self.fused_release_recovery[i].dispatch = Some(core);
        }
        self.persist_fused_release_archive_v04()
    }

    #[allow(clippy::too_many_arguments)]
    fn advance_fused_release_v04(
        &mut self,
        run: RunHandleV2,
        vault: &mut dyn KernelIngressCommitSinkV2,
        manifest: Digest32V2,
        generation: u64,
        fence: u64,
        now: UnixMillisV2,
        clock: &mut impl FnMut() -> UnixMillisV2,
    ) -> Result<(), KernelAgentAuthorityErrorV2> {
        let Some(index) = self
            .pending_releases
            .iter()
            .position(|p| p.run == run && p.private_candidate.is_some())
        else {
            self.prepare_fused_release_v04(run, vault, manifest, generation, fence, now)?;
            return Ok(());
        };
        let p = &self.pending_releases[index];
        if let Some(ticket) = p.ticket_commitment {
            let ticket = self
                .release_tickets
                .iter()
                .find(|t| t.commitment == ticket)
                .ok_or(KernelAgentAuthorityErrorV2::StateConflict)?
                .ticket;
            let active = self.policy.as_ref().unwrap().declassification_rules.clone();
            return active
                .with_current_fused_dispatch_policy(
                    self.config.installation_id,
                    manifest,
                    generation,
                    fence,
                    now.get(),
                    |_, _| {
                        self.dispatch_release_for(
                            release_request_id()?,
                            DispatchReleaseRequestV2::new(ticket),
                            vault,
                            true,
                            manifest,
                            generation,
                            fence,
                            now,
                        )
                        .map(|_| ())
                    },
                )
                .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?;
        }
        if p.consumed {
            return Ok(());
        }
        if let Some(receipt) = self
            .fused_release_recovery
            .iter()
            .find(|r| Some(r.candidate) == p.private_candidate)
            .and_then(|r| r.settlement.clone())
        {
            let request = AuthorizeReleaseRequestV2::new(p.pending, p.approval, receipt)
                .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
            return self
                .authorize_release_for(&request, vault, true, manifest, generation, now)
                .map(|_| ());
        }
        let policy = self
            .policy
            .as_ref()
            .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?;
        let client = policy
            .fused_approval_client
            .as_ref()
            .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?;
        let edge = client.deployment_edge();
        if edge.role() != EndpointRoleV2::KernelApproval
            || edge.installation_id() != self.config.installation_id
            || edge.active_state_manifest_digest() != manifest
            || edge.deployment_generation() != generation
            || edge.client_identity() != self.config.kerneld_identity
            || edge.server_identity() != self.config.approvald_identity
            || edge.server_boot_id() != self.config.approvald_boot_id
            || now.get() >= p.expires_at.get()
        {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        self.recheck_release_task(p, manifest, generation, now)?;
        let deadline = UnixMillisV2::new(now.get().saturating_add(5000).min(p.expires_at.get()));
        let RegisteredApprovalV2::Release { approval, .. } = client
            .register_approval(
                p.envelope.clone(),
                p.display_authentication.clone(),
                deadline,
            )
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?
        else {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        };
        let after = clock();
        if after.get() < now.get() || after.get() >= deadline.get() {
            return Err(KernelAgentAuthorityErrorV2::Expired);
        }
        if let Some(session) = self
            .private_session_authentications
            .iter()
            .find(|s| s.task == p.durable_task_id && s.consumed)
        {
            client
                .attach_private_release_approval_v04(
                    session.registered.record,
                    approval,
                    session.root,
                    deadline,
                )
                .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        }
        let query = clock();
        if query.get() < after.get() || query.get() >= deadline.get() {
            return Err(KernelAgentAuthorityErrorV2::Expired);
        }
        let view = client
            .get_kernel_release_approval_settlement(approval, deadline)
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        let received = clock();
        if received.get() < query.get() || received.get() >= deadline.get() {
            return Err(KernelAgentAuthorityErrorV2::Expired);
        }
        if let ApprovalSettlementViewV2::Approved { settlement }
        | ApprovalSettlementViewV2::Denied { settlement } = view
        {
            let request = AuthorizeReleaseRequestV2::new(p.pending, p.approval, settlement)
                .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
            self.authorize_release_for(&request, vault, true, manifest, generation, received)?;
        }
        Ok(())
    }

    /// Reconciliation requires no new session or approval. It cannot send a
    /// business request: only query/fetch/ack against the original nonce.
    pub(super) fn reconcile_fused_release_v04(
        &mut self,
        index: usize,
        vault: &mut dyn KernelIngressCommitSinkV2,
        now: UnixMillisV2,
    ) -> Result<(), KernelAgentAuthorityErrorV2> {
        let r = self
            .fused_release_recovery
            .get(index)
            .cloned()
            .ok_or(KernelAgentAuthorityErrorV2::InvalidReference)?;
        let core = r
            .dispatch
            .ok_or(KernelAgentAuthorityErrorV2::StateConflict)?;
        let digest = core
            .semantic_digest()
            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let ProtocolDispatchSubjectV2::FinalRelease { binding, .. } = core.subject() else {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        };
        let id = release_request_id()?;
        let p = self
            .policy
            .as_ref()
            .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?;
        let g7 =
            p.g7.as_ref()
                .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?;
        let query = g7
            .executor
            .query(
                id,
                checked_deadline(now, 5000)?,
                QueryByExecutionNonceRequestV2::new(
                    core.execution_nonce(),
                    digest,
                    core.dispatch_subject_digest(),
                )
                .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?,
            )
            .map_err(map_executor_client_error)?;
        let completion = match query.status() {
            ExecutorStatusV2::Acknowledged if r.commit.is_some() => {
                self.fused_release_recovery[index].acknowledged = true;
                return Ok(());
            }
            ExecutorStatusV2::CompletionAvailable { completion, .. } => *completion,
            ExecutorStatusV2::FailedNoEffect { .. } => {
                let outcome = verify_task_no_effect_response(
                    &p.durable,
                    &query,
                    core.execution_nonce(),
                    digest,
                    core.dispatch_subject_digest(),
                    g7.executor_receipt_key_id,
                    g7.executor_receipt_public_key,
                    now,
                )?;
                self.policy
                    .as_mut()
                    .unwrap()
                    .durable
                    .reconcile_task_outcome(outcome)
                    .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?;
                return vault
                    .mark_release_failed_no_effect(
                        binding.durable_release_id(),
                        core.execution_nonce(),
                        digest,
                        core.dispatch_subject_digest(),
                        now,
                    )
                    .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict);
            }
            _ => return Ok(()), // Uncertainty is never reclassified as no-effect.
        };
        let commit = if let Some(commit) = r.commit {
            if r.completion != Some(completion) {
                return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
            }
            commit
        } else {
            let response = g7
                .executor
                .fetch_completion(
                    id,
                    checked_deadline(now, 5000)?,
                    FetchCompletionRequestV2::new(
                        core.execution_nonce(),
                        digest,
                        core.dispatch_subject_digest(),
                        completion,
                    )
                    .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?,
                )
                .map_err(map_executor_client_error)?;
            if response.execution_nonce() != core.execution_nonce()
                || response.dispatch_core_digest() != digest
                || response.dispatch_subject_digest() != core.dispatch_subject_digest()
                || response.completion() != completion
            {
                return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
            }
            let ExecutorCompletionPayloadV2::FinalReleaseReceipt {
                receipt,
                audit_evidence,
                ..
            } = response.payload()
            else {
                return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
            };
            receipt
                .verify(g7.executor_receipt_key_id, g7.executor_receipt_public_key)
                .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
            let u = receipt.unsigned();
            if u.installation_id() != core.installation_id()
                || u.active_state_manifest_digest() != core.active_state_manifest_digest()
                || u.durable_release_id() != binding.durable_release_id()
                || u.execution_nonce() != core.execution_nonce()
                || u.dispatch_core_digest() != digest
                || u.dispatch_subject_digest() != core.dispatch_subject_digest()
                || u.vault_segment_digest() != binding.vault_segment_digest()
                || u.release_payload_digest() != binding.release_payload_digest()
                || u.destination_digest() != binding.destination_digest()
                || u.executor_identity() != core.executor_identity()
                || u.release_audit_digest() != audit_evidence.digest()
                || completion.final_release_identity()
                    != Some((
                        binding.durable_release_id(),
                        receipt.digest(),
                        audit_evidence.digest(),
                    ))
            {
                return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
            }
            let outcome = verify_task_completion_response(
                &p.durable,
                &response,
                g7.executor_receipt_key_id,
                g7.executor_receipt_public_key,
                now,
            )?;
            self.policy
                .as_mut()
                .unwrap()
                .durable
                .reconcile_task_outcome(outcome)
                .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?;
            vault
                .commit_recovered_release(
                    binding.durable_release_id(),
                    core.execution_nonce(),
                    digest,
                    core.dispatch_subject_digest(),
                    receipt.digest(),
                    audit_evidence.digest(),
                    now,
                )
                .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?;
            let commit = domain_digest(
                b"SAVANA_KERNEL_RELEASE_COMMIT_V2\0",
                &[
                    digest.as_bytes(),
                    receipt.digest().as_bytes(),
                    audit_evidence.digest().as_bytes(),
                ],
            );
            self.fused_release_recovery[index].completion = Some(completion);
            self.fused_release_recovery[index].commit = Some(commit);
            self.persist_fused_release_archive_v04()?;
            commit
        };
        self.policy
            .as_ref()
            .unwrap()
            .g7
            .as_ref()
            .unwrap()
            .executor
            .acknowledge(
                id,
                checked_deadline(now, 5000)?,
                AcknowledgeCommittedCompletionRequestV2::new(
                    core.execution_nonce(),
                    digest,
                    core.dispatch_subject_digest(),
                    completion,
                    commit,
                )
                .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?,
            )
            .map_err(map_executor_client_error)?;
        Ok(())
    }
}

fn release_request_id() -> Result<RequestIdV2, KernelAgentAuthorityErrorV2> {
    let mut bytes = [0; 16];
    getrandom(&mut bytes).map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
    if bytes == [0; 16] {
        return Err(KernelAgentAuthorityErrorV2::Unavailable);
    }
    Ok(RequestIdV2::new(bytes))
}
