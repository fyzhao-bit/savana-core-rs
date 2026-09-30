//! Host-private result preparation. No Agent RPC, public data or release grant.
use super::*;

impl KernelAgentAuthorityV2 {
    /// No Agent-supplied bytes, source, descriptor, destination or clause. The
    /// selector is signed in the private profile and matched to the live root.
    pub(super) fn prepare_fused_release_v04(
        &mut self,
        run: savana_kernel_protocol::v2::RunHandleV2,
        vault: &mut dyn KernelIngressCommitSinkV2,
        manifest: Digest32V2,
        generation: u64,
        fence: u64,
        now: UnixMillisV2,
    ) -> Result<PrepareReleaseResponseV2, KernelAgentAuthorityErrorV2> {
        let candidate =
            self.prepare_fused_final_result_v04(run, manifest, generation, fence, now)?;
        if let Some(p) = self
            .pending_releases
            .iter()
            .find(|p| p.run == run && p.private_candidate.is_some())
        {
            if p.private_candidate != Some(candidate.digest()) || p.expires_at.get() <= now.get() {
                return Err(KernelAgentAuthorityErrorV2::StateConflict);
            }
            return Ok(PrepareReleaseResponseV2::new(
                p.pending,
                p.approval,
                p.envelope.clone(),
                p.display_authentication.clone(),
            ));
        }
        if self.pending_releases.len() >= self.maximum_records {
            return Err(KernelAgentAuthorityErrorV2::LimitExceeded);
        }
        let release = candidate
            .release()
            .ok_or(KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let session = self
            .sessions
            .iter()
            .find(|s| s.run == run)
            .ok_or(KernelAgentAuthorityErrorV2::InvalidReference)?;
        let policy = self
            .policy
            .as_ref()
            .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?;
        let g7 = policy
            .g7
            .as_ref()
            .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?;
        let original = policy
            .durable
            .recover_fused_executions_v04(candidate.task())
            .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?
            .into_iter()
            .find(|e| {
                e.core() == candidate.core() && e.result_commit() == Some(candidate.result_commit())
            })
            .ok_or(KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let descriptor_digest = Digest32V2::new(release.descriptor);
        let active = policy
            .active_tools
            .resolve(descriptor_digest, session.role, now)
            .ok_or(KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let descriptor = active.descriptor().unsigned();
        let profile = descriptor
            .business_profile()
            .ok_or(KernelAgentAuthorityErrorV2::BindingMismatch)?;
        if descriptor.executor_identity() != g7.executor_identity
            || descriptor.destination_projection_digest()
                != compiled_projection_digest(
                    PROJECTION_DESTINATION_DOMAIN,
                    descriptor.destination_projection().get(),
                )
            || descriptor.display_projection_digest()
                != compiled_projection_digest(
                    PROJECTION_DISPLAY_DOMAIN,
                    descriptor.display_projection().get(),
                )
        {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        let resource = savana_kernel_protocol::v2::fused_final_result_resource_v04(
            candidate.task(),
            candidate.source(),
            original.descriptor(),
        )
        .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let business_request =
            savana_kernel_protocol::v2::final_result_release_business_request_v04(
                profile,
                &business_step_request_id(savana_kernel_protocol::v2::InternalStepIdV2::new(
                    *candidate.digest().as_bytes(),
                )),
                resource,
                Digest32V2::new(release.turn),
                candidate.private_payload(),
            )
            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let provenance = candidate.provenance().provenance_digest();
        let evidence_digest = savana_policy_core::v2::evidence_digest_v2(&[
            savana_policy_core::v2::EvidenceDigestEntryV2::new(
                savana_policy_core::v2::value_digest_v2(candidate.value())
                    .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?,
                provenance,
            ),
        ])
        .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let token_set_digest =
            savana_policy_core::v2::token_set_digest_v2(&[TokenSetDigestEntryV2::new(
                IdentifierV2::new("terminal_result").unwrap(),
                candidate.digest(),
                provenance,
                g7.executor_identity,
            )])
            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let state = policy
            .durable
            .task_authorization_state(candidate.task())
            .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?;
        let matched = match_business_proposal(
            &state,
            &business_request,
            descriptor_digest,
            PlanRevisionDigestV2::new(*candidate.profile().as_bytes()),
            evidence_digest,
            // Final result release has no result-derived controls.
            &std::collections::BTreeMap::new(),
            generation,
            now,
        )?;
        if matched.content().clause_id() != release.clause {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        let selections =
            savana_policy_core::v2::ControlSelectionV2::from_match(&matched, provenance)
                .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let proposal = FinalReleaseBusinessProposalV2 {
            business_request,
            task_match: matched,
            control_selections: selections,
            display_projection_digest: descriptor.display_projection_digest(),
        };
        let executor = g7.executor_identity;
        self.finish_prepare_release(
            run,
            None,
            executor,
            Some(candidate.digest()),
            proposal,
            vec![candidate.provenance().clone()],
            candidate.provenance().label().effects(),
            domain_digest(
                b"SAVANA_FINAL_RELEASE_PAYLOAD_V2\0",
                &[candidate.private_payload()],
            ),
            evidence_digest,
            token_set_digest,
            vault,
            manifest,
            generation,
            now,
        )
    }

    /// Recover a declared terminal result only for the current authenticated
    /// run, while holding the live deployment/fence lease. The returned private
    /// candidate must still pass distinct result-resource authorization, G3,
    /// FinalRelease approval and durable vault publication before any export.
    pub(super) fn prepare_fused_final_result_v04(
        &self,
        run: savana_kernel_protocol::v2::RunHandleV2,
        manifest: Digest32V2,
        generation: u64,
        fence: u64,
        now: UnixMillisV2,
    ) -> Result<savana_policy_core::v2::FusedFinalResultCandidateV04, KernelAgentAuthorityErrorV2>
    {
        self.ensure_durable_available()?;
        let policy = self
            .policy
            .as_ref()
            .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?;
        policy
            .declassification_rules
            .with_current_fused_dispatch_policy(
                self.config.installation_id,
                manifest,
                generation,
                fence,
                now.get(),
                |_, _| {
                    let s = self
                        .sessions
                        .iter()
                        .find(|s| {
                            s.run == run
                                && matches!(
                                    s.status,
                                    AgentSessionStatusV2::Ready | AgentSessionStatusV2::Running,
                                )
                        })
                        .ok_or(KernelAgentAuthorityErrorV2::InvalidReference)?;
                    let root = self.require_current_session_task_authorization(s, now)?;
                    if s.active_state_manifest_digest != manifest
                        || s.task_authorization_digest != Some(root)
                    {
                        return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
                    }
                    let candidate = policy
                        .durable
                        .fused_final_result_candidate_v04(s.durable_task_id, now)
                        .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?;
                    let core = candidate.core();
                    if candidate.root() != root
                        || core.durable_run_id() != s.durable_run_id
                        || core.installation_id() != self.config.installation_id
                        || core.active_state_manifest_digest() != manifest
                        || core.deployment_generation() != generation
                        || core.effect_fence_epoch() != fence
                        || candidate.provenance().producer_identity() != s.producer_identity
                        || candidate.provenance().expires_at().get() > s.expires_at.get()
                    {
                        return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
                    }
                    Ok(candidate)
                },
            )
            .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?
    }
}
