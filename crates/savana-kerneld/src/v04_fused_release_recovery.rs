//! Encrypted, rollback-anchored publication history. No raw output, session or
//! boot-local capability is restored by this archive.
use super::*;
use savana_kernel_protocol::v2::SignedApprovalSettlementV2;

#[derive(Clone)]
pub(super) struct FusedReleaseRecoveryV04 {
    pub(super) candidate: Digest32V2,
    pub(super) envelope: SignedApprovalEnvelopeV2,
    pub(super) display: SignedUiAuthenticationEnvelopeV2,
    pub(super) settlement: Option<SignedApprovalSettlementV2>,
    pub(super) dispatch: Option<ProtocolDispatchCoreV2>,
    pub(super) completion: Option<savana_kernel_protocol::v2::ExecutorCompletionDescriptorV2>,
    pub(super) commit: Option<Digest32V2>,
}

impl KernelAgentAuthorityV2 {
    /// Derive owner notification solely from already committed release history.
    /// No reservation, timeout, model response or approval alone is completion.
    pub(super) fn fused_publication_v04(
        &self,
        task: DurableTaskIdV2,
    ) -> Result<
        Option<savana_kernel_protocol::v2::PrivatePublicationV04>,
        KernelAgentAuthorityErrorV2,
    > {
        self.ensure_durable_available()?;
        let Some(r) = self
            .fused_release_recovery
            .iter()
            .find(|r| r.dispatch.is_some_and(|c| c.durable_task_id() == task))
        else {
            return Ok(None);
        };
        let Some(commit) = r.commit else {
            return Ok(None);
        };
        self.validate_fused_release_archive_v04(r)?;
        let core = r
            .dispatch
            .ok_or(KernelAgentAuthorityErrorV2::StateConflict)?;
        let (release, receipt, audit) = r
            .completion
            .and_then(|c| c.final_release_identity())
            .ok_or(KernelAgentAuthorityErrorV2::StateConflict)?;
        let ProtocolDispatchSubjectV2::FinalRelease { binding, .. } = core.subject() else {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        };
        Ok(Some(
            savana_kernel_protocol::v2::PrivatePublicationV04::new(
                task,
                core.durable_run_id(),
                core.task_binding()
                    .ok_or(KernelAgentAuthorityErrorV2::StateConflict)?
                    .authorization_digest(),
                self.config.kerneld_server_boot_id,
                release,
                binding.release_payload_digest(),
                binding.destination_digest(),
                r.envelope
                    .envelope_digest()
                    .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?,
                receipt,
                audit,
                commit,
            )
            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?,
        ))
    }

    pub(super) fn encode_fused_release_recovery_v04(
        &self,
        e: &mut minicbor::Encoder<Vec<u8>>,
    ) -> Result<(), KernelAgentAuthorityErrorV2> {
        e.array(self.fused_release_recovery.len() as u64)
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        for r in &self.fused_release_recovery {
            e.array(7)
                .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
            encode_recovery_value(e, &r.candidate)?;
            encode_recovery_value(e, &r.envelope)?;
            encode_recovery_value(e, &r.display)?;
            encode_optional_recovery_value(e, r.settlement.as_ref())?;
            match r.dispatch {
                Some(core) => {
                    e.bytes(
                        &core
                            .canonical_bytes()
                            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?,
                    )
                    .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
                }
                None => {
                    e.null()
                        .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
                }
            }
            match r.completion {
                Some(completion) => {
                    let (id, receipt, audit) = completion
                        .final_release_identity()
                        .ok_or(KernelAgentAuthorityErrorV2::BindingMismatch)?;
                    e.array(4)
                        .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
                    encode_recovery_value(e, &id)?;
                    encode_recovery_value(e, &receipt)?;
                    encode_recovery_value(e, &audit)?;
                    e.u32(completion.encoded_length())
                        .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
                }
                None => {
                    e.null()
                        .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
                }
            }
            encode_optional_recovery_value(e, r.commit.as_ref())?;
        }
        Ok(())
    }
    pub(super) fn decode_fused_release_recovery_v04(
        &mut self,
        d: &mut minicbor::Decoder<'_>,
        c: &mut V2DecodeContext,
    ) -> Result<(), KernelAgentAuthorityErrorV2> {
        let count = decode_recovery_count(d, self.maximum_records)?;
        for _ in 0..count {
            require_recovery_array(d, 7)?;
            let r = FusedReleaseRecoveryV04 {
                candidate: decode_recovery_value(d, c)?,
                envelope: decode_recovery_value(d, c)?,
                display: decode_recovery_value(d, c)?,
                settlement: decode_optional_recovery_value(d, c)?,
                dispatch: if d
                    .datatype()
                    .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?
                    == minicbor::data::Type::Null
                {
                    d.null()
                        .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
                    None
                } else {
                    Some(
                        ProtocolDispatchCoreV2::from_canonical_bytes(
                            d.bytes()
                                .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?,
                        )
                        .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?,
                    )
                },
                completion: if d
                    .datatype()
                    .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?
                    == minicbor::data::Type::Null
                {
                    d.null()
                        .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
                    None
                } else {
                    require_recovery_array(d, 4)?;
                    Some(savana_kernel_protocol::v2::ExecutorCompletionDescriptorV2::final_release_receipt(
                        decode_recovery_value(d,c)?, decode_recovery_value(d,c)?, decode_recovery_value(d,c)?,
                        d.u32().map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?)
                        .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?)
                },
                commit: decode_optional_recovery_value(d, c)?,
            };
            let material = self.validate_fused_release_archive_v04(&r)?;
            let task = material.task_action_binding().unwrap().task();
            if self.fused_release_recovery.iter().any(|r| {
                r.envelope
                    .unverified_material()
                    .ok()
                    .and_then(|e| e.task_action_binding())
                    .is_some_and(|b| b.task() == task)
            }) {
                return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
            }
            self.fused_release_recovery.push(r);
        }
        Ok(())
    }
    fn validate_fused_release_archive_v04(
        &self,
        r: &FusedReleaseRecoveryV04,
    ) -> Result<UnsignedApprovalEnvelopeV2, KernelAgentAuthorityErrorV2> {
        let fail = |_| KernelAgentAuthorityErrorV2::BindingMismatch;
        let raw = r.envelope.unverified_material().map_err(fail)?;
        let key = self.config.envelope_signing_key.verifying_key().to_bytes();
        let m = r
            .envelope
            .verify(
                derive_ed25519_key_id_v2(key),
                key,
                self.config.installation_id,
                raw.active_state_manifest_digest(),
                raw.deployment_generation(),
                ApprovalPurposeV2::FinalRelease,
                raw.expected_principal(),
                raw.issued_at(),
            )
            .map_err(fail)?;
        let display = r
            .display
            .verify_deployment(
                derive_ed25519_key_id_v2(key),
                key,
                self.config.installation_id,
                m.active_state_manifest_digest(),
                m.deployment_generation(),
            )
            .map_err(fail)?;
        let task = m
            .task_action_binding()
            .ok_or(KernelAgentAuthorityErrorV2::BindingMismatch)?
            .task();
        if r.candidate.as_bytes() == &[0; 32]
            || !matches!(m.binding(), ApprovalBindingV2::FinalRelease { .. })
            || m.approvald_endpoint_identity() != self.config.approvald_identity
            || m.display_declassification_provenance_digest().is_none()
            || m.display_digest() != approval_display_digest_v2(m.display_text().as_bytes())
            || display.purpose() != UiAuthenticationPurposeV2::ApprovalDisplay
            || display.expected_principal() != Some(m.expected_principal())
            || display.authentication_origin() != FixedOriginV2::Approval8766
            || display.return_origin() != FixedOriginV2::Approval8766
            || display.issued_at() != m.issued_at()
            || display.expires_at() != m.expires_at()
            || display.binding()
                != (UiAuthenticationBindingV2::ApprovalDisplay {
                    durable_task_id: task,
                    approval_envelope_digest: r.envelope.envelope_digest().map_err(fail)?,
                    approval_purpose: ApprovalPurposeV2::FinalRelease,
                    display_digest: m.display_digest(),
                })
        {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        if let Some(core) = &r.dispatch {
            if core.installation_id() != self.config.installation_id
                || core.durable_task_id() != task
                || core.active_state_manifest_digest() != m.active_state_manifest_digest()
                || core.deployment_generation() != m.deployment_generation()
                || r.settlement.is_none()
            {
                return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
            }
            if !matches!((core.subject(), m.binding()),
                (ProtocolDispatchSubjectV2::FinalRelease { binding: a, .. }, ApprovalBindingV2::FinalRelease { binding: b }) if a == b)
            {
                return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
            }
            let receipt = r
                .settlement
                .as_ref()
                .ok_or(KernelAgentAuthorityErrorV2::BindingMismatch)?;
            let expected = m.task_action_context(&receipt.unsigned()).map_err(fail)?;
            if !matches!(core.subject(), ProtocolDispatchSubjectV2::FinalRelease { approval_settlement_digest, .. }
                if approval_settlement_digest == receipt.settlement_digest().map_err(fail)?)
                || core.task_binding().map(|b| b.content_digest()) != Some(expected.content_digest)
                || receipt.unsigned().decision() != ApprovalDecisionV2::Approve
            {
                return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
            }
        }
        if r.completion.is_some() != r.commit.is_some()
            || (r.completion.is_some() && r.dispatch.is_none())
        {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        if let Some(completion) = r.completion {
            let core = r
                .dispatch
                .ok_or(KernelAgentAuthorityErrorV2::BindingMismatch)?;
            let (id, receipt, audit) = completion
                .final_release_identity()
                .ok_or(KernelAgentAuthorityErrorV2::BindingMismatch)?;
            let ApprovalBindingV2::FinalRelease { binding } = m.binding() else {
                return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
            };
            let commit = domain_digest(
                b"SAVANA_KERNEL_RELEASE_COMMIT_V2\0",
                &[
                    core.semantic_digest().map_err(fail)?.as_bytes(),
                    receipt.as_bytes(),
                    audit.as_bytes(),
                ],
            );
            if id != binding.durable_release_id() || r.commit != Some(commit) {
                return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
            }
        }
        Ok(m)
    }

    pub(super) fn bind_fused_release_archive_v04(
        &mut self,
        index: usize,
        now: UnixMillisV2,
    ) -> Result<(), KernelAgentAuthorityErrorV2> {
        let p = &self.pending_releases[index];
        let Some(candidate) = p.private_candidate else {
            return Ok(());
        };
        let new = p
            .envelope
            .unverified_material()
            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let existing = self
            .fused_release_recovery
            .iter()
            .find(|r| {
                r.envelope
                    .unverified_material()
                    .ok()
                    .and_then(|m| m.task_action_binding())
                    .is_some_and(|b| b.task() == p.durable_task_id)
            })
            .cloned();
        if let Some(r) = existing {
            let old = self.validate_fused_release_archive_v04(&r)?;
            if r.candidate != candidate
                || r.dispatch.is_some()
                || old.expires_at().get() <= now.get()
                || old.issued_at().get() > now.get()
                || old.binding() != new.binding()
                || old.task_action_binding() != new.task_action_binding()
                || old.expected_principal() != new.expected_principal()
                || old.display_text() != new.display_text()
                || old.active_state_manifest_digest() != new.active_state_manifest_digest()
                || old.deployment_generation() != new.deployment_generation()
            {
                return Err(KernelAgentAuthorityErrorV2::StateConflict);
            }
            let p = &mut self.pending_releases[index];
            p.envelope_digest = r
                .envelope
                .envelope_digest()
                .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
            p.envelope = r.envelope;
            p.display_authentication = r.display;
            p.challenge = old.decision_challenge();
            p.expires_at = old.expires_at();
            return Ok(());
        }
        if self.fused_release_recovery.len() >= self.maximum_records {
            return Err(KernelAgentAuthorityErrorV2::LimitExceeded);
        }
        let r = FusedReleaseRecoveryV04 {
            candidate,
            envelope: p.envelope.clone(),
            display: p.display_authentication.clone(),
            settlement: None,
            dispatch: None,
            completion: None,
            commit: None,
        };
        self.validate_fused_release_archive_v04(&r)?;
        self.fused_release_recovery.push(r);
        self.persist_fused_release_archive_v04()
    }

    pub(super) fn retain_fused_release_settlement_v04(
        &mut self,
        index: usize,
        receipt: &SignedApprovalSettlementV2,
    ) -> Result<(), KernelAgentAuthorityErrorV2> {
        let p = &self.pending_releases[index];
        let Some(candidate) = p.private_candidate else {
            return Ok(());
        };
        let r = self
            .fused_release_recovery
            .iter_mut()
            .find(|r| r.candidate == candidate)
            .ok_or(KernelAgentAuthorityErrorV2::StateConflict)?;
        if let Some(old) = &r.settlement {
            return if old == receipt {
                Ok(())
            } else {
                Err(KernelAgentAuthorityErrorV2::AlreadyConsumed)
            };
        }
        r.settlement = Some(receipt.clone());
        self.persist_fused_release_archive_v04()
    }

    pub(super) fn retain_fused_release_dispatch_v04(
        &mut self,
        candidate: Digest32V2,
        core: ProtocolDispatchCoreV2,
    ) -> Result<(), KernelAgentAuthorityErrorV2> {
        let r = self
            .fused_release_recovery
            .iter_mut()
            .find(|r| r.candidate == candidate)
            .ok_or(KernelAgentAuthorityErrorV2::StateConflict)?;
        if let Some(old) = &r.dispatch {
            return if old == &core {
                Ok(())
            } else {
                Err(KernelAgentAuthorityErrorV2::StateConflict)
            };
        }
        r.dispatch = Some(core);
        self.persist_fused_release_archive_v04()
    }

    pub(super) fn persist_fused_release_archive_v04(
        &mut self,
    ) -> Result<(), KernelAgentAuthorityErrorV2> {
        self.persist_recovery_snapshot().map_err(|e| {
            self.durable_poisoned = true;
            e
        })
    }
}
