//! Private approval material in the encrypted, rollback-anchored agent owner.
//! No session, capability, ticket, challenge renewal or provider send is restored.
use super::*;
use savana_kernel_protocol::v2::{AuthorizeToolCallRequestV2, SignedApprovalSettlementV2};

#[derive(Clone)]
pub(super) struct FusedApprovalRecoveryV04 {
    action: ActionIntentIdV2,
    envelope: SignedApprovalEnvelopeV2,
    display: SignedUiAuthenticationEnvelopeV2,
    settlement: Option<SignedApprovalSettlementV2>,
}

impl KernelAgentAuthorityV2 {
    pub(super) fn encode_fused_approval_recovery_v04(
        &self,
        encoder: &mut minicbor::Encoder<Vec<u8>>,
    ) -> Result<(), KernelAgentAuthorityErrorV2> {
        encoder
            .array(self.fused_approval_recovery.len() as u64)
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        for record in &self.fused_approval_recovery {
            encoder
                .array(4)
                .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
            encode_recovery_value(encoder, &record.action)?;
            encode_recovery_value(encoder, &record.envelope)?;
            encode_recovery_value(encoder, &record.display)?;
            encode_optional_recovery_value(encoder, record.settlement.as_ref())?;
        }
        Ok(())
    }

    pub(super) fn decode_fused_approval_recovery_v04(
        &mut self,
        decoder: &mut minicbor::Decoder<'_>,
        context: &mut V2DecodeContext,
    ) -> Result<(), KernelAgentAuthorityErrorV2> {
        let count = decode_recovery_count(decoder, self.maximum_records)?;
        self.fused_approval_recovery
            .try_reserve_exact(count)
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        for _ in 0..count {
            require_recovery_array(decoder, 4)?;
            let record = FusedApprovalRecoveryV04 {
                action: decode_recovery_value(decoder, context)?,
                envelope: decode_recovery_value(decoder, context)?,
                display: decode_recovery_value(decoder, context)?,
                settlement: decode_optional_recovery_value(decoder, context)?,
            };
            self.validate_fused_approval_archive_v04(&record)?;
            if self
                .fused_approval_recovery
                .iter()
                .any(|r| r.action == record.action)
            {
                return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
            }
            self.fused_approval_recovery.push(record);
        }
        Ok(())
    }

    fn validate_fused_approval_archive_v04(
        &self,
        record: &FusedApprovalRecoveryV04,
    ) -> Result<UnsignedApprovalEnvelopeV2, KernelAgentAuthorityErrorV2> {
        let fail = |_| KernelAgentAuthorityErrorV2::BindingMismatch;
        let raw = record.envelope.unverified_material().map_err(fail)?;
        let key = self.config.envelope_signing_key.verifying_key().to_bytes();
        // Historical integrity only. Live time, root, plan and G5 are checked
        // again before rebinding this material to new boot-local handles.
        let material = record
            .envelope
            .verify(
                derive_ed25519_key_id_v2(key),
                key,
                self.config.installation_id,
                raw.active_state_manifest_digest(),
                raw.deployment_generation(),
                ApprovalPurposeV2::ToolExecution,
                raw.expected_principal(),
                raw.issued_at(),
            )
            .map_err(fail)?;
        let display = record
            .display
            .verify_deployment(
                derive_ed25519_key_id_v2(key),
                key,
                self.config.installation_id,
                material.active_state_manifest_digest(),
                material.deployment_generation(),
            )
            .map_err(fail)?;
        let task = material
            .task_action_binding()
            .ok_or(KernelAgentAuthorityErrorV2::BindingMismatch)?;
        if !matches!(material.binding(), ApprovalBindingV2::ToolExecution { action_intent_id, .. } if action_intent_id == record.action)
            || material.approvald_endpoint_identity() != self.config.approvald_identity
            || material
                .display_declassification_provenance_digest()
                .is_none()
            || material.display_digest()
                != approval_display_digest_v2(material.display_text().as_bytes())
            || display.purpose() != UiAuthenticationPurposeV2::ApprovalDisplay
            || display.expected_principal() != Some(material.expected_principal())
            || display.authentication_origin() != FixedOriginV2::Approval8766
            || display.return_origin() != FixedOriginV2::Approval8766
            || display.issued_at() != material.issued_at()
            || display.expires_at() != material.expires_at()
            || display.binding()
                != (UiAuthenticationBindingV2::ApprovalDisplay {
                    durable_task_id: task.task(),
                    approval_envelope_digest: record.envelope.envelope_digest().map_err(fail)?,
                    approval_purpose: ApprovalPurposeV2::ToolExecution,
                    display_digest: material.display_digest(),
                })
        {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        Ok(material)
    }

    pub(super) fn retain_fused_approval_v04(
        &mut self,
        action: ActionIntentIdV2,
        envelope: SignedApprovalEnvelopeV2,
        display: SignedUiAuthenticationEnvelopeV2,
    ) -> Result<(), KernelAgentAuthorityErrorV2> {
        if self.fused_approval_recovery.len() >= self.maximum_records {
            return Err(KernelAgentAuthorityErrorV2::LimitExceeded);
        }
        if self
            .fused_approval_recovery
            .iter()
            .any(|r| r.action == action)
        {
            return Err(KernelAgentAuthorityErrorV2::StateConflict);
        }
        let record = FusedApprovalRecoveryV04 {
            action,
            envelope,
            display,
            settlement: None,
        };
        self.validate_fused_approval_archive_v04(&record)?;
        self.fused_approval_recovery
            .try_reserve(1)
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        self.fused_approval_recovery.push(record);
        self.commit_fused_approval_archive_v04()
    }

    pub(super) fn retain_fused_settlement_v04(
        &mut self,
        intent_index: usize,
        receipt: &SignedApprovalSettlementV2,
    ) -> Result<(), KernelAgentAuthorityErrorV2> {
        if self.intents[intent_index].fused.is_none() {
            return Ok(());
        }
        let action = self.intents[intent_index].action_intent_id;
        let record = self
            .fused_approval_recovery
            .iter_mut()
            .find(|r| r.action == action)
            .ok_or(KernelAgentAuthorityErrorV2::StateConflict)?;
        if let Some(existing) = &record.settlement {
            if existing != receipt {
                return Err(KernelAgentAuthorityErrorV2::AlreadyConsumed);
            }
            return Ok(());
        }
        record.settlement = Some(receipt.clone());
        self.commit_fused_approval_archive_v04()
    }

    fn commit_fused_approval_archive_v04(&mut self) -> Result<(), KernelAgentAuthorityErrorV2> {
        if let Err(error) = self.persist_recovery_snapshot() {
            // Includes encoding failure after a private in-memory mutation.
            self.durable_poisoned = true;
            return Err(error);
        }
        Ok(())
    }

    /// Called only after current session/root/plan, G4/G5 and display disclosure
    /// checks. Saved receipts go through the ordinary exact G6 verifier again.
    pub(super) fn rebind_fused_approval_v04(
        &mut self,
        index: usize,
        manifest: Digest32V2,
        generation: u64,
        now: UnixMillisV2,
        trace: ProtocolDecisionTraceV2,
    ) -> Result<Option<EvaluateToolCallResponseV2>, KernelAgentAuthorityErrorV2> {
        let intent = self.intents[index].clone();
        let Some(fused) = &intent.fused else {
            return Ok(None);
        };
        let Some(record) = self
            .fused_approval_recovery
            .iter()
            .find(|r| r.action == intent.action_intent_id)
            .cloned()
        else {
            return Ok(None);
        };
        let material = self.validate_fused_approval_archive_v04(&record)?;
        let expected_task = savana_kernel_protocol::v2::TaskActionApprovalBindingV2::new(
            intent.task_match.content_digest(),
            intent.task_match.content().authorization_id(),
            intent.task_match.content().authorization_revision(),
            intent.durable_task_id,
        )
        .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        if material.active_state_manifest_digest() != manifest
            || material.deployment_generation() != generation
            || material.approvald_endpoint_identity()
                != self
                    .policy
                    .as_ref()
                    .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?
                    .approval
                    .approvald_identity
            || material.expected_principal() != intent.principal
            || material.binding()
                != (ApprovalBindingV2::ToolExecution {
                    action_intent_id: intent.action_intent_id,
                    binding: intent.semantic_binding,
                })
            || material.task_action_binding() != Some(expected_task)
            || material.display_projection_digest()
                != intent.semantic_binding.display_projection_digest()
            || material.display_text().as_bytes() != intent.display_plaintext.as_slice()
            || material.expires_at().get() > fused.expires_at.get()
        {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        if now.get() < material.issued_at().get() || now.get() >= material.expires_at().get() {
            return Err(KernelAgentAuthorityErrorV2::Expired);
        }
        let approval = mint_handle(ToolKernelApprovalHandleV2::from_authority_entropy)?;
        let commitment = approval.authority_commitment(&self.handle_key);
        let binding_digest = savana_policy_core::v2::tool_approval_binding_digest_v2(
            intent.action_intent_id,
            savana_policy_core::v2::tool_execution_semantic_binding_digest_v2(
                &intent.policy_binding,
            )
            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?,
            manifest,
        )
        .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        self.tool_approvals
            .try_reserve(1)
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        self.tool_approvals.push(ToolApprovalRecordV2 {
            approval,
            commitment,
            pending_commitment: intent.pending_commitment,
            action_intent_id: intent.action_intent_id,
            envelope: record.envelope.clone(),
            display_authentication: record.display.clone(),
            envelope_digest: record
                .envelope
                .envelope_digest()
                .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?,
            binding_digest,
            challenge: material.decision_challenge(),
            expected_principal: intent.principal,
            active_state_manifest_digest: manifest,
            expires_at: material.expires_at(),
            consumed: false,
        });
        self.intents[index].approval_commitment = Some(commitment);
        self.intents[index].state = IntentRecordStateV2::AwaitingApproval;
        if let Some(receipt) = record.settlement {
            let request = AuthorizeToolCallRequestV2::new(intent.pending, approval, receipt)
                .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
            let authorized = match self.authorize_tool_call_inner(
                &request,
                manifest,
                generation,
                now,
                IntentAccessV2::PrivateFused,
            ) {
                Ok(authorized) => authorized,
                Err(error) => {
                    // An expired/invalid saved settlement is not a new pending
                    // ceremony. Never expose an invitation to replace it.
                    if self.intents[index].state == IntentRecordStateV2::AwaitingApproval {
                        self.intents[index].state = IntentRecordStateV2::Evaluating;
                        self.intents[index].approval_commitment = None;
                        self.tool_approvals.pop();
                    }
                    return Err(error);
                }
            };
            return Ok(Some(EvaluateToolCallResponseV2::Allowed {
                ticket: authorized.ticket(),
                trace,
            }));
        }
        Ok(Some(EvaluateToolCallResponseV2::NeedsApproval {
            approval,
            envelope: record.envelope,
            display_authentication: record.display,
            trace,
        }))
    }
}
