use ed25519_dalek::{Signature, VerifyingKey};
use minicbor::Encode as _;
use savana_kernel_protocol::v2::{
    ActionIntentIdV2, Digest32V2, DurableReleaseIdV2, DurableRunIdV2, DurableTaskIdV2,
    Ed25519KeyIdV2, ExecutorIdentityV2, FinalReleaseSemanticBindingV2, HpkeX25519KeyIdV2,
    Nonce32V2, UnixMillisV2,
};
use sha2::{Digest as _, Sha256};

use super::{
    ActionIntentRecordV2, AuthenticatedEffectDispositionV2, DispatchQuotaSubjectV2, G4Error,
    G5DecisionBranchV2, SharedVerifiedConnectorRegistryV2, ToolExecutionSemanticBindingV2,
};

const DISPATCH_SUBJECT_DOMAIN: &[u8] = b"SAVANA_DISPATCH_SUBJECT_V2\0";
const DISPATCH_CORE_DOMAIN: &[u8] = b"SAVANA_DISPATCH_CORE_V2\0";
const MAX_DISPATCH_ENTRIES: usize = 65_536;
const MAX_EXECUTOR_RECEIPT_BYTES: usize = 1024 * 1024;

#[derive(Debug)]
pub(crate) struct VerifiedExecutionTicketV2 {
    ticket_digest: Digest32V2,
    action_intent_id: ActionIntentIdV2,
    semantic_binding_digest: Digest32V2,
}

impl VerifiedExecutionTicketV2 {
    pub(crate) fn from_verified_ticket(
        ticket_digest: Digest32V2,
        action_intent_id: ActionIntentIdV2,
        semantic_binding_digest: Digest32V2,
    ) -> Result<Self, G4Error> {
        if is_zero(ticket_digest.as_bytes())
            || is_zero(action_intent_id.as_bytes())
            || is_zero(semantic_binding_digest.as_bytes())
        {
            return Err(G4Error::StateConflict);
        }
        Ok(Self {
            ticket_digest,
            action_intent_id,
            semantic_binding_digest,
        })
    }

    #[cfg(test)]
    pub(crate) fn new_for_test(record: &ActionIntentRecordV2, seed: u8) -> Self {
        Self::from_verified_ticket(
            Digest32V2::new([seed; 32]),
            record.action_intent_id,
            record.semantic_binding_digest,
        )
        .unwrap()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct VerifiedApprovalSettlementBindingV2 {
    settlement_digest: Digest32V2,
    action_intent_id: ActionIntentIdV2,
    approval_binding_digest: Digest32V2,
    active_state_manifest_digest: Digest32V2,
}

impl VerifiedApprovalSettlementBindingV2 {
    pub(crate) fn from_verified_settlement(
        settlement_digest: Digest32V2,
        action_intent_id: ActionIntentIdV2,
        approval_binding_digest: Digest32V2,
        active_state_manifest_digest: Digest32V2,
    ) -> Result<Self, G4Error> {
        if [
            settlement_digest,
            Digest32V2::new(*action_intent_id.as_bytes()),
            approval_binding_digest,
            active_state_manifest_digest,
        ]
        .iter()
        .any(|digest| is_zero(digest.as_bytes()))
        {
            return Err(G4Error::InvalidIntentBinding);
        }
        Ok(Self {
            settlement_digest,
            action_intent_id,
            approval_binding_digest,
            active_state_manifest_digest,
        })
    }

    #[cfg(test)]
    pub(crate) fn new_for_test(record: &ActionIntentRecordV2, seed: u8) -> Self {
        Self::from_verified_settlement(
            Digest32V2::new([seed; 32]),
            record.action_intent_id,
            super::intent::tool_approval_binding_digest_v2(
                record.action_intent_id,
                record.semantic_binding_digest,
                record.active_state_manifest_digest,
            )
            .unwrap(),
            record.active_state_manifest_digest,
        )
        .unwrap()
    }
}

#[derive(Debug, Clone)]
pub(crate) struct VerifiedEffectGateAuthorityV2 {
    installation_id: Digest32V2,
    active_state_manifest_digest: Digest32V2,
    deployment_generation: u64,
    effect_fence_epoch: u64,
    executor_identity: ExecutorIdentityV2,
    executor_key_id: HpkeX25519KeyIdV2,
    connector_registry: SharedVerifiedConnectorRegistryV2,
    executor_connector_registry_digest: Digest32V2,
    expires_at: UnixMillisV2,
}

impl VerifiedEffectGateAuthorityV2 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_authenticated_unfenced_ledger(
        installation_id: Digest32V2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        effect_fence_epoch: u64,
        effects_fenced: bool,
        executor_identity: ExecutorIdentityV2,
        executor_key_id: HpkeX25519KeyIdV2,
        connector_registry: &SharedVerifiedConnectorRegistryV2,
        expires_at: UnixMillisV2,
    ) -> Result<Self, G4Error> {
        let executor_connector_registry_digest = connector_registry.current_head_digest()?;
        if effects_fenced
            || deployment_generation == 0
            || effect_fence_epoch == 0
            || expires_at.get() == 0
            || is_zero(installation_id.as_bytes())
            || is_zero(active_state_manifest_digest.as_bytes())
            || is_zero(executor_identity.as_bytes())
            || is_zero(executor_key_id.as_bytes())
            || is_zero(executor_connector_registry_digest.as_bytes())
        {
            return Err(G4Error::StateConflict);
        }
        Ok(Self {
            installation_id,
            active_state_manifest_digest,
            deployment_generation,
            effect_fence_epoch,
            executor_identity,
            executor_key_id,
            connector_registry: connector_registry.clone(),
            executor_connector_registry_digest,
            expires_at,
        })
    }

    pub(super) fn while_current_connector_registry_head<T>(
        &self,
        operation: impl FnOnce(Digest32V2) -> Result<T, G4Error>,
    ) -> Result<T, G4Error> {
        self.connector_registry
            .while_current_head(self.executor_connector_registry_digest, operation)
    }
}

fn final_release_binding_digest(
    binding: &FinalReleaseSemanticBindingV2,
) -> Result<Digest32V2, G4Error> {
    binding
        .semantic_digest()
        .ok_or(G4Error::BindingDigestFailure)
}

#[cfg(test)]
pub(crate) fn final_release_binding_for_test(
    seed: u8,
    executor_identity: [u8; 32],
) -> FinalReleaseSemanticBindingV2 {
    FinalReleaseSemanticBindingV2::from_nonzero_components(
        DurableReleaseIdV2::new([6; 32]),
        Digest32V2::new([seed; 32]),
        Digest32V2::new([seed.wrapping_add(1); 32]),
        Digest32V2::new([seed.wrapping_add(2); 32]),
        Digest32V2::new([seed.wrapping_add(3); 32]),
        Digest32V2::new([seed.wrapping_add(4); 32]),
        Digest32V2::new([seed.wrapping_add(5); 32]),
        Digest32V2::new([seed.wrapping_add(6); 32]),
        Digest32V2::new([seed.wrapping_add(7); 32]),
        Digest32V2::new(executor_identity),
        Digest32V2::new([seed.wrapping_add(8); 32]),
    )
    .unwrap()
}

#[derive(Debug, Clone)]
pub(crate) struct VerifiedFinalReleaseDispatchV2 {
    installation_id: Digest32V2,
    active_state_manifest_digest: Digest32V2,
    durable_task_id: DurableTaskIdV2,
    durable_run_id: DurableRunIdV2,
    durable_release_id: DurableReleaseIdV2,
    binding: FinalReleaseSemanticBindingV2,
    binding_digest: Digest32V2,
}

impl VerifiedFinalReleaseDispatchV2 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_verified_release(
        installation_id: Digest32V2,
        active_state_manifest_digest: Digest32V2,
        durable_task_id: DurableTaskIdV2,
        durable_run_id: DurableRunIdV2,
        durable_release_id: DurableReleaseIdV2,
        binding: FinalReleaseSemanticBindingV2,
    ) -> Result<Self, G4Error> {
        if is_zero(installation_id.as_bytes())
            || is_zero(active_state_manifest_digest.as_bytes())
            || is_zero(durable_task_id.as_bytes())
            || is_zero(durable_run_id.as_bytes())
            || is_zero(durable_release_id.as_bytes())
            || durable_release_id != binding.durable_release_id()
        {
            return Err(G4Error::InvalidIntentBinding);
        }
        Ok(Self {
            installation_id,
            active_state_manifest_digest,
            durable_task_id,
            durable_run_id,
            durable_release_id,
            binding,
            binding_digest: final_release_binding_digest(&binding)?,
        })
    }

    pub(crate) const fn durable_run_id(&self) -> DurableRunIdV2 {
        self.durable_run_id
    }

    pub(super) const fn binding(&self) -> FinalReleaseSemanticBindingV2 {
        self.binding
    }

    #[cfg(test)]
    pub(crate) fn new_for_test(
        installation_id: Digest32V2,
        active_state_manifest_digest: Digest32V2,
        binding: FinalReleaseSemanticBindingV2,
    ) -> Self {
        Self::from_verified_release(
            installation_id,
            active_state_manifest_digest,
            DurableTaskIdV2::new([4; 32]),
            DurableRunIdV2::new([5; 32]),
            DurableReleaseIdV2::new([6; 32]),
            binding,
        )
        .unwrap()
    }
}

#[derive(Debug)]
pub(crate) struct VerifiedFinalReleaseTicketV2 {
    ticket_digest: Digest32V2,
    durable_release_id: DurableReleaseIdV2,
    binding_digest: Digest32V2,
}

impl VerifiedFinalReleaseTicketV2 {
    pub(crate) fn from_verified_ticket(
        ticket_digest: Digest32V2,
        durable_release_id: DurableReleaseIdV2,
        binding_digest: Digest32V2,
    ) -> Result<Self, G4Error> {
        if is_zero(ticket_digest.as_bytes())
            || is_zero(durable_release_id.as_bytes())
            || is_zero(binding_digest.as_bytes())
        {
            return Err(G4Error::StateConflict);
        }
        Ok(Self {
            ticket_digest,
            durable_release_id,
            binding_digest,
        })
    }

    #[cfg(test)]
    pub(crate) fn new_for_test(record: &VerifiedFinalReleaseDispatchV2, seed: u8) -> Self {
        Self::from_verified_ticket(
            Digest32V2::new([seed; 32]),
            record.durable_release_id,
            record.binding_digest,
        )
        .unwrap()
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct VerifiedFinalReleaseApprovalBindingV2 {
    settlement_digest: Digest32V2,
    durable_release_id: DurableReleaseIdV2,
    binding_digest: Digest32V2,
    active_state_manifest_digest: Digest32V2,
}

impl VerifiedFinalReleaseApprovalBindingV2 {
    pub(crate) fn from_verified_settlement(
        settlement_digest: Digest32V2,
        durable_release_id: DurableReleaseIdV2,
        binding_digest: Digest32V2,
        active_state_manifest_digest: Digest32V2,
    ) -> Result<Self, G4Error> {
        if is_zero(settlement_digest.as_bytes())
            || is_zero(durable_release_id.as_bytes())
            || is_zero(binding_digest.as_bytes())
            || is_zero(active_state_manifest_digest.as_bytes())
        {
            return Err(G4Error::StateConflict);
        }
        Ok(Self {
            settlement_digest,
            durable_release_id,
            binding_digest,
            active_state_manifest_digest,
        })
    }

    pub(crate) const fn active_state_manifest_digest(self) -> Digest32V2 {
        self.active_state_manifest_digest
    }

    #[cfg(test)]
    pub(crate) fn new_for_test(record: &VerifiedFinalReleaseDispatchV2, seed: u8) -> Self {
        Self::from_verified_settlement(
            Digest32V2::new([seed; 32]),
            record.durable_release_id,
            record.binding_digest,
            record.active_state_manifest_digest,
        )
        .unwrap()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchSubjectV2 {
    ToolExecution {
        action_intent_id: ActionIntentIdV2,
        binding: ToolExecutionSemanticBindingV2,
        approval_settlement_digest: Option<Digest32V2>,
    },
    FinalRelease {
        binding: FinalReleaseSemanticBindingV2,
        approval_settlement_digest: Digest32V2,
    },
}

impl DispatchSubjectV2 {
    pub const fn tool_action_intent_id(&self) -> Option<ActionIntentIdV2> {
        match self {
            Self::ToolExecution {
                action_intent_id, ..
            } => Some(*action_intent_id),
            Self::FinalRelease { .. } => None,
        }
    }

    pub const fn durable_release_id(&self) -> Option<DurableReleaseIdV2> {
        match self {
            Self::ToolExecution { .. } => None,
            Self::FinalRelease { binding, .. } => Some(binding.durable_release_id()),
        }
    }
}

impl<C> minicbor::Encode<C> for DispatchSubjectV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        match self {
            Self::ToolExecution {
                action_intent_id,
                binding,
                approval_settlement_digest,
            } => {
                encoder.array(4)?.u16(1)?;
                action_intent_id.encode(encoder, context)?;
                binding.encode(encoder, context)?;
                match approval_settlement_digest {
                    Some(digest) => digest.encode(encoder, context)?,
                    None => {
                        encoder.null()?;
                    }
                }
            }
            Self::FinalRelease {
                binding,
                approval_settlement_digest,
            } => {
                encoder.array(3)?.u16(2)?;
                binding.encode(encoder, context)?;
                approval_settlement_digest.encode(encoder, context)?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchCoreV2 {
    pub(crate) installation_id: Digest32V2,
    pub(crate) active_state_manifest_digest: Digest32V2,
    pub(crate) deployment_generation: u64,
    pub(crate) effect_fence_epoch: u64,
    pub(crate) durable_task_id: DurableTaskIdV2,
    pub(crate) durable_run_id: DurableRunIdV2,
    pub(crate) execution_nonce: Nonce32V2,
    pub(crate) subject: DispatchSubjectV2,
    pub(crate) dispatch_subject_digest: Digest32V2,
    pub(crate) executor_identity: ExecutorIdentityV2,
    pub(crate) executor_key_id: HpkeX25519KeyIdV2,
    pub(crate) executor_connector_registry_digest: Digest32V2,
    pub(crate) expires_at: UnixMillisV2,
    pub(crate) task_binding: Option<savana_kernel_protocol::v2::DispatchTaskBindingV2>,
}

impl DispatchCoreV2 {
    pub const fn task_binding(&self) -> Option<savana_kernel_protocol::v2::DispatchTaskBindingV2> {
        self.task_binding
    }
    pub const fn installation_id(&self) -> Digest32V2 {
        self.installation_id
    }

    pub const fn active_state_manifest_digest(&self) -> Digest32V2 {
        self.active_state_manifest_digest
    }

    pub const fn deployment_generation(&self) -> u64 {
        self.deployment_generation
    }

    pub const fn effect_fence_epoch(&self) -> u64 {
        self.effect_fence_epoch
    }

    pub const fn durable_task_id(&self) -> DurableTaskIdV2 {
        self.durable_task_id
    }

    pub const fn durable_run_id(&self) -> DurableRunIdV2 {
        self.durable_run_id
    }

    pub const fn execution_nonce(&self) -> Nonce32V2 {
        self.execution_nonce
    }

    pub const fn dispatch_subject_digest(&self) -> Digest32V2 {
        self.dispatch_subject_digest
    }

    pub const fn subject(&self) -> &DispatchSubjectV2 {
        &self.subject
    }

    pub const fn executor_identity(&self) -> ExecutorIdentityV2 {
        self.executor_identity
    }

    pub const fn executor_key_id(&self) -> HpkeX25519KeyIdV2 {
        self.executor_key_id
    }

    pub const fn executor_connector_registry_digest(&self) -> Digest32V2 {
        self.executor_connector_registry_digest
    }

    pub const fn expires_at(&self) -> UnixMillisV2 {
        self.expires_at
    }
}

impl<C> minicbor::Encode<C> for DispatchCoreV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder
            .array(if self.task_binding.is_some() { 15 } else { 14 })?
            .u16(if self.task_binding.is_some() { 3 } else { 2 })?;
        self.installation_id.encode(encoder, context)?;
        self.active_state_manifest_digest.encode(encoder, context)?;
        encoder
            .u64(self.deployment_generation)?
            .u64(self.effect_fence_epoch)?;
        self.durable_task_id.encode(encoder, context)?;
        self.durable_run_id.encode(encoder, context)?;
        self.execution_nonce.encode(encoder, context)?;
        self.subject.encode(encoder, context)?;
        self.dispatch_subject_digest.encode(encoder, context)?;
        self.executor_identity.encode(encoder, context)?;
        self.executor_key_id.encode(encoder, context)?;
        self.executor_connector_registry_digest
            .encode(encoder, context)?;
        self.expires_at.encode(encoder, context)?;
        if let Some(binding) = self.task_binding {
            binding.encode(encoder, context)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelDispatchStateV2 {
    Prepared,
    Dispatching,
    EffectStarted,
    CompletionCommitted,
    FailedNoEffect,
    Indeterminate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchRecoverySubjectKindV2 {
    ToolExecution,
    FinalRelease,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernelDispatchRecoveryProjectionV2 {
    durable_task_id: DurableTaskIdV2,
    durable_run_id: DurableRunIdV2,
    execution_nonce: Nonce32V2,
    dispatch_core_digest: Digest32V2,
    dispatch_subject_digest: Digest32V2,
    subject_kind: DispatchRecoverySubjectKindV2,
    durable_release_id: Option<DurableReleaseIdV2>,
    state: KernelDispatchStateV2,
}

impl KernelDispatchRecoveryProjectionV2 {
    pub const fn durable_task_id(self) -> DurableTaskIdV2 {
        self.durable_task_id
    }

    pub const fn durable_run_id(self) -> DurableRunIdV2 {
        self.durable_run_id
    }

    pub const fn execution_nonce(self) -> Nonce32V2 {
        self.execution_nonce
    }

    pub const fn dispatch_core_digest(self) -> Digest32V2 {
        self.dispatch_core_digest
    }

    pub const fn dispatch_subject_digest(self) -> Digest32V2 {
        self.dispatch_subject_digest
    }

    pub const fn subject_kind(self) -> DispatchRecoverySubjectKindV2 {
        self.subject_kind
    }

    pub const fn durable_release_id(self) -> Option<DurableReleaseIdV2> {
        self.durable_release_id
    }

    pub const fn state(self) -> KernelDispatchStateV2 {
        self.state
    }
}

#[derive(Debug, Clone)]
pub(crate) struct KernelDispatchJournalEntryV2 {
    pub(crate) core: DispatchCoreV2,
    pub(crate) core_digest: Digest32V2,
    pub(crate) quota_subject: DispatchQuotaSubjectV2,
    pub(crate) sealed_envelope_digest: Digest32V2,
    pub(crate) consumed_ticket_digest: Digest32V2,
    pub(crate) state: KernelDispatchStateV2,
    pub(crate) effect_evidence_digest: Option<Digest32V2>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct KernelDispatchJournalV2 {
    pub(crate) entries: Vec<KernelDispatchJournalEntryV2>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchPreparationKindV2 {
    Created,
    Replay,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DispatchPreparationV2 {
    kind: DispatchPreparationKindV2,
    execution_nonce: Nonce32V2,
    dispatch_core_digest: Digest32V2,
    dispatch_subject_digest: Digest32V2,
    state: KernelDispatchStateV2,
}

impl DispatchPreparationV2 {
    pub const fn kind(self) -> DispatchPreparationKindV2 {
        self.kind
    }

    pub const fn execution_nonce(self) -> Nonce32V2 {
        self.execution_nonce
    }

    pub const fn state(self) -> KernelDispatchStateV2 {
        self.state
    }

    pub const fn dispatch_core_digest(self) -> Digest32V2 {
        self.dispatch_core_digest
    }

    pub const fn dispatch_subject_digest(self) -> Digest32V2 {
        self.dispatch_subject_digest
    }
}

impl KernelDispatchJournalV2 {
    pub(crate) fn recovery_projection(
        &self,
    ) -> Result<Vec<KernelDispatchRecoveryProjectionV2>, G4Error> {
        let mut projection = Vec::new();
        projection
            .try_reserve(self.entries.len())
            .map_err(|_| G4Error::AllocationFailure)?;
        projection.extend(self.entries.iter().map(|entry| {
            let (subject_kind, durable_release_id) = match entry.core.subject {
                DispatchSubjectV2::ToolExecution { .. } => {
                    (DispatchRecoverySubjectKindV2::ToolExecution, None)
                }
                DispatchSubjectV2::FinalRelease { binding, .. } => (
                    DispatchRecoverySubjectKindV2::FinalRelease,
                    Some(binding.durable_release_id()),
                ),
            };
            KernelDispatchRecoveryProjectionV2 {
                durable_task_id: entry.core.durable_task_id,
                durable_run_id: entry.core.durable_run_id,
                execution_nonce: entry.core.execution_nonce,
                dispatch_core_digest: entry.core_digest,
                dispatch_subject_digest: entry.core.dispatch_subject_digest,
                subject_kind,
                durable_release_id,
                state: entry.state,
            }
        }));
        projection.sort_unstable_by(|left, right| {
            left.execution_nonce
                .as_bytes()
                .cmp(right.execution_nonce.as_bytes())
        });
        Ok(projection)
    }

    pub(crate) fn prepare_tool_or_replay(
        &mut self,
        record: &ActionIntentRecordV2,
        decision: G5DecisionBranchV2,
        approval: Option<VerifiedApprovalSettlementBindingV2>,
        ticket: VerifiedExecutionTicketV2,
        authority: VerifiedEffectGateAuthorityV2,
        sealed_envelope_digest: Digest32V2,
    ) -> Result<DispatchPreparationV2, G4Error> {
        let connector_registry = authority.connector_registry.clone();
        let expected_head = authority.executor_connector_registry_digest;
        connector_registry.while_current_head(expected_head, |current_head| {
            self.prepare_tool_or_replay_at_current_head(
                record,
                decision,
                approval,
                ticket,
                authority,
                sealed_envelope_digest,
                current_head,
            )
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn prepare_tool_or_replay_at_current_head(
        &mut self,
        record: &ActionIntentRecordV2,
        decision: G5DecisionBranchV2,
        approval: Option<VerifiedApprovalSettlementBindingV2>,
        ticket: VerifiedExecutionTicketV2,
        authority: VerifiedEffectGateAuthorityV2,
        sealed_envelope_digest: Digest32V2,
        connector_registry_digest: Digest32V2,
    ) -> Result<DispatchPreparationV2, G4Error> {
        if ticket.action_intent_id != record.action_intent_id
            || ticket.semantic_binding_digest != record.semantic_binding_digest
        {
            return Err(G4Error::StateConflict);
        }
        if let Some(existing) = self.entries.iter().find(|entry| {
            entry.core.subject.tool_action_intent_id() == Some(record.action_intent_id)
        }) {
            let replay_approval = match (decision, approval) {
                (G5DecisionBranchV2::Permit, None) => None,
                (G5DecisionBranchV2::RequireApproval, Some(a))
                    if a.action_intent_id == record.action_intent_id
                        && a.active_state_manifest_digest
                            == record.active_state_manifest_digest
                        && a.approval_binding_digest
                            == super::intent::tool_approval_binding_digest_v2(
                                record.action_intent_id,
                                record.semantic_binding_digest,
                                record.active_state_manifest_digest,
                            )? =>
                {
                    Some(a.settlement_digest)
                }
                _ => return Err(G4Error::StateConflict),
            };
            if !matches!(&existing.core.subject, DispatchSubjectV2::ToolExecution {binding,approval_settlement_digest,..}
                if binding == record.binding() && *approval_settlement_digest == replay_approval)
                || existing.core.durable_task_id != record.durable_task_id
                || existing.core.durable_run_id != record.durable_run_id
                || existing.consumed_ticket_digest != ticket.ticket_digest
                || existing.sealed_envelope_digest != sealed_envelope_digest
                || existing.core.installation_id != authority.installation_id
                || existing.core.active_state_manifest_digest
                    != authority.active_state_manifest_digest
                || existing.core.deployment_generation != authority.deployment_generation
                || existing.core.effect_fence_epoch != authority.effect_fence_epoch
                || existing.core.executor_identity != authority.executor_identity
                || existing.core.executor_key_id != authority.executor_key_id
                || existing.core.executor_connector_registry_digest != connector_registry_digest
            {
                return Err(G4Error::StateConflict);
            }
            return Ok(preparation(existing, DispatchPreparationKindV2::Replay));
        }
        if self.entries.len() >= MAX_DISPATCH_ENTRIES
            || record.installation_id != authority.installation_id
            || record.active_state_manifest_digest != authority.active_state_manifest_digest
            || is_zero(sealed_envelope_digest.as_bytes())
            || ticket.action_intent_id != record.action_intent_id
            || ticket.semantic_binding_digest != record.semantic_binding_digest
            || self
                .entries
                .iter()
                .any(|entry| entry.consumed_ticket_digest == ticket.ticket_digest)
            || Digest32V2::new(*authority.executor_identity.as_bytes())
                != record.material.binding.executor_identity_digest()
        {
            return Err(G4Error::StateConflict);
        }
        let approval_settlement_digest = match (decision, approval) {
            (G5DecisionBranchV2::Permit, None) => None,
            (G5DecisionBranchV2::RequireApproval, Some(approval))
                if approval.action_intent_id == record.action_intent_id
                    && approval.approval_binding_digest
                        == super::intent::tool_approval_binding_digest_v2(
                            record.action_intent_id,
                            record.semantic_binding_digest,
                            record.active_state_manifest_digest,
                        )?
                    && approval.active_state_manifest_digest
                        == record.active_state_manifest_digest =>
            {
                Some(approval.settlement_digest)
            }
            _ => return Err(G4Error::StateConflict),
        };
        let subject = DispatchSubjectV2::ToolExecution {
            action_intent_id: record.action_intent_id,
            binding: record.material.binding.clone(),
            approval_settlement_digest,
        };
        let dispatch_subject_digest = dispatch_subject_digest(&subject)?;
        let mut nonce = [0_u8; 32];
        getrandom::getrandom(&mut nonce).map_err(|_| G4Error::AllocationFailure)?;
        if nonce == [0; 32]
            || self
                .entries
                .iter()
                .any(|entry| entry.core.execution_nonce.as_bytes() == &nonce)
        {
            return Err(G4Error::AllocationFailure);
        }
        let core = DispatchCoreV2 {
            installation_id: authority.installation_id,
            active_state_manifest_digest: authority.active_state_manifest_digest,
            deployment_generation: authority.deployment_generation,
            effect_fence_epoch: authority.effect_fence_epoch,
            durable_task_id: record.durable_task_id,
            durable_run_id: record.durable_run_id,
            execution_nonce: Nonce32V2::new(nonce),
            subject,
            dispatch_subject_digest,
            executor_identity: authority.executor_identity,
            executor_key_id: authority.executor_key_id,
            executor_connector_registry_digest: connector_registry_digest,
            expires_at: authority.expires_at,
            task_binding: None,
        };
        let core_digest = dispatch_core_digest(&core)?;
        self.entries
            .try_reserve(1)
            .map_err(|_| G4Error::AllocationFailure)?;
        let entry = KernelDispatchJournalEntryV2 {
            core,
            core_digest,
            quota_subject: DispatchQuotaSubjectV2::tool_attempt(
                record.material.binding.attempt_kind(),
            ),
            sealed_envelope_digest,
            consumed_ticket_digest: ticket.ticket_digest,
            state: KernelDispatchStateV2::Prepared,
            effect_evidence_digest: None,
        };
        let result = preparation(&entry, DispatchPreparationKindV2::Created);
        self.entries.push(entry);
        Ok(result)
    }

    pub(crate) fn prepare_final_release_or_replay(
        &mut self,
        record: &VerifiedFinalReleaseDispatchV2,
        approval: VerifiedFinalReleaseApprovalBindingV2,
        ticket: VerifiedFinalReleaseTicketV2,
        authority: VerifiedEffectGateAuthorityV2,
        sealed_envelope_digest: Digest32V2,
    ) -> Result<DispatchPreparationV2, G4Error> {
        let connector_registry = authority.connector_registry.clone();
        let expected_head = authority.executor_connector_registry_digest;
        connector_registry.while_current_head(expected_head, |current_head| {
            self.prepare_final_release_or_replay_at_current_head(
                record,
                approval,
                ticket,
                authority,
                sealed_envelope_digest,
                current_head,
            )
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn prepare_final_release_or_replay_at_current_head(
        &mut self,
        record: &VerifiedFinalReleaseDispatchV2,
        approval: VerifiedFinalReleaseApprovalBindingV2,
        ticket: VerifiedFinalReleaseTicketV2,
        authority: VerifiedEffectGateAuthorityV2,
        sealed_envelope_digest: Digest32V2,
        connector_registry_digest: Digest32V2,
    ) -> Result<DispatchPreparationV2, G4Error> {
        if ticket.durable_release_id != record.durable_release_id
            || ticket.binding_digest != record.binding_digest
            || approval.durable_release_id != record.durable_release_id
            || approval.binding_digest != record.binding_digest
            || approval.active_state_manifest_digest != record.active_state_manifest_digest
        {
            return Err(G4Error::StateConflict);
        }
        if let Some(existing) = self.entries.iter().find(|entry| {
            entry.core.subject.durable_release_id() == Some(record.durable_release_id)
        }) {
            if !matches!(
                existing.core.subject,
                DispatchSubjectV2::FinalRelease {
                    binding,
                    approval_settlement_digest,
                } if binding == record.binding
                    && approval_settlement_digest == approval.settlement_digest
            ) || existing.core.durable_task_id != record.durable_task_id
                || existing.core.durable_run_id != record.durable_run_id
                || existing.consumed_ticket_digest != ticket.ticket_digest
                || existing.sealed_envelope_digest != sealed_envelope_digest
                || existing.core.installation_id != authority.installation_id
                || existing.core.active_state_manifest_digest
                    != authority.active_state_manifest_digest
                || existing.core.deployment_generation != authority.deployment_generation
                || existing.core.effect_fence_epoch != authority.effect_fence_epoch
                || existing.core.executor_identity != authority.executor_identity
                || existing.core.executor_key_id != authority.executor_key_id
                || existing.core.executor_connector_registry_digest != connector_registry_digest
            {
                return Err(G4Error::StateConflict);
            }
            return Ok(preparation(existing, DispatchPreparationKindV2::Replay));
        }
        if self.entries.len() >= MAX_DISPATCH_ENTRIES
            || record.installation_id != authority.installation_id
            || record.active_state_manifest_digest != authority.active_state_manifest_digest
            || record.binding.executor_identity_digest()
                != Digest32V2::new(*authority.executor_identity.as_bytes())
            || is_zero(sealed_envelope_digest.as_bytes())
            || ticket.durable_release_id != record.durable_release_id
            || ticket.binding_digest != record.binding_digest
            || approval.durable_release_id != record.durable_release_id
            || approval.binding_digest != record.binding_digest
            || approval.active_state_manifest_digest != record.active_state_manifest_digest
            || self
                .entries
                .iter()
                .any(|entry| entry.consumed_ticket_digest == ticket.ticket_digest)
            || self.entries.iter().any(|entry| {
                matches!(
                    entry.core.subject,
                    DispatchSubjectV2::FinalRelease {
                        approval_settlement_digest,
                        ..
                    } if approval_settlement_digest == approval.settlement_digest
                )
            })
        {
            return Err(G4Error::StateConflict);
        }
        let subject = DispatchSubjectV2::FinalRelease {
            binding: record.binding,
            approval_settlement_digest: approval.settlement_digest,
        };
        let dispatch_subject_digest = dispatch_subject_digest(&subject)?;
        let mut nonce = [0_u8; 32];
        getrandom::getrandom(&mut nonce).map_err(|_| G4Error::AllocationFailure)?;
        if nonce == [0; 32]
            || self
                .entries
                .iter()
                .any(|entry| entry.core.execution_nonce.as_bytes() == &nonce)
        {
            return Err(G4Error::AllocationFailure);
        }
        let core = DispatchCoreV2 {
            installation_id: authority.installation_id,
            active_state_manifest_digest: authority.active_state_manifest_digest,
            deployment_generation: authority.deployment_generation,
            effect_fence_epoch: authority.effect_fence_epoch,
            durable_task_id: record.durable_task_id,
            durable_run_id: record.durable_run_id,
            execution_nonce: Nonce32V2::new(nonce),
            subject,
            dispatch_subject_digest,
            executor_identity: authority.executor_identity,
            executor_key_id: authority.executor_key_id,
            executor_connector_registry_digest: connector_registry_digest,
            expires_at: authority.expires_at,
            task_binding: None,
        };
        let core_digest = dispatch_core_digest(&core)?;
        let quota_subject =
            DispatchQuotaSubjectV2::final_release(record.binding.release_quota_subject_digest());
        self.entries
            .try_reserve(1)
            .map_err(|_| G4Error::AllocationFailure)?;
        let entry = KernelDispatchJournalEntryV2 {
            core,
            core_digest,
            quota_subject,
            sealed_envelope_digest,
            consumed_ticket_digest: ticket.ticket_digest,
            state: KernelDispatchStateV2::Prepared,
            effect_evidence_digest: None,
        };
        let result = preparation(&entry, DispatchPreparationKindV2::Created);
        self.entries.push(entry);
        Ok(result)
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct VerifiedExecutorDispositionV2 {
    pub(crate) execution_nonce: Nonce32V2,
    pub(crate) dispatch_core_digest: Digest32V2,
    pub(crate) dispatch_subject_digest: Digest32V2,
    pub(crate) evidence_digest: Digest32V2,
    pub(crate) disposition: AuthenticatedEffectDispositionV2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExecutorDispositionKindV2 {
    EffectStarted,
    KnownSuccess,
    FailedNoEffect,
    Indeterminate,
}

impl ExecutorDispositionKindV2 {
    const fn tag(self) -> u16 {
        match self {
            Self::EffectStarted => 1,
            Self::KnownSuccess => 2,
            Self::FailedNoEffect => 3,
            Self::Indeterminate => 4,
        }
    }

    const fn signature_domain(self) -> &'static [u8] {
        match self {
            Self::EffectStarted => b"SAVANA_EXECD_EFFECT_STARTED_RECEIPT_V2\0",
            Self::KnownSuccess => b"SAVANA_EXECD_KNOWN_SUCCESS_RECEIPT_V2\0",
            Self::FailedNoEffect => b"SAVANA_EXECD_FAILED_NO_EFFECT_RECEIPT_V2\0",
            Self::Indeterminate => b"SAVANA_EXECD_INDETERMINATE_RECEIPT_V2\0",
        }
    }

    const fn disposition(self) -> AuthenticatedEffectDispositionV2 {
        match self {
            Self::EffectStarted => {
                AuthenticatedEffectDispositionV2::from_verified_effect_started_receipt()
            }
            Self::KnownSuccess => AuthenticatedEffectDispositionV2::from_verified_known_success(),
            Self::FailedNoEffect => {
                AuthenticatedEffectDispositionV2::from_verified_failed_no_effect()
            }
            Self::Indeterminate => AuthenticatedEffectDispositionV2::from_verified_indeterminate(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SignedExecutorDispositionReceiptV2 {
    canonical_payload: Vec<u8>,
    key_id: Ed25519KeyIdV2,
    signature: [u8; 64],
}

impl SignedExecutorDispositionReceiptV2 {
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, G4Error> {
        if bytes.is_empty() || bytes.len() > MAX_EXECUTOR_RECEIPT_BYTES {
            return Err(G4Error::StateConflict);
        }
        let mut decoder = minicbor::Decoder::new(bytes);
        require_array(&mut decoder, 3)?;
        let canonical_payload = decoder
            .bytes()
            .map_err(|_| G4Error::StateConflict)?
            .to_vec();
        let key_id = Ed25519KeyIdV2::new(decode_fixed::<32>(&mut decoder)?);
        let signature = decode_fixed::<64>(&mut decoder)?;
        if decoder.position() != bytes.len() {
            return Err(G4Error::StateConflict);
        }
        let receipt = Self {
            canonical_payload,
            key_id,
            signature,
        };
        if encode_signed_receipt(&receipt)? != bytes {
            return Err(G4Error::StateConflict);
        }
        decode_receipt_payload(&receipt.canonical_payload)?;
        Ok(receipt)
    }

    pub(crate) fn verify_for_entry(
        &self,
        entry: &KernelDispatchJournalEntryV2,
        expected_key_id: Ed25519KeyIdV2,
        public_key: [u8; 32],
        now: UnixMillisV2,
    ) -> Result<VerifiedExecutorDispositionV2, G4Error> {
        if self.key_id != expected_key_id || now.get() >= entry.core.expires_at.get() {
            return Err(G4Error::StateConflict);
        }
        let payload = decode_receipt_payload(&self.canonical_payload)?;
        if payload.installation_id != entry.core.installation_id
            || payload.active_state_manifest_digest != entry.core.active_state_manifest_digest
            || payload.deployment_generation != entry.core.deployment_generation
            || payload.effect_fence_epoch != entry.core.effect_fence_epoch
            || payload.execution_nonce != entry.core.execution_nonce
            || payload.dispatch_core_digest != entry.core_digest
            || payload.dispatch_subject_digest != entry.core.dispatch_subject_digest
            || payload.issued_at.get() > now.get()
            || is_zero(payload.evidence_digest.as_bytes())
        {
            return Err(G4Error::StateConflict);
        }
        let digest = domain_hash(payload.kind.signature_domain(), &self.canonical_payload);
        let mut signature_input = Vec::from(payload.kind.signature_domain());
        signature_input.extend_from_slice(digest.as_bytes());
        VerifyingKey::from_bytes(&public_key)
            .map_err(|_| G4Error::StateConflict)?
            .verify_strict(&signature_input, &Signature::from_bytes(&self.signature))
            .map_err(|_| G4Error::StateConflict)?;
        Ok(VerifiedExecutorDispositionV2 {
            execution_nonce: payload.execution_nonce,
            dispatch_core_digest: payload.dispatch_core_digest,
            dispatch_subject_digest: payload.dispatch_subject_digest,
            evidence_digest: payload.evidence_digest,
            disposition: payload.kind.disposition(),
        })
    }

    /// Reconcile a historical terminal fact, never grant another execution.
    /// A dispatch deadline limits starting effects, not receipt delivery.
    pub(crate) fn verify_terminal_for_entry(
        &self,
        entry: &KernelDispatchJournalEntryV2,
        expected_key_id: Ed25519KeyIdV2,
        public_key: [u8; 32],
        now: UnixMillisV2,
    ) -> Result<VerifiedExecutorDispositionV2, G4Error> {
        let payload = decode_receipt_payload(&self.canonical_payload)?;
        if payload.issued_at.get() > now.get()
            || !matches!(
                payload.kind,
                ExecutorDispositionKindV2::KnownSuccess | ExecutorDispositionKindV2::FailedNoEffect
            )
        {
            return Err(G4Error::StateConflict);
        }
        self.verify_stored_for_entry(entry, expected_key_id, public_key)
    }

    pub(crate) fn verify_stored_for_entry(
        &self,
        entry: &KernelDispatchJournalEntryV2,
        expected_key_id: Ed25519KeyIdV2,
        public_key: [u8; 32],
    ) -> Result<VerifiedExecutorDispositionV2, G4Error> {
        if self.key_id != expected_key_id {
            return Err(G4Error::StateConflict);
        }
        let payload = decode_receipt_payload(&self.canonical_payload)?;
        if payload.installation_id != entry.core.installation_id
            || payload.active_state_manifest_digest != entry.core.active_state_manifest_digest
            || payload.deployment_generation != entry.core.deployment_generation
            || payload.effect_fence_epoch != entry.core.effect_fence_epoch
            || payload.execution_nonce != entry.core.execution_nonce
            || payload.dispatch_core_digest != entry.core_digest
            || payload.dispatch_subject_digest != entry.core.dispatch_subject_digest
            || payload.issued_at.get() == 0
            || is_zero(payload.evidence_digest.as_bytes())
        {
            return Err(G4Error::StateConflict);
        }
        let digest = domain_hash(payload.kind.signature_domain(), &self.canonical_payload);
        let mut signature_input = Vec::from(payload.kind.signature_domain());
        signature_input.extend_from_slice(digest.as_bytes());
        VerifyingKey::from_bytes(&public_key)
            .map_err(|_| G4Error::StateConflict)?
            .verify_strict(&signature_input, &Signature::from_bytes(&self.signature))
            .map_err(|_| G4Error::StateConflict)?;
        Ok(VerifiedExecutorDispositionV2 {
            execution_nonce: payload.execution_nonce,
            dispatch_core_digest: payload.dispatch_core_digest,
            dispatch_subject_digest: payload.dispatch_subject_digest,
            evidence_digest: payload.evidence_digest,
            disposition: payload.kind.disposition(),
        })
    }

    #[cfg(test)]
    pub(crate) fn effect_started_for_test(
        entry: &KernelDispatchJournalEntryV2,
        key_id: Ed25519KeyIdV2,
        signing_key: &ed25519_dalek::SigningKey,
        evidence_seed: u8,
        issued_at: UnixMillisV2,
    ) -> Self {
        use ed25519_dalek::Signer as _;

        let payload = ExecutorDispositionReceiptPayloadV2 {
            kind: ExecutorDispositionKindV2::EffectStarted,
            installation_id: entry.core.installation_id,
            active_state_manifest_digest: entry.core.active_state_manifest_digest,
            deployment_generation: entry.core.deployment_generation,
            effect_fence_epoch: entry.core.effect_fence_epoch,
            execution_nonce: entry.core.execution_nonce,
            dispatch_core_digest: entry.core_digest,
            dispatch_subject_digest: entry.core.dispatch_subject_digest,
            evidence_digest: Digest32V2::new([evidence_seed; 32]),
            issued_at,
        };
        let canonical_payload = encode_receipt_payload(payload).unwrap();
        let digest = domain_hash(payload.kind.signature_domain(), &canonical_payload);
        let mut signature_input = Vec::from(payload.kind.signature_domain());
        signature_input.extend_from_slice(digest.as_bytes());
        let receipt = Self {
            canonical_payload,
            key_id,
            signature: signing_key.sign(&signature_input).to_bytes(),
        };
        Self::from_canonical_bytes(&encode_signed_receipt(&receipt).unwrap()).unwrap()
    }
}

#[derive(Debug, Clone, Copy)]
struct ExecutorDispositionReceiptPayloadV2 {
    kind: ExecutorDispositionKindV2,
    installation_id: Digest32V2,
    active_state_manifest_digest: Digest32V2,
    deployment_generation: u64,
    effect_fence_epoch: u64,
    execution_nonce: Nonce32V2,
    dispatch_core_digest: Digest32V2,
    dispatch_subject_digest: Digest32V2,
    evidence_digest: Digest32V2,
    issued_at: UnixMillisV2,
}

impl VerifiedExecutorDispositionV2 {
    #[cfg(test)]
    pub(crate) fn effect_started_for_test(entry: &KernelDispatchJournalEntryV2, seed: u8) -> Self {
        Self {
            execution_nonce: entry.core.execution_nonce,
            dispatch_core_digest: entry.core_digest,
            dispatch_subject_digest: entry.core.dispatch_subject_digest,
            evidence_digest: Digest32V2::new([seed; 32]),
            disposition: AuthenticatedEffectDispositionV2::effect_started_for_test(),
        }
    }

    #[cfg(test)]
    pub(crate) fn effect_started_from_preparation_for_test(
        preparation: DispatchPreparationV2,
        seed: u8,
    ) -> Self {
        Self {
            execution_nonce: preparation.execution_nonce,
            dispatch_core_digest: preparation.dispatch_core_digest,
            dispatch_subject_digest: preparation.dispatch_subject_digest,
            evidence_digest: Digest32V2::new([seed; 32]),
            disposition: AuthenticatedEffectDispositionV2::effect_started_for_test(),
        }
    }
}

impl KernelDispatchJournalV2 {
    pub(crate) fn reconcile(
        &mut self,
        proof: VerifiedExecutorDispositionV2,
    ) -> Result<KernelDispatchStateV2, G4Error> {
        let entry = self
            .entries
            .iter_mut()
            .find(|entry| entry.core.execution_nonce == proof.execution_nonce)
            .ok_or(G4Error::StateConflict)?;
        if entry.core_digest != proof.dispatch_core_digest
            || entry.core.dispatch_subject_digest != proof.dispatch_subject_digest
            || is_zero(proof.evidence_digest.as_bytes())
        {
            return Err(G4Error::StateConflict);
        }
        entry.state = match proof.disposition.kind() {
            super::quota::AuthenticatedEffectDispositionKindV2::EffectStarted => {
                KernelDispatchStateV2::EffectStarted
            }
            super::quota::AuthenticatedEffectDispositionKindV2::KnownSuccess => {
                KernelDispatchStateV2::CompletionCommitted
            }
            super::quota::AuthenticatedEffectDispositionKindV2::FailedNoEffect => {
                KernelDispatchStateV2::FailedNoEffect
            }
            super::quota::AuthenticatedEffectDispositionKindV2::Indeterminate => {
                KernelDispatchStateV2::Indeterminate
            }
        };
        entry.effect_evidence_digest = Some(proof.evidence_digest);
        Ok(entry.state)
    }
}

pub(crate) fn dispatch_subject_digest(subject: &DispatchSubjectV2) -> Result<Digest32V2, G4Error> {
    let canonical = minicbor::to_vec(subject).map_err(|_| G4Error::BindingDigestFailure)?;
    Ok(domain_hash(DISPATCH_SUBJECT_DOMAIN, &canonical))
}

pub(crate) fn dispatch_core_digest(core: &DispatchCoreV2) -> Result<Digest32V2, G4Error> {
    let canonical = minicbor::to_vec(core).map_err(|_| G4Error::BindingDigestFailure)?;
    Ok(domain_hash(DISPATCH_CORE_DOMAIN, &canonical))
}

fn decode_receipt_payload(bytes: &[u8]) -> Result<ExecutorDispositionReceiptPayloadV2, G4Error> {
    let mut decoder = minicbor::Decoder::new(bytes);
    require_array(&mut decoder, 11)?;
    if decoder.u16().map_err(|_| G4Error::StateConflict)? != 2 {
        return Err(G4Error::StateConflict);
    }
    let kind = match decoder.u16().map_err(|_| G4Error::StateConflict)? {
        1 => ExecutorDispositionKindV2::EffectStarted,
        2 => ExecutorDispositionKindV2::KnownSuccess,
        3 => ExecutorDispositionKindV2::FailedNoEffect,
        4 => ExecutorDispositionKindV2::Indeterminate,
        _ => return Err(G4Error::StateConflict),
    };
    let payload = ExecutorDispositionReceiptPayloadV2 {
        kind,
        installation_id: Digest32V2::new(decode_fixed::<32>(&mut decoder)?),
        active_state_manifest_digest: Digest32V2::new(decode_fixed::<32>(&mut decoder)?),
        deployment_generation: decoder.u64().map_err(|_| G4Error::StateConflict)?,
        effect_fence_epoch: decoder.u64().map_err(|_| G4Error::StateConflict)?,
        execution_nonce: Nonce32V2::new(decode_fixed::<32>(&mut decoder)?),
        dispatch_core_digest: Digest32V2::new(decode_fixed::<32>(&mut decoder)?),
        dispatch_subject_digest: Digest32V2::new(decode_fixed::<32>(&mut decoder)?),
        evidence_digest: Digest32V2::new(decode_fixed::<32>(&mut decoder)?),
        issued_at: UnixMillisV2::new(decoder.u64().map_err(|_| G4Error::StateConflict)?),
    };
    if decoder.position() != bytes.len() || encode_receipt_payload(payload)? != bytes {
        return Err(G4Error::StateConflict);
    }
    Ok(payload)
}

fn encode_receipt_payload(
    payload: ExecutorDispositionReceiptPayloadV2,
) -> Result<Vec<u8>, G4Error> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(11)
        .and_then(|encoder| encoder.u16(2))
        .and_then(|encoder| encoder.u16(payload.kind.tag()))
        .map_err(|_| G4Error::StateConflict)?;
    payload
        .installation_id
        .encode(&mut encoder, &mut ())
        .map_err(|_| G4Error::StateConflict)?;
    payload
        .active_state_manifest_digest
        .encode(&mut encoder, &mut ())
        .map_err(|_| G4Error::StateConflict)?;
    encoder
        .u64(payload.deployment_generation)
        .and_then(|encoder| encoder.u64(payload.effect_fence_epoch))
        .map_err(|_| G4Error::StateConflict)?;
    payload
        .execution_nonce
        .encode(&mut encoder, &mut ())
        .map_err(|_| G4Error::StateConflict)?;
    payload
        .dispatch_core_digest
        .encode(&mut encoder, &mut ())
        .map_err(|_| G4Error::StateConflict)?;
    payload
        .dispatch_subject_digest
        .encode(&mut encoder, &mut ())
        .map_err(|_| G4Error::StateConflict)?;
    payload
        .evidence_digest
        .encode(&mut encoder, &mut ())
        .map_err(|_| G4Error::StateConflict)?;
    encoder
        .u64(payload.issued_at.get())
        .map_err(|_| G4Error::StateConflict)?;
    Ok(encoder.into_writer())
}

fn encode_signed_receipt(receipt: &SignedExecutorDispositionReceiptV2) -> Result<Vec<u8>, G4Error> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(3)
        .and_then(|encoder| encoder.bytes(&receipt.canonical_payload))
        .map_err(|_| G4Error::StateConflict)?;
    receipt
        .key_id
        .encode(&mut encoder, &mut ())
        .map_err(|_| G4Error::StateConflict)?;
    encoder
        .bytes(&receipt.signature)
        .map_err(|_| G4Error::StateConflict)?;
    Ok(encoder.into_writer())
}

fn require_array(decoder: &mut minicbor::Decoder<'_>, expected: u64) -> Result<(), G4Error> {
    if decoder.array().map_err(|_| G4Error::StateConflict)? != Some(expected) {
        return Err(G4Error::StateConflict);
    }
    Ok(())
}

fn decode_fixed<const N: usize>(decoder: &mut minicbor::Decoder<'_>) -> Result<[u8; N], G4Error> {
    decoder
        .bytes()
        .map_err(|_| G4Error::StateConflict)?
        .try_into()
        .map_err(|_| G4Error::StateConflict)
}

pub(crate) fn preparation(
    entry: &KernelDispatchJournalEntryV2,
    kind: DispatchPreparationKindV2,
) -> DispatchPreparationV2 {
    DispatchPreparationV2 {
        kind,
        execution_nonce: entry.core.execution_nonce,
        dispatch_core_digest: entry.core_digest,
        dispatch_subject_digest: entry.core.dispatch_subject_digest,
        state: entry.state,
    }
}

fn domain_hash(domain: &[u8], canonical: &[u8]) -> Digest32V2 {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(canonical);
    Digest32V2::new(hasher.finalize().into())
}

fn is_zero<const N: usize>(bytes: &[u8; N]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}
