use std::fs::File;
use std::time::Instant;

use savana_kernel_protocol::v2::{
    Digest32V2, EffectLedgerProjectionBindingV2, ExecutorFailureClassV2, Nonce32V2,
    SignedExecutorEffectStartedReceiptV2, UnixMillisV2,
};

use crate::effect_gate::{
    EffectGateCoordinatorV2, EffectGateErrorV2, EffectGateGuardV2, EffectGateOperationKindV2,
};
use crate::{
    ArmedEffectV2, DurableExecdServiceV2, ExecdErrorV2, ExecdJournalStateV2, ExecdQueryV2,
    ProviderAttemptPredecessorV2, RetainedProviderResponseV2, SignedDispatchAdmissionV2,
    SignedExecutorReceiptV2, StoredExecutorCompletionV2,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ExecdRuntimeErrorV2 {
    #[error("executor journal operation failed")]
    Journal(ExecdErrorV2),
    #[error("effect gate deadline was exceeded")]
    DeadlineExceeded,
    #[error("effect gate is fenced")]
    Fenced,
    #[error("effect gate is unavailable")]
    EffectGateUnavailable,
    #[error("effect gate ownership invariant failed")]
    GuardInvariant,
}

impl From<ExecdErrorV2> for ExecdRuntimeErrorV2 {
    fn from(error: ExecdErrorV2) -> Self {
        Self::Journal(error)
    }
}

impl From<EffectGateErrorV2> for ExecdRuntimeErrorV2 {
    fn from(error: EffectGateErrorV2) -> Self {
        match error {
            EffectGateErrorV2::DeadlineExceeded => Self::DeadlineExceeded,
            EffectGateErrorV2::Fenced => Self::Fenced,
            EffectGateErrorV2::Unavailable => Self::EffectGateUnavailable,
        }
    }
}

/// The production mutation boundary for execd.
///
/// The durable journal and effect-gate guards deliberately share one owner.
/// A guard is acquired before a new `Prepared` record can become durable and is
/// retained until a terminal disposition receipt has itself become durable.
pub struct EffectGatedExecdRuntimeV2 {
    durable: DurableExecdServiceV2,
    effect_gate: EffectGateCoordinatorV2,
    active: Vec<(Nonce32V2, EffectGateGuardV2)>,
}

impl std::fmt::Debug for EffectGatedExecdRuntimeV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EffectGatedExecdRuntimeV2")
            .field("durable", &self.durable)
            .field("active_effects", &self.active.len())
            .finish_non_exhaustive()
    }
}

impl EffectGatedExecdRuntimeV2 {
    pub fn from_durable_service(
        durable: DurableExecdServiceV2,
        shared_only_effect_gate_descriptor: File,
        read_only_ledger_projection_descriptor: File,
        projection_binding: EffectLedgerProjectionBindingV2,
        deadline: Instant,
    ) -> Result<Self, ExecdRuntimeErrorV2> {
        let effect_gate = EffectGateCoordinatorV2::from_shared_only_descriptors(
            shared_only_effect_gate_descriptor,
            read_only_ledger_projection_descriptor,
            projection_binding,
        )?;
        let projection = durable.recovery_projection()?;
        let mut active = Vec::new();
        active
            .try_reserve(
                projection
                    .iter()
                    .filter(|entry| requires_effect_gate(entry.state()))
                    .count(),
            )
            .map_err(|_| ExecdRuntimeErrorV2::Journal(ExecdErrorV2::AllocationFailure))?;
        for entry in projection {
            if requires_effect_gate(entry.state()) {
                let guard = effect_gate.acquire(
                    EffectGateOperationKindV2::Recovery,
                    Digest32V2::new(*entry.execution_nonce().as_bytes()),
                    deadline,
                )?;
                active.push((entry.execution_nonce(), guard));
            }
        }
        Ok(Self {
            durable,
            effect_gate,
            active,
        })
    }

    pub fn query(&self, nonce: Nonce32V2) -> Result<ExecdQueryV2, ExecdRuntimeErrorV2> {
        self.durable.query(nonce).map_err(Into::into)
    }

    pub(crate) fn sealed_execution_envelope(
        &self,
        nonce: Nonce32V2,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, ExecdRuntimeErrorV2> {
        self.durable
            .sealed_execution_envelope(nonce)
            .map_err(Into::into)
    }

    pub fn recovery_projection(&self) -> Result<Vec<ExecdQueryV2>, ExecdRuntimeErrorV2> {
        self.durable.recovery_projection().map_err(Into::into)
    }

    pub fn terminal_receipt(
        &self,
        nonce: Nonce32V2,
    ) -> Result<SignedExecutorReceiptV2, ExecdRuntimeErrorV2> {
        self.durable.terminal_receipt(nonce).map_err(Into::into)
    }

    pub fn effect_started_receipt(
        &self,
        nonce: Nonce32V2,
    ) -> Result<SignedExecutorEffectStartedReceiptV2, ExecdRuntimeErrorV2> {
        self.durable
            .effect_started_receipt(nonce)
            .map_err(Into::into)
    }

    pub fn retained_provider_response(
        &self,
        nonce: Nonce32V2,
    ) -> Result<RetainedProviderResponseV2, ExecdRuntimeErrorV2> {
        self.durable
            .retained_provider_response(nonce)
            .map_err(Into::into)
    }

    pub fn completion(
        &self,
        nonce: Nonce32V2,
    ) -> Result<StoredExecutorCompletionV2, ExecdRuntimeErrorV2> {
        self.durable.completion(nonce).map_err(Into::into)
    }

    pub fn accept_signed_dispatch(
        &mut self,
        canonical_envelope: &[u8],
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<ExecdQueryV2, ExecdRuntimeErrorV2> {
        let admission = self
            .durable
            .classify_signed_dispatch(canonical_envelope, now)?;
        let verified = match admission {
            SignedDispatchAdmissionV2::ExactReplay(query) => {
                if requires_effect_gate(query.state()) && !self.has_guard(query.execution_nonce()) {
                    return Err(ExecdRuntimeErrorV2::GuardInvariant);
                }
                return Ok(query);
            }
            SignedDispatchAdmissionV2::New(verified) => *verified,
        };
        let nonce = verified.payload.execution_nonce;
        // Reserve before either the OS guard or the durable Prepared write. If
        // allocation fails, no journal entry can be left without owned guard
        // storage.
        self.active
            .try_reserve(1)
            .map_err(|_| ExecdRuntimeErrorV2::Journal(ExecdErrorV2::AllocationFailure))?;
        let guard = self.effect_gate.acquire(
            EffectGateOperationKindV2::DispatchExecution,
            Digest32V2::new(*nonce.as_bytes()),
            deadline,
        )?;
        let query = self.durable.commit_new_signed_dispatch(verified)?;
        if requires_effect_gate(query.state()) && !self.has_guard(query.execution_nonce()) {
            self.active.push((query.execution_nonce(), guard));
        }
        Ok(query)
    }

    pub fn prepare_provider_attempt(
        &mut self,
        nonce: Nonce32V2,
        prepared_request_digest: Digest32V2,
        now: UnixMillisV2,
    ) -> Result<ProviderAttemptPredecessorV2, ExecdRuntimeErrorV2> {
        self.require_guard(nonce)?;
        self.durable
            .prepare_provider_attempt(nonce, prepared_request_digest, now)
            .map_err(Into::into)
    }

    pub fn record_effect_started(
        &mut self,
        predecessor: ProviderAttemptPredecessorV2,
        now: UnixMillisV2,
    ) -> Result<ArmedEffectV2, ExecdRuntimeErrorV2> {
        self.require_guard(predecessor.execution_nonce())?;
        self.durable
            .record_effect_started(predecessor, now)
            .map_err(Into::into)
    }

    pub fn record_provider_response(
        &mut self,
        nonce: Nonce32V2,
        response: Vec<u8>,
    ) -> Result<RetainedProviderResponseV2, ExecdRuntimeErrorV2> {
        self.require_guard(nonce)?;
        self.durable
            .record_provider_response(nonce, response)
            .map_err(Into::into)
    }

    pub fn prepare_final_release_evidence(
        &mut self,
        nonce: Nonce32V2,
        provider_evidence: Vec<u8>,
        audit_evidence: Vec<u8>,
        now: UnixMillisV2,
    ) -> Result<Digest32V2, ExecdRuntimeErrorV2> {
        self.require_guard(nonce)?;
        self.durable
            .prepare_final_release_evidence(nonce, provider_evidence, audit_evidence, now)
            .map_err(Into::into)
    }

    #[cfg(test)]
    pub fn record_known_success(
        &mut self,
        nonce: Nonce32V2,
        evidence_digest: Digest32V2,
        now: UnixMillisV2,
    ) -> Result<SignedExecutorReceiptV2, ExecdRuntimeErrorV2> {
        self.require_guard(nonce)?;
        let receipt = self
            .durable
            .record_known_success(nonce, evidence_digest, now)?;
        self.release_guard(nonce)?;
        Ok(receipt)
    }

    pub fn record_tool_completion(
        &mut self,
        nonce: Nonce32V2,
        result: Vec<u8>,
        evidence_digest: Digest32V2,
        now: UnixMillisV2,
    ) -> Result<StoredExecutorCompletionV2, ExecdRuntimeErrorV2> {
        self.require_guard(nonce)?;
        let completion =
            self.durable
                .record_tool_completion(nonce, result, evidence_digest, now)?;
        self.release_guard(nonce)?;
        Ok(completion)
    }

    pub fn record_final_release_completion(
        &mut self,
        nonce: Nonce32V2,
        now: UnixMillisV2,
    ) -> Result<StoredExecutorCompletionV2, ExecdRuntimeErrorV2> {
        self.require_guard(nonce)?;
        let completion = self.durable.record_final_release_completion(nonce, now)?;
        self.release_guard(nonce)?;
        Ok(completion)
    }

    pub fn record_failed_no_effect(
        &mut self,
        nonce: Nonce32V2,
        class: ExecutorFailureClassV2,
        evidence_digest: Digest32V2,
        now: UnixMillisV2,
    ) -> Result<SignedExecutorReceiptV2, ExecdRuntimeErrorV2> {
        self.require_guard(nonce)?;
        let receipt = self
            .durable
            .record_failed_no_effect(nonce, class, evidence_digest, now)?;
        self.release_guard(nonce)?;
        Ok(receipt)
    }

    pub fn record_failed_no_effect_recovery(
        &mut self,
        nonce: Nonce32V2,
        class: ExecutorFailureClassV2,
        evidence_digest: Digest32V2,
        now: UnixMillisV2,
    ) -> Result<SignedExecutorReceiptV2, ExecdRuntimeErrorV2> {
        self.require_guard(nonce)?;
        let receipt =
            self.durable
                .record_failed_no_effect_recovery(nonce, class, evidence_digest, now)?;
        self.release_guard(nonce)?;
        Ok(receipt)
    }

    pub fn record_indeterminate(
        &mut self,
        nonce: Nonce32V2,
        evidence_digest: Digest32V2,
        now: UnixMillisV2,
    ) -> Result<SignedExecutorReceiptV2, ExecdRuntimeErrorV2> {
        self.require_guard(nonce)?;
        let receipt = self
            .durable
            .record_indeterminate(nonce, evidence_digest, now)?;
        self.release_guard(nonce)?;
        Ok(receipt)
    }

    pub fn record_indeterminate_recovery(
        &mut self,
        nonce: Nonce32V2,
        evidence_digest: Digest32V2,
        now: UnixMillisV2,
    ) -> Result<SignedExecutorReceiptV2, ExecdRuntimeErrorV2> {
        self.require_guard(nonce)?;
        let receipt = self
            .durable
            .record_indeterminate_recovery(nonce, evidence_digest, now)?;
        self.release_guard(nonce)?;
        Ok(receipt)
    }

    pub fn acknowledge_completion(
        &mut self,
        nonce: Nonce32V2,
        kernel_commit_digest: Digest32V2,
    ) -> Result<(), ExecdRuntimeErrorV2> {
        self.durable
            .acknowledge_completion(nonce, kernel_commit_digest)
            .map_err(Into::into)
    }

    pub fn fence(&self, deadline: Instant) -> Result<(), ExecdRuntimeErrorV2> {
        self.effect_gate.fence(deadline).map_err(Into::into)
    }

    fn has_guard(&self, nonce: Nonce32V2) -> bool {
        self.active
            .iter()
            .any(|(active_nonce, _)| *active_nonce == nonce)
    }

    fn require_guard(&self, nonce: Nonce32V2) -> Result<(), ExecdRuntimeErrorV2> {
        if self.has_guard(nonce) {
            Ok(())
        } else {
            Err(ExecdRuntimeErrorV2::GuardInvariant)
        }
    }

    fn release_guard(&mut self, nonce: Nonce32V2) -> Result<(), ExecdRuntimeErrorV2> {
        let index = self
            .active
            .iter()
            .position(|(active_nonce, _)| *active_nonce == nonce)
            .ok_or(ExecdRuntimeErrorV2::GuardInvariant)?;
        self.active.swap_remove(index);
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn active_guard_count_for_test(&self) -> usize {
        self.active.len()
    }
}

const fn requires_effect_gate(state: ExecdJournalStateV2) -> bool {
    matches!(
        state,
        ExecdJournalStateV2::Prepared
            | ExecdJournalStateV2::ProviderAttemptPrepared
            | ExecdJournalStateV2::EffectStarted
            | ExecdJournalStateV2::ProviderResponseRetained
            | ExecdJournalStateV2::ReleaseEvidencePrepared
    )
}
