use std::sync::{Arc, RwLock};

use savana_kernel_protocol::v2::{
    ActionIntentIdV2, Digest32V2, DurableReleaseIdV2, DurableRunIdV2, DurableTaskIdV2, EntityIdV2,
    ExecutorIdentityV2, FinalReleaseSemanticBindingV2, HpkeX25519KeyIdV2, ImplementationIdV2,
    NamespaceIdV2, PrincipalIdV2, RoleIdV2, ToolClassIdV2, UnixMillisV2,
    VerifiedEffectLedgerProjectionV2, VersionV2,
};

use super::dispatch::{
    DispatchCoreV2, DispatchPreparationV2, VerifiedApprovalSettlementBindingV2,
    VerifiedEffectGateAuthorityV2, VerifiedExecutionTicketV2,
    VerifiedFinalReleaseApprovalBindingV2, VerifiedFinalReleaseDispatchV2,
    VerifiedFinalReleaseTicketV2,
};
use super::ontology::{OntologyEvaluationContextV2, OntologyEvaluationV2};
use super::{
    ArgumentNameV2, AttemptKindV2, ConnectorRegistryStateV2, G3Error, G4Error, G5Error,
    G5PolicyDispositionV2, KernelValueV2, OntologyExprV2, ValidatorBuildManifestIdentityV2,
    VerifiedInternalValidatorImplementationV2, VerifiedInternalValidatorRegistryV2,
    VerifiedOntologySetV2, VerifiedQuotaLimitV2,
};

/// Shared access to one verified connector chain and its current standing-policy
/// view. Callers may submit canonical deltas for verification, but cannot set a
/// raw head digest.
#[derive(Debug, Clone)]
pub struct SharedVerifiedConnectorRegistryV2 {
    inner: Arc<RwLock<ConnectorRegistryStateV2>>,
}

impl SharedVerifiedConnectorRegistryV2 {
    pub fn from_verified_state(state: ConnectorRegistryStateV2) -> Result<Self, G4Error> {
        if state
            .genesis_digest()
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
            || state.head_digest().as_bytes().iter().all(|byte| *byte == 0)
        {
            return Err(G4Error::StateConflict);
        }
        Ok(Self {
            inner: Arc::new(RwLock::new(state)),
        })
    }

    pub fn current_head_digest(&self) -> Result<Digest32V2, G4Error> {
        self.inner
            .read()
            .map(|state| state.head_digest())
            .map_err(|_| G4Error::StateConflict)
    }

    pub fn snapshot(&self) -> Result<ConnectorRegistryStateV2, G4Error> {
        self.inner
            .read()
            .map(|state| state.clone())
            .map_err(|_| G4Error::StateConflict)
    }

    pub fn verify_and_apply_canonical_delta(&self, bytes: &[u8]) -> Result<(), G4Error> {
        self.inner
            .write()
            .map_err(|_| G4Error::StateConflict)?
            .apply_canonical_delta(bytes)
    }

    pub fn verify_and_replay_canonical_delta(&self, bytes: &[u8]) -> Result<(), G4Error> {
        self.inner
            .write()
            .map_err(|_| G4Error::StateConflict)?
            .replay_canonical_delta(bytes)
    }

    #[cfg(test)]
    pub(crate) fn try_verify_and_apply_canonical_delta(&self, bytes: &[u8]) -> Result<(), G4Error> {
        self.inner
            .try_write()
            .map_err(|_| G4Error::StateConflict)?
            .apply_canonical_delta(bytes)
    }

    /// Replaces only the standing-policy view of the exact same verified
    /// registered chain. It cannot advance, fork, or roll back the chain.
    pub fn replace_verified_standing_policy_state(
        &self,
        replacement: ConnectorRegistryStateV2,
    ) -> Result<(), G4Error> {
        let mut current = self.inner.write().map_err(|_| G4Error::StateConflict)?;
        if !current.has_same_verified_registered_chain(&replacement) {
            return Err(G4Error::StateConflict);
        }
        *current = replacement;
        Ok(())
    }

    pub(super) fn while_current_head<T>(
        &self,
        expected: Digest32V2,
        operation: impl FnOnce(Digest32V2) -> Result<T, G4Error>,
    ) -> Result<T, G4Error> {
        let state = self.inner.read().map_err(|_| G4Error::StateConflict)?;
        let current = state.head_digest();
        if current != expected {
            return Err(G4Error::StateConflict);
        }
        operation(current)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedOntologyEvaluationV2 {
    pub(super) inner: OntologyEvaluationV2,
}

impl VerifiedOntologyEvaluationV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn evaluate(
        expression: &OntologyExprV2,
        arguments: Vec<(ArgumentNameV2, &KernelValueV2)>,
        ontology: Vec<((NamespaceIdV2, EntityIdV2), &KernelValueV2)>,
        sets: Vec<VerifiedOntologySetV2>,
        role: RoleIdV2,
        tool: ToolClassIdV2,
        attempt_kind: AttemptKindV2,
        principal: PrincipalIdV2,
        task: DurableTaskIdV2,
    ) -> Result<Self, G4Error> {
        let context = OntologyEvaluationContextV2::new(
            arguments,
            ontology,
            sets,
            role,
            tool,
            attempt_kind,
            principal,
            task,
        )?;
        Ok(Self {
            inner: expression.evaluate(&context),
        })
    }

    pub const fn permits(self) -> bool {
        self.inner.permits()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedPolicyDispositionV2 {
    pub(super) inner: G5PolicyDispositionV2,
}

impl VerifiedPolicyDispositionV2 {
    pub const fn permit_from_verified_policy() -> Self {
        Self {
            inner: G5PolicyDispositionV2::from_verified_policy_permit(),
        }
    }

    pub const fn require_approval_from_verified_policy() -> Self {
        Self {
            inner: G5PolicyDispositionV2::from_verified_policy_require_approval(),
        }
    }

    pub const fn deny_from_verified_policy() -> Self {
        Self {
            inner: G5PolicyDispositionV2::from_verified_policy_deny(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InternalValidatorBuildV2 {
    kind: super::InternalValidatorImplementationKindV2,
    implementation_id: ImplementationIdV2,
    semantic_version: VersionV2,
    build_manifest_digest: Digest32V2,
}

impl InternalValidatorBuildV2 {
    pub const fn new(
        kind: super::InternalValidatorImplementationKindV2,
        implementation_id: ImplementationIdV2,
        semantic_version: VersionV2,
        build_manifest_digest: Digest32V2,
    ) -> Self {
        Self {
            kind,
            implementation_id,
            semantic_version,
            build_manifest_digest,
        }
    }
}

pub fn activate_internal_validator_registry(
    builds: Vec<InternalValidatorBuildV2>,
) -> Result<VerifiedInternalValidatorRegistryV2, G5Error> {
    let mut implementations = Vec::new();
    implementations
        .try_reserve_exact(builds.len())
        .map_err(|_| G5Error::AllocationFailure)?;
    for build in builds {
        let identity = ValidatorBuildManifestIdentityV2::from_reproducible_build_manifest(
            build.implementation_id,
            build.semantic_version,
            build.build_manifest_digest,
        )?;
        implementations.push(
            VerifiedInternalValidatorImplementationV2::from_build_manifest(build.kind, identity)?,
        );
    }
    VerifiedInternalValidatorRegistryV2::from_build_manifest(implementations)
}

/// An exact execution ticket after kerneld has resolved and authenticated its
/// opaque handle. The raw ticket digest is deliberately not exposed again.
#[derive(Debug)]
pub struct ResolvedExecutionTicketV2 {
    pub(super) inner: VerifiedExecutionTicketV2,
    pub(super) ticket_digest: Digest32V2,
}

impl ResolvedExecutionTicketV2 {
    pub fn from_resolved_kernel_ticket(
        ticket_digest: Digest32V2,
        action_intent_id: ActionIntentIdV2,
        semantic_binding_digest: Digest32V2,
    ) -> Result<Self, G4Error> {
        Ok(Self {
            inner: VerifiedExecutionTicketV2::from_verified_ticket(
                ticket_digest,
                action_intent_id,
                semantic_binding_digest,
            )?,
            ticket_digest,
        })
    }
}

/// A tool approval settlement after kerneld has consumed the purpose-specific
/// approvald transfer and matched it to the durable action intent.
#[derive(Debug, Clone, Copy)]
pub struct VerifiedToolApprovalSettlementV2 {
    pub(super) inner: VerifiedApprovalSettlementBindingV2,
}

impl VerifiedToolApprovalSettlementV2 {
    pub fn from_consumed_exact_settlement(
        settlement_digest: Digest32V2,
        action_intent_id: ActionIntentIdV2,
        approval_binding_digest: Digest32V2,
        active_state_manifest_digest: Digest32V2,
    ) -> Result<Self, G4Error> {
        Ok(Self {
            inner: VerifiedApprovalSettlementBindingV2::from_verified_settlement(
                settlement_digest,
                action_intent_id,
                approval_binding_digest,
                active_state_manifest_digest,
            )?,
        })
    }
}

/// The authenticated, unfenced deployment projection read immediately before
/// the atomic kernel dispatch-preparation transaction.
#[derive(Debug)]
pub struct VerifiedEffectGateLeaseV2 {
    pub(super) inner: VerifiedEffectGateAuthorityV2,
}

impl VerifiedEffectGateLeaseV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn from_verified_ledger_projection(
        projection: VerifiedEffectLedgerProjectionV2,
        installation_id: Digest32V2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        effect_fence_epoch: u64,
        executor_identity: ExecutorIdentityV2,
        executor_key_id: HpkeX25519KeyIdV2,
        connector_registry: &SharedVerifiedConnectorRegistryV2,
        expires_at: UnixMillisV2,
    ) -> Result<Self, G4Error> {
        if projection.installation_id() != installation_id
            || projection.active_state_manifest_digest() != active_state_manifest_digest
            || projection.deployment_generation() != deployment_generation
            || projection.effect_fence_epoch() != effect_fence_epoch
            || projection.effects_fenced()
            || !projection.terminal_phase()
        {
            return Err(G4Error::StateConflict);
        }
        Self::from_authenticated_ledger(
            installation_id,
            active_state_manifest_digest,
            deployment_generation,
            effect_fence_epoch,
            false,
            executor_identity,
            executor_key_id,
            connector_registry,
            expires_at,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_authenticated_ledger(
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
        Ok(Self {
            inner: VerifiedEffectGateAuthorityV2::from_authenticated_unfenced_ledger(
                installation_id,
                active_state_manifest_digest,
                deployment_generation,
                effect_fence_epoch,
                effects_fenced,
                executor_identity,
                executor_key_id,
                connector_registry,
                expires_at,
            )?,
        })
    }
}

/// A release record accepted from the vault after exact release-policy and
/// principal checks. It contains no release bytes.
#[derive(Debug, Clone)]
pub struct VerifiedFinalReleaseRecordV2 {
    pub(super) inner: VerifiedFinalReleaseDispatchV2,
}

impl VerifiedFinalReleaseRecordV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn from_authorized_vault_release(
        installation_id: Digest32V2,
        active_state_manifest_digest: Digest32V2,
        durable_task_id: DurableTaskIdV2,
        durable_run_id: DurableRunIdV2,
        durable_release_id: DurableReleaseIdV2,
        binding: FinalReleaseSemanticBindingV2,
    ) -> Result<Self, G4Error> {
        Ok(Self {
            inner: VerifiedFinalReleaseDispatchV2::from_verified_release(
                installation_id,
                active_state_manifest_digest,
                durable_task_id,
                durable_run_id,
                durable_release_id,
                binding,
            )?,
        })
    }

    pub const fn binding(&self) -> FinalReleaseSemanticBindingV2 {
        self.inner.binding()
    }
}

/// A one-use final-release ticket after kerneld resolves its opaque handle.
#[derive(Debug)]
pub struct ResolvedFinalReleaseTicketV2 {
    pub(super) inner: VerifiedFinalReleaseTicketV2,
    pub(super) ticket_digest: Digest32V2,
}

impl ResolvedFinalReleaseTicketV2 {
    pub fn from_resolved_kernel_ticket(
        ticket_digest: Digest32V2,
        durable_release_id: DurableReleaseIdV2,
        binding_digest: Digest32V2,
    ) -> Result<Self, G4Error> {
        Ok(Self {
            inner: VerifiedFinalReleaseTicketV2::from_verified_ticket(
                ticket_digest,
                durable_release_id,
                binding_digest,
            )?,
            ticket_digest,
        })
    }
}

/// A final-release approval after the purpose-specific approval settlement has
/// been consumed and bound to the exact vault release.
#[derive(Debug)]
pub struct VerifiedFinalReleaseSettlementV2 {
    pub(super) inner: VerifiedFinalReleaseApprovalBindingV2,
    destination_digest: Digest32V2,
    token_set_digest: Digest32V2,
    issued_at: UnixMillisV2,
    expires_at: UnixMillisV2,
}

impl VerifiedFinalReleaseSettlementV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn from_consumed_exact_settlement(
        settlement_digest: Digest32V2,
        durable_release_id: DurableReleaseIdV2,
        binding_digest: Digest32V2,
        destination_digest: Digest32V2,
        token_set_digest: Digest32V2,
        active_state_manifest_digest: Digest32V2,
        issued_at: UnixMillisV2,
        expires_at: UnixMillisV2,
    ) -> Result<Self, G4Error> {
        if destination_digest.as_bytes().iter().all(|byte| *byte == 0)
            || token_set_digest.as_bytes().iter().all(|byte| *byte == 0)
            || issued_at.get() == 0
            || issued_at.get() >= expires_at.get()
        {
            return Err(G4Error::StateConflict);
        }
        Ok(Self {
            inner: VerifiedFinalReleaseApprovalBindingV2::from_verified_settlement(
                settlement_digest,
                durable_release_id,
                binding_digest,
                active_state_manifest_digest,
            )?,
            destination_digest,
            token_set_digest,
            issued_at,
            expires_at,
        })
    }

    pub(crate) fn validate_declassification(
        &self,
        destination_digest: Digest32V2,
        token_set_digest: Digest32V2,
        active_state_manifest_digest: Digest32V2,
        at_unix_ms: u64,
        max_age_ms: u64,
    ) -> Result<(), G3Error> {
        if self.destination_digest != destination_digest
            || self.token_set_digest != token_set_digest
            || self.inner.active_state_manifest_digest() != active_state_manifest_digest
        {
            return Err(G3Error::ConsentScopeMismatch);
        }
        if at_unix_ms < self.issued_at.get()
            || at_unix_ms >= self.expires_at.get()
            || at_unix_ms.saturating_sub(self.issued_at.get()) > max_age_ms
        {
            return Err(G3Error::ConsentExpired);
        }
        Ok(())
    }
}

/// Read-only result of the atomic G7 preparation commit. The consumed ticket
/// is represented only by its digest and cannot be replayed as a capability.
#[derive(Debug, Clone)]
pub struct KernelPreparedDispatchV2 {
    task_binding: super::TaskDispatchBindingV2,
    preparation: DispatchPreparationV2,
    core: DispatchCoreV2,
    consumed_ticket_digest: Digest32V2,
    sealed_envelope_digest: Digest32V2,
}

impl KernelPreparedDispatchV2 {
    pub(super) const fn new(
        preparation: DispatchPreparationV2,
        core: DispatchCoreV2,
        consumed_ticket_digest: Digest32V2,
        sealed_envelope_digest: Digest32V2,
        task_binding: super::TaskDispatchBindingV2,
    ) -> Self {
        Self {
            task_binding,
            preparation,
            core,
            consumed_ticket_digest,
            sealed_envelope_digest,
        }
    }

    pub const fn preparation(&self) -> DispatchPreparationV2 {
        self.preparation
    }

    pub const fn task_binding(&self) -> &super::TaskDispatchBindingV2 {
        &self.task_binding
    }

    pub const fn core(&self) -> &DispatchCoreV2 {
        &self.core
    }

    pub const fn consumed_ticket_digest(&self) -> Digest32V2 {
        self.consumed_ticket_digest
    }

    pub const fn sealed_envelope_digest(&self) -> Digest32V2 {
        self.sealed_envelope_digest
    }
}

pub(super) fn validate_quota_subject(
    limit: VerifiedQuotaLimitV2,
    expected: super::DispatchQuotaSubjectV2,
) -> Result<VerifiedQuotaLimitV2, G4Error> {
    if limit.subject() != expected {
        return Err(G4Error::InvalidQuotaLimit);
    }
    Ok(limit)
}
