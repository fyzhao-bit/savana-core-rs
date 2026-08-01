use savana_kernel_protocol::v2::{
    decode_read_agent_view_response_v2, encode_read_agent_view_response_v2, BootIdV2, Digest32V2,
    DurableRunIdV2, DurableTaskIdV2, MaskedDocumentHandleV2, PrincipalIdV2, ProducerIdentityV2,
    ReadAgentViewResponseV2, ServiceIdentityV2, UnixMillisV2, VaultPublicStateV2,
};
use savana_kernel_protocol::StableCode;
use savana_policy_core::v2::EffectSetV2;
use sha2::{Digest as _, Sha256};

use crate::v2_agent_authority::{PreparedAgentClaimMaterialV2, SignedPlannerPolicyV2};
use crate::v2_core_services::KernelIngressCommitSinkV2;
use crate::v2_declassification_policy::ActiveDeclassificationRuleSetV2;
use crate::v2_input_owner::FinalizedKernelInputV2;
use crate::v2_runtime::accept_finalized_input_into_kernel;

const DURABLE_RUN_DOMAIN_V2: &[u8] = b"SAVANA_KERNEL_DURABLE_RUN_V2\0";
const MASKED_AGENT_VIEW_RECORD_TAG_V2: u16 = 0;

pub(crate) struct ProductionKernelDataPlaneV2 {
    input_runtime: savana_input_runtime::InputRuntimeV2,
    vault: savana_vault::DurableVaultServiceV2,
    declassification_rules: ActiveDeclassificationRuleSetV2,
    installation_id: Digest32V2,
    producer_identity: ProducerIdentityV2,
    agentd_boot_id: BootIdV2,
    agentd_identity: ServiceIdentityV2,
    agentd_peer_identity_digest: Digest32V2,
    policy_allowed_effects: EffectSetV2,
    logical_run_ttl_ms: u64,
}

impl std::fmt::Debug for ProductionKernelDataPlaneV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ProductionKernelDataPlaneV2(<private-state>)")
    }
}

impl ProductionKernelDataPlaneV2 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        input_runtime: savana_input_runtime::InputRuntimeV2,
        vault: savana_vault::DurableVaultServiceV2,
        declassification_rules: ActiveDeclassificationRuleSetV2,
        installation_id: Digest32V2,
        producer_identity: ProducerIdentityV2,
        agentd_boot_id: BootIdV2,
        agentd_identity: ServiceIdentityV2,
        agentd_peer_identity_digest: Digest32V2,
        policy_allowed_effects: EffectSetV2,
        logical_run_ttl_ms: u64,
    ) -> Result<Self, StableCode> {
        if [
            installation_id.as_bytes(),
            producer_identity.as_bytes(),
            agentd_boot_id.as_bytes(),
            agentd_identity.as_bytes(),
            agentd_peer_identity_digest.as_bytes(),
        ]
        .iter()
        .any(|value| value.iter().all(|byte| *byte == 0))
            || logical_run_ttl_ms == 0
        {
            return Err(StableCode::KernelUnavailable);
        }
        Ok(Self {
            input_runtime,
            vault,
            declassification_rules,
            installation_id,
            producer_identity,
            agentd_boot_id,
            agentd_identity,
            agentd_peer_identity_digest,
            policy_allowed_effects,
            logical_run_ttl_ms,
        })
    }
}

impl KernelIngressCommitSinkV2 for ProductionKernelDataPlaneV2 {
    fn commit(
        &mut self,
        durable_task_id: DurableTaskIdV2,
        principal: PrincipalIdV2,
        finalized: &FinalizedKernelInputV2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        now: UnixMillisV2,
    ) -> Result<PreparedAgentClaimMaterialV2, StableCode> {
        if principal != finalized.authorization().authenticated_principal() || now.get() == 0 {
            return Err(StableCode::ApprovalBindingMismatch);
        }
        let durable_run_id = durable_run_id(
            self.installation_id,
            active_state_manifest_digest,
            durable_task_id,
            principal,
            finalized.input_commitment(),
        )?;
        let expires_at = UnixMillisV2::new(
            now.get()
                .checked_add(self.logical_run_ttl_ms)
                .ok_or(StableCode::KernelUnavailable)?
                .min(finalized.authorization().expires_at().get()),
        );
        if expires_at.get() <= now.get() {
            return Err(StableCode::PolicyExpired);
        }
        let declassification_rules = self
            .declassification_rules
            .snapshot()
            .map_err(|_| StableCode::PolicyDenied)?;
        let accepted = accept_finalized_input_into_kernel(
            &self.input_runtime,
            &mut self.vault,
            &declassification_rules,
            finalized,
            self.installation_id,
            active_state_manifest_digest,
            deployment_generation,
            self.producer_identity,
            durable_task_id,
            durable_run_id,
            self.policy_allowed_effects,
            now,
            expires_at,
        )
        .map_err(|_| StableCode::PolicyDenied)?;
        let (gated, initial_value, provenance, live) = accepted.into_parts();
        let signed_planner_policy =
            SignedPlannerPolicyV2::from_verified_input(gated.planner_envelope())
                .map_err(|_| StableCode::PolicyDenied)?;
        let context = savana_vault::VaultAccessContextV2::from_authenticated_agent(
            self.agentd_boot_id,
            self.agentd_identity,
            self.agentd_peer_identity_digest,
            durable_run_id,
            expires_at,
        )
        .map_err(|_| StableCode::KernelUnavailable)?;
        let document = self
            .vault
            .issue_masked_document(&live, context, now)
            .map_err(|_| StableCode::KernelUnavailable)?;
        PreparedAgentClaimMaterialV2::from_verified_ingress(
            durable_run_id,
            self.producer_identity,
            initial_value,
            provenance,
            document,
            self.policy_allowed_effects,
            signed_planner_policy,
            expires_at,
        )
        .map_err(|_| StableCode::KernelUnavailable)
    }

    fn read_agent_view(
        &mut self,
        document: MaskedDocumentHandleV2,
        maximum_encoded_bytes: u32,
        now: UnixMillisV2,
    ) -> Result<ReadAgentViewResponseV2, StableCode> {
        let material = self
            .vault
            .read_agent_bytes_for_authenticated_agent(
                &document,
                self.agentd_boot_id,
                self.agentd_identity,
                self.agentd_peer_identity_digest,
                now,
            )
            .map_err(map_vault_error)?;
        let response = decode_persisted_agent_view(&material)?;
        let encoded = encode_read_agent_view_response_v2(&response)
            .map_err(|_| StableCode::KernelUnavailable)?;
        if encoded.len()
            > usize::try_from(maximum_encoded_bytes).map_err(|_| StableCode::PolicyLimitExceeded)?
        {
            return Err(StableCode::PolicyLimitExceeded);
        }
        Ok(response)
    }

    fn revoke_vault(
        &mut self,
        document: MaskedDocumentHandleV2,
        now: UnixMillisV2,
    ) -> Result<VaultPublicStateV2, StableCode> {
        let state = self
            .vault
            .revoke_for_authenticated_agent(
                &document,
                self.agentd_boot_id,
                self.agentd_identity,
                self.agentd_peer_identity_digest,
                now,
            )
            .map_err(map_vault_error)?;
        Ok(match state {
            savana_vault::VaultPublicStateV2::Pending => VaultPublicStateV2::Pending,
            savana_vault::VaultPublicStateV2::Live => VaultPublicStateV2::Live,
            savana_vault::VaultPublicStateV2::ReleaseAuthorized => {
                VaultPublicStateV2::ReleaseAuthorized
            }
            savana_vault::VaultPublicStateV2::Dispatching => VaultPublicStateV2::Dispatching,
            savana_vault::VaultPublicStateV2::Released => VaultPublicStateV2::Released,
            savana_vault::VaultPublicStateV2::FailedNoEffect => VaultPublicStateV2::FailedNoEffect,
            savana_vault::VaultPublicStateV2::Revoked => VaultPublicStateV2::Revoked,
            savana_vault::VaultPublicStateV2::Expired => VaultPublicStateV2::Expired,
            savana_vault::VaultPublicStateV2::Indeterminate => VaultPublicStateV2::Indeterminate,
            savana_vault::VaultPublicStateV2::RestartInvalidated => {
                VaultPublicStateV2::RestartInvalidated
            }
        })
    }

    fn read_release_payload(
        &mut self,
        document: MaskedDocumentHandleV2,
        durable_run_id: DurableRunIdV2,
        now: UnixMillisV2,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, StableCode> {
        self.vault
            .read_release_bytes_for_authenticated_agent(
                &document,
                self.agentd_boot_id,
                self.agentd_identity,
                self.agentd_peer_identity_digest,
                durable_run_id,
                now,
            )
            .map_err(map_vault_error)
    }

    fn prepare_release(
        &mut self,
        document: MaskedDocumentHandleV2,
        durable_run_id: DurableRunIdV2,
        material: savana_vault::VaultReleaseMaterialV2,
        now: UnixMillisV2,
    ) -> Result<savana_vault::PendingVaultReleaseV2, StableCode> {
        self.vault
            .prepare_release_for_authenticated_agent(
                &document,
                self.agentd_boot_id,
                self.agentd_identity,
                self.agentd_peer_identity_digest,
                durable_run_id,
                material,
                now,
            )
            .map_err(map_vault_error)
    }

    fn authorize_release(
        &mut self,
        pending: savana_vault::PendingVaultReleaseV2,
        approval: savana_vault::VerifiedFinalReleaseApprovalV2,
        now: UnixMillisV2,
    ) -> Result<savana_vault::AuthorizedVaultReleaseV2, StableCode> {
        self.vault
            .authorize_release(pending, approval, now)
            .map_err(map_vault_error)
    }

    fn mark_release_dispatch_prepared(
        &mut self,
        authorized: savana_vault::AuthorizedVaultReleaseV2,
        commit: savana_vault::KernelPreparedReleaseDispatchV2,
        now: UnixMillisV2,
    ) -> Result<savana_vault::VaultDispatchPreparedV2, StableCode> {
        self.vault
            .mark_dispatch_prepared(authorized, commit, now)
            .map_err(map_vault_error)
    }

    fn mark_release_dispatching(
        &mut self,
        prepared: savana_vault::VaultDispatchPreparedV2,
        now: UnixMillisV2,
    ) -> Result<(), StableCode> {
        self.vault
            .mark_dispatching(prepared, now)
            .map_err(map_vault_error)
    }

    fn commit_known_release(
        &mut self,
        prepared: savana_vault::VaultDispatchPreparedV2,
        final_release_receipt_digest: Digest32V2,
        release_audit_digest: Digest32V2,
        now: UnixMillisV2,
    ) -> Result<(), StableCode> {
        self.vault
            .commit_known_release(
                prepared,
                final_release_receipt_digest,
                release_audit_digest,
                now,
            )
            .map_err(map_vault_error)
    }

    fn mark_release_failed_no_effect(
        &mut self,
        durable_release_id: savana_kernel_protocol::v2::DurableReleaseIdV2,
        execution_nonce: savana_kernel_protocol::v2::Nonce32V2,
        dispatch_core_digest: Digest32V2,
        dispatch_subject_digest: Digest32V2,
        now: UnixMillisV2,
    ) -> Result<(), StableCode> {
        self.vault
            .mark_failed_no_effect_by_identity(
                durable_release_id,
                execution_nonce,
                dispatch_core_digest,
                dispatch_subject_digest,
                now,
            )
            .map_err(map_vault_error)
    }

    fn mark_release_indeterminate(
        &mut self,
        prepared: savana_vault::VaultDispatchPreparedV2,
        now: UnixMillisV2,
    ) -> Result<(), StableCode> {
        self.vault
            .mark_indeterminate(prepared, now)
            .map_err(map_vault_error)
    }

    fn commit_tool_result(
        &mut self,
        durable_task_id: DurableTaskIdV2,
        durable_run_id: DurableRunIdV2,
        principal: PrincipalIdV2,
        provenance: savana_policy_core::v2::ProvenanceRecordV2,
        executor_commit_digest: Digest32V2,
        result: Vec<u8>,
        expires_at: UnixMillisV2,
        now: UnixMillisV2,
    ) -> Result<MaskedDocumentHandleV2, StableCode> {
        let ingress = savana_vault::VaultIngressMaterialV2::from_verified_gated_input(
            durable_task_id,
            durable_run_id,
            principal,
            savana_policy_core::v2::provenance_digest_v2(&provenance)
                .map_err(|_| StableCode::PolicyDenied)?,
            executor_commit_digest,
            expires_at,
            result,
        )
        .map_err(map_vault_error)?;
        let pending = self
            .vault
            .create_pending_ingress(ingress, now)
            .map_err(map_vault_error)?;
        let live = self
            .vault
            .commit_ingress(pending, now)
            .map_err(map_vault_error)?;
        let context = savana_vault::VaultAccessContextV2::from_authenticated_agent(
            self.agentd_boot_id,
            self.agentd_identity,
            self.agentd_peer_identity_digest,
            durable_run_id,
            expires_at,
        )
        .map_err(map_vault_error)?;
        self.vault
            .issue_masked_document(&live, context, now)
            .map_err(map_vault_error)
    }
}

pub(crate) fn decode_persisted_agent_view(
    material: &[u8],
) -> Result<ReadAgentViewResponseV2, StableCode> {
    let mut cursor = 0_usize;
    let mut response = None;
    while cursor < material.len() {
        let header_end = cursor
            .checked_add(10)
            .filter(|end| *end <= material.len())
            .ok_or(StableCode::KernelUnavailable)?;
        let tag = u16::from_be_bytes(
            material[cursor..cursor + 2]
                .try_into()
                .map_err(|_| StableCode::KernelUnavailable)?,
        );
        let length = u64::from_be_bytes(
            material[cursor + 2..header_end]
                .try_into()
                .map_err(|_| StableCode::KernelUnavailable)?,
        );
        let length = usize::try_from(length).map_err(|_| StableCode::KernelUnavailable)?;
        let record_end = header_end
            .checked_add(length)
            .filter(|end| *end <= material.len())
            .ok_or(StableCode::KernelUnavailable)?;
        if tag == MASKED_AGENT_VIEW_RECORD_TAG_V2 {
            if response.is_some() {
                return Err(StableCode::KernelUnavailable);
            }
            response = Some(
                decode_read_agent_view_response_v2(&material[header_end..record_end])
                    .map_err(|_| StableCode::KernelUnavailable)?,
            );
        }
        cursor = record_end;
    }
    response.ok_or(StableCode::KernelUnavailable)
}

fn map_vault_error(error: savana_vault::VaultErrorV2) -> StableCode {
    match error {
        savana_vault::VaultErrorV2::InvalidCapability
        | savana_vault::VaultErrorV2::InvalidInput => StableCode::HandleUnknown,
        savana_vault::VaultErrorV2::Expired => StableCode::PolicyExpired,
        savana_vault::VaultErrorV2::TerminalState => StableCode::HandleAlreadyConsumed,
        savana_vault::VaultErrorV2::AllocationFailure => StableCode::KernelOverloaded,
        savana_vault::VaultErrorV2::StateConflict => StableCode::PolicyDenied,
        savana_vault::VaultErrorV2::ClockRollback
        | savana_vault::VaultErrorV2::DurableState
        | savana_vault::VaultErrorV2::DurableAuthentication
        | savana_vault::VaultErrorV2::RollbackDetected
        | savana_vault::VaultErrorV2::CommitUncertain
        | savana_vault::VaultErrorV2::InvalidApproval => StableCode::KernelUnavailable,
    }
}

fn durable_run_id(
    installation_id: Digest32V2,
    active_state_manifest_digest: Digest32V2,
    durable_task_id: DurableTaskIdV2,
    principal: PrincipalIdV2,
    input_commitment: Digest32V2,
) -> Result<DurableRunIdV2, StableCode> {
    let mut hasher = Sha256::new();
    hasher.update(DURABLE_RUN_DOMAIN_V2);
    for value in [
        installation_id.as_bytes().as_slice(),
        active_state_manifest_digest.as_bytes().as_slice(),
        durable_task_id.as_bytes().as_slice(),
        principal.as_bytes().as_slice(),
        input_commitment.as_bytes().as_slice(),
    ] {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value);
    }
    let digest: [u8; 32] = hasher.finalize().into();
    if digest == [0; 32] {
        return Err(StableCode::KernelUnavailable);
    }
    Ok(DurableRunIdV2::new(digest))
}
