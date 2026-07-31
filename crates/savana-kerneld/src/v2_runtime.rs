use ed25519_dalek::{Signer as _, SigningKey};
use minicbor::Encode as _;
use savana_kernel_protocol::v2::{
    derive_ed25519_key_id_v2, encode_read_agent_view_response_v2, AgentViewV2, BoundedAgentTextV2,
    ClosedRedactionClassV2, Digest32V2, Ed25519KeyIdV2, Ed25519SignatureV2, PlaceholderViewV2,
    ReadAgentViewResponseV2, UnixMillisV2,
};
use savana_policy_core::v2::{DispatchSubjectV2, KernelPreparedDispatchV2};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::v2_input_owner::FinalizedKernelInputV2;
use crate::DaemonError;

const SEALED_EXECUTION_ENVELOPE_DOMAIN: &[u8] = b"SAVANA_SEALED_EXECUTION_ENVELOPE_V2\0";
const MASKED_AGENT_VIEW_RECORD_TAG_V2: u16 = 0;
const MAX_AGENT_VIEW_RESPONSE_BYTES_V2: usize = 8 * 1024 * 1024;

pub(crate) struct KernelTaskSigningIdentityV2 {
    key_id: Ed25519KeyIdV2,
    signing_key: SigningKey,
}

impl std::fmt::Debug for KernelTaskSigningIdentityV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("KernelTaskSigningIdentityV2(<redacted>)")
    }
}

impl KernelTaskSigningIdentityV2 {
    pub(crate) fn from_seed(key_id: Ed25519KeyIdV2, seed: [u8; 32]) -> Result<Self, DaemonError> {
        let seed = Zeroizing::new(seed);
        if is_zero(key_id.as_bytes()) || is_zero(seed.as_ref()) {
            return Err(v2_runtime_error());
        }
        let signing_key = SigningKey::from_bytes(&seed);
        if derive_ed25519_key_id_v2(signing_key.verifying_key().to_bytes()) != key_id {
            return Err(v2_runtime_error());
        }
        Ok(Self {
            key_id,
            signing_key,
        })
    }

    pub(crate) fn public_key(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    pub(crate) fn sign_statement(
        &self,
        statement: savana_agentd::KernelTaskStatementV2,
    ) -> Result<savana_agentd::SignedKernelTaskStatementV2, DaemonError> {
        let signing_bytes = statement.signing_bytes().map_err(|_| v2_runtime_error())?;
        let signature = self.signing_key.sign(&signing_bytes).to_bytes();
        savana_agentd::SignedKernelTaskStatementV2::from_kernel_signature(
            statement,
            self.key_id,
            Ed25519SignatureV2::new(signature),
        )
        .map_err(|_| v2_runtime_error())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum KernelIngressPipelineErrorV2 {
    #[error("ingress transfer does not match the active kernel deployment")]
    DeploymentBinding,
    #[error("ingress content is not valid UTF-8")]
    InvalidText,
    #[error("G1/G2 rejected the ingress content")]
    InputGate,
    #[error("G3 rejected the ingress provenance")]
    Provenance,
    #[error("the durable vault rejected the ingress mutation")]
    Vault,
}

pub(crate) struct AcceptedKernelIngressV2 {
    gated_input: savana_input_runtime::GatedPlannerInputV2,
    provenance: savana_policy_core::v2::ProvenanceRecordV2,
    live_vault_segment: savana_vault::LiveVaultSegmentV2,
}

impl std::fmt::Debug for AcceptedKernelIngressV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AcceptedKernelIngressV2")
            .field("input_commitment", &self.gated_input.input_commitment())
            .field("provenance_digest", &self.provenance.provenance_digest())
            .finish_non_exhaustive()
    }
}

impl AcceptedKernelIngressV2 {
    pub(crate) const fn gated_input(&self) -> &savana_input_runtime::GatedPlannerInputV2 {
        &self.gated_input
    }

    pub(crate) const fn provenance(&self) -> &savana_policy_core::v2::ProvenanceRecordV2 {
        &self.provenance
    }

    pub(crate) const fn live_vault_segment(&self) -> &savana_vault::LiveVaultSegmentV2 {
        &self.live_vault_segment
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        savana_input_runtime::GatedPlannerInputV2,
        savana_policy_core::v2::ProvenanceRecordV2,
        savana_vault::LiveVaultSegmentV2,
    ) {
        (self.gated_input, self.provenance, self.live_vault_segment)
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn accept_ingress_into_kernel(
    input_runtime: &savana_input_runtime::InputRuntimeV2,
    vault: &mut savana_vault::DurableVaultServiceV2,
    transfer: savana_ingressd::IngressKernelTransferV2,
    expected_installation_id: Digest32V2,
    expected_active_state_manifest_digest: Digest32V2,
    producer_identity: savana_kernel_protocol::v2::ProducerIdentityV2,
    durable_task_id: savana_kernel_protocol::v2::DurableTaskIdV2,
    durable_run_id: savana_kernel_protocol::v2::DurableRunIdV2,
    policy_allowed_effects: savana_policy_core::v2::EffectSetV2,
    now: UnixMillisV2,
    expires_at: UnixMillisV2,
) -> Result<AcceptedKernelIngressV2, KernelIngressPipelineErrorV2> {
    if transfer.installation_id() != expected_installation_id
        || transfer.active_state_manifest_digest() != expected_active_state_manifest_digest
        || now.get() == 0
        || now.get() >= expires_at.get()
    {
        return Err(KernelIngressPipelineErrorV2::DeploymentBinding);
    }
    let channel = match transfer.content_kind() {
        savana_ingressd::ContentKindV2::ChatText => savana_input_runtime::InputChannelV2::ChatText,
        savana_ingressd::ContentKindV2::PlainText
        | savana_ingressd::ContentKindV2::ParsedDocument => {
            savana_input_runtime::InputChannelV2::OriginalSource
        }
    };
    let (ingress_evidence, original_bytes) = transfer.into_provenance_evidence_and_bytes();
    let principal = ingress_evidence.principal();
    let original_text = std::str::from_utf8(&original_bytes)
        .map_err(|_| KernelIngressPipelineErrorV2::InvalidText)?;
    let gated_input = input_runtime
        .process(channel, original_text, now)
        .map_err(|_| KernelIngressPipelineErrorV2::InputGate)?;
    let normalized_value =
        savana_policy_core::v2::KernelValueV2::text(gated_input.normalized_input())
            .map_err(|_| KernelIngressPipelineErrorV2::Provenance)?;
    let provenance_context =
        savana_policy_core::v2::ProvenanceContextV2::from_authenticated_runtime(
            producer_identity,
            durable_run_id,
            expected_active_state_manifest_digest,
            now,
            expires_at,
        )
        .map_err(|_| KernelIngressPipelineErrorV2::Provenance)?;
    let provenance = savana_policy_core::v2::ProvenanceRecordV2::from_verified_ingress_evidence(
        &normalized_value,
        provenance_context,
        ingress_evidence,
        policy_allowed_effects,
    )
    .map_err(|_| KernelIngressPipelineErrorV2::Provenance)?;
    let material = savana_vault::VaultIngressMaterialV2::from_verified_gated_input(
        durable_task_id,
        durable_run_id,
        principal,
        provenance.provenance_digest(),
        gated_input.input_commitment(),
        expires_at,
        original_bytes.to_vec(),
    )
    .map_err(|_| KernelIngressPipelineErrorV2::Vault)?;
    let live_vault_segment = vault
        .ingest_verified(material, now)
        .map_err(|_| KernelIngressPipelineErrorV2::Vault)?;
    Ok(AcceptedKernelIngressV2 {
        gated_input,
        provenance,
        live_vault_segment,
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn accept_finalized_input_into_kernel(
    input_runtime: &savana_input_runtime::InputRuntimeV2,
    vault: &mut savana_vault::DurableVaultServiceV2,
    finalized: &FinalizedKernelInputV2,
    expected_installation_id: Digest32V2,
    expected_active_state_manifest_digest: Digest32V2,
    expected_deployment_generation: u64,
    producer_identity: savana_kernel_protocol::v2::ProducerIdentityV2,
    durable_task_id: savana_kernel_protocol::v2::DurableTaskIdV2,
    durable_run_id: savana_kernel_protocol::v2::DurableRunIdV2,
    policy_allowed_effects: savana_policy_core::v2::EffectSetV2,
    now: UnixMillisV2,
    expires_at: UnixMillisV2,
) -> Result<AcceptedKernelIngressV2, KernelIngressPipelineErrorV2> {
    let authorization = finalized.authorization();
    if authorization.installation_id() != expected_installation_id
        || authorization.active_state_manifest_digest() != expected_active_state_manifest_digest
        || authorization.deployment_generation() != expected_deployment_generation
        || now.get() == 0
        || now.get() >= authorization.expires_at().get()
        || now.get() >= expires_at.get()
        || expires_at.get() > authorization.expires_at().get()
    {
        return Err(KernelIngressPipelineErrorV2::DeploymentBinding);
    }

    let channels = finalized.channels();
    let (runtime_channel, planner_bytes) = match channels {
        [channel] if channel.channel() == savana_kernel_protocol::v2::InputChannelV2::ChatText => (
            savana_input_runtime::InputChannelV2::ChatText,
            channel.bytes(),
        ),
        [channel]
            if channel.channel() == savana_kernel_protocol::v2::InputChannelV2::OriginalSource =>
        {
            (
                savana_input_runtime::InputChannelV2::OriginalSource,
                channel.bytes(),
            )
        }
        [original, extracted]
            if original.channel() == savana_kernel_protocol::v2::InputChannelV2::OriginalSource
                && extracted.channel()
                    == savana_kernel_protocol::v2::InputChannelV2::ExtractedPage =>
        {
            (
                savana_input_runtime::InputChannelV2::ExtractedPage,
                extracted.bytes(),
            )
        }
        _ => return Err(KernelIngressPipelineErrorV2::InputGate),
    };
    let planner_text = std::str::from_utf8(planner_bytes)
        .map_err(|_| KernelIngressPipelineErrorV2::InvalidText)?;
    let gated_input = input_runtime
        .process(runtime_channel, planner_text, now)
        .map_err(|_| KernelIngressPipelineErrorV2::InputGate)?;
    let normalized_value =
        savana_policy_core::v2::KernelValueV2::text(gated_input.normalized_input())
            .map_err(|_| KernelIngressPipelineErrorV2::Provenance)?;
    let provenance_context =
        savana_policy_core::v2::ProvenanceContextV2::from_authenticated_runtime(
            producer_identity,
            durable_run_id,
            expected_active_state_manifest_digest,
            now,
            expires_at,
        )
        .map_err(|_| KernelIngressPipelineErrorV2::Provenance)?;
    let provenance = savana_policy_core::v2::ProvenanceRecordV2::from_verified_kernel_input(
        &normalized_value,
        provenance_context,
        authorization.settlement_digest(),
        finalized.source_provenance_digest(),
        authorization.authentication_context_digest(),
        authorization.binding_digest(),
        policy_allowed_effects,
    )
    .map_err(|_| KernelIngressPipelineErrorV2::Provenance)?;

    let masked_agent_view = encode_masked_agent_view(&gated_input)?;
    let sensitive_bytes = encode_finalized_vault_material(channels, &masked_agent_view)?;
    let material = savana_vault::VaultIngressMaterialV2::from_verified_gated_input(
        durable_task_id,
        durable_run_id,
        authorization.authenticated_principal(),
        provenance.provenance_digest(),
        finalized.input_commitment(),
        expires_at,
        sensitive_bytes,
    )
    .map_err(|_| KernelIngressPipelineErrorV2::Vault)?;
    let live_vault_segment = vault
        .ingest_verified(material, now)
        .map_err(|_| KernelIngressPipelineErrorV2::Vault)?;
    Ok(AcceptedKernelIngressV2 {
        gated_input,
        provenance,
        live_vault_segment,
    })
}

fn encode_finalized_vault_material(
    channels: &[crate::v2_input_owner::FinalizedKernelInputChannelV2],
    masked_agent_view: &[u8],
) -> Result<Vec<u8>, KernelIngressPipelineErrorV2> {
    let mut payload_bytes = 10_usize
        .checked_add(masked_agent_view.len())
        .ok_or(KernelIngressPipelineErrorV2::Vault)?;
    for channel in channels {
        payload_bytes = payload_bytes
            .checked_add(10)
            .and_then(|value| value.checked_add(channel.bytes().len()))
            .ok_or(KernelIngressPipelineErrorV2::Vault)?;
    }
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(payload_bytes)
        .map_err(|_| KernelIngressPipelineErrorV2::Vault)?;
    encoded.extend_from_slice(&MASKED_AGENT_VIEW_RECORD_TAG_V2.to_be_bytes());
    encoded.extend_from_slice(&(masked_agent_view.len() as u64).to_be_bytes());
    encoded.extend_from_slice(masked_agent_view);
    for channel in channels {
        encoded.extend_from_slice(&channel.channel().tag().to_be_bytes());
        encoded.extend_from_slice(&(channel.bytes().len() as u64).to_be_bytes());
        encoded.extend_from_slice(channel.bytes());
    }
    Ok(encoded)
}

fn encode_masked_agent_view(
    gated_input: &savana_input_runtime::GatedPlannerInputV2,
) -> Result<Vec<u8>, KernelIngressPipelineErrorV2> {
    let masked = gated_input
        .masked_agent_input()
        .map_err(|_| KernelIngressPipelineErrorV2::InputGate)?;
    let text = BoundedAgentTextV2::new(masked.text().to_owned())
        .map_err(|_| KernelIngressPipelineErrorV2::InputGate)?;
    let placeholders = masked
        .placeholders()
        .iter()
        .enumerate()
        .map(|(ordinal, placeholder)| {
            let ordinal =
                u32::try_from(ordinal).map_err(|_| KernelIngressPipelineErrorV2::InputGate)?;
            let token = BoundedAgentTextV2::new(placeholder.token().to_owned())
                .map_err(|_| KernelIngressPipelineErrorV2::InputGate)?;
            let class = match placeholder.class() {
                savana_input_runtime::DetectionClassV2::PersonalData => {
                    ClosedRedactionClassV2::PersonalData
                }
                savana_input_runtime::DetectionClassV2::Credential => {
                    ClosedRedactionClassV2::Credential
                }
                // A path or filename that discloses protected content by its
                // name alone is neither a credential nor data about a person;
                // it is protected because policy says the reference itself is.
                savana_input_runtime::DetectionClassV2::ProtectedReference => {
                    ClosedRedactionClassV2::PolicyProtected
                }
            };
            PlaceholderViewV2::new(ordinal, token, class)
                .map_err(|_| KernelIngressPipelineErrorV2::InputGate)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let view = AgentViewV2::masked_text(text, placeholders)
        .map_err(|_| KernelIngressPipelineErrorV2::InputGate)?;
    let response = ReadAgentViewResponseV2::new(view, None);
    let encoded = encode_read_agent_view_response_v2(&response)
        .map_err(|_| KernelIngressPipelineErrorV2::InputGate)?;
    if encoded.len() > MAX_AGENT_VIEW_RESPONSE_BYTES_V2 {
        return Err(KernelIngressPipelineErrorV2::InputGate);
    }
    Ok(encoded)
}

pub(crate) struct KernelDispatchSigningIdentityV2 {
    key_id: Ed25519KeyIdV2,
    signing_key: SigningKey,
}

impl std::fmt::Debug for KernelDispatchSigningIdentityV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("KernelDispatchSigningIdentityV2(<redacted>)")
    }
}

impl KernelDispatchSigningIdentityV2 {
    pub(crate) fn from_seed(key_id: Ed25519KeyIdV2, seed: [u8; 32]) -> Result<Self, DaemonError> {
        let seed = Zeroizing::new(seed);
        if is_zero(key_id.as_bytes()) || is_zero(seed.as_ref()) {
            return Err(v2_runtime_error());
        }
        let signing_key = SigningKey::from_bytes(&seed);
        if derive_ed25519_key_id_v2(signing_key.verifying_key().to_bytes()) != key_id {
            return Err(v2_runtime_error());
        }
        Ok(Self {
            key_id,
            signing_key,
        })
    }

    pub(crate) fn public_key(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    pub(crate) fn sign_prepared_dispatch(
        &self,
        prepared: &KernelPreparedDispatchV2,
        issued_at: UnixMillisV2,
        effect_gate_lease_digest: Digest32V2,
        ledger_projection_digest: Digest32V2,
    ) -> Result<SignedKernelDispatchEnvelopeV2, DaemonError> {
        let core = prepared.core();
        if issued_at.get() == 0
            || issued_at.get() >= core.expires_at().get()
            || is_zero(effect_gate_lease_digest.as_bytes())
            || is_zero(ledger_projection_digest.as_bytes())
        {
            return Err(v2_runtime_error());
        }
        let kind_tag = match core.subject() {
            DispatchSubjectV2::ToolExecution { .. } => 1,
            DispatchSubjectV2::FinalRelease { .. } => 2,
        };
        let mut payload = minicbor::Encoder::new(Vec::new());
        payload
            .array(15)
            .and_then(|encoder| encoder.u16(2))
            .map_err(|_| v2_runtime_error())?;
        core.installation_id()
            .encode(&mut payload, &mut ())
            .map_err(|_| v2_runtime_error())?;
        core.active_state_manifest_digest()
            .encode(&mut payload, &mut ())
            .map_err(|_| v2_runtime_error())?;
        payload
            .u64(core.deployment_generation())
            .and_then(|encoder| encoder.u64(core.effect_fence_epoch()))
            .map_err(|_| v2_runtime_error())?;
        Digest32V2::new(*core.executor_identity().as_bytes())
            .encode(&mut payload, &mut ())
            .map_err(|_| v2_runtime_error())?;
        payload.u16(kind_tag).map_err(|_| v2_runtime_error())?;
        core.execution_nonce()
            .encode(&mut payload, &mut ())
            .map_err(|_| v2_runtime_error())?;
        prepared
            .preparation()
            .dispatch_core_digest()
            .encode(&mut payload, &mut ())
            .map_err(|_| v2_runtime_error())?;
        core.dispatch_subject_digest()
            .encode(&mut payload, &mut ())
            .map_err(|_| v2_runtime_error())?;
        prepared
            .sealed_envelope_digest()
            .encode(&mut payload, &mut ())
            .map_err(|_| v2_runtime_error())?;
        payload
            .u64(issued_at.get())
            .and_then(|encoder| encoder.u64(core.expires_at().get()))
            .map_err(|_| v2_runtime_error())?;
        effect_gate_lease_digest
            .encode(&mut payload, &mut ())
            .map_err(|_| v2_runtime_error())?;
        ledger_projection_digest
            .encode(&mut payload, &mut ())
            .map_err(|_| v2_runtime_error())?;

        let canonical_payload = payload.into_writer();
        let payload_digest: [u8; 32] = Sha256::digest(&canonical_payload).into();
        let mut signature_input =
            Vec::with_capacity(SEALED_EXECUTION_ENVELOPE_DOMAIN.len() + payload_digest.len());
        signature_input.extend_from_slice(SEALED_EXECUTION_ENVELOPE_DOMAIN);
        signature_input.extend_from_slice(&payload_digest);
        let signature = self.signing_key.sign(&signature_input).to_bytes();

        let mut envelope = minicbor::Encoder::new(Vec::new());
        envelope
            .array(3)
            .and_then(|encoder| encoder.bytes(&canonical_payload))
            .map_err(|_| v2_runtime_error())?;
        self.key_id
            .encode(&mut envelope, &mut ())
            .map_err(|_| v2_runtime_error())?;
        envelope.bytes(&signature).map_err(|_| v2_runtime_error())?;
        let canonical_bytes = envelope.into_writer();
        let envelope_digest = Digest32V2::new(Sha256::digest(&canonical_bytes).into());
        Ok(SignedKernelDispatchEnvelopeV2 {
            canonical_bytes,
            envelope_digest,
        })
    }
}

#[derive(Clone)]
pub(crate) struct SignedKernelDispatchEnvelopeV2 {
    canonical_bytes: Vec<u8>,
    envelope_digest: Digest32V2,
}

impl std::fmt::Debug for SignedKernelDispatchEnvelopeV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SignedKernelDispatchEnvelopeV2")
            .field("envelope_digest", &self.envelope_digest)
            .finish_non_exhaustive()
    }
}

impl SignedKernelDispatchEnvelopeV2 {
    pub(crate) fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub(crate) const fn envelope_digest(&self) -> Digest32V2 {
        self.envelope_digest
    }
}

pub(crate) fn prepare_vault_release_commit(
    prepared: &KernelPreparedDispatchV2,
) -> Result<savana_vault::KernelPreparedReleaseDispatchV2, DaemonError> {
    let binding = match prepared.core().subject() {
        DispatchSubjectV2::FinalRelease { binding, .. } => *binding,
        DispatchSubjectV2::ToolExecution { .. } => return Err(v2_runtime_error()),
    };
    savana_vault::KernelPreparedReleaseDispatchV2::from_verified_kernel_commit(
        binding,
        prepared.consumed_ticket_digest(),
        prepared.preparation().execution_nonce(),
        prepared.preparation().dispatch_core_digest(),
        prepared.preparation().dispatch_subject_digest(),
    )
    .map_err(|_| v2_runtime_error())
}

pub(crate) fn verify_tool_approval_settlement(
    settlement: savana_approvald::ConsumedApprovalSettlementV2,
    action_intent_id: savana_kernel_protocol::v2::ActionIntentIdV2,
    semantic_binding_digest: Digest32V2,
    active_state_manifest_digest: Digest32V2,
    now: UnixMillisV2,
) -> Result<savana_policy_core::v2::VerifiedToolApprovalSettlementV2, DaemonError> {
    let approval_binding_digest = savana_policy_core::v2::tool_approval_binding_digest_v2(
        action_intent_id,
        semantic_binding_digest,
        active_state_manifest_digest,
    )
    .map_err(|_| v2_runtime_error())?;
    if settlement.purpose() != savana_approvald::ApprovalPurposeV2::ToolExecution
        || settlement.binding_digest() != approval_binding_digest
        || settlement.expires_at().get() <= now.get()
    {
        return Err(v2_runtime_error());
    }
    savana_policy_core::v2::VerifiedToolApprovalSettlementV2::from_consumed_exact_settlement(
        settlement.settlement_digest(),
        action_intent_id,
        approval_binding_digest,
        active_state_manifest_digest,
    )
    .map_err(|_| v2_runtime_error())
}

pub(crate) fn verify_final_release_approval_settlement(
    settlement: savana_approvald::ConsumedApprovalSettlementV2,
    authorized_release: savana_vault::AuthorizedVaultReleaseV2,
    active_state_manifest_digest: Digest32V2,
    now: UnixMillisV2,
) -> Result<savana_policy_core::v2::VerifiedFinalReleaseSettlementV2, DaemonError> {
    let binding = authorized_release.binding();
    let binding_digest = binding.semantic_digest().ok_or_else(v2_runtime_error)?;
    if settlement.purpose() != savana_approvald::ApprovalPurposeV2::FinalRelease
        || settlement.binding_digest() != binding_digest
        || settlement.settlement_digest() != authorized_release.approval_settlement_digest()
        || authorized_release.binding_digest() != binding_digest
        || settlement.expires_at().get() <= now.get()
    {
        return Err(v2_runtime_error());
    }
    savana_policy_core::v2::VerifiedFinalReleaseSettlementV2::from_consumed_exact_settlement(
        settlement.settlement_digest(),
        binding.durable_release_id(),
        binding_digest,
        active_state_manifest_digest,
    )
    .map_err(|_| v2_runtime_error())
}

fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

fn v2_runtime_error() -> DaemonError {
    DaemonError::stable(savana_kernel_protocol::StableCode::KernelUnavailable)
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer as _, SigningKey};
    use minicbor::Encode as _;
    use sha2::{Digest as _, Sha256};
    use std::sync::{Arc, Mutex};

    use savana_agentd::{
        AgentTaskServiceV2, AuthenticatedJarvisControlV2, KernelTaskAuthorityVerifierV2,
        KernelTaskStatementV2, SignedKernelTaskStatementV2,
    };
    use savana_execd::{ExecdJournalStateV2, ExecdServiceV2, VerifiedExecdDeploymentV2};
    use savana_ingressd::{
        AuthenticatedKernelIngressReceiverV2, ContentKindV2, IngressBrowserContextV2,
        IngressServiceV2, VerifiedIngressUiAuthorizationV2,
    };
    use savana_input_runtime::{
        InputRuntimeV2, SignedInputRuntimeAssetsV2, VerifiedInputRuntimeAssetsV2,
    };
    use savana_kernel_protocol::v2::{
        derive_ed25519_key_id_v2, encode_signed_sealed_execution_envelope_v2, ActionTemplateIdV2,
        AgentViewV2, BootIdV2, BoundedCiphertextV2, Digest32V2, DurableReleaseIdV2, DurableRunIdV2,
        DurableTaskIdV2, Ed25519KeyIdV2, ExecutorIdentityV2, FinalReleaseSemanticBindingV2,
        FixedBytes32V2, HpkeX25519KeyIdV2, IngressUiAuthorizationHandleV2,
        InputChannelCommitmentV2, InputSourceKindV2, InputSourceProvenanceV2, Nonce32V2,
        PlannerRouteIdV2, PrincipalIdV2, ProducerIdentityV2, SealedExecutionEnvelopePayloadV2,
        ServiceIdentityV2, SignedSealedExecutionEnvelopeV2, UnixMillisV2, VersionV2,
        ZeroizingBytesV2,
    };
    use savana_policy_core::v2::{
        DispatchQuotaSubjectV2, DurableG4StateV2, DurableStateNamespaceV2, KernelDispatchStateV2,
        ResolvedFinalReleaseTicketV2, RollbackProtectedStateAnchorV2, RollbackProtectedStateHeadV2,
        VerifiedEffectGateLeaseV2, VerifiedFinalReleaseRecordV2, VerifiedFinalReleaseSettlementV2,
        VerifiedQuotaLimitV2,
    };
    use savana_vault::{
        DurableVaultNamespaceV2, DurableVaultServiceV2, VaultAccessContextV2, VaultErrorV2,
        VaultRollbackAnchorV2, VaultServiceV2, VaultStateHeadV2,
    };

    use super::{
        accept_finalized_input_into_kernel, accept_ingress_into_kernel,
        prepare_vault_release_commit, KernelDispatchSigningIdentityV2, KernelTaskSigningIdentityV2,
    };
    use crate::v2_input_owner::{KernelInputOwnerV2, KernelVerifiedUiAuthorizationV2};

    #[derive(Clone)]
    struct MemoryAnchor(Arc<Mutex<RollbackProtectedStateHeadV2>>);

    impl MemoryAnchor {
        fn new() -> Self {
            Self(Arc::new(Mutex::new(
                RollbackProtectedStateHeadV2::new(0, Digest32V2::new([0; 32])).unwrap(),
            )))
        }
    }

    impl RollbackProtectedStateAnchorV2 for MemoryAnchor {
        fn current_head(
            &self,
        ) -> Result<RollbackProtectedStateHeadV2, savana_policy_core::v2::G4Error> {
            self.0
                .lock()
                .map(|head| *head)
                .map_err(|_| savana_policy_core::v2::G4Error::DurableStateIo)
        }

        fn compare_and_advance(
            &mut self,
            expected: RollbackProtectedStateHeadV2,
            next: RollbackProtectedStateHeadV2,
        ) -> Result<(), savana_policy_core::v2::G4Error> {
            let mut head = self
                .0
                .lock()
                .map_err(|_| savana_policy_core::v2::G4Error::DurableStateIo)?;
            if *head != expected {
                return Err(savana_policy_core::v2::G4Error::DurableStateRollback);
            }
            *head = next;
            Ok(())
        }
    }

    #[derive(Clone)]
    struct VaultMemoryAnchor(Arc<Mutex<VaultStateHeadV2>>);

    impl VaultMemoryAnchor {
        fn new() -> Self {
            Self(Arc::new(Mutex::new(
                VaultStateHeadV2::new(0, Digest32V2::new([0; 32])).unwrap(),
            )))
        }
    }

    impl VaultRollbackAnchorV2 for VaultMemoryAnchor {
        fn current_head(&self) -> Result<VaultStateHeadV2, VaultErrorV2> {
            self.0
                .lock()
                .map(|head| *head)
                .map_err(|_| VaultErrorV2::DurableState)
        }

        fn compare_and_advance(
            &mut self,
            expected: VaultStateHeadV2,
            next: VaultStateHeadV2,
        ) -> Result<(), VaultErrorV2> {
            let mut head = self.0.lock().map_err(|_| VaultErrorV2::DurableState)?;
            if *head != expected {
                return Err(VaultErrorV2::RollbackDetected);
            }
            *head = next;
            Ok(())
        }
    }

    fn input_runtime() -> InputRuntimeV2 {
        const ASSET_DIGEST_DOMAIN: &[u8] = b"SAVANA_INPUT_RUNTIME_ASSET_V2\0";
        const ASSET_SIGNATURE_DOMAIN: &[u8] = b"SAVANA_INPUT_RUNTIME_ASSET_SIGNATURE_V2\0";

        let mut payload = minicbor::Encoder::new(Vec::new());
        payload
            .array(7)
            .unwrap()
            .u16(2)
            .unwrap()
            .u64(10)
            .unwrap()
            .u64(10_000)
            .unwrap();
        PlannerRouteIdV2::new(7)
            .encode(&mut payload, &mut ())
            .unwrap();
        payload
            .array(6)
            .unwrap()
            .u32(4096)
            .unwrap()
            .u16(32)
            .unwrap()
            .u16(8)
            .unwrap()
            .u16(8)
            .unwrap()
            .u16(8)
            .unwrap()
            .u32(65_536)
            .unwrap()
            .array(0)
            .unwrap()
            .array(1)
            .unwrap()
            .array(6)
            .unwrap()
            .u32(1)
            .unwrap()
            .str("send")
            .unwrap()
            .u16(1)
            .unwrap()
            .u32(11)
            .unwrap()
            .array(1)
            .unwrap();
        ActionTemplateIdV2::new(21)
            .encode(&mut payload, &mut ())
            .unwrap();
        payload.null().unwrap();
        let payload = payload.into_writer();
        let signing_key = SigningKey::from_bytes(&[0x31; 32]);
        let key_id = Ed25519KeyIdV2::new([0x32; 32]);
        let mut digest_hasher = Sha256::new();
        digest_hasher.update(ASSET_DIGEST_DOMAIN);
        digest_hasher.update(&payload);
        let digest: [u8; 32] = digest_hasher.finalize().into();
        let mut signature_input = Vec::from(ASSET_SIGNATURE_DOMAIN);
        signature_input.extend_from_slice(&digest);
        let signature = signing_key.sign(&signature_input).to_bytes();
        let mut signed = minicbor::Encoder::new(Vec::new());
        signed.array(3).unwrap().bytes(&payload).unwrap();
        key_id.encode(&mut signed, &mut ()).unwrap();
        signed.bytes(&signature).unwrap();
        let signed =
            SignedInputRuntimeAssetsV2::from_canonical_bytes(&signed.into_writer()).unwrap();
        InputRuntimeV2::new(
            VerifiedInputRuntimeAssetsV2::verify(
                &signed,
                key_id,
                signing_key.verifying_key().to_bytes(),
                UnixMillisV2::new(20),
            )
            .unwrap(),
        )
    }

    #[test]
    fn ingress_g1_g2_g3_and_vault_are_one_rust_owned_pipeline() {
        let installation = Digest32V2::new([0x41; 32]);
        let manifest = Digest32V2::new([0x42; 32]);
        let ingress_boot = BootIdV2::new([0x43; 32]);
        let kernel_boot = BootIdV2::new([0x44; 32]);
        let ingress_identity = ServiceIdentityV2::new([0x45; 32]);
        let kernel_identity = ServiceIdentityV2::new([0x46; 32]);
        let browser_context = IngressBrowserContextV2::from_authenticated_origin(
            ingress_boot,
            Digest32V2::new([0x47; 32]),
            UnixMillisV2::new(500),
        )
        .unwrap();
        let mut ingress = IngressServiceV2::from_verified_deployment(
            installation,
            manifest,
            ingress_boot,
            ingress_identity,
            kernel_boot,
            kernel_identity,
            8,
            4096,
        )
        .unwrap();
        let tab = ingress
            .open_authenticated_tab(
                VerifiedIngressUiAuthorizationV2::from_verified_ui_settlement(
                    PrincipalIdV2::new([0x48; 32]),
                    Digest32V2::new([0x49; 32]),
                    Digest32V2::new([0x4a; 32]),
                    UnixMillisV2::new(500),
                )
                .unwrap(),
                browser_context,
                UnixMillisV2::new(30),
            )
            .unwrap();
        let content = b"send to alice@example.com".to_vec();
        let content_digest = Digest32V2::new(Sha256::digest(&content).into());
        ingress
            .begin(
                &tab,
                browser_context,
                Nonce32V2::new([0x4b; 32]),
                ContentKindV2::ChatText,
                content.len() as u64,
                Some(content_digest),
                UnixMillisV2::new(31),
            )
            .unwrap();
        ingress
            .append(
                &tab,
                browser_context,
                Nonce32V2::new([0x4c; 32]),
                0,
                content,
                UnixMillisV2::new(32),
            )
            .unwrap();
        let finalized = ingress
            .finalize(
                &tab,
                browser_context,
                Nonce32V2::new([0x4d; 32]),
                content_digest,
                UnixMillisV2::new(33),
            )
            .unwrap();
        let transfer = ingress
            .consume_for_kernel(
                finalized,
                AuthenticatedKernelIngressReceiverV2::from_mutual_authentication(
                    kernel_boot,
                    kernel_identity,
                    UnixMillisV2::new(500),
                )
                .unwrap(),
                UnixMillisV2::new(34),
            )
            .unwrap();

        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(
            directory.path(),
            <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700),
        )
        .unwrap();
        let vault_path = directory.path().join("vault-state-v2.cbor");
        let vault_deployment =
            VaultServiceV2::from_verified_deployment(installation, manifest, kernel_boot, 8)
                .unwrap();
        let mut vault = DurableVaultServiceV2::open(
            &vault_path,
            [0x4e; 32],
            DurableVaultNamespaceV2::from_verified_installation(
                installation,
                Digest32V2::new([0x4f; 32]),
            )
            .unwrap(),
            Box::new(VaultMemoryAnchor::new()),
            vault_deployment,
        )
        .unwrap();
        let accepted = accept_ingress_into_kernel(
            &input_runtime(),
            &mut vault,
            transfer,
            installation,
            manifest,
            ProducerIdentityV2::new([0x50; 32]),
            DurableTaskIdV2::new([0x51; 32]),
            DurableRunIdV2::new([0x52; 32]),
            savana_policy_core::v2::EffectSetV2::SEND,
            UnixMillisV2::new(35),
            UnixMillisV2::new(500),
        )
        .unwrap();

        assert_eq!(accepted.gated_input().protected_values().len(), 1);
        assert_eq!(accepted.provenance().root_evidence().as_slice().len(), 3);
        assert!(format!("{:?}", accepted.live_vault_segment()).contains("<opaque>"));
        assert_eq!(vault.segment_count(), 1);
        let encrypted = std::fs::read(vault_path).unwrap();
        assert!(!encrypted
            .windows(b"alice@example.com".len())
            .any(|window| window == b"alice@example.com"));
    }

    #[test]
    fn finalized_kernel_owned_input_flows_through_g1_g2_g3_and_vault() {
        let installation = Digest32V2::new([0x30; 32]);
        let manifest = Digest32V2::new([0x35; 32]);
        let content = b"send to alice@example.com".to_vec();
        let content_digest = Digest32V2::new(Sha256::digest(&content).into());
        let mut input_owner = KernelInputOwnerV2::new(4, 4096).unwrap();
        let ui_authorization =
            IngressUiAuthorizationHandleV2::from_authority_entropy([0x61; 32]).unwrap();
        input_owner
            .register_verified_ui_authorization(
                ui_authorization,
                KernelVerifiedUiAuthorizationV2::for_test(),
            )
            .unwrap();
        let begun = input_owner
            .begin(
                savana_kernel_protocol::v2::BeginInputRequestV2::new(
                    ui_authorization,
                    savana_kernel_protocol::v2::ContentKindV2::ChatText,
                    content.len() as u64,
                    Some(content_digest),
                )
                .unwrap(),
                manifest,
                7,
                UnixMillisV2::new(30),
            )
            .unwrap();
        let prior = begun.channels()[0].cumulative_digest();
        let chunk_digest = savana_kernel_protocol::v2::input_chunk_digest_v2(
            begun.session(),
            savana_kernel_protocol::v2::InputChannelV2::ChatText,
            0,
            &content,
        )
        .unwrap();
        let resulting =
            savana_kernel_protocol::v2::input_channel_step_digest_v2(prior, 0, chunk_digest)
                .unwrap();
        let ack = input_owner
            .append(
                savana_kernel_protocol::v2::AppendInputChunkRequestV2::new(
                    begun.writer(),
                    savana_kernel_protocol::v2::DirectInputChannelV2::ChatText,
                    0,
                    prior,
                    ZeroizingBytesV2::new(content.clone()).unwrap(),
                    chunk_digest,
                    resulting,
                )
                .unwrap(),
            )
            .unwrap();
        let finalized = input_owner
            .finalize(
                savana_kernel_protocol::v2::FinalizeInputRequestV2::new(
                    begun.session(),
                    vec![InputChannelCommitmentV2::new(
                        savana_kernel_protocol::v2::InputChannelV2::ChatText,
                        1,
                        0,
                        content.len() as u64,
                        ack.cumulative_digest(),
                    )
                    .unwrap()],
                    InputSourceProvenanceV2::direct(
                        InputSourceKindV2::Chat,
                        content.len() as u64,
                        content_digest,
                        VersionV2::new(1, 0, 0),
                    )
                    .unwrap(),
                )
                .unwrap(),
            )
            .unwrap();

        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(
            directory.path(),
            <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700),
        )
        .unwrap();
        let vault_path = directory.path().join("vault-state-v2.cbor");
        let mut vault = DurableVaultServiceV2::open(
            &vault_path,
            [0x62; 32],
            DurableVaultNamespaceV2::from_verified_installation(
                installation,
                Digest32V2::new([0x63; 32]),
            )
            .unwrap(),
            Box::new(VaultMemoryAnchor::new()),
            VaultServiceV2::from_verified_deployment(
                installation,
                manifest,
                BootIdV2::new([0x64; 32]),
                8,
            )
            .unwrap(),
        )
        .unwrap();

        let accepted = accept_finalized_input_into_kernel(
            &input_runtime(),
            &mut vault,
            &finalized,
            installation,
            manifest,
            7,
            ProducerIdentityV2::new([0x65; 32]),
            DurableTaskIdV2::new([0x66; 32]),
            DurableRunIdV2::new([0x67; 32]),
            savana_policy_core::v2::EffectSetV2::SEND,
            UnixMillisV2::new(35),
            UnixMillisV2::new(400),
        )
        .unwrap();

        assert_eq!(accepted.gated_input().protected_values().len(), 1);
        assert_eq!(accepted.provenance().root_evidence().as_slice().len(), 4);
        assert_eq!(vault.segment_count(), 1);
        let agent_context = VaultAccessContextV2::from_authenticated_agent(
            BootIdV2::new([0x64; 32]),
            ServiceIdentityV2::new([0x68; 32]),
            Digest32V2::new([0x69; 32]),
            DurableRunIdV2::new([0x67; 32]),
            UnixMillisV2::new(400),
        )
        .unwrap();
        let document = vault
            .issue_masked_document(
                accepted.live_vault_segment(),
                agent_context,
                UnixMillisV2::new(36),
            )
            .unwrap();
        let material = vault
            .read_agent_bytes(&document, agent_context, UnixMillisV2::new(37))
            .unwrap();
        let response = crate::v2_data_plane::decode_persisted_agent_view(&material).unwrap();
        match response.view() {
            AgentViewV2::MaskedText { text, placeholders } => {
                assert!(!text.as_str().contains("alice@example.com"));
                assert_eq!(placeholders.len(), 1);
                assert!(text.as_str().contains(placeholders[0].token().as_str()));
            }
            other => panic!("unexpected agent view: {other:?}"),
        }
        let encrypted = std::fs::read(vault_path).unwrap();
        assert!(!encrypted
            .windows(b"alice@example.com".len())
            .any(|window| window == b"alice@example.com"));
    }

    #[test]
    fn final_release_crosses_policy_execd_and_vault_with_one_exact_binding() {
        let installation = Digest32V2::new([0x11; 32]);
        let manifest = Digest32V2::new([0x12; 32]);
        let executor = ExecutorIdentityV2::new([0x13; 32]);
        let envelope_seed = [0x16; 32];
        let receipt_seed = [0x17; 32];
        let envelope_key_id = derive_ed25519_key_id_v2(
            SigningKey::from_bytes(&envelope_seed)
                .verifying_key()
                .to_bytes(),
        );
        let receipt_key_id = derive_ed25519_key_id_v2(
            SigningKey::from_bytes(&receipt_seed)
                .verifying_key()
                .to_bytes(),
        );
        let release_id = DurableReleaseIdV2::new([0x18; 32]);
        let binding = FinalReleaseSemanticBindingV2::from_nonzero_components(
            release_id,
            Digest32V2::new([0x19; 32]),
            Digest32V2::new([0x1a; 32]),
            Digest32V2::new([0x1b; 32]),
            Digest32V2::new([0x1c; 32]),
            Digest32V2::new([0x1d; 32]),
            Digest32V2::new([0x1e; 32]),
            Digest32V2::new([0x1f; 32]),
            Digest32V2::new([0x20; 32]),
            Digest32V2::new(*executor.as_bytes()),
            Digest32V2::new([0x21; 32]),
        )
        .unwrap();
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(
            directory.path(),
            <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700),
        )
        .unwrap();
        let path = directory.path().join("kernel-g4-state-v2.cbor");
        let namespace = DurableStateNamespaceV2::from_verified_installation(
            installation,
            Digest32V2::new([0x22; 32]),
        )
        .unwrap();
        let mut policy =
            DurableG4StateV2::open(&path, [0x23; 32], namespace, Box::new(MemoryAnchor::new()))
                .unwrap();
        let release = VerifiedFinalReleaseRecordV2::from_authorized_vault_release(
            installation,
            manifest,
            DurableTaskIdV2::new([0x24; 32]),
            DurableRunIdV2::new([0x25; 32]),
            release_id,
            binding,
        )
        .unwrap();
        let prepared = policy
            .prepare_verified_final_release_dispatch(
                &release,
                VerifiedQuotaLimitV2::from_verified_policy(
                    1,
                    Digest32V2::new([0x26; 32]),
                    DispatchQuotaSubjectV2::final_release(binding.release_quota_subject_digest()),
                )
                .unwrap(),
                VerifiedFinalReleaseSettlementV2::from_consumed_exact_settlement(
                    Digest32V2::new([0x27; 32]),
                    release_id,
                    binding.semantic_digest().unwrap(),
                    manifest,
                )
                .unwrap(),
                ResolvedFinalReleaseTicketV2::from_resolved_kernel_ticket(
                    Digest32V2::new([0x28; 32]),
                    release_id,
                    binding.semantic_digest().unwrap(),
                )
                .unwrap(),
                VerifiedEffectGateLeaseV2::from_authenticated_ledger(
                    installation,
                    manifest,
                    7,
                    9,
                    false,
                    executor,
                    HpkeX25519KeyIdV2::new([0x29; 32]),
                    Digest32V2::new([0x2a; 32]),
                    UnixMillisV2::new(10_000),
                )
                .unwrap(),
                Digest32V2::new([0x2b; 32]),
            )
            .unwrap();

        let envelope_signing_key = SigningKey::from_bytes(&envelope_seed);
        let protocol_core = crate::v2_agent_authority::protocol_dispatch_core(&prepared).unwrap();
        assert_eq!(
            protocol_core.semantic_digest().unwrap(),
            prepared.preparation().dispatch_core_digest()
        );
        let signed = SignedSealedExecutionEnvelopeV2::sign(
            SealedExecutionEnvelopePayloadV2::new(
                protocol_core,
                FixedBytes32V2::new([0x2c; 32]),
                BoundedCiphertextV2::new(vec![0x2d; 64]).unwrap(),
            )
            .unwrap(),
            &envelope_signing_key,
        )
        .unwrap();
        let signed = encode_signed_sealed_execution_envelope_v2(&signed).unwrap();

        let deployment = VerifiedExecdDeploymentV2::from_verified_manifest(
            installation,
            manifest,
            7,
            9,
            Digest32V2::new(*executor.as_bytes()),
            envelope_key_id,
            envelope_signing_key.verifying_key().to_bytes(),
            receipt_key_id,
            receipt_seed,
        )
        .unwrap();
        let mut execd = ExecdServiceV2::new(deployment);
        let accepted = execd
            .accept_signed_dispatch(&signed, UnixMillisV2::new(101))
            .unwrap();
        assert_eq!(accepted.state(), ExecdJournalStateV2::Prepared);
        assert_eq!(
            accepted.dispatch_core_digest(),
            prepared.preparation().dispatch_core_digest()
        );

        let predecessor = execd
            .prepare_provider_attempt(
                prepared.preparation().execution_nonce(),
                Digest32V2::new([0x2e; 32]),
                UnixMillisV2::new(102),
            )
            .unwrap();
        let armed = execd
            .record_effect_started(predecessor, UnixMillisV2::new(103))
            .unwrap();
        let state = policy
            .reconcile_typed_effect_started_final_release_dispatch(
                armed.receipt(),
                receipt_key_id,
                ed25519_dalek::SigningKey::from_bytes(&receipt_seed)
                    .verifying_key()
                    .to_bytes(),
                UnixMillisV2::new(104),
            )
            .unwrap();
        assert_eq!(state, KernelDispatchStateV2::EffectStarted);

        let vault_commit = prepare_vault_release_commit(&prepared).unwrap();
        assert_eq!(
            vault_commit,
            savana_vault::KernelPreparedReleaseDispatchV2::from_verified_kernel_commit(
                binding,
                prepared.consumed_ticket_digest(),
                prepared.preparation().execution_nonce(),
                prepared.preparation().dispatch_core_digest(),
                prepared.preparation().dispatch_subject_digest(),
            )
            .unwrap()
        );
    }

    #[test]
    fn kernel_signed_task_correlation_is_the_only_agentd_preparation_path() {
        let installation = Digest32V2::new([0x41; 32]);
        let manifest = Digest32V2::new([0x42; 32]);
        let protocol_abi = Digest32V2::new([0x43; 32]);
        let agentd_identity = ServiceIdentityV2::new([0x44; 32]);
        let machine_boot = BootIdV2::new([0x45; 32]);
        let client_boot = BootIdV2::new([0x46; 32]);
        let agentd_boot = BootIdV2::new([0x47; 32]);
        let kerneld_boot = BootIdV2::new([0x48; 32]);
        let task_seed = [0x4a; 32];
        let key_id = derive_ed25519_key_id_v2(
            SigningKey::from_bytes(&task_seed)
                .verifying_key()
                .to_bytes(),
        );
        let signer = KernelTaskSigningIdentityV2::from_seed(key_id, task_seed).unwrap();
        let verifier = KernelTaskAuthorityVerifierV2::from_verified_deployment(
            installation,
            manifest,
            5,
            protocol_abi,
            agentd_identity,
            agentd_boot,
            kerneld_boot,
            key_id,
            signer.public_key(),
        )
        .unwrap();
        let context = AuthenticatedJarvisControlV2::from_mutual_authentication(
            installation,
            Digest32V2::new([0x4b; 32]),
            Digest32V2::new([0x4c; 32]),
            machine_boot,
            client_boot,
            agentd_boot,
            kerneld_boot,
        )
        .unwrap();
        let durable_task = DurableTaskIdV2::new([0x4d; 32]);
        let correlation = Digest32V2::new([0x4e; 32]);
        let signed_preparation = signer
            .sign_statement(
                KernelTaskStatementV2::preparation(
                    installation,
                    manifest,
                    5,
                    protocol_abi,
                    agentd_identity,
                    machine_boot,
                    client_boot,
                    agentd_boot,
                    kerneld_boot,
                    durable_task,
                    correlation,
                    Digest32V2::new([0x4f; 32]),
                    UnixMillisV2::new(10_000),
                    UnixMillisV2::new(20_000),
                )
                .unwrap(),
            )
            .unwrap();
        let preparation = verifier
            .verify_preparation(
                SignedKernelTaskStatementV2::from_canonical_bytes(
                    &signed_preparation.canonical_bytes().unwrap(),
                )
                .unwrap(),
                context,
            )
            .unwrap();
        let mut agentd = AgentTaskServiceV2::from_verified_deployment(
            installation,
            manifest,
            5,
            protocol_abi,
            agentd_identity,
            agentd_boot,
            kerneld_boot,
            key_id,
            signer.public_key(),
            128,
        )
        .unwrap();
        assert_eq!(
            agentd.prepare_ingress(
                context,
                Nonce32V2::new([0x50; 32]),
                preparation,
                UnixMillisV2::new(100),
            ),
            Err(savana_agentd::AgentTaskErrorV2::KernelAuthentication)
        );
    }

    #[test]
    fn signing_identities_reject_key_ids_not_derived_from_the_seed() {
        assert!(KernelTaskSigningIdentityV2::from_seed(
            Ed25519KeyIdV2::new([0x61; 32]),
            [0x62; 32],
        )
        .is_err());
        assert!(KernelDispatchSigningIdentityV2::from_seed(
            Ed25519KeyIdV2::new([0x63; 32]),
            [0x64; 32],
        )
        .is_err());
    }
}
