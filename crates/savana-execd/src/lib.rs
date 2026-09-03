#![forbid(unsafe_code)]

#[cfg(all(feature = "macos-development-authority", not(debug_assertions)))]
compile_error!("macos-development-authority is forbidden in release builds");

#[allow(dead_code)] // Wired by the production execd runtime owner.
mod effect_gate;
mod runtime;

use ed25519_dalek::{
    Signature as Ed25519Signature, Signer as _, SigningKey, VerifyingKey as Ed25519VerifyingKey,
};
use minicbor::Encode as _;
use savana_kernel_protocol::v2::{
    decode_signed_sealed_execution_envelope_v2, encode_executor_completion_payload_v2, Digest32V2,
    DispatchSubjectV2, Ed25519KeyIdV2, ExecutorCompletionDescriptorV2, ExecutorCompletionPayloadV2,
    ExecutorFailureClassV2, ExecutorFinalReleaseAuditEvidenceV2, ExecutorIdentityV2, Nonce32V2,
    SignedExecutorEffectStartedReceiptV2, SignedExecutorFinalReleaseReceiptV2, UnixMillisV2,
    UnsignedExecutorEffectStartedReceiptV2, UnsignedExecutorFinalReleaseReceiptV2,
};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

mod connector_registry;
mod connector_runtime;
mod daemon;
mod durable;
#[cfg(feature = "openclaw-release-test-support")]
#[doc(hidden)]
pub mod openclaw_release_test_support;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod protocol_service;
mod provider_transport;
#[allow(dead_code)] // Constructed only by verified production deployment state.
mod sandbox_process;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod state_owner;
mod v2_service;
mod worker_process;
#[allow(dead_code)] // Activated by the production connector worker supervisor.
mod worker_protocol;
#[allow(dead_code)] // Activated by the production connector worker supervisor.
mod worker_supervisor;
use durable::DurableExecdServiceV2;
pub use durable::{DurableExecdNamespaceV2, ExecdRollbackAnchorV2, ExecdStateHeadV2};
pub use protocol_service::{
    ExecdProtocolDeploymentV2, ExecdProtocolServiceErrorV2, ExecdProtocolServiceV2,
};
use runtime::EffectGatedExecdRuntimeV2;
pub use runtime::ExecdRuntimeErrorV2;
pub use state_owner::{ExecdStateOwnerErrorV2, ExecdStateOwnerV2};
pub use v2_service::{ExecdSuiteOneServerV2, ExecdSuiteOneServiceErrorV2};

/// Starts the fixed, fail-closed production executor daemon.
///
/// The implementation accepts only the compiled bootstrap path and inherited
/// service-manager listener. It never binds a caller-selected socket.
pub fn run(config_path: &std::path::Path) -> Result<(), ExecdDaemonErrorV2> {
    daemon::run(config_path)
}

pub use connector_registry::{
    ExecdConnectorRegistryErrorV2, ExecdConnectorRegistryGuardV2, ExecdConnectorRegistryTrustV2,
    ExecdConnectorRegistryV2,
};
pub use daemon::ExecdDaemonErrorV2;

/// Private executable entry point for the installed one-job connector codec.
///
/// This is public only so the package's fixed worker binary can call into the
/// library. It is not part of the execd service API.
#[doc(hidden)]
pub fn run_connector_worker_stdio_v2() -> Result<(), &'static str> {
    worker_process::run_stdio()
}

#[cfg(test)]
const SEALED_ENVELOPE_DOMAIN: &[u8] = b"SAVANA_SEALED_EXECUTION_ENVELOPE_V2\0";
const EFFECT_STARTED_DOMAIN: &[u8] = b"SAVANA_EXECD_EFFECT_STARTED_RECEIPT_V2\0";
const KNOWN_SUCCESS_DOMAIN: &[u8] = b"SAVANA_EXECD_KNOWN_SUCCESS_RECEIPT_V2\0";
const FAILED_NO_EFFECT_DOMAIN: &[u8] = b"SAVANA_EXECD_FAILED_NO_EFFECT_RECEIPT_V2\0";
const INDETERMINATE_DOMAIN: &[u8] = b"SAVANA_EXECD_INDETERMINATE_RECEIPT_V2\0";
const SIGNED_RECEIPT_DIGEST_DOMAIN: &[u8] = b"SAVANA_EXECD_SIGNED_RECEIPT_DIGEST_V2\0";
const MAX_ENVELOPE_BYTES: usize = 8 * 1024 * 1024;
const MAX_JOURNAL_ENTRIES: usize = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ExecdErrorV2 {
    #[error("execution envelope is noncanonical")]
    NonCanonicalEnvelope,
    #[error("execution envelope signature is invalid")]
    InvalidEnvelopeSignature,
    #[error("execution envelope does not match the active deployment")]
    DeploymentBinding,
    #[error("execution authorization is expired or not yet valid")]
    InvalidTime,
    #[error("execution nonce was rebound to different material")]
    NonceRebinding,
    #[error("execution journal transition is illegal")]
    IllegalTransition,
    #[error("execution journal entry was not found")]
    NotFound,
    #[error("execution journal reached its compiled capacity")]
    Capacity,
    #[error("execution allocation failed")]
    AllocationFailure,
    #[error("executor receipt is invalid")]
    InvalidReceipt,
    #[error("durable executor journal I/O or invariant failure")]
    DurableState,
    #[error("durable executor journal authentication failed")]
    DurableAuthentication,
    #[error("durable executor journal rollback was detected")]
    RollbackDetected,
    #[error("durable executor journal commit outcome is uncertain")]
    CommitUncertain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DispatchEnvelopeKindV2 {
    ToolExecution,
    FinalRelease,
}

impl DispatchEnvelopeKindV2 {
    pub const fn tag(self) -> u16 {
        match self {
            Self::ToolExecution => 1,
            Self::FinalRelease => 2,
        }
    }

    fn from_tag(tag: u16) -> Result<Self, ExecdErrorV2> {
        match tag {
            1 => Ok(Self::ToolExecution),
            2 => Ok(Self::FinalRelease),
            _ => Err(ExecdErrorV2::NonCanonicalEnvelope),
        }
    }
}

#[derive(Clone)]
pub struct VerifiedExecdDeploymentV2 {
    installation_id: Digest32V2,
    active_state_manifest_digest: Digest32V2,
    deployment_generation: u64,
    effect_fence_epoch: u64,
    executor_identity_digest: Digest32V2,
    kernel_envelope_key_id: Ed25519KeyIdV2,
    kernel_envelope_verifying_key: Ed25519VerifyingKey,
    effect_receipt_key_id: Ed25519KeyIdV2,
    effect_receipt_signing_key: SigningKey,
}

impl std::fmt::Debug for VerifiedExecdDeploymentV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifiedExecdDeploymentV2")
            .field("deployment_generation", &self.deployment_generation)
            .field("effect_fence_epoch", &self.effect_fence_epoch)
            .finish_non_exhaustive()
    }
}

impl VerifiedExecdDeploymentV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn from_verified_manifest(
        installation_id: Digest32V2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        effect_fence_epoch: u64,
        executor_identity_digest: Digest32V2,
        kernel_envelope_key_id: Ed25519KeyIdV2,
        kernel_envelope_public_key: [u8; 32],
        effect_receipt_key_id: Ed25519KeyIdV2,
        effect_receipt_signing_seed: [u8; 32],
    ) -> Result<Self, ExecdErrorV2> {
        if deployment_generation == 0
            || effect_fence_epoch == 0
            || [
                installation_id.as_bytes(),
                active_state_manifest_digest.as_bytes(),
                executor_identity_digest.as_bytes(),
                kernel_envelope_key_id.as_bytes(),
                effect_receipt_key_id.as_bytes(),
            ]
            .iter()
            .any(|bytes| is_zero(bytes))
            || effect_receipt_signing_seed == [0; 32]
        {
            return Err(ExecdErrorV2::DeploymentBinding);
        }
        let kernel_envelope_verifying_key =
            Ed25519VerifyingKey::from_bytes(&kernel_envelope_public_key)
                .map_err(|_| ExecdErrorV2::DeploymentBinding)?;
        let effect_receipt_signing_key = SigningKey::from_bytes(&effect_receipt_signing_seed);
        if savana_kernel_protocol::v2::derive_ed25519_key_id_v2(kernel_envelope_public_key)
            != kernel_envelope_key_id
            || savana_kernel_protocol::v2::derive_ed25519_key_id_v2(
                effect_receipt_signing_key.verifying_key().to_bytes(),
            ) != effect_receipt_key_id
        {
            return Err(ExecdErrorV2::DeploymentBinding);
        }
        Ok(Self {
            installation_id,
            active_state_manifest_digest,
            deployment_generation,
            effect_fence_epoch,
            executor_identity_digest,
            kernel_envelope_key_id,
            kernel_envelope_verifying_key,
            effect_receipt_key_id,
            effect_receipt_signing_key,
        })
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

    pub const fn executor_identity(&self) -> ExecutorIdentityV2 {
        ExecutorIdentityV2::new(*self.executor_identity_digest.as_bytes())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecdJournalStateV2 {
    Prepared,
    ProviderAttemptPrepared,
    EffectStarted,
    ProviderResponseRetained,
    ReleaseEvidencePrepared,
    CompletionAvailable,
    FailedNoEffect,
    Indeterminate,
    Acknowledged,
}

impl ExecdJournalStateV2 {
    const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::CompletionAvailable
                | Self::FailedNoEffect
                | Self::Indeterminate
                | Self::Acknowledged
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecdQueryV2 {
    execution_nonce: Nonce32V2,
    dispatch_core_digest: Digest32V2,
    dispatch_subject_digest: Digest32V2,
    kind: DispatchEnvelopeKindV2,
    state: ExecdJournalStateV2,
    failure_class: Option<ExecutorFailureClassV2>,
    prepared_request_digest: Option<Digest32V2>,
    retained_provider_response_digest: Option<Digest32V2>,
    retained_provider_response_length: Option<u32>,
}

impl ExecdQueryV2 {
    pub const fn execution_nonce(self) -> Nonce32V2 {
        self.execution_nonce
    }

    pub const fn dispatch_core_digest(self) -> Digest32V2 {
        self.dispatch_core_digest
    }

    pub const fn dispatch_subject_digest(self) -> Digest32V2 {
        self.dispatch_subject_digest
    }

    pub const fn kind(self) -> DispatchEnvelopeKindV2 {
        self.kind
    }

    pub const fn state(self) -> ExecdJournalStateV2 {
        self.state
    }

    pub const fn failure_class(self) -> Option<ExecutorFailureClassV2> {
        self.failure_class
    }

    pub const fn prepared_request_digest(self) -> Option<Digest32V2> {
        self.prepared_request_digest
    }

    pub const fn retained_provider_response_digest(self) -> Option<Digest32V2> {
        self.retained_provider_response_digest
    }

    pub const fn retained_provider_response_length(self) -> Option<u32> {
        self.retained_provider_response_length
    }
}

#[derive(Debug, Clone, Copy)]
struct DispatchEnvelopePayloadV2 {
    installation_id: Digest32V2,
    active_state_manifest_digest: Digest32V2,
    deployment_generation: u64,
    effect_fence_epoch: u64,
    executor_identity_digest: Digest32V2,
    kind: DispatchEnvelopeKindV2,
    execution_nonce: Nonce32V2,
    dispatch_core_digest: Digest32V2,
    dispatch_subject_digest: Digest32V2,
    #[cfg(test)]
    sealed_envelope_digest: Digest32V2,
    issued_at: UnixMillisV2,
    expires_at: UnixMillisV2,
    #[cfg(test)]
    effect_gate_lease_digest: Digest32V2,
    #[cfg(test)]
    ledger_projection_digest: Digest32V2,
}

#[derive(Debug)]
pub(crate) struct VerifiedSignedDispatchEnvelopeV2 {
    payload: DispatchEnvelopePayloadV2,
    exact_envelope_digest: Digest32V2,
    canonical_envelope: Zeroizing<Vec<u8>>,
}

#[derive(Debug)]
pub(crate) enum SignedDispatchAdmissionV2 {
    ExactReplay(ExecdQueryV2),
    New(Box<VerifiedSignedDispatchEnvelopeV2>),
}

#[derive(Debug, Clone)]
struct ExecdJournalEntryV2 {
    payload: DispatchEnvelopePayloadV2,
    exact_envelope_digest: Digest32V2,
    canonical_envelope: Zeroizing<Vec<u8>>,
    state: ExecdJournalStateV2,
    failure_class: Option<ExecutorFailureClassV2>,
    prepared_request_digest: Option<Digest32V2>,
    provider_attempt_predecessor_digest: Option<Digest32V2>,
    effect_started_receipt: Option<SignedExecutorEffectStartedReceiptV2>,
    retained_provider_response: Option<Zeroizing<Vec<u8>>>,
    release_evidence_prepared_digest: Option<Digest32V2>,
    release_provider_evidence: Option<Zeroizing<Vec<u8>>>,
    release_audit_evidence: Option<Zeroizing<Vec<u8>>>,
    completion: Option<StoredExecutorCompletionV2>,
    terminal_receipt: Option<SignedExecutorReceiptV2>,
}

#[derive(Clone)]
pub struct ExecdServiceV2 {
    deployment: VerifiedExecdDeploymentV2,
    entries: Vec<ExecdJournalEntryV2>,
}

impl std::fmt::Debug for ExecdServiceV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExecdServiceV2")
            .field(
                "deployment_generation",
                &self.deployment.deployment_generation,
            )
            .field("journal_entries", &self.entries.len())
            .finish_non_exhaustive()
    }
}

impl ExecdServiceV2 {
    pub fn new(deployment: VerifiedExecdDeploymentV2) -> Self {
        Self {
            deployment,
            entries: Vec::new(),
        }
    }

    pub fn accept_signed_dispatch(
        &mut self,
        canonical_envelope: &[u8],
        now: UnixMillisV2,
    ) -> Result<ExecdQueryV2, ExecdErrorV2> {
        match self.classify_signed_dispatch(canonical_envelope, now)? {
            SignedDispatchAdmissionV2::ExactReplay(query) => Ok(query),
            SignedDispatchAdmissionV2::New(verified) => self.accept_verified_dispatch(*verified),
        }
    }

    fn classify_signed_dispatch(
        &self,
        canonical_envelope: &[u8],
        now: UnixMillisV2,
    ) -> Result<SignedDispatchAdmissionV2, ExecdErrorV2> {
        let verified = verify_dispatch_envelope(canonical_envelope, &self.deployment, now)?;
        if let Some(existing) = self
            .entries
            .iter()
            .find(|entry| entry.payload.execution_nonce == verified.payload.execution_nonce)
        {
            if existing.exact_envelope_digest != verified.exact_envelope_digest {
                return Err(ExecdErrorV2::NonceRebinding);
            }
            return Ok(SignedDispatchAdmissionV2::ExactReplay(project_entry(
                existing,
            )));
        }
        if self.entries.len() >= MAX_JOURNAL_ENTRIES {
            return Err(ExecdErrorV2::Capacity);
        }
        Ok(SignedDispatchAdmissionV2::New(Box::new(verified)))
    }

    fn accept_verified_dispatch(
        &mut self,
        verified: VerifiedSignedDispatchEnvelopeV2,
    ) -> Result<ExecdQueryV2, ExecdErrorV2> {
        if self
            .entries
            .iter()
            .any(|entry| entry.payload.execution_nonce == verified.payload.execution_nonce)
        {
            return Err(ExecdErrorV2::NonceRebinding);
        }
        if self.entries.len() >= MAX_JOURNAL_ENTRIES {
            return Err(ExecdErrorV2::Capacity);
        }
        self.entries
            .try_reserve(1)
            .map_err(|_| ExecdErrorV2::AllocationFailure)?;
        self.entries.push(ExecdJournalEntryV2 {
            payload: verified.payload,
            exact_envelope_digest: verified.exact_envelope_digest,
            canonical_envelope: verified.canonical_envelope,
            state: ExecdJournalStateV2::Prepared,
            failure_class: None,
            prepared_request_digest: None,
            provider_attempt_predecessor_digest: None,
            effect_started_receipt: None,
            retained_provider_response: None,
            release_evidence_prepared_digest: None,
            release_provider_evidence: None,
            release_audit_evidence: None,
            completion: None,
            terminal_receipt: None,
        });
        self.query(verified.payload.execution_nonce)
    }

    pub fn query(&self, nonce: Nonce32V2) -> Result<ExecdQueryV2, ExecdErrorV2> {
        self.entries
            .iter()
            .find(|entry| entry.payload.execution_nonce == nonce)
            .map(project_entry)
            .ok_or(ExecdErrorV2::NotFound)
    }

    pub(crate) fn sealed_execution_envelope(
        &self,
        nonce: Nonce32V2,
    ) -> Result<Zeroizing<Vec<u8>>, ExecdErrorV2> {
        self.entries
            .iter()
            .find(|entry| entry.payload.execution_nonce == nonce)
            .map(|entry| Zeroizing::new(entry.canonical_envelope.to_vec()))
            .ok_or(ExecdErrorV2::NotFound)
    }

    pub fn recovery_projection(&self) -> Result<Vec<ExecdQueryV2>, ExecdErrorV2> {
        let mut projection = Vec::new();
        projection
            .try_reserve(self.entries.len())
            .map_err(|_| ExecdErrorV2::AllocationFailure)?;
        projection.extend(self.entries.iter().map(project_entry));
        projection.sort_unstable_by(|left, right| {
            left.execution_nonce
                .as_bytes()
                .cmp(right.execution_nonce.as_bytes())
        });
        Ok(projection)
    }

    pub fn terminal_receipt(
        &self,
        nonce: Nonce32V2,
    ) -> Result<SignedExecutorReceiptV2, ExecdErrorV2> {
        let entry = self
            .entries
            .iter()
            .find(|entry| entry.payload.execution_nonce == nonce)
            .ok_or(ExecdErrorV2::NotFound)?;
        entry
            .terminal_receipt
            .clone()
            .ok_or(ExecdErrorV2::IllegalTransition)
    }

    pub fn effect_started_receipt(
        &self,
        nonce: Nonce32V2,
    ) -> Result<SignedExecutorEffectStartedReceiptV2, ExecdErrorV2> {
        let entry = self
            .entries
            .iter()
            .find(|entry| entry.payload.execution_nonce == nonce)
            .ok_or(ExecdErrorV2::NotFound)?;
        entry
            .effect_started_receipt
            .clone()
            .ok_or(ExecdErrorV2::IllegalTransition)
    }

    pub fn retained_provider_response(
        &self,
        nonce: Nonce32V2,
    ) -> Result<RetainedProviderResponseV2, ExecdErrorV2> {
        let entry = self
            .entries
            .iter()
            .find(|entry| entry.payload.execution_nonce == nonce)
            .ok_or(ExecdErrorV2::NotFound)?;
        let bytes = entry
            .retained_provider_response
            .as_ref()
            .ok_or(ExecdErrorV2::IllegalTransition)?;
        RetainedProviderResponseV2::from_journal(bytes.clone())
    }

    pub fn completion(&self, nonce: Nonce32V2) -> Result<StoredExecutorCompletionV2, ExecdErrorV2> {
        self.entries
            .iter()
            .find(|entry| entry.payload.execution_nonce == nonce)
            .ok_or(ExecdErrorV2::NotFound)?
            .completion
            .clone()
            .ok_or(ExecdErrorV2::IllegalTransition)
    }

    pub fn prepare_provider_attempt(
        &mut self,
        nonce: Nonce32V2,
        prepared_request_digest: Digest32V2,
        now: UnixMillisV2,
    ) -> Result<ProviderAttemptPredecessorV2, ExecdErrorV2> {
        if is_zero(prepared_request_digest.as_bytes()) {
            return Err(ExecdErrorV2::IllegalTransition);
        }
        let entry = self.entry_mut(nonce)?;
        ensure_live(entry, now)?;
        if entry.state != ExecdJournalStateV2::Prepared {
            return Err(ExecdErrorV2::IllegalTransition);
        }
        let predecessor_digest = provider_attempt_predecessor_digest(
            entry.payload.execution_nonce,
            entry.payload.dispatch_core_digest,
            entry.payload.dispatch_subject_digest,
            prepared_request_digest,
            now,
        );
        entry.state = ExecdJournalStateV2::ProviderAttemptPrepared;
        entry.prepared_request_digest = Some(prepared_request_digest);
        entry.provider_attempt_predecessor_digest = Some(predecessor_digest);
        Ok(ProviderAttemptPredecessorV2 {
            execution_nonce: nonce,
            predecessor_digest,
            prepared_request_digest,
            connector_identity_digest: domain_hash_parts(
                b"SAVANA_EXECD_BOUND_CONNECTOR_IDENTITY_V2\0",
                &[
                    entry.payload.dispatch_subject_digest.as_bytes(),
                    entry.exact_envelope_digest.as_bytes(),
                ],
            ),
            connector_codec_job_descriptor_digest: domain_hash_parts(
                b"SAVANA_EXECD_BOUND_CONNECTOR_JOB_DESCRIPTOR_V2\0",
                &[
                    entry.exact_envelope_digest.as_bytes(),
                    prepared_request_digest.as_bytes(),
                ],
            ),
            external_attempt_ordinal: 1,
        })
    }

    pub fn record_effect_started(
        &mut self,
        predecessor: ProviderAttemptPredecessorV2,
        now: UnixMillisV2,
    ) -> Result<ArmedEffectV2, ExecdErrorV2> {
        let entry_index = self.entry_index(predecessor.execution_nonce)?;
        {
            let entry = &self.entries[entry_index];
            ensure_live(entry, now)?;
            if entry.state != ExecdJournalStateV2::ProviderAttemptPrepared
                || entry.provider_attempt_predecessor_digest != Some(predecessor.predecessor_digest)
            {
                return Err(ExecdErrorV2::IllegalTransition);
            }
        }
        let receipt = sign_effect_started_receipt(
            &self.entries[entry_index],
            &predecessor,
            now,
            self.deployment.effect_receipt_key_id,
            &self.deployment.effect_receipt_signing_key,
        )?;
        let entry = &mut self.entries[entry_index];
        entry.state = ExecdJournalStateV2::EffectStarted;
        entry.effect_started_receipt = Some(receipt.clone());
        Ok(ArmedEffectV2 {
            execution_nonce: predecessor.execution_nonce,
            receipt,
            permit: EffectPermitV2 {
                execution_nonce: predecessor.execution_nonce,
                dispatch_core_digest: entry.payload.dispatch_core_digest,
                dispatch_subject_digest: entry.payload.dispatch_subject_digest,
            },
        })
    }

    pub fn record_provider_response(
        &mut self,
        nonce: Nonce32V2,
        response: Vec<u8>,
    ) -> Result<RetainedProviderResponseV2, ExecdErrorV2> {
        if response.is_empty()
            || response.len() > crate::worker_protocol::MAX_CONNECTOR_RESPONSE_BYTES
        {
            return Err(ExecdErrorV2::Capacity);
        }
        let entry = self.entry_mut(nonce)?;
        if let Some(existing) = entry.retained_provider_response.as_ref() {
            if existing.as_slice() != response.as_slice() {
                return Err(ExecdErrorV2::NonceRebinding);
            }
            return RetainedProviderResponseV2::from_journal(existing.clone());
        }
        if entry.state != ExecdJournalStateV2::EffectStarted {
            return Err(ExecdErrorV2::IllegalTransition);
        }
        entry.retained_provider_response = Some(Zeroizing::new(response));
        entry.state = ExecdJournalStateV2::ProviderResponseRetained;
        RetainedProviderResponseV2::from_journal(
            entry
                .retained_provider_response
                .as_ref()
                .ok_or(ExecdErrorV2::DurableState)?
                .clone(),
        )
    }

    #[cfg(test)]
    pub fn record_known_success(
        &mut self,
        nonce: Nonce32V2,
        evidence_digest: Digest32V2,
        now: UnixMillisV2,
    ) -> Result<SignedExecutorReceiptV2, ExecdErrorV2> {
        if self
            .entries
            .get(self.entry_index(nonce)?)
            .and_then(|entry| entry.retained_provider_response.as_ref())
            .is_none()
        {
            return Err(ExecdErrorV2::IllegalTransition);
        }
        self.record_terminal(
            nonce,
            evidence_digest,
            now,
            ExecutorReceiptKindV2::KnownSuccess,
            &[ExecdJournalStateV2::ProviderResponseRetained],
            ExecdJournalStateV2::CompletionAvailable,
            true,
        )
    }

    pub fn record_tool_completion(
        &mut self,
        nonce: Nonce32V2,
        result: Vec<u8>,
        evidence_digest: Digest32V2,
        now: UnixMillisV2,
    ) -> Result<StoredExecutorCompletionV2, ExecdErrorV2> {
        let entry_index = self.entry_index(nonce)?;
        if self.entries[entry_index].payload.kind != DispatchEnvelopeKindV2::ToolExecution
            || self.entries[entry_index].state != ExecdJournalStateV2::ProviderResponseRetained
            || self.entries[entry_index]
                .retained_provider_response
                .is_none()
        {
            return Err(ExecdErrorV2::IllegalTransition);
        }
        let payload =
            ExecutorCompletionPayloadV2::tool_result(result).map_err(|_| ExecdErrorV2::Capacity)?;
        let descriptor = payload
            .descriptor()
            .map_err(|_| ExecdErrorV2::DurableState)?;
        let canonical_payload = encode_executor_completion_payload_v2(&payload)
            .map_err(|_| ExecdErrorV2::DurableState)?;
        let stored = StoredExecutorCompletionV2::new(descriptor, canonical_payload)?;
        self.record_terminal(
            nonce,
            evidence_digest,
            now,
            ExecutorReceiptKindV2::KnownSuccess,
            &[ExecdJournalStateV2::ProviderResponseRetained],
            ExecdJournalStateV2::CompletionAvailable,
            true,
        )?;
        self.entries[entry_index].completion = Some(stored.clone());
        Ok(stored)
    }

    pub fn prepare_final_release_evidence(
        &mut self,
        nonce: Nonce32V2,
        provider_evidence: Vec<u8>,
        audit_evidence: Vec<u8>,
        now: UnixMillisV2,
    ) -> Result<Digest32V2, ExecdErrorV2> {
        let entry_index = self.entry_index(nonce)?;
        let entry = &self.entries[entry_index];
        if entry.payload.kind != DispatchEnvelopeKindV2::FinalRelease
            || entry.state != ExecdJournalStateV2::ProviderResponseRetained
            || entry.retained_provider_response.is_none()
            || provider_evidence.is_empty()
            || audit_evidence.is_empty()
        {
            return Err(ExecdErrorV2::IllegalTransition);
        }
        ensure_live(entry, now)?;
        let audit = ExecutorFinalReleaseAuditEvidenceV2::new(audit_evidence.clone())
            .map_err(|_| ExecdErrorV2::Capacity)?;
        let effect_receipt = entry
            .effect_started_receipt
            .as_ref()
            .ok_or(ExecdErrorV2::IllegalTransition)?;
        let prepared_digest = domain_hash_parts(
            b"SAVANA_EXECD_RELEASE_EVIDENCE_PREPARED_RECORD_V2\0",
            &[
                entry.payload.execution_nonce.as_bytes(),
                entry.payload.dispatch_core_digest.as_bytes(),
                entry.payload.dispatch_subject_digest.as_bytes(),
                effect_receipt.digest().as_bytes(),
                domain_hash_parts(
                    b"SAVANA_CONNECTOR_PROVIDER_EVIDENCE_V2\0",
                    &[&provider_evidence],
                )
                .as_bytes(),
                audit.digest().as_bytes(),
                &now.get().to_be_bytes(),
            ],
        );
        let entry = &mut self.entries[entry_index];
        entry.state = ExecdJournalStateV2::ReleaseEvidencePrepared;
        entry.release_evidence_prepared_digest = Some(prepared_digest);
        entry.release_provider_evidence = Some(Zeroizing::new(provider_evidence));
        entry.release_audit_evidence = Some(Zeroizing::new(audit_evidence));
        Ok(prepared_digest)
    }

    pub fn record_final_release_completion(
        &mut self,
        nonce: Nonce32V2,
        now: UnixMillisV2,
    ) -> Result<StoredExecutorCompletionV2, ExecdErrorV2> {
        let entry_index = self.entry_index(nonce)?;
        let entry = &self.entries[entry_index];
        if entry.payload.kind != DispatchEnvelopeKindV2::FinalRelease
            || entry.state != ExecdJournalStateV2::ReleaseEvidencePrepared
        {
            return Err(ExecdErrorV2::IllegalTransition);
        }
        let provider_evidence = entry
            .release_provider_evidence
            .as_ref()
            .ok_or(ExecdErrorV2::IllegalTransition)?
            .to_vec();
        let audit_evidence_bytes = entry
            .release_audit_evidence
            .as_ref()
            .ok_or(ExecdErrorV2::IllegalTransition)?
            .to_vec();
        let release_evidence_prepared_journal_record_digest = entry
            .release_evidence_prepared_digest
            .ok_or(ExecdErrorV2::IllegalTransition)?;
        let envelope = decode_signed_sealed_execution_envelope_v2(&entry.canonical_envelope)
            .map_err(|_| ExecdErrorV2::NonCanonicalEnvelope)?;
        let binding = match envelope.payload().core().subject() {
            DispatchSubjectV2::FinalRelease { binding, .. } => binding,
            DispatchSubjectV2::ToolExecution { .. } => return Err(ExecdErrorV2::IllegalTransition),
        };
        let audit_evidence = ExecutorFinalReleaseAuditEvidenceV2::new(audit_evidence_bytes)
            .map_err(|_| ExecdErrorV2::Capacity)?;
        let provider_evidence_digest = domain_hash_parts(
            b"SAVANA_CONNECTOR_PROVIDER_EVIDENCE_V2\0",
            &[&provider_evidence],
        );
        let unsigned = UnsignedExecutorFinalReleaseReceiptV2::new(
            entry.payload.installation_id,
            entry.payload.active_state_manifest_digest,
            entry.payload.deployment_generation,
            entry.payload.effect_fence_epoch,
            binding.durable_release_id(),
            entry.payload.execution_nonce,
            entry.payload.dispatch_core_digest,
            entry.payload.dispatch_subject_digest,
            binding.vault_segment_digest(),
            binding.release_payload_digest(),
            binding.destination_digest(),
            ExecutorIdentityV2::new(*entry.payload.executor_identity_digest.as_bytes()),
            provider_evidence_digest,
            audit_evidence.digest(),
            release_evidence_prepared_journal_record_digest,
            now,
        )
        .map_err(|_| ExecdErrorV2::InvalidReceipt)?;
        let final_receipt = SignedExecutorFinalReleaseReceiptV2::sign(
            unsigned,
            self.deployment.effect_receipt_key_id,
            &self.deployment.effect_receipt_signing_key,
        )
        .map_err(|_| ExecdErrorV2::InvalidReceipt)?;
        let evidence_digest = final_receipt.digest();
        let payload = ExecutorCompletionPayloadV2::final_release(
            final_receipt,
            provider_evidence,
            audit_evidence,
        )
        .map_err(|_| ExecdErrorV2::InvalidReceipt)?;
        let descriptor = payload
            .descriptor()
            .map_err(|_| ExecdErrorV2::DurableState)?;
        let canonical_payload = encode_executor_completion_payload_v2(&payload)
            .map_err(|_| ExecdErrorV2::DurableState)?;
        let stored = StoredExecutorCompletionV2::new(descriptor, canonical_payload)?;
        self.record_terminal(
            nonce,
            evidence_digest,
            now,
            ExecutorReceiptKindV2::KnownSuccess,
            &[ExecdJournalStateV2::ReleaseEvidencePrepared],
            ExecdJournalStateV2::CompletionAvailable,
            false,
        )?;
        self.entries[entry_index].completion = Some(stored.clone());
        Ok(stored)
    }

    pub fn record_failed_no_effect(
        &mut self,
        nonce: Nonce32V2,
        class: ExecutorFailureClassV2,
        evidence_digest: Digest32V2,
        now: UnixMillisV2,
    ) -> Result<SignedExecutorReceiptV2, ExecdErrorV2> {
        let receipt = self.record_terminal(
            nonce,
            evidence_digest,
            now,
            ExecutorReceiptKindV2::FailedNoEffect,
            &[
                ExecdJournalStateV2::Prepared,
                ExecdJournalStateV2::ProviderAttemptPrepared,
            ],
            ExecdJournalStateV2::FailedNoEffect,
            true,
        )?;
        self.entry_mut(nonce)?.failure_class = Some(class);
        Ok(receipt)
    }

    pub fn record_failed_no_effect_recovery(
        &mut self,
        nonce: Nonce32V2,
        class: ExecutorFailureClassV2,
        evidence_digest: Digest32V2,
        now: UnixMillisV2,
    ) -> Result<SignedExecutorReceiptV2, ExecdErrorV2> {
        let receipt = self.record_terminal(
            nonce,
            evidence_digest,
            now,
            ExecutorReceiptKindV2::FailedNoEffect,
            &[
                ExecdJournalStateV2::Prepared,
                ExecdJournalStateV2::ProviderAttemptPrepared,
            ],
            ExecdJournalStateV2::FailedNoEffect,
            false,
        )?;
        self.entry_mut(nonce)?.failure_class = Some(class);
        Ok(receipt)
    }

    pub fn record_indeterminate(
        &mut self,
        nonce: Nonce32V2,
        evidence_digest: Digest32V2,
        now: UnixMillisV2,
    ) -> Result<SignedExecutorReceiptV2, ExecdErrorV2> {
        self.record_terminal(
            nonce,
            evidence_digest,
            now,
            ExecutorReceiptKindV2::Indeterminate,
            &[
                ExecdJournalStateV2::ProviderAttemptPrepared,
                ExecdJournalStateV2::EffectStarted,
                ExecdJournalStateV2::ProviderResponseRetained,
                ExecdJournalStateV2::ReleaseEvidencePrepared,
            ],
            ExecdJournalStateV2::Indeterminate,
            true,
        )
    }

    pub fn record_indeterminate_recovery(
        &mut self,
        nonce: Nonce32V2,
        evidence_digest: Digest32V2,
        now: UnixMillisV2,
    ) -> Result<SignedExecutorReceiptV2, ExecdErrorV2> {
        self.record_terminal(
            nonce,
            evidence_digest,
            now,
            ExecutorReceiptKindV2::Indeterminate,
            &[
                ExecdJournalStateV2::ProviderAttemptPrepared,
                ExecdJournalStateV2::EffectStarted,
                ExecdJournalStateV2::ProviderResponseRetained,
                ExecdJournalStateV2::ReleaseEvidencePrepared,
            ],
            ExecdJournalStateV2::Indeterminate,
            false,
        )
    }

    pub fn acknowledge_completion(
        &mut self,
        nonce: Nonce32V2,
        kernel_commit_digest: Digest32V2,
    ) -> Result<(), ExecdErrorV2> {
        if is_zero(kernel_commit_digest.as_bytes()) {
            return Err(ExecdErrorV2::IllegalTransition);
        }
        let entry = self.entry_mut(nonce)?;
        if entry.state != ExecdJournalStateV2::CompletionAvailable {
            return Err(ExecdErrorV2::IllegalTransition);
        }
        entry.state = ExecdJournalStateV2::Acknowledged;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn record_terminal(
        &mut self,
        nonce: Nonce32V2,
        evidence_digest: Digest32V2,
        now: UnixMillisV2,
        kind: ExecutorReceiptKindV2,
        allowed_states: &[ExecdJournalStateV2],
        next_state: ExecdJournalStateV2,
        enforce_live_time: bool,
    ) -> Result<SignedExecutorReceiptV2, ExecdErrorV2> {
        if is_zero(evidence_digest.as_bytes()) {
            return Err(ExecdErrorV2::IllegalTransition);
        }
        let entry_index = self.entry_index(nonce)?;
        {
            let entry = &self.entries[entry_index];
            if enforce_live_time {
                ensure_live(entry, now)?;
            } else if now.get() < entry.payload.issued_at.get() {
                return Err(ExecdErrorV2::InvalidTime);
            }
            if !allowed_states.contains(&entry.state) || entry.state.is_terminal() {
                return Err(ExecdErrorV2::IllegalTransition);
            }
        }
        let receipt = sign_receipt(
            &self.entries[entry_index],
            kind,
            evidence_digest,
            now,
            self.deployment.effect_receipt_key_id,
            &self.deployment.effect_receipt_signing_key,
        )?;
        let entry = &mut self.entries[entry_index];
        entry.state = next_state;
        entry.terminal_receipt = Some(receipt.clone());
        Ok(receipt)
    }

    fn entry_index(&self, nonce: Nonce32V2) -> Result<usize, ExecdErrorV2> {
        self.entries
            .iter()
            .position(|entry| entry.payload.execution_nonce == nonce)
            .ok_or(ExecdErrorV2::NotFound)
    }

    fn entry_mut(&mut self, nonce: Nonce32V2) -> Result<&mut ExecdJournalEntryV2, ExecdErrorV2> {
        let index = self.entry_index(nonce)?;
        Ok(&mut self.entries[index])
    }
}

#[derive(Debug)]
pub struct ProviderAttemptPredecessorV2 {
    execution_nonce: Nonce32V2,
    predecessor_digest: Digest32V2,
    prepared_request_digest: Digest32V2,
    connector_identity_digest: Digest32V2,
    connector_codec_job_descriptor_digest: Digest32V2,
    external_attempt_ordinal: u16,
}

impl ProviderAttemptPredecessorV2 {
    pub const fn execution_nonce(&self) -> Nonce32V2 {
        self.execution_nonce
    }
}

#[derive(Debug)]
pub struct EffectPermitV2 {
    execution_nonce: Nonce32V2,
    dispatch_core_digest: Digest32V2,
    dispatch_subject_digest: Digest32V2,
}

impl EffectPermitV2 {
    pub const fn execution_nonce(&self) -> Nonce32V2 {
        self.execution_nonce
    }

    pub const fn dispatch_core_digest(&self) -> Digest32V2 {
        self.dispatch_core_digest
    }

    pub const fn dispatch_subject_digest(&self) -> Digest32V2 {
        self.dispatch_subject_digest
    }
}

#[derive(Debug)]
pub struct ArmedEffectV2 {
    execution_nonce: Nonce32V2,
    receipt: SignedExecutorEffectStartedReceiptV2,
    permit: EffectPermitV2,
}

pub struct RetainedProviderResponseV2 {
    bytes: Zeroizing<Vec<u8>>,
    digest: Digest32V2,
}

#[derive(Clone)]
pub struct StoredExecutorCompletionV2 {
    descriptor: ExecutorCompletionDescriptorV2,
    canonical_payload: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for StoredExecutorCompletionV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StoredExecutorCompletionV2")
            .field("descriptor", &self.descriptor)
            .field("encoded_len", &self.canonical_payload.len())
            .finish_non_exhaustive()
    }
}

impl StoredExecutorCompletionV2 {
    fn new(
        descriptor: ExecutorCompletionDescriptorV2,
        canonical_payload: Vec<u8>,
    ) -> Result<Self, ExecdErrorV2> {
        let payload =
            savana_kernel_protocol::v2::decode_executor_completion_payload_v2(&canonical_payload)
                .map_err(|_| ExecdErrorV2::DurableState)?;
        if payload
            .descriptor()
            .map_err(|_| ExecdErrorV2::DurableState)?
            != descriptor
        {
            return Err(ExecdErrorV2::DurableState);
        }
        Ok(Self {
            descriptor,
            canonical_payload: Zeroizing::new(canonical_payload),
        })
    }

    pub const fn descriptor(&self) -> ExecutorCompletionDescriptorV2 {
        self.descriptor
    }

    pub fn canonical_payload(&self) -> &[u8] {
        &self.canonical_payload
    }
}

impl std::fmt::Debug for RetainedProviderResponseV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RetainedProviderResponseV2")
            .field("encoded_len", &self.bytes.len())
            .field("digest", &self.digest)
            .finish_non_exhaustive()
    }
}

impl RetainedProviderResponseV2 {
    fn from_journal(bytes: Zeroizing<Vec<u8>>) -> Result<Self, ExecdErrorV2> {
        if bytes.is_empty() || bytes.len() > crate::worker_protocol::MAX_CONNECTOR_RESPONSE_BYTES {
            return Err(ExecdErrorV2::DurableState);
        }
        let digest = crate::worker_protocol::connector_response_digest(&bytes);
        Ok(Self { bytes, digest })
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub const fn digest(&self) -> Digest32V2 {
        self.digest
    }

    pub fn into_bytes(self) -> Zeroizing<Vec<u8>> {
        self.bytes
    }
}

impl ArmedEffectV2 {
    pub const fn execution_nonce(&self) -> Nonce32V2 {
        self.execution_nonce
    }

    pub const fn receipt(&self) -> &SignedExecutorEffectStartedReceiptV2 {
        &self.receipt
    }

    pub fn into_effect_permit(self) -> EffectPermitV2 {
        self.permit
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExecutorReceiptKindV2 {
    EffectStarted,
    KnownSuccess,
    FailedNoEffect,
    Indeterminate,
}

impl ExecutorReceiptKindV2 {
    const fn tag(self) -> u16 {
        match self {
            Self::EffectStarted => 1,
            Self::KnownSuccess => 2,
            Self::FailedNoEffect => 3,
            Self::Indeterminate => 4,
        }
    }

    const fn domain(self) -> &'static [u8] {
        match self {
            Self::EffectStarted => EFFECT_STARTED_DOMAIN,
            Self::KnownSuccess => KNOWN_SUCCESS_DOMAIN,
            Self::FailedNoEffect => FAILED_NO_EFFECT_DOMAIN,
            Self::Indeterminate => INDETERMINATE_DOMAIN,
        }
    }

    fn from_tag(tag: u16) -> Result<Self, ExecdErrorV2> {
        match tag {
            1 => Ok(Self::EffectStarted),
            2 => Ok(Self::KnownSuccess),
            3 => Ok(Self::FailedNoEffect),
            4 => Ok(Self::Indeterminate),
            _ => Err(ExecdErrorV2::InvalidReceipt),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SignedExecutorReceiptV2 {
    canonical_bytes: Vec<u8>,
    kind: ExecutorReceiptKindV2,
}

impl SignedExecutorReceiptV2 {
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub fn verify(
        &self,
        expected_key_id: Ed25519KeyIdV2,
        public_key: &Ed25519VerifyingKey,
    ) -> Result<(), ExecdErrorV2> {
        let decoded = decode_signed_receipt(&self.canonical_bytes)?;
        if decoded.kind != self.kind || decoded.key_id != expected_key_id {
            return Err(ExecdErrorV2::InvalidReceipt);
        }
        let digest = receipt_signature_digest(decoded.kind, &decoded.canonical_payload);
        let mut signature_input = Vec::from(decoded.kind.domain());
        signature_input.extend_from_slice(digest.as_bytes());
        public_key
            .verify_strict(
                &signature_input,
                &Ed25519Signature::from_bytes(&decoded.signature),
            )
            .map_err(|_| ExecdErrorV2::InvalidReceipt)
    }

    pub fn digest(&self) -> Digest32V2 {
        let mut hasher = Sha256::new();
        hasher.update(SIGNED_RECEIPT_DIGEST_DOMAIN);
        hasher.update(&self.canonical_bytes);
        Digest32V2::new(hasher.finalize().into())
    }
}

#[derive(Debug)]
struct DecodedSignedReceiptV2 {
    canonical_payload: Vec<u8>,
    key_id: Ed25519KeyIdV2,
    signature: [u8; 64],
    kind: ExecutorReceiptKindV2,
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

fn verify_dispatch_envelope(
    canonical_envelope: &[u8],
    deployment: &VerifiedExecdDeploymentV2,
    now: UnixMillisV2,
) -> Result<VerifiedSignedDispatchEnvelopeV2, ExecdErrorV2> {
    verify_dispatch_envelope_inner(canonical_envelope, deployment, Some(now))
}

fn verify_persisted_dispatch_envelope(
    canonical_envelope: &[u8],
    deployment: &VerifiedExecdDeploymentV2,
) -> Result<VerifiedSignedDispatchEnvelopeV2, ExecdErrorV2> {
    verify_dispatch_envelope_inner(canonical_envelope, deployment, None)
}

fn verify_dispatch_envelope_inner(
    canonical_envelope: &[u8],
    deployment: &VerifiedExecdDeploymentV2,
    now: Option<UnixMillisV2>,
) -> Result<VerifiedSignedDispatchEnvelopeV2, ExecdErrorV2> {
    #[cfg(not(test))]
    {
        verify_protocol_dispatch_envelope(canonical_envelope, deployment, now)
    }

    #[cfg(test)]
    {
        if let Ok(verified) = verify_protocol_dispatch_envelope(canonical_envelope, deployment, now)
        {
            return Ok(verified);
        }
        if canonical_envelope.is_empty() || canonical_envelope.len() > MAX_ENVELOPE_BYTES {
            return Err(ExecdErrorV2::NonCanonicalEnvelope);
        }
        let mut decoder = minicbor::Decoder::new(canonical_envelope);
        require_array(&mut decoder, 3, ExecdErrorV2::NonCanonicalEnvelope)?;
        let canonical_payload = decoder
            .bytes()
            .map_err(|_| ExecdErrorV2::NonCanonicalEnvelope)?
            .to_vec();
        let key_id = Ed25519KeyIdV2::new(decode_fixed::<32>(
            &mut decoder,
            ExecdErrorV2::NonCanonicalEnvelope,
        )?);
        let signature = decode_fixed::<64>(&mut decoder, ExecdErrorV2::NonCanonicalEnvelope)?;
        if decoder.position() != canonical_envelope.len()
            || encode_signed_object(&canonical_payload, key_id, signature)? != canonical_envelope
        {
            return Err(ExecdErrorV2::NonCanonicalEnvelope);
        }
        if key_id != deployment.kernel_envelope_key_id {
            return Err(ExecdErrorV2::InvalidEnvelopeSignature);
        }
        let digest: [u8; 32] = Sha256::digest(&canonical_payload).into();
        let mut signature_input = Vec::from(SEALED_ENVELOPE_DOMAIN);
        signature_input.extend_from_slice(&digest);
        deployment
            .kernel_envelope_verifying_key
            .verify_strict(&signature_input, &Ed25519Signature::from_bytes(&signature))
            .map_err(|_| ExecdErrorV2::InvalidEnvelopeSignature)?;
        let payload = decode_dispatch_payload(&canonical_payload)?;
        if payload.installation_id != deployment.installation_id
            || payload.active_state_manifest_digest != deployment.active_state_manifest_digest
            || payload.deployment_generation != deployment.deployment_generation
            || payload.effect_fence_epoch != deployment.effect_fence_epoch
            || payload.executor_identity_digest != deployment.executor_identity_digest
        {
            return Err(ExecdErrorV2::DeploymentBinding);
        }
        if let Some(now) = now {
            if now.get() < payload.issued_at.get() || now.get() >= payload.expires_at.get() {
                return Err(ExecdErrorV2::InvalidTime);
            }
        }
        Ok(VerifiedSignedDispatchEnvelopeV2 {
            payload,
            exact_envelope_digest: sha256_digest(canonical_envelope),
            canonical_envelope: Zeroizing::new(canonical_envelope.to_vec()),
        })
    }
}

fn verify_protocol_dispatch_envelope(
    canonical_envelope: &[u8],
    deployment: &VerifiedExecdDeploymentV2,
    now: Option<UnixMillisV2>,
) -> Result<VerifiedSignedDispatchEnvelopeV2, ExecdErrorV2> {
    if canonical_envelope.is_empty() || canonical_envelope.len() > MAX_ENVELOPE_BYTES {
        return Err(ExecdErrorV2::NonCanonicalEnvelope);
    }
    let envelope = decode_signed_sealed_execution_envelope_v2(canonical_envelope)
        .map_err(|_| ExecdErrorV2::NonCanonicalEnvelope)?;
    let executor_identity =
        ExecutorIdentityV2::new(*deployment.executor_identity_digest.as_bytes());
    let payload = envelope
        .verify(
            deployment.kernel_envelope_key_id,
            deployment.kernel_envelope_verifying_key.to_bytes(),
            deployment.installation_id,
            deployment.active_state_manifest_digest,
            deployment.deployment_generation,
            deployment.effect_fence_epoch,
            executor_identity,
            now,
        )
        .map_err(|_| ExecdErrorV2::InvalidEnvelopeSignature)?;
    let core = payload.core();
    let kind = match core.subject() {
        DispatchSubjectV2::ToolExecution { .. } => DispatchEnvelopeKindV2::ToolExecution,
        DispatchSubjectV2::FinalRelease { .. } => DispatchEnvelopeKindV2::FinalRelease,
    };
    let dispatch_core_digest = core
        .semantic_digest()
        .map_err(|_| ExecdErrorV2::NonCanonicalEnvelope)?;
    if payload.dispatch_core_digest() != dispatch_core_digest
        || core.dispatch_subject_digest()
            != core
                .subject()
                .semantic_digest()
                .map_err(|_| ExecdErrorV2::NonCanonicalEnvelope)?
    {
        return Err(ExecdErrorV2::NonCanonicalEnvelope);
    }
    let exact_envelope_digest = sha256_digest(canonical_envelope);
    Ok(VerifiedSignedDispatchEnvelopeV2 {
        payload: DispatchEnvelopePayloadV2 {
            installation_id: core.installation_id(),
            active_state_manifest_digest: core.active_state_manifest_digest(),
            deployment_generation: core.deployment_generation(),
            effect_fence_epoch: core.effect_fence_epoch(),
            executor_identity_digest: deployment.executor_identity_digest,
            kind,
            execution_nonce: core.execution_nonce(),
            dispatch_core_digest,
            dispatch_subject_digest: core.dispatch_subject_digest(),
            #[cfg(test)]
            sealed_envelope_digest: exact_envelope_digest,
            issued_at: UnixMillisV2::new(1),
            expires_at: core.expires_at(),
            #[cfg(test)]
            effect_gate_lease_digest: dispatch_core_digest,
            #[cfg(test)]
            ledger_projection_digest: deployment.active_state_manifest_digest,
        },
        exact_envelope_digest,
        canonical_envelope: Zeroizing::new(canonical_envelope.to_vec()),
    })
}

#[cfg(test)]
fn decode_dispatch_payload(
    canonical_payload: &[u8],
) -> Result<DispatchEnvelopePayloadV2, ExecdErrorV2> {
    let mut decoder = minicbor::Decoder::new(canonical_payload);
    require_array(&mut decoder, 15, ExecdErrorV2::NonCanonicalEnvelope)?;
    if decoder
        .u16()
        .map_err(|_| ExecdErrorV2::NonCanonicalEnvelope)?
        != 2
    {
        return Err(ExecdErrorV2::NonCanonicalEnvelope);
    }
    let payload = DispatchEnvelopePayloadV2 {
        installation_id: Digest32V2::new(decode_fixed::<32>(
            &mut decoder,
            ExecdErrorV2::NonCanonicalEnvelope,
        )?),
        active_state_manifest_digest: Digest32V2::new(decode_fixed::<32>(
            &mut decoder,
            ExecdErrorV2::NonCanonicalEnvelope,
        )?),
        deployment_generation: decoder
            .u64()
            .map_err(|_| ExecdErrorV2::NonCanonicalEnvelope)?,
        effect_fence_epoch: decoder
            .u64()
            .map_err(|_| ExecdErrorV2::NonCanonicalEnvelope)?,
        executor_identity_digest: Digest32V2::new(decode_fixed::<32>(
            &mut decoder,
            ExecdErrorV2::NonCanonicalEnvelope,
        )?),
        kind: DispatchEnvelopeKindV2::from_tag(
            decoder
                .u16()
                .map_err(|_| ExecdErrorV2::NonCanonicalEnvelope)?,
        )?,
        execution_nonce: Nonce32V2::new(decode_fixed::<32>(
            &mut decoder,
            ExecdErrorV2::NonCanonicalEnvelope,
        )?),
        dispatch_core_digest: Digest32V2::new(decode_fixed::<32>(
            &mut decoder,
            ExecdErrorV2::NonCanonicalEnvelope,
        )?),
        dispatch_subject_digest: Digest32V2::new(decode_fixed::<32>(
            &mut decoder,
            ExecdErrorV2::NonCanonicalEnvelope,
        )?),
        sealed_envelope_digest: Digest32V2::new(decode_fixed::<32>(
            &mut decoder,
            ExecdErrorV2::NonCanonicalEnvelope,
        )?),
        issued_at: UnixMillisV2::new(
            decoder
                .u64()
                .map_err(|_| ExecdErrorV2::NonCanonicalEnvelope)?,
        ),
        expires_at: UnixMillisV2::new(
            decoder
                .u64()
                .map_err(|_| ExecdErrorV2::NonCanonicalEnvelope)?,
        ),
        effect_gate_lease_digest: Digest32V2::new(decode_fixed::<32>(
            &mut decoder,
            ExecdErrorV2::NonCanonicalEnvelope,
        )?),
        ledger_projection_digest: Digest32V2::new(decode_fixed::<32>(
            &mut decoder,
            ExecdErrorV2::NonCanonicalEnvelope,
        )?),
    };
    if decoder.position() != canonical_payload.len()
        || encode_dispatch_payload(payload)? != canonical_payload
        || payload.deployment_generation == 0
        || payload.effect_fence_epoch == 0
        || payload.issued_at.get() >= payload.expires_at.get()
        || [
            payload.installation_id.as_bytes(),
            payload.active_state_manifest_digest.as_bytes(),
            payload.executor_identity_digest.as_bytes(),
            payload.execution_nonce.as_bytes(),
            payload.dispatch_core_digest.as_bytes(),
            payload.dispatch_subject_digest.as_bytes(),
            payload.sealed_envelope_digest.as_bytes(),
            payload.effect_gate_lease_digest.as_bytes(),
            payload.ledger_projection_digest.as_bytes(),
        ]
        .iter()
        .any(|bytes| is_zero(bytes))
    {
        return Err(ExecdErrorV2::NonCanonicalEnvelope);
    }
    Ok(payload)
}

#[cfg(test)]
fn encode_dispatch_payload(payload: DispatchEnvelopePayloadV2) -> Result<Vec<u8>, ExecdErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(15)
        .and_then(|encoder| encoder.u16(2))
        .map_err(|_| ExecdErrorV2::AllocationFailure)?;
    payload
        .installation_id
        .encode(&mut encoder, &mut ())
        .map_err(|_| ExecdErrorV2::AllocationFailure)?;
    payload
        .active_state_manifest_digest
        .encode(&mut encoder, &mut ())
        .map_err(|_| ExecdErrorV2::AllocationFailure)?;
    encoder
        .u64(payload.deployment_generation)
        .and_then(|encoder| encoder.u64(payload.effect_fence_epoch))
        .map_err(|_| ExecdErrorV2::AllocationFailure)?;
    payload
        .executor_identity_digest
        .encode(&mut encoder, &mut ())
        .map_err(|_| ExecdErrorV2::AllocationFailure)?;
    encoder
        .u16(payload.kind.tag())
        .map_err(|_| ExecdErrorV2::AllocationFailure)?;
    payload
        .execution_nonce
        .encode(&mut encoder, &mut ())
        .map_err(|_| ExecdErrorV2::AllocationFailure)?;
    payload
        .dispatch_core_digest
        .encode(&mut encoder, &mut ())
        .map_err(|_| ExecdErrorV2::AllocationFailure)?;
    payload
        .dispatch_subject_digest
        .encode(&mut encoder, &mut ())
        .map_err(|_| ExecdErrorV2::AllocationFailure)?;
    payload
        .sealed_envelope_digest
        .encode(&mut encoder, &mut ())
        .map_err(|_| ExecdErrorV2::AllocationFailure)?;
    encoder
        .u64(payload.issued_at.get())
        .and_then(|encoder| encoder.u64(payload.expires_at.get()))
        .map_err(|_| ExecdErrorV2::AllocationFailure)?;
    payload
        .effect_gate_lease_digest
        .encode(&mut encoder, &mut ())
        .map_err(|_| ExecdErrorV2::AllocationFailure)?;
    payload
        .ledger_projection_digest
        .encode(&mut encoder, &mut ())
        .map_err(|_| ExecdErrorV2::AllocationFailure)?;
    Ok(encoder.into_writer())
}

fn sign_receipt(
    entry: &ExecdJournalEntryV2,
    kind: ExecutorReceiptKindV2,
    evidence_digest: Digest32V2,
    issued_at: UnixMillisV2,
    key_id: Ed25519KeyIdV2,
    signing_key: &SigningKey,
) -> Result<SignedExecutorReceiptV2, ExecdErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(11)
        .and_then(|encoder| encoder.u16(2))
        .and_then(|encoder| encoder.u16(kind.tag()))
        .map_err(|_| ExecdErrorV2::AllocationFailure)?;
    entry
        .payload
        .installation_id
        .encode(&mut encoder, &mut ())
        .map_err(|_| ExecdErrorV2::AllocationFailure)?;
    entry
        .payload
        .active_state_manifest_digest
        .encode(&mut encoder, &mut ())
        .map_err(|_| ExecdErrorV2::AllocationFailure)?;
    encoder
        .u64(entry.payload.deployment_generation)
        .and_then(|encoder| encoder.u64(entry.payload.effect_fence_epoch))
        .map_err(|_| ExecdErrorV2::AllocationFailure)?;
    entry
        .payload
        .execution_nonce
        .encode(&mut encoder, &mut ())
        .map_err(|_| ExecdErrorV2::AllocationFailure)?;
    entry
        .payload
        .dispatch_core_digest
        .encode(&mut encoder, &mut ())
        .map_err(|_| ExecdErrorV2::AllocationFailure)?;
    entry
        .payload
        .dispatch_subject_digest
        .encode(&mut encoder, &mut ())
        .map_err(|_| ExecdErrorV2::AllocationFailure)?;
    evidence_digest
        .encode(&mut encoder, &mut ())
        .map_err(|_| ExecdErrorV2::AllocationFailure)?;
    encoder
        .u64(issued_at.get())
        .map_err(|_| ExecdErrorV2::AllocationFailure)?;
    let canonical_payload = encoder.into_writer();
    let digest = receipt_signature_digest(kind, &canonical_payload);
    let mut signature_input = Vec::from(kind.domain());
    signature_input.extend_from_slice(digest.as_bytes());
    let signature = signing_key.sign(&signature_input).to_bytes();
    Ok(SignedExecutorReceiptV2 {
        canonical_bytes: encode_signed_object(&canonical_payload, key_id, signature)?,
        kind,
    })
}

fn sign_effect_started_receipt(
    entry: &ExecdJournalEntryV2,
    predecessor: &ProviderAttemptPredecessorV2,
    started_at: UnixMillisV2,
    key_id: Ed25519KeyIdV2,
    signing_key: &SigningKey,
) -> Result<SignedExecutorEffectStartedReceiptV2, ExecdErrorV2> {
    if predecessor.execution_nonce != entry.payload.execution_nonce {
        return Err(ExecdErrorV2::InvalidReceipt);
    }
    let unsigned = UnsignedExecutorEffectStartedReceiptV2::new(
        entry.payload.installation_id,
        entry.payload.active_state_manifest_digest,
        entry.payload.deployment_generation,
        entry.payload.effect_fence_epoch,
        entry.payload.execution_nonce,
        entry.payload.dispatch_core_digest,
        entry.payload.dispatch_subject_digest,
        ExecutorIdentityV2::new(*entry.payload.executor_identity_digest.as_bytes()),
        predecessor.connector_identity_digest,
        predecessor.external_attempt_ordinal,
        predecessor.connector_codec_job_descriptor_digest,
        predecessor.prepared_request_digest,
        predecessor.predecessor_digest,
        started_at,
    )
    .map_err(|_| ExecdErrorV2::InvalidReceipt)?;
    SignedExecutorEffectStartedReceiptV2::sign(unsigned, key_id, signing_key)
        .map_err(|_| ExecdErrorV2::InvalidReceipt)
}

fn decode_signed_receipt(bytes: &[u8]) -> Result<DecodedSignedReceiptV2, ExecdErrorV2> {
    let mut decoder = minicbor::Decoder::new(bytes);
    require_array(&mut decoder, 3, ExecdErrorV2::InvalidReceipt)?;
    let canonical_payload = decoder
        .bytes()
        .map_err(|_| ExecdErrorV2::InvalidReceipt)?
        .to_vec();
    let key_id = Ed25519KeyIdV2::new(decode_fixed::<32>(
        &mut decoder,
        ExecdErrorV2::InvalidReceipt,
    )?);
    let signature = decode_fixed::<64>(&mut decoder, ExecdErrorV2::InvalidReceipt)?;
    if decoder.position() != bytes.len()
        || encode_signed_object(&canonical_payload, key_id, signature)? != bytes
    {
        return Err(ExecdErrorV2::InvalidReceipt);
    }
    let mut payload_decoder = minicbor::Decoder::new(&canonical_payload);
    require_array(&mut payload_decoder, 11, ExecdErrorV2::InvalidReceipt)?;
    if payload_decoder
        .u16()
        .map_err(|_| ExecdErrorV2::InvalidReceipt)?
        != 2
    {
        return Err(ExecdErrorV2::InvalidReceipt);
    }
    let kind = ExecutorReceiptKindV2::from_tag(
        payload_decoder
            .u16()
            .map_err(|_| ExecdErrorV2::InvalidReceipt)?,
    )?;
    let installation_id = Digest32V2::new(decode_fixed::<32>(
        &mut payload_decoder,
        ExecdErrorV2::InvalidReceipt,
    )?);
    let active_state_manifest_digest = Digest32V2::new(decode_fixed::<32>(
        &mut payload_decoder,
        ExecdErrorV2::InvalidReceipt,
    )?);
    let deployment_generation = payload_decoder
        .u64()
        .map_err(|_| ExecdErrorV2::InvalidReceipt)?;
    let effect_fence_epoch = payload_decoder
        .u64()
        .map_err(|_| ExecdErrorV2::InvalidReceipt)?;
    let execution_nonce = Nonce32V2::new(decode_fixed::<32>(
        &mut payload_decoder,
        ExecdErrorV2::InvalidReceipt,
    )?);
    let dispatch_core_digest = Digest32V2::new(decode_fixed::<32>(
        &mut payload_decoder,
        ExecdErrorV2::InvalidReceipt,
    )?);
    let dispatch_subject_digest = Digest32V2::new(decode_fixed::<32>(
        &mut payload_decoder,
        ExecdErrorV2::InvalidReceipt,
    )?);
    let evidence_digest = Digest32V2::new(decode_fixed::<32>(
        &mut payload_decoder,
        ExecdErrorV2::InvalidReceipt,
    )?);
    let issued_at = UnixMillisV2::new(
        payload_decoder
            .u64()
            .map_err(|_| ExecdErrorV2::InvalidReceipt)?,
    );
    if payload_decoder.position() != canonical_payload.len()
        || deployment_generation == 0
        || effect_fence_epoch == 0
        || issued_at.get() == 0
        || [
            installation_id.as_bytes(),
            active_state_manifest_digest.as_bytes(),
            execution_nonce.as_bytes(),
            dispatch_core_digest.as_bytes(),
            dispatch_subject_digest.as_bytes(),
            evidence_digest.as_bytes(),
        ]
        .iter()
        .any(|bytes| is_zero(bytes))
    {
        return Err(ExecdErrorV2::InvalidReceipt);
    }
    Ok(DecodedSignedReceiptV2 {
        canonical_payload,
        key_id,
        signature,
        kind,
        installation_id,
        active_state_manifest_digest,
        deployment_generation,
        effect_fence_epoch,
        execution_nonce,
        dispatch_core_digest,
        dispatch_subject_digest,
        evidence_digest,
        issued_at,
    })
}

fn encode_signed_object(
    canonical_payload: &[u8],
    key_id: Ed25519KeyIdV2,
    signature: [u8; 64],
) -> Result<Vec<u8>, ExecdErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(3)
        .and_then(|encoder| encoder.bytes(canonical_payload))
        .map_err(|_| ExecdErrorV2::AllocationFailure)?;
    key_id
        .encode(&mut encoder, &mut ())
        .map_err(|_| ExecdErrorV2::AllocationFailure)?;
    encoder
        .bytes(&signature)
        .map_err(|_| ExecdErrorV2::AllocationFailure)?;
    Ok(encoder.into_writer())
}

fn provider_attempt_predecessor_digest(
    nonce: Nonce32V2,
    core_digest: Digest32V2,
    subject_digest: Digest32V2,
    prepared_request_digest: Digest32V2,
    now: UnixMillisV2,
) -> Digest32V2 {
    let mut hasher = Sha256::new();
    hasher.update(b"SAVANA_PROVIDER_ATTEMPT_PREPARED_V2\0");
    hasher.update(nonce.as_bytes());
    hasher.update(core_digest.as_bytes());
    hasher.update(subject_digest.as_bytes());
    hasher.update(prepared_request_digest.as_bytes());
    hasher.update(now.get().to_be_bytes());
    Digest32V2::new(hasher.finalize().into())
}

fn ensure_live(entry: &ExecdJournalEntryV2, now: UnixMillisV2) -> Result<(), ExecdErrorV2> {
    if now.get() < entry.payload.issued_at.get() || now.get() >= entry.payload.expires_at.get() {
        return Err(ExecdErrorV2::InvalidTime);
    }
    Ok(())
}

fn project_entry(entry: &ExecdJournalEntryV2) -> ExecdQueryV2 {
    let retained_provider_response_digest = entry
        .retained_provider_response
        .as_ref()
        .map(|bytes| crate::worker_protocol::connector_response_digest(bytes));
    let retained_provider_response_length = entry
        .retained_provider_response
        .as_ref()
        .and_then(|bytes| u32::try_from(bytes.len()).ok());
    ExecdQueryV2 {
        execution_nonce: entry.payload.execution_nonce,
        dispatch_core_digest: entry.payload.dispatch_core_digest,
        dispatch_subject_digest: entry.payload.dispatch_subject_digest,
        kind: entry.payload.kind,
        state: entry.state,
        failure_class: entry.failure_class,
        prepared_request_digest: entry.prepared_request_digest,
        retained_provider_response_digest,
        retained_provider_response_length,
    }
}

fn require_array(
    decoder: &mut minicbor::Decoder<'_>,
    expected: u64,
    error: ExecdErrorV2,
) -> Result<(), ExecdErrorV2> {
    if decoder.array().map_err(|_| error)? != Some(expected) {
        return Err(error);
    }
    Ok(())
}

fn decode_fixed<const N: usize>(
    decoder: &mut minicbor::Decoder<'_>,
    error: ExecdErrorV2,
) -> Result<[u8; N], ExecdErrorV2> {
    decoder
        .bytes()
        .map_err(|_| error)?
        .try_into()
        .map_err(|_| error)
}

fn sha256_digest(bytes: &[u8]) -> Digest32V2 {
    Digest32V2::new(Sha256::digest(bytes).into())
}

fn domain_hash_parts(domain: &[u8], parts: &[&[u8]]) -> Digest32V2 {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for part in parts {
        hasher.update(part);
    }
    Digest32V2::new(hasher.finalize().into())
}

fn receipt_signature_digest(kind: ExecutorReceiptKindV2, canonical_payload: &[u8]) -> Digest32V2 {
    let mut hasher = Sha256::new();
    hasher.update(kind.domain());
    hasher.update(canonical_payload);
    Digest32V2::new(hasher.finalize().into())
}

fn is_zero<const N: usize>(bytes: &[u8; N]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

#[cfg(test)]
mod tests {
    use chacha20poly1305::aead::{Aead as _, Payload};
    use chacha20poly1305::{ChaCha20Poly1305, KeyInit as _, Nonce};
    use std::fs::{self, File, OpenOptions};
    use std::os::unix::fs::PermissionsExt as _;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use ed25519_dalek::{Signer as _, SigningKey};
    use hkdf::Hkdf;
    use minicbor::Encode as _;
    use savana_kernel_protocol::v2::{
        encode_signed_sealed_execution_envelope_v2, ActionIntentIdV2, AttemptKindV2,
        BoundedCiphertextV2, Digest32V2, DispatchCoreV2, DispatchRequestV2, DispatchSubjectV2,
        DurableReleaseIdV2, DurableRunIdV2, DurableTaskIdV2, Ed25519KeyIdV2,
        EffectLedgerProjectionBindingV2, ExecutorFailureClassV2, ExecutorIdentityV2,
        FinalReleaseSemanticBindingV2, FixedBytes32V2, HpkeX25519KeyIdV2, InternalStepIdV2,
        KernelExecutorOperationV2, Nonce32V2, PlanRevisionDigestV2,
        SealedExecutionEnvelopePayloadV2, SignedExecutorEffectStartedReceiptV2,
        SignedSealedExecutionEnvelopeV2, ToolExecutionSemanticBindingV2, UnixMillisV2,
    };
    use savana_policy_core::v2::{
        DurableStateNamespaceV2, G4Error, RollbackProtectedStateAnchorV2,
        RollbackProtectedStateHeadV2,
    };
    use sha2::{Digest as _, Sha256};
    use zeroize::Zeroizing;

    use super::{
        DispatchEnvelopeKindV2, DurableExecdNamespaceV2, DurableExecdServiceV2,
        EffectGatedExecdRuntimeV2, ExecdConnectorRegistryTrustV2, ExecdConnectorRegistryV2,
        ExecdErrorV2, ExecdJournalStateV2, ExecdQueryV2, ExecdRollbackAnchorV2,
        ExecdRuntimeErrorV2, ExecdServiceV2, ExecdStateHeadV2, ExecdStateOwnerErrorV2,
        ExecdStateOwnerV2, VerifiedExecdDeploymentV2,
    };
    use crate::protocol_service::{
        hpke_x25519_key_id, ExecdProtocolDeploymentV2, ExecdProtocolServiceErrorV2,
        ExecdProtocolServiceV2, PreparedConnectorDispatchV2, PreparedDispatchProcessorV2,
    };

    const ENVELOPE_DOMAIN: &[u8] = b"SAVANA_SEALED_EXECUTION_ENVELOPE_V2\0";
    const EFFECT_PROJECTION_DOMAIN: &[u8] = b"SAVANA_EFFECT_LEDGER_PROJECTION_SIGNATURE_V2\0";

    #[derive(Clone, Copy)]
    struct Fixture {
        installation: Digest32V2,
        manifest: Digest32V2,
        kernel_key_id: Ed25519KeyIdV2,
        receipt_key_id: Ed25519KeyIdV2,
        executor_identity: Digest32V2,
    }

    fn fixture() -> (Fixture, SigningKey, SigningKey, VerifiedExecdDeploymentV2) {
        let kernel_key = SigningKey::from_bytes(&[0x31; 32]);
        let receipt_key = SigningKey::from_bytes(&[0x32; 32]);
        let values = Fixture {
            installation: Digest32V2::new([0x11; 32]),
            manifest: Digest32V2::new([0x12; 32]),
            kernel_key_id: savana_kernel_protocol::v2::derive_ed25519_key_id_v2(
                kernel_key.verifying_key().to_bytes(),
            ),
            receipt_key_id: savana_kernel_protocol::v2::derive_ed25519_key_id_v2(
                receipt_key.verifying_key().to_bytes(),
            ),
            executor_identity: Digest32V2::new([0x15; 32]),
        };
        let deployment = VerifiedExecdDeploymentV2::from_verified_manifest(
            values.installation,
            values.manifest,
            7,
            9,
            values.executor_identity,
            values.kernel_key_id,
            kernel_key.verifying_key().to_bytes(),
            values.receipt_key_id,
            receipt_key.to_bytes(),
        )
        .unwrap();
        (values, kernel_key, receipt_key, deployment)
    }

    fn signed_envelope(
        values: Fixture,
        kernel_key: &SigningKey,
        nonce: Nonce32V2,
        kind: DispatchEnvelopeKindV2,
        subject_seed: u8,
    ) -> Vec<u8> {
        signed_envelope_at_fence(values, kernel_key, nonce, kind, subject_seed, 9)
    }

    #[test]
    fn protocol_owned_dispatch_envelope_is_admitted_and_replayed_exactly() {
        let (values, kernel_key, _, deployment) = fixture();
        let binding = ToolExecutionSemanticBindingV2::new(
            PlanRevisionDigestV2::new([0x41; 32]),
            InternalStepIdV2::new([0x42; 32]),
            Digest32V2::new([0x43; 32]),
            Digest32V2::new([0x44; 32]),
            Digest32V2::new([0x45; 32]),
            Digest32V2::new([0x46; 32]),
            Digest32V2::new([0x47; 32]),
            Digest32V2::new([0x48; 32]),
            Digest32V2::new([0x49; 32]),
            values.executor_identity,
            AttemptKindV2::new(1),
        )
        .unwrap();
        let nonce = Nonce32V2::new([0x4a; 32]);
        let core = DispatchCoreV2::new(
            values.installation,
            values.manifest,
            7,
            9,
            DurableTaskIdV2::new([0x4b; 32]),
            DurableRunIdV2::new([0x4c; 32]),
            nonce,
            DispatchSubjectV2::tool_execution(ActionIntentIdV2::new([0x4d; 32]), binding, None)
                .unwrap(),
            ExecutorIdentityV2::new(*values.executor_identity.as_bytes()),
            HpkeX25519KeyIdV2::new([0x4e; 32]),
            Digest32V2::new([0x4f; 32]),
            UnixMillisV2::new(10_000),
        )
        .unwrap();
        let envelope = SignedSealedExecutionEnvelopeV2::sign(
            SealedExecutionEnvelopePayloadV2::new(
                core,
                Digest32V2::new([0x4f; 32]),
                FixedBytes32V2::new([0x50; 32]),
                BoundedCiphertextV2::new(vec![0x51; 64]).unwrap(),
            )
            .unwrap(),
            &kernel_key,
        )
        .unwrap();
        let canonical = encode_signed_sealed_execution_envelope_v2(&envelope).unwrap();
        let mut service = ExecdServiceV2::new(deployment);
        let first = service
            .accept_signed_dispatch(&canonical, UnixMillisV2::new(200))
            .unwrap();
        let replay = service
            .accept_signed_dispatch(&canonical, UnixMillisV2::new(201))
            .unwrap();
        assert_eq!(first, replay);
        assert_eq!(first.execution_nonce(), nonce);
        assert_eq!(first.state(), ExecdJournalStateV2::Prepared);
    }

    fn signed_envelope_at_fence(
        values: Fixture,
        kernel_key: &SigningKey,
        nonce: Nonce32V2,
        kind: DispatchEnvelopeKindV2,
        subject_seed: u8,
        effect_fence_epoch: u64,
    ) -> Vec<u8> {
        let mut payload = minicbor::Encoder::new(Vec::new());
        payload.array(15).unwrap().u16(2).unwrap();
        values.installation.encode(&mut payload, &mut ()).unwrap();
        values.manifest.encode(&mut payload, &mut ()).unwrap();
        payload.u64(7).unwrap().u64(effect_fence_epoch).unwrap();
        values
            .executor_identity
            .encode(&mut payload, &mut ())
            .unwrap();
        payload.u16(kind.tag()).unwrap();
        nonce.encode(&mut payload, &mut ()).unwrap();
        Digest32V2::new([0x21; 32])
            .encode(&mut payload, &mut ())
            .unwrap();
        Digest32V2::new([subject_seed; 32])
            .encode(&mut payload, &mut ())
            .unwrap();
        Digest32V2::new([0x23; 32])
            .encode(&mut payload, &mut ())
            .unwrap();
        payload.u64(100).unwrap().u64(10_000).unwrap();
        Digest32V2::new([0x24; 32])
            .encode(&mut payload, &mut ())
            .unwrap();
        Digest32V2::new([0x25; 32])
            .encode(&mut payload, &mut ())
            .unwrap();
        let payload = payload.into_writer();
        let digest: [u8; 32] = Sha256::digest(&payload).into();
        let mut signature_input = Vec::from(ENVELOPE_DOMAIN);
        signature_input.extend_from_slice(&digest);
        let signature = kernel_key.sign(&signature_input).to_bytes();
        let mut outer = minicbor::Encoder::new(Vec::new());
        outer.array(3).unwrap().bytes(&payload).unwrap();
        values.kernel_key_id.encode(&mut outer, &mut ()).unwrap();
        outer.bytes(&signature).unwrap();
        outer.into_writer()
    }

    fn effect_gate_fixture(
        root: &std::path::Path,
        values: Fixture,
    ) -> (
        File,
        File,
        EffectLedgerProjectionBindingV2,
        std::path::PathBuf,
        SigningKey,
    ) {
        let gate_path = root.join("effect-gate-v2");
        fs::write(&gate_path, []).unwrap();
        let gate = OpenOptions::new().read(true).open(gate_path).unwrap();

        let projection_key = SigningKey::from_bytes(&[0xd1; 32]);
        let projection_key_id = Ed25519KeyIdV2::new([0xd2; 32]);
        let binding = EffectLedgerProjectionBindingV2::from_verified_deployment(
            values.installation,
            values.manifest,
            7,
            9,
            Digest32V2::new([0xd3; 32]),
            Digest32V2::new([0xd4; 32]),
            projection_key_id,
            projection_key.verifying_key().to_bytes(),
        )
        .unwrap();
        let projection_path = root.join("effect-ledger-projection-v2.cbor");
        fs::write(
            &projection_path,
            signed_effect_projection(&projection_key, binding, false),
        )
        .unwrap();
        let projection = OpenOptions::new()
            .read(true)
            .open(&projection_path)
            .unwrap();
        (gate, projection, binding, projection_path, projection_key)
    }

    fn signed_effect_projection(
        projection_key: &SigningKey,
        binding: EffectLedgerProjectionBindingV2,
        effects_fenced: bool,
    ) -> Vec<u8> {
        let mut payload = minicbor::Encoder::new(Vec::new());
        payload
            .array(11)
            .unwrap()
            .u16(2)
            .unwrap()
            .bytes(binding.installation_id().as_bytes())
            .unwrap()
            .bytes(binding.active_state_manifest_digest().as_bytes())
            .unwrap()
            .u64(binding.deployment_generation())
            .unwrap()
            .u64(binding.effect_fence_epoch())
            .unwrap()
            .bytes(binding.projection_identity().as_bytes())
            .unwrap()
            .bytes(binding.authenticated_head_digest().as_bytes())
            .unwrap()
            .bool(effects_fenced)
            .unwrap()
            .bool(true)
            .unwrap()
            .bytes(&[0xd5; 32])
            .unwrap()
            .bytes(&[0; 32])
            .unwrap();
        let payload = payload.into_writer();
        let digest: [u8; 32] = Sha256::digest(&payload).into();
        let mut signature_input = Vec::from(EFFECT_PROJECTION_DOMAIN);
        signature_input.extend_from_slice(&digest);
        let signature = projection_key.sign(&signature_input).to_bytes();
        let mut outer = minicbor::Encoder::new(Vec::new());
        outer
            .array(3)
            .unwrap()
            .bytes(&payload)
            .unwrap()
            .bytes(binding.signing_key_id().as_bytes())
            .unwrap()
            .bytes(&signature)
            .unwrap();
        outer.into_writer()
    }

    #[derive(Clone, Default)]
    struct TestAnchor(Arc<Mutex<ExecdStateHeadV2>>);

    impl ExecdRollbackAnchorV2 for TestAnchor {
        fn current_head(&self) -> Result<ExecdStateHeadV2, ExecdErrorV2> {
            self.0
                .lock()
                .map(|head| *head)
                .map_err(|_| ExecdErrorV2::DurableState)
        }

        fn compare_and_advance(
            &mut self,
            expected: ExecdStateHeadV2,
            next: ExecdStateHeadV2,
        ) -> Result<(), ExecdErrorV2> {
            let mut head = self.0.lock().map_err(|_| ExecdErrorV2::DurableState)?;
            if *head != expected {
                return Err(ExecdErrorV2::RollbackDetected);
            }
            *head = next;
            Ok(())
        }
    }

    #[derive(Clone)]
    struct ConnectorTestAnchor(Arc<Mutex<RollbackProtectedStateHeadV2>>);

    impl Default for ConnectorTestAnchor {
        fn default() -> Self {
            Self(Arc::new(Mutex::new(
                RollbackProtectedStateHeadV2::new(0, Digest32V2::new([0; 32])).unwrap(),
            )))
        }
    }

    impl RollbackProtectedStateAnchorV2 for ConnectorTestAnchor {
        fn current_head(&self) -> Result<RollbackProtectedStateHeadV2, G4Error> {
            self.0
                .lock()
                .map(|head| *head)
                .map_err(|_| G4Error::StateConflict)
        }

        fn compare_and_advance(
            &mut self,
            expected: RollbackProtectedStateHeadV2,
            next: RollbackProtectedStateHeadV2,
        ) -> Result<(), G4Error> {
            let mut head = self.0.lock().map_err(|_| G4Error::StateConflict)?;
            if *head != expected || next.sequence() != expected.sequence().saturating_add(1) {
                return Err(G4Error::DurableStateRollback);
            }
            *head = next;
            Ok(())
        }
    }

    struct CountingDispatchProcessorV2(Arc<AtomicUsize>);

    impl PreparedDispatchProcessorV2 for CountingDispatchProcessorV2 {
        fn is_ready(&self) -> bool {
            true
        }

        fn process(
            &self,
            _owner: &ExecdStateOwnerV2,
            _query: ExecdQueryV2,
            _payload: Zeroizing<Vec<u8>>,
            _connector: Option<&PreparedConnectorDispatchV2>,
            _now: UnixMillisV2,
            _deadline: Instant,
        ) -> Result<(), ExecdProtocolServiceErrorV2> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn recover(
            &self,
            _owner: &ExecdStateOwnerV2,
            _query: ExecdQueryV2,
            _now: UnixMillisV2,
            _deadline: Instant,
        ) -> Result<(), ExecdProtocolServiceErrorV2> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    struct FailingBeforeEffectProcessorV2(Arc<AtomicUsize>);

    impl PreparedDispatchProcessorV2 for FailingBeforeEffectProcessorV2 {
        fn is_ready(&self) -> bool {
            true
        }

        fn process(
            &self,
            _owner: &ExecdStateOwnerV2,
            _query: ExecdQueryV2,
            _payload: Zeroizing<Vec<u8>>,
            _connector: Option<&PreparedConnectorDispatchV2>,
            _now: UnixMillisV2,
            _deadline: Instant,
        ) -> Result<(), ExecdProtocolServiceErrorV2> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(ExecdProtocolServiceErrorV2::Binding)
        }

        fn recover(
            &self,
            _owner: &ExecdStateOwnerV2,
            _query: ExecdQueryV2,
            _now: UnixMillisV2,
            _deadline: Instant,
        ) -> Result<(), ExecdProtocolServiceErrorV2> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(ExecdProtocolServiceErrorV2::Binding)
        }
    }

    struct ExpiringBeforeEffectProcessorV2;

    impl PreparedDispatchProcessorV2 for ExpiringBeforeEffectProcessorV2 {
        fn is_ready(&self) -> bool {
            true
        }

        fn process(
            &self,
            _owner: &ExecdStateOwnerV2,
            _query: ExecdQueryV2,
            _payload: Zeroizing<Vec<u8>>,
            _connector: Option<&PreparedConnectorDispatchV2>,
            _now: UnixMillisV2,
            deadline: Instant,
        ) -> Result<(), ExecdProtocolServiceErrorV2> {
            if let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
                std::thread::sleep(remaining + Duration::from_millis(5));
            }
            Err(ExecdProtocolServiceErrorV2::Binding)
        }

        fn recover(
            &self,
            _owner: &ExecdStateOwnerV2,
            _query: ExecdQueryV2,
            _now: UnixMillisV2,
            _deadline: Instant,
        ) -> Result<(), ExecdProtocolServiceErrorV2> {
            Err(ExecdProtocolServiceErrorV2::Binding)
        }
    }

    fn protocol_registry_fixture(
        root: &std::path::Path,
        registry_genesis: Digest32V2,
    ) -> (
        Fixture,
        SigningKey,
        HpkeX25519KeyIdV2,
        [u8; 32],
        ExecdProtocolDeploymentV2,
        ExecdStateOwnerV2,
        Arc<ExecdConnectorRegistryV2>,
    ) {
        let journal_path = root.join("execd-journal-v2.cbor");
        let registry_path = root.join("connector-registry-v2.cbor");
        let (values, kernel_key, _, deployment) = fixture();
        let seal_private_key = [0xd1; 32];
        let seal_public_key =
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(seal_private_key))
                .to_bytes();
        let seal_key_id = hpke_x25519_key_id(seal_public_key);
        let protocol_deployment = ExecdProtocolDeploymentV2::from_verified_deployment(
            &deployment,
            seal_key_id,
            seal_private_key,
            1,
            1,
            registry_genesis,
        )
        .unwrap();
        let (gate, projection, projection_binding, _, _) = effect_gate_fixture(root, values);
        let owner = ExecdStateOwnerV2::open(
            &journal_path,
            [0xd2; 32],
            DurableExecdNamespaceV2::from_verified_installation(
                values.installation,
                Digest32V2::new([0xd3; 32]),
            )
            .unwrap(),
            Box::new(TestAnchor::default()),
            deployment,
            gate,
            projection,
            projection_binding,
            Instant::now() + Duration::from_secs(1),
            16,
        )
        .unwrap();
        let registry = Arc::new(
            ExecdConnectorRegistryV2::open(
                &registry_path,
                [0xd4; 32],
                DurableStateNamespaceV2::from_verified_installation(
                    values.installation,
                    Digest32V2::new([0xd5; 32]),
                )
                .unwrap(),
                Box::new(ConnectorTestAnchor::default()),
                ExecdConnectorRegistryTrustV2::from_authenticated_deployment(
                    values.installation,
                    values.manifest,
                    7,
                    registry_genesis,
                    Ed25519KeyIdV2::new([0; 32]),
                    [0; 32],
                    vec![],
                    vec![],
                )
                .unwrap(),
            )
            .unwrap(),
        );
        (
            values,
            kernel_key,
            seal_key_id,
            seal_public_key,
            protocol_deployment,
            owner,
            registry,
        )
    }

    fn sealed_registry_dispatch_request(
        values: Fixture,
        kernel_key: &SigningKey,
        seal_key_id: HpkeX25519KeyIdV2,
        seal_public_key: [u8; 32],
        registry_head: Digest32V2,
        nonce: Nonce32V2,
    ) -> DispatchRequestV2 {
        let binding = ToolExecutionSemanticBindingV2::new(
            PlanRevisionDigestV2::new([0xd6; 32]),
            InternalStepIdV2::new([0xd7; 32]),
            Digest32V2::new([0xd8; 32]),
            Digest32V2::new([0xd9; 32]),
            Digest32V2::new([0xda; 32]),
            Digest32V2::new([0xdb; 32]),
            Digest32V2::new([0xdc; 32]),
            Digest32V2::new([0xdd; 32]),
            Digest32V2::new([0xde; 32]),
            values.executor_identity,
            AttemptKindV2::new(1),
        )
        .unwrap();
        let core = DispatchCoreV2::new(
            values.installation,
            values.manifest,
            7,
            9,
            DurableTaskIdV2::new([0xdf; 32]),
            DurableRunIdV2::new([0xe0; 32]),
            nonce,
            DispatchSubjectV2::tool_execution(ActionIntentIdV2::new([0xe1; 32]), binding, None)
                .unwrap(),
            ExecutorIdentityV2::new(*values.executor_identity.as_bytes()),
            seal_key_id,
            registry_head,
            UnixMillisV2::new(10_000),
        )
        .unwrap();
        let core_digest = core.semantic_digest().unwrap();
        let ephemeral_secret = x25519_dalek::StaticSecret::from([0xe2; 32]);
        let ephemeral_public = x25519_dalek::PublicKey::from(&ephemeral_secret).to_bytes();
        let shared = ephemeral_secret
            .diffie_hellman(&x25519_dalek::PublicKey::from(seal_public_key))
            .to_bytes();
        let mut key_nonce = [0_u8; 44];
        let mut info = Vec::new();
        info.extend_from_slice(b"SAVANA_EXECUTION_HPKE_X25519_CHACHA20POLY1305_V2\0");
        info.extend_from_slice(&ephemeral_public);
        info.extend_from_slice(&seal_public_key);
        Hkdf::<Sha256>::new(Some(core_digest.as_bytes()), &shared)
            .expand(&info, &mut key_nonce)
            .unwrap();
        let plaintext = b"credential-free connector material";
        let ciphertext = ChaCha20Poly1305::new_from_slice(&key_nonce[..32])
            .unwrap()
            .encrypt(
                Nonce::from_slice(&key_nonce[32..]),
                Payload {
                    msg: plaintext,
                    aad: core_digest.as_bytes(),
                },
            )
            .unwrap();
        DispatchRequestV2::new(
            SignedSealedExecutionEnvelopeV2::sign(
                SealedExecutionEnvelopePayloadV2::new(
                    core,
                    Digest32V2::new([0xe3; 32]),
                    FixedBytes32V2::new(ephemeral_public),
                    BoundedCiphertextV2::new(ciphertext).unwrap(),
                )
                .unwrap(),
                kernel_key,
            )
            .unwrap(),
        )
    }

    #[test]
    fn deterministic_processor_preflight_failure_is_terminal_before_registry_guard_release() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let genesis = Digest32V2::new([0xe4; 32]);
        let (values, kernel_key, seal_key_id, seal_public_key, deployment, owner, registry) =
            protocol_registry_fixture(root.path(), genesis);
        let calls = Arc::new(AtomicUsize::new(0));
        let service = ExecdProtocolServiceV2::new_with_connector_registry(
            deployment,
            owner,
            Box::new(FailingBeforeEffectProcessorV2(Arc::clone(&calls))),
            registry,
        )
        .unwrap();
        let nonce = Nonce32V2::new([0xe5; 32]);
        let request = sealed_registry_dispatch_request(
            values,
            &kernel_key,
            seal_key_id,
            seal_public_key,
            genesis,
            nonce,
        );

        service
            .execute(
                KernelExecutorOperationV2::Dispatch(request),
                UnixMillisV2::new(200),
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();

        let projection = service
            .recovery_projection_for_test(Instant::now() + Duration::from_secs(1))
            .unwrap();
        let query = projection
            .iter()
            .find(|query| query.execution_nonce() == nonce)
            .unwrap();
        assert_eq!(query.state(), ExecdJournalStateV2::FailedNoEffect);
        assert_eq!(
            query.failure_class(),
            Some(ExecutorFailureClassV2::ConnectorUnavailableBeforeEffect)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn expired_effect_deadline_uses_bounded_owner_cleanup_to_terminalize_before_guard_release() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let genesis = Digest32V2::new([0xea; 32]);
        let (values, kernel_key, seal_key_id, seal_public_key, deployment, owner, registry) =
            protocol_registry_fixture(root.path(), genesis);
        let service = ExecdProtocolServiceV2::new_with_connector_registry(
            deployment,
            owner,
            Box::new(ExpiringBeforeEffectProcessorV2),
            registry,
        )
        .unwrap();
        let nonce = Nonce32V2::new([0xeb; 32]);
        let request = sealed_registry_dispatch_request(
            values,
            &kernel_key,
            seal_key_id,
            seal_public_key,
            genesis,
            nonce,
        );

        service
            .execute(
                KernelExecutorOperationV2::Dispatch(request),
                UnixMillisV2::new(200),
                Instant::now() + Duration::from_millis(100),
            )
            .unwrap();

        let query = service
            .recovery_projection_for_test(Instant::now() + Duration::from_secs(1))
            .unwrap()
            .into_iter()
            .find(|query| query.execution_nonce() == nonce)
            .unwrap();
        assert_eq!(query.state(), ExecdJournalStateV2::FailedNoEffect);
        assert_eq!(
            query.failure_class(),
            Some(ExecutorFailureClassV2::ConnectorUnavailableBeforeEffect)
        );
    }

    #[test]
    fn stale_prepared_head_terminalizes_on_restart_but_poisoned_registry_aborts_recovery() {
        for poisoned in [false, true] {
            let root = tempfile::tempdir().unwrap();
            fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
            let genesis = Digest32V2::new([0xe6; 32]);
            let (values, kernel_key, seal_key_id, seal_public_key, deployment, owner, registry) =
                protocol_registry_fixture(root.path(), genesis);
            let nonce = Nonce32V2::new([if poisoned { 0xe7 } else { 0xe8 }; 32]);
            let recorded_head = if poisoned {
                genesis
            } else {
                Digest32V2::new([0xe9; 32])
            };
            let request = sealed_registry_dispatch_request(
                values,
                &kernel_key,
                seal_key_id,
                seal_public_key,
                recorded_head,
                nonce,
            );
            owner
                .accept_signed_dispatch(
                    encode_signed_sealed_execution_envelope_v2(request.envelope()).unwrap(),
                    UnixMillisV2::new(200),
                    Instant::now() + Duration::from_secs(1),
                )
                .unwrap();
            if poisoned {
                registry.poison_for_test();
            }
            let calls = Arc::new(AtomicUsize::new(0));
            let result = ExecdProtocolServiceV2::recover_prepared_with_connector_registry(
                &deployment,
                &owner,
                &CountingDispatchProcessorV2(Arc::clone(&calls)),
                &registry,
                UnixMillisV2::new(210),
                Instant::now() + Duration::from_secs(1),
            );
            let query = owner
                .query(nonce, Instant::now() + Duration::from_secs(1))
                .unwrap();
            if poisoned {
                assert!(result.is_err());
                assert_eq!(query.state(), ExecdJournalStateV2::Prepared);
            } else {
                result.unwrap();
                assert_eq!(query.state(), ExecdJournalStateV2::FailedNoEffect);
                assert_eq!(
                    query.failure_class(),
                    Some(ExecutorFailureClassV2::ConnectorUnavailableBeforeEffect)
                );
            }
            assert_eq!(calls.load(Ordering::SeqCst), 0);
        }
    }

    fn stale_registry_dispatch_request(
        values: Fixture,
        kernel_key: &SigningKey,
        seal_key_id: HpkeX25519KeyIdV2,
        nonce: Nonce32V2,
        subject: DispatchSubjectV2,
    ) -> DispatchRequestV2 {
        let core = DispatchCoreV2::new(
            values.installation,
            values.manifest,
            7,
            9,
            DurableTaskIdV2::new([0xf1; 32]),
            DurableRunIdV2::new([0xf2; 32]),
            nonce,
            subject,
            ExecutorIdentityV2::new(*values.executor_identity.as_bytes()),
            seal_key_id,
            Digest32V2::new([0xf3; 32]),
            UnixMillisV2::new(10_000),
        )
        .unwrap();
        DispatchRequestV2::new(
            SignedSealedExecutionEnvelopeV2::sign(
                SealedExecutionEnvelopePayloadV2::new(
                    core,
                    Digest32V2::new([0xf4; 32]),
                    FixedBytes32V2::new([0xf5; 32]),
                    BoundedCiphertextV2::new(vec![0xf6; 64]).unwrap(),
                )
                .unwrap(),
                kernel_key,
            )
            .unwrap(),
        )
    }

    #[test]
    fn stale_registry_head_refuses_tool_and_release_before_journal_or_effect_mutation() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let journal_path = root.path().join("execd-journal-v2.cbor");
        let registry_path = root.path().join("connector-registry-v2.cbor");
        let (values, kernel_key, _, deployment) = fixture();
        let seal_private_key = [0xf7; 32];
        let seal_public_key =
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(seal_private_key))
                .to_bytes();
        let seal_key_id = hpke_x25519_key_id(seal_public_key);
        let registry_genesis = Digest32V2::new([0xf8; 32]);
        let protocol_deployment = ExecdProtocolDeploymentV2::from_verified_deployment(
            &deployment,
            seal_key_id,
            seal_private_key,
            1,
            1,
            registry_genesis,
        )
        .unwrap();
        let (gate, projection, projection_binding, _, _) = effect_gate_fixture(root.path(), values);
        let owner = ExecdStateOwnerV2::open(
            &journal_path,
            [0xf9; 32],
            DurableExecdNamespaceV2::from_verified_installation(
                values.installation,
                Digest32V2::new([0xfa; 32]),
            )
            .unwrap(),
            Box::new(TestAnchor::default()),
            deployment,
            gate,
            projection,
            projection_binding,
            Instant::now() + Duration::from_secs(1),
            16,
        )
        .unwrap();
        let connector_registry = Arc::new(
            ExecdConnectorRegistryV2::open(
                &registry_path,
                [0xfb; 32],
                DurableStateNamespaceV2::from_verified_installation(
                    values.installation,
                    Digest32V2::new([0xfc; 32]),
                )
                .unwrap(),
                Box::new(ConnectorTestAnchor::default()),
                ExecdConnectorRegistryTrustV2::from_authenticated_deployment(
                    values.installation,
                    values.manifest,
                    7,
                    registry_genesis,
                    Ed25519KeyIdV2::new([0; 32]),
                    [0; 32],
                    vec![],
                    vec![],
                )
                .unwrap(),
            )
            .unwrap(),
        );
        let processor_calls = Arc::new(AtomicUsize::new(0));
        let service = ExecdProtocolServiceV2::new_with_connector_registry(
            protocol_deployment,
            owner,
            Box::new(CountingDispatchProcessorV2(Arc::clone(&processor_calls))),
            connector_registry,
        )
        .unwrap();
        let journal_before = fs::read(&journal_path).ok();

        let tool_binding = ToolExecutionSemanticBindingV2::new(
            PlanRevisionDigestV2::new([0x81; 32]),
            InternalStepIdV2::new([0x82; 32]),
            Digest32V2::new([0x83; 32]),
            Digest32V2::new([0x84; 32]),
            Digest32V2::new([0x85; 32]),
            Digest32V2::new([0x86; 32]),
            Digest32V2::new([0x87; 32]),
            Digest32V2::new([0x88; 32]),
            Digest32V2::new([0x89; 32]),
            values.executor_identity,
            AttemptKindV2::new(1),
        )
        .unwrap();
        let tool = stale_registry_dispatch_request(
            values,
            &kernel_key,
            seal_key_id,
            Nonce32V2::new([0x8a; 32]),
            DispatchSubjectV2::tool_execution(
                ActionIntentIdV2::new([0x8b; 32]),
                tool_binding,
                None,
            )
            .unwrap(),
        );
        assert_eq!(
            service.execute(
                KernelExecutorOperationV2::Dispatch(tool),
                UnixMillisV2::new(200),
                Instant::now() + Duration::from_secs(1),
            ),
            Err(ExecdProtocolServiceErrorV2::Binding)
        );

        let release_binding = FinalReleaseSemanticBindingV2::from_nonzero_components(
            DurableReleaseIdV2::new([0x91; 32]),
            Digest32V2::new([0x92; 32]),
            Digest32V2::new([0x93; 32]),
            Digest32V2::new([0x94; 32]),
            Digest32V2::new([0x95; 32]),
            Digest32V2::new([0x96; 32]),
            Digest32V2::new([0x97; 32]),
            Digest32V2::new([0x98; 32]),
            Digest32V2::new([0x99; 32]),
            values.executor_identity,
            Digest32V2::new([0x9a; 32]),
        )
        .unwrap();
        let release = stale_registry_dispatch_request(
            values,
            &kernel_key,
            seal_key_id,
            Nonce32V2::new([0x9b; 32]),
            DispatchSubjectV2::final_release(release_binding, Digest32V2::new([0x9c; 32])).unwrap(),
        );
        assert_eq!(
            service.execute(
                KernelExecutorOperationV2::Dispatch(release),
                UnixMillisV2::new(201),
                Instant::now() + Duration::from_secs(1),
            ),
            Err(ExecdProtocolServiceErrorV2::Binding)
        );
        assert!(service
            .recovery_projection_for_test(Instant::now() + Duration::from_secs(1))
            .unwrap()
            .is_empty());
        assert_eq!(service.active_effect_guard_count_for_test(), 0);
        assert_eq!(processor_calls.load(Ordering::SeqCst), 0);
        assert_eq!(fs::read(journal_path).ok(), journal_before);
    }

    #[test]
    fn signed_dispatch_is_exactly_replayable_but_nonce_rebinding_is_rejected() {
        let (values, kernel_key, _, deployment) = fixture();
        let mut service = ExecdServiceV2::new(deployment);
        let nonce = Nonce32V2::new([0x41; 32]);
        let envelope = signed_envelope(
            values,
            &kernel_key,
            nonce,
            DispatchEnvelopeKindV2::ToolExecution,
            0x42,
        );

        let first = service
            .accept_signed_dispatch(&envelope, UnixMillisV2::new(200))
            .unwrap();
        let replay = service
            .accept_signed_dispatch(&envelope, UnixMillisV2::new(201))
            .unwrap();
        assert_eq!(first, replay);
        assert_eq!(first.state(), ExecdJournalStateV2::Prepared);

        let rebound = signed_envelope(
            values,
            &kernel_key,
            nonce,
            DispatchEnvelopeKindV2::ToolExecution,
            0x43,
        );
        assert_eq!(
            service
                .accept_signed_dispatch(&rebound, UnixMillisV2::new(202))
                .unwrap_err(),
            ExecdErrorV2::NonceRebinding
        );
    }

    #[test]
    fn recovery_projection_is_capability_free_and_strictly_nonce_sorted() {
        let (values, kernel_key, _, deployment) = fixture();
        let mut service = ExecdServiceV2::new(deployment);
        for (nonce_seed, subject_seed) in [(0x52, 0x62), (0x51, 0x61)] {
            let envelope = signed_envelope(
                values,
                &kernel_key,
                Nonce32V2::new([nonce_seed; 32]),
                DispatchEnvelopeKindV2::ToolExecution,
                subject_seed,
            );
            service
                .accept_signed_dispatch(&envelope, UnixMillisV2::new(200))
                .unwrap();
        }

        let projection = service.recovery_projection().unwrap();

        assert_eq!(projection.len(), 2);
        assert_eq!(projection[0].execution_nonce(), Nonce32V2::new([0x51; 32]));
        assert_eq!(projection[1].execution_nonce(), Nonce32V2::new([0x52; 32]));
        assert_eq!(projection[0].state(), ExecdJournalStateV2::Prepared);
    }

    #[test]
    fn stale_fence_and_cross_subject_substitution_fail_closed() {
        let (values, kernel_key, _, deployment) = fixture();
        let mut service = ExecdServiceV2::new(deployment);
        let stale = signed_envelope_at_fence(
            values,
            &kernel_key,
            Nonce32V2::new([0x51; 32]),
            DispatchEnvelopeKindV2::FinalRelease,
            0x52,
            10,
        );
        assert_eq!(
            service
                .accept_signed_dispatch(&stale, UnixMillisV2::new(200))
                .unwrap_err(),
            ExecdErrorV2::DeploymentBinding
        );
    }

    #[test]
    fn effect_permit_exists_only_after_signed_receipt_is_durable_in_the_journal() {
        let (values, kernel_key, receipt_key, deployment) = fixture();
        let receipt_public = receipt_key.verifying_key();
        let mut service = ExecdServiceV2::new(deployment);
        let nonce = Nonce32V2::new([0x61; 32]);
        let envelope = signed_envelope(
            values,
            &kernel_key,
            nonce,
            DispatchEnvelopeKindV2::ToolExecution,
            0x62,
        );
        service
            .accept_signed_dispatch(&envelope, UnixMillisV2::new(200))
            .unwrap();

        let predecessor = service
            .prepare_provider_attempt(nonce, Digest32V2::new([0x63; 32]), UnixMillisV2::new(210))
            .unwrap();
        let armed = service
            .record_effect_started(predecessor, UnixMillisV2::new(211))
            .unwrap();
        assert_eq!(armed.execution_nonce(), nonce);
        assert_eq!(
            service.query(nonce).unwrap().state(),
            ExecdJournalStateV2::EffectStarted
        );
        armed
            .receipt()
            .verify(values.receipt_key_id, receipt_public.to_bytes())
            .unwrap();
        let protocol_receipt = SignedExecutorEffectStartedReceiptV2::from_canonical_bytes(
            &armed.receipt().canonical_bytes().unwrap(),
        )
        .unwrap();
        protocol_receipt
            .verify(values.receipt_key_id, receipt_public.to_bytes())
            .unwrap();
        assert_eq!(protocol_receipt.unsigned().execution_nonce(), nonce);

        assert_eq!(
            service
                .prepare_provider_attempt(
                    nonce,
                    Digest32V2::new([0x63; 32]),
                    UnixMillisV2::new(212),
                )
                .unwrap_err(),
            ExecdErrorV2::IllegalTransition
        );
    }

    #[test]
    fn typed_terminal_receipts_are_one_way_and_subject_bound() {
        let (values, kernel_key, receipt_key, deployment) = fixture();
        let mut service = ExecdServiceV2::new(deployment);
        let nonce = Nonce32V2::new([0x71; 32]);
        let envelope = signed_envelope(
            values,
            &kernel_key,
            nonce,
            DispatchEnvelopeKindV2::FinalRelease,
            0x72,
        );
        service
            .accept_signed_dispatch(&envelope, UnixMillisV2::new(200))
            .unwrap();
        let predecessor = service
            .prepare_provider_attempt(nonce, Digest32V2::new([0x73; 32]), UnixMillisV2::new(210))
            .unwrap();
        let _armed = service
            .record_effect_started(predecessor, UnixMillisV2::new(211))
            .unwrap();
        service
            .record_provider_response(nonce, b"provider response".to_vec())
            .unwrap();
        let completion = service
            .record_known_success(nonce, Digest32V2::new([0x74; 32]), UnixMillisV2::new(220))
            .unwrap();
        assert_eq!(
            service.terminal_receipt(nonce).unwrap().canonical_bytes(),
            completion.canonical_bytes()
        );
        completion
            .verify(values.receipt_key_id, &receipt_key.verifying_key())
            .unwrap();
        assert_eq!(
            service.query(nonce).unwrap().state(),
            ExecdJournalStateV2::CompletionAvailable
        );
        assert_eq!(
            service
                .record_failed_no_effect(
                    nonce,
                    ExecutorFailureClassV2::ResourceFailureBeforeEffect,
                    Digest32V2::new([0x75; 32]),
                    UnixMillisV2::new(221),
                )
                .unwrap_err(),
            ExecdErrorV2::IllegalTransition
        );
    }

    #[test]
    fn typed_tool_completion_is_distinct_from_provider_response_and_survives_codec_round_trip() {
        let (values, kernel_key, _, deployment) = fixture();
        let mut service = ExecdServiceV2::new(deployment);
        let nonce = Nonce32V2::new([0x76; 32]);
        let envelope = signed_envelope(
            values,
            &kernel_key,
            nonce,
            DispatchEnvelopeKindV2::ToolExecution,
            0x77,
        );
        service
            .accept_signed_dispatch(&envelope, UnixMillisV2::new(200))
            .unwrap();
        let predecessor = service
            .prepare_provider_attempt(nonce, Digest32V2::new([0x78; 32]), UnixMillisV2::new(210))
            .unwrap();
        service
            .record_effect_started(predecessor, UnixMillisV2::new(211))
            .unwrap();
        service
            .record_provider_response(nonce, b"opaque provider response".to_vec())
            .unwrap();

        let stored = service
            .record_tool_completion(
                nonce,
                b"decoded tool result".to_vec(),
                Digest32V2::new([0x79; 32]),
                UnixMillisV2::new(220),
            )
            .unwrap();
        let decoded = savana_kernel_protocol::v2::decode_executor_completion_payload_v2(
            stored.canonical_payload(),
        )
        .unwrap();
        assert_eq!(decoded.descriptor().unwrap(), stored.descriptor());
        assert_eq!(
            service.completion(nonce).unwrap().canonical_payload(),
            stored.canonical_payload()
        );
        assert_ne!(
            service.retained_provider_response(nonce).unwrap().bytes(),
            stored.canonical_payload()
        );
    }

    #[test]
    fn typed_final_release_completion_binds_release_receipt_and_audit_evidence() {
        let (values, kernel_key, receipt_key, deployment) = fixture();
        let nonce = Nonce32V2::new([0x7a; 32]);
        let binding = FinalReleaseSemanticBindingV2::from_nonzero_components(
            savana_kernel_protocol::v2::DurableReleaseIdV2::new([0x7b; 32]),
            Digest32V2::new([0x7c; 32]),
            Digest32V2::new([0x7d; 32]),
            Digest32V2::new([0x7e; 32]),
            Digest32V2::new([0x7f; 32]),
            Digest32V2::new([0x80; 32]),
            Digest32V2::new([0x81; 32]),
            Digest32V2::new([0x82; 32]),
            Digest32V2::new([0x83; 32]),
            values.executor_identity,
            Digest32V2::new([0x84; 32]),
        )
        .unwrap();
        let subject =
            DispatchSubjectV2::final_release(binding, Digest32V2::new([0x85; 32])).unwrap();
        let core = DispatchCoreV2::new(
            values.installation,
            values.manifest,
            7,
            9,
            DurableTaskIdV2::new([0x86; 32]),
            DurableRunIdV2::new([0x87; 32]),
            nonce,
            subject,
            ExecutorIdentityV2::new(*values.executor_identity.as_bytes()),
            HpkeX25519KeyIdV2::new([0x88; 32]),
            Digest32V2::new([0x89; 32]),
            UnixMillisV2::new(1_000),
        )
        .unwrap();
        let payload = SealedExecutionEnvelopePayloadV2::new(
            core,
            Digest32V2::new([0x89; 32]),
            FixedBytes32V2::new([0x8a; 32]),
            BoundedCiphertextV2::new(vec![0x8b; 64]).unwrap(),
        )
        .unwrap();
        let envelope = SignedSealedExecutionEnvelopeV2::sign(payload, &kernel_key).unwrap();
        let encoded = encode_signed_sealed_execution_envelope_v2(&envelope).unwrap();
        let mut service = ExecdServiceV2::new(deployment);
        service
            .accept_signed_dispatch(&encoded, UnixMillisV2::new(200))
            .unwrap();
        let predecessor = service
            .prepare_provider_attempt(nonce, Digest32V2::new([0x8c; 32]), UnixMillisV2::new(210))
            .unwrap();
        service
            .record_effect_started(predecessor, UnixMillisV2::new(211))
            .unwrap();
        service
            .record_provider_response(nonce, b"provider response".to_vec())
            .unwrap();
        let prepared_digest = service
            .prepare_final_release_evidence(
                nonce,
                b"provider evidence".to_vec(),
                vec![0x81, 0x02],
                UnixMillisV2::new(220),
            )
            .unwrap();
        let stored = service
            .record_final_release_completion(nonce, UnixMillisV2::new(221))
            .unwrap();
        let completion = savana_kernel_protocol::v2::decode_executor_completion_payload_v2(
            stored.canonical_payload(),
        )
        .unwrap();
        match completion {
            savana_kernel_protocol::v2::ExecutorCompletionPayloadV2::FinalReleaseReceipt {
                receipt,
                ..
            } => {
                receipt
                    .verify(
                        values.receipt_key_id,
                        receipt_key.verifying_key().to_bytes(),
                    )
                    .unwrap();
                assert_eq!(receipt.unsigned().execution_nonce(), nonce);
                assert_eq!(
                    receipt.unsigned().durable_release_id(),
                    binding.durable_release_id()
                );
                assert_eq!(
                    receipt
                        .unsigned()
                        .release_evidence_prepared_journal_record_digest(),
                    prepared_digest
                );
            }
            _ => panic!("final release produced a tool completion"),
        }
        assert!(matches!(
            stored.descriptor(),
            savana_kernel_protocol::v2::ExecutorCompletionDescriptorV2::FinalReleaseReceipt { .. }
        ));
    }

    #[test]
    fn encrypted_durable_journal_survives_restart_without_replacing_nonce() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.path().join("execd-journal-v2.cbor");
        let anchor = TestAnchor::default();
        let namespace = DurableExecdNamespaceV2::from_verified_installation(
            Digest32V2::new([0x11; 32]),
            Digest32V2::new([0x82; 32]),
        )
        .unwrap();
        let (values, kernel_key, _, deployment) = fixture();
        let nonce = Nonce32V2::new([0x83; 32]);
        let envelope = signed_envelope(
            values,
            &kernel_key,
            nonce,
            DispatchEnvelopeKindV2::ToolExecution,
            0x84,
        );
        {
            let mut durable = DurableExecdServiceV2::open(
                &path,
                [0x85; 32],
                namespace,
                Box::new(anchor.clone()),
                deployment,
            )
            .unwrap();
            durable
                .accept_signed_dispatch(&envelope, UnixMillisV2::new(200))
                .unwrap();
            let predecessor = durable
                .prepare_provider_attempt(
                    nonce,
                    Digest32V2::new([0x86; 32]),
                    UnixMillisV2::new(210),
                )
                .unwrap();
            durable
                .record_effect_started(predecessor, UnixMillisV2::new(211))
                .unwrap();
        }
        let (_, _, _, deployment) = fixture();
        let mut reopened =
            DurableExecdServiceV2::open(&path, [0x85; 32], namespace, Box::new(anchor), deployment)
                .unwrap();
        assert_eq!(
            reopened.query(nonce).unwrap().state(),
            ExecdJournalStateV2::EffectStarted
        );
        assert_eq!(
            reopened
                .accept_signed_dispatch(&envelope, UnixMillisV2::new(220))
                .unwrap()
                .execution_nonce(),
            nonce
        );
        let persisted = fs::read(path).unwrap();
        assert!(!persisted
            .windows(nonce.as_bytes().len())
            .any(|window| window == nonce.as_bytes()));
    }

    #[test]
    fn retained_provider_response_is_encrypted_idempotent_and_survives_restart() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.path().join("execd-journal-v2.cbor");
        let anchor = TestAnchor::default();
        let namespace = DurableExecdNamespaceV2::from_verified_installation(
            Digest32V2::new([0x11; 32]),
            Digest32V2::new([0x87; 32]),
        )
        .unwrap();
        let (values, kernel_key, _, deployment) = fixture();
        let nonce = Nonce32V2::new([0x88; 32]);
        let envelope = signed_envelope(
            values,
            &kernel_key,
            nonce,
            DispatchEnvelopeKindV2::ToolExecution,
            0x89,
        );
        let response = b"secret provider response that must not appear in the journal";
        let expected_digest = crate::worker_protocol::connector_response_digest(response);
        {
            let mut durable = DurableExecdServiceV2::open(
                &path,
                [0x8a; 32],
                namespace,
                Box::new(anchor.clone()),
                deployment,
            )
            .unwrap();
            durable
                .accept_signed_dispatch(&envelope, UnixMillisV2::new(200))
                .unwrap();
            let predecessor = durable
                .prepare_provider_attempt(
                    nonce,
                    Digest32V2::new([0x8b; 32]),
                    UnixMillisV2::new(210),
                )
                .unwrap();
            durable
                .record_effect_started(predecessor, UnixMillisV2::new(211))
                .unwrap();

            let retained = durable
                .record_provider_response(nonce, response.to_vec())
                .unwrap();
            assert_eq!(retained.digest(), expected_digest);
            assert_eq!(retained.bytes(), response);
            assert_eq!(
                durable
                    .record_provider_response(nonce, response.to_vec())
                    .unwrap()
                    .digest(),
                expected_digest
            );
            assert_eq!(
                durable
                    .record_provider_response(nonce, b"rebound response".to_vec())
                    .unwrap_err(),
                ExecdErrorV2::NonceRebinding
            );
            let projection = durable.query(nonce).unwrap();
            assert_eq!(
                projection.retained_provider_response_digest(),
                Some(expected_digest)
            );
            assert_eq!(
                projection.retained_provider_response_length(),
                Some(response.len() as u32)
            );
        }

        let persisted = fs::read(&path).unwrap();
        assert!(!persisted
            .windows(response.len())
            .any(|window| window == response));

        let (_, _, _, deployment) = fixture();
        let reopened =
            DurableExecdServiceV2::open(&path, [0x8a; 32], namespace, Box::new(anchor), deployment)
                .unwrap();
        let retained = reopened.retained_provider_response(nonce).unwrap();
        assert_eq!(retained.bytes(), response);
        assert_eq!(retained.digest(), expected_digest);
    }

    #[test]
    fn typed_tool_completion_survives_encrypted_restart() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.path().join("execd-journal-v2.cbor");
        let anchor = TestAnchor::default();
        let namespace = DurableExecdNamespaceV2::from_verified_installation(
            Digest32V2::new([0x11; 32]),
            Digest32V2::new([0x90; 32]),
        )
        .unwrap();
        let (values, kernel_key, _, deployment) = fixture();
        let nonce = Nonce32V2::new([0x91; 32]);
        let envelope = signed_envelope(
            values,
            &kernel_key,
            nonce,
            DispatchEnvelopeKindV2::ToolExecution,
            0x92,
        );
        let expected = {
            let mut durable = DurableExecdServiceV2::open(
                &path,
                [0x93; 32],
                namespace,
                Box::new(anchor.clone()),
                deployment,
            )
            .unwrap();
            durable
                .accept_signed_dispatch(&envelope, UnixMillisV2::new(200))
                .unwrap();
            let predecessor = durable
                .prepare_provider_attempt(
                    nonce,
                    Digest32V2::new([0x94; 32]),
                    UnixMillisV2::new(210),
                )
                .unwrap();
            durable
                .record_effect_started(predecessor, UnixMillisV2::new(211))
                .unwrap();
            durable
                .record_provider_response(nonce, b"provider response".to_vec())
                .unwrap();
            durable
                .record_tool_completion(
                    nonce,
                    b"typed result".to_vec(),
                    Digest32V2::new([0x95; 32]),
                    UnixMillisV2::new(220),
                )
                .unwrap()
        };

        let (_, _, _, deployment) = fixture();
        let reopened =
            DurableExecdServiceV2::open(&path, [0x93; 32], namespace, Box::new(anchor), deployment)
                .unwrap();
        let recovered = reopened.completion(nonce).unwrap();
        assert_eq!(recovered.descriptor(), expected.descriptor());
        assert_eq!(recovered.canonical_payload(), expected.canonical_payload());
        assert_eq!(
            reopened.query(nonce).unwrap().state(),
            ExecdJournalStateV2::CompletionAvailable
        );
    }

    #[test]
    fn recovery_terminalizes_an_expired_unstarted_dispatch_without_reissuing_it() {
        let (values, kernel_key, receipt_key, deployment) = fixture();
        let mut service = ExecdServiceV2::new(deployment);
        let nonce = Nonce32V2::new([0x8c; 32]);
        service
            .accept_signed_dispatch(
                &signed_envelope(
                    values,
                    &kernel_key,
                    nonce,
                    DispatchEnvelopeKindV2::ToolExecution,
                    0x8d,
                ),
                UnixMillisV2::new(200),
            )
            .unwrap();
        assert_eq!(
            service
                .record_failed_no_effect(
                    nonce,
                    ExecutorFailureClassV2::ResourceFailureBeforeEffect,
                    Digest32V2::new([0x8e; 32]),
                    UnixMillisV2::new(10_001),
                )
                .unwrap_err(),
            ExecdErrorV2::InvalidTime
        );

        let receipt = service
            .record_failed_no_effect_recovery(
                nonce,
                ExecutorFailureClassV2::ResourceFailureBeforeEffect,
                Digest32V2::new([0x8e; 32]),
                UnixMillisV2::new(10_001),
            )
            .unwrap();

        receipt
            .verify(values.receipt_key_id, &receipt_key.verifying_key())
            .unwrap();
        assert_eq!(
            service.query(nonce).unwrap().state(),
            ExecdJournalStateV2::FailedNoEffect
        );
    }

    #[test]
    fn production_runtime_holds_effect_gate_from_prepared_through_durable_terminal_receipt() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let journal_path = root.path().join("execd-journal-v2.cbor");
        let namespace = DurableExecdNamespaceV2::from_verified_installation(
            Digest32V2::new([0x11; 32]),
            Digest32V2::new([0xa2; 32]),
        )
        .unwrap();
        let (values, kernel_key, _, deployment) = fixture();
        let (gate, projection, projection_binding, _, _) = effect_gate_fixture(root.path(), values);
        let owner = ExecdStateOwnerV2::open(
            &journal_path,
            [0xa3; 32],
            namespace,
            Box::new(TestAnchor::default()),
            deployment,
            gate,
            projection,
            projection_binding,
            Instant::now() + Duration::from_secs(1),
            16,
        )
        .unwrap();
        let nonce = Nonce32V2::new([0xa4; 32]);
        let envelope = signed_envelope(
            values,
            &kernel_key,
            nonce,
            DispatchEnvelopeKindV2::ToolExecution,
            0xa5,
        );

        owner
            .accept_signed_dispatch(
                envelope.clone(),
                UnixMillisV2::new(200),
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
        assert_eq!(owner.active_guard_count_for_test(), 1);
        assert_eq!(
            owner
                .accept_signed_dispatch(
                    envelope,
                    UnixMillisV2::new(201),
                    Instant::now() + Duration::from_secs(1),
                )
                .unwrap()
                .execution_nonce(),
            nonce
        );
        assert_eq!(owner.active_guard_count_for_test(), 1);
        let predecessor = owner
            .prepare_provider_attempt(
                nonce,
                Digest32V2::new([0xa6; 32]),
                UnixMillisV2::new(210),
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
        let _armed = owner
            .record_effect_started(
                predecessor,
                UnixMillisV2::new(211),
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
        owner
            .record_provider_response(
                nonce,
                b"provider response".to_vec(),
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
        assert_eq!(owner.active_guard_count_for_test(), 1);
        owner
            .record_known_success(
                nonce,
                Digest32V2::new([0xa7; 32]),
                UnixMillisV2::new(220),
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
        assert_eq!(owner.active_guard_count_for_test(), 0);
        assert_eq!(
            owner
                .query(nonce, Instant::now() + Duration::from_secs(1))
                .unwrap()
                .state(),
            ExecdJournalStateV2::CompletionAvailable
        );
    }

    #[test]
    fn production_runtime_reacquires_effect_gate_for_unresolved_restart_entries() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let journal_path = root.path().join("execd-journal-v2.cbor");
        let anchor = TestAnchor::default();
        let namespace = DurableExecdNamespaceV2::from_verified_installation(
            Digest32V2::new([0x11; 32]),
            Digest32V2::new([0xb2; 32]),
        )
        .unwrap();
        let (values, kernel_key, _, deployment) = fixture();
        let nonce = Nonce32V2::new([0xb3; 32]);
        let envelope = signed_envelope(
            values,
            &kernel_key,
            nonce,
            DispatchEnvelopeKindV2::FinalRelease,
            0xb4,
        );
        {
            let mut durable = DurableExecdServiceV2::open(
                &journal_path,
                [0xb5; 32],
                namespace,
                Box::new(anchor.clone()),
                deployment,
            )
            .unwrap();
            durable
                .accept_signed_dispatch(&envelope, UnixMillisV2::new(200))
                .unwrap();
            let predecessor = durable
                .prepare_provider_attempt(
                    nonce,
                    Digest32V2::new([0xb6; 32]),
                    UnixMillisV2::new(210),
                )
                .unwrap();
            durable
                .record_effect_started(predecessor, UnixMillisV2::new(211))
                .unwrap();
        }
        let (values, _, _, deployment) = fixture();
        let durable = DurableExecdServiceV2::open(
            &journal_path,
            [0xb5; 32],
            namespace,
            Box::new(anchor),
            deployment,
        )
        .unwrap();
        let (gate, projection, projection_binding, _, _) = effect_gate_fixture(root.path(), values);
        let mut runtime = EffectGatedExecdRuntimeV2::from_durable_service(
            durable,
            gate,
            projection,
            projection_binding,
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap();

        assert_eq!(runtime.active_guard_count_for_test(), 1);
        runtime
            .record_indeterminate(nonce, Digest32V2::new([0xb7; 32]), UnixMillisV2::new(220))
            .unwrap();
        assert_eq!(runtime.active_guard_count_for_test(), 0);
    }

    #[test]
    fn production_runtime_rereads_projection_after_each_zero_to_one_gate_transition() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let journal_path = root.path().join("execd-journal-v2.cbor");
        let namespace = DurableExecdNamespaceV2::from_verified_installation(
            Digest32V2::new([0x11; 32]),
            Digest32V2::new([0xc2; 32]),
        )
        .unwrap();
        let (values, kernel_key, _, deployment) = fixture();
        let (gate, projection, projection_binding, projection_path, projection_key) =
            effect_gate_fixture(root.path(), values);
        let owner = ExecdStateOwnerV2::open(
            &journal_path,
            [0xc3; 32],
            namespace,
            Box::new(TestAnchor::default()),
            deployment,
            gate,
            projection,
            projection_binding,
            Instant::now() + Duration::from_secs(1),
            16,
        )
        .unwrap();
        let first_nonce = Nonce32V2::new([0xc4; 32]);
        owner
            .accept_signed_dispatch(
                signed_envelope(
                    values,
                    &kernel_key,
                    first_nonce,
                    DispatchEnvelopeKindV2::ToolExecution,
                    0xc5,
                ),
                UnixMillisV2::new(200),
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
        owner
            .record_failed_no_effect(
                first_nonce,
                ExecutorFailureClassV2::ResourceFailureBeforeEffect,
                Digest32V2::new([0xc6; 32]),
                UnixMillisV2::new(201),
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();

        fs::write(
            projection_path,
            signed_effect_projection(&projection_key, projection_binding, true),
        )
        .unwrap();
        let second_nonce = Nonce32V2::new([0xc7; 32]);
        assert_eq!(
            owner
                .accept_signed_dispatch(
                    signed_envelope(
                        values,
                        &kernel_key,
                        second_nonce,
                        DispatchEnvelopeKindV2::ToolExecution,
                        0xc8,
                    ),
                    UnixMillisV2::new(202),
                    Instant::now() + Duration::from_secs(1),
                )
                .unwrap_err(),
            ExecdStateOwnerErrorV2::Runtime(ExecdRuntimeErrorV2::Fenced)
        );
        assert_eq!(
            owner
                .query(second_nonce, Instant::now() + Duration::from_secs(1))
                .unwrap_err(),
            ExecdStateOwnerErrorV2::Runtime(ExecdRuntimeErrorV2::Journal(ExecdErrorV2::NotFound))
        );
    }

    #[test]
    fn authenticated_snapshot_rollback_and_namespace_substitution_are_rejected() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.path().join("execd-journal-v2.cbor");
        let anchor = TestAnchor::default();
        let namespace = DurableExecdNamespaceV2::from_verified_installation(
            Digest32V2::new([0x11; 32]),
            Digest32V2::new([0x92; 32]),
        )
        .unwrap();
        let (values, kernel_key, _, deployment) = fixture();
        let first_nonce = Nonce32V2::new([0x93; 32]);
        let first = signed_envelope(
            values,
            &kernel_key,
            first_nonce,
            DispatchEnvelopeKindV2::ToolExecution,
            0x94,
        );
        let old_bytes;
        {
            let mut durable = DurableExecdServiceV2::open(
                &path,
                [0x95; 32],
                namespace,
                Box::new(anchor.clone()),
                deployment,
            )
            .unwrap();
            durable
                .accept_signed_dispatch(&first, UnixMillisV2::new(200))
                .unwrap();
            old_bytes = fs::read(&path).unwrap();
            let second = signed_envelope(
                values,
                &kernel_key,
                Nonce32V2::new([0x96; 32]),
                DispatchEnvelopeKindV2::FinalRelease,
                0x97,
            );
            durable
                .accept_signed_dispatch(&second, UnixMillisV2::new(201))
                .unwrap();
        }
        fs::write(&path, old_bytes).unwrap();
        let (_, _, _, deployment) = fixture();
        assert_eq!(
            DurableExecdServiceV2::open(
                &path,
                [0x95; 32],
                namespace,
                Box::new(anchor.clone()),
                deployment,
            )
            .unwrap_err(),
            ExecdErrorV2::RollbackDetected
        );

        let (_, _, _, deployment) = fixture();
        let wrong_namespace = DurableExecdNamespaceV2::from_verified_installation(
            Digest32V2::new([0x11; 32]),
            Digest32V2::new([0x98; 32]),
        )
        .unwrap();
        assert!(matches!(
            DurableExecdServiceV2::open(
                &path,
                [0x95; 32],
                wrong_namespace,
                Box::new(TestAnchor::default()),
                deployment,
            ),
            Err(ExecdErrorV2::DurableAuthentication | ExecdErrorV2::RollbackDetected)
        ));
    }
}
