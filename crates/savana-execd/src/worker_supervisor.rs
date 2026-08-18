use std::time::Instant;

use savana_kernel_protocol::v2::{Digest32V2, Nonce32V2, UnixMillisV2};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use savana_policy_core::v2::{
    BoundedConnectorHostV2, BoundedConnectorUrlV2, ConnectorTierV2, ConnectorTransportV2,
};

use crate::worker_protocol::{
    connector_material_digest, connector_response_digest, connector_transcript_begin,
    connector_transcript_step, decode_connector_worker_frame, encode_provider_response_frame,
    prepared_provider_request_digest, verify_connector_worker_job, ConnectorCodecJobModeV2,
    ConnectorOutcomeKindV2, ConnectorWorkerFrameV2, ConnectorWorkerProtocolErrorV2,
    PreparedProviderRequestFrameV2, VerifiedConnectorWorkerJobV2, VerifiedConnectorWorkerTrustV2,
    MAX_CONNECTOR_FRAME_BYTES,
};
use crate::{
    ArmedEffectV2, EffectPermitV2, ExecdJournalStateV2, ExecdQueryV2, ExecdStateOwnerV2,
    ProviderAttemptPredecessorV2, RetainedProviderResponseV2,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ConnectorWorkerSupervisorErrorV2 {
    #[error("a verified connector sandbox launcher is unavailable")]
    SandboxUnavailable,
    #[error("the connector worker could not be launched")]
    LaunchFailed,
    #[error("the connector worker deadline was exceeded")]
    DeadlineExceeded,
    #[error("the connector worker violated its one-job protocol")]
    ProtocolViolation,
    #[error("the connector worker protocol failed")]
    Protocol(ConnectorWorkerProtocolErrorV2),
    #[error("the durable provider attempt failed")]
    ProviderAttemptFailed,
}

pub(crate) enum ConnectorWorkerInputV2<'a> {
    Prepare {
        credential_free_material: &'a [u8],
    },
    DecodeRetainedResponse {
        retained_provider_response: &'a [u8],
        effect_started_receipt_digest: Digest32V2,
    },
}

pub(crate) trait ConnectorWorkerChildV2: Send {
    fn send_job(
        &mut self,
        canonical_descriptor: &[u8],
        input: ConnectorWorkerInputV2<'_>,
        deadline: Instant,
    ) -> Result<(), ConnectorWorkerSupervisorErrorV2>;

    fn receive_frame(
        &mut self,
        deadline: Instant,
    ) -> Result<Option<Vec<u8>>, ConnectorWorkerSupervisorErrorV2>;

    fn send_provider_response(
        &mut self,
        canonical_frame: &[u8],
        deadline: Instant,
    ) -> Result<(), ConnectorWorkerSupervisorErrorV2>;

    fn finish_after_terminal(
        &mut self,
        deadline: Instant,
    ) -> Result<(), ConnectorWorkerSupervisorErrorV2>;

    fn kill_and_reap(&mut self);
}

pub(crate) trait VerifiedConnectorSandboxLauncherV2: Send + Sync {
    fn launch_one_job(
        &self,
        job: &VerifiedConnectorWorkerJobV2,
        ephemeral_signing_seed: Zeroizing<[u8; 32]>,
        deadline: Instant,
    ) -> Result<Box<dyn ConnectorWorkerChildV2>, ConnectorWorkerSupervisorErrorV2>;
}

/// The implementation must persist the effect-start receipt before the first
/// provider byte and persist the complete response before returning it.
pub(crate) trait DurableProviderAttemptV2 {
    fn execute_and_retain(
        &mut self,
        job: &VerifiedConnectorWorkerJobV2,
        prepared: &PreparedProviderRequestFrameV2,
        deadline: Instant,
    ) -> Result<DurablyRetainedProviderResponseV2, ConnectorWorkerSupervisorErrorV2>;
}

/// Credential-bearing transport owned by execd. The codec worker never
/// receives this object or any credential material.
pub(crate) trait ProviderTransportV2: Send {
    /// Returns the manifest-bound provider target used by the pre-existing
    /// deployment connector/release path.
    fn verified_deployment_target(
        &self,
    ) -> Result<VerifiedProviderTargetV2, ConnectorWorkerSupervisorErrorV2>;

    /// Resolves one active registry descriptor against the provisioned
    /// transport before the durable attempt can cross EffectStarted.
    fn verify_connector_target(
        &self,
        tier: ConnectorTierV2,
        transport: &ConnectorTransportV2,
        active_host_allowlist: &[BoundedConnectorHostV2],
    ) -> Result<VerifiedProviderTargetV2, ConnectorWorkerSupervisorErrorV2>;

    fn execute(
        &mut self,
        request: &VerifiedProviderRequestV2,
        permit: &EffectPermitV2,
        maximum_response_bytes: u32,
        deadline: Instant,
    ) -> Result<Vec<u8>, ConnectorWorkerSupervisorErrorV2>;
}

/// An exact registry transport that has already matched measured provider
/// provisioning and current standing policy. Callers cannot populate it from
/// a claimed digest or URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifiedProviderTargetV2 {
    canonical_url: BoundedConnectorUrlV2,
    tls_identity_pin: Digest32V2,
}

impl VerifiedProviderTargetV2 {
    pub(super) fn https(
        canonical_url: BoundedConnectorUrlV2,
        tls_identity_pin: Digest32V2,
    ) -> Result<Self, ConnectorWorkerSupervisorErrorV2> {
        if tls_identity_pin.as_bytes() == &[0; 32] {
            return Err(ConnectorWorkerSupervisorErrorV2::ProviderAttemptFailed);
        }
        Ok(Self {
            canonical_url,
            tls_identity_pin,
        })
    }

    pub(crate) const fn canonical_url(&self) -> &BoundedConnectorUrlV2 {
        &self.canonical_url
    }

    pub(crate) const fn tls_identity_pin(&self) -> Digest32V2 {
        self.tls_identity_pin
    }
}

const PROVIDER_REQUEST_PAYLOAD_DOMAIN_V2: &[u8] = b"SAVANA_PROVIDER_REQUEST_PAYLOAD_V2\0";
const PROVIDER_REQUEST_WIRE_DOMAIN_V2: &[u8] = b"SAVANA_BOUND_PROVIDER_REQUEST_WIRE_V2\0";

/// Execd-owned custom-provider wire request. The networkless codec supplies
/// only the opaque final field; it cannot choose the authority, route, TLS
/// identity, or dispatch binding carried by the outer canonical frame.
pub(crate) struct VerifiedProviderRequestV2 {
    target: VerifiedProviderTargetV2,
    execution_nonce: Nonce32V2,
    dispatch_core_digest: Digest32V2,
    dispatch_subject_digest: Digest32V2,
    payload_digest: Digest32V2,
    digest: Digest32V2,
    canonical_bytes: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for VerifiedProviderRequestV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifiedProviderRequestV2")
            .field("target", &self.target)
            .field("execution_nonce", &self.execution_nonce)
            .field("encoded_len", &self.canonical_bytes.len())
            .finish_non_exhaustive()
    }
}

impl VerifiedProviderRequestV2 {
    pub(crate) fn bind(
        target: VerifiedProviderTargetV2,
        execution_nonce: Nonce32V2,
        dispatch_core_digest: Digest32V2,
        dispatch_subject_digest: Digest32V2,
        credential_free_request_digest: Digest32V2,
        credential_free_payload: &[u8],
    ) -> Result<Self, ConnectorWorkerSupervisorErrorV2> {
        let payload_length = u32::try_from(credential_free_payload.len())
            .map_err(|_| ConnectorWorkerSupervisorErrorV2::ProviderAttemptFailed)?;
        let capacity = credential_free_payload
            .len()
            .checked_add(target.canonical_url().as_str().len())
            .and_then(|length| length.checked_add(256))
            .filter(|length| *length <= MAX_CONNECTOR_FRAME_BYTES)
            .ok_or(ConnectorWorkerSupervisorErrorV2::ProviderAttemptFailed)?;
        if credential_free_payload.is_empty()
            || is_zero(execution_nonce.as_bytes())
            || is_zero(dispatch_core_digest.as_bytes())
            || is_zero(dispatch_subject_digest.as_bytes())
            || credential_free_request_digest
                != prepared_provider_request_digest(credential_free_payload)
        {
            return Err(ConnectorWorkerSupervisorErrorV2::ProviderAttemptFailed);
        }
        let payload_digest = provider_request_payload_digest(credential_free_payload);
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(capacity)
            .map_err(|_| ConnectorWorkerSupervisorErrorV2::ProviderAttemptFailed)?;
        let mut encoder = minicbor::Encoder::new(bytes);
        encoder
            .array(11)
            .and_then(|encoder| encoder.u16(2))
            .and_then(|encoder| encoder.u16(1))
            .and_then(|encoder| encoder.str(target.canonical_url().as_str()))
            .and_then(|encoder| encoder.bytes(target.tls_identity_pin().as_bytes()))
            .and_then(|encoder| encoder.bytes(execution_nonce.as_bytes()))
            .and_then(|encoder| encoder.bytes(dispatch_core_digest.as_bytes()))
            .and_then(|encoder| encoder.bytes(dispatch_subject_digest.as_bytes()))
            .and_then(|encoder| encoder.u32(payload_length))
            .and_then(|encoder| encoder.bytes(credential_free_request_digest.as_bytes()))
            .and_then(|encoder| encoder.bytes(payload_digest.as_bytes()))
            .and_then(|encoder| encoder.bytes(credential_free_payload))
            .map_err(|_| ConnectorWorkerSupervisorErrorV2::ProviderAttemptFailed)?;
        let canonical_bytes = encoder.into_writer();
        if canonical_bytes.len() > MAX_CONNECTOR_FRAME_BYTES {
            return Err(ConnectorWorkerSupervisorErrorV2::ProviderAttemptFailed);
        }
        let digest = provider_request_wire_digest(&canonical_bytes);
        Ok(Self {
            target,
            execution_nonce,
            dispatch_core_digest,
            dispatch_subject_digest,
            payload_digest,
            digest,
            canonical_bytes: Zeroizing::new(canonical_bytes),
        })
    }

    pub(crate) const fn target(&self) -> &VerifiedProviderTargetV2 {
        &self.target
    }

    pub(crate) const fn payload_digest(&self) -> Digest32V2 {
        self.payload_digest
    }

    pub(crate) const fn digest(&self) -> Digest32V2 {
        self.digest
    }

    pub(crate) fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub(crate) fn matches_permit(&self, permit: &EffectPermitV2) -> bool {
        self.execution_nonce == permit.execution_nonce()
            && self.dispatch_core_digest == permit.dispatch_core_digest()
            && self.dispatch_subject_digest == permit.dispatch_subject_digest()
    }
}

trait DurableExecdAttemptJournalV2 {
    fn query(
        &self,
        nonce: Nonce32V2,
        deadline: Instant,
    ) -> Result<ExecdQueryV2, ConnectorWorkerSupervisorErrorV2>;

    fn prepare_provider_attempt(
        &self,
        nonce: Nonce32V2,
        prepared_request_digest: Digest32V2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<ProviderAttemptPredecessorV2, ConnectorWorkerSupervisorErrorV2>;

    fn record_effect_started(
        &self,
        predecessor: ProviderAttemptPredecessorV2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<ArmedEffectV2, ConnectorWorkerSupervisorErrorV2>;

    fn record_provider_response(
        &self,
        nonce: Nonce32V2,
        response: Vec<u8>,
        deadline: Instant,
    ) -> Result<RetainedProviderResponseV2, ConnectorWorkerSupervisorErrorV2>;
}

impl DurableExecdAttemptJournalV2 for ExecdStateOwnerV2 {
    fn query(
        &self,
        nonce: Nonce32V2,
        deadline: Instant,
    ) -> Result<ExecdQueryV2, ConnectorWorkerSupervisorErrorV2> {
        self.query(nonce, deadline)
            .map_err(|_| ConnectorWorkerSupervisorErrorV2::ProviderAttemptFailed)
    }

    fn prepare_provider_attempt(
        &self,
        nonce: Nonce32V2,
        prepared_request_digest: Digest32V2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<ProviderAttemptPredecessorV2, ConnectorWorkerSupervisorErrorV2> {
        self.prepare_provider_attempt(nonce, prepared_request_digest, now, deadline)
            .map_err(|_| ConnectorWorkerSupervisorErrorV2::ProviderAttemptFailed)
    }

    fn record_effect_started(
        &self,
        predecessor: ProviderAttemptPredecessorV2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<ArmedEffectV2, ConnectorWorkerSupervisorErrorV2> {
        self.record_effect_started(predecessor, now, deadline)
            .map_err(|_| ConnectorWorkerSupervisorErrorV2::ProviderAttemptFailed)
    }

    fn record_provider_response(
        &self,
        nonce: Nonce32V2,
        response: Vec<u8>,
        deadline: Instant,
    ) -> Result<RetainedProviderResponseV2, ConnectorWorkerSupervisorErrorV2> {
        self.record_provider_response(nonce, response, deadline)
            .map_err(|_| ConnectorWorkerSupervisorErrorV2::ProviderAttemptFailed)
    }
}

/// Concrete bridge between the connector supervisor and execd's owner thread.
///
/// The durable predecessor and EffectStarted receipt are committed before
/// transport sees a permit. The full provider response is committed before it
/// can be returned to the codec worker.
pub(crate) struct OwnerBackedProviderAttemptV2<'a> {
    journal: &'a dyn DurableExecdAttemptJournalV2,
    transport: &'a mut dyn ProviderTransportV2,
    target: &'a VerifiedProviderTargetV2,
    now: UnixMillisV2,
}

impl<'a> OwnerBackedProviderAttemptV2<'a> {
    pub(crate) fn new(
        journal: &'a ExecdStateOwnerV2,
        transport: &'a mut dyn ProviderTransportV2,
        target: &'a VerifiedProviderTargetV2,
        now: UnixMillisV2,
    ) -> Self {
        Self {
            journal,
            transport,
            target,
            now,
        }
    }

    #[cfg(test)]
    fn from_parts(
        journal: &'a dyn DurableExecdAttemptJournalV2,
        transport: &'a mut dyn ProviderTransportV2,
        target: &'a VerifiedProviderTargetV2,
        now: UnixMillisV2,
    ) -> Self {
        Self {
            journal,
            transport,
            target,
            now,
        }
    }
}

impl DurableProviderAttemptV2 for OwnerBackedProviderAttemptV2<'_> {
    fn execute_and_retain(
        &mut self,
        job: &VerifiedConnectorWorkerJobV2,
        prepared: &PreparedProviderRequestFrameV2,
        deadline: Instant,
    ) -> Result<DurablyRetainedProviderResponseV2, ConnectorWorkerSupervisorErrorV2> {
        ensure_deadline(deadline)?;
        let query = self.journal.query(job.execution_nonce(), deadline)?;
        if query.state() != ExecdJournalStateV2::Prepared
            || query.dispatch_core_digest() != job.dispatch_core_digest()
            || query.dispatch_subject_digest() != job.dispatch_subject_digest()
        {
            return Err(ConnectorWorkerSupervisorErrorV2::ProviderAttemptFailed);
        }
        let request = VerifiedProviderRequestV2::bind(
            self.target.clone(),
            job.execution_nonce(),
            job.dispatch_core_digest(),
            job.dispatch_subject_digest(),
            prepared.request_digest(),
            prepared.request(),
        )?;
        let predecessor = self.journal.prepare_provider_attempt(
            job.execution_nonce(),
            request.digest(),
            self.now,
            deadline,
        )?;
        let armed = self
            .journal
            .record_effect_started(predecessor, self.now, deadline)?;
        let effect_started_receipt_digest = armed.receipt().digest();
        let permit = armed.into_effect_permit();
        ensure_deadline(deadline)?;
        let response = self.transport.execute(
            &request,
            &permit,
            prepared.maximum_response_bytes(),
            deadline,
        )?;
        if response.is_empty() || response.len() > prepared.maximum_response_bytes() as usize {
            return Err(ConnectorWorkerSupervisorErrorV2::ProviderAttemptFailed);
        }
        let retained =
            self.journal
                .record_provider_response(job.execution_nonce(), response, deadline)?;
        DurablyRetainedProviderResponseV2::from_durable_attempt(
            retained.into_bytes().to_vec(),
            effect_started_receipt_digest,
        )
    }
}

pub(crate) struct DurablyRetainedProviderResponseV2 {
    bytes: Zeroizing<Vec<u8>>,
    effect_started_receipt_digest: Digest32V2,
}

impl std::fmt::Debug for DurablyRetainedProviderResponseV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DurablyRetainedProviderResponseV2")
            .field("encoded_len", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

impl DurablyRetainedProviderResponseV2 {
    pub(crate) fn from_durable_attempt(
        bytes: Vec<u8>,
        effect_started_receipt_digest: Digest32V2,
    ) -> Result<Self, ConnectorWorkerSupervisorErrorV2> {
        if bytes.is_empty()
            || bytes.len() > crate::worker_protocol::MAX_CONNECTOR_RESPONSE_BYTES
            || is_zero(effect_started_receipt_digest.as_bytes())
        {
            return Err(ConnectorWorkerSupervisorErrorV2::ProviderAttemptFailed);
        }
        Ok(Self {
            bytes: Zeroizing::new(bytes),
            effect_started_receipt_digest,
        })
    }
}

pub(crate) struct ConnectorWorkerSupervisorV2 {
    trust: VerifiedConnectorWorkerTrustV2,
    launcher: Box<dyn VerifiedConnectorSandboxLauncherV2>,
}

impl std::fmt::Debug for ConnectorWorkerSupervisorV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConnectorWorkerSupervisorV2")
            .field("trust", &self.trust)
            .finish_non_exhaustive()
    }
}

impl ConnectorWorkerSupervisorV2 {
    pub(crate) fn from_verified_launcher(
        trust: VerifiedConnectorWorkerTrustV2,
        launcher: Option<Box<dyn VerifiedConnectorSandboxLauncherV2>>,
    ) -> Result<Self, ConnectorWorkerSupervisorErrorV2> {
        Ok(Self {
            trust,
            launcher: launcher.ok_or(ConnectorWorkerSupervisorErrorV2::SandboxUnavailable)?,
        })
    }

    pub(crate) fn prepare_and_decode(
        &self,
        canonical_descriptor: &[u8],
        material: Zeroizing<Vec<u8>>,
        ephemeral_signing_seed: Zeroizing<[u8; 32]>,
        now: UnixMillisV2,
        deadline: Instant,
        provider: &mut dyn DurableProviderAttemptV2,
    ) -> Result<ConnectorWorkerOutcomeV2, ConnectorWorkerSupervisorErrorV2> {
        let job = verify_connector_worker_job(canonical_descriptor, &self.trust, now)
            .map_err(ConnectorWorkerSupervisorErrorV2::Protocol)?;
        if job.mode() != ConnectorCodecJobModeV2::PrepareAndDecode
            || connector_material_digest(&material) != job.bounded_material_digest()
            || !job.ephemeral_seed_matches(&ephemeral_signing_seed)
        {
            return Err(ConnectorWorkerSupervisorErrorV2::ProtocolViolation);
        }
        let mut child = self
            .launcher
            .launch_one_job(&job, ephemeral_signing_seed, deadline)?;
        let result = run_prepare_protocol(
            child.as_mut(),
            &job,
            material.as_slice(),
            deadline,
            provider,
        );
        if result.is_err() {
            child.kill_and_reap();
        }
        result
    }

    pub(crate) fn decode_retained_response(
        &self,
        canonical_descriptor: &[u8],
        retained_response: Zeroizing<Vec<u8>>,
        ephemeral_signing_seed: Zeroizing<[u8; 32]>,
        effect_started_receipt_digest: Digest32V2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<ConnectorWorkerOutcomeV2, ConnectorWorkerSupervisorErrorV2> {
        let job = verify_connector_worker_job(canonical_descriptor, &self.trust, now)
            .map_err(ConnectorWorkerSupervisorErrorV2::Protocol)?;
        if job.mode() != ConnectorCodecJobModeV2::DecodeRetainedResponse
            || job.retained_provider_response_digest()
                != Some(connector_response_digest(&retained_response))
            || job.retained_provider_response_length() != Some(retained_response.len() as u32)
            || job.effect_started_receipt_digest() != Some(effect_started_receipt_digest)
            || !job.ephemeral_seed_matches(&ephemeral_signing_seed)
        {
            return Err(ConnectorWorkerSupervisorErrorV2::ProtocolViolation);
        }
        let mut child = self
            .launcher
            .launch_one_job(&job, ephemeral_signing_seed, deadline)?;
        let result = run_decode_protocol(
            child.as_mut(),
            &job,
            retained_response.as_slice(),
            effect_started_receipt_digest,
            deadline,
        );
        if result.is_err() {
            child.kill_and_reap();
        }
        result
    }
}

#[derive(Debug)]
pub(crate) enum ConnectorWorkerOutcomeV2 {
    FailedBeforeEffect,
    Completion {
        result: Zeroizing<Vec<u8>>,
        result_digest: Digest32V2,
    },
    Indeterminate,
}

fn run_prepare_protocol(
    child: &mut dyn ConnectorWorkerChildV2,
    job: &VerifiedConnectorWorkerJobV2,
    material: &[u8],
    deadline: Instant,
    provider: &mut dyn DurableProviderAttemptV2,
) -> Result<ConnectorWorkerOutcomeV2, ConnectorWorkerSupervisorErrorV2> {
    ensure_deadline(deadline)?;
    child.send_job(
        job.canonical_descriptor(),
        ConnectorWorkerInputV2::Prepare {
            credential_free_material: material,
        },
        deadline,
    )?;
    let begin = connector_transcript_begin(job);
    let first = receive_frame(child, job, deadline)?;
    match first {
        ConnectorWorkerFrameV2::Outcome(outcome) => {
            let expected = connector_transcript_step(begin, 1, 3, 0, outcome.transcript_material());
            if outcome.kind() != ConnectorOutcomeKindV2::FailedBeforeEffect
                || outcome.transcript_digest() != expected
            {
                return Err(ConnectorWorkerSupervisorErrorV2::ProtocolViolation);
            }
            child.finish_after_terminal(deadline)?;
            Ok(ConnectorWorkerOutcomeV2::FailedBeforeEffect)
        }
        ConnectorWorkerFrameV2::Prepared(prepared) => {
            let prepared_transcript =
                connector_transcript_step(begin, 1, 1, 0, prepared.transcript_material());
            if prepared.transcript_digest() != prepared_transcript {
                return Err(ConnectorWorkerSupervisorErrorV2::ProtocolViolation);
            }
            let retained = provider.execute_and_retain(job, &prepared, deadline)?;
            if retained.bytes.len() > prepared.maximum_response_bytes() as usize {
                return Err(ConnectorWorkerSupervisorErrorV2::ProtocolViolation);
            }
            let provider_frame = encode_provider_response_frame(
                job,
                &retained.bytes,
                retained.effect_started_receipt_digest,
            )
            .map_err(ConnectorWorkerSupervisorErrorV2::Protocol)?;
            let response_transcript =
                connector_transcript_step(prepared_transcript, 2, 2, 1, &provider_frame);
            child.send_provider_response(&provider_frame, deadline)?;
            let outcome = match receive_frame(child, job, deadline)? {
                ConnectorWorkerFrameV2::Outcome(outcome) => outcome,
                ConnectorWorkerFrameV2::Prepared(_) => {
                    return Err(ConnectorWorkerSupervisorErrorV2::ProtocolViolation);
                }
            };
            let expected = connector_transcript_step(
                response_transcript,
                1,
                3,
                2,
                outcome.transcript_material(),
            );
            validate_terminal_outcome(
                &outcome,
                connector_response_digest(&retained.bytes),
                expected,
            )?;
            child.finish_after_terminal(deadline)?;
            project_outcome(outcome)
        }
    }
}

fn run_decode_protocol(
    child: &mut dyn ConnectorWorkerChildV2,
    job: &VerifiedConnectorWorkerJobV2,
    retained_response: &[u8],
    effect_started_receipt_digest: Digest32V2,
    deadline: Instant,
) -> Result<ConnectorWorkerOutcomeV2, ConnectorWorkerSupervisorErrorV2> {
    ensure_deadline(deadline)?;
    child.send_job(
        job.canonical_descriptor(),
        ConnectorWorkerInputV2::DecodeRetainedResponse {
            retained_provider_response: retained_response,
            effect_started_receipt_digest,
        },
        deadline,
    )?;
    let outcome = match receive_frame(child, job, deadline)? {
        ConnectorWorkerFrameV2::Outcome(outcome) => outcome,
        ConnectorWorkerFrameV2::Prepared(_) => {
            return Err(ConnectorWorkerSupervisorErrorV2::ProtocolViolation);
        }
    };
    let expected = connector_transcript_step(
        connector_transcript_begin(job),
        1,
        3,
        0,
        outcome.transcript_material(),
    );
    validate_terminal_outcome(
        &outcome,
        connector_response_digest(retained_response),
        expected,
    )?;
    child.finish_after_terminal(deadline)?;
    project_outcome(outcome)
}

fn receive_frame(
    child: &mut dyn ConnectorWorkerChildV2,
    job: &VerifiedConnectorWorkerJobV2,
    deadline: Instant,
) -> Result<ConnectorWorkerFrameV2, ConnectorWorkerSupervisorErrorV2> {
    ensure_deadline(deadline)?;
    let bytes = child
        .receive_frame(deadline)?
        .ok_or(ConnectorWorkerSupervisorErrorV2::ProtocolViolation)?;
    if bytes.len() > MAX_CONNECTOR_FRAME_BYTES {
        return Err(ConnectorWorkerSupervisorErrorV2::ProtocolViolation);
    }
    decode_connector_worker_frame(&bytes, job).map_err(ConnectorWorkerSupervisorErrorV2::Protocol)
}

fn validate_terminal_outcome(
    outcome: &crate::worker_protocol::ConnectorOutcomeFrameV2,
    response_digest: Digest32V2,
    expected_transcript: Digest32V2,
) -> Result<(), ConnectorWorkerSupervisorErrorV2> {
    if outcome.kind() == ConnectorOutcomeKindV2::FailedBeforeEffect
        || outcome.provider_response_digest() != Some(response_digest)
        || outcome.transcript_digest() != expected_transcript
    {
        return Err(ConnectorWorkerSupervisorErrorV2::ProtocolViolation);
    }
    Ok(())
}

fn project_outcome(
    outcome: crate::worker_protocol::ConnectorOutcomeFrameV2,
) -> Result<ConnectorWorkerOutcomeV2, ConnectorWorkerSupervisorErrorV2> {
    match outcome.kind() {
        ConnectorOutcomeKindV2::FailedBeforeEffect => {
            Ok(ConnectorWorkerOutcomeV2::FailedBeforeEffect)
        }
        ConnectorOutcomeKindV2::Indeterminate => Ok(ConnectorWorkerOutcomeV2::Indeterminate),
        ConnectorOutcomeKindV2::Completion => {
            let result = outcome
                .result()
                .ok_or(ConnectorWorkerSupervisorErrorV2::ProtocolViolation)?;
            let result_digest = outcome
                .result_digest()
                .ok_or(ConnectorWorkerSupervisorErrorV2::ProtocolViolation)?;
            Ok(ConnectorWorkerOutcomeV2::Completion {
                result: Zeroizing::new(result.to_vec()),
                result_digest,
            })
        }
    }
}

fn ensure_deadline(deadline: Instant) -> Result<(), ConnectorWorkerSupervisorErrorV2> {
    if Instant::now() >= deadline {
        Err(ConnectorWorkerSupervisorErrorV2::DeadlineExceeded)
    } else {
        Ok(())
    }
}

fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

fn provider_request_payload_digest(bytes: &[u8]) -> Digest32V2 {
    let mut hasher = Sha256::new();
    hasher.update(PROVIDER_REQUEST_PAYLOAD_DOMAIN_V2);
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    Digest32V2::new(hasher.finalize().into())
}

fn provider_request_wire_digest(bytes: &[u8]) -> Digest32V2 {
    let mut hasher = Sha256::new();
    hasher.update(PROVIDER_REQUEST_WIRE_DOMAIN_V2);
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    Digest32V2::new(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use ed25519_dalek::SigningKey;
    use savana_kernel_protocol::v2::{
        derive_ed25519_key_id_v2, Digest32V2, ExecutorIdentityV2,
        SignedExecutorEffectStartedReceiptV2, UnixMillisV2, UnsignedExecutorEffectStartedReceiptV2,
    };
    use savana_policy_core::v2::{
        BoundedConnectorHostV2, BoundedConnectorUrlV2, ConnectorTierV2, ConnectorTransportV2,
    };
    use zeroize::Zeroizing;

    use super::{
        ConnectorWorkerChildV2, ConnectorWorkerInputV2, ConnectorWorkerOutcomeV2,
        ConnectorWorkerSupervisorErrorV2, ConnectorWorkerSupervisorV2,
        DurableExecdAttemptJournalV2, DurableProviderAttemptV2, DurablyRetainedProviderResponseV2,
        OwnerBackedProviderAttemptV2, ProviderTransportV2, VerifiedConnectorSandboxLauncherV2,
        VerifiedProviderRequestV2, VerifiedProviderTargetV2,
    };
    use crate::worker_protocol::test_support::{
        fixture, outcome_frame, outcome_transcript_material, prepared_frame,
        prepared_transcript_material, ConnectorFixtureV2,
    };
    use crate::worker_protocol::{
        connector_transcript_begin, connector_transcript_step, prepared_provider_request_digest,
        verify_connector_worker_job, ConnectorCodecJobModeV2, ConnectorOutcomeKindV2,
        ConnectorWorkerFrameV2, PreparedProviderRequestFrameV2, VerifiedConnectorWorkerJobV2,
        VerifiedConnectorWorkerTrustV2, MAX_CONNECTOR_FRAME_BYTES,
    };
    use crate::{
        ArmedEffectV2, DispatchEnvelopeKindV2, EffectPermitV2, ExecdJournalStateV2, ExecdQueryV2,
        ProviderAttemptPredecessorV2, RetainedProviderResponseV2,
    };

    struct FakeChild {
        frames: VecDeque<Vec<u8>>,
        clean_exit: bool,
        killed: Arc<AtomicBool>,
        provider_frames: Arc<AtomicUsize>,
    }

    impl ConnectorWorkerChildV2 for FakeChild {
        fn send_job(
            &mut self,
            canonical_descriptor: &[u8],
            input: ConnectorWorkerInputV2<'_>,
            _deadline: Instant,
        ) -> Result<(), ConnectorWorkerSupervisorErrorV2> {
            if canonical_descriptor.is_empty() {
                return Err(ConnectorWorkerSupervisorErrorV2::ProtocolViolation);
            }
            match input {
                ConnectorWorkerInputV2::Prepare {
                    credential_free_material: [],
                } => Err(ConnectorWorkerSupervisorErrorV2::ProtocolViolation),
                ConnectorWorkerInputV2::DecodeRetainedResponse {
                    retained_provider_response,
                    effect_started_receipt_digest,
                } if retained_provider_response.is_empty()
                    || effect_started_receipt_digest.as_bytes() == &[0; 32] =>
                {
                    Err(ConnectorWorkerSupervisorErrorV2::ProtocolViolation)
                }
                _ => Ok(()),
            }
        }

        fn receive_frame(
            &mut self,
            _deadline: Instant,
        ) -> Result<Option<Vec<u8>>, ConnectorWorkerSupervisorErrorV2> {
            Ok(self.frames.pop_front())
        }

        fn send_provider_response(
            &mut self,
            canonical_frame: &[u8],
            _deadline: Instant,
        ) -> Result<(), ConnectorWorkerSupervisorErrorV2> {
            if canonical_frame.is_empty() {
                return Err(ConnectorWorkerSupervisorErrorV2::ProtocolViolation);
            }
            self.provider_frames.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn finish_after_terminal(
            &mut self,
            _deadline: Instant,
        ) -> Result<(), ConnectorWorkerSupervisorErrorV2> {
            if self.clean_exit && self.frames.is_empty() {
                Ok(())
            } else {
                Err(ConnectorWorkerSupervisorErrorV2::ProtocolViolation)
            }
        }

        fn kill_and_reap(&mut self) {
            self.killed.store(true, Ordering::SeqCst);
            self.frames.clear();
        }
    }

    struct FakeLauncher {
        frames: Vec<Vec<u8>>,
        clean_exit: bool,
        launches: Arc<AtomicUsize>,
        killed: Arc<AtomicBool>,
        provider_frames: Arc<AtomicUsize>,
    }

    impl VerifiedConnectorSandboxLauncherV2 for FakeLauncher {
        fn launch_one_job(
            &self,
            _job: &VerifiedConnectorWorkerJobV2,
            _ephemeral_signing_seed: Zeroizing<[u8; 32]>,
            _deadline: Instant,
        ) -> Result<Box<dyn ConnectorWorkerChildV2>, ConnectorWorkerSupervisorErrorV2> {
            self.launches.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(FakeChild {
                frames: self.frames.clone().into(),
                clean_exit: self.clean_exit,
                killed: Arc::clone(&self.killed),
                provider_frames: Arc::clone(&self.provider_frames),
            }))
        }
    }

    struct FakeProvider {
        calls: usize,
    }

    struct FakeJournal {
        steps: Arc<Mutex<Vec<&'static str>>>,
        prepared_digest: Arc<Mutex<Option<Digest32V2>>>,
    }

    impl DurableExecdAttemptJournalV2 for FakeJournal {
        fn query(
            &self,
            nonce: savana_kernel_protocol::v2::Nonce32V2,
            _deadline: Instant,
        ) -> Result<ExecdQueryV2, ConnectorWorkerSupervisorErrorV2> {
            self.steps.lock().unwrap().push("query");
            Ok(ExecdQueryV2 {
                execution_nonce: nonce,
                dispatch_core_digest: Digest32V2::new([6; 32]),
                dispatch_subject_digest: Digest32V2::new([7; 32]),
                kind: DispatchEnvelopeKindV2::ToolExecution,
                state: ExecdJournalStateV2::Prepared,
                failure_class: None,
                prepared_request_digest: None,
                retained_provider_response_digest: None,
                retained_provider_response_length: None,
            })
        }

        fn prepare_provider_attempt(
            &self,
            nonce: savana_kernel_protocol::v2::Nonce32V2,
            prepared_request_digest: Digest32V2,
            _now: UnixMillisV2,
            _deadline: Instant,
        ) -> Result<ProviderAttemptPredecessorV2, ConnectorWorkerSupervisorErrorV2> {
            self.steps.lock().unwrap().push("prepare");
            *self.prepared_digest.lock().unwrap() = Some(prepared_request_digest);
            Ok(ProviderAttemptPredecessorV2 {
                execution_nonce: nonce,
                predecessor_digest: Digest32V2::new([0x61; 32]),
                prepared_request_digest: Digest32V2::new([0x62; 32]),
                connector_identity_digest: Digest32V2::new([0x63; 32]),
                connector_codec_job_descriptor_digest: Digest32V2::new([0x64; 32]),
                external_attempt_ordinal: 1,
            })
        }

        fn record_effect_started(
            &self,
            predecessor: ProviderAttemptPredecessorV2,
            _now: UnixMillisV2,
            _deadline: Instant,
        ) -> Result<ArmedEffectV2, ConnectorWorkerSupervisorErrorV2> {
            self.steps.lock().unwrap().push("effect-started");
            let nonce = predecessor.execution_nonce();
            let signing_key = SigningKey::from_bytes(&[0x65; 32]);
            let key_id = derive_ed25519_key_id_v2(signing_key.verifying_key().to_bytes());
            let unsigned = UnsignedExecutorEffectStartedReceiptV2::new(
                Digest32V2::new([1; 32]),
                Digest32V2::new([2; 32]),
                3,
                4,
                nonce,
                Digest32V2::new([6; 32]),
                Digest32V2::new([7; 32]),
                ExecutorIdentityV2::new([8; 32]),
                predecessor.connector_identity_digest,
                predecessor.external_attempt_ordinal,
                predecessor.connector_codec_job_descriptor_digest,
                predecessor.prepared_request_digest,
                predecessor.predecessor_digest,
                UnixMillisV2::new(9),
            )
            .unwrap();
            Ok(ArmedEffectV2 {
                execution_nonce: nonce,
                receipt: SignedExecutorEffectStartedReceiptV2::sign(unsigned, key_id, &signing_key)
                    .unwrap(),
                permit: EffectPermitV2 {
                    execution_nonce: nonce,
                    dispatch_core_digest: Digest32V2::new([6; 32]),
                    dispatch_subject_digest: Digest32V2::new([7; 32]),
                },
            })
        }

        fn record_provider_response(
            &self,
            _nonce: savana_kernel_protocol::v2::Nonce32V2,
            response: Vec<u8>,
            _deadline: Instant,
        ) -> Result<RetainedProviderResponseV2, ConnectorWorkerSupervisorErrorV2> {
            self.steps.lock().unwrap().push("retain");
            RetainedProviderResponseV2::from_journal(Zeroizing::new(response))
                .map_err(|_| ConnectorWorkerSupervisorErrorV2::ProviderAttemptFailed)
        }
    }

    struct FakeTransport {
        steps: Arc<Mutex<Vec<&'static str>>>,
        prepared_digest: Arc<Mutex<Option<Digest32V2>>>,
    }

    impl ProviderTransportV2 for FakeTransport {
        fn verified_deployment_target(
            &self,
        ) -> Result<VerifiedProviderTargetV2, ConnectorWorkerSupervisorErrorV2> {
            VerifiedProviderTargetV2::https(
                BoundedConnectorUrlV2::new("https://provider.example/mcp").unwrap(),
                Digest32V2::new([0x70; 32]),
            )
        }

        fn verify_connector_target(
            &self,
            _tier: ConnectorTierV2,
            transport: &ConnectorTransportV2,
            _active_host_allowlist: &[BoundedConnectorHostV2],
        ) -> Result<VerifiedProviderTargetV2, ConnectorWorkerSupervisorErrorV2> {
            match transport {
                ConnectorTransportV2::Https {
                    canonical_url,
                    tls_identity_pin,
                } => VerifiedProviderTargetV2::https(canonical_url.clone(), *tls_identity_pin),
                ConnectorTransportV2::Stdio { .. } => {
                    Err(ConnectorWorkerSupervisorErrorV2::ProviderAttemptFailed)
                }
            }
        }

        fn execute(
            &mut self,
            request: &VerifiedProviderRequestV2,
            permit: &EffectPermitV2,
            maximum_response_bytes: u32,
            _deadline: Instant,
        ) -> Result<Vec<u8>, ConnectorWorkerSupervisorErrorV2> {
            assert_eq!(
                permit.execution_nonce(),
                savana_kernel_protocol::v2::Nonce32V2::new([5; 32])
            );
            assert!(request.matches_permit(permit));
            assert_eq!(
                *self.prepared_digest.lock().unwrap(),
                Some(request.digest())
            );
            assert_eq!(
                request.target().canonical_url().as_str(),
                "https://provider.example/mcp"
            );
            assert!(maximum_response_bytes >= b"provider response".len() as u32);
            self.steps.lock().unwrap().push("transport");
            Ok(b"provider response".to_vec())
        }
    }

    impl DurableProviderAttemptV2 for FakeProvider {
        fn execute_and_retain(
            &mut self,
            _job: &VerifiedConnectorWorkerJobV2,
            prepared: &PreparedProviderRequestFrameV2,
            _deadline: Instant,
        ) -> Result<DurablyRetainedProviderResponseV2, ConnectorWorkerSupervisorErrorV2> {
            assert_eq!(prepared.request(), b"prepared request");
            self.calls += 1;
            DurablyRetainedProviderResponseV2::from_durable_attempt(
                b"provider response".to_vec(),
                Digest32V2::new([0x55; 32]),
            )
        }
    }

    fn trust(fixture: &ConnectorFixtureV2) -> VerifiedConnectorWorkerTrustV2 {
        VerifiedConnectorWorkerTrustV2::from_verified_deployment(
            Digest32V2::new([1; 32]),
            Digest32V2::new([2; 32]),
            3,
            4,
            Digest32V2::new([8; 32]),
            Digest32V2::new([10; 32]),
            Digest32V2::new([11; 32]),
            savana_kernel_protocol::v2::derive_ed25519_key_id_v2(fixture.parent_public_key),
            fixture.parent_public_key,
        )
        .unwrap()
    }

    fn supervisor(
        fixture: &ConnectorFixtureV2,
        frames: Vec<Vec<u8>>,
        clean_exit: bool,
    ) -> (
        ConnectorWorkerSupervisorV2,
        Arc<AtomicUsize>,
        Arc<AtomicBool>,
        Arc<AtomicUsize>,
    ) {
        let launches = Arc::new(AtomicUsize::new(0));
        let killed = Arc::new(AtomicBool::new(false));
        let provider_frames = Arc::new(AtomicUsize::new(0));
        let launcher = FakeLauncher {
            frames,
            clean_exit,
            launches: Arc::clone(&launches),
            killed: Arc::clone(&killed),
            provider_frames: Arc::clone(&provider_frames),
        };
        (
            ConnectorWorkerSupervisorV2::from_verified_launcher(
                trust(fixture),
                Some(Box::new(launcher)),
            )
            .unwrap(),
            launches,
            killed,
            provider_frames,
        )
    }

    fn valid_prepare_frames(fixture: &ConnectorFixtureV2) -> Vec<Vec<u8>> {
        let job = verify_connector_worker_job(
            &fixture.descriptor,
            &trust(fixture),
            UnixMillisV2::new(100),
        )
        .unwrap();
        let begin = connector_transcript_begin(&job);
        let prepared_digest =
            connector_transcript_step(begin, 1, 1, 0, &prepared_transcript_material(&job));
        let prepared = prepared_frame(fixture, &job, prepared_digest);
        let provider_frame = crate::worker_protocol::encode_provider_response_frame(
            &job,
            b"provider response",
            Digest32V2::new([0x55; 32]),
        )
        .unwrap();
        let response_transcript =
            connector_transcript_step(prepared_digest, 2, 2, 1, &provider_frame);
        let outcome_digest = connector_transcript_step(
            response_transcript,
            1,
            3,
            2,
            &outcome_transcript_material(
                &job,
                ConnectorOutcomeKindV2::Completion,
                Some(b"provider response"),
                Some(b"decoded result"),
            ),
        );
        let outcome = outcome_frame(
            fixture,
            &job,
            ConnectorOutcomeKindV2::Completion,
            Some(b"provider response"),
            Some(b"decoded result"),
            outcome_digest,
        )
        .unwrap();
        vec![prepared, outcome]
    }

    #[test]
    fn prepare_transport_decode_is_one_ordered_job_and_uses_durable_provider_boundary() {
        let fixture = fixture(ConnectorCodecJobModeV2::PrepareAndDecode);
        let (supervisor, launches, killed, provider_frames) =
            supervisor(&fixture, valid_prepare_frames(&fixture), true);
        let mut provider = FakeProvider { calls: 0 };
        let outcome = supervisor
            .prepare_and_decode(
                &fixture.descriptor,
                Zeroizing::new(fixture.material.clone()),
                Zeroizing::new(fixture.ephemeral.to_bytes()),
                UnixMillisV2::new(100),
                Instant::now() + Duration::from_secs(1),
                &mut provider,
            )
            .unwrap();

        match outcome {
            ConnectorWorkerOutcomeV2::Completion { result, .. } => {
                assert_eq!(result.as_slice(), b"decoded result");
            }
            _ => panic!("completion"),
        }
        assert_eq!(provider.calls, 1);
        assert_eq!(provider_frames.load(Ordering::SeqCst), 1);
        assert_eq!(launches.load(Ordering::SeqCst), 1);
        assert!(!killed.load(Ordering::SeqCst));
    }

    #[test]
    fn owner_backed_attempt_commits_effect_start_before_transport_and_response_afterward() {
        let fixture = fixture(ConnectorCodecJobModeV2::PrepareAndDecode);
        let job = verify_connector_worker_job(
            &fixture.descriptor,
            &trust(&fixture),
            UnixMillisV2::new(100),
        )
        .unwrap();
        let begin = connector_transcript_begin(&job);
        let prepared_digest =
            connector_transcript_step(begin, 1, 1, 0, &prepared_transcript_material(&job));
        let prepared = match crate::worker_protocol::decode_connector_worker_frame(
            &prepared_frame(&fixture, &job, prepared_digest),
            &job,
        )
        .unwrap()
        {
            ConnectorWorkerFrameV2::Prepared(prepared) => prepared,
            ConnectorWorkerFrameV2::Outcome(_) => panic!("expected prepared request"),
        };
        let steps = Arc::new(Mutex::new(Vec::new()));
        let prepared_digest = Arc::new(Mutex::new(None));
        let journal = FakeJournal {
            steps: Arc::clone(&steps),
            prepared_digest: Arc::clone(&prepared_digest),
        };
        let mut transport = FakeTransport {
            steps: Arc::clone(&steps),
            prepared_digest,
        };
        let target = VerifiedProviderTargetV2::https(
            BoundedConnectorUrlV2::new("https://provider.example/mcp").unwrap(),
            Digest32V2::new([0x70; 32]),
        )
        .unwrap();
        let mut attempt = OwnerBackedProviderAttemptV2::from_parts(
            &journal,
            &mut transport,
            &target,
            UnixMillisV2::new(110),
        );

        let retained = attempt
            .execute_and_retain(&job, &prepared, Instant::now() + Duration::from_secs(1))
            .unwrap();

        assert_eq!(retained.bytes.as_slice(), b"provider response");
        assert_ne!(retained.effect_started_receipt_digest.as_bytes(), &[0; 32]);
        assert_eq!(
            steps.lock().unwrap().as_slice(),
            ["query", "prepare", "effect-started", "transport", "retain"]
        );
    }

    #[test]
    fn provider_request_outer_frame_fixes_target_for_hostile_inner_routing_bytes() {
        let target = VerifiedProviderTargetV2::https(
            BoundedConnectorUrlV2::new("https://provider.example:9443/mcp/v2?scope=full").unwrap(),
            Digest32V2::new([0x70; 32]),
        )
        .unwrap();
        let nonce = savana_kernel_protocol::v2::Nonce32V2::new([5; 32]);
        let core = Digest32V2::new([6; 32]);
        let subject = Digest32V2::new([7; 32]);

        for hostile_inner in [
            b"Host: evil.example\r\n\r\nbody".as_slice(),
            b"POST /other HTTP/1.1\r\nHost: provider.example\r\n\r\n",
            b"GET https://evil.example/steal HTTP/1.1\r\n\r\n",
            b"/other?redirect=https://evil.example\r\nHost: evil.example",
        ] {
            let request = VerifiedProviderRequestV2::bind(
                target.clone(),
                nonce,
                core,
                subject,
                prepared_provider_request_digest(hostile_inner),
                hostile_inner,
            )
            .unwrap();
            let mut decoder = minicbor::Decoder::new(request.canonical_bytes());
            assert_eq!(decoder.array().unwrap(), Some(11));
            assert_eq!(decoder.u16().unwrap(), 2);
            assert_eq!(decoder.u16().unwrap(), 1);
            assert_eq!(
                decoder.str().unwrap(),
                "https://provider.example:9443/mcp/v2?scope=full"
            );
            assert_eq!(decoder.bytes().unwrap(), &[0x70; 32]);
            assert_eq!(decoder.bytes().unwrap(), nonce.as_bytes());
            assert_eq!(decoder.bytes().unwrap(), core.as_bytes());
            assert_eq!(decoder.bytes().unwrap(), subject.as_bytes());
            assert_eq!(decoder.u32().unwrap() as usize, hostile_inner.len());
            assert_eq!(
                decoder.bytes().unwrap(),
                prepared_provider_request_digest(hostile_inner).as_bytes()
            );
            assert_eq!(
                decoder.bytes().unwrap(),
                request.payload_digest().as_bytes()
            );
            assert_eq!(decoder.bytes().unwrap(), hostile_inner);
            assert_eq!(decoder.position(), request.canonical_bytes().len());
            assert_eq!(request.target().canonical_url(), target.canonical_url());
        }
    }

    #[test]
    fn provider_request_matches_openclaw_release_golden_vector() {
        let target = VerifiedProviderTargetV2::https(
            BoundedConnectorUrlV2::new("https://127.0.0.1:43191/savana/final-release").unwrap(),
            Digest32V2::new([0x70; 32]),
        )
        .unwrap();
        let payload = b"released assistant response";
        let request = VerifiedProviderRequestV2::bind(
            target,
            savana_kernel_protocol::v2::Nonce32V2::new([0x05; 32]),
            Digest32V2::new([0x06; 32]),
            Digest32V2::new([0x07; 32]),
            prepared_provider_request_digest(payload),
            payload,
        )
        .unwrap();
        let actual = request
            .canonical_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();

        assert_eq!(
            actual,
            include_str!("../../savana-openclaw-release/tests/fixtures/provider-request-v2.hex")
                .trim()
        );
    }

    #[test]
    fn terminal_reuse_wrong_order_and_oversized_frames_kill_and_reap() {
        let fixture = fixture(ConnectorCodecJobModeV2::PrepareAndDecode);
        let mut frames = valid_prepare_frames(&fixture);
        frames.push(frames[1].clone());
        let (reused_supervisor, _, killed, _) = supervisor(&fixture, frames, true);
        let mut provider = FakeProvider { calls: 0 };
        assert!(reused_supervisor
            .prepare_and_decode(
                &fixture.descriptor,
                Zeroizing::new(fixture.material.clone()),
                Zeroizing::new(fixture.ephemeral.to_bytes()),
                UnixMillisV2::new(100),
                Instant::now() + Duration::from_secs(1),
                &mut provider,
            )
            .is_err());
        assert!(killed.load(Ordering::SeqCst));

        let (oversized, _, oversized_killed, _) =
            supervisor(&fixture, vec![vec![0; MAX_CONNECTOR_FRAME_BYTES + 1]], true);
        assert!(oversized
            .prepare_and_decode(
                &fixture.descriptor,
                Zeroizing::new(fixture.material),
                Zeroizing::new(fixture.ephemeral.to_bytes()),
                UnixMillisV2::new(100),
                Instant::now() + Duration::from_secs(1),
                &mut FakeProvider { calls: 0 },
            )
            .is_err());
        assert!(oversized_killed.load(Ordering::SeqCst));
    }

    #[test]
    fn recovery_decode_never_invokes_provider_transport() {
        let fixture = fixture(ConnectorCodecJobModeV2::DecodeRetainedResponse);
        let job = verify_connector_worker_job(
            &fixture.descriptor,
            &trust(&fixture),
            UnixMillisV2::new(100),
        )
        .unwrap();
        let response = b"provider response";
        let outcome_digest = connector_transcript_step(
            connector_transcript_begin(&job),
            1,
            3,
            0,
            &outcome_transcript_material(
                &job,
                ConnectorOutcomeKindV2::Completion,
                Some(response),
                Some(b"decoded result"),
            ),
        );
        let outcome = outcome_frame(
            &fixture,
            &job,
            ConnectorOutcomeKindV2::Completion,
            Some(response),
            Some(b"decoded result"),
            outcome_digest,
        )
        .unwrap();
        let (supervisor, _, killed, provider_frames) = supervisor(&fixture, vec![outcome], true);

        assert!(matches!(
            supervisor
                .decode_retained_response(
                    &fixture.descriptor,
                    Zeroizing::new(response.to_vec()),
                    Zeroizing::new(fixture.ephemeral.to_bytes()),
                    Digest32V2::new([15; 32]),
                    UnixMillisV2::new(100),
                    Instant::now() + Duration::from_secs(1),
                )
                .unwrap(),
            ConnectorWorkerOutcomeV2::Completion { .. }
        ));
        assert_eq!(provider_frames.load(Ordering::SeqCst), 0);
        assert!(!killed.load(Ordering::SeqCst));
    }

    #[test]
    fn invalid_descriptor_or_missing_sandbox_is_rejected_before_launch() {
        let fixture = fixture(ConnectorCodecJobModeV2::PrepareAndDecode);
        assert_eq!(
            ConnectorWorkerSupervisorV2::from_verified_launcher(trust(&fixture), None).unwrap_err(),
            ConnectorWorkerSupervisorErrorV2::SandboxUnavailable
        );
        let frames = valid_prepare_frames(&fixture);
        let (supervisor, launches, _, _) = supervisor(&fixture, frames, true);
        let mut rebound = fixture.descriptor.clone();
        let last = rebound.len() - 1;
        rebound[last] ^= 1;
        assert!(supervisor
            .prepare_and_decode(
                &rebound,
                Zeroizing::new(fixture.material),
                Zeroizing::new(fixture.ephemeral.to_bytes()),
                UnixMillisV2::new(100),
                Instant::now() + Duration::from_secs(1),
                &mut FakeProvider { calls: 0 },
            )
            .is_err());
        assert_eq!(launches.load(Ordering::SeqCst), 0);
    }
}
