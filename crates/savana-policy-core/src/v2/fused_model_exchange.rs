//! Synchronous private-owner model exchange. Never an Agent/public RPC.
//! The host supplies authenticated current policy/provenance and a pinned,
//! bounded transport. No implementation here opens a socket or enables cloud.
use super::*;
use savana_continuation_core::planning::Role;
use savana_kernel_protocol::v2::{Digest32V2, DurableTaskIdV2, UnixMillisV2};

pub const MAX_FUSED_MODEL_REPLY_BYTES_V04: usize = 16 * 1024;
/// Bounds a serialized owner/policy lease. The trusted adapter enforces it.
pub const MAX_FUSED_MODEL_EXCHANGE_MS_V04: u64 = 5_000;

/// Transport implementations are trusted egress adapters: the identity must be
/// established by pinned configuration/authenticated connection, not a model.
/// They must enforce the absolute deadline and allocation limit while reading;
/// disable redirects, fallback endpoints, hidden retries and extra telemetry.
pub trait FusedModelTransportV04 {
    fn recipient_identity(&self) -> [u8; 32];
    fn exchange(
        &mut self,
        request: &[u8],
        deadline: UnixMillisV2,
        maximum_reply_bytes: usize,
    ) -> Result<Vec<u8>, FusedModelTransportErrorV04>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FusedModelTransportErrorV04 {
    Unavailable,
}

/// Cloud/model placeholder: no network, credentials or fake response.
pub struct DisabledFusedModelTransportV04;
impl FusedModelTransportV04 for DisabledFusedModelTransportV04 {
    fn recipient_identity(&self) -> [u8; 32] {
        [0; 32]
    }
    fn exchange(
        &mut self,
        _: &[u8],
        _: UnixMillisV2,
        _: usize,
    ) -> Result<Vec<u8>, FusedModelTransportErrorV04> {
        Err(FusedModelTransportErrorV04::Unavailable)
    }
}

/// For local orchestration/audit only. Do not forward outcomes as model feedback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FusedModelExchangeOutcomeV04 {
    Accepted,
    RejectedReply,
    Unavailable,
}

pub struct FusedModelReleaseContextV04<'a> {
    pub rules: &'a DeclassificationRuleSetV2,
    pub provenance: ProvenanceContextV2,
    pub parents: &'a [&'a ProvenanceRecordV2],
    pub allowed_effects: EffectSetV2,
}

/// Legacy unscheduled-profile exchange: callers cannot supply outbound bytes.
/// Freeze is a separate owner transition. Profiles with signed delivery slots
/// reject this path and require `exchange_scheduled_fused_model_v04` instead.
/// Every explicit attempt charges first.
///
/// Policy must remain pinned/current throughout this serialized owner call.
/// `clock` is the host clock, never response metadata. Returned errors/outcomes
/// stay private; this is not whole-service output mediation or a scheduler.
#[allow(clippy::too_many_arguments)]
pub fn exchange_fused_model_v04(
    owner: &mut DurableG4StateV2,
    task: DurableTaskIdV2,
    expected_revision: u64,
    round: u16,
    role: Role,
    release: FusedModelReleaseContextV04<'_>,
    transport: &mut (impl FusedModelTransportV04 + ?Sized),
    mut clock: impl FnMut() -> UnixMillisV2,
) -> Result<FusedModelExchangeOutcomeV04, G4Error> {
    let now = clock();
    let recipient = transport.recipient_identity();
    if recipient == [0; 32] {
        return Err(G4Error::StateConflict);
    }
    let profile = owner.fused_model_release_binding_v04(task, now)?;
    let reservation = owner.update_fused_planning_v04(
        task,
        expected_revision,
        FusedPlanningUpdateV04::ReserveDelivery {
            round,
            role,
            recipient,
        },
        now,
    )?;
    exchange_reserved(
        owner,
        task,
        round,
        role,
        release,
        transport,
        clock,
        now,
        recipient,
        profile,
        reservation,
        u64::MAX,
    )
}

/// One public clock tick: persist missed windows and at most one reservation.
/// A successful/failed reply cannot trigger another attempt outside a signed
/// slot. None means no transmission was due; this result stays host-private.
#[allow(clippy::too_many_arguments)]
pub fn exchange_scheduled_fused_model_v04(
    owner: &mut DurableG4StateV2,
    task: DurableTaskIdV2,
    expected_revision: u64,
    release: FusedModelReleaseContextV04<'_>,
    transport: &mut (impl FusedModelTransportV04 + ?Sized),
    mut clock: impl FnMut() -> UnixMillisV2,
) -> Result<Option<FusedModelExchangeOutcomeV04>, G4Error> {
    let now = clock();
    let recipient = transport.recipient_identity();
    if recipient == [0; 32] {
        return Err(G4Error::StateConflict);
    }
    let profile = owner.fused_model_release_binding_v04(task, now)?;
    let reservation = owner.update_fused_planning_v04(
        task,
        expected_revision,
        FusedPlanningUpdateV04::ClaimScheduledDelivery { recipient },
        now,
    )?;
    let Some(slot) = reservation.scheduled_slot().cloned() else {
        return Ok(None);
    };
    exchange_reserved(
        owner,
        task,
        slot.round,
        slot.role,
        release,
        transport,
        clock,
        now,
        recipient,
        profile,
        reservation,
        slot.closes_at,
    )
    .map(Some)
}

#[allow(clippy::too_many_arguments)]
fn exchange_reserved(
    owner: &mut DurableG4StateV2,
    task: DurableTaskIdV2,
    round: u16,
    role: Role,
    release: FusedModelReleaseContextV04<'_>,
    transport: &mut (impl FusedModelTransportV04 + ?Sized),
    mut clock: impl FnMut() -> UnixMillisV2,
    now: UnixMillisV2,
    recipient: [u8; 32],
    profile: [u8; 32],
    reservation: FusedPlanningResultV04,
    slot_deadline: u64,
) -> Result<FusedModelExchangeOutcomeV04, G4Error> {
    let view = reservation
        .view_for_release_check()
        .ok_or(G4Error::StateConflict)?;
    let bytes = view.canonical_bytes().map_err(|_| G4Error::StateConflict)?;
    // Dynamic projection is NOT endorsement/declassification on its own. Join
    // original tool-result lineage into the same current G3 release decision.
    let observation_parents = owner.fused_observation_parents_v04(task, round, now)?;
    let mut parents = release.parents.to_vec();
    parents.extend(observation_parents.iter());
    let provenance_context = if let Some(expiry) = observation_parents
        .iter()
        .map(|p| p.expires_at().get())
        .min()
    {
        release
            .provenance
            .restrict_expiry(UnixMillisV2::new(expiry))
            .map_err(|_| G4Error::StateConflict)?
    } else {
        release.provenance
    };
    // JSON encodes public_view as an integer array. Inspect its decoded text as
    // well, otherwise ordinary PII could be hidden from the wire-text scanner.
    let text = std::str::from_utf8(&view.public_view).map_err(|_| G4Error::StateConflict)?;
    super::leak_gate::enforce_for_declassification(
        &KernelValueV2::text(text.to_owned()).map_err(|_| G4Error::StateConflict)?,
        LeakGateDutyV2::BlocklistAndNoResidualPii,
    )
    .map_err(|_| G4Error::StateConflict)?;
    let value = KernelValueV2::bytes(bytes.clone()).map_err(|_| G4Error::StateConflict)?;
    let transition = DeclassificationTransitionV2::BuildFusedModelEnvelope {
        model_identity_digest: Digest32V2::new(recipient),
    };
    let purpose = ClosedDeclassificationPurposeV2::FusedModelCall.purpose_digest();
    let binding = super::task_authorization::hash_parts(
        b"SAVANA_FUSED_MODEL_RELEASE_V04\0",
        &[&profile, &view.commitment(), &recipient],
    );
    let provenance = ProvenanceRecordV2::declassify(
        &value,
        provenance_context,
        transition,
        release.rules,
        purpose,
        binding,
        None,
        &parents,
        release.allowed_effects,
        now.get(),
    )
    .map_err(|_| G4Error::StateConflict)?;
    if provenance.judge_handoff(transition, release.rules) != HandoffJudgmentV2::Admits {
        return Err(G4Error::StateConflict);
    }
    let rule = release
        .rules
        .authorizing_rule(6, purpose)
        .ok_or(G4Error::StateConflict)?;
    let deadline = view
        .deadline
        .min(slot_deadline)
        .min(
            now.get()
                .checked_add(MAX_FUSED_MODEL_EXCHANGE_MS_V04)
                .ok_or(G4Error::StateConflict)?,
        )
        .min(provenance.expires_at().get())
        .min(release.rules.not_after_unix_ms())
        .min(rule.not_after_unix_ms());
    let send_at = clock();
    if send_at.get() < now.get()
        || send_at.get() >= deadline
        || owner.fused_model_release_binding_v04(task, send_at)? != profile
        || transport.recipient_identity() != recipient
    {
        return Err(G4Error::StateConflict);
    }
    // No retries or fallback. A timeout/lost reply leaves this attempt charged.
    let reply = match transport.exchange(
        &bytes,
        UnixMillisV2::new(deadline),
        MAX_FUSED_MODEL_REPLY_BYTES_V04,
    ) {
        Ok(bytes) if bytes.len() <= MAX_FUSED_MODEL_REPLY_BYTES_V04 => bytes,
        Ok(_) => return Ok(FusedModelExchangeOutcomeV04::RejectedReply),
        Err(_) => return Ok(FusedModelExchangeOutcomeV04::Unavailable),
    };
    let completed_at = clock();
    if completed_at.get() < send_at.get()
        || completed_at.get() >= deadline
        || transport.recipient_identity() != recipient
    {
        return Ok(FusedModelExchangeOutcomeV04::RejectedReply);
    }
    let update = match role {
        Role::Advisor => FusedPlanningUpdateV04::AcceptAdvice {
            round,
            sender: recipient,
            bytes: reply,
        },
        Role::Planner => FusedPlanningUpdateV04::AcceptPlan {
            round,
            sender: recipient,
            bytes: reply,
        },
    };
    match owner.update_fused_planning_v04(task, reservation.revision(), update, completed_at) {
        Ok(_) => Ok(FusedModelExchangeOutcomeV04::Accepted),
        // Storage uncertainty must not be disguised as a harmless model error.
        Err(G4Error::StateConflict) => Ok(FusedModelExchangeOutcomeV04::RejectedReply),
        Err(e) => Err(e),
    }
}
