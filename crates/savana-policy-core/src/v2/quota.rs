use savana_kernel_protocol::v2::{Digest32V2, DurableRunIdV2, Nonce32V2};

use super::{AttemptKindV2, G4Error};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VerifiedQuotaLimitV2 {
    limit: u32,
    policy_binding_digest: Digest32V2,
    subject: DispatchQuotaSubjectV2,
}

impl VerifiedQuotaLimitV2 {
    pub fn from_verified_policy(
        limit: u32,
        policy_binding_digest: Digest32V2,
        subject: DispatchQuotaSubjectV2,
    ) -> Result<Self, G4Error> {
        if limit == 0
            || is_zero(policy_binding_digest.as_bytes())
            || matches!(
                subject,
                DispatchQuotaSubjectV2::FinalRelease {
                    release_quota_subject_digest
                } if is_zero(release_quota_subject_digest.as_bytes())
            )
        {
            return Err(G4Error::InvalidQuotaLimit);
        }
        Ok(Self {
            limit,
            policy_binding_digest,
            subject,
        })
    }

    #[cfg(test)]
    pub(crate) fn new_for_test(limit: u32, seed: u8, subject: DispatchQuotaSubjectV2) -> Self {
        Self::from_verified_policy(limit, Digest32V2::new([seed; 32]), subject).unwrap()
    }

    pub const fn limit(self) -> u32 {
        self.limit
    }

    pub const fn policy_binding_digest(self) -> Digest32V2 {
        self.policy_binding_digest
    }

    pub const fn subject(self) -> DispatchQuotaSubjectV2 {
        self.subject
    }
}

impl<C> minicbor::Encode<C> for VerifiedQuotaLimitV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.array(3)?.u32(self.limit)?;
        self.policy_binding_digest.encode(encoder, context)?;
        self.subject.encode(encoder, context)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DispatchQuotaSubjectV2 {
    ToolAttempt {
        attempt_kind: AttemptKindV2,
    },
    FinalRelease {
        release_quota_subject_digest: Digest32V2,
    },
}

impl DispatchQuotaSubjectV2 {
    pub const fn tool_attempt(attempt_kind: AttemptKindV2) -> Self {
        Self::ToolAttempt { attempt_kind }
    }

    pub const fn final_release(release_quota_subject_digest: Digest32V2) -> Self {
        Self::FinalRelease {
            release_quota_subject_digest,
        }
    }
}

impl<C> minicbor::Encode<C> for DispatchQuotaSubjectV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        match self {
            Self::ToolAttempt { attempt_kind } => {
                encoder.array(2)?.u16(1)?;
                attempt_kind.encode(encoder, context)?;
            }
            Self::FinalRelease {
                release_quota_subject_digest,
            } => {
                encoder.array(2)?.u16(2)?;
                release_quota_subject_digest.encode(encoder, context)?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DispatchQuotaCounterV2 {
    reserved: u32,
    spent: u32,
}

impl DispatchQuotaCounterV2 {
    pub const fn new(reserved: u32, spent: u32) -> Self {
        Self { reserved, spent }
    }

    pub const fn reserved(self) -> u32 {
        self.reserved
    }

    pub const fn spent(self) -> u32 {
        self.spent
    }
}

impl<C> minicbor::Encode<C> for DispatchQuotaCounterV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        _context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.array(2)?.u32(self.reserved)?.u32(self.spent)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DispatchQuotaReservationStateV2 {
    Reserved,
    Spent,
    ReleasedNoEffect,
    IndeterminateSpent,
}

impl DispatchQuotaReservationStateV2 {
    pub const fn tag(self) -> u16 {
        match self {
            Self::Reserved => 1,
            Self::Spent => 2,
            Self::ReleasedNoEffect => 3,
            Self::IndeterminateSpent => 4,
        }
    }
}

impl<C> minicbor::Encode<C> for DispatchQuotaReservationStateV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        _context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.array(1)?.u16(self.tag())?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum AuthenticatedEffectDispositionKindV2 {
    EffectStarted,
    KnownSuccess,
    FailedNoEffect,
    Indeterminate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AuthenticatedEffectDispositionV2(AuthenticatedEffectDispositionKindV2);

impl AuthenticatedEffectDispositionV2 {
    pub(crate) const fn from_verified_effect_started_receipt() -> Self {
        Self(AuthenticatedEffectDispositionKindV2::EffectStarted)
    }

    pub(crate) const fn from_verified_known_success() -> Self {
        Self(AuthenticatedEffectDispositionKindV2::KnownSuccess)
    }

    pub(crate) const fn from_verified_failed_no_effect() -> Self {
        Self(AuthenticatedEffectDispositionKindV2::FailedNoEffect)
    }

    pub(crate) const fn from_verified_indeterminate() -> Self {
        Self(AuthenticatedEffectDispositionKindV2::Indeterminate)
    }

    pub(crate) const fn kind(self) -> AuthenticatedEffectDispositionKindV2 {
        self.0
    }

    #[cfg(test)]
    pub(crate) const fn effect_started_for_test() -> Self {
        Self::from_verified_effect_started_receipt()
    }

    #[cfg(test)]
    pub(crate) const fn known_success_for_test() -> Self {
        Self::from_verified_known_success()
    }

    #[cfg(test)]
    pub(crate) const fn failed_no_effect_for_test() -> Self {
        Self::from_verified_failed_no_effect()
    }

    #[cfg(test)]
    pub(crate) const fn indeterminate_for_test() -> Self {
        Self::from_verified_indeterminate()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DispatchQuotaReservationV2 {
    pub(crate) durable_run_id: DurableRunIdV2,
    pub(crate) quota_subject: DispatchQuotaSubjectV2,
    pub(crate) dispatch_subject_digest: Digest32V2,
    pub(crate) execution_nonce: Nonce32V2,
    pub(crate) state: DispatchQuotaReservationStateV2,
}

impl DispatchQuotaReservationV2 {
    pub fn reserve(
        counter: DispatchQuotaCounterV2,
        verified_limit: VerifiedQuotaLimitV2,
        durable_run_id: DurableRunIdV2,
        quota_subject: DispatchQuotaSubjectV2,
        dispatch_subject_digest: Digest32V2,
        execution_nonce: Nonce32V2,
    ) -> Result<(DispatchQuotaCounterV2, Self), G4Error> {
        if verified_limit.subject != quota_subject {
            return Err(G4Error::InvalidQuotaLimit);
        }
        let used = counter
            .reserved
            .checked_add(counter.spent)
            .ok_or(G4Error::QuotaExceeded)?;
        if used >= verified_limit.limit {
            return Err(G4Error::QuotaExceeded);
        }
        let next_counter = DispatchQuotaCounterV2 {
            reserved: counter
                .reserved
                .checked_add(1)
                .ok_or(G4Error::QuotaExceeded)?,
            spent: counter.spent,
        };
        Ok((
            next_counter,
            Self {
                durable_run_id,
                quota_subject,
                dispatch_subject_digest,
                execution_nonce,
                state: DispatchQuotaReservationStateV2::Reserved,
            },
        ))
    }

    pub(crate) fn transition(
        self,
        counter: DispatchQuotaCounterV2,
        disposition: AuthenticatedEffectDispositionV2,
    ) -> Result<(DispatchQuotaCounterV2, Self), G4Error> {
        use AuthenticatedEffectDispositionKindV2::{
            EffectStarted, FailedNoEffect, Indeterminate, KnownSuccess,
        };
        use DispatchQuotaReservationStateV2::{
            IndeterminateSpent, ReleasedNoEffect, Reserved, Spent,
        };

        let (next_counter, next_state) = match (self.state, disposition.kind()) {
            (Reserved, EffectStarted | KnownSuccess) => (spend(counter)?, Spent),
            (Reserved, Indeterminate) => (spend(counter)?, IndeterminateSpent),
            (Reserved, FailedNoEffect) => (release(counter)?, ReleasedNoEffect),
            (Spent, EffectStarted | KnownSuccess) => (counter, Spent),
            (Spent, Indeterminate) => (counter, IndeterminateSpent),
            (Spent, FailedNoEffect) | (ReleasedNoEffect | IndeterminateSpent, _) => {
                return Err(G4Error::InvalidQuotaTransition);
            }
        };
        Ok((
            next_counter,
            Self {
                state: next_state,
                ..self
            },
        ))
    }

    pub const fn state(self) -> DispatchQuotaReservationStateV2 {
        self.state
    }

    pub const fn quota_subject(self) -> DispatchQuotaSubjectV2 {
        self.quota_subject
    }
}

impl<C> minicbor::Encode<C> for DispatchQuotaReservationV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.array(5)?;
        self.durable_run_id.encode(encoder, context)?;
        self.quota_subject.encode(encoder, context)?;
        self.dispatch_subject_digest.encode(encoder, context)?;
        self.execution_nonce.encode(encoder, context)?;
        self.state.encode(encoder, context)?;
        Ok(())
    }
}

fn spend(counter: DispatchQuotaCounterV2) -> Result<DispatchQuotaCounterV2, G4Error> {
    Ok(DispatchQuotaCounterV2 {
        reserved: counter
            .reserved
            .checked_sub(1)
            .ok_or(G4Error::InvalidQuotaTransition)?,
        spent: counter
            .spent
            .checked_add(1)
            .ok_or(G4Error::InvalidQuotaTransition)?,
    })
}

fn release(counter: DispatchQuotaCounterV2) -> Result<DispatchQuotaCounterV2, G4Error> {
    Ok(DispatchQuotaCounterV2 {
        reserved: counter
            .reserved
            .checked_sub(1)
            .ok_or(G4Error::InvalidQuotaTransition)?,
        spent: counter.spent,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchQuotaMutationKindV2 {
    Applied,
    Replay,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DispatchQuotaMutationV2 {
    kind: DispatchQuotaMutationKindV2,
    counter: DispatchQuotaCounterV2,
    reservation_state: DispatchQuotaReservationStateV2,
}

impl DispatchQuotaMutationV2 {
    pub const fn kind(self) -> DispatchQuotaMutationKindV2 {
        self.kind
    }

    pub const fn counter(self) -> DispatchQuotaCounterV2 {
        self.counter
    }

    pub const fn reservation_state(self) -> DispatchQuotaReservationStateV2 {
        self.reservation_state
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct DispatchQuotaCounterEntryV2 {
    pub(crate) durable_run_id: DurableRunIdV2,
    pub(crate) subject: DispatchQuotaSubjectV2,
    pub(crate) verified_limit: VerifiedQuotaLimitV2,
    pub(crate) counter: DispatchQuotaCounterV2,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct DispatchQuotaLedgerEntryV2 {
    pub(crate) reservation: DispatchQuotaReservationV2,
    pub(crate) last_disposition: Option<AuthenticatedEffectDispositionV2>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct DispatchQuotaLedgerV2 {
    pub(crate) counters: Vec<DispatchQuotaCounterEntryV2>,
    pub(crate) reservations: Vec<DispatchQuotaLedgerEntryV2>,
}

impl DispatchQuotaLedgerV2 {
    const MAX_COUNTERS: usize = 65_536;
    const MAX_RESERVATIONS: usize = 65_536;

    pub const fn new() -> Self {
        Self {
            counters: Vec::new(),
            reservations: Vec::new(),
        }
    }

    pub(crate) fn reserve_or_replay(
        &mut self,
        verified_limit: VerifiedQuotaLimitV2,
        durable_run_id: DurableRunIdV2,
        subject: DispatchQuotaSubjectV2,
        dispatch_subject_digest: Digest32V2,
        execution_nonce: Nonce32V2,
    ) -> Result<DispatchQuotaMutationV2, G4Error> {
        if verified_limit.subject != subject {
            return Err(G4Error::InvalidQuotaLimit);
        }
        if let Some(entry) = self
            .reservations
            .iter()
            .find(|entry| entry.reservation.execution_nonce == execution_nonce)
        {
            if entry.reservation.durable_run_id != durable_run_id
                || entry.reservation.quota_subject != subject
                || entry.reservation.dispatch_subject_digest != dispatch_subject_digest
            {
                return Err(G4Error::StateConflict);
            }
            let counter_entry = self
                .counters
                .iter()
                .find(|counter| {
                    counter.durable_run_id == durable_run_id && counter.subject == subject
                })
                .ok_or(G4Error::InvalidQuotaTransition)?;
            if counter_entry.verified_limit != verified_limit {
                return Err(G4Error::StateConflict);
            }
            return Ok(DispatchQuotaMutationV2 {
                kind: DispatchQuotaMutationKindV2::Replay,
                counter: counter_entry.counter,
                reservation_state: entry.reservation.state,
            });
        }
        if self
            .reservations
            .iter()
            .any(|entry| entry.reservation.dispatch_subject_digest == dispatch_subject_digest)
        {
            return Err(G4Error::StateConflict);
        }

        let counter_index = self
            .counters
            .iter()
            .position(|entry| entry.durable_run_id == durable_run_id && entry.subject == subject);
        let counter = counter_index
            .map(|index| self.counters[index].counter)
            .unwrap_or(DispatchQuotaCounterV2::new(0, 0));
        if counter_index.is_some_and(|index| self.counters[index].verified_limit != verified_limit)
        {
            return Err(G4Error::StateConflict);
        }
        let (next_counter, reservation) = DispatchQuotaReservationV2::reserve(
            counter,
            verified_limit,
            durable_run_id,
            subject,
            dispatch_subject_digest,
            execution_nonce,
        )?;

        if self.reservations.len() >= Self::MAX_RESERVATIONS
            || (counter_index.is_none() && self.counters.len() >= Self::MAX_COUNTERS)
        {
            return Err(G4Error::IntentLimitExceeded);
        }
        self.reservations
            .try_reserve(1)
            .map_err(|_| G4Error::AllocationFailure)?;
        if counter_index.is_none() {
            self.counters
                .try_reserve(1)
                .map_err(|_| G4Error::AllocationFailure)?;
        }
        match counter_index {
            Some(index) => self.counters[index].counter = next_counter,
            None => self.counters.push(DispatchQuotaCounterEntryV2 {
                durable_run_id,
                subject,
                verified_limit,
                counter: next_counter,
            }),
        }
        self.reservations.push(DispatchQuotaLedgerEntryV2 {
            reservation,
            last_disposition: None,
        });
        Ok(DispatchQuotaMutationV2 {
            kind: DispatchQuotaMutationKindV2::Applied,
            counter: next_counter,
            reservation_state: DispatchQuotaReservationStateV2::Reserved,
        })
    }

    pub(crate) fn transition_or_replay(
        &mut self,
        execution_nonce: Nonce32V2,
        dispatch_subject_digest: Digest32V2,
        disposition: AuthenticatedEffectDispositionV2,
    ) -> Result<DispatchQuotaMutationV2, G4Error> {
        let reservation_index = self
            .reservations
            .iter()
            .position(|entry| entry.reservation.execution_nonce == execution_nonce)
            .ok_or(G4Error::IntentNotFound)?;
        let current = self.reservations[reservation_index];
        if current.reservation.dispatch_subject_digest != dispatch_subject_digest {
            return Err(G4Error::StateConflict);
        }
        let counter_index = self
            .counters
            .iter()
            .position(|entry| {
                entry.durable_run_id == current.reservation.durable_run_id
                    && entry.subject == current.reservation.quota_subject
            })
            .ok_or(G4Error::InvalidQuotaTransition)?;
        let counter = self.counters[counter_index].counter;
        if current.last_disposition == Some(disposition) {
            return Ok(DispatchQuotaMutationV2 {
                kind: DispatchQuotaMutationKindV2::Replay,
                counter,
                reservation_state: current.reservation.state,
            });
        }
        let (next_counter, next_reservation) =
            current.reservation.transition(counter, disposition)?;
        self.counters[counter_index].counter = next_counter;
        self.reservations[reservation_index] = DispatchQuotaLedgerEntryV2 {
            reservation: next_reservation,
            last_disposition: Some(disposition),
        };
        Ok(DispatchQuotaMutationV2 {
            kind: DispatchQuotaMutationKindV2::Applied,
            counter: next_counter,
            reservation_state: next_reservation.state,
        })
    }

    pub(crate) fn counter(
        &self,
        durable_run_id: DurableRunIdV2,
        subject: DispatchQuotaSubjectV2,
    ) -> Result<DispatchQuotaCounterV2, G4Error> {
        self.counters
            .iter()
            .find_map(|entry| {
                (entry.durable_run_id == durable_run_id && entry.subject == subject)
                    .then_some(entry.counter)
            })
            .ok_or(G4Error::QuotaCounterNotFound)
    }
}

fn is_zero<const N: usize>(bytes: &[u8; N]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

#[cfg(test)]
#[path = "quota_tests.rs"]
mod tests;
