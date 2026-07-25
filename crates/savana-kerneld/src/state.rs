use savana_kernel_protocol::{Digest32, Nonce32, StableCode, UnixMillis};

const REPLAY_SLOTS_PER_CLIENT: usize = 128;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ReplayStatus {
    Pending,
    Finished,
}

#[derive(Clone, Copy)]
struct ReplayEntry {
    client_nonce: Nonce32,
    transcript_digest: Digest32,
    expires_at: UnixMillis,
    status: ReplayStatus,
}

struct ReplayPartition {
    slots: [Option<ReplayEntry>; REPLAY_SLOTS_PER_CLIENT],
}

impl ReplayPartition {
    const fn new() -> Self {
        Self {
            slots: [None; REPLAY_SLOTS_PER_CLIENT],
        }
    }

    fn clean_expired(&mut self, now: UnixMillis) {
        for slot in &mut self.slots {
            if slot
                .as_ref()
                .is_some_and(|entry| entry.expires_at.get() <= now.get())
            {
                *slot = None;
            }
        }
    }

    #[cfg(test)]
    const fn slot_count(&self) -> usize {
        self.slots.len()
    }

    #[cfg(test)]
    fn clear_slot_for_test(&mut self, slot: usize) {
        self.slots[slot] = None;
    }

    #[cfg(test)]
    fn used_slots_for_test(&self) -> usize {
        self.slots.iter().filter(|slot| slot.is_some()).count()
    }
}

pub(super) struct ReplayState {
    latest_observed: UnixMillis,
    partitions: Box<[ReplayPartition]>,
}

impl ReplayState {
    pub(super) fn new(client_count: usize, startup_now: UnixMillis) -> Self {
        let partitions = std::iter::repeat_with(ReplayPartition::new)
            .take(client_count)
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Self {
            latest_observed: startup_now,
            partitions,
        }
    }

    pub(super) fn observe(&mut self, now: UnixMillis) -> Result<(), StableCode> {
        if now.get() < self.latest_observed.get() {
            return Err(StableCode::KernelUnavailable);
        }
        self.latest_observed = now;
        Ok(())
    }

    pub(super) fn reserve_slot(
        &mut self,
        partition_index: usize,
        client_nonce: Nonce32,
        now: UnixMillis,
    ) -> Result<usize, StableCode> {
        let partition = self
            .partitions
            .get_mut(partition_index)
            .ok_or(StableCode::KernelUnavailable)?;
        partition.clean_expired(now);

        let mut first_available = None;
        for (index, slot) in partition.slots.iter().enumerate() {
            match slot {
                Some(entry) if entry.client_nonce == client_nonce => {
                    return Err(StableCode::IdentityReplay);
                }
                None if first_available.is_none() => first_available = Some(index),
                Some(_) | None => {}
            }
        }
        first_available.ok_or(StableCode::KernelOverloaded)
    }

    pub(super) fn commit_pending(
        &mut self,
        partition_index: usize,
        slot_index: usize,
        client_nonce: Nonce32,
        transcript_digest: Digest32,
        expires_at: UnixMillis,
    ) -> Result<(), StableCode> {
        let slot = self
            .partitions
            .get_mut(partition_index)
            .and_then(|partition| partition.slots.get_mut(slot_index))
            .ok_or(StableCode::KernelUnavailable)?;
        if slot.is_some() {
            return Err(StableCode::KernelUnavailable);
        }
        *slot = Some(ReplayEntry {
            client_nonce,
            transcript_digest,
            expires_at,
            status: ReplayStatus::Pending,
        });
        Ok(())
    }

    pub(super) fn validate_pending(
        &self,
        partition_index: usize,
        slot_index: usize,
        client_nonce: Nonce32,
        transcript_digest: Digest32,
        expires_at: UnixMillis,
    ) -> Result<(), StableCode> {
        let entry = self
            .partitions
            .get(partition_index)
            .and_then(|partition| partition.slots.get(slot_index))
            .and_then(Option::as_ref)
            .ok_or(StableCode::IdentityTranscriptMismatch)?;
        if entry.client_nonce != client_nonce
            || entry.transcript_digest != transcript_digest
            || entry.expires_at != expires_at
        {
            return Err(StableCode::IdentityTranscriptMismatch);
        }
        match entry.status {
            ReplayStatus::Pending => Ok(()),
            ReplayStatus::Finished => Err(StableCode::IdentityReplay),
        }
    }

    pub(super) fn mark_finished(
        &mut self,
        partition_index: usize,
        slot_index: usize,
    ) -> Result<(), StableCode> {
        let entry = self
            .partitions
            .get_mut(partition_index)
            .and_then(|partition| partition.slots.get_mut(slot_index))
            .and_then(Option::as_mut)
            .ok_or(StableCode::IdentityTranscriptMismatch)?;
        if entry.status != ReplayStatus::Pending {
            return Err(StableCode::IdentityReplay);
        }
        entry.status = ReplayStatus::Finished;
        Ok(())
    }

    #[cfg(test)]
    fn partition_count(&self) -> usize {
        self.partitions.len()
    }

    #[cfg(test)]
    fn partitions_for_test(&self) -> &[ReplayPartition] {
        &self.partitions
    }

    #[cfg(test)]
    fn partitions_for_test_mut(&mut self) -> &mut [ReplayPartition] {
        &mut self.partitions
    }

    #[cfg(test)]
    pub(super) fn status_for_digest(&self, digest: Digest32) -> Option<(ReplayStatus, UnixMillis)> {
        self.partitions
            .iter()
            .flat_map(|partition| partition.slots.iter())
            .filter_map(Option::as_ref)
            .find(|entry| entry.transcript_digest == digest)
            .map(|entry| (entry.status, entry.expires_at))
    }

    #[cfg(test)]
    fn admit_pending_for_test(
        &mut self,
        partition_index: usize,
        client_nonce: Nonce32,
        transcript_digest: Digest32,
        expires_at: UnixMillis,
        now: UnixMillis,
    ) -> Result<usize, StableCode> {
        let slot = self.reserve_slot(partition_index, client_nonce, now)?;
        self.commit_pending(
            partition_index,
            slot,
            client_nonce,
            transcript_digest,
            expires_at,
        )?;
        Ok(slot)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_partitions_are_fixed_at_128_slots_per_configured_client() {
        let state = ReplayState::new(16, UnixMillis::new(1_000));

        assert_eq!(state.partition_count(), 16);
        assert!(state
            .partitions_for_test()
            .iter()
            .all(|partition| partition.slot_count() == 128));
    }

    #[test]
    fn replay_is_partitioned_and_live_entries_are_never_evicted() {
        let mut state = ReplayState::new(2, UnixMillis::new(1_000));
        let digest = Digest32::new([0x44; 32]);

        for byte in 1_u8..=128 {
            state
                .admit_pending_for_test(
                    0,
                    Nonce32::new([byte; 32]),
                    digest,
                    UnixMillis::new(6_000),
                    UnixMillis::new(1_000),
                )
                .unwrap();
        }

        assert_eq!(
            state
                .admit_pending_for_test(
                    0,
                    Nonce32::new([0xff; 32]),
                    digest,
                    UnixMillis::new(6_000),
                    UnixMillis::new(1_000),
                )
                .unwrap_err(),
            StableCode::KernelOverloaded
        );
        assert_eq!(
            state
                .admit_pending_for_test(
                    0,
                    Nonce32::new([128; 32]),
                    digest,
                    UnixMillis::new(6_000),
                    UnixMillis::new(1_000),
                )
                .unwrap_err(),
            StableCode::IdentityReplay
        );
        assert!(state
            .admit_pending_for_test(
                1,
                Nonce32::new([1; 32]),
                digest,
                UnixMillis::new(6_000),
                UnixMillis::new(1_000),
            )
            .is_ok());
    }

    #[test]
    fn admission_scans_past_the_first_hole_for_a_late_duplicate() {
        let mut state = ReplayState::new(1, UnixMillis::new(1_000));
        let digest = Digest32::new([0x44; 32]);
        for byte in 1_u8..=128 {
            state
                .admit_pending_for_test(
                    0,
                    Nonce32::new([byte; 32]),
                    digest,
                    UnixMillis::new(6_000),
                    UnixMillis::new(1_000),
                )
                .unwrap();
        }
        state.partitions_for_test_mut()[0].clear_slot_for_test(0);

        assert_eq!(
            state
                .admit_pending_for_test(
                    0,
                    Nonce32::new([128; 32]),
                    digest,
                    UnixMillis::new(6_000),
                    UnixMillis::new(1_000),
                )
                .unwrap_err(),
            StableCode::IdentityReplay
        );
        assert_eq!(state.partitions_for_test()[0].used_slots_for_test(), 127);
    }

    #[test]
    fn cleanup_is_limited_to_the_current_client_partition() {
        let mut state = ReplayState::new(2, UnixMillis::new(1_000));
        let digest = Digest32::new([0x44; 32]);
        for partition in 0..2 {
            state
                .admit_pending_for_test(
                    partition,
                    Nonce32::new([0x20; 32]),
                    digest,
                    UnixMillis::new(2_000),
                    UnixMillis::new(1_000),
                )
                .unwrap();
        }

        state
            .reserve_slot(0, Nonce32::new([0x21; 32]), UnixMillis::new(2_000))
            .unwrap();

        assert_eq!(state.partitions_for_test()[0].used_slots_for_test(), 0);
        assert_eq!(state.partitions_for_test()[1].used_slots_for_test(), 1);
    }
}
