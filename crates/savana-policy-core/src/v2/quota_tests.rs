use super::DispatchQuotaLedgerV2;
use crate::v2::{
    AttemptKindV2, AuthenticatedEffectDispositionV2, DispatchQuotaCounterV2,
    DispatchQuotaMutationKindV2, DispatchQuotaReservationStateV2, DispatchQuotaReservationV2,
    DispatchQuotaSubjectV2, G4Error, VerifiedQuotaLimitV2,
};
use savana_kernel_protocol::v2::{Digest32V2, DurableRunIdV2, Nonce32V2};

fn digest(byte: u8) -> Digest32V2 {
    Digest32V2::new([byte; 32])
}

fn limit(value: u32, subject: DispatchQuotaSubjectV2) -> VerifiedQuotaLimitV2 {
    VerifiedQuotaLimitV2::new_for_test(value, 0x7a, subject)
}

#[test]
fn quota_admission_is_checked_and_branch_typed() {
    let tool = DispatchQuotaSubjectV2::tool_attempt(AttemptKindV2::ToolWrite);
    let release = DispatchQuotaSubjectV2::final_release(digest(7));
    assert_ne!(tool, release);

    let counter = DispatchQuotaCounterV2::new(1, 1);
    assert_eq!(
        DispatchQuotaReservationV2::reserve(
            counter,
            limit(2, tool),
            DurableRunIdV2::new([1; 32]),
            tool,
            digest(2),
            Nonce32V2::new([3; 32]),
        )
        .unwrap_err(),
        G4Error::QuotaExceeded
    );
}

#[test]
fn quota_reservation_implements_the_exact_transition_matrix() {
    let (counter, reserved) = DispatchQuotaReservationV2::reserve(
        DispatchQuotaCounterV2::new(0, 0),
        limit(
            1,
            DispatchQuotaSubjectV2::tool_attempt(AttemptKindV2::ToolRead),
        ),
        DurableRunIdV2::new([1; 32]),
        DispatchQuotaSubjectV2::tool_attempt(AttemptKindV2::ToolRead),
        digest(2),
        Nonce32V2::new([3; 32]),
    )
    .unwrap();
    assert_eq!(counter, DispatchQuotaCounterV2::new(1, 0));

    let (counter, spent) = reserved
        .transition(
            counter,
            AuthenticatedEffectDispositionV2::effect_started_for_test(),
        )
        .unwrap();
    assert_eq!(spent.state(), DispatchQuotaReservationStateV2::Spent);
    assert_eq!(counter, DispatchQuotaCounterV2::new(0, 1));

    let (counter, indeterminate) = spent
        .transition(
            counter,
            AuthenticatedEffectDispositionV2::indeterminate_for_test(),
        )
        .unwrap();
    assert_eq!(
        indeterminate.state(),
        DispatchQuotaReservationStateV2::IndeterminateSpent
    );
    assert_eq!(counter, DispatchQuotaCounterV2::new(0, 1));
    assert_eq!(
        indeterminate
            .transition(
                counter,
                AuthenticatedEffectDispositionV2::failed_no_effect_for_test(),
            )
            .unwrap_err(),
        G4Error::InvalidQuotaTransition
    );
}

#[test]
fn failed_no_effect_releases_without_spending() {
    let (counter, reserved) = DispatchQuotaReservationV2::reserve(
        DispatchQuotaCounterV2::new(0, 0),
        limit(1, DispatchQuotaSubjectV2::final_release(digest(4))),
        DurableRunIdV2::new([1; 32]),
        DispatchQuotaSubjectV2::final_release(digest(4)),
        digest(2),
        Nonce32V2::new([3; 32]),
    )
    .unwrap();
    let (counter, released) = reserved
        .transition(
            counter,
            AuthenticatedEffectDispositionV2::failed_no_effect_for_test(),
        )
        .unwrap();
    assert_eq!(
        released.state(),
        DispatchQuotaReservationStateV2::ReleasedNoEffect
    );
    assert_eq!(counter, DispatchQuotaCounterV2::new(0, 0));
}

#[test]
fn quota_ledger_keeps_tool_and_release_branches_separate() {
    let run = DurableRunIdV2::new([0x21; 32]);
    let mut ledger = DispatchQuotaLedgerV2::new();
    let tool = ledger
        .reserve_or_replay(
            limit(
                1,
                DispatchQuotaSubjectV2::tool_attempt(AttemptKindV2::ToolWrite),
            ),
            run,
            DispatchQuotaSubjectV2::tool_attempt(AttemptKindV2::ToolWrite),
            digest(0x22),
            Nonce32V2::new([0x23; 32]),
        )
        .unwrap();
    let release = ledger
        .reserve_or_replay(
            limit(1, DispatchQuotaSubjectV2::final_release(digest(0x24))),
            run,
            DispatchQuotaSubjectV2::final_release(digest(0x24)),
            digest(0x25),
            Nonce32V2::new([0x26; 32]),
        )
        .unwrap();

    assert_eq!(tool.kind(), DispatchQuotaMutationKindV2::Applied);
    assert_eq!(release.kind(), DispatchQuotaMutationKindV2::Applied);
    assert_eq!(
        ledger
            .counter(
                run,
                DispatchQuotaSubjectV2::tool_attempt(AttemptKindV2::ToolWrite)
            )
            .unwrap(),
        DispatchQuotaCounterV2::new(1, 0)
    );
    assert_eq!(
        ledger
            .counter(run, DispatchQuotaSubjectV2::final_release(digest(0x24)))
            .unwrap(),
        DispatchQuotaCounterV2::new(1, 0)
    );
    assert_eq!(
        ledger
            .counter(run, DispatchQuotaSubjectV2::final_release(digest(0x27)))
            .unwrap_err(),
        G4Error::QuotaCounterNotFound
    );
}

#[test]
fn quota_replay_does_not_double_reserve_or_spend() {
    let run = DurableRunIdV2::new([0x31; 32]);
    let subject = DispatchQuotaSubjectV2::tool_attempt(AttemptKindV2::ToolIrreversible);
    let dispatch = digest(0x32);
    let nonce = Nonce32V2::new([0x33; 32]);
    let mut ledger = DispatchQuotaLedgerV2::new();
    ledger
        .reserve_or_replay(limit(1, subject), run, subject, dispatch, nonce)
        .unwrap();
    let replay = ledger
        .reserve_or_replay(limit(1, subject), run, subject, dispatch, nonce)
        .unwrap();
    assert_eq!(replay.kind(), DispatchQuotaMutationKindV2::Replay);
    assert_eq!(
        ledger.counter(run, subject).unwrap(),
        DispatchQuotaCounterV2::new(1, 0)
    );

    ledger
        .transition_or_replay(
            nonce,
            dispatch,
            AuthenticatedEffectDispositionV2::known_success_for_test(),
        )
        .unwrap();
    let transition_replay = ledger
        .transition_or_replay(
            nonce,
            dispatch,
            AuthenticatedEffectDispositionV2::known_success_for_test(),
        )
        .unwrap();
    assert_eq!(
        transition_replay.kind(),
        DispatchQuotaMutationKindV2::Replay
    );
    assert_eq!(
        ledger.counter(run, subject).unwrap(),
        DispatchQuotaCounterV2::new(0, 1)
    );
}

#[test]
fn quota_conflicts_and_illegal_transitions_leave_ledger_unchanged() {
    let run = DurableRunIdV2::new([0x41; 32]);
    let subject = DispatchQuotaSubjectV2::tool_attempt(AttemptKindV2::ToolWrite);
    let dispatch = digest(0x42);
    let nonce = Nonce32V2::new([0x43; 32]);
    let mut ledger = DispatchQuotaLedgerV2::new();
    ledger
        .reserve_or_replay(limit(2, subject), run, subject, dispatch, nonce)
        .unwrap();
    assert_eq!(
        ledger
            .reserve_or_replay(
                limit(2, DispatchQuotaSubjectV2::final_release(digest(0x44)),),
                run,
                DispatchQuotaSubjectV2::final_release(digest(0x44)),
                digest(0x45),
                nonce,
            )
            .unwrap_err(),
        G4Error::StateConflict
    );
    assert_eq!(
        ledger.counter(run, subject).unwrap(),
        DispatchQuotaCounterV2::new(1, 0)
    );

    ledger
        .transition_or_replay(
            nonce,
            dispatch,
            AuthenticatedEffectDispositionV2::known_success_for_test(),
        )
        .unwrap();
    let before = ledger.counter(run, subject).unwrap();
    assert_eq!(
        ledger
            .transition_or_replay(
                nonce,
                dispatch,
                AuthenticatedEffectDispositionV2::failed_no_effect_for_test(),
            )
            .unwrap_err(),
        G4Error::InvalidQuotaTransition
    );
    assert_eq!(ledger.counter(run, subject).unwrap(), before);
}

#[test]
fn one_dispatch_subject_can_never_acquire_a_second_nonce() {
    let run = DurableRunIdV2::new([0x51; 32]);
    let subject = DispatchQuotaSubjectV2::tool_attempt(AttemptKindV2::ToolIrreversible);
    let dispatch = digest(0x52);
    let mut ledger = DispatchQuotaLedgerV2::new();
    ledger
        .reserve_or_replay(
            limit(2, subject),
            run,
            subject,
            dispatch,
            Nonce32V2::new([0x53; 32]),
        )
        .unwrap();
    let before = ledger.counter(run, subject).unwrap();

    assert_eq!(
        ledger
            .reserve_or_replay(
                limit(2, subject),
                run,
                subject,
                dispatch,
                Nonce32V2::new([0x54; 32]),
            )
            .unwrap_err(),
        G4Error::StateConflict
    );
    assert_eq!(ledger.counter(run, subject).unwrap(), before);
}

#[test]
fn quota_limit_is_immutable_after_first_policy_bound_reservation() {
    let run = DurableRunIdV2::new([0x61; 32]);
    let subject = DispatchQuotaSubjectV2::tool_attempt(AttemptKindV2::ToolWrite);
    let mut ledger = DispatchQuotaLedgerV2::new();
    ledger
        .reserve_or_replay(
            VerifiedQuotaLimitV2::new_for_test(1, 0x62, subject),
            run,
            subject,
            digest(0x63),
            Nonce32V2::new([0x64; 32]),
        )
        .unwrap();

    assert_eq!(
        ledger
            .reserve_or_replay(
                VerifiedQuotaLimitV2::new_for_test(2, 0x65, subject),
                run,
                subject,
                digest(0x66),
                Nonce32V2::new([0x67; 32]),
            )
            .unwrap_err(),
        G4Error::StateConflict
    );
    assert_eq!(
        ledger.counter(run, subject).unwrap(),
        DispatchQuotaCounterV2::new(1, 0)
    );
}

#[test]
fn quota_limit_capability_cannot_cross_subject_branches() {
    let tool = DispatchQuotaSubjectV2::tool_attempt(AttemptKindV2::ToolWrite);
    let release = DispatchQuotaSubjectV2::final_release(digest(0x91));
    let tool_limit = VerifiedQuotaLimitV2::new_for_test(100, 0x92, tool);

    assert_eq!(
        DispatchQuotaReservationV2::reserve(
            DispatchQuotaCounterV2::new(0, 0),
            tool_limit,
            DurableRunIdV2::new([0x93; 32]),
            release,
            digest(0x94),
            Nonce32V2::new([0x95; 32]),
        )
        .unwrap_err(),
        G4Error::InvalidQuotaLimit
    );
}
