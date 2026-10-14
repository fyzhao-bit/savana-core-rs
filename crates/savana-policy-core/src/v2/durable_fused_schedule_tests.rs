use super::*;

fn scheduled_profile() -> FusedPlanningProfileV04 {
    let mut p = profile();
    p.release_model_views = true;
    p.delivery_schedule = vec![
        FusedDeliverySlotV04 {
            id: 1,
            round: 1,
            role: Role::Advisor,
            opens_at: 11,
            closes_at: 14,
        },
        FusedDeliverySlotV04 {
            id: 2,
            round: 1,
            role: Role::Advisor,
            opens_at: 16,
            closes_at: 19,
        },
        FusedDeliverySlotV04 {
            id: 3,
            round: 1,
            role: Role::Planner,
            opens_at: 21,
            closes_at: 25,
        },
        FusedDeliverySlotV04 {
            id: 4,
            round: 1,
            role: Role::Planner,
            opens_at: 30,
            closes_at: 35,
        },
    ];
    p
}
fn install_scheduled(s: &mut DurableG4StateV2) {
    s.install_verified_task_authorization(auth(1)).unwrap();
    s.install_fused_planning_v04(verified(scheduled_profile()), now(10))
        .unwrap();
    assert_eq!(s.snapshot.payload_schema, 13);
}

#[test]
fn fused_schedule_missing_worker_only_skips_expired_windows() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(STATE_FILE_NAME);
    let anchor = TestRollbackProtectedStateAnchorV2::default();
    let mut s = task_store(&path, [0x81; 32], anchor.clone());
    install_scheduled(&mut s);
    let jobs = s.scheduled_fused_work_v04(now(11)).unwrap();
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].recipient, Some([20; 32]));
    let head = s.current_head;
    let outcome = s
        .update_fused_planning_v04(task(), 1, U::SkipExpiredDeliveries, now(11))
        .unwrap();
    assert!(outcome.view_for_release_check().is_none());
    assert_eq!(s.current_head, head);
    s.update_fused_planning_v04(task(), 1, U::SkipExpiredDeliveries, now(20))
        .unwrap();
    drop(s);
    let mut s = task_store(&path, [0x81; 32], anchor);
    let jobs = s.scheduled_fused_work_v04(now(21)).unwrap();
    assert_eq!(jobs[0].recipient, Some([21; 32]));
    assert_eq!(jobs[0].revision, 2);
    s.revoke_task_authorization(task()).unwrap();
    assert!(s.scheduled_fused_work_v04(now(21)).unwrap().is_empty());
}

#[test]
fn fused_schedule_reopen_retains_unactivated_candidate_without_retransmission() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(STATE_FILE_NAME);
    let anchor = TestRollbackProtectedStateAnchorV2::default();
    let mut s = task_store(&path, [0x81; 32], anchor.clone());
    install_scheduled(&mut s);
    let mut worker = Worker {
        reader: 21,
        ..Default::default()
    };
    tick(&mut s, &mut worker, [21; 3]).unwrap();
    drop(s);
    let mut s = task_store(&path, [0x81; 32], anchor);
    let work = s.scheduled_fused_work_v04(now(40)).unwrap();
    assert_eq!(work[0].activation_round, Some(1));
    let state = s.fused_planning_status_v04(task(), now(40)).unwrap();
    assert_eq!(state.active_plan_revision, 0);
    s.update_fused_planning_v04(
        task(),
        state.revision,
        U::Activate {
            round: 1,
            expected_plan_revision: 0,
        },
        now(40),
    )
    .unwrap();
    assert_eq!(
        s.fused_planning_status_v04(task(), now(40))
            .unwrap()
            .active_plan_revision,
        1
    );
    assert_eq!(worker.requests.len(), 1);
}
fn tick(
    s: &mut DurableG4StateV2,
    worker: &mut Worker,
    times: [u64; 3],
) -> Result<Option<FusedModelExchangeOutcomeV04>, G4Error> {
    let parent = parent();
    let parents = [&parent];
    let rules = rules(worker.reader, false);
    let release = FusedModelReleaseContextV04 {
        rules: &rules,
        provenance: context(),
        parents: &parents,
        allowed_effects: EffectSetV2::ALL,
    };
    let revision = s.fused_planning_status_v04(task(), now(times[0]))?.revision;
    let mut clock = times.into_iter();
    exchange_scheduled_fused_model_v04(s, task(), revision, release, worker, || {
        now(clock.next().expect("bounded clock reads"))
    })
}

#[test]
fn fused_schedule_is_signed_bounded_and_cannot_expand_rounds() {
    assert!(scheduled_profile().signing_digest().is_ok());
    for case in 0..10 {
        let mut p = scheduled_profile();
        match case {
            0 => p.release_model_views = false,
            1 => p.delivery_schedule[0].id = 0,
            2 => p.delivery_schedule[1].id = 1,
            3 => p.delivery_schedule[1].opens_at = 13,
            4 => p.delivery_schedule[0].closes_at = 11,
            5 => p.delivery_schedule[0].round = 99,
            6 => p.delivery_schedule[0].opens_at = 9,
            7 => p.delivery_schedule[1].closes_at = 21,
            8 => p.policy.rounds[0].advisor = None,
            9 => p.policy.rounds[0].max_deliveries = 1,
            _ => unreachable!(),
        }
        assert!(p.signing_digest().is_err(), "case {case}");
    }
    let p = scheduled_profile();
    let mut changed = p.clone();
    changed.delivery_schedule[0].opens_at += 1;
    assert_ne!(
        p.signing_digest().unwrap(),
        changed.signing_digest().unwrap()
    );
    // Legacy profiles retain canonical bytes: absent is not an unsigned schedule.
    assert!(!serde_json::to_string(&profile())
        .unwrap()
        .contains("delivery_schedule"));
}

#[test]
fn fused_schedule_retries_follow_public_slots_not_model_success_or_failure() {
    for mode in 0..4 {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(STATE_FILE_NAME);
        let anchor = TestRollbackProtectedStateAnchorV2::default();
        let mut s = task_store(&path, [0x81; 32], anchor.clone());
        install_scheduled(&mut s);
        let mut worker = Worker {
            reader: 20,
            mode,
            ..Default::default()
        };
        let head = s.current_head;
        assert_eq!(tick(&mut s, &mut worker, [10; 3]).unwrap(), None);
        assert_eq!(head, s.current_head);
        assert!(tick(&mut s, &mut worker, [11; 3]).unwrap().is_some());
        assert_eq!(tick(&mut s, &mut worker, [11; 3]).unwrap(), None);
        assert_eq!(worker.requests.len(), 1);
        drop(s);
        let mut s = task_store(&path, [0x81; 32], anchor);
        assert_eq!(tick(&mut s, &mut worker, [13; 3]).unwrap(), None);
        assert!(tick(&mut s, &mut worker, [16; 3]).unwrap().is_some());
        assert_eq!(worker.requests[0], worker.requests[1]);
        assert_eq!(tick(&mut s, &mut worker, [17; 3]).unwrap(), None);
        assert_eq!(worker.requests.len(), 2);
        assert!(s.snapshot.dispatch.entries.is_empty());
    }
}

#[test]
fn fused_schedule_skips_missed_slots_freezes_empty_advice_and_never_catches_up() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(STATE_FILE_NAME);
    let anchor = TestRollbackProtectedStateAnchorV2::default();
    let mut s = task_store(&path, [0x81; 32], anchor.clone());
    install_scheduled(&mut s);
    let mut worker = Worker {
        reader: 21,
        ..Default::default()
    };
    assert_eq!(tick(&mut s, &mut worker, [20; 3]).unwrap(), None);
    drop(s);
    let mut s = task_store(&path, [0x81; 32], anchor.clone());
    assert!(tick(&mut s, &mut worker, [16; 3]).is_err()); // persisted clock floor
    assert_eq!(
        tick(&mut s, &mut worker, [21; 3]).unwrap(),
        Some(FusedModelExchangeOutcomeV04::Accepted)
    );
    let view: ModelView = serde_json::from_slice(&worker.requests[0]).unwrap();
    assert!(view.suggested_templates.is_empty());
    assert_eq!(tick(&mut s, &mut worker, [40; 3]).unwrap(), None);
    drop(s);
    let mut s = task_store(&path, [0x81; 32], anchor);
    assert_eq!(tick(&mut s, &mut worker, [41; 3]).unwrap(), None);
    assert_eq!(worker.requests.len(), 1);
    assert!(s.compiled_fused_plan_v04(task(), 1, now(41)).is_ok());
}

#[test]
fn fused_schedule_rejects_manual_bypass_wrong_recipient_stale_revision_and_revocation() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(STATE_FILE_NAME);
    let mut s = task_store(
        &path,
        [0x81; 32],
        TestRollbackProtectedStateAnchorV2::default(),
    );
    install_scheduled(&mut s);
    let head = s.current_head;
    assert!(s
        .update_fused_planning_v04(task(), 1, send(), now(11))
        .is_err());
    assert!(s
        .update_fused_planning_v04(task(), 1, U::FreezeEnvelope { round: 1 }, now(20))
        .is_err());
    assert!(s
        .update_fused_planning_v04(
            task(),
            0,
            U::ClaimScheduledDelivery {
                recipient: [20; 32]
            },
            now(11)
        )
        .is_err());
    let mut worker = Worker {
        reader: 21,
        ..Default::default()
    };
    assert!(tick(&mut s, &mut worker, [11; 3]).is_err());
    assert_eq!(head, s.current_head);
    worker.reader = 20;
    assert!(exchange(
        &mut s,
        &mut worker,
        &rules(20, false),
        Role::Advisor,
        [11; 3]
    )
    .is_err());
    s.revoke_task_authorization(task()).unwrap();
    assert!(tick(&mut s, &mut worker, [11; 3]).is_err());
    assert!(worker.requests.is_empty());
}

#[test]
fn fused_schedule_slot_deadline_rejects_late_reply_without_early_retry() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(STATE_FILE_NAME);
    let mut s = task_store(
        &path,
        [0x81; 32],
        TestRollbackProtectedStateAnchorV2::default(),
    );
    install_scheduled(&mut s);
    let mut worker = Worker {
        reader: 20,
        ..Default::default()
    };
    assert_eq!(
        tick(&mut s, &mut worker, [11, 11, 14]).unwrap(),
        Some(FusedModelExchangeOutcomeV04::RejectedReply)
    );
    assert_eq!(worker.deadlines, vec![14]);
    assert_eq!(tick(&mut s, &mut worker, [14; 3]).unwrap(), None);
    worker.reader = 21;
    tick(&mut s, &mut worker, [21; 3]).unwrap();
    let view: ModelView = serde_json::from_slice(&worker.requests[1]).unwrap();
    assert!(view.suggested_templates.is_empty());
}

#[test]
fn fused_schedule_commit_failures_never_send_uncertain_claims_survive_reopen() {
    for mode in 0..3 {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(STATE_FILE_NAME);
        let anchor = TestRollbackProtectedStateAnchorV2::default();
        let mut s = task_store(&path, [0x81; 32], anchor.clone());
        install_scheduled(&mut s);
        if mode == 0 {
            s.set_before_next_commit_hook_for_test(|| Err(G4Error::DurableStateIo));
        } else {
            s.rollback_anchor = Box::new(super::super::super::continuation_tests::FailAnchor {
                inner: anchor.clone(),
                after: mode == 2,
            });
        }
        let mut worker = Worker {
            reader: 20,
            ..Default::default()
        };
        assert!(tick(&mut s, &mut worker, [11; 3]).is_err());
        assert!(worker.requests.is_empty());
        drop(s);
        let mut s = task_store(&path, [0x81; 32], anchor);
        let r = tick(&mut s, &mut worker, [11; 3]).unwrap();
        assert_eq!(r.is_some(), mode == 0);
        assert_eq!(worker.requests.len(), usize::from(mode == 0));
        tick(&mut s, &mut worker, [16; 3]).unwrap();
        assert_eq!(worker.requests.len(), 1 + usize::from(mode == 0));
    }
}

#[test]
fn fused_schedule_restore_rejects_schema_downgrade_cursor_or_counter_forgery() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(STATE_FILE_NAME);
    let mut s = task_store(
        &path,
        [0x81; 32],
        TestRollbackProtectedStateAnchorV2::default(),
    );
    install_scheduled(&mut s);
    let mut worker = Worker {
        reader: 20,
        ..Default::default()
    };
    tick(&mut s, &mut worker, [11; 3]).unwrap();
    for schema in [11, 12] {
        let mut corrupt = s.snapshot.clone();
        corrupt.payload_schema = schema;
        assert!(validate_snapshot(&corrupt).is_err());
    }
    for (field, value) in [
        ("schedule_cursor", serde_json::json!(0)),
        ("schedule_cursor", serde_json::json!(5)),
        ("scheduled_reservations", serde_json::json!([])),
        ("scheduled_reservations", serde_json::json!([1, 1])),
        ("scheduled_reservations", serde_json::json!([2])),
    ] {
        let mut corrupt = s.snapshot.clone();
        let mut table = serde_json::to_value(&corrupt.continuations.planning).unwrap();
        table["records"][0][field] = value;
        corrupt.continuations.planning = serde_json::from_value(table).unwrap();
        assert!(validate_snapshot(&corrupt).is_err(), "{field}");
    }
}
