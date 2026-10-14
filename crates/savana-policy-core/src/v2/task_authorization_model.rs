//! Bounded differential trace exploration, using the real encrypted state owner.
//! This is deliberately a test-only child of the existing durable fixture: no
//! production authority constructor is made public merely to support the model.
//! Bounds: two clauses, two authorized alternatives each, two prepare attempts;
//! one invalid tuple probe, five first-outcome states, three recovery positions.
use super::*;
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug)]
enum ResultKind {
    Pending,
    Started,
    Unknown,
    Success,
    NoEffect,
}

/// Independent resource-accounting oracle. It has no Rust policy digest,
/// dispatch-core, snapshot, or production matching code. Clause 2 depends on a
/// proven successful clause 1; unknown/started/pending retain their budget.
#[derive(Default)]
struct Oracle {
    attempts: [u64; 2],
    used: [u64; 2],
    succeeded: [bool; 2],
}
impl Oracle {
    fn permits(&self, clause: usize, valid_tuple: bool, stale: bool, reused: bool) -> bool {
        valid_tuple
            && !stale
            && !reused
            && self.attempts[clause] < 2
            && self.used[clause] < 1
            && (clause == 0 || self.succeeded[0])
    }
    fn reserve(&mut self, clause: usize) {
        self.attempts[clause] += 1;
        self.used[clause] += 1;
    }
    fn outcome(&mut self, clause: usize, result: ResultKind) {
        match result {
            ResultKind::NoEffect => self.used[clause] -= 1,
            ResultKind::Success => self.succeeded[clause] = true,
            _ => {}
        }
    }
    fn check(&self, f: &Fixture) {
        let state = f.store.task_authorization_state(task()).unwrap();
        for i in 0..2 {
            assert_eq!(
                state.clause_consumption(i as u64 + 1),
                Some((self.attempts[i], self.used[i]))
            );
        }
    }
    fn observation(&self) -> ([u64; 2], [u64; 2], [bool; 2]) {
        (self.attempts, self.used, self.succeeded)
    }
}

fn contracts() -> Vec<TaskAuthorizationClauseV2> {
    let first = release_action(release(20).binding());
    let second = ActionAlternativeV2::new(
        first.tool_descriptor_digest(),
        first.codec_profile(),
        first.effect(),
        first.resource_digest(),
        first.destination_digest(),
        d(0xda),
        first.magnitude_unit(),
    )
    .unwrap();
    (1..=2)
        .map(|id| {
            TaskAuthorizationClauseV2::new(
                id,
                vec![first.clone(), second.clone()],
                1,
                1,
                2,
                if id == 2 { vec![1] } else { vec![] },
                true,
            )
            .unwrap()
        })
        .collect()
}

/// The proposer remains untrusted. Only expected-key verified action approval
/// can supply this fixture's endorsements; a third tuple is a negative probe.
fn selected_and_approved(
    f: &Fixture,
    clause: usize,
    candidate: usize,
    approval_nonce: u8,
) -> Option<TaskDispatchAuthorizationV2> {
    use savana_kernel_protocol::v2::*;
    let state = f.store.task_authorization_state(task()).unwrap();
    let root = state.authorization();
    let c = &root.material().clauses()[clause];
    let action = if candidate < 2 {
        c.alternatives()[candidate].clone()
    } else {
        let first = &c.alternatives()[0];
        ActionAlternativeV2::new(
            first.tool_descriptor_digest(),
            first.codec_profile(),
            first.effect(),
            first.resource_digest(),
            first.destination_digest(),
            d(0xdb),
            first.magnitude_unit(),
        )
        .unwrap()
    };
    let content = ActionContentV2::new(
        root.material().authorization_id(),
        root.material().revision(),
        c.clause_id(),
        (candidate % 2) as u64,
        action,
        1,
        d(0x92),
        release(20).binding().evidence_digest(),
        d(9),
        root.candidate_domain(c.clause_id(), UnixMillisV2::new(10))
            .unwrap()
            .digest(),
        state.digest(),
        state.revision(),
    )
    .unwrap();
    let current = TaskMatchContextV2 {
        current_authorization: Some(root),
        pre_state_digest: state.digest(),
        pre_state_revision: state.revision(),
        deployment_generation: 7,
        now: UnixMillisV2::new(10),
    };
    let matched = root.match_action(&content, &current).ok()?;
    let selections = ControlSelectionV2::from_match(&matched, d(0xdd)).unwrap();
    for selection in &selections {
        assert_eq!(
            selection.integrity(),
            crate::v2::IntegrityV2::ExternalUntrusted
        );
        assert_eq!(selection.allowed_effects(), crate::v2::EffectSetV2::READ);
    }
    let context = TaskActionApprovalContextV2 {
        content_digest: matched.content_digest(),
        authorization_id: root.material().authorization_id(),
        authorization_revision: root.material().revision(),
        principal: root.material().principal(),
        task: task(),
        installation_digest: d(2),
        manifest_digest: d(3),
        deployment_generation: 7,
        challenge_nonce: d(approval_nonce),
        settlement_nonce: d(approval_nonce),
        authentication_context_digest: d(0xde),
        display_digest: d(0xdf),
    };
    let key = SigningKey::from_bytes(&[0xe5; 32]);
    let signed = sign_task_action_approval_v2(
        TaskActionApprovalV2::new(
            context.clone(),
            TaskActionApprovalDecisionV2::Approve,
            UnixMillisV2::new(1),
            UnixMillisV2::new(1000),
        )
        .unwrap(),
        &key,
    )
    .unwrap();
    let proof = verify_task_action_approval_v2(
        &signed,
        &key.verifying_key(),
        &context,
        UnixMillisV2::new(10),
    )
    .unwrap();
    let endorsements = checked_control_endorsements_v2(
        &matched,
        &selections,
        ControlEvidenceV2::ActionApproval {
            approval: &proof,
            expected_context: &context,
        },
        &current,
    )
    .unwrap();
    Some(TaskDispatchAuthorizationV2::new(matched, endorsements))
}

fn reopen(f: Fixture) -> Fixture {
    let before = f.store.task_authorization_state(task()).unwrap().digest();
    let head = f.anchor.current_head().unwrap();
    let Fixture {
        directory,
        anchor,
        store,
    } = f;
    drop(store);
    let store = task_store(
        &directory.path().join(STATE_FILE_NAME),
        [0x81; 32],
        anchor.clone(),
    );
    assert_eq!(
        store.task_authorization_state(task()).unwrap().digest(),
        before
    );
    assert_eq!(anchor.current_head().unwrap(), head);
    Fixture {
        directory,
        anchor,
        store,
    }
}

#[test]
fn bounded_task_traces_match_independent_accounting_oracle() {
    let mut traces = 0usize;
    let mut admitted = 0usize;
    let mut rejected = 0usize;
    let mut observations = BTreeSet::new();
    for first_clause in 0..2 {
        for first_candidate in 0..2 {
            for first_outcome in [
                ResultKind::Pending,
                ResultKind::Started,
                ResultKind::Unknown,
                ResultKind::Success,
                ResultKind::NoEffect,
            ] {
                for recovery in 0..3 {
                    for second_clause in 0..2 {
                        for second_candidate in 0..3 {
                            for stale in [false, true] {
                                for reused_nonce in [false, true] {
                                    traces += 1;
                                    let mut f = Fixture::new(contracts());
                                    let mut oracle = Oracle::default();
                                    let first = selected_and_approved(
                                        &f,
                                        first_clause,
                                        first_candidate,
                                        0xe1,
                                    )
                                    .unwrap();
                                    let old_second = selected_and_approved(
                                        &f,
                                        second_clause,
                                        second_candidate,
                                        if reused_nonce { 0xe1 } else { 0xe2 },
                                    );
                                    if recovery == 1 {
                                        f = reopen(f);
                                    }
                                    let expected = oracle.permits(first_clause, true, false, false);
                                    let first_prepared = prepare(&mut f.store, &first, 20);
                                    assert_eq!(
                                        first_prepared.is_ok(),
                                        expected,
                                        "first prepare trace {traces}"
                                    );
                                    if let Ok(p) = first_prepared {
                                        admitted += 1;
                                        oracle.reserve(first_clause);
                                        oracle.check(&f);
                                        match first_outcome {
                                            ResultKind::Pending => {}
                                            ResultKind::Started | ResultKind::Unknown => {
                                                f.store
                                                    .reconcile_signed_final_release_dispatch(
                                                        &receipt(
                                                            p,
                                                            if matches!(
                                                                first_outcome,
                                                                ResultKind::Started
                                                            ) {
                                                                1
                                                            } else {
                                                                4
                                                            },
                                                        ),
                                                        Ed25519KeyIdV2::new([0xc2; 32]),
                                                        SigningKey::from_bytes(&[0xc1; 32])
                                                            .verifying_key()
                                                            .to_bytes(),
                                                        UnixMillisV2::new(10),
                                                    )
                                                    .unwrap();
                                            }
                                            ResultKind::Success | ResultKind::NoEffect => {
                                                let proof = outcome(
                                                    &f.store,
                                                    p,
                                                    if matches!(first_outcome, ResultKind::Success)
                                                    {
                                                        2
                                                    } else {
                                                        3
                                                    },
                                                );
                                                f.store
                                                    .reconcile_task_outcome(proof.clone())
                                                    .unwrap();
                                                let after = f
                                                    .store
                                                    .task_authorization_state(task())
                                                    .unwrap()
                                                    .digest();
                                                f.store.reconcile_task_outcome(proof).unwrap();
                                                assert_eq!(
                                                    f.store
                                                        .task_authorization_state(task())
                                                        .unwrap()
                                                        .digest(),
                                                    after
                                                );
                                            }
                                        }
                                        oracle.outcome(first_clause, first_outcome);
                                    } else {
                                        rejected += 1;
                                    }
                                    oracle.check(&f);
                                    observations.insert(oracle.observation());
                                    if recovery == 2 {
                                        f = reopen(f);
                                    }
                                    let first_admitted = expected;
                                    let second = if stale {
                                        old_second
                                    } else {
                                        selected_and_approved(
                                            &f,
                                            second_clause,
                                            second_candidate,
                                            if reused_nonce { 0xe1 } else { 0xe2 },
                                        )
                                    };
                                    let expected = oracle.permits(
                                        second_clause,
                                        second_candidate < 2,
                                        stale && first_admitted,
                                        reused_nonce && first_admitted,
                                    );
                                    let before =
                                        f.store.task_authorization_state(task()).unwrap().digest();
                                    let actual =
                                        second.as_ref().map(|r| prepare(&mut f.store, r, 21));
                                    assert_eq!(actual.as_ref().is_some_and(|r| r.is_ok()), expected,
            "trace {traces}: first {first_clause}/{first_candidate}/{first_outcome:?}, second {second_clause}/{second_candidate}, stale={stale}, reuse={reused_nonce}, recovery={recovery}");
                                    if expected {
                                        admitted += 1;
                                        oracle.reserve(second_clause);
                                    } else {
                                        rejected += 1;
                                        assert_eq!(
                                            f.store
                                                .task_authorization_state(task())
                                                .unwrap()
                                                .digest(),
                                            before
                                        );
                                    }
                                    oracle.check(&f);
                                    observations.insert(oracle.observation());
                                    let f = reopen(f);
                                    oracle.check(&f);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    assert_eq!(traces, 1440);
    assert!(admitted > 0 && rejected > 0 && observations.len() > 4);
    eprintln!("bounded model: {traces} traces, {admitted} admitted / {rejected} refused probes, {} distinct accounting observations; two clauses/two authorized candidates/two prepare attempts", observations.len());
}
