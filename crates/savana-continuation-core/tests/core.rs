use savana_continuation_core::finite::*;
use savana_continuation_core::ledger::*;
use savana_continuation_core::observation::*;
use savana_continuation_core::quotient::*;
use savana_continuation_core::release::*;
use savana_continuation_core::Error;
use std::collections::BTreeSet;

fn definition(outputs: &[&str]) -> Definition {
    Definition {
        context: Context {
            root: [1; 32],
            semantics: [2; 32],
            observer_scope: [3; 32],
            renderer: [4; 32],
        },
        commands: vec![10, 20],
        initial: (0..outputs.len().min(2))
            .map(|i| InitialState {
                state: i as u32,
                baseline: 0,
            })
            .collect(),
        states: outputs
            .iter()
            .enumerate()
            .map(|(i, text)| State {
                color: 0,
                public: vec![
                    PublicStep {
                        next: i as u32,
                        output: text.as_bytes().to_vec(),
                    },
                    PublicStep {
                        next: i as u32,
                        output: b"fixed-catalog".to_vec(),
                    },
                ],
                private: vec![],
            })
            .collect(),
    }
}

fn safe_certificate(model: &Model) -> Certificate {
    match check_strict(model, Limits::default()) {
        Check::Safe(c) => c,
        result => panic!("expected safe, got {result:?}"),
    }
}

#[test]
fn totality_and_nonempty_initial_worlds_are_required() {
    let mut d = definition(&["same", "same"]);
    d.states[1].public.pop();
    assert_eq!(Model::new(d).unwrap_err(), Error::Invalid);
    let mut d = definition(&["same"]);
    d.initial.clear();
    assert_eq!(Model::new(d).unwrap_err(), Error::Invalid);
}

#[test]
fn reject_invalid_successors_and_duplicate_commands() {
    let mut d = definition(&["same"]);
    d.states[0].public[0].next = 9;
    assert_eq!(Model::new(d).unwrap_err(), Error::Invalid);
    let mut d = definition(&["same"]);
    d.commands[1] = 10;
    assert_eq!(Model::new(d).unwrap_err(), Error::Invalid);
}

#[test]
fn raw_subject_or_error_difference_is_detected() {
    for outputs in [
        ["subject-a", "subject-b"],
        ["accepted", "error"],
        ["", "accepted"],
    ] {
        let model = Model::new(definition(&outputs)).unwrap();
        let Check::Unsafe(c) = check_strict(&model, Limits::default()) else {
            panic!("missed leak")
        };
        assert!(replay_counterexample(&model, &c));
        assert_ne!(c.left_output, c.right_output);
    }
}

#[test]
fn actual_private_answers_are_independent_not_public_inputs() {
    let mut d = definition(&["handled-locally", "handled-locally", "yes", "no"]);
    d.states[0].private = vec![PrivateStep { event: 1, next: 2 }];
    d.states[1].private = vec![PrivateStep { event: 1, next: 3 }];
    let model = Model::new(d).unwrap();
    let Check::Unsafe(c) = check_strict(&model, Limits::default()) else {
        panic!("answer leak")
    };
    assert!(!c.prefix.is_empty());
    assert!(replay_counterexample(&model, &c));
}

#[test]
fn private_migration_catalog_is_checked() {
    let mut d = definition(&["fixed", "fixed", "fixed"]);
    d.states[1].private.push(PrivateStep { event: 3, next: 2 });
    d.states[2].public[1].output = b"new-version-tools".to_vec();
    let model = Model::new(d).unwrap();
    assert!(matches!(
        check_strict(&model, Limits::default()),
        Check::Unsafe(_)
    ));
}

#[test]
fn private_recovery_and_rejection_edges_are_not_skipped() {
    let mut d = definition(&["fixed", "fixed", "recovery-error"]);
    d.states[1].private.push(PrivateStep { event: 50, next: 2 });
    let model = Model::new(d).unwrap();
    assert!(matches!(
        check_strict(&model, Limits::default()),
        Check::Unsafe(_)
    ));
}

#[test]
fn all_nondeterministic_private_successors_are_checked() {
    let mut d = definition(&["fixed", "fixed", "fixed", "leak"]);
    d.states[0].private = vec![
        PrivateStep { event: 7, next: 2 },
        PrivateStep { event: 7, next: 3 },
    ];
    let model = Model::new(d).unwrap();
    assert!(matches!(
        check_strict(&model, Limits::default()),
        Check::Unsafe(_)
    ));
}

#[test]
fn private_business_states_can_differ_under_equal_transcripts() {
    let mut d = definition(&["handled-locally", "handled-locally", "handled-locally"]);
    d.states[0].color = 12; // Private result predicate differs, but no egress.
    d.states[1].color = 99;
    d.states[0].private = vec![PrivateStep { event: 1, next: 2 }];
    let model = Model::new(d).unwrap();
    let c = safe_certificate(&model);
    assert!(c.pairs.contains(&(2, 1)));
    verify_certificate(&model, &c, Limits::default()).unwrap();
}

#[test]
fn certificate_must_include_initial_and_private_closure() {
    let mut d = definition(&["fixed", "fixed", "fixed"]);
    d.states[0].private.push(PrivateStep { event: 1, next: 2 });
    let model = Model::new(d).unwrap();
    let original = safe_certificate(&model);
    for removed in [(0, 1), (2, 1)] {
        let mut c = original.clone();
        c.pairs.retain(|p| *p != removed);
        assert_eq!(
            verify_certificate(&model, &c, Limits::default()),
            Err(Error::Certificate)
        );
    }
}

#[test]
fn certificate_binding_covers_root_scope_renderer_and_semantics() {
    let original = definition(&["fixed", "fixed"]);
    let c = safe_certificate(&Model::new(original.clone()).unwrap());
    for i in 0..4 {
        let mut d = original.clone();
        match i {
            0 => d.context.root = [8; 32],
            1 => d.context.observer_scope = [8; 32],
            2 => d.context.renderer = [8; 32],
            _ => d.context.semantics = [8; 32],
        }
        assert_eq!(
            verify_certificate(&Model::new(d).unwrap(), &c, Limits::default()),
            Err(Error::Binding)
        );
    }
}

#[test]
fn corrupt_certificate_never_panics_or_passes() {
    let model = Model::new(definition(&["fixed", "fixed"])).unwrap();
    let good = safe_certificate(&model);
    for pairs in [
        vec![],
        vec![(u32::MAX, 0)],
        vec![(0, 0), (0, 0)],
        vec![(1, 1), (0, 0)],
    ] {
        let c = Certificate {
            binding: good.binding,
            pairs,
        };
        assert!(verify_certificate(&model, &c, Limits::default()).is_err());
    }
}

#[test]
fn resource_exhaustion_is_unknown_not_acceptance() {
    let model = Model::new(definition(&["fixed", "fixed"])).unwrap();
    assert_eq!(
        check_strict(
            &model,
            Limits {
                pairs: 1,
                transitions: 50
            }
        ),
        Check::Unknown
    );
    assert_eq!(
        check_strict(
            &model,
            Limits {
                pairs: 10,
                transitions: 1
            }
        ),
        Check::Unknown
    );
}

fn policy(model: &Model, withheld: bool) -> ReleasePolicy {
    let alphabet: BTreeSet<_> = model
        .states()
        .iter()
        .flat_map(|s| s.public.iter().map(|p| p.output.clone()))
        .collect();
    ReleasePolicy {
        model_binding: model.binding(),
        rewrites: alphabet
            .into_iter()
            .map(|from| {
                let to = if withheld && from != b"fixed-catalog" {
                    b"handled-locally".to_vec()
                } else {
                    from.clone()
                };
                Rewrite { from, to }
            })
            .collect(),
    }
}

#[test]
fn release_search_rechecks_concrete_examples_and_keeps_safe_candidate() {
    let model = Model::new(definition(&["yes", "no"])).unwrap();
    let candidates = vec![policy(&model, false), policy(&model, true)];
    let Synthesis::Safe {
        index,
        certificate,
        full_checks,
        counterexamples,
    } = synthesize_release(&model, &candidates, Limits::default()).unwrap()
    else {
        panic!("no policy")
    };
    assert_eq!((index, full_checks, counterexamples.len()), (1, 2, 1));
    let candidate = candidates[1].apply(&model).unwrap();
    assert!(!replay_counterexample(&candidate, &counterexamples[0]));
    verify_certificate(&candidate, &certificate, Limits::default()).unwrap();
    assert_eq!(
        verify_certificate(&model, &certificate, Limits::default()),
        Err(Error::Binding)
    );
}

#[test]
fn no_solution_and_unknown_are_distinct() {
    let model = Model::new(definition(&["yes", "no"])).unwrap();
    assert_eq!(
        synthesize_release(&model, &[policy(&model, false)], Limits::default()).unwrap(),
        Synthesis::NoSolutionInLibrary
    );
    assert_eq!(
        synthesize_release(
            &model,
            &[policy(&model, true)],
            Limits {
                pairs: 1,
                transitions: 1
            }
        )
        .unwrap(),
        Synthesis::Unknown
    );
}

#[test]
fn candidate_cannot_omit_renderer_cases() {
    let model = Model::new(definition(&["yes", "no"])).unwrap();
    let mut candidate = policy(&model, true);
    candidate.rewrites.pop();
    assert_eq!(candidate.apply(&model).unwrap_err(), Error::Invalid);
}

#[test]
fn renderer_expansion_is_bounded_before_building_the_candidate() {
    let strings = vec!["x"; MAX_STATES];
    let model = Model::new(definition(&strings)).unwrap();
    let mut candidate = policy(&model, false);
    for rewrite in &mut candidate.rewrites {
        rewrite.to = vec![b'x'; MAX_BYTES];
    }
    assert_eq!(candidate.apply(&model).unwrap_err(), Error::Limit);
    assert_eq!(
        synthesize_release(&model, &[candidate], Limits::default()).unwrap(),
        Synthesis::Unknown
    );
}

#[test]
fn quotient_matches_behavior_not_only_invariants() {
    let model = Model::new(definition(&["Denied", "Granted"])).unwrap();
    let q = build_quotient(&model, Limits::default()).unwrap();
    assert_ne!(q.classes[0], q.classes[1]);
    let forged = Quotient {
        binding: model.binding(),
        classes: vec![0, 0],
    };
    assert_eq!(
        verify_quotient(&model, &forged, Limits::default()),
        Err(Error::Certificate)
    );
}

#[test]
fn quotient_refines_future_behavior_until_stable() {
    let mut d = definition(&["same", "same", "later-secret", "same"]);
    d.states[0].public[0].next = 2;
    d.states[3].public[0].next = 1;
    let model = Model::new(d).unwrap();
    let q = build_quotient(&model, Limits::default()).unwrap();
    assert_ne!(q.classes[0], q.classes[1]);
    assert_eq!(q.classes[1], q.classes[3]);
    verify_quotient(&model, &q, Limits::default()).unwrap();
}

#[test]
fn quotient_preserves_goals_and_private_event_labels() {
    let mut d = definition(&["same", "same", "same"]);
    d.states[0].private.push(PrivateStep { event: 1, next: 2 });
    d.states[1].private.push(PrivateStep { event: 2, next: 2 });
    d.states[2].color = 1;
    let model = Model::new(d).unwrap();
    let q = build_quotient(&model, Limits::default()).unwrap();
    assert_eq!(q.classes.iter().collect::<BTreeSet<_>>().len(), 3);
}

// Independent greatest-fixed-point elimination oracle, not the BFS algorithm.
fn reference_safe(model: &Model) -> bool {
    let n = model.states().len() as u32;
    let mut q: BTreeSet<_> = (0..n).flat_map(|l| (0..n).map(move |r| (l, r))).collect();
    loop {
        let old = q.clone();
        q.retain(|&(l, r)| {
            let a = &model.states()[l as usize];
            let b = &model.states()[r as usize];
            a.public
                .iter()
                .zip(&b.public)
                .all(|(x, y)| x.output == y.output && old.contains(&(x.next, y.next)))
                && a.private.iter().all(|x| old.contains(&(x.next, r)))
                && b.private.iter().all(|y| old.contains(&(l, y.next)))
        });
        if old == q {
            break;
        }
    }
    model.definition().initial.iter().all(|l| {
        model
            .definition()
            .initial
            .iter()
            .filter(|r| r.baseline == l.baseline)
            .all(|r| q.contains(&(l.state, r.state)))
    })
}

#[test]
fn bounded_exhaustive_checker_and_independent_oracle_agree() {
    let mut checked = 0;
    for outputs in 0..8 {
        for nexts in 0..27 {
            for private in 0..4 {
                let mut d = definition(&["0", "0", "0"]);
                let mut targets = nexts;
                for (i, s) in d.states.iter_mut().enumerate() {
                    s.public[0].output = vec![b'0' + ((outputs >> i) & 1) as u8];
                    s.public[0].next = targets % 3;
                    targets /= 3;
                    if i < 2 && private & (1 << i) != 0 {
                        s.private.push(PrivateStep { event: 1, next: 2 });
                    }
                }
                let model = Model::new(d).unwrap();
                let result = check_strict(&model, Limits::default());
                assert_eq!(matches!(result, Check::Safe(_)), reference_safe(&model));
                if let Check::Unsafe(c) = result {
                    assert!(replay_counterexample(&model, &c));
                }
                let q = build_quotient(&model, Limits::default()).unwrap();
                verify_quotient(&model, &q, Limits::default()).unwrap();
                checked += 1;
            }
        }
    }
    assert_eq!(checked, 864);
}

fn ledger() -> Ledger {
    Ledger::new(
        TaskKey {
            installation_lineage: [1; 32],
            task_lineage: [2; 32],
        },
        [3; 32],
        vec![
            DomainLimit {
                domain: 1,
                total: 2,
                per_resource: 1,
            },
            DomainLimit {
                domain: 2,
                total: 10,
                per_resource: 10,
            },
        ],
        10,
    )
    .unwrap()
}

fn reservation(id: u8, object: u8) -> Reservation {
    Reservation {
        execution: [id; 32],
        request_binding: [8; 32],
        resource: ResourceKey {
            source: [4; 32],
            namespace: [5; 32],
            object: [object; 32],
            incarnation: 0,
        },
        charges: vec![
            Charge {
                domain: 1,
                amount: 1,
            },
            Charge {
                domain: 2,
                amount: 4,
            },
        ],
    }
}

fn restore_ledger(bytes: &[u8]) -> Result<Ledger, Error> {
    Ledger::restore(
        bytes,
        TaskKey {
            installation_lineage: [1; 32],
            task_lineage: [2; 32],
        },
        [3; 32],
        &[
            DomainLimit {
                domain: 1,
                total: 2,
                per_resource: 1,
            },
            DomainLimit {
                domain: 2,
                total: 10,
                per_resource: 10,
            },
        ],
        10,
    )
}

#[test]
fn ledger_restore_reconstructs_all_charges_and_original_replay() {
    let mut l = ledger();
    // Arrival order differs from the canonical snapshot order.
    for r in [reservation(9, 6), reservation(1, 7)] {
        let u = l.prepare(r).unwrap();
        l.apply(u).unwrap();
    }
    let bytes = l.snapshot().unwrap();
    let mut restored = restore_ledger(&bytes).unwrap();
    assert_eq!(restored.snapshot().unwrap(), bytes);
    assert_eq!(
        (restored.usage(1), restored.usage(2), restored.revision()),
        (Some(2), Some(8), 2)
    );
    let replay = restored.prepare(reservation(9, 6)).unwrap();
    assert_eq!(restored.apply(replay).unwrap(), Applied::OriginalReplay);
    assert_eq!(
        restored.prepare(reservation(10, 6)).unwrap_err(),
        Error::Limit
    );
}

#[test]
fn ledger_restore_rejects_config_substitution_and_noncanonical_state() {
    let bytes = ledger().snapshot().unwrap();
    for field in ["schema", "task", "root", "limits", "max_executions"] {
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        match field {
            "schema" => value[field] = 2.into(),
            "task" => value[field]["task_lineage"][0] = 9.into(),
            "root" => value[field][0] = 9.into(),
            "limits" => value[field][0]["total"] = 9.into(),
            _ => value[field] = 11.into(),
        }
        assert!(restore_ledger(&serde_json::to_vec(&value).unwrap()).is_err());
    }
    let mut whitespace = bytes.clone();
    whitespace.push(b' ');
    assert!(restore_ledger(&whitespace).is_err());
    assert_eq!(
        restore_ledger(&vec![0; 4 * 1024 * 1024 + 1]).unwrap_err(),
        Error::Limit
    );
}

#[test]
fn ledger_restore_rejects_duplicate_and_overbudget_history() {
    let mut l = ledger();
    let u = l.prepare(reservation(1, 6)).unwrap();
    l.apply(u).unwrap();
    let bytes = l.snapshot().unwrap();
    // Preserve struct-field ordering so rejection exercises history validation,
    // not merely canonical JSON checking.
    let r = serde_json::to_string(&reservation(1, 6)).unwrap();
    let s = String::from_utf8(bytes).unwrap();
    let duplicate = s.replace(&format!("[{r}]"), &format!("[{r},{r}]"));
    assert_ne!(duplicate, s);
    assert!(restore_ledger(duplicate.as_bytes()).is_err());
    let excessive = s.replace("\"amount\":4", "\"amount\":11");
    assert_ne!(excessive, s);
    assert_eq!(
        restore_ledger(excessive.as_bytes()).unwrap_err(),
        Error::Limit
    );
}

#[test]
fn multi_domain_failure_does_not_partially_debit() {
    let mut l = ledger();
    let mut request = reservation(1, 6);
    request.charges[1].amount = 11;
    assert_eq!(l.prepare(request).unwrap_err(), Error::Limit);
    assert_eq!(
        (l.usage(1), l.usage(2), l.revision()),
        (Some(0), Some(0), 0)
    );
    let update = l.prepare(reservation(1, 6)).unwrap();
    l.apply(update).unwrap();
    assert_eq!((l.usage(1), l.usage(2)), (Some(1), Some(4)));
}

#[test]
fn caller_cannot_omit_a_required_consumption_domain() {
    let l = ledger();
    let mut r = reservation(1, 6);
    r.charges.pop();
    assert_eq!(l.prepare(r).unwrap_err(), Error::Binding);
    assert_eq!(l.usage(1), Some(0));
}

#[test]
fn cloud_configuration_stays_disabled_and_has_no_endpoint() {
    let config: serde_json::Value = serde_json::from_str(include_str!(
        "../../../deploy/config/advisor-v04.placeholder.json"
    ))
    .unwrap();
    assert_eq!(config["enabled"], false);
    assert_eq!(config["raw_private_data_allowed"], false);
    assert_eq!(config["business_credentials_allowed"], false);
    assert!(config["endpoint"].is_null());
    assert!(config["project_id"].is_null());
    assert_eq!(config["model"], "deepseek-ai/DeepSeek-V4.1-Flash");
}

#[test]
fn original_replay_does_not_recharge_but_changed_binding_is_rejected() {
    let mut l = ledger();
    let r = reservation(1, 6);
    let update = l.prepare(r.clone()).unwrap();
    l.apply(update).unwrap();
    let update = l.prepare(r.clone()).unwrap();
    assert_eq!(l.apply(update).unwrap(), Applied::OriginalReplay);
    let mut changed = r;
    changed.request_binding = [9; 32];
    assert_eq!(l.prepare(changed).unwrap_err(), Error::History);
    assert_eq!(l.usage(1), Some(1));
}

#[test]
fn fresh_execution_identity_cannot_renew_resource_consumption() {
    let mut l = ledger();
    let u = l.prepare(reservation(1, 6)).unwrap();
    l.apply(u).unwrap();
    assert_eq!(l.prepare(reservation(2, 6)).unwrap_err(), Error::Limit);
    let u = l.prepare(reservation(2, 7)).unwrap();
    l.apply(u).unwrap();
    assert_eq!(l.prepare(reservation(3, 8)).unwrap_err(), Error::Limit);
}

#[test]
fn stale_preparation_and_cross_task_application_are_rejected() {
    let mut l = ledger();
    let a = l.prepare(reservation(1, 6)).unwrap();
    let b = l.prepare(reservation(2, 7)).unwrap();
    l.apply(a).unwrap();
    assert_eq!(l.apply(b), Err(Error::Binding));
    let candidate = l.prepare(reservation(2, 7)).unwrap();
    assert_eq!(ledger().apply(candidate), Err(Error::Binding));
}

#[test]
fn checked_arithmetic_prevents_overflow_and_zero_or_duplicate_charges() {
    let l = ledger();
    let mut r = reservation(1, 6);
    r.charges[1].amount = u64::MAX;
    assert_eq!(l.prepare(r).unwrap_err(), Error::Limit);
    let mut r = reservation(1, 6);
    r.charges[1].amount = 0;
    assert_eq!(l.prepare(r).unwrap_err(), Error::Invalid);
    let mut r = reservation(1, 6);
    r.charges[1].domain = 1;
    assert_eq!(l.prepare(r).unwrap_err(), Error::Invalid);
}

fn observations() -> (Scope, Vec<Slot>, Observations) {
    let scope = Scope {
        root: [1; 32],
        policy: [2; 32],
        observer_scope: [3; 32],
        renderer: [4; 32],
    };
    let slots = vec![
        Slot {
            id: 1,
            logical_round: 1,
            projection: Projection::PublicConstant(b"accepted".to_vec()),
        },
        Slot {
            id: 2,
            logical_round: 3,
            projection: Projection::DeclaredBoolean,
        },
    ];
    let state = Observations::new(scope.clone(), slots.clone()).unwrap();
    (scope, slots, state)
}

#[test]
fn observe_never_pins_or_refreshes_and_freeze_requires_pin() {
    let (_, _, mut o) = observations();
    assert_eq!(o.frozen_bytes_for_release_check(1), None);
    assert_eq!(o.charged_slots(), 0);
    assert_eq!(o.freeze(1), Err(Error::History));
    assert_eq!(o.pin(1, 0, PinnedInput::Public), Err(Error::Binding));
    o.pin(1, 1, PinnedInput::Public).unwrap();
    o.freeze(1).unwrap();
    for _ in 0..10 {
        assert_eq!(
            o.frozen_bytes_for_release_check(1),
            Some(b"accepted".as_slice())
        );
    }
    assert_eq!(o.charged_slots(), 1);
}

#[test]
fn repinning_old_slot_cannot_change_cut_or_value() {
    let (_, _, mut o) = observations();
    let input = PinnedInput::Boolean {
        cut: [8; 32],
        value: false,
    };
    o.pin(2, 3, input.clone()).unwrap();
    o.pin(2, 3, input).unwrap();
    assert_eq!(
        o.pin(
            2,
            3,
            PinnedInput::Boolean {
                cut: [9; 32],
                value: true
            }
        ),
        Err(Error::History)
    );
    o.freeze(2).unwrap();
    assert_eq!(
        o.frozen_bytes_for_release_check(2),
        Some(b"false".as_slice())
    );
    assert_eq!(o.charged_slots(), 1);
}

#[test]
fn snapshot_reopen_preserves_pin_and_freeze_without_current_facts() {
    let (scope, slots, mut o) = observations();
    o.pin(
        2,
        3,
        PinnedInput::Boolean {
            cut: [8; 32],
            value: true,
        },
    )
    .unwrap();
    let bytes = o.snapshot().unwrap();
    let commitment = o.state_commitment();
    let mut recovered = Observations::restore(&bytes, &scope, &slots, commitment).unwrap();
    recovered.freeze(2).unwrap();
    let bytes = recovered.snapshot().unwrap();
    let recovered =
        Observations::restore(&bytes, &scope, &slots, recovered.state_commitment()).unwrap();
    assert_eq!(
        recovered.frozen_bytes_for_release_check(2),
        Some(b"true".as_slice())
    );
    assert_eq!(recovered.charged_slots(), 1);
}

#[test]
fn snapshot_requires_external_commitment_scope_and_exact_encoding() {
    let (scope, slots, o) = observations();
    let bytes = o.snapshot().unwrap();
    assert!(Observations::restore(&bytes, &scope, &slots, [0; 32]).is_err());
    let mut wrong = scope.clone();
    wrong.observer_scope = [7; 32];
    assert!(Observations::restore(&bytes, &wrong, &slots, o.state_commitment()).is_err());
    let mut extra = bytes.clone();
    extra.push(b' ');
    assert!(Observations::restore(&extra, &scope, &slots, o.state_commitment()).is_err());
    let mut changed = slots;
    changed[0].logical_round = 99;
    assert!(Observations::restore(&bytes, &scope, &changed, o.state_commitment()).is_err());
}
