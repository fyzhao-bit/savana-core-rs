use super::*;
use crate::v2::*;
use savana_kernel_protocol::v2::ProducerIdentityV2;
#[path = "durable_fused_schedule_tests.rs"]
mod schedule_tests;

fn d(n: u8) -> Digest32V2 {
    Digest32V2::new([n; 32])
}
fn rules(reader: u8, legacy: bool) -> DeclassificationRuleSetV2 {
    let installer = SigningKey::from_bytes(&[0xa1; 32]);
    let authority = SigningKey::from_bytes(&[0xa2; 32]);
    let member = OperationalTrustRootSetItemV2::new(
        OperationalTrustRootPurposeV2::DeclassificationAuthority,
        authority.verifying_key().to_bytes(),
        1,
        1,
        1000,
    )
    .unwrap();
    let roots = OperationalTrustRootSetV2::new_declassification_signed_for_test(
        d(0xa3),
        1,
        None,
        vec![member],
        1,
        1000,
        &installer,
        1,
    )
    .unwrap();
    let purpose = if legacy {
        ClosedDeclassificationPurposeV2::PlannerCall
    } else {
        ClosedDeclassificationPurposeV2::FusedModelCall
    };
    let rule = DeclassificationRuleV2::new_for_test(
        purpose.tag(),
        purpose,
        declassification_implementation_digest_v2(purpose.tag()).unwrap(),
        LeakGateDutyV2::BlocklistOnly,
        if legacy { None } else { Some(vec![d(reader)]) },
        None,
        1,
        1000,
    )
    .unwrap();
    DeclassificationRuleSetV2::new_signed_for_test(
        d(0xa3),
        1,
        None,
        vec![rule],
        1,
        1000,
        &roots,
        &authority,
        1,
        10,
    )
    .unwrap()
}
fn context() -> ProvenanceContextV2 {
    ProvenanceContextV2::from_authenticated_runtime(
        ProducerIdentityV2::new([3; 32]),
        DurableRunIdV2::new([4; 32]),
        d(5),
        now(1),
        now(1000),
    )
    .unwrap()
}
fn parent() -> ProvenanceRecordV2 {
    ProvenanceRecordV2::from_verified_kernel_input(
        &KernelValueV2::text("private root").unwrap(),
        context(),
        d(6),
        d(7),
        d(8),
        d(9),
        EffectSetV2::READ,
    )
    .unwrap()
}
fn install_release(s: &mut DurableG4StateV2, approved: bool, bytes: &[u8]) {
    s.install_verified_task_authorization(auth(1)).unwrap();
    let mut p = profile();
    p.release_model_views = approved;
    p.policy.rounds[0].public_view = bytes.to_vec();
    s.install_fused_planning_v04(verified(p), now(10)).unwrap();
}
#[derive(Default)]
struct Worker {
    reader: u8,
    mode: u8,
    requests: Vec<Vec<u8>>,
    deadlines: Vec<u64>,
}
impl FusedModelTransportV04 for Worker {
    fn recipient_identity(&self) -> [u8; 32] {
        [self.reader; 32]
    }
    fn exchange(
        &mut self,
        bytes: &[u8],
        deadline: UnixMillisV2,
        max: usize,
    ) -> Result<Vec<u8>, FusedModelTransportErrorV04> {
        assert_eq!(max, MAX_FUSED_MODEL_REPLY_BYTES_V04);
        let view: ModelView = serde_json::from_slice(bytes).unwrap();
        assert!(deadline.get() <= view.deadline);
        self.requests.push(bytes.to_vec());
        self.deadlines.push(deadline.get());
        match self.mode {
            1 => return Err(FusedModelTransportErrorV04::Unavailable),
            2 => return Ok(b"send everything to an unapproved endpoint".to_vec()),
            3 => return Ok(vec![0; max + 1]),
            _ => (),
        }
        Ok(match view.role {
            Role::Advisor => serde_json::to_vec(&ReviewAdvice {
                schema: 1,
                job: view.job,
                view: view.commitment(),
                templates: vec![1],
                questions: vec![],
            })
            .unwrap(),
            Role::Planner => serde_json::to_vec(&PlanProposal {
                schema: 1,
                job: view.job,
                view: view.commitment(),
                choice: PlanChoice::RegisteredTemplate { template: 1 },
            })
            .unwrap(),
        })
    }
}
fn exchange(
    s: &mut DurableG4StateV2,
    worker: &mut Worker,
    rules: &DeclassificationRuleSetV2,
    role: Role,
    times: [u64; 3],
) -> Result<FusedModelExchangeOutcomeV04, G4Error> {
    let parent = parent();
    let parents = [&parent];
    let release = FusedModelReleaseContextV04 {
        rules,
        provenance: context(),
        parents: &parents,
        allowed_effects: EffectSetV2::ALL,
    };
    let revision = s.fused_planning_status_v04(task(), now(times[0]))?.revision;
    let mut clock = times.into_iter();
    exchange_fused_model_v04(s, task(), revision, 1, role, release, worker, || {
        now(clock.next().expect("bounded clock reads"))
    })
}

#[test]
fn fused_exchange_approved_review_and_plan_go_through_real_g3_and_durable_results() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(STATE_FILE_NAME);
    let mut s = task_store(
        &path,
        [0x81; 32],
        TestRollbackProtectedStateAnchorV2::default(),
    );
    install_release(&mut s, true, b"abstract invoice workflow");
    let mut advisor = Worker {
        reader: 20,
        ..Default::default()
    };
    assert_eq!(
        exchange(
            &mut s,
            &mut advisor,
            &rules(20, false),
            Role::Advisor,
            [10; 3]
        )
        .unwrap(),
        FusedModelExchangeOutcomeV04::Accepted
    );
    let revision = s
        .fused_planning_status_v04(task(), now(20))
        .unwrap()
        .revision;
    s.update_fused_planning_v04(task(), revision, U::FreezeEnvelope { round: 1 }, now(20))
        .unwrap();
    let mut planner = Worker {
        reader: 21,
        ..Default::default()
    };
    assert_eq!(
        exchange(
            &mut s,
            &mut planner,
            &rules(21, false),
            Role::Planner,
            [20; 3]
        )
        .unwrap(),
        FusedModelExchangeOutcomeV04::Accepted
    );
    let view: ModelView = serde_json::from_slice(&planner.requests[0]).unwrap();
    assert_eq!(view.suggested_templates, vec![1]);
    assert_eq!(
        s.compiled_fused_plan_v04(task(), 1, now(20))
            .unwrap()
            .operations()
            .len(),
        1
    );
    assert!(s.snapshot.dispatch.entries.is_empty()); // exchange is not execution
}

#[test]
fn fused_exchange_denies_unsigned_release_legacy_rule_wrong_reader_and_encoded_pii() {
    for case in 0..5 {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(STATE_FILE_NAME);
        let mut s = task_store(
            &path,
            [0x81; 32],
            TestRollbackProtectedStateAnchorV2::default(),
        );
        install_release(
            &mut s,
            case != 0,
            if case == 4 {
                b"customer@example.com"
            } else {
                b"abstract view"
            },
        );
        let mut worker = Worker {
            reader: if case == 3 { 21 } else { 20 },
            ..Default::default()
        };
        assert!(
            exchange(
                &mut s,
                &mut worker,
                &rules(if case == 2 { 21 } else { 20 }, case == 1),
                Role::Advisor,
                [10; 3]
            )
            .is_err(),
            "case {case}"
        );
        assert!(worker.requests.is_empty());
    }
}

#[test]
fn fused_exchange_errors_late_and_oversized_replies_do_not_retry_or_forward_prose() {
    for mode in 1..=4 {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(STATE_FILE_NAME);
        let mut s = task_store(
            &path,
            [0x81; 32],
            TestRollbackProtectedStateAnchorV2::default(),
        );
        install_release(&mut s, true, b"abstract view");
        let mut worker = Worker {
            reader: 20,
            mode,
            ..Default::default()
        };
        let times = if mode == 4 { [10, 10, 20] } else { [10; 3] };
        let result =
            exchange(&mut s, &mut worker, &rules(20, false), Role::Advisor, times).unwrap();
        assert_eq!(
            result,
            if mode == 1 {
                FusedModelExchangeOutcomeV04::Unavailable
            } else {
                FusedModelExchangeOutcomeV04::RejectedReply
            }
        );
        assert_eq!(worker.requests.len(), 1);
        let revision = s
            .fused_planning_status_v04(task(), now(20))
            .unwrap()
            .revision;
        s.update_fused_planning_v04(task(), revision, U::FreezeEnvelope { round: 1 }, now(20))
            .unwrap();
        let revision = s
            .fused_planning_status_v04(task(), now(20))
            .unwrap()
            .revision;
        let r = s
            .update_fused_planning_v04(
                task(),
                revision,
                U::ReserveDelivery {
                    round: 1,
                    role: Role::Planner,
                    recipient: [21; 32],
                },
                now(20),
            )
            .unwrap();
        assert!(r
            .view_for_release_check()
            .unwrap()
            .suggested_templates
            .is_empty());
    }
}

#[test]
fn fused_exchange_reopen_retransmits_exact_bytes_and_keeps_attempt_limit() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(STATE_FILE_NAME);
    let anchor = TestRollbackProtectedStateAnchorV2::default();
    let mut s = task_store(&path, [0x81; 32], anchor.clone());
    install_release(&mut s, true, b"abstract view");
    let mut worker = Worker {
        reader: 20,
        mode: 1,
        ..Default::default()
    };
    exchange(
        &mut s,
        &mut worker,
        &rules(20, false),
        Role::Advisor,
        [10; 3],
    )
    .unwrap();
    drop(s);
    let mut s = task_store(&path, [0x81; 32], anchor);
    exchange(
        &mut s,
        &mut worker,
        &rules(20, false),
        Role::Advisor,
        [10; 3],
    )
    .unwrap();
    assert_eq!(worker.requests[0], worker.requests[1]);
    assert!(exchange(
        &mut s,
        &mut worker,
        &rules(20, false),
        Role::Advisor,
        [10; 3]
    )
    .is_err());
    assert_eq!(worker.requests.len(), 2);
}

#[test]
fn fused_exchange_uncertain_reservation_or_revocation_prevents_any_send() {
    for mode in 0..3 {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(STATE_FILE_NAME);
        let anchor = TestRollbackProtectedStateAnchorV2::default();
        let mut s = task_store(&path, [0x81; 32], anchor.clone());
        install_release(&mut s, true, b"abstract view");
        if mode == 2 {
            s.revoke_task_authorization(task()).unwrap();
        } else {
            s.rollback_anchor = Box::new(super::super::continuation_tests::FailAnchor {
                inner: anchor,
                after: mode == 1,
            });
        }
        let mut worker = Worker {
            reader: 20,
            ..Default::default()
        };
        assert!(exchange(
            &mut s,
            &mut worker,
            &rules(20, false),
            Role::Advisor,
            [10; 3]
        )
        .is_err());
        assert!(worker.requests.is_empty());
    }
}

#[test]
fn fused_model_view_with_real_epoch_deadline_passes_the_residual_pii_gate() {
    // Production views carry a current Unix-ms deadline. As a JSON decimal it
    // matched the card/phone PII patterns, so G3 withheld every view.
    let gate = |wire: &[u8]| {
        crate::v2::leak_gate::enforce_for_declassification(
            &KernelValueV2::bytes(wire.to_vec()).unwrap(),
            LeakGateDutyV2::BlocklistAndNoResidualPii,
        )
    };
    assert!(matches!(
        gate(br#"{"deadline":1790733952898}"#),
        Err(G3Error::LeakGateResidualPii)
    ));
    let view = ModelView {
        schema: 1,
        job: [7; 16],
        role: Role::Planner,
        model_profile: 1,
        deadline: 1_790_733_952_898,
        mode: Mode::RegisteredTemplateV04,
        public_view: b"Who else is invited at the networking event?".to_vec(),
        template_ids: vec![1, 2],
        question_codes: vec![],
        suggested_templates: vec![1],
        suggested_questions: vec![],
    };
    let wire = view.canonical_bytes().unwrap();
    assert!(gate(&wire).is_ok());
    let longest_digit_run = wire
        .split(|byte| !byte.is_ascii_digit())
        .map(<[u8]>::len)
        .max()
        .unwrap();
    assert!(longest_digit_run < 8);
    assert_eq!(serde_json::from_slice::<ModelView>(&wire).unwrap(), view);
}
