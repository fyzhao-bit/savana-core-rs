//! Actual encrypted G4/G7 transactions with synthetic executor evidence. No
//! declassification, publication, model call or external tool execution.
use super::*;
use crate::v2::{FusedOwnedResultV04, FusedResultScopeV04, RecoveredFusedExecutionV04};

fn at(t: u64) -> UnixMillisV2 {
    UnixMillisV2::new(t)
}

fn owned_result(
    job: &RecoveredFusedExecutionV04,
    bytes: &[u8],
    wrong_nonce: bool,
) -> FusedOwnedResultV04 {
    try_owned_result(job, bytes, wrong_nonce).unwrap()
}

fn try_owned_result(
    job: &RecoveredFusedExecutionV04,
    bytes: &[u8],
    wrong_nonce: bool,
) -> Result<FusedOwnedResultV04, G4Error> {
    let value = KernelValueV2::bytes(bytes.to_vec()).unwrap();
    let nonce = if wrong_nonce {
        d(201)
    } else {
        crate::v2::task_authorization::hash_parts(
            b"SAVANA_EXECUTION_NONCE_DIGEST_V2\0",
            &[job.core().execution_nonce().as_bytes()],
        )
    };
    let p = ProvenanceRecordV2::from_verified_executor_tool_result(
        &value,
        ProvenanceContextV2::from_authenticated_runtime(
            job.scope().producer(),
            job.core().durable_run_id(),
            d(3),
            at(10),
            job.scope().expires_at(),
        )
        .unwrap(),
        job.intent(),
        nonce,
        job.result_binding(),
        job.descriptor(),
        d(66),
        job.scope().effects(),
    )
    .unwrap();
    FusedOwnedResultV04::from_verified_result(&value, &p)
}

fn dispatch(
    f: &mut Fixture,
    profile: &FusedPlanningProfileV04,
    operation: u16,
) -> KernelPreparedDispatchV2 {
    // Compile against the live task pre-state, not the initial recipe-approval
    // drafts. Prior consumption must remain visible in every fresh intent.
    let mut input = input(f, profile, operation, 1, 39 + operation as u8, 93);
    let principal = f
        .store
        .task_authorization_state(task())
        .unwrap()
        .authorization()
        .material()
        .principal();
    input.request = bind(f, &input, 10).unwrap().with_fused_result_scope(
        FusedResultScopeV04::from_authenticated_session(
            principal,
            ProducerIdentityV2::new([90; 32]),
            at(100),
            EffectSetV2::SEND,
        )
        .unwrap(),
    );
    prepare(f, &input, 10, 100).unwrap()
}

fn succeed(f: &mut Fixture, dispatch: &KernelPreparedDispatchV2) {
    let p = dispatch.preparation();
    f.store
        .reconcile_tool_dispatch_with_outcome(
            VerifiedExecutorDispositionV2 {
                execution_nonce: p.execution_nonce(),
                dispatch_core_digest: p.dispatch_core_digest(),
                dispatch_subject_digest: p.dispatch_subject_digest(),
                evidence_digest: d(66),
                disposition: AuthenticatedEffectDispositionV2::known_success_for_test(),
            },
            true,
        )
        .unwrap();
}

fn complete_prefix(f: &mut Fixture, profile: &FusedPlanningProfileV04, count: u16) {
    for operation in 1..=count {
        let prepared = dispatch(f, profile, operation);
        succeed(f, &prepared);
        f.store
            .record_fused_result_commit_v04(task(), prepared.preparation().execution_nonce(), d(77))
            .unwrap();
    }
}

#[test]
fn fused_final_result_requires_all_completions_and_original_checkpoint() {
    let (mut f, profile, _) = scoped_inputs_fixture(Some(3));
    assert!(f
        .store
        .fused_final_result_candidate_v04(task(), at(10))
        .is_err());
    complete_prefix(&mut f, &profile, 2);
    let mut missing_scope = input(&mut f, &profile, 3, 1, 42, 93);
    missing_scope.request = bind(&f, &missing_scope, 10).unwrap();
    let head = f.store.current_head;
    assert!(prepare(&mut f, &missing_scope, 10, 100).is_err());
    assert_eq!(f.store.current_head, head);
    let prepared = dispatch(&mut f, &profile, 3);
    let nonce = prepared.preparation().execution_nonce();
    assert!(f
        .store
        .fused_execution_needs_result_v04(task(), nonce)
        .unwrap());
    assert!(f
        .store
        .fused_final_result_candidate_v04(task(), at(10))
        .is_err());
    let job = f
        .store
        .recover_fused_executions_v04(task())
        .unwrap()
        .remove(2);
    assert!(f
        .store
        .record_fused_result_value_v04(task(), nonce, d(77), owned_result(&job, b"final", false))
        .is_err());
    succeed(&mut f, &prepared);
    assert!(f
        .store
        .fused_final_result_candidate_v04(task(), at(10))
        .is_err());
    // A digest-only checkpoint cannot discard the declared terminal value.
    assert!(f
        .store
        .record_fused_result_commit_v04(task(), nonce, d(77))
        .is_err());
    let head = f.store.current_head;
    assert!(f
        .store
        .record_fused_result_value_v04(task(), nonce, d(77), owned_result(&job, b"final", true))
        .is_err());
    assert_eq!(f.store.current_head, head);
    f.store
        .record_fused_result_value_v04(task(), nonce, d(77), owned_result(&job, b"final", false))
        .unwrap();
    let c = f
        .store
        .fused_final_result_candidate_v04(task(), at(10))
        .unwrap();
    assert_eq!(c.value().as_bytes_value(), Some(b"final".as_slice()));
    assert_eq!(c.source(), 3);
    assert_eq!(c.task(), task());
    assert_eq!(c.core().execution_nonce(), nonce);
    assert_eq!(c.result_commit(), d(77));
}

#[test]
fn fused_final_result_failed_or_unknown_effect_never_becomes_completed_output() {
    for disposition in [
        AuthenticatedEffectDispositionV2::failed_no_effect_for_test(),
        AuthenticatedEffectDispositionV2::indeterminate_for_test(),
    ] {
        let (mut f, profile, _) = scoped_inputs_fixture(Some(3));
        complete_prefix(&mut f, &profile, 2);
        let prepared = dispatch(&mut f, &profile, 3);
        let p = prepared.preparation();
        f.store
            .reconcile_tool_dispatch_with_outcome(
                VerifiedExecutorDispositionV2 {
                    execution_nonce: p.execution_nonce(),
                    dispatch_core_digest: p.dispatch_core_digest(),
                    dispatch_subject_digest: p.dispatch_subject_digest(),
                    evidence_digest: d(66),
                    disposition,
                },
                true,
            )
            .unwrap();
        let mut f = f.reopen();
        let head = f.store.current_head;
        assert!(f
            .store
            .fused_final_result_candidate_v04(task(), at(11))
            .is_err());
        assert!(f
            .store
            .record_fused_result_commit_v04(task(), p.execution_nonce(), d(77))
            .is_err());
        assert_eq!(f.store.current_head, head);
    }
}

fn completed(bytes: &[u8]) -> Fixture {
    let (mut f, profile, _) = scoped_inputs_fixture(Some(3));
    complete_prefix(&mut f, &profile, 2);
    let prepared = dispatch(&mut f, &profile, 3);
    succeed(&mut f, &prepared);
    let job = f
        .store
        .recover_fused_executions_v04(task())
        .unwrap()
        .remove(2);
    f.store
        .record_fused_result_value_v04(
            task(),
            job.core().execution_nonce(),
            d(77),
            owned_result(&job, bytes, false),
        )
        .unwrap();
    f
}

#[test]
fn fused_final_result_reopen_is_read_only_and_never_extends_authority() {
    let f = completed(b"private terminal result");
    let digest = f
        .store
        .fused_final_result_candidate_v04(task(), at(10))
        .unwrap()
        .digest();
    let usage = f
        .store
        .task_authorization_state(task())
        .unwrap()
        .clause_consumption(1);
    let mut f = f.reopen();
    let head = f.store.current_head;
    for _ in 0..2 {
        let c = f
            .store
            .fused_final_result_candidate_v04(task(), at(11))
            .unwrap();
        assert_eq!(c.digest(), digest);
        assert_eq!(c.provenance().expires_at(), at(100));
    }
    for time in [9, 100, 1001] {
        assert!(f
            .store
            .fused_final_result_candidate_v04(task(), at(time))
            .is_err());
    }
    assert!(f
        .store
        .fused_final_result_candidate_v04(DurableTaskIdV2::new([88; 32]), at(11))
        .is_err());
    assert_eq!(f.store.current_head, head);
    assert_eq!(
        f.store
            .task_authorization_state(task())
            .unwrap()
            .clause_consumption(1),
        usage
    );
    f.store.revoke_task_authorization(task()).unwrap();
    let f = f.reopen();
    assert!(f
        .store
        .fused_final_result_candidate_v04(task(), at(11))
        .is_err());
    // Historical settlement remains recoverable, not new release authority.
    assert_eq!(
        f.store.recover_fused_executions_v04(task()).unwrap().len(),
        3
    );
}

#[test]
fn fused_final_result_requires_explicit_source_and_bounded_payload() {
    let (mut f, profile, _) = scoped_inputs_fixture(None);
    complete_prefix(&mut f, &profile, 3);
    assert!(f
        .store
        .fused_final_result_candidate_v04(task(), at(10))
        .is_err());
    let max = savana_kernel_protocol::v2::MAX_FINAL_RELEASE_BUSINESS_PAYLOAD_BYTES_V2;
    // The existing snapshot cap applies to encoded CBOR, so it is stricter
    // than the raw final-release payload cap. Do not relax it for publication.
    let f = completed(&vec![b'x'; max - 32]);
    assert!(f
        .store
        .fused_final_result_candidate_v04(task(), at(10))
        .is_ok());
    let job = f
        .store
        .recover_fused_executions_v04(task())
        .unwrap()
        .remove(2);
    assert!(try_owned_result(&job, &vec![b'x'; max], false).is_err());
    assert!(try_owned_result(&job, &vec![b'x'; max + 1], false).is_err());
}

#[test]
fn fused_final_result_restore_rejects_erased_or_rebound_result() {
    let f = completed(b"original");
    let raw: serde_json::Value =
        serde_json::from_slice(&f.store.snapshot.continuations.encode().unwrap()).unwrap();
    for case in 0..4 {
        let mut json = raw.clone();
        let record = &mut json["planning"]["records"][0];
        match case {
            0 => record["executions"][2]["result_value"] = serde_json::Value::Null,
            1 => record["executions"][2]["result_commit"] = serde_json::Value::Null,
            2 => record["profile"]["final_result_source"] = serde_json::json!(2),
            _ => record["profile"]["schema"] = serde_json::json!(1),
        }
        if let Ok(table) = crate::v2::continuation_state::ContinuationTableV04::decode(
            &serde_json::to_vec(&json).unwrap(),
        ) {
            let mut snapshot = f.store.snapshot.clone();
            snapshot.continuations = table;
            assert!(validate_snapshot(&snapshot).is_err(), "case {case}");
        }
    }
}
