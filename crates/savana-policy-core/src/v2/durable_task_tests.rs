//! Adversarial tests of the real owner, encrypted snapshot and single commit.
use super::*;
use crate::v2::durable_tests::{
    release_action, shared_connector_registry, signed_task, task_clause, task_request, task_store,
};
use crate::v2::{
    checked_control_endorsements_v2, ControlEvidenceV2, ControlSelectionV2, TaskMatchContextV2,
};
use ed25519_dalek::{Signer, SigningKey};
use savana_kernel_protocol::v2::{
    ActionAlternativeV2, ActionCodecProfileV2, MagnitudeUnitV2, TaskAuthorizationClauseV2,
    TaskEffectV2,
};

fn task() -> DurableTaskIdV2 {
    DurableTaskIdV2::new([4; 32])
}
fn d(seed: u8) -> Digest32V2 {
    Digest32V2::new([seed; 32])
}

fn issuance_draft(
    revision: u64,
    destination: &str,
) -> savana_kernel_protocol::v2::TaskAuthorizationDraftV2 {
    use savana_kernel_protocol::v2::*;
    let profile = BusinessProfileV2::new(
        ActionCodecProfileV2::McpToolsCallJsonV1,
        "mail.send",
        d(21),
        d(22),
        TaskEffectV2::Send,
        BusinessMagnitudeV2::FixedCount(1),
        vec![
            BusinessFieldV2::new(
                "body",
                BusinessFieldRoleV2::Payload,
                BusinessFieldTypeV2::Text,
            )
            .unwrap(),
            BusinessFieldV2::new(
                "file",
                BusinessFieldRoleV2::Resource,
                BusinessFieldTypeV2::Text,
            )
            .unwrap(),
            BusinessFieldV2::new(
                "to",
                BusinessFieldRoleV2::Destination,
                BusinessFieldTypeV2::Text,
            )
            .unwrap(),
        ],
    )
    .unwrap();
    let controls = BusinessControlsV2::from_fields(
        &profile,
        vec![
            (
                "file".into(),
                BusinessValueV2::Text("private-report".into()),
            ),
            ("to".into(), BusinessValueV2::Text(destination.into())),
        ],
    )
    .unwrap();
    TaskAuthorizationDraftV2::new(
        d(30),
        PrincipalIdV2::new([31; 32]),
        task(),
        revision,
        d(2),
        d(3),
        7,
        UnixMillisV2::new(1),
        UnixMillisV2::new(1000),
        d(32),
        vec![TaskAuthorizationDraftClauseV2::new(
            1,
            vec![TaskAuthorizationDraftAlternativeV2::new(d(33), controls).unwrap()],
            1,
            10,
            10,
            vec![],
            false,
        )
        .unwrap()],
    )
    .unwrap()
}
fn issued(
    draft: &savana_kernel_protocol::v2::TaskAuthorizationDraftV2,
    evidence: u8,
) -> VerifiedTaskAuthorizationV2 {
    use savana_kernel_protocol::v2::*;
    let key = SigningKey::from_bytes(&[34; 32]);
    let m = draft
        .to_unsigned_authorization(
            TaskEvidenceKindV2::AuthenticatedStructuredInput,
            d(evidence),
        )
        .unwrap();
    let s = sign_task_authorization_v2(m, &key).unwrap();
    VerifiedTaskAuthorizationV2::verify(
        &s,
        &key.verifying_key(),
        draft.principal(),
        draft.task(),
        d(2),
        d(3),
        UnixMillisV2::new(10),
    )
    .unwrap()
}

#[test]
fn pending_issuance_snapshot_cannot_lose_its_installed_authority() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(STATE_FILE_NAME);
    let mut store = task_store(
        &path,
        [0x81; 32],
        TestRollbackProtectedStateAnchorV2::default(),
    );
    let draft = issuance_draft(1, "Alice");
    store
        .record_pending_task_authorization(draft.clone(), d(40))
        .unwrap();
    store
        .install_pending_task_authorization(d(40), issued(&draft, 41))
        .unwrap();
    let mut broken = store.snapshot.clone();
    broken.tasks = Default::default();
    assert_eq!(
        validate_snapshot(&broken),
        Err(G4Error::DurableStateCorrupt)
    );
}

#[test]
fn pending_issuance_before_commit_failure_leaves_no_receipt_or_grant() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(STATE_FILE_NAME);
    let anchor = TestRollbackProtectedStateAnchorV2::default();
    let mut store = task_store(&path, [0x81; 32], anchor.clone());
    let draft = issuance_draft(1, "Alice");
    store
        .record_pending_task_authorization(draft.clone(), d(40))
        .unwrap();
    let head = anchor.current_head().unwrap();
    store.set_before_next_commit_hook_for_test(|| Err(G4Error::DurableStateIo));
    assert_eq!(
        store.install_pending_task_authorization(d(40), issued(&draft, 41)),
        Err(G4Error::DurableStateIo)
    );
    assert_eq!(head, anchor.current_head().unwrap());
    assert!(store.task_authorization_state(task()).is_err());
    assert!(store
        .pending_task_authorization(d(40))
        .unwrap()
        .unwrap()
        .installed_digest()
        .is_none());
    drop(store);
    let mut reopened = task_store(&path, [0x81; 32], anchor);
    assert!(reopened.task_authorization_state(task()).is_err());
    reopened
        .install_pending_task_authorization(d(40), issued(&draft, 41))
        .unwrap();
    assert_eq!(
        reopened
            .task_authorization_state(task())
            .unwrap()
            .authorization()
            .digest(),
        issued(&draft, 41).digest()
    );
}

#[test]
fn pending_issuance_uncertain_commit_recovers_receipt_and_grant_together() {
    struct FailingAnchor(TestRollbackProtectedStateAnchorV2);
    impl RollbackProtectedStateAnchorV2 for FailingAnchor {
        fn current_head(&self) -> Result<RollbackProtectedStateHeadV2, G4Error> {
            self.0.current_head()
        }
        fn compare_and_advance(
            &mut self,
            _: RollbackProtectedStateHeadV2,
            _: RollbackProtectedStateHeadV2,
        ) -> Result<(), G4Error> {
            Err(G4Error::DurableStateIo)
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(STATE_FILE_NAME);
    let anchor = TestRollbackProtectedStateAnchorV2::default();
    let mut store = task_store(&path, [0x81; 32], anchor.clone());
    let draft = issuance_draft(1, "Alice");
    store
        .record_pending_task_authorization(draft.clone(), d(40))
        .unwrap();
    let verified = issued(&draft, 41);
    store.rollback_anchor = Box::new(FailingAnchor(anchor.clone()));
    assert_eq!(
        store.install_pending_task_authorization(d(40), verified.clone()),
        Err(G4Error::DurableCommitUncertain)
    );
    assert_eq!(
        store.install_pending_task_authorization(d(40), verified.clone()),
        Err(G4Error::DurableCommitUncertain)
    );
    drop(store);
    let mut reopened = task_store(&path, [0x81; 32], anchor);
    assert_eq!(
        reopened
            .pending_task_authorization(d(40))
            .unwrap()
            .unwrap()
            .installed_digest(),
        Some(verified.digest())
    );
    assert_eq!(
        reopened
            .task_authorization_state(task())
            .unwrap()
            .authorization()
            .digest(),
        verified.digest()
    );
    let head = reopened.authenticated_state_head().unwrap();
    reopened
        .install_pending_task_authorization(d(40), verified)
        .unwrap();
    assert_eq!(head, reopened.authenticated_state_head().unwrap());
}

#[test]
fn pending_issuance_is_durable_unprivileged_exact_and_installs_atomically() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(STATE_FILE_NAME);
    let anchor = TestRollbackProtectedStateAnchorV2::default();
    let mut store = task_store(&path, [0x81; 32], anchor.clone());
    let draft = issuance_draft(1, "Alice");
    let pending = store
        .record_pending_task_authorization(draft.clone(), d(40))
        .unwrap();
    assert!(pending.installed_digest().is_none());
    assert!(store.task_authorization_state(task()).is_err());
    let head = store.current_head;
    store
        .record_pending_task_authorization(draft.clone(), d(40))
        .unwrap();
    assert_eq!(head, store.current_head);
    assert!(store
        .record_pending_task_authorization(issuance_draft(1, "Bob"), d(40))
        .is_err());
    assert_eq!(head, store.current_head);
    let bytes = std::fs::read(&path).unwrap();
    assert!(!bytes
        .windows(b"private-report".len())
        .any(|w| w == b"private-report"));
    drop(store);
    let mut store = task_store(&path, [0x81; 32], anchor.clone());
    assert_eq!(
        store.pending_task_authorization(d(40)).unwrap().unwrap(),
        &pending
    );
    let wrong = issued(&issuance_draft(1, "Bob"), 41);
    assert!(store
        .install_pending_task_authorization(d(40), wrong)
        .is_err());
    assert_eq!(head, store.current_head);
    let verified = issued(&draft, 41);
    store
        .install_pending_task_authorization(d(40), verified.clone())
        .unwrap();
    assert_eq!(store.current_head.sequence(), head.sequence() + 1);
    assert_eq!(
        store
            .task_authorization_state(task())
            .unwrap()
            .authorization(),
        &verified
    );
    assert_eq!(
        store
            .pending_task_authorization(d(40))
            .unwrap()
            .unwrap()
            .installed_digest(),
        Some(verified.digest())
    );
    let installed_head = store.current_head;
    store
        .install_pending_task_authorization(d(40), verified.clone())
        .unwrap();
    assert_eq!(installed_head, store.current_head);
    drop(store);
    let mut store = task_store(&path, [0x81; 32], anchor);
    assert_eq!(
        store
            .task_authorization_state(task())
            .unwrap()
            .authorization(),
        &verified
    );
    store.revoke_task_authorization(task()).unwrap();
    let revoked_head = store.current_head;
    store
        .install_pending_task_authorization(d(40), verified)
        .unwrap();
    assert_eq!(revoked_head, store.current_head);
    assert!(store.task_authorization_state(task()).unwrap().revoked());
    assert!(store
        .record_pending_task_authorization(issuance_draft(2, "Alice"), d(42))
        .is_err());
}

#[test]
fn pending_amendments_compare_the_exact_predecessor_and_do_not_replace_each_other() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = task_store(
        &dir.path().join(STATE_FILE_NAME),
        [0x81; 32],
        TestRollbackProtectedStateAnchorV2::default(),
    );
    let first = issuance_draft(1, "Alice");
    store
        .record_pending_task_authorization(first.clone(), d(40))
        .unwrap();
    store
        .install_pending_task_authorization(d(40), issued(&first, 41))
        .unwrap();
    let a = issuance_draft(2, "Alice");
    let b = issuance_draft(2, "Bob");
    store
        .record_pending_task_authorization(a.clone(), d(42))
        .unwrap();
    store
        .record_pending_task_authorization(b.clone(), d(43))
        .unwrap();
    store
        .install_pending_task_authorization(d(42), issued(&a, 44))
        .unwrap();
    let head = store.current_head;
    assert!(store
        .install_pending_task_authorization(d(43), issued(&b, 45))
        .is_err());
    assert_eq!(head, store.current_head);
    assert_eq!(
        store
            .task_authorization_state(task())
            .unwrap()
            .authorization()
            .material()
            .revision(),
        2
    );
}
fn clause(
    id: u64,
    budget: u64,
    attempts: u64,
    deps: Vec<u64>,
    retry: bool,
) -> TaskAuthorizationClauseV2 {
    task_clause(
        id,
        release_action(super::super::dispatch::final_release_binding_for_test(
            0x91, [13; 32],
        )),
        budget,
        attempts,
        deps,
        retry,
    )
}
struct Fixture {
    directory: tempfile::TempDir,
    anchor: TestRollbackProtectedStateAnchorV2,
    store: DurableG4StateV2,
}
impl Fixture {
    fn new(clauses: Vec<TaskAuthorizationClauseV2>) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let anchor = TestRollbackProtectedStateAnchorV2::default();
        let mut store = task_store(
            &directory.path().join(STATE_FILE_NAME),
            [0x81; 32],
            anchor.clone(),
        );
        store
            .install_verified_task_authorization(signed_task(task(), 1, clauses))
            .unwrap();
        Self {
            directory,
            anchor,
            store,
        }
    }
    fn request(&self, id: u64, magnitude: u64) -> TaskDispatchAuthorizationV2 {
        task_request(&self.store, task(), id, magnitude, d(0x92), d(0x93), d(9))
    }
    fn amend(&mut self, rev: u64, clauses: Vec<TaskAuthorizationClauseV2>) -> Result<(), G4Error> {
        self.store
            .install_verified_task_authorization(signed_task(task(), rev, clauses))
    }
}
fn release(id: u8) -> VerifiedFinalReleaseDispatchV2 {
    let binding = FinalReleaseSemanticBindingV2::from_nonzero_components(
        DurableReleaseIdV2::new([id; 32]),
        d(0x91),
        d(0x92),
        d(0x93),
        d(0x94),
        d(0x95),
        d(0x96),
        d(0x97),
        d(0x98),
        d(13),
        d(0x99),
    )
    .unwrap();
    VerifiedFinalReleaseDispatchV2::from_verified_release(
        d(2),
        d(3),
        task(),
        DurableRunIdV2::new([id; 32]),
        DurableReleaseIdV2::new([id; 32]),
        binding,
    )
    .unwrap()
}
fn prepare(
    store: &mut DurableG4StateV2,
    request: &TaskDispatchAuthorizationV2,
    id: u8,
) -> Result<DispatchPreparationV2, G4Error> {
    let release = release(id);
    let b = release.binding();
    let release = crate::v2::VerifiedFinalReleaseRecordV2::from_authorized_vault_release(
        d(2),
        d(3),
        request.matched.authorization().material().task(),
        DurableRunIdV2::new([id; 32]),
        b.durable_release_id(),
        b,
    )
    .unwrap();
    let approval = crate::v2::VerifiedFinalReleaseSettlementV2::from_consumed_exact_settlement(
        d(id),
        b.durable_release_id(),
        b.semantic_digest().unwrap(),
        b.destination_digest(),
        b.token_set_digest(),
        d(3),
        UnixMillisV2::new(1),
        UnixMillisV2::new(1000),
    )
    .unwrap();
    store
        .prepare_task_bound_final_release_dispatch(
            &release,
            VerifiedQuotaLimitV2::new_for_test(
                100,
                0xd1,
                DispatchQuotaSubjectV2::final_release(
                    release.binding().release_quota_subject_digest(),
                ),
            ),
            &approval,
            crate::v2::ResolvedFinalReleaseTicketV2::from_resolved_kernel_ticket(
                d(id),
                b.durable_release_id(),
                b.semantic_digest().unwrap(),
            )
            .unwrap(),
            crate::v2::VerifiedEffectGateLeaseV2::from_authenticated_ledger(
                d(2),
                d(3),
                7,
                8,
                false,
                ExecutorIdentityV2::new([13; 32]),
                savana_kernel_protocol::v2::HpkeX25519KeyIdV2::new([0x93; 32]),
                &shared_connector_registry(0x94),
                UnixMillisV2::new(10_000),
            )
            .unwrap(),
            d(id),
            request,
            UnixMillisV2::new(10),
        )
        .map(|p| p.preparation())
}
fn receipt(p: DispatchPreparationV2, kind: u16) -> SignedExecutorDispositionReceiptV2 {
    let key = SigningKey::from_bytes(&[0xc1; 32]);
    let domain: &[u8] = match kind {
        1 => b"SAVANA_EXECD_EFFECT_STARTED_RECEIPT_V2\0",
        2 => b"SAVANA_EXECD_KNOWN_SUCCESS_RECEIPT_V2\0",
        3 => b"SAVANA_EXECD_FAILED_NO_EFFECT_RECEIPT_V2\0",
        4 => b"SAVANA_EXECD_INDETERMINATE_RECEIPT_V2\0",
        _ => unreachable!(),
    };
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(11)
        .unwrap()
        .u16(2)
        .unwrap()
        .u16(kind)
        .unwrap()
        .bytes(d(2).as_bytes())
        .unwrap()
        .bytes(d(3).as_bytes())
        .unwrap()
        .u64(7)
        .unwrap()
        .u64(8)
        .unwrap()
        .bytes(p.execution_nonce().as_bytes())
        .unwrap()
        .bytes(p.dispatch_core_digest().as_bytes())
        .unwrap()
        .bytes(p.dispatch_subject_digest().as_bytes())
        .unwrap()
        .bytes(d(0xc3).as_bytes())
        .unwrap()
        .u64(10)
        .unwrap();
    let payload = e.into_writer();
    let mut h = Sha256::new();
    h.update(domain);
    h.update(&payload);
    let mut message = domain.to_vec();
    message.extend_from_slice(&h.finalize());
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(3)
        .unwrap()
        .bytes(&payload)
        .unwrap()
        .bytes(d(0xc2).as_bytes())
        .unwrap()
        .bytes(&key.sign(&message).to_bytes())
        .unwrap();
    SignedExecutorDispositionReceiptV2::from_canonical_bytes(&e.into_writer()).unwrap()
}
fn outcome(store: &DurableG4StateV2, p: DispatchPreparationV2, kind: u16) -> VerifiedTaskOutcomeV2 {
    store
        .verify_task_outcome(
            &receipt(p, kind),
            Ed25519KeyIdV2::new([0xc2; 32]),
            SigningKey::from_bytes(&[0xc1; 32])
                .verifying_key()
                .to_bytes(),
            UnixMillisV2::new(10),
        )
        .unwrap()
}

#[test]
fn task_state_no_effect_refunds_magnitude_once_but_never_attempts() {
    let mut f = Fixture::new(vec![clause(1, 5, 2, vec![], true)]);
    let request = f.request(1, 5);
    let p = prepare(&mut f.store, &request, 20).unwrap();
    assert!(f
        .store
        .reconcile_authenticated_failed_no_effect(
            p.execution_nonce(),
            p.dispatch_core_digest(),
            p.dispatch_subject_digest(),
            d(0xc3)
        )
        .is_err());
    let proof = outcome(&f.store, p, 3);
    f.store.reconcile_task_outcome(proof.clone()).unwrap();
    f.store.reconcile_task_outcome(proof).unwrap();
    assert_eq!(
        f.store
            .task_authorization_state(task())
            .unwrap()
            .clause_consumption(1),
        Some((1, 0))
    );
    let request = f.request(1, 5);
    let p = prepare(&mut f.store, &request, 21).unwrap();
    let proof = outcome(&f.store, p, 3);
    f.store.reconcile_task_outcome(proof).unwrap();
    let request = f.request(1, 1);
    assert!(prepare(&mut f.store, &request, 22).is_err());
    assert_eq!(
        f.store
            .task_authorization_state(task())
            .unwrap()
            .clause_consumption(1),
        Some((2, 0))
    );
}

#[test]
fn task_state_dependency_requires_signed_success_and_epoch_survives_aba() {
    let graph = || {
        vec![
            clause(1, 20, 20, vec![], false),
            clause(2, 20, 20, vec![1], false),
        ]
    };
    let mut f = Fixture::new(graph());
    let dependent = f.request(2, 1);
    assert!(prepare(&mut f.store, &dependent, 20).is_err());
    let first = f.request(1, 1);
    let p = prepare(&mut f.store, &first, 21).unwrap();
    let proof = outcome(&f.store, p, 2);
    f.store.reconcile_task_outcome(proof).unwrap();
    f.amend(
        2,
        vec![
            clause(1, 30, 30, vec![], false),
            clause(2, 30, 30, vec![1], false),
        ],
    )
    .unwrap();
    let allowed = f.request(2, 1);
    prepare(&mut f.store, &allowed, 22).unwrap(); // limits-only revision carries success
    f.amend(
        3,
        vec![
            clause(1, 20, 20, vec![], false),
            clause(2, 20, 20, vec![], false),
        ],
    )
    .unwrap();
    f.amend(4, graph()).unwrap();
    let dependent = f.request(2, 1);
    assert!(
        prepare(&mut f.store, &dependent, 23).is_err(),
        "A->B->A must not revive old success"
    );
}

#[test]
fn task_state_stale_budget_overflow_new_run_and_commit_failure_do_not_reserve() {
    let mut f = Fixture::new(vec![clause(1, u64::MAX, 4, vec![], false)]);
    let first = f.request(1, u64::MAX);
    let stale = f.request(1, 1);
    let head = f.store.authenticated_state_head().unwrap();
    f.store
        .set_before_next_commit_hook_for_test(|| Err(G4Error::DurableStateIo));
    assert!(prepare(&mut f.store, &first, 20).is_err());
    assert_eq!(f.store.authenticated_state_head().unwrap(), head);
    assert!(f.store.recovery_projection().unwrap().is_empty());
    prepare(&mut f.store, &first, 20).unwrap();
    let head = f.store.authenticated_state_head().unwrap();
    assert!(prepare(&mut f.store, &stale, 21).is_err());
    let current = f.request(1, 1);
    assert!(prepare(&mut f.store, &current, 22).is_err()); // checked addition overflow, new run
    assert_eq!(f.store.authenticated_state_head().unwrap(), head);
    assert_eq!(f.store.recovery_projection().unwrap().len(), 1);
}

#[test]
fn task_state_legacy_intent_cannot_gain_authority_after_upgrade() {
    let mut f = Fixture::new(vec![clause(1, 10, 10, vec![], false)]);
    let implementation = super::super::validator_tests::implementation(
        super::super::InternalValidatorImplementationKindV2::ProjectionBindingIntegrity,
        0x82,
    );
    let registry =
        VerifiedInternalValidatorRegistryV2::from_build_manifest(vec![implementation.clone()])
            .unwrap();
    let (record, stored) =
        super::super::validator_tests::evaluation_fixture(vec![implementation.declaration()]);
    let created = f
        .store
        .create_or_replay_verified_intent(
            RequestIdV2::new([1; 16]),
            &[1],
            d(2),
            d(3),
            DurableRunIdV2::new([4; 32]),
            DurableTaskIdV2::new([5; 32]),
            record.material().clone(),
        )
        .unwrap();
    f.store
        .evaluate_g5(
            &registry,
            created.action_intent_id(),
            &stored,
            OntologyEvaluationV2::Match,
            G5PolicyDispositionV2::permit_for_test(),
        )
        .unwrap();
    let mut legacy = f.store.snapshot.clone();
    legacy.payload_schema = 2;
    legacy.tasks = TaskLedgerV2::default();
    legacy.sequence = 1;
    legacy.previous_state_digest = Digest32V2::new([0; 32]);
    let bytes =
        encode_encrypted_snapshot(&legacy, &f.store.encryption_key, f.store.namespace).unwrap();
    let head = RollbackProtectedStateHeadV2 {
        sequence: legacy.sequence,
        state_digest: state_head_digest(f.store.namespace, &bytes),
    };
    // Authenticated historical fixture, not a migration implementation shortcut.
    f.store.anchored_path.replace(&bytes).unwrap();
    let path = f.directory.path().join(STATE_FILE_NAME);
    let anchor = TestRollbackProtectedStateAnchorV2::default();
    anchor
        .clone()
        .compare_and_advance(RollbackProtectedStateHeadV2::GENESIS, head)
        .unwrap();
    drop(f.store);
    let mut store = task_store(&path, [0x81; 32], anchor.clone());
    let action = ActionAlternativeV2::new(
        record.binding().tool_descriptor_digest(),
        ActionCodecProfileV2::FixedJsonPostV1,
        TaskEffectV2::Update,
        d(0xb6),
        d(0xb7),
        d(0xb8),
        MagnitudeUnitV2::Count,
    )
    .unwrap();
    store
        .install_verified_task_authorization(signed_task(
            DurableTaskIdV2::new([5; 32]),
            1,
            vec![task_clause(1, action, 10, 10, vec![], false)],
        ))
        .unwrap();
    let request = task_request(
        &store,
        DurableTaskIdV2::new([5; 32]),
        1,
        1,
        d(0xb9),
        d(0xba),
        Digest32V2::new(*record.binding().plan_revision_digest().as_bytes()),
    );
    let result = store.prepare_tool_dispatch(
        created.action_intent_id(),
        VerifiedQuotaLimitV2::new_for_test(
            10,
            0xd1,
            DispatchQuotaSubjectV2::tool_attempt(AttemptKindV2::ToolWrite),
        ),
        None,
        VerifiedExecutionTicketV2::new_for_test(&record, 0xd2),
        VerifiedEffectGateAuthorityV2::from_authenticated_unfenced_ledger(
            d(2),
            d(3),
            7,
            8,
            false,
            ExecutorIdentityV2::new([13; 32]),
            savana_kernel_protocol::v2::HpkeX25519KeyIdV2::new([0xd3; 32]),
            &shared_connector_registry(0x94),
            UnixMillisV2::new(10_000),
        )
        .unwrap(),
        d(0xd4),
        &request,
        UnixMillisV2::new(10),
    );
    assert!(
        result.is_err(),
        "a legacy intent is recovery-only even with a later valid contract"
    );
    assert!(store.recovery_projection().unwrap().is_empty());
    drop(store);
    let store = task_store(&path, [0x81; 32], anchor);
    assert!(store
        .snapshot
        .legacy_intents
        .contains(&created.action_intent_id()));
}

#[test]
fn task_state_unknown_schema_is_not_rewritten_and_legacy_effects_remain_recovery_only() {
    let mut f = Fixture::new(vec![clause(1, 10, 10, vec![], false)]);
    let request = f.request(1, 1);
    let p = prepare(&mut f.store, &request, 20).unwrap();
    f.store
        .reconcile_authenticated_indeterminate(
            p.execution_nonce(),
            p.dispatch_core_digest(),
            p.dispatch_subject_digest(),
            d(0xc3),
        )
        .unwrap();
    let mut legacy = f.store.snapshot.clone();
    legacy.payload_schema = 2;
    legacy.tasks = TaskLedgerV2::default();
    legacy.sequence = 1;
    legacy.previous_state_digest = Digest32V2::new([0; 32]);
    let bytes =
        encode_encrypted_snapshot(&legacy, &f.store.encryption_key, f.store.namespace).unwrap();
    f.store.anchored_path.replace(&bytes).unwrap();
    let head = RollbackProtectedStateHeadV2 {
        sequence: 1,
        state_digest: state_head_digest(f.store.namespace, &bytes),
    };
    let anchor = TestRollbackProtectedStateAnchorV2::default();
    anchor
        .clone()
        .compare_and_advance(RollbackProtectedStateHeadV2::GENESIS, head)
        .unwrap();
    let path = f.directory.path().join(STATE_FILE_NAME);
    drop(f.store);
    let mut store = task_store(&path, [0x81; 32], anchor.clone());
    assert_eq!(
        store.recovery_projection().unwrap()[0].state(),
        KernelDispatchStateV2::Indeterminate
    );
    store
        .install_verified_task_authorization(signed_task(
            task(),
            1,
            vec![clause(1, 10, 10, vec![], false)],
        ))
        .unwrap();
    assert!(prepare(&mut store, &request, 20).is_err()); // never promote old dispatch to task-bound
                                                         // Legacy exact recovery reconciliation still works after migration.
    store
        .reconcile_authenticated_indeterminate(
            p.execution_nonce(),
            p.dispatch_core_digest(),
            p.dispatch_subject_digest(),
            d(0xc3),
        )
        .unwrap();
    // A genuinely new task proceeds in the same store without discarding unknown effects.
    assert_eq!(store.recovery_projection().unwrap().len(), 1);
    let new_task = DurableTaskIdV2::new([0xee; 32]);
    let current = store.task_authorization_state(task()).unwrap();
    let m = current.authorization().material();
    let key = SigningKey::from_bytes(&[0xb1; 32]);
    let material = savana_kernel_protocol::v2::TaskAuthorizationV2::new(
        d(0xef),
        m.principal(),
        new_task,
        1,
        d(2),
        d(3),
        m.not_before(),
        m.expires_at(),
        m.evidence_kind(),
        m.user_evidence_digest(),
        m.rendering_digest(),
        m.clauses().to_vec(),
    )
    .unwrap();
    let signed = savana_kernel_protocol::v2::sign_task_authorization_v2(material, &key).unwrap();
    let verified = VerifiedTaskAuthorizationV2::verify(
        &signed,
        &key.verifying_key(),
        m.principal(),
        new_task,
        d(2),
        d(3),
        UnixMillisV2::new(10),
    )
    .unwrap();
    store.install_verified_task_authorization(verified).unwrap();
    let request = task_request(&store, new_task, 1, 1, d(0xb9), d(0xba), d(9));
    prepare(&mut store, &request, 21).unwrap();
    assert_eq!(store.recovery_projection().unwrap().len(), 2);
    assert_eq!(
        store
            .recovery_projection()
            .unwrap()
            .iter()
            .find(|entry| entry.execution_nonce() == p.execution_nonce())
            .unwrap()
            .state(),
        KernelDispatchStateV2::Indeterminate
    );
    // Construct a future payload under valid AEAD. The production encoder must
    // not learn how to emit unknown schemas just to support this negative test.
    let unknown = store.snapshot.clone();
    let mut payload = encode_snapshot_payload(&unknown).unwrap();
    assert_eq!(&payload[..2], &[0x8c, 4]);
    payload[1] = 5;
    let nonce = [0x71; STATE_NONCE_BYTES];
    let aad = state_encryption_aad(
        store.namespace,
        unknown.sequence,
        unknown.previous_state_digest,
        &nonce,
    );
    let ciphertext = Aes256Gcm::new_from_slice(&*store.encryption_key)
        .unwrap()
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &payload,
                aad: &aad,
            },
        )
        .unwrap();
    let bytes = encode_encrypted_envelope(
        unknown.sequence,
        unknown.previous_state_digest,
        &nonce,
        &ciphertext,
    )
    .unwrap();
    assert!(matches!(
        decode_encrypted_snapshot(&bytes, &store.encryption_key, store.namespace),
        Err(G4Error::DurableStateCorrupt)
    ));
    store.anchored_path.replace(&bytes).unwrap();
    drop(store);
    assert!(DurableG4StateV2::open_for_test_in_namespace(
        &path,
        [0x81; 32],
        anchor,
        DurableStateNamespaceV2::new_for_test(2, 0x54)
    )
    .is_err());
    assert_eq!(fs::read(path).unwrap(), bytes);
}

#[test]
fn task_state_pending_old_outcome_and_retroactive_retry_cannot_expand_authority() {
    let mut f = Fixture::new(vec![
        clause(1, 5, 5, vec![], false),
        clause(2, 5, 5, vec![1], false),
    ]);
    let request = f.request(1, 5);
    let p = prepare(&mut f.store, &request, 20).unwrap();
    f.amend(
        2,
        vec![
            clause(1, 5, 5, vec![], true),
            clause(2, 5, 5, vec![], false),
        ],
    )
    .unwrap();
    let no_effect = outcome(&f.store, p, 3);
    f.store.reconcile_task_outcome(no_effect).unwrap();
    assert_eq!(
        f.store
            .task_authorization_state(task())
            .unwrap()
            .clause_consumption(1),
        Some((1, 5))
    );
    f.amend(
        3,
        vec![
            clause(1, 10, 5, vec![], true),
            clause(2, 5, 5, vec![1], false),
        ],
    )
    .unwrap();
    let request = f.request(1, 1);
    let p = prepare(&mut f.store, &request, 21).unwrap();
    f.amend(
        4,
        vec![
            clause(1, 10, 5, vec![], true),
            clause(2, 5, 5, vec![], false),
        ],
    )
    .unwrap();
    f.amend(
        5,
        vec![
            clause(1, 10, 5, vec![], true),
            clause(2, 5, 5, vec![1], false),
        ],
    )
    .unwrap();
    let success = outcome(&f.store, p, 2);
    f.store.reconcile_task_outcome(success).unwrap();
    let dependent = f.request(2, 1);
    assert!(prepare(&mut f.store, &dependent, 22).is_err());
}

#[test]
fn task_state_effect_started_unknown_and_raw_success_cannot_refund_or_unlock() {
    for kind in [1, 4] {
        let mut f = Fixture::new(vec![
            clause(1, 5, 5, vec![], true),
            clause(2, 5, 5, vec![1], false),
        ]);
        let request = f.request(1, 5);
        let p = prepare(&mut f.store, &request, 20).unwrap();
        f.store
            .reconcile_signed_final_release_dispatch(
                &receipt(p, kind),
                Ed25519KeyIdV2::new([0xc2; 32]),
                SigningKey::from_bytes(&[0xc1; 32])
                    .verifying_key()
                    .to_bytes(),
                UnixMillisV2::new(10),
            )
            .unwrap();
        assert!(f
            .store
            .reconcile_final_release_dispatch(VerifiedExecutorDispositionV2 {
                execution_nonce: p.execution_nonce(),
                dispatch_core_digest: p.dispatch_core_digest(),
                dispatch_subject_digest: p.dispatch_subject_digest(),
                evidence_digest: d(0xc3),
                disposition: AuthenticatedEffectDispositionV2::from_verified_known_success()
            })
            .is_err());
        let proof = outcome(&f.store, p, 3);
        assert!(f.store.reconcile_task_outcome(proof).is_err());
        let request = f.request(1, 1);
        assert!(prepare(&mut f.store, &request, 21).is_err());
        let request = f.request(2, 1);
        assert!(prepare(&mut f.store, &request, 22).is_err());
        assert_eq!(
            f.store
                .task_authorization_state(task())
                .unwrap()
                .clause_consumption(1),
            Some((1, 5))
        );
    }
}

#[test]
fn task_state_concurrent_prepares_and_file_lock_have_one_winner() {
    let f = Fixture::new(vec![clause(1, 5, 5, vec![], false)]);
    let request = f.request(1, 4);
    let path = f.directory.path().join(STATE_FILE_NAME);
    assert!(DurableG4StateV2::open_for_test_in_namespace(
        &path,
        [0x81; 32],
        f.anchor.clone(),
        DurableStateNamespaceV2::new_for_test(2, 0x54)
    )
    .is_err());
    let store = Arc::new(Mutex::new(f.store));
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let handles: Vec<_> = [20, 21]
        .into_iter()
        .map(|id| {
            let store = store.clone();
            let barrier = barrier.clone();
            let request = request.clone();
            std::thread::spawn(move || {
                barrier.wait();
                prepare(&mut store.lock().unwrap(), &request, id).is_ok()
            })
        })
        .collect();
    assert_eq!(
        handles
            .into_iter()
            .filter(|h| h.thread().id() != std::thread::current().id())
            .map(|h| usize::from(h.join().unwrap()))
            .sum::<usize>(),
        1
    );
    assert_eq!(
        store
            .lock()
            .unwrap()
            .task_authorization_state(task())
            .unwrap()
            .clause_consumption(1),
        Some((1, 4))
    );
    drop(store);
    let reopened = task_store(&path, [0x81; 32], f.anchor);
    assert_eq!(
        reopened
            .task_authorization_state(task())
            .unwrap()
            .clause_consumption(1),
        Some((1, 4))
    );
}

#[test]
fn task_state_uncertain_commit_reopens_one_charged_reservation() {
    struct FailingAnchor {
        inner: TestRollbackProtectedStateAnchorV2,
    }
    impl RollbackProtectedStateAnchorV2 for FailingAnchor {
        fn current_head(&self) -> Result<RollbackProtectedStateHeadV2, G4Error> {
            self.inner.current_head()
        }
        fn compare_and_advance(
            &mut self,
            _: RollbackProtectedStateHeadV2,
            _: RollbackProtectedStateHeadV2,
        ) -> Result<(), G4Error> {
            Err(G4Error::DurableStateIo)
        }
    }
    let mut f = Fixture::new(vec![clause(1, 5, 5, vec![], false)]);
    let request = f.request(1, 4);
    f.store.rollback_anchor = Box::new(FailingAnchor {
        inner: f.anchor.clone(),
    });
    assert_eq!(
        prepare(&mut f.store, &request, 20).unwrap_err(),
        G4Error::DurableCommitUncertain
    );
    assert_eq!(
        prepare(&mut f.store, &request, 20).unwrap_err(),
        G4Error::DurableCommitUncertain
    );
    let path = f.directory.path().join(STATE_FILE_NAME);
    drop(f.store);
    let mut store = task_store(&path, [0x81; 32], f.anchor);
    let p = prepare(&mut store, &request, 20).unwrap();
    assert_eq!(p.kind(), DispatchPreparationKindV2::Replay);
    assert_eq!(
        store
            .task_authorization_state(task())
            .unwrap()
            .clause_consumption(1),
        Some((1, 4))
    );
    assert_eq!(store.recovery_projection().unwrap().len(), 1);
}

#[test]
fn task_state_durable_identity_unit_limits_and_revocation_cannot_reset_consumption() {
    use savana_kernel_protocol::v2::{
        sign_task_authorization_v2, PrincipalIdV2, TaskAuthorizationV2,
    };
    let mut f = Fixture::new(vec![clause(1, 10, 10, vec![], false)]);
    let request = f.request(1, 4);
    prepare(&mut f.store, &request, 20).unwrap();
    let original = f
        .store
        .task_authorization_state(task())
        .unwrap()
        .authorization()
        .clone();
    for change in 0..4 {
        let m = original.material();
        let key = SigningKey::from_bytes(&[0xb1; 32]);
        let id = if change == 0 {
            d(0xee)
        } else {
            m.authorization_id()
        };
        let principal = if change == 1 {
            PrincipalIdV2::new([0xee; 32])
        } else {
            m.principal()
        };
        let installation = if change == 2 {
            d(0xee)
        } else {
            m.installation_digest()
        };
        let other_task = if change == 3 {
            DurableTaskIdV2::new([0xee; 32])
        } else {
            task()
        };
        let m = TaskAuthorizationV2::new(
            id,
            principal,
            other_task,
            2,
            installation,
            m.manifest_digest(),
            m.not_before(),
            m.expires_at(),
            m.evidence_kind(),
            m.user_evidence_digest(),
            m.rendering_digest(),
            m.clauses().to_vec(),
        )
        .unwrap();
        let a = VerifiedTaskAuthorizationV2::verify(
            &sign_task_authorization_v2(m, &key).unwrap(),
            &key.verifying_key(),
            principal,
            other_task,
            installation,
            d(3),
            UnixMillisV2::new(10),
        )
        .unwrap();
        assert!(
            f.store.install_verified_task_authorization(a).is_err(),
            "identity mutation {change}"
        );
    }
    let a = original.material().clauses()[0].alternatives()[0].clone();
    let other_unit = ActionAlternativeV2::new(
        a.tool_descriptor_digest(),
        a.codec_profile(),
        a.effect(),
        a.resource_digest(),
        a.destination_digest(),
        a.parameters_digest(),
        MagnitudeUnitV2::Count,
    )
    .unwrap();
    assert!(f
        .amend(2, vec![task_clause(1, other_unit, 10, 10, vec![], false)])
        .is_err());
    assert!(f.amend(1, vec![clause(1, 20, 20, vec![], false)]).is_err());
    f.amend(2, vec![clause(1, 20, 20, vec![], false)]).unwrap();
    assert!(f
        .store
        .install_verified_task_authorization(original)
        .is_err());
    f.store.revoke_task_authorization(task()).unwrap();
    let request = f.request(1, 1);
    assert!(prepare(&mut f.store, &request, 21).is_err());
    assert!(f.amend(3, vec![clause(1, 30, 30, vec![], false)]).is_err());
}

fn with_approval(
    f: &Fixture,
    mut request: TaskDispatchAuthorizationV2,
) -> TaskDispatchAuthorizationV2 {
    use savana_kernel_protocol::v2::{
        sign_task_action_approval_v2, verify_task_action_approval_v2, TaskActionApprovalContextV2,
        TaskActionApprovalDecisionV2, TaskActionApprovalV2,
    };
    let m = &request.matched;
    let a = m.authorization().material();
    let context = TaskActionApprovalContextV2 {
        content_digest: m.content_digest(),
        authorization_id: a.authorization_id(),
        authorization_revision: a.revision(),
        principal: a.principal(),
        task: a.task(),
        installation_digest: a.installation_digest(),
        manifest_digest: a.manifest_digest(),
        deployment_generation: 7,
        challenge_nonce: d(0xe1),
        settlement_nonce: d(0xe2),
        authentication_context_digest: d(0xe3),
        display_digest: d(0xe4),
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
    let approval = verify_task_action_approval_v2(
        &signed,
        &key.verifying_key(),
        &context,
        UnixMillisV2::new(10),
    )
    .unwrap();
    let state = f.store.task_authorization_state(task()).unwrap();
    let current = TaskMatchContextV2 {
        current_authorization: Some(state.authorization()),
        pre_state_digest: state.digest(),
        pre_state_revision: state.revision(),
        deployment_generation: 7,
        now: UnixMillisV2::new(10),
    };
    request.endorsements = checked_control_endorsements_v2(
        m,
        &ControlSelectionV2::from_match(m, d(0xe6)).unwrap(),
        ControlEvidenceV2::ActionApproval {
            approval: &approval,
            expected_context: &context,
        },
        &current,
    )
    .unwrap();
    request
}

#[test]
fn task_state_endorsements_settlement_nonce_and_original_replay_are_atomic() {
    let mut f = Fixture::new(vec![clause(1, 10, 10, vec![], false)]);
    let request = with_approval(&f, f.request(1, 1));
    let mut reordered = request.clone();
    reordered.endorsements.swap(0, 1);
    assert!(prepare(&mut f.store, &reordered, 20).is_err());
    assert!(f.store.recovery_projection().unwrap().is_empty());
    let p = prepare(&mut f.store, &request, 20).unwrap();
    let binding = f
        .store
        .task_dispatch_binding(p.execution_nonce())
        .unwrap()
        .clone();
    let fresh_same_nonce = with_approval(&f, f.request(1, 1));
    assert!(prepare(&mut f.store, &fresh_same_nonce, 21).is_err());
    f.amend(2, vec![clause(1, 20, 20, vec![], false)]).unwrap();
    let same = prepare(&mut f.store, &request, 20).unwrap();
    assert_eq!(p.execution_nonce(), same.execution_nonce());
    assert_eq!(
        f.store
            .task_dispatch_binding(same.execution_nonce())
            .unwrap(),
        &binding
    );
    let newly_matched = f.request(1, 1);
    assert!(prepare(&mut f.store, &newly_matched, 20).is_err());
    let result = f.store.verify_task_outcome(
        &receipt(p, 2),
        Ed25519KeyIdV2::new([0xc2; 32]),
        SigningKey::from_bytes(&[0xff; 32])
            .verifying_key()
            .to_bytes(),
        UnixMillisV2::new(10),
    );
    assert!(result.is_err());
    assert!(f
        .store
        .verify_task_outcome(
            &receipt(p, 2),
            Ed25519KeyIdV2::new([0xff; 32]),
            SigningKey::from_bytes(&[0xc1; 32])
                .verifying_key()
                .to_bytes(),
            UnixMillisV2::new(10)
        )
        .is_err());
}

#[test]
fn task_state_public_final_prepare_rejects_missing_authority() {
    use crate::v2::{
        ResolvedFinalReleaseTicketV2, VerifiedEffectGateLeaseV2, VerifiedFinalReleaseRecordV2,
        VerifiedFinalReleaseSettlementV2,
    };
    let mut f = Fixture::new(vec![clause(1, 10, 10, vec![], false)]);
    let r = release(20);
    let b = r.binding();
    let record = VerifiedFinalReleaseRecordV2 { inner: r.clone() };
    let approval = VerifiedFinalReleaseSettlementV2::from_consumed_exact_settlement(
        d(20),
        b.durable_release_id(),
        b.semantic_digest().unwrap(),
        b.destination_digest(),
        b.token_set_digest(),
        d(3),
        UnixMillisV2::new(1),
        UnixMillisV2::new(1000),
    )
    .unwrap();
    let ticket = ResolvedFinalReleaseTicketV2::from_resolved_kernel_ticket(
        d(21),
        b.durable_release_id(),
        b.semantic_digest().unwrap(),
    )
    .unwrap();
    let authority = VerifiedEffectGateLeaseV2::from_authenticated_ledger(
        d(2),
        d(3),
        7,
        8,
        false,
        ExecutorIdentityV2::new([13; 32]),
        savana_kernel_protocol::v2::HpkeX25519KeyIdV2::new([0x93; 32]),
        &shared_connector_registry(0x94),
        UnixMillisV2::new(1000),
    )
    .unwrap();
    assert!(f
        .store
        .prepare_verified_final_release_dispatch(
            &record,
            VerifiedQuotaLimitV2::new_for_test(
                10,
                0xd1,
                DispatchQuotaSubjectV2::final_release(b.release_quota_subject_digest())
            ),
            &approval,
            ticket,
            authority,
            d(22)
        )
        .is_err());
    assert!(f.store.recovery_projection().unwrap().is_empty());
}

#[test]
fn task_state_shared_tool_plan_binding_is_checked_before_reserving() {
    let directory = tempfile::tempdir().unwrap();
    let mut store = task_store(
        &directory.path().join(STATE_FILE_NAME),
        [0x81; 32],
        TestRollbackProtectedStateAnchorV2::default(),
    );
    let implementation = super::super::validator_tests::implementation(
        super::super::InternalValidatorImplementationKindV2::ProjectionBindingIntegrity,
        0x82,
    );
    let registry =
        VerifiedInternalValidatorRegistryV2::from_build_manifest(vec![implementation.clone()])
            .unwrap();
    let (record, stored) =
        super::super::validator_tests::evaluation_fixture(vec![implementation.declaration()]);
    let created = store
        .create_or_replay_verified_intent(
            RequestIdV2::new([1; 16]),
            &[1],
            d(2),
            d(3),
            DurableRunIdV2::new([4; 32]),
            DurableTaskIdV2::new([5; 32]),
            record.material().clone(),
        )
        .unwrap();
    store
        .evaluate_g5(
            &registry,
            created.action_intent_id(),
            &stored,
            OntologyEvaluationV2::Match,
            G5PolicyDispositionV2::permit_for_test(),
        )
        .unwrap();
    let action = ActionAlternativeV2::new(
        record.binding().tool_descriptor_digest(),
        ActionCodecProfileV2::FixedJsonPostV1,
        TaskEffectV2::Update,
        d(0xb6),
        d(0xb7),
        d(0xb8),
        MagnitudeUnitV2::Count,
    )
    .unwrap();
    store
        .install_verified_task_authorization(signed_task(
            DurableTaskIdV2::new([5; 32]),
            1,
            vec![task_clause(1, action, 10, 10, vec![], false)],
        ))
        .unwrap();
    let request = task_request(
        &store,
        DurableTaskIdV2::new([5; 32]),
        1,
        1,
        d(0xb9),
        d(0xba),
        d(0xff),
    ); // statically valid, wrong actual plan
    let head = store.authenticated_state_head().unwrap();
    assert!(store
        .prepare_tool_dispatch(
            created.action_intent_id(),
            VerifiedQuotaLimitV2::new_for_test(
                10,
                0xd1,
                DispatchQuotaSubjectV2::tool_attempt(AttemptKindV2::ToolWrite)
            ),
            None,
            VerifiedExecutionTicketV2::new_for_test(&record, 0xd2),
            VerifiedEffectGateAuthorityV2::from_authenticated_unfenced_ledger(
                d(2),
                d(3),
                7,
                8,
                false,
                ExecutorIdentityV2::new([13; 32]),
                savana_kernel_protocol::v2::HpkeX25519KeyIdV2::new([0xd3; 32]),
                &shared_connector_registry(0x94),
                UnixMillisV2::new(10_000)
            )
            .unwrap(),
            d(0xd4),
            &request,
            UnixMillisV2::new(10)
        )
        .is_err());
    assert_eq!(store.authenticated_state_head().unwrap(), head);
    assert!(store.recovery_projection().unwrap().is_empty());
}
