use ed25519_dalek::SigningKey;
use savana_kernel_protocol::v2::{
    Digest32V2, DurableReleaseIdV2, DurableRunIdV2, DurableTaskIdV2, ExecutorIdentityV2,
    FinalReleaseSemanticBindingV2, ImplementationIdV2, InternalSlotDigestV2, InternalStepIdV2,
    Nonce32V2, PlanRevisionDigestV2, PrincipalIdV2, RequestIdV2, RoleIdV2, ToolClassIdV2,
    ValueInternalIdV2, VersionV2,
};

use super::dispatch::{
    final_release_binding_for_test, VerifiedEffectGateAuthorityV2, VerifiedExecutorDispositionV2,
    VerifiedFinalReleaseApprovalBindingV2, VerifiedFinalReleaseDispatchV2,
    VerifiedFinalReleaseTicketV2,
};
use super::durable::{DurableStateNamespaceV2, TestRollbackProtectedStateAnchorV2};
use super::intent::VerifiedToolProposalV2;
use super::ontology::OntologyEvaluationV2;
use super::{
    activate_internal_validator_registry, tool_approval_binding_digest_v2,
    tool_execution_semantic_binding_digest_v2, ActionIntentResolutionKindV2, ActionIntentStateV2,
    AttemptKindV2, AuthenticatedEffectDispositionV2, ConnectorRegistryStateV2,
    DispatchQuotaMutationKindV2, DispatchQuotaSubjectV2, DurableG4StateV2, G4Error,
    G5DecisionResolutionKindV2, G5PolicyDispositionV2, InternalValidatorBuildV2,
    InternalValidatorImplementationKindV2, OntologyExprV2, OntologyOperandV2, OntologyScalarV2,
    ResolvedExecutionTicketV2, SharedVerifiedConnectorRegistryV2, StableActionArgumentBindingV2,
    ToolExecutionSemanticBindingV2, VerifiedActionIntentMaterialV2, VerifiedEffectGateLeaseV2,
    VerifiedInternalValidatorRegistryV2, VerifiedOntologyEvaluationV2, VerifiedPolicyDispositionV2,
    VerifiedQuotaLimitV2, VerifiedToolApprovalSettlementV2,
};
use crate::v2::ArgumentNameV2;

fn shared_connector_registry(seed: u8) -> SharedVerifiedConnectorRegistryV2 {
    SharedVerifiedConnectorRegistryV2::from_verified_state(
        ConnectorRegistryStateV2::from_verified_genesis(
            Digest32V2::new([seed; 32]),
            [0; 32],
            vec![],
            vec![],
        )
        .unwrap(),
    )
    .unwrap()
}

#[test]
fn intent_replay_current_state_and_quota_tombstone_survive_restart() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("kernel-g4-state-v2.cbor");
    let key = [0x41; 32];
    let request = RequestIdV2::new([1; 16]);
    let run = DurableRunIdV2::new([4; 32]);
    let task = DurableTaskIdV2::new([5; 32]);
    let dispatch_subject = Digest32V2::new([0x81; 32]);
    let nonce = Nonce32V2::new([0x82; 32]);
    let subject = DispatchQuotaSubjectV2::tool_attempt(AttemptKindV2::ToolWrite);
    let anchor = TestRollbackProtectedStateAnchorV2::default();

    let action_intent_id = {
        let mut store = DurableG4StateV2::open_for_test(&path, key, anchor.clone()).unwrap();
        let intent_material = material(6);
        let created = store
            .create_or_replay_intent(
                proposal(request, run, task, &intent_material),
                intent_material,
            )
            .unwrap();
        assert_eq!(created.kind(), ActionIntentResolutionKindV2::Created);
        store
            .advance_intent_for_test(
                created.action_intent_id(),
                ActionIntentStateV2::NeedsApproval,
            )
            .unwrap();
        let reserved = store
            .reserve_quota(limit(1, subject), run, subject, dispatch_subject, nonce)
            .unwrap();
        assert_eq!(reserved.kind(), DispatchQuotaMutationKindV2::Applied);
        created.action_intent_id()
    };

    let mut reopened = DurableG4StateV2::open_for_test(&path, key, anchor.clone()).unwrap();
    let replay_material = material(6);
    let replay = reopened
        .create_or_replay_intent(
            proposal(request, run, task, &replay_material),
            replay_material,
        )
        .unwrap();
    assert_eq!(replay.kind(), ActionIntentResolutionKindV2::Replay);
    assert_eq!(replay.action_intent_id(), action_intent_id);
    assert_eq!(replay.current_state(), ActionIntentStateV2::NeedsApproval);

    let reservation_replay = reopened
        .reserve_quota(limit(1, subject), run, subject, dispatch_subject, nonce)
        .unwrap();
    assert_eq!(
        reservation_replay.kind(),
        DispatchQuotaMutationKindV2::Replay
    );
    assert_eq!(
        reopened
            .reserve_quota(
                limit(1, subject),
                run,
                subject,
                dispatch_subject,
                Nonce32V2::new([0x83; 32]),
            )
            .unwrap_err(),
        G4Error::StateConflict
    );
    let spent = reopened
        .transition_quota(
            nonce,
            dispatch_subject,
            AuthenticatedEffectDispositionV2::effect_started_for_test(),
        )
        .unwrap();
    assert_eq!(spent.counter().spent(), 1);
}

#[test]
fn durable_state_rejects_wrong_authentication_key_and_modified_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("kernel-g4-state-v2.cbor");
    let anchor = TestRollbackProtectedStateAnchorV2::default();
    {
        let mut store = DurableG4StateV2::open_for_test(&path, [0x31; 32], anchor.clone()).unwrap();
        store
            .reserve_quota(
                limit(
                    1,
                    DispatchQuotaSubjectV2::tool_attempt(AttemptKindV2::ToolRead),
                ),
                DurableRunIdV2::new([1; 32]),
                DispatchQuotaSubjectV2::tool_attempt(AttemptKindV2::ToolRead),
                Digest32V2::new([2; 32]),
                Nonce32V2::new([3; 32]),
            )
            .unwrap();
    }
    assert_eq!(
        DurableG4StateV2::open_for_test(&path, [0x32; 32], anchor.clone()).unwrap_err(),
        G4Error::DurableStateAuthentication
    );

    let mut bytes = std::fs::read(&path).unwrap();
    let last = bytes.last_mut().unwrap();
    *last ^= 1;
    std::fs::write(&path, bytes).unwrap();
    assert_eq!(
        DurableG4StateV2::open_for_test(&path, [0x31; 32], anchor).unwrap_err(),
        G4Error::DurableStateAuthentication
    );
}

#[test]
fn durable_state_key_and_head_are_bound_to_installation_namespace() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("kernel-g4-state-v2.cbor");
    let key = [0x39; 32];
    let namespace_a = DurableStateNamespaceV2::new_for_test(0x3a, 0x3b);
    let namespace_b = DurableStateNamespaceV2::new_for_test(0x3c, 0x3d);
    let subject = DispatchQuotaSubjectV2::tool_attempt(AttemptKindV2::ToolRead);
    {
        let mut store = DurableG4StateV2::open_for_test_in_namespace(
            &path,
            key,
            TestRollbackProtectedStateAnchorV2::default(),
            namespace_a,
        )
        .unwrap();
        store
            .reserve_quota(
                limit(1, subject),
                DurableRunIdV2::new([0x3e; 32]),
                subject,
                Digest32V2::new([0x3f; 32]),
                Nonce32V2::new([0x40; 32]),
            )
            .unwrap();
    }

    assert_eq!(
        DurableG4StateV2::open_for_test_in_namespace(
            &path,
            key,
            TestRollbackProtectedStateAnchorV2::default(),
            namespace_b,
        )
        .unwrap_err(),
        G4Error::DurableStateAuthentication
    );
}

#[test]
fn durable_state_rejects_authenticated_snapshot_rollback() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("kernel-g4-state-v2.cbor");
    let anchor = TestRollbackProtectedStateAnchorV2::default();
    let key = [0x51; 32];
    let run = DurableRunIdV2::new([1; 32]);
    let subject = DispatchQuotaSubjectV2::tool_attempt(AttemptKindV2::ToolRead);

    let old_snapshot = {
        let mut store = DurableG4StateV2::open_for_test(&path, key, anchor.clone()).unwrap();
        store
            .reserve_quota(
                limit(2, subject),
                run,
                subject,
                Digest32V2::new([2; 32]),
                Nonce32V2::new([3; 32]),
            )
            .unwrap();
        std::fs::read(&path).unwrap()
    };

    {
        let mut store = DurableG4StateV2::open_for_test(&path, key, anchor.clone()).unwrap();
        store
            .reserve_quota(
                limit(2, subject),
                run,
                subject,
                Digest32V2::new([4; 32]),
                Nonce32V2::new([5; 32]),
            )
            .unwrap();
    }

    std::fs::write(&path, old_snapshot).unwrap();
    assert_eq!(
        DurableG4StateV2::open_for_test(&path, key, anchor).unwrap_err(),
        G4Error::DurableStateRollback
    );
}

#[test]
fn durable_snapshot_encrypts_projection_values_at_rest() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("kernel-g4-state-v2.cbor");
    let anchor = TestRollbackProtectedStateAnchorV2::default();
    let mut store = DurableG4StateV2::open_for_test(&path, [0x61; 32], anchor).unwrap();
    let intent_material = material(6);
    store
        .create_or_replay_intent(
            proposal(
                RequestIdV2::new([1; 16]),
                DurableRunIdV2::new([4; 32]),
                DurableTaskIdV2::new([5; 32]),
                &intent_material,
            ),
            intent_material,
        )
        .unwrap();
    let encrypted = std::fs::read(path).unwrap();
    assert!(!encrypted
        .windows(b"destination-6".len())
        .any(|window| window == b"destination-6"));
    assert!(!encrypted
        .windows(b"display-6".len())
        .any(|window| window == b"display-6"));
}

#[test]
fn g5_decision_replays_after_encrypted_restart() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("kernel-g4-state-v2.cbor");
    let anchor = TestRollbackProtectedStateAnchorV2::default();
    let key = [0x71; 32];
    let implementation = super::validator_tests::implementation(
        InternalValidatorImplementationKindV2::ProjectionBindingIntegrity,
        0x72,
    );
    let registry = activate_internal_validator_registry(vec![InternalValidatorBuildV2::new(
        InternalValidatorImplementationKindV2::ProjectionBindingIntegrity,
        ImplementationIdV2::new(4),
        VersionV2::new(1, 0, 0),
        Digest32V2::new([0x72; 32]),
    )])
    .unwrap();
    let (record, stored) =
        super::validator_tests::evaluation_fixture(vec![implementation.declaration()]);
    let ontology = || {
        VerifiedOntologyEvaluationV2::evaluate(
            &OntologyExprV2::eq(
                OntologyOperandV2::literal(OntologyScalarV2::boolean(true)),
                OntologyOperandV2::literal(OntologyScalarV2::boolean(true)),
            ),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            RoleIdV2::new(1),
            ToolClassIdV2::new(1),
            AttemptKindV2::ToolWrite,
            PrincipalIdV2::new([0x73; 32]),
            DurableTaskIdV2::new([5; 32]),
        )
        .unwrap()
    };
    {
        let mut store = DurableG4StateV2::open_for_test(&path, key, anchor.clone()).unwrap();
        let material = record.material().clone();
        let intent = store
            .create_or_replay_verified_intent(
                RequestIdV2::new([1; 16]),
                &[0x01],
                Digest32V2::new([2; 32]),
                Digest32V2::new([3; 32]),
                DurableRunIdV2::new([4; 32]),
                DurableTaskIdV2::new([5; 32]),
                material,
            )
            .unwrap();
        let created = store
            .evaluate_verified_g5(
                &registry,
                intent.action_intent_id(),
                &stored,
                ontology(),
                VerifiedPolicyDispositionV2::permit_from_verified_policy(),
            )
            .unwrap();
        assert_eq!(created.kind(), G5DecisionResolutionKindV2::Created);
    }

    let mut reopened = DurableG4StateV2::open_for_test(&path, key, anchor).unwrap();
    let replay = reopened
        .evaluate_verified_g5(
            &registry,
            record.action_intent_id(),
            &stored,
            ontology(),
            VerifiedPolicyDispositionV2::permit_from_verified_policy(),
        )
        .unwrap();
    assert_eq!(replay.kind(), G5DecisionResolutionKindV2::Replay);
}

#[test]
fn g7_prepare_quota_intent_and_wal_commit_atomically_and_replay_after_restart() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("kernel-g4-state-v2.cbor");
    let anchor = TestRollbackProtectedStateAnchorV2::default();
    let key = [0x81; 32];
    let implementation = super::validator_tests::implementation(
        InternalValidatorImplementationKindV2::ProjectionBindingIntegrity,
        0x82,
    );
    let registry =
        VerifiedInternalValidatorRegistryV2::from_build_manifest(vec![implementation.clone()])
            .unwrap();
    let (record, stored) =
        super::validator_tests::evaluation_fixture(vec![implementation.declaration()]);
    let subject = DispatchQuotaSubjectV2::tool_attempt(AttemptKindV2::ToolWrite);
    let connector_genesis = Digest32V2::new([0x84; 32]);
    let connector_signing_key = SigningKey::from_bytes(&[0x89; 32]);
    let connector_registry = SharedVerifiedConnectorRegistryV2::from_verified_state(
        ConnectorRegistryStateV2::from_verified_genesis(
            connector_genesis,
            connector_signing_key.verifying_key().to_bytes(),
            vec![],
            vec![],
        )
        .unwrap(),
    )
    .unwrap();
    let (connector_delta, _) =
        super::dispatch_tests::signed_registry_add(connector_genesis, &connector_signing_key);
    let authority = || {
        VerifiedEffectGateLeaseV2::from_authenticated_ledger(
            Digest32V2::new([2; 32]),
            Digest32V2::new([3; 32]),
            7,
            8,
            false,
            ExecutorIdentityV2::new([13; 32]),
            savana_kernel_protocol::v2::HpkeX25519KeyIdV2::new([0x83; 32]),
            &connector_registry,
            savana_kernel_protocol::v2::UnixMillisV2::new(10_000),
        )
        .unwrap()
    };
    let preparation = {
        let mut store = DurableG4StateV2::open_for_test(&path, key, anchor.clone()).unwrap();
        let material = record.material().clone();
        let intent = store
            .create_or_replay_intent(
                proposal(
                    RequestIdV2::new([1; 16]),
                    DurableRunIdV2::new([4; 32]),
                    DurableTaskIdV2::new([5; 32]),
                    &material,
                ),
                material,
            )
            .unwrap();
        store
            .evaluate_g5(
                &registry,
                intent.action_intent_id(),
                &stored,
                OntologyEvaluationV2::Match,
                G5PolicyDispositionV2::permit_for_test(),
            )
            .unwrap();
        store.set_before_next_commit_hook_for_test({
            let connector_registry = connector_registry.clone();
            let connector_delta = connector_delta.clone();
            move || match connector_registry.try_verify_and_apply_canonical_delta(&connector_delta)
            {
                Err(G4Error::StateConflict) => Ok(()),
                Ok(()) => Err(G4Error::StateConflict),
                Err(error) => Err(error),
            }
        });
        let prepared = store
            .prepare_verified_tool_dispatch(
                intent.action_intent_id(),
                VerifiedQuotaLimitV2::new_for_test(1, 0x85, subject),
                None,
                ResolvedExecutionTicketV2::from_resolved_kernel_ticket(
                    Digest32V2::new([0x86; 32]),
                    record.action_intent_id(),
                    super::tool_execution_semantic_binding_digest_v2(record.binding()).unwrap(),
                )
                .unwrap(),
                authority(),
                Digest32V2::new([0x87; 32]),
            )
            .unwrap();
        assert_eq!(
            connector_registry.current_head_digest().unwrap(),
            connector_genesis
        );
        assert_eq!(
            prepared.core().execution_nonce(),
            prepared.preparation().execution_nonce()
        );
        assert_eq!(
            prepared.core().dispatch_subject_digest(),
            prepared.preparation().dispatch_subject_digest()
        );
        assert_eq!(
            prepared.consumed_ticket_digest(),
            Digest32V2::new([0x86; 32])
        );
        assert_eq!(
            store
                .quota_counter(record.durable_run_id, subject)
                .unwrap()
                .reserved(),
            1
        );
        prepared
    };

    let mut reopened = DurableG4StateV2::open_for_test(&path, key, anchor.clone()).unwrap();
    let replay = reopened
        .prepare_verified_tool_dispatch(
            record.action_intent_id(),
            VerifiedQuotaLimitV2::new_for_test(1, 0x85, subject),
            None,
            ResolvedExecutionTicketV2::from_resolved_kernel_ticket(
                Digest32V2::new([0x86; 32]),
                record.action_intent_id(),
                super::tool_execution_semantic_binding_digest_v2(record.binding()).unwrap(),
            )
            .unwrap(),
            authority(),
            Digest32V2::new([0x87; 32]),
        )
        .unwrap();
    assert_eq!(
        replay.preparation().execution_nonce(),
        preparation.preparation().execution_nonce()
    );
    assert_eq!(
        reopened
            .quota_counter(record.durable_run_id, subject)
            .unwrap()
            .reserved(),
        1
    );
    reopened
        .reconcile_tool_dispatch(
            VerifiedExecutorDispositionV2::effect_started_from_preparation_for_test(
                preparation.preparation(),
                0x88,
            ),
        )
        .unwrap();
    assert_eq!(
        reopened
            .quota_counter(record.durable_run_id, subject)
            .unwrap()
            .spent(),
        1
    );
    drop(reopened);

    let reopened = DurableG4StateV2::open_for_test(&path, key, anchor).unwrap();
    assert_eq!(
        reopened
            .quota_counter(record.durable_run_id, subject)
            .unwrap()
            .spent(),
        1
    );
}

#[test]
fn g7_approval_dispatch_advances_through_authorized_approval_atomically() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("kernel-g4-state-v2.cbor");
    let anchor = TestRollbackProtectedStateAnchorV2::default();
    let key = [0x91; 32];
    let implementation = super::validator_tests::implementation(
        InternalValidatorImplementationKindV2::ProjectionBindingIntegrity,
        0x92,
    );
    let registry =
        VerifiedInternalValidatorRegistryV2::from_build_manifest(vec![implementation.clone()])
            .unwrap();
    let (record, stored) =
        super::validator_tests::evaluation_fixture(vec![implementation.declaration()]);
    let subject = DispatchQuotaSubjectV2::tool_attempt(AttemptKindV2::ToolWrite);
    let semantic_binding_digest =
        tool_execution_semantic_binding_digest_v2(record.binding()).unwrap();
    let mut store = DurableG4StateV2::open_for_test(&path, key, anchor).unwrap();
    let material = record.material().clone();
    let intent = store
        .create_or_replay_intent(
            proposal(
                RequestIdV2::new([0x93; 16]),
                DurableRunIdV2::new([4; 32]),
                DurableTaskIdV2::new([5; 32]),
                &material,
            ),
            material,
        )
        .unwrap();
    store
        .evaluate_verified_g5(
            &registry,
            intent.action_intent_id(),
            &stored,
            matching_ontology(),
            VerifiedPolicyDispositionV2::require_approval_from_verified_policy(),
        )
        .unwrap();

    let prepared = store
        .prepare_verified_tool_dispatch(
            intent.action_intent_id(),
            VerifiedQuotaLimitV2::new_for_test(1, 0x94, subject),
            Some(
                VerifiedToolApprovalSettlementV2::from_consumed_exact_settlement(
                    Digest32V2::new([0x95; 32]),
                    intent.action_intent_id(),
                    tool_approval_binding_digest_v2(
                        intent.action_intent_id(),
                        semantic_binding_digest,
                        Digest32V2::new([3; 32]),
                    )
                    .unwrap(),
                    Digest32V2::new([3; 32]),
                )
                .unwrap(),
            ),
            ResolvedExecutionTicketV2::from_resolved_kernel_ticket(
                Digest32V2::new([0x96; 32]),
                intent.action_intent_id(),
                semantic_binding_digest,
            )
            .unwrap(),
            VerifiedEffectGateLeaseV2::from_authenticated_ledger(
                Digest32V2::new([2; 32]),
                Digest32V2::new([3; 32]),
                7,
                8,
                false,
                ExecutorIdentityV2::new([13; 32]),
                savana_kernel_protocol::v2::HpkeX25519KeyIdV2::new([0x97; 32]),
                &shared_connector_registry(0x98),
                savana_kernel_protocol::v2::UnixMillisV2::new(10_000),
            )
            .unwrap(),
            Digest32V2::new([0x99; 32]),
        )
        .unwrap();

    assert_eq!(
        prepared.preparation().kind(),
        super::DispatchPreparationKindV2::Created
    );
    let replay_material = record.material().clone();
    let replay = store
        .create_or_replay_intent(
            proposal(
                RequestIdV2::new([0x93; 16]),
                DurableRunIdV2::new([4; 32]),
                DurableTaskIdV2::new([5; 32]),
                &replay_material,
            ),
            replay_material,
        )
        .unwrap();
    assert_eq!(
        replay.current_state(),
        ActionIntentStateV2::DispatchPrepared
    );
}

#[test]
fn g7_final_release_wal_and_quota_survive_restart_without_aliasing_tool_attempts() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("kernel-g4-state-v2.cbor");
    let anchor = TestRollbackProtectedStateAnchorV2::default();
    let key = [0x91; 32];
    let binding = final_release_binding_for_test(0x92, [13; 32]);
    let release = VerifiedFinalReleaseDispatchV2::new_for_test(
        Digest32V2::new([2; 32]),
        Digest32V2::new([3; 32]),
        binding,
    );
    let subject = DispatchQuotaSubjectV2::final_release(binding.release_quota_subject_digest());
    let connector_genesis = Digest32V2::new([0x94; 32]);
    let connector_signing_key = SigningKey::from_bytes(&[0x9d; 32]);
    let connector_registry = SharedVerifiedConnectorRegistryV2::from_verified_state(
        ConnectorRegistryStateV2::from_verified_genesis(
            connector_genesis,
            connector_signing_key.verifying_key().to_bytes(),
            vec![],
            vec![],
        )
        .unwrap(),
    )
    .unwrap();
    let (connector_delta, _) =
        super::dispatch_tests::signed_registry_add(connector_genesis, &connector_signing_key);
    let authority = || {
        VerifiedEffectGateAuthorityV2::from_authenticated_unfenced_ledger(
            Digest32V2::new([2; 32]),
            Digest32V2::new([3; 32]),
            7,
            8,
            false,
            ExecutorIdentityV2::new([13; 32]),
            savana_kernel_protocol::v2::HpkeX25519KeyIdV2::new([0x93; 32]),
            &connector_registry,
            savana_kernel_protocol::v2::UnixMillisV2::new(10_000),
        )
        .unwrap()
    };
    let preparation = {
        let mut store = DurableG4StateV2::open_for_test(&path, key, anchor.clone()).unwrap();
        store.set_before_next_commit_hook_for_test({
            let connector_registry = connector_registry.clone();
            let connector_delta = connector_delta.clone();
            move || match connector_registry.try_verify_and_apply_canonical_delta(&connector_delta)
            {
                Err(G4Error::StateConflict) => Ok(()),
                Ok(()) => Err(G4Error::StateConflict),
                Err(error) => Err(error),
            }
        });
        let prepared = store
            .prepare_final_release_dispatch(
                &release,
                VerifiedQuotaLimitV2::new_for_test(1, 0x95, subject),
                VerifiedFinalReleaseApprovalBindingV2::new_for_test(&release, 0x96),
                VerifiedFinalReleaseTicketV2::new_for_test(&release, 0x97),
                authority(),
                Digest32V2::new([0x98; 32]),
            )
            .unwrap();
        assert_eq!(
            connector_registry.current_head_digest().unwrap(),
            connector_genesis
        );
        assert_eq!(
            store
                .quota_counter(release.durable_run_id(), subject)
                .unwrap()
                .reserved(),
            1
        );
        prepared
    };

    let mut reopened = DurableG4StateV2::open_for_test(&path, key, anchor.clone()).unwrap();
    let replay = reopened
        .prepare_final_release_dispatch(
            &release,
            VerifiedQuotaLimitV2::new_for_test(1, 0x95, subject),
            VerifiedFinalReleaseApprovalBindingV2::new_for_test(&release, 0x96),
            VerifiedFinalReleaseTicketV2::new_for_test(&release, 0x97),
            authority(),
            Digest32V2::new([0x98; 32]),
        )
        .unwrap();
    assert_eq!(replay.execution_nonce(), preparation.execution_nonce());

    assert_eq!(
        reopened
            .prepare_final_release_dispatch(
                &release,
                VerifiedQuotaLimitV2::new_for_test(1, 0x95, subject),
                // Replay is exact only when it carries the same consumed
                // settlement. A second settlement cannot alias the durable
                // release identifier and inherit the first preparation.
                VerifiedFinalReleaseApprovalBindingV2::new_for_test(&release, 0x9c),
                VerifiedFinalReleaseTicketV2::new_for_test(&release, 0x97),
                authority(),
                Digest32V2::new([0x98; 32]),
            )
            .unwrap_err(),
        G4Error::StateConflict
    );

    let other_binding = FinalReleaseSemanticBindingV2::from_nonzero_components(
        DurableReleaseIdV2::new([7; 32]),
        Digest32V2::new([0xa0; 32]),
        Digest32V2::new([0xa1; 32]),
        Digest32V2::new([0xa2; 32]),
        Digest32V2::new([0xa3; 32]),
        Digest32V2::new([0xa4; 32]),
        Digest32V2::new([0xa5; 32]),
        Digest32V2::new([0xa6; 32]),
        Digest32V2::new([0xa7; 32]),
        Digest32V2::new([13; 32]),
        Digest32V2::new([0xa8; 32]),
    )
    .unwrap();
    let other_release = VerifiedFinalReleaseDispatchV2::from_verified_release(
        Digest32V2::new([2; 32]),
        Digest32V2::new([3; 32]),
        DurableTaskIdV2::new([4; 32]),
        DurableRunIdV2::new([5; 32]),
        DurableReleaseIdV2::new([7; 32]),
        other_binding,
    )
    .unwrap();
    let other_subject =
        DispatchQuotaSubjectV2::final_release(other_binding.release_quota_subject_digest());
    assert_eq!(
        reopened
            .prepare_final_release_dispatch(
                &other_release,
                VerifiedQuotaLimitV2::new_for_test(1, 0x95, other_subject),
                // Reusing the same approval settlement digest for a different
                // exact release must be rejected even after a restart.
                VerifiedFinalReleaseApprovalBindingV2::new_for_test(&other_release, 0x96),
                VerifiedFinalReleaseTicketV2::new_for_test(&other_release, 0x9a),
                authority(),
                Digest32V2::new([0x9b; 32]),
            )
            .unwrap_err(),
        G4Error::StateConflict
    );
    reopened
        .reconcile_final_release_dispatch(
            VerifiedExecutorDispositionV2::effect_started_from_preparation_for_test(
                preparation,
                0x99,
            ),
        )
        .unwrap();
    assert_eq!(
        reopened
            .quota_counter(release.durable_run_id(), subject)
            .unwrap()
            .spent(),
        1
    );
    assert_eq!(
        reopened
            .quota_counter(
                release.durable_run_id(),
                DispatchQuotaSubjectV2::tool_attempt(AttemptKindV2::ToolWrite),
            )
            .unwrap_err(),
        G4Error::QuotaCounterNotFound
    );
    drop(reopened);

    let reopened = DurableG4StateV2::open_for_test(&path, key, anchor).unwrap();
    assert_eq!(
        reopened
            .quota_counter(release.durable_run_id(), subject)
            .unwrap()
            .spent(),
        1
    );
}

fn limit(value: u32, subject: DispatchQuotaSubjectV2) -> VerifiedQuotaLimitV2 {
    VerifiedQuotaLimitV2::new_for_test(value, 0x79, subject)
}

fn proposal(
    request_id: RequestIdV2,
    run: DurableRunIdV2,
    task: DurableTaskIdV2,
    material: &VerifiedActionIntentMaterialV2,
) -> VerifiedToolProposalV2 {
    VerifiedToolProposalV2::from_authenticated_decoded_request(
        request_id,
        &[0xa1, 0x01],
        Digest32V2::new([2; 32]),
        Digest32V2::new([3; 32]),
        run,
        task,
        material,
    )
    .unwrap()
}

fn material(seed: u8) -> VerifiedActionIntentMaterialV2 {
    VerifiedActionIntentMaterialV2::new_for_test(
        ToolExecutionSemanticBindingV2::from_verified_authorization(
            PlanRevisionDigestV2::new([6; 32]),
            InternalStepIdV2::new([6; 32]),
            Digest32V2::new([seed; 32]),
            Digest32V2::new([7; 32]),
            Digest32V2::new([8; 32]),
            Digest32V2::new([9; 32]),
            Digest32V2::new([10; 32]),
            Digest32V2::new([11; 32]),
            Digest32V2::new([12; 32]),
            ExecutorIdentityV2::new([13; 32]),
            AttemptKindV2::ToolWrite,
        )
        .unwrap(),
        vec![StableActionArgumentBindingV2::new_for_test(
            ArgumentNameV2::new("message").unwrap(),
            InternalSlotDigestV2::new([0x31; 32]),
            ValueInternalIdV2::new([0x32; 32]),
            Digest32V2::new([0x33; 32]),
            Digest32V2::new([0x34; 32]),
        )],
        seed,
    )
}

fn matching_ontology() -> VerifiedOntologyEvaluationV2 {
    VerifiedOntologyEvaluationV2::evaluate(
        &OntologyExprV2::eq(
            OntologyOperandV2::literal(OntologyScalarV2::boolean(true)),
            OntologyOperandV2::literal(OntologyScalarV2::boolean(true)),
        ),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        RoleIdV2::new(1),
        ToolClassIdV2::new(1),
        AttemptKindV2::ToolWrite,
        PrincipalIdV2::new([0x73; 32]),
        DurableTaskIdV2::new([5; 32]),
    )
    .unwrap()
}
