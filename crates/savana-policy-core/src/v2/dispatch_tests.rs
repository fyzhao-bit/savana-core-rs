use savana_kernel_protocol::v2::{
    Digest32V2, Ed25519KeyIdV2, ExecutorIdentityV2, HpkeX25519KeyIdV2, UnixMillisV2,
};

use super::dispatch::{
    final_release_binding_for_test, KernelDispatchJournalV2, SignedExecutorDispositionReceiptV2,
    VerifiedApprovalSettlementBindingV2, VerifiedEffectGateAuthorityV2, VerifiedExecutionTicketV2,
    VerifiedFinalReleaseApprovalBindingV2, VerifiedFinalReleaseDispatchV2,
    VerifiedFinalReleaseTicketV2,
};
use super::{
    DispatchPreparationKindV2, DispatchQuotaSubjectV2, DispatchSubjectV2, G4Error,
    G5DecisionBranchV2, KernelDispatchStateV2,
};

fn authority(manifest: Digest32V2, fenced: bool) -> Result<VerifiedEffectGateAuthorityV2, G4Error> {
    VerifiedEffectGateAuthorityV2::from_authenticated_unfenced_ledger(
        Digest32V2::new([2; 32]),
        manifest,
        7,
        8,
        fenced,
        ExecutorIdentityV2::new([13; 32]),
        HpkeX25519KeyIdV2::new([14; 32]),
        Digest32V2::new([15; 32]),
        UnixMillisV2::new(1_000),
    )
}

#[test]
fn g7_preparation_creates_one_nonce_and_exact_replay() {
    let (record, _) = super::validator_tests::evaluation_fixture(Vec::new());
    let mut journal = KernelDispatchJournalV2::default();
    let created = journal
        .prepare_tool_or_replay(
            &record,
            G5DecisionBranchV2::Permit,
            None,
            VerifiedExecutionTicketV2::new_for_test(&record, 30),
            authority(record.active_state_manifest_digest, false).unwrap(),
            Digest32V2::new([16; 32]),
        )
        .unwrap();
    assert_eq!(created.kind(), DispatchPreparationKindV2::Created);
    assert_eq!(created.state(), KernelDispatchStateV2::Prepared);

    let replay = journal
        .prepare_tool_or_replay(
            &record,
            G5DecisionBranchV2::Permit,
            None,
            VerifiedExecutionTicketV2::new_for_test(&record, 30),
            authority(record.active_state_manifest_digest, false).unwrap(),
            Digest32V2::new([16; 32]),
        )
        .unwrap();
    assert_eq!(replay.kind(), DispatchPreparationKindV2::Replay);
    assert_eq!(replay.execution_nonce(), created.execution_nonce());
    assert_eq!(journal.entries.len(), 1);
}

#[test]
fn recovery_projection_exposes_only_typed_identity_state_and_subject_kind() {
    let (record, _) = super::validator_tests::evaluation_fixture(Vec::new());
    let mut journal = KernelDispatchJournalV2::default();
    let created = journal
        .prepare_tool_or_replay(
            &record,
            G5DecisionBranchV2::Permit,
            None,
            VerifiedExecutionTicketV2::new_for_test(&record, 0x34),
            authority(record.active_state_manifest_digest, false).unwrap(),
            Digest32V2::new([0x35; 32]),
        )
        .unwrap();

    let projection = journal.recovery_projection().unwrap();

    assert_eq!(projection.len(), 1);
    assert_eq!(projection[0].execution_nonce(), created.execution_nonce());
    assert_eq!(projection[0].durable_task_id(), record.durable_task_id);
    assert_eq!(projection[0].durable_run_id(), record.durable_run_id);
    assert_eq!(
        projection[0].dispatch_subject_digest(),
        created.dispatch_subject_digest()
    );
    assert_eq!(projection[0].state(), KernelDispatchStateV2::Prepared);
    assert_eq!(
        projection[0].subject_kind(),
        super::DispatchRecoverySubjectKindV2::ToolExecution
    );
}

#[test]
fn g7_requires_exact_approval_and_unfenced_authority() {
    let (record, _) = super::validator_tests::evaluation_fixture(Vec::new());
    let mut journal = KernelDispatchJournalV2::default();
    assert_eq!(
        journal
            .prepare_tool_or_replay(
                &record,
                G5DecisionBranchV2::RequireApproval,
                None,
                VerifiedExecutionTicketV2::new_for_test(&record, 31),
                authority(record.active_state_manifest_digest, false).unwrap(),
                Digest32V2::new([17; 32]),
            )
            .unwrap_err(),
        G4Error::StateConflict
    );
    assert!(authority(record.active_state_manifest_digest, true).is_err());

    journal
        .prepare_tool_or_replay(
            &record,
            G5DecisionBranchV2::RequireApproval,
            Some(VerifiedApprovalSettlementBindingV2::new_for_test(
                &record, 18,
            )),
            VerifiedExecutionTicketV2::new_for_test(&record, 32),
            authority(record.active_state_manifest_digest, false).unwrap(),
            Digest32V2::new([19; 32]),
        )
        .unwrap();
}

#[test]
fn g7_reconciliation_accepts_only_entry_bound_typed_proof() {
    let (record, _) = super::validator_tests::evaluation_fixture(Vec::new());
    let mut journal = KernelDispatchJournalV2::default();
    journal
        .prepare_tool_or_replay(
            &record,
            G5DecisionBranchV2::Permit,
            None,
            VerifiedExecutionTicketV2::new_for_test(&record, 33),
            authority(record.active_state_manifest_digest, false).unwrap(),
            Digest32V2::new([20; 32]),
        )
        .unwrap();
    let signing = ed25519_dalek::SigningKey::from_bytes(&[0x71; 32]);
    let key_id = Ed25519KeyIdV2::new([0x72; 32]);
    let receipt = SignedExecutorDispositionReceiptV2::effect_started_for_test(
        &journal.entries[0],
        key_id,
        &signing,
        21,
        UnixMillisV2::new(900),
    );
    let proof = receipt
        .verify_for_entry(
            &journal.entries[0],
            key_id,
            signing.verifying_key().to_bytes(),
            UnixMillisV2::new(950),
        )
        .unwrap();
    assert_eq!(
        journal.reconcile(proof).unwrap(),
        KernelDispatchStateV2::EffectStarted
    );
}

#[test]
fn g7_final_release_uses_a_distinct_subject_and_quota_branch() {
    let binding = final_release_binding_for_test(0x81, [13; 32]);
    let release = VerifiedFinalReleaseDispatchV2::new_for_test(
        Digest32V2::new([2; 32]),
        Digest32V2::new([3; 32]),
        binding,
    );
    let approval = VerifiedFinalReleaseApprovalBindingV2::new_for_test(&release, 0x82);
    let ticket = VerifiedFinalReleaseTicketV2::new_for_test(&release, 0x83);
    let mut journal = KernelDispatchJournalV2::default();
    let created = journal
        .prepare_final_release_or_replay(
            &release,
            approval,
            ticket,
            authority(Digest32V2::new([3; 32]), false).unwrap(),
            Digest32V2::new([0x84; 32]),
        )
        .unwrap();
    assert_eq!(created.kind(), DispatchPreparationKindV2::Created);
    assert!(matches!(
        journal.entries[0].core.subject,
        DispatchSubjectV2::FinalRelease { .. }
    ));
    assert_eq!(
        journal.entries[0].quota_subject,
        DispatchQuotaSubjectV2::final_release(binding.release_quota_subject_digest())
    );

    let replay = journal
        .prepare_final_release_or_replay(
            &release,
            VerifiedFinalReleaseApprovalBindingV2::new_for_test(&release, 0x82),
            VerifiedFinalReleaseTicketV2::new_for_test(&release, 0x83),
            authority(Digest32V2::new([3; 32]), false).unwrap(),
            Digest32V2::new([0x84; 32]),
        )
        .unwrap();
    assert_eq!(replay.kind(), DispatchPreparationKindV2::Replay);
    assert_eq!(replay.execution_nonce(), created.execution_nonce());
}
