use ed25519_dalek::{Signer as _, SigningKey};
use savana_kernel_protocol::v2::{
    Digest32V2, Ed25519KeyIdV2, ExecutorIdentityV2, HpkeX25519KeyIdV2, ProjectionIdV2, RoleIdV2,
    UnixMillisV2, VersionV2,
};
use sha2::{Digest as _, Sha256};

use super::dispatch::{
    final_release_binding_for_test, KernelDispatchJournalV2, SignedExecutorDispositionReceiptV2,
    VerifiedApprovalSettlementBindingV2, VerifiedEffectGateAuthorityV2, VerifiedExecutionTicketV2,
    VerifiedFinalReleaseApprovalBindingV2, VerifiedFinalReleaseDispatchV2,
    VerifiedFinalReleaseTicketV2,
};
use super::{
    ConnectorDescriptorV2, ConnectorRegistryStateV2, DispatchPreparationKindV2,
    DispatchQuotaSubjectV2, DispatchSubjectV2, EffectSetV2, G4Error, G5DecisionBranchV2,
    InternalValidatorDeclarationV2, KernelDispatchStateV2, SharedVerifiedConnectorRegistryV2,
    UnsignedToolDescriptorV2,
};

fn authority(manifest: Digest32V2, fenced: bool) -> Result<VerifiedEffectGateAuthorityV2, G4Error> {
    let registry = shared_registry(Digest32V2::new([15; 32]), [0; 32]);
    authority_for_registry(manifest, fenced, &registry)
}

fn authority_for_registry(
    manifest: Digest32V2,
    fenced: bool,
    registry: &SharedVerifiedConnectorRegistryV2,
) -> Result<VerifiedEffectGateAuthorityV2, G4Error> {
    VerifiedEffectGateAuthorityV2::from_authenticated_unfenced_ledger(
        Digest32V2::new([2; 32]),
        manifest,
        7,
        8,
        fenced,
        ExecutorIdentityV2::new([13; 32]),
        HpkeX25519KeyIdV2::new([14; 32]),
        registry,
        UnixMillisV2::new(1_000),
    )
}

fn shared_registry(
    genesis: Digest32V2,
    authority_public_key: [u8; 32],
) -> SharedVerifiedConnectorRegistryV2 {
    SharedVerifiedConnectorRegistryV2::from_verified_state(
        ConnectorRegistryStateV2::from_verified_genesis(
            genesis,
            authority_public_key,
            vec![],
            vec![],
        )
        .unwrap(),
    )
    .unwrap()
}

pub(super) fn signed_registry_add(
    genesis: Digest32V2,
    authority: &SigningKey,
) -> (Vec<u8>, Digest32V2) {
    let tool = UnsignedToolDescriptorV2::new_for_test(
        VersionV2::new(1, 0, 0),
        vec![RoleIdV2::new(1)],
        Vec::<InternalValidatorDeclarationV2>::new(),
        ProjectionIdV2::new(1),
        Digest32V2::new([0x51; 32]),
    )
    .unwrap();
    let mut identity = minicbor::Encoder::new(Vec::new());
    identity
        .array(2)
        .unwrap()
        .str("live-head")
        .unwrap()
        .array(2)
        .unwrap()
        .u16(1)
        .unwrap()
        .bytes(&[0x52; 32])
        .unwrap();
    let mut id_hasher = Sha256::new();
    id_hasher.update(b"savana.connector.user.v2\0");
    id_hasher.update(identity.into_writer());
    let connector_id = Digest32V2::new(id_hasher.finalize().into());
    let mut descriptor = minicbor::Encoder::new(Vec::new());
    descriptor
        .array(7)
        .unwrap()
        .bytes(connector_id.as_bytes())
        .unwrap()
        .str("live-head")
        .unwrap()
        .u16(2)
        .unwrap()
        .array(2)
        .unwrap()
        .u16(1)
        .unwrap()
        .bytes(&[0x52; 32])
        .unwrap()
        .array(1)
        .unwrap();
    descriptor
        .writer_mut()
        .extend_from_slice(&minicbor::to_vec(&tool).unwrap());
    descriptor
        .u16(EffectSetV2::SEND.bits())
        .unwrap()
        .u64(1)
        .unwrap();
    let descriptor =
        ConnectorDescriptorV2::from_canonical_bytes(&descriptor.into_writer(), &[]).unwrap();

    let mut payload = minicbor::Encoder::new(Vec::new());
    payload
        .array(6)
        .unwrap()
        .u16(1)
        .unwrap()
        .u64(1)
        .unwrap()
        .bytes(genesis.as_bytes())
        .unwrap()
        .array(2)
        .unwrap()
        .u16(1)
        .unwrap();
    payload
        .writer_mut()
        .extend_from_slice(descriptor.canonical_bytes());
    payload.bytes(&[0x53; 32]).unwrap().u64(1).unwrap();
    let payload = payload.into_writer();
    let mut payload_hasher = Sha256::new();
    payload_hasher.update(b"savana.connector-registry.delta.v2.payload\0");
    payload_hasher.update(&payload);
    let payload_digest: [u8; 32] = payload_hasher.finalize().into();
    let mut signature_hasher = Sha256::new();
    signature_hasher.update(b"savana.connector-registry.delta.v2.signature\0");
    signature_hasher.update(payload_digest);
    let signature_digest: [u8; 32] = signature_hasher.finalize().into();
    let signature = authority.sign(&signature_digest).to_bytes();
    let mut delta = minicbor::Encoder::new(Vec::new());
    delta.array(3).unwrap();
    delta.writer_mut().extend_from_slice(&payload);
    delta
        .bytes(&payload_digest)
        .unwrap()
        .bytes(&signature)
        .unwrap();
    (delta.into_writer(), connector_id)
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
fn g7_refuses_a_stale_registry_lease_and_commits_the_live_head() {
    let (record, _) = super::validator_tests::evaluation_fixture(Vec::new());
    let signing_key = SigningKey::from_bytes(&[0x54; 32]);
    let genesis = Digest32V2::new([15; 32]);
    let registry = shared_registry(genesis, signing_key.verifying_key().to_bytes());
    let stale =
        authority_for_registry(record.active_state_manifest_digest, false, &registry).unwrap();
    let (delta, _) = signed_registry_add(genesis, &signing_key);
    registry.verify_and_apply_canonical_delta(&delta).unwrap();

    let mut journal = KernelDispatchJournalV2::default();
    assert_eq!(
        journal
            .prepare_tool_or_replay(
                &record,
                G5DecisionBranchV2::Permit,
                None,
                VerifiedExecutionTicketV2::new_for_test(&record, 0x55),
                stale,
                Digest32V2::new([0x56; 32]),
            )
            .unwrap_err(),
        G4Error::StateConflict
    );
    assert!(journal.entries.is_empty());

    journal
        .prepare_tool_or_replay(
            &record,
            G5DecisionBranchV2::Permit,
            None,
            VerifiedExecutionTicketV2::new_for_test(&record, 0x55),
            authority_for_registry(record.active_state_manifest_digest, false, &registry).unwrap(),
            Digest32V2::new([0x56; 32]),
        )
        .unwrap();
    assert_eq!(
        journal.entries[0].core.executor_connector_registry_digest(),
        registry.current_head_digest().unwrap()
    );

    let release_signing_key = SigningKey::from_bytes(&[0x57; 32]);
    let release_genesis = Digest32V2::new([0x58; 32]);
    let release_registry = shared_registry(
        release_genesis,
        release_signing_key.verifying_key().to_bytes(),
    );
    let binding = final_release_binding_for_test(0x59, [13; 32]);
    let release = VerifiedFinalReleaseDispatchV2::new_for_test(
        Digest32V2::new([2; 32]),
        Digest32V2::new([3; 32]),
        binding,
    );
    let stale_release =
        authority_for_registry(Digest32V2::new([3; 32]), false, &release_registry).unwrap();
    let (release_delta, _) = signed_registry_add(release_genesis, &release_signing_key);
    release_registry
        .verify_and_apply_canonical_delta(&release_delta)
        .unwrap();
    let mut release_journal = KernelDispatchJournalV2::default();
    assert_eq!(
        release_journal
            .prepare_final_release_or_replay(
                &release,
                VerifiedFinalReleaseApprovalBindingV2::new_for_test(&release, 0x5a),
                VerifiedFinalReleaseTicketV2::new_for_test(&release, 0x5b),
                stale_release,
                Digest32V2::new([0x5c; 32]),
            )
            .unwrap_err(),
        G4Error::StateConflict
    );
    assert!(release_journal.entries.is_empty());
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
