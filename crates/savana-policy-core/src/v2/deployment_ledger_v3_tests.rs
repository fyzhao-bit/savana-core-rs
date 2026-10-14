use super::super::deployment_v3_test_support::{enrollment_for, record, record_for};
use super::super::deployment_v3_test_support::{sign_transaction, transaction_material};
use super::*;

#[test]
fn external_transaction_authorization_binds_every_v3_pre_state_field() {
    let state = genesis();
    let ledger = verified(&state, TpmStateHeadV3::GENESIS);
    let tx = sign_transaction(transaction_material(&state));
    tx.validate_authenticated_pre_state_v3(&ledger, d(50), d(51), d(52), d(53))
        .unwrap();
    for slot in 0..4 {
        let mut roots = [d(50), d(51), d(52), d(53)];
        roots[slot] = d(199);
        assert!(tx
            .validate_authenticated_pre_state_v3(&ledger, roots[0], roots[1], roots[2], roots[3])
            .is_err());
    }
    // Validly signed alternate ledger is still not the state externally approved.
    for slot in 0..6 {
        let mut m = state.material().clone();
        match slot {
            0 => m.active_manifest = d(199),
            1 => m.identity_profile = d(199),
            2 => m.fence_epoch += 1,
            3 => m.written_at_ms += 1,
            4 => m.bootstrap_tcb_lock = d(199),
            5 => {
                m.highest_ever =
                    HighestEverV2::new([HighWaterEntryV2::new(5, d(199), 3).unwrap(); 29]).unwrap()
            }
            _ => unreachable!(),
        }
        let other = verified(
            &DeploymentLedgerStateV3::new(m).unwrap(),
            TpmStateHeadV3::GENESIS,
        );
        assert!(tx
            .validate_authenticated_pre_state_v3(&other, d(50), d(51), d(52), d(53))
            .is_err());
    }
}

#[test]
fn v3_preparation_rejects_time_platform_pending_work_and_terminal_tag_only() {
    let state = genesis();
    let ledger = verified(&state, TpmStateHeadV3::GENESIS);
    let tx = sign_transaction(transaction_material(&state));
    let platform = &tx.intent().material().target_platform;
    let records = [ledger.record().clone()];
    let history =
        DeploymentLedgerHistoryV3::verify(&records, state.payload_digest(), records[0].head())
            .unwrap();
    history
        .validate_new_transaction(&tx, platform, 150001, None)
        .unwrap();
    for now in [0, 150000, 160000, u64::MAX] {
        assert!(history
            .validate_new_transaction(&tx, platform, now, None)
            .is_err());
    }
    let other_platform = super::super::PlatformLockV2::new(
        super::super::ClosedTargetOsV2::Linux,
        super::super::ClosedTargetArchitectureV2::Aarch64,
        d(11),
        d(12),
        d(13),
        d(14),
        d(15),
    )
    .unwrap();
    assert!(history
        .validate_new_transaction(&tx, &other_platform, 150001, None)
        .is_err());
    let auxiliary = record(
        b"pending",
        DeploymentRecordScopeV3::new(Domain::CommitAttestation, 1, [0; 32]).unwrap(),
        records[0].head(),
    );
    let mut pending = records.to_vec();
    pending.push(auxiliary.clone());
    let history =
        DeploymentLedgerHistoryV3::verify(&pending, state.payload_digest(), auxiliary.head())
            .unwrap();
    assert!(history
        .validate_new_transaction(&tx, platform, 150001, None)
        .is_err());
}

fn d(n: u8) -> Digest32V2 {
    Digest32V2::new([n; 32])
}
fn genesis() -> DeploymentLedgerStateV3 {
    DeploymentLedgerStateV3::new(DeploymentLedgerMaterialV3 {
        installation: d(1),
        epoch: 1,
        generation: 1,
        written_at_ms: 150000,
        phase: Phase::Idle,
        transaction: None,
        effects_fenced: false,
        fence_epoch: 1,
        active_manifest: d(2),
        active_activation: ActiveActivationV2::Normal,
        identity_profile: d(3),
        bootstrap_tcb_lock: d(4),
        highest_ever: HighestEverV2::new(std::array::from_fn(|i| {
            HighWaterEntryV2::new(4, d(i as u8 + 20), 2).unwrap()
        }))
        .unwrap(),
        grant: Grant::None,
        rollback_grant_id: None,
        rollback_origin: None,
        transaction_head: None,
        previous_payload: d(0),
    })
    .unwrap()
}
fn step(current: &DeploymentLedgerStateV3, to: Phase) -> DeploymentLedgerStateV3 {
    let mut m = current.material().clone();
    m.generation += 1;
    m.written_at_ms += 1;
    m.previous_payload = current.payload_digest();
    m.phase = to;
    if to == Phase::Prepared {
        m.transaction = Some(Nonce32V2::new([m.generation as u8; 32]));
        m.rollback_grant_id = Some(d(m.generation as u8 + 180));
    }
    if to == Phase::Idle {
        m.transaction = None;
        m.rollback_grant_id = None;
    }
    m.transaction_head = m.transaction.map(|_| d(m.generation as u8 + 100));
    m.effects_fenced = !matches!(
        to,
        Phase::Idle | Phase::Committed | Phase::RolledBack | Phase::Prepared | Phase::Aborted
    );
    if matches!(to, Phase::Prepared | Phase::Aborted) {
        m.effects_fenced = current.material.effects_fenced;
    }
    if matches!(
        to,
        Phase::Armed
            | Phase::RollbackPrepared
            | Phase::Committed
            | Phase::RolledBack
            | Phase::FailedSafe
    ) {
        m.fence_epoch += 1;
    }
    m.grant = match to {
        Phase::Idle => Grant::None,
        Phase::Prepared | Phase::Armed | Phase::Quiesced | Phase::Installed | Phase::Verified => {
            Grant::Prearmed
        }
        Phase::RollbackPrepared | Phase::RollbackInstalled | Phase::RollbackVerified => {
            Grant::Consuming
        }
        Phase::RolledBack => Grant::Consumed,
        _ => Grant::Burned,
    };
    m.rollback_origin = match to {
        Phase::RollbackPrepared => Some(match current.material.phase {
            Phase::Armed => Origin::Armed,
            Phase::Quiesced => Origin::Quiesced,
            Phase::Installed => Origin::Installed,
            Phase::Verified => Origin::Verified,
            _ => panic!("invalid test predecessor"),
        }),
        Phase::RollbackInstalled
        | Phase::RollbackVerified
        | Phase::RolledBack
        | Phase::FailedSafe => current.material.rollback_origin,
        _ => None,
    };
    if to == Phase::Committed {
        m.active_manifest = d(m.generation as u8 + 150);
        m.active_activation = ActiveActivationV2::Normal;
    }
    if to == Phase::RolledBack {
        m.active_manifest = d(200);
        m.active_activation = ActiveActivationV2::ConsumedRollback {
            failed_transaction_id: m.transaction.unwrap(),
            rollback_grant_id: m.rollback_grant_id.unwrap(),
        };
    }
    DeploymentLedgerStateV3::new(m).unwrap()
}
fn verified(
    s: &DeploymentLedgerStateV3,
    previous: TpmStateHeadV3,
) -> VerifiedDeploymentLedgerRecordV3 {
    VerifiedDeploymentLedgerRecordV3::verify(record(s.canonical_bytes(), s.scope(), previous))
        .unwrap()
}
fn prefix(to: Phase) -> DeploymentLedgerStateV3 {
    let mut s = genesis();
    for p in [
        Phase::Prepared,
        Phase::Armed,
        Phase::Quiesced,
        Phase::Installed,
        Phase::Verified,
        Phase::Committed,
    ] {
        let n = step(&s, p);
        s.validate_successor(&n).unwrap();
        s = n;
        if p == to {
            return s;
        }
    }
    panic!("unknown prefix")
}

#[test]
fn complete_normal_abort_rollback_and_fail_safe_state_paths() {
    let g = genesis();
    g.validate_fresh_genesis().unwrap();
    let mut s = g;
    for p in [
        Phase::Prepared,
        Phase::Aborted,
        Phase::Idle,
        Phase::Prepared,
        Phase::Armed,
        Phase::Quiesced,
        Phase::Installed,
        Phase::Verified,
        Phase::Committed,
        Phase::Prepared,
    ] {
        let n = step(&s, p);
        s.validate_successor(&n).unwrap();
        s = n;
    }
    for source in [
        Phase::Armed,
        Phase::Quiesced,
        Phase::Installed,
        Phase::Verified,
    ] {
        let mut s = prefix(source);
        let failed = step(&s, Phase::FailedSafe);
        s.validate_successor(&failed).unwrap();
        for p in [
            Phase::RollbackPrepared,
            Phase::RollbackInstalled,
            Phase::RollbackVerified,
            Phase::RolledBack,
            Phase::Prepared,
        ] {
            let n = step(&s, p);
            s.validate_successor(&n).unwrap();
            s = n;
            if matches!(
                p,
                Phase::RollbackPrepared | Phase::RollbackInstalled | Phase::RollbackVerified
            ) {
                let failed = step(&s, Phase::FailedSafe);
                s.validate_successor(&failed).unwrap();
            }
        }
    }
}

#[test]
fn canonical_codec_is_bounded_and_closes_tags_counts_and_trailing_bytes() {
    let states = [
        genesis(),
        prefix(Phase::Verified),
        step(&prefix(Phase::Armed), Phase::RollbackPrepared),
    ];
    for s in states {
        let b = s.canonical_bytes();
        assert_eq!(DeploymentLedgerStateV3::from_canonical_bytes(b).unwrap(), s);
        for len in 0..b.len() {
            assert!(DeploymentLedgerStateV3::from_canonical_bytes(&b[..len]).is_err());
        }
        let mut extra = b.to_vec();
        extra.push(0);
        assert!(DeploymentLedgerStateV3::from_canonical_bytes(&extra).is_err());
        // Any accepted mutation must itself be exactly canonical. Unknown enum,
        // boolean and option tags cannot slip through via permissive decoding.
        for i in 0..b.len() {
            let mut bad = b.to_vec();
            bad[i] ^= 0xff;
            if let Ok(value) = DeploymentLedgerStateV3::from_canonical_bytes(&bad) {
                assert_eq!(value.canonical_bytes(), bad);
            }
        }
    }
    assert!(DeploymentLedgerStateV3::from_canonical_bytes(&vec![0; MAX_BYTES + 1]).is_err());
    for p in [
        Phase::BootstrapBridge,
        Phase::BridgeRestorePrepared,
        Phase::BridgeRestoreInstalled,
        Phase::BridgeRestoreVerified,
    ] {
        let mut m = genesis().material().clone();
        m.phase = p;
        assert!(DeploymentLedgerStateV3::new(m).is_err());
    }
}

#[test]
fn successors_preserve_every_high_water_entry_and_key_epoch() {
    let s = prefix(Phase::Installed);
    let n = step(&s, Phase::Verified);
    for i in 0..29 {
        for value in [
            HighWaterEntryV2::new(3, d(90), 2).unwrap(),
            HighWaterEntryV2::new(4, d(90), 2).unwrap(),
            HighWaterEntryV2::new(5, d(90), 1).unwrap(),
        ] {
            let mut m = n.material.clone();
            let mut entries = *m.highest_ever.entries();
            entries[i] = value;
            m.highest_ever = HighestEverV2::new(entries).unwrap();
            assert!(s
                .validate_successor(&DeploymentLedgerStateV3::new(m).unwrap())
                .is_err());
        }
        let mut m = n.material.clone();
        let mut entries = *m.highest_ever.entries();
        entries[i] = HighWaterEntryV2::new(5, d(90), 3).unwrap();
        m.highest_ever = HighestEverV2::new(entries).unwrap();
        s.validate_successor(&DeploymentLedgerStateV3::new(m).unwrap())
            .unwrap();
    }
}

#[test]
fn invalid_phase_context_fence_activation_and_origin_never_advance() {
    let s = prefix(Phase::Installed);
    let n = step(&s, Phase::Verified);
    let mutations: [fn(&mut DeploymentLedgerMaterialV3); 12] = [
        |m| m.installation = d(90),
        |m| m.epoch += 1,
        |m| m.generation += 1,
        |m| m.previous_payload = d(90),
        |m| m.written_at_ms = 1,
        |m| m.identity_profile = d(90),
        |m| m.bootstrap_tcb_lock = d(90),
        |m| m.fence_epoch += 1,
        |m| m.rollback_grant_id = Some(d(90)),
        |m| m.transaction = Some(Nonce32V2::new([90; 32])),
        |m| m.active_manifest = d(90),
        |m| m.phase = Phase::Quiesced,
    ];
    for f in mutations {
        let mut m = n.material.clone();
        f(&mut m);
        assert!(
            DeploymentLedgerStateV3::new(m).map_or(true, |bad| s.validate_successor(&bad).is_err())
        );
    }
    let mut m = step(&s, Phase::RollbackPrepared).material;
    m.rollback_origin = Some(Origin::Armed);
    assert!(s
        .validate_successor(&DeploymentLedgerStateV3::new(m).unwrap())
        .is_err());
    let committed = prefix(Phase::Committed);
    let mut m = step(&committed, Phase::Prepared).material;
    m.transaction = committed.material.transaction;
    assert!(committed
        .validate_successor(&DeploymentLedgerStateV3::new(m).unwrap())
        .is_err());
    let mut m = genesis().material;
    m.epoch = 2;
    assert!(DeploymentLedgerStateV3::new(m)
        .unwrap()
        .validate_fresh_genesis()
        .is_err());
}

#[test]
fn signed_ledger_requires_exact_scope_installation_and_time() {
    let g = genesis();
    let r = verified(&g, TpmStateHeadV3::GENESIS);
    r.validate_fresh_genesis().unwrap();
    for scope in [
        DeploymentRecordScopeV3::new(Domain::CommitAttestation, 1, [0; 32]).unwrap(),
        DeploymentRecordScopeV3::new(Domain::LedgerActivation, 2, [0; 32]).unwrap(),
        DeploymentRecordScopeV3::new(Domain::LedgerActivation, 1, [2; 32]).unwrap(),
    ] {
        assert!(VerifiedDeploymentLedgerRecordV3::verify(record(
            g.canonical_bytes(),
            scope,
            TpmStateHeadV3::GENESIS
        ))
        .is_err());
    }
    for field in 0..3 {
        let mut m = g.material.clone();
        match field {
            0 => m.installation = d(99),
            1 => m.epoch = 2,
            _ => m.written_at_ms = 151000,
        }
        let bad = DeploymentLedgerStateV3::new(m).unwrap();
        assert!(VerifiedDeploymentLedgerRecordV3::verify(record(
            bad.canonical_bytes(),
            bad.scope(),
            TpmStateHeadV3::GENESIS
        ))
        .is_err());
    }
    assert!(verified(&g, r.record.head())
        .validate_fresh_genesis()
        .is_err());
}

#[test]
fn intervening_chain_cannot_hide_skipped_ledger_or_enrollment_switch() {
    let g = genesis();
    let first = verified(&g, TpmStateHeadV3::GENESIS);
    let next = step(&g, Phase::Prepared);
    let aux = record(
        b"synthetic auxiliary bytes",
        DeploymentRecordScopeV3::new(Domain::InstallationEvidenceEnvelope, 2, [2; 32]).unwrap(),
        first.record.head(),
    );
    let second = verified(&next, aux.head());
    first.validate_successor(&second, &[aux.clone()]).unwrap();
    assert!(first.validate_successor(&second, &[]).is_err());
    assert!(first
        .validate_successor(&second, &[aux.clone(), aux.clone()])
        .is_err());
    assert!(first
        .validate_successor(&second, &vec![aux.clone(); MAX_INTERVENING + 1])
        .is_err());
    let hidden = record(g.canonical_bytes(), g.scope(), first.record.head());
    let later = verified(&next, hidden.head());
    assert!(first.validate_successor(&later, &[hidden]).is_err());
    let foreign = VerifiedDeploymentLedgerRecordV3::verify(record_for(
        next.canonical_bytes(),
        next.scope(),
        first.record.head(),
        enrollment_for([99; 32]),
    ))
    .unwrap();
    assert!(first.validate_successor(&foreign, &[]).is_err());
}

fn append_history(
    history: &mut Vec<VerifiedDeploymentRecordEnvelopeV3>,
    state: &DeploymentLedgerStateV3,
) {
    let previous = history.last().map_or(TpmStateHeadV3::GENESIS, |r| r.head());
    history.push(record(state.canonical_bytes(), state.scope(), previous));
}
#[test]
fn history_requires_reviewed_genesis_exact_live_head_and_all_records() {
    let g = genesis();
    let mut s = g.clone();
    let mut history = Vec::new();
    append_history(&mut history, &s);
    for p in [
        Phase::Prepared,
        Phase::Armed,
        Phase::Quiesced,
        Phase::Installed,
    ] {
        s = step(&s, p);
        append_history(&mut history, &s);
    }
    let head = history.last().unwrap().head();
    let done = DeploymentLedgerHistoryV3::verify(&history, g.payload_digest(), head).unwrap();
    assert_eq!(done.latest_ledger().state(), &s);
    assert!(done.trailing_evidence().is_empty());
    assert_eq!(done.head(), head);
    assert!(DeploymentLedgerHistoryV3::verify(&history, d(90), head).is_err());
    assert!(DeploymentLedgerHistoryV3::verify(
        &history,
        g.payload_digest(),
        TpmStateHeadV3::GENESIS
    )
    .is_err());
    assert!(DeploymentLedgerHistoryV3::verify(
        &history[..history.len() - 1],
        g.payload_digest(),
        head
    )
    .is_err());
    let mut gap = history.clone();
    gap.remove(2);
    assert!(DeploymentLedgerHistoryV3::verify(&gap, g.payload_digest(), head).is_err());
    assert!(DeploymentLedgerHistoryV3::verify(&[], g.payload_digest(), head).is_err());
    assert!(DeploymentLedgerHistoryV3::verify(
        &vec![history[0].clone(); MAX_HISTORY + 1],
        g.payload_digest(),
        head
    )
    .is_err());
    let aux = record(
        b"not a verified transition",
        DeploymentRecordScopeV3::new(Domain::VerificationEvidence, 5, [2; 32]).unwrap(),
        head,
    );
    let head = aux.head();
    history.push(aux);
    let done = DeploymentLedgerHistoryV3::verify(&history, g.payload_digest(), head).unwrap();
    assert_eq!(
        done.latest_ledger().state().material().phase,
        Phase::Installed
    );
    assert_eq!(done.trailing_evidence().len(), 1);
}

#[test]
fn history_rejects_reused_transactions_and_consumed_rollback_grants() {
    let g = genesis();
    let mut s = g.clone();
    let mut history = Vec::new();
    append_history(&mut history, &s);
    let first_id = [2; 32];
    for p in [
        Phase::Prepared,
        Phase::Aborted,
        Phase::Idle,
        Phase::Prepared,
        Phase::Aborted,
        Phase::Idle,
    ] {
        s = step(&s, p);
        append_history(&mut history, &s);
    }
    let mut m = step(&s, Phase::Prepared).material;
    m.rollback_grant_id = Some(d(182)); // First aborted transaction burned this ID.
    let burned = DeploymentLedgerStateV3::new(m).unwrap();
    s.validate_successor(&burned).unwrap();
    let mut reused_grant_history = history.clone();
    append_history(&mut reused_grant_history, &burned);
    assert!(DeploymentLedgerHistoryV3::verify(
        &reused_grant_history,
        g.payload_digest(),
        reused_grant_history.last().unwrap().head()
    )
    .is_err());
    let mut m = step(&s, Phase::Prepared).material;
    m.transaction = Some(Nonce32V2::new(first_id));
    let reused = DeploymentLedgerStateV3::new(m).unwrap();
    s.validate_successor(&reused).unwrap(); // A pair cannot know all previous IDs.
    append_history(&mut history, &reused);
    assert!(DeploymentLedgerHistoryV3::verify(
        &history,
        g.payload_digest(),
        history.last().unwrap().head()
    )
    .is_err());

    let mut history = Vec::new();
    let mut s = g.clone();
    append_history(&mut history, &s);
    for _ in 0..2 {
        for p in [
            Phase::Prepared,
            Phase::Armed,
            Phase::RollbackPrepared,
            Phase::RollbackInstalled,
            Phase::RollbackVerified,
            Phase::RolledBack,
        ] {
            let next = step(&s, p);
            s.validate_successor(&next).unwrap();
            s = next;
            append_history(&mut history, &s);
        }
    }
    DeploymentLedgerHistoryV3::verify(&history, g.payload_digest(), history.last().unwrap().head())
        .unwrap();
    let next = step(&s, Phase::Prepared);
    let mut reused = next.material.clone();
    reused.rollback_grant_id = Some(d(182));
    let reused = DeploymentLedgerStateV3::new(reused).unwrap();
    s.validate_successor(&reused).unwrap();
    append_history(&mut history, &reused);
    assert!(DeploymentLedgerHistoryV3::verify(
        &history,
        g.payload_digest(),
        history.last().unwrap().head()
    )
    .is_err());
    history.pop();
    append_history(&mut history, &next);
    DeploymentLedgerHistoryV3::verify(&history, g.payload_digest(), history.last().unwrap().head())
        .unwrap();
}

#[test]
fn typed_evidence_matches_actual_installed_and_committed_ledger_chain() {
    use super::super::{
        ArtifactIdentityV2, ClosedArtifactTypeV2, ClosedCommitDigestFieldV2 as C,
        ClosedTargetArchitectureV2 as Arch, ClosedTargetOsV2 as Os,
        ClosedVerificationDigestFieldV2 as V, CommitClaimsV3, PlatformLockV2, VerificationClaimsV3,
        VerifiedCommitAttestationV3, VerifiedVerificationEvidenceV3,
    };
    let g = genesis();
    let mut installed = g.clone();
    let mut history = Vec::new();
    append_history(&mut history, &installed);
    for p in [
        Phase::Prepared,
        Phase::Armed,
        Phase::Quiesced,
        Phase::Installed,
    ] {
        installed = step(&installed, p);
        append_history(&mut history, &installed);
    }
    let ir = VerifiedDeploymentLedgerRecordV3::verify(history.last().unwrap().clone()).unwrap();
    let after_verify = step(&installed, Phase::Verified);
    let committed = step(&after_verify, Phase::Committed);
    let mut vd = [d(50); 28];
    vd[V::InstallationId as usize - 1] = d(1);
    vd[V::InstallIdentityProfile as usize - 1] = installed.material.identity_profile;
    vd[V::HighestEver as usize - 1] = installed.material.highest_ever.digest().unwrap();
    vd[V::InstalledManifest as usize - 1] = committed.material.active_manifest;
    let v = VerificationClaimsV3::new(
        vd,
        1,
        installed.material.transaction.unwrap(),
        installed.material.generation,
        installed.material.fence_epoch,
        installed.material.written_at_ms + 1,
        ArtifactIdentityV2::new(
            ClosedArtifactTypeV2::RootHelper,
            Os::Linux,
            Arch::Aarch64,
            100,
            d(51),
            d(52),
            d(53),
        )
        .unwrap(),
        ArtifactIdentityV2::new(
            ClosedArtifactTypeV2::Watchdog,
            Os::Linux,
            Arch::Aarch64,
            100,
            d(51),
            d(52),
            d(53),
        )
        .unwrap(),
    )
    .unwrap();
    let vrec = record(&v.canonical_bytes(), v.scope(), ir.record.head());
    let verification = VerifiedVerificationEvidenceV3::verify(vrec.clone(), v).unwrap();
    verification.validate_installed_ledger(&ir, &[]).unwrap();
    let verified_ledger = verified(&after_verify, vrec.head());
    history.push(vrec.clone());
    history.push(verified_ledger.record.clone());
    ir.validate_successor(&verified_ledger, &[vrec]).unwrap();
    let cr = verified(&committed, verified_ledger.record.head());
    history.push(cr.record.clone());
    verified_ledger.validate_successor(&cr, &[]).unwrap();
    assert!(verification.validate_installed_ledger(&cr, &[]).is_err());
    let mut cd = [d(50); 16];
    cd[C::InstallationId as usize - 1] = d(1);
    cd[C::VerificationEvidence as usize - 1] = verification.record_digest();
    cd[C::CommittedRecordPayload as usize - 1] = committed.payload_digest();
    cd[C::CommittedManifest as usize - 1] = committed.material.active_manifest;
    cd[C::CommittedHighestEver as usize - 1] = committed.material.highest_ever.digest().unwrap();
    let c = CommitClaimsV3::new(
        cd,
        1,
        PlatformLockV2::new(Os::Linux, Arch::Aarch64, d(1), d(2), d(3), d(4), d(5)).unwrap(),
        committed.material.transaction.unwrap(),
        committed.material.generation,
        committed.material.fence_epoch,
        committed.material.written_at_ms,
    )
    .unwrap();
    let commit_record = record(&c.canonical_bytes(), c.scope(), cr.record.head());
    history.push(commit_record.clone());
    let attestation =
        VerifiedCommitAttestationV3::verify(commit_record, c.clone(), &verification).unwrap();
    attestation.validate_committed_ledger(&cr, &[]).unwrap();
    let replay = DeploymentLedgerHistoryV3::verify(
        &history,
        g.payload_digest(),
        attestation.record().head(),
    )
    .unwrap();
    replay
        .validate_normal_commit(&verification, &attestation)
        .unwrap();
    let mut fresh = super::super::deployment_v3_test_support::transaction_material_on(
        &committed,
        c.platform().clone(),
    );
    let fresh_tx = sign_transaction(fresh.clone());
    assert!(replay
        .validate_new_transaction(&fresh_tx, c.platform(), 150100, None)
        .is_err());
    replay
        .validate_new_transaction(
            &fresh_tx,
            c.platform(),
            150100,
            Some((&verification, &attestation)),
        )
        .unwrap();
    fresh.transaction_id = committed.material.transaction.unwrap();
    let reused = sign_transaction(fresh);
    assert!(replay
        .validate_new_transaction(
            &reused,
            c.platform(),
            150100,
            Some((&verification, &attestation))
        )
        .is_err());
    assert!(attestation.validate_committed_ledger(&ir, &[]).is_err());
    // A signed changed ledger is not the committed record named by the attestation.
    let mut wrong = committed.material.clone();
    wrong.bootstrap_tcb_lock = d(99);
    let wrong = verified(
        &DeploymentLedgerStateV3::new(wrong).unwrap(),
        verified_ledger.record.head(),
    );
    assert!(attestation.validate_committed_ledger(&wrong, &[]).is_err());
    let aux = record(
        b"aux",
        DeploymentRecordScopeV3::new(
            Domain::InstallationEvidenceEnvelope,
            committed.material.generation,
            *committed.material.transaction.unwrap().as_bytes(),
        )
        .unwrap(),
        cr.record.head(),
    );
    let with_aux = VerifiedCommitAttestationV3::verify(
        record(&c.canonical_bytes(), c.scope(), aux.head()),
        c,
        &verification,
    )
    .unwrap();
    with_aux
        .validate_committed_ledger(&cr, &[aux.clone()])
        .unwrap();
    assert!(with_aux.validate_committed_ledger(&cr, &[]).is_err());
    history.pop();
    history.push(aux);
    history.push(with_aux.record().clone());
    DeploymentLedgerHistoryV3::verify(&history, g.payload_digest(), with_aux.record().head())
        .unwrap()
        .validate_normal_commit(&verification, &with_aux)
        .unwrap();
    let later = record(
        b"unclassified later state",
        DeploymentRecordScopeV3::new(Domain::InstallationEvidenceEnvelope, 7, [2; 32]).unwrap(),
        with_aux.record().head(),
    );
    let head = later.head();
    history.push(later);
    assert!(
        DeploymentLedgerHistoryV3::verify(&history, g.payload_digest(), head)
            .unwrap()
            .validate_normal_commit(&verification, &with_aux)
            .is_err()
    );
}
