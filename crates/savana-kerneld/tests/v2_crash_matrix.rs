mod v2_release_support;

use savana_execd::ExecdJournalStateV2;
use savana_kernel_protocol::v2::{Digest32V2, ExecutorFailureClassV2, Nonce32V2};

use v2_release_support::{deadline, now, ExecdCrashFixture};

#[test]
fn every_effect_transition_survives_owner_restart_without_nonce_reissue() {
    let fixture = ExecdCrashFixture::new();
    let nonce = Nonce32V2::new([0x61; 32]);
    let envelope = fixture.signed_tool_envelope(nonce);

    {
        let owner = fixture.open_owner(8);
        let accepted = owner
            .accept_signed_dispatch(envelope.clone(), now(200), deadline())
            .unwrap();
        assert_eq!(accepted.execution_nonce(), nonce);
        assert_eq!(accepted.state(), ExecdJournalStateV2::Prepared);
    }
    {
        let owner = fixture.open_owner(8);
        assert_eq!(
            owner.query(nonce, deadline()).unwrap().state(),
            ExecdJournalStateV2::Prepared
        );
        let replay = owner
            .accept_signed_dispatch(envelope.clone(), now(201), deadline())
            .unwrap();
        assert_eq!(replay.execution_nonce(), nonce);
        let predecessor = owner
            .prepare_provider_attempt(nonce, Digest32V2::new([0x62; 32]), now(210), deadline())
            .unwrap();
        owner
            .record_effect_started(predecessor, now(211), deadline())
            .unwrap();
    }
    {
        let owner = fixture.open_owner(8);
        assert_eq!(
            owner.query(nonce, deadline()).unwrap().state(),
            ExecdJournalStateV2::EffectStarted
        );
        owner
            .record_provider_response(nonce, b"one provider response".to_vec(), deadline())
            .unwrap();
    }
    {
        let owner = fixture.open_owner(8);
        assert_eq!(
            owner.query(nonce, deadline()).unwrap().state(),
            ExecdJournalStateV2::ProviderResponseRetained
        );
        owner
            .record_tool_completion(
                nonce,
                b"typed result".to_vec(),
                Digest32V2::new([0x63; 32]),
                now(220),
                deadline(),
            )
            .unwrap();
    }
    {
        let owner = fixture.open_owner(8);
        assert_eq!(
            owner.query(nonce, deadline()).unwrap().state(),
            ExecdJournalStateV2::CompletionAvailable
        );
        assert!(!owner
            .completion(nonce, deadline())
            .unwrap()
            .canonical_payload()
            .is_empty());
        assert_eq!(
            owner
                .accept_signed_dispatch(envelope, now(221), deadline())
                .unwrap()
                .execution_nonce(),
            nonce
        );
        owner
            .acknowledge_completion(nonce, Digest32V2::new([0x64; 32]), deadline())
            .unwrap();
    }
    {
        let owner = fixture.open_owner(8);
        assert_eq!(
            owner.query(nonce, deadline()).unwrap().state(),
            ExecdJournalStateV2::Acknowledged
        );
    }

    let persisted = std::fs::read(fixture.journal_path()).unwrap();
    assert!(!persisted
        .windows(nonce.as_bytes().len())
        .any(|window| window == nonce.as_bytes()));
}

#[test]
fn crash_after_attempt_preparation_recovers_indeterminate_without_reissuing_effect() {
    let fixture = ExecdCrashFixture::new();
    let nonce = Nonce32V2::new([0x71; 32]);
    let envelope = fixture.signed_tool_envelope(nonce);

    {
        let owner = fixture.open_owner(8);
        owner
            .accept_signed_dispatch(envelope.clone(), now(200), deadline())
            .unwrap();
        owner
            .prepare_provider_attempt(nonce, Digest32V2::new([0x72; 32]), now(210), deadline())
            .unwrap();
    }
    {
        let owner = fixture.open_owner(8);
        assert_eq!(
            owner.query(nonce, deadline()).unwrap().state(),
            ExecdJournalStateV2::ProviderAttemptPrepared
        );
        owner
            .record_indeterminate_recovery(nonce, Digest32V2::new([0x73; 32]), now(211), deadline())
            .unwrap();
    }
    {
        let owner = fixture.open_owner(8);
        assert_eq!(
            owner.query(nonce, deadline()).unwrap().state(),
            ExecdJournalStateV2::Indeterminate
        );
        assert!(owner.terminal_receipt(nonce, deadline()).is_ok());
        assert_eq!(
            owner
                .accept_signed_dispatch(envelope, now(212), deadline())
                .unwrap()
                .state(),
            ExecdJournalStateV2::Indeterminate
        );
    }
}

#[test]
fn crash_after_pre_effect_failure_retains_one_terminal_receipt() {
    let fixture = ExecdCrashFixture::new();
    let nonce = Nonce32V2::new([0x81; 32]);
    let envelope = fixture.signed_tool_envelope(nonce);

    {
        let owner = fixture.open_owner(8);
        owner
            .accept_signed_dispatch(envelope.clone(), now(200), deadline())
            .unwrap();
        owner
            .record_failed_no_effect(
                nonce,
                ExecutorFailureClassV2::ConnectorUnavailableBeforeEffect,
                Digest32V2::new([0x82; 32]),
                now(201),
                deadline(),
            )
            .unwrap();
    }
    {
        let owner = fixture.open_owner(8);
        let query = owner.query(nonce, deadline()).unwrap();
        assert_eq!(query.state(), ExecdJournalStateV2::FailedNoEffect);
        assert_eq!(
            query.failure_class(),
            Some(ExecutorFailureClassV2::ConnectorUnavailableBeforeEffect)
        );
        assert!(owner.terminal_receipt(nonce, deadline()).is_ok());
        assert_eq!(
            owner
                .accept_signed_dispatch(envelope, now(202), deadline())
                .unwrap()
                .state(),
            ExecdJournalStateV2::FailedNoEffect
        );
    }
}
