#![cfg(feature = "test-support")]

mod support;

use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};

use savana_kernel_protocol::HardLimits;
use savana_kerneld::test_support::{
    probe_v2_declassification_rollover, V2DeclassificationRolloverScenario,
};
use support::{
    ControlOpcode, ControlStatus, Installation, StrictUpdaterError, UpdaterEvent,
    STRICT_UPDATER_EVENTS,
};

#[test]
fn v2_valid_generation_successor_reaches_both_active_rule_consumers() {
    let observed =
        probe_v2_declassification_rollover(V2DeclassificationRolloverScenario::ValidSuccessor);

    assert_eq!(observed.result(), Ok(()));
    assert_ne!(observed.old_digest(), observed.candidate_digest());
    assert_eq!(observed.ingress_digest(), observed.candidate_digest());
    assert_eq!(observed.agent_digest(), observed.candidate_digest());
    assert_eq!(observed.active_generation(), 2);
    assert!(observed.admission_resumed());
}

fn assert_v2_rollover_rejected_without_partial_publication(
    scenario: V2DeclassificationRolloverScenario,
) {
    let observed = probe_v2_declassification_rollover(scenario);

    assert!(observed.result().is_err());
    assert_eq!(observed.ingress_digest(), observed.old_digest());
    assert_eq!(observed.agent_digest(), observed.old_digest());
    assert_eq!(observed.active_generation(), 1);
    assert!(observed.admission_resumed());
}

#[test]
fn v2_rule_set_rollback_retains_the_old_complete_runtime() {
    assert_v2_rollover_rejected_without_partial_publication(
        V2DeclassificationRolloverScenario::RuleSetRollback,
    );
}

#[test]
fn v2_wrong_manifest_pin_retains_the_old_complete_runtime() {
    assert_v2_rollover_rejected_without_partial_publication(
        V2DeclassificationRolloverScenario::WrongManifestPin,
    );
}

#[test]
fn v2_bad_rule_set_signature_retains_the_old_complete_runtime() {
    assert_v2_rollover_rejected_without_partial_publication(
        V2DeclassificationRolloverScenario::BadRuleSetSignature,
    );
}

#[test]
fn v2_expired_rule_set_retains_the_old_complete_runtime() {
    assert_v2_rollover_rejected_without_partial_publication(
        V2DeclassificationRolloverScenario::ExpiredRuleSet,
    );
}

#[test]
fn v2_partial_runtime_generation_retains_the_old_complete_runtime() {
    assert_v2_rollover_rejected_without_partial_publication(
        V2DeclassificationRolloverScenario::PartialRuntimeGeneration,
    );
}

#[test]
fn rollover_closes_admission_and_drains_in_flight_dispatch() {
    let installation = Installation::build();
    let mut daemon = installation.spawn_lifecycle_daemon();
    daemon.continue_startup();
    daemon.command_expect(ControlOpcode::PauseBegin, ControlStatus::Ready);

    installation.install_next_candidate_strictly().unwrap();
    daemon.send(ControlOpcode::Refresh);
    assert!(daemon
        .receive_for(ControlOpcode::Refresh, Duration::from_millis(100))
        .is_none());

    daemon.send(ControlOpcode::ProbeAdmission);
    assert!(daemon
        .receive_for(ControlOpcode::ProbeAdmission, Duration::from_millis(100))
        .is_none());

    daemon.command_expect(ControlOpcode::ReleaseBegin, ControlStatus::Ok);
    let refresh = daemon.receive(ControlOpcode::Refresh);
    assert_eq!(refresh.status, ControlStatus::Published);
    assert_eq!(refresh.identity(), installation.next_identity());

    let admitted = daemon.receive(ControlOpcode::ProbeAdmission);
    assert_eq!(admitted.status, ControlStatus::Ok);
    assert_eq!(admitted.generation, 2);
    daemon.shutdown();
}

#[test]
fn asynchronous_lifecycle_jobs_have_a_shared_hard_capacity() {
    let installation = Installation::build();
    let mut daemon = installation.spawn_lifecycle_daemon();
    daemon.continue_startup();
    daemon.command_expect(ControlOpcode::PauseBegin, ControlStatus::Ready);

    installation.install_next_candidate_strictly().unwrap();
    daemon.send(ControlOpcode::Refresh);
    assert!(daemon
        .receive_for(ControlOpcode::Refresh, Duration::from_millis(100))
        .is_none());

    // The refresh holds the rollover path behind the paused real BeginRun;
    // admission probes also block after rollover closes admission.  A bounded
    // control plane must reject excess *combined* asynchronous work instead
    // of growing one thread per command without limit.
    for index in 0..40 {
        daemon.send(if index % 2 == 0 {
            ControlOpcode::Refresh
        } else {
            ControlOpcode::ProbeAdmission
        });
        thread::sleep(Duration::from_millis(5));
    }

    let deadline = Instant::now() + Duration::from_secs(2);
    let mut saw_rejection = false;
    while Instant::now() < deadline && !saw_rejection {
        if let Some(response) =
            daemon.receive_for(ControlOpcode::Refresh, Duration::from_millis(20))
        {
            saw_rejection |= response.status == ControlStatus::KernelUnavailable;
        }
        if let Some(response) =
            daemon.receive_for(ControlOpcode::ProbeAdmission, Duration::from_millis(20))
        {
            saw_rejection |= response.status == ControlStatus::KernelUnavailable;
        }
    }
    assert!(
        saw_rejection,
        "excess asynchronous lifecycle work must be rejected while the real jobs are blocked"
    );

    daemon.command_expect(ControlOpcode::ReleaseBegin, ControlStatus::Ok);
    daemon.shutdown();
}

#[test]
fn asynchronous_lifecycle_response_write_failure_is_fatal() {
    let installation = Installation::build();
    let mut child = Command::new(&installation.executable)
        .arg("--config")
        .arg(&installation.config)
        .env("SAVANA_TEST_V1_RUNTIME", "frozen-regression-v1")
        .env("SAVANA_TEST_LIFECYCLE_CONTROL", "stdio-v1")
        .env_remove("SAVANA_TEST_POLICY_CORE_LIVE_PERSISTENCE_FAULT")
        .env_remove("SAVANA_TEST_PROCESS_ENTROPY")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let mut frame = [0_u8; 72];

    stdout.read_exact(&mut frame).unwrap();
    assert_eq!(frame[0], ControlOpcode::StartupReady as u8);
    assert_eq!(frame[1], ControlStatus::Ready as u8);
    stdin
        .write_all(&[ControlOpcode::ContinueStartup as u8])
        .unwrap();
    stdin.flush().unwrap();
    stdout.read_exact(&mut frame).unwrap();
    assert_eq!(frame[0], ControlOpcode::ContinueStartup as u8);
    assert_eq!(frame[1], ControlStatus::Ok as u8);

    // Closing the sole response reader forces the next asynchronous fixed
    // response to receive EPIPE.  The daemon must enter its existing fatal
    // lifecycle path, not keep accepting requests after silently dropping it.
    drop(stdout);
    stdin.write_all(&[ControlOpcode::Refresh as u8]).unwrap();
    stdin.flush().unwrap();

    let deadline = Instant::now() + Duration::from_secs(2);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            let _ = child.wait();
            panic!("daemon kept running after asynchronous lifecycle response EPIPE");
        }
        thread::sleep(Duration::from_millis(10));
    };
    assert!(
        !status.success(),
        "response EPIPE must be a fatal daemon error"
    );
}

#[test]
fn publication_switches_identity_engine_and_release_bound_limits_as_one_generation() {
    let installation = Installation::build();
    let mut daemon = installation.spawn_lifecycle_daemon();
    daemon.continue_startup();
    daemon.command_expect(ControlOpcode::CaptureOldArtifacts, ControlStatus::Ok);

    installation.install_next_candidate_strictly().unwrap();
    let published = daemon.command(ControlOpcode::Refresh);
    assert_eq!(published.status, ControlStatus::Published);
    assert_eq!(published.identity(), installation.next_identity());

    let hello = daemon.command(ControlOpcode::Observe);
    let engine = daemon.command(ControlOpcode::QueryPolicy);
    assert_eq!(hello.status, ControlStatus::Ok);
    assert_eq!(hello.generation, 2);
    assert_eq!(hello.identity(), installation.next_identity());
    // Within an already verified release, a live policy cannot change the
    // release-bound resource profile.  Changing limits needs a new verified
    // release; this rollover still publishes the new policy atomically.
    assert_eq!(hello.frame_limit, HardLimits::COMPILED.frame_bytes() as u32);
    // QueryPolicy returns Ok only after comparing the snapshot's identity and
    // effective limits with the engine's live values.
    assert_eq!(engine.status, ControlStatus::Ok);
    assert_eq!(engine.identity(), installation.next_identity());
    daemon.command_expect(
        ControlOpcode::UseOldContext,
        ControlStatus::IdentityTranscriptMismatch,
    );
    daemon.command_expect(ControlOpcode::ObserveReplayTombstone, ControlStatus::Ok);
    daemon.shutdown();
}

#[test]
fn old_ingress_and_handles_fail_after_rollover_even_with_reused_key() {
    let installation = Installation::build();
    let mut daemon = installation.spawn_lifecycle_daemon();
    daemon.continue_startup();
    daemon.command_expect(ControlOpcode::CaptureOldArtifacts, ControlStatus::Ok);

    installation.install_next_candidate_strictly().unwrap();
    daemon.command_expect(ControlOpcode::Refresh, ControlStatus::Published);
    daemon.command_expect(
        ControlOpcode::SubmitOldIngress,
        ControlStatus::AttestationBindingMismatch,
    );
    daemon.command_expect(ControlOpcode::UseOldRun, ControlStatus::HandleStalePolicy);
    daemon.shutdown();
}

#[test]
fn strict_updater_uses_the_fixed_inode_and_exact_durability_order() {
    let installation = Installation::build();
    let ledger_before = installation.ledger_bytes();
    let lock_before = installation.update_lock_identity();

    let events = installation.install_next_candidate_strictly().unwrap();

    assert_eq!(events, STRICT_UPDATER_EVENTS);
    assert_eq!(installation.update_lock_identity(), lock_before);
    assert_eq!(installation.ledger_bytes(), ledger_before);
    assert_eq!(
        std::fs::read(&installation.kernel_lock).unwrap(),
        installation.next_candidate().kernel_lock
    );
    assert_eq!(
        std::fs::read(&installation.selected_policy).unwrap(),
        installation.next_candidate().policy
    );
    assert_eq!(
        std::fs::read(&installation.selected_signature).unwrap(),
        installation.next_candidate().signature.as_bytes()
    );
}

#[test]
fn exclusive_updater_waits_for_initial_acceptance_shared_guard() {
    let installation = Arc::new(Installation::build());
    let mut daemon = installation.spawn_lifecycle_daemon();
    let (done_tx, done_rx) = mpsc::sync_channel(1);
    let updater_installation = Arc::clone(&installation);
    let updater = thread::spawn(move || {
        let result = updater_installation.install_next_candidate_strictly();
        done_tx.send(result).unwrap();
    });

    assert!(done_rx.recv_timeout(Duration::from_millis(100)).is_err());
    daemon.continue_startup();
    assert_eq!(
        done_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .unwrap(),
        STRICT_UPDATER_EVENTS
    );
    updater.join().unwrap();
    daemon.shutdown();
}

#[test]
fn refresh_is_nonblocking_while_exclusive_updater_owns_the_lock() {
    let installation = Installation::build();
    let mut daemon = installation.spawn_lifecycle_daemon();
    daemon.continue_startup();
    let exclusive = installation.acquire_strict_update_lock().unwrap();

    let response = daemon.command_with_timeout(ControlOpcode::Refresh, Duration::from_secs(1));

    assert_eq!(response.status, ControlStatus::KernelUnavailable);
    drop(exclusive);
    daemon.command_expect(ControlOpcode::QueryPolicy, ControlStatus::Ok);
    daemon.shutdown();
}

#[test]
fn no_old_new_candidate_mix_reaches_verification() {
    let installation = Arc::new(Installation::build());
    let mut daemon = installation.spawn_lifecycle_daemon();
    daemon.continue_startup();
    let mut updater = installation.spawn_paused_strict_install();

    for expected in [
        UpdaterEvent::KernelLockRenamed,
        UpdaterEvent::PolicyRenamed,
        UpdaterEvent::SignatureRenamed,
    ] {
        updater.advance_until(expected);
        daemon.command_expect(ControlOpcode::Refresh, ControlStatus::KernelUnavailable);
    }
    assert_eq!(updater.finish().unwrap(), STRICT_UPDATER_EVENTS);
    daemon.command_expect(ControlOpcode::Refresh, ControlStatus::Published);
    daemon.shutdown();
}

#[test]
fn replacing_the_update_lock_inode_is_always_rejected() {
    let installation = Installation::build();
    installation.replace_update_lock_inode();

    assert_eq!(
        installation.install_next_candidate_strictly().unwrap_err(),
        StrictUpdaterError::UpdateLockChanged
    );
    assert_eq!(installation.ledger_bytes(), None);
}

#[test]
fn candidate_replacement_succeeds_after_startup_guard_releases() {
    let installation = Installation::build();
    let mut daemon = installation.spawn_lifecycle_daemon();
    daemon.continue_startup();

    assert_eq!(
        installation.install_next_candidate_strictly().unwrap(),
        STRICT_UPDATER_EVENTS
    );
    let response = daemon.command(ControlOpcode::Refresh);
    assert_eq!(response.status, ControlStatus::Published);
    assert_eq!(response.identity(), installation.next_identity());
    daemon.shutdown();
}
