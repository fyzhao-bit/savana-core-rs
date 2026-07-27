#![cfg(feature = "test-support")]

mod support;

use std::os::unix::process::ExitStatusExt;

use nix::libc::SIGABRT;
use support::{ControlOpcode, ControlStatus, Installation, LivePersistenceFault};

#[test]
fn post_rename_failure_aborts_and_restart_recovers_from_durable_ledger() {
    let installation = Installation::build();
    let mut daemon = installation
        .spawn_lifecycle_daemon_with_persistence_fault(Some(LivePersistenceFault::AfterRename));
    daemon.continue_startup();
    installation.install_next_candidate_strictly().unwrap();

    daemon.send(ControlOpcode::PostRenameFault);
    let status = daemon.wait();
    assert_eq!(status.signal(), Some(SIGABRT));
    // The engine-owned AfterRename hook only reports uncertainty after the
    // real ledger replacement has completed, so restart recovery is anchored
    // in these durable next-generation bytes rather than selected-policy I/O.
    assert_eq!(
        installation.ledger_bytes(),
        Some(installation.next_ledger_bytes())
    );

    let mut restarted = installation.spawn_lifecycle_daemon();
    restarted.continue_startup();
    let current = restarted.command(ControlOpcode::QueryPolicy);
    assert_eq!(current.status, ControlStatus::Ok);
    assert_eq!(current.identity(), installation.next_identity());
    restarted.shutdown();
}

#[test]
fn dropping_armed_daemon_publication_guard_aborts() {
    let installation = Installation::build();
    let mut daemon = installation.spawn_lifecycle_daemon();
    daemon.continue_startup();
    installation.install_next_candidate_strictly().unwrap();

    daemon.send(ControlOpcode::DropPublicationGuard);
    let status = daemon.wait();
    assert_eq!(status.signal(), Some(SIGABRT));
}

#[test]
fn post_snapshot_swap_failure_aborts() {
    let installation = Installation::build();
    let mut daemon = installation.spawn_lifecycle_daemon();
    daemon.continue_startup();
    installation.install_next_candidate_strictly().unwrap();

    daemon.send(ControlOpcode::PostSwapFault);
    let status = daemon.wait();
    assert_eq!(status.signal(), Some(SIGABRT));
}

#[test]
fn pre_rename_failure_returns_a_stable_error_and_old_dispatch_resumes() {
    let installation = Installation::build();
    let mut daemon = installation
        .spawn_lifecycle_daemon_with_persistence_fault(Some(LivePersistenceFault::BeforeRename));
    daemon.continue_startup();
    installation.install_next_candidate_strictly().unwrap();

    daemon.command_expect(
        ControlOpcode::PreRenameFault,
        ControlStatus::KernelUnavailable,
    );
    let current = daemon.command(ControlOpcode::QueryPolicy);
    assert_eq!(current.status, ControlStatus::Ok);
    assert_eq!(current.identity(), installation.initial_identity());
    daemon.command_expect(ControlOpcode::ProbeAdmission, ControlStatus::Ok);
    daemon.command_expect(ControlOpcode::CaptureOldArtifacts, ControlStatus::Ok);
    daemon.shutdown();
}
