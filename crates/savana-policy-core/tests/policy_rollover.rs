mod support;

use std::os::unix::process::ExitStatusExt;

use savana_kernel_protocol::StableCode;
use savana_policy_core::{PolicyRolloverDisposition, PolicyRolloverFailure};

#[test]
fn disposition_is_exact_and_strict_advance_only() {
    let fixture = support::RolloverFixture::new();
    assert_eq!(
        fixture
            .engine
            .rollover_disposition(fixture.current_identity())
            .unwrap(),
        PolicyRolloverDisposition::Unchanged(fixture.current_identity())
    );
    assert_eq!(
        fixture
            .engine
            .rollover_disposition(fixture.next_identity())
            .unwrap(),
        PolicyRolloverDisposition::Advance(fixture.next_identity())
    );
    assert_eq!(
        fixture
            .engine
            .rollover_disposition(fixture.same_version_different_identity())
            .unwrap_err()
            .code(),
        StableCode::PolicyEquivocation
    );
    assert_eq!(
        fixture
            .engine
            .rollover_disposition(fixture.lower_identity())
            .unwrap_err()
            .code(),
        StableCode::PolicyRollback
    );
}

#[test]
fn strict_advance_updates_narrow_projections_and_old_handles_stay_stale() {
    let fixture = support::RolloverFixture::new();
    let old_run = fixture.begin_current().run;
    let committed = fixture.commit_next().unwrap();
    assert_eq!(committed.identity(), fixture.next_identity());
    assert_eq!(
        committed.complete_daemon_publication(),
        fixture.next_identity()
    );
    assert_eq!(
        fixture.engine.current_policy_identity(),
        fixture.next_identity()
    );
    assert_eq!(fixture.engine.effective_limits(), fixture.next_limits());

    let next_context = fixture.next_context();
    assert_eq!(
        fixture
            .ingest_next(&next_context, old_run)
            .unwrap_err()
            .code(),
        StableCode::HandleStalePolicy
    );
    fixture.clock.set(3_000, 101);
    assert_eq!(
        fixture
            .ingest_next_with_expiry(&next_context, old_run, 3_900)
            .unwrap_err()
            .code(),
        StableCode::HandleUnknown
    );
}

#[test]
fn new_generation_cannot_shadow_a_rollover_tombstone() {
    let fixture = support::RolloverFixture::new();
    let old_run = fixture.begin_current().run;
    fixture.commit_next().unwrap().complete_daemon_publication();
    let next_context = fixture.next_context();
    fixture.replay_first_handle_draw();
    assert_eq!(
        fixture
            .engine
            .begin_run(
                &next_context,
                fixture.begin_request(
                    fixture.next_identity(),
                    savana_kernel_protocol::KernelValue::Null
                ),
            )
            .unwrap_err()
            .code(),
        StableCode::KernelUnavailable
    );
    assert_eq!(
        fixture
            .ingest_next(&next_context, old_run)
            .unwrap_err()
            .code(),
        StableCode::HandleStalePolicy
    );
}

#[test]
fn rollover_failure_debug_is_redacted() {
    let fixture = support::RolloverFixture::new();
    let failure = fixture
        .engine
        .prepare_rollover(fixture.next_identity())
        .unwrap()
        .verify_accept_and_commit(
            &[],
            fixture.next_policy_signature(),
            support::unix_now(),
            fixture.next_identity(),
        )
        .unwrap_err();
    assert!(matches!(failure, PolicyRolloverFailure::Rejected(_)));
    assert_eq!(
        format!("{failure:?}"),
        "PolicyRolloverFailure::Rejected(<redacted>)"
    );
}

#[test]
fn dropping_armed_committed_rollover_aborts_subprocess() {
    const CHILD: &str = "SAVANA_TEST_DROP_COMMITTED";
    if std::env::var_os(CHILD).is_some() {
        let fixture = support::RolloverFixture::new();
        let committed = fixture.commit_next().unwrap();
        drop(committed);
        std::process::exit(99);
    }
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("dropping_armed_committed_rollover_aborts_subprocess")
        .arg("--nocapture")
        .env(CHILD, "1")
        .status()
        .unwrap();
    assert_eq!(status.signal(), Some(nix::libc::SIGABRT));
}
