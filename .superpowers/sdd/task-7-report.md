# Task 7 — generation-scoped policy dispatch

## Delivered

- Replaced split policy metadata with `PolicyRuntime` and one immutable, Arc-backed generation snapshot containing runtime identity, complete policy identity, effective limits, and generation.
- Bound pending handshakes and live contexts to policy identity, generation, and the separate connection-binding digest; stale generations fail closed before replay consumption.
- Added dispatch/admission gate leases, close-and-drain publication ordering, non-barging reopen behavior, and stream-before-lease teardown.
- Routed authenticated `BeginRun` and `IngestUserInput` to `PolicyEngine`; unsupported operations remain `KERNEL_UNAVAILABLE` and Health uses the exact dispatch snapshot identity.
- Added real UDS policy protocol coverage for Begin/Ingest, fresh same-client continuation, wrong-client handle rejection, and response-plus-EOF semantics.

## TDD record

The three real `policy_protocol` cases were first run with the policy adapter temporarily returning `KERNEL_UNAVAILABLE`; each completed the daemon handshake and failed at BeginRun with that exact code. Restoring the engine adapter made all three green.

## Fixture-race diagnosis and repair

The original parallel full-lib failure was `EACCES` from `savana-policy-core/tests/support/mod.rs` while writing a release-stage fixture. The failure disappeared in both exact tests and a serial suite. The call chain was a concurrent socket test installing process-global `umask(0o117)`, then `tempfile`/`create_dir_all` creating a fixture directory without owner execute permission, after which the next nested write failed.

Fixture creation now repairs root, stage-parent, and release-directory modes immediately after each individual directory creation. The deterministic regression test holds `PROCESS_TEST_LOCK`, installs that hostile umask, and successfully creates the policy runtime fixture.

## Verification

- `cargo fmt --check`
- `cargo test -p savana-kerneld --lib --no-fail-fast` — 144/144 (two consecutive parallel runs)
- `cargo test -p savana-kerneld --test policy_protocol --features test-support` — 3/3
- `cargo test -p savana-kerneld --test production_state_machine --features test-support` — 5/5
