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

- `cargo fmt --all -- --check`
- `cargo test -p savana-kerneld --lib --no-fail-fast` — 145/145 (three consecutive parallel runs)
- `cargo test -p savana-kerneld --test policy_protocol --features test-support` — 3/3
- `cargo test -p savana-kerneld --test production_state_machine --features test-support` — 5/5
- `cargo test -p savana-policy-core --all-targets` — all unit, integration, and example targets passed
- `cargo clippy -p savana-kerneld --all-targets -- -D warnings`
- `cargo clippy -p savana-kerneld --all-targets --features test-support -- -D warnings`
- `cargo check -p savana-kerneld --no-default-features`
- `cargo test -p savana-kerneld --doc` — 27/27

## Independent review fixes

- Removed the UDS capability probe that silently returned from all three
  `policy_protocol` tests. They now must execute the real daemon/socket flight
  and fail visibly in an environment that forbids UDS binding.
- Reused the crate's single policy-core support module so Clippy no longer
  reports duplicate module inclusion, and closed the remaining test-support
  lint.
- Repaired every temporary fixture root before nested release construction;
  the hostile-umask regression now exercises the exact `runtime_fixture` path
  that originally raced.
- Replaced the weak lease-only worker-limit assertion with a deterministic
  single-worker regression. The same real worker first accepts a 1,025-byte
  length under generation 1 / 4,096 bytes and reports a truncated frame after
  client write shutdown. The test then publishes generation 2 / 1,024 bytes
  through `close_and_drain -> replace -> reopen`; the same worker reports
  `PROTOCOL_FRAME_TOO_LARGE` for the same length header.
- Mutation-checked the worker regression by temporarily sourcing limits from
  the unchanged policy engine. The test failed with
  `PROTOCOL_TRUNCATED_FRAME` instead of `PROTOCOL_FRAME_TOO_LARGE`, proving it
  detects a stale worker limit copy.
- Removed the separate runtime argument from `KernelServer::new_preflight`;
  the server now derives its runtime from the handshake service, making a
  split identity/dispatch runtime unrepresentable at construction.
