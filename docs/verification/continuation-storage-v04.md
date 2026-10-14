# v0.4 continuation storage: implementation and verification boundary

Local implementation record, 2026-09-19. This is not a production security
certificate or a claim that the complete v0.4 architecture is deployed.

## Actual call path

An authenticated trusted host selects its storage-profile verification key and
the expected `VerifiedTaskAuthorizationV2`; neither is selected by model input.

1. `VerifiedContinuationStorageV04::verify` checks exact signed profile bytes,
   signature purpose, parent/installation/task identities, validity and bounds.
2. `DurableG4StateV2::install_continuation_storage_v04` requires that exact parent
   to be installed and current, then installs an empty bounded history once.
3. `update_continuation_storage_v04` checks the task's current authority and the
   expected record revision, applies all updates to a copy, and commits the
   resulting ledger and observations together using the existing G4 owner.
4. On restart, the existing authenticated encryption/namespace/anchor checks run.
   Nested state is also validated: counters are rebuilt from original records;
   observation scope, slots, pins and frozen bytes are checked against commitment.
5. `continuation_storage_v04` returns a private host view, including retained
   history after revocation. It neither publishes bytes nor authorizes dispatch.

`RecordReservation` stores a trusted-host supplied exact request-binding digest.
It does not validate that digest against G1–G7 or debit the existing G7 dispatch
transaction. Never send a tool request on the strength of this bookkeeping API.
The storage signature similarly does not authorize a new action or disclosure.
An optional, separately signed [dispatch accounting policy](continuation-dispatch-v04.md)
now connects the actual G7 transaction. Once enrolled, direct `RecordReservation`
bookkeeping is rejected; only G7 may insert a reservation for that task.

## Limits and compatibility

- At most 32 task records per owner; 8 domains, 256 executions and 32 observation
  slots per profile; 16 updates per batch. Closed canonical JSON, profile at most
  128 KiB, table at most 8 MiB. Existing owner file limits also apply.
- Restore validates reservation history by replay, with bounded but potentially
  quadratic work. No large-scale recovery-performance claim is made.
- Parent validity contains child validity. A parent revision, expiry or revocation
  stops writes; it does not silently discard the previous history.
- A different profile cannot replace an installed one. Controlled continuation
  replacement is future work, not a delete/reinstall operation.
- Old schema 2/3/4 snapshots remain supported by the new owner. Existing writes
  remain schema 4 until profile installation. The new schema 5 is never silently
  downgraded. Explicit dispatch enrollment further upgrades to schema 6.
  Deploying an old binary over an upgraded state is unsupported and
  must fail closed, not create a new state directory or reset its anchor.
- No production state, credential, approval or Touch ID enrollment was modified.

## Tests and what they establish

Tests live in `savana-policy-core/src/v2/durable_continuation_tests.rs` and
`savana-continuation-core/tests/core.rs`.

| Test group | Checked property |
| --- | --- |
| Signed profile and installed parent | Wrong issuer/parent, expired/tampered/noncanonical material rejected; exact reinstall is a no-op |
| Encrypted owner reopen | Stable charges, execution IDs and pinned Boolean survive reopen; later freeze uses original input |
| Batch/precommit failure | No partial debit or observation; durable head unchanged |
| Replay/stale revision | Original replay is uncharged and does not write; stale update and different repin rejected |
| Expiry/revocation/amendment | No new update; history retained across reopen |
| Old snapshot/new anchor | Reopen rejects rollback rather than initializing fresh state |
| Anchor fail before/after advance | Commit reports uncertainty and poisons the open owner; reopening reconciles the exact written state |
| Schema/corruption/bounds | Old canonical encoding retained until opt-in; missing parent, changed nested configuration and over-limit input rejected |
| Ledger snapshots | All domains reconstructed, canonical ordering, duplicate/over-budget history and configuration substitution rejected |

These tests use real temporary encrypted files and the actual G4 transaction path,
but a test rollback anchor. They do not prove hardware rollback resistance or
Linux process isolation. They do not exercise business effects or public release.

## Reproducible checks

```sh
cargo test -p savana-continuation-core --all-targets --locked
cargo test -p savana-policy-core --lib --locked
cargo check -p savana-kerneld --locked
cargo clippy -p savana-continuation-core --all-targets --locked -- -D warnings
tools/check-frozen-v2-core.sh
```

The new finite crate passes strict Clippy locally. Strict policy/dependency Clippy
is not clean: pre-existing warnings occur in protocol `kernel_ingress.rs`
(large enum), `task_context.rs` (format collection), `transport.rs` (large error),
and policy `durable.rs` (existing final-release function argument count),
`control_selection.rs` (large enum), `task_state.rs` (manual range pattern).
They were not suppressed or silently presented as passing.

Second-batch local results: policy-core 243/243 unit tests (including 11 continuation
owner tests), finite-core 34/34 integration tests; kernel compilation, targeted
format checks, patch whitespace and frozen-source validation passed. The frozen
validator's own negative tests also passed (their intentional checksum and sort
failures are expected). Doc-test commands ran successfully with no doc tests.

Linux CI includes focused owner tests and kernel compilation, but has not run
in this local session. Current host is macOS; Docker daemon is unavailable.
TPM/HSM, service isolation, full egress closure, compiler coverage, replacement,
SDK/UI integration and the review worker remain separate acceptance work.
