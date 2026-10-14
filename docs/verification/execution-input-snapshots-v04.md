# v0.4 managed execution input snapshots

Implementation record, 2026-09-19. This closes the **owner-side input retention**
gap between G7 admission and later execution/recovery. It does not yet connect
these snapshots to execd's wire payload or a provider transaction.

## Problem and implemented behavior

Managed-source evidence binds an immutable object identity and its revision, but
the object may change after admission. Re-reading the current object at effect
time would not reproduce the admitted input. The owner now copies the actual
live object's content and display label when admitting a new managed-resource
execution, after signature/action/freshness validation and before committing G7.

The private snapshot binds:

- Original G7 execution nonce and exact reservation request-binding digest.
  That binding includes the original dispatch core, envelope/ticket, task contract,
  authorization and transition; it is not a caller-selected execution identity.
- Dispatch-policy and source-policy digests, full action-content digest, stable
  resource key, exact object revision, label and bytes.
- A purpose-separated integrity commitment to this complete snapshot.

Snapshot, signed fact, stable consumption, original task/quota and G7 journal are
saved in one existing encrypted/anchored owner transaction. Precommit failures
leave all of them unchanged. Uncertain commit returns no handoff and poisons the
owner; reopen uses the existing anti-rollback recovery path.

Renaming, editing or deleting the current object cannot change the saved snapshot.
Replay does not recapture input, renew a fact, mint a new execution ID or charge
again. Success, proven-no-effect and indeterminate outcomes retain both original
input and stable consumption. Old encrypted-file rollback cannot remove a pin
while restoring an unspent ledger when the independent anchor remains intact.

## Private interface and authority boundary

`DurableG4StateV2::managed_execution_snapshot_v04(task, execution, expected_core)`
returns `ManagedExecutionSnapshotV04` only for the exact stored task/nonce/core.
The returned object has read-only accessors for nonce, stable resource, revision,
label, bytes and commitment. It has no public constructor, serializer or
deserializer; Debug is redacted. The snapshot commitment and resource identity
are private metadata, **not** automatically safe to publish.

The host must authenticate the private reader. Audit access intentionally remains
possible after source deletion, task expiry or revocation. This API is **not** an
execution grant, a G3-approved handoff, a release capability or a current-reader
authorization for an external recipient. Revoked tasks still fail normal G7.
There is no new RPC, MCP tool, HTTP endpoint or Python method in this batch.

For a future executable bridge, the exact input must still pass existing
provenance/current-reader checks and be bound into the authenticated executor
handoff. The executor/provider must enforce the specified version semantics.
In particular, saved source bytes do not prove that a current-version update is
still valid or that a remote service applies an update exactly once. We have not
changed the sealed execution envelope or enabled a route that bypasses it.

## Compatibility, restore and retention

The first successful managed-resource G7 admission on this code upgrades the
owner to payload schema 8. Registering a source without admitting an execution
still uses schema 7. External issuer-only tasks still use schema 6. Schema 4–7
remain readable; no live installation was migrated and no downgrade API exists.

Each dispatch record set records a `snapshot_start` boundary. The old prefix
contains no snapshots; the new suffix must contain exactly one snapshot for every
execution. Restore rejects missing pins, pins before the boundary, invalid
boundaries, cross-execution substitution, inconsistent source/fact/request binding,
bad commitments, oversized content and schema mismatch. If a saved revision is
still current, bytes and label must also match the current catalog exactly. For
older revisions, immutable admission construction plus authenticated durable
state protects the historical input; this is not an independent signed source
history for every version.

Old schema-7 executions did not capture original bytes. Reading a snapshot for
one fails; no current object data is substituted. Existing legacy journal replay
semantics are preserved, without creating a snapshot retroactively. A migrated
owner can contain such an old prefix alongside new pinned executions. Any future
snapshot-requiring execution path must reject unavailable legacy inputs.

Content remains bounded by its signed source limit (at most 32 KiB) and labels by
256 UTF-8 bytes. The signed execution count and aggregate 8 MiB continuation-state
cap include these records. Capacity failure must not permit an unpinned dispatch.
There is no pruning/reset API. Deleting a source object's current content does
**not** delete copies retained for admitted executions. This deliberate recovery
retention is not secure erasure; production retention/compaction remains a
separate design and authorization requirement.

## Tests and remaining work

`durable_managed_execution_tests.rs` adds 15 tests covering original source
capture, exact task/nonce/core lookup, encrypted storage, redacted Debug, edit/
delete/restart/replay, stale facts, original quota failure, precommit failure,
uncertain anchor failure before/after advancement, missing/corrupt/swapped pins,
legacy-prefix migration without backfill, external-source compatibility,
revocation, terminal/unknown outcomes, size bounds and authenticated-file rollback.

These tests use real encrypted-owner files with test rollback anchors. Terminal
receipt-verification output is injected at an existing private test seam; they
are not live provider calls, two-owner distributed recovery tests, or TPM/HSM
acceptance. The current test host is macOS, despite the Linux product target.

```sh
cargo test -p savana-policy-core --lib managed_execution --locked
cargo test -p savana-policy-core --lib --locked
cargo test -p savana-continuation-core --all-targets --locked
cargo check -p savana-kerneld --locked
tools/check-frozen-v2-core.sh
```

Local results: **288/288 policy-core library tests**, including the 15 new
execution-snapshot tests, and **34/34 continuation-core tests** passed. Main
kernel compilation, targeted formatting, whitespace and frozen-source checks
passed. Policy-library Clippy completed with the same three pre-existing warnings
(argument count, large enum, manual range pattern); strict workspace lint
cleanliness is not claimed. The Linux CI filter includes this suite by module
path, but that workflow was not run on this macOS host.

Still pending: authenticated snapshot-to-executor transport and actual provider
effect/version checks, cross-owner late-response recovery, compiler/residual
replacement, fixed exclusive publisher, SDK/UI and native Linux acceptance.
Google Cloud/DeepSeek remain disabled placeholders. No cloud calls, deployment
reset, commit, push or PR are part of this batch.
