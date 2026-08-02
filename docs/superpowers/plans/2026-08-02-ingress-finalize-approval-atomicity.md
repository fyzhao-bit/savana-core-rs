# Ingress Finalize/Approval Atomicity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make ingress input finalization and tag-3 approval publication one atomic, retry-safe production service operation.

**Architecture:** `KernelInputOwnerV2` will hold its exclusive mutable borrow while validating a finalize request and exposing an immutable, commitment-only `PreparedKernelInputFinalizationV2` to a closure. `KernelIngressAuthorityV2` will gate and build an opaque pending-publication candidate from that view without inserting a record; after the closure succeeds, the owner moves the exact bound bytes and marks the session finalized, and the authority publishes the already-reserved candidate infallibly with that finalized value.

**Tech Stack:** Rust, Cargo workspace tests, signed Savana V2 declassification rules, frozen-core SHA-256 manifest.

## Global Constraints

- Exercise `KernelIngressOperationV2::FinalizeInput` through `CoreKernelRuntimeServicesV2`.
- Gate refusal leaves input state, retained bytes, session handle, and finalize request retryable.
- Gate refusal creates no pending record and signs/publishes no approval envelope.
- The prepared view exposes only authenticated commitment metadata, never channel bytes or raw capabilities.
- No rollback reconstructs state after mutation; all fallible work occurs before bytes move.
- The same exclusively borrowed session supplies both the gated commitments and the committed bytes.

---

### Task 1: Reproduce the production-boundary state loss

**Files:**
- Modify: `crates/savana-kerneld/src/v2_core_services.rs`
- Modify: `crates/savana-kerneld/src/v2_input_owner.rs`

**Interfaces:**
- Consumes: real `CoreKernelRuntimeServicesV2::execute_operation` ingress routing.
- Produces: failing no-rule and wrong-implementation retry tests plus an owner transaction refusal test.

- [ ] Add a service fixture that installs a real `KernelIngressAuthorityV2`, begins/appends a chat input through service operations, and retains the exact finalize request.
- [ ] Add table-driven no-rule and wrong-implementation cases asserting the first finalize returns `ApprovalBindingMismatch`, the session remains `Receiving`, retained bytes are unchanged, no pending record exists, and replacing only the signed policy authority permits the identical finalize request once.
- [ ] Add an owner test whose finalization closure returns an error, asserting state/bytes are unchanged and the identical request can subsequently commit.
- [ ] Run focused tests and record the expected RED: current code leaves the session `Finalized` with zero retained bytes.

### Task 2: Add owner-serialized prepared finalization

**Files:**
- Modify: `crates/savana-kerneld/src/v2_input_owner.rs`

**Interfaces:**
- Produces: `PreparedKernelInputFinalizationV2` commitment-only view and generic `finalize_with` transaction method.
- Consumes: `FinalizeInputRequestV2` plus a closure returning either an opaque prepared result or its own error.

- [ ] Compute and validate request provenance, the finalized input commitment, and the channel commitment digest while the session remains `Receiving`.
- [ ] Reserve the owned finalized-channel vector before invoking the closure so no fallible operation remains after a successful gate.
- [ ] Invoke the closure with only input commitment, source provenance digest, verified UI authorization, and channel commitments digest.
- [ ] On closure error, return without changing the session, channels, chunks, authorization evidence, or bytes.
- [ ] On closure success, move the exact exclusively borrowed channel bytes, clear chunk metadata, mark `Finalized`, and return both the owned finalized input and closure result.

### Task 3: Defer authority publication until input commit

**Files:**
- Modify: `crates/savana-kerneld/src/v2_ingress_authority.rs`
- Modify: `crates/savana-kerneld/src/v2_core_services.rs`

**Interfaces:**
- Consumes: `&PreparedKernelInputFinalizationV2`.
- Produces: opaque `PreparedPendingIngressPublicationV2`, followed by infallible `publish_pending_approval(candidate, finalized)`.

- [ ] Move the pending-vector capacity reservation before candidate construction.
- [ ] Gate the exact display text and build/sign envelopes into an opaque candidate without inserting a pending record.
- [ ] Update `FinalizeInput` routing to split-borrow input and authority, execute the authority preparation inside `input.finalize_with`, then publish the candidate with the returned owned finalized value.
- [ ] Update authority tests to use the owner transaction and assert denial never publishes while admission publishes exactly once.
- [ ] Run the focused tests and confirm GREEN.

### Task 4: Verify, freeze, report, and commit

**Files:**
- Modify: `deploy/frozen-v2-core.sha256`
- Modify: `.superpowers/sdd/2026-08-01-savana-v2-remaining-security-and-connector-implementation/task-4-report.md`

**Interfaces:**
- Produces: final evidence and one local commit; no push.

- [ ] Run focused input-owner, ingress-authority, and core-services tests.
- [ ] Run locked protocol, approvald, and kerneld package suites.
- [ ] Run locked workspace check, formatting, diff check, frozen checker, and frozen-checker self-tests.
- [ ] Refresh only hashes for frozen files changed by this round and append RED/GREEN commands, results, and atomicity invariants to the Task 4 report.
- [ ] Stage the scoped diff and commit locally without pushing.
