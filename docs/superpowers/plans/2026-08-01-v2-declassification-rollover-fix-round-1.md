# V2 Declassification Rollover Fix Round 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make a verified V2 declassification successor a complete, production-triggerable live endpoint/runtime publication that continues serving real agent and ingress traffic after rollover.

**Architecture:** `V2GenerationRuntime` owns one atomically replaceable bundle containing the verified generation, declassification rules/root, both verified service edges, both generation-bound handshake owners, and the generation-bound dispatcher. Listeners keep only their fixed role, socket, peer verifier, and runtime; each accepted connection obtains all generation-bound state from one active-bundle read under a dispatch lease. SIGHUP is consumed by the internal server lifecycle and invokes a disk-backed successor publisher that re-runs the complete deployment/startup verification path, constructs a complete endpoint bundle with the shared runtime owner, and submits only the resulting verified successor to `PolicyRolloverCoordinator`.

**Tech Stack:** Rust 2021, `Arc`/`RwLock`, Unix domain sockets, Suite-1 V2 transport, signal-hook, cargo test.

## Global Constraints

- No agent-facing rollover operation and no public raw-authority constructor.
- A type named `VerifiedV2DeclassificationSuccessorV2` exists only after rule signature/window/root/manifest-pin/generation and complete endpoint runtime checks pass.
- Admission is closed and drained before live predecessor checks and the single bundle pointer replacement.
- Any construction or publication failure leaves the old complete endpoint/runtime/rule bundle usable and admission open.
- Tests must execute real Suite-1 agent and ingress listener/handshake/dispatcher paths after success and failure.
- Strict RED to GREEN evidence is appended to the requested Task 2 report.

---

### Task 1: RED tests for complete live endpoint rollover

**Files:**
- Modify: `crates/savana-kerneld/tests/policy_rollover.rs`
- Modify: `crates/savana-kerneld/src/lib.rs` (test-support result contract only)

**Interfaces:**
- Consumes: `probe_v2_declassification_rollover(V2DeclassificationRolloverScenario)`.
- Produces: assertions for `verified_successor_constructed`, real agent/ingress request generation and rule digest, and a distinct incomplete-endpoint-runtime scenario.

- [x] Add assertions that valid rollover completes real post-rollover agent and ingress requests at generation 2 with the successor rule digest.
- [x] Add assertions that bad signature, wrong pin, expiry, and incomplete endpoint material never construct a verified successor.
- [x] Add assertions that rollback/generation discontinuity fail publication and both real paths still serve generation 1 with the old digest.
- [x] Run `cargo test -p savana-kerneld --test policy_rollover v2_ --all-features --locked`; capture the expected compile/behavior failure caused by the missing real-path result contract and fixed listener state.

### Task 2: Verified complete bundle construction and atomic acquisition

**Files:**
- Modify: `crates/savana-kerneld/src/v2_declassification_policy.rs`
- Modify: `crates/savana-kerneld/src/policy_runtime.rs`
- Modify: `crates/savana-kerneld/src/v2_listener.rs`
- Modify: `crates/savana-kerneld/src/v2_dispatch.rs`
- Modify: `crates/savana-kerneld/src/v2_kernel_owner.rs`

**Interfaces:**
- Produces: `V2LiveEndpointRuntimeV2::from_verified_deployment(...)`, `VerifiedV2DeclassificationSuccessorV2::from_verified_deployment(...)`, and `V2GenerationRuntime::acquire_endpoint(role, deadline)`.
- The verified successor stores already-parsed `Arc<DeclassificationRuleSetV2>` and a complete `Arc<V2LiveEndpointRuntimeV2>`, never unverified bytes.

- [x] Change the successor constructor to parse canonical rules, verify signature/window against the verified root, require manifest-pin equality, derive the generation from `VerifiedDaemonStartupV2`, and require a live endpoint runtime matching that generation.
- [x] Make the live endpoint runtime build both service edges, both handshakes, and one dispatcher only from `VerifiedDaemonStartupV2`, matching key material, boot identity, and a shared `Arc<KernelRuntimeOwnerV2>`.
- [x] Store the live endpoint runtime in `ActiveV2DeploymentBundle`; validate live rule/root/generation predecessors while admission is closed, then replace only the one bundle pointer.
- [x] Change listeners to acquire a role-specific endpoint snapshot and `V2GenerationLease` together; remove fixed edge/handshake/dispatcher ownership from listeners.
- [x] Run the focused V2 rollover tests until GREEN, then run listener/connection/dispatch unit tests.

### Task 3: Real Suite-1 integration probe and incomplete-runtime rejection

**Files:**
- Modify: `crates/savana-kerneld/src/v2_startup.rs`
- Modify: `crates/savana-kerneld/src/lib.rs`
- Modify: `crates/savana-kerneld/tests/policy_rollover.rs`

**Interfaces:**
- The probe uses real Unix listeners, native-peer verification, `V2ClientHandshake`, encrypted application records, active listeners, active dispatcher, and a bounded runtime owner.
- Test support may observe results but cannot manufacture a `VerifiedV2DeclassificationSuccessorV2` or bypass any production verifier.

- [x] Build initial and successor endpoint bundles from the fully verified manifest fixtures and matching key material.
- [x] For success, submit one real agent health request and one real ingress health request using successor handshake edges; record the lease generation and active rule digest observed inside the real runtime-owner dispatch.
- [x] For each failure, submit the same two requests against the old generation and prove the old dispatcher/rules remain usable.
- [x] Make the partial-runtime scenario use mismatched/missing generation-bound dispatcher key material so complete endpoint construction fails before a verified successor exists; keep a separate generation-discontinuity case for predecessor coverage.
- [x] Run the focused integration test and confirm all result fields are derived from the real request path.

### Task 4: Production SIGHUP lifecycle trigger

**Files:**
- Modify: `crates/savana-kerneld/src/server.rs`
- Modify: `crates/savana-kerneld/src/signal_control.rs`
- Modify: `crates/savana-kerneld/src/v2_server.rs`
- Modify: `crates/savana-kerneld/src/v2_startup.rs`

**Interfaces:**
- Add `ServerLifecycle::take_v2_rollover_request() -> Result<bool, StableCode>` with a default `false` implementation.
- Add private `V2VerifiedSuccessorPublisher::publish_next_verified_successor() -> Result<(), StableCode>` implemented by the production disk loader.

- [x] Add a failing signal test proving SIGHUP requests rollover without shutdown and is consumed exactly once.
- [x] Add a failing server-loop unit test proving one lifecycle request invokes the successor publisher and a rejected candidate is nonfatal.
- [x] Register/block/unblock SIGHUP with the existing signal owner and implement one-shot request consumption.
- [x] Retain config path, coordinator, runtime, shared runtime owner, and active boot identity in a production successor publisher; on request, reload the complete verified startup/material, build a complete endpoint runtime, construct the verified successor, and publish it.
- [x] Pass the publisher into `run_kerneld_v2_workers`; do not drop the coordinator while workers run.
- [x] Run signal, server, startup, rollover, and real endpoint tests until GREEN.

### Task 5: Verification, report, and commit

**Files:**
- Append: `.superpowers/sdd/2026-08-01-savana-v2-remaining-security-and-connector-implementation/task-2-report.md`

- [x] Run `cargo fmt --all -- --check` and `git diff --check`.
- [x] Run focused rollover, startup, listener/connection/dispatcher, macOS deployment, and macOS startup tests.
- [x] Run `cargo test -p savana-kerneld --all-features --locked`; after the review-only freshness correction, rerun the complete library, rollover, startup, and static suites affected by that correction.
- [x] Append Fix round 1 design invariants, honest RED/GREEN chronology, exact commands, counts, and any residual concern to the report.
- [x] Commit all fix-round changes without pushing.

## Self-review

- Spec coverage: all five review findings map to Tasks 1–4; verification/report/commit map to Task 5.
- Placeholder scan: no TODO/TBD or unspecified implementation step remains.
- Type consistency: listeners consume `V2GenerationRuntime::acquire_endpoint`; verified successor and active bundle both carry `V2LiveEndpointRuntimeV2`; the lifecycle calls only the private verified-successor publisher.
