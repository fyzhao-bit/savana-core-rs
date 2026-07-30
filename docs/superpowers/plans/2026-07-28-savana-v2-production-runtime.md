# Savana V2 Production Runtime Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the existing Rust G1-G7 state machines into bounded, authenticated, crash-recoverable daemon runtimes with process isolation for untrusted jobs.

**Architecture:** Each daemon owns mutable durable state on one dedicated owner thread reached through a bounded typed command queue. Network workers authenticate, decode one role-specific request, submit one command, write at most one response, and never hold a state lock across IPC. Agentd and execd each own one process-wide reference-counted EffectGate coordinator. Parser/OCR and connector codecs execute as one-job child processes over inherited anonymous channels.

**Tech Stack:** Rust 1.82, `std::sync::mpsc`, Unix-domain sockets, `rustix`/`nix`, canonical CBOR, Ed25519, AES-GCM, HMAC-SHA256, platform sandbox adapters.

## Global Constraints

- Preserve the exactly-ten-crate workspace boundary.
- Keep `#![forbid(unsafe_code)]` in every crate.
- Use bounded queues, bounded frames, checked arithmetic, and fail-closed errors.
- Process one request and at most one response per authenticated application connection.
- JavaScript and Python receive only the closed JARVIS DTOs and opaque `TaskHandleV2`.
- Original data, normalization, G1-G3, policy state, and vault material stay in Rust.
- No worker process receives a service key, credential, reusable listener, or network authority.
- A poisoned lock, uncertain durable commit, missing rollback anchor, missing sandbox, or failed recovery check makes the affected service unavailable.
- Every production behavior is added test-first and the failing test is observed before implementation.

---

### Task 1: Bounded single-owner daemon state runtime

**Files:**
- Create: `crates/savana-kerneld/src/v2_state_owner.rs`
- Modify: `crates/savana-kerneld/src/lib.rs`
- Test: `crates/savana-kerneld/src/v2_state_owner.rs`

**Interfaces:**
- Produces: `StateOwnerV2<C, R>::spawn(name, capacity, handler)`, `StateOwnerV2::request(command, deadline)`, and deterministic shutdown.
- Guarantees: one handler invocation at a time, bounded admission, deadline rejection, panic/fatal fail-stop, and joined owner thread.

- [x] **Step 1: Write failing owner-thread tests**

  Add tests proving 128 concurrent callers never overlap the handler, the bounded queue returns `RuntimeBusy`, expired requests are not executed, and owner failure permanently returns `RuntimeUnavailable`.

- [x] **Step 2: Run the focused tests and verify RED**

  Run `cargo test -p savana-kerneld v2_state_owner --all-features`.
  Expected: compilation fails because `v2_state_owner` and `StateOwnerV2` do not exist.

- [x] **Step 3: Implement the minimal generic state owner**

  Use `sync_channel`, a private response channel per command, a monotonic deadline supplied by the caller, one named `JoinHandle`, and an atomic lifecycle state. Do not expose the queue sender or handler.

- [x] **Step 4: Run focused and kerneld tests**

  Run `cargo test -p savana-kerneld --all-targets --all-features`.
  Expected: all tests pass.

---

### Task 2: Closed authenticated V2 application dispatch

**Files:**
- Create: `crates/savana-kernel-protocol/src/v2/service.rs`
- Modify: `crates/savana-kernel-protocol/src/v2/mod.rs`
- Create: `crates/savana-kerneld/src/v2_dispatch.rs`
- Modify: `crates/savana-kerneld/src/lib.rs`
- Modify: `crates/savana-kerneld/src/server.rs`
- Test: `crates/savana-kernel-protocol/tests/v2_service_wire.rs`
- Test: `crates/savana-kerneld/src/v2_dispatch.rs`

**Interfaces:**
- Produces: canonical `ApplicationRequestEnvelopeV2`, `ApplicationResponseEnvelopeV2`, `KernelOperationV2`, and closed stable errors.
- Consumes: mutually authenticated peer role, boot IDs, service identities, request ID, deadline, and active manifest/generation.

- [x] **Step 1: Write failing canonical-wire and role-confusion tests**

  Use hand-authored CBOR vectors for health, ingress acceptance, dispatch preparation, receipt reconciliation, and vault release. Reject non-canonical CBOR, wrong role, wrong boot, unknown tag, trailing bytes, oversized frame, expired deadline, and a second request on the same connection.

- [x] **Step 2: Run protocol tests and verify RED**

  Run `cargo test -p savana-kernel-protocol --test v2_service_wire`.
  Expected: compilation fails because the V2 service envelope and codec are absent.

- [x] **Step 3: Implement closed canonical envelopes**

  Add exact array lengths and operation discriminants. Decode once with compiled collection/byte limits and re-encode equality before constructing an operation.

- [x] **Step 4: Write failing dispatcher ownership tests**

  Prove authenticated worker threads can only submit typed commands to `StateOwnerV2`; they cannot borrow durable stores, signing keys, rollback anchors, or EffectGate descriptors.

- [ ] **Step 5: Implement dispatcher integration**

  Negotiate protocol major 2 during the existing authenticated handshake, bind the endpoint role to the verified service identity, acquire a policy generation lease, decode one V2 envelope, send one owner command, return one signed/closed response, and close the stream before releasing the lease.

- [x] **Step 6: Run protocol and daemon tests**

  Run `cargo test -p savana-kernel-protocol --all-targets` and `cargo test -p savana-kerneld --all-targets --all-features`.
  Expected: all tests pass.

---

### Task 3: Process-wide EffectGate coordinators

**Files:**
- Create: `crates/savana-agentd/src/effect_gate.rs`
- Modify: `crates/savana-agentd/src/lib.rs`
- Create: `crates/savana-execd/src/effect_gate.rs`
- Modify: `crates/savana-execd/src/lib.rs`

**Interfaces:**
- Produces: crate-private `EffectGateCoordinatorV2::from_shared_only_descriptor`, `acquire(kind, deadline)`, `fence()`, and RAII `EffectGateGuardV2`.
- Guarantees: the OS shared lock is taken on active count `0 -> 1`, released on `1 -> 0`, new acquisition stops after fence intent, and no caller can clone/close/unlock the descriptor.

- [x] **Step 1: Write failing overlapping-holder tests**

  Prove two guards share one OS lock, dropping the first does not unlock, dropping the final guard unlocks, fence intent blocks barging, and poisoned state fails closed.

- [x] **Step 2: Run focused tests and verify RED**

  Run `cargo test -p savana-agentd effect_gate` and `cargo test -p savana-execd effect_gate`.
  Expected: compilation fails because the coordinators do not exist.

- [x] **Step 3: Implement both service-local coordinators**

  Store the only owned descriptor inside a private `Mutex` state with `active_count`, `closing`, and `poisoned`. Use POSIX record locks through safe `rustix`/`nix` APIs and a `Condvar` for drain/fence.

- [x] **Step 4: Bind guards to effect operations**

  Require a live guard before agentd planner markers and kernel operations 29/34, and before execd `Prepared` through terminal receipt persistence. No public API accepts a boolean or digest as a substitute for the guard.

- [x] **Step 5: Run both crate suites**

  Run `cargo test -p savana-agentd --all-targets` and `cargo test -p savana-execd --all-targets`.
  Expected: all tests pass.

---

### Task 4: Durable recovery coordinator

**Files:**
- Create: `crates/savana-kerneld/src/v2_recovery.rs`
- Modify: `crates/savana-kerneld/src/lib.rs`
- Modify: `crates/savana-policy-core/src/v2/durable.rs`
- Modify: `crates/savana-agentd/src/durable.rs`
- Modify: `crates/savana-execd/src/durable.rs`
- Modify: `crates/savana-vault/src/durable.rs`

**Interfaces:**
- Produces: `RecoverySnapshotV2`, `RecoveryActionV2`, and `RecoveryCoordinatorV2::scan`.
- Guarantees: recovery never mints a nonce/capability, never repeats an external effect, and only advances using authenticated stored receipts and exact semantic bindings.

- [ ] **Step 1: Write failing crash-matrix tests**

  Cover crash before/after agent task registration, approval consumption, kernel dispatch WAL, execd `Prepared`, effect start, terminal receipt, vault dispatching, and final commit.

- [x] **Step 2: Run focused tests and verify RED**

  Run `cargo test -p savana-kerneld v2_recovery --all-features`.
  Expected: compilation fails because recovery snapshots/actions are absent.

- [x] **Step 3: Add read-only durable projections**

  Each durable service emits a capability-free projection containing typed durable IDs, state discriminants, exact digests, nonce identity, sequence, and authenticated head. It emits no secret bytes or resolver token.

- [x] **Step 4: Implement deterministic reconciliation**

  Join projections by typed IDs and exact digests. Emit only `CompleteKnownSuccess`, `CompleteKnownNoEffect`, `QuarantineIndeterminate`, `AbortBeforeEffect`, or `Noop`. Reject contradictions and rollbacks.

- [x] **Step 5: Apply recovery through the state owner**

  Execute actions serially, persist each local transition before requesting the next daemon transition, and re-scan after every applied action.

- [x] **Step 6: Run all durable-store suites**

  Run the policy-core, agentd, approvald, execd, vault, and kerneld tests.
  Expected: all tests pass.

---

### Task 5: One-job parser/OCR and connector worker processes

**Files:**
- Create: `crates/savana-ingressd/src/worker_protocol.rs`
- Create: `crates/savana-ingressd/src/worker_supervisor.rs`
- Create: `crates/savana-ingressd/src/bin/savana-parser-worker.rs`
- Modify: `crates/savana-ingressd/src/lib.rs`
- Create: `crates/savana-execd/src/worker_protocol.rs`
- Create: `crates/savana-execd/src/worker_supervisor.rs`
- Create: `crates/savana-execd/src/bin/savana-connector-worker.rs`
- Modify: `crates/savana-execd/src/lib.rs`

**Interfaces:**
- Produces: signed parent job descriptors, bounded page/prepared-request frames, exactly one terminal outcome, and one-job child supervisors.
- Guarantees: anonymous inherited channel only, no listener, no service key, no persistent credential, closed descriptor inheritance, deadline/resource ceilings, kill-and-reap on protocol violation.

- [x] **Step 1: Write failing private-ABI tests**

  Reject wrong parent signature, wrong ephemeral key, repeated terminal frame, page after terminal, oversized frame, descriptor/job mismatch, and parser/connector domain confusion.

- [x] **Step 2: Run focused tests and verify RED**

  Run `cargo test -p savana-ingressd worker` and `cargo test -p savana-execd worker`.
  Expected: compilation fails because worker protocol/supervisors are absent.

- [x] **Step 3: Implement canonical one-job protocols**

  Use length-prefixed canonical CBOR over inherited stdin/stdout-equivalent descriptors. Generate one ephemeral attestation seed in the child, zeroize it, and bind the public key to the parent descriptor before accepting output.

- [x] **Step 4: Implement supervisor lifecycle**

  Spawn the fixed installed binary path, clear the environment, close unrelated descriptors, enforce one descriptor and one terminal transcript, apply deadline/output limits, and kill/reap on any failure.

- [x] **Step 5: Add platform sandbox verification hooks**

  Require an injected verified Linux or macOS sandbox launcher. A missing or unverifiable launcher returns `SandboxUnavailable`; direct unsandboxed production spawn is impossible.

- [x] **Step 6: Run crate and process integration tests**

  Run both worker binaries against valid and malicious transcripts.
  Expected: valid one-job transcript succeeds; all malformed/reuse/network-authority fixtures fail closed.

---

### Task 6: Daemon binaries and deployment trust adapters

**Files:**
- Create: `crates/savana-agentd/src/main.rs`
- Create: `crates/savana-approvald/src/main.rs`
- Create: `crates/savana-ingressd/src/main.rs`
- Create: `crates/savana-execd/src/main.rs`
- Create: `crates/savana-kerneld/src/deployment_trust.rs`
- Modify: `crates/savana-kerneld/src/main.rs`
- Create: `crates/savana-kerneld/src/bin/savana-deploy.rs`
- Create: `crates/savana-kerneld/src/bin/savana-deploy-watchdog.rs`
- Create: `crates/savana-approvald/src/bin/savana-approvalctl.rs`

**Interfaces:**
- Produces: service-manager-only startup, fixed socket/port ownership, platform keystore handles, rollback-anchor handles, code-identity/sandbox measurement, restart activation, and watchdog health.
- Guarantees: no key file fallback in production V2, no caller-selected socket/route/key/manifest, and no online bootstrap-TCB replacement.

- [x] **Step 1: Write failing deployment-manifest and startup tests**

  Reject wrong UID/GID, writable executable/config parents, unmeasured binary closure, missing keystore/rollback anchor, wrong socket owner/mode, wrong code identity, sandbox mismatch, and stale effect-fence epoch.

- [x] **Step 2: Run focused tests and verify RED**

  Run `cargo test -p savana-kerneld deployment_trust --all-features`.
  Expected: compilation fails because deployment trust adapters are absent.

- [x] **Step 3: Implement narrow platform traits and verified startup state**

  Platform adapters return opaque signing/decryption/rollback handles and measured identities. Construct daemon state only from a completely verified release manifest and active-state projection.

- [ ] **Step 4: Implement fixed daemon entry points**

  Each binary accepts only its root-owned config path, verifies service identity before binding, creates its state owner, performs recovery, then publishes readiness.

- [ ] **Step 5: Implement deploy/watchdog/approvalctl authority separation**

  Keep deployment write authority out of daemons, EffectGate exclusive authority out of agentd/execd, and approval credential administration out of approvald’s public browser route.

- [ ] **Step 6: Run startup and CLI tests**

  Run all binary integration tests.
  Expected: approved fixtures start and terminate cleanly; every authority-confusion fixture fails before socket publication.

---

### Task 7: Concurrency, crash, sandbox, and end-to-end security gates

**Files:**
- Create: `crates/savana-kerneld/tests/v2_concurrency.rs`
- Create: `crates/savana-kerneld/tests/v2_crash_matrix.rs`
- Create: `crates/savana-kerneld/tests/v2_end_to_end.rs`
- Create: `crates/savana-ingressd/tests/worker_isolation.rs`
- Create: `crates/savana-execd/tests/worker_isolation.rs`
- Modify: `README.md`

**Interfaces:**
- Consumes all production entry points from Tasks 1-6.
- Produces release evidence for bounded concurrency, crash safety, role isolation, and process isolation.

- [x] **Step 1: Add concurrent owner/rollover/EffectGate adversarial tests**

  Exercise 128 concurrent requests, writer intent, queue saturation, deadline expiry, process gate A/B overlap, fence drain, and state-owner termination.

- [ ] **Step 2: Add deterministic crash-point tests**

  Terminate processes at every durable transition, restart from the same stores/anchors, and assert no second task, approval consumption, nonce, effect, or final release.

- [ ] **Step 3: Add real process-isolation tests**

  Verify worker UID/profile, closed descriptor set, denied network creation, bounded memory/CPU/output, one-job exit, and absence of persistent key material on Linux and macOS hosts that advertise the corresponding platform capability.

- [ ] **Step 4: Add full authenticated V2 flow**

  Exercise `ingress -> G1/G2 -> G3 -> vault -> G4/G5 -> G6 -> G7 -> execd -> reconciliation -> final vault release`, including signed kerneld-to-agentd status correlation.

- [x] **Step 5: Run release gates**

  Run:

  ```bash
  rustup run 1.82.0 cargo fmt --all -- --check
  rustup run 1.82.0 cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
  rustup run 1.82.0 cargo test --workspace --all-targets --all-features --locked
  rustup run 1.82.0 cargo doc --workspace --all-features --no-deps
  ```

  Expected: every command exits zero with no warning.

- [x] **Step 6: Update completion claims**

  Document only routes and platform controls exercised by the passing product evidence. Keep unsupported platform claims explicitly closed.
