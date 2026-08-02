# V2 Live Kernel Client Rollover Fix Round 2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:executing-plans` to implement this plan task by task.

**Goal:** Keep the already-running agentd and ingressd Suite-One kerneld
clients usable across one fully verified live kerneld generation successor,
with atomic fail-closed authority replacement, exactly one recovery retry, and
proactive SIGHUP reload.

**Architecture:** Each client becomes a cloneable stable transport context plus
a shared `Arc<RwLock<Arc<GenerationAuthority>>>`. A private fixed-path daemon
loader produces only fully verified startups. The holder validates exact +1
continuity under its publication lock, swaps one immutable authority pointer,
and retries only a first-attempt handshake-stage rejection. SIGHUP invokes the
same serialized reload entry point.

**Tech Stack:** Rust 1.82, std Unix sockets and synchronization,
`signal-hook`, existing Savana Suite-One protocol and deployment-trust types,
Cargo workspace tests.

**Design:**
`docs/superpowers/specs/2026-08-01-savana-v2-live-kernel-client-rollover-design.md`

## Global constraints

- Keep exact Suite-One transcript equality and all existing closed public
  errors.
- No public production setter or constructor may accept successor edge fields.
- Verify full fixed-path startup and exact successor continuity before a single
  atomic pointer swap.
- One immutable authority snapshot is used for a whole connection.
- Reload only after a first-attempt handshake-stage rejection; reconnect and
  retry exactly once.
- Failed or concurrent stale reload leaves the prior authority intact.
- The post-publication integration probe must use the exact agentd and ingressd
  client objects created before publication.
- Append exact RED/GREEN evidence under `## Fix round 2` in the existing Task 2
  report and do not push.

---

## Task 1: Lock the long-running client regression with strict RED tests

**Files:**

- Modify: `crates/savana-agentd/src/kernel_client.rs`
- Modify: `crates/savana-ingressd/src/kernel_client.rs`

- [ ] Add focused tests that create each real client from generation one,
  configure a test-only full-startup successor source, serve a generation-two
  Suite-One health endpoint, and require the same client object to succeed.
- [ ] Add failure tests for malformed/partial/rollback/skipped/identity-changing
  successor sources. Require reload failure, unchanged generation-one
  selection, and a subsequent successful generation-one request.
- [ ] Add tests proving cloned clients share one publication, a request retains
  one coherent snapshot, application failures never trigger reload, and a
  handshake recovery performs at most one retry.
- [ ] Run strict RED before production implementation:

```bash
cargo test -p savana-agentd kernel_client::tests::preexisting_client_adopts_verified_successor -- --exact --nocapture
cargo test -p savana-ingressd kernel_client::tests::preexisting_client_adopts_verified_successor -- --exact --nocapture
```

Expected: both fail because current clients retain immutable generation-one
authority. Record exact commands and failures in the report.

---

## Task 2: Implement the agentd atomic generation-authority holder

**Files:**

- Modify: `crates/savana-agentd/Cargo.toml`
- Modify: `crates/savana-agentd/src/kernel_client.rs`
- Modify: `crates/savana-agentd/src/lib.rs`

- [ ] Move the edge and task-authority verification key into one immutable
  redacted generation snapshot. Move socket, boot IDs, native binding, signing
  key, public key, and closed edge ID into stable shared context.
- [ ] Add a private verified-startup loader trait/callback and a daemon-only
  constructor that seeds continuity from `VerifiedDaemonStartupV2`. Keep the
  old non-reloadable constructor for existing callers and tests.
- [ ] Validate same installation; checked exact +1 sequence/generation/fence;
  stable ABI and six runtime identities; exact client/kerneld service locks;
  exact edge/listener/native-peer/key lock; retained boot/key/task-authority
  bindings. Recheck against active authority under the write lock and publish
  with one pointer replacement.
- [ ] Make the client cloneable. Snapshot one authority per operation and use
  it for the handshake plus all task-authority response verification.
- [ ] Split attempts into closed internal handshake-rejection and terminal
  failures. Serialize reloads, recognize a concurrent successful advance,
  reconnect with fresh nonce/ephemeral key, and retry once only.
- [ ] Expose only feature-gated test support needed by the kerneld integration
  probe; do not expose raw authority in production.
- [ ] Run focused agent client tests:

```bash
cargo test -p savana-agentd kernel_client::tests -- --nocapture
```

Expected: PASS.

---

## Task 3: Implement the ingressd atomic generation-authority holder

**Files:**

- Modify: `crates/savana-ingressd/Cargo.toml`
- Modify: `crates/savana-ingressd/src/kernel_client.rs`
- Modify: `crates/savana-ingressd/src/lib.rs`

- [ ] Apply the same stable/shared split, complete continuity validation,
  publication lock discipline, clone semantics, handshake-only recovery, and
  retry-once bound to the ingress client.
- [ ] Keep the ingress health and operation response semantics unchanged and
  keep all public errors closed.
- [ ] Expose only feature-gated verified-startup test support for the kerneld
  integration probe.
- [ ] Run focused ingress client tests:

```bash
cargo test -p savana-ingressd kernel_client::tests -- --nocapture
```

Expected: PASS.

---

## Task 4: Wire private fixed-path loaders and SIGHUP into both daemons

**Files:**

- Modify: `crates/savana-agentd/src/daemon.rs`
- Modify: `crates/savana-ingressd/src/daemon.rs`
- Modify: `deploy/systemd/savana-agentd.service`
- Modify: `deploy/systemd/savana-ingressd.service`
- Modify deployment/lifecycle tests that own these service contracts

- [ ] Factor each daemon's existing bounded bootstrap read, DTO parse,
  `load_native_startup`, and loaded-config verification into a private loader
  that always uses the compiled-in bootstrap path.
- [ ] Capture stable retained boot IDs, native binding, key material, and
  bootstrap authority identity in the client holder; build one agent client
  and clone it for dispatcher/browser.
- [ ] Prepare `signal-hook` SIGHUP handling before workers and listeners run.
  Spawn a private signal thread that invokes the same client reload method and
  treats rejection as nonfatal without logging authority details.
- [ ] Add systemd `ExecReload` SIGHUP actions and source-contract tests. Preserve
  all other lifecycle signals.
- [ ] Test the reload lifecycle helper without process-global test races, then
  run:

```bash
cargo test -p savana-agentd daemon -- --nocapture
cargo test -p savana-ingressd daemon -- --nocapture
```

Expected: PASS.

---

## Task 5: Replace the fresh-client rollover probe with pre-existing clients

**Files:**

- Modify: `crates/savana-kerneld/Cargo.toml`
- Modify: `crates/savana-kerneld/src/v2_startup.rs`
- Modify: `crates/savana-kerneld/src/lib.rs` if probe evidence needs extension
- Modify: `crates/savana-kerneld/tests/policy_rollover.rs`

- [ ] Propagate `test-support` to agentd and ingressd.
- [ ] Construct both real package clients from the generation-one verified
  startup before publishing the successor. Prove generation-one typed health
  requests through the real listeners.
- [ ] Publish the kerneld generation-two live bundle, serve generation-two
  listeners, and issue typed health requests through those exact same client
  objects. The client successor source must return the same fully verified
  generation-two startup used to build the server bundle.
- [ ] For rejected rollover scenarios, prove the clients retain generation one
  and still make real generation-one requests. Extend probe observations only
  with closed boolean/counter evidence if necessary.
- [ ] Run the exact real-rollover test:

```bash
cargo test -p savana-kerneld --features test-support --test policy_rollover v2_valid_generation_successor_serves_real_agent_and_ingress_requests -- --exact --nocapture
```

Expected: PASS, with generation-two agent and ingress observations coming from
pre-publication client objects.

---

## Task 6: Verify the affected surface and record evidence

**Files:**

- Modify (ignored evidence):
  `.superpowers/sdd/2026-08-01-savana-v2-remaining-security-and-connector-implementation/task-2-report.md`

- [ ] Run focused and affected package suites:

```bash
cargo test -p savana-agentd --all-features
cargo test -p savana-ingressd --all-features
cargo test -p savana-kerneld --features test-support --test policy_rollover
cargo test -p savana-kerneld --features test-support --lib v2_startup
cargo test -p savana-kerneld --all-features --test macos_startup
cargo test -p savana-kerneld --all-features --test macos_deployment
```

- [ ] Run all-features compile, formatting/diff, and one broader suite:

```bash
cargo check --workspace --all-targets --all-features
cargo test --workspace --all-features
cargo fmt --all -- --check
git diff --check
```

- [ ] Append `## Fix round 2` with exact RED/GREEN commands and outcomes.
- [ ] Use `superpowers:verification-before-completion`, request independent
  code review, resolve findings, and rerun affected verification.
- [ ] Commit the complete implementation and report the commit hash, changed
  files, tests, residual risks, no-push status, and confirmation that unrelated
  work was untouched.
