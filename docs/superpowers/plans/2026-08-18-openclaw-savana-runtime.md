# OpenClaw + Savana Production Runtime Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: use
> `superpowers:subagent-driven-development` when the user explicitly requests
> delegated execution, otherwise use `superpowers:executing-plans` inline.

**Goal:** Ship a fail-closed OpenClaw runtime in the user's `savana-core-rs`
repository that sends only the current inbound text into Savana and returns
only bytes received from Savana's explicit final-release path.

**Architecture:** OpenClaw loads a pinned TypeScript provider/harness. The
harness owns no Savana capability and talks over bounded NDJSON to a Python
child process. Python owns the public Savana SDK objects. A small Rust release
receiver validates execd's existing mTLS provider request, durably binds the
released payload to the sole in-flight turn, and exposes that result to Python
without changing any kernel, daemon, route, or wire format.

**Tech stack:** Rust 1.82, PyO3/maturin, Python 3.12+, TypeScript/Node,
`openclaw@2026.7.1-2`, rustls TLS 1.3, canonical CBOR, NDJSON.

**Approved spec:**
`docs/superpowers/specs/2026-08-18-openclaw-savana-runtime-design.md`

## Non-negotiable repository and security boundaries

- All new code is committed to this `savana-core-rs` worktree on
  `codex/security-capabilities-implementation`.
- Do not clone for editing, commit to, open a PR against, or push to the
  upstream OpenClaw repository.
- Pin the compatibility dependency to exactly `openclaw@2026.7.1-2`.
- Do not change kerneld, agentd, ingressd, approvald, execd routes, ports,
  decisions, or wire encodings.
- Do not add a capability serializer, raw private-document reader, fallback
  model loop, OpenClaw tool surface, or OpenClaw MCP surface.
- Stop for design review if the existing verified release transport cannot
  deliver to the receiver without a daemon or wire change.

## File map

Existing files to modify:

- `Cargo.toml`
- `crates/savana-client/src/error.rs`
- `crates/savana-client/src/execution.rs`
- `crates/savana-client/src/connectors.rs`
- `crates/savana-client/tests/execution_workflows.rs`
- `crates/savana-client/tests/connector_workflows.rs`
- `crates/savana-kernel-protocol/src/v2/kernel_agent_success.rs`
- `crates/savana-core-py/Cargo.toml`
- `crates/savana-core-py/src/client.rs`
- `crates/savana-core-py/src/lib.rs`
- `crates/savana-core-py/python/savana/openclaw_bridge/*`
- `crates/savana-core-py/tests/test_client_sdk.py`
- `crates/savana-core-py/tests/test_openclaw_bridge.py`

New Rust crate:

- `crates/savana-openclaw-release/Cargo.toml`
- `crates/savana-openclaw-release/src/lib.rs`
- `crates/savana-openclaw-release/src/request.rs`
- `crates/savana-openclaw-release/src/reservation.rs`
- `crates/savana-openclaw-release/src/server.rs`
- `crates/savana-openclaw-release/tests/*`

New OpenClaw package, inside this repository:

- `integrations/openclaw-savana-runtime/package.json`
- `integrations/openclaw-savana-runtime/package-lock.json`
- `integrations/openclaw-savana-runtime/tsconfig.json`
- `integrations/openclaw-savana-runtime/openclaw.plugin.json`
- `integrations/openclaw-savana-runtime/index.ts`
- `integrations/openclaw-savana-runtime/src/config.ts`
- `integrations/openclaw-savana-runtime/src/protocol.ts`
- `integrations/openclaw-savana-runtime/src/input.ts`
- `integrations/openclaw-savana-runtime/src/bridge-process.ts`
- `integrations/openclaw-savana-runtime/src/session-bindings.ts`
- `integrations/openclaw-savana-runtime/src/provider.ts`
- `integrations/openclaw-savana-runtime/src/harness.ts`
- `integrations/openclaw-savana-runtime/test/*`
- `integrations/openclaw-savana-runtime/README.md`

## Task 1: Bounded execution and release polling

**Files:**

- Modify: `crates/savana-client/src/execution.rs`
- Modify: `crates/savana-client/tests/execution_workflows.rs`

- [ ] Add failing tests where execution returns `Prepared`, `Dispatching`, and
  `ResultGatePending` before success, and release returns `Prepared` and
  `Dispatching` before success.
- [ ] Assert every refresh preserves the original opaque execution/release ref,
  a mismatch fails closed, terminal states stop polling, and no dispatch is
  repeated.
- [ ] Add a private maximum refresh count and a small poll interval. Every loop
  iteration must call the existing request guard so `run_agent` cancellation
  and deadline remain authoritative.
- [ ] Implement `refresh_execution_until_terminal` and
  `refresh_release_until_terminal`; return `DeadlineExceeded` when the guard or
  bounded poll budget expires.
- [ ] Run:

  ```bash
  cargo test -p savana-client --test execution_workflows
  ```

- [ ] Commit: `fix(client): poll execution and release to terminal state`

The terminal loop must have this shape; it must not redispatch:

```rust
loop {
    self.check_request_guard()?;
    match self.refresh_execution(execution)? {
        Prepared | Dispatching | ResultGatePending => bounded_wait()?,
        terminal => return decode_terminal(terminal),
    }
}
```

## Task 2: Truthful refusal taxonomy

**Files:**

- Modify: `crates/savana-client/src/error.rs`
- Modify: `crates/savana-client/src/execution.rs`
- Modify: `crates/savana-client/tests/execution_workflows.rs`
- Modify: `crates/savana-core-py/src/client.rs`
- Modify: `crates/savana-core-py/tests/test_client_sdk.py`

- [ ] Add a table-driven failing test for every `PublicStableCodeV2` accepted in
  a `ToolDenied` response.
- [ ] Preserve `ApprovalDenied` only for `ApprovalDenied` and
  `PolicyRefused` only for explicit policy/registry/ontology/projection policy
  evidence.
- [ ] Add a redacted `OperationRefused { code }` client error for protocol
  denial codes that do not prove a policy refusal. Never expose reason strings
  from private material.
- [ ] Map the new error through PyO3 with its stable code.
- [ ] Run Rust and Python focused tests.
- [ ] Commit: `fix(client): classify protocol refusals truthfully`

## Task 3: Truthful masked views and connector readiness

**Files:**

- Modify: `crates/savana-kernel-protocol/src/v2/kernel_agent_success.rs`
- Modify: `crates/savana-client/src/connectors.rs`
- Modify: `crates/savana-client/tests/connector_workflows.rs`
- Modify: `crates/savana-core-py/src/client.rs`
- Modify: `crates/savana-core-py/tests/test_client_sdk.py`

- [ ] Add read-only getters for the already-public structured field name,
  masked text, and placeholders. Do not add decoding of private values.
- [ ] Add a Python assertion that `MaskedView.fields` returns immutable tuples
  of masked public projections and that no raw/capability attribute exists.
- [ ] Add a connector snapshot test containing active and inactive entries;
  only active entries may be returned by `list_connectors()`.
- [ ] Implement the minimum getters/projection/filtering required by the tests.
- [ ] Run:

  ```bash
  cargo test -p savana-client --test connector_workflows
  cargo test -p savana-kernel-protocol
  python -m pytest crates/savana-core-py/tests/test_client_sdk.py -q
  ```

- [ ] Commit: `fix(client): expose truthful public projections`

## Task 4: Operation-scoped Python callback failures

**Files:**

- Modify: `crates/savana-core-py/src/client.rs`
- Modify: `crates/savana-core-py/tests/test_client_sdk.py`

- [ ] Add failing tests with two sessions and overlapping callback failures,
  plus a reentrant same-session attempt. Each outer operation must receive only
  its own Python exception.
- [ ] Remove callback-error storage from `PySession`.
- [ ] Construct one fresh `Arc<CallbackErrors>` for every `execute`,
  `run_agent`, `release`, and `register_connector` invocation and consume it in
  that operation's `finish` path only.
- [ ] Run the focused Python suite under the freshly rebuilt extension.
- [ ] Commit: `fix(python): isolate callback failures per operation`

## Task 5: Canonical final-release request decoder

**Files:**

- Modify: `Cargo.toml`
- Create: `crates/savana-openclaw-release/Cargo.toml`
- Create: `crates/savana-openclaw-release/src/lib.rs`
- Create: `crates/savana-openclaw-release/src/request.rs`
- Create: `crates/savana-openclaw-release/tests/request.rs`

- [ ] Copy no code from an OpenClaw repository. Use execd's existing public
  request construction as the compatibility oracle.
- [ ] Add a failing golden-vector test generated by
  `VerifiedProviderRequestV2::bind` for the exact canonical eleven-element
  outer CBOR array.
- [ ] Reject indefinite items, trailing bytes, wrong tags/lengths, duplicate or
  malformed digests, payload lengths over 1 MiB, and digest mismatches.
- [ ] Return an owned `VerifiedReleaseRequest` containing only bounded public
  routing evidence plus the released payload.
- [ ] Run:

  ```bash
  cargo test -p savana-openclaw-release --test request
  ```

- [ ] Commit: `feat(openclaw): decode verified release requests`

## Task 6: Durable single-flight reservation state

**Files:**

- Create: `crates/savana-openclaw-release/src/reservation.rs`
- Create: `crates/savana-openclaw-release/tests/reservation.rs`

- [ ] Add failing tests for reserve, claim, duplicate delivery, expiry,
  `failed_no_effect`, indeterminate sealing, process restart, and cross-turn
  rejection.
- [ ] Enforce one global in-flight final release. Reservation IDs are 256-bit
  random opaque values and are never written into OpenClaw transcripts.
- [ ] Persist a versioned canonical journal using write-temp, `sync_all`, atomic
  rename, and parent-directory `sync_all` before acknowledging delivery.
- [ ] A crash/timeout/indeterminate result seals the receiver until explicit
  reconciliation. Only proven `failed_no_effect` may clear an unclaimed
  reservation.
- [ ] Run the crate tests and commit:
  `feat(openclaw): add durable release reservations`.

## Task 7: Loopback mTLS release receiver

**Files:**

- Create: `crates/savana-openclaw-release/src/server.rs`
- Create: `crates/savana-openclaw-release/tests/server.rs`
- Modify: `crates/savana-core-py/Cargo.toml`
- Modify: `crates/savana-core-py/src/lib.rs`
- Modify: `crates/savana-core-py/src/client.rs`

- [ ] Add a failing integration test using the existing execd TLS fixture and
  `VerifiedRustlsProviderTransportV2` against a loopback receiver.
- [ ] Require TLS 1.3, mutual client authentication, exact client identity or
  SPKI binding, fixed ALPN, loopback address, bounded incremental CBOR input,
  and one request per connection.
- [ ] Claim the sole reservation, durably store payload and evidence, then send
  a canonical non-empty acknowledgement and close. Never acknowledge first.
- [ ] Expose a private PyO3 receiver class for reserve/wait/clear/seal/close;
  keep it out of `savana.__all__` and do not expose payload before claim.
- [ ] Run Rust receiver tests and rebuilt-extension Python tests.
- [ ] Commit: `feat(openclaw): receive released output over pinned mtls`

## Task 8: Closed Python bridge protocol

**Files:**

- Create: `crates/savana-core-py/python/savana/openclaw_bridge/__init__.py`
- Create: `crates/savana-core-py/python/savana/openclaw_bridge/__main__.py`
- Create: `crates/savana-core-py/python/savana/openclaw_bridge/protocol.py`
- Create: `crates/savana-core-py/python/savana/openclaw_bridge/config.py`
- Create: `crates/savana-core-py/tests/test_openclaw_bridge.py`

- [ ] Write failing decoder tests for the closed message union:
  `initialize`, `turn.start`, `approval.answer`, `turn.cancel`,
  `session.reset`, `shutdown` and the corresponding outbound messages.
- [ ] Enforce UTF-8 NDJSON, one top-level object, exact keys, monotonically
  increasing request ids, 1 MiB encoded line, 256 KiB inbound text, and 1 MiB
  released text bounds.
- [ ] Redact all errors and logs; reserve stdout exclusively for protocol
  messages and write bounded redacted diagnostics to stderr.
- [ ] Load only absolute executables/paths and a closed environment allowlist.
- [ ] Run Python tests and commit:
  `feat(openclaw): add bounded Python bridge protocol`.

## Task 9: Python Savana session orchestration

**Files:**

- Create: `crates/savana-core-py/python/savana/openclaw_bridge/runtime.py`
- Create: `crates/savana-core-py/python/savana/openclaw_bridge/auth.py`
- Modify: `crates/savana-core-py/tests/test_openclaw_bridge.py`

- [ ] Use fake SDK objects first to test one live SDK session per
  `(agent identity, OpenClaw session id)`, reset/shutdown closure, serialized
  operations, approval correlation, cancellation, and no handle serialization.
- [ ] Define `WebAuthnBroker` over an inherited, product-owned local descriptor;
  no bootstrap secret or assertion may enter plugin config, transcript, prompt,
  argv, environment, or bridge stdout. Include a deterministic test broker only
  in tests.
- [ ] Implement the real turn flow:
  `Client.session` -> `ingest_text(CHAT_TEXT)` ->
  `run_agent(PRIVATE, RunLimits)` -> choose opaque output -> reserve ->
  `Session.release` -> wait for receiver.
- [ ] Map only redacted progress and stable errors outward. Do not call
  `read_view` on private execution output.
- [ ] Run tests and commit: `feat(openclaw): orchestrate Savana turns`.

## Task 10: OpenClaw package, config, and protocol

**Files:**

- Create: `integrations/openclaw-savana-runtime/package.json`
- Create: `integrations/openclaw-savana-runtime/package-lock.json`
- Create: `integrations/openclaw-savana-runtime/tsconfig.json`
- Create: `integrations/openclaw-savana-runtime/openclaw.plugin.json`
- Create: `integrations/openclaw-savana-runtime/src/config.ts`
- Create: `integrations/openclaw-savana-runtime/src/protocol.ts`
- Create: `integrations/openclaw-savana-runtime/test/config.test.ts`
- Create: `integrations/openclaw-savana-runtime/test/protocol.test.ts`

- [ ] Pin `openclaw` exactly to `2026.7.1-2`; package metadata must point to
  `fyzhao-bit/savana-core-rs`, never `openclaw/openclaw`.
- [ ] Add tests that reject unknown keys, relative Python paths, version drift,
  oversized limits, secret-looking inline values, malformed messages, and
  incompatible bridge negotiation.
- [ ] Implement only the closed schema and discriminated message union needed
  by the approved design.
- [ ] Run `npm ci`, typecheck, and tests, then commit:
  `feat(openclaw): scaffold pinned Savana runtime plugin`.

## Task 11: Child-process and session binding

**Files:**

- Create: `integrations/openclaw-savana-runtime/src/bridge-process.ts`
- Create: `integrations/openclaw-savana-runtime/src/session-bindings.ts`
- Create: `integrations/openclaw-savana-runtime/test/bridge-process.test.ts`
- Create: `integrations/openclaw-savana-runtime/test/session-bindings.test.ts`

- [ ] Test absolute executable spawning with `shell: false`, fixed argv,
  allowlisted environment, stdout-only protocol, stderr redaction, abort,
  crash, duplicate response, and line bounds.
- [ ] Bind `(agentId, sessionId)` to one opaque bridge session id in memory.
  Never persist Savana handles or replay a turn after reconnect.
- [ ] On protocol violation or possible-effect crash, fail closed and retire the
  binding.
- [ ] Run TypeScript tests and commit:
  `feat(openclaw): manage isolated Savana bridge sessions`.

## Task 12: Provider, harness, and exact inbound selection

**Files:**

- Create: `integrations/openclaw-savana-runtime/src/input.ts`
- Create: `integrations/openclaw-savana-runtime/src/provider.ts`
- Create: `integrations/openclaw-savana-runtime/src/harness.ts`
- Create: `integrations/openclaw-savana-runtime/index.ts`
- Create: `integrations/openclaw-savana-runtime/test/harness.test.ts`

- [ ] Compile against the official pinned contract: `AgentHarness.supports`,
  `runAttempt`, `reset`, and `dispose`.
- [ ] Test that only `params.transcriptPrompt` matching
  `currentInboundContext.text` is accepted. Reject assembled `params.prompt`,
  attachments, injected contexts, empty/mismatched input, `params.tools`, and
  any MCP/tool inventory.
- [ ] Register provider `savana`, model `agent`, and harness `savana`. Support
  only explicit model-scoped `agentRuntime.id: \"savana\"` selection.
- [ ] Return progress as bounded visible events and exactly one released
  terminal assistant message. Never return quarantined or unreleased bytes.
- [ ] Implement `reset`/`dispose` as bridge lifecycle operations. A claimed run
  failure is terminal; never invoke the embedded loop or fallback model.
- [ ] Run the compatibility suite and commit:
  `feat(openclaw): register the Savana agent harness`.

## Task 13: End-to-end failure and release binding

**Files:**

- Create: `integrations/openclaw-savana-runtime/test/e2e.test.ts`
- Create: `crates/savana-core-py/tests/test_openclaw_e2e.py`
- Modify deployment fixtures under `tests/fixtures/` only as needed.

- [ ] Test one approved no-effect chat turn, one connector effect turn, one
  denial, one `failed_no_effect`, one quarantined output, one indeterminate
  result, cancellation, bridge crash, receiver crash, duplicate delivery, and
  cross-session delivery.
- [ ] Prove emitted assistant bytes exactly equal the journaled released
  payload and no other test path can produce an assistant reply.
- [ ] Run with existing agentd/approvald/ingressd/execd fixtures. Do not mark
  complete with a mocked status-only release.
- [ ] Commit: `test(openclaw): prove released-only end-to-end delivery`.

## Task 14: Packaging, doctor, and operator documentation

**Files:**

- Create: `integrations/openclaw-savana-runtime/src/doctor.ts`
- Create: `integrations/openclaw-savana-runtime/test/doctor.test.ts`
- Create: `integrations/openclaw-savana-runtime/README.md`
- Modify: `README.md`
- Modify: `README.zh-CN.md`

- [ ] Add a preflight that checks exact OpenClaw/plugin/bridge versions,
  explicit harness selection, tool and MCP denial, no fallback, local service
  origins, private file permissions, active signed connectors, release target,
  and receiver certificate bindings without printing secrets.
- [ ] Document installation from this repository, exact package pinning,
  model-scoped runtime configuration, certificate provisioning, test vs.
  production limits, reset/recovery, and the honest upstream privacy boundary.
- [ ] Explicitly state that OpenClaw upstream is not modified and no code is
  pushed there.
- [ ] Run doctor unit tests and commit:
  `docs(openclaw): document the Savana runtime deployment`.

## Task 15: Frozen-boundary verification and review

- [ ] Run formatting, lint, all Rust workspace tests, Python tests against a
  freshly built extension, TypeScript typecheck/tests, and the local e2e suite.
- [ ] Compare daemon route/port/wire files against the pre-integration commit;
  any behavioral diff is a release blocker.
- [ ] Search artifacts and logs for serialized handles, bootstrap secrets,
  assertions, raw private views, `params.prompt`, OpenClaw tool/MCP catalogs,
  unpinned OpenClaw versions, shell spawning, and upstream repository targets.
- [ ] Review with `superpowers:requesting-code-review`, resolve findings with
  `superpowers:receiving-code-review`, then rerun fresh verification using
  `superpowers:verification-before-completion`.
- [ ] Commit any verification-only fixes, push only this Savana branch, and
  update the existing Savana pull request. Never push to OpenClaw upstream.
