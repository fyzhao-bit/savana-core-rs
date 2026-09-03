# OpenClaw MCP Per-Call Approval Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Route final releases over a distinct signed execd transport and require every OpenClaw-triggered Savana approval to be decided through the trusted inherited approval broker instead of chat.

**Architecture:** Execd selects one of two verified provider transports from the already authenticated `DispatchEnvelopeKindV2`, before a provider attempt can emit bytes. The OpenClaw bridge delegates the human decision to the product-owned FD 3 broker; the unchanged Rust SDK then completes the exact Approvald WebAuthn ceremony, while OpenClaw receives only lifecycle state and released output.

**Tech Stack:** Rust 1.82, rustls 0.23, Serde closed-schema JSON, Python 3.12, PyO3 public SDK, TypeScript, Vitest, macOS launchd development deployment.

**Spec:** `docs/superpowers/specs/2026-08-19-openclaw-mcp-per-call-approval-design.md`

## Global Constraints

- OpenClaw registers no tool and receives no MCP catalog, tool argument, private result, bootstrap token, WebAuthn material, or kernel capability.
- Every tool execution, including read-only MCP calls, uses a fresh kernel approval; connector registration remains a separate manual workflow.
- Chat messages never authorize an approval.
- Public loopback ports 8765-8768 and provider frame V2 do not change.
- Split routing must fail before provider effect start on every kind/connector mismatch.
- Old non-OpenClaw bootstraps remain `legacy-shared`; `split-final-release` requires complete, distinct release provider material.
- No automatic retry, replanning, tool substitution, or fallback follows approval denial or an indeterminate effect.
- Rust workspace code remains `unsafe_code = "forbid"` and uses the pinned dependency set in `Cargo.lock`.

---

## File Map

- `crates/savana-execd/src/connector_runtime.rs`: dispatch-kind provider router and runtime integration.
- `crates/savana-execd/src/daemon.rs`: closed bootstrap DTO, distinct credentials, and verified transport construction.
- `crates/savana-kerneld/src/bin/savana-development-build-inputs.rs`: canonical development split-routing template.
- `crates/savana-policy-core/src/bin/savana-development-material.rs`: digest-bound development provider material.
- `deploy/macos/development/install.sh`: distinct development release TLS identities and private keys.
- `deploy/macos/development/validate.sh`: build-input checks for the new TLS material and split mode.
- `deploy/systemd/savana-execd.service`: production final-release private-key credential binding.
- `crates/savana-core-py/python/savana/openclaw_bridge/auth.py`: trusted approval broker request/response.
- `crates/savana-core-py/python/savana/openclaw_bridge/config.py`: fixed signed execd bootstrap path used by preflight.
- `crates/savana-core-py/python/savana/openclaw_bridge/runtime.py`: synchronous SDK callback routing through the broker.
- `crates/savana-core-py/python/savana/openclaw_bridge/protocol.py`: removal of chat approval messages.
- `crates/savana-core-py/tests/test_openclaw_bridge.py`: broker correlation, denial, timeout, and duplicate-call tests.
- `crates/savana-core-py/tests/test_openclaw_e2e.py`: two-call/final-release trusted approval acceptance.
- `integrations/openclaw-savana-runtime/src/protocol.ts`: bounded protocol without `approval.answer` or display-bearing approval messages.
- `integrations/openclaw-savana-runtime/src/bridge-process.ts`: bridge lifecycle without an approval-answer writer.
- `integrations/openclaw-savana-runtime/src/harness.ts`: waiting-only harness with no Approve/Deny chat prompt.
- `integrations/openclaw-savana-runtime/src/doctor.ts`: live execd split-target and TLS-material agreement.
- `integrations/openclaw-savana-runtime/test/*.test.ts`: protocol, bridge, harness, doctor, and end-to-end regression.
- `integrations/openclaw-savana-runtime/README.md`: exact operator boundary and trusted approval broker contract.
- `docs/openclaw-deployment-acceptance-gate.md`: implementation evidence and remaining live-deployment evidence.
- `deploy/frozen-v2-core.files`, `deploy/frozen-v2-core.sha256`: reviewed frozen boundary after all tests pass.

### Task 1: Dispatch-kind provider routing

**Files:**
- Modify: `crates/savana-execd/src/connector_runtime.rs`

**Interfaces:**
- Consumes: `DispatchEnvelopeKindV2`, `ProviderTransportV2`, and the existing optional `PreparedConnectorDispatchV2`.
- Produces: `VerifiedProviderTransportRouterV2::legacy(tool)` and `VerifiedProviderTransportRouterV2::split(tool, final_release)`, plus `with_transport(kind, has_connector, operation)`.

- [ ] **Step 1: Write routing tests that name the cross-route bugs**

  Add test transports with observable IDs and tests equivalent to:

  ```rust
  #[test]
  fn split_router_never_sends_tool_execution_to_release_transport() {
      let router = split_router();
      let selected = router
          .with_transport(DispatchEnvelopeKindV2::ToolExecution, true, |transport| {
              transport.verified_deployment_target()
          })
          .unwrap();
      assert_eq!(selected.canonical_url().as_str(), "https://tool.example/");
  }

  #[test]
  fn split_router_never_sends_final_release_to_tool_transport() {
      let router = split_router();
      let selected = router
          .with_transport(DispatchEnvelopeKindV2::FinalRelease, false, |transport| {
              transport.verified_deployment_target()
          })
          .unwrap();
      assert_eq!(selected.canonical_url().as_str(), "https://release.example/savana/final-release");
  }
  ```

  Add literal failure assertions for `ToolExecution` without a connector and `FinalRelease` with a connector.

- [ ] **Step 2: Run the focused tests and verify RED**

  Run: `cargo test -p savana-execd connector_runtime::tests -- --nocapture`

  Expected: compilation fails because `VerifiedProviderTransportRouterV2` and `with_transport` do not exist.

- [ ] **Step 3: Implement the minimal router**

  Use the following closed shape:

  ```rust
  enum VerifiedProviderTransportRouterV2 {
      LegacyShared(Mutex<Box<dyn ProviderTransportV2>>),
      Split {
          tool: Mutex<Box<dyn ProviderTransportV2>>,
          final_release: Mutex<Box<dyn ProviderTransportV2>>,
      },
  }

  impl VerifiedProviderTransportRouterV2 {
      fn with_transport<T>(
          &self,
          kind: DispatchEnvelopeKindV2,
          has_connector: bool,
          operation: impl FnOnce(&mut dyn ProviderTransportV2) -> Result<T, ExecdProtocolServiceErrorV2>,
      ) -> Result<T, ExecdProtocolServiceErrorV2>;
  }
  ```

  Validate `(ToolExecution, true)` and `(FinalRelease, false)` before locking. Replace the runtime's single `transport` mutex with this router, and move the existing target verification, descriptor issue, durable effect boundary, provider call, and completion logic into the selected closure without changing their order.

- [ ] **Step 4: Run focused and package tests and verify GREEN**

  Run: `cargo test -p savana-execd connector_runtime::tests -- --nocapture`

  Run: `cargo test -p savana-execd`

  Expected: all tests pass; the mutation “swap the two split match arms” fails the two selection tests.

- [ ] **Step 5: Commit the routing unit**

  ```bash
  git add crates/savana-execd/src/connector_runtime.rs
  git commit -m "feat(execd): split final release provider routing"
  ```

### Task 2: Signed split-provider bootstrap and credentials

**Files:**
- Modify: `crates/savana-execd/src/daemon.rs`
- Modify: `crates/savana-kerneld/src/bin/savana-development-build-inputs.rs`
- Modify: `crates/savana-policy-core/src/bin/savana-development-material.rs`
- Modify: `deploy/macos/development/install.sh`
- Modify: `deploy/macos/development/validate.sh`
- Modify: `deploy/systemd/savana-execd.service`
- Modify: `crates/savana-core-py/python/savana/openclaw_bridge/config.py`
- Modify: `integrations/openclaw-savana-runtime/src/doctor.ts`
- Modify: `integrations/openclaw-savana-runtime/test/doctor.test.ts`

**Interfaces:**
- Consumes: `VerifiedProviderTransportRouterV2` from Task 1 and existing `ProviderDtoV2` fields.
- Produces: closed `ProviderRoutingModeDtoV2::{LegacyShared, SplitFinalRelease}`, optional `final_release_provider`, and the fixed credential `final-release-provider-tls-private-key-v2.der`.

- [ ] **Step 1: Write bootstrap parsing and construction tests**

  Add daemon tests using complete literal JSON values for these cases:

  ```rust
  #[test]
  fn legacy_bootstrap_defaults_to_shared_provider() {
      let bootstrap: BootstrapDtoV2 = serde_json::from_value(legacy_bootstrap_json()).unwrap();
      assert_eq!(bootstrap.provider_routing_mode, ProviderRoutingModeDtoV2::LegacyShared);
      assert!(bootstrap.final_release_provider.is_none());
  }

  #[test]
  fn split_bootstrap_requires_a_final_release_provider() {
      let mut value = legacy_bootstrap_json();
      value["provider_routing_mode"] = serde_json::json!("split-final-release");
      assert!(validate_provider_routing(&serde_json::from_value(value).unwrap()).is_err());
  }
  ```

  Add failures for a release provider in legacy mode and identical tool/release endpoint-binding or credential-identity digests in split mode.

- [ ] **Step 2: Run focused tests and verify RED**

  Run: `cargo test -p savana-execd daemon::implementation::tests -- --nocapture`

  Expected: compilation fails because routing DTOs and validation do not exist.

- [ ] **Step 3: Implement closed bootstrap validation and transport construction**

  Add:

  ```rust
  #[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
  #[serde(rename_all = "kebab-case")]
  enum ProviderRoutingModeDtoV2 {
      #[default]
      LegacyShared,
      SplitFinalRelease,
  }
  ```

  Add `#[serde(default)] provider_routing_mode` and
  `#[serde(default)] final_release_provider: Option<ProviderDtoV2>` to the
  closed bootstrap. Load the second private key only in split mode. Refactor
  the existing provider builder into one helper that still calls
  `VerifiedRustlsProviderTransportV2::from_verified_manifest` for every
  provider. Require distinct canonical URL, socket address, endpoint-binding
  digest, credential identity, client leaf digest, and private-key credential
  in split mode.

  Add the absolute, root-owned `execd_bootstrap_path` to the closed bridge
  deployment configuration. The doctor reads that exact file after the live
  authenticated SDK probe succeeds and requires `split-final-release`, the
  exact release URL/address, matching server-certificate SPKI, matching root
  and client-certificate digests, and a client leaf SPKI matching
  `expected_client_spki_pin_path`.

- [ ] **Step 4: Verify RED for generated development material**

  Add assertions to the existing development build/deployment tests that the
  generated execd JSON contains:

  ```json
  {
    "provider_routing_mode": "split-final-release",
    "final_release_provider": {
      "address": "127.0.0.1:43191",
      "server_name": "release.savana-development.invalid",
      "canonical_url": "https://release.savana-development.invalid:43191/savana/final-release"
    }
  }
  ```

  Run: `cargo test -p savana-kerneld --bin savana-development-build-inputs`

  Expected: failure because the generated object does not contain the split fields.

- [ ] **Step 5: Generate distinct macOS development TLS material**

  Generate release server and release client certificates from the existing
  runtime CA, install their DER/SPKI material under the fixed development
  config tree, and install the release client PKCS#8 key as
  `credentials/execd/final-release-provider-tls-private-key-v2.der` with the
  same closed ownership model as the current execd provider key. Patch both
  providers' digests in `savana-development-material` using a generalized
  endpoint-binding helper that takes the literal address, server name, root,
  client certificate, and ALPN.

- [ ] **Step 6: Run deployment tests and verify GREEN**

  Run: `cargo test -p savana-kerneld --bin savana-development-build-inputs`

  Run: `cargo test -p savana-policy-core --bin savana-development-material`

  Run: `cargo test -p savana-execd`

  Run on macOS: `bash -n deploy/macos/development/install.sh deploy/macos/development/validate.sh`

  Expected: all tests and syntax checks pass.

- [ ] **Step 7: Commit the signed deployment unit**

  ```bash
  git add crates/savana-execd/src/daemon.rs crates/savana-kerneld/src/bin/savana-development-build-inputs.rs crates/savana-policy-core/src/bin/savana-development-material.rs deploy/macos/development/install.sh deploy/macos/development/validate.sh deploy/systemd/savana-execd.service
  git commit -m "feat(deploy): bind final release provider separately"
  ```

### Task 3: Trusted approval broker protocol

**Files:**
- Modify: `crates/savana-core-py/python/savana/openclaw_bridge/auth.py`
- Modify: `crates/savana-core-py/python/savana/openclaw_bridge/runtime.py`
- Modify: `crates/savana-core-py/python/savana/openclaw_bridge/protocol.py`
- Modify: `crates/savana-core-py/tests/test_openclaw_bridge.py`

**Interfaces:**
- Consumes: the existing inherited FD 3 `WebAuthnBroker` framed Unix stream and public SDK `ApprovalRequest(display, purpose)`.
- Produces: `WebAuthnBroker.decide_approval(display: str, purpose: str, deadline_unix_ms: int) -> bool`; no bridge `approval.answer` command.

- [ ] **Step 1: Write broker decision tests**

  Use a real socketpair broker fixture and assert the exact request:

  ```python
  {
      "protocol_version": 1,
      "type": "approval.decide",
      "approval_id": "ERERERERERERERERERERERERERERERERERERERERERE",
      "display": "Tool execution; connector: mail; tool: search",
      "purpose": "tool_execution",
      "deadline_unix_ms": 1_900_000_000_000,
  }
  ```

  Return an exact `approval.decision` with the same ID and `approved: true`.
  Add tests rejecting a mismatched ID, unknown purpose, late deadline,
  duplicate response key, oversized display, and non-boolean decision.

- [ ] **Step 2: Run the focused Python tests and verify RED**

  Run: `python3 -m pytest crates/savana-core-py/tests/test_openclaw_bridge.py -q`

  Expected: failure because `decide_approval` does not exist.

- [ ] **Step 3: Implement the closed broker exchange**

  Validate the four closed purposes, NFC/control-free display, 16 KiB encoded
  display maximum, future deadline, fresh 32-byte base64url correlation, exact
  response keys, and constant correlation equality. Reuse `_roundtrip` so
  decision and WebAuthn exchanges remain serialized on the inherited stream.

- [ ] **Step 4: Replace `ApprovalRouter` chat correlation with broker correlation**

  Construct `ApprovalRouter` with the trusted broker. In `__call__`, emit only:

  ```python
  {
      "protocol_version": PROTOCOL_VERSION,
      "request_id": self._turn_request_id,
      "type": "turn.event",
      "event": "approval_required",
      "purpose": purpose,
  }
  ```

  Then call `decide_approval`. Remove `_PendingApproval`, `answer`, and the
  `approval.answer` inbound protocol branch. Any exception returns `False`.

- [ ] **Step 5: Prove one broker decision per SDK callback**

  Add a runtime test whose fake `run_agent` invokes the approval callback
  twice with two tool displays and whose fake `release` invokes it once with
  `final_release`. Assert three distinct broker IDs, two tool purposes, one
  release purpose, and terminal denial when the second decision is false.

- [ ] **Step 6: Run Python tests and verify GREEN**

  Run: `python3 -m pytest crates/savana-core-py/tests/test_openclaw_bridge.py -q`

  Run: `python3 -m pytest crates/savana-core-py/tests/test_openclaw_e2e.py -q`

  Expected: all tests pass and no test sends `approval.answer`.

- [ ] **Step 7: Commit the trusted approval unit**

  ```bash
  git add crates/savana-core-py/python/savana/openclaw_bridge/auth.py crates/savana-core-py/python/savana/openclaw_bridge/runtime.py crates/savana-core-py/python/savana/openclaw_bridge/protocol.py crates/savana-core-py/tests/test_openclaw_bridge.py crates/savana-core-py/tests/test_openclaw_e2e.py
  git commit -m "feat(openclaw): require trusted approval broker"
  ```

### Task 4: Waiting-only OpenClaw adapter

**Files:**
- Modify: `integrations/openclaw-savana-runtime/src/protocol.ts`
- Modify: `integrations/openclaw-savana-runtime/src/bridge-process.ts`
- Modify: `integrations/openclaw-savana-runtime/src/harness.ts`
- Modify: `integrations/openclaw-savana-runtime/test/protocol.test.ts`
- Modify: `integrations/openclaw-savana-runtime/test/bridge-process.test.ts`
- Modify: `integrations/openclaw-savana-runtime/test/harness.test.ts`
- Modify: `integrations/openclaw-savana-runtime/test/e2e.test.ts`

**Interfaces:**
- Consumes: `turn.event { event: "approval_required", purpose }`.
- Produces: lifecycle presentation only; no `onApproval`, approval-answer writer, user-input question, or chat-answer parser.

- [ ] **Step 1: Write protocol rejection tests**

  Assert that encoding an object with `type: "approval.answer"` throws
  `ProtocolError`, decoding `type: "approval.request"` throws, and the bounded
  `approval_required` event still decodes successfully.

- [ ] **Step 2: Run focused TypeScript tests and verify RED**

  Run: `npm test -- --run test/protocol.test.ts test/bridge-process.test.ts test/harness.test.ts`

  Working directory: `integrations/openclaw-savana-runtime`

  Expected: rejection tests fail because chat approval is still supported.

- [ ] **Step 3: Remove chat approval from the protocol and bridge**

  Delete `approval.answer` from `PluginToBridgeMessage`, key validation, and
  the bridge writer. Delete outbound `approval.request` decoding and pending
  approval ID state. Keep `approval_required` as a lifecycle event.

- [ ] **Step 4: Remove the harness approval prompt**

  Delete `ApprovalCoordinator`, `deliverAgentHarnessUserInputPrompt`, and the
  `queueMessage` approval parser. Make `queueMessage` reject all messages while
  the run is active. Progress rendering may show `approval_required`, but it
  must expose neither display text nor Approve/Deny controls.

- [ ] **Step 5: Run TypeScript tests and verify GREEN**

  Run: `npm run typecheck`

  Run: `npm test`

  Working directory: `integrations/openclaw-savana-runtime`

  Expected: typecheck and all tests pass; searching production files for
  `approval.answer`, `ApprovalCoordinator`, and `Savana approval` returns no
  matches.

- [ ] **Step 6: Commit the waiting-only adapter unit**

  ```bash
  git add integrations/openclaw-savana-runtime/src integrations/openclaw-savana-runtime/test
  git commit -m "fix(openclaw): remove chat approval authority"
  ```

### Task 5: End-to-end release route and deployment gate

**Files:**
- Modify: `crates/savana-core-py/tests/test_openclaw_e2e.py`
- Modify: `crates/savana-openclaw-release/tests/server.rs`
- Modify: `integrations/openclaw-savana-runtime/test/e2e.test.ts`
- Modify: `integrations/openclaw-savana-runtime/README.md`
- Modify: `docs/openclaw-deployment-acceptance-gate.md`

**Interfaces:**
- Consumes: split execd routing, trusted approval broker decisions, and the existing Rust release reservation.
- Produces: automated acceptance evidence and an operator-readable remaining live-deployment gate.

- [ ] **Step 1: Write the split-route acceptance test**

  Start two distinct loopback TLS receivers using distinct canonical URLs and
  pins. Dispatch a tool query and a final-release query through the real
  runtime router. Assert the tool receiver observes only the tool frame and
  the release receiver observes only the reserved release frame. Mutating the
  kind/connector pairing must leave both receivers without an accepted frame.

- [ ] **Step 2: Run the acceptance test and verify RED**

  Run: `cargo test -p savana-execd -p savana-openclaw-release -- --nocapture`

  Expected: the new acceptance test fails until Tasks 1 and 2 are fully wired.

- [ ] **Step 3: Complete the real broker/release E2E fixture**

  Use a real socketpair for FD 3. The fixture must answer three sequential
  `approval.decide` requests and the following Approvald WebAuthn assertion
  requests, then deliver one reserved release over the real Rust receiver.
  Assert OpenClaw observes lifecycle events and one released assistant value,
  but no display text, tool result, approval ID, or broker frame.

- [ ] **Step 4: Run all focused acceptance suites and verify GREEN**

  Run: `cargo test -p savana-execd -p savana-openclaw-release`

  Run: `python3 -m pytest crates/savana-core-py/tests/test_openclaw_bridge.py crates/savana-core-py/tests/test_openclaw_e2e.py -q`

  Run: `npm run typecheck && npm test`

  Working directory for the last command: `integrations/openclaw-savana-runtime`

  Expected: every command passes.

- [ ] **Step 5: Update operator documentation truthfully**

  Document the FD 3 `approval.decide` contract, split execd provider material,
  one approval per tool call, terminal denial, and the prohibition on chat
  approval. Change the acceptance gate from “design missing” to an
  evidence-based checklist. Keep any unperformed live installation or
  hardware-WebAuthn check explicitly pending.

- [ ] **Step 6: Commit the acceptance unit**

  ```bash
  git add crates/savana-core-py/tests/test_openclaw_e2e.py crates/savana-openclaw-release/tests/server.rs integrations/openclaw-savana-runtime/test/e2e.test.ts integrations/openclaw-savana-runtime/README.md docs/openclaw-deployment-acceptance-gate.md
  git commit -m "test(openclaw): prove approved split release delivery"
  ```

### Task 6: Frozen-boundary review and full verification

**Files:**
- Modify: `deploy/frozen-v2-core.files`
- Modify: `deploy/frozen-v2-core.sha256`
- Modify only if public documentation changed: `README.md`, `README.zh-CN.md`

**Interfaces:**
- Consumes: all completed tasks and repository frozen-core tooling.
- Produces: reviewed hash closure and final verification evidence.

- [ ] **Step 1: Format without changing behavior**

  Run: `cargo fmt --all -- --check`

  If it reports differences, run `cargo fmt --all`, inspect the diff, and rerun the check.

- [ ] **Step 2: Run the Rust workspace tests**

  Run: `cargo test --workspace --all-targets`

  Expected: all tests pass with no ignored new failures.

- [ ] **Step 3: Run Python and TypeScript suites**

  Run: `python3 -m pytest crates/savana-core-py/tests pytests -q`

  Run: `npm ci && npm run typecheck && npm test`

  Working directory for the npm command: `integrations/openclaw-savana-runtime`

  Expected: all tests pass.

- [ ] **Step 4: Review and update the frozen file closure**

  Run: `tools/check-frozen-v2-core.sh`

  Inspect every changed frozen file against the approved spec. Regenerate
  `deploy/frozen-v2-core.files` and `deploy/frozen-v2-core.sha256` with the
  repository's existing deterministic procedure, then rerun:

  Run: `tools/check-frozen-v2-core.sh`

  Expected: exit code 0.

- [ ] **Step 5: Verify no secrets or generated binaries are staged**

  Run: `git status --short`

  Run: `git diff --check`

  Run: `git diff --cached --stat`

  Expected: only source, tests, documentation, deployment metadata, and frozen hashes are present; no `.so`, wheel, certificate private key, runtime state, or generated credential is tracked.

- [ ] **Step 6: Commit the frozen boundary and verification report**

  ```bash
  git add deploy/frozen-v2-core.files deploy/frozen-v2-core.sha256 README.md README.zh-CN.md
  git commit -m "docs(openclaw): close split transport security review"
  ```
