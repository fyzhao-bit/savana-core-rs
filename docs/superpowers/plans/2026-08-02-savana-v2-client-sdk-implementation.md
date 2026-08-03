# Savana V2 Client SDK Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Rust-owned client SDK and a small asynchronous Python facade over Savana's existing Agent, Ingress, and Approval browser services without changing any daemon or wire encoding.

**Architecture:** `savana-client` owns strict local HTTP, canonical CBOR, typed opaque capabilities, browser authentication, ingress, planning, execution, release, connectors, and the bounded agent loop. `savana-core-py` exposes Rust objects and synchronous worker-safe calls; the pure-Python `savana` facade uses `asyncio.to_thread` so application code receives async methods while all protocol state stays in Rust.

**Tech Stack:** Rust 1.82, `savana-kernel-protocol`, `minicbor`, `sha2`, `getrandom`, `zeroize`, PyO3 0.22, Python 3.12+, maturin, pytest.

## Global Constraints

- Do not modify production code in `savana-agentd`, `savana-ingressd`, `savana-approvald`, `savana-kerneld`, or `savana-execd`.
- Do not change an existing HTTP route, port, CBOR tag, canonical encoding, size bound, or daemon state transition.
- The only network destinations are `127.0.0.1:8766`, `127.0.0.1:8767`, and `127.0.0.1:8768`; Jarvis supplies bootstrap material out of band.
- Python never constructs wire requests, decodes CBOR, signs approval settlements, or obtains raw bytes from a general `Handle`.
- Every malformed response, wrong handle kind, policy refusal, indeterminate effect, deadline, and unexpected state fails closed.
- Planner privacy never silently downgrades between `PRIVATE` and `THIRD_PARTY`.
- Ingress methods return committed completion, not a fabricated document handle.
- `PlanStep` is opaque because the current Agent response provides only `AgentPlanStepRefV2`.
- Connector descriptors are canonical deployment artifacts validated in Rust; approval and kernel authorization sign the resulting registry delta, and the SDK owns no signing key.
- Autonomous retry is allowed only after an explicit no-effect failure; indeterminate and effect-succeeded states are never retried.

---

### Task 1: Add canonical client response decoders

**Files:**
- Modify: `crates/savana-kernel-protocol/src/v2/browser_agent.rs`
- Modify: `crates/savana-kernel-protocol/src/v2/browser_ingress.rs`
- Modify: `crates/savana-kernel-protocol/src/v2/browser.rs`
- Modify: `crates/savana-kernel-protocol/src/v2/browser_approval.rs`
- Modify: `crates/savana-kernel-protocol/src/v2/browser_enrollment.rs`
- Modify: `crates/savana-kernel-protocol/src/v2/mod.rs`

**Interfaces:**
- Consumes: the existing server-side `encode_*_response_v2` functions and `V2DecodeContext`.
- Produces: canonical decoders for every response used by the client, plus consuming `into_parts` accessors for zeroizing response fields.

- [ ] **Step 1: Write failing response round-trip and noncanonical tests**

Add tests that call these exact missing functions:

```rust
decode_agent_ui_authentication_complete_browser_response_v2
decode_agent_browser_read_view_response_v2
decode_ingress_ui_authentication_complete_browser_response_v2
decode_ingress_browser_mutation_response_v2
decode_ui_authentication_browser_begin_response_v2
decode_ui_authentication_browser_finish_response_v2
decode_approval_display_view_v2
decode_approval_decision_browser_begin_response_v2
decode_approval_decision_browser_finish_response_v2
decode_begin_enrollment_browser_response_v2
decode_finish_enrollment_browser_response_v2
```

For each family, encode a valid response, decode it, re-encode it byte-for-byte, then append `0x00` and assert decoding fails.

- [ ] **Step 2: Run the protocol tests to verify RED**

Run: `cargo test -p savana-kernel-protocol --all-features browser`

Expected: compilation fails because the client response decoder symbols do not exist.

- [ ] **Step 3: Implement bounded canonical decoders and accessors**

Every decoder follows this shape and uses the existing module-specific maximum:

```rust
pub fn decode_ingress_browser_mutation_response_v2(
    bytes: &[u8],
) -> Result<IngressBrowserMutationResponseV2, ProtocolError> {
    validate_body(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    let value = decode_ingress_mutation(&mut decoder, &mut V2DecodeContext)?;
    if decoder.position() != bytes.len()
        || encode_ingress_browser_mutation_response_v2(value)? != bytes
    {
        return Err(noncanonical());
    }
    Ok(value)
}
```

For zeroizing JSON/options fields, add consuming accessors returning `Zeroizing<Vec<u8>>`; do not add cloning getters.

- [ ] **Step 4: Run focused tests and verify GREEN**

Run: `cargo test -p savana-kernel-protocol --all-features browser`

Expected: all response round-trip, trailing-data, existing request, and wire tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/savana-kernel-protocol/src/v2
git commit -m "feat(protocol): add V2 browser response decoders"
```

### Task 2: Create the Rust client foundation and strict transport

**Files:**
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Create: `crates/savana-client/Cargo.toml`
- Create: `crates/savana-client/src/lib.rs`
- Create: `crates/savana-client/src/error.rs`
- Create: `crates/savana-client/src/handle.rs`
- Create: `crates/savana-client/src/http.rs`
- Create: `crates/savana-client/src/types.rs`
- Create: `crates/savana-client/tests/support/mod.rs`
- Create: `crates/savana-client/tests/http_boundary.rs`
- Create: `crates/savana-client/tests/handle_boundary.rs`

**Interfaces:**
- Consumes: Task 1 response decoders.
- Produces: `Client`, `ClientEndpoints`, `SessionBootstrap`, `BrowserTransport`, `LocalFixedHttpTransport`, `Handle`, all public value/enums/errors, and `tests/support/mod.rs::ScriptedTransport`.

- [ ] **Step 1: Write failing endpoint, HTTP, and handle tests**

Tests require exact endpoint validation and redaction:

```rust
assert!(ClientEndpoints::new(
    "http://localhost:8768",
    "http://localhost:8767",
    "http://localhost:8766",
).is_ok());
assert!(ClientEndpoints::new("http://example.com:8768", "http://localhost:8767", "http://localhost:8766").is_err());
assert_eq!(format!("{:?}", document_handle), "Handle(<opaque:document>)");
assert!(document_handle.expect_plan_step().is_err());
```

The HTTP parser tests reject chunked encoding, duplicate `Content-Length`, bodies over 8 MiB, non-200 status, wrong content type, trailing bytes, and any peer address not loopback.

- [ ] **Step 2: Run the new crate test to verify RED**

Run: `cargo test -p savana-client --test http_boundary --test handle_boundary`

Expected: Cargo fails because `savana-client` and its public types do not exist.

- [ ] **Step 3: Implement the minimal foundation**

Define the transport seam and endpoint closure exactly:

```rust
pub trait BrowserTransport: Send + Sync {
    fn send(&self, request: BrowserRequest) -> Result<BrowserResponse, SavanaError>;
}

pub struct BrowserRequest {
    pub service: BrowserService,
    pub route: BrowserRoute,
    pub origin: BrowserOrigin,
    pub content_type: BrowserContentType,
    pub body: Vec<u8>,
}

pub struct Client {
    endpoints: ClientEndpoints,
    transport: Arc<dyn BrowserTransport>,
    nonces: Arc<dyn NonceSource>,
}
```

`Handle` wraps a private enum of actual protocol capability types plus a private session binding. It exposes `kind()` and redacted `Debug`, but no raw bytes, CBOR, base64, or retagging method. `SessionBootstrap::from_control_plane_token` is the one dedicated parser for a base64url, nonzero, 32-byte `AgentUiAuthenticationTransferCapabilityV2` supplied by the trusted control integration.

- [ ] **Step 4: Run foundation tests and verify GREEN**

Run: `cargo test -p savana-client --test http_boundary --test handle_boundary`

Expected: all strict transport and opaque-handle tests pass.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock crates/savana-client
git commit -m "feat(client): add strict Rust SDK foundation"
```

### Task 3: Implement enrollment and authenticated session bootstrap

**Files:**
- Create: `crates/savana-client/src/auth.rs`
- Create: `crates/savana-client/src/identity.rs`
- Create: `crates/savana-client/src/session.rs`
- Create: `crates/savana-client/tests/auth_state_machine.rs`

**Interfaces:**
- Consumes: `Client`, `SessionBootstrap`, Task 1 auth/enrollment decoders, and `BrowserTransport`.
- Produces: `Identity::load`, `Client::enroll`, `Client::session`, `WebAuthnProvider`, `Session`, and private authenticated Agent/Ingress/Approval tab types.

- [ ] **Step 1: Write failing scripted auth tests**

Script the exact route order:

```text
ApprovalUiAuthenticationAccept (form)
ApprovalUiAuthenticationBegin (CBOR)
ApprovalUiAuthenticationFinish (CBOR)
AgentUiAuthenticationComplete (form)
```

Assert that a wrong response variant, malformed HTML pre-authentication carrier, zero transfer, rejected WebAuthn callback, reused bootstrap, or mismatched return origin returns `AuthError` and never creates `Session`.

- [ ] **Step 2: Run auth tests to verify RED**

Run: `cargo test -p savana-client --test auth_state_machine`

Expected: compilation fails because `Client::session`, `Client::enroll`, and `WebAuthnProvider` do not exist.

- [ ] **Step 3: Implement the state machines**

Use this provider contract:

```rust
pub trait WebAuthnProvider: Send + Sync {
    fn assert_credential(&self, options_json: &[u8]) -> Result<WebAuthnAssertion, AuthError>;
    fn create_credential(&self, options_json: &[u8]) -> Result<WebAuthnAttestation, AuthError>;
}
```

Parse only the existing bounded `data-purpose` and `data-pre-authentication` HTML attributes. `Identity` persists version, credential digest, credential ID, and public credential state as canonical JSON with mode `0600` on Unix; it stores no private key. Session creation consumes `SessionBootstrap` exactly once and retains the returned Agent tab plus initial document capability only inside Rust.

- [ ] **Step 4: Run auth tests and verify GREEN**

Run: `cargo test -p savana-client --test auth_state_machine`

Expected: all session, enrollment, one-shot, origin, and redaction tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/savana-client/src crates/savana-client/tests/auth_state_machine.rs
git commit -m "feat(client): add V2 enrollment and session authentication"
```

### Task 4: Implement ingress, masked views, planning, revoke, and close

**Files:**
- Create: `crates/savana-client/src/approval.rs`
- Create: `crates/savana-client/src/ingress.rs`
- Create: `crates/savana-client/src/agent.rs`
- Create: `crates/savana-client/tests/session_workflows.rs`

**Interfaces:**
- Consumes: authenticated `Session`, `WebAuthnProvider`, Task 1 decoders, existing browser request encoders.
- Produces: `Session::ingest_text`, `ingest_file`, `read_view`, `run_planner`, `revoke`, `close`, `MaskedView`, `Plan`, and opaque `PlanStep`.

- [ ] **Step 1: Write failing workflow tests**

Assert the ingress sequence `PrepareFollowupIngress -> bootstrap/auth ingress -> Begin -> Append* -> Finalize -> approval -> Finalize` with 256 KiB chunks, strictly increasing sequences, SHA-256 digest checking, and abort-on-precommit-error. Assert `RunPlanner` versus `RunPlannerWithThirdPartyMapper` selection is exact and that `PlannerCommitted` is the only accepted planner response.

- [ ] **Step 2: Run workflow tests to verify RED**

Run: `cargo test -p savana-client --test session_workflows`

Expected: compilation fails because the Session workflow methods do not exist.

- [ ] **Step 3: Implement the methods with exact response matching**

Expose these Rust signatures:

```rust
impl Session {
    pub fn ingest_text(&mut self, text: &str, kind: ContentKind) -> Result<(), SavanaError>;
    pub fn ingest_file(&mut self, path: &Path, kind: ContentKind) -> Result<(), SavanaError>;
    pub fn read_view(&mut self, document: &Handle) -> Result<MaskedView, SavanaError>;
    pub fn run_planner(&mut self, privacy: IntentPrivacy) -> Result<Plan, SavanaError>;
    pub fn revoke(&mut self, document: &Handle) -> Result<(), SavanaError>;
    pub fn close(&mut self) -> Result<(), SavanaError>;
}
```

`PlanStep` stores only its session-bound `AgentPlanStepRefV2`. `MaskedView` faithfully represents the existing `AgentViewV2` variants; it does not flatten structured/page/content-state views into invented text.

- [ ] **Step 4: Run session tests and verify GREEN**

Run: `cargo test -p savana-client --test session_workflows`

Expected: ingress, privacy, view, revoke, close, wrong-handle, and failure-order tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/savana-client/src crates/savana-client/tests/session_workflows.rs
git commit -m "feat(client): add V2 ingress and planning workflows"
```

### Task 5: Implement tool execution, release, and connector workflows

**Files:**
- Create: `crates/savana-client/src/execution.rs`
- Create: `crates/savana-client/src/connectors.rs`
- Create: `crates/savana-client/tests/execution_workflows.rs`
- Create: `crates/savana-client/tests/connector_workflows.rs`

**Interfaces:**
- Consumes: `Session`, `Plan`, approval state machine, scripted transport.
- Produces: `ApprovalRequest`, `ExecutionResult`, `ConnectorDescriptor`, `Session::execute`, `release`, `register_connector`, `remove_connector`, and `list_connectors`.

- [ ] **Step 1: Write failing execution and connector tests**

Cover every exact branch: `ToolDenied`, `ToolOpenApproval`, `ToolAuthorized`, `ExecutionDispatched`, each terminal refresh state, release approval/dispatch/refresh, connector approval/finalize, removal, and snapshot. Prove denied approval never dispatches, indeterminate never retries, quarantined output never becomes a `Handle`, and a malformed canonical connector artifact is rejected before transport.

- [ ] **Step 2: Run tests to verify RED**

Run: `cargo test -p savana-client --test execution_workflows --test connector_workflows`

Expected: compilation fails because the workflow methods and values do not exist.

- [ ] **Step 3: Implement exact state matching**

Use decision-only callbacks:

```rust
pub trait ApprovalCallback: Send + Sync {
    fn decide(&self, request: &ApprovalRequest) -> Result<bool, SavanaError>;
}

pub struct ApprovalRequest {
    pub display: String,
    pub purpose: ApprovalPurpose,
}

pub fn execute(
    &mut self,
    plan: &Plan,
    approval: &dyn ApprovalCallback,
) -> Result<ExecutionResult, SavanaError>;

pub fn release(
    &mut self,
    document: &Handle,
    approval: &dyn ApprovalCallback,
) -> Result<ExecutionResult, SavanaError>;
```

Approvald remains the only settlement signer. Connector descriptor loading uses `savana_policy_core::v2::ConnectorDescriptorV2::from_canonical_bytes_for_local_projection` before `RegisterConnector`; snapshot decoding yields session-bound connector-ID handles without exposing canonical snapshot bytes to Python.

- [ ] **Step 4: Run tests and verify GREEN**

Run: `cargo test -p savana-client --test execution_workflows --test connector_workflows`

Expected: all transition, refusal, approval, release, connector, and retry-safety tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/savana-client/src crates/savana-client/tests
git commit -m "feat(client): add execution release and connector workflows"
```

### Task 6: Implement the bounded autonomous agent loop

**Files:**
- Create: `crates/savana-client/src/agent_loop.rs`
- Create: `crates/savana-client/tests/agent_loop.rs`

**Interfaces:**
- Consumes: `run_planner`, `execute`, `ApprovalCallback`.
- Produces: `RunLimits`, `AgentEvent`, `EventCallback`, and `Session::run_agent`.

- [ ] **Step 1: Write failing loop tests**

Script zero-step completion, multi-plan completion, maximum steps, maximum replans, deadline, cancellation, policy refusal, no-effect failure, indeterminate execution, and effect-succeeded output quarantine. Assert only the explicit no-effect branch replans and every event is redacted.

- [ ] **Step 2: Run loop tests to verify RED**

Run: `cargo test -p savana-client --test agent_loop`

Expected: compilation fails because `RunLimits`, `AgentEvent`, and `run_agent` do not exist.

- [ ] **Step 3: Implement the bounded loop**

```rust
pub fn run_agent(
    &mut self,
    privacy: IntentPrivacy,
    limits: RunLimits,
    approval: &dyn ApprovalCallback,
    events: &dyn EventCallback,
) -> Result<ExecutionResult, SavanaError>;
```

Use monotonic `Instant` deadlines, checked counters, zero-step completion, and a cancellation flag checked before every new service request. Never infer or emit an effect for an opaque plan step.

- [ ] **Step 4: Run loop tests and verify GREEN**

Run: `cargo test -p savana-client --test agent_loop`

Expected: all loop limit, event, refusal, and retry-safety tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/savana-client/src/agent_loop.rs crates/savana-client/tests/agent_loop.rs
git commit -m "feat(client): add bounded autonomous agent loop"
```

### Task 7: Expose the Rust SDK through PyO3 and an async Python facade

**Files:**
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Modify: `crates/savana-core-py/Cargo.toml`
- Modify: `crates/savana-core-py/pyproject.toml`
- Modify: `crates/savana-core-py/src/lib.rs`
- Create: `crates/savana-core-py/src/client.rs`
- Create: `crates/savana-core-py/python/savana/__init__.py`
- Create: `crates/savana-core-py/python/savana/client.py`
- Create: `crates/savana-core-py/tests/test_client_sdk.py`

**Interfaces:**
- Consumes: complete `savana-client` Rust API.
- Produces: the eighteen core Python types and fifteen business methods from the approved spec, with async Python Session operations.

- [ ] **Step 1: Write failing Python API tests**

Assert imports, redacted repr, enum values, exception inheritance, no `Handle(bytes)` constructor, exact method names, `asyncio` non-blocking behavior with a scripted Rust transport, callback exception propagation, and session context-manager close behavior.

- [ ] **Step 2: Run Python tests to verify RED**

Run: `python3 -m pytest crates/savana-core-py/tests/test_client_sdk.py -q`

Expected: import or attribute failure because the `savana` package does not exist.

- [ ] **Step 3: Implement PyO3 classes and the async facade**

Keep the existing `savana_core` module and legacy functions compatible. Put client bindings in `src/client.rs`; register them from the existing `#[pymodule]`. The pure Python layer wraps every blocking Rust call like this:

```python
async def run_planner(self, intent_privacy: IntentPrivacy) -> Plan:
    return await asyncio.to_thread(
        self._inner.run_planner,
        intent_privacy.value,
    )
```

`Session.__aexit__` calls `close` exactly once. Rust pyclasses own capabilities; Python value objects expose only redacted public projections.
Add `crates/libsavana-ner`, `crates/savana-client`, and
`crates/savana-core-py` as workspace members so the inherited workspace
metadata is valid and workspace checks cover the wheel.

- [ ] **Step 4: Build the extension and verify GREEN**

Run: `python3 -m maturin develop --manifest-path crates/savana-core-py/Cargo.toml`

Run: `python3 -m pytest crates/savana-core-py/tests/test_client_sdk.py crates/savana-core-py/tests/test_smoke.py -q`

Expected: client SDK tests pass and existing `savana_core` smoke tests still import.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock crates/savana-core-py
git commit -m "feat(python): expose asynchronous Savana V2 client SDK"
```

### Task 8: Document, freeze, and verify the completed SDK

**Files:**
- Modify: `README.md`
- Modify: `README.zh-CN.md`
- Create: `docs/client-sdk-v2.md`
- Modify: `deploy/frozen-v2-core.sha256`

**Interfaces:**
- Consumes: all implemented public APIs.
- Produces: English and Chinese usage, exact interface counts, topology, bootstrap requirements, loop example, and verification evidence.

- [ ] **Step 1: Add compile-checked examples and README interface tables**

Document exactly three external services, fifteen business methods, eighteen core types, opaque PlanStep behavior, ingress completion semantics, explicit release, canonical connector descriptors followed by signed registry deltas, and the loop retry rules. Include a Python example that ingests the goal before `run_agent`.

- [ ] **Step 2: Run focused and workspace verification**

Run:

```bash
cargo fmt --all -- --check
cargo test -p savana-kernel-protocol --all-features
cargo test -p savana-client --all-features
cargo check --workspace --all-targets --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
python3 -m pytest crates/savana-core-py/tests -q
./tools/check-frozen-v2-core.sh
git diff --check
```

Expected: every command exits zero.

- [ ] **Step 3: Prove daemon production sources are unchanged**

Run:

```bash
git diff 00c57bc -- crates/savana-agentd crates/savana-ingressd crates/savana-approvald crates/savana-kerneld crates/savana-execd
```

Expected: no output.

- [ ] **Step 4: Commit documentation and the regenerated frozen digest**

```bash
git add README.md README.zh-CN.md docs/client-sdk-v2.md deploy/frozen-v2-core.sha256
git commit -m "docs(client): document the Savana V2 SDK"
```

- [ ] **Step 5: Review final diff and status**

Run: `git status --short --branch && git log --oneline -10`

Expected: clean worktree with the client SDK commits on `codex/security-capabilities-implementation`; do not push until the user asks.
