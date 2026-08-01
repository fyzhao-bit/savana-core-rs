# Savana V2 Remaining Security and Connector Registration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the remaining production gaps in the accepted declassification v1.1 design, then implement connector registration v1.2 stages R1-R4 without granting runtime registration any final-release authority.

**Architecture:** The declassification work first makes the active signed policy, planner constraints, approval artifact, and deployment trust root load-bearing in production. Connector registration then adds a policy-core-owned canonical descriptor/delta/chain model, a UI-only approval flow in kerneld, a durable authority-signed registry, and independent execd verification; the current dispatch registry digest becomes the verified live chain head. Connector control lives in a distinct control vocabulary, never in `KernelAgentOperationV2`.

**Tech Stack:** Rust 2021 workspace, canonical `minicbor`, Ed25519, SHA-256 domain separation, existing suite-one mutual-authenticated local transport, durable atomic-file stores, HPKE dispatch, Cargo tests, macOS Seatbelt, frozen-core manifests.

## Global Constraints

- Remote specifications are `docs/declassification-v2.md` v1.1 and `docs/connector-registration-v2.md` v1.2 at remote commit `1c35365`.
- Connector self-service ships disabled: an all-zero connector-authority public key means no runtime registration operation exists.
- Runtime registration may mint only `ConnectorTierV2::UserRegistered = 2`; only a deployment generation may mint `DeploymentShipped = 1`.
- Tier-2 effect ceiling is `requested_effects ∩ !EffectSetV2::FINAL_RELEASE`; asking above the ceiling is a decode-time refusal, not clipping.
- Connector ID domains are exactly `savana.connector.deployment.v2\0` and `savana.connector.user.v2\0`.
- Registry delta digest/signature domains use the exact `savana.connector-registry.delta.v2.*\0` family and head domain `savana.connector-registry.head.v2\0`.
- Registry sequences are strictly `+1`; `previous_head_digest` must equal the current verified head; `max_user_connectors = 16`.
- Tier-2 remote hosts use one shared policy-core predicate: lowercase, trailing-dot removal, IDNA/punycode normalization, label-boundary suffix matching, exact-only IP literals; empty allowlist refuses all tier-2 HTTPS connectors.
- Adds require a fresh, principal/challenge/descriptor-bound, single-use `ApprovalPurposeV2::ConnectorRegistration = 4` settlement. Removes require no approval but remain signed, chained, durable, and auditable.
- Registration never authors a declassification rule. A registered connector is not a final-release sink unless a separate deployment-signed tag-5 rule names its exact destination identity.
- No public raw authority constructors, wildcard rules, permissive defaults, general token accessors, or test-only production bypasses.
- All production behavior changes follow RED → GREEN TDD and update the frozen boundary only after reviewing every changed frozen file.

---

### Task 1: Retain and enforce effective signed planner policy

**Files:**
- Modify: `crates/savana-kerneld/src/v2_agent_authority.rs`
- Modify: `crates/savana-input-runtime/src/lib.rs`
- Modify: `crates/savana-kernel-protocol/src/v2/kernel_agent.rs`
- Test: kerneld planner unit tests and `crates/savana-kernel-protocol/tests/v2_kernel_agent_wire.rs`

**Interfaces:**
- `PlannerTicketRecordV2` gains the exact effective `PlannerLimitsV2`, allowed action templates/tool classes, task template, intent, and purpose derived from the signed input policy.
- `commit_planner_value` validates plan encoded size, step count, dependency count, argument count, and every selected action/tool against that retained effective policy before any value or plan-step commit.

- [ ] Write a RED real-authority test whose prepare request is within the signed policy but whose committed plan exceeds one effective limit; assert no planner value, plan step, or consumed ticket is created.
- [ ] Write RED tests for an unlisted action template/tool class and for a valid boundary-equal plan.
- [ ] Run `cargo test -p savana-kerneld planner_commit_enforces_retained_signed_policy --all-features --locked` and confirm the over-limit/unlisted cases are currently accepted.
- [ ] Add a private `EffectivePlannerPolicyV2` value retained on the ticket and a single `validate_committed_plan(&self, plan, encoded_len)` method; do not reconstruct policy from caller data.
- [ ] Run the focused tests and protocol wire tests until GREEN.
- [ ] Commit with `fix(v2): enforce signed planner policy at commit`.

### Task 2: Make declassification rollover production-reachable and atomic

**Files:**
- Modify: `crates/savana-kerneld/src/v2_declassification_policy.rs`
- Modify: `crates/savana-kerneld/src/v2_startup.rs`
- Modify: `crates/savana-kerneld/src/bootstrap.rs`
- Modify: `crates/savana-kerneld/src/policy_runtime.rs`
- Test: `crates/savana-kerneld/tests/policy_rollover.rs`

**Interfaces:**
- Add a production `VerifiedV2DeclassificationSuccessorV2` constructed only from a fully verified successor deployment bundle: new active manifest pin, canonical rule-set bytes, declassification trust root, generation, and time.
- Extend the existing `PolicyRolloverCoordinator` with an internal V2 hook that closes admission, validates the full deployment successor, checks manifest-pin equality and `validate_predecessor`, then swaps the shared `ActiveDeclassificationRuleSetV2` snapshot only when the complete runtime bundle is publishable.
- Any failure retains the old complete runtime and active rule set; there is no standalone caller that can swap only rules.

- [ ] Add a RED integration test through the real rollover coordinator proving a valid generation successor changes the active digest used by ingress and agent paths.
- [ ] Add RED rollback, wrong pin, bad signature, expired set, and partial-runtime failure cases; assert old admission resumes with the old digest.
- [ ] Run `cargo test -p savana-kerneld --test policy_rollover --all-features --locked` and capture the missing production hook failure.
- [ ] Implement the verified bundle and one atomic publication point. Remove or subsume any rules-only swap path that lacks manifest-pin validation.
- [ ] Run focused rollover, startup, and macOS deployment tests until GREEN.
- [ ] Commit with `fix(v2): publish declassification successors atomically`.

### Task 3: Complete deployment authenticated pre-state binding

**Files:**
- Modify: `crates/savana-policy-core/src/v2/deployment_authorization.rs`
- Modify: `crates/savana-policy-core/src/v2/deployment_transaction_core.rs`
- Modify: `crates/savana-policy-core/src/bin/support/mod.rs`
- Test: `crates/savana-policy-core/tests/v2_security_state_manifest.rs`
- Test: `crates/savana-policy-core/tests/v2_deployment_transaction_intent.rs`

**Interfaces:**
- `validate_authenticated_pre_state` accepts four root digests in fixed order: deployment, activation, release, declassification.
- The production support caller supplies the authenticated declassification root digest from the same bootstrap TCB lock used by transaction staging.

- [ ] Add RED tests for missing, zero, swapped, and wrong-version declassification root digests at the public pre-state validator and the production support path.
- [ ] Run the two targeted test binaries and confirm the fourth digest is not enforced.
- [ ] Thread the fourth digest through all constructors/callers and require exact equality before authorization.
- [ ] Run targeted tests until GREEN and commit with `fix(v2): bind declassification root in prestate`.

### Task 4: Render the exact gated approval artifact

**Files:**
- Modify: `crates/savana-kernel-protocol/src/v2/signed.rs`
- Modify: `crates/savana-kernel-protocol/src/v2/browser_approval.rs`
- Modify: `crates/savana-kernel-protocol/src/v2/browser_assets.rs`
- Modify: `crates/savana-approvald/src/protocol_service.rs`
- Modify: `crates/savana-approvald/src/ui_authority.rs`
- Test: approval protocol/browser/approvald tests

**Interfaces:**
- Define `BoundedApprovalDisplayTextV2`: canonical UTF-8 bytes, no forbidden controls, bounded by `MAX_APPROVAL_DISPLAY_BYTES_V2`; its bytes are exactly the bytes gated by `BuildApprovalDisplay`, signed, persisted, returned, and placed into DOM with `textContent`. Text inputs use their canonical text; binary inputs use one complete reversible canonical base64 representation rather than truncation or a length summary. Tag-5 final-release declassification still gates the underlying raw release bytes separately.
- `ApprovalDisplayViewV2` returns this exact text plus the nonzero declassification node digest. `printable()` is not used for the human approval artifact.

- [ ] Add a RED browser behavior test containing more than 64 bytes and non-ASCII text; assert the complete exact string appears and no `bytes:<len>`/hex summary is rendered.
- [ ] Add RED invalid UTF-8/control/tamper tests that refuse before displaying or settling.
- [ ] Run focused browser and approvald tests and confirm current length-only rendering failure.
- [ ] Implement the bounded text type and dedicated renderer; keep protocol diagnostics separate from the human artifact.
- [ ] Run focused tests until GREEN and commit with `fix(v2): render exact gated approval text`.

### Task 5: Replace synthetic declassification regressions with real state tests

**Files:**
- Modify: `crates/savana-kerneld/src/v2_agent_authority.rs`
- Modify: `crates/savana-policy-core/tests/v2_declassification_rules.rs`
- Test: kerneld real authority/durable tests

**Interfaces:**
- The tool gate-order test must execute the real authority, durable journal, and quota ledger; no closure/counter-only assertion.
- Rule-set matrix fixtures use 65 distinct sorted rules for overflow, explicit lower-sequence rollback, nested noncanonical encoding mutations, and exact expected errors.

- [ ] Add RED real-state gate refusal test and record the pre/post dispatch state and quota reservation.
- [ ] Correct the rule matrix so every vector isolates one failure cause.
- [ ] Run focused kerneld and rule-set tests until GREEN.
- [ ] Commit with `test(v2): make declassification regressions load bearing`.

### Task 6: Implement connector descriptor, tier, host policy, delta, and chain

**Files:**
- Create: `crates/savana-policy-core/src/v2/connector_registry.rs`
- Modify: `crates/savana-policy-core/src/v2/mod.rs`
- Modify: `crates/savana-policy-core/src/v2/deployment_limits.rs`
- Modify: `crates/savana-policy-core/Cargo.toml` only for a pinned IDNA normalization dependency if the workspace has no equivalent
- Create test: `crates/savana-policy-core/tests/v2_connector_registry.rs`

**Interfaces:**
```rust
pub enum ConnectorTierV2 { DeploymentShipped = 1, UserRegistered = 2 }
pub enum ConnectorTransportV2 {
    Stdio { package_digest: Digest32V2 },
    Https { canonical_url: BoundedConnectorUrlV2, tls_identity_pin: Digest32V2 },
}
pub struct ConnectorDescriptorV2 { /* private verified fields */ }
pub struct ConnectorRegistryDeltaV2 { /* private canonical signed delta */ }
pub struct ConnectorRegistryStateV2 { /* genesis + verified deltas + active map */ }
pub fn user_tier_host_allowed_v2(host: &str, allowlist: &[BoundedConnectorHostV2]) -> Result<bool, G4Error>;
```
- Canonical byte constructors decode, validate, recompute IDs, enforce tier ceilings and limits, verify the connector-authority signature, and never expose raw signing constructors outside test support.

- [ ] Write RED canonical/limits/ID-domain/tier-ceiling/host-vector/chain tests covering CF1-CF5, CF7, CF9, and CF10.
- [ ] Run `cargo test -p savana-policy-core --test v2_connector_registry --all-features --locked` and confirm the types are absent.
- [ ] Implement the minimal canonical objects, shared host predicate, hard limit 16, chain head, add/remove/replay/fork behavior, and zero-authority disabled state.
- [ ] Run focused tests until GREEN and commit with `feat(v2): add verified connector registry chain`.

### Task 7: Extend deployment/G7 material with connector authority and standing constraints

**Files:**
- Modify: `crates/savana-kerneld/src/v2_startup.rs`
- Modify: `crates/savana-kerneld/src/bin/savana-development-build-inputs.rs`
- Modify: `crates/savana-kerneld/src/v2_agent_authority.rs`
- Modify: `crates/savana-policy-core/src/v2/production.rs`
- Modify: `crates/savana-policy-core/src/v2/dispatch.rs`
- Modify: deployment fixtures and macOS validators

**Interfaces:**
- G7 material carries `connector_registry_genesis_digest`, connector-authority key id/public key, and sorted user-tier host allowlist.
- `KernelG7RuntimeV2` owns a shared verified connector registry head. Every effect lease and dispatch core binds its current head, not a stale startup constant.
- The connector-authority private key remains kernel-owned and distinct from envelope/correlation keys; zero public key disables registration.

- [ ] Add RED startup/identity tests for wrong key id, key reuse, zero-key disabled behavior, unsorted/duplicate hosts, and narrowed allowlist inerting existing tier-2 entries.
- [ ] Implement loading and runtime material with exact key-distinctness checks.
- [ ] Run startup/deployment tests until GREEN and commit with `feat(v2): pin connector registry authority in g7`.

### Task 8: Add a UI-only connector control and approval vocabulary

**Files:**
- Create: `crates/savana-kernel-protocol/src/v2/kernel_connector.rs`
- Modify: `crates/savana-kernel-protocol/src/v2/mod.rs`
- Modify: `crates/savana-kernel-protocol/src/v2/signed.rs`
- Modify: `crates/savana-kernel-protocol/src/v2/browser_agent.rs`
- Modify: `crates/savana-agentd/src/browser_authority.rs`
- Modify: `crates/savana-agentd/src/kernel_client.rs`
- Modify: `crates/savana-approvald/src/protocol_service.rs`
- Test: protocol wire and browser-origin tests

**Interfaces:**
- `KernelConnectorControlOperationV2` is a separate closed enum and is absent from `KernelAgentOperationV2`.
- `ApprovalPurposeV2::ConnectorRegistration = 4` and `ApprovalBindingV2::ConnectorRegistration { descriptor_digest, previous_head_digest }` use distinct envelope/settlement domains.
- Proposal carries a one-use UI authorization bound to the descriptor digest and authenticated principal; no LLM/agent operation can mint or submit it.

- [ ] Add RED compile/vocabulary tests proving connector proposal is absent from agent operations and unauthenticated/non-UI proposals are unencodable or refused.
- [ ] Add RED canonical wire/purpose/domain/cross-purpose settlement tests.
- [ ] Implement the control and browser flow; build a canonical human display containing tier, name, full transport identity, complete tools, and effects, then route it through tag-3 declassification.
- [ ] Run protocol/agentd/approvald tests until GREEN and commit with `feat(v2): add ui-only connector approval control`.

### Task 9: Implement kerneld pending registration and durable signed chain

**Files:**
- Create: `crates/savana-kerneld/src/v2_connector_authority.rs`
- Create: `crates/savana-policy-core/src/v2/connector_store.rs`
- Modify: `crates/savana-kerneld/src/v2_core_services.rs`
- Modify: `crates/savana-kerneld/src/v2_startup.rs`
- Modify: `crates/savana-kerneld/src/v2_agent_authority.rs` only for shared active-tool/head publication
- Test: kerneld connector authority/store tests

**Interfaces:**
- `KernelConnectorAuthorityV2` implements `propose_add`, `authorize_add`, `apply_approved_add`, `remove`, and `snapshot` over opaque one-use handles.
- Add applies only after exact descriptor approval settlement verification; remove needs a UI-authenticated control session but no approval settlement.
- `DurableConnectorRegistryStoreV2` atomically persists canonical deltas and recovers to genesis on missing/corrupt state; it never reconstructs an unverified widening.

- [ ] Write RED settlement replay, A-for-B, expired, deny, crash-boundary, remove, restart, capacity, and generation-narrowing tests.
- [ ] Implement pending state, delta signing, atomic store, idempotent exact replay, and active head publication.
- [ ] Run focused tests until GREEN and commit with `feat(v2): persist approved connector registry updates`.

### Task 10: Make execd independently verify and converge on the registry

**Files:**
- Modify: `crates/savana-kernel-protocol/src/v2/kernel_executor.rs`
- Create: `crates/savana-execd/src/connector_registry.rs`
- Modify: `crates/savana-execd/src/connector_runtime.rs`
- Modify: `crates/savana-execd/src/provider_transport.rs`
- Modify: `crates/savana-execd/src/protocol_service.rs`
- Test: execd registry/convergence/transport tests

**Interfaces:**
- Execd accepts canonical genesis+deltas over the existing mutually authenticated kernel-executor channel, independently verifies every signature/policy constraint, and atomically publishes a verified head.
- Dispatch is refused unless `dispatch_core.executor_connector_registry_digest == execd.active_head`.
- HTTPS connect revalidates canonical host, current allowlist, TLS identity pin, and refuses cross-host redirects; unprovisioned package/transport identity fails before effect.

- [ ] Add RED behind-by-one, wrong signature, wiped state, narrowed host, TLS pin, redirect, and recovery tests.
- [ ] Implement independent verifier/store and head equality at dispatch admission.
- [ ] Run execd and kernel-executor tests until GREEN and commit with `feat(v2): verify connector registry independently in execd`.

### Task 11: Publish connector tools through G4 without release authority

**Files:**
- Modify: `crates/savana-policy-core/src/v2/descriptor.rs`
- Modify: `crates/savana-policy-core/src/v2/production.rs`
- Modify: `crates/savana-kerneld/src/v2_agent_authority.rs`
- Modify: `crates/savana-kerneld/src/v2_startup.rs`
- Test: connector/declassification composition and policy attack matrix

**Interfaces:**
- Active tool resolution accepts either deployment-manifest-signed descriptors or connector-chain-authenticated tier-2 descriptors; provenance records the source tier.
- Tier-2 tools remain subject to G4 intent, G5 policy/approval, G7 quota/effect lease, and their descriptor effects never include `FINAL_RELEASE`.
- A tag-5 release still requires a deployment-signed declassification rule naming the exact destination; connector registration cannot create one.

- [ ] Add RED composition tests: registered tool becomes proposable; final-release remains refused without a rule; promotion changes connector ID; an old rule does not follow promotion; runtime cannot mint tier 1.
- [ ] Implement connector-chain descriptor activation and active-tool atomic refresh.
- [ ] Run policy-core/kerneld attack matrices until GREEN and commit with `feat(v2): admit tiered connector tools through g4`.

### Task 12: Freeze, document, verify, and review

**Files:**
- Modify: `README.md`
- Modify: `README.zh-CN.md`
- Modify: `deploy/frozen-v2-core.files`
- Modify: `deploy/frozen-v2-core.sha256`
- Modify: `crates/savana-kerneld/src/bin/savana-development-build-inputs.rs`
- Modify: `crates/savana-kerneld/tests/macos_deployment.rs`
- Modify: `deploy/macos/development/install.sh`
- Modify: `deploy/macos/development/validate.sh`

- [ ] Document the external connector-control interfaces, disabled-by-default deployment fields, tier limits, removal behavior, convergence semantics, and the fact that registration never grants final release.
- [ ] Run `cargo fmt --all -- --check`.
- [ ] Run `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`.
- [ ] Run `cargo test --workspace --all-targets --all-features --locked` outside the parent sandbox where Unix sockets/Seatbelt require it.
- [ ] Run `cargo build --workspace --release --locked` and record the intentional refusal of the incompatible all-features release combination without weakening its compile guards.
- [ ] Run `RUSTDOCFLAGS='-D warnings' cargo doc --workspace --all-features --no-deps --locked`.
- [ ] Run the mandatory native macOS Seatbelt target with `SAVANA_REQUIRE_NATIVE_MACOS_SANDBOX_TEST=1` outside the parent sandbox.
- [ ] Review every frozen path, regenerate hashes using repository conventions, run `tools/check-frozen-v2-core.sh`, then run its adversarial checker suite.
- [ ] Run `git diff --check`, inspect the complete diff, request independent security review, fix all Critical/Important findings, and commit the verified result.
