# Savana V2 Planner Privacy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement `docs/planner-privacy-v2.md` so an external planner receives only a freshly relabeled, closed structural graph while intent, semantic catalog data, the deterministic decode table, and the kernel envelope nonce remain outside the planner request.

**Architecture:** `savana-agentd` performs two strictly one-way model exchanges. A mapper selected by the user’s intent-trust boundary receives a nonce-free intent projection plus the local semantic catalog and returns a bounded abstract workflow; agentd validates it, mints fresh node IDs, and sends only the resulting structural graph to plannerd. Agentd then validates the returned topological order, deterministically decodes it into the existing `PlannerPlanV2`, and injects the locally held `envelope_nonce`; kerneld and all kernel service wire schemas remain unchanged.

**Tech Stack:** Rust 1.82, canonical CBOR with `minicbor`, rustls 0.23 mTLS/SPKI pinning, existing V2 opaque handles and `EffectSetV2`, AES-256-GCM/HMAC durable state patterns, Cargo integration tests.

## Global Constraints

- `docs/planner-privacy-v2.md` v1.2 is the normative design.
- Do not change `PlannerEnvelopeV2`, `PlannerPlanV2`, `PlannerStepV2`, any `Kernel*OperationV2` tag, or any kerneld request/response wire encoding.
- Adding read-only Rust accessors to `PlannerEnvelopeV2` is allowed; its canonical bytes and schema remain byte-for-byte unchanged.
- The planner request contains only `StructuralNodeV2`, `StructuralEdgeV2`, and the closed `OrderValidDataflow` goal. It contains no free text, semantic name, description, action-template ID, tool-class ID, connector ID, planner route, task template, intent tag, slot reference, envelope nonce, expiry, or model/mapper handle.
- Structural roles are exactly `Source = 1`, `Transform = 2`, and `Sink = 3`.
- Structural effects use the existing closed `EffectSetV2`; zero, unknown bits, and `FINAL_RELEASE` on a non-`Sink` node fail closed.
- A graph has at most 256 nodes and 4096 edges. Node IDs are nonzero 16-byte values minted with `getrandom` after every successful mapper response and are never reused across planner calls.
- Mapper and planner CBOR objects use schema version `2`, fixed arrays, definite lengths, canonical shortest integers, exact re-encoding checks, and an 8 MiB body ceiling.
- The mapper never receives `envelope_nonce` or `expires_at`; plannerd never receives the mapper request, semantic catalog, decode table, or any handle back to mapperd.
- Decode is a local table lookup. The remote planner returns only an exact permutation of graph node IDs; agentd computes dependency ordinals from the validated local edge set and injects `envelope_nonce` locally.
- Browser action tag `2` remains the private, fail-safe default. A new explicit tag `16` means “allow third-party mapper for this task”; it is rejected when the deployment ceiling is `PrivateOnly`.
- The third-party option changes only confidentiality. It never changes active tools, policy limits, kerneld authorization, approval, execution, release, or effect-gate behavior.
- Connector `structural_role` is part of the canonical signed connector descriptor. Rich semantic strings stay only in agentd’s encrypted local catalog and mapper request; they never enter kerneld, execd, or plannerd messages.
- Deployment-shipped catalog entries are measured in the agentd bootstrap. User-registered entries are projected from the approved connector descriptor and stored under a distinct agentd durable namespace; missing, stale, corrupt, or unmatched catalog data fails planning closed.
- No production path may fall back to sending a `PlannerEnvelopeV2` directly to plannerd.

---

### Task 1: Closed structural graph, mapper projection, and deterministic decode

**Files:**
- Create: `crates/savana-agentd/src/planner_privacy.rs`
- Modify: `crates/savana-agentd/src/lib.rs`
- Modify: `crates/savana-kernel-protocol/src/v2/kernel_agent_success.rs`
- Test: `crates/savana-agentd/src/planner_privacy.rs`

**Interfaces:**
- Produces: `StructuralRoleV2`, `StructuralNodeIdV2`, `StructuralNodeV2`, `StructuralEdgeV2`, `StructuralGraphV2`, `StructuralPlannerRequestV2`, `OrderedStructuralPlanV2`, `MapperIntentRequestV2`, `MappedWorkflowV2`, `PlannerDecodeTableV2`, and `decode_ordered_plan_v2`.
- Consumes: existing `ActiveToolViewV2`, `PlannerEnvelopeV2`, `PlannerStepV2`, `PlannerPlanV2`, `EffectSetV2`, and planner limits.

- [ ] **Step 1: Write RED canonicality and privacy tests**

  Add table-driven tests that name the break they catch: free text cannot be represented in the structural types; unknown role/effect tags, zero/reused IDs, duplicate nodes, unknown edge endpoints, self-edges, duplicate edges, cycles, over-256 nodes, and over-4096 edges are rejected. Hand-derive one literal canonical CBOR vector and assert exact bytes.

- [ ] **Step 2: Run the focused tests and confirm RED**

  Run: `cargo test -p savana-agentd planner_privacy --all-features --locked`

  Expected: compilation fails because `planner_privacy` and its closed types do not exist.

- [ ] **Step 3: Implement the closed local types and codecs**

  Implement these exact public shapes in agentd:

  ```rust
  pub enum StructuralRoleV2 { Source = 1, Transform = 2, Sink = 3 }
  pub struct StructuralNodeIdV2([u8; 16]);
  pub struct StructuralNodeV2 {
      id: StructuralNodeIdV2,
      role: StructuralRoleV2,
      effect_class: EffectSetV2,
      in_arity: u8,
      out_arity: u8,
  }
  pub struct StructuralEdgeV2 { from: StructuralNodeIdV2, to: StructuralNodeIdV2 }
  pub struct StructuralGraphV2 { nodes: Vec<StructuralNodeV2>, edges: Vec<StructuralEdgeV2> }
  pub enum StructuralGoalV2 { OrderValidDataflow = 1 }
  pub struct StructuralPlannerRequestV2 { graph: StructuralGraphV2, goal: StructuralGoalV2 }
  pub struct OrderedStructuralPlanV2 { ordered_nodes: Vec<StructuralNodeIdV2> }
  ```

  Encode requests as `[2, nodes, edges, 1]`, nodes as `[id_bytes, role_tag, effect_bits, in_arity, out_arity]`, edges as `[from_id, to_id]`, and responses as `[2, ordered_node_ids]`. Decode with declared-length checks before allocation and require byte-identical re-encoding.

- [ ] **Step 4: Add nonce-free mapper input and validated mapped workflow**

  Add read-only accessors for task template, intent, action allowlist, slots, relations, and effective limits to `PlannerEnvelopeV2` without changing its encoder/decoder. Define mapper request fields from those accessors but deliberately omit route, nonce, and expiry. Define mapped nodes by local ordinal plus concrete `tool_class`, `action_template`, sorted slot bindings, signed structural role/effect, and bounded edges between local ordinals. Validation must prove every action is envelope-allowed, every tool pair is active and catalog-backed, every slot reference belongs to the envelope, every edge endpoint exists, the graph is acyclic, and all effective limits hold. Mapper-local ordinals do not impose an order; only the later planner permutation does, and decode converts incoming edges into lower dependency ordinals after validating that permutation topologically.

- [ ] **Step 5: Write RED deterministic-decode tests**

  Test that a missing, duplicated, unknown, or non-permutation planner node ID is rejected; a planner order that violates an edge is rejected; reordered fresh IDs decode to the exact concrete tool/action/slot bindings; dependencies are computed from local edges; and a remote response cannot select a different tool, slot, action, or nonce.

- [ ] **Step 6: Implement fresh relabeling and deterministic decode**

  After mapper validation, draw a unique nonzero 16-byte ID for every node, retrying bounded collisions. Build a private `PlannerDecodeTableV2` that owns node-to-concrete mappings and edges. `decode_ordered_plan_v2(envelope, table, ordered)` must return `PlannerPlanV2::new(envelope.envelope_nonce(), steps)` and never accept a nonce from either model response.

- [ ] **Step 7: Verify and commit**

  Run:

  ```bash
  cargo test -p savana-agentd planner_privacy --all-features --locked
  cargo test -p savana-kernel-protocol --test v2_kernel_agent_wire --all-features --locked
  cargo fmt --all -- --check
  git diff --check
  ```

  Commit: `feat(agentd): add closed planner privacy graph`

### Task 2: Signed structural roles and durable local semantic catalog

**Files:**
- Modify: `crates/savana-policy-core/src/v2/connector_registry.rs`
- Modify: `crates/savana-policy-core/src/v2/mod.rs`
- Modify: `crates/savana-policy-core/tests/v2_connector_registry.rs`
- Modify: `crates/savana-policy-core/tests/v2_connector_store.rs`
- Create: `crates/savana-agentd/src/planner_catalog.rs`
- Modify: `crates/savana-agentd/src/browser_authority.rs`
- Modify: `crates/savana-agentd/src/daemon.rs`
- Modify: `crates/savana-agentd/src/lib.rs`
- Modify: `crates/savana-kerneld/src/bin/savana-development-build-inputs.rs`
- Modify: `crates/savana-policy-core/src/bin/savana-development-material.rs`
- Test: `crates/savana-agentd/src/planner_catalog.rs`

**Interfaces:**
- Produces: signed `ConnectorStructuralRoleV2`; `PlannerCatalogEntryV2`; encrypted `DurablePlannerCatalogV2`; descriptor-to-catalog projection.
- Consumes: canonical `ConnectorDescriptorV2`, each nested `UnsignedToolDescriptorV2`, and the installation/store namespace already verified by agentd startup.

- [ ] **Step 1: Write RED connector descriptor tests**

  Update literal raw descriptor builders to include one closed `structural_role` field. Prove role mutation changes canonical bytes and signed delta digest; missing/zero/unknown roles are rejected; role survives add/remove/replay/store reopen; and descriptor limits remain unchanged.

- [ ] **Step 2: Run focused descriptor/store tests and confirm RED**

  Run:

  ```bash
  cargo test -p savana-policy-core --test v2_connector_registry --all-features --locked
  cargo test -p savana-policy-core --test v2_connector_store --all-features --locked
  ```

  Expected: descriptor vector and field-count failures until the signed role is implemented.

- [ ] **Step 3: Add signed connector structural role**

  Add `ConnectorStructuralRoleV2::{Source = 1, Transform = 2, Sink = 3}` to the canonical connector descriptor immediately before `descriptor_version`; include it in exact re-encoding, delta signatures, display approval text, accessors, and all fixture generators. Do not add rich descriptions to the signed descriptor.

- [ ] **Step 4: Write RED catalog projection and durability tests**

  Test exact projection of every nested tool into `(tool_class, action_template, signed role, effects, semantic_name, semantic_description)`, where the local semantic strings are bounded NFC text with controls forbidden. Test encrypted-at-rest bytes contain none of the semantic text; wrong key/domain/store/installation, rollback, noncanonical ordering, duplicates, corrupt ciphertext, unsafe metadata, and missing non-genesis state fail closed. Test a stale catalog entry cannot enter a mapper request unless an exact active-tool pair selects it.

- [ ] **Step 5: Implement `DurablePlannerCatalogV2`**

  Use distinct domains `SAVANA_AGENTD_PLANNER_CATALOG_KEY_V2\0`, `SAVANA_AGENTD_PLANNER_CATALOG_STATE_V2\0`, and `SAVANA_AGENTD_PLANNER_CATALOG_HEAD_V2\0`; fixed file name `planner-catalog-state-v2.cbor`; AES-256-GCM; an installation/store-bound key; one rollback anchor; private single-link metadata; canonical sorted entries; and a maximum of 4096 entries. Derive user-registered semantic strings locally as `"<connector display name>/<provider tool id>"` and `"connector <display name>; tool <provider tool id>"`. Those strings never re-enter the descriptor or kernel calls.

- [ ] **Step 6: Seed shipped entries and wire registration projection**

  Add measured bootstrap fields for `planner_catalog_state_path`, `planner_catalog_rollback_anchor_path`, `planner_catalog_store_id`, and sorted `planner_shipped_catalog`. The development generator must emit the existing shipped tool’s exact class/template/effects with `Sink` role. On `RegisterConnector`, agentd parses and persists the local projection before asking kerneld to authorize it; a rejected or later-removed connector leaves only an inert catalog row because mapper requests always intersect with kernel-provided `active_tools`.

- [ ] **Step 7: Verify and commit**

  Run:

  ```bash
  cargo test -p savana-policy-core --test v2_connector_registry --all-features --locked
  cargo test -p savana-policy-core --test v2_connector_store --all-features --locked
  cargo test -p savana-agentd planner_catalog --all-features --locked
  cargo test -p savana-agentd browser_authority::tests::all_connector_actions_share_the_closed_authenticated_tab_gate --all-features --locked
  cargo fmt --all -- --check
  git diff --check
  ```

  Commit: `feat(v2): project connector catalog for private planning`

### Task 3: Intent trust boundary and mapper client

**Files:**
- Modify: `crates/savana-agentd/src/planner_privacy.rs`
- Create: `crates/savana-agentd/src/mapper_client.rs`
- Modify: `crates/savana-agentd/src/browser_authority.rs`
- Modify: `crates/savana-agentd/src/daemon.rs`
- Modify: `crates/savana-agentd/src/lib.rs`
- Modify: `crates/savana-kernel-protocol/src/v2/browser_agent.rs`
- Modify: `crates/savana-kernel-protocol/src/v2/browser_assets.rs`
- Modify: `crates/savana-kernel-protocol/src/v2/mod.rs`
- Test: `crates/savana-kernel-protocol/tests/v2_agent_browser_connector_wire.rs`
- Test: `crates/savana-agentd/src/mapper_client.rs`

**Interfaces:**
- Produces: `IntentTrustDeploymentCeilingV2`, explicit browser action tag `16`, and `PinnedMtlsAgentMapperClientV2::map`.
- Consumes: nonce-free `MapperIntentRequestV2`, private/third-party mapper endpoints, and deployment ceiling.

- [ ] **Step 1: Write RED fail-safe boundary tests**

  Preserve browser action tag `2` as the exact private default and add literal tag `16` for explicit third-party mapping. Test that tag 2 always chooses the private endpoint; tag 16 chooses the third-party endpoint only under `UserMayUseThirdParty`; `PrivateOnly` rejects tag 16 before network I/O; action replay cannot change the choice; and no choice changes the kernel prepare/commit request.

- [ ] **Step 2: Run focused browser tests and confirm RED**

  Run:

  ```bash
  cargo test -p savana-kernel-protocol --test v2_agent_browser_connector_wire --all-features --locked
  cargo test -p savana-agentd browser_authority::tests --all-features --locked
  ```

  Expected: tag 16 and boundary types do not exist.

- [ ] **Step 3: Implement boundary vocabulary and UI opt-out**

  Add `AgentBrowserActionV2::RunPlannerWithThirdPartyMapper` at tag 16 without changing tag 2. Add a separate, plainly labeled UI control: `Run planner (share intent with configured third party)`. The ordinary `Run planner` button keeps tag 2. Treat the explicit action as a per-task opt-out; do not persist it as the next task’s default.

- [ ] **Step 4: Write RED mapper transport/privacy tests**

  Use a live local TLS fixture to decode the exact request body and prove it contains no envelope nonce, expiry, planner route, handle, or structural node ID. Test exact `/savana.mapper.v2/map`, POST-only CBOR, content-length, connection-close, no redirects/cookies/compression/chunking, mTLS, leaf-SPKI pinning before the first application byte, size/deadline limits, canonical response, and distinct endpoint selection.

- [ ] **Step 5: Implement mapper mTLS client and deployment ceiling**

  Reuse the audited TLS/HTTP mechanics from `planner_client.rs` through a focused private transport helper rather than copy-pasting certificate parsing. Configure a required private mapper host/port/SPKI and an optional third-party mapper host/port/SPKI. The third-party endpoint is accepted only when the measured bootstrap ceiling is `UserMayUseThirdParty`; private is the constructor default and startup fails closed if it is absent.

- [ ] **Step 6: Verify and commit**

  Run:

  ```bash
  cargo test -p savana-agentd mapper_client --all-features --locked
  cargo test -p savana-agentd browser_authority::tests --all-features --locked
  cargo test -p savana-kernel-protocol --test v2_agent_browser_connector_wire --all-features --locked
  cargo fmt --all -- --check
  git diff --check
  ```

  Commit: `feat(agentd): enforce intent trust boundary`

### Task 4: Replace the planner envelope exchange with structural planning

**Files:**
- Modify: `crates/savana-agentd/src/planner_client.rs`
- Modify: `crates/savana-agentd/src/planner_privacy.rs`
- Modify: `crates/savana-agentd/src/lib.rs`
- Test: `crates/savana-agentd/src/planner_client.rs`

**Interfaces:**
- Changes: `PinnedMtlsAgentPlannerClientV2::plan(&StructuralPlannerRequestV2, UnixMillisV2) -> Result<OrderedStructuralPlanV2, AgentPlannerClientErrorV2>`.
- Removes: every production serialization or response decode of `PlannerEnvelopeV2`/`PlannerPlanV2` inside `planner_client.rs`.

- [ ] **Step 1: Write RED exact-boundary tests**

  A live TLS fixture must decode the request as `StructuralPlannerRequestV2`, assert its exact graph, and verify byte absence for independently chosen intent, tool class, action template, semantic name, semantic description, envelope nonce, and slot reference. The fixture returns an ordered-node response. Add negative tests for unknown/duplicate/missing IDs, oversized responses, malformed/noncanonical CBOR, redirect, compression, chunking, wrong content type, wrong SPKI, absent ALPN policy, and deadline expiry.

- [ ] **Step 2: Run focused planner tests and confirm RED**

  Run: `cargo test -p savana-agentd planner_client --all-features --locked`

  Expected: the current client still accepts `PlannerEnvelopeV2` and decodes `PlannerPlanV2`.

- [ ] **Step 3: Change the planner client to the structural-only API**

  Serialize only `StructuralPlannerRequestV2`; decode only `OrderedStructuralPlanV2`. Delete the imports and call sites for `decode_planner_plan_v2`, `PlannerEnvelopeV2`, and `PlannerPlanV2` from this module. Keep the exact existing route `/savana.planner.v2/plan`, TLS pin, body ceiling, and closed HTTP surface.

- [ ] **Step 4: Add a source/API regression guard**

  Add a compile-time API test that can call `plan` only with `StructuralPlannerRequestV2`, plus a behavior test that mutating any envelope-only secret cannot change planner request bytes when the structural graph is unchanged. Do not use a grep-only source test as the primary evidence.

- [ ] **Step 5: Verify and commit**

  Run:

  ```bash
  cargo test -p savana-agentd planner_client --all-features --locked
  cargo test -p savana-agentd planner_privacy --all-features --locked
  cargo fmt --all -- --check
  git diff --check
  ```

  Commit: `fix(agentd): send only structural graphs to planner`

### Task 5: Wire the one-way mapper → planner → deterministic decode pipeline

**Files:**
- Modify: `crates/savana-agentd/src/browser_authority.rs`
- Modify: `crates/savana-agentd/src/daemon.rs`
- Modify: `crates/savana-agentd/src/lib.rs`
- Test: `crates/savana-agentd/src/browser_authority.rs`
- Test: `crates/savana-agentd/tests/planner_privacy_e2e.rs`

**Interfaces:**
- Consumes: prepared kernel envelope, current active tools, matched local catalog, selected mapper, structural planner, and deterministic decoder.
- Produces: the unchanged `CommitPlannerValueRequestV2` and existing browser plan-step references.

- [ ] **Step 1: Write RED pipeline and invariant tests**

  Build real local mapper and planner TLS fixtures plus a fake kernel authority. Assert the exact order: kernel prepare → mapper once → planner once → local decode → kernel commit. Assert mapper cannot be called again based on planner output; plannerd receives no mapper endpoint/handle; every run gets disjoint node IDs; the decode table never leaves agentd; nonce is added only after planner response; malformed mapper/planner output causes no kernel commit; and the effect-gate guard remains held across both exchanges and commit.

- [ ] **Step 2: Run focused authority/E2E tests and confirm RED**

  Run:

  ```bash
  cargo test -p savana-agentd browser_authority::tests::planner_privacy --all-features --locked
  cargo test -p savana-agentd --test planner_privacy_e2e --all-features --locked
  ```

  Expected: the existing authority calls plannerd directly with the kernel envelope.

- [ ] **Step 3: Implement the production pipeline**

  In `RunPlanner`, retain the effect guard; prepare the kernel envelope; intersect `active_tools` with the local catalog; build the nonce-free mapper request; call exactly one selected mapper; validate and freshly relabel; call plannerd with only the structural graph; deterministically decode; inject the local nonce; commit to kerneld; then build the same browser plan-step objects as today. Never expose mapper/planner bytes through public errors or debug output.

- [ ] **Step 4: Prove authorization is unchanged**

  Re-run kerneld planner-limit/tool/action tests and add an E2E case where a malicious mapper selects a catalog tool that is not active: agentd rejects before planner I/O and kerneld state remains unchanged. Add a case where a malicious planner reorders across a dependency: agentd rejects before commit.

- [ ] **Step 5: Verify and commit**

  Run:

  ```bash
  cargo test -p savana-agentd --all-features --locked -- --test-threads=1
  cargo test -p savana-kerneld planner_commit_enforces_retained_signed_policy --all-features --locked
  cargo test -p savana-kerneld planner_request_is_closed_to_signed_policy --all-features --locked
  cargo fmt --all -- --check
  git diff --check
  ```

  Commit: `feat(agentd): enforce private structural planning pipeline`

### Task 6: Deployment closure, frozen core, documentation, and final verification

**Files:**
- Modify: `crates/savana-kerneld/src/bin/savana-development-build-inputs.rs`
- Modify: `crates/savana-policy-core/src/bin/savana-development-material.rs`
- Modify: `crates/savana-kerneld/tests/macos_deployment.rs`
- Modify: `deploy/macos/development/install.sh`
- Modify: `deploy/macos/development/validate.sh`
- Modify: `deploy/systemd/savana-agentd.service`
- Modify: `deploy/frozen-v2-core.files`
- Modify: `deploy/frozen-v2-core.sha256`
- Modify: `README.md`
- Modify: `README.zh-CN.md`
- Modify: `docs/planner-privacy-v2.md`
- Test: `crates/savana-kerneld/tests/macos_deployment.rs`

**Interfaces:**
- Produces: measured private mapper endpoint, optional third-party mapper ceiling, distinct catalog paths/credentials, accurate public interface documentation, and frozen-core coverage.

- [ ] **Step 1: Write RED deployment tests**

  Require exact private mapper host/port/SPKI, an explicit ceiling tag, catalog state/anchor/store IDs, private mapper credentials, root-owned private paths, and sandbox/network rules that permit only the measured mapper and planner destinations. Reject missing/zero/unknown ceiling, aliased mapper/planner pins under a private-only deployment, unsafe catalog paths, and unmeasured catalog entries.

- [ ] **Step 2: Run deployment tests and confirm RED**

  Run: `cargo test -p savana-kerneld --test macos_deployment --all-features --locked -- --test-threads=1`

  Expected: generated bootstrap/install/validate artifacts lack mapper and catalog closure.

- [ ] **Step 3: Complete deployment material and docs**

  Generate a development mapper certificate for `mapper.savana-development.invalid`, install its root/client material under agentd-only credentials, pin its SPKI, and keep it distinct from planner identity. Update both READMEs with the exact external interfaces: mapper `POST /savana.mapper.v2/map`, planner `POST /savana.planner.v2/plan`, browser private tag 2, explicit third-party tag 16, local catalog store, and unchanged kernel planner operations. Update the design status to implemented and record the honest structural-shape floor.

- [ ] **Step 4: Refresh frozen core and run static gates**

  Run the repository’s frozen-core refresh mechanism only for intentional files, then:

  ```bash
  sh tools/check-frozen-v2-core.sh
  sh tools/tests/check-frozen-v2-core.sh tools/check-frozen-v2-core.sh
  cargo fmt --all -- --check
  cargo check --workspace --all-targets --all-features --locked
  cargo clippy --workspace --all-targets --all-features --locked -- -D warnings -A clippy::result-large-err -A clippy::large-enum-variant -A clippy::type-complexity -A clippy::too-many-arguments -A clippy::clone-on-copy
  git diff --check
  ```

- [ ] **Step 5: Run full serialized verification**

  Run:

  ```bash
  cargo test --workspace --all-features --locked -- --test-threads=1
  ```

  Require exit code 0, zero failed tests, and account explicitly for any environment-gated ignored test.

- [ ] **Step 6: Commit**

  Commit: `docs(v2): finalize planner privacy deployment`
