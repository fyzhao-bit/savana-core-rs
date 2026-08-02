# Savana V2 Declassification Implementation Plan

> **For Codex:** Execute this plan task-by-task with `superpowers:test-driven-development`; run the named RED command before each production change and the matching GREEN command afterwards.

**Goal:** Implement the accepted `docs/declassification-v2.md` v1.1 design end to end so every confidentiality-reducing V2 transition is authorized by a signed, deployment-pinned rule and leaves load-bearing provenance evidence.

**Architecture:** Add a canonical signed `DeclassificationRuleSetV2` beside the existing operational trust objects, pin it into the active deployment closure, and make `ProvenanceRecordV2::declassify` the sole rule-checked wrapper over the private kernel downgrade constructor. Kerneld owns the active verified set and routes masked ingress, planner calls, approval displays, execution handoffs, and final releases through it. Stored node digests and exact reader identities then make handoff judgment fail closed.

**Tech Stack:** Rust 2021 workspace, `minicbor`, `ed25519-dalek`, SHA-256 domain separation, existing V2 deployment/approval/vault/HPKE authorities, Cargo tests and frozen-core manifest.

**Resolved design decisions:** Use signature tag 29, operational binding tag 3, operational purpose tag 5, security-domain tag 29, maximum 64 rules and 16 readers. Approval display keeps `BlocklistOnly` as its hard-coded minimum; deployment rules may tighten it. S3 first replaces the hard-coded planner purpose/template/limits with request- and policy-bound vocabulary because otherwise a planner declassification would authorize a fictitious intent.

---

## Task 1: Lock the wire registries and hard limits

**Files:**
- Modify: `crates/savana-policy-core/src/v2/deployment_limits.rs`
- Modify: `crates/savana-policy-core/src/v2/deployment_ledger.rs`
- Modify: `crates/savana-policy-core/src/v2/deployment_manifest_closure.rs`
- Modify: `crates/savana-policy-core/src/v2/deployment_operational_trust.rs`
- Test: `crates/savana-policy-core/tests/v2_deployment_control.rs`
- Test: `crates/savana-policy-core/tests/v2_operational_trust_root.rs`

1. Add tests asserting domain 29, purpose 5, binding 3, canonical ordering, set-domain selection, and the 64/16 hard limits.
2. Run the two targeted tests and confirm they fail because the new vocabulary is absent.
3. Add the closed enum variants, update exhaustive arrays/counts/decoders, and add the two hard limits.
4. Run the targeted tests until green.

## Task 2: Implement the canonical signed rule set

**Files:**
- Create: `crates/savana-policy-core/src/v2/declassification.rs`
- Modify: `crates/savana-policy-core/src/v2/mod.rs`
- Modify: `crates/savana-policy-core/Cargo.toml` only if an existing dependency is not already available
- Test: `crates/savana-policy-core/tests/v2_declassification_rules.rs`

1. Write negative-first tests for canonical CBOR shape, payload/signed digests, domain signature verification, owner/purpose mismatch, illegal reader shapes, illegal consent shapes, zero/duplicate/unsorted fields, set/rule windows, chain linkage, maximum sizes, and wrong trust-root purpose.
2. Confirm the new test target fails to compile because rule types do not exist.
3. Implement `ClosedDeclassificationPurposeV2`, transition-owned `DeclassificationRuleV2`, reader/consent constraints, payload encode/decode, digest derivation, signature verification, and `DeclassificationRuleSetV2` accessors.
4. Keep constructors closed: production accepts canonical signed bytes plus verified trust material; test signing helpers remain behind test support.
5. Run `cargo test -p savana-policy-core --test v2_declassification_rules --all-features --locked` until green.

## Task 3: Pin the rule set into deployment state

**Files:**
- Modify: `crates/savana-policy-core/src/v2/deployment_manifest_claim.rs`
- Modify: `crates/savana-policy-core/src/v2/deployment_manifest_closure.rs`
- Modify: `crates/savana-policy-core/src/v2/deployment_manifest.rs`
- Modify: `crates/savana-policy-core/src/v2/deployment_schema.rs`
- Modify: `crates/savana-policy-core/src/v2/deployment_transaction_core.rs`
- Modify: deployment fixture/build helpers under `crates/savana-policy-core/tests/`
- Test: `crates/savana-policy-core/tests/v2_security_state_manifest.rs`
- Test: `crates/savana-policy-core/tests/v2_deployment_entrypoints.rs`

1. Add tests proving activation refuses a missing, wrong-domain, or digest-mismatched rule set and preserves rollback high-water monotonicity.
2. Run those tests and observe the expected RED failures.
3. Extend the manifest/closure/transaction material with the declassification trust-root identity and signed rule-set identity, including exact digest equality and domain closure.
4. Update every exhaustive manifest fixture with explicit declassification material; never synthesize a permissive default during verification.
5. Run the targeted deployment tests until green.

## Task 4: Make provenance declassification rule checked

**Files:**
- Modify: `crates/savana-policy-core/src/v2/provenance.rs`
- Modify: `crates/savana-policy-core/src/v2/provenance_tests.rs`
- Modify: `crates/savana-policy-core/src/v2/labels.rs`

1. Add RED tests for the exact check order and stable errors: set expired, no rule, rule expired, implementation mismatch, reader unauthorized, consent missing/expired/scope mismatch/consumed, leak-gate failure, and effect-ceiling preservation.
2. Add success tests for all five transition tags, exact rule/purpose/implementation/token digests, required parents, and exact tag-4/tag-5 reader identity.
3. Implement public `ProvenanceRecordV2::declassify`; keep `kernel_declassification` private and callable only from this wrapper.
4. Add minimal read-only accessors to `VerifiedFinalReleaseSettlementV2` needed to validate exact scope, age, and one-use settlement state without creating a second consent authority.
5. Run `cargo test -p savana-policy-core v2::provenance --all-features --locked` until green.

## Task 5: Load and roll over the active verified rule set

**Files:**
- Modify: `crates/savana-kerneld/src/deployment_trust.rs`
- Modify: `crates/savana-kerneld/src/v2_runtime.rs`
- Modify: `crates/savana-kerneld/src/v2_agent_authority.rs`
- Modify: kerneld deployment fixtures and test support
- Test: `crates/savana-kerneld/tests/deployment_units.rs`
- Test: `crates/savana-kerneld/tests/policy_rollover.rs`

1. Add RED startup and rollover tests for missing bytes, invalid signature, manifest digest mismatch, expired set, chain rollback, and atomic retention of the old active set on failure.
2. Decode and verify the set during deployment load, store only the verified object in active runtime state, and swap it atomically with the rest of policy state.
3. Run the targeted tests until green.

## Task 6: Route masked agent ingress through transition 1

**Files:**
- Modify: `crates/savana-kerneld/src/value_owner.rs` or the actual V2 value-owner module found during execution
- Modify: `crates/savana-vault/src/lib.rs`
- Modify: `crates/savana-vault/src/durable.rs`
- Modify: `crates/savana-kerneld/src/v2_agent_authority.rs`
- Test: value-owner unit tests and `crates/savana-kerneld/tests/v2_agent_*`

1. Add RED tests proving the exact post-mask bytes are gated, the token-set digest is bound, failed gating writes no vault record, and readback returns the view plus node digest evidence.
2. Add a provenance-node digest field to the durable masked-view record with decode-time nonzero validation.
3. Call `declassify` immediately after masking and before vault commit; persist the resulting node digest atomically.
4. Run targeted kerneld/vault tests until green.

## Task 7: Replace fictitious planner intent and route transition 2

**Files:**
- Modify: `crates/savana-kernel-protocol/src/v2/kernel_agent.rs`
- Modify: `crates/savana-input-runtime/src/lib.rs`
- Modify: `crates/savana-kerneld/src/v2_agent_authority.rs`
- Modify: `crates/savana-agentd/src/kernel_client.rs`
- Modify: protocol wire tests and kerneld planner tests

1. Add RED wire/authority tests that the request carries closed template, intent, purpose values, and bounded limits; reject unknown or policy-incompatible values.
2. Replace the `SummarizeDocument`/template-1/fixed-limit construction with the authenticated request values intersected with active policy limits.
3. Add RED tests proving the exact canonical planner envelope is transition-2 gated, all prompt-value provenance nodes are parents, the slot-binding digest is bound, and failed authorization does not mint a planner ticket.
4. Store the declassification node digest in `PlannerTicketRecordV2`, bind it into the ticket/envelope digest, and test tamper refusal.
5. Run protocol, input-runtime, agentd, and kerneld planner tests until green.

## Task 8: Make readers and confidentiality load bearing

**Files:**
- Modify: `crates/savana-policy-core/src/v2/provenance.rs`
- Modify: `crates/savana-kerneld/src/v2_agent_authority.rs`
- Modify: relevant durable/envelope protocol records
- Test: provenance and kerneld handoff tests

1. Add RED tests for `Admits`, `Refuses`, and `Unproven`, including missing lineage head, reader-set miss, wrong exact executor/release identity, and public values.
2. Implement the three-valued handoff judgment and require a matching `KernelDeclassification` lineage head for every confidentiality-reducing envelope.
3. Store and verify the node digest in every handoff record rather than accepting unbound reader metadata.
4. Run targeted tests until green.

## Task 9: Route approval display through transition 3

**Files:**
- Modify: `crates/savana-kerneld/src/v2_agent_authority.rs`
- Modify: `crates/savana-kernel-protocol/src/v2/approval_service.rs`
- Modify: `crates/savana-approvald/src/lib.rs` and durable protocol only where the envelope shape must carry evidence
- Test: approval protocol wire and kerneld approval tests

1. Add RED tests proving the exact rendered artifact is gated before envelope signing/registration and that the node digest is signed into the approval envelope.
2. Apply the rule-selected duty with `BlocklistOnly` as the minimum; on refusal mint neither envelope nor display transfer.
3. Verify the digest at approvald ingress and retain it through settlement audit evidence.
4. Run targeted approval tests until green.

## Task 10: Route execution handoff through transition 4

**Files:**
- Modify: `crates/savana-policy-core/src/v2/g7.rs` or the actual dispatch preparation module
- Modify: `crates/savana-kerneld/src/v2_agent_authority.rs`
- Modify: `crates/savana-kernel-protocol/src/v2/execution.rs`
- Test: G7 unit tests and kerneld release/tool execution tests

1. Add RED tests that gate the exact plaintext immediately before HPKE sealing, require exact executor-reader membership, preserve G7 equality bindings, and refuse sealing on any mismatch.
2. Bind the transition-4 node digest into the signed sealed execution envelope and verify it in execd.
3. Run targeted policy-core, protocol, kerneld, and execd tests until green.

## Task 11: Route final release through transition 5 and consumed settlement consent

**Files:**
- Modify: `crates/savana-kerneld/src/v2_agent_authority.rs`
- Modify: `crates/savana-policy-core/src/v2/production.rs`
- Modify: `crates/savana-vault/src/lib.rs`
- Modify: final-release protocol/durable envelope fields as required
- Test: `crates/savana-kerneld/tests/v2_release_*` and policy/vault tests

1. Add RED tests for exact plaintext re-verification, nonempty token scope, settlement age <= rule maximum, exact release/binding/manifest scope, consumed settlement reuse, reader mismatch, and no seal/no durable dispatch on failure.
2. Gate the verified plaintext after vault digest verification and before HPKE sealing using the existing consumed `VerifiedFinalReleaseSettlementV2`.
3. Bind the node digest into final-release sealed evidence and consume the authorization exactly once in the same atomic authority transition.
4. Run targeted release tests until green.

## Task 12: Author a closed development rule set and document operations

**Files:**
- Modify: deployment development generator/config under `deploy/`
- Modify: `README.md`
- Modify: `README.zh-CN.md`
- Test: deployment generation/unit tests

1. Add RED fixture tests requiring all five exact rules, closed purposes, implementation digests, intended readers, windows, and final-release consent.
2. Generate/sign a development rule set through the existing developer trust workflow; do not embed a bypass or wildcard rule.
3. Document rule rotation, trust-root binding, failure behavior, and the externally exposed evidence fields in both READMEs.
4. Run deployment tests until green.

## Task 13: Freeze and verify the complete implementation

**Files:**
- Modify: `deploy/frozen-core-v2.sha256`
- Modify: any frozen allowlist/manifest file named by the freeze checker

1. Run `cargo fmt --all -- --check`; fix formatting with `cargo fmt --all` and inspect the diff.
2. Run `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`.
3. Run `cargo test --workspace --all-targets --all-features --locked`.
4. Run the repository's frozen-core verification command, update the freeze manifest only after reviewing every changed path, then rerun it.
5. Run `cargo build --workspace --all-targets --all-features --release --locked`.
6. Inspect `git diff --check`, `git status --short`, and the complete diff; record any platform-only test not runnable on this host.
