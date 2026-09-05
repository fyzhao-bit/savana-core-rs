# Intent-bound Execution Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the approved task-authorization/selection/execution design in the existing Rust production path, verify it, then revise the paper to match evidence.
**Architecture:** A separately authenticated task contract precedes planning. The kernel matches whole actions against grouped contract clauses, produces acyclic authorization evidence, and reserves task consumption atomically with dispatch. The executor independently checks the business request before emission.
**Tech Stack:** Existing Rust workspace, bounded canonical CBOR, Ed25519, SHA-256, existing encrypted policy snapshot/WAL and executor journal, existing authenticated ingress/approval services; LaTeX paper.
**Spec:** `docs/superpowers/specs/2026-09-04-intent-bound-execution-design.md` (approved).

## Global Constraints

- Work only in `/Users/fz/Documents/jarvis/.worktrees/intent-bound-execution`, branch `codex/intent-bound-execution`, based on `d0bf45b`. Preserve the old dirty authentication worktree and local running services. No deployment, push, credential reset, or data deletion.
- V1 stays frozen. New authority must fail closed without the new evidence; old V2 in-flight effects are recovery-only, never silently upgraded, wiped, or re-signed.
- An arbitrary malicious planner/agent/worker is in scope. Context cleanliness grants no authority. Action approval cannot expand a task contract. Untrusted selections retain READ ceiling and cannot be ordinary derivation parents that increase authority.
- Match the complete action relation, not a Cartesian product of allowed resources and destinations. State/consumption belongs to task authorization, not run/nonce/request ID.
- Content digest excludes future endorsements/settlements. Authorization digest includes the complete sorted evidence set and state transition. Request evidence must describe the actual emitted business request, not merely a worker's assertion.
- No Python signing or trusted-evidence construction; data-plane inputs stay in the authenticated ingress/approval path. Existing gates, role isolation, signatures, quotas and fences stay enforced.
- Every behavioral change uses a failing behavioral test before implementation. Existing behavior that already passes gets characterization evidence, not artificial failures. Tests must use production entry points, not a parallel demonstration engine.
- Do not call the overall code complete until Tasks 1–8 and their reviews pass. Do not write paper mechanisms as implemented before that point. No fabricated experimental measurements or acceptance scores.

## Task 1: Bounded task-contract and action-content protocol

**Files:** Create `crates/savana-kernel-protocol/src/v2/task_authorization.rs`; modify `crates/savana-kernel-protocol/src/v2/mod.rs`; add focused tests beside the new module.

Define the shared, unprivileged wire/material types (decoding/signing a material object is not by itself authority):

- `TaskAuthorizationV2`: schema (fixed `1` for this new independently versioned object), authorization ID `Digest32V2`, principal `PrincipalIdV2`, task `DurableTaskIdV2`, revision `u64`, installation and manifest digests, `not_before`/`expires_at` `UnixMillisV2`, evidence-kind enum (`AuthenticatedStructuredInput`, `ApprovedDraft`), user-evidence and rendering digests, bounded clauses.
- `TaskAuthorizationClauseV2`: nonzero stable clause ID, bounded complete `ActionAlternativeV2` list; each alternative jointly binds tool descriptor digest, codec profile enum, one closed effect, exact resource digest, exact destination digest, exact parameters digest and magnitude unit. Clause carries maximum single magnitude, total magnitude budget, maximum attempts, bounded predecessor clause IDs, and explicit retry-after-proven-no-effect flag.
- `ActionContentV2`: authorization ID/revision, clause ID/alternative index, exact action fields above, magnitude, payload/provenance/plan-revision/candidate-domain/pre-state digests and pre-state revision. No approval, endorsement or authorization digest field.
- `SignedTaskAuthorizationV2` plus purpose-separated `sign_task_authorization_v2` / `verify_task_authorization_v2`; verification requires an expected verifying key and expected principal/task/installation/manifest/current time, returns validated material, never trusts a self-declared signing key. The issuer key is supplied by a trusted later integration, not generated here.
- `task_authorization_digest_v2` / `action_content_digest_v2` hash domain-separated canonical encodings. Accessors and constructors validate nonzero IDs/digests; identifiers/membership bounded. Max 64 clauses, 64 complete alternatives per clause, 32 predecessors, 1 MiB encoded contract; checked integer arithmetic. Reject duplicates, unknown enums/versions, indefinite/noncanonical arrays, trailing CBOR, missing fields, empty sets, unsorted/duplicate clause IDs, duplicate alternatives, invalid time range, cycles/self/missing dependencies, zero limits, single limit above total budget, and unbounded allocation on decode.
- Complete alternative membership is encoded directly, not separate resource/destination sets. Codec enum initially `McpToolsCallJsonV1` and `FixedJsonPostV1`; this type does not imply an implemented mapping.
- Do not expose secret input bytes in Debug. Only digests/typed identifiers belong in these objects.

- [ ] Write behavioral tests first: canonical round-trip; wrong key/purpose/principal/task/manifest/time rejects; mutate each signed binding; malformed lengths and graph reject; alternative cross-pair cannot be represented as an authorized member; content digest mutation vectors with literal expected hashes derived independently once.
- [ ] Run `cargo test --locked -p savana-kernel-protocol task_authorization`, record expected failing API/behavior output.
- [ ] Implement using existing minicbor/manual bounded decode conventions; export only necessary protocol items.
- [ ] Re-run focused tests, then `cargo test --locked -p savana-kernel-protocol`; `cargo fmt --all -- --check` and diff check on changed files.
- [ ] Commit this task and report exact test evidence and any unfinished integration (Tasks 2–8 remain required).

## Task 2: Closed joint matching, candidate evidence, and control endorsements

**Files:** Create `crates/savana-policy-core/src/v2/task_authorization.rs`, `control_selection.rs`; export through `mod.rs`. Add `crates/savana-kernel-protocol/src/v2/task_action_approval.rs` and its module export for the independently signed content-bound action settlement. Existing provenance/labels/intent/validator are inspected here; their production binding changes are coordinated in Task 5, after durable state and authenticated issuance exist.

- [ ] Add failing tests for summary-only contract vs send even with approval; `(A,Alice)/(B,Bob)` cross-pair; always-untrusted selector including singleton; unproven/partial candidate domain; expired/revoked/changed candidate; digest mutation/cross-action endorsement reuse; ordinary derive cannot accept endorsement.
- [ ] Introduce private-field `VerifiedTaskAuthorizationV2` constructed only by expected-key/context verification, and a joint matcher consuming `ActionContentV2` plus current task state. Return an opaque verified match, never a caller-supplied boolean.
- [ ] `ControlSelectionV2` records each of seven planes and proposer parent. `ControlEndorsementV2` is separate from `KernelValueV2`/ordinary provenance; constructor is private to checked endorsement. Require the complete seven-plane set exactly once in canonical order.
- [ ] Accept closed evidence of a matched explicit alternative, complete-contract-domain singleton, or verified one-use action settlement inside the matched contract. The only first-phase candidate source is the full bounded contract alternative list; registry-derived complete domains can be added only with an independently verified complete snapshot. Runtime values/search pages never establish completeness.
- [ ] Bind candidate membership, source digest, epoch and validity; recheck time and current contract revision, not epoch alone. No ContextClean branch.
- [ ] Add `AuthorizationDigestV2` construction over content digest, sorted endorsements, settlement digests, policy identity and next-state digest; construct after content-bound settlements. Golden vectors plus individual-field mutation tests.
- [ ] Define a bounded, separately domain-signed `TaskActionApprovalV2` material carrying content digest, authorization ID/revision, principal/task/installation/manifest, decision, challenge/settlement nonce, authentication-context and display digests, issued/expires timestamps. Verify with the expected approval-service key/context/time. Only the trusted approval service will sign this after a real ceremony (Task 4); a raw decision/digest/boolean is never accepted as verified consent. Do not rebrand the old `VerifiedApprovalSettlementV2` with a supplied content digest: it discards the envelope binding after verification.
- [ ] Keep this phase's matcher/selection/evidence APIs additive and non-dispatching; leave existing G4/G5 construction unchanged until Task 5 can attach the actual persisted authority and close every old issuance path together. Clearly report that these library foundations do not yet enforce production task authorization. Run `cargo test --locked -p savana-policy-core` and protocol tests for the new settlement, commit and review.

Task 2 API/phase details:

- `VerifiedTaskAuthorizationV2::verify` wraps Task 1 expected-key/context verification and stores the immutable contract and its digest. No constructor from plain decoded material. Provide read-only identity/material accessors for the trusted durable owner.
- A joint match checks auth ID/revision, clause/alternative index, exact entire `ActionAlternativeV2`, single-action magnitude bound/unit, complete candidate-domain digest and current validity. It returns an opaque immutable match bound to the exact ContentDigest. Persistent remaining budget/dependency checks are required in Task 3; do not claim a static match proves those.
- Derive candidate domain from every alternative in the verified contract clause, binding contract digest/revision, clause and canonical complete alternatives. Caller-provided subsets or matching epoch alone are insufficient. Current revision/expiry is checked again on use; revocation is represented by the durable current contract (Task 3), not a caller-supplied allow flag.
- `ControlFacetV2` order is Tool=1, EffectKind=2, Scope=3, Magnitude=4, Argument=5, Destination=6, Trigger=7. Argument binds the whole canonical parameters digest. Trigger binds contract prerequisites plus the content's pre-state identity. Build all selections from the exact content and nonzero proposer-parent digest, always ExternalUntrusted/READ even for pinned/singleton choices. Endorsements stay outside `ProvenanceRecordV2`, so ordinary value derivation cannot take them as parents.
- Explicit grouped-relation evidence may choose any exact alternative in the authenticated clause; singleton evidence requires the full clause alternative set to have one member. Settlement evidence requires the new purpose-specific signature and exact content/context/time. No evidence branch may run before joint contract matching.
- `TaskActionApprovalV2`/`SignedTaskActionApprovalV2` use a separate fixed schema/domain with bounded manual canonical encode/decode/sign/verify and expected key checks. Add deployment generation to the material/context. Verify decision Approve before endorsement; Deny/expired/wrong challenge/wrong display/content/principal/task/manifest/generation fails. This is approval-service signed material only; the service's user-authenticated issuance is Task 4.
- Final authorization digest builder accepts all seven endorsements exactly once in canonical order, checks content/contract/candidate/pre-state bindings and approval consistency, and binds policy identity plus supplied nonzero next-state digest. It is not a dispatch capability; only Task 3's atomic owner can establish the authoritative next-state digest and consume the evidence. No ordinary caller can turn this digest into a prepared dispatch.
- Test real library entry points (valid signed fixture keys, no mock checker), with hand-derived expected outcomes. Add table-driven mutations of every sensitive binding. Reject cross-action reuse, dropped/reordered/duplicate facets, false singleton proof, mixed units, expired authorization/approval, and approval outside contract. Keep Error variants closed and payload-free. Add this task's tests in adjacent `_tests.rs` files if necessary for readability.

## Task 3: Task state in the existing atomic policy transaction

**Files:** Modify `crates/savana-policy-core/src/v2/durable.rs`, `dispatch.rs`, `quota.rs`, `production.rs`, `intent.rs`; new `task_state.rs` for bounded transition mechanics, exported only as required.

- [ ] Write failures using the actual durable store: same prepare replay once; new request/nonce/run cannot overspend; stale state and dependency not completed reject before reservation; concurrent preparations, budget overflow, amendment preserving consumed counts, crash/reopen at existing persistence hooks.
- [ ] Add task contracts/revisions, per-clause attempts/magnitude, durable reservations/verified completion evidence to `DurableG4SnapshotV2`, encode/decode in the existing snapshot with an explicit new state schema. No separate ledger commit.
- [ ] At `prepare_tool_dispatch`, check task/current candidates/fence and consume matching capability/approval/endorsements, task limits and existing quota in the cloned snapshot before its single `commit(next)`; return existing record unchanged on exact replay.
- [ ] Keep EffectStarted/Indeterminate charged. Verified proven-no-effect disposition may refund once only when contract permits; bind refunds to actual journal entry, not an agent claim. Dependency requires verified success evidence.
- [ ] Explicitly decode legacy state for recovery-only queries/effect reconciliation; no new authority can be minted from missing fields. Reject unknown schema without overwriting. Add upgrade/recovery tests retaining unknown effects.
- [ ] Run policy-core durable/dispatch suites, commit and review.

## Task 4: Authenticated contract establishment and amendment

**Files:** Modify protocol `kernel_ingress.rs`, `kernel_service.rs`, `application.rs`, `signed.rs`, `browser_ingress.rs`; input-runtime `src/lib.rs`; kerneld `v2_ingress_authority.rs`, `v2_core_services.rs`, `v2_agent_authority.rs`, startup/runtime configuration; approvald's signed settlement handlers as needed.

- [ ] Test real ingress handler refusal of unsigned/agent-signed/self-attested contracts, wrong user/session/task/version, tampered approved drafts, missing fields, ambiguous free text; valid authenticated structured path and exact approved-draft path succeed before planning.
- [ ] Add bounded structured contract draft operations on authenticated ingress (not JARVIS content-free control). Store canonical draft, render full fields, bind approval challenge/settlement to draft digest and dedicated task-authorization purpose. Trusted kernel issuer verifies settlement then signs; dedicated expected key purpose in startup/config.
- [ ] Authenticate structured input through the existing ingress/session authority. No arbitrary public Rust constructor or boolean stands for a verified user. Unsupported natural-language expressions stay nonexecuting drafts; do not claim an open-language compiler.
- [ ] Amendments require explicit independent task-level approval and monotonic revision, preserve prior consumption and stable clause IDs. Record revocation/version replacement durably before new plans.
- [ ] Require a verified contract on a session before planner preparation. Keep existing signed envelope/template restrictions and test the real commit handler rejects disallowed templates/classes. Correct the old design's inaccurate missing-whitelist claim.
- [ ] Route all new operations with closed role/error/size/version contracts; preserve auth/browser projects outside this worktree. Run protocol/input-runtime/kerneld focused tests and commit.

## Task 5: Connect planner proposals, G4–G7, approvals and release

**Files:** Modify kerneld `v2_agent_authority.rs`, `v2_value_owner.rs`, `v2_agent_durable.rs`, protocol `kernel_agent.rs`, `kernel_agent_success.rs`, semantic bindings and executor wire types; client/agentd operation forwarding where needed.

- [ ] Test arbitrary planner steps and slot swaps through `commit_planner_value`/`propose_tool_call`, full cross-pair rejection, summary→send rejection even when global tool allowed, fabricated evidence, fresh-run budget resets, replanning within contract, declassification gate refusal before prepare.
- [ ] Attach contract identity to durable session/run state; at proposal resolve owned values into the exact joint action and candidate domain. Do not trust planner asserted resource/destination identifiers: derive from stored bindings and registered codec mapping.
- [ ] Preserve proposer provenance for all seven selected controls. Build ContentDigest, render approval from it, settle then endorse; construct final AuthorizationDigest only afterward. Bind intent/capability/approval/journal/seal/receipts consistently with no cycle or missing-field fallback.
- [ ] Populate verified relations from contract matching, replace the empty relation assumption. New plan versions require fresh evaluation but cannot alter authority. Final release must obey the same task resource/destination/effect budget constraints, not become an unguarded bypass.
- [ ] Route to Task 3 atomic prepare. Recovery never reconstructs new grants from old records. Run kerneld production-handler tests plus existing declassification/leak-gate regressions, commit and review.

## Task 6: Exact request profile and executor boundary validation

**Files:** Create protocol `business_request.rs`; modify policy descriptor/codec mappings, kerneld action projection; execd `worker_supervisor.rs`, `connector_runtime.rs`, `provider_transport.rs`, executor journal and protocol executor types.

- [ ] Write executor-boundary failures for worker-changed recipient/resource/tool/method/path, duplicate or unknown control fields, extra JSON-RPC keys, credential-slot mismatch and redirect; assert actual mock-provider attempt counter remains zero.
- [ ] Implement shared bounded typed JSON request profiles: strict JSON-RPC 2.0 `tools/call` with fixed method/tool/argument schema, or reviewed fixed POST path with a closed typed argument mapping. Registration signs the profile/version and mapping. Missing/unsupported profile fails strict execution; no raw byte fallback.
- [ ] Reject duplicate JSON keys during parsing, before conversion to a map. Canonical business request binds target, profile, exact controls, payload digest and credential identity. Kernel derives semantics with the same codec specification used by the executor.
- [ ] Independently validate untrusted worker output against the kernel-bound canonical request before any provider invocation; retain sandbox/size/digest checks. Restrict authentication insertion to the bound slot/target, no auth override, no redirects.
- [ ] Persist final application request digest linked to AuthorizationDigest in executor journal before provider call; exclude secrets from Debug/logs. Cover crash-before/after record, replay, unknown outcome; claim neither TLS-byte equivalence nor provider-internal semantics.
- [ ] For completion-dependent clauses, verify success against the retained provider response using the reviewed closed response codec. A worker's signed `Completion` assertion is insufficient; forged success over a failure/indeterminate response must not unlock successors. Bind authoritative completion evidence to request authorization and retained response. Preserve the existing rejection of post-effect `FailedBeforeEffect` claims.
- [ ] Include `crates/savana-openclaw-release/src/request.rs` and reservation recovery in any outer-frame schema change and its tests. The current transport writes a custom CBOR application frame over mTLS, not native HTTP/MCP; document and validate that boundary accurately.
- [ ] Run focused execd/protocol/kerneld tests then relevant complete suites; commit and review.

## Task 7: Human-readable trusted approval and SDK closure

**Files:** Modify protocol approval display/browser asset modules, approvald handlers, `crates/savana-client`, `crates/savana-core-py` wrappers and README API documentation; deployment manifest/schema files where new purpose/schema is registered.

- [ ] Test trusted display of exact resource→destination pairs, tool/effect/magnitude/unit/budget/preconditions; HTML/control-character attacks; critical oversize fields refused rather than silently truncated. Test task amendments clearly distinct from per-action approval.
- [ ] Render from canonical kernel content, not model prose. Display user-recognizable fields alongside exact identities; reject unsupported/missing mapping. Keep session/origin/authentication bindings intact.
- [ ] SDK transports drafts/handles/closed status only; cannot mint contracts or trusted evidence. Expose precise method/error/version changes and tests; do not promise an unchanged interface count.
- [ ] Validate deployment signer purposes and schema gates without installing locally. Update frozen hash manifests only for reviewed changed files, leave V1 assets untouched. Run focused UI/SDK/config tests, commit and review.

## Task 8: Integrated adversarial/recovery evidence and bounded state model

**Files:** Add `crates/savana-kerneld/tests/intent_bound_execution.rs`, shared real-component test fixtures as needed, `crates/savana-policy-core/tests/task_authorization_model.rs`, `docs/verification/intent-bound-execution.md`.

- [ ] Execute actual authenticated ingress→planner commit→proposal→approval→durable prepare→execd→controlled mock-provider path. Include permitted dynamic multi-step task and summary-only/cross-pair/malicious-worker negative cases with observed kernel state and provider counters.
- [ ] Test every persistence transition using existing crash hooks plus task-specific cases; exact replay, new nonce/run, budget overflow, completion-dependent actions, verified one-time no-effect refund, unknown outcome, stale candidates/amendment and legacy recovery-only records.
- [ ] Add finite state exploration of two clauses/two candidates/two attempts with state version, endorsement/approval, prepare, send, outcome and recovery events; compare legal Rust transitions against independently specified invariants. Record bounds and state counts actually observed, not a full-kernel proof.
- [ ] Run `cargo test --locked --workspace` plus required feature-gated production/security tests discovered from Cargo manifests, format/diff checks, frozen-manifest checker. Separate platform prerequisites from code failures. Fix regressions before claiming closure.
- [ ] Record commands, exact snapshot, pass/fail and exclusions; broad whole-branch security/code review before paper. No experimental security success-rate inference from unit-test counts.

## Task 9: Paper revision after implementation is verified

**Files:** `paper/usenix-sec27/main.tex`, `references.bib`, `README.md`; relevant `docs/academic-summary.zh-CN.md`, `docs/paper-draft.md`, `docs/technical-report.md`; add implementation-to-claim table.

- [ ] Use immutable user LaTeX attachment `e26ecf5e-cfd4-4b41-a129-89f03923f795/pasted-text.txt` as primary prose input, preserving it. Revise repository paper, not attachment.
- [ ] Map each mechanism claim to final code/test/assumption. Focus joint task traces, complete-domain evidence, acyclic digests, atomic consumption and actual business-request boundary. State limited codecs/grammar and remaining experimental gaps honestly.
- [ ] Verify primary citations for PCAS/Progent/CaMeL/FIDES/CapAgent/IGAC and classical endorsement; distinguish threat models from demonstrated attacks. Keep results TBD unless actually measured and report engineering tests separately.
- [ ] Verify current USENIX 2027 formatting/instructions; compile LaTeX, resolve undefined references/labels and check rendered layout with PDF skill. Do not use fallback styling as official submission readiness.
- [ ] Final status must separately state code evidence, unmeasured experiments, remaining limitations, local branch/commits, and that nothing has been pushed/deployed without approval.
