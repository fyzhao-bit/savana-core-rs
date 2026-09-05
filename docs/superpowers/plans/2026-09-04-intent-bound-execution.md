# Intent-bound Execution Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the approved task-authorization/selection/execution design in the existing Rust production path, verify it, then revise the paper to match evidence.
**Architecture:** A separately authenticated task contract precedes planning. The kernel matches whole actions against grouped contract clauses, produces acyclic authorization evidence, and reserves task consumption atomically with dispatch. The executor independently checks the business request before emission.
**Tech Stack:** Existing Rust workspace, bounded canonical CBOR, Ed25519, SHA-256, existing encrypted policy snapshot/WAL and executor journal, existing authenticated ingress/approval services; LaTeX paper.
**Spec:** `docs/superpowers/specs/2026-09-04-intent-bound-execution-design.md` (approved).

**Dependency order:** Tasks 1–3, then Task 6A (shared business-request/profile foundation), Tasks 4–5, Task 6B (executor enforcement), Tasks 7–9. Task 6 is split, not expanded: the authenticated issuer and proposal projection need the same finite semantic mapping before they can display or derive a meaningful contract. The final executor checks still follow production binding integration.

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

- [x] Write behavioral tests first: canonical round-trip; wrong key/purpose/principal/task/manifest/time rejects; mutate each signed binding; malformed lengths and graph reject; alternative cross-pair cannot be represented as an authorized member; content digest mutation vectors with literal expected hashes derived independently once.
- [x] Run `cargo test --locked -p savana-kernel-protocol task_authorization`, record expected failing API/behavior output.
- [x] Implement using existing minicbor/manual bounded decode conventions; export only necessary protocol items.
- [x] Re-run focused tests, then `cargo test --locked -p savana-kernel-protocol`; `cargo fmt --all -- --check` and diff check on changed files.
- [x] Commit this task and report exact test evidence and any unfinished integration (Tasks 2–8 remain required).

## Task 2: Closed joint matching, candidate evidence, and control endorsements

**Files:** Create `crates/savana-policy-core/src/v2/task_authorization.rs`, `control_selection.rs`; export through `mod.rs`. Add `crates/savana-kernel-protocol/src/v2/task_action_approval.rs` and its module export for the independently signed content-bound action settlement. Existing provenance/labels/intent/validator are inspected here; their production binding changes are coordinated in Task 5, after durable state and authenticated issuance exist.

- [x] Add failing tests for summary-only contract vs send even with approval; `(A,Alice)/(B,Bob)` cross-pair; always-untrusted selector including singleton; unproven/partial candidate domain; expired/revoked/changed candidate; digest mutation/cross-action endorsement reuse; ordinary derive cannot accept endorsement.
- [x] Introduce private-field `VerifiedTaskAuthorizationV2` constructed only by expected-key/context verification, and a joint matcher consuming `ActionContentV2` plus current task state. Return an opaque verified match, never a caller-supplied boolean.
- [x] `ControlSelectionV2` records each of seven planes and proposer parent. `ControlEndorsementV2` is separate from `KernelValueV2`/ordinary provenance; constructor is private to checked endorsement. Require the complete seven-plane set exactly once in canonical order.
- [x] Accept closed evidence of a matched explicit alternative, complete-contract-domain singleton, or verified one-use action settlement inside the matched contract. The only first-phase candidate source is the full bounded contract alternative list; registry-derived complete domains can be added only with an independently verified complete snapshot. Runtime values/search pages never establish completeness.
- [x] Bind candidate membership, source digest, epoch and validity; recheck time and current contract revision, not epoch alone. No ContextClean branch.
- [x] Add `AuthorizationDigestV2` construction over content digest, sorted endorsements, settlement digests, policy identity and next-state digest; construct after content-bound settlements. Golden vectors plus individual-field mutation tests.
- [x] Define a bounded, separately domain-signed `TaskActionApprovalV2` material carrying content digest, authorization ID/revision, principal/task/installation/manifest, decision, challenge/settlement nonce, authentication-context and display digests, issued/expires timestamps. Verify with the expected approval-service key/context/time. Only the trusted approval service will sign this after a real ceremony (Task 4); a raw decision/digest/boolean is never accepted as verified consent. Do not rebrand the old `VerifiedApprovalSettlementV2` with a supplied content digest: it discards the envelope binding after verification.
- [x] Keep this phase's matcher/selection/evidence APIs additive and non-dispatching; leave existing G4/G5 construction unchanged until Task 5 can attach the actual persisted authority and close every old issuance path together. Clearly report that these library foundations do not yet enforce production task authorization. Run `cargo test --locked -p savana-policy-core` and protocol tests for the new settlement, commit and review.

Task 2 API/phase details:

- `VerifiedTaskAuthorizationV2::verify` wraps Task 1 expected-key/context verification and stores the immutable contract and its digest. No constructor from plain decoded material. Provide read-only identity/material accessors for the trusted durable owner.
- A joint match checks auth ID/revision, clause/alternative index, exact entire `ActionAlternativeV2`, single-action magnitude bound/unit, complete candidate-domain digest and current validity. It returns an opaque immutable match bound to the exact ContentDigest. Persistent remaining budget/dependency checks are required in Task 3; do not claim a static match proves those.
- Derive candidate domain from every alternative in the verified contract clause, binding contract digest/revision, clause and canonical complete alternatives. Caller-provided subsets or matching epoch alone are insufficient. Current revision/expiry is checked again on use; revocation is represented by the durable current contract (Task 3), not a caller-supplied allow flag.
- `TaskMatchContextV2` is supplied by the trusted current owner and includes a nonzero deployment generation, current verified contract, pre-state digest/revision and time. Recheck action-approval generation and validity at endorsement and final digest use; an earlier valid signature is not permission to survive a generation change. Persisted one-use consumption is Task 3, not proof cloning.
- `ControlFacetV2` order is Tool=1, EffectKind=2, Scope=3, Magnitude=4, Argument=5, Destination=6, Trigger=7. Argument binds the whole canonical parameters digest. Trigger binds contract prerequisites plus the content's pre-state identity. Build all selections from the exact content and nonzero proposer-parent digest, always ExternalUntrusted/READ even for pinned/singleton choices. Endorsements stay outside `ProvenanceRecordV2`, so ordinary value derivation cannot take them as parents.
- Explicit grouped-relation evidence may choose any exact alternative in the authenticated clause; singleton evidence requires the full clause alternative set to have one member AND maximum single magnitude 1 (magnitudes are positive integers). A single tuple with a larger magnitude range is not a singleton of complete actions; it may use explicit grouped-relation or exact approval evidence instead. Settlement evidence requires the new purpose-specific signature and exact content/context/time. No evidence branch may run before joint contract matching.
- `TaskActionApprovalV2`/`SignedTaskActionApprovalV2` use a separate fixed schema/domain with bounded manual canonical encode/decode/sign/verify and expected key checks. Add deployment generation to the material/context. Verify decision Approve before endorsement; Deny/expired/wrong challenge/wrong display/content/principal/task/manifest/generation fails. This is approval-service signed material only; the service's user-authenticated issuance is Task 4.
- Approval-backed endorsements expose immutable verified settlement digest and nonce for Task 3's durable one-use consumption; other evidence kinds expose neither. These values come from the retained verified proof, never additional caller-supplied metadata.
- Final authorization digest builder accepts all seven endorsements exactly once in canonical order, checks content/contract/candidate/pre-state bindings and approval consistency, and binds policy identity plus a supplied nonzero task-transition commitment. That commitment describes pre-state/revision, clause charge/delta and successor revision; it excludes the future AuthorizationDigest and evidence records to avoid a hash cycle. It is not a dispatch capability; only Task 3's atomic owner can establish the authoritative transition commitment and consume the evidence. No ordinary caller can turn this digest into a prepared dispatch.
- Test real library entry points (valid signed fixture keys, no mock checker), with hand-derived expected outcomes. Add table-driven mutations of every sensitive binding. Reject cross-action reuse, dropped/reordered/duplicate facets, false singleton proof, mixed units, expired authorization/approval, and approval outside contract. Keep Error variants closed and payload-free. Add this task's tests in adjacent `_tests.rs` files if necessary for readability.

## Task 3: Task state in the existing atomic policy transaction

**Files:** Modify `crates/savana-policy-core/src/v2/durable.rs`, `dispatch.rs`, `quota.rs`, `production.rs`, `intent.rs`; new `task_state.rs` for bounded transition mechanics, exported only as required.

- [x] Write failures using the actual durable store: same prepare replay once; new request/nonce/run cannot overspend; stale state and dependency not completed reject before reservation; concurrent preparations, budget overflow, amendment preserving consumed counts, crash/reopen at existing persistence hooks.
- [x] Add task contracts/revisions, per-clause attempts/magnitude, durable reservations/verified completion evidence to `DurableG4SnapshotV2`, encode/decode in the existing snapshot with an explicit new state schema. No separate ledger commit.
- [x] At `prepare_tool_dispatch`, check task/current candidates/fence and consume matching capability/approval/endorsements, task limits and existing quota in the cloned snapshot before its single `commit(next)`; return existing record unchanged on exact replay.
- [x] Keep EffectStarted/Indeterminate charged. Verified proven-no-effect disposition may refund once only when contract permits; bind refunds to actual journal entry, not an agent claim. Dependency requires verified success evidence.
- [x] Explicitly decode legacy state for recovery-only queries/effect reconciliation; no new authority can be minted from missing fields. Reject unknown schema without overwriting. Add upgrade/recovery tests retaining unknown effects.
- [x] Run policy-core durable/dispatch suites, commit and review.

Task 3 state/API details:

- Keep the existing envelope/key-derivation/head schema 2; independently version the plaintext payload as 3. Decode and canonically verify the legacy 9-field payload using its legacy encoding before migration. Unknown schema fails without rewriting. Legacy intents/dispatch records retain effect history and reconciliation, but cannot mint or replay a fresh dispatch grant without task authorization.
- The durable owner installs only `VerifiedTaskAuthorizationV2`. It indexes authorization ID and durable task/principal, rejects replacement with a new authorization ID for the same task, and persists contract material in the authenticated encrypted snapshot. Rehydration from that validated snapshot is a crate-private authority path, not a public constructor from unverified material. Authenticated issuance and deployment-key wiring remain Task 4.
- A durable task ID has exactly one authorization identity and principal in this store: changing the principal does not create a fresh lookup namespace for the same task. Contract installation must match the store's installation namespace. At prepare, compare task/installation/manifest/generation and shared plan/descriptor bindings against the actual intent/release and verified effect-gate authority, not just the caller's proposed match context. Persist the full content/authorization association with the exact dispatch subject; Task 5 supplies the real resolved-value projection and propagates this association into seals/wire bindings.
- Initial authorization installation is idempotent only for identical material. An amendment retains authorization ID, task/principal/installation, increments revision monotonically, carries existing consumption and terminal/unknown effects, and retains removed-clause tombstones. Same-revision conflict, revision rollback, consumed-clause unit change and attempts to lower limits below already charged consumption reject. Revocation is durable and blocks new preparation, never discards records.
- A predecessor clause is satisfied by at least one verified successful action under its applicable task graph, not by Prepared and not by requiring every allowed alternative to execute. Bind completion eligibility to the action/dependency skeleton: all clause IDs, complete alternatives (including units) and predecessor edges. If that skeleton changes on amendment, historical successes and old pending outcomes do not unlock the revised graph; their records and charges remain. Limits/time-only amendments with an unchanged skeleton may retain verified completion eligibility. Snapshot no-effect retry permission at prepare; later permission expansion cannot retroactively refund a preparation that forbade it.
- Persist a monotonic completion/skeleton epoch and advance it on each skeleton change; a digest comparison alone must not revive ancient completions after A→B→A amendments. Reservations bind their epoch, and epoch overflow rejects. Cover the round trip in a regression.
- Build a deterministic task-state commitment from the current contract/revision, clause counters, verified dependency state and reservations. Generate the proposed transition commitment from expected pre-state/revision, selected clause, magnitude/attempt charge and successor revision, excluding future AuthorizationDigest. The atomic owner recomputes it and rechecks the final evidence set rather than accepting a caller's nonzero digest as proof.
- Each successful new prepare permanently increments the clause's attempt count. Proven no effect may refund magnitude once if the contract permits retries, but never refunds the attempt counter; maximum attempts remains an absolute bound on preparations. `EffectStarted` and `Indeterminate` remain charged. Neither a bare digest nor a worker completion assertion can unlock a dependency for new task-bound records; preserve the old recovery-only reconciliation interface and require an opaque verified completion/no-effect proof for strict records, with the executor verification producer integrated in Task 6.
- New task-bound tool and final-release preparation use the existing single cloned-snapshot transaction and return the existing `KernelPreparedDispatchV2` only after commit. The existing public preparation API must not silently succeed with missing new authority: stage unsupported daemon call sites as explicit nonexecuting failures until Task 5 supplies it, or coordinate a mandatory argument without a permissive default. No parallel in-memory dispatch engine or separate authority ledger.
- Exact replay must bind the original full content/authorization, intent or release subject, execution nonce and stored reservation and return the original record without another charge. A genuinely new dispatch is a new attempt against the same task counters, never a reset. A different request ID that the existing intent index aliases to the exact same intent and dispatch replays the original nonce without a charge; changed content or evidence is not such a replay. Legacy recovery queries must not turn into a new executor handoff. All non-replay checks happen while holding the owner/registry guard; stale pre-state cannot consume quota. Test overlapping preparations against the actual owner and file-lock semantics, checked overflow, amend/remove/re-add, revocation/reopen, crash/uncertain commit, both tool and final-release paths.

## Task 4: Authenticated contract establishment and amendment

**Files:** Modify protocol `kernel_ingress.rs`, `kernel_service.rs`, `application.rs`, `signed.rs`, `browser_ingress.rs`; input-runtime `src/lib.rs`; kerneld `v2_ingress_authority.rs`, `v2_core_services.rs`, `v2_agent_authority.rs`, startup/runtime configuration; approvald's signed settlement handlers as needed.

Staging boundary: Task 4A adds unprivileged readable draft/control types, exact active-descriptor profile checking, the dedicated task-root approval purpose, and approvald's existing signed ceremony/persistence/query path. It does **not** establish an authenticated kernel issuer. Task 4B must still persist pending issuance identities through the existing owner, authenticate structured ingress or approved drafts, load the dedicated signing key, install/amend/revoke authority, and guard both planner preparation and commit. The checkboxes below remain open until that production integration and its verification are complete.

Task 4A wire notes: readable draft schema 1 is a canonical 12-field CBOR array, bounded to 1 MiB, with separate draft and final-authorization digest domains. Control projections use only Resource/Destination/Parameter fields from the shared business codec; payload and variable quantity are deliberately absent. Task-root approval purpose tag 5 binds authorization ID, task, revision, create/amend/revoke change kind, and draft digest. Registration remains on authenticated `IngressApproval` tag 20; its result tag 5 carries a dedicated opaque handle; settlement query is `IngressApproval` tag 25 with the existing closed Query error contract. AgentApproval does not gain this operation or purpose. Existing display-declassification requirements remain mandatory. A revocation binding is not itself an implemented revocation issuer.

Task 4B checkpoint (2026-09-05): native dedicated-key issuance, exact finalized-input
proof, durable pending/approval/installation receipts, monotonic amendment/revocation,
IngressKernel 51–54 and same-origin browser mutations are implemented. G4 plaintext
schema 4 retains schema 2/3 recovery readers. Planner preparation/commit require the
current root. Input handoff stays Processing until matching authority exists, including
exact replay and root-before-input commit ordering. Dedicated key material/config
generation is wired without deployment. Full protocol/policy/ingress tests pass with
test-local sockets permitted; native issuer 5/5, pending issuance 4/4, handoff 1/1 and
development input generator 1/1 pass. Feature-gated kerneld/policy all-target compilation
passes. Still open: fresh-session browser recovery after in-memory ingress loss,
content-bound task-action settlement production, and end-to-end closure. Latest full
kerneld library run has one known final-release failure because Task 5 has not replaced
the intentionally disabled no-task-authority prepare call. This is not Task 4/branch
completion and is not yet deployable.

- [ ] Test real ingress handler refusal of unsigned/agent-signed/self-attested contracts, wrong user/session/task/version, tampered approved drafts, missing fields, ambiguous free text; valid authenticated structured path and exact approved-draft path succeed before planning.
- [ ] Add bounded structured contract draft operations on authenticated ingress (not JARVIS content-free control). Store canonical draft, render full fields, bind approval challenge/settlement to draft digest and dedicated task-authorization purpose. Trusted kernel issuer verifies settlement then signs; dedicated expected key purpose in startup/config.
- [ ] Authenticate structured input through the existing ingress/session authority. No arbitrary public Rust constructor or boolean stands for a verified user. Unsupported natural-language expressions stay nonexecuting drafts; do not claim an open-language compiler.
- [ ] Amendments require explicit independent task-level approval and monotonic revision, preserve prior consumption and stable clause IDs. Record revocation/version replacement durably before new plans.
- [ ] Require a verified contract on a session before planner preparation. Keep existing signed envelope/template restrictions and test the real commit handler rejects disallowed templates/classes. Correct the old design's inaccurate missing-whitelist claim.
- [ ] Route all new operations with closed role/error/size/version contracts; preserve auth/browser projects outside this worktree. Run protocol/input-runtime/kerneld focused tests and commit.

Task 4 issuance details:

- Avoid a second digest cycle at the task root. A bounded canonical task draft contains the proposed contract identity/revision/context/time/clauses and source-input commitment, but excludes the future task-level settlement and final signed authorization. The trusted renderer binds that draft; task-level approval binds draft digest plus exact rendering/context. Only after verification does the issuer construct `TaskAuthorizationV2` with its actual user-evidence/settlement digest and rendering digest. Do not ask an approval to sign a contract digest that already includes that same approval.
- `ProductionKernelDataPlaneV2` in `v2_data_plane.rs` implements the production `KernelIngressCommitSinkV2`; preserve its finalized-principal check and existing input/vault handoff. `mark_ingress_committed` currently marks a task ready, so ensure real planner preparation independently requires the newly installed task authorization. Retry after an uncertain cross-component handoff may query/idempotently recover the same authorization, never generate a replacement authorization ID or reset consumption.
- Actual protocol approval issuance is in approvald `protocol_service.rs`, with persistence in `protocol_durable.rs` / `protocol_state_owner.rs` and UI ceremony in `ui_authority.rs`. It uses protocol signed envelopes and verified WebAuthn assertions; changing only the older service type in `lib.rs` is not sufficient. New task-root approval purpose must be role-bound to trusted ingress, and task-action settlement must be derived from the stored exact kernel envelope after the real verified ceremony, never from agent-supplied binding fields.
- Preserve display declassification requirements: adding a task-root purpose must not create an agent-callable path for displaying arbitrary sensitive data without its existing gate. Authenticated structured input and approved drafts must be distinguishable evidence sources selected by the trusted handler, not a user/agent supplied `trusted` flag.

Task 4D/7C recovery checkpoint (2026-09-05): IngressKernel 55 and the fixed
same-origin `/v2/task/recover` route resolve existing durable issuance using
fresh task/principal-bound UI authentication, without an old input handle.
Installed current receipts are observations only (no re-sign, activation or
counter mutation); revoked/replaced/expired state is refused. Existing approval
display pairs retain their exact signed bytes. A persisted draft that crashed
before display creation gets the real display gate and still requires separate
task approval. Recovery proof is internally scoped and rejected by structured
issuance/revocation, not rebranded as new finalized input. The actual browser has
a request-digest recovery control; Rust/Python adds
`recover_task_authorization(request_digest, approval)` with fresh authentication
and no upload. Inventory: 19 business methods, 20 types. Pending recovery needs
the previously observed issuance request digest; creation editor/context remains
open. No deployment. Checks: kerneld library 313, policy library 230, ingress
library 21, protocol 245, Rust client 89 and Python SDK 16 passed. Browser DOM
tests cover installed/pending recovery, no implicit commit and wrong receipts.
Two old policy fixtures used a payload digest where evidence belongs; they now
use the release accessor and the stronger production checks remain unchanged.

## Task 5: Connect planner proposals, G4–G7, approvals and release

**Files:** Modify kerneld `v2_agent_authority.rs`, `v2_value_owner.rs`, `v2_agent_durable.rs`, protocol `kernel_agent.rs`, `kernel_agent_success.rs`, semantic bindings and executor wire types; client/agentd operation forwarding where needed.

Task 5A checkpoint (2026-09-05, not Task 5 completion): real tool proposals now
project exact owned fields through the signed business profile, match a unique
complete contract alternative before creating a durable intent, retain the
actual committed planner provenance for all seven untrusted selections, and
recheck task/root/state/generation at evaluation, approval and dispatch. Exact
request-ID aliases retain the same application request ID. Overlapping clauses
with the same complete alternative fail closed rather than choosing a budget.
Contract relation commitments are distinct from ontology relation IDs. The G4
display commitment includes canonical ActionContent and the root digest;
readable trusted rendering remains Task 7. Tool prepare calls the atomic
task-bound owner; final release and the dedicated TaskActionApproval producer
remain unfinished. Existing G5 approval is not rebranded as that new proof.

Nested dispatch cores use schema 3 / 15 fields for new task-bound records, binding
ContentDigest, AuthorizationDigest and the preseal plaintext-plus-declassification
commitment before the atomic commit. Legacy schema 2 / 14 fields remain readable
for recovery only. The preseal commitment is NOT the final provider-request hash.
Recovery rejects a new bound core with missing task accounting. Protocol/policy
core encoding parity, exact replay, paired proposal rejection, post-commit slot
swap, revocation, generation change and existing execution declassification gate
have focused regression coverage. This checkpoint does not yet enforce worker
business-request equivalence or prove the end-to-end provider path (Task 6B/8).

- [ ] Test arbitrary planner steps and slot swaps through `commit_planner_value`/`propose_tool_call`, full cross-pair rejection, summary→send rejection even when global tool allowed, fabricated evidence, fresh-run budget resets, replanning within contract, declassification gate refusal before prepare.
- [ ] Attach contract identity to durable session/run state; at proposal resolve owned values into the exact joint action and candidate domain. Do not trust planner asserted resource/destination identifiers: derive from stored bindings and registered codec mapping.
- [ ] Preserve proposer provenance for all seven selected controls. Build ContentDigest, render approval from it, settle then endorse; construct final AuthorizationDigest only afterward. Bind intent/capability/approval/journal/seal/receipts consistently with no cycle or missing-field fallback.
- [ ] Populate verified relations from contract matching, replace the empty relation assumption. New plan versions require fresh evaluation but cannot alter authority. Final release must obey the same task resource/destination/effect budget constraints, not become an unguarded bypass.
- [ ] Route to Task 3 atomic prepare. Recovery never reconstructs new grants from old records. Run kerneld production-handler tests plus existing declassification/leak-gate regressions, commit and review.

Task 4C/5B action-approval checkpoint (2026-09-05): tool G5 creates a schema-3
approval envelope binding ContentDigest plus authorization ID/revision and task.
After the real verified user ceremony, approvald signs the separate TaskActionApproval
and persists it together with the generic settlement. New settlement arity 4
transports this proof; legacy arity 3 never supplies it. Recovery rejects removal
or mismatch of a required proof. The paired UI task must match the action task.
Native authorization independently verifies both signatures and the exact stored
envelope/content context before marking consent consumed. G7 uses approval-backed
endorsements when consent is required, carrying the real settlement digest and
nonce into atomic task consumption and AuthorizationDigest. No old generic consent
is rebranded as the new proof. Protocol, real approval-service ceremony/recovery,
and native proposal/evaluate/authorize regressions pass. Task 7A's actual tool
approval display now renders deterministic readable JSON with exact resource,
destination, complete request, budgets and predecessors; format characters and
markup are escaped without changing request semantics. Overlong expansion is
refused, never truncated. Tests: full protocol 241, approvald 19, native agent
authority 31 passed. Final-release producer and whole-chain validation remain open.

## Task 6: Exact request profile and executor boundary validation

Native final-release checkpoint (2026-09-05): release preparation now derives a
unique complete final-release alternative from the current authenticated draft,
actual owned input and committed plan; the original source is mandatory evidence.
The actual vault bytes are encoded in the reviewed closed delivery request and
the readable action display. Both generic release consent and its separately
signed exact TaskActionApproval are required before consuming consent. Dispatch
rechecks the current task, preserves the raw-plaintext leak gate, and calls the
atomic task-bound prepare before sealing the content/request capsule. Atomic
prepare additionally rejects a release whose destination or evidence differs
from its matched action, without consuming budget (behavior reproduced before
the fix). A real native/vault/approval-proof fixture reaches authenticated Suite1
IPC; the captured dispatch independently verifies, decrypts and checks its exact
bytes/turn/core. The fixture executor deliberately returns ServiceUnavailable:
this is not provider success or a complete issuer-to-provider experiment.
Full feature-gated kerneld library: 310 passed. The V1 replay-boundary test passed
in isolation (305.18 s); earlier intermittent expiry/frame failures mean the
whole-branch result still requires a fresh run. No V1 production behavior changed.

Final-release receiver checkpoint (2026-09-05): the closed fixed POST mapping now
names `input:<digest>` and `application-turn:<digest>`, with canonical unpadded
base64 for at most 32 KiB of actual binary payload and a count of one release.
The receiver checks that exact turn against its durable reservation, rather than
assigning whichever delivery arrives next. New raw legacy bodies are refused;
explicit legacy claimed journal records remain readable/reconcilable without
rewriting on open. New claimed records use a distinct tag and revalidate the
inner turn on recovery. The mTLS receiver returns the reviewed correlated JSON
success response only after durable claim. Outer custom CBOR/mTLS framing stays
unchanged. Protocol capsule checks tie actual decoded bytes, destination and
evidence to the authenticated release core. Tests: full protocol 242 passed
before the additional core-consistency test; both focused release codec tests
passed afterward. Full receiver suite 16 passed, including actual mTLS positive
and wrong-turn/legacy-body rejection. This is not the complete native issuer to
provider run; live profile deployment and UI/context integration remain open.

Task 6B execution-boundary checkpoint (2026-09-05): the real tool seal now
contains a closed ActionContent/business-request capsule. The executor verifies
its preseal/core binding, actual target and credential identities and compares
the worker request before the provider-attempt journal transition. New execution
without a supported profile is refused. The custom outer CBOR/mTLS frame is
unchanged. Both live completion and retained-response recovery classify the
transport-retained response using the pinned closed response codec; a worker's
success cannot override failure, unknown, wrong-ID or malformed responses.
Signed terminal evidence binds AuthorizationDigest, the actual journaled outer
application request digest, retained response digest and completion descriptor.
Native consumers verify it before result commit/dependency advancement. Signed
no-effect query evidence replaces fabricated status digests for task refunds;
dispatch acknowledgement alone no longer caches a terminal result. Historical
terminal reconciliation can finish after expiry, without starting another effect.

Checkpoint checks: protocol full suite 239 passed; policy library 230 passed;
executor library 53 passed (local mTLS socket tests outside sandbox); native agent
authority subset 30 passed. Exact request mutation test includes a positive
provider-attempt control; actual retained-owner tests cover seven response cases.
These are component/handler checks, NOT the Task 8 complete issuer-to-provider
experiment. Dedicated action approval, real final-release producer, production
profile deployment and full-branch verification still prevent overall completion.

**Files:** Create protocol `business_request.rs`; modify policy descriptor/codec mappings, kerneld action projection; execd `worker_supervisor.rs`, `connector_runtime.rs`, `provider_transport.rs`, executor journal and protocol executor types.

Execution split: implement and review shared bounded request/response types, canonical codecs and signed descriptor mapping as Task 6A immediately after Task 3. This foundation supplies Tasks 4–5 with exact resource/destination/parameter/magnitude projections and displayable values. Integrate actual pre-provider validation, journal binding and authoritative outcome production as Task 6B after Task 5. Neither subtask alone completes Task 6 or establishes end-to-end enforcement.

- [ ] Write executor-boundary failures for worker-changed recipient/resource/tool/method/path, duplicate or unknown control fields, extra JSON-RPC keys, credential-slot mismatch and redirect; assert actual mock-provider attempt counter remains zero.
- [ ] Implement shared bounded typed JSON request profiles: strict JSON-RPC 2.0 `tools/call` with fixed method/tool/argument schema, or reviewed fixed POST path with a closed typed argument mapping. Registration signs the profile/version and mapping. Missing/unsupported profile fails strict execution; no raw byte fallback.
- [ ] Reject duplicate JSON keys during parsing, before conversion to a map. Canonical business request binds target, profile, exact controls, payload digest and credential identity. Kernel derives semantics with the same codec specification used by the executor.
- [ ] Independently validate untrusted worker output against the kernel-bound canonical request before any provider invocation; retain sandbox/size/digest checks. Restrict authentication insertion to the bound slot/target, no auth override, no redirects.
- [ ] Persist final application request digest linked to AuthorizationDigest in executor journal before provider call; exclude secrets from Debug/logs. Cover crash-before/after record, replay, unknown outcome; claim neither TLS-byte equivalence nor provider-internal semantics.
- [ ] For completion-dependent clauses, verify success against the retained provider response using the reviewed closed response codec. A worker's signed `Completion` assertion is insufficient; forged success over a failure/indeterminate response must not unlock successors. Bind authoritative completion evidence to request authorization and retained response. Preserve the existing rejection of post-effect `FailedBeforeEffect` claims.
- [ ] Include `crates/savana-openclaw-release/src/request.rs` and reservation recovery in any outer-frame schema change and its tests. The current transport writes a custom CBOR application frame over mTLS, not native HTTP/MCP; document and validate that boundary accurately.
- [ ] Run focused execd/protocol/kerneld tests then relevant complete suites; commit and review.

## Task 7: Human-readable trusted approval and SDK closure

Task 7B SDK checkpoint (2026-09-05, not full Task 7 completion): Rust and the
asynchronous Python facade now expose `establish_task_authorization`,
`approve_task_authorization`, and `revoke_task_authorization`. They transport only
bounded unsigned drafts and receipt observations over the four existing same-origin
Ingress task routes. Dedicated task-purpose credential approval cannot be replaced
by a tool-purpose approval. Wrong issuance receipts close the client without a new
nonce retry. Public inventory is now 18 business methods and 20 Python product
types; English/Chinese READMEs and API inventory tests match. Rust client 88 passed;
Python SDK 15 passed against a newly built local extension, without installation.
Full Python-target compilation passed. Still open: contract editor/context,
fresh authenticated-session recovery, reviewed live profiles, deployment hashes,
final-release producer and complete integrated validation.

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
