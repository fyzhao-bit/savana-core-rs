# Fused host integration and remaining product work

2026-09-24 update: an optional manifest-configured Unix mTLS production worker
and Python endpoint are now implemented; see [worker integration](fused-model-worker-v04.md).
The default pool remains empty. Earlier statements below that all production
workers are placeholders describe the pre-integration state, not the new code.
No live deployment or full AgentDojo protection is implied by this update.

2026-09-20. This is an implementation/verification record, not a claim that all
non-cloud v0.4 product work is finished.

## Actual daemon path

The normal V2 daemon lifecycle invokes private workflow ticks at a 100 ms cadence
without catch-up bursts. A tick is an internal command on `KernelRuntimeOwnerV2`,
not an Agent/HTTP/MCP operation. It shares serialization, queue cancellation and
the commit-claim boundary with service calls and signed administration. Readiness
must be published first. Wall time is sampled inside the owner, not supplied by a
model and not the timestamp at which a queued command was enqueued.

`KernelAgentAuthorityV2::tick_fused_planning` selects at most one enrolled task per
turn, with private round-robin selection. It resolves the actual session input
from `KernelValueOwnerV2`, checks principal/root/installation/manifest/run/expiry,
and selects the worker by the signed slot's recipient. No model-supplied parent
provenance or raw outbound request is accepted.

The current deployment lease is held through the G3-gated exchange. Provenance
expiry is capped by the input, session and current trust lease. A stale or absent
deployment, revoked task or mismatched session sends nothing. The worker pool is
empty in production: Google Cloud/DeepSeek remain the requested placeholders.
The daemon does not silently select a public API or synthetic-success worker.
When a worker/session is unavailable, `SkipExpiredDeliveries` only persists missed
public windows; it does not reserve a fictitious sent attempt or create a plan.
The kernel's Linux AF_UNIX-only network restrictions remain unchanged.

An accepted plan can activate only through the existing durable prefix-preserving
transition. This is not an execution ticket. If the process stops after reply
settlement but before activation, the scheduler reconstructs pending activation
from stored accepted candidates and resumes without another model request.
A refused candidate cannot starve future signed model slots. Storage uncertainty
is treated as unavailable, not as a harmless model rejection.

## Frozen-action dispatch binding

`DurableG4StateV2::bind_fused_dispatch_v04` now resolves the next operation
from the active durable candidate and an existing frozen G4 intent. It checks
installation, manifest, task, generation, current root/pre-state and the exact
signed execution commitment. It cannot skip ahead to another matching action,
substitute newly created value handles or silently repair a stale supplied
selector. A dependency must have an authenticated `CompletionCommitted` journal
entry for the original task/intent/nonce, not just a reservation or an Unknown.

The daemon's tool-dispatch path calls this binder before managed-input binding
and G7 preparation. New-work preflight and G7 share the same
activation/order/material/dependency predicate. Preflight is read-only and does
not charge, reserve, send, approve or mint an execution ticket. If activation
changes after preflight, the old selector is rejected by the G7 transaction.

For an already dispatched intent, recovery selects the original operation and
activation revision, including after plan replacement and encrypted reopen. Its
entire original action content must match the persisted dispatch binding; even a
refreshed pre-state under the old intent ID is refused. G7 retains the original
nonce and consumption. An uncertain/poisoned owner supplies no binding.

This is a bridge for **already frozen and signed exact work**, not a compiler
that creates new actions from model proposals. In particular, the daemon's
earlier fused-session legacy guard still prevents ordinary Agent requests from
reaching this branch for an enrolled task. No public readiness/status API was
added, and no private compiler/publisher bypass was introduced. Candidate-to-G4
construction and its private caller remain outstanding; do not interpret this
call-site wiring as an enabled end-to-end fused workflow.

## Private local candidate compiler

The kernel now has `prepare_active_fused_actions_v04`, an internal **draft-only**
compiler. It reads the durable activated plan, not the newest accepted proposal,
and lowers its closed operation/slot definitions against the current role-filtered
tool registry and the session's signed planner limits. Local inputs are owned
value handles mapped to the signed slot IDs; missing/extra/duplicate/aliased slots,
unknown handles, wrong runs/manifests and future/expired source provenance are refused.
No model supplies resolved values or trusted source facts.

Compilation holds the existing current-deployment read lease, rechecking actual
installation/manifest/generation and live signing roots, and caps local provenance
expiry by the lease, profile, session and inputs. It uses the non-improving candidate
provenance transition locally, **not declassification or a model call**.

The legacy proposer and this compiler share `prepare_tool_intent_material`: actual
stored-value resolution, complete root tuple matching, task-linked slots, business
request construction, destination/display projections, provenance and verified G4
material construction. This is not a second permissive implementation of G4. A
valid field combined with a wrong destination still fails whole-action matching.
The compiler alone creates no durable intent, public handle, G5 decision,
approval or G7 grant. The later private action layer below is a separate caller.

The returned in-memory private draft has no Debug/Serialize implementation. It
contains concrete G4 material, exact execution/display bytes, execution commitment
and a private comparison with the profile's signed commitment. That comparison is
**not execution authority**. No admin/Agent/MCP/Python endpoint or daemon callback
has been added to publish the draft. Private pinning and G4/G5/G6 orchestration
were subsequently added below; consumer entry/signing/UI and sending remain closed.

### Real-material replacement limitation uncovered

Logical operation and business request IDs now stay stable across reorderings;
they are not derived from the new ordinal. However, real G4 material also commits
the task-match relation and approval display. Those can change with plan/pre-state
even though the visible business parameters are unchanged. The earlier synthetic
zero-argument G7 fixtures do not establish approval reuse for these real materials.
A new regression makes this explicit: reorder two compiled operations, retain each
request ID, and observe changed exact execution commitments. No security field was
removed or normalized to make them compare equal.

Consequently, reusing the original frozen G4 material and current task evidence,
or introducing a separately specified/checked stable-recipe approval format, is
still required before automatic multi-step/replacement execution. The existing
signed profile cannot simply be replaced mid-task. The current compiler produces
private drafts and deliberately does not pretend this obligation is solved.

### Checked recipe evidence (exact-draft-bound, not an approval)

`FusedExecutionRecipeV04::from_verified_g4` now constructs a separate typed,
non-serializable recipe witness from the current G4 material, verified whole-task
match and the original neutral local slots. For every argument it reconstructs
the exact task-linked slot and checks its digest, ordinal, owned value identity,
value digest and provenance. Missing/reordered/already-task-bound witnesses fail.
This does not simply erase slot hashes from an untrusted description.

The purpose-separated recipe hash retains the exact root and deployment generation,
logical operation identity, descriptor/publisher/registry activation/retry policy,
executor and attempt kind, argument names, full neutral slots (installation,
manifest, run, type/cardinality/confidentiality, owned value and provenance),
tokens, exact destination projection, display **implementation**, and action
tuple/magnitude/payload/candidate domain. Only the plan revision, pre-state counters
and their derived task relations, and the rendered display **result**, are outside
recipe equality. The actual G4 material and current display are never modified.

The witness also records the exact material/content digests.
`matches_exact_draft` refuses transplanting it onto a different G4 draft even when
both recipe hashes match. A recompile must construct its own exact evidence; the
old G6 approval does not transfer. Equal task matches alone do not identify an
operation: two identical business effects still have different logical step and
projected request identities, which this recipe keeps.

The local compiler now produces this evidence alongside its existing exact
commitment. It is deliberately **not accepted by current exact execution
bindings** and not used as a G7 capability. The follow-up admission layer below
stores a separately signed allowlist; it does not reinterpret legacy signatures.
The schema-16 layer below now provides private persistent input bindings. Next steps require private signing/UI
preparation and an exclusive private orchestrator with live G4/G5/G6/G7 checks and
original execution identity preservation. Recipe equality does not prove remaining budget,
dependency completion, noninterference, or a safe general continuation replacement.

Tests cover real owned-store G4 reorder (equal recipes, unequal exact commitments),
same plaintext with different source (unequal recipes), malformed/cross-context
witnesses, and exact-draft transplant refusal. Static policy proof tests additionally
cover changed pre-state, pinned root/generation/magnitude, 20 security-field
mutations and run/type/cardinality/confidentiality changes. Static tests are not
presented as durable multi-step execution or budget-recovery evidence.

Recipe-batch validation: **371 policy tests**, **329 serial kernel tests**,
eight focused real-G4 compiler tests, kernel/client/Python compilation and Linux
policy/client cross-target compilation pass. Clippy exits successfully with
existing warnings; all **251** refreshed source fingerprints verify. These are
Mac-hosted checks, not native Linux service or hardware-anchor acceptance.

### Separate signed recipe admission (schema 14)

The private admin route now supports `ApprovePlanningRecipes` with a separately
signed `FusedRecipeApprovalV04`. Its schema-1 recipe digest meaning, exact root,
profile, installation/manifest, generation, lifetime and complete operation list
are pinned. Protocol enrollment can precede local draft compilation, followed by
this separate one-time approval; the original profile/root is not rewritten.
Existing exact-binding profiles cannot be switched into this mode. Installation
and its retry receipt commit together; replacement/expiry-based renewal under a
fresh request ID is refused. Existing effects cannot be retroactively approved.

The existing private compiler reports `matches_recipe_approval` after real G4
construction and under the current deployment lease. Tests show approval remains
matched across a permitted reorder, but not a new source for identical text, a
different generation, or expiry. This is separate from `matches_profile_approval`:
the latter remains false for recipe-only enrollment. No intent/handle/effect is
created by this compiler. G7's existing exact-binding path explicitly refuses
recipe approval alone, including after restore or if an exact commitment was
signed in the recipe field. The separate typed-evidence path below adds the live
G7 check; it does not reinterpret legacy exact signatures.

Restore and failure tests cover immutable admission, expired exact receipt replay,
revoked roots, wrong scope/signatures, schema downgrades, receipt/state substitution,
uncertain anchor commits and rollback to pre-approval state. Payload schema 14 can
coexist with the optional schema-13 delivery schedule. These tests use the actual
encrypted owner, not a simulated success response. Recovery of volatile local value
handles was subsequently added below; authenticated session recovery and
end-to-end private execution are still outstanding.

Admission-batch validation: **380 policy tests**, **330 serial kernel tests**,
**5 Rust admin SDK tests** and **6 Python tests against the built native extension**
pass. Linux policy/client cross-target checks and Clippy (existing warnings) pass;
all **252** source fingerprints verify. No Linux service was installed or reset.

## Python/operator preparation

`savana.managed_admin.prepare_artifact(kind, document_bytes)` invokes Rust parsing,
validation, canonical serialization and purpose-separated digest calculation.
Supported kinds are `command`, `planning_profile`, `storage_profile`,
`dispatch_policy`, `source_policy`, and `recipe_approval`. The return value has a redacted repr and
explicit `canonical_bytes()` and `signing_digest()` accessors. It works offline
and performs no submission or key access.

Review the returned canonical bytes in the private operator environment. The
independently provisioned authority signs the exact returned digest. Nested
profile/policy signatures must be prepared first and placed into the outer
command; prepare/sign that final command last. Then use the existing Linux-only
`submit_signed(canonical_bytes, signature)` API. After uncertain delivery retain
and retry identical bytes/signature/request ID; do not mint a fresh command.
Preparation is not verification of a live deployment/root or of nested
signatures; the kernel still performs those checks. Never expose these methods
or artifacts to a planner tool or general chat renderer.

The Python extension now uses PyO3's build-script link setup, so an ordinary
`cargo build -p savana-core-py` works on macOS without ad-hoc dynamic-lookup flags.
Linux behavior is unchanged. No signing keys were generated or installed.

## Evidence

Host tests use real session/value provenance, the encrypted policy owner, signed
rules/profile and a deterministic test-only worker. They verify one-call
activation, disabled-worker behavior, failed/malicious responses, stale policy,
wrong principal, revocation, and recovery between reply and activation. An owner
test checks expired ticks cannot mutate. A separate encrypted-reopen test checks
the accepted candidate remains pending activation without retransmission.
Operator tests verify canonical digest stability, unknown/duplicate-field
rejection, redacted objects, no submission side effect, and Python-to-Rust calls.

Previous host batch results: 360 policy tests, 321 serial kernel tests, 48 continuation-core
tests, four Rust operator SDK tests and five Python tests against the freshly
built native extension pass. Focused policy fusion tests: 39. Ordinary Python
extension build and Clippy succeed (existing lints remain). All 249 source
fingerprints verify. Linux x86_64 target checks pass for policy core and client;
the full kernel target check stops in `ring` because this host lacks
`x86_64-linux-gnu-gcc`. Neither target checking nor Mac tests prove Linux runtime
or hardware acceptance.

Dispatch-binding tests add six cases covering read-only selection followed by
actual G7, encrypted replay, replacement/stale-preflight refusal, changed
material/current-policy refusal, real dependency outcomes, and legacy isolation.
They also cover exact replay content and poisoned-owner refusal. The focused
fusion suite now contains 45 tests. The fixtures use the actual encrypted owner
and G7 journal, not a cloud or provider-success substitute.

Final dispatch-binding regression: **366 policy tests**, **321 serial kernel
tests**, and **45 focused fusion tests** pass. The first sandboxed kernel run
failed at temporary Unix-socket permissions and poisoned the shared test lock;
the rerun with local test sockets allowed passed all 321. Kernel/client/Python
extension checking and Clippy pass (existing warnings remain), as do Linux
x86_64 policy/client target checks and all **249** explicitly refreshed source
fingerprints. The fingerprint list is a source baseline, not a signed deployment.
No new native Linux execution or hardware acceptance was performed.

Final compiler batch regression: **368 policy tests**, **327 serial kernel
tests**, six focused real-G4 compiler tests and **47 focused policy fusion
tests** pass. The current-generation negative test initially exposed that the
root matcher alone accepts a supplied nonzero generation; the compiler was
fixed to hold/check the actual deployment lease. The final suite also checks
source not-before/expiry, real tuple mismatch, no new handles or durable writes,
reorder identity and changed exact approval commitments. Kernel/client/Python
extension checks, Linux policy/client cross-target checks, Clippy (existing
warnings), diff checks and all **250** refreshed source fingerprints pass.
This is still Mac-hosted verification, not Linux runtime acceptance.

## Live recipe verification in the durable G7 owner (schema 15)

`TaskDispatchAuthorizationV2::with_fused_recipe` accepts only a sealed,
non-deserializable `FusedExecutionRecipeV04`, not a hash from an RPC or model.
For a new execution, both preflight and the prospective G7 transaction verify:

- The next active operation and its dependency success; plan/step identities must
  equal the private compiler's policy/revision-derived identities.
- The separately signed allowlist, current root, actual dispatch generation and
  validity window, plus exact G4 material and action-content witness equality.
- All existing G5/G6, task endorsement, current pre-state, connector/fence and
  quota checks. A matching recipe never supplies the required G6 settlement.
- The original dispatch expiry must not exceed recipe-approval expiry. Passing a
  longer fresh lease cannot extend an old execution on replay.

The transaction records approval/recipe/exact-material/content digests and
admission time together with the original operation/revision/intent/nonce and
accounting. Schema 15 is required once such a receipt exists. It is an assertion
by the authenticated durable owner that the live witness passed, **not** a newly
deserialized live witness. Restore cross-checks this assertion against the signed
allowlist, frozen intent, task binding and dispatch journal under the existing
encrypted snapshot and rollback-anchor trust assumptions. It does not reconstruct
neutral source slots from hashes or independently re-prove a compromised owner.

Replay can use that original receipt without manufacturing fresh recipe evidence;
if supplied, evidence must still match the original exact material/content.
Replacement cannot reset the execution identity, started prefix or consumption.
Unknown outcomes retain reservations; an authenticated no-effect outcome retains
the attempt and follows existing V2 magnitude-release policy. Only authenticated
success unblocks dependent operations, including an old execution's late response.

Six new tests use nonempty stored bindings, real G5 and G7 transactions and encrypted
owner recovery. They cover reorder/replay, stale or transplanted evidence, changed
source, expiry, missing G6, receipt corruption/schema downgrade, uncertain anchor
commits and late success/failure/Unknown. Descriptors, signing keys and authenticated
effect dispositions are private test fixtures; no provider effect is sent. Separate
kernel tests cover the real owned-store G4 compiler. These are complementary checks,
not a claim that a live consumer workflow now reaches this new path.

## Immutable local input registration and recovery (schema 16)

The host-private `pin_active_fused_inputs_v04` compiles already-owned values under
the actual deployment lease before pinning. It is not a JSON/MCP input importer:
the trusted host first authenticates the session and resolves the original values
through the existing owner. Canonical value/provenance self-consistency alone is
not a substitute for this trusted admission step.

The durable `pin_fused_inputs_v04` records the complete signed-policy slot set,
stable value IDs, canonical bytes, original provenance, profile commitment (which
includes task/root/installation), manifest, durable run, generation and capture time.
Limits are 256 distinct slots/identities, 32 KiB each for canonical value and
provenance, and 128 KiB combined per task. Internal-slot values, missing/extra slots,
duplicate identities and foreign/expired provenance are refused. Value and
provenance byte buffers are zeroized on drop.

Admission is immutable and must precede recipe approval or effects; legacy exact-
binding profiles cannot opt in. Identical live retries make no new commit. Changed
bytes, source, IDs, run, lifetime or generation cannot replace the record. Schema
16 coexists with recipe approvals, G7 receipts and delivery scheduling; recovery
validates scope/content/provenance and rejects a missing feature/schema downgrade.
This uses the existing encrypted owner and rollback anchor, not another state file.

`restore_active_fused_inputs_v04` requires a current authenticated session of the
original durable run, current root and deployment lease. It restores only the
durable owner's typed recovery result. The value owner separates the fresh handle's
authorization commitment from the original G4 value identity: old process handles
are invalid, while new process handles retain the original identity and provenance.
Restore checks every input and total capacity before installing any values; retries
in one process return the same newly minted handles. It neither recreates a login
nor extends an input, task, session or approval lifetime.

The private compiler checks each supplied value against its fixed slot. G7 separately
checks the frozen intent's names/IDs/value/provenance/run against this record, even
if someone signs an inconsistent recipe. Dispatch expiry is also capped at the
earliest fixed-input expiry. Original dispatch replay retains its original receipt;
no task budget, attempt or permission is reset by input recovery.

Tests separately exercise encrypted-owner reopen/uncertain commits/corruption,
real G4 compilation with a newly created value owner, process-handle invalidation,
stable recipe identity after reorder, substitution/late pin/capacity/generation/
revocation rejection, and pinned-input G7 admission/replay. Kernel tests supply the
already-authenticated session through fixtures; they do **not** establish full
production process/session restart, live provider execution or consumer UI recovery.

## Private next-action G4/G5/G6 orchestration

`prepare_next_fused_action_v04` accepts only a current local run and owner context,
not a model-supplied operation ID, argument map, draft or proposal request ID. Under
the current deployment lease it reads the next unreserved operation from the active
durable plan, restores only the pinned input set, compiles real G4 material, and
requires the separately signed recipe match. A purpose-separated deterministic
proposal identity binds installation/manifest/run/task/profile/plan/operation and
the exact commitment/current content. The shared `commit_prepared_tool_intent`
creates or replays the original durable G4 intent.

The resulting action is private and non-serializable. A route marker on its volatile
intent record separates it from legacy Agent actions. Public evaluation,
authorization and dispatch refuse this marker; merely knowing a pending handle or
ticket is insufficient. No Agent/MCP/Python endpoint or daemon driver invokes the
new orchestrator yet. The following private dispatch layer extends this boundary
without making its handles available to those callers.

`evaluate_fused_action_v04` uses the same stored-binding resolver, business/display
comparison, ontology, validators and durable G5 decisions as legacy evaluation.
`authorize_fused_action_v04` uses the same G6 settlement signature/challenge,
principal, purpose, manifest/generation and exact task-content checks. The approval
handle is selected locally from the action; the caller supplies only its signed
settlement. Recipe admission never converts RequireApproval to Permit. Approval
envelope lifetime is capped by the fixed inputs, session, recipe and creation-time
deployment lease; every subsequent call still needs a live lease/current root.

Both stages recheck the active revision/next operation, current recipe, pinned-input
lifetime and current task pre-state. Replacing a pending plan invalidates its old
action/approval; an unstarted action is not silently rebound to a fresh pre-state.
G5 uses the rules borrowed from the held lease rather than reacquiring the same
publication lock, avoiding nested-read deadlock when a deployment writer is queued.

Six new tests cover real G4/G5 Allow/Deny, deterministic retry, lost volatile
intent/ticket mappings, missing pin/recipe and wrong generation, replacement/expiry/
revocation, and G6 generic/wrong-content/correct signed receipts. They also test the
legacy evaluation/authorization/dispatch guards with known internal handles.
The lost-mapping test retains the authenticated session and the existing durable
owner; it is not a production process-restart or user approval-device test. These
tests make no provider call and consume no task execution quota.

## Private G7/execd dispatch and reconciliation

`dispatch_fused_action_v04` accepts the private action, resolves its ticket locally,
and uses the existing dispatch implementation under the current deployment read
lease. It supplies the stored typed recipe to `bind_fused_dispatch_v04`; G7 still
checks the exact G4 material/content, current activation, root/pre-state, fixed
inputs, G5/G6, dependencies, connector and quota. The envelope deadline is capped
by the private action's input/session/recipe deadline and the current deployment
lease. The original G3 handoff must succeed before registry sync or G7 charge.

Legacy/public and private routes are checked **before** cached dispatch or any
intent/ticket/execution status lookup returns a result. Each volatile execution
also pins manifest, deployment generation and effect fence. A cached retry checks
that context and returns the original execution handle without sending or charging
again; it does not authorize a new effect. This applies after a lost dispatch
response. The recovery layer below now handles a G7 commit with no surviving
volatile execution record, without creating a new send ticket. Production service
restart coordination and login/session recovery are separate, still-pending work.

`reconcile_fused_execution_v04` queries only that original nonce/core/subject.
Status witnesses are checked for the exact queried execution, manifest/generation/
fence, digest and expected signing key before accounting or fetching results.
Known success still needs the existing exact signed task outcome plus result-vault
commit. Lost cleanup acknowledgement retains the already committed success and
does not insert/send again. A signed no-effect result follows the root's retry
policy; it is not unconditional magnitude refund and never resets attempts.

For this private route, an uncertain query response is a **transient observation**,
not V2's irreversible terminal-Indeterminate disposition. The original reservation
is retained, or a supplied exact effect-start receipt is verified and recorded.
The host may query again for a late signed success, including after recipe expiry
or task revocation; settling an old effect creates no new authority. This does not
change legacy V2 terminal-state semantics or authorize blind retransmission.

The status/document-handle wrapper has no public constructor, serde or RPC. These
are internal results, not planner observations or output publication permissions.
No final-release guard is opened. Eight added regressions cover handoff refusal,
old-plan/expired-recipe refusal, real local execd success, response/ack loss,
no-effect under a no-refund root, transient Unknown followed by late success,
legacy cache/status isolation and foreign-nonce/key/digest rejection. The executor
journal, authenticated IPC, envelope crypto and result vault are real test paths;
provider calls use only a test connector in temporary directories, not a network
provider, native Linux deployment or a production recovery workflow.

## Historical execution/result recovery (schema 17)

G7 now accepts a host-private `FusedResultScopeV04` built from the original
authenticated session: principal, provenance producer, result expiry and permitted
effect labels. This is trusted host input, not a model assertion or a new signed
user approval. It is admitted only alongside fixed inputs and an exact recipe;
principal and lifetime are checked against the original task root. The scope is
saved in the same encrypted, rollback-protected transaction as the execution link
and budget reservation. Exact replay cannot change it. Schema downgrade, missing
scope feature, invalid principal/producer/effect bits and invalid lifetime fail
closed. Older records without a scope are not backfilled from today's session.

`recover_fused_executions_v04` returns opaque, non-deserializable historical
projections after validating the journal/intent/recipe/task links. It uses historical
authority rather than requiring a currently unrevoked/unexpired plan. Recovery
does not renew permission: the only reconstructed objects are private query handles
for the original nonce/core/subject. The host validates deployment context and all
capacity/collision checks before changing the volatile table. It does not restore
a login, approval, action or execution ticket. No consumer or Agent RPC calls this
helper. A prepared-but-unsent execution retains its original reservation; this
implementation does not blindly resend it or infer no-effect from missing status.

Private result provenance uses the original G4 material/intent/G7 core identity,
not a process handle. After verified success, the order is: exact result vault
commit, signed outcome accounting, immutable result-reference checkpoint, then
executor cleanup acknowledgement. A crash before the checkpoint repeats the exact
fetch/gate/vault commit; a crash after it can restore the document directly from
the vault, even after execd has cleaned its copy. The checkpoint stores only a
stable reference, never plaintext or a process document capability. The trusted
host supplies that reference only after the actual vault commit; its owner API is
not itself an independent proof of storage by an untrusted caller.

Vault restoration checks the result-specific ID domain, task/run/principal,
original commit digest, exact expiry and Live state. It cannot promote Pending,
revoked or expired data. Across service boots, only the internal segment capability
is rotated; exact result replay still requires the same bytes, provenance and
lifetime. Old segment tokens are invalidated, fresh document handles use the
current authenticated boot, and same-process query retries reuse their handle.

Tests independently reopen the encrypted kernel owner and vault (the latter under
a new boot), and run real local execd/vault integration while clearing volatile
sessions/intents/approvals/tickets/executions. Fault injection covers post-G7,
post-vault, post-outcome and post-checkpoint cuts; no additional provider invocation
or budget reset is permitted. This is not yet a native Linux multi-service reboot
acceptance test. Retained execd data must not be mistaken for permission to repeat
the effect.

### Production historical recovery driver

The existing daemon timer now enters the same serialized owner through
`tick_private_workflows_v04`. Historical recovery, planning and new actions rotate turns;
recovery selects one scoped execution at a time, sorted by nonce with a private
round-robin cursor, and permits at most one pipeline per second. All network calls
in a pipeline share the original five-second logical deadline. No missed ticks
are replayed. The authenticated owner inventory includes revoked/expired tasks,
but never backfills a result scope for an older execution. The deployment
publication read lock pins installation/manifest/generation/fence while querying
the current authenticated executor. A different deployment is skipped, not
silently migrated or granted new authority.

Before a result checkpoint, the driver restores only one private query identity
and invokes the existing receipt/fetch/vault/outcome path. After checkpoint it
only queries cleanup status. A retained completion must have the exact original
signed effect-start receipt and recompute the stored vault commit digest before
an acknowledgement is resent. This does not fetch plaintext, create a document,
renew expiry or dispatch an effect. An authenticated `Acknowledged` query marks
only a volatile cleanup cache; it is not new success evidence. After restart the
cache is lost and the same durable checkpoint is queried again. Surviving private
handles receive the durable result reference before cleanup, so they can still
recover the original vault result.

Transport/receipt/capacity/result-expiry failures leave the job reserved and allow
later turns to select other jobs. They do not emit a public status, planner input
or consumer event. An unusable authenticated owner remains fatal. Expired results
that were never committed are not resurrected; prepared-but-unsent executions
are not automatically resent or declared no-effect. This is bounded polling of a
finite authenticated inventory, not a scalable indexed queue or a proof of total
transcript privacy. Shared-owner timing, general publication, recovery across a
different deployment and operator handling of permanently unresolved jobs remain
outside the completed boundary.

New tests exercise the production authority tick with real local test execd/vault:
lost dispatch response, checkpoint crash, lost cleanup response, wrong completion
or receipt digest, unavailable executor and a surviving private result handle.
They assert one provider invocation, unchanged consumption, exact cleanup, context
isolation, pacing and fatal poisoned-state handling. Separate tests cover owner
inventory reopen/legacy exclusion and planning progress without an available vault.

### Production new-action driver

The third owner-clock phase now drives new private actions. It requires both a
configured G7 runtime and vault, then selects a task from live authenticated
Ready/Running sessions with current root authority and an active fused plan.
Selection is private round-robin, at most one new-action pipeline per second.
Tasks are deliberately serial: any prior execution without a result checkpoint
or signed no-effect settlement prevents starting the next operation. This is a
conservative throughput restriction, not inference that an Unknown effect failed.

The existing private helpers restore only pinned inputs and the exact registered
recipe, construct/replay durable G4, run G5 and enforce G6. Denial and NeedsApproval
remain private pending states; no fake approval, user prompt publication, legacy
Agent fallback or new authorization is created. Once a trusted caller supplies
the exact valid signed G6 settlement, the same action can resume. This batch does
not deliver the approval envelope to a consumer or implement that caller's UI.

Real owner time is reread between preparation, evaluation and dispatch. Backwards
time stops the turn; expired root, recipe or approval cannot be renewed by retries.
Each helper acquires its own current policy lease rather than nesting locks. The
G7 dispatch lease now additionally checks the live effect fence under the same
publication read lock as send, closing the evaluation-to-dispatch fence-change
window even when installation/manifest/generation remain the same. G7 continues
to check exact content, dependencies, quota and original authorization.

After G7 commit, the historical driver owns reconciliation. The new-action phase
never resends an execution after a prepared-but-unsent crash or a lost dispatch
reply. Tests run local authenticated execd/vault with a test connector and exercise
automatic G4–G7, waiting for an unsettled predecessor, both failure cuts, live fence
change, signed-approval resume, and expiry of a previously signed approval. Local
tests also cover denial, repeated pending approval without duplicate records,
expired/revoked roots and stage-to-stage time checks. These are not native Linux
deployment/hardware acceptance or a complete consumer workflow/privacy proof.

### Private pending-approval recovery

Agent recovery schema 4 adds a bounded private archive keyed by stable G4 action
identity: the original signed approval envelope, signed display authentication
envelope and optional verified settlement. It uses the existing encrypted,
rollback-anchored agent owner. No boot-local approval/pending/ticket handle is
serialized. Schemas 2/3 remain readable but cannot invent lost approval records;
an archive cannot be encoded back to an older schema and silently discarded.

The pending archive commits before a NeedsApproval response can escape. Verified
Approve/Deny receipts commit before consumption or ticket publication. A failed
write or encoding poisons the owner, preventing both live use and later retries
from treating an in-memory mutation as durable. The two-owner ordering is G5
decision first, approval archive second: failure between them permits a fresh
unexposed challenge only when no approval archive was committed. It does not
produce a dispatch capability.

Recovery first checks canonical encoding, signatures, deployment/service and
display/envelope/task linkage, bounded counts and duplicate stable IDs. Once a
separately authenticated live session reconstructs the exact current G4 intent,
G5 and current display-declassification checks run before rebinding. Current
principal, task root revision/content, plan, semantic/display binding and original
expiry must agree. Only fresh boot-local handles are minted. The original
challenge, envelope and expiry remain unchanged. Saved receipts pass the shared
G6 verifier again under the current settlement key and time; refusal remains a
refusal, and an expired/invalid receipt is not exposed as a new pending ceremony.
G7 remains responsible for execution/consumption uniqueness. Recovery itself
does not send effects, refund quota, or authenticate a user.

Tests cover encrypted owner reopen before and after settlement, rollback to the
pre-settlement file, fresh handles with identical signed material, preserved
approval/refusal, current-key revalidation, expired receipt, stale handles,
changed plan/revoked authority, malformed signature/duplicate/wrong-installation
archives and failed pending/settlement commits. The private fixture supplies a
live session separately after asserting that snapshot restore created none.
These are not a full multi-process login/approval UI recovery acceptance test.
Archive storage is bounded and fails closed at capacity; no expiry-based deletion
or automatic reapproval is introduced.

### Approval receiver delivery-binding prerequisite

The approval service's mutable state schema 5 now records the delivery endpoint
role and exact signed display-authentication envelope digest alongside each
paired approval. These are private, encrypted, rollback-anchored records, not a
new public status or model-visible approval feed. Registration validates both
signatures, current deployment and time, complete approval/display/task/principal
pairing, and that the display interval stays within the approval interval.
Changing a correctly signed display nonce still changes its digest and is refused
for the same approval. Standalone UI registration cannot replace that pairing.

Pair insertion is atomic even at the in-memory service boundary: a failed second
insert (including nonce collision or capacity failure) cannot retain the first.
The durable owner still commits the complete change once. Exact retries do not
rewrite state or mint a new decision; existing signed Approve/Deny settlements
remain unchanged. Browser-facing cached registration also passes through this
owner validation, closing the prior payload-digest-only fast path for forged
signatures, substituted displays, stale time and poisoned storage. Ordinary
content-authentication retries similarly recheck signatures/time/role, and the
generic route rejects ApprovalDisplay rather than creating a separate ceremony.

Schema 4 remains readable. Migration derives a role only from the closed approval
purpose and a unique existing, valid signed display pair. Missing material is not
invented; ambiguous/malformed old pairs are rejected, not arbitrarily selected or
silently reset. New writes use schema 5. No installed state has been migrated by
this development work. The archive and validation scans remain bounded, not a
claim of indexed or constant-cost recovery.

Tests cover both service-level snapshots and real encrypted owner reopen with a
fresh UI authority, fresh ephemeral handles, rejected stale handles, no plaintext
in the state file, unchanged file/head on exact retries, valid-but-different
signed displays, forged signatures on cached payloads, wrong roles, expiry,
uncertain commits, old-schema migration, missing/misbound pairs, and preservation
of signed approval and refusal. Enrollment/hardware ceremonies are not claimed
by the UI-registration unit fixtures.

This was the receiver prerequisite in batch 26. Batch 27 adds the transport and
private owner-driver receipt processing described below, not native provisioning.

### Dedicated private approval edge (batch 27)

`KernelApproval` is a new authenticated role (wire tag 8), with only health (0),
exact tool-approval pair registration (20) and settlement query (21). Deployment
trust derives its client identity from Kerneld, not Agentd/Ingressd. Transport
handshakes bind role, keys, service identities, boot and deployment locks. The
client's fixed Linux path is `/run/savana/approvald/kerneld/approvald.sock`.
Enrollment, revocation, ordinary UI authentication, root approvals and release
approvals are not operations on this edge. Kernel registration requires an exact
task/action binding. A tool handle is additionally scoped to its retained role;
knowing a Kernel handle does not allow an Agent query. Schema 5 preserves that
role across restart; schema 4 tool pairs remain Agent-owned.

The private owner action driver now handles NeedsApproval through this client
when installed. It re-registers the exact archived envelope/display, queries a
fresh boot-local handle, and feeds both signed outcomes back through G6. Receipt
signature, task/action, root/content, deployment and expiry checks still apply.
An outer `Approved` label cannot override a signed denial. Pending, unavailable,
late or time-regressing replies grant no ticket and do not renew the challenge.
Approval does not immediately dispatch: a later action turn re-evaluates and
uses G7. No envelope, handle or private status is forwarded to the Agent/model.

Tests cover actual SuiteOne UDS frames for registration/query, cross-role
handshake rejection, encrypted state reopen/role persistence, and the private
owner-driver/G6 path. Native peer observation is a fixture in the socket test;
the kernel receipt tests use a debug-only typed transport adapter and signed
test decisions, not a real human ceremony. Invalid query handles now receive a
valid encrypted query error rather than causing an error-encoding disconnect.

**Still not a deployed consumer approval flow:** batch 28 adds native Linux
bootstrap installation, dedicated socket activation, purpose-separated client
credentials, verified Kerneld peer and directory provisioning. These are opt-in
artifacts, not an installed deployment. The display transfer is still not routed
from the trusted consumer session. A separate same-origin private handoff
receiver is now implemented; see [private approval UI](private-approval-ui-v04.md).
Without configuration the driver safely remains
pending; invalid enabled configuration fails startup. Consumer session recovery
and exclusive publication also remain outstanding. See the
[Linux startup contract](kernel-approval-linux-v04.md). No live Savana service was
changed, and the production hardware-authority gate remains intact.

## Outstanding (not cloud placeholders)

- Consumer input intake and authenticated session recovery using the new private
  input helpers, plus trusted approval delivery/settlement plumbing. Historical
  recovery/cleanup, new-action driving and private approval-material recovery
  are wired, but do not reconstruct a login or deliver an approval to a user.
  Signed recipe admission is implemented, but neither it nor the private draft
  comparison opens a consumer workflow entry. The new driver acts only on a live
  authorized private session, an activated plan and its admitted exact recipe.
- An exclusive publication path covering final output, failures, reconnects and
  private clarification, plus its admission/observation obligations. A public
  window plus at-most-once delivery is not a fixed total transcript.
- General private discovery/loop/residual compilation beyond registered reorder,
  and the proof/coverage obligations for any broader claimed fragment.
- Consumer approval/intake/result/recovery UI and end-to-end Python business
  workflow wiring. Offline operator signing preparation is not that UI.
- Real provider recovery and native Linux service/isolation/hardware-anchor
  acceptance. Batch 28 compiled the Linux Kerneld/Approvald path and passed the
  complete kernel/approval library suites in an isolated aarch64 Linux container.
  This supersedes batch 24's blocked cross-compilation attempt, but it is not a
  deployed systemd, cross-service-UID or hardware-authority acceptance run.

Legacy fused-session planning/final-release guards intentionally remain closed.
No old state, credentials or enrollment were erased. No live service deployment,
network inference, git commit or push was performed.
