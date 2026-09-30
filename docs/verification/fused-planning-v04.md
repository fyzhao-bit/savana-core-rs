# Fused planning: implemented boundary and acceptance

2026-09-20. This is an additive, opt-in **protocol/compiler staging backend**,
not completion or activation of the v0.4 product. No cloud was contacted and no
live store was migrated. The normal unenrolled V2 path is unchanged.

Follow-up: optional signed delivery slots now use schema 13 and a durable cursor;
scheduled profiles reject manual reserve/freeze bypasses. The daemon timer is
now connected to the same owner; production cloud transports are disabled.
See [scheduling limits](fused-scheduling-v04.md) and [host integration](fused-host-v04.md).

## Code and interfaces

- `savana-continuation-core::planning`: closed model views, advice, proposals,
  registry validation, deterministic local compilation, restricted replacement.
- `FusedPlanningProfileV04` / `VerifiedFusedPlanningProfileV04`: canonical signed
  private configuration, with independently selected issuer and current root,
  installation/task/validity checks. This is not a disclosure authorization.
- `DurableG4StateV2::install_fused_planning_v04`: install once before any task
  effect, allocate public random jobs once, no policy replacement/reset.
- `update_fused_planning_v04`: optimistic owner-revision check followed by
  freeze, reserve delivery, accept advice/plan or local candidate activation.
  Writes use the existing encrypted state, atomic replacement, independent anchor
  and uncertain-commit poisoning. The result contains no view until commit succeeds.
- `fused_planning_status_v04`: current-authority-checked private recovery read;
  does not create jobs, publish, retry or advance state.
- `compiled_fused_plan_v04`: read a checked candidate, not an execution grant.
- `lower_fused_plan_v04`: bind stable local slot keys to fresh kernel-envelope
  slots, recheck policy commitment, time, active action/tool pairs, action
  allowlist, step/dependency/argument/encoded-byte bounds, emit `PlannerPlanV2`.
- Existing Linux operator `managed_admin.submit_signed` accepts the new signed
  `enroll_planning` operation. Nested profile signatures and receipt binding are
  checked in Rust. No Agent API, signing key or public HTTP endpoint was added.

Enrollment **intentionally blocks legacy planner/session authorization and final
release for that task** until production fusion wiring exists. Unbound G7 tool
dispatch is also blocked. The subsequent execution-binding batch permits only
explicitly signed, active-operation-bound private G7 preparation; see
[execution and egress integration](fused-execution-and-egress-v04.md).
Do not enroll a real task expecting an executable fused workflow yet. Already
prepared legacy planner tickets cannot be committed after enrollment. The signed
management endpoint remains opt-in and uninstalled on this machine.

## Exact supported semantics

The initial publisher is a closed constant-view protocol, not arbitrary semantic
redaction. Its profile is private and contains the approved byte view, public
time windows, recipients, model profile and allowed numeric references. The host
must establish those bytes/metadata are authorized before any real send. Policy
signing alone does not establish that claim.

Model-facing `ModelView` contains schema, fresh public job identity, role, model
profile, public deadline/mode, approved view, template/question lists and bounded
advice references. It excludes private root/task/store hashes, slot bindings,
resource IDs and live budget. Its digest commits only public view material.
Advice allows no free-text body, executable code, destination, arbitrary tool or
permission. Wrong role, sender, view, job, reference, encoding or bounds fail.

Advisor jobs are optional. Planner envelopes freeze at a public cut, not on
private success/failure. Missing advice uses an admitted empty-suggestions
fallback. Late new advice is rejected. Exact accepted duplicates are no-ops;
different second results are rejected, including after restart. Accepted planner
results use the same once-only rule. Send attempts are durably charged before
returning the original bytes for release checking. A lost reply can consume an
attempt, never replenish it. Each request rechecks recipient, window, task
authority and local monotonic floor. No implicit transport retry exists.

Two distinct proposal variants are supported: selection of a registered template,
or a complete dependency-valid operation ordering. These use the new closed JSON
protocol. `StructuralOrderV04` is **not wire-compatible** with the old anonymous-ID
CBOR planner endpoint; compatibility currently means local lowering into V2 plans,
not automatic acceptance of an old cloud reply on the new protocol.

Compilation preserves the full root-registered operation set and its local
bindings; templates currently vary order, not business operation membership.
Replacement must preserve the exact started prefix and execution IDs, retain all
dependencies and obey the monotonic revision/replacement limit. A legal example
is A,B,C -> A,C,B after A starts, when B/C depend only on A and the host has
reviewed those dependencies. After B also starts that same switch is refused.
This is not a general equivalence theorem for effectful operations: completeness
of the trusted dependency/operation specification remains a premise.

The pure transition tests exercise that useful replacement and counterexample.
The real durable owner now records the started prefix atomically with G7, using
the original nonce and intent. Activation after G7 work is allowed only when the
exact prefix is preserved. Old outcomes still settle their original journal
entry; dependencies require known success, not merely reservation. It does not
guess started state from model output, reset a ledger, or waive a gate. The
ordinary chat controller has not been switched to this private interface.

## Storage/recovery

Protocol-only enrollment upgrades owner payload schema to 11; exact signed
execution bindings require schema 12. Old empty planning
tables serialize exactly as before; old schemas cannot carry a nonempty table.
The table lives in the existing continuation payload, not a parallel authority.
Reopen revalidates policy/parent, job uniqueness, bounds, view reconstruction,
advice/proposal bindings and local plan invariants. Old authenticated snapshots
remain subject to the independent rollback anchor. No reset or downgrade API.

## Tests and evidence

- 14 new core tests: optional review, once-only advice, replay/bounds, recipient
  and time checks, canonical hostile-input rejection, no implicit private fields,
  compiler modes, legal replacement, cross-version prefix rejection and restore.
- 12 new policy tests: V2 lowering plus real encrypted-owner signature binding,
  retry/reopen, atomic admin enrollment, clock/revocation/amendment, precommit and
  both uncertain-anchor cuts, schema rollback and legacy G7 fail-closed behavior.
- A kernel regression rejects both fresh legacy planning and a preexisting
  planner ticket after fused enrollment.
- Offline example: `cargo run -p savana-continuation-core --example fused_planning
  --offline`. Its worker is a deterministic test fixture, not an LLM. It issues
  no network request, business effect, approval or execution ticket.

Local policy regression reached 335 passing tests; continuation tests reached
48 passing tests (34 existing + 14 new). Kernel/client/Python-extension compilation
passed. The full kernel suite passed 312 tests, including the new enrollment
regression, after approved permission to create temporary local Unix sockets;
the first restricted-sandbox run failed socket tests (267 passed / 45 failed).
These are macOS-hosted checks and test anchors, not native Linux deployment or
hardware anti-rollback evidence. All 245 repository source fingerprints checked;
updating those hashes does not sign or activate a release.

## Still required before product enablement

1. Consumer-authenticated ingress/approval and exclusive service-level model
   egress covering catalogs, errors, reconnect and all calls. The private helper
   now checks explicit signed fixed-view approval plus the new exact-reader G3
   rule, but this does not mediate every existing product output.
2. Public scheduler and production bounded worker adapter, with active-rule
   lifecycle serialization; recipient/coalition history across tasks as required.
3. Trusted host construction/approval of exact execution commitments, local
   compiler/session wiring, and provider integration. Atomic G7 identity binding,
   retained old responses and restricted replacement are now implemented/tested
   in the real durable owner; full residual contracts are not.
4. Private resource discovery/loop compiler, reviewed predicates, trusted evidence
   and program semantics; general residual contracts and BC/K6 progress evidence.
5. Ordinary-user approval/source UI, host orchestration and native Linux service,
   isolation, provider/recovery and hardware-anchor acceptance.

Cloud/model selection remain disabled placeholders. Do not report this protocol
backend as a deployed, fully mediated or Strict Inference-certified product.
