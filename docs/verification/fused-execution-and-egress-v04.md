# Fused execution and model egress: implemented boundary

2026-09-20. Private Rust integration, not an enabled product or a deployment
certificate. The ordinary chat path, cloud transport and consumer UI are not
switched on. No real external business effect is produced by these tests.

Follow-up: [signed scheduling and policy lifecycle](fused-scheduling-v04.md)
adds schema 13, a scheduled exchange helper, and a tested publication-lock lease.
The [host follow-up](fused-host-v04.md) connects the lease/timer to the owner, but
production model transports remain disabled. The manual helper
described below now rejects profiles that opt into signed slots.

## Exact execution admission

`FusedPlanningProfileV04.execution_bindings` is optional, signed, sorted and
complete over the registered operation IDs. Empty retains protocol-only behavior
and denies business dispatch. Each entry commits verified local G4 material plus
the exact task action: descriptor, arguments and original value identities,
provenance, tokens, destination/display projections, executor, retry policy,
authorization/clause/alternative, magnitude, payload and candidate domain.

`fused_execution_commitment_v04` abstracts only the plan/step IDs and changing
task pre-state fields. G7 independently rechecks current task authorization and
pre-state. Real local argument identities remain fixed: this does NOT promise
that newly minted slots/values after restart will match old commitments. The
trusted host must preserve bindings or refuse. The signed mapping is an explicit
local admission decision, not evidence that a model's semantic extraction is true.
It narrows existing root authority; it cannot mint a task authorization.

`TaskDispatchAuthorizationV2::with_fused_operation` carries an untrusted operation
selector and activation revision, not a grant. In the existing G7 prospective
snapshot the owner checks the signature-approved commitment, registered class,
template and argument names, active order, current root/time, unique original
intent/nonce, and completed dependencies. It advances the started prefix in the
same commit as the G7 journal, task usage, quota and any enrolled resource ledger.
If a later check or commit fails, none of these changes escapes.

Schema 12 retains execution links and refuses downgrade/erasure. Restore checks
the started sequence against actual task/journal/intent associations in both
directions. No model status can advance it. Stable resource deduplication applies
when the existing signed continuation/resource policy is enrolled; task usage
and operation once-only binding apply independently. No new accounting database.

## Restricted replacement and old outcomes

For independent B/C, after A is reserved, `[A,B,C] -> [A,C,B]` can activate.
After A and B are reserved, that switch fails despite both plans being valid in
isolation. "Started" conservatively begins at durable reservation, before external
I/O. Replacement never reconstructs an old reservation from current data.

An original G7 replay keeps its original activation revision, intent and nonce.
New work checks the current activation revision and exact next operation. An old
executor response settles the original G7 entry even after replacement; it does
not update the new plan by step position. Only `CompletionCommitted` satisfies a
dependency. `FailedNoEffect`/`Indeterminate` cannot remint the operation or reset
stable resource consumption. Existing task-ledger refund policy is not replaced
or broadened by this integration. No general program-equivalence or private-loop
replacement theorem is claimed.

## Fixed-view model exchange

`release_model_views` defaults to false. Setting it in the signed private profile
explicitly approves the profile's constant views, public metadata, allowed advice
references and recipient schedule. This is operator approval, not a newly built
ordinary-user consent UI. UTF-8 views only are admitted for this initial profile.
A separate signed G3 rule is still mandatory.

G3 has a new closed transition/purpose (tag 6): `BuildFusedModelEnvelope` /
`FusedModelCall`. Unlike legacy planner declassification, it names one exact model
identity and requires a reader allowlist. It enforces the model PII/blocklist duty
even when a rule requests a weaker floor; its implementation identity binds the
scanner pattern set. Existing tags 1–5 are unchanged. Existing deployment rules
do not gain permission for tag 6 automatically.

`exchange_fused_model_v04` accepts no caller-provided request bytes. It:

1. Checks explicit release admission, current root, recipient and owner revision.
2. Durably reserves a bounded delivery of the original frozen view.
3. Checks decoded public-view text as well as the complete canonical wire value,
   to prevent JSON integer-array encoding from bypassing ordinary PII detection.
4. Runs real G3 declassification and exact-reader judgment, binding the view,
   recipient and signed profile in private provenance evidence.
5. Rechecks time/current root/recipient immediately before one transport call.
6. Accepts only bounded, canonical, job/view-bound advice/proposals before the
   deadline; settles results through the durable once-only owner path.

Failures and raw replies stay private. There is no implicit retry, changed job
ID, fallback model or fake success. An uncertain reservation returns before any
send; a lost response consumes an attempt. Explicit retransmissions retain exact
original bytes and original public identity, including after encrypted reopen.

`FusedModelTransportV04` is a trusted adapter contract: authenticate the pinned
endpoint, enforce deadline/allocation limits while reading, and prohibit hidden
retries, redirects and extra telemetry. This batch supplies only a disabled cloud
placeholder and deterministic test workers. The host must serialize active-rule
changes across the exchange; passing an old signed rule snapshot is not a current
deployment proof. The helper is not an automatically running scheduler.

## Evidence and limitations

Tests exercise the actual encrypted G4/G7 owner and separate rollback test anchor:
atomic operation/accounting commits, exact replay, changed material, stale
activation, prefix-preserving and prefix-breaking replacement, old late outcomes,
dependencies, schema/link corruption, precommit failure and both uncertain-anchor
cuts. Model tests exercise real signed G3 rules, legacy/wrong-reader rejection,
encoded PII, bounded/late/bad replies, fixed fallback, exact retransmission and
no-send on uncertain reservation or revocation. Transport fixtures do not call a
cloud service or simulate a successful business provider.

Local regression: policy library 351 passed; continuation core 48 passed; kernel
library 312 passed with serial test execution. The initial parallel kernel run
passed 310 and failed two existing startup tests (global fixture-lock timeout,
then lock poisoning); the serial rerun passed without code changes to those
checks. Rust client and Python-extension compilation passed. Policy Clippy retains
three existing policy warnings and three dependency warnings, with none added by
these modules. Repository source fingerprints explicitly updated and all 246
checked. These are Mac-hosted tests with a test rollback anchor, not native Linux
or hardware anti-rollback acceptance and not a signed deployment release.

Still required: host/ingress/compiler/session wiring, exclusive process-level
egress and deployment-policy lifecycle guards, public scheduler, generic private
discovery/loop and residual compiler, final feedback publication, consumer SDK/UI,
provider recovery, and native Linux isolation/hardware-anchor acceptance. Fixed
approved views plus a pattern scanner are NOT a proof of semantic redaction,
whole-service noninterference, cross-task coalition safety, or Strict Inference.
