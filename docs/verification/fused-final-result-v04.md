# Private terminal-result retention, approval and publication (v0.4)

2026-09-24 update. The native owner now prepares, approves, dispatches and
reconciles a declared terminal tool result. Native executor/vault tests and
Python→Rust→AgentDojo provider conformance have run. This is **not** deployed
consumer acceptance, freshly authenticated reconnect, or an official protected
AgentDojo score. The retention-only work below preceded this update.

## Native publication added

The administrator can sign draft schema 3 with `final_result_source` and
`final_release: {clause, descriptor, turn}`. Compilation produces profile schema
4. The root has one **separate** FinalRelease clause with one exact alternative,
one attempt/count, no no-effect retry and all finite operations as predecessors.
Publication is not a planner-selectable operation. Changing the turn, descriptor,
clause, source or schema cannot reuse the signature or another root clause.

The closed `/savana/final-result-release` codec names a `result:` resource derived
from task, source operation and source descriptor, and an exact
`application-turn:` destination. No result bytes or circular root/profile hash
are used to pre-authorize that resource. The legacy `/savana/final-release`
codec remains `input:`-only; the two profiles/decoders cannot be substituted.

Data/control flow in the native code:

1. Recover the signed terminal source and its original committed execution,
   retained bytes, provenance, result commitment and current root/session/fence.
2. Construct the request **inside Rust** from those bytes and the signed
   descriptor/turn. No Python/model-provided result handle, payload or target is
   accepted by this path.
3. Apply the existing exact display projection/G3 rules, reserve the original
   task/run/principal-owned vault result, and create the signed FinalRelease
   envelope/display pair. It is delivered on the pinned KernelApproval edge.
4. G6 verifies the FinalRelease settlement and exact action approval. A prior
   tool approval, login, denial or mere polling is not a publication grant.
5. Recheck the root/result and current G3 final destination; seal the actual
   request and use the existing G7 reservation, permit, nonce and execd journal.
   G7 independently checks the current candidate and exact request bytes.
6. Authenticate the executor receipt/audit and reconcile original task usage;
   commit the corresponding vault release; durably retain the completion and
   kernel commit before acknowledging executor cleanup.

The host driver separates prepare, approval and dispatch turns. Legacy Agent
authorize/dispatch/status entry points reject the private publication handles.
The workflow driver is scheduled alongside planning, execution and recovery.
Missing native deployment configuration continues to fail closed.

## Recovery and limits

Encrypted, rollback-anchored owner snapshot schema 5 retains the original
candidate commitment, signed approval/display, exact settlement, dispatch core,
completion and kernel commit. No plaintext result, session, boot-local ticket or
new approval challenge is restored from this publication archive. Schema 2–4
snapshots remain readable, but cannot silently contain new publication state.

After a post-dispatch restart, the owner can query/fetch/ack using the **original**
nonce without a login session or new provider send. The cross-journal gap where
G7 persisted but the publication archive did not is recovered from the original
G7 record, never by creating a new dispatch. Uncertainty remains Unknown/reserved;
in particular a crash before sending does not manufacture a signed NoEffect.
This is conservative recovery, not a claim of liveness across every crash point.
Approval and provenance lifetimes do not renew. Consumption is not reset.

Native fixture case 42 reopens the actual encrypted owner twice, including this
cross-journal gap and the committed state, with no sessions or release handles.
It checks the original dispatch and all three consumed clauses. The executor,
policy owner and vault remain live in that fixture: it is not an all-services
restart or hardware rollback acceptance test.

The Python provider receiver is explicitly synthetic, on the isolated native
test socket. It independently compares released bytes with the last actual
AgentDojo provider response, checks the fixed application turn, and rejects
rebound or duplicate publication. It does not supply production authentication
and does not implement a model/official-task oracle.

New evidence: [publication conformance report](../../experiments/AGENTDOJO-PUBLICATION-20260924.zh-CN.md).

## Problem fixed

Previously, the fused owner retained raw results only when a later operation's
argument or a signed model observation needed them. A terminal tool result with
neither consumer had a durable result commitment but no retained value in the
workflow owner. It could not safely become the source of a private release job
after volatile result handles were lost.

## Data and control flow

1. The administrator signs a finite task draft with `schema: 2` and optional
   `final_result_source: N`. The Rust compiler emits profile schema 3. `N` must
   exist and be the last operation of **every** registered template. The model
   cannot select arbitrary result bytes or silently change the terminal source.
   This is source-retention admission only, not a root FinalRelease clause.
2. G7 refuses to start a required-result operation without authenticated result
   scope. The source must use the existing input/recipe and execution gates.
3. The native executor recovery path authenticates the original receipt and
   result, commits it to the vault, settles G7, then checkpoints the owned value
   in the encrypted durable workflow state. The existing `needs_result_value`
   query now includes the declared terminal source. This reuses the real recovery
   path rather than creating a second ingestion API.
4. `DurableG4StateV2::fused_final_result_candidate_v04(task, now)` requires every
   active-plan operation to match its original journal entry, have
   `CompletionCommitted` and a nonempty result checkpoint, and belong to the
   current signed root and the same run. It rechecks the terminal value's intent,
   execution nonce, producer, manifest, run, confined security label and original
   expiry. Unknown, failed, merely started or digest-only terminal results fail.
5. The host-private `prepare_fused_final_result_v04` additionally holds the live
   deployment/fence lease and checks the authenticated session's principal,
   explicit current root, run, manifest, producer and lifetime. Its return value
   has no RPC encoding, public handle or publication authority.

The private candidate commitment binds task, root, profile, source operation,
original dispatch core, result commitment, provenance and exact bytes. Reading
it is non-mutating: no new nonce, dispatch, refund, approval or publication slot
is created. The candidate does not gain a new expiry on recovery.

Example: with `A -> B`, B consuming A's original tool result, a signed terminal
source of B retains B's own response. It cannot substitute A, a planner's prose,
or a caller's new bytes. Reopening the encrypted owner returns the same candidate
digest and preserves both operations' existing consumption. This is not a claim
that B's business result is semantically correct or already safe to publish.

## Compatibility and limits

The new optional field is omitted when absent, preserving old canonical signing
bytes. Old draft/profile schemas cannot opt in by appending the field. Existing
schema-17 result checkpoints and original provenance are reused. Missing required
values, rebound source identifiers and invalid schema changes fail restoration.
The existing per-value **32 KiB encoded CBOR** limit (including overhead),
provenance limit and total 256 KiB result-retention limit remain. The final-result
candidate also checks the legacy 32 KiB raw release payload ceiling; it does not
relax the stricter snapshot cap. Large results require an explicit future design,
not truncation or an unmediated file reference.

No Python result-export method, Agent capability, legacy input-release expansion
or automatic approval was added. The finite compiler still requires the full
signed task/tool skeleton; this change does not enable general discovery.

## Earlier retention-only regression evidence

The Python component regression inventory selects eight additional exact Rust
tests: signed draft/source validation, profile signature mutation, complete
checkpoint requirements, read-only reopen/expiry/revocation, explicit source and
size limits, restoration corruption, failed/unknown effects, and the native
two-step executor/vault/owner path with terminal-source retention. Native tests
use synthetic identities and provider responses, not a live model or real effect.
Verified for this change:

- Python-selected native security regressions: **78/78** passed, including the
  eight new cases. Report scope remains `component_only`, `model_trials: 0`,
  `production_acceptance: false`.
- Python experiment unit/integration tests: **108/108** passed, no skips.
- Offline ARM64 Linux container: policy-core `fused_` tests **89/89** passed;
  kerneld `fused_` tests **88 passed, 1 intentionally ignored**. The ignored
  case is the explicit AgentDojo provider probe, which requires its own runner;
  it is not treated as executed or passed.
- `cargo check --offline --locked --workspace --all-targets` and
  `git diff --check` passed. Existing ownerctl dead-code warnings remain; Linux
  also reports existing execd/connector test-support unused-code warnings.

Reproduction commands (from the repository root):

```sh
PYTHONPATH=experiments python -m savana_bench regressions --timeout 600
PYTHONPATH=experiments SAVANA_COMPONENT_DRIVER="$PWD/target/debug/examples/benchmark_driver" \
  python -m unittest discover -s experiments/tests -q
cargo test --offline --locked -p savana-policy-core -p savana-kerneld \
  --features savana-kerneld/test-support --lib fused_ -- --test-threads=1
```

The Linux run used the already-present `savana-tpm-test:local` image, no network,
read-only source/registry mounts and the existing isolated build volume. These
test sets overlap and must not be added together as independent security cases.
No AWS instance, cloud model, customer data or real business effect was used.

## Remaining product/experiment boundary

Still required: production consumer delivery and fresh authentication before
result reconnect; official AgentDojo task/tool adapters that actually invoke
this owner; signed deployed worker configuration and multi-service acceptance.
The fixed test plan must not be reported as general model planning. The approval
transport is documented in [private-release-approval-v04.md](private-release-approval-v04.md).

`savana_bench.readiness` therefore still refuses full-product experiments. None
of these component tests may be reported as protected utility or attack success.
