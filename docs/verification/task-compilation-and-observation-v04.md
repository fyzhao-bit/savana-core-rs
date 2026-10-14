# v0.4 finite task compilation and dynamic observations

2026-09-24. Source implementation and component verification. **Not a completed
product deployment, final-result publisher, or official protected AgentDojo run.**

## Implemented boundary

Follow-up: [terminal-result retention](fused-final-result-v04.md) adds explicit
draft schema 2 / profile schema 3 source selection without widening old schemas
or granting publication authority.

The native compiler accepts an administrator-authored finite task skeleton. It
does not infer permission from a natural-language request, model response, tool
description, attack label, or benchmark oracle. The authenticated task root and
signed live tool registry must already exist.

```text
administrator: reviewed draft + signed CompilePlanning command
  -> authenticated local root-only management socket
  -> current task root + current registry + native service role
  -> deterministic Rust compiler -> atomic profile/receipt admission

owner clock -> approved delivery slot -> frozen model view -> G3 -> model worker
  -> bound finite template/order proposal -> local compilation
  -> owned inputs + root matching + recipe approval + G4/G5/G6/G7
  -> executor -> provider -> verified result -> private vault/owner checkpoint
  -> next approved slot: signed JSON projection + original result provenance
  -> G3 + leak gate + exact recipient -> model worker
```

Neither compiling a profile nor accepting a model proposal grants an execution
ticket. The old direct Agent route remains closed for fused tasks.

## Task/tool compiler

`FusedTaskDraftV04` in `savana-policy-core/src/v2/fused_task_compiler.rs` has a
closed, versioned JSON schema. Its fields are `schema`, `root`, `observer_scope`,
`not_before`, `expires_at`, `operations`, `templates`, `rounds`,
`delivery_schedule`, `release_model_views`, and `max_replacements`.

Each operation names an ID, root clause ID, descriptor digest, exact tool name,
typed slot bindings, and additional predecessor IDs. The compiler:

- Requires exactly one operation for every root clause; no omitted or repeated
  clause, inferred alternative task, or model-created authority.
- Resolves the descriptor from the active signed registry with the native role
  and current time. It checks the provider tool ID, business operation, argument
  order/names, descriptor lifetime and root descriptor/codec/effect alternative.
- Inherits every root predecessor. Extra dependencies may restrict the task;
  they cannot remove root prerequisites. Cycles and unsupported bindings fail.
- Rejects ambiguous tool-class/action-template mappings instead of selecting a
  different provider. Numeric identifiers must fit the finite planner schema.
- Allows predecessor results only in signed payload roles. The existing lowering
  path further restricts these result bindings to the text `body` field. Result
  text cannot supply destination/resource controls.
- Creates no execution commitments or approvals. Existing input pinning, recipe
  approval, exact action approval where required, and G4–G7 are still mandatory.

Bounds: 256 KiB draft/command, 1–64 operations, at most 32 templates, 16 rounds,
256 delivery slots, 16 bindings and 64 explicit predecessors per operation.
Other existing policy/descriptor limits also apply and can be stricter.

`compile_fused_task_v04` returns an unsigned profile. The privileged
`CompilePlanning` command admits the compiled profile using its verified outer
administrator signature; an independently fabricated profile cannot use that
crate-private admission constructor. Live tools are mandatory for new admission.
Admission is refused once dispatch journal entries exist for the task.

The command receipt is atomically retained with admission. An exact replay
returns the original historical receipt, even after expiry, but does not renew
the root, tools, profile or execution authority. Reusing the request ID with
different bytes fails. Clients check command digest, request ID, task and nonzero
compiled profile digest. Offline preparation cannot validate a live deployment.

### Python operator interface

The existing `savana.managed_admin` interface now recognizes `planning_draft` in
addition to `command` and `planning_profile`. No signing key is loaded by it.
This source change requires rebuilding/installing the native Python extension;
an already installed older wheel does not acquire the new discriminator.
A new macOS ARM64 debug wheel was built and tested in an isolated temporary
directory. The existing application environment was not upgraded. This does not
constitute a Linux wheel build or installation on the server.

```python
import json
from savana.managed_admin import prepare_artifact, submit_signed

async def admit_reviewed_task(command_dict, sign_reviewed_digest):
    # command_dict includes installation/store/request/time and this operation:
    # {"kind": "compile_planning", "task": task_bytes_32,
    #  "draft": administrator_reviewed_finite_draft}
    # All digests are JSON arrays of 32 integers, not hex strings.
    prepared = prepare_artifact("command", json.dumps(command_dict).encode())
    # This callback is the separately provisioned operator signing authority,
    # not a model callback or a signing key supplied by the chat/Agent.
    signature = sign_reviewed_digest(prepared.signing_digest())
    return await submit_signed(prepared.canonical_bytes(), signature)
```

Review the canonical artifact before signing. Retain the exact command and
signature to resolve an uncertain result; do not generate a fresh request ID to
retry. The receipt is private operator information, not model feedback.

## Dynamic observations

`Round.observations` is optional and omitted when empty, preserving old signed
static-profile serialization. Dynamic profiles require profile schema 2, policy
schema 3, `release_model_views: true`, and a signed nonempty delivery schedule.
The model wire shape is unchanged; only its `public_view` bytes are constructed
from the admitted projection at the round's first due delivery.

For example, a round may explicitly permit:

```json
{"source": 1, "path": ["result", "structuredContent", "savana_status"]}
```

If operation 1 has a committed result, the host reads the original retained
bytes and projects only that path. The public view is UTF-8 JSON shaped as:

```json
{"context":"approved context","observations":[{"source":1,"path":["result","structuredContent","savana_status"],"status":"available","value":"succeeded"}]}
```

The bytes containing other result fields are not included in this view. The
source operation ID, path, presence/status and selected value **are disclosure**:
they must be covered by the signed profile and the current G3 recipient rule.
This is not permission to expose arbitrary original tool output or an unapproved
success/failure side channel. If no result exists at freeze time, or the selected
path is absent, the projection contains `status: "unavailable"` without a value.
That frozen absence does not assert failure, refund consumption or enable retry.

Supported paths select exact object keys or canonical decimal array indices.
There are no wildcards, executable expressions, model-selected selectors or
implicit recursive extraction. Up to 4 projections per round, 16 path components
per projection, 128 bytes per component, 16 KiB total source bytes, and 4 KiB
rendered view are allowed. Duplicate JSON keys, malformed/trailing JSON,
nonfinite numbers and oversized structures are rejected, not coerced to absence.
The structural parser limits containers to 4096 entries and uses serde's depth
bound. Selecting a subtree authorizes that entire subtree, not just its leaves.

The first scheduled claim freezes the source bytes and exact projection with
the durable reservation. Later results cannot backfill the same round; later
slots do not recompute an earlier frozen view. Encrypted-owner validation checks
the retained sources against authenticated execution results and checks their
original validity at freeze time. Reopen does not reset delivery consumption.

Before handoff, the owner joins the original tool-result provenance with the
initial input provenance, caps expiry by every result parent, and performs the
existing whole-envelope G3 decision, exact-reader check and leak scan. Signed
selection is not endorsement: tool text remains untrusted. Failed G3 or uncertain
delivery does not refund a reserved slot, invent a model result or trigger an
unscheduled retry. Original private source bytes remain in the encrypted owner;
the added freeze is a retained copy, not an additional public export.

## Evidence and limits

Observed local checks for this change:

- Policy `fused_`: 82 passed, including 5 compiler/admission tests.
- Continuation planning: 19 passed, including 3 projection/freeze tests.
- Native kerneld `fused_` with test support: 87 passed, 1 explicitly ignored
  provider probe. The two new native observation tests passed.
- Rust management client: 6 passed, including compiled-receipt binding.
- Python experiment regression suite: 108 passed, none skipped.
- Newly built native Python extension: 8 management-wrapper tests passed,
  including real Rust draft/command canonicalization, purpose-separated digests,
  signed observation selectors and rejection of unknown/duplicate fields.
- Offline ARM64 Linux compiler/admission tests: 5 passed.
- Offline ARM64 Linux native dynamic-observation tests: 2 passed. The positive
  result/G3/reopen chain and negative no-G3/no-model-call chain both passed.
- Workspace all-target offline compilation and `git diff --check` passed.
- Python-selected exact Rust regressions: 66/66 passed, no ignored tests in that
  selection. The first run was 65/66 because Homebrew Node could not load its
  `libsimdjson` dependency; the failing test and full selection passed using the
  available bundled Node. No security assertion was removed to obtain a pass.

These selections overlap; do not add the counts together as unique coverage.
Full-product preflight still exits 2 with its six reviewed blockers. The changed
source tree has not been converted into a signed deployment/release inventory.

The native positive test executes a synthetic provider through G4–G7 and IPC,
checkpoints its real result, releases a selected field through G3 to a synthetic
model worker, accepts its bound proposal, reopens encrypted state and executes
the second step. The negative test omits the necessary G3 model rule: zero model
requests occur and the consumed slot is not retried. These are component tests,
not live DeepSeek calls or official AgentDojo scores.

The paired-prefix unit case checks equal earlier views and equal later views
for different unselected private fields. It is not a proof of total publication,
timing noninterference, arbitrary state migration, or all application paths.

Still incomplete: general natural-language task/root authoring; arbitrary
AgentDojo tool-schema/semantic adapters; final tool-result publication with its
own authority, exact approval and authenticated reconnect; a protected official
AgentDojo pipeline; installation and real server/model trials. The legacy final
release path only authorizes the original input and was **not** relaxed to expose
tool results. No cloud resource, paid model call, credential upload, deployment
reset, commit or push was performed by this implementation batch.
