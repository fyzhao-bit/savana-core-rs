# Savana V2 client SDK

This document describes the implemented Rust client and asynchronous Python
facade. It is an application API over existing V2 browser workflows, not a new
daemon protocol, a kernel bypass, or a direct browser wire client.

## Fixed topology and trust boundary

The SDK sends requests to exactly three application-facing services:

| Service | Fixed loopback endpoint | Operations owned by the service |
| --- | --- | --- |
| Agent | `http://localhost:8768` | authenticated session actions, masked views, planning, execution, release, and connector workflows |
| Ingress | `http://localhost:8767` | bounded text/file ingestion and commit |
| Approval | `http://localhost:8766` | WebAuthn and approval ceremonies |

JARVIS supplies the one-time agent bootstrap through the trusted control plane
out of band. It is not a fourth application service, and the SDK has no method
that mints or fetches a bootstrap. The Python facade fixes the three endpoints;
applications cannot redirect an individual operation to another host, port,
route, origin, or service role.

The Rust layer owns fixed-HTTP framing, canonical CBOR, request nonces,
capability kinds, session binding, state transitions, deadlines, cancellation,
and response validation. Python does not construct protocol requests, decode
wire responses, sign approval settlements, or select kernel operations.

## Bootstrap and WebAuthn

`Identity.load(path)` reads the non-secret enrollment identity used to select
an existing public credential. The identity file contains no signing key.
`Client.session(identity, bootstrap, webauthn, approval)` consumes a canonical
base64url one-time bootstrap token supplied by JARVIS and completes the
existing Approval/Agent WebAuthn flow. A bootstrap cannot be reused. The
session stores `approval` as the mandatory human decision callback for every
later ingress display; ingestion never supplies a default decision or
auto-approves.

The Python `webauthn` object is called synchronously by the Rust worker with
these exact methods:

```python
assert_credential(options_json: bytes) -> dict[str, bytes]
create_credential(options_json: bytes) -> dict[str, bytes]
```

`assert_credential` must return the byte fields `credential_id`,
`authenticator_data`, `client_data_json`, `signature`, and `user_handle`.
`create_credential`, used by `Client.enroll`, must return `credential_id`,
`client_data_json`, and `attestation_object`. Callback exceptions propagate to
the awaiting application; the SDK does not retry a failed callback.

Enrollment is available as:

```python
identity = await Client().enroll(
    enrollment_token,
    code,
    webauthn,
    identity_path,
)
```

The enrollment token and code come from the existing trusted enrollment flow;
the SDK does not create them.

## Public Python surface

The intent-bound branch product surface has twenty-one public types:

| Category | Public types |
| --- | --- |
| Connection and lifetime | `Identity`, `Client`, `Session` |
| Values | `Handle`, `MaskedView`, `Plan`, `PlanStep`, `ApprovalRequest`, `ExecutionResult`, `ConnectorDescriptor` |
| Task data and observations | `TaskAuthorizationContext`, `TaskAuthorizationDraft`, `TaskAuthorizationReceipt` |
| Choices | `IntentPrivacy`, `ContentKind` |
| Loop control | `RunLimits`, `AgentEvent` |
| Errors | `SavanaError`, `AuthError`, `ApprovalDenied`, `PolicyRefused` |

There are twenty business methods:

| # | Method | Result and implemented meaning |
| ---: | --- | --- |
| 1 | `Identity.load(path)` | Load a public enrollment identity from its protected local file. |
| 2 | `Client.session(identity, bootstrap, webauthn, approval)` | Asynchronously consume the out-of-band bootstrap, bind the default ingress decision callback, and return an authenticated `Session`. |
| 3 | `Client.enroll(enrollment_token, code, webauthn, identity_path)` | Asynchronously complete WebAuthn enrollment and persist an `Identity`. |
| 4 | `Session.ingest_text(text, content_kind)` | Commit bounded UTF-8 input; returns `None`. |
| 5 | `Session.ingest_file(path, content_kind)` | Stream and commit a bounded file; returns `None`. |
| 6 | `Session.read_view(handle)` | Return the next kernel-approved `MaskedView` page for the exact initial document or one of its opaque continuation handles. |
| 7 | `Session.run_planner(intent_privacy)` | Plan over the current committed session state and return a `Plan`. |
| 8 | `Session.execute(plan, approval)` | Evaluate and execute every opaque step, returning an `ExecutionResult`. |
| 9 | `Session.run_agent(intent_privacy, limits, approval, events)` | Run the bounded plan/execute/replan loop. |
| 10 | `Session.release(document, approval)` | Explicitly approve, dispatch, and refresh final release. |
| 11 | `Session.register_connector(descriptor, approval)` | Approve and register a validated connector artifact, returning a connector `Handle`. |
| 12 | `Session.remove_connector(connector)` | Remove the connector ID bound to the supplied session handle. |
| 13 | `Session.list_connectors()` | Return session-bound handles for the authoritative connector snapshot. |
| 14 | `Session.revoke(document)` | Revoke the supplied document handle. |
| 15 | `Session.close()` | Close the existing agent session; repeated facade closes return `None`. |
| 16 | `Session.establish_task_authorization(draft)` | Submit exact structured data on finalized authenticated ingress; returns a kernel receipt observation. |
| 17 | `Session.approve_task_authorization(draft, approval)` | Prepare, authenticate and approve an exact task contract under purpose `task_authorization`, then commit its settlement; returns a receipt observation. |
| 18 | `Session.revoke_task_authorization(draft)` | Revoke the exact current task draft on authenticated ingress; returns its authorization digest as 32 bytes. |
| 19 | `Session.recover_task_authorization(request_digest, approval)` | Fresh authentication to recover an existing receipt or independently approve a pending draft; no new root identity or budget reset. |
| 20 | `Session.task_authorization_context()` | Authenticated kernel task/source metadata, current signed profiles and pending request IDs; creates no authority. Opens fresh authenticated follow-up ingress if none exists. |

Five supporting value operations are deliberately inventoried separately:

| Supporting operation | Meaning |
| --- | --- |
| `ConnectorDescriptor.load(path)` | Read, bound, parse, and validate a canonical connector deployment artifact in Rust. |
| `RunLimits.cancel()` | Set the shared cancellation flag so the loop starts no new service request. |
| `TaskAuthorizationDraft.from_canonical_bytes(bytes)` | Validate bounded canonical draft schema 1 as untrusted data; does not sign or establish authority. |
| `TaskAuthorizationContext.tools_json()` | Nonsecret tool names/digests and the exact control field types required by their reviewed profiles. |
| `TaskAuthorizationContext.draft(id, clauses_json)` | Rust validates closed JSON clauses and fills kernel-owned identities, source, profile and revision into an unprivileged draft; never signs it. |

They are not `Identity`, `Client`, or `Session` business workflows and do not
increase the count of twenty. Constructors, properties such as
`Session.initial_document`, enum members, and async context-manager methods are
also not counted as business methods.

### Building a task draft from kernel context

After committing input, call `context = await session.task_authorization_context()`.
`json.loads(context.tools_json())` lists the currently active reviewed tool
profiles and required control fields (role 1 resource, 2 destination, 5 parameter;
type 1 text, 2 unsigned integer, 3 boolean). The application must let the user
select exact whole alternatives; it must not interpret a list as permission to
cross-pair resources and destinations. Missing profiles remain unavailable.

`context.draft(authorization_id, clauses_json)` takes a 32-byte ID and UTF-8 JSON
bytes. If `context.authorization_identity` is present, use its ID; its next
revision is fixed by Rust. Otherwise an application may generate a fresh random
ID for this first proposal. The clauses JSON is a list of closed objects:

```json
[
  {
    "clause_id": 1,
    "alternatives": [
      {
        "descriptor_digest": "<64 lowercase hex characters from tools_json>",
        "controls": [["resource", "<exact resource>"], ["destination", "<exact destination>"]]
      }
    ],
    "maximum_single_magnitude": 1,
    "total_magnitude_budget": 1,
    "maximum_attempts": 1,
    "predecessor_clause_ids": [],
    "retry_after_proven_no_effect": false
  }
]
```

Replace the explanatory placeholders and include **every** control field required
by the selected profile. Payload and magnitude fields are excluded from controls;
later concrete requests still pass the separate content gates and budget checks.
Rust rejects unknown/duplicate fields, unsupported values, unknown descriptors,
profile mismatches and invalid clause graphs. It supplies the authenticated
principal/task/installation/manifest/source and revision; Python never supplies
trusted evidence or signing keys. Building a draft creates no authorization:
`await session.approve_task_authorization(draft, approval)` runs separate consent.

The read-only `context.pending_requests` property lists still-applicable issuance
request digests, including after fresh authentication with no old input handle.
It never returns old contract control values. Recovery does not make that old
source a newly finalized input: new creation/amendment still requires the exact
current finalized session. Re-reading context never installs pending drafts.

Task receipt properties `request_digest` and `authorization_digest` are 32-byte
observations, not transferable execution authority. Rust pins the issuance request
identity and refuses a mismatching receipt, wrong approval purpose, unknown schema
or noncanonical draft. The fixed Ingress routes are `/v2/task/establish`,
`/v2/task/approval/prepare`, `/v2/task/approval/commit`, and `/v2/task/revoke`.
The latter routes require the same authenticated ingress tab; an Agent session
without finalized ingress cannot call them. Transport uncertainty closes the SDK
session without blindly resubmitting a grant under a new nonce. Task approval is
not a way to expand a single action's consent.

Current branch limitation: these are implemented transport/ceremony workflows,
not a finished contract editor or fresh-session recovery UI. Final-release and
deployment integration remain incomplete. Ordinary `ingest_text` does not infer
a task contract, and no automatic natural-language authority compiler is claimed.

## Opaque values and truthful projections

Every capability-bearing Python value is a `Handle`. Applications cannot
construct one from bytes, extract CBOR/base64/raw bytes, or retag it. Rust
records the expected capability kind and session binding, so a wrong-kind or
cross-session use fails closed. `Handle.kind` and redacted `repr` output are
diagnostic projections, not capability material.

`PlanStep` contains only its opaque step `Handle`. It has no `kind`, `reads`,
or `effect` projection because the Agent response does not provide those
fields. The SDK never synthesizes them. `Plan.steps` preserves this opacity.

`MaskedView` exposes only the existing masked-text, structured, document-page,
or content-state projections plus an optional opaque `continuation` `Handle`.
The cursor bytes are never exposed. Agentd accepts views only for the session's
exact initial document, so ordinary output-document handles are rejected
locally before transport. Pagination keeps the same one-argument method:

```python
page = await session.read_view(session.initial_document)
while page.continuation is not None:
    page = await session.read_view(page.continuation)
```

`ApprovalRequest` exposes exactly `display` and `purpose`; it has no
`recipients` field. The display is the protocol-produced human text, while its
`repr` remains redacted.

## Ingestion, planning, execution, and release

`ingest_text` and `ingest_file` drive the existing Ingress
begin/append/finalize/approval/commit sequence. The committed response contains
public input state, not a new document reference, so both methods return
successful completion (`None` in Python). They never fabricate a `Handle`.
After Approvald returns the truthful ingress display, the session's mandatory
`approval` callback receives `ApprovalRequest(display=..., purpose="ingress")`
before any decision ceremony begins. Its exact `bool` selects Approve or Deny;
a denial is signed, completes the second `FinalizeRejected`, and raises
`ApprovalDenied` without committing input. A callback exception fails closed
without retry or an `ApprovalDecisionBegin` request.

`run_planner` accepts only `IntentPrivacy.PRIVATE` or
`IntentPrivacy.THIRD_PARTY`. It has no `goal` or `inputs` parameters because
the browser action carries neither field. Commit the goal with `ingest_text`
and commit every input file with `ingest_file` before calling `run_planner` or
`run_agent`. Privacy selection never silently falls back to the other mode.

`execute` performs propose, evaluate, optional approval, authorize, dispatch,
and one terminal refresh for each opaque plan step. Its approval callback has
the exact synchronous signature:

```python
approval(request: ApprovalRequest) -> bool
```

The callback decides only yes or no and must return exactly `bool`.
Approvald—not the callback or SDK—signs the settlement. A denied approval never
dispatches the operation.

Final release is never inferred from an opaque plan step or execution output.
Call `release(document, approval)` explicitly for the selected document; that
method folds the existing prepare, approval, dispatch, and refresh workflow.

## Connector lifecycle

A connector input is a canonical unsigned deployment artifact, not an editable
name/transport/effect record. `ConnectorDescriptor.load(path)` reads a bounded
file and Rust validates its canonical representation before any service
request. The SDK owns no deployment or registry signing key and exposes no raw
descriptor bytes.

`register_connector` then runs the existing approval and kernel-authorization
workflow. Those authorities produce the signed registry delta after descriptor
validation. `remove_connector` and `list_connectors` use the existing Agent
actions; returned connector handles bind the connector ID to the current
session.

## Bounded autonomous loop

`RunLimits(max_steps, max_replans, deadline_seconds)` requires finite positive
values. The `events` callback is invoked synchronously with one redacted
`AgentEvent` argument; its return value is ignored. Events can report planning,
step start/completion, approval requirement, replanning, refusal, and
completion, but never invent an effect for an opaque step.

The loop follows these terminal rules:

| Execution outcome | Loop behavior |
| --- | --- |
| `succeeded` | Continue within the step/deadline limits. |
| exact `failed_no_effect` | Replan only if the positive replan budget remains. |
| `effect_succeeded_output_quarantined` | Return the terminal result without retry or replan. |
| indeterminate effect | Raise `SavanaError` with code `effect_indeterminate`, close the Rust session state, and never retry. |
| policy refusal or approval denial | Emit refusal where applicable and stop; never ask for a policy-avoiding plan. |

Each proposed step is evaluated independently. Prior approval does not
authorize a later step. `RunLimits.cancel()` prevents new work but cannot undo
an external effect that already completed.

## Async Python example

The example receives `bootstrap_token` from a trusted JARVIS control
integration; it does not obtain the token from a fourth HTTP service. The
`webauthn` object implements the exact callback contract above. `approve` is
passed to `Client.session` for ingress and explicitly to later execution,
release, or connector workflows. It and `on_event` are ordinary synchronous
Python callables with signatures checked by the binding.

```python
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Protocol

from savana import (
    AgentEvent,
    ApprovalRequest,
    Client,
    ContentKind,
    ExecutionResult,
    Identity,
    IntentPrivacy,
    RunLimits,
)


class WebAuthnCallbacks(Protocol):
    def assert_credential(self, options_json: bytes) -> dict[str, bytes]: ...

    def create_credential(self, options_json: bytes) -> dict[str, bytes]: ...


async def run_task(
    *,
    bootstrap_token: str,
    webauthn: WebAuthnCallbacks,
    approve: Callable[[ApprovalRequest], bool],
    on_event: Callable[[AgentEvent], None],
    input_paths: Sequence[Path] = (),
) -> ExecutionResult:
    identity = Identity.load(Path("/var/lib/jarvis/savana-identity.json"))
    client = Client()
    session = await client.session(identity, bootstrap_token, webauthn, approve)

    async with session:
        # The planner has no goal/inputs arguments. Commit them first.
        await session.ingest_text(
            "Summarize the supplied reports and prepare the requested actions.",
            ContentKind.CHAT_TEXT,
        )
        for path in input_paths:
            await session.ingest_file(path, ContentKind.PARSED_DOCUMENT)

        limits = RunLimits(24, 4, 120.0)
        return await session.run_agent(
            IntentPrivacy.PRIVATE,
            limits,
            approve,
            on_event,
        )
```

`run_task` deliberately does not release an output automatically. If the
application chooses an output for public release, it must separately call
`await session.release(document, approve)` while the session is open.

All blocking Rust transport work runs away from the asyncio event-loop thread.
Callbacks are still synchronous and must not reenter the same `Session`;
reentrant or concurrent access fails promptly with `invalid_state`.

## Errors and cleanup

`AuthError`, `ApprovalDenied`, and `PolicyRefused` derive from `SavanaError`.
Errors expose stable public codes and redact private paths, credentials,
capability bytes, endpoint internals, and unmasked content. Malformed or
unexpected responses, wrong handle kinds, wrong-session handles, callback
failure, deadline, cancellation, and indeterminate effects are failures—not
empty successful values.

Use `async with session` or call `await session.close()` explicitly. The Python
facade coalesces repeated close calls, while the Rust workflow still sends the
existing close action when required by session state.

## Verification contract

Task 8 uses these exact gates without weaker substitutions:

```bash
cargo fmt --all -- --check
cargo test -p savana-kernel-protocol --all-features
cargo test -p savana-client --all-features
cargo check --workspace --all-targets --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
python3 -m pytest crates/savana-core-py/tests -q
./tools/check-frozen-v2-core.sh
git diff --check
git diff 00c57bc -- crates/savana-agentd crates/savana-ingressd \
  crates/savana-approvald crates/savana-kerneld crates/savana-execd
```

The Python API tests inventory the twenty types, eighteen business
methods, the three supporting operations, callback behavior, ingestion `None`
result, opaque values, redaction, async worker behavior, and close semantics.
The example above is syntax-compiled during final documentation verification;
the API calls and callback shapes are covered by those binding tests.

On 2026-08-03, formatting, both focused Rust suites, exact workspace checking,
the Python suite, the frozen-core checker, whitespace checking, and the
daemon-diff proof passed. The Python suite reported 10 passed and 2 legacy NER
smoke tests skipped because `SAVANA_NER_ASSETS` was not configured. The exact
workspace clippy command remained blocked by nine pre-existing lints in source
files byte-identical to baseline `00c57bc` (one protocol lint and eight kerneld
lints); changing the kerneld files would violate the required unchanged-daemon
proof. The implementation report next to the approved plan records the
commands, diagnostic reruns, and unrestricted full-suite environment evidence
without claiming all-green verification.
