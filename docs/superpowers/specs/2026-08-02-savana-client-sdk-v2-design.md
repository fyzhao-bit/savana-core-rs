# Savana V2 Client SDK Design

> Date: 2026-08-02
>
> Status: approved for implementation
>
> Requirement baseline: `docs/client-sdk-v2.md` from
> `origin/claude/security-capabilities-assessment-06bjbl`

## 1. Goal and completion boundary

Add an application-facing client SDK over the three existing V2 browser HTTP
services. The SDK gives the Python server a small asynchronous API suitable for
a redesigned frontend while keeping CBOR, fixed-HTTP framing, opaque
capabilities, state-machine orchestration, and protocol validation in Rust.

The externally reachable service boundary remains exactly:

- Agent HTTP, served by agentd on port 8768;
- Ingress HTTP, served by ingressd on port 8767; and
- Approval HTTP, served by approvald on port 8766.

This work does not modify agentd, ingressd, approvald, kerneld, execd, their
ports, their HTTP routes, their CBOR wire formats, the G1-G7 policy rules,
planner privacy, connector authorization, or kernel security behavior. If a
required operation cannot be expressed through the existing three services,
the SDK fails closed instead of adding a kernel or daemon bypass.

## 2. Chosen architecture

The implementation has three layers:

1. `savana-client` is a new Rust library. It owns endpoint validation,
   fixed-HTTP requests, CBOR encoding and decoding through
   `savana-kernel-protocol`, opaque handle storage, request nonces, polling,
   workflow state, limits, and stable error classification.
2. `savana-core-py` exposes the supported client values and operations through
   PyO3. Python never constructs a protocol request, decodes CBOR, or
   destructures a capability.
3. The Python `savana` package presents asynchronous methods. Blocking local
   transport work is dispatched away from the Python event-loop thread, but
   all protocol and security-relevant state remains in Rust.

A generated direct-TypeScript wire client is not part of this change. The
redesigned frontend calls the Python server's business API. This prevents the
browser bundle from acquiring kernel protocol types or privileged control
plane verbs.

## 3. Honest session and authentication boundary

The source proposal shows `Identity.load()` followed by a parameterless
`Client.session()`, but the implemented protocol does not authorize a session
from an arbitrary local device-key file. A session begins only from a Jarvis
bootstrap transfer capability and completes the existing approvald WebAuthn
ceremony.

The SDK therefore consumes a bootstrap handle supplied out of band by the
Jarvis control plane. It never exposes Jarvis as a fourth application service,
mints a bootstrap capability, stores a signing key, or substitutes a local key
for WebAuthn. `Identity` stores only the non-secret enrollment identity needed
to select an existing credential. The browser performs WebAuthn and returns
the resulting assertion through an application callback; Rust encodes,
submits, and validates the protocol response.

All capability-bearing values are represented by one Python `Handle`. A
`Handle` has no public raw-bytes constructor, has a redacted representation,
records its expected Rust-side capability kind, and can only be consumed by an
operation that accepts that kind. A caller cannot relabel a document as a
ticket, fabricate a connector reference, or skip an intermediate state.

## 4. Public SDK surface and counts

The network boundary is three services. The ergonomic SDK has fifteen business
methods after adding the chat and autonomous-loop operations required by the
frontend:

- `Identity.load`;
- `Client.session` and `Client.enroll`;
- `Session.ingest_text`, `ingest_file`, `fetch`, `read_view`, `run_planner`,
  `execute`, `run_agent`, `register_connector`, `remove_connector`,
  `list_connectors`, `revoke`, and `close`.

The eighteen core public types are:

- connection and lifetime: `Identity`, `Client`, `Session`;
- values: `Handle`, `MaskedView`, `Plan`, `PlanStep`, `ApprovalRequest`,
  `ExecutionResult`, `ConnectorDescriptor`;
- choices: `IntentPrivacy`, `ContentKind`;
- loop control: `RunLimits`, `AgentEvent`;
- errors: `SavanaError`, `AuthError`, `ApprovalDenied`, `PolicyRefused`.

Transport descriptor variants, placeholder records, WebAuthn assertion
carriers, and callback protocols are supporting types and are not included in
the eighteen-type product count.

Every listed method must drive its corresponding existing service workflow.
There are no successful placeholder implementations. If implementation proves
that a listed workflow is not reachable through the existing authenticated
surface, work stops for an explicit design correction instead of shipping a
stub or changing a daemon implicitly.

## 5. Request and data flow

For chat input, `Session.ingest_text` streams UTF-8 bytes through ingressd's
existing `Begin -> Append -> Finalize` protocol. `ingest_file` uses the same
flow with bounded chunks and backpressure. Parsing and masking remain on the
existing ingress/kernel path. The SDK receives and stores only the returned
opaque reference.

`run_planner` selects the existing `RunPlanner` or
`RunPlannerWithThirdPartyMapper` agent action. `IntentPrivacy.THIRD_PARTY`
never falls back to private or vice versa. A deployment refusal becomes
`PolicyRefused`.

`execute` folds the existing propose, evaluate, optional approval, authorize,
dispatch, and refresh actions for each plan step. The SDK never treats an HTTP
success status as a policy success until the canonical CBOR response has been
decoded and matched to the expected workflow state.

Connector registration folds prepare/propose/authorize/apply through the
existing Agent and Approval surfaces. Removal and snapshots use their existing
agent actions. Connector descriptors are encoded in Rust and are never accepted
as caller-provided CBOR.

## 6. Autonomous loop agent

`Session.run_agent` is an orchestration convenience, not a new daemon or kernel
operation. Rust repeatedly reads the current masked view, runs the planner,
executes the returned plan steps, incorporates new output handles, and replans
until completion or a stop condition.

`RunLimits` requires finite positive `max_steps`, `max_replans`, and deadline
values. The SDK emits redacted `AgentEvent` values for planning, step start,
step completion, approval requirement, replanning, refusal, and completion so
the Python server can stream progress to the frontend without exposing wire
objects or secrets.

Every proposed step is independently evaluated by the kernel. A previous
approval cannot authorize a later step. Policy refusal stops the loop and is
surfaced; the SDK does not silently ask the planner for a policy-avoiding
alternative. Only an explicit no-effect failure may be replanned within the
limits. An indeterminate or effect-succeeded state is never automatically
retried because doing so could duplicate an external effect.

Cancellation prevents new work but cannot undo an already completed external
effect. Closing the session follows the existing close action even after
failure, subject to the service's state.

## 7. Error model

All errors derive from `SavanaError` and retain a stable public code while
redacting credentials, capability bytes, unmasked data, and internal endpoint
details.

- authentication, enrollment, bootstrap, and WebAuthn failures map to
  `AuthError`;
- an explicit human rejection maps to `ApprovalDenied`;
- policy, effect-ceiling, release-rule, planner-privacy, and connector refusals
  map to `PolicyRefused`, including the public step and reason when available;
- malformed or unexpected service responses, wrong-handle kinds, invalid
  state transitions, transport failures, deadlines, and indeterminate effects
  remain typed `SavanaError` failures and never become empty successful values.

An approval callback decides only yes or no. It does not sign. Approvald owns
settlement signing, and the SDK only transports the signed settlement through
the existing workflow.

## 8. Compatibility and additive protocol support

Client-side canonical response decoders may be added to
`savana-kernel-protocol` where the crate currently exports only server-side
encoders. Such changes must be additive library APIs with canonical
round-trip tests. They may not change an existing encoding, type discriminant,
route, daemon handler, or maximum wire bound.

The frozen kernel deployment boundary is unchanged. New client-only files are
not added to the frozen core list unless they already belong to an existing
frozen protocol crate, in which case the normal frozen digest update records
the additive source change without altering runtime deployment topology.

## 9. Testing and acceptance

Implementation follows test-driven development. Rust tests first define the
public state machine against a scripted in-memory transport and prove:

- requests target only the three approved services and fixed routes;
- canonical request/response CBOR comes from `savana-kernel-protocol`;
- handles are opaque, kind checked, redacted, and non-forgeable through Python;
- ingest chunking, planner privacy selection, per-step evaluation, approval,
  dispatch, refresh, connector workflows, close, and revoke preserve order;
- every refusal and malformed transition fails closed;
- loop step/replan/deadline limits stop deterministically;
- policy refusal and indeterminate effects are not silently replanned or
  retried; and
- callbacks and events never receive capability bytes or unmasked values
  except the approval display fields already intended for the human.

PyO3 and Python tests prove the eighteen-type surface, fifteen business
methods, async event-loop behavior, exception mapping, and absence of public
wire-type constructors. Integration tests use the existing daemon fixtures
where practical; they do not modify daemon production behavior.

Completion requires formatting, focused tests, all affected package tests,
workspace checking, clippy, Python tests, frozen-boundary verification, and a
review of the final diff confirming no production changes under agentd,
ingressd, approvald, kerneld, or execd.
