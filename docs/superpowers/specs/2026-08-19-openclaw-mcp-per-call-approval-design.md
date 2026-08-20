# OpenClaw MCP Per-Call Approval and Split Final-Release Transport Design

Status: approved by the product owner on 2026-08-19.

## Goal

Allow the Savana-owned agent loop to use manually registered MCP connectors
while preserving the product claim that OpenClaw cannot choose tools, approve
effects, observe private tool material, or receive anything except an
explicitly approved final release.

Every real MCP invocation, including read-only calls, requires a fresh Savana
approval. Execd keeps the existing connector provider and sends final-release
traffic over a separately deployment-bound transport selected from the
already verified dispatch kind.

## Fixed security boundary

- OpenClaw owns channel ingress, progress presentation, Gateway sessions, and
  the released transcript.
- Savana owns planning, G1-G7 policy, connector registration, connector
  selection, approval, execution, private results, declassification, and
  final release.
- OpenClaw registers no tool and projects no MCP catalog into a model prompt.
- A connector is registered once through Savana's manual connector workflow.
  Agent text cannot register, replace, or update a connector.
- Each tool execution and each final release consumes a distinct approval.
- Chat text such as `Approve`, `允许`, or `确认` is never an approval signal.
- Existing public ports 8765-8768 and provider frame V2 remain unchanged.
- No private tool argument, tool result, WebAuthn material, bootstrap token,
  opaque kernel capability, or approval display is written to OpenClaw logs
  or transcripts.

## Component boundary

### Execd

Execd owns provider routing because it is the component that has already
verified the signed execution envelope and its `DispatchSubjectV2`.

The signed execd bootstrap keeps the existing `provider` object and adds:

```json
{
  "provider_routing_mode": "split-final-release",
  "provider": { "...": "existing tool provider" },
  "final_release_provider": { "...": "release-only provider" }
}
```

`provider_routing_mode` is a closed enum:

- `legacy-shared` preserves an existing non-OpenClaw deployment and rejects a
  `final_release_provider` object.
- `split-final-release` requires a complete `final_release_provider` object
  and a distinct final-release client private-key credential.

The split configuration binds the final-release socket address, canonical
URL, server name, server SPKI, root CA, client certificate, client private
key, ALPN, endpoint-binding digest, and credential identity. All paths and
digests are part of the already signed bootstrap material.

After the envelope has been verified and durably prepared:

- `ToolExecution` requires a resolved connector and selects only `provider`.
- `FinalRelease` requires the absence of a connector and selects only
  `final_release_provider`.
- A kind/connector mismatch fails before a provider attempt is prepared and
  before the first external byte can be emitted.

The existing `VerifiedProviderRequestV2` encoding is reused. The receiver does
not need a new dispatch-kind field because a tool request cannot reach the
release endpoint in split mode.

### OpenClaw release receiver

The Rust release receiver remains a fixed-loopback, TLS 1.3, mTLS,
single-flight receiver. It validates the canonical URL, TLS pin, client
identity, ALPN, reservation, execution and dispatch digests, payload digest,
and duplicate state before exposing released UTF-8 bytes to the bridge.

### Trusted approval broker

The OpenClaw bridge already receives a product-owned inherited Unix stream as
file descriptor 3. The same closed, length-prefixed broker protocol is
extended with `approval.decide`.

The bridge sends the broker:

- a fresh random approval correlation ID;
- the protocol-produced display text;
- the closed approval purpose;
- the absolute approval deadline.

The trusted broker opens or focuses the Savana approval experience and
returns a correlated boolean decision only after the user acts. Returning
`true` does not itself settle the approval. The unchanged Rust SDK then asks
Approvald for the decision ceremony and obtains the WebAuthn assertion over
the exact approval envelope through the broker. Approvald verifies and signs
the settlement.

OpenClaw receives only an `approval_required` lifecycle event and remains in a
waiting state. The bridge protocol no longer accepts `approval.answer`, and
the harness no longer renders an Approve/Deny chat prompt.

## End-to-end data flow

1. OpenClaw forwards only the exact current inbound user text to the Savana
   bridge.
2. The Python bridge calls the public Savana SDK and ingests the text.
3. The Rust agent loop proposes an operation against an already registered
   connector.
4. G1-G7 and the existing plan/effect bindings evaluate the proposal.
5. The SDK receives Approvald's truthful display artifact.
6. The bridge sends `approval.decide` over the inherited trusted broker
   channel and emits only a redacted waiting event to OpenClaw.
7. The trusted Savana approval experience obtains the user's decision. If the
   user approves, the unchanged SDK completes Approvald's WebAuthn-bound
   decision ceremony.
8. Execd receives the signed `ToolExecution`, requires a registered connector,
   and uses only the existing tool provider.
9. The private result returns to Savana and the agent loop may continue. Every
   later MCP call repeats steps 3-8 with a new approval.
10. The final document gets a separate final-release approval.
11. Execd selects the final-release transport from the verified
    `FinalRelease` kind and sends the existing canonical provider frame to the
    Rust release receiver.
12. Only the receiver's reserved released bytes become one OpenClaw assistant
    message.

## Approval and capability binding

The kernel's existing signed objects remain authoritative. Each approval is
bound to the principal, authenticated session, run, execution nonce, dispatch
core digest, dispatch subject digest, connector identity, tool identity,
canonical arguments and payload digests, declared effects, policy decision,
deadline, and approval purpose.

The trusted broker correlation ID is an additional UI correlation only. It
cannot authorize an execution and cannot replace the Approvald settlement.
Changing a connector, tool, argument, effect declaration, run, nonce,
deadline, or purpose produces a different kernel binding and requires a new
ceremony.

## Denial and failure semantics

- Denial, closing the trusted approval experience, broker failure, or timeout
  returns `false` to the SDK. No execution is dispatched and the whole agent
  loop terminates.
- OpenClaw does not replan, substitute tools, change arguments, fall back to a
  different runtime, or retry after denial.
- A duplicate, stale, mismatched, or late broker response is rejected.
- A crash before the durable effect-start boundary is failed-no-effect.
- A connection loss after an external attempt may have started is
  indeterminate. The loop terminates and never retries automatically.
- Pending approvals and unconsumed UI correlations are invalid after bridge
  restart.
- Concurrent runs have independent correlation IDs and kernel bindings.
- A successful tool call without a successful final-release ceremony exposes
  no answer to OpenClaw.

## Compatibility and deployment

Old, non-OpenClaw bootstraps deserialize as `legacy-shared`. They keep their
existing behavior. A deployment that selects `split-final-release` fails
startup unless all release provider material and its distinct private-key
credential are present and digest-bound.

The macOS development material generator and installer create distinct tool
and release client credentials plus a fixed release receiver server identity.
The OpenClaw doctor requires split mode and exact agreement between the signed
execd target and the bridge release target before Gateway startup.

This is a frozen-boundary change because execd's signed configuration and
provider-routing behavior change. The reviewed file list and frozen digests
must be regenerated only after the complete test suite passes.

## Verification

Acceptance requires automated evidence for all of the following:

- verified routing selects the tool provider for `ToolExecution` and the
  release provider for `FinalRelease`;
- kind/connector cross-use fails before provider effect start;
- split mode rejects missing, aliased, or incomplete release material;
- independent endpoint and credential digests are enforced;
- the OpenClaw bridge accepts no chat approval message;
- every SDK approval callback uses the inherited trusted broker and a fresh
  correlation;
- denial, timeout, duplicate, mismatch, and restart fail closed;
- two or more tool calls produce two or more broker decisions and kernel
  approvals;
- final-release delivery reaches the Rust receiver only through the split
  target;
- no unreleased result becomes assistant text;
- existing Rust, Python SDK, TypeScript adapter, deployment, and frozen-core
  checks remain green.

