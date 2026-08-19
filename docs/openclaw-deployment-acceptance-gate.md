# OpenClaw production deployment acceptance gate

Status: blocked pending a reviewed transport design. This is a fail-closed
release gate, not a test bypass or a missing OpenClaw configuration value.

## Observable implementation facts

The current execd process owns one
`VerifiedRustlsProviderTransportV2`. Its deployment manifest pins one socket
address, canonical URL, TLS server identity, client credential, and ALPN.

Tool execution may resolve a connector descriptor, but
`verify_https_connector_target_v2` still requires that descriptor to name the
same provisioned canonical URL, TLS pin, hostname, and port. Final release does
not resolve a connector descriptor: `connector_dispatch_for_subject` returns a
connector only for `ToolExecution`, so `FinalRelease` uses the same global
deployment provider target directly.

The OpenClaw release receiver validates the canonical provider frame, mTLS
client, URL, server SPKI pin, reservation, and payload binding. The frame
contains execution and dispatch digests, but no receiver-verifiable dispatch
kind. Consequently the receiver cannot distinguish a tool provider frame from
a final-release provider frame. Its global one-release reservation is safe
only when no tool frame can arrive at that endpoint.

The current macOS development deployment additionally pins the provider to
`https://provider.savana-development.invalid:9444/`; the JARVIS provider owns
that listener. Its connector registry starts from an empty genesis and ships
with the connector update authority disabled. The installed JARVIS runtime
also does not expose the product-owned inherited-FD WebAuthn/bootstrap broker
required by the OpenClaw bridge.

## Why startup is refused

Repointing the single provider to the OpenClaw receiver would disable the
existing JARVIS connector provider. Allowing both tool and final-release frames
to reach the receiver could let an unrelated tool frame claim the sole release
reservation. Proxying by guessing from plaintext payload shape would not be a
cryptographic dispatch-kind proof.

Starting OpenClaw while any of those conditions remains true would contradict
the released-only security claim. `openclaw savana doctor --json` therefore
continues to fail closed.

## Reviewed designs that can clear the gate

One of these mutually exclusive designs must be approved and implemented:

1. Add a separately manifest-bound final-release transport selected from the
   already verified `FinalRelease` dispatch kind. This preserves the existing
   tool provider but changes execd configuration/runtime behavior and requires
   a frozen-boundary review.
2. Ship an OpenClaw-only Savana deployment with no tool connectors and pin its
   sole provider to the Rust release receiver. This requires no wire change,
   but it does not satisfy the intended MCP-capable personal assistant.
3. Extend the provider wire with a signed, receiver-verifiable dispatch kind
   and place a Rust multiplexer at the pinned endpoint. This is a wire-version
   change and requires a new protocol design and compatibility plan.

Until one design clears review, do not weaken the doctor, fabricate deployment
credentials, share bootstrap tokens through OpenClaw configuration, or start
the Gateway with a fallback model/tool loop.
