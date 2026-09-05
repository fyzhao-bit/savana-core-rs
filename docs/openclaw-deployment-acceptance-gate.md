# OpenClaw production deployment acceptance gate

Status: reviewed design 1 is implemented in source. Live installation and
hardware-backed approval evidence remain pending. This is a fail-closed
release gate, not a test bypass.

## Implemented security boundary

Execd now supports the closed `split-final-release` routing mode. It constructs
two independent `VerifiedRustlsProviderTransportV2` instances from signed
bootstrap material and separate private-key credentials.

The runtime accepts only `(ToolExecution, connector present)` and
`(FinalRelease, connector absent)`. It validates that pairing before locking or
calling either transport. Tool execution selects the tool provider and final
release selects the release provider. Each worker descriptor is issued with
the credential identity of the selected transport.

The macOS development material keeps the JARVIS tool provider at port 9444 and
adds the distinct release identity
`https://release.savana-development.invalid:43191/savana/final-release`, with
separate server/client certificates and an execd client private key.

The OpenClaw chat protocol contains neither `approval.request` nor
`approval.answer`. Every SDK approval callback sends a fresh
`approval.decide` request on the inherited product broker socket. Only bounded
`approval_required` lifecycle state crosses into OpenClaw; display text and
correlation IDs stay inside the trusted Savana side.

## Automated source evidence

- Router tests prove the two dispatch kinds select different manifest-bound
  targets and reject both kind/connector mismatches before transport access.
- Bootstrap tests prove legacy defaulting and fail-closed split requirements.
- Python tests prove one fresh broker decision per callback, absolute deadline
  and cancellation behavior, terminal denial, and no chat approval command.
  The integration fixture exercises the real framed broker socket and real
  Rust mTLS/durable release receiver, but intentionally uses SDK/session test
  doubles; it is not evidence of a live authenticated dispatch or hardware
  WebAuthn ceremony.
- TypeScript tests prove approval control messages poison the bridge and chat
  `queueMessage` cannot approve.
- The doctor verifies the root-owned execd bootstrap and recomputes the final
  provider server SPKI, CA/client digests, client SPKI, credential identity,
  and endpoint binding after an authenticated live SDK probe.

The release receiver still validates the canonical provider frame, TLS 1.3,
mTLS client, URL, server SPKI pin, reservation and payload binding. Provider
wire V2 and public service ports 8765–8768 are unchanged.

## Remaining live acceptance evidence

Before enabling the production Gateway, operators must record all of:

1. Install and restart the reviewed execd build with the signed
   `split-final-release` bootstrap and both private-key credentials. On
   systemd, install
   `deploy/systemd/savana-execd-split-final-release.conf` as an execd service
   drop-in; the base unit intentionally remains compatible with
   `legacy-shared` and does not request the second credential.
2. Start the Rust final-release receiver on the fixed loopback port with its
   reviewed server identity and execd client pin.
3. Provide FD 3 from the product-owned broker and demonstrate three sequential
   trusted-UI decisions—two tool calls and final release—each followed by the
   unchanged Approvald hardware-WebAuthn ceremony.
4. Demonstrate denial, window close and timeout each terminate the whole agent
   loop without retry, replanning, tool substitution or fallback.
5. Run `openclaw savana doctor --json`, archive a zero-finding report and
   complete the frozen-boundary hash review.

The live records in steps 3 and 4—not the source integration fixture—are the
acceptance evidence for authenticated execd dispatch and the unchanged
Approvald hardware-WebAuthn sequence.

Until those live checks pass, do not weaken the doctor, fabricate deployment
credentials, expose approval displays or IDs to OpenClaw, share bootstrap
tokens through configuration, or start the Gateway with a fallback model/tool
loop.
# Intent-bound profile deployment addendum (2026-09-05)

For a **new** macOS development build, materialization now authenticates the
single legacy build-input descriptor under its pinned publisher before doing
anything with it, creates a fresh registry publisher distinct from the other
generated role keys, and signs a separate schema-3 `development.final_release`
descriptor. Its fixed POST mapping binds the materialized final-release URL,
actual server SPKI pin and client-certificate credential identity. Compiled
projection digests, policy activation and a single-attempt constraint are
included. This happens before the new deployment is activated; no running state
is migrated. Partial materialization aborts installation, not a runtime fallback.

The legacy `development.draft_due_diligence_report` descriptor is re-signed
without changing its content or inventing a profile. Its nested provider API is
not the supported flat closed grammar, so it remains unavailable to strict task
execution. The new release descriptor alone does **not** make the legacy agent
workflow usable. A host-product scope broker and genuinely reviewed tool
mappings are still deployment prerequisites. Neither this code nor its tests
install local services, issue production credentials or certify live readiness.
