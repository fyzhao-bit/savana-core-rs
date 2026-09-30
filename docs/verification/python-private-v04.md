# Python → v0.4 private owner interface

Authentication update: [passkey assurance](passkey-assurance-v04.md) adds a
deployment-selected user-verified passkey profile alongside attested hardware.
Python signatures are unchanged. References to the hardware provider below mean
the real WebAuthn provider for the selected profile, never a software test signer.
Native intake and the live owner provider still require deployment integration.

Status (2026-09-21): the SDK can authenticate an **already issued private
Ingress transfer**, poll private approval handoffs and conduct exact tool-action
approval through the real fixed approvald HTTP routes. This is NOT a complete
AgentDojo adapter or a replacement for native deployment acceptance.

## Interface

2026-09-24 addition: `PrivateSession.poll_publication()` and
`wait_publication(expected_task=..., expected_root=..., approval=...)` expose
owner-only, kernel-committed publication **metadata**, not raw private results or
a grant. `PublicationReceipt.matches_payload(bytes)` checks bytes already obtained
from the approved receiver. Pending approval/None is never completion. Exact
interfaces, Python experiment adapter, data flow and remaining deployment limits:
[private publication SDK](private-publication-sdk-v04.md).

The additional `connect_from_ingress(identity=..., ingress_tab=..., webauthn=...)`
entry uses an **already authenticated, committed Ingress tab** (raw canonical
43-character base64url capability, held by trusted native intake). Rust calls
fixed Ingress `/v04/session/open`, validates the canonical purpose/version-bound
reply, and directly performs the original private login. The intermediate
private transfer never leaves Rust. No Agent session, root, input, enrollment or
plan is created, and no errors trigger a retry or fallback. The API must not be
exposed as a browser token input or used to scrape capabilities from a page.
Native intake still has to obtain its tab through the real authentication flow;
this entry is not a substitute for that flow or a running Linux deployment.

```python
from savana import Identity
from savana.private_v04 import connect

async def review_one(identity_path, private_transfer, hardware_provider, user_review):
    identity = Identity.load(identity_path)
    async with await connect(
        identity=identity,
        transfer=private_transfer,
        webauthn=hardware_provider,
    ) as owner:
        if await owner.poll_approval():
            approved = await owner.review_pending(user_review)
            # approved is a confirmed signed decision, NOT tool execution success.
            return approved
        return None  # no pending handoff now; NOT task completion
```

The provider implements `assert_credential(options_json: bytes)` (sync or async),
returning the existing WebAuthn dictionary with byte fields `credential_id`,
`authenticator_data`, `client_data_json`, `signature`, `user_handle`.
It must perform the actual hardware ceremony. `user_review(ApprovalRequest)`
may also be sync or async and returns a boolean explicit user decision. A choice
does not bypass the subsequent hardware-signed decision ceremony.

`private_transfer` is the raw 43-character canonical base64url private-session
handoff from authenticated Ingress `/v04/session/open`. It is NOT a URL, a V2
Agent bootstrap, a task ID, or a self-generated token. It must remain in the
trusted owner process, not model prompts, benchmark logs, command arguments or
AgentDojo `messages`/`extra_args`. This module deliberately lives separately from
the public V2 `Client`/`Session` inventory and from signed root administration.

## Actual flow

1. Python calls Rust via the native extension on a worker thread.
2. Rust POSTs `/v04/session/begin` to fixed localhost:8766, decodes bounded,
   canonical v0.4 options, invokes the hardware provider and checks that the
   returned credential matches the loaded identity.
3. Rust POSTs `/v04/session/finish`; approvald still verifies principal,
   signature, challenge, root binding and lifetime. The opaque browser capability
   stays inside Rust. The kernel owner's existing clock consumes its signed
   authentication receipt; the SDK does not claim or directly admit a run.
4. `poll_approval()` calls `/v04/session/poll`. No pending approval is not an
   idle/done/publication signal. This is a private owner observation only.
5. `review_pending()` uses `/v04/private-approval/accept`, authenticates the
   display, verifies its ToolExecution or independent FinalRelease purpose and presents the actual display
   to the user callback. A separate signed decision follows. The next kernel
   turn, not Python, rechecks execution gates and drives the effect.

There are no Agent HTTP requests, no public planner/execute calls, no minted
authority, no exported run/value/result handles, no automatic consent and no
fallback into the V2 SDK. No cloud model is enabled.

## Errors, cleanup and experiments

- Bad/wrong-purpose/noncanonical replies fail closed. Poll/review errors clear
  local capabilities. An uncertain decision is not automatically retried.
- `close()` only forgets local capabilities. It does not cancel the kernel run,
  revoke authority, refund quota or undo a signed approval.
- Python cancellation drains the active worker and forgets any returned local
  capability. Repeated cancellation cannot release the session lock while that
  worker still operates. A hardware callback must eventually settle; cancellation
  cannot undo server-side authentication or a decision already sent.
- Exceptions remain errors/unknown, never experimental safety or utility wins.
  This module provides no task-success metric or result publication endpoint.

Prerequisites remain: native services, measured identities, committed private
input, real signed root and installed private profile/recipe. This SDK does not
automatically create those artifacts or restore a private browser after restart.

AgentDojo still needs a task-to-root/profile compiler, its simulated tool provider
connected to the kernel execution path, and an authorized observation/result
bridge. In particular, routing a proposed tool call to AgentDojo's runtime after
an SDK boolean is NOT kernel mediation. Do not open the full-product experiment
gate on the strength of these client tests.

## Tests

`cargo test --offline --locked -p savana-client` covers the existing client plus
private authentication, route/origin separation, canonical decoding, exact
approval/denial, wrong purpose/credential, uncertain responses, close and no
Agent/implicit-execution traffic. These are scripted transport tests, not a
hardware acceptance test. Existing approvald/kernel private-session tests cover
the server's real cryptographic receipt validation independently.

`crates/savana-core-py/tests/test_private_v04.py` covers the Python surface, async
hardware/approval callback bridging, local cleanup and cancellation with a built
native extension. Existing `test_client_sdk.py` checks V2 compatibility.

Validation on 2026-09-21: 103 Rust client tests, 22 Python SDK tests (6 new
private-interface tests plus 16 existing V2 tests), 3 approvald and 2 kernel
private-session tests passed. The whole-workspace all-target check and the
315-file source fingerprint check passed. Built and tested a cp312-abi3 macOS
wheel in an isolated temporary directory, not the live installation. These
counts are compatibility/security regression evidence, not AgentDojo results,
Linux hardware acceptance or an end-to-end Python-to-hardware measurement.
Changed Rust files pass targeted formatting and `git diff --check` passes.
Workspace-wide formatting still reports unrelated existing differences in kernel,
platform and policy files; those user changes were not reformatted in this work.
