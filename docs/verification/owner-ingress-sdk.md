# Authenticated owner intake SDK — 2026-09-24

This is client code, not a claim that the local UI / AWS deployment is connected.
The subsequent [Linux native task-entry work](linux-owner-control.md) implements
the measured bootstrap issuer client, but has not upgraded the enrolled host or
provided the interactive browser/review adapter.
It adds a non-Agent intake path in `savana-client` and `savana.owner_ingress`.
Existing browser-enrolled discoverable passkeys can authenticate without
re-enrollment or a fabricated Python `Identity` file. The server remains the
authority for the credential, expected principal, task, boot and expiry.

## Implemented sequence

1. `owner_ingress.connect(bootstrap=..., webauthn=...)`: consume a real, raw
   kernel-issued Ingress bootstrap and perform Ingress WebAuthn authentication.
   No Agent session is created. The successful credential ID stays in Rust and
   is pinned for subsequent input, task and private-session authentication.
2. `commit_text(text, approval)`: accept one nonempty UTF-8 text of at most 64 KiB,
   bind its byte length and SHA-256, verify the chunk acknowledgement/digest,
   authenticate the input approval display, obtain explicit user choice,
   sign the exact decision, and confirm final input commitment.
3. `task_authorization_context()`: obtain owner-only authoritative metadata.
   `approve_task_authorization(draft, approval)` performs a separate task-level
   approval ceremony and checks the issuance request digest in both handoff and
   commit receipt. Chat text never becomes authority by itself.
4. `into_private_session()`: one-way handoff after input commit and root approval.
   The kernel still requires a signed v0.4 planning enrollment. Intermediate
   capabilities remain in Rust. Missing authorization never falls back to V2.

All requests use fixed loopback services. This object exposes no file, Agent,
model, execution or result-release methods. It does **not** itself constrain the
authority of an arbitrary supplied draft: the trusted task composer must use the
agreed scope, and the kernel validates it. In particular, the requested
text-only/no-tools/no-cloud deployment still needs its actual signed profile;
a generic draft or a dummy planning operation is not evidence of that scope.

On a transport/protocol/callback error after an operation begins, the local
session closes without automatic replay. Closing does not undo committed input,
revoke a root, cancel execution or refund consumption. Unconfirmed input may
remain staged on the server until its normal expiry. Python serializes calls,
drains cancelled native workers and closes any otherwise orphaned capability.

## Trusted composition example (not a standalone application)

The context now also exposes `private_binding_json()` (verified task,
installation, manifest, generation, source and lifetime) and
`final_result_resource(operation, descriptor)` (the Rust stable selector codec
for a descriptor already present in the context). These are owner-only metadata
helpers, not authorization, and must not be passed to a model. See the
[experiment wiring record](experiment-wiring-20260925.md) for the subsequent
Python authoring and Linux regression work; that candidate is not a live upgrade.

```python
from savana import owner_ingress

# These are real trusted deployment components, not included fixtures:
# issued_bootstrap, webauthn_provider, native_review, compose_scoped_draft.
async with await owner_ingress.connect(
    bootstrap=issued_bootstrap, webauthn=webauthn_provider
) as intake:
    await intake.commit_text(user_entered_synthetic_text, native_review)
    context = await intake.task_authorization_context()
    draft = compose_scoped_draft(context)  # proposal only; cannot self-sign
    receipt = await intake.approve_task_authorization(draft, native_review)
    private = await intake.into_private_session()

async with private:
    if await private.poll_approval():
        await private.review_pending(native_review)
```

Neither `native_review` nor `webauthn_provider` may be an auto-approve fixture.
Do not expose the intake instance, metadata, draft or bootstrap to an LLM/MCP.

## Verification boundaries / remaining deployment work

Rust scripted-transport tests exercise the real SDK state machine, including a
positive login → signed input → distinct root approval → private handoff path;
transport loss at every login/input stage; malformed capabilities; wrong
approval purpose; mismatched task receipt; changed credential; denial; bounds;
and no Agent requests. Python tests cover the scheduling/cancellation boundary.
Scripted responses are **not** real-server signature or browser-passkey evidence.

Verified locally in this iteration:

- `cargo test -p savana-client --offline`: existing client suite passed after
  extracting the shared approval flow and adding the owner implementation.
- `cargo test -p savana-client --test owner_ingress --offline`: 10 tests passed.
- `cargo check -p savana-core-py --offline`: passed.
- Built a fresh macOS ARM64 abi3 wheel and installed it into an isolated
  temporary directory, without replacing the live UI's installed SDK.
- `test_owner_ingress.py`, `test_private_v04.py`, `test_client_sdk.py`: 31 tests
  passed against that wheel, including 8 new owner-wrapper tests. Existing
  `asyncio.iscoroutinefunction` deprecation warnings remain.

The live frontend has not been configured with this path. Its connection button
must remain disabled until a real trusted bootstrap issuer, interactive browser
WebAuthn/review provider, owner/conversation mapping and signed scoped private
profile are installed and verified together. No enrollment state was reset by
this change; no new kernel binary was deployed to AWS in this iteration.
