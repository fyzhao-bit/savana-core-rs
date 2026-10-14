# Private approval handoff receiver

`GET http://localhost:8766/v04/private-approval` serves a constant form. It does
not discover tasks, list private actions, show status, issue a handoff or log in
a user. Its password-style field POSTs the 32-byte base64url capability to
`/v04/private-approval/accept`; capability-bearing query/fragment paths are not
accepted by the server. Responses are no-store and no-referrer, with the existing
fixed-origin/CSP protections. There are no external assets or model calls.

POST acceptance requires the exact Approval origin and a live KernelApproval
record with the original durable approval/display pair. It returns only the
existing pre-authentication shell. The original expected principal, WebAuthn
proof, display digest and decision ceremony remain mandatory. An accepted handoff
creates no approval tab, vote, settlement, task, execution ticket or budget.

The legacy Agent/Ingress/Jarvis route now rejects KernelApproval transfers. The
private route rejects their transfers. Unknown, malformed, expired and wrong-role
transfers on the private route get one generic HTTP 400 response with no reflected
token or redirect. This normalization is not a timing/noninterference proof.

Fresh pending pairs can be re-registered after encrypted reopen with a new volatile
transfer while retaining the original signed envelopes. Old page capabilities
remain invalid. This is **not** authenticated browser/session recovery: a completed
authentication cannot be silently replayed to create a new logged-in browser.

The shared approval renderer now retains its status element after replacing the
authentication screen, removes the old pre-authentication data attribute, and
checks that the returned decision matches the user's selected decision. Browser
tests exercise approve, deny and an unexpected decision as well as exact Unicode
display text. Socket tests exercise the actual HTTP parser/handler with signed
fixtures, but do not claim physical hardware enrollment or a live deployment.

## Still required

The trusted authenticated consumer session must deliver this handoff. The private
kernel driver still does not expose it via Agent status, logs or a public queue,
and the receiver is not automatically reachable from a consumer workflow. Do not
tell a user to extract a production token from memory or manufacture one. Remaining
work includes authenticated intake/session recovery, private routing, exclusive
publication and actual Linux/AWS acceptance. The receipt still goes through G6;
only a later, revalidated G7 turn can dispatch an effect.
