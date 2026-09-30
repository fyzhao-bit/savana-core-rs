# Browser-coordinated experiment start — 2026-09-25

## Scope and prior failure

The previous run `1b1b7ffaea1649a1b283ecf73b1875bc` ended at
`owner_authentication`: zero model calls, zero scored episodes, nine Unknown.
Its evidence is preserved, not relabelled as a successful defense. See
[the previous checkpoint](experiment-sdk-input-digest-20260925.md).

This change affects only the Python experiment authentication bridge, launcher,
local gateway and administrative status text. It does not modify the Rust
kernel, Python SDK binary, kernel state, enrollment or authorization policies.
Kernel access remains through the official Python SDK. The readiness message
is an experiment-broker protocol, not a kernel IPC or capability.

## Flow and security boundaries

```text
administrator start -> experiment process armed
  -> root broker offers experiment.ready (independent launch ID)
  -> browser explicitly clicks Start experiment
  -> broker validates exact request ID, launch ID, types and deadline
  -> launcher opens its model credential and enters the benchmark runner
  -> official Python owner-control bootstrap
  -> actual WebAuthn assertion, input confirmation and separate task approvals
  -> existing protected model/tool/publication path
```

Before the explicit start, the launcher creates no run, opens no model key,
and requests no kernel bootstrap or WebAuthn challenge. The readiness deadline
is 900 seconds; it is not an extension of any kernel or approval deadline.
After readiness, the existing 115-second broker bound remains. The fixed AWS
termination deadline remains **2026-09-25 16:11:22 UTC**.

Readiness is single-use per connection and bound to a fresh random launch ID.
Missing readiness, an expired request, mismatched identity, non-Boolean start,
decline and replay all fail closed. A start click cannot approve a task/action.
The root-owned Unix socket still verifies the experiment process UID/GID.
The loopback HTTP bridge still requires its private bearer and exact Host and
Origin. No new public/root-administration endpoint was added.

The browser now polls serially and only in visible tabs. Stale query responses
cannot overwrite a clicked request. Expired requests and connection failures
disable actions. An uncertain POST is never automatically repeated or followed
by an automatic cancellation POST; the same pending ID stays blocked until
the operator can establish its outcome. No browser assertion or approval was
submitted by the assistant during deployment or testing.

## Verification and deployment evidence

- Local Python protected regression: **43 passed**.
- Additional Python readiness regression: **7 passed**.
- JavaScript state-machine regression: **8 passed**, using a synthetic DOM and
  timers, not a real authenticator.
- AWS installed-source tests: readiness 7 + HTTP bridge 6 + administration 2:
  **15 passed**. These overlap local tests and are not 15 additional cases.
- Deployment SSM command: `f8bb4586-3b46-4255-97a1-a56d9f816141`, Success/0.
- Uploaded package: seven allowlisted Python/test files, 16,466 bytes, SHA-256
  `b593ad1ef1b53f729f0e1b8cc2a16776653881b7b72ea22b69452ea3f322e3b4`.
  No credentials, personal data or old kernel state were included.
- Full per-file before/after hashes and native process readbacks are in
  `experiments/results/auth-ready-deployment-20260925/deployment.json`.
- All five native service PIDs, binary hashes and restart counters were
  unchanged. Only the Python auth socket/service was restarted.
- All 16 remote administration prerequisites passed after deployment. That is
  **readiness to request authentication**, not proof of successful login.
- Five sequential authenticated local gateway reads returned HTTP 200 with
  no pending request, in 0.810, 1.173, 0.826, 0.304 and 0.306 seconds. This is
  bounded evidence of a working route, not a guarantee against SSM interruption.
- Both open authorization tabs were reloaded to replace their old overlapping
  polling code. No user credential or approval button was activated.

The old Python package source snapshot was saved before editing under
`experiments/results/auth-ready-deployment-20260925/before/`. Old run manifests
must be checked against their matching source snapshot, not rewritten to match
the new launcher. The remote old sources are also retained root-private under
`/root/savana-browser-ready-20260925/before/`.

## Limits

### Armed handoff checkpoint

SSM `332ab601-3b4f-477a-8912-3d452fb5e74f` returned Success/0. It checked the
deployed Python/SDK hashes, preserved the prior failed run byte-for-byte in
`/var/lib/savana-benchmark/retained-runs/1b1b7ffaea1649a1b283ecf73b1875bc`,
and armed the new experiment process. The service readback was active/running;
the active runs directory still contained **zero** runs before user start.
Browser inspection then showed an enabled **Start experiment** button, disabled
**Review / use passkey**, and the explicit no-challenge-yet readiness message.
This checkpoint does not assert that the user clicked, authenticated, approved
an input or obtained a benchmark score.

### Experimental limits

This is still the Linux B/file-backed, nine-episode calendar integration
subset, not TPM production acceptance or a full AgentDojo result. It has a
bounded template proposer, not adaptive post-tool model replanning. Deployment
tests and a visible start button cannot establish an end-to-end score. Only
actual model calls, kernel-authorized final publication, matching bytes and
the official oracle can yield a scored episode. Until then results remain
Unknown and no defense success rate is reported.
