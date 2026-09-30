# Authorized corrected reinstallation — 2026-09-25

**Later result:** the user reported registration complete and a real run was
started. It failed before WebAuthn at the next authority-envelope trust boundary.
See [the corrected-attempt report](experiment-corrected-attempt-20260925.md).
The preflight and enrollment checkpoint below is historical, not current success.

This supersedes the **deployment** blocker in
[the first-run report](experiment-first-run-20260925.md), not its failed benchmark result.
The user explicitly authorized archiving and reinstalling the temporary host.

## Executed, not inferred

On `i-071646e066afc6302` in `ap-southeast-1`, SSM operation
`7c3b9fe9-8d22-4bc0-95c3-20059f9c9ce0` completed successfully:

- Verified the prior replacement receipt and the exact failed run audit head.
- Archived current configuration, keys, state, enrollment, operator records and
  benchmark evidence under `/root/savana-replaced-3j1x72_b`.
- Moved old transient runtime sockets to `/run/savana-runtime-replaced-zx4d1jfl`.
  Persistent archives are recoverable until instance termination; transient
  archives do not survive a reboot. No archive was restored as experiment state.
- Installed fresh signed B/file-backed configuration from the corrected Python
  assembler. The existing Linux binaries were reused, not modified.
- Preserved the previously authorized model key only as a host-bound encrypted
  systemd credential on this same machine; no plaintext export or new upload.
- Started all five native services plus the independent auth and operator
  services: active/running, zero restarts at the checkpoint.
- Confirmed all administration preflight checks, including the new
  `task_correlation_trust`, are true.
- Called `savana.owner_control.issue_bootstrap()` through the Python SDK against
  the real services. Native task preparation, correlation verification, Jarvis
  selector resolution and fixed-target ingress transfer parsing succeeded.
  The resulting capability is retained only in a root-private `/run` file;
  this probe did **not** authenticate, consent, install a task root or call a model.

This specifically verifies the previously broken real entry path. It is not
proof that subsequent user authentication, tool execution or publication works.

## Local authentication handoff

The task's exact old gateway process was verified and stopped, then replaced
with a gateway holding the new broker's private token. Existing SSM tunnels
were reused. The old Mac kernel and its port 8767 were not stopped.

Actual HTTP checks through the gateway:

- `/__experiment/pending`: 200, no pending request.
- `/v2/enrollment/bootstrap`: 200, HTML.
- `/v2/savana-ui.js`: 200, JavaScript.

Browser automation returned `net::ERR_BLOCKED_BY_CLIENT` when navigating the
enrollment tab. This was reported to the user; no alternate automation was used
to bypass that block. The user received the link and one fresh short-lived
registration pair. Its secret values are **not** stored in this document or repo.
User enrollment and subsequent authentication remain to be confirmed.

## Budget protection

The original relative systemd timer displayed a later next-run time after the
reload. The independent AWS Scheduler was read back: **ENABLED**, unchanged
`at(2026-09-25T05:23:52)` UTC, targeting only this instance.

An additional absolute local guard, `savana-acceptance-expiry-absolute.timer`,
was created for the same original **05:23:52 UTC** deadline and verified active
by SSM operation `fb528b94-1ece-44e0-9bf9-c2f277d60178`. No new instance, inbound
rule or budget/lifetime extension was created. Local shutdown is not equivalent
to AWS termination; the existing independent AWS termination remains necessary.

## Scores remain unchanged

The original failure remains: **0 scored episodes, 0 model calls, 9 Unknown**.
The new deployment has not started a scored run. This is a nine-case finite
calendar subset, not full AgentDojo, adaptive tool-output replanning or
production TPM/rollback acceptance.
