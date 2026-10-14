# Protected experiment deployment — 2026-09-25

**Later checkpoint:** the first actual run failed before model invocation.
See [first-run evidence and bootstrap/trust fixes](experiment-first-run-20260925.md).
The readiness observations below are historical, not current experiment readiness.

This is implementation, deployment and regression evidence, **not a protected
AgentDojo score or proof of complete product acceptance**. It supersedes the
remaining *deployment-wiring* items in `experiment-wiring-20260925.md`; it does
not turn the finite-calendar experiment into a general adaptive agent.

## Scope and real execution boundary

- Linux ARM64 B/file-backed integration deployment on the authorized temporary
  AWS host `i-071646e066afc6302`, `ap-southeast-1`.
- Python SDK is the only experiment-facing kernel interface. The independent
  root operator uses `savana.managed_admin`, not handwritten kernel IPC.
- Three reviewed upstream AgentDojo workspace calendar tasks, each clean plus
  two fixed attacks: **nine cases**, using AgentDojo 0.1.35 tasks and oracles.
- The model proposes a bounded template. It does **not** read an injected tool
  result and autonomously replan. Published output is the original tool result,
  not a generated natural-language answer. These results must not be pooled
  with the unrestricted baseline or called a full AgentDojo defense score.
- Runtime authorization still needs real user input confirmation, task-root
  authorization, WebAuthn and execution/final-release approval. No synthetic
  passkey or test receipt is installed in this deployment.

## What changed

1. **Owned input instead of invented handles.** A closed typed input document
   binds the clean prompt and exact private slots before task creation. Rust
   derives selected text from the actually consented `GatedIngress` value,
   preserves provenance, and durably pins it to the real task/run. Missing,
   duplicate, additional, oversized, wrong-control and wrong-source inputs fail
   closed. Retrying restores the same pin; it cannot reset spending or replace
   the input.
2. **Native execution preparation.** The signed private managed-admin operation
   `PreparePlanningExecution` returns actual task/run/recipe material after
   current-root, profile, manifest, generation and input checks. It neither
   grants G6 authority nor executes a tool.
3. **Separated operator.** A root-owned Python service independently reconstructs
   the finite clean plan, canonicalizes/signs it through the SDK, durably retains
   the exact request, and approves only the kernel-produced recipe. The
   unprivileged experiment process never receives its signing key. Identical
   command replay is supported; new roots/runs are not silently substituted.
4. **Runtime assembly.** The runner performs owner ingress, real root consent,
   compilation, private-session handoff, input/recipe preparation, separately
   authenticated tool and release transports, receipt/payload matching and
   official oracle evaluation. One async event loop remains alive across the
   handoff, including its authentication bridge.
5. **Deployment provisioning.** The native offline authoring tool generates
   three signed descriptors, exact model-recipient G3 policy, separate mTLS
   identities, managed-admin trust and public provisioning metadata. It does
   not generate task grants. Fourteen Linux binaries and the CPython native
   extension were rebuilt offline from the recorded Rust sources.
6. **Actual human authentication bridge.** A separate root service binds the
   benchmark Unix peer, exact loopback Host/Origin and a private administrative
   bearer. A local SSM gateway presents the real approval text and invokes the
   browser's real WebAuthn API. There is no automatic approval. The server SDK
   performs ingress on Linux; local port 8767 is not needed or taken over.
7. **Fixed administration entry.** `savana-experiment-admin` provides status,
   prepare-auth, configure-model, enroll and start. Status checks real services
   and the authenticated HTTP endpoint, not just active socket units. Start
   refuses missing prerequisites and existing experiment evidence.

See `experiments/SERVER-EXPERIMENT-QUICKSTART.zh-CN.md` for commands and the
data/control-flow diagram. Private evidence is retained under
`/var/lib/savana-benchmark/runs/<run-id>/`: input environment, proposed model
view, actual tool trace, publication receipt metadata, received bytes and
official oracle result. Hash-chain verification detects inconsistencies; it is
**not** remote attestation or a portable kernel signature.

## Deployment fixes found by real activation

These failures were not hidden by a green unit-test result:

- Moving `/run/savana` to an EBS-backed `/root` archive failed with `EXDEV`.
  Persistent state now archives under `/root`; transient sockets archive on
  the same `/run` filesystem. The exact interrupted replacement was resumed,
  rather than deleting or resetting directories broadly.
- Generator output inherited root's restrictive umask. Public measured metadata
  was copied as 0600, whereas startup correctly demanded 0444. The installer
  now normalizes **public** metadata and executable modes, not private keys.
  The repair compared bytes with the fresh staging files before the manifest
  was signed. Signed startup verification subsequently passed.
- Auth-service main shadowed the `http` module with a local variable, causing
  an actual startup failure despite HTTP-handler tests passing. The name is
  fixed; a regression now exercises the socket-activated main entry.
- The isolated regression scratch directory had been archived with old state.
  It was recreated as a fresh 0700 directory owned by the test account. No
  systemd namespace restriction was disabled.
- The old Mac deployment still owns local 8767 through launchd. The gateway now
  defaults to the necessary 8766 only. Optional native-browser ingress must be
  explicitly requested; no old Mac kernel service was stopped.

## Artifact and operation provenance

Only the approved Linux artifacts, deployment/SDK source and synthetic tests
were uploaded. No model key, AWS credential, personal data or previous kernel
state was included. Objects are in the pre-existing private, AES256-encrypted,
lifecycle-limited bucket `savana-protected-20260924-wlqdul-377521353256`.

| Object | SHA-256 |
| --- | --- |
| `artifacts/experiment-complete-20260925.tgz` (126 files, 32,985,820 bytes) | `06576055654b4932f1f3399281296335676d31117f95e29173aa1e148e8b91fb` |
| `artifacts/installer-patch-20260925.tgz` | `adf7ae89ca7f2ca48dace85e29c58c4b347106979e9c5f28959aac907a7e3fef` |
| `artifacts/auth-startup-patch-20260925.tgz` | `5d93f50872a7530670057df25c895fd769a7ab318975c2da57d341657fb27cf2` |
| `artifacts/gateway-port-patch-20260925.tgz` | `60568efc8afc7fbe540d23b98506cff48f70b82807e2cab932731ec97301b131` |

The deployed `savana-kerneld` binary SHA-256 is
`766257b23232d38cca01666b0d36a516028799cc9a02230f2a6c43aa876f8699`.
Full binary/source receipts and the explicit upload inventory are retained
locally at `/private/tmp/savana-experiment-complete.keagof` (which also contains
private temporary material; **do not upload that directory as a whole**).
The final comparison checked all **498 recorded Rust source files**: no changes
since the build, and identical binary/SDK source snapshots. The Linux native
SDK SHA-256 is `6cf28699c51a7a5e1c544f067098059304ba71e8e986bb66ef7b4498f8f70b79`.

Relevant SSM operations:

- `5fdd36a3-fbc2-4572-957d-3001fcd0583e`: candidate generation and 52 Linux tests.
- `d14c892e-52b6-4e26-8481-258ab49af5bf`: public-mode repair, signed startup
  verification, five kernel services and independent operator activation.
- `0ac799a9-c4b0-45fd-8e0f-23ebdac4c96c`: actual auth startup-failure diagnosis.
- `95fdedb1-7645-42cf-a67e-b416415c3367`: corrected auth deployment, **53 Linux
  tests passed**, real service and auth-HTTP preflight.
- `074fcd17-37e9-43c2-8fa3-b1a52945bf24`: final gateway patch, **54 Linux tests
  passed**, all seven services active with zero restarts, matching installed
  kernel binary hash and an empty scored-experiment output directory.

Previous persistent kernel state, enrollment and credentials were moved to
`/root/savana-replaced-4ggslhce`; old code to
`/root/savana-protected-code-before-20260925`. They are recoverable until the
temporary host is terminated and were not restored into the fresh deployment.
Transient sockets were moved to `/run/savana-runtime-replaced-yg90p9m4` and do
not survive reboot. No new instance, inbound security-group rule or lifetime
extension was created. The original automatic termination remains
**2026-09-25 05:23:52 UTC**.

## Verification and truthful readiness

- Policy-core fused tests: **92 passed**.
- Kernel fused tests: **52 passed**.
- Final combined local installer/build, experiment and native owner/managed-admin
  Python suite, with fresh synthetic templates: **209 passed, 10 skipped,
  29 subtests passed**. Skips are not counted as passes; Python dependency
  deprecation warnings remain. The template keys stay local and were not uploaded.
- Updated authentication/gateway subset: **5 passed**.
- Final AWS Linux deployment-related synthetic suite: **54 passed**, including
  the optional-ingress regression. These tests are not scored episodes.
- Actual local HTTP through SSM: authentication page 200, its JavaScript 200
  `text/javascript`, pending queue 200, native enrollment page 200, native
  JavaScript 200 `application/javascript`. The former 400/MIME/empty-response
  failure is not present on these verified endpoints.

At this checkpoint the five native kernel services, owner control, operator,
auth service, authenticated auth HTTP and expiry guard are healthy.
**No real protected episode has yet run in this deployment, and no real model
generation was sent during this work.** A read-only provider model-list check
validated the local credential; it is not a benchmark/model-quality result.

The remaining live execution boundary is explicit:

1. Model credential installation awaits the user's choice: encrypted transfer
   only to this temporary host, or a local-only credential relay. Existing
   source-upload permission explicitly excluded credentials; it is not reused
   as permission to upload the model key.
2. Fresh deployment enrollment and subsequent approvals require the real user.
   No short-lived code is minted while the user is absent.
3. The first real end-to-end run remains unverified until those steps complete.
   Passing components must not be described as proof that this boundary works.

Even a completed nine-case run would not establish full AgentDojo coverage,
adaptive-loop prompt-injection resistance, production TPM protection or a
complete security evaluation of Savana v0.4.

A sanitized, non-scoring readiness snapshot is in
`experiments/results/aws-protected-deployment-20260925/readiness.json`.
