# Private consumer admission and approval handoff (v0.4)

Status: source-level first admission and same-process approval handoff are wired.
This is **not** a completed product or native installation acceptance. This
session interface does not enable or deploy model workers.

Update: separate private **FinalRelease approval delivery** is also implemented;
see [its exact boundary and tests](private-release-approval-v04.md). This does not
complete terminal-result publication or reconnect. Model worker source code has
since been added in [the worker implementation](fused-model-worker-v04.md), but is
not enabled by this session interface or deployed by these changes.

## Implemented route

1. An authenticated Ingress tab explicitly requests `POST /v04/session/open`.
   Ingress sends operation 57 over IngressKernel with its existing authenticated
   authorization and finalized input session. There is no caller-selected task,
   principal, root, run or plaintext payload in this request.
2. The kernel input owner verifies the tab's authority. The agent authority
   checks the current signed task root, principal, deployment, expiry, explicit
   fused enrollment and ready, committed input material. It signs a separate
   `PrivateSessionV04` envelope, bound to task, durable run, root digest and
   current kernel boot. Authentication and return origins are both Approval.
3. KernelApproval operation 22 registers that envelope with approvald. Ingress
   returns only a private-session transfer. The browser posts it to
   `http://localhost:8766/v04/session/accept` in a form body, never a query,
   fragment, Agent message or persistent browser storage.
4. A deliberate click runs `/v04/session/begin` and `/v04/session/finish`.
   The durable approval owner checks the actual WebAuthn signature, user
   presence/verification, expected principal, RP/origin, challenge, counter and
   hardware credential constraints. Successful authentication mints a separate
   browser capability. It is **not a tool decision**.
5. The kernel owner clock polls operation 23. It verifies the purpose-separated
   signature, deployment, exact envelope/binding/challenge/principal, boot,
   current task root and expiry again. Only then does it consume the pending
   login and admit the committed input into an internal run. No Agent session,
   run, value or tool handle is returned to the Agent or browser. Admission
   lifetime is bounded by input, root, envelope and receipt lifetimes.
6. G5 still creates the original exact tool approval/display pair. After
   registration, the kernel attaches its approval handle to the authenticated
   private session using KernelApproval operation 24. Approvald checks the root
   association supplied by the trusted kernel and the signed task/principal
   pair; it never replaces a different unresolved pending approval.
7. The private browser polls `/v04/session/poll` with its in-memory capability.
   A separate **Review pending action** button posts the handoff to the existing
   `/v04/private-approval/accept` page. Display authentication and action approval
   remain separate ceremonies. G6 verifies the exact signed action decision;
   the next owner turn re-evaluates and reaches G7. Login/notification alone
   cannot create a ticket or dispatch an effect.

All private browser mutation routes require their exact fixed origin and content
type. The cross-origin accept route admits only Ingress, not Agent or JARVIS.
All new approval-service operations require the dedicated KernelApproval edge.
Responses use the existing no-store/CSP/no-referrer HTTP writer. Credential
revocation and durable-owner failure are checked when querying authentication
and handing off approvals, including an exact finish retry.

Legacy Agent creation reconciliation, claim, authentication preparation/continuation, task status,
session status and cancellation reject explicitly enrolled private tasks.
Existing fused guards still block the public planner/action paths.

## Required existing state

This route does not invent a signed root, enroll a task or choose a private plan.
It requires an authenticated committed input, a ready task with a real signed
root, an explicitly installed private workflow profile and a correctly measured,
configured KernelApproval connection. Model workers remain disabled. The
existing signed/admin workflow must supply registered plans/inputs/recipes where
required; this change is not automatic consumer enrollment or dynamic planning.

## Deliberate remaining limits

- Browser, transfer and pending-login identities are process-local and bounded.
  Expired or foreign tokens fail closed. A restarted approvald does not restore
  an old logged-in browser. Recovering an already completed signed challenge is
  not a new browser authentication. A restarted kernel cannot accept an old
  boot-bound proof without its original pending record.
- A consumed task currently loses its volatile input admission material and is
  restored as indeterminate by the recovery format. The snapshot validator now
  accepts absent consumed material only in post-admission/terminal states, keeps
  task/run/root identity, and still rejects a material-free Ready task. A second
  restart preserves the tombstone; no old session/transfer is reinstated. This
  fixes a restart rejection, not authenticated continuation. Fresh authenticated
  private-session recovery/reconnect remains to be implemented. No consumed
  budget, execution reservation or signed approval is reset to work around it.
- The authenticated private poll currently carries approval handoffs only. It
  is not the exclusive result publisher, result reconnect protocol, full error
  observation contract, or a general result-dependent loop compiler.
- Native V3 install/apply/watchdog/bootstrap and real Linux/systemd/TPM/browser
  acceptance remain outstanding. Container tests cannot attest these boundaries.

Consequently the six experiment preflight blockers are retained. Do not use
component test pass rates as model safety/success rates or product readiness.

## Reproducible checks

- `savana-approvald` private-session tests exercise real signature verification
  with synthetic enrolled P-256 test credentials and encrypted durable state:
  fresh login, exact retry, wrong principal/challenge/flags, expiry, revocation,
  cross-task/root handoff, restart rejection and no implicit action decision.
- The framed/encrypted Unix transport test also sends operations 22, 23 and 24;
  notification attachment before authentication is rejected over that transport.
- `savana-kerneld` `fused_private_session_*` checks real receipt verification,
  private value admission, once-only consumption and cross-purpose, digest,
  principal, challenge, boot, key and expiry rejection using signed fixtures.
  The admission test also checks restart and repeat-restart tombstones and
  rejects a Ready snapshot whose committed material is missing.
- Protocol tests cover canonical encoding, role separation and fixed HTTP origin
  rules; a Node DOM harness exercises login, in-memory polling and deliberate
  approval-page handoff. This is not a real-browser hardware-key ceremony.
- The Python `savana_bench regressions` entry selects these eight new exact Rust
  cases in addition to the previous 37, and rejects missing/ignored/zero-test
  matches. It requires working Node.js and Python 3.10+ as well as offline Cargo.
