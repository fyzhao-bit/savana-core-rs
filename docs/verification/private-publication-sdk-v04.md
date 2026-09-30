# Private publication receipts through the Python SDK

2026-09-24. Implemented completion observation, **not** an official protected
AgentDojo run or deployed end-to-end acceptance. The experiment calls Python
only. It does not invoke a Rust executable, speak internal IPC or read a vault.

## Interfaces

Owner-side `savana.private_v04.PrivateSession` adds:

- `await poll_publication() -> PublicationReceipt | None`
- `await wait_publication(expected_task=bytes32, expected_root=bytes32,
  approval=callback, timeout=120.0, poll_interval=1.0) -> PublicationReceipt`

`PublicationReceipt` is a frozen native value with no Python constructor. Its
read-only byte fields are `task_id`, `run_id`, `root_digest`, `release_id`,
`destination_digest`, `payload_digest`, `approval_digest`, `receipt_digest`,
`audit_digest` and `commit_digest`. `matches_payload(bytes)` matches already
received bytes against the native final-release payload commitment. Repr is
redacted. No method exports a private result, grants access or executes a tool.

The existing V2 Agent API is unchanged. These are private owner interfaces,
not LLM/MCP tools. A Python object or exported JSON is **not portable attestation**;
trust depends on the authenticated native channel and trusted owner process.

## Data and control flow

1. Existing native FinalRelease dispatch obtains its independent signed approval
   and passes G3/G6/G7. Approval alone does not produce a completion value.
2. Kernel validates the original executor receipt/audit, settles task consumption
   and vault release, and persists completion plus commit. Only that committed
   archive can produce publication metadata. Native reopen reuses the original
   release identity and does not send the business request again.
3. A paced owner tick sends metadata over authenticated `KernelApproval`, op 27.
   Approvald requires a live authenticated private session, exact task/run/root/
   boot, exact attached FinalRelease envelope, and an Approved settlement for
   the same principal. Pending/denied/foreign approvals and expired sessions fail
   closed. An already committed historical publication does not need a renewed
   FinalRelease approval; its original settlement is retained, not reissued.
4. Approvald caches the derived notification. Exact retries are idempotent;
   replacement is rejected. This cache is not a new durable source of truth.
   Failure to notify does not reverse the commit, refund usage or repeat a tool.
5. The native SDK polls `POST /v04/session/publication` on the fixed approval
   origin. Agent/Ingress/JARVIS origins, GET and query-token variants are rejected.
   It reuses the authenticated private-session capability; the service checks
   expiry/revocation on every observation. A cached confirmed value cannot be
   changed or regress to None within that SDK session.
6. Python `wait_publication` reviews separate pending approvals only through the
   explicit callback and existing authentication/signing flow. None means
   **not observed**, not task success, denial or attack resistance.
7. `experiments/savana_bench/private_episode.py::finish_private_episode` checks
   expected task/run/root/destination, then calls the application's approved
   receiver and checks its bytes with the native receipt. It emits metadata-only
   audit events, closes the local session, and returns `published` or `unknown`.
   Published is delivery observation, **not** task utility/security. Official
   oracles must still evaluate the real environment, including uncertain cases.

The receiver callback must retrieve the already published bytes. It cannot be
implemented by calling the upstream tool again or reading internal kernel state.
This patch does **not** provide the missing production receiver transport.

## Example (already authenticated/admitted task)

```python
from savana_bench.private_episode import finish_private_episode
from savana_bench.publication_audit import PrivateEpisodeAudit

# All scope values come from the actual pre-approved task/deployment, not model
# output. owner_session is the real SDK PrivateSession. No mock credentials.
with PrivateEpisodeAudit(new_log_in_private_directory) as owner_audit:
    outcome = await finish_private_episode(
        session=owner_session,
        expected_task=task_id,
        expected_run=run_id,
        expected_root=root_digest,
        expected_destination=destination_digest,
        approval=review_authenticated_approval,
        receive_publication=approved_receiver.receive,
        emit=owner_audit,
    )
# Only outcome.status == "published" carries matched payload bytes.
# Neither branch supplies an AgentDojo grade by itself.
```

Audit records contain observer wall-clock time, sequence, task/run/root/destination, original release, approved
envelope, payload/receipt/audit/commit digests, byte length and observation stage.
They exclude bootstrap tokens, passkey proofs, private plaintext and exception
strings. The writer must persist or raise; an audit failure cannot return a
successful episode. `PrivateEpisodeAudit` opens a new mode-0600 file in an
owner-private directory, refuses symlinks/overwrites, hash-chains closed event
schemas, checks order/scope, handles short writes, fsyncs each row, and refuses
further writes after an uncertain write. It never turns observation into oracle
success. Keep the final digest independently: an unkeyed hash chain alone cannot
prevent a malicious file owner from rewriting the entire log. These observer
records do not replace a full signed kernel
audit archive. Do not give them to the planner.

Timeout/cancellation closes local capabilities, not the remote run. Retain the
attempted episode and investigate its original identity: no automatic fresh
root, bootstrap, dispatch or refund. Receiver failure may happen after an actual
effect. Unknown remains in denominators and never means no effects.

## Remaining boundaries

- New authenticated reconnection after expiry/restart is not implemented here.
  A durable kernel commit can survive without an accessible current browser
  session. Publication metadata is not a replacement reconnect capability.
- The official task runner still lacks complete admitted task/model/provider/
  production receiver wiring. The old official runner remains **undefended**.
- No live DeepSeek request, new AWS instance, production install or official
  protected episode was performed for this change.

## Validation

- Fresh native Python extension: private SDK/owner intake/V2 SDK plus completion
  adapter scheduling tests: **53 passed**. Scheduling fakes are explicitly unit
  tests, not proof of runtime authentication.
- Python experiment framework: **124 passed**, including five exclusive-file,
  fsync/short-write, chain/scope/order and uncertainty tests for the audit writer.
- Native private SDK transport tests: **11 passed**.
- Approvald private-session tests: **5 passed**, including live signed WebAuthn
  proof, pending-versus-published, scope, immutable retry, expiry and revocation.
- Canonical publication codec / KernelApproval role tests: **2 passed**.
- Actual native executor/vault publication + encrypted owner reopen: **2 passed**;
  these tests assert approved-but-uncommitted is None, real payload matches, and
  restored commit identity is unchanged. Other services stay live in this fixture.
- Workspace/all-target compile check passed; existing ownerctl dead-code warnings
  remain. The protocol suite passed after selecting the existing working Node
  runtime (the Homebrew Node executable has a missing dylib).
- Offline ARM64 Linux container: the same codec (2), origin (1), private service
  (5), private SDK (11) and native publication/reopen (2) selection passed: **21
  tests**, no skipped cases. This is a local container, not AWS/multi-UID/TPM
  acceptance. The preinstalled `1.82.0-aarch64-unknown-linux-gnu` toolchain was
  selected explicitly; network remained disabled. Existing unused-code warnings
  remain. The transient test container exited successfully and was removed.
- Source drift check: **331 files** verified; targeted Rust formatting and
  `git diff --check` passed. No live installation was replaced.

These sets overlap; do not add them into a benchmark sample count. The source
freeze inventory includes the new protocol module; it is drift detection, not
an independent audit or a hardware assurance statement.
