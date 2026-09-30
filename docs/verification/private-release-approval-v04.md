# Private final-release approval transport (v0.4)

2026-09-24. This document describes **approval delivery**. The subsequent native
terminal-result owner is now connected; see
[publication and recovery](fused-final-result-v04.md). Deployed consumer/reconnect
acceptance is still outstanding.
No official protected AgentDojo episode or cloud deployment is claimed here.

## Implemented path

The dedicated authenticated `KernelApproval` connection now supports a signed
`FinalRelease` approval/display pair, as well as the existing `ToolExecution`
pair. A kernel-delivered pair must contain a task-action binding. Both kernel
signatures, purpose, task, principal, display digest, deployment and lifetimes
are checked by the existing durable approval owner before registration.

- Operation 20 registers the pair and returns a purpose-specific handle.
- Operation 25 (`AttachPrivateReleaseApprovalV04`) attaches a **release** handle
  to a currently authenticated private session. Its fields are session, approval
  and root digest. Tool attachment remains operation 24 with unchanged encoding.
- Operation 26 (`GetKernelReleaseApprovalSettlement`) queries the release
  settlement. Tool queries remain operation 21. Each new tag has an explicit
  application-layer error contract; invalid references return typed encrypted
  errors rather than silently closing the stream.

Attachment checks the session's signed root association against the digest
supplied by the trusted kernel, current authentication/revocation state, and the
approval's signed task and principal. The approval service does not independently
resolve a root revision or grant G6/G7 authority: the native release owner must
still revalidate current authorization and exact release content at consumption.

The pending slot stores a typed tool-or-release handle. A second request cannot
replace a different unresolved pending request in either direction. Neither
entropy reused under a different handle type nor an Agent-owned record can be
queried as a kernel release. Re-registering the exact pair after durable recovery
preserves its approval/denial; it does not reset a decision or extend expiry.
Legacy schema-four records without a recorded delivery role remain Agent-owned.

The private-session SDK follows the existing separate display authentication and
decision ceremonies. Only `ToolExecution` and `FinalRelease` are accepted here;
the callback receives the actual authenticated purpose. An ingress/root/connector
approval cannot be substituted. Login, polling, or a previous tool approval never
implicitly approves publication. Uncertain decisions are not retried as new votes.

Python's existing `savana.private_v04.PrivateSession.review_pending(approval)`
inherits this behavior through the native extension. Its callback receives
`request.display` and `request.purpose` (`tool_execution` or `final_release`). No
Python signing authority, direct provider call or result-export API was added.
An existing installed wheel must be rebuilt to acquire the changed native SDK.

## Verification coverage

- Canonical protocol round trips and wrong-role rejection for tags 25/26;
  release registration responses remain rejected on IngressApproval.
- Real framed/encrypted Unix socket registration, pending query and unknown
  release query; attachment without private authentication is rejected.
- Signed synthetic WebAuthn authentication, wrong-root attachment, typed-handle
  confusion, Agent-query rejection, pending tool/release conflicts and expiry.
- FinalRelease approval and denial survive durable snapshot restoration and
  exact re-registration. Only approval carries an action authorization proof.
- SDK approval/denial for both purposes each require independent display and
  decision ceremonies, and pass the correct purpose to the callback.

These are component tests with synthetic keys, not real hardware enrollment,
production multi-service acceptance, or a measured model defense rate.

Verified on this change:

- Approval daemon: 52/52 unit tests on macOS and separately in the existing
  offline ARM64 Linux container, including encrypted Unix transport.
- Protocol, approval daemon and Rust client: combined `--lib --tests` run passed.
- Workspace `cargo check --workspace --all-targets` passed with existing
  `savana-ownerctl` dead-code warnings.
- Python experiment regression suite: 108/108 passed, with no skipped tests.
- Python-selected native security regressions: 70/70 exact Rust cases passed,
  including existing multi-step result, dynamic-observation and recovery cases.
  The report explicitly retains `model_trials: 0` and
  `production_acceptance: false`.
- Rebuilt macOS ARM64 debug wheel, installed into an isolated temporary target:
  private-session and SDK Python tests 23/23 passed. The running application
  environment and remote deployment were not upgraded.

The Rust suite and Python-selected native regressions overlap; their counts are
not additive independent security cases. None is an AgentDojo defense score.

## Still required before protected experiments

Follow-up: [terminal-result publication](fused-final-result-v04.md) now adds a
separate signed result-resource clause and drives native approval, G3/G6/G7,
executor delivery and durable reconciliation. The old release API still binds
the original input document; it was **not** widened to arbitrary tool/model output.
Freshly authenticated result reconnect, a deployed consumer, official AgentDojo
task/tool adapters and deployed worker acceptance remain required.
The experiment readiness gate therefore stays closed.
