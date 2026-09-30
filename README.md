# savana-core-rs

[简体中文](README.zh-CN.md)

## Current source snapshot — 2026-09-29

This branch includes the Linux/v0.4 kernel work, Python SDK, deployment tooling,
and the [finite AgentDojo experiment runner](experiments/AGENTDOJO-PROTECTED-RUNNER.zh-CN.md).
The new [software-identity experiment mode](experiments/SOFTWARE-IDENTITY-BENCHMARK.zh-CN.md)
uses an explicitly armed test identity and bounded preconsent, not real human or
hardware authentication. Production defaults remain interactive. This mode has
not been deployed or produced a protected benchmark score. Raw experiment
artifacts and operational logs remain local under ignored `experiments/results/`;
historical reports may reference those non-published files.

Pre-push checks: 71 focused Python tests and macOS workspace `cargo check`
passed. The frozen-core integrity check still reports **17 source/hash
mismatches**; the freeze was not regenerated merely to make that check pass.
This is a development checkpoint, not a validated release. See the
[checkpoint record](docs/verification/source-checkpoint-20260929.md).

The dated records below describe separate implementation stages, not a claim
that the complete product or native hardware acceptance is finished.

## v0.4 implementation records (Linux target)

An independent [user-verified passkey profile](docs/verification/passkey-assurance-v04.md)
is deployment-selected alongside the unchanged attested-hardware profile. It supports
synced/zero-counter credentials, signs the actual assurance, and durably consumes
one-use challenges. Login still does not approve actions. It makes no hardware
non-copyability claim. Python APIs are unchanged; real enrollment and AWS native
product acceptance are not complete.

An additive TPM P-256/ECDSA-SHA256 deployment signature suite is implemented with
strict V3 envelopes, pinned TPM object checks and a fixed Linux device adapter.
V2 Ed25519 remains unchanged. Signed first-install enrollment, TPM-enforced PCR
signing, an isolated authority and whole-head NV recovery now connect to the Linux
Vault/Agent/G4/Connector runtime anchors. Software-TPM interoperability passed.
An [offline enrollment authoring tool](docs/verification/tpm-enrollment-authoring-v3.md)
now prepares/finalizes/verifies public material without private keys or activation.
[Python-driven Rust component experiments](experiments/COMPONENT-LOOP.zh-CN.md)
exercise actual synthetic requests and support local-model stdio, not full product evaluation.
[Fresh TPM preparation and signed activation](docs/verification/tpm-first-install-v3.md)
now have a closed native adapter and software-TPM tests; occupied slots and consumed
state cannot be reset. Legacy deployment migration, renewal and native hardware
acceptance remain incomplete; no installation was changed. See the
[current TPM authority boundary](docs/verification/tpm-authority-v3.md).
An independent [V3 deployment record journal](docs/verification/deployment-records-v3.md)
now anchors complete signed records and checks verification/commit evidence.
It also archives immutable history, verifies ledger transitions and binds both
evidence consumers to the actual ledger chain. This is not completion of the
deployment driver or permission to bypass the still-closed installer/bootstrap gate.
Linux [native staging preparation](docs/verification/linux-staging-v3.md) now checks
actual files, all six typed plans and external transaction bindings to V3 history.
It also binds all 35 payloads to the signed release manifest and rejects conflicts
with all 29 version/key-epoch high-water domains; retained manifests are reverified
for expiry and normal updates cannot replace the bootstrap TCB.
Its read-only result cannot install artifacts, start services or unfence effects.

The private action compiler now prepares only the durable next operation, so an
exhausted completed clause cannot block a separately authorized successor. Six
synthetic integration cases cover dependent two-step execution, volatile execution
handle loss, reversed dependencies, revocation, and exact second-step approval
before owner-clock resumption. These exercise real G4–G7, authenticated local IPC,
execd journaling and vault checkpoints, but use fixture sessions/keys/provider.
The first private consumer login and task-scoped approval-browser handoff are now
wired through authenticated Ingress, dedicated WebAuthn receipts, the kernel owner
clock and the KernelApproval edge. Legacy Agent login/status/claim paths reject
enrolled private tasks. See [private sessions and limits](docs/verification/private-session-v04.md).
Result-dependent registered loops now pass verified private responses into the
next step's payload, with encrypted recovery, exact per-step approval and no
quota reset. Two/three-step integration tests inspect actual provider requests.
See [result-loop scope and checks](docs/verification/result-dependent-loop-v04.md).
Owner-only Python `poll_publication` / `wait_publication` now observe a native
committed publication receipt. The experiment completion adapter matches actual
receiver bytes and records audit metadata; approval alone is not completion.
See [interfaces and flow](docs/verification/private-publication-sdk-v04.md).
This is not an official protected AgentDojo score or a production receiver.
Native installation/startup, private login recovery, exclusive publication/reconnect
and general dynamic planning remain incomplete; full-product experiments stay blocked.

The in-progress v0.4 path adds a bounded finite continuation checker, encrypted
stable-consumption/pin/freeze state, atomic G7 resource accounting, and a first
Rust-managed private object source. Renames/content edits preserve object IDs;
deletion retains tombstones and spent budget. Original managed input bytes are
now pinned atomically with G7 and survive edit/delete/replay. The five private
source-management methods plus the execution-snapshot read are documented in
[managed resources](docs/verification/managed-resources-v04.md) and
[execution snapshots](docs/verification/execution-input-snapshots-v04.md).
They are not new Agent, MCP or public HTTP endpoints. A separate Linux operator
SDK can submit signed administrative commands; it does not expose raw owner methods.
An opt-in signed UTF-8 projection now has an exact-byte pre-seal guard in the
kernel tool-dispatch path, retaining the existing G3/HPKE/execd checks. This is
not automatic task enrollment. Already-enrolled requests now bind source facts
inside the kernel using an optional purpose-separated Linux issuer; no model
supplies trusted facts. See [handoff](docs/verification/managed-handoff-v04.md) and
[admission/configuration limits](docs/verification/managed-admission-v04.md).
A signed private administration backend now supports resource import/edit and
atomic task enrollment with durable retry receipts. An opt-in Linux root-only
socket and Rust/Python `managed_admin.submit_signed` operator wrappers now route
to that same owner. No private admin key is held by the Agent or daemon. Signing
workflow, consumer approval UI and native deployment acceptance remain pending:
[administration boundary](docs/verification/managed-admin-v04.md).

The fused V2/v0.4 staging backend now includes closed review/advice/envelope
protocols, a durable once-only outbox, registered-plan compilation and V2 lowering.
Exact signed operation commitments now bind the active continuation to the real
G7 transaction, with retained old execution IDs under restricted replacement.
A private model-exchange helper charges attempts durably and enforces a new
exact-recipient G3 rule over frozen views. Its cloud transport is disabled.
Signed delivery windows now bound retries; the durable cursor skips missed slots
after recovery. The daemon timer now enters the same state owner and holds a
current-deployment policy lease through model exchange. It recovers a saved but
unactivated candidate without retransmission. Production model adapters remain
disabled. See [host integration](docs/verification/fused-host-v04.md).
A host-private dispatch binder now selects the next active operation for an
already frozen, exactly approved action, with original replay identity retained.
It is called by the daemon dispatch path and rechecked by G7; it is not the
missing candidate-to-action compiler or a new Agent/Python endpoint.
A private draft compiler now resolves activated operations to real local G4
material using the same checks as the existing proposer. It mints no handles or
execution grants by itself. Its private G4/G5/G6 caller is described below;
no consumer workflow entry is open yet. Real task-relation/display
commitments can change on recompile, so automatic approval reuse remains blocked;
see the replacement limitation in the host integration record.
A separate exact-draft recipe witness now checks reconstruction of every exact G4
slot before producing a stable recipe commitment. Real reordering preserves it,
while source/ownership changes do not. It neither transfers an exact approval nor
enables execution. Separately signed recipe allowlists can now be admitted through
the private admin transaction and restored with exact retry receipts (schema 14).
The compiler checks this approval against current recipes/generation/expiry.
The durable G7 owner now also checks the live exact-draft witness, active operation,
root and generation, and caps execution lifetime at recipe-approval expiry. Its
atomic schema-15 receipt preserves the original execution and accounting on replay;
current G5/G6, dependencies and quotas remain mandatory. Local owned inputs can now
be immutably pinned in the encrypted owner (schema 16), then restored with new
process handles but the original value identity/provenance. The compiler and G7
reject substitution; expiry and revocation still apply. These are private host
helpers, not consumer intake/session recovery. A private orchestrator now selects
the next unreserved operation, restores only pinned inputs, and creates a durable
G4 intent using the shared proposer implementation. It runs shared G5 and exact G6
envelope/receipt verification under a current policy lease; old Agent entries reject
these internal handles, including cached execution/status lookups. Private G7/execd
sending and result reconciliation now use the same sealed-envelope, signed-receipt
and vault paths. Lost responses retain the original query identity; transient
Unknown keeps its reservation and allows a later exact success, without resend.
Schema 17 now stores original result scope with G7 and checkpoints the vault result
before executor cleanup. Private query/result handles can be restored without the
old session, intent or ticket; stable identities, provenance and expiry are retained.
The production owner timer now discovers these historical executions, reconciles
one at a time, and retries exact cleanup acknowledgements without new dispatch or
plaintext refetch after checkpoint. Recovery, planning and new-action turns now
rotate. New actions require a live authorized session, active plan, pinned inputs
and exact signed recipe; they rerun G4/G5/G6/G7. Denial or required user approval
pauses the action; a recipe never substitutes for G6. Each task waits for prior
result checkpoint/no-effect settlement before advancing. Job-local faults retain
reservations, while poisoned storage fails closed. Private pending approval
envelopes and verified settlements now survive encrypted, rollback-anchored
agent-owner recovery. Rebinding requires the same current G4/root/plan and reruns
G5/display disclosure/G6; it never renews challenges or expiry, restores login,
or dispatches by itself. Consumer intake, authenticated session recovery and
trusted approval delivery/UI remain pending.
The approval receiver now persists the exact delivery role/display pairing and
revalidates cached retries; restart or re-registration cannot swap the display
challenge or reset a decision. A distinct `KernelApproval` role now supports
encrypted private registration/query and G6 receipt processing in the owner
driver; it never impersonates Agent/Ingress. Native Linux bootstrap now installs
the client when both signed bootstraps and the dedicated credential/socket are
provisioned. Approvald checks the Kernel-only listener and measured peer; opt-in
systemd units and role-directory provisioning are included. Trusted consumer
browser routing is **not yet wired**. No installed service has been changed;
without provisioning the client stays disabled. See the
[Linux approval deployment contract](docs/verification/kernel-approval-linux-v04.md).
Legacy chat/session planning and final release still fail closed for enrolled
tasks: consumer intake/approval/publisher/UI wiring is not complete, so do not enable this
on live tasks. See [fusion boundaries](docs/verification/fused-planning-v04.md)
and [execution/egress integration](docs/verification/fused-execution-and-egress-v04.md).

This is **not yet the complete v0.4 product**: general compiler/residual replacement,
exclusive publication, concrete provider effects, SDK/UI and native Linux
hardware/sandbox acceptance remain pending. Cloud/DeepSeek integrations stay
disabled placeholders. [Implementation plan and evidence](docs/research/v04-product-implementation.md).

Savana's Rust security-kernel workspace. Production crates forbid unsafe Rust
except for the narrowly audited native boundary in
`savana-platform-identity`: systemd descriptor ownership transfer and the
Linux Landlock/seccomp worker launcher, plus the macOS
CoreFoundation/Security.framework FFI and Seatbelt worker-launcher modules.
Those four modules deny unsafe code by default and annotate every required
unsafe operation locally.

The production workspace is frozen to these eleven crates:

- `savana-kernel-protocol`: bounded framing, canonical CBOR, isolated V1/V2
  wire types, stable error codes, opaque handles, and hard resource ceilings;
- `savana-policy-core`: signed policy/release verification, anti-rollback
  state, descriptor-anchored release identity, and narrow verified
  projections;
- `savana-vault`: authority-owned sensitive-data storage boundary;
- `savana-input-runtime`: Rust-owned input processing boundary;
- `savana-leak-gate`: the shared deterministic blocklist and PII detector used
  by both masking and in-kernel declassification verification;
- `savana-platform-identity`: audited native peer, process, executable, and
  service-manager listener measurements;
- `savana-agentd`: JARVIS control and agent-session boundary;
- `savana-kerneld`: fail-closed bootstrap, daemon-key ownership, authenticated
  Unix-domain transport, bounded workers, audit/panic/signal handling, and the
  public one-shot daemon entry point;
- `savana-ingressd`: local ingress boundary;
- `savana-approvald`: local approval and authentication boundary; and
- `savana-execd`: fenced executor boundary.

The separated V2 service/runtime crates now contain Rust-owned G1-G7, ingress,
approval, task-resolution, vault, and execution state machines. The client
SDK adds `savana-client` and `savana-core-py` as workspace members so Rust and
Python bindings are checked together; they are not added to the frozen
production deployment core. The legacy `libsavana-ner` crate is also a
workspace member for the Python wheel and remains off the V2 security path.

An additional **experimental research** member, [`savana-private-workflow`](crates/savana-private-workflow/README.md),
implements evidence-grounded dynamic order discovery and controlled-disclosure
planner continuations. Its three model commands are `Observe`, `Discover` and
`RequestInvoice`. It is not a new production RPC, SDK endpoint or executor grant;
the current deployment and G1–G7 path are unchanged. See its README for the
offline fixture, trust assumptions and required production integration.

Protocol `1.0` is retained only as frozen compatibility and regression
evidence under debug `test-support`. Its test-only daemon accepts exactly one
`Health`, `BeginRun`, or `IngestUserInput` request, returns one response, and
closes the connection. No release build can enable that listener.

Protocol `2.0` is separately typed. Its wire foundation contains fixed-width
primitives, redacted `TaskHandleV2`/bootstrap-selector types, closed endpoint
roles, and the content-free JARVIS-to-agentd control operations `Health` (0),
`PrepareIngress` (10), `GetTaskStatus` (11), and `CancelTask` (12). The V2
decoder does not fall back to V1, rejects cross-endpoint operation tags, and
accepts only byte-exact canonical CBOR.

The V2 Rust runtime implements:

- signed G1/G2 input assets, normalization, injection/secret/PII gates,
  protected-span tokenization, and a closed planner envelope;
- G3 labels, provenance, non-improving derivation, and handle-free semantic
  digests, plus manifest-pinned signed declassification rules;
- G4 stored binding, descriptor/registry activation, action-intent
  deduplication, and ontology projection;
- internal-only G5 validator dispatch;
- G6 WebAuthn verification, purpose-separated signed settlements, durable
  counters, replay consumption, encryption, and rollback protection;
- G7 tool/final-release dispatch, exact approval and quota binding, a single
  durable execution nonce, signed executor receipts, and reconciliation;
- five mandatory declassification transitions for masked agent views, planner
  envelopes, approval displays, executor handoffs, and final releases. Each
  transition gates the exact outgoing bytes, records a provenance node, checks
  the recipient class and exact executor/sink where applicable, and binds the
  node digest into the signed handoff object;
- encrypted, rollback-protected vault, execd journal, policy WAL, approval
  state, and agentd `TaskHandleV2` resolver;
- canonical kerneld-to-agentd task statements bound to the deployment signing
  key, manifest, generation, ABI, logical service identity, and boot IDs.
- one bounded mutable-state owner thread per daemon boundary, with
  fail-stop panic handling, deadline rejection, and bounded admission;
- process-wide agentd/execd EffectGate coordinators that hold the measured
  shared OS lock across planner/effect transitions and stop new holders after
  fence intent;
- deterministic capability-free recovery projections and reconciliation over
  the policy WAL, agent task state, execd nonce journal, and vault release
  state; and
- measured one-job parser and connector-codec child processes over anonymous
  inherited pipes. Their environments are cleared, transcripts and output are
  bounded, malformed/reused jobs are killed and reaped, and a missing or
  changed sandbox wrapper/profile fails closed; and
- the authoritative Suite-1 protocol core: fixed handshake prefixes,
  ephemeral X25519, Ed25519 transcript authentication, HKDF-SHA-256 traffic
  keys, mutual HMAC confirmation, ChaCha20-Poly1305 records, closed
  application responses, and one encrypted request/response per connection.
  Kerneld keeps its handshake signing key, pending handshakes, nonce replay
  table, and measured-process boot bindings on a dedicated bounded owner
  thread.

The kerneld V2 composition and release-gate tests exercise the Rust-owned
`ingress → G1/G2 → G3 → vault`, `G7 → execd → reconciliation → vault release`,
and `kerneld-signed task correlation → agentd` chains. The production runtime
routes all 25 AgentKernel and 12 IngressKernel operations through the bounded
state owner; authenticated requests cannot select handlers or cross service
roles.

Production `run()` enters only the V2 startup gate and never binds, decodes,
or falls back to V1. The Linux integration startup verifies the fixed systemd
descriptors, socket metadata, signed deployment root, measured service
artifacts, authority identities, key locks, and effect-ledger projection
before constructing the role-isolated listener graph. Its route-completeness
gate proves that all 25 AgentKernel and 12 IngressKernel operations have one
closed handler before startup can publish Ready. Release binaries reject that
file-backed integration authority before taking listener ownership; normal
debug builds reject it as well unless the explicit
`savana-policy-core/filesystem-integration-authority` integration feature is
enabled. A native hardware authority adapter is required to make release
startup available.

Agentd, ingressd, approvald, execd, and kerneld have fixed production config
paths, systemd socket activation, mutually authenticated Suite-1 service
edges, and closed browser/control surfaces. Agent-control Health delegates to
the authenticated kerneld client and reports `KERNEL_UNAVAILABLE` when
kerneld cannot be authenticated. The loopback UI surfaces include task status
and cancellation without exposing raw task authority.

The private root-only `savana-approvalctl` exists. Linux now includes the
measured `savana-worker-sandbox` wrapper with fail-closed Landlock, seccomp,
descriptor closure, and resource limits; native Linux CI is still required
for its runtime evidence. The deployment core now implements the closed normal
and bootstrap-bridge phase graphs, complete canonical signed ledger records,
fixed, explicitly tagged 28-domain highest-ever vector and digest, exact
dual-slot authentication and conflict selection, old-slot-only durable
replacement, reopen verification, watchdog owner-identity takeover and
live-owner heartbeat renewal, and recovery of the one crash window between a
durable successor slot and its native monotonic-counter advance. Canonical
signed transaction heads use the fixed 25-step/8-evidence language, require
the exact phase prefix and its bidirectionally required evidence references,
append under their complete signed digest with no-replace publication, retain
exact ancestry, and are rebound to the authenticated selected ledger and its
predecessor during recovery. Production ledger successors are derived from an
authenticated ledger plus the exact durable head, signed only through the
non-exportable native-authority boundary, and written through a typed
head-first/ledger-CAS transition store. That store authenticates the selected
head ancestry before progress and never chooses an orphan by time or chain
length. A fixed-inode cross-process deployment mutex now covers every bounded
CAS and is rechecked before success. The transition crash matrix covers every
head, ledger, native-counter, and final-reload durability boundary. Bounded
orphan GC deletes only private temporary heads and current-generation failed
CAS heads; unknown directory members fail closed.

Normal `ABORTED → IDLE` compaction now requires a domain-13 signed
`EvidenceGcCheckpointV2` that binds the exact terminal ledger signed digest,
immutable-core signed digest, final head, and the canonical predecessor-head
chain digest. The checkpoint is published no-replace in an anchored private
directory, flushed, reopened, and reauthenticated before the ledger reference
can be cleared. Its 12-point checkpoint/ledger crash matrix recovers only the
old `ABORTED` state or the exact new `IDLE` state, and checkpoint-referenced
head ancestry remains a GC root after both ledger slots advance. The fixed
spool enforces the protocol's 1 MiB transaction limit and redacts descriptor
contents from `Debug`.

The checkpoint is now carried by the domain-22
`InstallationEvidenceEnvelopeV2` host hash chain. Sequence one has the
explicit zero predecessor; later sequences bind the complete signed digest of
their immediate predecessor. The checkpoint store persists and reopens the
complete envelope, and the transition path no longer accepts a bare
checkpoint.

The deployment protocol also has one canonical hard-limit lock,
domain-separated file/staging Merkle rules, and closed service-transition,
isolated-E2E, evidence-contract, and protected-acceptance plan decoders. The
18-member store registry, 51-member logical-path registry, 44-member staging
registry, canonical `ArtifactIdentityV2`, `PlatformLockV2`, exact 40-entry
normal file tree, complete 75-operation artifact install plan, and
expand-only migration plan are compiled closed tables with no numeric or
string fallback. Bootstrap-owned paths have no normal staging role.
The fixed deployment spool accepts only
`apply <lowercase-64-hex-staging-id>`, walks the compiled root-owned path
without following ancestors, and opens only the single-link fixed transaction
descriptor. Software signing and rollback authorities are compiled only under
`test-support`; production has sealed authority traits and no file-backed
implementation.

The signed transaction authorization, immutable transaction core, complete
deployment and activation operational-root sets, all nine installation
evidence kinds, four auxiliary runtime-evidence schemas, their anchored
content-addressed stores, and transition-time reference resolution are now
implemented. The root helper and watchdog binary targets accept only their
closed invocation shapes, harden the root process, use the fixed spool and
stores, bind the staged transaction to the authenticated ledger pre-state,
current trust roots, and derived staging selector, and fail before reporting
success when the target-native authority is absent. Watchdog recovery
authenticates the selected ledger and head, uses the activation-signed
immutable core only to discover the bounded authorization-key references,
then selects those keys from the installer-authenticated root chain and fully
reauthenticates the core and head ancestry before deriving one closed recovery
action. Linux recovery/apply units and the private deployment directory layout
are included. The macOS worker launcher now applies a deny-default Seatbelt
profile, closes inherited descriptors, enforces CPU/file/process limits, and
uses a fixed parent supervisor to terminate a child above its measured
physical-memory footprint. The macOS CI job forces native positive execution,
unlisted file-and-metadata denial, network denial, and memory-limit tests,
while a nested development sandbox that itself forbids `sandbox_init` is
detected and cannot be mistaken for platform evidence.

What remains target-specific rather than substitutable in Rust is a selected
and tested non-exportable Linux/macOS keystore adapter, its hardware-backed
monotonic rollback authority, and the native apply/recovery operations that
consume those handles. Until that adapter is compiled into the sealed platform
boundary, `savana-deploy` and `savana-deploy-watchdog` deliberately exit
unavailable and the recovery gate cannot publish readiness.
`FAILED_SAFE` now requires exactly one kind-9, domain-22-enveloped
`DeploymentFailureEvidenceV2` reference that binds the fenced native
measurement and exact source head; a head without it is rejected. Wiring the
general installation-evidence and auxiliary-evidence stores into transitions
is complete. The target deployment must identify its Linux distribution,
architecture, HSM/PKCS#11 module, slot/token and key labels, Ed25519 mechanism,
and monotonic-counter facility. macOS additionally requires the exact Team ID,
bundle IDs, signing requirements, provisioning, and entitlements. V2 remains
fixed to Ed25519; a P-256-only hardware target requires an explicit protocol
revision rather than an algorithm substitution.
Systemd encrypted credential files and authenticated rollback-head files are
development/integration mechanisms; they are not claimed to be
non-exportable hardware authority. Consequently this repository does not
claim `PlatformComplete` or `ProductComplete`.

The kerneld library API is deliberately narrow:

```rust
pub fn run(config_path: &Path) -> Result<(), DaemonError>;
```

`DaemonError` is opaque and exposes only its stable code. Handshake state,
peer credentials, signing keys, unsigned configuration DTOs, socket controls,
authenticated connection capabilities, and policy-rollover coordination
remain internal. JARVIS transports canonical signed artifacts and opaque
handles; it does not select a role or receive a Rust capability.

## Exposed interfaces

### OpenClaw production runtime

The repository also contains the pinned, text-only OpenClaw adapter at
[`integrations/openclaw-savana-runtime`](integrations/openclaw-savana-runtime/README.md).
It targets exactly `openclaw@2026.7.1-2` and registers one provider
(`savana`), one model (`agent`), and one harness (`savana`), with zero
OpenClaw tools and zero MCP servers. OpenClaw upstream is a read-only
compatibility dependency; every adapter source, test, and document remains in
this `savana-core-rs` repository.

The adapter sends only the exact current inbound text to the public Python SDK.
Savana runs the private bounded agent loop and explicit approval flow. The only
assistant text accepted back is a payload delivered by execd to the fixed
loopback TLS 1.3/mTLS receiver, durably claimed by the sole release
reservation. See the integration README for installation, fixed-port release
connector provisioning, certificate formats, the FD 3 product authentication
broker, OpenClaw model-scoped configuration, `savana.runtime` doctor check,
recovery, and the honest transcript privacy boundary.

JARVIS remains the trusted control integration and supplies a one-time session
bootstrap out of band. The V2 client SDK then uses exactly three
application-facing loopback services: Agent, Ingress, and Approval. JARVIS is
not a fourth SDK service. Neither the Python application nor the SDK connects
directly to `kerneld`, `execd`, the vault, or a G1-G7 state machine.

### V2 client SDK

The asynchronous Python facade is implemented by the Rust-owned
`savana-client` state machine and the `savana-core-py` bindings. Its fixed
network topology is:

| Service | Fixed endpoint | SDK responsibility |
| --- | --- | --- |
| Agent | `http://localhost:8768` | authenticated session actions, masked views, planning, execution, release, and connector workflows |
| Ingress | `http://localhost:8767` | bounded text/file ingestion and committed completion |
| Approval | `http://localhost:8766` | WebAuthn and human approval ceremonies |

The twenty business methods are counted only across the three workflow
owners:

| Owner | Business methods |
| --- | --- |
| `Identity` | `load(path)` |
| `Client` | `session(identity, bootstrap, webauthn, approval)`, `enroll(enrollment_token, code, webauthn, identity_path)` |
| `Session` | `ingest_text`, `ingest_file`, `task_authorization_context`, `establish_task_authorization`, `approve_task_authorization`, `revoke_task_authorization`, `recover_task_authorization`, `read_view`, `run_planner`, `execute`, `run_agent`, `release`, `register_connector`, `remove_connector`, `list_connectors`, `revoke`, `close` |

The twenty-one product types are:

| Category | Types |
| --- | --- |
| connection and lifetime | `Identity`, `Client`, `Session` |
| opaque and projected values | `Handle`, `MaskedView`, `Plan`, `PlanStep`, `ApprovalRequest`, `ExecutionResult`, `ConnectorDescriptor` |
| task-contract data and observations | `TaskAuthorizationContext`, `TaskAuthorizationDraft`, `TaskAuthorizationReceipt` |
| choices | `IntentPrivacy`, `ContentKind` |
| loop control | `RunLimits`, `AgentEvent` |
| errors | `SavanaError`, `AuthError`, `ApprovalDenied`, `PolicyRefused` |

`TaskAuthorizationContext.tools_json()`, `TaskAuthorizationContext.draft(id, clauses_json)`,
`TaskAuthorizationDraft.from_canonical_bytes(bytes)`, `ConnectorDescriptor.load(path)` and `RunLimits.cancel()` are supporting value
operations, not additional business workflows. Handles expose no raw bytes or
retagging operation, and `PlanStep` exposes only an opaque step handle, not
invented `kind`, `reads`, or `effect` fields. Ingestion returns committed
completion (`None` in Python), not a fabricated document handle. Consequently
`run_planner(intent_privacy)` has no `goal` or `inputs` arguments: commit the
goal with `ingest_text` and files with `ingest_file` before planning or calling
`run_agent`.

In the intent-bound branch, committed input alone does not authorize planning.
An exact task contract is required first. The five task methods use authenticated
Ingress routes; task-level approval has the distinct `task_authorization` purpose.
Drafts are untrusted data and receipts are observations, not execution tickets;
Python cannot sign or construct trusted evidence. Missing finalized ingress fails
closed for new issuance. `recover_task_authorization(request_digest, approval)`
reauthenticates the same task/principal and retrieves only existing durable
issuance; it does not upload replacement input, re-sign a grant, or reset budgets.
Keep the observed issuance request digest for recovery. Pending drafts still need
the dedicated task approval; inactive/expired records fail closed.
`task_authorization_context()` returns authenticated task/source identities,
currently active signed business profiles and recoverable pending request IDs,
without issuing authority or revealing old contract controls. The fixed ingress
editor builds complete alternatives, budgets and predecessor clauses and opens
independent task approval. Empty profile lists remain unavailable, not permissive.
Live deployment profiles and whole-chain verification are still being completed;
this branch is not yet deployment-ready.

The callback supplied to `Client.session` receives every truthful ingress
approval display and must return an exact `bool`; ingress never auto-approves.
`read_view` accepts only the exact initial document or an opaque
`MaskedView.continuation` handle, preserving pagination without exposing cursor
bytes or adding a business method.

Release is an explicit `release(document, approval)` workflow. An
`ApprovalRequest` contains only `display` and `purpose`. Connector registration
loads a canonical unsigned deployment artifact, validates it in Rust, and then
runs approval and kernel authorization to produce the signed registry delta.
The bounded agent loop replans only after the exact `failed_no_effect` result;
it never retries an indeterminate effect or an
`effect_succeeded_output_quarantined` result.

See [`docs/client-sdk-v2.md`](docs/client-sdk-v2.md) for bootstrap and WebAuthn
callback contracts, the complete method table, a checked async example, error
semantics, and verification commands.

### JARVIS / Python control IPC

The production endpoint is the local Unix socket
`/run/savana/agentd/jarvis/control.sock`. It uses the authenticated Suite-1
transport, canonical CBOR, one request and one response per connection, opaque
handles, fixed deadlines, and bounded messages. The complete operation set is:

| Tag | Operation | Purpose |
| ---: | --- | --- |
| 0 | `Health` | Return the public service state; includes authenticated kerneld availability. |
| 10 | `PrepareIngress` | Create a task and return an opaque task handle plus a one-time browser bootstrap action. |
| 11 | `GetTaskStatus` | Read the public state of a task using its opaque handle. |
| 12 | `CancelTask` | Request cancellation using the task-bound cancellation authority. |

There is no generic `execute`, raw policy-evaluation, vault-read, key-export,
socket-selection, role-selection, or arbitrary-operation call on this
boundary.

### Signed declassification interface

Declassification is an internal Rust policy boundary, not a Python control
API. `kerneld` loads a canonical `DeclassificationRuleSetV2`, verifies its
Ed25519 signer through a declassification-purpose operational trust-root set,
and requires its signed digest to equal the deployment-manifest pin. The only
node-minting entry is:

```rust
ProvenanceRecordV2::declassify(
    value, context, transition, verified_rule_set, purpose_digest,
    token_set_digest, final_release_settlement, parents, effects, now,
)
```

The closed transition set is `MaskTokenizeAndLeakCheck`,
`BuildPlannerEnvelope`, `BuildApprovalDisplay`, `BuildExecutionEnvelope`, and
`BuildFinalRelease`. `judge_handoff` returns `Admits`, `Refuses`, or `Unproven`;
only `Admits` can cross a service boundary. Agent-view, planner-ticket,
approval-envelope, and sealed-execution payloads carry the resulting
declassification provenance digest. Final release additionally requires a
fresh, exact, single-use approval settlement and a non-empty value scope.

### Browser loopback HTTP

The browser surface binds only to `localhost`, uses exact hosts and origins,
rejects cookies and authorization headers, disables CORS, applies a fixed CSP,
caps request bodies at 1 MiB, and accepts only the routes below:

| Origin | Routes |
| --- | --- |
| `http://localhost:8765` | `GET /v2/shell`; `GET /v2/bootstrap/{ingress\|approval\|agent}/{selector}`; `POST /v2/bootstrap/continue` |
| `http://localhost:8766` | `GET /v2/enrollment/bootstrap`; `POST /v2/ui-auth/{accept\|begin\|finish}`; `POST /v2/approval/display`; `POST /v2/approval/decision/{begin\|finish}`; `POST /v2/webauthn/enroll/{begin\|finish}` |
| `http://localhost:8767` | `POST /v2/bootstrap/accept`; `POST /v2/ui-auth/complete`; `POST /v2/input/{begin\|chunk\|finalize\|abort}` |
| `http://localhost:8768` | `POST /v2/ui-auth/complete`; `POST /v2/agent/view`; `POST /v2/agent/action` |

Every origin also serves `GET /v2/savana-ui.js`. Dynamic bootstrap selectors,
tab capabilities, document references, and authentication transfers are
single-purpose opaque capabilities rather than bearer access to a general
API.

### Private mapper and structural planner

Planner privacy is implemented entirely in `savana-agentd`; the kernel planner
operations and the canonical `PlannerEnvelopeV2`, `PlannerPlanV2`, and
`PlannerStepV2` wire encodings are unchanged. The two outbound model
interfaces are closed mTLS CBOR endpoints:

| Recipient | Exact interface | Receives |
| --- | --- | --- |
| private mapper | `POST /savana.mapper.v2/map` | nonce-free intent projection plus the active, local semantic-catalog projection |
| structural planner | `POST /savana.planner.v2/plan` | freshly relabeled closed structural nodes, edges, and the fixed order-dataflow goal only |

Browser agent action tag `2` is the fail-safe private mapper path. Tag `16` is
the explicit per-task action that shares intent with a configured third-party
mapper, and it is rejected unless the measured deployment ceiling permits it.
The development deployment is `PrivateOnly` and pins distinct mapper and
planner server identities and agentd-only mTLS credentials.

TLS identity and network routing are deliberately separate. Each endpoint's
host is used only for SNI, SAN verification, and the HTTP `Host` field. The
signed bootstrap also carries a bounded, canonical, sorted connect-address
list; agentd connects only to those measured socket addresses and never falls
back to DNS. Development binds planner and mapper to `127.0.0.1:9443` and
`127.0.0.1:9445` while retaining their distinct `.invalid` TLS names.

On Linux the deployment-specific systemd network drop-in is mandatory. The
base unit has `IPAddressDeny=any` and no allow entry, and its `ExecStartPre`
refuses startup unless the fixed root-owned drop-in exactly matches the signed
bootstrap. The root installation sequence is:

```sh
install -d -o root -g root -m 0755 /etc/systemd/system/savana-agentd.service.d
/usr/libexec/savana/savana-systemd-agentd-network-policy-v2 install /etc/savana/agentd-bootstrap-v2.json
/usr/libexec/savana/savana-systemd-agentd-network-policy-v2 validate /etc/savana/agentd-bootstrap-v2.json
systemctl daemon-reload
systemctl restart savana-agentd.service
```

The generator atomically installs only
`20-measured-network.conf` as root:root `0444`. It permits exactly the unique
IPs found in the measured endpoint lists; endpoint ports and server identities
remain enforced by typed configuration and pinned mTLS.

The semantic catalog is an encrypted, rollback-protected local agentd store at
`/var/lib/savana/agentd/planner-catalog-state-v2.cbor` in production (under the
fixed agentd state directory on macOS development). Shipped rows are measured;
registered rows are projections of approved signed connector descriptors; only
exact active tool/action pairs enter a mapper request. The decode table and
kernel envelope nonce remain local, and decode is deterministic.
For user registration the exact fail-closed order is kerneld authorization of
the approved pending descriptor, durable catalog commit, then kerneld apply;
pending, denied, expired, and rejected descriptors never consume catalog
capacity.

This privacy boundary has an unavoidable structural-shape floor: the planner
still learns node count, coarse roles/effects, and dataflow topology because it
must order that graph. It does not learn business semantics or reusable tool
identifiers. Hiding topology itself requires local planning or fixed template
selection, not this remote structural-planning mode.

### Authenticated service IPC

These endpoints are exposed only to their pinned local service peer. They are
not supported application or Python interfaces:

| Role | Production endpoint | Closed operations |
| --- | --- | --- |
| `AgentKernel` | `/run/savana/kerneld/agentd/kerneld.sock` | `Health`, `ClaimAgentSession`, `PrepareFollowupIngress`, `GetAgentSessionStatus`, `PreparePlannerCall`, `CommitPlannerValue`, `DeriveValue`, `ProposeToolCall`, `EvaluateToolCall`, `AuthorizeToolCall`, `DispatchExecution`, `GetExecutionStatus`, `ReadAgentView`, `PrepareRelease`, `AuthorizeRelease`, `DispatchRelease`, `GetReleaseStatus`, `RevokeVault`, `CloseAgentSession`, `PrepareNewIngress`, `PrepareAgentUiAuthentication`, `AuthenticateAgentUi`, `GetKernelTaskStatus`, `CancelKernelTask`, `ResumeCommittedAgentAuthentication` |
| `IngressKernel` | `/run/savana/kerneld/ingressd/kerneld.sock` | `Health`, `BeginInput`, `AppendInputChunk`, `FinalizeInput`, `CommitInputSettlement`, `AbortInput`, `GetInputStatus`, `PrepareIngressUiAuthentication`, `AuthenticateIngressUi`, `RegisterParserWorkerJob`, `AppendParserWorkerPageFrame`, `CommitParserWorkerResult` |
| `KernelExecutor` | `/run/savana/execd/kerneld/execd.sock` | `Health`, `Dispatch`, `QueryByExecutionNonce`, `AcknowledgeCommittedCompletion`, `FetchCompletion` |
| `AgentApproval` | `/run/savana/approvald/agentd/approvald.sock` | `AgentHealth`, `RegisterAgentApproval`, `GetAgentApprovalSettlement`, `RegisterAgentUiAuthentication`, `ConsumeAgentUiAuthenticationSettlement`, `CloseAgentAuthenticationAttempt` |
| `IngressApproval` | `/run/savana/approvald/ingressd/approvald.sock` | `IngressHealth`, `RegisterIngressApproval`, `GetIngressApprovalSettlement`, `RegisterIngressUiAuthentication`, `ConsumeIngressUiAuthenticationSettlement` |
| `ApprovalAdmin` | `/run/savana/approvald/admin/approvald.sock` | `AdminHealth`, `CreateEnrollmentCode`, `RevokeCredential` |

The `ApprovalAdmin` socket is root-only and is consumed by the private
`savana-approvalctl` command. macOS development deployment uses the same
listener names and operation sets under
`/Library/Application Support/Savana/Development/run/`; those paths are not a
separate API.

### Rust embedding and protocol crates

Each installed daemon has a fixed-path startup function:

```rust
savana_kerneld::run(config_path)
savana_agentd::run(config_path)
savana_ingressd::run(config_path)
savana_approvald::run(config_path)
savana_execd::run(config_path)
```

The daemon validates the compiled production or explicitly gated development
config path and inherits its listeners from systemd or launchd; callers cannot
choose an arbitrary listener. `savana-kernel-protocol` publishes the bounded
V2 wire types and canonical encoders/decoders required to implement an
authorized client, but constructing a protocol value does not grant a
capability.

V1, raw G1-G7 controls, vault contents, plaintext secrets, signing/private
keys, peer credentials, handshake state, executor nonces, and internal owner
threads are not exposed as production interfaces. The
`savana-development-audit-bridge`, parser worker, and connector-codec worker
are fixed deployment helpers, not service APIs.

The authoritative V2 interface definitions are the closed types in
[`crates/savana-kernel-protocol/src/v2`](crates/savana-kernel-protocol/src/v2).
The frozen V1 compatibility contract is documented separately in
[`docs/protocol-v1.md`](docs/protocol-v1.md). Cross-language fixtures and
deterministic regeneration commands are in
[`vectors/kerneld/README.md`](vectors/kerneld/README.md).

Run the kernel gates with Rust 1.82:

```bash
rustup run 1.82.0 cargo fmt --all -- --check
rustup run 1.82.0 cargo clippy --workspace --all-targets --all-features \
  --locked -- -D warnings
rustup run 1.82.0 cargo test --workspace --all-targets --all-features --locked
rustup run 1.82.0 cargo doc --workspace --all-features --no-deps --locked
rustup run 1.82.0 cargo build --workspace --release --locked
```

The release command intentionally excludes `--all-features` and
`--all-targets`: test and example targets activate the compile-time
`test-support` authority, which production release builds reject.

The production Unix-socket tests require a host that permits filesystem
Unix-domain socket binding. A restricted sandbox may fail first with
`IdentitySocketPermissions`; run the suite on the host rather than treating
the subsequent process-global mutex poison as a product failure.

The daemon-side live-policy coordinator and
`.selected-policy-v1.update.lock` protocol are implemented. The external
privileged installer/updater and its trusted lifecycle trigger are separate
deliverables. Until that updater follows the documented exclusive-lock,
temporary-file, atomic-replacement, and `fsync` protocol for each temporary
file and both parent directories, deployments must activate policy changes by
restarting the daemon and must not claim coordinated live rollover.

ONNX model assets are not vendored. `libsavana-ner` resolves them at runtime
from the local directory named by `SAVANA_NER_ASSETS`.
