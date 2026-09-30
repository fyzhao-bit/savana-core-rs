# Savana v0.4 product implementation

Started 2026-09-18 from `Savana_Complete_Architecture_EN_v0_4.pdf` (35 pages),
SHA-256 `36589495c1e895a9f91ba37f0a78f653cd8e52cbde02ec330d31d14430dca65b`.
The user permits changes to the Rust kernel. This does not authorize resetting
existing installations, clearing credentials, uploading private data, or purchasing
cloud services. Existing unrelated working-tree changes are preserved.

## Delivery boundary

The PDF is a target architecture, not a ready implementation specification. Its
S2–S5 proof/research packages were not attached. Their saved counts are not current
test results. No hand proof, model checker, or library unit test is production
certification. We will not enable a strict mode while any required egress,
observation, authority, or recovery premise is missing.

The first product target is a **Linux-hosted Rust kernel**, Python host and private
web UI (user direction, 2026-09-18). Stop new macOS signing/Touch ID deployment work;
do not remove its existing code or weaken Linux isolation. Reuse the systemd,
separate-service identities, Unix IPC and native sandbox foundations. Keep existing
V2 gates and approval paths. Add explicit new-mode admission;
do not silently change old static or DeclaredFeedback contracts. Optional bounded
probabilistic inference remains disabled until conditional-law checking, durable
sampling/accounting and probabilistic refinement exist. Cloud advice starts with
a fake worker and cannot be required for local safety. The requested real worker
is **DeepSeek-V4.1-Flash self-hosted on Google Cloud**, not the DeepSeek public API.
Google Cloud is outside the local private boundary. Until the user changes the
data policy explicitly, only approved ReviewView/PlannerEnvelope data may leave.
Any local secret-dependent language analysis must remain local or report a private
capability limitation, not silently use the cloud worker on raw records.

Per the subsequent user instruction, **Google Cloud and DeepSeek-V4.1-Flash are
placeholders only**. Do not wait on project IDs, install cloud tools, download
weights, call a live model endpoint or provision resources. Other Linux/kernel
implementation continues. Future activation will require region, GPU capacity,
spending limit, model revision and runtime image digest; none is inferred here.
Local unit tests on the current macOS development machine do not constitute Linux
systemd, sandbox, TPM/HSM or full-product deployment acceptance.

## Ordered delivery checklist

| Stage | Required implementation | Completion evidence |
| --- | --- | --- |
| A: finite core | Explicit trusted finite semantics, complete strict paired closure, independent certificate recheck, finite release-policy search, exact behavioral quotient | Adversarial unit tests, concrete witnesses, resource exhaustion is Unknown; no caller-supplied omitted edges accepted |
| B: private state | Root-bound stable multi-domain consumption, original execution/observation keys, typed evidence and purpose roles | Atomic all-or-none charges, update/rename/replay tests, no new dispatch authority |
| C: owner integration | Durable admission/ledger/pin/freeze and original-response references in existing owner; authenticated anti-rollback reopen | Real restart/crash-cut tests against both owners, current-reader checks, no fabricated fallback output |
| D: continuation/replacement | Restricted language/compiler, C1–C6 and BC0–BC5 coverage, separate K1–K6 judgments, final dependency recheck and anchored transfer | Useful F/G replacement, late response, CAS/execd race, fair-progress rejection witnesses |
| E: release integration | Fixed exclusive publisher, InferenceSpec and recipient/history scope, authenticated private clarification, whole-envelope mediation | Paired transcripts including errors/catalog/reconnect/jobs, no undeclared direct Agent egress |
| F: SDK and product UI | Python wrappers for submit/observe, separate private administration and reports, approval/registration/recovery UX | Browser walkthrough from intake through real approved action to private result, existing SDK regression tests |
| G: optional advice | Frozen ReviewView outbox, bounded fake worker, one accepted ReviewAdvice, final local envelope rebuild | Duplicate/wrong-scope/stale/malicious-result tests before any real cloud connector |
| H: release | Packaging, manifests, migration checks, documentation, integration tests and deployment validation | Explicit list of remaining assumptions and actual run evidence; user approval for destructive migration |

## Current code placement

2026-09-24 terminal-result follow-up: a signed final source can now be retained
through native executor/vault recovery and prepared privately under the current
session and deployment lease. See [coverage and remaining publication boundary](../verification/fused-final-result-v04.md).
This does not enable a result publisher or the official AgentDojo protection arm.

Current acceptance snapshot (batch 39, 2026-09-20): the native Linux private
approval client/listener and role-isolated HTTP receiver are implemented and
Linux library/regression tests have run. User-approved AWS native identity tests
confirmed a cross-UID executable-measurement blocker. Worker sandbox startup
bugs found in that run are fixed and regression-tested. A narrow root measurement
broker now implements cross-UID measurement; actual Linux container processes
pass positive and negative tests. Native systemd/ProtectProc and target-release
acceptance of this additional TCB component remain outstanding. No full product
deployment or hardware-authority acceptance passed.
The user has selected a new TPM signature suite. V3 P-256 signatures, strict
verification and a Linux TPM device adapter now exist and pass swtpm protocol
interoperability. Signed first-install enrollment, mandatory TPM PCR signing,
whole-head NV journals and an isolated service now connect to Linux runtime
Vault/Agent/G4/Connector anchors. Fresh TPM provisioning and externally signed
activation now have native adapters and software-TPM coverage. V2 deployment-record
migration, renewal and native hardware acceptance remain open; V2 signed formats are unchanged.
Batch 35 adds offline enrollment authoring plus Python-driven real Rust research
component experiments, not the missing native deployment or complete v0.4 loop.
Batch 36 connects fresh prepare/activate to the existing runtime state anchors;
it does not bypass the still-unimplemented legacy deployment transition.
Batch 37 adds independent V3 record encoding, an anchored native A/B journal and
two typed verification/commit evidence consumers. This is not the full deployment
ledger/transition migration or native installer/bootstrap completion. See
[the V3 record boundary](../verification/deployment-records-v3.md).
Batch 38 adds immutable native history archival, complete bounded replay of normal
ledger history, spent-identity detection and actual ledger-to-evidence binding.
It does not yet connect the full installer/watchdog/bootstrap execution path.
Batch 39 adds actual descriptor-relative Linux staging measurement, all six typed
plan/digest checks and external transaction authorization against V3 history,
combined in a read-only native preparation API. Fixed-root tmpfs checks pass;
actual installation/service activation still does not. See
[the staging/preparation boundary](../verification/linux-staging-v3.md).
See [the current TPM authority contract](../verification/tpm-authority-v3.md).
This is **not a completed consumer product**. Authenticated private intake and
session recovery, trusted approval-page routing, exclusive publication and the
broader private-loop compiler remain open, as do real systemd/isolation/hardware
authority acceptance. The historical batch notes below are chronological, not
claims that every earlier limitation still applies. Current approval deployment
details are in [the Linux contract](../verification/kernel-approval-linux-v04.md),
[the private receiver boundary](../verification/private-approval-ui-v04.md) and
[the AWS acceptance plan](../verification/aws-linux-v04.md).

`crates/savana-continuation-core` is an additive Rust kernel library. Stage A/B
primitives are deliberately not production RPCs or effect/disclosure capabilities.
They do not activate a root, replace G1–G7 or grant an executor ticket. The second
batch adds an encrypted-owner storage wrapper; dispatch/publisher integration
remains a separate acceptance gate.

The finite semantics must come from a reviewed, root-bound compiler/adapter in the
trusted host, never from the candidate certificate. An abstract command alphabet
requires a coverage proof for real command/argument classes, including unsupported
inputs. A finite table alone does not prove real-world subject or data coverage.
The state classifier is private; model/proof outputs must not be exposed publicly
unless separately authorized. All inference checking is deterministic strict mode
in this first backend. Progress and authority are separate properties.

## First batch status (2026-09-18)

- Implemented the finite A-stage backend: total model validation, paired closure,
  concrete counterexamples, independent certificates, finite renderer search and
  exact labeled quotienting. Full AST compilation/behavioral-summary generation
  and K6 are still pending; this is not completion of all R0/R1 obligations.
- Implemented B-stage ledger transitions and observation pin/freeze/snapshot
  primitives. They are not yet in the production durable owner or SDK. There is
  no new executable dispatch or declassification capability.
- Added 31 focused tests, including 864 finite transition systems checked against
  an independent greatest-fixed-point oracle. All pass locally. Focused formatting
  and warning-denying Clippy checks pass. Existing policy-core baseline: 232 unit
  tests passed. The frozen V2 file check passes; production files are unchanged.
- Linux CI added for the new crate. **Not yet run on Linux**: this host is macOS,
  and the installed Docker client has no running daemon. Native isolation,
  systemd, hardware-key and anti-rollback acceptance remain unverified.
- Google Cloud / DeepSeek configuration is a disabled JSON placeholder, with
  no endpoint, no project, no credentials, no download or outbound inference call.
- Existing Linux bootstrap documentation explicitly restricts filesystem keys to
  integration mode. Production needs its TPM/HSM/PKCS#11 and hardware monotonic
  anchor acceptance; changing the target OS does not waive that requirement.

Next integration gate: put the root-bound new state into the actual durable owner
and connect closed compiler/replacement interfaces without creating an unsigned
root or bypass of current G1–G7. Stages C–H are not completed by these unit tests.

## Second batch status (2026-09-19)

- Added a signed `ContinuationStorageProfileV04`, with purpose-separated signing,
  exact canonical encoding, independently selected issuer trust, installation/task/
  parent binding, contained validity and bounded domains/executions/slots. This
  is a storage profile, **not** a new execution/disclosure root or model RPC.
- Integrated the stable ledger and pin/freeze records into `DurableG4StateV2`.
  Updates reuse its encrypted snapshot, lock, atomic replacement, anchor and
  uncertain-commit poisoning. Batches update charges and observations together.
  Exact replays do not recharge or advance the anchor. Replacing an installed
  profile with a different one is rejected, not treated as a fresh ledger.
- Reopen reconstructs consumption from original reservations and verifies exact
  observation commitments. Expiry, task revocation and changed task authority
  block new transitions; original history remains available only to private host
  audit/recovery code. A caller must still authenticate any reader.
- Existing state stays schema 4 until explicit signed profile installation,
  which upgrades it to schema 5 in the anchored transaction. Older binaries must
  reject schema 5; there is no automatic downgrade, clearing or reset. No live
  installation was migrated. Repository source fingerprints are deliberately
  refreshed for changed core files and the new transitive dependency only; this
  is **not** a signed production release or deployment authorization.
- Storage tests cover real encrypted files, original-ID replay, invalid batches,
  precommit failure, anchor failures both before and after advancement, poisoned
  handles, restart, old-file rollback, schema compatibility and malformed state.
  The independent anchor used in these tests is a test implementation, not TPM
  evidence. Native Linux service/hardware acceptance remains outstanding.
- Main kernel compilation succeeds locally. Final full policy regression:
  **243 passed**, including 11 new continuation-owner tests. The finite-core suite
  has **34 passing tests**. Exact validation commands/results and known lint blockers are recorded
  in [storage verification](../verification/continuation-storage-v04.md).

Still incomplete: atomic coupling to real G7/executor effects, original late
responses across both durable owners, restricted compiler/residual construction,
K1–K6 replacement, exclusive publisher/InferenceSpec, SDK/UI, and the durable
review outbox/fake worker. Existing cloud JSON remains disabled and does not count
as implementation of the review queue. Stage C is partial; stages D–H are not
complete. No production RPC or strict-mode activation is exposed by this batch.

## Third batch: real G7 accounting integration (2026-09-19)

- Added a separately signed `ContinuationDispatchPolicyV04` that binds the existing
  storage profile, task, source/namespace, expected resource issuer, time limits
  and a complete domain-by-domain cost function. It imposes additional limits;
  it cannot expand the existing V2 task contract or replace approval/G1–G7.
- Resource facts bind the whole exact action digest, policy, stable identity and
  validity. The owner verifies the signature using its stored policy key inside
  guarded G7 preparation. Costs come from closed signed rules (fixed per execution
  or checked magnitude multiplication), never Agent-provided debit amounts.
- The normal `prepare_task_bound_tool_dispatch` path now commits stable debit,
  original task accounting, original quota and journal entry together. For an
  enrolled task, missing/invalid resource evidence fails the original entry point
  too. All domains are charged atomically, and the exact ticket/envelope/approval/
  task transition are bound to the original reservation.
- Enrollment requires an unused task with no previous journal entries or ledger
  records. It is idempotent only for the exact same policy. No silent upgrade over
  past effects, policy replacement, clearing or refund API is provided.
- Schema 4/5 keep their meaning; explicit dispatch enrollment upgrades to schema
  6. Reopen checks a bijection between stable reservations, signed facts and
  original G7 entries. Original replay does not contact the issuer or charge again.
  Unknown, success and proven-no-effect reconciliation do not reset stable usage.
- Added 15 focused G7 tests, alongside the previous 11 storage tests. They cover
  actual encrypted-owner preparation and returned kernel handoffs, not a live
  provider call. See [dispatch verification](../verification/continuation-dispatch-v04.md)
  for exact guarantees, trust assumptions and checks.
- Local validation: all **258 policy tests passed**, including all 26 continuation
  storage/dispatch tests; main kernel compilation, targeted formatting, diff
  whitespace and frozen-source checks passed. Policy-library Clippy reports the
  same three pre-existing warnings; it is not claimed warning-free.

Still not enabled as a deployed v0.4 product: concrete stable-identity adapter and
issuer provisioning, host/SDK admission and fact transport, dynamic-root compiler,
residual contracts, K1–K6 replacement, fixed publisher/InferenceSpec, UI, queue/fake
worker, native Linux hardware/sandbox acceptance. Enrolled tasks explicitly reject
the legacy final-release path until publisher integration is complete. This is
additional G7 accounting, **not** a certificate of full privacy or strict inference.
Google Cloud/DeepSeek remain disabled placeholders; no live data was migrated.

## Fourth batch: first-party stable resource source (2026-09-19)

- Added a signed, bounded source policy and five private owner APIs for source
  registration, object creation, optimistic edit/delete, private read and exact
  action-bound evidence issuance. IDs are owner-generated, immutable and never
  reused; labels are not selectors. This is not an arbitrary MCP/filesystem adapter.
- Integrated the catalog into the existing encrypted and anchored G4 owner.
  Explicit source registration upgrades to schema 7. Empty catalogs preserve old
  schema 4/5/6 encodings; registration cannot reinterpret an existing dispatch
  policy. Exact reinstall is a no-op; policy changes are refused.
- G7 new preparation rechecks the live object revision and target-bound selector
  under the debit transaction. Updating/deleting after issuance invalidates the
  pending fact without debit. Refreshed facts do not replenish per-resource limits.
  Original execution replay retains its identity and debit after edit/delete and
  encrypted restart, using historical admission facts rather than fresh content.
- Added 15 focused tests, including exact selector hashing against both existing
  business codecs, lifecycle bounds, source pinning, stale/forged signed facts,
  encrypted restart, precommit and uncertain-anchor failures. Verification scope
  and private interfaces: [managed resources](../verification/managed-resources-v04.md).
- Local regression: **273 policy-core library tests** and **34 continuation-core
  tests** passed. Kernel compilation, targeted formatting and frozen-source checks
  passed; library Clippy retains three pre-existing warnings. This is macOS-hosted
  Rust validation, not native Linux acceptance.

Still incomplete: external source identity adapters, host/SDK and target-platform
issuer provisioning, actual provider effect/version coupling, dynamic-root
compiler, residual replacement, exclusive publisher/InferenceSpec, SDK/UI and
review queue. This batch does not turn source-admin mutations into Agent tools,
authorize dynamic resources by itself, or establish Linux hardware acceptance.
No deployment reset/migration, cloud calls, commit or push occurred.

## Fifth batch: immutable G7 input snapshots (2026-09-19)

- New managed-resource G7 admissions copy the actual object revision/label/bytes
  and bind them to original nonce, request binding, source/dispatch policy and
  action digest. Pins, facts, stable debit, task/quota and original journal commit
  together. Source edits/deletes and execution outcomes do not replace the pin.
- Added a private read-only `managed_execution_snapshot_v04` API with exact
  task/nonce/core lookup. It grants neither execution nor external disclosure;
  current G3 and effect gates remain mandatory for any future outbound bridge.
- Payload schema 8 records a boundary between legacy unpinned executions and the
  new fully pinned suffix. Legacy replay never captures present-day bytes as old
  input. Snapshot-required reads of old history fail instead. No live migration
  or reset was performed; existing source-only schema 7 stays unchanged.
- Added 15 tests for input stability, restart/replay, both uncertain-anchor cuts,
  precommit/quota failures, corruption/substitution, legacy-prefix compatibility,
  revocation/outcomes, bounds and old-file rollback. Details and limitations:
  [execution snapshots](../verification/execution-input-snapshots-v04.md).
- Local validation: **288 policy-core library tests** and **34 continuation-core
  tests** passed; main kernel compilation, targeted formatting and frozen-source
  checks passed. Library Clippy retains the same three pre-existing warnings.
  No native Linux or live executor/provider acceptance run was performed.

This completes owner-side retention of original managed inputs, not the concrete
execd/provider bridge. Cross-owner recovery, executable version semantics,
compiler/replacement, exclusive publisher, SDK/UI and Linux hardware acceptance
remain outstanding. Cloud/model placeholders stay disabled.

## Sixth batch: exact managed-input pre-seal guard (2026-09-19)

- Added a closed, signed `Utf8PayloadV1` source projection. The default remains
  private audit/retention only. New projection policies use owner schema 9;
  absence preserves old signed encodings and existing schema behavior.
- Added `check_managed_execution_handoff_v04` in the existing kernel tool-send
  path after G3 and G7, before HPKE/signature/dispatch. It checks current authority,
  original prepared journal and pin, canonical action content, exact payload,
  source target/locator, and the original preseal commitment including G3 node.
  Rejection after G7 does not refund usage or erase the original dispatch record.
- Kernel and execd now share the existing presealed digest algorithm; fixed golden
  vectors preserve the wire commitment. No new snapshot sidecar, unsigned raw
  attachment, generic file path or public endpoint was added. Existing executor
  signature, HPKE, route/credential, worker and effect checks remain mandatory.
- Added nine durable handoff tests and one protocol golden-vector test. The
  durable fixtures exercise the original encrypted owner/G7 path with test issuer
  keys and a fixed G3 test digest; they do not claim a live provider execution.
  [Detailed boundary and failure semantics](../verification/managed-handoff-v04.md).
- Local regression: policy-core **297/297**, kernel **304/304**, executor
  **53/53**, continuation core **34/34** passed. Kernel/executor socket tests needed permission outside the
  restricted sandbox; all traffic was test-local. Protocol library: **61/64**
  passed, including the new golden vector; three existing browser DOM tests
  failed because Homebrew Node could not load `libsimdjson.30.dylib`. This machine
  dependency was not modified. These are macOS-hosted checks, not Linux acceptance.
- Kernel/executor compilation, focused formatting, whitespace and frozen-source
  fingerprint checks passed. Policy library Clippy retains the same three
  pre-existing warnings (argument count, enum size, manual range pattern).

Still incomplete: production chat intake does not provision managed issuers or
attach managed resource facts automatically. The new guard is a mandatory sender
check for enrolled managed work, not completion of that host admission pipeline.
Concrete provider/recovery semantics, compiler/replacement, exclusive publisher,
SDK/UI and native Linux acceptance remain outstanding. Cloud/DeepSeek remain
disabled; no live state reset, deployment, commit or push occurred.

## Seventh batch: production fact binding and optional Linux issuer (2026-09-19)

- The existing authenticated kerneld tool path now calls
  `bind_managed_dispatch_input_v04` after G3/control endorsements and before G7.
  For enrolled managed work it resolves the source from signed stored policy,
  checks exact immutable selector/current bytes/projection/target, and signs the
  current fact with the deployment-selected resource issuer. No request supplies
  its own trusted issuer, source revision or fact signature.
- Binding is read-only. G7 rechecks the revision in the existing debit transaction.
  A committed execution's retry skips new issuance/source lookup and preserves
  the original snapshot/nonce/consumption; G7 and pre-seal gates remain mandatory.
  Ordinary unenrolled tasks preserve their existing route. External-source
  continuation adapters are not silently replaced with this first-party issuer.
- Linux startup accepts an optional manifest-bound issuer configuration and a
  fixed native credential. Missing/extra/mismatched or reused role key material
  fails closed; no task/envelope key fallback or key generation exists. Added an
  uninstalled systemd opt-in drop-in. Enabling the option on macOS is refused;
  existing macOS defaults are unchanged. Hardware signing is not established.
- Added 11 admission tests and two issuer-constructor tests. Local regression:
  policy-core **308/308**, kerneld **306/306** passed; the strengthened same-content
  rename/refresh test also passed on the subsequent targeted run. Kernel build,
  focused formatting and frozen-source checks passed. Policy Clippy has the same
  three existing warnings. No native Linux service run was performed; CI gained
  an issuer-constructor test step. [Exact scope/configuration](../verification/managed-admission-v04.md).

Remaining: authenticated resource import/admin and task enrollment UI, trusted
private request construction (not automatic source injection into model context),
concrete provider effects/recovery, compiler/residual replacement, exclusive
publisher, SDK/UI and native Linux acceptance. No live credentials, deployment,
state reset, cloud invocation, commit or push were performed.

## Eighth batch: signed private administration and atomic enrollment (2026-09-19)

- Added the closed `ManagedAdminCommandV04` and a verified-proof constructor.
  Commands bind installation, owner store, request ID, time window and exact
  operation bytes. The trusted host selects the current administrator key;
  commands cannot select their own trust. Nested source/storage/dispatch policies
  retain their separate purpose signatures and current-root checks.
- Added `apply_managed_admin_v04` for registration, create, revision-checked
  edit/delete, and atomic storage-plus-dispatch enrollment under an existing
  root. The result and mutation commit together in encrypted anchored state.
  No task root, execution grant, model access or publication is issued.
- Schema 10 adds a bounded private retry journal. Exact replay returns the old
  receipt/object ID after lost responses or restart; changed contents/issuer
  cannot reuse the ID. Capacity exhaustion fails new changes without eviction.
  Expired new operations fail; expired committed replay is historical observation
  only, including after deletion/revocation. Re-enrollment never resets actual
  G7 usage. No live schema migration/reset was performed.
- Added 15 tests covering signatures, role separation, encoding/size/namespace,
  atomicity, source/root requirements, replay, real G7 consumption, capacity,
  corrupt links and both uncertain-anchor recovery cuts. Local full regression:
  policy-core **323**, kerneld **306**, continuation core **34** passed. Focused
  management tests also cover the later metadata-only receipt-link validation.
  Policy library Clippy retains only the same three existing warnings.
  [Private management API and boundaries](../verification/managed-admin-v04.md).

This batch implements the owner-side management backend, not its transport or UI.
Deployment-selected administrator trust/authentication, browser/Python management
entry points, trusted private payload construction, provider recovery, residual
replacement/compiler, exclusive publisher and native Linux acceptance remain.
No model endpoint, cloud invocation, live deployment, commit or push was added.

## Ninth batch: isolated Linux operator transport and Python submission (2026-09-19)

- Added an opt-in root-only Unix socket, independent admin public-key trust in the
  signed bootstrap, strict descriptor/path/permission checks, and a bounded worker.
  No admin private key enters kerneld or Agent. Unsupported macOS opt-in fails.
- Added a private command variant to the existing state-owner queue rather than
  a second G4 database/owner. Root-peer admission precedes framing; the same owner
  thread verifies the pinned signature and calls the atomic admin transaction.
  The 50 Agent/Ingress operation tags are unchanged.
- Added absolute I/O deadlines, one-request/EOF framing, generic uncertain-result
  handling, redacted receipts, and fixed-path Rust/Python operator wrappers. SDK
  reply validation binds request, command digest and operation result. No signing
  helper, automatic ID regeneration or hidden retry was introduced.
- Added optional systemd artifacts, but did not install/enable them, provision
  keys, re-sign deployment manifests, alter live state, or start services.
- Verified: kerneld library 311 tests; Rust client all-target suite; 3 Python
  wrapper/native-extension tests; Linux-target Rust client compilation. Clippy
  succeeds with 9 existing kerneld warnings, no new warnings from these modules.
  The Mac Python extension was linked with dynamic Python symbol lookup for local
  tests. Kerneld cross-compilation stopped in existing `ring` C compilation because
  the host lacks a Linux C compiler/sysroot; native Linux CI checks were added but
  were not executed here. None of this is native systemd/deployment acceptance.

Remaining: a reviewed key provisioning/signing workflow and ordinary-user source
management/approval UI (do not run a chat/web process as root to use this API),
private payload construction, concrete provider effects/recovery, residual
replacement/compiler, exclusive publication, and native Linux deployment tests.
Google Cloud/DeepSeek remain disabled placeholders. No commit or push performed.

## Tenth batch: fused-planning protocol/compiler staging (2026-09-20)

- Added the agreed [fusion plan](fused-planning-v04.md), closed review/advice/plan
  schemas, optional advisor, public-cut envelope reconstruction, one accepted
  result per job, bounded exact retransmission and no arbitrary advice forwarding.
- Added signed task-bound registration and durable outbox/result state in the
  existing encrypted/anchored owner (schema 11). A reservation commits before a
  private view is returned for release checking; uncertain commits return no view.
  Added private recovery status and Rust/Python operator enrollment via the
  existing signed command transport, without adding a model-facing endpoint.
- Added local registered-order compilation and a V2 lowering adapter that rechecks
  current envelope/action/tool/slot/bounds. New JSON proposal variants are explicit;
  they do not silently reinterpret the legacy CBOR planner wire protocol.
- Added restricted started-prefix-preserving replacement in the pure core, with a
  useful reorder example and an individually-valid-but-invalid-switch counterexample.
  This does not complete arbitrary private-loop/residual compilation or BC/K6.
- New-mode enrollment blocks legacy planning, cached-ticket commit, G7 effects and
  final release until their fusion adapters exist. No silent fallback. Production
  replacement after actual G7 work is also refused instead of losing obligations.
- Local tests: continuation core 48 (14 new), policy library 335 (12 new), kernel
  library 312 (1 new), operator client focused tests 2; kernel/client/Python-extension compilation passed. Core
  Clippy with warnings denied passed; policy Clippy retains 3 pre-existing policy
  warnings plus 3 dependency warnings. Offline fake-worker example ran without
  network or effects. The restricted-sandbox full kernel run first failed socket
  tests (267 passed / 45 failed); an approved temporary-local-socket rerun outside
  that sandbox passed all 312. Repository source fingerprints were explicitly
  updated and all 245 entries checked; this is not a signed deployment release.
  Native Linux acceptance has not been performed.

This is still **not the complete product**. The current chat path is not switched
to fusion. Full egress mediation, worker/scheduler wiring, exact operation-to-G7
binding, dynamic private-loop compilation, real residual migration and consumer
UI remain. Details and private API boundaries:
[fused planning verification](../verification/fused-planning-v04.md).
No cloud deployment, live-state migration, commit or push was performed.

## Eleventh batch: exact G7 binding and guarded model exchange (2026-09-20)

- Added optional complete signed per-operation execution commitments to the
  planning profile. They bind actual G4 material and task action content, not a
  model's operation name. Current task/pre-state gates remain mandatory.
- G7 now atomically retains the activated operation, original intent and execution
  nonce together with existing accounting. Schema 12 checks journal/intent/task
  links on restore. Empty execution bindings still refuse fused business effects.
- Restricted replacement now works in the actual durable owner after reservation:
  preserve the exact started prefix, continue settling late old outcomes at their
  original nonce, and require authenticated completion for dependent new work.
  Unknown/no-effect cannot remint the same registered operation.
- Added explicit fixed-view release approval (default false), a new exact-model
  G3 transition/purpose, and a private exchange helper. Reservation commits before
  any transport call. Both decoded view text and full wire bytes pass the model
  leak gate; legacy planner rules cannot authorize the new transition.
- The helper sends only frozen bytes, checks current root/recipient/time, accepts
  bounded job/view-bound replies, and has no implicit retries or raw-error output
  to models. Cloud transport is a disabled placeholder. Active deployment-rule
  serialization, bounded network adapter and public scheduler remain host work.
- Added 16 tests: ten real-owner G7/commitment/replacement/recovery tests, five
  model-exchange tests, and one exact-model G3 regression. Full policy suite:
  **351 passed**; continuation core: **48 passed**; kernel serial suite:
  **312 passed**. Initial parallel kernel run passed 310 and failed two due to a
  process-global fixture-lock timeout and consequent lock poisoning; no safety
  check was weakened, and serial rerun passed. Rust client/Python-extension check
  passed. Policy Clippy succeeds with the same three pre-existing policy warnings
  plus three dependency warnings. All 246 source fingerprints checked.

This is not complete product enablement. Ordinary chat/session planning and final
release remain blocked for fused tasks. Still needed: trusted host construction
and approval of local commitments, compiler/session/SDK/UI wiring, exclusive
service-level egress, public scheduler, general private discovery/loop/residual
compiler, final feedback publication, provider recovery and native Linux service,
isolation/hardware-anchor acceptance. No cloud call, live migration, service
deployment, commit or push. See
[execution and egress verification](../verification/fused-execution-and-egress-v04.md).

## Twelfth batch: durable public delivery slots (2026-09-20)

- Added optional signed nonoverlapping Advisor/Planner delivery windows. Schema
  13 stores the cursor and consumed slot IDs alongside the original protocol
  counters; restore checks both representations agree. Legacy encodings remain
  unchanged when no schedule is present.
- Added a private scheduled exchange helper. Missed windows are durably skipped,
  due reservation/freeze commits precede I/O, and retries require a later signed
  slot regardless of the last response. Scheduled profiles refuse manual reserve
  and freeze paths. The helper retains G3 and original frozen-byte validation.
- Each exchange now supplies a deadline capped at the public slot, view and
  disclosure expiries and five seconds. Enforcing this during I/O remains the
  trusted adapter's responsibility; only the disabled adapter and test workers
  exist. No cloud connection was enabled.
- Added a kernel current-policy lease: check installation/manifest/generation,
  revalidate signed rules against current roots, and serialize bounded handoff
  callbacks with deployment publication. This primitive is tested separately,
  not yet connected to a production scheduler/transport.
- Seven added real-owner scheduling/recovery tests and three policy-lifecycle
  tests pass. See [detailed boundary](../verification/fused-scheduling-v04.md).
- Full regression: policy library **358 passed**, kernel library **315 passed**
  (serial local-socket run), continuation core **48 passed**. The final focused
  fused rerun passed all **37** tests. Kernel/client/Python-extension compilation
  passed; all **246** repository source fingerprints checked. These are local
  Mac-hosted checks, not native Linux deployment or hardware acceptance.

Still not complete product enablement: no daemon timer or exclusive output
publisher, no complete private compiler/session/SDK/UI flow, no final feedback
publisher, and no native Linux/hardware-anchor acceptance. At-most-once time
windows do not prove fixed total publication or absence/timing noninterference.
No deployment, live-state reset, cloud call, commit or push was performed.

## Thirteenth batch: running owner scheduler and operator preparation (2026-09-20)

- Connected the production V2 server lifecycle to private clock ticks through
  the same bounded state-owner queue. One task/possible handoff per turn; no
  model-facing tick operation or catch-up bursts. Only enrolled profiles act.
- Connected current deployment locking to real session/input provenance and the
  G3 exchange helper. The host checks task/principal/run/manifest and caps expiry
  by session, input and signing authority. The production worker pool stays empty
  as requested; absent workers only skip elapsed slots, never fake model success.
- Connected accepted replies to private durable activation. Added recovery of
  accepted-but-not-activated candidates, without needing another model slot or
  request. A rejected candidate does not prevent later scheduled deliveries.
- Added offline Rust-backed `managed_admin.prepare_artifact` to Python: canonical
  bytes and signing digests for five closed artifact kinds, redacted objects,
  no key loading and no submission. Existing signed submission stays Linux-only.
- Fixed ordinary Python-extension builds on macOS with the supported PyO3 build
  linker setup. The initial plain build failed unresolved Python symbols; after
  the build-script fix the ordinary build and real native Python tests pass.
- Final local regression: **360 policy tests**, **321 kernel tests** (serial),
  **48 continuation-core tests**, **4 Rust operator SDK tests**, **5 native Python
  operator tests** pass. Focused policy fusion tests: **39**. Clippy completed
  with existing warnings; no new warnings in the added host/preparation code.
  All **249** source fingerprints pass after explicit baseline update.
- Linux x86_64 target checks pass for policy core and Rust client. Full kerneld
  target checking is blocked in the `ring` C build by missing
  `x86_64-linux-gnu-gcc`. Docker Desktop is installed but its daemon is not running.
  This is not Linux execution, systemd/sandbox or hardware-anchor acceptance.

The request to finish **all non-placeholder parts is not yet satisfied**. The
trusted candidate-to-session/execution compiler/value binding, exclusive final
publication/clarification, general private-loop/residual compiler and consumer
UI/business SDK path remain incomplete. No safety guard was removed to hide those
gaps. See [current host boundary](../verification/fused-host-v04.md). No cloud
call, deployment/state reset, commit or push was performed.

## Fourteenth batch: checked frozen-action dispatch bridge (2026-09-20)

- Added a read-only durable-owner binder which selects the next active operation
  from an already frozen G4 intent and exact signed execution material. Task,
  installation, manifest, generation, root and current pre-state are checked;
  the model does not choose a selector or a new value mapping.
- Preflight and G7 now share new-work checks for active revision, exact order,
  material, duplicate intent and completed dependencies. Preflight does not
  reserve consumption. A replacement between preflight and commit invalidates
  the stale selector even if both plans have the same order.
- Recovery selects an original dispatch's original revision/operation and exact
  action content. It neither refreshes the old pre-state nor remints the nonce.
  This remains true after encrypted reopen and prefix-preserving replacement.
- Connected the binder to the daemon's real tool-dispatch construction before
  managed input binding. All earlier fused-session legacy guards remain closed.
  The new helper is not a model, Agent, HTTP or Python interface.
- Added six tests using real encrypted owner/G7 fixtures; all 45 focused fusion
  tests pass, including poisoned-owner and changed replay-content checks.
- Final regression: **366 policy tests** and **321 serial kernel tests** pass.
  The sandboxed kernel run initially failed local socket permissions; the
  permitted local-socket rerun passed. Kernel/client/Python-extension checking,
  Linux policy/client cross-target checks and Clippy pass (existing warnings).
  All **249** refreshed source fingerprints verify; no signed release was made.

This completes the **frozen-action selection/binding component**, not the whole
candidate-to-execution product path. Trusted construction of approved G4 work,
private orchestration, exclusive publication/clarification, the general residual
compiler and consumer workflow remain incomplete. Cloud/DeepSeek stay disabled;
there was no live deployment, state reset, commit or push. See
[the exact implemented boundary](../verification/fused-host-v04.md).

## Fifteenth batch: private active-candidate/G4 draft compiler (2026-09-20)

- Added a durable read of the active compilation snapshot, with root/revocation,
  profile lifetime and clock-floor checks. A newer unactivated candidate is not
  selected; encrypted reopen preserves the exact activation.
- Added registry-pair lowering without fabricating public tool handles, using
  the same finite adapter as the old planner-view lowering.
- Added a private read-only kernel compiler. Current deployment locking, actual
  session/root/role, signed limits and owned values/provenance precede lowering.
  It refuses missing/extra/aliased slots, foreign/expired values and wrong scope.
- Extracted the existing real G4 preparation into one shared implementation used
  by both legacy proposals and local compilation. No validation was dropped.
  Drafts contain actual business requests, task matches, projections, execution
  bytes and exact commitments; no public handles, persistent intents or grants.
- Logical operation/request identities survive reordering. A real-value regression
  revealed that embedded task relation and approval display commitments need not
  survive recompile. Old synthetic material fixtures did not establish that claim.
  We retain these checks and explicitly mark automatic approval reuse unresolved.
- Six kernel compiler tests plus two policy adapter/active-snapshot tests were
  added. The private compiler is not yet invoked by a production workflow or
  exposed as a client endpoint. Input registration, approval preparation and
  private execution orchestration remain to be connected.
- Final regression: **368 policy tests**, **327 serial kernel tests**, **47
  focused policy fusion tests** and **6 real-G4 compiler tests** pass. Checks
  for kernel/client/Python and Linux policy/client targets pass; Clippy retains
  existing warnings. All **250** source fingerprints verify. No Linux native
  deployment or hardware acceptance is claimed.

Cloud placeholders, deployment and user state are unchanged. No commit or push.
See [precise compiler and replacement boundary](../verification/fused-host-v04.md).

## Sixteenth batch: checked stable recipe evidence (2026-09-20)

- Added draft-only `FusedExecutionRecipeV04`, separately domain-tagged from exact
  execution commitments. Construction requires neutral owned-slot witnesses that
  reproduce every exact task-linked G4 argument; raw hashes/model JSON cannot
  manufacture the typed evidence.
- Recipes retain root/deployment, logical identity, complete source/slot metadata,
  descriptor/registry/retry/executor/tokens, destination, display implementation
  and complete business action. They separate plan/pre-state-dependent context
  and rendered current display from recipe equality, without changing G4 material.
- The real private compiler emits recipe evidence. A second exact-draft check
  prevents old evidence being transplanted onto a same-recipe recompile.
- Real G4 reorder and identical-plaintext/new-source regressions complement
  static context/mutation/slot-field tests. Matching task content alone is not an
  operation identity; logical step and projected request identity remain bound.
- Existing exact signatures and G6/G7 behavior are unchanged. This batch does
  **not** enable automatic approval reuse. Versioned signed recipe admission,
  pre-enrollment preparation, durable local input registration and private
  execution orchestration are still required. No new RPC, cloud call, deployment,
  state reset, commit or push.
- Validation: **371 policy tests**, **329 serial kernel tests**, eight focused
  real-G4 compiler tests, kernel/client/Python checks, Linux policy/client target
  checks, Clippy (existing warnings), and **251** source fingerprints pass.
  No native Linux runtime or hardware acceptance is claimed.

See [recipe boundary and tests](../verification/fused-host-v04.md).

## Seventeenth batch: signed recipe admission and recovery (2026-09-20)

- Added separately domain-signed `FusedRecipeApprovalV04`: fixed recipe schema,
  task/root/profile/installation/manifest/generation/lifetime and full ordered
  operation-to-recipe map. Legacy exact approval profiles cannot be reinterpreted.
- Added `ApprovePlanningRecipes` to the existing root-only private admin path.
  Admission and its exact historical receipt commit together, under schema 14;
  no profile/root rewrite, renewal, consumption reset or new execution occurs.
- Encrypted restore checks state/receipt/profile links. Tests cover stale/revoked
  roots, invalid signatures, wrong scopes, clock rollback, immutable replacement,
  expired exact retry, uncertain commits, snapshot rollback and schedule coexistence.
- The real local compiler reports a separate recipe-approval match under the
  current deployment lease. Reorder retains it; new sources, wrong generation
  and expiry do not. Existing exact G6/G7 requirements remain unchanged, with a
  regression proving recipe approval alone cannot dispatch before/after reopen.
- Rust/Python private offline preparation gains the `recipe_approval` artifact
  kind, and the SDK checks the new receipt against the exact submitted artifact.
  It does not load keys, sign, submit, or expose a consumer/Agent approval endpoint.
- Still pending: authenticated persistent input binding, private signing/intake
  workflow, live G7 recipe-evidence binding, private execution orchestration and
  exclusive publication. Cloud placeholders and live deployment remain untouched.
- Validation: **380 policy tests**, **330 serial kernel tests**, **5 Rust admin
  SDK tests**, **6 native-extension Python tests**, Linux policy/client target
  checks and Clippy (existing warnings) pass. All **252** source fingerprints
  verify. This does not claim native Linux deployment/hardware acceptance.

See [admission semantics](../verification/managed-admin-v04.md) and
[host boundaries](../verification/fused-host-v04.md). No commit or push.

## Eighteenth batch: live G7 recipe evidence and atomic recovery (2026-09-20)

- Added an in-process typed recipe witness to task dispatch authorization. Both
  selector preflight and G7 verify the exact current G4/content, canonical active
  plan/operation identity, signed recipe, root, generation, expiry and dependencies.
  Legacy exact commitments remain unchanged; recipe hashes alone cannot dispatch.
- Kept G5/G6 and all task/quota/connector checks. A recipe approval cannot replace
  a current G6 settlement, and execution lifetime cannot exceed approval lifetime.
- Added schema-15 atomic receipt links to the existing encrypted owner snapshot.
  Reopen cross-checks the original signed allowlist, intent, task binding and nonce;
  it reuses the owner's authenticated admission assertion, not a deserialized live
  source witness. Replays preserve original identity and consumption after reorder
  or uncertain anchor commits. No reset or renewal operation was introduced.
- Added six transaction/recovery regressions with nonempty stored values, including
  late old outcomes and dependency gating. Unknown retains reservations; verified
  no-effect uses existing V2 accounting, retaining attempts while releasing magnitude.
- The private end-to-end orchestrator, persistent authenticated input registration,
  signing/intake UI, exclusive publication and native Linux/provider acceptance
  remain outstanding. No cloud call, deployment, state reset, commit or push.
- Validation: **386 policy tests**, **330 serial kernel tests**, kernel/client/
  Python compilation, Linux policy/client cross-target checks, Clippy (existing
  warnings) and **252** refreshed source fingerprints pass. This is Mac-hosted
  verification, not native Linux deployment or provider acceptance.

See [G7 verification and remaining boundaries](../verification/fused-host-v04.md).

## Nineteenth batch: immutable local inputs and stable recovery (2026-09-20)

- Added schema-16, immutable input pinning inside the encrypted owner: exact policy
  slots, stable IDs, original canonical bytes/provenance, profile/root/run/manifest/
  generation and capture time. Pinning precedes recipe approval/effects, allows only
  exact live retries, and preserves the existing task ledger and rollback protection.
- Added private host intake/recovery helpers under the current deployment lease.
  Intake uses real G4 and already-owned values; raw provenance JSON is not trusted
  ingress. Recovery requires an existing authenticated current session of the same
  durable run, not a newly manufactured session or root.
- Split process-local handle authorization from stable internal value identity.
  Fresh process handles recover the original recipe without accepting old handles,
  substituting newly imported values, or renewing any lifetime. Capacity failure is
  all-or-nothing; same-process restore retries reuse the new handles.
- The compiler and G7 check fixed inputs independently. G7 refuses even a signed
  recipe for a different pinned source and caps dispatch lifetime by input expiry.
- Added five durable/G7 and three real-compiler/value-owner regressions. They do
  not claim full production session restart or provider/UI integration. Consumer
  intake/session recovery, execution orchestration and exclusive publication remain
  outstanding. Cloud placeholders, deployment, git commit and push are untouched.
- Validation: **391 policy tests**, **333 serial kernel tests**, kernel/client/
  Python compilation and Linux policy/client cross-target checks pass. Clippy
  completes with existing warnings; **253** source fingerprints verify. No native
  Linux runtime or hardware acceptance is claimed.

See [input trust/recovery boundary](../verification/fused-host-v04.md).

## Twentieth batch: private action creation and G5/G6 orchestration (2026-09-20)

- Added owner-selected next-action creation under the current deployment lease.
  It requires fixed inputs and a matching signed recipe, supplies no model-chosen
  step/arguments, and creates/replays the actual durable G4 intent through the same
  committer as legacy proposals. No new persistence schema or public RPC is needed.
- Added private G5/G6 helpers sharing existing resolution, ontology/validator,
  signed display envelope and exact settlement/content verification. Approval
  lifetime is capped by input/session/recipe/deployment limits. Borrowing leased
  rules avoids reacquiring the publication lock inside G5.
- Added an internal route marker; legacy Agent evaluation, authorization and
  dispatch reject fused action handles/tickets. Active revision/next operation,
  root/pre-state, recipe and input lifetime are rechecked before private stages.
- Six new tests cover G4/G5 retries, lost volatile mappings, Allow/Deny, live
  context refusal, old-plan invalidation, G6 signed content checks and legacy
  entry rejection. They do not simulate a provider effect or full session restart.
- Still pending: private G7/execd sending/reconciliation, authenticated session and
  approval recovery, exclusive publication and consumer UI/driver wiring. The new
  helpers have no live consumer/daemon entry yet. No cloud call, deployment,
  state reset, commit or push.
- Validation: **391 policy tests**, **339 serial kernel tests**, kernel/client/
  Python compilation, Linux policy/client target checks and Clippy (existing
  warnings) pass. All **254** source fingerprints verify. No native Linux runtime,
  approval-device or real provider acceptance is claimed.

See [private action boundary](../verification/fused-host-v04.md).

## Twenty-first batch: private G7 dispatch and result reconciliation (2026-09-20)

- Connected the private action to the existing G7/execd sealed-envelope path.
  Ticket selection and recipe proof come from the host's frozen action, not the
  model. Current G3, activation/root/pre-state, G5/G6, connector and quota checks
  remain mandatory; execution lifetime is capped by private action/deployment limits.
- Isolated legacy/public dispatch and every status selector before cache return.
  Cached execution IDs pin manifest, deployment generation and effect fence.
  A lost response retains the original identity and does not trigger another send.
- Added private result reconciliation through the existing signed task outcome
  and vault commit. Query witnesses must match the queried nonce/core/subject,
  deployment context, digest and expected signing key. Lost cleanup ack preserves
  the already committed result.
- Kept private transient Unknown distinct from V2 terminal Indeterminate: retain
  the original reservation, allow query-only reconciliation of late success, and
  never refund/retry merely because the outcome is unknown. No-effect settlement
  obeys the root retry policy and never resets attempt consumption.
- Eight new regressions use isolated test directories. Six run authenticated local
  execd, real envelope crypto/journaling and a test connector; two cover fail-closed
  preflight. They include late success after revocation/recipe expiry, lost response/
  ack, foreign nonce/key/digest, no-effect policy and legacy cache/status isolation.
- Still pending: production driver/consumer entry, complete session/approval/
  execution mapping recovery, exclusive publication and UI. A post-G7/pre-mapping
  crash remains fail-closed, not an implemented recovery UX. No native Linux runtime
  acceptance, real provider, cloud deployment, state reset, git commit or push.
- Validation: **359 serial kernel tests with `test-support`**, **391 policy tests**,
  kernel/client/Python compilation and Linux policy/client cross-target checks pass.
  Clippy completes with existing warnings and all **254** source fingerprints verify.

See [private dispatch boundary](../verification/fused-host-v04.md).

## Twenty-second batch: historical execution/result recovery (2026-09-20)

- Added schema 17 original result scope to the same G7 transaction as the exact
  execution and budget reservation. Principal/lifetime are checked against the
  original root; replay cannot rewrite scope and older records are not backfilled.
- Added authenticated-owner historical projections and private query-handle
  restoration with no surviving session, intent, approval or ticket. This is
  query-only recovery, not re-login, new authorization or provider retransmission.
- Bound private result provenance to stable G4/G7 identity instead of an ephemeral
  handle. After actual vault commit and signed outcome settlement, an immutable
  result reference is persisted before acknowledging executor cleanup.
- Added result-specific vault restoration with exact task/run/principal/commit/
  expiry/Live-state checks. A new service boot rotates local capabilities without
  replacing result bytes/provenance or extending retention. Result replay remains
  byte-exact and old segment tokens are invalidated.
- Added four owner tests, two vault tests and three kernel integration tests
  (including multiple fault cuts). Owner/vault reopen tests use mock rollback
  anchors; kernel tests clear volatile authority records and use a local test
  connector. They are not native Linux multi-service reboot/hardware acceptance.
- Still pending: consumer intake/login and unstarted approval recovery, production
  recovery/cleanup-ack driver, exclusive publication, general private loop expansion
  and UI. Cloud placeholders and installed services are untouched. No commit/push.
- Updated deployment listener inventory for the optional managed administration
  socket and added a regression checking root-only access and opt-in activation.
- Validation: **362 kernel library tests with `test-support`**, **395 policy tests**,
  **10 vault tests**, and **5 deployment-unit tests** pass. Native kernel/client/
  Python compilation and Linux policy/client/vault cross-target checks pass;
  Clippy completes with existing warnings. All **255** source fingerprints verify.
- The complete `savana-kerneld --features test-support` test command also passes,
  including the 4,096-request replay-capacity boundary, policy lifecycle, crash,
  concurrency, end-to-end and documentation tests (451 tests across its targets).

See [historical recovery boundary](../verification/fused-host-v04.md).

## Twenty-third batch: production historical recovery scheduling (2026-09-20)

- Wired the existing serialized daemon-owner timer to alternate planning and
  historical execution recovery. Inventory comes from authenticated durable G7
  records, not live sessions, models or caller-provided handles. Legacy records
  without original result scopes are excluded rather than backfilled.
- Added bounded round-robin polling with one recovery pipeline per second and a
  shared five-second network deadline. Deployment publication is pinned across
  the handoff; changed installation/manifest/generation/fence is never retargeted.
- Added exact cleanup retry after result checkpoint, including lost response
  recovery. Verify the original signed receipt and recompute the vault commit
  before acknowledgement; never fetch plaintext or send a provider effect here.
  Volatile cleanup caching avoids repeat IPC and is safely rebuilt after restart.
- Keep an existing private handle's result reference current before cleanup, so
  it can recover from vault after the executor discards its copy. Job-local
  failures retain reservations; poisoned storage remains fatal.
- Added two owner inventory tests and six kernel tests (seven executor scenarios
  plus planning-turn scheduling). These use local test services and simulated
  volatile loss, not a native Linux multi-service reboot or hardware acceptance.
- Pending: consumer intake, unstarted action/session/approval recovery, production
  new-action driving, exclusive publication/UI, general private loops and native
  deployment acceptance. Cross-deployment recovery and permanently unresolved job
  handling remain conservative, not automatic migration or no-effect inference.
  Cloud placeholders, installed services and user state are untouched. No commit/push.
- Validation: **368 kernel library tests** pass both serially and in the final
  parallel run; **397 policy tests** and **5 deployment-unit tests** pass. Fixed
  an existing oversized-frame test's expected peer-close race without relaxing
  its frame-rejection assertion. Native kernel/client/Python checks and Linux
  policy/client/vault cross-target checks pass. Clippy completes with existing
  warnings; all **256** source fingerprints verify. This batch did not rerun the
  entire multi-target kernel integration suite reported in batch 22.

See [production recovery boundary](../verification/fused-host-v04.md).

## Twenty-fourth batch: production private new-action scheduling (2026-09-20)

- Extended the owner timer to rotate recovery, planning and new-action phases.
  New-action selection uses live authenticated sessions and current durable root/
  plan state, never caller-selected operation IDs. Tasks advance serially only
  after previous execution result checkpoints or signed no-effect settlements.
- Reused pinned-input restoration, exact recipe checks and private G4–G7 helpers.
  Denial/NeedsApproval stays private and cannot dispatch; an exact signed G6
  settlement permits the original action to resume. No consumer approval UI or
  receipt delivery route is created by this internal scheduler.
- Added live fence validation inside the G7 publication lease, including a test
  changing the fence after evaluation but before send. Reread owner time between
  phases; expired recipes/root/approval and backwards time cannot grant execution.
- Added eight tests, including six authenticated local executor scenarios: normal
  automatic execution, post-G7 pre-send failure, lost dispatch response, fence
  change, exact signed-approval resume and expired signed approval. Other cases
  cover repeated pending/denied actions and authority/time limits. The phase test
  also checks that absent vault prevents new work without starving planning.
- Remaining: consumer intake and authenticated session recovery, durable pending
  approval recovery/delivery, exclusive publication/UI, broader private loops and
  native Linux isolation/hardware/provider acceptance. Per-task serial polling is
  conservative, not a completion guarantee or a general parallel scheduler.
  Cloud placeholders, installed services and user state are untouched. No commit/push.

See [new-action driver boundary](../verification/fused-host-v04.md).

Validation: **376 kernel library tests** pass with `test-support`; native
kernel/client/Python compilation and Linux policy/client/vault cross-target checks
pass. Clippy completes with warnings and **257** source fingerprints verify.
The complete Linux kerneld cross-target check was attempted but is blocked by
`ring`'s C build dependency: this Mac lacks `x86_64-linux-gnu-gcc`. It is not a
successful full Linux build or native runtime acceptance. The full multi-target
integration suite and unchanged policy/vault test suites were not rerun this batch.

## Twenty-fifth batch: private pending-approval durability (2026-09-20)

- Agent recovery schema 4 retains original signed action/display envelopes and
  verified G6 settlements, indexed by stable G4 identity, inside the existing
  encrypted rollback-anchored owner. Older snapshots remain readable without
  inventing approval history; writing populated archives as schema 2/3 is denied.
- Persist pending material before exposing it, and settlement before consumed
  state/ticket. Persistence failures poison the owner. Restore signatures and
  canonical structure, then require a live authenticated session and exact
  current root/plan/content, G5 and display-declassification checks before fresh
  private handle binding. Reverify saved settlement signatures/content/time with
  current G6 keys. Denial/expiry cannot turn into another approval opportunity.
- Tests exercise real encrypted owner reopen before/after settlement and reject
  authentic pre-settlement rollback. Additional cases cover approved/denied
  continuation, stale capabilities, changed keys/plan/root, expiry, archive
  corruption/duplicates and failed pending/settlement writes. The fixtures
  explicitly do not restore login sessions or send provider effects.
- Still outstanding: consumer intake/authenticated session recovery, trusted
  approval transport/UI, exclusive publication, broader private loops and native
  Linux isolation/hardware/provider acceptance. Cloud placeholders, installed
  services, credentials and user data are untouched. No commit/push/deployment.

See [private approval recovery boundary](../verification/fused-host-v04.md).

Validation: **383 kernel library tests** (seven new recovery tests) and **5
deployment-unit tests** pass. Native kernel/client/Python compilation and Linux
policy/client/vault cross-target checks pass; **258** source fingerprints verify.
Clippy completes with existing warnings, and the two new range-pattern warnings
were corrected. The unchanged policy/vault suites and the full multi-target
integration suite were not rerun. Native Linux deployment and complete Linux
kerneld cross-compilation remain unverified; batch 24's missing C cross-toolchain
blocker has not been resolved by this approval-recovery change.

## Twenty-sixth batch: durable approval receiver pairing (2026-09-20)

- Before adding private approval transport, closed a receiver-side recovery gap:
  approval state schema 5 binds each paired approval to its exact display envelope
  and delivery role. Registration/restart cannot replace a signed display nonce
  or reset an existing signed decision. Pair insertion is atomic even if its
  second insert fails. Display lifetime cannot outlast the signed approval.
- Cached browser registrations now revalidate both signatures/pairing/time and
  durable owner health rather than treating a payload digest as authority. The
  ordinary UI-authentication cache received the same check; ApprovalDisplay is
  rejected by that generic route and must use paired registration.
- Schema 4 migration only recovers an unambiguous existing signed pairing under
  the closed role/purpose mapping. Ambiguous or malformed old pairs fail closed;
  no state reset, new challenge, settlement or credential is invented.
- Ten new tests cover immutable pair/restart behavior, capacity/nonce-failure
  atomicity, interval limits, legacy migration, corrupted pair links, signed
  approve/deny preservation, encrypted owner/UI reopen, old handles, cache-hit
  forgery/expiry, standalone-display rejection and poisoned storage.
- Private Kerneld-to-Approvald transport is still outstanding. Existing Agent/
  Ingress endpoints cannot be used by impersonation. Next work needs a distinct
  deployment-bound edge, Linux socket/peer/key configuration, private polling and
  trusted user routing. Authenticated session recovery, exclusive publication,
  broader loops and native Linux acceptance also remain open. Cloud placeholders,
  installed services and user data are unchanged; no commit/push/deployment.

Validation: all approval package tests pass (**25 library tests plus four other
test cases**), as do **383 kernel library tests** and native kernel/client/Python
compilation. Clippy for the approval library completes with existing warnings.
All **259** source fingerprints and `git diff --check` pass.
This is Mac-hosted verification, not Linux service, real hardware enrollment or
an end-to-end fused approval UI acceptance run. Unchanged policy/vault suites and
full Linux kerneld compilation were not rerun.

See [approval receiver boundary](../verification/fused-host-v04.md).

## Twenty-seventh batch: private kernel approval protocol and driver (2026-09-20)

- Added the deployment-bound `KernelApproval` role (8), canonical requests and
  responses for health/registration/query, the fixed-path SuiteOne client and
  server dispatch. No Agent/Ingress credential reuse and no enrollment/admin/UI
  authentication operations on the new edge.
- Receiver accepts only ToolExecution with exact task/action binding. Handles
  and durable pairings retain the delivery role across encrypted reopen. Legacy
  schema 4 tool pairs remain Agent-owned; migration does not upgrade their role.
- Private action driver can deliver its original archived approval and query the
  resulting handle. Signed approve/deny goes through existing G6 checks and
  durable receipt retention. Time is checked between transport stages. Pending,
  service failure and expired replies do not grant tickets or change challenges.
  The next action turn, not the delivery helper, performs any G7 dispatch.
- Actual encrypted UDS tests uncovered an existing invalid-query error mapping:
  an ApprovalBindingMismatch was not legal for the query response schema, causing
  stream closure. Query failures now map into their closed error vocabulary.
- Native bootstrap/client installation, Linux listener/socket/key/peer setup
  and trusted user routing remain unfinished. Production defaults to no client
  and keeps fused approvals pending. No end-to-end consumer approval claim, no
  cloud provider activation, no deployment, reset, commit or push.

Validation: **389 kernel library tests**, **28 approval library tests plus four
other approval test cases**, and **65 protocol library tests** pass. Native
kernel/client/Python compilation, all **260** frozen fingerprints and
`git diff --check` pass. Approval-library Clippy completes with existing
dependency warnings. The protocol suite initially hit a broken system Node
dynamic-library dependency; rerunning with the already bundled Node runtime
passed without modifying system packages. An existing unpublished-listener test
also raced a peer close on macOS: it now accepts NotConnected only for the final
half-close, preserving its zero-response/zero-dispatch assertions; the final
complete kernel run passed. No Linux-native or real hardware acceptance was run.
See [private approval edge boundary](../verification/fused-host-v04.md).

## Twenty-eighth batch: Linux private approval startup (2026-09-20)

- Added optional, manifest-bound `kernel_approval` bootstrap blocks to Kerneld
  and Approvald. Kerneld loads only a fixed dedicated credential, checks key IDs
  and purpose separation, creates the verified KernelApproval edge and installs
  the client in the private policy owner. Stray credentials without configuration
  fail startup; no config/credential retains the previous closed behavior.
- Approvald accepts the extra systemd descriptor only when configured. It checks
  exact descriptor names/count, socket path/ownership/mode, the non-root Kerneld
  GID, client key ID and separation, then runs the existing native peer measurement
  and SuiteOne checks on a dedicated bounded listener/worker pool. macOS rejects
  this Linux-only configuration instead of silently using a development route.
- Added opt-in socket and service drop-ins plus tmpfiles role-directory ownership.
  This avoids relying on SocketUser/SocketGroup to set parent directories, which
  they do not do. No global group expansion, user-data reset or credential reuse.
- Added tests for key alias/mismatch/zero, closed bootstrap fields, opt-in unit
  shape, role directory ownership and explicit independent encrypted credentials.
  Linux CI now includes the approval transport/startup and kernel delivery tests.
- Consumer intake/approval routing, authenticated session recovery and exclusive
  publication remain open. Systemd credentials are still an integration adapter;
  the real TPM/HSM/rollback authority acceptance gate has not been bypassed.

Mac-hosted checks: 391 kernel library tests, 31 approval library tests plus four
other approval cases, and six deployment-unit tests pass. Native kernel/client/
Python compilation passes. Linux native Kerneld/Approvald compilation and all
390 kernel / 31 approval library tests pass on aarch64 with Rust 1.82.0. These
checks used an offline container, read-only source/registry mounts, no host ports,
no capabilities and an unprivileged user with a dedicated supplementary test
group. Initial root/no-supplementary-group runs exposed test-runner prerequisites;
they were corrected without weakening production identity checks. An existing
unpublished-listener test now accepts Linux's connection-reset close as well as
EOF while retaining its zero-response/zero-dispatch assertions. Mac sandbox
socket denial required rerunning local socket tests outside the sandbox.
The complete Linux test commands for `savana-approvald`, `savana-policy-core`,
`savana-vault`, `savana-client`, `savana-continuation-core` and
`savana-private-workflow` also pass, including their integration/doc tests.
The frozen-source check verifies all 265 entries; `git diff --check` passes.
Docker Desktop was started only for isolated Linux verification; no existing
Savana deployment, private state or enrollment was changed. No commit or push.

See [Linux private approval startup](../verification/kernel-approval-linux-v04.md).

## Twenty-ninth batch: private approval receiver and AWS preparation (2026-09-20)

- Added an Approval-only private landing page and same-origin POST receiver.
  KernelApproval transfers cannot be consumed by the legacy public-role route;
  public-role transfers cannot enter this receiver. Valid transfers establish
  pre-authentication only: hardware authentication, display validation and a
  separate explicit decision remain mandatory. No approval or ticket is minted
  by presenting a transfer.
- Recheck the durable authentication/approval pair and expiry before accepting a
  private transfer. Reopen invalidates old volatile transfers; a new transfer
  requires re-registration of the original signed pair. This is not recovery of
  an already authenticated browser session. Invalid private handoffs share one
  bounded HTTP response; this does not establish timing indistinguishability.
- Fixed approval rendering removing its own status node. Approve/deny outcomes
  now remain visible, stale pre-authentication state is removed, and a mismatched
  or unknown decision response is an error rather than a false success/denial.
- Added a read-only AWS inventory checker with explicit account/region/profile/
  instance binding and an operation allowlist. Its offline tests cover missing
  and mismatched inventory and prohibit write operations. Passing prerequisites
  never reports hardware authority, rollback protection or production acceptance
  as verified. No AWS API call, resource creation, private-data upload or cloud
  model activation was performed. Target profile/region/instance (or a creation
  budget) still need user selection.
- Trusted delivery of the kernel handoff into the authenticated consumer session
  is still missing. The private receiver is not a complete consumer approval
  flow. Intake/recovery, exclusive publication, the broader private-loop compiler
  and real Linux service/hardware acceptance remain open. Existing fail-closed
  authority and publication gates remain intact.

Validation: on macOS, 391 kernel library tests, 36 approval library tests plus
four other approval cases, and 66 protocol library tests pass. Native Agent,
Ingress and Python binding compilation passes. Linux offline unprivileged
container runs pass all 390 kernel and 36 approval library tests. Five AWS
checker tests pass without credentials or network. These are code regressions,
not real AWS/systemd/TPM or user-browser acceptance. No deployment, reset,
commit or push was performed.

## Thirtieth batch: approved AWS native identity acceptance (2026-09-20)

- With explicit source-transfer approval and an approximately USD 10 budget,
  tested only the identity module and synthetic fixtures on an isolated AWS
  x86_64 host. No credentials, personal data or old kernel state were uploaded.
  TPM 2.0 and Secure Boot were verified in the guest, not merely in inventory.
- Real debug/release peer measurement accepts same-UID connections, but rejects
  cross-UID connections with `Io`, both normally and under key production unit
  restrictions. Independent probes show `/proc/PID/exe` permission denial and
  `ProtectProc=invisible` hiding the peer. This is an open deployment blocker;
  same-UID library tests did not cover it. Identity checks were not weakened.
- Native worker tests exposed an early `RLIMIT_NOFILE=4` causing `EMFILE` during
  Landlock construction, then a missing executable grant for the ELF interpreter.
  Apply the final FD limit after temporary setup descriptors close, before worker
  execution; grant execute only to the verified fixed root-owned glibc loader,
  not a runtime directory. Keep other resource limits and sandbox denials intact.
- Final identity-module suites pass **21 tests on AWS x86_64 / Rust 1.98** and
  **21 on offline ARM Linux / Rust 1.82**, including sandbox startup, final FD
  limits, file denial, network denial and unrelated direct-execution denial.
  Native identity matrix tests remain diagnostic and explicitly report that
  production acceptance is not established. Linux CI now runs the wrapper suite.
- Added 13 previously uncovered production identity manifest/source files to
  the frozen inventory (278 total). No consumer flow, platform signer/rollback
  adapter, or general compiler completion is implied. No commit or push.

Detailed evidence and cloud retention/cleanup limits are recorded in
[AWS native acceptance](../verification/aws-linux-v04.md). The synthetic host
and its attached disk were destroyed after testing; no old deployment was reset.

## Thirty-first batch: honest experiment preparation (2026-09-20)

- Added a standard-library Python experiment package under `experiments/`:
  result validation, exact scheduled-trial/manifest binding, separate utility /
  attack-goal / security-effect oracles, unknown-result bounds, task-cluster
  bootstrap and exact paired-arm comparisons. Missing runs, silent retries,
  incomplete safety traces and all-refusal strategies cannot inflate the joint
  safe-and-successful metric. Input manifests are researcher provenance, not
  runtime or hardware attestation.
- A V2 SDK component helper calls the actual ingress, task authorization and
  agent-loop methods with private intent and explicit callbacks, closes sessions,
  and preserves cancellation. Its fixture tests are not live SDK acceptance; it
  does not provide the missing general private v0.4 consumer/model path.
- Added an offline Python entry point to 21 existing Rust security regressions.
  Each test must resolve uniquely and run exactly once; zero/ignored tests do
  not pass. Useful replacement, cross-version prefix failure, frozen advice,
  stable consumption and recovery remain component evidence, not LLM trials.
- Recorded AgentDojo as the primary injection/utility benchmark, tau2 as the
  multi-turn complement, and a disabled model matrix from small Qwen3.5 models
  to DeepSeek V4.1 Flash plus an unresolved JEV entry. No model, provider or
  benchmark tool-execution adapter was activated. Full AgentDojo/tau2 integration
  is not implemented in this batch.
- Full-product experiment admission stays blocked. Cross-UID peer measurement,
  the sealed signer/anchor, private intake/recovery, consumer approval delivery,
  exclusive publication and broader loop compilation remain unfinished. This
  batch does not fix those architecture gaps or weaken any production gate.

Validation: 28 Python tests and 21 exact Rust regression selections pass on the
local macOS host. The 278-entry frozen-source check and whitespace check pass.
These are not fresh Linux/hardware acceptance or model success/safety results.
No AWS resources, cloud calls, model downloads, deployment changes, commit or
push. The execution plan and limitations are documented in
[the experiment guide](../../experiments/README.zh-CN.md).

## Thirty-second batch: native Linux cross-UID measurement (2026-09-20)

- Added a fixed-path, root-only identity broker rather than combining daemon
  UIDs or adding ptrace capability to ordinary services. Its startup verifies
  exact SYS_PTRACE-only effective/permitted/bounding capabilities, empty
  ambient/inheritable sets and no-new-privileges. A root-installed directional
  allowlist binds caller and peer UID, primary GID and executable SHA-256. Root
  administration peers require an explicit pinned edge, not a root wildcard.
- Requests transfer an already-connected Unix socket FD, not a caller-selected
  PID/path/hash. The broker measures real SO_PEERCRED identities. Both requester
  and broker use SO_PEERPIDFD to pin the actual socket peer and reject exit/PID
  reuse; older kernels lacking this Linux 6.5+ facility fail closed. The client
  verifies returned credentials and hashes the returned immutable executable FD.
- Added bounded strict policy parsing, descriptor cleanup/CLOEXEC, absolute frame
  deadlines, nonblocking broker connect, executable-size limits, no fallback on
  denial/unavailability, separate systemd units and an opt-in client group drop-in.
  This is an explicit privileged TCB addition, not hardware signing or rollback
  authority. Existing role/signature/permission checks remain necessary.
- Native ARM Linux/Rust 1.82 tests pass 32 identity/sandbox cases. A separate
  no-network disposable-container harness passes seven real-process cases:
  broker absent, permitted distinct UIDs, wrong caller hash, wrong peer hash,
  unlisted caller UID, pinned root administrator, and no fallback after shutdown.
  The broker runs with the production capability set even inside that harness.
  The harness is not systemd namespace or full-product acceptance.
- Six deployment-unit tests and 28 Python experiment tests pass. Frozen inventory
  expands to 283 entries covering the new production source and units. Native
  Clippy could not run because that offline Linux toolchain lacks the component;
  compilation/tests are not described as a successful Clippy run.
- The final Linux kernel library regression passes all 390 tests after the
  socket-bound pidfd change; the Python extension also compiles offline on macOS.
  A dedicated CI job now builds and runs the cross-UID container harness without
  host installation or network access during execution. Remote CI has not run.

No native signer/monotonic adapter, authenticated private consumer intake,
approval delivery into that session, exclusive publication or general private
loop completion is claimed. The next hardware signing implementation requires
the user's selection between a new TPM-compatible suite with V2 compatibility
and an external Ed25519 hardware service. No cloud provisioning, paid inference,
state reset, commit or push was performed. See
[the broker boundary and acceptance contract](../verification/linux-identity-broker-v2.md).

## Thirty-third batch: additive TPM signing suite (2026-09-20)

- Implemented the selected TPM route as a separately versioned deployment
  signature suite. V2 Ed25519 types, wire formats and verifiers are unchanged;
  there is no automatic algorithm negotiation or fallback.
- V3 binds installation, epoch, purpose, TPM-bound key ID and payload digest.
  The 176-byte envelope has strict lengths/tags and low-S P1363 signatures.
  All thirteen deployment purpose tags are pairwise separated in regression.
- Public-object validation requires the exact non-exportable sign-only P-256
  template. The native Linux adapter opens only the kernel resource-manager
  device, checks trusted public/Name/qualified-Name pins before each signature,
  verifies the result independently, zeroizes authorization buffers and poisons
  an instance after ambiguous failure. It has no key creation/clear/export or NV
  commands, generic public transport or simulator fallback.
- Real swtpm commands exposed TPM_RC_RETRY handling absent from the first unit
  fixtures. Only that exact no-command-started response now permits at most five
  submissions. IO/auth/malformed responses do not retry. The final explicit
  simulator test passes three signatures, wrong authorization and wrong-key pin.
- Native ARM Linux identity/sandbox suite: 45 passed, one emulator case ignored
  in the normal run and separately executed successfully by the required harness.
  macOS library: 30 passed; V2 native-signing compatibility: five passed; scoped
  macOS Clippy passes. The attempted macOS all-target run hit four pre-existing
  launchd socket test permission errors in the tool sandbox, not counted as passes.
  The final Linux kernel library regression also passes all 390 tests.
  The Python extension compiles and the new CI workflow passes actionlint; no
  remote CI execution is claimed. Frozen production inventory is now 286 files.

The profile currently uses TPM password authorization, not PCR policy. It assumes
a trusted OS/device path and trusted externally provisioned binding; public blob
validation is not hardware attestation. Production V3 enrollment/trust selection,
deployment-record consumer migration, boot policy, signer service permissions and
monotonic NV crash/concurrency handling remain open. Old production authority
constructors still fail closed. The other private-session/publication/compiler
gaps and experiment gate remain unchanged. No AWS, real TPM enrollment/clear,
deployment/state reset, commit or push. See
[the exact protocol and acceptance boundary](../verification/tpm-signature-v3.md).

## Thirty-fourth batch: TPM runtime authority connection (2026-09-20)

- Added mandatory policy-only signing: static SHA256 PCRs including PCR7,
  PolicyCommandCode(Sign), PolicyPassword, fresh sessions and no password fallback.
  Actual swtpm commands verify normal signing, password-bypass denial and a PCR
  change between policy evaluation and Sign.
- Added externally signed, canonical, expiring enrollment with measured roles,
  pinned TPM public/qualified Name and five disjoint store slots. First-install
  only: profile renewal/epoch migration and old-state import remain blocked.
- Added whole-head NV_Extend anchoring with durable two-slot preparation and
  exclusive writer locks. Lost TPM replies recover the new head; old journal
  restore, same-sequence substitution, wrong namespace and exhaustion fail closed.
- Added a fixed-endpoint root TPM service and measured client with explicit
  deployment/kernel role separation, an active-enrollment NV guard and per-request
  PCR key-possession proof. Secrets remain in the authority's systemd credentials;
  raw-device access is not given to kerneld or the Python/model processes.
- Connected Linux startup to TPM-backed Vault, Agent-authority, G4 and Connector
  anchors; removed its file-MAC fallback. Old macOS/test behavior is retained.
  Also fixed kerneld credential loading for systemd's exact per-UID ACL or
  ownership-on-read-only-mount layouts, without allowing broad group/world access.
- Added systemd unit contracts, strict enrollment/role/frame/ACL tests and expanded
  the existing offline TPM emulator harness to NV commit/recovery.

Validation includes Linux kernel library **390 passed**, deployment-unit contracts
**7 passed**, unchanged V2 native-signing compatibility **5 passed**, macOS identity
library **39 passed**, scoped macOS Clippy and **28 Python experiment tests**.
Linux identity and explicit emulator final-run counts are recorded in the TPM
authority contract. Python extension compilation passed. Native hardware, systemd
service activation, first-install provisioning and full-product acceptance did not
run. No AWS resources/upload, real TPM mutation, old-state reset, commit or push.

This is still **not all production deployment paths connected**. V2 deployment
records, installer/watchdog and bootstrap trust constructors need an explicit V3
migration; the existing unsupported `run_apply` transition remains closed. The
new signer must not be shoehorned into an Ed25519 field or used as evidence that
the deployment gate passed. Enrollment renewal needs continuity guarantees before
it can be enabled. Experiment readiness stays false. See the
[current authority contract](../verification/tpm-authority-v3.md).

## Thirty-fifth batch: enrollment authoring and executable component experiments (2026-09-20)

- Added `savana-tpm-enroll`: bounded public JSON prepare → externally signed
  finalize → native-codec verify. No private key import, hardware activation,
  reset/migration field, command invocation or production-state access exists.
- Added the Rust `benchmark_driver` example around the existing private-workflow
  PlannerPort. It creates signed synthetic roots/facts, discovers new objects,
  executes only through that Rust component and records actual synthetic-provider
  requests. Encrypted state is reopened after each step against one retained
  volatile test anchor. This is not a production G1–G7 or power-loss/TPM run.
- Added Python `component-loop`: independent effect/closed-output oracles, separate
  attack-goal scoring, scripted adversarial controls, local-model JSON stdio port,
  bounded child lifetimes, immutable output directories, predeclared schedules,
  synced start/results records and source/binary/config provenance. Interrupted or
  incomplete runs cannot silently become successful complete datasets.
- Added CI build/wiring so real Rust loop tests are executed, not silently skipped.
  The full-product gate remains false. Specific local-model runtime adapters,
  reviewer-model matrix, AgentDojo/τ² adapters and cloud models have not run.

Validation: macOS identity library **43 passed**; Linux identity library
**54 passed, 1 explicitly ignored emulator test**. The emulator was not rerun in
this batch. Python tests **44 passed** both locally and in an offline non-root
Linux container, including actual Rust child processes. Identity all-targets
Clippy and private-workflow example `--no-deps` Clippy pass. Dependency-wide
warning-denying Clippy for that example hits existing kernel-protocol warnings
(large enum/error variants and format-collect), not changed by this batch.
Frozen source inventory is updated to 299 entries, not signed release evidence.

Still open: V3 deployment semantic consumers/installer/watchdog and native
bootstrap, hardware provisioning/renewal/acceptance, authenticated intake/session
recovery, trusted approval routing, exclusive publication/reconnect and broader
private-loop compilation. No AWS/cloud operation, real TPM mutation, old-state
reset, deployment, commit or push was performed. See the
[enrollment boundary](../verification/tpm-enrollment-authoring-v3.md) and
[experiment guide](../../experiments/COMPONENT-LOOP.zh-CN.md).

## Thirty-sixth batch: native TPM first-install path (2026-09-20)

- Added root-only `savana-tpm-first-install prepare|activate` with fixed device,
  paths, objects, epoch 1 and GENESIS initial heads. All-slot vacancy and live PCR
  checks precede hardware mutation. Closed encrypted credential inputs and manual
  systemd units replace ad hoc object creation; no reset/renewal/clear operation.
- Activation authenticates the external installer, exact reserved proposal,
  unchanged initial state and fresh PCR-gated possession before pinning the guard.
  A lost reply is resolved by exact readback, not repeated extension. Runtime and
  provisioning hold the same exclusive guard lock. Partial prepare stops closed.
- Added public proposal inspection/finalization using the same canonical parser
  as runtime verification. Inspection grants no authority and exposes no secrets.
- Added fresh swtpm tests through real CreatePrimary/EvictControl/NV commands and
  existing runtime anchor advance/reopen. Occupied slots, wrong auth, expiry,
  changed enrollment and consumed heads reject; no synthetic acceptance fallback.

This closes first-install **implementation**, not native product bootstrap,
credential packaging/provenance review, renewal or hardware acceptance. Other
open gates remain V3 deployment semantic consumers/installer/watchdog, authenticated
intake/session recovery and approval routing, exclusive publication/reconnect,
broader private-loop compilation and native systemd/hardware validation. No AWS
resource/upload, real TPM mutation, deployment reset, cloud call, commit or push.
See [the exact first-install contract](../verification/tpm-first-install-v3.md).

Validation: Linux identity library **60 passed** plus **7 integration tests**;
both exact swtpm scenarios ran separately and passed (ordinary suite marks those
two ignored). macOS identity library **47 passed**, scoped all-targets Clippy
passed, Python experiment regression **44 passed** including real Rust children.
Frozen inventory **304 files** verifies; no hardware/systemd acceptance is inferred.

## Thirty-seventh batch: V3 record journal and two semantic consumers (2026-09-20)

- Added a distinct canonical V3 deployment envelope, binding enrollment,
  installation/epoch/store, purpose, sequence/previous head, generation,
  transaction, time and complete payload. V2 Ed25519 formats are unchanged.
- Added a fixed-path root-only Linux A/B record journal backed by the existing
  measured TPM authority. Durable preparation precedes head advancement;
  recovery distinguishes pending records from committed records and reuses the
  original bytes on exact resumption. Lost replies cannot reset or replay a head.
- Added typed verification evidence and commit attestation consumers, comparing
  all 28/16 digest fields against expected material plus roles, context and time.
  Commit binds its original verification evidence, next fence and same enrollment;
  two independently approved but different enrollments cannot be spliced.
- Added actual swtpm signing/NV/recovery coverage and a separate root-owned disk
  contract in disposable tmpfs, including nonblocking special-file rejection.
  First-install now also refuses old or new deployment-state directories.

The 13 purpose tags have a common cryptographic codec; **only two typed semantic
consumers** are added here. Their expected claims still require a trusted driver
and measurements. The two-slot journal is not a historical evidence archive.
Complete V3 ledger/transition/installer/watchdog/bootstrap migration remains open,
along with authenticated intake/session recovery and trusted approval routing,
exclusive publication/reconnect, broader loop compilation and native hardware/
systemd acceptance. Production constructors and full-product experiments remain
fail-closed. No AWS/cloud call, real TPM mutation, deployment/reset, commit or push.

Validation: macOS identity library **53 passed**; Linux identity library
**66 passed, 3 ignored in the ordinary suite**. All three special cases ran
separately and passed: two swtpm scenarios and one root tmpfs disk contract.
The full macOS policy-core library passes **402 tests**; the five new semantic
consumer tests also pass on Linux. V2 deployment
control/entrypoint/native-signing regression **37 passed**. Python experiment
suite **44 passed**, including real Rust subprocesses. Linux kerneld compilation
and scoped macOS identity Clippy pass; pre-existing kernel/execd dead-code
warnings remain. Policy-wide warning-denying Clippy is blocked by existing
`durable.rs` argument-count, `control_selection.rs` enum-size and `task_state.rs`
range-pattern findings, not reported as passing. Frozen inventory **307 files**
verifies. These are local/component results, not remote CI or hardware acceptance.

## Thirty-eighth batch: experimental deployment-history prerequisites (2026-09-20)

- Added V3 ledger payload decoding and normal/abort/rollback/failed-safe semantic
  checks. The existing V2 phase/fence/grant graph is reused without changing its
  signatures. All 29 high-water domains preserve sequence and key-epoch floors.
  Bootstrap bridge/epoch migration remains deliberately unsupported.
- Added complete bounded history replay from reviewed genesis to the exact live
  head, including intermediate signed records. Rollback-grant IDs are explicit
  and immutable within a transaction. Reused old transactions or reserved,
  burned and consumed rollback grants reject even after another transaction.
- Added immutable native archive publication before A/B slots and TPM advancement.
  Open/append authenticate all committed ancestry; missing old history cannot be
  reconstructed from two recent slots. Archive failure does not advance the TPM.
  History limits are 4096 records / 16 MiB; no GC/renewal/performance claim.
- Bound verification and commit claims to the actual Installed/Committed ledger
  records and their complete intervening ancestry. The combined history checker
  validates the normal commit chain. A native root reader uses the fixed TPM
  journal; these objects still cannot be cast into a kernel bootstrap permit.
- Python `regressions` now executes 28 exact Rust component cases, including these
  prerequisites. It does not convert their pass rate into model/security results.

Still open: trusted native deployment driver with measured staging and all
transaction/readiness obligations; installer/watchdog/bootstrap activation;
authenticated private intake/session and approval delivery; exclusive publication
and reconnect; broader private-loop compilation; real systemd/TPM and browser
acceptance. Full-product readiness remains false. Cloud models remain placeholders.
The requested broader AWS source-upload authorization has not been assumed:
previous consent covered only identity-module source and synthetic tests. No AWS
operation, source upload, hardware mutation, deployment/reset, commit or push was
performed in this batch.

Validation: macOS policy-core library **411 passed**, V2 deployment compatibility
**37 passed**, identity library **54 passed**. Linux identity library **67 passed**
with three special cases run separately: swtpm signing/PCR/NV, first-install and
runtime-history recovery, and root tmpfs archive/disk contracts all passed.
The **9** new ledger tests also passed on Linux, and Linux kerneld compilation
passed with existing dead-code warnings. Python exact component regressions
**28/28 passed**; experiment-tool tests **44 passed, none skipped**, using a rebuilt
real Rust benchmark driver. The frozen source inventory contains **308** files.
Identity all-targets Clippy passes. Policy library-only, no-dependencies Clippy
passes with the three previously documented lints explicitly excluded; this is
not a workspace-wide warning-free result. A dependency-inclusive check also found
existing protocol `format_collect` and `result_large_err` findings. None of these
local checks constitutes a full-product, live-model or hardware acceptance run.

## Thirty-ninth batch: native staging and V3 preparation binding (2026-09-20)

- Linux now reads a closed actual staging inventory through retained descriptors,
  hashes bounded payloads, checks exact root ownership/modes/link count/device and
  empty ACL/xattr profile, and rejects unknown files, aliases and special files.
  Revalidation rehashes bytes and poisons a changed lease; no signed digest is
  substituted for the actual filesystem measurement.
- The policy layer constructs the existing canonical staging tree and decodes
  all six real plan files, checking each domain-separated digest against the
  signed transaction. Selector and descriptor bytes are exact bindings too.
- Existing external Ed25519 transaction and rollback signatures now bind directly
  to the authenticated V3 ledger fields and four trust-root revisions, without
  fabricating a V2 ledger. Time/platform/reused-ID checks preserve history;
  Committed preparation additionally requires typed exact commit evidence.
- A combined native read-only preparation API reads the real TPM journal and
  rechecks complete history/head, staged bytes and expiration after measurements.
  It cannot sign, install, unfence or start services. The legacy apply path also
  requires actual Linux staging after its existing authority checks.
- Added non-root Linux filesystem/adversarial tests, signed six-plan integration
  tests and a separate fixed-root test restricted to disposable marked tmpfs.
  CI invokes the new tests; Python component regressions now select 30 exact cases.

Remaining delivery gates are not closed by this batch: native trust/TCB and
manifest/materialization closure, privileged installation/watchdog/bootstrap;
private intake/session and approval-page handoff; exclusive public publication
and reconnect; broader private-loop compilation; real systemd/hardware/browser
acceptance. No live state, credentials or deployment was removed or modified.
No cloud model, AWS resource, upload, commit or push was performed.

Validation: macOS policy library **413 passed**; deployment control, entrypoint,
native-signing and external-transaction integration **43 passed**. Linux deployment
library selection **36 passed**, including the three signed-staging tests; Linux
identity **71 passed, 4 ignored in the ordinary suite**. All four special cases
ran explicitly and passed: two software-TPM cases plus root journal and fixed
staging tmpfs contracts. Linux kerneld compilation passes with existing dead-code
warnings. Python component regressions **30/30 passed** and experiment-tool tests
**44 passed, none skipped**, with a rebuilt Rust driver. macOS identity all-targets
Clippy passes; policy lib-only/no-dependencies Clippy passes with the same three
documented pre-existing lint exclusions. Linux Clippy and remote CI are not claimed.
The **310-file** frozen inventory and whitespace checks pass. The combined native
preparation API compiles but has not run against a deployed measured TPM service;
its lower-level file, authorization, history and simulator components were tested
separately. Full product readiness remains false.

## Fortieth batch: signed release-to-staging closure (2026-09-21)

- Native V3 read-only preparation now requires canonical desired-manifest bytes
  and verifies release/component signatures with the authenticated release roots.
  The manifest must match the exact authorized transaction, measured platform
  binding, installation epoch and helper/watchdog identities. The complete
  bootstrap TCB digest must remain equal to the selected V3 ledger; normal
  preparation is not a bootstrap-replacement operation.
- All 35 file roles require one staged payload of the exact signed size and
  SHA-256. A valid partial staging tree no longer suffices for manifest-bound
  preparation. The fixed single-worker layout explicitly rejects manifests with
  additional unmaterialized parser/connector workers. This is content closure,
  not installed ACL/native-code/service-semantics verification.
- All 29 manifest versioned domains are compared to the anchored high-water
  vector: older sequences, same-sequence forks and older signer-key epochs fail,
  including an epoch regression combined with a sequence advance. The returned
  candidate vector does not mutate the ledger or consume a rollback grant.
- Revalidation rehashes the retained files and checks the anchored head, then
  samples time and re-verifies the retained manifest at that time. An expired
  transaction or release is not extended by retaining a verified Rust object.
  Large file rehashes precede the final clock sample, not follow it.
- Added cross-platform signed-manifest assertions for every missing/changed/size-
  mismatched payload and conflicts in every high-water domain. Linux additionally
  exercises all 35 actual staged files through the descriptor reader and rejects
  transaction substitution, invalid time windows, signature tampering and file
  mutation. Fixture artifacts now hash actual synthetic one-byte contents.
- Python component regressions select 31 exact Rust cases; CI explicitly runs
  the signed-manifest integration suite on Linux. These remain component tests,
  not model success/security-rate trials or production acceptance.

Validation: policy library **413 passed** on macOS, signed-manifest integration
**7 passed** on both macOS and Linux, V2 deployment compatibility **43 passed**,
Linux deployment-library selection **36 passed**. Python exact regressions
**31/31 passed**; Python experiment tests **44 passed, none skipped** with a rebuilt
Rust driver. Policy lib-only/no-dependencies Clippy passes with the same three
documented pre-existing exclusions. Linux kerneld compiles with existing dead-code
warnings. No remote CI or hardware acceptance is claimed.

**The requested full experimental endpoint has NOT been reached.** Remaining:
native installation/watchdog/bootstrap and real measurements; authenticated
private intake/session recovery; delivery of private approval handoffs to the
consumer browser; exclusive publication/reconnect; general private-loop
compilation; full Linux/systemd/TPM/browser acceptance. The combined native
preparation object itself is not yet exercised through an installed TPM-backed
deployment driver. The six readiness blockers remain and `preflight` exits 2.
Cloud-model integrations remain placeholders. No AWS provisioning, source upload,
live-state reset, hardware mutation, commit or push occurred. Expanded AWS upload
consent for full source/deployment/synthetic tests (about $10 cap) was requested;
the previous identity-module-only consent has not been silently broadened.

## Implementation batch 41 — selected-action compilation and dependent loop regression

The requested five product paths are **not all connected**. This batch changes
the runtime compiler, not the native installer or consumer authentication boundary.

- Admission/pinning still lowers and prepares the full registered plan. Runtime
  execution instead selects exactly the durable owner's next operation, after
  checking the complete plan shape, slot closure, pinned inputs and provenance.
  No external operation selector, shortened plan or alternate input is accepted.
- Previously, runtime compilation re-prepared completed steps. The authoritative
  approval display rejects a consumed clause's next attempt; consequently that
  historical step could block a different, still-authorized successor. A fresh
  G4 materialization is now made only for the next operation. G5/G6/G7, live
  deployment/root/expiry, exact recipes and dependency/budget checks stay intact.
- Added six native-library integration cases with two distinct destinations and
  two one-use clauses, the second requiring verified success of the first.
  Actual authenticated Unix IPC reaches the executor's effect gate/journal and
  vault checkpoint. Successful cases prove both effects occur exactly once and
  each clause consumes `(1, 1)`. They also assert the old full-plan compilation
  fails on the exhausted clause, exposing the regression rather than masking it.
- The additional cases cover execution-handle loss, reversed planner order,
  root revocation, waiting for second-step approval, and completion after an
  exact signed second-step settlement on the next owner tick. These cases
  advance the supplied clock through production pacing intervals without
  resetting scheduling cursors. Fixture sessions, approval signatures, rollback
  anchors and the provider are synthetic: this is not login recovery, browser
  approval, TPM acceptance or a general model-driven result-dependent loop.
- Python `regressions` now selects 37 exact Rust cases and explicitly enables
  `test-support` only for the six kerneld fixtures. Missing/ignored/zero-test
  matches still fail. Full-product preflight stays closed.

Remaining product wiring, unchanged by these tests:

| Path | Current boundary still missing |
| --- | --- |
| Native install/start | V3 privileged apply/watchdog/bootstrap with actual installed measurements and hardware acceptance; the old apply entry still returns unavailable. |
| Private session | Authenticated consumer intake and reauthentication/recovery into a live private session; a root admin command is not user authentication. |
| Approval handoff | Delivery of the kernel-only capability to that authenticated consumer; the approvald receiver alone is not an end-to-end browser path. |
| Publication/reconnect | Exclusive authenticated publication and reconnect route covering errors and recovery without a secret-dependent alternate channel. |
| General loop | Result-dependent local bindings and end-to-end enrollment/session/publication; registered, pre-pinned static-input sequences are only a subset. |

Validation: private-chain selection **73 passed** on both macOS and the isolated
Linux container; Python-driven exact Rust regressions **37/37 passed**; Python
experiment tests **45 passed, none skipped**, with the rebuilt real Rust component
driver supplied. The 310-file frozen inventory, touched-file formatting and
`git diff --check` pass. Full-product preflight still exits **2** with all six
readiness blockers. Existing Linux dead-code warnings remain; no clean remote CI
or native hardware acceptance is claimed.

No live deployment, state reset, cloud model, AWS upload/provisioning, commit or
push is performed by this batch. Component pass counts are not model safety or
success rates. Native Linux/systemd/TPM/browser acceptance remains outstanding.

## Implementation batch 42 — first private consumer admission and approval handoff

Source routes now connect an authenticated Ingress tab to a purpose-separated
private WebAuthn ceremony on approvald, then to once-only internal value/session
admission on the kernel owner clock. The signed binding includes task, durable
run, current root and kernel boot. No Agent run/value/tool handle is exported.
Login polling has bounded pacing and its own workflow turn, not a second network
pipeline within the action turn. Completed action and budget state are untouched.

The existing G5 delivery now attaches exact pending tool approvals to that
authenticated private session through KernelApproval. A dedicated browser
capability polls for the handoff and a deliberate button opens the separate
private approval page. Task/principal/root mismatch, unresolved-action replacement,
expired/revoked authentication and wrong service roles are rejected. Notification
and login do not cast an action vote: real display/decision and G6/G7 remain.

Legacy Agent login preparation/continuation, authentication consumption, session
claim, task/session status and cancellation are blocked for enrolled private tasks.
Existing public planner/action rejection is retained. New protocol and DOM tests,
P-256 signed synthetic WebAuthn/rollback-protected approval-owner tests, actual
encrypted Unix service transport, and kernel receipt/value-admission tests cover
these boundaries. Python regressions selects 45 exact Rust cases (eight new).

The new admission/restart test also exposed an old snapshot invariant that
mistook deliberately consumed input for corrupt storage. Restore now accepts a
material-free post-admission/terminal tombstone with its original task/run/root,
but rejects material-free Ready tasks and partial principal/run identity. Repeat
restart preserves that tombstone without restoring session or tool authority.
This prevents startup rejection; it does **not** implement authenticated resume.

The full workspace-member guard now explicitly includes the existing continuation
and private-workflow crates, while keeping the exact frozen-core list and unsafe
boundary checks. Deployment-unit tests separately enforce both manual-only TPM
first-install units (device confinement, no automatic start/restart, encrypted
credentials and activation write scope), rather than treating them as daemons.

This batch **does not complete all five requested product paths**. Installed
native startup, fresh private reauthentication after process loss, exclusive
publication/reconnect and general result-dependent loops remain. The first-login
and handoff paths have source/regression evidence, not a full installed
browser/hardware acceptance run. All six experiment readiness blockers remain.
See [precise routes, prerequisites and remaining limits](../verification/private-session-v04.md).
No cloud-model activation, live deployment reset, AWS upload/provisioning, commit
or push is performed.

Final targeted validation: Linux private-chain tests **75 passed**; Linux
approvald tests **39 passed** including encrypted service transport; macOS kernel
unit tests **399 passed**; deployment unit checks **7 passed**; Python-selected
exact Rust regressions **45/45 passed**; Python experiment tests **45 passed,
none skipped** with the existing Rust component driver. Protocol integration
tests including operation 57 and workspace boundaries pass. The 313-file frozen
inventory and touched-file formatting/diff checks pass. Full-product preflight
still exits **2** with six blockers, deliberately. These are synthetic/component
checks, not hardware acceptance, model evaluations, or production success rates.

## Implementation batch 43 — verified result-dependent private loop

Policy schema 2 declares finite predecessor-result slots. Recipe schema 2 signs
the profile, precise result edges and the immutable initial-input commitment;
it does not preapprove future G4–G7 actions. Result sources can populate only
the signed descriptor's text `body` payload, never resource/destination controls.
The local compiler skips unavailable future slots and prepares only the next
ready operation. The model wire format is unchanged and accepts no result data.

Verified tool bytes/provenance are checkpointed atomically in the encrypted owner
before executor cleanup. Rehydration uses a new strict UTF-8 G3 derivation that
preserves the private/untrusted label and source evidence. Historical validation
checks the original admission lifetime; restoration does not renew rights or
replace execution IDs. Terminal outputs without consumers keep their old path.
See [result-loop design, bounds and example](../verification/result-dependent-loop-v04.md).

Six integration tests inspect real synthetic-provider requests for two/three-step
dataflow, encrypted owner reopen, exact approval, revocation and Unknown. Five
additional focused tests cover dependency/slot closure, forged model fields,
initial-input/source-edge signing and strict provenance-preserving conversion.
The three-step test uses an explicitly authorized three-attempt fixture and
separate paced cleanup confirmations; no production quota or gate was relaxed.

Validation on 2026-09-21: macOS kernel library **405 passed**, policy library
**416 passed**, continuation suite **50 passed** (34 core + 16 planning).
Offline ARM Linux: result-loop integration **6 passed**, result-related policy
tests **5 passed**, planning **16 passed**. Python-selected exact Rust regressions
**56/56 passed**. Rebuilt Rust experiment driver plus Python tests **46 passed,
none skipped**. Workspace all-target compilation, touched-source formatting,
diff checks and the **313-file** frozen-source inventory passed.

The first regression run hit a broken Homebrew Node dynamic library, not a failed
browser assertion; the final run used the bundled working Node. Repeated Python
testing also exposed a process-group cleanup permission error on this host. The
driver now reaps its own direct child when possible and reports a stable failure,
never successful descendant cleanup; an explicit denial regression covers it.

These are component tests, not model trials or native deployment acceptance.
Preflight still exits 2 with the existing product gates: native cross-UID/TPM
acceptance, private reauthentication, installed browser handoff and exclusive
publication/reconnect remain, as does unrestricted dynamic discovery/branching.
The registered result-to-payload loop requested in this batch is implemented.
Cloud adapters stay disabled. No AWS action, reset, commit or push occurred.

## Scope constraints

- Preserve exact old execution IDs, original frozen bytes, privacy history and
  consumed rights across continuation changes; no refund-on-Unknown.
- A model/pLLM only proposes. Private user answers and missing answers cannot become
  public inputs just to remove them from the privacy model.
- Separate PUB proof reuse from protected-world indistinguishability. Do not
  invent a mixed-version counterexample incompatible with PUB premises.
- Failure to establish total publication is an admission failure, not permission
  to emit a secret-dependent error, absence, or fabricated `false`.
- An always-withheld transcript is not evidence of task completion. Keep private
  business correctness and one publicly realizable cooperative strategy in scope.
- No automated upload, cloud provisioning, deployment reset, commit or push is
  included in this first implementation batch.
