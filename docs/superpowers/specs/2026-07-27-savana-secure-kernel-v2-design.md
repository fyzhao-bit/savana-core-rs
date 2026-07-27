# Savana Secure Kernel V2

> Date: 2026-07-27
>
> Status: section-by-section design approved; written-spec review pending
>
> Scope: complete the product security boundary, not merely make dormant wire
> tags return success.

## 1. Authority and supersession

This document is the authoritative design for the production V2 boundary. It
supersedes the following older assumptions wherever they conflict:

- handles are bound to one authenticated client and peer identity, not to one
  transient UDS connection;
- one request and one response are processed per UDS connection;
- all user text, pasted content, files, and OCR output enter through a separate
  Rust ingress service rather than ordinary JARVIS code;
- plaintext tool arguments, tool results, and approved vault releases travel
  directly between the kernel and a separate executor, never through JARVIS;
- G1 and G2 are kernel-owned decisions, not Python orchestration;
- `DetectStrict` and `LeakGate` are mandatory internal checks rather than
  skippable authoritative public operations;
- production V2 has exactly seven Rust crates, not the older five-crate target;
- production policy and binary activation happens through a signed,
  restart-based deployment transaction, not a live public rollover operation;
- the production package runs JARVIS only in `required` mode.

V1 remains a fail-closed migration baseline. Its semantics are not silently
changed. Final required-mode production accepts V2 only, and V1 production
entry points are removed after cutover.

## 2. Approved decisions

| ID | Decision |
|---|---|
| D1 | Complete the boundary in strict stages: policy, vault, input runtime, ingress, execution, integration, deployment. |
| D2 | Keep the current one-request-per-connection transport model. |
| D3 | Bind capabilities to boot, authenticated client, peer identity, run, type, expiry, and policy generation; do not bind them to a transient connection. |
| D4 | Ordinary JARVIS JavaScript and Python never receive original user data. |
| D5 | Every user input path, including chat text and files, is owned by `savana-ingressd`. |
| D6 | Parsing and OCR run in disposable, sandboxed Rust-managed workers outside `savana-kerneld`. |
| D7 | G1, G2, NER, tokenization, masking, provenance creation, and vault commitment are kernel-owned. |
| D8 | Tool execution and approved release use `savana-execd`; JARVIS owns no tool credential and receives no plaintext. |
| D9 | V2 uses separate sockets and closed operation sets for JARVIS, ingress, execution, approval, and administration roles. |
| D10 | Sensitive frames use an authenticated encrypted stream and zeroizing decode path. |
| D11 | V1 deployment uses a non-resident root helper, a signed transaction descriptor, fixed root-owned staging, restart activation, and a durable rollback watchdog. |
| D12 | “Complete” requires the signed deployed artifact, real required-mode E2E, committed deployment transaction, rollback evidence, and removal of legacy fallbacks. |

## 3. Security objective and claims

### 3.1 Objective

The product boundary must make the Rust services authoritative for portable
security decisions and external effects. JARVIS coordinates opaque state but
cannot:

- observe original user input, OCR text, vault plaintext, raw tool arguments,
  or raw tool results;
- construct trusted values or provenance;
- inject policies, active tools, ontology rows, validator verdicts, identities,
  approvals, or execution outcomes;
- obtain tool credentials;
- materialize or repeat an external effect outside a kernel-issued execution
  nonce;
- fall back to Python security logic after a refusal or infrastructure failure.

The accurate product claim is:

> Ordinary JARVIS JavaScript and Python do not receive original user data or
> approved plaintext. Original data is confined to the browser and the
> isolated Rust ingress/OCR, kernel/vault, and executor components for the
> minimum stage that requires it.

The product must not claim that plaintext exists only in `savana-kerneld`.
The browser, a sandboxed parser/OCR worker, and the selected executor
necessarily process plaintext.

### 3.2 In-scope failures and attacks

The boundary fails closed under:

- ordinary JARVIS bugs, stale requests, duplicate requests, and invalid state
  transitions;
- untrusted local processes attempting to impersonate a service or reuse a
  socket, handle, receipt, ticket, grant, or nonce;
- modified, expired, rolled-back, wrong-domain, or wrong-key signed artifacts;
- malformed CBOR, malformed sensitive frames, chunk reordering, truncation,
  oversized input, Unicode ambiguity, parser bombs, and model contract drift;
- missing models, queue saturation, deadline expiry, cancellation, daemon
  restart, transport loss, partial writes, and uncertain execution results;
- replay and concurrent consumption of approvals, vaults, pending calls,
  execution tickets, and results;
- replacement of a tool descriptor, destination projection, validator,
  ontology, policy, release, model, or service identity;
- interrupted installation, concurrent installers, power loss, rollback
  failure, and restart during deployment recovery.

### 3.3 Explicit limitations

This design does not protect against:

- root, kernel, hypervisor, debugger, or physical-memory compromise;
- compromise of the browser itself or of a Rust component while that component
  is intentionally processing plaintext;
- compromise of trusted signing keys, platform keystores, or signed policy;
- a malicious external destination after a correctly authorized release;
- all CPU, memory, timing, swap, or kernel-buffer side channels.

Deployments must disable core dumps, restrict ptrace, use encrypted swap where
appropriate, and apply platform sandboxing. These measures reduce exposure;
they are not described as HSM-equivalent isolation.

## 4. Process architecture

```text
┌────────────────────────────────────────────────────────────────────┐
│ Browser                                                            │
│                                                                    │
│ ingressd-owned input window       Authority-owned WebAuthn window  │
└──────────────┬──────────────────────────────┬──────────────────────┘
               │ original input               │ masked signed display
               ▼                              ▼
┌──────────────────────────┐       ┌───────────────────────────────┐
│ savana-ingressd          │       │ Approval Authority            │
│ low privilege            │       │ separate OS identity          │
│ no policy/approval keys  │       │ ingress/approval signing keys │
│                          │       │ WebAuthn and replay state      │
│ disposable parser/OCR ───┼──┐    └──────────────┬────────────────┘
└──────────────────────────┘  │                   │ signed receipt
                              ▼                   ▼
                    ┌──────────────────────────────────────┐
                    │ savana-kerneld                       │
                    │ policy + G1–G7                       │
                    │ provenance + vault + input runtime   │
                    │ approval verification + dispatch FSM │
                    └──────────────┬───────────────────────┘
                                   │ sealed execution/release
                                   ▼
                    ┌──────────────────────────────────────┐
                    │ savana-execd                         │
                    │ minimal per-tool credentials         │
                    │ durable nonce/result journal         │
                    │ sandboxed connectors                 │
                    └──────────────┬───────────────────────┘
                                   │ external effect
                                   ▼
                             External sink

JARVIS communicates only with opaque grants, handles, masked values,
signed approval envelopes, and public status.
```

### 4.1 Rust crate boundary

The final workspace contains exactly:

```text
savana-kernel-protocol
savana-policy-core
savana-vault
savana-input-runtime
savana-kerneld
savana-ingressd
savana-execd
```

`libsavana-ner`, `savana-core-py`, PyO3, maturin, the Python vault, Python
G1/G2/NER, and Python tool-policy fallbacks are removed only after the
required-mode release is deployed and healthy.

### 4.2 Identities and key ownership

| Identity | May hold | Must not hold |
|---|---|---|
| JARVIS | kernel client-auth key; Authority tool/release client-auth key | raw input, tool credentials, producer/policy/model/approval keys |
| ingressd | kernel ingress client-auth key; Authority ingress client-auth key | policy, approval, vault, executor, or daemon signing keys |
| kerneld | daemon identity; verified public trust roots; vault state | Authority private keys or tool credentials |
| Approval Authority | ingress and approval keys; WebAuthn public credential state | raw input, vault entries, tool credentials |
| execd | executor identity and narrowly scoped tool credentials | policy, approval, vault, ingress, or daemon signing keys |
| deployment helper | fixed release verification roots and deployment ledger access | runtime user data or service credentials |

The handshake keys are service- and role-specific. Possession of one client
key never authorizes another socket or signing domain.

### 4.3 Connection model

Each UDS connection performs:

1. OS peer credential verification before application decoding;
2. a mutually signed transcript with protocol, role, both nonces, boot ID,
   exact release/policy/model/resource identities, and ephemeral key material;
3. one canonical request;
4. at most one canonical response;
5. connection close.

Subsequent operations open new authenticated connections. Long-lived state is
located through random 256-bit capabilities bound to:

- daemon boot ID;
- authenticated client ID and exact peer UID/GID;
- run and object type;
- immutable policy generation and relevant registry/ontology versions;
- monotonic and wall-clock expiry.

Supplementary groups authorize socket access only; they do not replace the
exact peer and transcript checks.

## 5. End-to-end input flow

### 5.1 Browser session

JARVIS calls `PrepareIngress` without user data. The kernel creates a
single-use `IngressGrant` bound to:

- new-run or existing-run target;
- the authenticated JARVIS client;
- the one allowed ingressd identity;
- task and conversation request context;
- policy generation, issue time, expiry, and random nonce.

The response includes only the grant identity and an exact fixed-origin URL:

```text
http://localhost:8767/input/{canonical-grant-id}
```

JARVIS opens that URL in a separate `noopener` window. It does not proxy,
frame, render, or receive the input form. The ingress service has no CORS
allowlist for JARVIS. Completion signaling carries only the grant ID and an
opaque completion nonce.

The listener is held by systemd/launchd socket activation so there is no
service-restart window in which an unprivileged process can claim the port.
Host, origin, method, CSRF, grant expiry, and canonical path spelling are
strictly checked.

### 5.2 Parsing and OCR

ingressd accepts chat text, pasted content, and files. Files enter a
disposable parser/OCR worker with:

- no network;
- no service or signing keys;
- no inherited writable filesystem other than a bounded private temporary
  area;
- disabled core dumps and ptrace restrictions;
- signed parser/render/OCR binaries and model assets;
- hard page, pixel, archive expansion, nesting, byte, CPU, wall-clock, and
  output limits.

MIME, magic, extension, and parser result must agree under signed policy.
Malformed or unsupported content fails closed. Raw output is streamed to the
kernel and is never returned to JARVIS or persisted by ingressd.

### 5.3 Kernel input transaction

The ingress role uses:

```text
40  BeginInput
41  AppendInputChunk
42  FinalizeInput
43  CommitInputReceipt
44  AbortInput
45  GetInputStatus
```

Chunks bind grant, session, sequence number, cumulative digest, declared total
length, and final length. Missing, repeated, reordered, cross-session, or
post-finalization chunks are rejected.

`FinalizeInput` runs, in order:

1. pinned Unicode normalization and structural limits;
2. G1 injection classification and rule checks;
3. G1 sensitive-data detection and vault tokenization;
4. signed NER models and deterministic span reconciliation;
5. G2 local extraction under a signed model, closed grammar/schema, and
   policy whitelist;
6. mandatory leak checks over every masked or extracted output;
7. construction of a daemon-signed masked ingress approval envelope.

Model absence, model output-contract drift, queue saturation, deadline expiry,
grammar failure, schema failure, unknown field, or leak detection denies the
transaction. No chat or Python fallback is allowed.

The ingressd registers the exact daemon-signed envelope with the Approval
Authority under its ingress-only client role. The Authority renders the
signed masked display, performs a fresh WebAuthn user-verification ceremony,
and signs an ingress receipt bound to the complete challenge.

`CommitInputReceipt` atomically:

- validates the receipt and its one-use nonce;
- converts `PendingIngress` to a live vault;
- creates only masked/tokenized policy values and kernel-derived provenance;
- creates a run or appends to the target run;
- creates a claim capability bound to the target JARVIS client;
- clears all obsolete plaintext staging.

JARVIS then calls `ClaimGatedInput`. It receives run/value/document handles,
masked values, and active tool views, never raw input.

## 6. G1–G7 ownership

| Gate | Kernel-owned behavior |
|---|---|
| G1 | Unicode normalization, prompt-injection policy, PII/secret detection, tokenization, and denial. |
| G2 | Local signed extraction model, signed GBNF/schema, closed field whitelist, deterministic safety filtering. |
| G3 | Source, parent, root-evidence, value digest, reader set, and taint/provenance propagation. |
| G4 | Signed policy × signed registry tool set, attempt classification, ontology evaluation, quotas, and atomic reservation. |
| G5 | Required internal validators plus fully bound signed external attestations. |
| G6 | Daemon-signed masked approval envelope and exact WebAuthn-backed one-use receipt verification. |
| G7 | One-way execution/release state, durable execution nonce, result receipt, redacted audit, and no automatic replay. |

The policy state sequence is:

```text
PreparePlannerCall
  → CommitPlannerValue / DeriveValue
  → ProposeToolCall
  → EvaluateToolCall
       ├─ Denied
       ├─ NeedsApproval → AuthorizeToolCall
       └─ Allowed
  → DispatchExecution
  → Pending | Succeeded | Failed | Indeterminate
```

### 6.1 Provenance

Every value record contains kernel-generated:

- source kind and producer identity;
- canonical value digest;
- ordered parent handles and parent provenance digests;
- root signed-ingress evidence;
- reader/effect classification;
- policy, registry, ontology, run, and boot identity;
- creation and expiry data.

Derivation never upgrades trust. One untrusted parent keeps the derived value
untrusted. Tool results are always `ToolResult` sources and are treated as
untrusted input regardless of executor authenticity.

Policy-core never stores pre-gate raw text as a normal `KernelValue`.

### 6.2 Registry, descriptor, ontology, and validators

The kernel recomputes a descriptor digest over the entire canonical
descriptor, including:

- provider and tool identity;
- argument and result schemas;
- roles and effects;
- attempt class and limits;
- internal and external validator requirements;
- executor identity;
- destination/display projection;
- idempotency contract;
- registry version.

Publisher-supplied digest bytes are evidence to compare, not authority.

Ontology uses a closed signed AST with only bounded, typed operations such as
`Eq`, `Ne`, `In`, `NotIn`, `All`, and `Any`. It contains no strings that are
interpreted as code.

Validator declarations are:

```text
Internal { implementation_id, semantic_version, code_digest }
External { validator_id, key_id, semantic_version }
```

External attestations bind run, pending call, canonical argument digest,
validator declaration, verdict, public reason, issue/expiry, policy/registry/
ontology identity, and a replay-protected nonce.

Policy, registry, ontology, model, and release identities each have a
daemon-owned persistent high-water ledger. Signed but rolled-back snapshots
are rejected after restart.

### 6.3 Approval

Approval purposes are disjoint:

```text
Ingress
ToolExecution
FinalRelease
```

An envelope and receipt bind purpose, task, conversation, principal, run,
tool/executor, exact argument and provenance digests, destination/display
projection, masked display digest, token set, policy and artifact identities,
boot, issue/expiry, challenge nonce, receipt nonce, and signing identities.

Cross-purpose use fails. Only `Approve` authorizes. One boot-global replay
ledger provides one concurrent winner. Active receipt tombstones are never
evicted to admit new work.

## 7. Execution and result flow

### 7.1 JARVIS-facing operations

JARVIS may invoke:

```text
0   Health
10  PrepareIngress
11  ClaimGatedInput

12  PreparePlannerCall
13  CommitPlannerValue
14  DeriveValue
15  ProposeToolCall
16  EvaluateToolCall
17  AuthorizeToolCall
18  DispatchExecution
19  GetExecutionStatus

30  ReadMaskedDocument
31  PrepareRelease
32  AuthorizeRelease
33  DispatchRelease
34  GetReleaseStatus
35  RevokeVault
```

`ReadMaskedDocument` uses an opaque cursor and policy-lowered page/byte limit.
It never returns a raw page, token mapping, or complete oversized
pages-plus-chunks duplicate.

### 7.2 Executor protocol

Only the exact kerneld identity may connect to execd:

```text
60  Dispatch
61  QueryByExecutionNonce
62  AcknowledgeCommittedResult
```

`DispatchExecution` does not return tool arguments. The kernel:

1. validates and atomically reserves the pending call, ticket, approval, and
   attempt quota;
2. derives one random execution nonce;
3. signs and encrypts the exact tool, arguments, destination, policy,
   registry, provenance, expiry, and nonce for the selected executor;
4. sends the sealed envelope directly to execd.

execd durably records the nonce before an effect. Repeating the same nonce
returns the prior status; it never repeats the effect. Where the external
service supports idempotency, the same nonce is its idempotency key.

Raw results return directly to the kernel. The kernel gates/masks them, records
an untrusted `ToolResult` provenance node, and exposes only a resulting value
handle or public failure status to JARVIS. execd retains a bounded encrypted
result journal until operation 62 confirms that the kernel committed the
exact result digest.

The closed public outcome is:

```text
Pending
Succeeded { value_handle, public_metadata }
Failed { stable_failure_class }
Indeterminate { recovery_reference }
```

`Indeterminate` is terminal for automatic execution. Operators may reconcile
the original nonce, but neither JARVIS nor the kernel may mint a replacement
nonce as an implicit retry.

### 7.3 Final vault release

Final release follows:

```text
PrepareRelease
  → daemon-signed masked envelope
  → Authority WebAuthn receipt
  → AuthorizeRelease
  → DispatchRelease
  → execd/sink
```

Plaintext never appears in a JARVIS response. The selected executor receives
only the approved destination and data, with the same nonce, durable journal,
query, acknowledgement, and indeterminate-state rules as tool execution.

## 8. Vault and sensitive transport

### 8.1 Sensitive frame path

Non-sensitive metadata uses bounded canonical CBOR. Sensitive operations use a
dedicated frame path:

- signed handshake transcripts include ephemeral key material;
- HKDF-derived direction keys are unique per connection;
- frames use a pinned, standard AEAD construction and monotonic per-connection
  sequence;
- length, role, operation, request ID, chunk identity, and finality are
  authenticated;
- generic frame and audit layers see ciphertext only;
- decryption writes directly into zeroizing bounded storage;
- canonical validation never creates a second plaintext re-encoding.

Crypto suites and dependencies are pinned in the implementation plan and
covered by fixed cross-language vectors. No custom cipher construction is
permitted.

### 8.2 Vault lifecycle

```text
PendingIngress
  → Live
  → ReleaseAuthorized
  → Dispatching
  → Released | Revoked | Expired | Indeterminate | RestartInvalidated
```

All operations share one liveness check for object type, boot, client, peer,
run, immutable policy snapshot, wall and monotonic clocks, expiry, state, and
revocation.

Vault APIs never expose:

- a secret input or secret output;
- raw entry enumeration;
- raw token resolution;
- a serializable vault;
- raw values in `Debug`, error, metric, trace, or audit output;
- deterministic production nonce helpers.

### 8.3 Atomic failure rule

Invalid input, receipt, binding, or pre-dispatch validation changes no live
state and writes no plaintext.

After validation, the kernel reserves all one-use objects atomically. If the
sealed executor transfer is proven to have written zero bytes and the executor
has not accepted the nonce, the reservation may return to its exact prior
state. Retrying still requires an explicit status query and explicit caller
action.

After any byte is written or delivery is uncertain:

- the approval/ticket cannot be reused;
- the vault cannot be released to another nonce;
- state becomes dispatching or indeterminate;
- the executor must authenticate a complete frame before decrypting or
  invoking a connector;
- a partial frame never triggers an effect;
- no second response is written on the failed connection.

## 9. Resource, error, and audit rules

One compiled `HardLimits` profile covers frames, sensitive chunks, input
sessions, pages, pixels, expanded bytes, characters, model workers, queues,
runs, values, handles, pending calls, approvals, vaults, execution journals,
and all replay ledgers. Signed policy may lower but never raise a compiled
ceiling.

Expired state is removed through bounded indexes and bounded incremental GC.
No request performs an unbounded full-store scan. Active state and live replay
tombstones are not evicted to admit new work.

Error behavior:

- wrong peer, handshake, transcript, version, role, canonical encoding, or
  pre-request frame errors close silently;
- an authenticated canonical request may receive one request-bound stable
  error;
- model, overload, deadline, cancellation, audit, entropy, storage, and
  service failures fail closed;
- mutating operations are not automatically retried;
- errors reveal no existence, raw value, identity detail, policy internals, or
  validation oracle beyond the approved stable public code.

Audit records contain operation, public state transition, public code,
monotonic timing, policy/release identities, and keyed pseudonymous
correlation IDs. They contain no plaintext, masked tokens, raw handles,
destinations, signatures, credentials, or personal identifiers.

Audit failure before an effect blocks the effect. Audit failure after an
effect poisons the executor/kernel transaction and produces a fail-stop or
indeterminate outcome; it never reports a clean failure that invites replay.

## 10. Deployment and rollback

### 10.1 Privileged surface

V1 has no long-running root deployment daemon and no root deployment socket.
A fixed, signed, root-owned helper accepts only:

- one canonical signed transaction descriptor;
- one content-addressed staging ID located below a fixed root-owned spool.

It does not accept caller-selected trust roots, source directories, target
paths, scripts, environment overrides, or runtime credentials.

All files are opened relative to trusted directory descriptors and rechecked
for identity, type, owner, mode, size, digest, signature, ACL, xattr, and
platform code-signing state. Archives with traversal, symlink, hardlink,
device, setuid, capability, or unknown members are rejected.

`identity-state.ref` is a non-secret locator. Private keys, bearer references,
and keystore tokens never travel through argv or ordinary environment
variables.

### 10.2 Deployment transaction

The root-owned durable state machine is:

```text
PREPARED
  → ARMED
  → QUIESCED
  → INSTALLED
  → VERIFIED
  → COMMITTED

failure:
ROLLING_BACK
  → ROLLED_BACK
  → FAILED_SAFE
```

Each transition, file, directory, and ledger update is fsync'd before the next
step. A global transaction lock and transaction nonce prevent concurrent or
replayed installers. The watchdog is installed outside the release being
replaced and has a boot-time recovery unit.

The deployment ledger maintains a binary release-sequence high-water mark.
Normal installation is strictly increasing. Rollback is a pre-armed exact
unit containing:

- the candidate Rust bundle;
- a strictly newer forward-rollback policy compatible with that bundle;
- the matching model/resource lock;
- the matching signed JARVIS artifact;
- the same exact Authority lock;
- forward-compatible database state.

Policy, WebAuthn counters, approval replays, executor nonces, audit state, and
deployment ledgers are never rolled back.

### 10.3 Cutover

The transaction:

1. fences new browser sessions and new executor dispatch;
2. drains or marks existing operations indeterminate;
3. stops JARVIS, ingressd, execd, Authority, and kerneld;
4. installs and fsyncs the complete bound unit;
5. starts kerneld, Authority, ingressd, and execd;
6. verifies their signed identities and readiness;
7. starts JARVIS in `required` mode;
8. runs a protected E2E against an isolated sink;
9. commits on success or lets the watchdog execute the pre-armed rollback.

Policy and binary updates activate only by restart. There is no public live
rollover operation or SIGHUP activation path in V2.

Production packaging accepts only `required`. Shadow runs only against
synthetic or protected pre-release traffic and cannot materialize or release.
Disabled mode is a development-only build/configuration and is never marketed
as the security boundary.

## 11. Migration and implementation order

The implementation order is:

```text
V2 protocol and state model
  → G3–G7 policy state machine
  → vault and approval state
  → G1/G2/NER input runtime
  → ingressd and sandboxed parsing/OCR
  → execd and durable execution journal
  → Approval Authority and JARVIS integration
  → packaging, updater, and service installation
  → signed candidate E2E
  → required-mode deployment
  → legacy removal
  → final signed build and rollback exercise
```

NER/input-runtime asset verification and pure runtime work may proceed in a
separate worktree while policy and vault work advance. Shared daemon
integration occurs only after the policy and vault branches pass their own
gates.

No new operation is opened in the daemon dispatcher until its core state,
resource bounds, negative tests, authenticated UDS tests, audit behavior, and
restart semantics pass.

## 12. Verification

Implementation uses test-driven development. Every transition begins with a
failing behavior test. Security tests may not be skipped, conditionally
succeed, or silently use a fallback.

Required gates include:

1. canonical V2 vectors, differential codecs, parser fuzzing, and invalid
   shape/length/tag/property tests;
2. model-based G3–G7 transitions and concurrency tests for quotas, approvals,
   tickets, receipts, results, and replay ledgers;
3. real signed G1/G2/NER assets, Unicode adversarial cases, injection cases,
   grammar/schema failures, queue/deadline/cancellation, and tensor-contract
   failures;
4. malicious PDF/image, archive expansion, MIME mismatch, page/pixel/CPU
   limits, parser crash, and sandbox-escape-negative tests;
5. vault binding mutation, expiry, revocation, restart, canary, redaction, and
   zeroization tests;
6. sensitive transport failure injection at every write boundary, proving
   zero-write recovery and partial-write burn behavior;
7. execd crash/restart, concurrent dispatch, nonce replay, result
   acknowledgement, idempotency, and indeterminate recovery tests;
8. every cross-role peer/key/socket/operation denial and every cross-client,
   run, boot, object-type, policy, registry, and ontology handle denial;
9. deployment failure injection for every write, fsync, rename, stop, start,
   signal, disk-full, concurrent install, boot recovery, and rollback step;
10. real Linux and macOS UID/GID, supplementary group, ACL/xattr, code-signing,
    socket activation, and sandbox verification;
11. browser, virtual WebAuthn authenticator, real signed assets, and isolated
    external sink required-mode E2E proving one external effect, zero fallback,
    and zero original-data exposure to JARVIS;
12. static API, symbol, dependency, route, and source scans proving the exact
    seven-crate surface and absence of PyO3, old Python security paths, raw
    vault APIs, public low-level model APIs, and tool credentials in JARVIS;
13. three independent final security reviews with
    Critical/Important/Minor = `0/0/0`.

## 13. Completion criteria

The source is complete only when:

- every V2 operation above is implemented and fails closed outside its allowed
  role and state;
- all seven crates pass formatting, lint, unit, integration, property,
  concurrency, fuzz-corpus, symbol, API, and documentation gates;
- required-mode JARVIS contains no security fallback or raw-data route;
- ingressd and execd use their real sandbox, model, credential, and journal
  configurations on Linux and macOS;
- legacy Rust/Python interfaces are absent from source and built artifacts.

The product boundary is complete only when:

- the exact final seven-crate release, policies, models, services, Authority
  lock, and JARVIS artifact are signed as one transaction;
- installation identity and all public keys match the signed locks;
- protected real-asset acceptance succeeds;
- required-mode browser-to-input-to-approval-to-effect E2E succeeds;
- exactly one effect is observed and all original-data canaries are absent
  from JARVIS-visible messages, logs, traces, databases, caches, and artifacts;
- daemon/service-kill and indeterminate recovery tests show no automatic
  replay;
- the rollback unit is exercised successfully;
- the final transaction is committed and no watchdog rollback remains armed;
- the independent final reviews report no findings.

If production keys, real model assets, native service hosts, or the protected
deployment environment are unavailable, the result may be reported as source
complete with exact missing gates. It must not be described as product
complete.
