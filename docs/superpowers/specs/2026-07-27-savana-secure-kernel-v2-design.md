# Savana Secure Kernel V2

> Date: 2026-07-27
>
> Status: section-by-section architecture approved; normative master
> corrections applied; revised written-spec review pending
>
> Scope: complete the product security boundary, not merely make dormant wire
> tags return success.

## 1. Authority and companion specifications

This is the authoritative product-boundary design for V2. Two normative
companion specifications close the implementation details:

- [V2 protocol and state design](./2026-07-27-savana-kernel-v2-protocol-state-design.md)
- [V2 deployment and platform design](./2026-07-27-savana-kernel-v2-deployment-design.md)

An implementation is conforming only when it satisfies all three documents.
This master specification is authoritative for the product claim, authority
boundaries, permitted information flows, capability exceptions, effect-safety
invariants, deployment transaction shape, and completion evidence. The
companion documents are authoritative for exact wire, cryptographic,
persistence, and platform mechanics only where they are consistent with those
master rules.

The corrections frozen in this revision are normative overrides. In
particular, any companion text that exposes another JARVIS handle, creates an
action intent before its complete binding, admits an external validator,
defines a boot-independent recovery capability other than `TaskHandleV2`,
permits a non-atomic kernel effect transition, uses a circular deployment
identity, permits an online V2 bootstrap-TCB update, or uses a less specific
rollback/evidence state is superseded by this document. An unresolved
cross-document ambiguity fails closed and the affected dispatcher remains
disabled.

This design supersedes the following older assumptions wherever they conflict:

- handles bind to one authenticated client and peer identity, not one
  transient UDS connection;
- one request and at most one response are processed per authenticated local
  connection;
- all authoritative local application-service security decisions and content
  transformations are implemented in signed Rust services;
- JARVIS JavaScript and Python receive no user-derived content, even when that
  content is masked;
- all chat text, pasted content, files, and OCR output enter through
  `savana-ingressd`;
- G1, G2, NER, tokenization, masking, provenance, and vault commitment are
  kernel-owned;
- `savana-agentd`, not JARVIS, owns agent sessions and planner orchestration;
- `savana-approvald`, not a Python Approval Authority, owns WebAuthn and signed
  settlements;
- plaintext tool arguments, raw results, and approved releases travel directly
  between kerneld and `savana-execd`;
- the external planner receives only a closed abstract intent envelope with
  opaque slots, never user-derived free text;
- `DetectStrict` and `LeakGate` are mandatory internal transitions rather than
  skippable authoritative public operations;
- the final production workspace has nine Rust crates;
- policy, registry, ontology, models, resources, projections, internal validators,
  services, and binaries activate as one signed restart transaction;
- the production package runs JARVIS only in `required` mode.

V1 remains an unchanged, fail-closed migration baseline. V2 has distinct
types, decoders, endpoints, signature domains, and vectors. Final production
accepts V2 only, and V1 runtime entry points are removed after cutover.

## 2. Approved decisions

| ID | Decision |
|---|---|
| D1 | Complete the boundary in strict stages: protocol/state, policy, vault, input, agent, approval, execution, integration, deployment. |
| D2 | On each encrypted daemon UDS/XPC application connection, process one request and at most one response; browser HTTP connections follow their closed route/session protocol instead. |
| D3 | Bind runtime capabilities to boot, service/client identity, OS peer, run, type, expiry, and active security state; do not bind them to a transient connection. `TaskHandleV2` is the sole boot-independent exception and is query-only after its originating boot. |
| D4 | JARVIS JavaScript and Python receive only opaque `TaskHandleV2`, closed public status, and a fixed-origin no-content bootstrap URL. They never receive an action, recovery, conversation, content-session, approval, execution, or release handle. |
| D5 | Every user-input path is owned by `savana-ingressd`; parsing/OCR run in disposable sandbox workers. |
| D6 | G1, G2, NER, tokenization, masking, provenance, and vault state are owned by kerneld and Rust libraries. |
| D7 | `savana-agentd` owns Rust agent-session data, declassified display, and abstract planner orchestration. |
| D8 | The external planner receives no user-derived free text or concrete protected value. |
| D9 | `savana-approvald` owns WebAuthn, credentials, counters, signed settlements, enrollment, UI authentication, and approval replay state; its private root-only `savana-approvalctl` binary is the only enrollment/revocation client. |
| D10 | `savana-execd` owns connector credentials, effect dispatch, durable execution nonces, and raw-result return to kerneld. |
| D11 | V2 uses separate role-specific sockets/XPC services and operation enums. |
| D12 | Sensitive local records use the fixed V2 encrypted transport and zeroizing decoder. Browser origins use no cookies, `Authorization` header, or persistent storage; content sessions are WebAuthn-backed, origin-bound, and held only in tab memory. |
| D13 | Deployment uses a non-resident root helper, complete signed manifests, one root ledger, a non-circular one-use rollback grant, restart activation, a monotonic effect-fence epoch, and a durable watchdog. |
| D14 | Completion evidence has four levels: source, artifact, platform, and product. Product completion binds the exact sorted set of advertised `PlatformEvidenceRefV2` values and independent `0/0/0` reviews. |
| D15 | A tool action intent is created only after one exact active descriptor and one strictly sorted, duplicate-free argument binding have been resolved to internal stable identities. |
| D16 | The initial V2 validator surface is internal-only. No caller-supplied or externally obtained validator attestation is authoritative. |
| D17 | Kernel source labels and derivations never improve integrity merely because Rust or kerneld performed a computation; declassification preserves integrity and root evidence. |
| D18 | Dispatch preparation, approval/ticket consumption, quota accounting, nonce creation, WAL publication, and result publication use kernel-owned atomic transactions. |
| D19 | V2 has no online bootstrap-TCB update. Helper, watchdog, ledger verifier, and deployment trust-root changes require an offline native maintenance ceremony outside an application deployment transaction. |
| D20 | Agentd alone owns localhost ports 8765 and 8768. JARVIS owns no listener; task health/preparation/status/cancellation exist only on its authenticated local control role. |
| D21 | Capability indexes store only typed token hashes. Same-boot exact-response replay uses role-specific AEAD-sealed capability-free snapshots or operation-specific typed emissions that are never resolvers. The action-intent live projection uses one non-token `ActionIntentEmissionReference` to its already stored intent/state-handle emissions; the only other live projection is agentd's durable TaskHandle emission. Neither may revive an old child capability. |
| D22 | One tagged `DispatchSubjectV2` union carries either tool execution or final release through every preparation, envelope, journal, receipt, recovery, and quota record. |
| D23 | Agentd and execd serialize OS gate operations through a non-bypassable process-level reference-count coordinator; an exclusive lock proves no live holder, never journal terminality. |
| D24 | An immutable release-root-signed `ProductReleaseV2`, not a Product signer or opaque digest, is the authority for the exact release-manifest and six-field advertised platform sets. |
| D25 | `PrepareIngress` uses an agentd durable local saga plus a kerneld durable agent-task semantic index; it never relies on cross-daemon ACID and cannot create a second durable task after an inter-daemon crash. |

## 3. Data classes and product claim

### 3.1 Original data

`OriginalDataV2` includes every user-derived:

- byte, string, scalar, file, filename, form field, and metadata value;
- parser or OCR output;
- raw planner or tool result;
- copied, sliced, normalized, translated, reversibly encoded, or otherwise
  content-preserving derivative.

Replacing a protected span while preserving the rest of a sentence does not
make the sentence cease to be user-derived content.

### 3.2 JARVIS-visible data

`JarvisVisibleV2` contains only:

- opaque `TaskHandleV2` values;
- fixed closed public task/service states and failure classes;
- fixed-origin `JarvisBootstrapUrlV2` values generated by agentd.

It has no generic text, bytes, number, map, value, conversation, run,
document, vault, planner, action, tool, approval, receipt, execution, recovery,
provenance, token, digest, destination, argument, result, or content-session
field. A public status never embeds a `PublicActionHandleV2`,
`RecoveryReferenceV2`, or another capability. A bootstrap URL contains only
the fixed agentd origin and a random one-use bootstrap ID. It can render only
static bootstrap state and initiate UI authentication; possession of it does
not authorize reading or submitting user-derived content.

The closed public task states are:

```text
AwaitingUiAuthentication { optional no-content bootstrap }
AwaitingInput
Processing
AwaitingIngressApproval
Ready { optional no-content bootstrap }
Running
Dispatching
Succeeded
EffectSucceededOutputQuarantined { closed failure class }
PolicyDenied { closed failure class }
FailedNoEffect { closed failure class }
Indeterminate
Cancelled
Expired
```

No variant may acquire another payload without a new major protocol.

`TaskHandleV2` is the only exported capability that remains resolvable across
a service or machine boot. It is bound to the installation, authenticated
JARVIS control-client identity and OS peer class, durable task ID, handle type,
creating manifest digest, creating deployment generation, protocol ABI, and
the distinct `task_logical_expires_at` and
`query_tombstone_retain_until` bounds. Both time fields must equal the signed
kernel correlation's logical-expiry and status-retention fields. Its exact
origin tuple is:

```text
TaskOriginBootV2 {
    machine_boot_id,
    jarvis_control_client_boot_id,
    agentd_server_boot_id,
    kerneld_server_boot_id
}
```

The agentd resolver binds all four values plus the signed kernel correlation;
the correlation independently binds the authenticated agentd client boot,
kerneld server boot, and machine boot without receiving or trusting a JARVIS
field. Across a change to any tuple member, the handle authorizes only
`GetTaskStatus`; that response remains a closed content-free status.
`CancelTask` additionally requires all four current values to equal the
origin tuple and that no effect or release has reached dispatch preparation.
Every other handle, UI grant, cursor, ticket, and content capability is
boot-bound.

JARVIS has no kernel, approval, planner, or executor data-plane key. It cannot
call a data-bearing endpoint. It never receives a post-authentication content
URL or a browser content-session secret.

### 3.3 Rust agent data

`AgentViewV2` is a kernel-produced, purpose-bound Rust data-plane type. It may
contain escaped masked/tokenized content and fixed structural views required
for the Rust-owned agent UI. It:

- is available only to the authenticated agentd role;
- remains labelled with provenance, confidentiality, readers, purpose, and
  expiry;
- cannot be converted to a planner envelope or executor argument without a
  separate kernel transition;
- never enters a JARVIS response or JARVIS-controlled DOM, log, database,
  cache, or route.

The browser may render `AgentViewV2` only on the fixed agentd origin after a
fresh approvald WebAuthn UI-authentication settlement has been consumed by
kerneld. The resulting content session is origin-, principal-, task-, boot-,
manifest-, purpose-, and expiry-bound, is held only in that tab's memory, and
cannot be resumed from a URL, cookie, header, or browser store.

### 3.4 Planner data

`PlannerEnvelopeV2` contains only:

- fixed schema/route identity, fresh envelope nonce, and bounded expiry;
- signed static template IDs;
- closed intent, effect, and relation enums;
- fresh envelope-scoped opaque slot aliases that resolve only under that
  envelope nonce;
- policy-approved structural facts whose types are closed;
- bounded public resource limits.

It contains no user-derived free text, filename, query, topic, destination,
contact, document content, OCR text, arbitrary number, raw digest, or concrete
protected value. G2 performs the local semantic extraction needed to construct
this envelope.

Planner output is a closed plan graph referencing template IDs and opaque
slots. It is always externally untrusted and cannot itself authorize an
effect.

### 3.5 Accurate claim

The accurate product claim is:

> All authoritative local application-service security decisions and content
> transformations are implemented in the signed Rust services. Ordinary
> JARVIS JavaScript and Python receive no user-derived content, masked content,
> approval content, planner payload, tool payload, or released plaintext. The
> external planner receives only a closed abstract intent envelope without
> user-derived free text or concrete protected values.

The product must not claim that plaintext exists only in kerneld. The browser,
an isolated parser/OCR worker, kerneld/vault, the Rust approval UI, and a
selected executor necessarily process different approved representations.
The browser, OS/WebAuthn stack, and external destination are transport,
presentation, authentication, or sink participants; none is an authoritative
application policy or declassification decision-maker.

## 4. Security objective and limitations

### 4.1 Objective

The Rust boundary is authoritative for trusted facts and effects. JARVIS
cannot:

- observe or transform data-plane content;
- construct trusted values, labels, provenance, action intents, or outcomes;
- inject policy, tools, ontology, projections, validators, identity, approval,
  or execution facts;
- read vault entries or materialize protected values;
- call a planner, tool, approval signer, or protected destination;
- obtain planner, WebAuthn/approval, vault, or tool credentials;
- cause a second execution nonce for the same action intent;
- fall back to Python security logic after refusal or infrastructure failure.

### 4.2 In-scope failures and attacks

The boundary fails closed under:

- ordinary JARVIS bugs, duplicate control requests, stale status, and invalid
  cancellation;
- service impersonation, wrong peer identity, wrong role, cross-socket
  messages, handle mutation, replay, and concurrent consumption;
- malformed or non-canonical wire data, sensitive-frame truncation or
  reordering, oversized input, Unicode ambiguity, parser bombs, and model
  contract drift;
- modified, expired, rolled-back, wrong-domain, or wrong-key artifacts;
- missing models, queue saturation, deadlines, cancellation, service restart,
  transport loss, partial writes, and uncertain effects;
- replay of ingress grants, approvals, action intents, tickets, vault releases,
  execution nonces, and results;
- replacement of descriptors, projections, validators, ontology, models,
  sandbox profiles, binaries, service identities, or release state;
- interrupted deployment, concurrent deployment, power loss, rollback
  failure, and boot during transaction recovery.

### 4.3 Explicit limitations

This design does not protect against:

- root, kernel, hypervisor, debugger, browser, or physical-memory compromise;
- compromise of a Rust data-plane process while it intentionally processes a
  representation authorized for that process;
- compromise of trusted signing keys, platform keystores, or signed policy;
- a malicious external planner acting on the abstract envelope;
- a malicious external destination after a correctly authorized release;
- all timing, traffic, CPU, memory, swap, or kernel-buffer side channels.

Core dumps are disabled, ptrace is restricted, swap protection is required,
and native sandboxing is mandatory. These controls reduce exposure; they are
not described as HSM-equivalent isolation.

## 5. Process and crate architecture

```text
JARVIS control shell ── TaskHandle/status/bootstrap ──► savana-agentd
                                                          │
Browser ── bootstrap ──► approvald WebAuthn UI auth ──────┤
                                                          │
Browser ── original input ──► savana-ingressd ────────────┤
                                                          ▼
                                                  savana-kerneld
                                                   G1–G7 / vault
                                                    │          │
                             abstract planner ◄──────┘          │ sealed effect
                             through agentd                     ▼
                                                        savana-execd
                                                          │
                                                          ▼
                                                     external sink

ingressd ── signed ingress envelope ──► savana-approvald
agentd   ── UI-auth/tool/release envelope ──► savana-approvald
approvalctl ── root admin enrollment/revocation ───────────┘
```

The final workspace contains exactly:

```text
savana-kernel-protocol
savana-policy-core
savana-vault
savana-input-runtime
savana-agentd
savana-kerneld
savana-ingressd
savana-approvald
savana-execd
```

Additional independently signed binary targets do not add crates:

- `savana-deploy` and `savana-deploy-watchdog` are private binary targets of
  the kerneld package;
- `savana-approvalctl` is a private root-only binary target of the approvald
  package and is the sole approval-admin protocol client;
- parser/OCR one-job workers are private binary targets of ingressd;
- connector one-job workers are private binary targets of execd.

The root binaries use dedicated private modules and a dependency/symbol
denylist. `savana-approvalctl` links only the canonical approval-admin client,
platform keystore, and local transport modules; it links no settlement signer,
vault, planner, executor, or deployment authority. Parser and connector
workers link no service key, policy, vault, approval, planner, or deployment
module. Connector workers are anonymous one-job, networkless provider codecs:
they may construct or parse only a descriptor-bound request/response
transcript. Before spawn, measured execd verifies the complete
`SignedConnectorCodecJobDescriptorV2` signature and active role lock; the
worker receives those exact canonical bytes on its anonymous channel and
independently validates every job/channel/resource/mode/ephemeral-key binding,
but receives no rotating service verification key. Its private ABI emits only
`PreparedProviderRequestV2`, `ConnectorCodecDecodedCompletionV2`, and
`ConnectorCodecOutcomePayloadV2` under the one-job prepared-request/outcome
attestations. The outcome-payload digest domain is exactly
`"SAVANA_CONNECTOR_CODEC_OUTCOME_PAYLOAD_V2\0"`. It cannot contain an
`ExecutorCompletionDescriptorV2`, `ExecutorCompletionPayloadV2`, service
receipt, journal identity, or audit authority. Execd retains every connector
credential, performs the only external transport, verifies the worker
attestations, and only then constructs the service-owned journal, receipt,
audit, and external completion objects.
The retained provider response, provider evidence, and complete signed
outcome-attestation digests use respectively
`"SAVANA_CONNECTOR_PROVIDER_RESPONSE_V2\0"`,
`"SAVANA_CONNECTOR_PROVIDER_EVIDENCE_V2\0"`, and
`"SAVANA_CONNECTOR_CODEC_OUTCOME_ATTESTATION_V2\0"`; a raw or
payload-only hash is never interchangeable with them.

After required-mode deployment, `libsavana-ner`, `savana-core-py`, PyO3,
maturin, Python G1/G2/NER/vault/policy code, the Python Approval Authority, and
Python planner/tool paths are removed.

## 6. Identity and local interfaces

Every edge uses a distinct client key, server key, peer rule, endpoint role,
and operation enum:

```text
JARVIS       → agentd control
agentd       → kerneld agent
ingressd     → kerneld ingress
kerneld      → execd
agentd       → approvald agent
ingressd     → approvald ingress
approvalctl  → approvald admin
```

There is no JARVIS-to-kerneld, JARVIS-to-approvald, JARVIS-to-execd,
agentd-to-execd, or ingressd-to-execd data-plane edge.

Every encrypted local handshake binds both server and client process-boot IDs
into its signed transcript. The server binds the authenticated client key,
observed OS peer/code identity, and declared client boot as one live tuple and
rejects a tuple that changes its boot ID without a verified peer restart. A
caller-supplied boot field outside that transcript is never an authority. This
is the authenticated source for every boot-bound UI, replay, planner, and
effect record.

Key ownership:

| Identity | May hold |
|---|---|
| JARVIS | agentd control client-auth key only; no loopback listener or data-plane key |
| agentd | kernel agent key; approvald agent key; restricted planner credential; service-manager-injected 8765 and 8768 listener descriptors |
| ingressd | kernel ingress key; approvald ingress key; parser-job-descriptor signing key |
| kerneld | daemon/envelope identity; execd client key; approval/UI, task-correlation, and execution-envelope signing keys; verified public roots; vault and durable dispatch state |
| approvald | four distinct settlement signing keys: UI authentication, ingress, tool, and release; WebAuthn public credential/counter state |
| execd | executor identity; distinct effect-receipt and connector-codec-job-descriptor signing keys; envelope-unsealing and journal key hierarchy; connector-specific credentials |
| approvalctl | root-only approval-admin client key and no runtime settlement, vault, planner, executor, or deployment key |
| deploy/watchdog | fixed release/deployment verification roots and deployment ledger access only |

Each replay-bearing daemon additionally holds only the exact boot-fresh
role-scoped AEAD keys in the eleven-row matrix below. Agentd alone may hold
the separate non-exportable durable replay-escrow AEAD handle, identified by
its typed `ReplayAeadKeyIdV2`; no other service may select or decode that key
ID.

The deployment `EffectGateV2` is an OS descriptor, not a key. agentd and execd
receive service-manager-created shared-lock-only descriptors plus read-only
ledger projections; their UID/code-identity policy cannot request an exclusive
lock, modify the ledger, or change either fence. deploy/watchdog alone receives
the exclusive-lock/write authority. Each runtime descriptor is owned only by a
process-level mutex/reference-count coordinator; individual requests cannot
lock, unlock, close, duplicate, or inherit it. A planner hold is bounded by the
compiled planner deadline and its durable marker; expiry causes fail-closed
reconciliation and exact-process termination before deployment continues.
Blocking cutover while a real planner exchange is unresolved is intentional
generation safety, not planner authority over deployment.

Runtime addresses, UID/GID or XPC identity, parent topology, key locations,
native sandbox profiles, and code-integrity rules are fixed by the deployment
companion specification.

Fixed browser origins are:

```text
agentd JARVIS shell/bootstrap  http://localhost:8765
savana-approvald              http://localhost:8766
savana-ingressd               http://localhost:8767
savana-agentd                 http://localhost:8768
```

Agentd is the sole 8765 listener and selector resolver. It serves only the
signed static JARVIS shell/bootstrap artifact and the closed bootstrap
GET/continue routes. JARVIS owns no TCP listener. `Health`,
`PrepareIngress`, `GetTaskStatus`, and `CancelTask` are never mapped to HTTP;
they are accepted only on the authenticated JARVIS-control UDS/XPC role, where
agentd rechecks its client key and OS peer binding. A loopback request with a
forged `Origin` cannot use a leaked `TaskHandleV2`.

WebAuthn begin and finish routes exist only on approvald at
`http://localhost:8766`. Ingressd at 8767 and agentd at 8768 expose only their
purpose-specific one-use authentication-completion routes; neither service
accepts WebAuthn options, challenges, assertions, credential data, or
caller-supplied approve/deny data over HTTP or UDS. Their authenticated UDS
roles may consume only approvald's already stored, purpose-specific signed
settlement through the exact one-use record/transfer pair.

Each Rust listener is reserved by the service manager, binds only
`127.0.0.1`, rejects alternate Host spellings and every Origin outside the
closed source-origin allowlist for the exact bootstrap transition, emits no
CORS permission, and uses no opener or cross-origin content channel.
Content-bearing requests are same-origin only. Sensitive pages use no-store
caching, a closed CSP, no third-party assets, no service worker, and no
persistent browser storage.

All four localhost origins prohibit `Set-Cookie`, the `Cookie` request header,
the `Authorization` request header, HTTP authentication, URL user-info, and
local/session/IndexedDB storage. They emit `Referrer-Policy: no-referrer`,
`Cross-Origin-Opener-Policy: same-origin`, and a CSP with
`frame-ancestors 'none'`. A request containing a forbidden credential
mechanism is rejected before application dispatch.

Every permitted browser transition between Rust origins uses exactly one of
`KernelIngressBootstrapTransferCapabilityV2`,
`IngressUiAuthenticationTransferCapabilityV2`,
`ApprovalDisplayAuthenticationTransferCapabilityV2`,
`AgentUiAuthenticationTransferCapabilityV2`,
`IngressUiAuthenticationSettlementTransferCapabilityV2`, or
`AgentUiAuthenticationSettlementTransferCapabilityV2`. There is no generic
transfer decoder or cross-purpose conversion. Each is a distinct random,
hashed-at-rest, boot-bound, one-use newtype carried only in the body of an
auto-submitted form POST from its fixed source origin to its fixed target
origin. Its stored record binds the task
preparation/correlation, source and target origins, closed UI-authentication
purpose, active manifest and deployment generation, issuing and consuming
service identities, nonce, expiry, and the expected principal when one is
already known. Before initial principal selection it instead binds the exact
pending authentication preparation and permits only starting that ceremony.

The target atomically consumes the transfer before returning a fixed
content-free pre-authentication page. The transfer itself cannot read or
submit content. After approvald completes the exact WebAuthn ceremony, it
posts a distinct random one-use completion capability to the intended content
origin. That origin consumes it, obtains and submits the exact signed
settlement through its authenticated Rust service path, and only its
same-origin POST response may install the resulting
`IngressTabSessionCapabilityV2` or `AgentTabSessionCapabilityV2` in tab
memory. No transition capability or tab-session capability appears in a URL,
referrer, cookie, header, browser store, JARVIS object, or cross-origin
response body readable by JARVIS.

Ingressd and agentd expose closed, operation-specific browser response unions.
A same-origin state or action response contains only its fixed state and typed
per-tab non-capability references. The sole data-plane read exception is the
authenticated 8768 `AgentBrowserReadViewResponseV2`, which may contain exactly
one bounded `AgentViewV2`, its typed per-tab object references, and an optional
tab-bound view cursor; it cannot contain raw/original data, a kernel handle,
or a JARVIS-visible value. An action that must cross origins returns exactly
one typed fixed-form POST variant whose target origin and transfer newtype are
fixed by the operation: ingress finalize/tool approval/release approval use
`ApprovalDisplayAuthenticationTransferCapabilityV2`, follow-up input uses
`KernelIngressBootstrapTransferCapabilityV2`, and authentication completion
uses only its ingress/agent settlement-transfer type. There is no generic
redirect, URL parameter, arbitrary response map, or prose-only carrier.
Same-boot exact replay normally returns the same sealed canonical response.
The two explicit exceptions are closed live projections: `ProposeToolCall`
re-emits only the same typed intent/state handles required by its current
canonical intent revision, and a cross-boot `PrepareIngress` retry re-emits the
same `TaskHandleV2` with current public bootstrap state. Neither exception may
revive an expired, consumed, or old-boot child capability.

JARVIS receives only an agentd `JarvisBootstrapUrlV2`. Its one-use ID has no
content authority. An `Ingress` bootstrap first carries the exact
`KernelIngressBootstrapTransferCapabilityV2` to ingressd; ingressd registers
the `IngressInput` envelope, consumes the returning
`IngressUiAuthenticationSettlementTransferCapabilityV2`, and alone submits
the stored `SignedUiAuthenticationSettlementV2` through
`AuthenticateIngressUi`. An `Agent` bootstrap carries
`AgentUiAuthenticationTransferCapabilityV2` to approvald; agentd alone
consumes the returning `AgentUiAuthenticationSettlementTransferCapabilityV2`
and submits the stored settlement through `AuthenticateAgentUi`. An
`Approval` bootstrap remains at approvald, where
`ApprovalTabSessionCapabilityV2` gates display and a separate decision
ceremony. Every settlement binds the exact task, authenticated principal,
browser nonce, purpose, origins, service identities, active manifest,
originating boot, issue/expiry, and one settlement nonce. Neither daemon may
mint, edit, fetch, or submit another purpose's settlement.

After exact verification, kerneld creates one origin- and purpose-bound
`IngressUiAuthorizationHandleV2` or `AgentUiAuthorizationHandleV2`. Only the
bound Rust content service may retain that handle behind its independently
generated `IngressTabSessionCapabilityV2` or
`AgentTabSessionCapabilityV2`; the first authorized content-plane transition
atomically consumes the bound kernel handle. The browser receives the tab
capability only in a same-origin POST response, keeps it only in tab memory,
and presents it only in a canonical same-origin request body.
It never appears in a URL, referrer, cookie, `Authorization` header, log,
browser store, or JARVIS-visible object. Reload, tab duplication, origin
change, boot change, expiry, logout, or first terminal consumption invalidates
it. UI authentication authenticates access to the content plane; it does not
approve ingress, a tool effect, or a final release.

## 7. Control and input flow

### 7.1 JARVIS control surface

JARVIS may call only:

```text
0   Health
10  PrepareIngress
11  GetTaskStatus
12  CancelTask
```

These operations exist only on the encrypted, mutually authenticated
JARVIS-control UDS/XPC connection; none has an HTTP route. Responses are
`JarvisVisibleV2`. Cancellation succeeds only before an effect
or release reaches `DispatchPrepared`, and only during the task's originating
boot. Otherwise it returns the closed `CancellationTooLate` request error and
does not alter execution state. A post-boot `TaskHandleV2` remains valid for
`GetTaskStatus` only. Public `Dispatching`, `Succeeded`, and `Indeterminate`
states contain no action or recovery handle.

### 7.2 New input

1. JARVIS calls agentd `PrepareIngress` without user data.
2. Before calling kerneld, agentd atomically reserves its durable
   `PrepareIngress` saga under the authenticated JARVIS semantic replay key. It
   stores one stable random agent-task nonce and phase `Reserved`; it creates
   no public handle and sends no response yet.
   It then calls the kernel-agent operation `PrepareNewIngress`, supplying no
   principal, content, policy, model, run, approval, or caller capability.
   The JARVIS request nonce and agent-task nonce are authenticated
   idempotency selectors only: neither is a bearer token, public resolver, or
   D3 capability exception.
3. Kerneld's independent durable semantic index binds the installation, exact
   logical agentd identity, and agent-task nonce to exactly one durable task and
   signed non-capability correlation. An exact cross-boot reconciliation can
   only return that task's correlation and state-appropriate current-boot
   preparation/transfer; under the task lock it first tombstones an unconsumed
   old-boot preparation, and it never rewinds a progressed task or creates a
   second durable task. Agentd atomically advances its saga through
   `KernelCommitted` to `Published`, creates and binds the sole public handle,
   its typed-hash/capsule material, and one current no-content bootstrap
   selector in that final local transaction, and only then replies. JARVIS receives only
   `TaskHandleV2` and the fixed agentd bootstrap URL. A crash at any boundary
   resumes the same two durable semantic identities rather than claiming
   cross-daemon ACID.
4. JARVIS opens the URL in a separate `noopener` window. The bootstrap response
   is static and content-free; a purpose-specific one-use POST passes through
   ingressd and starts approvald WebAuthn UI authentication for
   `IngressInput`.
5. ingressd consumes the kernel ingress bootstrap transfer, obtains the exact
   signed authentication envelope, registers it with approvald, then retrieves
   approvald's stored signed settlement through its authenticated Rust
   service path. It calls kerneld `AuthenticateIngressUi` with the original
   ingress-authentication preparation and settlement. Agentd cannot retrieve
   or submit this ingress settlement.
6. kerneld atomically consumes the settlement, binds the authenticated
   principal to the pending task, creates the one-use
   `IngressUiAuthorizationHandleV2`, and records an unredeemable future
   `PendingAgentClaimBindingV2`. That binding is not a claim commitment or
   capability: it fixes only the task, principal, expected logical agentd,
   manifest, settlement, nonce, and expiry needed to derive the eventual
   commitment after approved input exists.
   No ingress-writer or agent-claim capability exists yet. The ingress UI
   authorization handle is delivered only to ingressd; ingressd retains it
   behind the browser's `IngressTabSessionCapabilityV2` and consumes it only
   when `BeginInput` succeeds through the tab-memory protocol in section 6.
   Neither capability nor the content URL enters JARVIS.
7. The authenticated browser sends original input only to ingressd. Its
   closed HTTP DTO has no channel selector: content kind and server state fix
   the bytes as original source or chat text, never `ExtractedPage`.
8. Disposable parser/OCR workers emit bounded unsigned page frames only over
   a private preopened one-job pipe, followed by exactly one terminal
   `SignedParserWorkerResultAttestationV2`. That terminal attestation binds the
   job nonce, ephemeral signer, signed descriptor, worker artifact, original
   input, complete ordered page/frame transcript, output digests, and limits.
   Ingressd and kerneld verify the same descriptor/transcript/attestation
   chain before kerneld atomically converts private parser staging into an
   `ExtractedPage` channel; the worker holds no persistent service key.
9. kerneld runs normalization, G1, tokenization, NER, G2, schema/grammar,
   projection, and mandatory leak checks.
10. kerneld persists one daemon-signed ingress envelope in
   `AwaitingApproval`. Its `NewRun` subject binds the exact UI-authentication
   settlement and authenticated principal, contains no caller-selected
   principal, and contains no nonexistent run handle.
11. ingressd registers the exact envelope with approvald and sends the browser
    to approvald's fixed no-content bootstrap. The pending-envelope selector is
    transferred only in a one-use POST body and approvald reveals no display
    until it has performed a fresh WebAuthn UI-authentication ceremony for its
    own origin and established an `ApprovalTabSessionCapabilityV2` in tab
    memory.
12. approvald renders the signed Rust display, then performs the distinct
    WebAuthn ingress-approval ceremony with user verification and stores a
    signed approve or deny settlement.
13. ingressd submits the exact settlement to kerneld.
14. Approval atomically creates only kernel-owned state: the principal-bound
    run, immutable vault segment, policy values, provenance, and an
    unredeemable stored agent-claim commitment derived from and permanently
    consuming that exact pending binding, while consuming the finalized ingress
    writer/session. The commitment additionally fixes the stable initial
    value/document/vault identities and active-tool set; there is exactly one
    commitment digest per task. No cross-daemon browser transition is part of
    that transaction. Denial, expiry, or precommit failure clears staging and
    tombstones the pending binding and creates none of those live objects.
15. Agentd reconciles the signed durable-task correlation, prepares the
    separate `AgentContent` authentication, and stores its one-use agent
    transfer behind a new 8765 `OpenAgent` selector. JARVIS observes only
    closed `Ready` plus that no-content agentd bootstrap URL; it receives no
    agent content URL or transfer capability.
16. JARVIS may open the independent 8765 URL in a `noopener` window. Agentd
    consumes the selector and posts only
    `AgentUiAuthenticationTransferCapabilityV2` to approvald. Before any
    `AgentViewV2` is returned, approvald performs fresh `AgentContent`
    WebAuthn; agentd consumes the purpose-specific settlement transfer, calls
    `AuthenticateAgentUi`, stores the returned authorization behind
    `AgentTabSessionCapabilityV2`, and claims the committed session. Only then
    does agentd receive its Rust-only capabilities and `AgentViewV2`.

Existing-run input is a separate closed path. It can originate only from an
already authenticated agentd tab. agentd calls `PrepareFollowupIngress` with
its boot-bound agent session, run handle, and fresh request nonce. The
session/run state carries the last kernel-issued observed `RunRevisionV2`;
the caller cannot supply or edit a bare revision digest. Under the run lock,
kerneld compares that observed revision with the current canonical revision
before it snapshots the exact value into a distinct task preparation, signed
durable correlation, and POST-only ingress transfer. The browser performs a
fresh `IngressInput`
UI-authentication ceremony whose expected principal is the run principal,
then follows steps 7–13 above. Approval atomically appends the new immutable
vault/provenance values and advances `RunRevisionV2` from the snapshotted
predecessor with a domain-separated digest in the same transaction, or changes
nothing on a principal/revision/concurrency mismatch. Agentd refreshes its
observation only from the authenticated kernel session status. JARVIS cannot
supply a session, run handle, or revision and cannot initiate this path
through `PrepareIngress`.

For a new or existing run, the ingress-approval settlement principal must match
the UI-authenticated principal exactly. An existing-run subject additionally
binds the exact run identity, principal, and expected revision.

### 7.3 Input-state rule

The one-way UI and ingress state is:

```text
TaskPrepared → UiAuthPending → UiAuthenticated → Granted
        → Receiving → Finalizing → AwaitingApproval
        → Committing → CommittedUnclaimed
                         ├─→ AgentAuthPending → AgentClaimed
                         └─→ RestartInvalidated

terminal before commit:
Denied | Aborted | Expired | FailedClosed | RestartInvalidated

public projection after committed restart invalidation:
FailedNoEffect { Infrastructure }
```

Only receiving/finalizing/awaiting-approval own zeroizing plaintext staging.
Bootstrap and UI-authentication state contains no user-derived content.
Finalize is transactional. Denial, abort, expiry, invalid settlement, model
failure, resource failure, or pre-commit restart consumes the grant and clears
staging.

The shared public/internal name `RestartInvalidated` never erases phase
semantics. Its durable record carries one closed disposition:
`PreCommitStagingCleared`, `CommittedClaimRetainedByPolicy`, or
`CommittedClaimDestroyedByPolicy`. The first proves no run/vault/claim ever
committed; either committed disposition binds the exact prior
claim/vault/retention decision and may never be reported as a precommit clear.
All three project to the same content-free public failure only where this
section requires it.

`CommittedUnclaimed` is never stranded by a daemon restart. Agentd's private
boot scan may call the sole internal
`ResumeCommittedAgentAuthentication` mutation with the exact signed durable
correlation and a fresh nonce. The correlation is only an identifier: the
authenticated agentd identity, stored unredeemable claim commitment, expected
principal, installation, compatible active manifest, and either exact
`CommittedUnclaimed` state or the narrowly recoverable `AgentAuthPending`
state described below are all independently required. Its closed result either
creates one fresh boot-bound `AgentContent` authentication
preparation/envelope for a first attempt, returns a non-content signed closure
descriptor for an old attempt, or—after a safe closure proof—creates one
replacement attempt. It cannot read content, claim a run, release data, or
create an effect. A fresh WebAuthn settlement is still mandatory before
`AgentClaimed`. Expiry, incompatible state, or unrecoverable authentication
state atomically destroys or retains the unclaimed vault segment according to
signed retention policy and terminalizes the public task as
`FailedNoEffect { Infrastructure }`. `TaskHandleV2` itself remains
post-boot query-only.

The first successful authentication-preparation mutation—normal same-boot
`PrepareAgentUiAuthentication` or internal recovery
`ResumeCommittedAgentAuthentication`—advances the one-way main state from
`CommittedUnclaimed` to `AgentAuthPending` and creates exactly one boot-bound
authentication-recovery record. An exact replay in that boot returns the same
preparation; a different nonce or request identity conflicts while that record
is live. Kerneld durably retains a non-authorizing
`SignedAgentAuthenticationClosureDescriptorV2` for that exact attempt. After
an agentd restart or authentication expiry, a proof-free recovery call from
`AgentAuthPending` may return only that signed descriptor; it may not mint a
replacement.

Agentd submits the descriptor to approvald's exact recovery operation. Under
approvald's complete record, ceremony, settlement, transfer, denylist, and
journal indexes, approvald atomically produces one closed
`SignedAgentAuthenticationAttemptClosureProofV2` disposition:

```text
NeverRegisteredDenylisted
RegisteredInvalidatedUnredeemed
SettlementOrTransferObserved
Indeterminate
```

The first disposition is legal only when approvald found no prior record and,
in the same transaction, inserted a permanent tombstone that makes any later
registration of the old envelope/attempt impossible. It is never a bare
absence assertion. The second requires durable proof that every existing
record, ceremony, settlement, and transfer is terminal and unredeemed. The
proof binds the installation, manifest/generation, task/correlation, claim
commitment, principal, exact service/code/boot identities, old preparation,
envelope and transfer identities, complete index generation and journal head,
tombstone sequence, nonce, time window, signing domain, key ID, and key epoch.

Only those first two safe dispositions authorize kerneld, under the durable
task lock, to tombstone the old preparation/envelope/replay material and
create exactly one replacement recovery record while the main state remains
`AgentAuthPending`. Old authentication and registration paths must check the
tombstone. `SettlementOrTransferObserved`, `Indeterminate`, a missing or
corrupt index/head, a mismatched proof, or local absence in agentd/kerneld
advances only to `RestartInvalidated`; absence is never itself
non-redemption evidence.

## 8. G1–G7 and planner ownership

| Gate | Rust owner and behavior |
|---|---|
| G1 | kerneld/input-runtime: Unicode, prompt-injection policy, PII/secret detection, tokenization, denial. |
| G2 | kerneld/input-runtime: signed local extraction model, closed grammar/schema, whitelist, abstract intent and slot construction. |
| G3 | policy-core: source, parents, roots, labels, readers, digests, provenance propagation, and the mandatory source-label rules below; no computation or declassification improves integrity. |
| G4 | policy-core: policy × registry active set, closed ontology, attempt class, quota and action-intent deduplication. |
| G5 | policy-core: required manifest-bound internal validators only. External and caller-supplied validator attestations are disabled in initial V2. |
| G6 | kerneld/approvald: daemon-signed display and exact WebAuthn-backed one-use settlement. |
| G7 | kerneld/execd: fully bound durable action intent, atomic dispatch preparation, OS effect-gate lease/fence epoch, execution nonce, result ingress, audit, and no automatic replay. |

G3 source initialization is closed:

- signed policy constants begin `KernelTrusted`;
- an approved ingress begins `UserAuthorized`; approval authorizes use but does
  not assert that its contents are objectively true;
- kernel extraction takes the least-trusted integrity of every content parent,
  which is the maximum element under the protocol's explicit
  `KernelTrusted < UserAuthorized < ExternalUntrusted` order, and applies the
  confidentiality join, reader/effect intersection, and complete root-evidence
  union;
- planner output, tool result, and recovered external execution are always
  `ExternalUntrusted`;
- ordinary derivation uses those same least-trusted/most-restrictive
  operations and never drops a root;
- kernel declassification preserves integrity and complete root evidence. It
  may change representation, confidentiality, or readers only through a
  manifest-bound closed transition with a successful mandatory leak gate.

The fact that input-runtime, policy-core, or kerneld produced a value is never
evidence for an integrity upgrade. Public random handles are excluded from
value, provenance, validated-plan, argument, and action-intent security
digests. Wire transcript digests may bind an exact handle-bearing message, but
the validated semantic representation first resolves every handle to a stable
kernel-internal identity.

The agent flow is:

```text
ClaimAgentSession
  → PreparePlannerCall
  → external planner receives PlannerEnvelopeV2
  → CommitPlannerValue
  → DeriveValue
  → ProposeToolCall
       exact active descriptor
       + strictly sorted unique named arguments
       + resolved value/provenance digests
       + atomic ActionIntent creation
  → EvaluateToolCall
       ├─ Denied
       ├─ NeedsApproval → AuthorizeToolCall
       └─ Allowed
  → DispatchExecution
  → Pending | Succeeded | EffectSucceededOutputQuarantined
              | FailedNoEffect | Indeterminate
```

agentd is the only planner client. Its credential is restricted to the signed
planner route. The request is the exact closed `PlannerEnvelopeV2`; the
response must be a closed plan graph. Planner output is always untrusted,
passes schema, provenance, injection, and leak checks, and cannot authorize an
effect. A wire planner-output digest may bind the exact nonce and
`PlannerSlotRefV2` values only as transcript/root evidence. Before any
security identity is computed, kerneld constructs a canonical
`ResolvedPlannerEnvelopeV2` and `ResolvedPlannerPlanV2` that replace every
wire slot reference with its immutable `InternalSlotDigestV2` and contain no
handle, request ID, transport nonce, or expiry. Domain-separated
`PlanRevisionDigestV2` and `InternalStepIdV2` values are computed only from
that handle-free representation, the installation, active manifest, durable
run, step ordinal, and exact dependency graph.

Agentd acquires its process gate coordinator, authenticates the read-only
ledger projection, and proves `effects_fenced = false` plus exact manifest,
generation, and epoch before writing the durable planner-request marker—in
that order. The coordinator takes the OS shared `EffectGateV2` lock on its
first active operation and releases it only after the last planner/effect
operation has a durable response, failure, terminal, or reconciled outcome.
Agentd retains its operation reference through the entire planner exchange, so
no planner request can straddle an active-state or egress-policy cutover.

Concrete tool arguments remain opaque slots in the plan. On the first
`ProposeToolCall`, kerneld resolves one exact active descriptor and a strictly
increasing, duplicate-free vector of `(argument_name,
value_internal_id, value_digest, provenance_digest)`. Only after that complete
binding passes descriptor schema and plan-step validation does kerneld compute
the domain-separated `ArgumentDigest` over that complete vector and a
separate `ProvenanceSetDigest`, then compute and persist
`ActionIntentIdV2` from the exact plan revision, internal step, descriptor,
argument, and provenance-set digests. Those same bindings are copied without
reinterpretation into approval, dispatch, the sealed envelope, and both
journals. An exact replay returns the same intent and its current canonical
state, including a denial, authorization, dispatch, or terminal outcome; it
never resets the intent to pending. Reusing the same proposal idempotency
identity with different bytes, or trying to rebind an already bound internal
plan step to another tool, name, value identity, provenance, or descriptor,
is a binding conflict. A distinct, freshly validated plan revision/step may
create a new intent only when signed policy, dependency state, attempt class,
and quota permit it; it never creates another nonce for the prior intent.
Non-increasing or duplicate argument order is rejected before semantic
lookup. Agentd receives only the random intent handle, never an internal ID or
semantic digest.

Only execd receives materialized argument values, after G3–G6 and atomic
dispatch preparation. Initial V2 accepts no external validator declaration,
attestation, route, credential, or caller-provided verdict. Adding one requires
a later protocol-major design with its own challenge, signed binding, network
identity, replay ledger, and deployment domain.

The protocol/state companion supplies the lower-level lattice, digest,
ontology, projection, replay, approval, quota, and journal mechanics. The
source-label initialization, handle-free semantic digests, post-binding action
intent, internal-only validators, atomic kernel transactions, unified
quarantine terminal, and TaskHandle recovery rule in this master are the
controlling definitions where older companion text differs.

## 9. Approval, execution, result, and release

WebAuthn-signed authorization domains are disjoint:

```text
UiAuthentication { IngressInput | ApprovalDisplay | AgentContent }
ApprovalDecision { Ingress | ToolExecution | FinalRelease }
```

agentd can register only exact daemon-signed UI-authentication, tool, and
release envelopes. ingressd can register only ingress envelopes.
`savana-approvalctl` can perform only the closed enrollment and revocation
admin operations and cannot register, sign, fetch, or settle an approval.
Neither runtime registration API accepts an independent purpose, principal,
display, challenge, decision, credential, destination, or approval boolean.

For ingress, tool, and final-release approvals alike, approvald returns no
display content until a fresh `ApprovalDisplay` WebAuthn authentication has
established an approvald-origin, principal-, task-, envelope-, manifest-, and
tab-bound `ApprovalTabSessionCapabilityV2` held only in memory. The user then
chooses approve or deny and performs a second, distinct WebAuthn
approval-decision ceremony. The display authentication and decision use
different signed types, domains, challenges, nonces, one-use states, and
replay entries: display authentication can never approve, while a decision
assertion cannot create or resume a display session. Both authenticated
principals must equal the approval envelope's exact expected principal.

Before writing any executor byte, kerneld commits one atomic kernel
effect-preparation transaction. That transaction:

- verifies exactly one closed `DispatchSubjectV2` variant:
  `ToolExecution` binds the durable action intent, descriptor, complete
  argument binding, provenance set, and attempt class; `FinalRelease` instead
  binds a distinct `durable_release_id`, vault segment, evidence, token set,
  display/destination projections, and release policy;
- consumes the execution/release ticket and exact approval settlement when
  required;
- moves quota from available to reserved;
- locks every field of that subject plus the exact executor and active
  manifest;
- creates the sole execution nonce;
- stores the sealed subject-specific envelope, AEAD-sealed exact-replay
  capsule, and `Prepared` WAL entry; and
- binds that prepared dispatch to the current monotonic
  `effect_fence_epoch` and a compiled maximum expiry.

Quota authority is branch-typed. `ToolExecution` reserves and later spends or
releases only its signed-policy `(durable run, AttemptKindV2)` bucket.
`FinalRelease` has no attempt kind; it uses the separate
`(durable run, release_quota_subject_digest)` bucket fixed by the immutable
release-policy decision. The two counters, keys, and decoders cannot alias.
Both use the same `reserved → spent | released-no-effect |
indeterminate-spent` reconciliation rule for their exact dispatch subject and
nonce.

Agentd obtains its same process gate coordinator, reauthenticates the ledger
projection, proves the unfenced exact manifest/generation/epoch, and writes
its durable call marker before calling kerneld `DispatchExecution` or
`DispatchRelease`. It retains that operation reference until kerneld has
durably committed and returned the preparation or a fail-closed rejection.
Independently, kerneld's atomic effect-preparation transaction rereads the
authenticated ledger authority and rejects a fenced or mismatched
manifest/generation/epoch before it reserves quota, consumes authority, or
creates a WAL entry. Consequently deployment's exclusive gate prevents a new
kernel WAL root from appearing between frozen-set enumeration and `ARMED`.
Already durable recovery/resend work remains in the exact frozen WAL set and
cannot create another subject or nonce.

The subject tag and canonical subject bytes are copied without reinterpretation
into `DispatchCoreV2`, its digest, kerneld WAL, the HPKE plaintext union,
execd's journal and receipt, recovery, quota reconciliation, and terminal
tombstone. A final release never fabricates or aliases an
`ActionIntentIdV2`, tool descriptor, argument digest, or attempt class.

Either every kernel-owned item becomes durable and visible or none does.
There is no fictitious cross-daemon ACID commit. Execd's journal is the
durable truth at the external-byte boundary. After `Prepared`, external
attempt one first fsyncs receipt-free `ProviderAttemptPrepared`; an authorized
later idempotent attempt instead fsyncs `ProviderRetryPrepared`, preserving
the prior effect receipt and spent lineage. Execd then signs and durably
stores the complete `ExecutorEffectStartedReceiptRecordV2`, fsyncs the later
`EffectStarted` record that names both its digest and encrypted record ID, and
only then may emit the first provider byte. The complete signed-receipt and
receipt-record digest domains are respectively
`"SAVANA_EXECD_EFFECT_STARTED_SIGNED_RECEIPT_V2\0"` and
`"SAVANA_EXECD_EFFECT_STARTED_RECEIPT_RECORD_V2\0"`.

The exact bounded provider response is encrypted and fsynced as
`ProviderResponseRetained` before any normal or recovery codec receives it.
A tool result may then reach `CompletionAvailable`. A final release instead
must first encrypt the provider evidence and attestation, construct
`ExecutorFinalReleaseAuditEvidenceV2` under
`"SAVANA_EXECD_FINAL_RELEASE_AUDIT_EVIDENCE_V2\0"`, and fsync
`ReleaseEvidencePrepared`; only afterward may execd sign the final receipt
whose complete signed digest uses
`"SAVANA_EXECD_FINAL_RELEASE_SIGNED_RECEIPT_V2\0"` and publish
`CompletionAvailable`. The receipt-free predecessor → signed receipt → later
journal record ordering is a directed hash DAG, never a mutual digest
reference.

Until kerneld authenticates, stores, and reconciles the full signed receipt
and original nonce lineage, quota remains reserved and no unrelated nonce or
attempt may be created. Kerneld atomically moves reserved quota to spent
together with its WAL/audit transition when execd proves `EffectStarted`,
known success, or a terminal indeterminate outcome; an authenticated
`FailedNoEffect` instead releases the reservation. A
`ProviderRetryPrepared`, `ProviderResponseRetained`, or
`ReleaseEvidencePrepared` descendant can never become `FailedNoEffect`.
A crash resumes reconciliation of the same nonce and exact durable state. No
crash path can expose a prepared dispatch without its consumed ticket,
approval, quota reservation, nonce index, and exact replay result.

`DeploymentLedgerV2` owns a monotonically increasing
`effect_fence_epoch`. Arming a deployment atomically sets
`effects_fenced = true` and advances the epoch before service quiescence.
Every prepared dispatch authorization binds the installation, active manifest,
fence epoch, exact tagged dispatch subject, nonce, dispatch digest, exact
executor, and expiry. It is not a transferable lease token.

A manifest-bound kernel `EffectGateV2` closes the check/use race. Execd must
obtain an operation reference from its single process gate coordinator before
it writes `Prepared` or enters a connector. Under one non-bypassable mutex,
the coordinator takes the injected OS shared lock only on active-count
`0 → 1` and releases it only on `1 → 0`, after every referenced operation has
a durable terminal or reconciled outcome. Business code cannot close,
duplicate, unlock, fork, inherit, or directly operate the gate descriptor;
the only permitted native primitive is the deployment companion's
process-associated POSIX `fcntl` record lock. Linux OFD locks and `flock` are
forbidden, and no OS record lock is treated as recursive or reference counted.

Before writing `Prepared`, execd obtains the operation reference, rereads only
the fixed authenticated read-only ledger projection, and proves
`effects_fenced = false` plus the exact manifest, generation, epoch, and
prepared dispatch authorization. Only then may it durably write `Prepared`;
it then follows the exact attempt-prepared → complete signed-receipt record →
`EffectStarted` sequence above before the first possibly irrevocable connector
byte. It retains the reference through response retention, codec completion,
release-evidence preparation when applicable, and the durable terminal or
indeterminate execd journal record. Any descriptor-coordinator, projection,
gate, receipt-record, response-record, or binding failure fails closed.

Deployment's exclusive acquisition proves only that no live process still
holds a shared lock; a crash may have released the OS lock after a durable
`EffectStarted` but before its terminal. While exclusive and after installing
the OS deny-all fence, deploy/watchdog stops the exact normal-mode
agentd/kerneld/execd processes and proves their code/start identities exited.
Only then does it authenticate and freeze the complete agentd marker plus
kerneld/execd journal-head set and bind its digest in `ARMED`; it does not
write those role-owned journals. After exclusive release, exact role-specific
recovery services run only under the raised ledger and OS fences. They
reconcile each frozen orphan: a first-attempt receipt-free
`ProviderAttemptPrepared` with no `EffectStarted` ancestor may become
`FailedNoEffect`; a retry-prepared, effect-started, response-retained, or
release-evidence-prepared lineage without a provable outcome becomes durable
`Indeterminate`; and known outcomes use their exact terminal.
`QUIESCED` cannot commit until every frozen item has a matching authenticated
terminal/reconciled record and no extra pre-fence item exists. Thus no external
byte can occur between an unlocked fence check and an epoch change, and lock
release alone is never evidence of a terminal.

A stale dispatch authorization fails as `FailedNoEffect`; after
`EffectStarted`, no state may claim no effect. A
nonce/digest/authorization/subject mismatch poisons the transaction. An
authenticated stale-authorization rejection proves that execd wrote no
external byte; kerneld atomically terminalizes that nonce as
`FailedNoEffect` and releases, rather than spends, its quota reservation. It
does not create a replacement nonce for the same subject. Connector-internal
retry is permitted only for the same execution nonce, only when the signed
descriptor declares an exact bounded idempotency contract, and only from the
protocol's closed retry state; all other automatic mutation retry is
forbidden.

Exact replay returns the prior nonce state. Execd retains an authenticated
terminal nonce tombstone until every envelope, task, action, and recovery
retention deadline has passed. A missing or corrupt nonce index or journal
chain is fail-stop and never reported as `Unknown`.

Raw results return directly from execd to kerneld and enter a separate
tool-result transaction:

```text
ResultAvailableInExecd
  → ResultGating
  → ResultCommitted
  → ResultAcknowledged

failure:
ResultGatePending | EffectSucceededOutputQuarantined | Indeterminate
```

Result gating applies structural limits, indirect-injection checks,
secret/PII/NER detection, tokenization, result schema, and mandatory leak
checks. The result vault segment, value, provenance, agent-view document,
public outcome, replay record, and kernel `ResultCommitted` WAL state publish
in one atomic transaction. That transaction also creates the sole random
`MaskedDocumentHandleV2`, its typed-hash resolver, and a sealed immutable
`ExecutionDocumentHandleEmission` that only the same-boot AgentKernel
execution-status operation may open. The dispatch call itself returns only
`Prepared` or `Dispatching`, never a synchronous document handle. Agentd
obtains the handle through status, maps it to a tab-bound non-capability
document reference, and reads the approved `AgentViewV2` through the handle.
JARVIS receives only closed public task status.

If gating rejects a result after an external effect, or the effect/result is
known but mandatory kernel audit/publication cannot commit, the sole durable
and public terminal is `EffectSucceededOutputQuarantined` with the closed
`ResultGate` or `Audit` failure class. It consumes the approval and quota,
cannot transition to `FailedNoEffect`, and cannot authorize any replay. Execd
retains the exact encrypted result for bounded recovery or policy-directed
destruction of that same nonce. Temporary gating or audit unavailability
keeps reconciliation pending and fail-closed; only an unprovable external
effect outcome becomes `Indeterminate`.

Final vault release follows the same durable dispatch protocol and goes only
to a selected execd connector or external sink. V2 has no JARVIS, agentd, or
browser plaintext-release endpoint. Every result, receipt, quarantine,
acknowledgement, and terminal record remains tagged by the same dispatch
subject. A final release uses its typed durable release/receipt evidence and
never fabricates a tool result digest, document, action intent, argument, or
attempt class. Any untrusted provider acknowledgement is retained and gated as
release evidence; a known release whose required evidence is rejected uses
`EffectSucceededOutputQuarantined { ReleaseEvidence }`, while a known release
whose audit/publication cannot commit uses
`EffectSucceededOutputQuarantined { Audit }`. Neither may be relabelled as a
tool result or exposed as content through public status. `ResultGate` is legal
only for a tool-result subject, `ReleaseEvidence` only for a final-release
subject, and `Audit` for either; every cross-subject class pairing is rejected.
“Known release” requires execd to have fsynced `EffectStarted`, retained the
exact provider response, verified the manifest-bound provider-success
predicate and connector-codec outcome attestation, fsynced the exact
provider evidence plus recomputable audit object as
`ReleaseEvidencePrepared`, and only then issued and retained the complete
`SignedExecutorFinalReleaseReceiptV2` for that dispatch subject. Release
success/publication requires both the release-evidence gate and audit gate to
accept those same bytes; passing only one gate is never success. In either
final-release quarantine branch, the same kernel transaction records the
vault as already `Released`, spends the release quota, installs the
no-redispatch tombstone, and binds the full receipt/provider/audit evidence;
quarantine describes evidence or publication failure after the irreversible
release, not an unreleased vault. Without the complete known-release proof the
outcome is `Indeterminate` and its reservation becomes
`indeterminate-spent`, never `ReleaseEvidence`.

Agentd's 8768 action response returns a tab-bound non-capability execution or
release reference when dispatch begins. Separate nonce-bound
`RefreshExecution` and `RefreshRelease` browser mutations resolve only the
matching same-tab internal kernel handle and call the closed status operation.
Only tool success may add a document reference; release success is a
content-free terminal. There is no SSE, URL capability, JARVIS polling
payload, implicit retry, or cross-branch reference conversion.
The execution/release reference stays byte-stable while that same typed
agentd object record remains live: its PRF binds a random agentd-local record
ID and one immutable reference-binding revision, never a kernel internal ID or
mutable execution state revision. Agentd alone maps the local record to the
opaque kernel handle. Status changes therefore do not rotate the reference;
expiry, tab/session destruction, typed tombstoning, or record replacement
invalidates it without creating a cross-type alias.

## 10. Resource, error, audit, and recovery rules

One compiled limits profile covers frames, chunks, browser sessions,
parser/OCR work, model pools, queues, runs, values, provenance roots, plans,
intents, approvals, vaults, WAL entries, execution journals, replay records,
and browser responses. Signed state may lower but never raise a hard ceiling.

Expired objects use bounded indexes and dependency-aware incremental GC. No
request performs an unbounded store scan. Active state and unexpired
tombstones are never evicted to admit new work.

Every mutation has an idempotency identity. Same-boot exact replay normally
returns the same canonical response snapshot; the same identity with different
bytes is rejected. A distinct request for the same action intent still resolves
to the existing intent and cannot create a new execution nonce.

Capability resolvers store only
`SHA-256(exact_type_domain || random_token)` and never plaintext token bytes.
When an exact response contains a random handle or transfer that could not
otherwise be reconstructed after response loss, the issuing Rust service also
stores one role-specific AEAD-sealed replay capsule. Its closed kind is exactly
one of `ExactResponseSnapshot`, `TypedCapabilityResponseEmission`,
`ActionIntentHandleEmission`, `ActionStateHandleEmission`,
`DurableTaskHandleEmission`, `ExecutionDocumentHandleEmission`, or
`ActionIntentEmissionReference`. The reference kind contains only the exact
same-boot internal emission key, record digest, and stable proposal digest; it
contains no token and cannot act as a resolver. The execution-document kind is
an immutable, pre-stored operation-30 emission for the one document handle
created by a committed tool-result outcome; it is not a live projection and
cannot be opened by dispatch, release, browser, or another operation. Capsule
AAD binds the complete replay or internal-emission key, request/operation where
applicable, authenticated client/service and OS peer, internal object, active
manifest, deployment generation, key scope/epoch, transaction sequence,
plaintext digest/length, creation, and retention bound. A capsule is opened
only after an exact authenticated replay or closed internal-emission match and
is never accepted by a capability resolver or another operation. Every
decrypted token must match an already existing typed-hash resolver row; a
missing row is fail-stop and is never recreated from escrow. Decrypted bytes
are zeroized immediately.

The manifest fixes exactly eleven boot-fresh replay roles and their exact
strictly sorted capsule-kind sets:

| Replay role | Exact permitted boot-fresh kinds |
|---|---|
| `AgentdJarvisControl` | `ExactResponseSnapshot` |
| `IngressdBrowser` | `ExactResponseSnapshot`, `TypedCapabilityResponseEmission` |
| `AgentdAgentBrowser` | `ExactResponseSnapshot`, `TypedCapabilityResponseEmission` |
| `KerneldAgentKernel` | `ExactResponseSnapshot`, `TypedCapabilityResponseEmission`, `ActionIntentHandleEmission`, `ActionStateHandleEmission`, `ExecutionDocumentHandleEmission`, `ActionIntentEmissionReference` |
| `KerneldIngressKernel` | `ExactResponseSnapshot`, `TypedCapabilityResponseEmission` |
| `ExecdKernelExecutor` | `ExactResponseSnapshot` |
| `ApprovaldAgent` | `ExactResponseSnapshot`, `TypedCapabilityResponseEmission` |
| `ApprovaldIngress` | `ExactResponseSnapshot`, `TypedCapabilityResponseEmission` |
| `ApprovaldAdmin` | `ExactResponseSnapshot`, `TypedCapabilityResponseEmission` |
| `ApprovaldBrowser` | `ExactResponseSnapshot`, `TypedCapabilityResponseEmission` |
| `AgentdJarvisBrowser` | `TypedCapabilityResponseEmission` |

Every boot role uses a fresh locked-memory
`XChaCha20Poly1305` key for exactly one server boot. Missing, extra,
duplicate, unsorted, or cross-role-substituted kinds reject the manifest, and
no boot-fresh role permits `DurableTaskHandleEmission`. The separate
deployment-owned `AgentdDurableReplayAeadLockV2` permits exactly that one
durable kind and none of the six boot-only kinds.

Boot-scoped capsules use a boot-scoped replay key destroyed at restart.
Agentd's `PrepareIngress` durable semantic index is separately keyed by the
installation, protocol major, authenticated JARVIS principal, exact OS peer
class, and `client_request_nonce`; it is not a boot-scoped replay key with the
boot field ignored. The index instead seals only its
`TaskHandleV2` emission with a platform-keystore-backed replay-escrow key so
the same task handle can be returned through its exact
`query_tombstone_retain_until` bound and never after it.
It never revives the response's originating-boot bootstrap selector; agentd
projects current closed public state and, when authorized, creates a new
no-content bootstrap selector. `ServiceIdentityLockV2` fixes the unique agentd
AEAD role, typed CSPRNG `ReplayAeadKeyIdV2`, derived diagnostic identity,
algorithm, non-exportable key-handle identity, active encryption epoch,
bounded decrypt-only retired epochs, and their time windows.
Before a capsule from another manifest may be opened, the destination
manifest must contain both the applicable exact
`PersistentStoreCompatibilityV2` declaration and the one directional
`ReplayCapsuleCompatibilityEdgeV2` in
`ServiceIdentityLockV2.agentd_durable_replay_sealing`. The latter is the sole
edge/vector authority and is restricted to `DurableTaskHandleEmission`;
boot-scoped, action-state, execution-document, and browser-reference capsules
can never cross a manifest. Default is rejection, and V2 performs no online
rewrap. Hard limits and the signed resource profile, not the identity lock,
fix capsule count, bytes, and retention ceilings.

Capsules have no wire DTO, public route, generic object-ID opener, or
dispatcher entry. An ordinary snapshot is emitted only as zeroizing canonical
response bytes and is never parsed into a capability. An operation-specific
typed exact emission must verify every token against its existing typed
resolver row before rebuilding that one compiled response. The two
live-projection modules may only reassemble their specified closed response
projection from a single serializable state revision. They cannot change
semantic authorization, intent, effect, vault, quota, or terminal state;
mint/reconstruct a capability token; create/restore a resolver row; or treat a
capsule as a resolver. Their only bounded writes are the atomic replay
commitment metadata for the actually emitted projection and, for a durable
TaskHandle projection, creation/tombstoning of the one current-boot
content-free bootstrap selector already authorized by canonical task state.
Neither write revives an originating-boot child capability. A corrupt,
missing, wrong-key,
wrong-AAD, unknown-epoch,
length/digest-mismatched, or noncanonical client-replay capsule poisons its
exact mutation replay slot; the same failure in an internal capsule poisons
that exact internal emission record. Either path returns only
`ServiceUnavailable`; it cannot cause the mutation to run again, mint a
replacement, rebuild a resolver row, or change semantic state. Golden tests cover response
loss, process restart, key rotation, capsule substitution, stale child
capabilities, and proof that a capsule cannot resolve a handle.

Cancellation, vault revocation, agent-session close, dispatch preparation, and
release preparation serialize on the same durable task/effect record.
Cancellation or revocation succeeds only in the originating boot and only
while every affected effect is earlier than `DispatchPrepared`; success
atomically terminalizes pending tickets/approvals and clears staging. Once any
effect is prepared, cancellation returns `CancellationTooLate` and changes
nothing.

Error behavior:

- wrong peer, transcript, role, protocol, canonical encoding, or pre-request
  frame errors close silently;
- an authenticated canonical request may receive one request-bound closed
  error;
- model, overload, deadline, cancellation, audit, entropy, storage, and
  service failures fail closed;
- no caller mutation and no external effect is automatically retried or
  replaced with a new identity;
- a closed daemon-private reconciliation worker may resume only the explicitly
  named `PrepareIngress`, authentication-closure, planner-marker, dispatch,
  result, and deployment sagas, using the already durable semantic key,
  subject, request digest, execution nonce, and next legal state; it may not
  synthesize a new caller request, capability, authority, subject, nonce, or
  connector attempt;
- a status query plus explicit exact retry may resend only the same operation
  identity and, for dispatch, the same execution nonce;
- `FailedNoEffect` requires durable proof that no effect occurred;
- every unprovable post-dispatch condition is terminal `Indeterminate`;
- a known external success whose result is denied is
  `EffectSucceededOutputQuarantined`, never `FailedNoEffect`.

kerneld and execd have complementary durable journals. Restart recovery queries
the original nonce and never generates a replacement. The durable task record
maps every internal action, release, nonce, and closed outcome to the
kernel-owned `DurableTaskIdV2` and its signed durable-task correlation, never
to `TaskHandleV2`. Agentd alone maps that correlation to its public
`TaskHandleV2`; no separate boot-independent `RecoveryReferenceV2` is
exported. After a restart, the task handle authorizes only a closed
`GetTaskStatus` query. Execution, release, UI, cursor, ticket, claim, and
recovery-internal handles from the old boot are invalid.

`TaskHandleV2` is agentd-owned. agentd durably stores only the hash of its
random token in the authoritative resolver, the authenticated JARVIS
control-client and OS-peer binding, the exact `TaskOriginBootV2`, creating
manifest digest, deployment generation, protocol ABI,
`task_logical_expires_at`, `query_tombstone_retain_until`, and
kernel-signed durable-task correlation created by `PrepareNewIngress`; the
only recoverable token copy is the durable typed TaskHandle-emission capsule
described above. A destination manifest may query it only when agentd's
resolver store and kerneld's correlation/task store each have their own exact
`PersistentStoreCompatibilityV2` declaration: the store ID must match, its
desired reader range must contain the creating schema epoch, and its complete
migration digest, post-migration digest rule, and validator artifact/result
must verify under an unchanged protocol ABI. These are complete
destination-store declarations, not cross-manifest edges; one daemon's
declaration cannot authorize the other. Opening the token capsule additionally
requires the separate directional agentd replay edge described earlier.
Missing, wildcard, wrong-store, out-of-range, one-sided, or schema-only
inferred compatibility is rejection.
The authenticated AgentKernel transcript supplies the
correlation's agentd/kerneld/machine portion, while agentd alone supplies and
stores the authenticated JARVIS client-boot member. Kerneld stores the
correlation, not the public handle, in each relevant WAL record. After
restart, agentd's authenticated service-only status reconciler may ask kerneld
for the closed outcome of that exact correlation. This status operation is the
correlation's sole cross-boot resolver. The correlation is never exposed to
JARVIS and is not a bearer capability. It authorizes no content read, claim,
release, or effect and cannot authorize a mutation by itself. The single
`ResumeCommittedAgentAuthentication` exception may use it only as a lookup
selector and additionally requires all independent transcript/client-boot,
service/code/OS-peer, state, identity, commitment, manifest-compatibility,
nonce, replay-capacity, signed-invalidation, and fresh-WebAuthn conditions in
section 7.3.

Audit contains only closed transition data, stable public codes, active state
identity, timing, and keyed pseudonymous correlation. It contains no content,
masked text, handle bytes, destination, credential, signature, WebAuthn
identifier, or private-key locator.

Audit failure before an effect blocks the effect. If the external outcome is
known after an effect, audit failure poisons the transaction and must
eventually publish `EffectSucceededOutputQuarantined { Audit }`; until that
terminal can commit the service fails stop and returns only
`ServiceUnavailable`. It never records `Indeterminate` for a known outcome.
Only an outcome that cannot be proven becomes `Indeterminate`.

## 11. Deployment and rollback

Every normal target and rollback target is a complete signed
`SecurityStateManifestV2` covering:

- the exact ten-crate source and built binary closure;
- JARVIS control artifact and the private `savana-approvalctl` binary;
- policy, registry, ontology, models, resources, destination and display
  projections, internal validators, grammar/schema, protocol, services,
  identities, approval, planner route/TLS/key lock, executor/connector
  registry, executor sealing/result-key lock, completion-evidence trust policy,
  and signed egress destinations;
- the complete signed deployment/activation
  `OperationalTrustRootSetV2` objects, immutable signed release trust-root
  set, exact component-signing policy, and closed
  `ServiceIdentityLockV2`, `ExecutorKeyLockV2`, `PlannerLockV2`, and
  `ApprovalLockV2` payloads with role-specific current/retired keys and epochs;
- the complete parser/connector private wire and crypto ABI: parser job
  descriptor, ordered page frames and one terminal result attestation, plus
  connector-codec job descriptor, pipe frames,
  `PreparedProviderRequestV2`, `ConnectorCodecDecodedCompletionV2`,
  `ConnectorCodecOutcomePayloadV2`, prepare/decode mode matrix,
  prepared-request and outcome attestations, exact receipt/evidence digest
  domains, and ordered transcript;
- native service, socket/XPC, sandbox, entitlement, code-integrity, and
  bootstrap TCB closure;
- persistent-store compatibility.

For every normal candidate and rollback target, the manifest's complete
canonical `BootstrapTcbLockDigest` must equal the
`bootstrap_tcb_lock_digest` member of the complete
`BootstrapSlotClosureV2` selected by the currently active offline bootstrap
slot. It is not equal to the complete slot-closure digest. The boot gate
independently recomputes and authenticates that complete slot closure,
including its installation-specific profile, attestation, and genesis. The
normal artifact/install plan is rejected if it contains any bootstrap-owned
path, helper, watchdog, ledger verifier/schema authority, active-slot
selector, bootstrap trust root, slot closure, or bootstrap
keystore/profile/attestation/genesis object. This remains true when
deploy/watchdog binary targets were compiled from the same kerneld crate:
source checks may report their build outputs, but a normal candidate may
reach `ArtifactComplete` only when those reproducible bootstrap-target bytes
equal the already selected active slot. Any changed output blocks normal
artifact completion and requires the offline maintenance ceremony before it
can be installed or activated.

Every signed deployment/evidence object carries a closed
`DomainSignatureV2` wrapper containing exactly `signature_domain`,
`signer_key_id`, `signer_key_epoch`, and `signature`;
the object type fixes the only legal domain and signer role, so a field/tag,
role, key, or epoch disagreement is rejected before signature acceptance.
Manifest component/release cardinality and artifact-to-component signer
mapping are closed by `ReleaseTrustRootSetV2` and the component-signing policy.
`InstallationEpochAttestationV2` has one canonical unsigned payload, explicit
activation-key and installer-or-MDM key IDs/epochs/root-set identities, two
disjoint signature domains over that same payload, and one domain-separated
complete signed-attestation digest used by every later reference.

One root-owned `DeploymentLedgerV2` is the sole active/high-water authority.
Services do not independently advance a competing release high-water. Every
nonterminal ledger generation binds the digest of one immutable
`DurableDeploymentTransactionCoreV2` and the head of its append-only
`DurableDeploymentTransactionRecordV2` chain. The core contains the complete
signed transaction/grant/payload, staging selector/tree, desired and rollback
closures, transition plans, exact owner, deadline, and pre-state. Each head
binds its predecessor, expected previous ledger digest/generation, target
phase, completed idempotent steps, and evidence references. A head is flushed
before the ledger CAS points to it; an unreferenced head is only garbage, and
a missing or mismatched referenced head causes an external boot-integrity halt
because no authenticated next ledger record can be created. With a valid
current ledger/core/head chain, a closed transition failure may instead append
an authenticated failure head and enter `FAILED_SAFE` from one of the
explicitly listed transaction phases. Recovery follows only this authenticated
chain and never scans the spool to invent state.
`COMMITTED`, `ROLLED_BACK`, `ABORTED`, and `FAILED_SAFE` retain the exact final
head needed for attestation and recovery audit.

The ledger also stores the monotonic `effect_fence_epoch`; every transition to
`ARMED` first holds the exclusive manifest-bound `EffectGateV2`, installs the
deny-all OS fence, authenticates and freezes the complete
operation/journal-head set, then binds that set while advancing the epoch in
the durable record that raises the effect fence. After exclusive release,
role-specific services run only in fenced recovery mode and reconcile that
exact frozen set before `QUIESCED`; deploy/watchdog never forges their journal
records. Agentd and execd may hold only coordinator-managed shared operation
references under section 9; they cannot call the OS lock API directly.

Normal upgrades advance every changed domain. Rollback never decreases a
high-water value. It activates one exact complete rollback manifest only
through a transaction-bound, pre-armed, one-use `RollbackGrantV2`; the
highest-ever vector remains unchanged.

Deployment and rollback identities are acyclic:

```text
transaction_id =
  an independent cryptographically random Nonce32

StagingClosureDigestV2 =
  the indexed Merkle root of every immutable staged entry except the fixed
  DeploymentTransactionV2.cbor descriptor

TransactionIntentDigestV2 =
  digest(canonical TransactionIntentV2, including transaction_id,
         StagingClosureDigestV2, and exact desired/rollback manifests,
         but containing no rollback grant or authorization signature)

RollbackGrantV2 binds:
  TransactionIntentDigestV2
  + the same transaction_id
  + installation and epoch
  + exact pre-active, desired, and rollback manifests
  + every origin-specific rollback-phase highest-ever digest
  + install/bootstrap identities and arm/support limits

TransactionPayloadDigestV2 =
  digest(canonical [TransactionIntentV2,
                    TransactionIntentDigestV2,
                    complete signed RollbackGrantV2])
```

The signed intent field `staging_tree_digest` equals
`StagingClosureDigestV2`, and the root spool selector must equal that same
digest. The excluded fixed descriptor contains the intent, grant, payload
digest, and authorization signature, so it cannot create a staging hash cycle.
All signed manifests, binaries, resources, and their metadata remain covered
staged entries. The grant contains no transaction-payload digest, the intent
contains no grant, and the transaction ID is not derived from either. The
deployment authorization signature covers `TransactionPayloadDigestV2`. No
hash input contains itself directly or through a nested signed object.

The initial deployment mechanism has no root daemon or privilege-broker
socket. A fixed root-only helper accepts only a content-addressed staging ID
below a fixed root-owned spool. It accepts no arbitrary path, trust root,
command, script, service name, environment override, or inherited descriptor.

V2 exposes no `BootstrapTcbUpdateV2`, bootstrap-update socket, online
trust-root rotation, or application-transaction path that replaces
`savana-deploy`, its watchdog, the deployment ledger verifier/schema, or a
deployment trust root. Changing any of them requires all Savana services to be
stopped and an OS-native, root-authorized offline maintenance ceremony. The
ceremony is not assumed to be indivisible merely because it is packaged. It
uses a signed `BootstrapMaintenanceIntentV2`, two content-addressed bootstrap
slots, a monotonic package sequence, an append-only
`BootstrapMaintenanceRecordV2`, and one same-filesystem atomic active-slot
selector:

```text
MAINTENANCE_PREPARED
  → BOOTSTRAP_FILES_STAGED
  → KEYS_AND_PROFILES_CREATED
  → NEW_EPOCH_GENESIS_DURABLE
  → ACTIVE_SLOT_COMMITTED
  → MAINTENANCE_VERIFIED
```

Every record binds the signed maintenance intent and its static old/new
bootstrap identities, old/new installation epochs, exact release-root
vectors, helper/watchdog/verifier/schema, predecessor, completed step,
recovery action, and the closed current-selector state. From
`GenesisStaged` onward it additionally retains the exact attempted-new
complete slot-closure digest over the already durable keystore profile,
attestation, and genesis; earlier records cannot invent that not-yet-created
closure. Before the active-slot commit, recovery either resumes the signed
plan or removes only authenticated new-slot/orphan objects and retains the
old active closure. After selector commit, recovery first attempts forward
verification. If that validation is irrecoverable before any Savana runtime
activation, the signed maintenance chain may atomically restore the retained
old-slot selector and terminalize `RolledBack`; the attempted package
high-water remains advanced. Once runtime activation could have occurred,
recovery may only finish the new epoch or remain fail safe. Neither branch
restores an old operational-store snapshot.
No Savana runtime service starts while a maintenance record is nonterminal or
the selector/genesis/attestation set is inconsistent. Linux uses signed native
package verification plus same-directory `renameat(2)` and directory fsync
for the selector; macOS uses the signed Installer receipt plus APFS
same-volume atomic rename and directory fsync. Power-loss injection covers
every file, root, keystore, profile, genesis, selector, and verification
boundary. This separate ceremony is not a successful V2 application
deployment.

Normal-state egress is also native and manifest-bound. Linux's authoritative
control is one measured cgroup-BPF program that atomically enforces the exact
destination address, transport, and port-range tuple for agentd and execd;
systemd `IPAddressAllow` is supplemental only. macOS uses the equivalently
measured PF/application-sandbox tuple. Agentd and execd additionally verify
the exact signed TLS/mTLS route and SPKI pins in their closed client stacks.
An allowed IP with a wrong port, transport, SNI, certificate chain, or pin is
denied and is a required native negative test.

The legal deployment sequence is:

```text
IDLE | COMMITTED | ROLLED_BACK
  → PREPARED → ARMED → QUIESCED → INSTALLED → VERIFIED → COMMITTED

PREPARED → ABORTED → IDLE

ARMED | QUIESCED | INSTALLED | VERIFIED
  → ROLLBACK_PREPARED
  → ROLLBACK_INSTALLED
  → ROLLBACK_VERIFIED
  → ROLLED_BACK

ROLLBACK_PREPARED | ROLLBACK_INSTALLED | ROLLBACK_VERIFIED
  → FAILED_SAFE

PREPARED | ARMED | QUIESCED | INSTALLED | VERIFIED
  → FAILED_SAFE
```

The `FAILED_SAFE` arrows are legal only when the current ledger, immutable
core, complete head ancestry, and new failure evidence all authenticate and
the failure head is durable before the ledger CAS. If the ledger/head/core
cannot be authenticated, the bootstrap gate remains in the external
boot-integrity halt and writes no synthetic `FAILED_SAFE` record.

`ROLLBACK_PREPARED` atomically consumes the one-use grant, selects the exact
rollback closure, and records whether the current durable high-water is the
grant's pre-attempt or post-attempt digest. Failure before `INSTALLED` preserves
the pre-attempt vector; failure at or after `INSTALLED` preserves the
post-attempt vector. Neither path decreases a high-water entry.

`ROLLBACK_INSTALLED` records the exact rollback file selector and complete
store-compatibility result. `ROLLBACK_VERIFIED` contains exactly one closed
`RollbackTerminalReadinessRefV2`. A rollback originating at `VERIFIED` binds
`RollbackVerificationEvidenceV2`, including the exact candidate verification,
and may later form the `RolledBack` branch of `PlatformEvidenceV2`. A rollback
originating at `ARMED`, `QUIESCED`, or `INSTALLED` instead binds a
phase-tagged `RecoveryRollbackReadinessEvidenceV2` with the exact store,
native-control, fence, journal, service-readiness, and recovery measurements
available for that origin; it contains no fabricated candidate-verification
digest and can never establish `PlatformComplete`.

`ROLLED_BACK` is written only after the selected readiness evidence verifies
while the fence remains raised; its single terminal record activates the
consumed rollback manifest, lowers the fence, and advances
`effect_fence_epoch` again. There is no hidden
`ROLLED_BACK → IDLE` transition. `COMMITTED` likewise burns the grant, lowers
the fence, and advances the epoch in one terminal record. `ABORTED` preserves
the preceding activation and has no usable grant, then an authenticated
generation transition compacts it to `IDLE`. A later deployment may enter
`PREPARED` only from one of the allowed unfenced phases shown above.

`FAILED_SAFE` is a separate terminal with the fence raised. No general effect
is permitted, and V2 defines no transition out of it; recovery requires the
separate offline operator-maintenance boundary. Before `FAILED_SAFE`, a
watchdog or boot recovery may resume a nonterminal deployment or rollback only
at the exact next idempotent step; it cannot invent a target, grant,
high-water vector, or fence epoch.

Linux and macOS mechanisms, root invocation, complete transaction fields,
service identities, fs-verity/code signing, systemd/App Sandbox/XPC/PF
profiles, storage durability, watchdog races, and boot recovery use the
deployment companion mechanics. The acyclic transaction/grant construction,
immutable V2 bootstrap TCB, effect-fence epoch, refined rollback states, and
evidence/completion rules in this section take precedence where the older
companion differs.

## 12. Migration and implementation order

The strict implementation order is:

```text
Master override and corrected protocol/state freeze
  → G3 source labels and handle-free semantic digests
  → post-binding action intent / internal-only G5 / atomic G7 state
  → vault and approval primitives
  → G1/G2/NER input runtime
  → ingressd and parser/OCR sandbox
  → agentd PrepareNewIngress / abstract planner / UI-session boundary
  → approvald WebAuthn and private approvalctl
  → execd and durable connector journal
  → JARVIS control-shell cutover
  → OS effect-gate lease/fence epoch
  → native packaging and acyclic deployment transaction
  → signed candidate E2E
  → required-mode deployment
  → legacy removal
  → refined rollback exercise
  → four-layer final evidence
```

No V2 mutation tag is opened in a dispatcher until its schema, limits,
signature domains, state transition, replay semantics, audit, restart
behavior, negative tests, and authenticated endpoint tests pass.

The first corrected kernel-agent surface includes `PrepareNewIngress`,
`PrepareAgentUiAuthentication`, and `AuthenticateAgentUi`. Planner commit
returns validated plan-step handles, not pre-bound action intents; the intent
is created by the first complete tool/argument binding. External
validator-attestation tags and every online bootstrap-update entry point remain
absent.

## 13. Verification and completion

Implementation uses test-driven development. Security tests may not skip,
conditionally succeed, or silently use a fallback.

Required gates include:

1. independent V1/V2 types, role-specific enums, fixed vectors, cross-version
   rejection, canonical single-pass decoding, and parser fuzzing;
2. model-based G3 source initialization, no-trust-upgrade derivation,
   handle-free semantic digests, internal-only G5, and post-binding
   action-intent tests;
3. real signed G1/G2/NER/parser/OCR assets, Unicode and injection adversarial
   tests, schema/grammar failures, and resource exhaustion;
4. malicious file, MIME, archive expansion, parser crash, worker isolation,
   job-scoped worker-result attestation, rejection of browser-created
   `ExtractedPage`, and source-provenance tests;
5. vault binding, expiry, revocation, restart, canary, redaction, and
   zeroization tests;
6. response-loss and crash injection proving atomic ticket/approval/quota/WAL
   preparation; AEAD-sealed exact snapshots and typed intent/TaskHandle
   emissions without a capability-resolver bypass; poisoned-capsule,
   missing-resolver-row, stale-child, TaskHandle cross-boot projection,
   replay-key rotation/fifth-retired-epoch, and manifest-read-edge rejection;
   every agentd-reservation/kerneld-task/publication crash point yields one
   durable task and one eventual public handle rather than an orphan duplicate;
   pending-agent-claim binding single consumption; approvald
   never-registered denylist and registered-unredeemed invalidation at every
   registration/response-loss crash point before replacement agent
   authentication; rejection of observed/indeterminate closure; and atomic
   result/vault/provenance/WAL publication;
7. execd/kernel recovery, tagged tool/release dispatch-subject vectors, nonce
   tombstone replay, branch-separated tool/release quota counters, typed
   result/release-evidence/audit output quarantine, networkless connector-codec
   descriptor/request/response attestations with credential and network
   absence, two concurrent gate operations completing out of order, proof that
   projection validation precedes every marker/Prepared/WAL, descriptor
   close/crash at `ProviderAttemptPrepared`, `ProviderRetryPrepared`,
   `EffectStarted`, `ProviderResponseRetained`, and
   `ReleaseEvidencePrepared`; full signed-receipt record recovery; proof that
   retry/spent lineage never becomes `FailedNoEffect`; exclusive-barrier
   orphan reconciliation, acknowledgement, and indeterminate reconciliation;
8. all cross-role, peer, key, endpoint, handle, state, and artifact denials;
9. agentd/approvald/ingressd browser-origin, CSP, cache, exact browser success
   unions/fixed-form carriers, WebAuthn, one-use tab-memory session,
   no-cookie/no-Authorization, forged-Origin TaskHandle denial, authenticated
   four-member `TaskOriginBootV2` cancellation binding, concurrent/restarted
   agent-authentication recovery, async browser execution/release refresh
   through tab-bound non-capability refs, control-only status/cancel, and
   no-JARVIS-content tests;
10. static DTO/API/route/symbol scans proving `JarvisVisibleV2` contains only
    `TaskHandleV2`, closed status, and no-content bootstrap URL; planner
    envelopes contain no user-derived free text; and no external-validator or
    online-bootstrap API exists;
11. root deployment failure injection, every append-head/ledger and offline
    bootstrap-maintenance power-loss boundary, concurrent invocation,
    rejection of online bootstrap update, acyclic transaction/grant vectors,
    exact equality of every normal candidate's bootstrap lock to the selected
    active offline slot, rejection of every bootstrap-owned normal install
    path, phase-specific early/verified rollback evidence, durability, and
    boot recovery;
12. real Linux and macOS identity, sandbox, egress, code-integrity,
   filesystem, service-manager, and native E2E gates;
13. a required-mode E2E suite that traverses every mandatory boundary in
    order: JARVIS no-content bootstrap, fresh pre-input UI authentication,
    Rust ingress, fresh approval-display authentication, distinct ingress
    decision assertion, atomic ingress commit, fresh agent-content
    authentication, abstract planner exchange, tool approval-display
    authentication and distinct decision when policy requires it, one exact
    effect, result gating, and a separate final-release
    display-authentication/decision/release case; paired bypass tests prove no
    step can be skipped or substituted, exactly one effect occurs,
    cancellation is same-boot-only, post-boot task query is status-only, and
    JARVIS receives no data;
14. exact ten-crate and binary-target closure, including private
    `savana-approvalctl`, parser/OCR workers, connector workers, deploy, and
    watchdog;
15. release-root-signed `ProductReleaseV2`, every exact-set domain/golden
    vector, subset/superset/cross-release rejection, four-layer evidence
    validation, and three independent final reviews bound to the exact
    revision, artifact manifest, complete advertised platform evidence set,
    and E2E evidence with Critical/Important/Minor `0/0/0`.

The advertised production set has one independent release-root authority:

```text
RequiredPlatformReleaseTupleV2 {
    os: ClosedOsV2,
    architecture: ClosedArchitectureV2,
    manifest_digest: Digest32,
    source_lock_digest: Digest32,
    protocol_lock_digest: Digest32,
    platform_closure_digest: Digest32
}

SignedReleaseManifestEntryV2 {
    manifest_digest: Digest32,
    manifest_payload_digest: Digest32,
    manifest_release_signature:
        DomainSignatureV2 { signature_domain = ManifestRelease }
}

ProductReleasePayloadV2 {
    schema_version: u16 = 2,
    domain_tag: ClosedDeploymentObjectDomainV2 = ProductRelease,
    product_family_digest: Digest32,
    product_identity_digest: Digest32,
    release_identity_digest: Digest32,
    release_sequence: u64,
    previous_product_release_signed_digest: None | Digest32,
    evidence_trust_policy_digest: Digest32,
    evidence_layer_limits_digest: Digest32,
    release_trust_root_set_signed_digest: Digest32,
    release_trust_root_set_digest: Digest32,
    release_manifests: [SignedReleaseManifestEntryV2],
    release_manifest_set_digest: Digest32,
    required_platform_tuples: [RequiredPlatformReleaseTupleV2],
    required_platform_tuple_set_digest: Digest32,
    issued_at_unix_ms: UnixMillis,
    not_before_unix_ms: UnixMillis,
    expires_at_unix_ms: UnixMillis
}

ProductReleaseV2 {
    payload: ProductReleasePayloadV2,
    payload_digest: Digest32,
    release_root_signature:
        DomainSignatureV2 { signature_domain = ProductRelease }
}
```

Both vectors are bounded, strictly sorted, and duplicate-free. Their
domain-separated exact-set digests are recomputed from the canonical item
schemas; no caller supplies an opaque set digest without the items. The
`ProductReleaseV2` payload digest, signature input, complete signed-object
digest, authorized release-root key/epoch, predecessor rule, and every other
set-digest domain literal are fixed by the deployment companion. The
immutable `ReleaseTrustRootSetV2` in the offline bootstrap TCB, not a Product,
review, artifact, deployment, or service key, verifies this object.

`ProductCompletionAttestationV2` must carry the exact signed product-release
digest and recompute its release-manifest and required-platform tuple sets
from that object. Its own redundant set digests, every
`PlatformEvidenceRefV2` projection, and every review must equal those sets
exactly. A subset, superset, two-field platform tuple, cross-release manifest,
different trust policy/limits, unknown signer, or mismatched predecessor is
rejection.

Evidence and completion have exactly four monotonic layers:

1. Signed `SourceEvidenceV2` binds the exact completion-evidence trust policy
   and layer limits, source revision, all three design digests, corrected
   protocol vectors, unit/property/model/fuzz results, and legacy-source scan.
   An authorized `Source` signer may establish `SourceImplemented`.
2. Signed `ArtifactEvidenceV2` binds the same trust policy and limits, one
   source-evidence digest, reproducible toolchain/SBOM, complete signed
   `SecurityStateManifestV2`, exact ten-crate source closure, and every signed
   binary target. An authorized `Artifact` signer may establish
   `ArtifactComplete`.
3. `PlatformEvidenceV2` is the unsigned deterministic canonical composition
   of one artifact-evidence chain, one signed preterminal verification, and
   exactly one domain-tagged terminal attestation for the exact OS,
   architecture, installation, attempted and final-active manifests, ledger
   generation, native controls, effect-fence result, persistent-store
   compatibility, required-mode E2E, and rollback exercise. Its closed
   terminal union is either `Committed = 1` with a valid
   `CommitAttestationV2`, or `RolledBack = 2` with a valid
   `RollbackVerificationAttestationV2`; the two cannot be omitted, combined,
   relabelled, or decoded under the other tag. Only the valid final
   composition may establish `PlatformComplete`.
4. Signed `ProductEvidenceV2` is exactly
   `ProductCompletionAttestationV2`. It binds the same trust policy and
   limits, exact release-root-signed `ProductReleaseV2`, release manifest set,
   exact advertised six-field platform tuple set, exact
   source/artifact/platform/terminal-attestation sets, a strictly sorted
   duplicate-free vector of `PlatformEvidenceRefV2`, legacy absence, and the
   three independent final `0/0/0` reviews. Only an authorized `Product`
   signer may attest that already authoritative release/set chain and
   establish `ProductComplete`; it cannot choose the advertised set.

```text
PlatformEvidenceRefV2 {
    os: ClosedOsV2,
    architecture: ClosedArchitectureV2,
    installation_id: Digest32,
    installation_epoch: u64,
    manifest_digest: Digest32,
    final_active_manifest_digest: Digest32,
    evidence_trust_policy_digest: Digest32,
    evidence_layer_limits_digest: Digest32,
    source_evidence_digest: Digest32,
    artifact_evidence_digest: Digest32,
    platform_evidence_digest: Digest32,
    terminal_outcome: PlatformTerminalOutcomeV2,
    terminal_attestation_digest: Digest32,
    source_lock_digest: Digest32,
    protocol_lock_digest: Digest32,
    platform_closure_digest: Digest32,
    verification_evidence_digest: Digest32
}
```

The vector is strictly increasing by canonical `(os tag, architecture tag,
manifest_digest bytes, installation_id bytes, installation_epoch)` and has no
duplicate OS/architecture tuple. Each reference must reproduce one valid
`PlatformEvidenceV2`, including its exact lower-layer chain, attempted and
final-active manifests, verification, closed terminal tag and sole matching
terminal-attestation digest, installation, policy, limits, and lock/closure
digests. All references use the product object's one source-evidence and
trust-policy digest. The artifact, platform, and canonical
`(terminal_outcome, terminal_attestation_digest)` sets in product evidence
must equal the exact duplicate-free sets projected from those references.

Projecting every reference to `(os, architecture, manifest_digest,
source_lock_digest, protocol_lock_digest, platform_closure_digest)` must equal
the signed product release's advertised production platform set exactly: no
missing, extra, duplicate, wildcard, family-wide, cross-installation, or
source-evidence substitute is accepted. Any redundant-field disagreement or
mixing values from different evidence chains is rejection. Product evidence
is an aggregation of already final platform evidence and reviews; it is not an
input to the deployment transaction it attests, avoiding an evidence cycle.

Missing production keys, real assets, native hosts, or protected deployment
evidence permits only the precise lower completion state. It must never be
reported as product complete.
